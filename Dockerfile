# --- Stage 1: Build Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Production Backend & Runtime ---
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies (libpcap / tcpdump utilities for offline traces)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend application
COPY backend/ ./backend/
COPY pytest.ini ./

# Copy built frontend assets
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create isolated quarantine and reports directories outside web root
RUN mkdir -p /app/backend/storage/quarantine /app/backend/storage/reports \
    && useradd -m -u 1001 tracex \
    && chown -R tracex:tracex /app

USER tracex

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
