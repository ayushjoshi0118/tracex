from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.database import init_db, SessionLocal
from backend.app.api.v1 import api_router
from backend.app.utils.sample_data import seed_initial_forensic_database

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    init_db()
    
    # Seed initial forensic test artifacts and demonstration cases
    db = SessionLocal()
    try:
        seed_initial_forensic_database(db)
    finally:
        db.close()
        
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Professional Defensive Digital Forensics & Threat Intelligence Platform",
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "platform": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "version": settings.VERSION,
        "quarantine_storage": str(settings.QUARANTINE_DIR),
        "database": "connected"
    }

@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "docs": "/docs",
        "health": "/api/health"
    }
