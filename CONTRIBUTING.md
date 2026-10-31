# Contributing to TRACEX

Thank you for your interest in contributing to TRACEX! We welcome defensive digital forensics tools, threat intelligence integrations, and usability improvements.

## Code of Conduct

- TRACEX is committed to defensive security and educational research.
- Do NOT submit pull requests containing offensive attack payloads, weaponized exploits, or invasive network scanning routines.

## Development Workflow

### Prerequisites
- Python 3.10+
- Node.js 18+ (Node 20+ recommended)
- npm or pnpm

### Backend Setup
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r backend/requirements.txt
pytest -v backend/tests
```

### Frontend Setup
```bash
cd frontend
npm install
npm run build
npm test
```

### Pull Request Guidelines
1. Ensure all backend tests (`pytest`) and frontend tests (`vitest`) pass.
2. Maintain strict separation of observed facts, external intelligence, and analyst hypotheses.
3. Preserve all non-destructive quarantine boundaries.
