from fastapi import APIRouter
from backend.app.api.v1.files import router as files_router
from backend.app.api.v1.threat_intel import router as intel_router
from backend.app.api.v1.email import router as email_router
from backend.app.api.v1.network import router as network_router
from backend.app.api.v1.evidence import router as evidence_router
from backend.app.api.v1.investigations import router as investigations_router
from backend.app.api.v1.reports import router as reports_router

api_router = APIRouter()
api_router.include_router(files_router)
api_router.include_router(intel_router)
api_router.include_router(email_router)
api_router.include_router(network_router)
api_router.include_router(evidence_router)
api_router.include_router(investigations_router)
api_router.include_router(reports_router)
