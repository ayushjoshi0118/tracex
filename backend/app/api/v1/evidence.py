from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.config import settings
from backend.app.models.evidence import Evidence
from backend.app.schemas.entities import (
    EvidenceResponse,
    CustodyLogResponse,
    EvidenceVerificationRequest
)
from backend.app.services.evidence_service import (
    register_evidence_item,
    verify_evidence_integrity,
    transfer_custody
)
from backend.app.utils.security import generate_quarantine_path

router = APIRouter(prefix="/evidence", tags=["Evidence Management"])

@router.post("/register", response_model=EvidenceResponse)
async def register_evidence(
    file: UploadFile = File(...),
    name: str = Form(...),
    investigation_id: Optional[str] = Form(None),
    acquired_by: str = Form("Analyst-101"),
    badge_number: str = Form("BADGE-489"),
    source_description: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Registers an evidence artifact into the digital locker with cryptographic fingerprints
    and an immutable Chain of Custody entry.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have a valid filename"
        )

    target_path, stored_filename = generate_quarantine_path(settings.QUARANTINE_DIR, file.filename)

    total_written = 0
    with open(target_path, "wb") as buffer:
        while chunk := await file.read(64 * 1024):
            total_written += len(chunk)
            if total_written > settings.MAX_UPLOAD_SIZE_BYTES:
                buffer.close()
                if target_path.exists():
                    target_path.unlink()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File exceeds maximum evidence size limit"
                )
            buffer.write(chunk)

    evidence = register_evidence_item(
        db=db,
        file_path=target_path,
        original_filename=file.filename,
        stored_filename=stored_filename,
        name=name,
        acquired_by=acquired_by,
        badge_number=badge_number,
        investigation_id=investigation_id,
        source_description=source_description,
        notes=notes
    )
    return evidence

@router.get("/", response_model=List[EvidenceResponse])
def list_evidence(investigation_id: Optional[str] = None, db: Session = Depends(get_db)):
    """List all registered evidence items, optionally filtered by investigation ID."""
    query = db.query(Evidence)
    if investigation_id:
        query = query.filter(Evidence.investigation_id == investigation_id)
    return query.order_by(Evidence.acquisition_timestamp.desc()).all()

@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence_details(evidence_id: str, db: Session = Depends(get_db)):
    """Fetch complete forensic details and chain of custody logs for an evidence item."""
    item = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )
    return item

@router.post("/{evidence_id}/verify", response_model=CustodyLogResponse)
def run_integrity_audit(
    evidence_id: str,
    payload: EvidenceVerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Executes an on-disk cryptographic integrity audit.
    Recalculates the SHA-256 hash and validates against baseline.
    """
    _, custody_log = verify_evidence_integrity(
        db=db,
        evidence_id=evidence_id,
        performed_by=payload.verified_by,
        badge_number=payload.badge_number,
        reason=payload.reason,
        notes=payload.notes
    )
    return custody_log
