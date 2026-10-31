import os
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyLog
from backend.app.models.investigation import Investigation
from backend.app.services.file_forensics import (
    calculate_file_hashes,
    detect_file_signature,
    format_human_bytes
)
from backend.app.utils.security import calculate_shannon_entropy

def register_evidence_item(
    db: Session,
    file_path: Path,
    original_filename: str,
    stored_filename: str,
    name: str,
    acquired_by: str,
    badge_number: str,
    investigation_id: Optional[str] = None,
    source_description: Optional[str] = None,
    notes: Optional[str] = None
) -> Evidence:
    """
    Registers a new piece of forensic evidence.
    Generates cryptographic fingerprints, initial custody ledger record, and stores outside web root.
    """
    # Verify investigation exists if provided
    if investigation_id:
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation with ID '{investigation_id}' does not exist"
            )

    evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    file_size = os.path.getsize(file_path)

    # Compute authoritative cryptographic hashes
    hashes = calculate_file_hashes(file_path)

    # Inspect headers for signature and entropy
    with open(file_path, "rb") as f:
        header_sample = f.read(min(file_size, 64 * 1024))
        
    sig = detect_file_signature(header_sample, original_filename)
    entropy_val = str(calculate_shannon_entropy(header_sample))

    now = datetime.now(timezone.utc)

    # Create Evidence Record
    evidence = Evidence(
        id=evidence_id,
        investigation_id=investigation_id,
        name=name or original_filename,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_path=str(file_path.resolve()),
        file_size_bytes=file_size,
        sha256=hashes.sha256,
        sha512=hashes.sha512,
        md5=hashes.md5,
        mime_type=sig.matched_extension,
        magic_signature=sig.description,
        file_type_mismatch=sig.is_mismatch,
        entropy=entropy_val,
        source_description=source_description or "Digital Forensic Seizure",
        acquired_by=acquired_by,
        badge_number=badge_number,
        acquisition_timestamp=now,
        is_quarantined=True,
        integrity_status="verified",
        last_verified_at=now,
        last_verified_by=acquired_by,
        notes=notes
    )
    db.add(evidence)
    db.flush()

    # Append Genesis Chain of Custody record
    genesis_custody = CustodyLog(
        evidence_id=evidence_id,
        action="Evidence Acquisition & Ingestion",
        performed_by=acquired_by,
        badge_number=badge_number,
        timestamp=now,
        recorded_sha256=hashes.sha256,
        calculated_sha256=hashes.sha256,
        is_hash_match=True,
        reason="Initial secure digital acquisition and cryptographic hashing",
        custody_location="Forensic Quarantine Vault",
        notes="Evidence seized, hashed, and entered into custody chain with SHA-256 fingerprint."
    )
    db.add(genesis_custody)
    db.commit()
    db.refresh(evidence)

    return evidence

def verify_evidence_integrity(
    db: Session,
    evidence_id: str,
    performed_by: str,
    badge_number: str,
    reason: str = "Cryptographic Audit",
    notes: Optional[str] = None
) -> Tuple[Evidence, CustodyLog]:
    """
    Performs on-disk bit-level integrity verification.
    Recalculates the SHA-256 hash of the quarantined file and compares with recorded baseline.
    Logs an immutable custody checkpoint.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )

    target_file = Path(evidence.file_path)
    now = datetime.now(timezone.utc)

    if not target_file.exists():
        evidence.integrity_status = "file_missing"
        evidence.last_verified_at = now
        evidence.last_verified_by = performed_by
        
        custody_log = CustodyLog(
            evidence_id=evidence_id,
            action="Integrity Audit Failed - File Missing",
            performed_by=performed_by,
            badge_number=badge_number,
            timestamp=now,
            recorded_sha256=evidence.sha256,
            calculated_sha256="FILE_NOT_FOUND_ON_DISK",
            is_hash_match=False,
            reason=reason,
            custody_location="Quarantine Storage",
            notes="CRITICAL ERROR: Quarantined artifact file missing from physical storage."
        )
        db.add(custody_log)
        db.commit()
        db.refresh(evidence)
        return evidence, custody_log

    # Recalculate hash on disk
    current_hashes = calculate_file_hashes(target_file)
    is_match = (current_hashes.sha256.lower() == evidence.sha256.lower())

    if is_match:
        evidence.integrity_status = "verified"
        log_action = "Integrity Audit Passed"
        log_notes = f"SHA-256 verification succeeded ({current_hashes.sha256[:16]}...). File integrity is intact."
    else:
        evidence.integrity_status = "compromised"
        log_action = "Tamper Detected - Hash Mismatch"
        log_notes = f"CRITICAL: Cryptographic fingerprint discrepancy detected! Baseline: {evidence.sha256}, Current: {current_hashes.sha256}"

    evidence.last_verified_at = now
    evidence.last_verified_by = performed_by

    custody_log = CustodyLog(
        evidence_id=evidence_id,
        action=log_action,
        performed_by=performed_by,
        badge_number=badge_number,
        timestamp=now,
        recorded_sha256=evidence.sha256,
        calculated_sha256=current_hashes.sha256,
        is_hash_match=is_match,
        reason=reason,
        custody_location="Forensic Quarantine Vault",
        notes=f"{notes or ''} - {log_notes}".strip()
    )

    db.add(custody_log)
    db.commit()
    db.refresh(evidence)
    return evidence, custody_log

def transfer_custody(
    db: Session,
    evidence_id: str,
    transferred_to: str,
    recipient_badge: str,
    transferred_by: str,
    releasing_badge: str,
    new_location: str,
    reason: str,
    notes: Optional[str] = None
) -> CustodyLog:
    """
    Records a formal custody transfer of an evidence item.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )

    # First check integrity before transfer
    target_file = Path(evidence.file_path)
    current_hash = calculate_file_hashes(target_file).sha256 if target_file.exists() else "FILE_MISSING"
    is_match = (current_hash.lower() == evidence.sha256.lower())
    now = datetime.now(timezone.utc)

    custody_log = CustodyLog(
        evidence_id=evidence_id,
        action="Custody Transfer",
        performed_by=f"{transferred_by} (Badge: {releasing_badge}) -> {transferred_to} (Badge: {recipient_badge})",
        badge_number=recipient_badge,
        timestamp=now,
        recorded_sha256=evidence.sha256,
        calculated_sha256=current_hash,
        is_hash_match=is_match,
        reason=reason,
        custody_location=new_location,
        notes=notes or f"Custody transferred from {transferred_by} to {transferred_to}."
    )

    db.add(custody_log)
    db.commit()
    return custody_log
