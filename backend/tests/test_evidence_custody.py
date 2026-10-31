import tempfile
from pathlib import Path
from backend.app.database import SessionLocal, init_db
from backend.app.services.evidence_service import (
    register_evidence_item,
    verify_evidence_integrity,
    transfer_custody
)

def test_evidence_lifecycle_and_tamper_detection():
    init_db()
    db = SessionLocal()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"ORIGINAL FORENSIC DISK SECTOR DATA 2026")
        temp_path = Path(f.name)

    try:
        # 1. Register evidence
        ev = register_evidence_item(
            db=db,
            file_path=temp_path,
            original_filename="disk_sector.bin",
            stored_filename="disk_sector_stored.bin",
            name="Seized Hard Drive Sector #12",
            acquired_by="Examiner Alpha",
            badge_number="BX-100"
        )
        assert ev.id.startswith("EVD-")
        assert ev.integrity_status == "verified"
        assert len(ev.custody_logs) == 1
        assert ev.custody_logs[0].is_hash_match is True

        # 2. Verify intact integrity
        ev_verified, log_pass = verify_evidence_integrity(
            db=db,
            evidence_id=ev.id,
            performed_by="Auditor Beta",
            badge_number="AUD-200"
        )
        assert ev_verified.integrity_status == "verified"
        assert log_pass.is_hash_match is True

        # 3. Simulate unauthorized bit modification on disk (tampering)
        with open(temp_path, "wb") as f:
            f.write(b"TAMPERED MODIFIED DATA CORRUPTED")

        # 4. Verify that integrity check detects tamper
        ev_tampered, log_fail = verify_evidence_integrity(
            db=db,
            evidence_id=ev.id,
            performed_by="Auditor Beta",
            badge_number="AUD-200"
        )
        assert ev_tampered.integrity_status == "compromised"
        assert log_fail.is_hash_match is False
        assert "Tamper Detected" in log_fail.action
    finally:
        db.close()
        if temp_path.exists():
            temp_path.unlink()
