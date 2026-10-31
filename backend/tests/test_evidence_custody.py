import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import SessionLocal, init_db
from backend.app.services.evidence_service import (
    register_evidence_item,
    verify_evidence_integrity,
    transfer_custody
)
from backend.app.utils.security import generate_quarantine_path, sanitize_filename

client = TestClient(app)

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

def test_transfer_custody_and_audit_trail():
    init_db()
    db = SessionLocal()

    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
        f.write(b"VOLATILE MEMORY DUMP PAYLOAD 2026")
        temp_path = Path(f.name)

    try:
        ev = register_evidence_item(
            db=db,
            file_path=temp_path,
            original_filename="memory_dump.raw",
            stored_filename="mem_dump_stored.raw",
            name="Host RAM Dump Evidence",
            acquired_by="First Responder A",
            badge_number="FR-101"
        )

        custody_log = transfer_custody(
            db=db,
            evidence_id=ev.id,
            transferred_to="Malware Lab Analyst",
            recipient_badge="LAB-404",
            transferred_by="First Responder A",
            releasing_badge="FR-101",
            new_location="Classified Vault B",
            reason="Malware dynamic reverse engineering",
            notes="Transferred in sealed anti-static bag."
        )

        assert custody_log.badge_number == "LAB-404"
        assert custody_log.is_hash_match is True
        assert "Classified Vault B" in custody_log.custody_location
        assert "FR-101" in custody_log.performed_by
    finally:
        db.close()
        if temp_path.exists():
            temp_path.unlink()

def test_missing_file_integrity_audit():
    init_db()
    db = SessionLocal()

    with tempfile.NamedTemporaryFile(suffix=".tmp", delete=False) as f:
        f.write(b"TEMPORARY FORENSIC DUMP")
        temp_path = Path(f.name)

    try:
        ev = register_evidence_item(
            db=db,
            file_path=temp_path,
            original_filename="deleted_later.tmp",
            stored_filename="deleted_later_stored.tmp",
            name="Temporary Evidence",
            acquired_by="Analyst C",
            badge_number="AC-300"
        )

        # Unlink file before checking integrity
        temp_path.unlink()

        ev_missing, log_missing = verify_evidence_integrity(
            db=db,
            evidence_id=ev.id,
            performed_by="Auditor D",
            badge_number="AUD-400"
        )

        assert ev_missing.integrity_status == "file_missing"
        assert log_missing.is_hash_match is False
        assert log_missing.calculated_sha256 == "FILE_NOT_FOUND_ON_DISK"
    finally:
        db.close()
        if temp_path.exists():
            temp_path.unlink()

def test_path_traversal_sanitization():
    # Attempt directory traversal filenames
    malicious_names = [
        "../../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\cmd.exe",
        "file/../../root.sh",
        "\x00hidden.exe",
        ".hidden_profile"
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        q_dir = Path(temp_dir)
        for name in malicious_names:
            clean = sanitize_filename(name)
            assert ".." not in clean
            assert not clean.startswith("/")
            assert not clean.startswith("\\")
            target_path, stored_name = generate_quarantine_path(q_dir, name)
            assert target_path.parent == q_dir.resolve()

def test_security_headers_middleware():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
