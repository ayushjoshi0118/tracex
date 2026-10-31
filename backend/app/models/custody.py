from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class CustodyLog(Base):
    """
    Chain of Custody audit record.
    Preserves an immutable chronological ledger of evidence handling.
    """
    __tablename__ = "custody_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(64), nullable=False)  # acquired, transferred, verified, analyzed, check_out, check_in, tamper_detected
    performed_by = Column(String(128), nullable=False)
    badge_number = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Cryptographic Checkpoint
    recorded_sha256 = Column(String(64), nullable=False)
    calculated_sha256 = Column(String(64), nullable=False)
    is_hash_match = Column(Boolean, default=True, nullable=False)
    
    reason = Column(String(255), nullable=True)
    custody_location = Column(String(255), default="Secure Forensic Quarantine Locker", nullable=False)
    notes = Column(Text, nullable=True)

    evidence = relationship("Evidence", back_populates="custody_logs")
