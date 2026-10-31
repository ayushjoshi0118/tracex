from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, BigInteger, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True, index=True)  # e.g., EVD-9A3F1B
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    
    # Cryptographic Fingerprints
    sha256 = Column(String(64), nullable=False, index=True)
    sha512 = Column(String(128), nullable=False)
    md5 = Column(String(32), nullable=False)
    
    # Forensic Classification
    mime_type = Column(String(128), default="application/octet-stream", nullable=False)
    magic_signature = Column(String(255), nullable=True)
    file_type_mismatch = Column(Boolean, default=False, nullable=False)
    entropy = Column(String(32), default="0.0", nullable=False)
    
    # Acquisition Metadata
    source_description = Column(Text, nullable=True)
    acquired_by = Column(String(128), nullable=False)
    badge_number = Column(String(64), nullable=False)
    acquisition_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_quarantined = Column(Boolean, default=True, nullable=False)
    
    # Integrity Verification State
    integrity_status = Column(String(32), default="verified", nullable=False)  # verified, compromised, unverified
    last_verified_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_verified_by = Column(String(128), nullable=True)
    notes = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="evidence_items")
    custody_logs = relationship("CustodyLog", back_populates="evidence", cascade="all, delete-orphan", order_by="CustodyLog.timestamp.desc()")
