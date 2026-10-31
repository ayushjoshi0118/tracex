from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class InvestigationIOC(Base):
    __tablename__ = "investigation_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(32), nullable=False)  # ip, domain, url, hash_md5, hash_sha256, email
    value = Column(String(512), nullable=False, index=True)
    category = Column(String(64), default="unknown", nullable=False)  # c2, phishing, malware, dropzone, scanner
    threat_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    classification = Column(String(32), default="unknown", nullable=False)  # malicious, suspicious, benign, unknown
    attribution_source = Column(String(128), default="Analyst Heuristic", nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    notes = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="iocs")
