from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(128), default="Analyst", nullable=False)
    badge_number = Column(String(64), default="AN-001", nullable=False)
    content = Column(Text, nullable=False)
    is_finding = Column(String(32), default="observation", nullable=False)  # observation, interpretation, hypothesis, verified_fact
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    investigation = relationship("Investigation", back_populates="notes")
