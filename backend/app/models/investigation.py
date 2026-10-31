from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.orm import relationship
from backend.app.database import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)  # e.g., INV-2026-001
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="active", nullable=False)  # active, in_review, closed, archived
    priority = Column(String(32), default="medium", nullable=False)  # critical, high, medium, low
    lead_analyst = Column(String(128), default="Analyst-101", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    evidence_items = relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan")
    iocs = relationship("InvestigationIOC", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    notes = relationship("InvestigationNote", back_populates="investigation", cascade="all, delete-orphan")
