from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), default="artifact", nullable=False)  # artifact, network, email, system, custody, intel
    severity = Column(String(32), default="info", nullable=False)  # critical, high, medium, low, info
    source = Column(String(128), default="Analyst Entry", nullable=False)
    raw_reference = Column(String(255), nullable=True)  # File hash, packet id, email message-id, etc.

    investigation = relationship("Investigation", back_populates="timeline_events")
