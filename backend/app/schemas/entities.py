from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

# --- EVIDENCE SCHEMAS ---

class EvidenceCreate(BaseModel):
    name: str
    investigation_id: Optional[str] = None
    source_description: Optional[str] = None
    acquired_by: str = "Analyst-101"
    badge_number: str = "BADGE-489"
    notes: Optional[str] = None

class EvidenceVerificationRequest(BaseModel):
    verified_by: str = "Analyst-101"
    badge_number: str = "BADGE-489"
    reason: str = "Routine Integrity Audit"
    notes: Optional[str] = None

class CustodyLogResponse(BaseModel):
    id: int
    evidence_id: str
    action: str
    performed_by: str
    badge_number: str
    timestamp: datetime
    recorded_sha256: str
    calculated_sha256: str
    is_hash_match: bool
    reason: Optional[str] = None
    custody_location: str
    notes: Optional[str] = None

    class Config:
        from_attributes = True

class EvidenceResponse(BaseModel):
    id: str
    investigation_id: Optional[str] = None
    name: str
    original_filename: str
    file_size_bytes: int
    sha256: str
    sha512: str
    md5: str
    mime_type: str
    magic_signature: Optional[str] = None
    file_type_mismatch: bool
    entropy: str
    source_description: Optional[str] = None
    acquired_by: str
    badge_number: str
    acquisition_timestamp: datetime
    is_quarantined: bool
    integrity_status: str
    last_verified_at: datetime
    last_verified_by: Optional[str] = None
    notes: Optional[str] = None
    custody_logs: List[CustodyLogResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


# --- INVESTIGATION SCHEMAS ---

class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "medium"  # critical, high, medium, low
    lead_analyst: str = "Analyst-101"

class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None  # active, in_review, closed, archived
    priority: Optional[str] = None
    lead_analyst: Optional[str] = None

class TimelineEventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str = "artifact"  # artifact, network, email, system, custody, intel
    severity: str = "info"  # critical, high, medium, low, info
    source: str = "Analyst Entry"
    raw_reference: Optional[str] = None
    timestamp: Optional[datetime] = None

class TimelineEventResponse(BaseModel):
    id: int
    investigation_id: str
    timestamp: datetime
    title: str
    description: Optional[str] = None
    category: str
    severity: str
    source: str
    raw_reference: Optional[str] = None

    class Config:
        from_attributes = True

class IOCCreate(BaseModel):
    ioc_type: str  # ip, domain, url, hash_md5, hash_sha256, email
    value: str
    category: str = "c2"
    threat_score: float = 0.0
    classification: str = "unknown"  # malicious, suspicious, benign, unknown
    attribution_source: str = "Analyst Entry"
    notes: Optional[str] = None

class IOCResponse(BaseModel):
    id: int
    investigation_id: str
    ioc_type: str
    value: str
    category: str
    threat_score: float
    classification: str
    attribution_source: str
    first_seen: datetime
    last_seen: datetime
    notes: Optional[str] = None

    class Config:
        from_attributes = True

class InvestigationNoteCreate(BaseModel):
    author: str = "Analyst"
    badge_number: str = "AN-001"
    content: str
    is_finding: str = "observation"  # observation, interpretation, hypothesis, verified_fact

class InvestigationNoteResponse(BaseModel):
    id: int
    investigation_id: str
    author: str
    badge_number: str
    content: str
    is_finding: str
    created_at: datetime

    class Config:
        from_attributes = True

class InvestigationDetailResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    lead_analyst: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    ioc_count: int = 0
    timeline_event_count: int = 0
    evidence_items: List[EvidenceResponse] = Field(default_factory=list)
    iocs: List[IOCResponse] = Field(default_factory=list)
    timeline_events: List[TimelineEventResponse] = Field(default_factory=list)
    notes: List[InvestigationNoteResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True

class InvestigationSummaryResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    lead_analyst: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    ioc_count: int = 0
    timeline_event_count: int = 0

    class Config:
        from_attributes = True


# --- REPORT SCHEMAS ---

class ReportExportRequest(BaseModel):
    format: str = "json"  # pdf or json
    include_evidence: bool = True
    include_timeline: bool = True
    include_iocs: bool = True
    include_notes: bool = True
    analyst_signature: str = "Lead Forensic Examiner"
    badge_number: str = "BF-9921"
