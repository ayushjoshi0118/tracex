from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

# --- MODULE 1: FILE FORENSICS SCHEMAS ---

class FileHashAnalysis(BaseModel):
    md5: str
    sha1: str
    sha256: str
    sha512: str

class FileSignatureMatch(BaseModel):
    expected_magic: str
    detected_magic: str
    description: str
    matched_extension: str
    claimed_extension: str
    is_mismatch: bool

class FileForensicsResponse(BaseModel):
    file_id: str
    filename: str
    file_size_bytes: int
    file_size_human: str
    hashes: FileHashAnalysis
    entropy: float
    entropy_level: str  # low, normal, packed/encrypted
    mime_type: str
    detected_type: str
    signature: FileSignatureMatch
    strings_sample: list[str] = Field(default_factory=list)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)
    security_verdict: str  # clean, suspicious, malicious, anomaly_detected
    quarantine_path: str
    analysis_timestamp: datetime
    analysis_notes: list[str] = Field(default_factory=list)


# --- MODULE 2: THREAT INTELLIGENCE SCHEMAS ---

class ExternalSourceProvenance(BaseModel):
    provider: str
    retrieval_timestamp: datetime
    source_url: Optional[str] = None
    is_live_api: bool
    status: str

class ThreatScoreBreakdown(BaseModel):
    reputation_score: float  # 0 to 100
    risk_level: str  # Clean, Low, Suspicious, Malicious, Critical
    classification: str  # C2, Phishing, Malware, Scanner, Dropzone, Unknown
    confidence: float

class ThreatIntelReport(BaseModel):
    ioc_type: str  # ip, domain, url, hash
    ioc_value: str
    score: ThreatScoreBreakdown
    categories: list[str] = Field(default_factory=list)
    geolocation: Optional[dict[str, Any]] = None
    autonomous_system: Optional[dict[str, Any]] = None
    whois_summary: Optional[dict[str, Any]] = None
    threat_actors_or_campaigns: list[str] = Field(default_factory=list)
    external_sources: list[ExternalSourceProvenance] = Field(default_factory=list)
    raw_attributes: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False
    query_timestamp: datetime


# --- MODULE 3: EMAIL FORENSICS SCHEMAS ---

class AuthResultDetail(BaseModel):
    protocol: str  # SPF, DKIM, DMARC
    status: str  # pass, fail, softfail, neutral, missing, not_configured
    status_category: str  # verified, failed, missing_unauthenticated
    details: str
    raw_header_value: Optional[str] = None

class EmailHop(BaseModel):
    hop_number: int
    by_server: str
    from_server: str
    ip: Optional[str] = None
    timestamp_str: Optional[str] = None
    delay_seconds: Optional[int] = None

class SuspiciousEmailUrl(BaseModel):
    raw_url: str
    defanged_url: str
    domain: str
    is_ip_address: bool
    is_lookalike_punycode: bool
    potential_risk: str

class EmailForensicsResponse(BaseModel):
    message_id: Optional[str] = None
    subject: str
    sender: str
    sender_name: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    sender_reply_to_mismatch: bool
    date_sent: Optional[str] = None
    recipients: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    auth_results: list[AuthResultDetail] = Field(default_factory=list)
    hops: list[EmailHop] = Field(default_factory=list)
    extracted_urls: list[SuspiciousEmailUrl] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    phishing_indicators: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: float
    verdict: str  # Clean, Suspicious, Likely Phishing, High Risk Spoofing
    analysis_timestamp: datetime


# --- MODULE 4: NETWORK FORENSICS SCHEMAS ---

class ProtocolStats(BaseModel):
    protocol: str
    packet_count: int
    byte_count: int
    percentage: float

class TopTalker(BaseModel):
    ip: str
    packets_sent: int
    packets_received: int
    bytes_total: int
    associated_domains: list[str] = Field(default_factory=list)

class DNSQueryRecord(BaseModel):
    query_name: str
    query_type: str
    response_ips: list[str] = Field(default_factory=list)
    client_ip: str
    server_ip: str
    timestamp: str
    is_suspicious_tld: bool
    entropy: float

class NetworkAnomaly(BaseModel):
    title: str
    description: str
    severity: str  # low, medium, high, critical
    evidence_packets: list[int] = Field(default_factory=list)

class NetworkForensicsResponse(BaseModel):
    filename: str
    file_size_bytes: int
    total_packets: int
    capture_duration_seconds: float
    protocol_distribution: list[ProtocolStats] = Field(default_factory=list)
    top_talkers: list[TopTalker] = Field(default_factory=list)
    dns_queries: list[DNSQueryRecord] = Field(default_factory=list)
    http_requests: list[dict[str, Any]] = Field(default_factory=list)
    conversations: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[NetworkAnomaly] = Field(default_factory=list)
    analysis_timestamp: datetime
