export interface FileHashAnalysis {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

export interface FileSignatureMatch {
  expected_magic: string;
  detected_magic: string;
  description: string;
  matched_extension: string;
  claimed_extension: string;
  is_mismatch: boolean;
}

export interface FileForensicsResponse {
  file_id: string;
  filename: string;
  file_size_bytes: number;
  file_size_human: string;
  hashes: FileHashAnalysis;
  entropy: number;
  entropy_level: string;
  mime_type: string;
  detected_type: string;
  signature: FileSignatureMatch;
  strings_sample: string[];
  yara_matches: Array<{
    rule: string;
    tags: string[];
    severity: string;
    description: string;
  }>;
  security_verdict: string;
  quarantine_path: string;
  analysis_timestamp: string;
  analysis_notes: string[];
}

export interface ExternalSourceProvenance {
  provider: string;
  retrieval_timestamp: string;
  source_url?: string;
  is_live_api: boolean;
  status: string;
}

export interface ThreatScoreBreakdown {
  reputation_score: number;
  risk_level: string;
  classification: string;
  confidence: number;
}

export interface ThreatIntelReport {
  ioc_type: string;
  ioc_value: string;
  score: ThreatScoreBreakdown;
  categories: string[];
  geolocation?: {
    country: string;
    country_code: string;
    city?: string;
    lat?: number;
    lon?: number;
  };
  autonomous_system?: {
    asn: string;
    org: string;
  };
  threat_actors_or_campaigns: string[];
  external_sources: ExternalSourceProvenance[];
  raw_attributes: Record<string, any>;
  cached: boolean;
  query_timestamp: string;
}

export interface AuthResultDetail {
  protocol: string;
  status: string;
  status_category: 'verified' | 'failed' | 'missing_unauthenticated' | 'unverified';
  details: string;
  raw_header_value?: string;
}

export interface EmailHop {
  hop_number: number;
  by_server: string;
  from_server: string;
  ip?: string;
  timestamp_str?: string;
  delay_seconds?: number;
}

export interface SuspiciousEmailUrl {
  raw_url: string;
  defanged_url: string;
  domain: string;
  is_ip_address: boolean;
  is_lookalike_punycode: boolean;
  potential_risk: string;
}

export interface EmailForensicsResponse {
  message_id?: string;
  subject: string;
  sender: string;
  sender_name?: string;
  return_path?: string;
  reply_to?: string;
  sender_reply_to_mismatch: boolean;
  date_sent?: string;
  recipients: string[];
  cc: string[];
  auth_results: AuthResultDetail[];
  hops: EmailHop[];
  extracted_urls: SuspiciousEmailUrl[];
  attachments: Array<{
    filename: string;
    content_type: string;
    size_bytes: number;
    is_executable: boolean;
  }>;
  phishing_indicators: Array<{
    category: string;
    severity: string;
    indicator: string;
  }>;
  risk_score: number;
  verdict: string;
  analysis_timestamp: string;
}

export interface ProtocolStats {
  protocol: string;
  packet_count: number;
  byte_count: number;
  percentage: number;
}

export interface TopTalker {
  ip: string;
  packets_sent: number;
  packets_received: number;
  bytes_total: number;
  associated_domains: string[];
}

export interface DNSQueryRecord {
  query_name: string;
  query_type: string;
  response_ips: string[];
  client_ip: string;
  server_ip: string;
  timestamp: string;
  is_suspicious_tld: boolean;
  entropy: number;
}

export interface NetworkAnomaly {
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence_packets: number[];
}

export interface NetworkForensicsResponse {
  filename: string;
  file_size_bytes: number;
  total_packets: number;
  capture_duration_seconds: number;
  protocol_distribution: ProtocolStats[];
  top_talkers: TopTalker[];
  dns_queries: DNSQueryRecord[];
  http_requests: Array<{
    client_ip: string;
    server_ip: string;
    server_port: number;
    request_line: string;
    host: string;
    user_agent: string;
    has_auth: boolean;
  }>;
  conversations: Array<{
    connection: string;
    packets: number;
    bytes: number;
    src: string;
    dst: string;
    protocol: string;
  }>;
  anomalies: NetworkAnomaly[];
  analysis_timestamp: string;
}

export interface CustodyLog {
  id: number;
  evidence_id: string;
  action: string;
  performed_by: string;
  badge_number: string;
  timestamp: string;
  recorded_sha256: string;
  calculated_sha256: string;
  is_hash_match: boolean;
  reason?: string;
  custody_location: string;
  notes?: string;
}

export interface EvidenceItem {
  id: string;
  investigation_id?: string;
  name: string;
  original_filename: string;
  file_size_bytes: number;
  sha256: string;
  sha512: string;
  md5: string;
  mime_type: string;
  magic_signature?: string;
  file_type_mismatch: boolean;
  entropy: string;
  source_description?: string;
  acquired_by: string;
  badge_number: string;
  acquisition_timestamp: string;
  is_quarantined: boolean;
  integrity_status: 'verified' | 'compromised' | 'unverified' | 'file_missing';
  last_verified_at: string;
  last_verified_by?: string;
  notes?: string;
  custody_logs?: CustodyLog[];
}

export interface InvestigationSummary {
  id: string;
  title: string;
  description?: string;
  status: 'active' | 'in_review' | 'closed' | 'archived';
  priority: 'critical' | 'high' | 'medium' | 'low';
  lead_analyst: string;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  ioc_count: number;
  timeline_event_count: number;
}

export interface TimelineEvent {
  id: number;
  investigation_id: string;
  timestamp: string;
  title: string;
  description?: string;
  category: 'artifact' | 'network' | 'email' | 'system' | 'custody' | 'intel';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source: string;
  raw_reference?: string;
}

export interface InvestigationIOC {
  id: number;
  investigation_id: string;
  ioc_type: string;
  value: string;
  category: string;
  threat_score: number;
  classification: 'malicious' | 'suspicious' | 'benign' | 'unknown';
  attribution_source: string;
  first_seen: string;
  last_seen: string;
  notes?: string;
}

export interface InvestigationNote {
  id: number;
  investigation_id: string;
  author: string;
  badge_number: string;
  content: string;
  is_finding: 'observation' | 'interpretation' | 'hypothesis' | 'verified_fact';
  created_at: string;
}

export interface InvestigationDetail extends InvestigationSummary {
  evidence_items: EvidenceItem[];
  iocs: InvestigationIOC[];
  timeline_events: TimelineEvent[];
  notes: InvestigationNote[];
}

export interface HashComparisonDetail {
  algorithm: string;
  hash_a: string;
  hash_b: string;
  is_match: boolean;
}

export interface EvidenceComparisonResponse {
  item_a_id: string;
  item_a_name: string;
  item_b_id: string;
  item_b_name: string;
  hashes: HashComparisonDetail[];
  exact_hash_match: boolean;
  size_a_bytes: number;
  size_b_bytes: number;
  size_a_human: string;
  size_b_human: string;
  size_delta_bytes: number;
  size_ratio_percentage: number;
  entropy_a: number;
  entropy_b: number;
  entropy_delta: number;
  entropy_a_level: string;
  entropy_b_level: string;
  signature_a: string;
  signature_b: string;
  is_same_file_type: boolean;
  shared_strings_count: number;
  unique_to_a_count: number;
  unique_to_b_count: number;
  shared_strings_sample: string[];
  unique_to_a_sample: string[];
  unique_to_b_sample: string[];
  header_a_hex: string;
  header_b_hex: string;
  header_bytes_match: boolean;
  forensic_conclusions: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  group: string;
  data: Record<string, any>;
  severity?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  relation: string;
  confidence: number;
}

export interface InvestigationGraphResponse {
  investigation_id: string;
  title: string;
  total_nodes: number;
  total_edges: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

