# TRACEX System Architecture & Threat Model

**Platform**: TRACEX Digital Forensics & Threat Intelligence Platform  
**Tagline**: *Investigate. Analyze. Correlate. Discover.*  
**Standard Compliance**: ISO/IEC 27037 (Digital Evidence Handling), RFC 5322, RFC 7208, RFC 6376, RFC 7489, RFC 8617  

---

## 1. Architectural Principles

TRACEX is designed with a defense-in-depth posture tailored specifically for forensic evidence processing and incident triage:

1. **Zero-Execution Quarantine Sandbox**: Uploaded forensic artifacts are stored strictly outside the public web root in an isolated directory (`/backend/storage/quarantine`) with path-traversal countermeasures, execution restrictions (`rw-------` / `0o600`), and safe byte streaming.
2. **Cryptographic Integrity & Chain of Custody**: Every artifact is fingerprinted on acquisition with SHA-256, SHA-512, and MD5 hashes. Real-time on-disk audit checks recalculate checksums to detect physical file tampering or bit-rot.
3. **Strict Epistemic Separation**: Analysis results and reports enforce an explicit distinction between:
   - **Observed Facts**: Cryptographic baselines, packet payload bytes, verified header structures.
   - **External Threat Intelligence**: Curated and live reputation records with provider provenance and retrieval timestamps.
   - **Analyst Interpretations**: Deductive hypotheses and investigative notes.
4. **Non-Attribution Standard**: Metadata anomalies, high Shannon entropy, and file extension mismatches are structural heuristics and are never claimed as definitive malware detection without dynamic behavioral confirmation or reverse engineering.

---

## 2. High-Level System Architecture

```mermaid
flowchart TD
    subgraph Client["Presentation Tier (React 19 + TypeScript + Vite)"]
        UI["SOC Command Center Dashboard"]
        M1["Module 1: File Forensics"]
        M2["Module 2: Threat Intelligence"]
        M3["Module 3: Email Forensics"]
        M4["Module 4: PCAP Network Inspector"]
        M5["Module 5: Evidence Locker"]
        M6["Module 6: Case Workspace"]
        M7["Module 7: Certified Reports"]
        Graph["Evidence Correlation Graph"]
        Compare["Metadata Comparison Matrix"]
    end

    subgraph Gateway["API & Security Gateway (FastAPI)"]
        Router["FastAPI Route Dispatcher"]
        SecHeaders["Security Headers Middleware (CSP, HSTS, X-Frame)"]
        PathGuard["Path Traversal & Quarantine Guard"]
        Streamer["Chunk Streamer (50 MB Threshold)"]
    end

    subgraph CoreEngines["Forensic Analysis & Intelligence Engines"]
        HashEngine["Cryptographic Hasher (SHA-256 / SHA-512 / MD5)"]
        EntropyEngine["Shannon Entropy Profiler (0.0 - 8.0)"]
        PEParser["PE Deep Parser (COFF, Optional, Section Entropy)"]
        ELFParser["ELF Binary Parser (32/64-bit, ABI, Machine)"]
        PDFParser["PDF Active Element Scanner (/JS, /Launch, /OpenAction)"]
        ContainerParser["Office OpenXML & ZIP Safe Parser (VBA Macros)"]
        EMLParser["RFC 5322 & ARC Relay Parser (Hop Latency, Auth)"]
        PCAPParser["Scapy Offline Frame DPI (DNS, HTTP, TLS SNI, TCP Flags)"]
        IntelEngine["Threat Feeds & Curated Repository (Provenance Tracking)"]
        CorrelationEngine["Multi-Stage IOC Correlator (Cross-Disciplinary Weighting)"]
        ReportEngine["ReportLab Forensic PDF & JSON Export"]
    end

    subgraph DataTier["Storage & Persistence Tier"]
        Quarantine[("Quarantine Vault (rw------- / Outside Web Root)")]
        RelationalDB[("SQLAlchemy Relational Database (SQLite / PostgreSQL)")]
        CustodyLedger[("Immutable Chain of Custody Ledger")]
    end

    Client --> Router
    Router --> SecHeaders
    SecHeaders --> PathGuard
    PathGuard --> Streamer
    Streamer --> Quarantine

    Router --> CoreEngines
    CoreEngines --> HashEngine
    CoreEngines --> EntropyEngine
    CoreEngines --> PEParser
    CoreEngines --> ELFParser
    CoreEngines --> PDFParser
    CoreEngines --> ContainerParser
    CoreEngines --> EMLParser
    CoreEngines --> PCAPParser
    CoreEngines --> IntelEngine
    CoreEngines --> CorrelationEngine
    CoreEngines --> ReportEngine

    Router --> RelationalDB
    CoreEngines --> RelationalDB
    Streamer --> CustodyLedger
```

---

## 3. Evidence Lifecycle & Chain of Custody Sequence

The diagram below illustrates the complete lifecycle of a digital evidence artifact from physical acquisition through cryptographic verification and formal custody transfer:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Forensic Examiner
    participant Gateway as API Gateway
    participant Guard as Security Guard
    participant Vault as Quarantine Vault
    participant Hash as Hashing Engine
    participant DB as Relational Database
    participant Ledger as Chain of Custody Ledger

    Analyst->>Gateway: POST /api/v1/evidence/register (File, Badge, Source)
    Gateway->>Guard: Validate filename & inspect for path traversal
    Guard->>Vault: Write byte chunks (max 50 MB) & enforce chmod 0600
    Vault-->>Hash: Stream bytes for SHA-256, SHA-512, MD5
    Hash-->>Gateway: Cryptographic Baselines
    Gateway->>DB: Create Evidence record (EVD-XXXXXX, baseline hash, metadata)
    Gateway->>Ledger: Append Genesis Custody Log (Badge, Timestamp, Baseline Match)
    Gateway-->>Analyst: Return 201 Created (Evidence ID, Baseline Hash)

    Note over Analyst,Ledger: Routine Cryptographic Audit / Tamper Verification
    Analyst->>Gateway: POST /api/v1/evidence/{id}/verify (Badge, Reason)
    Gateway->>Vault: Read physical bytes from quarantine on disk
    Vault->>Hash: Recalculate SHA-256 hash
    Hash-->>Gateway: Current Checksum
    alt Current Checksum == Baseline Checksum
        Gateway->>DB: Set integrity_status = 'verified'
        Gateway->>Ledger: Append 'Integrity Audit Passed' Log
    else Current Checksum != Baseline Checksum
        Gateway->>DB: Set integrity_status = 'compromised'
        Gateway->>Ledger: Append 'Tamper Detected - Hash Mismatch' Alert Log
    end
    Gateway-->>Analyst: Return Verification Result & Updated Ledger Checkpoint
```

---

## 4. Multi-Stage IOC Correlation Architecture

```mermaid
flowchart LR
    subgraph Inputs["Heterogeneous Evidence Sources"]
        F1["Quarantined Executable (File Strings)"]
        F2["Network Capture (PCAP Outbound Sessions)"]
        F3["Phishing Email (Relay Hops & URLs)"]
    end

    subgraph Correlator["TraceX IOC Correlation Engine"]
        Extractor["Indicator Normalization & Type Identifier"]
        Aggregator["Cross-Source Corroboration Matrix"]
        Scorer["Weighted Confidence Scoring"]
        TriCat["Evidentiary Tri-Categorizer"]
    end

    subgraph Outputs["Tri-Categorized Findings"]
        V1["[VERIFIED EVIDENCE] Directly Observed in Local Quarantined Artifacts"]
        V2["[EXTERNAL INTEL] Matched Historical Repositories with Timestamps"]
        V3["[HEURISTIC OBSERVATION] Statistical Anomalies Requiring Validation"]
    end

    Inputs --> Extractor
    Extractor --> Aggregator
    Aggregator --> Scorer
    Scorer --> TriCat
    TriCat --> Outputs
```

---

## 5. STRIDE Threat Model & Countermeasures

| Threat Category | Potential Threat | TraceX Countermeasure |
|---|---|---|
| **Spoofing** | Attacker fabricates evidence records or impersonates authorized examiner. | All custody transactions require mandatory analyst name and badge number. Genesis baseline SHA-256 hash is immutably sealed in the audit ledger upon acquisition. |
| **Tampering** | Evidence files on disk modified or corrupted (bit-rot or unauthorized alteration). | Real-time on-disk integrity audit re-reads quarantined bytes and recalculates SHA-256. Any single-bit discrepancy immediately marks the artifact as `COMPROMISED` and records an immutable tamper alert log. |
| **Repudiation** | Analyst denies transferring evidence custody or modifying investigation dossier. | Custody transfers record releasing badge, recipient badge, reason, destination vault location, and timestamp in an append-only ledger. |
| **Information Disclosure** | Quarantined malware or sensitive seized artifacts accessed via web root or path traversal. | Uploads stored strictly outside web root. Filenames are stripped of path separators, null bytes, and salted with UUID prefixes. Directory resolution validates that files cannot escape quarantine root. |
| **Denial of Service** | Malformed PCAP files, ZIP bombs, or multi-gigabyte uploads crash the server. | 50 MB hard ceiling on file uploads via streaming. Libpcap packet counter capped at 15,000 frames. ZIP Central Directory inspected without extraction, mitigating decompression bombs. |
| **Elevation of Privilege** | Attacker uploads executable (.exe/.elf) and triggers execution via the backend host. | Quarantined files are stored with non-executable permissions (`chmod 0o600`). The backend performs purely static stream analysis; no shell commands (`os.system`, `subprocess`) or interpreters are ever executed on uploaded files. Docker container runs under non-root user `tracex` (UID 1001). |

---

## 6. Defensive Forensic Engineering Guidelines

1. **Non-Attribution Guarantee**: File extension mismatches, high Shannon entropy, and suspicious ports are structural indicators. TraceX never labels a sample as malware based solely on metadata.
2. **Provenance Transparency**: External threat intelligence always cites the provider, retrieval timestamp, and query status. Data is never simulated or fabricated.
3. **Auditable Custody**: Evidence is never overwritten or deleted silently. All transfers and integrity checks are cryptographically verifiable.
