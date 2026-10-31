<div align="center">

# TRACEX
### Defensive Digital Forensics & Threat Intelligence Platform

**Investigate. Analyze. Correlate. Discover.**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Pytest](https://img.shields.io/badge/Pytest-27%2F27%20Passing-brightgreen?style=flat&logo=pytest&logoColor=white)](https://pytest.org)
[![Vitest](https://img.shields.io/badge/Vitest-Passing-729B1B?style=flat&logo=vitest&logoColor=white)](https://vitest.dev)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*A professional, extensible, security-conscious digital forensics platform designed for defensive cybersecurity investigations, educational research, and threat correlation.*

</div>

---

## Table of Contents

- [Platform Overview](#platform-overview)
- [Key Architectural Tenets](#key-architectural-tenets)
- [Module Deep Dive](#module-deep-dive)
  - [Module 1: File Forensics & Deep Structural Parsing](#module-1-file-forensics--deep-structural-parsing)
  - [Module 2: Threat Intelligence & Correlation Engine](#module-2-threat-intelligence--correlation-engine)
  - [Module 3: Email Forensics & Relay Analysis](#module-3-email-forensics--relay-analysis)
  - [Module 4: Network Forensics (Offline PCAP DPI)](#module-4-network-forensics-offline-pcap-dpi)
  - [Module 5: Evidence Management & Chain of Custody](#module-5-evidence-management--chain-of-custody)
  - [Module 6: Investigation Workspace & Relationship Graph](#module-6-investigation-workspace--relationship-graph)
  - [Module 7: Certified Forensic Report Generation](#module-7-certified-forensic-report-generation)
- [Defensive Security Posture](#defensive-security-posture)
- [Documentation & Technical References](#documentation--technical-references)
- [Tech Stack](#tech-stack)
- [Quick Start Guide](#quick-start-guide)
  - [Local Development](#local-development)
  - [Docker Compose Deployment](#docker-compose-deployment)
- [Testing Suite](#testing-suite)
- [Project Structure](#project-structure)
- [License](#license)

---

## Platform Overview

TRACEX is an operational defensive digital forensics and threat intelligence platform designed to replace static dashboards and simulated scanners with **real, passive forensic analysis engines**. 

TRACEX provides investigators with a centralized environment to safely triage suspicious files, inspect email spoofing, dissect offline packet captures, query threat reputation feeds with verified provenance, and enforce a legally sound **Chain of Custody** ledger.

```
+---------------------------------------------------------------------------------------------------+
|                                       TRACEX DEFENSIVE PLATFORM                                    |
|                             Investigate. Analyze. Correlate. Discover.                            |
+---------------------------------------------------------------------------------------------------+
|  [SOC Overview]  |  [File Forensics]  |  [Threat Intel]  |  [Email]  |  [PCAP]  |  [Evidence Locker]  |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  +-----------------------------+  +--------------------------------+  +------------------------+  |
|  |     EVIDENCE QUARANTINE     |  |    CHAIN OF CUSTODY LEDGER     |  |   EVIDENTIARY RIGOR    |  |
|  | - Isolated web-root sandbox |  | - Genesis baseline SHA-256     |  | - [VERIFIED FACTS]     |  |
|  | - Zero execution boundary   |  | - Bit-rot & tamper alerts      |  | - [EXTERNAL INTEL]     |  |
|  | - Path traversal guard      |  | - Recalculated hash audit      |  | - [INTERPRETATIONS]    |  |
|  +-----------------------------+  +--------------------------------+  +------------------------+  |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## Key Architectural Tenets

1. **Zero-Execution Quarantine Boundary**: Uploaded forensic artifacts are stored outside the public web root in an isolated quarantine vault (`backend/storage/quarantine`) with strict filename sanitization, non-executable file permissions (`chmod 0o600`), and path traversal prevention.
2. **Strict Epistemic Separation**: Every finding explicitly separates **Observed Facts** (physical hashes, raw payload bytes, verified headers) from **Analyst Interpretations** (hypotheses, behavioral theories) and **External Intelligence** (curated and live feeds).
3. **Transparent Intelligence Provenance**: External threat intelligence results always include the exact data provider, retrieval timestamp, and query source. TRACEX never fabricates intelligence results.
4. **Immutable Chain of Custody**: Cryptographic fingerprints (SHA-256, SHA-512, MD5) are recorded at acquisition. Real-time on-disk audit checks detect bit-rot or unauthorized modifications.
5. **Non-Attribution Standard**: Suspicious metadata, high Shannon entropy, or file extension mismatches are structural heuristics and are never claimed as definitive malware detection without dynamic behavioral confirmation.

---

## Module Deep Dive

### Module 1: File Forensics & Deep Structural Parsing
- **Multi-Algorithm Hashing**: Computes MD5, SHA-1, SHA-256, and SHA-512 in memory-safe 64 KB chunks.
- **Deep Structural Parsers**:
  - **Portable Executables (PE)**: Dissects COFF machine architectures (`x86-64`, `ARM64`), PE32/PE32+ headers, compilation timestamps, subsystem indicators, and per-section Shannon byte entropy to detect packing without executing code.
  - **ELF Binaries**: Identifies 32-bit vs. 64-bit architecture, endianness, OS ABI, and object types (`ET_EXEC`, `ET_DYN`).
  - **PDF Documents**: Inspects internal object dictionaries for active scripting primitives (`/JavaScript`, `/JS`), launch triggers (`/Launch`, `/OpenAction`), and embedded payloads (`/EmbeddedFiles`).
  - **Containers & Office OpenXML**: Inspects the ZIP Central Directory table without extracting files, safely identifying macros (`word/vbaProject.bin`, `xl/vbaProject.bin`) without exposing the host to directory traversal or decompression bombs.
- **Binary Signature & Magic Bytes**: Inspects file headers against an internal registry of 35+ file signatures.
- **Extension Mismatch Detection**: Flags weaponized files attempting to evade detection (e.g., an executable `.exe` masquerading as an image `.jpg` or `.pdf`).
- **Shannon Entropy Profiler**: Computes byte entropy on a scale of `0.0` to `8.0`. High entropy (> 7.2) flags packed, compressed, or encrypted droppers.
- **Printable Strings Extractor**: Safely extracts ASCII and UTF-16 strings without executing content, with a live client-side filter.
- **YARA Threat Rules**: Matches behavioral indicators (process injection APIs, base64 PE headers, PowerShell download cradles).

### Module 2: Threat Intelligence & Correlation Engine
- **Multi-IOC Triage**: Supports IP addresses, domains, URLs, and cryptographic file hashes (MD5, SHA-1, SHA-256).
- **Reputation Scoring**: Combines live API queries (VirusTotal, AbuseIPDB, AlienVault OTX) when keys are configured, with a curated offline repository of high-fidelity threat signatures.
- **Multi-Stage IOC Correlation**: Correlates indicators across files, emails, and PCAP streams with cross-source confidence weighting ($0.65$ single source, $0.85$ dual-source, $1.0$ cross-disciplinary).
- **Evidentiary Tri-Categorization**: Automatically sorts indicators into `verified_evidence`, `external_intelligence`, and `heuristic_observation`.
- **Provenance Logging**: Every report displays the provider name, timestamp, and status.
- **Autonomous System (ASN) & GeoIP**: Displays geographic jurisdiction, AS number, and network operator.

### Module 3: Email Forensics & Relay Analysis
- **RFC 5322 / MIME Parsing**: Deep inspection of raw `.eml` uploads and pasted headers with defensive handling for folded headers and corrupted multipart boundaries.
- **Authentication Interpretation**: Evaluates SPF, DKIM, and DMARC status, strictly distinguishing between **Missing Authentication** (unconfigured domain policy) and **Authentication Failure** (cryptographic violation or unauthorized sending IP).
- **ARC (Authenticated Received Chain)**: Parses `ARC-Seal`, `ARC-Authentication-Results`, and `ARC-Message-Signature` headers to evaluate intermediary relay validation (`cv=pass` vs `cv=fail`).
- **Transit Latency Profiling**: Reverses `Received:` headers from origin MTA to boundary gateway and calculates hop-to-hop time deltas to detect relay delays and anomalies.
- **Sender Deception Analysis**: Compares `From:` against `Reply-To:` and `Return-Path:` to detect Business Email Compromise (BEC) and domain spoofing.
- **URL Extraction & Automated Defanging**: Extracts hyperlinks and safely defangs them (`hxxps[://]domain[.]com`) to prevent accidental clicks.

### Module 4: Network Forensics (Offline PCAP DPI)
- **Offline Packet Dissection**: Passive inspection of Libpcap and PCAPNG traces with a 15,000 packet ceiling to prevent resource exhaustion.
- **TLS SNI Extraction**: Offline zero-decryption parsing of Server Name Indication (SNI) hostnames from TLS 1.2/1.3 `ClientHello` handshake records.
- **TCP Flag Heuristics**: Monitors SYN, SYN-ACK, FIN, and RST ratios to detect SYN port scanning and abnormal session reset storms.
- **Protocol Distribution**: Frame breakdowns across Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, and TLS.
- **Top Talkers Matrix**: Tracks conversations, volume, and associated domain queries.
- **DNS Tunneling Detection**: Identifies high-entropy randomized subdomains commonly leveraged for C2 communication and data exfiltration.
- **Cleartext Credential Extraction**: Detects unencrypted HTTP Basic authentication headers.
- **Suspicious Port Detection**: Flags non-standard listeners (e.g., port 4444 reverse shells, IRC botnet communication).

### Module 5: Evidence Management & Chain of Custody
- **Evidence Registration**: Issues unique alphanumeric IDs (`EVD-XXXXXX`) with acquisition timestamp, examiner name, and badge number.
- **Live On-Disk Integrity Auditing**: Recalculates the SHA-256 hash of the quarantined file on disk and verifies it against the acquisition baseline. Flags any bit-level discrepancy as `COMPROMISED`.
- **Immutable Custody Ledger**: Chronological audit trail recording acquisition, transfers, and verification checkpoints.
- **Custody Transfers**: Formal handoff recording releasing badge, recipient badge, reason, and destination vault location.

### Module 6: Investigation Workspace & Relationship Graph
- **Case Dossier Management**: Organizes evidence, notes, and threat indicators into structured investigations with priority and status filters.
- **Interactive Relationship Graph**: Force-directed visual correlation mapping cases, evidence artifacts, threat indicators, and timeline milestones.
- **Chronological Timeline**: Milestones categorized by artifact, network, email, custody, and threat intelligence.
- **Bifurcated Notes Interface**: Explicitly tags entries as either **[VERIFIED FACT]** or **[ANALYST INTERPRETATION]**.

### Module 7: Certified Forensic Report Generation
- **Certified PDF Reports**: Professional, printable PDF dossier rendered with ReportLab. Includes case metadata, cryptographic hash tables, timeline reconstruction, mandatory limitations disclosures, and examiner signature certification.
- **Structured JSON Export**: Machine-readable export separating verified evidence from analytical assessments and including `forensic_standards_compliance` declarations.

---

## Defensive Security Posture

| Risk Area | Countermeasure Implemented |
|---|---|
| **Malicious File Execution** | Files stored outside web root in quarantine vault with `0o600` permissions. No execution commands invoked. |
| **Path Traversal Attacks** | Strict filename regex cleaning, null-byte eradication, and `.resolve().relative_to()` path validation. |
| **Denial of Service (DoS)** | 50 MB file upload limit, 15,000 packet cap on PCAP parser, 60-string buffer ceiling. |
| **Credential & Secret Exposure** | API keys stored in environment variables; never leaked to frontend client responses. |
| **Evidence Tampering** | Baseline SHA-256 hashing on acquisition with on-demand physical audit re-checks. |
| **Container Security** | Multi-stage Docker build running under dedicated non-root user `tracex` (UID 1001). |

---

## Documentation & Technical References

- **[System Architecture & Threat Model](docs/ARCHITECTURE.md)**: In-depth technical architecture, data flows, and STRIDE threat analysis.
- **[Forensic Analysis Techniques & Technical Limitations](docs/ANALYSIS_TECHNIQUES_AND_LIMITATIONS.md)**: Operational boundaries, false-positive risks, and defensive standards for each analysis module.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure and safe handling commitments.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Development workflow and pull request guidelines.

---

## Tech Stack

### Frontend
- **Framework**: React 19 + TypeScript + Vite
- **Styling**: Tailwind CSS v4 (Deep Charcoal & Midnight Blue theme)
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **HTTP Client**: Axios

### Backend
- **Framework**: Python 3.11 + FastAPI
- **Validation**: Pydantic v2 + Pydantic-Settings
- **ORM / Database**: SQLAlchemy + SQLite (PostgreSQL compatible)
- **Forensics Libraries**: Python `hashlib`, `email` parser, Scapy, ReportLab
- **Testing**: Pytest (27 unit/integration tests), Vitest

---

## Quick Start Guide

### Local Development

#### 1. Backend Setup
```bash
# Clone repository
git clone https://github.com/your-org/tracex.git
cd tracex

# Create and activate Python virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Run backend development server
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend will be available at `http://127.0.0.1:8000`. Swagger API docs at `http://127.0.0.1:8000/docs`.

#### 2. Frontend Setup
```bash
cd frontend

# Install frontend dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend will be available at `http://localhost:5173`.

---

### Docker Compose Deployment

To launch the complete application with isolated volumes:
```bash
docker-compose up --build -d
```
Access the application at `http://localhost:8000`.

---

## Testing Suite

TRACEX features automated test coverage across both backend services and frontend components.

```bash
# Run Backend Pytest Suite (27 unit and integration tests)
pytest -v backend/tests

# Run Frontend Vitest Suite
cd frontend
npm test

# Build Production Frontend
npm run build
```

---

## Project Structure

```
tracex/
├── backend/
│   ├── app/
│   │   ├── api/v1/                  # API endpoints (files, intel, email, network, evidence, cases, reports)
│   │   ├── models/                  # SQLAlchemy models (Evidence, CustodyLog, Investigation, IOC, Note)
│   │   ├── schemas/                 # Pydantic request/response schemas
│   │   ├── services/                # Forensic analysis & reporting engines
│   │   ├── utils/                   # Security utilities & sample data generators
│   │   ├── config.py                # Environment configuration
│   │   ├── database.py              # Engine & session setup
│   │   └── main.py                  # FastAPI application entrypoint with security headers & SPA fallback
│   ├── sample_artifacts/            # Pre-bundled safe test artifacts (.eml, .pcap, .ps1)
│   ├── storage/quarantine/          # Isolated forensic quarantine directory
│   ├── tests/                       # Pytest test suite (27 passing tests)
│   └── requirements.txt             # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/              # Navbar, MetricCard, StatusBadge, EvidenceGraph, etc.
│   │   ├── pages/                   # Dashboard, FileForensics, ThreatIntel, Email, Network, Evidence, Cases, MetadataComparison
│   │   ├── services/                # Axios API client
│   │   ├── types/                   # TypeScript forensic data interfaces
│   │   └── tests/                   # Vitest component test suite
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   ├── ARCHITECTURE.md              # System architecture & STRIDE threat model
│   └── ANALYSIS_TECHNIQUES_AND_LIMITATIONS.md # Methodology & operational limitations
├── .github/workflows/
│   └── ci.yml                       # GitHub Actions CI workflow (Audit + Pytest + Vitest + Docker)
├── Dockerfile                       # Multi-stage production container
├── docker-compose.yml               # Container orchestration
├── .env.example                     # Environment template
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── CHANGELOG.md
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
