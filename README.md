<div align="center">

# TRACEX
### Defensive Digital Forensics & Threat Intelligence Platform

**Investigate. Analyze. Correlate. Discover.**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Pytest](https://img.shields.io/badge/Pytest-100%25%20Passing-brightgreen?style=flat&logo=pytest&logoColor=white)](https://pytest.org)
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
  - [Module 1: File Forensics & Hashing](#module-1-file-forensics--hashing)
  - [Module 2: Threat Intelligence & Provenance](#module-2-threat-intelligence--provenance)
  - [Module 3: Email Forensics & Header Parser](#module-3-email-forensics--header-parser)
  - [Module 4: Network Forensics (Offline PCAP)](#module-4-network-forensics-offline-pcap)
  - [Module 5: Evidence Management & Chain of Custody](#module-5-evidence-management--chain-of-custody)
  - [Module 6: Investigation Workspace](#module-6-investigation-workspace)
  - [Module 7: Certified Forensic Report Generation](#module-7-certified-forensic-report-generation)
- [Defensive Security Posture](#defensive-security-posture)
- [Tech Stack](#tech-stack)
- [Quick Start Guide](#quick-start-guide)
  - [Local Development](#local-development)
  - [Docker Compose Deployment](#docker-compose-deployment)
- [Testing Suite](#testing-suite)
- [Project Structure](#project-structure)
- [License](#license)

---

## Platform Overview

TRACEX is an operational defensive digital forensics and threat intelligence platform designed to replace static dashboards and simulated scanners with **real forensic analysis engines**. 

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

1. **Zero-Execution Quarantine Boundary**: Uploaded forensic artifacts are stored outside the public web root in an isolated quarantine vault (`/backend/storage/quarantine`) with strict filename sanitization and path traversal prevention.
2. **Strict Epistemic Separation**: Every finding explicitly separates **Observed Facts** (physical hashes, raw payload bytes, verified headers) from **Analyst Interpretations** (hypotheses, behavioral theories) and **External Intelligence** (curated and live feeds).
3. **Transparent Intelligence Provenance**: External threat intelligence results always include the exact data provider, retrieval timestamp, and query source. TRACEX never fabricates intelligence results.
4. **Immutable Chain of Custody**: Cryptographic fingerprints (SHA-256, SHA-512, MD5) are recorded at acquisition. Real-time on-disk audit checks detect bit-rot or unauthorized modifications.

---

## Module Deep Dive

### Module 1: File Forensics & Hashing
- **Multi-Algorithm Hashing**: Computes MD5, SHA-1, SHA-256, and SHA-512 in memory-safe 64 KB chunks.
- **Binary Signature & Magic Bytes**: Inspects file headers against an internal registry of 35+ file signatures (PE, ELF, Mach-O, PDF, Office OpenXML, PCAP, ZIP, EML, etc.).
- **Extension Mismatch Detection**: Flags weaponized files attempting to evade detection (e.g., an executable `.exe` masquerading as an image `.jpg` or `.pdf`).
- **Shannon Entropy Profiler**: Computes byte entropy on a scale of `0.0` to `8.0`. High entropy (> 7.2) flags packed, compressed, or encrypted droppers.
- **Printable Strings Extractor**: Safely extracts ASCII and UTF-16 strings without executing content, with a live client-side filter.
- **YARA Threat Rules**: Matches behavioral indicators (process injection APIs, base64 PE headers, PowerShell download cradles).

### Module 2: Threat Intelligence & Provenance
- **Multi-IOC Triage**: Supports IP addresses, domains, URLs, and cryptographic file hashes (MD5, SHA-1, SHA-256).
- **Reputation Scoring**: Combines live API queries (VirusTotal, AbuseIPDB, AlienVault OTX) when keys are configured, with a curated offline repository of high-fidelity threat signatures.
- **Provenance Logging**: Every report displays the provider name, timestamp, and status.
- **Autonomous System (ASN) & GeoIP**: Displays geographic jurisdiction, AS number, and network operator.

### Module 3: Email Forensics & Header Parser
- **RFC 822 / MIME Parsing**: Deep inspection of raw `.eml` uploads and pasted headers.
- **Authentication Interpretation**: Evaluates SPF, DKIM, and DMARC status, strictly distinguishing between **Missing Authentication** and **Authentication Failure**.
- **Sender Deception Analysis**: Compares `From:` against `Reply-To:` and `Return-Path:` to detect Business Email Compromise (BEC) and domain spoofing.
- **Hop-by-Hop Relay Path**: Traces `Received:` headers from origin MTA to boundary gateway.
- **URL Extraction & Automated Defanging**: Extracts hyperlinks and safely defangs them (`hxxps[://]domain[.]com`) to prevent accidental clicks.

### Module 4: Network Forensics (Offline PCAP)
- **Offline Packet Dissection**: Passive inspection of Libpcap and PCAPNG traces with a 15,000 packet ceiling to prevent resource exhaustion.
- **Protocol Distribution**: Frame breakdowns across Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, and TLS.
- **Top Talkers Matrix**: Tracks conversations, volume, and associated domain queries.
- **DNS Tunneling Detection**: Identifies high-entropy randomized subdomains commonly leveraged for C2 communication and data exfiltration.
- **Cleartext Credential Extraction**: Detects unencrypted HTTP Basic authentication headers.
- **Suspicious Port Detection**: Flags non-standard listeners (e.g., port 4444 reverse shells, IRC botnet communication).

### Module 5: Evidence Management & Chain of Custody
- **Evidence Registration**: Issues unique alphanumeric IDs (`EVD-XXXXXX`) with acquisition timestamp, examiner name, and badge number.
- **Live On-Disk Integrity Auditing**: Recalculates the SHA-256 hash of the quarantined file on disk and verifies it against the acquisition baseline. Flags any bit-level discrepancy as `COMPROMISED`.
- **Immutable Custody Ledger**: Chronological audit trail recording acquisition, transfers, and verification checkpoints.

### Module 6: Investigation Workspace
- **Case Dossier Management**: Organizes evidence, notes, and threat indicators into structured investigations with priority and status filters.
- **Chronological Timeline**: Milestones categorized by artifact, network, email, custody, and threat intelligence.
- **Bifurcated Notes Interface**: Explicitly tags entries as either **[VERIFIED FACT]** or **[ANALYST INTERPRETATION]**.

### Module 7: Certified Forensic Report Generation
- **Certified PDF Reports**: Professional, printable PDF dossier rendered with ReportLab. Includes case metadata, cryptographic hash tables, timeline reconstruction, and examiner signature certification.
- **Structured JSON Export**: Machine-readable export separating verified evidence from analytical assessments.

---

## Defensive Security Posture

| Risk Area | Countermeasure Implemented |
|---|---|
| **Malicious File Execution** | Files stored outside web root in quarantine vault. No execution commands invoked. |
| **Path Traversal Attacks** | Strict filename regex cleaning, null-byte eradication, and `.resolve().relative_to()` path validation. |
| **Denial of Service (DoS)** | 50 MB file upload limit, 15,000 packet cap on PCAP parser, 60-string buffer ceiling. |
| **Credential & Secret Exposure** | API keys stored in environment variables; never leaked to frontend client responses. |
| **Evidence Tampering** | Baseline SHA-256 hashing on acquisition with on-demand physical audit re-checks. |

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
- **Testing**: Pytest, Vitest, Playwright

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
# Run Backend Pytest Suite (12 unit and integration tests)
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
│   │   └── main.py                  # FastAPI application entrypoint
│   ├── sample_artifacts/            # Pre-bundled safe test artifacts (.eml, .pcap, .ps1)
│   ├── storage/quarantine/          # Isolated forensic quarantine directory
│   ├── tests/                       # Pytest test suite
│   └── requirements.txt             # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/              # Navbar, MetricCard, StatusBadge, etc.
│   │   ├── pages/                   # Dashboard, FileForensics, ThreatIntel, Email, Network, Evidence, Cases
│   │   ├── services/                # Axios API client
│   │   ├── types/                   # TypeScript forensic data interfaces
│   │   └── tests/                   # Vitest component test suite
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   └── ARCHITECTURE.md              # System architecture & threat model
├── .github/workflows/
│   └── ci.yml                       # GitHub Actions CI workflow
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
