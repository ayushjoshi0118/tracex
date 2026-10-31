# Changelog

All notable changes to the TRACEX platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-31

### Added
- **Deep Structural Parsers (File Forensics)**:
  - Full COFF header, Optional Header (PE32/PE32+), subsystem identification, and per-section Shannon entropy for Windows Executables.
  - 32-bit and 64-bit ELF binary header parser (endianness, ABI, machine architecture).
  - PDF active primitive scanner detecting `/JavaScript`, `/JS`, `/Launch`, and `/OpenAction` injection vectors.
  - Office OpenXML and ZIP container safe Central Directory inspector detecting embedded VBA macros (`word/vbaProject.bin`, `xl/vbaProject.bin`) without disk extraction.
  - PNG/JPEG dimensions and color channel metadata extractor.
- **Advanced Email Forensics**:
  - Authenticated Received Chain (ARC) verification (`ARC-Seal: cv=pass`, `ARC-Authentication-Results`).
  - Hop transit latency calculation extracting time deltas across consecutive MTAs.
  - Fallback resilient parsing for folded headers and corrupted multipart boundaries.
- **Offline Network DPI (PCAP)**:
  - TLS 1.2/1.3 Server Name Indication (SNI) zero-decryption extraction from `ClientHello` frames.
  - TCP flag analytics tracking SYN, SYN-ACK, FIN, and RST ratios for port scan and connection teardown storm detection.
- **Multi-Stage IOC Correlation Engine**:
  - Cross-source corroboration weighting across files, emails, and PCAP streams.
  - Evidentiary tri-categorization separating `verified_evidence`, `external_intelligence`, and `heuristic_observation`.
- **Production Hardening & Compliance**:
  - Security headers middleware (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`).
  - Non-executable permissions enforcement (`chmod 0o600`) on quarantined files in POSIX environments.
  - Automated production SPA serving and fallback routing directly within FastAPI.
  - Comprehensive STRIDE threat model and architectural sequence diagrams in `docs/ARCHITECTURE.md`.
  - Operational limitations document `docs/ANALYSIS_TECHNIQUES_AND_LIMITATIONS.md`.
  - Expanded test matrix with 27 automated unit and integration tests.

## [1.0.0] - 2026-10-31

### Added
- Initial release of TRACEX Defensive Forensics & Threat Intelligence Platform.
- Modules 1-7: File Forensics, Threat Intelligence, Email Forensics, Network Forensics, Evidence Locker & Chain of Custody, Case Workspace, and ReportLab PDF Export.
- Full Docker and docker-compose deployment.
- GitHub Actions CI workflow.
