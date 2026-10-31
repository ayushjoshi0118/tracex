# Changelog

All notable changes to the TRACEX platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-31

### Added
- **Module 1 (File Forensics)**:
  - Cryptographic baseline hashing: SHA-256, SHA-512, MD5, SHA-1.
  - Binary magic header signature detector with 35+ formats (PE, ELF, Mach-O, PDF, Office OpenXML, PCAP, EML, ZIP).
  - Extension mismatch detector (flags disguised executables e.g. EXE renamed as JPG/PDF).
  - Shannon entropy calculator for packed, compressed, or obfuscated payloads.
  - Printable ASCII/Unicode string extractor with filter interface.
  - YARA rule threat pattern scanner.
- **Module 2 (Threat Intelligence)**:
  - Multi-IOC investigation: IP, Domain, URL, and File Hashes.
  - External threat intelligence integrations with full provenance logging (VirusTotal, AbuseIPDB, AlienVault OTX, and Curated Threat Database).
  - Autonomous System (ASN) and Geolocation tracking.
  - Clear distinction between verified evidence, external intelligence, and heuristic observations.
- **Module 3 (Email Forensics)**:
  - RFC 822 / MIME .eml file parser and raw header extractor.
  - Detailed SPF, DKIM, and DMARC status evaluation (strictly separating missing vs failed auth).
  - Hop-by-hop relay timeline tracing.
  - Sender vs Reply-To mismatch detection.
  - URL extractor with automated defanging (`hxxps[://]`).
  - Phishing indicator classification and risk scoring.
- **Module 4 (Network Forensics)**:
  - Offline PCAP / PCAPNG packet dissection.
  - Protocol distribution breakdowns.
  - Top talkers IP matrix.
  - DNS query log with Shannon entropy calculation for DNS tunneling and exfiltration detection.
  - HTTP stream extraction with cleartext credential alerts.
  - Suspicious port anomaly alerts (Metasploit 4444, Elite 1337, etc.).
- **Module 5 (Evidence Management)**:
  - Unique Evidence ID generation (`EVD-XXXXXX`).
  - Acquisition timestamping and examiner badge tracking.
  - Append-only immutable Chain of Custody ledger.
  - Live on-disk cryptographic integrity audit and tamper detection.
- **Module 6 & 7 (Investigation Workspace & Reports)**:
  - Case dossier management with priority and status filters.
  - Evidentiary separation of Observed Facts from Analyst Interpretations.
  - Timeline milestones.
  - Professional PDF export via ReportLab with examiner signature certification.
  - Machine-readable structured JSON export.
- **Infrastructure & Testing**:
  - Full Docker and docker-compose deployment.
  - GitHub Actions CI workflow.
  - Pytest, Vitest, and Playwright test suites.
