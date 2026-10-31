# Security Policy

## TRACEX Security Architecture & Defensive Scope

TRACEX is explicitly designed as a **defensive digital forensics and threat intelligence platform**. It does NOT contain offensive weaponization, automated exploitation, or invasive network scanning tools.

### Key Security Commitments

1. **Zero-Execution Quarantine Policy**:
   - Files uploaded to TRACEX are stored outside the public web root in an isolated storage directory.
   - TRACEX never invokes `os.system`, `subprocess.Popen`, or runtime interpreters on uploaded content.
   - Files are parsed strictly via passive stream readers (hashing, binary header magic identification, Shannon entropy, static string search).

2. **Path Traversal & Injection Prevention**:
   - Filenames are sanitized through regex validation, null-byte eradication, and UUID salting.
   - Resolved filesystem paths are checked against the root quarantine directory to prohibit directory traversal.

3. **Chain of Custody & Tamper Detection**:
   - SHA-256 baseline fingerprints are computed at acquisition time.
   - Any physical modification of stored evidence will cause subsequent on-disk integrity audits to flag the item as `compromised`.
   - Custody logs are strictly append-only.

4. **API Key & Secret Protection**:
   - Threat intelligence API keys (e.g. VirusTotal, AbuseIPDB, AlienVault OTX) are configured strictly via environment variables or `.env` files.
   - API keys are never leaked to client responses or logged in plaintext.

## Reporting a Vulnerability

If you discover a security vulnerability within TRACEX, please report it responsibly:

- **Email**: `security@tracex-forensics.internal`
- Please provide detailed reproduction steps and affected components.
- Do not create public GitHub issues for sensitive security vulnerabilities.
