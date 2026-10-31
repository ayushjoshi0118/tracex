import hashlib
import os
import mimetypes
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone
import uuid

from backend.app.schemas.forensics import (
    FileForensicsResponse,
    FileHashAnalysis,
    FileSignatureMatch
)
from backend.app.utils.security import (
    calculate_shannon_entropy,
    extract_ascii_and_unicode_strings
)

# Known Magic Byte Signatures for Forensic Identification
MAGIC_SIGNATURES: List[Dict[str, Any]] = [
    {"magic": b"MZ", "offset": 0, "ext": "exe", "mime": "application/x-dosexec", "desc": "Windows Portable Executable (PE / MZ)"},
    {"magic": b"\x7fELF", "offset": 0, "ext": "elf", "mime": "application/x-elf", "desc": "Linux ELF Executable / Shared Object"},
    {"magic": b"%PDF-", "offset": 0, "ext": "pdf", "mime": "application/pdf", "desc": "Adobe Portable Document Format (PDF)"},
    {"magic": b"PK\x03\x04", "offset": 0, "ext": "zip", "mime": "application/zip", "desc": "ZIP Archive / Office OpenXML Document (DOCX, XLSX, PPTX)"},
    {"magic": b"PK\x05\x06", "offset": 0, "ext": "zip", "mime": "application/zip", "desc": "Empty or Spanned ZIP Archive"},
    {"magic": b"\x89PNG\r\n\x1a\n", "offset": 0, "ext": "png", "mime": "image/png", "desc": "Portable Network Graphics (PNG)"},
    {"magic": b"\xff\xd8\xff", "offset": 0, "ext": "jpg", "mime": "image/jpeg", "desc": "JPEG Image"},
    {"magic": b"GIF87a", "offset": 0, "ext": "gif", "mime": "image/gif", "desc": "Graphics Interchange Format (GIF87a)"},
    {"magic": b"GIF89a", "offset": 0, "ext": "gif", "mime": "image/gif", "desc": "Graphics Interchange Format (GIF89a)"},
    {"magic": b"Rar!\x1a\x07\x00", "offset": 0, "ext": "rar", "mime": "application/x-rar-compressed", "desc": "RAR Archive v4"},
    {"magic": b"Rar!\x1a\x07\x01\x00", "offset": 0, "ext": "rar", "mime": "application/x-rar-compressed", "desc": "RAR Archive v5"},
    {"magic": b"7z\xbc\xaf\x27\x1c", "offset": 0, "ext": "7z", "mime": "application/x-7z-compressed", "desc": "7-Zip Compressed Archive"},
    {"magic": b"\x1f\x8b\x08", "offset": 0, "ext": "gz", "mime": "application/gzip", "desc": "GZIP Compressed Archive"},
    {"magic": b"BZh", "offset": 0, "ext": "bz2", "mime": "application/x-bzip2", "desc": "BZIP2 Compressed Archive"},
    {"magic": b"\xd4\xc3\xb2\xa1", "offset": 0, "ext": "pcap", "mime": "application/vnd.tcpdump.pcap", "desc": "Libpcap Packet Capture (Microsecond, Little Endian)"},
    {"magic": b"\xa1\xb2\xc3\xd4", "offset": 0, "ext": "pcap", "mime": "application/vnd.tcpdump.pcap", "desc": "Libpcap Packet Capture (Microsecond, Big Endian)"},
    {"magic": b"\x4d\x3c\xb2\xa1", "offset": 0, "ext": "pcap", "mime": "application/vnd.tcpdump.pcap", "desc": "Libpcap Packet Capture (Nanosecond, Little Endian)"},
    {"magic": b"\xa1\xb2\x3c\x4d", "offset": 0, "ext": "pcap", "mime": "application/vnd.tcpdump.pcap", "desc": "Libpcap Packet Capture (Nanosecond, Big Endian)"},
    {"magic": b"\x0a\x0d\x0d\x0a", "offset": 0, "ext": "pcapng", "mime": "application/x-pcapng", "desc": "PCAP Next Generation Capture (pcapng)"},
    {"magic": b"SQLite format 3\x00", "offset": 0, "ext": "sqlite", "mime": "application/x-sqlite3", "desc": "SQLite 3 Database"},
    {"magic": b"{\"", "offset": 0, "ext": "json", "mime": "application/json", "desc": "JSON Text Data"},
    {"magic": b"{\r\n", "offset": 0, "ext": "json", "mime": "application/json", "desc": "JSON Text Data"},
    {"magic": b"{\n", "offset": 0, "ext": "json", "mime": "application/json", "desc": "JSON Text Data"},
    {"magic": b"<?xml", "offset": 0, "ext": "xml", "mime": "application/xml", "desc": "XML Document"},
    {"magic": b"<!DOCTYPE html", "offset": 0, "ext": "html", "mime": "text/html", "desc": "HTML Web Document"},
    {"magic": b"<html", "offset": 0, "ext": "html", "mime": "text/html", "desc": "HTML Document"},
    {"magic": b"Received:", "offset": 0, "ext": "eml", "mime": "message/rfc822", "desc": "RFC 822 / MIME Email Message (EML)"},
    {"magic": b"From:", "offset": 0, "ext": "eml", "mime": "message/rfc822", "desc": "RFC 822 / MIME Email Message (EML)"},
    {"magic": b"Return-Path:", "offset": 0, "ext": "eml", "mime": "message/rfc822", "desc": "RFC 822 / MIME Email Message (EML)"},
    {"magic": b"Delivered-To:", "offset": 0, "ext": "eml", "mime": "message/rfc822", "desc": "RFC 822 / MIME Email Message (EML)"},
    {"magic": b"CAFEBABE", "offset": 0, "ext": "class", "mime": "application/java-vm", "desc": "Java Class File or Mach-O Universal Binary"},
    {"magic": b"\xfe\xed\xfa\xce", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 32-bit (Big Endian)"},
    {"magic": b"\xce\xfa\xed\xfe", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 32-bit (Little Endian)"},
    {"magic": b"\xfe\xed\xfa\xcf", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 64-bit (Big Endian)"},
    {"magic": b"\xcf\xfa\xed\xfe", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 64-bit (Little Endian)"},
]

def format_human_bytes(size: int) -> str:
    """Format bytes into readable units."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"

def calculate_file_hashes(file_path: Path) -> FileHashAnalysis:
    """
    Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes in chunks.
    Ensures safe resource limits without loading whole file into memory.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    chunk_size = 64 * 1024  # 64 KB chunks
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return FileHashAnalysis(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest()
    )

def detect_file_signature(header_bytes: bytes, filename: str) -> FileSignatureMatch:
    """
    Match binary header against forensic magic byte registry and detect extension mismatch.
    """
    claimed_ext = Path(filename).suffix.lstrip(".").lower()
    
    # Try exact magic matches
    for sig in MAGIC_SIGNATURES:
        magic = sig["magic"]
        offset = sig["offset"]
        if len(header_bytes) >= offset + len(magic):
            if header_bytes[offset:offset + len(magic)] == magic:
                detected_ext = sig["ext"]
                
                # Check for Office OpenXML vs generic ZIP
                if detected_ext == "zip" and claimed_ext in ["docx", "xlsx", "pptx", "jar", "apk"]:
                    detected_ext = claimed_ext
                
                # Check for text/eml variations
                if detected_ext == "eml" and claimed_ext in ["eml", "msg", "txt"]:
                    detected_ext = claimed_ext

                is_mismatch = (claimed_ext != "" and claimed_ext != detected_ext)
                # Specific high-risk mismatch detection: e.g. EXE renamed as JPG/PDF/DOC
                if detected_ext in ["exe", "elf", "macho"] and claimed_ext in ["jpg", "png", "pdf", "docx", "txt", "xlsx"]:
                    is_mismatch = True

                detected_hex = " ".join(f"{b:02X}" for b in header_bytes[:len(magic)])
                expected_hex = " ".join(f"{b:02X}" for b in magic)

                return FileSignatureMatch(
                    expected_magic=expected_hex,
                    detected_magic=detected_hex,
                    description=sig["desc"],
                    matched_extension=detected_ext,
                    claimed_extension=claimed_ext or "none",
                    is_mismatch=is_mismatch
                )

    # Fallback to UTF-8 / ASCII text inspection
    try:
        sample_text = header_bytes[:512].decode("utf-8")
        if sample_text.isprintable() or any(c in sample_text for c in ["\r", "\n", "\t"]):
            is_mismatch = (claimed_ext in ["exe", "dll", "bin", "png", "jpg", "pdf", "zip"])
            return FileSignatureMatch(
                expected_magic="Plain Text / ASCII / UTF-8",
                detected_magic=" ".join(f"{b:02X}" for b in header_bytes[:8]),
                description="Plain Text Document / Source Code / Configuration",
                matched_extension="txt" if claimed_ext != "txt" and not is_mismatch else (claimed_ext or "txt"),
                claimed_extension=claimed_ext or "none",
                is_mismatch=is_mismatch
            )
    except Exception:
        pass

    # Unknown binary structure
    sample_hex = " ".join(f"{b:02X}" for b in header_bytes[:8])
    return FileSignatureMatch(
        expected_magic="Unknown / Unmapped Magic",
        detected_magic=sample_hex,
        description="Unidentified Binary Data Stream",
        matched_extension="bin",
        claimed_extension=claimed_ext or "none",
        is_mismatch=(claimed_ext not in ["", "bin", "dat", "raw"])
    )

def run_yara_inspection(file_path: Path, header_bytes: bytes, strings_sample: list[str]) -> list[dict[str, Any]]:
    """
    Forensic rule scanning: detects embedded shellcode patterns, PE indicators,
    suspicious API calls (VirtualAlloc, CreateRemoteThread), base64 payloads, or malicious scripts.
    """
    matches = []
    
    # 1. Suspicious Windows API strings in non-PE or PE
    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory",
        "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA", "IsDebuggerPresent",
        "WSAStartup", "URLDownloadToFileA", "WinExec", "ShellExecuteA"
    ]
    found_apis = [api for api in suspicious_apis if any(api.lower() in s.lower() for s in strings_sample)]
    if found_apis:
        matches.append({
            "rule": "Suspicious_Process_Injection_APIs",
            "tags": ["process_injection", "evasion", "windows"],
            "severity": "high",
            "description": f"Found {len(found_apis)} sensitive Windows APIs commonly used in process injection: {', '.join(found_apis[:4])}"
        })

    # 2. Base64 encoded PE executable (TVqQ = MZ header base64)
    if any("TVqQ" in s for s in strings_sample):
        matches.append({
            "rule": "Base64_Encoded_PE_Executable",
            "tags": ["obfuscation", "dropper", "pe"],
            "severity": "critical",
            "description": "Detected base64-encoded Windows PE executable header ('TVqQAAMAAAAEAAAA...')"
        })

    # 3. Powershell encoded command or download cradles
    suspicious_keywords = ["IEX", "DownloadString", "Invoke-Expression", "powershell -enc", "bypass -nop"]
    found_keywords = [kw for kw in suspicious_keywords if any(kw.lower() in s.lower() for s in strings_sample)]
    if found_keywords:
        matches.append({
            "rule": "Malicious_Powershell_Download_Cradle",
            "tags": ["script", "downloader", "execution"],
            "severity": "high",
            "description": f"Found PowerShell download cradle signatures: {', '.join(found_keywords)}"
        })

    # 4. Embedded URL/C2 beaconing indicators
    c2_urls = [s for s in strings_sample if s.startswith("http://") or s.startswith("https://")]
    if len(c2_urls) > 5:
        matches.append({
            "rule": "Multiple_Hardcoded_URLs",
            "tags": ["c2", "network", "ioc"],
            "severity": "medium",
            "description": f"Extracted {len(c2_urls)} embedded network URLs/URIs"
        })

    return matches

def analyze_file_forensics(file_path: Path, original_filename: str) -> FileForensicsResponse:
    """
    Execute comprehensive forensic analysis on the quarantined artifact.
    """
    file_id = f"FILE-{uuid.uuid4().hex[:8].upper()}"
    file_size = os.path.getsize(file_path)
    file_size_human = format_human_bytes(file_size)

    # 1. Calculate cryptographic hashes
    hashes = calculate_file_hashes(file_path)

    # 2. Read initial header chunk (up to 128 KB) for signature, entropy, and string extraction
    read_size = min(file_size, 128 * 1024)
    with open(file_path, "rb") as f:
        header_sample = f.read(read_size)

    # 3. Calculate Shannon entropy
    entropy = calculate_shannon_entropy(header_sample)
    if entropy > 7.2:
        entropy_level = "High (Packed, Encrypted, or Compressed)"
    elif entropy > 5.0:
        entropy_level = "Normal (Typical code / text / mixed binary)"
    else:
        entropy_level = "Low (Sparse or repetitive data)"

    # 4. File signature and extension mismatch analysis
    signature_match = detect_file_signature(header_sample, original_filename)

    # 5. Extract printable strings
    strings_sample = extract_ascii_and_unicode_strings(header_sample, min_length=4, max_strings=60)

    # 6. YARA / Threat rule scanning
    yara_matches = run_yara_inspection(file_path, header_sample, strings_sample)

    # 7. Formulate security verdict & notes
    analysis_notes = []
    verdict = "clean"

    if signature_match.is_mismatch:
        analysis_notes.append(
            f"EXTENSION MISMATCH DETECTED: File claims to be '{signature_match.claimed_extension}' but binary headers match '{signature_match.matched_extension}' ({signature_match.description})."
        )
        verdict = "suspicious"

    if entropy > 7.3 and signature_match.matched_extension in ["exe", "elf", "bin", "dll"]:
        analysis_notes.append("High Shannon entropy (>7.3) suggests executable is packed (e.g., UPX) or encrypted to evade static detection.")
        if verdict != "malicious":
            verdict = "suspicious"

    if yara_matches:
        has_critical = any(m["severity"] == "critical" for m in yara_matches)
        has_high = any(m["severity"] == "high" for m in yara_matches)
        if has_critical:
            verdict = "malicious"
        elif has_high and verdict != "malicious":
            verdict = "suspicious"
        for match in yara_matches:
            analysis_notes.append(f"YARA Alert [{match['severity'].upper()}]: {match['description']}")

    if not analysis_notes:
        analysis_notes.append("No anomalous header mismatches or known weaponization signatures detected.")

    guessed_mime, _ = mimetypes.guess_type(original_filename)

    return FileForensicsResponse(
        file_id=file_id,
        filename=original_filename,
        file_size_bytes=file_size,
        file_size_human=file_size_human,
        hashes=hashes,
        entropy=entropy,
        entropy_level=entropy_level,
        mime_type=guessed_mime or "application/octet-stream",
        detected_type=signature_match.description,
        signature=signature_match,
        strings_sample=strings_sample[:50],
        yara_matches=yara_matches,
        security_verdict=verdict,
        quarantine_path=str(file_path.name),
        analysis_timestamp=datetime.now(timezone.utc),
        analysis_notes=analysis_notes
    )
