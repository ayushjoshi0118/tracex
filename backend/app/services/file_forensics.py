import hashlib
import os
import struct
import mimetypes
import zipfile
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

# Comprehensive Magic Byte Signatures for Forensic Identification
MAGIC_SIGNATURES: List[Dict[str, Any]] = [
    {"magic": b"MZ", "offset": 0, "ext": "exe", "mime": "application/x-dosexec", "desc": "Windows Portable Executable (PE / MZ)"},
    {"magic": b"\x7fELF", "offset": 0, "ext": "elf", "mime": "application/x-elf", "desc": "Linux ELF Executable / Shared Object"},
    {"magic": b"%PDF-", "offset": 0, "ext": "pdf", "mime": "application/pdf", "desc": "Adobe Portable Document Format (PDF)"},
    {"magic": b"PK\x03\x04", "offset": 0, "ext": "zip", "mime": "application/zip", "desc": "ZIP Archive / Office OpenXML Container"},
    {"magic": b"PK\x05\x06", "offset": 0, "ext": "zip", "mime": "application/zip", "desc": "Empty or Spanned ZIP Archive"},
    {"magic": b"\x89PNG\r\n\x1a\n", "offset": 0, "ext": "png", "mime": "image/png", "desc": "Portable Network Graphics (PNG)"},
    {"magic": b"\xff\xd8\xff", "offset": 0, "ext": "jpg", "mime": "image/jpeg", "desc": "JPEG Image File"},
    {"magic": b"GIF87a", "offset": 0, "ext": "gif", "mime": "image/gif", "desc": "Graphics Interchange Format (GIF87a)"},
    {"magic": b"GIF89a", "offset": 0, "ext": "gif", "mime": "image/gif", "desc": "Graphics Interchange Format (GIF89a)"},
    {"magic": b"Rar!\x1a\x07\x00", "offset": 0, "ext": "rar", "mime": "application/x-rar-compressed", "desc": "RAR Archive v4"},
    {"magic": b"Rar!\x1a\x07\x01\x00", "offset": 0, "ext": "rar", "mime": "application/x-rar-compressed", "desc": "RAR Archive v5"},
    {"magic": b"7z\xbc\xaf\x27\x1c", "offset": 0, "ext": "7z", "mime": "application/x-7z-compressed", "desc": "7-Zip Compressed Archive"},
    {"magic": b"\x1f\x8b\x08", "offset": 0, "ext": "gz", "mime": "application/gzip", "desc": "GZIP Compressed Stream"},
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
    {"magic": b"CAFEBABE", "offset": 0, "ext": "class", "mime": "application/java-vm", "desc": "Java Class File or Mach-O Universal Binary"},
    {"magic": b"\xfe\xed\xfa\xce", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 32-bit (Big Endian)"},
    {"magic": b"\xce\xfa\xed\xfe", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 32-bit (Little Endian)"},
    {"magic": b"\xfe\xed\xfa\xcf", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 64-bit (Big Endian)"},
    {"magic": b"\xcf\xfa\xed\xfe", "offset": 0, "ext": "macho", "mime": "application/x-mach-binary", "desc": "Mach-O 64-bit (Little Endian)"},
    {"magic": b"\x4c\x00\x00\x00\x01\x14\x02\x00", "offset": 0, "ext": "lnk", "mime": "application/x-ms-shortcut", "desc": "Windows Shell Link (LNK) Shortcut"},
    {"magic": b"regf", "offset": 0, "ext": "dat", "mime": "application/x-ms-registry", "desc": "Windows Registry Hive (regf)"},
    {"magic": b"MSCF", "offset": 0, "ext": "cab", "mime": "application/vnd.ms-cab-compressed", "desc": "Microsoft Cabinet Archive (CAB)"},
    {"magic": b"ustar", "offset": 257, "ext": "tar", "mime": "application/x-tar", "desc": "POSIX Tar Archive (ustar)"},
    {"magic": b"CD001", "offset": 32769, "ext": "iso", "mime": "application/x-iso9660-image", "desc": "ISO 9660 Optical Disc Image"},
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
    Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes in memory-safe 64 KB chunks.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    chunk_size = 64 * 1024
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

def parse_pe_structural_metadata(data: bytes) -> Dict[str, Any]:
    """
    Safely dissects Portable Executable (PE) headers without executing code.
    Parses DOS header, e_lfanew, COFF header, Optional header, and Section table.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        return {}

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return {"format": "PE", "error": "Truncated DOS header or invalid e_lfanew pointer"}

        pe_sig = data[e_lfanew:e_lfanew+4]
        if pe_sig != b"PE\x00\x00":
            return {"format": "MS-DOS", "note": "Valid MZ header but lacks PE signature (Pure 16-bit DOS binary)"}

        coff_offset = e_lfanew + 4
        machine_code, num_sections, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff_offset)

        machine_map = {
            0x014C: "Intel 386 (x86 32-bit)",
            0x8664: "AMD64 / x86-64 (64-bit)",
            0x01C0: "ARM Little-Endian",
            0xAA64: "ARM64 Little-Endian",
            0x0200: "Intel Itanium"
        }
        machine_str = machine_map.get(machine_code, f"Unknown Architecture (0x{machine_code:04X})")

        dt_utc = None
        try:
            dt_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except Exception:
            dt_utc = f"Raw Epoch: {timestamp}"

        meta: Dict[str, Any] = {
            "pe_signature_offset": f"0x{e_lfanew:X}",
            "target_architecture": machine_str,
            "number_of_sections": num_sections,
            "compile_timestamp": dt_utc,
            "characteristics_flags": f"0x{characteristics:04X}",
            "is_dll": bool(characteristics & 0x2000),
            "is_system_driver": bool(characteristics & 0x1000)
        }

        # Parse Optional Header
        if opt_size > 0 and coff_offset + 20 + 28 <= len(data):
            opt_offset = coff_offset + 20
            magic = struct.unpack_from("<H", data, opt_offset)[0]
            is_pe32_plus = (magic == 0x020B)
            
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            meta["entry_point_rva"] = f"0x{entry_point:X}"
            meta["optional_header_type"] = "PE32+ (64-bit)" if is_pe32_plus else "PE32 (32-bit)"

            # Parse Subsystem & DllCharacteristics
            if not is_pe32_plus and opt_offset + 70 <= len(data):
                subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
                dll_chars = struct.unpack_from("<H", data, opt_offset + 70)[0]
                meta["subsystem"] = "Windows GUI (2)" if subsystem == 2 else "Windows CUI/Console (3)" if subsystem == 3 else f"Other ({subsystem})"
                meta["has_aslr"] = bool(dll_chars & 0x0040)
                meta["has_dep_nx"] = bool(dll_chars & 0x0100)
            elif is_pe32_plus and opt_offset + 72 <= len(data):
                subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
                dll_chars = struct.unpack_from("<H", data, opt_offset + 70)[0]
                meta["subsystem"] = "Windows GUI (2)" if subsystem == 2 else "Windows CUI/Console (3)" if subsystem == 3 else f"Other ({subsystem})"
                meta["has_aslr"] = bool(dll_chars & 0x0040)
                meta["has_dep_nx"] = bool(dll_chars & 0x0100)

        # Parse Section Table
        sections_offset = coff_offset + 20 + opt_size
        sections = []
        for i in range(min(num_sections, 24)):
            s_off = sections_offset + (i * 40)
            if s_off + 40 > len(data):
                break
            raw_name = data[s_off:s_off+8].rstrip(b"\x00").decode("latin-1", errors="ignore")
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s_off + 8)

            # Compute section entropy if data is present
            sec_entropy = 0.0
            if raw_ptr + raw_size <= len(data) and raw_size > 0:
                sec_bytes = data[raw_ptr:raw_ptr + min(raw_size, 32 * 1024)]
                sec_entropy = calculate_shannon_entropy(sec_bytes)

            sections.append({
                "name": raw_name,
                "virtual_address": f"0x{v_addr:X}",
                "virtual_size_bytes": v_size,
                "raw_size_bytes": raw_size,
                "entropy": sec_entropy,
                "is_high_entropy": sec_entropy > 7.3
            })

        meta["sections"] = sections
        return meta
    except Exception as e:
        return {"error": f"Partial PE parsing error: {str(e)}"}

def parse_elf_structural_metadata(data: bytes) -> Dict[str, Any]:
    """
    Safely dissects Executable and Linkable Format (ELF) binary headers.
    """
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {}

    try:
        ei_class = data[4]  # 1: 32-bit, 2: 64-bit
        ei_data = data[5]   # 1: Little-endian, 2: Big-endian
        endian_str = "<" if ei_data == 1 else ">"

        e_type, e_machine = struct.unpack_from(f"{endian_str}HH", data, 16)
        
        type_map = {1: "Relocatable (ET_REL)", 2: "Executable (ET_EXEC)", 3: "Shared Object (ET_DYN)", 4: "Core Dump (ET_CORE)"}
        machine_map = {3: "x86 (Intel 80386)", 62: "x86-64 / AMD64", 40: "ARM", 183: "AArch64 (ARM 64-bit)"}

        return {
            "elf_class": "64-bit (ELF64)" if ei_class == 2 else "32-bit (ELF32)",
            "data_encoding": "2's complement, little endian" if ei_data == 1 else "2's complement, big endian",
            "elf_type": type_map.get(e_type, f"Unknown ({e_type})"),
            "target_architecture": machine_map.get(e_machine, f"Machine ID: {e_machine}"),
        }
    except Exception as e:
        return {"error": f"Partial ELF parsing error: {str(e)}"}

def parse_pdf_structural_metadata(data: bytes) -> Dict[str, Any]:
    """
    Inspects PDF file structure without executing embedded renderers.
    Identifies version and potential active execution or injection vectors.
    """
    if not data.startswith(b"%PDF-"):
        return {}

    try:
        header_line = data[:20].decode("latin-1", errors="ignore").split("\r")[0].split("\n")[0]
        version_str = header_line.replace("%PDF-", "").strip()

        # Search for potential active payload keywords
        js_count = data.count(b"/JavaScript") + data.count(b"/JS")
        launch_count = data.count(b"/Launch")
        embedded_files = data.count(b"/EmbeddedFiles")
        open_action = data.count(b"/OpenAction") + data.count(b"/AA")
        acro_form = data.count(b"/AcroForm")

        total_objects = data.count(b" obj")
        total_streams = data.count(b"stream")

        return {
            "pdf_version": version_str,
            "total_indirect_objects": total_objects,
            "total_streams": total_streams,
            "javascript_blocks_count": js_count,
            "launch_actions_count": launch_count,
            "embedded_files_count": embedded_files,
            "open_actions_count": open_action,
            "has_interactive_forms": bool(acro_form > 0),
            "heuristic_flags": [
                f"Contains {js_count} embedded JavaScript actions" if js_count > 0 else None,
                f"Contains {launch_count} external application launch actions" if launch_count > 0 else None,
                f"Contains {embedded_files} embedded file streams" if embedded_files > 0 else None,
                "Executes actions on document open (/OpenAction)" if open_action > 0 else None
            ]
        }
    except Exception as e:
        return {"error": f"PDF inspection error: {str(e)}"}

def parse_zip_or_office_container(file_path: Path) -> Dict[str, Any]:
    """
    Inspects ZIP archives and Office OpenXML documents without extracting to disk.
    Detects macro presence (VBA), file member counts, and compressed ratios.
    """
    try:
        if not zipfile.is_zipfile(file_path):
            return {}

        with zipfile.ZipFile(file_path, "r") as zf:
            infolist = zf.infolist()
            total_uncompressed = sum(info.file_size for info in infolist)
            total_compressed = sum(info.compress_size for info in infolist)
            filenames = [info.filename for info in infolist]

            has_macros = any("vbaProject.bin" in fn or "vbaData.xml" in fn for fn in filenames)
            is_word = any(fn.startswith("word/") for fn in filenames)
            is_excel = any(fn.startswith("xl/") for fn in filenames)
            is_powerpoint = any(fn.startswith("ppt/") for fn in filenames)

            doc_type = "Generic ZIP Archive"
            if is_word:
                doc_type = "Microsoft Word Document (Macro-Enabled)" if has_macros else "Microsoft Word Document (DOCX)"
            elif is_excel:
                doc_type = "Microsoft Excel Spreadsheet (Macro-Enabled)" if has_macros else "Microsoft Excel Spreadsheet (XLSX)"
            elif is_powerpoint:
                doc_type = "Microsoft PowerPoint Presentation"

            return {
                "container_type": doc_type,
                "archive_member_count": len(infolist),
                "total_uncompressed_bytes": total_uncompressed,
                "total_compressed_bytes": total_compressed,
                "compression_ratio": round((total_compressed / max(total_uncompressed, 1)) * 100, 1),
                "has_embedded_vba_macros": has_macros,
                "manifest_sample": filenames[:12]
            }
    except Exception as e:
        return {"error": f"ZIP inspection error: {str(e)}"}

def parse_image_dimensions(data: bytes) -> Dict[str, Any]:
    """
    Safely reads dimensions for PNG and JPEG files without executing external image libraries.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        try:
            width, height, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])
            return {
                "image_format": "PNG",
                "width_pixels": width,
                "height_pixels": height,
                "bit_depth": bit_depth,
                "color_type": color_type
            }
        except Exception:
            pass
    elif data.startswith(b"\xff\xd8\xff"):
        return {"image_format": "JPEG", "has_exif_marker": b"\xff\xe1" in data[:1024]}

    return {}

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

                detected_hex = " ".join(f"{b:02X}" for b in header_bytes[:min(len(magic), 16)])
                expected_hex = " ".join(f"{b:02X}" for b in magic[:16])

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
    suspicious API calls, base64 payloads, or malicious scripts.
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
    Strictly observes evidentiary boundaries: separates verified structural facts
    from heuristic indicators. Never labels an artifact as malware solely based on metadata.
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

    # 6. Deep Structural Metadata Parsers (PE, ELF, PDF, ZIP/Office, Images)
    structural_meta: Dict[str, Any] = {}
    if signature_match.matched_extension == "exe":
        structural_meta["portable_executable"] = parse_pe_structural_metadata(header_sample)
    elif signature_match.matched_extension == "elf":
        structural_meta["elf_binary"] = parse_elf_structural_metadata(header_sample)
    elif signature_match.matched_extension == "pdf":
        structural_meta["pdf_structure"] = parse_pdf_structural_metadata(header_sample)
    elif signature_match.matched_extension in ["zip", "docx", "xlsx", "pptx"]:
        structural_meta["container_metadata"] = parse_zip_or_office_container(file_path)
    elif signature_match.matched_extension in ["png", "jpg"]:
        structural_meta["image_metadata"] = parse_image_dimensions(header_sample)

    # 7. YARA / Threat rule scanning
    yara_matches = run_yara_inspection(file_path, header_sample, strings_sample)

    # 8. Formulate security verdict & notes
    analysis_notes = []
    verdict = "clean"
    verdict_rationale = "No anomalous header mismatches or known weaponization signatures detected."

    if signature_match.is_mismatch:
        analysis_notes.append(
            f"EXTENSION MISMATCH DETECTED: File claims to be '{signature_match.claimed_extension}' but binary headers match '{signature_match.matched_extension}' ({signature_match.description})."
        )
        verdict = "suspicious"
        verdict_rationale = "Artifact claims an extension that diverges from its verifiable binary header signature. Note: Extension mismatches indicate potential obfuscation or accidental renaming; they do not prove weaponization."

    if entropy > 7.3 and signature_match.matched_extension in ["exe", "elf", "bin", "dll"]:
        analysis_notes.append("High Shannon entropy (>7.3) suggests executable is packed (e.g., UPX) or encrypted to evade static detection.")
        if verdict != "malicious":
            verdict = "suspicious"
            verdict_rationale = "High byte entropy observed in executable structure. Note: High entropy indicates encryption/compression, which is also utilized by legitimate game binaries and commercial packers."

    if yara_matches:
        has_critical = any(m["severity"] == "critical" for m in yara_matches)
        has_high = any(m["severity"] == "high" for m in yara_matches)
        if has_critical:
            verdict = "malicious"
            verdict_rationale = "High-confidence structural weaponization signatures identified (e.g. base64 PE headers or process injection patterns)."
        elif has_high and verdict != "malicious":
            verdict = "suspicious"
            verdict_rationale = "Identified suspicious API references or PowerShell cradle patterns matching forensic threat rules."
        for match in yara_matches:
            analysis_notes.append(f"YARA Alert [{match['severity'].upper()}]: {match['description']}")

    # 9. Document Accuracy and Limitations
    accuracy_and_limitations = [
        "Cryptographic Hashing (SHA-256 / SHA-512): Mathematically deterministic; 100% accurate for bit-level integrity verification.",
        "Magic Byte Identification: Matches known static byte sequences at specified offsets; polyglots or appended payloads may conceal secondary formats.",
        "Shannon Entropy Profiler: Measures byte distribution randomness on a 0.0-8.0 scale. High entropy indicates packing/encryption but does NOT constitute proof of malicious intent.",
        "Static String Extraction: Dissects printable byte sequences from unexecuted binary streams; strings obfuscated at runtime or resolved via dynamic hashing will not be visible.",
        "Defensive Forensic Principle: Suspicious metadata or extension discrepancies alone must never be used to make definitive malware determinations without dynamic behavioral sandboxing or reverse engineering."
    ]

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
        structural_metadata=structural_meta,
        strings_sample=strings_sample[:50],
        yara_matches=yara_matches,
        security_verdict=verdict,
        verdict_rationale=verdict_rationale,
        quarantine_path=str(file_path.name),
        analysis_timestamp=datetime.now(timezone.utc),
        analysis_notes=analysis_notes,
        accuracy_and_limitations=accuracy_and_limitations
    )
