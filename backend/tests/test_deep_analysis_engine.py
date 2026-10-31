import io
import struct
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

from backend.app.services.file_forensics import (
    analyze_file_forensics,
    parse_pe_structural_metadata,
    parse_elf_structural_metadata,
    parse_pdf_structural_metadata,
    parse_zip_or_office_container
)
from backend.app.services.email_forensics import analyze_email_forensics, safe_parse_date
from backend.app.services.network_forensics import analyze_pcap_forensics, extract_tls_sni
from backend.app.services.threat_intel import correlate_indicators, query_threat_intelligence
from backend.app.services.reporting_service import (
    generate_json_investigation_report,
    generate_pdf_investigation_report
)
from backend.app.models.investigation import Investigation
from backend.app.models.evidence import Evidence
from backend.app.models.ioc import InvestigationIOC
from backend.app.models.note import InvestigationNote
from backend.app.models.timeline import TimelineEvent
from backend.app.schemas.entities import ReportExportRequest


# --- 1. SYNTHETIC PE FILE TESTS ---
def test_synthetic_pe_structural_parsing():
    """Build a synthetic PE32+ (x86-64) binary with section table and verify structural extraction."""
    pe_buffer = bytearray(512)
    # DOS Header
    pe_buffer[0:2] = b"MZ"
    struct.pack_into("<I", pe_buffer, 0x3C, 64)  # e_lfanew = 64

    # PE Signature
    pe_offset = 64
    pe_buffer[pe_offset:pe_offset+4] = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    # Machine: 0x8664 (AMD64), NumberOfSections: 2, TimeDateStamp: 1700000000, SizeOfOptionalHeader: 240, Characteristics: 0x0002 (EXECUTABLE_IMAGE)
    struct.pack_into("<HHIIIHH", pe_buffer, pe_offset + 4, 0x8664, 2, 1700000000, 0, 0, 240, 0x0002)

    # Optional Header (PE32+)
    opt_offset = pe_offset + 24
    struct.pack_into("<H", pe_buffer, opt_offset, 0x020B)  # Magic: PE32+ (64-bit)
    # Subsystem: 3 (Windows CUI) at offset 68 in PE32+ optional header
    struct.pack_into("<H", pe_buffer, opt_offset + 68, 3)

    # Section Headers (40 bytes each) at opt_offset + 240
    sec_offset = opt_offset + 240
    # Section 1: .text
    pe_buffer[sec_offset:sec_offset+8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", pe_buffer, sec_offset + 8, 1024, 0x1000, 512, 0x400)
    # Section 2: .rdata
    sec2_offset = sec_offset + 40
    pe_buffer[sec2_offset:sec2_offset+8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", pe_buffer, sec2_offset + 8, 512, 0x2000, 256, 0x600)

    pe_meta = parse_pe_structural_metadata(bytes(pe_buffer))
    assert pe_meta["target_architecture"] == "AMD64 / x86-64 (64-bit)"
    assert pe_meta["number_of_sections"] == 2
    assert pe_meta["optional_header_type"] == "PE32+ (64-bit)"
    assert "Console" in pe_meta["subsystem"]
    assert len(pe_meta["sections"]) == 2
    assert pe_meta["sections"][0]["name"] == ".text"
    assert pe_meta["sections"][1]["name"] == ".rdata"

    # Save to temp file and run full file forensics
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(pe_buffer)
        temp_path = Path(tf.name)

    try:
        report = analyze_file_forensics(temp_path, "sample_test.exe")
        assert report.signature.matched_extension == "exe"
        assert "portable_executable" in report.structural_metadata
        assert len(report.accuracy_and_limitations) >= 4
        assert "verdict_rationale" in report.model_dump()
    finally:
        if temp_path.exists():
            temp_path.unlink()


# --- 2. SYNTHETIC ELF BINARY TESTS ---
def test_synthetic_elf_structural_parsing():
    """Build a synthetic 64-bit little-endian ELF binary header and verify extraction."""
    elf_buffer = bytearray(64)
    elf_buffer[0:4] = b"\x7fELF"
    elf_buffer[4] = 2  # 64-bit
    elf_buffer[5] = 1  # Little endian
    elf_buffer[6] = 1  # ELF version 1
    elf_buffer[7] = 0  # System V ABI
    struct.pack_into("<H", elf_buffer, 16, 2)  # ET_EXEC
    struct.pack_into("<H", elf_buffer, 18, 62)  # x86-64 machine ID

    elf_meta = parse_elf_structural_metadata(bytes(elf_buffer))
    assert elf_meta["elf_class"] == "64-bit (ELF64)"
    assert "little endian" in elf_meta["data_encoding"]
    assert elf_meta["elf_type"] == "Executable (ET_EXEC)"
    assert "x86-64" in elf_meta["target_architecture"]


# --- 3. SYNTHETIC PDF ACTIVE ELEMENT TESTS ---
def test_synthetic_pdf_active_elements():
    """Build a PDF with active scripting and launch elements and verify detection."""
    pdf_content = (
        b"%PDF-1.7\r\n"
        b"1 0 obj\r\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\r\nendobj\r\n"
        b"2 0 obj\r\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\r\nendobj\r\n"
        b"3 0 obj\r\n<< /Type /Page /Parent 2 0 R >>\r\nendobj\r\n"
        b"4 0 obj\r\n<< /Type /Action /S /JavaScript /JS (app.alert('Test');) >>\r\nendobj\r\n"
        b"%%EOF\r\n"
    )
    pdf_meta = parse_pdf_structural_metadata(pdf_content)
    assert pdf_meta["pdf_version"] == "1.7"
    assert pdf_meta["javascript_blocks_count"] > 0
    assert pdf_meta["open_actions_count"] > 0
    assert any("JavaScript" in str(h) for h in pdf_meta["heuristic_flags"])


# --- 4. SYNTHETIC ZIP / OFFICE OPENXML MACRO TESTS ---
def test_synthetic_office_openxml_macro_detection():
    """Build an in-memory DOCX / ZIP containing vbaProject.bin and verify macro flag."""
    zip_bytes_io = io.BytesIO()
    with zipfile.ZipFile(zip_bytes_io, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<document>Legitimate text</document>")
        zf.writestr("word/vbaProject.bin", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 64)

    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
        tf.write(zip_bytes_io.getvalue())
        temp_path = Path(tf.name)

    try:
        container_meta = parse_zip_or_office_container(temp_path)
        assert "Microsoft Word" in container_meta["container_type"]
        assert container_meta["has_embedded_vba_macros"] is True
        assert container_meta["archive_member_count"] == 3
    finally:
        if temp_path.exists():
            temp_path.unlink()


# --- 5. MALFORMED EML & ARC AUTHENTICATION TESTS ---
def test_malformed_eml_and_arc_authentication():
    """Verify handling of malformed email headers, non-standard dates, ARC headers, and transit delays."""
    sample_eml = """Received: from gateway.internal.net (gateway [10.0.0.1])
    by boundary.corp.local with ESMTP; Fri, 30 Oct 2026 12:02:15 +0000
Received: from mail.attacker-domain.org (mail.attacker-domain.org [198.51.100.44])
    by gateway.internal.net with ESMTP; Fri, 30 Oct 2026 12:01:45 +0000
From: "Urgent Payroll Notice" <payroll@trusted-service.com>
Reply-To: <attacker-exfil@external-c2.net>
Subject: Immediate Action Required: Account Access Suspended
Date: 30 Oct 2026 12:00:00 -0000
Authentication-Results: mx.corp.local;
    spf=fail (sender IP 198.51.100.44 is not authorized);
    dkim=fail header.d=trusted-service.com;
    dmarc=fail (p=reject)
ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=forwarder.org; s=arc1;
ARC-Authentication-Results: i=1; mx.corp.local; arc=pass
Content-Type: multipart/mixed; boundary="====CORRUPT_BOUNDARY_123===="

--====CORRUPT_BOUNDARY_123====
Content-Type: text/plain; charset=utf-8

Please click here to update your credentials immediately:
hxxp://185.220.101.5/verify.php
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", encoding="utf-8", delete=False) as tf:
        tf.write(sample_eml)
        temp_path = Path(tf.name)

    try:
        res = analyze_email_forensics(temp_path)
        # Sender mismatch
        assert res.sender_reply_to_mismatch is True
        # Check authentication results
        auth_protocols = {a.protocol: a for a in res.auth_results}
        assert "SPF" in auth_protocols and auth_protocols["SPF"].status == "fail"
        assert "DKIM" in auth_protocols and auth_protocols["DKIM"].status == "fail"
        assert "DMARC" in auth_protocols and auth_protocols["DMARC"].status == "fail"
        assert "ARC" in auth_protocols and auth_protocols["ARC"].status == "pass"

        # Check hops and delay
        assert len(res.hops) == 2
        assert res.hops[0].delay_seconds is not None
        assert res.hops[1].delay_seconds is not None
        assert res.hops[1].delay_seconds >= 30  # 12:01:45 to 12:02:15 = 30 seconds delta

        # Check limitations documentation
        assert len(res.accuracy_and_limitations) >= 4
    finally:
        if temp_path.exists():
            temp_path.unlink()


# --- 6. OFFLINE PCAP & TLS SNI EXTRACTION TESTS ---
def test_tls_sni_extraction_from_bytes():
    """Verify raw byte extraction of Server Name Indication (SNI) from TLS ClientHello."""
    hostname = "c2-beacon.dark-apt-infra.com"
    hn_bytes = hostname.encode("utf-8")
    
    # Construct synthetic TLS ClientHello packet
    client_random = b"\xAA" * 32
    session_id = b""
    cipher_suites = b"\xC0\x2F\xC0\x30"  # 4 bytes
    compression = b"\x00"  # 1 byte
    
    # SNI extension: type 0 (2 bytes) + ext_len (2 bytes) + list_len (2 bytes) + type 0 (1 byte) + name_len (2 bytes) + hostname
    sni_ext_payload = struct.pack(">HBH", len(hn_bytes) + 3, 0, len(hn_bytes)) + hn_bytes
    sni_extension = struct.pack(">HH", 0, len(sni_ext_payload)) + sni_ext_payload
    extensions = struct.pack(">H", len(sni_extension)) + sni_extension
    
    handshake_body = (
        b"\x03\x03" +  # TLS 1.2
        client_random +
        b"\x00" +  # session id len 0
        struct.pack(">H", len(cipher_suites)) + cipher_suites +
        b"\x01" + compression +
        extensions
    )
    
    handshake_hdr = b"\x01" + struct.pack(">I", len(handshake_body))[1:]  # 0x01 + 3-byte length
    handshake = handshake_hdr + handshake_body
    
    record_hdr = b"\x16\x03\x01" + struct.pack(">H", len(handshake))  # Type 0x16, TLS 1.0 record
    tls_packet_payload = record_hdr + handshake

    extracted = extract_tls_sni(tls_packet_payload)
    assert extracted == hostname


def test_offline_pcap_analysis_with_scapy():
    """Create a synthetic PCAP using Scapy with DNS, HTTP, and TLS packets and test offline parsing."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.utils import wrpcap
    from scapy.packet import Raw

    pkts = []
    # 1. DNS Packet
    dns_pkt = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53211, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="suspicious-domain-lookup.xyz")
    )
    pkts.append(dns_pkt)

    # 2. HTTP Packet with Basic Auth
    http_payload = b"GET /admin HTTP/1.1\r\nHost: internal-proxy.corp\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n\r\n"
    http_pkt = IP(src="192.168.1.100", dst="10.0.0.5") / TCP(sport=49152, dport=80, flags="PA") / Raw(load=http_payload)
    pkts.append(http_pkt)

    # 3. Write to temporary PCAP file
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)

    try:
        wrpcap(str(pcap_path), pkts)
        res = analyze_pcap_forensics(pcap_path)
        assert res.total_packets == 2
        assert len(res.dns_queries) >= 1
        assert res.dns_queries[0].query_name == "suspicious-domain-lookup.xyz"
        assert len(res.http_requests) >= 1
        assert res.http_requests[0]["has_auth"] is True

        # Cleartext credential anomaly
        creds_anomalies = [a for a in res.anomalies if "Cleartext Authentication" in a.title]
        assert len(creds_anomalies) == 1

        # Accuracy and limitations
        assert len(res.accuracy_and_limitations) >= 5
    finally:
        if pcap_path.exists():
            pcap_path.unlink()


# --- 7. MULTI-STAGE IOC CORRELATION ENGINE TESTS ---
def test_ioc_correlation_engine():
    """Verify cross-corroboration weighting and evidentiary tri-categorization."""
    raw_indicators = [
        {"ioc": "198.51.100.44", "source": "quarantine/sample_beacon.exe (Extracted String)"},
        {"ioc": "198.51.100.44", "source": "network/traffic_capture.pcap (Outbound TCP Session)"},
        {"ioc": "198.51.100.44", "source": "email/phishing_sample.eml (Relay Hop)"},
        {"ioc": "secure-login-update-account.com", "source": "email/phishing_sample.eml (Body Link)"},
        {"ioc": "8.8.8.8", "source": "network/traffic_capture.pcap (DNS Query)"}
    ]

    response = correlate_indicators(raw_indicators)
    assert response.total_indicators == 3  # 198.51.100.44, secure-login..., 8.8.8.8
    assert response.corroborated_indicators_count >= 1

    # Find the 3-source corroborated C2 IP
    c2_ioc = next(item for item in response.correlated_items if item.ioc_value == "198.51.100.44")
    assert c2_ioc.corroboration_level == "Cross-Disciplinary (3+ Sources)"
    assert c2_ioc.confidence_weight == 1.0
    assert c2_ioc.evidentiary_category == "verified_evidence"
    assert c2_ioc.intel_score >= 80.0

    # Clean DNS resolver
    dns_ioc = next(item for item in response.correlated_items if item.ioc_value == "8.8.8.8")
    assert dns_ioc.intel_score == 0.0

    # Summary breakdown
    assert "verified_evidence" in response.evidentiary_summary
    assert len(response.accuracy_and_limitations) >= 4


# --- 8. STRUCTURED FORENSIC REPORTING (PDF & JSON) TESTS ---
def test_forensic_reporting_standards_and_limitations():
    """Verify that generated JSON and PDF reports contain accuracy/limitations and non-attribution rule."""
    mock_inv = Investigation(
        id="INV-2026-TEST",
        title="APT Emotet Telemetry Analysis",
        description="Forensic investigation into spear-phishing and C2 beaconing.",
        status="open",
        priority="critical",
        lead_analyst="Senior DFIR Engineer",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

    mock_ev = Evidence(
        id="EV-001",
        investigation_id="INV-2026-TEST",
        name="Quarantined Payload",
        original_filename="invoice_march.exe",
        stored_filename="invoice_march_quarantined.exe",
        file_path="quarantine/invoice_march.exe",
        file_size_bytes=1024,
        sha256="ed01ebf83334a19373070b818de2e95a415239b6d3663a58d4e9d98717f782de",
        sha512="a" * 128,
        md5="b" * 32,
        magic_signature="Windows Portable Executable (PE / MZ)",
        file_type_mismatch=False,
        entropy="6.8",
        acquisition_timestamp=datetime.now(timezone.utc),
        acquired_by="Investigator Agent",
        badge_number="DFIR-7701",
        source_description="Extracted from email attachment",
        is_quarantined=True,
        integrity_status="verified",
        last_verified_at=datetime.now(timezone.utc)
    )
    mock_inv.evidence_items.append(mock_ev)

    mock_ioc = InvestigationIOC(
        id="IOC-001",
        investigation_id="INV-2026-TEST",
        ioc_type="ip",
        value="198.51.100.44",
        classification="C2 Command & Control",
        threat_score=90.0,
        category="c2",
        attribution_source="PCAP & Threat Intel Repository",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        notes="Corroborated Cobalt Strike beacon"
    )
    mock_inv.iocs.append(mock_ioc)

    mock_note_fact = InvestigationNote(
        id="NOTE-001",
        investigation_id="INV-2026-TEST",
        author="Lead Analyst",
        badge_number="DFIR-7701",
        content="SHA-256 hash verified against acquisition record.",
        is_finding="verified_fact",
        created_at=datetime.now(timezone.utc)
    )
    mock_note_hypo = InvestigationNote(
        id="NOTE-002",
        investigation_id="INV-2026-TEST",
        author="Lead Analyst",
        badge_number="DFIR-7701",
        content="High probability of secondary lateral movement staging.",
        is_finding="hypothesis",
        created_at=datetime.now(timezone.utc)
    )
    mock_inv.notes.extend([mock_note_fact, mock_note_hypo])

    # 1. JSON Report Validation
    json_report = generate_json_investigation_report(mock_inv)
    assert "forensic_standards_compliance" in json_report
    assert "non_attribution_rule" in json_report["forensic_standards_compliance"]
    assert "methodology_accuracy_and_limitations" in json_report
    assert len(json_report["methodology_accuracy_and_limitations"]) == 4
    assert len(json_report["forensic_findings"]["observed_facts"]) == 1
    assert len(json_report["forensic_findings"]["analyst_interpretations_and_hypotheses"]) == 1

    # 2. PDF Report Validation
    export_req = ReportExportRequest(
        format="pdf",
        include_evidence=True,
        include_iocs=True,
        include_timeline=True,
        include_notes=True,
        analyst_signature="Senior Examiner",
        badge_number="DFIR-7701"
    )
    pdf_bytes = generate_pdf_investigation_report(mock_inv, export_req)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF")
