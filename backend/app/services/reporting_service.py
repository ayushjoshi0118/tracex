import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from backend.app.models.investigation import Investigation
from backend.app.schemas.entities import ReportExportRequest

CORE_LIMITATIONS_DOCUMENTATION = [
    {
        "module": "Module 1: File Forensics & Structural Parsing",
        "description": "Cryptographic SHA-256/512 hashing is 100% mathematically deterministic. Shannon entropy indicates packing or compression, not malicious intent. Magic byte matches can be bypassed by polyglots. Structural anomalies and extension mismatches alone NEVER prove malware."
    },
    {
        "module": "Module 2: Threat Intelligence & Provenance",
        "description": "Feed indicators decay over time due to dynamic cloud IPs and domain reallocation. Unmatched indicators indicate unindexed assets, not verified benign status. Every lookup records explicit provider provenance and retrieval timestamp."
    },
    {
        "module": "Module 3: Email Forensics & Relay Analysis",
        "description": "Transit delays rely on MTA timestamps subject to minor clock drift. Missing SPF/DKIM/DMARC records represent an unconfigured security baseline, which must not be conflated with an active cryptographic spoofing failure."
    },
    {
        "module": "Module 4: Offline Network Forensics",
        "description": "Passive packet inspection without active probes. TLS SNI extraction inspects unencrypted ClientHello headers; ECH or raw IP traffic conceals SNI. High-entropy DNS flags potential tunneling or benign CDN lookups."
    }
]

def generate_json_investigation_report(inv: Investigation) -> Dict[str, Any]:
    """
    Produce a structured, machine-readable forensic report in JSON format.
    Explicitly separates:
    1. Verified Physical/Cryptographic Evidence (Observed Facts)
    2. External Threat Intelligence Records
    3. Analyst Hypotheses and Interpretations
    4. Technical Accuracy and Limitations documentation
    """
    now = datetime.now(timezone.utc)
    
    evidence_list = []
    for ev in inv.evidence_items:
        evidence_list.append({
            "evidence_id": ev.id,
            "name": ev.name,
            "original_filename": ev.original_filename,
            "file_size_bytes": ev.file_size_bytes,
            "cryptographic_hashes": {
                "sha256": ev.sha256,
                "sha512": ev.sha512,
                "md5": ev.md5
            },
            "file_type": ev.magic_signature,
            "extension_mismatch": ev.file_type_mismatch,
            "shannon_entropy": ev.entropy,
            "acquisition": {
                "timestamp": ev.acquisition_timestamp.isoformat() if ev.acquisition_timestamp else None,
                "acquired_by": ev.acquired_by,
                "badge_number": ev.badge_number,
                "source": ev.source_description
            },
            "integrity_status": ev.integrity_status,
            "last_verified_at": ev.last_verified_at.isoformat() if ev.last_verified_at else None,
            "custody_chain_length": len(ev.custody_logs)
        })

    iocs_list = []
    for ioc in inv.iocs:
        iocs_list.append({
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "threat_classification": ioc.classification,
            "threat_score": ioc.threat_score,
            "category": ioc.category,
            "provenance_source": ioc.attribution_source,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "notes": ioc.notes
        })

    timeline_list = []
    for evt in inv.timeline_events:
        timeline_list.append({
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
            "title": evt.title,
            "description": evt.description,
            "category": evt.category,
            "severity": evt.severity,
            "source": evt.source,
            "raw_reference": evt.raw_reference
        })

    facts = []
    interpretations = []
    for n in inv.notes:
        note_dict = {
            "author": n.author,
            "badge": n.badge_number,
            "created_at": n.created_at.isoformat() if n.created_at else None,
            "content": n.content,
            "type": n.is_finding
        }
        if n.is_finding in ["verified_fact", "observation"]:
            facts.append(note_dict)
        else:
            interpretations.append(note_dict)

    return {
        "platform": "TRACEX Digital Forensics & Threat Intelligence Platform",
        "tagline": "Investigate. Analyze. Correlate. Discover.",
        "report_type": "Official Forensic Investigation Dossier",
        "generated_at": now.isoformat(),
        "forensic_standards_compliance": {
            "evidentiary_standard": "ISO/IEC 27037 Digital Evidence Handling Guidelines",
            "non_attribution_rule": "Suspicious metadata, high Shannon entropy, or file extension mismatches are structural heuristics and are NEVER claimed as definitive malware detection without dynamic behavioral confirmation or reverse engineering.",
            "provenance_mandate": "Every threat intelligence indicator records explicit provider attribution, query timestamp, and retrieval status."
        },
        "investigation": {
            "id": inv.id,
            "title": inv.title,
            "description": inv.description,
            "status": inv.status,
            "priority": inv.priority,
            "lead_analyst": inv.lead_analyst,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "updated_at": inv.updated_at.isoformat() if inv.updated_at else None
        },
        "verified_evidence_artifacts": evidence_list,
        "threat_intelligence_iocs": iocs_list,
        "chronological_event_timeline": timeline_list,
        "forensic_findings": {
            "observed_facts": facts,
            "analyst_interpretations_and_hypotheses": interpretations
        },
        "methodology_accuracy_and_limitations": CORE_LIMITATIONS_DOCUMENTATION
    }

def generate_pdf_investigation_report(inv: Investigation, options: ReportExportRequest) -> bytes:
    """
    Render a forensic PDF report with cryptographic tables, timeline,
    separation of facts from analyst interpretations, and technical limitations.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0284c7")
    )
    h2_style = ParagraphStyle(
        "ReportH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )
    warning_style = ParagraphStyle(
        "ReportWarning",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#b45309")
    )

    story = []

    # Header Banner
    story.append(Paragraph("TRACEX // DEFENSIVE FORENSICS & THREAT INTELLIGENCE", subtitle_style))
    story.append(Paragraph(f"FORENSIC REPORT: {inv.id}", title_style))
    story.append(Paragraph(f"Title: {inv.title} | Status: {inv.status.upper()} | Priority: {inv.priority.upper()}", body_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0ea5e9"), spaceAfter=12))

    # Executive Overview
    story.append(Paragraph("1. INVESTIGATION SUMMARY & METADATA", h2_style))
    overview_data = [
        [Paragraph("<b>Investigation ID:</b>", body_style), Paragraph(inv.id, mono_style),
         Paragraph("<b>Lead Analyst:</b>", body_style), Paragraph(f"{inv.lead_analyst} ({options.badge_number})", body_style)],
        [Paragraph("<b>Creation Date:</b>", body_style), Paragraph(str(inv.created_at)[:19], body_style),
         Paragraph("<b>Report Generated:</b>", body_style), Paragraph(str(datetime.now(timezone.utc))[:19] + " UTC", body_style)],
        [Paragraph("<b>Evidence Items:</b>", body_style), Paragraph(str(len(inv.evidence_items)), body_style),
         Paragraph("<b>Associated IOCs:</b>", body_style), Paragraph(str(len(inv.iocs)), body_style)],
    ]
    overview_table = Table(overview_data, colWidths=[1.4 * inch, 2.2 * inch, 1.4 * inch, 2.4 * inch])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 12))

    # Case Description
    if inv.description:
        story.append(Paragraph(f"<b>Case Objective:</b> {inv.description}", body_style))
        story.append(Spacer(1, 10))

    # Evidence & Cryptographic Fingerprints Table
    if options.include_evidence and inv.evidence_items:
        story.append(Paragraph("2. EVIDENCE INTEGRITY & CRYPTOGRAPHIC HASHES (OBSERVED FACTS)", h2_style))
        story.append(Paragraph("<i>All evidence is stored in isolated quarantine outside the public web root. Hashes represent verified SHA-256 baselines.</i>", body_style))
        story.append(Spacer(1, 6))

        evidence_rows = [
            [Paragraph("<b>ID</b>", body_style),
             Paragraph("<b>Original Name</b>", body_style),
             Paragraph("<b>Size</b>", body_style),
             Paragraph("<b>SHA-256 Fingerprint</b>", body_style),
             Paragraph("<b>Integrity</b>", body_style)]
        ]

        for item in inv.evidence_items:
            evidence_rows.append([
                Paragraph(item.id, mono_style),
                Paragraph(item.original_filename[:20], body_style),
                Paragraph(f"{item.file_size_bytes} B", body_style),
                Paragraph(item.sha256[:28] + "...", mono_style),
                Paragraph(item.integrity_status.upper(), body_style)
            ])

        ev_table = Table(evidence_rows, colWidths=[1.1 * inch, 1.8 * inch, 0.9 * inch, 2.6 * inch, 1.0 * inch])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(ev_table)
        story.append(Spacer(1, 14))

    # Threat Intelligence IOCs
    if options.include_iocs and inv.iocs:
        story.append(Paragraph("3. INDICATORS OF COMPROMISE (EXTERNAL INTEL)", h2_style))
        ioc_rows = [
            [Paragraph("<b>Type</b>", body_style),
             Paragraph("<b>Indicator Value</b>", body_style),
             Paragraph("<b>Class</b>", body_style),
             Paragraph("<b>Score</b>", body_style),
             Paragraph("<b>Attribution Source</b>", body_style)]
        ]

        for ioc in inv.iocs:
            ioc_rows.append([
                Paragraph(ioc.ioc_type.upper(), body_style),
                Paragraph(ioc.value[:32], mono_style),
                Paragraph(ioc.classification.upper(), body_style),
                Paragraph(f"{ioc.threat_score}/100", body_style),
                Paragraph(ioc.attribution_source[:24], body_style)
            ])

        ioc_table = Table(ioc_rows, colWidths=[0.9 * inch, 2.5 * inch, 1.3 * inch, 0.9 * inch, 1.8 * inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 14))

    # Findings: Facts vs Analyst Interpretations
    if options.include_notes and inv.notes:
        story.append(Paragraph("4. FORENSIC FINDINGS & ANALYST ASSESSMENTS", h2_style))
        story.append(Paragraph("<i>Strict evidentiary separation between observed technical facts and analytical hypotheses:</i>", body_style))
        story.append(Spacer(1, 6))

        for note in inv.notes:
            is_fact = note.is_finding in ["verified_fact", "observation"]
            badge_color = "#10b981" if is_fact else "#f59e0b"
            badge_label = "[VERIFIED FACT]" if is_fact else "[ANALYST INTERPRETATION]"
            
            note_content = f"<b><font color='{badge_color}'>{badge_label}</font> Recorded by {note.author} ({note.badge_number}):</b><br/>{note.content}"
            story.append(Paragraph(note_content, body_style))
            story.append(Spacer(1, 6))

    # Technical Accuracy and Limitations Section
    story.append(Paragraph("5. METHODOLOGY, ACCURACY & TECHNICAL LIMITATIONS", h2_style))
    story.append(Paragraph(
        "<b>Evidentiary Non-Attribution Standard:</b> Suspicious metadata, high Shannon entropy, or extension discrepancies are structural heuristics. In accordance with ISO/IEC 27037 forensic guidelines, they are <u>never</u> claimed as definitive proof of malware without dynamic behavioral confirmation or reverse engineering.",
        warning_style
    ))
    story.append(Spacer(1, 6))

    limitation_rows = [
        [Paragraph("<b>Forensic Module</b>", body_style), Paragraph("<b>Methodology & Operational Boundaries</b>", body_style)]
    ]
    for lim in CORE_LIMITATIONS_DOCUMENTATION:
        limitation_rows.append([
            Paragraph(f"<b>{lim['module']}</b>", body_style),
            Paragraph(lim['description'], body_style)
        ])

    lim_table = Table(limitation_rows, colWidths=[2.2 * inch, 5.2 * inch])
    lim_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(lim_table)

    # Sign-off & Audit Certification
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
    story.append(Paragraph(f"<b>Certified Forensic Examiner:</b> {options.analyst_signature}", body_style))
    story.append(Paragraph(f"<b>Analyst Badge Number:</b> {options.badge_number}", body_style))
    story.append(Paragraph("<i>This document represents a legally defensible digital forensics report generated by the TRACEX platform. Chain of custody hash verification certificates are archived in the immutable ledger.</i>", subtitle_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
