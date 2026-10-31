import re
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.parse

from backend.app.schemas.forensics import (
    EmailForensicsResponse,
    AuthResultDetail,
    EmailHop,
    SuspiciousEmailUrl
)

def defang_url(url: str) -> str:
    """Safely defang URL so it cannot be clicked accidentally."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged

def parse_auth_headers(headers: email.message.EmailMessage) -> List[AuthResultDetail]:
    """
    Parse Authentication-Results and Received-SPF headers.
    CRITICAL: Clearly distinguishes between 'missing', 'failed', and 'verified pass'.
    """
    results: List[AuthResultDetail] = []
    
    # 1. Received-SPF header
    spf_header = headers.get("Received-SPF", "")
    auth_results_header = headers.get("Authentication-Results", "")
    
    # Parse SPF
    if spf_header:
        spf_lower = spf_header.lower()
        if "pass" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="pass",
                status_category="verified",
                details="Sender IP is authorized by domain's SPF record.",
                raw_header_value=spf_header[:120]
            ))
        elif "fail" in spf_lower and "softfail" not in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="fail",
                status_category="failed",
                details="Sender IP is explicitly NOT authorized (SPF Hard Fail - High Risk of Spoofing).",
                raw_header_value=spf_header[:120]
            ))
        elif "softfail" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="softfail",
                status_category="failed",
                details="Sender IP is likely not authorized (SPF Softfail).",
                raw_header_value=spf_header[:120]
            ))
        elif "neutral" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="neutral",
                status_category="unverified",
                details="Domain owner makes no statement on whether IP is authorized (SPF Neutral).",
                raw_header_value=spf_header[:120]
            ))
    elif "spf=pass" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="SPF",
            status="pass",
            status_category="verified",
            details="SPF pass recorded in Authentication-Results.",
            raw_header_value=auth_results_header[:120]
        ))
    elif "spf=fail" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="SPF",
            status="fail",
            status_category="failed",
            details="SPF fail recorded in Authentication-Results.",
            raw_header_value=auth_results_header[:120]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="SPF",
            status="missing",
            status_category="missing_unauthenticated",
            details="No SPF verification header present. Message lacks sender authorization checks.",
            raw_header_value=None
        ))

    # Parse DKIM
    dkim_sig = headers.get("DKIM-Signature", "")
    if "dkim=pass" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="pass",
            status_category="verified",
            details="Cryptographic signature verified against sender DNS public key.",
            raw_header_value=auth_results_header[:120]
        ))
    elif "dkim=fail" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="fail",
            status_category="failed",
            details="DKIM signature failed cryptographic verification (Possible tampering or replay attack).",
            raw_header_value=auth_results_header[:120]
        ))
    elif dkim_sig:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="signature_present",
            status_category="unverified",
            details="DKIM-Signature header present on message, verification details in transit.",
            raw_header_value=dkim_sig[:120]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="missing",
            status_category="missing_unauthenticated",
            details="No DKIM signature present on message. Message content integrity cannot be verified.",
            raw_header_value=None
        ))

    # Parse DMARC
    if "dmarc=pass" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="pass",
            status_category="verified",
            details="Domain owner policy satisfied (DMARC Pass).",
            raw_header_value=auth_results_header[:120]
        ))
    elif "dmarc=fail" in auth_results_header.lower():
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="fail",
            status_category="failed",
            details="DMARC alignment failed. Domain owner policy violated.",
            raw_header_value=auth_results_header[:120]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="missing",
            status_category="missing_unauthenticated",
            details="No DMARC evaluation header found. Domain does not enforce or report DMARC policy.",
            raw_header_value=None
        ))

    return results

def extract_email_hops(headers: email.message.EmailMessage) -> List[EmailHop]:
    """
    Parse 'Received' headers in reverse order (origin to destination) to trace relay hops.
    """
    received_headers = headers.get_all("Received", [])
    hops: List[EmailHop] = []
    
    # Process from origin (last received header) to destination (first received header)
    hop_num = 1
    for r_hdr in reversed(received_headers):
        # Extract 'from' and 'by'
        from_match = re.search(r'from\s+([^\s;]+)', r_hdr, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s;]+)', r_hdr, re.IGNORECASE)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r_hdr)
        time_match = re.search(r';\s*([^\r\n]+)$', r_hdr)
        
        from_server = from_match.group(1) if from_match else "Unknown Relay"
        by_server = by_match.group(1) if by_match else "Unknown Gateway"
        ip = ip_match.group(1) if ip_match else None
        timestamp_str = time_match.group(1).strip() if time_match else None

        hops.append(EmailHop(
            hop_number=hop_num,
            by_server=by_server,
            from_server=from_server,
            ip=ip,
            timestamp_str=timestamp_str,
            delay_seconds=0
        ))
        hop_num += 1

    return hops

def extract_urls_from_body(body_text: str) -> List[SuspiciousEmailUrl]:
    """
    Extract URLs from email body, check for direct IP destinations, and defang them.
    """
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`]+', re.IGNORECASE)
    raw_urls = url_pattern.findall(body_text)
    
    suspicious_urls: List[SuspiciousEmailUrl] = []
    seen = set()

    for url in raw_urls:
        url_clean = url.rstrip('.,;()[]"\'')
        if url_clean in seen:
            continue
        seen.add(url_clean)

        parsed = urllib.parse.urlparse(url_clean)
        domain = parsed.netloc.split(":")[0]
        
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
        is_punycode = "xn--" in domain.lower()
        
        risk = "Low"
        if is_ip:
            risk = "High (Direct IP destination bypasses DNS reputation)"
        elif is_punycode:
            risk = "Critical (Punycode / Homograph IDN deceptive domain)"
        elif any(k in url_clean.lower() for k in ["login", "verify", "update-account", "password", "session"]):
            risk = "Suspicious (Phishing credential harvester keywords)"

        suspicious_urls.append(SuspiciousEmailUrl(
            raw_url=url_clean,
            defanged_url=defang_url(url_clean),
            domain=domain,
            is_ip_address=is_ip,
            is_lookalike_punycode=is_punycode,
            potential_risk=risk
        ))

    return suspicious_urls

def analyze_email_forensics(file_path: Path) -> EmailForensicsResponse:
    """
    Parse RFC 822 / MIME email file (.eml) and extract full forensic indicators.
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("Subject", "(No Subject)")
    sender = msg.get("From", "Unknown Sender")
    reply_to = msg.get("Reply-To", None)
    return_path = msg.get("Return-Path", None)
    date_sent = msg.get("Date", None)
    message_id = msg.get("Message-ID", None)

    # Extract clean email addresses
    from_email_match = re.search(r'<([^>]+)>', sender)
    from_addr = from_email_match.group(1) if from_email_match else sender
    
    reply_to_addr = None
    if reply_to:
        reply_match = re.search(r'<([^>]+)>', reply_to)
        reply_to_addr = reply_match.group(1) if reply_match else reply_to

    # Check for Sender vs Reply-To Mismatch
    mismatch = False
    if reply_to_addr and from_addr:
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        reply_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            mismatch = True

    # Parse Authentication Headers
    auth_results = parse_auth_headers(msg)

    # Parse Email Hops
    hops = extract_email_hops(msg)

    # Extract Body and Attachments
    body_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "is_executable": any(filename.lower().endswith(ext) for ext in [".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".hta", ".js", ".ps1", ".docm", ".xlsm"])
                })
            elif content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode("utf-8", errors="replace"))
        except Exception:
            pass

    full_body = "\n".join(body_parts)
    extracted_urls = extract_urls_from_body(full_body)

    # Phishing indicators & heuristic score calculation
    phishing_indicators = []
    risk_score = 0.0

    if mismatch:
        risk_score += 35.0
        phishing_indicators.append({
            "category": "Sender Deception",
            "severity": "high",
            "indicator": f"Sender domain ({from_addr}) differs from Reply-To target ({reply_to_addr}). Typical BEC / phishing tactic."
        })

    # Failed Auth Penalties
    for auth in auth_results:
        if auth.status_category == "failed":
            risk_score += 30.0
            phishing_indicators.append({
                "category": f"Authentication Failure ({auth.protocol})",
                "severity": "critical",
                "indicator": f"{auth.protocol} verification failed: {auth.details}"
            })
        elif auth.status_category == "missing_unauthenticated":
            risk_score += 10.0
            phishing_indicators.append({
                "category": f"Missing Authentication ({auth.protocol})",
                "severity": "medium",
                "indicator": f"{auth.protocol} is missing on message headers."
            })

    # Suspicious urgency keywords in subject or body
    urgency_terms = ["urgent", "account suspended", "immediate action required", "password expired", "wire transfer", "unauthorized login", "payment overdue"]
    found_urgency = [term for term in urgency_terms if term in subject.lower() or term in full_body.lower()]
    if found_urgency:
        risk_score += 20.0
        phishing_indicators.append({
            "category": "Social Engineering",
            "severity": "medium",
            "indicator": f"Urgency keywords detected: {', '.join(found_urgency)}"
        })

    # Risky attachments
    risky_att = [a for a in attachments if a["is_executable"]]
    if risky_att:
        risk_score += 45.0
        phishing_indicators.append({
            "category": "Malicious Attachment",
            "severity": "critical",
            "indicator": f"Email carries dangerous executable/script attachments: {', '.join(a['filename'] for a in risky_att)}"
        })

    # Risky URLs
    high_risk_urls = [u for u in extracted_urls if "Critical" in u.potential_risk or "High" in u.potential_risk]
    if high_risk_urls:
        risk_score += 30.0
        phishing_indicators.append({
            "category": "Malicious Link",
            "severity": "high",
            "indicator": f"Found {len(high_risk_urls)} direct IP or lookalike URLs in email body."
        })

    risk_score = min(round(risk_score, 1), 100.0)

    verdict = "Clean"
    if risk_score >= 70:
        verdict = "Likely Phishing / Malicious Spoof"
    elif risk_score >= 35:
        verdict = "Suspicious Email"
    elif risk_score > 0:
        verdict = "Low Risk / Unauthenticated"

    return EmailForensicsResponse(
        message_id=message_id,
        subject=subject,
        sender=sender,
        sender_name=sender.split("<")[0].strip() if "<" in sender else None,
        return_path=return_path,
        reply_to=reply_to,
        sender_reply_to_mismatch=mismatch,
        date_sent=date_sent,
        recipients=[msg.get("To", "")] if msg.get("To") else [],
        cc=[msg.get("Cc", "")] if msg.get("Cc") else [],
        auth_results=auth_results,
        hops=hops,
        extracted_urls=extracted_urls,
        attachments=attachments,
        phishing_indicators=phishing_indicators,
        risk_score=risk_score,
        verdict=verdict,
        analysis_timestamp=datetime.now(timezone.utc)
    )
