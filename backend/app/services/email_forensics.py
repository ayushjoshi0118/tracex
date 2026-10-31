import re
import email
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
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

def safe_parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Safely parse RFC 2822 / 5322 date string into UTC datetime."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # Fallback regex for common non-standard formats
        try:
            m = re.search(r'(\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', date_str)
            if m:
                dt = datetime.strptime(m.group(1), "%d %b %Y %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        return None

def parse_auth_headers(headers: email.message.EmailMessage) -> List[AuthResultDetail]:
    """
    Parse Authentication-Results, Received-SPF, and ARC headers.
    CRITICAL: Strictly separates:
    1. 'verified' (Cryptographic or MTA policy verified pass)
    2. 'failed' (Explicit validation failure - spoofing or tampering indicator)
    3. 'missing_unauthenticated' (Missing security mechanism - unauthenticated baseline, NOT proof of attack)
    """
    results: List[AuthResultDetail] = []
    
    spf_header = headers.get("Received-SPF", "")
    auth_results_header = headers.get("Authentication-Results", "")
    arc_auth_header = headers.get("ARC-Authentication-Results", "")
    
    # --- 1. SPF (Sender Policy Framework) ---
    if spf_header:
        spf_lower = spf_header.lower()
        if "pass" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="pass",
                status_category="verified",
                details="Sender IP is explicitly authorized by the domain's SPF DNS record.",
                raw_header_value=spf_header[:140]
            ))
        elif "fail" in spf_lower and "softfail" not in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="fail",
                status_category="failed",
                details="Sender IP is explicitly NOT authorized (SPF Hard Fail - High risk of sender spoofing).",
                raw_header_value=spf_header[:140]
            ))
        elif "softfail" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="softfail",
                status_category="failed",
                details="Sender IP is likely unauthorized (SPF Softfail policy violation).",
                raw_header_value=spf_header[:140]
            ))
        elif "neutral" in spf_lower:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="neutral",
                status_category="unverified",
                details="Domain owner makes no explicit authorization statement for sending IP (SPF Neutral).",
                raw_header_value=spf_header[:140]
            ))
        else:
            results.append(AuthResultDetail(
                protocol="SPF",
                status="none",
                status_category="missing_unauthenticated",
                details="SPF evaluation yielded no policy declaration (SPF None).",
                raw_header_value=spf_header[:140]
            ))
    elif "spf=pass" in auth_results_header.lower() or "spf=pass" in arc_auth_header.lower():
        results.append(AuthResultDetail(
            protocol="SPF",
            status="pass",
            status_category="verified",
            details="SPF pass recorded in receiving MTA Authentication-Results header.",
            raw_header_value=auth_results_header[:140] if auth_results_header else arc_auth_header[:140]
        ))
    elif "spf=fail" in auth_results_header.lower() or "spf=fail" in arc_auth_header.lower():
        results.append(AuthResultDetail(
            protocol="SPF",
            status="fail",
            status_category="failed",
            details="SPF fail recorded in receiving MTA Authentication-Results header.",
            raw_header_value=auth_results_header[:140] if auth_results_header else arc_auth_header[:140]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="SPF",
            status="missing",
            status_category="missing_unauthenticated",
            details="No SPF verification header present. Message lacks sender IP authorization records.",
            raw_header_value=None
        ))

    # --- 2. DKIM (DomainKeys Identified Mail) ---
    dkim_sig = headers.get("DKIM-Signature", "")
    all_auth_text = f"{auth_results_header} {arc_auth_header}".lower()
    
    if "dkim=pass" in all_auth_text:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="pass",
            status_category="verified",
            details="Cryptographic signature verified against sender domain's DNS public key.",
            raw_header_value=(auth_results_header or arc_auth_header)[:140]
        ))
    elif "dkim=fail" in all_auth_text:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="fail",
            status_category="failed",
            details="DKIM signature failed cryptographic verification (indicates body/header modification or forgery).",
            raw_header_value=(auth_results_header or arc_auth_header)[:140]
        ))
    elif dkim_sig:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="signature_present",
            status_category="unverified",
            details="DKIM-Signature header present on message; awaiting relay validation.",
            raw_header_value=dkim_sig[:140]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="DKIM",
            status="missing",
            status_category="missing_unauthenticated",
            details="No DKIM signature present on message. Message content integrity cannot be verified.",
            raw_header_value=None
        ))

    # --- 3. DMARC (Domain-based Message Authentication) ---
    if "dmarc=pass" in all_auth_text:
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="pass",
            status_category="verified",
            details="Domain owner alignment policy satisfied (DMARC Pass).",
            raw_header_value=(auth_results_header or arc_auth_header)[:140]
        ))
    elif "dmarc=fail" in all_auth_text:
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="fail",
            status_category="failed",
            details="DMARC alignment failed. Domain owner policy violated.",
            raw_header_value=(auth_results_header or arc_auth_header)[:140]
        ))
    else:
        results.append(AuthResultDetail(
            protocol="DMARC",
            status="missing",
            status_category="missing_unauthenticated",
            details="No DMARC evaluation header found. Domain does not enforce or report DMARC policy.",
            raw_header_value=None
        ))

    # --- 4. ARC (Authenticated Received Chain) ---
    arc_seal = headers.get("ARC-Seal", "")
    if arc_seal or arc_auth_header:
        if "cv=pass" in arc_seal.lower() or "arc=pass" in all_auth_text:
            results.append(AuthResultDetail(
                protocol="ARC",
                status="pass",
                status_category="verified",
                details="Authenticated Received Chain (ARC) validated across intermediaries (cv=pass).",
                raw_header_value=arc_seal[:140] or arc_auth_header[:140]
            ))
        elif "cv=fail" in arc_seal.lower() or "arc=fail" in all_auth_text:
            results.append(AuthResultDetail(
                protocol="ARC",
                status="fail",
                status_category="failed",
                details="ARC chain validation failed. Intermediary authentication integrity compromised.",
                raw_header_value=arc_seal[:140] or arc_auth_header[:140]
            ))
        else:
            results.append(AuthResultDetail(
                protocol="ARC",
                status="chain_present",
                status_category="unverified",
                details="ARC headers present on message (ARC-Seal / ARC-Authentication-Results).",
                raw_header_value=arc_seal[:140]
            ))
    else:
        results.append(AuthResultDetail(
            protocol="ARC",
            status="not_configured",
            status_category="missing_unauthenticated",
            details="No ARC headers present. Message was delivered directly without intermediary chain validation.",
            raw_header_value=None
        ))

    return results

def extract_email_hops(headers: email.message.EmailMessage) -> List[EmailHop]:
    """
    Parse 'Received' headers in reverse order (origin to final recipient MTA)
    to trace relay hops and compute transit latency deltas.
    """
    received_headers = headers.get_all("Received", [])
    hops: List[EmailHop] = []
    
    # Process from origin (last Received header) to destination (first Received header)
    hop_num = 1
    prev_hop_dt: Optional[datetime] = None

    for r_hdr in reversed(received_headers):
        # Extract 'from' and 'by'
        from_match = re.search(r'from\s+([^\s;]+)', r_hdr, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s;]+)', r_hdr, re.IGNORECASE)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r_hdr)
        time_match = re.search(r';\s*([^\r\n]+)$', r_hdr)
        
        from_server = from_match.group(1) if from_match else "Unknown Origin / Relay"
        by_server = by_match.group(1) if by_match else "Unknown Gateway"
        ip = ip_match.group(1) if ip_match else None
        raw_timestamp = time_match.group(1).strip() if time_match else None

        hop_dt = safe_parse_date(raw_timestamp)
        delay_seconds: Optional[int] = None

        if hop_dt and prev_hop_dt:
            delta = int((hop_dt - prev_hop_dt).total_seconds())
            # Latency can be slightly negative due to minor unsynchronized MTA clocks
            delay_seconds = max(0, delta)
        elif hop_dt:
            delay_seconds = 0

        hops.append(EmailHop(
            hop_number=hop_num,
            by_server=by_server,
            from_server=from_server,
            ip=ip,
            timestamp_str=raw_timestamp,
            delay_seconds=delay_seconds
        ))

        if hop_dt:
            prev_hop_dt = hop_dt

        hop_num += 1

    return hops

def extract_urls_from_body(body_text: str) -> List[SuspiciousEmailUrl]:
    """
    Extract URLs from email body, check for direct IP destinations, punycode,
    and credential harvesting keywords, defanging each artifact.
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
            risk = "High (Direct IP destination bypasses DNS reputation filters)"
        elif is_punycode:
            risk = "Critical (Punycode / IDN homograph deceptive domain)"
        elif any(k in url_clean.lower() for k in ["login", "verify", "update-account", "password", "session", "bank", "secure-"]):
            risk = "Suspicious (Phishing credential harvester keywords in path)"

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
    Forensic analysis of RFC 822 / MIME email file (.eml).
    Handles malformed RFC 5322 headers, folded lines, corrupted multipart boundaries,
    non-standard dates, and strict SPF/DKIM/DMARC/ARC status.
    """
    # Defensive file read with fallback policy
    try:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception:
        # Fallback to compat32 policy for heavily non-compliant / malformed messages
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.compat32).parse(f)

    subject = str(msg.get("Subject", "(No Subject)"))
    sender = str(msg.get("From", "Unknown Sender"))
    reply_to = str(msg.get("Reply-To")) if msg.get("Reply-To") else None
    return_path = str(msg.get("Return-Path")) if msg.get("Return-Path") else None
    date_sent = str(msg.get("Date")) if msg.get("Date") else None
    message_id = str(msg.get("Message-ID")) if msg.get("Message-ID") else None

    # Clean address parsing
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

    # Parse Authentication Headers (SPF, DKIM, DMARC, ARC)
    auth_results = parse_auth_headers(msg)

    # Parse Email Hops and Transit Latency
    hops = extract_email_hops(msg)

    # Extract Body and Attachments safely
    body_parts = []
    attachments = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    filename = part.get_filename()

                    if "attachment" in content_disposition or filename:
                        filename = filename or "unnamed_attachment"
                        payload = part.get_payload(decode=True) or b""
                        attachments.append({
                            "filename": filename,
                            "content_type": content_type,
                            "size_bytes": len(payload),
                            "is_executable": any(filename.lower().endswith(ext) for ext in [
                                ".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".hta", ".js", ".ps1", ".docm", ".xlsm"
                            ])
                        })
                    elif content_type in ["text/plain", "text/html"]:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    continue
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode("utf-8", errors="replace"))
            else:
                body_parts.append(str(msg.get_payload() or ""))
    except Exception:
        body_parts.append("(Message body could not be decoded due to corrupted MIME boundary)")

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
            "indicator": f"Sender domain ({from_addr}) differs from Reply-To target ({reply_to_addr}). Classic BEC / spoofing indicator."
        })

    # Auth checks: failed is critical, missing is medium informational
    for auth in auth_results:
        if auth.status_category == "failed":
            risk_score += 30.0
            phishing_indicators.append({
                "category": f"Authentication Failure ({auth.protocol})",
                "severity": "critical",
                "indicator": f"{auth.protocol} verification failed: {auth.details}"
            })
        elif auth.status_category == "missing_unauthenticated" and auth.protocol in ["SPF", "DKIM"]:
            risk_score += 10.0
            phishing_indicators.append({
                "category": f"Missing Authentication ({auth.protocol})",
                "severity": "medium",
                "indicator": f"{auth.protocol} records are absent on message headers. Note: Missing authentication indicates lack of domain enforcement, not proven maliciousness."
            })

    # Urgency keywords in subject or body
    urgency_terms = ["urgent", "account suspended", "immediate action required", "password expired", "wire transfer", "unauthorized login", "payment overdue"]
    found_urgency = [term for term in urgency_terms if term in subject.lower() or term in full_body.lower()]
    if found_urgency:
        risk_score += 20.0
        phishing_indicators.append({
            "category": "Social Engineering",
            "severity": "medium",
            "indicator": f"Urgency keywords detected: {', '.join(found_urgency)}"
        })

    # Dangerous attachments
    risky_att = [a for a in attachments if a.get("is_executable")]
    if risky_att:
        risk_score += 45.0
        phishing_indicators.append({
            "category": "High Risk Attachment",
            "severity": "critical",
            "indicator": f"Email carries executable/macro attachment: {', '.join(a['filename'] for a in risky_att)}. Requires isolated sandbox analysis."
        })

    # Risky URLs
    high_risk_urls = [u for u in extracted_urls if "Critical" in u.potential_risk or "High" in u.potential_risk]
    if high_risk_urls:
        risk_score += 30.0
        phishing_indicators.append({
            "category": "Suspicious Link",
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

    accuracy_and_limitations = [
        "MIME & RFC 5322 Header Extraction: Extracts relay hops, timestamps, and routing headers. Headers added prior to the boundary MTA of the receiving organization can be fabricated by an attacker.",
        "SPF / DKIM / DMARC / ARC Verification: Evaluates receiving MTA authentication records. 'Missing' authentication signifies an unconfigured domain, distinct from an explicit cryptographic failure.",
        "Hop Transit Latency: Computed from timestamps in consecutive Received headers. Unsynchronized MTA system clocks may cause slight inaccuracies or negative delays.",
        "Defensive Forensic Principle: Missing email authentication and keyword matches are heuristic indicators of risk. They do not constitute conclusive proof of malicious intent without verified recipient targeting and telemetry."
    ]

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
        analysis_timestamp=datetime.now(timezone.utc),
        accuracy_and_limitations=accuracy_and_limitations
    )
