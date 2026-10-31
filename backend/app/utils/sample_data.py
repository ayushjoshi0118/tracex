import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy.orm import Session

# Suppress Scapy layer 2 warnings for offline generation
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR

from backend.app.config import settings
from backend.app.models.investigation import Investigation
from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyLog
from backend.app.models.ioc import InvestigationIOC
from backend.app.models.timeline import TimelineEvent
from backend.app.models.note import InvestigationNote
from backend.app.services.evidence_service import register_evidence_item

def create_sample_eml(file_path: Path):
    """Generate realistic phishing test .eml file."""
    content = """Received: from mail-relay-ext.suspicious-net.ru (mail-relay-ext.suspicious-net.ru [185.220.101.5])
    by mx.corporate-defense.com with ESMTP id 8F92AB12
    for <cfo@corporate-defense.com>; Fri, 30 Oct 2026 14:22:10 +0000
Received: from internal-spoof-node ([10.0.4.15])
    by mail-relay-ext.suspicious-net.ru with HTTP;
    Fri, 30 Oct 2026 14:21:45 +0000
From: "Corporate Security Office" <security-alerts@corporate-defense.com>
Reply-To: "External Audit Team" <verify@secure-login-update-account.com>
Return-Path: <bounce-daemon@suspicious-net.ru>
To: <cfo@corporate-defense.com>
Subject: URGENT: Mandatory Executive Credential Verification Required Immediately
Date: Fri, 30 Oct 2026 14:21:40 +0000
Message-ID: <20261030142140.8A9F1B2C@corporate-defense.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: softfail (corporate-defense.com: domain of security-alerts@corporate-defense.com does not designate 185.220.101.5 as permitted sender)
Authentication-Results: mx.corporate-defense.com;
    spf=softfail smtp.mailfrom=security-alerts@corporate-defense.com;
    dkim=fail header.d=corporate-defense.com;
    dmarc=fail (p=QUARANTINE dis=QUARANTINE)

ATTENTION CFO:

Our threat detection platform detected an unauthorized login attempt against your executive workstation.
Your account access is scheduled to be terminated in 2 hours unless confirmed.

Please verify your corporate credentials immediately at the link below:
http://185.220.101.5/auth/login.php?user=cfo@corporate-defense.com

Alternative verification mirror:
https://secure-login-update-account.com/sso/session-reset

Regards,
Corporate Security IT Operations
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

def create_sample_pcap(file_path: Path):
    """Generate safe forensic PCAP with DNS, HTTP, and anomalous C2 packets."""
    pkts = []
    base_t = datetime.now(timezone.utc).timestamp() - 600

    # 1. Normal DNS resolution
    pkt1 = Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=53120, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="google.com")
    )
    pkt1.time = base_t + 1.0
    pkts.append(pkt1)

    pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.105") / UDP(sport=53, dport=53120) / DNS(
        qr=1, rd=1, ra=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.190.46")
    )
    pkt2.time = base_t + 1.05
    pkts.append(pkt2)

    # 2. Suspicious High Entropy DNS Tunneling
    pkt3 = Ether() / IP(src="192.168.1.105", dst="198.51.100.44") / UDP(sport=54210, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="a8f92cb78e0192a54fb2890aef.exfil.update-server-cdn-check.net")
    )
    pkt3.time = base_t + 12.0
    pkts.append(pkt3)

    # 3. HTTP Request with cleartext auth header
    http_payload = b"POST /api/v1/auth HTTP/1.1\r\nHost: internal-portal.local\r\nAuthorization: Basic YWRtaW46U3VwZXJTZWNyZXQyMDI2IQ==\r\nUser-Agent: Mozilla/5.0 ForensicsTest\r\nContent-Length: 14\r\n\r\nuser=root&pw=1"
    pkt4 = Ether() / IP(src="192.168.1.105", dst="10.0.0.1") / TCP(sport=49152, dport=80, flags="PA") / http_payload
    pkt4.time = base_t + 15.0
    pkts.append(pkt4)

    # 4. Anomalous Reverse Shell Connection on Port 4444
    pkt5 = Ether() / IP(src="192.168.1.105", dst="198.51.100.44") / TCP(sport=51234, dport=4444, flags="PA") / b"Microsoft Windows [Version 10.0.19045.3803]\nC:\\Users\\Victim> whoami\n"
    pkt5.time = base_t + 20.0
    pkts.append(pkt5)

    wrpcap(str(file_path), pkts)

def create_sample_powershell_dropper(file_path: Path):
    """Generate safe sample PowerShell dropper script for file forensics and YARA testing."""
    content = """<#
.SYNOPSIS
    Simulated Threat Emulation Dropper Artifact for Forensics Training
#>
[CmdletBinding()]
param()

Write-Host "[+] Initializing security update diagnostic check..." -ForegroundColor Cyan
# Base64 encoded test payload containing MZ PE signature simulation
$encodedPayload = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABPE"

$targetHost = "http://198.51.100.44:4444/beacon.bin"
$injectionTarget = "svchost.exe"

# Suspicious Windows API strings for static detection
$apis = @("VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory")
Write-Verbose "Simulating injection API resolution: $($apis -join ', ')"

function Invoke-DownloadTest {
    param([string]$Url)
    Write-Output "Downloading telemetry from: $Url"
    # powershell -enc download cradle simulation
}
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

def seed_initial_forensic_database(db: Session):
    """Populates the database with realistic demonstration cases if empty."""
    existing_cases = db.query(Investigation).count()
    if existing_cases > 0:
        return

    # Seed Sample Artifact Files
    sample_dir = settings.BASE_DIR / "sample_artifacts"
    sample_dir.mkdir(parents=True, exist_ok=True)

    eml_sample = sample_dir / "spear_phishing_executive.eml"
    pcap_sample = sample_dir / "c2_beaconing_network_trace.pcap"
    ps1_sample = sample_dir / "dropper_simulation.ps1"

    create_sample_eml(eml_sample)
    create_sample_pcap(pcap_sample)
    create_sample_powershell_dropper(ps1_sample)

    now = datetime.now(timezone.utc)

    # 1. Primary Investigation Case
    case1_id = "INV-2026-001"
    case1 = Investigation(
        id=case1_id,
        title="Operation SilentBeacon: Executive Spear-Phishing & Lateral C2",
        description="Comprehensive forensic triage investigating suspected BEC credential harvesting targeting the Chief Financial Officer, followed by DNS tunneling and anomalous egress traffic.",
        status="active",
        priority="critical",
        lead_analyst="Specialist R. Vance",
        created_at=now - timedelta(days=2),
        updated_at=now
    )
    db.add(case1)
    db.flush()

    # 2. Register Evidence in Case 1
    # Register EML
    ev1 = register_evidence_item(
        db=db,
        file_path=eml_sample,
        original_filename="spear_phishing_executive.eml",
        stored_filename=f"seed_{eml_sample.name}",
        name="Seized CFO Mailbox EML Artifact",
        acquired_by="Specialist R. Vance",
        badge_number="DFIR-8820",
        investigation_id=case1_id,
        source_description="Extracted directly from Microsoft 365 Exchange Online Mailbox of CFO",
        notes="Email received with softfail SPF, invalid DKIM, and spoofed security team address."
    )

    # Register PCAP
    ev2 = register_evidence_item(
        db=db,
        file_path=pcap_sample,
        original_filename="c2_beaconing_network_trace.pcap",
        stored_filename=f"seed_{pcap_sample.name}",
        name="Perimeter Gateway Egress Capture",
        acquired_by="Agent S. Chen",
        badge_number="DFIR-4109",
        investigation_id=case1_id,
        source_description="Mirror port pcap tap from core boundary switch",
        notes="Contains suspicious DNS tunneling to update-server-cdn-check.net and TCP port 4444 egress."
    )

    # 3. Associate IOCs
    iocs_to_add = [
        InvestigationIOC(
            investigation_id=case1_id,
            ioc_type="ip",
            value="185.220.101.5",
            category="tor_exit",
            threat_score=95.0,
            classification="malicious",
            attribution_source="AbuseIPDB & Tor Project Directory",
            notes="Relay node originating the phishing attack."
        ),
        InvestigationIOC(
            investigation_id=case1_id,
            ioc_type="ip",
            value="198.51.100.44",
            category="c2",
            threat_score=90.0,
            classification="malicious",
            attribution_source="Firewall Egress Telemetry",
            notes="Active destination for reverse shell communication over port 4444."
        ),
        InvestigationIOC(
            investigation_id=case1_id,
            ioc_type="domain",
            value="secure-login-update-account.com",
            category="phishing",
            threat_score=92.0,
            classification="malicious",
            attribution_source="Email Body URL Extraction",
            notes="Credential harvester domain mimicking single sign-on portal."
        ),
        InvestigationIOC(
            investigation_id=case1_id,
            ioc_type="domain",
            value="update-server-cdn-check.net",
            category="dropzone",
            threat_score=88.0,
            classification="malicious",
            attribution_source="DNS Packet Inspection",
            notes="High-entropy subdomain query destination used for staging exfiltration."
        )
    ]
    for ioc in iocs_to_add:
        db.add(ioc)

    # 4. Timeline Events
    timeline_events = [
        TimelineEvent(
            investigation_id=case1_id,
            timestamp=now - timedelta(days=2, hours=4),
            title="Suspicious Inbound Email Received",
            description="Email received from spoofed sender 'security-alerts@corporate-defense.com' with SPF softfail.",
            category="email",
            severity="high",
            source="Mail Gateway",
            raw_reference=ev1.sha256
        ),
        TimelineEvent(
            investigation_id=case1_id,
            timestamp=now - timedelta(days=1, hours=22),
            title="Workstation Clicked Harvester Link",
            description="CFO workstation 192.168.1.105 queried DNS for deceptive domain secure-login-update-account.com.",
            category="network",
            severity="critical",
            source="DNS Resolver Logs",
            raw_reference="secure-login-update-account.com"
        ),
        TimelineEvent(
            investigation_id=case1_id,
            timestamp=now - timedelta(days=1, hours=21),
            title="High-Entropy DNS Exfiltration Detected",
            description="Anomalous queries matching pattern *.exfil.update-server-cdn-check.net logged.",
            category="network",
            severity="critical",
            source="Core Switch PCAP",
            raw_reference=ev2.sha256
        ),
        TimelineEvent(
            investigation_id=case1_id,
            timestamp=now - timedelta(hours=14),
            title="Evidence Seized & Quarantined",
            description="PCAP and EML artifacts secured into TRACEX forensic quarantine with SHA-256 baseline.",
            category="custody",
            severity="info",
            source="DFIR Vault Ingestion",
            raw_reference=ev1.id
        )
    ]
    for evt in timeline_events:
        db.add(evt)

    # 5. Analyst Notes (Separating Verified Facts from Interpretations)
    notes = [
        InvestigationNote(
            investigation_id=case1_id,
            author="Specialist R. Vance",
            badge_number="DFIR-8820",
            content="Baseline cryptographic hashes verified: EML SHA-256 matches acquisition manifest exactly. All evidence remains in immutable quarantine.",
            is_finding="verified_fact"
        ),
        InvestigationNote(
            investigation_id=case1_id,
            author="Specialist R. Vance",
            badge_number="DFIR-8820",
            content="Observed cleartext HTTP basic authorization payload in PCAP packet #4 containing 'admin:SuperSecret2026!'.",
            is_finding="verified_fact"
        ),
        InvestigationNote(
            investigation_id=case1_id,
            author="Agent S. Chen",
            badge_number="DFIR-4109",
            content="Analyst Assessment: The attacker likely leveraged credentials obtained from the phishing harvester to authenticate against internal service port 80, followed by deploying an interactive reverse shell to 198.51.100.44.",
            is_finding="interpretation"
        )
    ]
    for n in notes:
        db.add(n)

    # 6. Secondary Investigation Case
    case2_id = "INV-2026-002"
    case2 = Investigation(
        id=case2_id,
        title="Threat Hunting: Unauthorized Remote Registry & Persistence",
        description="Routine threat hunting investigation inspecting suspicious persistence keys and scheduled tasks discovered on dev workstation cluster.",
        status="in_review",
        priority="medium",
        lead_analyst="Agent S. Chen",
        created_at=now - timedelta(days=5),
        updated_at=now - timedelta(days=1)
    )
    db.add(case2)

    db.commit()
