import os
import re
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict

# Suppress Scapy layer 2 warnings for offline PCAP processing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import Ether, ARP

from backend.app.schemas.forensics import (
    NetworkForensicsResponse,
    ProtocolStats,
    TopTalker,
    DNSQueryRecord,
    NetworkAnomaly
)
from backend.app.utils.security import calculate_shannon_entropy

SUSPICIOUS_PORTS = {
    4444: "Metasploit / Reverse Shell Default Port",
    1337: "Elite / Trojan Backdoor Port",
    6667: "IRC Botnet Communication",
    31337: "Back Orifice Trojan Port",
    8000: "Common Non-Standard HTTP Proxy/C2",
    8080: "Alternative HTTP / Proxy",
    8443: "Alternative HTTPS / Staging",
    5555: "Android ADB Remote Exploitation Target"
}

def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Safely extract Server Name Indication (SNI) hostname from TLS ClientHello packet bytes.
    Operates offline without requiring TLS decryption.
    """
    if len(payload) < 43:
        return None
    # TLS Record Header: Type 0x16 (Handshake)
    if payload[0] != 0x16:
        return None
    # Handshake Header: Type 0x01 (ClientHello)
    if len(payload) < 9 or payload[5] != 0x01:
        return None
    try:
        idx = 5 + 4  # skip record header + handshake header
        # Client Version (2 bytes) + Client Random (32 bytes) = 34 bytes
        idx += 34
        if idx >= len(payload):
            return None
        # Session ID length (1 byte)
        session_id_len = payload[idx]
        idx += 1 + session_id_len
        if idx + 2 > len(payload):
            return None
        # Cipher Suites length (2 bytes)
        cipher_suites_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + cipher_suites_len
        if idx + 1 > len(payload):
            return None
        # Compression Methods length (1 byte)
        compression_len = payload[idx]
        idx += 1 + compression_len
        if idx + 2 > len(payload):
            return None
        # Extensions length (2 bytes)
        extensions_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        end_extensions = idx + extensions_len
        
        while idx + 4 <= end_extensions and idx + 4 <= len(payload):
            ext_type = int.from_bytes(payload[idx:idx+2], "big")
            ext_len = int.from_bytes(payload[idx+2:idx+4], "big")
            idx += 4
            if ext_type == 0:  # server_name extension
                if idx + 5 <= len(payload):
                    # server_name_list_length (2) + name_type (1) + name_length (2)
                    name_len = int.from_bytes(payload[idx+3:idx+5], "big")
                    if idx + 5 + name_len <= len(payload):
                        hostname = payload[idx+5:idx+5+name_len].decode("utf-8", errors="ignore").strip()
                        if hostname:
                            return hostname
            idx += ext_len
    except Exception:
        pass
    return None

def analyze_pcap_forensics(file_path: Path, max_packets: int = 15000) -> NetworkForensicsResponse:
    """
    Offline forensic inspection of Libpcap/pcapng captures.
    Safely limits parsing up to max_packets to prevent denial-of-service / memory exhaustion.
    Performs DPI for DNS, HTTP, TLS SNI, and TCP flag heuristics.
    """
    filename = file_path.name
    file_size_bytes = os.path.getsize(file_path)

    total_packets = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    protocol_counts: Dict[str, int] = defaultdict(int)
    protocol_bytes: Dict[str, int] = defaultdict(int)
    
    # Talkers: ip -> {sent, recv, bytes, domains}
    talkers: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "sent": 0, "recv": 0, "bytes": 0, "domains": set()
    })

    # DNS queries
    dns_records: List[DNSQueryRecord] = []
    seen_dns_queries = set()

    # HTTP requests
    http_requests: List[Dict[str, Any]] = []

    # Conversations: (src, dst, proto) -> {packets, bytes, ports}
    conversations_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "src": "", "dst": "", "proto": ""
    })

    # Anomalies and heuristic metrics
    anomalies: List[NetworkAnomaly] = []
    suspicious_ports_found: Set[Tuple[int, str, str, str]] = set()
    high_entropy_dns_count = 0
    plaintext_creds_found = []
    tls_sni_seen: Set[str] = set()

    # TCP flag tracking for scan detection
    # ip -> set of targeted dst ports with SYN flag
    syn_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
    tcp_flag_counts: Dict[str, int] = defaultdict(int)

    try:
        with PcapReader(str(file_path)) as reader:
            for pkt in reader:
                total_packets += 1
                if total_packets > max_packets:
                    break

                try:
                    pkt_len = len(pkt)
                    pkt_time = float(pkt.time)
                except Exception:
                    continue

                if start_time is None or pkt_time < start_time:
                    start_time = pkt_time
                if end_time is None or pkt_time > end_time:
                    end_time = pkt_time

                # Protocol identification
                proto_name = "Other"
                src_ip = None
                dst_ip = None
                src_port = None
                dst_port = None

                if pkt.haslayer(ARP):
                    proto_name = "ARP"
                elif pkt.haslayer(ICMP):
                    proto_name = "ICMP"
                elif pkt.haslayer(DNS):
                    proto_name = "DNS"
                elif pkt.haslayer(TCP):
                    proto_name = "TCP"
                elif pkt.haslayer(UDP):
                    proto_name = "UDP"

                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst

                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    # TCP Flag Analysis
                    flags = pkt[TCP].flags
                    # Scapy flags: S (SYN), A (ACK), F (FIN), R (RST), P (PSH), U (URG)
                    flags_str = str(flags)
                    if "S" in flags_str and "A" not in flags_str:
                        tcp_flag_counts["SYN"] += 1
                        if src_ip and dst_port:
                            syn_scan_tracker[src_ip].add(dst_port)
                    elif "S" in flags_str and "A" in flags_str:
                        tcp_flag_counts["SYN-ACK"] += 1
                    elif "R" in flags_str:
                        tcp_flag_counts["RST"] += 1
                    elif "F" in flags_str:
                        tcp_flag_counts["FIN"] += 1

                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

                # Refine application protocol
                if (src_port == 80 or dst_port == 80) and proto_name == "TCP":
                    proto_name = "HTTP"
                elif (src_port == 443 or dst_port == 443) and proto_name == "TCP":
                    proto_name = "TLS/HTTPS"
                elif (src_port == 53 or dst_port == 53):
                    proto_name = "DNS"

                protocol_counts[proto_name] += 1
                protocol_bytes[proto_name] += pkt_len

                # Talker tracking
                if src_ip:
                    talkers[src_ip]["sent"] += 1
                    talkers[src_ip]["bytes"] += pkt_len
                if dst_ip:
                    talkers[dst_ip]["recv"] += 1
                    talkers[dst_ip]["bytes"] += pkt_len

                # Conversation tracking
                if src_ip and dst_ip:
                    conv_key = f"{min(src_ip, dst_ip)} <-> {max(src_ip, dst_ip)} ({proto_name})"
                    conversations_map[conv_key]["packets"] += 1
                    conversations_map[conv_key]["bytes"] += pkt_len
                    conversations_map[conv_key]["src"] = src_ip
                    conversations_map[conv_key]["dst"] = dst_ip
                    conversations_map[conv_key]["proto"] = proto_name

                # Check suspicious ports
                for p in [src_port, dst_port]:
                    if p in SUSPICIOUS_PORTS and src_ip and dst_ip:
                        suspicious_ports_found.add((p, SUSPICIOUS_PORTS[p], src_ip, dst_ip))

                # DNS Deep Inspection
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    try:
                        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                        qtype_num = pkt[DNSQR].qtype
                        qtype_str = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 12: "PTR"}.get(qtype_num, f"TYPE{qtype_num}")

                        answers = []
                        if pkt.haslayer(DNSRR) and pkt[DNS].ancount > 0:
                            for i in range(pkt[DNS].ancount):
                                rr = pkt[DNS].an[i]
                                if hasattr(rr, "rdata"):
                                    rdata_str = str(rr.rdata)
                                    if isinstance(rr.rdata, bytes):
                                        rdata_str = rr.rdata.decode("utf-8", errors="ignore")
                                    answers.append(rdata_str)

                        q_entropy = calculate_shannon_entropy(qname.encode("utf-8"))
                        if q_entropy > 4.2 and len(qname) > 30:
                            high_entropy_dns_count += 1

                        dns_key = f"{src_ip}:{qname}:{qtype_str}"
                        if dns_key not in seen_dns_queries and len(dns_records) < 100:
                            seen_dns_queries.add(dns_key)
                            dns_records.append(DNSQueryRecord(
                                query_name=qname,
                                query_type=qtype_str,
                                response_ips=answers[:4],
                                client_ip=src_ip or "0.0.0.0",
                                server_ip=dst_ip or "0.0.0.0",
                                timestamp=datetime.fromtimestamp(pkt_time, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3],
                                is_suspicious_tld=any(qname.endswith(f".{t}") for t in ["xyz", "top", "tk", "click", "buzz"]),
                                entropy=round(q_entropy, 2)
                            ))

                        if src_ip:
                            talkers[src_ip]["domains"].add(qname)
                    except Exception:
                        pass

                # HTTP & TLS Deep Inspection on TCP Payload
                if pkt.haslayer(TCP) and pkt[TCP].payload:
                    try:
                        payload_raw = bytes(pkt[TCP].payload)
                        
                        # 1. Check TLS SNI ClientHello
                        sni = extract_tls_sni(payload_raw)
                        if sni:
                            tls_sni_seen.add(sni)
                            if src_ip:
                                talkers[src_ip]["domains"].add(f"tls:{sni}")
                            if any(sni.endswith(f".{t}") for t in ["xyz", "top", "tk", "click", "buzz"]):
                                anomalies.append(NetworkAnomaly(
                                    title=f"Suspicious TLS SNI Destination ({sni})",
                                    description=f"TLS ClientHello from {src_ip} -> {dst_ip} requested hostname with high-risk TLD: {sni}",
                                    severity="medium"
                                ))

                        # 2. Check HTTP Methods
                        for method in [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE "]:
                            if payload_raw.startswith(method):
                                lines = payload_raw[:1024].decode("utf-8", errors="ignore").split("\r\n")
                                req_line = lines[0] if lines else ""
                                host_hdr = ""
                                ua_hdr = ""
                                auth_hdr = ""
                                for l in lines[1:]:
                                    if l.lower().startswith("host:"):
                                        host_hdr = l.split(":", 1)[1].strip()
                                    elif l.lower().startswith("user-agent:"):
                                        ua_hdr = l.split(":", 1)[1].strip()
                                    elif l.lower().startswith("authorization:"):
                                        auth_hdr = l.split(":", 1)[1].strip()

                                if auth_hdr and "Basic" in auth_hdr:
                                    plaintext_creds_found.append(f"{src_ip} -> {dst_ip} (HTTP Basic Auth)")

                                if host_hdr and src_ip:
                                    talkers[src_ip]["domains"].add(host_hdr)

                                if len(http_requests) < 50:
                                    http_requests.append({
                                        "client_ip": src_ip,
                                        "server_ip": dst_ip,
                                        "server_port": dst_port,
                                        "request_line": req_line[:120],
                                        "host": host_hdr or dst_ip,
                                        "user_agent": ua_hdr[:80] if ua_hdr else "None",
                                        "has_auth": bool(auth_hdr)
                                    })
                                break
                    except Exception:
                        pass
    except Exception as e:
        anomalies.append(NetworkAnomaly(
            title="PCAP Frame Inspection Notice",
            description=f"Stream encountered truncated or malformed frame boundaries: {str(e)}",
            severity="low"
        ))

    # Duration
    duration = 0.0
    if start_time and end_time and end_time >= start_time:
        duration = round(end_time - start_time, 2)

    # Format Protocol Distribution
    proto_dist: List[ProtocolStats] = []
    total_pkts_for_dist = max(total_packets, 1)
    for p_name, p_cnt in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
        proto_dist.append(ProtocolStats(
            protocol=p_name,
            packet_count=p_cnt,
            byte_count=protocol_bytes[p_name],
            percentage=round((p_cnt / total_pkts_for_dist) * 100, 1)
        ))

    # Format Top Talkers
    top_talkers_list: List[TopTalker] = []
    sorted_talkers = sorted(talkers.items(), key=lambda x: (x[1]["sent"] + x[1]["recv"]), reverse=True)[:10]
    for ip_addr, stats in sorted_talkers:
        top_talkers_list.append(TopTalker(
            ip=ip_addr,
            packets_sent=stats["sent"],
            packets_received=stats["recv"],
            bytes_total=stats["bytes"],
            associated_domains=list(stats["domains"])[:5]
        ))

    # Format Conversations
    convs_list = []
    for conv_key, c_data in sorted(conversations_map.items(), key=lambda x: x[1]["packets"], reverse=True)[:15]:
        convs_list.append({
            "connection": conv_key,
            "packets": c_data["packets"],
            "bytes": c_data["bytes"],
            "src": c_data["src"],
            "dst": c_data["dst"],
            "protocol": c_data["proto"]
        })

    # Generate Anomaly Detections
    for p, desc, s_ip, d_ip in suspicious_ports_found:
        anomalies.append(NetworkAnomaly(
            title=f"Suspicious Port Communication (Port {p})",
            description=f"Observed packet stream between {s_ip} and {d_ip} matching {desc}.",
            severity="high"
        ))

    if high_entropy_dns_count > 3:
        anomalies.append(NetworkAnomaly(
            title="Suspected DNS Tunneling / Exfiltration",
            description=f"Detected {high_entropy_dns_count} high-entropy DNS queries with long randomized subdomains.",
            severity="critical"
        ))

    if plaintext_creds_found:
        anomalies.append(NetworkAnomaly(
            title="Cleartext Authentication Credentials Transmitted",
            description=f"Observed unencrypted HTTP Basic authorization headers: {', '.join(plaintext_creds_found[:3])}",
            severity="high"
        ))

    # Port scanning heuristic
    for scanner_ip, ports_targeted in syn_scan_tracker.items():
        if len(ports_targeted) >= 15:
            anomalies.append(NetworkAnomaly(
                title="Potential TCP Port Scanning Activity",
                description=f"Source host {scanner_ip} sent TCP SYN packets across {len(ports_targeted)} distinct destination ports.",
                severity="high"
            ))

    # TCP Reset Storm / Abrupt Teardown check
    if total_packets > 100 and tcp_flag_counts["RST"] > (total_packets * 0.4):
        anomalies.append(NetworkAnomaly(
            title="Elevated TCP RST Ratio (Connection Teardown Storm)",
            description=f"RST flag packets account for {tcp_flag_counts['RST']} frames (>{round(tcp_flag_counts['RST']/total_packets*100, 1)}% of capture), indicating rejected sessions or active firewall resets.",
            severity="medium"
        ))

    accuracy_and_limitations = [
        "Offline PCAP Parsing: Evaluates captured packet frames passively without active network transmission or probing.",
        "Protocol Classification: Uses standard port mapping and deep packet inspection (DPI) heuristics for DNS, HTTP, and TLS ClientHello. Traffic on non-standard ports or encapsulated in VPN/tunnels may be classified as generic TCP/UDP.",
        "TLS SNI Extraction: Extracts unencrypted Server Name Indication (SNI) hostnames from TLS 1.2/1.3 ClientHello records. Encrypted ClientHello (ECH) or IP-direct HTTPS connections will not reveal SNI hostnames.",
        "Shannon Entropy Heuristics: Identifies potential DNS tunneling or data exfiltration based on character randomness and subdomain length. Legitimate CDN lookups or anti-spam queries may also exhibit elevated entropy.",
        "Defensive Forensic Principle: Network anomalies indicate atypical communication patterns or cleartext exposures. They do not constitute conclusive proof of compromise without correlating endpoint artifacts."
    ]

    return NetworkForensicsResponse(
        filename=filename,
        file_size_bytes=file_size_bytes,
        total_packets=total_packets,
        capture_duration_seconds=duration,
        protocol_distribution=proto_dist,
        top_talkers=top_talkers_list,
        dns_queries=dns_records,
        http_requests=http_requests,
        conversations=convs_list,
        anomalies=anomalies,
        analysis_timestamp=datetime.now(timezone.utc),
        accuracy_and_limitations=accuracy_and_limitations
    )
