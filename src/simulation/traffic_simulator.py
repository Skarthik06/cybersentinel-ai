"""
CyberSentinel AI — Traffic Simulator (DPI Pipeline Edition)
============================================================
Generates realistic malicious network traffic as raw PacketEvents and
streams them directly to the 'raw-packets' Kafka topic — the same topic
the DPI sensor writes to.

This means EVERY simulated scenario passes through the full pipeline:
  raw-packets → RLM Engine (EMA profiling + ChromaDB scoring) → threat-alerts → MCP/LLM

Each scenario generates a BURST of 30–150 packets so RLM can build a
behavioral profile and cross the min_observations gate (default: 20).

Scenarios (12 MITRE-mapped + 5 UNKNOWN novel threats):
  MITRE ATT&CK Mapped:
  • C2 Beacon              T1071.001 — beacon timing regularity, low jitter     [CRITICAL]
  • Data Exfiltration      T1048.003 — high entropy, large outbound transfers   [HIGH]
  • Lateral Movement SMB   T1021.002 — internal SMB/WinRM/DCOM access           [HIGH]
  • Port Scan              T1046     — SYN-only probe bursts, many dest ports    [MEDIUM]
  • DNS Tunneling          T1071.004 — high QPS, encoded long subdomains         [HIGH]
  • Brute Force SSH        T1110.001 — rapid auth failures, port 22              [HIGH]
  • RDP Lateral Movement   T1021.001 — internal RDP from non-admin host          [HIGH]
  • Exploit Public App     T1190     — SQLi/RCE/XXE payload patterns             [CRITICAL]
  • High Entropy Payload   T1027     — packed/encrypted payload, near-max entropy[HIGH]
  • Protocol Tunneling     T1572     — oversized ICMP/DNS with payload           [HIGH]
  • Credential Spray       T1110.003 — low-and-slow LDAP/HTTPS auth attempts     [HIGH]
  • Reverse Shell          T1059.004 — outbound shell, bidirectional small pkts  [CRITICAL]

  UNKNOWN Novel Threats (no MITRE mapping — AI must classify & recommend):
  • Polymorphic Beacon     — beacon intervals mutate to evade timing detection   [HIGH]
  • Covert Storage Channel — data encoded in IP header reserved/ToS fields       [HIGH]
  • Slow-Drip Exfil        — 1-2 bytes/packet over thousands of sessions         [HIGH]
  • Mesh C2 Relay          — multi-hop internal relay, no direct ext contact     [CRITICAL]
  • Synthetic Idle Traffic — mimics legitimate traffic but statistically wrong   [MEDIUM]
"""

import asyncio
import json
import logging
import os
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List

from aiokafka import AIOKafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIM] %(levelname)s: %(message)s",
)
logger = logging.getLogger("traffic-simulator")

KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
KAFKA_TOPIC       = "raw-packets"          # Full DPI pipeline — NOT threat-alerts
# Scenarios per minute. Default 2 = one scenario every 30s.
# Each scenario is a burst of packets, so RLM sees meaningful volume.
EVENTS_PER_MINUTE = int(os.getenv("SIMULATION_RATE", "2"))

# ── Kafka SASL/SCRAM-SHA-256 (optional — activated only when KAFKA_SASL_PASSWORD is set) ──
_KAFKA_SASL_USERNAME = os.getenv("KAFKA_SASL_USERNAME", "")
_KAFKA_SASL_PASSWORD = os.getenv("KAFKA_SASL_PASSWORD", "")
_KAFKA_SASL_KWARGS: dict = (
    {"security_protocol": "SASL_PLAINTEXT",
     "sasl_mechanism": "SCRAM-SHA-256",
     "sasl_plain_username": _KAFKA_SASL_USERNAME,
     "sasl_plain_password": _KAFKA_SASL_PASSWORD}
    if _KAFKA_SASL_PASSWORD else {}
)

# ── Realistic IP pools ────────────────────────────────────────────────────────
EXTERNAL_C2_IPS = [
    "185.220.101.47",   # Tor exit node
    "185.220.101.34",   # Tor exit node
    "91.108.4.168",     # Known botnet C2
    "45.142.212.100",   # Cobalt Strike C2 (AbuseIPDB flagged)
    "5.188.86.211",     # Russian bulletproof hosting
    "77.83.247.81",     # Malware distribution
    "194.165.16.77",    # APT-linked infrastructure
    "2.58.149.79",      # RaaS C2
]

EXTERNAL_EXFIL_IPS = [
    "93.184.220.29",    # Known data staging server
    "104.21.66.40",     # Cloudflare-proxied exfil endpoint
    "31.13.71.36",      # Eastern European exfil server
    "157.240.241.35",   # High-volume transfer destination
    "52.26.11.81",      # AWS-hosted attacker C2
]

EXTERNAL_EXPLOIT_IPS = [
    "89.248.165.200",   # Shodan-indexed exploit scanner
    "198.20.69.74",     # Mass exploit scanner
    "185.156.73.54",    # Known exploit framework host
]

INTERNAL_IPS = [
    "10.0.0.55",        # Finance workstation
    "10.0.1.23",        # HR laptop
    "10.0.1.45",        # Engineering server
    "10.0.2.88",        # Domain controller
    "10.0.3.12",        # File server
    "172.16.0.5",       # Legacy system
    "192.168.1.50",     # Guest network host
]

DNS_TUNNEL_SERVERS = [
    "8.8.8.8",          # Google DNS abused as cover
    "1.1.1.1",          # Cloudflare DNS abused as cover
    "208.67.222.222",   # OpenDNS abused for tunneling
]

SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 31337, 1337, 8888, 9999, 1234, 54321]


# ── PacketEvent builder ───────────────────────────────────────────────────────

def _ts(offset_seconds: float = 0.0) -> str:
    """UTC ISO timestamp with optional second offset for burst sequencing."""
    return (datetime.utcnow() + timedelta(seconds=offset_seconds)).isoformat()


def _session_id(src: str, dst: str, sport: int, dport: int, proto: str) -> str:
    eps = sorted([(src, sport), (dst, dport)])
    return f"{proto}:{eps[0][0]}:{eps[0][1]}-{eps[1][0]}:{eps[1][1]}"


def _packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    payload_size: int,
    entropy: float,
    flags: str = "",
    has_tls: bool = False,
    has_dns: bool = False,
    dns_query: str = "",
    http_method: str = "",
    is_suspicious: bool = True,
    suspicion_reasons: List[str] = None,
    session_id: str = "",
    ts_offset: float = 0.0,
) -> Dict:
    """Build a single PacketEvent matching the format RLM _process_packet_event() reads."""
    return {
        "src_ip":            src_ip,
        "dst_ip":            dst_ip,
        "src_port":          src_port,
        "dst_port":          dst_port,
        "protocol":          protocol,
        "payload_size":      payload_size,
        "entropy":           round(entropy, 4),
        "flags":             flags,
        "has_tls":           has_tls,
        "has_dns":           has_dns,
        "dns_query":         dns_query,
        "http_method":       http_method,
        "is_suspicious":     is_suspicious,
        "suspicion_reasons": suspicion_reasons or [],
        "session_id":        session_id or _session_id(src_ip, dst_ip, src_port, dst_port, protocol),
        "timestamp":         _ts(ts_offset),
        "source":            "simulator",
    }


# ── MITRE-mapped scenario burst generators ───────────────────────────────────

def scenario_c2_beacon() -> List[Dict]:
    """
    C2 beaconing: compromised internal host contacts known C2 at regular intervals.
    Low timing jitter (automated implant), HTTPS on non-standard port sometimes.
    MITRE T1071.001 — Application Layer Protocol: Web Protocols.
    Burst: 40–80 packets simulating repeated beacon check-ins over ~20 min.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([443, 80, 8080, 8443])
    has_tls = dport in (443, 8443)
    n     = random.randint(40, 80)
    sid   = _session_id(src, dst, sport, dport, "TCP")
    burst = []
    # Regular interval with low jitter — key C2 signature
    interval = random.uniform(28.0, 62.0)
    for i in range(n):
        size    = random.randint(200, 800)    # Small beacon check-in payload
        entropy = round(random.uniform(6.5, 7.6), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=has_tls,
            is_suspicious=True,
            suspicion_reasons=["C2_BEACON_TIMING", f"KNOWN_C2_IP:{dst}", "LOW_JITTER_INTERVAL"],
            session_id=sid,
            ts_offset=i * interval,
        ))
    return burst


def scenario_data_exfiltration() -> List[Dict]:
    """
    Large encrypted outbound data transfer to external staging server.
    High entropy payload + large size = encrypted data transfer.
    MITRE T1048.003 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol.
    Burst: 60–120 packets simulating a sustained file transfer session.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_EXFIL_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([443, 22, 8443, 21])
    has_tls = dport in (443, 8443)
    n     = random.randint(60, 120)
    sid   = _session_id(src, dst, sport, dport, "TCP")
    burst = []
    for i in range(n):
        # Large packets — file transfer chunks
        size    = random.randint(8000, 64000)
        entropy = round(random.uniform(7.1, 7.95), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=has_tls,
            is_suspicious=True,
            suspicion_reasons=["HIGH_ENTROPY_PAYLOAD", "LARGE_OUTBOUND_TRANSFER", f"EXFIL_DEST:{dst}"],
            session_id=sid,
            ts_offset=i * random.uniform(0.2, 1.0),
        ))
    return burst


def scenario_lateral_movement() -> List[Dict]:
    """
    Internal host accessing other hosts via SMB/WinRM/DCOM — lateral spread.
    Typical pattern: one compromised host probes/connects to multiple internal targets.
    MITRE T1021.002 — Remote Services: SMB/Windows Admin Shares.
    Burst: 30–60 packets across multiple internal targets.
    """
    src   = random.choice(INTERNAL_IPS)
    targets = random.sample([ip for ip in INTERNAL_IPS if ip != src], min(3, len(INTERNAL_IPS)-1))
    port  = random.choice([445, 135, 5985, 22])
    proto_name = {445: "SMB", 135: "DCOM/RPC", 5985: "WinRM", 22: "SSH"}[port]
    burst = []
    n_per_target = random.randint(10, 20)
    for ti, target in enumerate(targets):
        sport = random.randint(49152, 65535)
        sid   = _session_id(src, target, sport, port, "TCP")
        for i in range(n_per_target):
            size    = random.randint(100, 4096)
            entropy = round(random.uniform(4.5, 6.5), 4)
            burst.append(_packet(
                src_ip=src, dst_ip=target, src_port=sport, dst_port=port,
                protocol="TCP", payload_size=size, entropy=entropy,
                flags="PA",
                is_suspicious=True,
                suspicion_reasons=["LATERAL_MOVEMENT_PATTERN", f"ADMIN_PROTOCOL:{proto_name}", "INTERNAL_TO_INTERNAL"],
                session_id=sid,
                ts_offset=ti * n_per_target * 0.5 + i * 0.5,
            ))
    return burst


def scenario_port_scan() -> List[Dict]:
    """
    External attacker SYN-scanning internal host across many ports.
    SYN-only (no SYN-ACK response) = stealth scan signature.
    MITRE T1046 — Network Service Discovery.
    Burst: 80–150 SYN packets hitting different ports.
    """
    src     = random.choice(EXTERNAL_C2_IPS)
    dst     = random.choice(INTERNAL_IPS)
    n       = random.randint(80, 150)
    burst   = []
    # Sequential port scan — consistent sport, varying dport
    base_sport = random.randint(49152, 65535)
    ports_to_scan = random.sample(range(1, 65535), n)
    for i, dport in enumerate(ports_to_scan):
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=base_sport + i, dst_port=dport,
            protocol="TCP", payload_size=0, entropy=0.0,
            flags="S",   # SYN only = no handshake = stealth scan
            is_suspicious=True,
            suspicion_reasons=["PORT_SCAN", "SYN_ONLY_NO_HANDSHAKE", f"KNOWN_SCANNER:{src}"],
            session_id=_session_id(src, dst, base_sport + i, dport, "TCP"),
            ts_offset=i * 0.01,   # Fast scan — 10ms per port
        ))
    return burst


def scenario_dns_tunneling() -> List[Dict]:
    """
    Data exfiltration via encoded DNS queries at high rate.
    Long subdomain labels (>45 chars) with base64/hex encoding = tunnel signature.
    MITRE T1071.004 — Application Layer Protocol: DNS.
    Burst: 50–100 DNS query packets.
    """
    src  = random.choice(INTERNAL_IPS)
    dst  = random.choice(DNS_TUNNEL_SERVERS)
    n    = random.randint(50, 100)
    burst = []
    # Generate fake encoded subdomains
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(n):
        label_len  = random.randint(45, 63)
        subdomain  = "".join(random.choices(alphabet, k=label_len))
        dns_q      = f"{subdomain}.tunnel.evil.com"
        size       = random.randint(60, 200)
        entropy    = round(random.uniform(5.5, 7.2), 4)
        sport      = random.randint(49152, 65535)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=53,
            protocol="UDP", payload_size=size, entropy=entropy,
            flags="", has_dns=True, dns_query=dns_q,
            is_suspicious=True,
            suspicion_reasons=["DNS_TUNNELING", f"LONG_SUBDOMAIN:{len(subdomain)}_chars", "HIGH_DNS_RATE"],
            session_id=_session_id(src, dst, sport, 53, "UDP"),
            ts_offset=i * 0.1,
        ))
    return burst


def scenario_brute_force_ssh() -> List[Dict]:
    """
    Rapid failed authentication attempts against SSH service.
    Small TCP payloads at high rate — automated credential stuffing.
    MITRE T1110.001 — Brute Force: Password Guessing.
    Burst: 100–200 connection attempts.
    """
    src   = random.choice(EXTERNAL_C2_IPS)
    dst   = random.choice(INTERNAL_IPS)
    n     = random.randint(100, 200)
    burst = []
    for i in range(n):
        sport = random.randint(49152, 65535)
        # SSH auth attempts: small packets (username+password exchange)
        size  = random.randint(40, 300)
        entropy = round(random.uniform(3.5, 5.5), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=22,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA",
            is_suspicious=True,
            suspicion_reasons=["SSH_BRUTE_FORCE", "RAPID_AUTH_ATTEMPTS", f"KNOWN_ATTACKER:{src}"],
            session_id=_session_id(src, dst, sport, 22, "TCP"),
            ts_offset=i * 0.3,
        ))
    return burst


def scenario_rdp_lateral_movement() -> List[Dict]:
    """
    Internal host using RDP to access other internal hosts.
    Unusual for non-admin workstations — credential reuse or stolen token.
    MITRE T1021.001 — Remote Services: Remote Desktop Protocol.
    Burst: 40–80 RDP session packets.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice([ip for ip in INTERNAL_IPS if ip != src])
    sport = random.randint(49152, 65535)
    n     = random.randint(40, 80)
    sid   = _session_id(src, dst, sport, 3389, "TCP")
    burst = []
    for i in range(n):
        # RDP: variable packet size — screen updates can be large
        size    = random.randint(1000, 16000)
        entropy = round(random.uniform(5.0, 7.0), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=3389,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=True,
            is_suspicious=True,
            suspicion_reasons=["UNUSUAL_INTERNAL_RDP", "LATERAL_MOVEMENT_PATTERN", "NON_ADMIN_WORKSTATION"],
            session_id=sid,
            ts_offset=i * 0.5,
        ))
    return burst


def scenario_exploit_public_app() -> List[Dict]:
    """
    Web application exploitation: SQLi/RCE/XXE/path traversal payloads.
    Small HTTP requests containing malformed/malicious input patterns.
    MITRE T1190 — Exploit Public-Facing Application.
    Burst: 30–60 exploit attempt packets.
    """
    src   = random.choice(EXTERNAL_EXPLOIT_IPS)
    dst   = random.choice(INTERNAL_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443, 8080, 8443, 8888])
    payload_types = ["SQL_INJECTION", "RCE_ATTEMPT", "PATH_TRAVERSAL", "XXE_INJECTION", "SSTI_INJECTION"]
    n     = random.randint(30, 60)
    burst = []
    for i in range(n):
        pt   = random.choice(payload_types)
        size = random.randint(100, 2000)     # HTTP request with exploit payload
        entropy = round(random.uniform(4.0, 6.5), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport + i, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=(dport in (443, 8443)),
            http_method=random.choice(["GET", "POST", "PUT"]),
            is_suspicious=True,
            suspicion_reasons=[f"EXPLOIT_PAYLOAD:{pt}", "WEB_EXPLOIT_PATTERN", f"KNOWN_SCANNER:{src}"],
            session_id=_session_id(src, dst, sport + i, dport, "TCP"),
            ts_offset=i * 0.2,
        ))
    return burst


def scenario_high_entropy_payload() -> List[Dict]:
    """
    Encrypted or packed payload transfer — shellcode, custom encryption, packed malware.
    Near-maximum Shannon entropy (>7.6) across all packets = not compressible text.
    MITRE T1027 — Obfuscated Files or Information.
    Burst: 40–80 high-entropy data packets.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([443, 8443, 4443, 9443])
    n     = random.randint(40, 80)
    sid   = _session_id(src, dst, sport, dport, "TCP")
    burst = []
    for i in range(n):
        size    = random.randint(4000, 32000)
        entropy = round(random.uniform(7.6, 7.99), 4)   # Near-max entropy threshold
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=True,
            is_suspicious=True,
            suspicion_reasons=[f"ENTROPY:{entropy}_exceeds_7.5_threshold", "PACKED_OR_ENCRYPTED_PAYLOAD", "CONSISTENT_HIGH_ENTROPY"],
            session_id=sid,
            ts_offset=i * 0.3,
        ))
    return burst


def scenario_protocol_tunneling() -> List[Dict]:
    """
    Data hidden inside ICMP or DNS protocol — oversized payloads covert channel.
    Normal ICMP ≤ 64B; DNS ≤ 512B. Oversized = tunnel.
    MITRE T1572 — Protocol Tunneling.
    Burst: 50–100 oversized protocol packets.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    proto = random.choice(["ICMP", "UDP"])   # UDP for DNS tunnel
    dport = 0 if proto == "ICMP" else 53
    n     = random.randint(50, 100)
    burst = []
    for i in range(n):
        sport   = random.randint(49152, 65535)
        # Intentionally oversized — key anomaly indicator
        size    = random.randint(1200, 4000)
        entropy = round(random.uniform(6.5, 7.5), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol=proto, payload_size=size, entropy=entropy,
            flags="",
            is_suspicious=True,
            suspicion_reasons=[f"OVERSIZED_{proto}_PAYLOAD:{size}B", f"{proto}_TUNNEL_PATTERN", "COVERT_CHANNEL_INDICATOR"],
            session_id=_session_id(src, dst, sport, dport, proto),
            ts_offset=i * 0.2,
        ))
    return burst


def scenario_credential_spray() -> List[Dict]:
    """
    Low-and-slow password spray: one password tried across many accounts.
    Deliberately slow to avoid lockout policies — 1 attempt per account per minute.
    MITRE T1110.003 — Brute Force: Password Spraying.
    Burst: 50–100 auth requests spread across LDAP/HTTPS targets.
    """
    src   = random.choice(EXTERNAL_C2_IPS)
    dst   = random.choice(INTERNAL_IPS)
    dport = random.choice([389, 636, 443, 80])
    service = {389: "LDAP", 636: "LDAPS", 443: "HTTPS", 80: "HTTP"}[dport]
    n     = random.randint(50, 100)
    burst = []
    for i in range(n):
        sport = random.randint(49152, 65535)
        # Auth packets: small, consistent size
        size  = random.randint(100, 600)
        entropy = round(random.uniform(3.0, 5.0), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA",
            is_suspicious=True,
            suspicion_reasons=[f"CREDENTIAL_SPRAY_{service}", "LOW_AND_SLOW_AUTH", "MANY_ACCOUNTS_TARGETED"],
            session_id=_session_id(src, dst, sport, dport, "TCP"),
            ts_offset=i * 1.5,   # 1.5s between attempts — evading lockout
        ))
    return burst


def scenario_reverse_shell() -> List[Dict]:
    """
    Reverse shell: compromised host opens outbound TCP to attacker on suspicious port.
    Bidirectional small-packet pattern — stdin/stdout of interactive shell session.
    MITRE T1059.004 — Command and Scripting Interpreter: Unix Shell.
    Burst: 60–120 bidirectional shell interaction packets.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice(SUSPICIOUS_PORTS)
    n     = random.randint(60, 120)
    sid   = _session_id(src, dst, sport, dport, "TCP")
    burst = []
    for i in range(n):
        # Shell: tiny packets — single command/response lines
        size    = random.randint(20, 200)
        entropy = round(random.uniform(3.5, 5.5), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA",
            is_suspicious=True,
            suspicion_reasons=[f"SUSPICIOUS_PORT:{dport}", "INTERACTIVE_SHELL_PATTERN", "BIDIRECTIONAL_SMALL_PACKETS"],
            session_id=sid,
            ts_offset=i * random.uniform(0.5, 3.0),
        ))
    return burst


# ── UNKNOWN Novel Threat Scenarios ────────────────────────────────────────────
# These have NO mitre_technique — the AI must classify the threat and
# recommend remediation. The behavioral patterns are real but don't map
# cleanly to any single ATT&CK technique.

def scenario_polymorphic_beacon() -> List[Dict]:
    """
    UNKNOWN THREAT: Polymorphic beaconing — the implant mutates its beacon
    interval every few check-ins to evade timing-based detection.
    Unlike T1071.001 (regular intervals), this beacon has structured variability:
    intervals shift by a constant delta each cycle.
    No MITRE technique maps precisely to this evasion technique.
    Burst: 50–90 packets with arithmetic-progression timing.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([443, 80, 8080])
    n     = random.randint(50, 90)
    sid   = _session_id(src, dst, sport, dport, "TCP")
    burst = []
    base_interval = random.uniform(15.0, 30.0)
    delta         = random.uniform(1.5, 4.0)    # Interval shifts by delta each cycle
    t = 0.0
    for i in range(n):
        size    = random.randint(180, 900)
        entropy = round(random.uniform(5.5, 7.2), 4)
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=(dport == 443),
            is_suspicious=True,
            suspicion_reasons=[
                "POLYMORPHIC_BEACON_INTERVAL",
                "ARITHMETIC_INTERVAL_PROGRESSION",
                "TIMING_EVASION_PATTERN",
                "UNKNOWN_THREAT_TYPE",
            ],
            session_id=sid,
            ts_offset=t,
        ))
        t += base_interval + (i % 5) * delta
    return burst


def scenario_covert_storage_channel() -> List[Dict]:
    """
    UNKNOWN THREAT: Covert storage channel via IP header field manipulation.
    Attacker encodes data in IP ToS/DSCP bits or reserved flags — payload is
    benign-looking but header fields carry hidden information. Packet payloads
    look normal; only statistical analysis of header bits reveals the channel.
    Burst: 60–100 packets with unusual header entropy patterns.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443, 53])
    n     = random.randint(60, 100)
    burst = []
    # Payload entropy looks normal — the anomaly is in the header (simulated via
    # unusually consistent payload sizes that encode data via LSB steganography)
    magic_sizes = [x for x in range(100, 200, 2)]   # Even sizes only = covert channel marker
    for i in range(n):
        size    = random.choice(magic_sizes)
        entropy = round(random.uniform(4.0, 5.5), 4)   # Looks legitimate
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport + (i % 8), dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA", has_tls=(dport == 443),
            is_suspicious=True,
            suspicion_reasons=[
                "COVERT_STORAGE_CHANNEL_PATTERN",
                "HEADER_FIELD_ENCODING_SUSPECTED",
                "STATISTICAL_PAYLOAD_ALIGNMENT",
                "UNKNOWN_THREAT_TYPE",
            ],
            session_id=_session_id(src, dst, sport + (i % 8), dport, "TCP"),
            ts_offset=i * 0.8,
        ))
    return burst


def scenario_slow_drip_exfiltration() -> List[Dict]:
    """
    UNKNOWN THREAT: Slow-drip exfiltration — 1-4 bytes per connection spread
    across thousands of separate sessions to thousands of destinations.
    Each individual session looks completely benign; only aggregate analysis
    reveals the exfiltration pattern. Evades DLP and volume-based detection.
    No single MITRE technique describes multi-session micro-exfiltration.
    Burst: 80–150 tiny packets to multiple destinations.
    """
    src   = random.choice(INTERNAL_IPS)
    n     = random.randint(80, 150)
    burst = []
    # Many different destinations — each gets 1-4 bytes
    all_dsts = EXTERNAL_C2_IPS + EXTERNAL_EXFIL_IPS
    for i in range(n):
        dst     = random.choice(all_dsts)
        sport   = random.randint(49152, 65535)
        dport   = random.choice([80, 443, 8080, 53])
        size    = random.randint(1, 4)        # 1-4 bytes per packet — the "drip"
        entropy = round(random.uniform(0.5, 2.0), 4)    # Very low entropy = literal bytes
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="TCP", payload_size=size, entropy=entropy,
            flags="PA",
            is_suspicious=True,
            suspicion_reasons=[
                "MICRO_PACKET_EXFILTRATION",
                "SLOW_DRIP_PATTERN",
                "MANY_DESTINATION_SCATTER",
                "UNKNOWN_THREAT_TYPE",
            ],
            session_id=_session_id(src, dst, sport, dport, "TCP"),
            ts_offset=i * random.uniform(1.0, 5.0),
        ))
    return burst


def scenario_mesh_c2_relay() -> List[Dict]:
    """
    UNKNOWN THREAT: Mesh C2 relay — no single compromised host talks directly
    to external C2. Instead, internal hosts form a relay chain:
      A → B → C → D → external (only D touches internet)
    Makes attribution and detection extremely difficult. Each hop looks like
    normal internal traffic. No MITRE technique fully describes mesh relay C2.
    Burst: 60–100 internal relay packets across a chain of internal hosts.
    """
    # Build a relay chain of internal IPs
    chain_length = random.randint(3, min(5, len(INTERNAL_IPS)))
    chain = random.sample(INTERNAL_IPS, chain_length)
    n_per_hop = random.randint(15, 25)
    burst = []
    for hop_idx in range(len(chain) - 1):
        src_hop = chain[hop_idx]
        dst_hop = chain[hop_idx + 1]
        sport   = random.randint(49152, 65535)
        dport   = random.choice([8080, 8443, 9000, 4433])
        sid     = _session_id(src_hop, dst_hop, sport, dport, "TCP")
        for i in range(n_per_hop):
            size    = random.randint(200, 2000)
            entropy = round(random.uniform(5.0, 7.0), 4)
            burst.append(_packet(
                src_ip=src_hop, dst_ip=dst_hop, src_port=sport, dst_port=dport,
                protocol="TCP", payload_size=size, entropy=entropy,
                flags="PA",
                is_suspicious=True,
                suspicion_reasons=[
                    "MESH_C2_RELAY_PATTERN",
                    f"RELAY_HOP_{hop_idx + 1}_OF_{len(chain) - 1}",
                    "INTERNAL_RELAY_CHAIN",
                    "UNKNOWN_THREAT_TYPE",
                ],
                session_id=sid,
                ts_offset=(hop_idx * n_per_hop + i) * 0.4,
            ))
    return burst


def scenario_synthetic_idle_traffic() -> List[Dict]:
    """
    UNKNOWN THREAT: Synthetic idle traffic — malware that mimics legitimate
    background traffic patterns (NTP, DNS heartbeats, OCSP checks) but with
    statistically detectable anomalies:
      - Packet sizes are TOO consistent (real traffic has variance)
      - Inter-arrival times are perfectly uniform (no OS/network jitter)
      - Destination ports rotate through a fixed sequence
    Evades basic signature detection; only ML anomaly detection catches it.
    Burst: 40–80 suspiciously-uniform "legitimate-looking" packets.
    """
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    # Mimics NTP/DNS/OCSP — legitimate-looking ports
    ports = [123, 53, 80, 443]
    n     = random.randint(40, 80)
    burst = []
    fixed_size = random.choice([64, 128, 256, 512])   # Unnaturally consistent size
    fixed_interval = random.uniform(4.9, 5.1)          # Near-perfect 5s interval (no jitter)
    for i in range(n):
        dport = ports[i % len(ports)]       # Rotating through fixed sequence
        burst.append(_packet(
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol="UDP" if dport in (53, 123) else "TCP",
            payload_size=fixed_size,        # Perfectly consistent = unnatural
            entropy=round(random.uniform(3.8, 4.2), 4),
            flags="",
            has_dns=(dport == 53),
            is_suspicious=True,
            suspicion_reasons=[
                "SYNTHETIC_TRAFFIC_PATTERN",
                "UNNATURAL_SIZE_CONSISTENCY",
                "ZERO_JITTER_INTERVAL",
                "PORT_ROTATION_SEQUENCE",
                "UNKNOWN_THREAT_TYPE",
            ],
            session_id=_session_id(src, dst, sport, dport, "UDP" if dport in (53, 123) else "TCP"),
            ts_offset=i * fixed_interval,
        ))
    return burst


# ── Scenario registry ─────────────────────────────────────────────────────────
# (fn, weight, display_name)
# Higher weight = more frequent. Unknown threats are less frequent but present.

SCENARIOS = [
    # MITRE-mapped
    (scenario_c2_beacon,              5, "C2 Beacon [T1071.001 CRITICAL]"),
    (scenario_data_exfiltration,      4, "Data Exfiltration [T1048.003 HIGH]"),
    (scenario_lateral_movement,       3, "Lateral Movement SMB [T1021.002 HIGH]"),
    (scenario_port_scan,              3, "Port Scan [T1046 MEDIUM]"),
    (scenario_dns_tunneling,          3, "DNS Tunneling [T1071.004 HIGH]"),
    (scenario_brute_force_ssh,        3, "Brute Force SSH [T1110.001 HIGH]"),
    (scenario_rdp_lateral_movement,   3, "RDP Lateral Movement [T1021.001 HIGH]"),
    (scenario_exploit_public_app,     4, "Public App Exploit [T1190 CRITICAL]"),
    (scenario_high_entropy_payload,   3, "High Entropy Payload [T1027 HIGH]"),
    (scenario_protocol_tunneling,     2, "Protocol Tunneling [T1572 HIGH]"),
    (scenario_credential_spray,       3, "Credential Spray [T1110.003 HIGH]"),
    (scenario_reverse_shell,          4, "Reverse Shell [T1059.004 CRITICAL]"),
    # Unknown — AI classifies
    (scenario_polymorphic_beacon,     2, "Polymorphic Beacon [UNKNOWN HIGH]"),
    (scenario_covert_storage_channel, 1, "Covert Storage Channel [UNKNOWN HIGH]"),
    (scenario_slow_drip_exfiltration, 2, "Slow-Drip Exfiltration [UNKNOWN HIGH]"),
    (scenario_mesh_c2_relay,          2, "Mesh C2 Relay [UNKNOWN CRITICAL]"),
    (scenario_synthetic_idle_traffic, 1, "Synthetic Idle Traffic [UNKNOWN MEDIUM]"),
]

_fns, _weights, _names = zip(*SCENARIOS)


# ── Simulator ────────────────────────────────────────────────────────────────

class TrafficSimulator:

    def __init__(self):
        self.producer: AIOKafkaProducer = None
        self.scenarios_run   = 0
        self.packets_sent    = 0

    async def start(self):
        logger.info("CyberSentinel Traffic Simulator starting (DPI pipeline mode)...")
        logger.info(f"  Topic     : {KAFKA_TOPIC}  (full DPI → RLM → LLM pipeline)")
        logger.info(f"  Scenarios : {len(SCENARIOS)} ({len(SCENARIOS)-5} MITRE + 5 UNKNOWN novel threats)")
        logger.info(f"  Rate      : {EVENTS_PER_MINUTE} scenarios/min → 1 scenario every {60/EVENTS_PER_MINUTE:.0f}s")
        logger.info(f"  Packet burst: 30-150 packets per scenario (clears RLM min_observations gate)")

        self.producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            compression_type="gzip",
            **_KAFKA_SASL_KWARGS,
        )
        await self.producer.start()
        logger.info(f"Kafka connected — streaming to '{KAFKA_TOPIC}'")
        logger.info("Simulating threat scenarios...")

        interval_sec = 60.0 / EVENTS_PER_MINUTE

        while True:
            try:
                idx  = random.choices(range(len(_fns)), weights=_weights, k=1)[0]
                fn   = _fns[idx]
                name = _names[idx]

                packets = fn()
                self.scenarios_run += 1

                # Send all packets in the burst
                for pkt in packets:
                    await self.producer.send(KAFKA_TOPIC, value=pkt)
                    self.packets_sent += 1

                src = packets[0].get("src_ip", "?")
                dst = packets[0].get("dst_ip", "?")
                logger.info(
                    f"[{self.scenarios_run:>4}] {name:<45} "
                    f"{src:>15} → {dst:<15} "
                    f"({len(packets)} packets)"
                )

                if self.scenarios_run % 10 == 0:
                    logger.info(
                        f"--- Summary: {self.scenarios_run} scenarios | "
                        f"{self.packets_sent} packets → {KAFKA_TOPIC} ---"
                    )

                # Wait for next scenario slot
                await asyncio.sleep(interval_sec)

            except Exception as e:
                logger.error(f"Simulator error: {e}")
                await asyncio.sleep(5)

    async def stop(self):
        if self.producer:
            await self.producer.stop()


async def main():
    sim = TrafficSimulator()
    try:
        await sim.start()
    except KeyboardInterrupt:
        logger.info("Simulator shutting down...")
    finally:
        await sim.stop()


if __name__ == "__main__":
    asyncio.run(main())
