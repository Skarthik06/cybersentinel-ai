"""
CyberSentinel AI — Traffic Simulator
=====================================
Generates realistic malicious network traffic events and streams them to Kafka.
Simulates what the DPI sensor would detect from real-world threat traffic.

No Npcap / packet capture required — runs fully inside Docker.

Scenarios generated (12 threat types across full MITRE kill-chain):
  • C2 Beacon              — compromised host beaconing to known C2 infrastructure   [CRITICAL]
  • Data Exfiltration      — large encrypted transfers to external IPs                [HIGH]
  • Lateral Movement (SMB) — internal host-to-host suspicious traffic via SMB/RDP    [HIGH]
  • Port Scan              — attacker reconnaissance against internal targets          [MEDIUM]
  • DNS Tunneling          — data exfiltrated via high-volume encoded DNS queries     [HIGH]
  • Brute Force SSH        — rapid authentication attempts against SSH service        [HIGH]
  • RDP Lateral Movement   — internal RDP-based lateral movement                      [HIGH]
  • Exploit Public App     — exploitation attempt against public-facing web app       [CRITICAL]
  • High Entropy Payload   — obfuscated/encrypted payload indicating packed malware   [HIGH]
  • Protocol Tunneling     — data hidden inside ICMP/DNS protocol traffic             [HIGH]
  • Credential Spray       — low-and-slow password spray across many accounts        [HIGH]
  • Reverse Shell          — compromised host initiating outbound shell connection    [CRITICAL]

These represent a realistic kill-chain:
  Recon → Initial Access → Execution → Lateral Movement → C2 Beaconing → Exfiltration
"""

import asyncio
import json
import logging
import os
import random
import uuid
from datetime import datetime
from typing import Dict

from aiokafka import AIOKafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIM] %(levelname)s: %(message)s",
)
logger = logging.getLogger("traffic-simulator")

KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
KAFKA_TOPIC       = "threat-alerts"
# How many threat events to emit per minute (spread evenly)
# Default 2 = 1 event every 30 seconds — generates meaningful data without token burn
EVENTS_PER_MINUTE = int(os.getenv("SIMULATION_RATE", "2"))

# ── Realistic IP pools ────────────────────────────────────────────────────────
# External: IPs from known threat intelligence feeds (Tor exit nodes, botnet C2s)
EXTERNAL_C2_IPS = [
    "185.220.101.47",  # Tor exit node (real TI feed entry)
    "185.220.101.34",  # Tor exit node
    "91.108.4.168",    # Known botnet C2
    "45.142.212.100",  # Cobalt Strike C2 (flagged AbuseIPDB)
    "5.188.86.211",    # Russian bulletproof hosting
    "77.83.247.81",    # Known malware distribution
    "194.165.16.77",   # APT-linked infrastructure
    "2.58.149.79",     # RaaS (Ransomware-as-a-Service) C2
]

EXTERNAL_EXFIL_IPS = [
    "93.184.220.29",   # Known data staging server
    "104.21.66.40",    # Cloudflare-proxied exfil endpoint
    "31.13.71.36",     # Eastern European exfil server
    "157.240.241.35",  # Suspicious large-transfer destination
    "52.26.11.81",     # AWS-hosted C2 (attacker-owned)
]

# Internal: simulated compromised hosts across subnets
INTERNAL_IPS = [
    "10.0.0.55",    # Finance workstation
    "10.0.1.23",    # HR laptop
    "10.0.1.45",    # Engineering server
    "10.0.2.88",    # Domain controller
    "10.0.3.12",    # File server
    "172.16.0.5",   # Legacy system
    "192.168.1.50", # Guest network host
]

SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 31337, 1337, 8888, 9999, 1234, 54321]

EXTERNAL_EXPLOIT_IPS = [
    "89.248.165.200",   # Shodan-indexed exploit scanner
    "198.20.69.74",     # Mass exploit scanner
    "185.156.73.54",    # Known exploit framework host
]

DNS_TUNNEL_DOMAINS = [
    "8.8.8.8",    # Attacker using Google DNS as cover
    "1.1.1.1",    # Attacker using Cloudflare as cover
    "208.67.222.222",  # OpenDNS abused for tunneling
]

# ── Scenario generators ───────────────────────────────────────────────────────

def _session_id(src: str, dst: str, sport: int, dport: int, proto: str) -> str:
    eps = sorted([(src, sport), (dst, dport)])
    return f"{proto}:{eps[0][0]}:{eps[0][1]}-{eps[1][0]}:{eps[1][1]}"


def scenario_c2_beacon() -> Dict:
    """
    Realistic C2 beaconing: compromised internal host communicates with
    known C2 infrastructure at regular intervals (automated jitter).
    Matches MITRE T1071.001 (Application Layer Protocol: Web Protocols).
    """
    src      = random.choice(INTERNAL_IPS)
    dst      = random.choice(EXTERNAL_C2_IPS)
    interval = round(random.uniform(28.0, 62.0), 2)   # 28–62s beacon interval
    std_dev  = round(random.uniform(0.05, 1.5), 4)    # Low jitter = automated
    sport    = random.randint(49152, 65535)
    dport    = random.choice([443, 80, 8080, 8443])
    return {
        "type":             "C2_BEACON_DETECTED",
        "severity":         "CRITICAL",
        "timestamp":        datetime.utcnow().isoformat(),
        "src_ip":           src,
        "dst_ip":           dst,
        "src_port":         sport,
        "dst_port":         dport,
        "protocol":         "TCP",
        "avg_interval_sec": interval,
        "std_dev":          std_dev,
        "mitre_technique":  "T1071.001",
        "anomaly_score":    round(random.uniform(0.82, 0.98), 4),
        "description": (
            f"C2 beacon: {src} contacts {dst} every {interval:.1f}s "
            f"(σ={std_dev:.4f}) — highly regular timing indicates automated implant. "
            f"Destination matches known Tor exit / botnet C2 infrastructure."
        ),
        "session_id":       _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_data_exfiltration() -> Dict:
    """
    Large encrypted outbound transfer to external IP.
    Matches MITRE T1048.003 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol).
    """
    src       = random.choice(INTERNAL_IPS)
    dst       = random.choice(EXTERNAL_EXFIL_IPS)
    mb        = random.randint(75, 450)
    bytes_out = mb * 1_000_000
    sport     = random.randint(49152, 65535)
    dport     = random.choice([443, 22, 8443, 21])
    entropy   = round(random.uniform(7.1, 7.95), 4)
    return {
        "type":            "DATA_EXFILTRATION_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons": [
            f"HIGH_ENTROPY_PAYLOAD:{entropy}",
            f"LARGE_OUTBOUND_TRANSFER:{bytes_out}",
        ],
        "payload_size":    bytes_out,
        "entropy":         entropy,
        "mitre_technique": "T1048.003",
        "anomaly_score":   round(random.uniform(0.71, 0.91), 4),
        "description": (
            f"Data exfiltration suspected: {src} transferred {mb}MB "
            f"to external {dst} over encrypted channel "
            f"(entropy={entropy}, port={dport}). "
            f"Volume and destination are consistent with staged data theft."
        ),
        "session_id":      _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_lateral_movement() -> Dict:
    """
    Internal host-to-host movement via SMB/RDP/WMI.
    Indicates compromised host attempting to spread or access other systems.
    Matches MITRE T1021.002 (Remote Services: SMB/Windows Admin Shares).
    """
    src  = random.choice(INTERNAL_IPS)
    dst  = random.choice([ip for ip in INTERNAL_IPS if ip != src])
    port = random.choice([445, 135, 3389, 5985, 22])
    proto_name = {445:"SMB", 135:"DCOM/RPC", 3389:"RDP", 5985:"WinRM", 22:"SSH"}[port]
    sport = random.randint(49152, 65535)
    return {
        "type":            "LATERAL_MOVEMENT_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        port,
        "protocol":        "TCP",
        "reasons": [
            f"SUSPICIOUS_PORT:{port}",
            "LATERAL_MOVEMENT_PATTERN",
        ],
        "mitre_technique": "T1021.002",
        "anomaly_score":   round(random.uniform(0.65, 0.88), 4),
        "description": (
            f"Lateral movement: {src} connecting to {dst} via {proto_name} (port {port}). "
            f"Internal-to-internal admin protocol use is consistent with "
            f"Pass-the-Hash, credential reuse, or worm propagation (MITRE T1021.002)."
        ),
        "session_id":      _session_id(src, dst, sport, port, "TCP"),
    }


def scenario_port_scan() -> Dict:
    """
    External attacker scanning internal hosts for open ports.
    Early-stage reconnaissance — indicates active targeting.
    Matches MITRE T1046 (Network Service Discovery).
    """
    src        = random.choice(EXTERNAL_C2_IPS)
    dst        = random.choice(INTERNAL_IPS)
    port_count = random.randint(100, 800)
    sport      = random.randint(49152, 65535)
    dport      = random.choice([22, 80, 443, 3389, 8080, 8443])
    return {
        "type":            "PORT_SCAN_DETECTED",
        "severity":        "MEDIUM",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons": [
            f"PORT_SCAN:{port_count}_ports",
        ],
        "flags":           "S",
        "port_count":      port_count,
        "mitre_technique": "T1046",
        "anomaly_score":   round(random.uniform(0.48, 0.70), 4),
        "description": (
            f"Port scan detected: {src} probed {port_count} ports on {dst}. "
            f"SYN-only packets (no complete handshake) indicate stealth scan. "
            f"Source IP matches known threat infrastructure. (MITRE T1046)"
        ),
        "session_id":      _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_dns_tunneling() -> Dict:
    """DNS tunneling: data exfiltrated via high-volume DNS queries with encoded subdomains.
    Matches MITRE T1071.004 (Application Layer Protocol: DNS)."""
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(DNS_TUNNEL_DOMAINS)
    qps   = random.randint(80, 300)
    sport = random.randint(49152, 65535)
    subdomain_len = random.randint(45, 63)
    return {
        "type":            "DNS_TUNNELING_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        53,
        "protocol":        "UDP",
        "reasons":         [f"HIGH_DNS_QUERY_RATE:{qps}_qps", f"LONG_SUBDOMAIN:{subdomain_len}_chars"],
        "queries_per_sec": qps,
        "subdomain_length": subdomain_len,
        "mitre_technique": "T1071.004",
        "anomaly_score":   round(random.uniform(0.72, 0.89), 4),
        "description": (
            f"DNS tunneling suspected: {src} sending {qps} DNS queries/sec to {dst} "
            f"with encoded subdomains ({subdomain_len} chars avg). "
            f"High-rate DNS with long subdomains indicates data exfiltration via DNS protocol. (MITRE T1071.004)"
        ),
        "session_id": _session_id(src, dst, sport, 53, "UDP"),
    }


def scenario_brute_force_ssh() -> Dict:
    """SSH brute force: rapid authentication attempts against SSH service.
    Matches MITRE T1110.001 (Brute Force: Password Guessing)."""
    src     = random.choice(EXTERNAL_C2_IPS)
    dst     = random.choice(INTERNAL_IPS)
    attempts = random.randint(150, 800)
    sport   = random.randint(49152, 65535)
    return {
        "type":            "BRUTE_FORCE_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        22,
        "protocol":        "TCP",
        "reasons":         [f"RAPID_AUTH_FAILURES:{attempts}", "SSH_BRUTE_FORCE_PATTERN"],
        "attempt_count":   attempts,
        "mitre_technique": "T1110.001",
        "anomaly_score":   round(random.uniform(0.68, 0.85), 4),
        "description": (
            f"SSH brute force: {src} made {attempts} failed authentication attempts "
            f"against {dst}:22 in under 60 seconds. "
            f"Automated credential stuffing pattern detected. (MITRE T1110.001)"
        ),
        "session_id": _session_id(src, dst, sport, 22, "TCP"),
    }


def scenario_rdp_lateral_movement() -> Dict:
    """RDP-based lateral movement: internal host using Remote Desktop to access other hosts.
    Matches MITRE T1021.001 (Remote Services: Remote Desktop Protocol)."""
    src  = random.choice(INTERNAL_IPS)
    dst  = random.choice([ip for ip in INTERNAL_IPS if ip != src])
    sport = random.randint(49152, 65535)
    return {
        "type":            "LATERAL_MOVEMENT_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        3389,
        "protocol":        "TCP",
        "reasons":         ["RDP_LATERAL_MOVEMENT", "UNUSUAL_INTERNAL_RDP"],
        "mitre_technique": "T1021.001",
        "anomaly_score":   round(random.uniform(0.66, 0.84), 4),
        "description": (
            f"RDP lateral movement: {src} opened Remote Desktop session to {dst}:3389. "
            f"Internal-to-internal RDP from non-admin workstation indicates credential reuse "
            f"or stolen session token. (MITRE T1021.001)"
        ),
        "session_id": _session_id(src, dst, sport, 3389, "TCP"),
    }


def scenario_exploit_public_app() -> Dict:
    """Exploitation attempt against public-facing web application.
    Matches MITRE T1190 (Exploit Public-Facing Application)."""
    src    = random.choice(EXTERNAL_EXPLOIT_IPS)
    dst    = random.choice(INTERNAL_IPS)
    sport  = random.randint(49152, 65535)
    dport  = random.choice([80, 443, 8080, 8443, 8888])
    payload_type = random.choice(["SQL_INJECTION", "RCE_ATTEMPT", "PATH_TRAVERSAL", "XXE_INJECTION"])
    return {
        "type":            "EXPLOIT_ATTEMPT_DETECTED",
        "severity":        "CRITICAL",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons":         [f"MALICIOUS_PAYLOAD:{payload_type}", "WEB_EXPLOIT_PATTERN"],
        "payload_type":    payload_type,
        "mitre_technique": "T1190",
        "anomaly_score":   round(random.uniform(0.80, 0.97), 4),
        "description": (
            f"Web application exploit attempt: {src} sent {payload_type} payload "
            f"to {dst}:{dport}. Malformed request matches known exploit framework signatures. "
            f"Immediate patching and WAF rule review required. (MITRE T1190)"
        ),
        "session_id": _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_high_entropy_payload() -> Dict:
    """Obfuscated/encrypted payload: high entropy data transfer indicating packed malware or encrypted C2.
    Matches MITRE T1027 (Obfuscated Files or Information)."""
    src     = random.choice(INTERNAL_IPS)
    dst     = random.choice(EXTERNAL_C2_IPS)
    entropy = round(random.uniform(7.6, 7.99), 4)
    size    = random.randint(50, 200) * 1000
    sport   = random.randint(49152, 65535)
    dport   = random.choice([443, 8443, 4443, 9443])
    return {
        "type":            "HIGH_ENTROPY_PAYLOAD_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons":         [f"ENTROPY:{entropy}_exceeds_threshold", "PACKED_OR_ENCRYPTED_PAYLOAD"],
        "entropy":         entropy,
        "payload_size":    size,
        "mitre_technique": "T1027",
        "anomaly_score":   round(random.uniform(0.69, 0.88), 4),
        "description": (
            f"High-entropy payload detected: {src} → {dst}:{dport} "
            f"(entropy={entropy}, size={size//1000}KB). "
            f"Near-maximum entropy indicates packed malware, shellcode, or custom encryption. "
            f"Consistent with stage-2 payload delivery or encrypted C2 channel. (MITRE T1027)"
        ),
        "session_id": _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_protocol_tunneling() -> Dict:
    """Protocol tunneling: data hidden inside legitimate protocol traffic (ICMP/DNS).
    Matches MITRE T1572 (Protocol Tunneling)."""
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    proto = random.choice(["ICMP", "DNS"])
    size  = random.randint(1200, 4000)
    sport = random.randint(49152, 65535)
    dport = 0 if proto == "ICMP" else 53
    return {
        "type":            "PROTOCOL_TUNNELING_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        proto,
        "reasons":         [f"OVERSIZED_{proto}_PAYLOAD:{size}B", f"{proto}_TUNNEL_PATTERN"],
        "tunnel_protocol": proto,
        "payload_size":    size,
        "mitre_technique": "T1572",
        "anomaly_score":   round(random.uniform(0.71, 0.90), 4),
        "description": (
            f"Protocol tunneling via {proto}: {src} → {dst} "
            f"with {size}B payload (normal {proto} ≤ 64B). "
            f"Oversized {proto} packets indicate covert channel — C2 traffic hidden inside "
            f"legitimate protocol to bypass network controls. (MITRE T1572)"
        ),
        "session_id": _session_id(src, dst, sport, dport, proto),
    }


def scenario_credential_spray() -> Dict:
    """Password spraying: low-and-slow authentication attempts across many accounts.
    Matches MITRE T1110.003 (Brute Force: Password Spraying)."""
    src      = random.choice(EXTERNAL_C2_IPS)
    dst      = random.choice(INTERNAL_IPS)
    accounts = random.randint(40, 200)
    sport    = random.randint(49152, 65535)
    dport    = random.choice([389, 636, 443, 80])  # LDAP, LDAPS, web login
    service  = {389:"LDAP", 636:"LDAPS", 443:"HTTPS", 80:"HTTP"}[dport]
    return {
        "type":            "CREDENTIAL_SPRAY_DETECTED",
        "severity":        "HIGH",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons":         [f"SPRAY_{accounts}_ACCOUNTS", f"LOW_AND_SLOW_{service}"],
        "accounts_targeted": accounts,
        "service":         service,
        "mitre_technique": "T1110.003",
        "anomaly_score":   round(random.uniform(0.67, 0.85), 4),
        "description": (
            f"Password spray attack: {src} attempted authentication against {accounts} "
            f"accounts on {dst} via {service} (port {dport}). "
            f"Low-rate spread across accounts avoids lockout policies. "
            f"Consistent with credential harvesting pre-lateral movement. (MITRE T1110.003)"
        ),
        "session_id": _session_id(src, dst, sport, dport, "TCP"),
    }


def scenario_reverse_shell() -> Dict:
    """Reverse shell: compromised host initiating outbound shell connection to attacker.
    Matches MITRE T1059.004 (Command and Scripting Interpreter: Unix Shell)."""
    src   = random.choice(INTERNAL_IPS)
    dst   = random.choice(EXTERNAL_C2_IPS)
    sport = random.randint(49152, 65535)
    dport = random.choice(SUSPICIOUS_PORTS)
    return {
        "type":            "REVERSE_SHELL_DETECTED",
        "severity":        "CRITICAL",
        "timestamp":       datetime.utcnow().isoformat(),
        "src_ip":          src,
        "dst_ip":          dst,
        "src_port":        sport,
        "dst_port":        dport,
        "protocol":        "TCP",
        "reasons":         [f"SUSPICIOUS_OUTBOUND_PORT:{dport}", "INTERACTIVE_SHELL_PATTERN", "BIDIRECTIONAL_SMALL_PACKETS"],
        "shell_port":      dport,
        "mitre_technique": "T1059.004",
        "anomaly_score":   round(random.uniform(0.88, 0.99), 4),
        "description": (
            f"Reverse shell detected: {src} opened outbound TCP connection to "
            f"{dst}:{dport} — a known attacker-used port. "
            f"Bidirectional small-packet pattern (stdin/stdout) confirms interactive shell session. "
            f"Host is fully compromised and under attacker control. (MITRE T1059.004)"
        ),
        "session_id": _session_id(src, dst, sport, dport, "TCP"),
    }


# ── Scenario scheduler ───────────────────────────────────────────────────────
# Weight: higher = more frequent.
# CRITICAL scenarios weighted highest for realistic SOC alert distribution.
SCENARIOS = [
    (scenario_c2_beacon,              5, "C2 Beacon [CRITICAL]"),
    (scenario_data_exfiltration,      4, "Data Exfiltration [HIGH]"),
    (scenario_lateral_movement,       3, "Lateral Movement SMB [HIGH]"),
    (scenario_port_scan,              3, "Port Scan [MEDIUM]"),
    (scenario_dns_tunneling,          3, "DNS Tunneling [HIGH]"),
    (scenario_brute_force_ssh,        3, "Brute Force SSH [HIGH]"),
    (scenario_rdp_lateral_movement,   3, "RDP Lateral Movement [HIGH]"),
    (scenario_exploit_public_app,     4, "Public App Exploit [CRITICAL]"),
    (scenario_high_entropy_payload,   3, "High Entropy Payload [HIGH]"),
    (scenario_protocol_tunneling,     2, "Protocol Tunneling [HIGH]"),
    (scenario_credential_spray,       3, "Credential Spray [HIGH]"),
    (scenario_reverse_shell,          4, "Reverse Shell [CRITICAL]"),
]

_fns, _weights, _names = zip(*SCENARIOS)


class TrafficSimulator:

    def __init__(self):
        self.producer: AIOKafkaProducer = None
        self.events_sent = 0

    async def start(self):
        logger.info("🎭 CyberSentinel Traffic Simulator starting...")
        logger.info(f"   Scenarios: {len(SCENARIOS)} threat types across full MITRE kill-chain")
        logger.info(f"   Rate: {EVENTS_PER_MINUTE} events/minute → 1 event every {60 / EVENTS_PER_MINUTE:.0f}s")

        self.producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            compression_type="gzip",
        )
        await self.producer.start()
        logger.info(f"✅ Kafka connected — streaming to topic '{KAFKA_TOPIC}'")
        logger.info("🚀 Simulating threat scenarios...")

        interval_sec = 60.0 / EVENTS_PER_MINUTE

        while True:
            try:
                fn = random.choices(_fns, weights=_weights, k=1)[0]
                name_idx = _fns.index(fn)
                event = fn()

                await self.producer.send(KAFKA_TOPIC, value=event)
                self.events_sent += 1

                logger.info(
                    f"📡 [{self.events_sent:>5}] {_names[name_idx]:<35} "
                    f"{event.get('src_ip','?'):>15} → {event.get('dst_ip','?'):<15} "
                    f"(score={event.get('anomaly_score', '?')})"
                )

                if self.events_sent % 20 == 0:
                    logger.info(
                        f"📊 Summary: {self.events_sent} events sent "
                        f"| Rate: {EVENTS_PER_MINUTE}/min | Topic: {KAFKA_TOPIC}"
                    )

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
