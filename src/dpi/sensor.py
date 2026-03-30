"""
CyberSentinel AI — Deep Packet Inspection (DPI) Sensor
Captures and analyzes network packets in real-time using Scapy.
Streams enriched packet metadata to Kafka for downstream ML processing.
"""

import asyncio
import json
import logging
import math
import os
import struct
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis
from aiokafka import AIOKafkaProducer
from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, Raw, ICMP, sniff
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DPI] %(levelname)s: %(message)s")
logger = logging.getLogger("dpi-sensor")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
KAFKA_TOPIC_PACKETS = "raw-packets"
KAFKA_TOPIC_ALERTS = "threat-alerts"

# Known malicious port patterns
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888,  # Common reverse shell ports
    31337, 12345, 27374,             # Classic backdoor ports
    1433, 3306, 5432, 27017,         # DB ports (external access suspicious)
}

# C2 beacon timing detection (packets at regular intervals = potential C2)
C2_INTERVAL_THRESHOLD_SEC = 60


@dataclass
class PacketEvent:
    """Normalized packet event for downstream ML processing."""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    flags: str
    ttl: int
    entropy: float           # Shannon entropy of payload (high = encrypted/compressed)
    has_tls: bool
    has_dns: bool
    dns_query: Optional[str]
    http_method: Optional[str]
    http_host: Optional[str]
    http_uri: Optional[str]
    user_agent: Optional[str]
    is_suspicious: bool
    suspicion_reasons: list
    session_id: str


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy — high values suggest encryption or compression."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def make_session_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    """Bidirectional session fingerprint."""
    endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
    return f"{proto}:{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"


def analyze_packet(pkt) -> Optional[PacketEvent]:
    """Parse a raw Scapy packet into a structured PacketEvent."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    ttl = ip.ttl
    proto = "OTHER"
    src_port = dst_port = 0
    flags = ""
    suspicion_reasons = []

    if pkt.haslayer(TCP):
        proto = "TCP"
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)

        # SYN flood detection
        if "S" in flags and "A" not in flags:
            pass  # tracked at flow level

        # Port scan detection (small payload, multiple ports)
        if dst_port in SUSPICIOUS_PORTS:
            suspicion_reasons.append(f"SUSPICIOUS_PORT:{dst_port}")

    elif pkt.haslayer(UDP):
        proto = "UDP"
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    # Extract payload
    payload = b""
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

    entropy = calculate_entropy(payload)

    # High entropy on non-standard ports = suspicious
    # Skip if this is a standard web/SSH port (HTTPS, SSH, etc.) in either direction
    _web_ports = {80, 443, 8443, 8080, 22}
    if entropy > 7.2 and dst_port not in _web_ports and src_port not in _web_ports:
        suspicion_reasons.append(f"HIGH_ENTROPY_PAYLOAD:{entropy}")

    # TTL anomaly (non-standard OS TTL)
    # Skip for RFC-1918 private sources — Docker containers use TTL=64 and decrement by 1
    _private = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                "172.29.", "172.30.", "172.31.", "192.168.", "127.")
    _is_internal_src = any(src_ip.startswith(p) for p in _private)
    if ttl not in {32, 64, 128, 255} and not _is_internal_src:
        suspicion_reasons.append(f"ANOMALOUS_TTL:{ttl}")

    # DNS analysis
    dns_query = None
    has_dns = pkt.haslayer(DNS)
    if has_dns and pkt[DNS].qr == 0:  # DNS query
        try:
            dns_query = pkt[DNS].qd.qname.decode("utf-8").rstrip(".")
            # DGA detection: long random-looking subdomains
            parts = dns_query.split(".")
            if parts and len(parts[0]) > 20:
                suspicion_reasons.append(f"POTENTIAL_DGA:{dns_query}")
        except Exception:
            pass

    # HTTP analysis
    http_method = http_host = http_uri = user_agent = None
    if pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        try:
            http_method = req.Method.decode() if req.Method else None
            http_host = req.Host.decode() if req.Host else None
            http_uri = req.Path.decode() if req.Path else None
            if req.User_Agent:
                user_agent = req.User_Agent.decode()
                # Known malware user-agents
                malware_agents = ["python-requests", "curl/7.68", "Go-http-client/1.1", "masscan"]
                if any(ma in user_agent for ma in malware_agents):
                    suspicion_reasons.append(f"SUSPICIOUS_UA:{user_agent}")
        except Exception:
            pass

    # Cleartext credential patterns in payload
    if payload:
        payload_str = payload.decode("utf-8", errors="ignore").lower()
        if "password=" in payload_str or "passwd=" in payload_str or "secret=" in payload_str:
            suspicion_reasons.append("CLEARTEXT_CREDENTIALS")

    return PacketEvent(
        timestamp=datetime.utcnow().isoformat(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        payload_size=len(payload),
        flags=flags,
        ttl=ttl,
        entropy=entropy,
        has_tls=pkt.haslayer(TLS),
        has_dns=has_dns,
        dns_query=dns_query,
        http_method=http_method,
        http_host=http_host,
        http_uri=http_uri,
        user_agent=user_agent,
        is_suspicious=len(suspicion_reasons) > 0,
        suspicion_reasons=suspicion_reasons,
        session_id=make_session_id(src_ip, dst_ip, src_port, dst_port, proto),
    )


class DPISensor:
    """
    Real-time DPI sensor that captures packets and streams to Kafka.
    Maintains per-session flow tracking in Redis for stateful analysis.
    """

    def __init__(self):
        self.producer: Optional[AIOKafkaProducer] = None
        self.redis: Optional[aioredis.Redis] = None
        self.packet_count = 0
        self.alert_count = 0
        self.interface = os.getenv("CAPTURE_INTERFACE", "eth0")
        self.bpf_filter = os.getenv("BPF_FILTER", "ip")

    async def start(self):
        logger.info("🚀 CyberSentinel DPI Sensor starting...")

        self.producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            compression_type="gzip",
            max_batch_size=1048576,
        )
        await self.producer.start()

        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True, max_connections=5)

        logger.info(f"✅ Kafka connected | Redis connected")
        logger.info(f"📡 Capturing on interface: {self.interface} | Filter: {self.bpf_filter}")

        # Run packet capture in executor to avoid blocking event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._capture, loop)

    def _capture(self, loop):
        """Synchronous packet capture (runs in thread pool)."""
        def _prn(pkt):
            asyncio.run_coroutine_threadsafe(self._handle_packet(pkt), loop)
            # Return None explicitly — Scapy prints any non-None prn return value to stdout

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_prn,
            store=False,
        )

    async def _handle_packet(self, pkt):
        """Process a single captured packet."""
        event = analyze_packet(pkt)
        if not event:
            return

        self.packet_count += 1
        event_dict = asdict(event)

        # Stream to raw packets topic
        await self.producer.send(KAFKA_TOPIC_PACKETS, value=event_dict)

        # Track session flow in Redis (sliding window for C2 detection)
        session_key = f"session:{event.session_id}"
        pipe = self.redis.pipeline()
        pipe.lpush(session_key, event.timestamp)
        pipe.ltrim(session_key, 0, 99)  # Keep last 100 timestamps per session
        pipe.expire(session_key, 3600)  # 1hr TTL
        await pipe.execute()

        # Check for C2 beacon pattern (regular timing intervals)
        await self._check_c2_beacon(event, session_key)

        # Immediate high-priority alert for severe suspicion
        if event.is_suspicious:
            self.alert_count += 1
            severity = "CRITICAL" if len(event.suspicion_reasons) >= 2 else "HIGH"
            alert = {
                "type": "DPI_ALERT",
                "severity": severity,
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "reasons": event.suspicion_reasons,
                "session_id": event.session_id,
            }
            await self.producer.send(KAFKA_TOPIC_ALERTS, value=alert)
            logger.warning(f"🚨 ALERT [{severity}] {event.src_ip} → {event.dst_ip} | {event.suspicion_reasons}")

        if self.packet_count % 1000 == 0:
            logger.info(f"📊 Processed {self.packet_count:,} packets | {self.alert_count} alerts")

    async def _check_c2_beacon(self, event: PacketEvent, session_key: str):
        """Detect regular timing intervals that indicate C2 beaconing."""
        timestamps = await self.redis.lrange(session_key, 0, 19)
        if len(timestamps) < 10:
            return

        times = sorted([datetime.fromisoformat(t).timestamp() for t in timestamps])
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        if not intervals:
            return

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # Low variance + regular interval = C2 beaconing
        if C2_INTERVAL_THRESHOLD_SEC > avg_interval > 5 and std_dev < 2.0:
            alert = {
                "type": "C2_BEACON_DETECTED",
                "severity": "CRITICAL",
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "avg_interval_sec": round(avg_interval, 2),
                "std_dev": round(std_dev, 4),
                "session_id": event.session_id,
                "mitre_technique": "T1071.001",  # Application Layer Protocol: Web Protocols
            }
            await self.producer.send(KAFKA_TOPIC_ALERTS, value=alert)
            logger.critical(f"🔴 C2 BEACON DETECTED: {event.src_ip} → {event.dst_ip} | interval={avg_interval:.1f}s σ={std_dev:.3f}")


async def main():
    sensor = DPISensor()
    try:
        await sensor.start()
    except KeyboardInterrupt:
        logger.info("Shutting down DPI sensor...")
    finally:
        if sensor.producer:
            await sensor.producer.stop()
        if sensor.redis:
            await sensor.redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
