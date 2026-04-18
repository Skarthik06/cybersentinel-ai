#!/usr/bin/env python3
"""
CyberSentinel AI — PCAP Replay Script

Replays packets from a PCAP file through the DPI pipeline by producing
pre-parsed packet events directly to the Kafka 'raw_packets' topic.
This is functionally equivalent to what the DPI sensor produces from
live capture, so the full pipeline (RLM → MCP → Alerts) runs against
the labeled traffic.

Use cases:
  - Validate detection coverage against labeled attack datasets
  - Regression-test signature changes before deploying to production
  - Benchmark throughput under known-bad traffic

Usage:
  python scripts/replay_pcap.py path/to/capture.pcap [OPTIONS]

Options:
  --rate FLOAT      Replay rate multiplier (1.0 = real-time, 0 = max speed)
  --loop INT        Number of times to replay (0 = infinite)
  --topic STR       Kafka topic (default: raw_packets)
  --kafka STR       Bootstrap server (default: localhost:9092)
  --filter STR      BPF filter to apply to PCAP (e.g. "tcp port 443")
  --label STR       Tag all events with a dataset label (stored in metadata)

Requirements:
  pip install scapy aiokafka
"""

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from typing import Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTP
    try:
        from scapy.layers.inet6 import IPv6
        _IPV6 = True
    except ImportError:
        _IPV6 = False
except ImportError:
    print("❌ scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from aiokafka import AIOKafkaProducer
except ImportError:
    print("❌ aiokafka not installed. Run: pip install aiokafka")
    sys.exit(1)


# ── Packet → event conversion (mirrors sensor.py logic) ──────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


def packet_to_event(pkt, label: Optional[str] = None) -> Optional[dict]:
    """Convert a scapy packet to the same JSON schema the DPI sensor emits."""
    src_ip = dst_ip = None
    ttl = 64
    proto = "OTHER"

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip, ttl = ip.src, ip.dst, ip.ttl
    elif _IPV6 and pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip, dst_ip, ttl = ip6.src, ip6.dst, ip6.hlim
    else:
        return None  # Not an IP packet — skip

    src_port = dst_port = 0
    flags = ""
    payload = b""

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port, dst_port = tcp.sport, tcp.dport
        proto = "TCP"
        flags = str(tcp.flags)
        if tcp.payload:
            payload = bytes(tcp.payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port, dst_port = udp.sport, udp.dport
        proto = "UDP"
        if udp.payload:
            payload = bytes(udp.payload)
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    has_dns = pkt.haslayer(DNS)
    dns_query = None
    if has_dns and pkt[DNS].qd:
        try:
            dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            pass

    has_tls = (dst_port == 443 or src_port == 443) and len(payload) > 0

    entropy = round(_entropy(payload[:512]), 4) if payload else 0.0

    session_key = f"{min(src_ip, dst_ip)}:{min(src_port, dst_port)}-{max(src_ip, dst_ip)}:{max(src_port, dst_port)}"
    session_id = hashlib.md5(session_key.encode()).hexdigest()[:16]

    event = {
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(pkt.time))),
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "protocol":    proto,
        "payload_size": len(payload),
        "flags":       flags,
        "ttl":         ttl,
        "entropy":     entropy,
        "has_tls":     has_tls,
        "has_dns":     has_dns,
        "dns_query":   dns_query,
        "session_id":  session_id,
        "source":      "pcap_replay",
        "_label":      label,
    }
    return event


# ── Replay engine ─────────────────────────────────────────────────────────────

async def replay(
    pcap_path: str,
    kafka_bootstrap: str,
    topic: str,
    rate: float,
    loops: int,
    bpf_filter: Optional[str],
    label: Optional[str],
) -> None:
    print(f"📂 Loading PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"   {len(packets)} packets loaded")

    if bpf_filter:
        from scapy.all import sniff
        filtered = [p for p in packets if p.sprintf(bpf_filter)]
        print(f"   {len(filtered)} packets after BPF filter: {bpf_filter!r}")
        packets = filtered

    # Pre-convert to events (skip non-IP)
    events = [e for p in packets if (e := packet_to_event(p, label)) is not None]
    print(f"   {len(events)} IP events ready for replay")

    if not events:
        print("❌ No IP packets found in PCAP")
        return

    producer = AIOKafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode(),
        compression_type="gzip",
    )
    await producer.start()

    try:
        loop_count = 0
        while loops == 0 or loop_count < loops:
            loop_count += 1
            print(f"\n▶️  Replay pass {loop_count}/{loops or '∞'} — {len(events)} events")

            sent = 0
            t0 = time.time()
            first_ts = float(packets[0].time) if packets else t0

            for i, event in enumerate(events):
                # Rate-limited replay: sleep to simulate original timing
                if rate > 0 and i > 0:
                    orig_ts = float(packets[i].time) if i < len(packets) else first_ts
                    elapsed_orig = (orig_ts - first_ts) / rate
                    elapsed_real = time.time() - t0
                    sleep_for = elapsed_orig - elapsed_real
                    if sleep_for > 0:
                        await asyncio.sleep(sleep_for)

                await producer.send(topic, value=event)
                sent += 1

                if sent % 500 == 0:
                    elapsed = time.time() - t0
                    rate_actual = sent / elapsed if elapsed > 0 else 0
                    print(f"   [{sent}/{len(events)}] {rate_actual:.0f} events/s", end="\r", flush=True)

            await producer.flush()
            elapsed = time.time() - t0
            print(f"\n   ✅ Pass {loop_count}: {sent} events in {elapsed:.1f}s ({sent/elapsed:.0f} events/s)")

    finally:
        await producer.stop()

    print(f"\n✅ Replay complete: {loop_count} pass(es), {loop_count * len(events)} total events sent")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Replay PCAP files through the CyberSentinel DPI pipeline"
    )
    parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    parser.add_argument("--rate",   type=float, default=0.0,
                        help="Replay rate multiplier (1.0=realtime, 0=max speed)")
    parser.add_argument("--loop",   type=int,   default=1,
                        help="Number of replay passes (0=infinite)")
    parser.add_argument("--topic",  default="raw_packets",
                        help="Kafka topic (default: raw_packets)")
    parser.add_argument("--kafka",  default=os.getenv("KAFKA_BOOTSTRAP", "localhost:9092"),
                        help="Kafka bootstrap server")
    parser.add_argument("--filter", default=None,
                        help="BPF filter to apply (e.g. 'tcp port 80')")
    parser.add_argument("--label",  default=None,
                        help="Dataset label tag (e.g. 'cicids2018-portscan')")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"❌ File not found: {args.pcap}")
        sys.exit(1)

    asyncio.run(replay(
        pcap_path=args.pcap,
        kafka_bootstrap=args.kafka,
        topic=args.topic,
        rate=args.rate,
        loops=args.loop,
        bpf_filter=args.filter,
        label=args.label,
    ))


if __name__ == "__main__":
    main()
