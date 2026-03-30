# The Two Input Pipelines

**CyberSentinel AI — DPI Real Pipeline vs Traffic Simulator**

This document explains one of the most important architectural distinctions in CyberSentinel AI: the system has two completely separate data input paths that serve different purposes and populate different parts of the database.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  PIPELINE 1 — REAL DPI (Production)                                 │
│                                                                      │
│  Real Network Traffic → sensor.py → raw-packets → RLM Engine       │
│                       → threat-alerts → MCP Orchestrator            │
│                                                                      │
│  Populates: packets, behavior_profiles (real metrics), alerts,      │
│             incidents, ChromaDB behavior_profiles collection         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  PIPELINE 2 — TRAFFIC SIMULATOR (Testing & Demo)                    │
│                                                                      │
│  traffic_simulator.py → threat-alerts → MCP Orchestrator           │
│  (skips sensor.py and raw-packets entirely)                          │
│                                                                      │
│  Populates: alerts, incidents only                                   │
│  Does NOT populate: packets, behavior_profiles                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline 1 — Real DPI Path (Full Platform)

### Step-by-Step Flow

```
Physical or Virtual Network Interface
    │
    ▼
src/dpi/sensor.py  (Scapy AsyncSniffer + BPF filter "ip")
    │
    ├── For EVERY packet:
    │     PacketEvent dataclass built with:
    │     ├── src_ip, dst_ip, src_port, dst_port
    │     ├── protocol (TCP/UDP/ICMP/DNS)
    │     ├── payload_size (bytes)
    │     ├── flags (SYN, ACK, RST, etc.)
    │     ├── ttl
    │     ├── entropy (Shannon entropy of raw payload bytes, 0–8 scale)
    │     ├── has_tls (True if TLS layer detected)
    │     ├── has_dns (True if DNS layer present)
    │     ├── dns_query (extracted domain name)
    │     ├── http_method, http_host, http_uri, user_agent
    │     ├── is_suspicious (True if any detector fires)
    │     ├── suspicion_reasons (list of triggered detector names)
    │     └── session_id (bidirectional: sorted(src:sport, dst:dport))
    │
    ├──► Kafka topic: "raw-packets"   (ALL packets — every single one)
    │
    └── If is_suspicious == True:
    └──► Kafka topic: "threat-alerts"  (immediate DPI alert, no delay)
```

```
Kafka topic: "raw-packets"
    │
    ▼
src/models/rlm_engine._consume_packets()
    │
    ├── Get or create BehaviorProfile for src_ip
    │
    ├── _update_profile() — EMA update:
    │   ├── avg_bytes_per_min   = (1-α)*old + α*payload_size
    │   ├── avg_entropy         = (1-α)*old + α*entropy
    │   ├── avg_packets_per_min = (1-α)*old + α*1
    │   ├── dominant_protocols[protocol] += EMA
    │   ├── typical_dst_ports[dst_port]  += 1
    │   ├── typical_dst_ips[dst_ip]      += 1
    │   ├── active_hours[hour_of_day]    += EMA
    │   ├── weekend_ratio               = EMA of is_weekend
    │   ├── observation_count           += 1
    │   └── context_window.append(event_summary)  ← rolling last-N
    │
    ├── profile.to_text() → natural language string:
    │     "Entity 10.0.0.55 (host) behavior: avg 8420 bytes/min,
    │      847.0 packets/min, entropy 7.10. Protocols: TCP(85%)...
    │      Anomaly: 0.723. Recent: [last 5 events]."
    │
    ├── is_embed_cached(redis, profile_text) ?
    │     YES → skip ChromaDB query (reuse last anomaly_score)
    │     NO  → continue
    │
    ├── ChromaDB cosine similarity:
    │     threat_collection.query(query_texts=[profile_text], n_results=3)
    │     similarity = max(0, 1 - distance/2)
    │     anomaly_score = top result similarity
    │
    ├── mark_embed_cached(redis, profile_text)
    │
    └── if anomaly_score > RLM_ANOMALY_THRESHOLD (0.65):
    └──► Kafka topic: "threat-alerts"  (RLM behavioral anomaly alert)
```

```
Every 300 seconds (RLM_SAVE_INTERVAL):
    ├── UPSERT all in-memory BehaviorProfiles → PostgreSQL behavior_profiles
    │     ├── entity_id (IP address)
    │     ├── anomaly_score (ChromaDB-computed, real)
    │     ├── observation_count (real packet count)
    │     ├── avg_bytes_per_min (EMA, real)
    │     ├── avg_entropy (EMA, real)
    │     ├── dominant_protocols (JSONB)
    │     ├── typical_dst_ports (JSONB)
    │     └── profile_text (the to_text() string)
    │
    └── Upsert profile → ChromaDB behavior_profiles collection
          ID: profile_{ip}_{YYYYMMDDH}
          TTL: 30 days
```

**Result:** The Hosts tab shows real, meaningful values for all metrics because real packets were observed, counted, and profiled.

---

## Pipeline 2 — Traffic Simulator Path (Testing & Demo)

### What the Simulator Does

`src/simulation/traffic_simulator.py` generates 12 types of synthetic threat events as Python dictionaries — **no actual packets are generated or captured**.

Each scenario function returns a dict like:

```python
# scenario_protocol_tunneling() example:
{
    "type":            "PROTOCOL_TUNNELING_DETECTED",
    "severity":        "HIGH",
    "timestamp":       "2026-03-29T17:33:02.123456",
    "src_ip":          "172.16.0.5",         ← randomly chosen from INTERNAL_IPS
    "dst_ip":          "185.220.101.47",      ← randomly chosen from EXTERNAL_C2_IPS
    "src_port":        54823,
    "dst_port":        0,
    "protocol":        "ICMP",
    "tunnel_protocol": "ICMP",
    "payload_size":    2847,                  ← hardcoded random value
    "mitre_technique": "T1572",
    "anomaly_score":   0.83,                  ← hardcoded random float (NEVER used by RLM)
    "reasons":         ["OVERSIZED_ICMP_PAYLOAD:2847B", "ICMP_TUNNEL_PATTERN"],
    "description":     "Protocol tunneling via ICMP: ...",
    "session_id":      "ICMP:172.16.0.5:54823-185.220.101.47:0",
}
```

This dict is **serialised to JSON and published directly to Kafka `"threat-alerts"`**.

### Step-by-Step Flow

```
traffic_simulator.py
    │
    ├── Random weighted scenario selection:
    │     C2_BEACON         weight=5  (most frequent)
    │     DATA_EXFIL        weight=4
    │     REVERSE_SHELL     weight=4
    │     EXPLOIT_PUBLIC    weight=4
    │     LATERAL_MOVEMENT  weight=3
    │     ... (12 total)
    │
    ├── Call scenario function → Python dict (no packets, no capture)
    │
    └──► Kafka topic: "threat-alerts"  (DIRECTLY — skips "raw-packets")
```

```
Kafka topic: "threat-alerts"
    │
    ▼
src/agents/mcp_orchestrator._consume_alerts()
    │
    ├── if severity NOT in ("HIGH", "CRITICAL"):
    │     → INSERT into alerts table, done (no LLM call)
    │
    └── if severity in ("HIGH", "CRITICAL"):
         → investigation_queue.put(alert)
         → InvestigateAgent.investigate(alert)
```

```
InvestigateAgent.investigate(alert):
    │
    ├── asyncio.gather() — 4 tools in parallel:
    │   ├── query_threat_database(type + mitre_technique)
    │   ├── get_host_profile(src_ip)        ← returns zeros if not real-DPI
    │   ├── lookup_ip_reputation(dst_ip)    ← AbuseIPDB API
    │   └── get_recent_alerts(src_ip, hours=6)
    │
    ├── _summarize_result() — compress each to 1-3 lines
    │
    ├── 1 LLM call → JSON verdict:
    │     {title, severity, description, evidence,
    │      affected_ips, mitre_techniques, block_recommended}
    │
    └── _create_incident() → PostgreSQL incidents table
          block_recommended: True/False (from AI verdict or severity==CRITICAL)
          block_target_ip: the IP to potentially block
```

**Result:** Alerts and incidents are created with correct data. But the behavioral profile for the source IP remains all zeros — because the RLM engine never saw any raw packets from that IP.

---

## The Exact Gap: What Gets Skipped

### Why `172.16.0.5` shows zeros in the Hosts tab

Suppose the simulator generates `PROTOCOL_TUNNELING_DETECTED` with `src_ip: "172.16.0.5"`.

**What happens:**
1. Alert published to `threat-alerts` ✓
2. MCP orchestrator picks up the alert ✓
3. LLM investigates, creates an incident ✓
4. `172.16.0.5` appears in `affected_ips` of 3 incidents ✓
5. If block recommended, appears in `firewall_rules` ✓

**What does NOT happen:**
1. The RLM engine never sees a raw packet from `172.16.0.5`
2. `behavior_profiles.observation_count` stays 0
3. `behavior_profiles.avg_bytes_per_min` stays 0
4. `behavior_profiles.avg_entropy` stays 0
5. `behavior_profiles.anomaly_score` stays 0
6. `behavior_profiles.profile_text` stays null

So in the Hosts tab, looking up `172.16.0.5` shows:
```
BLOCKED:          YES        (real — from firewall_rules)
BLOCK EVENTS:     1          (real — count of firewall_rules rows)
LINKED INCIDENTS: 3          (real — incidents where this IP in affected_ips)
RECENT ALERTS:    [3 alerts] (real — from alerts table)
ANOMALY SCORE:    0%         ← expected zero (no real DPI data)
AVG BYTES/MIN:    0          ← expected zero (no real DPI data)
AVG ENTROPY:      0.00       ← expected zero (no real DPI data)
OBSERVATIONS:     0          ← expected zero (no real DPI data)
PROFILE NOTE:     PROFILED   ← fallback default (profile_text is null)
```

The zeros are **not a bug** — they accurately reflect that no real packet was ever observed from this IP. The alert and incident data is real (generated by the AI pipeline). The behavioral profile data is zero because it can only be built from actual network packets.

---

## Simulator Scenarios and MITRE Mapping

| Scenario | MITRE ID | Severity | IPs Used |
|----------|----------|----------|----------|
| C2 Beacon | T1071.001 | CRITICAL | Internal → External C2 |
| Data Exfiltration | T1048.003 | HIGH | Internal → External Exfil |
| Lateral Movement (SMB) | T1021.002 | HIGH | Internal → Internal |
| Port Scan | T1046 | MEDIUM | External → Internal |
| DNS Tunneling | T1071.004 | HIGH | Internal → DNS Servers |
| Brute Force SSH | T1110.001 | HIGH | External → Internal |
| RDP Lateral Movement | T1021.001 | HIGH | Internal → Internal |
| Exploit Public App | T1190 | CRITICAL | External Exploit → Internal |
| High Entropy Payload | T1027 | HIGH | Internal → External C2 |
| Protocol Tunneling | T1572 | HIGH | Internal → External C2 |
| Credential Spray | T1110.003 | HIGH | External → Internal |
| Reverse Shell | T1059.004 | CRITICAL | Internal → External C2 |

**Scenario weighting:** CRITICAL scenarios (C2 Beacon, Exploit, Reverse Shell, Exfil) are weighted higher (4–5) vs others (2–3) to produce a realistic SOC alert distribution.

---

## Configuring the Simulator

```bash
# .env or docker-compose environment
SIMULATION_RATE=2   # events per minute (default: 2 = 1 every 30s)

# For faster testing (more alerts):
SIMULATION_RATE=10  # 1 event every 6s

# For slower / budget-conscious mode:
SIMULATION_RATE=1   # 1 event per minute
```

The simulator automatically spreads events evenly: `interval_sec = 60 / EVENTS_PER_MINUTE`.

---

## When to Use Each Pipeline

| Use Case | Pipeline | Why |
|----------|----------|-----|
| Production SOC deployment | Real DPI | Need real packet data, real behavioral profiles |
| Testing AI investigation | Simulator | No Npcap needed, controlled scenario injection |
| Testing block recommendations | Simulator | Generates CRITICAL alerts reliably |
| Testing n8n SOAR workflows | Simulator | Predictable event types and rates |
| Demo to stakeholders | Simulator | Works without real network infrastructure |
| Testing RLM behavioral profiling | Real DPI only | Simulator bypasses RLM entirely |
| Academic evaluation of detection | Real DPI only | Need real observation_count / anomaly_score |
| Budget-limited API testing | Simulator + INVESTIGATION_INTERVAL_SEC=1800 | Control LLM call rate precisely |

---

*Pipeline Architecture — CyberSentinel AI v1.0 — 2025/2026*
