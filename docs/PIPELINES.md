# The Two Input Pipelines

**CyberSentinel AI — DPI Real Pipeline vs Traffic Simulator**

This document explains one of the most important architectural distinctions in CyberSentinel AI: the system has two data input paths. Both feed the same unified processing pipeline through the `raw-packets` Kafka topic.

> **v1.2 update:** The Traffic Simulator was upgraded in v1.2 to publish raw `PacketEvent` dicts to the `raw-packets` topic instead of pre-formed alerts to `threat-alerts`. Both pipelines are now **identical from the Kafka layer onwards** — the simulator is no longer a shortcut; it exercises the full RLM + AI investigation stack.

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
│  traffic_simulator.py → raw-packets → RLM Engine                   │
│                       → threat-alerts → MCP Orchestrator            │
│                                                                      │
│  Populates: packets (partial), behavior_profiles, alerts, incidents │
│  Each scenario = burst of 30–150 PacketEvents → RLM sees real volume│
└─────────────────────────────────────────────────────────────────────┘
```

Both pipelines merge at `raw-packets` → `RLM Engine` → `threat-alerts` → `MCP Orchestrator`.

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
    └──► Kafka topic: "raw-packets"   (ALL packets — every single one)
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
    └── if anomaly_score > RLM_ANOMALY_THRESHOLD (0.40):
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

---

## Pipeline 2 — Traffic Simulator Path (Testing & Demo)

### What the Simulator Does (v1.2 — Full DPI Pipeline Edition)

`src/simulation/traffic_simulator.py` generates 17 threat scenarios as **bursts of 30–150 raw `PacketEvent` dicts** and publishes them to the **same `raw-packets` Kafka topic** that the real DPI sensor uses.

This means every simulated scenario passes through the **full RLM pipeline**: EMA profiling → ChromaDB scoring → anomaly detection → `threat-alerts`. The `min_observations` gate (default: 20 packets) is cleared by the burst.

### PacketEvent Structure (simulator output)

```python
# scenario_c2_beacon() — one packet from the burst:
{
    "src_ip":          "192.168.1.15",     ← randomly chosen from INTERNAL_IPS
    "dst_ip":          "185.220.101.47",   ← randomly chosen from EXTERNAL_C2_IPS
    "src_port":        54823,
    "dst_port":        443,
    "protocol":        "TCP",
    "payload_size":    312,                ← scenario-realistic value
    "entropy":         6.8,               ← high for C2 beacon
    "flags":           "PA",
    "has_tls":         True,
    "has_dns":         False,
    "dns_query":       None,
    "http_method":     None,
    "is_suspicious":   True,
    "suspicion_reasons": ["BEACON_TIMING_REGULARITY", "HIGH_ENTROPY_PAYLOAD"],
    "session_id":      "TCP:192.168.1.15:54823-185.220.101.47:443",
    "timestamp":       "2026-04-06T14:22:01.123456",
}
```

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
    │     ... (17 total)
    │
    ├── Call scenario function → generate BURST of 30–150 PacketEvent dicts
    │     (enough for RLM min_observations gate to clear)
    │
    └──► Kafka topic: "raw-packets"  (SAME topic as real DPI sensor)
```

```
Kafka topic: "raw-packets"
    │
    ▼
src/models/rlm_engine._consume_packets()   ← SAME as Pipeline 1
    │
    ├── EMA profiling per src_ip
    ├── profile.to_text() → ChromaDB cosine similarity
    └── if anomaly_score > 0.40:
    └──► Kafka topic: "threat-alerts"
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
         → alert_queue.put(alert)
         → _process_alert_queue() → InvestigateAgent.investigate(alert)
```

```
InvestigateAgent.investigate(alert):
    │
    ├── asyncio.gather() — 4 tools in parallel:
    │   ├── query_threat_database(type + mitre_technique)
    │   ├── get_host_profile(src_ip)
    │   ├── lookup_ip_reputation(dst_ip)    ← AbuseIPDB API
    │   └── get_recent_alerts(src_ip, hours=6)
    │
    ├── _summarize_result() — compress each to 1-3 lines
    │
    ├── 1 LLM call → structured JSON verdict:
    │     {title, severity, description, evidence,
    │      affected_ips, mitre_techniques, block_recommended}
    │
    └── _create_incident() → PostgreSQL incidents table
          block_recommended: True for CRITICAL/HIGH (from AI verdict)
          block_target_ip: the IP to potentially block
```

---

## What Each Pipeline Populates

| Data | Real DPI | Simulator (v1.2) |
|------|----------|-----------------|
| `alerts` table | Yes | Yes |
| `incidents` table | Yes | Yes |
| `packets` table | Yes (every packet captured) | Partial (PacketEvents, not raw bytes) |
| `behavior_profiles.observation_count` | Yes (real count) | Yes (burst count, ~30–150) |
| `behavior_profiles.avg_bytes_per_min` | Yes (real EMA) | Yes (scenario-realistic values) |
| `behavior_profiles.avg_entropy` | Yes (real EMA) | Yes (scenario-realistic values) |
| `behavior_profiles.anomaly_score` | Yes (ChromaDB computed) | Yes (ChromaDB computed) |
| `packets_per_minute` TimescaleDB view | Yes | Yes |
| ChromaDB `behavior_profiles` collection | Yes | Yes |

> **Key difference from v1.1:** In v1.1 the simulator bypassed RLM entirely, leaving all behavioral profile fields at zero. In v1.2 the simulator feeds the full DPI pipeline and builds real profiles.

---

## AI Investigation — Pending Incidents When Paused

When AI investigation is **paused** for a source (simulator or dpi), the MCP orchestrator still creates a **pending incident** via `_create_pending_incident()`:

- Incident status: `OPEN`, investigation_summary: `"⏸ AI investigation was paused..."`
- `block_recommended`: `True` for CRITICAL/HIGH severity, `False` for MEDIUM/LOW
- `block_target_ip`: set to `src_ip` for CRITICAL/HIGH

This ensures CRITICAL and HIGH alerts always surface in the Block Recommendations panel even without a full AI investigation.

---

## AI Investigation Summary Format (v1.2)

When a full investigation runs, the AI generates a **structured 4-part analysis**:

```
OBSERVED: exact traffic seen — IPs, ports, protocol, entropy value, bytes/min
WHY SUSPICIOUS: which behavioural indicator fired and why it deviates from baseline
THREAT ASSESSMENT: most likely attacker objective + confidence (HIGH/MEDIUM/LOW) + reasoning
ATTACKER PROFILE: threat category (APT / ransomware / opportunistic scanner / insider / botnet)
```

The **Technical Playbook** (remediation) is generated separately on analyst request and contains:
- Containment commands (shell/CLI)
- Eradication steps
- Snort/Sigma detection rules tuned to the specific IOC
- Verification checklist

---

## Simulator Scenarios and MITRE Mapping

### MITRE ATT&CK Mapped (12)

| Scenario | MITRE ID | Severity | IPs Used |
|----------|----------|----------|----------|
| C2 Beacon | T1071.001 | CRITICAL | Internal → External C2 |
| Data Exfiltration | T1048.003 | HIGH | Internal → External Exfil |
| Lateral Movement SMB | T1021.002 | HIGH | Internal → Internal |
| Port Scan | T1046 | MEDIUM | External → Internal |
| DNS Tunneling | T1071.004 | HIGH | Internal → DNS Servers |
| Brute Force SSH | T1110.001 | HIGH | External → Internal |
| RDP Lateral Movement | T1021.001 | HIGH | Internal → Internal |
| Exploit Public App | T1190 | CRITICAL | External → Internal |
| High Entropy Payload | T1027 | HIGH | Internal → External C2 |
| Protocol Tunneling | T1572 | HIGH | Internal → External C2 |
| Credential Spray | T1110.003 | HIGH | External → Internal |
| Reverse Shell | T1059.004 | CRITICAL | Internal → External C2 |

### Unknown Novel Threats — AI Must Classify (5)

| Scenario | Type | Severity | Description |
|----------|------|----------|-------------|
| Polymorphic Beacon | POLYMORPHIC_BEACON | HIGH | Beacon intervals mutate to evade timing detection |
| Covert Storage Channel | COVERT_STORAGE_CHANNEL | HIGH | Data encoded in IP header reserved/ToS fields |
| Slow-Drip Exfil | SLOW_DRIP_EXFIL | HIGH | 1-2 bytes/packet over thousands of sessions |
| Mesh C2 Relay | MESH_C2_RELAY | CRITICAL | Multi-hop internal relay, no direct external contact |
| Synthetic Idle Traffic | SYNTHETIC_IDLE_TRAFFIC | MEDIUM | Mimics legitimate traffic but statistically wrong |

Unknown threats have no MITRE mapping — the AI investigation agent must classify them and recommend a technique ID.

**Scenario weighting:** CRITICAL scenarios (C2 Beacon, Exploit, Reverse Shell, Exfil) are weighted 4–5 vs others 2–3 to produce a realistic SOC alert distribution.

---

## Source Isolation — Investigation Pausing

AI investigation can be paused **per source** independently:

- `investigations:paused:simulator` — pauses only simulator investigations
- `investigations:paused:dpi` — pauses only real DPI investigations

This allows testing the simulator without burning LLM API quota, while keeping live DPI investigations running (or vice versa).

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
| Production SOC deployment | Real DPI | Need genuine packet capture from real interfaces |
| Testing AI investigation | Simulator | No Npcap needed, controlled scenario injection |
| Testing block recommendations | Simulator | Generates CRITICAL alerts reliably |
| Testing n8n SOAR workflows | Simulator | Predictable event types and rates |
| Demo to stakeholders | Simulator | Works without real network infrastructure |
| Testing RLM behavioral profiling | Both | v1.2 simulator feeds the full RLM pipeline |
| Academic evaluation of detection | Real DPI preferred | Real packet capture for genuine observation counts |
| Budget-limited API testing | Simulator + pause AI | Toggle AI pause via dashboard, control LLM call rate |

---

*Pipeline Architecture — CyberSentinel AI v1.2 — 2026*
