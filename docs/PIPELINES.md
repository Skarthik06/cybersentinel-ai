# The Two Input Pipelines

**CyberSentinel AI v1.3.0 — DPI Real Pipeline vs Traffic Simulator**

Both pipelines feed the same unified processing stack through the `raw-packets` Kafka topic. From that point onwards the code path is **identical** — same RLM engine, same IsolationForest layer, same AI investigation.

---

## Overview

```mermaid
graph LR
    subgraph P1["Pipeline 1 — Real DPI (Production)"]
        NIC[Network Interface\nIPv4 + IPv6] --> SENSOR[DPI Sensor\nScapy AsyncSniffer]
        SENSOR --> PII[_mask_pii\nGDPR redaction]
    end

    subgraph P2["Pipeline 2 — Traffic Simulator (Testing)"]
        SIM[Traffic Simulator\n17 scenarios]
    end

    PII --> RAW[Kafka\nraw-packets]
    SIM --> RAW

    subgraph UNIFIED["Unified Pipeline — identical for both inputs"]
        RAW --> RLM[RLM Engine\nEMA + IsolationForest]
        RLM --> TA[Kafka\nthreat-alerts]
        TA --> MCP[MCP Orchestrator\n1-call AI investigation]
        MCP --> PG[(PostgreSQL)]
        MCP --> CAMP[Campaign\nCorrelation]
    end
```

---

## Pipeline 1 — Real DPI Path (Production)

### Packet Capture and PII Masking

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant DPI as sensor.py
    participant MASK as _mask_pii()
    participant K as Kafka raw-packets

    NIC->>DPI: Raw IPv4/IPv6 packet
    DPI->>DPI: Build PacketEvent (21 fields)
    note over DPI: Shannon entropy, TLS detection,\nDNS query, HTTP metadata,\nsession_id fingerprint
    DPI->>MASK: event_dict
    MASK->>MASK: Redact emails in dns_query, http_uri, user_agent
    MASK->>MASK: Redact credential params (password=, token=, api_key=)
    MASK-->>DPI: sanitized event_dict
    DPI->>K: PacketEvent JSON (gzip compressed)
```

**PacketEvent fields:** `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `payload_size`, `flags`, `ttl`, `entropy`, `has_tls`, `has_dns`, `dns_query`, `http_method`, `http_host`, `http_uri`, `user_agent`, `is_suspicious`, `suspicion_reasons`, `session_id`

**IPv6 support:** `BPF_FILTER=ip or ip6` captures both address families. All 21 PacketEvent fields support IPv6 addresses.

### RLM Engine Processing

```mermaid
sequenceDiagram
    participant K as Kafka raw-packets
    participant RLM as RLM Engine
    participant EMA as EMA Profiler
    participant CHROMA as ChromaDB
    participant REDIS as Redis Cache
    participant IF as IsolationForest
    participant TA as Kafka threat-alerts

    K->>RLM: consume PacketEvent
    RLM->>EMA: _update_profile(src_ip, event)
    EMA->>EMA: avg_bytes_per_min = (1-alpha)*old + alpha*payload_size
    EMA->>EMA: avg_entropy, avg_packets_per_min, protocols, ports
    EMA->>EMA: observation_count += 1
    EMA-->>RLM: updated BehaviorProfile

    RLM->>RLM: profile.to_text() → natural language string
    RLM->>REDIS: is_embed_cached(sha256(profile_text))?
    alt Cache hit
        REDIS-->>RLM: reuse last anomaly_score
    else Cache miss
        RLM->>CHROMA: cosine similarity vs threat_signatures
        CHROMA-->>RLM: base_score (0-1)
        RLM->>REDIS: mark_embed_cached()
    end

    RLM->>IF: score(entity_id, base_score)
    IF->>IF: 50-obs rolling buffer\nIsolationForest blend (25% weight)
    IF-->>RLM: final_score

    RLM->>IF: push(entity_id, final_score)

    alt final_score > 0.65
        RLM->>TA: publish threat alert
    end
```

### Profile Persistence

Every 300 seconds the RLM engine UPSERTs all in-memory profiles to PostgreSQL:

```mermaid
graph LR
    TIMER[300s timer] --> UPSERT[UPSERT behavior_profiles]
    UPSERT --> PG[(PostgreSQL\nentity_id, anomaly_score,\nobservation_count, avg_bytes_per_min\navg_entropy, profile_text)]
    UPSERT --> CD[(ChromaDB\nbehavior_profiles collection\n30-day TTL)]
```

---

## Pipeline 2 — Traffic Simulator Path (Testing & Demo)

### What the Simulator Generates

`src/simulation/traffic_simulator.py` generates 17 threat scenarios as **bursts of 30–150 raw `PacketEvent` dicts** and publishes them to the **same `raw-packets` Kafka topic** that the real DPI sensor uses.

```mermaid
sequenceDiagram
    participant SIM as traffic_simulator.py
    participant K as Kafka raw-packets
    participant RLM as RLM Engine (same as Pipeline 1)

    SIM->>SIM: random weighted scenario selection
    note over SIM: 17 scenarios — 12 MITRE-mapped\n+ 5 unknown novel threats
    SIM->>SIM: generate burst of 30-150 PacketEvents
    note over SIM: enough packets to clear\nRLM_MIN_OBSERVATIONS=20 gate
    SIM->>K: publish burst to raw-packets
    K->>RLM: IDENTICAL processing to Pipeline 1
    note over RLM: EMA profiling, ChromaDB scoring,\nIsolationForest blend, threat-alerts
```

### Simulator Scenarios

#### MITRE ATT&CK Mapped (12)

| Scenario | MITRE ID | Severity | Burst Size |
|----------|----------|----------|-----------|
| C2 Beacon | T1071.001 | CRITICAL | ~60 pkts |
| Data Exfiltration | T1048.003 | HIGH | ~80 pkts |
| Lateral Movement SMB | T1021.002 | HIGH | ~50 pkts |
| Port Scan | T1046 | MEDIUM | ~150 pkts |
| DNS Tunneling | T1071.004 | HIGH | ~100 pkts |
| Brute Force SSH | T1110.001 | HIGH | ~120 pkts |
| RDP Lateral Movement | T1021.001 | HIGH | ~45 pkts |
| Exploit Public App | T1190 | CRITICAL | ~30 pkts |
| High Entropy Payload | T1027 | HIGH | ~40 pkts |
| Protocol Tunneling | T1572 | HIGH | ~60 pkts |
| Credential Spray | T1110.003 | HIGH | ~90 pkts |
| Reverse Shell | T1059.004 | CRITICAL | ~45 pkts |

#### Unknown Novel Threats — AI Must Classify (5)

| Scenario | Type | Severity | Description |
|----------|------|----------|-------------|
| Polymorphic Beacon | POLYMORPHIC_BEACON | HIGH | Beacon intervals mutate to evade timing detection |
| Covert Storage Channel | COVERT_STORAGE_CHANNEL | HIGH | Data encoded in IP header reserved/ToS fields |
| Slow-Drip Exfil | SLOW_DRIP_EXFIL | HIGH | 1–2 bytes/packet over thousands of sessions |
| Mesh C2 Relay | MESH_C2_RELAY | CRITICAL | Multi-hop internal relay, no direct external contact |
| Synthetic Idle Traffic | SYNTHETIC_IDLE_TRAFFIC | MEDIUM | Mimics legitimate traffic but statistically wrong |

Unknown threats have no MITRE mapping — the AI investigation must classify them and recommend a technique ID.

### Scenario Weighting

```mermaid
pie title Scenario Frequency Distribution
    "C2 Beacon (CRITICAL)" : 5
    "Data Exfil (HIGH)" : 4
    "Reverse Shell (CRITICAL)" : 4
    "Exploit Public App (CRITICAL)" : 4
    "Lateral Movement (HIGH)" : 3
    "Port Scan (MEDIUM)" : 3
    "DNS Tunneling (HIGH)" : 3
    "Brute Force SSH (HIGH)" : 3
    "RDP Lateral (HIGH)" : 3
    "High Entropy (HIGH)" : 3
    "Credential Spray (HIGH)" : 3
    "Protocol Tunnel (HIGH)" : 2
    "Novel Threats (5)" : 8
```

---

## MCP Orchestrator — Shared Final Stage

Both pipelines feed the same MCP Orchestrator:

```mermaid
flowchart TD
    TA[Kafka threat-alerts] --> ROUTE{severity?}
    ROUTE -->|HIGH or CRITICAL| QUEUE[investigation_queue]
    ROUTE -->|MEDIUM or LOW| DIRECT[INSERT alerts table\nno LLM call]

    QUEUE --> INV[InvestigateAgent.investigate]

    subgraph GATHER["Parallel intel gathering — 0 LLM calls"]
        INV --> G1[ChromaDB\nthreat_signatures top-3]
        INV --> G2[host_profile\nPostgreSQL + ChromaDB]
        INV --> G3[AbuseIPDB\nIP reputation]
        INV --> G4[recent_alerts\nlast 6h]
    end

    G1 --> SUM[_summarize_result\n1-3 lines each]
    G2 --> SUM
    G3 --> SUM
    G4 --> SUM

    SUM --> LLM["Single LLM call\n~553 tokens · $0.000165"]
    LLM --> VERDICT[JSON verdict]
    VERDICT --> INC[_create_incident\nPostgreSQL]
    VERDICT --> CAMP[_correlate_campaign\n24h window · asyncio.ensure_future]
```

### Pending Incidents When AI Is Paused

When AI investigation is paused for a source, the MCP orchestrator still creates a **pending incident** via `_create_pending_incident()`:

- Status: `OPEN`, investigation_summary: `"AI investigation was paused"`
- `block_recommended`: `True` for CRITICAL/HIGH severity, `False` for MEDIUM/LOW
- `block_target_ip`: set to `src_ip` for CRITICAL/HIGH

CRITICAL and HIGH alerts always surface in the RESPONSE tab even without full AI analysis.

---

## What Each Pipeline Populates

| Data | Real DPI | Simulator (v1.3) |
|------|----------|-----------------|
| `alerts` table | Yes | Yes |
| `incidents` table | Yes | Yes |
| `attacker_campaigns` table | Yes | Yes |
| `firewall_rules` table | Yes | Yes (via block recommendations) |
| `packets` table | Yes (every suspicious packet) | Yes (PacketEvent bursts) |
| `behavior_profiles.observation_count` | Yes (real packet count) | Yes (burst count: 30–150) |
| `behavior_profiles.avg_bytes_per_min` | Yes (real EMA) | Yes (scenario-realistic EMA) |
| `behavior_profiles.avg_entropy` | Yes (real EMA) | Yes (scenario entropy EMA) |
| `behavior_profiles.anomaly_score` | Yes (IsolationForest blended) | Yes (IsolationForest blended) |
| ChromaDB `behavior_profiles` collection | Yes | Yes |
| Raw packet bytes (pcap level) | Yes | No (no physical NIC) |

---

## Source Isolation — Investigation Pausing

AI investigation can be paused **per source** independently via Redis keys:

| Redis Key | Effect |
|-----------|--------|
| `investigations:paused:simulator` | Pauses only simulator investigations |
| `investigations:paused:dpi` | Pauses only real DPI investigations |

Toggle via the Dashboard (POST `/api/v1/control?source=simulator`). Useful for testing the simulator without burning LLM API quota while keeping live DPI investigations running.

---

## Configuring the Simulator Rate

```bash
# .env
SIMULATION_RATE=2   # events per minute (default: 1 every 30s)
SIMULATION_RATE=10  # faster testing: 1 every 6s
SIMULATION_RATE=1   # budget-conscious: 1 per minute
```

---

## When to Use Each Pipeline

| Use Case | Pipeline |
|----------|----------|
| Production SOC deployment | Real DPI |
| Testing AI investigation | Simulator |
| Testing block recommendations | Simulator (reliable CRITICAL alerts) |
| Testing n8n SOAR workflows | Simulator (predictable event types) |
| Demo to stakeholders | Simulator (no network infrastructure needed) |
| Testing IsolationForest progression detection | Both |
| Academic evaluation with real metrics | Real DPI preferred |
| Budget-limited API testing | Simulator + pause AI |

---

*Pipeline Architecture — CyberSentinel AI v1.3.0 — 2026*
