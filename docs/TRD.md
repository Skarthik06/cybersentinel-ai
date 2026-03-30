# Technical Requirements Document (TRD)

**Project:** CyberSentinel AI
**Version:** 1.1
**Status:** Production Ready
**Date:** 2025/2026

---

## 1. System Overview

CyberSentinel AI is an event-driven microservices platform. All inter-service communication happens asynchronously through Apache Kafka. Services are stateless — state lives in PostgreSQL (persistent), Redis (hot cache), and ChromaDB (vector store). No direct service-to-service HTTP calls exist in the detection pipeline.

The system has two input modes that operate independently:
- **Real DPI mode** — Scapy captures actual network packets, feeds the RLM engine, and builds real behavioral profiles
- **Simulator mode** — traffic_simulator.py generates synthetic threat events that bypass the RLM engine entirely

See `docs/PIPELINES.md` for the complete comparison of what each mode populates.

---

## 2. Technology Stack

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Packet Capture | Scapy | 2.5.0 | Industry standard; supports BPF, all protocols, async sniffing |
| Message Bus | Apache Kafka (Confluent) | 7.5.0 | Guaranteed delivery, consumer groups, replay capability |
| Vector Database | ChromaDB | 0.4.22 | Native Python, cosine similarity, no external infra required |
| Time-Series DB | TimescaleDB (PostgreSQL 15) | latest-pg15 | SQL familiarity + hypertable compression + retention policies |
| Cache | Redis | 7-alpine | Sub-millisecond latency for blocking decisions and embedding cache |
| Embedding Model | all-MiniLM-L6-v2 | pinned | 384-dim, 256-token limit, runs on CPU, zero API cost |
| LLM — Primary (investigation) | claude-opus-4-5 / gpt-4o-mini / gemini-2.5-flash | configurable | Switchable via `LLM_PROVIDER` env var |
| LLM — Fast (CVE analysis) | claude-haiku-4-5-20251001 / gpt-4o-mini / gemini-2.5-flash | configurable | `LLM_MODEL_FAST` override |
| LLM — Analysis (reports) | claude-sonnet-4-6 / gpt-4o-mini / gemini-2.5-flash | configurable | `LLM_MODEL_ANALYSIS` override |
| CTI Scraping | Playwright | 1.40.0 | Handles JavaScript-rendered pages; Chromium headless |
| REST API | FastAPI | 0.109.0 | Async, auto-Swagger, Pydantic validation, high throughput |
| API Validation | Pydantic | 2.5.0 | Type-safe schemas, automatic JSON serialisation |
| Auth | python-jose + passlib | 3.3.0 / 1.7.4 | JWT (HS256) + bcrypt (work factor 12) |
| SOAR | n8n | latest | Self-hosted, JSON-importable workflows, 11+ integrations |
| Frontend | React | 18.2.0 | Component model, hooks, broad ecosystem |
| Charts | Recharts | 2.12.0 | Declarative, works with React 18, no canvas complexity |
| Build Tool | Vite | 5.1.0 | Sub-second HMR, ESM native, proxy support |
| Observability | Grafana + Prometheus | 10.2 / v2.47 | De-facto standard for containerised monitoring |
| Containerisation | Docker Compose | v2.20+ | Reproducible, cross-platform, single-command deployment |

**Current recommended LLM provider:** OpenAI (`LLM_PROVIDER=openai`, model: `gpt-4o-mini`)
- Cost: $0.15/1M input, $0.60/1M output
- ~553 tokens/investigation → $0.000165/investigation
- With `INVESTIGATION_INTERVAL_SEC=1800`: ~$0.008/day → 625 days on $5 budget

---

## 3. Service Architecture

### 3.1 Container Inventory

| Container | Image | Ports | Network | Purpose |
|-----------|-------|-------|---------|---------|
| cybersentinel-zookeeper | confluentinc/cp-zookeeper:7.5.0 | — | internal | Kafka coordinator |
| cybersentinel-kafka | confluentinc/cp-kafka:7.5.0 | 9092 | internal + host | Event streaming |
| cybersentinel-postgres | timescale/timescaledb:latest-pg15 | 5432 | internal | Persistent storage |
| cybersentinel-redis | redis:7-alpine | 6379 | internal | Hot cache |
| cybersentinel-chromadb | chromadb/chroma:latest | 8000 | internal | Vector store |
| cybersentinel-dpi | custom (Dockerfile.dpi) | host net | host | Packet capture |
| cybersentinel-rlm | custom (Dockerfile.rlm) | — | internal | Behavioral profiling |
| cybersentinel-scraper | custom (Dockerfile.scraper) | — | internal | CTI harvesting |
| cybersentinel-simulator | custom (Dockerfile.simulator) | — | internal | Synthetic threat events |
| cybersentinel-mcp | custom (Dockerfile.mcp) | — | internal | AI investigation agents |
| cybersentinel-api | custom (Dockerfile.api) | 8080 | internal + host | REST gateway |
| cybersentinel-grafana | grafana/grafana:10.2.0 | 3001 | internal + host | Dashboards |
| cybersentinel-prometheus | prom/prometheus:v2.47.0 | 9090 | internal + host | Metrics |
| cybersentinel-n8n | n8nio/n8n:latest | 5678 | internal + host | SOAR workflows |

### 3.2 Kafka Topic Specification

| Topic | Retention | Producer | Consumers |
|-------|-----------|----------|-----------|
| `raw-packets` | 1 hour | dpi-sensor | rlm-engine |
| `threat-alerts` | 24 hours | dpi-sensor, rlm-engine, **traffic-simulator** | mcp-orchestrator, n8n-bridge |
| `enriched-alerts` | 24 hours | rlm-engine | mcp-orchestrator, n8n-bridge |
| `incidents` | 7 days | mcp-orchestrator | n8n-bridge |
| `cti-updates` | 48 hours | threat-intel-scraper | rlm-engine, n8n-bridge |

**Note:** `traffic-simulator` writes to `threat-alerts` directly — it never writes to `raw-packets`. This is why simulator-generated events don't populate behavioral profiles.

### 3.3 Inter-Service Data Flow

```
Network Interface
    │
    ▼ raw IP packets
DPI Sensor (Scapy)
    │ PacketEvent dataclass → JSON
    ├──► Kafka: raw-packets
    └──► Kafka: threat-alerts  (if is_suspicious=True)

Traffic Simulator [PARALLEL — skips DPI entirely]
    │ Python dicts → JSON
    └──► Kafka: threat-alerts  (synthetic events)

         │ (both DPI alerts and simulator events merge here)
         ▼
RLM Engine
    │ consumes raw-packets ONLY (not threat-alerts)
    │ updates BehaviorProfile (EMA)
    │ queries ChromaDB (cosine similarity)
    │ if score > threshold:
    ├──► Kafka: threat-alerts  (RLM_ANOMALY)
    └──► Kafka: enriched-alerts (DPI alert + RLM context)
         │
    ┌────┴────────────────────┐
    ▼                         ▼
MCP Orchestrator          n8n Bridge
(HIGH/CRITICAL only)      (all severities, routed by type)
    │                         │
    │ 1-call investigation      │ HTTP POST to n8n webhooks
    │ asyncio.gather + LLM      │
    │ JSON verdict              ▼
    │                     n8n Workflows
    ├──► PostgreSQL: alerts     01/02/03/04/05
    ├──► PostgreSQL: incidents
    │     (block_recommended, block_target_ip)
    ├──► API: GET /block-recommendations (analysts poll)
    └──► (no auto-block — analyst reviews via RESPONSE tab)

Analyst reviews RESPONSE tab:
    ├── BLOCK IP → POST /incidents/{id}/block
    │     ├── Redis: blocked:{ip}
    │     └── PostgreSQL: firewall_rules
    └── DISMISS → POST /incidents/{id}/dismiss
```

---

## 4. Module Specifications

### 4.1 DPI Sensor (`src/dpi/`)

**Entry point:** `sensor.py` — `DPISensor.start()`

**Capture method:** `scapy.sniff()` with BPF filter `"ip"`, runs in thread pool executor.

**PacketEvent fields:**
```python
timestamp, src_ip, dst_ip, src_port, dst_port,
protocol,  payload_size, flags, ttl, entropy,
has_tls, has_dns, dns_query,
http_method, http_host, http_uri, user_agent,
is_suspicious, suspicion_reasons, session_id
```

**Detection functions (`detectors.py`):**

| Function | Signal | MITRE | Threshold |
|----------|--------|-------|-----------|
| `detect_high_entropy()` | Shannon entropy > 7.2 on non-TLS port | T1048 | Configurable `ENTROPY_THRESHOLD` |
| `detect_suspicious_port()` | Port in {4444,5555,6666,31337,12345,...} | T1046 | Fixed set |
| `detect_dga()` | Subdomain > 20 chars, vowel ratio < 25% | T1568.002 | Configurable |
| `detect_c2_beacon()` | avg_interval < 60s AND std_dev < 2.0 | T1071.001 | Configurable `BEACON_AVG_INTERVAL_SEC` |
| `detect_cleartext_credentials()` | Payload contains `password=`, `Authorization: Basic` | T1003 | Fixed patterns |
| `detect_ttl_anomaly()` | TTL not in {32, 64, 128, 255} | T1595 | Fixed set |
| `detect_malware_user_agent()` | UA matches known scanner strings | T1595 | Fixed list |
| `detect_external_db_access()` | DB port accessed from non-RFC-1918 IP | T1078 | Port set |

**Severity thresholds (v1.1):**
- 1 detection reason → `HIGH` severity alert
- 2+ detection reasons → `CRITICAL` severity alert

**Session tracking (Redis):**
```
Key: session:{session_id}
Type: list (LPUSH + LTRIM + EXPIRE)
TTL: 3600 seconds
Max length: 100 timestamps
```

---

### 4.2 Traffic Simulator (`src/simulation/`)

**Entry point:** `traffic_simulator.py` — `TrafficSimulator.start()`

**Purpose:** Generate synthetic threat events for testing the AI investigation and SOAR pipeline without real network traffic or Npcap.

**Kafka target:** `threat-alerts` directly — **never writes to `raw-packets`**

**IP pools:**
```python
INTERNAL_IPS = [
    "10.0.0.55",    # Finance workstation
    "10.0.1.23",    # HR laptop
    "10.0.1.45",    # Engineering server
    "10.0.2.88",    # Domain controller
    "10.0.3.12",    # File server
    "172.16.0.5",   # Legacy system
    "192.168.1.50", # Guest network host
]

EXTERNAL_C2_IPS = [
    "185.220.101.47",  # Tor exit node
    "91.108.4.168",    # Known botnet C2
    "45.142.212.100",  # Cobalt Strike C2
    # ... (8 total)
]
```

**Scenario weights:**
```python
SCENARIOS = [
    (scenario_c2_beacon,              weight=5),   # CRITICAL
    (scenario_data_exfiltration,      weight=4),   # HIGH
    (scenario_reverse_shell,          weight=4),   # CRITICAL
    (scenario_exploit_public_app,     weight=4),   # CRITICAL
    (scenario_lateral_movement,       weight=3),   # HIGH
    (scenario_port_scan,              weight=3),   # MEDIUM
    (scenario_dns_tunneling,          weight=3),   # HIGH
    (scenario_brute_force_ssh,        weight=3),   # HIGH
    (scenario_rdp_lateral_movement,   weight=3),   # HIGH
    (scenario_high_entropy_payload,   weight=3),   # HIGH
    (scenario_protocol_tunneling,     weight=2),   # HIGH
    (scenario_credential_spray,       weight=3),   # HIGH
]
```

**Configuration:**
```
SIMULATION_RATE env var: events per minute (default: 2)
interval_sec = 60 / EVENTS_PER_MINUTE
```

---

### 4.3 RLM Engine (`src/models/`)

**Entry point:** `rlm_engine.py` — `RLMEngine.start()`

**Kafka consumer:** `raw-packets` topic ONLY — does not consume `threat-alerts`

**BehaviorProfile EMA update formula:**
```
new_value = (1 − α) × old_value + α × observation
α = 0.1 (default, configurable via RLM_ALPHA)
```

**Fields updated per raw packet:**
- `avg_bytes_per_min` — EMA of payload_size
- `avg_entropy` — EMA of payload entropy
- `dominant_protocols` — EMA frequency per protocol string
- `typical_dst_ports` — count per port
- `typical_dst_ips` — count per IP
- `active_hours` — EMA frequency per hour-of-day
- `weekend_ratio` — EMA of is_weekend boolean
- `observation_count` — +1 per packet

**Zero-observation condition:** If a source IP only appears in simulator-generated `threat-alerts` events and never in real `raw-packets`, its `observation_count` stays 0 and all metrics stay 0. This is expected behavior.

**to_text() output (natural language profile for embedding):**
```
Entity 192.168.1.55 (host) behavior: avg 8420 bytes/min,
847.0 packets/min, entropy 7.10. Protocols: TCP(85%), UDP(12%), DNS(3%).
Ports: 443, 80, 53, 8080. Active hours: 9, 10, 11, 14.
Weekend ratio: 2.0%. Anomaly: 0.723. Recent: [...].
```

**Persistence:** Every 300 seconds, all in-memory BehaviorProfiles UPSERT to PostgreSQL `behavior_profiles` table. The `profile_text` column stores the `to_text()` output — this is what the Hosts tab displays as "PROFILE NOTE".

---

### 4.4 MCP Orchestrator (`src/agents/`)

**Entry point:** `mcp_orchestrator.py` — `MCPOrchestrator.start()`

**LLM Abstraction:** All LLM calls go through `src/agents/llm_provider.py`. The `get_provider()` factory reads `LLM_PROVIDER` from env and returns a `ClaudeProvider`, `OpenAIProvider`, or `GeminiProvider` — all implementing the same `LLMProvider` abstract interface.

**Alert routing logic:**
```python
severity = alert.get("severity")
if severity in ("HIGH", "CRITICAL"):
    await investigation_queue.put(alert)  # → AI investigation (1 LLM call)
else:
    await db_conn.execute("INSERT INTO alerts ...", ...)  # direct to DB, no LLM cost
```

**Optimized 1-Call Investigation Pipeline (`InvestigateAgent.investigate()`):**

```python
# Step 1: Gather 4 intel sources in parallel — zero LLM calls
threat_raw, host_raw, rep_raw, recent_raw = await asyncio.gather(
    executor.execute("query_threat_database", {...}),  # ChromaDB top-3
    executor.execute("get_host_profile",     {...}),  # ChromaDB + PostgreSQL
    executor.execute("lookup_ip_reputation", {...}),  # AbuseIPDB (Redis cached)
    executor.execute("get_recent_alerts",    {...}),  # PostgreSQL last 6h
)

# Step 2: Compress each result to 1–3 essential lines
threat_summary = _summarize_result("query_threat_database", threat_raw)
host_summary   = _summarize_result("get_host_profile",      host_raw)
rep_summary    = _summarize_result("lookup_ip_reputation",  rep_raw)
recent_summary = _summarize_result("get_recent_alerts",     recent_raw)

# Step 3: Single LLM call — ~420-480 input tokens + ~183 output tokens = ~553 total
intel_context = f"Alert: {alert_slim_json}\nIntel:\n- Threat DB: {threat_summary}\n..."
response = await llm.chat(
    messages=[{"role": "user", "content": intel_context}],
    tools=None,          # NO tool schemas — biggest token saver
    system=ANALYSIS_SYSTEM_PROMPT,
    max_tokens=1024,
)

# Step 4: Parse JSON verdict → create incident directly (no LLM round-trip)
verdict = json.loads(response.text)
block_recommended = bool(verdict.get("block_recommended")) or verdict.get("severity") == "CRITICAL"
await executor._create_incident({...block_recommended, block_target_ip...})
```

**Token breakdown per investigation:**
| Component | Tokens |
|-----------|--------|
| ANALYSIS_SYSTEM_PROMPT | ~180–220 |
| alert_slim (raw_event stripped) | ~100–150 |
| threat_summary (1 line, 120 chars) | ~25 |
| host_summary (1 line, 100 chars) | ~20 |
| rep_summary (1 line, 120 chars) | ~25 |
| recent_summary (3 lines, 200 chars) | ~50 |
| **Total input** | **~420–480** |
| JSON verdict output | ~183 |
| **Grand total** | **~553** |

**Exponential backoff on rate limits:**
```
429 received → wait 5s → retry
429 again    → wait 15s → retry
429 again    → wait 45s → raise
```

**Block recommendation flow:**
```python
# After creating incident:
if block_recommended:
    logger.info(f"🔔 Block recommendation queued: {block_target_ip} → {incident_id}")
    # (no Redis setex, no firewall_rules insert — waits for analyst approval)
```

**MCP Tool implementations:**

| Tool | Implementation |
|------|---------------|
| `query_threat_database` | `chromadb.collection.query()` — top 3 matches (capped) |
| `get_host_profile` | ChromaDB query by entity_id + PostgreSQL fallback |
| `get_recent_alerts` | PostgreSQL SELECT with severity/IP/hours filters |
| `lookup_ip_reputation` | AbuseIPDB API v2 + Redis 1h cache |
| `block_ip` | Redis SETEX `blocked:{ip}` + PostgreSQL `firewall_rules` INSERT |
| `isolate_host` | Redis SETEX `isolated:{ip}` + PostgreSQL marker |
| `send_notification` | Slack webhook POST + PagerDuty Events API v2 POST |
| `create_incident` | PostgreSQL `incidents` INSERT (includes block_recommended, block_target_ip) |
| `query_packet_history` | TimescaleDB `packets_per_minute` aggregate query |

---

### 4.5 REST API (`src/api/`)

**Entry point:** `gateway.py` — FastAPI app

**Startup sequence:**
1. Create asyncpg connection pool (min 5, max 20)
2. Connect Redis client
3. Connect ChromaDB via `get_chroma_client()` from embedder
4. Create/get threat_signatures collection with governance check
5. Validate JWT_SECRET — raise RuntimeError if empty

**Endpoint specifications (full list):**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Checks postgres, redis, chromadb, llm providers |
| `POST` | `/auth/token` | None | Returns JWT (480-minute expiry) |
| `GET` | `/api/v1/dashboard` | Bearer | 12-field SOC stats from TimescaleDB |
| `GET` | `/api/v1/alerts` | Bearer | Paginated, filterable alerts |
| `POST` | `/api/v1/threat-search` | Bearer | ChromaDB semantic search |
| `GET` | `/api/v1/incidents` | Bearer | Incidents with status/severity filter + block fields |
| `PATCH` | `/api/v1/incidents/{id}` | Bearer (analyst+) | Update status, notes, assignment |
| `GET` | `/api/v1/block-recommendations` | Bearer | Pending block recommendations (OPEN + block_recommended) |
| `POST` | `/api/v1/incidents/{id}/block` | Bearer (responder+) | Approve block: firewall_rules + Redis + RESOLVED |
| `POST` | `/api/v1/incidents/{id}/dismiss` | Bearer (analyst+) | Dismiss recommendation: RESOLVED, no block |
| `GET` | `/api/v1/hosts/{ip}` | Bearer | Nested RLM profile + alert history + block status |

**Host response nesting (important):**

The `/api/v1/hosts/{ip}` response nests all behavioral profile metrics under a `profile` key:
```json
{
  "ip_address": "...",
  "is_blocked": true,
  "block_count": 1,
  "incident_count": 3,
  "profile": {
    "anomaly_score": 0.913,
    "observation_count": 48291,
    "avg_bytes_per_min": 8420.4,
    "avg_entropy": 7.12,
    "profile_text": "Entity 10.0.0.55 (host) behavior..."
  },
  "recent_alerts": [...]
}
```

Frontend must access `hostProfile.profile?.anomaly_score` (not `hostProfile.anomaly_score`). The column in PostgreSQL is `profile_text` (not `note`).

---

### 4.6 Database Schema (`scripts/db/init.sql`)

**Tables:**

| Table | Type | Key Details |
|-------|------|-------------|
| `packets` | TimescaleDB hypertable | Partitioned by day, 30-day retention, compressed after 7 days |
| `alerts` | Regular table | Indexed by timestamp, severity, src_ip, type, mitre_technique |
| `incidents` | Regular table | Status enum: OPEN/INVESTIGATING/RESOLVED/CLOSED; includes block_recommended, block_target_ip |
| `behavior_profiles` | Regular table | Indexed by anomaly_score, entity_type; profile_text column (not `note`) |
| `firewall_rules` | Regular table | Trigger sets `expires_at = created_at + duration_hours * INTERVAL '1 hour'` |
| `threat_intel` | Regular table | Unique on (source, indicator_type, indicator); full-text search index |
| `users` | Regular table | RBAC roles; bcrypt-hashed passwords; default admin/analyst seeded |
| `audit_log` | Regular table | All user actions with timestamp and IP |

**Key `incidents` columns (v1.1 additions):**
```sql
investigation_summary TEXT,           -- AI-generated full summary
block_recommended    BOOLEAN DEFAULT FALSE,  -- AI flagged this for blocking
block_target_ip      TEXT                    -- IP to potentially block
```

**Live migration (for existing deployments):**
```sql
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip TEXT;
```

**Views:**
- `active_threats` — HIGH/CRITICAL alerts in last 24h joined with profiles and incidents
- `soc_summary` — single-row dashboard stats

**Continuous aggregate:**
- `packets_per_minute` — per-IP packet count, byte total, avg entropy per minute bucket (only populated by real DPI, not simulator)

---

### 4.7 n8n SOAR (`n8n/`)

**Bridge routing table (`kafka_bridge.py`):**

| Topic | Condition | Webhook Path |
|-------|-----------|-------------|
| `threat-alerts` | severity == CRITICAL | `/webhook/critical-alert` |
| `threat-alerts` | severity == HIGH | `/webhook/high-alert` |
| `threat-alerts` | severity in (MEDIUM, LOW) | `/webhook/medium-alert` |
| `enriched-alerts` | any | `/webhook/enriched-alert` |
| `incidents` | any | `/webhook/new-incident` |
| `cti-updates` | type == CRITICAL_CVE | `/webhook/critical-cve` |
| `cti-updates` | type == ACTIVE_EXPLOITATION | `/webhook/active-exploitation` |
| `threat-alerts` | type == C2_BEACON_DETECTED | `/webhook/c2-beacon` |

---

## 5. RAG Pipeline Technical Specification

### 5.1 Embedding Model

| Property | Value |
|----------|-------|
| Model name | `all-MiniLM-L6-v2` |
| Dimensionality | 384 |
| Max input tokens | 256 (~900 chars) |
| Compute | CPU (no GPU required) |
| Cost | Free (local inference) |
| Distance metric | Cosine (`hnsw:space: cosine`) |
| Pinning | `SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)` |

### 5.2 ChromaDB Collections

| Collection | Documents | TTL | Populated by |
|-----------|-----------|-----|-------------|
| `threat_signatures` | 8 seed signatures | Never evicted | RLM engine startup |
| `cve_database` | NVD CVEs CVSS ≥ 7.0 | No TTL (upsert by CVE-ID) | CTI scraper every 4h |
| `cti_reports` | CISA, Abuse.ch, MITRE, OTX | 90 days | CTI scraper various schedules |
| `behavior_profiles` | One per IP per hour | 30 days | RLM engine (real DPI only) |

**Important:** `behavior_profiles` collection is only populated when real network packets are captured by the DPI sensor. The traffic simulator does not populate this collection.

---

## 6. Environment Variables Reference

| Variable | Default | Used By |
|----------|---------|---------|
| `LLM_PROVIDER` | `claude` | All services — selects active LLM: `claude` \| `openai` \| `gemini` |
| `ANTHROPIC_API_KEY` | — (required for claude) | mcp-orchestrator |
| `OPENAI_API_KEY` | — (required for openai) | mcp-orchestrator |
| `GOOGLE_API_KEY` | — (required for gemini) | mcp-orchestrator |
| `LLM_MODEL_PRIMARY` | (provider default) | mcp-orchestrator investigation |
| `LLM_MODEL_FAST` | (provider default) | n8n Workflow 03 CVE analysis |
| `LLM_MODEL_ANALYSIS` | (provider default) | n8n Workflows 02 and 05 |
| `LLM_TEMPERATURE` | `0.2` | All LLM calls |
| `INVESTIGATION_INTERVAL_SEC` | `1800` | mcp-orchestrator — min seconds between investigations |
| `SIMULATION_RATE` | `2` | traffic-simulator — events per minute |
| `POSTGRES_PASSWORD` | — (required) | all services |
| `REDIS_PASSWORD` | — (required) | all services |
| `JWT_SECRET` | — (required, min 32 chars) | api-gateway |
| `CHROMA_TOKEN` | — (required) | rlm-engine, api, scraper |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | rlm-engine, scraper, api |
| `MAX_CHUNK_CHARS` | `900` | embedder |
| `CHUNK_OVERLAP_CHARS` | `100` | embedder |
| `EMBED_BATCH_SIZE` | `100` | embedder |
| `EMBED_CACHE_TTL_SEC` | `3600` | embedder, rlm-engine |
| `MITRE_REEMBED_INTERVAL_DAYS` | `7` | scraper |
| `PROFILE_TTL_DAYS` | `30` | rlm-engine |
| `CTI_TTL_DAYS` | `90` | scraper |
| `RLM_ALPHA` | `0.1` | rlm-engine |
| `RLM_ANOMALY_THRESHOLD` | `0.65` | rlm-engine |
| `RLM_THREAT_MATCH_THRESHOLD` | `0.50` | rlm-engine |
| `RLM_MIN_OBSERVATIONS` | `20` | rlm-engine |
| `RLM_CHROMA_N_RESULTS` | `3` | rlm-engine |
| `CAPTURE_INTERFACE` | `eth0` | dpi-sensor |
| `BPF_FILTER` | `ip` | dpi-sensor |
| `BEACON_AVG_INTERVAL_SEC` | `60.0` | dpi-sensor |
| `ENTROPY_THRESHOLD` | `7.2` | dpi-sensor |
| `NVD_API_KEY` | (optional) | scraper |
| `ABUSEIPDB_KEY` | (optional) | mcp-orchestrator |
| `OTX_API_KEY` | (optional) | scraper |
| `SLACK_WEBHOOK` | (optional) | mcp-orchestrator, n8n |
| `PAGERDUTY_KEY` | (optional) | mcp-orchestrator, n8n |

---

## 7. Testing

### 7.1 Unit Tests (no Docker required)

```bash
pip install pytest
pytest tests/unit/ -v
```

**Coverage:**
- `test_detectors.py` — 27 tests across 9 detector functions
- `test_profile.py` — 5 tests for BehaviorProfile EMA logic

### 7.2 Integration Tests (requires running stack)

```bash
pytest tests/integration/ -v --tb=short
```

**Coverage:**
- `test_api.py` — health check, JWT auth, dashboard endpoint

### 7.3 Manual Validation Checklist

```bash
# 1. All containers healthy
docker compose ps

# 2. API health (check LLM provider active)
curl http://localhost:8080/health

# 3. Auth
curl -X POST http://localhost:8080/auth/token \
  -d "username=admin&password=cybersentinel2025"

# 4. Dashboard
curl -H "Authorization: Bearer {token}" http://localhost:8080/api/v1/dashboard

# 5. Block recommendations (after running simulator)
curl -H "Authorization: Bearer {token}" http://localhost:8080/api/v1/block-recommendations

# 6. Host profile (will show zeros if simulator-only)
curl -H "Authorization: Bearer {token}" http://localhost:8080/api/v1/hosts/172.16.0.5

# 7. Simulator logs
docker compose logs traffic-simulator --tail=20

# 8. MCP orchestrator logs (check "1 LLM call")
docker compose logs mcp-orchestrator --tail=50
```

---

*Technical Requirements Document — CyberSentinel AI v1.1 — 2025/2026*
