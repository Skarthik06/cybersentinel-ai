# System Architecture

**CyberSentinel AI — Deep Dive Design Document**

---

## 1. Design Principles

The architecture is built on five principles that shape every decision:

**1. Event-driven over request-driven.** No service calls another service directly via HTTP in the detection pipeline. All communication flows through Kafka. This means any service can restart, scale, or be replaced without affecting others.

**2. Online over offline.** The RLM engine learns from live traffic continuously. There is no training phase, no offline batch job, no labelled dataset dependency. The system improves as it observes more traffic.

**3. Local over cloud for embeddings.** All vector embeddings run on CPU using all-MiniLM-L6-v2 locally inside Docker. Zero embedding API cost, zero latency from external calls, zero data leaving the deployment.

**4. Proportional AI usage.** LLM APIs are expensive. They are called only for HIGH and CRITICAL alerts — the minority that genuinely warrant reasoning. Everything else is handled deterministically by code.

**5. Human-in-the-loop for response actions.** The AI investigates and recommends — but a human analyst approves IP blocks via the RESPONSE tab. This prevents automated false-positive blocking and follows SOAR best practice.

---

## 2. The Two Input Pipelines

CyberSentinel AI has **two completely separate data input paths**. Understanding the difference is critical for interpreting dashboard data.

### Pipeline 1 — Real DPI Path (Production)

This is the full platform operating on real network traffic.

```
Real Network Traffic (physical or virtual NIC)
    │
    ▼ src/dpi/sensor.py  (Scapy AsyncSniffer, BPF filter)
    │
    ├── Per-packet analysis (PacketEvent dataclass):
    │   ├── Shannon entropy of raw payload bytes
    │   ├── TLS layer detection (has_tls)
    │   ├── DNS query extraction (dns_query)
    │   ├── HTTP method/host/URI parsing
    │   ├── TTL, flags, payload_size, protocol
    │   └── Bidirectional session fingerprint (session_id)
    │
    ├──► Kafka: "raw-packets"   (ALL packets → RLM engine)
    │
    └──► Kafka: "threat-alerts" (suspicious packets only → MCP orchestrator)
         │ (immediate alert: port 4444, high entropy, DGA, C2 timing, etc.)
         │
    ▼ rlm_engine._consume_packets()
    │
    ├── EMA-update BehaviorProfile for src_ip:
    │   ├── avg_bytes_per_min    +1 per packet
    │   ├── avg_entropy          +1 per packet
    │   ├── avg_packets_per_min  +1 per packet
    │   ├── dominant_protocols   frequency table
    │   ├── typical_dst_ports    frequency table
    │   └── observation_count    +1 per packet
    │
    ├── profile.to_text() → natural language string
    ├── ChromaDB cosine similarity vs 8 threat signatures
    └── if score > threshold → Kafka: "threat-alerts"
         │
    RESULT: behavior_profiles table ← POPULATED with real metrics
            anomaly_score, avg_bytes_per_min, avg_entropy,
            observation_count all reflect real traffic
```

### Pipeline 2 — Traffic Simulator Path (Testing & Demo)

> **v1.2 update:** The simulator now feeds the full DPI pipeline via `raw-packets`. Behavioral profiles are built by the RLM engine for all simulated IPs.

```
src/simulation/traffic_simulator.py
    │
    ├── 17 scenario functions (12 MITRE-mapped + 5 unknown novel threats):
    │   ├── scenario_c2_beacon()              → CRITICAL   (burst ~60 pkts)
    │   ├── scenario_reverse_shell()          → CRITICAL   (burst ~45 pkts)
    │   ├── scenario_exploit_public_app()     → CRITICAL   (burst ~30 pkts)
    │   ├── scenario_data_exfiltration()      → HIGH       (burst ~80 pkts)
    │   ├── scenario_lateral_movement()       → HIGH       (burst ~50 pkts)
    │   ├── scenario_dns_tunneling()          → HIGH       (burst ~100 pkts)
    │   ├── scenario_brute_force_ssh()        → HIGH       (burst ~120 pkts)
    │   ├── scenario_rdp_lateral_movement()   → HIGH       (burst ~45 pkts)
    │   ├── scenario_high_entropy_payload()   → HIGH       (burst ~40 pkts)
    │   ├── scenario_protocol_tunneling()     → HIGH       (burst ~60 pkts)
    │   ├── scenario_credential_spray()       → HIGH       (burst ~90 pkts)
    │   ├── scenario_port_scan()              → MEDIUM     (burst ~150 pkts)
    │   ├── POLYMORPHIC_BEACON                → HIGH       (unknown, no MITRE)
    │   ├── COVERT_STORAGE_CHANNEL            → HIGH       (unknown, no MITRE)
    │   ├── SLOW_DRIP_EXFIL                   → HIGH       (unknown, no MITRE)
    │   ├── MESH_C2_RELAY                     → CRITICAL   (unknown, no MITRE)
    │   └── SYNTHETIC_IDLE_TRAFFIC            → MEDIUM     (unknown, no MITRE)
    │
    ▼ Kafka: "raw-packets"   ← burst of 30–150 PacketEvent dicts per scenario
    │
    ▼ rlm_engine._consume_packets()   ← SAME pipeline as real DPI
    │   └── EMA profiling, ChromaDB scoring, anomaly detection
    │
    ▼ Kafka: "threat-alerts"   ← only when anomaly_score > 0.40
    │
    ▼ mcp_orchestrator._consume_alerts()
    │
    RESULT: alerts table ← POPULATED
            incidents table ← POPULATED
            behavior_profiles table ← POPULATED (real EMA values)
            packets table ← POPULATED (partial — PacketEvent, not raw bytes)
            ChromaDB behavior_profiles ← POPULATED
```

### Pipeline Comparison (v1.2)

| Data | Real DPI | Simulator (v1.2) |
|------|----------|-----------------|
| `alerts` table | Yes | Yes |
| `incidents` table | Yes | Yes |
| `firewall_rules` table | Yes | Yes (via block recommendations) |
| `packets` table | Yes (every real packet) | Yes (PacketEvent bursts) |
| `behavior_profiles.observation_count` | Yes (real packet count) | Yes (burst count: 30–150) |
| `behavior_profiles.avg_bytes_per_min` | Yes (real EMA) | Yes (scenario-realistic EMA) |
| `behavior_profiles.avg_entropy` | Yes (real EMA) | Yes (scenario entropy EMA) |
| `behavior_profiles.anomaly_score` | Yes (ChromaDB computed) | Yes (ChromaDB computed) |
| `packets_per_minute` aggregate | Yes | Yes |
| ChromaDB `behavior_profiles` collection | Yes | Yes |
| Raw packet bytes (pcap level) | Yes | No (no physical NIC) |

---

## 3. The Four Processing Layers

### Layer 1 — Ingestion

Two sources feed the detection pipeline:

**DPI Sensor** runs in host network mode and captures every IP packet using Scapy's `AsyncSniffer` with a BPF filter. For each packet it builds a `PacketEvent` — a 21-field dataclass containing Shannon entropy of the payload, protocol dissection, DNS query, HTTP metadata, TLS presence, and a bidirectional session fingerprint. This event is serialised to JSON and published to Kafka's `raw-packets` topic with gzip compression.

In parallel, suspicious packets also emit immediately to `threat-alerts` — the DPI sensor does not wait for the RLM engine. If port 4444 is the destination, that alert fires instantly.

**CTI Scraper** runs five async scrapers on their own schedules (NVD every 4h, CISA every 6h, Abuse.ch every 1h, MITRE every 7d max, OTX every 2h). Each scraper builds structured text from raw CTI data, chunks it if needed, checks the embedding cache, and upserts into ChromaDB. Critical CVEs additionally publish to Kafka `cti-updates` to trigger the n8n CVE pipeline workflow.

**Traffic Simulator** (optional, for testing) generates synthetic threat scenarios at a configurable rate (default 2/min) and publishes **bursts of 30–150 raw PacketEvent dicts to `raw-packets`** — the same topic the DPI sensor uses. This means every simulated scenario passes through the full RLM profiling pipeline. Used when real packet capture is not available (no Npcap, WSL2, CI environments).

### Layer 2 — Intelligence

**RLM Engine** is the behavioral intelligence core. It maintains one `BehaviorProfile` per IP address in memory. Every packet from `raw-packets` updates that IP's profile using Exponential Moving Average (α=0.1 by default).

After each update, the engine converts the profile to a natural language sentence (`to_text()`), checks whether this exact text has been embedded recently (Redis SHA-256 cache), and if not, queries ChromaDB for cosine similarity against the 8 threat signature vectors.

If similarity exceeds the anomaly threshold (default 0.65), an enriched alert fires to `threat-alerts`. Every 5 minutes, all in-memory profiles are persisted to PostgreSQL. Every 30 minutes, stale ChromaDB profile entries are evicted.

### Layer 3 — Orchestration

Two parallel consumers receive alerts from Kafka:

**MCP Orchestrator** handles the AI reasoning path. It only dequeues HIGH and CRITICAL alerts. For each, it runs the configured LLM provider via the `llm_provider.py` abstraction layer using a **stateless 1-call investigation pipeline**:

```
Step 1: asyncio.gather() — 4 intel tools run in PARALLEL (zero LLM calls)
        ├─ query_threat_database → ChromaDB top-3 matches
        ├─ get_host_profile      → ChromaDB + PostgreSQL
        ├─ lookup_ip_reputation  → AbuseIPDB API (cached in Redis)
        └─ get_recent_alerts     → PostgreSQL last 6h for this IP

Step 2: _summarize_result() — compress each result to 1–3 lines
        (strips verbose raw output, keeps MITRE + confidence signal only)

Step 3: Single LLM call — compact alert + summarized intel → JSON verdict
        max_tokens=1024, tools=None (no tool schema overhead)
        ~420-480 input tokens, ~183 output tokens, total ~553 tokens

Step 4: Parse JSON verdict → _create_incident() directly (no LLM round-trip)
        Stores block_recommended flag → analyst reviews via RESPONSE tab
```

This replaced the old 3-call agentic loop (initial chat → tool round 1 → tool round 2), reducing tokens by ~90% (5,500 → 553 per investigation) and API calls by 67% (3 → 1).

**Block Recommendations (Human-in-the-Loop):** If the AI verdict sets `block_recommended=true` OR the severity is CRITICAL, the incident appears in the RESPONSE tab for analyst review. The analyst clicks BLOCK IP (executes Redis + PostgreSQL) or DISMISS. No automatic blocking occurs — this is the SOAR human-in-the-loop pattern.

**n8n Bridge** handles the automation path. It routes every Kafka event to the correct n8n webhook URL based on severity and event type, with Redis deduplication to prevent the same event from triggering a workflow twice within 60 seconds.

### Layer 4 — Delivery

**FastAPI API** serves the React frontend. It reads from PostgreSQL (historical data), Redis (real-time block/isolation status), and ChromaDB (semantic threat search). All endpoints require JWT authentication except `/health`.

**n8n SOAR** executes the 5 workflow playbooks as JSON graphs editable through the n8n visual canvas.

**React Frontend** is a single-page app at `http://localhost:5173` with 6 tabs:
- **OVERVIEW** — risk gauge, metric cards, alert timeline, platform health
- **ALERTS** — paginated alert table with MITRE tags and anomaly scores
- **INCIDENTS** — full incident lifecycle management
- **RESPONSE** — block recommendations panel (human-in-the-loop)
- **THREAT INTEL** — semantic ChromaDB search + MITRE coverage map
- **HOSTS** — RLM behavioral profile lookup by IP address

---

## 4. State Management

| State Type | Store | Why |
|-----------|-------|-----|
| Raw packets (time-series) | TimescaleDB hypertable | SQL queries, time bucketing, retention policies |
| Alerts + incidents | TimescaleDB / PostgreSQL | Relational queries, status joins |
| Block recommendations | PostgreSQL `incidents` (`block_recommended`, `block_target_ip`) | Persisted until analyst acts |
| Behavioral profiles (persistent) | PostgreSQL `behavior_profiles` | UPSERT by entity_id |
| Behavioral profiles (live) | Python dict in RLM process | Microsecond access for per-packet updates |
| Firewall block rules | Redis `blocked:{ip}` + PostgreSQL `firewall_rules` | Redis: hot-path lookup; PostgreSQL: persistence |
| Session timing windows | Redis list `session:{id}` | Sliding window for C2 beacon detection |
| Embedding cache | Redis `embed_cache:{sha256}` | Prevent redundant ChromaDB queries |
| MITRE re-embed guard | Redis `reembed_guard:mitre_attack` | Rate-limit static source re-embedding |
| n8n dedup | Redis `n8n_dedup:{sha256}` | Prevent duplicate workflow triggers |
| Threat signatures | ChromaDB `threat_signatures` | Semantic similarity lookup — never evicted |
| CTI reports | ChromaDB `cti_reports` | 90-day TTL |
| CVE database | ChromaDB `cve_database` | Upsert by CVE-ID, no eviction |
| Behavioral profiles (vectors) | ChromaDB `behavior_profiles` | 30-day TTL — only populated by real DPI |
| User accounts | PostgreSQL `users` | RBAC, bcrypt-hashed passwords |
| Audit log | PostgreSQL `audit_log` | Compliance, forensics |

---

## 5. Security Architecture

### 5.1 Authentication Chain

```
Client → POST /auth/token (username + password)
    │
    ▼ asyncpg query: SELECT password_hash FROM users WHERE username=$1
    │
    ▼ passlib.verify(password, hash)  ← bcrypt work factor 12
    │
    ▼ jwt.encode({sub, role, exp=+480min}, JWT_SECRET, HS256)
    │
    ▼ Bearer token returned
    │
Client → GET /api/v1/dashboard  Authorization: Bearer {token}
    │
    ▼ jwt.decode(token, JWT_SECRET)  ← validates signature + expiry
    │
    ▼ {username, role} injected into handler via Depends(get_current_user)
```

### 5.2 Role-Based Access

| Role | Read | Create Incidents | Update Incidents | Block IPs | Admin |
|------|------|-----------------|-----------------|-----------|-------|
| viewer | ✅ | ❌ | ❌ | ❌ | ❌ |
| analyst | ✅ | ✅ | ✅ | ❌ | ❌ |
| responder | ✅ | ✅ | ✅ | ✅ | ❌ |
| admin | ✅ | ✅ | ✅ | ✅ | ✅ |

### 5.3 Secret Management

All secrets are injected via environment variables from `.env`. No secret is hardcoded. The API gateway raises `RuntimeError` at startup if `JWT_SECRET` is empty — the service refuses to run without it.

### 5.4 Network Isolation

All containers communicate on the `cybersentinel-ai_cybersentinel-net` bridge network (Docker Compose prefixes the project directory name). Only these ports are exposed to the host: 8080 (API), 5678 (n8n), 3001 (Grafana), 9090 (Prometheus), 9092 (Kafka external), 5432 (PostgreSQL external for admin). Redis, ChromaDB, and Zookeeper are not exposed externally by default.

> **Operational note:** The N8N container is started with `docker run` outside of Docker Compose. It must be explicitly connected to `cybersentinel-ai_cybersentinel-net` to reach `host.docker.internal:8080` (the API gateway). This is handled automatically by `scripts/start_n8n.ps1`.

---

## 6. AI Investigation — Token Optimization Architecture

### The Problem (Old Agentic Loop)

The original investigation used a multi-round agentic loop:
1. **Call 1:** LLM receives full alert + all 9 tool schemas (~800 tokens of JSON) → decides which tools to call
2. **Call 2:** LLM receives full conversation history + raw tool results (uncompressed) → may call more tools
3. **Call 3:** LLM receives everything + additional results → writes final verdict

**Cost per investigation:** ~5,500–7,000 input tokens. Input:Output ratio ~10:1.

### The Solution (Optimized 1-Call Pipeline)

Three key optimizations applied:

**1. `tools=None` on the LLM call** — The old loop sent all 9 MCP tool schemas every call (~800 tokens each × 3 calls = 2,400 wasted tokens). The new pipeline runs all tools in code before the LLM call, so `tools=None` is passed. Savings: ~2,400 tokens/investigation.

**2. `_summarize_result()` compression** — Raw tool results were 300–500 tokens each (full JSON objects, verbose log lines). The summarizer keeps only 1–3 lines of essential facts per tool. Savings: ~1,200 tokens/investigation.

**3. `asyncio.gather()` parallel execution** — All 4 intel tools run simultaneously before any LLM call. Old system triggered tools one at a time inside the LLM loop, compounding context each round.

**4. `alert_slim` stripping** — `raw_event` field removed from alert before sending to LLM. The `raw_event` field duplicates all other fields in the alert JSON. Savings: ~300 tokens/investigation.

**5. `max_tokens=1024`** — Old system used `max_tokens=4096`. The JSON verdict format needs at most ~300 tokens. Savings: prevents output bloat.

### Result

| Metric | Before | After |
|--------|--------|-------|
| API calls/investigation | 3 | **1** |
| Tokens/investigation | ~5,500–7,000 | **~553** |
| Input:Output ratio | ~10:1 | **~2:1** |
| Reduction | — | **~90%** |
| Cost (GPT-4o mini) | ~$0.001 | **~$0.000165** |

A 2:1 input:output ratio is ideal for a structured JSON inference task — the model generates dense useful output per token spent.

---

## 7. Failure Modes and Mitigations

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| Kafka broker down | Alert pipeline pauses | Docker health check restarts; consumer group saves offset — no data loss on restart |
| ChromaDB unavailable | RLM scoring pauses; last score reused | Embedding cache means last known anomaly score continues to gate alerts |
| LLM API rate limit (429) | Investigation delayed | Exponential backoff: 5s → 15s → 45s (3 attempts). With 30-min investigation interval this rarely triggers |
| PostgreSQL down | API returns 503 | Connection pool with timeout; health endpoint reports degraded |
| Redis down | Blocking decisions fall back to DB check | All critical state also in PostgreSQL; Redis is hot-path optimisation |
| n8n unavailable | SOAR workflows don't trigger | Bridge retries 3 times with backoff; events still in Kafka for replay |
| DPI sensor exits | No new packet capture | Docker restart policy: `unless-stopped`; simulator can continue generating test events |
| Traffic simulator only (no DPI) | behavior_profiles metrics are 0 | Expected and correct — RLM needs real packets; simulator tests AI pipeline only |
| Grafana exits code 1 on startup | Observability dashboards unavailable | Remove `GF_INSTALL_PLUGINS` from docker-compose.yml — plugin download to grafana.com fails inside Docker network |
| n8n workflows inactive after import | All webhooks 404, triggers FAILED | Run `scripts/activate_n8n_workflows.py` then `docker restart N8N` — script sets active=1, activeVersionId, and publishes workflow_history |
| n8n LLM calls silently fail | Reports never generated | Recreate N8N container with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` — required for `$env.OPENAI_API_KEY` to work in n8n 2.15+ |
| API trigger returns 500 on long workflows | Frontend shows FAILED for valid runs | Use `httpx.AsyncClient(timeout=90)` and catch `TimeoutException` separately — OpenAI calls take 18–27s |

---

## 8. Scalability Design

### Current (Single-Node Docker Compose)

All services share the same Docker bridge network with no load balancing. Designed for single-machine deployment.

### Horizontal Scaling Path (Kubernetes)

| Service | Scaling Strategy |
|---------|-----------------|
| DPI Sensor | DaemonSet — one pod per network node |
| RLM Engine | Add consumers to `rlm-packet-processor` group — Kafka auto-rebalances |
| MCP Orchestrator | Add consumers to Kafka consumer group — rate-limited by LLM API |
| Traffic Simulator | Single replica (test/demo use only) |
| CTI Scraper | Single replica (idempotent upserts) |
| FastAPI | HorizontalPodAutoscaler on CPU/latency |
| n8n | Single replica (stateful; n8n cluster mode for HA) |
| PostgreSQL | Read replicas for API queries, primary for writes |
| Redis | Redis Cluster for HA |
| ChromaDB | Distributed mode for > 10M vectors |

---

## 9. Data Retention Policy

| Data | Retention | Mechanism |
|------|-----------|-----------|
| Raw packets (TimescaleDB) | 30 days | `add_retention_policy('packets', INTERVAL '30 days')` |
| Packet compression | After 7 days | `add_compression_policy('packets', INTERVAL '7 days')` |
| Alerts | Indefinite (no auto-delete) | Manual cleanup via API or SQL |
| Incidents | Indefinite | Manual archival |
| ChromaDB behavior_profiles | 30 days | `evict_stale_profiles()` in RLM persist cycle |
| ChromaDB cti_reports | 90 days | `evict_stale_profiles()` in scraper daily cycle |
| Redis session windows | 1 hour | `EXPIRE` on each LPUSH |
| Redis embedding cache | 1 hour | `SETEX EMBED_CACHE_TTL_SEC` |
| Redis block rules | Duration hours (default 24h) | `SETEX blocked:{ip} 86400` |
| Redis n8n dedup | 60 seconds | `SETEX n8n_dedup:{hash} 60` |
| Audit log | Indefinite | Manual archival |

---

---

## 10. Operational Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup/install.sh` | First-time setup — builds all 14 Docker containers |
| `scripts/setup/add_n8n.sh` | Adds n8n to the running stack |
| `scripts/setup/reset.sh` | Full reset — wipes all data, rebuilds from scratch |
| `scripts/start_n8n.ps1` | Start N8N with all required env vars; runs activation script; handles fresh setup |
| `scripts/activate_n8n_workflows.py` | Repair n8n workflow activation state in SQLite — fixes inactive/unpublished workflows |

See `docs/N8N_OPERATIONS.md` for the complete N8N operations reference.

---

*Architecture Document — CyberSentinel AI v1.2.2 — 2025/2026*
