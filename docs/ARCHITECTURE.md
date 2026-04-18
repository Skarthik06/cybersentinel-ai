# System Architecture

**CyberSentinel AI v1.3.0 — Deep Dive Design Document**

---

## 1. Design Principles

Five principles shape every architectural decision:

**1. Event-driven over request-driven.** No service calls another service directly via HTTP in the detection pipeline. All communication flows through Kafka. Any service can restart, scale, or be replaced without affecting others.

**2. Online over offline.** The RLM engine learns from live traffic continuously. There is no training phase, no offline batch job, no labelled dataset dependency. The system improves as it observes more traffic.

**3. Local over cloud for embeddings.** All vector embeddings run on CPU using `all-MiniLM-L6-v2` locally inside Docker containers. Zero embedding API cost, zero latency from external calls, zero data leaving the deployment.

**4. Proportional AI usage.** LLM APIs are expensive. They are called only for HIGH and CRITICAL alerts — the minority that genuinely warrant reasoning. Everything else is handled deterministically by code.

**5. Human-in-the-loop for response actions.** The AI investigates and recommends — but a human analyst approves IP blocks via the RESPONSE tab. This prevents automated false-positive blocking and follows SOAR best practice.

---

## 2. Full System Architecture

```mermaid
graph TB
    subgraph INGESTION["Layer 1 — Ingestion"]
        DPI[DPI Sensor\nScapy AsyncSniffer\nIPv4 + IPv6\nPII Masking]
        SIM[Traffic Simulator\n17 threat scenarios]
        CTI[CTI Scraper\nNVD · CISA · MITRE · OTX · Abuse.ch]
    end

    subgraph INTELLIGENCE["Layer 2 — Intelligence"]
        KAFKA[Kafka Event Bus\nraw-packets · threat-alerts\ncti-updates · incidents]
        RLM[RLM Engine\nEMA Profiles\nChromaDB scoring\nIsolationForest blend]
        CHROMA[ChromaDB\nall-MiniLM-L6-v2 embeddings\n4 collections]
    end

    subgraph ORCHESTRATION["Layer 3 — Orchestration"]
        MCP[MCP Orchestrator\n1-call AI investigation\nCampaign correlation]
        N8N[n8n SOAR\n5 automation workflows]
    end

    subgraph DELIVERY["Layer 4 — Delivery"]
        API[FastAPI Gateway\nJWT + RBAC]
        DASH[React Dashboard\n6 tabs]
        GRAF[Grafana + Prometheus\nObservability]
    end

    subgraph DATA["Persistence"]
        PG[(PostgreSQL\nincidents · alerts · campaigns\nbehavior_profiles · firewall_rules)]
        REDIS[(Redis\ncache · blocks · sessions)]
    end

    DPI --> KAFKA
    SIM --> KAFKA
    CTI --> CHROMA
    CTI --> KAFKA
    KAFKA --> RLM
    RLM --> CHROMA
    RLM --> KAFKA
    KAFKA --> MCP
    KAFKA --> N8N
    MCP --> PG
    MCP --> REDIS
    API --> PG
    API --> REDIS
    API --> CHROMA
    DASH --> API
    GRAF --> PG
```

---

## 3. The Two Input Pipelines

CyberSentinel AI has two completely separate data input paths. Both are **identical from the Kafka layer onwards**.

### Pipeline 1 — Real DPI (Production)

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant DPI as DPI Sensor
    participant PII as PII Masker
    participant K as Kafka raw-packets
    participant RLM as RLM Engine
    participant IF as IsolationForest
    participant TA as Kafka threat-alerts
    participant MCP as MCP Orchestrator

    NIC->>DPI: IPv4/IPv6 packets
    DPI->>DPI: Build PacketEvent (21 fields)
    DPI->>PII: _mask_pii() — redact emails + credentials
    PII->>K: PacketEvent JSON (gzip)
    K->>RLM: consume raw-packets
    RLM->>RLM: EMA profile update (alpha=0.1)
    RLM->>RLM: ChromaDB cosine similarity
    RLM->>IF: push score to rolling buffer
    IF->>IF: IsolationForest blend (25% weight)
    IF-->>RLM: blended final_score
    RLM->>TA: alert if final_score > 0.65
    TA->>MCP: consume + investigate
```

### Pipeline 2 — Traffic Simulator (Testing & Demo)

```mermaid
sequenceDiagram
    participant SIM as Traffic Simulator
    participant K as Kafka raw-packets
    participant RLM as RLM Engine
    participant TA as Kafka threat-alerts
    participant MCP as MCP Orchestrator

    SIM->>SIM: weighted scenario selection (17 types)
    SIM->>K: burst 30-150 PacketEvents
    K->>RLM: SAME pipeline as real DPI
    RLM->>TA: alert if score > 0.65
    TA->>MCP: investigate or create pending incident
```

Both pipelines produce identical alert and incident records from the Kafka layer onwards.

---

## 4. AI Investigation Pipeline

```mermaid
flowchart TD
    A[HIGH or CRITICAL alert received] --> B

    subgraph PARALLEL["Step 1 — Parallel intel gathering (0 LLM calls)"]
        B[asyncio.gather]
        B --> C[query_threat_database\nChromaDB top-3]
        B --> D[get_host_profile\nChromaDB + PostgreSQL]
        B --> E[lookup_ip_reputation\nAbuseIPDB API]
        B --> F[get_recent_alerts\nPostgreSQL last 6h]
    end

    C --> G[_summarize_result\ncompress to 1-3 lines each]
    D --> G
    E --> G
    F --> G

    G --> H["Step 2 — Single LLM call\nmax_tokens=1024 · tools=None\n~553 tokens · $0.000165"]

    H --> I[Parse JSON verdict]
    I --> J[_create_incident\nPostgreSQL]
    I --> K[_correlate_campaign\n24h window per src_ip]
    J --> L{block_recommended?}
    K --> M[(attacker_campaigns)]
    L -->|Yes| N[RESPONSE tab\nanalyst reviews]
    L -->|No| O[INCIDENTS tab\nOPEN status]
```

### Token Efficiency

| Metric | Old Agentic Loop | Optimized 1-Call |
|--------|-----------------|-----------------|
| LLM calls / investigation | 3 | **1** |
| Tokens / investigation | ~5,500–7,000 | **~553** |
| Cost (GPT-4o mini) | ~$0.001 | **~$0.000165** |
| Budget runway ($5) | ~5,000 | **~30,000 investigations** |

---

## 5. Anomaly Detection Stack

```mermaid
graph LR
    A[PacketEvent] --> B[EMA Profile Update\nalpha=0.1]
    B --> C[profile.to_text\nnatural language]
    C --> D{Redis cache hit?\nSHA-256 key}
    D -->|Yes| E[reuse last score]
    D -->|No| F[ChromaDB\ncosine similarity]
    F --> G[base_score 0-1]
    G --> H[IsolationForest blend\n25% weight\n50-obs rolling buffer]
    H --> I[final_score]
    I --> J{score > 0.65?}
    J -->|Yes| K[threat-alerts topic]
    J -->|No| L[continue profiling]
    E --> J
```

**IsolationForest layer:** sits on a 50-observation rolling buffer per IP and detects anomalous *progressions* — a slow ramp like `[0.30, 0.33, 0.37, 0.41, 0.46]` is flagged even though no single value crosses the threshold. Requires at least 10 observations before blending begins.

---

## 6. Kill Chain / Campaign Tracking

```mermaid
erDiagram
    incidents ||--o{ campaign_incidents : linked_to
    attacker_campaigns ||--|{ campaign_incidents : contains

    attacker_campaigns {
        text campaign_id PK
        text src_ip
        timestamptz first_seen
        timestamptz last_seen
        int incident_count
        text max_severity
        text[] mitre_stages
        text campaign_summary
    }

    campaign_incidents {
        text campaign_id FK
        text incident_id FK
    }
```

Every incident is automatically correlated with a campaign via `_correlate_campaign_with_pool()`. Incidents from the same source IP within 24 hours are grouped into the same campaign. The `GET /api/v1/campaigns` endpoint exposes all campaigns ordered by last activity.

---

## 7. Authentication and Authorization

```mermaid
sequenceDiagram
    participant C as Client
    participant API as FastAPI Gateway
    participant PG as PostgreSQL
    participant JWT as JWT Engine

    C->>API: POST /auth/token\nusername + password
    API->>PG: SELECT password_hash FROM users
    PG-->>API: hash
    API->>API: passlib.verify(password, hash)\nbcrypt work factor 12
    API->>JWT: encode(sub, role, exp=+480min)\nHS256 + JWT_SECRET
    JWT-->>C: Bearer token

    C->>API: GET /api/v1/dashboard\nAuthorization: Bearer token
    API->>JWT: decode + validate signature + expiry
    JWT-->>API: username, role
    API-->>C: 200 dashboard data
```

### Access Control

The current deployment uses a single `admin` account. All authenticated endpoints are accessible with the admin JWT token. The `users` table schema includes a `role` column (`admin`, `analyst`, `responder`, `viewer`) for future multi-user expansion, but role-based access differentiation is not enforced in the current API implementation.

---

## 8. State Management

| State Type | Store | Rationale |
|-----------|-------|-----------|
| Raw packets (time-series) | TimescaleDB hypertable | O(1) time-range queries via chunk exclusion |
| Alerts + incidents | PostgreSQL | Relational queries, status joins |
| Campaign tracking | PostgreSQL `attacker_campaigns` | 24h correlation window, kill chain grouping |
| Block recommendations | PostgreSQL `incidents` | Persisted until analyst acts |
| Behavioral profiles (persistent) | PostgreSQL `behavior_profiles` | UPSERT by entity_id |
| Behavioral profiles (live) | Python dict in RLM process | Microsecond access for per-packet EMA |
| Firewall block rules | Redis `blocked:{ip}` + PostgreSQL `firewall_rules` | Redis: hot-path lookup; PostgreSQL: persistence |
| Session timing windows | Redis list `session:{id}` | Sliding window for C2 beacon detection |
| Embedding cache | Redis `embed_cache:{sha256}` | Prevent redundant ChromaDB queries |
| MITRE re-embed guard | Redis `reembed_guard:mitre_attack` | Rate-limit static source re-embedding |
| n8n dedup | Redis `n8n_dedup:{sha256}` | Prevent duplicate workflow triggers |
| Threat signatures | ChromaDB `threat_signatures` | Semantic similarity lookup — never evicted |
| CTI reports | ChromaDB `cti_reports` | 90-day TTL |
| CVE database | ChromaDB `cve_database` | Upsert by CVE-ID, no eviction |
| Behavioral profile vectors | ChromaDB `behavior_profiles` | 30-day TTL |
| User accounts | PostgreSQL `users` | RBAC, bcrypt-hashed passwords |
| Audit log | PostgreSQL `audit_log` | Compliance, forensics |

---

## 9. Docker Compose Deployment Architecture

```mermaid
graph TB
    subgraph DC["Docker Compose — cybersentinel-net (14 containers)"]
        subgraph INFRA["Infrastructure"]
            ZK[zookeeper]
            KF[kafka\nhost:9092 / internal:29092]
            PG[postgres\n:5432]
            RD[redis\n:6379]
            CD[chromadb\n:8000]
        end
        subgraph CORE["Core Services"]
            DPI[dpi-sensor\nnetwork_mode: host\nNET_ADMIN + NET_RAW]
            RLM[rlm-engine]
            SCR[threat-intel-scraper]
            MCP[mcp-orchestrator\n:3000]
            API[api-gateway\n:8080]
            SIM[traffic-simulator]
        end
        subgraph DELIVERY["Delivery"]
            FE[frontend\n:5173]
            PR[prometheus\n:9090]
            GR[grafana\n:3001]
        end
    end

    N8N[N8N standalone\n:5678] -->|host.docker.internal:8080| API
```

Data survives container restarts because all state lives in named Docker volumes: `postgres_data`, `redis_data`, `kafka_data`, `chromadb_data`, `grafana_data`.

**Kafka permanent restart fix:** When ZooKeeper regenerates a new cluster ID, Kafka's stored `meta.properties` can contain the old ID causing `InconsistentClusterIdException`. Fix: `docker compose stop kafka zookeeper && docker volume rm cybersentinel-ai_kafka_data && docker compose up -d`. The `docker-compose.yml` kafka service also runs a ZooKeeper broker registration cleanup before starting to prevent stale registrations.

---

## 10. Security Architecture

### Secret Management

All secrets are injected via the `.env` file at the repo root. Docker Compose passes them as environment variables to each container. No secret is hardcoded in any source file or Docker image. The API gateway raises `RuntimeError` at startup if `JWT_SECRET` is empty — the service refuses to run without it.

### PII Masking

The DPI sensor calls `_mask_pii()` on every `PacketEvent` before publishing to Kafka. This redacts:
- Email addresses in `dns_query`, `http_uri`, `user_agent` → `[email-redacted]`
- Credential parameters (`password=`, `token=`, `api_key=`, etc.) → `param=[redacted]`

No PII reaches Kafka, PostgreSQL, or the LLM prompt.

### Network Isolation

All services communicate on the `cybersentinel-net` Docker bridge network. Only these ports are exposed to the host:

| Service | External Port | Notes |
|---------|--------------|-------|
| Frontend | 5173 | React SOC Dashboard |
| API Gateway | 8080 | FastAPI + Swagger |
| Grafana | 3001 | Metrics dashboards |
| Prometheus | 9090 | Metrics scraping |
| n8n | 5678 | Standalone container |
| Kafka | 9092 | External client access |

---

## 11. Failure Modes and Mitigations

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| Kafka restart — cluster ID mismatch | Broker crashes | `docker volume rm cybersentinel-ai_kafka_data` + restart removes stale meta.properties |
| Kafka broker down | Alert pipeline pauses | Consumer group offsets saved — no data loss on restart |
| ChromaDB unavailable | RLM scoring pauses | Embedding cache means last known anomaly score continues to gate alerts |
| LLM API rate limit (429) | Investigation delayed | Exponential backoff: 5s → 15s → 45s |
| PostgreSQL down | API returns 503 | asyncpg pool with timeout; health endpoint reports degraded |
| Redis down | Blocking decisions fall back to DB | All critical state also in PostgreSQL |
| n8n unavailable | SOAR workflows don't trigger | Bridge retries 3 times; events still in Kafka for replay |
| DPI sensor exits | No new packet capture | Docker Compose `restart: always` policy; simulator can continue test events |
| IsolationForest cold start | No blend for first 10 obs | `SequenceAnomalyDetector` returns raw ChromaDB score until 10 samples collected |

---

## 12. Scalability Design

```mermaid
graph TB
    subgraph SCALE["Horizontal Scaling Paths"]
        DPI_S[DPI Sensor\nDocker Compose — one container per host]
        RLM_S[RLM Engine\nAdd consumers to consumer group\nKafka auto-rebalances]
        MCP_S[MCP Orchestrator\nAdd consumers\nrate-limited by LLM API]
        API_S[FastAPI\nMultiple replicas behind load balancer\ncurrent: 1 container]
        PG_S[PostgreSQL\nRead replicas for API queries\nprimary for writes]
        RD_S[Redis\nRedis Cluster for HA]
        CD_S[ChromaDB\nDistributed mode for >10M vectors]
    end
```

---

## 13. Data Retention Policy

| Data | Retention | Mechanism |
|------|-----------|-----------|
| Raw packets | 30 days | TimescaleDB `add_retention_policy` drops partitions |
| Packet compression | After 7 days | `add_compression_policy` — 90%+ storage reduction |
| Alerts | Indefinite | Manual cleanup via API |
| Incidents | Indefinite | Manual archival |
| Campaigns | Indefinite | Grouped by src_ip + 24h window |
| ChromaDB behavior_profiles | 30 days | `evict_stale_profiles()` in RLM persist cycle |
| ChromaDB cti_reports | 90 days | `evict_stale_profiles()` in scraper cycle |
| Redis session windows | 1 hour | `EXPIRE` on each LPUSH |
| Redis embedding cache | 1 hour | `SETEX EMBED_CACHE_TTL_SEC` |
| Redis block rules | 24 hours default | `SETEX blocked:{ip} 86400` |
| Audit log | Indefinite | Manual archival |

---

*Architecture Document — CyberSentinel AI v1.3.0 — 2025/2026*
