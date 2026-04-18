# CyberSentinel AI

**Autonomous Threat Intelligence & Zero-Day Detection Platform**

Enterprise-grade, AI-powered SOC platform combining Deep Packet Inspection, Recursive Language Model (RLM) behavioral profiling, IsolationForest sequence anomaly detection, and AI-driven autonomous investigation with a human-in-the-loop response workflow. Deployed as **14 Docker containers** with a single command.

---

## What It Does

```mermaid
graph LR
    A[Network Traffic] --> B[DPI Sensor]
    B --> C[Kafka]
    C --> D[RLM Engine]
    D --> E[ChromaDB]
    E --> F[MCP Orchestrator]
    F --> G[AI Investigation]
    G --> H[SOC Dashboard]
    H --> I[Analyst Decision]
    I --> J[Block / Dismiss]
```

| Problem | Industry Average | CyberSentinel AI |
|---------|-----------------|-----------------|
| Breach detection time | 194 days | < 1 second |
| Alert triage | Manual | Autonomous AI |
| Incident creation | Hours to days | 15–45 seconds, 1 LLM call |
| CVE awareness | Manual monitoring | Automated every 4 hours |
| Block decisions | Ad-hoc | Human-in-the-loop review |

---

## System Architecture

```mermaid
graph TB
    subgraph INGESTION["Layer 1 — Ingestion"]
        DPI[DPI Sensor<br/>Scapy + libpcap<br/>IPv4 + IPv6]
        SIM[Traffic Simulator<br/>17 threat scenarios]
        CTI[CTI Scraper<br/>NVD · CISA · MITRE · OTX]
    end

    subgraph INTELLIGENCE["Layer 2 — Intelligence"]
        KAFKA[Kafka Event Bus<br/>raw-packets · threat-alerts]
        RLM[RLM Engine<br/>EMA Profiles + IsolationForest]
        CHROMA[ChromaDB<br/>all-MiniLM-L6-v2 embeddings]
    end

    subgraph ORCHESTRATION["Layer 3 — Orchestration"]
        MCP[MCP Orchestrator<br/>1-call AI investigation]
        N8N[n8n SOAR<br/>5 automation workflows]
    end

    subgraph DELIVERY["Layer 4 — Delivery"]
        API[FastAPI Gateway<br/>JWT + RBAC]
        DASH[React Dashboard<br/>6 tabs]
        GRAF[Grafana + Prometheus<br/>Observability]
    end

    subgraph DATA["Persistence"]
        PG[(PostgreSQL<br/>incidents · alerts · campaigns)]
        REDIS[(Redis<br/>cache · blocks · sessions)]
    end

    DPI --> KAFKA
    SIM --> KAFKA
    CTI --> CHROMA
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

## Two Input Modes

### Mode 1 — Real DPI (Production)

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant DPI as DPI Sensor
    participant K as Kafka raw-packets
    participant RLM as RLM Engine
    participant TA as Kafka threat-alerts
    participant MCP as MCP Orchestrator
    participant DB as PostgreSQL

    NIC->>DPI: IPv4/IPv6 packets
    DPI->>DPI: PII masking _mask_pii()
    DPI->>K: PacketEvent JSON
    K->>RLM: consume packet
    RLM->>RLM: EMA profile update
    RLM->>RLM: IsolationForest blend
    RLM->>TA: anomaly alert if score > 0.65
    TA->>MCP: consume alert
    MCP->>MCP: 1-call AI investigation
    MCP->>DB: create_incident()
    MCP->>DB: _correlate_campaign()
```

### Mode 2 — Traffic Simulator (Testing & Demo)

```mermaid
sequenceDiagram
    participant SIM as Traffic Simulator
    participant K as Kafka raw-packets
    participant RLM as RLM Engine
    participant TA as Kafka threat-alerts
    participant MCP as MCP Orchestrator

    SIM->>SIM: pick weighted scenario
    SIM->>K: burst 30-150 PacketEvents
    K->>RLM: same pipeline as real DPI
    RLM->>TA: anomaly alert if score > 0.65
    TA->>MCP: investigate or create pending incident
```

Both modes are **identical from the Kafka layer onwards** — the simulator is not a shortcut, it exercises the full RLM + AI stack.

---

## Quick Start

### Prerequisites

- Docker Desktop 24.0+ with 16 GB RAM allocated
- One LLM API key: `OPENAI_API_KEY` (recommended) or `ANTHROPIC_API_KEY` or `GOOGLE_API_KEY`

### 1. Configure

```bash
cp .env.example .env
# Edit .env — set LLM_PROVIDER=openai and your OPENAI_API_KEY
```

### 2. Start all 14 services

```bash
docker compose up -d

# Wait for Kafka to be healthy (~2-3 minutes)
docker compose ps
```

### 3. Run DB migrations (first time only)

```bash
docker exec -i cybersentinel-postgres psql -U sentinel -d cybersentinel < scripts/db/migrate_campaigns.sql
docker exec -i cybersentinel-postgres psql -U sentinel -d cybersentinel < scripts/db/migrate_multitenancy.sql
```

### 4. Start n8n SOAR

```powershell
.\scripts\start_n8n.ps1
```

### 5. Open the dashboard

| Service | URL | Credentials |
|---------|-----|-------------|
| SOC Dashboard | http://localhost:5173 | admin / cybersentinel2025 |
| API Swagger | http://localhost:8080/docs | admin / cybersentinel2025 |
| n8n SOAR | http://localhost:5678 | admin / see `.env` |
| Grafana | http://localhost:3001 | admin / admin2025 |
| Prometheus | http://localhost:9090 | none |

> See `docs/RUNNING.md` for the full start/stop guide and troubleshooting.

---

## SOC Dashboard — 6 Tabs

| Tab | Purpose |
|-----|---------|
| OVERVIEW | Risk gauge, metric cards, 24h alert timeline, platform health |
| ALERTS | Alert table — severity badges, anomaly score bars, MITRE tags |
| INCIDENTS | Incident lifecycle — OPEN / INVESTIGATING / RESOLVED / CLOSED |
| RESPONSE | Human-in-the-loop: Block Recommendations, Active Incidents, Firewall Rules |
| THREAT INTEL | ChromaDB semantic search + MITRE coverage map + CTI source status |
| HOSTS | RLM behavioral profile lookup — anomaly score, entropy, kill chain |

---

## AI Investigation Pipeline

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
    I --> K[_correlate_campaign\nkill chain tracking]
    J --> L{block_recommended?}
    L -->|Yes| M[RESPONSE tab\nanalyst reviews]
    L -->|No| N[INCIDENTS tab\nOPEN status]
```

| Metric | Old Agentic Loop | Optimized 1-Call |
|--------|-----------------|-----------------|
| LLM calls / investigation | 3 | **1** |
| Tokens / investigation | ~5,500–7,000 | **~553** |
| Cost (GPT-4o mini) | ~$0.001 | **~$0.000165** |
| Budget runway ($5) | ~5,000 | **~30,000 investigations** |

---

## Anomaly Detection Stack

```mermaid
graph LR
    A[PacketEvent] --> B[EMA Profile Update]
    B --> C[profile.to_text]
    C --> D{Redis cache hit?}
    D -->|Yes| E[reuse last score]
    D -->|No| F[ChromaDB cosine similarity]
    F --> G[base_score 0-1]
    G --> H[IsolationForest blend\n25% weight on score history]
    H --> I[final_score]
    I --> J{score > 0.65?}
    J -->|Yes| K[threat-alerts topic]
    J -->|No| L[continue profiling]
```

The **IsolationForest** layer sits on a 50-observation rolling buffer per IP and detects anomalous *progressions* — a slow ramp like `[0.30, 0.33, 0.37, 0.41, 0.46]` is flagged even though no single value crosses the threshold.

---

## Kill Chain / Campaign Tracking

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
    }

    campaign_incidents {
        text campaign_id FK
        text incident_id FK
    }
```

Every incident is automatically correlated with a campaign via `_correlate_campaign_with_pool()`. Incidents from the same source IP within 24 hours are grouped into the same campaign. The `GET /api/v1/campaigns` endpoint exposes all campaigns ordered by last activity.

---

## Docker Compose Deployment

```mermaid
graph TB
    subgraph DC["Docker Compose — cybersentinel-net (14 containers)"]
        subgraph INFRA["Infrastructure"]
            ZK[zookeeper]
            KF[kafka\nhost:9092]
            PG[postgres\n:5432]
            RD[redis\n:6379]
            CD[chromadb\n:8000]
        end
        subgraph CORE["Core Services"]
            DPI[dpi-sensor\nnetwork_mode: host]
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

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Layer |
|---|---|---|
| C2 Application Layer Protocol | T1071.001 | DPI timing + RLM |
| Network Service Discovery | T1046 | DPI SYN flood |
| Exfiltration over Non-C2 Channel | T1048.003 | RLM volume + entropy |
| Dynamic DNS Resolution (DGA) | T1568.002 | DPI DNS analysis |
| SMB Lateral Movement | T1021.002 | RLM internal patterns |
| RDP Lateral Movement | T1021.001 | DPI + RLM |
| Obfuscated/Packed Payload | T1027 | DPI entropy |
| Protocol Tunneling | T1572 | DPI oversized ICMP/DNS |
| Brute Force — Password Guessing | T1110.001 | DPI rapid auth failure |
| Password Spraying | T1110.003 | DPI low-and-slow |
| Exploit Public-Facing App | T1190 | DPI payload matching |
| Unix Reverse Shell | T1059.004 | DPI suspicious port |
| Proxy / Tor Usage | T1090.003 | CTI exit node IPs |
| Ransomware Staging | T1486 | RLM SMB enumeration |
| Credential Dumping | T1003 | RLM auth spike |

---

## LLM Provider Configuration

Switch providers with one env var — no code changes:

```bash
# .env
LLM_PROVIDER=openai          # claude | openai | gemini
OPENAI_API_KEY=sk-...

LLM_MODEL_PRIMARY=gpt-4o-mini
LLM_TEMPERATURE=0.2
INVESTIGATION_INTERVAL_SEC=1800
```

| Provider | Model | Cost/investigation | Recommendation |
|----------|-------|-------------------|----------------|
| openai | gpt-4o-mini | $0.000165 | Best value |
| claude | claude-sonnet-4-6 | ~$0.0004 | Best quality |
| gemini | gemini-2.5-flash | free tier | Not recommended (content filter) |

---

## Common Commands

```bash
# Check all containers
docker compose ps

# View service logs
docker compose logs -f mcp-orchestrator
docker compose logs -f rlm-engine

# Rebuild and redeploy a service after code change
docker compose up -d --build mcp-orchestrator

# Restart a service
docker compose restart api-gateway

# Full reset (WARNING: deletes all data volumes)
docker compose down -v
docker compose up -d
```

---

## Project Structure

```
cybersentinel-ai/
├── src/
│   ├── core/               # Config, logger, constants
│   ├── dpi/                # DPI sensor — packet capture + PII masking
│   ├── models/             # RLM engine — EMA + IsolationForest
│   ├── agents/             # MCP orchestrator + LLM provider + tools
│   ├── ingestion/          # CTI scraper + RAG embedder
│   ├── simulation/         # Traffic simulator (17 scenarios)
│   └── api/                # FastAPI REST gateway
├── docker/                 # Dockerfiles (one per service)
├── docker-compose.yml      # All 14 services
├── scripts/
│   ├── start_n8n.ps1       # Starts N8N container with correct env vars
│   ├── start_live_dpi.ps1  # Windows DPI with Npcap
│   └── db/                 # SQL migrations (migrate_campaigns.sql, migrate_multitenancy.sql)
├── configs/                # Prometheus + Grafana configs
├── frontend/               # React SOC Dashboard
├── n8n/                    # SOAR workflow JSONs
├── docs/                   # Full documentation
└── .env                    # All secrets and config (gitignored)
```

---

## Key Metrics

- **14** Docker containers (`docker compose up -d`)
- **6** SOC Dashboard tabs
- **5** SOAR workflows (n8n)
- **17** simulated threat scenarios (12 MITRE-mapped + 5 novel)
- **15** MITRE ATT&CK techniques covered
- **5** live CTI sources (NVD, CISA, Abuse.ch, MITRE, OTX)
- **3** LLM providers switchable via single env var
- **1** LLM call per investigation (~553 tokens, ~$0.000165)
- **0** external embedding API calls (fully local, CPU-only)
- **11/16** documented limitations fully fixed

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/RUNNING.md`](docs/RUNNING.md) | Start/stop guide, everyday workflow, troubleshooting |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Deep-dive system design with Mermaid diagrams |
| [`docs/PIPELINES.md`](docs/PIPELINES.md) | DPI vs Simulator pipeline comparison |
| [`docs/DEPLOYMENT_PLAN.md`](docs/DEPLOYMENT_PLAN.md) | Kubernetes deployment guide |
| [`docs/DATABASE.md`](docs/DATABASE.md) | Full schema — all tables, indexes, migrations |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | All REST API endpoints |
| [`docs/CHANGELOG.md`](docs/CHANGELOG.md) | Version history + architectural decisions |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Known limitations + severity |
| [`docs/LIMITATIONS_FIXES.md`](docs/LIMITATIONS_FIXES.md) | Fix audit — what was addressed and how |
| [`docs/TRD.md`](docs/TRD.md) | Technical Requirements Document |
| [`docs/RAG_DESIGN.md`](docs/RAG_DESIGN.md) | RAG pipeline design + governance |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | n8n SOAR workflow specifications |

---

*CyberSentinel AI v1.3.0 — Academic Capstone Project 2025/2026*
