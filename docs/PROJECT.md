# 🛡️ CyberSentinel AI

> **Autonomous Threat Intelligence & Zero-Day Detection Platform**
> Enterprise-grade AI-powered Security Operations Centre — detecting, investigating, and recommending responses to cyber threats in under 60 seconds.

---

## What Is This

CyberSentinel AI is a full-stack, production-deployable cybersecurity platform built as an academic capstone project. It combines five cutting-edge disciplines into a single autonomous system:

- **Real-time packet analysis** via Deep Packet Inspection (Scapy)
- **Behavioral AI profiling** via the novel Recursive Language Model (RLM) engine
- **Semantic threat intelligence** via ChromaDB vector embeddings (RAG)
- **Autonomous investigation** via multi-provider AI agents (Claude / GPT-4o / Gemini)
- **Human-in-the-loop SOAR** via Block Recommendations panel + n8n workflows

The platform deploys as 14 Docker containers with a single command.

---

## The Problem It Solves

| Metric | Industry Average | CyberSentinel AI |
|--------|-----------------|-----------------|
| Breach detection time | 194 days | < 1 second |
| Alert triage | Manual by analyst | Autonomous AI (~553 tokens, ~$0.000165) |
| Incident creation | Hours to days | Under 60 seconds |
| False positive rate | ~95% | Reduced via behavioral scoring + human approval |
| CVE awareness | Manual monitoring | Automated, every 4 hours |
| Block decisions | Ad-hoc, no audit trail | Human-in-the-loop, full audit log |

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1 — INGESTION                                            │
│  DPI Sensor (Scapy) ──────────────────────────┐                 │
│  Playwright CTI Scraper (NVD/CISA/MITRE/OTX) ─┼──► Kafka Bus   │
│  Traffic Simulator (17 scenarios → raw-packets) ───┘              │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2 — INTELLIGENCE                                         │
│  RLM Engine ──► EMA Profiles ──► ChromaDB (cosine similarity)  │
│  Embedding: all-MiniLM-L6-v2 (local, zero-cost, pinned)        │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3 — ORCHESTRATION                                        │
│  Kafka Bridge ──► n8n SOAR (5 workflows)                        │
│  MCP Orchestrator ──► 1-call AI investigation (~553 tokens)    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4 — DELIVERY                                             │
│  FastAPI REST ──► React SOC Dashboard (6 tabs)                  │
│  Grafana + Prometheus ──► Observability                         │
│  Slack · Teams · PagerDuty · Jira · ServiceNow · Email         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Critical Architecture Distinction: Two Input Pipelines

The system has two completely separate ways data enters the pipeline:

### Pipeline 1 — Real DPI (Full Platform)
```
Real packets → DPI Sensor → raw-packets (Kafka) → RLM Engine
                           → threat-alerts (Kafka) → MCP Orchestrator
```
Populates: ALL tables including `behavior_profiles` with real metrics.

### Pipeline 2 — Traffic Simulator (Testing & Demo)
```
Burst of 30–150 PacketEvents → raw-packets (Kafka) → RLM Engine
                              → threat-alerts (Kafka) → MCP Orchestrator
```
Populates: **ALL tables** — same as Pipeline 1. v1.2 upgraded the simulator to publish raw `PacketEvent` bursts to `raw-packets`, passing through the full RLM profiling pipeline. Behavioral profiles, anomaly scores, and ChromaDB entries are built for simulated IPs.

The only difference from real DPI: no actual network interface is read (no Npcap required). See `docs/PIPELINES.md` for the complete explanation and `docs/LIVE_DPI_SETUP.md` for how to enable real packet capture.

---

## Repository Structure

```
cybersentinel-ai/
│
├── src/                          # All application source code
│   ├── core/                     # Shared: config, logger, constants
│   ├── dpi/                      # Deep Packet Inspection engine
│   │   ├── sensor.py             # Scapy packet capture
│   │   ├── detectors.py          # 8 standalone detection functions
│   │   └── publisher.py          # Kafka publisher
│   ├── models/                   # RLM behavioral profiling engine
│   │   ├── rlm_engine.py         # Main engine (consumes raw-packets)
│   │   ├── profile.py            # BehaviorProfile EMA dataclass
│   │   └── signatures.py         # 8 MITRE threat signature seeds
│   ├── agents/                   # AI MCP agents (multi-provider)
│   │   ├── mcp_orchestrator.py   # 1-call investigation pipeline
│   │   ├── llm_provider.py       # Claude / OpenAI / Gemini abstraction
│   │   ├── tools.py              # 9 MCP tool JSON schemas
│   │   └── prompts.py            # ANALYSIS_SYSTEM_PROMPT
│   ├── ingestion/                # CTI scraper + RAG embedder
│   │   ├── embedder.py           # Governed ChromaDB embedding layer
│   │   ├── sources.py            # CTI source definitions
│   │   └── threat_intel_scraper.py  # NVD/CISA/Abuse.ch/MITRE/OTX
│   ├── simulation/               # Traffic simulator (test/demo)
│   │   └── traffic_simulator.py  # 17 scenarios → raw-packets (full DPI pipeline)
│   └── api/                      # FastAPI REST gateway
│       ├── gateway.py            # 19 endpoints including block recommendations, firewall, control
│       ├── auth.py               # JWT + RBAC
│       └── schemas.py            # Pydantic models
│
├── docker/                       # One Dockerfile per service
├── n8n/                          # SOAR workflows + Kafka bridge
│   ├── bridge/kafka_bridge.py    # Routes Kafka → n8n webhooks
│   └── workflows/                # 5 n8n workflow JSON files
├── scripts/
│   ├── db/init.sql               # TimescaleDB schema (auto-runs on first start)
│   └── setup/                    # install.sh, add_n8n.sh, reset.sh
├── configs/                      # Prometheus + Grafana configs
├── frontend/                     # React SOC Dashboard (6 tabs)
│   └── src/
│       ├── CyberSentinel_Dashboard.jsx  # 6-tab SOC interface
│       ├── CyberSentinel_Landing.jsx    # Landing page
│       └── App.jsx               # Router + floating view switcher
├── tests/                        # Unit + integration tests
├── docs/                         # All project documentation
│
├── docker-compose.yml            # 14-service stack
├── .env.example                  # All environment variables documented
└── README.md                     # Quick start
```

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
nano .env
# Set: LLM_PROVIDER=openai + OPENAI_API_KEY=sk-...
# Recommended: INVESTIGATION_INTERVAL_SEC=1800 (one investigation per 30min)

# 2. Start backend (14 services)
bash scripts/setup/install.sh

# 3. Add SOAR layer (n8n)
bash scripts/setup/add_n8n.sh

# 4. Start frontend
cd frontend && npm install && npm run dev

# 5. Import n8n workflows
# Open http://localhost:5678 → import all 5 files from n8n/workflows/
```

**Services after startup:**

| Service | URL | Credentials |
|---------|-----|-------------|
| SOC Dashboard | http://localhost:5173 | — |
| API (Swagger) | http://localhost:8080/docs | admin / cybersentinel2025 |
| n8n SOAR | http://localhost:5678 | admin / see `.env` |
| Grafana | http://localhost:3001 | admin / admin2025 |
| Prometheus | http://localhost:9090 | none |

---

## SOC Dashboard — 6 Tabs

| Tab | Key Features |
|-----|-------------|
| OVERVIEW | Risk gauge (0–100%), 6 KPI cards, 24h alert timeline, platform health |
| ALERTS | Table: severity badges, anomaly score bars, MITRE tags, investigation summaries |
| INCIDENTS | Lifecycle: OPEN → INVESTIGATING → RESOLVED → CLOSED; drawer with full detail |
| RESPONSE | Human-in-the-loop: Block Recommendations + Active Incidents + Firewall Rules (UNBLOCK) |
| THREAT INTEL | ChromaDB semantic search; MITRE ATT&CK coverage map; CTI source status |
| HOSTS | IP lookup: behavioral profile (real DPI only), block status, incidents, alerts |

---

## Documents in This Project

| Document | Purpose |
|----------|---------|
| [`PROJECT.md`](PROJECT.md) | This file — master overview |
| [`PRD.md`](PRD.md) | Product Requirements Document |
| [`TRD.md`](TRD.md) | Technical Requirements Document |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Deep-dive system design + token optimization |
| [`PIPELINES.md`](PIPELINES.md) | **DPI vs Simulator pipeline comparison (read this)** |
| [`LIVE_DPI_SETUP.md`](LIVE_DPI_SETUP.md) | Npcap installation + Start Live DPI.bat guide |
| [`RAG_DESIGN.md`](RAG_DESIGN.md) | RAG pipeline design + governance |
| [`API_REFERENCE.md`](API_REFERENCE.md) | All REST API endpoints including block recommendations |
| [`WORKFLOWS.md`](WORKFLOWS.md) | n8n SOAR workflow specs |
| [`N8N_OPERATIONS.md`](N8N_OPERATIONS.md) | n8n troubleshooting, activation script, fresh-start procedure |
| [`ABBREVIATIONS.md`](ABBREVIATIONS.md) | Complete glossary — all cybersecurity and project abbreviations |
| [`TWR_PRESENTATION.md`](TWR_PRESENTATION.md) | 18-section technical work report for panel presentation |
| [`THREAT_SIGNATURES.md`](THREAT_SIGNATURES.md) | All 19 RLM threat signatures — MITRE mapping, behavioral fingerprints, scoring |
| [`RESOURCES.md`](RESOURCES.md) | 25 research papers across 7 domains |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history + architectural decisions |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup + contribution guide |

---

## Key Metrics

- **14** Docker containers
- **6** SOC Dashboard tabs
- **5** SOAR workflows (n8n)
- **15** MITRE ATT&CK techniques covered
- **17** simulated threat scenarios (12 MITRE-mapped + 5 unknown novel threats)
- **5** live CTI sources (NVD, CISA, Abuse.ch, MITRE, OTX)
- **11+** enterprise integrations (Slack, Teams, PagerDuty, Jira, ServiceNow, Email, Telegram, AbuseIPDB)
- **3** LLM providers (Claude, GPT-4o, Gemini) — switchable via single env var
- **1** LLM API call per investigation
- **~553** tokens per investigation (90% reduction from original design)
- **~$0.000165** per investigation on GPT-4o mini
- **~30,000** investigations on a $5 OpenAI budget
- **0** external embedding API calls (fully local)
- **25** supporting research papers

---

## Research Positioning

This project makes **three novel contributions** to the academic literature:

1. **RLM Behavioral Engine** — Online, unsupervised host profiling via Exponential Moving Average updated recursively per network packet, converted to NLP text, and scored via cosine similarity against threat signature vectors. No training data, no labels, zero-day capable. Populated by both real DPI and the simulator (v1.2+).

2. **Optimized 1-Call LLM SOC Investigation** — AI agents investigate security alerts with a single LLM API call by pre-gathering all evidence in parallel (`asyncio.gather`), compressing it (`_summarize_result`), and sending one structured prompt. 90% token reduction vs traditional agentic loops.

3. **Human-in-the-Loop SOAR Pattern** — AI recommends blocking via `block_recommended` flag stored per incident. Human analyst approves or dismisses via the RESPONSE tab dashboard. Full audit trail in `audit_log`. No automated blocking that could disrupt legitimate services.

---

*CyberSentinel AI v1.2.2 — Capstone Project 2025/2026*
