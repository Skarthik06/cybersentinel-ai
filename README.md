# 🛡️ CyberSentinel AI

**Autonomous Threat Intelligence & Zero-Day Detection Platform**

Enterprise-grade, AI-powered SOC platform combining Deep Packet Inspection, Recursive Language Model (RLM) behavioral profiling, and AI-driven autonomous investigation with a human-in-the-loop response workflow.

---

## What Is This

CyberSentinel AI is a full-stack, production-deployable cybersecurity platform built as an academic capstone project. It combines five disciplines into a single autonomous system:

- **Real-time packet analysis** via Deep Packet Inspection (Scapy)
- **Behavioral AI profiling** via the Recursive Language Model (RLM) engine
- **Semantic threat intelligence** via ChromaDB vector embeddings (RAG)
- **Autonomous investigation** via AI agents (Claude / GPT-4o / Gemini, switchable)
- **Human-in-the-loop SOAR** via Block Recommendations panel + n8n workflows

The platform deploys as 14 Docker containers with a single command.

---

## The Problem It Solves

| Metric | Industry Average | CyberSentinel AI |
|--------|-----------------|-----------------|
| Breach detection time | 194 days | < 1 second |
| Alert triage | Manual by analyst | Autonomous AI |
| Incident creation | Hours to days | 15–45 seconds, 1 LLM call |
| False positive rate | ~95% | Reduced via behavioral scoring |
| CVE awareness | Manual monitoring | Automated, every 4 hours |
| Block decisions | Ad-hoc | Human-in-the-loop review panel |

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1 — INGESTION                                            │
│  DPI Sensor (Scapy) ──────────────────────────┐                 │
│  Playwright CTI Scraper (NVD/CISA/MITRE/OTX) ─┼──► Kafka Bus   │
│  Traffic Simulator (synthetic threat events) ──┘                │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2 — INTELLIGENCE                                         │
│  RLM Engine ──► EMA Profiles ──► ChromaDB (cosine similarity)  │
│  Embedding: all-MiniLM-L6-v2 (local, zero-cost, pinned)        │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3 — ORCHESTRATION                                        │
│  Kafka Bridge ──► n8n SOAR (5 workflows)                        │
│  MCP Orchestrator ──► 1-call AI investigation (optimized)      │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4 — DELIVERY                                             │
│  FastAPI REST ──► React SOC Dashboard (6 tabs)                  │
│  Grafana + Prometheus ──► Observability                         │
│  Slack · Teams · PagerDuty · Jira · ServiceNow · Email         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Two Input Modes: Real DPI vs Traffic Simulator

CyberSentinel AI has **two completely separate input paths** that serve different purposes.

### Mode 1 — Real DPI Pipeline (full platform)
```
Real Network Traffic
    │
    ▼ sensor.py (Scapy)                 ← captures actual packets
    │ Shannon entropy, TLS, DNS, HTTP analysis
    ▼ Kafka: "raw-packets"
    │
    ▼ rlm_engine._consume_packets()
    │ EMA behavioral profiling per IP
    │ → behavior_profiles table (populated with real metrics)
    │ → ChromaDB (anomaly scoring)
    ▼ Kafka: "threat-alerts"            ← only if anomaly detected
    │
    ▼ mcp_orchestrator → LLM → incident created
```

### Mode 2 — Traffic Simulator (testing & demo)
```
traffic_simulator.py
    │ Bursts of 30–150 raw PacketEvent dicts per scenario
    ▼ Kafka: "raw-packets"              ← SAME topic as real DPI (v1.2+)
    │
    ▼ rlm_engine._consume_packets()     ← EMA profiling, ChromaDB scoring
    ▼ Kafka: "threat-alerts"            ← only if anomaly detected
    │
    ▼ mcp_orchestrator → LLM → incident created
```

> **v1.2 change:** The simulator was upgraded to publish raw `PacketEvent` dicts to `raw-packets` (full pipeline). It no longer bypasses RLM. Both pipelines are now identical from the Kafka layer onwards.

**What each pipeline populates:**

| Data | Real DPI | Simulator (v1.2) |
|------|----------|-----------------|
| `alerts` table | Yes | Yes |
| `incidents` table | Yes | Yes |
| `packets` table | Yes (every packet) | Yes (scenario burst) |
| `behavior_profiles.observation_count` | Yes (real) | Yes (burst count) |
| `behavior_profiles.avg_bytes_per_min` | Yes (real EMA) | Yes (scenario values) |
| `behavior_profiles.avg_entropy` | Yes (real EMA) | Yes (scenario values) |
| `behavior_profiles.anomaly_score` | Yes (ChromaDB) | Yes (ChromaDB) |
| `packets_per_minute` TimescaleDB view | Yes | Yes |
| ChromaDB `behavior_profiles` collection | Yes | Yes |

Both pipelines are complete. The real DPI pipeline captures genuine packets from your network interface; the simulator generates realistic packet bursts for controlled testing without Npcap.

---

## Quick Start

### Prerequisites
- Docker Desktop with 12+ GB RAM allocated
- One LLM API key: `ANTHROPIC_API_KEY` (Claude) OR `OPENAI_API_KEY` (GPT-4o) OR `GOOGLE_API_KEY` (Gemini)

### 1. Configure
```bash
cp .env.example .env
nano .env
# Required: set LLM_PROVIDER (claude|openai|gemini) + matching API key
# Recommended: LLM_PROVIDER=openai + OPENAI_API_KEY (GPT-4o mini, most cost-efficient)
```

### 2. Launch Backend (14 services)
```bash
bash scripts/setup/install.sh
```

### 3. Add SOAR Automation (n8n)
```bash
bash scripts/setup/add_n8n.sh
# Then open http://localhost:5678 and import all 5 files from n8n/workflows/
```

### 4. Start Frontend
```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### 5. Access Dashboards

| Service | URL | Credentials |
|---------|-----|-------------|
| SOC Dashboard | http://localhost:5173 | — |
| API (Swagger) | http://localhost:8080/docs | Bearer token via `/auth/token` |
| n8n SOAR | http://localhost:5678 | admin / see `.env` |
| Grafana | http://localhost:3001 | admin / admin2025 |
| Prometheus | http://localhost:9090 | none |

**Default API credentials:**
- Username: `admin` / Password: `cybersentinel2025`
- Username: `analyst` / Password: `cybersentinel2025`

---

## Project Structure

```
cybersentinel-ai/
│
├── src/                          # All application source code
│   ├── core/                     # Shared: config, logger, constants
│   ├── dpi/                      # Deep Packet Inspection engine
│   ├── models/                   # RLM behavioral profiling engine
│   ├── agents/                   # AI MCP agents (multi-provider)
│   │   ├── mcp_orchestrator.py   # 1-call investigation pipeline
│   │   ├── llm_provider.py       # Claude / OpenAI / Gemini abstraction
│   │   ├── tools.py              # 9 MCP tool definitions
│   │   └── prompts.py            # System prompts
│   ├── ingestion/                # CTI scraper + RAG embedder
│   ├── simulation/               # Traffic simulator (synthetic threats)
│   │   └── traffic_simulator.py  # 12 threat scenarios, Kafka producer
│   └── api/                      # FastAPI REST gateway
│
├── docker/                       # One Dockerfile per service
├── n8n/                          # SOAR workflows + Kafka bridge
├── scripts/                      # DB schema, setup scripts
├── configs/                      # Prometheus + Grafana configs
├── frontend/                     # React SOC Dashboard (6 tabs)
├── tests/                        # Unit + integration tests
├── docs/                         # Full project documentation
│
├── docker-compose.yml            # 14-service stack
├── .env.example                  # All environment variables documented
└── README.md                     # This file
```

---

## SOC Dashboard — 6 Tabs

The React dashboard at `http://localhost:5173` has six tabs:

| Tab | Purpose |
|-----|---------|
| OVERVIEW | Risk gauge, 6 metric cards, 24h alert timeline, platform health radar |
| ALERTS | Full alert table with severity badges, anomaly score bars, MITRE tags |
| INCIDENTS | Incident registry — OPEN / INVESTIGATING / RESOLVED / CLOSED lifecycle |
| RESPONSE | Human-in-the-loop: Block Recommendations + Active Incidents + Firewall Rules |
| THREAT INTEL | ChromaDB semantic search + MITRE coverage map + CTI source status |
| HOSTS | RLM behavioral profile lookup — anomaly score, entropy, block status, recent alerts |

### RESPONSE Tab (Human-in-the-Loop)

The RESPONSE tab has three panels:

**Block Recommendations** — AI-flagged IPs awaiting analyst decision. Every CRITICAL/HIGH incident with `block_recommended=True` appears here. Analyst clicks **BLOCK IP** (inserts `firewall_rules` row + Redis `blocked:{ip}`) or **DISMISS** (marks incident RESOLVED without action).

**Active Incidents** — All `status='OPEN'` incidents as clickable cards. Expand any incident to see the AI investigation summary, Technical Playbook, and Threat Signature matches.

**Firewall Rules** — Currently blocked IPs from the `firewall_rules` table. Each row has an **UNBLOCK** button that calls `DELETE /api/v1/firewall-rules?ip={ip}` and removes the Redis key.

---

## AI Investigation — Token-Optimized Pipeline

The investigation engine uses a stateless **1-LLM-call pipeline** (not an agentic loop):

```
Alert received
    │
    ▼ asyncio.gather() — 4 intel tools run in PARALLEL (zero LLM calls)
    │ ├─ query_threat_database (ChromaDB)
    │ ├─ get_host_profile (ChromaDB)
    │ ├─ lookup_ip_reputation (AbuseIPDB)
    │ └─ get_recent_alerts (PostgreSQL)
    │
    ▼ _summarize_result() — compress each result to essential facts
    │
    ▼ 1 LLM call — compact context → structured JSON verdict
    │ max_tokens=1024, tools=None (no tool schemas in prompt)
    │
    ▼ Parse JSON → create_incident() directly from code
```

**Token efficiency results:**

| Metric | Old Agentic Loop | Optimized 1-Call |
|--------|-----------------|-----------------|
| LLM API calls per investigation | 3 | **1** |
| Tokens per investigation | ~5,500–7,000 | **~553** |
| Input:Output ratio | ~10:1 | **~2:1** |
| Reduction | — | **~90%** |
| Cost per investigation (GPT-4o mini) | ~$0.001 | **~$0.000165** |
| Budget runway ($5) | ~5,000 investigations | **~30,000 investigations** |

---

## LLM Provider Configuration

Switch providers by changing one environment variable — no code changes:

```bash
# .env
LLM_PROVIDER=openai        # claude | openai | gemini
OPENAI_API_KEY=sk-...      # only the matching key is required

# Optional model overrides
LLM_MODEL_PRIMARY=gpt-4o-mini    # investigation agent (default per provider)
LLM_MODEL_FAST=gpt-4o-mini       # CVE analysis (fast/cheap tier)
LLM_MODEL_ANALYSIS=gpt-4o-mini   # daily SOC reports
LLM_TEMPERATURE=0.2              # inference temperature
```

**Recommended configuration for cost efficiency:**
```bash
LLM_PROVIDER=openai
# GPT-4o mini: $0.15/1M input, $0.60/1M output
# ~553 tokens/investigation → $0.000165/investigation
# INVESTIGATION_INTERVAL_SEC=1800 → ~$0.008/day → 625 days on $5 budget
```

**Provider defaults:**
| Provider | Primary Model | Fast Model | Analysis Model |
|----------|-------------|------------|----------------|
| claude | claude-opus-4-5 | claude-haiku-4-5-20251001 | claude-sonnet-4-6 |
| openai | gpt-4o-mini | gpt-4o-mini | gpt-4o-mini |
| gemini | gemini-2.5-flash | gemini-2.5-flash | gemini-2.5-flash |

> **Note on Gemini:** The free tier is limited to 20 requests/day (not 250), and the safety filter blocks security content ("malware", "C2", "reverse shell"). Gemini is not recommended for this project.

---

## Live DPI — Real Packet Capture on Windows

To capture **real network traffic** from your Windows machine, use the included launcher:

```
Double-click: Start Live DPI.bat
```

The launcher automatically:
1. Elevates to Administrator (required for Npcap)
2. Installs Npcap 1.80 silently if not present
3. Installs Python packages (`scapy`, `aiokafka`, `redis`)
4. Starts Docker Desktop if not running
5. Starts the full Docker compose stack
6. Launches `src/dpi/sensor.py` pointing at `localhost:9092` (Kafka)

**Npcap** is the Windows packet capture driver. Without it, Scapy cannot read raw packets. The launcher handles the install automatically. For manual setup see [`docs/LIVE_DPI_SETUP.md`](docs/LIVE_DPI_SETUP.md).

> **Important:** The DPI sensor runs **on the host machine** (not in Docker) so it can access the physical network interface. All other services run in Docker.

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Layer |
|---|---|---|
| C2 via HTTP/S (Application Layer Protocol) | T1071.001 | DPI timing analysis + RLM |
| Network Scanning (Network Service Discovery) | T1046 | DPI SYN flood detection |
| Data Exfiltration (Non-C2 Encrypted Channel) | T1048.003 | RLM volume anomaly + entropy |
| DGA Malware (Dynamic Resolution) | T1568.002 | DPI DNS analysis |
| Lateral Movement SMB | T1021.002 | RLM internal traffic patterns |
| Lateral Movement RDP | T1021.001 | DPI + RLM |
| Obfuscated Payload (Packed/Encrypted) | T1027 | DPI entropy threshold |
| Protocol Tunneling | T1572 | DPI oversized ICMP/DNS |
| Brute Force Password Guessing | T1110.001 | DPI rapid auth failure rate |
| Password Spraying | T1110.003 | DPI low-and-slow pattern |
| Exploit Public-Facing Application | T1190 | DPI payload pattern matching |
| Reverse Shell (Unix Shell Interpreter) | T1059.004 | DPI suspicious port + bidirectional |
| Tor/Proxy Usage | T1090.003 | CTI known exit node IPs |
| Ransomware Staging | T1486 | RLM SMB enumeration |
| Credential Dumping | T1003 | RLM auth pattern spike |

---

## Common Commands

```bash
# Start full platform
docker compose up -d

# Stop (data preserved)
docker compose down

# View all logs
docker compose logs -f

# View specific service
docker compose logs -f mcp-orchestrator
docker compose logs -f rlm-engine

# Rebuild a specific service after code change
docker compose up -d --build mcp-orchestrator

# Check resource usage
docker stats

# Full reset (deletes all data volumes)
bash scripts/setup/reset.sh

# Run unit tests (no Docker needed)
pip install pytest && pytest tests/unit/ -v
```

---

## Documents

| Document | Purpose |
|----------|---------|
| [`docs/PROJECT.md`](docs/PROJECT.md) | Master project overview |
| [`docs/PRD.md`](docs/PRD.md) | Product Requirements Document |
| [`docs/TRD.md`](docs/TRD.md) | Technical Requirements Document |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Deep-dive system design |
| [`docs/PIPELINES.md`](docs/PIPELINES.md) | DPI vs Simulator pipeline comparison |
| [`docs/LIVE_DPI_SETUP.md`](docs/LIVE_DPI_SETUP.md) | Npcap + Start Live DPI.bat setup guide |
| [`docs/RAG_DESIGN.md`](docs/RAG_DESIGN.md) | RAG pipeline design + governance |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | All REST API endpoints |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | n8n SOAR workflow specs |
| [`docs/RESOURCES.md`](docs/RESOURCES.md) | Research papers + references |
| [`docs/CHANGELOG.md`](docs/CHANGELOG.md) | Version history + architectural decisions |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Dev setup + contribution guide |

---

## Key Metrics

- **14** Docker containers
- **6** SOC Dashboard tabs (Overview, Alerts, Incidents, Response, Threat Intel, Hosts)
- **5** SOAR workflows (n8n)
- **15** MITRE ATT&CK techniques covered
- **5** live CTI sources (NVD, CISA, Abuse.ch, MITRE, OTX)
- **17** simulated threat scenarios (12 MITRE-mapped + 5 unknown novel threats)
- **11+** enterprise integrations
- **3** LLM providers (Claude, GPT-4o, Gemini) — switchable via single env var
- **1** LLM API call per investigation (~553 tokens, ~$0.000165)
- **0** external embedding API calls (fully local)
- **25** supporting research papers

---

*CyberSentinel AI v1.2 — Academic Capstone Project 2025/2026*
