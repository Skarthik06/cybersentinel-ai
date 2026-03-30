# Changelog

All notable changes and architectural decisions are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] — 2026-03-28/29 — Investigation Optimization + Human-in-the-Loop Response

### Changed — AI Investigation Pipeline (Major Optimization)

**Problem:** The original agentic loop used 3 LLM API calls per investigation (~5,500–7,000 input tokens each). The loop passed all 9 MCP tool schemas (~800 tokens of JSON) every call, and raw tool results (300–500 tokens each) were fed back uncompressed.

**Solution:** Stateless 1-call investigation pipeline with four key optimizations:

1. **`tools=None`** — All 4 intel tools are run in code via `asyncio.gather()` before the LLM call. Tool schemas no longer appear in any prompt. Saved ~2,400 tokens/investigation.

2. **`_summarize_result()` compression** — Each raw tool result is compressed to 1–3 lines of essential facts before being included in the LLM prompt. Saved ~1,200 tokens/investigation.

3. **`asyncio.gather()`** — All 4 intel tools (query_threat_database, get_host_profile, lookup_ip_reputation, get_recent_alerts) execute in parallel instead of sequentially. Zero LLM calls during this phase.

4. **`alert_slim` stripping** — The `raw_event` field (which duplicates all other alert fields) is stripped before sending to the LLM. Saved ~300 tokens/investigation.

5. **`max_tokens=1024`** — Reduced from 4096. The JSON verdict format needs at most ~300 output tokens.

**Results:**

| Metric | Before | After |
|--------|--------|-------|
| LLM API calls per investigation | 3 | **1** |
| Tokens per investigation | ~5,500–7,000 | **~553** |
| Input:Output ratio | ~10:1 | **~2:1** |
| Reduction | — | **~90%** |
| Cost (GPT-4o mini) | ~$0.001 | **~$0.000165** |
| Budget runway ($5) | ~5,000 investigations | **~30,000 investigations** |

### Added — Human-in-the-Loop Block Recommendations

**Problem:** The original pipeline auto-blocked IPs on CRITICAL severity — a dangerous pattern that can disrupt legitimate services if the AI misclassifies.

**Solution:** SOAR human-in-the-loop pattern:

1. **`block_recommended` flag stored in incidents** — the AI sets `block_recommended=True` for CRITICAL alerts or when the verdict explicitly recommends blocking. The IP is stored in `block_target_ip`. No automatic blocking occurs.

2. **New `GET /api/v1/block-recommendations` endpoint** — returns all pending recommendations (incidents where `block_recommended=TRUE AND status='OPEN'`), CRITICAL first.

3. **New `POST /api/v1/incidents/{id}/block` endpoint** — analyst approves: inserts `firewall_rules` row + sets Redis `blocked:{ip}` + marks incident RESOLVED.

4. **New `POST /api/v1/incidents/{id}/dismiss` endpoint** — analyst dismisses: marks incident RESOLVED without blocking.

5. **New RESPONSE tab in SOC Dashboard** — dedicated panel showing all pending block recommendations with BLOCK IP and DISMISS buttons. Shows 3 metric cards: Active Blocks, Pending Recommendations, Incidents Resolved Today. Polls every 30 seconds.

6. **Database migration** — added 2 columns to `incidents` table:
   ```sql
   ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
   ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip TEXT;
   ```

### Added — Traffic Simulator Service

- New `src/simulation/traffic_simulator.py` — generates 12 realistic threat scenarios across the MITRE ATT&CK kill-chain
- New `docker/Dockerfile.simulator` and service `traffic-simulator` in docker-compose
- 12 threat scenarios: C2 Beacon, Data Exfiltration, Lateral Movement (SMB), Port Scan, DNS Tunneling, Brute Force SSH, RDP Lateral Movement, Exploit Public App, High Entropy Payload, Protocol Tunneling, Credential Spray, Reverse Shell
- Rate: configurable via `SIMULATION_RATE` env var (default: 2 events/minute)
- Publishes directly to Kafka `threat-alerts` — bypasses DPI and RLM pipeline
- See `docs/PIPELINES.md` for the full explanation of what this bypasses

### Added — Multi-Provider LLM Abstraction

- New `src/agents/llm_provider.py` supporting Claude (Anthropic), OpenAI GPT-4o, and Gemini
- Unified `LLMProvider` abstract interface — all providers expose identical `chat()` and `submit_tool_results()` methods
- Switch providers via single `LLM_PROVIDER` env var: `claude` | `openai` | `gemini`
- `OpenAIProvider`: converts MCP tool format to OpenAI `function_calling` format
- `ClaudeProvider`: uses Anthropic Messages API with native `tool_use`
- `GeminiProvider`: converts to Gemini `FunctionDeclaration` format
- Singleton factory via `get_provider()` — instantiated once per process
- `LLM_MODEL_PRIMARY`, `LLM_MODEL_FAST`, `LLM_MODEL_ANALYSIS` env vars for model tier overrides
- `LLM_TEMPERATURE` env var (default 0.2) controls inference determinism
- Exponential backoff retry on 429 rate-limit errors: 5s → 15s → 45s

### Added — SOC Dashboard Enhancements

**RESPONSE tab:**
- Dedicated 6th tab with red badge showing pending recommendation count
- 3 metric cards: Active Blocks, Pending Recommendations, Incidents Resolved Today
- Block Recommendations panel — always visible (not hidden when empty)
- BLOCK IP button → calls `POST /api/v1/incidents/{id}/block`
- DISMISS button → calls `POST /api/v1/incidents/{id}/dismiss`
- 30-second auto-polling

**Hosts tab (fixed and enhanced):**
- Fixed critical bug: all profile metrics were reading from wrong level (`hostProfile.anomaly_score` instead of `hostProfile.profile?.anomaly_score`)
- Fixed `hostProfile.note` → `hostProfile.profile?.profile_text` (correct DB column name)
- Added BLOCKED card (YES/NO, red if blocked)
- Added BLOCK EVENTS count
- Added LINKED INCIDENTS count
- Added PROFILE NOTE (from `profile_text` DB column)
- Added RECENT ALERTS section: severity badge, alert type, MITRE technique, timestamp

**Threat Intel tab (fixed):**
- Fixed semantic search results display — was showing raw `JSON.stringify(r)` instead of parsed content
- Now correctly extracts `r.document`, `r.similarity`, `r.metadata.mitre`, `r.metadata.severity`
- Similarity shown as percentage badge (e.g. "89.1% match")
- MITRE technique badge and severity badge per result
- Empty state shown when query returns no results

### Fixed — Docker + Infrastructure

- `docker-compose.yml` — `Dockerfile.playwright` → `Dockerfile.scraper` (threat-intel-scraper build)
- `docker-compose.yml` — `./scripts/init.sql` → `./scripts/db/init.sql` (postgres init volume)
- `docker-compose.yml` — `./configs/prometheus.yml` → `./configs/prometheus/prometheus.yml` (prometheus volume)
- `docker-compose.yml` — mcp-orchestrator was missing `LLM_PROVIDER`, `GOOGLE_API_KEY`, `OPENAI_API_KEY` env vars (only had `ANTHROPIC_API_KEY`)
- MCP Kafka consumer tuned to prevent consumer group eviction during long AI investigations: `session_timeout_ms=300000`, `heartbeat_interval_ms=10000`, `max_poll_interval_ms=600000`

### Fixed — DPI Severity Thresholds

- 1 detection reason = `HIGH` (was `MEDIUM`)
- 2+ detection reasons = `CRITICAL` (was `HIGH`)
- This ensures more alerts trigger AI investigation (which gates on HIGH/CRITICAL)

### Note on Gemini

Gemini was tested and abandoned as default:
- Free tier is 20 requests/DAY (not 250 as documented)
- `finish_reason:12` safety filter blocks security content ("malware", "C2", "reverse shell") — unusable for this project
- Gemini remains available as `LLM_PROVIDER=gemini` but not recommended

**Current recommended configuration:** `LLM_PROVIDER=openai` with GPT-4o mini.

---

## [1.0.0] — 2025-03-21 — Initial Production Release

### Added

**Core Platform**
- Deep Packet Inspection sensor (`src/dpi/sensor.py`) with Scapy-based packet capture
- 8 standalone detection functions in `src/dpi/detectors.py` — independently unit-testable
- Kafka publisher for DPI events (`src/dpi/publisher.py`)
- RLM (Recursive Language Model) behavioral profiling engine (`src/models/rlm_engine.py`)
- BehaviorProfile EMA dataclass (`src/models/profile.py`) with `to_text()`, `update()`, serialisation
- 8 threat signature seeds (`src/models/signatures.py`) covering MITRE T1071.001 through T1090.003
- MCP Orchestrator with 5 AI agents and 9 MCP tools (`src/agents/mcp_orchestrator.py`)
- AI system prompts (`src/agents/prompts.py`) — investigation, CVE analysis, board report
- MCP tool definitions JSON schema (`src/agents/tools.py`)
- Playwright-based CTI scraper for NVD, CISA, Abuse.ch, MITRE, OTX (`src/ingestion/threat_intel_scraper.py`)
- CTI source definitions (`src/ingestion/sources.py`)
- FastAPI REST gateway with JWT authentication (`src/api/gateway.py`)
- JWT auth helpers and RBAC dependency factory (`src/api/auth.py`)
- Pydantic schemas for all API endpoints (`src/api/schemas.py`)
- Central configuration module (`src/core/config.py`) — all parameters from environment
- Structured logging (`src/core/logger.py`)
- Shared constants — severity levels, MITRE IDs, alert types (`src/core/constants.py`)

**RAG Governance Layer**
- Full governed embedder module (`src/ingestion/embedder.py`):
  - Pinned embedding model via `SentenceTransformerEmbeddingFunction(model_name=...)`
  - Model version stored in collection metadata
  - Model mismatch warning at startup
  - `chunk_text()` for documents exceeding token limit
  - `truncate_with_log()` — logged truncation, never silent
  - Redis embedding cache (SHA-256 fingerprint, configurable TTL)
  - MITRE re-embed guard (configurable interval, Redis-backed)
  - `batch_upsert()` with cache checking and configurable batch size
  - `evict_stale_profiles()` for collection TTL governance
- All RAG thresholds moved to `config.py` — no hardcoded values anywhere

**Infrastructure**
- TimescaleDB schema with hypertable, compression, retention, continuous aggregate, RBAC users, audit log (`scripts/db/init.sql`)
- Docker Compose — 14-service core stack (`docker-compose.yml`)
- 6 Dockerfiles — one per service (`docker/`)
- One-shot install script with secret generation (`scripts/setup/install.sh`)
- n8n startup script (`scripts/setup/add_n8n.sh`)
- Full reset script (`scripts/setup/reset.sh`)
- Prometheus alert rules and scrape config (`configs/prometheus/`)
- Grafana datasource configuration (`configs/grafana/`)

**n8n SOAR Layer**
- Kafka → n8n bridge with deduplication and retry (`n8n/bridge/kafka_bridge.py`)
- n8n Docker extension (`n8n/docker-compose.n8n.yml`)
- Workflow 01: Critical Alert SOAR Playbook
- Workflow 02: Daily SOC Intelligence Report
- Workflow 03: CVE Intel Pipeline
- Workflow 04: SLA Watchdog & Escalation
- Workflow 05: Weekly Executive Board Report

**Frontend**
- React landing page with cinematic dark military aesthetic (`frontend/src/CyberSentinel_Landing.jsx`)
- React SOC Dashboard with 6 tabs and real API integration (`frontend/src/CyberSentinel_Dashboard.jsx`)
- App router with floating view switcher (`frontend/src/App.jsx`)
- Vite configuration with API proxy (`frontend/vite.config.js`)
- Demo mode — realistic mock data when backend is offline

**Tests**
- 27 unit tests for DPI detectors (`tests/unit/test_detectors.py`)
- 5 unit tests for BehaviorProfile EMA (`tests/unit/test_profile.py`)
- API integration tests (`tests/integration/test_api.py`)

**Documentation**
- Initial versions of all 10 docs (PROJECT, PRD, TRD, ARCHITECTURE, RAG_DESIGN, API_REFERENCE, WORKFLOWS, RESOURCES, CHANGELOG, CONTRIBUTING)

---

## Architectural Decisions

### ADR-001: Event-Driven Architecture via Kafka
**Decision:** All inter-service communication in the detection pipeline goes through Kafka topics — no direct HTTP calls between services.
**Rationale:** Independent scaling, guaranteed delivery, replay capability, clean separation of concerns.
**Alternatives considered:** Direct HTTP (tight coupling), gRPC (complexity without benefit), Redis Pub/Sub (no persistence).

### ADR-002: EMA for Behavioral Profiling
**Decision:** Exponential Moving Average for all profile fields, not raw time-series storage.
**Rationale:** O(1) memory per host regardless of traffic volume. Natural decay of old patterns. Online learning without labels.
**Alternatives considered:** LSTM (requires training data, GPU), raw time-series (query latency), sliding window (loses long-term patterns).

### ADR-003: Natural Language as Embedding Input
**Decision:** Convert numerical BehaviorProfile fields to English prose before embedding.
**Rationale:** Pre-trained NLP models understand semantic relationships in natural language. "High entropy payload on unusual port" maps to threat signature vectors more accurately than raw numbers.
**Alternatives considered:** Raw numeric vectors (requires domain-specific model), graph embeddings (too complex).

### ADR-004: Local Embedding Model
**Decision:** Use all-MiniLM-L6-v2 running locally via sentence-transformers.
**Rationale:** Zero cost per embedding call. No rate limits. No data leaving the deployment. 50ms latency on CPU is acceptable.
**Alternatives considered:** OpenAI text-embedding-3-small (API cost, latency, data egress), larger local models (higher CPU, diminishing returns).

### ADR-005: Severity Gate for LLM API
**Decision:** Only HIGH and CRITICAL alerts invoke the LLM for investigation.
**Rationale:** LLM API calls are expensive. LOW and MEDIUM alerts (the majority) are stored directly to the database. This cuts LLM API costs by ~90% while ensuring every serious threat gets AI reasoning.
**Alternatives considered:** All alerts (cost-prohibitive), CRITICAL only (misses HIGH threats).

### ADR-006: n8n for SOAR
**Decision:** Use n8n as the SOAR engine rather than custom Python code.
**Rationale:** Visual workflow canvas, version-controllable JSON exports, 400+ native integrations, no-code extensibility.
**Alternatives considered:** Prefect/Airflow (data pipeline focused), Temporal (complex), custom FastAPI handlers (no visual canvas), commercial SOAR (expensive).

### ADR-007: ChromaDB over FAISS or Weaviate
**Decision:** ChromaDB as the vector store.
**Rationale:** Docker-native, Python-native, collection-level metadata, handles < 1M vectors well.
**Alternatives considered:** FAISS (persistence complexity), Weaviate (heavier, large-scale), Pinecone (commercial), pgvector (TimescaleDB compatibility concerns).

### ADR-008: Multi-Provider LLM Abstraction
**Decision:** Abstract all LLM calls behind `LLMProvider` interface, supporting Claude, OpenAI, Gemini via single env var.
**Rationale:** API availability, cost, and rate limits differ by region/account. Single env var enables deployment regardless of available provider.
**Alternatives considered:** LangChain (opinionated, conflicts with agentic loop), LiteLLM (extra dependency), hardcoded parallel paths (unmaintainable).

### ADR-009: Human-in-the-Loop for IP Blocking
**Decision:** Replace auto-block with analyst-reviewed block recommendations via RESPONSE tab.
**Rationale:** Automated blocking of legitimate IPs (false positives) can disrupt business operations. SOAR best practice: AI recommends, human approves. The recommendation + approval audit trail also satisfies compliance requirements.
**Alternatives considered:** Auto-block with rollback (complex, risky), threshold-based auto-block (combined_score > 0.9 — still risks false positives), no blocking at all (reduces platform value).

### ADR-010: Stateless 1-Call Investigation Pipeline
**Decision:** Replace 3-call agentic loop with single LLM call: gather intel in parallel → summarize → 1 call → parse verdict → create incident.
**Rationale:** The agentic loop's primary cost was tool schema overhead (~800 tokens/call × 3 calls) and uncompressed tool results. Pre-gathering all intel eliminates this. Result: 90% token reduction, same investigation quality.
**Alternatives considered:** Keep agentic loop with fewer tools (still has schema overhead), reduce max_tool_rounds to 1 (doesn't solve schema cost), caching tool results (helps but doesn't eliminate schema overhead).

---

*Changelog — CyberSentinel AI v1.0/1.1 — 2025/2026*
