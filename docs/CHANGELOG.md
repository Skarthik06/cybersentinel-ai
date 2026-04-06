# Changelog

All notable changes and architectural decisions are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.0] — 2026-04-06 — Pipeline Unification + UX Overhaul + Investigation Quality

### Changed — Traffic Simulator: Full DPI Pipeline (Major)

**Problem (v1.1):** The simulator published pre-formed alert dicts directly to `threat-alerts`, bypassing `raw-packets` and the entire RLM engine. This meant behavioral profiles stayed at zero for all simulated IPs, the Hosts tab showed no meaningful data, and the AI had no behavioral context to work with.

**Solution:** Simulator now publishes **bursts of 30–150 raw `PacketEvent` dicts** to the `raw-packets` Kafka topic — the same topic used by the real DPI sensor. Every simulated scenario passes through the full pipeline:

```
simulator → raw-packets → RLM Engine (EMA profiling + ChromaDB) → threat-alerts → MCP/LLM
```

**Results:**
- Behavioral profiles now have real `observation_count`, `avg_bytes_per_min`, `avg_entropy`, `anomaly_score` for simulated IPs
- ChromaDB `behavior_profiles` collection populated by simulator runs
- Hosts tab shows meaningful data for simulator IPs
- AI investigation now receives real behavioral context (not zeros) for all scenarios

**17 scenarios total:** 12 MITRE-mapped (unchanged) + 5 UNKNOWN novel threats (AI must classify):
`POLYMORPHIC_BEACON`, `COVERT_STORAGE_CHANNEL`, `SLOW_DRIP_EXFIL`, `MESH_C2_RELAY`, `SYNTHETIC_IDLE_TRAFFIC`

---

### Changed — AI Investigation: Structured 4-Part Analysis Format

**Problem (v1.1):** AI investigation summary was a free-form paragraph, often including remediation steps and generic observations. Analysts could not quickly extract the key facts.

**Solution:** System prompt updated to require a structured 4-part description in every investigation:

```
OBSERVED: exact traffic seen — IPs, ports, protocol, entropy value, bytes/min
WHY SUSPICIOUS: which behavioural indicator fired and why it deviates from host baseline
THREAT ASSESSMENT: most likely attacker objective + confidence (HIGH/MEDIUM/LOW) + reasoning
ATTACKER PROFILE: threat category (APT / ransomware / opportunistic scanner / insider / botnet)
```

Each section is 1-2 sentences. Remediation is explicitly excluded from the investigation summary.

---

### Changed — Remediation: Separated as Technical Playbook

**Problem (v1.1):** Remediation was embedded in the AI investigation summary, making both sections look identical in the UI.

**Solution:** Remediation is now a separate **Technical Playbook** generated on analyst request:

- **Static playbook:** Always available immediately. MITRE-based generic playbook per technique.
- **AI Playbook:** Generated on demand via "Generate AI Playbook" button. Returns:
  - `CONTAINMENT (now)` — 2-3 actual shell/CLI commands with real IPs/ports
  - `ERADICATION (next 2h)` — commands or tool actions to remove the threat
  - `DETECTION RULES` — 1-2 Snort/Sigma/firewall rule lines tuned to the specific IOC
  - `VERIFICATION` — specific, observable checks confirming threat is gone

**Cost:** AI Playbook is only generated when the analyst explicitly requests it (button click), keeping token usage minimal.

---

### Changed — block_recommended Logic Fixed for Pending Incidents

**Problem (v1.1):** `_create_pending_incident()` (called when AI investigation is paused) always inserted `block_recommended=false`, regardless of severity. CRITICAL and HIGH pending incidents never appeared in Block Recommendations.

**Solution:** Severity-aware `block_recommended` in `_create_pending_incident()`:
```python
block_rec    = sev in ('CRITICAL', 'HIGH')
block_target = src_ip if block_rec else ''
```
CRITICAL and HIGH pending incidents now correctly appear in the Block Recommendations panel with the correct IP pre-filled.

---

### Added — Active Incidents Panel in Response Tab

New panel in the RESPONSE tab showing all `status='OPEN'` incidents as clickable cards. Each card shows:
- Incident ID, title, severity badge
- Detected timestamp
- Click to expand: AI investigation summary, Technical Playbook, Threat Signatures

Separate from Block Recommendations panel — shows ALL open incidents, not just those flagged for blocking.

---

### Added — Firewall Rules Panel with UNBLOCK Capability

New panel in the RESPONSE tab showing all currently blocked IPs from the `firewall_rules` table. Each row shows:
- Blocked IP address
- Block source (analyst, auto, pending)
- Blocked since timestamp
- **UNBLOCK button** — calls `DELETE /api/v1/firewall-rules?ip={ip}`

---

### Changed — DELETE /api/v1/firewall-rules: Path Param → Query Param

**Problem:** CIDR notation IPs (`192.168.1.6/32`) in URL path segments caused FastAPI routing failures. The `/32` suffix was interpreted as a path component, not part of the IP.

**Solution:** Changed endpoint from `DELETE /api/v1/firewall-rules/{ip_address}` to `DELETE /api/v1/firewall-rules?ip={ip_address}`. Frontend strips CIDR suffix before sending the request.

**DB query:** Uses `host(ip_address::inet) = $1` to match both `192.168.1.6` and `192.168.1.6/32`. Redis keys `blocked:{ip}` and `blocked:{ip}/32` are both deleted.

---

### Changed — Frontend: Landing Page Completely Rewritten

**`CyberSentinel_Landing.jsx`** rewritten from scratch with:
- **Water mosaic canvas** — 22×22px tiles with 4 sine wave interference patterns, animated via `requestAnimationFrame`
- **Animated robot SVG** — rotating radar sweep with pulsing rings
- **Terminal typewriter** — code snippets auto-type in a terminal window
- **IntersectionObserver scroll-reveal** — sections animate in from left/right/bottom as they enter viewport (`.sr` / `.sr-l` / `.sr-r` / `.sr-up` / `.sr-scale` → `.vis`)
- **Glassmorphism cards** — `backdrop-filter: blur(20px)` panels with gradient borders
- **Sections:** Hero, Stats Bar, Detection Pipeline, DPI Engine, RLM Engine, AI Agents (Claude), n8n SOAR, Dual Mode, Kill Chain Coverage, Integrations, Tech Stack, Architecture Diagram, Footer

**`CyberSentinel_Dashboard.jsx`** — `if (!authed)` block stripped to **login card only**: water canvas background + glassmorphism login card centred on screen. All showcase content moved to Landing page.

---

### Added — Source Isolation for AI Investigation Pausing

AI investigation can be paused per source independently via Redis keys:
- `investigations:paused:simulator` — pauses simulator investigations only
- `investigations:paused:dpi` — pauses DPI investigations only

Dashboard toggle creates/removes the Redis key for the relevant source.

---

### Fixed — Redis AOF Corruption Recovery

**Incident:** Power cut during operation corrupted the Redis AOF (Append-Only File): `appendonly.aof.4.incr.aof` had 399 corrupt bytes at end.

**Fix:**
```bash
docker compose exec redis redis-check-aof --fix /data/appendonlydir/appendonly.aof.4.incr.aof
docker compose up -d redis
```
AOF corruption is safe to fix this way — only the partial write at the end of the corrupted file is truncated.

---

## [1.1.0] — 2026-03-28/29 — Investigation Optimization + Human-in-the-Loop Response

### Changed — AI Investigation Pipeline (Major Optimization)

**Problem:** The original agentic loop used 3 LLM API calls per investigation (~5,500–7,000 input tokens each). The loop passed all 9 MCP tool schemas (~800 tokens of JSON) every call, and raw tool results (300–500 tokens each) were fed back uncompressed.

**Solution:** Stateless 1-call investigation pipeline with four key optimizations:

1. **`tools=None`** — All 4 intel tools are run in code via `asyncio.gather()` before the LLM call. Tool schemas no longer appear in any prompt. Saved ~2,400 tokens/investigation.

2. **`_summarize_result()` compression** — Each raw tool result is compressed to 1–3 lines of essential facts before being included in the LLM prompt. Saved ~1,200 tokens/investigation.

3. **`asyncio.gather()`** — All 4 intel tools execute in parallel instead of sequentially. Zero LLM calls during this phase.

4. **`alert_slim` stripping** — The `raw_event` field is stripped before sending to the LLM. Saved ~300 tokens/investigation.

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

**Problem:** The original pipeline auto-blocked IPs on CRITICAL severity — a dangerous pattern that can disrupt legitimate services.

**Solution:**

1. **`block_recommended` flag** stored in incidents — AI sets `True` for CRITICAL/HIGH. IP stored in `block_target_ip`. No automatic blocking.

2. **`GET /api/v1/block-recommendations`** — returns all pending recommendations (`block_recommended=TRUE AND status='OPEN'`), CRITICAL first.

3. **`POST /api/v1/incidents/{id}/block`** — analyst approves: inserts `firewall_rules` row + sets Redis `blocked:{ip}` + marks incident RESOLVED.

4. **`POST /api/v1/incidents/{id}/dismiss`** — analyst dismisses: marks incident RESOLVED without blocking.

5. **RESPONSE tab** in SOC Dashboard — dedicated panel with BLOCK IP and DISMISS buttons.

6. **DB migration** — added 2 columns to `incidents`:
   ```sql
   ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
   ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip TEXT;
   ```

### Added — Traffic Simulator Service

- New `src/simulation/traffic_simulator.py` — 12 threat scenarios across MITRE ATT&CK kill-chain
- New `docker/Dockerfile.simulator` and `traffic-simulator` service in docker-compose
- Published directly to `threat-alerts` (v1.1) — upgraded to `raw-packets` in v1.2

### Added — Multi-Provider LLM Abstraction

- New `src/agents/llm_provider.py` supporting Claude (Anthropic), OpenAI, and Gemini
- Unified `LLMProvider` abstract interface — `chat()` and `submit_tool_results()`
- Switch via single `LLM_PROVIDER` env var: `claude` | `openai` | `gemini`
- `LLM_MODEL_PRIMARY`, `LLM_MODEL_FAST`, `LLM_MODEL_ANALYSIS` env vars for tier overrides
- `LLM_TEMPERATURE` env var (default 0.2)
- Exponential backoff retry on 429: 5s → 15s → 45s

### Added — SOC Dashboard Enhancements

**RESPONSE tab:**
- 3 metric cards: Active Blocks, Pending Recommendations, Incidents Resolved Today
- Block Recommendations panel
- BLOCK IP + DISMISS buttons
- 30-second auto-polling

**Hosts tab (fixed):**
- Fixed: profile metrics reading from wrong level
- Added: BLOCKED card, BLOCK EVENTS count, LINKED INCIDENTS, PROFILE NOTE, RECENT ALERTS

**Threat Intel tab (fixed):**
- Fixed semantic search result display (was `JSON.stringify`)
- Now shows similarity %, MITRE badge, severity badge per result

### Fixed — Docker + Infrastructure

- `Dockerfile.playwright` → `Dockerfile.scraper`
- `./scripts/init.sql` → `./scripts/db/init.sql`
- `./configs/prometheus.yml` → `./configs/prometheus/prometheus.yml`
- mcp-orchestrator was missing `LLM_PROVIDER`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`
- Kafka consumer tuned: `session_timeout_ms=300000`, `heartbeat_interval_ms=10000`, `max_poll_interval_ms=600000`

### Fixed — DPI Severity Thresholds

- 1 detection reason = `HIGH` (was `MEDIUM`)
- 2+ detection reasons = `CRITICAL` (was `HIGH`)

### Note on Gemini

Gemini tested and abandoned:
- Free tier: 20 req/DAY (not 250)
- `finish_reason:12` safety filter blocks security content — unusable for this project
- Still available as `LLM_PROVIDER=gemini` but not recommended

**Recommended:** `LLM_PROVIDER=openai` with GPT-4o mini (`$0.15/1M input`, `$0.60/1M output`).

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
- MCP Orchestrator with AI investigation pipeline (`src/agents/mcp_orchestrator.py`)
- AI system prompts (`src/agents/prompts.py`) — investigation, CVE analysis, board report, remediation
- MCP tool definitions JSON schema (`src/agents/tools.py`)
- CTI scraper for NVD, CISA, Abuse.ch, MITRE, OTX (`src/ingestion/threat_intel_scraper.py`)
- FastAPI REST gateway with JWT authentication (`src/api/gateway.py`)
- JWT auth helpers and RBAC dependency factory (`src/api/auth.py`)
- Pydantic schemas (`src/api/schemas.py`)
- Central configuration module (`src/core/config.py`)
- Structured logging (`src/core/logger.py`)
- Shared constants (`src/core/constants.py`)

**RAG Governance Layer**
- Full governed embedder module (`src/ingestion/embedder.py`):
  - Pinned embedding model via `SentenceTransformerEmbeddingFunction(model_name=...)`
  - Model version stored in collection metadata + mismatch warning at startup
  - `chunk_text()`, `truncate_with_log()`, Redis embedding cache, MITRE re-embed guard
  - `batch_upsert()` with cache checking, `evict_stale_profiles()` for TTL governance

**Infrastructure**
- TimescaleDB schema with hypertable, compression, retention, continuous aggregate (`scripts/db/init.sql`)
- Docker Compose — 14-service core stack (`docker-compose.yml`)
- 6 Dockerfiles — one per service (`docker/`)
- Install script with secret generation (`scripts/setup/install.sh`)
- n8n startup script (`scripts/setup/add_n8n.sh`)
- Full reset script (`scripts/setup/reset.sh`)
- Prometheus alert rules and scrape config
- Grafana datasource configuration

**n8n SOAR Layer**
- Kafka → n8n bridge (`n8n/bridge/kafka_bridge.py`)
- Workflow 01: Critical Alert SOAR Playbook
- Workflow 02: Daily SOC Intelligence Report
- Workflow 03: CVE Intel Pipeline
- Workflow 04: SLA Watchdog & Escalation
- Workflow 05: Weekly Executive Board Report

**Frontend**
- React Landing page (`frontend/src/CyberSentinel_Landing.jsx`)
- React SOC Dashboard with 6 tabs (`frontend/src/CyberSentinel_Dashboard.jsx`)
- App router with floating view switcher (`frontend/src/App.jsx`)
- Vite configuration with API proxy (`frontend/vite.config.js`)
- Demo mode — realistic mock data when backend is offline

**Tests**
- 27 unit tests for DPI detectors (`tests/unit/test_detectors.py`)
- 5 unit tests for BehaviorProfile EMA (`tests/unit/test_profile.py`)
- API integration tests (`tests/integration/test_api.py`)

---

## Architectural Decisions

### ADR-001: Event-Driven Architecture via Kafka
**Decision:** All inter-service communication in the detection pipeline goes through Kafka topics.
**Rationale:** Independent scaling, guaranteed delivery, replay capability, clean separation of concerns.

### ADR-002: EMA for Behavioral Profiling
**Decision:** Exponential Moving Average for all profile fields, not raw time-series storage.
**Rationale:** O(1) memory per host regardless of traffic volume. Natural decay of old patterns. Online learning without labels.

### ADR-003: Natural Language as Embedding Input
**Decision:** Convert numerical BehaviorProfile fields to English prose before embedding.
**Rationale:** Pre-trained NLP models understand semantic relationships in natural language better than raw numbers.

### ADR-004: Local Embedding Model
**Decision:** Use all-MiniLM-L6-v2 running locally via sentence-transformers.
**Rationale:** Zero cost per embedding call. No rate limits. No data leaving the deployment. 50ms latency on CPU is acceptable.

### ADR-005: Severity Gate for LLM API
**Decision:** Only HIGH and CRITICAL alerts invoke the LLM for investigation.
**Rationale:** LLM API calls are expensive. LOW and MEDIUM alerts are stored directly. This cuts LLM costs by ~90% while ensuring every serious threat gets AI reasoning.

### ADR-006: n8n for SOAR
**Decision:** Use n8n as the SOAR engine rather than custom Python code.
**Rationale:** Visual workflow canvas, version-controllable JSON exports, 400+ native integrations.

### ADR-007: ChromaDB over FAISS or Weaviate
**Decision:** ChromaDB as the vector store.
**Rationale:** Docker-native, Python-native, collection-level metadata, handles < 1M vectors well.

### ADR-008: Multi-Provider LLM Abstraction
**Decision:** Abstract all LLM calls behind `LLMProvider` interface.
**Rationale:** API availability, cost, and rate limits differ by region/account.

### ADR-009: Human-in-the-Loop for IP Blocking
**Decision:** Replace auto-block with analyst-reviewed block recommendations via RESPONSE tab.
**Rationale:** Automated blocking of legitimate IPs can disrupt business. SOAR best practice: AI recommends, human approves.

### ADR-010: Stateless 1-Call Investigation Pipeline
**Decision:** Replace 3-call agentic loop with single LLM call: gather intel in parallel → summarize → 1 call → parse verdict → create incident.
**Rationale:** 90% token reduction, same investigation quality. Agentic loop's primary cost was tool schema overhead.

### ADR-011: Simulator Feeds Full DPI Pipeline
**Decision:** Traffic Simulator publishes raw PacketEvents to `raw-packets`, not pre-formed alerts to `threat-alerts`.
**Rationale:** Bypassing RLM left behavioral profiles at zero, giving the AI no behavioral context. Full pipeline means investigations are backed by real EMA profiles, enabling accurate THREAT ASSESSMENT and WHY SUSPICIOUS analysis.

### ADR-012: Structured 4-Part AI Investigation Format
**Decision:** Mandate OBSERVED / WHY SUSPICIOUS / THREAT ASSESSMENT / ATTACKER PROFILE structure in every investigation.
**Rationale:** Free-form paragraphs are hard for analysts to scan quickly. Structured format allows immediate extraction of the IOC, the anomaly indicator, the threat objective, and the actor category.

### ADR-013: Pending Incidents When AI Is Paused
**Decision:** Create basic OPEN incident via `_create_pending_incident()` when AI investigation is paused, with `block_recommended=True` for CRITICAL/HIGH.
**Rationale:** Ensures alerts are never silently dropped — they always surface in the Incidents and Block Recommendations panels even without full AI analysis.

---

*Changelog — CyberSentinel AI v1.0/1.1/1.2 — 2025/2026*
