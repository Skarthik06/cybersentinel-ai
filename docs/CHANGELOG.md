# Changelog

All notable changes and architectural decisions are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.2] — 2026-04-11 — Infrastructure Fixes + N8N Automation + Operations Documentation

### Fixed — Grafana Container: Exit Code 1 on Startup

**Problem:** Grafana exited immediately on startup with code 1. Root cause: `GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-worldmap-panel` in `docker-compose.yml` caused Grafana to attempt a DNS lookup to `grafana.com` during container init. Inside the Docker network, this lookup fails — Grafana errors and exits.

**Fix:** Removed `GF_INSTALL_PLUGINS` line from `docker-compose.yml`. Grafana starts cleanly without external plugin downloads. The clock and worldmap panels are not used by the project dashboards.

---

### Fixed — N8N Not Reachable from API Container

**Problem:** The `N8N` container was started with `docker run` outside of `docker compose`, so it was placed on the default Docker bridge network, not on `cybersentinel-ai_cybersentinel-net`. The API container (inside the compose network) could not reach `host.docker.internal:5678`.

**Fix:** Reconnect or recreate the N8N container on the correct network:
```powershell
docker network connect cybersentinel-ai_cybersentinel-net N8N
```

The correct network name is `cybersentinel-ai_cybersentinel-net` (Docker Compose prefixes the project folder name). This is now handled automatically by `scripts/start_n8n.ps1`.

---

### Fixed — N8N Workflow Activation: Inactive After Import

**Problem:** After importing workflow JSON files via `n8n import:workflow`, all 5 workflows were left in a broken state:
- `active = 0` in `workflow_entity` (n8n does not activate on import)
- `activeVersionId = NULL` (no published version pointer)
- No rows in `workflow_published_version` (n8n logs: "0 published workflows")
- n8n reads execution nodes from `workflow_history` using `publishedVersionId` — not from `workflow_entity.nodes`. Updating `workflow_entity` alone has no effect.

Result: All webhook endpoints returned 404, scheduled workflows never ran, and the frontend automation triggers returned FAILED.

**Fix:** New script `scripts/activate_n8n_workflows.py` automatically detects and repairs all three conditions by direct SQLite manipulation:
1. Sets `active = 1` for each workflow
2. Generates and sets `activeVersionId` UUID
3. Inserts row in `workflow_published_version`
4. Inserts correct nodes into `workflow_history` from the live JSON files

Run after any import or when workflows stop responding:
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
```

---

### Fixed — N8N Env Vars Blocked in Workflow Nodes

**Problem:** n8n 2.15+ introduced `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` as the default. All workflow nodes that referenced `$env.OPENAI_API_KEY` and `$env.SLACK_BOT_TOKEN` silently failed — the variables were blocked by the sandbox. This caused all OpenAI LLM calls in WF02/03/05 to fail without an obvious error message.

**Fix:** Recreate the N8N container with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`. This is now set in `scripts/start_n8n.ps1` automatically.

---

### Fixed — SLA Watchdog (WF04): Auth Node 422 Error

**Problem:** The Authenticate API node used `"body": "=username=admin&password=cybersentinel2025"` (a raw URL-encoded string) with `contentType: form`. n8n 2.15 HTTP Request node (typeVersion 4.2) no longer accepts a raw string for form bodies — it expects structured `bodyParameters`.

**Fix:** Changed auth node to use `bodyParameters`:
```json
"bodyParameters": {
  "parameters": [
    {"name": "username", "value": "admin"},
    {"name": "password", "value": "cybersentinel2025"}
  ]
}
```

---

### Fixed — SLA Watchdog (WF04): Build Approval Payload Crash

**Problem:** The Build Approval Payload code node tried to read `d.breached.length` where `d` was the Slack payload object (which has no `.breached` field). This caused the step to produce "0 breached, 0 warning" in every report title.

**Fix:** Changed to read SLA counts from `$('Check SLA Thresholds').item.json` instead:
```js
const slaData = $('Check SLA Thresholds').item.json;
// Use slaData.breached and slaData.warning for accurate counts
```

---

### Fixed — API Gateway: Workflow Triggers Returned 500 / FAILED

**Problem:** The trigger endpoint in `src/api/gateway.py` used `httpx.AsyncClient(timeout=10)` when proxying requests to n8n. OpenAI API calls inside WF02 and WF05 take 18–27 seconds — well beyond the 10-second timeout. Additionally, the exception handler only caught `httpx.ConnectError`, so `TimeoutException` propagated as an unhandled 500.

**Fix:**
```python
# Before
async with httpx.AsyncClient(timeout=10) as client:
    ...
except httpx.ConnectError:
    raise HTTPException(status_code=503, ...)

# After
async with httpx.AsyncClient(timeout=90) as client:
    ...
except httpx.TimeoutException:
    return {"workflow": workflow_id, "status": "triggered", "n8n_status": 202}
except httpx.ConnectError:
    raise HTTPException(status_code=503, ...)
```

Timeout raised to 90 seconds. `TimeoutException` now returns a successful 200 response (the workflow is running; it just hasn't returned yet). Frontend no longer shows FAILED on long-running workflows.

---

### Added — N8N Workflow Activation Script (`scripts/activate_n8n_workflows.py`)

Fully automated n8n workflow activator. Reads live workflow JSON from `n8n/workflows/`, directly manipulates the SQLite database at `D:/N8N/database.sqlite`, and ensures all three activation conditions are correct. Features:
- `--dry-run` flag to preview changes without touching the DB
- `--db` flag for custom SQLite path
- `--workflows-dir` flag for custom workflow directory
- `--wait` flag for use in startup scripts (adds delay before connecting)
- All output uses ASCII-safe characters (Windows cp1252 compatible)

---

### Added — N8N Fresh-Start Script (`scripts/start_n8n.ps1`)

PowerShell script for full N8N setup from scratch. Reads credentials from `.env`, removes old container, starts a new container with all required env vars (including `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`), waits for initialization, runs the activation script, and restarts N8N. Handles first-time setup and full resets with a single command.

---

### Added — N8N Operations Guide (`docs/N8N_OPERATIONS.md`)

Comprehensive operations reference covering:
- Why workflows break after restart (and when they don't)
- SQLite database structure n8n requires
- Fix script usage and sample output
- Full fresh-start procedure (automated and manual)
- N8N container reference (all required env vars)
- Troubleshooting all known error patterns
- Webhook reference table and full request chain

### Added — Abbreviations Reference (`docs/ABBREVIATIONS.md`)

Complete glossary of all cybersecurity and project-specific abbreviations across 8 sections: SOC/SOAR/SIEM terms, threat intelligence standards, MITRE ATT&CK techniques, network/protocol terms, AI/ML terms, platform/infrastructure terms, CyberSentinel-specific terms, and a metrics reference table.

### Added — TWR Presentation Document (`docs/TWR_PRESENTATION.md`)

Full 18-section technical work report document prepared for the academic panel presentation. Covers: executive summary, problem statement, objectives, system architecture, all core technical components, novel contributions with comparison tables, end-to-end data flow timeline, SOAR automation, SOC dashboard, threat detection matrix, security architecture, performance/cost analysis, technology stack, deployment architecture, testing, limitations, research positioning, and conclusion.

---

## [1.2.1] — 2026-04-08 — n8n Workflow Fixes + SLA + Board Report

### Fixed — n8n Code Nodes: HTTP Calls Blocked by JS Task Runner Sandbox

**Problem:** n8n 2.15 introduced a strict JS Task Runner sandbox that blocks ALL outbound HTTP inside Code nodes — `fetch`, `require('https')`, and `$helpers.httpRequest` all throw errors. Workflows 02, 03, and 05 were calling the OpenAI API from inside Code nodes.

**Fix:** Replaced the Code node LLM calls with dedicated **HTTP Request nodes** (typeVersion 4.2). The Code node now only builds the prompt (`Build AI Prompt` / `Build Board Prompt`), and the HTTP Request node handles the API call.

```
Before: [Code node: build prompt + call OpenAI] → sandbox blocks HTTP → error
After:  [Code node: build prompt] → [HTTP Request node: POST api.openai.com] → [Code node: parse + format]
```

All three workflows (02, 03, 05) now use this pattern. The HTTP Request node is sandbox-safe.

---

### Fixed — SLA Watchdog: "Open Incidents: 0" When 900+ Incidents Exist

**Problem:** n8n HTTP Request node (typeVersion 4.2) splits JSON array responses into multiple items. `$input.first().json.incidents` was looking for an `.incidents` key on a single incident object → `undefined` → empty array.

**Fix:** Changed to `$input.all()` to collect all split items:

```js
const items = $input.all();
const incidents = items.length > 0 && Array.isArray(items[0].json)
  ? items[0].json
  : items.map(function(i){ return i.json; }).filter(function(i){ return i && i.incident_id; });
```

Also fixed field names in `Build Slack SLA Alert` to match `IncidentResponse` schema:
- `inc.id` → `inc.incident_id || inc.id`
- `inc.threat_type` → `inc.threat_type || inc.type || inc.title`
- `inc.src_ip` → `inc.affected_ips && inc.affected_ips[0]`

---

### Fixed — Board Report: CRITICAL/HIGH Open Always 0

**Two root causes fixed:**

1. **Wrong dashboard URL** — WF05 was calling `/api/v1/dashboard/stats` (404). Fixed to `/api/v1/dashboard`.

2. **Wrong field names** — `stats.total_alerts` → `stats.total_alerts_24h`, `stats.total_incidents` → `stats.active_incidents`.

3. **Incidents array split** — Same n8n array splitting issue as SLA Watchdog. Fixed with `$('Fetch Open Incidents').all()` in `Aggregate Weekly Metrics`.

---

### Fixed — Build Approval Payload (WF04): Title Showed "0 breached, 0 warning"

**Problem:** Code read `d.breached` from the Slack payload object, which has no `.breached` field at that point.

**Fix:** Read counts from `d.text` instead (e.g., `"SLA Alert: 4 breached, 1 warning"`), which is always set by `Build Slack SLA Alert`.

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

*Changelog — CyberSentinel AI v1.0/1.1/1.2/1.2.1 — 2025/2026*
