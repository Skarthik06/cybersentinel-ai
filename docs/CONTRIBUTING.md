# Contributing

**CyberSentinel AI — Developer Setup & Contribution Guide**

---

## Development Environment Setup

### Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Docker Desktop | 24.0+ | `docker --version` |
| Docker Compose | v2.20+ | `docker compose version` |
| Python | 3.11+ | `python3 --version` |
| Node.js | 18+ | `node --version` |
| Git | 2.40+ | `git --version` |

### 1. Clone and Configure

```bash
git clone https://github.com/your-org/cybersentinel-ai
cd cybersentinel-ai
cp .env.example .env
# Edit .env — set LLM_PROVIDER and the matching API key
# Recommended: LLM_PROVIDER=openai + OPENAI_API_KEY=sk-...
# Budget tip: INVESTIGATION_INTERVAL_SEC=1800 → ~$0.008/day on GPT-4o mini
```

### 2. Start the Full Stack

```bash
# Core platform (14 services)
bash scripts/setup/install.sh

# Add n8n SOAR (optional)
bash scripts/setup/add_n8n.sh
```

### 3. Start the Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### 4. Run Unit Tests (no Docker required)

```bash
pip install pytest
pytest tests/unit/ -v
```

### 5. Run Integration Tests (requires running stack)

```bash
pytest tests/integration/ -v --tb=short
```

---

## Project Structure for Contributors

```
src/
├── core/           # Shared utilities — edit carefully, used by all services
│   ├── config.py   # All env vars — add new params here, never in other files
│   ├── logger.py   # Use get_logger(__name__) in all modules
│   └── constants.py # Add new severity levels, alert types, MITRE IDs here
│
├── dpi/            # Packet capture — runs in Docker host network mode
│   ├── sensor.py   # Main capture loop — writes to raw-packets AND threat-alerts
│   ├── detectors.py # ADD NEW DETECTORS HERE — pure functions, no side effects
│   └── publisher.py # Kafka publish helpers
│
├── models/         # RLM engine — only consumes raw-packets (not threat-alerts)
│   ├── rlm_engine.py   # Main engine — consumes raw-packets; populates behavior_profiles
│   ├── profile.py      # BehaviorProfile — add new EMA fields here
│   └── signatures.py   # ADD NEW THREAT SIGNATURES HERE — just add to the list
│
├── simulation/     # Traffic simulator — bypasses DPI and RLM entirely
│   └── traffic_simulator.py  # Writes to threat-alerts only
│   # IMPORTANT: Simulator events DO NOT update behavior_profiles
│   # See docs/PIPELINES.md for the full explanation
│
├── agents/         # LLM agents — 1-call pipeline, NOT agentic loop
│   ├── mcp_orchestrator.py  # asyncio.gather + _summarize_result + 1 LLM call
│   ├── llm_provider.py      # Multi-provider abstraction (Claude/OpenAI/Gemini)
│   ├── tools.py             # Tool JSON schemas — add new tools here
│   └── prompts.py           # ANALYSIS_SYSTEM_PROMPT — edit to tune behavior
│
├── ingestion/      # CTI pipeline — uses governed embedder
│   ├── embedder.py          # RAG governance layer — don't bypass this
│   ├── sources.py           # ADD NEW CTI SOURCES HERE
│   └── threat_intel_scraper.py  # Source-specific scrapers
│
└── api/            # FastAPI REST gateway
    ├── gateway.py   # 11 routes — add new endpoints here
    ├── auth.py      # JWT helpers — use get_current_user() dependency
    └── schemas.py   # Pydantic models — add new request/response models here
```

---

## Understanding the Two Pipelines (Critical for Development)

Before contributing to detection or profiling code, read `docs/PIPELINES.md`. In summary:

**Real DPI path:** `sensor.py` → `raw-packets` (Kafka) → `rlm_engine._consume_packets()` → `behavior_profiles` populated

**Simulator path:** `traffic_simulator.py` → `threat-alerts` (Kafka) → `mcp_orchestrator` → `alerts` + `incidents` populated

**The simulator NEVER writes to `raw-packets`. The RLM engine NEVER reads from `threat-alerts`.** These are two entirely separate flows. Any code that tries to bridge them (e.g. have the simulator also write to `raw-packets`) would break the architectural separation.

When writing tests:
- Unit tests for detection/profiling: use DPI path mocks
- Unit tests for AI investigation: use simulator-style dicts directly
- Integration tests: be explicit about which pipeline you're testing

---

## How to Add a New Threat Detector

1. Add a pure function to `src/dpi/detectors.py`:

```python
def detect_my_new_threat(arg1: str, arg2: int) -> Optional[str]:
    """
    Detect [describe what you're detecting].
    MITRE ATT&CK: T1XXX.XXX
    """
    if some_condition:
        return f"MY_THREAT_TYPE:{detail}"
    return None
```

2. Add a MITRE ID and alert type to `src/core/constants.py`:

```python
class MitreID:
    MY_NEW_TECHNIQUE = "T1XXX.XXX"

class AlertType:
    MY_NEW_THREAT = "MY_THREAT_TYPE"
```

3. Call your detector in `src/dpi/sensor.py` within `analyze_packet()`:

```python
result = detect_my_new_threat(pkt.some_field, pkt.other_field)
if result:
    suspicion_reasons.append(result)
```

4. Add the scenario to `src/simulation/traffic_simulator.py` if you want the simulator to generate this type:

```python
def scenario_my_new_threat() -> Dict:
    return {
        "type": "MY_THREAT_TYPE",
        "severity": "HIGH",
        "mitre_technique": "T1XXX.XXX",
        ...
    }
```

5. Write unit tests in `tests/unit/test_detectors.py`:

```python
class TestMyNewThreat:
    def test_positive_case(self):
        result = detect_my_new_threat("suspicious_value", 42)
        assert result is not None
        assert "MY_THREAT_TYPE" in result

    def test_negative_case(self):
        result = detect_my_new_threat("normal_value", 0)
        assert result is None
```

---

## How to Add a New CTI Source

1. Add a `ThreatSource` to `src/ingestion/sources.py`
2. Add a scraper method to `ThreatIntelScraper` in `src/ingestion/threat_intel_scraper.py`
3. Use `batch_upsert()` from `embedder.py` — never call ChromaDB directly
4. Add it to `asyncio.gather()` in `ThreatIntelScraper.start()`

---

## How to Add a New MCP Tool

1. Add the tool schema to `src/agents/tools.py` (MCP format)
2. Add the handler to `MCPToolExecutor.execute()` in `mcp_orchestrator.py`
3. Implement the handler method

**Note:** MCP tools are now called via `asyncio.gather()` before any LLM call — they are not called by the LLM during a conversation. If you add a new tool, call it in the `investigate()` method's `asyncio.gather()` block, not as a tool passed to the LLM.

---

## How to Add a New API Endpoint

Example — adding a new endpoint that follows the block/dismiss pattern:

```python
# In gateway.py:

class MyActionResponse(BaseModel):
    incident_id: str
    status: str
    message: str

@app.post("/api/v1/incidents/{incident_id}/my-action",
          response_model=MyActionResponse,
          tags=["Incidents"])
async def my_action(
    incident_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db),
    redis = Depends(get_redis),
):
    # Check role
    if current_user["role"] not in ("analyst", "responder", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Execute action
    await db.execute(
        "UPDATE incidents SET status='RESOLVED' WHERE incident_id=$1",
        incident_id
    )

    # Audit log
    await db.execute(
        "INSERT INTO audit_log (username, action, resource, resource_id) VALUES ($1,$2,$3,$4)",
        current_user["username"], "MY_ACTION", "incident", incident_id
    )

    return MyActionResponse(
        incident_id=incident_id,
        status="RESOLVED",
        message="Action completed."
    )
```

---

## How to Tune Investigation Parameters

```bash
# .env

# Reduce investigation frequency to save API budget
INVESTIGATION_INTERVAL_SEC=1800  # one investigation per 30 minutes

# More investigations per day (burns budget faster)
INVESTIGATION_INTERVAL_SEC=300   # one investigation per 5 minutes

# Change LLM provider
LLM_PROVIDER=openai              # claude | openai | gemini

# Override model for specific tier (leave empty for provider defaults)
LLM_MODEL_PRIMARY=gpt-4o-mini   # investigation agent
LLM_MODEL_FAST=gpt-4o-mini      # CVE analysis (fast/cheap)
LLM_MODEL_ANALYSIS=gpt-4o-mini  # daily reports

# Inference temperature
LLM_TEMPERATURE=0.2              # 0.0 = deterministic, 1.0 = creative
```

---

## How to Tune RAG Parameters

```bash
# .env

# More sensitive anomaly detection (more alerts, more false positives)
RLM_ANOMALY_THRESHOLD=0.55

# Less sensitive (fewer alerts, fewer false positives)
RLM_ANOMALY_THRESHOLD=0.75

# Faster profile learning (reacts faster, less stable)
RLM_ALPHA=0.2

# Disable embedding cache (for debugging only)
EMBED_CACHE_TTL_SEC=0

# Force MITRE re-embed more frequently (for development)
MITRE_REEMBED_INTERVAL_DAYS=1

# Extend profile retention
PROFILE_TTL_DAYS=60
```

After changing `.env`, restart affected services:
```bash
docker compose up -d rlm-engine
docker compose up -d scraper
```

---

## Code Style

- **Python:** Type hints on all function signatures. Docstrings on all public functions. Use `get_logger(__name__)` from `src/core/logger.py`.
- **No hardcoded values:** All thresholds, timeouts, and configuration belong in `src/core/config.py` read from environment variables.
- **No direct `os.getenv()` calls** outside `config.py`.
- **Embedder governance:** Never call `ChromaDB.upsert()` directly. Always use `batch_upsert()` from `src/ingestion/embedder.py`.
- **No `DefaultEmbeddingFunction()`** — always use `get_embedding_function()` from `src/ingestion/embedder.py`.
- **Pipeline separation:** Never add code that bridges the simulator path into `raw-packets`. Simulator events belong in `threat-alerts` only.
- **React:** Functional components only. Inline CSS. No UI libraries except Recharts. Access host profile data as `hostProfile.profile?.{metric}` (nested structure).

## Commit Message Convention

```
feat: add detect_dns_tunneling() to dpi/detectors.py
fix: gateway.py — correct hosts response to use nested profile.anomaly_score
refactor: mcp_orchestrator — compress _summarize_result output further
docs: update PIPELINES.md with new simulator scenario
test: add 3 tests for detect_external_db_access()
chore: update n8n workflow 01 to use new Jira field format
```

---

## Debugging Tips

```bash
# Watch all service logs
docker compose logs -f

# Watch specific service
docker compose logs -f mcp-orchestrator
docker compose logs -f rlm-engine
docker compose logs -f traffic-simulator

# Check investigation efficiency (should show "1 LLM call")
docker compose logs mcp-orchestrator | grep "1 LLM call"

# Check resource usage
docker stats --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'

# Connect to PostgreSQL
docker exec -it cybersentinel-postgres psql -U sentinel -d cybersentinel

# Check SOC summary
SELECT * FROM soc_summary;

# Check block recommendations
SELECT incident_id, title, block_target_ip, severity
FROM incidents
WHERE block_recommended = TRUE AND status = 'OPEN'
ORDER BY severity DESC;

# Check behavior_profiles (will be empty/zeros if simulator-only)
SELECT entity_id, observation_count, anomaly_score, avg_bytes_per_min
FROM behavior_profiles
ORDER BY anomaly_score DESC
LIMIT 10;

# Connect to Redis CLI
docker exec -it cybersentinel-redis redis-cli -a $REDIS_PASSWORD

# Check blocked IPs
KEYS blocked:*

# Check embedding cache size
KEYS embed_cache:* | wc -l

# Full reset (deletes all data)
bash scripts/setup/reset.sh
```

---

## Common Issues

### "Behavior profile shows all zeros"
Expected when using the traffic simulator. The RLM engine only reads from `raw-packets`. The simulator writes to `threat-alerts`. Real packet capture is required for behavioral profiling. See `docs/PIPELINES.md`.

### "Container using old code after rebuild"
```bash
# Stop and remove the container, then rebuild
docker stop cybersentinel-mcp && docker rm cybersentinel-mcp
docker compose up -d --build mcp-orchestrator
```

### "investigation_summary or block_recommended column does not exist"
Run the live migration:
```sql
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS investigation_summary TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip TEXT;
```

### "Gemini returns finish_reason:12"
Gemini's safety filter blocks security-related content. Use `LLM_PROVIDER=openai` or `LLM_PROVIDER=claude` instead.

### "Token usage higher than expected"
Check `INVESTIGATION_INTERVAL_SEC` — if set too low, many investigations run per hour. With `INVESTIGATION_INTERVAL_SEC=1800`, ~48 investigations/day at ~$0.008/day on GPT-4o mini.

---

*Contributing Guide — CyberSentinel AI v1.1 — 2025/2026*
