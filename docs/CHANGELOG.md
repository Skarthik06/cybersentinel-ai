# Changelog

All notable changes and architectural decisions are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.3.0] — 2026-04-18 — Detection Hardening + Security + Documentation

### Added — IPv6 Support

**Change:** `BPF_FILTER` updated from `ip` to `ip or ip6`.

The DPI sensor (`src/dpi/sensor.py`) now captures and parses both IPv4 and IPv6 packets. All 21 `PacketEvent` fields support IPv6 addresses. The BPF filter in `docker-compose.yml` also excludes Docker-internal virtual traffic (172.17–21.x) while capturing real host traffic.

---

### Added — GDPR PII Masking in DPI Sensor

**Change:** `_mask_pii()` static method added to `DPISensor` in `src/dpi/sensor.py`.

Called on every `PacketEvent` before publishing to Kafka. Redacts:
- Email addresses in `dns_query`, `http_uri`, `user_agent` → `[email-redacted]`
- Credential parameters (`password=`, `token=`, `api_key=`, `secret=`, `authorization=`) → `param=[redacted]`

No PII reaches Kafka, PostgreSQL, ChromaDB, or any LLM prompt.

---

### Added — IsolationForest Sequence Anomaly Detection

**Change:** `SequenceAnomalyDetector` class added to `src/models/rlm_engine.py`. Applied in `RLMEngine._score_and_alert()`.

The RLM engine now uses a two-layer scoring approach:

```
Layer 1 (ChromaDB):   cosine similarity against threat signatures → base_score
Layer 2 (IsolationForest): 50-observation rolling buffer per IP → blend 25% weight
Final score = 0.75 × base_score + 0.25 × IsolationForest score
```

This detects anomalous *progressions* — a slow ramp like `[0.30, 0.33, 0.37, 0.41, 0.46]` is flagged even though no single value crosses the 0.40 threshold. Requires 10 samples before blending begins; falls back to raw ChromaDB score during cold start.

`scikit-learn==1.4.2` added to `docker/Dockerfile.rlm`.

---

### Added — Kill Chain / Campaign Tracking

**Change:** `_correlate_campaign_with_pool()` added to `src/agents/mcp_orchestrator.py`. New SQL migration `scripts/db/migrate_campaigns.sql`.

Every incident is automatically correlated with an attacker campaign:
- Same `src_ip` within 24 hours → same campaign
- Campaign tracks `incident_count`, `max_severity`, `mitre_stages[]`, `first_seen`, `last_seen`
- Correlation runs as a fire-and-forget `asyncio.ensure_future()` — does not block incident creation

New endpoint: `GET /api/v1/campaigns` — returns all campaigns ordered by `last_seen DESC`.

New database tables: `attacker_campaigns`, `campaign_incidents`.

---

### Fixed — Cache Thundering-Herd Bug

**Problem:** `threat_intel_updated:*` keys were set by the embedder when CTI was updated but were never deleted after the RLM engine consumed them. This caused all behavioral profiles to bypass the Redis embedding cache for the full 3600-second TTL every time CTI was refreshed — creating a CPU/DB load spike.

**Fix:** RLM engine now deletes `threat_intel_updated:threat_signatures`, `threat_intel_updated:cti_reports`, and `threat_intel_updated:cve_database` immediately after consuming them. Cache is invalidated cleanly once per update.

---

### Fixed — Kafka Permanent Restart Fix (Docker Compose)

**Problem:** After ZooKeeper was restarted, Kafka's stored `meta.properties` in the `kafka_data` volume contained the old cluster ID. The broker crashed immediately on startup with `InconsistentClusterIdException`.

**Fix:** The `kafka` service in `docker-compose.yml` now runs:
```bash
(zookeeper-shell zookeeper:2181 delete /brokers/ids/1 2>/dev/null || true) && /etc/confluent/docker/run
```
This cleans up stale ZooKeeper broker registrations before starting. When volume conflicts occur, the `kafka_data` volume can be removed with `docker volume rm cybersentinel-ai_kafka_data`.

---

### Reverted — Kubernetes Migration (ADR-016 Reversed)

**What was attempted:**
A complete Kubernetes migration was built — `k8s/` directory with 15 manifests, StatefulSets, DaemonSet, HPA, PersistentVolumeClaims, and `scripts/k8s/apply-env.sh`.

**Why it was reverted:**
Kafka SASL/SCRAM-SHA-256 was required for the Kubernetes security posture. The Confluent Docker image (`confluentinc/cp-kafka:7.5.0`) has an irresolvable conflict between its `ClusterStatus` pre-flight ZooKeeper check and SASL configuration:

- With JAAS file in `KAFKA_OPTS`: pre-flight times out waiting for `SaslAuthenticated` state (ZooKeeper has no SASL)
- Without JAAS file: broker fails — `Could not find a 'KafkaServer' entry in the JAAS configuration`

All known workarounds were attempted (per-listener JAAS env vars, `KAFKA_ZOOKEEPER_SASL_ENABLED=false`, `-Dzookeeper.sasl.client=false`). None resolved the conflict. The bitnami/kafka image does not have this pre-flight limitation and is the recommended path for future Kubernetes + SASL deployment.

**Decision:** Reverted to Docker Compose (14 containers) with PLAINTEXT Kafka. The Docker Compose architecture is functionally complete and production-quality for a single-node deployment.

**ADR-016 status:** Reversed — Kubernetes migration deferred pending bitnami/kafka evaluation.
**ADR-017 status:** Reversed — `kafka-meta-cleanup` init container removed (Kubernetes-specific).

---

### Added — DB Migrations

New files: `scripts/db/migrate_campaigns.sql`, `scripts/db/migrate_multitenancy.sql`

**migrate_campaigns.sql:**
```sql
CREATE TABLE IF NOT EXISTS attacker_campaigns (
    campaign_id    TEXT PRIMARY KEY,
    src_ip         TEXT NOT NULL,
    first_seen     TIMESTAMPTZ,
    last_seen      TIMESTAMPTZ,
    incident_count INTEGER,
    max_severity   TEXT,
    mitre_stages   TEXT[],
    campaign_summary TEXT
);

CREATE TABLE IF NOT EXISTS campaign_incidents (
    campaign_id TEXT REFERENCES attacker_campaigns,
    incident_id TEXT REFERENCES incidents,
    PRIMARY KEY (campaign_id, incident_id)
);
```

**migrate_multitenancy.sql:** Adds `tenant_id VARCHAR(80) NOT NULL DEFAULT 'default'` to `alerts`, `incidents`, `behavior_profiles`, `firewall_rules`, `packets`. Creates `tenants` registry table.

---

### Changed — Documentation Complete Rewrite

All documentation files rewritten for v1.3.0:
- All Kubernetes references removed — `DEPLOYMENT_PLAN.md`, `RUNNING.md`, `ARCHITECTURE.md`, `MASTER.md`, `LIVE_DPI_SETUP.md`, `TRD.md`, `PROJECT.md`, `DATABASE.md`, `CHANGELOG.md` updated for Docker Compose
- `LIMITATIONS.md` updated with accurate fix status (K8s reverted)
- `LIMITATIONS_FIXES.md` completely rewritten to reflect actual implementation state
- All Mermaid diagrams updated for Docker Compose topology
- Kubernetes-specific files (`k8s/` directory, `docker-compose.access.yml`) kept in repo but removed from documentation as the primary deployment path

---

## [1.2.2] — 2026-04-11 — Infrastructure Fixes + N8N Automation + Operations Documentation

### Fixed — Grafana Container: Exit Code 1 on Startup

**Problem:** `GF_INSTALL_PLUGINS` caused Grafana to attempt a DNS lookup to `grafana.com` during container init. Inside the Docker network this lookup fails — Grafana exits immediately.

**Fix:** Removed `GF_INSTALL_PLUGINS` from `docker-compose.yml`.

---

### Fixed — N8N Not Reachable from API Container

**Problem:** N8N container started outside `docker compose` was on the default bridge network, not on `cybersentinel-ai_cybersentinel-net`.

**Fix:** `docker network connect cybersentinel-ai_cybersentinel-net N8N`. Now handled by `scripts/start_n8n.ps1`.

---

### Fixed — N8N Workflow Activation: Inactive After Import

**Problem:** After `n8n import:workflow`, all 5 workflows were left with `active=0`, `activeVersionId=NULL`, and no rows in `workflow_published_version`. All webhook endpoints returned 404.

**Fix:** `scripts/activate_n8n_workflows.py` automatically repairs all three conditions via direct SQLite manipulation.

---

### Fixed — N8N Env Vars Blocked in Workflow Nodes

**Problem:** n8n 2.15+ defaults `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` — all `$env.OPENAI_API_KEY` references silently fail.

**Fix:** Recreate N8N container with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`. Set in `scripts/start_n8n.ps1`.

---

### Fixed — SLA Watchdog (WF04): Auth Node 422 Error

**Problem:** n8n 2.15 HTTP Request node (typeVersion 4.2) no longer accepts raw URL-encoded strings for form bodies.

**Fix:** Changed auth node to use structured `bodyParameters`.

---

### Fixed — API Gateway: Workflow Triggers Returned 500

**Problem:** `httpx.AsyncClient(timeout=10)` timed out on OpenAI calls (18–27s). `TimeoutException` propagated as unhandled 500.

**Fix:** Timeout raised to 90 seconds. `TimeoutException` now returns 200 (workflow running, not failed).

---

### Added — N8N Workflow Activation Script, Start Script, Operations Guide

See `scripts/activate_n8n_workflows.py`, `scripts/start_n8n.ps1`, `docs/N8N_OPERATIONS.md`.

---

## [1.2.1] — 2026-04-08 — N8N Workflow Fixes + SLA + Board Report

### Fixed — N8N Code Nodes: HTTP Calls Blocked by JS Task Runner Sandbox

**Problem:** n8n 2.15 strict JS sandbox blocks all outbound HTTP inside Code nodes.

**Fix:** Replaced Code node LLM calls with dedicated HTTP Request nodes (typeVersion 4.2).

---

### Fixed — SLA Watchdog: "Open Incidents: 0" When 900+ Incidents Exist

**Problem:** `$input.first().json.incidents` was undefined because n8n splits JSON arrays into multiple items.

**Fix:** Changed to `$input.all()` to collect all split items.

---

### Fixed — Board Report: CRITICAL/HIGH Open Always 0

**Root causes:**
1. Wrong dashboard URL (`/api/v1/dashboard/stats` → 404)
2. Wrong field names (`stats.total_alerts` → `stats.total_alerts_24h`)
3. Same n8n array-splitting issue as SLA Watchdog

---

## [1.2.0] — 2026-04-06 — Pipeline Unification + UX Overhaul + Investigation Quality

### Changed — Traffic Simulator: Full DPI Pipeline

**Problem (v1.1):** Simulator published pre-formed alerts directly to `threat-alerts`, bypassing the RLM engine entirely. Behavioral profiles stayed at zero.

**Solution:** Simulator now publishes bursts of 30–150 raw `PacketEvent` dicts to `raw-packets`. Every simulated scenario passes through the full pipeline: RLM profiling → ChromaDB scoring → anomaly detection → AI investigation.

---

### Changed — AI Investigation: Structured 4-Part Analysis

System prompt updated to require: `OBSERVED` / `WHY SUSPICIOUS` / `THREAT ASSESSMENT` / `ATTACKER PROFILE` in every investigation summary.

---

### Changed — Remediation: Separated as Technical Playbook

Remediation separated from investigation summary. Generated on demand via `POST /api/v1/incidents/{id}/remediation`.

---

### Added — Active Incidents Panel + Firewall Rules Panel in RESPONSE Tab

Active Incidents panel: all `status='OPEN'` incidents as clickable cards.
Firewall Rules panel: all currently blocked IPs with UNBLOCK button.

---

### Fixed — block_recommended Logic for Pending Incidents

CRITICAL and HIGH pending incidents now correctly appear in Block Recommendations panel.

---

### Added — Source Isolation for AI Investigation Pausing

`investigations:paused:simulator` and `investigations:paused:dpi` Redis keys allow per-source pausing.

---

## [1.1.0] — 2026-03-28/29 — Investigation Optimization + Human-in-the-Loop Response

### Changed — AI Investigation Pipeline (Major Optimization)

Replaced 3-call agentic loop with stateless 1-call pipeline:
- `tools=None` — no tool schemas in prompt
- `_summarize_result()` — compress each tool result to 1–3 lines
- `asyncio.gather()` — all 4 intel tools in parallel
- `alert_slim` stripping — remove `raw_event` field
- `max_tokens=1024` — reduced from 4096

**Result:** 3 API calls → 1. ~5,500 tokens → ~553. Cost ~90% lower.

---

### Added — Human-in-the-Loop Block Recommendations

- `block_recommended` + `block_target_ip` fields in `incidents` table
- `GET /api/v1/block-recommendations` endpoint
- `POST /api/v1/incidents/{id}/block` — analyst approves
- `POST /api/v1/incidents/{id}/dismiss` — analyst dismisses
- RESPONSE tab in SOC Dashboard

---

### Added — Traffic Simulator Service

17 threat scenarios (12 MITRE-mapped + 5 unknown). Upgraded to full DPI pipeline in v1.2.

---

### Added — Multi-Provider LLM Abstraction

`src/agents/llm_provider.py` — supports Claude (Anthropic), OpenAI, and Gemini. Switch via `LLM_PROVIDER` env var.

---

## [1.0.0] — 2025-03-21 — Initial Production Release

### Added

- DPI sensor with Scapy-based packet capture (`src/dpi/sensor.py`)
- 8 detection functions (`src/dpi/detectors.py`)
- RLM behavioral profiling engine with EMA (`src/models/rlm_engine.py`)
- BehaviorProfile dataclass with `to_text()` and ChromaDB embedding
- 8 threat signature seeds (MITRE T1071.001 through T1090.003)
- MCP Orchestrator with AI investigation pipeline
- CTI scraper for NVD, CISA, Abuse.ch, MITRE, OTX
- FastAPI REST gateway with JWT authentication
- React SOC Dashboard with 6 tabs
- n8n SOAR with 5 workflow playbooks
- PostgreSQL + TimescaleDB schema with hypertable, compression, retention
- Prometheus + Grafana observability stack
- 27 unit tests for DPI detectors + 5 for BehaviorProfile EMA

---

## Architectural Decisions

### ADR-001: Event-Driven Architecture via Kafka
All inter-service communication in the detection pipeline goes through Kafka topics. Independent scaling, guaranteed delivery, replay capability.

### ADR-002: EMA for Behavioral Profiling
Exponential Moving Average for all profile fields. O(1) memory per host, natural decay of old patterns, online learning without labels.

### ADR-003: Natural Language as Embedding Input
Convert numerical BehaviorProfile fields to English prose before embedding. Pre-trained NLP models understand semantic relationships in natural language better than raw numbers.

### ADR-004: Local Embedding Model
`all-MiniLM-L6-v2` via sentence-transformers. Zero cost, no rate limits, no data leaving the deployment.

### ADR-005: Severity Gate for LLM API
Only HIGH and CRITICAL alerts invoke the LLM. Cuts LLM costs ~90% while ensuring every serious threat gets AI reasoning.

### ADR-006: n8n for SOAR
Visual workflow canvas, version-controllable JSON exports, 400+ native integrations.

### ADR-007: ChromaDB over FAISS or Weaviate
Docker-native, Python-native, collection-level metadata, handles < 1M vectors well.

### ADR-008: Multi-Provider LLM Abstraction
Abstract all LLM calls behind `LLMProvider` interface. API availability, cost, and rate limits differ by region/account.

### ADR-009: Human-in-the-Loop for IP Blocking
Replace auto-block with analyst-reviewed block recommendations. AI recommends, human approves — SOAR best practice.

### ADR-010: Stateless 1-Call Investigation Pipeline
Replace 3-call agentic loop with single LLM call. 90% token reduction, same investigation quality.

### ADR-011: Simulator Feeds Full DPI Pipeline
Traffic Simulator publishes raw PacketEvents to `raw-packets`, not pre-formed alerts. Bypassing RLM left behavioral profiles at zero.

### ADR-012: Structured 4-Part AI Investigation Format
Mandate OBSERVED / WHY SUSPICIOUS / THREAT ASSESSMENT / ATTACKER PROFILE. Structured format for fast analyst extraction.

### ADR-013: Pending Incidents When AI Is Paused
Create `OPEN` incident when AI is paused, with `block_recommended=True` for CRITICAL/HIGH. Alerts never silently dropped.

### ADR-014: IsolationForest Sequence Layer
Add IsolationForest on 50-observation rolling buffer per IP to detect gradual score progressions that never cross the threshold individually.

### ADR-015: PostgreSQL for Campaign Tracking
Use `attacker_campaigns` + `campaign_incidents` adjacency tables instead of a graph database. 24h correlation window via SQL is efficient and avoids Neo4j dependency.

### ADR-016: Kubernetes Migration — REVERSED
Kubernetes was built (15 manifests, StatefulSets, DaemonSet, HPA) but reverted. Root cause: Confluent Docker `ClusterStatus` pre-flight check is irreconcilable with SASL on non-SASL ZooKeeper. Deployment reverted to Docker Compose (14 containers). Future path: bitnami/kafka image removes this constraint.

### ADR-017: Kafka meta.properties Cleanup — REVERSED
The `kafka-meta-cleanup` init container was specific to the Kubernetes deployment (ADR-016). Reverted along with ADR-016. Docker Compose equivalent: `docker volume rm cybersentinel-ai_kafka_data` when `InconsistentClusterIdException` occurs.

---

*Changelog — CyberSentinel AI v1.3.0 — 2025/2026*
