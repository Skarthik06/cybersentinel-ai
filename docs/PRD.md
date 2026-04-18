# Product Requirements Document (PRD)

**Project:** CyberSentinel AI
**Version:** 1.3.0
**Status:** Production Ready
**Date:** 2025/2026

---

## 1. Executive Summary

CyberSentinel AI is an autonomous Security Operations Centre platform that augments human analyst capacity with AI-driven detection, investigation, and human-in-the-loop response. The platform targets enterprise security teams who face an impossible workload — hundreds of alerts per day, 194-day average breach detection time, and a global cybersecurity workforce shortage.

The core value proposition: **a threat detected by the DPI sensor is investigated by AI and presented to the analyst as a structured block recommendation within 60 seconds — the analyst approves or dismisses with one click.**

---

## 2. Problem Statement

### 2.1 The SOC Crisis

| Metric | Data |
|--------|------|
| Alert volume growth | 30% year-over-year as networks expand |
| False positive rate | ~95% of alerts are noise |
| Average breach detection time | 194 days (IBM Security, 2024) |
| Average breach cost | $4.45 million |
| Ransomware frequency | Executes every 11 seconds globally |

SOC teams burn out at high rates due to repetitive triage work. The problem is not lack of data — it is lack of intelligent filtering and structured action.

### 2.2 What Existing Tools Don't Solve

| Tool Type | Limitation |
|-----------|-----------|
| Signature-based IDS (Snort, Suricata) | Only detects known attacks — blind to zero-days |
| Commercial SIEM (Splunk, QRadar) | Expensive, requires manual rule authoring, high false positive rate |
| Traditional SOAR | Executes pre-written playbooks — cannot reason about novel threats |
| ML-based IDS | Requires labelled training datasets — cannot adapt online |
| Auto-blocking systems | False positives block legitimate services — no human oversight |

---

## 3. Target Users

### Primary User: SOC Analyst (Tier 1–2)

**Goals:**
- Quickly triage alerts without switching between 8 tools
- Understand the context of a threat in one place
- Have repetitive actions (investigation, evidence gathering) done automatically
- Review AI block recommendations and act with one click

**Pain Points:**
- Alert fatigue from hundreds of notifications per shift
- Manual cross-referencing between SIEM, threat intel, ticketing, and comms tools
- Fear of auto-blocking legitimate IPs — needs human approval gate

### Secondary User: CISO / Security Leadership

**Goals:**
- Executive visibility into security posture
- Evidence of security ROI for board reporting
- Compliance documentation

**Pain Points:**
- No single source of truth for security metrics
- Board reports require hours of manual data gathering

### Tertiary User: Security Engineer / Platform Admin

**Goals:**
- Deploy, configure, and extend the platform
- Integrate with existing enterprise toolchain
- Monitor platform health and LLM cost

---

## 4. Product Goals

### 4.1 Detection Goals

| Goal | Target | Measure |
|------|--------|---------|
| Packet-level detection latency | < 1 second | Time from packet arrival to alert |
| MITRE ATT&CK coverage | 15 techniques | Technique IDs covered |
| DPI signal accuracy | > 90% precision | True positive / (true positive + false positive) |
| Behavioral anomaly detection | Online, zero-label | No training dataset required |

### 4.2 Investigation Goals

| Goal | Target | Measure |
|------|--------|---------|
| AI investigation time | < 45 seconds | Alert receipt to verdict |
| LLM tokens per investigation | < 600 | Measured via API usage |
| LLM API calls per investigation | 1 | Stateless 1-call pipeline |
| Input:Output token ratio | ≤ 3:1 | Efficient prompt construction |

### 4.3 Response Goals

| Goal | Target | Measure |
|------|--------|---------|
| Block recommendation visibility | < 30 seconds after incident | RESPONSE tab poll interval |
| Human-in-the-loop latency | < 30 seconds for analyst action | Dashboard responsiveness |
| False positive protection | Zero automated blocks | All blocks require analyst approval |
| Audit trail completeness | 100% of block/dismiss actions | audit_log table entries |

### 4.4 Reporting Goals

| Goal | Target | Measure |
|------|--------|---------|
| Daily SOC report | 7AM Mon–Fri | Automated, zero manual effort |
| Weekly board report | Monday 8AM | AI-generated, board-ready |
| CVE patch notification | Within 4 hours of NVD publication | Automated Jira ticket |
| SLA breach response | < 15 min for CRITICAL | PagerDuty page sent |

---

## 5. Feature Requirements

### 5.1 Core Detection (Must Have)

**F-001: Deep Packet Inspection**
- Capture all IP traffic on a specified network interface via Scapy
- Extract 21-field PacketEvent: IPs, ports, protocol, payload size, entropy, TTL, DNS query, HTTP metadata, TLS presence, session fingerprint
- Detect 8 threat signals: high entropy, suspicious ports, DGA, C2 beaconing, cleartext credentials, TTL anomaly, malware user agents, external DB access
- Stream all packet events to Kafka `raw-packets` topic
- Suspicious packets additionally emit to `threat-alerts` immediately

**F-002: Behavioral Profiling (RLM Engine)**
- Consumes `raw-packets` Kafka topic exclusively (not simulator events)
- Build per-host behavioral profiles using Exponential Moving Average (α=0.1, configurable)
- Update profiles on every packet — no batch processing, no raw storage
- Convert profiles to natural language text (`to_text()`) and embed via all-MiniLM-L6-v2
- Score anomalies via cosine similarity against 8 threat signature vectors
- Emit anomaly alerts when score > configurable threshold (default: 0.65)
- Gate scoring until minimum observations reached (default: 20)
- Persist profiles to PostgreSQL every 300 seconds
- **Note:** Profile metrics will be 0 for IPs that only appear in simulator events — this is expected behavior

**F-003: Traffic Simulator**
- Generate synthetic threat events for testing without real network traffic
- 17 threat scenarios: 12 MITRE-mapped + 5 unknown novel threats (AI must classify)
- Publish raw PacketEvent bursts (30–150 packets) to `raw-packets` Kafka topic — full DPI pipeline (v1.2)
- Configurable rate via `SIMULATION_RATE` env var (default: 2/minute)
- Each burst clears the RLM min_observations gate; builds real behavioral profiles
- Enables testing of full platform including RLM profiling without Npcap

**F-004: Threat Intelligence Ingestion**
- Harvest CVEs from NIST NVD every 4 hours (CVSS ≥ 7.0)
- Harvest CISA KEV every 6 hours (actively exploited)
- Harvest Abuse.ch Feodo botnet C2 IPs every hour
- Harvest MITRE ATT&CK technique catalog at most weekly (re-embed guard)
- Harvest AlienVault OTX pulses every 2 hours (when API key provided)
- Embed all intel into ChromaDB with source + model provenance metadata

### 5.2 AI Investigation (Must Have)

**F-005: Multi-Provider LLM Investigation**
- Supports three LLM providers switchable via `LLM_PROVIDER` env var: `claude`, `openai`, `gemini`
- All providers abstracted behind unified interface in `src/agents/llm_provider.py`
- Stateless **1-call investigation pipeline** (not multi-round agentic loop):
  1. `asyncio.gather()` — 4 intel tools run in parallel (zero LLM calls)
  2. `_summarize_result()` — compress each result to essential facts
  3. Single LLM call — compact context → JSON verdict
  4. Parse JSON → `_create_incident()` directly from code
- Token target: < 600 tokens per investigation (~553 actual)
- API call target: 1 per investigation (not 3)
- Cost target: < $0.0002 per investigation (gpt-4o-mini)
- 9 MCP tools available for the evidence-gathering phase (executed before LLM call)
- Only HIGH and CRITICAL alerts trigger AI investigation (cost gate)
- Exponential backoff retry on rate limits: 5s → 15s → 45s

**F-006: Human-in-the-Loop Block Recommendations**
- Replace auto-block with analyst-reviewed recommendations
- AI sets `block_recommended=True` for CRITICAL alerts or explicit AI verdict
- `block_target_ip` stored per incident
- `GET /api/v1/block-recommendations` returns all pending recommendations
- `POST /api/v1/incidents/{id}/block` — analyst approves: executes Redis + PostgreSQL block, marks RESOLVED
- `POST /api/v1/incidents/{id}/dismiss` — analyst dismisses: marks RESOLVED without blocking
- All actions logged to `audit_log` table
- No automated blocking under any circumstance

### 5.3 SOAR Automation (Must Have)

**F-007: n8n Workflow Automation**
- Workflow 01: Critical Alert SOAR — enrichment, Jira ticket, notifications (note: no auto-block in workflow; block handled via human-in-the-loop dashboard)
- Workflow 02: Daily SOC Report — AI-generated analyst briefing every weekday morning
- Workflow 03: CVE Intel Pipeline — CVE analysis with fast LLM, patch ticket creation
- Workflow 04: SLA Watchdog — 15-minute checks, breach escalation to PagerDuty + ServiceNow
- Workflow 05: Weekly Board Report — 9-section executive report using primary LLM tier

**F-008: Kafka–n8n Bridge**
- Translate Kafka events to n8n webhook calls
- Route by event type and severity to appropriate webhook path
- Redis-based deduplication (60-second window)
- Exponential backoff retry (3 attempts) on n8n unavailability

### 5.4 SOC Dashboard (Must Have)

**F-009: React Frontend — 6 Tabs**

| Tab | Features |
|-----|---------|
| OVERVIEW | 6 KPI metric cards, risk gauge (0–100%), 24h alert timeline, platform health radar |
| ALERTS | Paginated table, severity badges, anomaly score bars, MITRE tags, investigation summaries |
| INCIDENTS | Full lifecycle management, OPEN/INVESTIGATING/RESOLVED/CLOSED, incident detail drawer |
| RESPONSE | **Block Recommendations panel** — BLOCK IP and DISMISS buttons, 30s auto-poll, 3 metric cards |
| THREAT INTEL | ChromaDB semantic search (results show document + similarity % + MITRE + severity), MITRE coverage map |
| HOSTS | IP lookup: RLM profile (nested `profile.*`), block status, block count, incident count, recent alerts |

**RESPONSE tab requirements:**
- Always visible even when no recommendations pending (shows empty state)
- Shows count badge on tab when recommendations > 0
- Polls `GET /api/v1/block-recommendations` every 30 seconds
- BLOCK IP button calls `POST /api/v1/incidents/{id}/block`
- DISMISS button calls `POST /api/v1/incidents/{id}/dismiss`
- Both actions refresh the recommendations list immediately

**Hosts tab requirements:**
- Profile metrics accessed as `hostProfile.profile?.{metric}` (not `hostProfile.{metric}`)
- Profile note shown from `profile_text` column (not `note`)
- Shows BLOCKED (YES/NO), BLOCK EVENTS count, LINKED INCIDENTS count
- Shows RECENT ALERTS section with severity badge, type, MITRE, timestamp
- Profile metrics (anomaly score, bytes, entropy, observations) will be 0 for simulator-only IPs

**Threat Intel tab requirements:**
- Search results rendered as `{document, similarity, metadata}` objects (not raw JSON)
- Similarity shown as percentage badge
- MITRE technique badge per result
- Empty state shown when no results found

**F-010: REST API**
- JWT authentication with bcrypt password verification
- Role-based access: admin, analyst, responder, viewer
- 11 endpoints (see `docs/API_REFERENCE.md` for full specification)
- Auto-generated Swagger documentation at `/docs`

### 5.5 Observability (Should Have)

**F-011: Grafana + Prometheus**
- Prometheus scrapes metrics from all services every 15 seconds
- Alerting rules: service down, Kafka consumer lag > 1000, high alert volume
- Grafana datasources: Prometheus + PostgreSQL

### 5.6 Enterprise Integrations (Should Have)

**F-012: Integration Catalog**
- Slack, PagerDuty, Jira, MS Teams, ServiceNow, Email (SMTP), Telegram, AbuseIPDB

---

## 6. Non-Functional Requirements

### 6.1 Performance

| Requirement | Target |
|-------------|--------|
| Packet capture throughput | ≥ 10,000 pkt/s |
| Kafka end-to-end latency | < 100ms |
| RLM profile update | < 10ms per packet |
| ChromaDB query latency | < 200ms |
| FastAPI response time (P95) | < 500ms |
| AI investigation (1-call) | < 45 seconds |
| Block recommendations poll | 30 seconds |

### 6.2 LLM Cost Efficiency

| Requirement | Target |
|-------------|--------|
| Tokens per investigation | < 600 (target ~553) |
| API calls per investigation | 1 |
| Input:Output ratio | ≤ 3:1 |
| Cost per investigation (GPT-4o mini) | < $0.0002 |
| Budget runway on $5 | > 25,000 investigations |

### 6.3 Security

- All secrets via environment variables — none hardcoded in source
- JWT_SECRET validated at startup — service refuses to start if missing
- Passwords hashed with bcrypt (work factor 12)
- All IP block decisions require human analyst approval (no auto-blocking)
- All block/dismiss actions logged to `audit_log` with username and timestamp
- CORS configurable via `CORS_ORIGINS` environment variable
- Redis and PostgreSQL password-protected
- ChromaDB token-authenticated

### 6.4 Reliability

- All Docker services have healthcheck definitions
- Kafka consumer groups enable restart without message loss
- PostgreSQL uses asyncpg connection pool (min 5, max 20)
- n8n bridge uses exponential backoff retry (3 attempts)
- Investigation interval configurable (`INVESTIGATION_INTERVAL_SEC=1800`) to prevent rate-limit bursts

### 6.5 Deployment

- Single command startup: `bash scripts/setup/install.sh`
- Works on Windows (WSL2), macOS, and Linux
- Minimum hardware: 16 GB RAM, 4 CPU cores, 8 GB disk
- Frontend: `cd frontend && npm install && npm run dev` (Node.js 18+)

---

## 7. Out of Scope (v1.x)

- Multi-tenant SaaS deployment
- Kubernetes orchestration
- EDR integration (CrowdStrike, SentinelOne)
- ZTNA policy enforcement
- Mobile app for executives
- Active directory / identity intelligence
- Endpoint agent deployment
- Fully automated IP blocking (by design — human-in-the-loop is a feature, not a limitation)

---

## 8. Success Criteria

The project is considered successful when:

1. All 14 Docker containers start healthy via `install.sh`
2. A test packet with suspicious characteristics triggers a HIGH/CRITICAL alert within 5 seconds
3. The AI investigation completes with 1 LLM call and produces a structured JSON verdict
4. The block recommendation appears in the RESPONSE tab within 30 seconds of incident creation
5. Analyst clicks BLOCK IP → IP is blocked in Redis and PostgreSQL → incident marked RESOLVED
6. Analyst clicks DISMISS → incident marked RESOLVED, no block executed
7. The n8n Workflow 01 executes end-to-end (enrichment → Jira → notify)
8. Workflow 02 delivers a daily SOC report at 7AM
9. The React dashboard loads with all 6 tabs showing live data from the API
10. All 27 unit tests pass without external dependencies
11. The health endpoint returns `{"status": "healthy"}` for all checks
12. Token usage per investigation ≤ 600 tokens (verified via API provider dashboard)

---

*Product Requirements Document — CyberSentinel AI v1.3.0 — 2025/2026*
