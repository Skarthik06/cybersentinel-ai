# SOAR Workflows

**CyberSentinel AI — n8n Workflow Specifications**

Five production workflows covering the complete SOC automation cycle.
All workflow JSON files are in `n8n/workflows/` — import directly into n8n.

---

## How n8n Fits the Architecture

n8n sits at Layer 3 (Orchestration) and receives events via the Kafka Bridge — a Python service that translates Kafka topic messages into HTTP webhook calls.

```
Kafka (threat-alerts, incidents, cti-updates)
    │
    ▼ n8n Kafka Bridge (n8n/bridge/kafka_bridge.py)
    │ Routes by: topic + severity + event type
    │ Deduplicates: Redis SHA-256, 60s window
    │
    ▼ n8n Webhooks
    │
    ▼ Workflow execution
    │
    ▼ Enterprise tools: Slack, PagerDuty, Jira, Teams, ServiceNow, Email, Telegram
```

**Note on auto-blocking in n8n:** Workflow 01 previously included an auto-block step. As of v1.1, IP blocking is handled through the human-in-the-loop RESPONSE tab in the dashboard (`POST /api/v1/incidents/{id}/block`). Workflow 01 still handles enrichment, incident creation, and notifications — but does not automatically execute IP blocks.

---

## Importing Workflows

**Method A — n8n UI (recommended):**
1. Open `http://localhost:5678`
2. Workflows → + Add Workflow → ⋮ → Import from File
3. Select the JSON file → Save → toggle Active ON
4. Repeat for all 5

**Method B — n8n CLI (inside Docker):**
```bash
docker exec -it cybersentinel-n8n \
  n8n import:workflow --separate \
  --input=/home/node/.n8n/workflows/
```

**After importing — required credential setup:**
Each workflow contains HTTP Request nodes that need credentials. Open each node and set the credential values (Slack webhook URL, PagerDuty API key, Jira token, etc.) from your `.env` file.

---

## Workflow 01 — Critical Alert SOAR Playbook

**File:** `01_critical_alert_soar.json`
**Trigger:** Kafka webhook — CRITICAL and HIGH severity alerts
**Purpose:** Full automated enrichment, Jira ticketing, and multi-channel notification

### Node Sequence

```
Webhook: Critical Alert
    │
    ▼ Parse & Enrich Alert (JavaScript)
    │ • Normalise severity, generate incidentId
    │ • Select playbook by threat type
    │
    ├──► Get Host Intelligence (HTTP GET /api/v1/hosts/{ip})
    └──► Check IP Reputation (HTTP GET AbuseIPDB)
         │
         ▼ Correlate Intelligence (JavaScript)
         │ Combined score = RLM_score * 0.6 + AbuseIPDB * 0.4
         │ Verdict: MALICIOUS_CONFIRMED / LIKELY_MALICIOUS / LIKELY_BENIGN
         │
         ▼ Create Incident (POST /api/v1/incidents)
         │
         ▼ Create Jira Security Incident
         │
         ├──► Slack: Rich Block Kit notification
         ├──► Should Page? (IF severity == CRITICAL)
         │       ▼
         │    PagerDuty Events API v2
         └──► MS Teams: Security Channel MessageCard
              │
              ▼ Respond to Bridge (200 OK)
```

**Note on blocking:** Workflow 01 does NOT execute IP blocks. Block recommendations are flagged by the AI investigation pipeline (`block_recommended=TRUE`) and shown in the RESPONSE tab of the SOC Dashboard for analyst review. The analyst clicks BLOCK IP to execute or DISMISS to close.

### Key Business Logic

- **Combined threat scoring:** RLM behavioral anomaly (60% weight) + AbuseIPDB reputation (40% weight)
- **PagerDuty gate:** Only pages on CRITICAL severity. HIGH gets Slack + Teams only.
- **Jira priority mapping:** CRITICAL → Highest, HIGH → High, MEDIUM → Medium
- **Dedup key:** `incidentId` prevents duplicate PagerDuty incidents

---

## Workflow 02 — Daily SOC Intelligence Report

**File:** `02_daily_soc_report.json`
**Trigger:** Cron schedule — 7:00 AM Monday through Friday
**Purpose:** AI-generated daily security briefing for the SOC team

### Node Sequence

```
Schedule: 7AM Mon–Fri
    │
    ▼ Authenticate API (POST /auth/token)
    │
    ├──► Fetch Dashboard Stats (GET /api/v1/dashboard)
    ├──► Fetch Top Critical Alerts (GET /api/v1/alerts?severity=CRITICAL)
    └──► Fetch Open Incidents (GET /api/v1/incidents?status=OPEN)
         │
         ▼ LLM: Generate Report (reads LLM_PROVIDER from env)
         │ 6 sections: Executive Summary, Key Metrics, Top 3 Threats,
         │             MITRE Techniques, Recommended Actions, Trend
         │
         ▼ Build Report Package (JavaScript)
         │ Calculates: risk level (NORMAL/ELEVATED/HIGH RISK/CRITICAL)
         │
         ├──► Slack: Post SOC Report (Block Kit format)
         ├──► Email: HTML template with metric dashboard
         └──► Teams: MessageCard for leadership channel
```

### Model Selection by Provider

| LLM_PROVIDER | Model Used | Override via |
|-------------|------------|-------------|
| claude | claude-sonnet-4-6 | LLM_MODEL_ANALYSIS |
| openai | gpt-4o-mini | LLM_MODEL_ANALYSIS |
| gemini | gemini-2.5-flash | LLM_MODEL_ANALYSIS |

The n8n workflow reads `$env.LLM_PROVIDER` at runtime — no workflow change needed when switching providers.

---

## Workflow 03 — CVE Intel Pipeline

**File:** `03_cve_intel_pipeline.json`
**Trigger:** Kafka webhook — `critical-cve` and `active-exploitation` events
**Purpose:** Instant CVE awareness with AI impact analysis and patch ticket creation

### Node Sequence

```
Webhook: critical-cve  ──────┐
Webhook: active-exploitation ─┤
                               ▼
                    LLM (fast tier): Analyze CVE Impact
                    │ 3 sentences:
                    │ 1. What systems are affected?
                    │ 2. What is the attack vector?
                    │ 3. What is the immediate action?
                               │
                    ▼ Build CVE Alert Package (JavaScript)
                               │
                    ├──► Slack: CVE Alert Block Kit
                    ├──► Jira: Create Vulnerability ticket
                    │     • Priority: Highest (CISA) / High (NVD)
                    │     • Labels: cve, patch-required
                    └──► Telegram: Mobile push to security team
```

### CISA vs NVD Handling

| Source | Urgency | Jira Priority | Due Date |
|--------|---------|---------------|----------|
| CISA KEV | 🚨 ACTIVELY EXPLOITED | Highest | CISA mandated date |
| NVD (CVSS ≥ 9.0) | ⚠️ CVSS {score} | High | 30 days from publish |

### Fast Tier Model by Provider

| LLM_PROVIDER | Model Used | Override via |
|-------------|------------|-------------|
| claude | claude-haiku-4-5-20251001 | LLM_MODEL_FAST |
| openai | gpt-4o-mini | LLM_MODEL_FAST |
| gemini | gemini-2.5-flash | LLM_MODEL_FAST |

All three fast-tier models complete the 3-sentence CVE impact analysis in under 5 seconds.

---

## Workflow 04 — SLA Watchdog & Incident Escalation

**File:** `04_sla_watchdog.json`
**Trigger:** Cron schedule — every 15 minutes, 24/7
**Purpose:** Enforce SLA guarantees on all open incidents, auto-escalate breaches

### SLA Thresholds

| Severity | SLA Limit | Warning At | Breach Action |
|----------|-----------|-----------|---------------|
| CRITICAL | 15 minutes | 3 min remaining | PagerDuty page + Slack + ServiceNow P1 |
| HIGH | 60 minutes | 12 min remaining | Slack alert + ServiceNow escalate |
| MEDIUM | 4 hours | 48 min remaining | Slack warning only |
| LOW | 24 hours | No warning | Log only |

### Node Sequence

```
Schedule: Every 15 Minutes
    │
    ▼ Authenticate API
    │
    ▼ Fetch Open Incidents (GET /api/v1/incidents?status=OPEN)
    │
    ▼ Check SLA Breaches (JavaScript)
    │ age_minutes = (now - created_at) / 60
    │ slaBreached = age_minutes >= SLA[severity]
    │
    ▼ Is SLA Breached? (IF node)
    │
    ├── YES ──► PagerDuty (dedup_key: sla_{incident_id})
    │           ▼
    │           Slack: SLA BREACH Alert
    │           ▼
    │           ServiceNow: PATCH → Priority 1
    │
    └── NO (warning) ──► Slack: SLA WARNING Alert
```

---

## Workflow 05 — Weekly Executive Board Report

**File:** `05_weekly_board_report.json`
**Trigger:** Cron schedule — Monday 8:00 AM
**Purpose:** C-Suite and Board-level security posture briefing

### Data Aggregation

```javascript
// Risk score formula (0–100)
riskScore = min(100, CRITICAL*10 + HIGH*3 + MEDIUM*0.5 + open_incidents*5)
```

### Node Sequence

```
Schedule: Monday 8AM
    │
    ▼ Authenticate API
    │
    ├──► Fetch 7-day Dashboard Stats
    ├──► Fetch All Alerts (7 days, limit 200)
    ├──► Fetch Open Incidents
    └──► Fetch Resolved This Week
         │
         ▼ Aggregate Weekly Metrics (JavaScript)
         │
         ▼ LLM (primary tier): Generate Board Report
         │ 9 mandatory sections (board-ready, no jargon)
         │
         ├──► Slack: Executive Summary (condensed)
         ├──► Email: Full HTML report to BOARD_EMAIL
         ├──► Teams: Leadership Channel MessageCard
         └──► Jira: Weekly Review Ticket (audit trail)
```

### Board Report Sections

| # | Section |
|---|---------|
| 1 | Executive Summary (3–4 sentences, overall posture) |
| 2 | Risk Posture (current level, trend vs last week) |
| 3 | Key Metrics This Week (numbers with business context) |
| 4 | Threat Landscape (what attackers are doing) |
| 5 | Critical Incidents Requiring Action |
| 6 | Security Investments Performance (ROI indicators) |
| 7 | Compliance & Regulatory Posture (GDPR, SOC2, HIPAA) |
| 8 | Recommended Board Actions (3–5 specific items) |
| 9 | Outlook Next Week (emerging threats, patch deadlines) |

### Primary Tier Model by Provider

| LLM_PROVIDER | Model Used | Override via |
|-------------|------------|-------------|
| claude | claude-opus-4-5 | LLM_MODEL_PRIMARY |
| openai | gpt-4o-mini | LLM_MODEL_PRIMARY |
| gemini | gemini-2.5-flash | LLM_MODEL_PRIMARY |

The primary tier is used because board reports require nuanced business translation and multi-paragraph structured writing. Set `LLM_MODEL_PRIMARY=gpt-4o` to use the full GPT-4o for higher quality board prose.

---

## Credential Configuration Reference

After importing workflows, configure these in n8n Settings → Credentials:

| n8n Credential | Type | Required For |
|----------------|------|-------------|
| CyberSentinel API | HTTP Header Auth (Bearer) | All workflows |
| Slack Webhook | HTTP Request | Workflows 01, 02, 03, 04, 05 |
| PagerDuty | HTTP Request (routing key) | Workflows 01, 04 |
| Jira | HTTP Basic Auth | Workflows 01, 03, 05 |
| MS Teams | HTTP Request (webhook) | Workflows 01, 02, 05 |
| ServiceNow | HTTP Basic Auth | Workflow 04 |
| SMTP | Email Send | Workflows 02, 05 |
| Telegram | HTTP Request (bot token) | Workflow 03 |

---

## LLM Provider Configuration for n8n

Workflows 02, 03, and 05 call an LLM for AI-generated content. They read `$env.LLM_PROVIDER` at runtime — no workflow changes needed when switching providers.

**Setup:**

```bash
# In .env — set provider and matching key
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Then restart mcp-orchestrator and n8n services:
docker compose up -d mcp-orchestrator
docker compose up -d n8n
```

**In n8n:** Settings → Environment Variables → add `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` for Claude, `GOOGLE_API_KEY` for Gemini).

---

## Testing Workflows Manually

```bash
# Trigger Workflow 01 with a test CRITICAL alert
curl -X POST http://localhost:5678/webhook/critical-alert \
  -H "Content-Type: application/json" \
  -d '{
    "type": "C2_BEACON_DETECTED",
    "severity": "CRITICAL",
    "src_ip": "10.0.0.99",
    "dst_ip": "185.220.101.47",
    "anomaly_score": 0.91,
    "mitre_technique": "T1071.001",
    "timestamp": "2026-03-29T09:00:00Z"
  }'

# Trigger Workflow 03 with a test CVE
curl -X POST http://localhost:5678/webhook/critical-cve \
  -H "Content-Type: application/json" \
  -d '{
    "type": "CRITICAL_CVE",
    "cve_id": "CVE-2026-1234",
    "cvss": 9.8,
    "description": "Remote code execution in Apache XYZ",
    "source": "NVD"
  }'

# Trigger Workflows 02 and 05 manually
# n8n UI → Workflows → select workflow → Execute Workflow button
```

---

*SOAR Workflows — CyberSentinel AI v1.1 — 2025/2026*
