# SOAR Workflows

**CyberSentinel AI — n8n Workflow Specifications**

Five production workflows covering the complete SOC automation cycle.
All workflow JSON files are in `n8n/workflows/` — import directly into n8n.

---

## Critical: N8N Environment Setup

Before workflows will run, the N8N container must be started with these environment variables:

| Variable | Required Value | Why |
|----------|---------------|-----|
| `N8N_BLOCK_ENV_ACCESS_IN_NODE` | `false` | n8n 2.15+ blocks `$env.OPENAI_API_KEY` etc. by default. Without this, all LLM calls silently fail. |
| `OPENAI_API_KEY` | Your key | Referenced as `$env.OPENAI_API_KEY` in WF02, WF03, WF05 |
| `SLACK_BOT_TOKEN` | Your token | Referenced as `$env.SLACK_BOT_TOKEN` in WF02, WF03, WF04, WF05 |
| `SLACK_CHANNEL_ID` | Your channel | Referenced as `$env.SLACK_CHANNEL_ID` |

Use `scripts/start_n8n.ps1` to start N8N with all required vars set from `.env`. See `docs/N8N_OPERATIONS.md` for full details.

**After any import or restart where workflows aren't activating:**
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
```

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
Schedule: 7AM Mon–Fri  OR  Manual Webhook
    │
    ▼ Authenticate API (POST /auth/token)
    │
    ▼ Fetch Dashboard Stats (GET /api/v1/dashboard)
    │
    ▼ Fetch Top Critical Alerts (GET /api/v1/alerts?severity=CRITICAL&hours=24&limit=10)
    │
    ▼ Fetch Open Incidents (GET /api/v1/incidents?status=OPEN)
    │
    ▼ Build AI Prompt (Code node — assembles prompt from data)
    │ 5 sections: Executive Summary, Key Metrics, Top 3 Threats,
    │             MITRE Techniques, Recommended Actions
    │
    ▼ Call OpenAI (HTTP Request → api.openai.com/v1/chat/completions)
    │ model: gpt-4o-mini, max_tokens: 1024
    │
    ▼ Build Slack Report (Code node — formats Block Kit payload)
    │ Calculates risk level: NORMAL / ELEVATED / HIGH RISK
    │
    ▼ Build Approval Payload (Code node)
    │
    ▼ Submit for Approval (POST /api/v1/reports/pending)
```

> **Note (n8n 2.15+):** The LLM call is an HTTP Request node, not a Code node. n8n's JS Task Runner sandbox blocks all outbound HTTP in Code nodes. The Code node only builds the prompt; the HTTP Request node makes the API call.

### LLM Used

Currently hardcoded to **OpenAI GPT-4o mini** via HTTP Request node. To switch providers, update the `Call OpenAI` node URL and Authorization header to point at your preferred provider's API.

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

| Severity | SLA Limit | Warning Threshold | Breach Action |
|----------|-----------|-------------------|---------------|
| CRITICAL | 30 minutes | ≥ 80% (24 min) | PagerDuty page + Slack + ServiceNow P1 |
| HIGH | 2 hours | ≥ 80% (96 min) | Slack alert + ServiceNow escalate |
| MEDIUM | 8 hours | ≥ 80% (384 min) | Slack warning only |
| LOW | 24 hours | ≥ 80% (1152 min) | Log only |

Warning fires at ≥ 80% SLA consumed. Breach fires at ≥ 100%.

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
Schedule: Monday 8AM  OR  Manual Webhook
    │
    ▼ Authenticate API (POST /auth/token)
    │
    ▼ Fetch Dashboard Stats (GET /api/v1/dashboard)
    │
    ▼ Fetch Open Incidents (GET /api/v1/incidents?limit=100&status=OPEN)
    │
    ▼ Aggregate Weekly Metrics (Code node — $input.all() for incident array)
    │ Fields: open_critical, open_high, open_medium, open_low,
    │         total_alerts, blocked_ips, top_threats, avg_response_time
    │
    ▼ Build Board Prompt (Code node — assembles prompt + system prompt)
    │
    ▼ Call OpenAI (HTTP Request → api.openai.com/v1/chat/completions)
    │ model: gpt-4o-mini, max_tokens: 800, temperature: 0.2
    │
    ▼ Build Slack Board Report (Code node — formats Block Kit payload)
    │
    ▼ Build Approval Payload (Code node)
    │
    ▼ Submit for Approval (POST /api/v1/reports/pending)
```

> **Note (n8n 2.15+):** Same sandbox constraint as WF02 — LLM call is an HTTP Request node.
> **Note on incidents:** `Aggregate Weekly Metrics` uses `$('Fetch Open Incidents').all()` to collect all items after n8n splits the JSON array response.

### Board Report Sections

| # | Section |
|---|---------|
| 1 | Executive Summary |
| 2 | Key Threats |
| 3 | Response Effectiveness |
| 4 | Recommendations |
| 5 | Next Week Outlook |

### LLM Used

Currently hardcoded to **OpenAI GPT-4o mini** via HTTP Request node (same as WF02). To switch to full GPT-4o for higher quality prose, update the `Call OpenAI` node body: change `gpt-4o-mini` to `gpt-4o`.

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

## LLM Configuration for n8n

Workflows 02, 03, and 05 call OpenAI GPT-4o mini directly via an HTTP Request node.

**Current implementation:** The `Call OpenAI` node in WF02/03/05 calls `https://api.openai.com/v1/chat/completions` with a Bearer token in the Authorization header.

**To switch models or providers:** Open the `Call OpenAI` node in n8n, update the URL and Authorization header for your preferred provider.

> **Why not `$env.LLM_PROVIDER`?** n8n 2.15 JS Task Runner sandbox blocks all HTTP from Code nodes. The HTTP Request node is required for external API calls — and HTTP Request nodes don't share env var routing logic. The simplest working approach is a direct HTTP Request to OpenAI.

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

## N8N Activation Reference

After importing workflows or after a fresh N8N setup, workflows start as **inactive drafts**. n8n requires three things in its SQLite database for a workflow to actually run:

1. `workflow_entity.active = 1`
2. `workflow_entity.activeVersionId` pointing to a version UUID
3. A row in `workflow_published_version` for each workflow
4. Correct nodes stored in `workflow_history` at that version UUID (n8n reads execution code from here, not from `workflow_entity.nodes`)

The script `scripts/activate_n8n_workflows.py` handles all of this automatically.

**Symptoms of inactive workflows:**
- `{"code":404,"message":"The requested webhook is not registered"}` from any webhook endpoint
- n8n logs: `Processed 5 draft workflows, 0 published workflows`
- Frontend Automation tab shows FAILED on all triggers

**Fix:**
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
# Then verify: docker logs --tail 5 N8N
# Should see: "Activated workflow ..." for all 5
```

See `docs/N8N_OPERATIONS.md` for a complete troubleshooting guide.

---

*SOAR Workflows — CyberSentinel AI v1.2.2 — 2025/2026*
