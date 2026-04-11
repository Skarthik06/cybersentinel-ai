# N8N Operations Guide — CyberSentinel AI
**Version:** 1.0 | **Last Updated:** 2026-04-10

---

## Table of Contents
1. [Why Workflows Break After Restart](#1-why-workflows-break-after-restart)
2. [What n8n Needs to Run Workflows](#2-what-n8n-needs-to-run-workflows)
3. [The Fix Script](#3-the-fix-script)
4. [Full Fresh-Start Procedure](#4-full-fresh-start-procedure)
5. [N8N Container Reference](#5-n8n-container-reference)
6. [Troubleshooting Common Errors](#6-troubleshooting-common-errors)
7. [Workflow Webhook Reference](#7-workflow-webhook-reference)

---

## 1. Why Workflows Break After Restart

### Normal restart — no problem
When you do `docker stop` then `docker start` (or reboot your machine), the N8N data folder at `D:/N8N/` is preserved on your host disk. The SQLite database keeps all settings, active flags, and published versions. **Workflows come back active automatically.**

### When it breaks
The workflow activation state breaks in exactly three scenarios:

| Scenario | What breaks |
|---|---|
| You delete the `D:/N8N/` folder | Entire n8n database is wiped — fresh start |
| You re-import workflow JSON files via CLI | Overwrites `active=0`, clears published state |
| N8N container is recreated without the correct env vars | `$env.OPENAI_API_KEY` and `$env.SLACK_BOT_TOKEN` stop working |

### What "broken" looks like
- n8n logs say: `Finished building workflow dependency index. Processed 5 draft workflows, 0 published workflows`
- Webhooks return: `{"code":404,"message":"The requested webhook is not registered"}`
- Frontend Automation tab shows workflows but manual triggers return FAILED
- SLA Watchdog schedule stops running silently

---

## 2. What n8n Needs to Run Workflows

n8n uses a SQLite database at `D:/N8N/database.sqlite`. For each workflow to be active, **three things** must be set correctly:

```
workflow_entity table
  ├── active = 1              (0 after import — must be set to 1)
  └── activeVersionId = UUID  (NULL after import — must point to a version)

workflow_published_version table
  └── row for each workflow   (missing after import — must be inserted)

workflow_history table
  └── nodes stored at the versionId  (must match the actual workflow code)
```

When any of these is wrong:
- `active = 0` → workflow does not start at all
- `activeVersionId = NULL` → n8n treats it as a draft, won't register schedules/webhooks
- Missing `workflow_published_version` row → same as above, shows as "0 published"
- Wrong nodes in `workflow_history` → old/broken code runs even if you edited the JSON file

---

## 3. The Fix Script

**File:** `scripts/activate_n8n_workflows.py`

This script automatically detects and fixes all three conditions above. It reads the current workflow JSON files from `n8n/workflows/` and ensures the SQLite database is in the correct state.

### When to run it
Run this script any time you see workflows not activating:

```powershell
# From the project root (D:/cybersentinel-ai)
python scripts/activate_n8n_workflows.py
docker restart N8N
```

That's it. N8N will restart and log `Activated workflow "..."` for all 5 workflows.

### What the script does
1. Opens `D:/N8N/database.sqlite`
2. Checks each of the 5 workflows:
   - Is `active = 1`? If not, sets it.
   - Is `activeVersionId` set? If not, sets it.
   - Is there a row in `workflow_published_version`? If not, inserts it.
   - Does `workflow_history` have the correct nodes? If not, inserts a new version.
3. Reports what it fixed
4. Tells you to restart N8N

### Dry run (see what would change without touching anything)
```powershell
python scripts/activate_n8n_workflows.py --dry-run
```

### Custom paths
```powershell
python scripts/activate_n8n_workflows.py --db D:/N8N/database.sqlite --workflows-dir n8n/workflows
```

### Sample output — all healthy
```
[n8n activator] DB: D:\N8N\database.sqlite
[n8n activator] Found 5 workflows in DB
  [OK]  wf01-critical-alert-soar
  [OK]  wf02-daily-soc-report
  [OK]  wf03-cve-intel-pipeline
  [OK]  wf04-sla-watchdog
  [OK]  wf05-weekly-board-report

[n8n activator] All workflows are already active and published. Nothing to do.
```

### Sample output — after fresh import (broken state)
```
[n8n activator] DB: D:\N8N\database.sqlite
[n8n activator] Found 5 workflows in DB
  [!] NEEDS FIX wf01-critical-alert-soar (inactive, no activeVersionId, not published)
  [!] NEEDS FIX wf02-daily-soc-report    (inactive, no activeVersionId, not published)
  ...
  -> wf01-critical-alert-soar: set active=1, activeVersionId=f449af5e
  -> wf01-critical-alert-soar: published_version -> f449af5e
  ...
[n8n activator] Done. Restart N8N for changes to take effect:
  docker restart N8N
```

---

## 4. Full Fresh-Start Procedure

Use this when starting from scratch — new machine, wiped `D:/N8N/`, or first-time setup.

### Automated (recommended)
```powershell
# From the project root — does everything automatically
.\scripts\start_n8n.ps1
```

This script:
1. Reads credentials from `.env`
2. Removes old N8N container if it exists
3. Creates a fresh N8N container with all required env vars
4. Waits 15 seconds for n8n to initialize and create its database
5. Runs `activate_n8n_workflows.py` to fix the activation state
6. Restarts N8N so it picks up all changes

### Manual (step by step)

**Step 1 — Start the rest of the project**
```powershell
docker compose up -d
```

**Step 2 — Remove old N8N container**
```powershell
docker rm -f N8N
```

**Step 3 — Start N8N with required env vars**
```powershell
# Read keys from .env first, then run:
docker run -d `
  --name N8N `
  --network cybersentinel-ai_cybersentinel-net `
  -p 5678:5678 `
  -v "D:/N8N:/home/node/.n8n" `
  -e "OPENAI_API_KEY=<your key>" `
  -e "SLACK_BOT_TOKEN=<your token>" `
  -e "SLACK_CHANNEL_ID=<your channel id>" `
  -e "N8N_BLOCK_ENV_ACCESS_IN_NODE=false" `
  -e "TZ=Asia/Kolkata" `
  -e "GENERIC_TIMEZONE=Asia/Kolkata" `
  n8nio/n8n:latest
```

**Step 4 — Import workflows (only needed if D:/N8N was wiped)**
```powershell
# Copy workflow files into container
docker cp n8n/workflows/. N8N:/home/node/workflows/
docker exec N8N chmod -R 777 /home/node/workflows/

# Import each workflow
docker exec N8N n8n import:workflow --input=/home/node/workflows/01_critical_alert_soar.json
docker exec N8N n8n import:workflow --input=/home/node/workflows/02_daily_soc_report.json
docker exec N8N n8n import:workflow --input=/home/node/workflows/03_cve_intel_pipeline.json
docker exec N8N n8n import:workflow --input=/home/node/workflows/04_sla_watchdog.json
docker exec N8N n8n import:workflow --input=/home/node/workflows/05_weekly_board_report.json
```

**Step 5 — Activate and publish**
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
```

**Step 6 — Verify**
```powershell
docker logs --tail 10 N8N
# Should see: Activated workflow "..." for all 5
```

---

## 5. N8N Container Reference

### Required environment variables

| Variable | Value | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | From `.env` | Used by workflows in `$env.OPENAI_API_KEY` |
| `SLACK_BOT_TOKEN` | From `.env` | Used by workflows in `$env.SLACK_BOT_TOKEN` |
| `SLACK_CHANNEL_ID` | `C0ANVSMJTH9` | Used by workflows in `$env.SLACK_CHANNEL_ID` |
| `N8N_BLOCK_ENV_ACCESS_IN_NODE` | `false` | **Critical.** Newer n8n blocks `$env` in nodes by default. Must be set to `false` or all API key references fail silently. |
| `TZ` | `Asia/Kolkata` | Correct timezone for schedules |
| `GENERIC_TIMEZONE` | `Asia/Kolkata` | n8n internal timezone |

> **Note:** If `N8N_BLOCK_ENV_ACCESS_IN_NODE` is not set to `false`, workflows will appear to run but all OpenAI and Slack calls will fail with a generic error about missing credentials.

### Volume mount
```
D:/N8N  →  /home/node/.n8n
```
All n8n data (database, credentials, execution history) lives in `D:/N8N/` on your host machine. **Never delete this folder unless doing a full reset.**

### Network
N8N must be on `cybersentinel-ai_cybersentinel-net` to reach the CyberSentinel API via `host.docker.internal:8080`.

To verify:
```powershell
docker network inspect cybersentinel-ai_cybersentinel-net --format "{{range .Containers}}{{.Name}} {{end}}"
# N8N should appear in the list
```

To add N8N to the network if missing:
```powershell
docker network connect cybersentinel-ai_cybersentinel-net N8N
```

### Access
- N8N UI: `http://localhost:5678`
- N8N webhooks: `http://localhost:5678/webhook/<path>`

---

## 6. Troubleshooting Common Errors

### "The requested webhook is not registered"
```json
{"code":404,"message":"The requested webhook ... is not registered."}
```
**Cause:** Workflow is inactive or not published.
**Fix:**
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
```

### Frontend trigger shows "FAILED"
**Cause 1:** Workflow takes longer than the API timeout (OpenAI calls can take 20-30s).
- Fixed in `src/api/gateway.py` — timeout is set to 90s, `TimeoutException` is caught and treated as "triggered".

**Cause 2:** N8N is not reachable from the API container.
```powershell
# Test from inside the API container
docker exec cybersentinel-api curl -s http://host.docker.internal:5678/health
# Should return: {"status":"ok",...}
```
If it fails, check N8N is running: `docker ps | grep N8N`

### "$env.OPENAI_API_KEY is blocked" or workflow silently skips OpenAI
**Cause:** N8N container missing `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`.
**Fix:** Recreate the container using `scripts/start_n8n.ps1` or manually add the env var.

Check current env vars:
```powershell
docker inspect N8N --format "{{range .Config.Env}}{{println .}}{{end}}"
# Look for: N8N_BLOCK_ENV_ACCESS_IN_NODE=false
```

### Workflow runs but Slack message not sent
**Cause:** Approval flow — workflows do NOT post directly to Slack. They submit a PENDING report to the API at `http://host.docker.internal:8080/api/v1/reports/pending`. A human must approve it in the frontend Automation tab.

**To check pending reports:**
```powershell
# Via API
curl -s "http://localhost:8080/api/v1/reports/pending?status=PENDING" -H "Authorization: Bearer <token>"
```

### SLA Authenticate node returns 422
**Cause:** Old SLA workflow used `"body": "=username=admin&password=..."` (raw string).
The fix is in `04_sla_watchdog.json` — uses `bodyParameters` instead.
If this recurs, run `activate_n8n_workflows.py` — it will push the correct nodes from the JSON file into the database.

### "5 draft workflows, 0 published" in n8n logs
This cosmetic message appears when `workflow_published_version` rows are missing. Workflows still activate if `active=1` and `activeVersionId` is set. But to clean it up:
```powershell
python scripts/activate_n8n_workflows.py
docker restart N8N
# Logs will then show: Processed 5 draft workflows, 5 published workflows
```

---

## 7. Workflow Webhook Reference

All manual triggers go through the CyberSentinel API (to avoid CORS issues in the browser). The API proxies to n8n.

| Workflow | Frontend Trigger | API Endpoint | n8n Webhook |
|---|---|---|---|
| Daily SOC Report | AUTOMATION tab > RUN NOW | `POST /api/v1/workflows/trigger/daily` | `/webhook/run-daily-report` |
| SLA Watchdog | AUTOMATION tab > RUN NOW | `POST /api/v1/workflows/trigger/sla` | `/webhook/run-sla-check` |
| Weekly Board Report | AUTOMATION tab > RUN NOW | `POST /api/v1/workflows/trigger/board` | `/webhook/run-board-report` |
| Critical Alert SOAR | Auto-triggered by alerts | n/a | `/webhook/critical-alert` |
| CVE Intel Pipeline | Auto-triggered by CVE feeds | n/a | `/webhook/critical-cve` |

### Flow when you click "RUN NOW" in the frontend
```
Browser
  └─> POST /api/v1/workflows/trigger/board   (CyberSentinel API, port 8080)
        └─> POST http://host.docker.internal:5678/webhook/run-board-report   (n8n)
              └─> Workflow runs (fetches data, calls OpenAI ~25s)
                    └─> POST http://host.docker.internal:8080/api/v1/reports/pending
                          └─> Report appears in AUTOMATION tab as PENDING
                                └─> You click APPROVE
                                      └─> API POSTs to Slack
```

### Direct curl trigger (for testing/debugging)
```powershell
# Get a token first
$TOKEN = (curl -s -X POST http://localhost:8080/auth/token `
  -H "Content-Type: application/x-www-form-urlencoded" `
  -d "username=admin&password=cybersentinel2025" | ConvertFrom-Json).access_token

# Trigger any workflow
curl -s -X POST http://localhost:8080/api/v1/workflows/trigger/daily -H "Authorization: Bearer $TOKEN"
curl -s -X POST http://localhost:8080/api/v1/workflows/trigger/sla   -H "Authorization: Bearer $TOKEN"
curl -s -X POST http://localhost:8080/api/v1/workflows/trigger/board -H "Authorization: Bearer $TOKEN"
```

---

## Quick Reference Card

```
EVERY TIME you start Docker fresh (no D:/N8N wipe):
  docker compose up -d
  docker start N8N
  → Workflows auto-activate. Nothing else needed.

IF workflows are broken (webhooks 404, frontend FAILED):
  python scripts/activate_n8n_workflows.py
  docker restart N8N

FULL RESET (wiped D:/N8N or new machine):
  docker compose up -d
  .\scripts\start_n8n.ps1

CHECK workflow status:
  docker logs --tail 5 N8N
  → Look for: "Activated workflow ..." x5

CHECK pending reports:
  Open http://localhost:5173 → AUTOMATION tab
```
