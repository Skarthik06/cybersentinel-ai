# Moving CyberSentinel AI to a New Machine

Everything runs in Docker and **builds from source in this repo**, so you do *not*
ship any container images. You move the **code**, the **`.env` secrets** (not in git),
and decide whether to bring the **data** (DB volumes stay on the old machine).

---

## 1. Install on the NEW PC (prerequisites)

| Tool | Why | Notes |
|------|-----|-------|
| **Docker Desktop** | Runs all 14 services | Windows: enable **WSL2** backend; enable virtualization in BIOS. Give it ≥ 6 GB RAM (stack uses ~4 GB). |
| **Git** | Clone the repo | Or just copy the folder (see §2). |
| **Python 3.10+** | Host live-DPI sensor | Tick **"Add Python to PATH"** during install. |
| **Npcap** | Packet capture (live DPI) | **Auto-installed** by the launcher — or grab it from npcap.com with "WinPcap API-compatible mode". |
| (not needed) Node.js | — | The frontend builds *inside* its container; no host Node required. |

Disk: ~10–12 GB for images + volumes. Internet needed on first build (base images, pip, npm).

> Live capture works only on **Windows (Npcap)** or **Linux (`scripts/start_dpi_linux.sh`)**. The rest of the platform is OS-independent.

---

## 2. Get the code onto the new PC

**Option A — Git (recommended):**
```bash
git clone <your-repo-url> cybersentinel-ai
cd cybersentinel-ai
```

**Option B — Copy the folder:** copy the whole `cybersentinel-ai` directory, but
**exclude** these (huge / machine-specific, they regenerate):
- `frontend/node_modules/`
- `frontend/dist/`
- `.git/` (optional)

`.env` is gitignored, so with Option A you must copy it separately (see §3).

---

## 3. Bring over secrets (`.env`)  ← most important

`.env` holds all API keys + passwords and is **not** in git.

- **Copy your existing `.env`** from the old machine to the new repo root, **or**
- Recreate it: `cp .env.example .env` then fill in at minimum:
  - `OPENAI_API_KEY` (AI investigation)
  - `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `CHROMA_TOKEN`, `JWT_SECRET`
  - optional: `ABUSEIPDB_KEY`, `NVD_API_KEY`, `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`

If you change `POSTGRES_PASSWORD`/`REDIS_PASSWORD`, do it **before** first `up` (they bake into the fresh volumes).

---

## 4. Build & start the stack

```bash
docker compose build          # builds all images from source (first time ~10–15 min)
docker compose up -d          # starts all 14 containers
docker compose ps             # all should be running; kafka/postgres healthy
```

Apply the campaigns migration (base schema auto-loads via init.sql; this part is manual):
```bash
docker exec -i cybersentinel-postgres psql -U sentinel -d cybersentinel < scripts/db/migrate_campaigns.sql
```

Open the dashboard: **http://localhost:5173** · API/Swagger: **http://localhost:8080/docs** (admin / cybersentinel2025).

---

## 5. Live DPI sensor (host side)

Just double-click **`Launch CyberSentinel.bat`** — it self-elevates, installs Npcap +
the 3 Python packages (`scapy`, `aiokafka`, `redis`) if missing, waits for Kafka, shows
the mode chooser, opens the browser, and starts capture. No manual sensor setup needed.

---

## 6. N8N SOAR (optional — only if you demo automation)

`scripts/start_n8n.ps1` hardcodes a host path `D:/N8N`. On the new PC either:
- create that folder (`mkdir D:\N8N`), **or**
- edit `start_n8n.ps1` line ~31 and change `-v "D:/N8N:/home/node/.n8n"` to a path that exists.

Then: `pwsh scripts/start_n8n.ps1`, import the playbooks from `n8n/workflows/`, and
**re-enter credentials in the n8n UI** (Slack/OpenAI creds live in n8n's own DB, not in git).

---

## 7. (Optional) Carry over existing DATA

By default the new machine starts **empty** (alerts/incidents/profiles regenerate from
the simulator + live DPI). To migrate the real data:

```bash
# OLD machine — dump
docker exec cybersentinel-postgres pg_dump -U sentinel cybersentinel > cs_dump.sql

# NEW machine — after `docker compose up -d`
docker exec -i cybersentinel-postgres psql -U sentinel -d cybersentinel < cs_dump.sql
```
(ChromaDB embeddings and Redis cache rebuild themselves; no need to migrate them.)

---

## Quick checklist

- [ ] Docker Desktop (WSL2) + Python + Git installed on new PC
- [ ] Repo cloned/copied (without `node_modules`)
- [ ] `.env` copied or recreated with real keys
- [ ] `docker compose build && docker compose up -d`
- [ ] Ran `migrate_campaigns.sql`
- [ ] http://localhost:5173 loads
- [ ] `Launch CyberSentinel.bat` runs live capture
- [ ] (optional) N8N path fixed + workflows imported
