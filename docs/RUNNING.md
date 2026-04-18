# How to Run CyberSentinel AI

**Everything you need to know about starting, stopping, and understanding the platform.**

---

## The Short Answer — Why Containers "Disappear"

When you stop Docker Compose, the **containers** are removed but your **data does not**.

Here is why:

| Thing | Where it lives | Survives `docker compose down`? |
|---|---|---|
| Postgres database | `postgres_data` (Docker named volume) | ✅ Yes |
| Redis cache | `redis_data` (Docker named volume) | ✅ Yes |
| Kafka messages | `kafka_data` (Docker named volume) | ✅ Yes |
| ChromaDB vectors | `chromadb_data` (Docker named volume) | ✅ Yes |
| Grafana dashboards | `grafana_data` (Docker named volume) | ✅ Yes |
| Running containers | RAM-only processes | ❌ No — recreated on next `docker compose up` |
| Your code / images | Docker image layers on disk | ✅ Yes |

**Containers are not data.** They are just processes. When Docker Compose restarts they are recreated from the same Docker images and reconnect to the same named volumes. All your incidents, alerts, behavior profiles, and threat intel are still there.

> **Exception:** `docker compose down -v` removes volumes — this deletes all data. Only use `-v` for a full reset.

---

## Architecture at a Glance

```
Docker Compose (14 containers on cybersentinel-net)
├── Infrastructure
│   ├── zookeeper          — Kafka coordination
│   ├── kafka              — Event streaming (host:9092, internal:29092)
│   ├── postgres           — TimescaleDB (port 5432)
│   ├── redis              — Cache + session state (port 6379)
│   └── chromadb           — Vector DB (port 8000)
│
├── Core Services
│   ├── dpi-sensor         — Live packet capture (network_mode: host)
│   ├── rlm-engine         — Behavioral profiling + anomaly scoring
│   ├── threat-intel-scraper — CVE/CTI ingestion from 5 sources
│   ├── mcp-orchestrator   — AI investigation engine (port 3000)
│   ├── api-gateway        — REST API + JWT auth (port 8080)
│   └── traffic-simulator  — Generates test attack traffic
│
└── Delivery
    ├── frontend           — React SOC Dashboard (port 5173)
    ├── prometheus         — Metrics collection (port 9090)
    └── grafana            — Metrics dashboards (port 3001)

N8N (standalone — started separately via start_n8n.ps1)
└── N8N                    — SOAR automation workflows (port 5678)
    Network: cybersentinel-ai_cybersentinel-net
    Volume: D:/N8N
```

---

## Prerequisites (one-time setup)

1. **Docker Desktop** installed and running
2. **Docker Compose V2** — `docker compose version` (comes with Docker Desktop 4.0+)
3. **`.env` file** present at the repo root with your API keys filled in

---

## Starting the Project

### Step 1 — Start Docker Desktop

Open Docker Desktop. Wait for the green whale icon in the system tray.

---

### Step 2 — Start all 14 services

```powershell
# From the repo root (D:\cybersentinel-ai)
docker compose up -d
```

This starts all 14 services in the correct dependency order. Kafka takes ~30 seconds to become healthy — the dependent services (rlm-engine, mcp-orchestrator, etc.) wait automatically.

---

### Step 3 — Start N8N (if not already running)

```powershell
# Check if N8N is running
docker ps --filter name=N8N

# If not running, start it
.\scripts\start_n8n.ps1
```

N8N persists between Docker Desktop restarts. If the container exists but is stopped, `docker start N8N` is enough.

---

### Step 4 — Verify everything is healthy

```powershell
# All containers should show Up
docker compose ps

# API health check — postgres/redis/chromadb/llm all green
curl http://localhost:8080/health
```

Open the dashboard: **http://localhost:5173**

---

## Stopping the Project

### Option A — Stop just the core stack (keep N8N running)

```powershell
docker compose down
```

All 14 core containers stop. N8N keeps running on port 5678. All data is preserved.

---

### Option B — Stop everything including N8N

```powershell
docker compose down
docker stop N8N
```

---

### Option C — Just close Docker Desktop

Docker Desktop will shut down all containers. Data is preserved in named volumes. Everything comes back on next `docker compose up -d`.

---

### Option D — Full reset (DELETES all data)

```powershell
# WARNING: This deletes all incidents, alerts, behavioral profiles, and threat intel
docker compose down -v
```

The `-v` flag removes named volumes. Use only when you want a completely fresh start.

---

## What Each Service Does

| Service | Role | URL |
|---|---|---|
| **frontend** | React SOC Dashboard — your main UI | http://localhost:5173 |
| **api-gateway** | REST API, auth, all data endpoints | http://localhost:8080 |
| **mcp-orchestrator** | AI investigation engine | internal port 3000 |
| **rlm-engine** | Behavioral profiling + anomaly scoring | internal only |
| **dpi-sensor** | Live packet capture (host network) | internal only |
| **threat-intel-scraper** | Pulls CVEs, CTI, MITRE into ChromaDB | internal only |
| **traffic-simulator** | Generates 17 test threat scenarios | internal only |
| **postgres** | Incidents, alerts, profiles database | internal port 5432 |
| **redis** | Cache, session state, block list | internal port 6379 |
| **kafka** | Event stream between all services | host 9092, internal 29092 |
| **chromadb** | Vector database for threat signatures | internal port 8000 |
| **grafana** | Metrics dashboards | http://localhost:3001 |
| **prometheus** | Metrics collection | http://localhost:9090 |
| **N8N** | SOAR automation workflows | http://localhost:5678 |

---

## Common Issues

### Kafka is in Restart Loop

This happens when ZooKeeper regenerated a new cluster ID but Kafka's stored `meta.properties` contains the old ID.

```powershell
# Stop kafka and zookeeper
docker compose stop kafka zookeeper

# Remove the stale kafka data volume
docker volume rm cybersentinel-ai_kafka_data

# Restart everything
docker compose up -d
```

### Container Using Old Code After Rebuild

```powershell
docker compose up -d --build --force-recreate mcp-orchestrator
```

### localhost:5173 or localhost:8080 not reachable

```powershell
# Check if containers are running
docker compose ps

# Check for errors
docker compose logs api-gateway | tail -20

# Restart the frontend or API
docker compose restart frontend
docker compose restart api-gateway
```

### API returns `{"detail":"Not Found"}` at root

That is expected. The root path `/` has no route. Use:
- `/health` — service health check
- `/docs` — full Swagger UI with all endpoints
- `/api/v1/dashboard` — dashboard data

### Services stuck waiting for Kafka

Check Kafka's health first:

```powershell
docker compose logs kafka | tail -20
# Look for: "started (kafka.server.KafkaServer)"
```

If Kafka shows `InconsistentClusterIdException`, follow the kafka restart loop fix above.

### Out of Memory

```powershell
# Check resource usage
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'

# Stop the traffic simulator to free ~100MB
docker compose stop traffic-simulator
```

---

## Everyday Workflow

```
Morning:
  1. Open Docker Desktop → wait for green whale
  2. docker compose up -d
  3. docker start N8N          (if needed)
  4. Open http://localhost:5173

Evening:
  1. docker compose down
  2. docker stop N8N           (or leave running)
  3. Close Docker Desktop (optional — data preserved)
```

Your data, incidents, and threat intel are all on named volumes and will be exactly where you left them next time.

---

## Database Access

```powershell
# Open a PostgreSQL shell
docker exec -it cybersentinel-postgres psql -U sentinel -d cybersentinel

# Useful queries
SELECT * FROM soc_summary;
SELECT incident_id, title, block_target_ip, severity
FROM incidents
WHERE block_recommended = TRUE AND status = 'OPEN'
ORDER BY severity DESC;

# Open a Redis CLI
docker exec -it cybersentinel-redis redis-cli -a <REDIS_PASSWORD>
KEYS blocked:*
```

---

*CyberSentinel AI v1.3.0 — Running Guide*
