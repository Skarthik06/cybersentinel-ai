# CyberSentinel AI — Frontend

React-based frontend with two views accessible from a floating pill switcher:

1. **Landing Page** (`CyberSentinel_Landing.jsx`) — Cinematic dark showcase for presentations
2. **SOC Dashboard** (`CyberSentinel_Dashboard.jsx`) — Full operator HUD with live API data

---

## Folder Structure

```
frontend/
├── index.html                        ← Vite HTML entry point
├── package.json                      ← Dependencies: React 18, Recharts, Vite
├── vite.config.js                    ← Dev server + API proxy to localhost:8080
└── src/
    ├── main.jsx                      ← React root mount
    ├── App.jsx                       ← Router — switches between Landing & Dashboard
    ├── CyberSentinel_Landing.jsx     ← Landing page component
    └── CyberSentinel_Dashboard.jsx   ← SOC dashboard component
```

---

## Quick Start

```bash
# 1. Make sure CyberSentinel backend is running
cd ..  # go to cybersentinel-ai root
docker compose -f docker-compose.yml -f n8n/docker-compose.n8n.yml up -d

# 2. Start the frontend
cd frontend
npm install
npm run dev

# 3. Open in browser
# http://localhost:3000
```

---

## API Connection

The frontend connects to `http://localhost:8080` (CyberSentinel FastAPI).

All 7 API calls are verified to match `src/api/gateway.py`:

| Frontend Call             | Backend Endpoint              | File              |
|---------------------------|-------------------------------|-------------------|
| GET /health               | @app.get("/health")           | gateway.py        |
| POST /auth/token          | @app.post("/auth/token")      | gateway.py        |
| GET /api/v1/dashboard     | @app.get("/api/v1/dashboard") | gateway.py        |
| GET /api/v1/alerts        | @app.get("/api/v1/alerts")    | gateway.py        |
| GET /api/v1/incidents     | @app.get("/api/v1/incidents") | gateway.py        |
| GET /api/v1/hosts/{ip}    | @app.get("/api/v1/hosts/...")  | gateway.py        |
| POST /api/v1/threat-search| @app.post("/api/v1/threat-search") | gateway.py   |

The dashboard automatically falls back to realistic demo data if the API is offline.

---

## Login

Default credentials (from `.env`):
- **Username:** admin
- **Password:** cybersentinel2025

---

## Dashboard Tabs

| Tab | What It Shows |
|---|---|
| Overview | 6 metric cards, alert timeline, platform health radar, risk gauge |
| Alerts | Full alert table with severity, MITRE tags, anomaly score bars |
| Incidents | Registry with OPEN/INVESTIGATING/RESOLVED/CLOSED tracking |
| Threat Intel | ChromaDB semantic search + MITRE ATT&CK coverage + CTI status |
| Hosts | RLM behavioral profile lookup by IP address |

---

*CyberSentinel AI Frontend v1.0 — Capstone 2025*
