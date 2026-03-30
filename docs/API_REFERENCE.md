# API Reference

**CyberSentinel AI REST API — v1.0**
**Base URL:** `http://localhost:8080`
**Interactive Docs:** `http://localhost:8080/docs` (Swagger UI)

---

## Authentication

All endpoints except `/health` require a JWT Bearer token.

### Get Token

```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

username=admin&password=cybersentinel2025
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer"
}
```

**Use the token:**
```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Token lifespan:** 480 minutes (8 hours). Configurable via `JWT_EXPIRY_MINUTES`.

**Default users (seeded by init.sql):**
| Username | Password | Role |
|----------|----------|------|
| admin | cybersentinel2025 | admin |
| analyst | cybersentinel2025 | analyst |

---

## Endpoints

---

### GET `/health`

Platform health check. No authentication required.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "api": "ok",
    "postgres": "ok",
    "redis": "ok",
    "chromadb": "ok",
    "llm": {
      "claude": false,
      "openai": true,
      "gemini": false,
      "active": "openai"
    }
  },
  "version": "1.0.0"
}
```

**LLM check fields:**
- `claude` / `openai` / `gemini` — `true` if the API key is configured for that provider
- `active` — which provider is currently selected via `LLM_PROVIDER`

**Status values:** `healthy` (all checks ok) or `degraded` (one or more checks failed).

---

### GET `/api/v1/dashboard`

Real-time SOC dashboard statistics from TimescaleDB and Redis.

**Auth:** Bearer token (any role)

**Response:**
```json
{
  "total_alerts_24h": 1247,
  "critical_alerts_24h": 23,
  "high_alerts_24h": 89,
  "active_incidents": 7,
  "packets_analyzed": 4820391,
  "unique_ips_seen": 2841,
  "blocked_ips": 34,
  "top_src_ips": [
    { "ip": "10.0.0.55", "count": 147, "severity": "CRITICAL" }
  ],
  "top_mitre_techniques": [
    { "technique": "T1071.001", "count": 23 }
  ],
  "top_threat_types": [
    { "type": "PORT_SCAN_DETECTED", "count": 67 }
  ],
  "alerts_by_hour": [
    { "hour": "2026-03-29T09:00:00", "count": 12, "severity": "HIGH" }
  ],
  "risk_score": 0.62
}
```

**Notes:**
- `risk_score` is computed as `min(1.0, (critical*10 + high*3) / max(total*5, 1))` — range 0.0–1.0
- `active_incidents` counts OPEN and INVESTIGATING only
- `blocked_ips` counts active (non-expired) firewall rules
- `packets_analyzed` is 0 when running with traffic simulator only (no real DPI)

---

### GET `/api/v1/alerts`

Paginated, filterable security alerts from the alerts table.

**Auth:** Bearer token (any role)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | null | Filter: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `src_ip` | string | null | Filter by source IP address |
| `alert_type` | string | null | Filter by alert type (e.g. `C2_BEACON_DETECTED`) |
| `hours` | integer | 24 | Look back N hours (max 8760) |
| `limit` | integer | 100 | Results per page (max 1000) |
| `offset` | integer | 0 | Pagination offset |

**Example:**
```http
GET /api/v1/alerts?severity=CRITICAL&hours=48&limit=20
Authorization: Bearer {token}
```

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "C2_BEACON_DETECTED",
    "severity": "CRITICAL",
    "timestamp": "2026-03-29T09:23:11.000Z",
    "src_ip": "10.0.0.55",
    "dst_ip": "185.220.101.47",
    "src_port": 54821,
    "dst_port": 443,
    "protocol": "TCP",
    "description": "C2 beacon detected. avg_interval=28.3s, std_dev=0.421",
    "mitre_technique": "T1071.001",
    "anomaly_score": 0.913,
    "investigation_summary": "Confirmed C2 communication. Block recommended."
  }
]
```

---

### POST `/api/v1/threat-search`

Semantic similarity search against ChromaDB threat knowledge base.

**Auth:** Bearer token (any role)

**Request Body:**
```json
{
  "query": "host making regular outbound connections with high payload entropy to unusual port",
  "n_results": 5,
  "collection": "threat_signatures"
}
```

**Parameters:**
- `query` — natural language description of what you're looking for
- `n_results` — number of results (1–20, default 5)
- `collection` — `threat_signatures` | `cti_reports` | `cve_database` (default: `threat_signatures`)

**Response:**
```json
{
  "query": "host making regular outbound connections...",
  "results": [
    {
      "document": "Host exhibits C2 beacon behavior: regular low-volume outbound connections at precise intervals, high payload entropy...",
      "metadata": {
        "mitre": "T1071.001",
        "severity": "CRITICAL",
        "embedding_model": "all-MiniLM-L6-v2"
      },
      "similarity": 0.891
    }
  ],
  "total": 1
}
```

**Important:** Results are objects with `document`, `metadata`, and `similarity` fields. Scores above 0.65 indicate strong semantic match.

---

### GET `/api/v1/incidents`

List security incidents with optional filters.

**Auth:** Bearer token (any role)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | null | `OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED` |
| `severity` | string | null | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `limit` | integer | 50 | Max results (1–500) |

**Response:**
```json
[
  {
    "incident_id": "INC-1743266582",
    "title": "PROTOCOL_TUNNELING_DETECTED — 172.16.0.5",
    "severity": "HIGH",
    "status": "OPEN",
    "description": "Protocol tunneling via ICMP detected...",
    "affected_ips": ["172.16.0.5"],
    "mitre_techniques": ["T1572"],
    "block_recommended": true,
    "block_target_ip": "172.16.0.5",
    "created_at": "2026-03-29T17:33:02.000Z",
    "updated_at": "2026-03-29T17:33:02.000Z"
  }
]
```

**New fields (added 2026-03-28):**
- `block_recommended` — `true` if the AI investigation flagged this IP for blocking or severity is CRITICAL
- `block_target_ip` — the IP address the AI recommends blocking (typically src_ip or dst_ip)

**Ordering:** OPEN first, then INVESTIGATING, then others. Within each status, newest first. CRITICAL severity incidents sorted before HIGH.

---

### PATCH `/api/v1/incidents/{incident_id}`

Update incident status, notes, or assignment.

**Auth:** Bearer token (role: analyst, responder, or admin)

**Path Parameter:** `incident_id` — e.g. `INC-1743266582`

**Request Body (all fields optional):**
```json
{
  "status": "RESOLVED",
  "notes": "IP blocked, host reimaged. Root cause: phishing email opened by user.",
  "assigned_to": "analyst@example.com"
}
```

**Response:**
```json
{
  "incident_id": "INC-1743266582",
  "updated": true
}
```

**Status transitions:**
```
OPEN → INVESTIGATING → RESOLVED → CLOSED
```

---

### GET `/api/v1/block-recommendations`

Returns all pending block recommendations — incidents where `block_recommended=TRUE` and `status='OPEN'`. Used by the RESPONSE tab to populate the human-in-the-loop review panel.

**Auth:** Bearer token (any role)

**Response:**
```json
[
  {
    "incident_id": "INC-1743266582",
    "title": "PROTOCOL_TUNNELING_DETECTED — 172.16.0.5",
    "severity": "HIGH",
    "block_target_ip": "172.16.0.5",
    "description": "Protocol tunneling via ICMP...",
    "mitre_techniques": ["T1572"],
    "created_at": "2026-03-29T17:33:02.000Z"
  }
]
```

**Ordering:** CRITICAL first, then HIGH, then by newest. Only OPEN incidents with `block_recommended=TRUE` are returned.

**Polling:** The RESPONSE tab polls this endpoint every 30 seconds to show fresh recommendations without page reload.

---

### POST `/api/v1/incidents/{incident_id}/block`

Analyst approves a block recommendation. Executes the block and marks the incident RESOLVED.

**Auth:** Bearer token (role: responder or admin)

**Path Parameter:** `incident_id` — the incident to action

**What this does:**
1. Inserts row into `firewall_rules` table (PostgreSQL persistent block)
2. Sets `Redis blocked:{ip}` key with 24-hour TTL (hot-path block enforcement)
3. Updates incident `status = 'RESOLVED'`, `block_recommended = FALSE`
4. Writes to `audit_log`

**Response:**
```json
{
  "incident_id": "INC-1743266582",
  "blocked_ip": "172.16.0.5",
  "status": "RESOLVED",
  "message": "IP 172.16.0.5 blocked. Incident marked RESOLVED."
}
```

---

### POST `/api/v1/incidents/{incident_id}/dismiss`

Analyst dismisses a block recommendation without blocking. Marks the incident RESOLVED.

**Auth:** Bearer token (role: analyst, responder, or admin)

**Path Parameter:** `incident_id` — the incident to dismiss

**What this does:**
1. Updates incident `status = 'RESOLVED'`, `block_recommended = FALSE`
2. Does NOT insert into firewall_rules or Redis
3. Writes to `audit_log`

**Response:**
```json
{
  "incident_id": "INC-1743266582",
  "status": "RESOLVED",
  "message": "Block recommendation dismissed. Incident marked RESOLVED."
}
```

---

### GET `/api/v1/hosts/{ip_address}`

Full behavioral profile and alert history for a specific IP.

**Auth:** Bearer token (any role)

**Path Parameter:** `ip_address` — e.g. `172.16.0.5`

**Response:**
```json
{
  "ip_address": "172.16.0.5",
  "is_blocked": true,
  "is_isolated": false,
  "block_count": 1,
  "incident_count": 3,
  "profile": {
    "entity_id": "172.16.0.5",
    "entity_type": "host",
    "anomaly_score": 0.0,
    "observation_count": 0,
    "avg_bytes_per_min": 0.0,
    "avg_entropy": 0.0,
    "profile_text": null,
    "updated_at": "2026-03-29T17:33:02.000Z"
  },
  "recent_alerts": [
    {
      "type": "DATA_EXFILTRATION_DETECTED",
      "severity": "HIGH",
      "timestamp": "2026-03-29T17:05:59.000Z",
      "dst_ip": "93.184.220.29",
      "mitre_technique": "T1048.003",
      "anomaly_score": 0.83
    },
    {
      "type": "PROTOCOL_TUNNELING_DETECTED",
      "severity": "HIGH",
      "timestamp": "2026-03-29T16:58:58.000Z",
      "dst_ip": "185.220.101.47",
      "mitre_technique": "T1572",
      "anomaly_score": 0.79
    }
  ]
}
```

**Response field explanations:**

| Field | Source | Notes |
|-------|--------|-------|
| `is_blocked` | Redis `blocked:{ip}` | Sub-millisecond hot-path lookup |
| `block_count` | PostgreSQL `firewall_rules` COUNT | Historical block events for this IP |
| `incident_count` | PostgreSQL `incidents` COUNT | Incidents where IP in `affected_ips` |
| `profile` | PostgreSQL `behavior_profiles` | Nested object — all metrics under `profile.*` |
| `profile.anomaly_score` | ChromaDB similarity computation | **0 if running simulator only (no real DPI)** |
| `profile.observation_count` | EMA packet counter | **0 if running simulator only (no real DPI)** |
| `profile.avg_bytes_per_min` | EMA of payload_size | **0 if running simulator only (no real DPI)** |
| `profile.avg_entropy` | EMA of Shannon entropy | **0 if running simulator only (no real DPI)** |
| `profile.profile_text` | `BehaviorProfile.to_text()` | null if no real DPI data |
| `recent_alerts` | PostgreSQL `alerts` | Last 20 alerts sorted newest first |

**Important:** `profile` is `null` if the host has never been seen by the RLM engine. Profile metrics are all 0 if the host only appears in simulator-generated events (not real packet capture). See `docs/PIPELINES.md` for a full explanation.

---

## Error Responses

All errors follow RFC 7807 Problem Details format:

```json
{
  "detail": "Invalid or expired authentication token"
}
```

| Status Code | Meaning |
|-------------|---------|
| 400 | Bad request — invalid parameters |
| 401 | Unauthorized — missing or invalid token |
| 403 | Forbidden — insufficient role for this action |
| 404 | Not found — resource doesn't exist |
| 422 | Unprocessable Entity — request body validation failed |
| 503 | Service Unavailable — upstream dependency (ChromaDB, PostgreSQL) down |

---

## Rate Limiting

No rate limiting is implemented in v1.0. For production deployment, place nginx or an API gateway in front that enforces per-IP rate limits.

---

## SDK Examples

### Python

```python
import httpx

BASE = "http://localhost:8080"

# Authenticate
resp = httpx.post(f"{BASE}/auth/token",
    data={"username": "admin", "password": "cybersentinel2025"})
token = resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Get dashboard
dashboard = httpx.get(f"{BASE}/api/v1/dashboard", headers=headers).json()
print(f"Risk score: {dashboard['risk_score']}")
print(f"Blocked IPs: {dashboard['blocked_ips']}")

# Get block recommendations
recs = httpx.get(f"{BASE}/api/v1/block-recommendations", headers=headers).json()
for rec in recs:
    print(f"Block recommendation: {rec['block_target_ip']} — {rec['title']}")

# Approve a block
incident_id = recs[0]["incident_id"]
result = httpx.post(f"{BASE}/api/v1/incidents/{incident_id}/block", headers=headers).json()
print(f"Blocked: {result['blocked_ip']}")

# Get host profile
host = httpx.get(f"{BASE}/api/v1/hosts/172.16.0.5", headers=headers).json()
print(f"Blocked: {host['is_blocked']}")
print(f"Incidents: {host['incident_count']}")
# Access profile metrics via the nested 'profile' key:
profile = host.get("profile") or {}
print(f"Anomaly score: {profile.get('anomaly_score', 0)}")
print(f"Observations: {profile.get('observation_count', 0)}")

# Semantic threat search
results = httpx.post(f"{BASE}/api/v1/threat-search", headers=headers,
    json={"query": "lateral movement via SMB internal", "n_results": 3}).json()
for r in results["results"]:
    doc = r.get("document", "")
    sim = r.get("similarity", 0)
    mitre = r.get("metadata", {}).get("mitre", "N/A")
    print(f"{sim:.2f} [{mitre}] — {doc[:80]}")
```

### JavaScript (fetch)

```javascript
const BASE = "http://localhost:8080";

// Authenticate
const { access_token } = await fetch(`${BASE}/auth/token`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "username=admin&password=cybersentinel2025"
}).then(r => r.json());

const headers = { Authorization: `Bearer ${access_token}` };

// Get block recommendations
const recs = await fetch(`${BASE}/api/v1/block-recommendations`, { headers })
  .then(r => r.json());
console.log(`Pending block recommendations: ${recs.length}`);

// Dismiss a recommendation
if (recs.length > 0) {
  const result = await fetch(
    `${BASE}/api/v1/incidents/${recs[0].incident_id}/dismiss`,
    { method: "POST", headers }
  ).then(r => r.json());
  console.log(`Dismissed: ${result.status}`);
}

// Get host profile — note nested profile object
const host = await fetch(`${BASE}/api/v1/hosts/172.16.0.5`, { headers })
  .then(r => r.json());
const anomalyScore = host.profile?.anomaly_score ?? 0;  // nested under .profile
const profileText  = host.profile?.profile_text ?? "No profile";
console.log(`${host.ip_address} | blocked=${host.is_blocked} | score=${anomalyScore}`);
```

### curl

```bash
# Set token once
TOKEN=$(curl -s -X POST http://localhost:8080/auth/token \
  -d "username=admin&password=cybersentinel2025" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Dashboard
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/dashboard | python3 -m json.tool

# Block recommendations
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/block-recommendations

# Approve a block
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/incidents/INC-1743266582/block

# Dismiss a recommendation
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/incidents/INC-1743266582/dismiss

# Host profile (note nested .profile object in response)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/hosts/172.16.0.5

# Semantic threat search
curl -s -X POST http://localhost:8080/api/v1/threat-search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware file encryption SMB shares", "n_results": 3}'
```

---

*API Reference — CyberSentinel AI v1.0 — 2025/2026*
