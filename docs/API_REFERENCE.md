# API Reference

**CyberSentinel AI REST API — v1.3.0**
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

**Token lifespan:** 480 minutes (8 hours).

**Default credentials:**

| Username | Password |
|----------|----------|
| admin | cybersentinel2025 |

> **Note:** Only the admin account is active. All authenticated endpoints accept the admin JWT token.

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
  "version": "1.3.0"
}
```

**Status values:** `healthy` (all checks ok) or `degraded` (one or more checks failed).

---

### GET `/api/v1/dashboard`

Real-time SOC statistics from TimescaleDB and Redis.

**Auth:** Bearer token

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
    { "hour": "2026-04-16T09:00:00", "count": 12, "severity": "HIGH" }
  ],
  "risk_score": 0.62
}
```

**Notes:**
- `risk_score` — range 0.0–1.0 computed from critical/high ratio
- `active_incidents` — OPEN and INVESTIGATING only
- `blocked_ips` — active (non-expired) firewall rules

---

### GET `/api/v1/alerts`

Paginated, filterable security alerts.

**Auth:** Bearer token

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | null | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `src_ip` | string | null | Filter by source IP |
| `alert_type` | string | null | Filter by type (e.g. `C2_BEACON_DETECTED`) |
| `hours` | integer | 24 | Look back N hours (max 8760) |
| `limit` | integer | 100 | Results per page (max 1000) |
| `offset` | integer | 0 | Pagination offset |

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "C2_BEACON_DETECTED",
    "severity": "CRITICAL",
    "timestamp": "2026-04-16T09:23:11.000Z",
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

**Note on `anomaly_score`:** From v1.3.0, this is the IsolationForest-blended score (75% ChromaDB + 25% IsolationForest), not raw cosine similarity.

---

### POST `/api/v1/threat-search`

Semantic similarity search against ChromaDB threat knowledge base.

**Auth:** Bearer token

**Request Body:**
```json
{
  "query": "host making regular outbound connections with high payload entropy to unusual port",
  "n_results": 5,
  "collection": "threat_signatures"
}
```

**Parameters:**
- `query` — natural language description
- `n_results` — 1–20 (default 5)
- `collection` — `threat_signatures` | `cti_reports` | `cve_database`

**Response:**
```json
{
  "query": "host making regular outbound connections...",
  "results": [
    {
      "document": "Host exhibits C2 beacon behavior...",
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

Scores above 0.65 indicate strong semantic match.

---

### GET `/api/v1/incidents`

List security incidents with optional filters.

**Auth:** Bearer token

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
    "created_at": "2026-04-16T17:33:02.000Z",
    "updated_at": "2026-04-16T17:33:02.000Z"
  }
]
```

**Ordering:** OPEN first, then INVESTIGATING, then others. Within each status, CRITICAL before HIGH, newest first.

---

### GET `/api/v1/incidents/{incident_id}/detail`

Full detail for a single incident including investigation summary, evidence, and linked metadata.

**Auth:** Bearer token

**Path Parameter:** `incident_id` — e.g. `INC-1743266582`

**Response:** Full `IncidentDetailResponse` with all fields including `investigation_summary`, `evidence`, `block_recommended`, `block_target_ip`, and `source`.

---

### PATCH `/api/v1/incidents/{incident_id}`

Update incident status, notes, or assignment.

**Auth:** Bearer token

**Request Body (all fields optional):**
```json
{
  "status": "RESOLVED",
  "notes": "IP blocked. Root cause: phishing email.",
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

All pending block recommendations — incidents where `block_recommended=TRUE` and `status='OPEN'`.

**Auth:** Bearer token

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
    "created_at": "2026-04-16T17:33:02.000Z"
  }
]
```

**Ordering:** CRITICAL first, then HIGH, then newest.

The RESPONSE tab polls this endpoint every 30 seconds.

---

### POST `/api/v1/incidents/{incident_id}/block`

Analyst approves a block recommendation. Executes the block and marks the incident RESOLVED.

**Auth:** Bearer token

**What this does:**
1. Inserts row into `firewall_rules` (PostgreSQL persistent block)
2. Sets `Redis blocked:{ip}` with 24-hour TTL
3. Updates incident `status = 'RESOLVED'`
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

Analyst dismisses a block recommendation without blocking.

**Auth:** Bearer token

**What this does:**
1. Updates incident `status = 'RESOLVED'`
2. Does NOT insert into `firewall_rules` or Redis
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

### POST `/api/v1/incidents/{incident_id}/remediation`

Generate an AI Technical Playbook for an incident on demand.

**Auth:** Bearer token

**Response:**
```json
{
  "incident_id": "INC-20260416074415",
  "playbook": "## TECHNICAL PLAYBOOK\n\n**CONTAINMENT (now)**\n```\niptables -I INPUT -s 185.220.101.47 -j DROP\n```\n\n**ERADICATION (next 2h)**\n..."
}
```

Playbook contains actual shell/CLI commands using real IPs and ports, Snort/Sigma detection rules, and a verification checklist. Cost: ~1 LLM call (~$0.0002 with GPT-4o mini).

---

### GET `/api/v1/hosts/{ip_address}`

Full behavioral profile and alert history for a specific IP.

**Auth:** Bearer token

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
    "anomaly_score": 0.913,
    "observation_count": 48291,
    "avg_bytes_per_min": 8420.4,
    "avg_entropy": 7.12,
    "profile_text": "Entity 172.16.0.5 (host) behavior...",
    "updated_at": "2026-04-16T17:33:02.000Z"
  },
  "recent_alerts": [
    {
      "type": "DATA_EXFILTRATION_DETECTED",
      "severity": "HIGH",
      "timestamp": "2026-04-16T17:05:59.000Z",
      "dst_ip": "93.184.220.29",
      "mitre_technique": "T1048.003",
      "anomaly_score": 0.83
    }
  ]
}
```

| Field | Source |
|-------|--------|
| `is_blocked` | Redis `blocked:{ip}` |
| `block_count` | PostgreSQL `firewall_rules` COUNT |
| `incident_count` | PostgreSQL `incidents` COUNT |
| `profile` | PostgreSQL `behavior_profiles` — nested object |
| `profile.anomaly_score` | IsolationForest-blended score |
| `recent_alerts` | PostgreSQL `alerts` — last 20, newest first |

**Important:** Access profile metrics via `host.profile?.anomaly_score` (nested under `profile`), not `host.anomaly_score`.

---

### GET `/api/v1/firewall-rules`

List all firewall rules (blocked IPs).

**Auth:** Bearer token

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | all | `active`, `expired`, `all` |

**Response:**
```json
[
  {
    "id": "550e8400-...",
    "ip_address": "185.220.101.47",
    "action": "BLOCK",
    "justification": "Analyst approved: C2 beacon confirmed",
    "incident_id": "INC-20260416074415",
    "created_by": "admin",
    "created_at": "2026-04-16T08:00:00.000Z",
    "duration_hours": 24,
    "expires_at": "2026-04-17T08:00:00.000Z",
    "is_active": true
  }
]
```

---

### DELETE `/api/v1/firewall-rules`

Unblock an IP. Removes Redis key and expires all active rules for that IP.

**Auth:** Bearer token

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | Yes | IP to unblock (CIDR suffix stripped automatically) |

```http
DELETE /api/v1/firewall-rules?ip=185.220.101.47
Authorization: Bearer {token}
```

**What this does:**
1. Deletes Redis keys `blocked:{ip}` and `blocked:{ip}/32`
2. Sets `expires_at = NOW()` on all active `firewall_rules` rows for this IP

**Response:**
```json
{
  "ip_address": "185.220.101.47",
  "unblocked": true,
  "rules_expired": 1,
  "message": "IP 185.220.101.47 unblocked. 1 active rule(s) expired."
}
```

---

### GET `/api/v1/campaigns`

All attacker campaigns ordered by most recent activity.

**Auth:** Bearer token

**Response:**
```json
[
  {
    "campaign_id": "10.0.0.55-1713200000",
    "src_ip": "10.0.0.55",
    "first_seen": "2026-04-16T08:00:00.000Z",
    "last_seen": "2026-04-16T17:30:00.000Z",
    "incident_count": 5,
    "max_severity": "CRITICAL",
    "mitre_stages": ["T1046", "T1021.002", "T1071.001", "T1486"],
    "campaign_summary": null
  }
]
```

**Notes:**
- Campaigns are grouped by `src_ip` within 24-hour windows
- `max_severity` is a ratchet — it can only increase, never decrease
- `mitre_stages` is the union of all MITRE techniques across campaign incidents
- `campaign_summary` is null unless explicitly generated by AI

---

### GET `/api/v1/control`

Check whether AI investigation is paused for a source.

**Auth:** Bearer token

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | string | `dpi` | `simulator` or `dpi` |

**Response:**
```json
{
  "investigations_paused": false,
  "source": "simulator"
}
```

---

### POST `/api/v1/control`

Pause or resume AI investigation for a specific source.

**Auth:** Bearer token

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `source` | string | `simulator` or `dpi` |

**Request Body:**
```json
{
  "investigations_paused": true
}
```

**Response:**
```json
{
  "investigations_paused": true,
  "source": "simulator",
  "state": "PAUSED"
}
```

When paused, incoming HIGH/CRITICAL alerts still create basic OPEN incidents via `_create_pending_incident()` — alerts are never silently dropped.

---

## Error Responses

```json
{
  "detail": "Invalid or expired authentication token"
}
```

| Status Code | Meaning |
|-------------|---------|
| 400 | Bad request — invalid parameters |
| 401 | Unauthorized — missing or invalid token |
| 404 | Not found — resource doesn't exist |
| 422 | Unprocessable Entity — request body validation failed |
| 503 | Service Unavailable — upstream dependency down |

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

# Dashboard
dashboard = httpx.get(f"{BASE}/api/v1/dashboard", headers=headers).json()
print(f"Risk score: {dashboard['risk_score']}")

# Block recommendations
recs = httpx.get(f"{BASE}/api/v1/block-recommendations", headers=headers).json()
for rec in recs:
    print(f"Block: {rec['block_target_ip']} — {rec['title']}")

# Approve a block
if recs:
    result = httpx.post(f"{BASE}/api/v1/incidents/{recs[0]['incident_id']}/block", headers=headers).json()
    print(f"Blocked: {result['blocked_ip']}")

# Campaigns
campaigns = httpx.get(f"{BASE}/api/v1/campaigns", headers=headers).json()
for c in campaigns:
    print(f"Campaign {c['campaign_id']}: {c['incident_count']} incidents, severity={c['max_severity']}")

# Host profile — note nested 'profile' key
host = httpx.get(f"{BASE}/api/v1/hosts/172.16.0.5", headers=headers).json()
profile = host.get("profile") or {}
print(f"Anomaly score: {profile.get('anomaly_score', 0)}")
print(f"Observations: {profile.get('observation_count', 0)}")
```

### JavaScript

```javascript
const BASE = "http://localhost:8080";

const { access_token } = await fetch(`${BASE}/auth/token`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "username=admin&password=cybersentinel2025"
}).then(r => r.json());

const headers = { Authorization: `Bearer ${access_token}` };

// Campaigns
const campaigns = await fetch(`${BASE}/api/v1/campaigns`, { headers }).then(r => r.json());
console.log(`Active campaigns: ${campaigns.length}`);

// Host profile — nested .profile object
const host = await fetch(`${BASE}/api/v1/hosts/172.16.0.5`, { headers }).then(r => r.json());
const score = host.profile?.anomaly_score ?? 0;
console.log(`${host.ip_address} | blocked=${host.is_blocked} | score=${score}`);
```

### curl

```bash
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

# Campaigns
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/campaigns

# Semantic threat search
curl -s -X POST http://localhost:8080/api/v1/threat-search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware file encryption SMB shares", "n_results": 3}'
```

---

## Full Endpoint Summary

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/token` | Get JWT token |
| `GET` | `/health` | Platform health check |
| `GET` | `/api/v1/dashboard` | SOC statistics |
| `GET` | `/api/v1/alerts` | Paginated alert list |
| `POST` | `/api/v1/threat-search` | ChromaDB semantic search |
| `GET` | `/api/v1/incidents` | Incident list |
| `GET` | `/api/v1/incidents/{id}/detail` | Single incident full detail |
| `PATCH` | `/api/v1/incidents/{id}` | Update incident |
| `GET` | `/api/v1/block-recommendations` | Pending block recommendations |
| `POST` | `/api/v1/incidents/{id}/block` | Approve block |
| `POST` | `/api/v1/incidents/{id}/dismiss` | Dismiss recommendation |
| `POST` | `/api/v1/incidents/{id}/remediation` | Generate AI playbook |
| `GET` | `/api/v1/hosts/{ip}` | Host behavioral profile |
| `GET` | `/api/v1/firewall-rules` | List blocked IPs |
| `DELETE` | `/api/v1/firewall-rules?ip={ip}` | Unblock an IP |
| `GET` | `/api/v1/campaigns` | Attacker campaign list |
| `GET` | `/api/v1/control?source=` | Check investigation pause state |
| `POST` | `/api/v1/control?source=` | Pause / resume investigations |
| `GET` | `/metrics` | Prometheus metrics |

---

*API Reference — CyberSentinel AI v1.3.0 — 2025/2026*
