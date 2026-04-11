"""
CyberSentinel AI — FastAPI REST Gateway
Production-ready REST API with JWT auth, full DB queries,
ChromaDB semantic search, and real-time Redis integration.
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Optional

import asyncpg
import chromadb
import httpx
from chromadb.utils import embedding_functions
from src.agents.llm_provider import available_providers, get_provider
from src.ingestion.embedder import (
    get_chroma_client as _get_chroma_client,
    get_embedding_function as _get_ef,
    get_or_create_collection as _get_collection,
    semantic_search as _semantic_search,
)
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import redis.asyncio as aioredis
import uvicorn

POSTGRES_URL = os.getenv("POSTGRES_URL")
REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379")
CHROMA_URL   = os.getenv("CHROMA_URL", "http://chromadb:8000")
CHROMA_TOKEN = os.getenv("CHROMA_TOKEN", "")
JWT_SECRET   = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM        = "HS256"
JWT_EXPIRE_MINUTES   = 480

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

app = FastAPI(
    title="CyberSentinel AI API",
    description="Enterprise AI-Powered Threat Detection & Response Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# ── Global clients ────────────────────────────────────────────────────────────
db_pool:      Optional[asyncpg.Pool]    = None
redis_client: Optional[aioredis.Redis] = None
chroma_collection = None


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_alerts_24h:     int
    critical_alerts_24h:  int
    high_alerts_24h:      int
    active_incidents:     int
    packets_analyzed:     int
    unique_ips_seen:      int
    blocked_ips:          int
    top_src_ips:          list
    top_mitre_techniques: list
    top_threat_types:     list
    alerts_by_hour:       list
    risk_score:           float


class AlertResponse(BaseModel):
    id:                    str
    type:                  str
    severity:              str
    timestamp:             datetime
    src_ip:                Optional[str]
    dst_ip:                Optional[str]
    description:           Optional[str]
    mitre_technique:       Optional[str]
    anomaly_score:         Optional[float]
    investigation_summary: Optional[str]
    source:                Optional[str] = "dpi"


class IncidentResponse(BaseModel):
    incident_id:           str
    title:                 str
    severity:              str
    status:                str
    description:           str
    affected_ips:          list
    mitre_techniques:      list
    created_at:            datetime
    updated_at:            Optional[datetime]
    investigation_summary: Optional[str] = None
    block_recommended:     Optional[bool] = False
    block_target_ip:       Optional[str]  = None
    source:                Optional[str]  = "dpi"


class BlockRecommendationResponse(BaseModel):
    incident_id:           str
    title:                 str
    severity:              str
    block_target_ip:       Optional[str]
    investigation_summary: Optional[str]
    mitre_techniques:      list
    created_at:            datetime


class ThreatSearchRequest(BaseModel):
    query:     str
    n_results: int = 5
    collection: str = "threat_signatures"


class IncidentUpdateRequest(BaseModel):
    status:      Optional[str] = None
    notes:       Optional[str] = None
    assigned_to: Optional[str] = None


class IncidentDetailResponse(BaseModel):
    incident_id:           str
    title:                 str
    severity:              str
    status:                str
    description:           Optional[str]
    affected_ips:          list
    mitre_techniques:      list
    evidence:              Optional[str]
    notes:                 Optional[str]
    assigned_to:           Optional[str]
    created_at:            datetime
    updated_at:            Optional[datetime]
    resolved_at:           Optional[datetime]
    investigation_summary: Optional[str]
    block_recommended:     Optional[bool] = False
    block_target_ip:       Optional[str]  = None

class RemediationRequest(BaseModel):
    mitre_technique: str
    alert_context:   str  # "src: 10.0.1.45, dst: 5.188.86.211, port: 443, type: C2_BEACON"

class StatusUpdateRequest(BaseModel):
    status: str  # INVESTIGATING | RESOLVED | CLOSED
    notes:  Optional[str] = None


class PendingReportSubmit(BaseModel):
    report_id:     str
    workflow:      str   # daily_soc | sla_watchdog | board_report
    title:         str
    slack_payload: dict  # full {channel, text, blocks} ready to POST to Slack


class PendingReportResponse(BaseModel):
    report_id:    str
    workflow:     str
    title:        str
    status:       str
    created_at:   datetime
    actioned_at:  Optional[datetime] = None
    actioned_by:  Optional[str]      = None


# ── Startup / shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global db_pool, redis_client, chroma_collection

    db_pool = await asyncpg.create_pool(
        POSTGRES_URL, min_size=5, max_size=20,
        command_timeout=30,
    )
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True, max_connections=10)

    _chroma = _get_chroma_client()
    _ef     = _get_ef()
    chroma_collection = _get_collection(_chroma, "threat_signatures", _ef)


@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()
    if redis_client:
        await redis_client.aclose()


# ── JWT helpers ───────────────────────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username, "role": payload.get("role", "viewer")}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate against the users table in PostgreSQL."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, password_hash, role FROM users WHERE username = $1 AND is_active = TRUE",
            form_data.username,
        )
    if not row or not pwd_context.verify(form_data.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_access_token({"sub": row["username"], "role": row["role"]})
    return {"access_token": token, "token_type": "bearer"}


# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.get("/api/v1/dashboard", response_model=DashboardStats)
async def get_dashboard(
    source: Optional[str] = Query(None, description="Filter by data source: simulator or dpi"),
    user:   dict          = Depends(get_current_user),
):
    """Real-time SOC dashboard statistics from TimescaleDB."""
    src_filter = f"AND COALESCE(source, 'dpi') = '{source.lower()}'" if source else ""
    async with db_pool.acquire() as conn:
        counts = await conn.fetchrow(f"""
            SELECT
                COUNT(*)                                                          AS total_24h,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL')                    AS critical_24h,
                COUNT(*) FILTER (WHERE severity = 'HIGH')                        AS high_24h
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours' {src_filter}
        """)

        active_incidents = await conn.fetchval(
            f"SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN','INVESTIGATING') {src_filter.replace('alerts', 'incidents') if source else ''}"
        ) or 0

        packets_analyzed = await conn.fetchval(
            f"SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours' {src_filter}"
        ) or 0

        unique_ips = await conn.fetchval(
            f"SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours' {src_filter}"
        ) or 0

        blocked_ips = await conn.fetchval(
            "SELECT COUNT(*) FROM firewall_rules WHERE action = 'BLOCK' AND (expires_at IS NULL OR expires_at > NOW())"
        ) or 0

        top_src_ips = await conn.fetch(f"""
            SELECT host(src_ip) AS src_ip, COUNT(*) AS alert_count, MAX(severity) AS max_severity
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours' AND src_ip IS NOT NULL {src_filter}
            GROUP BY src_ip ORDER BY alert_count DESC LIMIT 10
        """)

        top_mitre = await conn.fetch(f"""
            SELECT mitre_technique, COUNT(*) AS count
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours'
              AND mitre_technique IS NOT NULL AND mitre_technique != '' {src_filter}
            GROUP BY mitre_technique ORDER BY count DESC LIMIT 10
        """)

        top_types = await conn.fetch(f"""
            SELECT type, COUNT(*) AS count
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours' {src_filter}
            GROUP BY type ORDER BY count DESC LIMIT 5
        """)

        alerts_by_hour = await conn.fetch(f"""
            SELECT DATE_TRUNC('hour', timestamp) AS hour,
                   COUNT(*) AS count, severity
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours' {src_filter}
            GROUP BY hour, severity ORDER BY hour
        """)

    # Compute weighted risk score (0.0 – 1.0)
    c  = counts["critical_24h"] or 0
    h  = counts["high_24h"]     or 0
    t  = counts["total_24h"]    or 1
    risk_score = min(1.0, round((c * 10 + h * 3) / max(t * 5, 1), 4))

    return DashboardStats(
        total_alerts_24h     = counts["total_24h"]    or 0,
        critical_alerts_24h  = counts["critical_24h"] or 0,
        high_alerts_24h      = counts["high_24h"]     or 0,
        active_incidents     = active_incidents,
        packets_analyzed     = packets_analyzed,
        unique_ips_seen      = unique_ips,
        blocked_ips          = blocked_ips,
        top_src_ips          = [{"ip": r["src_ip"], "count": r["alert_count"], "severity": r["max_severity"]} for r in top_src_ips],
        top_mitre_techniques = [{"technique": r["mitre_technique"], "count": r["count"]} for r in top_mitre],
        top_threat_types     = [{"type": r["type"], "count": r["count"]} for r in top_types],
        alerts_by_hour       = [{"hour": r["hour"].isoformat(), "count": r["count"], "severity": r["severity"]} for r in alerts_by_hour],
        risk_score           = risk_score,
    )


# ── ALERTS ────────────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(
    severity:   Optional[str] = Query(None, description="Filter by severity level"),
    src_ip:     Optional[str] = Query(None, description="Filter by source IP"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    source:     Optional[str] = Query(None, description="Filter by data source: simulator or dpi"),
    hours:      int           = Query(24,  ge=1, le=8760),
    limit:      int           = Query(100, ge=1, le=1000),
    offset:     int           = Query(0,   ge=0),
    user:       dict          = Depends(get_current_user),
):
    """Get paginated, filterable security alerts from TimescaleDB."""
    conditions = ["timestamp > NOW() - $1 * INTERVAL '1 hour'"]
    params: list = [hours]

    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")
    if src_ip:
        params.append(src_ip)
        conditions.append(f"host(src_ip) = ${len(params)}")
    if alert_type:
        params.append(alert_type)
        conditions.append(f"type = ${len(params)}")
    if source:
        params.append(source.lower())
        conditions.append(f"COALESCE(source, 'dpi') = ${len(params)}")

    where = " AND ".join(conditions)
    params += [limit, offset]

    query = f"""
        SELECT id::text, type, severity, timestamp,
               host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
               description, mitre_technique, anomaly_score, investigation_summary,
               COALESCE(source, 'dpi') AS source
        FROM alerts
        WHERE {where}
        ORDER BY timestamp DESC
        LIMIT ${len(params) - 1} OFFSET ${len(params)}
    """
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    return [AlertResponse(**dict(r)) for r in rows]


# ── THREAT SEARCH ─────────────────────────────────────────────────────────────
@app.post("/api/v1/threat-search")
async def semantic_threat_search(
    request: ThreatSearchRequest,
    user:    dict = Depends(get_current_user),
):
    """Semantic similarity search against ChromaDB threat knowledge base."""
    if not chroma_collection:
        raise HTTPException(status_code=503, detail="ChromaDB not available")

    items = _semantic_search(
        chroma_collection,
        query=request.query,
        n_results=min(request.n_results, 20),
    )
    return {"query": request.query, "results": items, "total": len(items)}


# ── INCIDENTS ─────────────────────────────────────────────────────────────────
@app.get("/api/v1/incidents", response_model=List[IncidentResponse])
async def get_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity:      Optional[str] = Query(None),
    source:        Optional[str] = Query(None, description="Filter by data source: simulator or dpi"),
    limit:         int           = Query(50, ge=1, le=500),
    user:          dict          = Depends(get_current_user),
):
    """Get all security incidents with optional status/severity filters."""
    conditions, params = [], []

    if status_filter:
        params.append(status_filter.upper())
        conditions.append(f"status = ${len(params)}")
    if severity:
        params.append(severity.upper())
        conditions.append(f"severity = ${len(params)}")
    if source:
        params.append(source.lower())
        conditions.append(f"COALESCE(source, 'dpi') = ${len(params)}")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    query = f"""
        SELECT incident_id, title, severity, status, description,
               affected_ips, mitre_techniques, created_at, updated_at,
               investigation_summary, block_recommended, block_target_ip,
               COALESCE(source, 'dpi') AS source
        FROM incidents
        {where}
        ORDER BY
            CASE status WHEN 'OPEN' THEN 1 WHEN 'INVESTIGATING' THEN 2 ELSE 3 END,
            created_at DESC
        LIMIT ${len(params)}
    """
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    return [
        IncidentResponse(
            **{k: v for k, v in dict(r).items()
               if k in IncidentResponse.__fields__}
        )
        for r in rows
    ]


@app.patch("/api/v1/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    update:      IncidentUpdateRequest,
    user:        dict = Depends(get_current_user),
):
    """Update incident status, notes, or assignment. Requires analyst role."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot update incidents")

    fields, params = [], [incident_id]
    if update.status:
        params.append(update.status.upper())
        fields.append(f"status = ${len(params)}")
    if update.notes:
        params.append(update.notes)
        fields.append(f"notes = ${len(params)}")
    if update.assigned_to:
        params.append(update.assigned_to)
        fields.append(f"assigned_to = ${len(params)}")

    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    fields.append("updated_at = NOW()")
    async with db_pool.acquire() as conn:
        result = await conn.execute(
            f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = $1",
            *params,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "updated": True}


@app.get("/api/v1/incidents/{incident_id}/detail", response_model=IncidentDetailResponse)
async def get_incident_detail(
    incident_id: str,
    user: dict = Depends(get_current_user),
):
    """Full incident detail including investigation summary and resolution notes."""
    async with db_pool.acquire() as conn:
        # Get incident (including investigation_summary stored directly at creation time)
        row = await conn.fetchrow("""
            SELECT incident_id, title, severity, status, description,
                   affected_ips, mitre_techniques, evidence, notes,
                   assigned_to, created_at, updated_at, resolved_at,
                   investigation_summary
            FROM incidents WHERE incident_id = $1
        """, incident_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        # Use summary stored on incident; fall back to alerts table for older records
        summary = row["investigation_summary"] or None
        if not summary:
            mitre = (row["mitre_techniques"] or [])
            if mitre:
                alert_row = await conn.fetchrow("""
                    SELECT investigation_summary FROM alerts
                    WHERE mitre_technique = ANY($1::text[])
                      AND investigation_summary IS NOT NULL
                      AND investigation_summary != ''
                    ORDER BY timestamp DESC LIMIT 1
                """, mitre)
                if alert_row:
                    summary = alert_row["investigation_summary"]

    result = dict(row)
    result["investigation_summary"] = summary
    return IncidentDetailResponse(**result)


@app.patch("/api/v1/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    req: StatusUpdateRequest,
    user: dict = Depends(get_current_user),
):
    """Update incident status with optional resolution notes."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot update incidents")

    valid_statuses = {"INVESTIGATING", "RESOLVED", "CLOSED", "OPEN"}
    status_upper = req.status.upper()
    if status_upper not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    fields = [f"status = $2", "updated_at = NOW()"]
    params = [incident_id, status_upper]

    if req.notes:
        params.append(req.notes)
        fields.append(f"notes = ${len(params)}")

    if status_upper in ("RESOLVED", "CLOSED"):
        fields.append("resolved_at = NOW()")

    async with db_pool.acquire() as conn:
        result = await conn.execute(
            f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = $1",
            *params,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Incident not found")

    return {"incident_id": incident_id, "status": status_upper, "updated": True}


@app.get("/api/v1/block-recommendations", response_model=List[BlockRecommendationResponse])
async def get_block_recommendations(
    source: Optional[str] = Query(None, description="Filter by source: simulator or dpi"),
    user:   dict           = Depends(get_current_user),
):
    """Return pending block recommendations — incidents flagged by AI awaiting analyst approval."""
    src_clause = ""
    params: list = []
    if source:
        params.append(source.lower())
        src_clause = f"AND COALESCE(source, 'dpi') = $1"
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT incident_id, title, severity, block_target_ip,
                   investigation_summary, mitre_techniques, created_at
            FROM incidents
            WHERE block_recommended = TRUE AND status = 'OPEN' {src_clause}
            ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
                created_at DESC
        """, *params)
    return [BlockRecommendationResponse(**dict(r)) for r in rows]


@app.post("/api/v1/incidents/{incident_id}/block")
async def execute_ip_block(
    incident_id: str,
    user: dict = Depends(get_current_user),
):
    """Analyst approves block: write to Redis + firewall_rules, mark incident RESOLVED."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot execute blocks")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT block_target_ip, title, severity FROM incidents WHERE incident_id = $1",
            incident_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    ip = row["block_target_ip"]
    if not ip:
        raise HTTPException(status_code=400, detail="No block target IP recorded on this incident")

    block_data = json.dumps({
        "ip": ip,
        "blocked_at": datetime.utcnow().isoformat(),
        "duration_hours": 24,
        "justification": f"Analyst approved block: {row['title']}",
        "incident_id": incident_id,
    })

    # Write 24h expiring block rule to Redis
    await redis_client.setex(f"blocked:{ip}", 24 * 3600, block_data)

    # Permanent audit record in firewall_rules + resolve the incident
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO firewall_rules
                (ip_address, action, duration_hours, justification, incident_id, created_at)
            VALUES ($1, 'BLOCK', 24, $2, $3, NOW())
        """, ip, f"Analyst approved: {row['title']}", incident_id)

        await conn.execute("""
            UPDATE incidents
            SET status = 'RESOLVED',
                block_recommended = FALSE,
                updated_at = NOW(),
                resolved_at = NOW(),
                notes = COALESCE(notes || E'\\n', '') || $2
            WHERE incident_id = $1
        """, incident_id, f"IP {ip} blocked by analyst.")

    return {"incident_id": incident_id, "blocked_ip": ip, "status": "RESOLVED"}


@app.post("/api/v1/incidents/{incident_id}/dismiss")
async def dismiss_block_recommendation(
    incident_id: str,
    user: dict = Depends(get_current_user),
):
    """Analyst dismisses block recommendation — marks incident RESOLVED without blocking."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot dismiss incidents")

    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE incidents
            SET status = 'RESOLVED',
                block_recommended = FALSE,
                updated_at = NOW(),
                resolved_at = NOW(),
                notes = COALESCE(notes || E'\\n', '') || 'Block recommendation dismissed by analyst.'
            WHERE incident_id = $1
        """, incident_id)

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Incident not found")

    return {"incident_id": incident_id, "dismissed": True, "status": "RESOLVED"}


@app.post("/api/v1/incidents/{incident_id}/remediation")
async def generate_remediation(
    incident_id: str,
    req: RemediationRequest,
    user: dict = Depends(get_current_user),
):
    """Generate AI remediation steps for a specific MITRE technique. One focused call, no tools."""
    from src.agents.prompts import REMEDIATION_PROMPT
    try:
        provider = get_provider()
        response = await provider.chat(
            messages=[{
                "role": "user",
                "content": (
                    f"MITRE Technique: {req.mitre_technique}\n"
                    f"Alert Context: {req.alert_context}\n\n"
                    f"Provide remediation steps."
                ),
            }],
            system=REMEDIATION_PROMPT,
            max_tokens=400,
        )
        remediation_text = response.text

        # Save to incident notes for future views
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE incidents SET notes = $2, updated_at = NOW() WHERE incident_id = $1",
                incident_id, remediation_text,
            )

        return {"incident_id": incident_id, "remediation": remediation_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI remediation failed: {str(e)}")


# ── HOST INTELLIGENCE ─────────────────────────────────────────────────────────
@app.get("/api/v1/hosts/{ip_address}")
async def get_host_intelligence(
    ip_address: str,
    user:       dict = Depends(get_current_user),
):
    """Full behavioral profile, alert history, and block status for an IP."""
    async with db_pool.acquire() as conn:
        profile = await conn.fetchrow(
            "SELECT * FROM behavior_profiles WHERE entity_id = $1",
            ip_address,
        )
        recent_alerts = await conn.fetch("""
            SELECT type, severity, timestamp, host(dst_ip) AS dst_ip, description, mitre_technique, anomaly_score
            FROM alerts WHERE host(src_ip) = $1
            ORDER BY timestamp DESC LIMIT 20
        """, ip_address)
        block_count = await conn.fetchval(
            "SELECT COUNT(*) FROM firewall_rules WHERE ip_address = $1 AND action = 'BLOCK'",
            ip_address,
        ) or 0
        incident_count = await conn.fetchval(
            "SELECT COUNT(*) FROM incidents WHERE $1 = ANY(affected_ips)",
            ip_address,
        ) or 0

    is_blocked  = bool(await redis_client.exists(f"blocked:{ip_address}"))
    is_isolated = bool(await redis_client.exists(f"isolated:{ip_address}"))

    return {
        "ip_address":     ip_address,
        "is_blocked":     is_blocked,
        "is_isolated":    is_isolated,
        "block_count":    block_count,
        "incident_count": incident_count,
        "profile":        dict(profile) if profile else None,
        "recent_alerts":  [dict(a) for a in recent_alerts],
    }


# ── INVESTIGATIONS CONTROL ────────────────────────────────────────────────────
VALID_SOURCES = {"simulator", "dpi"}


class ControlRequest(BaseModel):
    investigations_paused: bool


def _pause_key(source: Optional[str]) -> str:
    src = (source or "").lower()
    return f"investigations:paused:{src}" if src in VALID_SOURCES else f"investigations:paused:{src}"


@app.get("/api/v1/control")
async def get_control(
    source: Optional[str] = Query(None, description="simulator or dpi"),
    user:   dict          = Depends(get_current_user),
):
    """Return paused state for a specific source (simulator or dpi)."""
    key = _pause_key(source or "dpi")
    paused = bool(await redis_client.get(key))
    return {"investigations_paused": paused, "source": source or "dpi"}


@app.post("/api/v1/control")
async def set_control(
    req:    ControlRequest,
    source: Optional[str] = Query(None, description="simulator or dpi"),
    user:   dict          = Depends(get_current_user),
):
    """Pause or resume AI investigations for a specific source."""
    key = _pause_key(source or "dpi")
    if req.investigations_paused:
        await redis_client.set(key, "1")
    else:
        await redis_client.delete(key)
    state = "PAUSED" if req.investigations_paused else "RESUMED"
    return {"investigations_paused": req.investigations_paused, "source": source or "dpi", "state": state}


# ── FIREWALL RULES ───────────────────────────────────────────────────────────
@app.get("/api/v1/firewall-rules")
async def list_firewall_rules(
    status_filter: Optional[str] = Query(None, alias="status", description="active | expired | all (default: all)"),
    user: dict = Depends(get_current_user),
):
    """Return all firewall rules with live active/expired status."""
    now = datetime.utcnow()
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id::text, ip_address::text, action, justification,
                   incident_id, created_by, created_at, duration_hours, expires_at
            FROM firewall_rules
            ORDER BY created_at DESC
            LIMIT 500
        """)

    rules = []
    for r in rows:
        is_active = r["expires_at"] is None or r["expires_at"].replace(tzinfo=None) > now
        entry = {
            "id":            r["id"],
            "ip_address":    r["ip_address"],
            "action":        r["action"],
            "justification": r["justification"],
            "incident_id":   r["incident_id"],
            "created_by":    r["created_by"],
            "created_at":    r["created_at"].isoformat(),
            "duration_hours":r["duration_hours"],
            "expires_at":    r["expires_at"].isoformat() if r["expires_at"] else None,
            "is_active":     is_active,
        }
        if status_filter == "active" and not is_active:
            continue
        if status_filter == "expired" and is_active:
            continue
        rules.append(entry)

    return rules


@app.delete("/api/v1/firewall-rules")
async def unblock_ip(
    ip: str = Query(..., description="IP address to unblock (without CIDR suffix)"),
    user: dict = Depends(get_current_user),
):
    """Analyst manually unblocks an IP — removes Redis key and expires all active rules for that IP."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot unblock IPs")

    # Strip any CIDR suffix that may have been passed
    clean_ip = ip.split("/")[0].strip()

    # Remove Redis block key (try both bare IP and /32 form)
    await redis_client.delete(f"blocked:{clean_ip}")
    await redis_client.delete(f"blocked:{clean_ip}/32")

    # Expire all active rules where host(ip_address) matches the bare IP
    async with db_pool.acquire() as conn:
        updated = await conn.execute("""
            UPDATE firewall_rules
            SET expires_at = NOW(), duration_hours = 0
            WHERE host(ip_address::inet) = $1
              AND (expires_at IS NULL OR expires_at > NOW())
        """, clean_ip)

    rows_updated = int(updated.split()[-1]) if updated else 0
    return {
        "ip_address":    clean_ip,
        "unblocked":     True,
        "rules_expired": rows_updated,
        "message":       f"IP {clean_ip} unblocked. {rows_updated} active rule(s) expired.",
    }


# ── HEALTH ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Platform health check — verifies all upstream dependencies."""
    checks = {"api": "ok", "postgres": "error", "redis": "error", "chromadb": "error"}

    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["postgres"] = "ok"
    except Exception:
        pass

    try:
        await redis_client.ping()
        checks["redis"] = "ok"
    except Exception:
        pass

    try:
        chroma_collection.count()
        checks["chromadb"] = "ok"
    except Exception:
        pass

    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    checks["llm"] = available_providers()
    return {"status": overall, "checks": checks, "version": "1.0.0"}


@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    try:
        async with db_pool.acquire() as conn:
            alert_count  = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '1 hour'")
            open_incidents = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE status = 'OPEN'")
            active_blocks  = await conn.fetchval("SELECT COUNT(*) FROM firewall_rules WHERE expires_at > NOW()")
    except Exception:
        alert_count = open_incidents = active_blocks = 0

    lines = [
        "# HELP cybersentinel_alerts_1h Alerts in the last hour",
        "# TYPE cybersentinel_alerts_1h gauge",
        f"cybersentinel_alerts_1h {alert_count}",
        "# HELP cybersentinel_open_incidents Open security incidents",
        "# TYPE cybersentinel_open_incidents gauge",
        f"cybersentinel_open_incidents {open_incidents}",
        "# HELP cybersentinel_active_blocks Active firewall blocks",
        "# TYPE cybersentinel_active_blocks gauge",
        f"cybersentinel_active_blocks {active_blocks}",
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


# ── n8n Workflow Trigger Proxy ────────────────────────────────────────────────

N8N_URL = os.getenv("N8N_URL", "http://host.docker.internal:5678")

WORKFLOW_WEBHOOKS = {
    "daily":  "run-daily-report",
    "sla":    "run-sla-check",
    "board":  "run-board-report",
}

@app.post("/api/v1/workflows/trigger/{workflow_id}")
async def trigger_workflow(workflow_id: str, user: dict = Depends(get_current_user)):
    """Proxy trigger to n8n webhook — avoids CORS from browser."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot trigger workflows")
    path = WORKFLOW_WEBHOOKS.get(workflow_id)
    if not path:
        raise HTTPException(status_code=404, detail=f"Unknown workflow: {workflow_id}. Valid: {list(WORKFLOW_WEBHOOKS)}")
    url = f"{N8N_URL}/webhook/{path}"
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(url, json={"triggered_by": user.get("username"), "timestamp": datetime.utcnow().isoformat()})
        return {"workflow": workflow_id, "status": "triggered", "n8n_status": resp.status_code}
    except httpx.TimeoutException:
        # Workflow started but response took >90s — treat as triggered (still running in n8n)
        return {"workflow": workflow_id, "status": "triggered", "n8n_status": 202}
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail=f"n8n not reachable at {N8N_URL}. Check N8N_URL in .env")


# ── Pending Reports (n8n approval queue) ─────────────────────────────────────

@app.post("/api/v1/reports/pending", status_code=201)
async def submit_pending_report(req: PendingReportSubmit):
    """n8n calls this instead of Slack. Stores report for analyst approval."""
    async with db_pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT report_id FROM pending_reports WHERE report_id = $1", req.report_id
        )
        if existing:
            return {"report_id": req.report_id, "status": "already_exists"}
        await conn.execute(
            """INSERT INTO pending_reports (report_id, workflow, title, slack_payload)
               VALUES ($1, $2, $3, $4)""",
            req.report_id, req.workflow, req.title, json.dumps(req.slack_payload)
        )
    return {"report_id": req.report_id, "status": "pending"}


@app.get("/api/v1/reports/pending", response_model=List[PendingReportResponse])
async def get_pending_reports(
    status_filter: Optional[str] = Query(None, alias="status"),
    user: dict = Depends(get_current_user),
):
    """Return reports awaiting approval. Default: PENDING only."""
    st = (status_filter or "PENDING").upper()
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT report_id, workflow, title, status, created_at, actioned_at, actioned_by
               FROM pending_reports WHERE status = $1 ORDER BY created_at DESC""",
            st
        )
    return [PendingReportResponse(**dict(r)) for r in rows]


@app.post("/api/v1/reports/{report_id}/approve")
async def approve_report(report_id: str, user: dict = Depends(get_current_user)):
    """Approve: send Slack payload, mark APPROVED."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot approve reports")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM pending_reports WHERE report_id = $1 AND status = 'PENDING'", report_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="Pending report not found")

    slack_token   = os.getenv("SLACK_BOT_TOKEN", "")
    slack_payload = json.loads(row["slack_payload"])

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {slack_token}", "Content-Type": "application/json"},
            content=json.dumps(slack_payload),
        )
    slack_ok = resp.json().get("ok", False)
    if not slack_ok:
        raise HTTPException(status_code=502, detail=f"Slack error: {resp.json().get('error','unknown')}")

    async with db_pool.acquire() as conn:
        await conn.execute(
            """UPDATE pending_reports
               SET status = 'APPROVED', actioned_at = NOW(), actioned_by = $2
               WHERE report_id = $1""",
            report_id, user.get("username", "unknown")
        )
    return {"report_id": report_id, "status": "APPROVED", "slack_ok": slack_ok}


@app.post("/api/v1/reports/{report_id}/deny")
async def deny_report(report_id: str, user: dict = Depends(get_current_user)):
    """Deny: discard without sending to Slack, mark DENIED."""
    if user.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot deny reports")

    async with db_pool.acquire() as conn:
        updated = await conn.execute(
            """UPDATE pending_reports
               SET status = 'DENIED', actioned_at = NOW(), actioned_by = $2
               WHERE report_id = $1 AND status = 'PENDING'""",
            report_id, user.get("username", "unknown")
        )
    if updated == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Pending report not found")
    return {"report_id": report_id, "status": "DENIED"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
