"""
Pydantic schemas for request/response validation across all API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AlertResponse(BaseModel):
    id: str
    type: str
    severity: str
    src_ip: str
    dst_ip: Optional[str]
    timestamp: datetime
    mitre_technique: Optional[str]
    anomaly_score: Optional[float]
    details: Optional[Dict[str, Any]]


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    description: str
    affected_ips: List[str]
    mitre_techniques: List[str]
    created_at: datetime
    updated_at: datetime


class IncidentUpdateRequest(BaseModel):
    status: Optional[str]
    notes: Optional[str]
    assigned_to: Optional[str]


class ThreatSearchRequest(BaseModel):
    query: str = Field(..., description="Natural language threat description")
    collection: str = Field("threat_signatures", description="ChromaDB collection to search")
    n_results: int = Field(5, ge=1, le=20)


class DashboardResponse(BaseModel):
    total_alerts_24h: int
    critical_alerts_24h: int
    high_alerts_24h: int
    active_incidents: int
    blocked_ips: int
    unique_ips_seen: int
    top_threat_types: List[Dict[str, Any]]
    risk_score: float


class HealthResponse(BaseModel):
    status: str
    checks: Dict[str, str]
    version: str = "1.0.0"
