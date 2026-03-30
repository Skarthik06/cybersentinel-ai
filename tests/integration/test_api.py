"""
Integration tests for the FastAPI gateway.
Requires: docker compose up -d

Credentials are read from environment variables:
  TEST_ADMIN_USERNAME  (default: admin)
  TEST_ADMIN_PASSWORD  — required, set in .env or CI secrets
"""
import os
import pytest
import httpx

BASE = "http://localhost:8080"

_TEST_USERNAME = os.getenv("TEST_ADMIN_USERNAME", "admin")
_TEST_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD")


@pytest.fixture(scope="module")
def token():
    if not _TEST_PASSWORD:
        pytest.skip("TEST_ADMIN_PASSWORD environment variable not set")
    resp = httpx.post(
        f"{BASE}/auth/token",
        data={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
    )
    assert resp.status_code == 200, f"Auth failed: {resp.text}"
    return resp.json()["access_token"]


def test_health_check():
    resp = httpx.get(f"{BASE}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


def test_authenticated_dashboard(token):
    resp = httpx.get(
        f"{BASE}/api/v1/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total_alerts_24h" in data


def test_unauthenticated_request():
    resp = httpx.get(f"{BASE}/api/v1/dashboard")
    assert resp.status_code == 401
