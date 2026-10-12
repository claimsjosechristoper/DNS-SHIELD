"""
Automated Test Suite for DNS Security Gateway REST Endpoints and Administration.
Verifies authentication, deterministic ALLOW/BLOCK statistics, rule CRUD,
blocklist management, upstream configuration, and audit logging.
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app
from gateway.config import GatewayConfig

client = TestClient(app)
AUTH_HEADER = {"X-API-Key": GatewayConfig.ADMIN_API_KEY}

def test_api_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "total_requests" in data
    assert "allowed_requests" in data
    assert "blocked_requests" in data
    assert "block_rate_percentage" not in data

def test_api_dns_statistics():
    response = client.get("/api/dns/statistics")
    assert response.status_code == 200
    data = response.json()
    assert "total_queries" in data
    assert "allowed_queries" in data
    assert "blocked_queries" in data
    assert "block_rate_percentage" not in data

def test_api_auth_login():
    # Invalid key
    bad_resp = client.post("/api/auth/login", json={"api_key": "wrong-key"})
    assert bad_resp.status_code == 401

    # Valid key
    ok_resp = client.post("/api/auth/login", json={"api_key": GatewayConfig.ADMIN_API_KEY})
    assert ok_resp.status_code == 200
    assert ok_resp.json()["status"] == "SUCCESS"

def test_api_dns_logs_and_latest():
    response = client.get("/api/dns/logs?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert "total" in data

    latest = client.get("/api/dns/latest")
    assert latest.status_code == 200

def test_api_custom_rules_crud():
    # Unauthorized
    unauth = client.get("/api/rules/custom")
    assert unauth.status_code == 401

    # Create Rule
    create_resp = client.post(
        "/api/rules/custom",
        json={"domain": "api-test-blocked.local", "rule_type": "subdomain", "reason": "Test block"},
        headers=AUTH_HEADER
    )
    assert create_resp.status_code == 200
    rule_id = create_resp.json()["id"]

    # List Rules
    list_resp = client.get("/api/rules/custom", headers=AUTH_HEADER)
    assert list_resp.status_code == 200
    domains = [r["domain"] for r in list_resp.json()]
    assert "api-test-blocked.local" in domains

    # Toggle Rule
    toggle_resp = client.put(f"/api/rules/custom/{rule_id}/toggle", headers=AUTH_HEADER)
    assert toggle_resp.status_code == 200

    # Delete Rule
    del_resp = client.delete(f"/api/rules/custom/{rule_id}", headers=AUTH_HEADER)
    assert del_resp.status_code == 200

def test_api_allowlist_crud():
    create_resp = client.post(
        "/api/rules/allowlist",
        json={"domain": "api-test-allowed.local", "rule_type": "exact", "reason": "Test allow"},
        headers=AUTH_HEADER
    )
    assert create_resp.status_code == 200
    allow_id = create_resp.json()["id"]

    list_resp = client.get("/api/rules/allowlist", headers=AUTH_HEADER)
    assert list_resp.status_code == 200

    del_resp = client.delete(f"/api/rules/allowlist/{allow_id}", headers=AUTH_HEADER)
    assert del_resp.status_code == 200

def test_api_blocklist_sources_and_sync():
    list_resp = client.get("/api/blocklists", headers=AUTH_HEADER)
    assert list_resp.status_code == 200
    sources = list_resp.json()
    assert len(sources) > 0

    first_id = sources[0]["id"]
    sync_resp = client.post(f"/api/blocklists/{first_id}/sync", headers=AUTH_HEADER)
    assert sync_resp.status_code in (200, 400)

def test_api_settings_and_audit():
    settings_resp = client.get("/api/settings", headers=AUTH_HEADER)
    assert settings_resp.status_code == 200

    # Update settings
    up_resp = client.put(
        "/api/settings",
        json={"blocked_response_rcode": "REFUSED", "log_retention_days": 45},
        headers=AUTH_HEADER
    )
    assert up_resp.status_code == 200

    # Verify audit log captures actions
    audit_resp = client.get("/api/audit", headers=AUTH_HEADER)
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) > 0
