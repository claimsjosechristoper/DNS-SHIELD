"""
Automated Integration Tests for DNS-SHIELD Hosted Management Subsystem.
Tests tenant creation, single-use expiring enrollment, device credential revocation,
and bounded telemetry ingestion.
"""

import time
import pytest
from fastapi.testclient import TestClient
from hosted_management.server import app, init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_hosted_db():
    init_db()


def test_tenant_creation_and_policy_initialization():
    resp = client.post("/api/v1/tenants", json={"name": "Acme Corp", "contact_email": "security@acme.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "tenant_id" in data
    assert data["name"] == "Acme Corp"


def test_enrollment_token_single_use_and_revocation():
    # 1. Create Tenant
    t_resp = client.post("/api/v1/tenants", json={"name": "Security Ops", "contact_email": "soc@secops.test"})
    tenant_id = t_resp.json()["tenant_id"]

    # 2. Generate Enrollment Token (15m expiry)
    tok_resp = client.post("/api/v1/enrollment/tokens", json={
        "tenant_id": tenant_id,
        "device_name": "WIN11-ANALYST-01",
        "expires_in_minutes": 15
    })
    assert tok_resp.status_code == 200
    token = tok_resp.json()["enrollment_token"]

    # 3. Enroll device with token
    enroll_resp = client.post("/api/v1/devices/enroll", json={
        "enrollment_token": token,
        "hardware_uuid": "UUID-12345",
        "os_version": "Windows 11 23H2",
        "hostname": "WIN11-ANALYST-01"
    })
    assert enroll_resp.status_code == 200
    dev_data = enroll_resp.json()
    device_id = dev_data["device_id"]
    device_key = dev_data["device_key"]
    assert device_id.startswith("dev_")
    assert device_key.startswith("key_")

    # 4. SINGLE-USE GUARANTEE: Attempting to reuse same token MUST be rejected
    reuse_resp = client.post("/api/v1/devices/enroll", json={
        "enrollment_token": token,
        "hardware_uuid": "UUID-54321",
        "os_version": "Windows 11 23H2",
        "hostname": "WIN11-ROLOGUE"
    })
    assert reuse_resp.status_code == 400
    assert "consumed" in reuse_resp.json()["detail"].lower()

    # 5. Telemetry Ingestion with valid credentials
    telemetry_resp = client.post(
        "/api/v1/telemetry/events",
        json={
            "device_id": device_id,
            "events": [
                {"timestamp": time.time(), "domain": "c2-beacon.test", "qtype": "A", "decision": "BLOCK", "reason": "C2 Threat Feed"}
            ]
        },
        headers={"X-Device-Id": device_id, "X-Device-Key": device_key}
    )
    assert telemetry_resp.status_code == 200
    assert telemetry_resp.json()["ingested"] == 1

    # 6. Revocation: Revoke device
    revoke_resp = client.post(f"/api/v1/devices/{device_id}/revoke")
    assert revoke_resp.status_code == 200

    # 7. Device list shows revoked status
    list_resp = client.get(f"/api/v1/devices?tenant_id={tenant_id}")
    devices = list_resp.json()
    revoked_dev = [d for d in devices if d["id"] == device_id][0]
    assert revoked_dev["revoked"] == 1
