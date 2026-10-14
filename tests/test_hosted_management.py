"""
Automated Integration Tests for DNS-SHIELD Hosted Management Subsystem.

Tests:
- Authenticated signed policy delivery with publisher digital signatures and SHA-256 integrity.
- Client-side policy verification: schema validation, rollback protection, and tamper detection.
- Single-use, expiring WebSocket connection tickets (elimination of long-lived API keys in URLs).
- WebSocket ticket reuse rejection and expiry rejection.
- Cross-tenant access denial (enforcing tenant credential boundaries).
- Single-use expiring enrollment tokens (rejection on reuse and expiration).
- Device credential revocation and telemetry ingestion blocking.
- Telemetry toggle settings (disabling telemetry halts event ingestion).
"""

import time
import pytest
from fastapi.testclient import TestClient
from hosted_management.server import app, init_db
from hosted_management.policy_verifier import (
    PolicyVerifier, PolicyVerificationError, compute_policy_hash, compute_publisher_signature
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_hosted_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_hosted.db"
    import hosted_management.server as srv
    monkeypatch.setattr(srv, "DB_PATH", test_db)
    srv.init_db()


def test_tenant_creation_and_policy_initialization():
    resp = client.post("/api/v1/tenants", json={"name": "Acme Corp", "contact_email": "security@acme.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "tenant_id" in data
    assert "api_key" in data
    assert "policy_signing_key" in data
    assert data["name"] == "Acme Corp"


def test_signed_policy_distribution_and_client_verification():
    """Policies must be digitally signed by publisher and verified client-side against rollback and tampering."""
    t_resp = client.post("/api/v1/tenants", json={"name": "Signed Corp", "contact_email": "signed@corp.test"}).json()
    tenant_id = t_resp["tenant_id"]
    api_key = t_resp["api_key"]
    signing_key = t_resp["policy_signing_key"].encode("utf-8")

    # Publish policy v2
    rules = ["malware-c2.test", "exfil-apex.test"]
    allow = ["internal.corp"]
    blocked_types = ["TXT", "NULL"]

    pub_resp = client.post(
        f"/api/v1/policies?tenant_id={tenant_id}",
        json={
            "name": "SecOps v2",
            "custom_blocked_domains": rules,
            "allowlisted_domains": allow,
            "blocked_record_types": blocked_types,
        },
        headers={"X-Tenant-Key": api_key}
    )
    assert pub_resp.status_code == 200
    pub_data = pub_resp.json()
    assert "publisher_signature" in pub_data
    assert "integrity_sha256" in pub_data

    # Fetch policy as endpoint device
    fetched = client.get(f"/api/v1/policies?tenant_id={tenant_id}", headers={"X-Tenant-Key": api_key}).json()
    assert fetched["version"] == 2

    # Client-side verification: Initial activation
    verifier = PolicyVerifier(tenant_id=tenant_id, signing_key=signing_key, current_version=1)
    verified = verifier.verify_and_prepare(fetched)
    assert verified["version"] == 2
    assert verified["status"] == "verified"
    assert verified["action"] == "activate"
    assert verified["integrity_sha256"] == fetched["integrity_sha256"]

    # 1. Idempotency Test: identical current policy must be an idempotent no-op
    noop_result = verifier.verify_and_prepare(fetched)
    assert noop_result["status"] == "no_change"
    assert noop_result["action"] == "noop"
    assert noop_result["version"] == 2

    # 2. Version Conflict Test: different content with existing version must be rejected
    conflict_policy = dict(fetched)
    conflict_policy["custom_rules"] = ["different-rule.test"]
    conflict_policy["integrity_sha256"] = compute_policy_hash(conflict_policy["custom_rules"], conflict_policy["allowlist"], conflict_policy["blocked_types"])
    # Note: Even if signed or forged with same version but different content hash, it must fail
    with pytest.raises(PolicyVerificationError):
        verifier.verify_and_prepare(conflict_policy)

    # 3. Rollback Protection Test: older version must be rejected
    v1_policy = dict(fetched)
    v1_policy["version"] = 1
    with pytest.raises(PolicyVerificationError, match="Policy rollback detected"):
        verifier.verify_and_prepare(v1_policy)

    # 4. Tamper Detection Test: modifying rule payload without valid signature on new version must fail
    tampered = dict(fetched)
    tampered["version"] = 3
    tampered["custom_rules"] = ["google.com"]
    with pytest.raises(PolicyVerificationError, match="checksum mismatch"):
        verifier.verify_and_prepare(tampered)

    # 5. Forged Signature Test: invalid publisher signature on new version must fail
    forged = dict(fetched)
    forged["version"] = 3
    forged["integrity_sha256"] = compute_policy_hash(forged["custom_rules"], forged["allowlist"], forged["blocked_types"])
    forged["publisher_signature"] = "forged_invalid_signature_hex"
    with pytest.raises(PolicyVerificationError, match="Publisher digital signature verification failed"):
        verifier.verify_and_prepare(forged)


def test_websocket_single_use_ticket_flow():
    """WebSockets require a short-lived single-use ticket; long-lived keys in URL query strings are rejected."""
    t_resp = client.post("/api/v1/tenants", json={"name": "WS Ticket Corp", "contact_email": "ws@corp.test"}).json()
    tenant_id = t_resp["tenant_id"]
    api_key = t_resp["api_key"]

    # Requesting ticket without tenant key must fail
    unauth_ticket = client.post(f"/api/v1/ws/ticket?tenant_id={tenant_id}")
    assert unauth_ticket.status_code == 401

    # Requesting ticket with valid tenant key succeeds
    ticket_resp = client.post(f"/api/v1/ws/ticket?tenant_id={tenant_id}", headers={"X-Tenant-Key": api_key})
    assert ticket_resp.status_code == 200
    ticket = ticket_resp.json()["ticket"]
    assert ticket.startswith("ticket_")

    # Connect to WebSocket with ticket -> succeeds
    with client.websocket_connect(f"/api/v1/ws/live?ticket={ticket}") as ws:
        assert ws is not None

    # TICKET REUSE REJECTION: Re-connecting with the same ticket must fail immediately
    with pytest.raises(Exception):
        with client.websocket_connect(f"/api/v1/ws/live?ticket={ticket}") as ws:
            pass

    # Connecting with long-lived API key in URL must fail
    with pytest.raises(Exception):
        with client.websocket_connect(f"/api/v1/ws/live?tenant_id={tenant_id}&api_key={api_key}") as ws:
            pass


def test_enrollment_token_single_use_and_revocation():
    # 1. Create Tenant
    t_resp = client.post("/api/v1/tenants", json={"name": "Security Ops", "contact_email": "soc@secops.test"})
    tenant_data = t_resp.json()
    tenant_id = tenant_data["tenant_id"]
    api_key = tenant_data["api_key"]

    # 2. Generate Enrollment Token (15m expiry)
    tok_resp = client.post("/api/v1/enrollment/tokens", json={
        "tenant_id": tenant_id,
        "device_name": "WIN11-ANALYST-01",
        "expires_in_minutes": 15
    }, headers={"X-Tenant-Key": api_key})
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
    revoke_resp = client.post(f"/api/v1/devices/{device_id}/revoke", headers={"X-Tenant-Key": api_key})
    assert revoke_resp.status_code == 200

    # 7. Device list shows revoked status
    list_resp = client.get(f"/api/v1/devices?tenant_id={tenant_id}", headers={"X-Tenant-Key": api_key})
    devices = list_resp.json()
    revoked_dev = [d for d in devices if d["id"] == device_id][0]
    assert revoked_dev["revoked"] == 1

    # 8. REVOCATION ENFORCEMENT: Revoked device MUST be forbidden from ingesting telemetry
    blocked_telemetry = client.post(
        "/api/v1/telemetry/events",
        json={
            "device_id": device_id,
            "events": [{"timestamp": time.time(), "domain": "after-revoke.test", "qtype": "A", "decision": "BLOCK", "reason": "Test"}]
        },
        headers={"X-Device-Id": device_id, "X-Device-Key": device_key}
    )
    assert blocked_telemetry.status_code == 403
    assert "revoked" in blocked_telemetry.json()["detail"].lower()


def test_enrollment_token_expiry():
    """Tokens created with negative expiry must be rejected upon enrollment."""
    t_resp = client.post("/api/v1/tenants", json={"name": "Expiry Corp", "contact_email": "exp@corp.test"})
    tenant_id = t_resp.json()["tenant_id"]

    tok_resp = client.post("/api/v1/enrollment/tokens", json={
        "tenant_id": tenant_id,
        "device_name": "EXPIRED-DEVICE",
        "expires_in_minutes": -1
    })
    token = tok_resp.json()["enrollment_token"]

    enroll_resp = client.post("/api/v1/devices/enroll", json={
        "enrollment_token": token,
        "hardware_uuid": "UUID-EXPIRED",
        "os_version": "Win11",
        "hostname": "EXPIRED-DEVICE"
    })
    assert enroll_resp.status_code == 400
    assert "expired" in enroll_resp.json()["detail"].lower()


def test_cross_tenant_access_denial():
    """Tenant A must not be able to access or mutate Tenant B's policies or devices."""
    t_a = client.post("/api/v1/tenants", json={"name": "Tenant Alpha", "contact_email": "alpha@test.com"}).json()
    t_b = client.post("/api/v1/tenants", json={"name": "Tenant Beta", "contact_email": "beta@test.com"}).json()

    bad_update = client.post(
        f"/api/v1/policies?tenant_id={t_b['tenant_id']}",
        json={
            "name": "Malicious Injection",
            "custom_blocked_domains": ["google.com"],
            "allowlisted_domains": [],
            "blocked_record_types": [],
        },
        headers={"X-Tenant-Key": t_a["api_key"]}
    )
    assert bad_update.status_code == 403
    assert "cross-tenant access denied" in bad_update.json()["detail"].lower()

    bad_list = client.get(
        f"/api/v1/devices?tenant_id={t_b['tenant_id']}",
        headers={"X-Tenant-Key": t_a["api_key"]}
    )
    assert bad_list.status_code == 403


def test_telemetry_toggle_settings():
    """Disabling telemetry in tenant settings must halt event recording."""
    t_resp = client.post("/api/v1/tenants", json={"name": "Privacy Corp", "contact_email": "priv@corp.test"}).json()
    tenant_id = t_resp["tenant_id"]
    api_key = t_resp["api_key"]

    tok = client.post("/api/v1/enrollment/tokens", json={"tenant_id": tenant_id, "device_name": "DEV-PRIV"}, headers={"X-Tenant-Key": api_key}).json()["enrollment_token"]
    dev = client.post("/api/v1/devices/enroll", json={"enrollment_token": tok, "hardware_uuid": "U-PRIV", "os_version": "Win11", "hostname": "DEV-PRIV"}).json()

    set_resp = client.put(
        f"/api/v1/tenants/{tenant_id}/settings",
        json={"telemetry_enabled": False, "anonymize_ips": True, "max_batch_size": 50},
        headers={"X-Tenant-Key": api_key}
    )
    assert set_resp.status_code == 200

    ingest_resp = client.post(
        "/api/v1/telemetry/events",
        json={"device_id": dev["device_id"], "events": [{"domain": "test.com"}]},
        headers={"X-Device-Id": dev["device_id"], "X-Device-Key": dev["device_key"]}
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["ingested"] == 0
    assert ingest_resp.json()["telemetry_disabled"] is True
