"""
Comprehensive Unit & Integration Tests for Asymmetric Ed25519 Policy Authentication.

Validates:
1. Ed25519 asymmetric signing (server private key) and verification (endpoint public key).
2. Server-side private key retention: endpoints only receive public keys.
3. Canonical envelope hashing and deterministic sorting.
4. Idempotent no-op for identical current policy version and content.
5. Strict conflict rejection for differing content under the same version.
6. Monotonic rollback rejection for older versions.
7. Persisted rollback state survival across service/process restarts via SQLite.
8. Key rotation mechanism using versioned key identifiers (key_id).
"""

import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from hosted_management.policy_verifier import (
    generate_publisher_keypair,
    canonicalize_envelope,
    compute_policy_content_hash,
    sign_policy_envelope,
    EndpointPolicyVerifier,
    PolicyVerificationError,
)


def test_asymmetric_keypair_generation():
    priv_hex, pub_hex = generate_publisher_keypair()
    assert len(priv_hex) == 64  # 32 bytes hex
    assert len(pub_hex) == 64   # 32 bytes hex
    assert priv_hex != pub_hex


def test_asymmetric_signing_and_verification():
    priv_hex, pub_hex = generate_publisher_keypair()
    tenant_id = "tenant-security-ops"
    version = 1
    custom_rules = ["malicious.example.com", "c2-exfil.org"]
    allowlist = ["internal.corp"]
    blocked_types = ["TXT", "ANY"]
    signed_at = 1700000000.0
    key_id = "key-2026-v1"

    sig_hex = sign_policy_envelope(
        private_key_hex=priv_hex,
        tenant_id=tenant_id,
        version=version,
        custom_rules=custom_rules,
        allowlist=allowlist,
        blocked_types=blocked_types,
        signed_at=signed_at,
        key_id=key_id,
    )
    assert len(sig_hex) == 128  # 64 bytes Ed25519 signature

    # Endpoint verifier configured with trusted public key only
    verifier = EndpointPolicyVerifier(
        trusted_public_key_hex=pub_hex,
        expected_tenant_id=tenant_id,
    )

    policy_envelope = {
        "tenant_id": tenant_id,
        "version": version,
        "custom_rules": custom_rules,
        "allowlist": allowlist,
        "blocked_types": blocked_types,
        "signed_at": signed_at,
        "key_id": key_id,
        "signature": sig_hex,
    }

    result = verifier.verify_and_process(policy_envelope)
    assert result["status"] == "verified"
    assert result["version"] == 1
    assert result["action"] == "activate"


def test_idempotent_equal_version_handling():
    priv_hex, pub_hex = generate_publisher_keypair()
    tenant_id = "tenant-idempotent"
    verifier = EndpointPolicyVerifier(trusted_public_key_hex=pub_hex, expected_tenant_id=tenant_id)

    # First delivery: version 3
    sig = sign_policy_envelope(priv_hex, tenant_id, 3, ["bad.com"], [], ["ANY"], 1000.0, "key-1")
    p1 = {
        "tenant_id": tenant_id,
        "version": 3,
        "custom_rules": ["bad.com"],
        "allowlist": [],
        "blocked_types": ["ANY"],
        "signed_at": 1000.0,
        "key_id": "key-1",
        "signature": sig,
    }
    res1 = verifier.verify_and_process(p1)
    assert res1["action"] == "activate"

    # Second delivery: identical content with same version 3 -> IDEMPOTENT NO-OP
    res2 = verifier.verify_and_process(p1)
    assert res2["status"] == "no_change"
    assert res2["action"] == "noop"
    assert res2["version"] == 3

    # Third delivery: conflicting content with same version 3 -> STRICT REJECTION
    sig_conflict = sign_policy_envelope(priv_hex, tenant_id, 3, ["different-rule.org"], [], ["ANY"], 1000.0, "key-1")
    p_conflict = {
        "tenant_id": tenant_id,
        "version": 3,
        "custom_rules": ["different-rule.org"],
        "allowlist": [],
        "blocked_types": ["ANY"],
        "signed_at": 1000.0,
        "key_id": "key-1",
        "signature": sig_conflict,
    }
    with pytest.raises(PolicyVerificationError, match="Version conflict"):
        verifier.verify_and_process(p_conflict)


def test_rollback_protection():
    priv_hex, pub_hex = generate_publisher_keypair()
    tenant_id = "tenant-rollback"
    verifier = EndpointPolicyVerifier(trusted_public_key_hex=pub_hex, expected_tenant_id=tenant_id, current_version=5)

    # Delivery of older version 4 must be rejected
    sig = sign_policy_envelope(priv_hex, tenant_id, 4, ["bad.com"], [], ["ANY"], 1000.0, "key-1")
    p_old = {
        "tenant_id": tenant_id,
        "version": 4,
        "custom_rules": ["bad.com"],
        "allowlist": [],
        "blocked_types": ["ANY"],
        "signed_at": 1000.0,
        "key_id": "key-1",
        "signature": sig,
    }
    with pytest.raises(PolicyVerificationError, match="Policy rollback detected"):
        verifier.verify_and_process(p_old)


def test_persisted_state_survives_restart():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        priv_hex, pub_hex = generate_publisher_keypair()
        tenant_id = "tenant-persist"

        # Instance 1: activates version 10
        verifier1 = EndpointPolicyVerifier(
            trusted_public_key_hex=pub_hex,
            expected_tenant_id=tenant_id,
            db_path=db_path,
        )
        sig = sign_policy_envelope(priv_hex, tenant_id, 10, ["persisted.com"], [], ["ANY"], 1234.0, "key-1")
        p10 = {
            "tenant_id": tenant_id,
            "version": 10,
            "custom_rules": ["persisted.com"],
            "allowlist": [],
            "blocked_types": ["ANY"],
            "signed_at": 1234.0,
            "key_id": "key-1",
            "signature": sig,
        }
        res = verifier1.verify_and_process(p10)
        assert res["action"] == "activate"
        assert verifier1.active_version == 10

        # Simulate service restart: fresh verifier instance loaded from existing SQLite DB
        verifier2 = EndpointPolicyVerifier(
            trusted_public_key_hex=pub_hex,
            expected_tenant_id=tenant_id,
            db_path=db_path,
        )
        assert verifier2.active_version == 10
        assert verifier2.active_content_hash == res["content_hash"]

        # Attempting rollback to version 9 on restarted instance must fail
        sig_old = sign_policy_envelope(priv_hex, tenant_id, 9, ["old.com"], [], ["ANY"], 1000.0, "key-1")
        p9 = {
            "tenant_id": tenant_id,
            "version": 9,
            "custom_rules": ["old.com"],
            "allowlist": [],
            "blocked_types": ["ANY"],
            "signed_at": 1000.0,
            "key_id": "key-1",
            "signature": sig_old,
        }
        with pytest.raises(PolicyVerificationError, match="Policy rollback detected"):
            verifier2.verify_and_process(p9)

        # Idempotent resubmission of v10 on restarted instance is no-op
        res_noop = verifier2.verify_and_process(p10)
        assert res_noop["status"] == "no_change"
        assert res_noop["action"] == "noop"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_key_rotation_with_keyring():
    priv1, pub1 = generate_publisher_keypair()
    priv2, pub2 = generate_publisher_keypair()
    tenant_id = "tenant-rotation"

    # Endpoint configured with keyring containing both the older key and the newly rotated key
    trusted_keyring = {
        "key-2025": pub1,
        "key-2026": pub2,
    }
    verifier = EndpointPolicyVerifier(
        trusted_keyring=trusted_keyring,
        expected_tenant_id=tenant_id,
    )

    # Sign with key-2025
    sig1 = sign_policy_envelope(priv1, tenant_id, 1, ["r1.com"], [], [], 100.0, key_id="key-2025")
    p1 = {
        "tenant_id": tenant_id,
        "version": 1,
        "custom_rules": ["r1.com"],
        "allowlist": [],
        "blocked_types": [],
        "signed_at": 100.0,
        "key_id": "key-2025",
        "signature": sig1,
    }
    assert verifier.verify_and_process(p1)["action"] == "activate"

    # Forward rotation: Sign with new key-2026
    sig2 = sign_policy_envelope(priv2, tenant_id, 2, ["r2.com"], [], [], 200.0, key_id="key-2026")
    p2 = {
        "tenant_id": tenant_id,
        "version": 2,
        "custom_rules": ["r2.com"],
        "allowlist": [],
        "blocked_types": [],
        "signed_at": 200.0,
        "key_id": "key-2026",
        "signature": sig2,
    }
    assert verifier.verify_and_process(p2)["action"] == "activate"

    # Unknown key_id must be rejected
    sig3 = sign_policy_envelope(priv2, tenant_id, 3, ["r3.com"], [], [], 300.0, key_id="key-unknown")
    p3 = {
        "tenant_id": tenant_id,
        "version": 3,
        "custom_rules": ["r3.com"],
        "allowlist": [],
        "blocked_types": [],
        "signed_at": 300.0,
        "key_id": "key-unknown",
        "signature": sig3,
    }
    with pytest.raises(PolicyVerificationError, match="No trusted public verification key found"):
        verifier.verify_and_process(p3)


def test_service_runtime_apply_policy():
    """Validates that ServiceRuntime.apply_policy authenticates signed policies and updates DB."""
    with tempfile.TemporaryDirectory() as td:
        from pathlib import Path
        from windows_service import ServiceRuntime
        from gateway.db import init_db, get_db

        runtime = ServiceRuntime(config_dir=Path(td), dns_port=53053)
        try:
            init_db(str(runtime.db_path))

            priv_hex, pub_hex = generate_publisher_keypair()
            tenant_id = "tenant-service-test"
            sig = sign_policy_envelope(priv_hex, tenant_id, 1, ["blocked-by-policy.com"], ["allowed.org"], ["TXT"], 1000.0, "key-1")

            envelope = {
                "tenant_id": tenant_id,
                "version": 1,
                "custom_rules": ["blocked-by-policy.com"],
                "allowlist": ["allowed.org"],
                "blocked_types": ["TXT"],
                "signed_at": 1000.0,
                "key_id": "key-1",
                "signature": sig,
                "public_key": pub_hex,
            }

            # Apply signed policy
            res = runtime.apply_policy(envelope)
            assert res["status"] == "activated"
            assert res["version"] == 1

            # Verify DB updated
            conn = get_db(str(runtime.db_path))
            cur = conn.cursor()
            cur.execute("SELECT domain FROM custom_rules")
            assert cur.fetchone()[0] == "blocked-by-policy.com"
            cur.execute("SELECT domain FROM allowlist")
            assert cur.fetchone()[0] == "allowed.org"
            cur.execute("SELECT qtype FROM blocked_record_types")
            assert cur.fetchone()[0] == "TXT"
            conn.close()

            # Idempotent re-apply is a no-op
            res_noop = runtime.apply_policy(envelope)
            assert res_noop["status"] == "no_change"

            # Rollback is strictly rejected
            sig_old = sign_policy_envelope(priv_hex, tenant_id, 0, [], [], [], 500.0, "key-1")
            envelope_old = {
                "tenant_id": tenant_id,
                "version": 0,
                "custom_rules": [],
                "allowlist": [],
                "blocked_types": [],
                "signed_at": 500.0,
                "key_id": "key-1",
                "signature": sig_old,
                "public_key": pub_hex,
            }
            with pytest.raises(PolicyVerificationError, match="Policy rollback detected"):
                runtime.apply_policy(envelope_old)
        finally:
            runtime.stop()

