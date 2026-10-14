"""
Comprehensive IPC Security and Authorization Tests.

Verifies:
- Unelevated ordinary-user access for read-only operations without admin secret.
- Strict rejection of unauthorized mutations without secret or with invalid token.
- Replay attack mitigation via nonces and timestamp freshness bounds.
- Strict message size enforcement (64 KB ceiling) against denial-of-service.
- Operation whitelisting and isolation.
"""

import time
import pytest
from local_ipc import (
    READ_ONLY_OPERATIONS,
    PRIVILEGED_OPERATIONS,
    MAX_IPC_MESSAGE_SIZE,
    ReplayCache,
    authorize_request,
    dispatch_request,
    encode_request,
    decode_request,
    make_auth_token,
)


@pytest.fixture
def test_secret():
    return b"test-super-secret-key-32bytes-admin"


@pytest.fixture
def mock_handlers():
    return {
        "get_status": lambda _p: {"state": "PROTECTED", "detail": "All systems nominal"},
        "get_events": lambda _p: [{"domain": "example.com", "decision": "ALLOW"}],
        "get_rules": lambda _p: {"custom_rules": []},
        "get_network_state": lambda _p: {"routing_verified": True},
        "diagnostics": lambda _p: {"service": "DNS-SHIELD"},
        "set_enabled": lambda p: {"state": "PROTECTED" if p.get("enabled") else "DISABLED"},
        "restore_network": lambda _p: {"success": True},
        "add_rule": lambda p: {"success": True, "domain": p.get("domain")},
        "delete_rule": lambda p: {"success": True},
        "apply_policy": lambda p: {"status": "activated", "version": p.get("version", 1)},
    }


def test_unelevated_ordinary_user_can_read_status_and_events(mock_handlers):
    """An unelevated process with no secret must be able to read status and events."""
    for op in READ_ONLY_OPERATIONS:
        req = {"operation": op, "payload": None}
        # Secret is None (unelevated user)
        res = dispatch_request(None, req, mock_handlers)
        assert res["ok"] is True, f"Failed for read-only operation: {op}"
        assert "result" in res


def test_unelevated_user_cannot_execute_privileged_mutations(mock_handlers):
    """An unelevated process without the admin secret MUST NOT execute privileged mutations."""
    for op in PRIVILEGED_OPERATIONS:
        req = {"operation": op, "payload": {"enabled": False}}
        res = dispatch_request(None, req, mock_handlers)
        assert res["ok"] is False, f"Privileged operation {op} unexpectedly succeeded without secret!"
        assert res["error"] == "privileged_secret_required"


def test_privileged_mutation_with_invalid_token_is_rejected(test_secret, mock_handlers):
    """Privileged mutations with forged or invalid tokens must be rejected."""
    cache = ReplayCache()
    req = {
        "operation": "set_enabled",
        "payload": {"enabled": False},
        "timestamp": time.time(),
        "nonce": "abcdef1234567890",
        "token": "forged_invalid_hmac_hex_token"
    }
    res = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res["ok"] is False
    assert res["error"] == "unauthorized"


def test_authorized_privileged_mutation_succeeds(test_secret, mock_handlers):
    """Privileged mutations with valid timestamp, nonce, and HMAC token succeed."""
    cache = ReplayCache()
    now = time.time()
    nonce = "valid_unique_nonce_12345"
    token = make_auth_token(test_secret, "set_enabled", {"enabled": True}, timestamp=now, nonce=nonce)

    req = {
        "operation": "set_enabled",
        "payload": {"enabled": True},
        "timestamp": now,
        "nonce": nonce,
        "token": token
    }
    res = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res["ok"] is True
    assert res["result"]["state"] == "PROTECTED"


def test_replay_attack_is_strictly_detected_and_prevented(test_secret, mock_handlers):
    """Sending the exact same valid signed request twice must trigger replay detection."""
    cache = ReplayCache()
    now = time.time()
    nonce = "replay_target_nonce_9999"
    token = make_auth_token(test_secret, "restore_network", None, timestamp=now, nonce=nonce)

    req = {
        "operation": "restore_network",
        "payload": None,
        "timestamp": now,
        "nonce": nonce,
        "token": token
    }

    # First attempt: succeeds
    res1 = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res1["ok"] is True

    # Replay attempt: MUST BE REJECTED
    res2 = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res2["ok"] is False
    assert res2["error"] == "replay_detected"


def test_expired_timestamp_is_rejected(test_secret, mock_handlers):
    """Requests older than the maximum permitted timestamp skew must be rejected."""
    cache = ReplayCache()
    old_time = time.time() - 300.0  # 5 minutes in the past
    nonce = "old_nonce_timestamp_5min"
    token = make_auth_token(test_secret, "set_enabled", {"enabled": False}, timestamp=old_time, nonce=nonce)

    req = {
        "operation": "set_enabled",
        "payload": {"enabled": False},
        "timestamp": old_time,
        "nonce": nonce,
        "token": token
    }

    res = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res["ok"] is False
    assert res["error"] == "expired_timestamp"


def test_future_skewed_timestamp_is_rejected(test_secret, mock_handlers):
    """Requests with future timestamps exceeding max skew must be rejected."""
    cache = ReplayCache()
    future_time = time.time() + 120.0  # 2 minutes into the future
    nonce = "future_nonce_skew_120"
    token = make_auth_token(test_secret, "add_rule", {"domain": "bad.com"}, timestamp=future_time, nonce=nonce)

    req = {
        "operation": "add_rule",
        "payload": {"domain": "bad.com"},
        "timestamp": future_time,
        "nonce": nonce,
        "token": token
    }

    res = dispatch_request(test_secret, req, mock_handlers, replay_cache=cache)
    assert res["ok"] is False
    assert res["error"] == "expired_timestamp"


def test_message_size_limit_enforced():
    """Messages exceeding MAX_IPC_MESSAGE_SIZE must be rejected upon decoding and encoding."""
    # Oversized payload
    large_payload = {"data": "A" * (MAX_IPC_MESSAGE_SIZE + 1024)}

    with pytest.raises(ValueError, match="exceeds maximum"):
        encode_request({"operation": "get_status", "payload": large_payload})

    oversized_bytes = b'{"operation": "get_status", "data": "' + (b"X" * (MAX_IPC_MESSAGE_SIZE + 10)) + b'"}\n'
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        decode_request(oversized_bytes)


def test_unknown_operation_rejected(test_secret, mock_handlers):
    """Operations not in the strict whitelist must be rejected immediately."""
    req = {"operation": "execute_arbitrary_cmd", "payload": {"cmd": "whoami"}}
    res = dispatch_request(test_secret, req, mock_handlers)
    assert res["ok"] is False
    assert res["error"] == "unknown_operation"
