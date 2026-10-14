from pathlib import Path

from local_ipc import authorize_request, make_auth_token, dispatch_request
from service_health import HealthState, evaluate_health
from windows_service import ServiceRuntime


def test_health_does_not_equate_running_with_protected():
    health = evaluate_health(
        enabled=True,
        listener_ready=True,
        policy_ready=True,
        upstream_ready=False,
        routing_verified=False,
    )
    assert health.state is HealthState.DEGRADED


def test_ipc_rejects_unauthorized_and_unknown_operations():
    secret = b"test-secret"
    unauthorized = {"operation": "set_enabled", "payload": {"enabled": True}, "token": "bad"}
    assert not authorize_request(secret, unauthorized)

    token = make_auth_token(secret, "exec", None)
    assert not authorize_request(secret, {"operation": "exec", "payload": None, "token": token})

    valid = {
        "operation": "get_status",
        "payload": None,
        "token": make_auth_token(secret, "get_status", None),
    }
    assert dispatch_request(secret, valid, {"get_status": lambda _: {"state": "DISABLED"}})["ok"]


def test_service_runtime_stop_is_safe(tmp_path: Path):
    runtime = ServiceRuntime(tmp_path)
    runtime.stop()
    assert runtime.status()["state"] == "DISABLED"


def test_health_degraded_when_routing_verified_but_listener_down():
    """Confirms DEGRADED health when adapter routing points to loopback but listener is down."""
    health = evaluate_health(
        enabled=True,
        listener_ready=False,
        policy_ready=True,
        upstream_ready=True,
        routing_verified=True,
    )
    assert health.state is HealthState.DEGRADED
    assert "incomplete" in health.detail.lower()


def test_ipc_dispatch_apply_policy_requires_secret():
    """Privileged apply_policy must be rejected without secret."""
    req = {"operation": "apply_policy", "payload": {"version": 2}}
    res = dispatch_request(None, req, {"apply_policy": lambda p: {"status": "ok"}})
    assert res["ok"] is False
    assert res["error"] == "privileged_secret_required"

