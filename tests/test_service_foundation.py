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
