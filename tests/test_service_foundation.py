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


def test_handle_cli_command_reads_secret_internally(tmp_path: Path, monkeypatch):
    """
    Verifies that handle_cli_command reads the IPC secret internally from %ProgramData%\DNS-SHIELD\ipc.secret
    and successfully invokes NamedPipeClient without secret command-line interpolation.
    """
    from windows_service import handle_cli_command
    import windows_service

    # Setup temporary ProgramData directory with secret
    secret_file = tmp_path / "ipc.secret"
    secret_file.write_bytes(b"test-secret-12345")
    monkeypatch.setattr(windows_service, "program_data_dir", lambda: tmp_path)

    captured_calls = []
    class MockClient:
        def __init__(self, secret=None):
            self.secret = secret

        def call(self, operation, payload=None):
            captured_calls.append({"operation": operation, "payload": payload, "secret": self.secret})
            return {"ok": True, "data": {"custom_rules": [{"domain": "malware-sample.test"}]}}

    monkeypatch.setattr(windows_service, "NamedPipeClient", MockClient)

    # 1. Test help
    assert handle_cli_command(["--help"]) == 0

    # 2. Test add-rule without passing any secret on command line
    ret = handle_cli_command(["add-rule", "malware-sample.test", "subdomain", "Test Reason"])
    assert ret == 0
    assert len(captured_calls) == 1
    call = captured_calls[0]
    assert call["operation"] == "add_rule"
    assert call["payload"]["domain"] == "malware-sample.test"
    # Secret was read internally from ipc.secret file, NOT from command line
    assert call["secret"] == b"test-secret-12345"

    # 3. Test get-rules
    ret_get = handle_cli_command(["get-rules"])
    assert ret_get == 0
    assert captured_calls[-1]["operation"] == "get_rules"


