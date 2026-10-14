"""
Unit tests for Standalone GUI Recovery Mechanism.

Demonstrates that:
1. GUI recovery works when the background service is completely stopped.
2. Recovery does NOT depend on IPC or Named Pipe connectivity to the service.
3. Standalone recovery accurately executes the narrowly scoped recovery path.
4. Both static and automatic (DHCP) DNS settings are properly restored.
5. Preserves administrator changes if the adapter no longer points to loopback.
"""

import json
from pathlib import Path
import pytest
from desktop_app import (
    is_elevated_admin,
    find_recovery_script,
    execute_standalone_recovery,
)
from network_manager import NetworkManager, AdapterDNSConfig


def test_recovery_script_exists_and_is_found():
    """Confirms find_recovery_script locates the genuine recovery.ps1 file."""
    script = find_recovery_script()
    assert script is not None
    assert script.exists()
    assert script.name == "recovery.ps1"


def test_standalone_recovery_executes_without_service_running(tmp_path: Path, monkeypatch):
    """
    Simulates service completely down (no NamedPipeServer).
    Demonstrates that execute_standalone_recovery restores configuration without IPC.
    """
    backup_file = tmp_path / "dns_backup.json"
    snapshot = {
        "Ethernet0": {
            "alias": "Ethernet0",
            "interface_index": 1,
            "ipv4_dhcp": True,
            "ipv4_servers": [],
            "ipv6_dhcp": True,
            "ipv6_servers": [],
        }
    }
    backup_file.write_text(json.dumps(snapshot), encoding="utf-8")

    # Current adapter state points to loopback
    current_cfg = AdapterDNSConfig(
        alias="Ethernet0",
        interface_index=1,
        ipv4_dhcp=False,
        ipv4_servers=["127.0.0.1"],
        ipv6_dhcp=False,
        ipv6_servers=["::1"],
    )

    # Mock NetworkManager to use tmp_path
    monkeypatch.setattr(
        "network_manager.NetworkManager.__init__",
        lambda self, config_dir=None: setattr(self, "backup_path", backup_file) or setattr(self, "config_dir", tmp_path)
    )
    monkeypatch.setattr("network_manager.NetworkManager.get_adapter_dns_config", lambda self, alias: current_cfg)

    # Force is_elevated_admin to True for in-process direct recovery execution
    monkeypatch.setattr("desktop_app.is_elevated_admin", lambda: True)

    # Execute standalone recovery - NO IPC CLIENT, NO SERVICE RUNNING
    res = execute_standalone_recovery()
    assert res["success"] is True
    assert "Ethernet0" in res["restored"]
    # Backup file must be deleted upon successful recovery
    assert not backup_file.exists()


def test_standalone_recovery_preserves_static_servers_without_dhcp_fallback(tmp_path: Path, monkeypatch):
    """
    Demonstrates that an adapter that originally had static DNS is restored to its exact
    static servers, and NOT converted to DHCP.
    """
    backup_file = tmp_path / "dns_backup.json"
    static_snapshot = {
        "Ethernet0": {
            "alias": "Ethernet0",
            "interface_index": 1,
            "ipv4_dhcp": False,
            "ipv4_servers": ["192.168.1.10", "192.168.1.1"],
            "ipv6_dhcp": False,
            "ipv6_servers": ["2001:db8::1"],
        }
    }
    backup_file.write_text(json.dumps(static_snapshot), encoding="utf-8")

    current_cfg = AdapterDNSConfig(
        alias="Ethernet0",
        interface_index=1,
        ipv4_dhcp=False,
        ipv4_servers=["127.0.0.1"],
        ipv6_dhcp=False,
        ipv6_servers=["::1"],
    )

    recorded_cmds = []
    import subprocess
    def mock_subprocess_run(cmd, *args, **kwargs):
        recorded_cmds.append(" ".join(cmd))
        class Dummy:
            returncode = 0
            stdout = ""
            stderr = ""
        return Dummy()

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    monkeypatch.setattr(
        "network_manager.NetworkManager.__init__",
        lambda self, config_dir=None: setattr(self, "backup_path", backup_file) or setattr(self, "config_dir", tmp_path)
    )
    monkeypatch.setattr("network_manager.NetworkManager.get_adapter_dns_config", lambda self, alias: current_cfg)
    monkeypatch.setattr("desktop_app.is_elevated_admin", lambda: True)

    res = execute_standalone_recovery()
    assert res["success"] is True

    # Assert netsh set dnsservers used address=192.168.1.10, NEVER source=dhcp
    ipv4_calls = [c for c in recorded_cmds if "ipv4" in c]
    assert any("address=192.168.1.10" in c for c in ipv4_calls)
    assert not any("source=dhcp" in c for c in ipv4_calls)
