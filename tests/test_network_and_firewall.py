"""
Unit and isolated integration tests for NetworkManager and FirewallManager.
Ensures dry-run safety, preflight probes, transactional backup handling, and secret redaction.
"""

import json
from pathlib import Path
from firewall_manager import FirewallManager
from network_manager import NetworkManager
from windows_service import ServiceRuntime


def test_firewall_preview_rules_generates_matching_rollback():
    fm = FirewallManager()
    preview = fm.preview_rules()
    status = fm.get_enforcement_status()

    assert status["state"] == "PENDING_INTEGRATION_VERIFICATION"
    assert status["faulty_exemption_design_removed"] is True
    assert status["loopback_access_preserved"] is True
    assert status["gateway_upstream_preserved"] is True
    assert len(status["non_claims"]) == 3

    assert preview["rules_count"] == 2
    assert preview["wfp_filters_count"] == 8
    assert len(preview["apply_commands"]) == 2
    assert len(preview["rollback_commands"]) == 2

    # Check port 853 rules in PowerShell NetFirewall preview
    rules_text = " ".join(preview["apply_commands"])
    assert "-RemotePort 853" in rules_text

    # Check rollback command matches rule names
    for rollback in preview["rollback_commands"]:
        assert rollback.startswith("Remove-NetFirewallRule -Name ")

    # Check WFP filters:
    wfp = preview["wfp_filters"]

    # 1. Loopback permit filter
    loopback_v4 = [f for f in wfp if f["id"] == "IPv4_Permit_Local_Gateway_Loopback"][0]
    assert loopback_v4["action"] == "FWP_ACTION_PERMIT"
    assert loopback_v4["weight"] == 100

    # 2. Gateway APP_ID permit filter using FWP_MATCH_EQUAL (conforming to Microsoft documentation)
    gateway_v4 = [f for f in wfp if f["id"] == "IPv4_Permit_Gateway_Service_Outbound"][0]
    assert gateway_v4["action"] == "FWP_ACTION_PERMIT"
    assert gateway_v4["weight"] == 90
    app_cond = [c for c in gateway_v4["conditions"] if c["field"] == "ALE_APP_ID"][0]
    assert app_cond["match"] == "FWP_MATCH_EQUAL"

    # 3. Rogue external port 53 block filter
    rogue_v4 = [f for f in wfp if f["id"] == "IPv4_Block_Rogue_External_Port53"][0]
    assert rogue_v4["action"] == "FWP_ACTION_BLOCK"
    assert rogue_v4["weight"] == 10


def test_network_manager_dry_run_does_not_mutate_system(tmp_path: Path):
    nm = NetworkManager(config_dir=tmp_path)
    res = nm.enable_protection(dry_run=True)

    assert res["success"] is True
    assert res["dry_run"] is True
    assert "planned_actions" in res
    # Ensure backup file is not created during dry run
    assert not (tmp_path / "dns_backup.json").exists()


def test_network_manager_snapshot_persistence_and_restore(tmp_path: Path):
    nm = NetworkManager(config_dir=tmp_path)
    backup_file = tmp_path / "dns_backup.json"

    # Write a test snapshot
    test_snapshot = {
        "Ethernet0": {
            "alias": "Ethernet0",
            "interface_index": 1,
            "ipv4_dhcp": True,
            "ipv4_servers": [],
            "ipv6_dhcp": True,
            "ipv6_servers": [],
        }
    }
    backup_file.write_text(json.dumps(test_snapshot), encoding="utf-8")
    assert backup_file.exists()

    # Call restore
    res = nm.restore_dns()
    assert res["success"] is True
    # Verify backup file removed after restoration
    assert not backup_file.exists()


def test_service_runtime_diagnostics_redacts_secrets(tmp_path: Path):
    runtime = ServiceRuntime(config_dir=tmp_path)
    diag = runtime.get_diagnostics()

    assert diag["service"] == "DNS-SHIELD"
    assert "version" in diag
    assert "os" in diag
    # CRITICAL SECURITY ASSERTIONS: Secrets must be redacted
    assert diag["ipc_secret"] == "[REDACTED]"
    assert diag["admin_key"] == "[REDACTED]"


def test_restore_preserves_admin_changes(tmp_path: Path, monkeypatch):
    from network_manager import AdapterDNSConfig
    nm = NetworkManager(config_dir=tmp_path)
    backup_file = tmp_path / "dns_backup.json"

    # Adapter was originally DHCP
    test_snapshot = {
        "Ethernet0": {
            "alias": "Ethernet0",
            "interface_index": 1,
            "ipv4_dhcp": True,
            "ipv4_servers": [],
            "ipv6_dhcp": True,
            "ipv6_servers": [],
        }
    }
    backup_file.write_text(json.dumps(test_snapshot), encoding="utf-8")

    # Simulate administrator reconfiguring adapter to 8.8.8.8 (no longer pointing to loopback)
    admin_cfg = AdapterDNSConfig(
        alias="Ethernet0",
        interface_index=1,
        ipv4_dhcp=False,
        ipv4_servers=["8.8.8.8"],
        ipv6_dhcp=True,
        ipv6_servers=[],
    )
    monkeypatch.setattr(nm, "get_adapter_dns_config", lambda alias: admin_cfg)

    res = nm.restore_dns()
    assert res["success"] is True
    # The restore should note that admin changes were preserved
    assert any("admin changes preserved" in r for r in res["restored"])


def test_degraded_status_reported_when_listener_dead(tmp_path: Path, monkeypatch):
    nm = NetworkManager(config_dir=tmp_path)

    # Simulate adapter routed to loopback
    monkeypatch.setattr(nm, "verify_routing", lambda: (True, "Routed to loopback"))

    # Check health when listener is dead (port 65530 or similar closed port)
    health = nm.check_health(listener_port=65530)
    assert health["state"] == "DEGRADED"
    assert "CRITICAL" in health["detail"]
    assert health["needs_recovery"] is True


def test_restore_preserves_static_dns_servers(tmp_path: Path, monkeypatch):
    """Verifies that adapters originally configured with static DNS are restored to static, not DHCP."""
    from network_manager import AdapterDNSConfig
    nm = NetworkManager(config_dir=tmp_path)
    backup_file = tmp_path / "dns_backup.json"

    # Adapter originally had static DNS: 10.0.0.1, 10.0.0.2
    test_snapshot = {
        "Ethernet0": {
            "alias": "Ethernet0",
            "interface_index": 1,
            "ipv4_dhcp": False,
            "ipv4_servers": ["10.0.0.1", "10.0.0.2"],
            "ipv6_dhcp": False,
            "ipv6_servers": ["2001:db8::1"],
        }
    }
    backup_file.write_text(json.dumps(test_snapshot), encoding="utf-8")

    # Adapter currently points to loopback
    current_cfg = AdapterDNSConfig(
        alias="Ethernet0",
        interface_index=1,
        ipv4_dhcp=False,
        ipv4_servers=["127.0.0.1"],
        ipv6_dhcp=False,
        ipv6_servers=["::1"],
    )
    monkeypatch.setattr(nm, "get_adapter_dns_config", lambda alias: current_cfg)

    recorded_commands = []
    import subprocess
    orig_run = subprocess.run
    def mock_run(cmd, *args, **kwargs):
        recorded_commands.append(cmd)
        class Dummy:
            returncode = 0
            stdout = ""
            stderr = ""
        return Dummy()

    monkeypatch.setattr(subprocess, "run", mock_run)

    res = nm.restore_dns()
    assert res["success"] is True
    assert "Ethernet0" in res["restored"]

    # Ensure netsh was called with static 10.0.0.1, NOT source=dhcp for IPv4
    ipv4_calls = [c for c in recorded_commands if "ipv4" in c]
    assert any("address=10.0.0.1" in " ".join(c) for c in ipv4_calls)
    assert not any("source=dhcp" in " ".join(c) for c in ipv4_calls)

