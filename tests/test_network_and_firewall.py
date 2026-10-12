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

    assert preview["rules_count"] == 5
    assert len(preview["apply_commands"]) == 5
    assert len(preview["rollback_commands"]) == 5

    # Check port 53 and 853 rules
    rules_text = " ".join(preview["apply_commands"])
    assert "remoteport=53" in rules_text
    assert "remoteport=853" in rules_text

    # Check rollback command matches rule names
    for rollback in preview["rollback_commands"]:
        assert rollback.startswith("netsh advfirewall firewall delete rule name=")


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
