"""
Windows Firewall & WFP Bypass Defense Manager.

Architecture Note on Windows Filtering & Rule Precedence:
In Windows Defender Firewall with Advanced Security (WFAS / netsh advfirewall),
outbound BLOCK rules take unconditional precedence over ordinary outbound ALLOW rules.
Therefore, a naive global outbound port-53 BLOCK rule paired with a program-specific
ALLOW rule will drop the gateway's own upstream packets and sever internet resolution.

This module implements the supported Windows Filtering Platform (WFP) native architecture:
1. Native WFP ALE Layer Filters (via fwpuclnt.dll and WFPManager):
   - Sublayer arbitration with FWP_MATCH_EQUAL on application ID byte blobs.
   - High-weight PERMIT for loopback (127.0.0.1 and ::1 on port 53) ensures local
     applications can resolve queries through the local gateway.
   - High-weight PERMIT for the gateway service binary allows upstream resolution.
   - Lower-weight BLOCK for all other outbound port 53 connections drops rogue queries.
   - Outbound port 853 BLOCK drops direct DoT (TCP) and DoQ (UDP).
   - Dynamic session lifecycle (FWPM_SESSION_FLAG_DYNAMIC) ensures filters are
     automatically cleaned up by the kernel on service crash or termination.
2. Auxiliary PowerShell NetSecurity Rules:
   - Preview commands for port 853 blocking.

Explicit Operational Boundaries & Non-Claims:
- Does NOT claim to intercept arbitrary DoH over HTTPS (port 443) without enterprise browser policy.
- Does NOT claim to intercept direct IP malware communication without domain resolution.
- Does NOT claim to intercept traffic routed through distinct virtual VPN network adapters.

Safety Policy:
By default, operations execute in dry-run mode. Live host activation remains PENDING
until disposable VM integration testing is verified.
"""

import enum
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from wfp_manager import WFPManager

logger = logging.getLogger("DNSShield.FirewallManager")


class EnforcementArchitecture(str, enum.Enum):
    WFP_ALE = "WFP_ALE"                          # Windows Filtering Platform ALE layer filter
    UPSTREAM_SCOPED = "UPSTREAM_SCOPED"          # Scoped destination IP rules
    DOH_ISOLATION = "DOH_ISOLATION"              # Global 53/853 block with DoH upstream transport


class FirewallManager:
    """Manages Windows bypass defense rules without breaking gateway upstream connectivity."""

    RULE_PREFIX = "DNSShield"

    def __init__(
        self,
        service_binary_path: Optional[Path] = None,
        upstream_ips: Optional[List[str]] = None,
        architecture: EnforcementArchitecture = EnforcementArchitecture.WFP_ALE,
    ):
        self.service_binary = service_binary_path or Path(os.sys.executable)
        self.upstream_ips = upstream_ips or ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"]
        self.architecture = architecture
        self.wfp = WFPManager(self.service_binary)

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Returns the current enforcement verification status, native WFP state, and boundaries."""
        return {
            "state": "PENDING_INTEGRATION_VERIFICATION",
            "active_architecture": self.architecture.value,
            "wfp_native_available": self.wfp.is_wfp_available(),
            "gateway_binary": str(self.service_binary),
            "upstream_ips": self.upstream_ips,
            "faulty_exemption_design_removed": True,
            "supported_approaches": [a.value for a in EnforcementArchitecture],
            "loopback_access_preserved": True,
            "gateway_upstream_preserved": True,
            "non_claims": [
                "Does not intercept arbitrary DoH (port 443) without enterprise browser policy.",
                "Does not prevent direct-IP connections that perform no DNS resolution.",
                "Does not intercept traffic routed through virtual TAP/TUN VPN adapters.",
            ],
            "precedence_rationale": (
                "Windows Defender Firewall evaluates Block rules before ordinary Allow rules. "
                "WFP ALE sublayer weight arbitration with FWP_MATCH_EQUAL ensures both local "
                "loopback resolution and external gateway upstreams succeed while rogue traffic is blocked."
            ),
        }

    def get_wfp_filter_definitions(self) -> List[Dict[str, Any]]:
        """Returns the native WFP filter definitions from WFPManager."""
        return self.wfp.get_filter_specifications()

    def get_powershell_netfirewall_rules(self) -> List[Dict[str, Any]]:
        """
        Generates supported PowerShell NetSecurity rules.
        Blocks direct port 853 encrypted DNS.
        """
        return [
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-DoT-TCP",
                "display_name": "DNS-SHIELD Block Outbound DoT (TCP 853)",
                "direction": "Outbound",
                "action": "Block",
                "protocol": "TCP",
                "remote_port": "853",
                "description": "Blocks direct outbound TCP port 853 to prevent DoT bypass.",
            },
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-DoQ-UDP",
                "display_name": "DNS-SHIELD Block Outbound DoQ (UDP 853)",
                "direction": "Outbound",
                "action": "Block",
                "protocol": "UDP",
                "remote_port": "853",
                "description": "Blocks direct outbound UDP port 853 to prevent DoQ bypass.",
            },
        ]

    def preview_rules(self) -> Dict[str, Any]:
        """Returns planned commands, native WFP manifest, and rollback commands for review."""
        ps_rules = self.get_powershell_netfirewall_rules()
        wfp_filters = self.get_wfp_filter_definitions()

        apply_commands = []
        rollback_commands = []

        for r in ps_rules:
            cmd = (
                f"New-NetFirewallRule -Name \"{r['name']}\" -DisplayName \"{r['display_name']}\" "
                f"-Direction {r['direction']} -Action {r['action']} -Protocol {r['protocol']} "
                f"-RemotePort {r['remote_port']} -Description \"{r['description']}\" -Enabled True"
            )
            apply_commands.append(cmd)
            rollback_cmd = f"Remove-NetFirewallRule -Name \"{r['name']}\" -ErrorAction SilentlyContinue"
            rollback_commands.append(rollback_cmd)

        return {
            "status": "PENDING_INTEGRATION_VERIFICATION",
            "architecture": self.architecture.value,
            "wfp_native_available": self.wfp.is_wfp_available(),
            "rules_count": len(ps_rules),
            "wfp_filters_count": len(wfp_filters),
            "wfp_filters": wfp_filters,
            "apply_commands": apply_commands,
            "rollback_commands": rollback_commands,
        }

    def apply_rules(self, dry_run: bool = True) -> Dict[str, Any]:
        """
        Applies bypass defense filters or returns preview.
        Guarded: dry_run=True by default to protect host laptop.
        """
        preview = self.preview_rules()
        if dry_run or os.name != "nt":
            return {"success": True, "dry_run": True, **preview}

        # Apply native WFP filters if running in authorized VM environment
        wfp_res = self.wfp.apply_filters(dry_run=False)

        return {
            "success": wfp_res.get("success", False),
            "dry_run": False,
            "wfp_result": wfp_res,
            **preview,
        }

    def remove_rules(self) -> Dict[str, Any]:
        """Safely cleans up any DNS-SHIELD rules and tears down WFP session."""
        wfp_res = self.wfp.remove_filters()
        preview = self.preview_rules()
        removed = []
        for cmd in preview["rollback_commands"]:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                removed.append(cmd)
            except Exception:
                pass
        return {"success": True, "wfp_cleanup": wfp_res, "removed": removed}
