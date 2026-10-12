"""
Windows Firewall Bypass Defense Manager.

Generates and applies Windows Advanced Firewall rules to block unauthorized
direct outbound port 53 (DNS) and port 853 (DoT/DoQ) traffic, ensuring that
local resolution cannot be bypassed by rogue processes querying public resolvers directly.
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("DNSShield.FirewallManager")


class FirewallManager:
    """Manages Windows Firewall rules for DNS leak and bypass prevention."""

    RULE_PREFIX = "DNSShield"

    def __init__(self, service_binary_path: Optional[Path] = None):
        self.service_binary = service_binary_path or Path(os.sys.executable)

    def get_rule_definitions(self) -> List[Dict[str, Any]]:
        """Returns structured descriptions of the required firewall rules."""
        service_path_str = str(self.service_binary)
        return [
            {
                "name": f"{self.RULE_PREFIX}-Allow-Service-Outbound-DNS",
                "description": "Allow DNS-SHIELD service to query upstream resolvers on port 53",
                "direction": "out",
                "action": "allow",
                "protocol": "any",
                "remoteport": "53",
                "program": service_path_str,
            },
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-Outbound-DNS-UDP",
                "description": "Block direct UDP port 53 queries to prevent malware bypass of local resolver",
                "direction": "out",
                "action": "block",
                "protocol": "udp",
                "remoteport": "53",
                "program": None,  # System-wide
            },
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-Outbound-DNS-TCP",
                "description": "Block direct TCP port 53 queries to prevent malware bypass of local resolver",
                "direction": "out",
                "action": "block",
                "protocol": "tcp",
                "remoteport": "53",
                "program": None,
            },
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-Outbound-DoT-TCP",
                "description": "Block port 853 (DNS-over-TLS) outbound to prevent encrypted DNS bypass",
                "direction": "out",
                "action": "block",
                "protocol": "tcp",
                "remoteport": "853",
                "program": None,
            },
            {
                "name": f"{self.RULE_PREFIX}-Block-Direct-Outbound-DoQ-UDP",
                "description": "Block port 853 (DNS-over-QUIC) outbound to prevent encrypted DNS bypass",
                "direction": "out",
                "action": "block",
                "protocol": "udp",
                "remoteport": "853",
                "program": None,
            },
        ]

    def preview_rules(self) -> Dict[str, Any]:
        """Returns planned commands and rollback commands for administrator confirmation."""
        rules = self.get_rule_definitions()
        apply_commands = []
        rollback_commands = []

        for r in rules:
            cmd = (
                f"netsh advfirewall firewall add rule "
                f"name=\"{r['name']}\" "
                f"dir={r['direction']} "
                f"action={r['action']} "
                f"protocol={r['protocol']} "
                f"remoteport={r['remoteport']} "
            )
            if r.get("program"):
                cmd += f"program=\"{r['program']}\" "
            cmd += f"description=\"{r['description']}\""
            apply_commands.append(cmd)

            rollback_cmd = f"netsh advfirewall firewall delete rule name=\"{r['name']}\""
            rollback_commands.append(rollback_cmd)

        return {
            "rules_count": len(rules),
            "apply_commands": apply_commands,
            "rollback_commands": rollback_commands,
        }

    def apply_rules(self, dry_run: bool = False) -> Dict[str, Any]:
        """Applies bypass defense firewall rules or returns preview if dry_run=True."""
        preview = self.preview_rules()
        if dry_run or os.name != "nt":
            return {"success": True, "dry_run": True, **preview}

        applied = []
        errors = []
        for cmd in preview["apply_commands"]:
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    applied.append(cmd)
                else:
                    errors.append(f"Failed: {cmd} -> {res.stderr.strip()}")
            except Exception as exc:
                errors.append(f"Exception: {cmd} -> {exc}")

        return {
            "success": len(errors) == 0,
            "applied": applied,
            "errors": errors,
        }

    def remove_rules(self) -> Dict[str, Any]:
        """Removes all DNS-SHIELD firewall rules."""
        preview = self.preview_rules()
        if os.name != "nt":
            return {"success": True, "removed": preview["rollback_commands"]}

        removed = []
        for cmd in preview["rollback_commands"]:
            try:
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                removed.append(cmd)
            except Exception:
                pass
        return {"success": True, "removed": removed}
