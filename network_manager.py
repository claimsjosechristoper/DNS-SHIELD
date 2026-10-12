"""
Transactional Windows Network Adapter DNS Configuration and Recovery Manager.

Identifies active physical network interfaces, snapshots original IPv4/IPv6
DNS settings to disk before mutation, validates listener readiness, routes
adapter resolution to local loopback, and provides robust, atomic rollback.
"""

import json
import logging
import os
import re
import socket
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("DNSShield.NetworkManager")


@dataclass
class AdapterDNSConfig:
    alias: str
    interface_index: int
    ipv4_dhcp: bool
    ipv4_servers: List[str]
    ipv6_dhcp: bool
    ipv6_servers: List[str]


class NetworkManager:
    """Manages transactional Windows DNS adapter configuration and recovery."""

    def __init__(self, config_dir: Optional[Path] = None):
        root = config_dir or Path(os.environ.get("PROGRAMDATA", Path.home() / "AppData" / "Local")) / "DNS-SHIELD"
        self.config_dir = root
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_path = self.config_dir / "dns_backup.json"

    def get_active_physical_adapters(self) -> List[Dict[str, Any]]:
        """
        Enumerates active physical network adapters (Ethernet, Wi-Fi).
        Excludes virtual, container, loopback, and tunnel adapters.
        """
        if os.name != "nt":
            # For isolated testing on non-Windows platforms
            return [{"alias": "Ethernet0", "index": 1, "description": "Virtual Test Adapter"}]

        ps_cmd = (
            "Get-NetAdapter | Where-Object { "
            "$_.Status -eq 'Up' -and "
            "$_.Virtual -eq $false -and "
            "$_.InterfaceDescription -notmatch 'Virtual|Hyper-V|WSL|Docker|VPN|TAP|Wintun|Bluetooth' "
            "} | Select-Object Name, InterfaceIndex, InterfaceDescription, MediaType | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode != 0 or not res.stdout.strip():
                logger.warning(f"Get-NetAdapter returned empty or failed: {res.stderr}")
                return []

            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            adapters = []
            for item in data:
                adapters.append({
                    "alias": item.get("Name", ""),
                    "index": item.get("InterfaceIndex", 0),
                    "description": item.get("InterfaceDescription", "")
                })
            return [a for a in adapters if a["alias"]]
        except Exception as exc:
            logger.error(f"Error enumerating active network adapters: {exc}")
            return []

    def get_adapter_dns_config(self, alias: str) -> Optional[AdapterDNSConfig]:
        """Retrieves current IPv4 and IPv6 DNS configuration for an adapter."""
        if os.name != "nt":
            return AdapterDNSConfig(alias=alias, interface_index=1, ipv4_dhcp=True, ipv4_servers=[], ipv6_dhcp=True, ipv6_servers=[])

        ps_cmd = f"Get-DnsClientServerAddress -InterfaceAlias '{alias}' | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | ConvertTo-Json -Compress"
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode != 0 or not res.stdout.strip():
                return None

            items = json.loads(res.stdout)
            if isinstance(items, dict):
                items = [items]

            ipv4_servers = []
            ipv6_servers = []
            if_index = 0

            for entry in items:
                if_index = entry.get("InterfaceIndex", if_index)
                family = entry.get("AddressFamily")
                servers = entry.get("ServerAddresses") or []
                if isinstance(servers, str):
                    servers = [servers]
                if family == 2:  # IPv4
                    ipv4_servers = [s for s in servers if s]
                elif family == 23:  # IPv6
                    ipv6_servers = [s for s in servers if s]

            # Determine DHCP vs Static via netsh
            ipv4_dhcp = self._is_dhcp(alias, "ipv4")
            ipv6_dhcp = self._is_dhcp(alias, "ipv6")

            return AdapterDNSConfig(
                alias=alias,
                interface_index=if_index,
                ipv4_dhcp=ipv4_dhcp,
                ipv4_servers=ipv4_servers,
                ipv6_dhcp=ipv6_dhcp,
                ipv6_servers=ipv6_servers,
            )
        except Exception as exc:
            logger.error(f"Failed to query DNS config for adapter {alias}: {exc}")
            return None

    def _is_dhcp(self, alias: str, proto: str) -> bool:
        cmd = ["netsh.exe", "interface", proto, "show", "dnsservers", f"name={alias}"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            output = res.stdout.lower()
            return "dhcp" in output and "statically configured" not in output
        except Exception:
            return True

    def preflight_check(self, test_port: int = 53, test_host: str = "127.0.0.1") -> Tuple[bool, str]:
        """
        Verifies local listener readiness before mutating network settings.
        Tests UDP connectivity and query resolution.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            # Send standard query for localhost or test name
            # ID: 0x1234, Flags: 0x0100 (standard query, recursion desired), QDCOUNT: 1
            query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            sock.sendto(query, (test_host, test_port))
            data, _ = sock.recvfrom(4096)
            if data and len(data) >= 12:
                return True, "Local listener is active and answering queries."
            return False, "Listener returned empty or invalid response."
        except socket.timeout:
            return False, f"Port {test_port} on {test_host} timed out. Gateway listener not responding."
        except Exception as exc:
            return False, f"Preflight probe error: {exc}"
        finally:
            sock.close()

    def enable_protection(self, target_aliases: Optional[List[str]] = None, dry_run: bool = False) -> Dict[str, Any]:
        """
        Transactionally snapshots adapter DNS and configures loopback DNS.
        """
        adapters = self.get_active_physical_adapters()
        if target_aliases:
            adapters = [a for a in adapters if a["alias"] in target_aliases]

        if not adapters:
            return {"success": False, "error": "No active physical adapters found to protect."}

        # 1. Snapshot configurations before changing anything
        snapshot: Dict[str, Any] = {}
        for a in adapters:
            alias = a["alias"]
            config = self.get_adapter_dns_config(alias)
            if config:
                snapshot[alias] = asdict(config)

        if not snapshot:
            return {"success": False, "error": "Could not read adapter DNS configurations."}

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "target_adapters": list(snapshot.keys()),
                "snapshot": snapshot,
                "planned_actions": [
                    f"Set {alias} IPv4 DNS to 127.0.0.1" for alias in snapshot
                ] + [
                    f"Set {alias} IPv6 DNS to ::1" for alias in snapshot
                ]
            }

        # Save snapshot atomically to disk
        try:
            tmp_backup = self.backup_path.with_suffix(".tmp")
            tmp_backup.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            tmp_backup.replace(self.backup_path)
        except Exception as exc:
            return {"success": False, "error": f"Failed to persist recovery snapshot: {exc}"}

        # 2. Mutate adapters with rollback on failure
        mutated = []
        try:
            for alias in snapshot.keys():
                # Configure IPv4 loopback DNS
                res_v4 = subprocess.run(
                    ["netsh.exe", "interface", "ipv4", "set", "dnsservers", f"name={alias}", "source=static", "address=127.0.0.1", "validate=no"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if res_v4.returncode != 0:
                    raise RuntimeError(f"Failed to set IPv4 DNS on {alias}: {res_v4.stderr.strip()}")

                # Configure IPv6 loopback DNS if IPv6 is supported
                subprocess.run(
                    ["netsh.exe", "interface", "ipv6", "set", "dnsservers", f"name={alias}", "source=static", "address=::1", "validate=no"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                mutated.append(alias)

            logger.info(f"Successfully configured DNS protection on adapters: {mutated}")
            return {"success": True, "protected_adapters": mutated}
        except Exception as exc:
            logger.error(f"Adapter configuration error: {exc}. Rolling back...")
            self.restore_dns()
            return {"success": False, "error": f"Configuration failed, changes rolled back: {exc}"}

    def restore_dns(self) -> Dict[str, Any]:
        """
        Restores original adapter configurations from snapshot.
        """
        if not self.backup_path.exists():
            return {"success": True, "restored": [], "message": "No active backup found; adapters already in default state."}

        try:
            snapshot = json.loads(self.backup_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"success": False, "error": f"Failed to parse recovery snapshot: {exc}"}

        restored = []
        errors = []

        for alias, cfg in snapshot.items():
            try:
                # Restore IPv4
                if cfg.get("ipv4_dhcp", True) or not cfg.get("ipv4_servers"):
                    subprocess.run(
                        ["netsh.exe", "interface", "ipv4", "set", "dnsservers", f"name={alias}", "source=dhcp"],
                        capture_output=True,
                        check=False
                    )
                else:
                    servers = cfg["ipv4_servers"]
                    subprocess.run(
                        ["netsh.exe", "interface", "ipv4", "set", "dnsservers", f"name={alias}", "source=static", f"address={servers[0]}", "validate=no"],
                        capture_output=True,
                        check=False
                    )
                    for sec in servers[1:]:
                        subprocess.run(
                            ["netsh.exe", "interface", "ipv4", "add", "dnsservers", f"name={alias}", f"address={sec}", "validate=no"],
                            capture_output=True,
                            check=False
                        )

                # Restore IPv6
                if cfg.get("ipv6_dhcp", True) or not cfg.get("ipv6_servers"):
                    subprocess.run(
                        ["netsh.exe", "interface", "ipv6", "set", "dnsservers", f"name={alias}", "source=dhcp"],
                        capture_output=True,
                        check=False
                    )
                else:
                    servers = cfg["ipv6_servers"]
                    subprocess.run(
                        ["netsh.exe", "interface", "ipv6", "set", "dnsservers", f"name={alias}", "source=static", f"address={servers[0]}", "validate=no"],
                        capture_output=True,
                        check=False
                    )
                    for sec in servers[1:]:
                        subprocess.run(
                            ["netsh.exe", "interface", "ipv6", "add", "dnsservers", f"name={alias}", f"address={sec}", "validate=no"],
                            capture_output=True,
                            check=False
                        )

                restored.append(alias)
            except Exception as exc:
                errors.append(f"Error restoring {alias}: {exc}")

        # Remove backup file after successful restoration
        if not errors:
            try:
                self.backup_path.unlink()
            except Exception:
                pass
            return {"success": True, "restored": restored}
        return {"success": False, "restored": restored, "errors": errors}

    def verify_routing(self) -> Tuple[bool, str]:
        """Checks if active physical adapters currently route DNS to loopback."""
        adapters = self.get_active_physical_adapters()
        if not adapters:
            return False, "No active physical adapters detected."

        for a in adapters:
            alias = a["alias"]
            cfg = self.get_adapter_dns_config(alias)
            if not cfg:
                continue
            # Check if 127.0.0.1 or ::1 is in configured servers
            has_loopback = any(s in ("127.0.0.1", "::1") for s in (cfg.ipv4_servers + cfg.ipv6_servers))
            if not has_loopback:
                return False, f"Adapter '{alias}' is not pointing to DNS-SHIELD loopback."

        return True, "Active physical adapters successfully routed to local DNS-SHIELD."
