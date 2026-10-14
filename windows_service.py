"""
Windows SCM service foundation for the DNS-SHIELD gateway.

Provides genuine Windows Service Control Manager (SCM) integration,
secure Named Pipe IPC, filesystem permissions under %ProgramData%\\DNS-SHIELD,
transactional adapter configuration, and dynamic health status evaluation.
"""

import json
import logging
import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway.config import GatewayConfig
from gateway.db import get_db, init_db
from gateway.server import DNSGatewayServer
from local_ipc import NamedPipeServer, NamedPipeClient, ensure_ipc_secret
from network_manager import NetworkManager
from service_health import HealthState, ProtectionHealth, evaluate_health

logger = logging.getLogger("DNSShield.WindowsService")

try:
    import win32con
    import win32event
    import win32security
    import win32service
    import win32serviceutil
except ImportError:  # pragma: no cover - exercised on Windows with pywin32
    win32con = win32event = win32security = win32service = win32serviceutil = None


def program_data_dir() -> Path:
    root = Path(os.environ.get("PROGRAMDATA", Path.home() / "AppData" / "Local"))
    return root / "DNS-SHIELD"


def restrict_storage_permissions(path: Path) -> None:
    """Allow only LocalSystem and local administrators to access service state."""
    if win32security is None or os.name != "nt":
        return
    try:
        dacl = win32security.ACL()
        for account in ("SYSTEM", "Administrators"):
            sid, _, _ = win32security.LookupAccountName(None, account)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.FILE_ALL_ACCESS,
                sid,
            )
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
    except Exception as exc:
        logger.warning(f"Could not apply restrictive ACL to {path}: {exc}")


class ServiceRuntime:
    """Owns the gateway lifecycle, health reporting, and local IPC dispatching."""

    def __init__(self, config_dir: Optional[Path] = None, dns_port: int = 53):
        self.config_dir = config_dir or program_data_dir()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if self.config_dir == program_data_dir():
            restrict_storage_permissions(self.config_dir)

        self.dns_port = dns_port
        self.ipc_secret_path = self.config_dir / "ipc.secret"
        self.log_path = self.config_dir / "service.log"
        self.db_path = self.config_dir / "dns_gateway.db"

        self.network_manager = NetworkManager(config_dir=self.config_dir)
        self.gateway: Optional[DNSGatewayServer] = None
        self.ipc: Optional[NamedPipeServer] = None
        self.enabled = False
        self._stop_event = threading.Event()
        self.health = evaluate_health(
            enabled=False,
            listener_ready=False,
            policy_ready=False,
            upstream_ready=False,
            routing_verified=False,
        )

    def start(self) -> ProtectionHealth:
        """Starts listeners, loads database, starts Named Pipe server."""
        try:
            ensure_ipc_secret(self.ipc_secret_path)
            restrict_storage_permissions(self.ipc_secret_path)

            handler = logging.FileHandler(self.log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            logger.addHandler(handler)

            init_db(str(self.db_path))

            # Bind DNS Gateway Server
            self.gateway = DNSGatewayServer(
                host="127.0.0.1",
                port=self.dns_port,
                db_path=str(self.db_path),
            )
            self.gateway.start()

            # Register IPC Handlers
            ipc_handlers = {
                "get_status": lambda _p: self.status(),
                "get_events": lambda p: self.get_recent_events(limit=p.get("limit", 100) if isinstance(p, dict) else 100),
                "diagnostics": lambda _p: self.get_diagnostics(),
                "set_enabled": self._set_enabled,
                "get_rules": lambda _p: self.get_rules(),
                "add_rule": self.add_rule,
                "delete_rule": self.delete_rule,
                "add_allowlist": self.add_allowlist,
                "delete_allowlist": self.delete_allowlist,
                "get_network_state": lambda _p: self.get_network_state(),
                "restore_network": lambda _p: self.network_manager.restore_dns(),
                "apply_policy": self.apply_policy,
            }

            self.ipc = NamedPipeServer(self.ipc_secret_path.read_bytes(), ipc_handlers)
            if os.name == "nt":
                self.ipc.start()

            self.enabled = True
            self._update_health_state()
            return self.health

        except Exception as exc:
            logger.error(f"Service startup failed: {exc}")
            self.health = evaluate_health(
                enabled=True,
                listener_ready=False,
                policy_ready=False,
                upstream_ready=False,
                routing_verified=False,
                startup_error=f"Startup failed: {exc}",
            )
            self.stop()
            return self.health

    def stop(self) -> None:
        """Gracefully shuts down listeners and local IPC server."""
        self.enabled = False
        if self.gateway is not None:
            self.gateway.stop()
            self.gateway = None
        if self.ipc is not None:
            self.ipc.stop()
            self.ipc = None
        self._stop_event.set()
        self.health = evaluate_health(
            enabled=False,
            listener_ready=False,
            policy_ready=False,
            upstream_ready=False,
            routing_verified=False,
        )

    def _update_health_state(self):
        """Re-evaluates health checks based on listener, upstream, and adapter state."""
        if not self.enabled:
            self.health = evaluate_health(
                enabled=False,
                listener_ready=False,
                policy_ready=False,
                upstream_ready=False,
                routing_verified=False,
            )
            return

        listener_ready = self.gateway is not None and self.gateway.running
        policy_ready = self.gateway is not None and self.gateway.policy_engine is not None

        upstream_ready = False
        if policy_ready and self.gateway.policy_engine.upstream_resolver:
            # Probe upstream
            upstreams = self.gateway.policy_engine.upstream_resolver.upstreams
            if upstreams:
                first = upstreams[0]
                probe = self.gateway.policy_engine.upstream_resolver.test_resolver(
                    first.get("address", "1.1.1.1"), int(first.get("port", 53))
                )
                upstream_ready = probe.get("success", False)

        routing_verified, _ = self.network_manager.verify_routing()

        self.health = evaluate_health(
            enabled=True,
            listener_ready=listener_ready,
            policy_ready=policy_ready,
            upstream_ready=upstream_ready,
            routing_verified=routing_verified,
        )

    def status(self) -> Dict[str, Any]:
        """Returns health state, listener readiness, and routing verification."""
        self._update_health_state()
        return {
            "state": self.health.state.value,
            "detail": self.health.detail,
            "listener_ready": self.health.listener_ready,
            "policy_ready": self.health.policy_ready,
            "upstream_ready": self.health.upstream_ready,
            "routing_verified": self.health.routing_verified,
            "dns_port": self.dns_port,
        }

    def _set_enabled(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict) or not isinstance(payload.get("enabled"), bool):
            raise ValueError("Payload must contain boolean 'enabled' property")

        desired = payload["enabled"]
        if desired:
            if not self.gateway or not self.gateway.running:
                self.start()
            # Transactionally route physical network adapter DNS
            net_res = self.network_manager.enable_protection()
            if not net_res.get("success", False):
                logger.warning(f"Could not route adapter DNS: {net_res.get('error')}")
            self.enabled = True
        else:
            self.network_manager.restore_dns()
            self.enabled = False

        self._update_health_state()
        return {
            "state": self.health.state.value,
            "detail": self.health.detail,
            "routing_verified": self.health.routing_verified,
        }

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Queries the latest DNS audit events from the SQLite database."""
        try:
            conn = get_db(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, reason, rcode, response_time_ms
                FROM dns_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (min(500, max(1, limit)),))
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.error(f"Error fetching DNS logs: {exc}")
            return []

    def get_rules(self) -> Dict[str, Any]:
        """Returns custom rules, allowlist entries, and blocklist sources."""
        try:
            conn = get_db(str(self.db_path))
            cur = conn.cursor()
            cur.execute("SELECT id, domain, rule_type, action, enabled, reason, created_at FROM custom_rules")
            custom_rules = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT id, domain, rule_type, enabled, reason, created_at FROM allowlist")
            allowlist = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT id, name, category, enabled, entry_count, last_status FROM blocklist_sources")
            blocklists = [dict(r) for r in cur.fetchall()]
            conn.close()
            return {
                "custom_rules": custom_rules,
                "allowlist": allowlist,
                "blocklists": blocklists,
            }
        except Exception as exc:
            return {"error": str(exc), "custom_rules": [], "allowlist": [], "blocklists": []}

    def add_rule(self, payload: Any) -> Dict[str, Any]:
        """Adds a custom block rule and reloads policy."""
        if not isinstance(payload, dict) or not payload.get("domain"):
            raise ValueError("domain is required")
        domain = payload["domain"].strip().lower()
        rule_type = payload.get("rule_type", "subdomain")
        reason = payload.get("reason", "Custom administrative block rule")

        conn = get_db(str(self.db_path))
        now = time.time()
        conn.execute("""
            INSERT OR REPLACE INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at)
            VALUES (?, ?, 'BLOCK', 1, ?, ?, ?)
        """, (domain, rule_type, reason, now, now))
        conn.commit()
        conn.close()

        if self.gateway and self.gateway.policy_engine:
            self.gateway.policy_engine.cache.invalidate_domain(domain)
            self.gateway.policy_engine.reload_policies()
        return {"success": True, "domain": domain}

    def delete_rule(self, payload: Any) -> Dict[str, Any]:
        """Deletes a custom block rule by domain or id."""
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        rule_id = payload.get("id")
        domain = payload.get("domain")

        conn = get_db(str(self.db_path))
        if rule_id:
            conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
        elif domain:
            conn.execute("DELETE FROM custom_rules WHERE domain = ?", (domain,))
        conn.commit()
        conn.close()

        if self.gateway and self.gateway.policy_engine:
            self.gateway.policy_engine.reload_policies()
        return {"success": True}

    def add_allowlist(self, payload: Any) -> Dict[str, Any]:
        """Adds an allowlist exemption and reloads policy."""
        if not isinstance(payload, dict) or not payload.get("domain"):
            raise ValueError("domain is required")
        domain = payload["domain"].strip().lower()
        rule_type = payload.get("rule_type", "exact")
        reason = payload.get("reason", "Administrative allowlist exemption")

        conn = get_db(str(self.db_path))
        now = time.time()
        conn.execute("""
            INSERT OR REPLACE INTO allowlist (domain, rule_type, enabled, reason, created_at)
            VALUES (?, ?, 1, ?, ?)
        """, (domain, rule_type, reason, now))
        conn.commit()
        conn.close()

        if self.gateway and self.gateway.policy_engine:
            self.gateway.policy_engine.reload_policies()
        return {"success": True, "domain": domain}

    def delete_allowlist(self, payload: Any) -> Dict[str, Any]:
        """Deletes an allowlist entry by id or domain."""
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        entry_id = payload.get("id")
        domain = payload.get("domain")

        conn = get_db(str(self.db_path))
        if entry_id:
            conn.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
        elif domain:
            conn.execute("DELETE FROM allowlist WHERE domain = ?", (domain,))
        conn.commit()
        conn.close()

        if self.gateway and self.gateway.policy_engine:
            self.gateway.policy_engine.reload_policies()
        return {"success": True}

    def apply_policy(self, payload: Any) -> Dict[str, Any]:
        """Validates and applies an asymmetric Ed25519 publisher signed policy envelope."""
        from hosted_management.policy_verifier import EndpointPolicyVerifier, PolicyVerificationError
        if not isinstance(payload, dict):
            raise ValueError("Policy payload must be a JSON object")

        pub_key = payload.get("public_key") or payload.get("policy_public_key")
        verifier = EndpointPolicyVerifier(
            trusted_public_key_hex=pub_key,
            expected_tenant_id=payload.get("tenant_id", ""),
            db_path=str(self.db_path),
        )
        if pub_key and payload.get("key_id"):
            verifier.keyring[payload["key_id"]] = verifier.public_key

        res = verifier.verify_and_process(payload)
        if res.get("action") == "noop":
            return {"status": "no_change", "version": res["version"]}

        # Atomically apply rules to the SQLite database
        conn = get_db(str(self.db_path))
        now = time.time()
        conn.execute("DELETE FROM custom_rules")
        for r in res.get("custom_rules", []):
            conn.execute(
                "INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at) VALUES (?, 'subdomain', 'BLOCK', 1, 'Policy Rule', ?, ?)",
                (r, now, now)
            )
        conn.execute("DELETE FROM allowlist")
        for a in res.get("allowlist", []):
            conn.execute(
                "INSERT INTO allowlist (domain, rule_type, enabled, reason, created_at) VALUES (?, 'exact', 1, 'Policy Exemption', ?)",
                (a, now)
            )
        conn.execute("DELETE FROM blocked_record_types")
        for bt in res.get("blocked_types", []):
            conn.execute(
                "INSERT INTO blocked_record_types (qtype, enabled, reason, created_at) VALUES (?, 1, 'Policy Blocked Record', ?)",
                (bt, now)
            )
        conn.commit()
        conn.close()

        if self.gateway and self.gateway.policy_engine:
            self.gateway.policy_engine.cache.clear()
            self.gateway.policy_engine.reload_policies()

        return {"status": "activated", "version": res["version"]}

    def get_network_state(self) -> Dict[str, Any]:
        """Returns detected network adapters and routing verification status."""
        adapters = self.network_manager.get_active_physical_adapters()
        routing_verified, msg = self.network_manager.verify_routing()
        return {
            "adapters": adapters,
            "routing_verified": routing_verified,
            "routing_message": msg,
        }

    def get_diagnostics(self) -> Dict[str, Any]:
        """Exports service diagnostics with sensitive API keys redacted."""
        status_info = self.status()
        adapters = self.network_manager.get_active_physical_adapters()

        upstreams = []
        if self.gateway and self.gateway.policy_engine:
            for u in self.gateway.policy_engine.upstream_resolver.upstreams:
                upstreams.append({
                    "address": u.get("address"),
                    "port": u.get("port"),
                    "protocol": u.get("protocol"),
                    "health": u.get("health_status"),
                    "latency_ms": u.get("last_latency_ms"),
                })

        return {
            "service": "DNS-SHIELD",
            "version": "2.0.0",
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "status": status_info,
            "storage_path": str(self.config_dir),
            "database_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "adapters": adapters,
            "upstreams": upstreams,
            # Explicit secret redaction guarantee:
            "ipc_secret": "[REDACTED]",
            "admin_key": "[REDACTED]",
        }


if win32serviceutil is not None:
    class DNSShieldWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "DNSShield"
        _svc_display_name_ = "DNS-SHIELD DNS Protection"
        _svc_description_ = "Local deterministic DNS filtering background service."

        def __init__(self, args: Any):
            super().__init__(args)
            self.stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self.runtime = ServiceRuntime()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.runtime.stop()
            win32event.SetEvent(self.stop_handle)

        def SvcDoRun(self):
            self.runtime.start()
            win32event.WaitForSingleObject(self.stop_handle, win32event.INFINITE)
else:
    DNSShieldWindowsService = None


def handle_cli_command(args: List[str]) -> int:
    """
    Packaged administrative CLI for headless VM integration and management.
    Reads ipc.secret internally without exposing secrets on the process command line.
    """
    if not args or args[0] in ("-h", "--help", "help"):
        print("DNS-SHIELD Packaged Administrative CLI")
        print("Usage: DNSShieldService.exe cli <command> [arguments]\n")
        print("Commands:")
        print("  add-rule <domain> [rule_type] [reason]   Add a custom domain block rule")
        print("  get-rules                                 Query active rules loaded in memory")
        print("  enable-protection                         Enable live DNS adapter redirection")
        print("  status                                    Query service and protection health status")
        print("  restore-network                           Restore original adapter DNS settings")
        return 0

    subcmd = args[0].lower()
    secret_path = program_data_dir() / "ipc.secret"
    secret = None
    if secret_path.exists():
        try:
            secret = secret_path.read_bytes().strip()
        except Exception as e:
            logger.debug(f"Could not read internal IPC secret: {e}")

    client = NamedPipeClient(secret=secret)

    if subcmd == "add-rule":
        if len(args) < 2:
            print("Error: add-rule requires <domain>", file=sys.stderr)
            return 1
        domain = args[1].strip().lower()
        rule_type = args[2] if len(args) > 2 else "subdomain"
        reason = args[3] if len(args) > 3 else "Administrative CLI Rule"
        resp = client.call("add_rule", {"domain": domain, "rule_type": rule_type, "reason": reason})
        print(json.dumps(resp, indent=2))
        return 0 if resp.get("ok") else 1

    elif subcmd == "get-rules":
        resp = client.call("get_rules")
        print(json.dumps(resp, indent=2))
        return 0 if resp.get("ok") else 1

    elif subcmd == "enable-protection":
        resp = client.call("set_enabled", {"enabled": True})
        if not resp.get("ok"):
            nm = NetworkManager()
            res = nm.enable_protection()
            print(json.dumps(res, indent=2))
            return 0 if res.get("success") else 1
        print(json.dumps(resp, indent=2))
        return 0

    elif subcmd == "status":
        resp = client.call("get_status")
        print(json.dumps(resp, indent=2))
        return 0 if resp.get("ok") else 1

    elif subcmd == "restore-network":
        resp = client.call("restore_network")
        if not resp.get("ok"):
            nm = NetworkManager()
            res = nm.restore_dns()
            print(json.dumps(res, indent=2))
            return 0 if res.get("success") else 1
        print(json.dumps(resp, indent=2))
        return 0

    else:
        print(f"Unknown CLI command: '{subcmd}'. Run 'cli --help' for usage.", file=sys.stderr)
        return 1


def main() -> None:
    if len(sys.argv) > 1:
        first = sys.argv[1].lower()
        if first == "cli":
            sys.exit(handle_cli_command(sys.argv[2:]))
        elif first in ("add-rule", "get-rules", "enable-protection", "status", "restore-network"):
            sys.exit(handle_cli_command(sys.argv[1:]))

    if DNSShieldWindowsService is None:
        raise RuntimeError("Windows SCM integration requires Windows and pywin32.")
    win32serviceutil.HandleCommandLine(DNSShieldWindowsService)


if __name__ == "__main__":
    main()
