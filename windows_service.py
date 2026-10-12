"""Windows SCM service foundation for the DNS-SHIELD gateway.

The module is importable on non-Windows hosts for lifecycle tests. SCM
registration is only available when pywin32 is installed on Windows.
"""

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict

from gateway.config import GatewayConfig
from gateway.db import init_db
from gateway.server import DNSGatewayServer
from local_ipc import NamedPipeServer, ensure_ipc_secret
from service_health import HealthState, ProtectionHealth, evaluate_health

logger = logging.getLogger("DNSShield.WindowsService")

try:
    import win32event
    import win32con
    import win32security
    import win32service
    import win32serviceutil
except ImportError:  # pragma: no cover - exercised only on non-Windows hosts
    win32con = win32event = win32security = win32service = win32serviceutil = None


def program_data_dir() -> Path:
    root = Path(os.environ.get("PROGRAMDATA", Path.home() / "AppData" / "Local"))
    return root / "DNS-SHIELD"


def restrict_storage_permissions(path: Path) -> None:
    """Allow only LocalSystem and local administrators to access service state."""
    if win32security is None:
        return
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


class ServiceRuntime:
    """Owns the gateway lifecycle without claiming verified protection."""

    def __init__(self, config_dir: Path | None = None):
        self.config_dir = config_dir or program_data_dir()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if self.config_dir == program_data_dir():
            restrict_storage_permissions(self.config_dir)
        self.ipc_secret_path = self.config_dir / "ipc.secret"
        self.log_path = self.config_dir / "service.log"
        self.db_path = self.config_dir / "dns_gateway.db"
        self.gateway: DNSGatewayServer | None = None
        self.ipc: NamedPipeServer | None = None
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
        try:
            ensure_ipc_secret(self.ipc_secret_path)
            restrict_storage_permissions(self.ipc_secret_path)
            handler = logging.FileHandler(self.log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            logger.addHandler(handler)
            init_db(str(self.db_path))
            self.gateway = DNSGatewayServer(
                host=GatewayConfig.DNS_HOST,
                port=GatewayConfig.DNS_PORT,
                db_path=str(self.db_path),
            )
            self.gateway.start()
            self.ipc = NamedPipeServer(
                self.ipc_secret_path.read_bytes(),
                {
                    "get_status": lambda _payload: self.status(),
                    "get_events": lambda _payload: [],
                    "diagnostics": lambda _payload: self.status(),
                    "set_enabled": self._set_enabled,
                },
            )
            if os.name == "nt":
                self.ipc.start()
            self.enabled = True
            self.health = evaluate_health(
                enabled=True,
                listener_ready=True,
                policy_ready=True,
                upstream_ready=False,
                routing_verified=False,
            )
            return self.health
        except Exception as exc:
            logger.error("Service startup failed: %s", exc)
            self.health = evaluate_health(
                enabled=True,
                listener_ready=False,
                policy_ready=False,
                upstream_ready=False,
                routing_verified=False,
                startup_error="Startup failed.",
            )
            self.stop()
            return self.health

    def stop(self) -> None:
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

    def status(self) -> Dict[str, Any]:
        return {
            "state": self.health.state.value,
            "detail": self.health.detail,
            "listener_ready": self.health.listener_ready,
            "policy_ready": self.health.policy_ready,
            "upstream_ready": self.health.upstream_ready,
            "routing_verified": self.health.routing_verified,
        }

    def _set_enabled(self, payload: Any) -> Dict[str, str]:
        if not isinstance(payload, dict) or not isinstance(payload.get("enabled"), bool):
            raise ValueError("enabled must be a boolean")
        if not payload["enabled"]:
            self.stop()
        return {"state": self.health.state.value}


if win32serviceutil is not None:
    class DNSShieldWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "DNSShield"
        _svc_display_name_ = "DNS-SHIELD DNS Protection"
        _svc_description_ = "Local deterministic DNS filtering service."

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


def main() -> None:
    if DNSShieldWindowsService is None:
        raise RuntimeError("Windows SCM integration requires Windows and pywin32.")
    win32serviceutil.HandleCommandLine(DNSShieldWindowsService)


if __name__ == "__main__":
    main()
