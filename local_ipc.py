"""Authenticated, narrow local control protocol for the Windows service."""

import hashlib
import hmac
import json
import logging
import secrets
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("DNSShield.IPC")

ALLOWED_OPERATIONS = frozenset({
    "get_status",
    "get_events",
    "set_enabled",
    "diagnostics",
    "get_rules",
    "add_rule",
    "delete_rule",
    "add_allowlist",
    "delete_allowlist",
    "get_network_state",
    "restore_network",
})


def ensure_ipc_secret(path: Path) -> bytes:
    """Ensures a 32-byte shared secret exists at path with restricted permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        secret = path.read_bytes().strip()
        if len(secret) == 32 or len(secret) == 64:
            return secret
    secret = secrets.token_bytes(32)
    path.write_bytes(secret)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return secret


def make_auth_token(secret: bytes, operation: str, payload: Any = None) -> str:
    """Creates an HMAC-SHA256 signature for an operation and payload."""
    message = json.dumps(
        {"operation": operation, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def authorize_request(secret: bytes, request: Dict[str, Any]) -> bool:
    """Validates operation and HMAC-SHA256 authentication token."""
    operation = request.get("operation")
    if operation not in ALLOWED_OPERATIONS:
        return False
    token = request.get("token")
    if not isinstance(token, str):
        return False
    expected = make_auth_token(secret, operation, request.get("payload"))
    return hmac.compare_digest(token, expected)


def dispatch_request(
    secret: bytes,
    request: Dict[str, Any],
    handlers: Dict[str, Callable[[Any], Any]],
) -> Dict[str, Any]:
    """Authorizes and dispatches an IPC request to registered handlers."""
    if not authorize_request(secret, request):
        return {"ok": False, "error": "unauthorized"}
    operation = request["operation"]
    handler = handlers.get(operation)
    if handler is None:
        return {"ok": False, "error": "operation_unavailable"}
    try:
        result = handler(request.get("payload"))
        return {"ok": True, "result": result}
    except Exception as exc:
        logger.error(f"Handler for {operation} raised error: {exc}")
        return {"ok": False, "error": str(exc)}


def encode_request(request: Dict[str, Any]) -> bytes:
    """Serializes a request dictionary into newline-terminated UTF-8 JSON."""
    return (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")


def decode_request(data: bytes) -> Dict[str, Any]:
    """Deserializes UTF-8 JSON request bytes into a dictionary."""
    text = data.decode("utf-8").strip()
    if not text:
        raise ValueError("Empty request")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("IPC request must be a JSON object")
    return value


class NamedPipeServer:
    """Windows named-pipe transport around the authenticated request protocol."""

    PIPE_NAME = r"\\.\pipe\DNSShield"

    def __init__(self, secret: bytes, handlers: Dict[str, Callable[[Any], Any]]):
        self.secret = secret
        self.handlers = handlers
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="DNSShield-IPC", daemon=True)

    def start(self) -> None:
        if __import__("sys").platform != "win32":
            raise RuntimeError("NamedPipeServer requires Windows.")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:  # pragma: no cover - requires Windows named-pipe APIs
        try:
            import win32file
            import win32pipe
            import win32security
        except ImportError:
            logger.error("win32 modules not available for NamedPipeServer")
            return

        # Explicit Security Descriptor: SYSTEM and Administrators full access; Interactive Users read/write
        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
            win32security.SDDL_REVISION_1,
        )
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = sd

        while not self._stop.is_set():
            pipe = win32pipe.CreateNamedPipe(
                self.PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                1000,
                attributes,
            )
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                _, data = win32file.ReadFile(pipe, 65536)
                if data:
                    response = dispatch_request(self.secret, decode_request(data), self.handlers)
                    win32file.WriteFile(pipe, encode_request(response))
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except Exception:
                    pass
            except Exception as e:
                if not self._stop.is_set():
                    logger.debug(f"Local IPC request handling: {e}")
            finally:
                win32file.CloseHandle(pipe)


class NamedPipeClient:
    """Client for local authenticated IPC over Windows named pipe."""

    def __init__(self, secret: bytes, pipe_name: str = NamedPipeServer.PIPE_NAME):
        self.secret = secret
        self.pipe_name = pipe_name

    def call(self, operation: str, payload: Any = None, timeout_s: float = 3.0) -> Dict[str, Any]:
        """Calls a named pipe operation with HMAC token and returns parsed response."""
        token = make_auth_token(self.secret, operation, payload)
        req = {
            "operation": operation,
            "payload": payload,
            "token": token
        }
        req_bytes = encode_request(req)

        try:
            import win32file
            import win32pipe

            handle = win32file.CreateFile(
                self.pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            try:
                win32file.WriteFile(handle, req_bytes)
                _, resp_bytes = win32file.ReadFile(handle, 65536)
                return json.loads(resp_bytes.decode("utf-8").strip())
            finally:
                win32file.CloseHandle(handle)
        except Exception as exc:
            return {"ok": False, "error": f"IPC communication failed: {exc}"}
