"""Authenticated, narrow local control protocol for the Windows service."""

import hashlib
import hmac
import json
import secrets
import threading
from pathlib import Path
from typing import Any, Callable, Dict

ALLOWED_OPERATIONS = frozenset({"get_status", "get_events", "set_enabled", "diagnostics"})


def ensure_ipc_secret(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes().strip()
    secret = secrets.token_bytes(32)
    path.write_bytes(secret)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return secret


def make_auth_token(secret: bytes, operation: str, payload: Any = None) -> str:
    message = json.dumps(
        {"operation": operation, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def authorize_request(secret: bytes, request: Dict[str, Any]) -> bool:
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
    if not authorize_request(secret, request):
        return {"ok": False, "error": "unauthorized"}
    operation = request["operation"]
    handler = handlers.get(operation)
    if handler is None:
        return {"ok": False, "error": "operation_unavailable"}
    return {"ok": True, "result": handler(request.get("payload"))}


def encode_request(request: Dict[str, Any]) -> bytes:
    return (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")


def decode_request(data: bytes) -> Dict[str, Any]:
    value = json.loads(data.decode("utf-8"))
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
        import win32file
        import win32pipe
        import win32security

        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)",
            win32security.SDDL_REVISION_1,
        )
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = sd
        while not self._stop.is_set():
            pipe = win32pipe.CreateNamedPipe(
                self.PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1,
                65536,
                65536,
                1000,
                attributes,
            )
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                _, data = win32file.ReadFile(pipe, 65536)
                response = dispatch_request(self.secret, decode_request(data), self.handlers)
                win32file.WriteFile(pipe, encode_request(response))
            except Exception:
                logger = __import__("logging").getLogger("DNSShield.IPC")
                logger.warning("Local IPC request failed.")
            finally:
                win32file.CloseHandle(pipe)
