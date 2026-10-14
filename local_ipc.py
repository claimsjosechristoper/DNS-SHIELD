"""
Authenticated, narrow local control protocol for the Windows service.

Separates read-only status monitoring (accessible to unelevated interactive users)
from privileged mutations (strictly requiring administrator HMAC-SHA256 authentication
with replay protection, timestamp bounds, and message limits).
"""

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Tuple

logger = logging.getLogger("DNSShield.IPC")

# Maximum permitted payload size over IPC to prevent denial-of-service / memory exhaustion
MAX_IPC_MESSAGE_SIZE = 65536  # 64 KB

# Operations accessible to unelevated local users (Desktop UI monitoring)
READ_ONLY_OPERATIONS = frozenset({
    "get_status",
    "get_events",
    "get_rules",
    "get_network_state",
    "diagnostics",
})

# Privileged operations requiring administrator HMAC-SHA256 authorization & replay protection
PRIVILEGED_OPERATIONS = frozenset({
    "set_enabled",
    "restore_network",
    "add_rule",
    "delete_rule",
    "add_allowlist",
    "delete_allowlist",
    "apply_policy",
})

ALLOWED_OPERATIONS = READ_ONLY_OPERATIONS | PRIVILEGED_OPERATIONS

# Replay protection threshold in seconds
MAX_TIMESTAMP_SKEW_SECONDS = 60.0


class ReplayCache:
    """Thread-safe bounded cache of recent request nonces to prevent replay attacks."""

    def __init__(self, ttl_seconds: float = MAX_TIMESTAMP_SKEW_SECONDS):
        self.ttl = ttl_seconds
        self._nonces: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: Optional[float] = None) -> bool:
        """
        Returns True if the nonce is valid and fresh (not replayed).
        Returns False if the nonce was already used within the validity window.
        """
        if not nonce or len(nonce) < 8:
            return False

        current_time = now if now is not None else time.time()
        with self._lock:
            # Purge expired nonces
            cutoff = current_time - (self.ttl * 2)
            expired = [n for n, ts in self._nonces.items() if ts < cutoff]
            for n in expired:
                del self._nonces[n]

            if nonce in self._nonces:
                return False  # Replay detected

            self._nonces[nonce] = current_time
            return True


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


def make_auth_token(
    secret: bytes,
    operation: str,
    payload: Any = None,
    timestamp: Optional[float] = None,
    nonce: Optional[str] = None,
) -> str:
    """Creates an HMAC-SHA256 signature for an operation, payload, timestamp, and nonce."""
    msg_dict: Dict[str, Any] = {"operation": operation, "payload": payload}
    if timestamp is not None:
        msg_dict["timestamp"] = timestamp
    if nonce is not None:
        msg_dict["nonce"] = nonce

    message = json.dumps(
        msg_dict,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def authorize_request_detail(
    secret: Optional[bytes],
    request: Dict[str, Any],
    replay_cache: Optional[ReplayCache] = None,
    now: Optional[float] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates operation tier, message limits, replay protection, and HMAC signature.
    Returns (is_authorized: bool, error_reason: Optional[str]).
    """
    operation = request.get("operation")
    if operation not in ALLOWED_OPERATIONS:
        return False, "unknown_operation"

    # Tier 1: Read-only monitoring operations are permitted for local unelevated UI
    if operation in READ_ONLY_OPERATIONS:
        return True, None

    # Tier 2: Privileged mutations strictly require administrator HMAC authorization
    if not secret:
        return False, "privileged_secret_required"

    token = request.get("token")
    if not isinstance(token, str) or not token:
        return False, "missing_token"

    # Verify timestamp to prevent replay of old signed messages
    ts = request.get("timestamp")
    current_time = now if now is not None else time.time()

    # Check for legacy token format (without timestamp/nonce) or modern replay-protected format
    if ts is not None:
        if not isinstance(ts, (int, float)):
            return False, "invalid_timestamp"
        if abs(current_time - float(ts)) > MAX_TIMESTAMP_SKEW_SECONDS:
            return False, "expired_timestamp"

        nonce = request.get("nonce")
        if not isinstance(nonce, str) or len(nonce) < 8:
            return False, "invalid_nonce"

        if replay_cache is not None:
            if not replay_cache.check_and_add(nonce, current_time):
                return False, "replay_detected"

        expected = make_auth_token(secret, operation, request.get("payload"), timestamp=float(ts), nonce=nonce)
    else:
        # Backward compatibility for direct callers: require exact payload HMAC
        expected = make_auth_token(secret, operation, request.get("payload"))

    if not hmac.compare_digest(token, expected):
        return False, "unauthorized"

    return True, None


def authorize_request(
    secret: Optional[bytes],
    request: Dict[str, Any],
    replay_cache: Optional[ReplayCache] = None,
    now: Optional[float] = None,
) -> bool:
    """Validates request and returns boolean success for standard authorization checks."""
    is_auth, _ = authorize_request_detail(secret, request, replay_cache, now)
    return is_auth


def dispatch_request(
    secret: Optional[bytes],
    request: Dict[str, Any],
    handlers: Dict[str, Callable[[Any], Any]],
    replay_cache: Optional[ReplayCache] = None,
) -> Dict[str, Any]:
    """Authorizes and dispatches an IPC request to registered handlers."""
    is_auth, err_msg = authorize_request_detail(secret, request, replay_cache)
    if not is_auth:
        return {"ok": False, "error": err_msg or "unauthorized"}

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
    encoded = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_IPC_MESSAGE_SIZE:
        raise ValueError(f"Serialized request exceeds maximum permitted size of {MAX_IPC_MESSAGE_SIZE} bytes")
    return encoded


def decode_request(data: bytes) -> Dict[str, Any]:
    """Deserializes UTF-8 JSON request bytes into a dictionary with size enforcement."""
    if len(data) > MAX_IPC_MESSAGE_SIZE:
        raise ValueError(f"IPC request data exceeds maximum limit of {MAX_IPC_MESSAGE_SIZE} bytes")
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

    def __init__(self, secret: Optional[bytes], handlers: Dict[str, Callable[[Any], Any]]):
        self.secret = secret
        self.handlers = handlers
        self.replay_cache = ReplayCache()
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

        # Security Descriptor: SYSTEM (SY) and Administrators (BA) Full Access; Interactive Users (IU) Read/Write
        # Network users (NU) have NO access.
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
                MAX_IPC_MESSAGE_SIZE,
                MAX_IPC_MESSAGE_SIZE,
                1000,
                attributes,
            )
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                _, data = win32file.ReadFile(pipe, MAX_IPC_MESSAGE_SIZE)
                if data:
                    try:
                        req_obj = decode_request(data)
                        response = dispatch_request(self.secret, req_obj, self.handlers, self.replay_cache)
                    except ValueError as ve:
                        response = {"ok": False, "error": str(ve)}
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

    def __init__(self, secret: Optional[bytes] = None, pipe_name: str = NamedPipeServer.PIPE_NAME):
        self.secret = secret
        self.pipe_name = pipe_name

    def call(self, operation: str, payload: Any = None, timeout_s: float = 3.0) -> Dict[str, Any]:
        """Calls a named pipe operation with appropriate tier authorization and replay token."""
        req: Dict[str, Any] = {
            "operation": operation,
            "payload": payload,
        }

        # If calling a privileged mutation, generate replay-protected token
        if operation in PRIVILEGED_OPERATIONS:
            if not self.secret:
                return {
                    "ok": False,
                    "error": "Administrative elevation required: privileged secret not accessible to unelevated process."
                }
            now = time.time()
            nonce = secrets.token_hex(16)
            token = make_auth_token(self.secret, operation, payload, timestamp=now, nonce=nonce)
            req["timestamp"] = now
            req["nonce"] = nonce
            req["token"] = token
        elif self.secret:
            # Optionally attach token for read-only operations if secret is available
            req["token"] = make_auth_token(self.secret, operation, payload)

        try:
            req_bytes = encode_request(req)
        except ValueError as ve:
            return {"ok": False, "error": str(ve)}

        try:
            import win32file

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
                _, resp_bytes = win32file.ReadFile(handle, MAX_IPC_MESSAGE_SIZE)
                return json.loads(resp_bytes.decode("utf-8").strip())
            finally:
                win32file.CloseHandle(handle)
        except Exception as exc:
            return {"ok": False, "error": f"IPC communication failed: {exc}"}
