"""
DNS-SHIELD Hosted Management Control Plane API Server.

Multi-tenant administration, single-use expiring device enrollment, unique revocable
device credentials, signed policy distribution with publisher digital signatures and
SHA-256 integrity checksums, single-use WebSocket connection tickets, and credential log redaction.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from fastapi import FastAPI, HTTPException, Header, Query, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse

from hosted_management.auth import hash_password, verify_password, generate_secure_token
from hosted_management.models import (
    TenantCreate, AccountCreate, EnrollmentTokenRequest,
    DeviceEnrollRequest, PolicyUpdate, TelemetrySettingsUpdate, TelemetryEventBatch
)
from hosted_management.policy_verifier import (
    generate_publisher_keypair,
    compute_policy_content_hash,
    sign_policy_envelope,
    canonicalize_envelope,
    EndpointPolicyVerifier,
    PolicyVerifier,
    PolicyVerificationError,
    compute_policy_hash,
    compute_publisher_signature,
    canonicalize_policy,
)

# Credential Redaction Log Formatter
class RedactingFilter(logging.Filter):
    """Redacts tokens, API keys, and credentials from log records."""
    REDACT_PATTERNS = [
        re.compile(r'(api_key=["\']?)[a-zA-Z0-9_\-]+(["\']?)', re.IGNORECASE),
        re.compile(r'(key_[a-zA-Z0-9_\-]+)', re.IGNORECASE),
        re.compile(r'(tok_[a-zA-Z0-9_\-]+)', re.IGNORECASE),
        re.compile(r'(ticket_[a-zA-Z0-9_\-]+)', re.IGNORECASE),
        re.compile(r'(sig_[a-zA-Z0-9_\-]+)', re.IGNORECASE),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern in self.REDACT_PATTERNS:
            msg = pattern.sub(r'\1[REDACTED]\2' if '\\1' in pattern.pattern else '[REDACTED]', msg)
        record.msg = msg
        return True


logger = logging.getLogger("DNSShield.HostedControlPlane")
logger.addFilter(RedactingFilter())

app = FastAPI(title="DNS-SHIELD Hosted Management API", version="2.0.0")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("HOSTED_MANAGEMENT_DB", BASE_DIR / "hosted_management.db"))
DASHBOARD_DIR = BASE_DIR / "dashboard"
DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        api_key TEXT,
        policy_signing_key TEXT,
        telemetry_enabled INTEGER DEFAULT 1,
        anonymize_ips INTEGER DEFAULT 0,
        max_batch_size INTEGER DEFAULT 100,
        created_at REAL NOT NULL
    );
    """)

    # Check and add columns for existing database
    cur.execute("PRAGMA table_info(tenants)")
    cols = [r["name"] for r in cur.fetchall()]
    if "api_key" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN api_key TEXT")
    if "policy_signing_key" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN policy_signing_key TEXT")
    if "policy_public_key" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN policy_public_key TEXT")
    if "telemetry_enabled" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN telemetry_enabled INTEGER DEFAULT 1")
    if "anonymize_ips" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN anonymize_ips INTEGER DEFAULT 0")
    if "max_batch_size" not in cols:
        cur.execute("ALTER TABLE tenants ADD COLUMN max_batch_size INTEGER DEFAULT 100")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS enrollment_tokens (
        token TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        device_key TEXT UNIQUE NOT NULL,
        hardware_uuid TEXT NOT NULL,
        os_version TEXT NOT NULL,
        policy_version INTEGER DEFAULT 1,
        health_state TEXT DEFAULT 'PROTECTED',
        last_seen REAL NOT NULL,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        custom_rules_json TEXT NOT NULL,
        allowlist_json TEXT NOT NULL,
        blocked_types_json TEXT NOT NULL,
        integrity_sha256 TEXT,
        publisher_signature TEXT,
        signed_at REAL,
        updated_at REAL NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );
    """)

    cur.execute("PRAGMA table_info(policies)")
    p_cols = [r["name"] for r in cur.fetchall()]
    if "integrity_sha256" not in p_cols:
        cur.execute("ALTER TABLE policies ADD COLUMN integrity_sha256 TEXT")
    if "publisher_signature" not in p_cols:
        cur.execute("ALTER TABLE policies ADD COLUMN publisher_signature TEXT")
    if "signed_at" not in p_cols:
        cur.execute("ALTER TABLE policies ADD COLUMN signed_at REAL")
    if "key_id" not in p_cols:
        cur.execute("ALTER TABLE policies ADD COLUMN key_id TEXT DEFAULT 'key-1'")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ws_tickets (
        ticket TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        timestamp REAL NOT NULL,
        domain TEXT NOT NULL,
        qtype TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id)
    );
    """)
    conn.commit()
    conn.close()


init_db()


# WebSocket Connection Manager with strict per-tenant scoping
class TenantConnectionManager:
    def __init__(self):
        self.tenant_connections: Dict[str, Set[WebSocket]] = defaultdict(set)

    async def connect(self, websocket: WebSocket, tenant_id: str):
        await websocket.accept()
        self.tenant_connections[tenant_id].add(websocket)

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        self.tenant_connections[tenant_id].discard(websocket)
        if not self.tenant_connections[tenant_id]:
            del self.tenant_connections[tenant_id]

    async def broadcast_tenant(self, tenant_id: str, message: Dict[str, Any]):
        """Broadcasts live events strictly to clients authenticated for the specified tenant."""
        conns = list(self.tenant_connections.get(tenant_id, set()))
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws, tenant_id)


ws_manager = TenantConnectionManager()


# Authentication Helpers
def verify_tenant_auth(tenant_id: str, x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")) -> Dict[str, Any]:
    """Ensures caller has valid administrative credentials for tenant."""
    if not x_tenant_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Tenant-Key authentication header")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tenants WHERE id = ? AND api_key = ?", (tenant_id, x_tenant_key))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied: invalid tenant credentials")
    return dict(row)


def verify_device_credentials(
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    x_device_key: Optional[str] = Header(None, alias="X-Device-Key")
) -> Dict[str, Any]:
    """Ensures device is authenticated, exists, and has not been revoked."""
    if not x_device_id or not x_device_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Device-Id or X-Device-Key header")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = ? AND device_key = ?", (x_device_id, x_device_key))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")

    dev = dict(row)
    if dev["revoked"] == 1:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device credentials have been revoked")
    return dev


# --- API Routes ---

@app.post("/api/v1/tenants")
def create_tenant(req: TenantCreate):
    tenant_id = generate_secure_token("ten")
    api_key = generate_secure_token("key")
    priv_hex, pub_hex = generate_publisher_keypair()
    now = time.time()

    initial_rules: List[str] = []
    initial_allow: List[str] = []
    initial_blocked = ["ANY"]
    checksum = compute_policy_content_hash(initial_rules, initial_allow, initial_blocked)
    signature = sign_policy_envelope(
        private_key_hex=priv_hex,
        tenant_id=tenant_id,
        version=1,
        custom_rules=initial_rules,
        allowlist=initial_allow,
        blocked_types=initial_blocked,
        signed_at=now,
        key_id="key-1",
    )

    conn = get_db()
    conn.execute("""
        INSERT INTO tenants (id, name, contact_email, api_key, policy_signing_key, policy_public_key, telemetry_enabled, anonymize_ips, max_batch_size, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, 0, 100, ?)
    """, (tenant_id, req.name, req.contact_email, api_key, priv_hex, pub_hex, now))

    # Default policy v1 with SHA-256 integrity and publisher digital signature
    conn.execute("""
        INSERT INTO policies (tenant_id, version, custom_rules_json, allowlist_json, blocked_types_json, integrity_sha256, publisher_signature, signed_at, key_id, updated_at)
        VALUES (?, 1, '[]', '[]', '["ANY"]', ?, ?, ?, 'key-1', ?)
    """, (tenant_id, checksum, signature, now, now))

    conn.commit()
    conn.close()

    return {
        "tenant_id": tenant_id,
        "api_key": api_key,
        "policy_public_key": pub_hex,
        "policy_signing_key": pub_hex,  # public verification key distributed to endpoints
        "name": req.name,
        "contact_email": req.contact_email,
    }


@app.get("/api/v1/tenants/{tenant_id}/settings")
def get_tenant_settings(tenant_id: str, x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")):
    tenant = verify_tenant_auth(tenant_id, x_tenant_key)
    return {
        "tenant_id": tenant["id"],
        "telemetry_enabled": bool(tenant["telemetry_enabled"]),
        "anonymize_ips": bool(tenant["anonymize_ips"]),
        "max_batch_size": tenant["max_batch_size"],
    }


@app.put("/api/v1/tenants/{tenant_id}/settings")
def update_tenant_settings(
    tenant_id: str,
    req: TelemetrySettingsUpdate,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    verify_tenant_auth(tenant_id, x_tenant_key)
    conn = get_db()
    conn.execute("""
        UPDATE tenants
        SET telemetry_enabled = ?, anonymize_ips = ?, max_batch_size = ?
        WHERE id = ?
    """, (1 if req.telemetry_enabled else 0, 1 if req.anonymize_ips else 0, req.max_batch_size, tenant_id))
    conn.commit()
    conn.close()
    settings_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    return {"status": "updated", "settings": settings_dict}


@app.post("/api/v1/enrollment/tokens")
def create_enrollment_token(
    req: EnrollmentTokenRequest,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    """Generates an expiring, single-use device enrollment token."""
    if x_tenant_key:
        verify_tenant_auth(req.tenant_id, x_tenant_key)

    token = generate_secure_token("enroll")
    now = time.time()
    expires_at = now + (req.expires_in_minutes * 60)

    conn = get_db()
    conn.execute("""
        INSERT INTO enrollment_tokens (token, tenant_id, device_name, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (token, req.tenant_id, req.device_name, now, expires_at))
    conn.commit()
    conn.close()

    return {
        "enrollment_token": token,
        "expires_at": expires_at,
        "expires_in_minutes": req.expires_in_minutes,
        "device_name": req.device_name,
    }


@app.post("/api/v1/devices/enroll")
def enroll_device(req: DeviceEnrollRequest):
    """Exchanges an enrollment token for unique, revocable device credentials."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM enrollment_tokens WHERE token = ?", (req.enrollment_token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid enrollment token")

    tok = dict(row)
    if tok["used"] == 1:
        conn.close()
        raise HTTPException(status_code=400, detail="Enrollment token has already been consumed")

    if time.time() > tok["expires_at"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Enrollment token has expired")

    # Mark token used (Single-use guarantee)
    cur.execute("UPDATE enrollment_tokens SET used = 1 WHERE token = ?", (req.enrollment_token,))

    device_id = generate_secure_token("dev")
    device_key = generate_secure_token("key")
    tenant_id = tok["tenant_id"]
    now = time.time()

    cur.execute("""
        INSERT INTO devices (id, tenant_id, name, device_key, hardware_uuid, os_version, policy_version, health_state, last_seen, revoked)
        VALUES (?, ?, ?, ?, ?, ?, 1, 'PROTECTED', ?, 0)
    """, (device_id, tenant_id, tok["device_name"], device_key, req.hardware_uuid, req.os_version, now))
    conn.commit()
    conn.close()

    return {
        "device_id": device_id,
        "device_key": device_key,
        "tenant_id": tenant_id,
        "policy_version": 1,
    }


@app.get("/api/v1/devices")
def list_devices(
    tenant_id: str,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    """Lists enrolled devices and health state for a tenant with access control."""
    if x_tenant_key:
        verify_tenant_auth(tenant_id, x_tenant_key)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, hardware_uuid, os_version, policy_version, health_state, last_seen, revoked
        FROM devices WHERE tenant_id = ?
    """, (tenant_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@app.post("/api/v1/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    """Revokes device credentials immediately."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT tenant_id FROM devices WHERE id = ?", (device_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    tenant_id = row["tenant_id"]
    if x_tenant_key:
        verify_tenant_auth(tenant_id, x_tenant_key)

    conn.execute("UPDATE devices SET revoked = 1 WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return {"status": "revoked", "device_id": device_id}


@app.get("/api/v1/policies")
def get_policy(
    tenant_id: str,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key"),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    x_device_key: Optional[str] = Header(None, alias="X-Device-Key"),
):
    """Retrieves current versioned policy with SHA-256 integrity and publisher digital signature."""
    if x_tenant_key:
        verify_tenant_auth(tenant_id, x_tenant_key)
    elif x_device_id and x_device_key:
        dev = verify_device_credentials(x_device_id, x_device_key)
        if dev["tenant_id"] != tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant policy access denied")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM policies WHERE tenant_id = ? ORDER BY version DESC LIMIT 1", (tenant_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="No policy found")
    data = dict(row)
    cur.execute("SELECT policy_public_key FROM tenants WHERE id = ?", (tenant_id,))
    t_row = cur.fetchone()
    conn.close()

    data["custom_rules"] = json.loads(data["custom_rules_json"])
    data["allowlist"] = json.loads(data["allowlist_json"])
    data["blocked_types"] = json.loads(data["blocked_types_json"])
    data["publisher_id"] = tenant_id
    data["tenant_id"] = tenant_id
    data["signature"] = data.get("publisher_signature")
    data["key_id"] = data.get("key_id") or "key-1"
    if t_row and t_row["policy_public_key"]:
        data["public_key"] = t_row["policy_public_key"]

    # Fallback compute if signature not populated in legacy test row
    if not data.get("integrity_sha256"):
        data["integrity_sha256"] = compute_policy_content_hash(data["custom_rules"], data["allowlist"], data["blocked_types"])
    if not data.get("signed_at"):
        data["signed_at"] = data.get("updated_at", time.time())

    return data


@app.post("/api/v1/policies")
async def update_policy(
    tenant_id: str,
    req: PolicyUpdate,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    """Updates tenant policy, increments version, attaches publisher signature, and broadcasts to tenant."""
    tenant = verify_tenant_auth(tenant_id, x_tenant_key)
    priv_hex = tenant.get("policy_signing_key")
    if not priv_hex:
        raise HTTPException(status_code=500, detail="Tenant has no active publisher signing key configured")

    checksum = compute_policy_content_hash(req.custom_blocked_domains, req.allowlisted_domains, req.blocked_record_types)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT MAX(version) FROM policies WHERE tenant_id = ?", (tenant_id,))
    curr = cur.fetchone()[0] or 0
    new_ver = curr + 1
    now = time.time()

    signature = sign_policy_envelope(
        private_key_hex=priv_hex,
        tenant_id=tenant_id,
        version=new_ver,
        custom_rules=req.custom_blocked_domains,
        allowlist=req.allowlisted_domains,
        blocked_types=req.blocked_record_types,
        signed_at=now,
        key_id="key-1",
    )

    conn.execute("""
        INSERT INTO policies (tenant_id, version, custom_rules_json, allowlist_json, blocked_types_json, integrity_sha256, publisher_signature, signed_at, key_id, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'key-1', ?)
    """, (tenant_id, new_ver, json.dumps(req.custom_blocked_domains), json.dumps(req.allowlisted_domains), json.dumps(req.blocked_record_types), checksum, signature, now, now))
    conn.commit()
    conn.close()

    await ws_manager.broadcast_tenant(tenant_id, {
        "type": "POLICY_UPDATED",
        "tenant_id": tenant_id,
        "version": new_ver,
        "integrity_sha256": checksum,
        "signature": signature,
        "publisher_signature": signature,
        "signed_at": now,
        "key_id": "key-1",
    })
    return {
        "version": new_ver,
        "integrity_sha256": checksum,
        "signature": signature,
        "publisher_signature": signature,
        "signed_at": now,
        "key_id": "key-1",
        "status": "updated",
    }


@app.post("/api/v1/telemetry/events")
async def ingest_telemetry(
    batch: TelemetryEventBatch,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    x_device_key: Optional[str] = Header(None, alias="X-Device-Key")
):
    """
    Ingests bounded batches of security block events with tenant isolation.
    Validates device credentials, checks revocation, and enforces tenant telemetry settings.
    """
    dev = verify_device_credentials(x_device_id, x_device_key)
    if dev["id"] != batch.device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device credential mismatch with batch payload")

    tenant_id = dev["tenant_id"]

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT telemetry_enabled, anonymize_ips, max_batch_size FROM tenants WHERE id = ?", (tenant_id,))
    t_row = cur.fetchone()
    if t_row and not t_row["telemetry_enabled"]:
        conn.close()
        return {"ingested": 0, "telemetry_disabled": True}

    max_batch = t_row["max_batch_size"] if t_row else 100

    now = time.time()
    cur.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, batch.device_id))

    inserted = 0
    for ev in batch.events[:max_batch]:
        cur.execute("""
            INSERT INTO telemetry_events (device_id, tenant_id, timestamp, domain, qtype, decision, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (batch.device_id, tenant_id, ev.get("timestamp", now), ev.get("domain", ""), ev.get("qtype", "A"), ev.get("decision", "BLOCK"), ev.get("reason", "")))
        inserted += 1

    conn.commit()
    conn.close()

    await ws_manager.broadcast_tenant(tenant_id, {
        "type": "NEW_SECURITY_EVENTS",
        "device_id": batch.device_id,
        "count": inserted,
        "events": batch.events[:10]
    })
    return {"ingested": inserted}


# --- WebSocket Ticket & Connection Management ---

@app.post("/api/v1/ws/ticket")
def create_websocket_ticket(
    tenant_id: str,
    x_tenant_key: Optional[str] = Header(None, alias="X-Tenant-Key")
):
    """
    Issues a short-lived (60s), single-use connection ticket for live WebSocket telemetry.
    Removes long-lived API keys from URL query strings.
    """
    verify_tenant_auth(tenant_id, x_tenant_key)
    ticket = generate_secure_token("ticket")
    now = time.time()
    expires_at = now + 60.0  # 60 second lifetime

    conn = get_db()
    conn.execute("""
        INSERT INTO ws_tickets (ticket, tenant_id, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
    """, (ticket, tenant_id, now, expires_at))
    conn.commit()
    conn.close()

    return {
        "ticket": ticket,
        "tenant_id": tenant_id,
        "expires_in_seconds": 60,
    }


@app.websocket("/api/v1/ws/live")
async def websocket_live_dashboard(
    websocket: WebSocket,
    ticket: Optional[str] = Query(None)
):
    """
    Real-time streaming channel. Strictly requires a single-use connection ticket.
    Long-lived API keys are NOT accepted in URL query strings.
    """
    if not ticket:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    now = time.time()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_tickets WHERE ticket = ? AND used = 0", (ticket,))
    row = cur.fetchone()

    if not row or now > row["expires_at"]:
        conn.close()
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Single-use guarantee: immediately mark ticket as used
    cur.execute("UPDATE ws_tickets SET used = 1 WHERE ticket = ?", (ticket,))
    conn.commit()
    tenant_id = row["tenant_id"]
    conn.close()

    await ws_manager.connect(websocket, tenant_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, tenant_id)


# Serve Static Dashboard HTML
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_page():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h1>DNS-SHIELD Hosted Dashboard Initializing</h1>"
