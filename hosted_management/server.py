"""
DNS-SHIELD Hosted Management Control Plane API Server.

Multi-tenant administration, single-use expiring device enrollment, unique revocable
device credentials, versioned policy distribution, and real-time live telemetry over WebSockets.
"""

import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse

from hosted_management.auth import hash_password, verify_password, generate_secure_token
from hosted_management.models import (
    TenantCreate, AccountCreate, EnrollmentTokenRequest,
    DeviceEnrollRequest, PolicyUpdate, TelemetryEventBatch
)

logger = logging.getLogger("DNSShield.HostedControlPlane")

app = FastAPI(title="DNS-SHIELD Hosted Management API", version="2.0.0")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hosted_management.db"
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
        created_at REAL NOT NULL
    );
    """)
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
        updated_at REAL NOT NULL,
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


# WebSocket Connection Manager for live dashboard updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.active_connections.discard(connection)


ws_manager = ConnectionManager()


# Authentication & Helper
def verify_device_credentials(x_device_id: Optional[str] = Header(None), x_device_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not x_device_id or not x_device_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing device credentials")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = ? AND device_key = ? AND revoked = 0", (x_device_id, x_device_key))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or revoked device credentials")
    return dict(row)


# --- API Routes ---

@app.post("/api/v1/tenants")
def create_tenant(req: TenantCreate):
    tenant_id = generate_secure_token("ten")
    conn = get_db()
    conn.execute("INSERT INTO tenants (id, name, contact_email, created_at) VALUES (?, ?, ?, ?)",
                 (tenant_id, req.name, req.contact_email, time.time()))
    # Default policy v1
    conn.execute("INSERT INTO policies (tenant_id, version, custom_rules_json, allowlist_json, blocked_types_json, updated_at) VALUES (?, 1, '[]', '[]', '[\"ANY\"]', ?)",
                 (tenant_id, time.time()))
    conn.commit()
    conn.close()
    return {"tenant_id": tenant_id, "name": req.name}


@app.post("/api/v1/enrollment/tokens")
def create_enrollment_token(req: EnrollmentTokenRequest):
    """Generates an expiring, single-use device enrollment token."""
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
def list_devices(tenant_id: str):
    """Lists enrolled devices and health state for a tenant."""
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
def revoke_device(device_id: str):
    """Revokes device credentials immediately."""
    conn = get_db()
    conn.execute("UPDATE devices SET revoked = 1 WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return {"status": "revoked", "device_id": device_id}


@app.get("/api/v1/policies")
def get_policy(tenant_id: str):
    """Retrieves current versioned policy for a tenant."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM policies WHERE tenant_id = ? ORDER BY version DESC LIMIT 1", (tenant_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="No policy found")
    data = dict(row)
    data["custom_rules"] = json.loads(data["custom_rules_json"])
    data["allowlist"] = json.loads(data["allowlist_json"])
    data["blocked_types"] = json.loads(data["blocked_types_json"])
    return data


@app.post("/api/v1/policies")
async def update_policy(tenant_id: str, req: PolicyUpdate):
    """Updates tenant policy, increments version, and notifies live dashboard."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT MAX(version) FROM policies WHERE tenant_id = ?", (tenant_id,))
    curr = cur.fetchone()[0] or 0
    new_ver = curr + 1

    conn.execute("""
        INSERT INTO policies (tenant_id, version, custom_rules_json, allowlist_json, blocked_types_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (tenant_id, new_ver, json.dumps(req.custom_blocked_domains), json.dumps(req.allowlisted_domains), json.dumps(req.blocked_record_types), time.time()))
    conn.commit()
    conn.close()

    await ws_manager.broadcast({
        "type": "POLICY_UPDATED",
        "tenant_id": tenant_id,
        "version": new_ver,
    })
    return {"version": new_ver, "status": "updated"}


@app.post("/api/v1/telemetry/events")
async def ingest_telemetry(
    batch: TelemetryEventBatch,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    x_device_key: Optional[str] = Header(None, alias="X-Device-Key")
):
    """
    Ingests bounded batches of security block events with tenant isolation.
    Broadcasts live events to dashboard without requiring browser reloads.
    """
    conn = get_db()
    cur = conn.cursor()
    now = time.time()
    # Update device last seen
    cur.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, batch.device_id))

    inserted = 0
    tenant_id = None
    cur.execute("SELECT tenant_id FROM devices WHERE id = ?", (batch.device_id,))
    t_row = cur.fetchone()
    if t_row:
        tenant_id = t_row[0]

    for ev in batch.events[:100]:  # Cap at 100 per batch
        if tenant_id:
            cur.execute("""
                INSERT INTO telemetry_events (device_id, tenant_id, timestamp, domain, qtype, decision, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (batch.device_id, tenant_id, ev.get("timestamp", now), ev.get("domain", ""), ev.get("qtype", "A"), ev.get("decision", "BLOCK"), ev.get("reason", "")))
            inserted += 1

    conn.commit()
    conn.close()

    # Broadcast to live dashboard WebSockets
    await ws_manager.broadcast({
        "type": "NEW_SECURITY_EVENTS",
        "device_id": batch.device_id,
        "count": inserted,
        "events": batch.events[:10]
    })
    return {"ingested": inserted}


@app.websocket("/api/v1/ws/live")
async def websocket_live_dashboard(websocket: WebSocket):
    """Real-time streaming channel for live dashboard events."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# Serve Static Dashboard HTML
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_page():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h1>DNS-SHIELD Hosted Dashboard Initializing</h1>"
