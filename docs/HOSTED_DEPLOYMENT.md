# DNS-SHIELD: Hosted Management Deployment Guide

**Revision:** 1.0  
**Scope:** Central Cloud Control Plane Deployment & Enrollment

---

## 1. Overview

The DNS-SHIELD Hosted Management service is an optional, out-of-band administrative control plane. It enables:
- Multi-tenant device inventory.
- Single-use, expiring device enrollment tokens (15-minute validity).
- Versioned policy distribution (admin block rules, allowlists).
- Bounded ingestion of security block events with live WebSocket streaming.

**Critical Architectural Constraint:**  
Laptop DNS filtering is 100% autonomous. No cloud query is made per DNS request. The workstation continues enforcing the last valid policy if the cloud backend is offline.

---

## 2. Deployment Architecture

```
Internet / Corporate WAN
       │ (HTTPS Port 443 / WSS)
       ▼
[ Caddy / Nginx TLS Reverse Proxy ] (Let's Encrypt / Enterprise PKI)
       │ (HTTP Port 9000)
       ▼
[ DNS-SHIELD Hosted FastAPI Backend ] (hosted_management.server:app)
       │
       ▼
[ SQLite / PostgreSQL Persistent Store ] (hosted_management.db)
```

---

## 3. Quickstart Deployment (Docker)

```bash
cd hosted_management
docker compose up -d
```

The management dashboard will be available at:  
`http://localhost:9000/dashboard`

---

## 4. Production Reverse Proxy Configuration (Caddy Example)

```caddyfile
shield.yourdomain.com {
    reverse_proxy localhost:9000 {
        header_up X-Forwarded-Proto {scheme}
    }
}
```

---

## 5. Security & Secret Management

- **HTTPS Mandatory:** In production, do not expose port 9000 unencrypted. Use TLS 1.3.
- **Unique Device Keys:** Never share enrollment tokens across devices. Each device receives a unique cryptographic key upon enrollment.
- **Privacy Controls:** By default, clients only transmit events where `decision == "BLOCK"`. Full DNS browsing queries are never uploaded.
