# DNS-SHIELD: Windows Architecture & Integration Specification

**Target Platform:** Windows 11 x64 (Primary Target, Build 22000+)  
**Supported Windows Versions:** Windows 10 x64 (Version 1809+, Build 17763+), Windows 11 x64 (all versions), Windows Server 2019/2022/2025 x64.  
**Architecture:** AMD64 / x86_64 native execution.  
**Document Revision:** 2.0 (Production Architecture)

---

## 1. Executive Summary & Product Scope

DNS-SHIELD is a production-grade, deterministic DNS protection solution for Microsoft Windows. It operates as a local Windows Service Control Manager (SCM) background service that intercepts DNS resolution on the local loopback interfaces (`127.0.0.1:53` and `[::1]:53`), strictly enforcing administrator policies, threat intelligence blocklists, and DNS protocol validation.

### What DNS-SHIELD Protects
- Enforces strict deterministic **`ALLOW`** or **`BLOCK`** verdicts on all DNS traffic routed to its local resolver.
- Immediately stops DNS queries matching known malicious domains (malware distribution, phishing, Command & Control (C2) botnet infrastructure).
- Enforces administrative policies (exact domain and wildcard/subdomain restrictions).
- Blocks high-risk or prohibited DNS record types (e.g., RFC 8482 ANY mitigation against amplification abuse).
- Defends against local loopback abuse with per-client rate limiting and burst token-bucket algorithms.
- Detects suspected DNS tunneling anomalies through multi-signal heuristics over bounded time windows without unexplainable numerical risk scores.

### Explicit Non-Claims & Operational Boundaries
- **Not a General Network Firewall:** DNS-SHIELD intercepts DNS resolution only. It does not inspect direct IP-to-IP TCP/UDP socket connections made by malware without domain name resolution.
- **Encrypted DNS (DoH/DoT/DoQ) Limitations:** If an application (or rogue process) directly initiates an HTTPS connection (TCP 443) to a third-party DoH resolver bypassing operating system DNS, DNS filtering on port 53 cannot inspect TLS payload without enterprise certificate inspection. DNS-SHIELD implements Windows Group Policy and Firewall perimeter blocks against standard DoT (port 853) and public DoH endpoints where configured, but does not guarantee interception of arbitrary custom HTTPS endpoints.
- **VPN Interception:** Virtual Private Networks that configure split-tunneling or replace TAP/Wintun adapter DNS will direct resolution to the VPN gateway unless configured to preserve local DNS.
- **Local Administrator Primacy:** An elevated user with local administrative privileges can always modify adapter configuration or stop Windows services.

---

## 2. System Architecture & Data Path

```mermaid
graph TD
    subgraph "Windows Operating System"
        APP[Applications / Browsers / OS Services]
        DNS_CLIENT[Windows DNS Client Cache / Resolver]
        NET_ADAPTER[Active Network Adapters (Wi-Fi / Ethernet)]
    end

    subgraph "DNS-SHIELD Privileged Windows Service (LocalSystem)"
        SVC_LISTENER[Dual-Stack Listener (127.0.0.1:53 & [::1]:53 UDP/TCP)]
        POLICY_ENGINE[Deterministic Policy Engine]
        MEM_CACHE[Bounded LRU Cache (TTL Respecting)]
        TUNNEL_DETECTOR[Explainable Tunneling Detector]
        UPSTREAM[Validated Upstream Forwarder (1.1.1.1 / 8.8.8.8 / 9.9.9.9)]
        PIPE_SERVER[Authenticated Named Pipe Server (\\.\pipe\DNSShield)]
        SECURE_STORE[(%ProgramData%\DNS-SHIELD\dns_gateway.db)]
    end

    subgraph "Unelevated User Session"
        DESKTOP_UI[DNS-SHIELD Desktop Control App (Native Win32/Tk)]
        TRAY[Windows System Tray Notification & Status]
    end

    subgraph "External Network"
        UPSTREAM_RESOLVERS[Approved Upstream Resolvers (Port 53 UDP/TCP)]
    end

    APP -->|getaddrinfo()| DNS_CLIENT
    DNS_CLIENT -->|Queries via Adapter DNS| NET_ADAPTER
    NET_ADAPTER -->|Configured Loopback 127.0.0.1:53| SVC_LISTENER
    SVC_LISTENER --> POLICY_ENGINE
    
    POLICY_ENGINE -->|1. Protocol & Syntax Validation| POLICY_ENGINE
    POLICY_ENGINE -->|2. Access Control / CIDR Check| POLICY_ENGINE
    POLICY_ENGINE -->|3. Rate Limiter| POLICY_ENGINE
    POLICY_ENGINE -->|4. Allowlist Match| UPSTREAM
    POLICY_ENGINE -->|5. Custom Rules / Threat Feeds / Blocked Types| BLOCKED_RESP[Deterministic BLOCK (REFUSED / NXDOMAIN)]
    POLICY_ENGINE -->|6. Tunneling Heuristic Check| TUNNEL_DETECTOR
    
    POLICY_ENGINE -->|7. Check Cache| MEM_CACHE
    POLICY_ENGINE -->|8. Forward if Uncached| UPSTREAM
    UPSTREAM -->|Validated Forwarding & ID Match| UPSTREAM_RESOLVERS
    
    POLICY_ENGINE -->|Audit Logging & Events| SECURE_STORE
    
    DESKTOP_UI <-->|Authenticated Local IPC (HMAC-SHA256 Token)| PIPE_SERVER
    DESKTOP_UI --> TRAY
```

---

## 3. Trust Boundaries & Privileged Components

| Component | Execution Context | Integrity Level | Responsibilities | Security Controls |
|---|---|---|---|---|
| **Windows Service (`DNSShieldService`)** | `NT AUTHORITY\System` (or dedicated service account) | System Integrity | Binds ports 53, manages adapter DNS configuration, loads threat databases, evaluates DNS policy, writes audit logs. | Isolated from user sessions; accepts commands only through authenticated Named Pipe; rejects arbitrary execution. |
| **Local IPC Transport** | Windows Named Pipe (`\\.\pipe\DNSShield`) | System to Medium Integrity | Transports control requests between Desktop App and Windows Service. | Explicit DACL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` allowing interactive users to connect; HMAC-SHA256 authenticated request messages. |
| **Desktop Application (`DNSShieldApp`)** | Interactive User | Medium Integrity (Unelevated) | Renders UI, displays live events, triggers enable/disable, manages custom allow/block rules, exports diagnostics. | Unelevated execution; no direct raw socket or SCM manipulation; redacts all secrets during diagnostics export. |
| **Upstream DNS Servers** | Remote Internet Hosts | Untrusted External | Resolves allowed public domain queries. | Queries must match transaction IDs, question name and type; timeouts produce `SERVFAIL`; no synthesized records. |

---

## 4. Local IPC Authentication Protocol

The Desktop Application communicates with the background service via Windows Named Pipe:
- **Pipe Path:** `\\.\pipe\DNSShield`
- **Security Descriptor:**
  ```sddl
  D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
  ```
  Grants `Generic All` to `SYSTEM` and `Administrators`, and `Generic Read/Write` to `Interactive Users`.
- **Authentication Scheme:**
  1. During service installation, a 32-byte cryptographic secret is generated and stored in `%ProgramData%\DNS-SHIELD\ipc.secret` with NTFS ACLs restricting read/write to `SYSTEM` and `Administrators`.
  2. For authorized users, an authentication token is computed per request using HMAC-SHA256:
     $$\text{Token} = \text{HMAC-SHA256}(\text{Secret}, \text{JSON}(\text{operation}, \text{payload}))$$
  3. The request format is strictly typed JSON:
     ```json
     {
       "operation": "set_enabled",
       "payload": {"enabled": true},
       "token": "<hmac_sha256_hex_digest>"
     }
     ```
  4. The service validates the HMAC token using constant-time comparison before dispatching the operation.
- **Allowed Operations (Strictly Enumerated):**
  - `get_status`: Returns health state, engine ready flags, and adapter routing status.
  - `get_events`: Returns recent query audit events (max 500 records).
  - `set_enabled`: Atomically enables or disables DNS protection and adapter routing.
  - `diagnostics`: Returns system health diagnostics with secrets redacted.
  - `get_rules`: Returns list of custom rules, allowlist, and blocklist sources.
  - `add_rule`, `delete_rule`: Adds or deletes custom domain rules.
  - `add_allowlist`, `delete_allowlist`: Adds or deletes allowlist exemptions.
  - `restore_network`: Emergency rollback of all adapter DNS modifications.
  *Notice:* Arbitrary command execution or path specification is strictly rejected.

---

## 5. Storage Architecture & Restrictive Permissions

All persistent service state is stored machine-wide under `%ProgramData%\DNS-SHIELD`:
- `C:\ProgramData\DNS-SHIELD\dns_gateway.db` — SQLite database (audit logs, custom rules, allowlist, blocklist feeds).
- `C:\ProgramData\DNS-SHIELD\ipc.secret` — 32-byte local IPC authentication secret.
- `C:\ProgramData\DNS-SHIELD\service.log` — Service operational log file.
- `C:\ProgramData\DNS-SHIELD\dns_backup.json` — Transactional snapshot of network adapter configurations prior to mutation.

### Filesystem Permissions (NTFS ACLs)
The service programmatically applies restrictive NTFS security descriptors using `win32security`:
- **Owner:** `Administrators`
- **Inheritance:** Disabled (`PROTECTED_DACL_SECURITY_INFORMATION`).
- **Access Control Entries (ACEs):**
  - `NT AUTHORITY\SYSTEM`: Full Control (`FILE_ALL_ACCESS`)
  - `BUILTIN\Administrators`: Full Control (`FILE_ALL_ACCESS`)
  - Standard non-admin interactive users: Denied read/write access to `ipc.secret` and raw databases.

---

## 6. Service Health State Machine

The service evaluates system health dynamically:

| State | Definition & Conditions | User Guidance |
|---|---|---|
| **`PROTECTED`** | All required conditions met: UDP/TCP listeners bound on port 53; policy engine loaded; upstream connectivity verified; active network adapter DNS verified to route to loopback. | Protection active. DNS queries are filtered deterministically. |
| **`DEGRADED`** | Service process is active, but one or more enforcement checks fail: e.g., upstream resolver down, or network adapter DNS was reverted or altered by external software. | Warning displayed. Detail specifies failing component. |
| **`DISABLED`** | Protection intentionally deactivated by user. Adapters restored to original DHCP/static DNS. | Protection paused. DNS bypasses the gateway. |
| **`ERROR`** | Critical initialization failure: socket bind conflict on port 53, database corruption, or permission error. | Error alert with diagnosis and recovery steps. |

*Critical Guarantee:* Process liveness is never equated with protection status. If port 53 listener is active but the network adapter points elsewhere, the state is immediately flagged as **`DEGRADED`**.

---

## 7. Windows DNS Integration & Transactional Recovery

### Pre-Flight Verification
Before altering network adapter DNS:
1. Probe local listener on `127.0.0.1:53` and `[::1]:53`.
2. Confirm test domain resolution through local listener.
3. Confirm test blocked domain is refused locally without touching upstream.
4. Detect port conflicts (e.g., Internet Connection Sharing, third-party DNS tools).

### Transactional Configuration Protocol
1. Query active network adapters using PowerShell / Win32 IP Helper API (`iphlpapi.dll`).
2. Filter for physical adapters with active default gateways (`NdisPhysicalMediumUnspecified` / `NdisPhysicalMediumNative802_11` / `NdisPhysicalMedium802_3`). Exclude virtual adapters (Hyper-V, WSL, Docker, VMware).
3. Record exact original configuration to `%ProgramData%\DNS-SHIELD\dns_backup.json`:
   - Adapter GUID & Interface Alias.
   - IPv4 DNS mode: `DHCP` vs `Static`.
   - IPv4 DNS Server List (e.g., `["192.168.1.1"]`).
   - IPv6 DNS mode: `DHCP` vs `Static`.
   - IPv6 DNS Server List.
4. Atomically persist backup file to disk before mutating any interface.
5. Apply loopback DNS (`netsh interface ipv4 set dns name="..." static 127.0.0.1 primary` and `netsh interface ipv6 set dns name="..." static ::1 primary`).
6. Verify active DNS configuration matches loopback.

### Recovery & Rollback Scenarios
- **Normal Disable:** Restores adapters to exact saved state in `dns_backup.json` (switching back to DHCP or restoring static addresses).
- **Service Crash / Unexpected Reboot:** On startup, the service detects existing backup. If service cannot start cleanly or user requests recovery, `recovery.ps1` or Desktop App restores saved settings.
- **Uninstallation:** Uninstaller invokes `restore_dns()` before removing service registration.
- **External Configuration Conflict:** If the user or IT administrator intentionally modifies DNS settings after protection is enabled, DNS-SHIELD detects the divergence and transitions to `DEGRADED` rather than blindly clobbering the user's manual changes.
