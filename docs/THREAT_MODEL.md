# DNS-SHIELD: Threat Model & Risk Analysis

**Document Revision:** 1.0  
**Scope:** Windows 11 x64 DNS Protection Service & Desktop Application  
**Framework:** STRIDE-based Threat Modeling

---

## 1. System Overview & Assets

### Protected Assets
1. **DNS Decision Integrity:** The assurance that DNS requests are evaluated strictly against active administrative and threat policies without unauthorized tampering or bypass.
2. **Local Machine Connectivity:** Normal network browsing and resolution must not be broken or trapped in an unrecoverable state upon crash or reboot.
3. **Audit History & Privacy:** Local DNS logs containing private domain queries and IP endpoints must not be readable by unprivileged local accounts or leaked externally without explicit telemetry consent.
4. **Local Administrative Secrets:** IPC tokens, database keys, and configuration secrets must remain confidential.
5. **System Resource Stability:** Sockets, threads, memory, and disk files must remain strictly bounded against algorithmic or volumetric exhaustion.

---

## 2. Threat Boundaries & STRIDE Analysis

```
+-------------------------------------------------------------------------------+
| User Session (Medium Integrity)                                               |
|                                                                               |
|  [DNSShield Desktop Application]  <---+                                       |
|  [Third-Party Applications]           | (Local Named Pipe Transport)          |
|  [Unprivileged Malware]               |                                       |
+---------------------------------------|---------------------------------------+
| Local IPC Trust Boundary              v                                       |
|  \\.\pipe\DNSShield (DACL: SYSTEM, Administrators Full; Users Read/Write)     |
+-------------------------------------------------------------------------------+
| System Session (System Integrity)                                             |
|                                                                               |
|  [DNSShield Service]                                                          |
|    - Dual-Stack Listener (127.0.0.1:53 / [::1]:53)                            |
|    - Policy Engine (Deterministic ALLOW/BLOCK)                                |
|    - SQLite Audit Store (%ProgramData%\DNS-SHIELD\dns_gateway.db)             |
+-------------------------------------------------------------------------------+
| Network Perimeter Trust Boundary                                              |
|                                                                               |
|  [Outbound UDP/TCP Port 53 / 853] ---> [Public Upstream Resolvers]            |
+-------------------------------------------------------------------------------+
```

### STRIDE Assessment Matrix

| Threat Category | Threat Description | Attack Vector | Severity | Mitigations Implemented |
|---|---|---|---|---|
| **Spoofing (Identity)** | Unauthorized local process sends spoofed management commands to change filtering policies. | Connecting to local IPC and sending unauthenticated control requests. | **High** | 1. Windows Named Pipe DACL allows connection, but every privileged operation requires an HMAC-SHA256 signature calculated with a 32-byte secret stored in `%ProgramData%\DNS-SHIELD\ipc.secret`.<br>2. File permissions restrict secret access to SYSTEM and local Administrators.<br>3. Constant-time comparison defends against timing attacks. |
| **Tampering (Data)** | DNS cache poisoning or forged upstream responses. | Upstream response injection or collision attacks on transaction IDs. | **High** | 1. Gateway validates upstream transaction ID matching.<br>2. Verifies question name (`q.qname`) and query type (`q.qtype`) match the original query.<br>3. Mismatched responses or unexpected IDs are discarded with SERVFAIL.<br>4. Policy checks ALWAYS precede cache lookups so updated rules cannot be bypassed by existing cached items. |
| **Repudiation** | Administrator or malware denies altering policy rules or modifying DNS configuration. | Unauthorized rule deletion or malicious allowlist insertion. | **Medium** | 1. Full administrative audit trail logged to `audit_logs` table with timestamps, actions, targets, and user details.<br>2. Database protected by SYSTEM/Admin-only NTFS permissions. |
| **Information Disclosure** | Unprivileged local users read browsing history or secrets. | Reading SQLite database or IPC secret file directly from disk. | **High** | 1. `%ProgramData%\DNS-SHIELD` protected with inheritance disabled; standard users have no read access to `ipc.secret` or database files.<br>2. Service diagnostics export explicitly redacts secrets and sensitive keys.<br>3. No API keys or passwords logged to console or `service.log`. |
| **Denial of Service** | Volumetric query flooding, memory exhaustion, or thread exhaustion. | Malicious local software floods port 53 with rapid DNS queries or jumbo payloads. | **High** | 1. Shared bounded worker pool (`max_workers=64`) prevents unbounded thread creation.<br>2. Token-bucket rate limiter enforces per-client requests per minute (RPM) and burst thresholds.<br>3. Packet size strictly capped (4096 UDP, 65535 TCP).<br>4. Bounded LRU cache (10,000 entries max) with automatic eviction prevents memory leak. |
| **Elevation of Privilege** | Local command injection or file path traversal via IPC. | Attacker passes malicious payloads in IPC requests. | **Critical** | 1. Narrow, strictly typed IPC operation whitelist: `ALLOWED_OPERATIONS = frozenset({'get_status', 'get_events', 'set_enabled', 'diagnostics', 'get_rules', 'add_rule', 'delete_rule', 'add_allowlist', 'delete_allowlist', 'restore_network'})`.<br>2. No arbitrary command execution, no shell invocation, no arbitrary file path acceptance from IPC. |

---

## 3. Bypass Vectors & Documented Limitations

### 1. Direct Outbound IP Connections (No DNS)
- **Threat:** Malware contacts a command and control server directly by raw IPv4/IPv6 address (e.g. `connect("198.51.100.24", 443)`).
- **Status:** **Out of Scope for DNS Filtering.** DNS-SHIELD does not act as a full network layer SPI firewall or TLS inspector. Documented clearly to prevent false security expectations.

### 2. Direct External Port 53 Bypass
- **Threat:** Malicious process ignores system DNS settings and crafts raw UDP/TCP packets directly to external resolvers (e.g. `8.8.8.8:53`).
- **Mitigation:** Optional Windows Firewall rule blocking outbound UDP/TCP 53 for all processes except the DNS-SHIELD service binary.

### 3. Encrypted DNS Bypass (DNS over HTTPS / DoH)
- **Threat:** Browser (Chrome, Firefox, Edge) or custom application uses built-in DoH over TCP 443 directly to Cloudflare, Google, or Quad9.
- **Mitigation:**
  - Standard DoT (TCP 853) and DoQ (UDP 853) can be blocked via Windows Firewall.
  - For browsers, enterprise policies (Group Policy / Registry) disable DoH fallback (`DnsOverHttpsMode = "off"`).
  - Arbitrary custom HTTPS DoH endpoints cannot be distinguished from standard HTTPS traffic without full SSL/TLS interception (which introduces major certificate and privacy implications).

### 4. Virtual Private Networks (VPN)
- **Threat:** Enterprise or third-party VPN client establishes a virtual network adapter and forces DNS through the VPN tunnel.
- **Handling:** DNS-SHIELD selectively binds physical adapters (Ethernet, Wi-Fi) and detects adapter changes, alerting the user to `DEGRADED` state if routing is overridden by a VPN interface.
