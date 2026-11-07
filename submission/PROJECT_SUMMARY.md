# DNS-SHIELD: COMPREHENSIVE PROJECT SUMMARY

## 1. PROBLEM STATEMENT
Modern cyber adversaries routinely exploit the Domain Name System (DNS) as an omnipresent covert channel. Because recursive DNS traffic (UDP/TCP port 53) is essential for internet navigation, it traverses perimeter firewalls unimpeded. Attackers leverage DNS tunneling to exfiltrate proprietary data, credentials, and Command-and-Control (C2) instructions by encoding data into domain label hierarchies.

Traditional endpoint solutions rely on:
- **Perimeter sinkholes / RPZ:** Blind to direct unmonitored connections and dynamic tunneling subdomains.
- **Cloud-based recursive resolvers (Cisco Umbrella, Cloudflare Zero Trust):** Introduce WAN latency (15-40ms), expose private enterprise DNS telemetry, and transmit exfiltrated data across the internet before blocking can occur.
- **Machine Learning / Risk-Scoring Engines:** Output probabilistic scores (e.g., "78% risk"), creating fatal operational liabilities: false-positive disruption of legitimate cloud services (CDN randomized hostnames), threshold drift, and lack of explainability.

---

## 2. PROJECT OBJECTIVES
DNS-SHIELD resolves these architectural shortcomings by providing an endpoint DNS security gateway engineered natively for 64-bit Windows workstations:
1. **Automatic Rule-Based ALLOW/BLOCK Decisions:** Absolute elimination of risk scoring, threat percentages, and score-based thresholds. Every DNS request receives an unambiguous binary verdict.
2. **Deterministic Precedence Pipeline:** Hierarchical evaluation prioritizing Administrative Allowlists -> Custom Policy Rules -> Exact Blocklists -> Subdomain Blocklists -> Deterministic Heuristic Tunneling Detection in under 2ms.
3. **Upstream Non-Contact Guarantee:** Blocked queries are immediately synthesized into RFC-compliant `REFUSED` or `NXDOMAIN` responses locally. Zero packets ever reach upstream resolvers.
4. **Cryptographic Policy Integrity & Anti-Rollback:** Tamper-resistant policy distribution with monotonic version checks rejecting stale or replayed configurations.
5. **Fail-Safe Network Resilience:** Standalone elevated recovery mechanism capable of restoring host network settings without communicating with the background service.

---

## 3. ARCHITECTURE & SUBSYSTEM MODULES

### 3.1 Gateway & Interception Layer (`gateway/server.py`, `wfp_manager.py`)
- Traps outbound DNS queries via Windows Filtering Platform (WFP) and loopback binding (`127.0.0.1:53`).
- Manages high-throughput concurrent UDP listener sockets and non-blocking TCP server loops with bounded worker pools.
- Enforces RFC 1035 compliance and domain normalization (lowercase ASCII canonicalization, trailing dot removal).

### 3.2 Deterministic Policy Engine (`gateway/policy.py`, `gateway/matcher.py`)
- Evaluates queries through an in-memory `RuleIndex` utilizing Python sets for $O(1)$ exact domain matches and dictionary-backed reversed-label tries for $O(k)$ subdomain matching.
- Implements strict hierarchical evaluation: an allowlist match immediately bypasses all subsequent block rules; an admin rule or blocklist match immediately produces a BLOCK verdict.

### 3.3 Heuristic Tunneling Detector (`detection_engine/tunneling_detector.py`)
- Computes Shannon's Information Entropy:
  $$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Enforces deterministic structural rules:
  - High Shannon entropy ($H \ge 3.80$)
  - Excessive label length ($\ge 35$ characters)
  - Favored tunneling record types (`TXT`, `CNAME`, `NULL`)
- Produces explainable diagnostic logs detailing exact arithmetic criteria.

### 3.4 Service Host & Authenticated IPC (`windows_service.py`, `local_ipc.py`)
- Native Windows Service host integrating with Advapi32 Service Control Manager (SCM).
- Communicates with unprivileged GUI and CLI tools via HMAC-SHA256 authenticated channels.
- Access control lists (ACLs) restrict configuration mutations to local Administrators.
- Includes a packaged administrative CLI tool inside `DNSShieldService.exe` that reads authentication secrets internally from `%ProgramData%\DNS-SHIELD\ipc.secret`.

### 3.5 Management Application & Standalone Recovery (`desktop_app.py`, `scripts/recovery.ps1`)
- Modern, unprivileged desktop GUI providing real-time telemetry, live query monitors, and policy management.
- Dedicated standalone PowerShell recovery script that directly invokes Windows NetAdapter cmdlets to restore DHCP DNS without service dependency.

---

## 4. WORKING PROCESS (THE PRECEDENCE PIPELINE)

```text
[ Client Application DNS Request ]
                |
                v
[ Loopback Gateway Interceptor (127.0.0.1:53) ]
                |
                +---> [ Domain Normalization & RFC Compliance Check ]
                |
                +---> [ Fast Local Cache Lookup (TTL) ]
                |            | Cache Miss
                |            v
                +---> [ Tier 1: Administrative Allowlist ] -----------> IF MATCH: ALLOW
                |            | No Match
                |            v
                +---> [ Tier 2: Tenant Custom Policies ] -------------> IF MATCH: BLOCK / ALLOW
                |            | No Match
                |            v
                +---> [ Tier 3: Exact Domain Blocklists ] ------------> IF MATCH: BLOCK
                |            | No Match
                |            v
                +---> [ Tier 4: Subdomain / Wildcard Blocklists ] ----> IF MATCH: BLOCK
                |            | No Match
                |            v
                +---> [ Tier 5: Heuristic Tunneling Detection ] ------> IF MATCH: BLOCK
                |            | No Match
                |            v
                +---> [ Tier 6: Default Forwarding Policy ] ----------> ALLOW
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
        [ BLOCK VERDICT ]                           [ ALLOW VERDICT ]
   Synthesize REFUSED / NXDOMAIN               Forward to Approved Upstream
  *ZERO Upstream Network Contact*             (1.1.1.1 / 8.8.8.8 / Custom)
               |                                           |
               +---------------------+---------------------+
                                     |
                                     v
                  [ SQLite WAL Database Audit Logger ]
```

---

## 5. TESTING & VERIFICATION RESULTS

### 5.1 Automated Regression Testing (pytest)
- **Total Test Cases:** 95
- **Passed:** 95 (100% pass rate)
- **Failed:** 0
- **Duration:** 11.20 seconds
- **Key Suites:** API endpoints (8), Detection heuristics & exceptions (8), Encoder/decoders (4), Gateway core & hardening (18), Hosted multi-tenant security (7), Installer & SCM quoting (2), IPC security (3), Windows Service foundation (15), WFP hardening (12), Integration flows (15).

### 5.2 Controlled Demonstration Verification (6 Checks)
1. **Allowed Query:** `allowed-service.test` -> resolved to `192.168.100.200` (`NOERROR`). Upstream contacted = `True`.
2. **Admin Policy Block:** `*.malware-sample.test` -> returned `REFUSED`. **Upstream contacted = `False` (0 pkts).**
3. **Tunneling Heuristic Block:** High-entropy Base32 `TXT` query -> returned `REFUSED`. **Upstream contacted = `False` (0 pkts).**
4. **Audit Trail Verification:** Exact verdicts, decision types, and forensic reasoning recorded in SQLite `dns_logs`.
5. **Zero-Contact Audit:** Upstream received 1 allowed query; 0 blocked queries reached upstream.
6. **Policy Rule Removal:** Rule deleted -> `c2-beacon.malware-sample.test` immediately resolved to `192.168.100.200` (`NOERROR`).

---

## 6. PACKAGING & BUILD PROVENANCE
- **Git Commit Hash:** `2739e82d7a37dce2baf72f522d1a7368ceeb7de0`
- **Final Installer:** `dist/DNS-SHIELD-Setup-x64.exe` (15,155,114 bytes)  
  SHA-256: `bb4de84678201d5f7955c42bd1d90071f699ff57916b8f0187b6a596ae08de22`
- **Service Executable:** `dist/DNSShieldService/DNSShieldService.exe` (3,611,938 bytes)  
  SHA-256: `7007fb11288e3f36334d124935f4e0c0d97e7b1dab0c831f3ed81395ca9d03a1`
- **Desktop Application:** `dist/DNSShieldApp/DNSShieldApp.exe` (1,856,077 bytes)  
  SHA-256: `92357121c4e691d0a944295b6c2463dfa59f528a4702075d5fb218d868088a2f`

---

## 7. IDENTIFIED LIMITATIONS & ENGINEERING BOUNDARIES
1. **Host Safety Constraint:** Live demonstration conducted on loopback unprivileged port 5353 to ensure zero disruption to the host development workstation.
2. **Browser DoH Bypass:** Applications using independent DNS-over-HTTPS bypass local port 53. Enterprise group policies (GPO) are required to disable browser DoH and block external DoH IPs via WFP.
3. **Ultra-Low-Throughput Drip Tunneling:** Queries spaced across hours/days require long-term historical baseline logging.

---

## 8. FUTURE WORK
1. **VM Runbook Execution:** Executing `docs/DISPOSABLE_VM_TEST_PROCEDURE.md` in a clean disposable VM to validate system-wide adapter redirection and WFP kernel filters.
2. **Loopback DoH Proxy:** Embedding a local TLS termination proxy to transparently intercept browser HTTPS DNS queries.
3. **Kernel WFP Driver:** Transitioning user-mode ctypes bindings into a signed kernel-mode WFP callout driver.
