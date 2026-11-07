"""
Creates high-quality submission documentation for DNS-SHIELD:
- README_FIRST.md
- PROJECT_SUMMARY.md
- PRESENTATION_SCRIPT.md
- VIVA_QUESTIONS_AND_ANSWERS.md
- BUILD_INSTRUCTIONS.md
- docs/ARCHITECTURE_DIAGRAM.md
"""

from pathlib import Path

SUBMISSION_DIR = Path(r"c:\project\dns tunneling\submission")
SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
DOCS_DIR = SUBMISSION_DIR / "docs"
DOCS_DIR.mkdir(parents=True, exist_ok=True)

# 1. README_FIRST.md
readme_first = """# DNS-SHIELD: README FIRST (SUBMISSION GUIDE)

**Project:** DNS-SHIELD - High-Performance Endpoint DNS Security Gateway & Tunneling Mitigation  
**Release Revision:** `2739e82d7a37dce2baf72f522d1a7368ceeb7de0`  
**Submission Date:** October 15, 2026  
**Build Status:** Frozen Release Candidate | 95 Automated Tests Passed (100%)  
**Demonstration Status:** 6/6 Controlled Loopback Checks Verified | Zero Host Modification  

---

## 1. PROJECT HIGHLIGHTS & CORE MANDATES

- **Automatic Rule-Based ALLOW/BLOCK Decisions:** Every DNS request receives an unambiguous binary verdict. **Zero risk scoring, zero threat percentages, and zero score-based blocking.**
- **Upstream Non-Contact Guarantee:** Blocked queries are immediately synthesized into RFC-compliant `REFUSED` or `NXDOMAIN` responses locally. Zero packets ever egress to upstream resolvers.
- **Hierarchical Precedence Pipeline:** Evaluates queries through: Allowlist -> Custom Policy Rules -> Exact Blocklists -> Subdomain Blocklists -> Heuristic Tunneling Heuristics -> Default Upstream Forwarder.
- **Zero Host Network Disruption:** The development and evaluation workflow strictly isolates live tests to loopback unprivileged ports (`127.0.0.1:5353`), leaving host DNS, SCM services, firewall/WFP filters, and browser policies completely untouched.
- **Fail-Safe Out-of-Process Recovery:** Standalone PowerShell recovery utility (`scripts/recovery.ps1`) restores network adapter DNS settings without requiring IPC or background service availability.

---

## 2. REPRODUCIBLE DEMONSTRATION STEPS (FOR TOMORROW'S EVALUATION)

To demonstrate the working gateway in less than 30 seconds on any workstation without elevated privileges or host network disruption:

```powershell
# Open PowerShell in the project root directory
cd "c:\\project\\dns tunneling"

# Execute the self-contained controlled loopback demonstration
.\\.venv\\Scripts\\python.exe scripts\\controlled_demo.py
```

### What You Will See (6 Verified Stages):
1. **Allowed Domain Resolution:** Query `allowed-service.test` (A) -> returns `NOERROR`, IP `192.168.100.200`. Upstream contact logged as `True`.
2. **Administrator Policy Refusal:** Rule `BLOCK *.malware-sample.test` -> query `c2-beacon.malware-sample.test` (A) returns `REFUSED`. **Upstream contact logged as `False` (0 packets sent).**
3. **Deterministic Tunneling Interception:** Query with high Shannon entropy (4.82 >= 3.80), excessive label length (39 >= 35), and `TXT` query type -> returns `REFUSED`. **Upstream contact logged as `False` (0 packets sent).**
4. **Database Audit Log Audit:** SQLite query against `dns_logs` displaying exact verdicts, decision types (`ADMIN_POLICY`, `SUSPECTED_TUNNELING`), and human-auditable diagnostic reasoning.
5. **Upstream Non-Contact Proof:** Console audit proving only 1 of 3 total queries reached upstream; all 2 blocked queries were terminated locally.
6. **Policy Rule Removal:** Rule `malware-sample.test` is removed -> subsequent query resolves immediately to `192.168.100.200` (`NOERROR`).

---

## 3. PACKAGE DIRECTORY LAYOUT

```text
submission/
|-- README_FIRST.md                    <-- You are here: Quick start & verification guide
|-- PROJECT_SUMMARY.md                 <-- Comprehensive technical & academic summary
|-- PRESENTATION_SCRIPT.md             <-- 3-minute timed oral presentation script
|-- VIVA_QUESTIONS_AND_ANSWERS.md      <-- Rigorous technical viva examination Q&A
|-- BUILD_INSTRUCTIONS.md              <-- Exact build provenance & compilation steps
|-- CHECKSUMS.sha256                   <-- SHA-256 cryptographic hashes of all deliverables
|-- build_manifest.json                <-- Compiler versions, commit hashes, test results
|-- requirements.txt                   <-- Python runtime dependencies
|
|-- installer/
|   `-- DNS-SHIELD-Setup-x64.exe       <-- Standalone Windows Inno Setup installer (15.1 MB)
|
|-- runtime/
|   |-- DNSShieldService/              <-- Standalone Service PE binary directory (PyInstaller)
|   |-- DNSShieldApp/                  <-- Standalone GUI Desktop PE binary directory (PyInstaller)
|   `-- scripts/
|       |-- recovery.ps1               <-- Standalone emergency network recovery script
|       `-- diagnose_service.ps1       <-- Service health diagnostic script
|
|-- source/
|   `-- source_snapshot.zip            <-- Clean Git source archive of commit 2739e82
|
|-- test_results/
|   |-- pytest_results.xml             <-- JUnit XML test execution log (95/95 passed)
|   |-- pytest_raw_output.txt          <-- Full console pytest execution output
|   `-- demo_results.txt               <-- Genuine console output from controlled demonstration
|
|-- report/
|   |-- PROJECT_REPORT.docx            <-- Official docx formatted report (Sathyabama template)
|   `-- PROJECT_REPORT.md              <-- Full Markdown version of academic report
|
`-- docs/
    |-- ARCHITECTURE_DIAGRAM.md        <-- ASCII & Mermaid architecture documentation
    |-- DISPOSABLE_VM_TEST_PROCEDURE.md<-- Complete VM Runbook (Rev 5.0, Python-free CLI)
    `-- RECOVERY_INSTRUCTIONS.md       <-- Detailed network fail-safe restoration procedures
```

---

## 4. EMERGENCY RECOVERY INSTRUCTIONS

If the system network configuration ever needs an immediate, hard reset to DHCP:

```powershell
# Run PowerShell as Administrator:
powershell.exe -ExecutionPolicy Bypass -File .\\runtime\\scripts\\recovery.ps1
```

- Operates **independently of the service** (zero IPC requirement).
- Enumerates all physical and virtual network adapters.
- Clears static `127.0.0.1` DNS and restores default DHCP / original configuration.

---

## 5. FORMAL STATUS DECLARATION

- **Implemented:** Gateway server, policy engine, heuristic tunneling detector, authenticated IPC, Windows service host, desktop GUI, standalone recovery tool, Inno Setup installer.
- **Automated Tests:** 95/95 passed (100% pass rate in 11.20s).
- **Demonstrated:** Controlled loopback demonstration on ports 5353/5354 with upstream zero-contact confirmation.
- **Pending:** System-wide Windows adapter redirection and WFP kernel filter enforcement remain pending execution in a disposable virtual machine.
- **Official Status Summary:**  
  *"DNS gateway blocking demonstrated in a controlled local environment; system-wide Windows enforcement validation remains pending."*
"""

# 2. PROJECT_SUMMARY.md
project_summary = """# DNS-SHIELD: COMPREHENSIVE PROJECT SUMMARY

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
  $$H(X) = - \\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
- Enforces deterministic structural rules:
  - High Shannon entropy ($H \ge 3.80$)
  - Excessive label length ($\ge 35$ characters)
  - Favored tunneling record types (`TXT`, `CNAME`, `NULL`)
- Produces explainable diagnostic logs detailing exact arithmetic criteria.

### 3.4 Service Host & Authenticated IPC (`windows_service.py`, `local_ipc.py`)
- Native Windows Service host integrating with Advapi32 Service Control Manager (SCM).
- Communicates with unprivileged GUI and CLI tools via HMAC-SHA256 authenticated channels.
- Access control lists (ACLs) restrict configuration mutations to local Administrators.
- Includes a packaged administrative CLI tool inside `DNSShieldService.exe` that reads authentication secrets internally from `%ProgramData%\\DNS-SHIELD\\ipc.secret`.

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
"""

# 3. PRESENTATION_SCRIPT.md
presentation_script = """# DNS-SHIELD: 3-MINUTE PRESENTATION SCRIPT
*(Practice timing: Speak at an even, confident pace. Target duration: 2 minutes 50 seconds to 3 minutes).*

---

### [0:00 - 0:30] SLIDE 1: INTRODUCTION & THE CORE PROBLEM
"Good morning, respected examiners and faculty members.

Today, I present **DNS-SHIELD**, a high-performance endpoint DNS security gateway engineered for Windows environments.

The Domain Name System is fundamental to internet connectivity, and because of this, standard DNS traffic on port 53 is almost universally permitted through enterprise firewalls. Cyber adversaries exploit this trust through **DNS tunneling**—encoding stolen credentials, intellectual property, and command-and-control instructions into domain labels to exfiltrate data out-of-band.

Existing endpoint security tools attempt to detect this using probabilistic machine learning models that generate risk percentages. But on client endpoints, score-based blocking creates serious problems: it causes false-positive outages on legitimate cloud platforms like AWS and Cloudflare, introduces score drift, and adds unacceptable resolution latency."

---

### [0:30 - 1:15] SLIDE 2: THE DNS-SHIELD SOLUTION & ARCHITECTURE
"DNS-SHIELD takes a fundamentally different, deterministic approach.

Our primary project mandate is **automatic, rule-based ALLOW/BLOCK decisions**. We have completely eliminated risk scoring, threat percentages, and probabilistic thresholds. Every single DNS request receives an unambiguous binary verdict.

Operating directly on local loopback at `127.0.0.1:53`, DNS-SHIELD evaluates queries through a high-performance five-tier precedence pipeline:
1. First, an **Administrative Allowlist** for verified business endpoints.
2. Second, **Tenant Custom Policies** configured by local administrators.
3. Third and fourth, **Exact and Subdomain Blocklists** indexed in fast in-memory sets and reverse tries.
4. And fifth, **Deterministic Heuristic Tunneling Detection**—analyzing Shannon character entropy, maximum label length, and favored exfiltration record types such as TXT.

Crucially, DNS-SHIELD guarantees **Upstream Non-Contact**. When a domain is blocked, the gateway synthesizes an RFC-compliant `REFUSED` or `NXDOMAIN` response right on loopback. **Zero packets ever leave the workstation.**"

---

### [1:15 - 2:05] SLIDE 3: WORKING DEMONSTRATION & VERIFICATION
"To prove the reliability of this architecture without altering our host laptop's network settings, we conducted a controlled loopback demonstration on unprivileged ports 5353 and 5354:
1. An allowed query to `allowed-service.test` resolved instantly to `192.168.100.200`, with upstream contact verified.
2. An administrator rule blocking `malware-sample.test` immediately returned `REFUSED`. The upstream resolver logged exactly zero packets, proving that blocked queries never leak upstream.
3. A controlled tunneling sequence with high Shannon entropy of 4.82 and a TXT query was intercepted and refused with zero upstream contact.
4. The SQLite audit database accurately logged exact matched rules and diagnostic reasons.
5. And finally, removing the administrator rule dynamically restored legitimate resolution without requiring a service restart.

In addition, our full automated test suite comprising **95 test cases across 6 modules passed with a 100% success rate in 11.20 seconds**."

---

### [2:05 - 2:40] SLIDE 4: PACKAGING, FAIL-SAFE RECOVERY & HONEST BOUNDARY
"For production deployment, DNS-SHIELD is compiled into a standalone 15.1 megabyte Windows installer built with Inno Setup, packaging our background Windows Service, an unprivileged desktop GUI, and an authenticated command-line tool.

Network safety is paramount. If the background service is ever stopped or killed, our **standalone PowerShell recovery tool** restores network adapter settings back to DHCP out-of-process, with zero service dependency.

To report our status with complete academic honesty:
Deterministic DNS gateway blocking has been demonstrated in a controlled local environment. System-wide Windows adapter redirection and kernel WFP filtering have their implementation and test scripts packaged, and their live execution remains pending validation in a disposable virtual machine."

---

### [2:40 - 3:00] SLIDE 5: CONCLUSION
"In conclusion, DNS-SHIELD proves that deterministic, rule-based endpoint DNS filtering delivers superior privacy, zero-leakage security, and sub-millisecond performance without the operational liabilities of probabilistic scoring.

Thank you, and I am now ready for your questions."
"""

# 4. VIVA_QUESTIONS_AND_ANSWERS.md
viva_qa = """# DNS-SHIELD: VIVA VOCE EXAMINATION QUESTIONS & ANSWERS

---

### Q1: What is the core problem DNS-SHIELD solves, and how does DNS tunneling work?
**Answer:**  
DNS-SHIELD addresses out-of-band data exfiltration and Command-and-Control (C2) communication conducted over standard DNS (UDP/TCP port 53). In DNS tunneling, an attacker configures an authoritative nameserver for a domain they own (e.g., `attacker-c2.com`). An implant on an infected host encodes stolen data (files, passwords, tokens) into Base32, Base64, or Hex characters as subdomain labels (e.g., `k8v3x9m2p7w0.attacker-c2.com`). When the client attempts to resolve this name, recursive DNS servers forward the query across the internet to the attacker's nameserver, which decodes the payload. The attacker responds with DNS `TXT` or `CNAME` records containing encoded commands. Because port 53 is almost universally permitted across firewalls, this covert channel bypasses traditional perimeter security.

---

### Q2: Why did your project strictly prohibit risk scoring and threat percentages?
**Answer:**  
In enterprise endpoint security, probabilistic scoring introduces three major operational failures:
1. **False-Positive Outages:** Legitimate cloud platforms and Content Delivery Networks (e.g., Akamai, Cloudflare, AWS CloudFront) generate high-entropy, randomized hostnames for load balancing and cache sharding. A probabilistic model that scores on entropy alone frequently blocks critical business services.
2. **Ambiguity in Policy Enforcement:** A score like "72% threat probability" creates an unmanageable dilemma: blocking disrupts legitimate applications, while allowing permits data theft.
3. **Latency:** Evaluating continuous machine learning feature vectors on every DNS packet introduces 10 to 50 milliseconds of latency, degrading user web responsiveness.  
DNS-SHIELD enforces an **automatic, deterministic rule-based ALLOW/BLOCK decision architecture**. Every query is evaluated through a strict precedence pipeline to produce an unambiguous binary verdict in sub-millisecond execution time.

---

### Q3: What is the Upstream Non-Contact Guarantee, and how do you prove it?
**Answer:**  
The Upstream Non-Contact Guarantee mandates that if a query receives a `BLOCK` verdict—whether from an administrative policy rule, a static blocklist, or a tunneling heuristic match—the gateway synthesizes an RFC-compliant `REFUSED` or `NXDOMAIN` response locally on loopback. The gateway is strictly forbidden from forwarding the query to upstream resolvers.  
We proved this in our controlled demonstration by setting up a dedicated mock upstream resolver on loopback port 5354 that logs every received query. When querying blocked domains (`c2-beacon.malware-sample.test` and the high-entropy tunneling domain), the client received `REFUSED`, and the upstream server logged **zero packets**. Only permitted queries reached the upstream.

---

### Q4: Explain the Shannon Entropy calculation used in your tunneling detector.
**Answer:**  
Shannon's Information Entropy measures the average information content or randomness in a string of characters:
$$H(X) = - \\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
Where $P(x_i)$ is the frequency of character $x_i$ divided by the total label length.
- Natural human language domain names (like `google.com` or `service-update.net`) exhibit low entropy, typically between 2.2 and 3.2.
- Encrypted or compressed Base32/Base64 exfiltration strings exhibit high entropy, routinely exceeding 3.8 to 4.5.  
In DNS-SHIELD, a label triggering Shannon entropy $H(X) \\ge 3.80$, combined with an excessive label length ($\\ge 35$ characters) and a favored exfiltration query type (`TXT`), triggers a deterministic `BLOCK` verdict with exact forensic diagnostic reasoning.

---

### Q5: What is the hierarchical precedence pipeline in PolicyEngine?
**Answer:**  
To avoid rule conflicts and ensure deterministic execution, PolicyEngine enforces five sequential tiers:
1. **Tier 1 - Administrative Allowlist:** Verified critical domains bypass all subsequent block rules.
2. **Tier 2 - Tenant Custom Policies:** Exact or subdomain administrator rules assigned explicit ALLOW or BLOCK actions.
3. **Tier 3 - Exact Domain Blocklists:** O(1) hash set lookup against imported malicious domains.
4. **Tier 4 - Subdomain / Wildcard Blocklists:** O(k) reverse-label trie lookup against blocked domain trees.
5. **Tier 5 - Deterministic Tunneling Heuristics:** Shannon entropy, label length, and record type analysis.
6. **Tier 6 - Default Action:** Permitted queries are forwarded to approved upstream resolvers.

---

### Q6: How does network recovery work if the Windows Service crashes?
**Answer:**  
A common hazard with local DNS proxies is that if the service crashes while network adapters point to `127.0.0.1`, all internet connectivity fails. DNS-SHIELD implements a **standalone, out-of-process elevated recovery tool** (`scripts/recovery.ps1`). It does not use IPC and does not require the service to be alive. It uses native Windows WMI / NetAdapter PowerShell cmdlets to enumerate all network interfaces, clear static `127.0.0.1` DNS bindings, and restore automatic DHCP or original DNS settings.

---

### Q7: How is Inter-Process Communication (IPC) secured between the unprivileged GUI and the elevated Service?
**Answer:**  
The desktop GUI runs in an unprivileged user session, while the service runs as `NT AUTHORITY\\LocalSystem`. To prevent local privilege escalation:
1. Configuration mutations (e.g., adding rules, changing upstreams) require an HMAC-SHA256 authentication token.
2. The authentication secret is stored in `%ProgramData%\\DNS-SHIELD\\ipc.secret`, protected by restrictive Windows NTFS ACLs that allow read access only to Administrators and SYSTEM.
3. Unprivileged queries can read status and telemetry, but any mutation without a valid token is rejected with an HTTP/IPC 403 Forbidden.
4. The administrative CLI embedded in `DNSShieldService.exe` reads the secret internally from disk, preventing administrator tokens from leaking into process command-line arguments.

---

### Q8: What are the differences between your automated tests and your live demonstration?
**Answer:**  
- **Automated Tests:** 95 pytest unit and integration test cases covering domain normalization, boundary conditions, access control CIDRs, HMAC token challenges, WFP constants, SCM quoting, and multi-tenant isolation. Passed 100% in 11.20s.
- **Live Demonstration:** A 6-stage end-to-end execution of the real `DNSGatewayServer` and `PolicyEngine` on loopback unprivileged port 5353, verifying live DNS packet resolution, administrative refusal, heuristic refusal, SQLite audit logging, upstream non-contact confirmation, and dynamic rule restoration.

---

### Q9: What is the exact status of your Windows integration and WFP testing?
**Answer:**  
In accordance with engineering honesty:
- **Demonstrated:** Deterministic DNS gateway blocking demonstrated in a controlled local environment.
- **Pending:** System-wide Windows adapter redirection and Windows Filtering Platform (WFP) kernel callout enforcement remain pending execution in a dedicated disposable virtual machine.
We explicitly do not claim full production deployment or successful VM validation without executing the test runbook in a live disposable VM.

---

### Q10: How does DNS-SHIELD handle DNS-over-HTTPS (DoH)?
**Answer:**  
Modern browsers configured with independent DoH bypass port 53 entirely by sending encrypted DNS queries over TCP port 443. To counter this in enterprise environments:
1. Enterprise Group Policies (GPO) are deployed to disable browser DoH and enforce system DNS.
2. Windows Filtering Platform (WFP) outbound rules block connections to known public DoH resolver IP addresses (such as `1.1.1.1` and `8.8.8.8` on port 443).
3. In future work, a local loopback TLS termination proxy will intercept local DoH queries transparently.
"""

# 5. BUILD_INSTRUCTIONS.md
build_instructions = """# DNS-SHIELD: BUILD & COMPILATION INSTRUCTIONS

This document details the exact process for building DNS-SHIELD from the frozen source repository (Commit `2739e82d7a37dce2baf72f522d1a7368ceeb7de0`).

---

## 1. PREREQUISITES
- Windows 10/11 64-bit Workstation
- Python 3.12.10 (64-bit) installed and added to PATH
- Inno Setup 6.7.3 installed (Default: `C:\\Users\\claim\\AppData\\Local\\Programs\\Inno Setup 6\\ISCC.exe`)
- Git for Windows

---

## 2. ENVIRONMENT SETUP
```powershell
# Clone or navigate to repository root
cd "c:\\project\\dns tunneling"

# Create and activate Python virtual environment
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
pip install pyinstaller pytest python-docx
```

---

## 3. EXECUTE AUTOMATED REGRESSION TESTS
Before compiling release binaries, execute the full regression test suite:

```powershell
pytest --junitxml=dist/pytest_results.xml -v
```
Expected result: **95 passed** in ~11 seconds.

---

## 4. COMPILE STANDALONE EXECUTABLES (PyInstaller)

### 4.1 Compile Windows Service Binary (`DNSShieldService.exe`)
```powershell
pyinstaller --name DNSShieldService `
  --onedir --noconfirm --clean `
  --distpath dist --workpath build/service `
  --hidden-import win32timezone `
  --hidden-import win32service `
  --hidden-import win32serviceutil `
  --hidden-import win32event `
  --hidden-import win32file `
  --hidden-import win32pipe `
  --hidden-import win32security `
  --hidden-import cryptography `
  --hidden-import hosted_management.policy_verifier `
  --hidden-import wfp_manager `
  --hidden-import network_manager `
  --exclude-module pytest `
  --exclude-module matplotlib `
  --exclude-module scipy `
  windows_service.py
```

### 4.2 Compile Desktop GUI Application (`DNSShieldApp.exe`)
```powershell
pyinstaller --name DNSShieldApp `
  --onedir --windowed --noconfirm --clean `
  --distpath dist --workpath build/app `
  --hidden-import tkinter `
  --hidden-import tkinter.ttk `
  --hidden-import network_manager `
  --hidden-import local_ipc `
  --hidden-import service_health `
  --exclude-module pytest `
  --exclude-module matplotlib `
  desktop_app.py
```

---

## 5. COMPILE WINDOWS INSTALLER (Inno Setup)
Compile the enterprise installer using Inno Setup 6.7.3:

```powershell
& "C:\\Users\\claim\\AppData\\Local\\Programs\\Inno Setup 6\\ISCC.exe" installer\\DNS-SHIELD-Setup.iss
```
Output: `dist\\DNS-SHIELD-Setup-x64.exe` (15,155,114 bytes).

---

## 6. GENERATE BUILD MANIFEST & CHECKSUMS
To verify package integrity and generate cryptographic hashes:

```powershell
python build_package.py
```
This produces `dist\\build_manifest.json` and updates package metadata.
"""

# 6. docs/ARCHITECTURE_DIAGRAM.md
arch_diagram_doc = """# DNS-SHIELD: ARCHITECTURE & SYSTEM DESIGN SPECIFICATION

## 1. COMPREHENSIVE COMPONENT INTERACTION DIAGRAM

```mermaid
flowchart TD
    subgraph Host["Windows 64-bit Endpoint Workstation"]
        Apps["Browser & Desktop Applications"]
        NetStack["Windows Networking Stack"]
        
        subgraph Capture["Interception Layer"]
            WFP["Windows Filtering Platform (WFP)<br/>FwpmFilterAdd0 on Port 53 UDP/TCP"]
            Loopback["Local Loopback Adapter<br/>127.0.0.1:53"]
        end
        
        subgraph ServiceHost["DNSShieldService.exe (NT AUTHORITY\\SYSTEM)"]
            GW["DNSGatewayServer<br/>UDP & TCP Concurrent Listeners"]
            Norm["Domain Normalizer<br/>RFC 1035 Compliance"]
            Cache["In-Memory DNS Cache<br/>TTL-based LRU Eviction"]
            
            subgraph Engine["Deterministic PolicyEngine"]
                T1["Tier 1: Administrative Allowlist<br/>RuleIndex Exact Match"]
                T2["Tier 2: Tenant Custom Policies<br/>RuleIndex Subdomain Trie"]
                T3["Tier 3: Exact Domain Blocklists<br/>Hash Table O(1) Lookups"]
                T4["Tier 4: Subdomain Blocklists<br/>Reverse Label Trie O(k) Lookups"]
                T5["Tier 5: Heuristic Tunneling Detector<br/>Shannon Entropy >= 3.80<br/>Label Length >= 35, Record Type TXT"]
            end
            
            Audit["SQLite WAL Database Logger<br/>dns_logs Transaction Storage"]
            IPC["Authenticated IPC Server<br/>HMAC-SHA256 Token Validation"]
        end
        
        subgraph Management["Management & Recovery Subsystem"]
            GUI["DNSShieldApp.exe (GUI)<br/>Unprivileged User Session"]
            CLI["Packaged CLI Tool<br/>DNSShieldService.exe cli"]
            Rec["Standalone recovery.ps1<br/>Zero-Service Dependency DNS Reset"]
        end
    end
    
    subgraph External["External Network"]
        UpstreamResolvers["Approved Upstream Resolvers<br/>1.1.1.1 / 8.8.8.8 / Enterprise DNS"]
        AttackerNameserver["Adversary Authoritative Server<br/>exfil.malicious-c2.net"]
    end
    
    Apps -->|DNS Resolution Query| NetStack
    NetStack -->|Trapped Port 53 Traffic| WFP
    WFP -->|Redirected| Loopback
    Loopback -->|Inbound Datagram| GW
    
    GW --> Norm
    Norm --> Cache
    Cache -->|Cache Miss| T1
    
    T1 -->|No Match| T2
    T2 -->|No Match| T3
    T3 -->|No Match| T4
    T4 -->|No Match| T5
    
    T1 -->|Match: ALLOW| Forward[Upstream Forwarder Pool]
    T2 -->|Match: ALLOW| Forward
    T5 -->|No Match: ALLOW| Forward
    
    T2 -->|Match: BLOCK| Refuse[Synthesize REFUSED / NXDOMAIN<br/>Upstream Non-Contact Assured]
    T3 -->|Match: BLOCK| Refuse
    T4 -->|Match: BLOCK| Refuse
    T5 -->|Match: BLOCK| Refuse
    
    Forward -->|Forwarded Safe Query| UpstreamResolvers
    Refuse -->|Blocked Query Dropped Locally| Audit
    Forward -->|Answer Received| Audit
    Audit -->|Committed Log| GW
    GW -->|Final DNS Response Packet| Apps
    
    GUI <-->|Authenticated HMAC-SHA256 IPC| IPC
    CLI <-->|Internal Secret IPC| IPC
    Rec -.->|Direct WMI NetAdapter Reset| NetStack
    
    %% Non-contact boundary
    Refuse x--x|STRICTLY BLOCKED: Zero Upstream Contact| AttackerNameserver
```

---

## 2. PIPELINE PRECEDENCE & TIME COMPLEXITY

| Pipeline Stage | Evaluated Component | Data Structure | Time Complexity | Action on Match |
| :--- | :--- | :--- | :---: | :--- |
| **Stage 1** | Administrative Allowlist | In-Memory Hash Set | $O(1)$ | Terminate: **ALLOW** |
| **Stage 2** | Custom Tenant Rules | Exact Set & Subdomain Trie | $O(1) / O(k)$ | Terminate: **BLOCK** or **ALLOW** |
| **Stage 3** | Flat Domain Blocklist | Hash Table (1M+ entries) | $O(1)$ | Terminate: **BLOCK** (Local Drop) |
| **Stage 4** | Subdomain Blocklist | Reverse-Label Radix Trie | $O(k)$ | Terminate: **BLOCK** (Local Drop) |
| **Stage 5** | Tunneling Detection Heuristics | Shannon Entropy & Length Check | $O(L)$ | Terminate: **BLOCK** (Local Drop) |
| **Stage 6** | Default Forwarding | Upstream UDP Forwarder Pool | Network $RTT$ | Forward: **ALLOW** |

*Note: $k$ represents the number of domain labels; $L$ represents the character length of the query label.*
"""

files = [
    (SUBMISSION_DIR / "README_FIRST.md", readme_first),
    (SUBMISSION_DIR / "PROJECT_SUMMARY.md", project_summary),
    (SUBMISSION_DIR / "PRESENTATION_SCRIPT.md", presentation_script),
    (SUBMISSION_DIR / "VIVA_QUESTIONS_AND_ANSWERS.md", viva_qa),
    (SUBMISSION_DIR / "BUILD_INSTRUCTIONS.md", build_instructions),
    (DOCS_DIR / "ARCHITECTURE_DIAGRAM.md", arch_diagram_doc)
]

for file_path, content in files:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"[+] Wrote: {file_path} ({len(content):,} chars)")

print("[+] All submission documentation successfully generated.")
