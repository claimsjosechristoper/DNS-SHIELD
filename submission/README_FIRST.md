# DNS-SHIELD: README FIRST (SUBMISSION GUIDE)

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
cd "c:\project\dns tunneling"

# Execute the self-contained controlled loopback demonstration
.\.venv\Scripts\python.exe scripts\controlled_demo.py
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
powershell.exe -ExecutionPolicy Bypass -File .\runtime\scripts\recovery.ps1
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
