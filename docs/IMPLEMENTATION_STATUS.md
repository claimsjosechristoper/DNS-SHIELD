# DNS-SHIELD: Honest Implementation & Verification Status Matrix

**Document Revision:** 2.2 (Release Candidate Status)  
**Last Updated:** 2026-10-14  
**Source Revision (Git):** `c46239042eccfd815f02be3aaa843cdc46474868`  
**Target Platform:** Windows 11 x64 (Build 22000+) / Windows 10 x64 (1809+)

---

## 1. Verification Classification Taxonomy

To ensure intellectual honesty and prevent treating mocked or dry-run validation as live OS enforcement, capabilities are evaluated under four mutually distinct levels:

1. **Implemented:** Source code and architecture written and present in repository.
2. **Automated-Test Verified:** Verified via isolated automated test suites (`pytest`) under simulated wire packets, loopback sockets, temporary databases, and mock interfaces.
3. **Windows-Integration Verified:** Tested live on a Windows operating system against genuine OS APIs (Win32 APIs, Named Pipes, Registry, NTFS DACLs).
4. **VM Integration Testing:** Marked **NOT RUN** because no isolated disposable Windows VM is available on this build machine. Protection was strictly **not** activated on the host laptop.

---

## 2. Capability Evidence Matrix

| Phase | Component / Capability | Status Classification | Evidence Artifacts | Classification Rationale & Technical Boundaries |
|---|---|---|---|---|
| **Phase 1** | Windows Architecture & Threat Model | **Implemented** | `docs/WINDOWS_ARCHITECTURE.md`<br>`docs/THREAT_MODEL.md` | Non-claims explicit: no direct-IP filtering, no generic packet inspection. |
| **Phase 2** | Dual-Stack Loopback UDP/TCP Listener | **Automated-Test Verified** | `gateway/server.py`<br>`tests/test_gateway_hardening.py` | Verified loopback binding, 2-byte prefix stream framing, and TCP reassembly in unit tests. |
| **Phase 2** | Upstream DNS Forwarding & Validation | **Automated-Test Verified** | `gateway/upstream.py`<br>`tests/test_gateway_hardening.py` | Transaction ID randomization, QR bit validation, and question matching verified. |
| **Phase 2** | Bounded DNS Cache with LRU & TTL | **Automated-Test Verified** | `gateway/cache.py`<br>`tests/test_gateway.py` | Bounded capacity (10k), TTL expiration, and domain invalidation on policy reloads verified. |
| **Phase 2** | DNS Domain Normalization | **Automated-Test Verified** | `gateway/normalization.py`<br>`tests/test_gateway_hardening.py` | RFC 1035 syntax check, RFC 2181 underscore preservation (`_dmarc`, `_tcp`, `_udp`). |
| **Phase 3** | SCM Service Architecture & Registration | **Implemented** | `windows_service.py` | `pywin32` ServiceFramework class defined with service recovery and stop handlers. **Host laptop activation prevented.** |
| **Phase 3** | NTFS DACL Storage Protection | **Windows-Integration Verified** | `windows_service.py`<br>`local_ipc.py` | Verified Win32 programmatic DACL setting SYSTEM and Administrators Full Access. |
| **Phase 3** | Two-Tier Local Named Pipe IPC | **Automated-Test Verified** | `local_ipc.py`<br>`tests/test_ipc_security.py` | **Conflict Resolved:** Unelevated GUI granted read-only status access without admin secret; privileged mutations require admin HMAC-SHA256, timestamp freshness ($\pm 60$s), and replay-cache nonces; 64 KB message limits enforced. |
| **Phase 3** | Protection Health State Machine | **Automated-Test Verified** | `service_health.py`<br>`tests/test_service_foundation.py` | 4 distinct states (`PROTECTED`, `DEGRADED`, `DISABLED`, `ERROR`). `PROTECTED` strictly requires listener + policy + upstream + routing. |
| **Phase 4** | Adapter Backup & Non-Destructive Recovery | **Automated-Test Verified** | `network_manager.py`<br>`scripts/recovery.ps1`<br>`tests/test_network_and_firewall.py`<br>`docs/CRASH_AND_RECOVERY_BEHAVIOR.md` | **Fixes Verified:** Preserves later administrator changes (skips adapters not on loopback); restores exact static DNS servers without defaulting static adapters to DHCP; accurately reports `DEGRADED` when adapter is trapped on loopback without active listener. |
| **Phase 5** | Native WFP Filtering Platform Implementation | **Automated-Test Verified** | `wfp_manager.py`<br>`tests/test_wfp_manager.py` | **Full SDK Implementation:** Complete ctypes structures (`FWPM_SUBLAYER0`, `FWPM_FILTER0`, `FWPM_FILTER_CONDITION0`, `FWP_VALUE0`), atomic transactions (`FwpmTransactionBegin0/Commit0/Abort0`), App ID normalization (`FwpmGetAppIdFromFileName0`), memory deallocation (`FwpmFreeMemory0`), filter enumeration (`FwpmFilterEnum0`), and sublayer weight arbitration (Loopback 100, Gateway 90, Block 10). Dynamic session auto-cleanup on crash. |
| **Phase 6** | Deterministic ALLOW/BLOCK Policy Engine | **Automated-Test Verified** | `gateway/policy.py`<br>`tests/test_gateway.py` | Strict precedence pipeline: Protocol Check -> Access CIDR -> Rate Limiting -> Allowlist -> Custom Rules -> Record Types -> Threat Feeds -> Heuristics. Zero risk scores. |
| **Phase 6** | Explainable DNS Tunneling Heuristics | **Automated-Test Verified** | `detection_engine/tunneling_detector.py`<br>`tests/test_detection_exceptions.py` | **Cloud bypass loophole closed:** Multi-tenant domains (`cloudfront.net`, `trafficmanager.net`, `amazonaws.com`) not exempt; narrow infrastructure exemptions scoped exclusively to A/AAAA lookups; TXT/NULL queries and bursts strictly enforced. |
| **Phase 6** | Blocklist Manager with LKG Fallback | **Automated-Test Verified** | `gateway/blocklist_manager.py`<br>`tests/test_gateway.py` | Retains last-known-good entries on upstream download error; file size limits enforced. |
| **Phase 7** | Native Desktop Control Center | **Implemented** | `desktop_app.py` | Native Tkinter UI supporting unelevated read-only monitoring; displays status, query audit trail, and rules; prompts for elevation on mutations. |
| **Phase 8** | Asymmetric Ed25519 Policy Authentication | **Automated-Test Verified** | `hosted_management/policy_verifier.py`<br>`hosted_management/server.py`<br>`tests/test_policy_authentication.py`<br>`tests/test_hosted_management.py`<br>`docs/POLICY_SIGNING_AND_KEY_MANAGEMENT.md` | **HMAC replaced with Ed25519:** Server retains private signing key; endpoints receive trusted public key; canonical envelope covers tenant ID, version, contents, and metadata; rollback protection persisted across restarts in SQLite; identical current policy treated as idempotent no-op; differing content under same version rejected; versioned keyring rotation supported. |
| **Phase 9** | Standalone PyInstaller Executables | **Implemented** | `dist/DNSShieldService/`<br>`dist/DNSShieldApp/` | Freshly rebuilt executables compiled in `dist/`. Service SHA-256: `B8FA3550...`, App SHA-256: `8956E675...`. |
| **Phase 9** | Inno Setup Packaging Script | **Automated-Test Verified (Compiler Missing)** | `installer/DNS-SHIELD-Setup.iss`<br>`tests/test_installer_quoting.py` | Quoted service path (`sc.exe create/config DNSShield binPath= "\"C:\Program Files\...\""` and direct `Set-ItemProperty ImagePath`). **Compiler Blocker:** `ISCC.exe` is not installed on this workstation (`"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"` missing). Standalone installer executable NOT claimed. |
| **Phase 10**| Automated Test Suite | **Automated-Test Verified** | `tests/` | **86 / 86 tests passing** across **16 test files** (100% pass rate). |

---

## 3. Fresh Build Artifact Manifest

| Artifact File | Path | Build Command | Exit Code | SHA-256 Digest |
|---|---|---|---|---|
| Service Binary | `dist\DNSShieldService\DNSShieldService.exe` | `.venv\Scripts\python.exe -m PyInstaller --name DNSShieldService ... windows_service.py` | `0` | `B8FA355099CA55C9CF621A9B467AACFDD42678F7D47F72D15946C1AC37031716` |
| Desktop App Binary | `dist\DNSShieldApp\DNSShieldApp.exe` | `.venv\Scripts\python.exe -m PyInstaller --name DNSShieldApp ... desktop_app.py` | `0` | `8956E675458310274CE5A08A2397A94825E6EBF61AD2093C948C94BFABA6C8E1` |
| Inno Setup Installer | `installer\Output\DNS-SHIELD-Setup-x64.exe` | `& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "installer\DNS-SHIELD-Setup.iss"` | `1` (CommandNotFound) | **NOT COMPILED** (ISCC compiler missing) |

---

## 4. Live Windows VM Integration Tests Status: NOT RUN

- **Rationale**: An isolated disposable Windows VM (Hyper-V / VirtualBox) is not configured on this development host. Under strict safety rules, protection was **not activated on the primary host laptop**.
- **Execution Plan**: When a disposable VM is provisioned, execute the steps in `docs/DISPOSABLE_VM_TEST_PROCEDURE.md`.
