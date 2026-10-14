# DNS-SHIELD: Disposable Windows VM Integration Validation Runbook

**Document Revision:** 5.0  
**Target Environment:** Clean Disposable Windows 11 x64 (22H2 / 23H2 / 24H2) Virtual Machine  
**Controlled Upstream Host:** Linux/BSD host with root access running `tcpdump` and a test resolver.  
**Self-Containment Guarantee:** Operates strictly using packaged binaries (`DNSShieldService.exe`, `DNSShieldApp.exe`, `recovery.ps1`). **No Python installation or repository source files required on the test VM.**  
**Safety Notice:** Run strictly inside a disposable VM. Never execute protection activation or network mutations on host developer workstations.

---

## 1. Required Files Inventory & VM Staging

Ensure the following files from the release package are staged inside the VM directory `C:\TestPackage\`:

```text
C:\TestPackage\
├── installer\
│   └── DNS-SHIELD-Setup-x64.exe   # Compiled Inno Setup installer package
├── DNSShieldService\              # Packaged service binary & administrative CLI
│   ├── DNSShieldService.exe
│   └── data\blocklists\           # Bundled blocklists
├── DNSShieldApp\                  # Packaged desktop GUI control center
│   └── DNSShieldApp.exe
├── scripts\
│   ├── recovery.ps1               # Standalone emergency network recovery script
│   └── collect_vm_evidence.ps1    # Automated diagnostic snapshot script
└── docs\
    ├── DISPOSABLE_VM_TEST_PROCEDURE.md
    └── RECOVERY_INSTRUCTIONS.md
```

---

## 2. Baseline Configuration & Upstream Dual-Protocol Capture

### Step 2.1: Record Original Network Configuration
Open an elevated PowerShell prompt on the VM and snapshot all active adapter DNS configurations:

```powershell
# Display and record baseline adapter configurations
Get-DnsClientServerAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Format-Table -AutoSize
Get-DnsClientServerAddress | Export-Clixml -Path "C:\TestPackage\baseline_dns.xml"

# Record whether adapters use DHCP or Static DNS
Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, Dhcp, ConnectionState
Get-NetIPInterface -AddressFamily IPv6 | Select-Object InterfaceAlias, Dhcp, ConnectionState
```

### Step 2.2: Start Dual-Protocol Packet Capture on Controlled Upstream
On the external upstream server (e.g., `192.168.100.1`), capture **both UDP and TCP port 53** from the VM IP:

```bash
# Real-time monitoring terminal:
sudo tcpdump -i any -n -v "(udp or tcp) port 53 and host <VM_IP_ADDRESS>" -l

# Background capture file for post-test packet correlation:
sudo tcpdump -i any -n "(udp or tcp) port 53 and host <VM_IP_ADDRESS>" -w /tmp/upstream_capture.pcap
```

---

## 3. Installation & Service Startup

### Step 3.1: Install and Start Background Service
```powershell
# 1. Register service via SCM with quoted path
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" install

# 2. Configure SCM failure recovery actions
sc.exe failure DNSShield reset= 86400 actions= restart/5000/restart/10000/restart/60000

# 3. Start service
sc.exe start DNSShield
Get-Service -Name DNSShield | Select-Object Name, Status, StartType

# 4. Verify listener on loopback port 53
Test-NetConnection -ComputerName 127.0.0.1 -Port 53
Test-NetConnection -ComputerName ::1 -Port 53
```

---

## 4. Explicit Protection Activation & System Verification

*Note: Starting the service binary does not mutate network adapters until protection is explicitly enabled.*

### Step 4.1: Explicitly Enable Protection (No Python Required)
```powershell
# Method A: Using the Packaged Administrative CLI (Reads credentials internally; no command-line secret)
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli enable-protection

# Method B: Using the Packaged Desktop Application GUI
# Launch GUI as Administrator and click 'Enable Protection':
Start-Process -FilePath "C:\TestPackage\DNSShieldApp\DNSShieldApp.exe"
```

### Step 4.2: Verify Adapter Settings & WFP Filter Installation
```powershell
# 1. Verify physical adapter IPv4 DNS now points to 127.0.0.1
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains "127.0.0.1" }

# 2. Verify physical adapter IPv6 DNS now points to ::1
Get-DnsClientServerAddress -AddressFamily IPv6 | Where-Object { $_.ServerAddresses -contains "::1" }

# 3. Export and inspect active WFP filters
netsh wfp show filters file="C:\TestPackage\wfp_filters.xml"
[xml]$wfp = Get-Content "C:\TestPackage\wfp_filters.xml"
$dnsFilters = $wfp.wfpdiag.filters.filter | Where-Object { 
    $_.displayData.name -like "*DNSShield*" -or 
    $_.displayData.name -like "*IPv4_Permit*" -or 
    $_.displayData.name -like "*IPv4_Block*" -or
    $_.displayData.name -like "*IPv6_Permit*" -or
    $_.displayData.name -like "*IPv6_Block*"
}
$dnsFilters | Select-Object filterId, @{N='Name';E={$_.displayData.name}}, action | Format-Table -AutoSize
# Expected: 8 filters registered under DNS-SHIELD sublayer
```

---

## 5. Policy Configuration: Supported Interface & Active Engine Verification

Add the controlled blocked domain `malware-sample.test` through the **supported administrative interface** without passing secrets on the process command line.

### Step 5.1: Add Block Rule via Packaged CLI or GUI
```powershell
# Method A: Packaged Administrative CLI (Reads %ProgramData%\DNS-SHIELD\ipc.secret internally)
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli add-rule malware-sample.test subdomain "Controlled Integration Test Domain"

# Method B: Desktop Application GUI
# Open GUI -> Click 'Custom Block Rules' tab -> Enter 'malware-sample.test' -> Click 'Add Block Rule'
```

### Step 5.2: Verify the Running Engine Loaded the Rule
Query active in-memory rules via the packaged CLI:

```powershell
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli get-rules
# Expected JSON output includes: "domain": "malware-sample.test"
```

---

## 6. Multi-Point Correlated Resolution Verification

We correlate three distinct observation points:
1. **Client Observation:** Known IP for allowed queries; explicit RFC `REFUSED` response for blocked queries.
2. **Gateway Observation:** Local audit table `dns_logs` records decision, rule, and timestamps.
3. **Upstream Observation:** Controlled upstream receives allowed queries, and **exactly zero queries** for blocked probes (UDP & TCP).

### Step 6.1: Configure Test Domain Probes
* **Allowed Name with Known Answer:** Use a name configured to return a known answer from the controlled upstream resolver (e.g., `allowed-site.test` returning `192.168.100.200`, or `example.com` returning `93.184.215.14`). Avoid random subdomains of unmanaged domains that return `NXDOMAIN`.
* **Blocked Name with Unique Probe Nonce:** Use a unique nonce under `malware-sample.test` (e.g., `probe-$nonce.malware-sample.test`) to allow unambiguous packet matching at the upstream capture.

```powershell
$allowedDomain = "example.com"  # Configured on controlled upstream to return valid A/AAAA records
$nonce = [Guid]::NewGuid().ToString().Substring(0, 8)
$blockedProbe = "probe-$nonce.malware-sample.test"
Write-Host "Allowed Test Domain: $allowedDomain"
Write-Host "Blocked Test Probe:  $blockedProbe"
```

### Step 6.2: Test IPv4 Resolution (Allowed vs. Blocked)
```powershell
# 1. Allowed resolution: Must resolve with valid answer (NOERROR, non-empty IP)
Resolve-DnsName -Name $allowedDomain -Server 127.0.0.1
# Expected: Returns valid IP address records with Status = Success

# 2. Blocked resolution: Client receives actual blocking response (REFUSED)
try {
    Resolve-DnsName -Name $blockedProbe -Server 127.0.0.1 -ErrorAction Stop
    Write-Host "[FAIL] Blocked probe unexpectedly resolved!" -ForegroundColor Red
} catch {
    Write-Host "[PASS] Client received refusal error: $_" -ForegroundColor Green
}

# Verify via nslookup (displays 'Query refused'):
nslookup $blockedProbe 127.0.0.1
# Expected stdout: '*** server can't find ...: Query refused'
```

### Step 6.3: Test IPv6 Resolution (Allowed vs. Blocked)
```powershell
# 1. Allowed resolution over IPv6 loopback
Resolve-DnsName -Name $allowedDomain -Server ::1
# Expected: Returns valid IP records

# 2. Blocked resolution over IPv6 loopback
try {
    Resolve-DnsName -Name $blockedProbe -Server ::1 -ErrorAction Stop
    Write-Host "[FAIL] Blocked probe unexpectedly resolved over IPv6!" -ForegroundColor Red
} catch {
    Write-Host "[PASS] Client received refusal over IPv6: $_" -ForegroundColor Green
}

nslookup $blockedProbe ::1
# Expected: 'Query refused'
```

### Step 6.4: Test Default Adapter Resolution (No Server Specified)
```powershell
# Tests the live adapter routing configured by NetworkManager
Resolve-DnsName -Name $allowedDomain
# Expected: Success with valid IP records

try {
    Resolve-DnsName -Name $blockedProbe -ErrorAction Stop
} catch {
    Write-Host "[PASS] Default adapter resolution refused for blocked probe." -ForegroundColor Green
}
```

### Step 6.5: Correlate Client, Gateway and Upstream Observations
```powershell
# 1. Gateway Observation: Verify audit trail in SQLite
sqlite3 "$env:ProgramData\DNS-SHIELD\dns_gateway.db" "SELECT timestamp, client_ip, domain, decision, decision_type, matched_rule, rcode FROM dns_logs WHERE domain LIKE '%$nonce%' ORDER BY id ASC;"
# Expected:
#   domain = probe-<nonce>.malware-sample.test
#   decision = BLOCK
#   decision_type = ADMIN_POLICY
#   matched_rule = malware-sample.test
#   rcode = REFUSED

# 2. Upstream Observation (on Linux controlled upstream host):
# Stop packet capture and analyze:
#   tcpdump -r /tmp/upstream_capture.pcap -n | grep "$nonce"
#
# CRITICAL CORRELATION ASSERTIONS:
# [ASSERTION 1] The allowed domain query appears in the capture and received an upstream response.
# [ASSERTION 2] 'probe-<nonce>.malware-sample.test' DOES NOT APPEAR AT ALL (0 packets, UDP & TCP).
```

### Step 6.6: Rogue External Port 53 & Port 853 Bypass Prevention
```powershell
# Attempt direct query to external public resolver bypassing local gateway
Resolve-DnsName -Name "example.com" -Server 1.1.1.1 -DnsOnly -QuickTimeout
# Expected: Query times out / fails due to WFP port 53 blocking filter

# Test port 853 (DNS-over-TLS / DNS-over-QUIC) blocking
Test-NetConnection -ComputerName 1.1.1.1 -Port 853
# Expected: TcpTestSucceeded : False
```

---

## 7. Lifecycle Resilience & Restoration Procedures

### Step 7.1: Service Crash Simulation & Standalone GUI / CLI Recovery
```powershell
# 1. Forcefully kill the background service
Stop-Process -Name "DNSShieldService" -Force

# 2. Verify degraded health in GUI or CLI:
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli status
# Or launch GUI: badge shows 'DEGRADED (DNS TRAPPED)'

# 3. Execute recovery without service IPC:
# Option A: Click 'Restore Network Now' in GUI (accepts UAC prompt)
# Option B: Run packaged CLI recovery:
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli restore-network
# Option C: Run standalone PowerShell recovery script:
powershell.exe -ExecutionPolicy Bypass -File "C:\TestPackage\scripts\recovery.ps1"

# 4. Confirm Adapter Recovery:
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses
# Expected: Adapters restored to baseline; no longer pointing to 127.0.0.1.
```

### Step 7.2: Service Restart & Reboot Persistence
```powershell
# 1. Restart service and re-enable protection
sc.exe start DNSShield
& "C:\TestPackage\DNSShieldService\DNSShieldService.exe" cli enable-protection

# 2. Reboot VM
Restart-Computer -Force

# 3. Post-reboot checks:
Get-Service -Name DNSShield # Must be 'Running'
Resolve-DnsName -Name "example.com" # Must resolve immediately
```

### Step 7.3: Dual Restoration: DHCP vs. Static DNS Configurations

#### Test Case A: Automatic (DHCP) Adapter
1. Ensure adapter is DHCP: `netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp`
2. Enable protection -> Adapter points to `127.0.0.1`.
3. Run recovery: `powershell.exe -ExecutionPolicy Bypass -File "C:\TestPackage\scripts\recovery.ps1"`
4. Verify adapter restored to DHCP (`source=dhcp`).

#### Test Case B: Static DNS Configuration
1. Configure adapter with static DNS:
   ```powershell
   netsh interface ipv4 set dnsservers name="Ethernet" source=static address=192.168.1.10 validate=no
   netsh interface ipv4 add dnsservers name="Ethernet" address=192.168.1.1 validate=no
   ```
2. Enable protection -> Adapter points to `127.0.0.1`.
3. Run recovery: `powershell.exe -ExecutionPolicy Bypass -File "C:\TestPackage\scripts\recovery.ps1"`
4. Verify adapter is restored to static `192.168.1.10` and `192.168.1.1`.
   **CRITICAL:** Static adapter MUST NOT be converted to DHCP.

### Step 7.4: Clean Uninstallation Verification
```powershell
# Run uninstaller silently
Start-Process -FilePath "$env:ProgramFiles\DNS-SHIELD\unins000.exe" -ArgumentList "/VERYSILENT" -Wait

# 1. Verify service removed:
Get-Service -Name DNSShield -ErrorAction SilentlyContinue # Returns null
# 2. Verify firewall rules removed:
Get-NetFirewallRule -Name "DNSShield*" -ErrorAction SilentlyContinue # Returns null
# 3. Verify Program Files directory removed:
Test-Path "$env:ProgramFiles\DNS-SHIELD" # Returns False
```

---

## 8. Disposable VM Verification Sign-Off Checklist

*Initial Status: All checks are initialized to **NOT RUN** pending execution in a dedicated disposable VM.*

| Test ID | Test Description | Required Verification Criteria | Status |
| :--- | :--- | :--- | :--- |
| **VM-01** | SCM Path Quoting & Permissions | Quoted `binPath`, Program Files ACLs (users read-only) | **NOT RUN** |
| **VM-02** | Explicit Protection Activation | Adapters point to `127.0.0.1`/`::1`, 8 WFP filters registered | **NOT RUN** |
| **VM-03** | Supported Policy Interface & Engine Loading | `add-rule` via Packaged CLI/GUI, confirmed via `get-rules` | **NOT RUN** |
| **VM-04** | Allowed Resolution (Known Answer) | Resolves with NOERROR and known IP (no NXDOMAIN) | **NOT RUN** |
| **VM-05** | Blocked Refusal & Upstream Non-Contact | Client receives `REFUSED`; exactly zero packets arrive at upstream (UDP & TCP) | **NOT RUN** |
| **VM-06** | Rogue Port 53 & Port 853 Bypass | Direct queries to public DNS and port 853 fail/timeout | **NOT RUN** |
| **VM-07** | Service Crash & Standalone Recovery | Standalone recovery works without service IPC | **NOT RUN** |
| **VM-08** | Reboot & Service Persistence | Service restarts automatically; resolution works after reboot | **NOT RUN** |
| **VM-09** | Dual Restoration (DHCP & Static) | DHCP restored to DHCP; Static restored to exact static IPs | **NOT RUN** |
| **VM-10** | Clean Uninstallation | Service, WFP filters, firewall rules, and files cleanly removed | **NOT RUN** |
