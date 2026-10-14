# DNS-SHIELD: Disposable Windows VM Integration Validation Runbook

**Document Revision:** 4.0  
**Target Environment:** Clean Disposable Windows 11 x64 (22H2 / 23H2 / 24H2) Virtual Machine  
**Controlled Upstream Host:** Linux/BSD host with root access running `tcpdump` and a test resolver.  
**Safety Notice:** Run strictly inside a disposable VM. Never execute protection activation or network mutations on host developer workstations.

---

## 1. Required Files Inventory & VM Staging

Ensure the following files are staged inside the VM directory `C:\TestPackage\`:

```text
C:\TestPackage\
├── DNSShieldService\              # PyInstaller service build directory
│   ├── DNSShieldService.exe
│   └── data\blocklists\           # Bundled blocklist text files
├── DNSShieldApp\                  # PyInstaller desktop application directory
│   └── DNSShieldApp.exe
├── scripts\
│   └── recovery.ps1               # Standalone emergency network recovery script
├── installer\
│   └── DNS-SHIELD-Setup-x64.exe   # Inno Setup installer package (when compiled)
└── baseline_dns.xml               # Generated in Step 2.1
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

# Background capture file for unambiguous post-test packet correlation:
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

*Note: Simply starting the service binary does not mutate network adapters until protection is explicitly enabled.*

### Step 4.1: Explicitly Enable Protection
```powershell
# Enable protection via NetworkManager
python -c "from network_manager import NetworkManager; nm = NetworkManager(); res = nm.enable_protection(); print(res)"

# Or launch GUI as Administrator and click 'Enable Protection':
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
$dnsFilters = $wfp.wfpdiag.filters.filter | Where-Object { $_.displayData.name -like "*DNSShield*" -or $_.displayData.name -like "*IPv4_Permit*" -or $_.displayData.name -like "*IPv4_Block*" }
$dnsFilters | Select-Object filterId, @{N='Name';E={$_.displayData.name}}, action | Format-Table -AutoSize
# Expected: 8 filters registered under DNS-SHIELD sublayer
```

---

## 5. Policy Configuration: Supported Interface & Active Engine Verification

Add the controlled blocked domain `malware-sample.test` through the **supported administrative policy interface** (not raw SQLite writes) and verify that the active running engine has loaded it.

### Step 5.1: Add Block Rule via Supported IPC / GUI
```powershell
# Method A: Via Supported Named Pipe IPC (PowerShell)
$secret = (Get-Content "$env:ProgramData\DNS-SHIELD\ipc.secret").Trim()
python -c "from local_ipc import NamedPipeClient; c = NamedPipeClient(secret=b'$secret'); res = c.call('add_rule', {'domain': 'malware-sample.test', 'rule_type': 'subdomain', 'reason': 'Controlled Integration Test Domain'}); print('add_rule result:', res)"

# Method B: Via Desktop Application
# Open GUI -> Navigate to 'Custom Block Rules' tab -> Enter 'malware-sample.test' -> Click 'Add Block Rule'
```

### Step 5.2: Verify the Running Engine Loaded the Rule
Query active rules from the running engine via IPC and assert in-memory presence:

```powershell
python -c "from local_ipc import NamedPipeClient; c = NamedPipeClient(); res = c.call('get_rules'); rules = [r['domain'] for r in res.get('data', {}).get('custom_rules', [])]; assert 'malware-sample.test' in rules, 'Rule not found in active engine!'; print('[PASS] Running engine confirmed loaded rule:', rules)"
```

---

## 6. Multi-Point Correlated Resolution Verification

A local gateway log alone is not proof of blocking. We correlate three observation points:
1. **Client Observation:** Client receives the actual blocking response (`REFUSED`).
2. **Gateway Observation:** Gateway logs decision `BLOCK`, type `ADMIN_POLICY`, matched rule.
3. **Upstream Observation:** Controlled upstream receives **zero queries** for the blocked domain (UDP & TCP).

### Step 6.1: Generate Unique Test Query Probes
Generate nonces to avoid caching and ensure unambiguous correlation:

```powershell
$nonce = [Guid]::NewGuid().ToString().Substring(0, 8)
$allowedDomain = "probe-$nonce-allow.example.com"
$blockedDomain = "probe-$nonce-block.malware-sample.test"
Write-Host "Allowed Probe: $allowedDomain"
Write-Host "Blocked Probe: $blockedDomain"
```

### Step 6.2: Test IPv4 Resolution (Loopback & Adapter Default)
```powershell
# 1. Allowed domain resolution via IPv4 loopback
Resolve-DnsName -Name $allowedDomain -Server 127.0.0.1
# Expected: Resolves successfully (NOERROR)

# 2. Blocked domain resolution via IPv4 loopback
# Client must receive the actual blocking response: REFUSED
try {
    Resolve-DnsName -Name $blockedDomain -Server 127.0.0.1 -ErrorAction Stop
    Write-Host "[FAIL] Blocked domain unexpectedly resolved!" -ForegroundColor Red
} catch {
    Write-Host "[PASS] Client received refusal error: $_" -ForegroundColor Green
}

# Verify via nslookup (explicitly displays 'Query refused'):
nslookup $blockedDomain 127.0.0.1
# Expected stdout: '*** server can't find ...: Query refused'
```

### Step 6.3: Test IPv6 Resolution (Loopback & Adapter Default)
```powershell
# 1. Allowed domain resolution via IPv6 loopback
Resolve-DnsName -Name $allowedDomain -Server ::1
# Expected: Resolves successfully (NOERROR)

# 2. Blocked domain resolution via IPv6 loopback
try {
    Resolve-DnsName -Name $blockedDomain -Server ::1 -ErrorAction Stop
    Write-Host "[FAIL] Blocked domain unexpectedly resolved over IPv6!" -ForegroundColor Red
} catch {
    Write-Host "[PASS] Client received refusal over IPv6: $_" -ForegroundColor Green
}

nslookup $blockedDomain ::1
# Expected: 'Query refused'
```

### Step 6.4: Test Default Windows Adapter Resolution (No Server Specified)
```powershell
# Query without -Server tests the live adapter routing to the local listener
Resolve-DnsName -Name $allowedDomain
# Expected: Success

try {
    Resolve-DnsName -Name $blockedDomain -ErrorAction Stop
} catch {
    Write-Host "[PASS] Default adapter resolution refused for blocked domain." -ForegroundColor Green
}
```

### Step 6.5: Correlate Client, Gateway and Upstream Observations
```powershell
# 1. Gateway Observation: Verify audit trail in SQLite
sqlite3 "$env:ProgramData\DNS-SHIELD\dns_gateway.db" "SELECT timestamp, client_ip, domain, decision, decision_type, matched_rule, rcode FROM dns_logs WHERE domain LIKE '%$nonce%' ORDER BY id ASC;"
# Expected:
#   probe-...-allow.example.com -> decision=ALLOW, rcode=NOERROR
#   probe-...-block.malware-sample.test -> decision=BLOCK, decision_type=ADMIN_POLICY, matched_rule=malware-sample.test, rcode=REFUSED

# 2. Upstream Observation (on Linux controlled upstream host):
# Stop packet capture and analyze:
#   tcpdump -r /tmp/upstream_capture.pcap -n | grep "$nonce"
#
# CRITICAL CORRELATION ASSERTIONS:
# [ASSERTION 1] 'probe-...-allow.example.com' appears in capture (both query & reply).
# [ASSERTION 2] 'probe-...-block.malware-sample.test' DOES NOT APPEAR AT ALL (0 packets, UDP & TCP).
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

### Step 7.1: Service Crash & Standalone GUI Recovery (Without IPC)
```powershell
# 1. Forcefully kill the background service
Stop-Process -Name "DNSShieldService" -Force

# 2. Launch GUI as standard unelevated user
Start-Process -FilePath "C:\TestPackage\DNSShieldApp\DNSShieldApp.exe"

# 3. Observe UI:
# Badge must show: "DEGRADED (DNS TRAPPED)"
# Button must show: "Restore Network Now"

# 4. Click 'Restore Network Now' -> Approve standard Windows UAC dialog.
# 5. Confirm Adapter Recovery:
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses
# Expected: Adapters restored to baseline; no longer pointing to 127.0.0.1.
```

### Step 7.2: Service Restart & Reboot Persistence
```powershell
# 1. Restart service and re-enable protection
sc.exe start DNSShield
python -c "from network_manager import NetworkManager; nm = NetworkManager(); nm.enable_protection()"

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
| **VM-03** | Policy Interface & Engine Loading | `add_rule` via IPC/GUI, confirmed in-memory via `get_rules` | **NOT RUN** |
| **VM-04** | Allowed Resolution (IPv4 & IPv6) | Resolves with NOERROR; query logged & verified in upstream tcpdump | **NOT RUN** |
| **VM-05** | Blocked Refusal & Upstream Non-Contact | Client receives `REFUSED`; exactly zero packets arrive at upstream (UDP & TCP) | **NOT RUN** |
| **VM-06** | Rogue Port 53 & Port 853 Bypass | Direct queries to public DNS and port 853 fail/timeout | **NOT RUN** |
| **VM-07** | Service Crash & Standalone Recovery | Standalone recovery via UAC works with service dead | **NOT RUN** |
| **VM-08** | Reboot & Service Persistence | Service restarts automatically; resolution works after reboot | **NOT RUN** |
| **VM-09** | Dual Restoration (DHCP & Static) | DHCP restored to DHCP; Static restored to exact static IPs | **NOT RUN** |
| **VM-10** | Clean Uninstallation | Service, WFP filters, firewall rules, and files cleanly removed | **NOT RUN** |
