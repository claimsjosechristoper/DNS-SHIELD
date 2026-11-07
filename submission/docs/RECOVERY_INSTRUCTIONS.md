# DNS-SHIELD: Standalone Network Recovery Guide

This guide describes how to safely restore Windows network adapter DNS settings to their original configurations when the DNS-SHIELD background service is dead, stopped, crashed, or uninstalled.

---

## 1. When Recovery is Required

Recovery is required if:
- Network adapter DNS servers are stuck pointing to loopback (`127.0.0.1` and `::1`).
- The DNS-SHIELD background service (`DNSShieldService`) is stopped, terminated, or crashed.
- Web browsing or name resolution fails because no service is listening on port 53.
- The Desktop Application displays the status: **`DEGRADED (DNS TRAPPED)`**.

---

## 2. Recovery Methods

### Method 1: Desktop GUI Recovery (Recommended for Standard Users)
1. Open **DNS-SHIELD Control Center** (`DNSShieldApp.exe`).
2. The health banner will indicate **`DEGRADED (DNS TRAPPED)`** and present a amber button: **`Restore Network Now`**.
3. Click **`Restore Network Now`**.
4. Confirm the prompt. If the app is running unelevated, Windows will display a standard User Account Control (UAC) prompt requesting administrative permission to run `recovery.ps1`.
5. Click **Yes** on the UAC prompt.
6. The app will restore all adapters using the persisted snapshot (`dns_backup.json`), clear stale WFP session state, and verify network connectivity.

### Method 2: Standalone PowerShell Recovery (For Administrators)
If the GUI cannot be opened:
1. Open PowerShell as **Administrator** (`Run as Administrator`).
2. Run the standalone recovery script:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\DNS-SHIELD\scripts\recovery.ps1"
   ```
   *(Or from the VM test directory: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TestPackage\scripts\recovery.ps1"`)*
3. The script executes the following operations:
   - Reads `C:\ProgramData\DNS-SHIELD\dns_backup.json`.
   - Restores each adapter:
     - Adapters originally configured with **DHCP** are reset using:  
       `netsh interface <family> set dnsservers name="<Alias>" source=dhcp`
     - Adapters originally configured with **Static DNS** are restored using:  
       `netsh interface <family> set dnsservers name="<Alias>" source=static address=<Original_IP>`
   - Cleans up legacy firewall rules matching `DNSShield*`.
   - Removes the backup snapshot file upon successful restoration.
   - Flushes the local DNS client resolver cache: `ipconfig /flushdns`.

### Method 3: Emergency Manual Fallback (No Scripts Available)
If neither the GUI nor the recovery scripts are accessible, open an elevated Command Prompt or PowerShell and run:

```powershell
# For DHCP (automatic) network adapters:
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp
netsh interface ipv6 set dnsservers name="Ethernet" source=dhcp

# For Static DNS adapters:
netsh interface ipv4 set dnsservers name="Ethernet" source=static address=1.1.1.1 validate=no
netsh interface ipv4 add dnsservers name="Ethernet" address=8.8.8.8 validate=no

# Clear resolver cache:
ipconfig /flushdns
```

---

## 3. Post-Recovery Verification

To confirm successful restoration:
```powershell
# Verify IPv4 DNS servers no longer point to 127.0.0.1
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses

# Verify normal internet resolution
Resolve-DnsName -Name "example.com"
```
