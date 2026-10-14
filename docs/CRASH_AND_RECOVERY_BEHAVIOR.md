# DNS-SHIELD Windows Service Crash & Recovery Behavior

## 1. Scenario: Abrupt Service Termination with Loopback DNS Trapping

### What Happens When `DNSShieldService.exe` Dies?
When the background protection service crashes, is killed (e.g., via Task Manager), or experiences unhandled termination:
1. **WFP Dynamic Filter Dissolution**:
   Because the WFP engine session was opened with `FWPM_SESSION_FLAG_DYNAMIC`, the Windows kernel automatically releases the engine handle and destroys all ALE permit/block filters registered in the `DNSShieldSubLayer`. No outbound port 53 or 853 blocking rules remain active in the kernel.
2. **Adapter DNS Configuration Remains Pointing to Loopback**:
   Windows network adapters remain configured with `127.0.0.1` and `::1` as their active DNS resolver addresses.
3. **The DNS "Black Hole"**:
   With no process listening on `127.0.0.1:53` or `[::1]:53`, all local application DNS requests fail immediately (ICMP Port Unreachable / Connection Refused). Windows applications cannot resolve domain names.

---

## 2. Selected Multi-Tier Recovery Architecture

To ensure zero permanent network lockout, DNS-SHIELD implements a multi-tier recovery architecture:

### Tier 1: Windows Service Control Manager (SCM) Auto-Restart
The Windows Service is registered with automatic recovery actions:
```powershell
sc.exe failure DNSShieldService reset= 86400 actions= restart/5000/restart/10000/run/10000
```
- First crash: SCM automatically restarts the service within 5 seconds.
- Second crash: SCM restarts the service within 10 seconds.
- When the service restarts, it re-binds port 53 on `127.0.0.1` and `::1`, reads active policy, re-engages dynamic WFP filters, and immediately restores name resolution.

### Tier 2: Degraded Health State Reporting in UI and Watchdog
If the service cannot be restarted or remains stopped:
- The Desktop GUI (`DNSShieldApp.exe`) and local diagnostic probes query loopback listener availability and adapter configuration via `network_manager.check_health()`.
- If the adapter points to loopback (`127.0.0.1`/`::1`) but the listener is unresponsive, the state is accurately flagged as:
  **`DEGRADED (SERVICE_UNRESPONSIVE_LOOPBACK_TRAPPED)`**
- A prominent alert is displayed with a one-click **"Restore Network"** button.

### Tier 3: Emergency Network DNS Recovery (`scripts/recovery.ps1` & `network_manager.restore_dns`)
When recovery is executed:
1. **Preserving Administrator Changes**:
   The recovery tool inspects each physical adapter's *current* DNS servers.
   If an adapter is **not** pointing to loopback (`127.0.0.1` or `::1`), the recovery tool logs `Preserving administrator DNS change` and **does not touch or overwrite it**.
2. **Non-Destructive Restoration (No Blanket DHCP Reset)**:
   - If the adapter was originally configured via DHCP: reset DNS to DHCP (`netsh interface ipv4/ipv6 set dnsservers source=dhcp`).
   - If the adapter was originally configured with static DNS servers: restores the exact primary and secondary static DNS addresses in their original order. Static adapters are **never** defaulted to DHCP.
3. **Recovery Without Snapshot (Corrupted/Missing Backup)**:
   If `dns_backup.json` is missing:
   - Adapters not pointing to loopback are untouched.
   - For adapters pointing to loopback: the tool inspects `Get-NetIPInterface -AddressFamily IPv4`.
     * If the interface IP is DHCP: resets DNS to DHCP.
     * If the interface IP is Static: preserves the static IP and sets DNS to the default gateway or fallback (`1.1.1.1`), ensuring the static IP configuration is never destroyed.
4. **Scoping Filter Cleanup**:
   Only DNS-SHIELD owned firewall objects (`Remove-NetFirewallRule -Name "DNSShield*"`) and WFP sublayers are removed. All unrelated Windows Firewall rules and enterprise network policies remain completely intact.
