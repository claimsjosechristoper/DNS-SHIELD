# DNS-SHIELD: Bypass Controls & Leak Prevention Architecture

**Document Revision:** 1.0  
**Target Platform:** Windows 11 / Windows 10 x64

---

## 1. Overview of Bypass Vectors

A local DNS filtering service that only listens on loopback is vulnerable to several standard bypass channels if operating system controls are not applied:
1. **Direct Port 53 Traffic:** An application creates its own UDP or TCP socket directly to a public resolver (e.g., `8.8.8.8:53`), bypassing the Windows DNS Client and adapter settings.
2. **Encrypted DNS (DoT / DoQ):** An application initiates outbound connections to port 853 (DNS-over-TLS / DNS-over-QUIC).
3. **Browser DNS-over-HTTPS (DoH):** Web browsers (Chrome, Edge, Firefox) automatically upgrade resolution to DoH over HTTPS port 443, bypassing operating system DNS.
4. **Virtual Network Adapters & VPNs:** VPN software creates virtual TAP/TUN/Wintun interfaces with dedicated DNS settings.
5. **Direct IP Connections:** Malware communicating with Command & Control nodes using raw IP addresses without resolving domain names.

---

## 2. Windows Firewall Controls

DNS-SHIELD defines the following outbound Windows Filtering architecture (managed via `firewall_manager.py`):

| Rule / Filter Name | Protocol | Remote Port | Target / Scope | Action | Purpose |
|---|---|---|---|---|---|
| `DNSShield_WFP_Block_Rogue_Port53_IPv4` | UDP / TCP | 53 | Non-gateway processes (`ALE_APP_ID != DNSShieldService.exe`) | **BLOCK** | Prevents rogue processes from querying external resolvers while preserving gateway upstream access. |
| `DNSShield_WFP_Block_Rogue_Port53_IPv6` | UDP / TCP | 53 | Non-gateway processes (`ALE_APP_ID != DNSShieldService.exe`) | **BLOCK** | Dual-stack IPv6 rogue query blocking. |
| `DNSShield-Block-Direct-DoT-TCP` | TCP | 853 | System-wide | **BLOCK** | Blocks direct outbound DNS-over-TLS endpoints. |
| `DNSShield-Block-Direct-DoQ-UDP` | UDP | 853 | System-wide | **BLOCK** | Blocks direct outbound DNS-over-QUIC endpoints. |

### Windows Filtering & Precedence Architecture
In Windows Defender Firewall with Advanced Security:
- **Block Rule Precedence:** Outbound BLOCK rules unconditionally override ordinary program-specific Outbound ALLOW rules. A naive global port-53 block rule will drop the gateway's own upstream packets if the gateway communicates via port 53.
- **Supported Solution (WFP ALE Layer):** Windows Filtering Platform (WFP) Application Layer Enforcement (`FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `V6`) filters evaluate process identity atomically (`FWPM_CONDITION_ALE_APP_ID != service_path`), permitting the service to reach external resolvers while blocking all other programs.
- **Alternative Supported Approach:** Encrypted upstream isolation (DoH over port 443) or scoped remote IP NetFirewall rules.
- **Current Status:** **PENDING_INTEGRATION_VERIFICATION**. Live firewall mutation is kept in dry-run mode on the host laptop and must be validated on a disposable Windows VM before activation.
- Rollback command: `Remove-NetFirewallRule -Name "DNSShield-*" -ErrorAction SilentlyContinue`

---

## 3. Browser DNS-over-HTTPS (DoH) Management

### Technical Reality & Boundaries
- DoH uses standard HTTPS (TCP 443). Blocking port 443 would break normal web browsing.
- Blocking all public DoH IP addresses via static IP lists is fragile and incomplete.

### Enterprise Browser Policies
To prevent browsers from bypassing DNS-SHIELD via DoH on managed Windows workstations:

1. **Microsoft Edge:**
   - Registry Key: `HKLM\SOFTWARE\Policies\Microsoft\Edge`
   - Value Name: `DnsOverHttpsMode`
   - Type: `REG_SZ`
   - Setting: `"off"` (or `"automatic"` where local DNS is preferred)

2. **Google Chrome:**
   - Registry Key: `HKLM\SOFTWARE\Policies\Google\Chrome`
   - Value Name: `DnsOverHttpsMode`
   - Type: `REG_SZ`
   - Setting: `"off"`

3. **Mozilla Firefox:**
   - Registry Key: `HKLM\SOFTWARE\Policies\Mozilla\Firefox`
   - Value Name: `DNSOverHTTPS`
   - Setting: `Enabled = false`

---

## 4. Operational Boundaries

- **Direct-IP Connections:** Malware connecting directly to an IP (e.g. `203.0.113.10:443`) does not initiate DNS resolution. DNS filtering does not inspect or block non-DNS traffic.
- **Root/Admin Access:** A user with local administrative rights can disable Windows services, delete firewall rules, or reconfigure network interfaces.
