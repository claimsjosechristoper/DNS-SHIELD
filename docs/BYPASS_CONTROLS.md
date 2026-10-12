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

DNS-SHIELD defines the following outbound Windows Filtering rules (managed via `firewall_manager.py`):

| Rule Name | Protocol | Remote Port | Program | Action | Purpose |
|---|---|---|---|---|---|
| `DNSShield-Allow-Service-Outbound-DNS` | UDP / TCP | 53 | `%ProgramFiles%\DNS-SHIELD\DNSShieldService.exe` | **ALLOW** | Permits DNS-SHIELD service to query approved upstreams. |
| `DNSShield-Block-Direct-Outbound-DNS-UDP` | UDP | 53 | Any | **BLOCK** | Prevents rogue processes from querying external resolvers over UDP. |
| `DNSShield-Block-Direct-Outbound-DNS-TCP` | TCP | 53 | Any | **BLOCK** | Prevents rogue processes from querying external resolvers over TCP. |
| `DNSShield-Block-Direct-Outbound-DoT-TCP` | TCP | 853 | Any | **BLOCK** | Blocks standard DNS-over-TLS endpoints. |
| `DNSShield-Block-Direct-Outbound-DoQ-UDP` | UDP | 853 | Any | **BLOCK** | Blocks standard DNS-over-QUIC endpoints. |

### Windows Firewall Precedence Notes
In Windows Defender Firewall with Advanced Security:
- Outbound block rules take precedence over outbound allow rules unless explicitly scoped.
- Scoping outbound port 53 block rules with an application exception allows the DNS-SHIELD service binary to connect outbound while all other executables are blocked from direct port 53 traffic.
- Rollback command: `netsh advfirewall firewall delete rule name="DNSShield-*"`

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
