# DNS Security Gateway: Deployment, Scope & Firewall Integration Guide

## 1. Architectural Scope & Protections

The **DNS Security Gateway** operates strictly at the **DNS control plane (Layer 7 application layer for name resolution)**. Every DNS query received on UDP or TCP port 53/5353 is deterministically evaluated against a strict policy hierarchy:
1. **DNS Protocol & Malformed Validation** (RFC 1035/1123 header, label, and opcode integrity).
2. **Access Control** (Client source IP verification against allowed subnets to prevent open resolver abuse).
3. **Per-Client Rate Limiting** (Protection against flood attacks and resource exhaustion).
4. **Administrator Allowlist** (Explicit domain/subdomain exemptions).
5. **Administrator Custom Block Rules** (Exact or subdomain policy blocks).
6. **Prohibited DNS Record Types** (e.g., blocking `ANY` records to mitigate amplification).
7. **Threat Blocklists** (Curated, validated feeds of known malware, phishing, and C2 domains).
8. **Upstream Forwarding & Bounded Caching** (Transparent resolution to configured authoritative/upstream resolvers, returning `SERVFAIL` on failure).

---

## 2. Inherent Boundaries & Evasion Vectors

DNS-only filtering enforces network policy **solely when an endpoint issues a standard DNS resolution query through this gateway**. It does **not** inspect arbitrary Layer 3/4 payload traffic. The following mechanisms can bypass DNS-layer enforcement unless separately controlled:

1. **Direct-IP Connections**: Malicious binaries or adversaries communicating directly with numeric IP addresses (e.g. `http://198.51.100.23:8080/c2`) do not generate DNS queries and will not trigger DNS enforcement.
2. **Hardcoded / External DNS Resolvers**: Workstations configured with static external DNS (e.g. `8.8.8.8` or `1.1.1.1`) bypass local DNS DHCP settings.
3. **DNS-over-HTTPS (DoH)**: Browsers or applications establishing encrypted HTTPS connections to public DoH resolvers over TCP port 443 (e.g., `https://dns.google/dns-query` or `https://cloudflare-dns.com/dns-query`).
4. **DNS-over-TLS (DoT)**: Clients utilizing dedicated TLS-encrypted DNS on TCP port 853.
5. **Virtual Private Networks (VPNs) & Tor**: Encrypted tunneling protocols encapsulating both DNS and IP traffic through tunnel interfaces.

---

## 3. Optional Firewall / IPS Integration Plan

To achieve enterprise-wide containment, network administrators should pair the DNS Security Gateway with edge perimeter or host-based firewall rules:

### A. Intercepting & Forcing Port 53 Traffic to Gateway
Prevent endpoints from querying external DNS by redirecting or blocking unauthorized outbound DNS.

#### Linux (`iptables` / `nftables`):
```bash
# Redirect all LAN UDP/TCP port 53 traffic to local DNS Gateway (192.168.1.1:53)
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j DNAT --to-destination 192.168.1.1:53

# Allow only the DNS Gateway itself to communicate outbound on port 53
iptables -A FORWARD -p udp --dport 53 -j DROP
iptables -A FORWARD -p tcp --dport 53 -j DROP
```

#### pfSense / OPNsense:
1. Navigate to **Firewall > NAT > Port Forward**.
2. **Interface**: LAN.
3. **Protocol**: TCP/UDP.
4. **Destination**: Invert match (`!`) "This Firewall" or "DNS Gateway IP".
5. **Port**: 53 (DNS).
6. **Redirect Target IP**: IP of DNS Gateway.
7. **Redirect Target Port**: 53 (or 5353).

#### Windows Firewall (Outbound Rule to Block Rogue External DNS):
```powershell
# Block outbound port 53 to any destination other than the configured internal gateway
New-NetFirewallRule -DisplayName "Block Outbound External DNS (UDP)" -Direction Outbound -LocalPort Any -RemotePort 53 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound External DNS (TCP)" -Direction Outbound -LocalPort Any -RemotePort 53 -Protocol TCP -Action Block
```

### B. Blocking Unauthorized DoT (Port 853) & Known DoH Endpoints
1. **Block DNS-over-TLS**: Drop all outbound TCP traffic to destination port 853:
   ```bash
   iptables -A FORWARD -p tcp --dport 853 -j DROP
   ```
2. **Block Public DoH Resolvers**: Block traffic to well-known DoH IP endpoints:
   - `1.1.1.1`, `1.0.0.1` (Cloudflare)
   - `8.8.8.8`, `8.8.4.4` (Google)
   - `9.9.9.9`, `149.112.112.112` (Quad9)
   - `208.67.222.222`, `208.67.220.220` (OpenDNS)
3. **Enterprise Group Policy (GPO)**: Disable browser DoH via centralized policy:
   - Chrome / Edge GPO: Set `BuiltInDnsClientEnabled` to `false` or enforce system DNS.
   - Firefox GPO: Set `network.trr.mode` = `5` (Disabled).

---

## 4. Local Deployment Instructions

### Development Mode (Safe Localhost Port 5353)
Does not require administrator / root privileges and does not alter system network settings.

1. **Activate Python Environment**:
   ```bash
   py -3.11 run.py --server
   ```
   Or launch with demo traffic to observe live ALLOW/BLOCK events:
   ```bash
   py -3.11 run.py --demo
   ```
2. **Access Dashboard**:
   Open `http://127.0.0.1:8000/` in any modern web browser.
3. **Authenticate**:
   Retrieve the administrative key from `data/admin_key.txt` or `.env`. Click **🔑 API Key** in the top navigation bar to authenticate.

---

### Production Deployment (Port 53)
To serve network clients on the standard DNS port 53:

1. **Configure `.env`**:
   ```env
   DNS_HOST=0.0.0.0
   DNS_PORT=53
   API_HOST=0.0.0.0
   API_PORT=8000
   ALLOWED_NETWORKS=192.168.1.0/24,127.0.0.0/8
   DEFAULT_BLOCKED_RCODE=REFUSED
   ```
2. **Bind Privileges**:
   - On Linux: Run under systemd with capability `CAP_NET_BIND_SERVICE`.
   - On Windows: Run PowerShell as Administrator.
3. **Launch Production Gateway**:
   ```bash
   py -3.11 run.py --dns-port 53 --dns-host 0.0.0.0
   ```

---

## 5. Verification & Testing

Verify that enforcement functions identically over UDP and TCP:

### 1. Test Allowed Benign Domain:
```bash
# Query gateway via UDP (port 5353)
nslookup -port=5353 google.com 127.0.0.1

# Query gateway via TCP (port 5353)
dig @127.0.0.1 -p 5353 google.com +tcp
```
*Expected Result*: Returns status `NOERROR` with valid upstream IP addresses.

### 2. Test Blocked Threat Feed Domain:
```bash
nslookup -port=5353 malware-dropper.test 127.0.0.1
```
*Expected Result*: Returns `Query refused` (`REFUSED`), never reaches upstream.

### 3. Test Administrator Policy Rule:
```bash
nslookup -port=5353 internal-prohibited.local 127.0.0.1
nslookup -port=5353 sub.internal-prohibited.local 127.0.0.1
```
*Expected Result*: Returns `Query refused` (`REFUSED`).

### 4. Test Label-Boundary Safety:
```bash
nslookup -port=5353 notinternal-prohibited.local 127.0.0.1
```
*Expected Result*: Not blocked by policy rule; resolved normally or forwarded.

---

## 6. Rollback Instructions

If you temporarily directed your workstation's network adapter to test the gateway:

### Windows Rollback:
1. Open PowerShell as Administrator.
2. List network interfaces:
   ```powershell
   Get-NetIPInterface
   ```
3. Reset DNS to automatic DHCP:
   ```powershell
   Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
   # Or for Ethernet:
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses
   ```
4. Flush client resolver cache:
   ```powershell
   Clear-DnsClientCache
   ```

### Linux Rollback:
1. Restore `/etc/resolv.conf`:
   ```bash
   sudo systemctl restart systemd-resolved
   # Or edit /etc/resolv.conf to nameserver 1.1.1.1
   ```
2. Flush local cache:
   ```bash
   sudo resolvectl flush-caches
   ```
