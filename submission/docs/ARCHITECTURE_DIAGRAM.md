# DNS-SHIELD: ARCHITECTURE & SYSTEM DESIGN SPECIFICATION

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
        
        subgraph ServiceHost["DNSShieldService.exe (NT AUTHORITY\SYSTEM)"]
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
