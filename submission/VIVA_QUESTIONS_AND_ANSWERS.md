# DNS-SHIELD: VIVA VOCE EXAMINATION QUESTIONS & ANSWERS

---

### Q1: What is the core problem DNS-SHIELD solves, and how does DNS tunneling work?
**Answer:**  
DNS-SHIELD addresses out-of-band data exfiltration and Command-and-Control (C2) communication conducted over standard DNS (UDP/TCP port 53). In DNS tunneling, an attacker configures an authoritative nameserver for a domain they own (e.g., `attacker-c2.com`). An implant on an infected host encodes stolen data (files, passwords, tokens) into Base32, Base64, or Hex characters as subdomain labels (e.g., `k8v3x9m2p7w0.attacker-c2.com`). When the client attempts to resolve this name, recursive DNS servers forward the query across the internet to the attacker's nameserver, which decodes the payload. The attacker responds with DNS `TXT` or `CNAME` records containing encoded commands. Because port 53 is almost universally permitted across firewalls, this covert channel bypasses traditional perimeter security.

---

### Q2: Why did your project strictly prohibit risk scoring and threat percentages?
**Answer:**  
In enterprise endpoint security, probabilistic scoring introduces three major operational failures:
1. **False-Positive Outages:** Legitimate cloud platforms and Content Delivery Networks (e.g., Akamai, Cloudflare, AWS CloudFront) generate high-entropy, randomized hostnames for load balancing and cache sharding. A probabilistic model that scores on entropy alone frequently blocks critical business services.
2. **Ambiguity in Policy Enforcement:** A score like "72% threat probability" creates an unmanageable dilemma: blocking disrupts legitimate applications, while allowing permits data theft.
3. **Latency:** Evaluating continuous machine learning feature vectors on every DNS packet introduces 10 to 50 milliseconds of latency, degrading user web responsiveness.  
DNS-SHIELD enforces an **automatic, deterministic rule-based ALLOW/BLOCK decision architecture**. Every query is evaluated through a strict precedence pipeline to produce an unambiguous binary verdict in sub-millisecond execution time.

---

### Q3: What is the Upstream Non-Contact Guarantee, and how do you prove it?
**Answer:**  
The Upstream Non-Contact Guarantee mandates that if a query receives a `BLOCK` verdict—whether from an administrative policy rule, a static blocklist, or a tunneling heuristic match—the gateway synthesizes an RFC-compliant `REFUSED` or `NXDOMAIN` response locally on loopback. The gateway is strictly forbidden from forwarding the query to upstream resolvers.  
We proved this in our controlled demonstration by setting up a dedicated mock upstream resolver on loopback port 5354 that logs every received query. When querying blocked domains (`c2-beacon.malware-sample.test` and the high-entropy tunneling domain), the client received `REFUSED`, and the upstream server logged **zero packets**. Only permitted queries reached the upstream.

---

### Q4: Explain the Shannon Entropy calculation used in your tunneling detector.
**Answer:**  
Shannon's Information Entropy measures the average information content or randomness in a string of characters:
$$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where $P(x_i)$ is the frequency of character $x_i$ divided by the total label length.
- Natural human language domain names (like `google.com` or `service-update.net`) exhibit low entropy, typically between 2.2 and 3.2.
- Encrypted or compressed Base32/Base64 exfiltration strings exhibit high entropy, routinely exceeding 3.8 to 4.5.  
In DNS-SHIELD, a label triggering Shannon entropy $H(X) \ge 3.80$, combined with an excessive label length ($\ge 35$ characters) and a favored exfiltration query type (`TXT`), triggers a deterministic `BLOCK` verdict with exact forensic diagnostic reasoning.

---

### Q5: What is the hierarchical precedence pipeline in PolicyEngine?
**Answer:**  
To avoid rule conflicts and ensure deterministic execution, PolicyEngine enforces five sequential tiers:
1. **Tier 1 - Administrative Allowlist:** Verified critical domains bypass all subsequent block rules.
2. **Tier 2 - Tenant Custom Policies:** Exact or subdomain administrator rules assigned explicit ALLOW or BLOCK actions.
3. **Tier 3 - Exact Domain Blocklists:** O(1) hash set lookup against imported malicious domains.
4. **Tier 4 - Subdomain / Wildcard Blocklists:** O(k) reverse-label trie lookup against blocked domain trees.
5. **Tier 5 - Deterministic Tunneling Heuristics:** Shannon entropy, label length, and record type analysis.
6. **Tier 6 - Default Action:** Permitted queries are forwarded to approved upstream resolvers.

---

### Q6: How does network recovery work if the Windows Service crashes?
**Answer:**  
A common hazard with local DNS proxies is that if the service crashes while network adapters point to `127.0.0.1`, all internet connectivity fails. DNS-SHIELD implements a **standalone, out-of-process elevated recovery tool** (`scripts/recovery.ps1`). It does not use IPC and does not require the service to be alive. It uses native Windows WMI / NetAdapter PowerShell cmdlets to enumerate all network interfaces, clear static `127.0.0.1` DNS bindings, and restore automatic DHCP or original DNS settings.

---

### Q7: How is Inter-Process Communication (IPC) secured between the unprivileged GUI and the elevated Service?
**Answer:**  
The desktop GUI runs in an unprivileged user session, while the service runs as `NT AUTHORITY\LocalSystem`. To prevent local privilege escalation:
1. Configuration mutations (e.g., adding rules, changing upstreams) require an HMAC-SHA256 authentication token.
2. The authentication secret is stored in `%ProgramData%\DNS-SHIELD\ipc.secret`, protected by restrictive Windows NTFS ACLs that allow read access only to Administrators and SYSTEM.
3. Unprivileged queries can read status and telemetry, but any mutation without a valid token is rejected with an HTTP/IPC 403 Forbidden.
4. The administrative CLI embedded in `DNSShieldService.exe` reads the secret internally from disk, preventing administrator tokens from leaking into process command-line arguments.

---

### Q8: What are the differences between your automated tests and your live demonstration?
**Answer:**  
- **Automated Tests:** 95 pytest unit and integration test cases covering domain normalization, boundary conditions, access control CIDRs, HMAC token challenges, WFP constants, SCM quoting, and multi-tenant isolation. Passed 100% in 11.20s.
- **Live Demonstration:** A 6-stage end-to-end execution of the real `DNSGatewayServer` and `PolicyEngine` on loopback unprivileged port 5353, verifying live DNS packet resolution, administrative refusal, heuristic refusal, SQLite audit logging, upstream non-contact confirmation, and dynamic rule restoration.

---

### Q9: What is the exact status of your Windows integration and WFP testing?
**Answer:**  
In accordance with engineering honesty:
- **Demonstrated:** Deterministic DNS gateway blocking demonstrated in a controlled local environment.
- **Pending:** System-wide Windows adapter redirection and Windows Filtering Platform (WFP) kernel callout enforcement remain pending execution in a dedicated disposable virtual machine.
We explicitly do not claim full production deployment or successful VM validation without executing the test runbook in a live disposable VM.

---

### Q10: How does DNS-SHIELD handle DNS-over-HTTPS (DoH)?
**Answer:**  
Modern browsers configured with independent DoH bypass port 53 entirely by sending encrypted DNS queries over TCP port 443. To counter this in enterprise environments:
1. Enterprise Group Policies (GPO) are deployed to disable browser DoH and enforce system DNS.
2. Windows Filtering Platform (WFP) outbound rules block connections to known public DoH resolver IP addresses (such as `1.1.1.1` and `8.8.8.8` on port 443).
3. In future work, a local loopback TLS termination proxy will intercept local DoH queries transparently.
