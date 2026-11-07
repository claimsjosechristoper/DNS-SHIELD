# DNS-SHIELD: 3-MINUTE PRESENTATION SCRIPT
*(Practice timing: Speak at an even, confident pace. Target duration: 2 minutes 50 seconds to 3 minutes).*

---

### [0:00 - 0:30] SLIDE 1: INTRODUCTION & THE CORE PROBLEM
"Good morning, respected examiners and faculty members.

Today, I present **DNS-SHIELD**, a high-performance endpoint DNS security gateway engineered for Windows environments.

The Domain Name System is fundamental to internet connectivity, and because of this, standard DNS traffic on port 53 is almost universally permitted through enterprise firewalls. Cyber adversaries exploit this trust through **DNS tunneling**—encoding stolen credentials, intellectual property, and command-and-control instructions into domain labels to exfiltrate data out-of-band.

Existing endpoint security tools attempt to detect this using probabilistic machine learning models that generate risk percentages. But on client endpoints, score-based blocking creates serious problems: it causes false-positive outages on legitimate cloud platforms like AWS and Cloudflare, introduces score drift, and adds unacceptable resolution latency."

---

### [0:30 - 1:15] SLIDE 2: THE DNS-SHIELD SOLUTION & ARCHITECTURE
"DNS-SHIELD takes a fundamentally different, deterministic approach.

Our primary project mandate is **automatic, rule-based ALLOW/BLOCK decisions**. We have completely eliminated risk scoring, threat percentages, and probabilistic thresholds. Every single DNS request receives an unambiguous binary verdict.

Operating directly on local loopback at `127.0.0.1:53`, DNS-SHIELD evaluates queries through a high-performance five-tier precedence pipeline:
1. First, an **Administrative Allowlist** for verified business endpoints.
2. Second, **Tenant Custom Policies** configured by local administrators.
3. Third and fourth, **Exact and Subdomain Blocklists** indexed in fast in-memory sets and reverse tries.
4. And fifth, **Deterministic Heuristic Tunneling Detection**—analyzing Shannon character entropy, maximum label length, and favored exfiltration record types such as TXT.

Crucially, DNS-SHIELD guarantees **Upstream Non-Contact**. When a domain is blocked, the gateway synthesizes an RFC-compliant `REFUSED` or `NXDOMAIN` response right on loopback. **Zero packets ever leave the workstation.**"

---

### [1:15 - 2:05] SLIDE 3: WORKING DEMONSTRATION & VERIFICATION
"To prove the reliability of this architecture without altering our host laptop's network settings, we conducted a controlled loopback demonstration on unprivileged ports 5353 and 5354:
1. An allowed query to `allowed-service.test` resolved instantly to `192.168.100.200`, with upstream contact verified.
2. An administrator rule blocking `malware-sample.test` immediately returned `REFUSED`. The upstream resolver logged exactly zero packets, proving that blocked queries never leak upstream.
3. A controlled tunneling sequence with high Shannon entropy of 4.82 and a TXT query was intercepted and refused with zero upstream contact.
4. The SQLite audit database accurately logged exact matched rules and diagnostic reasons.
5. And finally, removing the administrator rule dynamically restored legitimate resolution without requiring a service restart.

In addition, our full automated test suite comprising **95 test cases across 6 modules passed with a 100% success rate in 11.20 seconds**."

---

### [2:05 - 2:40] SLIDE 4: PACKAGING, FAIL-SAFE RECOVERY & HONEST BOUNDARY
"For production deployment, DNS-SHIELD is compiled into a standalone 15.1 megabyte Windows installer built with Inno Setup, packaging our background Windows Service, an unprivileged desktop GUI, and an authenticated command-line tool.

Network safety is paramount. If the background service is ever stopped or killed, our **standalone PowerShell recovery tool** restores network adapter settings back to DHCP out-of-process, with zero service dependency.

To report our status with complete academic honesty:
Deterministic DNS gateway blocking has been demonstrated in a controlled local environment. System-wide Windows adapter redirection and kernel WFP filtering have their implementation and test scripts packaged, and their live execution remains pending validation in a disposable virtual machine."

---

### [2:40 - 3:00] SLIDE 5: CONCLUSION
"In conclusion, DNS-SHIELD proves that deterministic, rule-based endpoint DNS filtering delivers superior privacy, zero-leakage security, and sub-millisecond performance without the operational liabilities of probabilistic scoring.

Thank you, and I am now ready for your questions."
