# Threat Signatures Reference

**CyberSentinel AI — RLM Engine Behavioral Threat Signatures**

This document describes every threat signature seed stored in the ChromaDB `threat_signatures` collection. These signatures are the foundation of the RLM anomaly detection system — every live host profile is compared against them via cosine similarity to produce an anomaly score.

---

## How Signatures Work

The RLM engine maintains a `BehaviorProfile` for each host on the network. Every packet updates that profile using Exponential Moving Average (EMA, α=0.1). After each update the engine:

1. Calls `profile.to_text()` — converts the numerical EMA fields to a natural language sentence
2. Generates a 384-dimension vector embedding via `all-MiniLM-L6-v2` (local CPU, zero cost)
3. Queries ChromaDB `threat_signatures` for cosine similarity
4. If `similarity ≥ RLM_ANOMALY_THRESHOLD (0.40)` → emits a `BEHAVIOR_ANOMALY` alert to Kafka `threat-alerts`

**The profile text format** (what gets compared against every signature):
```
Host 10.0.0.42 transfers 512 bytes per minute with 14 packets.
Average payload entropy is 7.23.
Traffic is 92% TCP, 5% UDP, 3% DNS.
Connects to 1 unique destinations on 2 unique ports.
Weekend traffic ratio is 0.08.
Current anomaly score: 0.00.
```

**Why natural language?** The `all-MiniLM-L6-v2` model was trained on NLP text and understands semantic relationships between words. Converting numbers to prose ("entropy is 7.23" → semantically close to "high entropy 7.1-7.95") produces better similarity separation than comparing raw vectors of floats.

**Similarity thresholds:**

| Range | Meaning | Action |
|-------|---------|--------|
| 0.00–0.39 | No match — normal traffic | Profile updated, no alert |
| 0.40–0.49 | Weak match | Alert emitted (severity from signature) |
| 0.50–0.64 | Moderate match | Alert emitted, AI investigates |
| 0.65–0.74 | Strong match | HIGH/CRITICAL alert |
| 0.75–1.00 | Very strong match | CRITICAL — active attack likely |

Measured similarity range for known-bad profiles in testing: **0.43–0.55**. The threshold of 0.40 is intentionally conservative to catch edge cases while still being above noise.

---

## Signature Source File

All signatures are defined in `src/models/signatures.py` and seeded into ChromaDB on RLM engine startup. IDs ending in `_v2` are the current active versions — they replace earlier versions which are de-duplicated on startup. The collection is static at runtime (never overwritten by scrapers).

---

## Signatures by Category

### 1. C2 Beaconing

**Signature ID:** `sig_c2_beacon_v2`
**MITRE:** T1071.001 — Application Layer Protocol: Web Protocols
**Severity:** CRITICAL

**Behavioral fingerprint:**
```
avg 200-800 bytes/min, low packets/min, entropy 6.5-7.6
Protocols: TCP dominant. Ports: 443, 80, 8080, 8443
Regular outbound connections to single external IP at consistent intervals
Low jitter timing pattern indicates automated C2 beacon implant check-in
Destination matches known botnet C2 or Tor exit node infrastructure
Recent: repeated TCP connections to same external IP, small payload, high entropy
```

**What triggers this:** A host that phones home on a regular schedule. The RLM observes consistent entropy (encrypted payload), low bytes/min (check-in only, no bulk transfer), and single unique destination. The "low jitter" pattern — regular intervals with minimal variation — is the key signal that separates C2 beaconing from legitimate HTTPS polling.

**Real-world example:** Cobalt Strike default beacon (60s interval), Metasploit Meterpreter HTTPS stager, or any RAT configured with a fixed sleep interval.

---

### 2. Data Exfiltration

**Signature ID:** `sig_data_exfil_v2`
**MITRE:** T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min very high outbound, entropy 7.1-7.95
Protocols: TCP dominant. Ports: 443, 22, 8443, 21
Large sustained data transfer to external IP. Payload size 8000-64000 bytes per packet
High entropy compressed or encrypted payload destined for external staging server
Volume and destination consistent with data theft exfiltration over encrypted channel
Recent: repeated large TCP transfers to external IP, high entropy payload
```

**What triggers this:** Sustained high-volume outbound transfers with near-maximum entropy. The combination of large payload size + consistently high entropy signals compressed or encrypted data being sent out — not typical browsing or API traffic which tends to be bursty and lower entropy.

**Second signature (T1048):** `sig_data_exfiltration` — broader fingerprint covering HTTP POST, SFTP, and off-hours transfer spikes. Catches the same class of behavior with a different angle.

---

### 3. Lateral Movement (SMB)

**Signature ID:** `sig_lateral_movement_v2`
**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min moderate, entropy 4.5-6.5
Protocols: TCP dominant. Ports: 445, 135, 5985, 3389, 22
Multiple unique internal destination IPs. SMB WinRM DCOM RDP SSH traffic
Internal to internal lateral movement admin protocol usage
Compromised workstation accessing other hosts via administrative shares
Recent: TCP connections to multiple internal IPs via SMB or WinRM port
```

**What triggers this:** A single host contacting many different internal IPs on administrative ports (SMB 445, WinRM 5985, RDP 3389). The `unique_dst_ips` count spikes while the ports stay consistent — the opposite of a port scan, which hits many ports on few hosts. This is a workstation or server that has been compromised and is pivoting.

**Second signature (T1021.002):** `sig_lateral_movement` — catches rapid internal scanning with high unique destination IP count and authentication-related traffic spikes.

---

### 4. Port Scan

**Signature ID:** `sig_port_scan_v2`
**MITRE:** T1046 — Network Service Discovery
**Severity:** MEDIUM

**Behavioral fingerprint:**
```
avg bytes/min very low, entropy 0.0
Protocols: TCP dominant. Ports: many different destination ports sequential
SYN only packets, no completed handshake — stealth scan pattern
High unique destination port count, rapid sequential probing
Network service discovery reconnaissance scanning many ports
Recent: TCP SYN to many different ports same destination, zero payload size
```

**What triggers this:** Entropy of 0.0 is the key indicator — SYN packets have no payload, so there is nothing to measure entropy against. Combined with high `unique_dst_ports`, very low `avg_bytes_per_min`, and TCP-only traffic, this precisely fingerprints an nmap-style stealth SYN scan.

**Second signature (T1046):** `sig_port_scan` — catches the same pattern via high RST response count and low payload size.

---

### 5. DNS Tunneling

**Signature ID:** `sig_dns_tunneling_v2`
**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min elevated, entropy 5.5-7.2
Protocols: UDP dominant. Ports: 53. has_dns: true
High rate DNS queries with encoded subdomains 45-63 characters long
DNS tunneling data exfiltration covert channel via DNS protocol
Long subdomain labels with base64 or hex encoded data payloads
Recent: UDP DNS queries to port 53 with long subdomain encoded label
```

**What triggers this:** DNS queries are normally short (domain names average 20-30 characters). DNS tunneling encodes data into subdomains — producing 45-63 character labels that are base64 or hex encoded. The UDP/53 protocol combined with elevated entropy (from the encoded data) and elevated volume (many queries) is the fingerprint. Tools like `iodine` and `dnscat2` produce this exact pattern.

**Related signature:** `sig_dga_malware` (T1568.002) — covers Domain Generation Algorithm malware where domain names are algorithmically random, producing many NXDOMAIN responses. Similar protocol (DNS/UDP) but different intent: DGA is for C2 resilience, tunneling is for data exfiltration.

---

### 6. Brute Force

**Signature ID:** `sig_brute_force_v2`
**MITRE:** T1110.001 — Brute Force: Password Guessing
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min low, entropy 3.5-5.5
Protocols: TCP dominant. Ports: 22, 389, 636, 443
Rapid repeated connection attempts to single destination
SSH brute force or credential stuffing authentication failures
Many short TCP sessions, same destination port, rapid auth attempts
Recent: rapid TCP connections to port 22, small payload, auth attempt pattern
```

**What triggers this:** Many short-lived TCP sessions to the same port on the same host. The entropy range (3.5-5.5) reflects authentication protocol overhead — not random encrypted data, but structured protocol headers with a small credential payload. Low bytes/min despite many attempts means each session is tiny (just the auth exchange, no data transfer after).

---

### 7. RDP Lateral Movement

**Signature ID:** `sig_rdp_lateral_v2`
**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min elevated, entropy 5.0-7.0
Protocols: TCP dominant. Ports: 3389. has_tls: true
Internal to internal RDP Remote Desktop Protocol session
Non-admin workstation initiating RDP to other internal hosts
Credential reuse or stolen session token lateral movement via RDP
Recent: TCP TLS connection to port 3389 internal destination large packets
```

**What triggers this:** RDP sessions are TLS-encrypted (has_tls=true) and involve larger packet sizes than SMB admin share access. The key anomaly is direction: a standard workstation (not an admin jump server) initiating RDP connections to peer hosts. Elevated bytes/min distinguishes an active remote desktop session from a scan or probe.

---

### 8. Web Application Exploit

**Signature ID:** `sig_web_exploit_v2`
**MITRE:** T1190 — Exploit Public-Facing Application
**Severity:** CRITICAL

**Behavioral fingerprint:**
```
avg bytes/min moderate, entropy 4.0-6.5
Protocols: TCP dominant. Ports: 80, 443, 8080, 8443, 8888
HTTP requests with malicious payload patterns, SQL injection, RCE attempt
Web application exploitation attempt from known scanner IP
Many short HTTP connections, varying source ports, exploit payload delivery
Recent: TCP HTTP connection to web port with exploit payload, small to medium size
```

**What triggers this:** A source IP making many short HTTP connections to web ports with moderate-entropy payloads. The connection pattern (many brief connections, varying source ports from the same host) matches automated exploit delivery or vulnerability scanning, as opposed to a legitimate browser session which produces fewer, longer-lived connections.

---

### 9. High Entropy Payload

**Signature ID:** `sig_high_entropy_v2`
**MITRE:** T1027 — Obfuscated Files or Information
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min high, entropy 7.6-7.99
Protocols: TCP dominant. Ports: 443, 8443, 4443, 9443. has_tls: true
Consistent near-maximum Shannon entropy across all packets
Packed malware shellcode or custom encrypted payload transfer
Stage-2 payload delivery or encrypted C2 channel high entropy
Recent: TCP TLS large packets to external IP, entropy exceeds 7.5 threshold
```

**What triggers this:** Shannon entropy of random data approaches 8.0 (the theoretical maximum for a byte). Encrypted or compressed data has entropy in the 7.5-7.99 range. What separates this from legitimate TLS traffic is *consistency* — a real HTTPS session alternates between high-entropy encrypted data and lower-entropy control records. A shellcode download or custom encrypted tunnel holds near-maximum entropy across every packet.

**Related signature:** `sig_ransomware_staging` (T1486) — covers the encryption side of ransomware, where high-entropy write operations happen *on the network shares* rather than in outbound traffic.

---

### 10. Protocol Tunneling

**Signature ID:** `sig_protocol_tunnel_v2`
**MITRE:** T1572 — Protocol Tunneling
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min moderate, entropy 6.5-7.5
Protocols: ICMP or UDP. Ports: 0 or 53
Oversized ICMP or DNS packets 1200-4000 bytes — covert channel
Data hidden inside legitimate protocol traffic to bypass controls
Protocol tunneling, covert C2 channel, ICMP/DNS oversized payload
Recent: ICMP or UDP packets to external IP with oversized payload
```

**What triggers this:** ICMP packets are normally small (ping = 64 bytes). An ICMP packet of 1200-4000 bytes carrying high-entropy data is a strong indicator of a covert channel — tools like `ptunnel` or `icmptunnel` embed TCP traffic inside ICMP echo requests to bypass firewalls that block TCP but allow ICMP. The same pattern applies to oversized DNS UDP packets.

---

### 11. Credential Spray

**Signature ID:** `sig_cred_spray_v2`
**MITRE:** T1110.003 — Brute Force: Password Spraying
**Severity:** HIGH

**Behavioral fingerprint:**
```
avg bytes/min low, entropy 3.0-5.0
Protocols: TCP dominant. Ports: 389, 636, 443, 80
Low-and-slow authentication attempts across many accounts
Password spray: LDAP, LDAPS, HTTPS — evading lockout policy
Single password tried across many user accounts from external source
Recent: TCP connections to LDAP or auth port, small consistent payload
```

**What triggers this:** Unlike brute force (many passwords → one account), password spraying tries one password against many accounts, staying below per-account lockout thresholds. The low-and-slow rate combined with LDAP/LDAPS destination ports and consistent small payload is the fingerprint. The entropy range (3.0-5.0) is lower than brute force because LDAP bind requests are more structured than SSH auth.

---

### 12. Reverse Shell

**Signature ID:** `sig_reverse_shell_v2`
**MITRE:** T1059.004 — Command and Scripting Interpreter: Unix Shell
**Severity:** CRITICAL

**Behavioral fingerprint:**
```
avg bytes/min low, entropy 3.5-5.5
Protocols: TCP dominant. Ports: 4444, 5555, 6666, 1337, 31337, 8888
Outbound connection from internal host to attacker suspicious port
Interactive reverse shell: bidirectional small packets, stdin/stdout
Host fully compromised — attacker has shell access on suspicious port
Recent: TCP outbound to suspicious high port, small packets, interactive session
```

**What triggers this:** Port 4444 is Metasploit's default listener port; 1337 and 31337 are hacker-culture standard ports. An internal host initiating an *outbound* TCP connection to one of these well-known attack tool ports is a near-certain indicator of compromise. The interactive shell pattern (bidirectional small packets, command-response cadence) produces low bytes/min and moderate entropy — commands and output rather than bulk data.

---

### Additional Static Signatures

These signatures do not have `_v2` equivalents — they use a different behavioral fingerprint format (not aligned with `BehaviorProfile.to_text()`) and are lower-weighted in similarity scoring, but still contribute to threat detection.

| ID | MITRE | Description |
|----|-------|-------------|
| `sig_credential_dumping` | T1003 | LSASS access, Kerberos TGS spikes, NTLM from unexpected hosts, pass-the-hash |
| `sig_tor_proxy` | T1090.003 | Tor exit node connections, ports 9001/9030, onion-routed circuit establishment |
| `sig_ransomware_staging` | T1486 | High-entropy write operations over SMB, shadow copy deletion, share enumeration |
| `sig_dga_malware` | T1568.002 | DGA random domain names, high NXDOMAIN rate, multi-TLD queries in short succession |

---

## Signature Coverage Summary

| # | Signature ID | MITRE | Technique | Severity |
|---|-------------|-------|-----------|----------|
| 1 | `sig_c2_beacon_v2` | T1071.001 | C2 Beaconing via Web Protocols | CRITICAL |
| 2 | `sig_data_exfil_v2` | T1048.003 | Exfiltration Over Encrypted Non-C2 Protocol | HIGH |
| 3 | `sig_data_exfiltration` | T1048 | Exfiltration Over Alternative Protocol | CRITICAL |
| 4 | `sig_lateral_movement_v2` | T1021.002 | Lateral Movement via SMB/Admin Shares | HIGH |
| 5 | `sig_lateral_movement` | T1021.002 | Lateral Movement (auth traffic variant) | HIGH |
| 6 | `sig_port_scan_v2` | T1046 | Network Service Discovery (Port Scan) | MEDIUM |
| 7 | `sig_port_scan` | T1046 | Network Service Discovery (RST variant) | MEDIUM |
| 8 | `sig_dns_tunneling_v2` | T1071.004 | DNS Tunneling / Covert Channel | HIGH |
| 9 | `sig_dga_malware` | T1568.002 | Domain Generation Algorithm | HIGH |
| 10 | `sig_brute_force_v2` | T1110.001 | SSH/LDAP Brute Force | HIGH |
| 11 | `sig_rdp_lateral_v2` | T1021.001 | RDP Lateral Movement | HIGH |
| 12 | `sig_web_exploit_v2` | T1190 | Web Application Exploit (RCE/SQLi) | CRITICAL |
| 13 | `sig_high_entropy_v2` | T1027 | High Entropy Payload / Shellcode | HIGH |
| 14 | `sig_ransomware_staging` | T1486 | Ransomware Staging / Encryption | CRITICAL |
| 15 | `sig_protocol_tunnel_v2` | T1572 | Protocol Tunneling (ICMP/DNS) | HIGH |
| 16 | `sig_cred_spray_v2` | T1110.003 | Password Spraying (LDAP/HTTPS) | HIGH |
| 17 | `sig_reverse_shell_v2` | T1059.004 | Reverse Shell (known attack ports) | CRITICAL |
| 18 | `sig_credential_dumping` | T1003 | Credential Dumping (LSASS/Kerberos) | HIGH |
| 19 | `sig_tor_proxy` | T1090.003 | Tor Proxy / Multi-hop Routing | HIGH |

**Total signatures:** 19 (across 13 distinct MITRE techniques)
**CRITICAL signatures:** 5 (C2 beacon, web exploit, ransomware, reverse shell, data exfil v1)
**HIGH signatures:** 13
**MEDIUM signatures:** 1 (port scan)

---

## Similarity Scoring: How a Match Becomes an Alert

```
BehaviorProfile.to_text()
    │
    ▼ all-MiniLM-L6-v2 → 384-dim embedding vector
    │
    ▼ ChromaDB cosine similarity query (n_results=3)
    │   against: threat_signatures collection (19 documents)
    │
    ▼ Score calculation:
    │   similarity = max(0, 1 - cosine_distance / 2)
    │
    ▼ Top match score returned to rlm_engine.py
    │
    ├── score < 0.40  → no alert, profile saved quietly
    │
    └── score ≥ 0.40  → alert emitted to Kafka threat-alerts
                         severity = matched signature severity
                         mitre_technique = matched signature MITRE ID
                         rlm_profile_summary = compact profile stats
```

The matched signature's `mitre` field is attached to every emitted alert, enabling direct MITRE ATT&CK mapping without any LLM call — the mapping happens at the embedding similarity layer.

---

## Adding New Signatures

New signatures are added to `src/models/signatures.py`. Rules for writing effective signatures:

1. **Match the `to_text()` format.** The profile text says "transfers N bytes per minute", "entropy is X.XX", "N% TCP". Signatures should use the same semantic units. "high entropy" is semantically close to "entropy 7.23" — "obfuscated traffic" is not.

2. **Include the quantitative range.** Ranges like "entropy 7.1-7.95" match more profiles than exact values. The embedding model understands that "7.23" is within "7.1-7.95".

3. **Name the protocol and ports.** "Ports: 445, 135, 5985" narrows the match. Generic signatures without ports will score against too many benign profiles.

4. **Use a `_v2` suffix** if you are replacing an existing signature. The engine deduplicates by ID on startup, so the old version is cleanly replaced.

5. **Test with `--dry-run`:** You can query ChromaDB directly to see what similarity score a sample profile text achieves against your new signature before deploying.

---

## How Signatures Differ from CVE / CTI Data

| | Threat Signatures | CVE Database | CTI Reports |
|--|------|------|------|
| Collection | `threat_signatures` | `cve_database` | `cti_reports` |
| Populated by | RLM engine at startup (static) | CTI scraper every 4h | CTI scraper every 1-7h |
| Evicted | Never | No (upsert by CVE-ID) | 90-day TTL |
| Queried by | RLM engine (per packet) | MCP Orchestrator, API | MCP Orchestrator, API |
| Format | Behavioral NLP description | CVE description + CVSS | C2 IPs, KEVs, ATT&CK |
| Purpose | Detect known attack patterns in live traffic | Correlate CVEs in investigation | Enrich investigation with live CTI |

Threat signatures are the only collection that drives **real-time alerting**. CVE and CTI data are used for **investigation enrichment** only — they do not produce alerts on their own.

---

*Threat Signatures Reference — CyberSentinel AI v1.2.2 — 2025/2026*
