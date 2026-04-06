"""
Threat signature seeds for ChromaDB.
Natural language descriptions are written to match the quantitative/technical
format of BehaviorProfile.to_text() — the RLM compares live profiles against
these via cosine similarity (all-MiniLM-L6-v2).

Measured similarity range for known-bad profiles: 0.43–0.55.
RLM_ANOMALY_THRESHOLD is tuned to 0.40 accordingly.

Each signature id must be unique — used to prevent duplicate seeding.
IDs with suffix _v2 replace the originals and are de-duplicated on startup.
"""

THREAT_SIGNATURES = [
    # ── C2 Beaconing ──────────────────────────────────────────────────────────
    {
        "id": "sig_c2_beacon_v2",
        "text": (
            "Entity host behavior: avg 200-800 bytes/min, low packets/min, entropy 6.5-7.6. "
            "Protocols: TCP dominant. Ports: 443, 80, 8080, 8443. "
            "Regular outbound connections to single external IP at consistent intervals. "
            "Low jitter timing pattern indicates automated C2 beacon implant check-in. "
            "Destination matches known botnet C2 or Tor exit node infrastructure. "
            "Recent: repeated TCP connections to same external IP, small payload, high entropy."
        ),
        "mitre": "T1071.001",
        "severity": "CRITICAL",
    },
    # ── Data Exfiltration ─────────────────────────────────────────────────────
    {
        "id": "sig_data_exfil_v2",
        "text": (
            "Entity host behavior: avg bytes/min very high outbound, entropy 7.1-7.95. "
            "Protocols: TCP dominant. Ports: 443, 22, 8443, 21. "
            "Large sustained data transfer to external IP. Payload size 8000-64000 bytes per packet. "
            "High entropy compressed or encrypted payload destined for external staging server. "
            "Volume and destination consistent with data theft exfiltration over encrypted channel. "
            "Recent: repeated large TCP transfers to external IP, high entropy payload."
        ),
        "mitre": "T1048.003",
        "severity": "HIGH",
    },
    {
        "id": "sig_data_exfiltration",
        "text": (
            "Unusually high outbound data volume to external IP, high entropy payload bytes/min. "
            "Large HTTP POST or SFTP transfers, off-hours spikes, encrypted channel exfiltration. "
            "Compressed high-entropy payloads destined for cloud or staging endpoints."
        ),
        "mitre": "T1048",
        "severity": "CRITICAL",
    },
    # ── Lateral Movement ──────────────────────────────────────────────────────
    {
        "id": "sig_lateral_movement_v2",
        "text": (
            "Entity host behavior: avg bytes/min moderate, entropy 4.5-6.5. "
            "Protocols: TCP dominant. Ports: 445, 135, 5985, 3389, 22. "
            "Multiple unique internal destination IPs. SMB WinRM DCOM RDP SSH traffic. "
            "Internal to internal lateral movement admin protocol usage. "
            "Compromised workstation accessing other hosts via administrative shares. "
            "Recent: TCP connections to multiple internal IPs via SMB or WinRM port."
        ),
        "mitre": "T1021.002",
        "severity": "HIGH",
    },
    {
        "id": "sig_lateral_movement",
        "text": (
            "Host connects to many internal systems rapidly via SMB, WinRM, or LDAP. "
            "High unique destination IP count within internal subnet, "
            "authentication-related traffic spikes, short connection durations."
        ),
        "mitre": "T1021.002",
        "severity": "HIGH",
    },
    # ── Port Scan ─────────────────────────────────────────────────────────────
    {
        "id": "sig_port_scan_v2",
        "text": (
            "Entity host behavior: avg bytes/min very low, entropy 0.0. "
            "Protocols: TCP dominant. Ports: many different destination ports sequential. "
            "SYN only packets no completed handshake stealth scan pattern. "
            "High unique destination port count rapid sequential probing. "
            "Network service discovery reconnaissance scanning many ports. "
            "Recent: TCP SYN to many different ports same destination, zero payload size."
        ),
        "mitre": "T1046",
        "severity": "MEDIUM",
    },
    {
        "id": "sig_port_scan",
        "text": (
            "High volume of SYN packets to many destination ports on few target hosts. "
            "High unique destination port count, many RST responses received, "
            "low payload size, rapid sequential connection attempts."
        ),
        "mitre": "T1046",
        "severity": "MEDIUM",
    },
    # ── DNS Tunneling ─────────────────────────────────────────────────────────
    {
        "id": "sig_dns_tunneling_v2",
        "text": (
            "Entity host behavior: avg bytes/min elevated, entropy 5.5-7.2. "
            "Protocols: UDP dominant. Ports: 53. has_dns true. "
            "High rate DNS queries with encoded subdomains 45-63 characters long. "
            "DNS tunneling data exfiltration covert channel via DNS protocol. "
            "Long subdomain labels with base64 or hex encoded data payloads. "
            "Recent: UDP DNS queries to port 53 with long subdomain encoded label."
        ),
        "mitre": "T1071.004",
        "severity": "HIGH",
    },
    {
        "id": "sig_dga_malware",
        "text": (
            "High DNS query rate with algorithmically random domain names, "
            "many NXDOMAIN responses, long subdomain strings, "
            "DNS queries to multiple TLDs in short succession."
        ),
        "mitre": "T1568.002",
        "severity": "HIGH",
    },
    # ── Brute Force ───────────────────────────────────────────────────────────
    {
        "id": "sig_brute_force_v2",
        "text": (
            "Entity host behavior: avg bytes/min low, entropy 3.5-5.5. "
            "Protocols: TCP dominant. Ports: 22, 389, 636, 443. "
            "Rapid repeated connection attempts to single destination. "
            "SSH brute force or credential stuffing authentication failures. "
            "Many short TCP sessions same destination port rapid auth attempts. "
            "Recent: rapid TCP connections to port 22 small payload auth attempt pattern."
        ),
        "mitre": "T1110.001",
        "severity": "HIGH",
    },
    # ── RDP Lateral Movement ──────────────────────────────────────────────────
    {
        "id": "sig_rdp_lateral_v2",
        "text": (
            "Entity host behavior: avg bytes/min elevated, entropy 5.0-7.0. "
            "Protocols: TCP dominant. Ports: 3389. has_tls true. "
            "Internal to internal RDP Remote Desktop Protocol session. "
            "Non-admin workstation initiating RDP to other internal hosts. "
            "Credential reuse or stolen session token lateral movement via RDP. "
            "Recent: TCP TLS connection to port 3389 internal destination large packets."
        ),
        "mitre": "T1021.001",
        "severity": "HIGH",
    },
    # ── Web Exploit ───────────────────────────────────────────────────────────
    {
        "id": "sig_web_exploit_v2",
        "text": (
            "Entity host behavior: avg bytes/min moderate, entropy 4.0-6.5. "
            "Protocols: TCP dominant. Ports: 80, 443, 8080, 8443, 8888. "
            "HTTP requests with malicious payload patterns SQL injection RCE attempt. "
            "Web application exploitation attempt from known scanner IP. "
            "Many short HTTP connections varying source ports exploit payload delivery. "
            "Recent: TCP HTTP connection to web port with exploit payload small to medium size."
        ),
        "mitre": "T1190",
        "severity": "CRITICAL",
    },
    # ── High Entropy Payload ──────────────────────────────────────────────────
    {
        "id": "sig_high_entropy_v2",
        "text": (
            "Entity host behavior: avg bytes/min high, entropy 7.6-7.99. "
            "Protocols: TCP dominant. Ports: 443, 8443, 4443, 9443. has_tls true. "
            "Consistent near-maximum Shannon entropy across all packets. "
            "Packed malware shellcode or custom encrypted payload transfer. "
            "Stage-2 payload delivery or encrypted C2 channel high entropy. "
            "Recent: TCP TLS large packets to external IP entropy exceeds 7.5 threshold."
        ),
        "mitre": "T1027",
        "severity": "HIGH",
    },
    {
        "id": "sig_ransomware_staging",
        "text": (
            "Rapid local file system access patterns over network shares, "
            "high-entropy write operations suggesting encryption, "
            "SMB share enumeration, shadow copy deletion indicators."
        ),
        "mitre": "T1486",
        "severity": "CRITICAL",
    },
    # ── Protocol Tunneling ────────────────────────────────────────────────────
    {
        "id": "sig_protocol_tunnel_v2",
        "text": (
            "Entity host behavior: avg bytes/min moderate, entropy 6.5-7.5. "
            "Protocols: ICMP or UDP. Ports: 0 or 53. "
            "Oversized ICMP or DNS packets 1200-4000 bytes covert channel. "
            "Data hidden inside legitimate protocol traffic to bypass controls. "
            "Protocol tunneling covert C2 channel ICMP DNS oversized payload. "
            "Recent: ICMP or UDP packets to external IP with oversized payload."
        ),
        "mitre": "T1572",
        "severity": "HIGH",
    },
    # ── Credential Spray ─────────────────────────────────────────────────────
    {
        "id": "sig_cred_spray_v2",
        "text": (
            "Entity host behavior: avg bytes/min low, entropy 3.0-5.0. "
            "Protocols: TCP dominant. Ports: 389, 636, 443, 80. "
            "Low-and-slow authentication attempts across many accounts. "
            "Password spray LDAP LDAPS HTTPS evading lockout policy. "
            "Single password tried across many user accounts external source. "
            "Recent: TCP connections to LDAP or auth port small consistent payload."
        ),
        "mitre": "T1110.003",
        "severity": "HIGH",
    },
    # ── Reverse Shell ─────────────────────────────────────────────────────────
    {
        "id": "sig_reverse_shell_v2",
        "text": (
            "Entity host behavior: avg bytes/min low, entropy 3.5-5.5. "
            "Protocols: TCP dominant. Ports: 4444, 5555, 6666, 1337, 31337, 8888. "
            "Outbound connection from internal host to attacker suspicious port. "
            "Interactive reverse shell bidirectional small packets stdin stdout. "
            "Host fully compromised attacker has shell access suspicious port. "
            "Recent: TCP outbound to suspicious high port small packets interactive session."
        ),
        "mitre": "T1059.004",
        "severity": "CRITICAL",
    },
    {
        "id": "sig_credential_dumping",
        "text": (
            "LSASS access patterns, unusual Kerberos TGS request volume, "
            "NTLM authentication spikes from unexpected hosts, "
            "SAM database access indicators, pass-the-hash traffic patterns."
        ),
        "mitre": "T1003",
        "severity": "HIGH",
    },
    {
        "id": "sig_tor_proxy",
        "text": (
            "Connections to known Tor exit node IP addresses, "
            "traffic on ports 9001 or 9030, onion-routed circuit establishment patterns, "
            "high-latency encrypted tunnels, geo-routing anomalies."
        ),
        "mitre": "T1090.003",
        "severity": "HIGH",
    },
]
