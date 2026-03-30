"""
Threat signature seeds for ChromaDB.
These 8 natural language descriptions represent known threat patterns.
The RLM engine compares live host profiles against these via cosine similarity.
"""

THREAT_SIGNATURES = [
    {
        "id": "sig_c2_beacon",
        "text": (
            "Host exhibits C2 beacon behavior: regular low-volume outbound connections "
            "at precise intervals, high payload entropy, connections to unusual ports, "
            "consistent timing patterns suggesting automated check-ins."
        ),
        "mitre": "T1071.001",
        "severity": "CRITICAL",
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
    {
        "id": "sig_data_exfiltration",
        "text": (
            "Unusually high outbound data volume, large HTTP POST requests to external IPs, "
            "off-hours activity spikes, DNS tunnel indicators, "
            "compressed high-entropy payloads destined for cloud storage endpoints."
        ),
        "mitre": "T1048",
        "severity": "CRITICAL",
    },
    {
        "id": "sig_port_scan",
        "text": (
            "High volume of SYN packets to many destination ports on few target hosts, "
            "high unique destination port count, many RST responses received, "
            "low payload size, rapid sequential connection attempts."
        ),
        "mitre": "T1046",
        "severity": "MEDIUM",
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
    {
        "id": "sig_ransomware_staging",
        "text": (
            "Rapid local file system access patterns over network shares, "
            "high-entropy write operations suggesting encryption, "
            "SMB share enumeration, shadow copy deletion indicators, "
            "unusual process spawning via network connections."
        ),
        "mitre": "T1486",
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
