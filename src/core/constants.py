"""
Shared constants — severity levels, MITRE technique IDs, alert types.
Import from here to avoid magic strings scattered across the codebase.
"""

class Severity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    ALL      = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


class AlertType:
    C2_BEACON          = "C2_BEACON_DETECTED"
    DGA_MALWARE        = "DGA_MALWARE_DETECTED"
    PORT_SCAN          = "PORT_SCAN_DETECTED"
    DATA_EXFIL         = "DATA_EXFILTRATION_DETECTED"
    LATERAL_MOVEMENT   = "LATERAL_MOVEMENT_DETECTED"
    CLEARTEXT_CREDS    = "CLEARTEXT_CREDENTIALS"
    HIGH_ENTROPY       = "HIGH_ENTROPY_PAYLOAD"
    SUSPICIOUS_PORT    = "SUSPICIOUS_PORT"
    TTL_ANOMALY        = "TTL_ANOMALY"
    RLM_ANOMALY        = "RLM_BEHAVIORAL_ANOMALY"
    RANSOMWARE         = "RANSOMWARE_STAGING"
    ACTIVE_EXPLOIT     = "ACTIVE_EXPLOITATION"
    CRITICAL_CVE       = "CRITICAL_CVE"


class MitreID:
    C2_HTTP            = "T1071.001"
    NETWORK_SCAN       = "T1046"
    DATA_EXFIL         = "T1048"
    DGA                = "T1568.002"
    LATERAL_MOVE       = "T1021.002"
    RANSOMWARE         = "T1486"
    CREDENTIAL_DUMP    = "T1003"
    TOR_PROXY          = "T1090.003"
    ACTIVE_SCANNING    = "T1595"


class IncidentStatus:
    OPEN         = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED     = "RESOLVED"
    CLOSED       = "CLOSED"


class UserRole:
    ADMIN    = "admin"
    ANALYST  = "analyst"
    VIEWER   = "viewer"
    RESPONDER = "responder"


# Suspicious ports worth flagging
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 2222, 5555}

# Known Tor-related ports
TOR_PORTS = {9001, 9030, 9050, 9051}

# CVE severity thresholds
CVE_CRITICAL_CVSS  = 9.0
CVE_HIGH_CVSS      = 7.0
