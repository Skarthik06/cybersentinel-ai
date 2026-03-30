"""
CyberSentinel AI — DPI Threat Detectors
Pure, stateless detection functions — each takes packet data
and returns an Optional[str] suspicion reason or None.

All functions are independently unit-testable (no external deps).
"""
import math
import statistics
from collections import deque
from typing import Optional


# ── Shannon Entropy ───────────────────────────────────────────────────────────
def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte payload.
    Scale: 0.0 (constant) → 8.0 (perfectly random).
    Encrypted/compressed payloads typically score > 7.0.
    """
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length) for c in freq.values()),
        4,
    )


# ── Payload ───────────────────────────────────────────────────────────────────
def detect_high_entropy(payload: bytes, threshold: float = 7.2) -> Optional[str]:
    """
    Flag payloads that appear encrypted or compressed on non-TLS ports.
    Entropy > 7.2 on plaintext ports = likely C2 or exfiltration.
    """
    if not payload:
        return None
    e = shannon_entropy(payload)
    if e >= threshold:
        return f"HIGH_ENTROPY_PAYLOAD:{e:.2f}"
    return None


def detect_cleartext_credentials(payload: bytes) -> Optional[str]:
    """
    Detect cleartext password transmission in HTTP/FTP/Telnet payloads.
    Matches common form-encoded and header-based credential patterns.
    """
    if not payload:
        return None
    try:
        text = payload.decode("utf-8", errors="ignore").lower()
        indicators = [
            "password=", "passwd=", "pass=", "pwd=",
            "authorization: basic",
            "user password",
            "secret=", "token=",
        ]
        for indicator in indicators:
            if indicator in text:
                return f"CLEARTEXT_CREDENTIALS:{indicator.upper().rstrip('=')}"
    except Exception:
        pass
    return None


# ── Ports ─────────────────────────────────────────────────────────────────────
SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444, 5555, 6666, 7777, 8888, 9999,   # Common reverse-shell ports
    31337, 12345, 27374, 1337,             # Classic backdoor ports
    2222,                                  # Alternate SSH (often unauthorised)
})

TOR_PORTS: frozenset[int] = frozenset({9001, 9030, 9050, 9051})


def detect_suspicious_port(dst_port: int) -> Optional[str]:
    """Flag connections to known RAT, backdoor, or C2 listener ports."""
    if dst_port in SUSPICIOUS_PORTS:
        return f"SUSPICIOUS_PORT:{dst_port}"
    if dst_port in TOR_PORTS:
        return f"TOR_PORT:{dst_port}"
    return None


# ── DNS / DGA ─────────────────────────────────────────────────────────────────
def detect_dga(domain: str, subdomain_len_threshold: int = 20) -> Optional[str]:
    """
    Detect Domain Generation Algorithm (DGA) activity.

    Heuristics:
    - Subdomain length > threshold (random-looking names are long)
    - High consonant ratio in subdomain (random strings lack vowels)

    MITRE ATT&CK: T1568.002
    """
    if not domain:
        return None
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return None

    subdomain = parts[0]
    if len(subdomain) <= subdomain_len_threshold:
        return None

    # Additional heuristic: low vowel ratio (< 25%) in long subdomains
    vowels   = sum(1 for c in subdomain.lower() if c in "aeiou")
    letters  = sum(1 for c in subdomain if c.isalpha())
    vowel_ratio = vowels / letters if letters > 0 else 0.0

    if vowel_ratio < 0.25:
        return f"DGA_LOW_VOWEL_RATIO:{domain[:50]}"
    return f"DGA_LONG_SUBDOMAIN:{domain[:50]}"


# ── C2 Beacon ────────────────────────────────────────────────────────────────
def detect_c2_beacon(
    timestamps: list[float],
    avg_interval_threshold: float = 60.0,
    std_dev_threshold: float = 2.0,
    min_samples: int = 10,
) -> Optional[str]:
    """
    Detect C2 beaconing via timing analysis on a list of Unix timestamps.

    A C2 beacon is characterised by:
    - Connections at regular short intervals (avg < threshold)
    - Very low variance (std_dev < threshold) — automated, not human

    MITRE ATT&CK: T1071.001
    """
    if len(timestamps) < min_samples:
        return None

    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    if not intervals:
        return None

    avg = statistics.mean(intervals)
    std = statistics.stdev(intervals) if len(intervals) > 1 else float("inf")

    if 2.0 < avg < avg_interval_threshold and std < std_dev_threshold:
        return f"C2_BEACON:avg={avg:.1f}s,std={std:.3f}"
    return None


# ── TTL ───────────────────────────────────────────────────────────────────────
STANDARD_TTLS: frozenset[int] = frozenset({32, 64, 128, 255})


def detect_ttl_anomaly(ttl: int) -> Optional[str]:
    """
    Flag packets with non-standard TTL values.
    Scanning tools (Masscan, Nmap) and certain malware use unusual TTL values
    to avoid detection or to fingerprint the OS stack.

    MITRE ATT&CK: T1595
    """
    if ttl not in STANDARD_TTLS:
        return f"TTL_ANOMALY:{ttl}"
    return None


# ── User-Agent ────────────────────────────────────────────────────────────────
MALWARE_USER_AGENTS: tuple[str, ...] = (
    "python-requests",
    "Go-http-client/1.1",
    "masscan",
    "zgrab",
    "libwww-perl",
    "sqlmap",
    "nikto",
    "dirbuster",
    "hydra",
    "nmap scripting engine",
)


def detect_malware_user_agent(user_agent: Optional[str]) -> Optional[str]:
    """
    Detect HTTP requests from known scanning / attack tools by User-Agent string.
    """
    if not user_agent:
        return None
    ua_lower = user_agent.lower()
    for pattern in MALWARE_USER_AGENTS:
        if pattern in ua_lower:
            return f"MALWARE_UA:{pattern.upper()}"
    return None


# ── Internal exposure ─────────────────────────────────────────────────────────
DB_PORTS: frozenset[int] = frozenset({1433, 3306, 5432, 27017, 6379, 9200})


def detect_external_db_access(dst_ip: str, dst_port: int) -> Optional[str]:
    """
    Flag database connections arriving from RFC-1918 external ranges.
    Direct external DB access is almost always misconfiguration or attack.
    """
    if dst_port not in DB_PORTS:
        return None
    # If dst_ip is not RFC-1918 — external DB exposure
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.")
    if not any(dst_ip.startswith(p) for p in private_prefixes):
        return f"EXTERNAL_DB_EXPOSURE:{dst_port}"
    return None
