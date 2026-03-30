"""
Unit tests for DPI threat detectors.
Run with: pytest tests/unit/test_detectors.py -v
No Docker or external services required.
"""
import pytest
from src.dpi.detectors import (
    shannon_entropy,
    detect_high_entropy,
    detect_suspicious_port,
    detect_dga,
    detect_c2_beacon,
    detect_cleartext_credentials,
    detect_ttl_anomaly,
    detect_malware_user_agent,
    detect_external_db_access,
)


# ── Shannon Entropy ───────────────────────────────────────────────────────────
class TestShannonEntropy:
    def test_empty_payload_returns_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_constant_bytes_zero_entropy(self):
        assert shannon_entropy(b"\x00" * 256) == 0.0

    def test_random_bytes_high_entropy(self):
        import os
        assert shannon_entropy(os.urandom(512)) > 6.5

    def test_plain_text_low_entropy(self):
        assert shannon_entropy(b"Hello world this is a normal sentence.") < 5.0

    def test_entropy_bounded(self):
        import os
        e = shannon_entropy(os.urandom(256))
        assert 0.0 <= e <= 8.0


# ── High Entropy Detection ────────────────────────────────────────────────────
class TestHighEntropy:
    def test_random_payload_flagged(self):
        import os
        result = detect_high_entropy(os.urandom(512), threshold=6.0)
        assert result is not None
        assert "HIGH_ENTROPY_PAYLOAD" in result

    def test_plain_text_not_flagged(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert detect_high_entropy(payload, threshold=7.2) is None

    def test_empty_payload_not_flagged(self):
        assert detect_high_entropy(b"") is None


# ── Suspicious Port ───────────────────────────────────────────────────────────
class TestSuspiciousPort:
    def test_metasploit_port_4444(self):
        assert detect_suspicious_port(4444) == "SUSPICIOUS_PORT:4444"

    def test_netcat_port_31337(self):
        assert detect_suspicious_port(31337) == "SUSPICIOUS_PORT:31337"

    def test_tor_port_9001(self):
        assert detect_suspicious_port(9001) == "TOR_PORT:9001"

    def test_https_not_flagged(self):
        assert detect_suspicious_port(443) is None

    def test_http_not_flagged(self):
        assert detect_suspicious_port(80) is None

    def test_ssh_not_flagged(self):
        assert detect_suspicious_port(22) is None


# ── DGA Detection ─────────────────────────────────────────────────────────────
class TestDGADetection:
    def test_long_low_vowel_subdomain_flagged(self):
        # Random-looking: 25 chars, few vowels
        result = detect_dga("xkzpqmnbwrftysdghjklzxc.malware.com", subdomain_len_threshold=20)
        assert result is not None

    def test_normal_subdomain_not_flagged(self):
        assert detect_dga("www.google.com", subdomain_len_threshold=20) is None

    def test_short_subdomain_not_flagged(self):
        assert detect_dga("api.example.com", subdomain_len_threshold=20) is None

    def test_empty_domain_not_flagged(self):
        assert detect_dga("") is None

    def test_single_label_not_flagged(self):
        assert detect_dga("localhost") is None


# ── C2 Beacon ─────────────────────────────────────────────────────────────────
class TestC2Beacon:
    def test_regular_intervals_flagged(self):
        # Timestamps every 30 seconds — very regular
        base = 1700000000.0
        timestamps = [base + i * 30.0 for i in range(15)]
        result = detect_c2_beacon(timestamps, avg_interval_threshold=60.0, std_dev_threshold=2.0)
        assert result is not None
        assert "C2_BEACON" in result

    def test_irregular_intervals_not_flagged(self):
        import random
        random.seed(42)
        base = 1700000000.0
        # Human-like browsing: random intervals 1–600s
        timestamps = [base + sum(random.uniform(1, 600) for _ in range(i)) for i in range(15)]
        result = detect_c2_beacon(timestamps, avg_interval_threshold=60.0, std_dev_threshold=2.0)
        assert result is None

    def test_insufficient_samples_not_flagged(self):
        timestamps = [1700000000.0 + i * 30.0 for i in range(5)]
        assert detect_c2_beacon(timestamps, min_samples=10) is None

    def test_very_long_interval_not_flagged(self):
        # avg = 300s — too long to be a C2 beacon (threshold is 60s)
        timestamps = [1700000000.0 + i * 300.0 for i in range(15)]
        result = detect_c2_beacon(timestamps, avg_interval_threshold=60.0)
        assert result is None


# ── Cleartext Credentials ─────────────────────────────────────────────────────
class TestCleartextCredentials:
    def test_password_form_field_flagged(self):
        payload = b"POST /login HTTP/1.1\r\n\r\nusername=admin&password=secret123"
        assert detect_cleartext_credentials(payload) is not None

    def test_basic_auth_header_flagged(self):
        payload = b"GET /api HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
        assert detect_cleartext_credentials(payload) is not None

    def test_normal_http_not_flagged(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"
        assert detect_cleartext_credentials(payload) is None

    def test_empty_payload_not_flagged(self):
        assert detect_cleartext_credentials(b"") is None


# ── TTL Anomaly ───────────────────────────────────────────────────────────────
class TestTTLAnomaly:
    @pytest.mark.parametrize("ttl", [64, 128, 255, 32])
    def test_standard_ttl_not_flagged(self, ttl):
        assert detect_ttl_anomaly(ttl) is None

    @pytest.mark.parametrize("ttl", [1, 50, 100, 200, 254])
    def test_non_standard_ttl_flagged(self, ttl):
        result = detect_ttl_anomaly(ttl)
        assert result is not None
        assert "TTL_ANOMALY" in result


# ── Malware User-Agent ────────────────────────────────────────────────────────
class TestMalwareUserAgent:
    def test_masscan_flagged(self):
        assert detect_malware_user_agent("masscan/1.0") is not None

    def test_sqlmap_flagged(self):
        assert detect_malware_user_agent("sqlmap/1.7.8") is not None

    def test_normal_browser_not_flagged(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert detect_malware_user_agent(ua) is None

    def test_none_not_flagged(self):
        assert detect_malware_user_agent(None) is None


# ── External DB Exposure ──────────────────────────────────────────────────────
class TestExternalDBExposure:
    def test_postgres_on_public_ip_flagged(self):
        assert detect_external_db_access("203.0.113.10", 5432) is not None

    def test_postgres_on_private_ip_not_flagged(self):
        assert detect_external_db_access("10.0.0.5", 5432) is None

    def test_http_on_public_ip_not_flagged(self):
        assert detect_external_db_access("203.0.113.10", 80) is None
