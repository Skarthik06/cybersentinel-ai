"""
Unit tests for the BehaviorProfile EMA logic.
"""
import pytest
from src.models.profile import BehaviorProfile


def test_profile_creation():
    p = BehaviorProfile(ip_address="192.168.1.1")
    assert p.ip_address == "192.168.1.1"
    assert p.anomaly_score == 0.0
    assert p.observation_count == 0


def test_ema_update():
    p = BehaviorProfile(ip_address="10.0.0.1")
    p.update(alpha=0.1, avg_bytes_per_min=1000.0)
    # EMA: (1-0.1)*0 + 0.1*1000 = 100
    assert p.avg_bytes_per_min == pytest.approx(100.0)
    assert p.observation_count == 1


def test_ema_convergence():
    """EMA should converge towards the true value over time."""
    p = BehaviorProfile(ip_address="10.0.0.2")
    for _ in range(100):
        p.update(alpha=0.1, avg_bytes_per_min=5000.0)
    # After many updates, should be close to 5000
    assert p.avg_bytes_per_min > 4000.0


def test_to_text_format():
    p = BehaviorProfile(ip_address="172.16.0.1")
    p.avg_bytes_per_min = 1500.0
    p.avg_entropy = 6.5
    text = p.to_text()
    assert "172.16.0.1" in text
    assert "1500" in text
    assert "6.50" in text


def test_profile_serialization():
    p = BehaviorProfile(ip_address="192.168.2.1")
    p.update(alpha=0.1, avg_bytes_per_min=2000.0, avg_entropy=5.5)
    d = p.to_dict()
    assert d["ip_address"] == "192.168.2.1"
    assert isinstance(d["context_window"], list)
    restored = BehaviorProfile.from_dict(d)
    assert restored.ip_address == p.ip_address
    assert restored.avg_bytes_per_min == pytest.approx(p.avg_bytes_per_min)
