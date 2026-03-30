"""
BehaviorProfile dataclass — the core data structure of the RLM engine.
Each host on the network gets one profile that self-updates using EMA.
"""
from __future__ import annotations
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class BehaviorProfile:
    """
    Exponential Moving Average behavioral fingerprint for a single host.

    All numeric fields are maintained as EMAs using:
        new = (1 - alpha) * old + alpha * observation

    The to_text() method converts this into natural language for
    ChromaDB embedding and semantic similarity search.
    """
    ip_address: str
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Traffic volume
    avg_bytes_per_min: float = 0.0
    avg_packets_per_min: float = 0.0

    # Payload characteristics
    avg_entropy: float = 0.0
    avg_payload_size: float = 0.0

    # Protocol distribution (fraction of total traffic)
    protocol_tcp_ratio: float = 0.0
    protocol_udp_ratio: float = 0.0
    protocol_dns_ratio: float = 0.0

    # Destination patterns
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    dominant_dst_ports: List[int] = field(default_factory=list)

    # Temporal patterns
    active_hours: List[int] = field(default_factory=list)
    weekend_ratio: float = 0.0

    # Anomaly scoring
    anomaly_score: float = 0.0
    alert_count: int = 0
    observation_count: int = 0

    # Rolling context window for recent events
    context_window: deque = field(default_factory=lambda: deque(maxlen=50))

    def update(self, alpha: float, **observations) -> None:
        """Apply EMA update for all provided observations."""
        for key, value in observations.items():
            if hasattr(self, key) and isinstance(getattr(self, key), float):
                old = getattr(self, key)
                setattr(self, key, (1 - alpha) * old + alpha * float(value))
        self.observation_count += 1
        self.last_seen = datetime.utcnow().isoformat()

    def to_text(self) -> str:
        """
        Convert the numerical profile to natural language text.
        This text is embedded and compared against ChromaDB threat signatures.
        """
        return (
            f"Host {self.ip_address} transfers {self.avg_bytes_per_min:.0f} bytes per minute "
            f"with {self.avg_packets_per_min:.0f} packets. "
            f"Average payload entropy is {self.avg_entropy:.2f}. "
            f"Traffic is {self.protocol_tcp_ratio*100:.0f}% TCP, "
            f"{self.protocol_udp_ratio*100:.0f}% UDP, "
            f"{self.protocol_dns_ratio*100:.0f}% DNS. "
            f"Connects to {self.unique_dst_ips} unique destinations "
            f"on {self.unique_dst_ports} unique ports. "
            f"Weekend traffic ratio is {self.weekend_ratio:.2f}. "
            f"Current anomaly score: {self.anomaly_score:.3f}."
        )

    def to_dict(self) -> dict:
        """Serialize for PostgreSQL persistence."""
        d = {k: v for k, v in self.__dict__.items() if k != "context_window"}
        d["context_window"] = list(self.context_window)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "BehaviorProfile":
        """Deserialize from PostgreSQL row."""
        ctx = data.pop("context_window", [])
        profile = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        profile.context_window = deque(ctx, maxlen=50)
        return profile
