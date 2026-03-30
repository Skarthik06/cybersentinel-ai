"""
CyberSentinel AI — RLM (Recursive Language Model) Engine

Builds per-entity behavioral profiles using Exponential Moving Averages,
embeds them as natural language vectors in ChromaDB, and scores anomalies
by cosine similarity against known threat signatures.

RAG Governance implemented:
  - Pinned embedding model via config (not DefaultEmbeddingFunction)
  - Embedding cache: skip re-embed if profile text unchanged (Redis SHA-256)
  - Anomaly threshold from config — no hardcoded 0.65
  - Minimum observations gate from config — no hardcoded 20
  - n_results from config
  - Profile collection TTL eviction runs on persist cycle
"""
import asyncio
import json
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import chromadb
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
import redis.asyncio as aioredis
import asyncpg

from src.core.config import chroma as chroma_cfg, rlm as rlm_cfg, kafka as kafka_cfg
from src.core.logger import get_logger
from src.ingestion.embedder import (
    get_chroma_client,
    get_embedding_function,
    get_or_create_collection,
    chunk_text,
    is_embed_cached,
    mark_embed_cached,
    evict_stale_profiles,
    EMBEDDING_MAX_CHARS,
)

logger = get_logger("rlm-engine")

POSTGRES_URL = os.getenv("POSTGRES_URL")
REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379")


# ── BehaviorProfile ───────────────────────────────────────────────────────────
@dataclass
class BehaviorProfile:
    """
    Recursive behavioral profile for a network entity (host, session, user).
    All numeric fields are maintained as EMAs — no raw history stored.
    Updated via update() with each new packet observation.
    """
    entity_id:   str
    entity_type: str  # "host" | "session" | "user"

    avg_bytes_per_min:  float = 0.0
    avg_packets_per_min: float = 0.0
    avg_entropy:        float = 0.0
    dominant_protocols: Dict[str, float] = field(default_factory=dict)
    typical_dst_ports:  Dict[int, int]   = field(default_factory=dict)
    typical_dst_ips:    Dict[str, int]   = field(default_factory=dict)

    active_hours:  Dict[int, float] = field(
        default_factory=lambda: defaultdict(float)
    )
    weekend_ratio: float = 0.5

    anomaly_score:     float = 0.0
    last_anomaly:      Optional[str] = None
    observation_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Rolling context window — last N event summaries
    context_window: deque = field(
        default_factory=lambda: deque(maxlen=rlm_cfg.context_window_size)
    )

    def to_text(self) -> str:
        """
        Convert numerical profile to natural language for embedding.
        Output is bounded to EMBEDDING_MAX_CHARS — chunked if longer.
        This is the 'recursive' step: profile → text → embed → compare.
        """
        protocols = ", ".join(
            f"{k}({v:.0%})"
            for k, v in sorted(self.dominant_protocols.items(), key=lambda x: -x[1])[:5]
        )
        top_ports = ", ".join(
            str(p)
            for p in sorted(self.typical_dst_ports, key=lambda p: -self.typical_dst_ports[p])[:10]
        )
        active_hrs = ", ".join(
            str(h)
            for h in sorted(self.active_hours, key=lambda h: -self.active_hours[h])[:5]
        )
        context_summary = (
            " | ".join(list(self.context_window)[-5:])
            if self.context_window else "no events"
        )

        return (
            f"Entity {self.entity_id} ({self.entity_type}) behavior: "
            f"avg {self.avg_bytes_per_min:.0f} bytes/min, "
            f"{self.avg_packets_per_min:.1f} packets/min, "
            f"entropy {self.avg_entropy:.2f}. "
            f"Protocols: {protocols}. "
            f"Ports: {top_ports}. "
            f"Active hours: {active_hrs}. "
            f"Weekend ratio: {self.weekend_ratio:.1%}. "
            f"Anomaly: {self.anomaly_score:.3f}. "
            f"Recent: {context_summary}."
        )


# ── RLM Engine ────────────────────────────────────────────────────────────────
class RLMEngine:
    """
    Recursive Language Model engine for network behavioral analysis.

    Pipeline per packet:
      1. Consume packet event from Kafka
      2. EMA-update the source IP's BehaviorProfile
      3. Convert profile → natural language text
      4. Check Redis cache — skip ChromaDB query if text unchanged
      5. Query ChromaDB for cosine similarity vs threat signatures
      6. If similarity > anomaly_threshold → emit enriched alert to Kafka
      7. Periodically persist profiles to PostgreSQL + evict stale ChromaDB entries
    """

    def __init__(self):
        self.profiles: Dict[str, BehaviorProfile] = {}
        self.chroma_client: Optional[chromadb.HttpClient] = None
        self.threat_collection  = None
        self.profile_collection = None
        self.ef = None
        self.producer: Optional[AIOKafkaProducer] = None
        self.redis: Optional[aioredis.Redis] = None
        self.db_pool: Optional[asyncpg.Pool] = None

    async def start(self):
        logger.info("🧠 CyberSentinel RLM Engine starting...")

        # ── ChromaDB with pinned model ────────────────────────────────────────
        self.chroma_client = get_chroma_client()
        self.ef = get_embedding_function()

        self.threat_collection = get_or_create_collection(
            self.chroma_client, "threat_signatures", self.ef
        )
        self.profile_collection = get_or_create_collection(
            self.chroma_client, "behavior_profiles", self.ef
        )

        # ── Kafka ─────────────────────────────────────────────────────────────
        self.producer = AIOKafkaProducer(
            bootstrap_servers=kafka_cfg.bootstrap,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        await self.producer.start()

        # ── Redis (embedding cache + IP cache) ────────────────────────────────
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True, max_connections=5)

        # ── PostgreSQL ────────────────────────────────────────────────────────
        self.db_pool = await asyncpg.create_pool(
            POSTGRES_URL, min_size=2, max_size=10
        )

        # Seed threat signatures
        await self._seed_threat_signatures()

        logger.info(
            f"✅ RLM Engine ready | "
            f"model={chroma_cfg.embedding_model} | "
            f"anomaly_threshold={rlm_cfg.anomaly_threshold} | "
            f"min_observations={rlm_cfg.min_observations}"
        )

        await asyncio.gather(
            self._consume_packets(),
            self._consume_alerts(),
            self._periodic_profile_persist(),
        )

    async def _seed_threat_signatures(self):
        """Seed ChromaDB with MITRE ATT&CK-mapped threat pattern descriptions."""
        from src.models.signatures import THREAT_SIGNATURES

        existing_ids: set = set()
        try:
            existing = self.threat_collection.get(include=[])
            existing_ids = set(existing["ids"])
        except Exception:
            pass

        new_sigs = [s for s in THREAT_SIGNATURES if s["id"] not in existing_ids]
        if new_sigs:
            self.threat_collection.add(
                documents=[s["text"] for s in new_sigs],
                ids=[s["id"] for s in new_sigs],
                metadatas=[
                    {
                        "mitre":    s["mitre"],
                        "severity": s["severity"],
                        "embedding_model": chroma_cfg.embedding_model,
                    }
                    for s in new_sigs
                ],
            )
            logger.info(f"✅ Seeded {len(new_sigs)} threat signatures")
        else:
            logger.info("ℹ️  Threat signatures already seeded")

    async def _consume_packets(self):
        """Consume raw packet events → update behavioral profiles."""
        consumer = AIOKafkaConsumer(
            kafka_cfg.topics["raw_packets"],
            bootstrap_servers=kafka_cfg.bootstrap,
            group_id="rlm-packet-processor",
            value_deserializer=lambda v: json.loads(v.decode()),
            auto_offset_reset="latest",
        )
        await consumer.start()
        logger.info("📡 Consuming raw-packets topic")
        try:
            async for msg in consumer:
                await self._process_packet_event(msg.value)
        finally:
            await consumer.stop()

    async def _process_packet_event(self, event: Dict[str, Any]):
        src_ip       = event.get("src_ip", "")
        dst_ip       = event.get("dst_ip", "")
        dst_port     = event.get("dst_port", 0)
        protocol     = event.get("protocol", "OTHER")
        payload_size = event.get("payload_size", 0)
        entropy      = event.get("entropy", 0.0)
        timestamp    = event.get("timestamp", datetime.utcnow().isoformat())

        profile = self._get_or_create_profile(src_ip, "host")
        await self._update_profile(
            profile, event, payload_size, entropy, protocol, dst_ip, dst_port, timestamp
        )

        # ── Embedding cache check ─────────────────────────────────────────────
        profile_text = profile.to_text()
        cached = await is_embed_cached(self.redis, profile_text, "threat_signatures")

        if cached:
            # Text unchanged — reuse last anomaly score, no ChromaDB query
            return

        # ── Score anomaly via ChromaDB ────────────────────────────────────────
        anomaly_score, matched_threat = await self._score_anomaly(profile, profile_text)
        profile.anomaly_score = anomaly_score

        # Mark as cached so next identical profile text skips re-query
        await mark_embed_cached(self.redis, profile_text, "threat_signatures")

        if anomaly_score > rlm_cfg.anomaly_threshold:
            await self._emit_ml_alert(profile, matched_threat, event)

    def _get_or_create_profile(
        self, entity_id: str, entity_type: str
    ) -> BehaviorProfile:
        if entity_id not in self.profiles:
            self.profiles[entity_id] = BehaviorProfile(
                entity_id=entity_id, entity_type=entity_type
            )
        return self.profiles[entity_id]

    async def _update_profile(
        self,
        profile: BehaviorProfile,
        event: Dict,
        payload_size: int,
        entropy: float,
        protocol: str,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ):
        """Recursive EMA update — α from config, no hardcoded values."""
        α = rlm_cfg.alpha
        profile.observation_count += 1

        profile.avg_bytes_per_min   = (1 - α) * profile.avg_bytes_per_min   + α * payload_size
        profile.avg_entropy         = (1 - α) * profile.avg_entropy          + α * entropy
        profile.dominant_protocols[protocol] = (
            profile.dominant_protocols.get(protocol, 0.0) * (1 - α) + α
        )
        profile.typical_dst_ports[dst_port] = (
            profile.typical_dst_ports.get(dst_port, 0) + 1
        )
        profile.typical_dst_ips[dst_ip] = (
            profile.typical_dst_ips.get(dst_ip, 0) + 1
        )

        try:
            dt      = datetime.fromisoformat(timestamp)
            hour    = dt.hour
            profile.active_hours[hour] = (
                profile.active_hours.get(hour, 0.0) * (1 - α) + α
            )
            is_weekend = dt.weekday() >= 5
            profile.weekend_ratio = (1 - α) * profile.weekend_ratio + α * float(is_weekend)
        except Exception:
            pass

        dns_info  = f" DNS:{event.get('dns_query', '')}" if event.get("dns_query") else ""
        http_info = (
            f" HTTP:{event.get('http_method', '')} {event.get('http_host', '')}"
            if event.get("http_method") else ""
        )
        profile.context_window.append(
            f"[{timestamp[:19]}] {protocol} →{dst_ip}:{dst_port} "
            f"size={payload_size}B entropy={entropy:.2f}{dns_info}{http_info}"
        )
        profile.updated_at = datetime.utcnow().isoformat()

    async def _score_anomaly(
        self, profile: BehaviorProfile, profile_text: str
    ) -> Tuple[float, Optional[Dict]]:
        """
        Cosine similarity between profile embedding and threat signatures.
        Gate: skip scoring until min_observations reached (cold-start protection).
        Thresholds are read from config — not hardcoded.
        """
        if profile.observation_count < rlm_cfg.min_observations:
            return 0.0, None

        # Chunk if needed (rare for profile text, but governed)
        chunks = chunk_text(profile_text)
        query_text = chunks[0]  # Use first chunk for anomaly scoring

        results = self.threat_collection.query(
            query_texts=[query_text],
            n_results=rlm_cfg.chroma_n_results,
            include=["metadatas", "distances", "documents"],
        )

        if not results["distances"] or not results["distances"][0]:
            return 0.0, None

        top_distance  = results["distances"][0][0]
        similarity    = max(0.0, 1.0 - (top_distance / 2.0))
        threat_meta   = results["metadatas"][0][0]   if results["metadatas"][0]  else None
        threat_doc    = results["documents"][0][0]   if results["documents"][0]  else None

        matched = (
            {"metadata": threat_meta, "document": threat_doc}
            if similarity > rlm_cfg.threat_match_threshold and threat_meta
            else None
        )
        return similarity, matched

    async def _emit_ml_alert(
        self,
        profile: BehaviorProfile,
        threat: Optional[Dict],
        raw_event: Dict,
    ):
        severity = "MEDIUM"
        mitre    = ""
        if threat and threat.get("metadata"):
            severity = threat["metadata"].get("severity", "MEDIUM")
            mitre    = threat["metadata"].get("mitre", "")

        alert = {
            "type":              "RLM_ANOMALY",
            "severity":          severity,
            "timestamp":         datetime.utcnow().isoformat(),
            "entity_id":         profile.entity_id,
            "entity_type":       profile.entity_type,
            "anomaly_score":     round(profile.anomaly_score, 4),
            "matched_mitre":     mitre,
            "threat_description": threat.get("document", "") if threat else "",
            "profile_summary":   profile.to_text()[:500],
            "src_ip":            raw_event.get("src_ip"),
            "dst_ip":            raw_event.get("dst_ip"),
            "observation_count": profile.observation_count,
        }

        await self.producer.send(kafka_cfg.topics["threat_alerts"], value=alert)
        logger.warning(
            f"🤖 RLM ANOMALY [{severity}] {profile.entity_id} "
            f"score={profile.anomaly_score:.3f} MITRE={mitre}"
        )

        # Upsert profile into ChromaDB for future baseline comparison
        try:
            self.profile_collection.upsert(
                documents=[profile.to_text()],
                ids=[f"profile_{profile.entity_id}_{datetime.utcnow().strftime('%Y%m%d%H')}"],
                metadatas=[{
                    "entity_id":       profile.entity_id,
                    "entity_type":     profile.entity_type,
                    "anomaly_score":   str(profile.anomaly_score),
                    "updated_at":      datetime.utcnow().isoformat(),
                    "embedding_model": chroma_cfg.embedding_model,
                }],
            )
        except Exception as e:
            logger.warning(f"Profile ChromaDB upsert failed: {e}")

    async def _consume_alerts(self):
        """Enrich DPI alerts with RLM profile context."""
        consumer = AIOKafkaConsumer(
            kafka_cfg.topics["threat_alerts"],
            bootstrap_servers=kafka_cfg.bootstrap,
            group_id="rlm-alert-enricher",
            value_deserializer=lambda v: json.loads(v.decode()),
            auto_offset_reset="latest",
        )
        await consumer.start()
        logger.info("🚨 Consuming threat-alerts for RLM enrichment")
        try:
            async for msg in consumer:
                alert = msg.value
                if alert.get("type") == "DPI_ALERT":
                    src_ip = alert.get("src_ip", "")
                    if src_ip in self.profiles:
                        profile = self.profiles[src_ip]
                        alert["rlm_profile_summary"] = profile.to_text()[:300]
                        alert["rlm_anomaly_score"]   = profile.anomaly_score
                        alert["observation_count"]   = profile.observation_count
                        alert["enriched"]            = True
                        await self.producer.send(kafka_cfg.topics["enriched"], value=alert)
        finally:
            await consumer.stop()

    async def _periodic_profile_persist(self):
        """
        Persist profiles to PostgreSQL every profile_save_interval seconds.
        Also runs collection TTL eviction on each cycle.
        """
        persist_interval = rlm_cfg.profile_save_interval
        eviction_counter = 0

        while True:
            await asyncio.sleep(persist_interval)
            logger.info(f"💾 Persisting {len(self.profiles)} profiles to PostgreSQL...")

            try:
                async with self.db_pool.acquire() as conn:
                    for entity_id, profile in list(self.profiles.items()):
                        await conn.execute("""
                            INSERT INTO behavior_profiles
                                (entity_id, entity_type, anomaly_score, observation_count,
                                 avg_bytes_per_min, avg_entropy, profile_text, updated_at)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                            ON CONFLICT (entity_id) DO UPDATE SET
                                anomaly_score      = EXCLUDED.anomaly_score,
                                observation_count  = EXCLUDED.observation_count,
                                avg_bytes_per_min  = EXCLUDED.avg_bytes_per_min,
                                avg_entropy        = EXCLUDED.avg_entropy,
                                profile_text       = EXCLUDED.profile_text,
                                updated_at         = NOW()
                        """,
                            entity_id, profile.entity_type, profile.anomaly_score,
                            profile.observation_count, profile.avg_bytes_per_min,
                            profile.avg_entropy, profile.to_text()
                        )
            except Exception as e:
                logger.error(f"Profile persist failed: {e}")

            # Run ChromaDB eviction every 6 persist cycles (~30 min at 5min interval)
            eviction_counter += 1
            if eviction_counter >= 6:
                eviction_counter = 0
                await evict_stale_profiles(
                    self.profile_collection,
                    ttl_days=chroma_cfg.profile_ttl_days,
                )


async def main():
    engine = RLMEngine()
    try:
        await engine.start()
    except KeyboardInterrupt:
        logger.info("RLM Engine shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
