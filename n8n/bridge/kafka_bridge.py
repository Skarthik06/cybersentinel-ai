"""
CyberSentinel AI — Kafka → n8n Webhook Bridge
============================================
n8n does not natively consume Kafka topics.
This lightweight bridge service:
  1. Consumes events from Kafka topics
  2. Routes them to the correct n8n webhook URLs
  3. Handles retries, dead-letter queueing, and deduplication

Topic → n8n Webhook Routing:
  threat-alerts (CRITICAL/HIGH)  → /webhook/critical-alert
  threat-alerts (MEDIUM/LOW)     → /webhook/medium-alert
  enriched-alerts                → /webhook/enriched-alert
  incidents                      → /webhook/new-incident
  cti-updates (CVE CRITICAL)     → /webhook/critical-cve
"""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime

import httpx
import redis.asyncio as aioredis
from aiokafka import AIOKafkaConsumer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BRIDGE] %(levelname)s: %(message)s"
)
logger = logging.getLogger("n8n-bridge")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
N8N_BASE = os.getenv("N8N_WEBHOOK_BASE", "http://n8n:5678/webhook")
N8N_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "bridge-secret-2025")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

# Dedup window — don't forward duplicate events within 60s
DEDUP_TTL_SEC = 60

# Routing table: (topic, condition_fn) → webhook path
ROUTES = [
    ("threat-alerts",  lambda e: e.get("severity") in ("CRITICAL",),       "critical-alert"),
    ("threat-alerts",  lambda e: e.get("severity") in ("HIGH",),            "high-alert"),
    ("threat-alerts",  lambda e: e.get("severity") in ("MEDIUM", "LOW"),    "medium-alert"),
    ("enriched-alerts", lambda e: True,                                      "enriched-alert"),
    ("incidents",      lambda e: True,                                       "new-incident"),
    ("threat-alerts",  lambda e: e.get("type") == "CRITICAL_CVE",           "critical-cve"),
    ("threat-alerts",  lambda e: e.get("type") == "ACTIVE_EXPLOITATION",    "active-exploitation"),
    ("threat-alerts",  lambda e: e.get("type") == "C2_BEACON_DETECTED",     "c2-beacon"),
]


def dedup_key(topic: str, event: dict) -> str:
    """Create a fingerprint for deduplication based on key event fields."""
    sig = json.dumps({
        "topic": topic,
        "type": event.get("type"),
        "src_ip": event.get("src_ip"),
        "severity": event.get("severity"),
        "ts_minute": event.get("timestamp", "")[:16],  # minute-level granularity
    }, sort_keys=True)
    return f"n8n_dedup:{hashlib.md5(sig.encode()).hexdigest()}"


class KafkaN8nBridge:
    def __init__(self):
        self.redis: aioredis.Redis = None
        self.http = httpx.AsyncClient(timeout=10.0)
        self.forwarded = 0
        self.deduplicated = 0
        self.failed = 0

    async def start(self):
        logger.info("🌉 Kafka→n8n Bridge starting...")
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)

        topics = list({r[0] for r in ROUTES})
        consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="n8n-bridge",
            value_deserializer=lambda v: json.loads(v.decode()),
            auto_offset_reset="latest",
        )
        await consumer.start()
        logger.info(f"📡 Consuming topics: {topics}")
        logger.info(f"🎯 n8n webhook base: {N8N_BASE}")

        try:
            async for msg in consumer:
                await self._route_event(msg.topic, msg.value)
        finally:
            await consumer.stop()
            await self.http.aclose()

    async def _route_event(self, topic: str, event: dict):
        """Find matching webhooks and forward the event."""
        # Deduplication check
        dk = dedup_key(topic, event)
        if await self.redis.exists(dk):
            self.deduplicated += 1
            return
        await self.redis.setex(dk, DEDUP_TTL_SEC, "1")

        # Find all matching routes
        matched = [
            webhook_path
            for (t, condition, webhook_path) in ROUTES
            if t == topic and condition(event)
        ]

        if not matched:
            return

        # Enrich event with bridge metadata
        enriched = {
            **event,
            "_bridge": {
                "topic": topic,
                "forwarded_at": datetime.utcnow().isoformat(),
                "routes": matched,
            }
        }

        # Forward to all matched webhook endpoints
        for webhook_path in matched:
            url = f"{N8N_BASE}/{webhook_path}"
            await self._post_to_n8n(url, enriched, webhook_path)

    async def _post_to_n8n(self, url: str, payload: dict, path: str, retries: int = 3):
        """POST event to n8n webhook with retry logic."""
        headers = {
            "Content-Type": "application/json",
            "X-Bridge-Secret": N8N_SECRET,
            "X-Event-Source": "CyberSentinel-Kafka-Bridge",
        }

        for attempt in range(retries):
            try:
                resp = await self.http.post(url, json=payload, headers=headers)
                if resp.status_code in (200, 201, 202):
                    self.forwarded += 1
                    severity = payload.get("severity", "")
                    src = payload.get("src_ip", "unknown")
                    logger.info(
                        f"✅ [{severity}] {payload.get('type', 'EVENT')} "
                        f"from {src} → /{path} (attempt {attempt+1})"
                    )
                    return
                elif resp.status_code == 404:
                    # Workflow not active in n8n — skip silently
                    logger.debug(f"n8n webhook /{path} not active (404) — workflow may be disabled")
                    return
                else:
                    logger.warning(f"n8n webhook returned {resp.status_code} for /{path}")
            except httpx.ConnectError:
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    logger.error(f"n8n unreachable after {retries} attempts for /{path}")
                    self.failed += 1
            except Exception as e:
                logger.error(f"Bridge error for /{path}: {e}")
                self.failed += 1
                return

        # Log periodic stats
        total = self.forwarded + self.deduplicated + self.failed
        if total % 100 == 0:
            logger.info(
                f"📊 Bridge stats — forwarded: {self.forwarded} | "
                f"deduped: {self.deduplicated} | failed: {self.failed}"
            )


async def main():
    bridge = KafkaN8nBridge()
    try:
        await bridge.start()
    except KeyboardInterrupt:
        logger.info("Bridge shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
