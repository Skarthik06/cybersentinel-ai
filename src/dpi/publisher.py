"""
Kafka publisher for DPI events.
Handles serialisation and error-retry for raw packet events.
"""
import asyncio
import json
import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict

from aiokafka import AIOKafkaProducer
from src.core.config import kafka as kafka_cfg
from src.core.logger import get_logger

logger = get_logger("dpi-publisher")


async def publish_packet_event(producer: AIOKafkaProducer, event: Dict[str, Any]) -> None:
    """Publish a packet event to Kafka raw-packets topic."""
    try:
        value = json.dumps(event, default=str).encode()
        await producer.send_and_wait(kafka_cfg.topics["raw_packets"], value=value)
    except Exception as e:
        logger.error(f"Failed to publish packet event: {e}")


async def publish_alert(producer: AIOKafkaProducer, alert: Dict[str, Any]) -> None:
    """Publish a threat alert to Kafka threat-alerts topic."""
    try:
        value = json.dumps(alert, default=str).encode()
        await producer.send_and_wait(kafka_cfg.topics["threat_alerts"], value=value)
        logger.warning(
            f"🚨 [{alert.get('severity')}] {alert.get('type')} "
            f"from {alert.get('src_ip')} → MITRE {alert.get('matched_mitre', 'N/A')}"
        )
    except Exception as e:
        logger.error(f"Failed to publish alert: {e}")
