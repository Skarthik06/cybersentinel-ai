"""
Structured logging configuration for all CyberSentinel services.
All modules import get_logger() from here for consistent formatting.
"""
import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Returns a configured logger for the given service/module name.

    Usage:
        from src.core.logger import get_logger
        logger = get_logger("dpi-sensor")
        logger.info("Packet captured", extra={"src_ip": "1.2.3.4"})
    """
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(log_level)
    return logger
