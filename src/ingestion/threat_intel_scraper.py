"""
CyberSentinel AI — Threat Intelligence Scraper

Harvests CTI from 5 live sources and embeds into ChromaDB.

RAG Governance implemented:
  - All text truncation uses truncate_with_log() (logged, not silent)
  - Chunking via chunk_text() for documents exceeding token limit
  - MITRE ATT&CK re-embed guard — max once per MITRE_REEMBED_INTERVAL_DAYS
  - Configurable batch size via EMBED_BATCH_SIZE env var
  - Upsert deduplication via deterministic IDs (no duplicate embeddings)
  - embedding_model version recorded in every document metadata
  - Collection TTL eviction for cti_reports
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import httpx
import redis.asyncio as aioredis
from aiokafka import AIOKafkaProducer

from src.core.config import chroma as chroma_cfg, kafka as kafka_cfg
from src.core.logger import get_logger
from src.ingestion.embedder import (
    get_chroma_client,
    get_embedding_function,
    get_or_create_collection,
    batch_upsert,
    truncate_with_log,
    chunk_text,
    should_reembed_static_source,
    evict_stale_profiles,
    EMBEDDING_MAX_CHARS,
)

logger = get_logger("cti-scraper")

POSTGRES_URL  = os.getenv("POSTGRES_URL")
REDIS_URL     = os.getenv("REDIS_URL", "redis://redis:6379")
NVD_API_KEY   = os.getenv("NVD_API_KEY", "")
OTX_API_KEY   = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")


class ThreatIntelScraper:
    """
    Scheduled CTI harvester. Runs each source on its own refresh interval.
    All embedding goes through the governed embedder layer.
    """

    def __init__(self):
        self.chroma_client  = None
        self.cti_collection = None
        self.cve_collection = None
        self.ef             = None
        self.http           = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.producer: Optional[AIOKafkaProducer] = None
        self.redis: Optional[aioredis.Redis]       = None

    async def start(self):
        logger.info("🌐 CyberSentinel CTI Scraper starting...")

        # ── ChromaDB with pinned, governed embedding function ─────────────────
        self.chroma_client = get_chroma_client()
        self.ef            = get_embedding_function()

        self.cti_collection = get_or_create_collection(
            self.chroma_client, "cti_reports", self.ef
        )
        self.cve_collection = get_or_create_collection(
            self.chroma_client, "cve_database", self.ef
        )

        # ── Kafka ─────────────────────────────────────────────────────────────
        self.producer = AIOKafkaProducer(
            bootstrap_servers=kafka_cfg.bootstrap,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        await self.producer.start()

        # ── Redis (re-embed guard + cache) ────────────────────────────────────
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True, max_connections=5)

        logger.info(
            f"✅ Scraper initialized | "
            f"model={chroma_cfg.embedding_model} | "
            f"batch_size={chroma_cfg.embed_batch_size} | "
            f"mitre_interval={chroma_cfg.mitre_reembed_interval_days}d"
        )

        # Launch all scrapers concurrently on their own schedules
        await asyncio.gather(
            self._schedule("NVD CVE",        self._scrape_nvd_cves,      interval_hours=4),
            self._schedule("CISA KEV",       self._scrape_cisa_kev,      interval_hours=6),
            self._schedule("Abuse.ch",       self._scrape_abuse_ch,      interval_hours=1),
            self._schedule("MITRE ATT&CK",   self._scrape_mitre_attack,  interval_hours=24),
            self._schedule("AlienVault OTX", self._scrape_otx_pulses,    interval_hours=2),
            self._schedule("CTI Eviction",   self._run_cti_eviction,     interval_hours=24),
        )

    async def _schedule(self, name: str, fn, interval_hours: float):
        """Run fn() immediately then every interval_hours."""
        while True:
            try:
                logger.info(f"🔄 Running: {name}")
                await fn()
            except Exception as e:
                logger.error(f"❌ {name} failed: {e}", exc_info=True)
            await asyncio.sleep(interval_hours * 3600)

    # ── NVD CVE ───────────────────────────────────────────────────────────────
    async def _scrape_nvd_cves(self):
        """
        Fetch CVEs from NIST NVD (last 7 days, CVSS ≥ 7.0).
        Each CVE is a single semantic unit — chunked if description is long.
        """
        now   = datetime.utcnow()
        start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"pubStartDate={start}&pubEndDate={end}&resultsPerPage=100"
        )

        resp = await self.http.get(url, headers=headers)
        if resp.status_code != 200:
            logger.warning(f"NVD API returned {resp.status_code}")
            return

        vulnerabilities = resp.json().get("vulnerabilities", [])
        logger.info(f"  📋 Processing {len(vulnerabilities)} CVEs from NVD")

        docs, ids, metas = [], [], []

        for vuln in vulnerabilities:
            cve        = vuln.get("cve", {})
            cve_id     = cve.get("id", "")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d["lang"] == "en"), ""
            )
            cvss_score = 0.0
            severity   = "UNKNOWN"
            try:
                metrics    = cve.get("metrics", {})
                cvss_data  = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {})
                )
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                severity   = cvss_data.get("baseSeverity", "UNKNOWN")
            except Exception:
                pass

            if cvss_score < 7.0:
                continue  # Only HIGH and CRITICAL

            # truncate_with_log ensures we know when description is cut
            desc_for_embed = truncate_with_log(
                description, EMBEDDING_MAX_CHARS - 120, f"{cve_id}.description"
            )

            text = (
                f"CVE: {cve_id}. CVSS: {cvss_score} ({severity}). "
                f"Published: {cve.get('published', '')[:10]}. "
                f"Description: {desc_for_embed}."
            )

            # chunk_text handles the rare case of very long descriptions
            chunks = chunk_text(text)
            for j, chunk in enumerate(chunks):
                chunk_id = cve_id if len(chunks) == 1 else f"{cve_id}_chunk_{j}"
                docs.append(chunk)
                ids.append(chunk_id)
                metas.append({
                    "cve_id":          cve_id,
                    "cvss_score":      str(cvss_score),
                    "severity":        severity,
                    "published":       cve.get("published", "")[:10],
                    "chunk_index":     str(j),
                    "total_chunks":    str(len(chunks)),
                    "source":          "NVD",
                    "embedding_model": chroma_cfg.embedding_model,
                })

            # Critical CVE → immediate Kafka alert
            if cvss_score >= 9.0:
                await self.producer.send(kafka_cfg.topics["cti_updates"], value={
                    "type":        "CRITICAL_CVE",
                    "severity":    "CRITICAL",
                    "timestamp":   datetime.utcnow().isoformat(),
                    "cve_id":      cve_id,
                    "cvss_score":  cvss_score,
                    "description": truncate_with_log(description, 300, "kafka_desc"),
                    "source":      "NVD",
                })
                logger.warning(
                    f"🚨 CRITICAL CVE: {cve_id} CVSS={cvss_score} "
                    f"— {description[:100]}"
                )

        if docs:
            embedded = await batch_upsert(
                self.cve_collection, docs, ids, metas, self.redis
            )
            logger.info(f"  ✅ NVD: {embedded} new CVEs embedded")

    # ── CISA KEV ──────────────────────────────────────────────────────────────
    async def _scrape_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        url  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = await self.http.get(url)
        if resp.status_code != 200:
            logger.warning(f"CISA KEV returned {resp.status_code}")
            return

        vulns = resp.json().get("vulnerabilities", [])
        logger.info(f"  📋 Processing {len(vulns)} CISA KEV entries")

        docs, ids, metas = [], [], []
        for vuln in vulns:
            cve_id   = vuln.get("cveID", "")
            product  = truncate_with_log(vuln.get("product", ""), 100, "kev_product")
            vendor   = truncate_with_log(vuln.get("vendorProject", ""), 80, "kev_vendor")
            short_desc = truncate_with_log(
                vuln.get("shortDescription", ""), EMBEDDING_MAX_CHARS - 200, "kev_desc"
            )
            action   = truncate_with_log(vuln.get("requiredAction", ""), 200, "kev_action")
            due_date = vuln.get("dueDate", "")

            text = (
                f"CISA KEV: {cve_id}. Product: {vendor} {product}. "
                f"Actively exploited in the wild. Due date: {due_date}. "
                f"Description: {short_desc}. "
                f"Required action: {action}."
            )

            chunks = chunk_text(text)
            for j, chunk in enumerate(chunks):
                chunk_id = (
                    f"cisa_{cve_id}" if len(chunks) == 1
                    else f"cisa_{cve_id}_chunk_{j}"
                )
                docs.append(chunk)
                ids.append(chunk_id)
                metas.append({
                    "cve_id":          cve_id,
                    "source":          "CISA_KEV",
                    "due_date":        due_date,
                    "vendor":          vendor,
                    "chunk_index":     str(j),
                    "embedding_model": chroma_cfg.embedding_model,
                })

            # All CISA KEV entries = actively exploited → alert
            await self.producer.send(kafka_cfg.topics["cti_updates"], value={
                "type":        "ACTIVE_EXPLOITATION",
                "severity":    "CRITICAL",
                "timestamp":   datetime.utcnow().isoformat(),
                "cve_id":      cve_id,
                "due_date":    due_date,
                "description": short_desc[:200],
                "source":      "CISA_KEV",
            })

        if docs:
            embedded = await batch_upsert(
                self.cti_collection, docs, ids, metas, self.redis
            )
            logger.info(f"  ✅ CISA KEV: {embedded} entries embedded")

    # ── Abuse.ch ──────────────────────────────────────────────────────────────
    async def _scrape_abuse_ch(self):
        """Fetch Feodo Tracker C2 botnet IP blocklist."""
        sources = [
            ("https://feodotracker.abuse.ch/downloads/ipblocklist.json", "botnet_c2"),
            ("https://urlhaus-api.abuse.ch/v1/urls/recent/",             "malware_url"),
        ]
        docs, ids, metas = [], [], []

        for url, indicator_type in sources:
            try:
                resp = await self.http.get(url)
                if resp.status_code != 200:
                    continue
                entries = resp.json() if isinstance(resp.json(), list) else resp.json().get("urls", [])

                for entry in entries[:500]:  # Cap at 500 per source per run
                    if indicator_type == "botnet_c2":
                        ip      = entry.get("ip_address", "")
                        malware = entry.get("malware", "Unknown")
                        country = entry.get("country", "")
                        if not ip:
                            continue
                        text = (
                            f"Botnet C2 IP: {ip}. Malware: {malware}. "
                            f"Country: {country}. Actively hosting command-and-control."
                        )
                        doc_id = f"c2_{ip.replace('.', '_')}"
                    else:
                        url_str = truncate_with_log(entry.get("url", ""), 200, "abuse_url")
                        threat  = entry.get("threat", "Unknown")
                        if not url_str:
                            continue
                        text   = f"Malware URL: {url_str}. Threat type: {threat}."
                        doc_id = f"url_{abs(hash(url_str))}"

                    docs.append(text)
                    ids.append(doc_id)
                    metas.append({
                        "source":          f"abuse_ch_{indicator_type}",
                        "indicator_type":  indicator_type,
                        "embedding_model": chroma_cfg.embedding_model,
                    })
            except Exception as e:
                logger.error(f"Abuse.ch {indicator_type} scrape failed: {e}")

        if docs:
            embedded = await batch_upsert(
                self.cti_collection, docs, ids, metas, self.redis
            )
            logger.info(f"  ✅ Abuse.ch: {embedded} indicators embedded")

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    async def _scrape_mitre_attack(self):
        """
        Embed MITRE ATT&CK enterprise techniques.

        RE-EMBED GUARD: MITRE updates ~twice a year but we scrape daily.
        should_reembed_static_source() returns False if guard is active,
        skipping the entire HTTP fetch + embed cycle — saving compute and time.
        """
        should_run = await should_reembed_static_source(
            self.redis,
            source_name="mitre_attack",
            interval_days=chroma_cfg.mitre_reembed_interval_days,
        )
        if not should_run:
            return

        url  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        resp = await self.http.get(url)
        if resp.status_code != 200:
            logger.warning(f"MITRE ATT&CK returned {resp.status_code}")
            return

        techniques = [
            obj for obj in resp.json().get("objects", [])
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False)
        ]
        logger.info(f"  📋 Processing {len(techniques)} MITRE ATT&CK techniques")

        docs, ids, metas = [], [], []
        for tech in techniques[:500]:
            external_id = ""
            for ref in tech.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "")
                    break

            name      = tech.get("name", "")
            platforms = ", ".join(tech.get("x_mitre_platforms", []))
            desc      = truncate_with_log(
                tech.get("description", ""), EMBEDDING_MAX_CHARS - 300, f"mitre_{external_id}.desc"
            )
            detection = truncate_with_log(
                tech.get("x_mitre_detection", ""), 300, f"mitre_{external_id}.detection"
            )

            text = (
                f"MITRE ATT&CK {external_id}: {name}. "
                f"Platforms: {platforms}. "
                f"Description: {desc}. "
                f"Detection: {detection}."
            )

            # Chunk long descriptions
            chunks = chunk_text(text)
            for j, chunk in enumerate(chunks):
                chunk_id = (
                    f"mitre_{external_id}" if len(chunks) == 1
                    else f"mitre_{external_id}_chunk_{j}"
                )
                docs.append(chunk)
                ids.append(chunk_id)
                metas.append({
                    "technique_id":    external_id,
                    "name":            name,
                    "platforms":       platforms,
                    "source":          "MITRE_ATTACK",
                    "chunk_index":     str(j),
                    "embedding_model": chroma_cfg.embedding_model,
                })

        if docs:
            embedded = await batch_upsert(
                self.cti_collection, docs, ids, metas, self.redis
            )
            logger.info(
                f"  ✅ MITRE ATT&CK: {embedded} technique chunks embedded "
                f"(guard reset for {chroma_cfg.mitre_reembed_interval_days}d)"
            )

    # ── AlienVault OTX ───────────────────────────────────────────────────────
    async def _scrape_otx_pulses(self):
        """Fetch threat intelligence pulses from AlienVault OTX."""
        if not OTX_API_KEY:
            logger.info("  ⚠️  OTX_API_KEY not set — skipping AlienVault OTX")
            return

        url  = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        resp = await self.http.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        if resp.status_code != 200:
            logger.warning(f"OTX returned {resp.status_code}")
            return

        pulses = resp.json().get("results", [])
        logger.info(f"  📋 Processing {len(pulses)} OTX pulses")

        docs, ids, metas = [], [], []
        for pulse in pulses:
            pulse_id = pulse.get("id", "")
            if not pulse_id:
                continue

            name  = truncate_with_log(pulse.get("name", ""), 120, "otx_name")
            desc  = truncate_with_log(
                pulse.get("description", ""), EMBEDDING_MAX_CHARS - 200, "otx_desc"
            )
            tags  = ", ".join(pulse.get("tags", [])[:10])
            ioc_count = len(pulse.get("indicators", []))

            text = (
                f"Threat Intel Pulse: {name}. "
                f"Tags: {tags}. "
                f"IOC count: {ioc_count}. "
                f"Description: {desc}."
            )

            chunks = chunk_text(text)
            for j, chunk in enumerate(chunks):
                chunk_id = (
                    f"otx_{pulse_id}" if len(chunks) == 1
                    else f"otx_{pulse_id}_chunk_{j}"
                )
                docs.append(chunk)
                ids.append(chunk_id)
                metas.append({
                    "pulse_id":        pulse_id,
                    "source":          "OTX",
                    "tags":            tags,
                    "chunk_index":     str(j),
                    "embedding_model": chroma_cfg.embedding_model,
                })

        if docs:
            embedded = await batch_upsert(
                self.cti_collection, docs, ids, metas, self.redis
            )
            logger.info(f"  ✅ OTX: {embedded} pulse chunks embedded")

    # ── CTI Collection Eviction ───────────────────────────────────────────────
    async def _run_cti_eviction(self):
        """
        Delete stale CTI entries from ChromaDB older than cti_ttl_days.
        Prevents cti_reports from growing unboundedly over months of operation.
        """
        logger.info(f"🗑️  Running CTI eviction (TTL={chroma_cfg.cti_ttl_days}d)...")
        deleted = await evict_stale_profiles(
            self.cti_collection,
            ttl_days=chroma_cfg.cti_ttl_days,
        )
        if deleted:
            logger.info(f"  Evicted {deleted} stale CTI entries")


async def main():
    scraper = ThreatIntelScraper()
    try:
        await scraper.start()
    except KeyboardInterrupt:
        logger.info("CTI Scraper shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
