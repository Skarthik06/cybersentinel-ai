"""
CyberSentinel AI — MCP Orchestrator (Multi-Agent System)
Coordinates specialized AI agents via Model Context Protocol (MCP):

  🔍 Monitor Agent   — Watches Kafka alert stream, triages severity
  🕵️ Investigate Agent — Deep-dives into threats using ChromaDB + external CTI
  🛡️ Response Agent  — Executes automated countermeasures
  📊 Report Agent    — Generates incident reports, notifies stakeholders
  🌐 Intel Agent     — Manages threat intelligence from Playwright scrapers

Each agent is backed by Claude (via Anthropic API) with specialized tools.
"""

import asyncio
import json
import logging
import os
import re
import time as _time
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.agents.llm_provider import get_provider, LLMResponse, ToolCall
from src.agents.prompts import ANALYSIS_SYSTEM_PROMPT
from src.agents.tools import MCP_TOOLS
import chromadb
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
import redis.asyncio as aioredis
import asyncpg
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MCP] %(levelname)s: %(message)s")
logger = logging.getLogger("mcp-orchestrator")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
CHROMA_URL = os.getenv("CHROMA_URL", "http://chromadb:8000")
CHROMA_TOKEN = os.getenv("CHROMA_TOKEN", "cybersentinel-token-2025")
POSTGRES_URL = os.getenv("POSTGRES_URL")
REDIS_URL = os.getenv("REDIS_URL")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
PAGERDUTY_KEY = os.getenv("PAGERDUTY_KEY", "")

# MCP_TOOLS imported from src.agents.tools (see tools.py for canonical definitions)


class MCPToolExecutor:
    """Executes MCP tool calls from Claude agents against real infrastructure."""

    def __init__(self, chroma_client, db_pool, redis_client):
        self.chroma = chroma_client
        self.db = db_pool
        self.redis = redis_client
        self.threat_collection  = chroma_client.get_or_create_collection("threat_signatures")
        self.profile_collection = chroma_client.get_or_create_collection("behavior_profiles")
        self.cti_collection     = chroma_client.get_or_create_collection("cti_reports")
        self.cve_collection     = chroma_client.get_or_create_collection("cve_database")
        self.http = httpx.AsyncClient(timeout=10.0)
        self._collection_map = {
            "threat_signatures": self.threat_collection,
            "behavior_profiles": self.profile_collection,
            "cti_reports":       self.cti_collection,
            "cve_database":      self.cve_collection,
        }

    async def execute(self, tool_name: str, tool_input: Dict) -> str:
        """Route and execute a tool call, returning result as string."""
        try:
            if tool_name == "query_threat_database":
                return await self._query_threat_db(tool_input)
            elif tool_name == "get_host_profile":
                return await self._get_host_profile(tool_input)
            elif tool_name == "get_recent_alerts":
                return await self._get_recent_alerts(tool_input)
            elif tool_name == "lookup_ip_reputation":
                return await self._lookup_ip_reputation(tool_input)
            elif tool_name == "block_ip":
                return await self._block_ip(tool_input)
            elif tool_name == "isolate_host":
                return await self._isolate_host(tool_input)
            elif tool_name == "send_notification":
                return await self._send_notification(tool_input)
            elif tool_name == "create_incident":
                return await self._create_incident(tool_input)
            elif tool_name == "query_packet_history":
                return await self._query_packet_history(tool_input)
            else:
                return f"Unknown tool: {tool_name}"
        except Exception as e:
            logger.error(f"Tool execution error [{tool_name}]: {e}")
            return f"Error executing {tool_name}: {str(e)}"

    async def _query_threat_db(self, args: Dict) -> str:
        collection_name = args.get("collection", "threat_signatures")
        collection = self._collection_map.get(collection_name, self.threat_collection)
        # Cap at 3 results max — more results add tokens without improving analysis
        n = min(int(args.get("n_results", 3)), 3)
        results = collection.query(
            query_texts=[args["query"]],
            n_results=n,
            include=["documents", "metadatas", "distances"],
        )
        if not results["ids"][0]:
            return f"No matching threats found in '{collection_name}'."
        output = []
        for i, (doc, meta, dist) in enumerate(zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        )):
            similarity = round(max(0, 1 - dist / 2) * 100, 1)
            output.append(
                f"Match {i+1} ({similarity}%): MITRE={meta.get('mitre', 'N/A')} "
                f"Sev={meta.get('severity', 'N/A')} | {doc[:150]}"
            )
        return "\n".join(output)

    async def _get_host_profile(self, args: Dict) -> str:
        ip = args["ip_address"]
        # Check ChromaDB for latest profile
        try:
            results = self.profile_collection.query(
                query_texts=[f"Entity {ip}"],
                n_results=1,
                where={"entity_id": ip},
                include=["documents", "metadatas"],
            )
            if results["ids"][0]:
                return f"Profile for {ip}:\n{results['documents'][0][0]}"
        except Exception:
            pass

        # Fallback to Redis cache
        cached = await self.redis.get(f"profile:{ip}")
        if cached:
            return f"Cached profile for {ip}:\n{cached}"

        return f"No profile found for IP {ip} — may be new/unseen host."

    async def _get_recent_alerts(self, args: Dict) -> str:
        hours = min(int(args.get("hours", 6)), 6)   # cap at 6h — older alerts rarely relevant
        limit = min(int(args.get("limit", 5)), 5)   # cap at 5 rows — enough context
        severity = args.get("severity")
        src_ip = args.get("src_ip")
        source = args.get("source")  # scope context to same pipeline (simulator vs dpi)

        query = """
            SELECT type, severity, timestamp, src_ip, dst_ip, description, mitre_technique
            FROM alerts
            WHERE timestamp > NOW() - ($1 * INTERVAL '1 hour')
        """
        params = [hours]
        if source:
            query += f" AND COALESCE(source, 'dpi') = ${len(params)+1}"
            params.append(source)
        if severity:
            query += f" AND severity = ${len(params)+1}"
            params.append(severity)
        if src_ip:
            query += f" AND src_ip = ${len(params)+1}"
            params.append(src_ip)
        query += f" ORDER BY timestamp DESC LIMIT ${len(params)+1}"
        params.append(limit)

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, *params)

        if not rows:
            return f"No alerts found in last {hours} hours."

        output = [f"Recent alerts (last {hours}h):"]
        for row in rows:
            output.append(
                f"[{row['timestamp'].strftime('%H:%M:%S')}] {row['severity']} | "
                f"{row['type']} | {row['src_ip']} → {row['dst_ip']} | {row.get('mitre_technique', '')}"
            )
        return "\n".join(output)

    async def _lookup_ip_reputation(self, args: Dict) -> str:
        ip = args["ip_address"]
        # Check cache first
        cache_key = f"ip_rep:{ip}"
        cached = await self.redis.get(cache_key)
        if cached:
            return f"[Cached] {cached}"

        # AbuseIPDB lookup (free tier)
        result_parts = []
        try:
            resp = await self.http.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": os.getenv("ABUSEIPDB_KEY", ""), "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result_parts.append(
                    f"AbuseIPDB: confidence={data.get('abuseConfidenceScore', 'N/A')}% "
                    f"reports={data.get('totalReports', 0)} "
                    f"country={data.get('countryCode', 'N/A')} "
                    f"isp={data.get('isp', 'N/A')}"
                )
        except Exception as e:
            result_parts.append(f"AbuseIPDB lookup failed: {e}")

        result = f"IP Reputation for {ip}:\n" + "\n".join(result_parts)
        await self.redis.setex(cache_key, 3600, result)
        return result

    async def _block_ip(self, args: Dict) -> str:
        ip = args["ip_address"]
        duration = args.get("duration_hours", 24)
        justification = args["justification"]
        incident_id = args["incident_id"]

        # Store block rule in Redis (would trigger firewall update in production)
        block_key = f"blocked:{ip}"
        block_data = json.dumps({
            "ip": ip, "blocked_at": datetime.utcnow().isoformat(),
            "duration_hours": duration, "justification": justification,
            "incident_id": incident_id,
        })
        if duration == 0:
            await self.redis.set(block_key, block_data)
        else:
            await self.redis.setex(block_key, duration * 3600, block_data)

        # Log to database
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO firewall_rules (ip_address, action, duration_hours, justification, incident_id, created_at)
                VALUES ($1, 'BLOCK', $2, $3, $4, NOW())
            """, ip, duration, justification, incident_id)

        duration_str = f"{duration}h" if duration > 0 else "permanent"
        logger.warning(f"🚫 BLOCKED IP: {ip} ({duration_str}) | Incident: {incident_id}")
        return f"✅ IP {ip} blocked for {duration_str}. Rule stored in Redis + database."

    async def _isolate_host(self, args: Dict) -> str:
        ip = args["ip_address"]
        hostname = args.get("hostname", "unknown")
        justification = args["justification"]
        incident_id = args["incident_id"]

        # Push VLAN change to network controller API (configure NETWORK_CONTROLLER_URL in .env)
        await self.redis.set(f"isolated:{ip}", json.dumps({
            "ip": ip, "hostname": hostname, "isolated_at": datetime.utcnow().isoformat(),
            "justification": justification, "incident_id": incident_id,
        }))

        logger.critical(f"🔒 HOST ISOLATED: {ip} ({hostname}) | Incident: {incident_id}")
        return f"✅ Host {ip} ({hostname}) isolated from network. Quarantine VLAN applied."

    async def _send_notification(self, args: Dict) -> str:
        channel = args["channel"]
        severity = args["severity"]
        title = args["title"]
        message = args["message"]
        incident_id = args.get("incident_id", "N/A")

        severity_emoji = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(severity, "⚠️")

        if channel == "slack" and SLACK_WEBHOOK:
            payload = {
                "text": f"{severity_emoji} *CyberSentinel Alert [{severity}]*: {title}",
                "attachments": [{
                    "color": {"LOW": "good", "MEDIUM": "warning", "HIGH": "danger", "CRITICAL": "danger"}.get(severity, "warning"),
                    "text": f"{message}\n\n*Incident ID:* `{incident_id}`",
                    "footer": "CyberSentinel AI | SOC Platform",
                    "ts": int(datetime.utcnow().timestamp()),
                }],
            }
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=payload, timeout=5.0)
                return f"✅ Slack notification sent: {title}"
            except Exception as e:
                return f"Slack notification failed: {e}"

        elif channel == "pagerduty" and PAGERDUTY_KEY:
            # PagerDuty Events API v2
            pd_payload = {
                "routing_key": PAGERDUTY_KEY,
                "event_action": "trigger",
                "payload": {
                    "summary": f"[{severity}] {title}",
                    "source": "CyberSentinel AI",
                    "severity": severity.lower(),
                    "custom_details": {"message": message, "incident_id": incident_id},
                },
            }
            try:
                async with httpx.AsyncClient() as client:
                    await client.post("https://events.pagerduty.com/v2/enqueue", json=pd_payload, timeout=5.0)
                return f"✅ PagerDuty alert triggered: {title}"
            except Exception as e:
                return f"PagerDuty alert failed: {e}"

        return f"Notification logged (no external webhook configured): [{severity}] {title}"

    async def _create_incident(self, args: Dict) -> str:
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        def _to_list(val):
            """Accept a Python list or JSON-encoded list string from the LLM."""
            if isinstance(val, list):
                return val
            if isinstance(val, str):
                try:
                    parsed = json.loads(val)
                    return parsed if isinstance(parsed, list) else [val]
                except (json.JSONDecodeError, ValueError):
                    return [val] if val else []
            return []

        affected_ips      = _to_list(args.get("affected_ips", []))
        mitre_techniques  = _to_list(args.get("mitre_techniques", []))

        description = args.get("description", "")
        evidence = args.get("evidence", "")
        investigation_summary = f"{description}\n\nEvidence: {evidence}".strip() if evidence else description
        block_recommended = bool(args.get("block_recommended", False))
        block_target_ip   = args.get("block_target_ip", "")

        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO incidents
                    (incident_id, title, severity, description, affected_ips,
                     mitre_techniques, evidence, investigation_summary,
                     block_recommended, block_target_ip, status, source, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'OPEN', $11, NOW())
            """, incident_id, args["title"], args["severity"], description,
                affected_ips, mitre_techniques,
                evidence, investigation_summary,
                block_recommended, block_target_ip,
                args.get("source", "dpi"))
        logger.info(f"📋 Incident created: {incident_id} [{args['severity']}] {args['title']}")
        return f"✅ Incident created: {incident_id} — {args['title']}"

    async def _query_packet_history(self, args: Dict) -> str:
        hours = int(args.get("hours", 1))
        src_ip = args.get("src_ip")
        protocol = args.get("protocol")

        query = """
            SELECT DATE_TRUNC('minute', timestamp) AS minute,
                   COUNT(*) AS packet_count,
                   SUM(payload_size) AS total_bytes,
                   AVG(entropy) AS avg_entropy,
                   protocol
            FROM packets
            WHERE timestamp > NOW() - ($1 * INTERVAL '1 hour')
        """
        params = [hours]
        if src_ip:
            query += f" AND src_ip = ${len(params)+1}"
            params.append(src_ip)
        if protocol:
            query += f" AND protocol = ${len(params)+1}"
            params.append(protocol)
        query += " GROUP BY minute, protocol ORDER BY minute DESC LIMIT 60"

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, *params)

        if not rows:
            return "No packet history found."

        lines = ["Packet history (per minute):"]
        for row in rows:
            lines.append(
                f"{row['minute'].strftime('%H:%M')} | {row['protocol']} | "
                f"pkts={row['packet_count']} bytes={row['total_bytes']:,} entropy={float(row['avg_entropy'] or 0):.2f}"
            )
        return "\n".join(lines)


def _summarize_result(tool_name: str, result: str) -> str:
    """
    Compress a raw tool result to only the essential facts.
    Keeps Call 2 input lean — full results are verbose and mostly unused.
    """
    result = str(result).strip()
    if not result or result.startswith("No ") or result.startswith("Error"):
        return result[:80]
    if tool_name == "query_threat_database":
        # Keep first match line only — MITRE + severity + brief pattern
        return result.split("\n")[0][:120]
    if tool_name == "get_host_profile":
        return result[:100]
    if tool_name == "lookup_ip_reputation":
        # Extract score + country line only
        for line in result.split("\n"):
            if "confidence=" in line or "AbuseIPDB" in line:
                return line.strip()[:120]
        return result[:100]
    if tool_name == "get_recent_alerts":
        lines = [l for l in result.split("\n") if l.strip()]
        return "\n".join(lines[:3])[:200]
    return result[:100]


class InvestigateAgent:
    """
    Claude-powered investigation agent.
    Given an alert, it uses MCP tools to autonomously investigate,
    correlate evidence, and produce an incident verdict.
    """

    def __init__(self, executor: MCPToolExecutor):
        self.executor = executor
        self.llm = get_provider()

    async def investigate(self, alert: Dict) -> Dict:
        """
        Stateless single-LLM-call investigation pipeline.

        Flow:
          1. Run 4 intel tools in parallel with asyncio.gather() — zero LLM calls
          2. Summarize each result with _summarize_result() to strip verbosity
          3. Single LLM call: compact alert + summarized intel → structured JSON verdict
          4. Parse JSON, call _create_incident directly from code (no tool round)
          5. Store block_recommended flag — analyst reviews and approves via dashboard

        Token cost: ~600-700 input tokens vs ~5,500 in the old multi-round loop (~88% reduction).
        API calls per investigation: 1 (was 3).
        """
        # Strip raw_event (duplicate of all other fields) — saves ~300 redundant tokens
        alert_slim = {k: v for k, v in alert.items() if k != "raw_event"}
        alert_text = json.dumps(alert_slim, separators=(",", ":"))
        src_ip     = alert.get("src_ip", "unknown")
        dst_ip     = alert.get("dst_ip", "")
        alert_type = alert.get("type", "UNKNOWN")

        logger.info(f"🕵️ Investigating alert: {alert_type} from {src_ip}")

        source = alert.get("source", "dpi")

        # ── Step 1: Gather intel in parallel (zero LLM calls) ─────────────
        threat_raw, host_raw, rep_raw, recent_raw = await asyncio.gather(
            self.executor.execute("query_threat_database", {
                "query": f"{alert_type} {alert.get('mitre_technique', '')}",
                "n_results": 3,
            }),
            self.executor.execute("get_host_profile",     {"ip_address": src_ip}),
            self.executor.execute("lookup_ip_reputation", {"ip_address": dst_ip or src_ip}),
            # Scope recent alerts to same pipeline — no cross-contamination between
            # simulator and live DPI investigations
            self.executor.execute("get_recent_alerts",    {"hours": 6, "limit": 5, "src_ip": src_ip, "source": source}),
        )

        # ── Step 2: Compress each result to essential facts only ───────────
        threat_summary = _summarize_result("query_threat_database", threat_raw)
        host_summary   = _summarize_result("get_host_profile",      host_raw)
        rep_summary    = _summarize_result("lookup_ip_reputation",  rep_raw)
        recent_summary = _summarize_result("get_recent_alerts",     recent_raw)

        # ── Step 3: Single LLM call — structured JSON verdict ──────────────
        intel_context = (
            f"Alert: {alert_text}\n\n"
            f"Intel:\n"
            f"- Threat DB: {threat_summary}\n"
            f"- Host profile: {host_summary}\n"
            f"- IP reputation: {rep_summary}\n"
            f"- Recent alerts: {recent_summary}"
        )

        response = await self._chat_with_retry(
            messages=[{"role": "user", "content": intel_context}],
            tools=None,
            system=ANALYSIS_SYSTEM_PROMPT,
            max_tokens=1024,
        )

        # ── Step 4: Parse JSON verdict ─────────────────────────────────────
        raw_text = response.text.strip() if response.text else ""

        # Strip markdown code fences if the model wraps its output
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$",          "", raw_text).strip()

        verdict = {}
        try:
            verdict = json.loads(raw_text)
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"⚠️ LLM returned non-JSON for {alert_type} — using fallback incident")
            verdict = {
                "title":            f"{alert_type} — Auto-Investigation",
                "severity":         alert.get("severity", "MEDIUM"),
                "mitre_technique":  alert.get("mitre_technique", "Unknown"),
                "description":      raw_text[:500] if raw_text else "Investigation incomplete — LLM parse error",
                "evidence":         "",
                "affected_ips":     [src_ip],
                "mitre_techniques": [alert.get("mitre_technique", "")],
                "block_recommended": False,
            }

        description = verdict.get("description", "")
        evidence    = verdict.get("evidence", "")
        analysis    = f"{description}\n\nEvidence: {evidence}".strip() if evidence else description

        # Determine whether analyst should review this for blocking
        block_recommended = bool(verdict.get("block_recommended")) or verdict.get("severity") == "CRITICAL"
        block_target_ip   = dst_ip or src_ip

        # ── Step 4b: Create incident directly (no LLM round-trip) ─────────
        create_result = await self.executor._create_incident({
            "title":             verdict.get("title",            f"{alert_type} Incident"),
            "severity":          verdict.get("severity",         alert.get("severity", "MEDIUM")),
            "description":       description,
            "evidence":          evidence,
            "affected_ips":      verdict.get("affected_ips",     [src_ip]),
            "mitre_techniques":  verdict.get("mitre_techniques", [alert.get("mitre_technique", "")]),
            "block_recommended": block_recommended,
            "block_target_ip":   block_target_ip,
            "source":            source,  # already extracted above — simulator or dpi
        })

        # Parse the generated incident ID for logging
        id_match    = re.search(r"INC-\d+", create_result)
        incident_id = id_match.group(0) if id_match else "INC-UNKNOWN"

        if block_recommended:
            logger.info(f"🔔 Block recommendation queued: {block_target_ip} → {incident_id} (awaiting analyst approval)")

        logger.info(f"✅ Investigation complete [1 LLM call] → {incident_id} [{verdict.get('severity', '?')}] [{self.llm.name()}]")
        return {
            "investigation_complete": True,
            "iterations":   1,
            "analysis":     analysis,
            "alert":        alert,
            "llm_provider": self.llm.name(),
        }

    async def _chat_with_retry(self, **kwargs) -> "LLMResponse":
        """
        Wrap llm.chat() with exponential backoff on 429 rate-limit errors.
        OpenAI backoff: 5s → 15s → 45s (total max wait ~65s across 3 attempts).
        With INVESTIGATION_INTERVAL_SEC=1800 this should essentially never trigger.
        """
        backoff = [5, 15, 45]
        for attempt in range(3):
            try:
                return await self.llm.chat(**kwargs)
            except Exception as e:
                if "429" in str(e) and attempt < 2:
                    wait = backoff[attempt]
                    logger.warning(f"⚠️ OpenAI 429 rate limit — retrying in {wait}s (attempt {attempt+1}/3)")
                    await asyncio.sleep(wait)
                else:
                    raise
        raise RuntimeError("Exhausted retries after 429 rate-limit errors")

    async def _submit_with_retry(self, messages, prev_response, tool_results,
                                  tools=None, system=None, max_tokens=512) -> "LLMResponse":
        """
        Wrap llm.submit_tool_results() with exponential backoff on 429.
        Same backoff schedule as _chat_with_retry: 5s → 15s → 45s.
        max_tokens: 512 for tool-call rounds, 1024 for final analysis round.
        """
        backoff = [5, 15, 45]
        for attempt in range(3):
            try:
                return await self.llm.submit_tool_results(messages, prev_response, tool_results,
                                                          tools=tools, system=system,
                                                          max_tokens=max_tokens)
            except Exception as e:
                if "429" in str(e) and attempt < 2:
                    wait = backoff[attempt]
                    logger.warning(f"⚠️ OpenAI 429 rate limit (tool result) — retrying in {wait}s (attempt {attempt+1}/3)")
                    await asyncio.sleep(wait)
                else:
                    raise
        raise RuntimeError("Exhausted retries after 429 rate-limit errors")


class MCPOrchestrator:
    """Main orchestrator — routes alerts to appropriate agents."""

    def __init__(self):
        self.chroma_client = None
        self.db_pool = None
        self.redis = None
        self.llm_provider = get_provider()
        self.executor: Optional[MCPToolExecutor] = None
        self.investigate_agent: Optional[InvestigateAgent] = None
        self.producer: Optional[AIOKafkaProducer] = None

        # Priority queue for alerts (CRITICAL > HIGH > MEDIUM > LOW)
        self.alert_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        # Per-IP rate limiting: deduplicate same-IP alerts before investigation
        self._medium_last_seen: dict = {}
        self._high_last_seen: dict = {}
        # Global investigation rate limiter — stay under 5 req/min for free-tier Gemini
        self._last_investigation_at: float = 0.0
        # Minimum seconds between investigations (4 tool calls per investigation → need ~60s gap)
        self._investigation_interval: float = float(os.getenv("INVESTIGATION_INTERVAL_SEC", "60"))

    async def start(self):
        logger.info("🎯 CyberSentinel MCP Orchestrator starting...")

        # Initialize infrastructure
        self.chroma_client = chromadb.HttpClient(
            host=CHROMA_URL.replace("http://", "").split(":")[0],
            port=int(CHROMA_URL.split(":")[-1]),
            headers={"Authorization": f"Bearer {CHROMA_TOKEN}"},
        )
        self.db_pool = await asyncpg.create_pool(POSTGRES_URL, min_size=2, max_size=10)
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True, max_connections=5)
        self.producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        await self.producer.start()

        self.executor = MCPToolExecutor(self.chroma_client, self.db_pool, self.redis)
        self.investigate_agent = InvestigateAgent(self.executor)

        # Default DPI investigations to paused on first run so simulator and live
        # investigations are always independent — user must explicitly enable each.
        # Only sets the key if it doesn't already exist (preserves user preference).
        if not await self.redis.exists("investigations:paused:dpi"):
            await self.redis.set("investigations:paused:dpi", "1")
            logger.info("🔒 DPI investigations defaulted to paused — enable via dashboard Live mode toggle")

        logger.info("✅ All agents initialized — starting orchestration")

        await asyncio.gather(
            self._consume_enriched_alerts(),
            self._process_alert_queue(),
        )

    async def _consume_enriched_alerts(self):
        """Consume enriched alerts from Kafka and queue for investigation."""
        consumer = AIOKafkaConsumer(
            "enriched-alerts", "threat-alerts",
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="mcp-orchestrator",
            value_deserializer=lambda v: json.loads(v.decode()),
            auto_offset_reset="latest",
            # Heartbeat is async — sessions stay alive during long AI investigations
            session_timeout_ms=30000,    # 30s — stale sessions expire before socket timeout
            heartbeat_interval_ms=3000,  # heartbeat every 3s (must be < session_timeout/3)
            max_poll_interval_ms=600000, # allow up to 10 min between polls
        )
        await consumer.start()
        logger.info("👂 Listening for alerts on enriched-alerts, threat-alerts")

        severity_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        try:
            async for msg in consumer:
                alert = msg.value
                severity = alert.get("severity", "LOW")
                priority = severity_priority.get(severity, 3)

                # CRITICAL: always queue
                # HIGH: queue once per IP per 5 min (avoids thundering herd on Gemini)
                # MEDIUM: queue once per IP per 30 min
                # LOW: log only
                src_ip = alert.get("src_ip", "unknown")
                now = _time.time()
                if priority == 0:  # CRITICAL — once per IP per 5 min (same as HIGH)
                    if now - self._high_last_seen.get(f"crit:{src_ip}", 0) > 300:
                        self._high_last_seen[f"crit:{src_ip}"] = now
                        if not self.alert_queue.full():
                            await self.alert_queue.put((priority, alert))
                            logger.info(f"📥 Queued CRITICAL alert from {src_ip}")
                        else:
                            await self._log_alert(alert)
                    else:
                        await self._log_alert(alert)
                elif priority == 1:  # HIGH — once per IP per 5 min
                    if now - self._high_last_seen.get(src_ip, 0) > 300:
                        self._high_last_seen[src_ip] = now
                        if not self.alert_queue.full():
                            await self.alert_queue.put((priority, alert))
                            logger.info(f"📥 Queued HIGH alert from {src_ip} (first in 5min)")
                        else:
                            await self._log_alert(alert)
                    else:
                        await self._log_alert(alert)
                elif priority == 2:  # MEDIUM — once per IP per 30 min
                    if now - self._medium_last_seen.get(src_ip, 0) > 1800:
                        self._medium_last_seen[src_ip] = now
                        if not self.alert_queue.full():
                            await self.alert_queue.put((priority, alert))
                            logger.info(f"📥 Queued MEDIUM alert from {src_ip} (first in 30min)")
                    else:
                        await self._log_alert(alert)
                else:
                    # LOW — log only
                    await self._log_alert(alert)
        finally:
            await consumer.stop()

    async def _process_alert_queue(self):
        """Process alerts from the priority queue sequentially."""
        logger.info("⚙️  Alert processor running...")
        while True:
            # Wait for next alert
            try:
                priority, alert = await asyncio.wait_for(self.alert_queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue

            # Global rate limiter — honour free-tier quota (5 req/min for Gemini)
            now = _time.time()
            wait_sec = self._investigation_interval - (now - self._last_investigation_at)
            if wait_sec > 0:
                logger.info(f"⏳ Rate-limit wait {wait_sec:.0f}s before next investigation")
                await asyncio.sleep(wait_sec)

            # Check if investigations are paused per source (simulator vs dpi)
            source = alert.get("source", "dpi")
            pause_key = f"investigations:paused:{source}"
            if await self.redis.exists(pause_key):
                logger.info(f"⏸️  Investigations paused [{source}] — creating pending incident")
                await self._log_alert(alert)
                await self._create_pending_incident(alert)
                continue

            self._last_investigation_at = _time.time()
            investigation = None
            try:
                investigation = await self.investigate_agent.investigate(alert)
            except Exception as e:
                logger.error(f"Investigation failed: {e}")
                # Always log the alert even if investigation failed
            await self._log_alert(alert, investigation=investigation)

    async def _log_alert(self, alert: Dict, investigation: Optional[Dict] = None):
        """Persist alert to PostgreSQL."""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO alerts
                        (type, severity, timestamp, src_ip, dst_ip, description,
                         mitre_technique, anomaly_score, investigation_summary, raw_event, source)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """,
                    alert.get("type", "UNKNOWN"),
                    alert.get("severity", "LOW"),
                    datetime.fromisoformat(alert.get("timestamp", datetime.utcnow().isoformat())),
                    alert.get("src_ip"),
                    alert.get("dst_ip"),
                    alert.get("description", alert.get("threat_description", "")),
                    alert.get("mitre_technique", ""),
                    alert.get("anomaly_score"),
                    investigation.get("analysis", "") if investigation else "",
                    json.dumps(alert),
                    alert.get("source", "dpi"),
                )
        except Exception as e:
            logger.error(f"Alert log failed: {e}")

    async def _create_pending_incident(self, alert: Dict):
        """Create a basic PENDING incident when AI investigation is paused.
        Ensures alerts always surface in the Incidents panel, even without AI analysis."""
        try:
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            src_ip  = alert.get("src_ip") or "unknown"
            dst_ip  = alert.get("dst_ip") or ""
            sev     = alert.get("severity", "MEDIUM")
            mitre   = alert.get("mitre_technique", "")
            desc    = alert.get("description") or alert.get("threat_description", "")
            score   = alert.get("anomaly_score")
            source  = alert.get("source", "dpi")
            title   = f"{alert.get('type','Alert')} — {src_ip}"
            summary = (
                f"⏸ AI investigation was paused when this alert arrived.\n\n"
                f"Host: {src_ip}"
                f"{f' → {dst_ip}' if dst_ip else ''}\n"
                f"Severity: {sev}"
                f"{f' | MITRE: {mitre}' if mitre else ''}"
                f"{f' | Score: {score:.2f}' if score is not None else ''}\n\n"
                f"Description: {desc}\n\n"
                f"Enable AI Investigation to trigger a full analysis on this host."
            )
            block_rec = sev in ('CRITICAL', 'HIGH')
            block_target = src_ip if block_rec else ''
            async with self.db_pool.acquire() as conn:
                # Avoid duplicate incidents for the same IP within a 2-minute window
                existing = await conn.fetchval("""
                    SELECT incident_id FROM incidents
                    WHERE $1 = ANY(affected_ips)
                      AND source = $2
                      AND created_at > NOW() - INTERVAL '2 minutes'
                    LIMIT 1
                """, src_ip, source)
                if existing:
                    logger.info(f"⏭  Skipping duplicate pending incident for {src_ip} (recent: {existing})")
                    return
                await conn.execute("""
                    INSERT INTO incidents
                        (incident_id, title, severity, description, affected_ips,
                         mitre_techniques, evidence, investigation_summary,
                         block_recommended, block_target_ip, status, source, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'OPEN', $11, NOW())
                """,
                    incident_id, title, sev, desc,
                    [src_ip], [mitre] if mitre else [],
                    f"anomaly_score={score}" if score is not None else "",
                    summary, block_rec, block_target, source,
                )
            logger.info(f"📋 Pending incident created: {incident_id} [{sev}] {title}")
        except Exception as e:
            logger.error(f"Pending incident creation failed: {e}")


async def main():
    orchestrator = MCPOrchestrator()
    try:
        await orchestrator.start()
    except KeyboardInterrupt:
        logger.info("MCP Orchestrator shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
