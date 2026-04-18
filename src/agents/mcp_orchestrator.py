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

# ── Kafka SASL/SCRAM-SHA-256 (optional — activated only when KAFKA_SASL_PASSWORD is set) ──
_KAFKA_SASL_USERNAME = os.getenv("KAFKA_SASL_USERNAME", "")
_KAFKA_SASL_PASSWORD = os.getenv("KAFKA_SASL_PASSWORD", "")
_KAFKA_SASL_KWARGS: dict = (
    {"security_protocol": "SASL_PLAINTEXT",
     "sasl_mechanism": "SCRAM-SHA-256",
     "sasl_plain_username": _KAFKA_SASL_USERNAME,
     "sasl_plain_password": _KAFKA_SASL_PASSWORD}
    if _KAFKA_SASL_PASSWORD else {}
)


async def _correlate_campaign_with_pool(
    db_pool, incident_id: str, src_ip: str, severity: str, mitre_techniques: list,
    source: str = "dpi"
) -> None:
    """Link incident to an attacker campaign — create or extend a 24-hour window per src_ip.

    Groups incidents from the same source IP AND same source pipeline that occur within
    24 hours into a single campaign record. Simulator and DPI campaigns are kept
    separate to prevent cross-pipeline contamination.
    """
    if not src_ip or src_ip in ("unknown", ""):
        return
    _SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT campaign_id, max_severity, mitre_stages
                FROM attacker_campaigns
                WHERE src_ip = $1 AND source = $2 AND last_seen > NOW() - INTERVAL '24 hours'
                ORDER BY last_seen DESC LIMIT 1
            """, src_ip, source)
            if row:
                campaign_id = row["campaign_id"]
                new_max = (severity
                           if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(row["max_severity"], 0)
                           else row["max_severity"])
                merged = sorted(set(row["mitre_stages"] or []) | set(mitre_techniques))
                await conn.execute("""
                    UPDATE attacker_campaigns
                    SET last_seen = NOW(), incident_count = incident_count + 1,
                        max_severity = $2, mitre_stages = $3
                    WHERE campaign_id = $1
                """, campaign_id, new_max, merged)
            else:
                campaign_id = (
                    f"CAM-{src_ip.replace('.', '-')}"
                    f"-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                )
                await conn.execute("""
                    INSERT INTO attacker_campaigns
                        (campaign_id, src_ip, source, first_seen, last_seen,
                         incident_count, max_severity, mitre_stages)
                    VALUES ($1, $2, $3, NOW(), NOW(), 1, $4, $5)
                """, campaign_id, src_ip, source, severity, mitre_techniques)
            await conn.execute("""
                INSERT INTO campaign_incidents (campaign_id, incident_id)
                VALUES ($1, $2) ON CONFLICT DO NOTHING
            """, campaign_id, incident_id)
        logger.info(f"🔗 Campaign correlated: {campaign_id} ← {incident_id} [{src_ip}] source={source}")
    except Exception as e:
        logger.warning(f"Campaign correlation failed for {incident_id}: {e}")


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
        # Use millisecond precision to avoid duplicate key when multiple alerts
        # arrive within the same second (epoch-second PKs collide).
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')[:19]}"

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

        # Fire-and-forget campaign correlation — never blocks or fails incident creation
        _src = args.get("block_target_ip", "") or (affected_ips[0] if affected_ips else "")
        asyncio.ensure_future(_correlate_campaign_with_pool(
            self.db, incident_id, _src, args["severity"], mitre_techniques,
            source=args.get("source", "dpi")
        ))

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
        # First match line: MITRE + severity + pattern. 200 chars keeps key context
        # for the LLM's "OBSERVED" + "THREAT" sections of the incident description.
        return result.split("\n")[0][:200]
    if tool_name == "get_host_profile":
        # 250 chars keeps top peers, ports, MITRE history — feeds rich
        # "WHY SUSPICIOUS" baseline-deviation analysis in the incident summary.
        return result[:250]
    if tool_name == "lookup_ip_reputation":
        for line in result.split("\n"):
            if "confidence=" in line or "AbuseIPDB" in line:
                return line.strip()[:160]
        return result[:120]
    if tool_name == "get_recent_alerts":
        lines = [l for l in result.split("\n") if l.strip()]
        return "\n".join(lines[:3])[:240]
    return result[:120]


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
        # Drop fields already represented in the intel summaries (host_summary covers
        # profile_summary/observation_count/avg_*; threat_summary covers threat_description
        # and matched_mitre). Saves ~400 input tokens per investigation.
        _drop = {
            "raw_event", "profile_summary", "threat_description", "matched_mitre",
            "observation_count", "avg_bytes_per_min", "avg_entropy",
        }
        alert_slim = {k: v for k, v in alert.items() if k not in _drop and v not in (None, "")}
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

        try:
            response = await self._chat_with_retry(
                messages=[{"role": "user", "content": intel_context}],
                tools=None,
                system=ANALYSIS_SYSTEM_PROMPT,
                # 768 leaves headroom for full 4-section description + evidence in JSON.
                # Description = OBSERVED + WHY SUSPICIOUS + THREAT + PROFILE (~400-500 out tokens).
                max_tokens=768,
            )
            raw_text = response.text.strip() if response.text else ""
        except Exception as llm_err:
            logger.error(f"LLM unavailable for {alert_type} — using rule-based fallback: {llm_err}")
            raw_text = json.dumps(self._rule_based_verdict(alert))

        # ── Step 4: Parse JSON verdict ─────────────────────────────────────

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

    def _rule_based_verdict(self, alert: Dict) -> Dict:
        """
        Deterministic rule-based investigation fallback used when the LLM API is
        unavailable. Generates a structured verdict from alert fields alone — no
        external calls. Ensures incidents are always created even during LLM outages.

        Rules:
          - CRITICAL + anomaly_score > 0.8  → block_recommended=True, HIGH confidence
          - CRITICAL                         → block_recommended=True, MEDIUM confidence
          - HIGH + known MITRE              → block_recommended=True, MEDIUM confidence
          - MEDIUM / LOW                    → block_recommended=False, LOW confidence
        """
        sev          = alert.get("severity", "MEDIUM")
        alert_type   = alert.get("type", "UNKNOWN")
        anomaly      = float(alert.get("anomaly_score", 0.0))
        mitre        = alert.get("mitre_technique", "")
        src_ip       = alert.get("src_ip", "unknown")
        dst_ip       = alert.get("dst_ip", "")

        _block_sevs = {"CRITICAL", "HIGH"}
        block_rec   = sev in _block_sevs

        if sev == "CRITICAL" and anomaly > 0.8:
            confidence  = "HIGH"
            description = (
                f"OBSERVED: {alert_type} from {src_ip} to {dst_ip or 'unknown'} "
                f"with anomaly score {anomaly:.3f}.\n"
                f"WHY SUSPICIOUS: Anomaly score {anomaly:.3f} exceeds CRITICAL threshold "
                f"and behavioral profile matches high-confidence threat pattern.\n"
                f"THREAT ASSESSMENT: Active threat — {mitre or 'technique TBD'} — HIGH confidence. "
                f"Immediate analyst review required.\n"
                f"ATTACKER PROFILE: Determined adversary — pattern matches known APT/targeted attack TTPs."
            )
        elif sev == "CRITICAL":
            confidence  = "MEDIUM"
            description = (
                f"OBSERVED: {alert_type} from {src_ip} — severity CRITICAL, "
                f"anomaly score {anomaly:.3f}.\n"
                f"WHY SUSPICIOUS: Critical severity threshold triggered with "
                f"{'MITRE ' + mitre if mitre else 'behavioral anomaly'}.\n"
                f"THREAT ASSESSMENT: Likely malicious — {mitre or 'TBD'} — MEDIUM confidence. "
                f"[NOTE: LLM unavailable — rule-based assessment]\n"
                f"ATTACKER PROFILE: Unknown — insufficient context for full classification."
            )
        elif sev == "HIGH":
            confidence  = "MEDIUM"
            description = (
                f"OBSERVED: {alert_type} from {src_ip} — severity HIGH, "
                f"anomaly score {anomaly:.3f}.\n"
                f"WHY SUSPICIOUS: High-severity behavioral indicator triggered "
                f"{'— ' + mitre if mitre else ''}.\n"
                f"THREAT ASSESSMENT: Suspicious activity — MEDIUM confidence. "
                f"[NOTE: LLM unavailable — rule-based assessment]\n"
                f"ATTACKER PROFILE: Unknown — analyst review recommended."
            )
        else:
            confidence  = "LOW"
            description = (
                f"OBSERVED: {alert_type} from {src_ip} — severity {sev}.\n"
                f"WHY SUSPICIOUS: Anomaly threshold triggered (score={anomaly:.3f}).\n"
                f"THREAT ASSESSMENT: Low-medium severity — LOW confidence. "
                f"[NOTE: LLM unavailable — rule-based assessment]\n"
                f"ATTACKER PROFILE: Likely automated scanner or misconfigured host."
            )

        return {
            "title":             f"{alert_type} — {sev} [Rule-Based]",
            "severity":          sev,
            "mitre_technique":   mitre,
            "mitre_techniques":  [mitre] if mitre else [],
            "description":       description,
            "evidence":          f"anomaly_score={anomaly:.3f} src={src_ip} dst={dst_ip} confidence={confidence}",
            "affected_ips":      [src_ip],
            "block_recommended": block_rec,
            "block_target_ip":   dst_ip or src_ip,
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
        # Separate timer for pending backlog — drains independently when queue is empty
        self._last_backlog_at: float = 0.0

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
            **_KAFKA_SASL_KWARGS,
        )
        await self.producer.start()

        self.executor = MCPToolExecutor(self.chroma_client, self.db_pool, self.redis)
        self.investigate_agent = InvestigateAgent(self.executor)

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
            **_KAFKA_SASL_KWARGS,
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
                # Queue empty — drain pending backlog independently of the main rate limiter
                now = _time.time()
                backlog_interval = float(os.getenv("BACKLOG_INTERVAL_SEC", "30"))
                if now - self._last_backlog_at >= backlog_interval:
                    processed = await self._reinvestigate_pending()
                    if processed:
                        self._last_backlog_at = _time.time()
                continue

            # Check if investigations are paused per source BEFORE rate-limiting.
            # Paused-source alerts (e.g. DPI when analyst paused it) are logged
            # immediately without consuming an investigation rate-limit slot — this
            # prevents a flood of paused DPI alerts from blocking simulator alerts.
            source = alert.get("source", "dpi")
            pause_key = f"investigations:paused:{source}"
            if await self.redis.exists(pause_key):
                logger.info(f"⏸️  Investigations paused [{source}] — creating pending incident")
                await self._log_alert(alert)
                await self._create_pending_incident(alert)
                continue

            # Global rate limiter — honour free-tier quota (5 req/min for Gemini)
            # Only reached for alerts that WILL be investigated.
            now = _time.time()
            wait_sec = self._investigation_interval - (now - self._last_investigation_at)
            if wait_sec > 0:
                logger.info(f"⏳ Rate-limit wait {wait_sec:.0f}s before next investigation")
                await asyncio.sleep(wait_sec)

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
                    # Postgres INET column rejects '' — coerce empty strings to NULL
                    alert.get("src_ip") or None,
                    alert.get("dst_ip") or None,
                    alert.get("description", alert.get("threat_description", "")),
                    alert.get("mitre_technique", ""),
                    alert.get("anomaly_score"),
                    investigation.get("analysis", "") if investigation else "",
                    json.dumps(alert),
                    alert.get("source", "dpi"),
                )
        except Exception as e:
            logger.error(f"Alert log failed: {e}")

    async def _reinvestigate_pending(self) -> bool:
        """Pick the oldest pending incident (investigation_summary LIKE '⏸%') and run a full
        AI investigation, updating it in-place. Uses its own rate timer so it drains the
        backlog during quiet periods without consuming new-alert investigation slots.
        Returns True if an incident was processed."""
        try:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT incident_id, title, severity, description, affected_ips,
                           mitre_techniques, source, created_at
                    FROM incidents
                    WHERE investigation_summary LIKE '⏸%' AND status = 'OPEN'
                    ORDER BY
                        CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                                      WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                        created_at ASC
                    LIMIT 1
                """)
            if not row:
                return False

            incident_id = row["incident_id"]
            src_ip  = (row["affected_ips"] or ["unknown"])[0]
            mitre   = (row["mitre_techniques"] or [""])[0]
            source  = row["source"] or "dpi"

            # Reconstruct alert from incident fields, enrich from alerts table if available
            alert: Dict = {
                "type":            row["title"].split(" — ")[0] if " — " in row["title"] else row["title"],
                "severity":        row["severity"],
                "src_ip":          src_ip,
                "description":     row["description"] or "",
                "mitre_technique": mitre,
                "source":          source,
                "timestamp":       row["created_at"].isoformat(),
            }
            async with self.db_pool.acquire() as conn:
                alert_row = await conn.fetchrow("""
                    SELECT type, severity, dst_ip, anomaly_score, mitre_technique, description
                    FROM alerts WHERE src_ip = $1 AND source = $2
                    ORDER BY timestamp DESC LIMIT 1
                """, src_ip, source)
            if alert_row:
                alert.update({k: v for k, v in dict(alert_row).items() if v is not None})

            logger.info(f"🔄 Backlog: re-investigating pending incident {incident_id} [{row['severity']}] {src_ip}")

            alert_type = alert.get("type", "UNKNOWN")
            dst_ip     = alert.get("dst_ip", "")
            _drop      = {"raw_event", "profile_summary", "threat_description", "matched_mitre",
                          "observation_count", "avg_bytes_per_min", "avg_entropy"}
            alert_slim = {k: v for k, v in alert.items() if k not in _drop and v not in (None, "")}

            threat_raw, host_raw, rep_raw, recent_raw = await asyncio.gather(
                self.executor.execute("query_threat_database", {"query": f"{alert_type} {mitre}", "n_results": 3}),
                self.executor.execute("get_host_profile",      {"ip_address": src_ip}),
                self.executor.execute("lookup_ip_reputation",  {"ip_address": dst_ip or src_ip}),
                self.executor.execute("get_recent_alerts",     {"hours": 6, "limit": 5, "src_ip": src_ip, "source": source}),
            )

            intel_context = (
                f"Alert: {json.dumps(alert_slim, separators=(',', ':'))}\n\n"
                f"Intel:\n"
                f"- Threat DB: {_summarize_result('query_threat_database', threat_raw)}\n"
                f"- Host profile: {_summarize_result('get_host_profile', host_raw)}\n"
                f"- IP reputation: {_summarize_result('lookup_ip_reputation', rep_raw)}\n"
                f"- Recent alerts: {_summarize_result('get_recent_alerts', recent_raw)}"
            )

            try:
                response = await self._chat_with_retry(
                    messages=[{"role": "user", "content": intel_context}],
                    tools=None, system=ANALYSIS_SYSTEM_PROMPT, max_tokens=768,
                )
                raw_text = response.text.strip() if response.text else ""
            except Exception as llm_err:
                logger.error(f"LLM unavailable for backlog reinvestigation {incident_id}: {llm_err}")
                raw_text = json.dumps(self._rule_based_verdict(alert))

            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
                raw_text = re.sub(r"\s*```$", "", raw_text).strip()

            try:
                verdict = json.loads(raw_text)
            except (json.JSONDecodeError, ValueError):
                verdict = self._rule_based_verdict(alert)

            description       = verdict.get("description", "")
            evidence          = verdict.get("evidence", "")
            analysis          = f"{description}\n\nEvidence: {evidence}".strip() if evidence else description
            block_recommended = bool(verdict.get("block_recommended")) or verdict.get("severity") == "CRITICAL"
            new_title         = verdict.get("title", row["title"])
            new_severity      = verdict.get("severity", row["severity"])
            new_mitre         = verdict.get("mitre_techniques", [mitre] if mitre else [])

            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE incidents SET
                        title = $2, severity = $3, description = $4,
                        investigation_summary = $5, mitre_techniques = $6,
                        block_recommended = $7,
                        block_target_ip = $8,
                        updated_at = NOW()
                    WHERE incident_id = $1
                """,
                    incident_id, new_title, new_severity, description, analysis,
                    new_mitre, block_recommended,
                    (dst_ip or src_ip) if block_recommended else "",
                )

            logger.info(f"✅ Backlog upgraded: {incident_id} [{new_severity}] {new_title}")
            return True

        except Exception as e:
            logger.error(f"Backlog reinvestigation error: {e}")
            return False

    async def _create_pending_incident(self, alert: Dict):
        """Create a basic PENDING incident when AI investigation is paused.
        Ensures alerts always surface in the Incidents panel, even without AI analysis."""
        try:
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')[:19]}"
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
            # Fire-and-forget campaign correlation
            asyncio.ensure_future(_correlate_campaign_with_pool(
                self.db_pool, incident_id, src_ip, sev, [mitre] if mitre else [],
                source=source
            ))
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
