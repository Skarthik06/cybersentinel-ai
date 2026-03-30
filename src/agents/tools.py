"""
MCP Tool Definitions — canonical list of the 9 tools available to AI agents.
Imported by mcp_orchestrator.py. Edit tool schemas here only.
"""

MCP_TOOLS = [
    {
        "name": "query_threat_database",
        "description": "Search ChromaDB vector database for similar threats by semantic query. Returns matching threat signatures with MITRE ATT&CK mappings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural language description of suspicious behavior"},
                "collection": {"type": "string", "enum": ["threat_signatures", "cti_reports", "cve_database"], "description": "Which collection to search", "default": "threat_signatures"},
                "n_results": {"type": "integer", "description": "Number of results to return", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_host_profile",
        "description": "Get the behavioral profile of a specific IP address from the RLM engine.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "IP address to look up"},
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "get_recent_alerts",
        "description": "Get recent security alerts from the database, optionally filtered by severity or IP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "src_ip": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
                "hours": {"type": "integer", "description": "Look back N hours", "default": 24},
            },
        },
    },
    {
        "name": "lookup_ip_reputation",
        "description": "Check an IP address against threat intelligence feeds (AbuseIPDB).",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string"},
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "block_ip",
        "description": "Add an IP address to the firewall blocklist. CRITICAL ACTION — requires justification.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string"},
                "duration_hours": {"type": "integer", "description": "Block duration. 0 = permanent."},
                "justification": {"type": "string"},
                "incident_id": {"type": "string"},
            },
            "required": ["ip_address", "justification", "incident_id"],
        },
    },
    {
        "name": "isolate_host",
        "description": "Network-isolate an internal host from the rest of the network (containment action).",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string"},
                "hostname": {"type": "string"},
                "justification": {"type": "string"},
                "incident_id": {"type": "string"},
            },
            "required": ["ip_address", "justification", "incident_id"],
        },
    },
    {
        "name": "send_notification",
        "description": "Send an alert notification to Slack, email, or PagerDuty.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "enum": ["slack", "pagerduty", "email"]},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "title": {"type": "string"},
                "message": {"type": "string"},
                "incident_id": {"type": "string"},
            },
            "required": ["channel", "severity", "title", "message", "incident_id"],
        },
    },
    {
        "name": "create_incident",
        "description": "Create a formal security incident record in the database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "description": {"type": "string"},
                "affected_ips": {"type": "array", "items": {"type": "string"}},
                "mitre_techniques": {"type": "array", "items": {"type": "string"}},
                "evidence": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    },
    {
        "name": "query_packet_history",
        "description": "Query historical packet data for an IP or session from TimescaleDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {"type": "string"},
                "hours": {"type": "integer", "default": 1},
                "protocol": {"type": "string"},
            },
        },
    },
]
