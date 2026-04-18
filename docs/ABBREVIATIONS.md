# Abbreviations & Glossary — CyberSentinel AI
**Complete reference for all technical terms, acronyms, and cybersecurity concepts used in this project.**

---

## Table of Contents
1. [Cybersecurity Core Terms](#1-cybersecurity-core-terms)
2. [Threat Intelligence & Standards](#2-threat-intelligence--standards)
3. [Network & Protocol Terms](#3-network--protocol-terms)
4. [AI & Machine Learning Terms](#4-ai--machine-learning-terms)
5. [Platform & Infrastructure Terms](#5-platform--infrastructure-terms)
6. [CyberSentinel-Specific Terms](#6-cybersentinel-specific-terms)
7. [Metrics & Scoring](#7-metrics--scoring)

---

## 1. Cybersecurity Core Terms

| Abbreviation | Full Form | Definition in this Project |
|---|---|---|
| **SOC** | Security Operations Centre | The team (and platform) responsible for monitoring, detecting, and responding to cybersecurity threats in real time. CyberSentinel is an AI-powered SOC platform. |
| **SOAR** | Security Orchestration, Automation and Response | Automated workflows that react to security events — e.g., creating tickets, sending Slack alerts, blocking IPs — without human intervention. CyberSentinel uses n8n for SOAR. |
| **SIEM** | Security Information and Event Management | A system that collects and correlates security logs from across an organisation. CyberSentinel replaces traditional SIEM with AI-driven analysis. |
| **TTP** | Tactics, Techniques and Procedures | The specific methods an attacker uses. Described by the MITRE ATT&CK framework. |
| **IOC** | Indicator of Compromise | Observable evidence that a system has been breached — e.g., a malicious IP address, file hash, or domain name. |
| **IOA** | Indicator of Attack | Behavioural signals that suggest an attack is in progress, even before compromise — e.g., unusual port scanning. |
| **APT** | Advanced Persistent Threat | A sophisticated, long-term cyberattack campaign typically attributed to nation-state or criminal groups. |
| **C2** / **C&C** | Command and Control | Infrastructure used by attackers to communicate with compromised systems. Detected in CyberSentinel as `C2_BEACON_DETECTED`. |
| **DPI** | Deep Packet Inspection | Network traffic analysis that reads the full content of network packets, not just headers. CyberSentinel uses Scapy for DPI. |
| **IDS** | Intrusion Detection System | A system that monitors network traffic for suspicious activity and issues alerts. |
| **IPS** | Intrusion Prevention System | Like IDS but also blocks detected threats automatically. |
| **EDR** | Endpoint Detection and Response | Security monitoring at the device level (laptops, servers). |
| **XDR** | Extended Detection and Response | Combines EDR, NDR, and cloud telemetry into one unified detection platform. |
| **NDR** | Network Detection and Response | Security monitoring at the network level — the layer CyberSentinel primarily operates on. |
| **DFIR** | Digital Forensics and Incident Response | The process of investigating a security breach after it occurs. |
| **TI** / **CTI** | (Cyber) Threat Intelligence | Structured knowledge about current threats, vulnerabilities, and attacker behaviour. CyberSentinel ingests CTI from NVD, CISA, Abuse.ch, OTX, and MITRE. |
| **RCE** | Remote Code Execution | A class of vulnerability that allows an attacker to run arbitrary code on a victim's system. Often found in CVEs with CVSS ≥ 9.0. |
| **SQLi** | SQL Injection | An attack that inserts malicious SQL into a query to manipulate a database. |
| **XSS** | Cross-Site Scripting | A web vulnerability that injects malicious scripts into web pages viewed by other users. |
| **OWASP** | Open Web Application Security Project | Non-profit organisation that maintains the OWASP Top 10 — the most critical web application vulnerabilities. |
| **MFA** | Multi-Factor Authentication | Using two or more verification factors to log in. |
| **RBAC** | Role-Based Access Control | Permissions assigned by role. CyberSentinel uses RBAC: `admin` can approve/deny/block; `analyst` can investigate; `viewer` is read-only. |
| **JWT** | JSON Web Token | A compact, URL-safe token format used for authentication. CyberSentinel API uses JWTs issued at `/auth/token`. |
| **HITL** | Human-in-the-Loop | A pattern where AI recommends an action but a human must approve it. CyberSentinel uses HITL for all IP block decisions — the AI sets `block_recommended`, an analyst clicks BLOCK IP in the RESPONSE tab. |
| **SLA** | Service Level Agreement | A committed response time target. In CyberSentinel: CRITICAL = 30 min, HIGH = 2 hours, MEDIUM = 8 hours, LOW = 24 hours. |
| **PCAP** | Packet Capture | A file format (`.pcap`) that records raw network traffic. Scapy can read and generate PCAP files. |
| **VPN** | Virtual Private Network | An encrypted tunnel used to hide network traffic. Can be legitimate or used by attackers to mask C2 activity. |
| **TLS/SSL** | Transport Layer Security / Secure Sockets Layer | Encryption protocol for network communications. DPI can detect TLS handshake anomalies. |
| **TTL** | Time To Live | A network packet field that limits its lifetime. Abnormal TTL values can indicate packet spoofing or tunnelling. Detected as `TTL_ANOMALY` in CyberSentinel. |

---

## 2. Threat Intelligence & Standards

| Abbreviation | Full Form | Definition in this Project |
|---|---|---|
| **CVE** | Common Vulnerabilities and Exposures | A publicly disclosed cybersecurity vulnerability with a unique ID (e.g., `CVE-2024-12345`). Assigned by MITRE, published in NVD. |
| **CVSS** | Common Vulnerability Scoring System | A standardised 0–10 score measuring CVE severity. Used in CyberSentinel to classify CVEs: CRITICAL (≥ 9.0), HIGH (7.0–8.9), MEDIUM (4.0–6.9), LOW (< 4.0). |
| **NVD** | National Vulnerability Database | The US government repository of all CVE data with CVSS scores. CyberSentinel's CTI scraper polls NVD every 4 hours. |
| **CISA** | Cybersecurity and Infrastructure Security Agency | US government agency. Maintains the **Known Exploited Vulnerabilities (KEV)** catalog — CVEs that are actively being used in attacks. CISA KEVs trigger `active-exploitation` events in CyberSentinel. |
| **KEV** | Known Exploited Vulnerabilities | CISA's catalog of CVEs confirmed to be actively exploited. Treated as highest urgency in the CVE Intel Pipeline (Workflow 03). |
| **MITRE** | MITRE Corporation | Non-profit research organisation that maintains ATT&CK, CVE, and CWE. |
| **ATT&CK** | Adversarial Tactics, Techniques and Common Knowledge | MITRE's comprehensive framework of attacker behaviours, organised into Tactics → Techniques → Sub-techniques. CyberSentinel maps every detection to an ATT&CK technique ID. |
| **T-ID** | Technique ID | A specific ATT&CK technique, e.g., `T1071.001` (Application Layer Protocol: Web Protocols — used for C2). |
| **CWE** | Common Weakness Enumeration | A catalogue of software weaknesses (code-level, unlike CVE which is instance-level). |
| **OTX** | Open Threat Exchange | AlienVault's open-source threat intelligence platform. Provides IOCs, malicious IPs, and threat pulses. CyberSentinel ingests OTX data. |
| **Abuse.ch** | Abuse.ch Threat Intelligence | Swiss non-profit maintaining threat intel feeds including MalwareBazaar, URLhaus, and Feodo Tracker (C2 server IPs). CyberSentinel ingests Feodo Tracker. |
| **AbuseIPDB** | AbuseIPDB | Community database of reported malicious IP addresses with confidence scores. WF01 queries AbuseIPDB for reputation scoring. |
| **STIX** | Structured Threat Information eXpression | A standardised language for representing CTI. Used with TAXII feeds. |
| **TAXII** | Trusted Automated eXchange of Indicator Information | Protocol for distributing STIX threat intelligence feeds. |
| **TLP** | Traffic Light Protocol | A system for classifying and sharing sensitive intelligence: WHITE (public), GREEN (community), AMBER (limited), RED (recipients only). |

### Key MITRE ATT&CK Techniques Detected in CyberSentinel

| Technique ID | Name | Detection Method |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols (C2) | DPI — regular HTTP/S beacon intervals |
| T1046 | Network Service Discovery (Port Scanning) | DPI — SYN packets to many ports |
| T1048 | Exfiltration Over Alternative Protocol | DPI — high entropy + large outbound transfer |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | DPI — high-entropy DNS queries |
| T1021.002 | Remote Services: SMB/Windows Admin Shares (Lateral Movement) | DPI — internal SMB traffic between hosts |
| T1486 | Data Encrypted for Impact (Ransomware) | RLM — spike in file I/O entropy + CPU |
| T1003 | OS Credential Dumping | DPI — LSASS memory access patterns |
| T1090.003 | Proxy: Multi-hop Proxy (Tor) | DPI — Tor exit node IP matching |
| T1595 | Active Scanning | DPI — ICMP + SYN sweep patterns |

---

## 3. Network & Protocol Terms

| Abbreviation | Full Form | Definition in this Project |
|---|---|---|
| **IP** | Internet Protocol | Network-layer addressing. CyberSentinel tracks `src_ip` and `dst_ip` for every alert. |
| **TCP** | Transmission Control Protocol | Connection-oriented transport protocol. DPI analyses TCP flags (SYN, ACK, RST) for port scan detection. |
| **UDP** | User Datagram Protocol | Connectionless transport protocol. Used by DNS; high UDP to unusual ports may indicate exfiltration. |
| **ICMP** | Internet Control Message Protocol | Protocol for network diagnostics (ping). High ICMP volumes indicate active scanning. |
| **DNS** | Domain Name System | Translates domain names to IP addresses. DNS query entropy analysis detects DGA malware. |
| **HTTP/S** | Hypertext Transfer Protocol (Secure) | Web protocol. Used as a covert C2 channel by many malware families. |
| **SMB** | Server Message Block | Windows file-sharing protocol. Lateral movement often uses SMB (T1021.002). |
| **SSH** | Secure Shell | Encrypted remote access protocol. |
| **EMA** | Exponential Moving Average | A time-weighted average that gives more weight to recent values. Used in CyberSentinel's RLM Engine to update host behaviour profiles for every new packet — no fixed window, always up to date. |
| **NIC** | Network Interface Card | The hardware that captures raw packets. The DPI sensor attaches to NIC using Scapy + Npcap. |
| **Npcap** | Nmap Packet Capture | Windows packet capture library (equivalent to libpcap on Linux). Required for live DPI on Windows. |
| **MTU** | Maximum Transmission Unit | Maximum packet size. Unusual fragment sizes can indicate evasion. |
| **TTL** | Time To Live | Network packet hop-count field. Abnormal values flagged as `TTL_ANOMALY`. |
| **DGA** | Domain Generation Algorithm | Malware technique that generates pseudo-random domain names for C2, making blocking difficult. Detected by DNS query entropy analysis in CyberSentinel. |
| **NAT** | Network Address Translation | Maps private IPs to public IPs. Affects source IP attribution in DPI. |
| **VLAN** | Virtual LAN | Network segmentation technique. Used to isolate infected hosts. |
| **BGP** | Border Gateway Protocol | Internet routing protocol. BGP hijacking is an advanced attack vector. |

---

## 4. AI & Machine Learning Terms

| Abbreviation | Full Form | Definition in this Project |
|---|---|---|
| **LLM** | Large Language Model | AI model trained on large text datasets capable of understanding and generating human language. CyberSentinel uses LLMs to investigate security alerts and generate reports. |
| **RAG** | Retrieval-Augmented Generation | A technique where relevant documents are retrieved from a vector database and included in the LLM prompt, grounding the response in specific knowledge. CyberSentinel uses RAG to find similar past threats before investigation. |
| **MCP** | Model Context Protocol | Anthropic's open standard for giving LLMs structured access to external tools and data sources. CyberSentinel's `mcp_orchestrator.py` implements MCP-style tool calling. |
| **NLP** | Natural Language Processing | AI field dealing with understanding and generating human language. Used to convert host behaviour profiles into text for embedding. |
| **EMA** | Exponential Moving Average | Statistical technique used in RLM Engine. See Network Terms above. |
| **RLM** | Recursive Language Model | CyberSentinel's novel contribution: a behavioural profiling engine that converts host network statistics into NLP text representations, recursively updated per packet using EMA. |
| **Vector Embedding** | — | A numerical representation of text as a high-dimensional vector. Semantically similar texts have similar vectors. CyberSentinel uses `all-MiniLM-L6-v2` to embed threat signatures, CVEs, and behaviour profiles. |
| **Cosine Similarity** | — | A metric measuring similarity between two vectors (range: -1 to 1, where 1 = identical). Used to compare a host's behaviour embedding against known threat signatures. |
| **ChromaDB** | — | An open-source vector database. CyberSentinel stores and searches 4 collections: `threat_signatures`, `cve_database`, `behavior_profiles`, `incident_history`. |
| **all-MiniLM-L6-v2** | — | A 6-layer MiniLM sentence embedding model. Fast, accurate, and runs fully locally — zero embedding API cost. Produces 384-dimension vectors. |
| **GPT-4o** | Generative Pre-trained Transformer 4o | OpenAI's multimodal flagship model. Used as the default LLM provider in CyberSentinel. |
| **GPT-4o mini** | — | A smaller, faster, cheaper version of GPT-4o. Used by n8n workflows for report generation (~$0.000165/investigation). |
| **Claude** | — | Anthropic's LLM family. Supported as an alternative provider in CyberSentinel (`LLM_PROVIDER=claude`). |
| **Gemini** | — | Google DeepMind's LLM family. Supported as an alternative provider (`LLM_PROVIDER=gemini`). |
| **asyncio** | — | Python's asynchronous I/O framework. CyberSentinel's MCP Orchestrator uses `asyncio.gather()` to run all 9 MCP tools in parallel, achieving the 1-call LLM pattern. |
| **Token** | — | The smallest unit of text processed by an LLM. Roughly 0.75 words. CyberSentinel uses ~553 tokens per investigation, compared to ~5,000+ for traditional agentic loops. |
| **Temperature** | — | LLM parameter controlling randomness (0 = deterministic, 1 = creative). Board Report uses 0.2 for factual output; investigation uses default (~0.7). |
| **Prompt Engineering** | — | The art of crafting LLM inputs to elicit accurate, structured outputs. CyberSentinel uses a structured system prompt (`ANALYSIS_SYSTEM_PROMPT`) with explicit JSON output format. |
| **Zero-shot** | — | LLM capability to answer questions about topics not explicitly in the training data, based on understanding. CyberSentinel exploits zero-shot capability for novel threat types. |

---

## 5. Platform & Infrastructure Terms

| Abbreviation | Full Form | Definition in this Project |
|---|---|---|
| **API** | Application Programming Interface | A defined way for services to communicate. CyberSentinel exposes a REST API via FastAPI on port 8080. |
| **REST** | Representational State Transfer | An architectural style for web APIs using HTTP verbs (GET, POST, PUT, DELETE). All CyberSentinel endpoints follow REST conventions. |
| **FastAPI** | — | A modern Python web framework for building REST APIs. Auto-generates OpenAPI/Swagger documentation at `/docs`. |
| **Kafka** | Apache Kafka | A distributed event streaming platform. CyberSentinel uses Kafka as the messaging backbone with 3 topics: `raw-packets`, `threat-alerts`, `incident-reports`. |
| **PostgreSQL** | — | Open-source relational database. Stores all alerts, incidents, investigations, and audit logs. Used with TimescaleDB extension for time-series optimisation. |
| **TimescaleDB** | — | A PostgreSQL extension that adds time-series optimisations (automatic partitioning, compression). Alerts are stored with microsecond timestamps. |
| **Redis** | — | In-memory key-value store. Used for caching dashboard stats and deduplicating n8n webhook events (SHA-256 hash, 60s window). |
| **Docker** | — | Container platform. CyberSentinel runs as 14 Docker containers. |
| **Docker Compose** | — | Tool for defining and running multi-container Docker applications. `docker compose up -d` starts the entire platform. |
| **n8n** | — | Open-source workflow automation platform (like Zapier, but self-hosted). CyberSentinel uses n8n for SOAR workflows. |
| **Prometheus** | — | Open-source metrics collection system. Scrapes metrics from all CyberSentinel services. |
| **Grafana** | — | Open-source observability platform. Visualises Prometheus metrics in dashboards. Available at port 3001. |
| **React** | — | JavaScript UI library. CyberSentinel's SOC Dashboard is built in React with a dark cyberpunk theme. |
| **Scapy** | — | Python packet manipulation library. Powers CyberSentinel's DPI sensor for real packet capture and analysis. |
| **Zookeeper** | Apache Zookeeper | Coordination service required by Kafka for distributed consensus. |
| **SQLite** | — | A lightweight, file-based SQL database. Used by n8n to store its configuration, workflows, and execution history. Located at `D:/N8N/database.sqlite`. |
| **JWT** | JSON Web Token | See Security Terms above. CyberSentinel tokens expire after 24 hours. |
| **CORS** | Cross-Origin Resource Sharing | Browser security policy restricting cross-domain HTTP requests. CyberSentinel's API acts as a proxy for n8n webhooks to avoid CORS issues from the browser. |
| **Pydantic** | — | Python data validation library. All API request/response models use Pydantic for validation. |
| **Webhook** | — | An HTTP callback — a URL that receives POST requests when an event occurs. n8n workflows are triggered via webhooks. |
| **CI/CD** | Continuous Integration / Continuous Deployment | Automated build, test, and deployment pipelines. |
| **ORM** | Object-Relational Mapper | Maps database rows to code objects. CyberSentinel uses raw asyncpg SQL queries for performance. |

---

## 6. CyberSentinel-Specific Terms

| Term | Definition |
|---|---|
| **RLM Engine** | Recursive Language Model Engine (`src/models/rlm_engine.py`). CyberSentinel's novel unsupervised host profiling system. Updates a `BehaviorProfile` for each IP using EMA on every raw packet. Converts numerical features (bytes, entropy, ports, protocols) to NLP text, embeds it with MiniLM, and scores it via cosine similarity against known threat signatures. Zero-shot capable — detects novel threats without labelled training data. |
| **BehaviorProfile** | A data structure tracking per-IP statistics: `avg_bytes_per_min`, `avg_packets_per_min`, `avg_entropy`, `dominant_protocol`, `distinct_ports`, `observation_count`, `anomaly_score`. Updated recursively with each packet. |
| **Anomaly Score** | A float (0.0–1.0) representing how closely an IP's current behaviour matches known threat patterns. Computed as the maximum cosine similarity across all threat signatures. Scores > 0.8 trigger `block_recommended`. |
| **block_recommended** | A boolean flag on each incident set by the AI investigation pipeline when it determines an IP should be blocked. Never auto-executed — analyst must approve via RESPONSE tab. |
| **MCP Orchestrator** | `src/agents/mcp_orchestrator.py`. Implements the 1-call LLM investigation pipeline. Runs 9 tools in parallel via `asyncio.gather()`, compresses results, and makes one LLM API call. |
| **MCP Tools** | The 9 investigation tools defined in `tools.py`: `get_alert_details`, `get_host_behavior`, `check_ip_reputation`, `search_threat_signatures`, `get_similar_incidents`, `check_cve_database`, `get_network_context`, `get_geolocation`, `get_firewall_history`. |
| **1-Call LLM Pattern** | CyberSentinel's key optimisation: all evidence gathering happens in parallel before a single LLM API call, instead of the traditional agentic loop (LLM calls tool → waits for result → calls next tool). Reduces tokens from ~5,000 to ~553 per investigation. |
| **Kafka Bridge** | `n8n/bridge/kafka_bridge.py`. A Python service that consumes Kafka topics and routes events to n8n webhooks. Deduplicates using Redis. Routes CRITICAL/HIGH alerts to Workflow 01, CVE events to Workflow 03. |
| **Pending Report** | A workflow-generated report (daily SOC report, SLA alert, board report) stored in `pending_reports` table with status `PENDING`. Displayed in the Automation tab for analyst approval before posting to Slack. |
| **Approval Flow** | The process where n8n workflows submit reports to the API (`POST /api/v1/reports/pending`) instead of directly posting to Slack. An analyst approves in the Automation tab, which triggers the Slack post. |
| **Traffic Simulator** | `src/simulation/traffic_simulator.py`. Generates 17 realistic threat scenarios as raw PacketEvent bursts published to the `raw-packets` Kafka topic — the same topic used by real DPI. This means simulated traffic passes through the full RLM profiling and AI investigation pipeline. |
| **Pipeline 1** | Real DPI pipeline: NIC → Scapy → DPI Sensor → `raw-packets` → RLM → `threat-alerts` → MCP. |
| **Pipeline 2** | Simulator pipeline: Traffic Simulator → `raw-packets` → RLM → `threat-alerts` → MCP. Same path as Pipeline 1 from `raw-packets` onwards. |
| **LLM Provider Abstraction** | `src/agents/llm_provider.py`. Allows switching between Claude, OpenAI, and Gemini via the `LLM_PROVIDER` env var with no code changes. |
| **ANALYSIS_SYSTEM_PROMPT** | The master system prompt in `src/agents/prompts.py` that instructs the LLM on its role, output format, and reasoning methodology for security investigations. |

---

## 7. Metrics & Scoring

| Metric | Formula / Range | Meaning |
|---|---|---|
| **Anomaly Score** | 0.0 – 1.0 | Cosine similarity between host's behaviour embedding and closest threat signature. > 0.8 = block recommended. |
| **Combined Threat Score** (WF01) | `(RLM_score × 0.6) + (AbuseIPDB% ÷ 100 × 0.4)` | Weighted combination of behavioural anomaly and external reputation. > 0.75 = MALICIOUS_CONFIRMED. |
| **Risk Score** (Dashboard) | `min(100, CRITICAL×10 + HIGH×3 + MEDIUM×0.5 + incidents×5)` | Overall platform risk level shown on the Overview gauge. |
| **SLA %** | `(age_minutes ÷ SLA_limit) × 100` | How much of the SLA time has been consumed. ≥ 80% = WARNING, ≥ 100% = BREACH. |
| **CVSS Score** | 0.0 – 10.0 | CVE severity. ≥ 9.0 = CRITICAL, 7.0–8.9 = HIGH, 4.0–6.9 = MEDIUM, < 4.0 = LOW. |
| **AbuseIPDB Score** | 0 – 100% | Confidence percentage that an IP is malicious, based on community reports. |
| **Tokens per Investigation** | ~553 tokens | CyberSentinel's efficiency metric for the 1-call LLM pattern. |
| **Cost per Investigation** | ~$0.000165 | At GPT-4o mini pricing ($0.15/1M input tokens, $0.60/1M output tokens). |
| **Investigations on $5** | ~30,000 | Budget coverage at current token efficiency. |
| **Detection Latency** | < 1 second | Time from packet capture to alert generation. |
| **Investigation Time** | < 60 seconds | Time from alert creation to AI investigation completion. |
| **Breach Detection (Industry)** | 194 days (IBM Cost of Data Breach 2023) | Industry average. CyberSentinel targets < 1 second for known threat patterns. |

---

*CyberSentinel AI — Abbreviations & Glossary — v1.3.0 — 2026*
