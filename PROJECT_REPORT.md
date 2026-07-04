<!-- ===================================================================
PREPARATION NOTES — DELETE THIS BLOCK BEFORE SUBMISSION
=====================================================================
Drafted from THIS project's own source and docs (MASTER.md, SRS.md, PRD.md,
LIMITATIONS.md, the IEEE journal draft) with the 19 pre-rendered diagrams.

Before submitting:
1. §1.3 formatting is auto-applied in the .docx: TNR 12pt · 1.5 spacing · justified ·
   margins L1.5"/R1"/T1"/B1" · chapter title 14pt bold UPPERCASE right · L1 12pt bold
   UPPERCASE · L2 bold · L3 bold italic. No header/footer text in body, no page borders;
   page numbers only (roman prelim, arabic body).
2. Figures: caption BELOW (Fig. x.y). Tables: caption ABOVE (Table x.y). Both centred + bold.
3. Insert your real screenshots at the Chapter 6.3 placeholders.
4. PLAGIARISM/AI (§1.4): rewrite Chapter 1 and Chapter 2 in YOUR words before Turnitin/AI
   check (highest-risk). Keep the specific technical detail. Cite REFERENCES in-text.
==================================================================== -->

# CYBERSENTINEL AI — AUTONOMOUS THREAT INTELLIGENCE AND ZERO-DAY DETECTION PLATFORM

**Project Report — Application Stream**

| | |
|---|---|
| Submitted by | S Karthik |
| Programme | Master of Computer Applications (MCA) |
| Department | Department of Computer Application, JSS Science and Technology University, Mysuru |
| Version | 1.3.0 |
| Academic Year | 2025–2026 |

---

## Abstract

Security Operations Centres (SOCs) face an asymmetric battle: alert volumes grow at roughly 30 % per year, the industry-average breach-detection time remains 194 days, and a global cybersecurity workforce shortage limits the analyst capacity available to triage every event. Traditional signature-based tools detect only known attacks and cannot reason about novel adversary behaviour, while many AI-augmented platforms require labelled training data, multiple Large Language Model (LLM) round-trips per investigation, or fully automated blocking that risks disrupting legitimate services. CyberSentinel AI is a self-hosted SOC platform that closes this gap on a single machine. It captures live IPv4/IPv6 traffic through a Deep Packet Inspection (DPI) sensor with PII masking, builds an Exponential Moving Average (EMA) behaviour profile per host, and blends it with an IsolationForest sequence-anomaly detector to catch both single-point spikes and slow behavioural drift. High-severity alerts are investigated by a token-efficient, stateless one-call LLM pipeline — all evidence tools run in parallel via `asyncio.gather()` before a single structured call of about 553 tokens (roughly $0.000165), a ~90 % token reduction over a conventional three-call agentic loop — grounded by Retrieval-Augmented Generation over a ChromaDB store seeded with MITRE ATT&CK, NVD, CISA KEV, AlienVault OTX, and Abuse.ch corpora. Crucially, the AI never auto-blocks: every block is a recommendation an analyst approves or dismisses in a six-tab React dashboard, and every action is audited. Incidents from the same source address are grouped into 24-hour attacker campaigns to expose kill chains. The platform runs as fourteen Docker containers via a single `docker compose up -d`, covers 15 MITRE ATT&CK techniques and 17 simulated threat scenarios, and demonstrates that a token-efficient, locally-embedded, human-in-the-loop autonomous SOC is achievable on commodity hardware without a GPU or any cloud embedding API.

**Keywords:** Deep Packet Inspection, Behavioural Anomaly Detection, IsolationForest, Retrieval-Augmented Generation, Large Language Models, MITRE ATT&CK, SOAR, Human-in-the-Loop.

---

## List of Figures

| Figure | Title |
|--------|-------|
| Fig. 3.1 | Use-case diagram |
| Fig. 3.2 | Data-flow diagram — Level 0 (context) |
| Fig. 4.1 | Four-layer system architecture |
| Fig. 4.2 | Docker Compose deployment (14 containers) |
| Fig. 4.3 | Data-flow diagram — Level 1 (system decomposition) |
| Fig. 4.4 | Data-flow diagram — Level 2 (MCP orchestrator) |
| Fig. 4.5 | Class diagram — core domain model |
| Fig. 4.6 | PostgreSQL entity-relationship diagram |
| Fig. 4.7 | Kafka topic architecture |
| Fig. 4.8 | ChromaDB collections map |
| Fig. 4.9 | LLM provider abstraction |
| Fig. 4.10 | RAG semantic-search flow |
| Fig. 5.1 | Master end-to-end flow chart |
| Fig. 5.2 | Activity diagram — alert lifecycle |
| Fig. 5.3 | Sequence diagram — one-call AI investigation |
| Fig. 5.4 | Pipeline 1 — DPI real traffic |
| Fig. 5.5 | Pipeline 2 — traffic simulator |
| Fig. 5.6 | Token economics — 3-call loop vs 1-call pipeline |
| Fig. 6.1 | Secure access terminal (login) |
| Fig. 6.2 | Dashboard — Simulated Threat Lab (Overview) |
| Fig. 6.3 | Dashboard — Live Network SOC (Overview) |
| Fig. 6.4 | Landing page |
| Fig. A.1 | Gantt chart — project work plan |

## List of Tables

| Table | Title |
|-------|-------|
| Table 1.1 | The SOC alert-handling crisis (industry figures) |
| Table 1.2 | Gaps left by existing tool categories |
| Table 2.1 | Key literature and its influence on CyberSentinel AI |
| Table 2.2 | Existing SOC archetypes and their investigation approach |
| Table 2.3 | Research gaps addressed by CyberSentinel AI |
| Table 2.4 | Comparison of related approaches with CyberSentinel AI |
| Table 3.1 | Functional requirements summary |
| Table 3.2 | Key non-functional requirements |
| Table 3.3 | Hardware requirements |
| Table 3.4 | Configuration and threshold reference |
| Table 3.5 | Data retention policy |
| Table 4.1 | Docker container inventory |
| Table 4.2 | ChromaDB collections |
| Table 4.3 | TimescaleDB optimisations on the packets hypertable |
| Table 4.4 | LLM provider comparison |
| Table 4.5 | RAG similarity bands |
| Table 4.6 | MITRE ATT&CK technique coverage |
| Table 5.1 | Tools and technologies |
| Table 5.2 | Module summary |
| Table 5.3 | Simulator scenarios — MITRE-mapped (12) |
| Table 5.4 | Simulator scenarios — novel / AI-classified (5) |
| Table 5.5 | Token budget per investigation |
| Table 5.6 | REST API endpoints |
| Table 5.7 | SOC dashboard tabs |
| Table 6.1 | Automated test suite summary |
| Table 6.2 | Validation of goals against observed behaviour |
| Table 6.3 | LLM cost model and budget runway |
| Table 7.1 | Current limitations and planned mitigations |
| Table A.1 | Development phases |

---

# CHAPTER 1: INTRODUCTION

CyberSentinel AI is an autonomous Security Operations Centre (SOC) platform that detects network threats in real time, investigates the serious ones with an AI agent, and hands the analyst a ready-made recommendation to act on. It is built as an academic capstone project and runs entirely on one host as fourteen Docker containers, so the whole detection-to-response loop can be demonstrated end-to-end without any cloud dependency beyond a single language-model API key. This chapter states the problem the project targets (Section 1.1) and the objectives and novel contributions it delivers (Section 1.2).

## 1.1 Problem Statement

Modern networks generate a volume of security telemetry that has outgrown the humans meant to watch it. The scale of the problem is captured by a handful of widely-cited industry figures, summarised in Table 1.1.

**Table 1.1: The SOC alert-handling crisis (industry figures)**

| Metric | Reported value |
|--------|----------------|
| Average time to identify a breach | 194 days (IBM Security, 2024) |
| Average cost of a breach | US $4.45 million |
| Share of alerts that are false positives | ~95 % |
| Year-over-year growth in alert volume | ~30 % |
| Global ransomware execution frequency | roughly every 11 seconds |

Three specific weaknesses drive these numbers. First, **triage does not scale** — deciding whether an alert is real still depends on an analyst manually gathering packet context, host history, threat-intelligence lookups, and reputation data, which is slow, repetitive, and the first thing to fall behind when volume spikes. Second, **automation is trusted too much or too little** — fully automated blocking systems create their own outages by acting on false positives, so many teams disable them, yet purely manual response cannot keep up; there is a missing middle ground where a machine performs the investigation while a human retains the final decision. Third, **detection is mostly signature-based** — rules catch what has been seen before but struggle with gradual, low-and-slow behaviour such as a beacon whose interval drifts or an exfiltration that leaks a few bytes at a time.

Existing tool categories each leave part of this problem unsolved, as set out in Table 1.2.

**Table 1.2: Gaps left by existing tool categories**

| Tool category | Gap |
|---------------|-----|
| Signature IDS (Snort, Suricata) | Detects only known attacks; blind to zero-days and gradual behaviour |
| Commercial SIEM (Splunk, QRadar) | Costly; needs manual rule authoring; high false-positive rate |
| Traditional SOAR | Runs pre-written playbooks; cannot reason about novel threats |
| ML-based IDS | Needs labelled training data; cannot adapt online |
| Auto-blocking systems | False positives disrupt legitimate services; no human oversight |

CyberSentinel AI addresses these weaknesses directly: it automates the investigation of high-severity alerts, keeps a human in the loop for every blocking action, and adds a behavioural, sequence-aware detection layer on top of signature matching so that gradual anomalies are not lost.

## 1.2 Objectives

The project was scoped around eight objectives:

1. **Capture and understand live traffic** — a DPI sensor that parses IPv4 and IPv6 packets into a structured 21-field event (protocol, ports, payload entropy, TLS/DNS/HTTP metadata) and strips personally identifiable information before that event leaves the sensor.
2. **Profile behaviour, not just signatures** — maintain an online EMA profile per host and score drift towards known-malicious patterns using semantic similarity in a vector database.
3. **Catch gradual anomalies** — add an IsolationForest layer over a rolling window of recent scores so a slow upward ramp is flagged even when no single score crosses the threshold.
4. **Investigate autonomously but cheaply** — investigate every HIGH and CRITICAL alert with exactly one LLM call after gathering evidence in parallel, keeping the cost to a fraction of a cent per investigation.
5. **Keep humans in control** — never block an IP automatically; present each recommendation for analyst approval or dismissal, and record every decision in an audit log.
6. **Correlate incidents into campaigns** — group incidents from the same source address within a rolling 24-hour window so an analyst sees a kill chain instead of scattered events.
7. **Automate the routine response** — push critical alerts, daily/weekly reports, and CVE intelligence to a SOAR layer that notifies the right channels without human effort.
8. **Deploy in one command** — package the entire platform to start with a single `docker compose up -d` and survive restarts without losing data.

Beyond these objectives, the platform makes five novel technical contributions: (i) a **stateless one-call LLM investigation** that runs all evidence tools in parallel before a single model call, cutting token cost by about 90 % versus a traditional multi-call agentic loop; (ii) an **IsolationForest sequence-anomaly layer** that reasons about score *trajectory* rather than a single value; (iii) a **dual-pipeline architecture** in which real DPI and a 17-scenario simulator feed the identical processing stack; (iv) **automatic attacker-campaign correlation** that reveals multi-stage kill chains; and (v) a **human-in-the-loop SOAR** design that eliminates false-positive auto-blocking.

---

# CHAPTER 2: LITERATURE REVIEW

Network intrusion detection has passed through three broad generations, and CyberSentinel AI deliberately borrows from all three rather than replacing them.

**Signature and rule-based detection.** Classic network IDS/IPS systems such as Snort (Roesch, 1999) and Suricata match traffic against curated rule sets. They are fast and precise for known attacks but, as many surveys note, blind to novel or slowly-evolving behaviour and prone to large volumes of low-context alerts. CyberSentinel AI keeps lightweight signature-style checks in its DPI sensor (suspicious ports, high payload entropy, DGA-like domains, cleartext credentials, anomalous TTLs, malware user agents) but treats them as one input among several rather than the whole decision.

**Machine-learning anomaly detection.** A large body of work applies statistical and machine-learning models to flow features to flag deviations from a learned baseline. IsolationForest (Liu et al., 2008) is a widely-used unsupervised method that isolates anomalies with little data and no labelled attacks, which suits a SOC where labelled ground truth is scarce. CyberSentinel AI applies IsolationForest not to raw features but to a *sequence* of anomaly scores per host, so the model reasons about the direction a host is drifting rather than a single snapshot.

**Behavioural profiling.** Exponential Moving Average smoothing is a standard online technique for maintaining a running baseline that adapts to change without storing history. Applying EMA per host gives each source address its own evolving "normal" against which drift is measured cheaply and continuously.

**Language models and retrieval-augmented generation.** Recent work shows LLMs can summarise and reason over security telemetry, but naïve agentic loops (where the model repeatedly calls tools) are slow and expensive. Retrieval-Augmented Generation — retrieving relevant context from a vector store before generation — grounds output in current facts. CyberSentinel AI combines the two but constrains them: it retrieves with a local embedding model (all-MiniLM-L6-v2; Reimers and Gurevych, 2019) and then makes a single, tool-free LLM call, trading a little flexibility for a large gain in speed and cost.

**Threat-intelligence frameworks.** The MITRE ATT&CK framework (Strom et al., 2020) provides a shared vocabulary of adversary techniques, and public feeds (NVD, CISA KEV, AlienVault OTX, Abuse.ch) provide current indicators. CyberSentinel AI ingests these into its vector store and maps every alert to an ATT&CK technique ID, so findings are expressed in a language analysts already use.

The platform's design draws on twenty-six peer-reviewed papers across eight research domains; the eleven most load-bearing studies — those that shaped a specific architectural decision — are summarised in Table 2.1.

**Table 2.1: Key literature and its influence on CyberSentinel AI**

| # | Paper (author, year) | Method | Influence on the platform |
|---|----------------------|--------|---------------------------|
| 1 | Bathiri & Vijayakumar (2024) | DPI + ML ensemble | Multi-signal DPI in `sensor.py` (entropy, port, timing) |
| 2 | Foreman, Waters et al. (2024) | TCP SYN + DPI | Suspicious-port / entropy detectors in `detectors.py` |
| 3 | DL-IDS survey (2025) | DL-IDS evolution (0 %→65.7 %) | Justifies hybrid DPI + RLM over pure signatures |
| 4 | Self-attention anomaly (2023) | EMA baselining | Validates the EMA update rule in `BehaviorProfile.update()` |
| 5 | Unsupervised online ML (2025) | Online, label-free ML | Justifies the zero-label RLM design |
| 6 | Molleti, Goje et al. (2024) | LLM SOC agents | Closest published work to the MCP orchestrator |
| 7 | Gen-5 agentic taxonomy (2025) | Agentic pipeline taxonomy | Maps the 3-call loop → 1-call pipeline evolution |
| 8 | CyberRAG (2025) | Agentic RAG | The 1-call pipeline simplifies its retrieval-reason loop |
| 9 | Strom et al. (2020) | MITRE ATT&CK | Foundation for the 15 technique detections |
| 10 | Efficient LLM inference (2024) | Token compression | Basis for `_summarize_result()` |
| 11 | Prompt-compression survey (2025) | Schema-overhead reduction | Basis for `tools=None` on the final call |

Contemporary SOC tooling falls into five archetypes (Table 2.2). Across them, eight structural limitations recur: high licensing cost, manual rule authoring, degradation of supervised ML under traffic drift, token waste in multi-call agentic loops (≈ 5,500–7,000 tokens per investigation), absence of a human-in-the-loop gate, ungoverned RAG caches, no kill-chain correlation, and poor data privacy when payloads are sent to cloud embedding APIs.

**Table 2.2: Existing SOC archetypes and their investigation approach**

| Archetype | Representative tools | Detection | Investigation |
|-----------|----------------------|-----------|---------------|
| Signature IDS | Snort, Suricata, Zeek | Static rules vs headers/payloads | Manual triage |
| Commercial SIEM | Splunk, QRadar, Elastic | Hand-authored correlation rules | Manual triage |
| Supervised ML-IDS | Academic prototypes | Trained classifier over labelled vectors | None |
| Traditional SOAR | Splunk SOAR, XSOAR | Pre-written playbooks | Sequential scripted actions |
| Recent agentic SOC | Published prototypes | As SIEM / ML | Multi-turn LLM loop (3–5 calls) |

**Research gap addressed.** The reviewed approaches tend to optimise one axis — detection accuracy, or automation, or explainability — in isolation. Fully automated response is either unsafe or disabled; ML detectors are accurate but opaque; LLM agents are explainable but costly. The contribution of this project is the *combination* under practical constraints: sequence-aware behavioural detection feeding a single-call, RAG-grounded LLM investigation, whose output is always gated by a human analyst and recorded for audit. Six concrete gaps motivated the design (Table 2.3), and Table 2.4 contrasts the common approaches with the platform.

**Table 2.3: Research gaps addressed by CyberSentinel AI**

| Research gap | How the platform closes it |
|--------------|----------------------------|
| No integrated single-deployment SOC | DPI, RLM, RAG, and agentic LLM in one `docker compose` artifact |
| No token-efficient agentic pattern | One-call pipeline (~553 tokens) via parallel pre-gathering |
| No human-in-the-loop default | Analyst approves every block; all actions audited |
| No sequence-level anomaly layer atop EMA | IsolationForest over a 50-observation rolling buffer |
| No campaign correlation without a graph DB | 24-hour windowed correlation via adjacency tables |
| No cache governance for CTI refresh | Redis SHA-256 keys + TTL guards prevent thundering-herd bypass |

**Table 2.4: Comparison of related approaches with CyberSentinel AI**

| Aspect | Signature IDS | ML anomaly IDS | LLM agentic tools | CyberSentinel AI |
|--------|---------------|----------------|-------------------|------------------|
| Detects novel / gradual behaviour | No | Partly | Depends | Yes (EMA + IsolationForest on score sequence) |
| Explainable output | Low | Low | High | High (LLM summary + MITRE mapping) |
| Cost per investigation | n/a | Low | High (multi-call) | Very low (1 call, ~553 tokens) |
| Automated response safety | Risky if auto-block | n/a | Varies | Human-in-the-loop, audited |
| Threat-intel grounding | Static rules | Rare | Sometimes | RAG over 5 live feeds |
| Deployment effort | Moderate | High | High | One command (14 containers) |

---

# CHAPTER 3: SOFTWARE REQUIREMENT SPECIFICATION

## 3.1 Product Perspective and Actors

CyberSentinel AI is a standalone, self-hosted platform; it is not a plug-in to a larger product. It sits passively between the monitored network and the human analyst, observing traffic, scoring it, investigating the serious cases, and surfacing recommendations — while modifying no traffic and blocking no address without approval. The actors and the actions available to each are shown in the use-case diagram (Fig. 3.1), and the highest-level data flow between the platform and the external entities it depends on is shown in the Level-0 data-flow diagram (Fig. 3.2).

![Use case diagram](assets/diagrams/Fig_12_Use_Case_Diagram.png)

**Fig. 3.1: Use-case diagram**

![DFD Level 0 context](assets/diagrams/Fig_16_DFD_Level0_Context.png)

**Fig. 3.2: Data-flow diagram — Level 0 (context)**

## 3.2 Functional Requirements

Table 3.1 summarises the functional requirements; each maps to a concrete source module and is exercised by the detection or investigation pipeline.

**Table 3.1: Functional requirements summary**

| ID | Requirement | Realised in |
|----|-------------|-------------|
| FR-01 | Capture IPv4/IPv6 packets, extract a 21-field event, detect 8 threat signals, mask PII before publishing | `src/dpi/sensor.py` |
| FR-02 | Generate 17 threat scenarios as packet bursts to the same topic as real DPI | `src/simulation/traffic_simulator.py` |
| FR-03 | Maintain an EMA behaviour profile per source IP (α = 0.1); gate scoring until 20 observations | `src/models/rlm_engine.py` |
| FR-04 | Score anomalies via ChromaDB cosine similarity blended 25 % with IsolationForest; alert at score ≥ 0.65 | `SequenceAnomalyDetector` |
| FR-05 | Investigate HIGH/CRITICAL alerts with exactly one LLM call after parallel evidence gathering | `src/agents/mcp_orchestrator.py` |
| FR-06 | Create and manage incidents with a lifecycle (OPEN/INVESTIGATING/RESOLVED/DISMISSED) | API + PostgreSQL |
| FR-07 | Correlate incidents from one source IP within 24 h into a campaign; ratchet severity; union MITRE stages | `_correlate_campaign_with_pool()` |
| FR-08 | Never auto-block; analyst approves/dismisses; log every decision | RESPONSE tab + `audit_log` |
| FR-09 | Ingest CVE and indicator intelligence from five feeds on scheduled cycles | `src/ingestion/threat_intel_scraper.py` |
| FR-10 | Protect all endpoints with JWT auth; secrets only via `.env` | `src/api/gateway.py` |
| FR-11 | Run five SOAR workflows for alerts, reports, and CVE intelligence | `n8n/workflows/` |
| FR-12 | Fall back to a deterministic rule-based verdict when the LLM is unavailable | `_rule_based_verdict()` |

## 3.3 Non-Functional Requirements

**Table 3.2: Key non-functional requirements**

| Category | Requirement |
|----------|-------------|
| Performance | Packet capture ≥ 10,000 pkt/s; RLM profile update < 10 ms/packet; ChromaDB query < 200 ms; API P95 < 500 ms; packet-to-alert ~1 s; investigation < 45 s |
| Cost | ≤ 600 tokens per investigation (≈553 typical); 1 API call; input:output ≤ 3:1; < $0.0002 per investigation; > 25,000 investigations on a $5 budget |
| Reliability | Kafka offsets persist across restarts; all state in named Docker volumes; asyncpg pool (5–20); LLM back-off 5 s → 15 s → 45 s; every service has a healthcheck |
| Security | No PII in Kafka/DB/LLM prompts; JWT (HS256, 480-min) with bcrypt (work factor 12); Redis and ChromaDB credential-protected; secrets only in `.env` |
| Maintainability | All config centralised in `src/core/config.py`; all ChromaDB writes routed through `embedder.batch_upsert()` |

## 3.4 External Interface and Configuration

The analyst interacts only through the React dashboard at `http://localhost:5173`; the REST API is documented via Swagger at `http://localhost:8080/docs`. The hardware envelope is given in Table 3.3, and the tunable configuration in Table 3.4.

**Table 3.3: Hardware requirements**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM (Docker) | 16 GB | 32 GB |
| Storage | 20 GB SSD | 50 GB SSD |
| OS | Windows 11 Pro / Linux / macOS with Docker Desktop | Linux preferred for the DPI container |
| GPU | Not required (all inference on CPU) | Not applicable |

**Table 3.4: Configuration and threshold reference**

| Variable | Default | Purpose |
|----------|---------|---------|
| `RLM_ALPHA` | 0.1 | EMA smoothing factor |
| `RLM_ANOMALY_THRESHOLD` | 0.65 | Minimum score to emit an alert |
| `RLM_MIN_OBSERVATIONS` | 20 | Packets required before scoring begins |
| `ISOLATION_FOREST_WEIGHT` | 0.25 | IsolationForest blend weight |
| `ISOLATION_FOREST_MIN_SAMPLES` | 10 | Observations before blending begins |
| `EMBED_CACHE_TTL_SEC` | 3600 | Redis embedding-cache lifetime |
| `PROFILE_TTL_DAYS` | 30 | behavior_profiles eviction |
| `CTI_TTL_DAYS` | 90 | cti_reports eviction |
| `INVESTIGATION_INTERVAL_SEC` | 1800 | Minimum gap between investigations |
| `SCRAPE_INTERVAL_HOURS` | 4 | CTI refresh interval |

**Table 3.5: Data retention policy**

| Data | Retention | Mechanism |
|------|-----------|-----------|
| Raw packets | 30 days (compressed after 7) | TimescaleDB retention + compression |
| Alerts / incidents / campaigns | Indefinite | Manual archival |
| ChromaDB behavior_profiles | 30 days | Eviction in RLM persist cycle |
| ChromaDB cti_reports | 90 days | Eviction in scraper cycle |
| Redis embedding cache | 1 hour | `SETEX` |
| Redis IP block rules | 24 hours | `SETEX blocked:{ip} 86400` |
| Audit log | Indefinite | Compliance requirement |

## 3.5 Constraints

The design is bound by non-negotiable constraints: the detection pipeline is event-driven (services communicate only through Kafka, never direct HTTP); all embeddings are computed locally (no cloud embedding API); exactly one LLM call is permitted per investigation; no IP is ever blocked without analyst approval; and PII must be masked before any packet event reaches Kafka.

---

# CHAPTER 4: SYSTEM DESIGN

## 4.1 Architectural Overview

CyberSentinel AI is organised into four layers — Ingestion, Intelligence, Orchestration, and Delivery — over a shared persistence tier (Fig. 4.1). The defining design decision is that the detection path is **event-driven**: the DPI sensor, RLM engine, and MCP orchestrator never call one another over HTTP; they exchange messages through Kafka topics, so any one of them can restart, scale, or fail without breaking the others.

![Four-layer system architecture](assets/diagrams/Fig_01_Four_Layer_System_Architecture.png)

**Fig. 4.1: Four-layer system architecture**

## 4.2 Deployment Architecture

The platform runs as fourteen containers on a single `cybersentinel-net` bridge network (Fig. 4.2), grouped into infrastructure, core services, and delivery. Their roles are listed in Table 4.1. All persistent state lives in named volumes that survive `docker compose down`.

![Docker Compose deployment](assets/diagrams/Fig_02_Docker_Compose_Deployment.png)

**Fig. 4.2: Docker Compose deployment (14 containers)**

**Table 4.1: Docker container inventory**

| Container | Image | Role |
|-----------|-------|------|
| zookeeper | cp-zookeeper:7.5.0 | Kafka coordination |
| kafka | cp-kafka:7.5.0 | Event streaming backbone |
| postgres | timescaledb:pg16 | All persistent data |
| redis | redis:7-alpine | Cache, block rules, session windows |
| chromadb | chromadb/chroma | Vector similarity store |
| dpi-sensor | Dockerfile.dpi | Live packet capture (host network) |
| rlm-engine | Dockerfile.rlm | Behavioural profiling + scoring |
| threat-intel-scraper | Dockerfile.scraper | CTI ingestion |
| mcp-orchestrator | Dockerfile.mcp | AI investigation pipeline |
| api-gateway | Dockerfile.api | REST API + JWT |
| traffic-simulator | Dockerfile.simulator | Synthetic threat generation |
| frontend | Dockerfile.frontend | React SOC dashboard |
| prometheus | prometheus:v2.47 | Metrics collection |
| grafana | grafana:10.2 | Metrics dashboards |

## 4.3 Data-Flow Decomposition

Decomposing the context diagram (Fig. 3.2) one level down yields the major processes and data stores of the platform (Fig. 4.3). The most intricate process — the MCP orchestrator's one-call investigation — is decomposed a further level in Fig. 4.4, showing the parallel evidence-gathering tools feeding the single LLM call.

![DFD Level 1 system decomposition](assets/diagrams/Fig_17_DFD_Level1_System_Decomposition.png)

**Fig. 4.3: Data-flow diagram — Level 1 (system decomposition)**

![DFD Level 2 MCP orchestrator](assets/diagrams/Fig_18_DFD_Level2_MCP_Orchestrator.png)

**Fig. 4.4: Data-flow diagram — Level 2 (MCP orchestrator)**

## 4.4 Core Domain Model

The platform's core entities and their relationships are captured in the class diagram (Fig. 4.5) and, at the persistence layer, in the PostgreSQL entity-relationship diagram (Fig. 4.6). Incidents link to campaigns through a junction table, and firewall rules reference the incident that justified them for a complete audit trail. TimescaleDB optimisations on the high-volume packet stream are listed in Table 4.3.

![Class diagram core domain](assets/diagrams/Fig_15_Class_Diagram_Core_Domain.png)

**Fig. 4.5: Class diagram — core domain model**

![PostgreSQL ERD](assets/diagrams/Fig_05_PostgreSQL_ERD.png)

**Fig. 4.6: PostgreSQL entity-relationship diagram**

**Table 4.3: TimescaleDB optimisations on the packets hypertable**

| Policy | Setting | Purpose |
|--------|---------|---------|
| Compression | after 7 days | > 90 % storage reduction on cold data |
| Retention | drop after 30 days | Bounds table growth |
| Materialised view | `packets_per_minute` | Pre-aggregated counts for the dashboard |
| Chunk interval | 1 day | Fast time-range queries |

## 4.5 Event Bus Design

All inter-service communication uses four Kafka topics with different retention and partition settings (Fig. 4.7). Raw packets are high-volume and short-lived; alerts and incidents are lower-volume and retained longer. Messages are JSON; `raw-packets` is gzip-compressed.

![Kafka topic architecture](assets/diagrams/Fig_03_Kafka_Topic_Architecture.png)

**Fig. 4.7: Kafka topic architecture**

## 4.6 Vector Store Design

Semantic correlation uses ChromaDB with four collections, each populated by a different producer and evicted on a different schedule (Fig. 4.8, Table 4.2). All embeddings use the local all-MiniLM-L6-v2 model (384 dimensions, CPU-only), so no traffic data leaves the host for embedding and there is zero embedding cost.

![ChromaDB collections map](assets/diagrams/Fig_04_ChromaDB_Collections_Map.png)

**Fig. 4.8: ChromaDB collections map**

**Table 4.2: ChromaDB collections**

| Collection | Populated by | Eviction |
|-----------|--------------|----------|
| threat_signatures | RLM engine at startup (8 seeds) | Never |
| cve_database | CTI scraper (NVD, CVSS ≥ 7.0) | Upsert by CVE-ID |
| cti_reports | CTI scraper (CISA, Abuse.ch, MITRE, OTX) | 90 days |
| behavior_profiles | RLM engine (real DPI + simulator) | 30 days |

## 4.7 LLM Provider Abstraction

To avoid vendor lock-in, all model access goes through a single provider abstraction (Fig. 4.9). Switching between OpenAI, Anthropic, and Google is a one-line change in `.env` (`LLM_PROVIDER`); the detection and embedding paths are never affected because embedding is always the local model. Table 4.4 compares the providers.

![LLM provider abstraction](assets/diagrams/Fig_06_LLM_Provider_Abstraction.png)

**Fig. 4.9: LLM provider abstraction**

**Table 4.4: LLM provider comparison**

| Setting | OpenAI (default) | Claude | Gemini |
|---------|------------------|--------|--------|
| Primary model | gpt-4o-mini | claude-sonnet-4-6 | gemini-2.x |
| Input / output cost per 1M | $0.15 / $0.60 | $3.00 / $15.00 | free tier |
| Cost per investigation | ~$0.000165 | ~$0.002 | ~$0 |
| Security content | Full | Full | Safety filter blocks |
| Recommendation | Yes (default) | Yes | No (20 req/day + filter) |

## 4.8 Anomaly Detection and Semantic Search

Detection is a hybrid of three cheap techniques. An EMA profile is updated per packet; the profile is rendered to text and embedded; the embedding's cosine similarity to known threat signatures gives a base score; and an IsolationForest, fitted on the last 50 scores for that host, contributes 25 % of the final blended score. A Redis cache short-circuits the embedding step when a host's profile text is unchanged. The retrieval path is shown in Fig. 4.10; the similarity value is interpreted in the bands of Table 4.5, and alerts map to the MITRE ATT&CK techniques of Table 4.6.

![RAG semantic search flow](assets/diagrams/Fig_10_RAG_Semantic_Search_Flow.png)

**Fig. 4.10: RAG semantic-search flow**

**Table 4.5: RAG similarity bands**

| Cosine similarity | Interpretation |
|-------------------|----------------|
| 0.00 – 0.49 | No meaningful match |
| 0.50 – 0.64 | Weak match — metadata attached |
| 0.65 – 0.74 | Moderate — MEDIUM/HIGH alert |
| 0.75 – 0.89 | Strong — HIGH/CRITICAL alert |
| 0.90 – 1.00 | Very strong — CRITICAL |

**Table 4.6: MITRE ATT&CK technique coverage**

| Technique | ID | Alert type |
|-----------|----|-----------|
| C2 Application-Layer Protocol | T1071.001 | C2_BEACON |
| Application-Layer Protocol: DNS | T1071.004 | DNS_TUNNEL |
| Remote Services: SMB | T1021.002 | LATERAL_MOVEMENT |
| Remote Services: RDP | T1021.001 | LATERAL_MOVEMENT_RDP |
| Exfiltration over Alternative Protocol | T1048.003 | DATA_EXFILTRATION |
| Network Service Discovery | T1046 | PORT_SCAN |
| Brute Force: SSH | T1110.001 | BRUTE_FORCE |
| Brute Force: Credential Spray | T1110.003 | CREDENTIAL_SPRAY |
| Exploit Public-Facing Application | T1190 | EXPLOIT_APP |
| Obfuscated Files / High Entropy | T1027 | HIGH_ENTROPY_PAYLOAD |
| Protocol Tunneling | T1572 | PROTOCOL_TUNNEL |
| Unix Reverse Shell | T1059.004 | REVERSE_SHELL |
| Dynamic Resolution: DGA | T1568.002 | DGA_DETECTED |
| Exfiltration over C2 Channel | T1041 | C2_EXFIL |
| Active Scanning | T1595 | ACTIVE_SCAN |

## 4.9 Security Design

The platform authenticates every request with a JWT (HS256, 480-minute expiry) issued via an OAuth2 password flow; passwords are bcrypt-hashed (work factor 12). Internal services (Kafka, PostgreSQL, Redis, ChromaDB) are reachable only on the internal bridge network, with Redis and ChromaDB additionally credential-protected. All secrets live in `.env` (never committed). PII is redacted from every packet event before it reaches Kafka, and every block/dismiss action is written to `audit_log` with the username, action, resource, timestamp, and client IP.

---

# CHAPTER 5: IMPLEMENTATION

## 5.1 Tools and Technologies Used

The platform is implemented in Python for all backend services and JavaScript (React) for the dashboard, orchestrated with Docker Compose. Table 5.1 lists the significant components.

**Table 5.1: Tools and technologies**

| Technology | Role |
|------------|------|
| Python 3.11 | All backend services |
| Scapy 2.5+ | Packet capture and layer parsing (DPI) |
| Apache Kafka (Confluent 7.5.0) | Event bus between all services |
| ChromaDB | Vector store for RAG (4 collections) |
| sentence-transformers (all-MiniLM-L6-v2) | Local CPU text embeddings (384-dim) |
| scikit-learn (IsolationForest 1.4.2) | Sequence anomaly detection |
| PostgreSQL + TimescaleDB (pg16) | Incidents, alerts, campaigns, packet hypertable |
| Redis 7 | Embedding cache, block list, session windows |
| FastAPI | REST API gateway with JWT auth |
| React 18 + Vite | Single-page SOC dashboard |
| n8n | SOAR workflow automation |
| Prometheus + Grafana | Metrics and observability |
| Docker Compose v2 | One-command deployment of 14 services |
| OpenAI GPT-4o mini (default) | LLM investigation (provider-swappable) |

## 5.2 Modules Description

**DPI Sensor (`src/dpi/sensor.py`)** captures packets with Scapy's asynchronous sniffer, parses each into a 21-field `PacketEvent` (addresses, ports, protocol, payload size, Shannon entropy, TLS/DNS/HTTP metadata, and lightweight suspicion flags), and calls `_mask_pii()` to redact email addresses and credential parameters before publishing, gzip-compressed, to `raw-packets`. It supports both IPv4 and IPv6 and detects eight threat signals (high entropy, suspicious ports, DGA domains, C2 beacon timing, cleartext credentials, TTL anomalies, malware user agents, external database access).

**RLM (behavioural) Engine (`src/models/rlm_engine.py`)** consumes `raw-packets`, updates the EMA `BehaviorProfile` for the source IP, renders it to natural-language text, and scores it. The `SequenceAnomalyDetector` holds a 50-observation rolling buffer per IP and blends an IsolationForest score at 25 % weight with the ChromaDB cosine base score; when the blended score reaches 0.65 it emits an alert to `threat-alerts`. It also guards against EMA-poisoning by tracking day-over-day baseline drift, and persists profiles to PostgreSQL and ChromaDB periodically.

**MCP Orchestrator (`src/agents/mcp_orchestrator.py`)** consumes `threat-alerts`. For HIGH/CRITICAL alerts it runs four evidence-gathering tools concurrently with `asyncio.gather()` — a threat-database lookup, the host profile, recent alerts, and an AbuseIPDB reputation check — compresses each result with `_summarize_result()`, then issues a single LLM call (`tools=None`, `max_tokens=1024`) returning a structured JSON verdict. It writes the incident, updates the alert, and fires campaign correlation as a non-blocking background task. If the LLM is unavailable, `_rule_based_verdict()` produces a deterministic fallback so incidents are still created.

**LLM Provider (`src/agents/llm_provider.py`)** presents one `complete()` interface over OpenAI, Anthropic, and Google back-ends and returns a unified response object (content plus token counts). **CTI Scraper (`src/ingestion/threat_intel_scraper.py`)** pulls CVEs from NVD (CVSS ≥ 7.0), the CISA KEV catalogue, MITRE ATT&CK techniques, OTX pulses, and Abuse.ch indicators on scheduled cycles, chunks them, and upserts embeddings into ChromaDB through the embedder. **Embedder (`src/ingestion/embedder.py`)** is the single governed entry point for all vector writes (`batch_upsert()`). **Traffic Simulator (`src/simulation/traffic_simulator.py`)** generates 17 threat scenarios (Tables 5.3 and 5.4) as bursts of 30–150 realistic `PacketEvent`s published to `raw-packets`. **API Gateway (`src/api/gateway.py`)** exposes the dashboard's REST endpoints (Table 5.6) with JWT authentication. **React Dashboard (`frontend/src/CyberSentinel_Dashboard.jsx`)** is a six-tab HUD (Table 5.7). **n8n SOAR (`n8n/workflows/`)** provides five automation workflows.

Table 5.2 summarises the modules.

**Table 5.2: Module summary**

| Module | File | Responsibility |
|--------|------|----------------|
| DPI Sensor | `src/dpi/sensor.py` | Capture, parse, mask PII, publish |
| RLM Engine | `src/models/rlm_engine.py` | EMA profiling, hybrid scoring, alert emission |
| MCP Orchestrator | `src/agents/mcp_orchestrator.py` | 1-call investigation, incidents, campaigns |
| LLM Provider | `src/agents/llm_provider.py` | Provider-agnostic model access |
| CTI Scraper | `src/ingestion/threat_intel_scraper.py` | Threat-intel ingestion and embedding |
| Embedder | `src/ingestion/embedder.py` | Governed vector-store writes |
| Simulator | `src/simulation/traffic_simulator.py` | 17-scenario traffic generation |
| API Gateway | `src/api/gateway.py` | REST + JWT + per-source queries |
| Dashboard | `frontend/src/CyberSentinel_Dashboard.jsx` | 6-tab SOC UI |

**Table 5.3: Simulator scenarios — MITRE-mapped (12)**

| Scenario | MITRE ID | Severity | Weight | Burst |
|----------|----------|----------|--------|-------|
| C2 Beacon | T1071.001 | CRITICAL | 5 | ~60 |
| Data Exfiltration | T1048.003 | HIGH | 4 | ~80 |
| Lateral Movement SMB | T1021.002 | HIGH | 3 | ~50 |
| Port Scan | T1046 | MEDIUM | 2 | ~150 |
| DNS Tunneling | T1071.004 | HIGH | 3 | ~100 |
| Brute Force SSH | T1110.001 | HIGH | 3 | ~120 |
| RDP Lateral Movement | T1021.001 | HIGH | 3 | ~45 |
| Exploit Public App | T1190 | CRITICAL | 4 | ~30 |
| High Entropy Payload | T1027 | HIGH | 3 | ~40 |
| Protocol Tunneling | T1572 | HIGH | 3 | ~60 |
| Credential Spray | T1110.003 | HIGH | 3 | ~90 |
| Reverse Shell | T1059.004 | CRITICAL | 4 | ~45 |

**Table 5.4: Simulator scenarios — novel / AI-classified (5)**

| Scenario | Severity | Behaviour |
|----------|----------|-----------|
| Polymorphic Beacon | HIGH | Beacon intervals mutate to evade timing detection |
| Covert Storage Channel | HIGH | Data hidden in IP-header reserved/ToS fields |
| Slow-Drip Exfil | HIGH | 1–2 bytes per packet over thousands of sessions |
| Mesh C2 Relay | CRITICAL | Multi-hop internal relay, no direct external contact |
| Synthetic Idle Traffic | MEDIUM | Mimics legitimate traffic but statistically wrong |

**Table 5.5: Token budget per investigation**

| Component | Input tokens |
|-----------|-------------|
| System prompt | ~120 |
| Alert (slim, no raw_event) | ~80 |
| Threat-DB result | ~120 |
| Host-profile result | ~60 |
| Recent-alerts result | ~80 |
| IP-reputation result | ~40 |
| Instruction suffix | ~53 |
| **Total input** | **~553** |
| LLM output (JSON verdict) | ~280 |

**Table 5.6: REST API endpoints (selected)**

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/token` | Obtain JWT (OAuth2 password flow) |
| `GET /api/v1/dashboard` | 24-hour SOC statistics |
| `GET /api/v1/alerts` | Filterable alert list |
| `GET /api/v1/incidents` | Incident list with block flag |
| `POST /api/v1/incidents/{id}/block` | Analyst approves a block |
| `POST /api/v1/incidents/{id}/dismiss` | Analyst dismisses |
| `GET /api/v1/block-recommendations` | Pending recommendations (priority-sorted) |
| `GET /api/v1/campaigns` | Attacker campaigns (kill-chain view) |
| `GET /api/v1/hosts/{ip}` | Host profile + recent alerts |
| `POST /api/v1/threat-search` | Semantic ChromaDB search |

**Table 5.7: SOC dashboard tabs**

| Tab | Content |
|-----|---------|
| OVERVIEW | Risk gauge, 6 KPI cards, 24-hour alert timeline, platform-health radar |
| ALERTS | Filterable table, severity badges, anomaly-score bars, MITRE tags |
| INCIDENTS | Lifecycle cards, block-recommended badge, campaign links |
| RESPONSE | Pending block recommendations, BLOCK/DISMISS buttons, 30-s poll |
| THREAT INTEL | Semantic search results with similarity % and MITRE badge |
| HOSTS | Per-IP RLM profile, block status, recent alerts |

**Detection methodology and algorithms.** Every alert passes through a six-step pipeline: (1) data collection — packets captured or simulated and built into a 21-field `PacketEvent`; (2) cleaning — `_mask_pii()` redaction, then gzip publish to `raw-packets`; (3) feature extraction — the EMA update produces per-host features (`avg_bytes_per_min`, `avg_entropy`, `observation_count`, dominant protocols, typical ports); (4) scoring — the profile text is embedded and scored; (5) alert emission when the blended score crosses the threshold; and (6) output generation — incident creation, campaign correlation, block recommendation, and SOAR notification. Four cooperating algorithms drive this pipeline. First, *Shannon entropy* is computed per payload to flag encrypted or packed content on non-standard ports (it triggers above 7.2):

[[EQ]] H(X) = − Σ p(xᵢ) · log₂ p(xᵢ)     (5.1)

Second, an *Exponential Moving Average* maintains an O(1)-memory baseline per host with smoothing factor α = 0.1:

[[EQ]] EMAₜ = (1 − α) · EMAₜ₋₁ + α · xₜ     (5.2)

Third, *hybrid scoring* blends the ChromaDB cosine base score with the IsolationForest sequence score at 25 % weight:

[[EQ]] final_score = 0.75 · base_score + 0.25 · isolation_forest_score     (5.3)

Fourth, the *one-call investigation* algorithm replaces an iterative agentic loop: the orchestrator gathers four tool results in parallel, compresses them, and issues a single structured LLM call — collapsing a ~6,500-token three-call loop to ~553 tokens (see Section 5.4 and Fig. 5.6).

## 5.3 Flow Chart

The end-to-end lifecycle of a single alert — from packet capture to analyst decision — is shown as a master flow chart in Fig. 5.1 and, in UML activity form, in Fig. 5.2. The AI investigation stage in the middle of that flow is expanded as a sequence diagram in Fig. 5.3.

![Master end-to-end flowchart](assets/diagrams/Fig_07_Master_End_to_End_Flowchart.png)

**Fig. 5.1: Master end-to-end flow chart**

![Activity diagram alert lifecycle](assets/diagrams/Fig_13_Activity_Diagram_Alert_Lifecycle.png)

**Fig. 5.2: Activity diagram — alert lifecycle**

![Sequence diagram one-call AI](assets/diagrams/Fig_14_Sequence_Diagram_One_Call_AI.png)

**Fig. 5.3: Sequence diagram — one-call AI investigation**

## 5.4 Integration of Modules

The modules are integrated exclusively through the Kafka event bus and shared data stores, never by direct service-to-service HTTP calls in the detection path. This is what allows the live DPI sensor (Fig. 5.4) and the traffic simulator (Fig. 5.5) to be interchangeable: both publish to `raw-packets`, and everything downstream is identical. The single-call design achieves a large token saving over a conventional agentic loop (Fig. 5.6).

![Pipeline 1 DPI real traffic](assets/diagrams/Fig_08_Pipeline1_DPI_Real_Traffic.png)

**Fig. 5.4: Pipeline 1 — DPI real traffic**

![Pipeline 2 traffic simulator](assets/diagrams/Fig_09_Pipeline2_Traffic_Simulator.png)

**Fig. 5.5: Pipeline 2 — traffic simulator**

![Token economics comparison](assets/diagrams/Fig_11_Token_Economics_Comparison.png)

**Fig. 5.6: Token economics — 3-call loop vs 1-call pipeline**

Beyond the detection path, an incident that is flagged `block_recommended` surfaces on the RESPONSE tab, where the analyst approves (writing a firewall rule and an audit-log entry, and marking the incident RESOLVED) or dismisses it; no block is ever executed automatically. Every incident is also correlated, as a fire-and-forget background task, with a 24-hour attacker campaign keyed on the source IP, so the union of MITRE stages across related incidents reveals the kill chain through the `GET /api/v1/campaigns` endpoint. Finally, a Kafka-to-webhook bridge routes critical events to five n8n SOAR workflows (critical-alert enrichment, daily SOC report, CVE-intel pipeline, SLA watchdog, and weekly board report).

---

# CHAPTER 6: RESULT

## 6.1 Testing

Testing was carried out at two levels: automated unit and integration tests for the deterministic core logic, and manual end-to-end verification of the running platform. The automated suite (run with `pytest tests/`) is summarised in Table 6.1.

**Table 6.1: Automated test suite summary**

| Test file | Focus | Test functions |
|-----------|-------|----------------|
| `tests/unit/test_detectors.py` | Entropy, suspicious-port, DGA, C2-beacon timing, cleartext credentials, TTL anomaly, malware user-agent detection | 36 |
| `tests/unit/test_profile.py` | EMA profile creation, update, convergence, text rendering, serialisation | 5 |
| `tests/integration/test_api.py` | Health check, authenticated dashboard access, rejection of unauthenticated requests | 3 |

The detector tests are pure functions with known inputs — random bytes must produce near-maximal Shannon entropy while constant bytes produce zero; port 4444 (a common reverse-shell port) must be flagged while port 443 must not; regularly-spaced connection intervals must trip the C2-beacon heuristic while irregular ones must not. The profile tests confirm that repeated EMA updates converge towards the true mean and that a profile round-trips through serialisation without loss. The integration tests confirm the API rejects requests without a valid JWT and returns dashboard data once authenticated.

End-to-end testing used the traffic simulator to drive all 17 scenarios through the live pipeline, confirming that alerts appear on the dashboard, that HIGH/CRITICAL alerts produce AI-investigated incidents, that block recommendations surface on the RESPONSE tab, and that approving a block writes both a firewall rule and an audit-log entry. The live DPI sensor was also validated on a physical Windows adapter, confirming that real host traffic is captured, profiled, and surfaced under the Live Network SOC view.

## 6.2 Validation

Validation checked the running platform against the product goals of Chapter 1 and the requirements of Chapter 3. Results are summarised in Table 6.2, and the LLM cost model — the platform's only recurring external cost — in Table 6.3.

**Table 6.2: Validation of goals against observed behaviour**

| Goal | Target | Observed |
|------|--------|----------|
| Packet-to-alert latency | < 1 s | Alerts appear within about a second of a burst |
| AI investigation time | < 45 s | A few seconds under normal LLM latency |
| LLM calls per investigation | exactly 1 | One call per investigation (confirmed in logs) |
| Tokens per investigation | < 600 | ~553 input tokens |
| MITRE technique coverage | 15 | 15 techniques mapped (Table 4.6) |
| No auto-block | 0 automatic blocks | Blocks occur only after an analyst click; all audited |
| IPv4 + IPv6 capture | both | Both address families parsed |
| PII redaction | none in Kafka | Emails/credentials redacted before publish |
| Campaign grouping | 24-h window | Same-source incidents grouped; severity ratchets up |
| One-command deploy | `docker compose up -d` | 14 containers start and recover across restarts |

**Table 6.3: LLM cost model and budget runway (GPT-4o mini)**

| Budget | Investigations | Days at 30-min interval |
|--------|----------------|-------------------------|
| $1 | ~6,000 | ~125 |
| $5 | ~30,000 | ~625 |
| $10 | ~60,000 | ~1,250 |
| $20 | ~120,000 | ~2,500 |

The gap between the 194-day industry breach-detection average and the platform's sub-second alert generation is the headline validation result: for behaviour the model has a signature for, the time from malicious packet to analyst-visible alert is a fraction of a second, and the time to a fully AI-written incident is a few seconds rather than hours. The token-economy redesign (Fig. 5.6) reduced cost per investigation by roughly 90 % and latency five-fold versus a conventional multi-call agentic loop. Of 16 documented limitations, 9 are fully fixed and 3 partially fixed in v1.3.0.

## 6.3 Screenshots

The following figures show the running platform. *(Insert the corresponding PNG under each caption in the Word document.)*

`![Login](assets/screenshots/login.png)`
**Fig. 6.1: Secure access terminal (login)**

`![Overview Simulated](assets/screenshots/overview_sim.png)`
**Fig. 6.2: Dashboard — Simulated Threat Lab (Overview: risk gauge, KPI cards, 24-hour timeline, platform-health radar)**

`![Overview Live](assets/screenshots/overview_live.png)`
**Fig. 6.3: Dashboard — Live Network SOC (Overview showing live-captured traffic)**

`![Landing](assets/screenshots/landing.png)`
**Fig. 6.4: Landing page (platform overview and pipeline explainer)**

---

# CHAPTER 7: FUTURE ENHANCEMENTS

The platform is a complete, production-quality single-node build; the following enhancements would move it towards a hardened, distributed deployment. Each is grounded in an honestly-assessed current limitation (Table 7.1).

**Table 7.1: Current limitations and planned mitigations**

| Current limitation | Planned mitigation |
|--------------------|--------------------|
| Single-machine deployment — one host is a single point of failure | Kubernetes migration with a non-Confluent (Bitnami) Kafka image; stateless services as scalable Deployments; PostgreSQL read replicas |
| No mutual TLS; Kafka has no authentication on the internal network | Kafka SASL/SCRAM + per-service TLS certificates (or an nginx TLS sidecar) |
| Default credentials shipped for demo | Mandatory credential rotation and a secrets vault (HashiCorp Vault / cloud secret manager) |
| EMA has limited temporal memory (IsolationForest partly mitigates) | An LSTM/Transformer sequence model for full progression-anomaly detection |
| Attacker tracking is per-source-IP only | Cross-IP attacker fingerprinting via a graph database (e.g., Neo4j) |
| Tested on simulated traffic | Validation against a labelled real-traffic dataset (CICIDS2017 / UNSW-NB15) |
| Blocks are recorded internally, not enforced on the wire | Integration with a physical firewall, cloud security group, or EDR |
| Single admin account (RBAC schema exists but unenforced) | Enforce analyst / responder / viewer / admin roles in the API |
| Static embedding model | A governed re-embedding pipeline to adopt newer embedding models |
| No alert de-duplication window | Redis-based suppression of repeated alerts from one IP |

Additional roadmap items include an analyst feedback loop that tunes the anomaly threshold and LLM prompt from approve/dismiss decisions, full multi-tenant isolation, a compliance-controls layer (GDPR, SOC 2, ISO 27001), and a lightweight mobile client for on-call analysts.

---

# REFERENCES

References cited in the text follow the author-year convention and are listed alphabetically below.

AbuseIPDB (2024), *AbuseIPDB API v2 Documentation*. Available: https://www.abuseipdb.com/api. Accessed: April 2026.

Alhuzali, A. (2025), "LLM-Powered Threat Intelligence: A Retrieval-Augmented Generation Approach", *PeerJ Computer Science*. Available: https://peerj.com/articles/cs-3371.

AlienVault (2024), *Open Threat Exchange (OTX) API*. Available: https://otx.alienvault.com/api. Accessed: April 2026.

Apache Software Foundation (2023), *Apache Kafka Documentation, 3.x*. Available: https://kafka.apache.org/documentation. Accessed: April 2026.

Bathiri, K. and Vijayakumar, M. (2024), "Enhancing Intrusion Detection Through Deep Packet Inspection with Machine Learning Approaches", *Proceedings of the IEEE ADICS Conference*. Available: https://ieeexplore.ieee.org/document/10533473.

Chroma (2024), *ChromaDB Documentation*. Available: https://docs.trychroma.com. Accessed: April 2026.

Cybersecurity and Infrastructure Security Agency (2024), *Known Exploited Vulnerabilities Catalog*. Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog. Accessed: April 2026.

"CyberRAG: An Agentic Retrieval-Augmented Generation Cyber Attack Classification Tool" (2025), *arXiv preprint*. Available: https://arxiv.org/pdf/2507.02424.

"Deep Learning-Based Intrusion Detection Systems: A Survey" (2025), *arXiv preprint*. Available: https://arxiv.org/html/2504.07839v3.

"Efficient LLM Inference: Reducing Token Usage Without Losing Quality" (2024), *arXiv preprint*.

"Evolution of Agentic AI: From Single to Gen-5 Pipelines" (2025), *arXiv preprint*. Available: https://arxiv.org/pdf/2512.06659.

Foreman, J., Waters, W. et al. (2024), "Detection of Hacker Intention Using Deep Packet Inspection", *MDPI Journal of Cybersecurity and Privacy*, Vol. 4, No. 4, Art. 37. Available: https://www.mdpi.com/2624-800X/4/4/37.

Halappanavar, M. et al. (2024), *Retrieval-Augmented Generation for Robust Cyber Defense*, Pacific Northwest National Laboratory, Technical Report PNNL-36792.

IBM Security (2024), *Cost of a Data Breach Report 2024*, IBM Corporation.

Koumar, J., Hynek, K. et al. (2025), "CESNET-TimeSeries24: A Time-Series Dataset for Network Anomaly Detection", *Nature Scientific Data*. Available: https://www.nature.com/articles/s41597-025-04603-x.

Liu, F.T., Ting, K.M. and Zhou, Z.-H. (2008), "Isolation Forest", *Proceedings of the 8th IEEE International Conference on Data Mining (ICDM)*, Pisa, Italy, pp. 413–422.

MITRE Corporation (2023), *MITRE ATT&CK Framework, v14*. Available: https://attack.mitre.org. Accessed: April 2026.

Molleti, R., Goje, V. et al. (2024), "Automated Threat Detection and Response Using Large Language Model Agents", *World Journal of Advanced Research and Reviews (WJARR)*. Available: https://wjarr.com/sites/default/files/WJARR-2024-3329.pdf.

National Institute of Standards and Technology (2023), *National Vulnerability Database API v2.0*. Available: https://nvd.nist.gov/developers. Accessed: April 2026.

OpenAI (2024), *GPT-4o mini Model and API Reference*. Available: https://platform.openai.com/docs. Accessed: April 2026.

Pedregosa, F. et al. (2011), "Scikit-learn: Machine Learning in Python", *Journal of Machine Learning Research*, Vol. 12, pp. 2825–2830.

"LLM Prompt Compression: Survey and Best Practices" (2025), *arXiv preprint*.

Ramírez, S. (2018), *FastAPI Documentation*. Available: https://fastapi.tiangolo.com. Accessed: April 2026.

Reimers, N. and Gurevych, I. (2019), "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks", *Proceedings of the 2019 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, Hong Kong, pp. 3982–3992.

Roesch, M. (1999), "Snort — Lightweight Intrusion Detection for Networks", *Proceedings of the 13th USENIX Systems Administration Conference (LISA)*, Seattle, USA, pp. 229–238.

"Security of LLM-Based Agents: A Comprehensive Survey" (2025), *Forensic Science International: Digital Investigation (ScienceDirect)*.

Strom, B.E. et al. (2020), *MITRE ATT&CK: Design and Philosophy*, MITRE Corporation. Available: https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf.

"Anomaly Detection Using Unsupervised Online Machine Learning" (2025), *arXiv preprint*. Available: https://arxiv.org/html/2509.01375v1.

Zhang, J. et al. (2025), "When LLMs Meet Cybersecurity: A Systematic Literature Review", *Cybersecurity (Springer)*. Available: https://cybersecurity.springeropen.com/articles/10.1186/s42400-025-00361-w.

n8n GmbH (2024), *n8n Workflow Automation Documentation*. Available: https://docs.n8n.io. Accessed: April 2026.

---

# APPENDIX A: PROJECT WORK PLAN

The project was executed across four versions (v1.0.0–v1.3.0) over a thirteen-week capstone cycle, in the eleven phases of Table A.1; the corresponding schedule is shown in the Gantt chart of Fig. A.1.

**Table A.1: Development phases**

| Phase | Task | Duration | Output |
|-------|------|----------|--------|
| 1 | Research and literature survey (8 domains) | 1 week | 26-paper bibliography mapped to design decisions |
| 2 | Architecture design and ADRs 1–8 | 1 week | Four-layer event-driven design; RAG governance |
| 3 | Threat-signature design and ChromaDB seeding | 1 week | 8 MITRE-mapped behavioural signatures |
| 4 | v1.0.0 — DPI, RLM EMA, 3-call loop, basic dashboard | 2 weeks | 14 containers up; baseline detection |
| 5 | v1.1.0 — investigation optimisation + human-in-the-loop | 1 week | One-call pipeline; RESPONSE tab; multi-provider LLM |
| 6 | v1.2.0 — pipeline unification + UX overhaul | 1 week | Simulator feeds full pipeline; 4-part AI summaries |
| 7 | v1.2.x — n8n automation + infrastructure fixes | 1 week | Activation script; SLA watchdog + Grafana fixes |
| 8 | v1.3.0 — detection hardening + documentation | 2 weeks | IsolationForest; campaigns; IPv6; PII masking |
| 9 | Testing — unit + integration | 1 week | Validated detection logic and API integration |
| 10 | Documentation — SRS, TRD, PRD, architecture | 1 week | Complete `docs/` set |
| 11 | Final validation — 12-item success checklist | 1 week | All success criteria met |

![Gantt chart work plan](assets/diagrams/Fig_19_Gantt_Chart_Work_Plan.png)

**Fig. A.1: Gantt chart — project work plan**

---

*CyberSentinel AI v1.3.0 — Application Stream Project Report — Department of Computer Application, JSSSTU, Mysuru — 2025–2026.*
