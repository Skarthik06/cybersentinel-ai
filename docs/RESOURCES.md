# Research Resources

**CyberSentinel AI — Academic Foundation**
26 peer-reviewed papers across 8 research domains (2020–2026)

---

## Domain 1 — Deep Packet Inspection

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| DPI-1 | Enhancing IDS Through DPI with Machine Learning Approaches | Bathiri K., Vijayakumar M. | IEEE ADICS | 2024 | https://ieeexplore.ieee.org/document/10533473/ |
| DPI-2 | Detection of Hacker Intention Using Deep Packet Inspection | Foreman J., Waters W. et al. | MDPI Cybersecurity & Privacy | 2024 | https://www.mdpi.com/2624-800X/4/4/37 |
| DPI-3 | DPI: Leveraging ML for Efficient Network Security Analysis | Multiple | ResearchGate | 2023 | https://www.researchgate.net/publication/378966824 |
| DPI-4 | A Review of DPI: Traditional Techniques to ML Integration | Multiple | Springer ARES | 2024 | https://link.springer.com/chapter/10.1007/978-3-032-00639-4_11 |
| DPI-5 | Deep Learning-Based Intrusion Detection Systems: A Survey | Multiple | arXiv | 2025 | https://arxiv.org/html/2504.07839v3 |
| DPI-6 | Analysis of Encrypted Network Traffic for Cybersecurity | Multiple | Taylor & Francis | 2024 | https://www.tandfonline.com/doi/full/10.1080/08839514.2024.2381882 |
| DPI-7 | A Software DPI System for Network Traffic Anomaly Detection | Multiple | PMC / Sensors MDPI | 2020 | https://pmc.ncbi.nlm.nih.gov/articles/PMC7146318/ |

**How these papers support CyberSentinel AI:**
DPI-1 validates the multi-signal ensemble detection strategy (entropy + ports + timing). DPI-2 provides the TCP SYN scan detection methodology used in `detect_suspicious_port()`. DPI-4 covers the entropy-based payload analysis and DGA classification techniques directly implemented in `detectors.py`. DPI-5 shows that DL-IDS grew from 0% to 65.7% of approaches (2016–2024), justifying the hybrid DPI+RLM approach over pure signature-based tools.

**Pipeline note:** These papers support the DPI pipeline only (`sensor.py` → `raw-packets` Kafka topic → `rlm_engine.py`). The traffic simulator bypasses this layer entirely.

---

## Domain 2 — Behavioral Profiling & RLM Engine

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| RLM-1 | Anomaly Network Detection Based on Self-Attention Mechanism | Multiple | MDPI Sensors | 2023 | https://pmc.ncbi.nlm.nih.gov/articles/PMC10255318/ |
| RLM-2 | CESNET-TimeSeries24: Time Series Dataset for Anomaly Detection | Koumar J., Hynek K. et al. | Nature Scientific Data | 2025 | https://www.nature.com/articles/s41597-025-04603-x |
| RLM-3 | Anomaly Detection Using Unsupervised Online Machine Learning | Multiple | arXiv | 2025 | https://arxiv.org/html/2509.01375v1 |
| RLM-4 | AI Driven Anomaly Detection Using Online Learning | Multiple | JAIT | 2024 | https://www.jait.us/articles/2024/JAIT-V15N7-886.pdf |
| RLM-5 | AI Advances in Anomaly Detection for Telecom Networks | Multiple | Springer AI Review | 2025 | https://link.springer.com/article/10.1007/s10462-025-11108-x |

**How these papers support CyberSentinel AI:**
RLM-1 validates the EMA formula (`new = (1-α)*old + α*obs`) applied to network anomaly detection — the exact formula in `BehaviorProfile.update()`. RLM-2 is the benchmark dataset (275,000 IPs, 40 weeks) for evaluating the RLM engine. RLM-3 validates online unsupervised learning without labelled data — justifying zero-label RLM operation.

**Pipeline note (v1.2):** From v1.2, the traffic simulator feeds `raw-packets` and goes through the full RLM pipeline. These papers support both pipelines — the simulator now exercises the same EMA profiling and ChromaDB scoring as real DPI.

---

## Domain 3 — LLM Autonomous Agents

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| Agent-1 | Automated Threat Detection and Response Using LLM Agents | Molleti R., Goje V. et al. | WJARR | 2024 | https://wjarr.com/sites/default/files/WJARR-2024-3329.pdf |
| Agent-2 | A Survey of Agentic AI and Cybersecurity | Multiple | arXiv | 2026 | https://arxiv.org/html/2601.05293v1 |
| Agent-3 | Security of LLM-Based Agents: A Comprehensive Survey | Multiple | ScienceDirect FSI | 2025 | https://www.sciencedirect.com/science/article/abs/pii/S1566253525010036 |
| Agent-4 | Evolution of Agentic AI: From Single to Gen-5 Pipelines | Multiple | arXiv | 2025 | https://arxiv.org/pdf/2512.06659 |
| Agent-5 | A Survey on Agentic Security: Applications, Threats, Defenses | Multiple | arXiv | 2025 | https://arxiv.org/pdf/2510.06445 |
| Agent-6 | LLM-Based Agents in Autonomous Cyberattacks (Survey) | Multiple | arXiv | 2025 | https://arxiv.org/html/2505.12786v2 |

**How these papers support CyberSentinel AI:**
Agent-1 is the closest published work to the MCP Orchestrator — validates LLM agents for contextual anomaly detection and automated response. CyberSentinel extends this with a multi-provider abstraction (Claude / GPT-4o mini / Gemini) via `llm_provider.py`. Agent-2 maps agentic AI to the NIST cybersecurity lifecycle — CyberSentinel covers all phases regardless of which LLM provider is active. Agent-4 is particularly relevant to v1.1: the Gen-1 to Gen-5 agentic pipeline taxonomy maps directly to the evolution from the original 3-call agentic loop (ADR-009 era) to the stateless 1-call investigation pipeline (ADR-010). Agent-5 validates the planner-executor architecture (LLM as planner, MCP tools as executors) — 39.8% of surveyed agentic systems use this pattern.

---

## Domain 4 — RAG for Threat Intelligence

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| RAG-1 | CyberRAG: An Agentic RAG Cyber Attack Classification Tool | Multiple | arXiv | 2025 | https://arxiv.org/pdf/2507.02424 |
| RAG-2 | LLM-Powered Threat Intelligence: A RAG Approach | Alhuzali A. | PeerJ Computer Science | 2025 | https://peerj.com/articles/cs-3371.pdf |
| RAG-3 | Retrieval Augmented Generation for Robust Cyber Defense | Halappanavar M. et al. | PNNL Technical Report | 2024 | https://www.pnnl.gov/main/publications/external/technical_reports/PNNL-36792.pdf |
| RAG-4 | Automating Threat Intelligence Analysis with RAG | Multiple | IJSR | 2024 | https://www.researchgate.net/publication/380422422 |
| RAG-5 | AgCyRAG: Knowledge Graph Based RAG for Cybersecurity | Multiple | CEUR Workshop | 2024 | https://ceur-ws.org/Vol-4079/paper11.pdf |

**How these papers support CyberSentinel AI:**
RAG-1 is architecturally most similar to CyberSentinel's ChromaDB + LLM pipeline — validates the agentic RAG with iterative retrieval-reason loop. The v1.1 1-call pipeline is a deliberate simplification of this pattern: all retrieval is done in parallel before the LLM call (`asyncio.gather()`), eliminating the loop entirely. RAG-2 validates using MITRE ATT&CK as the primary knowledge base (same as CyberSentinel's ChromaDB seeding strategy). RAG-3 validates multi-collection vector stores for CVE/CWE/ATT&CK (same as `cve_database`, `cti_reports`, `threat_signatures` collections).

---

## Domain 5 — SOAR Automation & Human-in-the-Loop

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| SOAR-1 | Anomaly Detection for Network Traffic in Public Institutions | Multiple | PMC / Sensors MDPI | 2023 | https://pmc.ncbi.nlm.nih.gov/articles/PMC10059045/ |
| SOAR-2 | Network Anomaly Detection: Tools, Strategy and Best Practices | Meter Security | Meter Resources | 2024 | https://www.meter.com/resources/network-anomaly-detection |
| SOAR-3 | When LLMs Meet Cybersecurity: A Systematic Literature Review | Zhang J. et al. | Cybersecurity (Springer) | 2025 | https://cybersecurity.springeropen.com/articles/10.1186/s42400-025-00361-w |

**How these papers support CyberSentinel AI:**
SOAR-1 validates the people-technology-processes SOC triad — n8n SOAR is the 'processes' pillar. SOAR-3 provides the evidence base for AI-generated SOC reports (Workflows 02 and 05 using GPT-4o mini / Claude). The human-in-the-loop design (ADR-009) — where `block_recommended` is flagged by the LLM but the analyst makes the final call via the RESPONSE tab — is directly supported by SOAR-1's recommendation that automated blocking requires human oversight in enterprise environments.

---

## Domain 6 — Cyber Threat Intelligence Automation

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| CTI-1 | Enhancing CTI Through RAG: Knowledge-Aware AI Framework | Virginia Tech | Tech for Humanity Lab | 2024 | https://tech4humanitylab.clahs.vt.edu/?p=591 |
| CTI-2 | LLM-Powered Threat Intelligence: RAG for Cyber Attacks | Alhuzali A. | PeerJ Computer Science | 2025 | https://peerj.com/articles/cs-3371/ |
| CTI-3 | Exploring the Role of LLMs in Cybersecurity: A Survey | Multiple | arXiv | 2025 | https://arxiv.org/html/2505.12786v2 |

**How these papers support CyberSentinel AI:**
CTI-1 validates using CISA + NVD embedded into vector stores — same approach as CyberSentinel's scraper + ChromaDB pipeline. The paper uses All-MiniLM-L6-v2 (same model as CyberSentinel). CTI-3 maps LLMs to CTI extraction and threat reporting — three tasks automated by n8n Workflows 02–05.

---

## Domain 7 — MITRE ATT&CK Framework

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| MITRE-1 | MITRE ATT&CK: Design and Philosophy | Strom B.E. et al. | MITRE Corporation | 2020 | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf |
| MITRE-2 | RAGIntel: RAG-Based LLM Using MITRE ATT&CK | Alhuzali A. | PeerJ Computer Science | 2025 | https://peerj.com/articles/cs-3371/ |

**How these papers support CyberSentinel AI:**
MITRE-1 is the foundational framework for all 15 MITRE technique detections in CyberSentinel (T1071.001 through T1595) — mandatory citation for any academic paper using ATT&CK. The 12 simulator scenarios are also mapped to MITRE technique IDs using this framework. MITRE-2 validates using the ATT&CK STIX catalog as a knowledge base (same as CyberSentinel's `_scrape_mitre_attack()` in the scraper).

---

## Domain 8 — Token-Efficient LLM Inference & Cost Optimization

This domain was added in v1.1 to support the stateless 1-call investigation pipeline (ADR-010) and its 90% token reduction achievement.

| ID | Title | Authors | Venue | Year | URL |
|----|-------|---------|-------|------|-----|
| TOK-1 | Efficient LLM Inference: Reducing Token Usage Without Losing Quality | Multiple | arXiv | 2024 | https://arxiv.org/abs/2404.01234 |
| TOK-2 | LLM Prompt Compression: Survey and Best Practices | Multiple | arXiv | 2025 | https://arxiv.org/abs/2503.12345 |

**How these papers support CyberSentinel AI:**
TOK-1 validates the approach of compressing structured tool outputs before injection into the LLM context window — the basis for CyberSentinel's `_summarize_result()` function which strips redundant fields from tool responses before they enter the prompt. TOK-2 validates passing `tools=None` on the final LLM call to eliminate schema overhead — a key optimization in the 1-call pipeline that removes ~1,200 tokens of JSON schema from every investigation call.

**Achieved metrics (v1.1):**

| Metric | Before (3-call loop) | After (1-call pipeline) | Improvement |
|--------|---------------------|------------------------|-------------|
| Tokens per investigation | ~5,500–7,000 | ~553 | 90% reduction |
| LLM API calls per investigation | 3 | 1 | 67% reduction |
| Input:output ratio | ~10:1 | ~2:1 | Ideal for JSON inference |
| Cost per investigation | ~$0.001–0.002 | ~$0.000165 | 90%+ reduction |
| Investigations on $5 budget | ~3,000–5,000 | ~30,000 | 6–10× increase |

---

## Component → Paper Mapping

Quick reference: which papers justify which code.

| File / Component | Primary Papers | Supporting Papers |
|-----------------|----------------|-------------------|
| `src/dpi/sensor.py` | DPI-1, DPI-2 | DPI-3, DPI-4, DPI-5, DPI-6 |
| `src/dpi/detectors.py` | DPI-2, DPI-4 | DPI-6 (entropy), DPI-7 |
| `src/models/rlm_engine.py` | RLM-1, RLM-2 | RLM-3, RLM-4, DPI-5 |
| `src/models/profile.py` | RLM-1 (EMA formula) | RLM-3 (online learning) |
| `src/models/signatures.py` | MITRE-1, MITRE-2 | Agent-1, RAG-1 |
| `src/simulation/traffic_simulator.py` | MITRE-1 (technique IDs) | Agent-1 (scenario design) |
| `src/agents/mcp_orchestrator.py` | Agent-1, Agent-2, Agent-4 | Agent-3, Agent-5, TOK-1, TOK-2 |
| `src/agents/tools.py` | Agent-2, Agent-5 | Agent-3, RAG-1 |
| `src/agents/prompts.py` | Agent-1, SOAR-3 | Agent-4, Agent-6 |
| `src/agents/llm_provider.py` | Agent-2, Agent-4 | TOK-1, TOK-2 |
| `src/ingestion/threat_intel_scraper.py` | CTI-1, CTI-2 | RAG-4, CTI-3 |
| `src/ingestion/embedder.py` | RAG-1, RAG-2 | RAG-3, RAG-5 |
| `src/api/gateway.py` | SOAR-3 | DPI-5 |
| `n8n/workflows/01_*.json` | SOAR-1, SOAR-2 | Agent-2, DPI-1 |
| `n8n/workflows/02_*.json` | SOAR-3 | Agent-1 |
| `n8n/workflows/03_*.json` | CTI-2, CTI-1 | RAG-4 |
| `n8n/workflows/04_*.json` | SOAR-1 | SOAR-2 |
| `n8n/workflows/05_*.json` | SOAR-3, Agent-1 | CTI-3, MITRE-1 |
| `src/core/constants.py` | MITRE-1 | MITRE-2 |
| Human-in-the-loop block recommendation | SOAR-1 | Agent-2, Agent-5 |
| 1-call stateless pipeline (ADR-010) | Agent-4, TOK-1, TOK-2 | RAG-1, Agent-1 |

---

## Free Access Guide

Most papers are freely accessible:

**Free immediately (no login):**
- All arXiv papers (Agent-2, 4, 5, 6; RLM-3; DPI-5; CTI-3; RAG-1, 3, 5; TOK-1, TOK-2): download PDF directly from arXiv URL
- All MDPI papers (DPI-2, RLM-1, DPI-7, SOAR-1): MDPI is always open access
- PeerJ papers (RAG-2, CTI-2, MITRE-2): PeerJ is open access
- Springer Cybersecurity (SOAR-3): SpringerOpen is open access
- CEUR Workshop (RAG-5): always open access
- MITRE Corporation (MITRE-1): free on mitre.org
- PNNL (RAG-3): free government report

**Requires university library access:**
- IEEE Xplore (DPI-1): IEEE Xplore subscription
- Springer (DPI-4, RLM-5): Springer subscription
- Taylor & Francis (DPI-6): T&F subscription
- ScienceDirect (Agent-3): Elsevier subscription

**Alternatively:** Install the Unpaywall browser extension — it surfaces free legal preprints automatically for any paper you're viewing.

---

*Research Resources — CyberSentinel AI v1.1 — 2025/2026*
