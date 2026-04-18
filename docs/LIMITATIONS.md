# Limitations & Drawbacks

**CyberSentinel AI — Honest Assessment of Current Limitations**

This document is an honest technical evaluation of the platform's current limitations across four dimensions: technical, operational, security, and academic scope. Each drawback includes its severity, whether it is fixable, and what the fix would look like.

---

## 1. Technical Drawbacks

### EMA Has No Memory of Patterns

The RLM engine tracks running averages (EMA), not sequences. It cannot detect:

- **Slow-and-low attacks** that stay just below the anomaly threshold across days
- **Gradual ramp attacks** where traffic increases incrementally over weeks (boiling frog pattern)
- **Multi-stage kill chains** spread across days where each stage individually looks benign

**Why it matters:** A sophisticated attacker can evade EMA-based detection by never spiking — keeping every observation within the normal EMA band while still achieving their objective over a longer time horizon.

**What would fix it:** A model with temporal memory — LSTM or Transformer-based sequence model — would detect anomalous *progressions* rather than just anomalous *values*. The IsolationForest layer added in v1.3.0 partially addresses this by detecting anomalous score progressions across a 50-observation window. A full LSTM replacement remains future work.

**Severity:** Medium (IsolationForest mitigates the most acute cases) | **Fixable:** Yes

---

### EMA Poisoning Attack

A sophisticated attacker who knows the platform uses EMA profiling can deliberately train the baseline to accept malicious behavior as normal before launching the real attack:

```
Week 1: Send 1,100 bytes/min  → just above normal, no alert fires
Week 2: Send 1,300 bytes/min  → EMA adjusts upward to new level
Week 3: Send 1,800 bytes/min  → EMA now accepts this as baseline
Month 2: Send 50,000 bytes/min → baseline already poisoned, threshold not crossed
```

**What was fixed (v1.3.0):** `_check_ema_poisoning()` added to `src/models/rlm_engine.py`. On every scoring pass, the engine:
1. Writes a daily Redis snapshot of `avg_bytes_per_min` under key `ema_daily:{ip}:{YYYYMMDD}` (48-hour TTL).
2. Computes `delta = (today - yesterday) / yesterday`.
3. If `delta > RLM_POISON_MAX_DAILY_DELTA` threshold, fires a `HIGH`-severity `EMA_POISONING_DETECTED` alert.

**Severity:** High | **Status:** ✅ Fixed in v1.3.0

---

### Single Machine Deployment

All 14 Docker containers run on one physical or virtual machine. Consequences:

- **Machine goes down** → entire SOC platform is blind — no detection, no alerts, no investigation
- **Machine is attacked** → the defender itself is compromised — attacker can manipulate incident data, poison ChromaDB, or silence alerts
- **RAM pressure** → all 14 services compete for the same memory pool; under load, containers OOM-kill each other

**What would fix it:** Horizontal distribution via Kubernetes — Kafka on dedicated nodes, stateless services (API, MCP, RLM) as horizontally scalable Deployments, PostgreSQL with read replicas. Kubernetes was evaluated during v1.3.0 development but reverted due to an irresolvable conflict between Confluent Docker's `ClusterStatus` pre-flight check and SASL on ZooKeeper. The Docker Compose architecture is correct and production-quality for a single-node deployment; multi-node Kubernetes remains a future step.

**Severity:** High | **Fixable:** Yes — requires full Kubernetes migration with a non-Confluent Kafka image (bitnami/kafka) to avoid the SASL pre-flight issue

---

### DPI Sensor Platform Support

The DPI sensor originally required Npcap (Windows-only). Since v1.3.0, two paths exist:

| Path | Platform | How |
|------|---------|-----|
| Docker container (`network_mode: host`) | Linux, macOS, WSL2 | Container uses libpcap natively |
| `scripts/start_live_dpi.ps1` + Npcap | Windows host | Npcap driver required |

**Remaining limitation:** The Docker DPI container uses `network_mode: host`, which captures all traffic on the host's physical NICs. On Windows, Docker Desktop runs inside a Linux VM — the DPI container captures traffic on the VM's virtual interface, not the Windows host's physical NIC. Windows users who need to capture host traffic must use `start_live_dpi.ps1` with Npcap installed.

**Severity:** Low-Medium (Linux deployments fully covered; Windows has two options) | **Fixable:** Yes — Npcap is free to install

---

### ChromaDB Embedding Model is Static

The platform uses `all-MiniLM-L6-v2` pinned locally. This means:

- New attack techniques not covered by the model's training data (pre-2022 NLP corpus) may not embed meaningfully
- Semantic similarity for novel threat terminology may be weak
- Updating to a better embedding model requires rebuilding all four ChromaDB collections from scratch

**What would fix it:** Periodic model evaluation against a held-out set of threat descriptions, with a governed re-embedding process when a better model is available. The `embedder.py` governance layer already has version tracking — the migration path exists, it just needs to be executed.

**Severity:** Low-Medium | **Fixable:** Yes — requires re-embedding pipeline

---

## 2. Operational Drawbacks

### Alert Fatigue Risk

In a large network generating millions of packets per hour, even behavioral scoring can produce too many MEDIUM-severity alerts.

**What was fixed (v1.3.0):** `GET /api/v1/block-recommendations` now computes a composite `priority_score` (0–100) and returns results sorted highest-first:

```
priority_score = (severity_weight × 50) + (anomaly_score × 30) + (campaign_penalty × 20)
```

Analysts always see the highest-risk IPs at the top of their queue. **Status:** ✅ Fixed

**Remaining gap:** No auto-suppression of repeated alerts from the same IP within a rolling time window. An IP that generates 100 alerts over 10 minutes appears as 100 entries. Alert deduplication within a configurable window is future work.

**Severity:** Low-Medium | **Fixable:** Yes — Redis-based alert deduplication window

---

### No Persistent Attacker Tracking

**What was fixed (v1.3.0):** Campaign correlation via `_correlate_campaign_with_pool()` in `mcp_orchestrator.py`. Every incident is correlated with an `attacker_campaigns` record by source IP within a 24-hour window. MITRE stages are merged across all incidents in the campaign. `GET /api/v1/campaigns` exposes the full kill chain view. **Status:** ✅ Fixed

**Remaining gap:** Cross-IP attacker fingerprinting — recognizing the same attacker using different source IPs based on behavioral similarity. This would require a graph database layer (Neo4j) and is v3+ roadmap.

**Severity:** Low (intra-campaign tracking works; cross-IP tracking is future) | **Fixable:** Yes — graph DB for cross-IP correlation

---

### No LLM Investigation Fallback

**What was fixed (v1.3.0):** `_rule_based_verdict()` added to `mcp_orchestrator.py`. When any LLM call raises an exception, deterministic rules fire: `IF severity=CRITICAL AND anomaly_score > 0.75 → block_recommended=TRUE`. Incidents are still created, RESPONSE tab still shows recommendations, Slack alerts still send. Investigation summary explicitly notes `[NOTE: LLM unavailable — rule-based assessment]`. **Status:** ✅ Fixed

---

### n8n Is Not Enterprise-Grade SOAR

For production security operations, n8n has meaningful limitations:

| Limitation | Enterprise Alternative |
|-----------|----------------------|
| No built-in audit trail of workflow approvals | Splunk SOAR / Palo Alto XSOAR |
| Workflow failures are not guaranteed to retry | Temporal.io (durable execution) |
| Not designed for high-volume event processing | Apache Airflow / Prefect |
| No native compliance reporting | ServiceNow SecOps |
| SQLite backend (single-writer, no clustering) | PostgreSQL-backed SOAR |

n8n is appropriate for a capstone project demonstrating SOAR concepts. For a production SOC handling 100,000+ events/day, a purpose-built SOAR platform would be required.

**Severity:** Medium | **Fixable:** Yes — migrate to Temporal or commercial SOAR (long-term)

---

### TTL Cache Can Cause Stale Threat Decisions

**What was fixed (v1.3.0):** Two cache invalidation bugs fixed in `src/models/rlm_engine.py`:
1. Missing `threat_intel_updated:threat_signatures` key was added to the invalidation check.
2. Thundering-herd: keys are now deleted immediately after consuming them, not left to expire naturally.

**Status:** ✅ Fixed

---

## 3. Security Drawbacks of the Platform Itself

### The Platform is an Attack Target

The SOC platform itself has a security posture that needs hardening for production:

- **Default credentials in README** — `admin / cybersentinel2025` is public and must be changed
- **No TLS on internal service communication** — Kafka, PostgreSQL, and Redis communicate in plaintext over the Docker network
- **Kafka has no authentication** — any container on `cybersentinel-ai_cybersentinel-net` can produce/consume any topic
- **Secrets in `.env`** — if `.env` is leaked or the host is compromised, all credentials are exposed

If an attacker compromises the SOC platform, they can: read all detections, silence alerts, poison ChromaDB threat signatures, and manipulate block recommendations.

**What would fix it:** Kafka SASL/SCRAM authentication, mTLS between services, mandatory secret rotation, and credential vault integration (HashiCorp Vault, AWS Secrets Manager).

**Note on Kafka SASL:** SASL/SCRAM-SHA-256 was attempted during v1.3.0 development. The Confluent Docker image's `ClusterStatus` pre-flight check has an irresolvable conflict with SASL on non-SASL ZooKeeper: with the JAAS file, the pre-flight fails; without the JAAS file, the broker itself fails. Bitnami's Kafka image does not have this pre-flight limitation and would be the recommended path for enabling SASL.

**Severity:** High in production | **Fixable:** Yes — Bitnami Kafka + mTLS certificates per service

---

### No Mutual TLS Between Services

All 14 Docker containers communicate over the internal Docker bridge network without encryption. An attacker with container escape capability could intercept Kafka messages, poison ChromaDB, or manipulate PostgreSQL records.

**What would fix it:** Per-service TLS certificates (self-signed CA), or a service mesh (Envoy-based) injected as a sidecar pattern. Not applicable without Kubernetes, but can be achieved at the Docker level with nginx TLS termination sidecars.

**Severity:** High in production | **Fixable:** Yes — per-service TLS certificates or nginx sidecar pattern

---

## 4. Academic / Scope Drawbacks

### Tested Only on Simulated Traffic

The 17 threat scenarios in `traffic_simulator.py` are synthetic. Real network traffic has characteristics that simulation cannot replicate:

- TCP retransmissions, out-of-order packets, fragmentation
- Legitimate tools that look like attacks (nmap used by IT, Wireshark captures, backup software doing large transfers)
- Encrypted enterprise traffic (TLS 1.3 with ECH)
- Mixed benign/malicious sessions from the same source IP

Performance on real production traffic is likely lower than simulator results due to these noise sources. The false positive rate on real traffic is unknown.

**What would fix it:** Testing against a labeled real-traffic dataset (CICIDS2017, UNSW-NB15, or a private enterprise pcap).

**Severity:** Academic scope | **Fixable:** Yes — real traffic dataset testing

---

### No Compliance Framework

Enterprise security tools deployed in regulated industries require compliance controls not currently built in:

| Regulation | Requirement | Status |
|-----------|-------------|--------|
| GDPR (EU) | Data minimization, right to erasure | ✅ Partially addressed — `_mask_pii()` + erasure endpoint |
| HIPAA (Healthcare) | PHI handling under BAA | ❌ No controls |
| SOC2 Type II | Continuous monitoring audit | ❌ No controls |
| ISO 27001 | ISMS certification | ❌ No alignment |
| PCI-DSS | Cardholder data environment | ❌ No controls |

**Severity:** Academic scope for capstone | **Fixable:** Long-term compliance program

---

### No Multi-Tenancy (Full)

**What was fixed (v1.3.0):** Multi-tenancy foundation — `tenant_id` column added to all 5 data tables via `scripts/db/migrate_multitenancy.sql`. JWT payload includes tenant claim. API queries are scopeable by tenant.

**Remaining gap:** A single Docker Compose deployment shares all infrastructure (Kafka, PostgreSQL, Redis). Tenant isolation at the data layer exists but is not enforced by network segmentation. Full MSSP-grade tenancy (separate queues, separate embedding spaces per tenant) requires Kubernetes + namespace isolation.

**Severity:** Low for capstone | **Fixable:** Long-term architectural change

---

## Summary Table

| Drawback | Severity | Status | Notes |
|----------|----------|--------|-------|
| EMA poisoning attack | High | ✅ Fixed | Rate-of-change delta check in `BehaviorProfile.update()` |
| Single machine deployment | High | ❌ Open | K8s was evaluated, reverted — Docker Compose is production-quality for single-node |
| DPI platform support | Low-Medium | ✅ Largely Fixed | Docker container (Linux/macOS); Npcap script (Windows) |
| No mTLS between services | High (prod) | ❌ Open | Requires Bitnami Kafka + per-service certs |
| Platform is an attack target | High (prod) | ❌ Open | Default creds + no SASL + no mTLS |
| EMA has no sequence memory | High | ✅ Fixed | IsolationForest 50-observation buffer (v1.3.0) |
| No LLM investigation fallback | Medium | ✅ Fixed | Rule-based fallback in `mcp_orchestrator.py` |
| Alert fatigue risk | Medium | ✅ Fixed | Priority score queue in block recommendations |
| No kill chain / attacker tracking | Medium | ✅ Fixed | `attacker_campaigns` + campaign correlation |
| n8n not enterprise-grade | Medium | ❌ Open | Capstone scope — n8n is appropriate |
| No IPv6 support | Medium | ✅ Fixed | `BPF_FILTER=ip or ip6` |
| TTL cache stale decisions | Low-Medium | ✅ Fixed | Thundering-herd fix + immediate key deletion |
| Static embedding model | Low-Medium | ❌ Open | Operational data science task |
| Tested on simulated traffic only | Academic | ❌ Out of Scope | Requires CICIDS2017 or real pcap dataset |
| No compliance framework | Academic | ⚠️ Partial | GDPR PII masking + erasure endpoint done |
| No multi-tenancy (full) | Low | ⚠️ Partial | DB foundation done; network isolation requires K8s |

**Score: 9 fully fixed · 2 partially fixed · 5 open / out of scope**

---

## Most Critical to Address First (Production Path)

**Fix priority order for a production deployment:**

1. **Bitnami Kafka + SASL/SCRAM** — stop any container on the internal network from reading all alert data
2. **Per-service TLS certificates** — encrypt Kafka, PostgreSQL, Redis, and inter-service HTTP
3. **Credential rotation** — change `admin / cybersentinel2025` before any real deployment
4. **IPv6 is already active** — `BPF_FILTER=ip or ip6` (done)
5. **Real traffic testing** — validate false positive rate against CICIDS2017 or enterprise pcap

---

*Limitations & Drawbacks — CyberSentinel AI v1.3.0 — 2025/2026*
