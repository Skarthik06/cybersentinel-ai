# RAG Pipeline Design & Governance

**CyberSentinel AI — Retrieval-Augmented Generation Architecture**

---

## 1. Why RAG for Cybersecurity

CyberSentinel AI uses RAG not for question-answering in the traditional sense, but for **semantic anomaly detection and threat correlation**. The core insight is:

> A network host's behavioral statistics, expressed as natural language, can be compared to known threat patterns using vector similarity — finding conceptual matches even when no exact keywords match.

This enables the system to detect novel attack variants that signature-based tools would miss: a new C2 beacon protocol will still score high similarity to the C2 beacon threat signature because the *behavioral description* (regular intervals, high entropy, unusual port) matches semantically, not literally.

**Critical note on pipeline separation:** The RAG pipeline has two distinct consumers. The RLM engine queries ChromaDB with real host behavioral profiles built from live packet capture. The MCP Orchestrator queries ChromaDB with alert context for AI investigations. Both use the same embedding model and collections — but only the RLM engine populates the `behavior_profiles` collection, and it only does so from real DPI data (`raw-packets` Kafka topic). The traffic simulator never populates ChromaDB — it bypasses both DPI and RLM entirely.

---

## 2. RAG Architecture Overview

```
Knowledge Base (ChromaDB)                Query Engine
══════════════════════════          ════════════════════════
threat_signatures (8 seeds)   ◄──── RLM Engine: profile.to_text()      [DPI pipeline only]
cve_database (NVD CVEs)       ◄──── MCP Agent: query_threat_database()  [both pipelines]
cti_reports (CISA/MITRE/OTX)  ◄──── API: /api/v1/threat-search          [both pipelines]
behavior_profiles (per-IP)    ◄──── MCP Agent: get_host_profile()       [DPI pipeline only]
```

### Query → Embed → Retrieve → Augment pipeline:

```
Natural language query
    │
    ▼ SentenceTransformerEmbeddingFunction("all-MiniLM-L6-v2")
384-dimensional vector
    │
    ▼ ChromaDB cosine similarity search (hnsw:space = cosine)
Top-N matching documents with distance scores
    │
    ▼ Convert distance to similarity: max(0, 1 - distance/2)
Ranked results with similarity scores 0–1
    │
    ▼ Augment: inject into LLM prompt or return via API
Grounded, evidence-based response
```

### Two Consumers of ChromaDB

| Consumer | Collection Used | When Active |
|----------|----------------|-------------|
| RLM Engine (anomaly scoring) | `threat_signatures`, `behavior_profiles` | DPI pipeline only — real packet capture required |
| MCP Orchestrator (1-call investigation) | `cve_database`, `cti_reports`, `behavior_profiles` | Both pipelines — triggered by threat-alerts |
| API semantic search | `cve_database`, `cti_reports` | Always — user-initiated search |

**Note:** The embedding cache in Redis is active regardless of which pipeline is running. The cache key includes the collection name and full profile text, so it is safe across both consumers.

---

## 3. Collections Deep Dive

### 3.1 `threat_signatures`

**Purpose:** The ground truth for anomaly detection. Every RLM behavioral profile is compared against these 8 hand-authored descriptions.

**Seeded at:** RLM engine startup (if not already present)

**Written by:** RLM engine only — never by the traffic simulator

**Contents:**

| ID | Description Snippet | MITRE | Severity |
|----|--------------------|----|--------|
| `sig_c2_beacon` | Regular periodic connections, high entropy, consistent timing | T1071.001 | CRITICAL |
| `sig_lateral_movement` | Many internal hosts, SMB/WinRM/LDAP, auth spikes | T1021.002 | HIGH |
| `sig_data_exfiltration` | High outbound bytes, large POST, off-hours, DNS tunnel | T1048 | CRITICAL |
| `sig_port_scan` | High SYN volume, many ports, many RST, low payload | T1046 | MEDIUM |
| `sig_dga_malware` | Random domain names, high NXDomain, long subdomains | T1568.002 | HIGH |
| `sig_ransomware_staging` | Network share access, high-entropy writes, SMB enum | T1486 | CRITICAL |
| `sig_credential_dumping` | LSASS, Kerberoasting, NTLM spikes | T1003 | HIGH |
| `sig_tor_proxy` | Known Tor exit IPs, ports 9001/9030, geo routing | T1090.003 | HIGH |

**Why 8 signatures?** These cover the 8 most common enterprise attack patterns per MITRE ATT&CK statistics. More signatures can be added by extending `signatures.py` — they are seeded automatically on next RLM startup.

**Never evicted** — these are the ground truth foundation of the entire detection system.

---

### 3.2 `cve_database`

**Purpose:** Indexed CVE descriptions for semantic search by MCP agents during investigations and by analysts via the API.

**Populated by:** `threat_intel_scraper._scrape_nvd_cves()` — every 4 hours

**Filter:** Only CVEs with CVSS ≥ 7.0 (HIGH and CRITICAL)

**Document format:**
```
CVE: CVE-2024-XXXXX. CVSS: 9.8 (CRITICAL).
Published: 2024-03-15.
Description: A remote code execution vulnerability in Apache XYZ
allows unauthenticated attackers to execute arbitrary code via
crafted HTTP requests to the /admin endpoint.
```

**ID format:** `CVE-2024-XXXXX` (direct CVE ID — upsert overwrites on re-scrape)

**Chunk handling:** Most CVE descriptions fit within 900 chars. Long descriptions are split into `CVE-ID_chunk_0`, `CVE-ID_chunk_1` etc. with `chunk_index` and `total_chunks` metadata.

**No TTL eviction** — CVE IDs are stable and upsert naturally handles updates.

**Available in:** Both DPI and simulator pipelines — the MCP Orchestrator queries this collection regardless of how the triggering alert was generated.

---

### 3.3 `cti_reports`

**Purpose:** Broader threat intelligence — active C2 IPs, MITRE techniques, OTX pulses.

**Populated by:** All scrapers except NVD

**TTL:** 90 days (configurable via `CTI_TTL_DAYS`)

**ID conventions:**

| Source | ID Format | Example |
|--------|-----------|---------|
| CISA KEV | `cisa_{CVE-ID}` | `cisa_CVE-2024-1234` |
| Abuse.ch C2 | `c2_{ip_underscored}` | `c2_185_220_101_47` |
| Abuse.ch URL | `url_{hash}` | `url_3829471` |
| MITRE ATT&CK | `mitre_{technique_id}` | `mitre_T1071.001` |
| MITRE (chunked) | `mitre_{id}_chunk_{n}` | `mitre_T1071.001_chunk_0` |
| OTX pulse | `otx_{pulse_id}` | `otx_abc123def` |

**Available in:** Both DPI and simulator pipelines — queried by `query_threat_database()` MCP tool regardless of alert origin.

---

### 3.4 `behavior_profiles`

**Purpose:** Historical embeddings of each host's behavioral profile, enabling baseline drift detection and cross-hour correlation.

**Populated by:** RLM engine only — one entry per entity_id per hour

**Critical constraint:** This collection is ONLY populated when real packet capture is running (DPI pipeline). The traffic simulator never writes to this collection. When running simulator-only, calls to `get_host_profile()` for simulator IPs will return no results or empty profiles.

**Expected behavior in simulator mode:**
- `behavior_profiles` collection remains empty or has no entries for simulator IPs
- `get_host_profile()` MCP tool returns "No behavioral profile found" for simulator IPs
- This is architecturally correct — behavioral profiling requires real packet data
- The investigation still completes successfully using only CVE, CTI, and AbuseIPDB data

**ID format:** `profile_{ip}_{YYYYMMDDH}` — e.g. `profile_10.0.0.55_2025030914`

**TTL:** 30 days (configurable via `PROFILE_TTL_DAYS`)

**Eviction:** Runs every 30 minutes during the RLM persist cycle

**Used for:** MCP agent `get_host_profile()` tool — searches by `where={"entity_id": ip}` to find the most recent profile for a given IP

---

## 4. Embedding Model Governance

### 4.1 Why all-MiniLM-L6-v2

| Property | Value | Why It Matters |
|----------|-------|---------------|
| Dimensionality | 384 | Small enough for fast cosine computation on CPU |
| Max tokens | 256 | Matches typical CTI document sizes; enforced via MAX_CHUNK_CHARS |
| Quality | State-of-art for semantic similarity | Validated on STS benchmarks |
| Cost | Free, local inference | No API calls, no rate limits, no data egress |
| Speed | ~50ms per document on CPU | Fast enough for real-time profile updates |
| License | Apache 2.0 | No commercial restrictions |

**Zero external embedding API calls** — all embedding computation is local. This means the embedding layer is completely free regardless of which LLM provider is configured for investigations (Claude, OpenAI, or Gemini). The LLM provider only affects investigation and report generation — never embedding.

### 4.2 Model Pinning

```python
# embedder.py
EMBEDDING_MODEL = chroma_cfg.embedding_model  # "all-MiniLM-L6-v2"

def get_embedding_function():
    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL  # Explicit name, not DefaultEmbeddingFunction()
    )
```

`DefaultEmbeddingFunction()` was deliberately avoided because it wraps whatever version ChromaDB bundles — changing between ChromaDB releases without warning. Using `SentenceTransformerEmbeddingFunction(model_name=...)` pins the exact model string.

### 4.3 Model Version Mismatch Detection

At collection creation/retrieval, the governance layer checks:

```python
stored_model = collection.metadata.get("embedding_model", "")
if stored_model and stored_model != EMBEDDING_MODEL:
    logger.warning(
        f"⚠️ EMBEDDING MODEL MISMATCH in '{name}'!\n"
        f"   Stored: '{stored_model}' | Running: '{EMBEDDING_MODEL}'\n"
        f"   Queries will return WRONG results."
    )
```

This protects against a critical failure mode: upgrading ChromaDB changes the default embedding model → existing vectors become incompatible with new query vectors → similarity scores are silently wrong.

### 4.4 Model Upgrade Procedure

If you need to change the embedding model:

1. Update `EMBEDDING_MODEL` in `.env`
2. Stop all services
3. Delete ChromaDB volume: `docker volume rm cybersentinel-ai_chromadb_data`
4. Restart — all collections will be re-seeded and re-embedded from scratch
5. Monitor startup logs for model mismatch warnings (should be none)

---

## 5. Chunking Strategy

### 5.1 Document Size Analysis

| Document Type | Typical Size | Chunk Needed? |
|--------------|-------------|---------------|
| C2 beacon signature | ~150 chars | Never |
| CVE description (short) | ~300 chars | Rarely |
| CVE description (long) | ~800–2000 chars | Sometimes |
| MITRE technique | ~400–1200 chars | Sometimes |
| OTX pulse | ~200–600 chars | Rarely |
| RLM behavioral profile | ~250–350 chars | Never |
| Abuse.ch C2 indicator | ~80 chars | Never |

### 5.2 Chunking Algorithm

```python
def chunk_text(text, max_chars=900, overlap=100):
    """
    Conservative chunking: 900 chars ≈ 225 tokens (well within 256-token limit).
    Overlap of 100 chars preserves semantic context at chunk boundaries.
    """
    if len(text) <= max_chars:
        return [text]           # No chunking — most documents take this path

    chunks, start = [], 0
    while start < len(text):
        end = start + max_chars
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = end - overlap   # Step back by overlap to preserve context

    logger.warning(f"📏 Text split into {len(chunks)} chunks ...")
    return chunks
```

### 5.3 Why No Semantic Chunking

Libraries like LangChain's `RecursiveCharacterTextSplitter` or semantic sentence-boundary splitting were deliberately not used because:

1. CTI documents are already semantic units — splitting a CVE description at sentence boundaries would separate the vulnerability description from the CVSS score
2. The overhead of NLTK/spaCy sentence tokenisation is not justified for documents this small
3. Character-based chunking with 100-char overlap is sufficient when documents rarely exceed the limit

---

## 6. Retrieval Strategy

### 6.1 Query Construction

**RLM Engine (anomaly detection):**
Query text = `profile.to_text()` — the full natural language behavioral description of the host. This path is only active when real DPI is running. Profiles generated from real packets contain actual EMA statistics. Profiles for simulator-only IPs have zero values and are not written to ChromaDB.

**MCP Agent (threat investigation — 1-call pipeline):**
The MCP Orchestrator uses a **stateless 1-call pipeline** — it does NOT use the LLM to generate query text. Instead, the `query_threat_database()` tool is called as part of `asyncio.gather()` before any LLM call, using the raw alert type and IP from the alert. This is why the investigation costs only ~553 tokens: the LLM never loops back to request more data.

The query text passed to ChromaDB is constructed directly from the alert event:
```python
query = f"{alert['type']} {alert.get('mitre_technique', '')} {alert.get('src_ip', '')}"
```

The LLM provider (Claude / GPT-4o / Gemini) sees the pre-retrieved ChromaDB results as part of its single structured prompt — it does not query ChromaDB itself.

**API (semantic search):**
Query text = user's natural language query from the `POST /api/v1/threat-search` endpoint. Works identically for all three LLM providers since the search itself is provider-independent.

### 6.2 Similarity Threshold Interpretation

| Score Range | Interpretation | Action |
|------------|----------------|--------|
| 0.0 – 0.49 | No meaningful match | Ignore |
| 0.50 – 0.64 | Weak pattern match | Attach threat metadata to alert |
| 0.65 – 0.74 | Moderate match | Emit anomaly alert (MEDIUM/HIGH) |
| 0.75 – 0.89 | Strong match | Emit anomaly alert (HIGH/CRITICAL) |
| 0.90 – 1.00 | Very strong match | Possible active attack (CRITICAL) |

All thresholds are configurable via environment variables — no hardcoded values in source code.

### 6.3 n_results Choice

The RLM engine queries with `n_results=3` (configurable via `RLM_CHROMA_N_RESULTS`). Only the top result's distance is used for scoring. The other 2 results provide diversity for potential future ensemble scoring.

The MCP agent queries with `n_results=5` (configurable per tool call) — it needs more context to build a comprehensive threat assessment. These results are then compressed by `_summarize_result()` before being injected into the LLM prompt, keeping token count low.

---

## 7. Embedding Cache Design

### 7.1 The Problem

The RLM engine calls `threat_collection.query()` on every packet that triggers an anomaly check. For a busy host generating 10,000 packets/minute, this would mean 10,000 ChromaDB queries per minute — extremely wasteful when the profile hasn't changed meaningfully.

### 7.2 The Solution

```python
# Redis cache key = SHA-256 of (collection + model + text)
def _embed_cache_key(text, collection):
    raw = f"{collection}:{EMBEDDING_MODEL}:{text}"
    return f"embed_cache:{hashlib.sha256(raw.encode()).hexdigest()}"

async def is_embed_cached(redis, text, collection):
    return bool(await redis.exists(_embed_cache_key(text, collection)))

async def mark_embed_cached(redis, text, collection):
    key = _embed_cache_key(text, collection)
    await redis.setex(key, CACHE_TTL, "1")  # TTL = 3600s default
```

When `is_embed_cached()` returns True, the RLM engine skips the ChromaDB query entirely and reuses the last anomaly score. This is safe because:

- The cache key includes the full profile text — any change to any EMA field changes the text, invalidates the cache, triggers a fresh query
- The 1-hour TTL ensures queries are still refreshed even for stable hosts
- The model name is in the cache key — a model change invalidates all cached entries automatically
- The cache is active regardless of which pipeline is running (DPI or simulator), but since the simulator never generates ChromaDB entries, the cache is only meaningfully exercised in the DPI pipeline

### 7.3 Cache Effectiveness Estimate

For a typical enterprise with 500 active hosts:
- Profile text changes significantly maybe every 50 packets (as EMA shifts)
- Without cache: 10,000 ChromaDB queries/min
- With cache: ~200 ChromaDB queries/min (98% reduction)

---

## 8. MITRE Re-Embed Guard

### 8.1 The Problem

The threat intel scraper runs `_scrape_mitre_attack()` every 24 hours. Each run downloads the full 500+ technique catalog and embeds every document into ChromaDB. But MITRE ATT&CK is updated only ~twice per year. Running this daily wastes:
- ~30 seconds of Playwright/HTTP time
- ~500 ChromaDB upsert operations
- Embedding computation for 500 documents

### 8.2 The Solution

```python
async def should_reembed_static_source(redis, source_name, interval_days):
    guard_key = f"reembed_guard:{source_name}"
    if await redis.exists(guard_key):
        return False  # Guard active — skip
    await redis.setex(guard_key, interval_days * 86400, "1")
    return True  # Guard set — proceed

# In scraper:
should_run = await should_reembed_static_source(
    self.redis, "mitre_attack",
    interval_days=chroma_cfg.mitre_reembed_interval_days  # default: 7
)
if not should_run:
    return  # Skip entire function including HTTP request
```

At most once per week, the MITRE catalog is re-fetched and re-embedded. Since ChromaDB uses upsert with stable IDs, no duplicate documents accumulate.

---

## 9. LLM Provider Independence

The embedding layer is completely decoupled from the investigation LLM provider. Changing `LLM_PROVIDER` between `claude`, `openai`, and `gemini` does not affect:

- Which embedding model is used (always `all-MiniLM-L6-v2`)
- How ChromaDB collections are queried
- Similarity scores or detection thresholds
- The embedding cache in Redis

The LLM provider only affects:
- The final single LLM API call in the investigation pipeline (analysis and verdict)
- The daily SOC report generation (Workflow 02)
- The CVE impact analysis (Workflow 03)
- The weekly board report (Workflow 05)

This means you can switch from Claude to OpenAI to Gemini without any impact on detection accuracy or the RAG pipeline. See `.env.example` for `LLM_PROVIDER` configuration.

**Provider abandonment note:** Gemini (`LLM_PROVIDER=gemini`) is not recommended for production. Gemini has a 20-request/day free tier limit and its safety filters block security-related content (returns `finish_reason: 12`). Use `claude` or `openai` instead.

---

## 10. Collection Governance Summary

| Governance Concern | Implementation |
|-------------------|----------------|
| Model pinning | `SentenceTransformerEmbeddingFunction(model_name=...)` |
| Model version tracking | Stored in `collection.metadata["embedding_model"]` |
| Model mismatch detection | Warning logged at `get_or_create_collection()` |
| Distance metric | `hnsw:space: cosine` on all collections |
| Provenance on all docs | `embedding_model` field in every document's metadata |
| Chunk tracking | `chunk_index`, `total_chunks` in metadata |
| Source tracking | `source` field in every document's metadata |
| Silent truncation prevention | `truncate_with_log()` everywhere |
| Redundant embedding prevention | Redis SHA-256 embedding cache |
| Static source re-embed rate limiting | Redis TTL guard per source |
| Collection size governance | `evict_stale_profiles()` with configurable TTL |
| Batch size tuning | `EMBED_BATCH_SIZE` environment variable |
| All thresholds configurable | No hardcoded values — all via config.py from env |
| Pipeline separation | `behavior_profiles` only written by RLM engine (DPI pipeline) |
| LLM provider independence | Embedding layer never calls external LLM API |

---

*RAG Design & Governance — CyberSentinel AI v1.1 — 2025/2026*
