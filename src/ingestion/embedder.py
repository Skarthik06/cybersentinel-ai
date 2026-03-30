"""
CyberSentinel AI — ChromaDB Embedder with Full RAG Governance

Handles:
  - Pinned embedding model with version tracking
  - Chunk splitting for documents exceeding token limits
  - Redis-backed embedding cache (skip re-embed if text unchanged)
  - Re-embed guard for static sources (MITRE)
  - Collection TTL / eviction for behavior profiles and CTI
  - Configurable batch sizes
  - Truncation logging
"""
import hashlib
import json
import logging
import math
import time
from typing import Any, Optional

import chromadb
import redis.asyncio as aioredis
from chromadb.config import Settings
from chromadb.utils import embedding_functions

from src.core.config import chroma as chroma_cfg, redis as redis_cfg
from src.core.logger import get_logger

logger = get_logger("cti-embedder")

# ── Embedding model — PINNED ──────────────────────────────────────────────────
# Version is stored as collection metadata at creation time.
# If the running model differs from stored metadata the startup check warns.
EMBEDDING_MODEL     = chroma_cfg.embedding_model        # "all-MiniLM-L6-v2"
EMBEDDING_MAX_CHARS = chroma_cfg.max_chunk_chars        # ~900 chars / ~225 tokens
CHUNK_OVERLAP       = chroma_cfg.chunk_overlap_chars    # 100 chars
BATCH_SIZE          = chroma_cfg.embed_batch_size       # 100 (env-tunable)
CACHE_TTL           = chroma_cfg.embed_cache_ttl_sec    # 3600 s


# ── ChromaDB client ───────────────────────────────────────────────────────────
def get_chroma_client() -> chromadb.HttpClient:
    return chromadb.HttpClient(
        host=chroma_cfg.host,
        port=chroma_cfg.port,
        settings=Settings(
            chroma_client_auth_provider="chromadb.auth.token.TokenAuthClientProvider",
            chroma_client_auth_credentials=chroma_cfg.token,
        ),
    )


def get_embedding_function() -> embedding_functions.SentenceTransformerEmbeddingFunction:
    """
    Return the pinned, explicitly named embedding function.
    Using SentenceTransformerEmbeddingFunction instead of DefaultEmbeddingFunction
    so the model name is explicit and version-controlled.
    """
    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )


def get_or_create_collection(
    client: chromadb.HttpClient,
    name: str,
    ef=None,
) -> chromadb.Collection:
    """
    Get or create a ChromaDB collection with governance metadata:
      - embedding_model: which model created these vectors
      - created_at: ISO timestamp
      - hnsw:space: cosine (correct metric for NLP embeddings)

    On retrieval, warns if stored model differs from running model.
    """
    if ef is None:
        ef = get_embedding_function()

    collection = client.get_or_create_collection(
        name=name,
        embedding_function=ef,
        metadata={
            "hnsw:space":       "cosine",
            "embedding_model":  EMBEDDING_MODEL,
            "created_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "max_chunk_chars":  str(EMBEDDING_MAX_CHARS),
        },
    )

    # Governance check — warn if model mismatch
    stored_model = collection.metadata.get("embedding_model", "")
    if stored_model and stored_model != EMBEDDING_MODEL:
        logger.warning(
            f"⚠️  EMBEDDING MODEL MISMATCH in collection '{name}'!\n"
            f"   Stored: '{stored_model}'  |  Running: '{EMBEDDING_MODEL}'\n"
            f"   Queries will return WRONG results. Re-embed the collection or "
            f"set EMBEDDING_MODEL={stored_model} in .env to match."
        )
    return collection


# ── Chunking ──────────────────────────────────────────────────────────────────
def chunk_text(text: str, max_chars: int = EMBEDDING_MAX_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Split text into overlapping chunks that fit within the embedding model's
    token limit. Uses character-based splitting (conservative: 4 chars ≈ 1 token).

    Returns a list of chunks. Single-chunk documents return a list of 1.
    Logs a warning whenever truncation/splitting occurs.
    """
    if not text:
        return [""]

    if len(text) <= max_chars:
        return [text]

    # Text exceeds limit — split with overlap
    chunks, start = [], 0
    while start < len(text):
        end = start + max_chars
        chunk = text[start:end]
        chunks.append(chunk)
        if end >= len(text):
            break
        start = end - overlap  # overlap to preserve context at boundaries

    logger.warning(
        f"📏 Text split into {len(chunks)} chunks "
        f"(original {len(text)} chars, max {max_chars} chars per chunk)"
    )
    return chunks


def truncate_with_log(text: str, max_chars: int, field_name: str = "text") -> str:
    """
    Truncate text to max_chars and log when truncation occurs.
    Used for metadata fields (not embedded documents) where chunking is not appropriate.
    """
    if len(text) > max_chars:
        logger.debug(
            f"✂️  Field '{field_name}' truncated: {len(text)} → {max_chars} chars"
        )
        return text[:max_chars]
    return text


# ── Redis embedding cache ─────────────────────────────────────────────────────
def _embed_cache_key(text: str, collection: str) -> str:
    """SHA-256 fingerprint of (text + collection + model) for cache key."""
    raw = f"{collection}:{EMBEDDING_MODEL}:{text}"
    return f"embed_cache:{hashlib.sha256(raw.encode()).hexdigest()}"


async def is_embed_cached(
    redis_client: aioredis.Redis,
    text: str,
    collection: str,
) -> bool:
    """
    Return True if this exact text has been embedded into this collection
    recently (within CACHE_TTL seconds). Prevents redundant re-embedding
    of unchanged documents — critical for RLM profiles queried thousands
    of times per hour.
    """
    if not redis_client or CACHE_TTL <= 0:
        return False
    key = _embed_cache_key(text, collection)
    return bool(await redis_client.exists(key))


async def mark_embed_cached(
    redis_client: aioredis.Redis,
    text: str,
    collection: str,
) -> None:
    """Mark a text+collection pair as recently embedded in Redis."""
    if not redis_client or CACHE_TTL <= 0:
        return
    key = _embed_cache_key(text, collection)
    await redis_client.setex(key, CACHE_TTL, "1")


# ── Re-embed guard for static sources ────────────────────────────────────────
async def should_reembed_static_source(
    redis_client: aioredis.Redis,
    source_name: str,
    interval_days: int,
) -> bool:
    """
    Returns True if a static CTI source (e.g. MITRE ATT&CK) should be
    re-embedded. Uses a Redis key with TTL = interval_days to gate re-embedding.

    MITRE updates ~twice a year. Embedding 500 techniques daily is wasteful.
    Setting MITRE_REEMBED_INTERVAL_DAYS=7 means re-embed at most weekly.
    """
    if not redis_client or interval_days <= 0:
        return True
    guard_key = f"reembed_guard:{source_name}"
    exists = await redis_client.exists(guard_key)
    if exists:
        logger.info(f"⏭️  Skipping re-embed for '{source_name}' — guard active ({interval_days}d interval)")
        return False
    # Set guard — expires after interval_days
    await redis_client.setex(guard_key, interval_days * 86400, "1")
    return True


# ── Batch upsert with caching ─────────────────────────────────────────────────
async def batch_upsert(
    collection: chromadb.Collection,
    documents: list[str],
    ids: list[str],
    metadatas: list[dict],
    redis_client: Optional[aioredis.Redis] = None,
    batch_size: int = BATCH_SIZE,
) -> int:
    """
    Upsert documents into ChromaDB in configurable batches.
    Checks the embedding cache before each document — skips re-embedding
    if the text has not changed since the last embed (cache hit).

    Returns number of documents actually embedded (cache misses).
    """
    collection_name = collection.name
    to_embed_docs, to_embed_ids, to_embed_metas = [], [], []
    cache_hits = 0

    for doc, doc_id, meta in zip(documents, ids, metadatas):
        if redis_client and await is_embed_cached(redis_client, doc, collection_name):
            cache_hits += 1
            continue
        to_embed_docs.append(doc)
        to_embed_ids.append(doc_id)
        to_embed_metas.append(meta)

    if cache_hits:
        logger.info(f"💾 Embedding cache: {cache_hits} hits, {len(to_embed_docs)} misses for '{collection_name}'")

    if not to_embed_docs:
        return 0

    # Upsert in batches
    embedded_count = 0
    for i in range(0, len(to_embed_docs), batch_size):
        batch_docs  = to_embed_docs[i:i + batch_size]
        batch_ids   = to_embed_ids[i:i + batch_size]
        batch_metas = to_embed_metas[i:i + batch_size]

        collection.upsert(
            documents=batch_docs,
            ids=batch_ids,
            metadatas=batch_metas,
        )
        embedded_count += len(batch_docs)
        logger.debug(f"  Upserted batch {i // batch_size + 1}: {len(batch_docs)} docs into '{collection_name}'")

        # Mark all batch docs as cached
        if redis_client:
            for doc in batch_docs:
                await mark_embed_cached(redis_client, doc, collection_name)

    logger.info(f"✅ Embedded {embedded_count} docs into '{collection_name}' (batch_size={batch_size})")
    return embedded_count


# ── CVE embedding ─────────────────────────────────────────────────────────────
async def embed_cve(
    collection: chromadb.Collection,
    cve_id: str,
    description: str,
    cvss: float,
    metadata: dict,
    redis_client: Optional[aioredis.Redis] = None,
) -> None:
    """
    Embed a single CVE. Chunks long descriptions automatically.
    Uses cache to skip re-embedding unchanged CVEs.
    """
    # Build enriched text — truncate description to max_chars for single-unit embed
    desc_truncated = truncate_with_log(description, EMBEDDING_MAX_CHARS - 80, "cve_description")
    text = (
        f"CVE: {cve_id}. "
        f"CVSS Score: {cvss} ({'CRITICAL' if cvss >= 9.0 else 'HIGH' if cvss >= 7.0 else 'MEDIUM'}). "
        f"Description: {desc_truncated}."
    )

    chunks = chunk_text(text)
    chunk_ids   = [cve_id if len(chunks) == 1 else f"{cve_id}_chunk_{j}" for j in range(len(chunks))]
    chunk_metas = [{**metadata, "chunk_index": j, "total_chunks": len(chunks)} for j in range(len(chunks))]

    await batch_upsert(collection, chunks, chunk_ids, chunk_metas, redis_client)


# ── CTI report embedding ──────────────────────────────────────────────────────
async def embed_cti_report(
    collection: chromadb.Collection,
    report_id: str,
    text: str,
    metadata: dict,
    redis_client: Optional[aioredis.Redis] = None,
) -> None:
    """Embed a CTI report, splitting into chunks if needed."""
    chunks = chunk_text(text)
    chunk_ids   = [report_id if len(chunks) == 1 else f"{report_id}_chunk_{j}" for j in range(len(chunks))]
    chunk_metas = [{**metadata, "chunk_index": j, "total_chunks": len(chunks)} for j in range(len(chunks))]
    await batch_upsert(collection, chunks, chunk_ids, chunk_metas, redis_client)


# ── Semantic search ───────────────────────────────────────────────────────────
def semantic_search(
    collection: chromadb.Collection,
    query: str,
    n_results: int = 5,
) -> list[dict[str, Any]]:
    """
    Semantic similarity search. Returns list of dicts with
    'document', 'metadata', and 'similarity' (0–1) fields.
    """
    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    items = []
    if results["documents"] and results["documents"][0]:
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            # ChromaDB cosine distance: 0 = identical, 2 = opposite
            similarity = round(max(0.0, 1.0 - dist / 2.0), 4)
            items.append({"document": doc, "metadata": meta, "similarity": similarity})
    return items


# ── Collection TTL eviction ───────────────────────────────────────────────────
async def evict_stale_profiles(
    collection: chromadb.Collection,
    ttl_days: int,
) -> int:
    """
    Delete behavior profile embeddings not updated in ttl_days.
    Prevents the behavior_profiles collection from growing unboundedly.

    Returns number of entries deleted.
    """
    import time as _time
    cutoff = _time.time() - ttl_days * 86400

    try:
        # Fetch all entries with metadata
        all_entries = collection.get(include=["metadatas"])
        stale_ids = []
        for doc_id, meta in zip(all_entries["ids"], all_entries["metadatas"]):
            updated_at_str = meta.get("updated_at", "")
            if not updated_at_str:
                continue
            try:
                import datetime
                ts = datetime.datetime.fromisoformat(
                    updated_at_str.replace("Z", "+00:00")
                ).timestamp()
                if ts < cutoff:
                    stale_ids.append(doc_id)
            except ValueError:
                pass

        if stale_ids:
            collection.delete(ids=stale_ids)
            logger.info(
                f"🗑️  Evicted {len(stale_ids)} stale profiles "
                f"(TTL={ttl_days}d) from '{collection.name}'"
            )
        return len(stale_ids)
    except Exception as e:
        logger.error(f"Profile eviction failed: {e}")
        return 0
