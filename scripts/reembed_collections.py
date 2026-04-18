#!/usr/bin/env python3
"""
CyberSentinel AI — ChromaDB Re-embedding Pipeline

Re-embeds all documents in one or more ChromaDB collections using the
currently configured embedding model. Run this after changing EMBEDDING_MODEL
to migrate vectors to the new model.

Why this exists:
  The embedder pins vectors to a specific model (e.g. all-MiniLM-L6-v2).
  If you switch to a larger model (e.g. all-mpnet-base-v2), existing vectors
  are in the old model's space — semantic queries return wrong results.
  This script exports all documents, drops the old collection, and re-upserts
  with fresh embeddings from the new model.

Usage:
  python scripts/reembed_collections.py [OPTIONS]

Options:
  --collections STR   Comma-separated list (default: all 4 collections)
  --chroma-url STR    ChromaDB URL (default: CHROMA_URL env or localhost:8000)
  --batch-size INT    Upsert batch size (default: 50)
  --dry-run           Print what would happen without making changes

Environment:
  CHROMA_URL    http://localhost:8000
  CHROMA_TOKEN  your-auth-token
  EMBEDDING_MODEL  all-MiniLM-L6-v2
"""

import argparse
import os
import sys
import time

try:
    import chromadb
    from chromadb.config import Settings
    from chromadb.utils import embedding_functions
except ImportError:
    print("❌ chromadb not installed. Run: pip install chromadb sentence-transformers")
    sys.exit(1)

# Load .env if present (for local runs outside Docker)
_env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.isfile(_env_file):
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

CHROMA_URL   = os.getenv("CHROMA_URL",      "http://localhost:8000")
CHROMA_TOKEN = os.getenv("CHROMA_TOKEN",    "")
EMBED_MODEL  = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

ALL_COLLECTIONS = [
    "threat_signatures",
    "cve_database",
    "cti_reports",
    "behavior_profiles",
]


def get_client() -> chromadb.HttpClient:
    host_port = CHROMA_URL.replace("http://", "").replace("https://", "")
    host, _, port = host_port.partition(":")
    return chromadb.HttpClient(
        host=host,
        port=int(port or 8000),
        settings=Settings(
            chroma_client_auth_provider="chromadb.auth.token.TokenAuthClientProvider",
            chroma_client_auth_credentials=CHROMA_TOKEN,
        ) if CHROMA_TOKEN else Settings(),
    )


def reembed_collection(
    client: chromadb.HttpClient,
    name: str,
    ef,
    batch_size: int,
    dry_run: bool,
) -> int:
    """
    Export all documents from a collection, delete it, recreate with new model,
    and re-upsert all documents. Returns number of documents migrated.
    """
    print(f"\n📦 Collection: {name}")

    try:
        collection = client.get_collection(name=name)
    except Exception:
        print(f"  ⏭️  Collection '{name}' does not exist — skipping")
        return 0

    # Export everything
    print(f"  📤 Exporting documents...")
    all_data = collection.get(include=["documents", "metadatas"])
    ids       = all_data["ids"]
    documents = all_data["documents"]
    metadatas = all_data["metadatas"]
    total     = len(ids)

    if total == 0:
        print(f"  ⏭️  Empty collection — skipping")
        return 0

    print(f"  📊 {total} documents found")

    old_model = collection.metadata.get("embedding_model", "unknown")
    if old_model == EMBED_MODEL:
        print(f"  ✅ Already using model '{EMBED_MODEL}' — no migration needed")
        return 0

    print(f"  🔄 Migrating: '{old_model}' → '{EMBED_MODEL}'")

    if dry_run:
        print(f"  🔍 [DRY RUN] Would delete and recreate '{name}' with {total} docs")
        return total

    # Delete old collection
    print(f"  🗑️  Deleting old collection...")
    client.delete_collection(name=name)

    # Recreate with new model metadata
    new_collection = client.create_collection(
        name=name,
        embedding_function=ef,
        metadata={
            "hnsw:space":       "cosine",
            "embedding_model":  EMBED_MODEL,
            "created_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "migrated_from":    old_model,
        },
    )

    # Re-upsert in batches
    embedded = 0
    for i in range(0, total, batch_size):
        batch_ids   = ids[i:i + batch_size]
        batch_docs  = documents[i:i + batch_size]
        batch_metas = metadatas[i:i + batch_size]

        new_collection.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
        )
        embedded += len(batch_ids)
        pct = int(embedded / total * 100)
        print(f"  ⚡ [{pct:3d}%] {embedded}/{total} docs re-embedded", end="\r", flush=True)

    print(f"\n  ✅ Migrated {embedded} docs to model '{EMBED_MODEL}'")
    return embedded


def main():
    parser = argparse.ArgumentParser(
        description="Re-embed ChromaDB collections after embedding model change"
    )
    parser.add_argument("--collections", default=",".join(ALL_COLLECTIONS),
                        help=f"Comma-separated (default: all)")
    parser.add_argument("--chroma-url",  default=CHROMA_URL)
    parser.add_argument("--batch-size",  type=int, default=50)
    parser.add_argument("--dry-run",     action="store_true")
    args = parser.parse_args()

    global CHROMA_URL
    CHROMA_URL = args.chroma_url

    targets = [c.strip() for c in args.collections.split(",") if c.strip()]

    print(f"🔧 Re-embedding pipeline")
    print(f"   Model:       {EMBED_MODEL}")
    print(f"   ChromaDB:    {CHROMA_URL}")
    print(f"   Collections: {', '.join(targets)}")
    print(f"   Batch size:  {args.batch_size}")
    if args.dry_run:
        print("   Mode:        DRY RUN (no changes)")
    print()

    try:
        client = get_client()
        client.heartbeat()
        print("✅ ChromaDB connected\n")
    except Exception as e:
        print(f"❌ Cannot connect to ChromaDB at {CHROMA_URL}: {e}")
        sys.exit(1)

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    print(f"⏳ Loading embedding model '{EMBED_MODEL}' (first run downloads ~90MB)...")
    # Warm up the model
    ef(["warmup"])
    print("   ✅ Model loaded\n")

    total_migrated = 0
    for name in targets:
        migrated = reembed_collection(client, name, ef, args.batch_size, args.dry_run)
        total_migrated += migrated

    print(f"\n✅ Re-embedding complete: {total_migrated} total documents migrated")
    if args.dry_run:
        print("   (No changes made — re-run without --dry-run to apply)")


if __name__ == "__main__":
    main()
