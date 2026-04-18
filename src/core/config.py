"""
CyberSentinel AI — Central Configuration
Reads all settings from environment variables.
Every service imports from here — no scattered os.getenv() calls.

RAG Governance parameters are all configurable here so thresholds,
embedding model version, batch sizes, and collection TTLs can be
tuned per deployment without touching source code.
"""
import os
from dataclasses import dataclass, field


# ── Database ──────────────────────────────────────────────────────────────────
@dataclass
class DatabaseConfig:
    host:     str = os.getenv("POSTGRES_HOST", "postgres")
    port:     int = int(os.getenv("POSTGRES_PORT", "5432"))
    name:     str = os.getenv("POSTGRES_DB", "cybersentinel")
    user:     str = os.getenv("POSTGRES_USER", "sentinel")
    password: str = os.getenv("POSTGRES_PASSWORD", "")

    @property
    def url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


# ── Redis ─────────────────────────────────────────────────────────────────────
@dataclass
class RedisConfig:
    host:     str = os.getenv("REDIS_HOST", "redis")
    port:     int = int(os.getenv("REDIS_PORT", "6379"))
    password: str = os.getenv("REDIS_PASSWORD", "")

    @property
    def url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}"
        return f"redis://{self.host}:{self.port}"


# ── Kafka ─────────────────────────────────────────────────────────────────────
@dataclass
class KafkaConfig:
    bootstrap: str = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
    topics: dict = field(default_factory=lambda: {
        "raw_packets":   "raw-packets",
        "threat_alerts": "threat-alerts",
        "enriched":      "enriched-alerts",
        "incidents":     "incidents",
        "cti_updates":   "cti-updates",
    })


# ── ChromaDB + RAG Governance ─────────────────────────────────────────────────
@dataclass
class ChromaConfig:
    host:  str = os.getenv("CHROMA_HOST", "chromadb")
    port:  int = int(os.getenv("CHROMA_PORT", "8000"))
    token: str = os.getenv("CHROMA_TOKEN", "")

    # ── Embedding model governance ────────────────────────────────────────────
    # Pinned version — changing this requires re-embedding all collections.
    # Record the version so incompatible embeddings are detected at startup.
    embedding_model: str = os.getenv(
        "EMBEDDING_MODEL", "all-MiniLM-L6-v2"
    )
    # Max tokens the embedding model supports. Documents exceeding this
    # are chunked before embedding. all-MiniLM-L6-v2 max = 256 tokens.
    embedding_max_tokens: int = int(os.getenv("EMBEDDING_MAX_TOKENS", "256"))
    # Approximate chars per token for English text (conservative estimate)
    chars_per_token: int = 4

    # ── Chunking ──────────────────────────────────────────────────────────────
    # Maximum characters a single embedded document may contain before
    # it is split into overlapping chunks.
    max_chunk_chars: int = int(os.getenv("MAX_CHUNK_CHARS", "900"))  # ~225 tokens
    chunk_overlap_chars: int = int(os.getenv("CHUNK_OVERLAP_CHARS", "100"))

    # ── Batch sizes ───────────────────────────────────────────────────────────
    # ChromaDB upsert batch size. Tune per deployment RAM.
    # Range: 50 (low RAM) → 500 (high RAM, fewer network round-trips).
    embed_batch_size: int = int(os.getenv("EMBED_BATCH_SIZE", "100"))

    # ── Collection TTL / eviction ─────────────────────────────────────────────
    # behavior_profiles: delete entries not updated in N days.
    profile_ttl_days: int = int(os.getenv("PROFILE_TTL_DAYS", "30"))
    # cti_reports: delete entries older than N days.
    cti_ttl_days: int = int(os.getenv("CTI_TTL_DAYS", "90"))

    # ── Embedding cache ───────────────────────────────────────────────────────
    # Redis TTL for embedding hash cache (seconds). 0 = disabled.
    embed_cache_ttl_sec: int = int(os.getenv("EMBED_CACHE_TTL_SEC", "3600"))

    # ── Re-embed guard for static sources ────────────────────────────────────
    # MITRE ATT&CK is re-embedded only if last embed > N days ago.
    mitre_reembed_interval_days: int = int(
        os.getenv("MITRE_REEMBED_INTERVAL_DAYS", "7")
    )

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def max_chunk_tokens(self) -> int:
        return self.max_chunk_chars // self.chars_per_token


# ── LLM Provider Configuration ────────────────────────────────────────────────
@dataclass
class LLMConfig:
    """
    Multi-provider LLM configuration.
    Set LLM_PROVIDER to switch between Claude, OpenAI GPT-4o, and Gemini.
    Only the API key for the active provider needs to be set.
    """
    # ── Provider selection ────────────────────────────────────────────────────
    # Options: "claude" | "openai" | "gemini"
    provider: str = os.getenv("LLM_PROVIDER", "claude")

    # ── API Keys (set only the one you need) ─────────────────────────────────
    anthropic_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    openai_key:    str = os.getenv("OPENAI_API_KEY", "")
    gemini_key:    str = os.getenv("GOOGLE_API_KEY", "")

    # ── Model overrides (optional — providers have sensible defaults) ─────────
    # If set, overrides the provider's default for that capability tier.
    model_primary:  str = os.getenv("LLM_MODEL_PRIMARY", "")   # investigation agent
    model_fast:     str = os.getenv("LLM_MODEL_FAST", "")       # CVE analysis
    model_analysis: str = os.getenv("LLM_MODEL_ANALYSIS", "")   # daily/weekly reports

    # ── Default models per provider (for reference) ───────────────────────────
    # Claude:  opus=claude-opus-4-5 | fast=claude-haiku-4-5-20251001 | analysis=claude-sonnet-4-6
    # OpenAI:  opus=gpt-4o          | fast=gpt-4o-mini               | analysis=gpt-4o
    # Gemini:  opus=gemini-1.5-pro  | fast=gemini-1.5-flash          | analysis=gemini-1.5-pro


# ── DPI Sensor ────────────────────────────────────────────────────────────────
@dataclass
class DPIConfig:
    interface:              str   = os.getenv("CAPTURE_INTERFACE", "eth0")
    bpf_filter:             str   = os.getenv("BPF_FILTER", "ip or ip6")
    beacon_avg_interval_sec: float = float(os.getenv("BEACON_AVG_INTERVAL_SEC", "60.0"))
    beacon_std_dev_threshold: float = float(os.getenv("BEACON_STD_DEV", "2.0"))
    entropy_threshold:      float = float(os.getenv("ENTROPY_THRESHOLD", "7.2"))
    dga_subdomain_len:      int   = int(os.getenv("DGA_SUBDOMAIN_LEN", "20"))


# ── RLM Engine ────────────────────────────────────────────────────────────────
@dataclass
class RLMConfig:
    # EMA learning rate (α). Higher = more reactive to new observations.
    alpha: float = float(os.getenv("RLM_ALPHA", "0.1"))

    # Cosine similarity threshold above which an anomaly alert is emitted.
    # Tunable without code changes — lower = more sensitive, more alerts.
    anomaly_threshold: float = float(os.getenv("RLM_ANOMALY_THRESHOLD", "0.65"))

    # Matched-threat minimum similarity to attach threat metadata to alert.
    threat_match_threshold: float = float(
        os.getenv("RLM_THREAT_MATCH_THRESHOLD", "0.50")
    )

    # Minimum observations before scoring starts (avoids cold-start false positives).
    min_observations: int = int(os.getenv("RLM_MIN_OBSERVATIONS", "20"))

    # How often profiles are persisted to PostgreSQL (seconds).
    profile_save_interval: int = int(os.getenv("RLM_SAVE_INTERVAL", "300"))

    # Rolling context window size per entity.
    context_window_size: int = int(os.getenv("RLM_CONTEXT_WINDOW", "50"))

    # n_results for ChromaDB anomaly query.
    chroma_n_results: int = int(os.getenv("RLM_CHROMA_N_RESULTS", "3"))

    # EMA poisoning detection — max allowed daily drift as a fraction of baseline.
    # If avg_bytes_per_min rises > 50% in 24h, emit POISONING_SUSPECTED alert.
    # 0.5 = 50% daily change limit. Set to 0 to disable.
    ema_poison_max_daily_delta: float = float(os.getenv("RLM_POISON_MAX_DAILY_DELTA", "0.5"))

    # Trend detection — number of consecutive score increases that trigger a
    # GRADUAL_ESCALATION_DETECTED alert even if no single score crosses the threshold.
    trend_window: int = int(os.getenv("RLM_TREND_WINDOW", "5"))


# ── API Gateway ───────────────────────────────────────────────────────────────
@dataclass
class APIConfig:
    host:              str = "0.0.0.0"
    port:              int = int(os.getenv("API_PORT", "8080"))
    jwt_secret:        str = os.getenv("JWT_SECRET", "")
    jwt_algorithm:     str = "HS256"
    jwt_expiry_minutes: int = int(os.getenv("JWT_EXPIRY_MINUTES", "480"))


# ── Singleton accessors ───────────────────────────────────────────────────────
db     = DatabaseConfig()
redis  = RedisConfig()
kafka  = KafkaConfig()
chroma = ChromaConfig()
llm = LLMConfig()
dpi    = DPIConfig()
rlm    = RLMConfig()
api    = APIConfig()
