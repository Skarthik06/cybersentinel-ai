# Database Documentation

**CyberSentinel AI — PostgreSQL + TimescaleDB Complete Reference**

---

## Table of Contents

1. [Database Overview](#1-database-overview)
2. [Extensions](#2-extensions)
3. [Entity Relationship Diagram](#3-entity-relationship-diagram)
4. [Table: packets](#4-table-packets)
5. [Table: alerts](#5-table-alerts)
6. [Table: incidents](#6-table-incidents)
7. [Table: behavior_profiles](#7-table-behavior_profiles)
8. [Table: firewall_rules](#8-table-firewall_rules)
9. [Table: threat_intel](#9-table-threat_intel)
10. [Table: users](#10-table-users)
11. [Table: audit_log](#11-table-audit_log)
12. [TimescaleDB Hypertable Configuration](#12-timescaledb-hypertable-configuration)
13. [Materialized View: packets_per_minute](#13-materialized-view-packets_per_minute)
14. [Views: active_threats & soc_summary](#14-views-active_threats--soc_summary)
15. [Triggers](#15-triggers)
16. [Index Reference](#16-index-reference)
17. [Seed Data](#17-seed-data)
18. [Migration History](#18-migration-history)
19. [Common Query Patterns](#19-common-query-patterns)
20. [Performance & Sizing](#20-performance--sizing)
21. [Backup & Recovery](#21-backup--recovery)

---

## 1. Database Overview

### Why PostgreSQL + TimescaleDB?

CyberSentinel AI chose **PostgreSQL 16 with the TimescaleDB extension** for the following reasons:

| Requirement | Why PostgreSQL + TimescaleDB |
|-------------|------------------------------|
| Time-series packet data at high volume | TimescaleDB hypertables auto-partition by time — queries on `packets` for "last 1 hour" are O(1) not O(n) |
| Relational data (users, incidents, audit) | Standard PostgreSQL tables handle this natively |
| Array columns (affected_ips, mitre_techniques) | PostgreSQL native `TEXT[]` arrays — no join table needed |
| JSON blobs (raw_event, suspicion_reasons) | `JSONB` with GIN indexing for fast full-text search |
| Automatic data expiry | TimescaleDB retention policies auto-drop old partitions without DELETE |
| Compression for cold data | TimescaleDB columnstore compression reduces storage 90%+ for 7-day-old packet data |
| Full-text search on threat intel | `pg_trgm` extension + GIN index on `description` |

### Connection Details

| Setting | Value | Source |
|---------|-------|--------|
| Host | `postgres` (Docker service name) | docker-compose.yml |
| Port | `5432` | docker-compose.yml |
| Database | `cybersentinel` | docker-compose.yml |
| User | `sentinel` | docker-compose.yml |
| Password | From `POSTGRES_PASSWORD` env var | `.env` |
| Full URL | `postgresql://sentinel:${POSTGRES_PASSWORD}@postgres:5432/cybersentinel` | `.env` |

### asyncpg Connection Pool (API Gateway)

```python
# src/api/gateway.py — pool created at startup
db_pool = await asyncpg.create_pool(
    dsn=POSTGRES_URL,
    min_size=5,       # 5 connections always open
    max_size=20,      # up to 20 connections under load
    command_timeout=30
)
```

The pool is shared across all FastAPI request handlers. Never create individual connections — always use `async with db_pool.acquire() as conn`.

---

## 2. Extensions

Three PostgreSQL extensions are installed at schema init:

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

| Extension | Purpose | Used By |
|-----------|---------|---------|
| `timescaledb` | Hypertables, compression policies, retention policies, continuous aggregates | `packets` table |
| `uuid-ossp` | `uuid_generate_v4()` function for generating UUIDs as primary keys | All tables except `incidents` |
| `pg_trgm` | Trigram-based similarity indexes for fast LIKE / full-text search | `threat_intel.description` GIN index |

---

## 3. Entity Relationship Diagram

```mermaid
erDiagram
    PACKETS {
        uuid id PK
        timestamptz timestamp
        inet src_ip
        inet dst_ip
        int src_port
        int dst_port
        varchar_10 protocol
        int payload_size
        varchar_20 flags
        smallint ttl
        numeric_5_4 entropy
        boolean has_tls
        boolean has_dns
        text dns_query
        varchar_10 http_method
        text http_host
        text http_uri
        text user_agent
        boolean is_suspicious
        jsonb suspicion_reasons
        text session_id
    }

    ALERTS {
        uuid id PK
        timestamptz timestamp
        varchar_80 type
        varchar_20 severity
        inet src_ip
        inet dst_ip
        int src_port
        int dst_port
        varchar_10 protocol
        text description
        jsonb suspicion_reasons
        varchar_20 mitre_technique
        numeric_6_4 anomaly_score
        text rlm_profile_summary
        text session_id
        text investigation_summary
        timestamptz investigated_at
        jsonb raw_event
    }

    INCIDENTS {
        varchar_40 incident_id PK
        text title
        varchar_20 severity
        varchar_20 status
        text description
        text_array affected_ips
        text_array mitre_techniques
        text evidence
        text notes
        varchar_80 assigned_to
        varchar_80 created_by
        timestamptz created_at
        timestamptz updated_at
        timestamptz resolved_at
        text investigation_summary
        boolean block_recommended
        text block_target_ip
    }

    BEHAVIOR_PROFILES {
        text entity_id PK
        varchar_20 entity_type
        numeric_6_4 anomaly_score
        int observation_count
        numeric_12_4 avg_bytes_per_min
        numeric_6_4 avg_entropy
        jsonb dominant_protocols
        jsonb typical_dst_ports
        text profile_text
        timestamptz first_seen
        timestamptz updated_at
    }

    FIREWALL_RULES {
        uuid id PK
        inet ip_address
        varchar_10 action
        text justification
        varchar_40 incident_id FK
        varchar_80 created_by
        timestamptz created_at
        int duration_hours
        timestamptz expires_at
    }

    THREAT_INTEL {
        uuid id PK
        varchar_40 source
        varchar_20 indicator_type
        text indicator
        varchar_20 severity
        text description
        text_array tags
        jsonb raw_data
        boolean embedded
        timestamptz first_seen
        timestamptz last_seen
        timestamptz expires_at
    }

    USERS {
        uuid id PK
        varchar_80 username
        varchar_120 email
        text password_hash
        varchar_20 role
        boolean is_active
        timestamptz last_login
        timestamptz created_at
    }

    AUDIT_LOG {
        uuid id PK
        timestamptz timestamp
        varchar_80 username
        varchar_80 action
        varchar_80 resource
        text resource_id
        jsonb details
        inet ip_address
    }

    ALERTS }o--|| BEHAVIOR_PROFILES : "src_ip = entity_id"
    ALERTS }o--o{ INCIDENTS : "src_ip IN affected_ips"
    INCIDENTS ||--o{ FIREWALL_RULES : "incident_id"
    USERS ||--o{ AUDIT_LOG : "username"
    USERS ||--o{ INCIDENTS : "assigned_to / created_by"
```

---

## 4. Table: `packets`

### Purpose

Stores every suspicious network packet captured by the DPI sensor (`src/dpi/sensor.py`). This is the highest-volume table in the system — it is a **TimescaleDB hypertable** automatically partitioned into 1-day chunks. Only suspicious packets are written here (non-suspicious packets are filtered out by `detectors.py` before reaching the publisher).

### DDL

```sql
CREATE TABLE IF NOT EXISTS packets (
    id                UUID         DEFAULT uuid_generate_v4(),
    timestamp         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    src_ip            INET         NOT NULL,
    dst_ip            INET         NOT NULL,
    src_port          INTEGER,
    dst_port          INTEGER,
    protocol          VARCHAR(10),
    payload_size      INTEGER      DEFAULT 0,
    flags             VARCHAR(20),
    ttl               SMALLINT,
    entropy           NUMERIC(5,4) DEFAULT 0,
    has_tls           BOOLEAN      DEFAULT FALSE,
    has_dns           BOOLEAN      DEFAULT FALSE,
    dns_query         TEXT,
    http_method       VARCHAR(10),
    http_host         TEXT,
    http_uri          TEXT,
    user_agent        TEXT,
    is_suspicious     BOOLEAN      DEFAULT FALSE,
    suspicion_reasons JSONB        DEFAULT '[]',
    session_id        TEXT,
    PRIMARY KEY (id, timestamp)
);
```

> **Why composite PK `(id, timestamp)`?** TimescaleDB requires the partitioning column (`timestamp`) to be part of the primary key. The `id` alone would not satisfy this constraint.

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Unique packet identifier |
| `timestamp` | TIMESTAMPTZ | NO | `NOW()` | Packet capture time (UTC). Used as hypertable partition key |
| `src_ip` | INET | NO | — | Source IP address (supports IPv4 and IPv6) |
| `dst_ip` | INET | NO | — | Destination IP address |
| `src_port` | INTEGER | YES | — | Source port (NULL for non-TCP/UDP) |
| `dst_port` | INTEGER | YES | — | Destination port |
| `protocol` | VARCHAR(10) | YES | — | `TCP`, `UDP`, `ICMP`, `DNS`, etc. |
| `payload_size` | INTEGER | NO | 0 | Payload bytes (excluding headers) |
| `flags` | VARCHAR(20) | YES | — | TCP flags: `SYN`, `ACK`, `RST`, `FIN`, `PSH` |
| `ttl` | SMALLINT | YES | — | IP Time-To-Live value |
| `entropy` | NUMERIC(5,4) | NO | 0 | Shannon entropy of payload (0–8 scale). High values indicate encrypted/compressed/random data |
| `has_tls` | BOOLEAN | NO | FALSE | TRUE if TLS handshake detected in payload |
| `has_dns` | BOOLEAN | NO | FALSE | TRUE if DNS layer detected in packet |
| `dns_query` | TEXT | YES | — | DNS query domain if `has_dns = TRUE` |
| `http_method` | VARCHAR(10) | YES | — | `GET`, `POST`, `PUT` etc. if HTTP detected |
| `http_host` | TEXT | YES | — | HTTP `Host` header value |
| `http_uri` | TEXT | YES | — | HTTP URI path |
| `user_agent` | TEXT | YES | — | HTTP `User-Agent` header |
| `is_suspicious` | BOOLEAN | NO | FALSE | TRUE if any detector flagged this packet |
| `suspicion_reasons` | JSONB | NO | `[]` | Array of detector names that fired, e.g. `["high_entropy", "known_c2_port"]` |
| `session_id` | TEXT | YES | — | Groups packets belonging to the same TCP session |

### Indexes

```sql
CREATE INDEX idx_packets_src_ip     ON packets (src_ip, timestamp DESC);
CREATE INDEX idx_packets_dst_ip     ON packets (dst_ip, timestamp DESC);
CREATE INDEX idx_packets_session    ON packets (session_id, timestamp DESC);
CREATE INDEX idx_packets_suspicious ON packets (is_suspicious, timestamp DESC)
    WHERE is_suspicious = TRUE;
```

| Index | Columns | Type | Purpose |
|-------|---------|------|---------|
| `idx_packets_src_ip` | `src_ip, timestamp DESC` | B-tree | Fast lookups of "all packets from IP X in last N minutes" |
| `idx_packets_dst_ip` | `dst_ip, timestamp DESC` | B-tree | Fast lookups of "all packets to IP X" |
| `idx_packets_session` | `session_id, timestamp DESC` | B-tree | Reassemble a full TCP session from individual packets |
| `idx_packets_suspicious` | `is_suspicious, timestamp DESC` | Partial B-tree | Only indexes suspicious rows — keeps index small since most packets are not suspicious |

### Row Lifecycle

```
sensor.py captures packet
    → detectors.py analyzes → is_suspicious = TRUE
    → publisher.py writes to Kafka raw-packets
    → rlm_engine.py consumes and INSERTs into packets table
    → After 7 days: TimescaleDB compresses the chunk (columnstore)
    → After 30 days: TimescaleDB drops the chunk entirely (auto-retention)
```

### Traffic Simulator Note

The simulator **never writes to this table**. Rows in `packets` only come from the real DPI pipeline. If running simulator-only, this table remains empty.

---

## 5. Table: `alerts`

### Purpose

Stores every detected threat alert — both from the RLM engine (behavioral anomalies from real traffic) and the traffic simulator (synthetic scenarios). Each row represents a single threat event. After MCP investigation, the `investigation_summary` and `investigated_at` fields are filled in.

### DDL

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id                    UUID         DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    type                  VARCHAR(80)  NOT NULL,
    severity              VARCHAR(20)  NOT NULL
                          CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    src_ip                INET,
    dst_ip                INET,
    src_port              INTEGER,
    dst_port              INTEGER,
    protocol              VARCHAR(10),
    description           TEXT,
    suspicion_reasons     JSONB        DEFAULT '[]',
    mitre_technique       VARCHAR(20),
    anomaly_score         NUMERIC(6,4),
    rlm_profile_summary   TEXT,
    session_id            TEXT,
    investigation_summary TEXT,
    investigated_at       TIMESTAMPTZ,
    raw_event             JSONB        DEFAULT '{}'
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Unique alert identifier |
| `timestamp` | TIMESTAMPTZ | NO | `NOW()` | When the alert was generated |
| `type` | VARCHAR(80) | NO | — | Alert category: `C2_BEACON`, `PORT_SCAN`, `DATA_EXFILTRATION`, `LATERAL_MOVEMENT`, `DGA_DETECTED`, `RANSOMWARE_STAGING`, `CREDENTIAL_DUMP`, `DNS_TUNNEL`, `TOR_PROXY`, `BEHAVIOR_ANOMALY`, etc. |
| `severity` | VARCHAR(20) | NO | — | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`. Enforced by CHECK constraint |
| `src_ip` | INET | YES | — | Source IP that triggered the alert |
| `dst_ip` | INET | YES | — | Destination IP involved |
| `src_port` | INTEGER | YES | — | Source port |
| `dst_port` | INTEGER | YES | — | Destination port |
| `protocol` | VARCHAR(10) | YES | — | Network protocol |
| `description` | TEXT | YES | — | Human-readable description of the threat |
| `suspicion_reasons` | JSONB | NO | `[]` | List of detector signals that fired |
| `mitre_technique` | VARCHAR(20) | YES | — | MITRE ATT&CK technique ID (e.g. `T1071.001`) |
| `anomaly_score` | NUMERIC(6,4) | YES | — | RLM engine similarity score (0–1). NULL for simulator alerts which have no RLM profile |
| `rlm_profile_summary` | TEXT | YES | — | Snapshot of the host's behavioral profile at time of alert |
| `session_id` | TEXT | YES | — | Links alert back to the originating TCP session in `packets` |
| `investigation_summary` | TEXT | YES | — | AI-generated analysis from MCP Orchestrator (filled after investigation) |
| `investigated_at` | TIMESTAMPTZ | YES | — | When MCP completed the investigation. NULL = not yet investigated |
| `raw_event` | JSONB | NO | `{}` | Full original event payload from Kafka (kept for forensics, stripped from LLM prompt for token efficiency) |

### Indexes

```sql
CREATE INDEX idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX idx_alerts_severity  ON alerts (severity, timestamp DESC);
CREATE INDEX idx_alerts_src_ip    ON alerts (src_ip,  timestamp DESC);
CREATE INDEX idx_alerts_type      ON alerts (type,    timestamp DESC);
CREATE INDEX idx_alerts_mitre     ON alerts (mitre_technique)
    WHERE mitre_technique IS NOT NULL;
```

| Index | Purpose |
|-------|---------|
| `idx_alerts_timestamp` | Dashboard: "all alerts in last 24h" sorted by time |
| `idx_alerts_severity` | Dashboard: filter by severity + time range |
| `idx_alerts_src_ip` | Hosts tab: recent alerts for a specific IP |
| `idx_alerts_type` | Filter by alert type (C2_BEACON, PORT_SCAN, etc.) |
| `idx_alerts_mitre` | Partial index — only rows where technique is set (avoids indexing NULLs) |

### Severity Values

| Value | Meaning | Typical Sources |
|-------|---------|----------------|
| `CRITICAL` | Confirmed active attack, immediate response required | C2 beacon, ransomware, exfiltration |
| `HIGH` | Strong threat indicators, investigate soon | Lateral movement, credential dump, DGA |
| `MEDIUM` | Suspicious activity, warrants review | Port scan, unusual protocol |
| `LOW` | Minor anomaly, informational | Unusual port, first-seen IP |
| `INFO` | Informational only | System events, baseline changes |

### Row Lifecycle

```
MCP Orchestrator or RLM engine INSERTs alert
    → investigation_summary = NULL, investigated_at = NULL
    → MCP investigation runs (asyncio.gather tools + LLM call)
    → UPDATE alerts SET investigation_summary = '...', investigated_at = NOW()
    → Alert visible in ALERTS tab of dashboard
    → Alert linked to incident via affected_ips array
```

---

## 6. Table: `incidents`

### Purpose

Represents a grouped security incident — one or more related alerts that together constitute a threat to investigate and respond to. Created by the MCP Orchestrator after completing an investigation. The `block_recommended` and `block_target_ip` fields enable the human-in-the-loop SOAR pattern.

### DDL

```sql
CREATE TABLE IF NOT EXISTS incidents (
    incident_id           VARCHAR(40)  DEFAULT 'INC-' || EXTRACT(EPOCH FROM NOW())::BIGINT PRIMARY KEY,
    title                 TEXT         NOT NULL,
    severity              VARCHAR(20)  NOT NULL
                          CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status                VARCHAR(20)  NOT NULL DEFAULT 'OPEN'
                          CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','CLOSED')),
    description           TEXT,
    affected_ips          TEXT[]       DEFAULT '{}',
    mitre_techniques      TEXT[]       DEFAULT '{}',
    evidence              TEXT,
    notes                 TEXT,
    assigned_to           VARCHAR(80),
    created_by            VARCHAR(80)  DEFAULT 'mcp-orchestrator',
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at           TIMESTAMPTZ,
    investigation_summary TEXT,
    block_recommended     BOOLEAN      DEFAULT FALSE,
    block_target_ip       TEXT
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `incident_id` | VARCHAR(40) | NO | `INC-{epoch}` | Human-readable ID like `INC-1711795200`. Uses Unix epoch to guarantee uniqueness without a sequence |
| `title` | TEXT | NO | — | Short incident title, e.g. `"C2 Beacon: 10.0.0.42 → 185.220.101.47"` |
| `severity` | VARCHAR(20) | NO | — | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `status` | VARCHAR(20) | NO | `OPEN` | Current lifecycle state (see Status Values below) |
| `description` | TEXT | YES | — | Detailed narrative of the incident |
| `affected_ips` | TEXT[] | NO | `{}` | Array of all IPs involved. Used for JOIN with alerts and firewall_rules |
| `mitre_techniques` | TEXT[] | NO | `{}` | Array of MITRE technique IDs confirmed in this incident |
| `evidence` | TEXT | YES | — | Raw evidence summary (packet details, connection logs) |
| `notes` | TEXT | YES | — | Analyst free-text notes |
| `assigned_to` | VARCHAR(80) | YES | — | Username of assigned analyst |
| `created_by` | VARCHAR(80) | YES | `mcp-orchestrator` | Who created the incident (`mcp-orchestrator` for automated, username for manual) |
| `created_at` | TIMESTAMPTZ | NO | `NOW()` | Incident creation time |
| `updated_at` | TIMESTAMPTZ | NO | `NOW()` | Last modification time |
| `resolved_at` | TIMESTAMPTZ | YES | — | When status changed to RESOLVED. NULL if still open |
| `investigation_summary` | TEXT | YES | — | AI-generated investigation narrative from MCP |
| `block_recommended` | BOOLEAN | NO | FALSE | TRUE = LLM recommends blocking `block_target_ip`. Analyst must confirm via RESPONSE tab |
| `block_target_ip` | TEXT | YES | — | The IP address the LLM recommends blocking. Only set when `block_recommended = TRUE` |

### Status Values

```mermaid
stateDiagram-v2
    [*] --> OPEN : MCP creates incident
    OPEN --> INVESTIGATING : Analyst picks up
    OPEN --> RESOLVED : Analyst blocks/dismisses
    INVESTIGATING --> RESOLVED : Action taken
    RESOLVED --> CLOSED : Archived after review
    OPEN --> CLOSED : Direct close (low severity)
```

| Status | Meaning |
|--------|---------|
| `OPEN` | New incident, awaiting analyst attention. Appears in RESPONSE tab if `block_recommended = TRUE` |
| `INVESTIGATING` | Analyst has taken ownership (`assigned_to` set) |
| `RESOLVED` | Action taken — either IP blocked (`POST /incidents/{id}/block`) or dismissed (`POST /incidents/{id}/dismiss`) |
| `CLOSED` | Archived — investigation complete, no further action |

### Human-in-the-Loop: block_recommended Fields

These two columns are the v1.1 addition (ADR-009). They store the LLM's block recommendation without automatically acting on it:

```sql
-- Added in v1.1 migration (run if upgrading from v1.0):
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip   TEXT;
```

**Flow:**
1. MCP Orchestrator LLM returns `{"block_recommended": true, "block_target_ip": "185.220.101.47"}`
2. `INSERT INTO incidents (..., block_recommended=TRUE, block_target_ip='185.220.101.47')`
3. React RESPONSE tab queries `GET /api/v1/block-recommendations` → shows pending items
4. Analyst clicks BLOCK IP → `POST /api/v1/incidents/{id}/block` → `INSERT INTO firewall_rules`
5. OR analyst clicks DISMISS → `POST /api/v1/incidents/{id}/dismiss` → `UPDATE status='DISMISSED'`

---

## 7. Table: `behavior_profiles`

### Purpose

Stores the running behavioral profile for each host IP observed by the RLM engine. Updated continuously as new packets arrive. Uses Exponential Moving Average (EMA) to smooth metrics over time. **Only populated by the DPI pipeline** — simulator IPs never appear here.

### DDL

```sql
CREATE TABLE IF NOT EXISTS behavior_profiles (
    entity_id          TEXT          PRIMARY KEY,
    entity_type        VARCHAR(20)   NOT NULL DEFAULT 'host',
    anomaly_score      NUMERIC(6,4)  DEFAULT 0,
    observation_count  INTEGER       DEFAULT 0,
    avg_bytes_per_min  NUMERIC(12,4) DEFAULT 0,
    avg_entropy        NUMERIC(6,4)  DEFAULT 0,
    dominant_protocols JSONB         DEFAULT '{}',
    typical_dst_ports  JSONB         DEFAULT '{}',
    profile_text       TEXT,
    first_seen         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `entity_id` | TEXT | NO | — | IP address as string, e.g. `"10.0.0.42"`. Primary key |
| `entity_type` | VARCHAR(20) | NO | `host` | Currently always `host`. Reserved for future `network`/`service` types |
| `anomaly_score` | NUMERIC(6,4) | NO | 0 | ChromaDB similarity score against threat signatures (0–1). Scores ≥ 0.65 trigger alerts |
| `observation_count` | INTEGER | NO | 0 | Total packets processed for this host. Low counts mean less reliable EMA estimates |
| `avg_bytes_per_min` | NUMERIC(12,4) | NO | 0 | EMA of bytes transmitted per minute. Large values suggest data exfiltration |
| `avg_entropy` | NUMERIC(6,4) | NO | 0 | EMA of payload entropy (0–8). Values > 7.0 suggest encrypted/C2 traffic |
| `dominant_protocols` | JSONB | NO | `{}` | Protocol distribution, e.g. `{"TCP": 0.85, "UDP": 0.15}` |
| `typical_dst_ports` | JSONB | NO | `{}` | Port frequency map, e.g. `{"443": 120, "80": 45, "8080": 12}` |
| `profile_text` | TEXT | YES | — | Natural language behavioral summary generated by `profile.to_text()`. Used as query input to ChromaDB |
| `first_seen` | TIMESTAMPTZ | NO | `NOW()` | When this host was first observed |
| `updated_at` | TIMESTAMPTZ | NO | `NOW()` | Last EMA update timestamp |

### EMA Update Formula

```python
# src/models/profile.py — BehaviorProfile.update()
alpha = 0.1  # Configurable via RLM_ALPHA env var

new_avg_bytes    = (1 - alpha) * old_avg_bytes    + alpha * current_bytes
new_avg_entropy  = (1 - alpha) * old_avg_entropy  + alpha * current_entropy
observation_count += 1
```

With `alpha = 0.1`: each new observation contributes 10% weight to the running average. The host needs at least `RLM_MIN_OBSERVATIONS = 20` packets before anomaly scoring begins.

### Why TEXT for entity_id?

PostgreSQL's `INET` type would be more type-safe, but `TEXT` was chosen because:
- ChromaDB also stores profiles with `entity_id` as a string key
- Joining `behavior_profiles.entity_id = alerts.src_ip::text` is simpler than casting INET to TEXT at join time
- IPv6 addresses serialize cleanly as strings

---

## 8. Table: `firewall_rules`

### Purpose

Records every IP block (or allow/log rule) created by analysts via the dashboard RESPONSE tab. Tracks who created the rule, why, which incident it relates to, and when it expires. Rules are time-limited — `expires_at` is auto-calculated from `duration_hours` via a trigger.

### DDL

```sql
CREATE TABLE IF NOT EXISTS firewall_rules (
    id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address     INET        NOT NULL,
    action         VARCHAR(10) NOT NULL DEFAULT 'BLOCK'
                   CHECK (action IN ('BLOCK','ALLOW','LOG')),
    justification  TEXT,
    incident_id    VARCHAR(40) REFERENCES incidents(incident_id) ON DELETE SET NULL,
    created_by     VARCHAR(80) DEFAULT 'mcp-orchestrator',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_hours INTEGER     DEFAULT 24,
    expires_at     TIMESTAMPTZ
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Unique rule identifier |
| `ip_address` | INET | NO | — | IP address being blocked/allowed/logged |
| `action` | VARCHAR(10) | NO | `BLOCK` | `BLOCK` = deny traffic, `ALLOW` = explicit permit, `LOG` = mirror only |
| `justification` | TEXT | YES | — | Human-readable reason for the rule |
| `incident_id` | VARCHAR(40) | YES | — | FK to `incidents.incident_id`. `ON DELETE SET NULL` means the rule persists even if the incident is deleted |
| `created_by` | VARCHAR(80) | YES | `mcp-orchestrator` | Username of analyst or `mcp-orchestrator` |
| `created_at` | TIMESTAMPTZ | NO | `NOW()` | Rule creation timestamp |
| `duration_hours` | INTEGER | YES | 24 | How long the rule stays active. 24 = 1 day, 168 = 1 week, 0 = permanent |
| `expires_at` | TIMESTAMPTZ | YES | — | Auto-calculated by trigger: `created_at + duration_hours hours`. NULL = permanent |

### Foreign Key Behavior

```sql
incident_id VARCHAR(40) REFERENCES incidents(incident_id) ON DELETE SET NULL
```

`ON DELETE SET NULL` is intentional: if an incident is deleted (e.g. during a data cleanup), the firewall rule is NOT deleted — the block remains active. The `incident_id` becomes NULL but the rule still expires on schedule.

---

## 9. Table: `threat_intel`

### Purpose

Stores structured threat intelligence indicators collected from external CTI sources (CISA KEV, NVD, Abuse.ch, MITRE ATT&CK, OTX). Each row is a single indicator with its source, type, severity, and description. The `embedded` flag tracks whether the description has been embedded into ChromaDB.

### DDL

```sql
CREATE TABLE IF NOT EXISTS threat_intel (
    id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    source         VARCHAR(40) NOT NULL,
    indicator_type VARCHAR(20) NOT NULL
                   CHECK (indicator_type IN ('IP','DOMAIN','CVE','TECHNIQUE','HASH','URL')),
    indicator      TEXT        NOT NULL,
    severity       VARCHAR(20),
    description    TEXT,
    tags           TEXT[]      DEFAULT '{}',
    raw_data       JSONB       DEFAULT '{}',
    embedded       BOOLEAN     DEFAULT FALSE,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    UNIQUE (source, indicator_type, indicator)
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Internal identifier |
| `source` | VARCHAR(40) | NO | — | CTI source: `cisa_kev`, `nvd`, `abuse_ch`, `mitre_attack`, `otx` |
| `indicator_type` | VARCHAR(20) | NO | — | Type of indicator (see Indicator Types below) |
| `indicator` | TEXT | NO | — | The actual indicator value (IP, CVE ID, domain, etc.) |
| `severity` | VARCHAR(20) | YES | — | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `description` | TEXT | YES | — | Human-readable description of the threat |
| `tags` | TEXT[] | NO | `{}` | Categorisation tags, e.g. `["ransomware", "apt28", "exploited-in-wild"]` |
| `raw_data` | JSONB | NO | `{}` | Original API response from the CTI source |
| `embedded` | BOOLEAN | NO | FALSE | TRUE = description has been embedded into ChromaDB. Prevents re-embedding on every scrape |
| `first_seen` | TIMESTAMPTZ | NO | `NOW()` | When this indicator was first ingested |
| `last_seen` | TIMESTAMPTZ | NO | `NOW()` | Last time the scraper confirmed this indicator is still active |
| `expires_at` | TIMESTAMPTZ | YES | — | When this indicator should be considered stale and removed from ChromaDB (90 days for CTI, NULL for CVEs) |

### Unique Constraint

```sql
UNIQUE (source, indicator_type, indicator)
```

Prevents duplicate entries when the scraper runs every 4 hours. Uses `INSERT ... ON CONFLICT (source, indicator_type, indicator) DO UPDATE SET last_seen = NOW()` to update the timestamp without creating duplicates.

### Indicator Types

| Type | Example Indicator | Source |
|------|-----------------|--------|
| `IP` | `185.220.101.47` | Abuse.ch, OTX |
| `DOMAIN` | `update-service.xyz` | Abuse.ch, OTX |
| `CVE` | `CVE-2024-12345` | NVD, CISA KEV |
| `TECHNIQUE` | `T1071.001` | MITRE ATT&CK |
| `HASH` | `d41d8cd98f00b204...` | OTX |
| `URL` | `http://malicious.xyz/c2` | Abuse.ch |

### Full-Text Search Index

```sql
CREATE INDEX idx_threat_text ON threat_intel
    USING gin(to_tsvector('english', description))
    WHERE description IS NOT NULL;
```

This GIN index on the `description` column (using `pg_trgm`) enables fast full-text search via `POST /api/v1/threat-search`. The `WHERE description IS NOT NULL` partial index skips rows without descriptions, keeping the index lean.

---

## 10. Table: `users`

### Purpose

Stores SOC analyst accounts for dashboard authentication. Uses bcrypt password hashing. Role-based access control enforced at the FastAPI layer.

### DDL

```sql
CREATE TABLE IF NOT EXISTS users (
    id            UUID         DEFAULT uuid_generate_v4() PRIMARY KEY,
    username      VARCHAR(80)  UNIQUE NOT NULL,
    email         VARCHAR(120) UNIQUE,
    password_hash TEXT         NOT NULL,
    role          VARCHAR(20)  NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('admin','analyst','responder','viewer')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    last_login    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Internal user ID |
| `username` | VARCHAR(80) | NO | — | Login username. UNIQUE constraint |
| `email` | VARCHAR(120) | YES | — | Email address. UNIQUE constraint (allows NULL — some service accounts have no email) |
| `password_hash` | TEXT | NO | — | bcrypt hash (12 rounds). Never store plaintext |
| `role` | VARCHAR(20) | NO | `viewer` | See Role Permissions below |
| `is_active` | BOOLEAN | NO | TRUE | FALSE = account disabled (soft delete) |
| `last_login` | TIMESTAMPTZ | YES | — | Updated on successful JWT token generation |
| `created_at` | TIMESTAMPTZ | NO | `NOW()` | Account creation time |

### Role Permissions

| Role | Dashboard | Alerts | Incidents | Block IPs | Users | Config |
|------|-----------|--------|-----------|-----------|-------|--------|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `analyst` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `responder` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `viewer` | ✅ | ✅ | Read only | ❌ | ❌ | ❌ |

---

## 11. Table: `audit_log`

### Purpose

Immutable compliance log of every significant action taken in the system. Every API call that modifies data (block IP, dismiss incident, create user, etc.) writes a row here. Cannot be deleted via the API — only direct database access can remove audit entries.

### DDL

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username    VARCHAR(80),
    action      VARCHAR(80) NOT NULL,
    resource    VARCHAR(80),
    resource_id TEXT,
    details     JSONB       DEFAULT '{}',
    ip_address  INET
);
```

### Column Reference

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `uuid_generate_v4()` | Unique log entry ID |
| `timestamp` | TIMESTAMPTZ | NO | `NOW()` | When the action occurred |
| `username` | VARCHAR(80) | YES | — | Who performed the action. NULL for system/automated actions |
| `action` | VARCHAR(80) | NO | — | What happened: `block_ip`, `dismiss_incident`, `login`, `create_incident`, etc. |
| `resource` | VARCHAR(80) | YES | — | What was acted on: `incidents`, `firewall_rules`, `users` |
| `resource_id` | TEXT | YES | — | ID of the affected resource (incident_id, UUID, IP) |
| `details` | JSONB | NO | `{}` | Additional context, e.g. `{"ip_blocked": "185.220.101.47", "duration_hours": 24}` |
| `ip_address` | INET | YES | — | IP address of the client making the request (from HTTP headers) |

### Example Audit Entries

```json
{ "action": "block_ip",          "username": "analyst1", "resource": "firewall_rules",
  "resource_id": "INC-1711795200", "details": {"ip": "185.220.101.47", "duration_hours": 24} }

{ "action": "dismiss_incident",  "username": "analyst2", "resource": "incidents",
  "resource_id": "INC-1711795201", "details": {"reason": "false positive - internal scanner"} }

{ "action": "login",             "username": "admin",    "resource": "users",
  "resource_id": "admin", "details": {"method": "password"} }
```

---

## 12. TimescaleDB Hypertable Configuration

### What Is a Hypertable?

The `packets` table is converted from a regular PostgreSQL table to a **TimescaleDB hypertable**:

```sql
SELECT create_hypertable('packets', 'timestamp',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);
```

A hypertable is physically stored as many small **chunks** — each chunk contains one day of data. When you query `WHERE timestamp > NOW() - INTERVAL '1 hour'`, PostgreSQL only scans today's chunk, not the entire table.

```mermaid
graph TB
    subgraph HYPERTABLE["packets hypertable"]
        C1["Chunk: 2026-03-24\n(compressed after 7 days)"]
        C2["Chunk: 2026-03-25\n(compressed after 7 days)"]
        C3["Chunk: 2026-03-26\n(compressed)"]
        C4["Chunk: 2026-03-27\n(compressed)"]
        C5["Chunk: 2026-03-28\n(compressed)"]
        C6["Chunk: 2026-03-29\n(active)"]
        C7["Chunk: 2026-03-30\n(active — today)"]
        DROP["Chunks older than 30 days\nAUTOMATICALLY DROPPED"]
    end

    QUERY["SELECT * FROM packets\nWHERE timestamp > NOW() - INTERVAL '1 hour'"]
    -->|Only scans today's chunk| C7

    style C1 fill:#bdbdbd,color:#000
    style C2 fill:#bdbdbd,color:#000
    style C3 fill:#bdbdbd,color:#000
    style C4 fill:#bdbdbd,color:#000
    style C5 fill:#bdbdbd,color:#000
    style C6 fill:#a5d6a7,color:#000
    style C7 fill:#4caf50,color:#fff
    style DROP fill:#ef9a9a,color:#000
    style QUERY fill:#7b68ee,color:#fff
```

### Compression Policy

```sql
PERFORM add_compression_policy('packets', INTERVAL '7 days');
```

After 7 days, a chunk is converted from row-oriented PostgreSQL storage to **columnstore format** (columnar compression). This typically achieves 90–95% storage reduction on packet data because:
- Many packets share the same protocol, flags, src_ip (high repetition)
- Columnar storage groups identical values together for compression
- Integer columns (ports, payload_size) compress extremely well with delta encoding

### Retention Policy

```sql
PERFORM add_retention_policy('packets', INTERVAL '30 days');
```

Chunks older than 30 days are **automatically dropped** — the entire partition file is deleted without a slow `DELETE` scan. This keeps storage bounded regardless of traffic volume.

### Policy Summary

| Policy | Setting | Effect |
|--------|---------|--------|
| Chunk interval | 1 day | Each day is a separate partition |
| Compression | After 7 days | Columnar compression, ~90% storage reduction |
| Retention | Drop after 30 days | Auto-delete old partitions without DELETE scan |
| Continuous aggregate refresh | Every 1 minute | `packets_per_minute` view stays current |

---

## 13. Materialized View: `packets_per_minute`

### Purpose

Pre-aggregates packet counts, byte totals, entropy averages, and suspicious counts per source IP per minute. Used by the dashboard for "packets by IP over time" charts without scanning the full `packets` hypertable.

### DDL

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS packets_per_minute
WITH (timescaledb.continuous) AS
    SELECT
        time_bucket('1 minute', timestamp) AS bucket,
        src_ip,
        COUNT(*)                                     AS packet_count,
        SUM(payload_size)                            AS total_bytes,
        AVG(entropy)                                 AS avg_entropy,
        COUNT(*) FILTER (WHERE is_suspicious = TRUE) AS suspicious_count
    FROM packets
    GROUP BY bucket, src_ip
WITH NO DATA;
```

### Continuous Aggregate Policy

```sql
PERFORM add_continuous_aggregate_policy('packets_per_minute',
    start_offset   => INTERVAL '1 hour',
    end_offset     => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute'
);
```

This policy ensures the materialized view is refreshed every minute, covering data from 1 hour ago up to 1 minute ago (recent incomplete minute is excluded to avoid partial aggregates).

### Query Example

```sql
-- Traffic volume for IP 10.0.0.42 over the last hour
SELECT bucket, packet_count, total_bytes, avg_entropy, suspicious_count
FROM packets_per_minute
WHERE src_ip = '10.0.0.42'
  AND bucket > NOW() - INTERVAL '1 hour'
ORDER BY bucket DESC;
```

---

## 14. Views: `active_threats` & `soc_summary`

### `active_threats`

Joins `alerts`, `behavior_profiles`, and `incidents` to produce a unified view of all CRITICAL/HIGH alerts in the last 24 hours with their associated profile scores and incident statuses.

```sql
CREATE OR REPLACE VIEW active_threats AS
    SELECT
        a.id, a.timestamp, a.type, a.severity, a.src_ip, a.dst_ip,
        a.mitre_technique, a.anomaly_score,
        bp.anomaly_score      AS profile_score,
        bp.observation_count,
        i.incident_id,
        i.status              AS incident_status
    FROM alerts a
    LEFT JOIN behavior_profiles bp
           ON bp.entity_id = a.src_ip::text
    LEFT JOIN incidents i
           ON a.src_ip::text = ANY(i.affected_ips)
          AND i.status IN ('OPEN','INVESTIGATING')
    WHERE a.timestamp > NOW() - INTERVAL '24 hours'
      AND a.severity IN ('CRITICAL','HIGH')
    ORDER BY a.timestamp DESC;
```

**Used by:** n8n Workflow 01 (critical alert SOAR), dashboard OVERVIEW tab

### `soc_summary`

Single-row KPI view used by the dashboard Overview tab and n8n daily report workflow.

```sql
CREATE OR REPLACE VIEW soc_summary AS
    SELECT
        (SELECT COUNT(*) FROM alerts    WHERE timestamp > NOW() - INTERVAL '24 hours')          AS total_alerts_24h,
        (SELECT COUNT(*) FROM alerts    WHERE timestamp > NOW() - INTERVAL '24 hours'
                                          AND severity = 'CRITICAL')                            AS critical_24h,
        (SELECT COUNT(*) FROM incidents WHERE status = 'OPEN')                                  AS open_incidents,
        (SELECT COUNT(*) FROM incidents WHERE status = 'INVESTIGATING')                         AS investigating_incidents,
        (SELECT COUNT(*) FROM firewall_rules WHERE expires_at > NOW())                          AS active_blocks,
        (SELECT COUNT(*) FROM behavior_profiles WHERE anomaly_score > 0.65)                     AS high_risk_hosts,
        (SELECT COUNT(*) FROM threat_intel  WHERE last_seen > NOW() - INTERVAL '24 hours')      AS new_intel_24h;
```

**Used by:** `GET /api/v1/dashboard`, `GET /api/v1/stats`, n8n Workflow 02 (daily SOC report)

---

## 15. Triggers

### `trg_firewall_expires` — Auto-calculate expires_at

```sql
CREATE OR REPLACE FUNCTION firewall_set_expires_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.expires_at := NEW.created_at + (NEW.duration_hours * INTERVAL '1 hour');
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_firewall_expires
    BEFORE INSERT OR UPDATE ON firewall_rules
    FOR EACH ROW EXECUTE FUNCTION firewall_set_expires_at();
```

**What it does:** Before every INSERT or UPDATE on `firewall_rules`, automatically sets `expires_at = created_at + duration_hours`. This means callers never need to calculate `expires_at` — they just set `duration_hours` and the trigger handles the rest.

**Example:**
```sql
INSERT INTO firewall_rules (ip_address, action, duration_hours)
VALUES ('185.220.101.47', 'BLOCK', 48);
-- expires_at is automatically set to NOW() + 48 hours
-- = 2026-04-01 10:15:00 UTC
```

**Edge cases:**
- `duration_hours = 0` → `expires_at = created_at` (rule expires immediately — effectively permanent if queried as `expires_at > NOW()`)
- `duration_hours = NULL` → `expires_at = NULL` (permanent block — never expires)

---

## 16. Index Reference

Complete list of all indexes across all tables:

| Table | Index Name | Columns | Type | Purpose |
|-------|-----------|---------|------|---------|
| `packets` | `idx_packets_src_ip` | `src_ip, timestamp DESC` | B-tree | Fast per-IP time-range queries |
| `packets` | `idx_packets_dst_ip` | `dst_ip, timestamp DESC` | B-tree | Fast per-destination queries |
| `packets` | `idx_packets_session` | `session_id, timestamp DESC` | B-tree | Session reassembly |
| `packets` | `idx_packets_suspicious` | `is_suspicious, timestamp DESC` WHERE `is_suspicious=TRUE` | Partial B-tree | Only suspicious rows — small index |
| `alerts` | `idx_alerts_timestamp` | `timestamp DESC` | B-tree | Dashboard: latest 24h alerts |
| `alerts` | `idx_alerts_severity` | `severity, timestamp DESC` | B-tree | Filter by severity + time |
| `alerts` | `idx_alerts_src_ip` | `src_ip, timestamp DESC` | B-tree | Host detail: alerts by IP |
| `alerts` | `idx_alerts_type` | `type, timestamp DESC` | B-tree | Filter by alert category |
| `alerts` | `idx_alerts_mitre` | `mitre_technique` WHERE NOT NULL | Partial B-tree | MITRE technique lookup |
| `incidents` | `idx_incidents_status` | `status, created_at DESC` | B-tree | RESPONSE tab: open incidents |
| `incidents` | `idx_incidents_severity` | `severity, created_at DESC` | B-tree | Filter by severity |
| `behavior_profiles` | `idx_profiles_score` | `anomaly_score DESC` | B-tree | Top risky hosts sorted by score |
| `behavior_profiles` | `idx_profiles_type` | `entity_type` | B-tree | Filter by entity type |
| `firewall_rules` | `idx_firewall_ip` | `ip_address` | B-tree | Is IP currently blocked? |
| `firewall_rules` | `idx_firewall_active` | `expires_at` | B-tree | Find active (non-expired) rules |
| `threat_intel` | `idx_threat_indicator` | `indicator` | B-tree | Exact indicator lookup |
| `threat_intel` | `idx_threat_source` | `source, last_seen DESC` | B-tree | Latest intel per source |
| `threat_intel` | `idx_threat_type` | `indicator_type` | B-tree | Filter by type (IP, CVE, etc.) |
| `threat_intel` | `idx_threat_text` | `to_tsvector(description)` WHERE NOT NULL | GIN | Full-text search on descriptions |
| `audit_log` | `idx_audit_timestamp` | `timestamp DESC` | B-tree | Latest audit entries |
| `audit_log` | `idx_audit_username` | `username, timestamp DESC` | B-tree | All actions by a user |

---

## 17. Seed Data

Two default user accounts are created at schema init:

```sql
-- admin account — password: cybersentinel2025
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@cybersentinel.ai',
     '$2b$12$KODr9Y22SHd9V8Wyi149DO5Tfj5rkedPGbgqnLU67FtIREvS5Ney6',
     'admin')
ON CONFLICT (username) DO NOTHING;

-- analyst account — password: cybersentinel2025
INSERT INTO users (username, email, password_hash, role) VALUES
    ('analyst', 'analyst@cybersentinel.ai',
     '$2b$12$KODr9Y22SHd9V8Wyi149DO5Tfj5rkedPGbgqnLU67FtIREvS5Ney6',
     'analyst')
ON CONFLICT (username) DO NOTHING;
```

### Changing Default Passwords

**Never use the default password in production.** To change:

```bash
# Method 1: Direct SQL with a new bcrypt hash
# Generate hash in Python:
python3 -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('YourNewPassword123!'))"

# Then update the DB:
docker exec -it cybersentinel-ai-postgres-1 psql -U sentinel -d cybersentinel \
  -c "UPDATE users SET password_hash = '<new_hash>' WHERE username = 'admin';"

# Method 2: POST /auth/change-password via API (if endpoint is implemented)
curl -X POST http://localhost:8080/auth/change-password \
  -H "Authorization: Bearer <token>" \
  -d '{"current_password": "cybersentinel2025", "new_password": "YourNewPassword123!"}'
```

---

## 18. Migration History

### v1.0 → v1.1 (Added in 2026-03-28)

Two columns were added to `incidents` for the human-in-the-loop block recommendation feature (ADR-009):

```sql
-- Run this on existing v1.0 databases to upgrade to v1.1:
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS block_target_ip TEXT;

-- Verify:
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'incidents'
  AND column_name IN ('block_recommended', 'block_target_ip');
```

**These columns are safe to add to a live production database** — both are nullable/have defaults, so existing rows are not affected. No application restart is needed.

### Schema Version Tracking

No formal migration framework (Alembic/Flyway) is used. Schema versions are tracked manually via the `CHANGELOG.md` and this file. Future versions should document all DDL changes here.

---

## 19. Common Query Patterns

### Dashboard: 24-hour stats

```sql
-- Used by GET /api/v1/dashboard
SELECT * FROM soc_summary;

-- Alerts by hour for the last 24h chart
SELECT DATE_TRUNC('hour', timestamp) AS hour,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical
FROM alerts
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour;
```

### Hosts Tab: Full host profile

```sql
-- Used by GET /api/v1/hosts/{ip}
SELECT
    bp.*,
    COUNT(fw.id) FILTER (WHERE fw.expires_at > NOW()) AS block_count,
    COUNT(DISTINCT inc.incident_id) AS incident_count
FROM behavior_profiles bp
LEFT JOIN firewall_rules fw ON fw.ip_address::text = bp.entity_id
LEFT JOIN incidents inc ON bp.entity_id = ANY(inc.affected_ips)
WHERE bp.entity_id = $1
GROUP BY bp.entity_id, bp.entity_type, bp.anomaly_score,
         bp.observation_count, bp.avg_bytes_per_min, bp.avg_entropy,
         bp.dominant_protocols, bp.typical_dst_ports, bp.profile_text,
         bp.first_seen, bp.updated_at;
```

### Response Tab: Pending block recommendations

```sql
-- Used by GET /api/v1/block-recommendations
SELECT incident_id, title, severity, block_target_ip,
       investigation_summary, created_at
FROM incidents
WHERE block_recommended = TRUE
  AND status = 'OPEN'
ORDER BY
    CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                  WHEN 'MEDIUM'   THEN 3 ELSE 4 END,
    created_at DESC;
```

### Analyst blocks an IP

```sql
-- Step 1: Create firewall rule
INSERT INTO firewall_rules (ip_address, action, justification, incident_id, created_by, duration_hours)
VALUES ($1, 'BLOCK', $2, $3, $4, 24)
RETURNING id, expires_at;

-- Step 2: Update incident status
UPDATE incidents
SET status = 'RESOLVED', resolved_at = NOW(), updated_at = NOW()
WHERE incident_id = $1;

-- Step 3: Write audit log
INSERT INTO audit_log (username, action, resource, resource_id, details, ip_address)
VALUES ($1, 'block_ip', 'firewall_rules', $2,
        jsonb_build_object('ip_blocked', $3, 'duration_hours', 24), $4);
```

### MCP: Recent alerts for an IP

```sql
-- Used by get_recent_alerts() MCP tool
SELECT id, timestamp, type, severity, mitre_technique, anomaly_score
FROM alerts
WHERE src_ip = $1::inet
ORDER BY timestamp DESC
LIMIT 10;
```

### Threat Intel: Full-text search

```sql
-- Used by POST /api/v1/threat-search (in-DB fallback — primary search uses ChromaDB)
SELECT id, source, indicator_type, indicator, severity, description
FROM threat_intel
WHERE to_tsvector('english', description) @@ plainto_tsquery('english', $1)
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY last_seen DESC
LIMIT 10;
```

### Is an IP currently blocked?

```sql
SELECT EXISTS (
    SELECT 1 FROM firewall_rules
    WHERE ip_address = $1::inet
      AND action = 'BLOCK'
      AND (expires_at IS NULL OR expires_at > NOW())
) AS is_blocked;
```

---

## 20. Performance & Sizing

### Storage Estimates

| Table | Growth Rate | After 30 days | Notes |
|-------|-------------|---------------|-------|
| `packets` | ~500k rows/hour (busy network) | Bounded by retention policy | TimescaleDB drops chunks after 30 days |
| `packets` (compressed) | ~50 bytes/row after compression | ~18 GB/month uncompressed → ~1.8 GB compressed | 90% compression on columnar chunks |
| `alerts` | ~100–500 rows/hour | ~5M rows after 30 days | ~500 MB |
| `incidents` | ~10–50 rows/hour | ~50k rows | ~50 MB |
| `behavior_profiles` | 1 row per IP (upserted) | ~10k rows for 10k hosts | ~10 MB |
| `threat_intel` | ~5k rows per scrape run | ~50k rows total | ~100 MB |
| `audit_log` | ~200 rows/hour | ~150k rows | ~150 MB |

### Connection Pool Tuning

| Load | `min_size` | `max_size` | Notes |
|------|-----------|-----------|-------|
| Development / simulator | 2 | 5 | Minimal concurrency needed |
| Production (default) | 5 | 20 | Current config in `gateway.py` |
| High-traffic SOC | 10 | 50 | Increase if API latency rises under load |

### Slow Query Prevention

The most common slow query patterns and how the schema avoids them:

| Anti-pattern | Risk | How Schema Avoids It |
|-------------|------|---------------------|
| `SELECT * FROM packets` without time filter | Full table scan | TimescaleDB chunk exclusion (always filter on `timestamp`) |
| `WHERE src_ip IN (SELECT ...)` subquery | Correlated subquery | Use array operator: `src_ip::text = ANY(affected_ips)` |
| `DELETE FROM packets WHERE timestamp < X` | Row-by-row delete, locks table | TimescaleDB retention policy drops entire chunk files |
| COUNT(*) without index | Sequential scan | `soc_summary` view uses indexed timestamp filters |
| Full-text search without GIN | Sequential scan | GIN index on `to_tsvector(description)` |

---

## 21. Backup & Recovery

### Backup the Running Database

```bash
# Full logical backup (all tables, all data)
docker exec cybersentinel-ai-postgres-1 \
    pg_dump -U sentinel -d cybersentinel \
    --format=custom \
    --file=/tmp/cybersentinel_backup_$(date +%Y%m%d).dump

# Copy backup out of the container
docker cp cybersentinel-ai-postgres-1:/tmp/cybersentinel_backup_$(date +%Y%m%d).dump \
    ./backups/
```

### Restore from Backup

```bash
# Restore to a running container
docker exec -i cybersentinel-ai-postgres-1 \
    pg_restore -U sentinel -d cybersentinel --clean \
    < ./backups/cybersentinel_backup_20260330.dump
```

### Backup Docker Volume (Binary Backup)

```bash
# Faster than pg_dump for large datasets — backs up the entire volume
docker run --rm \
    -v cybersentinel-ai_postgres_data:/data \
    -v $(pwd)/backups:/backup \
    alpine tar czf /backup/postgres_volume_$(date +%Y%m%d).tar.gz -C /data .
```

### Schedule Automated Backups

Add to crontab on the host machine:

```bash
# Daily backup at 02:00 UTC
0 2 * * * docker exec cybersentinel-ai-postgres-1 \
    pg_dump -U sentinel -d cybersentinel --format=custom \
    --file=/tmp/cs_backup_$(date +\%Y\%m\%d).dump && \
    docker cp cybersentinel-ai-postgres-1:/tmp/cs_backup_$(date +\%Y\%m\%d).dump \
    /opt/backups/cybersentinel/
```

### Inspect Database Directly

```bash
# Open psql shell inside the running container
docker exec -it cybersentinel-ai-postgres-1 psql -U sentinel -d cybersentinel

# Useful psql commands:
\dt                    -- list all tables
\d packets             -- describe packets table (columns + indexes)
\d+ behavior_profiles  -- verbose table description
SELECT * FROM soc_summary;  -- run KPI view
\q                     -- exit
```

---

*Database Documentation — CyberSentinel AI v1.1 — 2026*
*Source of truth: `scripts/db/init.sql` — always refer to that file for the canonical DDL.*
