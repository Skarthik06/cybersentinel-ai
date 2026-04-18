# Database Documentation

**CyberSentinel AI v1.3.0 — PostgreSQL + TimescaleDB Complete Reference**

---

## Table of Contents

1. [Database Overview](#1-database-overview)
2. [Extensions](#2-extensions)
3. [Entity Relationship Diagram](#3-entity-relationship-diagram)
4. [Table: packets](#4-table-packets)
5. [Table: alerts](#5-table-alerts)
6. [Table: incidents](#6-table-incidents)
7. [Table: attacker_campaigns](#7-table-attacker_campaigns)
8. [Table: campaign_incidents](#8-table-campaign_incidents)
9. [Table: behavior_profiles](#9-table-behavior_profiles)
10. [Table: firewall_rules](#10-table-firewall_rules)
11. [Table: threat_intel](#11-table-threat_intel)
12. [Table: users](#12-table-users)
13. [Table: audit_log](#13-table-audit_log)
14. [TimescaleDB Hypertable Configuration](#14-timescaledb-hypertable-configuration)
15. [Materialized View: packets_per_minute](#15-materialized-view-packets_per_minute)
16. [Views: active_threats & soc_summary](#16-views-active_threats--soc_summary)
17. [Triggers](#17-triggers)
18. [Index Reference](#18-index-reference)
19. [Seed Data](#19-seed-data)
20. [Migration History](#20-migration-history)
21. [Common Query Patterns](#21-common-query-patterns)
22. [Performance & Sizing](#22-performance--sizing)
23. [Backup & Recovery](#23-backup--recovery)

---

## 1. Database Overview

CyberSentinel AI uses **PostgreSQL 15 with the TimescaleDB extension**.

| Requirement | Why PostgreSQL + TimescaleDB |
|-------------|------------------------------|
| Time-series packet data | TimescaleDB hypertables auto-partition by time — queries are O(1) not O(n) |
| Relational data (users, incidents, audit) | Standard PostgreSQL tables |
| Array columns (affected_ips, mitre_techniques) | PostgreSQL native `TEXT[]` arrays |
| JSON blobs (raw_event, suspicion_reasons) | `JSONB` with GIN indexing |
| Automatic data expiry | TimescaleDB retention policies auto-drop old partitions |
| Compression for cold data | TimescaleDB columnstore compression ~90%+ for 7-day-old data |
| Full-text search | `pg_trgm` extension + GIN index on `description` |

### Connection Details (Docker Compose)

| Setting | Value |
|---------|-------|
| Host | `postgres` (Docker Compose service name) |
| Port | `5432` |
| Database | `cybersentinel` |
| User | `sentinel` |
| Password | `POSTGRES_PASSWORD` from `.env` |
| Full URL | `postgresql://sentinel:${POSTGRES_PASSWORD}@postgres:5432/cybersentinel` |

### asyncpg Connection Pool (API Gateway)

```python
db_pool = await asyncpg.create_pool(
    dsn=POSTGRES_URL,
    min_size=5,
    max_size=20,
    command_timeout=30
)
```

---

## 2. Extensions

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

| Extension | Purpose |
|-----------|---------|
| `timescaledb` | Hypertables, compression, retention, continuous aggregates |
| `uuid-ossp` | `uuid_generate_v4()` for primary keys |
| `pg_trgm` | Trigram similarity indexes for full-text search |

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

    ATTACKER_CAMPAIGNS {
        text campaign_id PK
        text src_ip
        timestamptz first_seen
        timestamptz last_seen
        int incident_count
        text max_severity
        text_array mitre_stages
        text campaign_summary
    }

    CAMPAIGN_INCIDENTS {
        text campaign_id FK
        text incident_id FK
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
    INCIDENTS ||--o{ FIREWALL_RULES : "incident_id"
    INCIDENTS ||--o{ CAMPAIGN_INCIDENTS : "incident_id"
    ATTACKER_CAMPAIGNS ||--|{ CAMPAIGN_INCIDENTS : "campaign_id"
    USERS ||--o{ AUDIT_LOG : "username"
```

---

## 4. Table: `packets`

Stores every suspicious network packet captured by the DPI sensor. This is the highest-volume table — it is a **TimescaleDB hypertable** partitioned into 1-day chunks.

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

> **PII note:** `dns_query`, `http_uri`, and `user_agent` are sanitized by `_mask_pii()` in the DPI sensor before reaching Kafka or this table.

### Row Lifecycle

```mermaid
graph LR
    CAP[DPI captures packet] --> DET[detectors.py — is_suspicious = TRUE]
    DET --> MASK[_mask_pii — redact PII]
    MASK --> K[Kafka raw-packets]
    K --> RLM[RLM engine INSERTs into packets]
    RLM --> COMP[After 7 days: TimescaleDB compresses chunk]
    COMP --> DROP[After 30 days: TimescaleDB drops chunk]
```

---

## 5. Table: `alerts`

Stores every detected threat alert from both the RLM engine and the traffic simulator.

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

**Note on `anomaly_score`:** This is the IsolationForest-blended score from v1.3.0 — 75% ChromaDB cosine similarity + 25% IsolationForest contribution.

---

## 6. Table: `incidents`

Represents a grouped security incident created by the MCP Orchestrator after completing an investigation.

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

### Status Lifecycle

```mermaid
stateDiagram-v2
    [*] --> OPEN : MCP creates incident
    OPEN --> INVESTIGATING : Analyst picks up
    OPEN --> RESOLVED : Analyst blocks or dismisses
    INVESTIGATING --> RESOLVED : Action taken
    RESOLVED --> CLOSED : Archived after review
    OPEN --> CLOSED : Direct close (low severity)
```

### Human-in-the-Loop Fields

| Column | Meaning |
|--------|---------|
| `block_recommended` | TRUE = LLM recommends blocking `block_target_ip`. Analyst must confirm via RESPONSE tab |
| `block_target_ip` | IP the LLM recommends blocking. Set when `block_recommended = TRUE` |

**Flow:**
1. MCP LLM returns `{"block_recommended": true, "block_target_ip": "185.220.101.47"}`
2. `INSERT INTO incidents (..., block_recommended=TRUE, block_target_ip='185.220.101.47')`
3. React RESPONSE tab polls `GET /api/v1/block-recommendations`
4. Analyst clicks BLOCK IP → `POST /api/v1/incidents/{id}/block` → inserts firewall rule
5. OR analyst clicks DISMISS → `POST /api/v1/incidents/{id}/dismiss`

---

## 7. Table: `attacker_campaigns`

Groups related incidents from the same source IP within a 24-hour window into attacker campaigns. Tracks the kill chain progression via `mitre_stages[]`.

### DDL

```sql
CREATE TABLE IF NOT EXISTS attacker_campaigns (
    campaign_id      TEXT PRIMARY KEY,
    src_ip           TEXT NOT NULL,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    incident_count   INTEGER,
    max_severity     TEXT,
    mitre_stages     TEXT[],
    campaign_summary TEXT
);
```

### Column Reference

| Column | Description |
|--------|-------------|
| `campaign_id` | `{src_ip}-{epoch}` — unique per source IP |
| `src_ip` | Attacker source IP address |
| `first_seen` | Timestamp of first incident in this campaign |
| `last_seen` | Timestamp of most recent incident |
| `incident_count` | Total incidents in this campaign |
| `max_severity` | Highest severity across all incidents (severity ratchet — never decreases) |
| `mitre_stages` | Union of all MITRE technique IDs across campaign incidents |
| `campaign_summary` | Optional AI-generated narrative of the attacker's activity |

### Correlation Logic

```mermaid
graph LR
    INC[New incident created] --> CORR[_correlate_campaign_with_pool]
    CORR --> QUERY{Existing campaign\nfor src_ip in last 24h?}
    QUERY -->|Yes| UPDATE[UPDATE campaign\nincrement incident_count\nratchet max_severity\nunion mitre_stages]
    QUERY -->|No| CREATE[INSERT new campaign\ncampaign_id = src_ip + epoch]
    UPDATE --> LINK[INSERT campaign_incidents]
    CREATE --> LINK
```

---

## 8. Table: `campaign_incidents`

Junction table linking incidents to campaigns.

### DDL

```sql
CREATE TABLE IF NOT EXISTS campaign_incidents (
    campaign_id TEXT REFERENCES attacker_campaigns(campaign_id),
    incident_id TEXT REFERENCES incidents(incident_id),
    PRIMARY KEY (campaign_id, incident_id)
);
```

---

## 9. Table: `behavior_profiles`

Running behavioral profile for each host IP, updated continuously by the RLM engine using EMA.

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

### EMA Formula

```python
alpha = 0.1  # RLM_ALPHA env var
new_avg_bytes   = (1 - alpha) * old_avg_bytes   + alpha * current_bytes
new_avg_entropy = (1 - alpha) * old_avg_entropy + alpha * current_entropy
observation_count += 1
```

Requires at least `RLM_MIN_OBSERVATIONS = 20` packets before anomaly scoring begins. IsolationForest blend begins after 10 samples.

**Note on `anomaly_score` in v1.3:** This stores the IsolationForest-blended final score (`0.75 × ChromaDB + 0.25 × IsolationForest`), not the raw ChromaDB cosine similarity.

---

## 10. Table: `firewall_rules`

Records every IP block created by analysts via the RESPONSE tab. Rules are time-limited — `expires_at` is auto-calculated by trigger.

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

`ON DELETE SET NULL` ensures firewall rules persist even if the associated incident is deleted.

---

## 11. Table: `threat_intel`

Structured threat intelligence indicators from external CTI sources.

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

The `UNIQUE` constraint prevents duplicates on upsert. The `embedded` flag tracks whether the description has been embedded into ChromaDB to avoid redundant embeddings.

---

## 12. Table: `users`

SOC analyst accounts for JWT authentication. Only `admin` credentials are used in the current deployment.

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

**Current deployment:** Only the `admin` account is active. All API endpoints are accessible with the admin JWT token. Role-based access differentiation between analyst/responder/viewer is defined in the schema but not enforced in the current API implementation.

---

## 13. Table: `audit_log`

Immutable compliance log of every significant action (block IP, dismiss incident, login, etc.).

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

---

## 14. TimescaleDB Hypertable Configuration

The `packets` table is a hypertable partitioned into 1-day chunks:

```sql
SELECT create_hypertable('packets', 'timestamp',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);
```

```mermaid
graph TB
    subgraph HYPERTABLE["packets hypertable"]
        C1["Chunk: Day -30\nAUTO DROPPED"]
        C5["Chunk: Day -7\n(compressed after 7 days)"]
        C6["Chunk: Yesterday\n(active)"]
        C7["Chunk: Today\n(active)"]
    end

    QUERY["SELECT * FROM packets\nWHERE timestamp > NOW() - INTERVAL '1 hour'"]
    -->|Only scans today chunk| C7

    style C1 fill:#ef9a9a,color:#000
    style C5 fill:#bdbdbd,color:#000
    style C6 fill:#a5d6a7,color:#000
    style C7 fill:#4caf50,color:#fff
    style QUERY fill:#7b68ee,color:#fff
```

| Policy | Setting | Effect |
|--------|---------|--------|
| Chunk interval | 1 day | Each day is a separate partition |
| Compression | After 7 days | ~90% storage reduction via columnstore |
| Retention | Drop after 30 days | Auto-delete without DELETE scan |
| Aggregate refresh | Every 1 minute | `packets_per_minute` view stays current |

---

## 15. Materialized View: `packets_per_minute`

Pre-aggregates packet counts, bytes, entropy per source IP per minute for dashboard charts.

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

---

## 16. Views: `active_threats` & `soc_summary`

### `active_threats`

Joins `alerts`, `behavior_profiles`, and `incidents` — all CRITICAL/HIGH alerts in last 24h with profile scores and incident status.

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
    LEFT JOIN behavior_profiles bp ON bp.entity_id = a.src_ip::text
    LEFT JOIN incidents i
           ON a.src_ip::text = ANY(i.affected_ips)
          AND i.status IN ('OPEN','INVESTIGATING')
    WHERE a.timestamp > NOW() - INTERVAL '24 hours'
      AND a.severity IN ('CRITICAL','HIGH')
    ORDER BY a.timestamp DESC;
```

### `soc_summary`

Single-row KPI view for the dashboard Overview tab.

```sql
CREATE OR REPLACE VIEW soc_summary AS
    SELECT
        (SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours')                AS total_alerts_24h,
        (SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours'
                                         AND severity = 'CRITICAL')                                AS critical_24h,
        (SELECT COUNT(*) FROM incidents WHERE status = 'OPEN')                                     AS open_incidents,
        (SELECT COUNT(*) FROM incidents WHERE status = 'INVESTIGATING')                            AS investigating_incidents,
        (SELECT COUNT(*) FROM firewall_rules WHERE expires_at > NOW())                             AS active_blocks,
        (SELECT COUNT(*) FROM behavior_profiles WHERE anomaly_score > 0.65)                        AS high_risk_hosts,
        (SELECT COUNT(*) FROM threat_intel WHERE last_seen > NOW() - INTERVAL '24 hours')          AS new_intel_24h;
```

---

## 17. Triggers

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

---

## 18. Index Reference

| Table | Index | Columns | Purpose |
|-------|-------|---------|---------|
| `packets` | `idx_packets_src_ip` | `src_ip, timestamp DESC` | Per-IP time-range queries |
| `packets` | `idx_packets_dst_ip` | `dst_ip, timestamp DESC` | Per-destination queries |
| `packets` | `idx_packets_session` | `session_id, timestamp DESC` | Session reassembly |
| `packets` | `idx_packets_suspicious` | `is_suspicious, timestamp DESC` (partial) | Only suspicious rows |
| `alerts` | `idx_alerts_timestamp` | `timestamp DESC` | Dashboard: latest 24h |
| `alerts` | `idx_alerts_severity` | `severity, timestamp DESC` | Filter by severity + time |
| `alerts` | `idx_alerts_src_ip` | `src_ip, timestamp DESC` | Host detail: alerts by IP |
| `alerts` | `idx_alerts_type` | `type, timestamp DESC` | Filter by alert category |
| `alerts` | `idx_alerts_mitre` | `mitre_technique` (partial, NOT NULL) | MITRE technique lookup |
| `incidents` | `idx_incidents_status` | `status, created_at DESC` | RESPONSE tab: open incidents |
| `incidents` | `idx_incidents_severity` | `severity, created_at DESC` | Filter by severity |
| `attacker_campaigns` | `idx_campaigns_src_ip` | `src_ip, last_seen DESC` | Correlation window lookup |
| `attacker_campaigns` | `idx_campaigns_last_seen` | `last_seen DESC` | GET /api/v1/campaigns ordering |
| `behavior_profiles` | `idx_profiles_score` | `anomaly_score DESC` | Top risky hosts |
| `behavior_profiles` | `idx_profiles_type` | `entity_type` | Filter by type |
| `firewall_rules` | `idx_firewall_ip` | `ip_address` | Is IP currently blocked? |
| `firewall_rules` | `idx_firewall_active` | `expires_at` | Active rules |
| `threat_intel` | `idx_threat_indicator` | `indicator` | Exact lookup |
| `threat_intel` | `idx_threat_source` | `source, last_seen DESC` | Latest per source |
| `threat_intel` | `idx_threat_text` | `to_tsvector(description)` (GIN, partial) | Full-text search |
| `audit_log` | `idx_audit_timestamp` | `timestamp DESC` | Latest entries |
| `audit_log` | `idx_audit_username` | `username, timestamp DESC` | Actions by user |

---

## 19. Seed Data

```sql
-- admin account — password: cybersentinel2025
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@cybersentinel.ai',
     '$2b$12$KODr9Y22SHd9V8Wyi149DO5Tfj5rkedPGbgqnLU67FtIREvS5Ney6',
     'admin')
ON CONFLICT (username) DO NOTHING;
```

**Never use the default password in production.** To change:

```bash
# Generate new bcrypt hash
python3 -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('YourNewPassword!'))"

# Update in Docker Compose
docker exec -it cybersentinel-postgres psql -U sentinel -d cybersentinel \
  -c "UPDATE users SET password_hash = '<new_hash>' WHERE username = 'admin';"
```

---

## 20. Migration History

### v1.0 → v1.1 — block_recommended fields (2026-03-28)

```sql
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_recommended BOOLEAN DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS block_target_ip   TEXT;
```

### v1.2 → v1.3 — campaign tracking (2026-04-16)

```sql
-- Run: docker exec -i cybersentinel-postgres psql -U sentinel -d cybersentinel \
--   < scripts/db/migrate_campaigns.sql

CREATE TABLE IF NOT EXISTS attacker_campaigns (
    campaign_id      TEXT PRIMARY KEY,
    src_ip           TEXT NOT NULL,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    incident_count   INTEGER,
    max_severity     TEXT,
    mitre_stages     TEXT[],
    campaign_summary TEXT
);

CREATE TABLE IF NOT EXISTS campaign_incidents (
    campaign_id TEXT REFERENCES attacker_campaigns(campaign_id),
    incident_id TEXT REFERENCES incidents(incident_id),
    PRIMARY KEY (campaign_id, incident_id)
);

CREATE INDEX IF NOT EXISTS idx_campaigns_src_ip    ON attacker_campaigns (src_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen ON attacker_campaigns (last_seen DESC);
```

---

## 21. Common Query Patterns

### Dashboard: 24-hour stats

```sql
SELECT * FROM soc_summary;
```

### Response Tab: Pending block recommendations

```sql
SELECT incident_id, title, severity, block_target_ip, investigation_summary, created_at
FROM incidents
WHERE block_recommended = TRUE AND status = 'OPEN'
ORDER BY
    CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
    created_at DESC;
```

### Campaigns: Active attacker campaigns

```sql
SELECT campaign_id, src_ip, first_seen, last_seen, incident_count, max_severity, mitre_stages
FROM attacker_campaigns
ORDER BY last_seen DESC
LIMIT 50;
```

### Campaign correlation window

```sql
-- Find existing campaign for src_ip within last 24 hours
SELECT campaign_id FROM attacker_campaigns
WHERE src_ip = $1 AND last_seen > NOW() - INTERVAL '24 hours'
ORDER BY last_seen DESC
LIMIT 1;
```

### Analyst blocks an IP

```sql
-- Step 1: Create firewall rule
INSERT INTO firewall_rules (ip_address, action, justification, incident_id, created_by, duration_hours)
VALUES ($1, 'BLOCK', $2, $3, $4, 24)
RETURNING id, expires_at;

-- Step 2: Update incident status
UPDATE incidents SET status = 'RESOLVED', resolved_at = NOW(), updated_at = NOW()
WHERE incident_id = $1;
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

## 22. Performance & Sizing

| Table | Growth Rate | After 30 days | Notes |
|-------|-------------|---------------|-------|
| `packets` | ~500k rows/hour (busy network) | Bounded by retention | TimescaleDB drops chunks after 30 days |
| `alerts` | ~100–500 rows/hour | ~5M rows | ~500 MB |
| `incidents` | ~10–50 rows/hour | ~50k rows | ~50 MB |
| `attacker_campaigns` | 1 row per unique src_ip per 24h | ~1k rows (bounded by attacker IPs) | ~1 MB |
| `behavior_profiles` | 1 row per IP (upserted) | ~10k rows | ~10 MB |
| `threat_intel` | ~5k rows per scrape | ~50k rows total | ~100 MB |
| `audit_log` | ~200 rows/hour | ~150k rows | ~150 MB |

---

## 23. Backup & Recovery

### Backup the Running Database

```bash
# Full logical backup
docker exec cybersentinel-postgres \
  pg_dump -U sentinel -d cybersentinel --format=custom \
  --file=/tmp/cybersentinel_backup.dump

docker cp cybersentinel-postgres:/tmp/cybersentinel_backup.dump \
  ./backups/cybersentinel_$(date +%Y%m%d).dump
```

### Restore from Backup

```bash
docker exec -i cybersentinel-postgres \
  pg_restore -U sentinel -d cybersentinel --clean \
  < ./backups/cybersentinel_20260416.dump
```

### Inspect Database Directly

```bash
docker exec -it cybersentinel-postgres psql -U sentinel -d cybersentinel

# Useful commands:
\dt                     -- list all tables
\d incidents            -- describe table
SELECT * FROM soc_summary;
SELECT * FROM attacker_campaigns ORDER BY last_seen DESC LIMIT 10;
\q
```

---

*Database Documentation — CyberSentinel AI v1.3.0 — 2026*
*Source of truth: `scripts/db/init.sql` + `scripts/db/migrate_campaigns.sql`*
