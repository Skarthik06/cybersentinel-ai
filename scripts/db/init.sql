-- ─────────────────────────────────────────────────────────────────────────────
-- CyberSentinel AI — TimescaleDB Production Schema
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ─────────────────────────────────────────────────────────────────────────────
-- PACKETS — hypertable (time-series core)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS packets (
    id              UUID        DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET        NOT NULL,
    dst_ip          INET        NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    payload_size    INTEGER     DEFAULT 0,
    flags           VARCHAR(20),
    ttl             SMALLINT,
    entropy         NUMERIC(5,4) DEFAULT 0,
    has_tls         BOOLEAN     DEFAULT FALSE,
    has_dns         BOOLEAN     DEFAULT FALSE,
    dns_query       TEXT,
    http_method     VARCHAR(10),
    http_host       TEXT,
    http_uri        TEXT,
    user_agent      TEXT,
    is_suspicious   BOOLEAN     DEFAULT FALSE,
    suspicion_reasons JSONB     DEFAULT '[]',
    session_id      TEXT,
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('packets', 'timestamp', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');

-- Compression: compress chunks older than 7 days (requires columnstore — skip if unavailable)
DO $$
BEGIN
    PERFORM add_compression_policy('packets', INTERVAL '7 days');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping compression policy: %', SQLERRM;
END $$;

-- Retention: auto-drop chunks older than 30 days
DO $$
BEGIN
    PERFORM add_retention_policy('packets', INTERVAL '30 days');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping retention policy: %', SQLERRM;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_packets_src_ip    ON packets (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip    ON packets (dst_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_packets_session   ON packets (session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_packets_suspicious ON packets (is_suspicious, timestamp DESC) WHERE is_suspicious = TRUE;

-- Continuous aggregate: packets per minute per IP
CREATE MATERIALIZED VIEW IF NOT EXISTS packets_per_minute
WITH (timescaledb.continuous) AS
    SELECT time_bucket('1 minute', timestamp) AS bucket,
           src_ip,
           COUNT(*)               AS packet_count,
           SUM(payload_size)      AS total_bytes,
           AVG(entropy)           AS avg_entropy,
           COUNT(*) FILTER (WHERE is_suspicious) AS suspicious_count
    FROM packets
    GROUP BY bucket, src_ip
WITH NO DATA;

DO $$
BEGIN
    PERFORM add_continuous_aggregate_policy('packets_per_minute',
        start_offset => INTERVAL '1 hour',
        end_offset   => INTERVAL '1 minute',
        schedule_interval => INTERVAL '1 minute');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping continuous aggregate policy: %', SQLERRM;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- ALERTS
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id                     UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    type                   VARCHAR(80) NOT NULL,
    severity               VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    src_ip                 INET,
    dst_ip                 INET,
    src_port               INTEGER,
    dst_port               INTEGER,
    protocol               VARCHAR(10),
    description            TEXT,
    suspicion_reasons      JSONB       DEFAULT '[]',
    mitre_technique        VARCHAR(20),
    anomaly_score          NUMERIC(6,4),
    rlm_profile_summary    TEXT,
    session_id             TEXT,
    investigation_summary  TEXT,
    investigated_at        TIMESTAMPTZ,
    raw_event              JSONB       DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp    ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip       ON alerts (src_ip,  timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type         ON alerts (type,    timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre        ON alerts (mitre_technique) WHERE mitre_technique IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- INCIDENTS
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    incident_id      VARCHAR(40)  DEFAULT 'INC-' || EXTRACT(EPOCH FROM NOW())::BIGINT PRIMARY KEY,
    title            TEXT         NOT NULL,
    severity         VARCHAR(20)  NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status           VARCHAR(20)  NOT NULL DEFAULT 'OPEN'
                                  CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','CLOSED')),
    description      TEXT,
    affected_ips     TEXT[]       DEFAULT '{}',
    mitre_techniques TEXT[]       DEFAULT '{}',
    evidence         TEXT,
    notes                TEXT,
    assigned_to          VARCHAR(80),
    created_by           VARCHAR(80)  DEFAULT 'mcp-orchestrator',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at          TIMESTAMPTZ,
    investigation_summary TEXT,
    block_recommended    BOOLEAN      DEFAULT FALSE,
    block_target_ip      TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity, created_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- BEHAVIOR PROFILES (RLM engine output)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS behavior_profiles (
    entity_id          TEXT         PRIMARY KEY,
    entity_type        VARCHAR(20)  NOT NULL DEFAULT 'host',
    anomaly_score      NUMERIC(6,4) DEFAULT 0,
    observation_count  INTEGER      DEFAULT 0,
    avg_bytes_per_min  NUMERIC(12,4) DEFAULT 0,
    avg_entropy        NUMERIC(6,4) DEFAULT 0,
    dominant_protocols JSONB        DEFAULT '{}',
    typical_dst_ports  JSONB        DEFAULT '{}',
    profile_text       TEXT,
    first_seen         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_score ON behavior_profiles (anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_type  ON behavior_profiles (entity_type);

-- ─────────────────────────────────────────────────────────────────────────────
-- FIREWALL RULES
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS firewall_rules (
    id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address     INET        NOT NULL,
    action         VARCHAR(10) NOT NULL DEFAULT 'BLOCK' CHECK (action IN ('BLOCK','ALLOW','LOG')),
    justification  TEXT,
    incident_id    VARCHAR(40) REFERENCES incidents(incident_id) ON DELETE SET NULL,
    created_by     VARCHAR(80) DEFAULT 'mcp-orchestrator',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_hours INTEGER     DEFAULT 24,
    expires_at     TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION firewall_set_expires_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.expires_at := NEW.created_at + (NEW.duration_hours * INTERVAL '1 hour');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_firewall_expires ON firewall_rules;
CREATE TRIGGER trg_firewall_expires
    BEFORE INSERT OR UPDATE ON firewall_rules
    FOR EACH ROW EXECUTE FUNCTION firewall_set_expires_at();

CREATE INDEX IF NOT EXISTS idx_firewall_ip      ON firewall_rules (ip_address);
CREATE INDEX IF NOT EXISTS idx_firewall_active  ON firewall_rules (expires_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- THREAT INTEL
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel (
    id              UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    source          VARCHAR(40) NOT NULL,
    indicator_type  VARCHAR(20) NOT NULL CHECK (indicator_type IN ('IP','DOMAIN','CVE','TECHNIQUE','HASH','URL')),
    indicator       TEXT        NOT NULL,
    severity        VARCHAR(20),
    description     TEXT,
    tags            TEXT[]      DEFAULT '{}',
    raw_data        JSONB       DEFAULT '{}',
    embedded        BOOLEAN     DEFAULT FALSE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    UNIQUE (source, indicator_type, indicator)
);

CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_intel (indicator);
CREATE INDEX IF NOT EXISTS idx_threat_source    ON threat_intel (source, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threat_type      ON threat_intel (indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_text      ON threat_intel USING gin(to_tsvector('english', description))
    WHERE description IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- USERS (RBAC)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    username      VARCHAR(80) UNIQUE NOT NULL,
    email         VARCHAR(120) UNIQUE,
    password_hash TEXT        NOT NULL,
    role          VARCHAR(20) NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('admin','analyst','responder','viewer')),
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default admin (change password after first login via UPDATE users SET password_hash = ... WHERE username = 'admin')
-- Hash generated with: passlib.context.CryptContext(schemes=["bcrypt"]).hash("<your-password>")
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@cybersentinel.ai',
     '$2b$12$KODr9Y22SHd9V8Wyi149DO5Tfj5rkedPGbgqnLU67FtIREvS5Ney6',
     'admin')
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, password_hash, role) VALUES
    ('analyst', 'analyst@cybersentinel.ai',
     '$2b$12$KODr9Y22SHd9V8Wyi149DO5Tfj5rkedPGbgqnLU67FtIREvS5Ney6',
     'analyst')
ON CONFLICT (username) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- AUDIT LOG
-- ─────────────────────────────────────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit_log (username, timestamp DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- VIEWS
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW active_threats AS
    SELECT
        a.id, a.timestamp, a.type, a.severity, a.src_ip, a.dst_ip,
        a.mitre_technique, a.anomaly_score,
        bp.anomaly_score    AS profile_score,
        bp.observation_count,
        i.incident_id, i.status AS incident_status
    FROM alerts a
    LEFT JOIN behavior_profiles bp ON bp.entity_id = a.src_ip::text
    LEFT JOIN incidents i ON a.src_ip::text = ANY(i.affected_ips) AND i.status IN ('OPEN','INVESTIGATING')
    WHERE a.timestamp > NOW() - INTERVAL '24 hours'
      AND a.severity IN ('CRITICAL','HIGH')
    ORDER BY a.timestamp DESC;

CREATE OR REPLACE VIEW soc_summary AS
    SELECT
        (SELECT COUNT(*) FROM alerts    WHERE timestamp > NOW() - INTERVAL '24 hours')          AS total_alerts_24h,
        (SELECT COUNT(*) FROM alerts    WHERE timestamp > NOW() - INTERVAL '24 hours' AND severity = 'CRITICAL') AS critical_24h,
        (SELECT COUNT(*) FROM incidents WHERE status = 'OPEN')                                  AS open_incidents,
        (SELECT COUNT(*) FROM incidents WHERE status = 'INVESTIGATING')                         AS investigating_incidents,
        (SELECT COUNT(*) FROM firewall_rules WHERE expires_at > NOW())                          AS active_blocks,
        (SELECT COUNT(*) FROM behavior_profiles WHERE anomaly_score > 0.65)                     AS high_risk_hosts,
        (SELECT COUNT(*) FROM threat_intel  WHERE last_seen > NOW() - INTERVAL '24 hours')      AS new_intel_24h;

