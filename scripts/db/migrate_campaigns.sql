-- ─────────────────────────────────────────────────────────────────────────────
-- CyberSentinel AI — Campaign / Kill Chain tracking tables
--
-- Groups incidents from the same source IP within a 24-hour window into a
-- campaign record so analysts see coordinated multi-stage attacks as a
-- single entity rather than isolated events.
--
-- Run:
--   psql "$POSTGRES_URL" -f scripts/db/migrate_campaigns.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS attacker_campaigns (
    campaign_id      TEXT        PRIMARY KEY,
    src_ip           TEXT        NOT NULL,
    source           TEXT        NOT NULL DEFAULT 'dpi',   -- 'simulator' or 'dpi'
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    incident_count   INTEGER     NOT NULL DEFAULT 1,
    max_severity     TEXT        NOT NULL DEFAULT 'LOW',
    mitre_stages     TEXT[]      NOT NULL DEFAULT '{}',
    campaign_summary TEXT
);

-- Add source column to existing deployments (idempotent)
ALTER TABLE attacker_campaigns ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'dpi';

CREATE TABLE IF NOT EXISTS campaign_incidents (
    campaign_id TEXT NOT NULL REFERENCES attacker_campaigns(campaign_id) ON DELETE CASCADE,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id)          ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, incident_id)
);

CREATE INDEX IF NOT EXISTS idx_attacker_campaigns_src_ip
    ON attacker_campaigns(src_ip);

CREATE INDEX IF NOT EXISTS idx_attacker_campaigns_last_seen
    ON attacker_campaigns(last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_campaign_incidents_incident_id
    ON campaign_incidents(incident_id);
