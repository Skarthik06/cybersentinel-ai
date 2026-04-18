-- ─────────────────────────────────────────────────────────────────────────────
-- CyberSentinel AI — Multi-tenancy Migration
-- Run ONCE after initial setup to add tenant_id to all data tables.
--
-- Usage (Docker):
--   docker exec -i cybersentinel-postgres \
--     psql -U sentinel -d cybersentinel \
--     < scripts/db/migrate_multitenancy.sql
--
-- Usage (Kubernetes):
--   kubectl exec -n cybersentinel -i deploy/postgres -- \
--     psql -U sentinel -d cybersentinel \
--     < scripts/db/migrate_multitenancy.sql
--
-- Design:
--   - tenant_id defaults to 'default' — all pre-migration data is assigned here
--   - Row-level queries must include WHERE tenant_id = $<param> to scope access
--   - JWT tokens include { "sub": "user", "role": "analyst", "tenant": "acme" }
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── alerts ────────────────────────────────────────────────────────────────────
ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_alerts_tenant
  ON alerts (tenant_id, timestamp DESC);

-- ── incidents ─────────────────────────────────────────────────────────────────
ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_incidents_tenant
  ON incidents (tenant_id, created_at DESC);

-- ── behavior_profiles ─────────────────────────────────────────────────────────
ALTER TABLE behavior_profiles
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

-- entity_id is already the PK (ip address) — make the PK tenant-scoped
-- We can't drop PK on timescaledb hypertable easily, so add a unique index instead
DROP INDEX IF EXISTS behavior_profiles_pkey_tenant;
CREATE UNIQUE INDEX IF NOT EXISTS behavior_profiles_pkey_tenant
  ON behavior_profiles (tenant_id, entity_id);

-- ── firewall_rules ────────────────────────────────────────────────────────────
ALTER TABLE firewall_rules
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_firewall_tenant
  ON firewall_rules (tenant_id, ip_address);

-- ── packets (hypertable) ──────────────────────────────────────────────────────
ALTER TABLE packets
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_packets_tenant
  ON packets (tenant_id, timestamp DESC);

-- ── threat_intel ──────────────────────────────────────────────────────────────
-- Threat intel is shared across tenants (global IOCs) — no tenant_id needed here.
-- Per-tenant private intel can be tagged via the 'tags' JSONB column.

-- ── users — bind each user to a tenant ───────────────────────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_users_tenant
  ON users (tenant_id, username);

-- The 'admin' seed user stays in 'default' tenant as super-admin
-- UPDATE users SET tenant_id = 'default' WHERE username = 'admin';

-- ── tenants registry ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(80)  PRIMARY KEY,
    name        TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    config      JSONB        DEFAULT '{}'
);

INSERT INTO tenants (tenant_id, name) VALUES ('default', 'Default Tenant')
  ON CONFLICT DO NOTHING;

COMMIT;

-- ── Row-level security (optional — enable for strict isolation) ───────────────
-- ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation ON alerts
--   USING (tenant_id = current_setting('app.current_tenant'));
-- (Set via: SET LOCAL app.current_tenant = 'acme'; before queries)
