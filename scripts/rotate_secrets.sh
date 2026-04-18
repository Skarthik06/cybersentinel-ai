#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel AI — Secret Rotation
#
# Generates new cryptographically random secrets for all platform credentials
# and writes them to .env. Backs up the current .env first.
#
# After rotation:
#   1. Run ./scripts/db/reset_admin_password.sh to sync DB user passwords
#   2. Restart all services: docker compose down && docker compose up -d
#   3. If using Kubernetes: kubectl rollout restart deployment -n cybersentinel
#
# Usage:
#   ./scripts/rotate_secrets.sh [--dry-run]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
DRY_RUN=false

for arg in "$@"; do
  [[ "$arg" == "--dry-run" ]] && DRY_RUN=true
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "❌ No .env file found at $ENV_FILE"
  echo "   Copy .env.example to .env first, then re-run."
  exit 1
fi

# ── Backup ────────────────────────────────────────────────────────────────────
BACKUP="$ENV_FILE.bak.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$BACKUP"
echo "📦 Backed up .env → $BACKUP"

# ── Generate secrets ──────────────────────────────────────────────────────────
gen_secret() {
  local length="${1:-32}"
  # Use /dev/urandom, convert to base64url (safe for all env contexts)
  head -c "$((length * 3 / 4 + 1))" /dev/urandom \
    | base64 \
    | tr '+/' '-_' \
    | tr -d '=' \
    | head -c "$length"
}

NEW_POSTGRES_PASSWORD=$(gen_secret 32)
NEW_REDIS_PASSWORD=$(gen_secret 32)
NEW_CHROMA_TOKEN=$(gen_secret 40)
NEW_JWT_SECRET=$(gen_secret 64)
NEW_GRAFANA_PASSWORD=$(gen_secret 24)

echo ""
echo "🔐 New secrets:"
echo "   POSTGRES_PASSWORD : ${NEW_POSTGRES_PASSWORD:0:8}...(truncated)"
echo "   REDIS_PASSWORD    : ${NEW_REDIS_PASSWORD:0:8}...(truncated)"
echo "   CHROMA_TOKEN      : ${NEW_CHROMA_TOKEN:0:8}...(truncated)"
echo "   JWT_SECRET        : ${NEW_JWT_SECRET:0:8}...(truncated)"
echo "   GRAFANA_PASSWORD  : ${NEW_GRAFANA_PASSWORD:0:8}...(truncated)"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "🔍 Dry run — no changes written."
  exit 0
fi

# ── Update .env in place ──────────────────────────────────────────────────────
update_env_var() {
  local key="$1"
  local value="$2"
  # Replace key=<anything> line; handles quoted and unquoted values
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

update_env_var "POSTGRES_PASSWORD" "$NEW_POSTGRES_PASSWORD"
update_env_var "REDIS_PASSWORD"    "$NEW_REDIS_PASSWORD"
update_env_var "CHROMA_TOKEN"      "$NEW_CHROMA_TOKEN"
update_env_var "JWT_SECRET"        "$NEW_JWT_SECRET"
update_env_var "GRAFANA_PASSWORD"  "$NEW_GRAFANA_PASSWORD"

echo "✅ .env updated with new secrets"

# ── Update Kubernetes secrets if cluster is running ───────────────────────────
if kubectl get namespace cybersentinel &>/dev/null 2>&1; then
  echo ""
  echo "🔄 Updating Kubernetes secrets..."

  kubectl create secret generic cybersentinel-secrets \
    --namespace cybersentinel \
    --from-literal=POSTGRES_PASSWORD="$NEW_POSTGRES_PASSWORD" \
    --from-literal=REDIS_PASSWORD="$NEW_REDIS_PASSWORD" \
    --from-literal=CHROMA_TOKEN="$NEW_CHROMA_TOKEN" \
    --from-literal=JWT_SECRET="$NEW_JWT_SECRET" \
    --from-literal=GRAFANA_PASSWORD="$NEW_GRAFANA_PASSWORD" \
    --save-config \
    --dry-run=client \
    -o yaml \
    | kubectl apply -f -

  echo "  ✅ Kubernetes secret updated"
  echo ""
  echo "🔄 Restarting deployments to pick up new secrets..."
  kubectl rollout restart deployment \
    api-gateway mcp-orchestrator rlm-engine \
    threat-intel-scraper traffic-simulator \
    grafana chromadb \
    -n cybersentinel 2>/dev/null || true
else
  echo "⚠️  Kubernetes namespace 'cybersentinel' not found — skipping k8s update"
fi

# ── Remind about DB password change ──────────────────────────────────────────
echo ""
echo "⚠️  IMPORTANT: The PostgreSQL role password must be updated separately:"
echo "   docker exec -it cybersentinel-postgres psql -U sentinel -d cybersentinel \\"
echo "     -c \"ALTER USER sentinel PASSWORD '${NEW_POSTGRES_PASSWORD}'\""
echo ""
echo "   Or for Kubernetes:"
echo "   kubectl exec -n cybersentinel deploy/postgres -- \\"
echo "     psql -U sentinel -d cybersentinel \\"
echo "     -c \"ALTER USER sentinel PASSWORD '${NEW_POSTGRES_PASSWORD}'\""
echo ""
echo "✅ Secret rotation complete. Restart services to apply."
