#!/bin/bash
# ─────────────────────────────────────────────────────────────
# CyberSentinel AI — One-Shot Install Script
# Run this after placing all project files in place.
# Usage: bash scripts/setup/install.sh
# ─────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║       CyberSentinel AI — Installer        ║"
echo "  ║   Autonomous Threat Detection Platform    ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Check prerequisites ────────────────────────────────────
echo -e "${BLUE}[1/6] Checking prerequisites...${NC}"

command -v docker >/dev/null 2>&1 || { echo -e "${RED}❌ Docker not found. Install Docker Desktop first.${NC}"; exit 1; }
echo -e "${GREEN}  ✅ Docker found: $(docker --version)${NC}"

docker compose version >/dev/null 2>&1 || { echo -e "${RED}❌ Docker Compose v2 not found.${NC}"; exit 1; }
echo -e "${GREEN}  ✅ Docker Compose: $(docker compose version)${NC}"

# ── 2. Check .env ────────────────────────────────────────────
echo -e "${BLUE}[2/6] Checking .env configuration...${NC}"
if [ ! -f .env ]; then
  cp .env.example .env
  echo -e "${YELLOW}  ⚠️  Created .env from .env.example"
  echo -e "  ⚠️  IMPORTANT: Set ANTHROPIC_API_KEY in .env before continuing!${NC}"
  echo ""
  read -p "Press Enter after you've edited .env to continue..."
fi

if grep -q "sk-ant-your-key-here" .env; then
  echo -e "${RED}❌ ANTHROPIC_API_KEY is still the placeholder value."
  echo "   Edit .env and set your real API key first.${NC}"
  exit 1
fi
echo -e "${GREEN}  ✅ .env configured${NC}"

# ── 3. Generate secrets if using defaults ────────────────────
echo -e "${BLUE}[3/6] Checking secrets...${NC}"
if grep -q "change_me" .env; then
  echo -e "${YELLOW}  ⚠️  Generating secure random secrets for default values...${NC}"
  POSTGRES_PASS=$(openssl rand -hex 16)
  REDIS_PASS=$(openssl rand -hex 16)
  JWT_SECRET=$(openssl rand -hex 32)
  CHROMA_TOKEN=$(openssl rand -hex 16)
  N8N_KEY=$(openssl rand -hex 16)

  sed -i "s/sentinel_secure_2025_change_me/$POSTGRES_PASS/g" .env
  sed -i "s/redis_secure_2025_change_me/$REDIS_PASS/g" .env
  sed -i "s/your-jwt-secret-minimum-32-chars-change-me/$JWT_SECRET/g" .env
  sed -i "s/cybersentinel-token-2025-change-me/$CHROMA_TOKEN/g" .env
  echo -e "${GREEN}  ✅ Secrets generated and written to .env${NC}"
fi

# ── 4. Pull Docker images ────────────────────────────────────
echo -e "${BLUE}[4/6] Pulling Docker images (~3 GB, please wait)...${NC}"
docker compose pull

# ── 5. Start core platform ───────────────────────────────────
echo -e "${BLUE}[5/6] Starting CyberSentinel AI core platform...${NC}"
docker compose up -d
echo -e "${YELLOW}  Waiting 30 seconds for services to initialise...${NC}"
sleep 30

# ── 6. Health check ──────────────────────────────────────────
echo -e "${BLUE}[6/6] Running health check...${NC}"
HEALTH=$(curl -s http://localhost:8080/health 2>/dev/null || echo '{"status":"unavailable"}')
if echo "$HEALTH" | grep -q '"status":"healthy"'; then
  echo -e "${GREEN}  ✅ API is healthy!${NC}"
else
  echo -e "${YELLOW}  ⚠️  API not ready yet. Check: docker compose logs cybersentinel-api${NC}"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         🛡️  CyberSentinel AI is RUNNING!              ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  API Docs:   http://localhost:8080/docs               ║${NC}"
echo -e "${GREEN}║  Grafana:    http://localhost:3001                    ║${NC}"
echo -e "${GREEN}║  Prometheus: http://localhost:9090                    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Next: Add n8n SOAR layer:${NC}"
echo "  docker compose -f docker-compose.yml -f n8n/docker-compose.n8n.yml up -d"
echo "  Then open http://localhost:5678 and import the 5 workflows from n8n/workflows/"
