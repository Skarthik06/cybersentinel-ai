#!/bin/bash
# Add n8n SOAR layer on top of running core platform
set -e
echo "🚀 Starting n8n SOAR layer..."
docker compose -f docker-compose.yml -f n8n/docker-compose.n8n.yml up -d

echo "⏱  Waiting 30s for n8n to initialise..."
sleep 30

HEALTH=$(curl -s http://localhost:5678/healthz 2>/dev/null || echo "unavailable")
if echo "$HEALTH" | grep -q "ok"; then
  echo "✅ n8n is running at http://localhost:5678"
  echo "   Login: admin / cybersentinel2025"
  echo ""
  echo "📋 Import workflows from n8n/workflows/ via the n8n UI:"
  echo "   Workflows → + New → ⋮ → Import from file"
else
  echo "⚠️  n8n not ready yet. Check: docker compose logs cybersentinel-n8n"
fi
