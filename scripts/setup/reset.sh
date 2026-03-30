#!/bin/bash
# Full reset — stops all containers and removes all volumes
# WARNING: This deletes ALL data including DB, ChromaDB, Redis
echo "⚠️  WARNING: This will DELETE all CyberSentinel data and volumes!"
read -p "Type 'RESET' to confirm: " confirm
if [ "$confirm" = "RESET" ]; then
  docker compose -f docker-compose.yml -f n8n/docker-compose.n8n.yml down -v
  echo "✅ Reset complete. Run install.sh to start fresh."
else
  echo "Cancelled."
fi
