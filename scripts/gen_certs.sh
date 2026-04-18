#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel AI — mTLS Certificate Generation
#
# Generates a self-signed CA + per-service certs for mutual TLS between
# internal services. Uses SAN (Subject Alternative Name) so Go/Python TLS
# stacks accept them without hostname-mismatch errors.
#
# Output: certs/ directory
#   certs/ca/ca.crt + ca.key
#   certs/<service>/cert.crt + cert.key + chain.crt
#
# Usage:
#   ./scripts/gen_certs.sh
#
# After generation:
#   1. Mount certs/ into containers via docker-compose overlay (see below)
#   2. Set KAFKA_SSL_ENABLED=true if enabling Kafka SASL+TLS
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="$REPO_ROOT/certs"
DAYS=825   # Apple/Chrome max cert validity

# Services that need a TLS certificate
SERVICES=(
  kafka
  postgres
  redis
  chromadb
  api-gateway
  mcp-orchestrator
  rlm-engine
  threat-intel-scraper
)

mkdir -p "$CERTS_DIR/ca"

# ── Root CA ───────────────────────────────────────────────────────────────────
if [[ ! -f "$CERTS_DIR/ca/ca.key" ]]; then
  echo "🔐 Generating root CA..."
  openssl genrsa -out "$CERTS_DIR/ca/ca.key" 4096

  openssl req -new -x509 \
    -key "$CERTS_DIR/ca/ca.key" \
    -out "$CERTS_DIR/ca/ca.crt" \
    -days "$DAYS" \
    -subj "/C=US/ST=Security/O=CyberSentinel AI/CN=CyberSentinel Internal CA" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:TRUE"

  echo "  ✅ CA certificate: $CERTS_DIR/ca/ca.crt"
else
  echo "  ⏭️  CA already exists, skipping"
fi

# ── Per-service certs ─────────────────────────────────────────────────────────
for SVC in "${SERVICES[@]}"; do
  SVC_DIR="$CERTS_DIR/$SVC"
  mkdir -p "$SVC_DIR"

  if [[ -f "$SVC_DIR/cert.crt" ]]; then
    echo "  ⏭️  $SVC cert exists, skipping"
    continue
  fi

  echo "🔑 Generating cert for $SVC ..."

  # Private key
  openssl genrsa -out "$SVC_DIR/cert.key" 2048

  # CSR config with SANs — Kubernetes pods resolve by service name
  cat > "$SVC_DIR/csr.cnf" <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[dn]
C=US
ST=Security
O=CyberSentinel AI
CN=$SVC

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SVC
DNS.2 = $SVC.cybersentinel
DNS.3 = $SVC.cybersentinel.svc.cluster.local
DNS.4 = localhost
IP.1  = 127.0.0.1
EOF

  # CSR
  openssl req -new \
    -key "$SVC_DIR/cert.key" \
    -out "$SVC_DIR/cert.csr" \
    -config "$SVC_DIR/csr.cnf"

  # Sign with CA
  openssl x509 -req \
    -in "$SVC_DIR/cert.csr" \
    -CA "$CERTS_DIR/ca/ca.crt" \
    -CAkey "$CERTS_DIR/ca/ca.key" \
    -CAcreateserial \
    -out "$SVC_DIR/cert.crt" \
    -days "$DAYS" \
    -sha256 \
    -extfile "$SVC_DIR/csr.cnf" \
    -extensions req_ext

  # Full chain (cert + CA) for services that need it
  cat "$SVC_DIR/cert.crt" "$CERTS_DIR/ca/ca.crt" > "$SVC_DIR/chain.crt"

  # Cleanup CSR
  rm -f "$SVC_DIR/cert.csr" "$SVC_DIR/csr.cnf"

  echo "  ✅ $SVC: $SVC_DIR/{cert.crt,cert.key,chain.crt}"
done

# ── Permissions ───────────────────────────────────────────────────────────────
find "$CERTS_DIR" -name "*.key" -exec chmod 600 {} \;
find "$CERTS_DIR" -name "*.crt" -exec chmod 644 {} \;

echo ""
echo "✅ All certificates generated in $CERTS_DIR/"
echo ""
echo "📋 Next steps:"
echo "   1. Add certs/ to .gitignore (already should be there)"
echo "   2. Use docker-compose.tls.yml overlay for service mounts:"
echo "      docker compose -f docker-compose.yml -f docker-compose.tls.yml up"
echo "   3. For Kubernetes, create TLS secrets:"
echo "      ./scripts/k8s/load-certs.sh"
