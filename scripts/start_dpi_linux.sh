#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberSentinel AI — Linux DPI Sensor Startup
#
# Runs the DPI sensor directly on Linux without Docker Desktop.
# Required for bare-metal deployments, VMs, and Kubernetes nodes.
#
# Usage (as root or with sudo — required for raw packet capture):
#   sudo ./scripts/start_dpi_linux.sh
#
# Environment: set vars in .env or export before running.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "❌ DPI sensor requires root (raw socket access). Re-run with sudo."
  exit 1
fi

# ── Dependency check ──────────────────────────────────────────────────────────
echo "🔍 Checking system dependencies..."

check_dep() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Missing: $1. Install with: $2"
    exit 1
  fi
  echo "  ✅ $1"
}

check_dep python3       "apt-get install python3"
check_dep pip3          "apt-get install python3-pip"

# libpcap must be present for Scapy
if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
  echo "❌ libpcap not found. Install with: apt-get install libpcap-dev"
  exit 1
fi
echo "  ✅ libpcap"

# ── Python venv ───────────────────────────────────────────────────────────────
VENV_DIR="$REPO_ROOT/.venv-dpi"
if [[ ! -d "$VENV_DIR" ]]; then
  echo "🐍 Creating Python venv at $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

echo "📦 Installing DPI dependencies..."
pip install --quiet --upgrade pip
pip install --quiet \
  scapy==2.5.0 \
  aiokafka==0.10.0 \
  "redis[asyncio]==5.0.1" \
  asyncpg==0.29.0

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="$REPO_ROOT/.env"
if [[ -f "$ENV_FILE" ]]; then
  echo "📋 Loading environment from $ENV_FILE"
  set -o allexport
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +o allexport
else
  echo "⚠️  No .env file found at $ENV_FILE — using existing environment"
fi

# ── Interface selection ───────────────────────────────────────────────────────
if [[ "${CAPTURE_INTERFACE:-auto}" == "auto" ]]; then
  # Pick first non-loopback, non-docker interface
  IFACE=$(ip link show \
    | awk -F': ' '/^[0-9]+:/{iface=$2} /state UP/ && iface !~ /^(lo|docker|br-|veth|virbr)/{print iface; exit}')
  if [[ -z "$IFACE" ]]; then
    echo "❌ Could not auto-detect network interface. Set CAPTURE_INTERFACE= in .env"
    exit 1
  fi
  export CAPTURE_INTERFACE="$IFACE"
  echo "🔌 Auto-selected interface: $CAPTURE_INTERFACE"
else
  echo "🔌 Using interface: $CAPTURE_INTERFACE"
fi

# ── Capability grant (alternative to running full root) ───────────────────────
# If running as non-root, grant python3 the CAP_NET_RAW capability.
# This is safer than running as root — drops all other privileges.
if [[ $EUID -ne 0 ]]; then
  PYTHON_BIN=$(command -v python3)
  setcap cap_net_raw+eip "$PYTHON_BIN" 2>/dev/null || {
    echo "⚠️  Could not setcap — running with current privileges"
  }
fi

# ── Start sensor ──────────────────────────────────────────────────────────────
echo ""
echo "🚀 Starting CyberSentinel DPI sensor..."
echo "   Interface:  $CAPTURE_INTERFACE"
echo "   BPF filter: ${BPF_FILTER:-ip or ip6}"
echo "   Kafka:      ${KAFKA_BOOTSTRAP:-kafka:29092}"
echo ""

cd "$REPO_ROOT"
export PYTHONPATH="$REPO_ROOT"

exec python3 -u src/dpi/sensor.py
