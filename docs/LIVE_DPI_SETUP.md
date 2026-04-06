# Live DPI Setup Guide

**CyberSentinel AI — Real Packet Capture on Windows**

This guide explains how to enable real-time Deep Packet Inspection (DPI) on Windows using Npcap, and how the `Start Live DPI.bat` launcher works.

---

## What Is Npcap and Why Is It Needed?

**Npcap** is the Windows packet capture driver developed by the Nmap project. It installs a kernel-mode driver that hooks into the network stack at the NDIS (Network Driver Interface Specification) layer, allowing user-space programs like Scapy to read raw network packets from any interface.

Without Npcap, Scapy cannot capture packets on Windows — `socket.socket(socket.AF_PACKET, ...)` is a Linux-only API. Npcap provides the WinPcap-compatible API that Scapy uses on Windows.

### Why Npcap (not WinPcap)?

WinPcap is abandoned (last update 2013) and does not support modern Windows 10/11 features. Npcap is the maintained successor, actively developed by the Nmap project, and supports:
- Windows 10 / 11 (including ARM)
- Loopback capture
- WinPcap compatibility mode (required for Scapy)
- Silent/admin install

---

## Architecture: DPI Sensor on Host, Services in Docker

The DPI sensor (`src/dpi/sensor.py`) runs **directly on the Windows host** — not inside Docker. This is a critical architectural decision:

```
Windows Host
│
├── Npcap (kernel driver) ← captures real packets from Ethernet/Wi-Fi
│
├── sensor.py (Python, runs on host)
│   ├── Scapy AsyncSniffer — captures from physical interface
│   ├── 8 detectors run on each packet
│   └── Publishes to Kafka at localhost:9092
│
└── Docker containers
    ├── kafka (exposed on localhost:9092 ← sensor connects here)
    ├── rlm-engine (processes raw-packets topic)
    ├── mcp-orchestrator (processes threat-alerts topic)
    └── ... (all other services)
```

The DPI sensor MUST run on the host because Docker containers run in a virtual network. Packets captured inside a container would only see container-to-container traffic, not your real Ethernet/Wi-Fi traffic.

---

## Start Live DPI.bat — What It Does

`Start Live DPI.bat` is a one-click launcher in the project root. Double-clicking it runs `scripts\start_live_dpi.ps1` with elevated privileges.

### What the Script Does (Step by Step)

| Step | Action | What Happens If It Fails |
|------|--------|--------------------------|
| 1 | Check Python in PATH | Exits with download link |
| 2 | Check if Npcap is installed | Auto-downloads and silently installs Npcap 1.80 |
| 3 | Install Python packages | `pip install scapy aiokafka redis` |
| 4 | Check Docker is running | Tries to start Docker Desktop automatically; waits up to 60s |
| 5 | Start docker compose stack | Runs `docker compose up -d` if not already running; waits 30s |
| 6 | Read Redis password | Reads `REDIS_PASSWORD` from `.env` file |
| 7 | Show active adapters | Lists all `Up` adapters (excludes vEthernet) |
| 8 | Launch sensor | Sets env vars and runs `python src/dpi/sensor.py` |

### Environment Variables Set by the Script

| Variable | Value | Purpose |
|----------|-------|---------|
| `PYTHONPATH` | project root | So `from src.dpi.sensor import ...` resolves |
| `KAFKA_BOOTSTRAP` | `localhost:9092` | Connects to Docker-exposed Kafka port |
| `REDIS_URL` | `redis://:PASSWORD@localhost:6379` | Connects to Docker-exposed Redis port |
| `CAPTURE_INTERFACE` | `auto` | Sensor will auto-detect the physical NIC |
| `BPF_FILTER` | `ip and not (net 192.168.65.0/24) and not (net 172.16.0.0/12)` | Excludes Docker management and bridge traffic |

---

## Prerequisites Before Using Start Live DPI.bat

### On Your PC

| Requirement | Why Needed | How to Check |
|-------------|------------|--------------|
| Windows 10 / 11 | Npcap supports Win10/11 only | System Settings → About |
| Python 3.11+ | Runs sensor.py | `python --version` in CMD |
| Python added to PATH | Script finds `python` command | `where python` in CMD |
| Docker Desktop running | Kafka must be up | `docker ps` in CMD |
| CyberSentinel stack started | `docker compose up -d` done first | `docker compose ps` |
| `.env` file present | Script reads `REDIS_PASSWORD` | `dir .env` in project root |
| Administrator rights | Npcap capture requires elevated access | Script auto-elevates via UAC |

### Python Packages Required

The script auto-installs these if missing:
- `scapy` — packet capture and parsing
- `aiokafka` — async Kafka producer
- `redis` — Redis client

If you want to install manually:
```bash
pip install scapy aiokafka redis
```

---

## Npcap Installation (Manual)

If the auto-install fails or you prefer manual setup:

1. Download from: `https://npcap.com/dist/npcap-1.80.exe`
2. Run the installer as Administrator
3. During installation, check:
   - **WinPcap API-compatible mode** — required for Scapy
   - **Support loopback traffic capture** — useful for testing
   - Leave other defaults as-is
4. Reboot if prompted (usually not required)

### Verify Npcap is Installed

```powershell
# Check for Npcap DLL
Test-Path "C:\Windows\System32\Npcap"           # Should return True
Test-Path "C:\Windows\System32\wpcap.dll"       # Should return True

# Or check installed programs
Get-Package "Npcap" -ErrorAction SilentlyContinue
```

### Verify Scapy Can See Your Interface

```python
# Run in Python (as Administrator)
from scapy.all import get_if_list, show_interfaces
show_interfaces()  # Should list your Ethernet/Wi-Fi adapters
```

---

## BPF Filter Explained

The sensor uses this Berkeley Packet Filter:

```
ip and not (net 192.168.65.0/24) and not (net 172.16.0.0/12)
```

| Rule | Meaning |
|------|---------|
| `ip` | Only capture IPv4 packets (skip ARP, IPv6, etc.) |
| `not net 192.168.65.0/24` | Exclude Docker Desktop management subnet |
| `not net 172.16.0.0/12` | Exclude Docker bridge networks (172.16–31.x.x) |

This ensures the sensor only captures **real external and LAN traffic** — not container-to-container communication.

**Customise for your environment:**
```bash
# If your LAN is 10.0.0.0/8 and you want to monitor it:
BPF_FILTER="ip and not (net 192.168.65.0/24) and not (net 172.16.0.0/12)"

# If you want to monitor specific ports only:
BPF_FILTER="ip and (port 80 or port 443 or port 22)"

# If you want to monitor a specific host:
BPF_FILTER="ip and host 192.168.1.100"
```

---

## Interface Auto-Detection

`CAPTURE_INTERFACE=auto` triggers auto-detection in `sensor.py`:

```python
def _detect_capture_interface() -> str:
    """Auto-detect the best physical network interface."""
    # Prefers interfaces matching: Ethernet, Wi-Fi, eth0, en0
    # Excludes: loopback, vEthernet (Docker), Hyper-V virtual switches
```

The sensor will:
1. List all available Scapy-visible interfaces
2. Score them by name pattern (Ethernet > Wi-Fi > eth0 > en0)
3. Exclude virtual/loopback interfaces
4. Return the highest-scoring interface

**To use a specific interface:**
```powershell
# List available interfaces first
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Then set it in the script or .env:
$env:CAPTURE_INTERFACE = "Ethernet"    # Use your actual interface name
```

---

## How Real DPI Integrates with the Dashboard

When the Live DPI sensor is running:

1. **Packets tab / Hosts tab** — shows real `observation_count`, `avg_bytes_per_min`, `avg_entropy`, `anomaly_score` for your network hosts
2. **Alerts tab** — shows real detection events from your actual network traffic
3. **Incidents** — AI investigates real threats from your network
4. **Block Recommendations** — AI flags real IPs from your network for analyst review

The dashboard simultaneously shows both **real DPI data** and **simulator data** — they are tagged with `source: "dpi"` and `source: "simulator"` respectively in the database.

---

## Dual Mode: DPI + Simulator Running Together

You can run both the Live DPI sensor and the Traffic Simulator simultaneously:

```
Real network traffic → DPI Sensor (on host) → raw-packets → RLM → AI
Synthetic scenarios  → Simulator (in Docker) → raw-packets → RLM → AI
```

Both publish to the same `raw-packets` Kafka topic. The RLM engine processes all messages regardless of source. The MCP Orchestrator tags alerts with their source:
- `source: "dpi"` for DPI-detected anomalies
- `source: "simulator"` for simulated scenarios

This lets you **train analysts on simulated threats while monitoring real traffic simultaneously**.

To pause simulator investigations (save LLM quota) while keeping DPI investigations active:
- Dashboard → RESPONSE tab → AI Investigation controls → Pause Simulator only

---

## Troubleshooting

### "No interfaces found" / "Permission denied"

The script must run as Administrator. The bat file auto-elevates via UAC. If it doesn't:
```powershell
# Right-click Start Live DPI.bat → Run as administrator
# OR open PowerShell as Administrator and run:
powershell -ExecutionPolicy Bypass -File scripts\start_live_dpi.ps1
```

### "Kafka connection refused"

The Docker stack must be running before starting the sensor:
```bash
docker compose up -d
docker compose ps  # verify kafka is healthy
```

### "Scapy: No match for interface"

Your physical adapter name may be unusual. List available interfaces:
```python
python -c "from scapy.all import conf; print(conf.ifaces)"
```
Then set `CAPTURE_INTERFACE` to the exact interface name in the PowerShell script.

### Npcap auto-download fails (corporate network)

Download manually from `https://npcap.com` and install with WinPcap-compatible mode checked.

### Docker doesn't auto-start

Start Docker Desktop manually from the Start menu, wait for the whale icon in the system tray to show "Docker Desktop is running", then re-run the bat file.

---

## Security Note

Running packet capture gives the sensor visibility into **all traffic** on your network interface — including potentially sensitive data (passwords, tokens). The sensor only captures **metadata** (IPs, ports, protocols, entropy) — not payload content. Raw payloads are never stored in any database table.

The BPF filter and Shannon entropy analysis run entirely locally. No raw packet data is sent to any external service. The only external API calls are:
- AbuseIPDB (for IP reputation lookups — destination IPs only, not payload)
- Your configured LLM provider (for investigation analysis — anonymised alert metadata only)

---

*Live DPI Setup — CyberSentinel AI v1.2 — 2026*
