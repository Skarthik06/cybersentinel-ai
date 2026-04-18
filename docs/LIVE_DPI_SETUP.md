# Live DPI Setup Guide

**CyberSentinel AI v1.3.0 — Running the DPI Sensor with Real Network Traffic**

This guide covers both methods for capturing live network traffic. The traffic simulator handles all testing and demo scenarios — live DPI is only needed when you want to analyse *real* packets from your physical network.

---

## Two DPI Methods

| Method | Platform | Requirement | How |
|--------|---------|------------|-----|
| **Method A — Docker Container** | Linux, macOS, WSL2 with network access | Docker with host network | `dpi-sensor` service in `docker-compose.yml` |
| **Method B — Windows Native** | Windows 10/11 host | Npcap installed | `scripts/start_live_dpi.ps1` |

---

## Method A — Docker Container (Linux / macOS / WSL2)

The `dpi-sensor` service is already defined in `docker-compose.yml`. It runs in `network_mode: host`, giving the container direct access to the host's network interfaces.

### How it works

```
Docker Container (dpi-sensor)
  network_mode: host
  cap_add: [NET_ADMIN, NET_RAW]
    └─> Scapy AsyncSniffer
          └─> Reads packets from host NIC via libpcap
                └─> Publishes PacketEvents to kafka:29092
```

### Enable the DPI sensor

The sensor starts automatically with `docker compose up -d`. It will capture real traffic by default.

Check which interface it is using:

```bash
docker compose logs dpi-sensor | grep -i "interface\|sniff\|started"
```

The sensor uses `CAPTURE_INTERFACE=auto` — it automatically selects the primary non-loopback physical interface.

### BPF Filter

The default BPF filter in `docker-compose.yml` excludes Docker-internal virtual traffic:

```
ip and not (net 192.168.65.0/24)
    and not (net 172.17.0.0/16 or net 172.18.0.0/16 or net 172.19.0.0/16
             or net 172.20.0.0/16 or net 172.21.0.0/16)
```

This keeps real host traffic while filtering out Docker bridge network noise.

To customize, edit the `BPF_FILTER` environment variable in `docker-compose.yml` under the `dpi-sensor` service:

```yaml
dpi-sensor:
  environment:
    CAPTURE_INTERFACE: "auto"    # or specify: "eth0", "ens3", "wlan0"
    BPF_FILTER: "ip or ip6"
```

### Windows Limitation with Docker DPI

On Windows, Docker Desktop runs inside a HyperV Linux VM. The `dpi-sensor` container captures traffic on the VM's virtual network interface — not the Windows host's physical NIC. This means:

- Traffic from Windows applications (browser, games, etc.) may not be visible
- Use Method B (Windows Native) if you need to capture physical host NIC traffic on Windows

---

## Method B — Windows Native (Npcap)

### Prerequisites

**Install Npcap:**
1. Download from: https://npcap.com/#download
2. Run the installer as Administrator
3. Select: **Install Npcap in WinPcap API-compatible Mode**
4. Reboot if prompted

### Running the Windows DPI Sensor

```powershell
# Right-click PowerShell → Run as Administrator
# OR: the script self-elevates if not already elevated

.\scripts\start_live_dpi.ps1
```

The script will:
1. Check if Docker is running
2. Install Python dependencies if needed (`scapy`, `kafka-python`)
3. List available network interfaces
4. Start the DPI sensor pointing to `localhost:9092` (Kafka on host port)

### Manual Interface Selection

If the auto-detection picks the wrong interface, specify it explicitly:

```powershell
# List interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Set interface before running
$env:CAPTURE_INTERFACE = "Ethernet"   # or "Wi-Fi", "Local Area Connection"
.\scripts\start_live_dpi.ps1
```

### Verifying DPI is Working

After starting either method, verify packets are flowing:

```bash
# Check DPI sensor logs (Method A)
docker compose logs -f dpi-sensor

# Check Kafka is receiving raw-packets
docker exec -it cybersentinel-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic raw-packets \
  --from-beginning \
  --max-messages 5
```

You should see JSON-formatted `PacketEvent` objects within a few seconds of any network activity.

---

## DPI Sensor Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CAPTURE_INTERFACE` | `auto` | Interface name or `auto` for automatic selection |
| `BPF_FILTER` | `ip and not (Docker nets)` | Berkeley Packet Filter expression |
| `KAFKA_BOOTSTRAP` | `localhost:9092` (native) / `kafka:29092` (Docker) | Kafka connection |
| `REDIS_URL` | from `.env` | Redis for deduplication cache |

### IPv6 Support

IPv6 is supported. The sensor parses both `IPv4` and `IPv6` headers via Scapy. To include IPv6 in the BPF filter:

```yaml
# docker-compose.yml
BPF_FILTER: "ip or ip6"
```

### PII Masking

All packets pass through `_mask_pii()` before being published to Kafka. This runs automatically — no configuration required. Redacted fields:
- Email addresses in DNS queries, HTTP URIs, User-Agent headers
- Credential parameters (`password=`, `token=`, `api_key=`, `secret=`, `authorization=`)

---

## DPI vs Simulator — Which to Use

| Scenario | Use |
|----------|-----|
| Demo / testing / development | Traffic Simulator (always running, no setup required) |
| Academic presentation | Traffic Simulator (controlled, repeatable scenarios) |
| Real threat monitoring | Live DPI (Method A for Linux/macOS, Method B for Windows) |
| Validating the full pipeline | Both simultaneously |

The simulator and DPI sensor write to the **same** `raw-packets` Kafka topic. They can run simultaneously — the RLM engine processes both streams and builds behavioral profiles for all seen IPs.

---

## Troubleshooting

### "No packets captured"

```bash
# Check the interface name the container sees
docker compose exec dpi-sensor ip link show

# Use a permissive filter to test
# Edit docker-compose.yml: BPF_FILTER: "ip"
docker compose up -d dpi-sensor
```

### "Permission denied" (Method A)

The container requires `NET_ADMIN` and `NET_RAW` capabilities. Verify these are set in `docker-compose.yml`:

```yaml
dpi-sensor:
  cap_add:
    - NET_ADMIN
    - NET_RAW
  network_mode: host
```

### "Npcap not found" (Method B)

```powershell
# Verify Npcap installation
python -c "from scapy.all import get_if_list; print('Npcap OK')"
# If this fails, reinstall Npcap from npcap.com
```

### "kafka bootstrap server not reachable" (Method B)

Method B connects to `localhost:9092` — the Docker Compose port-mapped Kafka. Ensure `docker compose up -d` is running first:

```powershell
docker compose ps
# Should show: cybersentinel-kafka ... Up ... 0.0.0.0:9092->9092/tcp
```

---

*Live DPI Setup Guide — CyberSentinel AI v1.3.0 — 2026*
