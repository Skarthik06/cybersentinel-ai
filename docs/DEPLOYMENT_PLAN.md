# Deployment Plan

**CyberSentinel AI — From Local Machine to Anywhere in the World**

> Read this fully before implementing anything. Each phase builds on the previous one. You can stop at any phase — each one gives you a working result on its own.

---

## Table of Contents

1. [The Problem — Why Deployment is Hard for This Project](#1-the-problem)
2. [The Strategy — Two Tracks](#2-the-strategy)
3. [Phase 1 — One-Click Local Start Script](#3-phase-1--one-click-local-start-script)
4. [Phase 2 — ngrok Permanent Demo URL](#4-phase-2--ngrok-permanent-demo-url)
5. [Phase 3 — Oracle Cloud Free Permanent Server](#5-phase-3--oracle-cloud-free-permanent-server)
6. [Phase 4 — Custom Domain + HTTPS](#6-phase-4--custom-domain--https)
7. [Decision Guide — Which Phases Do You Need?](#7-decision-guide)
8. [All Files That Will Be Created](#8-all-files-that-will-be-created)
9. [Troubleshooting Reference](#9-troubleshooting-reference)

---

## 1. The Problem

### Why You Cannot Just Deploy This on Any Free Platform

Most free cloud platforms (Render, Railway, Fly.io) give you 256 MB to 512 MB of RAM per service. Your project needs approximately 3.5 GB of RAM to run all services together:

```
Service                     RAM Required
─────────────────────────────────────────
Kafka + Zookeeper           ~1,000 MB
PostgreSQL TimescaleDB        ~512 MB
Redis                         ~128 MB
ChromaDB + embedding model    ~600 MB
MCP Orchestrator              ~256 MB
API Gateway (FastAPI)         ~256 MB
Frontend (React/Vite)         ~128 MB
Traffic Simulator             ~128 MB
Prometheus + Grafana          ~512 MB
─────────────────────────────────────────
TOTAL                       ~3,520 MB
```

This means platforms like Render, Railway, and Fly.io cannot run your full stack on their free tiers. They would work for 1 or 2 services at a time — not the complete platform.

### The Only Two Viable Free Options

| Option | How | RAM Available | Cost | Always On? |
|--------|-----|--------------|------|-----------|
| **ngrok** | Tunnel from your PC to internet | Your PC's RAM | Free | No — PC must be on |
| **Oracle Cloud** | Free ARM virtual machine | 24 GB | Free forever | Yes — 24/7 |

---

## 2. The Strategy

### Two Tracks Working Together

```
Track A: ngrok (for demos and interviews)
─────────────────────────────────────────
Your PC → Docker running → ngrok tunnel → https://yourname.ngrok.io
                                                    ↑
                              Anyone visits this URL and sees your live dashboard

Track B: Oracle Cloud (for permanent portfolio access)
──────────────────────────────────────────────────────
Oracle Free VM → Docker running → http://YOUR.VM.IP:5173
                                            ↑
                              Accessible 24/7 without your PC
```

### What Each Track Gives You

**Track A (ngrok):**
- Works today, right now
- Your full project runs exactly as designed
- Share a URL in an interview and they see your live dashboard
- No server, no cost, no credit card
- Limitation: your PC must be on and running

**Track B (Oracle Cloud):**
- Project runs 24/7 even when your PC is off
- Permanent URL you can put on your CV and GitHub README
- Free forever (Oracle's Always Free tier never expires)
- Limitation: requires ~2 hours of setup and an Oracle account

---

## 3. Phase 1 — One-Click Local Start Script

### What This Phase Does

Right now, to start your project you would need to:
1. Open terminal
2. Navigate to the folder
3. Type `docker-compose up -d`
4. Wait and check logs
5. Open browser manually

After this phase, you do this instead:
```bash
./start.sh
```
That single command does everything — starts Docker, waits for services to be healthy, opens the dashboard in your browser, and prints the ngrok URL if ngrok is configured.

### Files Created in This Phase

**`start.sh`** — The main one-click start script

```bash
#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# CyberSentinel AI — One-Click Start Script
# Usage: ./start.sh
# ─────────────────────────────────────────────────────────────────

set -e  # Stop if any command fails

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         CYBERSENTINEL AI — STARTING          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Step 1: Check Docker is running
echo "▶ Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    echo "✗ Docker is not running. Please start Docker Desktop first."
    exit 1
fi
echo "✓ Docker is running"

# Step 2: Pull latest code from GitHub
echo ""
echo "▶ Pulling latest code from GitHub..."
git pull origin main
echo "✓ Code is up to date"

# Step 3: Load environment variables
if [ ! -f .env ]; then
    echo "✗ .env file not found. Copy .env.example to .env and fill in your values."
    exit 1
fi
echo "✓ .env file found"

# Step 4: Start all services
echo ""
echo "▶ Starting all services..."
docker-compose up -d --build
echo "✓ All services started"

# Step 5: Wait for API to be healthy
echo ""
echo "▶ Waiting for API to be ready..."
MAX_WAIT=60
WAITED=0
until curl -s http://localhost:8080/health > /dev/null 2>&1; do
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo "✗ API did not start within ${MAX_WAIT}s. Check logs: docker-compose logs api-gateway"
        exit 1
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo "  waiting... (${WAITED}s)"
done
echo "✓ API is healthy"

# Step 6: Print access URLs
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║              PLATFORM IS READY               ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Dashboard  →  http://localhost:5173         ║"
echo "║  API        →  http://localhost:8080         ║"
echo "║  API Docs   →  http://localhost:8080/docs    ║"
echo "║  Grafana    →  http://localhost:3001         ║"
echo "║  n8n        →  http://localhost:5678         ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Login: admin / (your password in .env)      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Step 7: Start ngrok if installed
if command -v ngrok > /dev/null 2>&1; then
    echo "▶ Starting ngrok tunnel..."
    ngrok http 5173 &
    sleep 3
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"[^"]*' | head -1 | cut -d'"' -f4)
    if [ -n "$NGROK_URL" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════╗"
        echo "║           PUBLIC ACCESS VIA NGROK            ║"
        echo "╠══════════════════════════════════════════════╣"
        echo "║  Share this URL with anyone:                 ║"
        echo "║  $NGROK_URL"
        echo "╚══════════════════════════════════════════════╝"
    fi
else
    echo "ℹ ngrok not installed — dashboard accessible on local network only"
    echo "  Install ngrok from https://ngrok.com to get a shareable public URL"
fi

echo ""
echo "To stop everything: ./stop.sh"
echo ""
```

---

**`stop.sh`** — The one-click stop script

```bash
#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# CyberSentinel AI — One-Click Stop Script
# Usage: ./stop.sh
# ─────────────────────────────────────────────────────────────────

echo ""
echo "▶ Stopping all CyberSentinel AI services..."
docker-compose down
echo "✓ All services stopped"
echo ""
echo "Your data is preserved in Docker volumes."
echo "Run ./start.sh to start again."
echo ""
```

### How to Install This Phase

```bash
# In your project folder:
# 1. Create start.sh and stop.sh (content above)
# 2. Make them executable:
chmod +x start.sh
chmod +x stop.sh

# 3. Run it:
./start.sh
```

### What You Get After Phase 1

- `./start.sh` — starts everything, waits for health, prints URLs
- `./stop.sh` — stops everything cleanly
- Works on your PC
- If ngrok is installed, prints the public URL automatically

---

## 4. Phase 2 — ngrok Permanent Demo URL

### What is ngrok?

ngrok is a tool that creates a secure tunnel between your local computer and the internet. Without it, your project is only accessible on your home network. With it, anyone in the world can visit a URL and see your live running dashboard — even though the project is running on your PC.

```
Without ngrok:
  Your PC:5173  →  Only YOU can see it (localhost)

With ngrok:
  Your PC:5173  →  ngrok server  →  https://cybersentinel.ngrok.io
                                              ↑
                                   ANYONE can see this URL
```

### Free vs Paid ngrok

| Feature | Free | Paid ($8/month) |
|---------|------|----------------|
| Tunnels | 1 at a time | Multiple |
| URL | Random (changes every restart) | Fixed permanent domain |
| Bandwidth | Limited | Higher |
| Works for demos | ✅ Yes | ✅ Yes |

For your use case, the **free tier is enough**. The only limitation is the URL changes every time you restart ngrok. The paid tier gives you a permanent URL like `https://cybersentinel.ngrok.io` that never changes.

### Step-by-Step Setup

**Step 1: Create a free ngrok account**
- Go to `https://ngrok.com`
- Sign up with GitHub (easiest)
- No credit card needed

**Step 2: Download and install ngrok**
- Download for Windows from the ngrok dashboard
- Extract the `ngrok.exe` file
- Move it to a folder in your system PATH (e.g. `C:\Windows\System32\`) OR keep it in your project folder

**Step 3: Connect your account**
```bash
# Copy your authtoken from the ngrok dashboard
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE
```

**Step 4: Get a free static domain (one per account)**
- In the ngrok dashboard → "Domains" → "New Domain"
- You get one free static domain like `your-name-random.ngrok-free.app`
- This URL never changes — safe to put on your CV

**Step 5: Update `start.sh` to use your static domain**

In `start.sh`, replace the ngrok line:
```bash
# Change from:
ngrok http 5173 &

# Change to (using your static domain):
ngrok http --domain=your-name-random.ngrok-free.app 5173 &
```

### What You Get After Phase 2

- A permanent public URL like `https://cybersentinel-abc123.ngrok-free.app`
- `./start.sh` automatically starts ngrok and prints this URL
- Anyone visits this URL and sees your live SOC dashboard
- Works from any network, any country
- Free forever

---

## 5. Phase 3 — Oracle Cloud Free Permanent Server

### What is Oracle Cloud Always Free?

Oracle Cloud offers a **genuinely free tier that never expires**. Most cloud providers give free tiers for 12 months then charge. Oracle's Always Free resources are permanent.

The key resource for your project:

```
Oracle Always Free — ARM Ampere A1 VM
─────────────────────────────────────
CPUs:     4 (ARM architecture)
RAM:      24 GB
Storage:  200 GB
Network:  10 TB/month
Cost:     $0.00 forever
```

24 GB RAM is more than enough to run your entire stack.

### What You Need

- An Oracle Cloud account (free)
- A credit card (for identity verification only — Oracle will NOT charge you if you stay on free tier resources)
- About 2–3 hours for setup

### Architecture on Oracle Cloud

```
Internet
    │
    ▼
Oracle Cloud VM (24 GB RAM, free)
    │
    ├── Docker Compose
    │       ├── Frontend      → port 5173
    │       ├── API Gateway   → port 8080
    │       ├── MCP           → port 3000
    │       ├── Kafka         → internal
    │       ├── PostgreSQL    → internal
    │       ├── Redis         → internal
    │       ├── ChromaDB      → internal
    │       ├── Grafana       → port 3001
    │       └── Simulator     → internal
    │
    └── Nginx (reverse proxy)
            ├── / → frontend:5173
            └── /api → api-gateway:8080
```

Only the frontend, API, and Grafana are exposed to the internet. All other services (Kafka, DB, Redis, ChromaDB) stay internal — not reachable from outside.

### Step-by-Step Oracle Cloud Setup

#### Part A — Create Oracle Account

1. Go to `https://cloud.oracle.com`
2. Click "Start for free"
3. Fill in your details — use a real email and phone number
4. Enter credit card for identity verification
5. Select your home region (choose the closest one — you cannot change this later)
6. Account creation takes 10–15 minutes

#### Part B — Create the Free VM

1. In Oracle Cloud console → "Compute" → "Instances" → "Create Instance"
2. **Name:** `cybersentinel-vm`
3. **Image:** Oracle Linux 8 or Ubuntu 22.04 (Ubuntu is easier)
4. **Shape:** Click "Change Shape" → "Ampere" → `VM.Standard.A1.Flex`
   - Set OCPUs: **4**
   - Set RAM: **24 GB**
   - This combination is within the always-free limit
5. **SSH Keys:** Upload your public key OR have Oracle generate one for you (download the private key)
6. **Storage:** 200 GB (free)
7. Click "Create"
8. Wait 3–5 minutes for the VM to start
9. Copy the **Public IP Address** shown

#### Part C — Open Firewall Ports

By default Oracle blocks all ports. You need to open them:

1. Go to your VM → "Subnet" → "Security List" → "Add Ingress Rules"
2. Add these rules:

| Source CIDR | Protocol | Port | Purpose |
|------------|----------|------|---------|
| 0.0.0.0/0 | TCP | 22 | SSH (already open) |
| 0.0.0.0/0 | TCP | 80 | HTTP |
| 0.0.0.0/0 | TCP | 443 | HTTPS |
| 0.0.0.0/0 | TCP | 5173 | Dashboard |
| 0.0.0.0/0 | TCP | 8080 | API |
| 0.0.0.0/0 | TCP | 3001 | Grafana |

Also open the OS-level firewall (Oracle Linux/Ubuntu has its own firewall):
```bash
# On the VM via SSH:
sudo firewall-cmd --permanent --add-port=5173/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=3001/tcp
sudo firewall-cmd --reload
# OR for Ubuntu:
sudo ufw allow 5173
sudo ufw allow 8080
sudo ufw allow 3001
```

#### Part D — SSH Into the VM

```bash
# From your PC terminal:
ssh -i /path/to/your-private-key.pem ubuntu@YOUR.VM.IP.ADDRESS

# Example:
ssh -i ~/Downloads/oracle-key.pem ubuntu@132.145.20.55
```

#### Part E — Install Docker on the VM

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group (so you don't need sudo)
sudo usermod -aG docker ubuntu

# Log out and back in for group change to take effect
exit
ssh -i ~/Downloads/oracle-key.pem ubuntu@YOUR.VM.IP.ADDRESS

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify both installed
docker --version
docker-compose --version
```

#### Part F — Clone Your Repository and Configure

```bash
# On the VM:
git clone https://github.com/Skarthik06/cybersentinel-ai.git
cd cybersentinel-ai

# Create .env from template
cp .env.example .env

# Edit .env with your real values
nano .env
# Fill in: LLM_PROVIDER, OPENAI_API_KEY, POSTGRES_PASSWORD, etc.
# Press Ctrl+X then Y then Enter to save
```

#### Part G — Start the Project

```bash
# Make scripts executable
chmod +x start.sh stop.sh

# Start everything
./start.sh
```

Wait 3–5 minutes for all services to start (first run downloads Docker images).

#### Part H — Access Your Deployed Project

```
Dashboard  →  http://YOUR.VM.IP:5173
API        →  http://YOUR.VM.IP:8080
API Docs   →  http://YOUR.VM.IP:8080/docs
Grafana    →  http://YOUR.VM.IP:3001
```

Replace `YOUR.VM.IP` with your actual Oracle VM IP address.

#### Part I — Keep It Running After You Log Out

By default, if you log out of SSH, any running process stops. To keep the project running permanently:

```bash
# Start with nohup so it survives logout
nohup docker-compose up -d &

# OR better — set Docker to auto-restart on VM reboot
# Your docker-compose.yml already has restart: unless-stopped
# on all services, so they auto-start when the VM boots
```

To make the VM auto-start your project on reboot:
```bash
# Create a systemd service
sudo nano /etc/systemd/system/cybersentinel.service
```

Paste this:
```ini
[Unit]
Description=CyberSentinel AI
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ubuntu/cybersentinel-ai
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
User=ubuntu

[Install]
WantedBy=multi-user.target
```

Then enable it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cybersentinel
sudo systemctl start cybersentinel
```

Now every time the Oracle VM boots, your project starts automatically.

### What You Get After Phase 3

- Project running 24/7 at `http://YOUR.VM.IP:5173`
- Accessible from any browser, any device, anywhere in the world
- Your PC can be off
- Free forever on Oracle Always Free tier
- Auto-restarts if the VM reboots

---

## 6. Phase 4 — Custom Domain + HTTPS

### Why This Phase?

After Phase 3, your project is accessible at an IP address like `http://132.145.20.55:5173`. This works but looks unprofessional. This phase gives you:

- `https://cybersentinel-ai.your-name.com` — a real domain
- HTTPS (the padlock icon) — secure connection
- No port number in the URL — cleaner

### Free Domain Options

| Provider | Free Domain Format | How Long |
|----------|------------------|---------|
| Freenom | `.tk`, `.ml`, `.ga` | 1 year renewable |
| js.org | `yourname.js.org` | For JS projects |
| is-a.dev | `yourname.is-a.dev` | Open source projects |
| Oracle subdomain | Not available | — |

Alternatively, domains like `.com` cost about $10/year from Namecheap or Cloudflare.

### Nginx Reverse Proxy Setup

Instead of exposing raw ports (`:5173`, `:8080`), you put Nginx in front. Nginx listens on port 80/443 and routes traffic to the right service:

```
User visits https://cybersentinel.your-domain.com
    ↓
Nginx (port 443)
    ├── / path → frontend container (port 5173)
    ├── /api   → api-gateway container (port 8080)
    └── /grafana → grafana container (port 3001)
```

**`deploy/nginx/nginx.conf`:**

```nginx
server {
    listen 80;
    server_name cybersentinel.your-domain.com;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name cybersentinel.your-domain.com;

    # SSL certificates (from Certbot/Let's Encrypt — free)
    ssl_certificate     /etc/letsencrypt/live/cybersentinel.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybersentinel.your-domain.com/privkey.pem;

    # Dashboard
    location / {
        proxy_pass http://localhost:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API
    location /api {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Free HTTPS with Let's Encrypt

Let's Encrypt gives free SSL certificates (the padlock). Certbot automates installing them:

```bash
# On the Oracle VM:
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d cybersentinel.your-domain.com

# Certbot auto-renews every 90 days — set up auto-renewal:
sudo crontab -e
# Add this line:
0 12 * * * /usr/bin/certbot renew --quiet
```

### What You Get After Phase 4

- `https://cybersentinel.your-domain.com` — professional URL
- Padlock icon — HTTPS secure
- No port number visible
- Auto-renewing SSL certificate
- Ready to put on your CV, LinkedIn, GitHub README

---

## 7. Decision Guide

### Which Phases Do You Actually Need?

```
Do you need to demo the project in the next few days?
    YES → Do Phase 1 + Phase 2 (ngrok). Done in 1 hour.
    NO  → Continue below

Do you want 24/7 access without your PC running?
    YES → Do Phase 3 (Oracle Cloud). Takes 2-3 hours.
    NO  → Phase 1 + 2 is enough

Do you want a professional URL for your CV/portfolio?
    YES → Do Phase 3 + Phase 4.
    NO  → Phase 3's IP address is fine for demos

Are you submitting this as a university project?
    → Phase 1 + 2 is enough for demos
    → Phase 3 + 4 for permanent link in report

Are you job hunting and want recruiters to see a live demo?
    → Do all 4 phases
    → Put the Phase 4 URL on your GitHub README
```

### Minimum for Each Goal

| Goal | Phases Needed | Time |
|------|--------------|------|
| Demo in interview (PC present) | Phase 1 only | 30 min |
| Demo remotely (PC must be on) | Phase 1 + 2 | 1 hour |
| Always-on portfolio link | Phase 1 + 3 | 3 hours |
| Professional CV-ready URL | All 4 phases | 4 hours |

---

## 8. All Files That Will Be Created

```
cybersentinel-ai/
├── start.sh                        ← Phase 1: one-click start
├── stop.sh                         ← Phase 1: one-click stop
└── deploy/
    ├── oracle/
    │   └── setup.sh                ← Phase 3: automated Oracle VM setup
    └── nginx/
        ├── nginx.conf              ← Phase 4: reverse proxy config
        └── install-ssl.sh          ← Phase 4: Let's Encrypt setup
```

### Files Modified

```
.env.example    ← Add ngrok domain variable
README.md       ← Add live demo URL after Phase 3/4
```

---

## 9. Troubleshooting Reference

### Common Issues and Fixes

| Problem | Cause | Fix |
|---------|-------|-----|
| `./start.sh: Permission denied` | Script not executable | Run `chmod +x start.sh` |
| Services start but API is not healthy | Port 8080 already in use | Run `docker ps` to see what is using it |
| ngrok URL works but shows blank page | CORS blocking the ngrok domain | Add ngrok domain to `CORS_ORIGINS` in `.env` |
| Oracle VM reachable via SSH but not browser | OS firewall blocking ports | Run `sudo ufw allow 5173` on the VM |
| Oracle VM not reachable at all | Security List rules missing | Add ingress rules in Oracle Cloud console |
| Docker takes too long on Oracle ARM | First pull downloads ~3 GB | Wait 10–15 min on first run, subsequent starts are fast |
| ChromaDB embedding model slow on ARM | CPU inference on ARM | Normal — takes 30–60s to load on first start |
| `git pull` fails on VM | SSH key not configured | Use HTTPS for git clone on the VM |
| Project stops when you close SSH | Process tied to terminal | Use `nohup` or systemd service (see Phase 3 Part I) |

### Useful Commands on the Oracle VM

```bash
# Check all containers are running
docker ps

# See resource usage (RAM, CPU)
docker stats

# View logs for a specific service
docker-compose logs -f mcp-orchestrator
docker-compose logs -f api-gateway

# Restart one service without stopping others
docker-compose restart api-gateway

# Update project from GitHub and restart
git pull origin main
docker-compose up -d --build

# Check how much disk space is used
df -h
docker system df

# Free up unused Docker space
docker system prune -f
```

### RAM Usage Check

To verify the Oracle VM has enough memory:
```bash
free -h
# Should show ~24 GB total, with at least 4 GB free after all services start
```

---

## Summary

```
Phase 1 (30 min)  → ./start.sh and ./stop.sh created
                    One command starts everything on your PC

Phase 2 (30 min)  → ngrok installed and configured
                    Anyone anywhere can visit your live dashboard

Phase 3 (2-3 hrs) → Oracle Cloud VM running 24/7
                    Project accessible without your PC being on

Phase 4 (1 hr)    → Custom domain + HTTPS
                    Professional URL ready for CV and portfolio
```

**Recommended starting point:** Read this document fully, then decide.
If you want to demo soon → start with Phase 1 and 2.
If you want permanent deployment → go straight to Phase 3.

---

*Deployment Plan — CyberSentinel AI v1.1 — 2026*
