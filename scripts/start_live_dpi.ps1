# CyberSentinel AI - Live DPI Sensor: Auto-Setup and Launcher
# Handles: Admin elevation, Npcap install, pip packages, Docker start, sensor run
# Usage: Double-click Start Live DPI.bat  OR run this file directly in PowerShell

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Write-Step { param($msg) Write-Host "`n[ $msg ]" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  >>  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  !!  $msg" -ForegroundColor Red }

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CyberSentinel AI - Live Network DPI Sensor" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# STEP 1: Check Python
Write-Step "Checking Python"
try {
    $pyVer = python --version 2>&1
    if ($LASTEXITCODE -eq 0) { Write-OK "$pyVer" } else { throw }
} catch {
    Write-Fail "Python not found in PATH."
    Write-Warn "Download from https://python.org and check Add Python to PATH during install."
    Read-Host "`nPress Enter to exit"
    exit 1
}

# STEP 2: Install Npcap if missing
Write-Step "Checking Npcap"
$npcapInstalled = (Test-Path "C:\Windows\System32\Npcap") -or (Test-Path "C:\Windows\System32\wpcap.dll")
if ($npcapInstalled) {
    Write-OK "Npcap already installed."
} else {
    Write-Warn "Npcap not found. Downloading silently..."
    $npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
        Write-Warn "Installing Npcap..."
        Start-Process -FilePath $npcapInstaller -ArgumentList "/S /winpcap_mode=yes /loopback_support=yes" -Wait
        Remove-Item $npcapInstaller -ErrorAction SilentlyContinue
        Write-OK "Npcap installed."
    } catch {
        Write-Fail "Npcap install failed: $_"
        Write-Warn "Install manually from https://npcap.com and check WinPcap API-compatible mode."
        Read-Host "`nPress Enter to exit"
        exit 1
    }
}

# STEP 3: Install Python packages
Write-Step "Checking Python packages"
foreach ($pkg in @("scapy", "aiokafka", "redis")) {
    $check = python -c "import $pkg" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Installing $pkg..."
        python -m pip install $pkg --quiet --disable-pip-version-check
        Write-OK "$pkg installed."
    } else {
        Write-OK "$pkg ready."
    }
}

# STEP 4: Check Docker
Write-Step "Checking Docker"
$dockerOk = $false
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
} catch {}

if (-not $dockerOk) {
    Write-Warn "Docker not running. Starting Docker Desktop..."
    $ddPath = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($ddPath) {
        Start-Process $ddPath
        $waited = 0
        do { Start-Sleep 5; $waited += 5; docker info 2>&1 | Out-Null } while ($LASTEXITCODE -ne 0 -and $waited -lt 60)
        if ($LASTEXITCODE -ne 0) { Write-Fail "Docker did not start. Launch Docker Desktop manually."; Read-Host; exit 1 }
        Write-OK "Docker started."
    } else {
        Write-Fail "Docker Desktop not found. Install from https://docker.com/products/docker-desktop"
        Read-Host; exit 1
    }
} else {
    Write-OK "Docker running."
}

# STEP 5: Start stack if not running
Write-Step "Checking CyberSentinel stack"
Set-Location $ProjectRoot
$kafkaUp = docker compose ps --status running 2>&1 | Select-String "cybersentinel-kafka"
if ($kafkaUp) {
    Write-OK "Stack already running."
} else {
    Write-Warn "Starting docker compose stack..."
    docker compose up -d 2>&1 | Out-Null
    Write-Warn "Waiting 30s for services to start..."
    Start-Sleep 30
    Write-OK "Stack started."
}

# STEP 6: Start N8N (auto, no user action needed)
Write-Step "Starting N8N"
$n8nRunning = docker ps --filter "name=N8N" --filter "status=running" --format "{{.Names}}" 2>&1
if ($n8nRunning -eq "N8N") {
    Write-OK "N8N already running."
} else {
    Write-Warn "Starting N8N..."
    # Ensure network exists then start (or recreate) the container
    docker network connect cybersentinel-ai_cybersentinel-net N8N 2>&1 | Out-Null
    docker start N8N 2>&1 | Out-Null
    Start-Sleep 3
    $n8nCheck = docker ps --filter "name=N8N" --filter "status=running" --format "{{.Names}}"
    if ($n8nCheck -eq "N8N") {
        Write-OK "N8N started at http://localhost:5678"
    } else {
        # Container may be stale/missing — recreate it from start_n8n.ps1
        Write-Warn "N8N container not found — recreating..."
        & "$PSScriptRoot\start_n8n.ps1"
    }
}

# STEP 7: Read Redis password from .env
$redisPassword = ""
$envFile = Join-Path $ProjectRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^REDIS_PASSWORD=(.+)") { $redisPassword = $Matches[1].Trim() }
    }
}

# STEP 8: Show active adapters
Write-Host ""
Write-Host "Active network adapters:" -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "vEthernet*" } |
    ForEach-Object { Write-Host "   * $($_.Name)  ($($_.InterfaceDescription))" -ForegroundColor White }

# STEP 8: Launch sensor
Write-Step "Launching Live DPI Sensor"
$env:PYTHONPATH        = $ProjectRoot
$env:KAFKA_BOOTSTRAP   = "localhost:9092"
$env:REDIS_URL         = "redis://:$redisPassword@localhost:6379"
$env:CAPTURE_INTERFACE = "auto"
$env:BPF_FILTER        = "ip and not (net 192.168.65.0/24) and not (net 172.16.0.0/12)"

Write-Host "  Kafka:     localhost:9092" -ForegroundColor White
Write-Host "  Redis:     localhost:6379" -ForegroundColor White
Write-Host "  Interface: auto-detect -> physical Ethernet" -ForegroundColor White
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  LIVE CAPTURE ACTIVE - switch to Live Network SOC tab" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

$sensorScript = Join-Path $ProjectRoot "src"
$sensorScript = Join-Path $sensorScript "dpi"
$sensorScript = Join-Path $sensorScript "sensor.py"
python $sensorScript
