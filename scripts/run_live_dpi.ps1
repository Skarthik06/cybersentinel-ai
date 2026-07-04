# CyberSentinel AI - Live DPI Sensor launcher (parameterized)
#
#   -ClearData : TRUNCATE alerts/incidents/campaigns/etc. for a clean slate first
#   -EnableAI  : turn AI investigation ON (resume). Omit to keep it OFF (paused).
#
# Two ready-made entry points call this:
#   "Start Live DPI (Fresh + AI On).bat"  -> -ClearData -EnableAI
#   "Start Live DPI (Keep + AI Off).bat"  -> (no switches)
#
# Self-elevates (Npcap needs admin), forwards the switches through elevation.

param(
    [switch]$ClearData,
    [switch]$EnableAI
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $fwd = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($ClearData) { $fwd += " -ClearData" }
    if ($EnableAI)  { $fwd += " -EnableAI" }
    Start-Process PowerShell -Verb RunAs -ArgumentList $fwd
    exit
}

trap {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  SCRIPT FAILED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host $_ -ForegroundColor Red
    Write-Host "Line: $($_.InvocationInfo.ScriptLineNumber)  Command: $($_.InvocationInfo.Line.Trim())" -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit 1
}

# NOTE: "Continue" (not "Stop"). docker/python/redis-cli write progress to stderr,
# and under "Stop" PowerShell 5.1 treats native stderr as a TERMINATING error (the
# trap would fire on harmless "Container X Starting" lines). We gate on $LASTEXITCODE
# explicitly at each critical step instead.
$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Write-Step { param($msg) Write-Host "`n[ $msg ]" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  >>  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  !!  $msg" -ForegroundColor Red }

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CyberSentinel AI - Live Network DPI Sensor" -ForegroundColor Cyan
$modeData = if ($ClearData) { "FRESH START (clear all data)" } else { "KEEP existing data" }
$modeAI   = if ($EnableAI)  { "AI INVESTIGATION: ON" }        else { "AI INVESTIGATION: OFF" }
Write-Host "   Mode: $modeData  |  $modeAI" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan

# STEP 1: Python
Write-Step "Checking Python"
$pyVer = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Python not found in PATH. Install from https://python.org (check 'Add to PATH')."
    Read-Host "Press Enter to exit"; exit 1
}
Write-OK "$pyVer"

# STEP 2: Npcap
Write-Step "Checking Npcap"
if ((Test-Path "C:\Windows\System32\Npcap") -or (Test-Path "C:\Windows\System32\wpcap.dll")) {
    Write-OK "Npcap installed."
} else {
    Write-Warn "Npcap not found. Downloading..."
    $npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
    Start-Process -FilePath $npcapInstaller -ArgumentList "/S /winpcap_mode=yes /loopback_support=yes" -Wait
    Remove-Item $npcapInstaller -ErrorAction SilentlyContinue
    Write-OK "Npcap installed."
}

# STEP 3: Python packages
Write-Step "Checking Python packages"
foreach ($pkg in @("scapy", "aiokafka", "redis")) {
    python -c "import $pkg" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Installing $pkg..."
        python -m pip install $pkg --quiet --disable-pip-version-check
    }
    Write-OK "$pkg ready."
}

# STEP 4: Docker
Write-Step "Checking Docker"
docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Docker not running. Starting Docker Desktop..."
    $ddPath = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ddPath) { Write-Fail "Docker Desktop not found."; Read-Host "Press Enter to exit"; exit 1 }
    Start-Process $ddPath
    $waited = 0
    do { Start-Sleep 5; $waited += 5; docker info 2>$null | Out-Null } while ($LASTEXITCODE -ne 0 -and $waited -lt 90)
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker did not start."; Read-Host "Press Enter to exit"; exit 1 }
}
Write-OK "Docker running."

# STEP 5: Stack + Kafka health
Write-Step "Checking CyberSentinel stack"
Set-Location $ProjectRoot
$kafkaUp = docker compose ps --status running 2>$null | Select-String "cybersentinel-kafka"
if (-not $kafkaUp) {
    Write-Warn "Starting docker compose stack..."
    docker compose up -d 2>$null | Out-Null
}
Write-Warn "Waiting for Kafka to become healthy..."
$waited = 0; $kafkaHealthy = $false
do {
    Start-Sleep 5; $waited += 5
    $health = docker inspect --format='{{.State.Health.Status}}' cybersentinel-kafka 2>$null
    if ($health -eq "healthy") { $kafkaHealthy = $true; break }
    Write-Host "  ...still waiting ($waited s, status=$health)" -ForegroundColor DarkGray
} while ($waited -lt 180)
if (-not $kafkaHealthy) { Write-Fail "Kafka not healthy in 180s. Run: docker compose logs kafka"; Read-Host "Press Enter to exit"; exit 1 }
Write-OK "Kafka healthy."

# Read secrets from .env
$redisPassword = ""
$envFile = Join-Path $ProjectRoot ".env"
if (Test-Path $envFile) {
    # foreach statement (not ForEach-Object): keeps the $redisPassword assignment in
    # the same scope where it's read below, so PSScriptAnalyzer doesn't false-flag it
    # as "assigned but never used" (PSUseDeclaredVarsMoreThanAssignments).
    foreach ($line in (Get-Content $envFile)) {
        if ($line -match "^REDIS_PASSWORD=(.+)") { $redisPassword = $Matches[1].Trim() }
    }
}

# STEP 6: Optional data wipe
if ($ClearData) {
    Write-Step "Clearing SOC data (alerts, incidents, campaigns, profiles, packets...)"
    $tables = @("alerts","incidents","attacker_campaigns","campaign_incidents",
                "firewall_rules","behavior_profiles","packets","pending_reports","audit_log")
    foreach ($t in $tables) {
        docker exec cybersentinel-postgres psql -U sentinel -d cybersentinel -c "TRUNCATE TABLE $t RESTART IDENTITY CASCADE;" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-OK "cleared $t" } else { Write-Warn "skipped $t (missing?)" }
    }
    # Clear Redis blocklist + cached state (keep it simple: flush the cache DB)
    docker exec cybersentinel-redis redis-cli -a $redisPassword --no-auth-warning FLUSHDB 2>$null | Out-Null
    Write-OK "Redis cache + blocklist flushed."
} else {
    Write-Step "Keeping existing data (no wipe)"
    Write-OK "Existing alerts / incidents / campaigns preserved."
}

# STEP 7: AI investigation toggle (Redis: investigations:paused:<source>)
Write-Step "Setting AI investigation state"
if ($EnableAI) {
    docker exec cybersentinel-redis redis-cli -a $redisPassword --no-auth-warning DEL investigations:paused:dpi investigations:paused:simulator 2>$null | Out-Null
    Write-OK "AI investigation ENABLED (resumed dpi + simulator) - new threats will be AI-investigated."
} else {
    docker exec cybersentinel-redis redis-cli -a $redisPassword --no-auth-warning SET investigations:paused:dpi 1 2>$null | Out-Null
    docker exec cybersentinel-redis redis-cli -a $redisPassword --no-auth-warning SET investigations:paused:simulator 1 2>$null | Out-Null
    Write-OK "AI investigation DISABLED (paused) - alerts log, but no LLM calls / no API cost."
}

# STEP 8: Active adapters
Write-Host "`nActive network adapters:" -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "vEthernet*" } |
    ForEach-Object { Write-Host "   * $($_.Name)  ($($_.InterfaceDescription))" -ForegroundColor White }

# STEP 9: Launch sensor
Write-Step "Launching Live DPI Sensor"
# Use 127.0.0.1 (not localhost): on Windows, localhost -> IPv6 ::1 first and Docker
# Desktop's IPv6 port map stalls ~21s before IPv4 fallback. 127.0.0.1 connects instantly.
$env:PYTHONPATH        = $ProjectRoot
$env:KAFKA_BOOTSTRAP   = "127.0.0.1:9092"
$env:REDIS_URL         = "redis://:$redisPassword@127.0.0.1:6379"
$env:CAPTURE_INTERFACE = "auto"
$env:BPF_FILTER        = "ip and not (net 192.168.65.0/24) and not (net 172.16.0.0/12) and not (dst net 224.0.0.0/4) and not (dst host 255.255.255.255)"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  LIVE CAPTURE ACTIVE - switch to the Live Network SOC tab" -ForegroundColor Green
Write-Host "  $modeData  |  $modeAI" -ForegroundColor Gray
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

$sensorScript = Join-Path (Join-Path (Join-Path $ProjectRoot "src") "dpi") "sensor.py"
python $sensorScript
