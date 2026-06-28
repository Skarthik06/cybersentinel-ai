# CyberSentinel AI - One-click interactive launcher
#
# Does EVERYTHING in order:
#   1. Starts Docker Desktop (if needed) and brings the whole compose stack up
#   2. Waits until Kafka is healthy ("Kafka pulls it up")
#   3. Pops a window letting you choose the start mode
#   4. Opens the SOC dashboard in your browser
#   5. Starts the live DPI sensor in the chosen mode
#
# NOTE: Docker Desktop's own Play button CANNOT show this window (containers
# can't open windows on the host). Use THIS launcher instead of the Play button.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

trap {
    Write-Host "`n  SCRIPT FAILED: $_" -ForegroundColor Red
    Write-Host "  Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit 1
}

# NOTE: "Continue" (not "Stop"). docker writes progress to stderr, and under "Stop"
# PowerShell 5.1 treats native stderr as a terminating error (the trap would fire on
# harmless "Container X Starting" lines). We gate on $LASTEXITCODE explicitly instead.
$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Write-Step { param($m) Write-Host "`n[ $m ]" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "  OK  $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  >>  $m" -ForegroundColor Yellow }

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CYBERSENTINEL AI - One-Click Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── Phase 1: Docker engine ────────────────────────────────────────────────────
Write-Step "Checking Docker"
docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Docker not running - starting Docker Desktop..."
    $ddPath = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ddPath) { Write-Host "  !!  Docker Desktop not found." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
    Start-Process $ddPath
    $waited = 0
    do { Start-Sleep 5; $waited += 5; docker info 2>$null | Out-Null } while ($LASTEXITCODE -ne 0 -and $waited -lt 120)
    if ($LASTEXITCODE -ne 0) { Write-Host "  !!  Docker did not start in time." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
}
Write-OK "Docker engine running."

# ── Phase 2: bring the stack up + wait for Kafka ──────────────────────────────
Write-Step "Starting CyberSentinel stack (this is the 'Play button')"
Set-Location $ProjectRoot
docker compose up -d 2>$null | Out-Null
Write-OK "docker compose up -d issued."

Write-Warn "Waiting for Kafka to become healthy..."
$waited = 0; $kafkaHealthy = $false
do {
    Start-Sleep 5; $waited += 5
    $health = docker inspect --format='{{.State.Health.Status}}' cybersentinel-kafka 2>$null
    if ($health -eq "healthy") { $kafkaHealthy = $true; break }
    Write-Host "  ...still waiting ($waited s, status=$health)" -ForegroundColor DarkGray
} while ($waited -lt 180)
if (-not $kafkaHealthy) { Write-Host "  !!  Kafka not healthy in 180s. Run: docker compose logs kafka" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
Write-OK "Kafka healthy - stack is up."

# Show what's running so you can see all containers came up
Write-Host "`nRunning containers:" -ForegroundColor Cyan
docker compose ps --format "  * {{.Name}}  ({{.Status}})" 2>$null

# ── Phase 3: choose mode (popup window) ───────────────────────────────────────
Write-Step "Opening mode selector..."
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$cyan  = [System.Drawing.Color]::FromArgb(0, 229, 255)
$blue  = [System.Drawing.Color]::FromArgb(0, 176, 255)
$bg    = [System.Drawing.Color]::FromArgb(2, 10, 22)
$btnBg = [System.Drawing.Color]::FromArgb(8, 30, 52)
$muted = [System.Drawing.Color]::FromArgb(120, 180, 210)

$script:choice = $null

$form = New-Object System.Windows.Forms.Form
$form.Text = "CyberSentinel AI - Launch Mode"
$form.ClientSize = New-Object System.Drawing.Size(520, 330)
$form.StartPosition = "CenterScreen"
$form.BackColor = $bg
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$title = New-Object System.Windows.Forms.Label
$title.Text = "CYBERSENTINEL  AI"
$title.Font = New-Object System.Drawing.Font("Consolas", 16, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = $cyan
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(28, 20)
$form.Controls.Add($title)

$sub = New-Object System.Windows.Forms.Label
$sub.Text = "Stack is up & Kafka is ready. Choose how to start the LIVE DPI sensor:"
$sub.Font = New-Object System.Drawing.Font("Consolas", 9)
$sub.ForeColor = $muted
$sub.AutoSize = $true
$sub.Location = New-Object System.Drawing.Point(30, 56)
$form.Controls.Add($sub)

function New-ModeButton($text, $y, $accent) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Size = New-Object System.Drawing.Size(460, 64)
    $b.Location = New-Object System.Drawing.Point(30, $y)
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderColor = $accent
    $b.FlatAppearance.BorderSize = 1
    $b.BackColor = $btnBg
    $b.ForeColor = [System.Drawing.Color]::FromArgb(190, 230, 255)
    $b.Font = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
    $b.TextAlign = "MiddleLeft"
    $b.Cursor = "Hand"
    return $b
}

$btnFresh = New-ModeButton "  FRESH START`r`n  Clear all data  +  AI investigation ON" 96 $cyan
$btnFresh.Add_Click({ $script:choice = "fresh"; $form.Close() })
$form.Controls.Add($btnFresh)

$btnKeep = New-ModeButton "  KEEP DATA`r`n  No AI investigation  (no API cost)" 172 $blue
$btnKeep.Add_Click({ $script:choice = "keep"; $form.Close() })
$form.Controls.Add($btnKeep)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Size = New-Object System.Drawing.Size(460, 34)
$btnCancel.Location = New-Object System.Drawing.Point(30, 256)
$btnCancel.FlatStyle = "Flat"
$btnCancel.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 80, 100)
$btnCancel.BackColor = $bg
$btnCancel.ForeColor = $muted
$btnCancel.Font = New-Object System.Drawing.Font("Consolas", 9)
$btnCancel.Add_Click({ $script:choice = $null; $form.Close() })
$form.Controls.Add($btnCancel)

[void]$form.ShowDialog()

if (-not $script:choice) {
    Write-Warn "Launch cancelled (stack is still running)."
    Start-Sleep 1
    exit
}

# ── Phase 4: open browser ─────────────────────────────────────────────────────
Write-OK "Opening dashboard at http://localhost:5173"
Start-Process "http://localhost:5173"

# ── Phase 5: start the sensor in the chosen mode (Kafka already healthy) ───────
$runner = Join-Path $PSScriptRoot "run_live_dpi.ps1"
if ($script:choice -eq "fresh") {
    & $runner -ClearData -EnableAI
} else {
    & $runner
}
