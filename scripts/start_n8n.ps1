# CyberSentinel — Start N8N + auto-activate workflows
# Usage: .\scripts\start_n8n.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot ".env"

# Load .env
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim())
        }
    }
}

$OPENAI_API_KEY   = $env:OPENAI_API_KEY
$SLACK_BOT_TOKEN  = $env:SLACK_BOT_TOKEN
$SLACK_CHANNEL_ID = $env:SLACK_CHANNEL_ID

Write-Host "[CyberSentinel] Starting N8N container..." -ForegroundColor Cyan

# Remove old container if exists
docker rm -f N8N 2>$null

# Start fresh with all required env vars
docker run -d `
    --name N8N `
    --network cybersentinel-ai_cybersentinel-net `
    -p 5678:5678 `
    -v "D:/N8N:/home/node/.n8n" `
    -e "OPENAI_API_KEY=$OPENAI_API_KEY" `
    -e "SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN" `
    -e "SLACK_CHANNEL_ID=$SLACK_CHANNEL_ID" `
    -e "N8N_BLOCK_ENV_ACCESS_IN_NODE=false" `
    -e "TZ=Asia/Kolkata" `
    -e "GENERIC_TIMEZONE=Asia/Kolkata" `
    n8nio/n8n:latest

Write-Host "[CyberSentinel] Waiting 15s for N8N to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

Write-Host "[CyberSentinel] Activating workflows..." -ForegroundColor Cyan
python "$ProjectRoot\scripts\activate_n8n_workflows.py"

Write-Host "[CyberSentinel] Restarting N8N to pick up changes..." -ForegroundColor Yellow
docker restart N8N

Write-Host "[CyberSentinel] Done! N8N is ready at http://localhost:5678" -ForegroundColor Green
