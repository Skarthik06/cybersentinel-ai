# CyberSentinel AI - One-time registration of the DPI sensor as a Windows Scheduled Task.
# Triggers at user logon with highest privileges, no UAC prompt at runtime.
# Run this script ONCE. The sensor will then auto-start on every login.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BatPath     = Join-Path $ProjectRoot "Start Live DPI.bat"
$TaskName    = "CyberSentinel DPI"

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CyberSentinel AI - Auto-Start Registration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target script : $BatPath"
Write-Host "Task name     : $TaskName"
Write-Host "Trigger       : At user logon ($env:USERNAME)"
Write-Host "Privileges    : Highest (no UAC prompt at runtime)"
Write-Host ""

if (-not (Test-Path $BatPath)) {
    Write-Host "ERROR: Cannot find $BatPath" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Remove any prior registration so re-running this script is idempotent.
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Existing task found - removing old registration..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action    = New-ScheduledTaskAction -Execute $BatPath -WorkingDirectory $ProjectRoot
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Registered successfully." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The DPI sensor will now auto-start every time you log into Windows."
Write-Host ""
Write-Host "To run it right now without rebooting:"
Write-Host "    Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host ""
Write-Host "To remove auto-start later:"
Write-Host "    Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to close"
