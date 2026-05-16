# CyberSentinel AI - Removes the DPI sensor scheduled task.
# Counterpart to register_autostart.ps1. Safe to run even if not registered.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Stop"
$TaskName = "CyberSentinel DPI"

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   CyberSentinel AI - Disable Auto-Start" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
} else {
    Write-Host "No scheduled task named '$TaskName' was registered. Nothing to do." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "From now on, start the sensor manually by double-clicking 'Start Live DPI.bat'."
Write-Host "To re-enable auto-start later, run 'Enable Auto-Start.bat'."
Write-Host ""
Read-Host "Press Enter to close"
