@echo off
REM Clears all alerts/incidents/campaigns/profiles, turns AI investigation ON, then runs live DPI.
powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0scripts\run_live_dpi.ps1" -ClearData -EnableAI
if errorlevel 1 (
  echo.
  echo [Launcher] PowerShell exited with error %errorlevel%.
  pause
)
