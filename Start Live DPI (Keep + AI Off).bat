@echo off
REM Keeps existing data, leaves AI investigation OFF (no LLM cost), then runs live DPI.
powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0scripts\run_live_dpi.ps1"
if errorlevel 1 (
  echo.
  echo [Launcher] PowerShell exited with error %errorlevel%.
  pause
)
