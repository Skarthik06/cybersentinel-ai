@echo off
REM Run this AFTER `docker compose up -d`. Pops up a window with two start modes,
REM opens the dashboard in your browser, then starts the live DPI sensor.
powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0scripts\cybersentinel_launcher.ps1"
if errorlevel 1 (
  echo.
  echo [Launcher] PowerShell exited with error %errorlevel%.
  pause
)
