@echo off
powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0scripts\start_live_dpi.ps1"
if errorlevel 1 (
  echo.
  echo [Launcher] PowerShell exited with error %errorlevel%.
  pause
)
