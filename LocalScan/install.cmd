@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator access...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
if errorlevel 1 (
    echo.
    echo LocalScan installation failed. Review the error above.
    pause
    exit /b 1
)

pause
