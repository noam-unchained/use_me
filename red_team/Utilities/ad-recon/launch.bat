@echo off
:: AD Recon — CMD launcher
:: Drops you into the PowerShell script with execution policy bypassed.
:: Just double-click or run from any CMD prompt.

echo.
echo  [*] AD Recon — launching PowerShell edition...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [!] Something went wrong. Try running manually:
    echo      powershell -ExecutionPolicy Bypass -File launch.ps1
    echo.
    pause
)
