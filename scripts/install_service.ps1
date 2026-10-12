param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
& $Python -m pip install -r (Join-Path $root "requirements.txt")
& $Python (Join-Path $root "windows_service.py") install --startup=auto
& sc.exe failure DNSShield reset=86400 actions=restart/60000/restart/60000/""/0
Write-Host "DNS-SHIELD service prepared but not started. Review adapter and activation steps before starting."
