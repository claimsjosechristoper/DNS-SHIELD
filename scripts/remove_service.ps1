param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
& $Python (Join-Path $root "windows_service.py") stop
& $Python (Join-Path $root "windows_service.py") remove
Write-Host "DNS-SHIELD service registration removed. Network adapter DNS settings are not changed by this script."
