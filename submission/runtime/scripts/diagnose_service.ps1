$ErrorActionPreference = "Stop"
Get-Service -Name DNSShield -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
Get-ChildItem "$env:ProgramData\DNS-SHIELD" -Force -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime
Write-Host "This diagnostic does not change service, DNS, firewall, or adapter configuration."
