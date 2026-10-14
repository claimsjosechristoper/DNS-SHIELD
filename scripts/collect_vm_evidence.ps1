# DNS-SHIELD: Disposable VM Evidence Collection Script
# Run in an elevated PowerShell prompt inside the test VM

param(
    [string]$OutputDir = "C:\TestPackage\evidence"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host "=== Collecting DNS-SHIELD VM Integration Evidence ($timestamp) ===" -ForegroundColor Cyan

# 1. Adapter DNS Configuration
Write-Host "[1/6] Capturing live adapter DNS addresses..."
Get-DnsClientServerAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses | Format-Table -AutoSize | Out-String | Set-Content -Path "$OutputDir\live_dns_adapters.txt"
Get-DnsClientServerAddress | Export-Clixml -Path "$OutputDir\live_dns_adapters.xml"

# 2. Interface IP & DHCP States
Write-Host "[2/6] Capturing IP interfaces and DHCP configuration..."
Get-NetIPInterface | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, Dhcp, ConnectionState | Format-Table -AutoSize | Out-String | Set-Content -Path "$OutputDir\live_interfaces.txt"

# 3. Windows Filtering Platform (WFP) Filters
Write-Host "[3/6] Exporting Windows Filtering Platform filters..."
$wfpDiagPath = "$OutputDir\wfp_filters.xml"
netsh wfp show filters file="$wfpDiagPath"
if (Test-Path $wfpDiagPath) {
    [xml]$wfp = Get-Content $wfpDiagPath
    $dnsFilters = $wfp.wfpdiag.filters.filter | Where-Object { 
        $_.displayData.name -like "*DNSShield*" -or 
        $_.displayData.name -like "*IPv4_Permit*" -or 
        $_.displayData.name -like "*IPv4_Block*" -or
        $_.displayData.name -like "*IPv6_Permit*" -or
        $_.displayData.name -like "*IPv6_Block*"
    }
    $dnsFilters | Select-Object filterId, @{N='Name';E={$_.displayData.name}}, action | Format-Table -AutoSize | Out-String | Set-Content -Path "$OutputDir\wfp_dns_shield_filters.txt"
    Write-Host "      Found $($dnsFilters.Count) DNS-SHIELD WFP filters." -ForegroundColor Green
}

# 4. Service Status & SCM Registry Configuration
Write-Host "[4/6] Capturing SCM service status and registry ImagePath..."
Get-Service -Name DNSShield -ErrorAction SilentlyContinue | Format-List * | Out-String | Set-Content -Path "$OutputDir\service_scm_status.txt"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNSShield" -ErrorAction SilentlyContinue | Format-List ImagePath, DisplayName, Start, ObjectName | Out-String | Set-Content -Path "$OutputDir\service_registry_config.txt"

# 5. Gateway SQLite Database Audit Logs & Rules
Write-Host "[5/6] Exporting gateway database logs and rules..."
$dbPath = "$env:ProgramData\DNS-SHIELD\dns_gateway.db"
if (Test-Path $dbPath) {
    Copy-Item -Path $dbPath -Destination "$OutputDir\dns_gateway_snapshot.db" -Force
    # Export text dump if sqlite3 CLI is available
    if (Get-Command sqlite3 -ErrorAction SilentlyContinue) {
        sqlite3 $dbPath "SELECT timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, rcode FROM dns_logs ORDER BY id DESC LIMIT 100;" | Set-Content -Path "$OutputDir\recent_dns_audit_logs.txt"
        sqlite3 $dbPath "SELECT id, domain, rule_type, action, enabled, reason FROM custom_rules;" | Set-Content -Path "$OutputDir\active_custom_rules.txt"
    }
}

# 6. Windows Event Logs for DNSShield
Write-Host "[6/6] Capturing Application and System event log entries..."
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='DNSShield'} -MaxEvents 50 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message | Out-String | Set-Content -Path "$OutputDir\event_log_dns_shield.txt"

Write-Host "=== Evidence Collection Complete ===" -ForegroundColor Green
Write-Host "Evidence artifacts saved to: $OutputDir"
