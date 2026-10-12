<#
.SYNOPSIS
    DNS-SHIELD Emergency Network DNS Recovery Script.
.DESCRIPTION
    Restores all physical network adapters to original DHCP or static DNS addresses
    from %ProgramData%\DNS-SHIELD\dns_backup.json, or resets adapters to DHCP if no backup exists.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  DNS-SHIELD EMERGENCY NETWORK RECOVERY TOOL" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$BackupPath = "$env:ProgramData\DNS-SHIELD\dns_backup.json"

if (Test-Path $BackupPath) {
    Write-Host "[+] Found configuration backup at $BackupPath" -ForegroundColor Green
    try {
        $Snapshot = Get-Content $BackupPath -Raw | ConvertFrom-Json
        foreach ($prop in $Snapshot.PSObject.Properties) {
            $Alias = $prop.Name
            $Config = $prop.Value
            Write-Host "[*] Restoring adapter: $Alias" -ForegroundColor Yellow

            # Restore IPv4
            if ($Config.ipv4_dhcp -or -not $Config.ipv4_servers) {
                Write-Host "    -> Resetting IPv4 DNS to DHCP"
                netsh interface ipv4 set dnsservers name="$Alias" source=dhcp | Out-Null
            } else {
                $Primary = $Config.ipv4_servers[0]
                Write-Host "    -> Restoring static IPv4 primary DNS: $Primary"
                netsh interface ipv4 set dnsservers name="$Alias" source=static address="$Primary" validate=no | Out-Null
                for ($i = 1; $i -lt $Config.ipv4_servers.Count; $i++) {
                    $Sec = $Config.ipv4_servers[$i]
                    netsh interface ipv4 add dnsservers name="$Alias" address="$Sec" validate=no | Out-Null
                }
            }

            # Restore IPv6
            if ($Config.ipv6_dhcp -or -not $Config.ipv6_servers) {
                Write-Host "    -> Resetting IPv6 DNS to DHCP"
                netsh interface ipv6 set dnsservers name="$Alias" source=dhcp | Out-Null
            } else {
                $Primary6 = $Config.ipv6_servers[0]
                Write-Host "    -> Restoring static IPv6 primary DNS: $Primary6"
                netsh interface ipv6 set dnsservers name="$Alias" source=static address="$Primary6" validate=no | Out-Null
                for ($i = 1; $i -lt $Config.ipv6_servers.Count; $i++) {
                    $Sec6 = $Config.ipv6_servers[$i]
                    netsh interface ipv6 add dnsservers name="$Alias" address="$Sec6" validate=no | Out-Null
                }
            }
        }
        Remove-Item $BackupPath -Force
        Write-Host "[+] Recovery backup removed. Adapters restored successfully." -ForegroundColor Green
    } catch {
        Write-Warning "[-] Error reading backup file: $_. Falling back to universal DHCP reset."
        $FallbackDHCP = $true
    }
} else {
    Write-Host "[!] No backup file found. Resetting active physical adapters to DHCP..." -ForegroundColor Yellow
    $FallbackDHCP = $true
}

if ($FallbackDHCP) {
    $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
    foreach ($adapter in $Adapters) {
        Write-Host "[*] Resetting adapter '$($adapter.Name)' to DHCP..." -ForegroundColor Yellow
        netsh interface ipv4 set dnsservers name="$($adapter.Name)" source=dhcp | Out-Null
        netsh interface ipv6 set dnsservers name="$($adapter.Name)" source=dhcp | Out-Null
    }
    Write-Host "[+] All physical adapters reset to DHCP." -ForegroundColor Green
}

# Flush DNS Cache
Write-Host "[*] Flushing Windows DNS client cache..."
Clear-DnsClientCache
Write-Host "[+] DNS Cache flushed." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  RECOVERY COMPLETED SUCCESSFULLY." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
