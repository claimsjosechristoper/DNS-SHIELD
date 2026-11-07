<#
.SYNOPSIS
    DNS-SHIELD Emergency Network DNS Recovery Script.
.DESCRIPTION
    Restores physical network adapters to original DNS settings while:
    1. Preserving any later administrator changes (only touches adapters pointing to loopback).
    2. Restoring exact static configurations without converting static adapters to DHCP.
    3. Safely removing only DNS-SHIELD owned filtering objects.
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

            # 1. Check if adapter current DNS points to loopback
            $CurrentServers = (Get-DnsClientServerAddress -InterfaceAlias $Alias -ErrorAction SilentlyContinue).ServerAddresses
            $HasLoopback = ($CurrentServers -contains "127.0.0.1") -or ($CurrentServers -contains "::1")

            if (-not $HasLoopback -and $CurrentServers) {
                Write-Host "[+] Preserving later administrator DNS configuration on '$Alias'. Skipping overwrite." -ForegroundColor Green
                continue
            }

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
        Write-Warning "[-] Error reading backup file: $_. Attempting targeted adapter inspection."
        $FallbackTargeted = $true
    }
} else {
    Write-Host "[!] No backup file found. Inspecting adapters for trapped loopback configuration..." -ForegroundColor Yellow
    $FallbackTargeted = $true
}

if ($FallbackTargeted) {
    $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
    foreach ($adapter in $Adapters) {
        $Alias = $adapter.Name
        $CurrentServers = (Get-DnsClientServerAddress -InterfaceAlias $Alias -ErrorAction SilentlyContinue).ServerAddresses
        $IsTrapped = ($CurrentServers -contains "127.0.0.1") -or ($CurrentServers -contains "::1")

        if (-not $IsTrapped) {
            Write-Host "[*] Adapter '$Alias' is not pointing to loopback. Preserving existing configuration." -ForegroundColor Gray
            continue
        }

        # Check if IP assignment is DHCP
        $IsDhcp = ((Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp -eq "Enabled")
        if ($IsDhcp) {
            Write-Host "[*] Trapped adapter '$Alias' uses DHCP: resetting DNS to DHCP..." -ForegroundColor Yellow
            netsh interface ipv4 set dnsservers name="$Alias" source=dhcp | Out-Null
            netsh interface ipv6 set dnsservers name="$Alias" source=dhcp | Out-Null
        } else {
            # Static IP: Preserve static configuration and set DNS to default gateway
            $gw = (Get-NetRoute -InterfaceAlias $Alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
            if ($gw -and $gw -ne "0.0.0.0") {
                Write-Host "[*] Trapped adapter '$Alias' has STATIC IP. Preserving static configuration and setting DNS to gateway: $gw" -ForegroundColor Yellow
                netsh interface ipv4 set dnsservers name="$Alias" source=static address="$gw" validate=no | Out-Null
            } else {
                Write-Host "[*] Trapped adapter '$Alias' has STATIC IP with no default gateway. Setting DNS to 1.1.1.1 fallback." -ForegroundColor Yellow
                netsh interface ipv4 set dnsservers name="$Alias" source=static address="1.1.1.1" validate=no | Out-Null
            }
        }
    }
}

# Remove only owned DNS-SHIELD Firewall rules
Write-Host "[*] Removing owned DNS-SHIELD firewall rules..."
try {
    Remove-NetFirewallRule -Name "DNSShield*" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] DNS-SHIELD firewall rules removed." -ForegroundColor Green
} catch {
    Write-Warning "[-] Error removing firewall rules: $_"
}

# Flush DNS Cache
Write-Host "[*] Flushing Windows DNS client cache..."
Clear-DnsClientCache
Write-Host "[+] DNS Cache flushed." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  RECOVERY COMPLETED SUCCESSFULLY." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
