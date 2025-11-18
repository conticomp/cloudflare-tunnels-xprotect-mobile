<#
.SYNOPSIS
    Setup Cloudflare Tunnel for Milestone XProtect Mobile Server

.DESCRIPTION
    This script automates the deployment of Cloudflare Tunnel for XProtect Mobile Server.
    It creates a tunnel, installs cloudflared, configures routing, and fixes CORS headers
    to enable video streaming through the Cloudflare tunnel.

.NOTES
    Version: 1.4.0
    Author: @conticomp (https://github.com/conticomp)
    Requires: PowerShell 5.1, Administrator privileges, XProtect Mobile Server installed

.CREDITS
    Script created by @conticomp (https://github.com/conticomp)

    Based on community implementations:
    - YouTube tutorial by Joshua J
    - Reddit solutions by joshooaj (Milestone employee)
    - Cloudflare Tunnel documentation
    - MilestonePSTools module patterns

    Please preserve this attribution when sharing or modifying this script.

.EXAMPLE
    .\Setup-XProtectCloudflare.ps1
    Run the script interactively with prompts for all configuration values

.DISCLAIMER
    This script is provided "as-is" without warranty of any kind, express or implied.
    Use at your own risk. The author(s) are not liable for any damages or issues
    arising from the use of this script. Always test in a non-production environment.
    Not officially supported by Milestone Systems or Cloudflare.
#>

[CmdletBinding()]
param()

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Script version
$ScriptVersion = "1.4.0"

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

###############################################################################
# SECTION 1: PREREQUISITES CHECK
###############################################################################

Write-Host @"

================================================================================
  Cloudflare Tunnel Setup for XProtect Mobile Server v$ScriptVersion
================================================================================

"@ -ForegroundColor Cyan

Write-Host "Checking prerequisites..." -ForegroundColor Green

# Check PowerShell version
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw "This script requires PowerShell 5.1 or later. Current version: $($PSVersionTable.PSVersion)"
}

if ($PSVersionTable.PSVersion -ge [version]'6.0') {
    Write-Warning "This script was designed for Windows PowerShell 5.1. You are running PowerShell $($PSVersionTable.PSVersion). Some features may not work as expected."
}

# Check for 64-bit PowerShell
if ($env:PROCESSOR_ARCHITECTURE -eq 'x86') {
    throw "This script requires 64-bit PowerShell but appears to be running in 32-bit mode."
}

# Check for administrator privileges
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $principal.IsInRole($adminRole)) {
    throw "This script must be run as Administrator."
}

# Check for XProtect Mobile Server service
Write-Host "  [✓] Checking for XProtect Mobile Server..." -ForegroundColor Gray
$mobileServer = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'Milestone XProtect Mobile Server'" -ErrorAction SilentlyContinue
if ($null -eq $mobileServer) {
    throw "Milestone XProtect Mobile Server service not found. Please ensure XProtect Mobile Server is installed."
}
Write-Host "    Found: $($mobileServer.DisplayName) (Status: $($mobileServer.State))" -ForegroundColor Gray

# Locate the Mobile Server config file
$mobileServerConfigPath = "C:\Program Files\Milestone\XProtect Mobile Server\VideoOS.MobileServer.Service.exe.config"
if (-not (Test-Path $mobileServerConfigPath)) {
    throw "Mobile Server configuration file not found at: $mobileServerConfigPath"
}
Write-Host "  [✓] Mobile Server config file found" -ForegroundColor Gray

# Check internet connectivity
Write-Host "  [✓] Checking internet connectivity..." -ForegroundColor Gray
try {
    $null = Test-NetConnection -ComputerName "api.cloudflare.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Host "    Can reach Cloudflare API" -ForegroundColor Gray
} catch {
    throw "Cannot reach Cloudflare API at api.cloudflare.com:443. Please check your internet connection."
}

Write-Host "`n[✓] All prerequisites met!`n" -ForegroundColor Green

###############################################################################
# SECTION 2: GATHER CONFIGURATION INFORMATION
###############################################################################

Write-Host "================================================================================`n" -ForegroundColor Cyan
Write-Host "Configuration Input" -ForegroundColor Cyan
Write-Host "================================================================================`n" -ForegroundColor Cyan

Write-Host "Please provide the following information:`n" -ForegroundColor Yellow

# Customer name
$customerName = Read-Host "Customer name (e.g., 'acmecorp')"
while ([string]::IsNullOrWhiteSpace($customerName)) {
    Write-Host "Customer name cannot be empty." -ForegroundColor Red
    $customerName = Read-Host "Customer name (e.g., 'acmecorp')"
}
$customerName = $customerName.ToLower() -replace '[^a-z0-9-]', '-'

# Location name
$locationName = Read-Host "Location name (e.g., 'chicago', 'hq')"
while ([string]::IsNullOrWhiteSpace($locationName)) {
    Write-Host "Location name cannot be empty." -ForegroundColor Red
    $locationName = Read-Host "Location name (e.g., 'chicago', 'hq')"
}
$locationName = $locationName.ToLower() -replace '[^a-z0-9-]', '-'

# Tunnel name will be: customer-location
$tunnelName = "$customerName-$locationName"
Write-Host "  → Tunnel name will be: $tunnelName" -ForegroundColor Gray

# Domain name (must exist in Cloudflare)
Write-Host "`nDomain Configuration:" -ForegroundColor Yellow
Write-Host "  Note: Your domain must already be added to Cloudflare with active DNS." -ForegroundColor Gray

$domainName = Read-Host "Domain name (must exist in Cloudflare)"
while ([string]::IsNullOrWhiteSpace($domainName)) {
    Write-Host "Domain name cannot be empty." -ForegroundColor Red
    $domainName = Read-Host "Domain name (must exist in Cloudflare)"
}

# Subdomain for this server (default to customer-location)
$defaultSubdomain = $tunnelName
Write-Host "`n  The subdomain will be used to create the public URL." -ForegroundColor Gray
$subdomainInput = Read-Host "Subdomain [$defaultSubdomain]"
if ([string]::IsNullOrWhiteSpace($subdomainInput)) {
    $subdomain = $defaultSubdomain
    Write-Host "  → Using default: $subdomain" -ForegroundColor Gray
} else {
    $subdomain = $subdomainInput.ToLower() -replace '[^a-z0-9-]', '-'
}

# Full hostname will be: subdomain.domain
$publicHostname = "$subdomain.$domainName"
Write-Host "  → Public URL will be: https://$publicHostname" -ForegroundColor Gray

# Cloudflare credentials
Write-Host "`nCloudflare API Credentials:" -ForegroundColor Yellow
Write-Host "  You need an API token with permissions:" -ForegroundColor Gray
Write-Host "    - Account > Cloudflare Tunnel > Edit" -ForegroundColor Gray
Write-Host "    - Zone > DNS > Edit" -ForegroundColor Gray
Write-Host "  Create token at: https://dash.cloudflare.com/profile/api-tokens`n" -ForegroundColor Gray

$accountId = Read-Host "Cloudflare Account ID"
while ([string]::IsNullOrWhiteSpace($accountId)) {
    Write-Host "Account ID cannot be empty." -ForegroundColor Red
    $accountId = Read-Host "Cloudflare Account ID"
}

$apiTokenSecure = Read-Host "Cloudflare API Token" -AsSecureString
$apiToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiTokenSecure)
)
while ([string]::IsNullOrWhiteSpace($apiToken)) {
    Write-Host "API Token cannot be empty." -ForegroundColor Red
    $apiTokenSecure = Read-Host "Cloudflare API Token" -AsSecureString
    $apiToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiTokenSecure)
    )
}

# Summary
Write-Host "`n================================================================================`n" -ForegroundColor Cyan
Write-Host "Configuration Summary:" -ForegroundColor Yellow
Write-Host "  Tunnel Name:      $tunnelName" -ForegroundColor White
Write-Host "  Public Hostname:  $publicHostname" -ForegroundColor White
Write-Host "  Backend Service:  http://localhost:8081" -ForegroundColor White
Write-Host "  Cloudflare Account: $accountId" -ForegroundColor White
Write-Host "`n================================================================================`n" -ForegroundColor Cyan

$confirmation = Read-Host "Proceed with this configuration? (Y/N)"
if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
    Write-Host "Setup cancelled by user." -ForegroundColor Yellow
    exit 0
}

###############################################################################
# SECTION 3: HELPER FUNCTIONS
###############################################################################

function Invoke-CloudflareAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter()]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        [string]$ApiToken
    )

    $headers = @{
        "Authorization" = "Bearer $ApiToken"
        "Content-Type" = "application/json"
    }

    $uri = "https://api.cloudflare.com/client/v4$Endpoint"

    $params = @{
        Uri = $uri
        Method = $Method
        Headers = $headers
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }

    try {
        $response = Invoke-RestMethod @params

        if (-not $response.success) {
            $errorMessages = ($response.errors | ForEach-Object { $_.message }) -join '; '
            throw "Cloudflare API error: $errorMessages"
        }

        return $response.result
    }
    catch {
        throw "Failed to call Cloudflare API: $_"
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console with color
    switch ($Level) {
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage -ForegroundColor White }
    }

    # Also write to log file
    $logFile = Join-Path $env:TEMP "XProtectCloudflare-Setup-$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage
}

###############################################################################
# SECTION 4: CREATE CLOUDFLARE TUNNEL
###############################################################################

Write-Host "`n[1/6] Configuring Cloudflare Tunnel..." -ForegroundColor Cyan

try {
    # Check if tunnel with this name already exists
    Write-Log "Checking for existing tunnel named: $tunnelName"

    $existingTunnels = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel?name=$tunnelName" `
                                            -Method GET `
                                            -ApiToken $apiToken

    $tunnelId = $null
    $tunnelToken = $null

    # Force into array to handle both single object and array responses
    $tunnelArray = @($existingTunnels)

    if ($tunnelArray -and $tunnelArray.Count -gt 0 -and $null -ne $tunnelArray[0]) {
        # Tunnel with this name exists
        $existingTunnel = $tunnelArray[0]

        Write-Host "`n  Tunnel with name '$tunnelName' already exists!" -ForegroundColor Yellow
        Write-Host "  Tunnel ID: $($existingTunnel.id)" -ForegroundColor Gray
        Write-Host "  Created: $($existingTunnel.created_at)" -ForegroundColor Gray

        # Check connection status
        if ($existingTunnel.connections -and $existingTunnel.connections.Count -gt 0) {
            Write-Host "  Status: Connected ($($existingTunnel.connections.Count) connection(s))" -ForegroundColor Green
        } else {
            Write-Host "  Status: Not connected" -ForegroundColor Yellow
        }

        Write-Host "`n  What would you like to do?" -ForegroundColor Yellow
        Write-Host "    [U]se existing tunnel" -ForegroundColor White
        Write-Host "    [D]elete and create new tunnel" -ForegroundColor White
        Write-Host "    [E]xit script" -ForegroundColor White

        $choice = Read-Host "`n  Choice (U/D/E)"

        switch ($choice.ToUpper()) {
            'U' {
                Write-Log "Using existing tunnel" -Level Success
                $tunnelId = $existingTunnel.id

                # Get tunnel token from the token endpoint
                Write-Log "Retrieving tunnel token..."
                $tunnelToken = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel/$tunnelId/token" `
                                                     -Method GET `
                                                     -ApiToken $apiToken

                if ([string]::IsNullOrWhiteSpace($tunnelToken)) {
                    throw "Failed to retrieve tunnel token for existing tunnel"
                }

                Write-Log "  Tunnel ID: $tunnelId"
                Write-Log "  Token retrieved successfully"
            }
            'D' {
                Write-Log "Deleting existing tunnel..." -Level Warning

                # Delete the existing tunnel
                $null = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel/$($existingTunnel.id)" `
                                            -Method DELETE `
                                            -ApiToken $apiToken

                Write-Log "Existing tunnel deleted"
                Start-Sleep -Seconds 2

                # Create new tunnel
                Write-Log "Creating new tunnel: $tunnelName"

                $tunnelBody = @{
                    name = $tunnelName
                    config_src = "cloudflare"
                }

                $tunnel = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel" `
                                                -Method POST `
                                                -Body $tunnelBody `
                                                -ApiToken $apiToken

                $tunnelId = $tunnel.id
                $tunnelToken = $tunnel.token

                Write-Log "New tunnel created successfully!" -Level Success
                Write-Log "  Tunnel ID: $tunnelId"
            }
            'E' {
                Write-Host "`nExiting script as requested." -ForegroundColor Yellow
                exit 0
            }
            default {
                Write-Host "`nInvalid choice. Exiting." -ForegroundColor Red
                exit 1
            }
        }
    } else {
        # No existing tunnel, create new one
        Write-Log "No existing tunnel found, creating new tunnel: $tunnelName"

        $tunnelBody = @{
            name = $tunnelName
            config_src = "cloudflare"
        }

        $tunnel = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel" `
                                        -Method POST `
                                        -Body $tunnelBody `
                                        -ApiToken $apiToken

        $tunnelId = $tunnel.id
        $tunnelToken = $tunnel.token

        Write-Log "Tunnel created successfully!" -Level Success
        Write-Log "  Tunnel ID: $tunnelId"
    }

    # Validate we have tunnel ID and token
    if ([string]::IsNullOrWhiteSpace($tunnelId) -or [string]::IsNullOrWhiteSpace($tunnelToken)) {
        throw "Failed to obtain tunnel ID or token"
    }

} catch {
    Write-Log "Failed to configure tunnel: $_" -Level Error
    throw
}

###############################################################################
# SECTION 5: INSTALL CLOUDFLARED
###############################################################################

Write-Host "`n[2/6] Configuring cloudflared..." -ForegroundColor Cyan

try {
    $installPath = "C:\Program Files\cloudflared"
    $cloudflaredExe = Join-Path $installPath "cloudflared.exe"

    # Create directory if it doesn't exist
    if (-not (Test-Path $installPath)) {
        Write-Log "Creating directory: $installPath"
        New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    }

    # Step 1: Check if cloudflared.exe exists
    $needsDownload = $false
    if (-not (Test-Path $cloudflaredExe)) {
        $needsDownload = $true
        Write-Log "cloudflared.exe not found, will download"
    } else {
        Write-Log "cloudflared.exe found at: $cloudflaredExe"
        # Get version
        try {
            $version = & $cloudflaredExe --version 2>&1 | Select-Object -First 1
            Write-Log "  Current version: $version"
        } catch {
            Write-Log "  Could not determine version"
        }
    }

    # Download if needed
    if ($needsDownload) {
        Write-Log "Downloading cloudflared..."
        $downloadUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $cloudflaredExe -UseBasicParsing
        Write-Log "Download complete"
    }

    # Step 2: Check if service exists
    $existingService = Get-Service -Name "cloudflared" -ErrorAction SilentlyContinue
    $needsInstall = $false
    $reconfigure = $false

    if ($existingService) {
        Write-Host "`n  cloudflared service already exists!" -ForegroundColor Yellow
        Write-Host "  Status: $($existingService.Status)" -ForegroundColor Gray
        Write-Host "`n  What would you like to do?" -ForegroundColor Yellow
        Write-Host "    [K]eep existing configuration and skip installation" -ForegroundColor White
        Write-Host "    [R]econfigure with new tunnel (will reinstall service)" -ForegroundColor White
        Write-Host "    [E]xit script" -ForegroundColor White

        $choice = Read-Host "`n  Choice (K/R/E)"

        switch ($choice.ToUpper()) {
            'K' {
                Write-Log "Keeping existing cloudflared configuration"
                # Check if service is running
                if ($existingService.Status -ne 'Running') {
                    Write-Log "Service is stopped, starting it..."
                    Start-Service -Name "cloudflared"
                    Start-Sleep -Seconds 3
                    $existingService = Get-Service -Name "cloudflared"
                    if ($existingService.Status -eq 'Running') {
                        Write-Log "Service started successfully" -Level Success
                    } else {
                        Write-Log "Service failed to start. Status: $($existingService.Status)" -Level Warning
                    }
                } else {
                    Write-Log "Service is already running" -Level Success
                }
            }
            'R' {
                Write-Log "User chose to reconfigure with new tunnel" -Level Warning
                $reconfigure = $true
                $needsInstall = $true
                # Service will be stopped and reinstalled with new token in the install section
                Write-Log "Will reinstall service with new tunnel token"
            }
            'E' {
                Write-Host "`nExiting script as requested." -ForegroundColor Yellow
                exit 0
            }
            default {
                Write-Host "`nInvalid choice. Exiting." -ForegroundColor Red
                exit 1
            }
        }
    } else {
        Write-Log "cloudflared service not found, will install"
        $needsInstall = $true
    }

    # Step 3: Install service if needed
    if ($needsInstall) {
        # If reconfiguring, stop the service first
        if ($reconfigure) {
            Write-Log "Stopping existing service for reconfiguration..."
            Stop-Service -Name "cloudflared" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        # Clean up any orphaned registry entries before installation
        # This prevents "registry key already exists" errors from previous failed installations
        Write-Log "Checking for orphaned registry entries..."
        $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\cloudflared"
        $altServiceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Cloudflared"
        $eventLogRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\cloudflared"
        $altEventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Cloudflared"

        $cleanedAny = $false

        if (Test-Path $serviceRegistryPath) {
            Write-Log "  Removing orphaned service registry (lowercase)..."
            Remove-Item -Path $serviceRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
            $cleanedAny = $true
        }

        if (Test-Path $altServiceRegistryPath) {
            Write-Log "  Removing orphaned service registry (capitalized)..."
            Remove-Item -Path $altServiceRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
            $cleanedAny = $true
        }

        if (Test-Path $eventLogRegistryPath) {
            Write-Log "  Removing orphaned event log registry (lowercase)..."
            Remove-Item -Path $eventLogRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
            $cleanedAny = $true
        }

        if (Test-Path $altEventLogPath) {
            Write-Log "  Removing orphaned event log registry (capitalized)..."
            Remove-Item -Path $altEventLogPath -Recurse -Force -ErrorAction SilentlyContinue
            $cleanedAny = $true
        }

        if ($cleanedAny) {
            Write-Log "Orphaned registry entries cleaned up successfully"
        } else {
            Write-Log "No orphaned registry entries found"
        }

        Write-Log "Installing cloudflared service with tunnel token..."

        # Capture both stdout and stderr
        # Note: service install will replace existing service if present
        # cloudflared writes informational messages to stderr, so temporarily allow it
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $installOutput = & $cloudflaredExe service install $tunnelToken 2>&1
        $ErrorActionPreference = $previousErrorActionPreference

        # Check if installation was successful
        Start-Sleep -Seconds 2
        $service = Get-Service -Name "cloudflared" -ErrorAction SilentlyContinue

        if ($null -eq $service) {
            Write-Log "Installation output: $installOutput" -Level Error
            throw "cloudflared service installation failed. Service was not created."
        }

        Write-Log "Service installed successfully"

        # Set startup type to Automatic to ensure service persists across reboots
        Write-Log "Configuring service to start automatically..."
        Set-Service -Name "cloudflared" -StartupType Automatic
        Write-Log "Service startup type set to Automatic"

        # Start the service
        Write-Log "Starting cloudflared service..."
        Start-Service -Name "cloudflared"

        # Verify service is running
        Start-Sleep -Seconds 3
        $service = Get-Service -Name "cloudflared"
        if ($service.Status -ne 'Running') {
            throw "cloudflared service failed to start. Status: $($service.Status)"
        }

        Write-Log "cloudflared service is running" -Level Success
    }

} catch {
    Write-Log "Failed to configure cloudflared: $_" -Level Error
    throw
}

###############################################################################
# SECTION 6: CONFIGURE TUNNEL ROUTE
###############################################################################

Write-Host "`n[3/6] Configuring tunnel route..." -ForegroundColor Cyan

try {
    Write-Log "Configuring ingress rule for $publicHostname"

    $configBody = @{
        config = @{
            ingress = @(
                @{
                    hostname = $publicHostname
                    service = "http://localhost:8081"
                },
                @{
                    service = "http_status:404"
                }
            )
        }
    }

    $null = Invoke-CloudflareAPI -Endpoint "/accounts/$accountId/cfd_tunnel/$tunnelId/configurations" `
                                  -Method PUT `
                                  -Body $configBody `
                                  -ApiToken $apiToken

    Write-Log "Tunnel route configured successfully" -Level Success

} catch {
    Write-Log "Failed to configure tunnel route: $_" -Level Error
    throw
}

###############################################################################
# SECTION 7: CREATE DNS RECORD
###############################################################################

Write-Host "`n[4/6] Creating DNS record..." -ForegroundColor Cyan

try {
    # First, get the zone ID for the domain
    Write-Log "Looking up zone ID for domain: $domainName"
    $zones = @(Invoke-CloudflareAPI -Endpoint "/zones?name=$domainName" `
                                     -Method GET `
                                     -ApiToken $apiToken)

    if ($zones.Count -eq 0) {
        throw "Domain '$domainName' not found in Cloudflare account. Please add the domain to Cloudflare first."
    }

    $zoneId = $zones[0].id
    Write-Log "  Zone ID: $zoneId"

    # Check if DNS record already exists
    $existingRecords = @(Invoke-CloudflareAPI -Endpoint "/zones/$zoneId/dns_records?name=$publicHostname" `
                                              -Method GET `
                                              -ApiToken $apiToken)

    if ($existingRecords.Count -gt 0) {
        Write-Log "DNS record already exists for $publicHostname - updating..." -Level Warning
        $recordId = $existingRecords[0].id

        $dnsBody = @{
            type = "CNAME"
            name = $subdomain
            content = "$tunnelId.cfargotunnel.com"
            proxied = $true
        }

        $null = Invoke-CloudflareAPI -Endpoint "/zones/$zoneId/dns_records/$recordId" `
                                      -Method PUT `
                                      -Body $dnsBody `
                                      -ApiToken $apiToken

        Write-Log "DNS record updated" -Level Success
    } else {
        Write-Log "Creating new DNS CNAME record..."

        $dnsBody = @{
            type = "CNAME"
            name = $subdomain
            content = "$tunnelId.cfargotunnel.com"
            proxied = $true
            comment = "XProtect Mobile Server tunnel"
        }

        $null = Invoke-CloudflareAPI -Endpoint "/zones/$zoneId/dns_records" `
                                      -Method POST `
                                      -Body $dnsBody `
                                      -ApiToken $apiToken

        Write-Log "DNS record created successfully" -Level Success
    }

} catch {
    Write-Log "Failed to create DNS record: $_" -Level Error
    throw
}

###############################################################################
# SECTION 8: FIX CORS FOR VIDEO STREAMING
###############################################################################

Write-Host "`n[5/6] Configuring CORS headers for video streaming..." -ForegroundColor Cyan

try {
    Write-Log "Loading Mobile Server configuration file..."

    # Load the XML configuration
    [xml]$config = Get-Content $mobileServerConfigPath

    # Find the ServerSetings/HttpHeaders section
    $httpHeaders = $config.configuration.ServerSetings.HttpHeaders

    if ($null -eq $httpHeaders) {
        throw "ServerSetings/HttpHeaders section not found in configuration file"
    }

    # Look for existing Access-Control-Allow-Origin setting
    $corsOriginValue = $publicHostname  # Just the domain, no https://
    $corsNode = $httpHeaders.add | Where-Object { $_.key -eq 'Access-Control-Allow-Origin' }

    if ($null -eq $corsNode) {
        throw "Access-Control-Allow-Origin key not found in configuration file. Please verify XProtect Mobile Server installation."
    }

    # Always show current value
    $currentValue = $corsNode.value
    Write-Host "`n  Current CORS value: '$currentValue'" -ForegroundColor Gray

    # Check if we need to update
    $shouldUpdate = $false
    if ([string]::IsNullOrWhiteSpace($currentValue)) {
        # Empty value, update without prompting
        Write-Log "CORS value is empty, will set to: $corsOriginValue"
        $shouldUpdate = $true
    }
    elseif ($currentValue -eq $corsOriginValue) {
        # Same value, update anyway to be idempotent
        Write-Log "CORS value already matches: $corsOriginValue"
        $shouldUpdate = $true
    }
    else {
        # Different value, prompt user
        Write-Host "`n  CORS is currently set to a different value." -ForegroundColor Yellow
        Write-Host "  New value will be: $corsOriginValue" -ForegroundColor Cyan
        $response = Read-Host "`n  Overwrite existing CORS configuration? (Y/N)"

        if ($response -eq 'Y' -or $response -eq 'y') {
            Write-Log "User chose to overwrite CORS value"
            $shouldUpdate = $true
        } else {
            Write-Log "Keeping existing CORS configuration: $currentValue" -Level Warning
            Write-Host "`n  Skipping CORS update. Existing value retained." -ForegroundColor Yellow
            $shouldUpdate = $false
        }
    }

    # Update if needed
    if ($shouldUpdate) {
        Write-Log "Updating CORS header to: $corsOriginValue"
        $corsNode.value = $corsOriginValue

        # Save the configuration
        Write-Log "Saving configuration file..."
        $config.Save($mobileServerConfigPath)

        # Stop the Mobile Server service
        Write-Log "Stopping Mobile Server service..."
        Stop-Service -Name "Milestone XProtect Mobile Server" -Force

        # Wait for service to fully stop
        Write-Log "Waiting for service to stop..."
        $timeout = 30  # seconds
        $elapsed = 0
        do {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $service = Get-Service -Name "Milestone XProtect Mobile Server"
            if ($service.Status -eq 'Stopped') {
                Write-Log "Service stopped successfully"
                break
            }
        } while ($elapsed -lt $timeout)

        if ($service.Status -ne 'Stopped') {
            throw "Mobile Server service failed to stop within ${timeout}s. Status: $($service.Status)"
        }

        # Start the Mobile Server service
        Write-Log "Starting Mobile Server service..."
        Start-Service -Name "Milestone XProtect Mobile Server"

        # Wait for service to be running
        Write-Log "Waiting for service to start..."
        $timeout = 30  # seconds
        $elapsed = 0
        do {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $service = Get-Service -Name "Milestone XProtect Mobile Server"
            if ($service.Status -eq 'Running') {
                Write-Log "Service started successfully"
                break
            }
        } while ($elapsed -lt $timeout)

        if ($service.Status -ne 'Running') {
            throw "Mobile Server service failed to start within ${timeout}s. Status: $($service.Status)"
        }

        Write-Log "CORS configuration applied and service restarted" -Level Success
    } else {
        Write-Log "CORS configuration unchanged" -Level Info
    }

} catch {
    Write-Log "Failed to configure CORS: $_" -Level Error
    throw
}

###############################################################################
# SECTION 9: VALIDATION
###############################################################################

Write-Host "`n[6/6] Validating setup..." -ForegroundColor Cyan

try {
    # Check cloudflared service
    $cloudflaredService = Get-Service -Name "cloudflared"
    if ($cloudflaredService.Status -eq 'Running') {
        Write-Log "  [✓] cloudflared service is running" -Level Success
    } else {
        Write-Log "  [✗] cloudflared service is not running!" -Level Error
    }

    # Check startup type
    if ($cloudflaredService.StartType -eq 'Automatic') {
        Write-Log "  [✓] cloudflared startup type is Automatic" -Level Success
    } else {
        Write-Log "  [!] cloudflared startup type is $($cloudflaredService.StartType) (should be Automatic)" -Level Warning
    }

    # Check Mobile Server service
    $mobileServerService = Get-Service -Name "Milestone XProtect Mobile Server"
    if ($mobileServerService.Status -eq 'Running') {
        Write-Log "  [✓] Mobile Server service is running" -Level Success
    } else {
        Write-Log "  [✗] Mobile Server service is not running!" -Level Error
    }

    # Test DNS resolution
    Write-Log "Testing DNS resolution for $publicHostname..."
    Start-Sleep -Seconds 5  # Give DNS a moment to propagate

    try {
        $dnsResult = Resolve-DnsName -Name $publicHostname -ErrorAction Stop
        Write-Log "  [✓] DNS resolves to: $($dnsResult.IPAddress -join ', ')" -Level Success
    } catch {
        Write-Log "  [!] DNS not yet propagated (this is normal, may take a few minutes)" -Level Warning
    }

    Write-Host "`n" -NoNewline
    Write-Log "Setup validation complete!" -Level Success

} catch {
    Write-Log "Validation encountered errors: $_" -Level Warning
}

###############################################################################
# SECTION 10: SUCCESS MESSAGE
###############################################################################

Write-Host "`n`n" -NoNewline
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  ✓ Cloudflare Tunnel Setup Complete!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green

Write-Host "`nConfiguration Details:" -ForegroundColor Yellow
Write-Host "  Tunnel Name:          $tunnelName" -ForegroundColor White
Write-Host "  Tunnel ID:            $tunnelId" -ForegroundColor White
Write-Host "  Public URL:           https://$publicHostname" -ForegroundColor White
Write-Host "  Backend Service:      http://localhost:8081" -ForegroundColor White
Write-Host "  CORS Origin:          $publicHostname" -ForegroundColor White

Write-Host "`n⏱️  IMPORTANT - Tunnel Propagation:" -ForegroundColor Yellow
Write-Host "  Please wait 2-5 minutes for DNS propagation and tunnel" -ForegroundColor Cyan
Write-Host "  initialization before testing the URL. This is normal!" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. ⏰ Wait 2-5 minutes for tunnel to become active" -ForegroundColor White
Write-Host "  2. Open your browser to: https://$publicHostname" -ForegroundColor Cyan
Write-Host "  3. Login with your XProtect credentials" -ForegroundColor White
Write-Host "  4. Verify that video streaming works!" -ForegroundColor White

Write-Host "`nImportant Notes:" -ForegroundColor Yellow
Write-Host "  • The connection uses Cloudflare's SSL certificate (Flexible SSL mode)" -ForegroundColor Gray
Write-Host "  • Traffic from Cloudflare to your server is currently HTTP (port 8081)" -ForegroundColor Gray
Write-Host "  • To add Let's Encrypt certificates, run the Phase 2 script (coming soon)" -ForegroundColor Gray
Write-Host "  • No changes were made to Management Client configuration" -ForegroundColor Gray

Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
Write-Host "  • If login works but no video: Check browser console for CORS errors" -ForegroundColor Gray
Write-Host "  • If connection fails: Verify cloudflared service is running" -ForegroundColor Gray
Write-Host "  • Service management: Services.msc > cloudflared" -ForegroundColor Gray
Write-Host "  • Logs location: $env:TEMP\XProtectCloudflare-Setup-*.log" -ForegroundColor Gray

Write-Host "`nCloudflare Dashboard:" -ForegroundColor Yellow
Write-Host "  View your tunnel at:" -ForegroundColor White
Write-Host "  https://one.dash.cloudflare.com/$accountId/networks/tunnels/$tunnelId" -ForegroundColor Cyan

Write-Host "`n================================================================================" -ForegroundColor Green

# Save tunnel info to file for reference
$infoFile = Join-Path $env:USERPROFILE "Desktop\CloudflareTunnel-$tunnelName.txt"
@"
Cloudflare Tunnel Information
==============================
Created: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Tunnel Name: $tunnelName
Tunnel ID: $tunnelId
Public URL: https://$publicHostname
Backend: http://localhost:8081

Cloudflare Account ID: $accountId
Dashboard: https://one.dash.cloudflare.com/$accountId/networks/tunnels/$tunnelId

Services:
  - cloudflared: $(Get-Service cloudflared | Select-Object -ExpandProperty Status)
  - Mobile Server: $(Get-Service 'Milestone XProtect Mobile Server' | Select-Object -ExpandProperty Status)

Configuration:
  - CORS Origin: $publicHostname
  - Config File: $mobileServerConfigPath

Note: Wait 2-5 minutes for tunnel propagation before testing the URL.
"@ | Out-File -FilePath $infoFile -Encoding UTF8

Write-Host "`nTunnel information saved to: $infoFile`n" -ForegroundColor Gray

# End of script
