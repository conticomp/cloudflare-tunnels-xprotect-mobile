# Cloudflare Tunnel Setup for XProtect Mobile Server

Automate the deployment of Cloudflare Tunnels for Milestone XProtect Mobile Server with working video streaming.

## Overview

This PowerShell automation script creates a secure Cloudflare Tunnel that allows external access to your XProtect Mobile Server **without opening firewall ports or exposing your server's IP address**. It automatically configures the critical CORS headers needed for video streaming to work properly.

**The Problem It Solves:** By default, XProtect Mobile Server login works through Cloudflare tunnels, but video streaming fails with WebSocket errors. This script fixes that automatically.

## ⚠️ Disclaimer

This software is provided **"as-is" without any warranty of any kind**, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

**Use at your own risk.** The author(s) are not liable for any damages, data loss, or issues arising from the use of this software. Always test in a non-production environment first.

**Not officially supported by Milestone Systems or Cloudflare.** This is a community automation project.

## What Setup-XProtectCloudflare.ps1 Does

The setup script performs these tasks automatically:

1. ✅ **Verifies Prerequisites** - Checks for XProtect Mobile Server, Administrator privileges, and internet connectivity
2. ✅ **Creates Cloudflare Tunnel** - Sets up a secure tunnel with your specified naming convention
3. ✅ **Installs cloudflared Service** - Downloads and installs cloudflared.exe as a Windows service
4. ✅ **Configures Routing** - Sets up ingress rules to route traffic from your public hostname to the Mobile Server
5. ✅ **Creates DNS Records** - Automatically creates CNAME records in Cloudflare DNS
6. ✅ **Fixes CORS Headers** - The critical fix! Modifies the Mobile Server config to enable video streaming
7. ✅ **Validates Setup** - Tests that all services are running and DNS is resolving

**Total Setup Time:** ~5-10 minutes (most of which is automated)

## Prerequisites

### System Requirements

- **Windows Server** (2016 or later recommended)
- **PowerShell 5.1** (already included in Windows Server)
- **64-bit architecture**
- **Administrator privileges**
- **Milestone XProtect Mobile Server** installed and running

### Cloudflare Requirements

- Active Cloudflare account (free tier works)
- Domain added to Cloudflare with active zone
- DNS managed by Cloudflare (nameservers pointed to Cloudflare)
- API token with appropriate permissions (see below)

### Network Requirements

- Internet connectivity from the server
- Outbound access to:
  - `api.cloudflare.com:443` (HTTPS)
  - `github.com:443` (for cloudflared download)
  - Cloudflare edge servers on port `7844` (TCP/UDP)

## Cloudflare API Token Setup

You need to create an API token with the following permissions:

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click **"Create Token"**
3. Use **"Edit Cloudflare Tunnel"** template or create custom token with:
   - **Account** > Cloudflare Tunnel > **Edit**
   - **Zone** > DNS > **Edit**
4. Select your specific account and zones
5. Create token and **save it securely** (you'll need it during setup)

### Finding Your Account ID

1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain
3. Scroll down on the Overview page
4. Find **Account ID** in the right sidebar under "API"

## How It Works

### The Traffic Flow

```
User's Browser (HTTPS)
    ↓
Cloudflare Global Network
  • SSL Termination
  • DDoS Protection
  • CDN Caching
    ↓
Encrypted Tunnel (Outbound Port 7844)
    ↓
cloudflared.exe (Windows Service on your server)
    ↓
XProtect Mobile Server (HTTP on localhost:8081)
```

**Key Benefits:**
- **No Inbound Ports:** The tunnel connects outbound from your server, so no firewall changes needed
- **Automatic SSL:** Cloudflare provides the SSL certificate automatically
- **Security:** Your server's IP address is never exposed
- **DDoS Protection:** Cloudflare's network protects you from attacks

### The Critical CORS Fix

The script modifies this file:
```
C:\Program Files\Milestone\XProtect Mobile Server\VideoOS.MobileServer.Service.exe.config
```

It updates the `Access-Control-Allow-Origin` header to match your public hostname. **Without this fix, login will work but video streaming will fail** with WebSocket errors in the browser console.

---

## Step-by-Step Usage Guide

Follow these steps to set up your Cloudflare Tunnel. Don't worry - the script is interactive and will guide you through each step!

### Step 1: Prepare Your Cloudflare Account

Before running the script, you need a Cloudflare API token with the right permissions.

**Create an API Token:**

1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click **"Create Token"**
3. Use the **"Edit Cloudflare Tunnel"** template, or create a custom token with these permissions:
   - **Account** > Cloudflare Tunnel > **Edit**
   - **Zone** > DNS > **Edit**
4. Select your specific account and zones
5. Click **"Continue to summary"** → **"Create Token"**
6. **Copy and save the token** - you'll need it in Step 4

> **Pro Tip:** Store the API token in a password manager. You'll only see it once!

**Find Your Account ID:**

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain
3. Scroll down on the Overview page
4. Look in the right sidebar under "API" section
5. Copy your **Account ID**

> **Note:** Your domain must already be added to Cloudflare and using Cloudflare's nameservers. If you haven't done this yet, add your domain in Cloudflare first.

---

### Step 2: Download the Script

1. Download `Setup-XProtectCloudflare.ps1` to your XProtect Mobile Server
2. Place it in a convenient location like `C:\CloudflareTunnel\`

---

### Step 3: Prepare PowerShell

**Open PowerShell as Administrator:**

1. Press **Windows Key**
2. Type `PowerShell`
3. Right-click **Windows PowerShell**
4. Select **"Run as administrator"**

**Check Execution Policy:**

```powershell
Get-ExecutionPolicy
```

If it returns `Restricted`, you need to allow script execution:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

> **What This Does:** Allows you to run locally created scripts. Scripts downloaded from the internet will require confirmation.

---

### Step 4: Run the Setup Script

Navigate to where you saved the script:

```powershell
cd C:\CloudflareTunnel
.\Setup-XProtectCloudflare.ps1
```

The script will now guide you through the setup process interactively.

---

### Step 5: Answer the Configuration Prompts

The script will ask for several pieces of information. Here's what each means and how to answer:

#### **Customer Name**
```
Customer name (e.g., 'acmecorp'):
```
- Enter a short name for this customer/organization
- **Examples:** `acmecorp`, `smithinc`, `cityschools`
- Will be converted to lowercase and sanitized (spaces become dashes)
- Used as part of the tunnel name

#### **Location Name**
```
Location name (e.g., 'chicago', 'hq'):
```
- Enter a short name for this specific location
- **Examples:** `chicago`, `newyork`, `headquarters`, `warehouse1`
- Will be converted to lowercase and sanitized
- Combined with customer name to create tunnel name: `acmecorp-chicago`

> **Pro Tip:** Use consistent naming across locations. If you have multiple sites, this makes management much easier!

#### **Domain Name**
```
Domain name [example.com]:
```
- Enter your domain that's already configured in Cloudflare
- **Examples:** `example.com`, `yourdomain.net`, `security.company.com`
- Press **Enter** to use the default: `example.com`
- **Important:** This domain must already exist in your Cloudflare account

#### **Subdomain**
```
Subdomain [acmecorp-chicago]:
```
- Enter the subdomain you want to use for this server
- **Examples:** `vms1`, `cameras`, `video-server`
- Press **Enter** to use the default (same as tunnel name)
- Final URL will be: `https://subdomain.yourdomain.com`

> **Pro Tip:** If this customer has multiple sites, use descriptive subdomains like `acmecorp-chicago`, `acmecorp-boston`, etc.

#### **Cloudflare Account ID**
```
Cloudflare Account ID:
```
- Paste the Account ID you copied from the Cloudflare dashboard (from Step 1)
- **Format:** 32-character hexadecimal string
- **Example:** `a1b2c3d4e5f67890a1b2c3d4e5f67890`

#### **Cloudflare API Token**
```
Cloudflare API Token:
```
- Paste the API token you created (from Step 1)
- **Note:** You won't see the token as you type (security feature)
- Just paste it and press **Enter**

---

### Step 6: Review and Confirm

The script will show you a configuration summary:

```
Configuration Summary:
  Tunnel Name:      acmecorp-chicago
  Public Hostname:  acmecorp-chicago.example.com
  Backend Service:  http://localhost:8081
  Cloudflare Account: a1b2c3d4e5f6...

Proceed with this configuration? (Y/N):
```

**Review carefully:**
- Is the tunnel name correct?
- Is the public URL what you want?
- Is the account ID correct?

Type `Y` and press **Enter** to proceed, or `N` to cancel.

---

### Step 7: Let the Script Work

The script will now perform the following automatically:

**[1/6] Configuring Cloudflare Tunnel**
- Checks if a tunnel with this name already exists
- If found, asks whether to use existing or create new
- Creates/configures the tunnel via Cloudflare API

**[2/6] Configuring cloudflared**
- Downloads cloudflared.exe if not already present
- Checks if service already exists
- If found, asks whether to keep existing or reconfigure
- Installs and starts the Windows service

> **Note:** If the script prompts about existing resources, it's because you've run it before. Choose:
> - **Use existing** - Keep current configuration
> - **Reconfigure/Delete** - Replace with new configuration
> - **Exit** - Stop the script

**[3/6] Configuring tunnel route**
- Sets up ingress rules to route traffic to localhost:8081

**[4/6] Creating DNS record**
- Creates CNAME record pointing to the tunnel
- Updates existing record if already present

**[5/6] Configuring CORS headers**
- Modifies XProtect Mobile Server config file
- Restarts Mobile Server service to apply changes
- If CORS is already set to a different value, asks for confirmation

**[6/6] Validating setup**
- Verifies cloudflared service is running
- Verifies Mobile Server service is running
- Tests DNS resolution

---

### Step 8: Wait for Propagation

After the script completes, you'll see a success message:

```
✓ Cloudflare Tunnel Setup Complete!

⏱️  IMPORTANT - Tunnel Propagation:
  Please wait 2-5 minutes for DNS propagation and tunnel
  initialization before testing the URL. This is normal!
```

**Why the wait?**
- DNS records need to propagate across the internet
- Cloudflare tunnel needs to establish connection
- This typically takes 2-5 minutes

> **Pro Tip:** Use this time to grab a coffee! Trying too early will result in DNS errors.

---

### Step 9: Test Your Tunnel

After waiting 2-5 minutes:

1. **Open a web browser** (any modern browser works)
2. **Navigate to** your public URL: `https://acmecorp-chicago.example.com`
3. **Log in** with your XProtect credentials
4. **Click on a camera** to view video
5. **Verify video streams** appear!

**Expected Results:**
- ✅ Login page loads over HTTPS
- ✅ Authentication succeeds
- ✅ Camera list appears
- ✅ **Video streams when you click cameras** (this is the critical test!)

**If video doesn't work:**
- Open browser developer console (press **F12**)
- Look for CORS errors mentioning `Access-Control-Allow-Origin`
- See the Troubleshooting section below

---

### Step 10: Save Your Configuration

The script automatically saves tunnel information to your desktop:

```
C:\Users\Administrator\Desktop\CloudflareTunnel-acmecorp-chicago.txt
```

This file contains:
- Tunnel ID
- Public URL
- Dashboard links
- Service status
- Configuration details

> **Pro Tip:** Keep this file for reference, especially if you need to troubleshoot later!

---

## Managing Your Tunnel

After setup is complete, here's how to manage your tunnel:

### Check Tunnel Status

**View Service Status:**
```powershell
# Check cloudflared service
Get-Service cloudflared

# Check Mobile Server service
Get-Service "Milestone XProtect Mobile Server"
```

**View in Cloudflare Dashboard:**

Navigate to your tunnel dashboard:
```
https://one.dash.cloudflare.com/[your-account-id]/networks/tunnels
```

You'll see:
- Connection status (should show "Healthy")
- Traffic statistics
- Configuration details

### Control Services

**Restart Services:**
```powershell
# Restart cloudflared tunnel
Restart-Service cloudflared

# Restart Mobile Server
Restart-Service "Milestone XProtect Mobile Server"
```

**Stop/Start Services:**
```powershell
# Stop cloudflared
Stop-Service cloudflared

# Start cloudflared
Start-Service cloudflared
```

### View Logs

**Script Logs:**

The setup script creates a log file at:
```
C:\Users\[USERNAME]\AppData\Local\Temp\XProtectCloudflare-Setup-[DATE].log
```

**cloudflared Logs:**

1. Open **Event Viewer** (eventvwr.msc)
2. Navigate to: **Applications and Services Logs** > **Cloudflare**
3. View connection status and error messages

### Uninstall Tunnel

If you need to remove the tunnel completely:

```powershell
# Stop the service
Stop-Service cloudflared

# Uninstall the service
& "C:\Program Files\cloudflared\cloudflared.exe" service uninstall

# Delete the tunnel in Cloudflare Dashboard or via API
```

> **Note:** This does not remove the tunnel from Cloudflare's systems. Delete it in the dashboard to fully clean up.

---

## Troubleshooting Common Issues

Running into problems? Here are the most common issues and how to fix them:

### Video Streaming Not Working

**Problem:** Login works, but video won't stream when you click cameras

**What to check:**

1. **Open browser developer console** (press F12)
2. **Look for CORS errors** like:
   ```
   Access to XMLHttpRequest blocked by CORS policy:
   No 'Access-Control-Allow-Origin' header...
   ```

**How to fix:**

```powershell
# Verify CORS is configured correctly
$configPath = "C:\Program Files\Milestone\XProtect Mobile Server\VideoOS.MobileServer.Service.exe.config"
Select-String -Path $configPath -Pattern "Access-Control-Allow-Origin"
```

The value should match your public hostname (without `https://`). For example:
```xml
<add key="Access-Control-Allow-Origin" value="acmecorp-chicago.example.com" />
```

**If it's wrong or missing:**
1. Run the setup script again
2. When prompted about CORS, choose to overwrite
3. Or manually edit the config file and restart Mobile Server

---

### Cannot Reach Public URL

**Problem:** Browser shows "This site can't be reached" or DNS error

**What to check:**

1. **Wait longer** - DNS can take up to 5 minutes to propagate
2. **Clear DNS cache:**
   ```powershell
   ipconfig /flushdns
   ```
3. **Test DNS resolution:**
   ```powershell
   Resolve-DnsName acmecorp-chicago.example.com
   ```
4. **Check if cloudflared is running:**
   ```powershell
   Get-Service cloudflared
   ```

**How to fix:**

If cloudflared is stopped:
```powershell
Start-Service cloudflared
```

If DNS doesn't resolve after 5 minutes, check the DNS record in Cloudflare Dashboard.

---

### 502 Bad Gateway Error

**Problem:** Cloudflare shows "502 Bad Gateway" error

**What this means:** The tunnel is connected, but Mobile Server isn't responding

**What to check:**

```powershell
# Check if Mobile Server is running
Get-Service "Milestone XProtect Mobile Server"

# Check if port 8081 is listening
Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue
```

**How to fix:**

```powershell
# Restart Mobile Server
Restart-Service "Milestone XProtect Mobile Server"

# Restart cloudflared
Restart-Service cloudflared

# Wait 30 seconds and try again
```

---

### Script Fails: "Cannot reach Cloudflare API"

**Problem:** Script fails during prerequisite check

**What to check:**

1. **Test internet connectivity:**
   ```powershell
   Test-NetConnection -ComputerName api.cloudflare.com -Port 443
   ```
2. **Check if firewall is blocking HTTPS**
3. **Verify proxy settings** if your network uses a proxy

**How to fix:**

- Contact your network administrator if firewall/proxy is blocking Cloudflare
- Ensure outbound HTTPS (port 443) is allowed

---

### Script Fails: "Domain not found"

**Problem:** Error message: "Domain 'example.com' not found in Cloudflare account"

**What this means:** The domain isn't added to your Cloudflare account, or API token doesn't have access

**How to fix:**

1. **Verify domain is in Cloudflare:**
   - Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
   - Check if your domain is listed
2. **Check API token permissions:**
   - Token must have access to the specific zone (domain)
   - Recreate token with correct zone permissions if needed
3. **Double-check spelling** of domain name when prompted

---

### Tunnel Service Won't Start

**Problem:** cloudflared service shows status "Stopped"

**What to check:**

```powershell
# Check service status
Get-Service cloudflared

# View recent errors in Event Viewer
Get-EventLog -LogName Application -Source cloudflared -Newest 10
```

**How to fix:**

Try reinstalling the service:

```powershell
# Stop the service if running
Stop-Service cloudflared -ErrorAction SilentlyContinue

# Uninstall service
& "C:\Program Files\cloudflared\cloudflared.exe" service uninstall

# Re-run the setup script
.\Setup-XProtectCloudflare.ps1
```

When prompted about existing tunnel, choose **"Use existing tunnel"** to avoid creating a duplicate.

---

### Service Disappeared / "Registry Key Already Exists"

**Problem:**
- cloudflared service was working but is now missing
- Attempting to reinstall shows "Cannot install event logger: registry key already exists"
- May occur after running SSL setup script

**What happened:**
Windows removed the crashed service but left orphaned registry entries.

**How to fix:**

**Option 1: Use Repair Script** (if available)
```powershell
.\Repair-CloudflaredService.ps1
```

**Option 2: Manual Cleanup**
```powershell
# Remove orphaned registry entries
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\cloudflared" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Cloudflared" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\cloudflared" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Cloudflared" -Recurse -Force -ErrorAction SilentlyContinue
```

**Then reinstall:**
```powershell
.\Setup-XProtectCloudflare.ps1
```

When prompted about existing tunnel, choose **"Use the existing tunnel"** to avoid duplicates.

> **Note:** Version 1.4.0+ of the setup script automatically prevents and cleans up this issue.

---

## Getting Help

If you're still stuck after trying the troubleshooting steps:

1. **Check the log file:**
   ```
   C:\Users\[USERNAME]\AppData\Local\Temp\XProtectCloudflare-Setup-[DATE].log
   ```

2. **Check Event Viewer:**
   - Open Event Viewer (eventvwr.msc)
   - Navigate to: Applications and Services Logs > Cloudflare
   - Look for recent errors

3. **Verify tunnel in Cloudflare Dashboard:**
   - Check if tunnel shows as "Healthy"
   - Review configuration matches your expectations

---

### Credits

**Created by:** [@conticomp](https://github.com/conticomp)

This automation is based on successful community implementations:
- YouTube tutorial by Joshua J
- Reddit solutions by joshooaj (Milestone employee)
- Cloudflare Tunnel documentation
- MilestonePSTools module patterns

**Please preserve attribution when sharing or forking this project.**

### Contributing

Found a bug? Have a feature request? Contributions welcome!

---

**Version:** 1.4.0 (Phase 1: Core Tunnel Setup)
**Last Updated:** January 2025
**Tested With:** XProtect 2025 R2, Windows Server 2022, Cloudflare Free Tier

---

## Quick Reference

**Setup in 3 Commands:**
```powershell
# 1. Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 2. Navigate to script location
cd C:\CloudflareTunnel

# 3. Run setup
.\Setup-XProtectCloudflare.ps1
```

**Check Status:**
```powershell
Get-Service cloudflared, "Milestone XProtect Mobile Server"
```

**View Logs:**
```powershell
Get-Content $env:TEMP\XProtectCloudflare-Setup-*.log
```

**Restart Everything:**
```powershell
Restart-Service cloudflared
Restart-Service "Milestone XProtect Mobile Server"
```

---

*Secure video streaming through Cloudflare Tunnels - no exposed ports required!*
