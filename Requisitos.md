# Requirements and Dependencies

This document describes the licensing requirements, infrastructure, PowerShell modules, and permissions needed to run the scripts in this repository.

---

## 1. Microsoft 365 Licensing

Licenses that include Microsoft Defender XDR services are required.

| Recommended License | Included Services |
|---|---|
| Microsoft 365 E5 | MDA, MDE, MDI, MDO|
| Standalone Licenses | Defender for Cloud Apps, Defender for Endpoint P2, Defender for Identity, Defender for Office 365 P2 |

> **Note:** Without these licenses, the Advanced Hunting tables (e.g., `EmailEvents`, `AlertInfo`, `DeviceTvmSoftwareVulnerabilities`) will be empty and the reports will not display any information.

---

## 2. Execution Environment

| Requirement | Details |
|---|---|
| **PowerShell** | PowerShell 7+ **Required** see section 4 **Critical**|
| **Operating System** | Windows 11 or Windows Server 2016+ |
| **Administrator privileges** | Required only for `Domain-Health-Check.ps1` (`#Requires -RunAsAdministrator`) |
| **Global Administrator** | Permission required for App Registration |

---

## 3. App Registration in Microsoft Entra ID

All XDR/MDE reporting scripts authenticate against the Microsoft 365 Defender API and require an App Registration.

### 3.1 Create the App Registration

1. Sign in to the Azure portal: [https://entra.microsoft.com/](https://entra.microsoft.com/).
2. Navigate to **Microsoft Entra ID** > **App registrations** > **+ New registration**.
3. Configure the fields:
   - **Name:** A descriptive name, for example **`SecOps-Defender-Reports`**.
   - **Supported account types:** Select *Single tenant only - [Tenant]*.
   - **Redirect URI:** Leave blank (not required for Client Secret authentication).
4. Click **Register**.
5. Once created, on the App Registration **Overview** page, copy and save:
   - **Application (client) ID** → This is the `ClientId`.
   - **Directory (tenant) ID** → This is the `TenantId`.

### 3.2 Assign API Permissions

1. In the App Registration, go to **API permissions** > **+ Add a permission**.
2. Select **APIs my organization uses** and search for **`Microsoft Threat Protection`.**
3. Select **Application permissions**.
4. Check the **`AdvancedHunting.Read.All`** permission.
5. Click **Add permissions**.
6. **Important:** Click **Grant admin consent for [Tenant]** and confirm. Without this step, the application will not be able to execute Advanced Hunting queries.

> **Note:** The *Grant admin consent* button requires the **Global Administrator** or **Privileged Role Administrator** role.

### 3.3 Create a Client Secret (Optional)

1. In the App Registration, go to **Certificates & secrets** > **Client secrets** > **+ New client secret**.
2. Configure:
   - **Description:** A descriptive name, for example `SecOps-Reports-Key`.
   - **Expires:** Select the appropriate duration (recommended **6 months** or **12 months** depending on the organization's security policy).
3. Click **Add**.
4. **Immediately copy the secret value** (the **Value** column). This value is only shown once and cannot be retrieved later. This is the `ClientSecret`.

> ⚠️ **Warning:** Treat the Client Secret as a password. Do not store it in plain text in scripts or repositories. The scripts in this repository support environment variables and DPAPI-encrypted credentials (see sections 7 and 8).

### 3.4 Summary of Required Data

Once the above steps are completed, you should have the following three values:

| Data | Where to Find It | Example |
|---|---|---|
| **Tenant ID** | App Registration > Overview > Directory (tenant) ID | `7cbaabe5-dbcd-431d-8ea3-826b85b28c2b` |
| **Client ID** | App Registration > Overview > Application (client) ID | `846e446d-6748-4da8-924c-de9b9e3d60d4` |
| **Client Secret** (Optional) | App Registration > Certificates & secrets > Value | `2EV8Q~7vwnHG8f2pZTA3...` |

### 3.5 Supported Authentication Modes

| Mode | Additional Modules Required | Compatible Scripts |
|---|---|---|
| `Secret` | None (uses native `Invoke-RestMethod`) | All |
| `DeviceCode` | None (uses native `Invoke-RestMethod`) | Daily, Weekly, Vulnerability |
| `Interactive` | `Az.Accounts` **or** `Microsoft.Graph.Authentication` | Daily, Weekly, Vulnerability |
| `Certificate` | `MSAL.PS` | Weekly, Vulnerability |

---

## 4. PowerShell Modules

### 4.1 Install PowerShell 7 (Critical — install from the PowerShell-7.x.x-win-x64.msi or PowerShell-7.x.x-win-arm64.msi file)

1. Go to https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.6#install-the-msi-package

2. Select the version that matches your CPU architecture.

3. Double-click the .msi file.

4. The installer wizard will open → click Next.

5. Once installed, run this command to validate the installation path **Critical path**

```PowerShell
Get-Command pwsh
```
6. Expected output **C:\Program Files\PowerShell\7\pwsh.exe**


### 4.2 Modules per Script

| Script | Required Modules | Mandatory |
|---|---|---|
| `XDR/New-DefenderXDRDailyReport.ps1` | None (`Secret` mode) | — |
| | `Az.Accounts` **or** `Microsoft.Graph.Authentication` (`Interactive`/`DeviceCode` mode) | Conditional |
| `XDR/New-DefenderXDRWeeklyReport.ps1` | None (`Secret`/`DeviceCode` mode) | — |
| | `Az.Accounts` (`Interactive` mode) | Conditional |
| | `MSAL.PS` (`Certificate` mode) | Conditional |
| `XDR/Setup-DefenderXDRReportServer.ps1` | None | — |
| `MDE/New-DefenderVulnerabilityReport.ps1` | None (`Secret`/`DeviceCode` mode) | — |
| | `Az.Accounts` (`Interactive` mode) | Conditional |
| | `MSAL.PS` (`Certificate` mode) | Conditional |
| `MDO/Scripts/Block-OnMicrosoftEmails.ps1` | `ExchangeOnlineManagement` | **Yes** |
| `MDO/Scripts/Quarantine Attachments Can't be inspected.ps1` | `ExchangeOnlineManagement` | **Yes** |
| `MDO/Scripts/Domain-Health-Check.ps1` | `DomainHealthChecker`, `MailAuthDnsTools`, `EmailAuthChecker` | **Yes** (automatically installed if missing) |

### 4.3 Module Installation

```powershell
# Modules for MDO scripts (Exchange Online)
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# Modules for Domain Health Check (installed automatically by the script, but can be pre-installed)
Install-Module -Name DomainHealthChecker   -Scope CurrentUser -Force
Install-Module -Name MailAuthDnsTools      -Scope CurrentUser -Force
Install-Module -Name EmailAuthChecker      -Scope CurrentUser -Force

# Optional modules depending on authentication mode
Install-Module -Name Az.Accounts                      -Scope CurrentUser -Force   # Interactive
Install-Module -Name Microsoft.Graph.Authentication    -Scope CurrentUser -Force   # Interactive (alternative)
Install-Module -Name MSAL.PS                           -Scope CurrentUser -Force   # Certificate
```

---

## 5. Network Connectivity

The machine or server running the scripts must have HTTPS (443) access to the following endpoints:

| Endpoint | Purpose |
|---|---|
| `login.microsoftonline.com` | OAuth 2.0 Authentication (all XDR/MDE scripts) |
| `api.security.microsoft.com` | Advanced Hunting API - Microsoft 365 Defender |
| `outlook.office365.com` | Remote Exchange Online PowerShell (MDO scripts) |
| `*.protection.outlook.com` | Exchange Online Protection |
| Public DNS servers | DNS resolution for `Domain-Health-Check.ps1` (SPF, DKIM, DMARC, MTA-STS) |

> If the environment uses a proxy, the XDR Weekly and Vulnerability scripts support the `-ProxyUrl` parameter.

---

## 6. Directory Structure for Reports

The `Setup-DefenderXDRReportServer.ps1` script automatically creates the following structure:

```
<ScriptsPath>\
├── Config\          # Encrypted credentials (DPAPI)
├── Reports\         # Generated HTML reports
│   └── Logs\        # Log files
```

`Domain-Health-Check.ps1` generates reports in `C:\Scripts\MDO\` (automatically created if it does not exist).

---

## Quick Dependency Summary

```
Scripts XDR/MDE (Secret/DeviceCode)
  └── No additional modules (uses native Invoke-RestMethod)

Scripts XDR/MDE (Interactive)
  └── Az.Accounts  ─or─  Microsoft.Graph.Authentication

Scripts XDR/MDE (Certificate)
  └── MSAL.PS

Scripts MDO (Transport Rules)
  └── ExchangeOnlineManagement

Domain Health Check
  ├── DomainHealthChecker
  ├── MailAuthDnsTools
  └── EmailAuthChecker
```
