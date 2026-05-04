# Usage Guide — New-DefenderXDRDailyReport.ps1

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

This guide is aligned with the current state of the script `XDR/New-DefenderXDRDailyReport.ps1`.

---

## 1) Description

`New-DefenderXDRDailyReport.ps1` generates a daily HTML security operations report for Microsoft Defender XDR focused on:

- MDO (campaigns, URLs, and most attacked users)
- MDE (alerts by severity and endpoint health status)
- MDI (brute force and high-risk users)
- MDA (OAuth and Shadow IT)
- Consolidated XDR (alerts by service/severity and top recent alerts)

It also includes:

- Executive KPIs
- Operational tasks with links (MDO, MDI, and Entra ID)
- Daily KQL recommendations per workload

---

## 2) Prerequisites

1. **API Permissions**
   - `AdvancedHunting.Read.All` with administrator consent.

2. **Connectivity**
   - `https://api.security.microsoft.com`
   - `https://login.microsoftonline.com`

3. **Modules (depending on auth method)**
   - `Az.Accounts` for `Interactive` and (recommended) `DeviceCode`.
   - If `Az.Accounts` is not installed, the script can use REST fallback in `DeviceCode` (requires `TenantId` and `ClientId`).

---

## 3) Authentication

Supported methods:

- `Secret` (default)
- `Interactive`
- `DeviceCode`

### Important behavior

- If you don't pass `-AuthMode`, `Secret` is used.
- In `Secret`, you must provide `TenantId`, `ClientId`, and `ClientSecret` (directly or via environment variables).
- In `DeviceCode` without modules, you must provide `TenantId` and `ClientId`.

---

## 4) Main Parameters

| Parameter | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `TimeWindowHours` | Int | Analysis time window in hours | `720` |
| `OutputPath` | String | HTML output path | `XDR\Daily_SecOps_Report_YYYYMMDD.html` |
| `TenantId` | String | Entra ID Tenant ID | `$env:AZURE_TENANT_ID` |
| `ClientId` | String | App/Client ID | `$env:AZURE_CLIENT_ID` |
| `ClientSecret` | String | App secret | `$env:AZURE_CLIENT_SECRET` |
| `AuthMode` | String | Authentication method | `Secret` |
| `SendMail` | Bool | Send report via SMTP | `$false` |
| `SmtpServer` | String | SMTP server | N/A |
| `From` | String | Email sender | N/A |
| `To` | String | Recipient(s) | N/A |
| `Subject` | String | Email subject | `Reporte Diario de Seguridad - M365 Defender XDR` |
| `TimeoutSec` | Int | Timeout per query | `120` |
| `FailFast` | Bool | Stop execution on first failure | `$false` |

---

## 5) Execution Examples

### A. Standard execution (Secret by default)

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111" `
  -ClientSecret "tu_client_secret"
```

### B. Interactive (requires Az.Accounts)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force

.\New-DefenderXDRDailyReport.ps1 -AuthMode Interactive -TimeWindowHours 48
```

### C. Device Code (no local browser)

```powershell
# Recomendado con Az.Accounts:
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode

# Fallback REST (sin Az.Accounts):
.\New-DefenderXDRDailyReport.ps1 -AuthMode DeviceCode `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111"
```

### D. Sending via SMTP email

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -AuthMode Secret `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ClientId "11111111-1111-1111-1111-111111111111" `
  -ClientSecret "tu_client_secret" `
  -SendMail $true `
  -SmtpServer "smtp.tuempresa.com" `
  -From "security-reports@tuempresa.com" `
  -To "ciso@tuempresa.com" `
  -Subject "Reporte Diario de Seguridad - M365"
```

> Note: to send email, `SmtpServer`, `From`, and `To` must be provided.

---

## 6) HTML Report Contents

| Section | Description |
| :--- | :--- |
| **KPIs** | Total XDR Alerts, Active Incidents, Delivered Phishing, High-Risk Users, Brute Force, OAuth. |
| **MDO** | Daily operational tasks + daily KQL recommendation. |
| **Consolidated XDR** | Alerts by service/severity and top recent alerts. |
| **MDE** | Alerts by severity + daily KQL recommendation. |
| **MDI** | Operational tasks + brute force + high-risk users + daily KQL recommendation. |
| **Entra ID** | Operational tasks + daily KQL recommendation. |
| **MDA** | New OAuth consents + daily KQL recommendation. |
| **Recommendations** | Suggested operational actions for the day. |

---

## 7) Quick Troubleshooting

- **401 Unauthorized**
  - Validate `AdvancedHunting.Read.All` permissions + Admin Consent.

- **Secret authentication failure**
  - Confirm valid `TenantId`, `ClientId`, `ClientSecret`.

- **No Azure session in Interactive/DeviceCode**
  - Install `Az.Accounts` or use `DeviceCode` REST fallback with `TenantId` and `ClientId`.

- **Empty queries / no data**
  - Adjust `-TimeWindowHours` (e.g., `24`, `72`, `168`, `720` as needed).

- **Email not sending**
  - Verify that `-SendMail $true` and parameters `-SmtpServer`, `-From`, `-To` are all provided.

---

## 8) Recommended execution for automation

```powershell
.\New-DefenderXDRDailyReport.ps1 `
  -TenantId $env:AZURE_TENANT_ID `
  -ClientId $env:AZURE_CLIENT_ID `
  -ClientSecret $env:AZURE_CLIENT_SECRET `
  -TimeWindowHours 24
```

For a daily SOC environment, it is recommended to schedule execution every morning and store the HTML in a shared reports path.
