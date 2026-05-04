# Usage Guide — New-DefenderXDRWeeklyReport.ps1

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

This guide is aligned with the current state of the script `XDR/New-DefenderXDRWeeklyReport.ps1`.

---

## 1) Description

`New-DefenderXDRWeeklyReport.ps1` generates a weekly HTML security report for Microsoft Defender XDR focused on:

- MDO (campaigns and most attacked users)
- MDE (alert severity, at-risk hosts, and device health)
- MDI (spray/brute force and atypical locations)
- MDA (OAuth and Shadow IT)

It includes KPIs, an executive summary, and a weekly operational checklist.

---

## 2) Prerequisites

1. **API Permissions**
     - `AdvancedHunting.Read.All` with administrator consent.

2. **Connectivity**
     - `https://api.security.microsoft.com`
     - `https://login.microsoftonline.com`

3. **Modules (only depending on auth method)**
     - `Az.Accounts` for `Interactive`.
     - `MSAL.PS` for `Certificate` (per the current script implementation).

---

## 3) Authentication (current state)

- **Default:** `Secret`
- **Available alias:** `-Auth` (equivalent to `-AuthMode`)
- Supported methods: `Secret`, `DeviceCode`, `Interactive`, `Certificate`

### Important behavior

- If you don't pass `-Auth` or `-AuthMode`, the script uses `Secret`.
- In `Secret` mode, `ClientSecret` is required.
- `TenantId` and `ClientId` are required in the script.

---

## 4) Main Parameters

| Parameter | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `TimeWindowDays` | Int | Weekly analysis time window (`7`, `14`, `30`) | `7` |
| `OutputPath` | String | HTML output path | `XDR\Weekly_SecOps_Report_YYYYMMDD.html` |
| `AuthMode` / `Auth` | String | Authentication method | `Secret` |
| `TenantId` | String | Entra ID Tenant ID | Required |
| `ClientId` | String | App/Client ID | Required |
| `ClientSecret` | String | Secret (`Secret` only) | N/A |
| `CertThumbprint` | String | Cert thumbprint (`Certificate` only) | N/A |
| `SendMail` | Bool | Send report via SMTP | `$false` |
| `SmtpServer` | String | SMTP server | N/A |
| `To` | String | Email recipient(s) | N/A |
| `Subject` | String | Email subject | `Defender XDR - Reporte Semanal de Amenazas` |
| `ProxyUrl` | String | HTTP/HTTPS proxy | N/A |
| `TimeoutSec` | Int | Timeout per query | `120` |
| `FailFast` | Switch | Stop execution on first failure | `False` |
| `ExportCsv` | Switch | Export datasets to CSV | `False` |
| `UseParallel` | Switch | Execute queries in parallel (if applicable in logic) | `False` |
| `LogPath` | String | Log path | `C:\Reports\Logs\DefenderXDR.log` |
| `TestMode` | Switch | Test mode (per script logic) | `False` |

---

## 5) Execution Examples

### A. Standard execution (Secret by default)

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret"
```

### B. Same scenario using alias `-Auth`

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret" `
    -Auth Secret
```

### C. Device Code (remote session / no local browser)

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode DeviceCode
```

### D. Interactive (requires `Az.Accounts`)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force

.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode Interactive
```

### E. Certificate (requires `MSAL.PS`)

```powershell
Install-Module MSAL.PS -Scope CurrentUser -Force

.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -AuthMode Certificate `
    -CertThumbprint "THUMBPRINT_DEL_CERT"
```

### F. Export CSV + send via email

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "11111111-1111-1111-1111-111111111111" `
    -ClientSecret "tu_client_secret" `
    -TimeWindowDays 14 `
    -ExportCsv `
    -SendMail $true `
    -SmtpServer "smtp.tuempresa.com" `
    -To "ciso@tuempresa.com;soc@tuempresa.com" `
    -Subject "Reporte Semanal de Seguridad - M365"
```

> Note: The script uses an automatic sender `DefenderReport@<COMPUTERNAME>` in `Send-MailMessage`.

---

## 6) Outputs

- **Main HTML:** `Weekly_SecOps_Report_YYYYMMDD.html`
- **Execution log:** per `-LogPath`
- **Optional CSVs:** `CSV_Export` folder alongside the HTML (if `-ExportCsv`)

---

## 7) Quick Troubleshooting

- **401 Unauthorized**
    - Validate `AdvancedHunting.Read.All` permissions + Admin Consent.

- **`ClientSecret es requerido`**
    - Occurs when using default `Secret` without `-ClientSecret`.

- **`Az.Accounts` not found**
    - Install the module or use `Secret`/`DeviceCode`.

- **Certificate error**
    - Validate that the cert exists in `Cert:\CurrentUser\My\<thumbprint>` and that `MSAL.PS` is available.

- **Empty report or insufficient data**
    - Increase `-TimeWindowDays` to `14` or `30`.

---

## 8) Recommended execution for automation

For scheduled tasks, use `Secret` (default) with credentials from a secure variable or secret store, for example:

```powershell
.\New-DefenderXDRWeeklyReport.ps1 `
    -TenantId $env:AZURE_TENANT_ID `
    -ClientId $env:AZURE_CLIENT_ID `
    -ClientSecret $env:AZURE_CLIENT_SECRET `
    -TimeWindowDays 7
```