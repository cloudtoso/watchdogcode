# Emergency Account (Break Glass / Emergency Access Account) 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---
## 1. Explanation
An **emergency account** is an administrative account used only when regular administrators cannot authenticate due to failures in **MFA**, **federation**, **network**, **synchronization**, **security incidents**, or other critical dependencies. Its fundamental purpose is to ensure that at least one **Global Administrator** always has access to the Microsoft 365 environment.

---

## 2. Recommended Best Practices

- Maintain **at least two emergency accounts**.
- They must be **cloud-only** (no federation, no on-premises dependencies).
- Use the `*.onmicrosoft.com` domain.
- Credentials stored in **two secure physical locations**.
- **Non-expiring passwords**.
- **Phishing-resistant MFA** methods, such as **FIDO2** or physical passkeys.
- **Differentiated** configurations to avoid common points of failure.
- Exclude them from automated account cleanup processes.
- Monitor **every sign-in**.

---

## 3. Step-by-Step Implementation
### A. Account Creation
1. Create two cloud-only accounts in Entra ID:
   - `emergency1@tenant.onmicrosoft.com`
   - `emergency2@tenant.onmicrosoft.com`
2. Assign the **Global Administrator** role.
3. Configure MFA:
   - Account 1 → **FIDO2 key**.
   - Account 2 → **Different physical passkey**.

### B. Recommended Configuration
- Avoid dependencies with common administrators:
  - No federation.
  - No shared MFA.
- Store credentials in secure locations.
- Disable password expiration.
- Exclude from Conditional Access policies that could block them.
- Document the process and enable auditing.

### C. Validation and Maintenance
- Test access every **90 days**.
- Audit every sign-in.
- Maintain a secure record of credential locations.

---

## 4. Procedure to Create a Detection Rule in Microsoft Defender

## Steps
1. Go to: <https://security.microsoft.com/v2/advanced-hunting>
2. In the panel, add the following query:

```kusto
EntraIdSignInEvents
| where Timestamp >= ago(1h)
| where AccountUpn in ("breakglass@tenant.onmicrosoft.com", "breakglass02@tenant.onmicrosoft.com")
| project Timestamp, AccountUpn, LogonType, Application, RiskLevelAggregated, ClientAppUsed, Country, State, City
| order by Timestamp asc
```

3. Click **Run query**.
4. Click **Create detection rule**.
5. On the **General** page:
   - **Detection name:** Sign-in Break Glass Accounts
   - **Rule Description:** Detect Break Glass Accounts logins
   - **Frequency:** Continuous (NRT)
   - **Severity:** High
   - **Category:** Credential access
6. Click **Next**.
7. On the **Alert settings** page:
   - **Alert title:** Sign-in Break Glass Accounts
   - **Description:** Detect Break Glass Accounts logins
8. Click **Next**.
9. On the **Automated actions** page, click **Next**.
10. Click **Submit**.

---
## 5. Scripts, Queries, and Automation
### A. Create cloud-only account (PowerShell)
```powershell
# Create cloud-only account
Import-Module Microsoft.Graph.Users -ErrorAction Stop
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome

# Use a strong ASCII password to avoid issues (no ñ/accents)
$PasswordProfile = @{
  Password = "***************************"
  ForceChangePasswordNextSignIn = $false
}

$params = @{
  AccountEnabled    = $true
  DisplayName       = "Emergency Access 1"
  UserPrincipalName = "breakglass@tenant.onmicrosoft.com"
  MailNickname      = "breakglass"
  PasswordProfile   = $PasswordProfile
  PasswordPolicies  = "DisablePasswordExpiration"
  UsageLocation     = "US"
}

New-MgUser @params
```
### Assign Global Administrator Role

```powershell
# Assign Global Administrator role
# Requires being connected:
# Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","Directory.ReadWrite.All","User.Read.All"

$upn = "breakglass04@chiringuito365.com"

# 1) Get the Global Administrator role (already exists in your tenant)
$role = Get-MgDirectoryRole -All | Where-Object DisplayName -eq "Global Administrator"
if (-not $role) { throw "The 'Global Administrator' role was not found in DirectoryRole." }

# 2) Get breakglass user
$user = Get-MgUser -UserId $upn -ErrorAction Stop
if (-not $user) { throw "User $upn not found" }

# 3) Validate if already a member
$alreadyMember = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All |
  Where-Object { $_.Id -eq $user.Id }

if ($alreadyMember) {
  Write-Host "The user is already a member of 'Global Administrator': $upn" -ForegroundColor Yellow
  return
}

# 4) Add member by reference (most stable method)
New-MgDirectoryRoleMemberByRef `
  -DirectoryRoleId $role.Id `
  -BodyParameter @{
      "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)"
  } -ErrorAction Stop

Write-Host "Role 'Global Administrator' assigned to $upn" -ForegroundColor Green
```

### C. Monitor sign-ins (KQL)
```kql
EntraIdSignInEvents
| where Timestamp >= ago(1h)
| where AccountUpn in ("breakglass@tenant.onmicrosoft.com","breakglass02@tenant.onmicrosoft.com")
| project Timestamp, AccountUpn, LogonType, Application, RiskLevelAggregated, ClientAppUsed, Country, State, City
| order by Timestamp asc 
```

### D. Create alert in Sentinel (KQL)
```kql
SigninLogs
| where UserPrincipalName has "emergency"
| where ResultType == 0
```

---

## 6. References
- **Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---

## 7. Notes and Warnings
- Do not use these accounts for daily administrative tasks.
- Every sign-in must generate an immediate alert.
- Do not associate them with specific individuals.
- Use authentication methods different from those of regular administrators.
- Review with internal audit who has access to the credentials.


## Official References
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

---
 Internal Tools 2026
