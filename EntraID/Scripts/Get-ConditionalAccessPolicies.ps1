##############################################################################################
#This sample script is not supported under any Microsoft standard support program or service.
#This sample script is provided AS IS without warranty of any kind.
#Microsoft further disclaims all implied warranties including, without limitation, any implied
#warranties of merchantability or of fitness for a particular purpose. The entire risk arising
#out of the use or performance of the sample script and documentation remains with you. In no
#event shall Microsoft, its authors, or anyone else involved in the creation, production, or
#delivery of the scripts be liable for any damages whatsoever (including, without limitation,
#damages for loss of business profits, business interruption, loss of business information,
#or other pecuniary loss) arising out of the use of or inability to use the sample script or
#documentation, even if Microsoft has been advised of the possibility of such damages.
##############################################################################################

<#
.SYNOPSIS
    Gets a detailed report of all Conditional Access policies in the tenant.

.DESCRIPTION
    This script collects the complete configuration of each Conditional Access policy
    in Microsoft Entra ID (Azure AD), including:
    - General information (name, state, creation/modification date)
    - Conditions (users, groups, applications, platforms, locations, risk)
    - Access controls (Grant / Session)
    
    Generates three outputs:
    1. Console report with visual formatting
    2. CSV export with all relevant fields
    3. HTML export with table formatting

.NOTES
    Requires the Microsoft.Graph module with the appropriate scopes:
        Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"

    Author  : Ernesto Cobos Roqueñí, Arturo Mandujano
    Date    : 2026-03-04
    Version : 1.2
#>

# ─────────────────────────────────────────────
# Microsoft Graph module validation
# ─────────────────────────────────────────────
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns")

foreach ($mod in $requiredModules) {
    if (Get-Module -ListAvailable -Name $mod) {
        Write-Host "Module $mod installed correctly." -ForegroundColor DarkGray
    }
    else {
        Write-Host "[X] Module $mod not found. " -ForegroundColor Red -NoNewline
        Write-Host "Downloading and installing..." -ForegroundColor Yellow
        Install-Module $mod -Force -Scope CurrentUser
    }
}

# ─────────────────────────────────────────────
# Microsoft Graph connection
# ─────────────────────────────────────────────
$requiredScopes = @("Policy.Read.All", "Directory.Read.All")

try {
    $context = Get-MgContext -ErrorAction Stop
    if ($null -eq $context) { throw "Not connected" }

    $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        Write-Host "Missing scopes: $($missingScopes -join ', '). Reconnecting..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    }
    else {
        Write-Host "An active Microsoft Graph session already exists." -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        Write-Host "Connection established successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Could not connect to Microsoft Graph." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
}

# ─────────────────────────────────────────────
# Reports folder
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\EntraID"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Folder created: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Reports folder exists: $reportDir" -ForegroundColor DarkGray
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $reportDir "ConditionalAccess_$timestamp.csv"
$htmlPath  = Join-Path $reportDir "ConditionalAccess_$timestamp.html"

# ─────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────
function ConvertTo-FlatString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ($Value | ForEach-Object { $_.ToString() }) -join "; "
    }
    return $Value.ToString()
}

function Get-PolicyStateText {
    param([string]$State)
    switch ($State) {
        "enabled"                { return "Enabled" }
        "disabled"               { return "Disabled" }
        "enabledForReportingButNotEnforced" { return "Report-only" }
        default                  { return $State }
    }
}

function Resolve-UserOrGroup {
    <#
    .SYNOPSIS
        Attempts to resolve a user or group ID to its DisplayName.
    #>
    param([string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id)) { return $Id }

    # Special Conditional Access values
    switch ($Id) {
        "All"              { return "All users" }
        "GuestsOrExternalUsers" { return "Guests or external users" }
        "None"             { return "None" }
        default {
            try {
                $obj = Get-MgDirectoryObject -DirectoryObjectId $Id -ErrorAction Stop
                return $obj.AdditionalProperties.displayName ?? $Id
            }
            catch {
                return $Id
            }
        }
    }
}

function Resolve-Application {
    <#
    .SYNOPSIS
        Attempts to resolve an AppId to its DisplayName.
    #>
    param([string]$AppId)

    if ([string]::IsNullOrWhiteSpace($AppId)) { return $AppId }

    switch ($AppId) {
        "All"             { return "All applications" }
        "Office365"       { return "Office 365" }
        "MicrosoftAdminPortals" { return "Microsoft admin portals" }
        "None"            { return "None" }
        default {
            try {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Top 1 -ErrorAction Stop
                if ($sp) { return $sp.DisplayName }
                return $AppId
            }
            catch {
                return $AppId
            }
        }
    }
}

function Resolve-NamedLocation {
    <#
    .SYNOPSIS
        Attempts to resolve a named location ID to its DisplayName.
    #>
    param([string]$LocationId)

    if ([string]::IsNullOrWhiteSpace($LocationId)) { return $LocationId }

    switch ($LocationId) {
        "All"              { return "All locations" }
        "AllTrusted"       { return "All trusted locations" }
        default {
            try {
                $loc = Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $LocationId -ErrorAction Stop
                return $loc.DisplayName ?? $LocationId
            }
            catch {
                return $LocationId
            }
        }
    }
}

# ─────────────────────────────────────────────
# Get Conditional Access policies
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "Generating Conditional Access Policies Report..." -ForegroundColor Cyan

try {
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Could not retrieve Conditional Access policies." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

if (-not $policies -or $policies.Count -eq 0) {
    Write-Host "[i] No Conditional Access policies found in the tenant." -ForegroundColor Yellow
    return
}

# ─────────────────────────────────────────────
# Summary counters
# ─────────────────────────────────────────────
$countEnabled   = ($policies | Where-Object { $_.State -eq "enabled" }).Count
$countDisabled  = ($policies | Where-Object { $_.State -eq "disabled" }).Count
$countReport    = ($policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count

# ─────────────────────────────────────────────
# Process each policy
# ─────────────────────────────────────────────
$reportData = [System.Collections.Generic.List[PSObject]]::new()
$policyIndex = 0

foreach ($policy in $policies) {
    $policyIndex++
    $stateText  = Get-PolicyStateText -State $policy.State

    # --- Conditions: Users ---
    $cond = $policy.Conditions

    $includeUsers  = ConvertTo-FlatString ($cond.Users.IncludeUsers  | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeUsers  = ConvertTo-FlatString ($cond.Users.ExcludeUsers  | ForEach-Object { Resolve-UserOrGroup $_ })
    $includeGroups = ConvertTo-FlatString ($cond.Users.IncludeGroups | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeGroups = ConvertTo-FlatString ($cond.Users.ExcludeGroups | ForEach-Object { Resolve-UserOrGroup $_ })
    $includeRoles  = ConvertTo-FlatString ($cond.Users.IncludeRoles  | ForEach-Object { Resolve-UserOrGroup $_ })
    $excludeRoles  = ConvertTo-FlatString ($cond.Users.ExcludeRoles  | ForEach-Object { Resolve-UserOrGroup $_ })

    # --- Conditions: Applications ---
    $includeApps = ConvertTo-FlatString ($cond.Applications.IncludeApplications | ForEach-Object { Resolve-Application $_ })
    $excludeApps = ConvertTo-FlatString ($cond.Applications.ExcludeApplications | ForEach-Object { Resolve-Application $_ })
    $includeActions = ConvertTo-FlatString $cond.Applications.IncludeUserActions

    # --- Conditions: Platforms ---
    $includePlatforms = ConvertTo-FlatString $cond.Platforms.IncludePlatforms
    $excludePlatforms = ConvertTo-FlatString $cond.Platforms.ExcludePlatforms

    # --- Conditions: Locations ---
    $includeLocations = ConvertTo-FlatString ($cond.Locations.IncludeLocations | ForEach-Object { Resolve-NamedLocation $_ })
    $excludeLocations = ConvertTo-FlatString ($cond.Locations.ExcludeLocations | ForEach-Object { Resolve-NamedLocation $_ })

    # --- Conditions: Risk ---
    $signInRisk = ConvertTo-FlatString $cond.SignInRiskLevels
    $userRisk   = ConvertTo-FlatString $cond.UserRiskLevels

    # --- Conditions: Client App Types ---
    $clientAppTypes = ConvertTo-FlatString $cond.ClientAppTypes

    # --- Access controls: Grant ---
    $grantControls       = $policy.GrantControls
    $grantOperator       = $grantControls.Operator
    $builtInControls     = ConvertTo-FlatString $grantControls.BuiltInControls
    $customControls      = ConvertTo-FlatString $grantControls.CustomAuthenticationFactors
    $termsOfUse          = ConvertTo-FlatString $grantControls.TermsOfUse
    $authStrength        = $grantControls.AuthenticationStrength.DisplayName

    # --- Session controls ---
    $sessionControls = $policy.SessionControls

    $sessionItems = @()
    if ($sessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
        $sessionItems += "Application restrictions"
    }
    if ($sessionControls.CloudAppSecurity.IsEnabled) {
        $sessionItems += "Cloud App Security ($($sessionControls.CloudAppSecurity.CloudAppSecurityType))"
    }
    if ($sessionControls.PersistentBrowser.IsEnabled) {
        $sessionItems += "Persistent browser ($($sessionControls.PersistentBrowser.Mode))"
    }
    if ($sessionControls.SignInFrequency.IsEnabled) {
        $sessionItems += "Sign-in frequency ($($sessionControls.SignInFrequency.Value) $($sessionControls.SignInFrequency.Type))"
    }
    if ($sessionControls.ContinuousAccessEvaluation.Mode) {
        $sessionItems += "CAE ($($sessionControls.ContinuousAccessEvaluation.Mode))"
    }
    if ($sessionControls.DisableResilienceDefaults -eq $true) {
        $sessionItems += "Resilience disabled"
    }

    $sessionControlsFlat = ConvertTo-FlatString $sessionItems

    # --- Add to report ---
    $reportData.Add([PSCustomObject]@{
        Name                 = $policy.DisplayName
        State                = $stateText
        ID                   = $policy.Id
        Created              = $policy.CreatedDateTime
        Modified             = $policy.ModifiedDateTime
        IncludeUsers         = $includeUsers
        ExcludeUsers         = $excludeUsers
        IncludeGroups        = $includeGroups
        ExcludeGroups        = $excludeGroups
        IncludeRoles         = $includeRoles
        ExcludeRoles         = $excludeRoles
        IncludeApps          = $includeApps
        ExcludeApps          = $excludeApps
        UserActions          = $includeActions
        IncludePlatforms     = $includePlatforms
        ExcludePlatforms     = $excludePlatforms
        IncludeLocations     = $includeLocations
        ExcludeLocations     = $excludeLocations
        SignInRisk           = $signInRisk
        UserRisk             = $userRisk
        ClientAppTypes       = $clientAppTypes
        GrantOperator        = $grantOperator
        GrantControls        = $builtInControls
        AuthStrength         = $authStrength
        SessionControls      = $sessionControlsFlat
    })
}

# ─────────────────────────────────────────────
# Export to CSV
# ─────────────────────────────────────────────
try {
    $reportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8BOM
    Write-Host "[OK] CSV report exported: $csvPath" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Error exporting CSV: $($_.Exception.Message)" -ForegroundColor Red
}

# ─────────────────────────────────────────────
# Export to HTML
# ─────────────────────────────────────────────
$htmlHead = @"
<style>
    body   { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
    h1     { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
    h2     { color: #005a9e; margin-top: 30px; }
    table  { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
    th     { background: #0078d4; color: #fff; padding: 10px; text-align: left; }
    td     { border: 1px solid #ddd; padding: 8px; color: #333; }
    tr:nth-child(even) { background: #e9e9e9; }
    tr:nth-child(odd)  { background: #fff; }
    .enabled   { color: #107c10; font-weight: bold; }
    .disabled  { color: #d13438; font-weight: bold; }
    .report    { color: #ca5010; font-weight: bold; }
    .summary   { background: #0078d4; color: #fff; padding: 12px 20px; border-radius: 6px; display: inline-block; margin: 5px; }
</style>
"@

$tenantDetail = Get-MgOrganization | Select-Object -First 1
$tenantName   = $tenantDetail.DisplayName
$tenantId     = (Get-MgContext).TenantId

$htmlBody = @"
<h1>Conditional Access Policies Report <em style="font-size: 0.75em; font-weight: normal; margin-left: 80px;">&ldquo;Technology enables security, but discipline ensures its effectiveness&rdquo;</em></h1>
<p>Tenant: $tenantName | Tenant ID: $tenantId | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div>
    <span class="summary">Enabled: $countEnabled</span>
    <span class="summary">Disabled: $countDisabled</span>
    <span class="summary">Report-only: $countReport</span>
    <span class="summary">Total: $($policies.Count)</span>
</div>

<h2>Policy Details</h2>
"@

$htmlTable = $reportData | ConvertTo-Html -Fragment | Out-String

# Color states in HTML
$htmlTable = $htmlTable -replace "<td>Enabled</td>",    '<td class="enabled">Enabled</td>'
$htmlTable = $htmlTable -replace "<td>Disabled</td>", '<td class="disabled">Disabled</td>'
$htmlTable = $htmlTable -replace "<td>Report-only</td>",  '<td class="report">Report-only</td>'

$htmlFooter = '<footer style="text-align: center; margin-top: 40px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px;">chiringuito365.com&reg; | Internal Tools 2026</footer>'

$fullHtml = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlTable + $htmlFooter) -Title "Conditional Access Report" | Out-String

try {
    $fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "[OK] HTML report exported: $htmlPath" -ForegroundColor Green
    Invoke-Item $htmlPath
}
catch {
    Write-Host "[ERROR] Error exporting HTML: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Report generated successfully." -ForegroundColor Green