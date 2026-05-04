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
    Validates the Zero-hour Auto Purge (ZAP) configuration in the Microsoft 365 tenant.

.DESCRIPTION
    This script reviews the ZAP (Zero-hour Auto Purge) configuration in all relevant tenant
    policies to ensure compliance with Microsoft best practices:

    - Anti-Spam  (HostedContentFilterPolicy) : SpamZapEnabled, PhishZapEnabled
    - Anti-Malware (MalwareFilterPolicy)      : ZapEnabled
    - Anti-Phishing (AntiPhishPolicy)         : ZapEnabled (available in tenants with MDO)
    - Global transport configuration          : ZAP exclusion validations
    - Quarantine                              : Quarantine policies associated with ZAP actions

    Generates an HTML dashboard report with compliance status, policy details, and remediation
    recommendations.

.NOTES
    Requires prior connection to Exchange Online:
        Connect-ExchangeOnline

    Author : Ernesto Cobos Roqueñí, Arturo Mandujano
    Date   : 13/March/2026
    Version: 1.0
#>

# ─────────────────────────────────────────────
# Module validation and reports folder
# ─────────────────────────────────────────────
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Write-Host "ExchangeOnlineManagement module installed correctly." -ForegroundColor DarkGray
}
else {
    Write-Host "[X] ExchangeOnlineManagement module not found. " -ForegroundColor Red -NoNewline
    Write-Host "Downloading and installing..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser
}

$reportDir = "C:\Scripts\MDO"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    Write-Host "Folder created: $reportDir" -ForegroundColor DarkGray
}
else {
    Write-Host "Reports folder exists: $reportDir" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────
# Colors and formatting
# ─────────────────────────────────────────────
function Write-Status {
    param(
        [string]$Setting,
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [string]$Status  # PASS, WARN, FAIL, INFO
    )

    $null = $script:htmlRows.Add([pscustomobject]@{
        Section       = $script:currentSection
        PolicyName    = $script:currentPolicyName
        Setting       = $Setting
        CurrentValue  = $CurrentValue
        Recommended   = $RecommendedValue
        Status        = $Status
    })
}

# ─────────────────────────────────────────────
# Global counters and policy tracking
# ─────────────────────────────────────────────
$script:totalChecks = 0
$script:passCount   = 0
$script:warnCount   = 0
$script:failCount   = 0

$script:policyResults    = @{}
$script:currentPolicyKey = $null
$script:currentPolicyName = $null
$script:currentSection   = $null

$script:htmlRows = [System.Collections.ArrayList]::new()

function Set-CurrentPolicy {
    param([string]$Section, [string]$PolicyName)
    $script:currentPolicyKey  = "$Section|$PolicyName"
    $script:currentPolicyName = $PolicyName
    $script:currentSection    = $Section
    if (-not $script:policyResults.ContainsKey($script:currentPolicyKey)) {
        $script:policyResults[$script:currentPolicyKey] = @{ Pass = 0; Fail = 0; Warn = 0 }
    }
}

function Test-Setting {
    param(
        [string]$Setting,
        $CurrentValue,
        $RecommendedValue
    )

    $script:totalChecks++

    $currentStr     = if ($null -eq $CurrentValue) { "<null>" } else { "$CurrentValue" }
    $recommendedStr = "$RecommendedValue"

    if ("$CurrentValue" -eq "$RecommendedValue") {
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Pass++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'PASS'
    }
    else {
        $script:failCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Fail++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'FAIL'
    }
}

function Test-SettingWarn {
    param(
        [string]$Setting,
        $CurrentValue,
        $RecommendedValue
    )

    $script:totalChecks++

    $currentStr     = if ($null -eq $CurrentValue) { "<null>" } else { "$CurrentValue" }
    $recommendedStr = "$RecommendedValue"

    if ("$CurrentValue" -eq "$RecommendedValue") {
        $script:passCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Pass++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'PASS'
    }
    else {
        $script:warnCount++
        if ($script:currentPolicyKey -and $script:policyResults.ContainsKey($script:currentPolicyKey)) {
            $script:policyResults[$script:currentPolicyKey].Warn++
        }
        Write-Status -Setting $Setting -CurrentValue $currentStr -RecommendedValue $recommendedStr -Status 'WARN'
    }
}

# ─────────────────────────────────────────────
# Exchange Online connection
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "Validating Exchange Online connection..." -ForegroundColor DarkGray

try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "  Exchange Online connection active." -ForegroundColor Green
}
catch {
    Write-Host "  No active Exchange Online connection. Connecting..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "  Exchange Online connection established." -ForegroundColor Green
    }
    catch {
        Write-Host "[X] Could not connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$tenantName = (Get-OrganizationConfig).DisplayName

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " ZAP (Zero-hour Auto Purge) Validation"       -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Date  : $timestamp" -ForegroundColor DarkGray
Write-Host "Tenant: $tenantName" -ForegroundColor DarkGray
Write-Host ""

# ═════════════════════════════════════════════
# 1. ANTI-SPAM — ZAP for Spam and Phish
# ═════════════════════════════════════════════
Write-Host "1. Validating ZAP in Anti-Spam policies..." -ForegroundColor Yellow

$spamPolicies = Get-HostedContentFilterPolicy

foreach ($policy in $spamPolicies) {
    Set-CurrentPolicy -Section "Anti-Spam ZAP" -PolicyName $policy.Name

    # SpamZapEnabled — must be enabled (True)
    Test-Setting -Setting "SpamZapEnabled"  -CurrentValue $policy.SpamZapEnabled  -RecommendedValue "True"

    # PhishZapEnabled — must be enabled (True)
    Test-Setting -Setting "PhishZapEnabled" -CurrentValue $policy.PhishZapEnabled -RecommendedValue "True"

    # Verify that ZAP-associated actions are effective
    # ZAP moves/quarantines based on these actions — if the action is "NoAction", ZAP is useless
    $script:totalChecks++
    if ($policy.SpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "SpamAction (ZAP action for spam)" `
                     -CurrentValue $policy.SpamAction `
                     -RecommendedValue "MoveToJmf or Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "SpamAction (ZAP action for spam)" `
                     -CurrentValue "$($policy.SpamAction)" `
                     -RecommendedValue "MoveToJmf or Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.PhishSpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "PhishSpamAction (ZAP action for phish)" `
                     -CurrentValue $policy.PhishSpamAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "PhishSpamAction (ZAP action for phish)" `
                     -CurrentValue "$($policy.PhishSpamAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.HighConfidencePhishAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "HighConfidencePhishAction (ZAP action for HC phish)" `
                     -CurrentValue $policy.HighConfidencePhishAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "HighConfidencePhishAction (ZAP action for HC phish)" `
                     -CurrentValue "$($policy.HighConfidencePhishAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    $script:totalChecks++
    if ($policy.HighConfidenceSpamAction -eq "NoAction") {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "HighConfidenceSpamAction (ZAP action for HC spam)" `
                     -CurrentValue $policy.HighConfidenceSpamAction `
                     -RecommendedValue "Quarantine" `
                     -Status 'FAIL'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "HighConfidenceSpamAction (ZAP action for HC spam)" `
                     -CurrentValue "$($policy.HighConfidenceSpamAction)" `
                     -RecommendedValue "Quarantine" `
                     -Status 'PASS'
    }

    # Check if there are AllowedSenders/Domains that could exclude messages from ZAP
    $script:totalChecks++
    if ($policy.AllowedSenders.Count -gt 0 -or $policy.AllowedSenderDomains.Count -gt 0) {
        $script:warnCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
        Write-Status -Setting "AllowedSenders/Domains (exclude ZAP)" `
                     -CurrentValue "Senders: $($policy.AllowedSenders.Count), Domains: $($policy.AllowedSenderDomains.Count)" `
                     -RecommendedValue "0 — allow lists prevent ZAP actions" `
                     -Status 'WARN'
    }
    else {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "AllowedSenders/Domains" -CurrentValue "None" -RecommendedValue "0" -Status 'PASS'
    }
}

Write-Host "  Anti-Spam ZAP validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# 2. ANTI-MALWARE — ZAP for Malware
# ═════════════════════════════════════════════
Write-Host "2. Validating ZAP in Anti-Malware policies..." -ForegroundColor Yellow

$malwarePolicies = Get-MalwareFilterPolicy

foreach ($policy in $malwarePolicies) {
    Set-CurrentPolicy -Section "Anti-Malware ZAP" -PolicyName $policy.Name

    # ZapEnabled — must be enabled (True)
    Test-Setting -Setting "ZapEnabled" -CurrentValue $policy.ZapEnabled -RecommendedValue "True"

    # EnableFileFilter amplifies ZAP effectiveness by blocking dangerous types
    Test-SettingWarn -Setting "EnableFileFilter (complements ZAP)" -CurrentValue $policy.EnableFileFilter -RecommendedValue "True"

    # QuarantineTag — must be configured for ZAP to act
    $script:totalChecks++
    if ($policy.QuarantineTag) {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "QuarantineTag (ZAP destination)" -CurrentValue $policy.QuarantineTag -RecommendedValue "Configured" -Status 'PASS'
    }
    else {
        $script:warnCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
        Write-Status -Setting "QuarantineTag (ZAP destination)" -CurrentValue "<not configured>" -RecommendedValue "Configure" -Status 'WARN'
    }
}

Write-Host "  Anti-Malware ZAP validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# 3. ANTI-PHISHING — ZAP for spoofing
# ═════════════════════════════════════════════
Write-Host "3. Validating Anti-Phishing configuration relevant to ZAP..." -ForegroundColor Yellow

$phishPolicies = Get-AntiPhishPolicy

foreach ($policy in $phishPolicies) {
    Set-CurrentPolicy -Section "Anti-Phishing (ZAP impact)" -PolicyName $policy.Name

    # Enabled — if the policy is disabled, ZAP cannot act based on its detections
    Test-Setting -Setting "Enabled" -CurrentValue $policy.Enabled -RecommendedValue "True"

    # EnableSpoofIntelligence — improves detection that ZAP can then use
    Test-Setting -Setting "EnableSpoofIntelligence" -CurrentValue $policy.EnableSpoofIntelligence -RecommendedValue "True"

    # AuthenticationFailAction — action when authentication fails (spoofing), ZAP respects it
    Test-Setting -Setting "AuthenticationFailAction" -CurrentValue $policy.AuthenticationFailAction -RecommendedValue "MoveToJmf"

    # HonorDmarcPolicy — ZAP respects DMARC reject/quarantine
    Test-SettingWarn -Setting "HonorDmarcPolicy" -CurrentValue $policy.HonorDmarcPolicy -RecommendedValue "True"
}

Write-Host "  Anti-Phishing (ZAP impact) validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# 4. TRANSPORT RULES — ZAP Exceptions
# ═════════════════════════════════════════════
Write-Host "4. Searching for transport rules that may affect ZAP..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Transport Rules" -PolicyName "ZAP Exceptions"

$transportRules = Get-TransportRule -ResultSize Unlimited

# Search for rules that set SCL=-1 (bypass filtering = bypass ZAP)
$sclBypassRules = @($transportRules | Where-Object { $_.SetSCL -eq -1 })

$script:totalChecks++
if ($sclBypassRules.Count -gt 0) {
    $script:warnCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
    $ruleNames = ($sclBypassRules | ForEach-Object { $_.Name }) -join '; '
    Write-Status -Setting "Rules with SCL=-1 (bypass ZAP)" `
                 -CurrentValue "$($sclBypassRules.Count) rule(s): $ruleNames" `
                 -RecommendedValue "0 — SCL=-1 prevents ZAP from acting" `
                 -Status 'WARN'
}
else {
    $script:passCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
    Write-Status -Setting "Rules with SCL=-1 (bypass ZAP)" -CurrentValue "None" -RecommendedValue "0" -Status 'PASS'
}

# Search for rules that set HeaderContains X-MS-Exchange-Organization-SkipSafeLinksProcessing or similar
$skipProcessingRules = @($transportRules | Where-Object {
    $_.SetHeaderName -match 'X-MS-Exchange-Organization-SkipSafe|X-MS-Exchange-Organization-AuthAs' -or
    $_.SetHeaderValue -match 'Internal'
})

$script:totalChecks++
if ($skipProcessingRules.Count -gt 0) {
    $script:warnCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
    $ruleNames = ($skipProcessingRules | ForEach-Object { $_.Name }) -join '; '
    Write-Status -Setting "Rules with headers that skip protection" `
                 -CurrentValue "$($skipProcessingRules.Count) rule(s): $ruleNames" `
                 -RecommendedValue "0 — may interfere with ZAP actions" `
                 -Status 'WARN'
}
else {
    $script:passCount++
    if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
    Write-Status -Setting "Rules with headers that skip protection" -CurrentValue "None" -RecommendedValue "0" -Status 'PASS'
}

Write-Host "  Transport rules validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# 5. QUARANTINE POLICIES — ZAP Actions
# ═════════════════════════════════════════════
Write-Host "5. Validating quarantine policies associated with ZAP..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Quarantine" -PolicyName "Quarantine policies"

try {
    $quarantinePolicies = Get-QuarantinePolicy -ErrorAction Stop

    # Verify quarantine policies are configured
    $script:totalChecks++
    if ($quarantinePolicies.Count -gt 0) {
        $script:passCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
        Write-Status -Setting "Quarantine policies defined" `
                     -CurrentValue "$($quarantinePolicies.Count) policy(ies)" `
                     -RecommendedValue "At least 1" `
                     -Status 'PASS'
    }
    else {
        $script:failCount++
        if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Fail++ }
        Write-Status -Setting "Quarantine policies defined" `
                     -CurrentValue "0" `
                     -RecommendedValue "Configure quarantine policies" `
                     -Status 'FAIL'
    }

    # Verify each quarantine policy
    foreach ($qPolicy in $quarantinePolicies) {
        Set-CurrentPolicy -Section "Quarantine" -PolicyName $qPolicy.Name

        # EndUserQuarantinePermissionsValue — prevent users from releasing phish/malware messages
        # Value 0 is most restrictive (AdminOnlyAccessPolicy), 27 is moderate, high values are permissive
        if ($null -ne $qPolicy.EndUserQuarantinePermissionsValue) {
            $script:totalChecks++
            if ([int]$qPolicy.EndUserQuarantinePermissionsValue -le 27) {
                $script:passCount++
                if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
                Write-Status -Setting "EndUserQuarantinePermissionsValue" `
                             -CurrentValue "$($qPolicy.EndUserQuarantinePermissionsValue)" `
                             -RecommendedValue "0-27 (restrictive)" `
                             -Status 'PASS'
            }
            else {
                $script:warnCount++
                if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
                Write-Status -Setting "EndUserQuarantinePermissionsValue" `
                             -CurrentValue "$($qPolicy.EndUserQuarantinePermissionsValue)" `
                             -RecommendedValue "0-27 — high values allow users to release messages purged by ZAP" `
                             -Status 'WARN'
            }
        }

        # ESNEnabled — quarantine notifications to user
        if ($null -ne $qPolicy.ESNEnabled) {
            Test-SettingWarn -Setting "ESNEnabled (quarantine notifications)" -CurrentValue $qPolicy.ESNEnabled -RecommendedValue "True"
        }
    }
}
catch {
    $script:totalChecks++
    $script:warnCount++
    Write-Status -Setting "Quarantine policy access" `
                 -CurrentValue "Not available: $($_.Exception.Message)" `
                 -RecommendedValue "Verify permissions" `
                 -Status 'WARN'
}

Write-Host "  Quarantine policies validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# 6. PRESET SECURITY POLICIES — ZAP Coverage
# ═════════════════════════════════════════════
Write-Host "6. Validating Preset Security Policies (ZAP coverage)..." -ForegroundColor Yellow

Set-CurrentPolicy -Section "Preset Security Policies" -PolicyName "Standard / Strict"

try {
    $eopPreset = Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
    $atpPreset = Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue

    $script:totalChecks++
    if ($eopPreset) {
        $enabledEop = @($eopPreset | Where-Object { $_.State -eq 'Enabled' })
        if ($enabledEop.Count -gt 0) {
            $script:passCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            $names = ($enabledEop | ForEach-Object { $_.Name }) -join ', '
            Write-Status -Setting "EOP Preset Policies activas" `
                         -CurrentValue "$names" `
                         -RecommendedValue "Standard and/or Strict enabled" `
                         -Status 'PASS'
        }
        else {
            $script:warnCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "EOP Preset Policies activas" `
                         -CurrentValue "None enabled" `
                         -RecommendedValue "Enable Standard or Strict — includes ZAP enabled by default" `
                         -Status 'WARN'
        }
    }
    else {
        $script:totalChecks--
        # No preset rules found — not an error, just not configured
    }

    $script:totalChecks++
    if ($atpPreset) {
        $enabledAtp = @($atpPreset | Where-Object { $_.State -eq 'Enabled' })
        if ($enabledAtp.Count -gt 0) {
            $script:passCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Pass++ }
            $names = ($enabledAtp | ForEach-Object { $_.Name }) -join ', '
            Write-Status -Setting "ATP Preset Policies activas" `
                         -CurrentValue "$names" `
                         -RecommendedValue "Standard and/or Strict enabled" `
                         -Status 'PASS'
        }
        else {
            $script:warnCount++
            if ($script:policyResults.ContainsKey($script:currentPolicyKey)) { $script:policyResults[$script:currentPolicyKey].Warn++ }
            Write-Status -Setting "ATP Preset Policies activas" `
                         -CurrentValue "None enabled" `
                         -RecommendedValue "Enable Standard or Strict" `
                         -Status 'WARN'
        }
    }
    else {
        $script:totalChecks--
    }
}
catch {
    # Preset cmdlets not available — skip silently
}

Write-Host "  Preset Security Policies validated." -ForegroundColor Green

# ═════════════════════════════════════════════
# CONSOLE SUMMARY
# ═════════════════════════════════════════════
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " ZAP Validation Summary"                        -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Total checks       : $($script:totalChecks)"  -ForegroundColor White
Write-Host "  Passed (PASS)      : $($script:passCount)"    -ForegroundColor Green
Write-Host "  Warnings (WARN)    : $($script:warnCount)"    -ForegroundColor Yellow
Write-Host "  Failed (FAIL)      : $($script:failCount)"    -ForegroundColor Red

if ($script:totalChecks -gt 0) {
    $pct = [math]::Round(($script:passCount / $script:totalChecks) * 100, 1)
    Write-Host "  Compliance         : $pct%" -ForegroundColor $(if ($pct -ge 80) { 'Green' } elseif ($pct -ge 60) { 'Yellow' } else { 'Red' })
}

# ═════════════════════════════════════════════
# HTML REPORT GENERATION
# ═════════════════════════════════════════════

$safeTenantName   = $tenantName -replace '[\\/:*?"<>|]', '_'
$reportTimestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$date2             = Get-Date -Format "ddMMyyHHmmss"
$htmlFile          = "ZAP_Validation_${safeTenantName}_${date2}.html"

# Build section rows for the HTML detail table
$htmlDetailRows = ""
$lastSection = ""
foreach ($row in $script:htmlRows) {
    $statusClass = switch ($row.Status) {
        'PASS' { 'status-pass' }
        'WARN' { 'status-warn' }
        'FAIL' { 'status-fail' }
        'INFO' { 'status-info' }
        default { '' }
    }
    $statusIcon = switch ($row.Status) {
        'PASS' { '&#9989;' }
        'WARN' { '&#9888;&#65039;' }
        'FAIL' { '&#10060;' }
        'INFO' { '&#8505;&#65039;' }
        default { '' }
    }

    if ($row.Section -and $row.Section -ne $lastSection) {
        $htmlDetailRows += "<tr class='section-row'><td colspan='5'><strong>$($row.Section)</strong></td></tr>`n"
        $lastSection = $row.Section
    }

    $safeCurrentValue = [System.Web.HttpUtility]::HtmlEncode($row.CurrentValue)
    $safeRecommended  = [System.Web.HttpUtility]::HtmlEncode($row.Recommended)
    $safeSetting      = [System.Web.HttpUtility]::HtmlEncode($row.Setting)
    $safePolicyName   = [System.Web.HttpUtility]::HtmlEncode($row.PolicyName)

    $htmlDetailRows += @"
<tr>
    <td class='$statusClass'>$statusIcon $($row.Status)</td>
    <td class='policy-name'>$safePolicyName</td>
    <td><strong>$safeSetting</strong></td>
    <td><code>$safeCurrentValue</code></td>
    <td><code>$safeRecommended</code></td>
</tr>
"@
}

# Build policy summary rows
$policySummaryRows = ""
foreach ($key in $script:policyResults.Keys | Sort-Object) {
    $parts   = $key -split '\|', 2
    $section = $parts[0]
    $name    = $parts[1]
    $r       = $script:policyResults[$key]
    $total   = $r.Pass + $r.Fail + $r.Warn
    if ($total -gt 0) { $pctP = [math]::Round(($r.Pass / $total) * 100, 0) } else { $pctP = 0 }

    if ($pctP -ge 80) { $barColor = '#28a745' } elseif ($pctP -ge 60) { $barColor = '#ffc107' } else { $barColor = '#dc3545' }

    $policySummaryRows += @"
<tr>
    <td>$section</td>
    <td><strong>$name</strong></td>
    <td class='text-center'>$($r.Pass)</td>
    <td class='text-center'>$($r.Warn)</td>
    <td class='text-center'>$($r.Fail)</td>
    <td>
        <div class='progress' style='height:20px;'>
            <div class='progress-bar' style='width:${pctP}%;background-color:${barColor};' role='progressbar'>$pctP%</div>
        </div>
    </td>
</tr>
"@
}

# Dashboard card colors
if ($script:totalChecks -gt 0) {
    $overallPct = [math]::Round(($script:passCount / $script:totalChecks) * 100, 1)
}
else {
    $overallPct = 0
}
if ($overallPct -ge 80) { $overallColor = '#28a745' } elseif ($overallPct -ge 60) { $overallColor = '#ffc107' } else { $overallColor = '#dc3545' }

$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZAP Configuration Validation Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f7f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .hero { background-color: #0078d4; color: white; padding: 35px 20px; border-bottom: 4px solid #005a9e; text-align: center; }
        .hero h1 { font-size: 1.6rem; font-weight: 600; margin-bottom: 8px; }
        .hero p { font-size: 1.35rem; font-weight: 400; margin: 2px 0; opacity: 0.9; }
        .logo-img { max-height: 35px; filter: brightness(0) invert(1); margin-bottom: 10px; }
        .stat-number { font-size: 2.2rem; font-weight: 800; }
        .stat-label { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }
        .table-card { background: white; border: 1px solid #e1e4e8; border-radius: 8px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .section-divider { border-bottom: 2px solid #0078d4; color: #0078d4; font-weight: bold; margin: 25px 0 15px 0; font-size: 1.15rem; padding-bottom: 5px; }
        .section-row td { background-color: #e8f4fd !important; font-size: 1rem; padding: 10px 15px !important; border-top: 2px solid #0078d4; }
        .status-pass { color: #28a745; font-weight: 700; }
        .status-warn { color: #d39e00; font-weight: 700; }
        .status-fail { color: #dc3545; font-weight: 700; }
        .status-info { color: #0078d4; font-weight: 700; }
        .policy-name { color: #6c757d; font-size: 0.8rem; }
        .detail-table th { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; background-color: #f8f9fa; }
        .detail-table td { font-size: 0.85rem; vertical-align: middle; }
        .detail-table code { font-size: 0.8rem; color: #333; background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        .progress { border-radius: 10px; background-color: #e9ecef; }
        .progress-bar { border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
        .card-stat { border-radius: 10px; color: white; padding: 20px; text-align: center; }
        .link-docs { color: #107c10; text-decoration: none; font-weight: 600; }
        .link-docs:hover { text-decoration: underline; color: #0b5e0b; }
        .task-link { transition: background-color 0.2s, transform 0.1s; }
        .task-link:hover { background-color: #e8f4fd; transform: translateX(4px); border-left: 4px solid #0078d4; }
        .zap-info { background: linear-gradient(135deg, #e8f4fd 0%, #f0f7ff 100%); border-left: 4px solid #0078d4; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .zap-info h5 { color: #0078d4; font-weight: 700; }
        .zap-info ul li { margin-bottom: 6px; font-size: 0.9rem; }
        @media print {
            .hero { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .card-stat { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
    </style>
</head>
<body>

    <!-- Hero Header -->
    <div class="hero">
        <img src="https://dco.microsoft.com/Images/microsoft-white-logo.png" alt="Microsoft" class="logo-img">
        <h1> ZAP (Zero-hour Auto Purge) Validation</h1>
        <p style="font-size: 0.95rem;">Date: $reportTimestamp</p>
        <p style="font-size: 1.5rem;">Tenant: <strong>$tenantName</strong></p>
        <p><em>&ldquo;Technology enables security, but discipline ensures its effectiveness&rdquo;</em></p>
    </div>

    <div class="container-fluid px-4">

        <!-- ZAP Info Box -->
        <div class="zap-info mt-4">
            <h5>&#9432; What is ZAP (Zero-hour Auto Purge)?</h5>
            <p>ZAP is a protection feature in Microsoft 365 that <strong>retroactively</strong> detects and neutralizes malicious messages
            that were already delivered to user mailboxes. It acts when the filtering engine updates its signatures and reclassifies
            a previously delivered message as spam, phishing, or malware.</p>
            <ul>
                <li><strong>Spam ZAP:</strong> Moves messages reclassified as spam to the Junk Email folder.</li>
                <li><strong>Phish ZAP:</strong> Sends messages reclassified as phishing to quarantine.</li>
                <li><strong>Malware ZAP:</strong> Sends messages with malicious attachments to quarantine.</li>
            </ul>
            <p><strong>Important:</strong> ZAP only acts on <em>unread</em> messages in the inbox (except for high-confidence malware).
            Allowed sender lists (Allow lists) and transport rules with SCL=-1 <strong>can prevent</strong> ZAP from acting.</p>
        </div>

        <!-- Dashboard Cards -->
        <div class="row g-3 mt-3 text-center">
            <div class="col">
                <div class="card-stat" style="background-color: #0078d4;">
                    <div class="stat-label">Total Checks</div>
                    <div class="stat-number">$($script:totalChecks)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: $overallColor;">
                    <div class="stat-label">ZAP Compliance</div>
                    <div class="stat-number">$overallPct%</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #28a745;">
                    <div class="stat-label">Passed</div>
                    <div class="stat-number">$($script:passCount)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #ffc107; color: #333;">
                    <div class="stat-label">Warnings</div>
                    <div class="stat-number">$($script:warnCount)</div>
                </div>
            </div>
            <div class="col">
                <div class="card-stat" style="background-color: #dc3545;">
                    <div class="stat-label">Failed</div>
                    <div class="stat-number">$($script:failCount)</div>
                </div>
            </div>
        </div>

        <!-- Policy Summary -->
        <div class="table-card">
            <div class="section-divider">&#128202; Summary by Policy</div>
            <table class="table table-sm table-hover">
                <thead>
                    <tr>
                        <th>Section</th>
                        <th>Policy</th>
                        <th class="text-center">OK</th>
                        <th class="text-center">WARN</th>
                        <th class="text-center">FAIL</th>
                        <th style="min-width:150px;">Compliance</th>
                    </tr>
                </thead>
                <tbody>
                    $policySummaryRows
                </tbody>
            </table>
        </div>

        <!-- Detail Table -->
        <div class="table-card">
            <div class="section-divider">&#128269; Verification Details ($($script:totalChecks) checks)</div>
            <table class="table table-sm table-hover detail-table">
                <thead>
                    <tr>
                        <th style="width:80px;">Status</th>
                        <th>Policy</th>
                        <th>Setting</th>
                        <th>Current Value</th>
                        <th>Recommended</th>
                    </tr>
                </thead>
                <tbody>
                    $htmlDetailRows
                </tbody>
            </table>
        </div>

        <!-- Remediation Guide -->
        <div class="card shadow-sm border-danger mb-4">
            <div class="card-header text-white bg-danger">&#128295; ZAP Remediation Guide</div>
            <div class="card-body">
                <h6 class="fw-bold">If ZAP is disabled in Anti-Spam:</h6>
                <pre class="bg-light p-3 rounded"><code>Get-HostedContentFilterPolicy | Set-HostedContentFilterPolicy -SpamZapEnabled `$true -PhishZapEnabled `$true</code></pre>

                <h6 class="fw-bold mt-3">If ZAP is disabled in Anti-Malware:</h6>
                <pre class="bg-light p-3 rounded"><code>Get-MalwareFilterPolicy | Set-MalwareFilterPolicy -ZapEnabled `$true</code></pre>

                <h6 class="fw-bold mt-3">If there are transport rules with SCL=-1:</h6>
                <p class="text-muted">Review and remove or modify rules that set <code>SCL=-1</code>, as they prevent ZAP from acting on messages matching those rules.</p>
                <pre class="bg-light p-3 rounded"><code>Get-TransportRule | Where-Object { `$_.SetSCL -eq -1 } | Format-Table Name, State, Priority -AutoSize</code></pre>

                <h6 class="fw-bold mt-3">If Allow Lists are configured:</h6>
                <p class="text-muted">Senders and domains in allow lists are not affected by ZAP. Migrating to Tenant Allow/Block List can provide more secure control.</p>
                <pre class="bg-light p-3 rounded"><code># View current allow lists
Get-HostedContentFilterPolicy | Format-List Name, AllowedSenders, AllowedSenderDomains</code></pre>
            </div>
        </div>

        <!-- Documentation Links -->
        <div class="card shadow-sm border-primary mb-4">
            <div class="card-header text-white" style="background-color: #0078d4;">&#128221; ZAP Documentation — Microsoft Learn</div>
            <div class="card-body">
                <div class="list-group">
                    <div class="list-group-item task-link">
                        <strong>&#128279; Zero-hour auto purge (ZAP) in Microsoft Defender for Office 365</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Recommended settings for EOP and MDO security</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Anti-Spam policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/anti-spam-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Configure Anti-Malware policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Quarantine policies</strong><br>
                        <small><a href="https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies" target="_blank" class="link-docs">&#128218; Microsoft Learn</a></small>
                    </div>
                    <div class="list-group-item task-link">
                        <strong>&#128279; Microsoft Defender Portal — Threat Policies</strong><br>
                        <small><a href="https://security.microsoft.com/threatpolicy" target="_blank" class="link-docs">&#128218; Open portal</a></small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="text-center py-4">
            <p class="text-muted">chiringuito365.com&reg; | Internal Tools 2026</p>
        </div>

    </div><!-- /container -->
</body>
</html>
"@

# Save and open HTML report
$reportPath = Join-Path -Path $reportDir -ChildPath $htmlFile
$htmlReport | Out-File -FilePath $reportPath -Encoding utf8 -Force
Write-Host ""
Write-Host "  HTML report generated: $reportPath" -ForegroundColor Green
Invoke-Item $reportPath
