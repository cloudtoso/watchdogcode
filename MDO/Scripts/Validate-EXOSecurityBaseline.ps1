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
    Validates the security baseline in Exchange Online and generates an HTML dashboard.

.DESCRIPTION
    This script verifies the recommended configurations from the document
    "Baseline to improve the security posture in Exchange Online":

    1. Basic mail flow rules – Microsoft 365
       - Block emails to *.onmicrosoft.com (Comments: "Blocks messages whose 'To' header matches")
       - Quarantine Attachments Can't be inspected (Comments: "content can't be inspected")

    2. RejectDirectSend in Exchange Online
       - Get-OrganizationConfig | Select RejectDirectSend  (expected: $true)

    3. SPF, DKIM, DMARC and MTA-STS Standards
       - DNS query for all accepted tenant domains

    Generates an HTML dashboard-style report with compliance indicators.

.NOTES
    Requires prior connection to Exchange Online:
        Connect-ExchangeOnline

    Requires modules:
        ExchangeOnlineManagement
        DomainHealthChecker (optional, for SPF/DKIM/DMARC)

    Author : Ernesto Cobos Roqueñí, Arturo Mandujano
    Date   : 04/March/2026
    Version: 1.0

    Reference:
    https://github.com/watchdogcode/gol2026/blob/main/MDO/Línea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md
#>

# ─────────────────────────────────────────────
# Module validation
# ─────────────────────────────────────────────
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Write-Host "ExchangeOnlineManagement module installed correctly." -ForegroundColor DarkGray
}
else {
    Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser
}

# ─────────────────────────────────────────────
# Exchange Online connection
# ─────────────────────────────────────────────
try {
    $null = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' }
    if (-not $_) { throw "Not connected" }
}
catch {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false
        Write-Host "Connection established successfully." -ForegroundColor Green
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
}

# ─────────────────────────────────────────────
# Reports folder
# ─────────────────────────────────────────────
$reportDir = "C:\Scripts\SecurityBaseline"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
}
Write-Host "Reports folder exists: $reportDir" -ForegroundColor DarkGray

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$orgConfig  = Get-OrganizationConfig
$tenantName = $orgConfig.DisplayName
$htmlPath   = Join-Path $reportDir "SecurityBaseline_$timestamp.html"

Write-Host "Analyzing recommended baselines..." -ForegroundColor Yellow

# ─────────────────────────────────────────────
# Helper function to convert arrays to string
# ─────────────────────────────────────────────
function ConvertTo-FlatString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ($Value | ForEach-Object { $_.ToString() }) -join "; "
    }
    return $Value.ToString()
}

# ═════════════════════════════════════════════
# SECTION 1: Basic mail flow rules
# ═════════════════════════════════════════════

try {
    $allRules = Get-TransportRule -ResultSize Unlimited | Sort-Object Priority
}
catch {
    $allRules = @()
}

# --- Rule 1: Block emails to *.onmicrosoft.com ---
# Find rule whose Comments contains "Blocks messages whose 'To' header matches"
$blockOnMicrosoftRule = $allRules | Where-Object { $_.Comments -like "*Blocks messages whose 'To' header matches*" }

if ($blockOnMicrosoftRule) {
    $blockOnMicrosoftStatus  = "Implemented"
    $blockOnMicrosoftClass   = "pass"
    $blockOnMicrosoftState   = $blockOnMicrosoftRule.State
    $blockOnMicrosoftName    = $blockOnMicrosoftRule.Name
    $blockOnMicrosoftMode    = $blockOnMicrosoftRule.Mode
    $blockOnMicrosoftDetails = "Rule: $blockOnMicrosoftName | State: $blockOnMicrosoftState | Mode: $blockOnMicrosoftMode"
}
else {
    $blockOnMicrosoftStatus  = "Recommendation not implemented"
    $blockOnMicrosoftClass   = "fail"
    $blockOnMicrosoftState   = "N/A"
    $blockOnMicrosoftName    = "N/A"
    $blockOnMicrosoftMode    = "N/A"
    $blockOnMicrosoftDetails = "No rule found whose Comments contains: Blocks messages whose 'To' header matches"
}

# --- Rule 2: Quarantine Attachments Can't be inspected ---
# Find rule whose Comments contains "content can't be inspected"
$quarantineRule = $allRules | Where-Object { $_.Comments -like "*content can't be inspected*" }

if ($quarantineRule) {
    $quarantineStatus  = "Implemented"
    $quarantineClass   = "pass"
    $quarantineState   = $quarantineRule.State
    $quarantineName    = $quarantineRule.Name
    $quarantineMode    = $quarantineRule.Mode
    $quarantineDetails = "Rule: $quarantineName | State: $quarantineState | Mode: $quarantineMode"
}
else {
    $quarantineStatus  = "Recommendation not implemented"
    $quarantineClass   = "fail"
    $quarantineState   = "N/A"
    $quarantineName    = "N/A"
    $quarantineMode    = "N/A"
    $quarantineDetails = "No rule found whose Comments contains: content can't be inspected"
}

# ═════════════════════════════════════════════
# SECTION 2: RejectDirectSend
# ═════════════════════════════════════════════

$rejectDirectSend = $orgConfig.RejectDirectSend

if ($rejectDirectSend -eq $true) {
    $rejectDSStatus  = "Implemented"
    $rejectDSClass   = "pass"
    $rejectDSDetails = "Set-OrganizationConfig -RejectDirectSend `$true is configured correctly."
}
else {
    $rejectDSStatus  = "Recommendation not implemented"
    $rejectDSClass   = "fail"
    $rejectDSDetails = "RejectDirectSend is set to `$false. It is recommended to run: Set-OrganizationConfig -RejectDirectSend `$true"
}

# ═════════════════════════════════════════════
# SECTION 3: SPF, DKIM, DMARC, MTA-STS Standards
# ═════════════════════════════════════════════

# Check if DomainHealthChecker module is available
$hasDHC = $false
if (Get-Module -ListAvailable -Name DomainHealthChecker) {
    Import-Module DomainHealthChecker -ErrorAction SilentlyContinue
    if (Get-Command -Name Invoke-SpfDkimDmarc -ErrorAction SilentlyContinue) {
        $hasDHC = $true
    }
}

if (-not $hasDHC) {
    try {
        Install-Module DomainHealthChecker -Force -Scope CurrentUser -ErrorAction Stop
        Import-Module DomainHealthChecker -ErrorAction Stop
        $hasDHC = $true
    }
    catch { }
}

# Get accepted domains (including *.onmicrosoft.com)
try {
    $acceptedDomains = Get-AcceptedDomain | Sort-Object DomainName
}
catch {
    $acceptedDomains = @()
}

$domainResults = @()

foreach ($ad in $acceptedDomains) {
    $domain = $ad.DomainName.ToString()

    # SPF
    $spfRecord = ""
    $spfStatus = "fail"
    $spfAdvisory = "Not found"
    try {
        $spfTxt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue |
            Where-Object { ($_.Strings -join '') -match '^\s*v=spf1\b' }
        if ($spfTxt) {
            $spfRecord = ($spfTxt.Strings -join '')
            if ($spfRecord -match '-all') {
                $spfStatus = "pass"
                $spfAdvisory = "SPF with -all (hard fail) — Correct"
            }
            elseif ($spfRecord -match '~all') {
                $spfStatus = "warn"
                $spfAdvisory = "SPF with ~all (soft fail) — -all recommended"
            }
            else {
                $spfStatus = "warn"
                $spfAdvisory = "SPF found but without -all"
            }
        }
    }
    catch { }

    # DKIM (selector1 and selector2 for Microsoft 365)
    $dkimRecord = ""
    $dkimStatus = "fail"
    $dkimAdvisory = "Not found"
    try {
        foreach ($sel in @("selector1","selector2")) {
            $dkimCheck = Resolve-DnsName -Name "$sel._domainkey.$domain" -Type CNAME -ErrorAction SilentlyContinue
            if ($dkimCheck) {
                $dkimRecord = "$sel → $($dkimCheck.NameHost)"
                $dkimStatus = "pass"
                $dkimAdvisory = "DKIM CNAME found for $sel"
                break
            }
        }
    }
    catch { }

    # DMARC
    $dmarcRecord = ""
    $dmarcStatus = "fail"
    $dmarcAdvisory = "Not found"
    try {
        $dmarcTxt = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
        if ($dmarcTxt) {
            $dmarcRecord = ($dmarcTxt.Strings -join '')
            if ($dmarcRecord -match 'p=reject') {
                $dmarcStatus = "pass"
                $dmarcAdvisory = "DMARC with p=reject — Optimal"
            }
            elseif ($dmarcRecord -match 'p=quarantine') {
                $dmarcStatus = "warn"
                $dmarcAdvisory = "DMARC with p=quarantine — p=reject recommended"
            }
            elseif ($dmarcRecord -match 'p=none') {
                $dmarcStatus = "warn"
                $dmarcAdvisory = "DMARC with p=none — Monitoring only, p=reject recommended"
            }
            else {
                $dmarcStatus = "warn"
                $dmarcAdvisory = "DMARC found but without clear policy"
            }
        }
    }
    catch { }

    # MTA-STS
    $mtaRecord = ""
    $mtaStatus = "fail"
    $mtaAdvisory = "Not found"
    try {
        $mtaTxt = Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT -ErrorAction SilentlyContinue
        if ($mtaTxt) {
            $mtaRecord = ($mtaTxt.Strings -join '')
            if ($mtaRecord -match 'v=STSv1') {
                $mtaStatus = "pass"
                $mtaAdvisory = "MTA-STS configured"
            }
            else {
                $mtaStatus = "warn"
                $mtaAdvisory = "Record found but without v=STSv1"
            }
        }
    }
    catch { }

    # If DomainHealthChecker is available, enrich with its analysis
    if ($hasDHC) {
        try {
            $dhc = Invoke-SpfDkimDmarc -Name $domain -ErrorAction SilentlyContinue
            if ($dhc) {
                if ($dhc.SpfAdvisory) { $spfAdvisory = $dhc.SpfAdvisory }
                if ($dhc.DkimAdvisory) { $dkimAdvisory = $dhc.DkimAdvisory }
                if ($dhc.DmarcAdvisory) { $dmarcAdvisory = $dhc.DmarcAdvisory }
                if ($dhc.MtaAdvisory) { $mtaAdvisory = $dhc.MtaAdvisory }
                if ($dhc.DkimRecord -and $dhc.DkimRecord -ne "yourDkimRecord") {
                    $dkimRecord = $dhc.DkimRecord
                    $dkimStatus = "pass"
                }
            }
        }
        catch { }
    }

    $domainResults += [PSCustomObject]@{
        Domain       = $domain
        DomainType   = $ad.DomainType
        Default      = $ad.Default
        SPFRecord    = $spfRecord
        SPFStatus    = $spfStatus
        SPFAdvisory  = $spfAdvisory
        DKIMRecord   = $dkimRecord
        DKIMStatus   = $dkimStatus
        DKIMAdvisory = $dkimAdvisory
        DMARCRecord  = $dmarcRecord
        DMARCStatus  = $dmarcStatus
        DMARCAdvisory = $dmarcAdvisory
        MTARecord    = $mtaRecord
        MTAStatus    = $mtaStatus
        MTAAdvisory  = $mtaAdvisory
    }
}

# ─────────────────────────────────────────────
# Dashboard counters
# ─────────────────────────────────────────────
$totalChecks = 0
$passChecks  = 0
$failChecks  = 0
$warnChecks  = 0

# Count flow rules
foreach ($c in @($blockOnMicrosoftClass, $quarantineClass, $rejectDSClass)) {
    $totalChecks++
    switch ($c) {
        "pass" { $passChecks++ }
        "fail" { $failChecks++ }
        "warn" { $warnChecks++ }
    }
}

# Count domains
foreach ($dr in $domainResults) {
    foreach ($st in @($dr.SPFStatus, $dr.DKIMStatus, $dr.DMARCStatus, $dr.MTAStatus)) {
        $totalChecks++
        switch ($st) {
            "pass" { $passChecks++ }
            "fail" { $failChecks++ }
            "warn" { $warnChecks++ }
        }
    }
}

$compliancePercent = if ($totalChecks -gt 0) { [math]::Round(($passChecks / $totalChecks) * 100, 1) } else { 0 }

# ─────────────────────────────────────────────
# Generate HTML Dashboard
# ─────────────────────────────────────────────

$htmlHead = @"
<style>
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; background: #f0f2f5; color: #333; }
    .header { background: linear-gradient(135deg, #0078d4, #005a9e); color: #fff; padding: 30px; border-radius: 10px; margin-bottom: 25px; display: flex; align-items: center; justify-content: space-between; }
    .header-text { flex: 1; }
    .header-logo { flex-shrink: 0; margin-left: 30px; }
    .header-logo img { height: 50px; filter: brightness(0) invert(1); }
    .header h1 { margin: 0 0 5px 0; font-size: 24px; }
    .header p { margin: 5px 0; opacity: 0.9; font-size: 14px; }
    .header .quote { font-style: italic; opacity: 0.8; margin-top: 10px; font-size: 17px; }

    .dashboard { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
    .card { background: #fff; border-radius: 10px; padding: 20px; flex: 1; min-width: 180px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
    .card .number { font-size: 36px; font-weight: bold; margin: 10px 0; }
    .card .label { font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
    .card.total .number { color: #0078d4; }
    .card.pass .number { color: #107c10; }
    .card.fail .number { color: #d13438; }
    .card.warn .number { color: #ff8c00; }
    .card.percent .number { color: #0078d4; }

    .section { background: #fff; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .section h2 { color: #0078d4; margin-top: 0; border-bottom: 2px solid #0078d4; padding-bottom: 8px; font-size: 18px; }
    .section h3 { color: #005a9e; margin-top: 20px; font-size: 15px; }

    table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
    th { background: #0078d4; color: #fff; padding: 10px 12px; text-align: left; }
    td { border: 1px solid #e0e0e0; padding: 8px 12px; }
    tr:nth-child(even) { background: #f8f9fa; }
    tr:nth-child(odd) { background: #fff; }

    .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #fff; }
    .badge.pass { background: #107c10; }
    .badge.fail { background: #d13438; }
    .badge.warn { background: #ff8c00; }

    .status-row { display: flex; align-items: center; padding: 12px 15px; border-radius: 8px; margin-bottom: 8px; }
    .status-row.pass { background: #f0fff0; border-left: 4px solid #107c10; }
    .status-row.fail { background: #fff5f5; border-left: 4px solid #d13438; }
    .status-row.warn { background: #fffaf0; border-left: 4px solid #ff8c00; }
    .status-row .icon { font-size: 20px; margin-right: 12px; }
    .status-row .info { flex: 1; }
    .status-row .info .title { font-weight: bold; font-size: 14px; }
    .status-row .info .detail { font-size: 12px; color: #666; margin-top: 3px; }

    .ref-link { font-size: 12px; color: #0078d4; text-decoration: none; }
    .ref-link:hover { text-decoration: underline; }

    footer { text-align: center; margin-top: 30px; padding: 15px 0; border-top: 2px solid #0078d4; color: #555; font-size: 13px; }
</style>
"@

# Header
$htmlBody = @"
<div class="header">
    <div class="header-text">
        <h1>&#128737; Security Baseline Validation &mdash; Exchange Online</h1>
        <p><strong>Tenant:</strong> $tenantName &nbsp;|&nbsp; <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p class="quote">&ldquo;Technology enables security, but discipline ensures its effectiveness&rdquo;</p>
    </div>
    <div class="header-logo">
        <img src="https://cdn.theatlantic.com/assets/marketing/prod/logos/2024/03/MS-Security_logo_horiz_c-gray_rgb_1_O3yRRKf.png" alt="Microsoft Security">
    </div>
</div>
"@

# Dashboard cards
$htmlBody += @"
<div class="dashboard">
    <div class="card total">
        <div class="label">Checks</div>
        <div class="number">$totalChecks</div>
    </div>
    <div class="card pass">
        <div class="label">Compliant</div>
        <div class="number">$passChecks</div>
    </div>
    <div class="card fail">
        <div class="label">Non-Compliant</div>
        <div class="number">$failChecks</div>
    </div>
    <div class="card warn">
        <div class="label">Warning</div>
        <div class="number">$warnChecks</div>
    </div>
    <div class="card percent">
        <div class="label">Compliance</div>
        <div class="number">${compliancePercent}%</div>
    </div>
</div>
"@

# ─── Section 1: Mail flow rules ───
$blockIcon = if ($blockOnMicrosoftClass -eq "pass") { "&#9989;" } else { "&#10060;" }
$quarantineIcon = if ($quarantineClass -eq "pass") { "&#9989;" } else { "&#10060;" }

$htmlBody += @"
<div class="section">
    <h2>1. Basic mail flow rules &mdash; Microsoft 365</h2>
    <p style="font-size:13px; color:#666;">Recommended transport rules are verified to protect against emails to onmicrosoft.com domains and uninspectable attachments.</p>

    <div class="status-row $blockOnMicrosoftClass">
        <div class="icon">$blockIcon</div>
        <div class="info">
            <div class="title">Block emails to *.onmicrosoft.com</div>
            <div class="detail">State: <span class="badge $blockOnMicrosoftClass">$blockOnMicrosoftStatus</span></div>
            <div class="detail">$blockOnMicrosoftDetails</div>
            <div class="detail">Searches in Comments: <em>&quot;Blocks messages whose 'To' header matches&quot;</em></div>
        </div>
    </div>

    <div class="status-row $quarantineClass">
        <div class="icon">$quarantineIcon</div>
        <div class="info">
            <div class="title">Quarantine Attachments Can't be inspected</div>
            <div class="detail">State: <span class="badge $quarantineClass">$quarantineStatus</span></div>
            <div class="detail">$quarantineDetails</div>
            <div class="detail">Searches in Comments: <em>&quot;If the message has any attachment whose content can't be inspected&quot;</em></div>
        </div>
    </div>

    <h3>All tenant transport rules</h3>
    <table>
        <tr><th>Priority</th><th>Name</th><th>State</th><th>Mode</th><th>Last Modified</th><th>Comments (excerpt)</th></tr>
"@

foreach ($rule in $allRules) {
    $stateClass = if ($rule.State -eq 'Enabled') { 'pass' } else { 'fail' }
    $commentsExcerpt = if ($rule.Comments) { ($rule.Comments).Substring(0, [Math]::Min(100, $rule.Comments.Length)) + $(if ($rule.Comments.Length -gt 100) { "..." } else { "" }) } else { "&mdash;" }
    $htmlBody += "<tr>"
    $htmlBody += "<td style='text-align:center'>$($rule.Priority)</td>"
    $htmlBody += "<td>$($rule.Name)</td>"
    $htmlBody += "<td><span class='badge $stateClass'>$($rule.State)</span></td>"
    $htmlBody += "<td>$($rule.Mode)</td>"
    $htmlBody += "<td>$($rule.WhenChanged)</td>"
    $htmlBody += "<td style='font-size:11px'>$commentsExcerpt</td>"
    $htmlBody += "</tr>"
}

$htmlBody += "</table>"
$htmlBody += '<p style="font-size:11px; margin-top:10px;"><a class="ref-link" href="https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules" target="_blank">&#128279; Reference: Mail flow rules in Exchange Online</a></p>'
$htmlBody += "</div>"

# ─── Section 2: RejectDirectSend ───
$rejectIcon = if ($rejectDSClass -eq "pass") { "&#9989;" } else { "&#10060;" }

$htmlBody += @"
<div class="section">
    <h2>2. RejectDirectSend in Exchange Online</h2>
    <p style="font-size:13px; color:#666;">Direct Send allows sending emails to internal tenant mailboxes anonymously via SMTP port 25. Enabling RejectDirectSend blocks this attack vector.</p>

    <div class="status-row $rejectDSClass">
        <div class="icon">$rejectIcon</div>
        <div class="info">
            <div class="title">RejectDirectSend = $rejectDirectSend</div>
            <div class="detail">State: <span class="badge $rejectDSClass">$rejectDSStatus</span></div>
            <div class="detail">$rejectDSDetails</div>
        </div>
    </div>

    <table style="margin-top:15px;">
        <tr><th>Property</th><th>Current Value</th><th>Recommended Value</th><th>Result</th></tr>
        <tr>
            <td><code>RejectDirectSend</code></td>
            <td><strong>$rejectDirectSend</strong></td>
            <td><strong>True</strong></td>
            <td><span class="badge $rejectDSClass">$(if ($rejectDSClass -eq 'pass') { 'Compliant' } else { 'Non-Compliant' })</span></td>
        </tr>
    </table>

    <p style="font-size:11px; margin-top:10px;">
        <a class="ref-link" href="https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig#-rejectdirectsend" target="_blank">&#128279; Reference: Set-OrganizationConfig -RejectDirectSend</a>
    </p>
</div>
"@

# ─── Section 3: SPF, DKIM, DMARC, MTA-STS ───
$spfPassCount   = ($domainResults | Where-Object { $_.SPFStatus -eq "pass" } | Measure-Object).Count
$dkimPassCount  = ($domainResults | Where-Object { $_.DKIMStatus -eq "pass" } | Measure-Object).Count
$dmarcPassCount = ($domainResults | Where-Object { $_.DMARCStatus -eq "pass" } | Measure-Object).Count
$mtaPassCount   = ($domainResults | Where-Object { $_.MTAStatus -eq "pass" } | Measure-Object).Count
$totalDomains   = ($domainResults | Measure-Object).Count

$htmlBody += @"
<div class="section">
    <h2>3. SPF, DKIM, DMARC and MTA-STS Standards</h2>
    <p style="font-size:13px; color:#666;">DNS verification of email authentication standards for all accepted tenant domains (excluding *.onmicrosoft.com).</p>

    <div class="dashboard" style="margin-bottom:15px;">
        <div class="card" style="min-width:120px;"><div class="label">Domains</div><div class="number" style="color:#0078d4;">$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">SPF OK</div><div class="number" style="color:#107c10;">$spfPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">DKIM OK</div><div class="number" style="color:#107c10;">$dkimPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">DMARC OK</div><div class="number" style="color:#107c10;">$dmarcPassCount/$totalDomains</div></div>
        <div class="card" style="min-width:120px;"><div class="label">MTA-STS OK</div><div class="number" style="color:#107c10;">$mtaPassCount/$totalDomains</div></div>
    </div>

    <table>
        <tr>
            <th>Domain</th>
            <th>Type</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
            <th>MTA-STS</th>
        </tr>
"@

foreach ($dr in $domainResults) {
    $htmlBody += "<tr>"
    $htmlBody += "<td><strong>$($dr.Domain)</strong>$(if ($dr.Default) { ' <span style=''font-size:10px; color:#0078d4;''>(Default)</span>' })</td>"
    $htmlBody += "<td>$($dr.DomainType)</td>"
    $htmlBody += "<td><span class='badge $($dr.SPFStatus)'>$($dr.SPFStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.DKIMStatus)'>$($dr.DKIMStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.DMARCStatus)'>$($dr.DMARCStatus.ToUpper())</span></td>"
    $htmlBody += "<td><span class='badge $($dr.MTAStatus)'>$($dr.MTAStatus.ToUpper())</span></td>"
    $htmlBody += "</tr>"
}

$htmlBody += "</table>"

# Detail by domain table
$htmlBody += "<h3>Detail by domain</h3>"

foreach ($dr in $domainResults) {
    $htmlBody += @"
    <table style="margin-bottom:15px;">
        <tr><th colspan="3" style="background:#005a9e;">$($dr.Domain)</th></tr>
        <tr><td style="width:100px;"><strong>SPF</strong></td><td style="width:80px;"><span class="badge $($dr.SPFStatus)">$($dr.SPFStatus.ToUpper())</span></td><td style="font-size:11px;">$($dr.SPFAdvisory)<br/><code style="font-size:10px; word-break:break-all;">$($dr.SPFRecord)</code></td></tr>
        <tr><td><strong>DKIM</strong></td><td><span class="badge $($dr.DKIMStatus)">$($dr.DKIMStatus.ToUpper())</span></td><td style="font-size:11px;">$($dr.DKIMAdvisory)<br/><code style="font-size:10px; word-break:break-all;">$($dr.DKIMRecord)</code></td></tr>
        <tr><td><strong>DMARC</strong></td><td><span class="badge $($dr.DMARCStatus)">$($dr.DMARCStatus.ToUpper())</span></td><td style="font-size:11px;">$($dr.DMARCAdvisory)<br/><code style="font-size:10px; word-break:break-all;">$($dr.DMARCRecord)</code></td></tr>
        <tr><td><strong>MTA-STS</strong></td><td><span class="badge $($dr.MTAStatus)">$($dr.MTAStatus.ToUpper())</span></td><td style="font-size:11px;">$($dr.MTAAdvisory)<br/><code style="font-size:10px; word-break:break-all;">$($dr.MTARecord)</code></td></tr>
    </table>
"@
}

$htmlBody += '<p style="font-size:11px; margin-top:10px;">'
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc7208" target="_blank">&#128279; SPF RFC 7208</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://dkim.org/" target="_blank">&#128279; DKIM</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc7489.html" target="_blank">&#128279; DMARC RFC 7489</a> &nbsp;|&nbsp; '
$htmlBody += '<a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc8461" target="_blank">&#128279; MTA-STS RFC 8461</a>'
$htmlBody += '</p>'
$htmlBody += "</div>"

# ─── Reference ───
$htmlBody += @"
<div class="section">
    <h2>Reference</h2>
    <p>This report validates the configurations defined in the document:</p>
    <p><a class="ref-link" style="font-size:14px;" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/L%C3%ADnea%20base%20para%20mejorar%20la%20postura%20de%20seguridad%20en%20Exchange%20online.md" target="_blank">&#128279; Baseline to improve the security posture in Exchange Online</a></p>
</div>
"@

# Footer
$htmlFooter = '<footer>chiringuito365.com&reg; | Internal Tools 2026</footer>'

$htmlReport = ConvertTo-Html -Head $htmlHead -Body ($htmlBody + $htmlFooter) -Title "Security Baseline Validation - Exchange Online"
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($htmlPath, ($htmlReport -join "`r`n"), $utf8Bom)

# ─────────────────────────────────────────────
# Final console summary
# ─────────────────────────────────────────────
Write-Host "HTML report generated: $htmlPath" -ForegroundColor Green

# Open the HTML report
Invoke-Item $htmlPath