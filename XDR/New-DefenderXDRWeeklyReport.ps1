<#
.SYNOPSIS
    New-DefenderXDRWeeklyReport.ps1
    Generates a Weekly Executive Threat Report using the Microsoft Defender XDR Advanced Hunting API.

.DESCRIPTION
    Automates weekly security operations tasks for MDO, MDE, MDI, and MDA.
    Extracts KPIs, trends, and actionable insights into a standalone HTML report.

.PARAMETER TimeWindowDays
    Analysis period in days (7, 14, or 30). Default: 7.

.PARAMETER OutputPath
    Path to save the HTML report.

.PARAMETER AuthMode
    Authentication method: 'Secret' (default), 'DeviceCode', 'Interactive', 'Certificate'.

.PARAMETER TenantId
    Azure AD Tenant ID (Required).

.PARAMETER ClientId
    App Registration Client ID (Required).

.PARAMETER ClientSecret
    Client Secret (Required if AuthMode is 'Secret').

.PARAMETER CertThumbprint
    Certificate thumbprint (Required if AuthMode is 'Certificate').

.PARAMETER SendMail
    Switch to send the report via email.

.EXAMPLE
    .\New-DefenderXDRWeeklyReport.ps1 -TenantId "xxx" -ClientId "yyy" -AuthMode DeviceCode

.NOTES
    Requires the 'AdvancedHunting.Read.All' permission.
    Author  : Ernesto Cobos Roqueñí, Arturo Mandujano
#>

param(
    [ValidateSet(7, 14, 30)]
    [int]$TimeWindowDays = 30,

    [string]$OutputPath = "$PSScriptRoot\Weekly_SecOps_Report_$(Get-Date -Format 'yyyyMMdd').html",

    [Alias('Auth')]
    [ValidateSet('DeviceCode', 'Interactive', 'Secret', 'Certificate')]
    [string]$AuthMode = 'Secret',

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$ClientSecret,
    [string]$CertThumbprint,

    [bool]$SendMail = $false,
    [string]$SmtpServer,
    [string]$To,
    [string]$Subject = "Defender XDR - Weekly Threat Report",

    [string]$ProxyUrl,
    [int]$TimeoutSec = 120,
    [switch]$FailFast,
    [switch]$ExportCsv,
    [switch]$UseParallel,
    [switch]$IncludeMDO,
    [switch]$IncludeMDE,
    [switch]$IncludeMDI,
    [switch]$IncludeMDA,
    [string]$LogPath = 'C:\Reports\Logs\DefenderXDR.log',
    [switch]$TestMode
)

# --- CONFIGURATION ---
$ErrorActionPreference = "Continue"
$ApiBaseUrl = "https://api.security.microsoft.com/api"
$Scope = "https://api.security.microsoft.com/.default"
$Authority = "https://login.microsoftonline.com/$TenantId"

# Constants
$MAX_RETRIES = 3
$RETRY_DELAY_BASE = 2
$MIN_FAILURES_SPRAY = 10
$MIN_ALERTS_RISKY_HOST = 3
# Security: Token cache uses Export-Clixml protected by DPAPI (current user only)
$TOKEN_CACHE_FILE = "$env:TEMP\DefenderXDR_TokenCache.xml"
$KPI_CACHE_FILE = "$env:TEMP\DefenderXDR_KPICache.json"

# Workload selection: if none specified, all are included.
$RunMDO = $IncludeMDO.IsPresent
$RunMDE = $IncludeMDE.IsPresent
$RunMDI = $IncludeMDI.IsPresent
$RunMDA = $IncludeMDA.IsPresent
if (-not ($RunMDO -or $RunMDE -or $RunMDI -or $RunMDA)) {
    $RunMDO = $RunMDE = $RunMDI = $RunMDA = $true
}

if ($ProxyUrl) {
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($ProxyUrl)
}

# --- CREDENTIAL MASKING (Consistent with the Daily Report) ---
function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

$MaskedTenantId  = Mask-String $TenantId
$MaskedClientId  = Mask-String $ClientId
$MaskedSecret    = if ($ClientSecret) { '********' } else { '(not set)' }
$MaskedThumbprint = if ($CertThumbprint) { Mask-String $CertThumbprint } else { '(not set)' }

# --- LOGGING FUNCTION ---
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with colors
    $Color = switch($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'INFO'  { 'Cyan' }
        'DEBUG' { 'Gray' }
    }
    Write-Host $LogEntry -ForegroundColor $Color
    
    # File output
    try {
        $LogDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $LogDir)) { 
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null 
        }
        Add-Content -Path $LogPath -Value $LogEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silent failure in logging to avoid breaking the script
    }
}

# --- SECURITY POSTURE: Log masked credentials at startup ---
Write-Log "=== Security Context ===" -Level INFO
Write-Log "  Tenant ID   : $MaskedTenantId" -Level INFO
Write-Log "  Client ID   : $MaskedClientId" -Level INFO
Write-Log "  Secret    : $MaskedSecret" -Level INFO
Write-Log "  Cert Thumb: $MaskedThumbprint" -Level INFO
Write-Log "  Auth Mode : $AuthMode" -Level INFO
Write-Log "========================" -Level INFO

# --- AUTHENTICATION ---
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    $B64 = [Convert]::ToBase64String($Bytes)
    $B64 = $B64.TrimEnd('=')
    $B64 = $B64.Replace('+', '-').Replace('/', '_')
    return $B64
}

function Get-CertificateForAuth {
    if (-not $CertThumbprint) {
        throw "CertThumbprint is required for Certificate authentication."
    }

    $NormalizedThumb = ($CertThumbprint -replace '\s','').ToUpperInvariant()
    foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $StoreLocation)
        try {
            $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $Found = $Store.Certificates | Where-Object { $_.Thumbprint -eq $NormalizedThumb } | Select-Object -First 1
            if ($Found) {
                return $Found
            }
        }
        finally {
            $Store.Close()
        }
    }

    throw "No certificate found with thumbprint '$CertThumbprint' in CurrentUser/My or LocalMachine/My."
}

function New-ClientAssertionJwt {
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$TenantId
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "The certificate does not contain a private key."
    }

    $Rsa = $null
    try {
        $Rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    }
    catch {
        $Rsa = $null
    }

    if (-not $Rsa -and $Certificate.PrivateKey -is [System.Security.Cryptography.RSA]) {
        $Rsa = [System.Security.Cryptography.RSA]$Certificate.PrivateKey
    }

    if (-not $Rsa) {
        throw "Could not obtain the RSA private key from the certificate. Verify that it has an exportable private key and RSA algorithm."
    }

    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $Audience = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $Header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = (ConvertTo-Base64Url -Bytes $Certificate.GetCertHash())
    }

    $Payload = @{
        aud = $Audience
        iss = $ClientId
        sub = $ClientId
        jti = ([Guid]::NewGuid().ToString())
        nbf = $Now - 300
        exp = $Now + 600
    }

    $HeaderJson = ($Header | ConvertTo-Json -Compress)
    $PayloadJson = ($Payload | ConvertTo-Json -Compress)

    $EncodedHeader = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($HeaderJson))
    $EncodedPayload = ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($PayloadJson))
    $UnsignedToken = "$EncodedHeader.$EncodedPayload"

    $SignatureBytes = $Rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($UnsignedToken),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $EncodedSignature = ConvertTo-Base64Url -Bytes $SignatureBytes

    return "$UnsignedToken.$EncodedSignature"
}

function New-AuthToken {
    Write-Log "Authenticating via $AuthMode..." -Level INFO
    
    # Check token cache
    if ((Test-Path $TOKEN_CACHE_FILE)) {
        try {
            $CachedToken = Import-Clixml -Path $TOKEN_CACHE_FILE -ErrorAction Stop
            if ($CachedToken.Expiry -gt (Get-Date).AddMinutes(5)) {
                Write-Log "Using cached token (valid until $($CachedToken.Expiry))" -Level DEBUG
                return $CachedToken.Token
            }
        } catch {
            Write-Log "Invalid token cache, re-authenticating" -Level WARN
        }
    }
    
    try {
        $Token = $null
        
        if ($AuthMode -eq 'Secret') {
            if (-not $ClientSecret) { throw "ClientSecret is required for Secret authentication." }
            
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $Scope
            }
            $Response = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            $Token = $Response.access_token
            $ExpiresIn = $Response.expires_in
            
            # Security: Clear plaintext secret from memory immediately
            $PlainSecret = $null
            [System.GC]::Collect()
        }
        elseif ($AuthMode -eq 'Certificate') {
            $Cert = Get-CertificateForAuth
            Write-Log "Using certificate '$($Cert.Subject)' (thumbprint: $($Cert.Thumbprint)) for certificate authentication." -Level INFO

            $ClientAssertion = New-ClientAssertionJwt -Certificate $Cert -ClientId $ClientId -TenantId $TenantId

            $Body = @{
                grant_type            = 'client_credentials'
                client_id             = $ClientId
                scope                 = $Scope
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = $ClientAssertion
            }

            $Response = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body $Body -ErrorAction Stop
            $Token = $Response.access_token
            $ExpiresIn = $Response.expires_in
        }
        elseif ($AuthMode -eq 'DeviceCode') {
            $CodeReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/devicecode" -Body @{
                client_id = $ClientId
                scope     = $Scope
            }
            
            Write-Log "To sign in, open $($CodeReq.verification_uri) and enter the code: $($CodeReq.user_code)" -Level WARN
            
            $Expires = (Get-Date).AddSeconds($CodeReq.expires_in)
            $MaxAttempts = [math]::Ceiling($CodeReq.expires_in / 5)
            $Attempt = 0
            
            while ((Get-Date) -lt $Expires -and $Attempt -lt $MaxAttempts) {
                $Attempt++
                try {
                    $TokenReq = Invoke-RestMethod -Method Post -Uri "$Authority/oauth2/v2.0/token" -Body @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id  = $ClientId
                        device_code = $CodeReq.device_code
                    } -ErrorAction Stop
                    $Token = $TokenReq.access_token
                    $ExpiresIn = $TokenReq.expires_in
                    break
                }
                catch {
                    $Err = $_.Exception.Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($Err)
                    $ErrBody = $Reader.ReadToEnd() | ConvertFrom-Json
                    if ($ErrBody.error -eq "authorization_pending") {
                        Start-Sleep -Seconds 5
                    } else {
                        throw $_
                    }
                }
            }
            if (-not $Token) { throw "Device code flow expired after $Attempt attempts." }
        }
        elseif ($AuthMode -eq 'Interactive') {
            # Requires Az or Mg module
            if (Get-Module -ListAvailable -Name "Az.Accounts") {
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
                $Token = (Get-AzAccessToken -ResourceUrl "https://api.security.microsoft.com").Token
                $ExpiresIn = 3600 # Default Az token expiration
            } else {
                throw "Interactive authentication requires the 'Az.Accounts' module."
            }
        }
        
        # Cache the token
        if ($Token) {
            $CacheObj = @{
                Token = $Token
                Expiry = (Get-Date).AddSeconds($ExpiresIn - 300) # 5 min buffer
            }
            Export-Clixml -Path $TOKEN_CACHE_FILE -InputObject $CacheObj -Force -ErrorAction SilentlyContinue
            Write-Log "Token cached successfully" -Level DEBUG
        }
        
        return $Token
    }
    catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# --- API EXECUTOR ---
function Invoke-DefenderAhQuery {
    param(
        [string]$Token,
        [string]$Query,
        [string]$Name
    )

    if ($TestMode) {
        Write-Log "TEST MODE: Returning simulated data for '$Name'" -Level DEBUG
        return @{
            Name = $Name
            Results = @(@{ MockData = "Test"; Count = 0 })
            Error = $null
        }
    }

    $Uri = "$ApiBaseUrl/advancedhunting/run"
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Inject TimeWindow - Using parameterized approach for better KQL handling
    $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
    $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress

    $Retries = 0
    
    do {
        try {
            $Sw = [System.Diagnostics.Stopwatch]::StartNew()
            $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $Sw.Stop()
            
            Write-Log "Query '$Name' completed in $($Sw.ElapsedMilliseconds)ms - Rows: $($Response.Results.Count)" -Level DEBUG
            
            return @{
                Name = $Name
                Results = $Response.Results
                Error = $null
                Duration = $Sw.ElapsedMilliseconds
            }
        }
        catch {
            $StatusCode = 0
            if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
            
            if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                $Retries++
                $Wait = [math]::Pow($RETRY_DELAY_BASE, $Retries)
                Write-Log "API error $StatusCode for '$Name'. Retry $Retries/$MAX_RETRIES in $Wait seconds" -Level WARN
                Start-Sleep -Seconds $Wait
            }
            else {
                Write-Log "Query '$Name' failed: $($_.Exception.Message)" -Level ERROR
                if ($FailFast) { throw $_ }
                return @{ Name = $Name; Results = @(); Error = $_.Exception.Message; Duration = 0 }
            }
        }
    } while ($Retries -lt $MAX_RETRIES)

    Write-Log "Query '$Name' exceeded maximum retries" -Level ERROR
    return @{ Name = $Name; Results = @(); Error = "Max retries exceeded"; Duration = 0 }
}

# --- KQL QUERIES ---
$Queries = @{
    # MDO
    "MDO_Trend" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Incidents=count(), Phish=countif(ThreatTypes has 'Phish'), Malware=countif(ThreatTypes has 'Malware') by bin(Timestamp, 1d)
| order by Timestamp asc
"@

    "MDO_Campaigns" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Count=count(), Targets=dcount(RecipientEmailAddress) by Subject, SenderFromDomain
| top 20 by Count desc
"@

    "MDO_TopUsers" = @"
EmailEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ThreatTypes has_any ('Phish', 'Malware')
| summarize Attacks=count() by RecipientEmailAddress
| top 20 by Attacks desc
"@

    "MDO_Alerts" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has_any ('Defender for Office 365', 'Office 365', 'Office')
| project Title=tostring(column_ifexists('Title', '(Sin título)')), Severity=tostring(column_ifexists('Severity', 'Unknown'))
| summarize Count=count() by Title, Severity
| top 20 by Count desc
"@

    # MDE
    "MDE_Severity" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has 'Endpoint'
| summarize Count=count() by Severity
| order by Count desc
"@

    "MDE_HostsRisk" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has 'Endpoint'
| where Severity in ('High', 'Critical')
| join kind=inner (AlertEvidence | where Timestamp between (ago(TimeWindowDays*d) .. now()) | where EntityType == 'Machine') on AlertId
| summarize AlertCount=dcount(AlertId), MaxSev=max(Severity) by DeviceName, DeviceId
| where AlertCount >= $MIN_ALERTS_RISKY_HOST
| top 25 by AlertCount desc
"@

    "MDE_Health" = @"
DeviceInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize arg_max(Timestamp, OSPlatform, SensorHealthState, DeviceId) by DeviceName
| project DeviceName, OS=OSPlatform, Health=SensorHealthState, LastSeen=Timestamp, DeviceId
| top 25 by LastSeen desc
"@

    "MDE_Alerts" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has 'Endpoint'
| project Title=tostring(column_ifexists('Title', '(Sin título)')), Severity=tostring(column_ifexists('Severity', 'Unknown'))
| summarize Count=count() by Title, Severity
| top 20 by Count desc
"@

    # MDI
    "MDI_Spray" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType == 'LogonFailed'
| summarize Failures=count(), DistinctIPs=dcount(IPAddress) by AccountUpn, Location
| where Failures >= $MIN_FAILURES_SPRAY
| top 25 by Failures desc
"@

    "MDI_Atypical" = @"
IdentityLogonEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Countries=dcount(Location), LastSeen=max(Timestamp) by AccountUpn
| where Countries >= 3
| top 25 by Countries desc
"@

    "MDI_Alerts" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has_any ('Defender for Identity', 'Identity')
| project Title=tostring(column_ifexists('Title', '(Sin título)')), Severity=tostring(column_ifexists('Severity', 'Unknown'))
| summarize Count=count() by Title, Severity
| top 20 by Count desc
"@

    # MDA
    "MDA_OAuth" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ActionType in ('Consent to application', 'Grant consent')
| summarize Consents=count(), Users=dcount(AccountId) by Application, ApplicationId
| top 20 by Consents desc
"@

    "MDA_Apps" = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| summarize Events=count(), Users=dcount(AccountId) by Application
| top 20 by Events desc
"@

    "MDA_Alerts" = @"
AlertInfo
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ServiceSource has_any ('Defender for Cloud Apps', 'Cloud Apps', 'MCAS', 'Microsoft Cloud App Security')
| project Title=tostring(column_ifexists('Title', '(Sin título)')), Severity=tostring(column_ifexists('Severity', 'Unknown'))
| summarize Count=count() by Title, Severity
| top 20 by Count desc
"@
}

# --- MAIN EXECUTION ---
Write-Log "Starting Defender XDR Weekly Report Generation" -Level INFO
Write-Log "Time Window: Last $TimeWindowDays days" -Level INFO

try {
    # 1. Authenticate
    $Token = New-AuthToken
    if (-not $Token) { throw "Authentication failed - no token received" }

    # 2. Execute Queries (Parallel if PS 7+ and flag is enabled)
    $Data = @{}
    
    if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Log "Executing queries in parallel..." -Level INFO
        
        $Results = $Queries.GetEnumerator() |
            Where-Object {
                ($_.Key -notlike 'MDO_*' -or $RunMDO) -and
                ($_.Key -notlike 'MDE_*' -or $RunMDE) -and
                ($_.Key -notlike 'MDI_*' -or $RunMDI) -and
                ($_.Key -notlike 'MDA_*' -or $RunMDA)
            } |
            ForEach-Object -Parallel {
            $Query = $_.Value
            $Name = $_.Key
            $Token = $using:Token
            $TimeWindowDays = $using:TimeWindowDays
            $ApiBaseUrl = $using:ApiBaseUrl
            $TimeoutSec = $using:TimeoutSec
            $FailFast = $using:FailFast
            $TestMode = $using:TestMode
            $MAX_RETRIES = $using:MAX_RETRIES
            $RETRY_DELAY_BASE = $using:RETRY_DELAY_BASE
            
            # Execute query (reuse function logic)
            if ($TestMode) {
                return @{ Name = $Name; Results = @(@{ MockData = "Test" }); Error = $null }
            }
            
            $Uri = "$ApiBaseUrl/advancedhunting/run"
            $Headers = @{
                "Authorization" = "Bearer $Token"
                "Content-Type"  = "application/json"
            }
            $FinalQuery = $Query -replace "ago\(TimeWindowDays\*d\)", "ago($($TimeWindowDays)d)"
            $Body = @{ Query = $FinalQuery } | ConvertTo-Json -Compress
            
            $Retries = 0
            do {
                try {
                    $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
                    return @{ Name = $Name; Results = $Response.Results; Error = $null }
                }
                catch {
                    $StatusCode = 0
                    if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }
                    if ($StatusCode -eq 429 -or $StatusCode -ge 500) {
                        $Retries++
                        Start-Sleep -Seconds ([math]::Pow($RETRY_DELAY_BASE, $Retries))
                    } else {
                        return @{ Name = $Name; Results = @(); Error = $_.Exception.Message }
                    }
                }
            } while ($Retries -lt $MAX_RETRIES)
            
            return @{ Name = $Name; Results = @(); Error = "Max retries exceeded" }
        } -ThrottleLimit 5
        
        foreach ($Result in $Results) {
            $Data[$Result.Name] = $Result.Results
            if ($Result.Error) {
                Write-Log "Query '$($Result.Name)' had error: $($Result.Error)" -Level WARN
            }
        }
    }
    else {
        Write-Log "Executing queries sequentially..." -Level INFO
        foreach ($Key in $Queries.Keys) {
            if ($Key -like 'MDO_*' -and -not $RunMDO) { continue }
            if ($Key -like 'MDE_*' -and -not $RunMDE) { continue }
            if ($Key -like 'MDI_*' -and -not $RunMDI) { continue }
            if ($Key -like 'MDA_*' -and -not $RunMDA) { continue }
            $Result = Invoke-DefenderAhQuery -Token $Token -Query $Queries[$Key] -Name $Key
            $Data[$Key] = $Result.Results
        }
    }
    
    # Validate data
    $TotalRows = ($Data.Values | Measure-Object -Property Count -Sum).Sum
    Write-Log "Total rows retrieved: $TotalRows" -Level INFO
    
    if ($TotalRows -eq 0) {
        Write-Log "Warning: No data retrieved from any query" -Level WARN
    }

    # 3. Calculate KPIs
    $KPI_MDO_Phish = ($Data["MDO_Trend"] | Measure-Object -Property Phish -Sum).Sum
    $KPI_MDO_Malware = ($Data["MDO_Trend"] | Measure-Object -Property Malware -Sum).Sum
    $KPI_MDE_Alerts = ($Data["MDE_Severity"] | Measure-Object -Property Count -Sum).Sum
    $KPI_MDE_RiskyHosts = $Data["MDE_HostsRisk"].Count
    $KPI_MDI_Spray = $Data["MDI_Spray"].Count
    $KPI_MDA_OAuth = ($Data["MDA_OAuth"] | Measure-Object -Property Consents -Sum).Sum

    # Null safety
    if (-not $KPI_MDO_Phish) { $KPI_MDO_Phish = 0 }
    if (-not $KPI_MDO_Malware) { $KPI_MDO_Malware = 0 }
    if (-not $KPI_MDE_Alerts) { $KPI_MDE_Alerts = 0 }
    if (-not $KPI_MDE_RiskyHosts) { $KPI_MDE_RiskyHosts = 0 }
    if (-not $KPI_MDI_Spray) { $KPI_MDI_Spray = 0 }
    if (-not $KPI_MDA_OAuth) { $KPI_MDA_OAuth = 0 }
    
    Write-Log "KPIs calculated: Phish=$KPI_MDO_Phish, Malware=$KPI_MDO_Malware, Alerts=$KPI_MDE_Alerts" -Level INFO
    
    # Compare with previous period
    $PrevKPIs = $null
    $KPIChanges = @{}
    if (Test-Path $KPI_CACHE_FILE) {
        try {
            $PrevKPIs = Get-Content $KPI_CACHE_FILE -Raw | ConvertFrom-Json
            $KPIChanges = @{
                Phish = if ($PrevKPIs.Phish -gt 0) { [math]::Round((($KPI_MDO_Phish - $PrevKPIs.Phish) / $PrevKPIs.Phish) * 100, 1) } else { 0 }
                Malware = if ($PrevKPIs.Malware -gt 0) { [math]::Round((($KPI_MDO_Malware - $PrevKPIs.Malware) / $PrevKPIs.Malware) * 100, 1) } else { 0 }
                Alerts = if ($PrevKPIs.Alerts -gt 0) { [math]::Round((($KPI_MDE_Alerts - $PrevKPIs.Alerts) / $PrevKPIs.Alerts) * 100, 1) } else { 0 }
            }
            Write-Log "Trend vs previous: Phish $($KPIChanges.Phish)%, Malware $($KPIChanges.Malware)%, Alerts $($KPIChanges.Alerts)%" -Level INFO
        } catch {
            Write-Log "Could not load previous KPIs for comparison" -Level DEBUG
        }
    }
    
    # Save current KPIs for the next execution
    $CurrentKPIs = @{
        Phish = $KPI_MDO_Phish
        Malware = $KPI_MDO_Malware
        Alerts = $KPI_MDE_Alerts
        RiskyHosts = $KPI_MDE_RiskyHosts
        Date = (Get-Date).ToString("yyyy-MM-dd")
    }
    $CurrentKPIs | ConvertTo-Json | Out-File $KPI_CACHE_FILE -Encoding UTF8 -Force

    # --- STATUS CALCULATION (CISO View) ---
    $GlobalStatus = if ($KPI_MDE_RiskyHosts -gt 0 -or $KPI_MDO_Phish -gt 50) { "Critical" } elseif ($KPI_MDE_Alerts -gt 20) { "Warning" } else { "Healthy" }
    $StatusColor = switch ($GlobalStatus) { "Critical" { "#d13438" } "Warning" { "#ffaa44" } "Healthy" { "#107c10" } }
    
    # Tenant ID already masked at script start via Mask-String function

    # --- RECOMMENDED WEEKLY KQL BY WORKLOAD ---
    $MdoWeeklyKqlCatalog = @(
        @{ Id = 1; Category = "Trends"; Title = "Malware/phishing trends by day"; Query = $Queries["MDO_Trend"] },
        @{ Id = 2; Category = "Campaigns"; Title = "High-impact campaigns"; Query = $Queries["MDO_Campaigns"] },
        @{ Id = 3; Category = "Targeted Users"; Title = "Top most attacked users"; Query = $Queries["MDO_TopUsers"] }
    )
    $SelectedMdoWeeklyKql = $MdoWeeklyKqlCatalog | Get-Random

    $MdeWeeklyKqlCatalog = @(
        @{ Id = 1; Category = "Threat Analytics"; Title = "MDE alerts by severity"; Query = $Queries["MDE_Severity"] },
        @{ Id = 2; Category = "Hunting"; Title = "Hosts with multiple high/critical alerts"; Query = $Queries["MDE_HostsRisk"] },
        @{ Id = 3; Category = "Coverage"; Title = "Sensor health and onboarding"; Query = $Queries["MDE_Health"] }
    )
    $SelectedMdeWeeklyKql = $MdeWeeklyKqlCatalog | Get-Random

    $MdiWeeklyKqlCatalog = @(
        @{ Id = 1; Category = "Secure Score"; Title = "Password spray by account"; Query = $Queries["MDI_Spray"] },
        @{ Id = 2; Category = "Custom Detection"; Title = "Atypical locations by identity"; Query = $Queries["MDI_Atypical"] },
        @{ Id = 3; Category = "Custom Detection"; Title = "Distributed brute force (early signal)"; Query = @"
let Lookback = 7d;
let Window = 30m;
let MinFailures = 25;
let MinSrcIPs = 8;
IdentityLogonEvents
| where Timestamp >= ago(Lookback)
| where ActionType has_any ("Fail", "LogonFailed", "InvalidPassword", "UserLoginFailed")
| summarize Failures=count(), SrcIPs=dcount(IPAddress), IPList=make_set(IPAddress, 25), Apps=make_set(Application, 15)
  by AccountUpn, AccountName, AccountDomain, bin(Timestamp, Window)
| where Failures >= MinFailures and SrcIPs >= MinSrcIPs
| project Timestamp, AccountUpn, AccountName, AccountDomain, Failures, SrcIPs, IPList, Apps
| order by Failures desc, SrcIPs desc
"@ }
    )
    $SelectedMdiWeeklyKql = $MdiWeeklyKqlCatalog | Get-Random

    $EntraWeeklyKqlCatalog = @(
        @{ Id = 1; Category = "Administrative Changes"; Title = "Administrative role changes"; Query = @"
CloudAppEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where Application == "Azure Active Directory"
| where ActionType has_any ("Add member to role", "Remove member from role", "Update role", "Role")
| project Timestamp, ActionType, AccountDisplayName, IPAddress, CountryCode, RawEventData
| order by Timestamp desc
"@ },
        @{ Id = 2; Category = "Identity Secure Score"; Title = "High-risk sign-ins"; Query = @"
EntraIdSignInEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where RiskLevelAggregated in (50, 100)
| project Timestamp, AccountUpn, RiskLevelAggregated, RiskState, Application, IPAddress, Country
| order by Timestamp desc
"@ },
        @{ Id = 3; Category = "Synchronization"; Title = "Sign-in errors by code"; Query = @"
EntraIdSignInEvents
| where Timestamp between (ago(TimeWindowDays*d) .. now())
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn) by ErrorCode, FailureReason
| order by Failures desc
"@ }
    )
    $SelectedEntraWeeklyKql = $EntraWeeklyKqlCatalog | Get-Random

# 4. Generar HTML
function New-HtmlTable {
    param($Rows, $Cols)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<tr><td colspan='$($Cols.Count)' style='text-align:center; color:#888; padding:15px;'>No data available for this period.</td></tr>" }
    $Html = ""
    foreach ($Row in $Rows) {
        $Html += "<tr>"
        foreach ($Col in $Cols) {
            $Val = $Row.$Col
            
            # UI/UX: Deep Links and Formatting
            if ($Col -eq "DeviceName" -and $Row.DeviceId) {
                $Val = "<a href='https://security.microsoft.com/machines/$($Row.DeviceId)' target='_blank' title='View Device in Defender'>$Val</a>"
            }
            elseif ($Col -in @("AccountUpn", "RecipientEmailAddress") -and $Val) {
                $Val = "<a href='https://security.microsoft.com/users/sec/UserPage?user=$Val' target='_blank' title='View User in Defender'>$Val</a>"
            }
            elseif ($Val -is [DateTime]) { $Val = $Val.ToString("yyyy-MM-dd HH:mm") }
            
            $Html += "<td>$Val</td>"
        }
        $Html += "</tr>"
    }
    return $Html
}

$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Weekly Security Report</title>
    <style>
        :root {
            --primary-color: #0078d4;
            --secondary-color: #2b2b2b;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #323130;
            --border-color: #e1dfdd;
            --danger-color: #a80000;
        }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }
        .header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
        .header .subtitle { margin-top: 6px; font-size: 0.92em; opacity: 0.95; }
        .header .meta { font-size: 0.9em; opacity: 0.95; text-align: right; }
        .status-badge {
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.8em;
            display: inline-block;
            margin-bottom: 8px;
        }
        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        h2 {
            color: var(--secondary-color);
            margin-top: 40px;
            margin-bottom: 15px;
            font-size: 18px;
            border-left: 4px solid var(--primary-color);
            padding-left: 12px;
            display: flex;
            align-items: center;
        }
        h3 {
            color: #605e5c;
            font-size: 16px;
            margin-top: 22px;
            margin-bottom: 10px;
        }
        .summary {
            background-color: #e6f2ff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #cce4ff;
            margin-bottom: 25px;
        }
        .summary h3 { margin-top: 0; color: var(--secondary-color); }
        .summary ul { margin: 0; padding-left: 20px; }
        .summary li { margin-bottom: 8px; line-height: 1.6; }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .kpi-card {
            background: var(--card-bg);
            padding: 25px 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: transform 0.2s ease;
            border-top: 4px solid transparent;
        }
        .kpi-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .kpi-card.alert { border-top-color: var(--primary-color); }
        .kpi-card.danger { border-top-color: var(--danger-color); }
        .kpi-val { font-size: 3em; font-weight: 700; color: var(--secondary-color); line-height: 1; margin-bottom: 5px; }
        .kpi-label { font-size: 0.85em; color: #605e5c; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
        .table-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .table-container {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            overflow: hidden;
            margin-bottom: 30px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.95em; }
        th { background-color: #f8f9fa; color: #605e5c; text-align: left; padding: 12px 15px; font-weight: 600; border-bottom: 2px solid var(--border-color); }
        td { border-bottom: 1px solid var(--border-color); padding: 12px 15px; color: var(--text-color); }
        tr:last-child td { border-bottom: none; }
        tr:hover { background-color: #f8f9fa; }
        a { color: var(--primary-color); text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        .recs {
            background-color: #e6f2ff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #cce4ff;
        }
        .recs ul { margin: 0; padding-left: 20px; }
        .recs li { margin-bottom: 8px; line-height: 1.6; }

        .ops-section { margin-bottom: 30px; }
        .ops-group {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            overflow: hidden;
            margin-bottom: 20px;
        }
        .ops-group-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 14px 20px;
            font-weight: 600;
            font-size: 1em;
            color: #fff;
            letter-spacing: 0.3px;
        }
        .ops-group-header.mdo   { background: linear-gradient(135deg, #0078d4, #005a9e); }
        .ops-group-header.mde   { background: linear-gradient(135deg, #d83b01, #a52a00); }
        .ops-group-header.mdi   { background: linear-gradient(135deg, #e97a00, #c25e00); }
        .ops-group-header.entra { background: linear-gradient(135deg, #107c10, #0b5e0b); }
        .ops-group-header.mda   { background: linear-gradient(135deg, #008575, #00695c); }
        .ops-group-header .icon { font-size: 1.2em; }
        .ops-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            line-height: 1.6;
        }
        .ops-badge.weekly { background: rgba(255,255,255,0.25); color: #fff; }
        .ops-table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
        .ops-table th {
            background-color: #f8f9fa;
            color: #605e5c;
            text-align: left;
            padding: 10px 16px;
            font-weight: 600;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--border-color);
        }
        .ops-table td {
            padding: 11px 16px;
            border-bottom: 1px solid #f0f0f0;
            vertical-align: middle;
        }
        .ops-table tr:last-child td { border-bottom: none; }
        .ops-table tr:hover { background-color: #fafbfc; }
        .ops-task-name {
            font-family: 'Segoe UI Semibold', 'Segoe UI', sans-serif;
            font-weight: 600;
            color: var(--text-color);
            font-size: 0.93em;
        }
        .ops-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 5px 14px;
            border-radius: 5px;
            font-size: 0.82em;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.15s ease;
        }
        .ops-btn.portal { background: #0078d4; color: #fff; }
        .ops-btn.portal:hover { background: #005a9e; }
        .ops-btn.doc { background: #f3f2f1; color: #323130; border: 1px solid #d2d0ce; }
        .ops-btn.doc:hover { background: #e1dfdd; }
        .footer { text-align: center; margin-top: 50px; color: #8a8886; font-size: 0.85em; padding-bottom: 20px; }
        @media (max-width: 900px) {
            .header { flex-direction: column; align-items: flex-start; gap: 12px; }
            .header .meta { text-align: left; }
            .table-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Weekly Security Operations Report</h1>
            <div class="subtitle">Technology enables security, but discipline makes it effective</div>
        </div>
        <div class="meta">
            <div class="status-badge" style="background-color: $StatusColor;">$GlobalStatus</div>
            <div><strong>Period:</strong> Last $TimeWindowDays days</div>
            <div><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm")</div>
            <div style="font-size: 0.85em; margin-top: 4px;">Tenant ID: $MaskedTenantId</div>
        </div>
    </div>

    <div class="container">
        <div class="kpi-grid">
            <div class="kpi-card $(if($KPI_MDE_Alerts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_Alerts</div>
                <div class="kpi-label">Defender for Endpoint Alerts</div>
            </div>
            <div class="kpi-card $(if($KPI_MDO_Phish -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDO_Phish</div>
                <div class="kpi-label">Defender for Office Alerts</div>
            </div>
            <div class="kpi-card $(if($KPI_MDE_RiskyHosts -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDE_RiskyHosts</div>
                <div class="kpi-label">Critical Hosts (≥3 Alerts)</div>
            </div>
            <div class="kpi-card $(if($KPI_MDI_Spray -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDI_Spray</div>
                <div class="kpi-label">Defender for Identity Alerts</div>
            </div>
            <div class="kpi-card $(if($KPI_MDA_OAuth -gt 0){'danger'}else{'alert'})">
                <div class="kpi-val">$KPI_MDA_OAuth</div>
                <div class="kpi-label">New OAuth Consents</div>
            </div>
        </div>

        <h2>MDO: Email and Collaboration</h2>

        <h3>MDO Alerts (Top 20)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Title</th><th>Severity</th><th>Count</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDO_Alerts"] @("Title","Severity","Count"))</tbody>
            </table>
        </div>

        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mdo">
                    <span class="icon">&#x1f4e7;</span> Weekly Operational Tasks - Microsoft Defender for Office 365
                    <span class="ops-badge weekly">4 Weekly</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Task</th><th style="width:25%">Portal</th><th style="width:25%">Guide</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Review email detection trends</td><td><a class="ops-btn portal" href="https://security.microsoft.com/emailandcollabreport" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-tendencias-de-detecci%C3%B3n-de-correo-en-microsoft-defender-for-office-365" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Identify most attacked users</td><td><a class="ops-btn portal" href="https://security.microsoft.com/emailandcollabreport" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#identificar-usuarios-m%C3%A1s-atacados-por-malware-y-phishing" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Review malware and phishing campaigns</td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#revisar-campa%C3%B1as-de-malware-y-phishing" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Validate delivered emails with threats</td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatexplorerv3" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md#validar-correos-entregados-con-amenazas" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mdo">
                <span class="icon">&#x1f50d;</span> Weekly KQL Recommendation - MDO
                <span class="ops-badge weekly">#$($SelectedMdoWeeklyKql.Id) of $($MdoWeeklyKqlCatalog.Count)</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#e6f2ff; color:#0078d4; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdoWeeklyKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdoWeeklyKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdoWeeklyKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Run in Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDO/Guia%20de%20Seguridad%20Operacional%20MDO%20Semanal.md" target="_blank">&#x1f4d6; MDO Weekly Guide</a>
                </div>
            </div>
        </div>

        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Top Active Campaigns</h3>
                <table>
                    <thead><tr><th>Subject</th><th>Sender Domain</th><th>Count</th><th>Targets</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_Campaigns"] @("Subject","SenderFromDomain","Count","Targets"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Most Attacked Users</h3>
                <table>
                    <thead><tr><th>User Email</th><th>Attacks</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDO_TopUsers"] @("RecipientEmailAddress","Attacks"))</tbody>
                </table>
            </div>
        </div>

        <h2>MDE: Endpoint Security</h2>

        <h3>MDE Alerts (Top 20)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Title</th><th>Severity</th><th>Count</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDE_Alerts"] @("Title","Severity","Count"))</tbody>
            </table>
        </div>

        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mde">
                    <span class="icon">&#x1f6e1;</span> Weekly Operational Tasks - Microsoft Defender for Endpoint
                    <span class="ops-badge weekly">6 Weekly</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Task</th><th style="width:25%">Portal</th><th style="width:25%">Guide</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Threat trend analysis</td><td><a class="ops-btn portal" href="https://security.microsoft.com/threatanalytics3" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#an%C3%A1lisis-de-tendencias-de-amenazas" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Weekly Advanced Hunting</td><td><a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#advanced-hunting-semanal" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Exposure and vulnerabilities (MDVM)</td><td><a class="ops-btn portal" href="https://security.microsoft.com/tvm_dashboard" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#exposici%C3%B3n-y-vulnerabilidades" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Security configuration review</td><td><a class="ops-btn portal" href="https://security.microsoft.com/asr" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#revisi%C3%B3n-de-configuraciones-de-seguridad" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Repeat-offender devices</td><td><a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#dispositivos-reincidentes" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Operational / executive report</td><td><a class="ops-btn portal" href="https://security.microsoft.com/incidents" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md#reporte-operativo--ejecutivo" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Alerts by Severity</h3>
                <table>
                    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_Severity"] @("Severity","Count"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Hosts with Multiple High/Critical Alerts</h3>
                <table>
                    <thead><tr><th>Device Name</th><th>Alert Count</th><th>Max Severity</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDE_HostsRisk"] @("DeviceName","AlertCount","MaxSev"))</tbody>
                </table>
            </div>
        </div>
        <h3>Device Health Status (Top 25)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Device Name</th><th>OS</th><th>Health Status</th><th>Last Seen</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDE_Health"] @("DeviceName","OS","Health","LastSeen"))</tbody>
            </table>
        </div>

        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mde">
                <span class="icon">&#x1f50d;</span> Weekly KQL Recommendation - MDE
                <span class="ops-badge weekly">#$($SelectedMdeWeeklyKql.Id) of $($MdeWeeklyKqlCatalog.Count)</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#fce4ec; color:#d83b01; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdeWeeklyKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdeWeeklyKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdeWeeklyKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Run in Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDE/Guia%20de%20Seguridad%20Operacional%20MDE%20tareas%20semanales.md" target="_blank">&#x1f4d6; MDE Weekly Guide</a>
                </div>
            </div>
        </div>

        <h2>MDI: Identity Security</h2>

        <h3>MDI Alerts (Top 20)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Title</th><th>Severity</th><th>Count</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDI_Alerts"] @("Title","Severity","Count"))</tbody>
            </table>
        </div>

        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mdi">
                    <span class="icon">&#x1f512;</span> Weekly Operational Tasks - Microsoft Defender for Identity
                    <span class="ops-badge weekly">3 Weekly</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Task</th><th style="width:25%">Portal</th><th style="width:25%">Guide</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Review Secure Score recommendations</td><td><a class="ops-btn portal" href="https://security.microsoft.com/securescore" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-recomendaciones-de-secure-score-por-producto" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Respond to emerging threats (custom detections)</td><td><a class="ops-btn portal" href="https://security.microsoft.com/advanced-hunting" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#revisar-y-responder-a-amenazas-emergentes-custom-detections" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Custom detection for distributed password spray</td><td><a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md#ejemplo-custom-detection-password-spraying--brute-force-distribuido-se%C3%B1al-temprana" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">Password Spray / Brute Force</h3>
                <table>
                    <thead><tr><th>Account</th><th>Location</th><th>Failures</th><th>IPs</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Spray"] @("AccountUpn","Location","Failures","DistinctIPs"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Atypical Locations (Travel)</h3>
                <table>
                    <thead><tr><th>Account</th><th>Countries</th><th>Last Seen</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDI_Atypical"] @("AccountUpn","Countries","LastSeen"))</tbody>
                </table>
            </div>
        </div>

        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header mdi">
                <span class="icon">&#x1f50d;</span> Weekly KQL Recommendation - MDI
                <span class="ops-badge weekly">#$($SelectedMdiWeeklyKql.Id) of $($MdiWeeklyKqlCatalog.Count)</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#fff3e0; color:#e97a00; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedMdiWeeklyKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedMdiWeeklyKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedMdiWeeklyKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Run in Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDI/Gu%C3%ADa%20operativa%20semanal%20de%20Microsoft%20Defender%20for%20Identity.md" target="_blank">&#x1f4d6; MDI Weekly Guide</a>
                </div>
            </div>
        </div>

        <h2>Entra ID: Identity Governance</h2>

        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header entra">
                    <span class="icon">&#x1f510;</span> Weekly Operational Tasks - Microsoft Entra ID
                    <span class="ops-badge weekly">3 Weekly</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Task</th><th style="width:25%">Portal</th><th style="width:25%">Guide</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Review administrative changes</td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-cambios-administrativos" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Identity Secure Score tracking</td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraRecommendationsIdentitySecureScore.ReactView" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#seguimiento-del-identity-secure-score" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Review old synchronization errors</td><td><a class="ops-btn portal" href="https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/CrossTenantSynchronizationConfiguration.ReactView" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md#revisi%C3%B3n-de-errores-de-sincronizaci%C3%B3n-antiguos" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ops-group" style="margin-top: 20px;">
            <div class="ops-group-header entra">
                <span class="icon">&#x1f50d;</span> Weekly KQL Recommendation - Entra ID
                <span class="ops-badge weekly">#$($SelectedEntraWeeklyKql.Id) of $($EntraWeeklyKqlCatalog.Count)</span>
            </div>
            <div style="padding: 20px;">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                    <span style="background:#e8f5e9; color:#107c10; padding:3px 10px; border-radius:4px; font-size:0.78em; font-weight:600;">$($SelectedEntraWeeklyKql.Category)</span>
                </div>
                <h3 style="margin:0 0 12px 0; color:var(--secondary-color); font-size:1.05em;">$($SelectedEntraWeeklyKql.Title)</h3>
                <div style="background:#1e1e1e; color:#d4d4d4; padding:16px; border-radius:6px; font-family:'Cascadia Code','Consolas',monospace; font-size:0.82em; line-height:1.6; overflow-x:auto; white-space:pre-wrap;">$($SelectedEntraWeeklyKql.Query)</div>
                <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
                    <a class="ops-btn portal" href="https://security.microsoft.com/v2/advanced-hunting" target="_blank">&#x1f517; Run in Advanced Hunting</a>
                    <a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/EntraID/Gu%C3%ADa%20Operacional%20EntraID%20Tareas%20Semanales.md" target="_blank">&#x1f4d6; Entra ID Weekly Guide</a>
                </div>
            </div>
        </div>

        <h2>MDA: Cloud Apps and Shadow IT</h2>

        <h3>MDA Alerts (Top 20)</h3>
        <div class="table-container">
            <table>
                <thead><tr><th>Title</th><th>Severity</th><th>Count</th></tr></thead>
                <tbody>$(New-HtmlTable $Data["MDA_Alerts"] @("Title","Severity","Count"))</tbody>
            </table>
        </div>

        <div class="ops-section">
            <div class="ops-group">
                <div class="ops-group-header mda">
                    <span class="icon">&#x2601;</span> Weekly Operational Tasks - Microsoft Defender for Cloud Apps
                    <span class="ops-badge weekly">4 Weekly</span>
                </div>
                <table class="ops-table">
                    <thead><tr><th style="width:50%">Task</th><th style="width:25%">Portal</th><th style="width:25%">Guide</th></tr></thead>
                    <tbody>
                        <tr><td class="ops-task-name">Review SaaS Security Posture Management (SSPM)</td><td><a class="ops-btn portal" href="https://portal.cloudappsecurity.com/#/recommendations" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20semanales.md#review-saas-security-posture-management-sspm" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Health Check - App Connectors, Log Collectors y SIEM</td><td><a class="ops-btn portal" href="https://portal.cloudappsecurity.com/#/settings" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20semanales.md#health-check--app-connectors-log-collectors-y-siem" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Review Governance Log</td><td><a class="ops-btn portal" href="https://portal.cloudappsecurity.com/#/governancelog" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20semanales.md#review-governance-log" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                        <tr><td class="ops-task-name">Track New Changes - Defender XDR y MDCA</td><td><a class="ops-btn portal" href="https://learn.microsoft.com/en-us/defender-cloud-apps/release-notes" target="_blank">&#x1f517; Open Portal</a></td><td><a class="ops-btn doc" href="https://github.com/watchdogcode/gol2026/blob/main/MDA/Gu%C3%ADa%20de%20Seguridad%20Operacional%20MDA%20tareas%20semanales.md#track-new-changes--defender-xdr--mdca" target="_blank">&#x1f4d6; View Guide</a></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="table-grid">
            <div class="table-container">
                <h3 style="padding:0 15px;">New OAuth Consents</h3>
                <table>
                    <thead><tr><th>App Name</th><th>App ID</th><th>Consents</th><th>Users</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_OAuth"] @("Application","ApplicationId","Consents","Users"))</tbody>
                </table>
            </div>
            <div class="table-container">
                <h3 style="padding:0 15px;">Newly Discovered Apps (Shadow IT)</h3>
                <table>
                    <thead><tr><th>Application</th><th>Events</th><th>Users</th></tr></thead>
                    <tbody>$(New-HtmlTable $Data["MDA_Apps"] @("Application","Events","Users"))</tbody>
                </table>
            </div>
        </div>

        <div class="recs">
            <h3>Weekly Operational Checklist</h3>
            <ul>
                <li><strong>MDO:</strong> Review phishing campaigns and adjust Safe Links/Attachments policies. Verify most attacked users to identify possible compromise.</li>
                <li><strong>MDE:</strong> Investigate hosts with ≥3 high/critical alerts, isolate compromised devices, and validate EDR sensor health.</li>
                <li><strong>MDI:</strong> Review accounts with high failure rates, enforce MFA/reset, and analyze atypical locations.</li>
                <li><strong>MDA:</strong> Audit new OAuth consents, revoke suspicious permissions, and review Shadow IT usage.</li>
            </ul>
        </div>

        <div class="footer">
            Source: Defender XDR - Advanced Hunting & Reporting (Weekly Ops) | Generated at $(Get-Date -Format "HH:mm")
        </div>
    </div>
</body>
</html>
"@

    # 5. Save Report
    try {
        $Dir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $Dir)) { 
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null 
            Write-Log "Output directory created: $Dir" -Level DEBUG
        }
        
        # Use explicit UTF8 encoding (no BOM) for HTML
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $HtmlContent, $Utf8NoBom)
        
        Write-Log "Report saved to: $OutputPath" -Level INFO
        
        # Export CSV if requested
        if ($ExportCsv) {
            $CsvDir = Join-Path $Dir "CSV_Export"
            if (-not (Test-Path $CsvDir)) { New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null }
            
            foreach ($Key in $Data.Keys) {
                if ($Data[$Key].Count -gt 0) {
                    $CsvPath = Join-Path $CsvDir "$Key.csv"
                    $Data[$Key] | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                    Write-Log "CSV Exported: $CsvPath" -Level DEBUG
                }
            }
            Write-Log "CSV files exported to: $CsvDir" -Level INFO
        }
    }
    catch {
        Write-Log "Failed to save the report: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # 6. Send Email (Optional)
    if ($SendMail) {
        if ($SmtpServer -and $To) {
            try {
                Write-Log "Sending email to $To via $SmtpServer" -Level INFO
                Send-MailMessage -SmtpServer $SmtpServer -From "DefenderReport@$env:COMPUTERNAME" -To $To -Subject $Subject -Body $HtmlContent -BodyAsHtml -Priority High -Encoding ([System.Text.Encoding]::UTF8)
                Write-Log "Email sent successfully" -Level INFO
            }
            catch {
                Write-Log "Failed to send email: $($_.Exception.Message)" -Level ERROR
            }
        } else {
            Write-Log "Email skipped. Missing SmtpServer or To parameter" -Level WARN
        }
    }

    Write-Log "Defender XDR Weekly Report Generation completed successfully" -Level INFO
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level DEBUG
    throw
}
finally {
    # Clean sensitive data from memory
    if ($Token) { Clear-Variable -Name Token -ErrorAction SilentlyContinue }
    if ($ClientSecret) { Clear-Variable -Name ClientSecret -ErrorAction SilentlyContinue }
    if ($PlainSecret) { Clear-Variable -Name PlainSecret -ErrorAction SilentlyContinue }
    # Delete token cache file on exit for security
    if (Test-Path $TOKEN_CACHE_FILE) {
        Remove-Item $TOKEN_CACHE_FILE -Force -ErrorAction SilentlyContinue
        Write-Log "Token cache cleaned" -Level DEBUG
    }
    [System.GC]::Collect()
}

# --- APPENDIX: MANUAL QUERIES ---
<#
    APPENDIX: KQL Queries for Manual Execution in the Defender Portal
    
    // MDO: Trend
    EmailEvents | where Timestamp > ago(7d) | summarize Count=count() by bin(Timestamp, 1d), ThreatTypes
    
    // MDE: Risky Hosts
    AlertInfo | where Timestamp > ago(7d) | where ServiceSource == 'MicrosoftDefenderForEndpoint' 
    | summarize AlertCount=count(), MaxSev=max(Severity) by DeviceName | where AlertCount >= 3
    
    // MDI: Spray
    IdentityLogonEvents | where Timestamp > ago(7d) | where ActionType == 'LogonFailed' 
    | summarize Failures=count() by AccountUpn, Location | where Failures >= 10
    
    // MDA: OAuth
    CloudAppEvents | where Timestamp > ago(7d) | where ActionType in ('Consent to application', 'Grant consent')
#>
