<#
.SYNOPSIS
    Setup-DefenderXDRReportServer.ps1
    Initial setup script for Defender XDR Daily & Weekly Reporting.

.DESCRIPTION
        Configures the complete environment to run:
            - New-DefenderXDRDailyReport.ps1  (daily report)
            - New-DefenderXDRWeeklyReport.ps1 (weekly report)

    Actions performed:
      1. Creates a secure directory structure
        2. Requests and stores credentials (secret via DPAPI, existing certificate, or self-signed certificate)
      3. Validates App Registration permissions against the API
      4. Copies scripts to the execution path
      5. Configures email notifications (optional)
        6. Configures default workloads for the daily report (MDO/MDE/MDI/MDA)
            7. Generates secure wrappers for Task Scheduler
        8. Creates scheduled tasks (Daily 7:00 AM / Weekly Monday 7:30 AM)
        9. Runs a validation test (optional)

        If certificate authentication is chosen, the setup can create a self-signed
        certificate, export the public .cer for App Registration, and have the thumbprint
        ready for the scheduled tasks.

.PARAMETER ConfigPath
    Path for configuration files (default: $PSScriptRoot\Config).

.PARAMETER ReportsPath
    Base path for generated reports (default: $PSScriptRoot\Reports).

.PARAMETER ScriptsPath
    Path where report scripts will be copied (default: $PSScriptRoot).

.PARAMETER RepositoryRawBaseUrl
    RAW base URL of the repository to download missing scripts.
    Example: https://raw.githubusercontent.com/<owner>/<repo>/main/XDR

.PARAMETER SkipValidation
    Skips permission validation against the API.

.PARAMETER SkipScheduledTasks
    Skips the creation of scheduled tasks.

.PARAMETER SkipEmail
    Skips email notification configuration.

.EXAMPLE
    .\Setup-DefenderXDRReportServer.ps1
    .\Setup-DefenderXDRReportServer.ps1 -SkipScheduledTasks
    .\Setup-DefenderXDRReportServer.ps1 -SkipEmail -SkipValidation

.NOTES
    Must be run with the service account that will execute the scheduled reports.
    Credentials are protected with DPAPI (only work with the user who ran the setup).
    Required permission in App Registration: AdvancedHunting.Read.All (Application).
    If a self-signed certificate is generated, upload the exported .cer file in
    Entra ID > App registrations > Certificates & secrets before validating or scheduling.
    Author : Ernesto Cobos Roqueñí, Arturo Mandujano
#>

param(
    [string]$ConfigPath   = "$PSScriptRoot\Config",
    [string]$ReportsPath  = "$PSScriptRoot\Reports",
    [string]$ScriptsPath  = "$PSScriptRoot",
    [string]$RepositoryRawBaseUrl,
    [switch]$SkipValidation,
    [switch]$SkipScheduledTasks,
    [switch]$SkipEmail
)

$ErrorActionPreference = "Stop"

# ============================================================
#  UTILITIES
# ============================================================

function Mask-String {
    param([string]$Value, [int]$VisibleChars = 4)
    if ([string]::IsNullOrEmpty($Value)) { return '****' }
    if ($Value.Length -le $VisibleChars) { return '****' }
    return ('*' * ($Value.Length - $VisibleChars)) + $Value.Substring($Value.Length - $VisibleChars)
}

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "`n[$Step] $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "  [--] $Message" -ForegroundColor Gray
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [!!] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Cyan
}

function Get-PowerShell7ExecutablePath {
    $PwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($PwshCommand) {
        return $PwshCommand.Source
    }

    $CandidatePaths = @(
        (Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "PowerShell\7\pwsh.exe")
    )

    foreach ($Candidate in $CandidatePaths) {
        if ($Candidate -and (Test-Path $Candidate)) {
            return $Candidate
        }
    }

    return $null
}

function Normalize-InputValue {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return $null
    }

    return $Value.Trim()
}

function Test-GuidLikeValue {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return ($Value.Trim() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-GitHubRawBaseUrl {
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [string]$OverrideUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($OverrideUrl)) {
        return $OverrideUrl.TrimEnd('/')
    }

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        return $null
    }

    try {
        $GitRemote = (& git -C $SourceDir config --get remote.origin.url 2>$null)
        if (-not $GitRemote) {
            return $null
        }

        $GitRemote = $GitRemote.Trim()

        if ($GitRemote -match '^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(\.git)?$') {
            return "https://raw.githubusercontent.com/$($Matches.owner)/$($Matches.repo)/main/XDR"
        }

        if ($GitRemote -match '^git@github\.com:(?<owner>[^/]+)/(?<repo>[^/]+?)(\.git)?$') {
            return "https://raw.githubusercontent.com/$($Matches.owner)/$($Matches.repo)/main/XDR"
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-RepositoryScriptUrl {
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string]$RawBaseUrl
    )

    $DefaultScriptUrls = @{
        'New-DefenderXDRDailyReport.ps1'  = 'https://raw.githubusercontent.com/watchdogcode/gol2026/refs/heads/main/XDR/New-DefenderXDRDailyReport.ps1'
        'New-DefenderXDRWeeklyReport.ps1' = 'https://raw.githubusercontent.com/watchdogcode/gol2026/refs/heads/main/XDR/New-DefenderXDRWeeklyReport.ps1'
    }

    if (-not [string]::IsNullOrWhiteSpace($RawBaseUrl)) {
        return ('{0}/{1}' -f $RawBaseUrl.TrimEnd('/'), $ScriptName)
    }

    if ($DefaultScriptUrls.ContainsKey($ScriptName)) {
        return $DefaultScriptUrls[$ScriptName]
    }

    return $null
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    $B64 = [Convert]::ToBase64String($Bytes)
    $B64 = $B64.TrimEnd('=')
    $B64 = $B64.Replace('+', '-').Replace('/', '_')
    return $B64
}

function Get-CertificateByThumbprint {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $NormalizedThumb = ($Thumbprint -replace '\s','').ToUpperInvariant()
    foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $StoreLocation)
        try {
            $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $Found = $Store.Certificates | Where-Object { $_.Thumbprint -eq $NormalizedThumb } | Select-Object -First 1
            if ($Found) { return $Found }
        }
        finally {
            $Store.Close()
        }
    }

    return $null
}

function New-SelfSignedCertificateForAppAuth {
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$FriendlyName,
        [Parameter(Mandatory)][string]$CertStoreLocation,
        [int]$ValidYears = 2,
        [int]$KeyLength = 2048
    )

    $NotAfter = (Get-Date).AddYears($ValidYears)

    return New-SelfSignedCertificate `
        -Subject $Subject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation $CertStoreLocation `
        -KeyAlgorithm RSA `
        -KeyLength $KeyLength `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm SHA256 `
        -NotAfter $NotAfter `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')
}

function Export-PublicCertificateFile {
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $OutputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    Export-Certificate -Cert $Certificate -FilePath $OutputPath -Force | Out-Null
    return $OutputPath
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Ensure-AzAccountsModule {
    $AzAccountsModule = Get-Module -ListAvailable -Name 'Az.Accounts' | Sort-Object Version -Descending | Select-Object -First 1
    if ($AzAccountsModule) {
        try {
            Import-Module Az.Accounts -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Skip "Az.Accounts is installed but could not be imported: $($_.Exception.Message)"
        }

        return $true
    }

    Write-Skip 'Az.Accounts is not installed for this user.'
    $InstallAzAccounts = Read-Host '  Install Az.Accounts automatically now? [Y/n]'
    if ($InstallAzAccounts -in @('n','N')) {
        return $false
    }

    try {
        Write-Info 'Installing Az.Accounts from PSGallery in CurrentUser scope...'
        Install-Module -Name Az.Accounts -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module Az.Accounts -ErrorAction Stop | Out-Null
        Write-Ok 'Az.Accounts installed and imported successfully.'
        return $true
    }
    catch {
        Write-Fail "Could not install Az.Accounts automatically: $($_.Exception.Message)"
        Write-Host '    Setup will use Device Code for Microsoft Graph if you decide to continue.' -ForegroundColor DarkYellow
        return $false
    }
}

function Get-GraphDelegatedAccessToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string[]]$Scopes = @('Application.ReadWrite.All')
    )

    $GraphResource = 'https://graph.microsoft.com'
    $ScopeString = (($Scopes + 'offline_access') | Select-Object -Unique) -join ' '

    if (Get-Module -ListAvailable -Name 'Az.Accounts') {
        try {
            $AzContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $AzContext) {
                Write-Info 'No active Azure session found. Starting delegated authentication for Microsoft Graph...'
                Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
            }

            $TokenData = Get-AzAccessToken -TenantId $TenantId -ResourceUrl $GraphResource -ErrorAction Stop
            $AccessToken = if ($TokenData.Token -is [System.Security.SecureString]) {
                ConvertFrom-SecureStringToPlainText -SecureString $TokenData.Token
            }
            else {
                [string]$TokenData.Token
            }

            return @{
                AccessToken = $AccessToken
                Source      = 'Az.Accounts'
            }
        }
        catch {
            Write-Skip "Could not obtain Graph token via Az.Accounts: $($_.Exception.Message)"
        }
    }

    $PublicClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    $DeviceCodeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $DeviceCodeResponse = Invoke-RestMethod -Method Post -Uri $DeviceCodeUri -Body @{
        client_id = $PublicClientId
        scope     = $ScopeString
    } -ErrorAction Stop

    Write-Host ''
    Write-Host $DeviceCodeResponse.message -ForegroundColor Yellow

    $Elapsed = 0
    $Interval = [int]$DeviceCodeResponse.interval
    $ExpiresIn = [int]$DeviceCodeResponse.expires_in

    while ($Elapsed -lt $ExpiresIn) {
        Start-Sleep -Seconds $Interval
        $Elapsed += $Interval

        try {
            $TokenResponse = Invoke-RestMethod -Method Post -Uri $TokenUri -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $PublicClientId
                device_code = $DeviceCodeResponse.device_code
            } -ErrorAction Stop

            return @{
                AccessToken = [string]$TokenResponse.access_token
                Source      = 'DeviceCode'
            }
        }
        catch {
            $GraphError = $null
            if ($_.ErrorDetails.Message) {
                try { $GraphError = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            }

            if ($GraphError.error -eq 'authorization_pending') { continue }
            if ($GraphError.error -eq 'slow_down') {
                $Interval += 5
                continue
            }
            if ($GraphError.error -eq 'expired_token') {
                throw 'The device code for Microsoft Graph expired before completing the certificate registration.'
            }

            throw
        }
    }

    throw 'Timeout while requesting delegated token for Microsoft Graph.'
}

function Invoke-GraphApiRequest {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET','PATCH')][string]$Method = 'GET',
        [object]$Body
    )

    $Headers = @{ Authorization = "Bearer $AccessToken" }
    if ($Method -eq 'PATCH') {
        $Headers['Content-Type'] = 'application/json'
        return Invoke-RestMethod -Method Patch -Uri $Uri -Headers $Headers -Body ($Body | ConvertTo-Json -Depth 8 -Compress) -ErrorAction Stop
    }

    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
}

function ConvertTo-GraphKeyCredential {
    param([Parameter(Mandatory)]$KeyCredential)

    $GraphKeyCredential = [ordered]@{}
    foreach ($Name in @('customKeyIdentifier','displayName','endDateTime','key','keyId','startDateTime','type','usage')) {
        $Value = $KeyCredential.$Name
        if ($null -ne $Value -and $Value -ne '') {
            $GraphKeyCredential[$Name] = $Value
        }
    }

    return $GraphKeyCredential
}

function Register-CertificateWithAppRegistration {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$PublicCertificatePath
    )

    $GraphToken = Get-GraphDelegatedAccessToken -TenantId $TenantId
    Write-Ok "Microsoft Graph delegated token obtained via $($GraphToken.Source)"

    $Filter = [System.Uri]::EscapeDataString("appId eq '$ClientId'")
    $SearchUri = "https://graph.microsoft.com/v1.0/applications?`$filter=$Filter&`$select=id,appId,displayName"
    $SearchResponse = Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri $SearchUri -Method GET

    if (-not $SearchResponse.value -or $SearchResponse.value.Count -eq 0) {
        throw "Application Object not found for appId/clientId '$ClientId'."
    }

    $Application = @($SearchResponse.value)[0]
    $ApplicationUri = "https://graph.microsoft.com/v1.0/applications/$($Application.id)?`$select=id,appId,displayName,keyCredentials"
    $ApplicationDetail = Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri $ApplicationUri -Method GET

    $CertificateKey = [Convert]::ToBase64String($Certificate.RawData)
    $CertificateThumbprintBase64 = [Convert]::ToBase64String($Certificate.GetCertHash())
    $ExistingKeyCredentials = @($ApplicationDetail.keyCredentials)

    $AlreadyExists = $ExistingKeyCredentials | Where-Object {
        ($_.customKeyIdentifier -and $_.customKeyIdentifier -eq $CertificateThumbprintBase64) -or
        ($_.key -and $_.key -eq $CertificateKey)
    } | Select-Object -First 1

    if ($AlreadyExists) {
        return @{
            ApplicationObjectId = $Application.id
            ApplicationName     = $Application.displayName
            RegistrationMode    = 'AlreadyPresent'
        }
    }

    $MergedKeyCredentials = @()
    foreach ($ExistingKey in $ExistingKeyCredentials) {
        $MergedKeyCredentials += ,(ConvertTo-GraphKeyCredential -KeyCredential $ExistingKey)
    }

    $MergedKeyCredentials += ,([ordered]@{
        customKeyIdentifier = $CertificateThumbprintBase64
        displayName         = $Certificate.Subject
        endDateTime         = $Certificate.NotAfter.ToUniversalTime().ToString('o')
        key                 = $CertificateKey
        keyId               = ([guid]::NewGuid()).Guid
        startDateTime       = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        type                = 'AsymmetricX509Cert'
        usage               = 'Verify'
    })

    Invoke-GraphApiRequest -AccessToken $GraphToken.AccessToken -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.id)" -Method PATCH -Body @{
        keyCredentials = $MergedKeyCredentials
    } | Out-Null

    return @{
        ApplicationObjectId = $Application.id
        ApplicationName     = $Application.displayName
        RegistrationMode    = 'Added'
        PublicCertificate   = $PublicCertificatePath
    }
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
        throw "Could not obtain the RSA private key from the certificate."
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

# ============================================================
#  BANNER
# ============================================================

$Banner = @"

  ===================================================================
   Defender XDR Report Server - Setup
   Daily & Weekly Security Operations Reports
  ===================================================================
   User     : $env:USERDOMAIN\$env:USERNAME
   Computer : $env:COMPUTERNAME
   Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
   PS       : $($PSVersionTable.PSVersion)
  ===================================================================

"@

Write-Host $Banner -ForegroundColor Cyan

# ============================================================
#  STEP 1: Directory structure
# ============================================================

Write-Step "1/10" "Creating directory structure..."

$Directories = @(
    $ConfigPath,
    "$ReportsPath\Daily",
    "$ReportsPath\Weekly",
    "$ReportsPath\Logs"
)

foreach ($Dir in $Directories) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-Ok "Created: $Dir"
    } else {
        Write-Skip "Already exists: $Dir"
    }
}

# Protect configuration folder (current user + SYSTEM only)
try {
    $Acl = Get-Acl $ConfigPath
    $Acl.SetAccessRuleProtection($true, $false)
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$env:USERDOMAIN\$env:USERNAME", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.AddAccessRule($Rule)
    $RuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.AddAccessRule($RuleSystem)
    Set-Acl -Path $ConfigPath -AclObject $Acl -ErrorAction SilentlyContinue
    Write-Ok "Restricted ACL applied to $ConfigPath"
} catch {
    Write-Skip "Could not restrict ACL (requires elevated permissions)"
}

# ============================================================
#  STEP 2: Azure AD Credentials
# ============================================================

Write-Step "2/10" "Azure AD App Registration configuration"

$TenantId = Normalize-InputValue (Read-Host "  Enter Tenant ID")
$ClientId = Normalize-InputValue (Read-Host "  Enter Client ID (App Registration)")

if (-not (Test-GuidLikeValue $TenantId)) {
    throw "Invalid Tenant ID. Must be in GUID format, for example: 00000000-0000-0000-0000-000000000000"
}

if (-not (Test-GuidLikeValue $ClientId)) {
    throw "Invalid Client ID. Must be in GUID format, for example: 00000000-0000-0000-0000-000000000000"
}

Write-Host ""
Write-Info "Available authentication methods:"
Write-Host "    1. Existing certificate (RECOMMENDED for automation; thumbprint already uploaded to App Registration)" -ForegroundColor White
Write-Host "    2. Self-signed certificate (RECOMMENDED for automation; create on this server and export .cer)" -ForegroundColor White
Write-Host "    3. Client Secret  (Alternative for automation)" -ForegroundColor White
Write-Host "    4. Device Code    (For manual testing or servers without a browser)" -ForegroundColor White
Write-Host "    5. Interactive    (Browser popup login, only for manual execution)" -ForegroundColor White
Write-Host "    6. Skip           (I will configure credentials later)" -ForegroundColor White

$AuthChoice = Read-Host "`n  Select method [1-6]"

$AuthMode        = "DeviceCode"
$UseSecret       = $false
$UseCertificate  = $false
$SecretFile      = "$ConfigPath\ClientSecret.enc"
$CertThumbprint  = $null
$CertSubject     = $null
$CertPublicPath  = $null
$CertStoreLocation = $null
$CertProvisioningMode = $null
$CertAutoRegistration = $false
$CertAutoRegistrationStatus = $null
$AppObjectId = $null
$PlainSecretForValidation = $null

if ($AuthChoice -eq "1") {
    Write-Info "Configuring authentication by Certificate (existing)..."
    $CertThumbprint = ((Read-Host "  Enter the certificate Thumbprint") -replace '\s','').ToUpperInvariant()

    # Validate that the certificate exists in CurrentUser/My or LocalMachine/My
    $CertFound = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
    if (-not $CertFound) {
        throw "Certificate not found. Verify thumbprint and store (CurrentUser/My or LocalMachine/My)."
    }

    Write-Ok "Certificate found: $($CertFound.Subject) (Expires: $($CertFound.NotAfter.ToString('yyyy-MM-dd')))"
    if ($CertFound.NotAfter -lt (Get-Date).AddDays(30)) {
        Write-Fail "WARNING: The certificate expires in less than 30 days"
    }

    $CertSubject = $CertFound.Subject
    $CertStoreLocation = 'Cert:\CurrentUser\My'
    $CertProvisioningMode = 'Existing'

    $ExportExistingCer = Read-Host "  Export public .cer for App Registration? [Y/n]"
    if ($ExportExistingCer -notin @('n','N')) {
        $DefaultExistingCerPath = Join-Path $ConfigPath "DefenderXDR-ExistingCertificate.cer"
        $RequestedExistingCerPath = Read-Host "  Path to export the public .cer [default: $DefaultExistingCerPath]"
        if ([string]::IsNullOrWhiteSpace($RequestedExistingCerPath)) {
            $RequestedExistingCerPath = $DefaultExistingCerPath
        }
        $CertPublicPath = Export-PublicCertificateFile -Certificate $CertFound -OutputPath $RequestedExistingCerPath
        Write-Ok "Public .cer exported: $CertPublicPath"
    }

    $AuthMode       = "Certificate"
    $UseCertificate = $true
}
elseif ($AuthChoice -eq "2") {
    Write-Info "Creating self-signed certificate for App Registration..."

    $DefaultSubject = "CN=DefenderXDRReports-$env:COMPUTERNAME"
    $RequestedSubject = Read-Host "  Certificate Subject [default: $DefaultSubject]"
    if ([string]::IsNullOrWhiteSpace($RequestedSubject)) {
        $RequestedSubject = $DefaultSubject
    }

    $RequestedYears = Read-Host "  Validity in years [default: 2]"
    $ValidYears = 2
    if ($RequestedYears -and ($RequestedYears -as [int]) -ge 1) {
        $ValidYears = [int]$RequestedYears
    }

    $CertStoreLocation = 'Cert:\CurrentUser\My'
    $FriendlyName = "Defender XDR Report Server - $env:COMPUTERNAME"
    $DefaultCerPath = Join-Path $ConfigPath "DefenderXDR-AppRegistration.cer"
    $RequestedCerPath = Read-Host "  Path to export the public .cer [default: $DefaultCerPath]"
    if ([string]::IsNullOrWhiteSpace($RequestedCerPath)) {
        $RequestedCerPath = $DefaultCerPath
    }

    $CreatedCert = New-SelfSignedCertificateForAppAuth `
        -Subject $RequestedSubject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation $CertStoreLocation `
        -ValidYears $ValidYears

    $CertPublicPath = Export-PublicCertificateFile -Certificate $CreatedCert -OutputPath $RequestedCerPath
    $CertThumbprint = $CreatedCert.Thumbprint
    $CertSubject = $CreatedCert.Subject
    $CertProvisioningMode = 'SelfSigned'

    Write-Ok "Self-signed certificate created: $CertSubject"
    Write-Ok "Thumbprint: $CertThumbprint"
    Write-Ok "Expires: $($CreatedCert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Ok "Public .cer exported: $CertPublicPath"
    Write-Host "    Upload this .cer in Entra ID > App registrations > Certificates & secrets > Upload certificate." -ForegroundColor DarkYellow
    Write-Host "    The scheduled task will use this thumbprint automatically from the CurrentUser\\My store." -ForegroundColor DarkYellow

    $AuthMode       = "Certificate"
    $UseCertificate = $true
}
elseif ($AuthChoice -eq "3") {
    Write-Info "Configuring Client Secret..."
    $SecretInput = Read-Host "  Enter Client Secret" -AsSecureString

    # Save encrypted with DPAPI (only current user can decrypt)
    try {
        $SecretInput | ConvertFrom-SecureString | Out-File $SecretFile -Force -ErrorAction Stop
    }
    catch {
        throw "Could not save the Client Secret to '$SecretFile'. Run setup with the permissions of the user who will execute the task. Details: $($_.Exception.Message)"
    }

    # Get plain text for immediate validation
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretInput)
    $PlainSecretForValidation = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Ok "Secret encrypted (DPAPI) saved to: $SecretFile"
    Write-Host "       Only works with user: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor DarkYellow

    $AuthMode  = "Secret"
    $UseSecret = $true
}
elseif ($AuthChoice -eq "4") {
    $AuthMode = "DeviceCode"
    Write-Skip "Will use Device Code for authentication"
    Write-Host "    The daily report requires Az.Accounts or ClientId+TenantId (fallback REST)" -ForegroundColor DarkYellow
}
elseif ($AuthChoice -eq "5") {
    $AuthMode = "Interactive"
    Write-Skip "Will use Interactive authentication (browser popup)"
    Write-Host ""
    Write-Fail "WARNING: Interactive mode is NOT compatible with Task Scheduler."
    Write-Host "    Scheduled tasks cannot open browser windows." -ForegroundColor DarkYellow
    Write-Host "    Use this mode only for manual test execution." -ForegroundColor DarkYellow
    Write-Host "    For automation, use Client Secret (option 1) or Certificate (option 2)." -ForegroundColor DarkYellow
}
else {
    Write-Skip "Authentication configuration skipped"
}

if ($UseCertificate) {
    $RegisterAutomatically = Read-Host "`n  Automatically register the certificate in App Registration via Microsoft Graph? [y/N]"
    if ($RegisterAutomatically -in @('s','S')) {
        try {
            Write-Info 'Authentication in Entra is required to register certificates in the App Registration.'
            $ConfirmGraphAuth = Read-Host '  Start authentication now for Entra registration? [Y/n]'
            if ($ConfirmGraphAuth -in @('n','N')) {
                throw 'Automatic registration cancelled by user before authenticating to Entra.'
            }

            $HasAzAccounts = Ensure-AzAccountsModule
            if ($HasAzAccounts) {
                Write-Ok 'Az.Accounts will be used as the preferred method to obtain the Microsoft Graph token.'
            }
            else {
                Write-Skip 'Will continue with Device Code fallback for Microsoft Graph.'
            }

            $CertificateForRegistration = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
            if (-not $CertificateForRegistration) {
                throw "Certificate '$CertThumbprint' not found for App Registration registration."
            }

            Write-Info 'Registering certificate in App Registration using Microsoft Graph...'
            $GraphRegistration = Register-CertificateWithAppRegistration -TenantId $TenantId -ClientId $ClientId -Certificate $CertificateForRegistration -PublicCertificatePath $CertPublicPath

            $AppObjectId = $GraphRegistration.ApplicationObjectId
            $CertAutoRegistration = $true
            $CertAutoRegistrationStatus = $GraphRegistration.RegistrationMode

            if ($GraphRegistration.RegistrationMode -eq 'AlreadyPresent') {
                Write-Skip "The certificate was already registered in App Registration '$($GraphRegistration.ApplicationName)'."
            }
            else {
                Write-Ok "Certificate registered in App Registration '$($GraphRegistration.ApplicationName)' (ObjectId: $($GraphRegistration.ApplicationObjectId))"
            }
        }
        catch {
            Write-Fail "Could not automatically register the certificate: $($_.Exception.Message)"
            Write-Host '    Required permissions in delegated context: Application.ReadWrite.All and Application Administrator or Application Developer role.' -ForegroundColor DarkYellow
            Write-Host '    You can continue and manually upload the .cer if you prefer.' -ForegroundColor DarkYellow
        }
    }
}

# Display masked summary
Write-Host ""
Write-Info "Credentials summary (masked):"
Write-Host "    Tenant ID   : $(Mask-String $TenantId)" -ForegroundColor White
Write-Host "    Client ID   : $(Mask-String $ClientId)" -ForegroundColor White
Write-Host "    Secret      : $(if ($UseSecret) {'********'} else {'(not configured)'})" -ForegroundColor White
Write-Host "    Certificate : $(if ($UseCertificate) { Mask-String $CertThumbprint } else { '(not configured)' })" -ForegroundColor White
Write-Host "    Cert Subject: $(if ($UseCertificate -and $CertSubject) { $CertSubject } else { '(not configured)' })" -ForegroundColor White
Write-Host "    Cert .cer   : $(if ($UseCertificate -and $CertPublicPath) { $CertPublicPath } else { '(not configured)' })" -ForegroundColor White
Write-Host "    Cert Graph  : $(if ($UseCertificate -and $CertAutoRegistrationStatus) { $CertAutoRegistrationStatus } else { '(no automatic registration)' })" -ForegroundColor White
Write-Host "    Auth Mode   : $AuthMode" -ForegroundColor White

# ============================================================
#  STEP 3: Save configuration
# ============================================================

Write-Step "3/10" "Saving configuration..."

# Determine effective AuthMode for each script
# Daily and Weekly support Secret, Interactive, DeviceCode, and Certificate.
$DailyAuthMode = $AuthMode

$WeeklyAuthMode = $AuthMode

$Config = @{
    TenantId        = $TenantId
    ClientId        = $ClientId
    AuthMode        = $AuthMode
    DailyAuthMode   = $DailyAuthMode
    WeeklyAuthMode  = $WeeklyAuthMode
    SecretFile      = if ($UseSecret) { $SecretFile } else { $null }
    CertThumbprint  = if ($UseCertificate) { $CertThumbprint } else { $null }
    CertSubject     = if ($UseCertificate) { $CertSubject } else { $null }
    CertPublicPath  = if ($UseCertificate) { $CertPublicPath } else { $null }
    CertStoreLocation = if ($UseCertificate) { $CertStoreLocation } else { $null }
    CertProvisioningMode = if ($UseCertificate) { $CertProvisioningMode } else { $null }
    CertAutoRegistration = if ($UseCertificate) { $CertAutoRegistration } else { $false }
    CertAutoRegistrationStatus = if ($UseCertificate) { $CertAutoRegistrationStatus } else { $null }
    AppObjectId     = $AppObjectId
    ConfigDate      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ConfiguredBy    = "$env:USERDOMAIN\$env:USERNAME"
    ScriptsPath     = $ScriptsPath
    ReportsPath     = $ReportsPath
    LogPath         = "$ReportsPath\Logs"
    DailyScript     = "$ScriptsPath\New-DefenderXDRDailyReport.ps1"
    WeeklyScript    = "$ScriptsPath\New-DefenderXDRWeeklyReport.ps1"
    SendMail        = $false
    SmtpServer      = $null
    MailFrom        = $null
    MailTo          = $null
    RetentionDays   = 90
    DailyWorkloads  = @{ IncludeMDO = $true; IncludeMDE = $true; IncludeMDI = $true; IncludeMDA = $true }
    WeeklyWorkloads = @{ IncludeMDO = $true; IncludeMDE = $true; IncludeMDI = $true; IncludeMDA = $true }
}

$ConfigFile = "$ConfigPath\Config.json"
$Config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Ok "Configuration saved to: $ConfigFile"

# ============================================================
#  STEP 4: Validate permissions against the API
# ============================================================

Write-Step "4/10" "App Registration permission validation"

if ($SkipValidation) {
    Write-Skip "Validation skipped (-SkipValidation parameter)"
}
elseif (-not $UseSecret -and -not $UseCertificate) {
    Write-Skip "Validation requires Client Secret or Certificate (AuthMode=$AuthMode)"
}
else {
    $DoValidate = Read-Host "  Validate permissions now? (requires connectivity) [Y/n]"

    if ($DoValidate -notin @("n", "N")) {
        try {
            Write-Info "Attempting test authentication..."

            $AuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $TokenResponse = $null
            $AccessToken = $null

            if ($UseSecret -and $PlainSecretForValidation) {
                # Validate with Client Secret
                $Body = @{
                    grant_type    = "client_credentials"
                    client_id     = $ClientId
                    client_secret = $PlainSecretForValidation
                    scope         = "https://api.security.microsoft.com/.default"
                }
                $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body -ErrorAction Stop
                Write-Ok "Client Secret authentication successful (token expires in $($TokenResponse.expires_in)s)"
            }
            elseif ($UseCertificate -and $CertThumbprint) {
                # Validate with Certificate using client_assertion (same strategy as report scripts)
                $Cert = Get-CertificateByThumbprint -Thumbprint $CertThumbprint
                if (-not $Cert) {
                    throw "Certificate not found for validation. Thumbprint: $CertThumbprint"
                }

                $ClientAssertion = New-ClientAssertionJwt -Certificate $Cert -ClientId $ClientId -TenantId $TenantId
                $Body = @{
                    grant_type            = 'client_credentials'
                    client_id             = $ClientId
                    scope                 = 'https://api.security.microsoft.com/.default'
                    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                    client_assertion      = $ClientAssertion
                }
                $TokenResponse = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $Body -ErrorAction Stop
                Write-Ok "Certificate authentication successful"
            }

            # Test Advanced Hunting (if token was obtained)
            $TestToken = if ($TokenResponse) { $TokenResponse.access_token } elseif ($AccessToken) { $AccessToken } else { $null }

            if ($TestToken) {
                Write-Info "Testing access to Advanced Hunting API..."
                $Headers = @{
                    "Authorization" = "Bearer $TestToken"
                    "Content-Type"  = "application/json"
                }
                $TestQuery = @{ Query = "print Test='OK', Timestamp=now()" } | ConvertTo-Json -Compress
                $null = Invoke-RestMethod -Method Post `
                    -Uri "https://api.security.microsoft.com/api/advancedhunting/run" `
                    -Headers $Headers -Body $TestQuery -ErrorAction Stop

                Write-Ok "Advanced Hunting API accessible - Permissions verified"
                Write-Ok "AdvancedHunting.Read.All: CONCEDIDO"
            }
        }
        catch {
            Write-Fail "Validation error: $($_.Exception.Message)"
            if ($_.ErrorDetails.Message -match 'AADSTS700027') {
                Write-Host "    AADSTS700027: The certificate is not registered in the App Registration." -ForegroundColor DarkYellow
                if ($Config.CertPublicPath) {
                    Write-Host "    Upload the generated .cer at: $($Config.CertPublicPath)" -ForegroundColor DarkYellow
                }
                Write-Host "    Entra ID > App registrations > Certificates & secrets > Upload certificate." -ForegroundColor DarkYellow
            }
            Write-Host "    Verify that the App Registration has:" -ForegroundColor DarkYellow
            Write-Host "      - Permission: AdvancedHunting.Read.All (Application)" -ForegroundColor DarkYellow
            Write-Host "      - Admin Consent granted in the tenant" -ForegroundColor DarkYellow
            Write-Host "      - Valid (non-expired) Client Secret/Certificate" -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Skip "Validation skipped by user"
    }
}

# Clear secret from memory
if ($PlainSecretForValidation) {
    $PlainSecretForValidation = $null
    [System.GC]::Collect()
}

# ============================================================
#  STEP 5: Copy report scripts
# ============================================================

Write-Step "5/10" "Copying report scripts..."

$SourceDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$RawRepoBaseUrl = Get-GitHubRawBaseUrl -SourceDir $SourceDir -OverrideUrl $RepositoryRawBaseUrl

$ScriptsToCopy = @(
    "New-DefenderXDRDailyReport.ps1",
    "New-DefenderXDRWeeklyReport.ps1"
)

foreach ($Script in $ScriptsToCopy) {
    $Source = Join-Path $SourceDir $Script
    $Dest   = Join-Path $ScriptsPath $Script
    
    # Strict validation: Ensure the file exists and is larger than 500 bytes (avoids false positives from OneDrive/AV)
    $DestIsValid   = (Test-Path $Dest -PathType Leaf) -and ((Get-Item $Dest).Length -gt 500)
    $SourceIsValid = (Test-Path $Source -PathType Leaf) -and ((Get-Item $Source).Length -gt 500)

    if (($Source -eq $Dest) -and $DestIsValid) {
        Write-Skip "$Script is already in the destination path and is valid"
    }
    elseif ($SourceIsValid) {
        Copy-Item $Source -Destination $Dest -Force
        Write-Ok "Copied: $Script -> $ScriptsPath"
    }
    else {
        # Force TLS 1.2 for Invoke-WebRequest compatibility
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $DownloadUrl = Get-RepositoryScriptUrl -ScriptName $Script -RawBaseUrl $RawRepoBaseUrl
        $FallbackUrl = "https://raw.githubusercontent.com/watchdogcode/gol2026/main/XDR/$Script"
        $Downloaded  = $false

        if ($DownloadUrl) {
            try {
                Write-Info "Not found locally. Downloading from repository: $DownloadUrl"
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $Dest -UseBasicParsing -ErrorAction Stop
                $Downloaded = $true
                Write-Ok "Downloaded: $Script -> $Dest"
            }
            catch {
                Write-Fail "Could not download $Script from the repository: $($_.Exception.Message)"
            }
        }
        
        if (-not $Downloaded) {
            Write-Info "Trying direct download method (Fallback)..."
            try {
                Invoke-WebRequest $FallbackUrl -OutFile $Dest -UseBasicParsing -ErrorAction Stop
                Write-Ok "Downloaded via direct link: $Script -> $Dest"
            }
            catch {
                Write-Fail "Not found: $Source"
                Write-Host "    Direct download failed and no base URL was detected." -ForegroundColor DarkYellow
            }
        }
    }
}

# ============================================================
#  STEP 6: Email notification configuration
# ============================================================

Write-Step "6/10" "Email notification configuration (optional)"

if ($SkipEmail) {
    Write-Skip "Email configuration skipped (-SkipEmail parameter)"
}
else {
    $ConfigureEmail = Read-Host "  Configure report delivery via email? [y/N]"

    if ($ConfigureEmail -in @("s", "S")) {
        $SmtpServer = Read-Host "  SMTP server (e.g.: smtp.office365.com)"
        $MailFrom   = Read-Host "  Sender address (From)"
        $MailTo     = Read-Host "  Recipient address (To)"

        # Update config with email data
        $Config.SendMail   = $true
        $Config.SmtpServer = $SmtpServer
        $Config.MailFrom   = $MailFrom
        $Config.MailTo     = $MailTo

        $Config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8 -Force

        Write-Ok "Email configured: $MailFrom -> $MailTo via $SmtpServer"
    }
    else {
        Write-Skip "Email notifications skipped"
    }
}

# ============================================================
#  STEP 7: Workload preferences (daily report)
# ============================================================

Write-Step "7/10" "Configuring workloads with Default selection"

function Get-WorkloadPreferenceFromCsv {
    param(
        [AllowNull()][AllowEmptyString()][string]$InputValue,
        [Parameter(Mandatory)][string]$ScopeName
    )

    $Preference = @{
        IncludeMDO = $true
        IncludeMDE = $true
        IncludeMDI = $true
        IncludeMDA = $true
    }

    if ([string]::IsNullOrWhiteSpace($InputValue)) {
        Write-Skip "$($ScopeName): Default selection applied (MDO, MDE, MDI, MDA)."
        return $Preference
    }

    $Allowed = @('MDO','MDE','MDI','MDA')
    $Selected = $InputValue.Split(',') |
        ForEach-Object { $_.Trim().ToUpperInvariant() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    $Invalid = $Selected | Where-Object { $_ -notin $Allowed }
    if ($Invalid.Count -gt 0) {
        Write-Skip "$($ScopeName): invalid values will be ignored: $($Invalid -join ', ')"
    }

    $Valid = $Selected | Where-Object { $_ -in $Allowed }
    if ($Valid.Count -eq 0) {
        Write-Skip "$($ScopeName): no valid workloads detected; Default selection will be applied (MDO, MDE, MDI, MDA)."
        return $Preference
    }

    $Preference.IncludeMDO = $false
    $Preference.IncludeMDE = $false
    $Preference.IncludeMDI = $false
    $Preference.IncludeMDA = $false

    foreach ($Workload in $Valid) {
        switch ($Workload) {
            'MDO' { $Preference.IncludeMDO = $true }
            'MDE' { $Preference.IncludeMDE = $true }
            'MDI' { $Preference.IncludeMDI = $true }
            'MDA' { $Preference.IncludeMDA = $true }
        }
    }

    # Entra ID depends on MDI and must always remain enabled.
    if (-not $Preference.IncludeMDI) {
        $Preference.IncludeMDI = $true
        Write-Info "$($ScopeName): Entra ID is always included; MDI was enabled automatically."
    }

    return $Preference
}

$DailyWorkloads = @{
    IncludeMDO = $true
    IncludeMDE = $true
    IncludeMDI = $true
    IncludeMDA = $true
}

Write-Info "Available workloads: MDO, MDE, MDI, MDA"
$DailyInput = Read-Host "  Daily report -> enter workloads separated by commas (e.g.: MDO,MDE). Enter = Default selection (all)"
$DailyWorkloads = Get-WorkloadPreferenceFromCsv -InputValue $DailyInput -ScopeName 'Daily report'

$Config.DailyWorkloads = $DailyWorkloads
$Config | ConvertTo-Json -Depth 4 | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Ok "Daily workload preferences saved to config.json"

$SelectedDailyWorkloads = @()
if ($DailyWorkloads.IncludeMDO) { $SelectedDailyWorkloads += 'MDO' }
if ($DailyWorkloads.IncludeMDE) { $SelectedDailyWorkloads += 'MDE' }
if ($DailyWorkloads.IncludeMDI) { $SelectedDailyWorkloads += 'MDI' }
if ($DailyWorkloads.IncludeMDA) { $SelectedDailyWorkloads += 'MDA' }
Write-Info ("Active daily workloads: {0}" -f ($SelectedDailyWorkloads -join ', '))

$WeeklyWorkloads = @{
    IncludeMDO = $true
    IncludeMDE = $true
    IncludeMDI = $true
    IncludeMDA = $true
}

Write-Info "Available workloads: MDO, MDE, MDI, MDA"
$WeeklyInput = Read-Host "  Weekly report -> enter workloads separated by commas (e.g.: MDO,MDE,MDI). Enter = Default selection (all)"
$WeeklyWorkloads = Get-WorkloadPreferenceFromCsv -InputValue $WeeklyInput -ScopeName 'Weekly report'

$Config.WeeklyWorkloads = $WeeklyWorkloads
$Config | ConvertTo-Json -Depth 4 | Out-File $ConfigFile -Encoding UTF8 -Force
Write-Ok "Weekly workload preferences saved to config.json"

$SelectedWeeklyWorkloads = @()
if ($WeeklyWorkloads.IncludeMDO) { $SelectedWeeklyWorkloads += 'MDO' }
if ($WeeklyWorkloads.IncludeMDE) { $SelectedWeeklyWorkloads += 'MDE' }
if ($WeeklyWorkloads.IncludeMDI) { $SelectedWeeklyWorkloads += 'MDI' }
if ($WeeklyWorkloads.IncludeMDA) { $SelectedWeeklyWorkloads += 'MDA' }
Write-Info ("Active weekly workloads: {0}" -f ($SelectedWeeklyWorkloads -join ', '))

# ============================================================
#  STEP 8: Create wrappers for Task Scheduler
# ============================================================

Write-Step "8/10" "Creating scheduled execution wrappers..."

# ---- WRAPPER: Daily Report ----
$DailyWrapperContent = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper - Defender XDR Daily Report (scheduled execution)
    Automatically generated by Setup-DefenderReportServer.ps1

.NOTES
    User    : $env:USERDOMAIN\$env:USERNAME
    Created : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
#>

`$ErrorActionPreference = "Stop"

# Load configuration
`$ConfigFile = "$ConfigFile"
if (-not (Test-Path `$ConfigFile)) { Write-Error "Config not found: `$ConfigFile"; exit 1 }
`$Config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json
`$Config.TenantId = if (`$Config.TenantId) { [string]`$Config.TenantId.Trim() } else { `$Config.TenantId }
`$Config.ClientId = if (`$Config.ClientId) { [string]`$Config.ClientId.Trim() } else { `$Config.ClientId }
`$Config.CertThumbprint = if (`$Config.CertThumbprint) { ([string]`$Config.CertThumbprint -replace '\s','').ToUpperInvariant() } else { `$Config.CertThumbprint }

if (`$Config.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "Invalid TenantId in config.json: `$(`$Config.TenantId)"
    exit 1
}

if (`$Config.ClientId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "Invalid ClientId in config.json: `$(`$Config.ClientId)"
    exit 1
}

`$OutputDir = Join-Path `$Config.ReportsPath "Daily"
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }

# Determine AuthMode for the Daily report
`$DailyAuth = `$Config.DailyAuthMode
if (-not `$DailyAuth) { `$DailyAuth = `$Config.AuthMode }

# Load Client Secret from encrypted file (DPAPI)
`$ClientSecretPlain = `$null
if ((`$DailyAuth -eq "Secret") -and `$Config.SecretFile) {
    if (Test-Path `$Config.SecretFile) {
        try {
            `$Secure = Get-Content `$Config.SecretFile | ConvertTo-SecureString -ErrorAction Stop
            `$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$Secure)
            `$ClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$BSTR)
        } catch {
            Write-Error "Could not decrypt the secret. Run Setup again with the correct user."
            exit 1
        }
    } else {
        Write-Error "Secret file not found: `$(`$Config.SecretFile)"
        exit 1
    }
}

# Build parameters
`$Params = @{
    TenantId        = `$Config.TenantId
    ClientId        = `$Config.ClientId
    AuthMode        = `$DailyAuth
    TimeWindowHours = 24
    OutputPath      = Join-Path `$OutputDir "Daily_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    TimeoutSec      = 120
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

if (`$DailyAuth -eq "Certificate" -and `$Config.CertThumbprint) {
    `$Params['CertificateThumbprint'] = `$Config.CertThumbprint
}

# Add email parameters if configured
if (`$Config.SendMail -eq `$true -and `$Config.SmtpServer) {
    `$Params['SendMail']   = `$true
    `$Params['SmtpServer'] = `$Config.SmtpServer
    `$Params['From']       = `$Config.MailFrom
    `$Params['To']         = `$Config.MailTo
    `$Params['Subject']    = "Daily Security Report - M365 Defender XDR - `$(Get-Date -Format 'yyyy-MM-dd')"
}

# Add daily workload filters configured in setup
if (`$Config.DailyWorkloads) {
    if (`$Config.DailyWorkloads.IncludeMDO -eq `$true) { `$Params['IncludeMDO'] = `$true }
    if (`$Config.DailyWorkloads.IncludeMDE -eq `$true) { `$Params['IncludeMDE'] = `$true }
    if (`$Config.DailyWorkloads.IncludeMDI -eq `$true) { `$Params['IncludeMDI'] = `$true }
    if (`$Config.DailyWorkloads.IncludeMDA -eq `$true) { `$Params['IncludeMDA'] = `$true }
}

# Execute
if (-not (Test-Path `$Config.DailyScript -PathType Leaf)) {
    Write-Error "The main script was not found or is not a valid file: `$(`$Config.DailyScript). If using OneDrive, verify it is downloaded locally."
    exit 1
}
# Force OneDrive hydration

try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting Defender XDR Daily Report (Auth: `$DailyAuth)..." -ForegroundColor Cyan
    & `$Config.DailyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Daily report completed." -ForegroundColor Green

    # Cleanup of old reports
    `$RetentionDays = if (`$Config.RetentionDays) { `$Config.RetentionDays } else { 90 }
    Get-ChildItem "`$OutputDir\*.html" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Error in daily report: `$(`$_.Exception.Message)"
    exit 1
}
finally {
    `$ClientSecretPlain = `$null
    [System.GC]::Collect()
}
"@

$DailyWrapperPath = "$ScriptsPath\Run-DefenderXDRDailyReport.ps1"
$DailyWrapperContent | Out-File $DailyWrapperPath -Encoding UTF8 -Force
Write-Ok "Daily wrapper:  $DailyWrapperPath"

# ---- WRAPPER: Weekly Report ----
$WeeklyWrapperContent = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper - Defender XDR Weekly Report (scheduled execution)
    Automatically generated by Setup-DefenderReportServer.ps1

.NOTES
    User    : $env:USERDOMAIN\$env:USERNAME
    Created : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
#>

`$ErrorActionPreference = "Stop"

# Load configuration
`$ConfigFile = "$ConfigFile"
if (-not (Test-Path `$ConfigFile)) { Write-Error "Config not found: `$ConfigFile"; exit 1 }
`$Config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json
`$Config.TenantId = if (`$Config.TenantId) { [string]`$Config.TenantId.Trim() } else { `$Config.TenantId }
`$Config.ClientId = if (`$Config.ClientId) { [string]`$Config.ClientId.Trim() } else { `$Config.ClientId }
`$Config.CertThumbprint = if (`$Config.CertThumbprint) { ([string]`$Config.CertThumbprint -replace '\s','').ToUpperInvariant() } else { `$Config.CertThumbprint }

if (`$Config.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "Invalid TenantId in config.json: `$(`$Config.TenantId)"
    exit 1
}

if (`$Config.ClientId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Error "Invalid ClientId in config.json: `$(`$Config.ClientId)"
    exit 1
}

`$OutputDir = Join-Path `$Config.ReportsPath "Weekly"
`$LogDir    = `$Config.LogPath
if (-not (Test-Path `$OutputDir)) { New-Item -ItemType Directory -Path `$OutputDir -Force | Out-Null }
if (-not (Test-Path `$LogDir))    { New-Item -ItemType Directory -Path `$LogDir -Force | Out-Null }

# Determine AuthMode for the Weekly report
`$WeeklyAuth = `$Config.WeeklyAuthMode
if (-not `$WeeklyAuth) { `$WeeklyAuth = `$Config.AuthMode }

# Load Client Secret from encrypted file (DPAPI) if applicable
`$ClientSecretPlain = `$null
if (`$WeeklyAuth -eq "Secret" -and `$Config.SecretFile) {
    if (Test-Path `$Config.SecretFile) {
        try {
            `$Secure = Get-Content `$Config.SecretFile | ConvertTo-SecureString -ErrorAction Stop
            `$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$Secure)
            `$ClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$BSTR)
        } catch {
            Write-Error "Could not decrypt the secret. Run Setup again with the correct user."
            exit 1
        }
    } else {
        Write-Error "Secret file not found: `$(`$Config.SecretFile)"
        exit 1
    }
}

# Build parameters
`$Params = @{
    TenantId       = `$Config.TenantId
    ClientId       = `$Config.ClientId
    AuthMode       = `$WeeklyAuth
    TimeWindowDays = 7
    OutputPath     = Join-Path `$OutputDir "Weekly_SecOps_Report_`$(Get-Date -Format 'yyyyMMdd').html"
    LogPath        = Join-Path `$LogDir "DefenderXDR_Weekly_`$(Get-Date -Format 'yyyyMMdd').log"
    TimeoutSec     = 120
    ExportCsv      = `$true
}

if (`$ClientSecretPlain) { `$Params['ClientSecret'] = `$ClientSecretPlain }

# Add certificate if applicable
if (`$WeeklyAuth -eq "Certificate" -and `$Config.CertThumbprint) {
    `$Params['CertThumbprint'] = `$Config.CertThumbprint
}

# Add email parameters if configured
if (`$Config.SendMail -eq `$true -and `$Config.SmtpServer) {
    `$Params['SendMail']   = `$true
    `$Params['SmtpServer'] = `$Config.SmtpServer
    `$Params['To']         = `$Config.MailTo
    `$Params['Subject']    = "Defender XDR - Weekly Threat Report - Week of `$(Get-Date -Format 'yyyy-MM-dd')"
}

# Add weekly workload filters configured in setup
if (`$Config.WeeklyWorkloads) {
    if (`$Config.WeeklyWorkloads.IncludeMDO -eq `$true) { `$Params['IncludeMDO'] = `$true }
    if (`$Config.WeeklyWorkloads.IncludeMDE -eq `$true) { `$Params['IncludeMDE'] = `$true }
    if (`$Config.WeeklyWorkloads.IncludeMDI -eq `$true) { `$Params['IncludeMDI'] = `$true }
    if (`$Config.WeeklyWorkloads.IncludeMDA -eq `$true) { `$Params['IncludeMDA'] = `$true }
}

# Execute
if (-not (Test-Path `$Config.WeeklyScript -PathType Leaf)) {
    Write-Error "The main script was not found or is not a valid file: `$(`$Config.WeeklyScript). If using OneDrive, verify it is downloaded locally."
    exit 1
}
# Force OneDrive hydration

try {
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting Defender XDR Weekly Report (Auth: `$WeeklyAuth)..." -ForegroundColor Cyan
    & `$Config.WeeklyScript @Params
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Weekly report completed." -ForegroundColor Green

    # Cleanup of old reports and CSVs
    `$RetentionDays = if (`$Config.RetentionDays) { `$Config.RetentionDays } else { 90 }
    Get-ChildItem "`$OutputDir\*" -Include "*.html","*.csv" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # Cleanup of old logs
    Get-ChildItem "`$LogDir\*.log" -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Error in weekly report: `$(`$_.Exception.Message)"
    exit 1
}
finally {
    `$ClientSecretPlain = `$null
    [System.GC]::Collect()
}
"@

$WeeklyWrapperPath = "$ScriptsPath\Run-DefenderXDRWeeklyReport.ps1"
$WeeklyWrapperContent | Out-File $WeeklyWrapperPath -Encoding UTF8 -Force
Write-Ok "Weekly wrapper: $WeeklyWrapperPath"

# ============================================================
#  STEP 9: Scheduled tasks
# ============================================================

Write-Step "9/10" "Scheduled tasks (Task Scheduler)"

if ($SkipScheduledTasks) {
    Write-Skip "Task creation skipped (-SkipScheduledTasks parameter)"
}
elseif ($AuthMode -eq "Interactive") {
    Write-Fail "Scheduled tasks NOT compatible with Interactive mode (requires browser)."
    Write-Host "    Switch to Client Secret or Certificate for automation." -ForegroundColor DarkYellow
    Write-Skip "Task creation skipped automatically"
}
else {
    $CreateTasks = Read-Host "  Create scheduled tasks? [Y/n]"

    if ($CreateTasks -notin @("n", "N")) {
        $PwshExecutable = Get-PowerShell7ExecutablePath
        if (-not $PwshExecutable) {
            Write-Fail "PowerShell 7 (pwsh.exe) not found."
            Write-Host "    Install PowerShell 7 and run setup again to create scheduled tasks." -ForegroundColor DarkYellow
            Write-Skip "Task creation skipped automatically"
            $CreateTasks = "n"
        }
        else {
            Write-Ok "PowerShell 7 detected: $PwshExecutable"
        }
    }

    if ($CreateTasks -notin @("n", "N")) {

        $TaskDefs = @(
            @{
                Name    = "DefenderXDR-DailyReport"
                Script  = $DailyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Daily -At 7am }
                Desc    = "Daily security report - Defender XDR (Daily 7:00 AM) [Auth: $DailyAuthMode]"
            },
            @{
                Name    = "DefenderXDR-WeeklyReport"
                Script  = $WeeklyWrapperPath
                Trigger = { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "7:30AM" }
                Desc    = "Weekly security report - Defender XDR (Monday 7:30 AM) [Auth: $WeeklyAuthMode]"
            }
        )

        foreach ($Task in $TaskDefs) {
            try {
                $Action = New-ScheduledTaskAction -Execute $PwshExecutable `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($Task.Script)`""

                $Trigger = & $Task.Trigger

                $Settings = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 10) `
                    -StartWhenAvailable

                Register-ScheduledTask `
                    -TaskName $Task.Name `
                    -Action $Action `
                    -Trigger $Trigger `
                    -Settings $Settings `
                    -Description $Task.Desc `
                    -User "$env:USERDOMAIN\$env:USERNAME" `
                    -Force | Out-Null

                Write-Ok "Task created: $($Task.Name)"
                Write-Host "    $($Task.Desc)" -ForegroundColor DarkGray
            }
            catch {
                Write-Fail "Error creating '$($Task.Name)': $($_.Exception.Message)"
                Write-Host "    You can create it manually from Task Scheduler" -ForegroundColor DarkYellow
            }
        }
    }
    else {
        Write-Skip "Scheduled tasks skipped by user"
    }
}

# ============================================================
#  STEP 10: Execution test (optional)
# ============================================================

Write-Step "10/10" "Execution test"

if ($UseSecret -or $UseCertificate) {
    $RunTest = Read-Host "  Run a daily report test now? [y/N]"

    if ($RunTest -in @("s", "S")) {
        Write-Info "Running test with 1-hour window (minimal results)..."
        try {
            & $DailyWrapperPath
            Write-Ok "Test completed successfully"

            # Show path of generated report
            $TestReport = Get-ChildItem "$ReportsPath\Daily\*.html" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($TestReport) {
                Write-Ok "Test report: $($TestReport.FullName)"
            }
        }
        catch {
            Write-Fail "Test error: $($_.Exception.Message)"
            Write-Host "    Check configuration and permissions. Run manually:" -ForegroundColor DarkYellow
            Write-Host "    & '$DailyWrapperPath'" -ForegroundColor White
        }
    }
    else {
        Write-Skip "Execution test skipped"
    }
}
else {
    Write-Skip "Test requires Client Secret or Certificate configured"
}

# ============================================================
#  FINAL SUMMARY
# ============================================================

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  CONFIGURATION COMPLETED" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "`n  Configuration files:" -ForegroundColor Yellow
Write-Host "    Config       : $ConfigFile"
if ($UseSecret) {
    Write-Host "    Secret (DPAPI): $SecretFile  (user: $env:USERNAME)"
}
if ($UseCertificate) {
    Write-Host "    Certificate  : $CertThumbprint (CurrentUser/My or LocalMachine/My)"
    if ($Config.CertSubject) {
        Write-Host "    Subject      : $($Config.CertSubject)"
    }
    if ($Config.CertPublicPath) {
        Write-Host "    Public .cer  : $($Config.CertPublicPath)"
    }
    if ($Config.CertAutoRegistrationStatus) {
        Write-Host "    Graph        : $($Config.CertAutoRegistrationStatus)"
    }
}

Write-Host "`n  Authentication:" -ForegroundColor Yellow
Write-Host "    Daily  : $DailyAuthMode"
Write-Host "    Weekly : $WeeklyAuthMode"
if ($AuthMode -eq "Interactive") {
    Write-Host "    NOTE: Interactive mode requires an active user session" -ForegroundColor DarkYellow
}

Write-Host "`n  Report scripts:" -ForegroundColor Yellow
Write-Host "    Daily  : $ScriptsPath\New-DefenderXDRDailyReport.ps1"
Write-Host "    Weekly : $ScriptsPath\New-DefenderXDRWeeklyReport.ps1"

Write-Host "`n  Wrappers (Task Scheduler):" -ForegroundColor Yellow
Write-Host "    Daily  : $DailyWrapperPath"
Write-Host "    Weekly : $WeeklyWrapperPath"

Write-Host "`n  Reports are saved in:" -ForegroundColor Yellow
Write-Host "    Daily  : $ReportsPath\Daily\"
Write-Host "    Weekly : $ReportsPath\Weekly\"
Write-Host "    Logs   : $ReportsPath\Logs\"
Write-Host "    Retention: $($Config.RetentionDays) days (automatic cleanup)"

if ($UseCertificate -and $Config.CertPublicPath) {
    Write-Host "`n  Certificate registration in App Registration:" -ForegroundColor Yellow
    if ($Config.CertAutoRegistrationStatus -eq 'Added' -or $Config.CertAutoRegistrationStatus -eq 'AlreadyPresent') {
        Write-Host "    The certificate is already registered in Microsoft Graph for the App Registration." -ForegroundColor White
        if ($Config.AppObjectId) {
            Write-Host "    Application Object Id: $($Config.AppObjectId)" -ForegroundColor White
        }
        Write-Host "    Scheduled tasks will use thumbprint $($Config.CertThumbprint)" -ForegroundColor White
    }
    else {
        Write-Host "    1. Open Entra ID > App registrations > $ClientId" -ForegroundColor White
        Write-Host "    2. Go to Certificates & secrets > Certificates" -ForegroundColor White
        Write-Host "    3. Upload certificate: $($Config.CertPublicPath)" -ForegroundColor White
        Write-Host "    4. Wait for propagation then re-run validation if it was skipped" -ForegroundColor White
        Write-Host "    5. Scheduled tasks will use thumbprint $($Config.CertThumbprint)" -ForegroundColor White
    }
}

if ($Config.SendMail) {
    Write-Host "`n  Email configuration:" -ForegroundColor Yellow
    Write-Host "    SMTP Server : $($Config.SmtpServer)"
    Write-Host "    From        : $($Config.MailFrom)"
    Write-Host "    To          : $($Config.MailTo)"
}

Write-Host "`n  Manual test execution:" -ForegroundColor Yellow
Write-Host "    & '$DailyWrapperPath'" -ForegroundColor White
Write-Host "    & '$WeeklyWrapperPath'" -ForegroundColor White

if (-not $Config.SendMail) {
    Write-Host "`n  Add email (re-run setup or edit config.json):" -ForegroundColor Yellow
    Write-Host "    SendMail: true, SmtpServer, MailFrom, MailTo" -ForegroundColor White
}

Write-Host "`n" -NoNewline
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Setup completed.`n" -ForegroundColor Green