<#
.SYNOPSIS
    Zero Trust Assessment - Azure Automation Runbook (PowerShell 7.2 runtime)
    Fully unattended: certificate-based app-only authentication via
    Connect-ZtAssessment, report uploaded to Azure Blob Storage.

.NOTES
    Required modules in the Automation Account (runtime 7.2):
        - Microsoft.Graph.Authentication
        - Az.Accounts
        - Az.Storage
        - ZeroTrustAssessment
      (For -Services 'All' on a Hybrid Worker, also: ExchangeOnlineManagement,
       Microsoft.Online.SharePoint.PowerShell, AIPService)

    Required Automation variables (Shared Resources > Variables):
        - ZT-TenantId               (plain)
        - ZT-ClientId               (plain)
        - ZT-StorageAccountName     (plain)
        - ZT-KeyVaultName           (plain, OPTIONAL - enables Key Vault mode)
        - ZT-CertificateName        (plain, OPTIONAL - defaults to ZT-AppCert)

    Certificate source (one of):
        - Key Vault mode (preferred / Bicep deployment): certificate generated
          and stored in Key Vault; the worker VM's managed identity needs the
          "Key Vault Secrets User" role on the vault. No PFX files anywhere.
        - Classic mode: ZT-AppCert Automation certificate asset (the .pfx
          uploaded with Exportable = Yes; matching .cer on the app registration).

    Roles/permissions:
        - App registration: Graph application permissions with admin consent
        - For ExchangeOnline: "Office 365 Exchange Online > Exchange.ManageAsApp"
          application permission (admin consented) AND the Global Reader
          directory role assigned to the service principal
        - Service principal: Reader on subscriptions (for Azure checks) and
          "Storage Blob Data Contributor" on the storage account
#>

param(
    [string]$ContainerName = "ztassessment",

    # Default set for a Hybrid Worker with Exchange enabled (requires the
    # Office 365 Exchange Online > Exchange.ManageAsApp application permission
    # and the Global Reader directory role on the service principal).
    # Use 'All' to also attempt Security & Compliance, SharePoint and AIP.
    [ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePointOnline')]
    [string[]]$Services = @('Graph', 'Azure', 'ExchangeOnline')
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1. Read configuration from Automation account assets
# ---------------------------------------------------------------------------
$TenantId           = Get-AutomationVariable -Name 'ZT-TenantId'
$ClientId           = Get-AutomationVariable -Name 'ZT-ClientId'
$StorageAccountName = Get-AutomationVariable -Name 'ZT-StorageAccountName'

# Optional Key Vault settings (present in the Bicep-deployed design)
$KeyVaultName = $null
try { $KeyVaultName = Get-AutomationVariable -Name 'ZT-KeyVaultName' } catch { }
$CertificateName = 'ZT-AppCert'
try { $CertificateName = Get-AutomationVariable -Name 'ZT-CertificateName' } catch { }

# ---------------------------------------------------------------------------
# 2. Acquire the authentication certificate
#    Preferred: fetch from Key Vault using the worker VM's MANAGED IDENTITY
#    (the VM identity holds "Key Vault Secrets User" on the vault; the
#    certificate+private key comes back via the secret endpoint as base64 PFX).
#    Fallback: the classic ZT-AppCert Automation certificate asset.
# ---------------------------------------------------------------------------
if ($KeyVaultName) {
    Write-Output "Fetching certificate '$CertificateName' from Key Vault '$KeyVaultName' (VM managed identity)..."
    Connect-AzAccount -Identity | Out-Null
    $PfxBase64 = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -AsPlainText
    if (-not $PfxBase64) { throw "Certificate '$CertificateName' not found in Key Vault '$KeyVaultName'." }
    $PfxBytes = [System.Convert]::FromBase64String($PfxBase64)
    $PfxBase64 = $null
    # Drop the managed-identity context so later Az calls run as the app's
    # service principal, not the VM.
    Disconnect-AzAccount | Out-Null
    $TempPwd = ''   # Key Vault-exported PFX has no password
}
else {
    Write-Output "Loading certificate from Automation account asset 'ZT-AppCert'..."
    $RawCert = Get-AutomationCertificate -Name 'ZT-AppCert'
    if (-not $RawCert.HasPrivateKey) {
        throw "Certificate 'ZT-AppCert' has no private key. Re-upload the PFX and set Exportable = Yes."
    }
    # Round-trip through PFX bytes so the key can be re-imported persisted.
    $TempPwd  = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $PfxBytes = $RawCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $TempPwd)
}

# Import with a persisted user keyset. Without PersistKeySet the private key
# is ephemeral and signing fails later with "Keyset does not exist";
# UserKeySet/CurrentUser is used because the job account may lack rights to
# the LocalMachine store.
$KeyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

$Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxBytes, $TempPwd, $KeyFlags)
$PfxBytes = $null
$TempPwd  = $null

# Purge any stale copies of this certificate left by previous runs (e.g. a
# keyless copy from a failed job). The module's Azure leg looks the cert up
# by THUMBPRINT, so a broken leftover in either store breaks authentication.
foreach ($Location in 'CurrentUser', 'LocalMachine') {
    try {
        $CleanupStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $Location)
        $CleanupStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $Stale = $CleanupStore.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        foreach ($s in $Stale) {
            $CleanupStore.Remove($s)
            Write-Output "Removed stale certificate copy from $Location\My."
        }
        $CleanupStore.Close()
    }
    catch {
        Write-Output "Note: could not clean $Location\My ($($_.Exception.Message)) - continuing."
    }
}

$Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$Store.Add($Cert)
$Store.Close()
Write-Output "Certificate installed (CurrentUser\My, persisted key). Thumbprint: $($Cert.Thumbprint)"

# ---------------------------------------------------------------------------
# 3. Working folder inside the runbook sandbox
# ---------------------------------------------------------------------------
$ReportPath = Join-Path $env:TEMP "ZTAssessment"
New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null

# ---------------------------------------------------------------------------
# 4. Connect all services non-interactively (certificate-based app-only auth)
#    Connect-ZtAssessment handles Graph, Azure, and any other requested
#    services itself - no separate Connect-MgGraph/Connect-AzAccount needed.
# ---------------------------------------------------------------------------
Write-Output "Connecting via Connect-ZtAssessment (app-only CBA). Services: $($Services -join ', ')"
Connect-ZtAssessment `
    -ClientId  $ClientId `
    -TenantId  $TenantId `
    -Certificate $Cert `
    -Service   $Services *>&1 | ForEach-Object { Write-Output ($_ | Out-String).TrimEnd() }

# ---------------------------------------------------------------------------
# 5. Run the assessment
# ---------------------------------------------------------------------------
Write-Output "Starting Zero Trust Assessment. Output path: $ReportPath"
try {
    Invoke-ZtAssessment -Path $ReportPath *>&1 | ForEach-Object { Write-Output ($_ | Out-String).TrimEnd() }
}
catch {
    Write-Output "Invoke-ZtAssessment threw a terminating error:"
    Write-Output ($_ | Out-String)
    Write-Output ($_.ScriptStackTrace | Out-String)
}
Write-Output "Assessment finished. Verifying output..."

$ReportFiles = Get-ChildItem -Path $ReportPath -Recurse -File -ErrorAction SilentlyContinue
Write-Output "Files produced: $(@($ReportFiles).Count)"
$ReportFiles | Select-Object -First 20 | ForEach-Object { Write-Output "  $($_.FullName) ($([math]::Round($_.Length/1KB)) KB)" }

if (-not $ReportFiles) {
    throw "The assessment produced no output files in '$ReportPath'. Check the job's All Logs / Errors streams for Invoke-ZtAssessment errors (permissions, connection, or module issues)."
}

# ---------------------------------------------------------------------------
# 6. Zip the report folder and upload to Blob Storage
# ---------------------------------------------------------------------------
$Stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$ZipName = "ZTAssessment_$Stamp.zip"
$ZipPath = Join-Path $env:TEMP $ZipName

Compress-Archive -Path $ReportPath -DestinationPath $ZipPath -Force
if (-not (Test-Path $ZipPath)) {
    throw "Zip file was not created at '$ZipPath'."
}
Write-Output "Report zipped: $ZipPath ($([math]::Round((Get-Item $ZipPath).Length/1KB)) KB)"

# Ensure an Azure session exists for the upload. Connect-ZtAssessment treats
# an Azure connection failure as NON-fatal (it warns and skips the Azure
# tests), so never assume the session is there - connect explicitly if not.
if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Write-Output "No Azure context found - connecting explicitly for the blob upload..."
    Connect-AzAccount -ServicePrincipal `
        -Tenant $TenantId `
        -ApplicationId $ClientId `
        -CertificateThumbprint $Cert.Thumbprint | Out-Null
}

# OAuth-based storage context - requires "Storage Blob Data Contributor"
# for the service principal on the storage account.
$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount

if (-not (Get-AzStorageContainer -Name $ContainerName -Context $Context -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $ContainerName -Context $Context -Permission Off | Out-Null
    Write-Output "Created container: $ContainerName"
}

Set-AzStorageBlobContent -File $ZipPath -Container $ContainerName -Blob $ZipName -Context $Context -Force | Out-Null
Write-Output "Uploaded $ZipName to container '$ContainerName' in storage account '$StorageAccountName'."

# Also upload the HTML report on its own so it can be viewed directly
$HtmlReport = Get-ChildItem -Path $ReportPath -Filter "ZeroTrustAssessmentReport.html" -Recurse | Select-Object -First 1
if ($HtmlReport) {
    Set-AzStorageBlobContent -File $HtmlReport.FullName -Container $ContainerName `
        -Blob "ZTAssessment_$Stamp.html" -Context $Context `
        -Properties @{ ContentType = "text/html" } -Force | Out-Null
    Write-Output "Uploaded standalone HTML report."
}

# ---------------------------------------------------------------------------
# 7. Clean up: remove local report files (the Hybrid Worker disk persists
#    between jobs and the export contains sensitive tenant data) and the
#    certificate from the store
# ---------------------------------------------------------------------------
try {
    Remove-Item -Path $ReportPath -Recurse -Force -ErrorAction Stop
    Remove-Item -Path $ZipPath -Force -ErrorAction Stop
    Write-Output "Local report files and zip deleted."
}
catch {
    Write-Warning "Could not delete local report files: $($_.Exception.Message)"
}

try {
    $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $Store.Remove($Cert)
    $Store.Close()
    Write-Output "Certificate removed from store."
}
catch {
    Write-Warning "Could not remove certificate from store: $($_.Exception.Message)"
}

Write-Output "Runbook finished successfully."
