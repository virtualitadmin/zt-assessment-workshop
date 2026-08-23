<#
.SYNOPSIS
    Hybrid Worker VM preparation for the Zero Trust Assessment.
    Run by the Azure Custom Script Extension (as SYSTEM) at deploy time.
    Installs: PowerShell 7 (latest LTS), Visual C++ Redistributable x64,
    and all required PowerShell modules machine-wide.
    Idempotent - safe to re-run.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Allow TLS 1.2 and (where supported) TLS 1.3
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
$Log = 'C:\Windows\Temp\zt-vm-setup.log'
Start-Transcript -Path $Log -Append

function Get-FileWithRetry {
    param([string]$Uri, [string]$OutFile, [int]$Attempts = 5)
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Write-Output "Downloading ($i/$Attempts): $Uri"
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
            if ((Get-Item $OutFile).Length -gt 0) { return }
            throw 'Downloaded file is empty.'
        }
        catch {
            Write-Output "  Attempt $i failed: $($_.Exception.Message)"
            # Fallback method on the later attempts
            if ($i -ge 3) {
                try {
                    Write-Output '  Retrying with WebClient...'
                    (New-Object System.Net.WebClient).DownloadFile($Uri, $OutFile)
                    if ((Get-Item $OutFile -ErrorAction SilentlyContinue).Length -gt 0) { return }
                }
                catch { Write-Output "  WebClient also failed: $($_.Exception.Message)" }
            }
            if ($i -eq $Attempts) { throw "Failed to download $Uri after $Attempts attempts." }
            Start-Sleep -Seconds (10 * $i)
        }
    }
}

# ---------------------------------------------------------------------------
# 1. PowerShell 7 (MSI, machine-wide)
# ---------------------------------------------------------------------------
if (-not (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe')) {
    Write-Output 'Installing PowerShell 7...'
    $Msi = 'C:\Windows\Temp\pwsh7.msi'
    # Pinned version (fewer redirects than /latest/, deterministic installs).
    # Update the version here when a new LTS is adopted.
    Get-FileWithRetry -Uri 'https://ztstaging11106.blob.core.windows.net/installers/PowerShell-7.4.6-win-x64.msi?se=2026-09-22T16%3A41Z&sp=r&sv=2026-04-06&sr=b&sig=VXZBSrELlSJ5%2FGQRzNrwQi%2FBr3dMsZoDgAZQPV2i9fk%3D' -OutFile $Msi
    Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart ADD_PATH=1" -Wait
    Remove-Item $Msi -Force
} else { Write-Output 'PowerShell 7 already installed.' }

# ---------------------------------------------------------------------------
# 2. Visual C++ Redistributable x64 (required by the assessment engine)
# ---------------------------------------------------------------------------
$VcInstalled = Test-Path 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
if (-not $VcInstalled) {
    Write-Output 'Installing Visual C++ Redistributable...'
    $Vc = 'C:\Windows\Temp\vc_redist.x64.exe'
    Get-FileWithRetry -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -OutFile $Vc
    Start-Process $Vc -ArgumentList '/install /quiet /norestart' -Wait
    Remove-Item $Vc -Force
} else { Write-Output 'VC++ Redistributable already installed.' }

# ---------------------------------------------------------------------------
# 3. PowerShell 7 modules (machine-wide)
# ---------------------------------------------------------------------------
$Ps7Modules = @(
    'PSFramework'
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Beta.Teams'
    'Az.Accounts'
    'Az.Storage'
    'ExchangeOnlineManagement'
    'ZeroTrustAssessment'
)
$Ps7Script = @"
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
foreach (`$m in '$($Ps7Modules -join "','")') {
    if (-not (Get-Module -ListAvailable `$m)) {
        Write-Output "Installing `$m (PS7)..."
        Install-Module `$m -Scope AllUsers -Force -AllowClobber
    } else { Write-Output "`$m already present (PS7)." }
}
"@
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -ExecutionPolicy Bypass -Command $Ps7Script
if ($LASTEXITCODE -ne 0) { throw "PS7 module installation failed - see $Log" }

# ---------------------------------------------------------------------------
# 4. Windows PowerShell 5.1-only modules (SharePoint Online, AIP)
# ---------------------------------------------------------------------------
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
foreach ($m in 'Microsoft.Online.SharePoint.PowerShell', 'AIPService') {
    if (-not (Get-Module -ListAvailable $m)) {
        Write-Output "Installing $m (WinPS 5.1)..."
        Install-Module $m -Scope AllUsers -Force -AllowClobber
    } else { Write-Output "$m already present (WinPS 5.1)." }
}

Write-Output 'VM preparation complete.'
Stop-Transcript
