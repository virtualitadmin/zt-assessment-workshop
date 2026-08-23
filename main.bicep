// ===========================================================================
// Zero Trust Assessment - automated deployment (resource group scope)
// Provisions: storage (+container +retention), Automation account
// (+variables +certificate +runbook +schedule), Hybrid Worker VM
// (+networking +software install +worker registration), storage RBAC.
//
// NOT covered (Entra control plane - see bootstrap script / guide):
//   - App registration, Graph/Exchange/AIP permissions, admin consent,
//     directory roles (Global Reader etc.)
//   - Reader role on subscriptions (subscription scope - one CLI command,
//     see deployment notes)
// ===========================================================================

@description('Prefix for resource names (lowercase letters/numbers, 3-11 chars).')
@minLength(3)
@maxLength(11)
param baseName string = 'ztassess'

param location string = resourceGroup().location

// ---- Identity / app registration (created beforehand by bootstrap) --------
@description('Entra tenant ID.')
param tenantId string = tenant().tenantId

@description('Application (client) ID of the assessment app registration.')
param appClientId string

@description('Object ID of the app registration\'s SERVICE PRINCIPAL (not the app object). Used for the storage RBAC assignment.')
param servicePrincipalObjectId string

// ---- Certificate (generated in Key Vault at deploy time) ------------------
@description('Name of the authentication certificate inside Key Vault.')
param certificateName string = 'ZT-AppCert'

@description('Certificate subject.')
param certificateSubject string = 'CN=ZeroTrustAssessment'

@description('Certificate validity in months.')
param certificateValidityMonths int = 24

// ---- Runbook / VM software sources ---------------------------------------
@description('Publicly reachable URI of ztassessment-runbook-cert.ps1 (raw file).')
param runbookContentUri string

@description('Publicly reachable URI of vm-setup.ps1 (raw file) run by the VM extension to install PowerShell 7 + modules.')
param vmSetupScriptUri string

// ---- Assessment settings --------------------------------------------------
@description('Blob container for reports.')
param containerName string = 'ztassessment'

@description('Days to keep report blobs before lifecycle deletion. 0 disables the rule.')
param reportRetentionDays int = 90

@description('Services parameter passed to scheduled runs.')
param services array = ['Graph', 'Azure', 'ExchangeOnline']

@description('First scheduled run (ISO 8601, must be > 5 min in the future), e.g. 2026-09-01T02:00:00+00:00')
param scheduleStartTime string

@description('Interval in months between scheduled runs.')
param scheduleIntervalMonths int = 1

// ---- VM settings -----------------------------------------------------------
param vmSize string = 'Standard_D4s_v5'
param vmAdminUsername string
@secure()
param vmAdminPassword string
param vnetAddressPrefix string = '10.60.0.0/24'

// ===========================================================================
var storageName = toLower('${baseName}${uniqueString(resourceGroup().id)}')
var automationName = '${baseName}-aa'
var vmName = '${baseName}-hw01'
var workerGroupName = '${baseName}-workers'
var runbookName = 'ZeroTrustAssessment'

// ---------------------------------------------------------------------------
// Storage account + container + lifecycle retention
// ---------------------------------------------------------------------------
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take(storageName, 24)
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: { publicAccess: 'None' }
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = if (reportRetentionDays > 0) {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'zt-report-retention'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: ['blockBlob'], prefixMatch: ['${containerName}/'] }
            actions: { baseBlob: { delete: { daysAfterModificationGreaterThan: reportRetentionDays } } }
          }
        }
      ]
    }
  }
}

// Storage Blob Data Contributor for the assessment service principal
resource storageRbac 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, servicePrincipalObjectId, 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  scope: storage
  properties: {
    principalId: servicePrincipalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}

// ---------------------------------------------------------------------------
// Key Vault + certificate generation (replaces manual PFX handling entirely)
// ---------------------------------------------------------------------------
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('${baseName}-kv-${uniqueString(resourceGroup().id)}', 24)
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 30
  }
}

// Identity used only by the deployment script that creates the certificate
resource deployIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-deploy-id'
  location: location
}

// Key Vault Certificates Officer for the deployment identity (create the cert)
resource kvCertOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, deployIdentity.id, 'a4417e6f-fecd-4de8-b567-7b0420556985')
  scope: keyVault
  properties: {
    principalId: deployIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a4417e6f-fecd-4de8-b567-7b0420556985')
  }
}

// Key Vault Secrets User for the worker VM's managed identity (fetch the
// certificate WITH private key at runbook runtime via the secret endpoint)
resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, vm.id, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    principalId: vm.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

// Generates the self-signed certificate inside Key Vault (idempotent) and
// returns the PUBLIC portion (base64 .cer) for the app registration upload.
resource certScript 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: '${baseName}-create-cert'
  location: location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${deployIdentity.id}': {} }
  }
  properties: {
    azPowerShellVersion: '11.0'
    retentionInterval: 'PT1H'
    timeout: 'PT15M'
    arguments: '-VaultName ${keyVault.name} -CertName ${certificateName} -Subject "${certificateSubject}" -ValidityMonths ${certificateValidityMonths}'
    scriptContent: '''
      param($VaultName, $CertName, $Subject, $ValidityMonths)
      $existing = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -ErrorAction SilentlyContinue
      if (-not $existing) {
        $policy = New-AzKeyVaultCertificatePolicy `
          -SecretContentType 'application/x-pkcs12' `
          -SubjectName $Subject `
          -IssuerName 'Self' `
          -ValidityInMonths $ValidityMonths `
          -KeyType 'RSA' -KeySize 2048 `
          -KeyUsage DigitalSignature -Ekus '1.3.6.1.5.5.7.3.2'
        Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $policy | Out-Null
        do {
          Start-Sleep -Seconds 5
          $op = Get-AzKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName
        } while ($op.Status -eq 'inProgress')
        if ($op.Status -ne 'completed') { throw "Certificate creation failed: $($op.Status) $($op.ErrorMessage)" }
        $existing = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName
      }
      $cerBytes = $existing.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      $DeploymentScriptOutputs = @{
        thumbprint = $existing.Certificate.Thumbprint
        cerBase64  = [Convert]::ToBase64String($cerBytes)
      }
    '''
  }
  dependsOn: [kvCertOfficer]
}

// ---------------------------------------------------------------------------
// Automation account: variables, certificate, runbook, schedule
// ---------------------------------------------------------------------------
resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    sku: { name: 'Basic' }
    publicNetworkAccess: true
  }
}

resource varTenant 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'ZT-TenantId'
  properties: { value: '"${tenantId}"', isEncrypted: false }
}

resource varClient 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'ZT-ClientId'
  properties: { value: '"${appClientId}"', isEncrypted: false }
}

resource varStorage 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'ZT-StorageAccountName'
  properties: { value: '"${storage.name}"', isEncrypted: false }
}

resource varKeyVault 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'ZT-KeyVaultName'
  properties: { value: '"${keyVault.name}"', isEncrypted: false }
}

resource varCertName 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'ZT-CertificateName'
  properties: { value: '"${certificateName}"', isEncrypted: false }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
  parent: automation
  name: runbookName
  location: location
  properties: {
    runbookType: 'PowerShell72'
    logProgress: false
    logVerbose: false
    description: 'Unattended Zero Trust Assessment with blob delivery'
    publishContentLink: { uri: runbookContentUri }
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: 'ZT-Monthly'
  properties: {
    startTime: scheduleStartTime
    frequency: 'Month'
    interval: scheduleIntervalMonths
    timeZone: 'UTC'
  }
}

resource jobSchedule 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {
  parent: automation
  name: guid(automation.id, runbookName, 'ZT-Monthly')
  properties: {
    runbook: { name: runbook.name }
    schedule: { name: schedule.name }
    runOn: workerGroupName
    parameters: {
      ContainerName: containerName
      Services: string(services)
    }
  }
  dependsOn: [worker]
}

// ---------------------------------------------------------------------------
// Networking + Hybrid Worker VM
// ---------------------------------------------------------------------------
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${baseName}-nsg'
  location: location
  properties: {
    securityRules: [] // outbound HTTPS is allowed by default; no inbound required
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${baseName}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressPrefix] }
    subnets: [
      {
        name: 'workers'
        properties: {
          addressPrefix: vnetAddressPrefix
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: vmName
      adminUsername: vmAdminUsername
      adminPassword: vmAdminPassword
      windowsConfiguration: { enableAutomaticUpdates: true, patchSettings: { patchMode: 'AutomaticByOS' } }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 128
        managedDisk: { storageAccountType: 'Premium_LRS' }
      }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id }] }
  }
}

// Software install: PowerShell 7, VC++ redist, all assessment modules
resource vmSetup 'Microsoft.Compute/virtualMachines/extensions@2024-03-01' = {
  parent: vm
  name: 'SetupAssessmentPrereqs'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    settings: { fileUris: [vmSetupScriptUri] }
    protectedSettings: {
      commandToExecute: 'powershell -ExecutionPolicy Bypass -File vm-setup.ps1'
    }
  }
}

// ---------------------------------------------------------------------------
// Hybrid Worker group + registration
// ---------------------------------------------------------------------------
resource workerGroup 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups@2023-11-01' = {
  parent: automation
  name: workerGroupName
}

resource worker 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/hybridRunbookWorkers@2023-11-01' = {
  parent: workerGroup
  name: guid(vm.id)
  properties: { vmResourceId: vm.id }
}

resource workerExtension 'Microsoft.Compute/virtualMachines/extensions@2024-03-01' = {
  parent: vm
  name: 'HybridWorkerExtension'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Automation.HybridWorker'
    type: 'HybridWorkerForWindows'
    typeHandlerVersion: '1.1'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {
      AutomationAccountURL: automation.properties.automationHybridServiceUrl
    }
  }
  dependsOn: [worker, vmSetup]
}

// ---------------------------------------------------------------------------
output storageAccountName string = storage.name
output automationAccountName string = automation.name
output hybridWorkerGroup string = workerGroupName
output vmNameOut string = vmName
output keyVaultName string = keyVault.name
output certificateThumbprint string = certScript.properties.outputs.thumbprint
output certificateCerBase64 string = certScript.properties.outputs.cerBase64
output postDeploymentSteps string = '1) Upload the certificate PUBLIC key to the app registration: save certificateCerBase64 as ZTAssessment.cer ([IO.File]::WriteAllBytes(...,[Convert]::FromBase64String(<value>))) and upload under Certificates & secrets, or let the bootstrap script do it via Graph. 2) Assign Reader at subscription scope: az role assignment create --assignee ${servicePrincipalObjectId} --role Reader --scope /subscriptions/<subId>. 3) Entra permissions via Add-ZtAppPermissions.ps1 if not already done.'
