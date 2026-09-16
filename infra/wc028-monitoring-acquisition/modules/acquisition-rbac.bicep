targetScope = 'subscription'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param collectorPrincipalId string

@description('Principal ID of the separate WC-028 runtime-support identity.')
param runtimeSupportPrincipalId string

@description('Existing WC-024 monitoring evidence storage account resource ID.')
param monitoringEvidenceStorageAccountResourceId string

@description('Existing WC-024 monitoring evidence container resource ID.')
param monitoringEvidenceContainerResourceId string

@description('Validated WC-024 storage-readiness digest that gates evidence writer RBAC.')
param monitoringEvidenceStorageReadinessDigest string

@description('Exact monitoring-intent signing key resource ID whose public key may be read.')
param monitoringIntentSigningKeyResourceId string

var subscriptionPrefix = toLower('/subscriptions/${subscription().subscriptionId}/')
var evidenceStorageSegments = split(toLower(monitoringEvidenceStorageAccountResourceId), '/')
var evidenceStorageResourceGroupName = length(evidenceStorageSegments) == 9 && startsWith(
  toLower(monitoringEvidenceStorageAccountResourceId),
  '${subscriptionPrefix}resourcegroups/'
) && evidenceStorageSegments[5] == 'providers' && evidenceStorageSegments[6] == 'microsoft.storage' && evidenceStorageSegments[7] == 'storageaccounts' && !empty(evidenceStorageSegments[8])
  ? evidenceStorageSegments[4]
  : fail('monitoringEvidenceStorageAccountResourceId must be one storage account in the deployment subscription')
var evidenceStorageAccountName = evidenceStorageSegments[8]
var intentKeySegments = split(toLower(monitoringIntentSigningKeyResourceId), '/')
var intentKeyResourceGroupName = length(intentKeySegments) == 11 && startsWith(
  toLower(monitoringIntentSigningKeyResourceId),
  '${subscriptionPrefix}resourcegroups/'
) && intentKeySegments[5] == 'providers' && intentKeySegments[6] == 'microsoft.keyvault' && intentKeySegments[7] == 'vaults' && intentKeySegments[9] == 'keys' && !empty(intentKeySegments[8]) && !empty(intentKeySegments[10])
  ? intentKeySegments[4]
  : fail('monitoringIntentSigningKeyResourceId must be one exact Key Vault key in the deployment subscription')
var intentKeyVaultName = intentKeySegments[8]
var intentKeyName = intentKeySegments[10]

resource evidenceStorageResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: evidenceStorageResourceGroupName
}

resource intentKeyResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: intentKeyResourceGroupName
}

resource monitoringEvidenceStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: evidenceStorageAccountName
  scope: evidenceStorageResourceGroup
}

resource monitoringEvidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: monitoringEvidenceStorage
  name: 'default'
}

resource monitoringEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: monitoringEvidenceBlobService
  name: 'monitoring-evidence'
}

resource intentKeyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: intentKeyVaultName
  scope: intentKeyResourceGroup
}

resource monitoringIntentSigningKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: intentKeyVault
  name: intentKeyName
}

var validatedMonitoringEvidenceContainerResourceId = toLower(
  monitoringEvidenceStorage.id
) == toLower(monitoringEvidenceStorageAccountResourceId) && toLower(
  monitoringEvidenceContainer.id
) == toLower(monitoringEvidenceContainerResourceId)
  ? monitoringEvidenceContainer.id
  : fail('monitoring evidence storage bindings must resolve to the exact WC-024 container')
var validatedMonitoringIntentSigningKeyResourceId = toLower(
  monitoringIntentSigningKey.id
) == toLower(monitoringIntentSigningKeyResourceId)
  ? monitoringIntentSigningKey.id
  : fail('monitoring intent key binding does not resolve to the reviewed Key Vault key')

resource monitoringEvidenceCreateOnlyRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-monitoring-evidence-create-only',
    toLower(validatedMonitoringEvidenceContainerResourceId)
  )
  properties: {
    roleName: 'Athena WC028 Monitoring Evidence Create-Only Writer'
    description: 'Read exact known monitoring evidence Blobs and create new Blobs without overwrite, list, or delete permission.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
        ]
        notDataActions: []
      }
    ]
    assignableScopes: [
      evidenceStorageResourceGroup.id
    ]
  }
}

resource monitoringIntentKeyReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-monitoring-intent-key-reader',
    toLower(monitoringIntentSigningKeyResourceId)
  )
  properties: {
    roleName: 'Athena WC028 Monitoring Intent Key Reader'
    description: 'Read only the public material and properties of the exact monitoring-intent signing key.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
        ]
        notDataActions: []
      }
    ]
    assignableScopes: [
      intentKeyResourceGroup.id
    ]
  }
}

module collectorMonitoringEvidenceWriter 'monitoring-evidence-writer-assignment.bicep' = {
  name: 'wc028-monitoring-evidence-writer-${substring(replace(monitoringEvidenceStorageReadinessDigest, 'sha256:', ''), 0, 8)}'
  scope: evidenceStorageResourceGroup
  params: {
    principalId: collectorPrincipalId
    roleDefinitionId: monitoringEvidenceCreateOnlyRole.id
    storageAccountName: monitoringEvidenceStorage.name
    expectedContainerResourceId: validatedMonitoringEvidenceContainerResourceId
  }
}

module runtimeSupportMonitoringIntentKeyReader 'key-reader-assignment.bicep' = {
  name: 'wc028-monitoring-intent-key-reader-assignment'
  scope: intentKeyResourceGroup
  params: {
    principalId: runtimeSupportPrincipalId
    roleDefinitionId: monitoringIntentKeyReaderRole.id
    vaultName: intentKeyVault.name
    keyName: monitoringIntentSigningKey.name
    expectedKeyResourceId: validatedMonitoringIntentSigningKeyResourceId
  }
}

output monitoringEvidenceCreateOnlyRoleDefinitionId string = monitoringEvidenceCreateOnlyRole.id
output monitoringIntentKeyReaderRoleDefinitionId string = monitoringIntentKeyReaderRole.id
