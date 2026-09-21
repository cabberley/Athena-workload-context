targetScope = 'resourceGroup'

@description('Azure region for the isolated evidence collector identity and signing key.')
param location string = resourceGroup().location

@description('Lowercase prefix for deterministic evidence resources.')
param namePrefix string

@description('Existing monitoring-owned storage account name.')
param storageAccountName string

@description('Resource ID of the monitoring-evidence container created by monitoring-flow-log-storage.')
param monitoringEvidenceContainerResourceId string

@description('Subscription-scoped custom role definition for conditioned known-name Blob reads and add-only creation.')
param evidenceWriterRoleDefinitionId string

@description('Globally unique Key Vault name for the monitoring collector signing key.')
param keyVaultName string

@description('Resource tags applied to evidence resources.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-evidence'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var keyVaultCryptoUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')

resource collectorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${namePrefix}-monitoring-collector-id'
  location: location
  tags: union(resourceTags, {
    identityPurpose: 'isolated-signed-monitoring-evidence-collector'
  })
}

resource rbacAttestorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${namePrefix}-monitoring-rbac-attestor-id'
  location: location
  tags: union(resourceTags, {
    identityPurpose: 'isolated-effective-rbac-attestor'
  })
}

resource signingKeyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  tags: resourceTags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    publicNetworkAccess: 'Disabled'
    softDeleteRetentionInDays: 90
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
  }
}

resource signingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' = {
  parent: signingKeyVault
  name: 'monitoring-evidence-signing'
  properties: {
    kty: 'RSA'
    keySize: 3072
    keyOps: [
      'sign'
      'verify'
    ]
    attributes: {
      enabled: true
    }
  }
}

resource monitoringStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: monitoringStorage
  name: 'default'
}

resource monitoringEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: blobService
  name: 'monitoring-evidence'
}

var validatedMonitoringEvidenceContainerResourceId = toLower(monitoringEvidenceContainer.id) == toLower(monitoringEvidenceContainerResourceId)
  ? monitoringEvidenceContainer.id
  : fail('WC-024 evidence writer RBAC must bind to the monitoring-evidence container created by monitoring-flow-log-storage.')

var monitoringEvidenceWriterDataActions = [
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
]
var denyBlobListCondition = '(((!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND NOT SubOperationMatches{\'Blob.List\'})) AND !(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action\'})) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals \'monitoring-evidence\' AND (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/commits/*/manifest.json\' OR @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/commits/*/recovery.json\' OR @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/wc024-*/evidence.json\'))) AND (!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'})))'
var expectedEvidenceWriterRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  guid(
    subscription().id,
    'athena-wc028-monitoring-evidence-create-only',
    toLower(validatedMonitoringEvidenceContainerResourceId)
  )
)
var validatedEvidenceWriterRoleDefinitionId = toLower(evidenceWriterRoleDefinitionId) == toLower(expectedEvidenceWriterRoleDefinitionId)
  ? evidenceWriterRoleDefinitionId
  : fail('WC-024 evidence writer assignment must use the exact subscription-scoped create-only role.')

resource collectorEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedMonitoringEvidenceContainerResourceId, collectorIdentity.id, validatedEvidenceWriterRoleDefinitionId)
  scope: monitoringEvidenceContainer
  properties: {
    principalId: collectorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: validatedEvidenceWriterRoleDefinitionId
    condition: denyBlobListCondition
    conditionVersion: '2.0'
  }
}

resource collectorSigningKeyUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(signingKey.id, collectorIdentity.id, keyVaultCryptoUserRoleDefinitionId)
  scope: signingKey
  properties: {
    principalId: collectorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultCryptoUserRoleDefinitionId
  }
}

output collectorIdentityResourceId string = collectorIdentity.id
output collectorIdentityClientId string = collectorIdentity.properties.clientId
output collectorIdentityPrincipalId string = collectorIdentity.properties.principalId
output collectorIdentityTenantId string = collectorIdentity.properties.tenantId
output rbacAttestorIdentityResourceId string = rbacAttestorIdentity.id
output rbacAttestorIdentityClientId string = rbacAttestorIdentity.properties.clientId
output rbacAttestorIdentityPrincipalId string = rbacAttestorIdentity.properties.principalId
output rbacAttestorIdentityTenantId string = rbacAttestorIdentity.properties.tenantId
output keyVaultResourceId string = signingKeyVault.id
output signingKeyArmResourceId string = signingKey.id
output signingKeyResourceId string = signingKey.properties.keyUriWithVersion
output signingKeyCryptoUserRoleDefinitionId string = keyVaultCryptoUserRoleDefinitionId
output evidenceContainerResourceId string = validatedMonitoringEvidenceContainerResourceId
output evidenceWriterRoleDefinitionId string = validatedEvidenceWriterRoleDefinitionId
output evidenceWriterRoleName string = 'Athena WC028 Monitoring Evidence Create-Only Writer'
output evidenceWriterAllowedDataActions array = monitoringEvidenceWriterDataActions
output evidenceWriterAssignmentCondition string = denyBlobListCondition
output evidenceWriterAssignmentConditionVersion string = '2.0'
