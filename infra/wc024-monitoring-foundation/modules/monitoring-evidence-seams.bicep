targetScope = 'resourceGroup'

@description('Azure region for the isolated evidence collector identity and signing key.')
param location string = resourceGroup().location

@description('Lowercase prefix for deterministic evidence resources.')
param namePrefix string

@description('Existing monitoring-owned storage account name.')
param storageAccountName string

@description('Resource ID of the monitoring-evidence container created by monitoring-flow-log-storage.')
param monitoringEvidenceContainerResourceId string

@description('Globally unique Key Vault name for the monitoring collector signing key.')
param keyVaultName string

@description('Resource tags applied to evidence resources.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-evidence'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var storageBlobDataContributorRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var keyVaultCryptoUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')

resource collectorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${namePrefix}-monitoring-collector-id'
  location: location
  tags: union(resourceTags, {
    identityPurpose: 'isolated-signed-monitoring-evidence-collector'
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

resource collectorEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedMonitoringEvidenceContainerResourceId, collectorIdentity.id, storageBlobDataContributorRoleDefinitionId)
  scope: monitoringEvidenceContainer
  properties: {
    principalId: collectorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRoleDefinitionId
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
output keyVaultResourceId string = signingKeyVault.id
output signingKeyResourceId string = signingKey.properties.keyUriWithVersion
