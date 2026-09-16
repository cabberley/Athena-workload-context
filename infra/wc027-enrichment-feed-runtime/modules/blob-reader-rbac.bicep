targetScope = 'resourceGroup'

@description('Existing storage account name.')
param storageAccountName string

@description('Existing private Blob container name.')
param containerName string

@description('Exact user-assigned identity resource ID receiving bounded Blob read access.')
param identityResourceId string

var storageBlobDataReaderRoleDefinitionId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: blobService
  name: containerName
}

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, identityResourceId, storageBlobDataReaderRoleDefinitionId)
  scope: container
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
    conditionVersion: '2.0'
    condition: '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'
  }
}

output roleAssignmentResourceId string = reader.id
output containerResourceId string = container.id
