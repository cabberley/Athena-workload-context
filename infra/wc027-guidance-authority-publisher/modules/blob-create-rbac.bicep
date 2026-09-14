targetScope = 'resourceGroup'

param storageAccountName string
param containerName string
param identityResourceId string

resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: storage
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource creatorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(container.id, 'athena-wc027-immutable-blob-creator')
  properties: {
    roleName: 'Athena WC027 Immutable Blob Creator (${storageAccountName}/${containerName})'
    description: 'Create new immutable guidance authority blobs only. No read, list, overwrite, tags, move, delete, or privileged immutability operations.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource creator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, identity.id, creatorRole.id)
  scope: container
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: creatorRole.id
  }
}

output roleDefinitionResourceId string = creatorRole.id
output roleAssignmentResourceId string = creator.id
