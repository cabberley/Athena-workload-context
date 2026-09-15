targetScope = 'resourceGroup'

@description('Existing private Storage account name.')
param storageAccountName string

@description('Private Blob container name to create or reconcile.')
param containerName string

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

output name string = container.name
output resourceId string = container.id
output versioningEnabled bool = blobService.properties.isVersioningEnabled == true
  ? true
  : fail('WC-027 guidance-authority storage Blob versioning must be enabled')
