targetScope = 'resourceGroup'

@description('Existing private evidence Storage account name.')
param storageAccountName string

@description('Dedicated container for non-authoritative change-delivery failure receipts.')
param containerName string

resource evidenceStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource evidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: evidenceStorageAccount
  name: 'default'
}

resource failureReceiptContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  parent: evidenceBlobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

output containerResourceId string = failureReceiptContainer.id
