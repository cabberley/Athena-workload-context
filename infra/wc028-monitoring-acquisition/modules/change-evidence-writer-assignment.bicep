targetScope = 'resourceGroup'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param principalId string

@description('Subscription-level custom role permitting only known-Blob read and create-only write attempts.')
param roleDefinitionId string

@description('Existing WC-025 change-evidence storage account name.')
param storageAccountName string

@description('Exact existing WC-025 change-evidence container resource ID.')
param expectedContainerResourceId string

resource changeEvidenceStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource changeEvidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: changeEvidenceStorage
  name: 'default'
}

resource changeEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: changeEvidenceBlobService
  name: 'change-evidence'
}

var validatedContainerResourceId = toLower(changeEvidenceContainer.id) == toLower(
  expectedContainerResourceId
)
  ? changeEvidenceContainer.id
  : fail('change evidence writer assignment escaped the WC-025 container')

resource collectorChangeEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedContainerResourceId, principalId, roleDefinitionId)
  scope: changeEvidenceContainer
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output roleAssignmentResourceId string = collectorChangeEvidenceWriter.id
