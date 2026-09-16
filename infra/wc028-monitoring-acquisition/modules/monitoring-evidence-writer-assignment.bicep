targetScope = 'resourceGroup'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param principalId string

@description('Custom create-only monitoring evidence role definition ID.')
param roleDefinitionId string

@description('Existing WC-024 monitoring evidence storage account name.')
param storageAccountName string

@description('Exact existing monitoring-evidence container resource ID.')
param expectedContainerResourceId string

resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: storage
  name: 'default'
}

resource monitoringEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: blobService
  name: 'monitoring-evidence'
}

var validatedContainerResourceId = toLower(
  monitoringEvidenceContainer.id
) == toLower(expectedContainerResourceId)
  ? monitoringEvidenceContainer.id
  : fail('monitoring evidence writer escaped the reviewed container')
var denyBlobListCondition = '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'

resource collectorMonitoringEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedContainerResourceId, principalId, roleDefinitionId)
  scope: monitoringEvidenceContainer
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
    condition: denyBlobListCondition
    conditionVersion: '2.0'
  }
}

output roleAssignmentResourceId string = collectorMonitoringEvidenceWriter.id
