targetScope = 'resourceGroup'

param storageAccountName string
param expectedStorageAccountResourceId string
param runtimeSupportIdentityResourceId string
param runtimeSupportPrincipalId string
param roleDefinitionId string

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

var validatedStorageAccountResourceId = toLower(storageAccount.id) == toLower(expectedStorageAccountResourceId)
  ? storageAccount.id
  : fail('storage readback assignment escaped the reviewed storage account')

resource storageReadbackAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    toLower(validatedStorageAccountResourceId),
    toLower(runtimeSupportIdentityResourceId),
    toLower(roleDefinitionId)
  )
  scope: storageAccount
  properties: {
    principalId: runtimeSupportPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output assignmentId string = storageReadbackAssignment.id
