targetScope = 'resourceGroup'

@description('Existing Azure Container Registry name.')
param registryName string

@description('Managed identity principal object ID receiving repository pull access.')
param principalObjectId string

@description('Mode-compatible built-in role definition GUID.')
param roleDefinitionId string

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

resource pullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    registry.id,
    principalObjectId,
    roleDefinitionId
  )
  scope: registry
  properties: {
    principalId: principalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      roleDefinitionId
    )
  }
}

output roleAssignmentResourceId string = pullAssignment.id
