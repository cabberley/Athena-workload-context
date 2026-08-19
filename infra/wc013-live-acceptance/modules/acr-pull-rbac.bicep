targetScope = 'resourceGroup'

metadata name = 'WC-013 acceptance image pull role'
metadata description = 'Grants the separate acceptance identity only AcrPull on the supplied existing registry.'

@description('Name of the existing Azure Container Registry hosting the private acceptance image.')
param registryName string

@description('Deterministic name of the separate acceptance managed identity.')
param acceptanceIdentityName string

@description('Principal ID of the separate acceptance managed identity.')
param acceptanceIdentityPrincipalId string

var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: registryName
}

resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, acceptanceIdentityName, acrPullRoleDefinitionId)
  scope: registry
  properties: {
    principalId: acceptanceIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      acrPullRoleDefinitionId
    )
  }
}
