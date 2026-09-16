targetScope = 'resourceGroup'

@description('Existing Azure Container Registry name.')
param registryName string

@description('Exact user-assigned identity resource ID receiving AcrPull.')
param identityResourceId string

var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: registryName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource pullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, acrPullRoleDefinitionId)
  scope: registry
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      acrPullRoleDefinitionId
    )
  }
}

output roleAssignmentResourceId string = pullAssignment.id
