targetScope = 'resourceGroup'

@description('Existing ACR name.')
param registryName string

@description('Exact existing ACR resource ID.')
param expectedRegistryResourceId string

@description('Principal ID of the separate WC-028 runtime-support identity.')
param runtimeSupportPrincipalId string

@description('Resource ID of the separate WC-028 runtime-support identity.')
param runtimeSupportIdentityResourceId string

@description('Built-in AcrPull role definition ID.')
param acrPullRoleDefinitionId string

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

var validatedRegistryResourceId = toLower(registry.id) == toLower(expectedRegistryResourceId)
  ? registry.id
  : fail('ACR pull assignment escaped the reviewed registry')

resource runtimeSupportImagePull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    validatedRegistryResourceId,
    runtimeSupportIdentityResourceId,
    acrPullRoleDefinitionId
  )
  scope: registry
  properties: {
    principalId: runtimeSupportPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleDefinitionId
  }
}

output roleAssignmentResourceId string = runtimeSupportImagePull.id
