targetScope = 'resourceGroup'

@description('Exact existing Azure Container Registry resource ID.')
param registryResourceId string

@description('Exact service-principal object ID receiving image-pull permission.')
param identityPrincipalId string

@description('Reviewed ACR role-assignment permissions mode.')
@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
param registryRoleAssignmentMode string

var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var repositoryReaderRoleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: last(split(registryResourceId, '/'))
}

#disable-next-line use-resource-symbol-reference
var registryRuntime = reference(registry.id, '2025-04-01', 'Full')
var runtimeRegistryResourceId = toLower(registryRuntime.id) == toLower(registryResourceId)
  ? registryRuntime.id
  : fail('ACR runtime resource ID must match the exact parsed registry scope')
var validatedRoleAssignmentMode = registryRuntime.properties.roleAssignmentMode == registryRoleAssignmentMode
  ? registryRoleAssignmentMode
  : fail('ACR runtime roleAssignmentMode must match the reviewed mode')
var pullRoleDefinitionGuid = registryRoleAssignmentMode == 'LegacyRegistryPermissions'
  ? acrPullRoleDefinitionId
  : registryRoleAssignmentMode == 'AbacRepositoryPermissions'
    ? repositoryReaderRoleDefinitionId
    : fail('ACR roleAssignmentMode must be LegacyRegistryPermissions or AbacRepositoryPermissions')
var pullRoleDefinitionResourceId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  pullRoleDefinitionGuid
)
var guardedPullRoleDefinitionResourceId = !empty(runtimeRegistryResourceId) && !empty(validatedRoleAssignmentMode)
  ? pullRoleDefinitionResourceId
  : fail('ACR runtime identity and permission mode must be validated before role assignment')

resource pullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)
  scope: registry
  properties: {
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: guardedPullRoleDefinitionResourceId
  }
}

output roleAssignmentResourceId string = pullAssignment.id
output roleDefinitionResourceId string = guardedPullRoleDefinitionResourceId
output registryResourceId string = runtimeRegistryResourceId
output roleAssignmentMode string = validatedRoleAssignmentMode
