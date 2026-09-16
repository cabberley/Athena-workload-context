targetScope = 'resourceGroup'

@description('Existing Azure Container Registry name.')
param registryName string

@description('Exact user-assigned identity resource ID receiving mode-compatible repository pull access.')
param identityResourceId string

@description('Exact principal object ID of the managed identity receiving repository pull access.')
param identityPrincipalId string

@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
@description('Reviewed ACR role assignment mode expected from the existing registry.')
param expectedRegistryRoleAssignmentMode string

var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var repositoryReaderRoleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

var registryRoleAssignmentMode = registry.properties.roleAssignmentMode == expectedRegistryRoleAssignmentMode
  ? expectedRegistryRoleAssignmentMode
  : fail('existing registry roleAssignmentMode does not match the reviewed deployment input')
var validatedIdentityPrincipalId = identity.properties.principalId == identityPrincipalId
  ? identityPrincipalId
  : fail('managed identity principal object ID does not match the reviewed deployment input')
var pullRoleDefinitionId = registryRoleAssignmentMode == 'LegacyRegistryPermissions'
  ? acrPullRoleDefinitionId
  : registryRoleAssignmentMode == 'AbacRepositoryPermissions'
    ? repositoryReaderRoleDefinitionId
    : fail('registry roleAssignmentMode must be LegacyRegistryPermissions or AbacRepositoryPermissions')

module pullAssignment 'acr-pull-role-assignment.bicep' = {
  name: 'acr-pull-${take(replace(identityPrincipalId, '-', ''), 32)}'
  params: {
    registryName: registry.name
    principalObjectId: validatedIdentityPrincipalId
    roleDefinitionId: pullRoleDefinitionId
  }
}

output roleAssignmentResourceId string = pullAssignment.outputs.roleAssignmentResourceId
output roleAssignmentMode string = registryRoleAssignmentMode
output roleDefinitionId string = pullRoleDefinitionId
