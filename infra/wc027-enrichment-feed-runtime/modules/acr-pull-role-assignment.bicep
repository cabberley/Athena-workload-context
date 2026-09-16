targetScope = 'resourceGroup'

@description('Existing Azure Container Registry name.')
param registryName string

@description('Managed identity principal object ID receiving repository pull access.')
param principalObjectId string

@description('Mode-compatible built-in role definition GUID.')
param roleDefinitionId string

@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
@description('Reviewed ACR role assignment mode.')
param roleAssignmentMode string

@minLength(1)
@maxLength(256)
@description('Exact repository name allowed when ABAC repository permissions are enabled.')
param repositoryName string

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

var exactRepositoryCondition = '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${repositoryName}\'))'
var assignmentProperties = union(
  {
    principalId: principalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      roleDefinitionId
    )
  },
  roleAssignmentMode == 'AbacRepositoryPermissions'
    ? {
        conditionVersion: '2.0'
        condition: exactRepositoryCondition
      }
    : {}
)

resource pullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    registry.id,
    principalObjectId,
    roleDefinitionId
  )
  scope: registry
  properties: assignmentProperties
}

output roleAssignmentResourceId string = pullAssignment.id
output repositoryCondition string = roleAssignmentMode == 'AbacRepositoryPermissions'
  ? exactRepositoryCondition
  : ''
