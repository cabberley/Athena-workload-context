targetScope = 'resourceGroup'

@description('Exact existing Azure Container Registry resource ID.')
param registryResourceId string

@description('Exact service-principal object ID receiving image-pull permission.')
param identityPrincipalId string

@description('Exact digest-pinned image whose repository is authorized for this principal.')
@minLength(1)
@maxLength(2048)
param image string

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
var validatedAnonymousPullEnabled = registryRuntime.properties.?anonymousPullEnabled == false
  ? false
  : fail('ACR anonymousPullEnabled must be explicitly false before assigning image-pull access')
var pullRoleDefinitionGuid = registryRoleAssignmentMode == 'LegacyRegistryPermissions'
  ? acrPullRoleDefinitionId
  : registryRoleAssignmentMode == 'AbacRepositoryPermissions'
    ? repositoryReaderRoleDefinitionId
    : fail('ACR roleAssignmentMode must be LegacyRegistryPermissions or AbacRepositoryPermissions')
var pullRoleDefinitionResourceId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  pullRoleDefinitionGuid
)
var guardedPullRoleDefinitionResourceId = !empty(runtimeRegistryResourceId) && !empty(validatedRoleAssignmentMode) && validatedAnonymousPullEnabled == false
  ? pullRoleDefinitionResourceId
  : fail('ACR runtime identity, permission mode, and disabled anonymous pull must be validated before role assignment')
var expectedRegistryServer = '${toLower(last(split(registryResourceId, '/')))}.azurecr.io'
var imageParts = split(image, '@sha256:')
var imageRepositoryReference = length(imageParts) == 2 ? imageParts[0] : ''
var imageDigest = length(imageParts) == 2 ? imageParts[1] : ''
var repositoryPrefix = '${expectedRegistryServer}/'
var repositoryNameCandidate = startsWith(imageRepositoryReference, repositoryPrefix)
  ? substring(imageRepositoryReference, length(repositoryPrefix))
  : ''
var imageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  imageDigest,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var imageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  imageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedRepositoryName = image == toLower(image) && length(imageParts) == 2 && startsWith(
  imageRepositoryReference,
  repositoryPrefix
) && !empty(repositoryNameCandidate) && !contains(repositoryNameCandidate, '@') && length(imageDigest) == 64 && empty(
  imageDigestInvalidCharacters
) && imageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
  ? repositoryNameCandidate
  : fail('image must be a real lowercase digest-pinned image in the supplied registry')
var repositoryCondition = '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${validatedRepositoryName}\'))'
var pullConditionVersion = validatedRoleAssignmentMode == 'AbacRepositoryPermissions' ? '2.0' : null
var pullCondition = validatedRoleAssignmentMode == 'AbacRepositoryPermissions'
  ? repositoryCondition
  : null
var pullAssignmentName = registryRoleAssignmentMode == 'AbacRepositoryPermissions'
  ? guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId, validatedRepositoryName)
  : guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)

resource pullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: pullAssignmentName
  scope: registry
  properties: union({
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: guardedPullRoleDefinitionResourceId
  }, validatedRoleAssignmentMode == 'AbacRepositoryPermissions'
    ? {
        conditionVersion: pullConditionVersion
        condition: pullCondition
      }
    : {})
}

output roleAssignmentResourceId string = pullAssignment.id
output roleDefinitionResourceId string = guardedPullRoleDefinitionResourceId
output registryResourceId string = runtimeRegistryResourceId
output roleAssignmentMode string = validatedRoleAssignmentMode
output anonymousPullEnabled bool = validatedAnonymousPullEnabled
output repositoryName string = validatedRepositoryName
output conditionVersion string? = pullConditionVersion
output condition string? = pullCondition
