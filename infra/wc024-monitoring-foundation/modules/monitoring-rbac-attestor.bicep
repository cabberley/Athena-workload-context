targetScope = 'subscription'

extension microsoftGraphV1

@description('Principal ID of the isolated effective RBAC attestor identity.')
param attestorPrincipalId string

var attestorRoleDefinitionGuid = '2a8d9aea-2688-5841-a7e4-82f23d0f1bac'
var microsoftGraphApplicationId = '00000003-0000-0000-c000-000000000000'
var applicationReadAllAppRoleId = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
var attestorAllowedOperations = [
  'Microsoft.Authorization/roleAssignments/read'
  'Microsoft.Authorization/roleDefinitions/read'
  'Microsoft.Authorization/denyAssignments/read'
  'Microsoft.Authorization/roleAssignmentScheduleInstances/read'
]

resource attestorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: attestorRoleDefinitionGuid
  properties: {
    roleName: 'Athena WC-028 Effective RBAC Attestor'
    description: 'Read exact Azure RBAC assignments, full role definitions, deny assignments, and active PIM schedule instances without workload data access. Microsoft Graph transitive membership is granted separately.'
    type: 'CustomRole'
    permissions: [
      {
        actions: attestorAllowedOperations
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

resource attestorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, attestorPrincipalId, attestorRoleDefinition.id)
  scope: subscription()
  properties: {
    principalId: attestorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: attestorRoleDefinition.id
  }
}

resource microsoftGraphServicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' existing = {
  appId: microsoftGraphApplicationId
}

resource attestorDirectoryMembershipRead 'Microsoft.Graph/appRoleAssignedTo@v1.0' = {
  appRoleId: applicationReadAllAppRoleId
  principalId: attestorPrincipalId
  resourceDisplayName: 'Microsoft Graph'
  resourceId: microsoftGraphServicePrincipal.id
}

output attestorRoleDefinitionId string = attestorRoleDefinition.id
output attestorRoleName string = attestorRoleDefinition.properties.roleName
output attestorScopeId string = subscription().id
output attestorAllowedOperations array = attestorAllowedOperations
output microsoftGraphApplicationId string = microsoftGraphApplicationId
output applicationReadAllAppRoleId string = applicationReadAllAppRoleId
output applicationReadAllAssignmentId string = attestorDirectoryMembershipRead.id
output microsoftGraphServicePrincipalId string = microsoftGraphServicePrincipal.id
