targetScope = 'subscription'

@description('Principal ID of the only identity permitted to submit the reviewed Resource Graph query.')
param collectorPrincipalId string

var resourceGraphQueryRoleDefinitionGuid = '5687977f-aa06-5699-8e18-1a54a074b532'
var resourceGraphQueryAllowedOperations = [
  'Microsoft.ResourceGraph/resources/read'
]

resource resourceGraphQueryRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: resourceGraphQueryRoleDefinitionGuid
  properties: {
    roleName: 'Athena WC-028 Resource Graph Query Submitter'
    description: 'Submit Azure Resource Graph queries only within this subscription. Resource visibility remains independently limited by exact resource-provider read assignments.'
    type: 'CustomRole'
    permissions: [
      {
        actions: resourceGraphQueryAllowedOperations
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

resource collectorResourceGraphQueryReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, collectorPrincipalId, resourceGraphQueryRoleDefinition.id)
  scope: subscription()
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: resourceGraphQueryRoleDefinition.id
  }
}

output resourceGraphQueryRoleDefinitionId string = resourceGraphQueryRoleDefinition.id
output resourceGraphQueryRoleName string = resourceGraphQueryRoleDefinition.properties.roleName
output resourceGraphQueryScopeId string = subscription().id
output resourceGraphQueryAllowedOperations array = resourceGraphQueryAllowedOperations
output resourceGraphQueryRoleAssignmentId string = collectorResourceGraphQueryReader.id
