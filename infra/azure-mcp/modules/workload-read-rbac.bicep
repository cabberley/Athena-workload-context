targetScope = 'resourceGroup'

metadata name = 'Azure MCP workload resource-group read roles'
metadata description = 'One narrowly scoped Reader assignment for the MCP identity.'

@description('Principal ID of the dedicated Azure MCP user-assigned identity.')
param mcpIdentityPrincipalId string

var readerRoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, mcpIdentityPrincipalId, readerRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      readerRoleDefinitionId
    )
  }
}
