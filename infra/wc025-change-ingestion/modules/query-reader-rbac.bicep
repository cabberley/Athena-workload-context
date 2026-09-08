targetScope = 'resourceGroup'

@description('Dedicated Azure Resource Graph change-history identity principal ID.')
param queryIdentityPrincipalId string

@description('Subscription-scoped custom role definition ID for bounded change history.')
param changeHistoryReaderRoleDefinitionId string

resource queryIdentityChangeHistoryReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, queryIdentityPrincipalId, changeHistoryReaderRoleDefinitionId)
  properties: {
    principalId: queryIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: changeHistoryReaderRoleDefinitionId
  }
}
