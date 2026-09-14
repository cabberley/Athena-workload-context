targetScope = 'resourceGroup'

@description('Principal ID of the only identity permitted to read generic monitoring evidence.')
param collectorPrincipalId string

@description('Exact regional Network Watcher name.')
param networkWatcherName string

@description('Exact canonical VNet flow-log name.')
param flowLogName string

var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7'
)
var ipFlowVerifyRoleDefinitionGuid = '3728cdf6-4efd-5282-bdfc-63b7872fd801'
var ipFlowVerifyAllowedOperations = [
  'Microsoft.Network/networkWatchers/ipFlowVerify/action'
  'Microsoft.Network/networkWatchers/ipFlowVerify/read'
]

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' existing = {
  parent: networkWatcher
  name: flowLogName
}

resource ipFlowVerifyRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: ipFlowVerifyRoleDefinitionGuid
  properties: {
    roleName: 'Athena WC-028 Network Watcher IP Flow Verify'
    description: 'Run and read IP Flow Verify only at the exact reviewed Network Watcher.'
    type: 'CustomRole'
    permissions: [
      {
        actions: ipFlowVerifyAllowedOperations
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      resourceGroup().id
    ]
  }
}

resource collectorFlowLogReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(flowLog.id, collectorPrincipalId, readerRoleDefinitionId)
  scope: flowLog
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleDefinitionId
  }
}

resource collectorIpFlowVerifier 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(networkWatcher.id, collectorPrincipalId, ipFlowVerifyRoleDefinition.id)
  scope: networkWatcher
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: ipFlowVerifyRoleDefinition.id
  }
}

output readerRoleDefinitionId string = readerRoleDefinitionId
output resourceReadScopeIds array = [
  '${networkWatcher.id}/flowLogs/${flowLogName}'
]
output ipFlowVerifyRoleDefinitionId string = ipFlowVerifyRoleDefinition.id
output ipFlowVerifyScopeId string = networkWatcher.id
output ipFlowVerifyAllowedOperations array = ipFlowVerifyAllowedOperations
