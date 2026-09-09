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

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' existing = {
  parent: networkWatcher
  name: flowLogName
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

output readerRoleDefinitionId string = readerRoleDefinitionId
output resourceReadScopeIds array = [
  '${networkWatcher.id}/flowLogs/${flowLogName}'
]
