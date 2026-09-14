targetScope = 'resourceGroup'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param principalId string

@description('Subscription-level custom role permitting only IP Flow Verify.')
param roleDefinitionId string

@description('Exact existing Network Watcher name.')
param networkWatcherName string

@description('Exact existing Network Watcher resource ID.')
param expectedNetworkWatcherResourceId string

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

var validatedNetworkWatcherResourceId = toLower(networkWatcher.id) == toLower(
  expectedNetworkWatcherResourceId
)
  ? networkWatcher.id
  : fail('IP Flow Verify assignment escaped the reviewed Network Watcher')

resource collectorIpFlowVerifier 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedNetworkWatcherResourceId, principalId, roleDefinitionId)
  scope: networkWatcher
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output roleAssignmentResourceId string = collectorIpFlowVerifier.id
