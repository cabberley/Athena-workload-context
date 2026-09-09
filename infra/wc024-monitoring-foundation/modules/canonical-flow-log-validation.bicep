targetScope = 'resourceGroup'

@description('Exact regional Network Watcher resource name.')
param networkWatcherName string

@description('Exact reviewed canonical VNet flow-log name.')
param flowLogName string

@description('Exact reviewed workload VNet resource ID.')
param workloadVirtualNetworkResourceId string

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource existingFlowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' existing = {
  parent: networkWatcher
  name: flowLogName
}

var targetMatches = toLower(existingFlowLog.properties.targetResourceId) == toLower(workloadVirtualNetworkResourceId)
var locationMatches = toLower(existingFlowLog.location) == 'australiaeast'
var validatedFlowLogName = targetMatches
  ? existingFlowLog.name
  : fail('WC-024 refuses to update the canonical flow log unless its current target is the reviewed workload VNet.')
var validatedFlowLogLocation = locationMatches
  ? existingFlowLog.location
  : fail('WC-024 refuses to update the canonical flow log outside australiaeast.')

output validatedFlowLogName string = validatedFlowLogName
output validatedTargetResourceId string = targetMatches ? workloadVirtualNetworkResourceId : fail('Unreachable canonical flow-log validation failure.')
output validatedFlowLogLocation string = validatedFlowLogLocation
