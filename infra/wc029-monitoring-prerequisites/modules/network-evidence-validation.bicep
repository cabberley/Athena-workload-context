targetScope = 'resourceGroup'

@description('Expected Network Watcher and flow-log region.')
@allowed([
  'australiaeast'
])
param location string

@description('Existing regional Network Watcher name.')
param networkWatcherName string

@description('Exact workload VNet resource ID.')
param workloadVirtualNetworkResourceId string

@description('Exact monitoring-owned replacement storage account resource ID.')
param monitoringStorageAccountResourceId string

@description('Exact Traffic Analytics workspace resource ID.')
param workspaceResourceId string

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource canonicalFlowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' existing = {
  parent: networkWatcher
  name: 'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'
}

var trafficAnalytics = canonicalFlowLog.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration
var coverageIsValid = toLower(canonicalFlowLog.location) == location && canonicalFlowLog.properties.enabled && toLower(canonicalFlowLog.properties.targetResourceId) == toLower(workloadVirtualNetworkResourceId) && toLower(canonicalFlowLog.properties.storageId) == toLower(monitoringStorageAccountResourceId) && canonicalFlowLog.properties.format.type == 'JSON' && canonicalFlowLog.properties.format.version == 2 && canonicalFlowLog.properties.retentionPolicy.enabled && canonicalFlowLog.properties.retentionPolicy.days >= 30 && trafficAnalytics.enabled && trafficAnalytics.trafficAnalyticsInterval == 10 && toLower(trafficAnalytics.workspaceResourceId) == toLower(workspaceResourceId)
var validatedFlowLogResourceId = coverageIsValid ? canonicalFlowLog.id : fail('The canonical VNet flow log must write v2 records to monitoring-owned storage with 30-day retention and 10-minute Traffic Analytics in the adopted workspace.')

output coverage object = {
  networkWatcherResourceId: networkWatcher.id
  canonicalFlowLogResourceId: validatedFlowLogResourceId
  targetResourceId: workloadVirtualNetworkResourceId
  storageAccountResourceId: monitoringStorageAccountResourceId
  trafficAnalyticsWorkspaceResourceId: workspaceResourceId
  trafficAnalyticsIntervalMinutes: 10
  retainedLegacyStorageAccountName: 'athenahackathonflowwhtco'
}
