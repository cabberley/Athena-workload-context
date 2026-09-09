targetScope = 'resourceGroup'

@description('Existing regional Network Watcher resource name.')
param networkWatcherName string

@description('Deterministic VNet flow-log name.')
param flowLogName string

@description('Reviewed workload VNet resource ID.')
param workloadVirtualNetworkResourceId string

@description('Monitoring-owned replacement storage account resource ID.')
param storageAccountResourceId string

@description('Log Analytics workspace customer ID used by Traffic Analytics.')
param workspaceCustomerId string

@description('Log Analytics workspace resource ID used by Traffic Analytics.')
param workspaceResourceId string

@description('Region of the Log Analytics workspace.')
param workspaceLocation string

@description('Retention period for VNet flow-log records.')
@minValue(30)
@maxValue(365)
param retentionDays int

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource vnetFlowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' = {
  parent: networkWatcher
  name: flowLogName
  properties: {
    targetResourceId: workloadVirtualNetworkResourceId
    storageId: storageAccountResourceId
    enabled: true
    retentionPolicy: {
      days: retentionDays
      enabled: true
    }
    format: {
      type: 'JSON'
      version: 2
    }
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceId: workspaceCustomerId
        workspaceRegion: workspaceLocation
        workspaceResourceId: workspaceResourceId
        trafficAnalyticsInterval: 10
      }
    }
  }
}
