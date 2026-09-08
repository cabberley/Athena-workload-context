targetScope = 'resourceGroup'

@description('Resource ID of the isolated monitoring evidence collector identity.')
param collectorIdentityResourceId string

@description('Client ID of the isolated monitoring evidence collector identity.')
param collectorIdentityClientId string

@description('Resource ID of the monitoring-owned resource group.')
param monitoringResourceGroupId string

@description('Resource ID of the approved workload resource group.')
param workloadResourceGroupId string

@description('Resource ID of the private Log Analytics workspace.')
param workspaceResourceId string

@description('Resource ID of the generic AMA and VM Insights DCR.')
param dataCollectionRuleResourceId string

@description('Resource ID of the private data collection endpoint.')
param dataCollectionEndpointResourceId string

@description('Resource ID of the non-exportable collector signing key.')
param signingKeyResourceId string

@description('Resource ID of the monitoring-owned immutable evidence storage account.')
param evidenceStorageAccountResourceId string

@description('Maximum accepted age for a signed evidence handoff.')
@minValue(60)
@maxValue(900)
param maximumEvidenceAgeSeconds int

@description('The generic Connection Monitor capability state.')
param connectionMonitorDeploymentMode string

var validatedConnectionMonitorDeploymentMode = connectionMonitorDeploymentMode == 'capability-only'
  ? connectionMonitorDeploymentMode
  : fail('collector contracts require the generic Connection Monitor capability-only mode')

output collectorContract object = {
  schemaVersion: 'athena.wc024MonitoringCollectorContract.v1'
  collectorIdentityResourceId: collectorIdentityResourceId
  collectorIdentityClientId: collectorIdentityClientId
  monitoringResourceGroupId: monitoringResourceGroupId
  workloadResourceGroupId: workloadResourceGroupId
  workspaceResourceId: workspaceResourceId
  dataCollectionRuleResourceId: dataCollectionRuleResourceId
  dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  signalKinds: [
    'heartbeat'
    'perf'
    'insightsMetrics'
    'syslog'
    'disk'
    'guest'
    'vnetFlow'
    'trafficAnalytics'
  ]
  allowedReadOperations: [
    'Microsoft.OperationalInsights/workspaces/read'
    'Microsoft.OperationalInsights/workspaces/query/Heartbeat/read'
    'Microsoft.OperationalInsights/workspaces/query/Perf/read'
    'Microsoft.OperationalInsights/workspaces/query/InsightsMetrics/read'
    'Microsoft.OperationalInsights/workspaces/query/Syslog/read'
    'Microsoft.OperationalInsights/workspaces/query/VMComputer/read'
    'Microsoft.OperationalInsights/workspaces/query/VMConnection/read'
    'Microsoft.OperationalInsights/workspaces/query/VMBoundPort/read'
    'Microsoft.OperationalInsights/workspaces/query/VMProcess/read'
    'Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read'
    'Microsoft.Insights/Metrics/Read'
    'Microsoft.Insights/dataCollectionRules/read'
    'Microsoft.Insights/dataCollectionEndpoints/read'
    'Microsoft.Insights/dataCollectionRuleAssociations/read'
    'Microsoft.Insights/privateLinkScopes/read'
    'Microsoft.Network/networkWatchers/flowLogs/read'
    'Microsoft.Network/networkWatchers/connectionMonitors/read'
    'Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDestinationListenerResult/read'
    'Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorDNSResult/read'
    'Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorPathResult/read'
    'Microsoft.OperationalInsights/workspaces/query/NWConnectionMonitorTestResult/read'
  ]
  collectionMode: 'isolatedSignedCollector'
  handoffSchemaVersion: 'athena.wc024MonitoringEvidenceHandoff.v1'
  maximumEvidenceAgeSeconds: maximumEvidenceAgeSeconds
  connectionMonitorMode: 'capabilityOnly'
  signingKeyResourceId: signingKeyResourceId
  evidenceStorageAccountResourceId: evidenceStorageAccountResourceId
  evidenceContainerName: 'monitoring-evidence'
  connectionMonitorDeploymentMode: validatedConnectionMonitorDeploymentMode
}
