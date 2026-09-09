targetScope = 'resourceGroup'

@description('Resource ID of the isolated monitoring evidence collector identity.')
param collectorIdentityResourceId string

@description('Client ID of the isolated monitoring evidence collector identity.')
param collectorIdentityClientId string

@description('Resource ID of the monitoring-owned resource group.')
param monitoringResourceGroupId string

@description('Resource ID of the approved workload resource group.')
param workloadResourceGroupId string

@description('Exact reviewed workload VNet resource ID.')
param workloadVirtualNetworkResourceId string

@description('Exact reviewed 11 VM names that are inside the WC-024 workload boundary.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Resource ID of the private Log Analytics workspace.')
param workspaceResourceId string

@description('Resource ID of the generic AMA and VM Insights DCR.')
param dataCollectionRuleResourceId string

@description('Resource ID of the private data collection endpoint.')
param dataCollectionEndpointResourceId string

@description('Reviewed authorization model used by the isolated collector.')
@allowed([
  'conditionedWorkspacePlusExactResourceContext'
])
param authorizationMode string

@description('Observed Log Analytics workspace access-control mode.')
@allowed([
  'workspaceAndResourceContext'
  'workspaceOnly'
])
param workspaceAccessControlMode string

@description('Built-in Reader role definition resource ID.')
param readerRoleDefinitionId string

@description('Existing narrow VM signal-reader role definition resource ID.')
param signalReaderRoleDefinitionId string

@description('Built-in Log Analytics Data Reader role definition resource ID.')
param logAnalyticsDataReaderRoleDefinitionId string

@description('Exact Log Analytics table names permitted by the role-assignment condition.')
@minLength(13)
@maxLength(13)
param logAnalyticsAllowedTables array

@description('Exact restrictive Azure RBAC condition applied to Log Analytics data reads.')
param logAnalyticsAccessCondition string

@description('Exact management-plane resource IDs readable through built-in Reader.')
@minLength(27)
@maxLength(27)
param resourceReadScopeIds array

@description('Exact VM resource IDs readable through the narrow signal-reader role.')
@minLength(11)
@maxLength(11)
param signalReadScopeIds array

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
  schemaVersion: 'athena.wc024MonitoringCollectorContract.v2'
  collectorIdentityResourceId: collectorIdentityResourceId
  collectorIdentityClientId: collectorIdentityClientId
  monitoringResourceGroupId: monitoringResourceGroupId
  workloadResourceGroupId: workloadResourceGroupId
  workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
  approvedVmNames: approvedVmNames
  workspaceResourceId: workspaceResourceId
  dataCollectionRuleResourceId: dataCollectionRuleResourceId
  dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  authorizationMode: authorizationMode
  workspaceAccessControlMode: workspaceAccessControlMode
  readerRoleDefinitionId: readerRoleDefinitionId
  signalReaderRoleDefinitionId: signalReaderRoleDefinitionId
  logAnalyticsDataReaderRoleDefinitionId: logAnalyticsDataReaderRoleDefinitionId
  logAnalyticsAllowedTables: logAnalyticsAllowedTables
  logAnalyticsAccessCondition: logAnalyticsAccessCondition
  resourceReadScopeIds: resourceReadScopeIds
  signalReadScopeIds: signalReadScopeIds
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
    'Microsoft.OperationalInsights/workspaces/query/read'
    'Microsoft.OperationalInsights/workspaces/tables/data/read'
    'Microsoft.Compute/virtualMachines/instanceView/read'
    'Microsoft.Insights/Metrics/Read'
    'Microsoft.Insights/dataCollectionRules/read'
    'Microsoft.Insights/dataCollectionEndpoints/read'
    'Microsoft.Insights/dataCollectionRuleAssociations/read'
    'Microsoft.Insights/privateLinkScopes/read'
    'Microsoft.Network/networkWatchers/flowLogs/read'
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
