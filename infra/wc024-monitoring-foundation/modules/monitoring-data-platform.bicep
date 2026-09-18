targetScope = 'resourceGroup'

@description('Lowercase prefix for the monitoring private link scope name.')
param namePrefix string

@description('Existing Log Analytics workspace adopted by the monitoring foundation.')
param workspaceName string

@description('Existing data collection endpoint adopted by the monitoring foundation.')
param dataCollectionEndpointName string

@description('Existing data collection rule adopted without a PUT so its custom log source, flow, and tags remain unchanged.')
param dataCollectionRuleName string

@description('Reviewed existing custom DCR input stream that WC-024 must preserve.')
@allowed([
  'Custom-AthenaJson'
])
param preservedCustomLogStream string = 'Custom-AthenaJson'

@description('Reviewed existing custom DCR output table that WC-024 must preserve.')
@allowed([
  'Custom-AthenaApp_CL'
])
param preservedCustomLogTable string = 'Custom-AthenaApp_CL'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

var resourceContextTableNames = [
  'Heartbeat'
  'Perf'
  'InsightsMetrics'
  'Syslog'
  'VMConnection'
]

resource resourceContextTables 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' existing = [
  for tableName in resourceContextTableNames: {
    parent: workspace
    name: tableName
  }
]

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' existing = {
  name: dataCollectionEndpointName
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dataCollectionRuleName
}

var adoptedWorkspaceLocation = workspace.location
var adoptedDataCollectionEndpointLocation = dataCollectionEndpoint.location
var validatedWorkspaceLocation = toLower(adoptedWorkspaceLocation) == toLower(adoptedDataCollectionEndpointLocation)
  ? adoptedWorkspaceLocation
  : fail('WC-024 requires the adopted Log Analytics workspace and data collection endpoint to use the same Azure region. Reconcile the regional topology before deployment.')
var validatedDataCollectionEndpointLocation = toLower(adoptedWorkspaceLocation) == toLower(adoptedDataCollectionEndpointLocation)
  ? adoptedDataCollectionEndpointLocation
  : fail('WC-024 requires the adopted Log Analytics workspace and data collection endpoint to use the same Azure region. Reconcile the regional topology before deployment.')
var validatedWorkspaceResourceContextAccessEnabled = workspace.properties.features.enableLogAccessUsingOnlyResourcePermissions
  ? true
  : fail('WC-028 resource-context acquisition requires enableLogAccessUsingOnlyResourcePermissions=true.')

resource workloadPrivateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' existing = {
  name: '${namePrefix}-workload-ampls'
}

resource collectorPrivateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' existing = {
  name: '${namePrefix}-collector-ampls'
}

resource workloadWorkspacePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {
  parent: workloadPrivateLinkScope
  name: uniqueString(workspace.id)
  properties: {
    linkedResourceId: workspace.id
  }
}

resource workloadDcePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {
  parent: workloadPrivateLinkScope
  name: uniqueString(dataCollectionEndpoint.id)
  dependsOn: [
    workloadWorkspacePrivateLinkScope
  ]
  properties: {
    linkedResourceId: dataCollectionEndpoint.id
  }
}

resource collectorWorkspacePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {
  parent: collectorPrivateLinkScope
  name: uniqueString(workspace.id)
  dependsOn: [
    workloadDcePrivateLinkScope
  ]
  properties: {
    linkedResourceId: workspace.id
  }
}

resource collectorDcePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = {
  parent: collectorPrivateLinkScope
  name: uniqueString(dataCollectionEndpoint.id)
  dependsOn: [
    collectorWorkspacePrivateLinkScope
  ]
  properties: {
    linkedResourceId: dataCollectionEndpoint.id
  }
}

output workspaceResourceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
output workspaceLocation string = validatedWorkspaceLocation
output workspaceTags object = workspace.tags
output workspaceSkuName string = workspace.properties.sku.name
output workspaceRetentionDays int = workspace.properties.retentionInDays
output workspaceFeatures object = workspace.properties.features
output workspaceResourceContextAccessEnabled bool = validatedWorkspaceResourceContextAccessEnabled
output resourceContextTablePlans array = [
  for (tableName, index) in resourceContextTableNames: {
    table: tableName
    plan: resourceContextTables[index].properties.plan == 'Analytics'
      ? 'Analytics'
      : fail('WC-028 resource-context acquisition requires Analytics plan on every exact VM log table.')
    tableResourceId: resourceContextTables[index].id
  }
]
output dataCollectionRuleResourceId string = dataCollectionRule.id
output dataCollectionEndpointResourceId string = dataCollectionEndpoint.id
output dataCollectionEndpointLocation string = validatedDataCollectionEndpointLocation
output dataCollectionEndpointTags object = dataCollectionEndpoint.tags
output dataCollectionEndpointDescription string? = dataCollectionEndpoint.properties.?description
output dataCollectionEndpointKind string? = dataCollectionEndpoint.?kind
output workloadPrivateLinkScopeResourceId string = workloadPrivateLinkScope.id
output collectorPrivateLinkScopeResourceId string = collectorPrivateLinkScope.id
output preservedCustomLogStream string = preservedCustomLogStream
output preservedCustomLogTable string = preservedCustomLogTable
