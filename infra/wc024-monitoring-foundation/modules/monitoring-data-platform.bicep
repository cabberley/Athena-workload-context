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

@description('Resource tags applied to the new Azure Monitor Private Link Scope.')
param tags object = {}

@description('Set true only for the reviewed initial phase-one deployment that creates the Azure Monitor Private Link Scope in Open mode. Leave false thereafter to adopt and preserve its existing access mode.')
param createPrivateLinkScope bool = false

var resourceTags = union(tags, {
  component: 'wc024-monitoring-data-platform'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

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

resource createdPrivateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' = if (createPrivateLinkScope) {
  name: '${namePrefix}-ampls'
  location: 'global'
  tags: resourceTags
  properties: {
    accessModeSettings: {
      queryAccessMode: 'Open'
      ingestionAccessMode: 'Open'
    }
  }
}

resource adoptedPrivateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' existing = if (!createPrivateLinkScope) {
  name: '${namePrefix}-ampls'
}

resource createdWorkspacePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = if (createPrivateLinkScope) {
  parent: createdPrivateLinkScope
  name: uniqueString(workspace.id)
  properties: {
    linkedResourceId: workspace.id
  }
}

resource adoptedWorkspacePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = if (!createPrivateLinkScope) {
  parent: adoptedPrivateLinkScope
  name: uniqueString(workspace.id)
  properties: {
    linkedResourceId: workspace.id
  }
}

resource createdDcePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = if (createPrivateLinkScope) {
  parent: createdPrivateLinkScope
  name: uniqueString(dataCollectionEndpoint.id)
  properties: {
    linkedResourceId: dataCollectionEndpoint.id
  }
}

resource adoptedDcePrivateLinkScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-09-01' = if (!createPrivateLinkScope) {
  parent: adoptedPrivateLinkScope
  name: uniqueString(dataCollectionEndpoint.id)
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
output workspaceDailyQuotaGb int = workspace.properties.workspaceCapping.dailyQuotaGb
output workspaceFeatures object = workspace.properties.features
output dataCollectionRuleResourceId string = dataCollectionRule.id
output dataCollectionEndpointResourceId string = dataCollectionEndpoint.id
output dataCollectionEndpointLocation string = validatedDataCollectionEndpointLocation
output dataCollectionEndpointTags object = dataCollectionEndpoint.tags
output dataCollectionEndpointDescription string? = dataCollectionEndpoint.properties.?description
output dataCollectionEndpointKind string? = dataCollectionEndpoint.?kind
output privateLinkScopeResourceId string = createPrivateLinkScope ? createdPrivateLinkScope!.id : adoptedPrivateLinkScope!.id
output privateLinkScopeTags object = createPrivateLinkScope ? resourceTags : adoptedPrivateLinkScope!.tags
output privateLinkScopeAccessModeExclusions array = createPrivateLinkScope ? [] : adoptedPrivateLinkScope!.properties.accessModeSettings.exclusions ?? []
output preservedCustomLogStream string = preservedCustomLogStream
output preservedCustomLogTable string = preservedCustomLogTable
