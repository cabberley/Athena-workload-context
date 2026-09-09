targetScope = 'resourceGroup'

@description('Principal ID of the only identity permitted to read generic monitoring evidence.')
param collectorPrincipalId string

@description('Exact adopted Log Analytics workspace name.')
param workspaceName string

@description('Exact adopted data collection endpoint name.')
param dataCollectionEndpointName string

@description('Exact adopted data collection rule name.')
param dataCollectionRuleName string

@description('Exact adopted AMPLS names.')
@minLength(2)
@maxLength(2)
param privateLinkScopeNames array

var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7'
)
var logAnalyticsDataReaderRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '3b03c2da-16b3-4a49-8834-0f8130efdd3b'
)
var allowedLogTableNames = [
  'Heartbeat'
  'Perf'
  'InsightsMetrics'
  'Syslog'
  'VMComputer'
  'VMConnection'
  'VMBoundPort'
  'VMProcess'
  'NTANetAnalytics'
  'NWConnectionMonitorDestinationListenerResult'
  'NWConnectionMonitorDNSResult'
  'NWConnectionMonitorPathResult'
  'NWConnectionMonitorTestResult'
]
var allowedLogTableCondition = '''
(
  (
    !(ActionMatches{'Microsoft.OperationalInsights/workspaces/tables/data/read'})
  )
  OR
  (
    @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'Heartbeat'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'Perf'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'InsightsMetrics'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'Syslog'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'VMComputer'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'VMConnection'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'VMBoundPort'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'VMProcess'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'NTANetAnalytics'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'NWConnectionMonitorDestinationListenerResult'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'NWConnectionMonitorDNSResult'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'NWConnectionMonitorPathResult'
    OR @Resource[Microsoft.OperationalInsights/workspaces/tables:name] StringEquals 'NWConnectionMonitorTestResult'
  )
)
'''

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' existing = {
  name: dataCollectionEndpointName
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: dataCollectionRuleName
}

resource privateLinkScopes 'Microsoft.Insights/privateLinkScopes@2021-09-01' existing = [
  for privateLinkScopeName in privateLinkScopeNames: {
    name: privateLinkScopeName
  }
]

resource collectorWorkspaceDataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspace.id, collectorPrincipalId, logAnalyticsDataReaderRoleDefinitionId)
  scope: workspace
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: logAnalyticsDataReaderRoleDefinitionId
    condition: allowedLogTableCondition
    conditionVersion: '2.0'
  }
}

resource collectorDataCollectionEndpointReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dataCollectionEndpoint.id, collectorPrincipalId, readerRoleDefinitionId)
  scope: dataCollectionEndpoint
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleDefinitionId
  }
}

resource collectorDataCollectionRuleReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dataCollectionRule.id, collectorPrincipalId, readerRoleDefinitionId)
  scope: dataCollectionRule
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleDefinitionId
  }
}

resource collectorPrivateLinkScopeReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (privateLinkScopeName, index) in privateLinkScopeNames: {
    name: guid(privateLinkScopes[index].id, collectorPrincipalId, readerRoleDefinitionId)
    scope: privateLinkScopes[index]
    properties: {
      principalId: collectorPrincipalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: readerRoleDefinitionId
    }
  }
]

output readerRoleDefinitionId string = readerRoleDefinitionId
output logAnalyticsDataReaderRoleDefinitionId string = logAnalyticsDataReaderRoleDefinitionId
output allowedLogTableNames array = allowedLogTableNames
output logAnalyticsAccessCondition string = allowedLogTableCondition
output resourceReadScopeIds array = concat(
  [
    dataCollectionEndpoint.id
    dataCollectionRule.id
  ],
  map(privateLinkScopes, privateLinkScope => privateLinkScope.id)
)
