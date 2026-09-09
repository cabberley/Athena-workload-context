targetScope = 'subscription'

@description('Deterministic custom-role definition GUID.')
param roleDefinitionGuid string

@description('Only the monitoring, approved workload, and regional Network Watcher resource groups are assignable.')
@minLength(3)
@maxLength(3)
param assignableScopes array

resource monitoringEvidenceReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionGuid
  properties: {
    roleName: 'Athena WC024 Isolated Monitoring Evidence Reader'
    description: 'Read only the generic monitoring data plane, DCR associations, VNet flow logs, and Connection Monitor results. Assignment is reserved for the isolated signed collector.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.OperationalInsights/workspaces/read'
          'Microsoft.OperationalInsights/workspaces/query/read'
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
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: assignableScopes
  }
}

output roleDefinitionId string = monitoringEvidenceReaderRole.id
