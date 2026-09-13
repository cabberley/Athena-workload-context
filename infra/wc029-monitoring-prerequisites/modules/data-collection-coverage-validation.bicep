targetScope = 'resourceGroup'

@description('Expected DCR, workspace, and VM Insights solution region.')
@allowed([
  'australiaeast'
])
param location string

@description('Exact adopted Log Analytics workspace resource ID.')
param workspaceResourceId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: 'athena-hackathon-law'
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: 'athena-hackathon-linux-dcr'
}

resource vmInsightsSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' existing = {
  name: 'VMInsights(athena-hackathon-law)'
}

var dataFlowStreams = flatten(map(dataCollectionRule.properties.dataFlows, flow => flow.streams))
var performanceCounters = dataCollectionRule.properties.dataSources.?performanceCounters ?? []
var performanceCounterSpecifiers = flatten(map(performanceCounters, counter => counter.counterSpecifiers))
var logAnalyticsDestinations = dataCollectionRule.properties.destinations.?logAnalytics ?? []
var destinationWorkspaceResourceIds = map(logAnalyticsDestinations, destination => toLower(destination.workspaceResourceId))
var requiredStreams = [
  'Microsoft-Perf'
  'Microsoft-InsightsMetrics'
  'Microsoft-Syslog'
  'Custom-AthenaJson'
]
var requiredPerformanceCounters = [
  '\\Processor(_Total)\\% Processor Time'
  '\\Memory\\Available MBytes'
  '\\Memory\\% Used Memory'
  '\\Logical Disk(*)\\% Used Space'
  '\\Logical Disk(*)\\Disk Transfers/sec'
  '\\Network(*)\\Total Bytes Transmitted'
  '\\Network(*)\\Total Bytes Received'
  '\\VmInsights\\DetailedMetrics'
]
var missingStreams = filter(requiredStreams, stream => !contains(dataFlowStreams, stream))
var missingPerformanceCounters = filter(requiredPerformanceCounters, counter => !contains(performanceCounterSpecifiers, counter))
var coverageIsValid = toLower(workspace.location) == location && toLower(dataCollectionRule.location) == location && empty(missingStreams) && empty(missingPerformanceCounters) && contains(destinationWorkspaceResourceIds, toLower(workspaceResourceId))
var validatedDcrResourceId = coverageIsValid ? dataCollectionRule.id : fail('The adopted DCR must retain Perf, InsightsMetrics, Syslog, Athena custom logs, the reviewed guest counters, and the exact monitoring workspace destination.')

output coverage object = {
  workspaceResourceId: workspace.id
  dataCollectionRuleResourceId: validatedDcrResourceId
  vmInsightsSolutionResourceId: vmInsightsSolution.id
  streams: requiredStreams
  performanceCounters: requiredPerformanceCounters
}
