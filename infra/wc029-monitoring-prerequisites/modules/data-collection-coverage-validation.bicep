targetScope = 'resourceGroup'

@description('Expected DCR, workspace, and VM Insights solution region.')
@allowed([
  'australiaeast'
])
param location string

@description('Exact adopted Log Analytics workspace resource ID.')
param workspaceResourceId string

@description('Exact adopted data collection endpoint resource ID.')
param dataCollectionEndpointResourceId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: 'athena-hackathon-law'
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2024-03-11' existing = {
  name: 'athena-hackathon-linux-dcr'
}

resource vmInsightsSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' existing = {
  name: 'VMInsights(athena-hackathon-law)'
}

var dataFlows = dataCollectionRule.properties.?dataFlows ?? []
var performanceCounters = dataCollectionRule.properties.dataSources.?performanceCounters ?? []
var performanceCounterSpecifiers = flatten(map(performanceCounters, counter => counter.counterSpecifiers))
var logAnalyticsDestinations = dataCollectionRule.properties.destinations.?logAnalytics ?? []
var approvedWorkspaceDestinationNames = map(filter(logAnalyticsDestinations, destination => toLower(destination.workspaceResourceId) == toLower(workspaceResourceId)), destination => toLower(destination.name))
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
var streamsMissingExclusiveApprovedWorkspaceFlow = filter(requiredStreams, stream => empty(filter(dataFlows, flow => contains(flow.?streams ?? [], stream))) || !empty(filter(dataFlows, flow => contains(flow.?streams ?? [], stream) && (length(flow.?destinations ?? []) != 1 || empty(filter(flow.?destinations ?? [], destinationName => contains(approvedWorkspaceDestinationNames, toLower(destinationName))))))))
var missingPerformanceCounters = filter(requiredPerformanceCounters, counter => !contains(performanceCounterSpecifiers, counter))
var workspaceIsValid = toLower(workspace.id) == toLower(workspaceResourceId) && toLower(workspace.location) == location && workspace.properties.provisioningState == 'Succeeded'
var vmInsightsSolutionIsValid = toLower(vmInsightsSolution.location) == location && vmInsightsSolution.properties.provisioningState == 'Succeeded' && toLower(vmInsightsSolution.properties.workspaceResourceId) == toLower(workspaceResourceId)
var dcrDataCollectionEndpointIsValid = toLower(dataCollectionRule.properties.?dataCollectionEndpointId ?? '') == toLower(dataCollectionEndpointResourceId)
var dcrCoverageIsValid = toLower(dataCollectionRule.location) == location && dataCollectionRule.properties.provisioningState == 'Succeeded' && dcrDataCollectionEndpointIsValid && !empty(approvedWorkspaceDestinationNames) && empty(streamsMissingExclusiveApprovedWorkspaceFlow) && empty(missingPerformanceCounters)
var validatedWorkspaceResourceId = workspaceIsValid ? workspace.id : fail('The adopted Log Analytics workspace must exist in australiaeast with a Succeeded provisioning state and the exact reviewed resource ID.')
var validatedVmInsightsSolutionResourceId = vmInsightsSolutionIsValid ? vmInsightsSolution.id : fail('The VM Insights solution must exist in australiaeast with a Succeeded provisioning state and be bound to the exact monitoring workspace.')
var validatedDcrResourceId = dcrCoverageIsValid ? dataCollectionRule.id : fail('Every required DCR stream must flow exclusively to destinations bound to the approved workspace, the DCR must reference the exact approved DCE, and it must retain the reviewed guest counters with a Succeeded provisioning state.')

output coverage object = {
  workspaceResourceId: validatedWorkspaceResourceId
  dataCollectionRuleResourceId: validatedDcrResourceId
  dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  vmInsightsSolutionResourceId: validatedVmInsightsSolutionResourceId
  streams: requiredStreams
  performanceCounters: requiredPerformanceCounters
  approvedWorkspaceDestinationNames: approvedWorkspaceDestinationNames
}
