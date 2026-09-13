targetScope = 'subscription'

metadata name = 'Athena WC-029 monitoring prerequisites'
metadata description = 'Validates the deployed WC-024 monitoring baseline and prepares explicitly gated VM Insights and Connection Monitor guest prerequisites without defining governed paths or broad Activity Log export.'

@description('Exact subscription approved for WC-029.')
@allowed([
  'a6add389-9978-47ac-ab1e-a09212e321d4'
])
param expectedSubscriptionId string = 'a6add389-9978-47ac-ab1e-a09212e321d4'

@description('Reviewed deployment region.')
@allowed([
  'australiaeast'
])
param location string = 'australiaeast'

@description('Existing workload resource group containing the approved Linux VMs.')
@allowed([
  'rg-athena-demo-workload'
])
param workloadResourceGroupName string = 'rg-athena-demo-workload'

@description('Existing monitoring resource group containing the adopted DCR, workspace, and replacement storage.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string = 'rg-athena-demo-monitoring'

@description('Existing Network Watcher resource group.')
@allowed([
  'NetworkWatcherRG'
])
param networkWatcherResourceGroupName string = 'NetworkWatcherRG'

@description('Existing regional Network Watcher name.')
@allowed([
  'NetworkWatcher_australiaeast'
])
param networkWatcherName string = 'NetworkWatcher_australiaeast'

@description('Existing monitoring-owned replacement storage account.')
@allowed([
  'athenademomonchab01'
])
param monitoringStorageAccountName string = 'athenademomonchab01'

@description('Existing replacement-storage private endpoint.')
@allowed([
  'athena-demo-monitoring-monitoring-storage-pe'
])
param monitoringStoragePrivateEndpointName string = 'athena-demo-monitoring-monitoring-storage-pe'

@description('Install Dependency Agent for Linux on all approved VMs after what-if and operator approval.')
param deployVmInsightsDependencyAgent bool = false

@description('Install Network Watcher Agent for Linux only on exact approved Connection Monitor source VMs.')
param deployConnectionMonitorAgent bool = false

@description('Exact source VM names approved by published monitoring intent. Must be empty while Connection Monitor reconciliation is unavailable.')
@maxLength(11)
param connectionMonitorSourceVmNames array = []

@description('Must remain false. A separate security and data-governance decision is required before any subscription Activity Log diagnostic export can be introduced.')
@allowed([
  false
])
param subscriptionActivityLogExportEnabled bool = false

@description('Must remain false. Connection Monitor definitions require exact published-intent reconciliation and are not part of this prerequisite root.')
@allowed([
  false
])
param connectionMonitorDefinitionsEnabled bool = false

var approvedVmNames = [
  'athena-hackathon-client-01'
  'athena-hackathon-ecp-01'
  'athena-hackathon-ecp-02'
  'athena-hackathon-ecp-03'
  'athena-hackathon-iris-01'
  'athena-hackathon-mid-01'
  'athena-hackathon-mid-02'
  'athena-hackathon-sqlvm-01'
  'athena-hackathon-web-01'
  'athena-hackathon-web-02'
  'athena-hackathon-web-03'
]
var normalizedConnectionMonitorSourceVmNames = map(connectionMonitorSourceVmNames, vmName => toLower(string(vmName)))
var invalidConnectionMonitorSourceVmNames = filter(normalizedConnectionMonitorSourceVmNames, vmName => !contains(approvedVmNames, vmName))
var validatedConnectionMonitorSourceVmNames = deployConnectionMonitorAgent && !empty(normalizedConnectionMonitorSourceVmNames) && empty(invalidConnectionMonitorSourceVmNames) && length(union(normalizedConnectionMonitorSourceVmNames, [])) == length(normalizedConnectionMonitorSourceVmNames)
  ? normalizedConnectionMonitorSourceVmNames
  : !deployConnectionMonitorAgent && empty(normalizedConnectionMonitorSourceVmNames)
    ? []
    : fail('Connection Monitor agent deployment requires a distinct, non-empty subset of the exact approved VM names; the list must remain empty while deployment is disabled.')
var validatedSubscriptionId = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId)
  ? subscription().subscriptionId
  : fail('WC-029 may be deployed only to subscription a6add389-9978-47ac-ab1e-a09212e321d4.')
var workloadResourceGroupId = '/subscriptions/${validatedSubscriptionId}/resourceGroups/${workloadResourceGroupName}'
var monitoringResourceGroupId = '/subscriptions/${validatedSubscriptionId}/resourceGroups/${monitoringResourceGroupName}'
var workspaceResourceId = '${monitoringResourceGroupId}/providers/Microsoft.OperationalInsights/workspaces/athena-hackathon-law'
var dataCollectionRuleResourceId = '${monitoringResourceGroupId}/providers/Microsoft.Insights/dataCollectionRules/athena-hackathon-linux-dcr'
var dataCollectionEndpointResourceId = '${monitoringResourceGroupId}/providers/Microsoft.Insights/dataCollectionEndpoints/athena-hackathon-linux-dce'
var workloadVirtualNetworkResourceId = '${workloadResourceGroupId}/providers/Microsoft.Network/virtualNetworks/athena-hackathon-vnet'
var monitoringStorageAccountResourceId = '${monitoringResourceGroupId}/providers/Microsoft.Storage/storageAccounts/${monitoringStorageAccountName}'

resource workloadResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: workloadResourceGroupName
}

resource monitoringResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: monitoringResourceGroupName
}

module guestCoverageValidation 'modules/guest-coverage-validation.bicep' = {
  name: 'wc029-guest-coverage-validation'
  scope: workloadResourceGroup
  params: {
    location: location
    approvedVmNames: approvedVmNames
    monitoringResourceGroupName: monitoringResourceGroupName
    dataCollectionRuleResourceId: dataCollectionRuleResourceId
    dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  }
}

module dataCollectionCoverageValidation 'modules/data-collection-coverage-validation.bicep' = {
  name: 'wc029-data-collection-coverage-validation'
  scope: monitoringResourceGroup
  params: {
    location: location
    workspaceResourceId: workspaceResourceId
    dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  }
}

module networkEvidenceValidation 'modules/network-evidence-validation.bicep' = {
  name: 'wc029-network-evidence-validation'
  scope: resourceGroup(networkWatcherResourceGroupName)
  params: {
    location: location
    networkWatcherName: networkWatcherName
    workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
    monitoringStorageAccountResourceId: monitoringStorageAccountResourceId
    workspaceResourceId: workspaceResourceId
  }
}

module storageValidation 'modules/storage-validation.bicep' = {
  name: 'wc029-storage-validation'
  scope: monitoringResourceGroup
  params: {
    location: location
    storageAccountName: monitoringStorageAccountName
    storagePrivateEndpointName: monitoringStoragePrivateEndpointName
  }
}

module dependencyAgents 'br/public:avm/res/compute/virtual-machine/extension:0.1.0' = [for (vmName, index) in approvedVmNames: if (deployVmInsightsDependencyAgent) {
  name: 'wc029-dependency-agent-${index}'
  scope: workloadResourceGroup
  dependsOn: [
    dataCollectionCoverageValidation
    guestCoverageValidation
  ]
  params: {
    virtualMachineName: vmName
    name: 'DependencyAgentLinux'
    location: location
    publisher: 'Microsoft.Azure.Monitoring.DependencyAgent'
    type: 'DependencyAgentLinux'
    typeHandlerVersion: '9.10'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    provisionAfterExtensions: [
      'AzureMonitorLinuxAgent'
    ]
    settings: {
      enableAMA: 'true'
    }
    enableTelemetry: false
  }
}]

module connectionMonitorAgents 'br/public:avm/res/compute/virtual-machine/extension:0.1.0' = [for (vmName, index) in validatedConnectionMonitorSourceVmNames: {
  name: 'wc029-network-watcher-agent-${index}'
  scope: workloadResourceGroup
  dependsOn: [
    guestCoverageValidation
    networkEvidenceValidation
  ]
  params: {
    virtualMachineName: vmName
    name: 'NetworkWatcherAgentLinux'
    location: location
    publisher: 'Microsoft.Azure.NetworkWatcher'
    type: 'NetworkWatcherAgentLinux'
    typeHandlerVersion: '1.4'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    enableTelemetry: false
  }
}]

output readiness object = {
  schemaVersion: 'athena.wc029MonitoringInfrastructureReadiness.v1'
  subscriptionId: validatedSubscriptionId
  location: location
  workloadResourceGroupId: workloadResourceGroupId
  monitoringResourceGroupId: monitoringResourceGroupId
  approvedVmNames: approvedVmNames
  guestCoverage: guestCoverageValidation.outputs.coverage
  dataCollectionCoverage: dataCollectionCoverageValidation.outputs.coverage
  networkEvidence: networkEvidenceValidation.outputs.coverage
  storage: storageValidation.outputs.coverage
  vmInsightsDependencyAgentDeploymentEnabled: deployVmInsightsDependencyAgent
  connectionMonitorAgentDeploymentEnabled: deployConnectionMonitorAgent
  connectionMonitorSourceVmNames: validatedConnectionMonitorSourceVmNames
  connectionMonitorDefinitionsEnabled: connectionMonitorDefinitionsEnabled
  subscriptionActivityLogExportEnabled: subscriptionActivityLogExportEnabled
  boundedChangeEventRoute: 'infra/wc025-change-ingestion'
  noAutoRemediation: true
}

output dependencyAgentExtensionResourceIds array = deployVmInsightsDependencyAgent
  ? map(dependencyAgents, extension => extension.outputs.resourceId)
  : []

output connectionMonitorAgentExtensionResourceIds array = deployConnectionMonitorAgent
  ? map(connectionMonitorAgents, extension => extension.outputs.resourceId)
  : []
