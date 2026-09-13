targetScope = 'resourceGroup'

@description('Existing regional Network Watcher containing the canonical and redundant flow logs.')
param networkWatcherName string

@description('Name of the enabled canonical VNet flow log that must complete cutover first.')
param canonicalVnetFlowLogName string

@description('VNet resource ID owned by the enabled canonical VNet flow log.')
param workloadVirtualNetworkResourceId string

@description('Replacement monitoring storage account configured on disabled redundant flow logs.')
param replacementStorageAccountResourceId string

@description('Retained legacy storage account that every reviewed redundant flow log must currently use.')
param legacyFlowLogStorageAccountResourceId string

@description('Explicit reviewed names of redundant subnet or NIC flow logs to disable.')
@maxLength(32)
param legacyFlowLogNames array = []

@description('Explicit reviewed target resource IDs paired by index with legacyFlowLogNames.')
@maxLength(32)
param legacyFlowLogTargetResourceIds array = []

@description('Must be true only after the canonical VNet flow log is confirmed enabled and writing to replacement storage.')
param canonicalVnetFlowLogCutoverConfirmed bool = false

var workloadScopeId = '${subscription().id}/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Network'
var reviewedLegacyFlowLogMigrationAllowlist = [
  {
    name: 'snet-data-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-data'
  }
  {
    name: 'athena-hackathon-web-03-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-web-03-nic'
  }
  {
    name: 'athena-hackathon-ecp-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-ecp-01-nic'
  }
  {
    name: 'athena-hackathon-web-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-web-01-nic'
  }
  {
    name: 'snet-management-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-management'
  }
  {
    name: 'athena-hackathon-ecp-02-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-ecp-02-nic'
  }
  {
    name: 'snet-client-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-client'
  }
  {
    name: 'athena-hackathon-iris-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-iris-01-nic'
  }
  {
    name: 'snet-middle-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-middle'
  }
  {
    name: 'athena-hackathon-mid-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-mid-01-nic'
  }
  {
    name: 'athena-hackathon-sqlvm-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-sqlvm-01-nic'
  }
  {
    name: 'athena-hackathon-mid-02-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-mid-02-nic'
  }
  {
    name: 'snet-web-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-web'
  }
  {
    name: 'athena-hackathon-web-02-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-web-02-nic'
  }
  {
    name: 'athena-hackathon-ecp-03-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-ecp-03-nic'
  }
  {
    name: 'snet-appgw-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-appgw'
  }
  {
    name: 'athena-hackathon-client-01-nic-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/networkInterfaces/athena-hackathon-client-01-nic'
  }
  {
    name: 'snet-paas-private-endpoints-rg-athena-demo-workload-flowlog'
    targetResourceId: '${workloadScopeId}/virtualNetworks/athena-hackathon-vnet/subnets/snet-paas-private-endpoints'
  }
]
var requestedLegacyFlowLogMigrations = [
  for (flowLogName, index) in legacyFlowLogNames: {
    name: string(flowLogName)
    targetResourceId: string(legacyFlowLogTargetResourceIds[index])
  }
]
var reviewedLegacyFlowLogMigrationPairs = [
  for reviewedMigration in reviewedLegacyFlowLogMigrationAllowlist: '${toLower(string(reviewedMigration.name))}|${toLower(string(reviewedMigration.targetResourceId))}'
]
var requestedLegacyFlowLogMigrationPairs = [
  for requestedMigration in requestedLegacyFlowLogMigrations: '${toLower(requestedMigration.name)}|${toLower(requestedMigration.targetResourceId)}'
]
var unreviewedLegacyFlowLogMigrationPairs = filter(requestedLegacyFlowLogMigrationPairs, requestedPair => !contains(reviewedLegacyFlowLogMigrationPairs, requestedPair))
var legacyFlowLogMigrationIsValid = length(legacyFlowLogNames) == length(legacyFlowLogTargetResourceIds) && empty(unreviewedLegacyFlowLogMigrationPairs) && !contains(map(legacyFlowLogNames, flowLogName => toLower(string(flowLogName))), toLower(canonicalVnetFlowLogName)) && !contains(map(legacyFlowLogTargetResourceIds, targetResourceId => toLower(string(targetResourceId))), toLower(workloadVirtualNetworkResourceId)) && (empty(legacyFlowLogNames) || canonicalVnetFlowLogCutoverConfirmed)
var validatedLegacyFlowLogMigrations = legacyFlowLogMigrationIsValid ? requestedLegacyFlowLogMigrations : fail('legacy flow-log migration requires exact reviewed name/target allowlist entries, paired non-VNet targets, and explicit canonical VNet cutover confirmation')

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource existingLegacyFlowLogs 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' existing = [
  for legacyFlowLogMigration in validatedLegacyFlowLogMigrations: {
    parent: networkWatcher
    name: legacyFlowLogMigration.name
  }
]

resource legacyFlowLogs 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' = [
  for (legacyFlowLogMigration, index) in validatedLegacyFlowLogMigrations: {
    parent: networkWatcher
    name: legacyFlowLogMigration.name
    properties: {
      targetResourceId: toLower(existingLegacyFlowLogs[index].properties.targetResourceId) == toLower(legacyFlowLogMigration.targetResourceId) && toLower(existingLegacyFlowLogs[index].properties.storageId) == toLower(legacyFlowLogStorageAccountResourceId)
        ? legacyFlowLogMigration.targetResourceId
        : fail('WC-024 refuses to disable a legacy flow log unless its existing target and storage account match the reviewed allowlist.')
      storageId: replacementStorageAccountResourceId
      enabled: false
      retentionPolicy: {
        days: 0
        enabled: false
      }
      format: {
        type: 'JSON'
        version: 2
      }
      flowAnalyticsConfiguration: {
        networkWatcherFlowAnalyticsConfiguration: {
          enabled: false
        }
      }
    }
  }
]

output disabledLegacyFlowLogNames array = [for migration in validatedLegacyFlowLogMigrations: migration.name]
