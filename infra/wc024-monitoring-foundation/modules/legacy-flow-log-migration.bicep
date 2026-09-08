targetScope = 'resourceGroup'

@description('Existing regional Network Watcher containing the canonical and redundant flow logs.')
param networkWatcherName string

@description('Name of the enabled canonical VNet flow log that must complete cutover first.')
param canonicalVnetFlowLogName string

@description('VNet resource ID owned by the enabled canonical VNet flow log.')
param workloadVirtualNetworkResourceId string

@description('Replacement monitoring storage account configured on disabled redundant flow logs.')
param replacementStorageAccountResourceId string

@description('Explicit reviewed names of redundant subnet or NIC flow logs to disable.')
@maxLength(32)
param legacyFlowLogNames array = []

@description('Explicit reviewed target resource IDs paired by index with legacyFlowLogNames.')
@maxLength(32)
param legacyFlowLogTargetResourceIds array = []

@description('Must be true only after the canonical VNet flow log is confirmed enabled and writing to replacement storage.')
param canonicalVnetFlowLogCutoverConfirmed bool = false

var legacyFlowLogMigrationIsValid = length(legacyFlowLogNames) == length(legacyFlowLogTargetResourceIds) && !contains(map(legacyFlowLogNames, flowLogName => toLower(string(flowLogName))), toLower(canonicalVnetFlowLogName)) && !contains(map(legacyFlowLogTargetResourceIds, targetResourceId => toLower(string(targetResourceId))), toLower(workloadVirtualNetworkResourceId)) && (empty(legacyFlowLogNames) || canonicalVnetFlowLogCutoverConfirmed)
var validatedLegacyFlowLogNames = legacyFlowLogMigrationIsValid ? legacyFlowLogNames : fail('legacy flow-log migration requires paired non-VNet targets and explicit canonical VNet cutover confirmation')

resource networkWatcher 'Microsoft.Network/networkWatchers@2024-10-01' existing = {
  name: networkWatcherName
}

resource legacyFlowLogs 'Microsoft.Network/networkWatchers/flowLogs@2024-10-01' = [
  for (flowLogName, index) in validatedLegacyFlowLogNames: {
    parent: networkWatcher
    name: string(flowLogName)
    properties: {
      targetResourceId: string(legacyFlowLogTargetResourceIds[index])
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

output disabledLegacyFlowLogNames array = validatedLegacyFlowLogNames
