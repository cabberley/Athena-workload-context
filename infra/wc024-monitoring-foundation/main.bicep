targetScope = 'subscription'

metadata name = 'Athena WC-024 generic monitoring foundation'
metadata description = 'Deploys private generic Azure Monitor, VNet flow-log, and isolated evidence-collector foundations without workload-intent-derived thresholds or paths.'

@description('Reviewed Azure region for monitoring-owned resources and private endpoints.')
@allowed([
  'australiaeast'
])
param location string = 'australiaeast'

@description('The dedicated resource group owned by the generic monitoring foundation.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string = 'rg-athena-demo-monitoring'

@description('Lowercase prefix for deterministic monitoring resource names.')
@allowed([
  'athena-demo-monitoring'
])
@minLength(3)
@maxLength(32)
param namePrefix string = 'athena-demo-monitoring'

@description('Reviewed workload resource group whose VMs receive the generic DCR association.')
@allowed([
  'rg-athena-demo-workload'
])
param workloadResourceGroupName string = 'rg-athena-demo-workload'

@description('Exact names of the 11 reviewed workload VMs that already have successful Azure Monitor Agent deployment and the athena-linux-dcr association. Values must be distinct.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Reviewed workload VNet resource ID used only as the VNet flow-log target.')
param workloadVirtualNetworkResourceId string

@description('Resource group containing the existing regional Network Watcher.')
@allowed([
  'NetworkWatcherRG'
])
@minLength(1)
@maxLength(90)
param networkWatcherResourceGroupName string

@description('Existing regional Network Watcher resource name.')
@allowed([
  'NetworkWatcher_australiaeast'
])
@minLength(1)
@maxLength(80)
param networkWatcherName string

@description('Existing canonical VNet flow-log name. WC-024 updates this resource in place.')
@allowed([
  'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'
])
@minLength(1)
@maxLength(80)
param flowLogName string = 'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'

@description('Exact workload-local private endpoint subnet resource ID.')
param workloadPrivateEndpointSubnetResourceId string

@description('VNet hosting the isolated Azure MCP or signed-evidence collector runtime.')
param collectorRuntimeVirtualNetworkResourceId string

@description('Subnet hosting the isolated Azure MCP or signed-evidence collector runtime.')
param collectorRuntimeSubnetResourceId string

@description('Exact collector-local private endpoint subnet resource ID.')
param collectorPrivateEndpointSubnetResourceId string

@description('Globally unique lowercase storage account name for replacement flow-log and collector evidence storage.')
@minLength(3)
@maxLength(24)
param monitoringStorageAccountName string

@description('Globally unique Key Vault name for the isolated monitoring collector signing key.')
@minLength(3)
@maxLength(24)
param monitoringCollectorKeyVaultName string

@description('Retention period for replacement flow-log and signed-evidence data.')
@minValue(30)
@maxValue(365)
param retentionDays int = 30

@description('Existing Log Analytics workspace adopted by WC-024 rather than creating a parallel workspace.')
@allowed([
  'athena-hackathon-law'
])
@minLength(1)
@maxLength(63)
param workspaceName string = 'athena-hackathon-law'

@description('Existing data collection endpoint adopted by WC-024 rather than creating a parallel endpoint.')
@allowed([
  'athena-hackathon-linux-dce'
])
@minLength(1)
@maxLength(63)
param dataCollectionEndpointName string = 'athena-hackathon-linux-dce'

@description('Existing data collection rule adopted by WC-024 without overwriting custom data sources or tags.')
@allowed([
  'athena-hackathon-linux-dcr'
])
@minLength(1)
@maxLength(63)
param dataCollectionRuleName string = 'athena-hackathon-linux-dcr'

@description('Existing DCR-only association name adopted on each approved AMA-enabled VM without a PUT.')
@allowed([
  'athena-linux-dcr'
])
@minLength(1)
@maxLength(64)
param dataCollectionRuleAssociationName string = 'athena-linux-dcr'

@description('Separate DCE-only association created on each approved AMA-enabled VM.')
@allowed([
  'configurationAccessEndpoint'
])
param dataCollectionEndpointAssociationName string = 'configurationAccessEndpoint'

@description('Maximum accepted age for a signed monitoring evidence handoff.')
@minValue(60)
@maxValue(900)
param maximumEvidenceAgeSeconds int = 600

@description('Connection Monitor definitions remain disabled until an exact published intent is reconciled.')
param connectionMonitorDeploymentEnabled bool = false

@description('Resource tags applied to WC-024 resources.')
param tags object = {}

@description('Explicit reviewed redundant subnet or NIC flow-log names to disable after canonical VNet cutover. No target means no migration.')
@maxLength(32)
param legacyFlowLogNames array = []

@description('Explicit reviewed subnet or NIC IDs paired by index with legacyFlowLogNames. No target means no migration.')
@maxLength(32)
param legacyFlowLogTargetResourceIds array = []

@description('Set true only after the existing canonical VNet flow log is confirmed enabled and writing to replacement storage.')
param canonicalVnetFlowLogCutoverConfirmed bool = false

var resourceTags = union(tags, {
  component: 'wc024-monitoring-foundation'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})
var legacyFlowLogStorageAccountName = 'athenahackathonflowwhtco'
var workloadResourceGroupId = '${subscription().id}/resourceGroups/${workloadResourceGroupName}'
var reviewedWorkloadVirtualNetworkResourceId = '${workloadResourceGroupId}/providers/Microsoft.Network/virtualNetworks/athena-hackathon-vnet'
var reviewedWorkloadPrivateEndpointSubnetResourceId = '${reviewedWorkloadVirtualNetworkResourceId}/subnets/snet-paas-private-endpoints'
var reviewedCollectorRuntimeVirtualNetworkResourceId = '${monitoringResourceGroup.id}/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet'
var reviewedCollectorRuntimeSubnetResourceId = '${reviewedCollectorRuntimeVirtualNetworkResourceId}/subnets/collector-runtime'
var reviewedCollectorPrivateEndpointSubnetResourceId = '${reviewedCollectorRuntimeVirtualNetworkResourceId}/subnets/private-endpoints'
var reviewedApprovedVmNames = [
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
var normalizedApprovedVmNames = map(approvedVmNames, vmName => toLower(string(vmName)))
var uniqueApprovedVmNames = union(normalizedApprovedVmNames, [])
var unreviewedApprovedVmNames = filter(normalizedApprovedVmNames, vmName => !contains(reviewedApprovedVmNames, vmName))
var missingReviewedVmNames = filter(reviewedApprovedVmNames, vmName => !contains(normalizedApprovedVmNames, vmName))
var validatedApprovedVmNames = empty(unreviewedApprovedVmNames) && empty(missingReviewedVmNames) && length(uniqueApprovedVmNames) == length(reviewedApprovedVmNames)
  ? reviewedApprovedVmNames
  : fail('WC-024 approvedVmNames must match the exact reviewed 11-VM workload allowlist.')
var validatedWorkloadVirtualNetworkResourceId = toLower(workloadVirtualNetworkResourceId) == toLower(reviewedWorkloadVirtualNetworkResourceId)
  ? reviewedWorkloadVirtualNetworkResourceId
  : fail('WC-024 workloadVirtualNetworkResourceId must match the reviewed rg-athena-demo-workload VNet in the deployment subscription.')
var validatedWorkloadPrivateEndpointSubnetResourceId = toLower(workloadPrivateEndpointSubnetResourceId) == toLower(reviewedWorkloadPrivateEndpointSubnetResourceId)
  ? reviewedWorkloadPrivateEndpointSubnetResourceId
  : fail('WC-024 workloadPrivateEndpointSubnetResourceId must match the reviewed workload private-endpoint subnet.')
var validatedCollectorRuntimeVirtualNetworkResourceId = toLower(collectorRuntimeVirtualNetworkResourceId) == toLower(reviewedCollectorRuntimeVirtualNetworkResourceId)
  ? reviewedCollectorRuntimeVirtualNetworkResourceId
  : fail('WC-024 collectorRuntimeVirtualNetworkResourceId must match the dedicated WC-024 collector VNet.')
var validatedCollectorRuntimeSubnetResourceId = toLower(collectorRuntimeSubnetResourceId) == toLower(reviewedCollectorRuntimeSubnetResourceId)
  ? reviewedCollectorRuntimeSubnetResourceId
  : fail('WC-024 collectorRuntimeSubnetResourceId must match the dedicated WC-024 collector runtime subnet.')
var validatedCollectorPrivateEndpointSubnetResourceId = toLower(collectorPrivateEndpointSubnetResourceId) == toLower(reviewedCollectorPrivateEndpointSubnetResourceId)
  ? reviewedCollectorPrivateEndpointSubnetResourceId
  : fail('WC-024 collectorPrivateEndpointSubnetResourceId must match the dedicated WC-024 collector private-endpoint subnet.')
resource monitoringResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: monitoringResourceGroupName
}

module monitoringDataPlatform 'modules/monitoring-data-platform.bicep' = {
  name: 'adopt-monitoring-data-platform'
  scope: monitoringResourceGroup
  params: {
    namePrefix: namePrefix
    workspaceName: workspaceName
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionRuleName: dataCollectionRuleName
  }
}

module privateRuntimeTopologyValidation 'modules/private-runtime-topology-validation.bicep' = {
  name: 'validate-private-runtime-topology'
  scope: monitoringResourceGroup
  params: {
    workloadVirtualNetworkResourceId: validatedWorkloadVirtualNetworkResourceId
    workloadPrivateEndpointSubnetResourceId: validatedWorkloadPrivateEndpointSubnetResourceId
    collectorRuntimeVirtualNetworkResourceId: validatedCollectorRuntimeVirtualNetworkResourceId
    collectorRuntimeSubnetResourceId: validatedCollectorRuntimeSubnetResourceId
    collectorPrivateEndpointSubnetResourceId: validatedCollectorPrivateEndpointSubnetResourceId
  }
}

module dcrAssociationValidation 'modules/dcr-association-validation.bicep' = {
  name: 'validate-adopted-dcr-associations'
  scope: resourceGroup(workloadResourceGroupName)
  params: {
    approvedVmNames: validatedApprovedVmNames
    dataCollectionRuleResourceId: monitoringDataPlatform.outputs.dataCollectionRuleResourceId
    dataCollectionRuleAssociationName: dataCollectionRuleAssociationName
  }
}

module dcrAssociations 'modules/dcr-associations.bicep' = {
  name: 'create-dce-associations-after-dcr-validation'
  scope: resourceGroup(workloadResourceGroupName)
  dependsOn: [
    #disable-next-line no-unnecessary-dependson // Retain the review-visible all-or-nothing validation barrier before DCE association PUTs.
    dcrAssociationValidation
  ]
  params: {
    approvedVmNames: validatedApprovedVmNames
    dataCollectionEndpointResourceId: monitoringDataPlatform.outputs.dataCollectionEndpointResourceId
    dataCollectionEndpointLocation: monitoringDataPlatform.outputs.dataCollectionEndpointLocation
    dataCollectionEndpointAssociationName: dataCollectionEndpointAssociationName
    validatedDataCollectionRuleAssociationResourceIds: dcrAssociationValidation.outputs.validatedAdoptedDataCollectionRuleAssociationResourceIds
  }
}

module workloadPrivateDnsZones 'modules/private-dns-zones.bicep' = {
  name: 'workload-monitoring-private-dns-zones'
  scope: resourceGroup(workloadResourceGroupName)
  dependsOn: [
    dcrAssociations
  ]
  params: {
    tags: resourceTags
  }
}

module collectorPrivateDnsZones 'modules/private-dns-zones.bicep' = {
  name: 'collector-monitoring-private-dns-zones'
  scope: monitoringResourceGroup
  dependsOn: [
    dcrAssociations
  ]
  params: {
    tags: resourceTags
  }
}

module collectorKeyVaultPrivateDns 'modules/collector-key-vault-private-dns.bicep' = {
  name: 'collector-key-vault-private-dns'
  scope: monitoringResourceGroup
  dependsOn: [
    dcrAssociations
  ]
  params: {
    tags: resourceTags
  }
}

module monitoringStorage 'modules/monitoring-flow-log-storage.bicep' = {
  name: 'monitoring-flow-log-storage'
  scope: monitoringResourceGroup
  params: {
    location: location
    storageAccountName: monitoringStorageAccountName
    retentionDays: retentionDays
    tags: resourceTags
  }
}

module monitoringEvidenceSeams 'modules/monitoring-evidence-seams.bicep' = {
  name: 'monitoring-evidence-seams'
  scope: monitoringResourceGroup
  dependsOn: [
    #disable-next-line no-unnecessary-dependson // Preserve review-visible container creation before evidence writer RBAC.
    monitoringStorage
  ]
  params: {
    location: location
    namePrefix: namePrefix
    storageAccountName: monitoringStorageAccountName
    monitoringEvidenceContainerResourceId: monitoringStorage.outputs.monitoringEvidenceContainerResourceId
    keyVaultName: monitoringCollectorKeyVaultName
    tags: resourceTags
  }
}

module monitoringPrivateEndpoints 'modules/monitoring-private-endpoints.bicep' = {
  name: 'monitoring-private-endpoints'
  scope: monitoringResourceGroup
  params: {
    location: location
    namePrefix: namePrefix
    workloadPrivateEndpointSubnetResourceId: privateRuntimeTopologyValidation.outputs.workloadPrivateEndpointSubnetResourceId
    collectorPrivateEndpointSubnetResourceId: privateRuntimeTopologyValidation.outputs.collectorPrivateEndpointSubnetResourceId
    workloadAzureMonitorPrivateLinkScopeResourceId: monitoringDataPlatform.outputs.workloadPrivateLinkScopeResourceId
    collectorAzureMonitorPrivateLinkScopeResourceId: monitoringDataPlatform.outputs.collectorPrivateLinkScopeResourceId
    storageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    keyVaultResourceId: monitoringEvidenceSeams.outputs.keyVaultResourceId
    workloadStorageBlobPrivateDnsZoneResourceId: workloadPrivateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId
    collectorStorageBlobPrivateDnsZoneResourceId: collectorPrivateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId
    collectorKeyVaultPrivateDnsZoneResourceId: collectorKeyVaultPrivateDns.outputs.keyVaultPrivateDnsZoneResourceId
    workloadAzureMonitorPrivateDnsZoneResourceIds: workloadPrivateDnsZones.outputs.azureMonitorPrivateDnsZoneResourceIds
    collectorAzureMonitorPrivateDnsZoneResourceIds: collectorPrivateDnsZones.outputs.azureMonitorPrivateDnsZoneResourceIds
    tags: resourceTags
  }
  dependsOn: [
    dcrAssociations
  ]
}

module workloadPrivateDnsVnetLinks 'modules/private-dns-vnet-links.bicep' = {
  name: 'workload-monitoring-private-dns-vnet-links'
  scope: resourceGroup(workloadResourceGroupName)
  dependsOn: [
    monitoringPrivateEndpoints
  ]
  params: {
    namePrefix: '${namePrefix}-workload'
    virtualNetworkResourceId: privateRuntimeTopologyValidation.outputs.workloadVirtualNetworkResourceId
  }
}

module collectorPrivateDnsVnetLinks 'modules/private-dns-vnet-links.bicep' = {
  name: 'collector-monitoring-private-dns-vnet-links'
  scope: monitoringResourceGroup
  dependsOn: [
    monitoringPrivateEndpoints
  ]
  params: {
    namePrefix: '${namePrefix}-collector'
    virtualNetworkResourceId: privateRuntimeTopologyValidation.outputs.collectorRuntimeVirtualNetworkResourceId
  }
}

module collectorKeyVaultPrivateDnsLink 'modules/collector-key-vault-private-dns-link.bicep' = {
  name: 'collector-key-vault-private-dns-link'
  scope: monitoringResourceGroup
  dependsOn: [
    monitoringPrivateEndpoints
  ]
  params: {
    namePrefix: '${namePrefix}-collector'
    collectorVirtualNetworkResourceId: privateRuntimeTopologyValidation.outputs.collectorRuntimeVirtualNetworkResourceId
  }
}

module monitoringEvidenceReaderAssignments 'modules/monitoring-evidence-reader-rbac.bicep' = {
  name: 'monitoring-evidence-reader-assignments'
  scope: monitoringResourceGroup
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    workspaceName: workspaceName
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionRuleName: dataCollectionRuleName
    privateLinkScopeNames: [
      '${namePrefix}-workload-ampls'
      '${namePrefix}-collector-ampls'
    ]
  }
}

module workloadEvidenceReaderAssignments 'modules/workload-monitoring-evidence-reader-rbac.bicep' = {
  name: 'workload-monitoring-evidence-reader-assignments'
  scope: resourceGroup(workloadResourceGroupName)
  dependsOn: [
    dcrAssociations
  ]
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    approvedVmNames: validatedApprovedVmNames
    dataCollectionRuleAssociationName: dataCollectionRuleAssociationName
    dataCollectionEndpointAssociationName: dataCollectionEndpointAssociationName
  }
}

module canonicalFlowLogValidation 'modules/canonical-flow-log-validation.bicep' = {
  name: 'validate-canonical-vnet-flow-log'
  scope: resourceGroup(networkWatcherResourceGroupName)
  params: {
    networkWatcherName: networkWatcherName
    flowLogName: flowLogName
    workloadVirtualNetworkResourceId: validatedWorkloadVirtualNetworkResourceId
  }
}

module vnetFlowLog 'modules/vnet-flow-log.bicep' = {
  name: 'adopt-vnet-flow-log-with-traffic-analytics'
  scope: resourceGroup(networkWatcherResourceGroupName)
  params: {
    networkWatcherName: networkWatcherName
    flowLogName: canonicalFlowLogValidation.outputs.validatedFlowLogName
    workloadVirtualNetworkResourceId: canonicalFlowLogValidation.outputs.validatedTargetResourceId
    storageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    workspaceCustomerId: monitoringDataPlatform.outputs.workspaceCustomerId
    workspaceResourceId: monitoringDataPlatform.outputs.workspaceResourceId
    workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation
    retentionDays: retentionDays
  }
}

module networkWatcherEvidenceReaderAssignment 'modules/network-watcher-monitoring-evidence-reader-rbac.bicep' = {
  name: 'network-watcher-monitoring-evidence-reader-assignment'
  scope: resourceGroup(networkWatcherResourceGroupName)
  dependsOn: [
    vnetFlowLog
  ]
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    networkWatcherName: networkWatcherName
    flowLogName: canonicalFlowLogValidation.outputs.validatedFlowLogName
  }
}

module legacyFlowLogMigration 'modules/legacy-flow-log-migration.bicep' = {
  name: 'disable-redundant-legacy-flow-logs'
  scope: resourceGroup(networkWatcherResourceGroupName)
  dependsOn: [
    vnetFlowLog
  ]
  params: {
    networkWatcherName: networkWatcherName
    canonicalVnetFlowLogName: flowLogName
    workloadVirtualNetworkResourceId: validatedWorkloadVirtualNetworkResourceId
    replacementStorageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    legacyFlowLogNames: legacyFlowLogNames
    legacyFlowLogTargetResourceIds: legacyFlowLogTargetResourceIds
    canonicalVnetFlowLogCutoverConfirmed: canonicalVnetFlowLogCutoverConfirmed
  }
}

module connectionMonitorCapability 'modules/connection-monitor-capability.bicep' = {
  name: 'connection-monitor-capability'
  scope: monitoringResourceGroup
  params: {
    connectionMonitorDeploymentEnabled: connectionMonitorDeploymentEnabled
  }
}

module collectorContract 'modules/monitoring-collector-contract.bicep' = {
  name: 'monitoring-collector-contract'
  scope: monitoringResourceGroup
  params: {
    collectorIdentityResourceId: monitoringEvidenceSeams.outputs.collectorIdentityResourceId
    collectorIdentityClientId: monitoringEvidenceSeams.outputs.collectorIdentityClientId
    monitoringResourceGroupId: monitoringResourceGroup.id
    workloadResourceGroupId: workloadResourceGroupId
    workloadVirtualNetworkResourceId: validatedWorkloadVirtualNetworkResourceId
    approvedVmNames: validatedApprovedVmNames
    workspaceResourceId: monitoringDataPlatform.outputs.workspaceResourceId
    dataCollectionRuleResourceId: monitoringDataPlatform.outputs.dataCollectionRuleResourceId
    dataCollectionEndpointResourceId: monitoringDataPlatform.outputs.dataCollectionEndpointResourceId
    authorizationMode: 'conditionedWorkspacePlusExactResourceContext'
    workspaceAccessControlMode: monitoringDataPlatform.outputs.workspaceResourceContextAccessEnabled
      ? 'workspaceAndResourceContext'
      : 'workspaceOnly'
    readerRoleDefinitionId: monitoringEvidenceReaderAssignments.outputs.readerRoleDefinitionId
    signalReaderRoleDefinitionId: workloadEvidenceReaderAssignments.outputs.signalReaderRoleDefinitionId
    logAnalyticsDataReaderRoleDefinitionId: monitoringEvidenceReaderAssignments.outputs.logAnalyticsDataReaderRoleDefinitionId
    logAnalyticsAllowedTables: monitoringEvidenceReaderAssignments.outputs.allowedLogTableNames
    logAnalyticsAccessCondition: monitoringEvidenceReaderAssignments.outputs.logAnalyticsAccessCondition
    resourceReadScopeIds: concat(
      monitoringEvidenceReaderAssignments.outputs.resourceReadScopeIds,
      workloadEvidenceReaderAssignments.outputs.resourceReadScopeIds,
      networkWatcherEvidenceReaderAssignment.outputs.resourceReadScopeIds
    )
    signalReadScopeIds: workloadEvidenceReaderAssignments.outputs.signalReadScopeIds
    signingKeyResourceId: monitoringEvidenceSeams.outputs.signingKeyResourceId
    evidenceStorageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    maximumEvidenceAgeSeconds: maximumEvidenceAgeSeconds
    connectionMonitorDeploymentMode: connectionMonitorCapability.outputs.deploymentMode
  }
}

@description('Exact generic monitoring collector contract that must be captured, reviewed, and signed before a collector runs.')
output monitoringCollectorContract object = collectorContract.outputs.collectorContract

@description('Monitoring-owned replacement storage. It is separate from the retained legacy flow-log destination.')
output replacementMonitoringStorageAccountResourceId string = monitoringStorage.outputs.storageAccountResourceId

@description('Legacy flow-log storage blobs are retained. Redundant configured writers are disabled only through the reviewed migration inputs.')
output retainedLegacyFlowLogStorageAccountName string = legacyFlowLogStorageAccountName

@description('Generic-only Connection Monitor state. No endpoint path definitions are created by WC-024.')
output connectionMonitorDeploymentMode string = connectionMonitorCapability.outputs.deploymentMode

@description('Existing custom DCR data flow retained because WC-024 adopts the DCR without replacing it.')
output preservedCustomLogFlow object = {
  stream: monitoringDataPlatform.outputs.preservedCustomLogStream
  table: monitoringDataPlatform.outputs.preservedCustomLogTable
}

@description('Existing DCR associations adopted without modification on the approved VMs.')
output adoptedDataCollectionRuleAssociationResourceIds array = dcrAssociationValidation.outputs.validatedAdoptedDataCollectionRuleAssociationResourceIds

@description('Separate DCE-only associations created on the approved VMs.')
output dataCollectionEndpointAssociationResourceIds array = dcrAssociations.outputs.dataCollectionEndpointAssociationResourceIds

@description('Redundant subnet or NIC flow logs disabled only after the approved canonical VNet flow-log cutover.')
output disabledLegacyFlowLogNames array = legacyFlowLogMigration.outputs.disabledLegacyFlowLogNames
