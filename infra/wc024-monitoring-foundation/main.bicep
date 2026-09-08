targetScope = 'subscription'

metadata name = 'Athena WC-024 generic monitoring foundation'
metadata description = 'Deploys private generic Azure Monitor, VNet flow-log, and isolated evidence-collector foundations without workload-intent-derived thresholds or paths.'

@description('Azure region for monitoring-owned resources.')
param location string = deployment().location

@description('The dedicated resource group owned by the generic monitoring foundation.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string = 'rg-athena-demo-monitoring'

@description('Lowercase prefix for deterministic monitoring resource names.')
@minLength(3)
@maxLength(32)
param namePrefix string = 'athena-demo-monitoring'

@description('Reviewed workload resource group whose VMs receive the generic DCR association.')
@minLength(1)
@maxLength(90)
param workloadResourceGroupName string = 'rg-athena-demo-workload'

@description('Exact names of the 11 reviewed workload VMs that already have successful Azure Monitor Agent deployment and the athena-linux-dcr association. Values must be distinct.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Reviewed workload VNet resource ID used only as the VNet flow-log target.')
param workloadVirtualNetworkResourceId string

@description('Resource group containing the existing regional Network Watcher.')
@minLength(1)
@maxLength(90)
param networkWatcherResourceGroupName string

@description('Existing regional Network Watcher resource name.')
@minLength(1)
@maxLength(80)
param networkWatcherName string

@description('Existing canonical VNet flow-log name. WC-024 updates this resource in place.')
@minLength(1)
@maxLength(80)
param flowLogName string = 'athena-hackathon-vnet-rg-athena-demo-workload-flowlog'

@description('Existing subnet resource ID dedicated to private endpoints.')
param privateEndpointSubnetResourceId string

@description('VNet containing privateEndpointSubnetResourceId. It can differ from workload and collector runtime VNets only when reviewed routing or peering is confirmed.')
param privateEndpointVirtualNetworkResourceId string

@description('VNet hosting the isolated Azure MCP or signed-evidence collector runtime.')
param collectorRuntimeVirtualNetworkResourceId string

@description('Subnet hosting the isolated Azure MCP or signed-evidence collector runtime.')
param collectorRuntimeSubnetResourceId string

@description('Set true only after reviewed routing or peering validation confirms that workload agents can reach the private endpoint VNet when it differs from the workload VNet.')
param workloadPrivateEndpointConnectivityConfirmed bool = false

@description('Set true only after reviewed routing or peering validation confirms that the collector runtime can reach the private endpoint VNet when it differs from the collector runtime VNet.')
param collectorRuntimePrivateEndpointConnectivityConfirmed bool = false

@description('Set true only after reviewed DNS validation confirms that workload agents resolve private endpoint records through the managed zone links or approved forwarding.')
param workloadPrivateDnsResolutionConfirmed bool = false

@description('Set true only after reviewed DNS validation confirms that the collector runtime resolves private endpoint records through the managed zone links or approved forwarding.')
param collectorRuntimePrivateDnsResolutionConfirmed bool = false

@description('Resource group containing the private DNS zones and required workload-VNet links managed by WC-024.')
@minLength(1)
@maxLength(90)
param privateDnsResourceGroupName string = monitoringResourceGroupName

@description('Globally unique lowercase storage account name for replacement flow-log and collector evidence storage.')
@minLength(3)
@maxLength(24)
param monitoringStorageAccountName string

@description('Globally unique Key Vault name for the isolated monitoring collector signing key.')
@minLength(3)
@maxLength(24)
param monitoringCollectorKeyVaultName string

@description('Unambiguous GUID used for the custom isolated monitoring evidence-reader role.')
param collectorRoleDefinitionGuid string

@description('Retention period for replacement flow-log and signed-evidence data.')
@minValue(30)
@maxValue(365)
param retentionDays int = 30

@description('Existing Log Analytics workspace adopted by WC-024 rather than creating a parallel workspace.')
@minLength(1)
@maxLength(63)
param workspaceName string = 'athena-hackathon-law'

@description('Existing data collection endpoint adopted by WC-024 rather than creating a parallel endpoint.')
@minLength(1)
@maxLength(63)
param dataCollectionEndpointName string = 'athena-hackathon-linux-dce'

@description('Existing data collection rule adopted by WC-024 without overwriting custom data sources or tags.')
@minLength(1)
@maxLength(63)
param dataCollectionRuleName string = 'athena-hackathon-linux-dcr'

@description('Existing DCR-only association name adopted on each approved AMA-enabled VM without a PUT.')
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

@description('Set true only after reviewed private-ingestion evidence confirms all 11 approved VMs retain healthy Azure Monitor Agent and athena-linux-dcr associations, and Heartbeat, Perf, InsightsMetrics, Syslog, AthenaApp_CL, and NTANetAnalytics continue to ingest through the adopted monitoring platform.')
param privateMonitoringIngestionCutoverConfirmed bool = false

@description('Set true only for the reviewed first deployment that creates the Azure Monitor Private Link Scope in Open mode. Leave false for every later deployment so its existing mode is adopted and cannot be reopened.')
param createPrivateLinkScope bool = false

var resourceTags = union(tags, {
  component: 'wc024-monitoring-foundation'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})
var legacyFlowLogStorageAccountName = 'athenahackathonflowwhtco'
var workloadResourceGroupId = '${subscription().id}/resourceGroups/${workloadResourceGroupName}'
var networkWatcherResourceGroupId = '${subscription().id}/resourceGroups/${networkWatcherResourceGroupName}'
var validatedCreatePrivateLinkScope = createPrivateLinkScope && privateMonitoringIngestionCutoverConfirmed
  ? fail('WC-024 cannot create an Open Azure Monitor Private Link Scope during the private-only cutover. Adopt the existing scope so its PrivateOnly mode is preserved.')
  : createPrivateLinkScope

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
    tags: resourceTags
    createPrivateLinkScope: validatedCreatePrivateLinkScope
  }
}

module privateRuntimeTopologyValidation 'modules/private-runtime-topology-validation.bicep' = {
  name: 'validate-private-runtime-topology'
  scope: monitoringResourceGroup
  params: {
    workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
    privateEndpointVirtualNetworkResourceId: privateEndpointVirtualNetworkResourceId
    privateEndpointSubnetResourceId: privateEndpointSubnetResourceId
    collectorRuntimeVirtualNetworkResourceId: collectorRuntimeVirtualNetworkResourceId
    collectorRuntimeSubnetResourceId: collectorRuntimeSubnetResourceId
    workloadPrivateEndpointConnectivityConfirmed: workloadPrivateEndpointConnectivityConfirmed
    collectorRuntimePrivateEndpointConnectivityConfirmed: collectorRuntimePrivateEndpointConnectivityConfirmed
    workloadPrivateDnsResolutionConfirmed: workloadPrivateDnsResolutionConfirmed
    collectorRuntimePrivateDnsResolutionConfirmed: collectorRuntimePrivateDnsResolutionConfirmed
    privateMonitoringIngestionCutoverConfirmed: privateMonitoringIngestionCutoverConfirmed
  }
}

module dcrAssociationValidation 'modules/dcr-association-validation.bicep' = {
  name: 'validate-adopted-dcr-associations'
  scope: resourceGroup(workloadResourceGroupName)
  params: {
    approvedVmNames: approvedVmNames
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
    approvedVmNames: approvedVmNames
    dataCollectionEndpointResourceId: monitoringDataPlatform.outputs.dataCollectionEndpointResourceId
    dataCollectionEndpointLocation: monitoringDataPlatform.outputs.dataCollectionEndpointLocation
    dataCollectionEndpointAssociationName: dataCollectionEndpointAssociationName
    validatedDataCollectionRuleAssociationResourceIds: dcrAssociationValidation.outputs.validatedAdoptedDataCollectionRuleAssociationResourceIds
  }
}

module privateDnsZones 'modules/private-dns-zones.bicep' = {
  name: 'monitoring-private-dns-zones'
  scope: resourceGroup(privateDnsResourceGroupName)
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
  params: {
    location: location
    namePrefix: namePrefix
    storageAccountName: monitoringStorageAccountName
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
    privateEndpointSubnetResourceId: privateRuntimeTopologyValidation.outputs.privateEndpointSubnetResourceId
    azureMonitorPrivateLinkScopeResourceId: monitoringDataPlatform.outputs.privateLinkScopeResourceId
    storageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    keyVaultResourceId: monitoringEvidenceSeams.outputs.keyVaultResourceId
    storageBlobPrivateDnsZoneResourceId: privateDnsZones.outputs.storageBlobPrivateDnsZoneResourceId
    keyVaultPrivateDnsZoneResourceId: privateDnsZones.outputs.keyVaultPrivateDnsZoneResourceId
    azureMonitorPrivateDnsZoneResourceIds: privateDnsZones.outputs.azureMonitorPrivateDnsZoneResourceIds
    tags: resourceTags
  }
  dependsOn: [
    dcrAssociations
  ]
}

module privateDnsVnetLinks 'modules/private-dns-vnet-links.bicep' = {
  name: 'monitoring-private-dns-vnet-links'
  scope: resourceGroup(privateDnsResourceGroupName)
  dependsOn: [
    monitoringPrivateEndpoints
  ]
  params: {
    namePrefix: namePrefix
    workloadVirtualNetworkResourceId: privateRuntimeTopologyValidation.outputs.workloadVirtualNetworkResourceId
    collectorRuntimeVirtualNetworkResourceId: privateRuntimeTopologyValidation.outputs.collectorRuntimeVirtualNetworkResourceId
  }
}

module monitoringEvidenceReaderRole 'modules/monitoring-evidence-reader-role.bicep' = {
  name: 'monitoring-evidence-reader-role'
  params: {
    roleDefinitionGuid: collectorRoleDefinitionGuid
    assignableScopes: [
      monitoringResourceGroup.id
      workloadResourceGroupId
      networkWatcherResourceGroupId
    ]
  }
}

module monitoringResourceReaderAssignment 'modules/monitoring-evidence-reader-rbac.bicep' = {
  name: 'monitoring-resource-reader-assignment'
  scope: monitoringResourceGroup
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    roleDefinitionId: monitoringEvidenceReaderRole.outputs.roleDefinitionId
  }
}

module workloadAssociationReaderAssignment 'modules/monitoring-evidence-reader-rbac.bicep' = {
  name: 'workload-association-reader-assignment'
  scope: resourceGroup(workloadResourceGroupName)
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    roleDefinitionId: monitoringEvidenceReaderRole.outputs.roleDefinitionId
  }
}

module networkWatcherReaderAssignment 'modules/monitoring-evidence-reader-rbac.bicep' = {
  name: 'network-watcher-reader-assignment'
  scope: resourceGroup(networkWatcherResourceGroupName)
  params: {
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
    roleDefinitionId: monitoringEvidenceReaderRole.outputs.roleDefinitionId
  }
}

module monitoringPrivateAccess 'modules/monitoring-private-access.bicep' = if (privateMonitoringIngestionCutoverConfirmed) {
  name: 'disable-adopted-monitoring-public-access'
  scope: monitoringResourceGroup
  dependsOn: [
    monitoringPrivateEndpoints
    privateDnsVnetLinks
    dcrAssociations
    dcrAssociationValidation
    privateRuntimeTopologyValidation
  ]
  params: {
    workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation
    workspaceName: workspaceName
    workspaceTags: monitoringDataPlatform.outputs.workspaceTags
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionEndpointLocation: monitoringDataPlatform.outputs.dataCollectionEndpointLocation
    dataCollectionEndpointTags: monitoringDataPlatform.outputs.dataCollectionEndpointTags
    dataCollectionEndpointDescription: monitoringDataPlatform.outputs.?dataCollectionEndpointDescription
    dataCollectionEndpointKind: monitoringDataPlatform.outputs.?dataCollectionEndpointKind
    privateLinkScopeName: '${namePrefix}-ampls'
    privateLinkScopeTags: monitoringDataPlatform.outputs.privateLinkScopeTags
    privateLinkScopeAccessModeExclusions: monitoringDataPlatform.outputs.privateLinkScopeAccessModeExclusions
    workspaceSkuName: monitoringDataPlatform.outputs.workspaceSkuName
    workspaceRetentionDays: monitoringDataPlatform.outputs.workspaceRetentionDays
    workspaceDailyQuotaGb: monitoringDataPlatform.outputs.workspaceDailyQuotaGb
    workspaceFeatures: monitoringDataPlatform.outputs.workspaceFeatures
  }
}

module vnetFlowLog 'modules/vnet-flow-log.bicep' = {
  name: 'adopt-vnet-flow-log-with-traffic-analytics'
  scope: resourceGroup(networkWatcherResourceGroupName)
  params: {
    networkWatcherName: networkWatcherName
    flowLogName: flowLogName
    workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
    storageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
    workspaceCustomerId: monitoringDataPlatform.outputs.workspaceCustomerId
    workspaceResourceId: monitoringDataPlatform.outputs.workspaceResourceId
    workspaceLocation: monitoringDataPlatform.outputs.workspaceLocation
    retentionDays: retentionDays
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
    workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
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
    workspaceResourceId: monitoringDataPlatform.outputs.workspaceResourceId
    dataCollectionRuleResourceId: monitoringDataPlatform.outputs.dataCollectionRuleResourceId
    dataCollectionEndpointResourceId: monitoringDataPlatform.outputs.dataCollectionEndpointResourceId
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
