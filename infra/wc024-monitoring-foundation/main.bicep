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

@description('Exact existing Athena context UAMI resource ID. Its resource and principal identities must differ from the monitoring collector UAMI.')
param athenaContextIdentityResourceId string

var athenaContextIdentitySegments = split(toLower(athenaContextIdentityResourceId), '/')
resource athenaContextIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  scope: resourceGroup(athenaContextIdentitySegments[2], athenaContextIdentitySegments[4])
  name: athenaContextIdentitySegments[8]
}

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
var legacyFlowLogStorageAccountResourceId = '${workloadResourceGroupId}/providers/Microsoft.Storage/storageAccounts/${legacyFlowLogStorageAccountName}'
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
    location: location
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

module monitoringRbacAttestor 'modules/monitoring-rbac-attestor.bicep' = {
  name: 'monitoring-effective-rbac-attestor'
  scope: subscription()
  params: {
    attestorPrincipalId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId
  }
}

module monitoringIdentityProofAuthority 'modules/monitoring-identity-proof-authority.bicep' = {
  name: 'monitoring-identity-proof-authority'
  params: {
    tenantId: monitoringEvidenceSeams.outputs.collectorIdentityTenantId
    collectorPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
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
    legacyFlowLogStorageAccountResourceId: legacyFlowLogStorageAccountResourceId
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

var acquisitionIdentitySeparation = toLower(monitoringEvidenceSeams.outputs.collectorIdentityResourceId) != toLower(athenaContextIdentity.id) && toLower(monitoringEvidenceSeams.outputs.collectorIdentityResourceId) != toLower(monitoringEvidenceSeams.outputs.rbacAttestorIdentityResourceId) && toLower(athenaContextIdentity.id) != toLower(monitoringEvidenceSeams.outputs.rbacAttestorIdentityResourceId) && toLower(monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId) != toLower(athenaContextIdentity.properties.principalId) && toLower(monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId) != toLower(monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId) && toLower(athenaContextIdentity.properties.principalId) != toLower(monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId) ? true : fail('monitoring collector, Athena context, and RBAC attestor must be physically separate UAMIs with distinct principal IDs')
var resourceReadScopeIds = concat(
  monitoringEvidenceReaderAssignments.outputs.resourceReadScopeIds,
  workloadEvidenceReaderAssignments.outputs.resourceReadScopeIds,
  networkWatcherEvidenceReaderAssignment.outputs.resourceReadScopeIds
)
var workspaceTableResourceIds = map(
  monitoringEvidenceReaderAssignments.outputs.allowedLogTableNames,
  tableName => '${monitoringDataPlatform.outputs.workspaceResourceId}/tables/${tableName}'
)
var evidenceBlobServiceResourceId = '${monitoringStorage.outputs.storageAccountResourceId}/blobServices/default'
var networkWatcherResourceGroupId = subscriptionResourceId(
  'Microsoft.Resources/resourceGroups',
  networkWatcherResourceGroupName
)
var networkWatcherResourceId = resourceId(
  networkWatcherResourceGroupName,
  'Microsoft.Network/networkWatchers',
  networkWatcherName
)
var effectiveRbacTargetScopeIds = union(
  concat(
    [
      subscription().id
      workloadResourceGroupId
      monitoringResourceGroup.id
      networkWatcherResourceGroupId
      validatedWorkloadVirtualNetworkResourceId
      monitoringDataPlatform.outputs.workspaceResourceId
      monitoringStorage.outputs.storageAccountResourceId
      evidenceBlobServiceResourceId
      monitoringEvidenceSeams.outputs.evidenceContainerResourceId
      monitoringEvidenceSeams.outputs.keyVaultResourceId
      monitoringEvidenceSeams.outputs.signingKeyArmResourceId
      networkWatcherResourceId
    ],
    workspaceTableResourceIds,
    resourceReadScopeIds,
    workloadEvidenceReaderAssignments.outputs.signalReadScopeIds,
    workloadEvidenceReaderAssignments.outputs.resourceLogReadScopeIds,
    workloadEvidenceReaderAssignments.outputs.resourceHealthScopeIds
  ),
  []
)
var collectorContractInputs = {
  collectorIdentityResourceId: monitoringEvidenceSeams.outputs.collectorIdentityResourceId
  collectorIdentityClientId: monitoringEvidenceSeams.outputs.collectorIdentityClientId
  collectorTenantId: monitoringEvidenceSeams.outputs.collectorIdentityTenantId
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
  workspaceResourceContextAccessEnabled: monitoringDataPlatform.outputs.workspaceResourceContextAccessEnabled
  workspaceSkuName: monitoringDataPlatform.outputs.workspaceSkuName == 'PerGB2018'
    ? 'PerGB2018'
    : fail('WC-028 resource-context acquisition requires the Analytics workspace SKU.')
  resourceContextTablePlans: monitoringDataPlatform.outputs.resourceContextTablePlans
  readerRoleDefinitionId: monitoringEvidenceReaderAssignments.outputs.readerRoleDefinitionId
  signalReaderRoleDefinitionId: workloadEvidenceReaderAssignments.outputs.signalReaderRoleDefinitionId
  signalReaderRoleName: workloadEvidenceReaderAssignments.outputs.signalReaderRoleName
  resourceLogReaderRoleDefinitionId: workloadEvidenceReaderAssignments.outputs.resourceLogReaderRoleDefinitionId
  resourceLogReaderRoleName: workloadEvidenceReaderAssignments.outputs.resourceLogReaderRoleName
  resourceLogAllowedOperations: workloadEvidenceReaderAssignments.outputs.resourceLogAllowedOperations
  resourceLogReadScopeIds: workloadEvidenceReaderAssignments.outputs.resourceLogReadScopeIds
  logAnalyticsDataReaderRoleDefinitionId: monitoringEvidenceReaderAssignments.outputs.logAnalyticsDataReaderRoleDefinitionId
  rbacAttestorIdentityResourceId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityResourceId
  rbacAttestorIdentityClientId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityClientId
  rbacAttestorPrincipalId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId
  rbacAttestorTenantId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityTenantId
  rbacAttestorRoleDefinitionId: monitoringRbacAttestor.outputs.attestorRoleDefinitionId
  rbacAttestorRoleName: monitoringRbacAttestor.outputs.attestorRoleName
  rbacAttestorScopeId: monitoringRbacAttestor.outputs.attestorScopeId
  rbacAttestorAllowedOperations: monitoringRbacAttestor.outputs.attestorAllowedOperations
  rbacAttestorGraphApplicationId: monitoringRbacAttestor.outputs.microsoftGraphApplicationId
  rbacAttestorGraphApplicationReadAllAppRoleId: monitoringRbacAttestor.outputs.applicationReadAllAppRoleId
  rbacAttestorGraphApplicationReadAllAssignmentId: monitoringRbacAttestor.outputs.applicationReadAllAssignmentId
  rbacAttestorGraphServicePrincipalId: monitoringRbacAttestor.outputs.microsoftGraphServicePrincipalId
  identityProofAudience: monitoringIdentityProofAuthority.outputs.identityProofAudience
  identityProofApplicationId: monitoringIdentityProofAuthority.outputs.identityProofApplicationId
  identityProofApplicationObjectId: monitoringIdentityProofAuthority.outputs.identityProofApplicationObjectId
  identityProofServicePrincipalId: monitoringIdentityProofAuthority.outputs.identityProofServicePrincipalId
  identityProofAppRoleId: monitoringIdentityProofAuthority.outputs.identityProofAppRoleId
  identityProofAppRoleValue: monitoringIdentityProofAuthority.outputs.identityProofAppRoleValue
  identityProofAppRoleAssignmentId: monitoringIdentityProofAuthority.outputs.identityProofAppRoleAssignmentId
  identityProofAssignedPrincipalId: monitoringIdentityProofAuthority.outputs.identityProofAssignedPrincipalId
  resourceHealthRoleDefinitionId: workloadEvidenceReaderAssignments.outputs.resourceHealthRoleDefinitionId
  resourceHealthRoleName: workloadEvidenceReaderAssignments.outputs.resourceHealthRoleName
  resourceHealthScopeIds: workloadEvidenceReaderAssignments.outputs.resourceHealthScopeIds
  resourceHealthAllowedOperations: workloadEvidenceReaderAssignments.outputs.resourceHealthAllowedOperations
  logAnalyticsAllowedTables: monitoringEvidenceReaderAssignments.outputs.allowedLogTableNames
  logAnalyticsAccessCondition: monitoringEvidenceReaderAssignments.outputs.logAnalyticsAccessCondition
  resourceReadScopeIds: resourceReadScopeIds
  signalReadScopeIds: workloadEvidenceReaderAssignments.outputs.signalReadScopeIds
  signingKeyResourceId: monitoringEvidenceSeams.outputs.signingKeyResourceId
  signingKeyArmResourceId: monitoringEvidenceSeams.outputs.signingKeyArmResourceId
  signingKeyCryptoUserRoleDefinitionId: monitoringEvidenceSeams.outputs.signingKeyCryptoUserRoleDefinitionId
  evidenceStorageAccountResourceId: monitoringStorage.outputs.storageAccountResourceId
  evidenceBlobServiceResourceId: evidenceBlobServiceResourceId
  evidenceContainerResourceId: monitoringEvidenceSeams.outputs.evidenceContainerResourceId
  evidenceWriterRoleDefinitionId: monitoringEvidenceSeams.outputs.evidenceWriterRoleDefinitionId
  signingKeyVaultResourceId: monitoringEvidenceSeams.outputs.keyVaultResourceId
  networkWatcherResourceGroupId: networkWatcherResourceGroupId
  networkWatcherResourceId: networkWatcherResourceId
  workspaceTableResourceIds: workspaceTableResourceIds
  maximumEvidenceAgeSeconds: maximumEvidenceAgeSeconds
  connectionMonitorDeploymentMode: connectionMonitorCapability.outputs.deploymentMode
}
var monitoringRbacBootstrapHandoff = {
  schemaVersion: 'athena.wc024MonitoringRbacBootstrapHandoff.v1'
  sourceDeploymentName: deployment().name
  handoffId: guid(
    subscription().id,
    monitoringEvidenceSeams.outputs.collectorIdentityResourceId,
    athenaContextIdentity.id,
    monitoringEvidenceSeams.outputs.rbacAttestorIdentityResourceId,
    join(effectiveRbacTargetScopeIds, '|')
  )
  publicationState: 'blockedPendingEffectiveRbacInventory'
  scopeCollectionMode: 'subscriptionAndDescendantAtScope'
  managementGroupAncestorDisposition: 'notDirectlyEnumerated'
  subscriptionId: subscription().subscriptionId
  tenantId: tenant().tenantId
  monitoringReaderPrincipalId: monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId
  athenaContextIdentityId: athenaContextIdentity.id
  athenaContextPrincipalId: athenaContextIdentity.properties.principalId
  physicalIdentitySeparationEnforced: acquisitionIdentitySeparation
  effectiveRbacTargetScopeIds: effectiveRbacTargetScopeIds
  directoryMembershipCollection: {
    graphApplicationId: monitoringRbacAttestor.outputs.microsoftGraphApplicationId
    graphApplicationReadAllAppRoleId: monitoringRbacAttestor.outputs.applicationReadAllAppRoleId
    graphApplicationReadAllAssignmentId: monitoringRbacAttestor.outputs.applicationReadAllAssignmentId
    graphServicePrincipalId: monitoringRbacAttestor.outputs.microsoftGraphServicePrincipalId
    requestHeaders: {
      ConsistencyLevel: 'eventual'
    }
    collectorRequestPath: '/v1.0/servicePrincipals/${monitoringEvidenceSeams.outputs.collectorIdentityPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
    athenaContextRequestPath: '/v1.0/servicePrincipals/${athenaContextIdentity.properties.principalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
  }
  identityProofAuthority: {
    audience: monitoringIdentityProofAuthority.outputs.identityProofAudience
    applicationId: monitoringIdentityProofAuthority.outputs.identityProofApplicationId
    applicationObjectId: monitoringIdentityProofAuthority.outputs.identityProofApplicationObjectId
    servicePrincipalId: monitoringIdentityProofAuthority.outputs.identityProofServicePrincipalId
    appRoleId: monitoringIdentityProofAuthority.outputs.identityProofAppRoleId
    appRoleValue: monitoringIdentityProofAuthority.outputs.identityProofAppRoleValue
    appRoleAssignmentId: monitoringIdentityProofAuthority.outputs.identityProofAppRoleAssignmentId
    assignedPrincipalId: monitoringIdentityProofAuthority.outputs.identityProofAssignedPrincipalId
    requestedAccessTokenVersion: '1.0'
  }
  collectorContractInputs: collectorContractInputs
}

@description('Phase-one handoff. Collect effective RBAC only after these identities, roles, and exact target scopes exist, then pass the immutable reviewed handoff to publish-monitoring-contract.bicep.')
output monitoringRbacBootstrapHandoff object = monitoringRbacBootstrapHandoff

@description('Contract publication remains fail-closed until the phase-two template validates a fresh effective RBAC inventory against monitoringRbacBootstrapHandoff.')
output monitoringAcquisitionContractPublicationReady bool = false

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
