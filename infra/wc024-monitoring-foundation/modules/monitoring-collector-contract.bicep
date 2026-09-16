targetScope = 'resourceGroup'

@description('Resource ID of the isolated monitoring evidence collector identity.')
param collectorIdentityResourceId string

@description('Client ID of the isolated monitoring evidence collector identity.')
param collectorIdentityClientId string

@description('Tenant ID that owns the isolated monitoring evidence collector identity.')
param collectorTenantId string

@description('Resource ID of the monitoring-owned resource group.')
param monitoringResourceGroupId string

@description('Resource ID of the approved workload resource group.')
param workloadResourceGroupId string

@description('Exact reviewed workload VNet resource ID.')
param workloadVirtualNetworkResourceId string

@description('Exact reviewed 11 VM names that are inside the WC-024 workload boundary.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Resource ID of the private Log Analytics workspace.')
param workspaceResourceId string

@description('Resource ID of the generic AMA and VM Insights DCR.')
param dataCollectionRuleResourceId string

@description('Resource ID of the private data collection endpoint.')
param dataCollectionEndpointResourceId string

@description('Reviewed authorization model used by the isolated collector.')
@allowed([
  'conditionedWorkspacePlusExactResourceContext'
])
param authorizationMode string

@description('Observed Log Analytics workspace access-control mode.')
@allowed([
  'workspaceAndResourceContext'
  'workspaceOnly'
])
param workspaceAccessControlMode string

@description('Observed workspace resource-context access flag.')
param workspaceResourceContextAccessEnabled bool

@description('Observed adopted workspace SKU.')
param workspaceSkuName string

@description('Observed exact Analytics plans for supported resource-context tables.')
@minLength(5)
@maxLength(5)
param resourceContextTablePlans array

@description('Built-in Reader role definition resource ID.')
param readerRoleDefinitionId string

@description('Existing narrow VM signal-reader role definition resource ID.')
param signalReaderRoleDefinitionId string

@description('Exact deployed narrow VM signal-reader role name.')
param signalReaderRoleName string

@description('Exact custom role definition for resource-context Log Analytics reads.')
param resourceLogReaderRoleDefinitionId string

@description('Exact custom role name for resource-context Log Analytics reads.')
param resourceLogReaderRoleName string

@description('Exact registered resource-context log-table actions granted only at approved VMs.')
@minLength(5)
@maxLength(5)
param resourceLogAllowedOperations array

@description('Exact approved VM scopes receiving the resource-context log role.')
@minLength(11)
@maxLength(11)
param resourceLogReadScopeIds array

@description('Built-in Log Analytics Data Reader role definition resource ID.')
param logAnalyticsDataReaderRoleDefinitionId string

@description('Exact custom role definition resource ID for Resource Health availability reads.')
param resourceHealthRoleDefinitionId string

@description('Exact custom role name for Resource Health availability reads.')
param resourceHealthRoleName string

@description('Exact approved VM resource IDs receiving Resource Health availability-read assignments.')
@minLength(11)
@maxLength(11)
param resourceHealthScopeIds array

@description('Exact Resource Health management-plane operation allowlist.')
@minLength(1)
@maxLength(1)
param resourceHealthAllowedOperations array

@description('Resource ID of the isolated effective RBAC attestor identity.')
param rbacAttestorIdentityResourceId string

@description('Client ID of the isolated effective RBAC attestor identity.')
param rbacAttestorIdentityClientId string

@description('Principal ID of the isolated effective RBAC attestor identity.')
param rbacAttestorPrincipalId string

@description('Tenant ID of the isolated effective RBAC attestor identity.')
param rbacAttestorTenantId string

@description('Exact custom role definition used only by the RBAC attestor.')
param rbacAttestorRoleDefinitionId string

@description('Exact custom role name used only by the RBAC attestor.')
param rbacAttestorRoleName string

@description('Exact subscription scope receiving the RBAC attestor assignment.')
param rbacAttestorScopeId string

@description('Exact read-only Azure RBAC operations granted to the attestor.')
@minLength(4)
@maxLength(4)
param rbacAttestorAllowedOperations array

@description('Secure single-tenant Application ID URI of the deployed identity-proof API.')
param identityProofAudience string

@description('Application client ID of the deployed identity-proof API.')
param identityProofApplicationId string

@description('Application object ID of the deployed identity-proof API.')
param identityProofApplicationObjectId string

@description('Enterprise application service-principal object ID of the identity-proof API.')
param identityProofServicePrincipalId string

@description('Application role ID that emits the monitoring proof role claim.')
param identityProofAppRoleId string

@description('Application role value that the collector token must carry.')
param identityProofAppRoleValue string

@description('Direct app-role assignment ID binding the collector managed identity.')
param identityProofAppRoleAssignmentId string

@description('Principal ID receiving the direct identity-proof app-role assignment.')
param identityProofAssignedPrincipalId string

@description('Exact Log Analytics table names permitted by the role-assignment condition.')
@minLength(13)
@maxLength(13)
param logAnalyticsAllowedTables array

@description('Exact restrictive Azure RBAC condition applied to Log Analytics data reads.')
param logAnalyticsAccessCondition string

@description('Exact management-plane resource IDs readable through built-in Reader.')
@minLength(27)
@maxLength(27)
param resourceReadScopeIds array

@description('Exact VM resource IDs readable through the narrow signal-reader role.')
@minLength(11)
@maxLength(11)
param signalReadScopeIds array

@description('Resource ID of the non-exportable collector signing key.')
param signingKeyResourceId string

@description('ARM resource ID of the non-exportable collector signing key.')
param signingKeyArmResourceId string

@description('Exact Key Vault Crypto User role definition resource ID.')
param signingKeyCryptoUserRoleDefinitionId string

@description('Resource ID of the monitoring-owned immutable evidence storage account.')
param evidenceStorageAccountResourceId string

@description('Exact monitoring evidence container receiving immutable evidence writes.')
param evidenceContainerResourceId string

@description('Exact Storage Blob Data Contributor role definition resource ID.')
param evidenceWriterRoleDefinitionId string

@description('Externally collected effective RBAC inventory for both identities at the exact subscription and descendant scopes published by the phase-one handoff.')
param effectiveRbacInventory object

@description('Maximum accepted age for a signed evidence handoff.')
@minValue(60)
@maxValue(900)
param maximumEvidenceAgeSeconds int

@description('The generic Connection Monitor capability state.')
param connectionMonitorDeploymentMode string

var validatedConnectionMonitorDeploymentMode = connectionMonitorDeploymentMode == 'capability-only'
  ? connectionMonitorDeploymentMode
  : fail('collector contracts require the generic Connection Monitor capability-only mode')

var collectorContract = {
  schemaVersion: 'athena.wc024MonitoringCollectorContract.v2'
  collectorIdentityResourceId: collectorIdentityResourceId
  collectorIdentityClientId: collectorIdentityClientId
  monitoringResourceGroupId: monitoringResourceGroupId
  workloadResourceGroupId: workloadResourceGroupId
  workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
  approvedVmNames: approvedVmNames
  workspaceResourceId: workspaceResourceId
  dataCollectionRuleResourceId: dataCollectionRuleResourceId
  dataCollectionEndpointResourceId: dataCollectionEndpointResourceId
  authorizationMode: authorizationMode
  workspaceAccessControlMode: workspaceAccessControlMode
  readerRoleDefinitionId: readerRoleDefinitionId
  signalReaderRoleDefinitionId: signalReaderRoleDefinitionId
  logAnalyticsDataReaderRoleDefinitionId: logAnalyticsDataReaderRoleDefinitionId
  logAnalyticsAllowedTables: logAnalyticsAllowedTables
  logAnalyticsAccessCondition: logAnalyticsAccessCondition
  resourceReadScopeIds: resourceReadScopeIds
  signalReadScopeIds: signalReadScopeIds
  signalKinds: [
    'heartbeat'
    'perf'
    'insightsMetrics'
    'syslog'
    'disk'
    'guest'
    'vnetFlow'
    'trafficAnalytics'
  ]
  allowedReadOperations: [
    'Microsoft.OperationalInsights/workspaces/read'
    'Microsoft.OperationalInsights/workspaces/query/read'
    'Microsoft.OperationalInsights/workspaces/tables/data/read'
    'Microsoft.Compute/virtualMachines/instanceView/read'
    'Microsoft.Insights/Metrics/Read'
    'Microsoft.Insights/dataCollectionRules/read'
    'Microsoft.Insights/dataCollectionEndpoints/read'
    'Microsoft.Insights/dataCollectionRuleAssociations/read'
    'Microsoft.Insights/privateLinkScopes/read'
    'Microsoft.Network/networkWatchers/flowLogs/read'
  ]
  collectionMode: 'isolatedSignedCollector'
  handoffSchemaVersion: 'athena.wc024MonitoringEvidenceHandoff.v1'
  maximumEvidenceAgeSeconds: maximumEvidenceAgeSeconds
  connectionMonitorMode: 'capabilityOnly'
  signingKeyResourceId: signingKeyResourceId
  evidenceStorageAccountResourceId: evidenceStorageAccountResourceId
  evidenceContainerName: 'monitoring-evidence'
  connectionMonitorDeploymentMode: validatedConnectionMonitorDeploymentMode
}

output collectorContract object = collectorContract

var validatedAcquisitionWorkspaceAccessControlMode = workspaceAccessControlMode == 'workspaceAndResourceContext'
  ? workspaceAccessControlMode
  : fail('production monitoring acquisition requires resource-context Log Analytics mode')

output acquisitionCollectorContract object = union(collectorContract, {
  schemaVersion: 'athena.wc028MonitoringCollectorContract.v8'
  handoffSchemaVersion: 'athena.wc028MonitoringEvidenceHandoff.v2'
  acquisitionReceiptSchemaVersion: 'athena.wc028MonitoringAcquisitionReceipt.v5'
  workspaceAccessControlMode: validatedAcquisitionWorkspaceAccessControlMode
  workspaceResourceContextAccessEnabled: workspaceResourceContextAccessEnabled
  workspaceSkuName: workspaceSkuName
  resourceContextTablePlans: resourceContextTablePlans
  resourceIdColumn: '_ResourceId'
  logQueryPreferHeader: 'include-permissions=true'
  flowTableAcquisitionMode: 'unsupportedUnavailable'
  collectorTenantId: collectorTenantId
  signalReaderRoleName: signalReaderRoleName
  resourceLogReaderRoleDefinitionId: resourceLogReaderRoleDefinitionId
  resourceLogReaderRoleName: resourceLogReaderRoleName
  resourceLogAllowedOperations: resourceLogAllowedOperations
  resourceLogReadScopeIds: resourceLogReadScopeIds
  rbacAttestorIdentityResourceId: rbacAttestorIdentityResourceId
  rbacAttestorIdentityClientId: rbacAttestorIdentityClientId
  rbacAttestorPrincipalId: rbacAttestorPrincipalId
  rbacAttestorTenantId: rbacAttestorTenantId
  rbacAttestorRoleDefinitionId: rbacAttestorRoleDefinitionId
  rbacAttestorRoleName: rbacAttestorRoleName
  rbacAttestorScopeId: rbacAttestorScopeId
  rbacAttestorAllowedOperations: rbacAttestorAllowedOperations
  rbacAttestorIdentitySeparationEnforced: true
  identityProofAudience: identityProofAudience
  identityProofApplicationId: identityProofApplicationId
  identityProofApplicationObjectId: identityProofApplicationObjectId
  identityProofServicePrincipalId: identityProofServicePrincipalId
  identityProofAppRoleId: identityProofAppRoleId
  identityProofAppRoleAssignmentId: identityProofAppRoleAssignmentId
  identityProofAssignedPrincipalId: identityProofAssignedPrincipalId
  identityProofTokenVersion: '1.0'
  identityProofRequiredRole: identityProofAppRoleValue
  identityProofMaximumLifetimeSeconds: 7200
  resourceHealthRoleDefinitionId: resourceHealthRoleDefinitionId
  resourceHealthRoleName: resourceHealthRoleName
  resourceHealthScopeIds: resourceHealthScopeIds
  resourceHealthAllowedOperations: resourceHealthAllowedOperations
  signingKeyArmResourceId: signingKeyArmResourceId
  signingKeyCryptoUserRoleDefinitionId: signingKeyCryptoUserRoleDefinitionId
  evidenceContainerResourceId: evidenceContainerResourceId
  evidenceWriterRoleDefinitionId: evidenceWriterRoleDefinitionId
  effectiveRbacInventory: effectiveRbacInventory
  allowedReadOperations: concat(
    filter(
      collectorContract.allowedReadOperations,
      operation => !startsWith(toLower(operation), 'microsoft.operationalinsights/workspaces')
    ),
    resourceHealthAllowedOperations,
    resourceLogAllowedOperations
  )
})
