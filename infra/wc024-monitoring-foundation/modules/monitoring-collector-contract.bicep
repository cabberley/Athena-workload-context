targetScope = 'resourceGroup'

@description('Resource ID of the isolated monitoring evidence collector identity.')
param collectorIdentityResourceId string

@description('Client ID of the isolated monitoring evidence collector identity.')
param collectorIdentityClientId string

@description('Tenant ID that owns the isolated monitoring evidence collector identity.')
param collectorTenantId string

@description('Exact Container Apps Job that is the only approved collector UAMI attachment.')
param collectorRuntimeResourceId string

@description('Exact Container Apps Job that is the only approved RBAC attestor UAMI attachment.')
param rbacAttestorRuntimeResourceId string

@description('Separate runtime-support UAMI that is the only additional identity approved on the collector Job.')
param runtimeSupportIdentityResourceId string

@description('Principal ID of the separate runtime-support UAMI.')
param runtimeSupportIdentityPrincipalId string

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

@description('Exact custom role definition resource ID for Azure Resource Graph query submission.')
param resourceGraphQueryRoleDefinitionId string

@description('Exact custom role name for Azure Resource Graph query submission.')
param resourceGraphQueryRoleName string

@description('Exact approved workload resource-group scope at which the Resource Graph query operation is authorized.')
param resourceGraphQueryScopeId string

@description('Exact Azure Resource Graph query operation allowlist.')
@minLength(1)
@maxLength(1)
param resourceGraphQueryAllowedOperations array

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
@minLength(13)
@maxLength(13)
param rbacAttestorAllowedOperations array

@description('Separately governed reviewer principal that signed the accepted RBAC inventory.')
param rbacInventoryReviewerPrincipalId string

@description('Exact phase-one bootstrap handoff identifier covered by the reviewer signature.')
param rbacInventoryBootstrapHandoffId string

@description('Exact phase-one subscription deployment resource ID covered by the reviewer signature.')
param rbacInventoryBootstrapDeploymentId string

@description('Server-computed phase-one template hash covered by the reviewer signature.')
param rbacInventoryBootstrapTemplateHash string

@description('Deterministic binding ID of the complete phase-one collectorContractInputs object.')
param rbacInventoryBootstrapContractInputsBindingId string

@description('UAMI used by phase two to resolve the exact versioned reviewer public key.')
param rbacInventoryVerifierIdentityResourceId string

@description('Verifier UAMI client ID.')
param rbacInventoryVerifierIdentityClientId string

@description('Verifier UAMI principal ID.')
param rbacInventoryVerifierIdentityPrincipalId string

@description('Verifier UAMI tenant ID.')
param rbacInventoryVerifierIdentityTenantId string

@description('Exact reviewer key ARM resource ID.')
param rbacInventoryReviewerKeyArmResourceId string

@description('Exact separately governed reviewer Key Vault ARM resource ID.')
param rbacInventoryReviewerKeyVaultResourceId string

@description('Exact keys/get-only verifier role definition ID.')
param rbacInventoryVerifierRoleDefinitionId string

@description('Exact keys/get-only verifier role name.')
param rbacInventoryVerifierRoleName string

@description('Exact reviewer key scope receiving the verifier role.')
param rbacInventoryVerifierRoleScopeId string

@description('Exact verifier key-read data action.')
@minLength(1)
@maxLength(1)
param rbacInventoryVerifierAllowedDataActions array

@description('Exact verifier role assignment ID.')
param rbacInventoryVerifierRoleAssignmentId string

@description('Exact versioned reviewer key identifier.')
param rbacInventoryReviewerKeyId string

@description('Base64url RSA modulus for local reviewer-signature verification.')
@minLength(342)
@maxLength(1024)
param rbacInventoryReviewerPublicKeyModulus string

@description('Base64url RSA exponent for local reviewer-signature verification.')
@allowed([
  'AQAB'
])
param rbacInventoryReviewerPublicKeyExponent string

@description('SHA-256 SPKI fingerprint of the reviewer public key.')
@minLength(71)
@maxLength(71)
param rbacInventoryReviewerPublicKeyFingerprint string

@description('Detached reviewer signature over effectiveRbacInventory.')
param effectiveRbacInventoryAttestation object

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

@description('Exact runtime-support storage-readback role definition resource ID.')
param runtimeSupportStorageReaderRoleDefinitionId string

@description('Exact runtime-support storage-readback role name.')
param runtimeSupportStorageReaderRoleName string

@description('Exact management-plane operations in the runtime-support storage-readback role.')
@minLength(4)
@maxLength(4)
param runtimeSupportStorageReaderAllowedOperations array

@description('Exact runtime-support storage-readback role assignment resource ID.')
param runtimeSupportStorageReaderRoleAssignmentId string

@description('Exact storage-account scope of the runtime-support readback assignment.')
param runtimeSupportStorageReaderScopeId string

@description('Exact default Blob-service resource ID whose versioning readback is contract-bound.')
param evidenceBlobServiceResourceId string

@description('Exact monitoring evidence container receiving immutable evidence writes.')
param evidenceContainerResourceId string

@description('Observed evidence-container public access state.')
@allowed([
  'None'
])
param evidenceContainerPublicAccess string

@description('Exact monitoring-evidence immutability-policy resource ID.')
param evidenceImmutabilityPolicyResourceId string

@description('Exact conditioned known-name-read and add-only role definition resource ID.')
param evidenceWriterRoleDefinitionId string

@description('Exact conditioned known-name-read and add-only role name.')
param evidenceWriterRoleName string

@description('Exact Blob data actions in the evidence writer role.')
@minLength(2)
@maxLength(2)
param evidenceWriterAllowedDataActions array

@description('Exact role-assignment condition that denies the Blob.List suboperation.')
param evidenceWriterAssignmentCondition string

@description('Azure RBAC condition version for the evidence writer assignment.')
@allowed([
  '2.0'
])
param evidenceWriterAssignmentConditionVersion string

@description('Observed Blob-service versioning readback.')
param evidenceBlobVersioningEnabled bool

@description('Observed container immutability-policy presence.')
param evidenceContainerHasImmutabilityPolicy bool

@description('Observed container immutability-policy state.')
@allowed([
  'Locked'
  'Unlocked'
])
param evidenceContainerImmutabilityPolicyState string

@description('Observed container immutability retention period.')
@minValue(30)
@maxValue(365)
param evidenceContainerImmutabilityPeriodDays int

@description('Observed protected append-write setting.')
param evidenceContainerProtectedAppendWritesEnabled bool

@description('Observed protected append-write-all setting.')
param evidenceContainerProtectedAppendWritesAllEnabled bool

@description('ARM guid() binding over the exact reviewed storage-readiness preimage.')
param evidenceStorageReadbackBindingId string

@description('SHA-256 digest of the exact reviewed storage-readiness preimage.')
@minLength(71)
@maxLength(71)
param evidenceStorageReadinessDigest string

@description('Exact cleanup evidence schema that proves superseded broad collector RBAC is absent.')
@allowed([
  'athena.wc028LegacyCollectorRbacCleanup.v3'
])
param legacyCollectorRbacCleanupSchemaVersion string

@description('Non-zero digest of the exact superseded collector RBAC cleanup evidence.')
@minLength(71)
@maxLength(71)
param legacyCollectorRbacCleanupDigest string

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
  schemaVersion: 'athena.wc028MonitoringCollectorContract.v10'
  handoffSchemaVersion: 'athena.wc028MonitoringEvidenceHandoff.v2'
  acquisitionReceiptSchemaVersion: 'athena.wc028MonitoringAcquisitionReceipt.v6'
  workspaceAccessControlMode: validatedAcquisitionWorkspaceAccessControlMode
  workspaceResourceContextAccessEnabled: workspaceResourceContextAccessEnabled
  workspaceSkuName: workspaceSkuName
  resourceContextTablePlans: resourceContextTablePlans
  resourceIdColumn: '_ResourceId'
  logQueryPreferHeader: 'include-permissions=true'
  flowTableAcquisitionMode: 'unsupportedUnavailable'
  collectorTenantId: collectorTenantId
  collectorRuntimeResourceId: collectorRuntimeResourceId
  rbacAttestorRuntimeResourceId: rbacAttestorRuntimeResourceId
  runtimeSupportIdentityResourceId: runtimeSupportIdentityResourceId
  runtimeSupportIdentityPrincipalId: runtimeSupportIdentityPrincipalId
  runtimeSupportStorageReaderRoleDefinitionId: runtimeSupportStorageReaderRoleDefinitionId
  runtimeSupportStorageReaderRoleName: runtimeSupportStorageReaderRoleName
  runtimeSupportStorageReaderAllowedOperations: runtimeSupportStorageReaderAllowedOperations
  runtimeSupportStorageReaderRoleAssignmentId: runtimeSupportStorageReaderRoleAssignmentId
  runtimeSupportStorageReaderScopeId: runtimeSupportStorageReaderScopeId
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
  rbacInventoryBootstrapHandoffId: rbacInventoryBootstrapHandoffId
  rbacInventoryBootstrapDeploymentId: rbacInventoryBootstrapDeploymentId
  rbacInventoryBootstrapTemplateHash: rbacInventoryBootstrapTemplateHash
  rbacInventoryBootstrapContractInputsBindingId: rbacInventoryBootstrapContractInputsBindingId
  rbacInventoryVerifierIdentityResourceId: rbacInventoryVerifierIdentityResourceId
  rbacInventoryVerifierIdentityClientId: rbacInventoryVerifierIdentityClientId
  rbacInventoryVerifierIdentityPrincipalId: rbacInventoryVerifierIdentityPrincipalId
  rbacInventoryVerifierIdentityTenantId: rbacInventoryVerifierIdentityTenantId
  rbacInventoryReviewerKeyVaultResourceId: rbacInventoryReviewerKeyVaultResourceId
  rbacInventoryReviewerKeyArmResourceId: rbacInventoryReviewerKeyArmResourceId
  rbacInventoryVerifierRoleDefinitionId: rbacInventoryVerifierRoleDefinitionId
  rbacInventoryVerifierRoleName: rbacInventoryVerifierRoleName
  rbacInventoryVerifierRoleScopeId: rbacInventoryVerifierRoleScopeId
  rbacInventoryVerifierAllowedDataActions: rbacInventoryVerifierAllowedDataActions
  rbacInventoryVerifierRoleAssignmentId: rbacInventoryVerifierRoleAssignmentId
  rbacInventoryReviewerPrincipalId: rbacInventoryReviewerPrincipalId
  rbacInventoryReviewerKeyId: rbacInventoryReviewerKeyId
  rbacInventoryReviewerPublicKeyModulus: rbacInventoryReviewerPublicKeyModulus
  rbacInventoryReviewerPublicKeyExponent: rbacInventoryReviewerPublicKeyExponent
  rbacInventoryReviewerPublicKeyFingerprint: rbacInventoryReviewerPublicKeyFingerprint
  effectiveRbacInventoryAttestation: effectiveRbacInventoryAttestation
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
  resourceGraphQueryRoleDefinitionId: resourceGraphQueryRoleDefinitionId
  resourceGraphQueryRoleName: resourceGraphQueryRoleName
  resourceGraphQueryScopeId: resourceGraphQueryScopeId
  resourceGraphQueryAllowedOperations: resourceGraphQueryAllowedOperations
  resourceHealthRoleDefinitionId: resourceHealthRoleDefinitionId
  resourceHealthRoleName: resourceHealthRoleName
  resourceHealthScopeIds: resourceHealthScopeIds
  resourceHealthAllowedOperations: resourceHealthAllowedOperations
  signingKeyArmResourceId: signingKeyArmResourceId
  signingKeyCryptoUserRoleDefinitionId: signingKeyCryptoUserRoleDefinitionId
  evidenceBlobServiceResourceId: evidenceBlobServiceResourceId
  evidenceContainerResourceId: evidenceContainerResourceId
  evidenceContainerPublicAccess: evidenceContainerPublicAccess
  evidenceImmutabilityPolicyResourceId: evidenceImmutabilityPolicyResourceId
  evidenceWriterRoleDefinitionId: evidenceWriterRoleDefinitionId
  evidenceWriterRoleName: evidenceWriterRoleName
  evidenceWriterAllowedDataActions: evidenceWriterAllowedDataActions
  evidenceWriterAssignmentCondition: evidenceWriterAssignmentCondition
  evidenceWriterAssignmentConditionVersion: evidenceWriterAssignmentConditionVersion
  evidenceBlobVersioningEnabled: evidenceBlobVersioningEnabled
  evidenceContainerHasImmutabilityPolicy: evidenceContainerHasImmutabilityPolicy
  evidenceContainerImmutabilityPolicyState: evidenceContainerImmutabilityPolicyState
  evidenceContainerImmutabilityPeriodDays: evidenceContainerImmutabilityPeriodDays
  evidenceContainerProtectedAppendWritesEnabled: evidenceContainerProtectedAppendWritesEnabled
  evidenceContainerProtectedAppendWritesAllEnabled: evidenceContainerProtectedAppendWritesAllEnabled
  evidenceStorageReadbackBindingId: evidenceStorageReadbackBindingId
  evidenceStorageReadinessDigest: evidenceStorageReadinessDigest
  legacyCollectorRbacCleanupSchemaVersion: legacyCollectorRbacCleanupSchemaVersion
  legacyCollectorRbacCleanupDigest: legacyCollectorRbacCleanupDigest
  effectiveRbacInventory: effectiveRbacInventory
  allowedReadOperations: concat(
    filter(
      collectorContract.allowedReadOperations,
      operation => !startsWith(toLower(operation), 'microsoft.operationalinsights/workspaces')
    ),
    resourceGraphQueryAllowedOperations,
    resourceHealthAllowedOperations,
    resourceLogAllowedOperations
  )
})
