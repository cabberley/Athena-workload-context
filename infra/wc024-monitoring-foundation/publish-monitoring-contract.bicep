targetScope = 'subscription'

metadata name = 'Athena WC-024 monitoring contract publication'
metadata description = 'Publishes the reviewed monitoring collector contracts only after the phase-one identity and role bootstrap has produced an exact handoff and a fresh post-deployment effective RBAC inventory.'

@description('Name of the successful WC-024 phase-one subscription deployment whose exact outputs are authoritative.')
@minLength(1)
@maxLength(64)
param monitoringRbacBootstrapDeploymentName string

@description('Reviewed monitoring resource group that receives the published contract module.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string = 'rg-athena-demo-monitoring'

@description('Fresh post-deployment effective RBAC inventory collected with the handoff attestor identity through the exact subscription-wide and protected-scope requests.')
param monitoringEffectiveRbacInventory object

@description('Detached reviewer signature over the exact effective-RBAC inventory.')
param monitoringEffectiveRbacInventoryAttestation object

@description('Exact dormant or active Container Apps Job that is the only approved attachment for the collector UAMI.')
param collectorRuntimeResourceId string

@description('Exact Container Apps Job that is the only approved attachment for the RBAC attestor UAMI.')
param rbacAttestorRuntimeResourceId string

@description('Separate runtime-support UAMI that is the only additional identity approved on the collector Job.')
param runtimeSupportIdentityResourceId string

@description('Independently reviewed canonical digest of monitoringEffectiveRbacInventory.')
@minLength(71)
@maxLength(71)
param reviewedMonitoringEffectiveRbacInventoryDigest string

var reviewedInventoryDigestHex = replace(reviewedMonitoringEffectiveRbacInventoryDigest, 'sha256:', '')
var reviewedInventoryDigestWithoutDigits = replace(
  replace(
    replace(
      replace(
        replace(
          replace(
            replace(replace(replace(replace(reviewedInventoryDigestHex, '0', ''), '1', ''), '2', ''), '3', ''),
            '4',
            ''
          ),
          '5',
          ''
        ),
        '6',
        ''
      ),
      '7',
      ''
    ),
    '8',
    ''
  ),
  '9',
  ''
)
var reviewedInventoryDigestInvalidCharacters = replace(
  replace(
    replace(replace(replace(replace(reviewedInventoryDigestWithoutDigits, 'a', ''), 'b', ''), 'c', ''), 'd', ''),
    'e',
    ''
  ),
  'f',
  ''
)
var validatedReviewedInventoryDigest = reviewedMonitoringEffectiveRbacInventoryDigest == toLower(reviewedMonitoringEffectiveRbacInventoryDigest) && startsWith(
    reviewedMonitoringEffectiveRbacInventoryDigest,
    'sha256:'
  ) && length(reviewedInventoryDigestHex) == 64 && empty(reviewedInventoryDigestInvalidCharacters) && reviewedInventoryDigestHex != '0000000000000000000000000000000000000000000000000000000000000000'
  ? reviewedMonitoringEffectiveRbacInventoryDigest
  : fail('reviewedMonitoringEffectiveRbacInventoryDigest must be one real lowercase SHA-256 digest')

#disable-next-line no-deployments-resources
resource monitoringRbacBootstrapDeployment 'Microsoft.Resources/deployments@2025-04-01' existing = {
  name: monitoringRbacBootstrapDeploymentName
}

module publicationClock 'modules/deployment-timestamp.bicep' = {
  name: 'monitoring-contract-publication-clock'
}

var handoff = monitoringRbacBootstrapDeployment.properties.outputs.monitoringRbacBootstrapHandoff.value
var contractInputs = handoff.collectorContractInputs
var expectedBootstrapDeploymentId = subscriptionResourceId(
  'Microsoft.Resources/deployments',
  monitoringRbacBootstrapDeploymentName
)
var expectedCollectorContractInputsBindingId = handoff.collectorContractInputsBindingId
var bootstrapTemplateHash = monitoringRbacBootstrapDeployment.properties.templateHash
var subscriptionScope = subscription().id
var monitoringResourceGroupId = subscriptionResourceId(
  'Microsoft.Resources/resourceGroups',
  monitoringResourceGroupName
)
var expectedTargetScopeIds = union(
  concat(
    [
      subscriptionScope
      contractInputs.collectorRuntimeResourceId
      contractInputs.rbacAttestorRuntimeResourceId
      contractInputs.runtimeSupportIdentityResourceId
      contractInputs.rbacInventoryVerifierIdentityResourceId
      contractInputs.rbacInventoryReviewerKeyVaultResourceId
      contractInputs.rbacInventoryReviewerKeyArmResourceId
      contractInputs.rbacInventoryVerifierRoleDefinitionId
      contractInputs.rbacInventoryVerifierRoleAssignmentId
      contractInputs.runtimeSupportStorageReaderRoleDefinitionId
      contractInputs.runtimeSupportStorageReaderRoleAssignmentId
      contractInputs.workloadResourceGroupId
      contractInputs.monitoringResourceGroupId
      contractInputs.networkWatcherResourceGroupId
      contractInputs.workloadVirtualNetworkResourceId
      contractInputs.workspaceResourceId
      contractInputs.evidenceStorageAccountResourceId
      contractInputs.evidenceBlobServiceResourceId
      contractInputs.evidenceContainerResourceId
      contractInputs.evidenceImmutabilityPolicyResourceId
      contractInputs.signingKeyVaultResourceId
      contractInputs.signingKeyArmResourceId
      contractInputs.networkWatcherResourceId
    ],
    contractInputs.workspaceTableResourceIds,
    contractInputs.resourceReadScopeIds,
    contractInputs.signalReadScopeIds,
    contractInputs.resourceLogReadScopeIds,
    contractInputs.resourceHealthScopeIds
  ),
  []
)
var normalizedExpectedTargetScopeIds = map(expectedTargetScopeIds, scopeId => toLower(scopeId))
var normalizedHandoffTargetScopeIds = map(handoff.effectiveRbacTargetScopeIds, scopeId => toLower(scopeId))
var uncollectableTargetScopeIds = filter(
  normalizedHandoffTargetScopeIds,
  scopeId => !startsWith(scopeId, '${toLower(subscriptionScope)}/') && scopeId != toLower(subscriptionScope)
)
var handoffTargetsAreUnique = length(union(normalizedHandoffTargetScopeIds, [])) == length(normalizedHandoffTargetScopeIds)
var targetScopesMatch = empty(uncollectableTargetScopeIds) && handoffTargetsAreUnique && length(normalizedHandoffTargetScopeIds) == length(normalizedExpectedTargetScopeIds) && length(union(
  normalizedHandoffTargetScopeIds,
  normalizedExpectedTargetScopeIds
)) == length(normalizedExpectedTargetScopeIds)
var expectedHandoffId = guid(
  subscriptionScope,
  contractInputs.collectorIdentityResourceId,
  handoff.athenaContextIdentityId,
  contractInputs.rbacAttestorIdentityResourceId,
  expectedBootstrapDeploymentId,
  expectedCollectorContractInputsBindingId,
  contractInputs.legacyCollectorRbacCleanupDigest,
  handoff.rbacInventoryReviewAuthority.reviewerPrincipalId,
  handoff.rbacInventoryReviewAuthority.reviewerKeyId,
  handoff.rbacInventoryReviewAuthority.verifierIdentityResourceId,
  handoff.rbacInventoryReviewAuthority.publicKeyFingerprint
)
var handoffIdentitiesAreSeparated = toLower(contractInputs.collectorIdentityResourceId) != toLower(handoff.athenaContextIdentityId) && toLower(contractInputs.collectorIdentityResourceId) != toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(handoff.athenaContextIdentityId) != toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(handoff.monitoringReaderPrincipalId) != toLower(handoff.athenaContextPrincipalId) && toLower(handoff.monitoringReaderPrincipalId) != toLower(contractInputs.rbacAttestorPrincipalId) && toLower(handoff.athenaContextPrincipalId) != toLower(contractInputs.rbacAttestorPrincipalId)
var expectedCollectorMembershipRequestPath = '/v1.0/servicePrincipals/${handoff.monitoringReaderPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
var expectedContextMembershipRequestPath = '/v1.0/servicePrincipals/${handoff.athenaContextPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
var expectedVerifierMembershipRequestPath = '/v1.0/servicePrincipals/${contractInputs.rbacInventoryVerifierIdentityPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
var directoryMembershipCollectionMatches = handoff.directoryMembershipCollection.graphApplicationId == '00000003-0000-0000-c000-000000000000' && handoff.directoryMembershipCollection.graphApplicationReadAllAppRoleId == '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' && handoff.directoryMembershipCollection.graphApplicationReadAllAssignmentId == contractInputs.rbacAttestorGraphApplicationReadAllAssignmentId && handoff.directoryMembershipCollection.graphServicePrincipalId == contractInputs.rbacAttestorGraphServicePrincipalId && length(items(handoff.directoryMembershipCollection.requestHeaders)) == 1 && handoff.directoryMembershipCollection.requestHeaders.ConsistencyLevel == 'eventual' && handoff.directoryMembershipCollection.collectorRequestPath == expectedCollectorMembershipRequestPath && handoff.directoryMembershipCollection.athenaContextRequestPath == expectedContextMembershipRequestPath && handoff.directoryMembershipCollection.reviewerKeyVerifierRequestPath == expectedVerifierMembershipRequestPath
var expectedIdentityProofAudience = 'api://${toLower(handoff.tenantId)}/athena-monitoring-identity-proof'
var identityProofAuthorityIds = [
  toLower(handoff.identityProofAuthority.applicationId)
  toLower(handoff.identityProofAuthority.applicationObjectId)
  toLower(handoff.identityProofAuthority.servicePrincipalId)
  toLower(handoff.identityProofAuthority.appRoleId)
  toLower(handoff.identityProofAuthority.appRoleAssignmentId)
]
var identityProofAuthorityMatches = handoff.identityProofAuthority.audience == expectedIdentityProofAudience && handoff.identityProofAuthority.audience == contractInputs.identityProofAudience && handoff.identityProofAuthority.applicationId == contractInputs.identityProofApplicationId && handoff.identityProofAuthority.applicationObjectId == contractInputs.identityProofApplicationObjectId && handoff.identityProofAuthority.servicePrincipalId == contractInputs.identityProofServicePrincipalId && handoff.identityProofAuthority.appRoleId == contractInputs.identityProofAppRoleId && handoff.identityProofAuthority.appRoleValue == 'Athena.MonitoringAcquisition.ProveIdentity' && handoff.identityProofAuthority.appRoleValue == contractInputs.identityProofAppRoleValue && handoff.identityProofAuthority.appRoleAssignmentId == contractInputs.identityProofAppRoleAssignmentId && toLower(handoff.identityProofAuthority.assignedPrincipalId) == toLower(handoff.monitoringReaderPrincipalId) && toLower(handoff.identityProofAuthority.assignedPrincipalId) == toLower(contractInputs.identityProofAssignedPrincipalId) && handoff.identityProofAuthority.requestedAccessTokenVersion == '1.0' && length(union(
  identityProofAuthorityIds,
  []
)) == length(identityProofAuthorityIds)
var collectorRuntimeSegments = split(toLower(collectorRuntimeResourceId), '/')
var attestorRuntimeSegments = split(toLower(rbacAttestorRuntimeResourceId), '/')
var runtimeSupportIdentitySegments = split(toLower(runtimeSupportIdentityResourceId), '/')
var collectorRuntimeBindingIsValid = length(collectorRuntimeSegments) == 9
  ? collectorRuntimeSegments[1] == 'subscriptions' && collectorRuntimeSegments[2] == toLower(subscription().subscriptionId) && collectorRuntimeSegments[5] == 'providers' && collectorRuntimeSegments[6] == 'microsoft.app' && collectorRuntimeSegments[7] == 'jobs'
  : false
var attestorRuntimeBindingIsValid = length(attestorRuntimeSegments) == 9
  ? attestorRuntimeSegments[1] == 'subscriptions' && attestorRuntimeSegments[2] == toLower(subscription().subscriptionId) && attestorRuntimeSegments[5] == 'providers' && attestorRuntimeSegments[6] == 'microsoft.app' && attestorRuntimeSegments[7] == 'jobs'
  : false
var runtimeSupportIdentityBindingIsValid = length(runtimeSupportIdentitySegments) == 9
  ? runtimeSupportIdentitySegments[1] == 'subscriptions' && runtimeSupportIdentitySegments[2] == toLower(subscription().subscriptionId) && runtimeSupportIdentitySegments[5] == 'providers' && runtimeSupportIdentitySegments[6] == 'microsoft.managedidentity' && runtimeSupportIdentitySegments[7] == 'userassignedidentities' && !empty(runtimeSupportIdentitySegments[8])
  : false
var runtimeBindingsAreValid = collectorRuntimeBindingIsValid && attestorRuntimeBindingIsValid && runtimeSupportIdentityBindingIsValid && toLower(collectorRuntimeResourceId) == toLower(contractInputs.collectorRuntimeResourceId) && toLower(rbacAttestorRuntimeResourceId) == toLower(contractInputs.rbacAttestorRuntimeResourceId) && toLower(runtimeSupportIdentityResourceId) == toLower(contractInputs.runtimeSupportIdentityResourceId) && toLower(collectorRuntimeResourceId) != toLower(rbacAttestorRuntimeResourceId) && !contains(
  [
    toLower(contractInputs.collectorIdentityResourceId)
    toLower(handoff.athenaContextIdentityId)
    toLower(contractInputs.rbacAttestorIdentityResourceId)
  ],
  toLower(runtimeSupportIdentityResourceId)
)
var reviewAuthority = handoff.rbacInventoryReviewAuthority
var inventoryAttestation = monitoringEffectiveRbacInventoryAttestation
var reviewAuthorityIsSeparated = !contains(
  [
    toLower(handoff.monitoringReaderPrincipalId)
    toLower(handoff.athenaContextPrincipalId)
    toLower(contractInputs.rbacAttestorPrincipalId)
  ],
  toLower(reviewAuthority.reviewerPrincipalId)
) && toLower(reviewAuthority.verifierIdentityPrincipalId) != toLower(
  reviewAuthority.reviewerPrincipalId
) && !contains(
  [
    toLower(contractInputs.collectorIdentityResourceId)
    toLower(handoff.athenaContextIdentityId)
    toLower(contractInputs.rbacAttestorIdentityResourceId)
    toLower(contractInputs.runtimeSupportIdentityResourceId)
  ],
  toLower(reviewAuthority.verifierIdentityResourceId)
)
var expectedCollectorAssociatedResourcesRequestPath = '${toLower(contractInputs.collectorIdentityResourceId)}/listAssociatedResources?api-version=2021-09-30-preview'
var expectedCollectorFederatedCredentialsRequestPath = '${toLower(contractInputs.collectorIdentityResourceId)}/federatedIdentityCredentials?api-version=2023-01-31'
var expectedAttestorAssociatedResourcesRequestPath = '${toLower(contractInputs.rbacAttestorIdentityResourceId)}/listAssociatedResources?api-version=2021-09-30-preview'
var expectedAttestorFederatedCredentialsRequestPath = '${toLower(contractInputs.rbacAttestorIdentityResourceId)}/federatedIdentityCredentials?api-version=2023-01-31'
var expectedVerifierAssociatedResourcesRequestPath = '${toLower(contractInputs.rbacInventoryVerifierIdentityResourceId)}/listAssociatedResources?api-version=2021-09-30-preview'
var expectedVerifierFederatedCredentialsRequestPath = '${toLower(contractInputs.rbacInventoryVerifierIdentityResourceId)}/federatedIdentityCredentials?api-version=2023-01-31'
var expectedCollectorRuntimeConfigurationRequestPath = '${toLower(collectorRuntimeResourceId)}?api-version=2025-01-01'
var expectedAttestorRuntimeConfigurationRequestPath = '${toLower(rbacAttestorRuntimeResourceId)}?api-version=2025-01-01'
var managedIdentityAttachmentCollectionMatches = handoff.managedIdentityAttachmentCollection.collectorAssociatedResourcesRequestPath == expectedCollectorAssociatedResourcesRequestPath && handoff.managedIdentityAttachmentCollection.collectorFederatedIdentityCredentialsRequestPath == expectedCollectorFederatedCredentialsRequestPath && handoff.managedIdentityAttachmentCollection.rbacAttestorAssociatedResourcesRequestPath == expectedAttestorAssociatedResourcesRequestPath && handoff.managedIdentityAttachmentCollection.rbacAttestorFederatedIdentityCredentialsRequestPath == expectedAttestorFederatedCredentialsRequestPath && handoff.managedIdentityAttachmentCollection.reviewerKeyVerifierAssociatedResourcesRequestPath == expectedVerifierAssociatedResourcesRequestPath && handoff.managedIdentityAttachmentCollection.reviewerKeyVerifierFederatedIdentityCredentialsRequestPath == expectedVerifierFederatedCredentialsRequestPath
var expectedEvidenceStorageConfigurationRequestPath = '${toLower(contractInputs.evidenceStorageAccountResourceId)}?api-version=2025-06-01'
var expectedEvidenceBlobServiceConfigurationRequestPath = '${toLower(contractInputs.evidenceBlobServiceResourceId)}?api-version=2025-06-01'
var expectedEvidenceContainerConfigurationRequestPath = '${toLower(contractInputs.evidenceContainerResourceId)}?api-version=2025-06-01'
var expectedEvidenceImmutabilityPolicyConfigurationRequestPath = '${toLower(contractInputs.evidenceImmutabilityPolicyResourceId)}?api-version=2025-06-01'
var expectedSigningKeyVaultConfigurationRequestPath = '${toLower(contractInputs.signingKeyVaultResourceId)}?api-version=2024-11-01'
var exclusivePrincipalCollectionMatches = handoff.exclusiveDataPlanePrincipalCollection.assignmentCollectionScopeId == subscriptionScope && handoff.exclusiveDataPlanePrincipalCollection.queryFilter == 'none' && handoff.exclusiveDataPlanePrincipalCollection.evidenceStorageConfigurationRequestPath == expectedEvidenceStorageConfigurationRequestPath && handoff.exclusiveDataPlanePrincipalCollection.evidenceBlobServiceConfigurationRequestPath == expectedEvidenceBlobServiceConfigurationRequestPath && handoff.exclusiveDataPlanePrincipalCollection.evidenceContainerConfigurationRequestPath == expectedEvidenceContainerConfigurationRequestPath && handoff.exclusiveDataPlanePrincipalCollection.evidenceImmutabilityPolicyConfigurationRequestPath == expectedEvidenceImmutabilityPolicyConfigurationRequestPath && handoff.exclusiveDataPlanePrincipalCollection.signingKeyVaultConfigurationRequestPath == expectedSigningKeyVaultConfigurationRequestPath
var inventoryAttestationStructurallyMatches = inventoryAttestation.schemaVersion == 'athena.wc028MonitoringEffectiveRbacInventoryAttestation.v1' && inventoryAttestation.signatureAlgorithm == 'RS256' && inventoryAttestation.bootstrapHandoffId == handoff.handoffId && toLower(inventoryAttestation.bootstrapDeploymentId) == toLower(expectedBootstrapDeploymentId) && inventoryAttestation.bootstrapTemplateHash == bootstrapTemplateHash && inventoryAttestation.bootstrapContractInputsBindingId == expectedCollectorContractInputsBindingId && toLower(inventoryAttestation.reviewerPrincipalId) == toLower(reviewAuthority.reviewerPrincipalId) && inventoryAttestation.reviewerKeyId == reviewAuthority.reviewerKeyId && inventoryAttestation.publicKeyModulus == reviewAuthority.publicKeyModulus && inventoryAttestation.publicKeyExponent == reviewAuthority.publicKeyExponent && inventoryAttestation.publicKeyFingerprint == reviewAuthority.publicKeyFingerprint && inventoryAttestation.inventoryDigest == validatedReviewedInventoryDigest && inventoryAttestation.sourceManifestDigest == monitoringEffectiveRbacInventory.sourceManifestDigest && inventoryAttestation.legacyCollectorRbacCleanupSchemaVersion == handoff.legacyCollectorRbacCleanupSchemaVersion && inventoryAttestation.legacyCollectorRbacCleanupDigest == handoff.legacyCollectorRbacCleanupDigest && !empty(inventoryAttestation.signedPreimageDigest) && !empty(inventoryAttestation.signature)

var bootstrapCoreIsValid = monitoringRbacBootstrapDeployment.properties.provisioningState == 'Succeeded' && handoff.schemaVersion == 'athena.wc024MonitoringRbacBootstrapHandoff.v1' && handoff.sourceDeploymentName == monitoringRbacBootstrapDeploymentName && handoff.sourceDeploymentId == expectedBootstrapDeploymentId && handoff.collectorContractInputsBindingId == expectedCollectorContractInputsBindingId && handoff.handoffId == expectedHandoffId && handoff.publicationState == 'blockedPendingEffectiveRbacInventory' && handoff.legacyCollectorRbacCleanupSchemaVersion == 'athena.wc028LegacyCollectorRbacCleanup.v3' && handoff.legacyCollectorRbacCleanupDigest == contractInputs.legacyCollectorRbacCleanupDigest && contractInputs.legacyCollectorRbacCleanupDigest != 'sha256:0000000000000000000000000000000000000000000000000000000000000000' && toLower(handoff.subscriptionId) == toLower(subscription().subscriptionId) && toLower(handoff.tenantId) == toLower(tenant().tenantId) && toLower(contractInputs.monitoringResourceGroupId) == toLower(monitoringResourceGroupId)
var bootstrapCollectionIsValid = handoff.scopeCollectionMode == 'subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes' && handoff.roleAssignmentCollectionScopeId == subscriptionScope && handoff.roleAssignmentQueryFilter == 'assignedTo(principalId)' && handoff.roleAssignmentIncludeInherited == true && handoff.roleAssignmentIncludeGroups == true && handoff.roleAssignmentIncludeAllDescendantScopes == true && handoff.allPrincipalRoleAssignmentCollectionScopeId == subscriptionScope && handoff.allPrincipalRoleAssignmentQueryFilter == 'none' && handoff.allPrincipalRoleAssignmentIncludeInherited == true && handoff.allPrincipalRoleAssignmentIncludeAllDescendantScopes == true && handoff.roleAssignmentApiVersion == '2022-04-01' && handoff.denyAssignmentIncludeInherited == true && handoff.pimScheduleInstanceIncludeInherited == true && handoff.managementGroupAncestorDisposition == 'explicitManagementGroupAndTenantRootEnumerationRequired' && contractInputs.rbacAttestorGraphApplicationId == '00000003-0000-0000-c000-000000000000' && contractInputs.rbacAttestorGraphApplicationReadAllAppRoleId == '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' && !empty(contractInputs.rbacAttestorGraphApplicationReadAllAssignmentId) && !empty(contractInputs.rbacAttestorGraphServicePrincipalId)
var bootstrapReviewAuthorityIsValid = toLower(reviewAuthority.verifierIdentityResourceId) == toLower(contractInputs.rbacInventoryVerifierIdentityResourceId) && toLower(reviewAuthority.verifierIdentityClientId) == toLower(contractInputs.rbacInventoryVerifierIdentityClientId) && toLower(reviewAuthority.verifierIdentityPrincipalId) == toLower(contractInputs.rbacInventoryVerifierIdentityPrincipalId) && toLower(reviewAuthority.verifierIdentityTenantId) == toLower(contractInputs.rbacInventoryVerifierIdentityTenantId) && toLower(reviewAuthority.reviewerKeyArmResourceId) == toLower(contractInputs.rbacInventoryReviewerKeyArmResourceId)
var bootstrapEvidenceCollectionIsValid = toLower(contractInputs.collectorTenantId) == toLower(handoff.tenantId) && toLower(contractInputs.rbacAttestorTenantId) == toLower(handoff.tenantId) && directoryMembershipCollectionMatches && identityProofAuthorityMatches && managedIdentityAttachmentCollectionMatches && exclusivePrincipalCollectionMatches
var bootstrapSeparationIsValid = runtimeBindingsAreValid && handoff.physicalIdentitySeparationEnforced == true && handoff.reviewAuthoritySeparationEnforced == true && handoffIdentitiesAreSeparated && reviewAuthorityIsSeparated

module bootstrapCoreValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-core'
  params: {
    valid: bootstrapCoreIsValid
    failureMessage: 'monitoring contract publication requires the exact successful phase-one deployment, handoff ID, input binding, and cleanup evidence'
  }
}

module bootstrapCollectionValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-collection'
  params: {
    valid: bootstrapCollectionIsValid
    failureMessage: 'monitoring contract publication requires the exact inherited RBAC, Graph, deny, and PIM collection contract'
  }
}

module bootstrapReviewAuthorityValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-authority'
  params: {
    valid: bootstrapReviewAuthorityIsValid
    failureMessage: 'monitoring contract publication requires the exact isolated reviewer and verifier authority'
  }
}

module bootstrapEvidenceCollectionValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-evidence-collection'
  params: {
    valid: bootstrapEvidenceCollectionIsValid
    failureMessage: 'monitoring contract publication requires exact identities, request paths, collection modes, and authentication modes'
  }
}

module bootstrapSeparationValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-separation'
  params: {
    valid: bootstrapSeparationIsValid
    failureMessage: 'monitoring contract publication requires complete runtime and reviewer identity separation'
  }
}

module bootstrapTargetValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-rbac-bootstrap-targets'
  params: {
    valid: targetScopesMatch
    failureMessage: 'monitoring contract publication requires the exact unique subscription and descendant target scopes'
  }
}

var inventory = monitoringEffectiveRbacInventory
var effectiveRbacInventoryJson = string(inventory)
var validatedEffectiveRbacInventoryJson = length(effectiveRbacInventoryJson) <= 55000
  ? effectiveRbacInventoryJson
  : fail('monitoring contract publication limits the compact effective-RBAC inventory to 55,000 characters so total deployment-script environment data remains transport-safe')
module inventoryAttestationValidation 'modules/monitoring-rbac-inventory-attestation-validation.bicep' = {
  name: 'verify-monitoring-rbac-inventory-attestation'
  scope: resourceGroup(monitoringResourceGroupName)
  dependsOn: [
    bootstrapCoreValidationGate
    bootstrapCollectionValidationGate
    bootstrapReviewAuthorityValidationGate
    bootstrapEvidenceCollectionValidationGate
    bootstrapSeparationValidationGate
    bootstrapTargetValidationGate
  ]
  params: {
    signatureAlgorithm: inventoryAttestation.signatureAlgorithm
    bootstrapHandoffId: handoff.handoffId
    bootstrapDeploymentId: expectedBootstrapDeploymentId
    bootstrapTemplateHash: bootstrapTemplateHash
    bootstrapContractInputsBindingId: expectedCollectorContractInputsBindingId
    verifierIdentityResourceId: reviewAuthority.verifierIdentityResourceId
    reviewerPrincipalId: reviewAuthority.reviewerPrincipalId
    reviewerKeyId: reviewAuthority.reviewerKeyId
    publicKeyModulus: reviewAuthority.publicKeyModulus
    publicKeyExponent: reviewAuthority.publicKeyExponent
    publicKeyFingerprint: reviewAuthority.publicKeyFingerprint
    inventoryDigest: validatedReviewedInventoryDigest
    sourceManifestDigest: inventory.sourceManifestDigest
    legacyCollectorRbacCleanupSchemaVersion: handoff.legacyCollectorRbacCleanupSchemaVersion
    legacyCollectorRbacCleanupDigest: handoff.legacyCollectorRbacCleanupDigest
    signedPreimageDigest: inventoryAttestation.signedPreimageDigest
    signature: inventoryAttestation.signature
    effectiveRbacInventoryJson: validatedEffectiveRbacInventoryJson
  }
}

var inventoryAttestationMatches = inventoryAttestationStructurallyMatches && inventoryAttestationValidation.outputs.validated == true && inventoryAttestationValidation.outputs.inventoryDigest == validatedReviewedInventoryDigest && inventoryAttestationValidation.outputs.signedPreimageDigest == inventoryAttestation.signedPreimageDigest
var sealedInventoryAttestation = {
  schemaVersion: inventoryAttestation.schemaVersion
  signatureAlgorithm: inventoryAttestation.signatureAlgorithm
  bootstrapHandoffId: inventoryAttestation.bootstrapHandoffId
  bootstrapDeploymentId: inventoryAttestation.bootstrapDeploymentId
  bootstrapTemplateHash: inventoryAttestation.bootstrapTemplateHash
  bootstrapContractInputsBindingId: inventoryAttestation.bootstrapContractInputsBindingId
  reviewerPrincipalId: inventoryAttestation.reviewerPrincipalId
  reviewerKeyId: inventoryAttestation.reviewerKeyId
  publicKeyModulus: inventoryAttestation.publicKeyModulus
  publicKeyExponent: inventoryAttestation.publicKeyExponent
  publicKeyFingerprint: inventoryAttestation.publicKeyFingerprint
  inventoryDigest: inventoryAttestation.inventoryDigest
  sourceManifestDigest: inventoryAttestation.sourceManifestDigest
  legacyCollectorRbacCleanupSchemaVersion: inventoryAttestation.legacyCollectorRbacCleanupSchemaVersion
  legacyCollectorRbacCleanupDigest: inventoryAttestation.legacyCollectorRbacCleanupDigest
  signedPreimageDigest: inventoryAttestation.signedPreimageDigest
  signature: inventoryAttestation.signature
}
var collectorEvidence = inventory.collectorPrincipalEvidence
var contextEvidence = inventory.athenaContextPrincipalEvidence
var runtimeSupportEvidence = inventory.runtimeSupportPrincipalEvidence
var hierarchyEvidence = inventory.managementGroupHierarchyEvidence
var collectorAttachmentEvidence = inventory.collectorIdentityAttachmentEvidence
var attestorAttachmentEvidence = inventory.rbacAttestorIdentityAttachmentEvidence
var verifierEvidence = inventory.reviewerKeyVerifierEvidence
var exclusivePrincipalEvidence = inventory.exclusiveDataPlanePrincipalEvidence
var normalizedCollectorTargetScopeIds = map(
  inventory.collectorPrincipalEvidence.targetScopeIds,
  scopeId => toLower(scopeId)
)
var normalizedContextTargetScopeIds = map(
  inventory.athenaContextPrincipalEvidence.targetScopeIds,
  scopeId => toLower(scopeId)
)
var normalizedRuntimeSupportTargetScopeIds = map(
  runtimeSupportEvidence.targetScopeIds,
  scopeId => toLower(scopeId)
)
var collectorTargetsAreUnique = length(union(normalizedCollectorTargetScopeIds, [])) == length(normalizedCollectorTargetScopeIds)
var contextTargetsAreUnique = length(union(normalizedContextTargetScopeIds, [])) == length(normalizedContextTargetScopeIds)
var runtimeSupportTargetsAreUnique = length(union(normalizedRuntimeSupportTargetScopeIds, [])) == length(normalizedRuntimeSupportTargetScopeIds)
var normalizedInventoryProtectedScopeIds = map(inventory.protectedScopeIds, scopeId => toLower(scopeId))
var normalizedManagementGroupAncestry = map(inventory.managementGroupAncestry, scopeId => toLower(scopeId))
var tenantRootManagementGroupScope = '/providers/microsoft.management/managementgroups/${toLower(handoff.tenantId)}'
var managementGroupAncestryIsComplete = !empty(normalizedManagementGroupAncestry) && length(union(normalizedManagementGroupAncestry, [])) == length(normalizedManagementGroupAncestry) && last(normalizedManagementGroupAncestry) == tenantRootManagementGroupScope && empty(filter(normalizedManagementGroupAncestry, scopeId => !startsWith(scopeId, '/providers/microsoft.management/managementgroups/')))
var expectedHierarchyEdges = [
  for (parentScopeId, index) in normalizedManagementGroupAncestry: {
    childScopeId: index == 0 ? toLower(subscriptionScope) : normalizedManagementGroupAncestry[index - 1]
    parentScopeId: parentScopeId
  }
]
var normalizedHierarchyEdges = map(hierarchyEvidence.parentEdges, edge => {
  childScopeId: toLower(edge.childScopeId)
  parentScopeId: toLower(edge.parentScopeId)
})
var hierarchyEvidenceIsComplete = handoff.managementGroupHierarchyCollection.requestMethod == 'POST' && handoff.managementGroupHierarchyCollection.requestPath == '/providers/Microsoft.Management/getEntities?api-version=2020-05-01&$select=Name,Type,ParentNameChain' && handoff.managementGroupHierarchyCollection.subscriptionScopeId == subscriptionScope && handoff.managementGroupHierarchyCollection.requiresAllPages == true && handoff.managementGroupHierarchyCollection.requiresTwoStableReads == true && toLower(handoff.managementGroupHierarchyCollection.tenantRootScopeId) == tenantRootManagementGroupScope && hierarchyEvidence.requestPath == handoff.managementGroupHierarchyCollection.requestPath && toLower(hierarchyEvidence.subscriptionScopeId) == toLower(subscriptionScope) && string(map(hierarchyEvidence.orderedAncestry, scopeId => toLower(scopeId))) == string(normalizedManagementGroupAncestry) && string(normalizedHierarchyEdges) == string(expectedHierarchyEdges) && hierarchyEvidence.allPagesRetrieved == true && hierarchyEvidence.firstReadCompletedAt < hierarchyEvidence.secondReadCompletedAt && hierarchyEvidence.secondReadCompletedAt <= inventory.collectedAt && !empty(hierarchyEvidence.firstRawPageDigests) && string(hierarchyEvidence.firstRawPageDigests) == string(hierarchyEvidence.secondRawPageDigests)
var expectedInventoryProtectedScopeIds = union(concat(normalizedHandoffTargetScopeIds, normalizedManagementGroupAncestry), [])
var expectedPrincipalTargetScopeIds = union(concat([
  toLower(subscriptionScope)
], normalizedManagementGroupAncestry), [])
var protectedScopesMatch = length(union(normalizedInventoryProtectedScopeIds, [])) == length(normalizedInventoryProtectedScopeIds) && length(normalizedInventoryProtectedScopeIds) == length(expectedInventoryProtectedScopeIds) && length(union(
  normalizedInventoryProtectedScopeIds,
  expectedInventoryProtectedScopeIds
)) == length(expectedInventoryProtectedScopeIds)
var collectorTargetsMatch = collectorTargetsAreUnique && length(normalizedCollectorTargetScopeIds) == length(expectedPrincipalTargetScopeIds) && length(union(normalizedCollectorTargetScopeIds, expectedPrincipalTargetScopeIds)) == length(expectedPrincipalTargetScopeIds)
var contextTargetsMatch = contextTargetsAreUnique && length(normalizedContextTargetScopeIds) == length(expectedPrincipalTargetScopeIds) && length(union(normalizedContextTargetScopeIds, expectedPrincipalTargetScopeIds)) == length(expectedPrincipalTargetScopeIds)
var runtimeSupportTargetsMatch = runtimeSupportTargetsAreUnique && length(normalizedRuntimeSupportTargetScopeIds) == length(expectedPrincipalTargetScopeIds) && length(union(normalizedRuntimeSupportTargetScopeIds, expectedPrincipalTargetScopeIds)) == length(expectedPrincipalTargetScopeIds)
var publicationRequestedAt = publicationClock.outputs.deploymentTimestamp
var publicationRequestedAtEpoch = dateTimeToEpoch(publicationRequestedAt)
var inventoryCollectedAtEpoch = dateTimeToEpoch(inventory.collectedAt)
var inventoryExpiresAtEpoch = dateTimeToEpoch(inventory.expiresAt)
var inventoryIsFresh = inventoryCollectedAtEpoch <= publicationRequestedAtEpoch && publicationRequestedAtEpoch < inventoryExpiresAtEpoch && inventoryExpiresAtEpoch - inventoryCollectedAtEpoch <= 900
var firstReadCompletedAtEpoch = dateTimeToEpoch(inventory.firstReadCompletedAt)
var secondReadCompletedAtEpoch = dateTimeToEpoch(inventory.secondReadCompletedAt)
var independentReadTimesAreValid = firstReadCompletedAtEpoch < secondReadCompletedAtEpoch && secondReadCompletedAtEpoch <= inventoryCollectedAtEpoch
var principalEvidenceIsComplete = collectorEvidence.queryFilter == 'assignedTo(principalId)' && contextEvidence.queryFilter == 'assignedTo(principalId)' && runtimeSupportEvidence.queryFilter == 'assignedTo(principalId)' && collectorEvidence.includeInherited == true && collectorEvidence.includeGroups == true && collectorEvidence.includeAllDescendantScopes == true && contextEvidence.includeInherited == true && contextEvidence.includeGroups == true && contextEvidence.includeAllDescendantScopes == true && runtimeSupportEvidence.includeInherited == true && runtimeSupportEvidence.includeGroups == true && runtimeSupportEvidence.includeAllDescendantScopes == true && collectorEvidence.allPagesRetrieved == true && contextEvidence.allPagesRetrieved == true && runtimeSupportEvidence.allPagesRetrieved == true && length(collectorEvidence.firstReadTargetDigests) == length(expectedPrincipalTargetScopeIds) && length(contextEvidence.firstReadTargetDigests) == length(expectedPrincipalTargetScopeIds) && length(runtimeSupportEvidence.firstReadTargetDigests) == length(expectedPrincipalTargetScopeIds) && string(collectorEvidence.firstReadTargetDigests) == string(collectorEvidence.secondReadTargetDigests) && string(contextEvidence.firstReadTargetDigests) == string(contextEvidence.secondReadTargetDigests) && string(runtimeSupportEvidence.firstReadTargetDigests) == string(runtimeSupportEvidence.secondReadTargetDigests) && string(collectorEvidence.transitiveGroupIds) == string(inventory.collectorSecurityGroupIds) && string(contextEvidence.transitiveGroupIds) == string(inventory.athenaContextSecurityGroupIds) && empty(runtimeSupportEvidence.transitiveGroupIds) && !empty(collectorEvidence.firstRoleAssignmentRawPageDigests) && string(collectorEvidence.firstRoleAssignmentRawPageDigests) == string(collectorEvidence.secondRoleAssignmentRawPageDigests) && !empty(contextEvidence.firstRoleAssignmentRawPageDigests) && string(contextEvidence.firstRoleAssignmentRawPageDigests) == string(contextEvidence.secondRoleAssignmentRawPageDigests) && !empty(runtimeSupportEvidence.firstRoleAssignmentRawPageDigests) && string(runtimeSupportEvidence.firstRoleAssignmentRawPageDigests) == string(runtimeSupportEvidence.secondRoleAssignmentRawPageDigests) && !empty(collectorEvidence.firstTransitiveGroupRawPageDigests) && string(collectorEvidence.firstTransitiveGroupRawPageDigests) == string(collectorEvidence.secondTransitiveGroupRawPageDigests) && !empty(contextEvidence.firstTransitiveGroupRawPageDigests) && string(contextEvidence.firstTransitiveGroupRawPageDigests) == string(contextEvidence.secondTransitiveGroupRawPageDigests) && !empty(runtimeSupportEvidence.firstTransitiveGroupRawPageDigests) && string(runtimeSupportEvidence.firstTransitiveGroupRawPageDigests) == string(runtimeSupportEvidence.secondTransitiveGroupRawPageDigests)
var normalizedResourceReadScopeIds = map(contractInputs.resourceReadScopeIds, scopeId => toLower(scopeId))
var normalizedSignalReadScopeIds = map(contractInputs.signalReadScopeIds, scopeId => toLower(scopeId))
var normalizedResourceLogReadScopeIds = map(contractInputs.resourceLogReadScopeIds, scopeId => toLower(scopeId))
var normalizedResourceHealthScopeIds = map(contractInputs.resourceHealthScopeIds, scopeId => toLower(scopeId))
var expectedEvidenceWriterCondition = '(((!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND NOT SubOperationMatches{\'Blob.List\'})) AND !(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action\'})) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals \'monitoring-evidence\' AND (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/commits/*/manifest.json\' OR @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/commits/*/recovery.json\' OR @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike \'wc024-monitoring/wc024-*/evidence.json\'))) AND (!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'})))'
var expectedCollectorGrantBindings = [
  {
    roleDefinitionId: toLower(contractInputs.readerRoleDefinitionId)
    roleDefinitionName: 'Reader'
    assignmentScopeIds: normalizedResourceReadScopeIds
  }
  {
    roleDefinitionId: toLower(contractInputs.signalReaderRoleDefinitionId)
    roleDefinitionName: contractInputs.signalReaderRoleName
    assignmentScopeIds: normalizedSignalReadScopeIds
  }
  {
    roleDefinitionId: toLower(contractInputs.resourceLogReaderRoleDefinitionId)
    roleDefinitionName: contractInputs.resourceLogReaderRoleName
    assignmentScopeIds: normalizedResourceLogReadScopeIds
  }
  {
    roleDefinitionId: toLower(contractInputs.resourceHealthRoleDefinitionId)
    roleDefinitionName: contractInputs.resourceHealthRoleName
    assignmentScopeIds: normalizedResourceHealthScopeIds
  }
  {
    roleDefinitionId: toLower(contractInputs.evidenceWriterRoleDefinitionId)
    roleDefinitionName: contractInputs.evidenceWriterRoleName
    assignmentScopeIds: [
      toLower(contractInputs.evidenceContainerResourceId)
    ]
  }
  {
    roleDefinitionId: toLower(contractInputs.signingKeyCryptoUserRoleDefinitionId)
    roleDefinitionName: 'Key Vault Crypto User'
    assignmentScopeIds: [
      toLower(contractInputs.signingKeyArmResourceId)
    ]
  }
]
var invalidCollectorGrants = filter(
  inventory.collectorGrants,
  grant =>
    length(filter(
      expectedCollectorGrantBindings,
      expected =>
        toLower(grant.roleDefinitionId) == expected.roleDefinitionId && grant.roleDefinitionName == expected.roleDefinitionName && length(grant.assignmentScopeIds) == length(expected.assignmentScopeIds) && length(union(
          map(grant.assignmentScopeIds, scopeId => toLower(scopeId)),
          expected.assignmentScopeIds
        )) == length(expected.assignmentScopeIds)
    )) != 1 || length(union(map(grant.assignmentScopeIds, scopeId => toLower(scopeId)), [])) != length(grant.assignmentScopeIds) || toLower(grant.assignedPrincipalId) != toLower(inventory.collectorPrincipalId) || grant.assignedPrincipalType != 'ServicePrincipal' || toLower(grant.effectivePrincipalId) != toLower(inventory.collectorPrincipalId) || grant.inheritance != 'direct' || grant.groupDerived != false || (toLower(grant.roleDefinitionId) == toLower(contractInputs.evidenceWriterRoleDefinitionId)
      ? !contains(grant, 'condition') || !contains(grant, 'conditionVersion') || grant.condition != expectedEvidenceWriterCondition || grant.conditionVersion != '2.0'
      : contains(grant, 'condition') || contains(grant, 'conditionVersion'))
)
var missingOrDuplicateExpectedCollectorGrants = filter(
  expectedCollectorGrantBindings,
  expected =>
    length(filter(
      inventory.collectorGrants,
      grant =>
        toLower(grant.roleDefinitionId) == expected.roleDefinitionId && grant.roleDefinitionName == expected.roleDefinitionName && length(grant.assignmentScopeIds) == length(expected.assignmentScopeIds) && length(union(
          map(grant.assignmentScopeIds, scopeId => toLower(scopeId)),
          expected.assignmentScopeIds
        )) == length(expected.assignmentScopeIds)
    )) != 1
)
var collectorGrantRoleIds = map(inventory.collectorGrants, grant => toLower(grant.roleDefinitionId))
var collectorGrantDigests = map(inventory.collectorGrants, grant => grant.grantDigest)
var collectorGrantsMatch = length(inventory.collectorGrants) == length(expectedCollectorGrantBindings) && length(union(
  collectorGrantRoleIds,
  []
)) == length(collectorGrantRoleIds) && length(union(collectorGrantDigests, [])) == length(collectorGrantDigests) && empty(invalidCollectorGrants) && empty(missingOrDuplicateExpectedCollectorGrants)
var runtimeSupportGrantMatches = length(inventory.runtimeSupportGrants) == 1 && toLower(inventory.runtimeSupportPrincipalId) == toLower(contractInputs.runtimeSupportIdentityPrincipalId) && toLower(runtimeSupportEvidence.principalId) == toLower(contractInputs.runtimeSupportIdentityPrincipalId) && toLower(inventory.runtimeSupportGrants[0].assignedPrincipalId) == toLower(contractInputs.runtimeSupportIdentityPrincipalId) && inventory.runtimeSupportGrants[0].assignedPrincipalType == 'ServicePrincipal' && toLower(inventory.runtimeSupportGrants[0].effectivePrincipalId) == toLower(contractInputs.runtimeSupportIdentityPrincipalId) && toLower(inventory.runtimeSupportGrants[0].roleDefinitionId) == toLower(contractInputs.runtimeSupportStorageReaderRoleDefinitionId) && inventory.runtimeSupportGrants[0].roleDefinitionName == contractInputs.runtimeSupportStorageReaderRoleName && inventory.runtimeSupportGrants[0].assignmentScopeIds == [
  toLower(contractInputs.runtimeSupportStorageReaderScopeId)
] && inventory.runtimeSupportGrants[0].inheritance == 'direct' && inventory.runtimeSupportGrants[0].groupDerived == false && !contains(inventory.runtimeSupportGrants[0], 'condition') && !contains(inventory.runtimeSupportGrants[0], 'conditionVersion')
var expectedRoleDefinitionIds = union(map(expectedCollectorGrantBindings, binding => binding.roleDefinitionId), [
  toLower(contractInputs.rbacAttestorRoleDefinitionId)
  toLower(contractInputs.rbacInventoryVerifierRoleDefinitionId)
  toLower(contractInputs.runtimeSupportStorageReaderRoleDefinitionId)
])
var actualRoleDefinitionIds = map(inventory.roleDefinitions, role => toLower(role.roleDefinitionId))
var roleDefinitionSetMatches = length(union(actualRoleDefinitionIds, [])) == length(actualRoleDefinitionIds) && length(actualRoleDefinitionIds) == length(expectedRoleDefinitionIds) && length(union(
  actualRoleDefinitionIds,
  expectedRoleDefinitionIds
)) == length(expectedRoleDefinitionIds)
var expectedCustomRoleDefinitions = [
  {
    roleDefinitionId: toLower(contractInputs.signalReaderRoleDefinitionId)
    actions: [
      'microsoft.compute/virtualmachines/instanceview/read'
      'microsoft.insights/metrics/read'
    ]
  }
  {
    roleDefinitionId: toLower(contractInputs.resourceLogReaderRoleDefinitionId)
    actions: map(contractInputs.resourceLogAllowedOperations, action => toLower(action))
  }
  {
    roleDefinitionId: toLower(contractInputs.resourceHealthRoleDefinitionId)
    actions: map(contractInputs.resourceHealthAllowedOperations, action => toLower(action))
  }
  {
    roleDefinitionId: toLower(contractInputs.rbacAttestorRoleDefinitionId)
    actions: map(contractInputs.rbacAttestorAllowedOperations, action => toLower(action))
  }
  {
    roleDefinitionId: toLower(contractInputs.runtimeSupportStorageReaderRoleDefinitionId)
    actions: map(contractInputs.runtimeSupportStorageReaderAllowedOperations, action => toLower(action))
  }
]
var invalidCustomRoleDefinitions = filter(
  inventory.roleDefinitions,
  role =>
    contains(map(expectedCustomRoleDefinitions, expected => expected.roleDefinitionId), toLower(role.roleDefinitionId)) && length(filter(
      expectedCustomRoleDefinitions,
      expected =>
        toLower(role.roleDefinitionId) == expected.roleDefinitionId && length(role.actions) == length(expected.actions) && length(union(
          map(role.actions, action => toLower(action)),
          expected.actions
        )) == length(expected.actions)
    )) != 1 || contains(
      map(expectedCustomRoleDefinitions, expected => expected.roleDefinitionId),
      toLower(role.roleDefinitionId)
    ) && (!empty(role.notActions) || !empty(role.dataActions) || !empty(role.notDataActions))
)
var customRoleDefinitionsMatch = empty(invalidCustomRoleDefinitions)
var evidenceWriterRoleDefinitions = filter(
  inventory.roleDefinitions,
  role => toLower(role.roleDefinitionId) == toLower(contractInputs.evidenceWriterRoleDefinitionId)
)
var invalidEvidenceWriterRoleDefinitions = filter(
  evidenceWriterRoleDefinitions,
  role => role.roleDefinitionName != contractInputs.evidenceWriterRoleName || !empty(role.actions) || !empty(role.notActions) || !empty(role.notDataActions) || length(role.dataActions) != length(contractInputs.evidenceWriterAllowedDataActions) || length(union(
    map(role.dataActions, action => toLower(action)),
    map(contractInputs.evidenceWriterAllowedDataActions, action => toLower(action))
  )) != length(contractInputs.evidenceWriterAllowedDataActions)
)
var evidenceWriterRoleDefinitionMatches = length(evidenceWriterRoleDefinitions) == 1 && empty(invalidEvidenceWriterRoleDefinitions)
var verifierRoleDefinitions = filter(
  inventory.roleDefinitions,
  role => toLower(role.roleDefinitionId) == toLower(contractInputs.rbacInventoryVerifierRoleDefinitionId)
)
var invalidVerifierRoleDefinitions = filter(
  verifierRoleDefinitions,
  role => role.roleDefinitionName != contractInputs.rbacInventoryVerifierRoleName || !empty(role.actions) || !empty(role.notActions) || !empty(role.notDataActions) || length(role.dataActions) != length(contractInputs.rbacInventoryVerifierAllowedDataActions) || length(union(
    map(role.dataActions, action => toLower(action)),
    map(contractInputs.rbacInventoryVerifierAllowedDataActions, action => toLower(action))
  )) != length(contractInputs.rbacInventoryVerifierAllowedDataActions)
)
var verifierRoleDefinitionMatches = length(verifierRoleDefinitions) == 1 && empty(invalidVerifierRoleDefinitions)
var exactExpectedAssignmentCount = length(normalizedResourceReadScopeIds) + length(normalizedSignalReadScopeIds) + length(normalizedResourceLogReadScopeIds) + length(normalizedResourceHealthScopeIds) + 4
var globalRepeatedReadPagesAreStable = !empty(inventory.firstRoleDefinitionRawPageDigests) && string(inventory.firstRoleDefinitionRawPageDigests) == string(inventory.secondRoleDefinitionRawPageDigests) && !empty(inventory.firstDenyAssignmentRawPageDigests) && string(inventory.firstDenyAssignmentRawPageDigests) == string(inventory.secondDenyAssignmentRawPageDigests) && !empty(inventory.firstPimScheduleInstanceRawPageDigests) && string(inventory.firstPimScheduleInstanceRawPageDigests) == string(inventory.secondPimScheduleInstanceRawPageDigests)
var collectorEffectivePrincipalIds = union(
  [
    toLower(inventory.collectorPrincipalId)
  ],
  map(inventory.collectorSecurityGroupIds, principalId => toLower(principalId))
)
var allPrincipalsId = '00000000-0000-0000-0000-000000000000'
var malformedAllPrincipalsDenyAssignments = filter(
  inventory.denyAssignments,
  deny => contains(map(deny.excludedPrincipalIds, principalId => toLower(principalId)), allPrincipalsId) || (contains(map(deny.principalIds, principalId => toLower(principalId)), allPrincipalsId) && length(deny.principalIds) != 1)
)
var effectiveDenyAssignments = filter(
  inventory.denyAssignments,
  deny =>
    empty(filter(
      deny.excludedPrincipalIds,
      principalId => contains(collectorEffectivePrincipalIds, toLower(principalId))
    )) && (empty(deny.principalIds) || contains(
      map(deny.principalIds, principalId => toLower(principalId)),
      allPrincipalsId
    ) || !empty(filter(deny.principalIds, principalId => contains(collectorEffectivePrincipalIds, toLower(principalId)))))
)
var denyAssignmentsAreSafe = empty(malformedAllPrincipalsDenyAssignments) && empty(effectiveDenyAssignments) && empty(filter(
  inventory.denyAssignments,
  deny => contains(deny, 'condition')
))
var runtimeSupportEffectiveDenyAssignments = filter(
  inventory.denyAssignments,
  deny =>
    !contains(map(deny.excludedPrincipalIds, principalId => toLower(principalId)), toLower(contractInputs.runtimeSupportIdentityPrincipalId)) && (empty(deny.principalIds) || contains(
      map(deny.principalIds, principalId => toLower(principalId)),
      allPrincipalsId
    ) || contains(map(deny.principalIds, principalId => toLower(principalId)), toLower(contractInputs.runtimeSupportIdentityPrincipalId)))
)
var runtimeSupportDenyAssignmentsAreSafe = empty(runtimeSupportEffectiveDenyAssignments)
var verifierEffectiveDenyAssignments = filter(
  inventory.denyAssignments,
  deny =>
    !contains(map(deny.excludedPrincipalIds, principalId => toLower(principalId)), toLower(verifierEvidence.identityPrincipalId)) && (empty(deny.principalIds) || contains(
      map(deny.principalIds, principalId => toLower(principalId)),
      allPrincipalsId
    ) || contains(map(deny.principalIds, principalId => toLower(principalId)), toLower(verifierEvidence.identityPrincipalId)))
)
var verifierDenyAssignmentsAreSafe = empty(verifierEffectiveDenyAssignments)
var normalizedCollectorRuntimeIdentityIds = map(
  collectorAttachmentEvidence.associatedResourceIdentityResourceIds,
  identityId => toLower(identityId)
)
var expectedCollectorRuntimeIdentityIds = [
  toLower(contractInputs.collectorIdentityResourceId)
  toLower(runtimeSupportIdentityResourceId)
]
var collectorRuntimeIdentitySetMatches = length(union(normalizedCollectorRuntimeIdentityIds, [])) == length(normalizedCollectorRuntimeIdentityIds) && length(normalizedCollectorRuntimeIdentityIds) == length(expectedCollectorRuntimeIdentityIds) && length(union(
  normalizedCollectorRuntimeIdentityIds,
  expectedCollectorRuntimeIdentityIds
)) == length(expectedCollectorRuntimeIdentityIds)
var normalizedAttestorRuntimeIdentityIds = map(
  attestorAttachmentEvidence.associatedResourceIdentityResourceIds,
  identityId => toLower(identityId)
)
var attestorRuntimeIdentitySetMatches = normalizedAttestorRuntimeIdentityIds == [
  toLower(contractInputs.rbacAttestorIdentityResourceId)
]
var collectorAttachmentMatches = toLower(collectorAttachmentEvidence.identityResourceId) == toLower(contractInputs.collectorIdentityResourceId) && collectorAttachmentEvidence.associatedResourcesRequestPath == expectedCollectorAssociatedResourcesRequestPath && collectorAttachmentEvidence.federatedIdentityCredentialsRequestPath == expectedCollectorFederatedCredentialsRequestPath && collectorAttachmentEvidence.associatedResourceIds == [
  toLower(collectorRuntimeResourceId)
] && collectorAttachmentEvidence.associatedResourceConfigurationRequestPaths == [
  expectedCollectorRuntimeConfigurationRequestPath
] && collectorRuntimeIdentitySetMatches && length(collectorAttachmentEvidence.associatedResourceIdentityLifecycles) == 2 && length(filter(
  collectorAttachmentEvidence.associatedResourceIdentityLifecycles,
  binding => toLower(binding.identityResourceId) == toLower(contractInputs.collectorIdentityResourceId) && binding.lifecycle == 'All'
)) == 1 && length(filter(
  collectorAttachmentEvidence.associatedResourceIdentityLifecycles,
  binding => toLower(binding.identityResourceId) == toLower(runtimeSupportIdentityResourceId) && binding.lifecycle == 'None'
)) == 1 && length(collectorAttachmentEvidence.firstAssociatedResourceConfigurationDigests) == 1 && string(collectorAttachmentEvidence.firstAssociatedResourceConfigurationDigests) == string(collectorAttachmentEvidence.secondAssociatedResourceConfigurationDigests) && empty(collectorAttachmentEvidence.federatedIdentityCredentialIds) && collectorAttachmentEvidence.allPagesRetrieved == true && collectorAttachmentEvidence.firstReadCompletedAt < collectorAttachmentEvidence.secondReadCompletedAt && collectorAttachmentEvidence.secondReadCompletedAt <= inventory.collectedAt && string(collectorAttachmentEvidence.firstAssociatedResourceRawPageDigests) == string(collectorAttachmentEvidence.secondAssociatedResourceRawPageDigests) && string(collectorAttachmentEvidence.firstFederatedCredentialRawPageDigests) == string(collectorAttachmentEvidence.secondFederatedCredentialRawPageDigests)
var attestorAttachmentMatches = toLower(attestorAttachmentEvidence.identityResourceId) == toLower(contractInputs.rbacAttestorIdentityResourceId) && attestorAttachmentEvidence.associatedResourcesRequestPath == expectedAttestorAssociatedResourcesRequestPath && attestorAttachmentEvidence.federatedIdentityCredentialsRequestPath == expectedAttestorFederatedCredentialsRequestPath && attestorAttachmentEvidence.associatedResourceIds == [
  toLower(rbacAttestorRuntimeResourceId)
] && attestorAttachmentEvidence.associatedResourceConfigurationRequestPaths == [
  expectedAttestorRuntimeConfigurationRequestPath
] && attestorRuntimeIdentitySetMatches && attestorAttachmentEvidence.associatedResourceIdentityLifecycles == [
  {
    identityResourceId: toLower(contractInputs.rbacAttestorIdentityResourceId)
    lifecycle: 'All'
  }
] && length(attestorAttachmentEvidence.firstAssociatedResourceConfigurationDigests) == 1 && string(attestorAttachmentEvidence.firstAssociatedResourceConfigurationDigests) == string(attestorAttachmentEvidence.secondAssociatedResourceConfigurationDigests) && empty(attestorAttachmentEvidence.federatedIdentityCredentialIds) && attestorAttachmentEvidence.allPagesRetrieved == true && attestorAttachmentEvidence.firstReadCompletedAt < attestorAttachmentEvidence.secondReadCompletedAt && attestorAttachmentEvidence.secondReadCompletedAt <= inventory.collectedAt && string(attestorAttachmentEvidence.firstAssociatedResourceRawPageDigests) == string(attestorAttachmentEvidence.secondAssociatedResourceRawPageDigests) && string(attestorAttachmentEvidence.firstFederatedCredentialRawPageDigests) == string(attestorAttachmentEvidence.secondFederatedCredentialRawPageDigests)
var expectedPrivilegedScopeIds = map(
  [
    contractInputs.evidenceStorageAccountResourceId
    contractInputs.evidenceBlobServiceResourceId
    contractInputs.evidenceContainerResourceId
    contractInputs.evidenceImmutabilityPolicyResourceId
    contractInputs.signingKeyVaultResourceId
    contractInputs.signingKeyArmResourceId
  ],
  scopeId => toLower(scopeId)
)
var normalizedPrivilegedScopeIds = map(exclusivePrincipalEvidence.scopeIds, scopeId => toLower(scopeId))
var storageReadinessPreimage = 'athena.wc028MonitoringEvidenceStorageReadiness.v1|${toLower(contractInputs.evidenceStorageAccountResourceId)}|${toLower(contractInputs.evidenceBlobServiceResourceId)}|${toLower(contractInputs.evidenceContainerResourceId)}|${toLower(contractInputs.evidenceImmutabilityPolicyResourceId)}|true|${contractInputs.evidenceContainerPublicAccess}|${contractInputs.evidenceContainerImmutabilityPolicyState}|${contractInputs.evidenceContainerImmutabilityPeriodDays}|false|false'
var storageReadbackIsSafe = contractInputs.evidenceBlobVersioningEnabled == true && contractInputs.evidenceContainerPublicAccess == 'None' && contractInputs.evidenceContainerHasImmutabilityPolicy == true && contains([
  'Locked'
  'Unlocked'
], contractInputs.evidenceContainerImmutabilityPolicyState) && contractInputs.evidenceContainerImmutabilityPeriodDays >= 30 && contractInputs.evidenceContainerProtectedAppendWritesEnabled == false && contractInputs.evidenceContainerProtectedAppendWritesAllEnabled == false && contractInputs.evidenceStorageReadbackBindingId == guid(storageReadinessPreimage) && startsWith(contractInputs.evidenceStorageReadinessDigest, 'sha256:') && length(contractInputs.evidenceStorageReadinessDigest) == 71 && contractInputs.evidenceStorageReadinessDigest != 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
var exclusivePrincipalEvidenceMatches = exclusivePrincipalEvidence.assignmentCollectionScopeId == subscriptionScope && exclusivePrincipalEvidence.queryFilter == 'none' && exclusivePrincipalEvidence.includeInherited == true && exclusivePrincipalEvidence.includeAllDescendantScopes == true && exclusivePrincipalEvidence.allPagesRetrieved == true && length(normalizedPrivilegedScopeIds) == length(expectedPrivilegedScopeIds) && length(union(
  normalizedPrivilegedScopeIds,
  expectedPrivilegedScopeIds
)) == length(expectedPrivilegedScopeIds) && exclusivePrincipalEvidence.evidenceWriterAuthorizedPrincipalIds == [
  toLower(inventory.collectorPrincipalId)
] && exclusivePrincipalEvidence.signingKeyAuthorizedPrincipalIds == [
  toLower(inventory.collectorPrincipalId)
] && exclusivePrincipalEvidence.evidenceStorageSharedKeyAccessEnabled == false && exclusivePrincipalEvidence.evidenceStorageDefaultToOAuthAuthentication == true && exclusivePrincipalEvidence.evidenceBlobVersioningEnabled == contractInputs.evidenceBlobVersioningEnabled && exclusivePrincipalEvidence.evidenceContainerPublicAccess == contractInputs.evidenceContainerPublicAccess && exclusivePrincipalEvidence.evidenceContainerHasImmutabilityPolicy == contractInputs.evidenceContainerHasImmutabilityPolicy && exclusivePrincipalEvidence.evidenceContainerImmutabilityPolicyState == contractInputs.evidenceContainerImmutabilityPolicyState && exclusivePrincipalEvidence.evidenceContainerImmutabilityPeriodDays == contractInputs.evidenceContainerImmutabilityPeriodDays && exclusivePrincipalEvidence.evidenceContainerProtectedAppendWritesEnabled == contractInputs.evidenceContainerProtectedAppendWritesEnabled && exclusivePrincipalEvidence.evidenceContainerProtectedAppendWritesAllEnabled == contractInputs.evidenceContainerProtectedAppendWritesAllEnabled && exclusivePrincipalEvidence.signingKeyVaultRbacAuthorizationEnabled == true && empty(exclusivePrincipalEvidence.signingKeyVaultAccessPolicyPrincipalIds) && exclusivePrincipalEvidence.firstReadCompletedAt < exclusivePrincipalEvidence.secondReadCompletedAt && exclusivePrincipalEvidence.secondReadCompletedAt <= inventory.collectedAt && length(exclusivePrincipalEvidence.firstReadTargetDigests) == 1 && string(exclusivePrincipalEvidence.firstReadTargetDigests) == string(exclusivePrincipalEvidence.secondReadTargetDigests) && string(exclusivePrincipalEvidence.firstRawPageDigests) == string(exclusivePrincipalEvidence.secondRawPageDigests) && length(exclusivePrincipalEvidence.firstResourceConfigurationDigests) == 5 && string(exclusivePrincipalEvidence.firstResourceConfigurationDigests) == string(exclusivePrincipalEvidence.secondResourceConfigurationDigests)
var verifierGrant = verifierEvidence.grant
var verifierGrantMatches = toLower(verifierGrant.assignedPrincipalId) == toLower(contractInputs.rbacInventoryVerifierIdentityPrincipalId) && verifierGrant.assignedPrincipalType == 'ServicePrincipal' && toLower(verifierGrant.effectivePrincipalId) == toLower(contractInputs.rbacInventoryVerifierIdentityPrincipalId) && toLower(verifierGrant.roleDefinitionId) == toLower(contractInputs.rbacInventoryVerifierRoleDefinitionId) && verifierGrant.roleDefinitionName == contractInputs.rbacInventoryVerifierRoleName && verifierGrant.assignmentScopeIds == [
  toLower(contractInputs.rbacInventoryReviewerKeyArmResourceId)
] && verifierGrant.inheritance == 'direct' && verifierGrant.groupDerived == false && !contains(verifierGrant, 'condition') && !contains(verifierGrant, 'conditionVersion')
var verifierPrincipalEvidence = verifierEvidence.principalEvidence
var verifierPrincipalEvidenceMatches = toLower(verifierPrincipalEvidence.principalId) == toLower(contractInputs.rbacInventoryVerifierIdentityPrincipalId) && verifierPrincipalEvidence.queryFilter == 'assignedTo(principalId)' && verifierPrincipalEvidence.includeInherited == true && verifierPrincipalEvidence.includeGroups == true && verifierPrincipalEvidence.includeAllDescendantScopes == true && verifierPrincipalEvidence.targetScopeIds == [
  toLower(subscriptionScope)
] && empty(verifierPrincipalEvidence.transitiveGroupIds) && verifierPrincipalEvidence.allPagesRetrieved == true && string(verifierPrincipalEvidence.firstReadTargetDigests) == string(verifierPrincipalEvidence.secondReadTargetDigests) && string(verifierPrincipalEvidence.firstRoleAssignmentRawPageDigests) == string(verifierPrincipalEvidence.secondRoleAssignmentRawPageDigests) && string(verifierPrincipalEvidence.firstTransitiveGroupRawPageDigests) == string(verifierPrincipalEvidence.secondTransitiveGroupRawPageDigests)
var verifierAttachmentEvidence = verifierEvidence.attachmentEvidence
var verifierAttachmentMatches = toLower(verifierAttachmentEvidence.identityResourceId) == toLower(contractInputs.rbacInventoryVerifierIdentityResourceId) && verifierAttachmentEvidence.associatedResourcesRequestPath == expectedVerifierAssociatedResourcesRequestPath && verifierAttachmentEvidence.federatedIdentityCredentialsRequestPath == expectedVerifierFederatedCredentialsRequestPath && empty(verifierAttachmentEvidence.associatedResourceIds) && empty(verifierAttachmentEvidence.federatedIdentityCredentialIds) && !contains(verifierAttachmentEvidence, 'associatedResourceConfigurationRequestPaths') && !contains(verifierAttachmentEvidence, 'associatedResourceIdentityResourceIds') && !contains(verifierAttachmentEvidence, 'firstAssociatedResourceConfigurationDigests') && !contains(verifierAttachmentEvidence, 'secondAssociatedResourceConfigurationDigests') && verifierAttachmentEvidence.allPagesRetrieved == true && verifierAttachmentEvidence.firstReadCompletedAt < verifierAttachmentEvidence.secondReadCompletedAt && verifierAttachmentEvidence.secondReadCompletedAt <= inventory.collectedAt && string(verifierAttachmentEvidence.firstAssociatedResourceRawPageDigests) == string(verifierAttachmentEvidence.secondAssociatedResourceRawPageDigests) && string(verifierAttachmentEvidence.firstFederatedCredentialRawPageDigests) == string(verifierAttachmentEvidence.secondFederatedCredentialRawPageDigests)
var verifierEvidenceMatches = toLower(verifierEvidence.identityResourceId) == toLower(contractInputs.rbacInventoryVerifierIdentityResourceId) && toLower(verifierEvidence.identityClientId) == toLower(contractInputs.rbacInventoryVerifierIdentityClientId) && toLower(verifierEvidence.identityPrincipalId) == toLower(contractInputs.rbacInventoryVerifierIdentityPrincipalId) && toLower(verifierEvidence.identityTenantId) == toLower(contractInputs.rbacInventoryVerifierIdentityTenantId) && toLower(verifierEvidence.identityPrincipalId) != toLower(reviewAuthority.reviewerPrincipalId) && toLower(verifierEvidence.reviewerKeyArmResourceId) == toLower(contractInputs.rbacInventoryReviewerKeyArmResourceId) && toLower(verifierEvidence.roleDefinitionId) == toLower(contractInputs.rbacInventoryVerifierRoleDefinitionId) && verifierEvidence.roleDefinitionName == contractInputs.rbacInventoryVerifierRoleName && toLower(verifierEvidence.roleAssignmentId) == toLower(contractInputs.rbacInventoryVerifierRoleAssignmentId) && verifierEvidence.allowedDataActions == contractInputs.rbacInventoryVerifierAllowedDataActions && verifierEvidence.assignmentCount == 1 && verifierGrantMatches && verifierPrincipalEvidenceMatches && verifierAttachmentMatches
var inventorySourceMatches = inventory.sourceReference.name == 'monitoring-rbac/${inventory.collectionRunId}/effective-rbac-inventory.json' && inventory.sourceReference.contentDigest == inventory.sourceManifestDigest && inventory.inventoryDigest == validatedReviewedInventoryDigest

var inventoryCoreIsValid = inventory.schemaVersion == 'athena.wc028MonitoringEffectiveRbacInventory.v4' && inventory.scopeCollectionMode == 'subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes' && inventory.ancestorScopeCollectionComplete == true && inventory.subscriptionDescendantCollectionComplete == true && managementGroupAncestryIsComplete && hierarchyEvidenceIsComplete && inventoryIsFresh && inventorySourceMatches && toLower(inventory.subscriptionId) == toLower(handoff.subscriptionId) && toLower(inventory.tenantId) == toLower(handoff.tenantId) && toLower(inventory.collectorPrincipalId) == toLower(handoff.monitoringReaderPrincipalId) && toLower(inventory.athenaContextPrincipalId) == toLower(handoff.athenaContextPrincipalId) && toLower(collectorEvidence.principalId) == toLower(inventory.collectorPrincipalId) && toLower(contextEvidence.principalId) == toLower(inventory.athenaContextPrincipalId) && toLower(inventory.attestorIdentityResourceId) == toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(inventory.attestorClientId) == toLower(contractInputs.rbacAttestorIdentityClientId) && toLower(inventory.attestorPrincipalId) == toLower(contractInputs.rbacAttestorPrincipalId) && toLower(inventory.attestorTenantId) == toLower(contractInputs.rbacAttestorTenantId) && collectorTargetsMatch && contextTargetsMatch && runtimeSupportTargetsMatch
var inventoryReadStabilityIsValid = inventory.groupMembershipCollectionComplete == true && inventory.roleDefinitionCollectionComplete == true && inventory.denyAssignmentCollectionComplete == true && inventory.denyAssignmentIncludeInherited == true && inventory.pimScheduleInstanceCollectionComplete == true && inventory.pimScheduleInstanceIncludeInherited == true && inventory.repeatedReadStable == true && independentReadTimesAreValid && inventory.firstRawSnapshotDigest == inventory.secondRawSnapshotDigest && globalRepeatedReadPagesAreStable && principalEvidenceIsComplete
var inventoryAssignmentCountIsValid = empty(inventory.athenaContextGrants) && inventory.assignmentCount == exactExpectedAssignmentCount
var inventoryAttachmentsAreValid = protectedScopesMatch && collectorAttachmentMatches && attestorAttachmentMatches && verifierEvidenceMatches
var inventoryPrivilegePostureIsValid = storageReadbackIsSafe && exclusivePrincipalEvidenceMatches && denyAssignmentsAreSafe && runtimeSupportDenyAssignmentsAreSafe && verifierDenyAssignmentsAreSafe && empty(inventory.activePimScheduleInstances)

module inventoryAttestationValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-attestation'
  params: {
    valid: inventoryAttestationMatches
    failureMessage: 'monitoring contract publication requires one sealed cryptographically valid reviewer attestation'
  }
}

module inventoryCoreValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-core'
  params: {
    valid: inventoryCoreIsValid
    failureMessage: 'monitoring contract publication requires a fresh v4 inventory with the exact source, handoff identities, and collectable target scopes'
  }
}

module inventoryReadValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-reads'
  params: {
    valid: inventoryReadStabilityIsValid
    failureMessage: 'monitoring contract publication requires complete inherited collections and two independent stable reads; unproved parent-scope completeness is forbidden'
  }
}

module inventoryAssignmentCountValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-assignment-count'
  params: {
    valid: inventoryAssignmentCountIsValid
    failureMessage: 'monitoring contract publication requires the exact assignment count and no Athena context grants'
  }
}

module inventoryRoleDefinitionSetValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-role-definition-set'
  params: {
    valid: roleDefinitionSetMatches
    failureMessage: 'monitoring contract publication requires only the exact allowed role-definition IDs'
  }
}

module inventoryCustomRoleDefinitionValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-custom-role-definitions'
  params: {
    valid: customRoleDefinitionsMatch
    failureMessage: 'monitoring contract publication requires the exact immutable custom role definitions'
  }
}

module inventoryEvidenceWriterValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-evidence-writer'
  params: {
    valid: evidenceWriterRoleDefinitionMatches
    failureMessage: 'monitoring contract publication requires exact known-name Blob read and add-only evidence-writer permissions'
  }
}

module inventoryVerifierRoleValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-verifier-role'
  params: {
    valid: verifierRoleDefinitionMatches
    failureMessage: 'monitoring contract publication requires the exact reviewer-key read-only verifier role'
  }
}

module inventoryCollectorGrantValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-collector-grants'
  params: {
    valid: collectorGrantsMatch && runtimeSupportGrantMatches
    failureMessage: 'monitoring contract publication requires only the exact conditioned collector and runtime-support storage-reader grants'
  }
}

module inventoryAttachmentValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-attachments'
  params: {
    valid: inventoryAttachmentsAreValid
    failureMessage: 'monitoring contract publication requires exact protected scopes and complete collector, attestor, and verifier attachment evidence'
  }
}

module inventoryPrivilegeValidationGate 'modules/monitoring-publication-validation-gate.bicep' = {
  name: 'validate-monitoring-effective-rbac-privileges'
  params: {
    valid: inventoryPrivilegePostureIsValid
    failureMessage: 'monitoring contract publication requires immutable storage, exclusive data-plane principals, no effective deny, and no active PIM'
  }
}

module collectorContract 'modules/monitoring-collector-contract.bicep' = {
  name: 'publish-monitoring-collector-contract'
  scope: resourceGroup(monitoringResourceGroupName)
  dependsOn: [
    inventoryAttestationValidationGate
    inventoryCoreValidationGate
    inventoryReadValidationGate
    inventoryAssignmentCountValidationGate
    inventoryRoleDefinitionSetValidationGate
    inventoryCustomRoleDefinitionValidationGate
    inventoryEvidenceWriterValidationGate
    inventoryVerifierRoleValidationGate
    inventoryCollectorGrantValidationGate
    inventoryAttachmentValidationGate
    inventoryPrivilegeValidationGate
  ]
  params: {
    collectorIdentityResourceId: contractInputs.collectorIdentityResourceId
    collectorIdentityClientId: contractInputs.collectorIdentityClientId
    collectorTenantId: contractInputs.collectorTenantId
    collectorRuntimeResourceId: toLower(contractInputs.collectorRuntimeResourceId)
    rbacAttestorRuntimeResourceId: toLower(contractInputs.rbacAttestorRuntimeResourceId)
    runtimeSupportIdentityResourceId: toLower(contractInputs.runtimeSupportIdentityResourceId)
    runtimeSupportIdentityPrincipalId: toLower(contractInputs.runtimeSupportIdentityPrincipalId)
    runtimeSupportStorageReaderRoleDefinitionId: contractInputs.runtimeSupportStorageReaderRoleDefinitionId
    runtimeSupportStorageReaderRoleName: contractInputs.runtimeSupportStorageReaderRoleName
    runtimeSupportStorageReaderAllowedOperations: contractInputs.runtimeSupportStorageReaderAllowedOperations
    runtimeSupportStorageReaderRoleAssignmentId: contractInputs.runtimeSupportStorageReaderRoleAssignmentId
    runtimeSupportStorageReaderScopeId: contractInputs.runtimeSupportStorageReaderScopeId
    monitoringResourceGroupId: contractInputs.monitoringResourceGroupId
    workloadResourceGroupId: contractInputs.workloadResourceGroupId
    workloadVirtualNetworkResourceId: contractInputs.workloadVirtualNetworkResourceId
    approvedVmNames: contractInputs.approvedVmNames
    workspaceResourceId: contractInputs.workspaceResourceId
    dataCollectionRuleResourceId: contractInputs.dataCollectionRuleResourceId
    dataCollectionEndpointResourceId: contractInputs.dataCollectionEndpointResourceId
    authorizationMode: contractInputs.authorizationMode
    workspaceAccessControlMode: contractInputs.workspaceAccessControlMode
    workspaceResourceContextAccessEnabled: contractInputs.workspaceResourceContextAccessEnabled
    workspaceSkuName: contractInputs.workspaceSkuName
    resourceContextTablePlans: contractInputs.resourceContextTablePlans
    readerRoleDefinitionId: contractInputs.readerRoleDefinitionId
    signalReaderRoleDefinitionId: contractInputs.signalReaderRoleDefinitionId
    signalReaderRoleName: contractInputs.signalReaderRoleName
    resourceLogReaderRoleDefinitionId: contractInputs.resourceLogReaderRoleDefinitionId
    resourceLogReaderRoleName: contractInputs.resourceLogReaderRoleName
    resourceLogAllowedOperations: contractInputs.resourceLogAllowedOperations
    resourceLogReadScopeIds: contractInputs.resourceLogReadScopeIds
    logAnalyticsDataReaderRoleDefinitionId: contractInputs.logAnalyticsDataReaderRoleDefinitionId
    resourceHealthRoleDefinitionId: contractInputs.resourceHealthRoleDefinitionId
    resourceHealthRoleName: contractInputs.resourceHealthRoleName
    resourceHealthScopeIds: contractInputs.resourceHealthScopeIds
    resourceHealthAllowedOperations: contractInputs.resourceHealthAllowedOperations
    rbacAttestorIdentityResourceId: contractInputs.rbacAttestorIdentityResourceId
    rbacAttestorIdentityClientId: contractInputs.rbacAttestorIdentityClientId
    rbacAttestorPrincipalId: contractInputs.rbacAttestorPrincipalId
    rbacAttestorTenantId: contractInputs.rbacAttestorTenantId
    rbacAttestorRoleDefinitionId: contractInputs.rbacAttestorRoleDefinitionId
    rbacAttestorRoleName: contractInputs.rbacAttestorRoleName
    rbacAttestorScopeId: contractInputs.rbacAttestorScopeId
    rbacAttestorAllowedOperations: contractInputs.rbacAttestorAllowedOperations
    rbacInventoryBootstrapHandoffId: handoff.handoffId
    rbacInventoryBootstrapDeploymentId: expectedBootstrapDeploymentId
    rbacInventoryBootstrapTemplateHash: bootstrapTemplateHash
    rbacInventoryBootstrapContractInputsBindingId: expectedCollectorContractInputsBindingId
    rbacInventoryVerifierIdentityResourceId: reviewAuthority.verifierIdentityResourceId
    rbacInventoryVerifierIdentityClientId: contractInputs.rbacInventoryVerifierIdentityClientId
    rbacInventoryVerifierIdentityPrincipalId: contractInputs.rbacInventoryVerifierIdentityPrincipalId
    rbacInventoryVerifierIdentityTenantId: contractInputs.rbacInventoryVerifierIdentityTenantId
    rbacInventoryReviewerKeyVaultResourceId: contractInputs.rbacInventoryReviewerKeyVaultResourceId
    rbacInventoryReviewerKeyArmResourceId: contractInputs.rbacInventoryReviewerKeyArmResourceId
    rbacInventoryVerifierRoleDefinitionId: contractInputs.rbacInventoryVerifierRoleDefinitionId
    rbacInventoryVerifierRoleName: contractInputs.rbacInventoryVerifierRoleName
    rbacInventoryVerifierRoleScopeId: contractInputs.rbacInventoryVerifierRoleScopeId
    rbacInventoryVerifierAllowedDataActions: contractInputs.rbacInventoryVerifierAllowedDataActions
    rbacInventoryVerifierRoleAssignmentId: contractInputs.rbacInventoryVerifierRoleAssignmentId
    rbacInventoryReviewerPrincipalId: reviewAuthority.reviewerPrincipalId
    rbacInventoryReviewerKeyId: reviewAuthority.reviewerKeyId
    rbacInventoryReviewerPublicKeyModulus: reviewAuthority.publicKeyModulus
    rbacInventoryReviewerPublicKeyExponent: reviewAuthority.publicKeyExponent
    rbacInventoryReviewerPublicKeyFingerprint: reviewAuthority.publicKeyFingerprint
    effectiveRbacInventoryAttestation: sealedInventoryAttestation
    identityProofAudience: contractInputs.identityProofAudience
    identityProofApplicationId: contractInputs.identityProofApplicationId
    identityProofApplicationObjectId: contractInputs.identityProofApplicationObjectId
    identityProofServicePrincipalId: contractInputs.identityProofServicePrincipalId
    identityProofAppRoleId: contractInputs.identityProofAppRoleId
    identityProofAppRoleValue: contractInputs.identityProofAppRoleValue
    identityProofAppRoleAssignmentId: contractInputs.identityProofAppRoleAssignmentId
    identityProofAssignedPrincipalId: contractInputs.identityProofAssignedPrincipalId
    logAnalyticsAllowedTables: contractInputs.logAnalyticsAllowedTables
    logAnalyticsAccessCondition: contractInputs.logAnalyticsAccessCondition
    resourceReadScopeIds: contractInputs.resourceReadScopeIds
    signalReadScopeIds: contractInputs.signalReadScopeIds
    signingKeyResourceId: contractInputs.signingKeyResourceId
    signingKeyArmResourceId: contractInputs.signingKeyArmResourceId
    signingKeyCryptoUserRoleDefinitionId: contractInputs.signingKeyCryptoUserRoleDefinitionId
    evidenceStorageAccountResourceId: contractInputs.evidenceStorageAccountResourceId
    evidenceBlobServiceResourceId: contractInputs.evidenceBlobServiceResourceId
    evidenceContainerResourceId: contractInputs.evidenceContainerResourceId
    evidenceContainerPublicAccess: contractInputs.evidenceContainerPublicAccess
    evidenceImmutabilityPolicyResourceId: contractInputs.evidenceImmutabilityPolicyResourceId
    evidenceWriterRoleDefinitionId: contractInputs.evidenceWriterRoleDefinitionId
    evidenceWriterRoleName: contractInputs.evidenceWriterRoleName
    evidenceWriterAllowedDataActions: contractInputs.evidenceWriterAllowedDataActions
    evidenceWriterAssignmentCondition: contractInputs.evidenceWriterAssignmentCondition
    evidenceWriterAssignmentConditionVersion: contractInputs.evidenceWriterAssignmentConditionVersion
    evidenceBlobVersioningEnabled: contractInputs.evidenceBlobVersioningEnabled
    evidenceContainerHasImmutabilityPolicy: contractInputs.evidenceContainerHasImmutabilityPolicy
    evidenceContainerImmutabilityPolicyState: contractInputs.evidenceContainerImmutabilityPolicyState
    evidenceContainerImmutabilityPeriodDays: contractInputs.evidenceContainerImmutabilityPeriodDays
    evidenceContainerProtectedAppendWritesEnabled: contractInputs.evidenceContainerProtectedAppendWritesEnabled
    evidenceContainerProtectedAppendWritesAllEnabled: contractInputs.evidenceContainerProtectedAppendWritesAllEnabled
    evidenceStorageReadbackBindingId: contractInputs.evidenceStorageReadbackBindingId
    evidenceStorageReadinessDigest: contractInputs.evidenceStorageReadinessDigest
    legacyCollectorRbacCleanupSchemaVersion: contractInputs.legacyCollectorRbacCleanupSchemaVersion
    legacyCollectorRbacCleanupDigest: contractInputs.legacyCollectorRbacCleanupDigest
    effectiveRbacInventory: inventory
    maximumEvidenceAgeSeconds: contractInputs.maximumEvidenceAgeSeconds
    connectionMonitorDeploymentMode: contractInputs.connectionMonitorDeploymentMode
  }
}

@description('Exact generic monitoring collector contract published only after the post-deployment RBAC inventory is accepted.')
output monitoringCollectorContract object = collectorContract.outputs.collectorContract

@description('Exact WC-028 v9 acquisition collector contract published only after the post-deployment RBAC inventory is accepted.')
output monitoringAcquisitionCollectorContract object = union(collectorContract.outputs.acquisitionCollectorContract, {
  monitoringReaderPrincipalId: handoff.monitoringReaderPrincipalId
  athenaContextIdentityId: handoff.athenaContextIdentityId
  athenaContextPrincipalId: handoff.athenaContextPrincipalId
  physicalIdentitySeparationEnforced: handoff.physicalIdentitySeparationEnforced
})

@description('Phase-two publication handoff tying the contract outputs to the exact bootstrap and RBAC inventory.')
output monitoringContractPublicationHandoff object = {
  schemaVersion: 'athena.wc024MonitoringContractPublicationHandoff.v1'
  bootstrapHandoffId: handoff.handoffId
  bootstrapDeploymentId: expectedBootstrapDeploymentId
  bootstrapTemplateHash: bootstrapTemplateHash
  bootstrapContractInputsBindingId: expectedCollectorContractInputsBindingId
  effectiveRbacInventoryDigest: inventory.inventoryDigest
  effectiveRbacSourceManifestDigest: inventory.sourceManifestDigest
  effectiveRbacSignedPreimageDigest: inventoryAttestationValidation.outputs.signedPreimageDigest
  effectiveRbacAttestationValidationDigest: inventoryAttestationValidation.outputs.validationDigest
  effectiveRbacCryptographicReviewVerified: inventoryAttestationValidation.outputs.validated
  legacyCollectorRbacCleanupSchemaVersion: handoff.legacyCollectorRbacCleanupSchemaVersion
  legacyCollectorRbacCleanupDigest: handoff.legacyCollectorRbacCleanupDigest
  evidenceBlobVersioningEnabled: contractInputs.evidenceBlobVersioningEnabled
  evidenceContainerHasImmutabilityPolicy: contractInputs.evidenceContainerHasImmutabilityPolicy
  evidenceContainerImmutabilityPolicyState: contractInputs.evidenceContainerImmutabilityPolicyState
  evidenceContainerImmutabilityPeriodDays: contractInputs.evidenceContainerImmutabilityPeriodDays
  publishedAt: publicationRequestedAt
  publicationState: 'published'
}

output monitoringAcquisitionContractPublicationReady bool = true
