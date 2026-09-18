targetScope = 'subscription'

param sourceDeploymentName string
param sourceDeploymentId string
param collectorContractInputs object
param effectiveRbacTargetScopeIds array
param reviewAuthority object
param subscriptionId string
param tenantId string
param monitoringReaderPrincipalId string
param athenaContextIdentityId string
param athenaContextPrincipalId string
param physicalIdentitySeparationEnforced bool
param reviewAuthoritySeparationEnforced bool
param managedIdentityAttachmentCollection object
param exclusiveDataPlanePrincipalCollection object
param directoryMembershipCollection object
param identityProofAuthority object
param managementGroupHierarchyCollection object
param legacyCollectorRbacCleanupDigest string

var collectorContractInputsBindingId = guid(string(collectorContractInputs))
var handoffId = guid(
  subscription().id,
  collectorContractInputs.collectorIdentityResourceId,
  athenaContextIdentityId,
  collectorContractInputs.rbacAttestorIdentityResourceId,
  sourceDeploymentId,
  collectorContractInputsBindingId,
  legacyCollectorRbacCleanupDigest,
  reviewAuthority.reviewerPrincipalId,
  reviewAuthority.reviewerKeyId,
  reviewAuthority.verifierIdentityResourceId,
  reviewAuthority.publicKeyFingerprint
)

output handoff object = {
  schemaVersion: 'athena.wc024MonitoringRbacBootstrapHandoff.v1'
  sourceDeploymentName: sourceDeploymentName
  sourceDeploymentId: sourceDeploymentId
  collectorContractInputsBindingId: collectorContractInputsBindingId
  handoffId: handoffId
  publicationState: 'blockedPendingEffectiveRbacInventory'
  scopeCollectionMode: 'subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes'
  managementGroupAncestorDisposition: 'explicitManagementGroupAndTenantRootEnumerationRequired'
  roleAssignmentCollectionScopeId: subscription().id
  roleAssignmentQueryFilter: 'assignedTo(principalId)'
  roleAssignmentIncludeInherited: true
  roleAssignmentIncludeGroups: true
  roleAssignmentIncludeAllDescendantScopes: true
  allPrincipalRoleAssignmentCollectionScopeId: subscription().id
  allPrincipalRoleAssignmentQueryFilter: 'none'
  allPrincipalRoleAssignmentIncludeInherited: true
  allPrincipalRoleAssignmentIncludeAllDescendantScopes: true
  roleAssignmentApiVersion: '2022-04-01'
  denyAssignmentIncludeInherited: true
  pimScheduleInstanceIncludeInherited: true
  subscriptionId: subscriptionId
  tenantId: tenantId
  monitoringReaderPrincipalId: monitoringReaderPrincipalId
  athenaContextIdentityId: athenaContextIdentityId
  athenaContextPrincipalId: athenaContextPrincipalId
  physicalIdentitySeparationEnforced: physicalIdentitySeparationEnforced
  reviewAuthoritySeparationEnforced: reviewAuthoritySeparationEnforced
  legacyCollectorRbacCleanupSchemaVersion: 'athena.wc028LegacyCollectorRbacCleanup.v3'
  legacyCollectorRbacCleanupDigest: legacyCollectorRbacCleanupDigest
  effectiveRbacTargetScopeIds: effectiveRbacTargetScopeIds
  rbacInventoryReviewAuthority: reviewAuthority
  managedIdentityAttachmentCollection: managedIdentityAttachmentCollection
  exclusiveDataPlanePrincipalCollection: exclusiveDataPlanePrincipalCollection
  directoryMembershipCollection: directoryMembershipCollection
  identityProofAuthority: identityProofAuthority
  managementGroupHierarchyCollection: managementGroupHierarchyCollection
  collectorContractInputs: collectorContractInputs
}
