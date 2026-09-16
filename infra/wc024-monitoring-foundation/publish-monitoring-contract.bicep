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

@description('Fresh post-deployment effective RBAC inventory collected with the handoff attestor identity at only the handoff target scopes.')
param monitoringEffectiveRbacInventory object

@description('Independently reviewed canonical digest of monitoringEffectiveRbacInventory.')
@minLength(71)
@maxLength(71)
param reviewedMonitoringEffectiveRbacInventoryDigest string

var reviewedInventoryDigestHex = replace(reviewedMonitoringEffectiveRbacInventoryDigest, 'sha256:', '')
var reviewedInventoryDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  reviewedInventoryDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var reviewedInventoryDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  reviewedInventoryDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedReviewedInventoryDigest = reviewedMonitoringEffectiveRbacInventoryDigest == toLower(reviewedMonitoringEffectiveRbacInventoryDigest) && startsWith(reviewedMonitoringEffectiveRbacInventoryDigest, 'sha256:') && length(reviewedInventoryDigestHex) == 64 && empty(reviewedInventoryDigestInvalidCharacters) && reviewedInventoryDigestHex != '0000000000000000000000000000000000000000000000000000000000000000'
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
var subscriptionScope = subscription().id
var monitoringResourceGroupId = subscriptionResourceId('Microsoft.Resources/resourceGroups', monitoringResourceGroupName)
var expectedTargetScopeIds = union(
  concat(
    [
      subscriptionScope
      contractInputs.workloadResourceGroupId
      contractInputs.monitoringResourceGroupId
      contractInputs.networkWatcherResourceGroupId
      contractInputs.workloadVirtualNetworkResourceId
      contractInputs.workspaceResourceId
      contractInputs.evidenceStorageAccountResourceId
      contractInputs.evidenceBlobServiceResourceId
      contractInputs.evidenceContainerResourceId
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
var targetScopesMatch = empty(uncollectableTargetScopeIds) && handoffTargetsAreUnique && length(normalizedHandoffTargetScopeIds) == length(normalizedExpectedTargetScopeIds) && length(union(normalizedHandoffTargetScopeIds, normalizedExpectedTargetScopeIds)) == length(normalizedExpectedTargetScopeIds)
var expectedHandoffId = guid(
  subscriptionScope,
  contractInputs.collectorIdentityResourceId,
  handoff.athenaContextIdentityId,
  contractInputs.rbacAttestorIdentityResourceId,
  join(expectedTargetScopeIds, '|')
)
var handoffIdentitiesAreSeparated = toLower(contractInputs.collectorIdentityResourceId) != toLower(handoff.athenaContextIdentityId) && toLower(contractInputs.collectorIdentityResourceId) != toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(handoff.athenaContextIdentityId) != toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(handoff.monitoringReaderPrincipalId) != toLower(handoff.athenaContextPrincipalId) && toLower(handoff.monitoringReaderPrincipalId) != toLower(contractInputs.rbacAttestorPrincipalId) && toLower(handoff.athenaContextPrincipalId) != toLower(contractInputs.rbacAttestorPrincipalId)
var expectedCollectorMembershipRequestPath = '/v1.0/servicePrincipals/${handoff.monitoringReaderPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
var expectedContextMembershipRequestPath = '/v1.0/servicePrincipals/${handoff.athenaContextPrincipalId}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id'
var directoryMembershipCollectionMatches = handoff.directoryMembershipCollection.graphApplicationId == '00000003-0000-0000-c000-000000000000' && handoff.directoryMembershipCollection.graphApplicationReadAllAppRoleId == '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' && handoff.directoryMembershipCollection.graphApplicationReadAllAssignmentId == contractInputs.rbacAttestorGraphApplicationReadAllAssignmentId && handoff.directoryMembershipCollection.graphServicePrincipalId == contractInputs.rbacAttestorGraphServicePrincipalId && length(items(handoff.directoryMembershipCollection.requestHeaders)) == 1 && handoff.directoryMembershipCollection.requestHeaders.ConsistencyLevel == 'eventual' && handoff.directoryMembershipCollection.collectorRequestPath == expectedCollectorMembershipRequestPath && handoff.directoryMembershipCollection.athenaContextRequestPath == expectedContextMembershipRequestPath
var expectedIdentityProofAudience = 'api://${toLower(handoff.tenantId)}/athena-monitoring-identity-proof'
var identityProofAuthorityIds = [
  toLower(handoff.identityProofAuthority.applicationId)
  toLower(handoff.identityProofAuthority.applicationObjectId)
  toLower(handoff.identityProofAuthority.servicePrincipalId)
  toLower(handoff.identityProofAuthority.appRoleId)
  toLower(handoff.identityProofAuthority.appRoleAssignmentId)
]
var identityProofAuthorityMatches = handoff.identityProofAuthority.audience == expectedIdentityProofAudience && handoff.identityProofAuthority.audience == contractInputs.identityProofAudience && handoff.identityProofAuthority.applicationId == contractInputs.identityProofApplicationId && handoff.identityProofAuthority.applicationObjectId == contractInputs.identityProofApplicationObjectId && handoff.identityProofAuthority.servicePrincipalId == contractInputs.identityProofServicePrincipalId && handoff.identityProofAuthority.appRoleId == contractInputs.identityProofAppRoleId && handoff.identityProofAuthority.appRoleValue == 'Athena.MonitoringAcquisition.ProveIdentity' && handoff.identityProofAuthority.appRoleValue == contractInputs.identityProofAppRoleValue && handoff.identityProofAuthority.appRoleAssignmentId == contractInputs.identityProofAppRoleAssignmentId && toLower(handoff.identityProofAuthority.assignedPrincipalId) == toLower(handoff.monitoringReaderPrincipalId) && toLower(handoff.identityProofAuthority.assignedPrincipalId) == toLower(contractInputs.identityProofAssignedPrincipalId) && handoff.identityProofAuthority.requestedAccessTokenVersion == '1.0' && length(union(identityProofAuthorityIds, [])) == length(identityProofAuthorityIds)
var validatedHandoff = monitoringRbacBootstrapDeployment.properties.provisioningState == 'Succeeded' && handoff.schemaVersion == 'athena.wc024MonitoringRbacBootstrapHandoff.v1' && handoff.sourceDeploymentName == monitoringRbacBootstrapDeploymentName && handoff.handoffId == expectedHandoffId && handoff.publicationState == 'blockedPendingEffectiveRbacInventory' && handoff.scopeCollectionMode == 'subscriptionAndDescendantAtScope' && handoff.managementGroupAncestorDisposition == 'notDirectlyEnumerated' && toLower(handoff.subscriptionId) == toLower(subscription().subscriptionId) && toLower(handoff.tenantId) == toLower(tenant().tenantId) && toLower(contractInputs.monitoringResourceGroupId) == toLower(monitoringResourceGroupId) && toLower(contractInputs.collectorTenantId) == toLower(handoff.tenantId) && toLower(contractInputs.rbacAttestorTenantId) == toLower(handoff.tenantId) && contractInputs.rbacAttestorGraphApplicationId == '00000003-0000-0000-c000-000000000000' && contractInputs.rbacAttestorGraphApplicationReadAllAppRoleId == '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' && !empty(contractInputs.rbacAttestorGraphApplicationReadAllAssignmentId) && !empty(contractInputs.rbacAttestorGraphServicePrincipalId) && directoryMembershipCollectionMatches && identityProofAuthorityMatches && handoff.physicalIdentitySeparationEnforced == true && handoffIdentitiesAreSeparated && targetScopesMatch
  ? handoff
  : fail('monitoring contract publication requires the exact completed phase-one handoff and only subscription or descendant RBAC target scopes')

var inventory = monitoringEffectiveRbacInventory
var collectorEvidence = inventory.collectorPrincipalEvidence
var contextEvidence = inventory.athenaContextPrincipalEvidence
var normalizedCollectorTargetScopeIds = map(inventory.collectorPrincipalEvidence.targetScopeIds, scopeId => toLower(scopeId))
var normalizedContextTargetScopeIds = map(inventory.athenaContextPrincipalEvidence.targetScopeIds, scopeId => toLower(scopeId))
var collectorTargetsAreUnique = length(union(normalizedCollectorTargetScopeIds, [])) == length(normalizedCollectorTargetScopeIds)
var contextTargetsAreUnique = length(union(normalizedContextTargetScopeIds, [])) == length(normalizedContextTargetScopeIds)
var collectorTargetsMatch = collectorTargetsAreUnique && length(normalizedCollectorTargetScopeIds) == length(normalizedHandoffTargetScopeIds) && length(union(normalizedCollectorTargetScopeIds, normalizedHandoffTargetScopeIds)) == length(normalizedHandoffTargetScopeIds)
var contextTargetsMatch = contextTargetsAreUnique && length(normalizedContextTargetScopeIds) == length(normalizedHandoffTargetScopeIds) && length(union(normalizedContextTargetScopeIds, normalizedHandoffTargetScopeIds)) == length(normalizedHandoffTargetScopeIds)
var publicationRequestedAt = publicationClock.outputs.deploymentTimestamp
var publicationRequestedAtEpoch = dateTimeToEpoch(publicationRequestedAt)
var inventoryCollectedAtEpoch = dateTimeToEpoch(inventory.collectedAt)
var inventoryExpiresAtEpoch = dateTimeToEpoch(inventory.expiresAt)
var inventoryIsFresh = inventoryCollectedAtEpoch <= publicationRequestedAtEpoch && publicationRequestedAtEpoch < inventoryExpiresAtEpoch && inventoryExpiresAtEpoch - inventoryCollectedAtEpoch <= 900
var firstReadCompletedAtEpoch = dateTimeToEpoch(inventory.firstReadCompletedAt)
var secondReadCompletedAtEpoch = dateTimeToEpoch(inventory.secondReadCompletedAt)
var independentReadTimesAreValid = firstReadCompletedAtEpoch < secondReadCompletedAtEpoch && secondReadCompletedAtEpoch <= inventoryCollectedAtEpoch
var principalEvidenceIsComplete = collectorEvidence.queryFilter == 'atScope() and assignedTo(principalId)' && contextEvidence.queryFilter == 'atScope() and assignedTo(principalId)' && collectorEvidence.allPagesRetrieved == true && contextEvidence.allPagesRetrieved == true && length(collectorEvidence.firstReadTargetDigests) == length(normalizedHandoffTargetScopeIds) && length(contextEvidence.firstReadTargetDigests) == length(normalizedHandoffTargetScopeIds) && string(collectorEvidence.firstReadTargetDigests) == string(collectorEvidence.secondReadTargetDigests) && string(contextEvidence.firstReadTargetDigests) == string(contextEvidence.secondReadTargetDigests) && string(collectorEvidence.transitiveGroupIds) == string(inventory.collectorSecurityGroupIds) && string(contextEvidence.transitiveGroupIds) == string(inventory.athenaContextSecurityGroupIds) && !empty(collectorEvidence.firstRoleAssignmentRawPageDigests) && string(collectorEvidence.firstRoleAssignmentRawPageDigests) == string(collectorEvidence.secondRoleAssignmentRawPageDigests) && !empty(contextEvidence.firstRoleAssignmentRawPageDigests) && string(contextEvidence.firstRoleAssignmentRawPageDigests) == string(contextEvidence.secondRoleAssignmentRawPageDigests) && !empty(collectorEvidence.firstTransitiveGroupRawPageDigests) && string(collectorEvidence.firstTransitiveGroupRawPageDigests) == string(collectorEvidence.secondTransitiveGroupRawPageDigests) && !empty(contextEvidence.firstTransitiveGroupRawPageDigests) && string(contextEvidence.firstTransitiveGroupRawPageDigests) == string(contextEvidence.secondTransitiveGroupRawPageDigests)
var normalizedResourceReadScopeIds = map(contractInputs.resourceReadScopeIds, scopeId => toLower(scopeId))
var normalizedSignalReadScopeIds = map(contractInputs.signalReadScopeIds, scopeId => toLower(scopeId))
var normalizedResourceLogReadScopeIds = map(contractInputs.resourceLogReadScopeIds, scopeId => toLower(scopeId))
var normalizedResourceHealthScopeIds = map(contractInputs.resourceHealthScopeIds, scopeId => toLower(scopeId))
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
    roleDefinitionName: 'Storage Blob Data Contributor'
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
var invalidCollectorGrants = filter(inventory.collectorGrants, grant => length(filter(expectedCollectorGrantBindings, expected => toLower(grant.roleDefinitionId) == expected.roleDefinitionId && grant.roleDefinitionName == expected.roleDefinitionName && length(grant.assignmentScopeIds) == length(expected.assignmentScopeIds) && length(union(map(grant.assignmentScopeIds, scopeId => toLower(scopeId)), expected.assignmentScopeIds)) == length(expected.assignmentScopeIds))) != 1 || length(union(map(grant.assignmentScopeIds, scopeId => toLower(scopeId)), [])) != length(grant.assignmentScopeIds) || toLower(grant.assignedPrincipalId) != toLower(inventory.collectorPrincipalId) || grant.assignedPrincipalType != 'ServicePrincipal' || toLower(grant.effectivePrincipalId) != toLower(inventory.collectorPrincipalId) || grant.inheritance != 'direct' || grant.groupDerived != false || contains(grant, 'condition') || contains(grant, 'conditionVersion'))
var missingOrDuplicateExpectedCollectorGrants = filter(expectedCollectorGrantBindings, expected => length(filter(inventory.collectorGrants, grant => toLower(grant.roleDefinitionId) == expected.roleDefinitionId && grant.roleDefinitionName == expected.roleDefinitionName && length(grant.assignmentScopeIds) == length(expected.assignmentScopeIds) && length(union(map(grant.assignmentScopeIds, scopeId => toLower(scopeId)), expected.assignmentScopeIds)) == length(expected.assignmentScopeIds))) != 1)
var collectorGrantRoleIds = map(inventory.collectorGrants, grant => toLower(grant.roleDefinitionId))
var collectorGrantDigests = map(inventory.collectorGrants, grant => grant.grantDigest)
var collectorGrantsMatch = length(inventory.collectorGrants) == length(expectedCollectorGrantBindings) && length(union(collectorGrantRoleIds, [])) == length(collectorGrantRoleIds) && length(union(collectorGrantDigests, [])) == length(collectorGrantDigests) && empty(invalidCollectorGrants) && empty(missingOrDuplicateExpectedCollectorGrants)
var expectedRoleDefinitionIds = union(
  map(expectedCollectorGrantBindings, binding => binding.roleDefinitionId),
  [
    toLower(contractInputs.rbacAttestorRoleDefinitionId)
  ]
)
var actualRoleDefinitionIds = map(inventory.roleDefinitions, role => toLower(role.roleDefinitionId))
var roleDefinitionSetMatches = length(union(actualRoleDefinitionIds, [])) == length(actualRoleDefinitionIds) && length(actualRoleDefinitionIds) == length(expectedRoleDefinitionIds) && length(union(actualRoleDefinitionIds, expectedRoleDefinitionIds)) == length(expectedRoleDefinitionIds)
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
]
var invalidCustomRoleDefinitions = filter(inventory.roleDefinitions, role => contains(map(expectedCustomRoleDefinitions, expected => expected.roleDefinitionId), toLower(role.roleDefinitionId)) && length(filter(expectedCustomRoleDefinitions, expected => toLower(role.roleDefinitionId) == expected.roleDefinitionId && length(role.actions) == length(expected.actions) && length(union(map(role.actions, action => toLower(action)), expected.actions)) == length(expected.actions))) != 1 || contains(map(expectedCustomRoleDefinitions, expected => expected.roleDefinitionId), toLower(role.roleDefinitionId)) && (!empty(role.notActions) || !empty(role.dataActions) || !empty(role.notDataActions)))
var customRoleDefinitionsMatch = empty(invalidCustomRoleDefinitions)
var exactExpectedAssignmentCount = length(normalizedResourceReadScopeIds) + length(normalizedSignalReadScopeIds) + length(normalizedResourceLogReadScopeIds) + length(normalizedResourceHealthScopeIds) + 2
var globalRepeatedReadPagesAreStable = !empty(inventory.firstRoleDefinitionRawPageDigests) && string(inventory.firstRoleDefinitionRawPageDigests) == string(inventory.secondRoleDefinitionRawPageDigests) && !empty(inventory.firstDenyAssignmentRawPageDigests) && string(inventory.firstDenyAssignmentRawPageDigests) == string(inventory.secondDenyAssignmentRawPageDigests) && !empty(inventory.firstPimScheduleInstanceRawPageDigests) && string(inventory.firstPimScheduleInstanceRawPageDigests) == string(inventory.secondPimScheduleInstanceRawPageDigests)
var collectorEffectivePrincipalIds = union(
  [
    toLower(inventory.collectorPrincipalId)
  ],
  map(inventory.collectorSecurityGroupIds, principalId => toLower(principalId))
)
var effectiveDenyAssignments = filter(inventory.denyAssignments, deny => empty(filter(deny.excludedPrincipalIds, principalId => contains(collectorEffectivePrincipalIds, toLower(principalId)))) && (empty(deny.principalIds) || contains(map(deny.principalIds, principalId => toLower(principalId)), '00000000-0000-0000-0000-000000000000') || !empty(filter(deny.principalIds, principalId => contains(collectorEffectivePrincipalIds, toLower(principalId))))))
var denyAssignmentsAreSafe = empty(effectiveDenyAssignments) && empty(filter(inventory.denyAssignments, deny => contains(deny, 'condition')))
var inventoryCompletenessMatches = inventory.groupMembershipCollectionComplete == true && inventory.roleDefinitionCollectionComplete == true && inventory.denyAssignmentCollectionComplete == true && inventory.pimScheduleInstanceCollectionComplete == true && inventory.repeatedReadStable == true && independentReadTimesAreValid && inventory.firstRawSnapshotDigest == inventory.secondRawSnapshotDigest && globalRepeatedReadPagesAreStable && empty(inventory.athenaContextGrants) && denyAssignmentsAreSafe && empty(inventory.activePimScheduleInstances) && inventory.assignmentCount == exactExpectedAssignmentCount && roleDefinitionSetMatches && customRoleDefinitionsMatch && collectorGrantsMatch && principalEvidenceIsComplete
var inventorySourceMatches = inventory.sourceReference.name == 'monitoring-rbac/${inventory.collectionRunId}/effective-rbac-inventory.json' && inventory.sourceReference.contentDigest == inventory.sourceManifestDigest && inventory.inventoryDigest == validatedReviewedInventoryDigest
var validatedMonitoringEffectiveRbacInventory = inventory.schemaVersion == 'athena.wc028MonitoringEffectiveRbacInventory.v3' && inventory.scopeCollectionMode == 'subscriptionAndDescendantAtScope' && empty(inventory.managementGroupAncestry) && inventory.ancestorScopeCollectionComplete == false && inventory.subscriptionDescendantCollectionComplete == true && inventoryIsFresh && inventoryCompletenessMatches && inventorySourceMatches && toLower(inventory.subscriptionId) == toLower(validatedHandoff.subscriptionId) && toLower(inventory.tenantId) == toLower(validatedHandoff.tenantId) && toLower(inventory.collectorPrincipalId) == toLower(validatedHandoff.monitoringReaderPrincipalId) && toLower(inventory.athenaContextPrincipalId) == toLower(validatedHandoff.athenaContextPrincipalId) && toLower(collectorEvidence.principalId) == toLower(inventory.collectorPrincipalId) && toLower(contextEvidence.principalId) == toLower(inventory.athenaContextPrincipalId) && toLower(inventory.attestorIdentityResourceId) == toLower(contractInputs.rbacAttestorIdentityResourceId) && toLower(inventory.attestorClientId) == toLower(contractInputs.rbacAttestorIdentityClientId) && toLower(inventory.attestorPrincipalId) == toLower(contractInputs.rbacAttestorPrincipalId) && toLower(inventory.attestorTenantId) == toLower(contractInputs.rbacAttestorTenantId) && collectorTargetsMatch && contextTargetsMatch
  ? inventory
  : fail('monitoring contract publication requires the independently reviewed, fresh, complete v3 inventory bound to two distinct stable reads, the phase-one identities, exact grants, and collectable target scopes; management-group enumeration claims are forbidden')

module collectorContract 'modules/monitoring-collector-contract.bicep' = {
  name: 'publish-monitoring-collector-contract'
  scope: resourceGroup(monitoringResourceGroupName)
  params: {
    collectorIdentityResourceId: contractInputs.collectorIdentityResourceId
    collectorIdentityClientId: contractInputs.collectorIdentityClientId
    collectorTenantId: contractInputs.collectorTenantId
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
    evidenceContainerResourceId: contractInputs.evidenceContainerResourceId
    evidenceWriterRoleDefinitionId: contractInputs.evidenceWriterRoleDefinitionId
    effectiveRbacInventory: validatedMonitoringEffectiveRbacInventory
    maximumEvidenceAgeSeconds: contractInputs.maximumEvidenceAgeSeconds
    connectionMonitorDeploymentMode: contractInputs.connectionMonitorDeploymentMode
  }
}

@description('Exact generic monitoring collector contract published only after the post-deployment RBAC inventory is accepted.')
output monitoringCollectorContract object = collectorContract.outputs.collectorContract

@description('Exact WC-028 v8 acquisition collector contract published only after the post-deployment RBAC inventory is accepted.')
output monitoringAcquisitionCollectorContract object = union(collectorContract.outputs.acquisitionCollectorContract, {
  monitoringReaderPrincipalId: validatedHandoff.monitoringReaderPrincipalId
  athenaContextIdentityId: validatedHandoff.athenaContextIdentityId
  athenaContextPrincipalId: validatedHandoff.athenaContextPrincipalId
  physicalIdentitySeparationEnforced: validatedHandoff.physicalIdentitySeparationEnforced
})

@description('Phase-two publication handoff tying the contract outputs to the exact bootstrap and RBAC inventory.')
output monitoringContractPublicationHandoff object = {
  schemaVersion: 'athena.wc024MonitoringContractPublicationHandoff.v1'
  bootstrapHandoffId: validatedHandoff.handoffId
  effectiveRbacInventoryDigest: validatedMonitoringEffectiveRbacInventory.inventoryDigest
  effectiveRbacSourceManifestDigest: validatedMonitoringEffectiveRbacInventory.sourceManifestDigest
  publishedAt: publicationRequestedAt
  publicationState: 'published'
}

output monitoringAcquisitionContractPublicationReady bool = true
