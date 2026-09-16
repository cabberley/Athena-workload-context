targetScope = 'resourceGroup'

metadata name = 'WC-027 guidance authority publisher'
metadata description = 'Deploys the private publisher that verifies signed requests, creates immutable guidance authority assets, CAS-activates one binding, and submits only the active binding to the WC-027 enrichment runtime.'

param location string

@minLength(3)
@maxLength(32)
param namePrefix string

param managedEnvironmentResourceId string
param publisherImage string
param registryServer string
param registryResourceId string
@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
param registryRoleAssignmentMode string
param serviceBusNamespaceName string

@minLength(1)
@maxLength(1)
param requestSubmitterIdentityResourceIds array

param brokerIdentityResourceId string
param brokerIdentityPrincipalId string
param authorityReaderIdentityResourceId string
param authorityWriterIdentityResourceId string
param activationWriterIdentityResourceId string
param bindingSignerIdentityResourceId string
param requestTrustReaderIdentityResourceId string
param bindingTrustReaderIdentityResourceId string
param requestOutboxReaderIdentityResourceId string

@description('Exact additional runtime source/trust identities referenced by enrichmentRuntimeConfigurationJson and required by the publisher.')
@minLength(5)
@maxLength(5)
param sourceIdentityResourceIds array

@description('Exact storage account resource ID hosting enrichmentRuntimeConfigurationJson.guidanceAuthoritySource.')
param authorityStorageAccountResourceId string

@description('Exact storage account resource ID hosting enrichmentRuntimeConfigurationJson.guidanceActivation.')
param activationStorageAccountResourceId string

@description('Exact versioning-enabled storage account resource ID hosting the immutable publication-request outbox.')
param requestOutboxStorageAccountResourceId string

param requestKeyResourceId string
param bindingKeyResourceId string

@minLength(1)
@maxLength(512)
param requestLogicalKeyId string

@minLength(1)
@maxLength(512)
param bindingLogicalKeyId string

@minLength(71)
@maxLength(71)
param requestKeyFingerprint string

@minLength(71)
@maxLength(71)
param bindingKeyFingerprint string

@description('Exact JSON emitted by the deployed WC-027 enrichment runtime module.')
param enrichmentRuntimeConfigurationJson string

@minLength(71)
@maxLength(71)
param enrichmentRuntimeConfigurationDigest string

@minLength(71)
@maxLength(71)
param publisherConfigurationDigest string

param tags object = {}

var requestQueueName = 'wc027-guidance-authority-requests'
var triggerQueueName = 'wc027-enrichment-feed-requests'
var requestOutboxContainerName = 'wc027-guidance-request-outbox'
var serviceBusDataReceiverRoleDefinitionId = '4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d'
var serviceBusDataSenderRoleDefinitionId = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var repositoryReaderRoleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'
var imagePullRoleDefinitionId = registryRoleAssignmentMode == 'LegacyRegistryPermissions'
  ? acrPullRoleDefinitionId
  : repositoryReaderRoleDefinitionId
var guidancePublisherKedaPollingIntervalSeconds = 30
var guidancePublisherColdStartSeconds = 30
var guidancePublisherConnectionSetupSeconds = 30
var guidancePublisherProcessingSeconds = 60
var guidancePublisherCasMarginSeconds = 5
var guidancePublisherMinimumRemainingLifetimeSeconds = guidancePublisherKedaPollingIntervalSeconds + guidancePublisherColdStartSeconds + guidancePublisherConnectionSetupSeconds + guidancePublisherProcessingSeconds
var guidanceFeedKedaPollingIntervalSeconds = 30
var guidanceFeedColdStartSeconds = 30
var guidanceFeedConnectionSetupSeconds = 30
var guidanceFeedProcessingSeconds = 60
var guidanceFeedDeliveryJitterSeconds = 30
var guidanceFeedIrreversibleWriteMarginSeconds = 15
var guidanceFeedMinimumRemainingLifetimeSeconds = guidanceFeedKedaPollingIntervalSeconds + guidanceFeedColdStartSeconds + guidanceFeedConnectionSetupSeconds + guidanceFeedProcessingSeconds
var guidanceFeedTriggerRecoverySeconds = 300
var guidanceMinimumRemainingLifetimeSeconds = guidancePublisherMinimumRemainingLifetimeSeconds
var guidancePublicationDeliveryBudget = {
  publisherKedaPollingIntervalSeconds: guidancePublisherKedaPollingIntervalSeconds
  publisherColdStartSeconds: guidancePublisherColdStartSeconds
  publisherConnectionSetupSeconds: guidancePublisherConnectionSetupSeconds
  publisherProcessingSeconds: guidancePublisherProcessingSeconds
  publisherCasMarginSeconds: guidancePublisherCasMarginSeconds
  publisherMinimumRemainingLifetimeSeconds: guidancePublisherMinimumRemainingLifetimeSeconds
  feedKedaPollingIntervalSeconds: guidanceFeedKedaPollingIntervalSeconds
  feedColdStartSeconds: guidanceFeedColdStartSeconds
  feedConnectionSetupSeconds: guidanceFeedConnectionSetupSeconds
  feedProcessingSeconds: guidanceFeedProcessingSeconds
  feedDeliveryJitterSeconds: guidanceFeedDeliveryJitterSeconds
  feedIrreversibleWriteMarginSeconds: guidanceFeedIrreversibleWriteMarginSeconds
  feedMinimumRemainingLifetimeSeconds: guidanceFeedMinimumRemainingLifetimeSeconds
  feedTriggerRecoverySeconds: guidanceFeedTriggerRecoverySeconds
  minimumRemainingLifetimeSeconds: guidanceMinimumRemainingLifetimeSeconds
}
var parsedEnrichmentRuntimeConfiguration = json(enrichmentRuntimeConfigurationJson)
var runtimeAuthorityAssets = parsedEnrichmentRuntimeConfiguration.guidanceAuthoritySource
var runtimeActivation = parsedEnrichmentRuntimeConfiguration.guidanceActivation
var runtimeConfiguredIdentityResourceIds = map([
  parsedEnrichmentRuntimeConfiguration.serviceBus.brokerIdentityResourceId
  parsedEnrichmentRuntimeConfiguration.incidentLifecycleAssets.identityResourceId
  parsedEnrichmentRuntimeConfiguration.enrichmentFeedAssets.readerIdentityResourceId
  parsedEnrichmentRuntimeConfiguration.enrichmentFeedAssets.writerIdentityResourceId
  parsedEnrichmentRuntimeConfiguration.feedRegistry.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.monitoring.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.change.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.contextAuthority.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.monitoringIntent.identityResourceId
  parsedEnrichmentRuntimeConfiguration.guidanceAuthoritySource.identityResourceId
  parsedEnrichmentRuntimeConfiguration.guidanceActivation.identityResourceId
  parsedEnrichmentRuntimeConfiguration.monitoringCollectorKey.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.incident.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.correlationBinding.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.guidanceBinding.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.change.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.monitoringIntent.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.report.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.guidance.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.enrichment.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.feed.identityResourceId
  parsedEnrichmentRuntimeConfiguration.keys.notification.identityResourceId
], identityResourceId => toLower(identityResourceId))
var distinctRuntimeConfiguredIdentityResourceIds = union(
  runtimeConfiguredIdentityResourceIds,
  runtimeConfiguredIdentityResourceIds
)
var runtimeDeploymentAttachedIdentityResourceIds = map(
  parsedEnrichmentRuntimeConfiguration.deploymentBinding.attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var distinctRuntimeDeploymentAttachedIdentityResourceIds = union(
  runtimeDeploymentAttachedIdentityResourceIds,
  runtimeDeploymentAttachedIdentityResourceIds
)
var validatedRuntimeIdentityResourceIds = length(runtimeDeploymentAttachedIdentityResourceIds) == length(distinctRuntimeDeploymentAttachedIdentityResourceIds) && length(distinctRuntimeConfiguredIdentityResourceIds) == length(distinctRuntimeDeploymentAttachedIdentityResourceIds) && length(union(distinctRuntimeConfiguredIdentityResourceIds, distinctRuntimeDeploymentAttachedIdentityResourceIds)) == length(distinctRuntimeConfiguredIdentityResourceIds)
  ? distinctRuntimeConfiguredIdentityResourceIds
  : fail('embedded WC-027 runtime identities do not exactly match its deployment binding')
var expectedSourceIdentityResourceIds = map([
  parsedEnrichmentRuntimeConfiguration.incidentLifecycleAssets.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.monitoring.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.change.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.contextAuthority.identityResourceId
  parsedEnrichmentRuntimeConfiguration.correlationSources.monitoringIntent.identityResourceId
], identityResourceId => toLower(identityResourceId))
var normalizedSourceIdentityResourceIds = map(
  sourceIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var validatedSourceIdentityResourceIds = length(normalizedSourceIdentityResourceIds) == length(union(normalizedSourceIdentityResourceIds, normalizedSourceIdentityResourceIds)) && length(expectedSourceIdentityResourceIds) == length(normalizedSourceIdentityResourceIds) && length(union(expectedSourceIdentityResourceIds, normalizedSourceIdentityResourceIds)) == length(expectedSourceIdentityResourceIds)
  ? sourceIdentityResourceIds
  : fail('WC-027 guidance publisher source identities must exactly match the embedded runtime readers')
var runtimeTrustDomainFingerprints = [
  parsedEnrichmentRuntimeConfiguration.monitoringCollectorKey.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.change.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.monitoringIntent.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.incident.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.correlationBinding.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.guidanceBinding.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.report.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.guidance.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.enrichment.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.feed.keyFingerprint
  parsedEnrichmentRuntimeConfiguration.keys.notification.keyFingerprint
]
var validatedRuntimeTrustDomainFingerprints = length(union(runtimeTrustDomainFingerprints, runtimeTrustDomainFingerprints)) == length(runtimeTrustDomainFingerprints)
  ? runtimeTrustDomainFingerprints
  : fail('WC-027 runtime trust-domain public key fingerprints must be distinct')
var validatedRequestKeyFingerprint = !contains(validatedRuntimeTrustDomainFingerprints, requestKeyFingerprint)
  ? requestKeyFingerprint
  : fail('guidance publication request public key fingerprint must use a distinct trust domain')
var validatedBindingKeyFingerprint = bindingKeyFingerprint == parsedEnrichmentRuntimeConfiguration.keys.guidanceBinding.keyFingerprint
  ? bindingKeyFingerprint
  : fail('publisher binding signer fingerprint must match runtime guidance trust')
var authorityStorageAccountName = last(split(authorityStorageAccountResourceId, '/'))
var activationStorageAccountName = last(split(activationStorageAccountResourceId, '/'))
var requestOutboxStorageAccountName = last(split(requestOutboxStorageAccountResourceId, '/'))
var expectedAuthorityBlobEndpoint = 'https://${toLower(authorityStorageAccountName)}.blob.${environment().suffixes.storage}'
var expectedActivationTableEndpoint = 'https://${toLower(activationStorageAccountName)}.table.${environment().suffixes.storage}'
var validatedAuthorityStorageAccountName = runtimeAuthorityAssets.blobEndpoint == expectedAuthorityBlobEndpoint
  ? authorityStorageAccountName
  : fail('authorityStorageAccountResourceId must exactly host the runtime guidanceAuthoritySource endpoint')
var validatedActivationStorageAccountName = runtimeActivation.tableEndpoint == expectedActivationTableEndpoint
  ? activationStorageAccountName
  : fail('activationStorageAccountResourceId must exactly host the runtime guidanceActivation endpoint')
var authorityContainerName = runtimeAuthorityAssets.containerName == 'wc027-guidance-authority'
  ? runtimeAuthorityAssets.containerName
  : fail('runtime guidanceAuthoritySource container must be wc027-guidance-authority')
var activationTableName = runtimeActivation.tableName
var activationPartitionKey = runtimeActivation.partitionKey

resource requestOutboxStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: requestOutboxStorageAccountName
  scope: resourceGroup(split(requestOutboxStorageAccountResourceId, '/')[2], split(requestOutboxStorageAccountResourceId, '/')[4])
}

resource requestOutboxBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: requestOutboxStorageAccount
  name: 'default'
}

var validatedRequestOutboxStorageAccountName = requestOutboxBlobService.properties.isVersioningEnabled == true
  ? requestOutboxStorageAccountName
  : fail('requestOutboxStorageAccountResourceId must have Blob versioning enabled')
var requestOutboxBlobEndpoint = 'https://${toLower(validatedRequestOutboxStorageAccountName)}.blob.${environment().suffixes.storage}'

var registryResourceIdRawSegments = split(registryResourceId, '/')
var registryResourceIdSegments = concat(
  registryResourceIdRawSegments,
  [
    ''
    ''
    ''
    ''
    ''
    ''
    ''
    ''
    ''
  ]
)
var registryResourceIdValid = length(registryResourceIdRawSegments) == 9 && empty(registryResourceIdSegments[0]) && registryResourceIdSegments[1] == 'subscriptions' && !empty(registryResourceIdSegments[2]) && registryResourceIdSegments[3] == 'resourceGroups' && !empty(registryResourceIdSegments[4]) && registryResourceIdSegments[5] == 'providers' && registryResourceIdSegments[6] == 'Microsoft.ContainerRegistry' && registryResourceIdSegments[7] == 'registries' && !empty(registryResourceIdSegments[8]) && !contains(registryResourceId, '//') && !contains(registryResourceId, '?') && !contains(registryResourceId, '#') && !contains(registryResourceId, '%')
var validatedRegistryScope = registryResourceIdValid
  ? {
      subscriptionId: registryResourceIdSegments[2]
      resourceGroupName: registryResourceIdSegments[4]
      registryName: registryResourceIdSegments[8]
    }
  : fail('registryResourceId must identify one canonical Microsoft.ContainerRegistry/registries resource')

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: validatedRegistryScope.registryName
  scope: resourceGroup(
    validatedRegistryScope.subscriptionId,
    validatedRegistryScope.resourceGroupName
  )
}

var expectedRegistryServer = '${toLower(registry.name)}.azurecr.io'
var imagePrefix = '${expectedRegistryServer}/athena/wc027-guidance-authority-publisher@sha256:'
var imageDigest = replace(publisherImage, imagePrefix, '')
var imageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  imageDigest,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var imageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  imageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedPublisherImage = registryServer == expectedRegistryServer && publisherImage == toLower(publisherImage) && startsWith(
  publisherImage,
  imagePrefix
) && length(imageDigest) == 64 && empty(imageDigestInvalidCharacters) && imageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
  ? publisherImage
  : fail('publisherImage must be a real digest-pinned image in the supplied registry')

resource brokerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(brokerIdentityResourceId, '/'))
  scope: resourceGroup(split(brokerIdentityResourceId, '/')[2], split(brokerIdentityResourceId, '/')[4])
}

resource authorityReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(authorityReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(authorityReaderIdentityResourceId, '/')[2], split(authorityReaderIdentityResourceId, '/')[4])
}

resource authorityWriterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(authorityWriterIdentityResourceId, '/'))
  scope: resourceGroup(split(authorityWriterIdentityResourceId, '/')[2], split(authorityWriterIdentityResourceId, '/')[4])
}

resource activationWriterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(activationWriterIdentityResourceId, '/'))
  scope: resourceGroup(split(activationWriterIdentityResourceId, '/')[2], split(activationWriterIdentityResourceId, '/')[4])
}

resource bindingSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(bindingSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(bindingSignerIdentityResourceId, '/')[2], split(bindingSignerIdentityResourceId, '/')[4])
}

resource requestTrustReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(requestTrustReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(requestTrustReaderIdentityResourceId, '/')[2], split(requestTrustReaderIdentityResourceId, '/')[4])
}

resource bindingTrustReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(bindingTrustReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(bindingTrustReaderIdentityResourceId, '/')[2], split(bindingTrustReaderIdentityResourceId, '/')[4])
}

resource requestOutboxReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(requestOutboxReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(requestOutboxReaderIdentityResourceId, '/')[2], split(requestOutboxReaderIdentityResourceId, '/')[4])
}

var publisherOwnedIdentityResourceIds = [
  brokerIdentity.id
  authorityReaderIdentity.id
  authorityWriterIdentity.id
  activationWriterIdentity.id
  bindingSignerIdentity.id
  requestTrustReaderIdentity.id
  requestOutboxReaderIdentity.id
]
var normalizedPublisherOwnedIdentityResourceIds = map(
  publisherOwnedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var publisherRuntimeIdentityOverlap = intersection(
  normalizedPublisherOwnedIdentityResourceIds,
  validatedRuntimeIdentityResourceIds
)
var validatedPublisherOwnedIdentityResourceIds = length(union(normalizedPublisherOwnedIdentityResourceIds, normalizedPublisherOwnedIdentityResourceIds)) == length(normalizedPublisherOwnedIdentityResourceIds) && empty(publisherRuntimeIdentityOverlap)
  ? publisherOwnedIdentityResourceIds
  : fail('WC-027 guidance publisher identities must be distinct and separate from runtime identities')
var validatedBindingTrustReaderIdentityResourceId = toLower(bindingTrustReaderIdentity.id) == toLower(parsedEnrichmentRuntimeConfiguration.keys.guidanceBinding.identityResourceId)
  ? bindingTrustReaderIdentity.id
  : fail('WC-027 guidance publisher binding trust reader must match the embedded runtime trust identity')
var attachedIdentityResourceIds = concat(
  validatedPublisherOwnedIdentityResourceIds,
  [
    validatedBindingTrustReaderIdentityResourceId
  ],
  validatedSourceIdentityResourceIds
)
var normalizedAttachedIdentityResourceIds = map(
  attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var validatedAttachedIdentityResourceIds = length(union(normalizedAttachedIdentityResourceIds, normalizedAttachedIdentityResourceIds)) == length(normalizedAttachedIdentityResourceIds)
  ? attachedIdentityResourceIds
  : fail('WC-027 guidance publisher identities must be distinct')
var normalizedRequestSubmitterIdentityResourceIds = map(
  requestSubmitterIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var requestSubmitterRuntimeIdentityOverlap = intersection(
  normalizedRequestSubmitterIdentityResourceIds,
  validatedRuntimeIdentityResourceIds
)
var requestSubmitterAttachedIdentityOverlap = intersection(
  normalizedRequestSubmitterIdentityResourceIds,
  normalizedAttachedIdentityResourceIds
)
var validatedRequestSubmitterIdentityResourceIds = length(requestSubmitterIdentityResourceIds) == 1 && empty(requestSubmitterRuntimeIdentityOverlap) && empty(requestSubmitterAttachedIdentityOverlap)
  ? requestSubmitterIdentityResourceIds
  : fail('WC-027 guidance publisher requires one dedicated request submitter identity separate from publisher and runtime identities')
var jobIdentityMap = reduce(
  validatedAttachedIdentityResourceIds,
  {},
  (current, identityResourceId) => union(current, {
    '${identityResourceId}': {}
  })
)

resource serviceBus 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: serviceBusNamespaceName
}

resource requestQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: serviceBus
  name: requestQueueName
  properties: {
    requiresSession: true
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT15M'
    defaultMessageTimeToLive: 'PT10M'
    maxMessageSizeInKilobytes: 12288
    deadLetteringOnMessageExpiration: true
    lockDuration: 'PT5M'
    maxDeliveryCount: 10
  }
}

resource triggerQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: serviceBus
  name: triggerQueueName
}

resource requestReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(requestQueue.id, brokerIdentity.id, serviceBusDataReceiverRoleDefinitionId)
  scope: requestQueue
  properties: {
    principalId: brokerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataReceiverRoleDefinitionId)
  }
}

resource triggerSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(triggerQueue.id, brokerIdentity.id, serviceBusDataSenderRoleDefinitionId)
  scope: triggerQueue
  properties: {
    principalId: brokerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataSenderRoleDefinitionId)
  }
}

resource submitterIdentities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [for identityResourceId in validatedRequestSubmitterIdentityResourceIds: {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}]

resource requestSubmitters 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (identityResourceId, index) in validatedRequestSubmitterIdentityResourceIds: {
  name: guid(requestQueue.id, submitterIdentities[index].id, serviceBusDataSenderRoleDefinitionId)
  scope: requestQueue
  properties: {
    principalId: submitterIdentities[index].properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataSenderRoleDefinitionId)
  }
}]

module requestOutboxContainer '../wc027-guidance-publication-request-producer/modules/blob-container.bicep' = {
  name: 'wc027-guidance-request-outbox-container'
  scope: resourceGroup(split(requestOutboxStorageAccountResourceId, '/')[2], split(requestOutboxStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedRequestOutboxStorageAccountName
    containerName: requestOutboxContainerName
  }
}

module requestOutboxReaderRbac '../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-outbox-publisher-reader'
  scope: resourceGroup(split(requestOutboxStorageAccountResourceId, '/')[2], split(requestOutboxStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedRequestOutboxStorageAccountName
    containerName: requestOutboxContainerName
    identityResourceId: requestOutboxReaderIdentity.id
  }
  dependsOn: [
    requestOutboxContainer
  ]
}

module authorityWriterRbac 'modules/blob-create-rbac.bicep' = {
  name: 'wc027-guidance-authority-blob-create'
  scope: resourceGroup(split(authorityStorageAccountResourceId, '/')[2], split(authorityStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedAuthorityStorageAccountName
    containerName: authorityContainerName
    identityResourceId: authorityWriterIdentity.id
  }
}

module authorityReaderRbac '../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-authority-blob-reader'
  scope: resourceGroup(split(authorityStorageAccountResourceId, '/')[2], split(authorityStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedAuthorityStorageAccountName
    containerName: authorityContainerName
    identityResourceId: authorityReaderIdentity.id
  }
  dependsOn: [
    authorityWriterRbac
  ]
}

module activationWriterRbac 'modules/table-cas-rbac.bicep' = {
  name: 'wc027-guidance-activation-table-cas'
  scope: resourceGroup(split(activationStorageAccountResourceId, '/')[2], split(activationStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedActivationStorageAccountName
    tableName: activationTableName
    identityResourceId: activationWriterIdentity.id
  }
}

resource requestVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(requestKeyResourceId, '/')[8]
  scope: resourceGroup(split(requestKeyResourceId, '/')[2], split(requestKeyResourceId, '/')[4])
}

resource requestKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: requestVault
  name: split(requestKeyResourceId, '/')[10]
}

resource bindingVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(bindingKeyResourceId, '/')[8]
  scope: resourceGroup(split(bindingKeyResourceId, '/')[2], split(bindingKeyResourceId, '/')[4])
}

resource bindingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: bindingVault
  name: split(bindingKeyResourceId, '/')[10]
}

module requestKeyVerifier '../wc027-enrichment-feed-runtime/modules/key-verifier-rbac.bicep' = {
  name: 'wc027-guidance-request-key-verifier'
  scope: resourceGroup(split(requestKeyResourceId, '/')[2], split(requestKeyResourceId, '/')[4])
  params: {
    keyVaultName: requestVault.name
    keyName: requestKey.name
    identityResourceId: requestTrustReaderIdentity.id
  }
}

module bindingKeyVerifier '../wc027-enrichment-feed-runtime/modules/key-verifier-rbac.bicep' = {
  name: 'wc027-guidance-binding-key-verifier'
  scope: resourceGroup(split(bindingKeyResourceId, '/')[2], split(bindingKeyResourceId, '/')[4])
  params: {
    keyVaultName: bindingVault.name
    keyName: bindingKey.name
    identityResourceId: bindingTrustReaderIdentity.id
  }
}

module bindingSigner 'modules/key-signer-rbac.bicep' = {
  name: 'wc027-guidance-binding-key-signer'
  scope: resourceGroup(split(bindingKeyResourceId, '/')[2], split(bindingKeyResourceId, '/')[4])
  params: {
    keyVaultName: bindingVault.name
    keyName: bindingKey.name
    identityResourceId: bindingSignerIdentity.id
  }
}

module publisherImagePull '../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' = {
  name: 'wc027-guidance-publisher-acr-pull'
  scope: resourceGroup(
    validatedRegistryScope.subscriptionId,
    validatedRegistryScope.resourceGroupName
  )
  params: {
    registryName: registry.name
    identityResourceId: brokerIdentity.id
    identityPrincipalId: brokerIdentityPrincipalId
    expectedRegistryRoleAssignmentMode: registryRoleAssignmentMode
  }
}

var requestKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(requestKeyResourceId, '/')[2]}/resourceGroups/${split(requestKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(requestKey.id, 'athena-wc027-key-verifier'))
var bindingKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(bindingKeyResourceId, '/')[2]}/resourceGroups/${split(bindingKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(bindingKey.id, 'athena-wc027-key-verifier'))
var authorityResourceGroupId = '/subscriptions/${split(authorityStorageAccountResourceId, '/')[2]}/resourceGroups/${split(authorityStorageAccountResourceId, '/')[4]}'
var authorityContainerResourceId = '${authorityStorageAccountResourceId}/blobServices/default/containers/${authorityContainerName}'
var authorityWriterRoleId = extensionResourceId(authorityResourceGroupId, 'Microsoft.Authorization/roleDefinitions', guid(authorityContainerResourceId, 'athena-wc027-immutable-blob-creator'))
var authorityWriterAssignmentId = extensionResourceId(authorityContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(authorityContainerResourceId, authorityWriterIdentity.id, authorityWriterRoleId))
var authorityReaderAssignmentId = extensionResourceId(authorityContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(authorityContainerResourceId, authorityReaderIdentity.id, '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'))
var requestOutboxContainerResourceId = '${requestOutboxStorageAccountResourceId}/blobServices/default/containers/${requestOutboxContainerName}'
var requestOutboxReaderAssignmentId = extensionResourceId(requestOutboxContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(requestOutboxContainerResourceId, requestOutboxReaderIdentity.id, '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'))
var activationResourceGroupId = '/subscriptions/${split(activationStorageAccountResourceId, '/')[2]}/resourceGroups/${split(activationStorageAccountResourceId, '/')[4]}'
var activationTableResourceId = '${activationStorageAccountResourceId}/tableServices/default/tables/${activationTableName}'
var activationWriterRoleId = extensionResourceId(activationResourceGroupId, 'Microsoft.Authorization/roleDefinitions', guid(activationTableResourceId, 'athena-wc027-table-cas'))
var activationWriterAssignmentId = extensionResourceId(activationTableResourceId, 'Microsoft.Authorization/roleAssignments', guid(activationTableResourceId, activationWriterIdentity.id, activationWriterRoleId))
var bindingSignerRoleId = extensionResourceId('/subscriptions/${split(bindingKeyResourceId, '/')[2]}/resourceGroups/${split(bindingKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(bindingKey.id, 'athena-wc027-key-signer'))
var publisherImagePullRoleAssignmentResourceId = extensionResourceId(
  registry.id,
  'Microsoft.Authorization/roleAssignments',
  guid(
    registry.id,
    brokerIdentityPrincipalId,
    imagePullRoleDefinitionId
  )
)
var coreRbacResourceIds = [
  requestReceiver.id
  triggerSender.id
  authorityWriterRoleId
  authorityWriterAssignmentId
  authorityReaderAssignmentId
  requestOutboxReaderAssignmentId
  activationWriterRoleId
  activationWriterAssignmentId
  requestKeyVerifierRoleId
  extensionResourceId(requestKey.id, 'Microsoft.Authorization/roleAssignments', guid(requestKey.id, requestTrustReaderIdentity.id, requestKeyVerifierRoleId))
  bindingKeyVerifierRoleId
  extensionResourceId(bindingKey.id, 'Microsoft.Authorization/roleAssignments', guid(bindingKey.id, bindingTrustReaderIdentity.id, bindingKeyVerifierRoleId))
  bindingSignerRoleId
  extensionResourceId(bindingKey.id, 'Microsoft.Authorization/roleAssignments', guid(bindingKey.id, bindingSignerIdentity.id, bindingSignerRoleId))
  publisherImagePullRoleAssignmentResourceId
]
var submitterRbacResourceIds = map(validatedRequestSubmitterIdentityResourceIds, identityResourceId => extensionResourceId(requestQueue.id, 'Microsoft.Authorization/roleAssignments', guid(requestQueue.id, identityResourceId, serviceBusDataSenderRoleDefinitionId)))
var rbacResourceIds = concat(coreRbacResourceIds, submitterRbacResourceIds)
var bindingEvidenceDigest = guid(join(rbacResourceIds, '|'))

var publisherConfiguration = {
  schemaVersion: 'athena.wc027GuidanceAuthorityPublisherConfiguration.v1'
  serviceBus: {
    namespace: '${serviceBus.name}.servicebus.windows.net'
    requestQueueName: requestQueue.name
    triggerQueueName: triggerQueue.name
    brokerIdentityClientId: brokerIdentity.properties.clientId
    brokerIdentityResourceId: brokerIdentity.id
    requestSubmitterIdentityClientId: submitterIdentities[0].properties.clientId
    requestSubmitterIdentityResourceId: submitterIdentities[0].id
  }
  imagePull: {
    registryResourceId: registry.id
    registryServer: registryServer
    image: validatedPublisherImage
    roleAssignmentMode: registryRoleAssignmentMode
    roleDefinitionId: imagePullRoleDefinitionId
    roleAssignmentResourceId: publisherImagePullRoleAssignmentResourceId
    identityClientId: brokerIdentity.properties.clientId
    identityResourceId: brokerIdentity.id
    identityPrincipalId: brokerIdentityPrincipalId
  }
  requestOutbox: {
    blobEndpoint: requestOutboxBlobEndpoint
    containerName: requestOutboxContainerName
    identityClientId: requestOutboxReaderIdentity.properties.clientId
    identityResourceId: requestOutboxReaderIdentity.id
  }
  authorityAssets: {
    blobEndpoint: runtimeAuthorityAssets.blobEndpoint
    containerName: authorityContainerName
    readerIdentityClientId: authorityReaderIdentity.properties.clientId
    readerIdentityResourceId: authorityReaderIdentity.id
    writerIdentityClientId: authorityWriterIdentity.properties.clientId
    writerIdentityResourceId: authorityWriterIdentity.id
  }
  guidanceActivation: {
    tableEndpoint: runtimeActivation.tableEndpoint
    tableName: activationTableName
    partitionKey: activationPartitionKey
    identityClientId: activationWriterIdentity.properties.clientId
    identityResourceId: activationWriterIdentity.id
  }
  requestKey: {
    keyId: requestLogicalKeyId
    keyVaultKeyId: requestKey.properties.keyUriWithVersion
    keyFingerprint: validatedRequestKeyFingerprint
    identityClientId: requestTrustReaderIdentity.properties.clientId
    identityResourceId: requestTrustReaderIdentity.id
  }
  bindingSigningKey: {
    keyId: bindingLogicalKeyId
    keyVaultKeyId: bindingKey.properties.keyUriWithVersion
    keyFingerprint: validatedBindingKeyFingerprint
    identityClientId: bindingSignerIdentity.properties.clientId
    identityResourceId: bindingSignerIdentity.id
  }
  deliveryBudget: guidancePublicationDeliveryBudget
  enrichmentRuntimeConfiguration: parsedEnrichmentRuntimeConfiguration
  deploymentBinding: {
    bindingEvidenceId: bindingEvidenceDigest
    attachedIdentityResourceIds: validatedAttachedIdentityResourceIds
    rbacResourceIds: rbacResourceIds
  }
}
var publisherConfigurationJson = string(publisherConfiguration)

resource publisherJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${take(namePrefix, 18)}-w27-guide-auth'
  location: location
  tags: union(tags, {
    component: 'wc027-guidance-authority-publisher'
    dataBoundary: 'customer'
    managedBy: 'bicep'
    runtimeConfigurationDigest: publisherConfigurationDigest
    enrichmentRuntimeConfigurationDigest: enrichmentRuntimeConfigurationDigest
    bindingEvidenceDigest: bindingEvidenceDigest
  })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: jobIdentityMap
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      replicaTimeout: 900
      replicaRetryLimit: 0
      triggerType: 'Event'
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: 1
          pollingInterval: guidancePublisherKedaPollingIntervalSeconds
          rules: [
            {
              name: 'wc027-guidance-authority-request'
              type: 'azure-servicebus'
              identity: brokerIdentity.id
              auth: []
              metadata: {
                namespace: serviceBusNamespaceName
                queueName: requestQueue.name
                messageCount: '1'
                cloud: 'AzurePublicCloud'
                isSessionsEnabled: 'true'
              }
            }
          ]
        }
      }
      registries: [
        {
          server: registryServer
          identity: brokerIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc027-guidance-authority-publisher'
          image: validatedPublisherImage
          command: [
            'athena-context'
          ]
          args: [
            'wc027-guidance-authority-publisher'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: brokerIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON'
              value: publisherConfigurationJson
            }
          ]
          resources: {
            cpu: 1
            memory: '2Gi'
          }
        }
      ]
    }
  }
  dependsOn: [
    requestSubmitters
    requestOutboxReaderRbac
    publisherImagePull
  ]
}

output publisherJobResourceId string = publisherJob.id
output publisherImage string = validatedPublisherImage
output publisherImagePullRoleAssignmentMode string = registryRoleAssignmentMode
output publisherImagePullRoleDefinitionId string = imagePullRoleDefinitionId
output publisherImagePullRoleAssignmentResourceId string = publisherImagePullRoleAssignmentResourceId
output deployedPublisherConfigurationJson string = publisherConfigurationJson
output deployedPublisherConfigurationDigest string = startsWith(publisherConfigurationDigest, 'sha256:')
  ? publisherConfigurationDigest
  : fail('publisherConfigurationDigest must be a SHA-256 digest')
output attachedIdentityResourceIds array = validatedAttachedIdentityResourceIds
output bindingEvidenceDigest string = bindingEvidenceDigest
output requestQueueName string = requestQueue.name
output authorityContainerName string = authorityContainerName
output activationTableName string = activationTableName
output bindingLogicalKeyId string = bindingLogicalKeyId
output bindingKeyVaultKeyId string = bindingKey.properties.keyUriWithVersion
output requestQueueResourceId string = requestQueue.id
output requestKeyResourceId string = requestKey.id
output requestLogicalKeyId string = requestLogicalKeyId
output requestKeyVaultKeyId string = requestKey.properties.keyUriWithVersion
output requestKeyFingerprint string = validatedRequestKeyFingerprint
output requestOutboxBlobEndpoint string = requestOutboxBlobEndpoint
output requestOutboxContainerName string = requestOutboxContainerName
