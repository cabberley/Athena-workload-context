targetScope = 'resourceGroup'

metadata name = 'WC-027 guidance publication-request producer'
metadata description = 'Deploys the private event-triggered producer that verifies one canonical incident-bound request, reads the current signed occurrence and immutable published context authority, signs and self-verifies one deterministic GuidanceAuthorityPublicationRequest.v1, persists immutable outbox evidence, revalidates authority, and sends only that request to the existing guidance-authority publisher queue.'

param location string

@minLength(3)
@maxLength(32)
param namePrefix string

param managedEnvironmentResourceId string
param producerImage string
param registryServer string
param registryResourceId string
param serviceBusNamespaceName string

@minLength(1)
@maxLength(8)
param inputSubmitterIdentityResourceIds array

param receiverIdentityResourceId string
param senderIdentityResourceId string
param incidentReaderIdentityResourceId string
param contextAuthorityReaderIdentityResourceId string
param outboxReaderIdentityResourceId string
param outboxWriterIdentityResourceId string
param upstreamTrustReaderIdentityResourceId string
param requestSignerIdentityResourceId string
param requestVerifierIdentityResourceId string

@description('Exact storage account resource ID hosting the existing incident-assets container.')
param incidentStorageAccountResourceId string

@description('Exact storage account resource ID hosting the immutable context-authority container.')
param contextAuthorityStorageAccountResourceId string

@description('Exact storage account resource ID hosting the isolated immutable request outbox.')
param outboxStorageAccountResourceId string

param incidentKeyResourceId string
param correlationBindingKeyResourceId string
param requestKeyResourceId string

@minLength(1)
@maxLength(512)
param requestLogicalKeyId string

@minLength(71)
@maxLength(71)
param requestKeyFingerprint string

@description('Exact JSON emitted by the deployed WC-027 enrichment/feed runtime module.')
param enrichmentRuntimeConfigurationJson string

@minLength(71)
@maxLength(71)
param enrichmentRuntimeConfigurationDigest string

@minLength(71)
@maxLength(71)
param producerConfigurationDigest string

param tags object = {}

var inputQueueName = 'wc027-guidance-publication-inputs'
var outputQueueName = 'wc027-guidance-authority-requests'
var outboxContainerName = 'wc027-guidance-request-outbox'
var serviceBusDataReceiverRoleDefinitionId = '4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d'
var serviceBusDataSenderRoleDefinitionId = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var storageBlobDataReaderRoleDefinitionId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

var parsedRuntimeConfiguration = json(enrichmentRuntimeConfigurationJson)
var runtimeIncidentAssets = parsedRuntimeConfiguration.incidentLifecycleAssets
var runtimeContextAuthority = parsedRuntimeConfiguration.correlationSources.contextAuthority
var runtimeIncidentKey = parsedRuntimeConfiguration.keys.incident
var runtimeCorrelationBindingKey = parsedRuntimeConfiguration.keys.correlationBinding
var runtimeConfiguredIdentityResourceIds = map([
  parsedRuntimeConfiguration.serviceBus.brokerIdentityResourceId
  parsedRuntimeConfiguration.incidentLifecycleAssets.identityResourceId
  parsedRuntimeConfiguration.enrichmentFeedAssets.readerIdentityResourceId
  parsedRuntimeConfiguration.enrichmentFeedAssets.writerIdentityResourceId
  parsedRuntimeConfiguration.feedRegistry.identityResourceId
  parsedRuntimeConfiguration.correlationSources.monitoring.identityResourceId
  parsedRuntimeConfiguration.correlationSources.change.identityResourceId
  parsedRuntimeConfiguration.correlationSources.contextAuthority.identityResourceId
  parsedRuntimeConfiguration.correlationSources.monitoringIntent.identityResourceId
  parsedRuntimeConfiguration.guidanceAuthoritySource.identityResourceId
  parsedRuntimeConfiguration.guidanceActivation.identityResourceId
  parsedRuntimeConfiguration.monitoringCollectorKey.identityResourceId
  parsedRuntimeConfiguration.keys.incident.identityResourceId
  parsedRuntimeConfiguration.keys.correlationBinding.identityResourceId
  parsedRuntimeConfiguration.keys.guidanceBinding.identityResourceId
  parsedRuntimeConfiguration.keys.change.identityResourceId
  parsedRuntimeConfiguration.keys.monitoringIntent.identityResourceId
  parsedRuntimeConfiguration.keys.report.identityResourceId
  parsedRuntimeConfiguration.keys.guidance.identityResourceId
  parsedRuntimeConfiguration.keys.enrichment.identityResourceId
  parsedRuntimeConfiguration.keys.feed.identityResourceId
  parsedRuntimeConfiguration.keys.notification.identityResourceId
], identityResourceId => toLower(identityResourceId))
var distinctRuntimeConfiguredIdentityResourceIds = union(
  runtimeConfiguredIdentityResourceIds,
  runtimeConfiguredIdentityResourceIds
)
var runtimeDeploymentAttachedIdentityResourceIds = map(
  parsedRuntimeConfiguration.deploymentBinding.attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var distinctRuntimeDeploymentAttachedIdentityResourceIds = union(
  runtimeDeploymentAttachedIdentityResourceIds,
  runtimeDeploymentAttachedIdentityResourceIds
)
var validatedRuntimeIdentityResourceIds = length(runtimeDeploymentAttachedIdentityResourceIds) == length(distinctRuntimeDeploymentAttachedIdentityResourceIds) && length(distinctRuntimeConfiguredIdentityResourceIds) == length(distinctRuntimeDeploymentAttachedIdentityResourceIds) && length(union(distinctRuntimeConfiguredIdentityResourceIds, distinctRuntimeDeploymentAttachedIdentityResourceIds)) == length(distinctRuntimeConfiguredIdentityResourceIds)
  ? distinctRuntimeConfiguredIdentityResourceIds
  : fail('embedded WC-027 runtime identities do not exactly match its deployment binding')
var validatedServiceBusNamespaceName = parsedRuntimeConfiguration.serviceBus.namespace == '${toLower(serviceBusNamespaceName)}.servicebus.windows.net'
  ? serviceBusNamespaceName
  : fail('serviceBusNamespaceName must match the embedded WC-027 runtime namespace')
var runtimeTrustDomainKeyIds = [
  parsedRuntimeConfiguration.monitoringCollectorKey.keyId
  parsedRuntimeConfiguration.keys.change.keyId
  parsedRuntimeConfiguration.keys.monitoringIntent.keyId
  parsedRuntimeConfiguration.keys.incident.keyId
  parsedRuntimeConfiguration.keys.correlationBinding.keyId
  parsedRuntimeConfiguration.keys.guidanceBinding.keyId
  parsedRuntimeConfiguration.keys.report.keyId
  parsedRuntimeConfiguration.keys.guidance.keyId
  parsedRuntimeConfiguration.keys.enrichment.keyId
  parsedRuntimeConfiguration.keys.feed.keyId
  parsedRuntimeConfiguration.keys.notification.keyId
]
var runtimeTrustDomainKeyVaultKeyIds = [
  parsedRuntimeConfiguration.monitoringCollectorKey.keyVaultKeyId
  parsedRuntimeConfiguration.keys.change.keyVaultKeyId
  parsedRuntimeConfiguration.keys.monitoringIntent.keyVaultKeyId
  parsedRuntimeConfiguration.keys.incident.keyVaultKeyId
  parsedRuntimeConfiguration.keys.correlationBinding.keyVaultKeyId
  parsedRuntimeConfiguration.keys.guidanceBinding.keyVaultKeyId
  parsedRuntimeConfiguration.keys.report.keyVaultKeyId
  parsedRuntimeConfiguration.keys.guidance.keyVaultKeyId
  parsedRuntimeConfiguration.keys.enrichment.keyVaultKeyId
  parsedRuntimeConfiguration.keys.feed.keyVaultKeyId
  parsedRuntimeConfiguration.keys.notification.keyVaultKeyId
]
var runtimeTrustDomainFingerprints = [
  parsedRuntimeConfiguration.monitoringCollectorKey.keyFingerprint
  parsedRuntimeConfiguration.keys.change.keyFingerprint
  parsedRuntimeConfiguration.keys.monitoringIntent.keyFingerprint
  parsedRuntimeConfiguration.keys.incident.keyFingerprint
  parsedRuntimeConfiguration.keys.correlationBinding.keyFingerprint
  parsedRuntimeConfiguration.keys.guidanceBinding.keyFingerprint
  parsedRuntimeConfiguration.keys.report.keyFingerprint
  parsedRuntimeConfiguration.keys.guidance.keyFingerprint
  parsedRuntimeConfiguration.keys.enrichment.keyFingerprint
  parsedRuntimeConfiguration.keys.feed.keyFingerprint
  parsedRuntimeConfiguration.keys.notification.keyFingerprint
]
var validatedRuntimeTrustDomainFingerprints = length(union(runtimeTrustDomainFingerprints, runtimeTrustDomainFingerprints)) == length(runtimeTrustDomainFingerprints)
  ? runtimeTrustDomainFingerprints
  : fail('WC-027 runtime trust-domain public key fingerprints must be distinct')
var validatedRequestKeyFingerprint = !contains(validatedRuntimeTrustDomainFingerprints, requestKeyFingerprint)
  ? requestKeyFingerprint
  : fail('guidance publication-request key fingerprint must use a distinct trust domain')
var validatedRequestLogicalKeyId = !contains(runtimeTrustDomainKeyIds, requestLogicalKeyId) && !startsWith(toLower(requestLogicalKeyId), 'https://')
  ? requestLogicalKeyId
  : fail('guidance publication-request key ID must be a stable distinct logical authority')

var incidentStorageAccountName = last(split(incidentStorageAccountResourceId, '/'))
var contextAuthorityStorageAccountName = last(split(contextAuthorityStorageAccountResourceId, '/'))
var outboxStorageAccountName = last(split(outboxStorageAccountResourceId, '/'))
var expectedIncidentBlobEndpoint = 'https://${toLower(incidentStorageAccountName)}.blob.${environment().suffixes.storage}'
var expectedContextAuthorityBlobEndpoint = 'https://${toLower(contextAuthorityStorageAccountName)}.blob.${environment().suffixes.storage}'
resource outboxStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: outboxStorageAccountName
  scope: resourceGroup(split(outboxStorageAccountResourceId, '/')[2], split(outboxStorageAccountResourceId, '/')[4])
}

resource outboxBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: outboxStorageAccount
  name: 'default'
}

var validatedOutboxStorageAccountName = outboxBlobService.properties.isVersioningEnabled == true
  ? outboxStorageAccountName
  : fail('outboxStorageAccountResourceId must have Blob versioning enabled')
var outboxBlobEndpoint = 'https://${toLower(validatedOutboxStorageAccountName)}.blob.${environment().suffixes.storage}'
var validatedIncidentStorageAccountName = runtimeIncidentAssets.blobEndpoint == expectedIncidentBlobEndpoint && runtimeIncidentAssets.containerName == 'incident-assets'
  ? incidentStorageAccountName
  : fail('incidentStorageAccountResourceId must exactly host runtime incident-assets')
var validatedContextAuthorityStorageAccountName = runtimeContextAuthority.blobEndpoint == expectedContextAuthorityBlobEndpoint && runtimeContextAuthority.containerName == 'context-authority'
  ? contextAuthorityStorageAccountName
  : fail('contextAuthorityStorageAccountResourceId must exactly host runtime context-authority')

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: last(split(registryResourceId, '/'))
  scope: resourceGroup(split(registryResourceId, '/')[2], split(registryResourceId, '/')[4])
}

var expectedRegistryServer = '${toLower(registry.name)}.azurecr.io'
var imagePrefix = '${expectedRegistryServer}/athena/wc027-guidance-publication-request-producer@sha256:'
var imageDigest = replace(producerImage, imagePrefix, '')
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
var validatedProducerImage = registryServer == expectedRegistryServer && producerImage == toLower(producerImage) && startsWith(
  producerImage,
  imagePrefix
) && length(imageDigest) == 64 && empty(imageDigestInvalidCharacters) && imageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
  ? producerImage
  : fail('producerImage must be a real digest-pinned image in the supplied registry')

resource receiverIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(receiverIdentityResourceId, '/'))
  scope: resourceGroup(split(receiverIdentityResourceId, '/')[2], split(receiverIdentityResourceId, '/')[4])
}

resource senderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(senderIdentityResourceId, '/'))
  scope: resourceGroup(split(senderIdentityResourceId, '/')[2], split(senderIdentityResourceId, '/')[4])
}

resource incidentReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(incidentReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(incidentReaderIdentityResourceId, '/')[2], split(incidentReaderIdentityResourceId, '/')[4])
}

resource contextAuthorityReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(contextAuthorityReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(contextAuthorityReaderIdentityResourceId, '/')[2], split(contextAuthorityReaderIdentityResourceId, '/')[4])
}

resource outboxReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(outboxReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(outboxReaderIdentityResourceId, '/')[2], split(outboxReaderIdentityResourceId, '/')[4])
}

resource outboxWriterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(outboxWriterIdentityResourceId, '/'))
  scope: resourceGroup(split(outboxWriterIdentityResourceId, '/')[2], split(outboxWriterIdentityResourceId, '/')[4])
}

resource upstreamTrustReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(upstreamTrustReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(upstreamTrustReaderIdentityResourceId, '/')[2], split(upstreamTrustReaderIdentityResourceId, '/')[4])
}

resource requestSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(requestSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(requestSignerIdentityResourceId, '/')[2], split(requestSignerIdentityResourceId, '/')[4])
}

resource requestVerifierIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(requestVerifierIdentityResourceId, '/'))
  scope: resourceGroup(split(requestVerifierIdentityResourceId, '/')[2], split(requestVerifierIdentityResourceId, '/')[4])
}

var attachedIdentityResourceIds = [
  receiverIdentity.id
  senderIdentity.id
  incidentReaderIdentity.id
  contextAuthorityReaderIdentity.id
  outboxReaderIdentity.id
  outboxWriterIdentity.id
  upstreamTrustReaderIdentity.id
  requestSignerIdentity.id
  requestVerifierIdentity.id
]
var normalizedAttachedIdentityResourceIds = map(
  attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var validatedDistinctAttachedIdentityResourceIds = length(union(normalizedAttachedIdentityResourceIds, normalizedAttachedIdentityResourceIds)) == length(normalizedAttachedIdentityResourceIds)
  ? attachedIdentityResourceIds
  : fail('WC-027 guidance publication-request producer identities must be distinct')
var producerRuntimeIdentityOverlap = intersection(
  normalizedAttachedIdentityResourceIds,
  validatedRuntimeIdentityResourceIds
)
var validatedAttachedIdentityResourceIds = empty(producerRuntimeIdentityOverlap)
  ? validatedDistinctAttachedIdentityResourceIds
  : fail('WC-027 guidance publication-request producer identities must be separate from every runtime identity')
var normalizedInputSubmitterIdentityResourceIds = map(
  inputSubmitterIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var inputSubmitterProducerIdentityOverlap = intersection(
  normalizedInputSubmitterIdentityResourceIds,
  normalizedAttachedIdentityResourceIds
)
var validatedInputSubmitterIdentityResourceIds = length(union(normalizedInputSubmitterIdentityResourceIds, normalizedInputSubmitterIdentityResourceIds)) == length(normalizedInputSubmitterIdentityResourceIds) && empty(inputSubmitterProducerIdentityOverlap)
  ? inputSubmitterIdentityResourceIds
  : fail('WC-027 guidance request input submitters must be unique and separate from producer identities')
var jobIdentityMap = reduce(
  validatedAttachedIdentityResourceIds,
  {},
  (current, identityResourceId) => union(current, {
    '${identityResourceId}': {}
  })
)

resource serviceBus 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: validatedServiceBusNamespaceName
}

resource inputQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: serviceBus
  name: inputQueueName
  properties: {
    requiresSession: true
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT15M'
    defaultMessageTimeToLive: 'PT15M'
    maxMessageSizeInKilobytes: 12288
    deadLetteringOnMessageExpiration: true
    lockDuration: 'PT5M'
    maxDeliveryCount: 5
  }
}

resource outputQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: serviceBus
  name: outputQueueName
}
var validatedOutputQueueName = outputQueue.properties.requiresSession == true && outputQueue.properties.requiresDuplicateDetection == true
  ? outputQueue.name
  : fail('the guidance-authority request queue must require sessions and duplicate detection')

resource inputReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(inputQueue.id, receiverIdentity.id, serviceBusDataReceiverRoleDefinitionId)
  scope: inputQueue
  properties: {
    principalId: receiverIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataReceiverRoleDefinitionId)
  }
}

resource inputSubmitterIdentities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [for identityResourceId in validatedInputSubmitterIdentityResourceIds: {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}]

resource inputSubmitters 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (identityResourceId, index) in validatedInputSubmitterIdentityResourceIds: {
  name: guid(inputQueue.id, inputSubmitterIdentities[index].id, serviceBusDataSenderRoleDefinitionId)
  scope: inputQueue
  properties: {
    principalId: inputSubmitterIdentities[index].properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', serviceBusDataSenderRoleDefinitionId)
  }
}]

module outboxContainerDeployment 'modules/blob-container.bicep' = {
  name: 'wc027-guidance-request-outbox-container'
  scope: resourceGroup(split(outboxStorageAccountResourceId, '/')[2], split(outboxStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedOutboxStorageAccountName
    containerName: outboxContainerName
  }
}

module incidentReaderRbac '../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-incident-reader'
  scope: resourceGroup(split(incidentStorageAccountResourceId, '/')[2], split(incidentStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedIncidentStorageAccountName
    containerName: runtimeIncidentAssets.containerName
    identityResourceId: incidentReaderIdentity.id
  }
}

module contextAuthorityReaderRbac '../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-context-reader'
  scope: resourceGroup(split(contextAuthorityStorageAccountResourceId, '/')[2], split(contextAuthorityStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedContextAuthorityStorageAccountName
    containerName: runtimeContextAuthority.containerName
    identityResourceId: contextAuthorityReaderIdentity.id
  }
}

module outboxWriterRbac '../wc027-guidance-authority-publisher/modules/blob-create-rbac.bicep' = {
  name: 'wc027-guidance-request-outbox-create'
  scope: resourceGroup(split(outboxStorageAccountResourceId, '/')[2], split(outboxStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedOutboxStorageAccountName
    containerName: outboxContainerName
    identityResourceId: outboxWriterIdentity.id
  }
  dependsOn: [
    outboxContainerDeployment
  ]
}

module outboxReaderRbac '../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-outbox-reader'
  scope: resourceGroup(split(outboxStorageAccountResourceId, '/')[2], split(outboxStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: validatedOutboxStorageAccountName
    containerName: outboxContainerName
    identityResourceId: outboxReaderIdentity.id
  }
  dependsOn: [
    outboxWriterRbac
  ]
}

resource incidentVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(incidentKeyResourceId, '/')[8]
  scope: resourceGroup(split(incidentKeyResourceId, '/')[2], split(incidentKeyResourceId, '/')[4])
}

resource incidentKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: incidentVault
  name: split(incidentKeyResourceId, '/')[10]
}

resource correlationBindingVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(correlationBindingKeyResourceId, '/')[8]
  scope: resourceGroup(split(correlationBindingKeyResourceId, '/')[2], split(correlationBindingKeyResourceId, '/')[4])
}

resource correlationBindingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: correlationBindingVault
  name: split(correlationBindingKeyResourceId, '/')[10]
}

resource requestVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(requestKeyResourceId, '/')[8]
  scope: resourceGroup(split(requestKeyResourceId, '/')[2], split(requestKeyResourceId, '/')[4])
}

resource requestKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: requestVault
  name: split(requestKeyResourceId, '/')[10]
}

var validatedIncidentKeyVaultKeyId = incidentKey.properties.keyUriWithVersion == runtimeIncidentKey.keyVaultKeyId
  ? incidentKey.properties.keyUriWithVersion
  : fail('incidentKeyResourceId must resolve the exact runtime incident key version')
var validatedCorrelationBindingKeyVaultKeyId = correlationBindingKey.properties.keyUriWithVersion == runtimeCorrelationBindingKey.keyVaultKeyId
  ? correlationBindingKey.properties.keyUriWithVersion
  : fail('correlationBindingKeyResourceId must resolve the exact runtime correlation-binding key version')
var validatedRequestKeyVaultKeyId = !contains(runtimeTrustDomainKeyVaultKeyIds, requestKey.properties.keyUriWithVersion) && validatedRequestLogicalKeyId != requestKey.properties.keyUriWithVersion
  ? requestKey.properties.keyUriWithVersion
  : fail('guidance publication-request key must be distinct from upstream authorities')

module incidentKeyPublicReader 'modules/key-public-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-incident-key-reader'
  scope: resourceGroup(split(incidentKeyResourceId, '/')[2], split(incidentKeyResourceId, '/')[4])
  params: {
    keyVaultName: incidentVault.name
    keyName: incidentKey.name
    identityResourceId: upstreamTrustReaderIdentity.id
  }
}

module correlationBindingKeyPublicReader 'modules/key-public-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-correlation-key-reader'
  scope: resourceGroup(split(correlationBindingKeyResourceId, '/')[2], split(correlationBindingKeyResourceId, '/')[4])
  params: {
    keyVaultName: correlationBindingVault.name
    keyName: correlationBindingKey.name
    identityResourceId: upstreamTrustReaderIdentity.id
  }
}

module requestKeyPublicReader 'modules/key-public-reader-rbac.bicep' = {
  name: 'wc027-guidance-request-signature-reader'
  scope: resourceGroup(split(requestKeyResourceId, '/')[2], split(requestKeyResourceId, '/')[4])
  params: {
    keyVaultName: requestVault.name
    keyName: requestKey.name
    identityResourceId: requestVerifierIdentity.id
  }
}

module requestKeySigner '../wc027-guidance-authority-publisher/modules/key-signer-rbac.bicep' = {
  name: 'wc027-guidance-request-key-signer'
  scope: resourceGroup(split(requestKeyResourceId, '/')[2], split(requestKeyResourceId, '/')[4])
  params: {
    keyVaultName: requestVault.name
    keyName: requestKey.name
    identityResourceId: requestSignerIdentity.id
  }
}

module producerImagePull '../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' = {
  name: 'wc027-guidance-request-acr-pull'
  params: {
    registryName: registry.name
    identityResourceId: receiverIdentity.id
  }
}

var incidentContainerResourceId = '${incidentStorageAccountResourceId}/blobServices/default/containers/${runtimeIncidentAssets.containerName}'
var contextAuthorityContainerResourceId = '${contextAuthorityStorageAccountResourceId}/blobServices/default/containers/${runtimeContextAuthority.containerName}'
var outboxContainerResourceId = '${outboxStorageAccountResourceId}/blobServices/default/containers/${outboxContainerName}'
var outboxResourceGroupId = '/subscriptions/${split(outboxStorageAccountResourceId, '/')[2]}/resourceGroups/${split(outboxStorageAccountResourceId, '/')[4]}'
var outboxWriterRoleId = extensionResourceId(outboxResourceGroupId, 'Microsoft.Authorization/roleDefinitions', guid(outboxContainerResourceId, 'athena-wc027-immutable-blob-creator'))
var publicIncidentKeyReaderRoleId = extensionResourceId('/subscriptions/${split(incidentKeyResourceId, '/')[2]}/resourceGroups/${split(incidentKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(incidentKey.id, 'athena-wc027-exact-public-key-reader'))
var publicCorrelationKeyReaderRoleId = extensionResourceId('/subscriptions/${split(correlationBindingKeyResourceId, '/')[2]}/resourceGroups/${split(correlationBindingKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(correlationBindingKey.id, 'athena-wc027-exact-public-key-reader'))
var publicRequestKeyReaderRoleId = extensionResourceId('/subscriptions/${split(requestKeyResourceId, '/')[2]}/resourceGroups/${split(requestKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(requestKey.id, 'athena-wc027-exact-public-key-reader'))
var requestSignerRoleId = extensionResourceId('/subscriptions/${split(requestKeyResourceId, '/')[2]}/resourceGroups/${split(requestKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(requestKey.id, 'athena-wc027-key-signer'))
var coreRbacResourceIds = [
  inputReceiver.id
  extensionResourceId(incidentContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(incidentContainerResourceId, incidentReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  extensionResourceId(contextAuthorityContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(contextAuthorityContainerResourceId, contextAuthorityReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  outboxWriterRoleId
  extensionResourceId(outboxContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(outboxContainerResourceId, outboxWriterIdentity.id, outboxWriterRoleId))
  extensionResourceId(outboxContainerResourceId, 'Microsoft.Authorization/roleAssignments', guid(outboxContainerResourceId, outboxReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  publicIncidentKeyReaderRoleId
  extensionResourceId(incidentKey.id, 'Microsoft.Authorization/roleAssignments', guid(incidentKey.id, upstreamTrustReaderIdentity.id, publicIncidentKeyReaderRoleId))
  publicCorrelationKeyReaderRoleId
  extensionResourceId(correlationBindingKey.id, 'Microsoft.Authorization/roleAssignments', guid(correlationBindingKey.id, upstreamTrustReaderIdentity.id, publicCorrelationKeyReaderRoleId))
  publicRequestKeyReaderRoleId
  extensionResourceId(requestKey.id, 'Microsoft.Authorization/roleAssignments', guid(requestKey.id, requestVerifierIdentity.id, publicRequestKeyReaderRoleId))
  requestSignerRoleId
  extensionResourceId(requestKey.id, 'Microsoft.Authorization/roleAssignments', guid(requestKey.id, requestSignerIdentity.id, requestSignerRoleId))
  extensionResourceId(registry.id, 'Microsoft.Authorization/roleAssignments', guid(registry.id, receiverIdentity.id, acrPullRoleDefinitionId))
]
var submitterRbacResourceIds = map(validatedInputSubmitterIdentityResourceIds, identityResourceId => extensionResourceId(inputQueue.id, 'Microsoft.Authorization/roleAssignments', guid(inputQueue.id, identityResourceId, serviceBusDataSenderRoleDefinitionId)))
var rbacResourceIds = concat(coreRbacResourceIds, submitterRbacResourceIds)
var bindingEvidenceDigest = guid(join(rbacResourceIds, '|'))

var producerConfiguration = {
  schemaVersion: 'athena.wc027GuidancePublicationRequestProducerConfiguration.v1'
  serviceBus: {
    namespace: '${serviceBus.name}.servicebus.windows.net'
    inputQueueName: inputQueue.name
    outputQueueName: validatedOutputQueueName
    receiverIdentityClientId: receiverIdentity.properties.clientId
    receiverIdentityResourceId: receiverIdentity.id
    senderIdentityClientId: senderIdentity.properties.clientId
    senderIdentityResourceId: senderIdentity.id
  }
  incidentLifecycleAssets: {
    blobEndpoint: runtimeIncidentAssets.blobEndpoint
    containerName: runtimeIncidentAssets.containerName
    identityClientId: incidentReaderIdentity.properties.clientId
    identityResourceId: incidentReaderIdentity.id
  }
  contextAuthoritySource: {
    blobEndpoint: runtimeContextAuthority.blobEndpoint
    containerName: runtimeContextAuthority.containerName
    identityClientId: contextAuthorityReaderIdentity.properties.clientId
    identityResourceId: contextAuthorityReaderIdentity.id
  }
  requestOutbox: {
    blobEndpoint: outboxBlobEndpoint
    containerName: outboxContainerName
    readerIdentityClientId: outboxReaderIdentity.properties.clientId
    readerIdentityResourceId: outboxReaderIdentity.id
    writerIdentityClientId: outboxWriterIdentity.properties.clientId
    writerIdentityResourceId: outboxWriterIdentity.id
  }
  incidentKey: {
    keyId: runtimeIncidentKey.keyId
    keyVaultKeyId: validatedIncidentKeyVaultKeyId
    keyFingerprint: runtimeIncidentKey.keyFingerprint
    identityClientId: upstreamTrustReaderIdentity.properties.clientId
    identityResourceId: upstreamTrustReaderIdentity.id
  }
  correlationBindingKey: {
    keyId: validatedCorrelationBindingKeyVaultKeyId
    keyVaultKeyId: validatedCorrelationBindingKeyVaultKeyId
    keyFingerprint: runtimeCorrelationBindingKey.keyFingerprint
    identityClientId: upstreamTrustReaderIdentity.properties.clientId
    identityResourceId: upstreamTrustReaderIdentity.id
  }
  requestSigningKey: {
    keyId: validatedRequestLogicalKeyId
    keyVaultKeyId: validatedRequestKeyVaultKeyId
    keyFingerprint: validatedRequestKeyFingerprint
    signerIdentityClientId: requestSignerIdentity.properties.clientId
    signerIdentityResourceId: requestSignerIdentity.id
    verifierIdentityClientId: requestVerifierIdentity.properties.clientId
    verifierIdentityResourceId: requestVerifierIdentity.id
  }
  requestedActions: [
    'investigationCheck'
  ]
  deploymentBinding: {
    bindingEvidenceId: bindingEvidenceDigest
    attachedIdentityResourceIds: validatedAttachedIdentityResourceIds
    rbacResourceIds: rbacResourceIds
  }
}
var producerConfigurationJson = string(producerConfiguration)

resource producerJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${take(namePrefix, 15)}-w27-guide-req'
  location: location
  tags: union(tags, {
    component: 'wc027-guidance-publication-request-producer'
    dataBoundary: 'customer'
    managedBy: 'bicep'
    runtimeConfigurationDigest: producerConfigurationDigest
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
          pollingInterval: 30
          rules: [
            {
              name: 'wc027-guidance-publication-request-input'
              type: 'azure-servicebus'
              identity: receiverIdentity.id
              auth: []
              metadata: {
                namespace: validatedServiceBusNamespaceName
                queueName: inputQueue.name
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
          identity: receiverIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc027-guidance-publication-request-producer'
          image: validatedProducerImage
          command: [
            'athena-context'
          ]
          args: [
            'wc027-guidance-publication-request-producer'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: receiverIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC027_GUIDANCE_REQUEST_PRODUCER_CONFIG_JSON'
              value: producerConfigurationJson
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
    inputSubmitters
    incidentReaderRbac
    contextAuthorityReaderRbac
    outboxReaderRbac
    incidentKeyPublicReader
    correlationBindingKeyPublicReader
    requestKeyPublicReader
    requestKeySigner
    producerImagePull
  ]
}

var publisherHandoff = {
  schemaVersion: 'athena.wc027GuidancePublicationRequestPublisherHandoff.v1'
  requestQueueName: validatedOutputQueueName
  senderIdentityClientId: senderIdentity.properties.clientId
  senderIdentityResourceId: senderIdentity.id
  requestKeyResourceId: requestKey.id
  requestKey: {
    keyId: validatedRequestLogicalKeyId
    keyVaultKeyId: validatedRequestKeyVaultKeyId
    keyFingerprint: validatedRequestKeyFingerprint
  }
  requestOutbox: {
    blobEndpoint: outboxBlobEndpoint
    containerName: outboxContainerName
  }
  producerJobResourceId: producerJob.id
  producerConfigurationDigest: producerConfigurationDigest
}

output producerJobResourceId string = producerJob.id
output producerImage string = validatedProducerImage
output deployedProducerConfigurationJson string = producerConfigurationJson
output deployedProducerConfigurationDigest string = startsWith(producerConfigurationDigest, 'sha256:')
  ? producerConfigurationDigest
  : fail('producerConfigurationDigest must be a SHA-256 digest')
output attachedIdentityResourceIds array = validatedAttachedIdentityResourceIds
output bindingEvidenceDigest string = bindingEvidenceDigest
output inputQueueName string = inputQueue.name
output inputQueueResourceId string = inputQueue.id
output outputQueueName string = validatedOutputQueueName
output outputQueueResourceId string = outputQueue.id
output requestOutboxBlobEndpoint string = outboxBlobEndpoint
output requestOutboxContainerName string = outboxContainerName
output requestSenderIdentityResourceId string = senderIdentity.id
output requestKeyResourceId string = requestKey.id
output requestLogicalKeyId string = validatedRequestLogicalKeyId
output requestKeyVaultKeyId string = validatedRequestKeyVaultKeyId
output requestKeyFingerprint string = validatedRequestKeyFingerprint
output publisherHandoffJson string = string(publisherHandoff)
