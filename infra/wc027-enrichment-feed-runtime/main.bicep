targetScope = 'resourceGroup'

metadata name = 'WC-027 enrichment and feed-v2 producer runtime'
metadata description = 'Deploys the private Service Bus-triggered producer that publishes enrichment, feed-v2, and only then Notification v2. All runtime configuration, client IDs, principal IDs, storage endpoints, and versioned key URIs are derived from referenced Azure resources.'

@description('Azure region for the private Container Apps Job.')
param location string

@description('Lowercase deployment prefix.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Existing internal-only Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Digest-pinned WC-027 producer image.')
param producerImage string

@description('Existing Azure Container Registry login server.')
param registryServer string

@description('Existing Azure Container Registry resource ID.')
param registryResourceId string

@description('Existing private Premium Service Bus namespace name.')
param serviceBusNamespaceName string

@description('Existing Notification v2 outbox queue name.')
param notificationQueueName string

@description('Exact governed caller user-assigned identity resource IDs allowed to submit signed guidance bindings. Principal IDs are derived from these referenced resources.')
@minLength(1)
@maxLength(8)
param triggerSubmitterIdentityResourceIds array

@description('Broker identity resource ID attached to the Job and used by the scaler, ACR pull, and queue RBAC.')
param brokerIdentityResourceId string

@description('Producer identity resource ID that reads v1 incident-assets read-only without list access.')
param incidentReaderIdentityResourceId string

@description('Producer identity resource ID that reads back v2 enrichment/feed artifacts without list access.')
param feedV2ProducerReaderIdentityResourceId string

@description('Producer identity resource ID that creates and writes v2 enrichment/feed artifacts through the custom no-delete/no-list role.')
param feedV2WriterIdentityResourceId string

@description('Separately authorized presentation/gateway identity resource ID that reads v2 artifacts only.')
param feedV2ReaderIdentityResourceId string

@description('Feed registry Table writer identity resource ID.')
param registryWriterIdentityResourceId string

@description('Read-only identity resource ID for the current guidance-authority activation row.')
param guidanceActivationReaderIdentityResourceId string

@description('Trust/public-key reader identity resource ID used for Key Vault Reader and all verification keys.')
param trustReaderIdentityResourceId string

@description('Correlation monitoring source reader identity resource ID.')
param monitoringReaderIdentityResourceId string

@description('Correlation change-evidence source reader identity resource ID.')
param changeReaderIdentityResourceId string

@description('Correlation context-authority source reader identity resource ID.')
param contextAuthorityReaderIdentityResourceId string

@description('Correlation monitoring-intent source reader identity resource ID.')
param monitoringIntentReaderIdentityResourceId string

@description('Guidance-authority source reader identity resource ID.')
param guidanceAuthorityReaderIdentityResourceId string

@description('Report-only signing identity resource ID.')
param reportSignerIdentityResourceId string

@description('Guidance-only signing identity resource ID.')
param guidanceSignerIdentityResourceId string

@description('Enrichment-only signing identity resource ID.')
param enrichmentSignerIdentityResourceId string

@description('Feed-only signing identity resource ID.')
param feedSignerIdentityResourceId string

@description('Notification-only signing identity resource ID.')
param notificationSignerIdentityResourceId string

@description('Existing WC-013 replay storage account name that hosts the v1 incident-assets container and the v2 feed artifacts.')
param replayStorageAccountName string

@description('Existing v1 incident-assets container name. The producer receives read-only access here and never writes, deletes, or lists v1 lifecycle assets.')
@allowed([
  'incident-assets'
])
param incidentAssetContainerName string = 'incident-assets'

@description('Distinct private container that isolates WC-027 enrichment and feed-v2 artifacts.')
@minLength(3)
@maxLength(63)
param feedV2ContainerName string = 'wc027-enrichment-feed-v2'

@description('Private feed registry Table name.')
param feedRegistryTableName string = 'Wc027FeedRegistry'

@description('Feed registry partition key.')
@minLength(1)
@maxLength(256)
param feedRegistryPartitionKey string

@description('Guidance-authority activation Table name.')
param guidanceActivationTableName string = 'Wc027GuidanceActivation'

@description('Guidance-authority activation partition key.')
@minLength(1)
@maxLength(256)
param guidanceActivationPartitionKey string = 'wc027-guidance-authority'

@description('Existing storage account resource ID that hosts the correlation and guidance-authority evidence containers.')
param correlationSourceStorageAccountResourceId string

@description('Existing correlation monitoring evidence container name.')
param monitoringSourceContainerName string

@description('Existing correlation change-evidence container name.')
param changeSourceContainerName string

@description('Existing correlation context-authority container name.')
param contextAuthoritySourceContainerName string

@description('Existing correlation monitoring-intent container name.')
param monitoringIntentSourceContainerName string

@description('Existing guidance-authority evidence container name.')
param guidanceAuthoritySourceContainerName string

@description('Private presentation base URL.')
param presentationUrl string

@description('Existing WC-013 Key Vault name that holds the lifecycle and producer signing keys.')
param keyVaultName string

@description('Incident lifecycle signing key name.')
param incidentSigningKeyName string

@description('Report signing key name.')
param reportSigningKeyName string

@description('Guidance signing key name.')
param guidanceSigningKeyName string

@description('Enrichment signing key name.')
param enrichmentSigningKeyName string

@description('Feed signing key name.')
param feedSigningKeyName string

@description('Notification signing key name.')
param notificationSigningKeyName string

@description('Existing correlation-binding verification key ARM resource ID.')
param correlationBindingKeyResourceId string

@description('Existing guidance-binding verification key ARM resource ID.')
param guidanceBindingKeyResourceId string

@description('Stable logical key ID embedded in signed guidance bindings and activations.')
@minLength(1)
@maxLength(512)
param guidanceBindingLogicalKeyId string

@description('Existing change-evidence verification key ARM resource ID.')
param changeKeyResourceId string

@description('Existing monitoring-intent verification key ARM resource ID.')
param monitoringIntentKeyResourceId string

@description('Existing monitoring-collector verification key ARM resource ID.')
param monitoringCollectorKeyResourceId string

@description('Non-secret public-key fingerprints for every trust domain. Key IDs are derived from referenced versioned Key Vault resources.')
param trustDomainMetadata object

var runtimeTrustDomainFingerprints = [
  trustDomainMetadata.monitoringCollector.keyFingerprint
  trustDomainMetadata.change.keyFingerprint
  trustDomainMetadata.monitoringIntent.keyFingerprint
  trustDomainMetadata.incident.keyFingerprint
  trustDomainMetadata.correlationBinding.keyFingerprint
  trustDomainMetadata.guidanceBinding.keyFingerprint
  trustDomainMetadata.report.keyFingerprint
  trustDomainMetadata.guidance.keyFingerprint
  trustDomainMetadata.enrichment.keyFingerprint
  trustDomainMetadata.feed.keyFingerprint
  trustDomainMetadata.notification.keyFingerprint
]
var validatedTrustDomainMetadata = length(union(runtimeTrustDomainFingerprints, runtimeTrustDomainFingerprints)) == length(runtimeTrustDomainFingerprints)
  ? trustDomainMetadata
  : fail('WC-027 trust-domain public key fingerprints must be distinct')

@description('Reviewed non-secret monitoring collector contract object.')
param monitoringCollectorContract object

@description('Monitoring collector key activation timestamp.')
param monitoringCollectorKeyActivatedAt string

@description('Monitoring collector key expiry timestamp, or empty for none.')
param monitoringCollectorKeyExpiresAt string = ''

@description('Externally computed SHA-256 digest of the Bicep-generated runtimeConfigurationJson.')
@minLength(71)
@maxLength(71)
param runtimeConfigurationDigest string

@description('Resource tags.')
param tags object = {}

var jobNamePrefix = take(namePrefix, 18)
var triggerQueueName = 'wc027-enrichment-feed-requests'
var serviceBusDataReceiverRoleDefinitionId = '4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d'
var serviceBusDataSenderRoleDefinitionId = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var acrPullRoleDefinitionId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var storageBlobDataReaderRoleDefinitionId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var storageTableDataContributorRoleDefinitionId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var storageTableDataReaderRoleDefinitionId = '76199698-9eea-4c19-bc75-cec21354c6b6'

var expectedRegistryServer = '${toLower(registry.name)}.azurecr.io'
var imagePrefix = '${expectedRegistryServer}/athena/wc027-enrichment-feed-producer@sha256:'
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

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: last(split(registryResourceId, '/'))
  scope: resourceGroup(split(registryResourceId, '/')[2], split(registryResourceId, '/')[4])
}

resource brokerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(brokerIdentityResourceId, '/'))
  scope: resourceGroup(split(brokerIdentityResourceId, '/')[2], split(brokerIdentityResourceId, '/')[4])
}

resource incidentReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(incidentReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(incidentReaderIdentityResourceId, '/')[2], split(incidentReaderIdentityResourceId, '/')[4])
}

resource feedV2ProducerReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(feedV2ProducerReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(feedV2ProducerReaderIdentityResourceId, '/')[2], split(feedV2ProducerReaderIdentityResourceId, '/')[4])
}

resource feedV2WriterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(feedV2WriterIdentityResourceId, '/'))
  scope: resourceGroup(split(feedV2WriterIdentityResourceId, '/')[2], split(feedV2WriterIdentityResourceId, '/')[4])
}

resource feedV2ReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(feedV2ReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(feedV2ReaderIdentityResourceId, '/')[2], split(feedV2ReaderIdentityResourceId, '/')[4])
}

resource registryWriterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(registryWriterIdentityResourceId, '/'))
  scope: resourceGroup(split(registryWriterIdentityResourceId, '/')[2], split(registryWriterIdentityResourceId, '/')[4])
}

resource guidanceActivationReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(guidanceActivationReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(guidanceActivationReaderIdentityResourceId, '/')[2], split(guidanceActivationReaderIdentityResourceId, '/')[4])
}

resource trustReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(trustReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(trustReaderIdentityResourceId, '/')[2], split(trustReaderIdentityResourceId, '/')[4])
}

resource monitoringReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(monitoringReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(monitoringReaderIdentityResourceId, '/')[2], split(monitoringReaderIdentityResourceId, '/')[4])
}

resource changeReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(changeReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(changeReaderIdentityResourceId, '/')[2], split(changeReaderIdentityResourceId, '/')[4])
}

resource contextAuthorityReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(contextAuthorityReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(contextAuthorityReaderIdentityResourceId, '/')[2], split(contextAuthorityReaderIdentityResourceId, '/')[4])
}

resource monitoringIntentReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(monitoringIntentReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(monitoringIntentReaderIdentityResourceId, '/')[2], split(monitoringIntentReaderIdentityResourceId, '/')[4])
}

resource guidanceAuthorityReaderIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(guidanceAuthorityReaderIdentityResourceId, '/'))
  scope: resourceGroup(split(guidanceAuthorityReaderIdentityResourceId, '/')[2], split(guidanceAuthorityReaderIdentityResourceId, '/')[4])
}

resource reportSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(reportSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(reportSignerIdentityResourceId, '/')[2], split(reportSignerIdentityResourceId, '/')[4])
}

resource guidanceSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(guidanceSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(guidanceSignerIdentityResourceId, '/')[2], split(guidanceSignerIdentityResourceId, '/')[4])
}

resource enrichmentSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(enrichmentSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(enrichmentSignerIdentityResourceId, '/')[2], split(enrichmentSignerIdentityResourceId, '/')[4])
}

resource feedSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(feedSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(feedSignerIdentityResourceId, '/')[2], split(feedSignerIdentityResourceId, '/')[4])
}

resource notificationSignerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(notificationSignerIdentityResourceId, '/'))
  scope: resourceGroup(split(notificationSignerIdentityResourceId, '/')[2], split(notificationSignerIdentityResourceId, '/')[4])
}

resource triggerSubmitterIdentities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [for identityResourceId in triggerSubmitterIdentityResourceIds: {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}]

var attachedIdentityResourceIds = [
  brokerIdentity.id
  incidentReaderIdentity.id
  feedV2ProducerReaderIdentity.id
  feedV2WriterIdentity.id
  registryWriterIdentity.id
  guidanceActivationReaderIdentity.id
  trustReaderIdentity.id
  monitoringReaderIdentity.id
  changeReaderIdentity.id
  contextAuthorityReaderIdentity.id
  monitoringIntentReaderIdentity.id
  guidanceAuthorityReaderIdentity.id
  reportSignerIdentity.id
  guidanceSignerIdentity.id
  enrichmentSignerIdentity.id
  feedSignerIdentity.id
  notificationSignerIdentity.id
]

var validatedAttachedIdentityResourceIds = length(union(attachedIdentityResourceIds, attachedIdentityResourceIds)) == length(attachedIdentityResourceIds)
  ? attachedIdentityResourceIds
  : fail('WC-027 attached runtime identity resource IDs must be distinct')
var jobIdentityMap = reduce(
  validatedAttachedIdentityResourceIds,
  {},
  (current, identityResourceId) => union(current, {
    '${identityResourceId}': {}
  })
)

resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: serviceBusNamespaceName
}

var serviceBusNamespaceHostName = '${serviceBusNamespace.name}.servicebus.windows.net'

resource triggerQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: serviceBusNamespace
  name: triggerQueueName
  properties: {
    status: 'Active'
    autoDeleteOnIdle: 'P10675199DT2H48M5.4775807S'
    requiresSession: true
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P7D'
    enableBatchedOperations: true
    enableExpress: false
    enablePartitioning: false
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    lockDuration: 'PT5M'
    maxDeliveryCount: 10
    maxMessageSizeInKilobytes: 12288
    maxSizeInMegabytes: 1024
  }
}

resource notificationQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: serviceBusNamespace
  name: notificationQueueName
}

resource triggerReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(triggerQueue.id, brokerIdentity.id, serviceBusDataReceiverRoleDefinitionId)
  scope: triggerQueue
  properties: {
    principalId: brokerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      serviceBusDataReceiverRoleDefinitionId
    )
  }
}

resource triggerSubmitters 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (identityResourceId, index) in triggerSubmitterIdentityResourceIds: {
  name: guid(triggerQueue.id, identityResourceId, serviceBusDataSenderRoleDefinitionId)
  scope: triggerQueue
  properties: {
    principalId: triggerSubmitterIdentities[index].properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      serviceBusDataSenderRoleDefinitionId
    )
  }
}]

resource notificationSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationQueue.id, brokerIdentity.id, serviceBusDataSenderRoleDefinitionId)
  scope: notificationQueue
  properties: {
    principalId: brokerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      serviceBusDataSenderRoleDefinitionId
    )
  }
}

resource replayStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: replayStorageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: replayStorage
  name: 'default'
}

resource incidentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: blobService
  name: incidentAssetContainerName
}

resource feedV2Container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobService
  name: feedV2ContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' existing = {
  parent: replayStorage
  name: 'default'
}

resource feedRegistry 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  parent: tableService
  name: feedRegistryTableName
  properties: {}
}

resource guidanceActivation 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  parent: tableService
  name: guidanceActivationTableName
  properties: {}
}

resource correlationSourceStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: last(split(correlationSourceStorageAccountResourceId, '/'))
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
}

resource correlationSourceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: correlationSourceStorage
  name: 'default'
}

resource monitoringSourceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: correlationSourceBlobService
  name: monitoringSourceContainerName
}

resource changeSourceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: correlationSourceBlobService
  name: changeSourceContainerName
}

resource contextAuthoritySourceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: correlationSourceBlobService
  name: contextAuthoritySourceContainerName
}

resource monitoringIntentSourceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: correlationSourceBlobService
  name: monitoringIntentSourceContainerName
}

module guidanceAuthoritySourceContainer 'modules/private-container.bicep' = {
  name: 'wc027-guidance-authority-source-container'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: guidanceAuthoritySourceContainerName
  }
}
var guidanceAuthoritySourceContainerId = '${correlationSourceStorageAccountResourceId}/blobServices/default/containers/${guidanceAuthoritySourceContainerName}'

resource feedV2WriterRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(replayStorage.id, feedV2ContainerName, 'wc027-feed-v2-writer')
  properties: {
    roleName: 'Athena WC027 Feed v2 Blob Writer (${replayStorageAccountName}/${feedV2ContainerName})'
    description: 'Create, read, and write WC-027 enrichment and feed-v2 blobs for create-or-recover and feed index CAS. No blob or container delete and no container list.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        ]
        notDataActions: []
      }
    ]
  }
}

module monitoringSourceReader 'modules/blob-reader-rbac.bicep' = {
  name: 'wc027-monitoring-source-reader'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: monitoringSourceContainer.name
    identityResourceId: monitoringReaderIdentity.id
  }
}

module changeSourceReader 'modules/blob-reader-rbac.bicep' = {
  name: 'wc027-change-source-reader'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: changeSourceContainer.name
    identityResourceId: changeReaderIdentity.id
  }
}

module contextAuthoritySourceReader 'modules/blob-reader-rbac.bicep' = {
  name: 'wc027-context-authority-source-reader'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: contextAuthoritySourceContainer.name
    identityResourceId: contextAuthorityReaderIdentity.id
  }
}

module monitoringIntentSourceReader 'modules/blob-reader-rbac.bicep' = {
  name: 'wc027-monitoring-intent-source-reader'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: monitoringIntentSourceContainer.name
    identityResourceId: monitoringIntentReaderIdentity.id
  }
}

module guidanceAuthoritySourceReader 'modules/blob-reader-rbac.bicep' = {
  name: 'wc027-guidance-authority-source-reader'
  scope: resourceGroup(split(correlationSourceStorageAccountResourceId, '/')[2], split(correlationSourceStorageAccountResourceId, '/')[4])
  params: {
    storageAccountName: correlationSourceStorage.name
    containerName: guidanceAuthoritySourceContainer.outputs.name
    identityResourceId: guidanceAuthorityReaderIdentity.id
  }
}

resource incidentReaderV1 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(incidentContainer.id, incidentReaderIdentity.id, storageBlobDataReaderRoleDefinitionId)
  scope: incidentContainer
  properties: {
    principalId: incidentReaderIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
    conditionVersion: '2.0'
    condition: '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'
  }
}

resource feedV2Writer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedV2Container.id, feedV2WriterIdentity.id, feedV2WriterRole.id)
  scope: feedV2Container
  properties: {
    principalId: feedV2WriterIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: feedV2WriterRole.id
    conditionVersion: '2.0'
    condition: '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'
  }
}

resource feedV2ProducerReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedV2Container.id, feedV2ProducerReaderIdentity.id, storageBlobDataReaderRoleDefinitionId)
  scope: feedV2Container
  properties: {
    principalId: feedV2ProducerReaderIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
    conditionVersion: '2.0'
    condition: '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'
  }
}

resource feedV2PresentationReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedV2Container.id, feedV2ReaderIdentity.id, storageBlobDataReaderRoleDefinitionId)
  scope: feedV2Container
  properties: {
    principalId: feedV2ReaderIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
    conditionVersion: '2.0'
    condition: '(!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'} AND SubOperationMatches{\'Blob.List\'}))'
  }
}

resource registryWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedRegistry.id, registryWriterIdentity.id, storageTableDataContributorRoleDefinitionId)
  scope: feedRegistry
  properties: {
    principalId: registryWriterIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageTableDataContributorRoleDefinitionId
    )
  }
}

resource guidanceActivationReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(guidanceActivation.id, guidanceActivationReaderIdentity.id, storageTableDataReaderRoleDefinitionId)
  scope: guidanceActivation
  properties: {
    principalId: guidanceActivationReaderIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageTableDataReaderRoleDefinitionId
    )
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource incidentKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: incidentSigningKeyName
}

resource reportKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: reportSigningKeyName
}

resource guidanceKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: guidanceSigningKeyName
}

resource enrichmentKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: enrichmentSigningKeyName
}

resource feedKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: feedSigningKeyName
}

resource notificationKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: notificationSigningKeyName
}

resource correlationBindingVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(correlationBindingKeyResourceId, '/')[8]
  scope: resourceGroup(split(correlationBindingKeyResourceId, '/')[2], split(correlationBindingKeyResourceId, '/')[4])
}

resource correlationBindingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: correlationBindingVault
  name: split(correlationBindingKeyResourceId, '/')[10]
}

resource guidanceBindingVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(guidanceBindingKeyResourceId, '/')[8]
  scope: resourceGroup(split(guidanceBindingKeyResourceId, '/')[2], split(guidanceBindingKeyResourceId, '/')[4])
}

resource guidanceBindingKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: guidanceBindingVault
  name: split(guidanceBindingKeyResourceId, '/')[10]
}

resource changeVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(changeKeyResourceId, '/')[8]
  scope: resourceGroup(split(changeKeyResourceId, '/')[2], split(changeKeyResourceId, '/')[4])
}

resource changeKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: changeVault
  name: split(changeKeyResourceId, '/')[10]
}

resource monitoringIntentVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(monitoringIntentKeyResourceId, '/')[8]
  scope: resourceGroup(split(monitoringIntentKeyResourceId, '/')[2], split(monitoringIntentKeyResourceId, '/')[4])
}

resource monitoringIntentKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: monitoringIntentVault
  name: split(monitoringIntentKeyResourceId, '/')[10]
}

resource monitoringCollectorVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: split(monitoringCollectorKeyResourceId, '/')[8]
  scope: resourceGroup(split(monitoringCollectorKeyResourceId, '/')[2], split(monitoringCollectorKeyResourceId, '/')[4])
}

resource monitoringCollectorKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: monitoringCollectorVault
  name: split(monitoringCollectorKeyResourceId, '/')[10]
}

module incidentKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-incident-key-verifier'
  params: {
    keyVaultName: keyVault.name
    keyName: incidentKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module correlationBindingKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-correlation-binding-key-verifier'
  scope: resourceGroup(split(correlationBindingKeyResourceId, '/')[2], split(correlationBindingKeyResourceId, '/')[4])
  params: {
    keyVaultName: correlationBindingVault.name
    keyName: correlationBindingKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module guidanceBindingKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-guidance-binding-key-verifier'
  scope: resourceGroup(split(guidanceBindingKeyResourceId, '/')[2], split(guidanceBindingKeyResourceId, '/')[4])
  params: {
    keyVaultName: guidanceBindingVault.name
    keyName: guidanceBindingKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module changeKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-change-key-verifier'
  scope: resourceGroup(split(changeKeyResourceId, '/')[2], split(changeKeyResourceId, '/')[4])
  params: {
    keyVaultName: changeVault.name
    keyName: changeKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module monitoringIntentKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-monitoring-intent-key-verifier'
  scope: resourceGroup(split(monitoringIntentKeyResourceId, '/')[2], split(monitoringIntentKeyResourceId, '/')[4])
  params: {
    keyVaultName: monitoringIntentVault.name
    keyName: monitoringIntentKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module monitoringCollectorKeyVerifier 'modules/key-verifier-rbac.bicep' = {
  name: 'wc027-monitoring-collector-key-verifier'
  scope: resourceGroup(split(monitoringCollectorKeyResourceId, '/')[2], split(monitoringCollectorKeyResourceId, '/')[4])
  params: {
    keyVaultName: monitoringCollectorVault.name
    keyName: monitoringCollectorKey.name
    identityResourceId: trustReaderIdentity.id
  }
}

module reportSignerRbac 'modules/key-sign-verify-rbac.bicep' = {
  name: 'wc027-report-key-sign-verify'
  params: {
    keyVaultName: keyVault.name
    keyName: reportKey.name
    identityResourceId: reportSignerIdentity.id
  }
}

module guidanceSignerRbac 'modules/key-sign-verify-rbac.bicep' = {
  name: 'wc027-guidance-key-sign-verify'
  params: {
    keyVaultName: keyVault.name
    keyName: guidanceKey.name
    identityResourceId: guidanceSignerIdentity.id
  }
}

module enrichmentSignerRbac 'modules/key-sign-verify-rbac.bicep' = {
  name: 'wc027-enrichment-key-sign-verify'
  params: {
    keyVaultName: keyVault.name
    keyName: enrichmentKey.name
    identityResourceId: enrichmentSignerIdentity.id
  }
}

module feedSignerRbac 'modules/key-sign-verify-rbac.bicep' = {
  name: 'wc027-feed-key-sign-verify'
  params: {
    keyVaultName: keyVault.name
    keyName: feedKey.name
    identityResourceId: feedSignerIdentity.id
  }
}

module notificationSignerRbac 'modules/key-sign-verify-rbac.bicep' = {
  name: 'wc027-notification-key-sign-verify'
  params: {
    keyVaultName: keyVault.name
    keyName: notificationKey.name
    identityResourceId: notificationSignerIdentity.id
  }
}

module producerImagePull 'modules/acr-pull-rbac.bicep' = {
  name: 'wc027-producer-image-pull'
  scope: resourceGroup(
    split(registryResourceId, '/')[2],
    split(registryResourceId, '/')[4]
  )
  params: {
    registryName: registry.name
    identityResourceId: brokerIdentity.id
  }
}

var correlationSourceBlobEndpoint = correlationSourceStorage.properties.primaryEndpoints.blob
var runtimeConfiguration = {
  schemaVersion: 'athena.wc027EnrichmentFeedRuntimeConfiguration.v1'
  serviceBus: {
    namespace: serviceBusNamespaceHostName
    triggerQueueName: triggerQueue.name
    notificationQueueName: notificationQueue.name
    brokerIdentityClientId: brokerIdentity.properties.clientId
    brokerIdentityResourceId: brokerIdentity.id
  }
  incidentLifecycleAssets: {
    blobEndpoint: replayStorage.properties.primaryEndpoints.blob
    containerName: incidentContainer.name
    identityClientId: incidentReaderIdentity.properties.clientId
    identityResourceId: incidentReaderIdentity.id
  }
  enrichmentFeedAssets: {
    blobEndpoint: replayStorage.properties.primaryEndpoints.blob
    containerName: feedV2Container.name
    readerIdentityClientId: feedV2ProducerReaderIdentity.properties.clientId
    readerIdentityResourceId: feedV2ProducerReaderIdentity.id
    writerIdentityClientId: feedV2WriterIdentity.properties.clientId
    writerIdentityResourceId: feedV2WriterIdentity.id
  }
  feedRegistry: {
    tableEndpoint: replayStorage.properties.primaryEndpoints.table
    tableName: feedRegistry.name
    partitionKey: feedRegistryPartitionKey
    identityClientId: registryWriterIdentity.properties.clientId
    identityResourceId: registryWriterIdentity.id
  }
  guidanceActivation: {
    tableEndpoint: replayStorage.properties.primaryEndpoints.table
    tableName: guidanceActivation.name
    partitionKey: guidanceActivationPartitionKey
    identityClientId: guidanceActivationReaderIdentity.properties.clientId
    identityResourceId: guidanceActivationReaderIdentity.id
  }
  deploymentBinding: {
    bindingEvidenceId: bindingEvidenceDigest
    attachedIdentityResourceIds: validatedAttachedIdentityResourceIds
    rbacResourceIds: rbacResourceIds
  }
  presentationUrl: presentationUrl
  correlationSources: {
    monitoring: {
      blobEndpoint: correlationSourceBlobEndpoint
      containerName: monitoringSourceContainer.name
      identityClientId: monitoringReaderIdentity.properties.clientId
      identityResourceId: monitoringReaderIdentity.id
    }
    change: {
      blobEndpoint: correlationSourceBlobEndpoint
      containerName: changeSourceContainer.name
      identityClientId: changeReaderIdentity.properties.clientId
      identityResourceId: changeReaderIdentity.id
    }
    contextAuthority: {
      blobEndpoint: correlationSourceBlobEndpoint
      containerName: contextAuthoritySourceContainer.name
      identityClientId: contextAuthorityReaderIdentity.properties.clientId
      identityResourceId: contextAuthorityReaderIdentity.id
    }
    monitoringIntent: {
      blobEndpoint: correlationSourceBlobEndpoint
      containerName: monitoringIntentSourceContainer.name
      identityClientId: monitoringIntentReaderIdentity.properties.clientId
      identityResourceId: monitoringIntentReaderIdentity.id
    }
  }
  guidanceAuthoritySource: {
    blobEndpoint: correlationSourceBlobEndpoint
    containerName: guidanceAuthoritySourceContainer.outputs.name
    identityClientId: guidanceAuthorityReaderIdentity.properties.clientId
    identityResourceId: guidanceAuthorityReaderIdentity.id
  }
  monitoringCollectorContract: monitoringCollectorContract
  monitoringCollectorKey: {
    keyId: monitoringCollectorKey.properties.keyUriWithVersion
    keyVaultKeyId: monitoringCollectorKey.properties.keyUriWithVersion
    keyFingerprint: validatedTrustDomainMetadata.monitoringCollector.keyFingerprint
    identityClientId: trustReaderIdentity.properties.clientId
    identityResourceId: trustReaderIdentity.id
    activatedAt: monitoringCollectorKeyActivatedAt
    expiresAt: empty(monitoringCollectorKeyExpiresAt) ? null : monitoringCollectorKeyExpiresAt
  }
  keys: {
    incident: {
      keyId: 'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'
      keyVaultKeyId: incidentKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.incident.keyFingerprint
      identityClientId: trustReaderIdentity.properties.clientId
      identityResourceId: trustReaderIdentity.id
    }
    correlationBinding: {
      keyId: correlationBindingKey.properties.keyUriWithVersion
      keyVaultKeyId: correlationBindingKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.correlationBinding.keyFingerprint
      identityClientId: trustReaderIdentity.properties.clientId
      identityResourceId: trustReaderIdentity.id
    }
    guidanceBinding: {
      keyId: guidanceBindingLogicalKeyId
      keyVaultKeyId: guidanceBindingKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.guidanceBinding.keyFingerprint
      identityClientId: trustReaderIdentity.properties.clientId
      identityResourceId: trustReaderIdentity.id
    }
    change: {
      keyId: changeKey.properties.keyUriWithVersion
      keyVaultKeyId: changeKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.change.keyFingerprint
      identityClientId: trustReaderIdentity.properties.clientId
      identityResourceId: trustReaderIdentity.id
    }
    monitoringIntent: {
      keyId: monitoringIntentKey.properties.keyUriWithVersion
      keyVaultKeyId: monitoringIntentKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.monitoringIntent.keyFingerprint
      identityClientId: trustReaderIdentity.properties.clientId
      identityResourceId: trustReaderIdentity.id
    }
    report: {
      keyId: reportKey.properties.keyUriWithVersion
      keyVaultKeyId: reportKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.report.keyFingerprint
      identityClientId: reportSignerIdentity.properties.clientId
      identityResourceId: reportSignerIdentity.id
    }
    guidance: {
      keyId: guidanceKey.properties.keyUriWithVersion
      keyVaultKeyId: guidanceKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.guidance.keyFingerprint
      identityClientId: guidanceSignerIdentity.properties.clientId
      identityResourceId: guidanceSignerIdentity.id
    }
    enrichment: {
      keyId: enrichmentKey.properties.keyUriWithVersion
      keyVaultKeyId: enrichmentKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.enrichment.keyFingerprint
      identityClientId: enrichmentSignerIdentity.properties.clientId
      identityResourceId: enrichmentSignerIdentity.id
    }
    feed: {
      keyId: feedKey.properties.keyUriWithVersion
      keyVaultKeyId: feedKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.feed.keyFingerprint
      identityClientId: feedSignerIdentity.properties.clientId
      identityResourceId: feedSignerIdentity.id
    }
    notification: {
      keyId: notificationKey.properties.keyUriWithVersion
      keyVaultKeyId: notificationKey.properties.keyUriWithVersion
      keyFingerprint: validatedTrustDomainMetadata.notification.keyFingerprint
      identityClientId: notificationSignerIdentity.properties.clientId
      identityResourceId: notificationSignerIdentity.id
    }
  }
}
var runtimeConfigurationJson = string(runtimeConfiguration)

var incidentKeyVerifierRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(incidentKey.id, 'athena-wc027-key-verifier'))
var correlationBindingKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(correlationBindingKeyResourceId, '/')[2]}/resourceGroups/${split(correlationBindingKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(correlationBindingKey.id, 'athena-wc027-key-verifier'))
var guidanceBindingKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(guidanceBindingKeyResourceId, '/')[2]}/resourceGroups/${split(guidanceBindingKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(guidanceBindingKey.id, 'athena-wc027-key-verifier'))
var changeKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(changeKeyResourceId, '/')[2]}/resourceGroups/${split(changeKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(changeKey.id, 'athena-wc027-key-verifier'))
var monitoringIntentKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(monitoringIntentKeyResourceId, '/')[2]}/resourceGroups/${split(monitoringIntentKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(monitoringIntentKey.id, 'athena-wc027-key-verifier'))
var monitoringCollectorKeyVerifierRoleId = extensionResourceId('/subscriptions/${split(monitoringCollectorKeyResourceId, '/')[2]}/resourceGroups/${split(monitoringCollectorKeyResourceId, '/')[4]}', 'Microsoft.Authorization/roleDefinitions', guid(monitoringCollectorKey.id, 'athena-wc027-key-verifier'))
var reportSignerRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(reportKey.id, 'athena-wc027-key-sign-verify'))
var reportSignerAssignmentId = extensionResourceId(reportKey.id, 'Microsoft.Authorization/roleAssignments', guid(reportKey.id, reportSignerIdentity.id, reportSignerRoleId))
var guidanceSignerRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(guidanceKey.id, 'athena-wc027-key-sign-verify'))
var guidanceSignerAssignmentId = extensionResourceId(guidanceKey.id, 'Microsoft.Authorization/roleAssignments', guid(guidanceKey.id, guidanceSignerIdentity.id, guidanceSignerRoleId))
var enrichmentSignerRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(enrichmentKey.id, 'athena-wc027-key-sign-verify'))
var enrichmentSignerAssignmentId = extensionResourceId(enrichmentKey.id, 'Microsoft.Authorization/roleAssignments', guid(enrichmentKey.id, enrichmentSignerIdentity.id, enrichmentSignerRoleId))
var feedSignerRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(feedKey.id, 'athena-wc027-key-sign-verify'))
var feedSignerAssignmentId = extensionResourceId(feedKey.id, 'Microsoft.Authorization/roleAssignments', guid(feedKey.id, feedSignerIdentity.id, feedSignerRoleId))
var notificationSignerRoleId = extensionResourceId(resourceGroup().id, 'Microsoft.Authorization/roleDefinitions', guid(notificationKey.id, 'athena-wc027-key-sign-verify'))
var notificationSignerAssignmentId = extensionResourceId(notificationKey.id, 'Microsoft.Authorization/roleAssignments', guid(notificationKey.id, notificationSignerIdentity.id, notificationSignerRoleId))

var coreRbacResourceIds = [
  triggerReceiver.id
  notificationSender.id
  extensionResourceId(registry.id, 'Microsoft.Authorization/roleAssignments', guid(registry.id, brokerIdentity.id, acrPullRoleDefinitionId))
  feedV2WriterRole.id
  feedV2Writer.id
  feedV2ProducerReader.id
  feedV2PresentationReader.id
  incidentReaderV1.id
  extensionResourceId(monitoringSourceContainer.id, 'Microsoft.Authorization/roleAssignments', guid(monitoringSourceContainer.id, monitoringReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  extensionResourceId(changeSourceContainer.id, 'Microsoft.Authorization/roleAssignments', guid(changeSourceContainer.id, changeReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  extensionResourceId(contextAuthoritySourceContainer.id, 'Microsoft.Authorization/roleAssignments', guid(contextAuthoritySourceContainer.id, contextAuthorityReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  extensionResourceId(monitoringIntentSourceContainer.id, 'Microsoft.Authorization/roleAssignments', guid(monitoringIntentSourceContainer.id, monitoringIntentReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  extensionResourceId(guidanceAuthoritySourceContainerId, 'Microsoft.Authorization/roleAssignments', guid(guidanceAuthoritySourceContainerId, guidanceAuthorityReaderIdentity.id, storageBlobDataReaderRoleDefinitionId))
  registryWriter.id
  guidanceActivationReader.id
  incidentKeyVerifierRoleId
  extensionResourceId(incidentKey.id, 'Microsoft.Authorization/roleAssignments', guid(incidentKey.id, trustReaderIdentity.id, incidentKeyVerifierRoleId))
  correlationBindingKeyVerifierRoleId
  extensionResourceId(correlationBindingKey.id, 'Microsoft.Authorization/roleAssignments', guid(correlationBindingKey.id, trustReaderIdentity.id, correlationBindingKeyVerifierRoleId))
  guidanceBindingKeyVerifierRoleId
  extensionResourceId(guidanceBindingKey.id, 'Microsoft.Authorization/roleAssignments', guid(guidanceBindingKey.id, trustReaderIdentity.id, guidanceBindingKeyVerifierRoleId))
  changeKeyVerifierRoleId
  extensionResourceId(changeKey.id, 'Microsoft.Authorization/roleAssignments', guid(changeKey.id, trustReaderIdentity.id, changeKeyVerifierRoleId))
  monitoringIntentKeyVerifierRoleId
  extensionResourceId(monitoringIntentKey.id, 'Microsoft.Authorization/roleAssignments', guid(monitoringIntentKey.id, trustReaderIdentity.id, monitoringIntentKeyVerifierRoleId))
  monitoringCollectorKeyVerifierRoleId
  extensionResourceId(monitoringCollectorKey.id, 'Microsoft.Authorization/roleAssignments', guid(monitoringCollectorKey.id, trustReaderIdentity.id, monitoringCollectorKeyVerifierRoleId))
  reportSignerRoleId
  reportSignerAssignmentId
  guidanceSignerRoleId
  guidanceSignerAssignmentId
  enrichmentSignerRoleId
  enrichmentSignerAssignmentId
  feedSignerRoleId
  feedSignerAssignmentId
  notificationSignerRoleId
  notificationSignerAssignmentId
]
var triggerSubmitterRbacResourceIds = map(
  triggerSubmitterIdentityResourceIds,
  identityResourceId => extensionResourceId(triggerQueue.id, 'Microsoft.Authorization/roleAssignments', guid(triggerQueue.id, identityResourceId, serviceBusDataSenderRoleDefinitionId))
)
var rbacResourceIds = concat(coreRbacResourceIds, triggerSubmitterRbacResourceIds)
var bindingEvidenceDigest = guid(join(rbacResourceIds, '|'))

var resourceTags = union(tags, {
  component: 'wc027-enrichment-feed-runtime'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  runtimeConfigurationDigest: runtimeConfigurationDigest
  bindingEvidenceDigest: bindingEvidenceDigest
  attachedIdentityCount: string(length(validatedAttachedIdentityResourceIds))
})

resource producerJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-w27-enrich-v2'
  location: location
  tags: resourceTags
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
              name: 'wc027-signed-binding'
              type: 'azure-servicebus'
              identity: brokerIdentity.id
              metadata: {
                namespace: serviceBusNamespaceName
                queueName: triggerQueueName
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
          name: 'wc027-enrichment-feed-producer'
          image: validatedProducerImage
          command: [
            'athena-context'
          ]
          args: [
            'wc027-enrichment-feed-producer'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: brokerIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON'
              value: runtimeConfigurationJson
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
    producerImagePull
    reportSignerRbac
    guidanceSignerRbac
    enrichmentSignerRbac
    feedSignerRbac
    notificationSignerRbac
    triggerSubmitters
  ]
}

@description('Resource ID proving that the WC-027 producer Job/config was deployed.')
output producerJobResourceId string = producerJob.id

@description('Exact digest-pinned image deployed to the WC-027 producer Job.')
output producerImage string = validatedProducerImage

@description('Digest of the exact non-secret runtime configuration deployed to the Job.')
output deployedRuntimeConfigurationDigest string = startsWith(runtimeConfigurationDigest, 'sha256:')
  ? runtimeConfigurationDigest
  : fail('runtimeConfigurationDigest must be a SHA-256 digest')

@description('Exact non-secret runtime configuration JSON generated in Bicep and deployed to the Job.')
output deployedRuntimeConfigurationJson string = runtimeConfigurationJson

@description('Exact user-assigned identity resource IDs attached to the Job.')
output attachedIdentityResourceIds array = validatedAttachedIdentityResourceIds

@description('Deterministic evidence digest of the RBAC bindings generated by this deployment.')
output bindingEvidenceDigest string = bindingEvidenceDigest

@description('Custom least-privilege v2 blob writer role definition ID.')
output feedV2WriterRoleDefinitionId string = feedV2WriterRole.id

@description('Distinct private container isolating WC-027 enrichment and feed-v2 artifacts.')
output feedV2ContainerName string = feedV2Container.name

@description('Exact resource ID of the private WC-027 enrichment and feed-v2 container.')
output feedV2ContainerResourceId string = feedV2Container.id

@description('Exact resource ID of the WC-027 feed registry table.')
output feedRegistryTableResourceId string = feedRegistry.id

@description('Exact resource ID of the shared WC-027 guidance activation table.')
output guidanceActivationTableResourceId string = guidanceActivation.id

@description('Exact resource ID of the private WC-027 guidance-authority source container.')
output guidanceAuthoritySourceContainerResourceId string = guidanceAuthoritySourceContainerId

@description('Signed-binding trigger queue name.')
output triggerQueueName string = triggerQueue.name

@description('Exact resource ID of the signed-binding trigger queue.')
output triggerQueueResourceId string = triggerQueue.id

@description('Existing Notification v2 outbox queue name used by the producer.')
output notificationQueueName string = notificationQueue.name

@description('Exact resource ID of the existing Notification v2 outbox queue.')
output notificationQueueResourceId string = notificationQueue.id

@description('Private Service Bus namespace host used by the runtime configuration.')
output namespaceHostName string = serviceBusNamespaceHostName
