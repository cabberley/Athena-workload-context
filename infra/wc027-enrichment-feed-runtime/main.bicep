targetScope = 'resourceGroup'

metadata name = 'WC-027 enrichment and feed-v2 producer runtime'
metadata description = 'Deploys the private Service Bus-triggered producer that publishes enrichment, feed-v2, and only then Notification v2.'

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

@description('Existing private Service Bus namespace host name.')
param serviceBusNamespaceHostName string

@description('Existing Notification v2 outbox queue name.')
param notificationQueueName string

@description('Exact non-secret runtime configuration JSON.')
param runtimeConfigurationJson string

@description('Externally computed SHA-256 digest of runtimeConfigurationJson.')
@minLength(71)
@maxLength(71)
param runtimeConfigurationDigest string

@description('Broker identity resource ID attached to the Job and used by the scaler.')
param brokerIdentityResourceId string

@description('Broker identity client ID.')
param brokerIdentityClientId string

@description('Broker identity principal ID.')
param brokerIdentityPrincipalId string

@description('Exact governed caller principal IDs allowed to submit signed guidance bindings.')
@minLength(1)
@maxLength(8)
param triggerSubmitterPrincipalIds array

@description('All additional narrowly scoped reader, writer, registry, trust, and signer identity resource IDs attached to the Job.')
@minLength(12)
@maxLength(16)
param runtimeIdentityResourceIds array

@description('Client IDs matching runtimeIdentityResourceIds. Do not include the broker identity.')
@minLength(12)
@maxLength(16)
param runtimeIdentityClientIds array

@description('Existing WC-013 replay storage account name.')
param replayStorageAccountName string

@description('Incident-assets container name.')
@allowed([
  'incident-assets'
])
param incidentAssetContainerName string = 'incident-assets'

@description('Private feed registry Table name.')
param feedRegistryTableName string = 'Wc027FeedRegistry'

@description('Incident asset reader principal ID.')
param incidentReaderPrincipalId string

@description('Incident enrichment/feed writer principal ID.')
param incidentWriterPrincipalId string

@description('Feed registry writer principal ID.')
param registryWriterPrincipalId string

@description('Key Vault public-key reader principal ID.')
param trustReaderPrincipalId string

@description('Existing WC-013 Key Vault name.')
param keyVaultName string

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

@description('Principal ID for the report-only signing identity.')
param reportSignerPrincipalId string

@description('Principal ID for the guidance-only signing identity.')
param guidanceSignerPrincipalId string

@description('Principal ID for the enrichment-only signing identity.')
param enrichmentSignerPrincipalId string

@description('Principal ID for the feed-only signing identity.')
param feedSignerPrincipalId string

@description('Principal ID for the notification-only signing identity.')
param notificationSignerPrincipalId string

@description('Resource tags.')
param tags object = {}

var jobNamePrefix = take(namePrefix, 18)
var triggerQueueName = 'wc027-enrichment-feed-requests'
var serviceBusDataReceiverRoleDefinitionId = '4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d'
var serviceBusDataSenderRoleDefinitionId = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var storageBlobDataReaderRoleDefinitionId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var storageBlobDataContributorRoleDefinitionId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var storageTableDataContributorRoleDefinitionId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var keyVaultReaderRoleDefinitionId = '21090545-7ca7-4776-b22c-e363652d74d2'
var keyVaultCryptoUserRoleDefinitionId = '12338af0-0e69-4776-bea7-57ae8d297424'
var expectedRegistryServer = '${toLower(last(split(registryResourceId, '/')))}.azurecr.io'
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
var parsedRuntimeConfiguration = json(runtimeConfigurationJson)
var validatedRuntimeConfigurationJson = parsedRuntimeConfiguration.schemaVersion == 'athena.wc027EnrichmentFeedRuntimeConfiguration.v1' && parsedRuntimeConfiguration.serviceBus.namespace == serviceBusNamespaceHostName && parsedRuntimeConfiguration.serviceBus.triggerQueueName == triggerQueueName && parsedRuntimeConfiguration.serviceBus.notificationQueueName == notificationQueueName && parsedRuntimeConfiguration.serviceBus.brokerIdentityClientId == brokerIdentityClientId && parsedRuntimeConfiguration.incidentAssets.containerName == incidentAssetContainerName && parsedRuntimeConfiguration.feedRegistry.tableName == feedRegistryTableName
  ? runtimeConfigurationJson
  : fail('runtimeConfigurationJson does not match the deployed queue, identity, container, or registry resources')
var expectedIdentityClientIds = concat([
  brokerIdentityClientId
], runtimeIdentityClientIds)
var validatedRuntimeIdentityResourceIds = length(
  union(runtimeIdentityResourceIds, runtimeIdentityResourceIds)
) == length(runtimeIdentityResourceIds) && length(
  union(expectedIdentityClientIds, expectedIdentityClientIds)
) == length(expectedIdentityClientIds)
  ? runtimeIdentityResourceIds
  : fail('WC-027 runtime identities and client IDs must be distinct')
var jobIdentityMap = reduce(
  union([
    brokerIdentityResourceId
  ], validatedRuntimeIdentityResourceIds),
  {},
  (current, identityResourceId) => union(current, {
    '${identityResourceId}': {}
  })
)
var resourceTags = union(tags, {
  component: 'wc027-enrichment-feed-runtime'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  runtimeConfigurationDigest: runtimeConfigurationDigest
})

resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: serviceBusNamespaceName
}

resource triggerQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: serviceBusNamespace
  name: triggerQueueName
  properties: {
    requiresSession: true
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P7D'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    lockDuration: 'PT5M'
    maxDeliveryCount: 10
    maxMessageSizeInKilobytes: 12288
  }
}

resource notificationQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: serviceBusNamespace
  name: notificationQueueName
}

resource triggerReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(triggerQueue.id, brokerIdentityPrincipalId, serviceBusDataReceiverRoleDefinitionId)
  scope: triggerQueue
  properties: {
    principalId: brokerIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      serviceBusDataReceiverRoleDefinitionId
    )
  }
}

resource triggerSubmitters 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principalId in triggerSubmitterPrincipalIds: {
  name: guid(triggerQueue.id, principalId, serviceBusDataSenderRoleDefinitionId)
  scope: triggerQueue
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      serviceBusDataSenderRoleDefinitionId
    )
  }
}]

resource notificationSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationQueue.id, brokerIdentityPrincipalId, serviceBusDataSenderRoleDefinitionId)
  scope: notificationQueue
  properties: {
    principalId: brokerIdentityPrincipalId
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

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' existing = {
  parent: replayStorage
  name: 'default'
}

resource feedRegistry 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  parent: tableService
  name: feedRegistryTableName
  properties: {}
}

resource incidentReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(incidentContainer.id, incidentReaderPrincipalId, storageBlobDataReaderRoleDefinitionId)
  scope: incidentContainer
  properties: {
    principalId: incidentReaderPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
  }
}

resource incidentWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(incidentContainer.id, incidentWriterPrincipalId, storageBlobDataContributorRoleDefinitionId)
  scope: incidentContainer
  properties: {
    principalId: incidentWriterPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataContributorRoleDefinitionId
    )
  }
}

resource registryWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedRegistry.id, registryWriterPrincipalId, storageTableDataContributorRoleDefinitionId)
  scope: feedRegistry
  properties: {
    principalId: registryWriterPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageTableDataContributorRoleDefinitionId
    )
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
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

resource trustKeyReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, trustReaderPrincipalId, keyVaultReaderRoleDefinitionId)
  scope: keyVault
  properties: {
    principalId: trustReaderPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultReaderRoleDefinitionId
    )
  }
}

resource reportSignerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reportKey.id, reportSignerPrincipalId, keyVaultCryptoUserRoleDefinitionId)
  scope: reportKey
  properties: {
    principalId: reportSignerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

resource guidanceSignerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(guidanceKey.id, guidanceSignerPrincipalId, keyVaultCryptoUserRoleDefinitionId)
  scope: guidanceKey
  properties: {
    principalId: guidanceSignerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

resource enrichmentSignerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(enrichmentKey.id, enrichmentSignerPrincipalId, keyVaultCryptoUserRoleDefinitionId)
  scope: enrichmentKey
  properties: {
    principalId: enrichmentSignerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

resource feedSignerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(feedKey.id, feedSignerPrincipalId, keyVaultCryptoUserRoleDefinitionId)
  scope: feedKey
  properties: {
    principalId: feedSignerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

resource notificationSignerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationKey.id, notificationSignerPrincipalId, keyVaultCryptoUserRoleDefinitionId)
  scope: notificationKey
  properties: {
    principalId: notificationSignerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

module producerImagePull '../wc013-live-acceptance/modules/acr-pull-rbac.bicep' = {
  name: 'wc027-producer-image-pull'
  scope: resourceGroup(
    split(registryResourceId, '/')[2],
    split(registryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(registryResourceId, '/'))
    identityName: last(split(brokerIdentityResourceId, '/'))
    identityPrincipalId: brokerIdentityPrincipalId
  }
}

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
              identity: brokerIdentityResourceId
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
          identity: brokerIdentityResourceId
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
              value: brokerIdentityClientId
            }
            {
              name: 'ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON'
              value: validatedRuntimeConfigurationJson
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
    triggerReceiver
    triggerSubmitters
    notificationSender
    incidentReader
    incidentWriter
    registryWriter
    trustKeyReader
    reportSignerRole
    guidanceSignerRole
    enrichmentSignerRole
    feedSignerRole
    notificationSignerRole
  ]
}

@description('Resource ID proving that the WC-027 producer Job/config was deployed.')
output producerJobResourceId string = producerJob.id

@description('Digest of the exact non-secret runtime configuration deployed to the Job.')
output deployedRuntimeConfigurationDigest string = startsWith(runtimeConfigurationDigest, 'sha256:')
  ? runtimeConfigurationDigest
  : fail('runtimeConfigurationDigest must be a SHA-256 digest')

@description('Signed-binding trigger queue name.')
output triggerQueueName string = triggerQueue.name

@description('Private Service Bus namespace host used by the runtime configuration.')
output namespaceHostName string = serviceBusNamespaceHostName
