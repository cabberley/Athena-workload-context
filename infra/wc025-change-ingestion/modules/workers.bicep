targetScope = 'resourceGroup'

@description('Azure region for private WC-025 workers.')
param location string

@description('Tags inherited from WC-025 root orchestration.')
param resourceTags object

@description('Existing internal Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Existing ACR name containing the digest-pinned WC-025 worker image.')
param registryName string

@description('Existing ACR login server.')
param registryServer string

@description('Digest-pinned WC-025 change-ingester image.')
param changeIngesterImage string

@description('Existing private WC-025 Service Bus namespace name.')
param namespaceName string

@description('Existing private WC-025 queue name.')
param changeEventsQueueName string

@description('Dedicated Event Grid queue-ingester identity resource ID.')
param eventIngesterIdentityResourceId string

@description('Dedicated Event Grid queue-ingester identity client ID.')
param eventIngesterIdentityClientId string

@description('Dedicated Event Grid queue-ingester identity principal ID.')
param eventIngesterIdentityPrincipalId string

@description('Dedicated dead-letter purge identity resource ID.')
param purgeIdentityResourceId string

@description('Dedicated dead-letter purge identity client ID.')
param purgeIdentityClientId string

@description('Dedicated dead-letter purge identity principal ID.')
param purgeIdentityPrincipalId string

@description('Dedicated Azure Resource Graph change-history identity resource ID.')
param queryIdentityResourceId string

@description('Dedicated Azure Resource Graph change-history identity client ID.')
param queryIdentityClientId string

@description('Dedicated Azure Resource Graph change-history identity principal ID.')
param queryIdentityPrincipalId string

@description('Existing private evidence Storage account name.')
param evidenceStorageAccountName string

@description('Existing private container receiving create-only signed change-evidence artifacts.')
param evidenceContainerName string

@description('Dedicated private container receiving bounded dead-letter failure receipts.')
param failureReceiptContainerName string

@description('Existing Key Vault name containing the dedicated WC-025 key.')
param keyVaultName string

@description('Existing versioned signing key name.')
param changeSigningKeyName string

@description('Exact versioned Key Vault key URI used by both workers.')
param changeSigningKeyUriWithVersion string

@description('Exact deployment-owned approved scope JSON consumed by both workers.')
param approvedChangeScopeJson string

var serviceBusDataReceiverRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0')
var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
var storageBlobDataContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var keyVaultCryptoUserRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')
var serviceBusHostName = '${namespaceName}.servicebus.windows.net'
var jobNamePrefix = take(namespaceName, 18)
#disable-next-line no-hardcoded-env-urls // Worker validates the reviewed public-cloud Blob endpoint.
var evidenceBlobEndpoint = 'https://${evidenceStorageAccountName}.blob.core.windows.net'
var jobResources = {
  cpu: json('0.5')
  memory: '1Gi'
}

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: registryName
}

resource namespace 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: namespaceName
}

resource changeEventsQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: namespace
  name: changeEventsQueueName
}

resource evidenceStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: evidenceStorageAccountName
}

resource evidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: evidenceStorageAccount
  name: 'default'
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: evidenceBlobService
  name: evidenceContainerName
}

resource failureReceiptContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: evidenceBlobService
  name: failureReceiptContainerName
}

resource signingVault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: keyVaultName
}

resource changeSigningKey 'Microsoft.KeyVault/vaults/keys@2025-05-01' existing = {
  parent: signingVault
  name: changeSigningKeyName
}

resource eventIngesterQueueReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(changeEventsQueue.id, eventIngesterIdentityPrincipalId, serviceBusDataReceiverRoleId)
  scope: changeEventsQueue
  properties: {
    principalId: eventIngesterIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusDataReceiverRoleId
  }
}

resource purgeQueueReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(changeEventsQueue.id, purgeIdentityPrincipalId, serviceBusDataReceiverRoleId)
  scope: changeEventsQueue
  properties: {
    principalId: purgeIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusDataReceiverRoleId
  }
}

resource purgeFailureReceiptWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(failureReceiptContainer.id, purgeIdentityPrincipalId, storageBlobDataContributorRoleId)
  scope: failureReceiptContainer
  properties: {
    principalId: purgeIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRoleId
  }
}

resource eventIngesterEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceContainer.id, eventIngesterIdentityPrincipalId, storageBlobDataContributorRoleId)
  scope: evidenceContainer
  properties: {
    principalId: eventIngesterIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRoleId
  }
}

resource queryEvidenceWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceContainer.id, queryIdentityPrincipalId, storageBlobDataContributorRoleId)
  scope: evidenceContainer
  properties: {
    principalId: queryIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRoleId
  }
}

resource eventIngesterSigningKeyCryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(changeSigningKey.id, eventIngesterIdentityPrincipalId, keyVaultCryptoUserRoleId)
  scope: changeSigningKey
  properties: {
    principalId: eventIngesterIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultCryptoUserRoleId
  }
}

resource querySigningKeyCryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(changeSigningKey.id, queryIdentityPrincipalId, keyVaultCryptoUserRoleId)
  scope: changeSigningKey
  properties: {
    principalId: queryIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultCryptoUserRoleId
  }
}

resource eventIngesterAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, eventIngesterIdentityPrincipalId, acrPullRoleId)
  scope: registry
  properties: {
    principalId: eventIngesterIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

resource purgeAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, purgeIdentityPrincipalId, acrPullRoleId)
  scope: registry
  properties: {
    principalId: purgeIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

resource queryAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, queryIdentityPrincipalId, acrPullRoleId)
  scope: registry
  properties: {
    principalId: queryIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

resource eventIngesterJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-event-ingest'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${eventIngesterIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Event'
      replicaTimeout: 300
      replicaRetryLimit: 1
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: 4
          pollingInterval: 30
          rules: [
            {
              name: 'approved-resource-change-events'
              type: 'azure-servicebus'
              identity: eventIngesterIdentityResourceId
              auth: []
              metadata: {
                queueName: changeEventsQueueName
                namespace: namespaceName
                messageCount: '1'
                cloud: 'AzurePublicCloud'
              }
            }
          ]
        }
      }
      registries: [
        {
          server: registryServer
          identity: eventIngesterIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc025-change-event-ingester'
          image: changeIngesterImage
          command: [
            'athena-context'
          ]
          args: [
            'wc025-change-event-ingester'
            '--service-bus-namespace'
            serviceBusHostName
            '--change-events-queue'
            changeEventsQueueName
            '--managed-identity-client-id'
            eventIngesterIdentityClientId
            '--artifact-blob-endpoint'
            evidenceBlobEndpoint
            '--artifact-container'
            evidenceContainerName
            '--key-vault-key-id'
            changeSigningKeyUriWithVersion
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: eventIngesterIdentityClientId
            }
            {
              name: 'ATHENA_WC025_APPROVED_CHANGE_SCOPE_JSON'
              value: approvedChangeScopeJson
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    eventIngesterQueueReceiver
    eventIngesterEvidenceWriter
    eventIngesterSigningKeyCryptoUser
    eventIngesterAcrPull
  ]
}

resource deadLetterPurgeJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-dlq-purge'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${purgeIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 300
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: '*/1 * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registryServer
          identity: purgeIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc025-change-dead-letter-purge'
          image: changeIngesterImage
          command: [
            'athena-context'
          ]
          args: [
            'wc025-change-dead-letter-purge'
            '--service-bus-namespace'
            serviceBusHostName
            '--change-events-queue'
            changeEventsQueueName
            '--managed-identity-client-id'
            purgeIdentityClientId
            '--artifact-blob-endpoint'
            evidenceBlobEndpoint
            '--failure-container'
            failureReceiptContainerName
            '--maximum-messages-per-subqueue'
            '1000'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: purgeIdentityClientId
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    purgeQueueReceiver
    purgeFailureReceiptWriter
    purgeAcrPull
  ]
}

resource queryWorkerJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-change-query'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${queryIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 300
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: '*/5 * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registryServer
          identity: queryIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc025-change-history-query'
          image: changeIngesterImage
          command: [
            'athena-context'
          ]
          args: [
            'wc025-change-history-query'
            '--managed-identity-client-id'
            queryIdentityClientId
            '--artifact-blob-endpoint'
            evidenceBlobEndpoint
            '--artifact-container'
            evidenceContainerName
            '--key-vault-key-id'
            changeSigningKeyUriWithVersion
            '--lookback-minutes'
            '10'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: queryIdentityClientId
            }
            {
              name: 'ATHENA_WC025_APPROVED_CHANGE_SCOPE_JSON'
              value: approvedChangeScopeJson
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    queryEvidenceWriter
    querySigningKeyCryptoUser
    queryAcrPull
  ]
}

output eventIngesterJobResourceId string = eventIngesterJob.id
output deadLetterPurgeJobResourceId string = deadLetterPurgeJob.id
output queryWorkerJobResourceId string = queryWorkerJob.id
