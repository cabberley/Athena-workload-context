targetScope = 'resourceGroup'

metadata name = 'WC-013 one-shot acceptance resources'
metadata description = 'Private Key Vault, Azure Table replay storage, immutable Azure Blob artifacts, and the manual Container Apps Jobs for WC-013 and the operational phases.'

@description('Azure region for the acceptance resources.')
param location string

@description('Prefix used in deterministic job and private endpoint names.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Resource ID of the internal Container Apps managed environment.')
param managedEnvironmentResourceId string

@description('Resource ID of the dedicated subnet for private endpoints.')
param privateEndpointSubnetResourceId string

@description('Resource ID of the private DNS zone for Key Vault private endpoints.')
param keyVaultPrivateDnsZoneResourceId string

@description('Resource ID of the private DNS zone for Azure Table private endpoints.')
param storageTablePrivateDnsZoneResourceId string

@description('Resource ID of the private DNS zone for Azure Blob private endpoints.')
param storageBlobPrivateDnsZoneResourceId string

@description('Resource ID of the dedicated MCP/evidence managed identity.')
param evidenceIdentityResourceId string

@description('Client ID of the dedicated MCP/evidence managed identity.')
param evidenceIdentityClientId string

@description('Principal ID of the dedicated MCP/evidence managed identity.')
param evidenceIdentityPrincipalId string

@description('Resource ID of the separate acceptance-job managed identity.')
param acceptanceIdentityResourceId string

@description('Principal ID of the separate acceptance-job managed identity.')
param acceptanceIdentityPrincipalId string

@description('Client ID of the separate acceptance-job managed identity.')
param acceptanceIdentityClientId string

@description('Globally unique Key Vault name for the non-exportable signing key.')
param keyVaultName string

@description('Name of the one RSA signing key.')
param signingKeyName string

@description('Globally unique lowercase Storage account name for replay reservations.')
param replayStorageAccountName string

@description('Dedicated replay table name.')
param replayTableName string

@description('Dedicated immutable Blob container for operational artifacts.')
param artifactContainerName string

@description('Dedicated immutable Blob container written only by the isolated evidence collector.')
param collectorArtifactContainerName string

@description('Explicit unlocked WORM retention period for artifact blob versions.')
@minValue(1)
@maxValue(146000)
param artifactRetentionDays int

@description('Object IDs of operator managed identities that read exact artifact versions. These principals must not appear in workloadReceiptWriterObjectIds or match either runtime identity.')
@maxLength(32)
param operatorArtifactReaderObjectIds array

@description('Object IDs of workload-controller managed identities that create exact run-scoped fault receipts. These principals must not appear in operatorArtifactReaderObjectIds or match either runtime identity.')
@maxLength(32)
param workloadReceiptWriterObjectIds array = []

@description('Object ID of the separately governed managed identity allowed to read and start collector Jobs.')
param collectorControllerPrincipalId string

@description('Resource ID of the custom collector Job read/start role definition.')
param collectorControllerRoleDefinitionId string

@description('Exact non-secret WC-007 authority digest emitted by the configuration renderer.')
param wc007PinnedAuthorityDigest string

@description('Exact non-secret WC-008 assertion digest emitted by the configuration renderer.')
param wc008PinnedAssertionDigest string

@description('Digest-pinned configuration delivery image containing the reviewed non-secret WC-013 files, public key, and operational phase bundle.')
param acceptanceImage string

@description('Azure Container Registry login server hosting the private acceptance image.')
param acceptanceImageRegistryServer string

@description('Resource tags applied to WC-013 resources.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc013-live-acceptance'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var storageTableDataContributorRoleDefinitionId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var storageBlobDataContributorRoleDefinitionId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var storageBlobDataReaderRoleDefinitionId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var normalizedOperatorArtifactReaderObjectIds = map(operatorArtifactReaderObjectIds, objectId => toLower(string(objectId)))
var normalizedWorkloadReceiptWriterObjectIds = map(workloadReceiptWriterObjectIds, objectId => toLower(string(objectId)))
var normalizedRuntimeIdentityPrincipalIds = [
  toLower(acceptanceIdentityPrincipalId)
  toLower(evidenceIdentityPrincipalId)
]
var overlappingArtifactAccessObjectIds = intersection(
  normalizedOperatorArtifactReaderObjectIds,
  normalizedWorkloadReceiptWriterObjectIds
)
var operatorRuntimeIdentityOverlap = intersection(
  normalizedOperatorArtifactReaderObjectIds,
  normalizedRuntimeIdentityPrincipalIds
)
var workloadRuntimeIdentityOverlap = intersection(
  normalizedWorkloadReceiptWriterObjectIds,
  normalizedRuntimeIdentityPrincipalIds
)
var validatedOperatorArtifactReaderObjectIds = empty(operatorRuntimeIdentityOverlap)
  ? operatorArtifactReaderObjectIds
  : fail('operatorArtifactReaderObjectIds must not contain acceptance or evidence runtime identities')
var validatedWorkloadReceiptWriterObjectIds = !empty(overlappingArtifactAccessObjectIds)
  ? fail('operatorArtifactReaderObjectIds and workloadReceiptWriterObjectIds must contain distinct principals')
  : empty(workloadRuntimeIdentityOverlap)
    ? workloadReceiptWriterObjectIds
    : fail('workloadReceiptWriterObjectIds must not contain acceptance or evidence runtime identities')
var rejectedAcceptanceImageDigestSuffix = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var validatedAcceptanceImageRegistryServer = acceptanceImageRegistryServer == toLower(acceptanceImageRegistryServer) && endsWith(
  acceptanceImageRegistryServer,
  '.azurecr.io'
) && !contains(acceptanceImageRegistryServer, '/')
  ? acceptanceImageRegistryServer
  : fail('acceptanceImageRegistryServer must be an exact lowercase Azure Container Registry login server')
var acceptanceImageRepositoryPrefix = '${validatedAcceptanceImageRegistryServer}/athena/wc013-live@sha256:'
var acceptanceImageDigestCandidate = replace(acceptanceImage, acceptanceImageRepositoryPrefix, '')
var acceptanceImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  acceptanceImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var acceptanceImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  acceptanceImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedAcceptanceImage = acceptanceImage == toLower(acceptanceImage) && startsWith(
  acceptanceImage,
  acceptanceImageRepositoryPrefix
) && length(acceptanceImage) == length(acceptanceImageRepositoryPrefix) + 64 && length(
  acceptanceImageDigestCandidate
) == 64 && empty(
  acceptanceImageDigestInvalidCharacters
) && !endsWith(acceptanceImage, rejectedAcceptanceImageDigestSuffix)
  ? acceptanceImage
  : fail('acceptanceImage must use the exact acceptanceImageRegistryServer/athena/wc013-live repository and a real 64-character lowercase sha256 digest')
var operationalPhaseBundlePath = '/opt/athena/wc013-live/delivery/operational-phase-bundle.json'
var operationalScratchDirectory = '/tmp/athena-operational'
var baselineOperationalJobName = '${namePrefix}-op-baseline'
var faultedOperationalJobName = '${namePrefix}-op-faulted'
var recoveredOperationalJobName = '${namePrefix}-op-recovered'
var baselineOperationalInputsPath = '${operationalScratchDirectory}/baseline-inputs.json'
var faultedOperationalInputsPath = '${operationalScratchDirectory}/faulted-inputs.json'
var recoveredOperationalInputsPath = '${operationalScratchDirectory}/recovered-inputs.json'
var baselineOperationalHandoffPath = '${operationalScratchDirectory}/baseline-handoff.json'
var faultedOperationalHandoffPath = '${operationalScratchDirectory}/faulted-handoff.json'
var recoveredOperationalHandoffPath = '${operationalScratchDirectory}/recovered-handoff.json'
var operationalJobResources = {
  cpu: '0.5'
  memory: '1Gi'
}
var collectorJobDefinitions = [
  {
    key: 'acceptance'
    name: '${namePrefix}-accept-col'
    containerName: 'wc013-acceptance-evidence-collector'
    configurationPath: '/opt/athena/wc013-live/wc013-live-acceptance.json'
  }
  {
    key: 'baseline'
    name: '${namePrefix}-base-col'
    containerName: 'wc013-baseline-evidence-collector'
    configurationPath: '/opt/athena/wc013-live/delivery/configs/baseline.json'
  }
  {
    key: 'faulted'
    name: '${namePrefix}-fault-col'
    containerName: 'wc013-faulted-evidence-collector'
    configurationPath: '/opt/athena/wc013-live/delivery/configs/faulted.json'
  }
  {
    key: 'recovered'
    name: '${namePrefix}-recover-col'
    containerName: 'wc013-recovered-evidence-collector'
    configurationPath: '/opt/athena/wc013-live/delivery/configs/recovered.json'
  }
]

module signingKeyVault 'br/public:avm/res/key-vault/vault:0.14.0' = {
  name: 'wc013-signing-key-vault'
  params: {
    name: keyVaultName
    location: location
    enableTelemetry: false
    enableVaultForDeployment: false
    enableVaultForTemplateDeployment: false
    enableVaultForDiskEncryption: false
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enableRbacAuthorization: true
    sku: 'standard'
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
    privateEndpoints: [
      {
        name: '${namePrefix}-wc013-kv-pe'
        service: 'vault'
        subnetResourceId: privateEndpointSubnetResourceId
        privateDnsZoneGroup: {
          name: 'default'
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: keyVaultPrivateDnsZoneResourceId
            }
          ]
        }
      }
    ]
    keys: [
      {
        name: signingKeyName
        kty: 'RSA'
        keySize: 3072
        keyOps: [
          'sign'
          'verify'
        ]
        attributes: {
          enabled: true
        }
        roleAssignments: [
          {
            roleDefinitionIdOrName: 'Key Vault Crypto User'
            principalId: acceptanceIdentityPrincipalId
            principalType: 'ServicePrincipal'
            description: 'Athena evaluation jobs can resolve and sign only with this key.'
          }
          {
            roleDefinitionIdOrName: 'Key Vault Crypto User'
            principalId: evidenceIdentityPrincipalId
            principalType: 'ServicePrincipal'
            description: 'The isolated evidence collector can attest collection with this key.'
          }
        ]
      }
    ]
    tags: resourceTags
  }
}

module replayStorage 'br/public:avm/res/storage/storage-account:0.33.0' = {
  name: 'wc013-replay-storage'
  params: {
    name: replayStorageAccountName
    location: location
    enableTelemetry: false
    kind: 'StorageV2'
    skuName: 'Standard_ZRS'
    accessTier: 'Hot'
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    requireInfrastructureEncryption: true
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
    blobServices: {
      // Preserve the AVM 0.33.0 soft-delete defaults already applied to the replay account.
      containerDeleteRetentionPolicyEnabled: true
      containerDeleteRetentionPolicyDays: 7
      deleteRetentionPolicyEnabled: true
      deleteRetentionPolicyDays: 6
      isVersioningEnabled: true
      containers: [
        {
          name: artifactContainerName
          publicAccess: 'None'
          immutableStorageWithVersioningEnabled: true
          immutabilityPolicy: {
            immutabilityPeriodSinceCreationInDays: artifactRetentionDays
            allowProtectedAppendWrites: false
            allowProtectedAppendWritesAll: false
          }
        }
        {
          name: collectorArtifactContainerName
          publicAccess: 'None'
          immutableStorageWithVersioningEnabled: true
          immutabilityPolicy: {
            immutabilityPeriodSinceCreationInDays: artifactRetentionDays
            allowProtectedAppendWrites: false
            allowProtectedAppendWritesAll: false
          }
        }
      ]
    }
    privateEndpoints: [
      {
        name: '${namePrefix}-wc013-table-pe'
        service: 'table'
        subnetResourceId: privateEndpointSubnetResourceId
        privateDnsZoneGroup: {
          name: 'default'
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: storageTablePrivateDnsZoneResourceId
            }
          ]
        }
      }
      {
        name: '${namePrefix}-wc013-blob-pe'
        service: 'blob'
        subnetResourceId: privateEndpointSubnetResourceId
        privateDnsZoneGroup: {
          name: 'default'
          privateDnsZoneGroupConfigs: [
            {
              privateDnsZoneResourceId: storageBlobPrivateDnsZoneResourceId
            }
          ]
        }
      }
    ]
    tags: resourceTags
  }
}

var replayBlobEndpoint = replayStorage.outputs.serviceEndpoints.blob
var canonicalReplayBlobEndpoint = endsWith(replayBlobEndpoint, '/')
  ? substring(replayBlobEndpoint, 0, length(replayBlobEndpoint) - 1)
  : replayBlobEndpoint

resource replayStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: replayStorageAccountName
}

resource replayTableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' existing = {
  parent: replayStorageAccount
  name: 'default'
}

resource replayTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  parent: replayTableService
  name: replayTableName
  properties: {}
  dependsOn: [
    replayStorage
  ]
}

resource replayBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: replayStorageAccount
  name: 'default'
}

resource artifactContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: replayBlobService
  name: artifactContainerName
}

resource collectorArtifactContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' existing = {
  parent: replayBlobService
  name: collectorArtifactContainerName
}

resource replayTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    replayTable.id,
    evidenceIdentityPrincipalId,
    storageTableDataContributorRoleDefinitionId
  )
  scope: replayTable
  properties: {
    principalId: evidenceIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageTableDataContributorRoleDefinitionId
    )
  }
}

resource artifactBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    artifactContainer.id,
    acceptanceIdentityPrincipalId,
    storageBlobDataContributorRoleDefinitionId
  )
  scope: artifactContainer
  properties: {
    principalId: acceptanceIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataContributorRoleDefinitionId
    )
  }
  dependsOn: [
    replayStorage
  ]
}

resource collectorArtifactBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    collectorArtifactContainer.id,
    evidenceIdentityPrincipalId,
    storageBlobDataContributorRoleDefinitionId
  )
  scope: collectorArtifactContainer
  properties: {
    principalId: evidenceIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataContributorRoleDefinitionId
    )
  }
  dependsOn: [
    replayStorage
  ]
}

resource collectorArtifactBlobDataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    collectorArtifactContainer.id,
    acceptanceIdentityPrincipalId,
    storageBlobDataReaderRoleDefinitionId
  )
  scope: collectorArtifactContainer
  properties: {
    principalId: acceptanceIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
  }
  dependsOn: [
    replayStorage
  ]
}

resource workloadReceiptBlobDataContributors 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for workloadReceiptWriterObjectId in validatedWorkloadReceiptWriterObjectIds: {
  name: guid(
    artifactContainer.id,
    workloadReceiptWriterObjectId,
    storageBlobDataContributorRoleDefinitionId
  )
  scope: artifactContainer
  properties: {
    principalId: workloadReceiptWriterObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataContributorRoleDefinitionId
    )
  }
  dependsOn: [
    replayStorage
  ]
}]

resource operatorArtifactBlobDataReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for operatorArtifactReaderObjectId in validatedOperatorArtifactReaderObjectIds: {
  name: guid(
    artifactContainer.id,
    operatorArtifactReaderObjectId,
    storageBlobDataReaderRoleDefinitionId
  )
  scope: artifactContainer
  properties: {
    principalId: operatorArtifactReaderObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleDefinitionId
    )
  }
  dependsOn: [
    replayStorage
  ]
}]

module acceptanceJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'wc013-one-shot-job'
  params: {
    name: '${namePrefix}-acceptance'
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    triggerType: 'Manual'
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    replicaRetryLimit: 0
    replicaTimeout: 900
    managedIdentities: {
      userAssignedResourceIds: [
        acceptanceIdentityResourceId
      ]
    }
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: acceptanceIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'athena-wc013-live-acceptance'
        image: validatedAcceptanceImage
        command: [
          '/bin/sh'
          '-c'
        ]
        args: [
          'athena-context wc013-live-acceptance --config /opt/athena/wc013-live/wc013-live-acceptance.json --evidence-blob-endpoint ${replayStorage.outputs.serviceEndpoints.blob} --evidence-container ${collectorArtifactContainerName} --snapshot-output /tmp/evidence-snapshot.json && python -c "import base64; print(\'WC013_SNAPSHOT_B64=\' + base64.b64encode(open(\'/tmp/evidence-snapshot.json\', \'rb\').read()).decode(\'ascii\'))"'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: acceptanceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_LIVE'
            value: '1'
          }
          {
            name: 'ATHENA_WC013_LIVE_CONFIG'
            value: '/opt/athena/wc013-live/wc013-live-acceptance.json'
          }
          {
            name: 'ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST'
            value: wc007PinnedAuthorityDigest
          }
          {
            name: 'ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST'
            value: wc008PinnedAssertionDigest
          }
          {
            name: 'ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID'
            value: acceptanceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64'
            value: ''
          }
        ]
        resources: {
          cpu: '0.5'
          memory: '1Gi'
        }
      }
    ]
    tags: resourceTags
  }
}

module evidenceCollectorJobs 'br/public:avm/res/app/job:0.7.2' = [for collectorJob in collectorJobDefinitions: {
  name: 'wc013-${collectorJob.key}-evidence-collector-job'
  params: {
    name: collectorJob.name
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    triggerType: 'Manual'
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    replicaRetryLimit: 0
    replicaTimeout: 900
    managedIdentities: {
      userAssignedResourceIds: [
        evidenceIdentityResourceId
      ]
    }
    roleAssignments: [
      {
        roleDefinitionIdOrName: collectorControllerRoleDefinitionId
        principalId: collectorControllerPrincipalId
        principalType: 'ServicePrincipal'
        description: 'Only the governed controller may retrieve and start this fixed collector Job.'
      }
    ]
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: evidenceIdentityResourceId
      }
    ]
    containers: [
      {
        name: collectorJob.containerName
        image: validatedAcceptanceImage
        command: [
          'athena-context'
        ]
        args: [
          'wc013-evidence-collector-job'
          '--config'
          collectorJob.configurationPath
          '--artifact-blob-endpoint'
          canonicalReplayBlobEndpoint
          '--artifact-container'
          collectorArtifactContainerName
          '--emit-handoff-base64'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: evidenceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID'
            value: evidenceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST'
            value: wc007PinnedAuthorityDigest
          }
          {
            name: 'ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST'
            value: wc008PinnedAssertionDigest
          }
        ]
        resources: operationalJobResources
      }
    ]
    tags: resourceTags
  }
}]


module baselineOperationalPhaseJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'wc013-operational-baseline-job'
  params: {
    name: baselineOperationalJobName
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    triggerType: 'Manual'
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    replicaRetryLimit: 0
    replicaTimeout: 900
    managedIdentities: {
      userAssignedResourceIds: [
        acceptanceIdentityResourceId
      ]
    }
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: acceptanceIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'athena-operational-baseline'
        image: validatedAcceptanceImage
        command: [
          'athena-context'
        ]
        args: [
          'operational-phase-job'
          '--phase'
          'baseline'
          '--bundle'
          operationalPhaseBundlePath
          '--inputs-output'
          baselineOperationalInputsPath
          '--handoff-output'
          baselineOperationalHandoffPath
          '--artifact-blob-endpoint'
          canonicalReplayBlobEndpoint
          '--artifact-container'
          artifactContainerName
          '--evidence-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--evidence-container'
          collectorArtifactContainerName
          '--emit-handoff-base64'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: acceptanceIdentityClientId
          }
        ]
        resources: operationalJobResources
      }
    ]
    tags: resourceTags
  }
}

module faultedOperationalPhaseJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'wc013-operational-faulted-job'
  params: {
    name: faultedOperationalJobName
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    triggerType: 'Manual'
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    replicaRetryLimit: 0
    replicaTimeout: 900
    managedIdentities: {
      userAssignedResourceIds: [
        acceptanceIdentityResourceId
      ]
    }
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: acceptanceIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'athena-operational-faulted'
        image: validatedAcceptanceImage
        command: [
          'athena-context'
        ]
        args: [
          'operational-phase-job'
          '--phase'
          'faulted'
          '--bundle'
          operationalPhaseBundlePath
          '--inputs-output'
          faultedOperationalInputsPath
          '--handoff-output'
          faultedOperationalHandoffPath
          '--artifact-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--artifact-container'
          artifactContainerName
          '--evidence-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--evidence-container'
          collectorArtifactContainerName
          '--emit-handoff-base64'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: acceptanceIdentityClientId
          }
        ]
        resources: operationalJobResources
      }
    ]
    tags: resourceTags
  }
}

module recoveredOperationalPhaseJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'wc013-operational-recovered-job'
  params: {
    name: recoveredOperationalJobName
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    triggerType: 'Manual'
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    replicaRetryLimit: 0
    replicaTimeout: 900
    managedIdentities: {
      userAssignedResourceIds: [
        acceptanceIdentityResourceId
      ]
    }
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: acceptanceIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'athena-operational-recovered'
        image: validatedAcceptanceImage
        command: [
          'athena-context'
        ]
        args: [
          'operational-phase-job'
          '--phase'
          'recovered'
          '--bundle'
          operationalPhaseBundlePath
          '--inputs-output'
          recoveredOperationalInputsPath
          '--handoff-output'
          recoveredOperationalHandoffPath
          '--artifact-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--artifact-container'
          artifactContainerName
          '--evidence-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--evidence-container'
          collectorArtifactContainerName
          '--emit-handoff-base64'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: acceptanceIdentityClientId
          }
        ]
        resources: operationalJobResources
      }
    ]
    tags: resourceTags
  }
}

@description('Resource ID of the private signing Key Vault.')
output keyVaultResourceId string = signingKeyVault.outputs.resourceId

@description('Private signing Key Vault URI.')
output keyVaultUri string = signingKeyVault.outputs.uri

@description('Signing key name.')
output signingKeyName string = signingKeyName

@description('Exact versioned signing-key URI; it contains no private key material.')
output signingKeyUriWithVersion string = signingKeyVault.outputs.keys[0].uriWithVersion

@description('Resource ID of the replay Storage account.')
output replayStorageAccountResourceId string = replayStorage.outputs.resourceId

@description('Private Azure Table service endpoint.')
output replayTableEndpoint string = replayStorage.outputs.serviceEndpoints.table

@description('Dedicated replay table name.')
output replayTableName string = replayTableName

@description('Resource ID of the dedicated replay table.')
output replayTableResourceId string = replayTable.id

@description('Private Azure Blob service endpoint for immutable operational artifacts.')
output artifactBlobEndpoint string = replayStorage.outputs.serviceEndpoints.blob

@description('Dedicated immutable operational artifact container name.')
output artifactContainerName string = artifactContainerName

@description('Resource ID of the dedicated immutable operational artifact container.')
output artifactContainerResourceId string = artifactContainer.id

@description('Dedicated immutable collector artifact container name.')
output collectorArtifactContainerName string = collectorArtifactContainerName

@description('Resource ID of the dedicated immutable collector artifact container.')
output collectorArtifactContainerResourceId string = collectorArtifactContainer.id

@description('Configured unlocked WORM retention period for artifact blob versions.')
output artifactRetentionDays int = artifactRetentionDays

@description('Manual WC-013 acceptance job name.')
output acceptanceJobName string = acceptanceJob.outputs.name

@description('Manual WC-013 acceptance job resource ID.')
output acceptanceJobResourceId string = acceptanceJob.outputs.resourceId

@description('Deterministic manual Container Apps Job names for the phase-fixed operational runner jobs.')
output operationalPhaseJobNames object = {
  baseline: baselineOperationalPhaseJob.outputs.name
  faulted: faultedOperationalPhaseJob.outputs.name
  recovered: recoveredOperationalPhaseJob.outputs.name
}

@description('Deterministic manual Container Apps Job names for isolated evidence collection.')
output evidenceCollectorJobNames object = {
  acceptance: evidenceCollectorJobs[0].outputs.name
  baseline: evidenceCollectorJobs[1].outputs.name
  faulted: evidenceCollectorJobs[2].outputs.name
  recovered: evidenceCollectorJobs[3].outputs.name
}

@description('Exact reviewed collector templates for the governed start controller.')
output evidenceCollectorStartContracts array = [for collectorJob in collectorJobDefinitions: {
  schemaVersion: 'athena.wc013CollectorStartContract.v1'
  jobResourceId: resourceId('Microsoft.App/jobs', collectorJob.name)
  evidenceIdentityResourceId: evidenceIdentityResourceId
  evidenceIdentityClientId: evidenceIdentityClientId
  wc007PinnedAuthorityDigest: wc007PinnedAuthorityDigest
  wc008PinnedAssertionDigest: wc008PinnedAssertionDigest
  configuration: {
    triggerType: 'Manual'
    replicaRetryLimit: 0
    replicaTimeout: 900
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    registries: [
      {
        server: validatedAcceptanceImageRegistryServer
        identity: evidenceIdentityResourceId
      }
    ]
  }
  template: {
    containers: [
      {
        name: collectorJob.containerName
        image: validatedAcceptanceImage
        command: [
          'athena-context'
        ]
        args: [
          'wc013-evidence-collector-job'
          '--config'
          collectorJob.configurationPath
          '--artifact-blob-endpoint'
          replayStorage.outputs.serviceEndpoints.blob
          '--artifact-container'
          collectorArtifactContainerName
          '--emit-handoff-base64'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: evidenceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID'
            value: evidenceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST'
            value: wc007PinnedAuthorityDigest
          }
          {
            name: 'ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST'
            value: wc008PinnedAssertionDigest
          }
        ]
        resources: operationalJobResources
      }
    ]
  }
}]
