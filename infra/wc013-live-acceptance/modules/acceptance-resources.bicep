targetScope = 'resourceGroup'

metadata name = 'WC-013 one-shot acceptance resources'
metadata description = 'Private Key Vault, Azure Table replay storage, immutable Azure Blob artifacts, and the manual Container Apps Job for WC-013.'

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

@description('Resource ID of the separate acceptance-job managed identity.')
param acceptanceIdentityResourceId string

@description('Principal ID of the separate acceptance-job managed identity.')
param acceptanceIdentityPrincipalId string

@description('Client ID of the separate acceptance-job managed identity.')
param acceptanceIdentityClientId string

@description('Exact audience requested by the acceptance-job identity for private Azure MCP calls.')
param azureMcpAudience string

@description('Globally unique Key Vault name for the non-exportable signing key.')
param keyVaultName string

@description('Name of the one RSA signing key.')
param signingKeyName string

@description('Globally unique lowercase Storage account name for replay reservations.')
param replayStorageAccountName string

@description('Dedicated replay table name.')
param replayTableName string

@description('Dedicated replay reservation namespace.')
param replayPartitionKey string

@description('Dedicated immutable Blob container for operational artifacts.')
param artifactContainerName string

@description('Explicit unlocked WORM retention period for artifact blob versions.')
@minValue(1)
@maxValue(146000)
param artifactRetentionDays int

@description('Object ID of the separate operator managed identity that reads exact artifact versions.')
param operatorArtifactReaderObjectId string

@description('Exact non-secret WC-007 authority digest emitted by the configuration renderer.')
param wc007PinnedAuthorityDigest string

@description('Exact non-secret WC-008 assertion digest emitted by the configuration renderer.')
param wc008PinnedAssertionDigest string

@description('Digest-pinned configuration delivery image containing the reviewed non-secret WC-013 files.')
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
            description: 'WC-013 acceptance job can resolve and sign only with this key.'
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

resource replayTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    replayTable.id,
    acceptanceIdentityPrincipalId,
    storageTableDataContributorRoleDefinitionId
  )
  scope: replayTable
  properties: {
    principalId: acceptanceIdentityPrincipalId
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

resource operatorArtifactBlobDataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
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
}

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
        evidenceIdentityResourceId
      ]
    }
    registries: [
      {
        server: acceptanceImageRegistryServer
        identity: acceptanceIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'athena-wc013-live-acceptance'
        image: acceptanceImage
        command: [
          '/bin/sh'
          '-c'
        ]
        args: [
          'athena-context wc013-live-acceptance --config /opt/athena/wc013-live/wc013-live-acceptance.json --snapshot-output /tmp/evidence-snapshot.json && python -c "import base64; print(\'WC013_SNAPSHOT_B64=\' + base64.b64encode(open(\'/tmp/evidence-snapshot.json\', \'rb\').read()).decode(\'ascii\'))"'
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
            name: 'ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID'
            value: evidenceIdentityClientId
          }
          {
            name: 'ATHENA_WC013_AZURE_MCP_AUDIENCE'
            value: azureMcpAudience
          }
          {
            name: 'ATHENA_WC013_REPLAY_TABLE_ENDPOINT'
            value: replayStorage.outputs.serviceEndpoints.table
          }
          {
            name: 'ATHENA_WC013_REPLAY_TABLE_NAME'
            value: replayTableName
          }
          {
            name: 'ATHENA_WC013_REPLAY_PARTITION_KEY'
            value: replayPartitionKey
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

@description('Configured unlocked WORM retention period for artifact blob versions.')
output artifactRetentionDays int = artifactRetentionDays

@description('Manual WC-013 acceptance job name.')
output acceptanceJobName string = acceptanceJob.outputs.name

@description('Manual WC-013 acceptance job resource ID.')
output acceptanceJobResourceId string = acceptanceJob.outputs.resourceId
