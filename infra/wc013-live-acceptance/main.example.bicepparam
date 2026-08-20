using './main.bicep'

param location = 'australiaeast'
param foundationResourceGroupName = 'athena-synth-wc013-live-rg'
param namePrefix = 'athena-synth-live'

// Existing Entra resource applications; replace synthetic IDs before any deployment.
param azureMcpResourceApplicationClientId = '11111111-1111-1111-1111-111111111111'
param azureMcpAudience = 'api://athena-azure-mcp'
param trustedIngestionResourceApplicationClientId = '22222222-2222-2222-2222-222222222222'
param trustedIngestionAudience = 'api://athena-trusted-ingestion'

// The only Azure workload Reader assignment is made at this synthetic resource-group scope.
param targetDemoWorkloadSubscriptionId = '33333333-3333-3333-3333-333333333333'
param targetDemoWorkloadResourceGroupName = 'athena-synth-demo-workload-rg'

// Names must be globally available in the target Azure cloud.
param keyVaultName = 'athenasynthwc013kv'
param signingKeyName = 'wc013-signing'
param replayStorageAccountName = 'athenasynthwc013replay'
param replayTableName = 'Wc013Replay'
param replayPartitionKey = 'wc013-live-synthetic'
param artifactContainerName = 'operational-artifacts'
param artifactRetentionDays = 30
param operatorArtifactReaderObjectId = '44444444-4444-4444-4444-444444444444'

// Bootstrap values are deliberately unusable. Replace both with renderer output before starting the job.
param wc007PinnedAuthorityDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
param wc008PinnedAssertionDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'

// The image must be a private ACR image pinned by digest and contain only reviewed non-secret runtime files.
param acceptanceImage = 'athenasynth.azurecr.io/athena/wc013-live@sha256:0000000000000000000000000000000000000000000000000000000000000000'
param acceptanceImageRegistryServer = 'athenasynth.azurecr.io'
param acceptanceImageRegistryResourceId = '/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/athena-synth-shared-rg/providers/Microsoft.ContainerRegistry/registries/athenasynth'
