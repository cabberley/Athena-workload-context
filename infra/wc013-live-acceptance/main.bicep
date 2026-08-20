targetScope = 'subscription'

metadata name = 'Athena WC-013 live acceptance and operational phase jobs'
metadata description = 'Composes the private Azure MCP evidence plane with the bounded WC-013 acceptance job and the phase-fixed operational runner jobs.'

@description('Azure region for the dedicated WC-013 hosting resource group.')
param location string = deployment().location

@description('Dedicated resource group for the private MCP environment and WC-013 acceptance resources.')
@minLength(1)
@maxLength(90)
param foundationResourceGroupName string

@description('Lowercase prefix shared by the private MCP foundation and the acceptance job.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Existing Entra resource-application client ID that validates inbound Azure MCP tokens.')
param azureMcpResourceApplicationClientId string

@description('Exact Application ID URI used by the job when it calls the private Azure MCP endpoint.')
@minLength(1)
@maxLength(512)
param azureMcpAudience string

@description('Existing Entra resource-application client ID that issues the evidence identity ingestion token.')
param trustedIngestionResourceApplicationClientId string

@description('Exact Application ID URI for the trusted-ingestion access token.')
@minLength(1)
@maxLength(512)
param trustedIngestionAudience string

@description('Subscription containing the one reviewed synthetic demo workload resource group.')
param targetDemoWorkloadSubscriptionId string

@description('One reviewed synthetic demo workload resource group. The MCP evidence identity receives Reader only here.')
@minLength(1)
@maxLength(90)
param targetDemoWorkloadResourceGroupName string

@description('Globally unique Key Vault name for the non-exportable WC-013 signing key.')
@minLength(3)
@maxLength(24)
param keyVaultName string

@description('Name of the single RSA signing key. Its exact deployed version is returned as an output.')
@minLength(1)
@maxLength(127)
param signingKeyName string = 'wc013-signing'

@description('Globally unique lowercase Storage account name for WC-013 replay reservations.')
@minLength(3)
@maxLength(24)
param replayStorageAccountName string

@description('Dedicated Azure Table name for durable attempt and request replay reservations.')
@minLength(3)
@maxLength(63)
param replayTableName string = 'Wc013Replay'

@description('Dedicated replay-reservation namespace passed to the job as a non-secret setting.')
@minLength(1)
@maxLength(128)
param replayPartitionKey string

@description('Dedicated immutable Blob container for operational artifacts.')
@minLength(3)
@maxLength(63)
param artifactContainerName string = 'operational-artifacts'

@description('Explicit unlocked WORM retention period for artifact blob versions.')
@minValue(1)
@maxValue(146000)
param artifactRetentionDays int

@description('Object IDs of the separate operator managed identities that read exact artifact versions.')
@maxLength(32)
param operatorArtifactReaderObjectIds array

@description('Exact non-secret WC-007 authority digest emitted by the reviewed configuration renderer.')
@minLength(71)
@maxLength(71)
param wc007PinnedAuthorityDigest string

@description('Exact non-secret WC-008 deployment assertion digest emitted by the reviewed configuration renderer.')
@minLength(71)
@maxLength(71)
param wc008PinnedAssertionDigest string

@description('Digest-pinned configuration delivery image containing the reviewed non-secret WC-013 files, public key, and operational phase bundle.')
@minLength(1)
@maxLength(2048)
param acceptanceImage string

@description('Existing Azure Container Registry login server hosting the private acceptance image.')
@minLength(1)
@maxLength(255)
param acceptanceImageRegistryServer string

@description('Resource ID of the existing Azure Container Registry hosting the private acceptance image.')
@minLength(1)
@maxLength(2048)
param acceptanceImageRegistryResourceId string

@description('Reviewed Azure MCP release. Only the existing pinned implementation accepts this value.')
@allowed([
  '2.0.5'
])
param azureMcpVersion string = '2.0.5'

@description('Reviewed manifest digest for the existing pinned Azure MCP release.')
@allowed([
  'sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a'
])
param azureMcpImageDigest string = 'sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a'

@description('Resource tags applied to the WC-013 composition.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc013-live-acceptance'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var validatedAcceptanceImage = contains(acceptanceImage, '@sha256:')
  ? acceptanceImage
  : fail('acceptanceImage must be pinned by a sha256 manifest digest')

resource foundationResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: foundationResourceGroupName
  location: location
  tags: resourceTags
}

module azureMcp '../azure-mcp/main.bicep' = {
  name: 'wc013-private-azure-mcp-foundation'
  scope: foundationResourceGroup
  params: {
    location: location
    namePrefix: namePrefix
    azureMcpVersion: azureMcpVersion
    azureMcpImageDigest: azureMcpImageDigest
    entraApplicationClientId: azureMcpResourceApplicationClientId
    containerAppsPrivateDnsVnetLinkName: 'wc013-containerapps-link'
    workloadReadScopes: [
      {
        subscriptionId: targetDemoWorkloadSubscriptionId
        resourceGroupName: targetDemoWorkloadResourceGroupName
      }
    ]
    approvedLogWorkspaces: []
    tags: resourceTags
  }
}

resource evidenceIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: '${namePrefix}-mcp-evidence-id'
  scope: foundationResourceGroup
}

resource acceptanceJobIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: '${namePrefix}-context-id'
  scope: foundationResourceGroup
}

module privateDns 'modules/private-dns.bicep' = {
  name: 'wc013-private-endpoint-dns'
  scope: foundationResourceGroup
  params: {
    namePrefix: namePrefix
    virtualNetworkResourceId: azureMcp.outputs.virtualNetworkResourceId
    tags: resourceTags
  }
}

module acceptanceResources 'modules/acceptance-resources.bicep' = {
  name: 'wc013-one-shot-acceptance-resources'
  scope: foundationResourceGroup
  params: {
    location: location
    namePrefix: namePrefix
    managedEnvironmentResourceId: azureMcp.outputs.managedEnvironmentResourceId
    privateEndpointSubnetResourceId: azureMcp.outputs.privateEndpointSubnetResourceId
    keyVaultPrivateDnsZoneResourceId: privateDns.outputs.keyVaultPrivateDnsZoneResourceId
    storageTablePrivateDnsZoneResourceId: privateDns.outputs.storageTablePrivateDnsZoneResourceId
    storageBlobPrivateDnsZoneResourceId: privateDns.outputs.storageBlobPrivateDnsZoneResourceId
    evidenceIdentityResourceId: azureMcp.outputs.azureMcpIdentityResourceId
    evidenceIdentityClientId: evidenceIdentity.properties.clientId
    acceptanceIdentityResourceId: acceptanceJobIdentity.id
    acceptanceIdentityPrincipalId: acceptanceJobIdentity.properties.principalId
    acceptanceIdentityClientId: acceptanceJobIdentity.properties.clientId
    azureMcpAudience: azureMcpAudience
    keyVaultName: keyVaultName
    signingKeyName: signingKeyName
    replayStorageAccountName: replayStorageAccountName
    replayTableName: replayTableName
    replayPartitionKey: replayPartitionKey
    artifactContainerName: artifactContainerName
    artifactRetentionDays: artifactRetentionDays
    operatorArtifactReaderObjectIds: operatorArtifactReaderObjectIds
    wc007PinnedAuthorityDigest: wc007PinnedAuthorityDigest
    wc008PinnedAssertionDigest: wc008PinnedAssertionDigest
    acceptanceImage: validatedAcceptanceImage
    acceptanceImageRegistryServer: acceptanceImageRegistryServer
    tags: resourceTags
  }
}

module acceptanceImagePull 'modules/acr-pull-rbac.bicep' = {
  name: 'wc013-acceptance-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  dependsOn: [
    azureMcp
  ]
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    acceptanceIdentityName: '${namePrefix}-context-id'
    acceptanceIdentityPrincipalId: acceptanceJobIdentity.properties.principalId
  }
}

@description('Resource ID of the dedicated WC-013 hosting resource group.')
output foundationResourceGroupResourceId string = foundationResourceGroup.id

@description('VNet-scoped HTTPS endpoint for the pinned private Azure MCP Container App.')
output azureMcpInternalEndpoint string = azureMcp.outputs.azureMcpInternalEndpoint

@description('Exact audience that the acceptance identity requests for private Azure MCP calls.')
output azureMcpAudience string = azureMcpAudience

@description('Resource ID of the private Azure MCP Container App.')
output azureMcpContainerAppResourceId string = azureMcp.outputs.azureMcpContainerAppResourceId

@description('Resource ID of the internal Container Apps managed environment shared by MCP and the one-shot job.')
output managedEnvironmentResourceId string = azureMcp.outputs.managedEnvironmentResourceId

@description('Resource ID of the bounded Container Apps operational log workspace.')
output operationalLogWorkspaceResourceId string = azureMcp.outputs.operationalLogWorkspaceResourceId

@description('Customer ID used to query bounded Container Apps operational logs.')
output operationalLogWorkspaceCustomerId string = azureMcp.outputs.operationalLogWorkspaceCustomerId

@description('Dedicated MCP/evidence identity resource ID.')
output evidenceIdentityResourceId string = azureMcp.outputs.azureMcpIdentityResourceId

@description('Dedicated MCP/evidence identity principal ID.')
output evidenceIdentityPrincipalId string = evidenceIdentity.properties.principalId

@description('Dedicated MCP/evidence identity client ID.')
output evidenceIdentityClientId string = evidenceIdentity.properties.clientId

@description('Separate acceptance-job context identity resource ID. It has no workload Reader assignment.')
output acceptanceJobIdentityResourceId string = acceptanceJobIdentity.id

@description('Separate acceptance-job context identity principal ID.')
output acceptanceJobIdentityPrincipalId string = acceptanceJobIdentity.properties.principalId

@description('Separate acceptance-job context identity client ID.')
output acceptanceJobIdentityClientId string = acceptanceJobIdentity.properties.clientId

@description('Resource ID of the Key Vault that holds the signing key.')
output keyVaultResourceId string = acceptanceResources.outputs.keyVaultResourceId

@description('Private Key Vault URI.')
output keyVaultUri string = acceptanceResources.outputs.keyVaultUri

@description('Signing key name.')
output signingKeyName string = acceptanceResources.outputs.signingKeyName

@description('Exact versioned non-exportable Key Vault signing-key URI for the configuration renderer.')
output signingKeyUriWithVersion string = acceptanceResources.outputs.signingKeyUriWithVersion

@description('Replay Storage account resource ID.')
output replayStorageAccountResourceId string = acceptanceResources.outputs.replayStorageAccountResourceId

@description('Private HTTPS Azure Table endpoint for replay reservations.')
output replayTableEndpoint string = acceptanceResources.outputs.replayTableEndpoint

@description('Dedicated replay table name.')
output replayTableName string = acceptanceResources.outputs.replayTableName

@description('Replay table resource ID.')
output replayTableResourceId string = acceptanceResources.outputs.replayTableResourceId

@description('Private HTTPS Azure Blob endpoint for immutable operational artifacts.')
output artifactBlobEndpoint string = acceptanceResources.outputs.artifactBlobEndpoint

@description('Dedicated immutable operational artifact container name.')
output artifactContainerName string = acceptanceResources.outputs.artifactContainerName

@description('Artifact container resource ID used as the exact Blob data-role scope.')
output artifactContainerResourceId string = acceptanceResources.outputs.artifactContainerResourceId

@description('Configured unlocked WORM retention period for artifact blob versions.')
output artifactRetentionDays int = acceptanceResources.outputs.artifactRetentionDays

@description('Manual one-shot Container Apps Job name.')
output acceptanceJobName string = acceptanceResources.outputs.acceptanceJobName

@description('Manual one-shot Container Apps Job resource ID.')
output acceptanceJobResourceId string = acceptanceResources.outputs.acceptanceJobResourceId

@description('Deterministic manual Container Apps Job names for the phase-fixed operational runner jobs.')
output operationalPhaseJobNames object = acceptanceResources.outputs.operationalPhaseJobNames

@description('Existing trusted-ingestion resource application client ID; Bicep intentionally does not create Entra applications.')
output trustedIngestionResourceApplicationClientId string = trustedIngestionResourceApplicationClientId

@description('Exact trusted-ingestion token audience for the rendered collector trust configuration.')
output trustedIngestionAudience string = trustedIngestionAudience

@description('Exact reviewed demo workload resource-group scope receiving the only Reader assignment.')
output targetDemoWorkloadResourceGroupScope string = '/subscriptions/${targetDemoWorkloadSubscriptionId}/resourceGroups/${targetDemoWorkloadResourceGroupName}'

@description('Exact reviewed read-only Azure MCP tool allowlist.')
output allowedTools array = azureMcp.outputs.allowedTools
