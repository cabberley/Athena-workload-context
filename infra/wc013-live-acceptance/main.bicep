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

@description('Dedicated immutable Blob container for isolated collector handoffs.')
@minLength(3)
@maxLength(63)
param collectorArtifactContainerName string = 'collected-evidence'

@description('Dedicated private non-WORM Blob container for presentation assets.')
@allowed([
  'presentation-assets'
])
param presentationAssetContainerName string = 'presentation-assets'

@description('Explicit unlocked WORM retention period for artifact blob versions.')
@minValue(1)
@maxValue(146000)
param artifactRetentionDays int

@description('Object IDs of operator managed identities that read exact operational artifact versions and publish verified presentation assets. These principals receive Contributor only on presentation-assets and must not match workload or runtime identities.')
@maxLength(32)
param operatorArtifactReaderObjectIds array

@description('Object IDs of workload-controller managed identities that create exact run-scoped fault receipts. These principals must not appear in operatorArtifactReaderObjectIds or match either runtime identity.')
@maxLength(32)
param workloadReceiptWriterObjectIds array = []

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

@description('Digest-pinned controller image executed only by the protected GitHub workflow.')
@minLength(1)
@maxLength(2048)
param collectorControllerImage string

@description('Digest-pinned production image for the private presentation web app.')
@minLength(1)
@maxLength(2048)
param presentationImage string

@description('Existing Azure Container Registry login server hosting the presentation image.')
@minLength(1)
@maxLength(255)
param presentationImageRegistryServer string

@description('Resource ID of the existing Azure Container Registry hosting the presentation image.')
@minLength(1)
@maxLength(2048)
param presentationImageRegistryResourceId string

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
var rejectedImageDigestSuffix = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var expectedAcceptanceImageRegistryServer = '${toLower(last(split(acceptanceImageRegistryResourceId, '/')))}.azurecr.io'
var validatedAcceptanceImageRegistryServer = acceptanceImageRegistryServer == toLower(acceptanceImageRegistryServer) && acceptanceImageRegistryServer == expectedAcceptanceImageRegistryServer
  ? acceptanceImageRegistryServer
  : fail('acceptanceImageRegistryServer must exactly match the supplied Azure Container Registry resource ID')
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
) && !endsWith(acceptanceImage, rejectedImageDigestSuffix)
  ? acceptanceImage
  : fail('acceptanceImage must use the exact acceptanceImageRegistryServer/athena/wc013-live repository and a real 64-character lowercase sha256 digest')
var controllerImageRepositoryPrefix = '${validatedAcceptanceImageRegistryServer}/athena/wc013-controller@sha256:'
var controllerImageDigestCandidate = replace(collectorControllerImage, controllerImageRepositoryPrefix, '')
var controllerImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  controllerImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var controllerImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  controllerImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedControllerImage = collectorControllerImage == toLower(collectorControllerImage) && startsWith(
  collectorControllerImage,
  controllerImageRepositoryPrefix
) && length(collectorControllerImage) == length(controllerImageRepositoryPrefix) + 64 && length(
  controllerImageDigestCandidate
) == 64 && empty(
  controllerImageDigestInvalidCharacters
) && !endsWith(collectorControllerImage, rejectedImageDigestSuffix)
  ? collectorControllerImage
  : fail('collectorControllerImage must use the fixed ACR repository and a real non-placeholder sha256 digest')
var expectedPresentationImageRegistryServer = '${toLower(last(split(presentationImageRegistryResourceId, '/')))}.azurecr.io'
var validatedPresentationImageRegistryServer = presentationImageRegistryServer == toLower(presentationImageRegistryServer) && presentationImageRegistryServer == expectedPresentationImageRegistryServer
  ? presentationImageRegistryServer
  : fail('presentationImageRegistryServer must exactly match the supplied Azure Container Registry resource ID')
var presentationImageRepositoryPrefix = '${validatedPresentationImageRegistryServer}/athena/presentation-web@sha256:'
var presentationImageDigestCandidate = replace(presentationImage, presentationImageRepositoryPrefix, '')
var presentationImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  presentationImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var presentationImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  presentationImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedPresentationImage = presentationImage == toLower(presentationImage) && startsWith(
  presentationImage,
  presentationImageRepositoryPrefix
) && length(presentationImage) == length(presentationImageRepositoryPrefix) + 64 && length(
  presentationImageDigestCandidate
) == 64 && empty(
  presentationImageDigestInvalidCharacters
) && !endsWith(presentationImage, rejectedImageDigestSuffix)
  ? presentationImage
  : fail('presentationImage must use the exact presentationImageRegistryServer/athena/presentation-web repository and a real 64-character lowercase sha256 digest')
var validatedPresentationDeliveryRegistryServer = validatedPresentationImageRegistryServer == validatedAcceptanceImageRegistryServer
  ? validatedPresentationImageRegistryServer
  : fail('presentation and WC-013 delivery images must use the same reviewed Azure Container Registry')
var presentationAssetBlobEndpoint = 'https://${replayStorageAccountName}.blob.${environment().suffixes.storage}'
var collectorControllerFederatedCredentialIssuer = 'https://token.actions.githubusercontent.com'
var collectorControllerFederatedCredentialAudience = 'api://AzureADTokenExchange'
var collectorControllerFederatedCredentialSubject = 'repo:cabberley/Athena-workload-context:environment:athena-live'
var collectorControllerRoleDefinitionGuid = guid(
  subscription().id,
  foundationResourceGroupName,
  'athena-wc013-collector-controller'
)
var forbiddenCollectorControllerPrincipalIds = concat(
  map(operatorArtifactReaderObjectIds, objectId => toLower(string(objectId))),
  map(workloadReceiptWriterObjectIds, objectId => toLower(string(objectId))),
  [
    toLower(evidenceIdentity.properties.principalId)
    toLower(acceptanceJobIdentity.properties.principalId)
    toLower(presentationWeb.outputs.identityPrincipalId)
  ]
)
var validatedCollectorControllerPrincipalId = contains(
  forbiddenCollectorControllerPrincipalIds,
  toLower(collectorControllerIdentity.outputs.principalId)
)
  ? fail('deployment-owned collector controller identity must be distinct from runtime, presentation, operator, and workload principals')
  : collectorControllerIdentity.outputs.principalId

resource foundationResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: foundationResourceGroupName
  location: location
  tags: resourceTags
}

module collectorControllerIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc013-collector-controller-identity'
  scope: foundationResourceGroup
  params: {
    name: '${namePrefix}-collector-controller-id'
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    federatedIdentityCredentials: [
      {
        name: 'github-athena-live'
        issuer: collectorControllerFederatedCredentialIssuer
        subject: collectorControllerFederatedCredentialSubject
        audiences: [
          collectorControllerFederatedCredentialAudience
        ]
      }
    ]
    tags: union(resourceTags, {
      identityPurpose: 'github-oidc-collector-controller-only'
    })
  }
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

resource collectorControllerRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: collectorControllerRoleDefinitionGuid
  properties: {
    roleName: 'Athena WC013 Collector Controller ${uniqueString(foundationResourceGroup.id)}'
    description: 'Read and start only the fixed WC-013 collector Jobs. No deployment read, write, exec, or data-plane permission.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.App/jobs/read'
          'Microsoft.App/jobs/start/action'
          'Microsoft.App/jobs/executions/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      foundationResourceGroup.id
    ]
  }
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

module presentationWeb 'modules/presentation-web.bicep' = {
  name: 'wc013-private-presentation-web'
  scope: foundationResourceGroup
  params: {
    location: location
    namePrefix: namePrefix
    managedEnvironmentResourceId: azureMcp.outputs.managedEnvironmentResourceId
    presentationImage: validatedPresentationImage
    presentationImageRegistryServer: validatedPresentationDeliveryRegistryServer
    presentationImageRegistryResourceId: presentationImageRegistryResourceId
    deliveryImage: validatedAcceptanceImage
    presentationAssetBlobEndpoint: presentationAssetBlobEndpoint
    presentationAssetContainerName: presentationAssetContainerName
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
    evidenceIdentityPrincipalId: evidenceIdentity.properties.principalId
    acceptanceIdentityResourceId: acceptanceJobIdentity.id
    acceptanceIdentityPrincipalId: acceptanceJobIdentity.properties.principalId
    acceptanceIdentityClientId: acceptanceJobIdentity.properties.clientId
    keyVaultName: keyVaultName
    signingKeyName: signingKeyName
    replayStorageAccountName: replayStorageAccountName
    replayTableName: replayTableName
    artifactContainerName: artifactContainerName
    collectorArtifactContainerName: collectorArtifactContainerName
    presentationAssetContainerName: presentationAssetContainerName
    presentationIdentityPrincipalId: presentationWeb.outputs.identityPrincipalId
    artifactRetentionDays: artifactRetentionDays
    operatorArtifactReaderObjectIds: operatorArtifactReaderObjectIds
    workloadReceiptWriterObjectIds: workloadReceiptWriterObjectIds
    collectorControllerPrincipalId: validatedCollectorControllerPrincipalId
    collectorControllerRoleDefinitionId: collectorControllerRoleDefinition.id
    wc007PinnedAuthorityDigest: wc007PinnedAuthorityDigest
    wc008PinnedAssertionDigest: wc008PinnedAssertionDigest
    acceptanceImage: validatedAcceptanceImage
    acceptanceImageRegistryServer: validatedAcceptanceImageRegistryServer
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
    identityName: '${namePrefix}-context-id'
    identityPrincipalId: acceptanceJobIdentity.properties.principalId
  }
}

module evidenceCollectorImagePull 'modules/acr-pull-rbac.bicep' = {
  name: 'wc013-evidence-collector-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  dependsOn: [
    azureMcp
  ]
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    identityName: '${namePrefix}-mcp-evidence-id'
    identityPrincipalId: evidenceIdentity.properties.principalId
  }
}

module collectorControllerImagePull 'modules/acr-pull-rbac.bicep' = {
  name: 'wc013-controller-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    identityName: '${namePrefix}-collector-controller-id'
    identityPrincipalId: collectorControllerIdentity.outputs.principalId
  }
}

@description('Resource ID of the dedicated WC-013 hosting resource group.')
output foundationResourceGroupResourceId string = foundationResourceGroup.id

@description('VNet-scoped HTTPS endpoint for the pinned private Azure MCP Container App.')
output azureMcpInternalEndpoint string = azureMcp.outputs.azureMcpInternalEndpoint

@description('Exact audience that the isolated evidence collector requests for private Azure MCP calls.')
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

@description('Dedicated replay reservation namespace used by the isolated evidence collector.')
output replayPartitionKey string = replayPartitionKey

@description('Replay table resource ID.')
output replayTableResourceId string = acceptanceResources.outputs.replayTableResourceId

@description('Private HTTPS Azure Blob endpoint for immutable operational artifacts.')
output artifactBlobEndpoint string = acceptanceResources.outputs.artifactBlobEndpoint

@description('Dedicated immutable operational artifact container name.')
output artifactContainerName string = acceptanceResources.outputs.artifactContainerName

@description('Artifact container resource ID used as the exact Blob data-role scope.')
output artifactContainerResourceId string = acceptanceResources.outputs.artifactContainerResourceId

@description('Dedicated immutable collector artifact container name.')
output collectorArtifactContainerName string = acceptanceResources.outputs.collectorArtifactContainerName

@description('Collector artifact container resource ID used as the exact Blob data-role scope.')
output collectorArtifactContainerResourceId string = acceptanceResources.outputs.collectorArtifactContainerResourceId

@description('Dedicated private presentation asset container name.')
output presentationAssetContainerName string = acceptanceResources.outputs.presentationAssetContainerName

@description('Presentation asset container resource ID used as the exact Blob data-role scope.')
output presentationAssetContainerResourceId string = acceptanceResources.outputs.presentationAssetContainerResourceId

@description('Private HTTPS Azure Blob endpoint used by the presentation publisher and sidecar.')
output presentationAssetBlobEndpoint string = presentationAssetBlobEndpoint

@description('Configured unlocked WORM retention period for artifact blob versions.')
output artifactRetentionDays int = acceptanceResources.outputs.artifactRetentionDays

@description('Manual one-shot Container Apps Job name.')
output acceptanceJobName string = acceptanceResources.outputs.acceptanceJobName

@description('Manual one-shot Container Apps Job resource ID.')
output acceptanceJobResourceId string = acceptanceResources.outputs.acceptanceJobResourceId

@description('Deterministic manual Container Apps Job names for the phase-fixed operational runner jobs.')
output operationalPhaseJobNames object = acceptanceResources.outputs.operationalPhaseJobNames

@description('Deterministic manual Container Apps Job names for isolated evidence collection.')
output evidenceCollectorJobNames object = acceptanceResources.outputs.evidenceCollectorJobNames

@description('Reviewed exact collector templates consumed by the governed start controller.')
output evidenceCollectorStartContracts array = acceptanceResources.outputs.evidenceCollectorStartContracts

@description('Custom role definition assigned only to the governed collector controller.')
output collectorControllerRoleDefinitionId string = collectorControllerRoleDefinition.id

@description('Deployment-owned collector controller identity resource ID.')
output collectorControllerIdentityResourceId string = collectorControllerIdentity.outputs.resourceId

@description('Deployment-owned collector controller identity client ID used by GitHub OIDC login.')
output collectorControllerIdentityClientId string = collectorControllerIdentity.outputs.clientId

@description('Deployment-owned collector controller identity principal ID receiving only the collector controller role.')
output collectorControllerIdentityPrincipalId string = validatedCollectorControllerPrincipalId

@description('Exact digest-pinned ACR image containing the reviewed controller code and dependencies.')
output collectorControllerImage string = validatedControllerImage

@description('Name of the private presentation Container App.')
output presentationContainerAppName string = presentationWeb.outputs.name

@description('Resource ID of the private presentation Container App.')
output presentationContainerAppResourceId string = presentationWeb.outputs.resourceId

@description('VNet-scoped presentation FQDN.')
output presentationFqdn string = presentationWeb.outputs.fqdn

@description('Fully qualified private HTTPS presentation URL.')
output presentationHttpsUrl string = presentationWeb.outputs.httpsUrl

@description('Presentation identity resource ID. This identity receives only AcrPull and Blob Data Reader on presentation-assets.')
output presentationIdentityResourceId string = presentationWeb.outputs.identityResourceId

@description('Presentation identity client ID for ACR pull and read-only presentation asset access.')
output presentationIdentityClientId string = presentationWeb.outputs.identityClientId

@description('Presentation identity principal ID scoped to ACR pull and Blob Data Reader on presentation-assets.')
output presentationIdentityPrincipalId string = presentationWeb.outputs.identityPrincipalId

@description('Existing trusted-ingestion resource application client ID; Bicep intentionally does not create Entra applications.')
output trustedIngestionResourceApplicationClientId string = trustedIngestionResourceApplicationClientId

@description('Exact trusted-ingestion token audience for the rendered collector trust configuration.')
output trustedIngestionAudience string = trustedIngestionAudience

@description('Exact reviewed demo workload resource-group scope receiving the only Reader assignment.')
output targetDemoWorkloadResourceGroupScope string = '/subscriptions/${targetDemoWorkloadSubscriptionId}/resourceGroups/${targetDemoWorkloadResourceGroupName}'

@description('Exact reviewed read-only Azure MCP tool allowlist.')
output allowedTools array = azureMcp.outputs.allowedTools
