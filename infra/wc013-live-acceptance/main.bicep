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

@description('One reviewed synthetic demo workload resource group. The MCP evidence identity receives Reader; WC-016 identities receive only the custom signal-reader role.')
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

@description('Name of the dedicated non-exportable WC-016 incident signing key.')
@minLength(1)
@maxLength(127)
param incidentSigningKeyName string = 'wc016-incident-signing'

@description('Name of the dedicated non-exportable WC-027 feed signing key.')
param incidentFeedV2SigningKeyName string = 'wc027-feed-v2-signing'

@description('Name of the dedicated non-exportable WC-027 report signing key.')
param incidentReportSigningKeyName string = 'wc027-report-signing'

@description('Name of the dedicated non-exportable WC-027 guidance signing key.')
param incidentGuidanceSigningKeyName string = 'wc027-guidance-signing'

@description('Name of the dedicated non-exportable WC-027 enrichment signing key.')
param incidentEnrichmentSigningKeyName string = 'wc027-enrichment-signing'

@description('Name of the dedicated non-exportable WC-027 notification signing key.')
param incidentNotificationSigningKeyName string = 'wc027-notification-signing'

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

@description('Dedicated private Blob container for signed WC-016 incident assets.')
@allowed([
  'incident-assets'
])
param incidentAssetContainerName string = 'incident-assets'

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

@description('Reviewed role-assignment permissions mode for the acceptance image registry.')
@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
param acceptanceImageRegistryRoleAssignmentMode string

@description('Digest-pinned controller image executed only by the protected GitHub workflow.')
@minLength(1)
@maxLength(2048)
param collectorControllerImage string

@description('Digest-pinned production image for the private presentation web app.')
@minLength(1)
@maxLength(2048)
param presentationImage string

@description('Digest-pinned WC-016 scheduled signal detector image.')
@minLength(1)
@maxLength(2048)
param wc016DetectorImage string

@description('Digest-pinned WC-016 incident orchestrator image.')
@minLength(1)
@maxLength(2048)
param wc016OrchestratorImage string

@description('Exact approved singleton database VM resource ID for WC-016.')
param wc016DatabaseVmResourceId string

@description('Exact approved web VM resource IDs for WC-016.')
@minLength(1)
@maxLength(16)
param wc016WebVmResourceIds array

@description('Exact approved Azure Load Balancer resource ID for WC-016.')
param wc016LoadBalancerResourceId string

@description('Dedicated replay-table partition for WC-016 detector transition state.')
@minLength(1)
@maxLength(128)
param wc016DetectorStatePartitionKey string = 'wc016-signal-state'

@description('Dedicated Azure Table for WC-016 detector transition state.')
@minLength(3)
@maxLength(63)
param wc016DetectorStateTableName string = 'Wc016DetectorState'

@description('Dedicated Azure Table partition for WC-016 notification delivery reservations.')
@minLength(1)
@maxLength(128)
param wc016NotificationStatePartitionKey string = 'wc016-notification-delivery'

@description('Dedicated Azure Table for WC-016 notification delivery reservations.')
@minLength(3)
@maxLength(63)
param wc016NotificationStateTableName string = 'Wc016NotificationState'

@description('SHA-256 fingerprint of the exact deployed WC-016 incident signing public key.')
@minLength(71)
@maxLength(71)
param signingKeyFingerprint string

@description('Exact logical WC-016 incident signing key ID pinned separately by the browser and gateway.')
@allowed([
  'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'
])
param incidentSigningKeyId string = 'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'

@description('Exact logical WC-027 feed signing key ID.')
param incidentFeedV2SigningKeyId string

@description('SHA-256 fingerprint of the exact WC-027 feed signing public key.')
@minLength(71)
@maxLength(71)
param incidentFeedV2SigningKeyFingerprint string

@description('Exact logical WC-027 report signing key ID.')
param incidentReportSigningKeyId string

@description('SHA-256 fingerprint of the exact WC-027 report signing public key.')
@minLength(71)
@maxLength(71)
param incidentReportSigningKeyFingerprint string

@description('Exact logical WC-027 guidance signing key ID.')
param incidentGuidanceSigningKeyId string

@description('SHA-256 fingerprint of the exact WC-027 guidance signing public key.')
@minLength(71)
@maxLength(71)
param incidentGuidanceSigningKeyFingerprint string

@description('Exact logical WC-027 enrichment signing key ID.')
param incidentEnrichmentSigningKeyId string

@description('SHA-256 fingerprint of the exact WC-027 enrichment signing public key.')
@minLength(71)
@maxLength(71)
param incidentEnrichmentSigningKeyFingerprint string

@description('Exact logical WC-027 notification signing key ID.')
param incidentNotificationSigningKeyId string

@description('SHA-256 fingerprint of the exact WC-027 notification signing public key.')
@minLength(71)
@maxLength(71)
param incidentNotificationSigningKeyFingerprint string

@description('Activates WC-016 queues and Jobs only after the deployed incident key public material is pinned in both presentation verification layers.')
param wc016RuntimeEnabled bool = false

@description('Enables WC-027 notification v2 only after its separate enrichment/feed-v2 producer is deployed and healthy.')
param wc027FeedV2ProducerReady bool = false

@description('Exact deployed WC-027 enrichment/feed producer Job resource ID. Required before notification v2 can be enabled.')
param wc027EnrichmentFeedProducerJobResourceId string = ''

@description('SHA-256 digest of the exact runtime configuration deployed to the WC-027 producer Job.')
param wc027EnrichmentFeedProducerConfigurationDigest string = ''

@description('Exact non-secret runtime configuration JSON deployed to the WC-027 producer Job.')
param wc027EnrichmentFeedProducerConfigurationJson string = ''

@description('Exact digest-pinned image deployed to the WC-027 enrichment/feed producer Job.')
param wc027EnrichmentFeedProducerImage string = ''

@description('Exact non-secret ACR pull binding JSON emitted by the WC-027 enrichment/feed producer deployment.')
param wc027EnrichmentFeedProducerImagePullBindingJson string = ''

@description('Explicit confirmation that the separate WC-027 guidance publication-request producer is deployed and ready. False by default keeps the complete production chain fail-closed.')
param wc027RequestProducerReady bool = false

@description('Exact deployed WC-027 guidance publication-request producer Job resource ID.')
param wc027RequestProducerJobResourceId string = ''

@description('SHA-256 digest of the exact deployed guidance publication-request producer configuration.')
param wc027RequestProducerConfigurationDigest string = ''

@description('Exact non-secret configuration JSON deployed to the guidance publication-request producer Job.')
param wc027RequestProducerConfigurationJson string = ''

@description('Exact digest-pinned image deployed to the guidance publication-request producer Job.')
param wc027RequestProducerImage string = ''

@description('Exact non-secret ACR pull binding JSON emitted by the guidance publication-request producer deployment.')
param wc027RequestProducerImagePullBindingJson string = ''

@description('Explicit confirmation that the separately governed PublishedGuidanceAuthorityBinding.v2 publisher is deployed and ready. False by default keeps Notification v2 fail-closed even when a producer Job exists.')
param wc027PublisherReady bool = false

@description('Exact deployed WC-027 guidance-authority publisher Job resource ID.')
param wc027PublisherJobResourceId string = ''

@description('SHA-256 digest of the exact deployed guidance-authority publisher configuration.')
param wc027PublisherConfigurationDigest string = ''

@description('Exact non-secret configuration JSON deployed to the guidance-authority publisher Job.')
param wc027PublisherConfigurationJson string = ''

@description('Exact digest-pinned image deployed to the guidance-authority publisher Job.')
param wc027PublisherImage string = ''

@description('Exact JSON emitted by the bounded managed-identity publisher digest-pull check, including the complete live effective-ACR-access proof for all three PR #103 identities.')
param wc027PublisherImagePullEvidenceJson string = ''

@description('Trusted UTC instant used to reject stale WC-027 ACR readiness evidence.')
param wc027ReadinessEvaluationTimeUtc string = utcNow('yyyy-MM-ddTHH:mm:ss.fffZ')

@description('Confirms the exact legacy WC-016 resources and RBAC were removed and the cleanup script reported zero residuals.')
param wc016LegacyCleanupConfirmed bool = false

@description('Existing Azure Container Registry login server hosting the presentation image.')
@minLength(1)
@maxLength(255)
param presentationImageRegistryServer string

@description('Resource ID of the existing Azure Container Registry hosting the presentation image.')
@minLength(1)
@maxLength(2048)
param presentationImageRegistryResourceId string

@description('Reviewed role-assignment permissions mode for the presentation image registry.')
@allowed([
  'LegacyRegistryPermissions'
  'AbacRepositoryPermissions'
])
param presentationImageRegistryRoleAssignmentMode string

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
var rejectedIncidentFixtureFingerprint = 'sha256:22be507b9bc31492e1dec2c0f8e9db1c75ca999c13dfb6670e2cce2320ee1a2e'
var validatedWc016RuntimeEnabled = wc016RuntimeEnabled && !wc016LegacyCleanupConfirmed
  ? fail('WC-016 cannot be activated until the exact legacy cleanup report confirms zero residuals')
  : wc016RuntimeEnabled && signingKeyFingerprint == rejectedIncidentFixtureFingerprint
    ? fail('WC-016 cannot be activated with the checked-in incident trust fixture; pin the deployed key first')
    : wc016RuntimeEnabled
var wc027RequestProducerJobResourceIdRawSegments = split(
  wc027RequestProducerJobResourceId,
  '/'
)
var wc027RequestProducerJobResourceIdSegments = concat(
  wc027RequestProducerJobResourceIdRawSegments,
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
var wc027RequestProducerJobResourceIdShapeValid = length(wc027RequestProducerJobResourceIdRawSegments) == 9 && empty(wc027RequestProducerJobResourceIdSegments[0]) && wc027RequestProducerJobResourceIdSegments[1] == 'subscriptions' && !empty(wc027RequestProducerJobResourceIdSegments[2]) && toLower(wc027RequestProducerJobResourceIdSegments[2]) == toLower(subscription().subscriptionId) && wc027RequestProducerJobResourceIdSegments[3] == 'resourceGroups' && !empty(wc027RequestProducerJobResourceIdSegments[4]) && toLower(wc027RequestProducerJobResourceIdSegments[4]) == toLower(foundationResourceGroupName) && wc027RequestProducerJobResourceIdSegments[5] == 'providers' && wc027RequestProducerJobResourceIdSegments[6] == 'Microsoft.App' && wc027RequestProducerJobResourceIdSegments[7] == 'jobs' && !empty(wc027RequestProducerJobResourceIdSegments[8]) && !contains(wc027RequestProducerJobResourceId, '//') && !contains(wc027RequestProducerJobResourceId, '?') && !contains(wc027RequestProducerJobResourceId, '#') && !contains(wc027RequestProducerJobResourceId, '%')
var wc027RequestProducerRuntimeJobIdMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdShapeValid
  ? toLower(wc027RequestProducerRuntimeId!.outputs.runtimeJobResourceId) == toLower(wc027RequestProducerJobResourceId)
  : false
var wc027RequestProducerJobResourceIdValid = wc027RequestProducerJobResourceIdShapeValid && (!wc027RequestProducerReady || wc027RequestProducerRuntimeJobIdMatches)
var wc027RequestProducerConfigurationDigestHex = replace(
  wc027RequestProducerConfigurationDigest,
  'sha256:',
  ''
)
var wc027RequestProducerConfigurationDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027RequestProducerConfigurationDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027RequestProducerConfigurationDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027RequestProducerConfigurationDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027RequestProducerConfigurationDigestValid = length(wc027RequestProducerConfigurationDigest) == 71 && wc027RequestProducerConfigurationDigest == toLower(
  wc027RequestProducerConfigurationDigest
) && empty(wc027RequestProducerConfigurationDigestInvalidCharacters)
var wc027RequestProducerImageDigest = contains(wc027RequestProducerImage, '@sha256:')
  ? last(split(wc027RequestProducerImage, '@sha256:'))
  : ''
var wc027RequestProducerImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027RequestProducerImageDigest,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027RequestProducerImageInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027RequestProducerImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027RequestProducerImageValid = wc027RequestProducerImage == toLower(wc027RequestProducerImage) && length(wc027RequestProducerImageDigest) == 64 && empty(wc027RequestProducerImageInvalidCharacters) && wc027RequestProducerImageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
var wc027ReviewedPublisherKedaPollingIntervalSeconds = 30
var wc027ReviewedPublisherColdStartSeconds = 30
var wc027ReviewedPublisherConnectionSetupSeconds = 30
var wc027ReviewedPublisherProcessingSeconds = 60
var wc027ReviewedPublisherCasMarginSeconds = 5
var wc027ReviewedPublisherMinimumRemainingLifetimeSeconds = wc027ReviewedPublisherKedaPollingIntervalSeconds + wc027ReviewedPublisherColdStartSeconds + wc027ReviewedPublisherConnectionSetupSeconds + wc027ReviewedPublisherProcessingSeconds
var wc027ReviewedFeedKedaPollingIntervalSeconds = 30
var wc027ReviewedFeedColdStartSeconds = 30
var wc027ReviewedFeedConnectionSetupSeconds = 30
var wc027ReviewedFeedProcessingSeconds = 60
var wc027ReviewedFeedDeliveryJitterSeconds = 30
var wc027ReviewedFeedIrreversibleWriteMarginSeconds = 15
var wc027ReviewedFeedMinimumRemainingLifetimeSeconds = wc027ReviewedFeedKedaPollingIntervalSeconds + wc027ReviewedFeedColdStartSeconds + wc027ReviewedFeedConnectionSetupSeconds + wc027ReviewedFeedProcessingSeconds
var wc027ReviewedFeedTriggerRecoverySeconds = 300
var wc027ReviewedMinimumRemainingLifetimeSeconds = wc027ReviewedPublisherMinimumRemainingLifetimeSeconds
var wc027ParsedRequestProducerConfiguration = json(
  empty(wc027RequestProducerConfigurationJson)
    ? '{"deliveryBudget":{"feedColdStartSeconds":0,"feedConnectionSetupSeconds":0,"feedDeliveryJitterSeconds":0,"feedIrreversibleWriteMarginSeconds":0,"feedKedaPollingIntervalSeconds":0,"feedMinimumRemainingLifetimeSeconds":0,"feedProcessingSeconds":0,"feedTriggerRecoverySeconds":0,"minimumRemainingLifetimeSeconds":0,"publisherCasMarginSeconds":0,"publisherColdStartSeconds":0,"publisherConnectionSetupSeconds":0,"publisherKedaPollingIntervalSeconds":0,"publisherMinimumRemainingLifetimeSeconds":0,"publisherProcessingSeconds":0},"deploymentBinding":{"attachedIdentityResourceIds":[],"bindingEvidenceId":"","rbacResourceIds":[]},"requestSigningKey":{"keyFingerprint":"","keyId":"","keyVaultKeyId":""},"serviceBus":{"inputQueueName":"","namespace":"","outputQueueName":"","receiverIdentityResourceId":""}}'
    : wc027RequestProducerConfigurationJson
)
var wc027ParsedRequestProducerImagePullBinding = json(
  empty(wc027RequestProducerImagePullBindingJson)
    ? '{"anonymousPullEnabled":true,"condition":null,"conditionVersion":null,"image":"","principalId":"","registryResourceId":"","repositoryName":"","roleAssignmentMode":"","roleAssignmentResourceId":"","roleDefinitionId":"","schemaVersion":""}'
    : wc027RequestProducerImagePullBindingJson
)
var wc027RequestProducerImagePullIdentityResourceId = !empty(wc027RequestProducerConfigurationJson)
  ? wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityResourceId
  : ''
var wc027RequestProducerImagePullIdentityResourceIdRawSegments = split(
  wc027RequestProducerImagePullIdentityResourceId,
  '/'
)
var wc027RequestProducerImagePullIdentityResourceIdSegments = concat(
  wc027RequestProducerImagePullIdentityResourceIdRawSegments,
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
var wc027RequestProducerImagePullIdentityResourceIdValid = length(wc027RequestProducerImagePullIdentityResourceIdRawSegments) == 9 && empty(wc027RequestProducerImagePullIdentityResourceIdSegments[0]) && wc027RequestProducerImagePullIdentityResourceIdSegments[1] == 'subscriptions' && !empty(wc027RequestProducerImagePullIdentityResourceIdSegments[2]) && wc027RequestProducerImagePullIdentityResourceIdSegments[3] == 'resourceGroups' && !empty(wc027RequestProducerImagePullIdentityResourceIdSegments[4]) && wc027RequestProducerImagePullIdentityResourceIdSegments[5] == 'providers' && wc027RequestProducerImagePullIdentityResourceIdSegments[6] == 'Microsoft.ManagedIdentity' && wc027RequestProducerImagePullIdentityResourceIdSegments[7] == 'userAssignedIdentities' && !empty(wc027RequestProducerImagePullIdentityResourceIdSegments[8]) && !contains(wc027RequestProducerImagePullIdentityResourceId, '//') && !contains(wc027RequestProducerImagePullIdentityResourceId, '?') && !contains(wc027RequestProducerImagePullIdentityResourceId, '#') && !contains(wc027RequestProducerImagePullIdentityResourceId, '%')
resource wc027RequestProducerImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (wc027RequestProducerReady && wc027RequestProducerImagePullIdentityResourceIdValid) {
  name: wc027RequestProducerImagePullIdentityResourceIdSegments[8]
  scope: resourceGroup(
    wc027RequestProducerImagePullIdentityResourceIdSegments[2],
    wc027RequestProducerImagePullIdentityResourceIdSegments[4]
  )
}
var wc027RequestProducerImagePullPrincipalMatches = wc027RequestProducerReady && wc027RequestProducerImagePullIdentityResourceIdValid && !empty(wc027RequestProducerImagePullBindingJson)
  ? toLower(wc027RequestProducerImagePullIdentity!.properties.principalId) == toLower(wc027ParsedRequestProducerImagePullBinding.principalId)
  : false
var wc027RequestProducerImagePullRegistryResourceIdRawSegments = split(
  wc027ParsedRequestProducerImagePullBinding.registryResourceId,
  '/'
)
var wc027RequestProducerImagePullRegistryResourceIdSegments = concat(
  wc027RequestProducerImagePullRegistryResourceIdRawSegments,
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
var wc027RequestProducerImagePullRegistryResourceIdValid = length(wc027RequestProducerImagePullRegistryResourceIdRawSegments) == 9 && empty(wc027RequestProducerImagePullRegistryResourceIdSegments[0]) && wc027RequestProducerImagePullRegistryResourceIdSegments[1] == 'subscriptions' && !empty(wc027RequestProducerImagePullRegistryResourceIdSegments[2]) && wc027RequestProducerImagePullRegistryResourceIdSegments[3] == 'resourceGroups' && !empty(wc027RequestProducerImagePullRegistryResourceIdSegments[4]) && wc027RequestProducerImagePullRegistryResourceIdSegments[5] == 'providers' && wc027RequestProducerImagePullRegistryResourceIdSegments[6] == 'Microsoft.ContainerRegistry' && wc027RequestProducerImagePullRegistryResourceIdSegments[7] == 'registries' && !empty(wc027RequestProducerImagePullRegistryResourceIdSegments[8]) && !contains(wc027ParsedRequestProducerImagePullBinding.registryResourceId, '//') && !contains(wc027ParsedRequestProducerImagePullBinding.registryResourceId, '?') && !contains(wc027ParsedRequestProducerImagePullBinding.registryResourceId, '#') && !contains(wc027ParsedRequestProducerImagePullBinding.registryResourceId, '%')
var wc027RequestProducerImagePullRegistryMatchesImage = wc027RequestProducerImagePullRegistryResourceIdValid && first(split(wc027ParsedRequestProducerImagePullBinding.image, '/')) == '${toLower(wc027RequestProducerImagePullRegistryResourceIdSegments[8])}.azurecr.io'
var wc027RequestProducerImagePullAssignmentScopedToRegistry = wc027RequestProducerImagePullRegistryResourceIdValid && startsWith(
  toLower(wc027ParsedRequestProducerImagePullBinding.roleAssignmentResourceId),
  '${toLower(wc027ParsedRequestProducerImagePullBinding.registryResourceId)}/providers/microsoft.authorization/roleassignments/'
)
var wc027RequestProducerImagePullAssignmentInDeploymentBinding = !empty(wc027RequestProducerConfigurationJson) && contains(
  map(
    wc027ParsedRequestProducerConfiguration.deploymentBinding.rbacResourceIds,
    resourceId => toLower(resourceId)
  ),
  toLower(wc027ParsedRequestProducerImagePullBinding.roleAssignmentResourceId)
)
var wc027RequestProducerDeliveryBudget = wc027ParsedRequestProducerConfiguration.deliveryBudget
var wc027RequestProducerDeliveryBudgetValid = !contains([
  wc027RequestProducerDeliveryBudget.publisherKedaPollingIntervalSeconds == wc027ReviewedPublisherKedaPollingIntervalSeconds
  wc027RequestProducerDeliveryBudget.publisherColdStartSeconds == wc027ReviewedPublisherColdStartSeconds
  wc027RequestProducerDeliveryBudget.publisherConnectionSetupSeconds == wc027ReviewedPublisherConnectionSetupSeconds
  wc027RequestProducerDeliveryBudget.publisherProcessingSeconds == wc027ReviewedPublisherProcessingSeconds
  wc027RequestProducerDeliveryBudget.publisherCasMarginSeconds == wc027ReviewedPublisherCasMarginSeconds
  wc027RequestProducerDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027ReviewedPublisherMinimumRemainingLifetimeSeconds
  wc027RequestProducerDeliveryBudget.feedKedaPollingIntervalSeconds == wc027ReviewedFeedKedaPollingIntervalSeconds
  wc027RequestProducerDeliveryBudget.feedColdStartSeconds == wc027ReviewedFeedColdStartSeconds
  wc027RequestProducerDeliveryBudget.feedConnectionSetupSeconds == wc027ReviewedFeedConnectionSetupSeconds
  wc027RequestProducerDeliveryBudget.feedProcessingSeconds == wc027ReviewedFeedProcessingSeconds
  wc027RequestProducerDeliveryBudget.feedDeliveryJitterSeconds == wc027ReviewedFeedDeliveryJitterSeconds
  wc027RequestProducerDeliveryBudget.feedIrreversibleWriteMarginSeconds == wc027ReviewedFeedIrreversibleWriteMarginSeconds
  wc027RequestProducerDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027ReviewedFeedMinimumRemainingLifetimeSeconds
  wc027RequestProducerDeliveryBudget.feedTriggerRecoverySeconds == wc027ReviewedFeedTriggerRecoverySeconds
  wc027RequestProducerDeliveryBudget.minimumRemainingLifetimeSeconds == wc027ReviewedMinimumRemainingLifetimeSeconds
  wc027RequestProducerDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027RequestProducerDeliveryBudget.publisherKedaPollingIntervalSeconds + wc027RequestProducerDeliveryBudget.publisherColdStartSeconds + wc027RequestProducerDeliveryBudget.publisherConnectionSetupSeconds + wc027RequestProducerDeliveryBudget.publisherProcessingSeconds
  wc027RequestProducerDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027RequestProducerDeliveryBudget.feedKedaPollingIntervalSeconds + wc027RequestProducerDeliveryBudget.feedColdStartSeconds + wc027RequestProducerDeliveryBudget.feedConnectionSetupSeconds + wc027RequestProducerDeliveryBudget.feedProcessingSeconds
  wc027RequestProducerDeliveryBudget.minimumRemainingLifetimeSeconds == wc027RequestProducerDeliveryBudget.publisherMinimumRemainingLifetimeSeconds
], false)
var wc027RequestProducerImageRegistryServer = first(split(wc027RequestProducerImage, '/'))
var wc027RequestProducerExpectedIdentityResourceIds = map(
  wc027ParsedRequestProducerConfiguration.deploymentBinding.attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var wc027RequestProducerConfiguredIdentityResourceIds = wc027RequestProducerReady && !empty(wc027RequestProducerConfigurationJson)
  ? map([
      wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityResourceId
      wc027ParsedRequestProducerConfiguration.serviceBus.senderIdentityResourceId
      wc027ParsedRequestProducerConfiguration.incidentLifecycleAssets.identityResourceId
      wc027ParsedRequestProducerConfiguration.contextAuthoritySource.identityResourceId
      wc027ParsedRequestProducerConfiguration.requestOutbox.readerIdentityResourceId
      wc027ParsedRequestProducerConfiguration.requestOutbox.writerIdentityResourceId
      wc027ParsedRequestProducerConfiguration.incidentKey.identityResourceId
      wc027ParsedRequestProducerConfiguration.correlationBindingKey.identityResourceId
      wc027ParsedRequestProducerConfiguration.requestSigningKey.signerIdentityResourceId
      wc027ParsedRequestProducerConfiguration.requestSigningKey.verifierIdentityResourceId
    ], identityResourceId => toLower(identityResourceId))
  : []
var wc027DistinctRequestProducerConfiguredIdentityResourceIds = union(
  wc027RequestProducerConfiguredIdentityResourceIds,
  wc027RequestProducerConfiguredIdentityResourceIds
)
var wc027RequestProducerConfigurationIdentitiesMatchBinding = !empty(wc027DistinctRequestProducerConfiguredIdentityResourceIds) && length(wc027RequestProducerExpectedIdentityResourceIds) == length(union(wc027RequestProducerExpectedIdentityResourceIds, wc027RequestProducerExpectedIdentityResourceIds)) && length(wc027DistinctRequestProducerConfiguredIdentityResourceIds) == length(wc027RequestProducerExpectedIdentityResourceIds) && length(union(wc027DistinctRequestProducerConfiguredIdentityResourceIds, wc027RequestProducerExpectedIdentityResourceIds)) == length(wc027DistinctRequestProducerConfiguredIdentityResourceIds)
var wc027RequestProducerRbacResourceIds = wc027ParsedRequestProducerConfiguration.deploymentBinding.rbacResourceIds
var wc027RequestProducerRbacEvidenceMatches = !empty(wc027RequestProducerRbacResourceIds) && guid(
  join(wc027RequestProducerRbacResourceIds, '|')
) == wc027ParsedRequestProducerConfiguration.deploymentBinding.bindingEvidenceId
var wc027RequestProducerAttachedIdentityResourceIds = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? map(items(wc027RequestProducerJob!.identity.?userAssignedIdentities ?? {}), identity => toLower(identity.key))
  : []
var wc027RequestProducerIdentitiesMatch = !empty(wc027RequestProducerExpectedIdentityResourceIds) && length(
  wc027RequestProducerAttachedIdentityResourceIds
) == length(wc027RequestProducerExpectedIdentityResourceIds) && length(union(
  wc027RequestProducerAttachedIdentityResourceIds,
  wc027RequestProducerExpectedIdentityResourceIds
)) == length(wc027RequestProducerExpectedIdentityResourceIds)
var wc027RequestProducerRuntimeIdentityOverlap = intersection(
  wc027DistinctRequestProducerConfiguredIdentityResourceIds,
  wc027DistinctConfiguredIdentityResourceIds
)
var wc027RequestProducerPublisherIdentityOverlap = intersection(
  wc027DistinctRequestProducerConfiguredIdentityResourceIds,
  wc027DistinctPublisherConfiguredIdentityResourceIds
)
var wc027RequestProducerHasExactContainerCount = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? length(wc027RequestProducerJob!.properties.template.containers) == 1
  : false
var wc027RequestProducerIdentityTypeMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? (wc027RequestProducerJob!.identity.?type ?? '') == 'UserAssigned'
  : false
var wc027RequestProducerTemplateMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid && wc027RequestProducerHasExactContainerCount && !empty(wc027RequestProducerConfigurationJson)
  ? !contains([
      wc027RequestProducerJob!.properties.template.containers[0].name == 'wc027-guidance-publication-request-producer'
      wc027RequestProducerJob!.properties.template.containers[0].image == wc027RequestProducerImage
      length(wc027RequestProducerJob!.properties.template.containers[0].command) == 1
      wc027RequestProducerJob!.properties.template.containers[0].command[0] == 'athena-context'
      length(wc027RequestProducerJob!.properties.template.containers[0].args) == 1
      wc027RequestProducerJob!.properties.template.containers[0].args[0] == 'wc027-guidance-publication-request-producer'
      length(wc027RequestProducerJob!.properties.template.containers[0].env) == 2
      wc027RequestProducerJob!.properties.template.containers[0].env[0].name == 'AZURE_CLIENT_ID'
      wc027RequestProducerJob!.properties.template.containers[0].env[0].value == wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityClientId
      wc027RequestProducerJob!.properties.template.containers[0].env[1].name == 'ATHENA_WC027_GUIDANCE_REQUEST_PRODUCER_CONFIG_JSON'
      wc027RequestProducerJob!.properties.template.containers[0].env[1].value == wc027RequestProducerConfigurationJson
      wc027RequestProducerJob!.properties.template.containers[0].resources.cpu == 1
      wc027RequestProducerJob!.properties.template.containers[0].resources.memory == '2Gi'
      empty(wc027RequestProducerJob!.properties.template.containers[0].?probes ?? [])
      empty(wc027RequestProducerJob!.properties.template.containers[0].?volumeMounts ?? [])
      empty(wc027RequestProducerJob!.properties.template.?initContainers ?? [])
      empty(wc027RequestProducerJob!.properties.template.?volumes ?? [])
    ], false)
  : false
var wc027RequestProducerExecutionConfigurationMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? !contains([
      wc027RequestProducerJob!.properties.environmentId == azureMcp.outputs.managedEnvironmentResourceId
      wc027RequestProducerJob!.properties.configuration.replicaTimeout == 900
      wc027RequestProducerJob!.properties.configuration.replicaRetryLimit == 0
      wc027RequestProducerJob!.properties.configuration.triggerType == 'Event'
      empty(wc027RequestProducerJob!.properties.configuration.?identitySettings ?? [])
      empty(wc027RequestProducerJob!.properties.configuration.?secrets ?? [])
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.parallelism == 1
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.replicaCompletionCount == 1
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.minExecutions == 0
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.maxExecutions == 1
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.pollingInterval == 30
      length(wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
    ], false)
  : false
var wc027RequestProducerHasExactScalerRuleCount = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? length(wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
  : false
var wc027RequestProducerScalerMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid && !empty(wc027RequestProducerConfigurationJson) && wc027RequestProducerHasExactScalerRuleCount
  ? !contains([
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].name == 'wc027-guidance-publication-request-input'
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].type == 'azure-servicebus'
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].identity == wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityResourceId
      empty(wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].?auth ?? [])
      length(items(wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata)) == 5
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.namespace == first(split(wc027ParsedRequestProducerConfiguration.serviceBus.namespace, '.'))
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.queueName == wc027ParsedRequestProducerConfiguration.serviceBus.inputQueueName
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.messageCount == '1'
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.cloud == 'AzurePublicCloud'
      wc027RequestProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.isSessionsEnabled == 'true'
    ], false)
  : false
var wc027RequestProducerHasExactRegistryCount = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? length(wc027RequestProducerJob!.properties.configuration.registries) == 1
  : false
var wc027RequestProducerRegistryMatches = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid && !empty(wc027RequestProducerConfigurationJson) && wc027RequestProducerHasExactRegistryCount
  ? !contains([
      wc027RequestProducerJob!.properties.configuration.registries[0].server == wc027RequestProducerImageRegistryServer
      wc027RequestProducerJob!.properties.configuration.registries[0].identity == wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityResourceId
      length(items(wc027RequestProducerJob!.properties.configuration.registries[0])) == 2
    ], false)
  : false
var wc027RequestProducerTagsMatch = wc027RequestProducerReady && wc027RequestProducerJobResourceIdValid
  ? !contains([
      wc027RequestProducerJob!.tags.runtimeConfigurationDigest == wc027RequestProducerConfigurationDigest
      wc027RequestProducerJob!.tags.enrichmentRuntimeConfigurationDigest == wc027EnrichmentFeedProducerConfigurationDigest
    ], false)
  : false
var validatedWc027RequestProducerReady = wc027RequestProducerReady && !wc027EffectiveAcrAssignmentsVerified
  ? fail('WC-027 request producer requires PR #102-equivalent full role-definition resolution proving no extra direct, inherited, group-derived, or sibling-registry pull-capable assignment')
  : wc027RequestProducerReady && !wc027RequestProducerJobResourceIdValid
    ? fail('wc027RequestProducerJobResourceId must identify one Microsoft.App/jobs resource')
    : wc027RequestProducerReady && !wc027RequestProducerConfigurationDigestValid
    ? fail('WC-027 request producer requires the exact deployed configuration digest')
    : wc027RequestProducerReady && empty(wc027RequestProducerConfigurationJson)
      ? fail('WC-027 request producer requires the exact deployed configuration JSON')
      : wc027RequestProducerReady && (empty(wc027EnrichmentFeedProducerConfigurationJson) || !wc027ConfigurationDigestValid)
        ? fail('WC-027 request producer requires the exact deployed enrichment runtime configuration')
        : wc027RequestProducerReady && !wc027ConfigurationIdentitiesMatchBinding
          ? fail('WC-027 enrichment runtime identities do not exactly match its deployment binding')
          : wc027RequestProducerReady && !wc027RequestProducerConfigurationIdentitiesMatchBinding
            ? fail('WC-027 request producer configuration identities do not exactly match its deployment binding')
            : wc027RequestProducerReady && !empty(wc027RequestProducerRuntimeIdentityOverlap)
              ? fail('WC-027 request producer identities overlap the enrichment runtime identity boundary')
              : wc027RequestProducerReady && wc027PublisherReady && !empty(wc027RequestProducerPublisherIdentityOverlap)
                ? fail('WC-027 request producer identities overlap the publisher identity boundary')
                : wc027RequestProducerReady && !wc027RequestProducerImageValid
                  ? fail('WC-027 request producer requires the exact digest-pinned deployed image')
                  : wc027RequestProducerReady && !wc027RequestProducerIdentityTypeMatches
                    ? fail('WC-027 request producer Job must use only user-assigned identities')
                    : wc027RequestProducerReady && !wc027RequestProducerHasExactContainerCount
                      ? fail('WC-027 request producer Job must contain exactly one reviewed container')
                      : wc027RequestProducerReady && !wc027RequestProducerTemplateMatches
                        ? fail('WC-027 request producer Job execution template does not exactly match')
                        : wc027RequestProducerReady && !wc027RequestProducerExecutionConfigurationMatches
                          ? fail('WC-027 request producer Job replica and concurrency configuration does not exactly match')
                          : wc027RequestProducerReady && !wc027RequestProducerScalerMatches
                            ? fail('WC-027 request producer Job scaler configuration does not exactly match')
                            : wc027RequestProducerReady && wc027ParsedRequestProducerConfiguration.serviceBus.inputQueueName != 'wc027-guidance-publication-inputs'
                              ? fail('WC-027 request producer input queue does not match the production chain')
                              : wc027RequestProducerReady && wc027ParsedRequestProducerConfiguration.serviceBus.outputQueueName != 'wc027-guidance-authority-requests'
                                ? fail('WC-027 request producer output queue does not match the authority publisher')
                                : wc027RequestProducerReady && !wc027RequestProducerRegistryMatches
                                  ? fail('WC-027 request producer Job registry configuration does not exactly match')
                                  : wc027RequestProducerReady && !wc027RequestProducerTagsMatch
                                    ? fail('WC-027 request producer Job configuration digest tags do not match')
                                    : wc027RequestProducerReady && !wc027RequestProducerDeliveryBudgetValid
                                      ? fail('WC-027 request producer delivery budget does not match the reviewed publisher and feed delivery phases')
                                      : wc027RequestProducerReady && !wc027RuntimeDeliveryBudgetValid
                                        ? fail('WC-027 enrichment runtime delivery budget does not match the reviewed publisher and feed delivery phases')
                                        : wc027RequestProducerReady && !wc027RequestProducerRuntimeDeliveryBudgetsMatch
                                          ? fail('WC-027 request producer and enrichment runtime delivery budgets do not match')
                                          : wc027RequestProducerReady && !wc027RequestProducerRbacEvidenceMatches
                                            ? fail('WC-027 request producer RBAC evidence does not match its deployed configuration')
                                            : wc027RequestProducerReady && !wc027RequestProducerIdentitiesMatch
                                              ? fail('WC-027 request producer identities do not match its deployed configuration')
                                              : wc027RequestProducerReady
var wc027ProducerJobResourceIdRawSegments = split(
  wc027EnrichmentFeedProducerJobResourceId,
  '/'
)
var wc027PublisherJobResourceIdRawSegments = split(wc027PublisherJobResourceId, '/')
var wc027PublisherJobResourceIdSegments = concat(
  wc027PublisherJobResourceIdRawSegments,
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
var wc027PublisherJobResourceIdShapeValid = length(wc027PublisherJobResourceIdRawSegments) == 9 && empty(wc027PublisherJobResourceIdSegments[0]) && wc027PublisherJobResourceIdSegments[1] == 'subscriptions' && !empty(wc027PublisherJobResourceIdSegments[2]) && toLower(wc027PublisherJobResourceIdSegments[2]) == toLower(subscription().subscriptionId) && wc027PublisherJobResourceIdSegments[3] == 'resourceGroups' && !empty(wc027PublisherJobResourceIdSegments[4]) && toLower(wc027PublisherJobResourceIdSegments[4]) == toLower(foundationResourceGroupName) && wc027PublisherJobResourceIdSegments[5] == 'providers' && wc027PublisherJobResourceIdSegments[6] == 'Microsoft.App' && wc027PublisherJobResourceIdSegments[7] == 'jobs' && !empty(wc027PublisherJobResourceIdSegments[8]) && !contains(wc027PublisherJobResourceId, '//') && !contains(wc027PublisherJobResourceId, '?') && !contains(wc027PublisherJobResourceId, '#') && !contains(wc027PublisherJobResourceId, '%')
var wc027PublisherRuntimeJobIdMatches = wc027PublisherReady && wc027PublisherJobResourceIdShapeValid
  ? toLower(wc027PublisherRuntimeId!.outputs.runtimeJobResourceId) == toLower(wc027PublisherJobResourceId)
  : false
var wc027PublisherJobResourceIdValid = wc027PublisherJobResourceIdShapeValid && (!wc027PublisherReady || wc027PublisherRuntimeJobIdMatches)
var wc027PublisherConfigurationDigestHex = replace(wc027PublisherConfigurationDigest, 'sha256:', '')
var wc027PublisherConfigurationDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027PublisherConfigurationDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027PublisherConfigurationDigestValid = length(wc027PublisherConfigurationDigest) == 71 && wc027PublisherConfigurationDigest == toLower(wc027PublisherConfigurationDigest) && empty(wc027PublisherConfigurationDigestInvalidCharacters)
var wc027PublisherImageDigest = contains(wc027PublisherImage, '@sha256:')
  ? last(split(wc027PublisherImage, '@sha256:'))
  : ''
var wc027PublisherImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027PublisherImageDigest,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027PublisherImageInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027PublisherImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027PublisherImageValid = wc027PublisherImage == toLower(wc027PublisherImage) && length(wc027PublisherImageDigest) == 64 && empty(wc027PublisherImageInvalidCharacters) && wc027PublisherImageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
var wc027ParsedPublisherConfiguration = json(
  empty(wc027PublisherConfigurationJson)
    ? '{"deliveryBudget":{"feedColdStartSeconds":0,"feedConnectionSetupSeconds":0,"feedDeliveryJitterSeconds":0,"feedIrreversibleWriteMarginSeconds":0,"feedKedaPollingIntervalSeconds":0,"feedMinimumRemainingLifetimeSeconds":0,"feedProcessingSeconds":0,"feedTriggerRecoverySeconds":0,"minimumRemainingLifetimeSeconds":0,"publisherCasMarginSeconds":0,"publisherColdStartSeconds":0,"publisherConnectionSetupSeconds":0,"publisherKedaPollingIntervalSeconds":0,"publisherMinimumRemainingLifetimeSeconds":0,"publisherProcessingSeconds":0},"deploymentBinding":{"attachedIdentityResourceIds":[],"bindingEvidenceId":"","rbacResourceIds":[]},"enrichmentRuntimeConfiguration":{},"imagePull":{"anonymousPullEnabled":true,"condition":null,"conditionVersion":null,"identityClientId":"","identityPrincipalId":"","identityResourceId":"","image":"","registryResourceId":"","registryServer":"","repositoryName":"","roleAssignmentMode":"","roleAssignmentResourceId":"","roleDefinitionId":""},"requestOutbox":{"blobEndpoint":"","containerName":"","identityResourceId":""},"serviceBus":{"brokerIdentityResourceId":"","namespace":"","requestQueueName":"","requestSubmitterIdentityResourceId":""}}'
    : wc027PublisherConfigurationJson
)
var wc027PublisherImagePullIdentityResourceId = !empty(wc027PublisherConfigurationJson)
  ? wc027ParsedPublisherConfiguration.imagePull.identityResourceId
  : ''
var wc027PublisherImagePullIdentityResourceIdRawSegments = split(
  wc027PublisherImagePullIdentityResourceId,
  '/'
)
var wc027PublisherImagePullIdentityResourceIdSegments = concat(
  wc027PublisherImagePullIdentityResourceIdRawSegments,
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
var wc027PublisherImagePullIdentityResourceIdValid = length(wc027PublisherImagePullIdentityResourceIdRawSegments) == 9 && empty(wc027PublisherImagePullIdentityResourceIdSegments[0]) && wc027PublisherImagePullIdentityResourceIdSegments[1] == 'subscriptions' && !empty(wc027PublisherImagePullIdentityResourceIdSegments[2]) && wc027PublisherImagePullIdentityResourceIdSegments[3] == 'resourceGroups' && !empty(wc027PublisherImagePullIdentityResourceIdSegments[4]) && wc027PublisherImagePullIdentityResourceIdSegments[5] == 'providers' && wc027PublisherImagePullIdentityResourceIdSegments[6] == 'Microsoft.ManagedIdentity' && wc027PublisherImagePullIdentityResourceIdSegments[7] == 'userAssignedIdentities' && !empty(wc027PublisherImagePullIdentityResourceIdSegments[8]) && !contains(wc027PublisherImagePullIdentityResourceId, '//') && !contains(wc027PublisherImagePullIdentityResourceId, '?') && !contains(wc027PublisherImagePullIdentityResourceId, '#') && !contains(wc027PublisherImagePullIdentityResourceId, '%')
resource wc027PublisherImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (wc027PublisherReady && wc027PublisherImagePullIdentityResourceIdValid) {
  name: wc027PublisherImagePullIdentityResourceIdSegments[8]
  scope: resourceGroup(
    wc027PublisherImagePullIdentityResourceIdSegments[2],
    wc027PublisherImagePullIdentityResourceIdSegments[4]
  )
}
var wc027PublisherImagePullIdentityMatches = wc027PublisherReady && wc027PublisherImagePullIdentityResourceIdValid && !empty(wc027PublisherConfigurationJson)
  ? !contains([
      toLower(wc027PublisherImagePullIdentity!.id) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityResourceId)
      toLower(wc027PublisherImagePullIdentity!.properties.clientId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityClientId)
      toLower(wc027PublisherImagePullIdentity!.properties.principalId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityPrincipalId)
      toLower(wc027ParsedPublisherConfiguration.imagePull.identityResourceId) == toLower(wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId)
    ], false)
  : false
var wc027PublisherImagePullRegistryResourceIdRawSegments = split(
  wc027ParsedPublisherConfiguration.imagePull.registryResourceId,
  '/'
)
var wc027PublisherImagePullRegistryResourceIdSegments = concat(
  wc027PublisherImagePullRegistryResourceIdRawSegments,
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
var wc027PublisherImagePullRegistryResourceIdValid = length(wc027PublisherImagePullRegistryResourceIdRawSegments) == 9 && empty(wc027PublisherImagePullRegistryResourceIdSegments[0]) && wc027PublisherImagePullRegistryResourceIdSegments[1] == 'subscriptions' && !empty(wc027PublisherImagePullRegistryResourceIdSegments[2]) && wc027PublisherImagePullRegistryResourceIdSegments[3] == 'resourceGroups' && !empty(wc027PublisherImagePullRegistryResourceIdSegments[4]) && wc027PublisherImagePullRegistryResourceIdSegments[5] == 'providers' && wc027PublisherImagePullRegistryResourceIdSegments[6] == 'Microsoft.ContainerRegistry' && wc027PublisherImagePullRegistryResourceIdSegments[7] == 'registries' && !empty(wc027PublisherImagePullRegistryResourceIdSegments[8]) && !contains(wc027ParsedPublisherConfiguration.imagePull.registryResourceId, '//') && !contains(wc027ParsedPublisherConfiguration.imagePull.registryResourceId, '?') && !contains(wc027ParsedPublisherConfiguration.imagePull.registryResourceId, '#') && !contains(wc027ParsedPublisherConfiguration.imagePull.registryResourceId, '%')
var wc027ParsedPublisherImagePullEvidence = json(
  empty(wc027PublisherImagePullEvidenceJson)
    ? '{"anonymousPullEnabled":true,"attempts":0,"condition":null,"conditionVersion":null,"effectiveAccess":{"acrEscalationPathsChecked":false,"anonymousPullEnabled":true,"convergedMembershipReadbacks":false,"directAssignmentsComplete":false,"directMembershipTraversalComplete":false,"evidenceDigest":"","exactAssignmentReadbacksComplete":false,"expectedAssignmentCount":0,"expectedAssignmentIds":[],"extraPullCapableAssignmentIds":[],"governedSubscriptionIds":[],"inheritedAssignmentsComplete":false,"principalIds":[],"pullCapableAssignmentCount":0,"registryResourceIds":[],"reviewedAssignments":[],"roleAssignmentScheduleInstancesComplete":false,"roleDefinitionsResolved":false,"schemaVersion":"","siblingRegistriesChecked":false,"tenantId":"","tenantSubscriptionHierarchyComplete":false,"transitiveGroupsComplete":false,"verified":false,"verifiedAt":"1970-01-01T00:00:00.000Z"},"image":"","managedIdentityClientId":"","managedIdentityPrincipalId":"","managedIdentityResourceId":"","maxAttempts":0,"registryResourceId":"","registryServer":"","repositoryName":"","roleAssignmentMode":"","roleAssignmentResourceId":"","roleDefinitionId":"","schemaVersion":"","success":false,"verifiedAt":"1970-01-01T00:00:00.000Z"}'
    : wc027PublisherImagePullEvidenceJson
)
var wc027ParsedProducerConfiguration = json(
  empty(wc027EnrichmentFeedProducerConfigurationJson)
    ? '{"deliveryBudget":{"feedColdStartSeconds":0,"feedConnectionSetupSeconds":0,"feedDeliveryJitterSeconds":0,"feedIrreversibleWriteMarginSeconds":0,"feedKedaPollingIntervalSeconds":0,"feedMinimumRemainingLifetimeSeconds":0,"feedProcessingSeconds":0,"feedTriggerRecoverySeconds":0,"minimumRemainingLifetimeSeconds":0,"publisherCasMarginSeconds":0,"publisherColdStartSeconds":0,"publisherConnectionSetupSeconds":0,"publisherKedaPollingIntervalSeconds":0,"publisherMinimumRemainingLifetimeSeconds":0,"publisherProcessingSeconds":0}}'
    : wc027EnrichmentFeedProducerConfigurationJson
)
var wc027ParsedFeedProducerImagePullBinding = json(
  empty(wc027EnrichmentFeedProducerImagePullBindingJson)
    ? '{"anonymousPullEnabled":true,"condition":null,"conditionVersion":null,"image":"","principalId":"","registryResourceId":"","repositoryName":"","roleAssignmentMode":"","roleAssignmentResourceId":"","roleDefinitionId":"","schemaVersion":""}'
    : wc027EnrichmentFeedProducerImagePullBindingJson
)
var wc027FeedProducerImagePullIdentityResourceId = !empty(wc027EnrichmentFeedProducerConfigurationJson)
  ? wc027ParsedProducerConfiguration.serviceBus.brokerIdentityResourceId
  : ''
var wc027FeedProducerImagePullIdentityResourceIdRawSegments = split(
  wc027FeedProducerImagePullIdentityResourceId,
  '/'
)
var wc027FeedProducerImagePullIdentityResourceIdSegments = concat(
  wc027FeedProducerImagePullIdentityResourceIdRawSegments,
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
var wc027FeedProducerImagePullIdentityResourceIdValid = length(wc027FeedProducerImagePullIdentityResourceIdRawSegments) == 9 && empty(wc027FeedProducerImagePullIdentityResourceIdSegments[0]) && wc027FeedProducerImagePullIdentityResourceIdSegments[1] == 'subscriptions' && !empty(wc027FeedProducerImagePullIdentityResourceIdSegments[2]) && wc027FeedProducerImagePullIdentityResourceIdSegments[3] == 'resourceGroups' && !empty(wc027FeedProducerImagePullIdentityResourceIdSegments[4]) && wc027FeedProducerImagePullIdentityResourceIdSegments[5] == 'providers' && wc027FeedProducerImagePullIdentityResourceIdSegments[6] == 'Microsoft.ManagedIdentity' && wc027FeedProducerImagePullIdentityResourceIdSegments[7] == 'userAssignedIdentities' && !empty(wc027FeedProducerImagePullIdentityResourceIdSegments[8]) && !contains(wc027FeedProducerImagePullIdentityResourceId, '//') && !contains(wc027FeedProducerImagePullIdentityResourceId, '?') && !contains(wc027FeedProducerImagePullIdentityResourceId, '#') && !contains(wc027FeedProducerImagePullIdentityResourceId, '%')
resource wc027FeedProducerImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (wc027FeedV2ProducerReady && wc027FeedProducerImagePullIdentityResourceIdValid) {
  name: wc027FeedProducerImagePullIdentityResourceIdSegments[8]
  scope: resourceGroup(
    wc027FeedProducerImagePullIdentityResourceIdSegments[2],
    wc027FeedProducerImagePullIdentityResourceIdSegments[4]
  )
}
var wc027FeedProducerImagePullPrincipalMatches = wc027FeedV2ProducerReady && wc027FeedProducerImagePullIdentityResourceIdValid && !empty(wc027EnrichmentFeedProducerImagePullBindingJson)
  ? toLower(wc027FeedProducerImagePullIdentity!.properties.principalId) == toLower(wc027ParsedFeedProducerImagePullBinding.principalId)
  : false
var wc027FeedProducerImagePullRegistryResourceIdRawSegments = split(
  wc027ParsedFeedProducerImagePullBinding.registryResourceId,
  '/'
)
var wc027FeedProducerImagePullRegistryResourceIdSegments = concat(
  wc027FeedProducerImagePullRegistryResourceIdRawSegments,
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
var wc027FeedProducerImagePullRegistryResourceIdValid = length(wc027FeedProducerImagePullRegistryResourceIdRawSegments) == 9 && empty(wc027FeedProducerImagePullRegistryResourceIdSegments[0]) && wc027FeedProducerImagePullRegistryResourceIdSegments[1] == 'subscriptions' && !empty(wc027FeedProducerImagePullRegistryResourceIdSegments[2]) && wc027FeedProducerImagePullRegistryResourceIdSegments[3] == 'resourceGroups' && !empty(wc027FeedProducerImagePullRegistryResourceIdSegments[4]) && wc027FeedProducerImagePullRegistryResourceIdSegments[5] == 'providers' && wc027FeedProducerImagePullRegistryResourceIdSegments[6] == 'Microsoft.ContainerRegistry' && wc027FeedProducerImagePullRegistryResourceIdSegments[7] == 'registries' && !empty(wc027FeedProducerImagePullRegistryResourceIdSegments[8]) && !contains(wc027ParsedFeedProducerImagePullBinding.registryResourceId, '//') && !contains(wc027ParsedFeedProducerImagePullBinding.registryResourceId, '?') && !contains(wc027ParsedFeedProducerImagePullBinding.registryResourceId, '#') && !contains(wc027ParsedFeedProducerImagePullBinding.registryResourceId, '%')
var wc027FeedProducerImagePullRegistryMatchesImage = wc027FeedProducerImagePullRegistryResourceIdValid && first(split(wc027ParsedFeedProducerImagePullBinding.image, '/')) == '${toLower(wc027FeedProducerImagePullRegistryResourceIdSegments[8])}.azurecr.io'
var wc027FeedProducerImagePullAssignmentScopedToRegistry = wc027FeedProducerImagePullRegistryResourceIdValid && startsWith(
  toLower(wc027ParsedFeedProducerImagePullBinding.roleAssignmentResourceId),
  '${toLower(wc027ParsedFeedProducerImagePullBinding.registryResourceId)}/providers/microsoft.authorization/roleassignments/'
)
var wc027FeedProducerImagePullAssignmentInDeploymentBinding = !empty(wc027EnrichmentFeedProducerConfigurationJson) && contains(
  map(
    wc027ParsedProducerConfiguration.deploymentBinding.rbacResourceIds,
    resourceId => toLower(resourceId)
  ),
  toLower(wc027ParsedFeedProducerImagePullBinding.roleAssignmentResourceId)
)
var wc027PublisherImageRegistryServer = first(split(wc027PublisherImage, '/'))
var wc027PublisherImageRepositoryReference = first(split(wc027PublisherImage, '@sha256:'))
var wc027PublisherImageRepositoryPrefix = '${wc027PublisherImageRegistryServer}/'
var wc027PublisherImageRepositoryName = startsWith(
  wc027PublisherImageRepositoryReference,
  wc027PublisherImageRepositoryPrefix
)
  ? substring(
      wc027PublisherImageRepositoryReference,
      length(wc027PublisherImageRepositoryPrefix)
    )
  : ''
var wc027PublisherExpectedRepositoryCondition = '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${wc027PublisherImageRepositoryName}\'))'
var wc027PublisherLegacyImagePullConditionValid = wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode == 'LegacyRegistryPermissions' && wc027ParsedPublisherConfiguration.imagePull.conditionVersion == null && wc027ParsedPublisherConfiguration.imagePull.condition == null
var wc027PublisherAbacImagePullConditionValid = wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode == 'AbacRepositoryPermissions' && wc027ParsedPublisherConfiguration.imagePull.conditionVersion == '2.0' && wc027ParsedPublisherConfiguration.imagePull.condition == wc027PublisherExpectedRepositoryCondition
var wc027PublisherImagePullModeConditionValid = wc027PublisherLegacyImagePullConditionValid || wc027PublisherAbacImagePullConditionValid
var wc027PublisherImagePullConditionValid = wc027ParsedPublisherConfiguration.imagePull.anonymousPullEnabled == false && wc027ParsedPublisherConfiguration.imagePull.repositoryName == wc027PublisherImageRepositoryName && wc027PublisherImagePullModeConditionValid
var wc027RequestProducerExpectedRepositoryName = 'athena/wc027-guidance-publication-request-producer'
var wc027RequestProducerExpectedRepositoryCondition = '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${wc027RequestProducerExpectedRepositoryName}\'))'
var wc027RequestProducerLegacyImagePullBindingValid = wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == 'LegacyRegistryPermissions' && wc027ParsedRequestProducerImagePullBinding.roleDefinitionId == '7f951dda-4ed3-4680-a7ca-43fe172d538d' && wc027ParsedRequestProducerImagePullBinding.conditionVersion == null && wc027ParsedRequestProducerImagePullBinding.condition == null
var wc027RequestProducerAbacImagePullBindingValid = wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == 'AbacRepositoryPermissions' && wc027ParsedRequestProducerImagePullBinding.roleDefinitionId == 'b93aa761-3e63-49ed-ac28-beffa264f7ac' && wc027ParsedRequestProducerImagePullBinding.conditionVersion == '2.0' && wc027ParsedRequestProducerImagePullBinding.condition == wc027RequestProducerExpectedRepositoryCondition
var wc027RequestProducerImagePullBindingValid = !empty(wc027RequestProducerImagePullBindingJson) && !contains([
  wc027ParsedRequestProducerImagePullBinding.schemaVersion == 'athena.wc027AcrPullBinding.v1'
  wc027ParsedRequestProducerImagePullBinding.image == wc027RequestProducerImage
  wc027ParsedRequestProducerImagePullBinding.anonymousPullEnabled == false
  wc027ParsedRequestProducerImagePullBinding.repositoryName == wc027RequestProducerExpectedRepositoryName
  !empty(wc027ParsedRequestProducerImagePullBinding.principalId)
  !empty(wc027ParsedRequestProducerImagePullBinding.registryResourceId)
  !empty(wc027ParsedRequestProducerImagePullBinding.roleAssignmentResourceId)
  wc027RequestProducerImagePullPrincipalMatches
  wc027RequestProducerImagePullRegistryMatchesImage
  wc027RequestProducerImagePullAssignmentScopedToRegistry
  wc027RequestProducerImagePullAssignmentInDeploymentBinding
  wc027RequestProducerLegacyImagePullBindingValid || wc027RequestProducerAbacImagePullBindingValid
], false)
var wc027FeedProducerExpectedRepositoryName = 'athena/wc027-enrichment-feed-producer'
var wc027FeedProducerExpectedRepositoryCondition = '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${wc027FeedProducerExpectedRepositoryName}\'))'
var wc027FeedProducerLegacyImagePullBindingValid = wc027ParsedFeedProducerImagePullBinding.roleAssignmentMode == 'LegacyRegistryPermissions' && wc027ParsedFeedProducerImagePullBinding.roleDefinitionId == '7f951dda-4ed3-4680-a7ca-43fe172d538d' && wc027ParsedFeedProducerImagePullBinding.conditionVersion == null && wc027ParsedFeedProducerImagePullBinding.condition == null
var wc027FeedProducerAbacImagePullBindingValid = wc027ParsedFeedProducerImagePullBinding.roleAssignmentMode == 'AbacRepositoryPermissions' && wc027ParsedFeedProducerImagePullBinding.roleDefinitionId == 'b93aa761-3e63-49ed-ac28-beffa264f7ac' && wc027ParsedFeedProducerImagePullBinding.conditionVersion == '2.0' && wc027ParsedFeedProducerImagePullBinding.condition == wc027FeedProducerExpectedRepositoryCondition
var wc027FeedProducerImagePullBindingValid = !empty(wc027EnrichmentFeedProducerImagePullBindingJson) && !contains([
  wc027ParsedFeedProducerImagePullBinding.schemaVersion == 'athena.wc027AcrPullBinding.v1'
  wc027ParsedFeedProducerImagePullBinding.image == wc027EnrichmentFeedProducerImage
  wc027ParsedFeedProducerImagePullBinding.anonymousPullEnabled == false
  wc027ParsedFeedProducerImagePullBinding.repositoryName == wc027FeedProducerExpectedRepositoryName
  !empty(wc027ParsedFeedProducerImagePullBinding.principalId)
  !empty(wc027ParsedFeedProducerImagePullBinding.registryResourceId)
  !empty(wc027ParsedFeedProducerImagePullBinding.roleAssignmentResourceId)
  wc027FeedProducerImagePullPrincipalMatches
  wc027FeedProducerImagePullRegistryMatchesImage
  wc027FeedProducerImagePullAssignmentScopedToRegistry
  wc027FeedProducerImagePullAssignmentInDeploymentBinding
  wc027FeedProducerLegacyImagePullBindingValid || wc027FeedProducerAbacImagePullBindingValid
], false)
var wc027ParsedEffectiveAcrAccess = wc027ParsedPublisherImagePullEvidence.effectiveAccess
var wc027ReadinessEvaluationEpoch = dateTimeToEpoch(wc027ReadinessEvaluationTimeUtc)
var wc027EffectiveAcrVerifiedEpoch = dateTimeToEpoch(wc027ParsedEffectiveAcrAccess.verifiedAt)
var wc027PublisherPullVerifiedEpoch = dateTimeToEpoch(wc027ParsedPublisherImagePullEvidence.verifiedAt)
var wc027EffectiveAcrEvidenceFresh = !empty(wc027PublisherImagePullEvidenceJson) && wc027EffectiveAcrVerifiedEpoch <= wc027PublisherPullVerifiedEpoch && wc027PublisherPullVerifiedEpoch - wc027EffectiveAcrVerifiedEpoch <= 120 && wc027PublisherPullVerifiedEpoch <= wc027ReadinessEvaluationEpoch && wc027ReadinessEvaluationEpoch - wc027PublisherPullVerifiedEpoch <= 300
var wc027EffectiveAcrEvidenceDigestValid = length(wc027ParsedEffectiveAcrAccess.evidenceDigest) == 71 && startsWith(wc027ParsedEffectiveAcrAccess.evidenceDigest, 'sha256:') && wc027ParsedEffectiveAcrAccess.evidenceDigest == toLower(wc027ParsedEffectiveAcrAccess.evidenceDigest)
var wc027GovernedSubscriptionIds = map(
  wc027ParsedEffectiveAcrAccess.governedSubscriptionIds,
  subscriptionId => toLower(subscriptionId)
)
var wc027ReviewedEffectiveAcrAssignments = wc027ParsedEffectiveAcrAccess.reviewedAssignments
var wc027ReviewedEffectiveAcrAssignmentLabels = map(
  wc027ReviewedEffectiveAcrAssignments,
  assignment => assignment.label
)
var wc027ReviewedPublisherAcrAssignments = filter(
  wc027ReviewedEffectiveAcrAssignments,
  assignment => assignment.label == 'publisher'
)
var wc027ReviewedRequestProducerAcrAssignments = filter(
  wc027ReviewedEffectiveAcrAssignments,
  assignment => assignment.label == 'request-producer'
)
var wc027ReviewedFeedProducerAcrAssignments = filter(
  wc027ReviewedEffectiveAcrAssignments,
  assignment => assignment.label == 'feed-producer'
)
var wc027ReviewedRequestProducerAcrAssignment = first(concat(
  wc027ReviewedRequestProducerAcrAssignments,
  [
    {
      assignmentResourceId: ''
      condition: null
      conditionVersion: null
      principalId: ''
      registryResourceId: ''
      repositoryName: ''
      roleAssignmentMode: ''
      roleDefinitionId: ''
    }
  ]
))
var wc027ReviewedFeedProducerAcrAssignment = first(concat(
  wc027ReviewedFeedProducerAcrAssignments,
  [
    {
      assignmentResourceId: ''
      condition: null
      conditionVersion: null
      principalId: ''
      registryResourceId: ''
      repositoryName: ''
      roleAssignmentMode: ''
      roleDefinitionId: ''
    }
  ]
))
var wc027ReviewedPublisherAcrAssignment = first(concat(
  wc027ReviewedPublisherAcrAssignments,
  [
    {
      assignmentResourceId: ''
      condition: null
      conditionVersion: null
      principalId: ''
      registryResourceId: ''
      repositoryName: ''
      roleAssignmentMode: ''
      roleDefinitionId: ''
    }
  ]
))
var wc027ReviewedRequestProducerAcrAssignmentValid = length(wc027ReviewedRequestProducerAcrAssignments) == 1 && wc027RequestProducerImagePullBindingValid && !contains([
  toLower(wc027ReviewedRequestProducerAcrAssignment.principalId) == toLower(wc027ParsedRequestProducerImagePullBinding.principalId)
  toLower(wc027ReviewedRequestProducerAcrAssignment.assignmentResourceId) == toLower(wc027ParsedRequestProducerImagePullBinding.roleAssignmentResourceId)
  toLower(wc027ReviewedRequestProducerAcrAssignment.registryResourceId) == toLower(wc027ParsedRequestProducerImagePullBinding.registryResourceId)
  wc027ReviewedRequestProducerAcrAssignment.repositoryName == wc027ParsedRequestProducerImagePullBinding.repositoryName
  wc027ReviewedRequestProducerAcrAssignment.roleAssignmentMode == wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode
  wc027ReviewedRequestProducerAcrAssignment.roleDefinitionId == wc027ParsedRequestProducerImagePullBinding.roleDefinitionId
  wc027ReviewedRequestProducerAcrAssignment.conditionVersion == wc027ParsedRequestProducerImagePullBinding.conditionVersion
  wc027ReviewedRequestProducerAcrAssignment.condition == wc027ParsedRequestProducerImagePullBinding.condition
], false)
var wc027ReviewedFeedProducerAcrAssignmentValid = length(wc027ReviewedFeedProducerAcrAssignments) == 1 && wc027FeedProducerImagePullBindingValid && !contains([
  toLower(wc027ReviewedFeedProducerAcrAssignment.principalId) == toLower(wc027ParsedFeedProducerImagePullBinding.principalId)
  toLower(wc027ReviewedFeedProducerAcrAssignment.assignmentResourceId) == toLower(wc027ParsedFeedProducerImagePullBinding.roleAssignmentResourceId)
  toLower(wc027ReviewedFeedProducerAcrAssignment.registryResourceId) == toLower(wc027ParsedFeedProducerImagePullBinding.registryResourceId)
  wc027ReviewedFeedProducerAcrAssignment.repositoryName == wc027ParsedFeedProducerImagePullBinding.repositoryName
  wc027ReviewedFeedProducerAcrAssignment.roleAssignmentMode == wc027ParsedFeedProducerImagePullBinding.roleAssignmentMode
  wc027ReviewedFeedProducerAcrAssignment.roleDefinitionId == wc027ParsedFeedProducerImagePullBinding.roleDefinitionId
  wc027ReviewedFeedProducerAcrAssignment.conditionVersion == wc027ParsedFeedProducerImagePullBinding.conditionVersion
  wc027ReviewedFeedProducerAcrAssignment.condition == wc027ParsedFeedProducerImagePullBinding.condition
], false)
var wc027ReviewedPublisherAcrAssignmentValid = length(wc027ReviewedPublisherAcrAssignments) == 1 && !contains([
  toLower(wc027ReviewedPublisherAcrAssignment.principalId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityPrincipalId)
  toLower(wc027ReviewedPublisherAcrAssignment.assignmentResourceId) == toLower(wc027ParsedPublisherConfiguration.imagePull.roleAssignmentResourceId)
  toLower(wc027ReviewedPublisherAcrAssignment.registryResourceId) == toLower(wc027ParsedPublisherConfiguration.imagePull.registryResourceId)
  wc027ReviewedPublisherAcrAssignment.repositoryName == wc027ParsedPublisherConfiguration.imagePull.repositoryName
  wc027ReviewedPublisherAcrAssignment.roleAssignmentMode == wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode
  wc027ReviewedPublisherAcrAssignment.roleDefinitionId == wc027ParsedPublisherConfiguration.imagePull.roleDefinitionId
  wc027ReviewedPublisherAcrAssignment.conditionVersion == wc027ParsedPublisherConfiguration.imagePull.conditionVersion
  wc027ReviewedPublisherAcrAssignment.condition == wc027ParsedPublisherConfiguration.imagePull.condition
], false)
var wc027EffectiveAcrAssignmentsVerified = !contains([
  wc027ParsedEffectiveAcrAccess.schemaVersion == 'athena.wc027AcrEffectiveAccessEvidence.v1'
  wc027ParsedEffectiveAcrAccess.verified == true
  toLower(wc027ParsedEffectiveAcrAccess.tenantId) == toLower(tenant().tenantId)
  wc027ParsedEffectiveAcrAccess.tenantSubscriptionHierarchyComplete == true
  length(wc027GovernedSubscriptionIds) >= 1
  contains(wc027GovernedSubscriptionIds, toLower(wc027RequestProducerImagePullRegistryResourceIdSegments[2]))
  contains(wc027GovernedSubscriptionIds, toLower(wc027FeedProducerImagePullRegistryResourceIdSegments[2]))
  contains(wc027GovernedSubscriptionIds, toLower(wc027PublisherImagePullRegistryResourceIdSegments[2]))
  wc027ParsedEffectiveAcrAccess.anonymousPullEnabled == false
  wc027ParsedEffectiveAcrAccess.expectedAssignmentCount == 3
  wc027ParsedEffectiveAcrAccess.pullCapableAssignmentCount == 3
  wc027ParsedEffectiveAcrAccess.roleDefinitionsResolved == true
  wc027ParsedEffectiveAcrAccess.exactAssignmentReadbacksComplete == true
  wc027ParsedEffectiveAcrAccess.directAssignmentsComplete == true
  wc027ParsedEffectiveAcrAccess.inheritedAssignmentsComplete == true
  wc027ParsedEffectiveAcrAccess.transitiveGroupsComplete == true
  wc027ParsedEffectiveAcrAccess.directMembershipTraversalComplete == true
  wc027ParsedEffectiveAcrAccess.convergedMembershipReadbacks == true
  wc027ParsedEffectiveAcrAccess.roleAssignmentScheduleInstancesComplete == true
  wc027ParsedEffectiveAcrAccess.siblingRegistriesChecked == true
  wc027ParsedEffectiveAcrAccess.acrEscalationPathsChecked == true
  wc027EffectiveAcrEvidenceFresh
  wc027EffectiveAcrEvidenceDigestValid
  length(wc027ParsedEffectiveAcrAccess.expectedAssignmentIds) == 3
  length(wc027ParsedEffectiveAcrAccess.principalIds) == 3
  length(wc027ParsedEffectiveAcrAccess.registryResourceIds) >= 1
  length(wc027ReviewedEffectiveAcrAssignments) == 3
  length(filter(wc027ReviewedEffectiveAcrAssignmentLabels, label => label == 'request-producer')) == 1
  length(filter(wc027ReviewedEffectiveAcrAssignmentLabels, label => label == 'feed-producer')) == 1
  length(filter(wc027ReviewedEffectiveAcrAssignmentLabels, label => label == 'publisher')) == 1
  wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == wc027ParsedFeedProducerImagePullBinding.roleAssignmentMode
  wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode
  wc027ReviewedRequestProducerAcrAssignmentValid
  wc027ReviewedFeedProducerAcrAssignmentValid
  wc027ReviewedPublisherAcrAssignmentValid
  empty(wc027ParsedEffectiveAcrAccess.extraPullCapableAssignmentIds)
  !empty(wc027ParsedEffectiveAcrAccess.verifiedAt)
], false)
var wc027PublisherImagePullEvidenceValid = !empty(wc027PublisherImagePullEvidenceJson) && !contains([
  wc027ParsedPublisherImagePullEvidence.schemaVersion == 'athena.wc027AcrDigestPullReadiness.v1'
  wc027ParsedPublisherImagePullEvidence.success == true
  wc027ParsedPublisherImagePullEvidence.registryResourceId == wc027ParsedPublisherConfiguration.imagePull.registryResourceId
  wc027ParsedPublisherImagePullEvidence.registryServer == wc027ParsedPublisherConfiguration.imagePull.registryServer
  wc027ParsedPublisherImagePullEvidence.image == wc027PublisherImage
  wc027ParsedPublisherConfiguration.imagePull.image == wc027PublisherImage
  wc027ParsedPublisherImagePullEvidence.anonymousPullEnabled == false
  wc027ParsedPublisherImagePullEvidence.anonymousPullEnabled == wc027ParsedPublisherConfiguration.imagePull.anonymousPullEnabled
  wc027ParsedPublisherImagePullEvidence.repositoryName == wc027ParsedPublisherConfiguration.imagePull.repositoryName
  toLower(wc027ParsedPublisherImagePullEvidence.managedIdentityResourceId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityResourceId)
  toLower(wc027ParsedPublisherImagePullEvidence.managedIdentityClientId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityClientId)
  toLower(wc027ParsedPublisherImagePullEvidence.managedIdentityPrincipalId) == toLower(wc027ParsedPublisherConfiguration.imagePull.identityPrincipalId)
  wc027PublisherImagePullIdentityMatches
  wc027ParsedPublisherImagePullEvidence.roleAssignmentMode == wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode
  wc027ParsedPublisherImagePullEvidence.roleDefinitionId == wc027ParsedPublisherConfiguration.imagePull.roleDefinitionId
  toLower(wc027ParsedPublisherImagePullEvidence.roleAssignmentResourceId) == toLower(wc027ParsedPublisherConfiguration.imagePull.roleAssignmentResourceId)
  wc027ParsedPublisherImagePullEvidence.conditionVersion == wc027ParsedPublisherConfiguration.imagePull.conditionVersion
  wc027ParsedPublisherImagePullEvidence.condition == wc027ParsedPublisherConfiguration.imagePull.condition
  wc027PublisherImagePullConditionValid
  wc027ParsedPublisherImagePullEvidence.attempts >= 1
  wc027ParsedPublisherImagePullEvidence.maxAttempts >= wc027ParsedPublisherImagePullEvidence.attempts
  wc027ParsedPublisherImagePullEvidence.maxAttempts <= 20
  !empty(wc027ParsedPublisherImagePullEvidence.verifiedAt)
], false)
var wc027PublisherDeliveryBudget = wc027ParsedPublisherConfiguration.deliveryBudget
var wc027PublisherDeliveryBudgetValid = !contains([
  wc027PublisherDeliveryBudget.publisherKedaPollingIntervalSeconds == wc027ReviewedPublisherKedaPollingIntervalSeconds
  wc027PublisherDeliveryBudget.publisherColdStartSeconds == wc027ReviewedPublisherColdStartSeconds
  wc027PublisherDeliveryBudget.publisherConnectionSetupSeconds == wc027ReviewedPublisherConnectionSetupSeconds
  wc027PublisherDeliveryBudget.publisherProcessingSeconds == wc027ReviewedPublisherProcessingSeconds
  wc027PublisherDeliveryBudget.publisherCasMarginSeconds == wc027ReviewedPublisherCasMarginSeconds
  wc027PublisherDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027ReviewedPublisherMinimumRemainingLifetimeSeconds
  wc027PublisherDeliveryBudget.feedKedaPollingIntervalSeconds == wc027ReviewedFeedKedaPollingIntervalSeconds
  wc027PublisherDeliveryBudget.feedColdStartSeconds == wc027ReviewedFeedColdStartSeconds
  wc027PublisherDeliveryBudget.feedConnectionSetupSeconds == wc027ReviewedFeedConnectionSetupSeconds
  wc027PublisherDeliveryBudget.feedProcessingSeconds == wc027ReviewedFeedProcessingSeconds
  wc027PublisherDeliveryBudget.feedDeliveryJitterSeconds == wc027ReviewedFeedDeliveryJitterSeconds
  wc027PublisherDeliveryBudget.feedIrreversibleWriteMarginSeconds == wc027ReviewedFeedIrreversibleWriteMarginSeconds
  wc027PublisherDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027ReviewedFeedMinimumRemainingLifetimeSeconds
  wc027PublisherDeliveryBudget.feedTriggerRecoverySeconds == wc027ReviewedFeedTriggerRecoverySeconds
  wc027PublisherDeliveryBudget.minimumRemainingLifetimeSeconds == wc027ReviewedMinimumRemainingLifetimeSeconds
  wc027PublisherDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027PublisherDeliveryBudget.publisherKedaPollingIntervalSeconds + wc027PublisherDeliveryBudget.publisherColdStartSeconds + wc027PublisherDeliveryBudget.publisherConnectionSetupSeconds + wc027PublisherDeliveryBudget.publisherProcessingSeconds
  wc027PublisherDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027PublisherDeliveryBudget.feedKedaPollingIntervalSeconds + wc027PublisherDeliveryBudget.feedColdStartSeconds + wc027PublisherDeliveryBudget.feedConnectionSetupSeconds + wc027PublisherDeliveryBudget.feedProcessingSeconds
  wc027PublisherDeliveryBudget.minimumRemainingLifetimeSeconds == wc027PublisherDeliveryBudget.publisherMinimumRemainingLifetimeSeconds
], false)
var wc027RuntimeDeliveryBudget = wc027ParsedProducerConfiguration.deliveryBudget
var wc027RuntimeDeliveryBudgetValid = !contains([
  wc027RuntimeDeliveryBudget.publisherKedaPollingIntervalSeconds == wc027ReviewedPublisherKedaPollingIntervalSeconds
  wc027RuntimeDeliveryBudget.publisherColdStartSeconds == wc027ReviewedPublisherColdStartSeconds
  wc027RuntimeDeliveryBudget.publisherConnectionSetupSeconds == wc027ReviewedPublisherConnectionSetupSeconds
  wc027RuntimeDeliveryBudget.publisherProcessingSeconds == wc027ReviewedPublisherProcessingSeconds
  wc027RuntimeDeliveryBudget.publisherCasMarginSeconds == wc027ReviewedPublisherCasMarginSeconds
  wc027RuntimeDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027ReviewedPublisherMinimumRemainingLifetimeSeconds
  wc027RuntimeDeliveryBudget.feedKedaPollingIntervalSeconds == wc027ReviewedFeedKedaPollingIntervalSeconds
  wc027RuntimeDeliveryBudget.feedColdStartSeconds == wc027ReviewedFeedColdStartSeconds
  wc027RuntimeDeliveryBudget.feedConnectionSetupSeconds == wc027ReviewedFeedConnectionSetupSeconds
  wc027RuntimeDeliveryBudget.feedProcessingSeconds == wc027ReviewedFeedProcessingSeconds
  wc027RuntimeDeliveryBudget.feedDeliveryJitterSeconds == wc027ReviewedFeedDeliveryJitterSeconds
  wc027RuntimeDeliveryBudget.feedIrreversibleWriteMarginSeconds == wc027ReviewedFeedIrreversibleWriteMarginSeconds
  wc027RuntimeDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027ReviewedFeedMinimumRemainingLifetimeSeconds
  wc027RuntimeDeliveryBudget.feedTriggerRecoverySeconds == wc027ReviewedFeedTriggerRecoverySeconds
  wc027RuntimeDeliveryBudget.minimumRemainingLifetimeSeconds == wc027ReviewedMinimumRemainingLifetimeSeconds
  wc027RuntimeDeliveryBudget.publisherMinimumRemainingLifetimeSeconds == wc027RuntimeDeliveryBudget.publisherKedaPollingIntervalSeconds + wc027RuntimeDeliveryBudget.publisherColdStartSeconds + wc027RuntimeDeliveryBudget.publisherConnectionSetupSeconds + wc027RuntimeDeliveryBudget.publisherProcessingSeconds
  wc027RuntimeDeliveryBudget.feedMinimumRemainingLifetimeSeconds == wc027RuntimeDeliveryBudget.feedKedaPollingIntervalSeconds + wc027RuntimeDeliveryBudget.feedColdStartSeconds + wc027RuntimeDeliveryBudget.feedConnectionSetupSeconds + wc027RuntimeDeliveryBudget.feedProcessingSeconds
  wc027RuntimeDeliveryBudget.minimumRemainingLifetimeSeconds == wc027RuntimeDeliveryBudget.publisherMinimumRemainingLifetimeSeconds
], false)
var wc027ProducerPublisherDeliveryBudgetsMatch = !wc027RequestProducerReady || !wc027PublisherReady || string(wc027RequestProducerDeliveryBudget) == string(wc027PublisherDeliveryBudget)
var wc027RequestProducerRuntimeDeliveryBudgetsMatch = !wc027RequestProducerReady || string(wc027RequestProducerDeliveryBudget) == string(wc027RuntimeDeliveryBudget)
var wc027PublisherRuntimeDeliveryBudgetsMatch = !wc027PublisherReady || string(wc027PublisherDeliveryBudget) == string(wc027RuntimeDeliveryBudget)
var wc027PublisherExpectedIdentityResourceIds = map(
  wc027ParsedPublisherConfiguration.deploymentBinding.attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var wc027PublisherOwnedConfiguredIdentityResourceIds = wc027PublisherReady && !empty(wc027PublisherConfigurationJson)
  ? map([
      wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId
      wc027ParsedPublisherConfiguration.requestOutbox.identityResourceId
      wc027ParsedPublisherConfiguration.authorityAssets.readerIdentityResourceId
      wc027ParsedPublisherConfiguration.authorityAssets.writerIdentityResourceId
      wc027ParsedPublisherConfiguration.guidanceActivation.identityResourceId
      wc027ParsedPublisherConfiguration.requestKey.identityResourceId
      wc027ParsedPublisherConfiguration.bindingSigningKey.identityResourceId
    ], identityResourceId => toLower(identityResourceId))
  : []
var wc027PublisherDelegatedRuntimeIdentityResourceIds = wc027PublisherReady && !empty(wc027PublisherConfigurationJson)
  ? map([
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.incidentLifecycleAssets.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.correlationSources.monitoring.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.correlationSources.change.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.correlationSources.contextAuthority.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.correlationSources.monitoringIntent.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.monitoringCollectorKey.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.keys.change.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.keys.monitoringIntent.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.keys.incident.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.keys.correlationBinding.identityResourceId
      wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration.keys.guidanceBinding.identityResourceId
    ], identityResourceId => toLower(identityResourceId))
  : []
var wc027DistinctPublisherOwnedConfiguredIdentityResourceIds = union(
  wc027PublisherOwnedConfiguredIdentityResourceIds,
  wc027PublisherOwnedConfiguredIdentityResourceIds
)
var wc027DistinctPublisherDelegatedRuntimeIdentityResourceIds = union(
  wc027PublisherDelegatedRuntimeIdentityResourceIds,
  wc027PublisherDelegatedRuntimeIdentityResourceIds
)
var wc027DistinctPublisherConfiguredIdentityResourceIds = union(
  wc027DistinctPublisherOwnedConfiguredIdentityResourceIds,
  wc027DistinctPublisherDelegatedRuntimeIdentityResourceIds
)
var wc027PublisherConfigurationIdentitiesMatchBinding = !empty(wc027DistinctPublisherConfiguredIdentityResourceIds) && length(wc027PublisherExpectedIdentityResourceIds) == length(union(wc027PublisherExpectedIdentityResourceIds, wc027PublisherExpectedIdentityResourceIds)) && length(wc027DistinctPublisherConfiguredIdentityResourceIds) == length(wc027PublisherExpectedIdentityResourceIds) && length(union(wc027DistinctPublisherConfiguredIdentityResourceIds, wc027PublisherExpectedIdentityResourceIds)) == length(wc027DistinctPublisherConfiguredIdentityResourceIds)
var wc027PublisherRbacResourceIds = wc027ParsedPublisherConfiguration.deploymentBinding.rbacResourceIds
var wc027PublisherRbacEvidenceMatches = !empty(wc027PublisherRbacResourceIds) && guid(
  join(wc027PublisherRbacResourceIds, '|')
) == wc027ParsedPublisherConfiguration.deploymentBinding.bindingEvidenceId
var wc027PublisherAttachedIdentityResourceIds = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? map(items(wc027PublisherJob!.identity.?userAssignedIdentities ?? {}), identity => toLower(identity.key))
  : []
var wc027PublisherIdentitiesMatch = !empty(wc027PublisherExpectedIdentityResourceIds) && length(
  wc027PublisherAttachedIdentityResourceIds
) == length(wc027PublisherExpectedIdentityResourceIds) && length(union(
  wc027PublisherAttachedIdentityResourceIds,
  wc027PublisherExpectedIdentityResourceIds
)) == length(wc027PublisherExpectedIdentityResourceIds)
var wc027PublisherOwnedRuntimeIdentityOverlap = intersection(
  wc027DistinctPublisherOwnedConfiguredIdentityResourceIds,
  wc027DistinctConfiguredIdentityResourceIds
)
var wc027PublisherRequestSubmitterIdentityResourceId = toLower(
  wc027ParsedPublisherConfiguration.serviceBus.requestSubmitterIdentityResourceId
)
var wc027PublisherRequestSubmitterRuntimeIdentityOverlap = intersection(
  [
    wc027PublisherRequestSubmitterIdentityResourceId
  ],
  wc027DistinctConfiguredIdentityResourceIds
)
var wc027PublisherRequestSubmitterAttachedIdentityOverlap = intersection(
  [
    wc027PublisherRequestSubmitterIdentityResourceId
  ],
  wc027DistinctPublisherConfiguredIdentityResourceIds
)
var wc027PublisherHasExactContainerCount = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? length(wc027PublisherJob!.properties.template.containers) == 1
  : false
var wc027PublisherIdentityTypeMatches = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? (wc027PublisherJob!.identity.?type ?? '') == 'UserAssigned'
  : false
var wc027PublisherTemplateMatches = wc027PublisherReady && wc027PublisherJobResourceIdValid && wc027PublisherHasExactContainerCount && !empty(wc027PublisherConfigurationJson)
  ? !contains([
      wc027PublisherJob!.properties.template.containers[0].name == 'wc027-guidance-authority-publisher'
      wc027PublisherJob!.properties.template.containers[0].image == wc027PublisherImage
      length(wc027PublisherJob!.properties.template.containers[0].command) == 1
      wc027PublisherJob!.properties.template.containers[0].command[0] == 'athena-context'
      length(wc027PublisherJob!.properties.template.containers[0].args) == 1
      wc027PublisherJob!.properties.template.containers[0].args[0] == 'wc027-guidance-authority-publisher'
      length(wc027PublisherJob!.properties.template.containers[0].env) == 2
      wc027PublisherJob!.properties.template.containers[0].env[0].name == 'AZURE_CLIENT_ID'
      wc027PublisherJob!.properties.template.containers[0].env[0].value == wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityClientId
      wc027PublisherJob!.properties.template.containers[0].env[1].name == 'ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON'
      wc027PublisherJob!.properties.template.containers[0].env[1].value == wc027PublisherConfigurationJson
      wc027PublisherJob!.properties.template.containers[0].resources.cpu == 1
      wc027PublisherJob!.properties.template.containers[0].resources.memory == '2Gi'
      empty(wc027PublisherJob!.properties.template.containers[0].?probes ?? [])
      empty(wc027PublisherJob!.properties.template.containers[0].?volumeMounts ?? [])
      empty(wc027PublisherJob!.properties.template.?initContainers ?? [])
      empty(wc027PublisherJob!.properties.template.?volumes ?? [])
    ], false)
  : false
var wc027PublisherExecutionConfigurationMatches = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? !contains([
      wc027PublisherJob!.properties.environmentId == azureMcp.outputs.managedEnvironmentResourceId
      wc027PublisherJob!.properties.configuration.replicaTimeout == 900
      wc027PublisherJob!.properties.configuration.replicaRetryLimit == 0
      wc027PublisherJob!.properties.configuration.triggerType == 'Event'
      empty(wc027PublisherJob!.properties.configuration.?identitySettings ?? [])
      empty(wc027PublisherJob!.properties.configuration.?secrets ?? [])
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.parallelism == 1
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.replicaCompletionCount == 1
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.minExecutions == 0
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.maxExecutions == 1
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.pollingInterval == wc027PublisherDeliveryBudget.publisherKedaPollingIntervalSeconds
      length(wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
    ], false)
  : false
var wc027PublisherHasExactScalerRuleCount = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? length(wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
  : false
var wc027PublisherScalerMatches = wc027PublisherReady && wc027PublisherJobResourceIdValid && !empty(wc027PublisherConfigurationJson) && wc027PublisherHasExactScalerRuleCount
  ? !contains([
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].name == 'wc027-guidance-authority-request'
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].type == 'azure-servicebus'
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].identity == wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId
      empty(wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].?auth ?? [])
      length(items(wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata)) == 5
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.namespace == first(split(wc027ParsedPublisherConfiguration.serviceBus.namespace, '.'))
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.queueName == wc027ParsedPublisherConfiguration.serviceBus.requestQueueName
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.messageCount == '1'
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.cloud == 'AzurePublicCloud'
      wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.isSessionsEnabled == 'true'
    ], false)
  : false
var wc027PublisherHasExactRegistryCount = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? length(wc027PublisherJob!.properties.configuration.registries) == 1
  : false
var wc027PublisherRegistryMatches = wc027PublisherReady && wc027PublisherJobResourceIdValid && !empty(wc027PublisherConfigurationJson) && wc027PublisherHasExactRegistryCount
  ? !contains([
      wc027PublisherJob!.properties.configuration.registries[0].server == wc027PublisherImageRegistryServer
      wc027PublisherJob!.properties.configuration.registries[0].identity == wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId
      length(items(wc027PublisherJob!.properties.configuration.registries[0])) == 2
    ], false)
  : false
var wc027PublisherTagsMatch = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? !contains([
      wc027PublisherJob!.tags.enrichmentRuntimeConfigurationDigest == wc027EnrichmentFeedProducerConfigurationDigest
      wc027PublisherJob!.tags.runtimeConfigurationDigest == wc027PublisherConfigurationDigest
    ], false)
  : false
var validatedWc027PublisherReady = wc027PublisherReady && !wc027EffectiveAcrAssignmentsVerified
  ? fail('WC-027 publisher requires PR #102-equivalent full role-definition resolution proving no extra direct, inherited, group-derived, or sibling-registry pull-capable assignment')
  : wc027PublisherReady && !wc027PublisherJobResourceIdValid
    ? fail('wc027PublisherJobResourceId must identify one Microsoft.App/jobs resource')
    : wc027PublisherReady && !wc027PublisherConfigurationDigestValid
    ? fail('WC-027 publisher requires the exact deployed configuration digest')
    : wc027PublisherReady && empty(wc027PublisherConfigurationJson)
      ? fail('WC-027 publisher requires the exact deployed configuration JSON')
      : wc027PublisherReady && (empty(wc027EnrichmentFeedProducerConfigurationJson) || !wc027ConfigurationDigestValid)
        ? fail('WC-027 publisher requires the exact deployed enrichment runtime configuration')
        : wc027PublisherReady && !wc027ConfigurationIdentitiesMatchBinding
          ? fail('WC-027 enrichment runtime identities do not exactly match its deployment binding')
          : wc027PublisherReady && !wc027PublisherConfigurationIdentitiesMatchBinding
            ? fail('WC-027 publisher configuration identities do not exactly match its deployment binding')
            : wc027PublisherReady && !empty(wc027PublisherOwnedRuntimeIdentityOverlap)
              ? fail('WC-027 publisher-owned identities overlap the enrichment runtime identity boundary')
              : wc027PublisherReady && !empty(wc027PublisherRequestSubmitterRuntimeIdentityOverlap)
                ? fail('WC-027 publisher request submitter overlaps the enrichment runtime identity boundary')
                : wc027PublisherReady && !empty(wc027PublisherRequestSubmitterAttachedIdentityOverlap)
                  ? fail('WC-027 publisher request submitter overlaps an attached publisher identity')
                  : wc027PublisherReady && wc027RequestProducerReady && !empty(wc027RequestProducerPublisherIdentityOverlap)
                    ? fail('WC-027 request producer identities overlap the publisher identity boundary')
                    : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.serviceBus.namespace != wc027ParsedRequestProducerConfiguration.serviceBus.namespace
                      ? fail('WC-027 publisher namespace does not match the request producer')
                      : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.serviceBus.requestQueueName != wc027ParsedRequestProducerConfiguration.serviceBus.outputQueueName
                        ? fail('WC-027 publisher request queue does not match the request producer output queue')
                        : wc027PublisherReady && wc027RequestProducerReady && toLower(wc027ParsedPublisherConfiguration.serviceBus.requestSubmitterIdentityResourceId) != toLower(wc027ParsedRequestProducerConfiguration.serviceBus.senderIdentityResourceId)
                          ? fail('WC-027 publisher request submitter does not match the dedicated request producer sender')
                          : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.requestOutbox.blobEndpoint != wc027ParsedRequestProducerConfiguration.requestOutbox.blobEndpoint
                            ? fail('WC-027 publisher request outbox endpoint does not match the request producer')
                            : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.requestOutbox.containerName != wc027ParsedRequestProducerConfiguration.requestOutbox.containerName
                              ? fail('WC-027 publisher request outbox container does not match the request producer')
                              : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.requestKey.keyId != wc027ParsedRequestProducerConfiguration.requestSigningKey.keyId
                                ? fail('WC-027 publisher request logical key does not match the request producer')
                                : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.requestKey.keyVaultKeyId != wc027ParsedRequestProducerConfiguration.requestSigningKey.keyVaultKeyId
                                  ? fail('WC-027 publisher request key version does not match the request producer')
                                  : wc027PublisherReady && wc027RequestProducerReady && wc027ParsedPublisherConfiguration.requestKey.keyFingerprint != wc027ParsedRequestProducerConfiguration.requestSigningKey.keyFingerprint
                                    ? fail('WC-027 publisher request key fingerprint does not match the request producer')
                                    : wc027PublisherReady && !wc027PublisherImageValid
                                      ? fail('WC-027 publisher requires the exact digest-pinned deployed image')
                                      : wc027PublisherReady && !wc027PublisherImagePullEvidenceValid
                                        ? fail('WC-027 publisher requires successful bounded managed-identity digest-pull evidence')
                                        : wc027PublisherReady && !wc027PublisherIdentityTypeMatches
                                          ? fail('WC-027 publisher Job must use only user-assigned identities')
                                          : wc027PublisherReady && !wc027PublisherHasExactContainerCount
                                            ? fail('WC-027 publisher Job must contain exactly one reviewed container')
                                          : wc027PublisherReady && !wc027PublisherTemplateMatches
                                            ? fail('WC-027 publisher Job execution template does not exactly match')
                                            : wc027PublisherReady && !wc027PublisherExecutionConfigurationMatches
                                              ? fail('WC-027 publisher Job replica and concurrency configuration does not exactly match')
                                              : wc027PublisherReady && !wc027PublisherScalerMatches
                                                ? fail('WC-027 publisher Job scaler configuration does not exactly match')
                                                : wc027PublisherReady && !wc027PublisherRegistryMatches
                                                  ? fail('WC-027 publisher Job registry configuration does not exactly match')
                                                  : wc027PublisherReady && !wc027PublisherTagsMatch
                                                    ? fail('WC-027 publisher Job configuration digest tags do not match')
                                                    : wc027PublisherReady && !wc027PublisherDeliveryBudgetValid
                                                      ? fail('WC-027 publisher delivery budget does not match the reviewed publisher and feed delivery phases')
                                                      : wc027PublisherReady && !wc027RuntimeDeliveryBudgetValid
                                                        ? fail('WC-027 enrichment runtime delivery budget does not match the reviewed publisher and feed delivery phases')
                                                        : wc027PublisherReady && !wc027ProducerPublisherDeliveryBudgetsMatch
                                                          ? fail('WC-027 producer and publisher delivery budgets do not match')
                                                          : wc027PublisherReady && !wc027PublisherRuntimeDeliveryBudgetsMatch
                                                            ? fail('WC-027 publisher and enrichment runtime delivery budgets do not match')
                                                            : wc027PublisherReady && string(wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration) != string(wc027ParsedProducerConfiguration)
                                                              ? fail('WC-027 publisher embedded runtime configuration JSON does not match the producer')
                                                              : wc027PublisherReady && !wc027PublisherRbacEvidenceMatches
                                                                ? fail('WC-027 publisher RBAC evidence does not match its deployed configuration')
                                                                : wc027PublisherReady && !wc027PublisherIdentitiesMatch
                                                                  ? fail('WC-027 publisher identities do not match its deployed configuration')
                                                                  : wc027PublisherReady
var wc027ProducerJobResourceIdSegments = concat(
  wc027ProducerJobResourceIdRawSegments,
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
var wc027ProducerJobResourceIdShapeValid = length(wc027ProducerJobResourceIdRawSegments) == 9 && empty(wc027ProducerJobResourceIdSegments[0]) && wc027ProducerJobResourceIdSegments[1] == 'subscriptions' && !empty(wc027ProducerJobResourceIdSegments[2]) && toLower(wc027ProducerJobResourceIdSegments[2]) == toLower(subscription().subscriptionId) && wc027ProducerJobResourceIdSegments[3] == 'resourceGroups' && !empty(wc027ProducerJobResourceIdSegments[4]) && toLower(wc027ProducerJobResourceIdSegments[4]) == toLower(foundationResourceGroupName) && wc027ProducerJobResourceIdSegments[5] == 'providers' && wc027ProducerJobResourceIdSegments[6] == 'Microsoft.App' && wc027ProducerJobResourceIdSegments[7] == 'jobs' && !empty(wc027ProducerJobResourceIdSegments[8]) && !contains(wc027EnrichmentFeedProducerJobResourceId, '//') && !contains(wc027EnrichmentFeedProducerJobResourceId, '?') && !contains(wc027EnrichmentFeedProducerJobResourceId, '#') && !contains(wc027EnrichmentFeedProducerJobResourceId, '%')
var wc027ProducerRuntimeJobIdMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdShapeValid
  ? toLower(wc027ProducerRuntimeId!.outputs.runtimeJobResourceId) == toLower(wc027EnrichmentFeedProducerJobResourceId)
  : false
var wc027ProducerJobResourceIdValid = wc027ProducerJobResourceIdShapeValid && (!wc027FeedV2ProducerReady || wc027ProducerRuntimeJobIdMatches)
var wc027ConfigurationDigestHex = replace(
  wc027EnrichmentFeedProducerConfigurationDigest,
  'sha256:',
  ''
)
var wc027ConfigurationDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027ConfigurationDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027ConfigurationDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027ConfigurationDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027ConfigurationDigestValid = length(wc027EnrichmentFeedProducerConfigurationDigest) == 71 && wc027EnrichmentFeedProducerConfigurationDigest == toLower(
  wc027EnrichmentFeedProducerConfigurationDigest
) && empty(wc027ConfigurationDigestInvalidCharacters)
var wc027ProducerImageDigest = contains(wc027EnrichmentFeedProducerImage, '@sha256:')
  ? last(split(wc027EnrichmentFeedProducerImage, '@sha256:'))
  : ''
var wc027ProducerImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027ProducerImageDigest,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027ProducerImageInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027ProducerImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027ProducerImageValid = wc027EnrichmentFeedProducerImage == toLower(wc027EnrichmentFeedProducerImage) && length(wc027ProducerImageDigest) == 64 && empty(wc027ProducerImageInvalidCharacters) && wc027ProducerImageDigest != '0000000000000000000000000000000000000000000000000000000000000000'
var wc027ParsedConfiguration = json(
  empty(wc027EnrichmentFeedProducerConfigurationJson)
    ? '{"deploymentBinding":{"attachedIdentityResourceIds":[],"bindingEvidenceId":"","rbacResourceIds":[]}}'
    : wc027EnrichmentFeedProducerConfigurationJson
)
var wc027ProducerImageRegistryServer = first(split(wc027EnrichmentFeedProducerImage, '/'))
var wc027AttachedIdentityResourceIds = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? map(items(wc027ProducerJob!.identity.?userAssignedIdentities ?? {}), attachedIdentity => toLower(attachedIdentity.key))
  : []
var wc027ExpectedIdentityResourceIds = map(
  wc027ParsedConfiguration.deploymentBinding.attachedIdentityResourceIds,
  expectedIdentityResourceId => toLower(expectedIdentityResourceId)
)
var wc027ConfiguredIdentityResourceIds = !empty(wc027EnrichmentFeedProducerConfigurationJson)
  ? map([
      wc027ParsedConfiguration.serviceBus.brokerIdentityResourceId
      wc027ParsedConfiguration.incidentLifecycleAssets.identityResourceId
      wc027ParsedConfiguration.enrichmentFeedAssets.readerIdentityResourceId
      wc027ParsedConfiguration.enrichmentFeedAssets.writerIdentityResourceId
      wc027ParsedConfiguration.feedRegistry.identityResourceId
      wc027ParsedConfiguration.correlationSources.monitoring.identityResourceId
      wc027ParsedConfiguration.correlationSources.change.identityResourceId
      wc027ParsedConfiguration.correlationSources.contextAuthority.identityResourceId
      wc027ParsedConfiguration.correlationSources.monitoringIntent.identityResourceId
      wc027ParsedConfiguration.guidanceAuthoritySource.identityResourceId
      wc027ParsedConfiguration.guidanceActivation.identityResourceId
      wc027ParsedConfiguration.monitoringCollectorKey.identityResourceId
      wc027ParsedConfiguration.keys.incident.identityResourceId
      wc027ParsedConfiguration.keys.correlationBinding.identityResourceId
      wc027ParsedConfiguration.keys.guidanceBinding.identityResourceId
      wc027ParsedConfiguration.keys.change.identityResourceId
      wc027ParsedConfiguration.keys.monitoringIntent.identityResourceId
      wc027ParsedConfiguration.keys.report.identityResourceId
      wc027ParsedConfiguration.keys.guidance.identityResourceId
      wc027ParsedConfiguration.keys.enrichment.identityResourceId
      wc027ParsedConfiguration.keys.feed.identityResourceId
      wc027ParsedConfiguration.keys.notification.identityResourceId
    ], configuredIdentityResourceId => toLower(configuredIdentityResourceId))
  : []
var wc027DistinctConfiguredIdentityResourceIds = union(
  wc027ConfiguredIdentityResourceIds,
  wc027ConfiguredIdentityResourceIds
)
var wc027ConfigurationIdentitiesMatchBinding = !empty(wc027ExpectedIdentityResourceIds) && length(
  wc027ExpectedIdentityResourceIds
) == length(wc027DistinctConfiguredIdentityResourceIds) && length(
  union(wc027ExpectedIdentityResourceIds, wc027DistinctConfiguredIdentityResourceIds)
) == length(wc027ExpectedIdentityResourceIds)
var wc027RbacResourceIds = wc027ParsedConfiguration.deploymentBinding.rbacResourceIds
var wc027RbacEvidenceMatchesConfiguration = !empty(wc027RbacResourceIds) && guid(
  join(wc027RbacResourceIds, '|')
) == wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId
var wc027ProducerIdentitiesMatchExactly = !empty(wc027ExpectedIdentityResourceIds) && length(wc027AttachedIdentityResourceIds) == length(wc027ExpectedIdentityResourceIds) && length(union(wc027AttachedIdentityResourceIds, wc027ExpectedIdentityResourceIds)) == length(wc027ExpectedIdentityResourceIds)
var wc027ProducerHasExactContainerCount = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? length(wc027ProducerJob!.properties.template.containers) == 1
  : false
var wc027ProducerIdentityTypeMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? (wc027ProducerJob!.identity.?type ?? '') == 'UserAssigned'
  : false
var wc027ProducerTemplateMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid && wc027ProducerHasExactContainerCount && !empty(wc027EnrichmentFeedProducerConfigurationJson)
  ? !contains([
      wc027ProducerJob!.properties.template.containers[0].name == 'wc027-enrichment-feed-producer'
      wc027ProducerJob!.properties.template.containers[0].image == wc027EnrichmentFeedProducerImage
      length(wc027ProducerJob!.properties.template.containers[0].command) == 1
      wc027ProducerJob!.properties.template.containers[0].command[0] == 'athena-context'
      length(wc027ProducerJob!.properties.template.containers[0].args) == 1
      wc027ProducerJob!.properties.template.containers[0].args[0] == 'wc027-enrichment-feed-producer'
      length(wc027ProducerJob!.properties.template.containers[0].env) == 2
      wc027ProducerJob!.properties.template.containers[0].env[0].name == 'AZURE_CLIENT_ID'
      wc027ProducerJob!.properties.template.containers[0].env[0].value == wc027ParsedConfiguration.serviceBus.brokerIdentityClientId
      wc027ProducerJob!.properties.template.containers[0].env[1].name == 'ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON'
      wc027ProducerJob!.properties.template.containers[0].env[1].value == wc027EnrichmentFeedProducerConfigurationJson
      wc027ProducerJob!.properties.template.containers[0].resources.cpu == 1
      wc027ProducerJob!.properties.template.containers[0].resources.memory == '2Gi'
      empty(wc027ProducerJob!.properties.template.containers[0].?probes ?? [])
      empty(wc027ProducerJob!.properties.template.containers[0].?volumeMounts ?? [])
      empty(wc027ProducerJob!.properties.template.?initContainers ?? [])
      empty(wc027ProducerJob!.properties.template.?volumes ?? [])
    ], false)
  : false
var wc027ProducerExecutionConfigurationMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? !contains([
      wc027ProducerJob!.properties.environmentId == azureMcp.outputs.managedEnvironmentResourceId
      wc027ProducerJob!.properties.configuration.replicaTimeout == 900
      wc027ProducerJob!.properties.configuration.replicaRetryLimit == 0
      wc027ProducerJob!.properties.configuration.triggerType == 'Event'
      empty(wc027ProducerJob!.properties.configuration.?identitySettings ?? [])
      empty(wc027ProducerJob!.properties.configuration.?secrets ?? [])
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.parallelism == 1
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.replicaCompletionCount == 1
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.minExecutions == 0
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.maxExecutions == 1
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.pollingInterval == wc027RuntimeDeliveryBudget.feedKedaPollingIntervalSeconds
      length(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
    ], false)
  : false
var wc027ProducerHasExactScalerRuleCount = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? length(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1
  : false
var wc027ProducerScalerMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid && !empty(wc027EnrichmentFeedProducerConfigurationJson) && wc027ProducerHasExactScalerRuleCount
  ? !contains([
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].name == 'wc027-signed-binding'
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].type == 'azure-servicebus'
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].identity == wc027ParsedConfiguration.serviceBus.brokerIdentityResourceId
      empty(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].?auth ?? [])
      length(items(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata)) == 5
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.namespace == first(split(wc027ParsedConfiguration.serviceBus.namespace, '.'))
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.queueName == wc027ParsedConfiguration.serviceBus.triggerQueueName
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.messageCount == '1'
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.cloud == 'AzurePublicCloud'
      wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.isSessionsEnabled == 'true'
    ], false)
  : false
var wc027ProducerHasExactRegistryCount = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? length(wc027ProducerJob!.properties.configuration.registries) == 1
  : false
var wc027ProducerRegistryMatches = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid && !empty(wc027EnrichmentFeedProducerConfigurationJson) && wc027ProducerHasExactRegistryCount
  ? !contains([
      wc027ProducerJob!.properties.configuration.registries[0].server == wc027ProducerImageRegistryServer
      wc027ProducerJob!.properties.configuration.registries[0].identity == wc027ParsedConfiguration.serviceBus.brokerIdentityResourceId
      length(items(wc027ProducerJob!.properties.configuration.registries[0])) == 2
    ], false)
  : false
var wc027ProducerTagsMatch = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? !contains([
      wc027ProducerJob!.tags.runtimeConfigurationDigest == wc027EnrichmentFeedProducerConfigurationDigest
      wc027ProducerJob!.tags.bindingEvidenceDigest == wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId
    ], false)
  : false
var validatedWc027FeedV2ProducerReady = wc027FeedV2ProducerReady && !wc027EffectiveAcrAssignmentsVerified
  ? fail('WC-027 feed producer requires PR #102-equivalent full role-definition resolution proving no extra direct, inherited, group-derived, or sibling-registry pull-capable assignment')
  : wc027FeedV2ProducerReady && !startsWith(
      toLower(wc027EnrichmentFeedProducerJobResourceId),
      '/subscriptions/'
    )
    ? fail('WC-027 Notification v2 cannot be enabled without the exact deployed producer Job resource ID')
    : wc027FeedV2ProducerReady && !wc027ProducerJobResourceIdValid
    ? fail('wc027EnrichmentFeedProducerJobResourceId must identify one Microsoft.App/jobs resource')
    : wc027FeedV2ProducerReady && !wc027ConfigurationDigestValid
      ? fail('WC-027 Notification v2 requires the exact deployed producer configuration digest')
      : wc027FeedV2ProducerReady && empty(wc027EnrichmentFeedProducerConfigurationJson)
        ? fail('WC-027 Notification v2 requires the exact deployed producer configuration JSON')
        : wc027FeedV2ProducerReady && !wc027RuntimeDeliveryBudgetValid
          ? fail('WC-027 enrichment runtime delivery budget does not match the reviewed publisher and feed delivery phases')
          : wc027FeedV2ProducerReady && !wc027ProducerImageValid
            ? fail('WC-027 producer requires the exact digest-pinned deployed image')
            : wc027FeedV2ProducerReady && !wc027ProducerIdentityTypeMatches
              ? fail('WC-027 producer Job must use only user-assigned identities')
              : wc027FeedV2ProducerReady && !wc027ProducerHasExactContainerCount
                ? fail('WC-027 producer Job must contain exactly one reviewed container')
                : wc027FeedV2ProducerReady && !wc027ProducerTemplateMatches
                  ? fail('WC-027 producer Job execution template does not exactly match')
                  : wc027FeedV2ProducerReady && !wc027ProducerExecutionConfigurationMatches
                    ? fail('WC-027 producer Job replica and concurrency configuration does not exactly match')
                    : wc027FeedV2ProducerReady && !wc027ProducerScalerMatches
                      ? fail('WC-027 producer Job scaler configuration does not exactly match')
                      : wc027FeedV2ProducerReady && !wc027ProducerRegistryMatches
                        ? fail('WC-027 producer Job registry configuration does not exactly match')
                        : wc027FeedV2ProducerReady && !wc027ProducerTagsMatch
                          ? fail('WC-027 producer Job configuration and binding-evidence digest tags do not exactly match')
                          : wc027FeedV2ProducerReady && !validatedWc027RequestProducerReady
                          ? fail('WC-027 Notification v2 requires an explicitly ready guidance publication-request producer (wc027RequestProducerReady)')
                          : wc027FeedV2ProducerReady && !validatedWc027PublisherReady
                            ? fail('WC-027 Notification v2 requires an explicitly ready PublishedGuidanceAuthorityBinding.v2 publisher (wc027PublisherReady)')
                            : wc027FeedV2ProducerReady && empty(wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId)
                              ? fail('WC-027 Notification v2 requires deployment-derived RBAC binding evidence')
                              : wc027FeedV2ProducerReady && !wc027RbacEvidenceMatchesConfiguration
                                ? fail('WC-027 runtime configuration RBAC resources do not match its binding evidence')
                                : wc027FeedV2ProducerReady && !wc027ConfigurationIdentitiesMatchBinding
                                  ? fail('WC-027 runtime configuration identities do not exactly match its deployment binding')
                                  : wc027FeedV2ProducerReady && !wc027ProducerIdentitiesMatchExactly
                                    ? fail('WC-027 producer Job attached user-assigned identities do not exactly match the expected identity resource IDs')
                                    : wc027FeedV2ProducerReady && !validatedWc016RuntimeEnabled
                                      ? fail('WC-027 Notification v2 requires the deployed WC-016 runtime and notification outbox')
                                      : wc027FeedV2ProducerReady && validatedWc027PublisherReady
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
var wc016DetectorImageRepositoryPrefix = '${validatedAcceptanceImageRegistryServer}/athena/wc016-detector@sha256:'
var wc016DetectorImageDigestCandidate = replace(wc016DetectorImage, wc016DetectorImageRepositoryPrefix, '')
var wc016DetectorDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc016DetectorImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc016DetectorDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc016DetectorDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedWc016DetectorImage = wc016DetectorImage == toLower(wc016DetectorImage) && startsWith(
  wc016DetectorImage,
  wc016DetectorImageRepositoryPrefix
) && length(wc016DetectorImage) == length(wc016DetectorImageRepositoryPrefix) + 64 && length(
  wc016DetectorImageDigestCandidate
) == 64 && empty(
  wc016DetectorDigestInvalidCharacters
) && !endsWith(wc016DetectorImage, rejectedImageDigestSuffix)
  ? wc016DetectorImage
  : fail('wc016DetectorImage must use the fixed ACR repository and a real non-placeholder sha256 digest')
var wc016OrchestratorImageRepositoryPrefix = '${validatedAcceptanceImageRegistryServer}/athena/wc016-orchestrator@sha256:'
var wc016OrchestratorImageDigestCandidate = replace(wc016OrchestratorImage, wc016OrchestratorImageRepositoryPrefix, '')
var wc016OrchestratorDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc016OrchestratorImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc016OrchestratorDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc016OrchestratorDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedWc016OrchestratorImage = wc016OrchestratorImage == toLower(wc016OrchestratorImage) && startsWith(
  wc016OrchestratorImage,
  wc016OrchestratorImageRepositoryPrefix
) && length(wc016OrchestratorImage) == length(wc016OrchestratorImageRepositoryPrefix) + 64 && length(
  wc016OrchestratorImageDigestCandidate
) == 64 && empty(
  wc016OrchestratorDigestInvalidCharacters
) && !endsWith(wc016OrchestratorImage, rejectedImageDigestSuffix)
  ? wc016OrchestratorImage
  : fail('wc016OrchestratorImage must use the fixed ACR repository and a real non-placeholder sha256 digest')
var presentationAssetBlobEndpoint = 'https://${replayStorageAccountName}.blob.${environment().suffixes.storage}'
var collectorControllerFederatedCredentialIssuer = 'https://token.actions.githubusercontent.com'
var collectorControllerFederatedCredentialAudience = 'api://AzureADTokenExchange'
var collectorControllerFederatedCredentialSubject = 'repo:cabberley@26394346/Athena-workload-context@1334641162:environment:athena-live'
var collectorControllerRoleDefinitionGuid = guid(
  subscription().id,
  foundationResourceGroupName,
  'athena-wc013-collector-controller'
)
var wc016SignalReaderRoleDefinitionGuid = guid(
  targetDemoWorkloadSubscriptionId,
  targetDemoWorkloadResourceGroupName,
  'athena-wc016-approved-signal-reader'
)
var forbiddenCollectorControllerPrincipalIds = concat(
  map(operatorArtifactReaderObjectIds, objectId => toLower(string(objectId))),
  map(workloadReceiptWriterObjectIds, objectId => toLower(string(objectId))),
  [
    toLower(evidenceIdentity.properties.principalId)
    toLower(acceptanceJobIdentity.properties.principalId)
    toLower(presentationIdentity.outputs.principalId)
    toLower(wc016DetectorIdentity.outputs.principalId)
    toLower(wc016OrchestratorIdentity.outputs.principalId)
    toLower(wc016NotificationIdentity.outputs.principalId)
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

module wc027ProducerRuntimeId 'modules/job-runtime-id.bicep' = if (wc027FeedV2ProducerReady && wc027ProducerJobResourceIdShapeValid) {
  name: 'wc027-feed-runtime-id'
  params: {
    jobResourceId: wc027EnrichmentFeedProducerJobResourceId
  }
}

module wc027RequestProducerRuntimeId 'modules/job-runtime-id.bicep' = if (wc027RequestProducerReady && wc027RequestProducerJobResourceIdShapeValid) {
  name: 'wc027-request-producer-runtime-id'
  params: {
    jobResourceId: wc027RequestProducerJobResourceId
  }
}

module wc027PublisherRuntimeId 'modules/job-runtime-id.bicep' = if (wc027PublisherReady && wc027PublisherJobResourceIdShapeValid) {
  name: 'wc027-publisher-runtime-id'
  params: {
    jobResourceId: wc027PublisherJobResourceId
  }
}

resource wc027ProducerJob 'Microsoft.App/jobs@2025-01-01' existing = if (wc027FeedV2ProducerReady && wc027ProducerJobResourceIdShapeValid) {
  name: wc027ProducerJobResourceIdSegments[8]
  scope: resourceGroup(
    wc027ProducerJobResourceIdSegments[2],
    wc027ProducerJobResourceIdSegments[4]
  )
}

resource wc027RequestProducerJob 'Microsoft.App/jobs@2025-01-01' existing = if (wc027RequestProducerReady && wc027RequestProducerJobResourceIdShapeValid) {
  name: wc027RequestProducerJobResourceIdSegments[8]
  scope: resourceGroup(
    wc027RequestProducerJobResourceIdSegments[2],
    wc027RequestProducerJobResourceIdSegments[4]
  )
}

resource wc027PublisherJob 'Microsoft.App/jobs@2025-01-01' existing = if (wc027PublisherReady && wc027PublisherJobResourceIdShapeValid) {
  name: wc027PublisherJobResourceIdSegments[8]
  scope: resourceGroup(
    wc027PublisherJobResourceIdSegments[2],
    wc027PublisherJobResourceIdSegments[4]
  )
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

module wc016DetectorIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc016-detector-v2-identity'
  scope: foundationResourceGroup
  params: {
    name: '${namePrefix}-wc016-detector-v2-id'
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    tags: union(resourceTags, {
      identityPurpose: 'wc016-approved-signal-read-queue-send-state-only'
    })
  }
}

module wc016OrchestratorIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc016-orchestrator-v2-identity'
  scope: foundationResourceGroup
  params: {
    name: '${namePrefix}-wc016-orchestrator-v2-id'
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    tags: union(resourceTags, {
      identityPurpose: 'wc016-servicebus-signing-publication-only'
    })
  }
}

module wc016NotificationIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc016-notification-v2-identity'
  scope: foundationResourceGroup
  params: {
    name: '${namePrefix}-wc016-notification-v2-id'
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    tags: union(resourceTags, {
      identityPurpose: 'wc016-servicebus-teams-notification-only'
    })
  }
}

module presentationIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc013-presentation-pull-identity'
  scope: foundationResourceGroup
  params: {
    name: '${namePrefix}-presentation-id'
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    tags: union(resourceTags, {
      identityPurpose: 'presentation-acr-pull-and-private-assets-reader'
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

module wc016SignalReaderRole 'modules/wc016-signal-reader-role.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-approved-signal-reader-role'
  scope: subscription(targetDemoWorkloadSubscriptionId)
  params: {
    resourceGroupName: targetDemoWorkloadResourceGroupName
    roleDefinitionGuid: wc016SignalReaderRoleDefinitionGuid
  }
}

module wc016SignalReaderRbac 'modules/wc016-signal-reader-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-approved-signal-reader-rbac'
  scope: resourceGroup(
    targetDemoWorkloadSubscriptionId,
    targetDemoWorkloadResourceGroupName
  )
  params: {
    detectorPrincipalId: wc016DetectorIdentity.outputs.principalId
    orchestratorPrincipalId: wc016OrchestratorIdentity.outputs.principalId
    roleDefinitionId: wc016SignalReaderRole!.outputs.roleDefinitionId
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
    presentationImageRegistryRoleAssignmentMode: presentationImageRegistryRoleAssignmentMode
    deliveryImage: validatedAcceptanceImage
    presentationAssetBlobEndpoint: presentationAssetBlobEndpoint
    presentationAssetContainerName: presentationAssetContainerName
    incidentAssetContainerName: incidentAssetContainerName
    incidentSigningKeyId: incidentSigningKeyId
    incidentSigningKeyVaultKeyId: acceptanceResources.outputs.incidentSigningKeyUriWithVersion
    incidentSigningKeyFingerprint: signingKeyFingerprint
    presentationIdentityResourceId: presentationIdentity.outputs.resourceId
    presentationIdentityClientId: presentationIdentity.outputs.clientId
    presentationIdentityPrincipalId: presentationIdentity.outputs.principalId
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
    incidentSigningKeyName: incidentSigningKeyName
    incidentFeedV2SigningKeyName: incidentFeedV2SigningKeyName
    incidentReportSigningKeyName: incidentReportSigningKeyName
    incidentGuidanceSigningKeyName: incidentGuidanceSigningKeyName
    incidentEnrichmentSigningKeyName: incidentEnrichmentSigningKeyName
    incidentNotificationSigningKeyName: incidentNotificationSigningKeyName
    replayStorageAccountName: replayStorageAccountName
    replayTableName: replayTableName
    detectorStateTableName: wc016DetectorStateTableName
    notificationStateTableName: wc016NotificationStateTableName
    detectorIdentityPrincipalId: wc016DetectorIdentity.outputs.principalId
    artifactContainerName: artifactContainerName
    collectorArtifactContainerName: collectorArtifactContainerName
    presentationAssetContainerName: presentationAssetContainerName
    incidentAssetContainerName: incidentAssetContainerName
    presentationIdentityPrincipalId: presentationIdentity.outputs.principalId
    incidentOrchestratorPrincipalId: wc016OrchestratorIdentity.outputs.principalId
    notificationDispatcherPrincipalId: wc016NotificationIdentity.outputs.principalId
    wc016RuntimeEnabled: validatedWc016RuntimeEnabled
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
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: acceptanceJobIdentity.properties.principalId
    image: validatedAcceptanceImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
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
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: evidenceIdentity.properties.principalId
    image: validatedAcceptanceImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
  }
}

module collectorControllerImagePull 'modules/acr-pull-rbac.bicep' = {
  name: 'wc013-controller-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: collectorControllerIdentity.outputs.principalId
    image: validatedControllerImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
  }
}

module wc016DetectorImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-detector-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: wc016DetectorIdentity.outputs.principalId
    image: validatedWc016DetectorImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
  }
}

module wc016OrchestratorImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-orchestrator-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: wc016OrchestratorIdentity.outputs.principalId
    image: validatedWc016OrchestratorImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
  }
}

module wc016NotificationImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-notification-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryResourceId: acceptanceImageRegistryResourceId
    identityPrincipalId: wc016NotificationIdentity.outputs.principalId
    image: validatedWc016OrchestratorImage
    registryRoleAssignmentMode: acceptanceImageRegistryRoleAssignmentMode
  }
}

var wc013CoreAcrPullAssignments = concat([
  {
    label: 'acceptance'
    assignmentResourceId: acceptanceImagePull.outputs.roleAssignmentResourceId
    principalId: acceptanceJobIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acceptanceImagePull.outputs.roleDefinitionResourceId
    roleAssignmentMode: acceptanceImagePull.outputs.roleAssignmentMode
    anonymousPullEnabled: acceptanceImagePull.outputs.anonymousPullEnabled
    scope: acceptanceImagePull.outputs.registryResourceId
    image: validatedAcceptanceImage
    repositoryName: acceptanceImagePull.outputs.repositoryName
    conditionVersion: acceptanceImagePull.outputs.?conditionVersion
    condition: acceptanceImagePull.outputs.?condition
  }
  {
    label: 'evidence'
    assignmentResourceId: evidenceCollectorImagePull.outputs.roleAssignmentResourceId
    principalId: evidenceIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: evidenceCollectorImagePull.outputs.roleDefinitionResourceId
    roleAssignmentMode: evidenceCollectorImagePull.outputs.roleAssignmentMode
    anonymousPullEnabled: evidenceCollectorImagePull.outputs.anonymousPullEnabled
    scope: evidenceCollectorImagePull.outputs.registryResourceId
    image: validatedAcceptanceImage
    repositoryName: evidenceCollectorImagePull.outputs.repositoryName
    conditionVersion: evidenceCollectorImagePull.outputs.?conditionVersion
    condition: evidenceCollectorImagePull.outputs.?condition
  }
  {
    label: 'controller'
    assignmentResourceId: collectorControllerImagePull.outputs.roleAssignmentResourceId
    principalId: collectorControllerIdentity.outputs.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: collectorControllerImagePull.outputs.roleDefinitionResourceId
    roleAssignmentMode: collectorControllerImagePull.outputs.roleAssignmentMode
    anonymousPullEnabled: collectorControllerImagePull.outputs.anonymousPullEnabled
    scope: collectorControllerImagePull.outputs.registryResourceId
    image: validatedControllerImage
    repositoryName: collectorControllerImagePull.outputs.repositoryName
    conditionVersion: collectorControllerImagePull.outputs.?conditionVersion
    condition: collectorControllerImagePull.outputs.?condition
  }
], presentationWeb.outputs.acrPullAssignments)
var wc016AcrPullAssignments = validatedWc016RuntimeEnabled
  ? [
      {
        label: 'wc016-detector'
        assignmentResourceId: wc016DetectorImagePull!.outputs.roleAssignmentResourceId
        principalId: wc016DetectorIdentity.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionId: wc016DetectorImagePull!.outputs.roleDefinitionResourceId
        roleAssignmentMode: wc016DetectorImagePull!.outputs.roleAssignmentMode
        anonymousPullEnabled: wc016DetectorImagePull!.outputs.anonymousPullEnabled
        scope: wc016DetectorImagePull!.outputs.registryResourceId
        image: validatedWc016DetectorImage
        repositoryName: wc016DetectorImagePull!.outputs.repositoryName
        conditionVersion: wc016DetectorImagePull!.outputs.?conditionVersion
        condition: wc016DetectorImagePull!.outputs.?condition
      }
      {
        label: 'wc016-orchestrator'
        assignmentResourceId: wc016OrchestratorImagePull!.outputs.roleAssignmentResourceId
        principalId: wc016OrchestratorIdentity.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionId: wc016OrchestratorImagePull!.outputs.roleDefinitionResourceId
        roleAssignmentMode: wc016OrchestratorImagePull!.outputs.roleAssignmentMode
        anonymousPullEnabled: wc016OrchestratorImagePull!.outputs.anonymousPullEnabled
        scope: wc016OrchestratorImagePull!.outputs.registryResourceId
        image: validatedWc016OrchestratorImage
        repositoryName: wc016OrchestratorImagePull!.outputs.repositoryName
        conditionVersion: wc016OrchestratorImagePull!.outputs.?conditionVersion
        condition: wc016OrchestratorImagePull!.outputs.?condition
      }
      {
        label: 'wc016-notification'
        assignmentResourceId: wc016NotificationImagePull!.outputs.roleAssignmentResourceId
        principalId: wc016NotificationIdentity.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionId: wc016NotificationImagePull!.outputs.roleDefinitionResourceId
        roleAssignmentMode: wc016NotificationImagePull!.outputs.roleAssignmentMode
        anonymousPullEnabled: wc016NotificationImagePull!.outputs.anonymousPullEnabled
        scope: wc016NotificationImagePull!.outputs.registryResourceId
        image: validatedWc016OrchestratorImage
        repositoryName: wc016NotificationImagePull!.outputs.repositoryName
        conditionVersion: wc016NotificationImagePull!.outputs.?conditionVersion
        condition: wc016NotificationImagePull!.outputs.?condition
      }
    ]
  : []
var wc013AcrPullAssignments = concat(
  wc013CoreAcrPullAssignments,
  wc016AcrPullAssignments
)

var notificationV2ConfigurationJson = string({
  lifecycle: {
    keyVaultKeyId: acceptanceResources.outputs.incidentSigningKeyUriWithVersion
    keyId: incidentSigningKeyId
    keyFingerprint: signingKeyFingerprint
  }
  feed: {
    keyVaultKeyId: acceptanceResources.outputs.incidentFeedV2SigningKeyUriWithVersion
    keyId: incidentFeedV2SigningKeyId
    keyFingerprint: incidentFeedV2SigningKeyFingerprint
  }
  report: {
    keyVaultKeyId: acceptanceResources.outputs.incidentReportSigningKeyUriWithVersion
    keyId: incidentReportSigningKeyId
    keyFingerprint: incidentReportSigningKeyFingerprint
  }
  guidance: {
    keyVaultKeyId: acceptanceResources.outputs.incidentGuidanceSigningKeyUriWithVersion
    keyId: incidentGuidanceSigningKeyId
    keyFingerprint: incidentGuidanceSigningKeyFingerprint
  }
  enrichment: {
    keyVaultKeyId: acceptanceResources.outputs.incidentEnrichmentSigningKeyUriWithVersion
    keyId: incidentEnrichmentSigningKeyId
    keyFingerprint: incidentEnrichmentSigningKeyFingerprint
  }
  notification: {
    keyVaultKeyId: acceptanceResources.outputs.incidentNotificationSigningKeyUriWithVersion
    keyId: incidentNotificationSigningKeyId
    keyFingerprint: incidentNotificationSigningKeyFingerprint
  }
})

module wc016Runtime '../wc016-event-reassessment/main.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-deployable-runtime'
  scope: foundationResourceGroup
  dependsOn: [
    evidenceCollectorImagePull
    wc016DetectorImagePull
    wc016OrchestratorImagePull
    wc016NotificationImagePull
    wc016SignalReaderRbac
  ]
  params: {
    namePrefix: namePrefix
    location: location
    managedEnvironmentResourceId: azureMcp.outputs.managedEnvironmentResourceId
    virtualNetworkResourceId: azureMcp.outputs.virtualNetworkResourceId
    privateEndpointSubnetResourceId: azureMcp.outputs.privateEndpointSubnetResourceId
    registryServer: validatedAcceptanceImageRegistryServer
    detectorIdentityResourceId: wc016DetectorIdentity.outputs.resourceId
    detectorIdentityClientId: wc016DetectorIdentity.outputs.clientId
    detectorIdentityPrincipalId: wc016DetectorIdentity.outputs.principalId
    orchestratorIdentityResourceId: wc016OrchestratorIdentity.outputs.resourceId
    orchestratorIdentityClientId: wc016OrchestratorIdentity.outputs.clientId
    orchestratorIdentityPrincipalId: wc016OrchestratorIdentity.outputs.principalId
    notificationIdentityResourceId: wc016NotificationIdentity.outputs.resourceId
    notificationIdentityClientId: wc016NotificationIdentity.outputs.clientId
    notificationIdentityPrincipalId: wc016NotificationIdentity.outputs.principalId
    detectorImage: validatedWc016DetectorImage
    orchestratorImage: validatedWc016OrchestratorImage
    databaseVmResourceId: wc016DatabaseVmResourceId
    webVmResourceIds: wc016WebVmResourceIds
    loadBalancerResourceId: wc016LoadBalancerResourceId
    workloadSubscriptionId: targetDemoWorkloadSubscriptionId
    workloadResourceGroupName: targetDemoWorkloadResourceGroupName
    detectorStateTableEndpoint: acceptanceResources.outputs.replayTableEndpoint
    detectorStateTableName: acceptanceResources.outputs.detectorStateTableName
    detectorStatePartitionKey: wc016DetectorStatePartitionKey
    notificationStateTableEndpoint: acceptanceResources.outputs.replayTableEndpoint
    notificationStateTableName: acceptanceResources.outputs.notificationStateTableName
    notificationStatePartitionKey: wc016NotificationStatePartitionKey
    incidentAssetBlobEndpoint: presentationAssetBlobEndpoint
    presentationUrl: presentationWeb.outputs.httpsUrl
    signingKeyUriWithVersion: acceptanceResources.outputs.incidentSigningKeyUriWithVersion
    signingKeyId: incidentSigningKeyId
    signingKeyFingerprint: signingKeyFingerprint
    notificationV2ConfigurationJson: notificationV2ConfigurationJson
    notificationV2ProducerReady: validatedWc027FeedV2ProducerReady
    teamsConnectionName: 'teams'
    teamsNotifierWorkflowName: 'athena-wc016-teams-notifier'
    tags: resourceTags
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

@description('Exact versioned WC-016 incident signing-key URI.')
output incidentSigningKeyUriWithVersion string = acceptanceResources.outputs.incidentSigningKeyUriWithVersion

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

@description('Dedicated WC-016 detector and notification state-table boundaries.')
output wc016StateTables object = {
  detectorStateTableEndpoint: acceptanceResources.outputs.replayTableEndpoint
  detectorStateTableName: acceptanceResources.outputs.detectorStateTableName
  detectorStateTableResourceId: acceptanceResources.outputs.detectorStateTableResourceId
  detectorStatePartitionKey: wc016DetectorStatePartitionKey
  notificationStateTableEndpoint: acceptanceResources.outputs.replayTableEndpoint
  notificationStateTableName: acceptanceResources.outputs.notificationStateTableName
  notificationStateTableResourceId: acceptanceResources.outputs.notificationStateTableResourceId
  notificationStatePartitionKey: wc016NotificationStatePartitionKey
}

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

@description('Dedicated private incident asset container name.')
output incidentAssetContainerName string = acceptanceResources.outputs.incidentAssetContainerName

@description('Resource ID of the private incident asset container.')
output incidentAssetContainerResourceId string = acceptanceResources.outputs.incidentAssetContainerResourceId

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

@description('Presentation identity resource ID. This identity receives only AcrPull and Blob Data Reader on presentation-assets and incident-assets.')
output presentationIdentityResourceId string = presentationIdentity.outputs.resourceId

@description('Presentation identity client ID for ACR pull and read-only presentation asset access.')
output presentationIdentityClientId string = presentationIdentity.outputs.clientId

@description('Presentation identity principal ID scoped to ACR pull and read-only access to the two presentation containers.')
output presentationIdentityPrincipalId string = presentationIdentity.outputs.principalId

@description('Existing trusted-ingestion resource application client ID; Bicep intentionally does not create Entra applications.')
output trustedIngestionResourceApplicationClientId string = trustedIngestionResourceApplicationClientId

@description('Exact trusted-ingestion token audience for the rendered collector trust configuration.')
output trustedIngestionAudience string = trustedIngestionAudience

@description('Exact reviewed demo workload resource-group scope receiving the only Reader assignment.')
output targetDemoWorkloadResourceGroupScope string = '/subscriptions/${targetDemoWorkloadSubscriptionId}/resourceGroups/${targetDemoWorkloadResourceGroupName}'

@description('Exact reviewed read-only Azure MCP tool allowlist.')
output allowedTools array = azureMcp.outputs.allowedTools

@description('Dedicated hardened WC-016 v2 detector identity resource ID.')
output wc016DetectorIdentityResourceId string = wc016DetectorIdentity.outputs.resourceId

@description('Dedicated hardened WC-016 v2 detector identity client ID.')
output wc016DetectorIdentityClientId string = wc016DetectorIdentity.outputs.clientId

@description('Hardened WC-016 v2 orchestrator identity resource ID. This identity has no broad workload Reader role.')
output wc016OrchestratorIdentityResourceId string = wc016OrchestratorIdentity.outputs.resourceId

@description('Hardened WC-016 v2 orchestrator identity client ID.')
output wc016OrchestratorIdentityClientId string = wc016OrchestratorIdentity.outputs.clientId

@description('Private WC-016 Service Bus fully qualified namespace.')
output wc016ServiceBusNamespace string = validatedWc016RuntimeEnabled
  ? wc016Runtime!.outputs.namespaceHostName
  : ''

@description('Exact approved WC-016 resource-role and alert-rule JSON for deployment diagnostics.')
output wc016ApprovedConfiguration object = {
  wc016ApprovedResourceRolesJson: validatedWc016RuntimeEnabled
    ? wc016Runtime!.outputs.approvedResourceRolesJson
    : ''
  wc016ApprovedAlertRulesJson: validatedWc016RuntimeEnabled
    ? wc016Runtime!.outputs.approvedAlertRulesJson
    : ''
  wc013AcrPullAssignments: wc013AcrPullAssignments
}

@description('WC-016 scheduled detector Job resource ID.')
output wc016DetectorJobResourceId string = validatedWc016RuntimeEnabled
  ? wc016Runtime!.outputs.detectorJobResourceId
  : ''

@description('WC-016 session queue-scaled orchestrator Job resource ID.')
output wc016OrchestratorJobResourceId string = validatedWc016RuntimeEnabled
  ? wc016Runtime!.outputs.orchestratorJobResourceId
  : ''
