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
var wc027ProducerJobResourceIdRawSegments = split(
  wc027EnrichmentFeedProducerJobResourceId,
  '/'
)
var wc027PublisherJobResourceIdRawSegments = split(wc027PublisherJobResourceId, '/')
var wc027PublisherJobResourceIdSegments = concat(
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
  ],
  wc027PublisherJobResourceIdRawSegments
)
var wc027PublisherJobResourceIdValid = length(wc027PublisherJobResourceIdRawSegments) == 9 && wc027PublisherJobResourceIdSegments[1] == 'subscriptions' && wc027PublisherJobResourceIdSegments[3] == 'resourceGroups' && toLower(wc027PublisherJobResourceIdSegments[6]) == 'microsoft.app' && toLower(wc027PublisherJobResourceIdSegments[7]) == 'jobs' && !empty(wc027PublisherJobResourceIdSegments[8])
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
    ? '{"schemaVersion":"","deploymentBinding":{"attachedIdentityResourceIds":[],"bindingEvidenceId":"","rbacResourceIds":[]},"enrichmentRuntimeConfiguration":{"schemaVersion":"","monitoringCollectorContract":{"schemaVersion":"","acquisitionReceiptSchemaVersion":""},"monitoringCollectorContractDigest":"","monitoringAcquisitionAuthority":{"schemaVersion":"","authorityDigest":"","collectorContractDigest":"","maxAcquisitionCalls":0,"maxLogicalExchanges":0},"monitoringAcquisitionAuthorityDigest":""},"monitoringAcquisitionTrust":{"collectorContractDigest":"","acquisitionAuthorityDigest":""},"serviceBus":{"brokerIdentityResourceId":"","namespace":"","requestQueueName":""}}'
    : wc027PublisherConfigurationJson
)
var wc027ParsedProducerConfiguration = json(
  empty(wc027EnrichmentFeedProducerConfigurationJson)
    ? '{"schemaVersion":"","monitoringCollectorContract":{"schemaVersion":"","acquisitionReceiptSchemaVersion":""},"monitoringCollectorContractDigest":"","monitoringAcquisitionAuthority":{"schemaVersion":"","authorityDigest":"","collectorContractDigest":"","maxAcquisitionCalls":0,"maxLogicalExchanges":0},"monitoringAcquisitionAuthorityDigest":""}'
    : wc027EnrichmentFeedProducerConfigurationJson
)
var wc027MonitoringCollectorContractDigestHex = replace(wc027ParsedProducerConfiguration.monitoringCollectorContractDigest, 'sha256:', '')
var wc027MonitoringCollectorContractDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027MonitoringCollectorContractDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027MonitoringCollectorContractDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027MonitoringCollectorContractDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027MonitoringCollectorContractDigestValid = wc027ParsedProducerConfiguration.monitoringCollectorContractDigest == toLower(wc027ParsedProducerConfiguration.monitoringCollectorContractDigest) && startsWith(wc027ParsedProducerConfiguration.monitoringCollectorContractDigest, 'sha256:') && length(wc027MonitoringCollectorContractDigestHex) == 64 && empty(wc027MonitoringCollectorContractDigestInvalidCharacters) && wc027MonitoringCollectorContractDigestHex != '0000000000000000000000000000000000000000000000000000000000000000'
var wc027MonitoringAcquisitionAuthorityDigestHex = replace(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest, 'sha256:', '')
var wc027MonitoringAcquisitionAuthorityDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  wc027MonitoringAcquisitionAuthorityDigestHex,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var wc027MonitoringAcquisitionAuthorityDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  wc027MonitoringAcquisitionAuthorityDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var wc027MonitoringAcquisitionAuthorityDigestValid = wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest == toLower(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest) && startsWith(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest, 'sha256:') && length(wc027MonitoringAcquisitionAuthorityDigestHex) == 64 && empty(wc027MonitoringAcquisitionAuthorityDigestInvalidCharacters) && wc027MonitoringAcquisitionAuthorityDigestHex != '0000000000000000000000000000000000000000000000000000000000000000'
var wc027ProducerMonitoringTrustIsCurrent = wc027ParsedProducerConfiguration.schemaVersion == 'athena.wc027EnrichmentFeedRuntimeConfiguration.v2' && wc027ParsedProducerConfiguration.monitoringCollectorContract.schemaVersion == 'athena.wc028MonitoringCollectorContract.v10' && wc027ParsedProducerConfiguration.monitoringCollectorContract.acquisitionReceiptSchemaVersion == 'athena.wc028MonitoringAcquisitionReceipt.v6' && wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.schemaVersion == 'athena.wc028MonitoringAcquisitionAuthority.v6' && wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.authorityDigest == wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest && wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.collectorContractDigest == wc027ParsedProducerConfiguration.monitoringCollectorContractDigest && int(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.maxLogicalExchanges) >= 1 && int(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.maxAcquisitionCalls) >= int(wc027ParsedProducerConfiguration.monitoringAcquisitionAuthority.maxLogicalExchanges) && wc027MonitoringCollectorContractDigestValid && wc027MonitoringAcquisitionAuthorityDigestValid
var wc027PublisherMonitoringTrustMatches = wc027ParsedPublisherConfiguration.schemaVersion == 'athena.wc027GuidanceAuthorityPublisherConfiguration.v2' && wc027ParsedPublisherConfiguration.monitoringAcquisitionTrust.collectorContractDigest == wc027ParsedProducerConfiguration.monitoringCollectorContractDigest && wc027ParsedPublisherConfiguration.monitoringAcquisitionTrust.acquisitionAuthorityDigest == wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest
var wc027PublisherImageRegistryServer = first(split(wc027PublisherImage, '/'))
var wc027PublisherExpectedIdentityResourceIds = map(
  wc027ParsedPublisherConfiguration.deploymentBinding.attachedIdentityResourceIds,
  identityResourceId => toLower(identityResourceId)
)
var wc027PublisherRbacResourceIds = wc027ParsedPublisherConfiguration.deploymentBinding.rbacResourceIds
var wc027PublisherRbacEvidenceMatches = !empty(wc027PublisherRbacResourceIds) && guid(
  join(wc027PublisherRbacResourceIds, '|')
) == wc027ParsedPublisherConfiguration.deploymentBinding.bindingEvidenceId
var wc027PublisherAttachedIdentityResourceIds = wc027PublisherReady && wc027PublisherJobResourceIdValid
  ? map(items(wc027PublisherJob!.identity.userAssignedIdentities), identity => toLower(identity.key))
  : []
var wc027PublisherIdentitiesMatch = !empty(wc027PublisherExpectedIdentityResourceIds) && length(
  wc027PublisherAttachedIdentityResourceIds
) == length(wc027PublisherExpectedIdentityResourceIds) && length(union(
  wc027PublisherAttachedIdentityResourceIds,
  wc027PublisherExpectedIdentityResourceIds
)) == length(wc027PublisherExpectedIdentityResourceIds)
var validatedWc027PublisherReady = wc027PublisherReady && !wc027PublisherJobResourceIdValid
  ? fail('wc027PublisherJobResourceId must identify one Microsoft.App/jobs resource')
  : wc027PublisherReady && !wc027PublisherConfigurationDigestValid
    ? fail('WC-027 publisher requires the exact deployed configuration digest')
    : wc027PublisherReady && empty(wc027PublisherConfigurationJson)
      ? fail('WC-027 publisher requires the exact deployed configuration JSON')
      : wc027PublisherReady && !wc027PublisherImageValid
        ? fail('WC-027 publisher requires the exact digest-pinned deployed image')
        : wc027PublisherReady && wc027PublisherJob!.properties.template.containers[0].image != wc027PublisherImage
          ? fail('WC-027 publisher Job image does not match')
          : wc027PublisherReady && length(wc027PublisherJob!.properties.template.containers[0].command) != 1
            ? fail('WC-027 publisher Job command array does not match')
          : wc027PublisherReady && wc027PublisherJob!.properties.template.containers[0].command[0] != 'athena-context'
            ? fail('WC-027 publisher Job command does not match')
            : wc027PublisherReady && length(wc027PublisherJob!.properties.template.containers[0].args) != 1
              ? fail('WC-027 publisher Job arguments array does not match')
            : wc027PublisherReady && wc027PublisherJob!.properties.template.containers[0].args[0] != 'wc027-guidance-authority-publisher'
              ? fail('WC-027 publisher Job arguments do not match')
              : wc027PublisherReady && wc027PublisherJob!.properties.configuration.triggerType != 'Event'
                ? fail('WC-027 publisher Job trigger type does not match')
                : wc027PublisherReady && wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.maxExecutions != 1
                  ? fail('WC-027 publisher Job concurrency does not match')
                  : wc027PublisherReady && length(wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules) != 1
                    ? fail('WC-027 publisher Job scaler rules do not match')
                  : wc027PublisherReady && wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].type != 'azure-servicebus'
                    ? fail('WC-027 publisher Job scaler type does not match')
                  : wc027PublisherReady && wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].identity != wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId
                    ? fail('WC-027 publisher Job scaler identity does not match')
                    : wc027PublisherReady && wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.namespace != first(split(wc027ParsedPublisherConfiguration.serviceBus.namespace, '.'))
                      ? fail('WC-027 publisher Job scaler namespace does not match')
                    : wc027PublisherReady && wc027PublisherJob!.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.queueName != wc027ParsedPublisherConfiguration.serviceBus.requestQueueName
                      ? fail('WC-027 publisher Job scaler queue does not match')
                    : wc027PublisherReady && length(wc027PublisherJob!.properties.configuration.registries) != 1
                      ? fail('WC-027 publisher Job registry array does not match')
                    : wc027PublisherReady && wc027PublisherJob!.properties.configuration.registries[0].identity != wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityResourceId
                      ? fail('WC-027 publisher Job registry identity does not match')
                    : wc027PublisherReady && wc027PublisherJob!.properties.configuration.registries[0].server != wc027PublisherImageRegistryServer
                      ? fail('WC-027 publisher Job registry server does not match')
                      : wc027PublisherReady && wc027PublisherJob!.tags.enrichmentRuntimeConfigurationDigest != wc027EnrichmentFeedProducerConfigurationDigest
                        ? fail('WC-027 publisher embedded runtime configuration does not match the producer')
                      : wc027PublisherReady && string(wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration) != string(wc027ParsedProducerConfiguration)
                        ? fail('WC-027 publisher embedded runtime configuration JSON does not match the producer')
                      : wc027PublisherReady && !wc027ProducerMonitoringTrustIsCurrent
                        ? fail('WC-027 publisher requires the exact v9 monitoring collector contract and acquisition authority binding')
                      : wc027PublisherReady && !wc027PublisherMonitoringTrustMatches
                        ? fail('WC-027 publisher monitoring acquisition trust does not match the producer')
                      : wc027PublisherReady && wc027PublisherJob!.tags.monitoringCollectorContractDigest != wc027ParsedProducerConfiguration.monitoringCollectorContractDigest
                        ? fail('WC-027 publisher collector contract digest tag does not match')
                      : wc027PublisherReady && wc027PublisherJob!.tags.monitoringAcquisitionAuthorityDigest != wc027ParsedProducerConfiguration.monitoringAcquisitionAuthorityDigest
                        ? fail('WC-027 publisher acquisition authority digest tag does not match')
      : wc027PublisherReady && wc027PublisherJob!.tags.runtimeConfigurationDigest != wc027PublisherConfigurationDigest
        ? fail('WC-027 publisher Job configuration digest tag does not match')
        : wc027PublisherReady && wc027PublisherJob!.properties.template.containers[0].env[1].name != 'ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON'
          ? fail('WC-027 publisher Job does not contain the exact activation configuration')
          : wc027PublisherReady && wc027PublisherJob!.properties.template.containers[0].env[1].value != wc027PublisherConfigurationJson
            ? fail('WC-027 publisher Job configuration does not match')
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
var wc027ProducerJobResourceIdValid = length(wc027ProducerJobResourceIdRawSegments) == 9 && wc027ProducerJobResourceIdSegments[1] == 'subscriptions' && wc027ProducerJobResourceIdSegments[3] == 'resourceGroups' && toLower(wc027ProducerJobResourceIdSegments[6]) == 'microsoft.app' && toLower(wc027ProducerJobResourceIdSegments[7]) == 'jobs' && !empty(wc027ProducerJobResourceIdSegments[8])
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
var wc027ParsedConfiguration = json(
  empty(wc027EnrichmentFeedProducerConfigurationJson)
    ? '{"schemaVersion":"","deploymentBinding":{"attachedIdentityResourceIds":[],"bindingEvidenceId":"","rbacResourceIds":[]},"monitoringCollectorContract":{"schemaVersion":"","acquisitionReceiptSchemaVersion":""},"monitoringCollectorContractDigest":"","monitoringAcquisitionAuthority":{"schemaVersion":"","authorityDigest":"","collectorContractDigest":"","maxAcquisitionCalls":0,"maxLogicalExchanges":0},"monitoringAcquisitionAuthorityDigest":""}'
    : wc027EnrichmentFeedProducerConfigurationJson
)
var wc027AttachedIdentityResourceIds = wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid
  ? map(items(wc027ProducerJob!.identity.userAssignedIdentities), attachedIdentity => toLower(attachedIdentity.key))
  : []
var wc027ExpectedIdentityResourceIds = map(
  wc027ParsedConfiguration.deploymentBinding.attachedIdentityResourceIds,
  expectedIdentityResourceId => toLower(expectedIdentityResourceId)
)
var wc027ConfiguredIdentityResourceIds = wc027FeedV2ProducerReady && !empty(wc027EnrichmentFeedProducerConfigurationJson)
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
var validatedWc027FeedV2ProducerReady = wc027FeedV2ProducerReady && !startsWith(
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
        : wc027FeedV2ProducerReady && wc027ProducerJob!.tags.runtimeConfigurationDigest != wc027EnrichmentFeedProducerConfigurationDigest
          ? fail('WC-027 producer Job configuration digest tag does not match the activation input')
          : wc027FeedV2ProducerReady && wc027ProducerJob!.properties.template.containers[0].env[1].name != 'ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON'
            ? fail('WC-027 producer Job does not contain the exact activation configuration')
            : wc027FeedV2ProducerReady && wc027ProducerJob!.properties.template.containers[0].env[1].value != wc027EnrichmentFeedProducerConfigurationJson
              ? fail('WC-027 producer Job configuration does not match the activation input')
            : wc027FeedV2ProducerReady && !wc027ProducerMonitoringTrustIsCurrent
              ? fail('WC-027 Notification v2 requires the exact v9 monitoring collector contract and acquisition authority binding')
            : wc027FeedV2ProducerReady && wc027ProducerJob!.tags.monitoringCollectorContractDigest != wc027ParsedConfiguration.monitoringCollectorContractDigest
              ? fail('WC-027 producer collector contract digest tag does not match its deployed configuration')
            : wc027FeedV2ProducerReady && wc027ProducerJob!.tags.monitoringAcquisitionAuthorityDigest != wc027ParsedConfiguration.monitoringAcquisitionAuthorityDigest
              ? fail('WC-027 producer acquisition authority digest tag does not match its deployed configuration')
            : wc027FeedV2ProducerReady && !validatedWc027PublisherReady
                ? fail('WC-027 Notification v2 requires an explicitly ready PublishedGuidanceAuthorityBinding.v2 publisher (wc027PublisherReady)')
                : wc027FeedV2ProducerReady && empty(wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId)
                  ? fail('WC-027 Notification v2 requires deployment-derived RBAC binding evidence')
                  : wc027FeedV2ProducerReady && !wc027RbacEvidenceMatchesConfiguration
                    ? fail('WC-027 runtime configuration RBAC resources do not match its binding evidence')
                  : wc027FeedV2ProducerReady && wc027ProducerJob!.tags.bindingEvidenceDigest != wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId
                      ? fail('WC-027 producer Job RBAC binding evidence tag does not match its deployed configuration')
                      : wc027FeedV2ProducerReady && !wc027ConfigurationIdentitiesMatchBinding
                        ? fail('WC-027 runtime configuration identities do not exactly match its deployment binding')
                        : wc027FeedV2ProducerReady && !wc027ProducerIdentitiesMatchExactly
                          ? fail('WC-027 producer Job attached user-assigned identities do not exactly match the expected identity resource IDs')
                          : wc027FeedV2ProducerReady && wc027ProducerJob!.properties.template.containers[0].env[0].name != 'AZURE_CLIENT_ID'
                            ? fail('WC-027 producer Job does not expose its derived broker client ID')
                            : wc027FeedV2ProducerReady && wc027ProducerJob!.properties.template.containers[0].env[0].value != wc027ParsedConfiguration.serviceBus.brokerIdentityClientId
                              ? fail('WC-027 producer Job broker identity does not match its deployed configuration')
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

resource wc027ProducerJob 'Microsoft.App/jobs@2025-01-01' existing = if (wc027FeedV2ProducerReady && wc027ProducerJobResourceIdValid) {
  name: wc027ProducerJobResourceIdSegments[8]
  scope: resourceGroup(
    wc027ProducerJobResourceIdSegments[2],
    wc027ProducerJobResourceIdSegments[4]
  )
}

resource wc027PublisherJob 'Microsoft.App/jobs@2025-01-01' existing = if (wc027PublisherReady && wc027PublisherJobResourceIdValid) {
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

module wc016DetectorImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-detector-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    identityName: '${namePrefix}-wc016-detector-v2-id'
    identityPrincipalId: wc016DetectorIdentity.outputs.principalId
  }
}

module wc016OrchestratorImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-orchestrator-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    identityName: '${namePrefix}-wc016-orchestrator-v2-id'
    identityPrincipalId: wc016OrchestratorIdentity.outputs.principalId
  }
}

module wc016NotificationImagePull 'modules/acr-pull-rbac.bicep' = if (validatedWc016RuntimeEnabled) {
  name: 'wc016-notification-v2-image-pull'
  scope: resourceGroup(
    split(acceptanceImageRegistryResourceId, '/')[2],
    split(acceptanceImageRegistryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(acceptanceImageRegistryResourceId, '/'))
    identityName: '${namePrefix}-wc016-notification-v2-id'
    identityPrincipalId: wc016NotificationIdentity.outputs.principalId
  }
}

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
}

@description('WC-016 scheduled detector Job resource ID.')
output wc016DetectorJobResourceId string = validatedWc016RuntimeEnabled
  ? wc016Runtime!.outputs.detectorJobResourceId
  : ''

@description('WC-016 session queue-scaled orchestrator Job resource ID.')
output wc016OrchestratorJobResourceId string = validatedWc016RuntimeEnabled
  ? wc016Runtime!.outputs.orchestratorJobResourceId
  : ''
