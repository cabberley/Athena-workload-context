targetScope = 'resourceGroup'

metadata name = 'Athena WC-028 monitoring acquisition job'
metadata description = 'Runs one freshly reviewed identity-isolated WC-028 monitoring acquisition execution.'

@description('Azure region of the existing private Container Apps managed environment.')
param location string = resourceGroup().location

@description('Existing internal Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Existing ACR resource ID containing the digest-pinned Athena runtime image.')
param registryResourceId string

@description('Existing ACR login server.')
param registryServer string

@description('Digest-pinned WC-028 acquisition image.')
param acquisitionImage string

@description('Existing WC-024 collector user-assigned identity resource ID.')
param collectorIdentityResourceId string

@description('Existing runtime-support user-assigned identity used only for ACR pull and monitoring-intent public-key reads.')
param runtimeSupportIdentityResourceId string

@description('Athena context identity resource ID, supplied only for fail-closed separation validation.')
param athenaContextIdentityResourceId string

@description('Existing WC-024 monitoring evidence storage account resource ID.')
param monitoringEvidenceStorageAccountResourceId string

@description('Existing WC-024 monitoring evidence container resource ID.')
param monitoringEvidenceContainerResourceId string

@description('Existing exact versioned WC-024 collector signing key URI.')
param monitoringCollectorSigningKeyUriWithVersion string

@description('Exact monitoring-intent signing key resource ID whose public key may be read.')
param monitoringIntentSigningKeyResourceId string

@description('Exact versioned monitoring-intent signing key URI trusted by the reviewed runtime configuration.')
param monitoringIntentSigningKeyUriWithVersion string

@description('Existing immutable source-authority storage account resource ID. It must differ from monitoring evidence storage.')
param sourceAuthorityStorageAccountResourceId string

@description('Exact workload resource group whose Activity Log and Resource Graph change history may be read.')
param workloadResourceGroupResourceId string

@description('SHA-256 digest of the reviewed runtime configuration supplied as a secret.')
@minLength(71)
@maxLength(71)
param acquisitionRuntimeConfigurationDigest string

@description('SHA-256 digest emitted by remove-obsolete-collector-rbac.ps1 after exact legacy assignment cleanup.')
@minLength(71)
@maxLength(71)
param legacyCollectorRbacCleanupDigest string

@description('Digest of hierarchy-complete effective RBAC evidence for the dedicated runtime-support identity.')
@minLength(71)
@maxLength(71)
param runtimeSupportEffectiveRbacInventoryDigest string

@description('Digest of the immutable source manifest for the runtime-support effective RBAC inventory.')
@minLength(71)
@maxLength(71)
param runtimeSupportEffectiveRbacSourceManifestDigest string

@description('Digest of exact WC-024 Blob versioning and monitoring-evidence immutability readback.')
@minLength(71)
@maxLength(71)
param monitoringEvidenceStorageReadinessDigest string

@description('Exact reviewed WC-024 monitoring-evidence immutability policy state.')
@allowed([
  'Locked'
  'Unlocked'
])
param monitoringEvidenceImmutabilityPolicyState string

@description('Exact reviewed WC-024 monitoring-evidence immutability retention.')
@minValue(1)
param monitoringEvidenceImmutabilityRetentionDays int

@secure()
@description('Reviewed WC-028 runtime configuration. It contains no credentials and is secret-backed to avoid command-line or plain environment disclosure.')
param acquisitionRuntimeConfigurationJson string

@description('Hard deployment gate. This draft must remain false until PR #99 publishes the conditioned add-only Blob bootstrap, reviewed storage contract, signed replay binding, ancestor-complete collector RBAC evidence, and explicit successor receipt/authority schemas for mandatory wire attempts and call budgets.')
@allowed([
  false
])
param pr99RuntimeDependenciesReady bool = false

@description('Tags applied to the WC-028 job.')
param tags object = {}

var parsedRuntimeConfiguration = json(acquisitionRuntimeConfigurationJson)
var configuredStorageReadiness = parsedRuntimeConfiguration.monitoringEvidenceStorageReadiness
var validatedPr99RuntimeDependencyGate = pr99RuntimeDependenciesReady
  ? 'ready'
  : fail('WC-028 deployment remains blocked pending the complete reviewed PR #99 storage, replay, ancestor-RBAC, receipt, and authority contracts')
var registrySegments = split(registryResourceId, '/')
var registryResourceGroupName = length(registrySegments) == 9 && toLower(
  registrySegments[1]
) == 'subscriptions' && toLower(registrySegments[2]) == toLower(
  subscription().subscriptionId
) && toLower(registrySegments[3]) == 'resourcegroups' && toLower(
  registrySegments[5]
) == 'providers' && toLower(registrySegments[6]) == 'microsoft.containerregistry' && toLower(
  registrySegments[7]
) == 'registries' && !empty(registrySegments[4]) && !empty(registrySegments[8])
  ? registrySegments[4]
  : fail('registryResourceId must identify one ACR in the deployment subscription')
var validatedRegistryName = toLower(registrySegments[8])
var expectedRegistryServer = '${validatedRegistryName}.azurecr.io'
var validatedRegistryServer = registryServer == toLower(registryServer) && registryServer == expectedRegistryServer
  ? registryServer
  : fail('registryServer must exactly match registryName.azurecr.io')
var imageRepositoryPrefix = '${validatedRegistryServer}/athena/wc028-monitoring-acquisition@sha256:'
var imageDigestCandidate = replace(acquisitionImage, imageRepositoryPrefix, '')
var imageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  imageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var imageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  imageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var rejectedImageDigest = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var validatedAcquisitionImage = acquisitionImage == toLower(acquisitionImage) && startsWith(
  acquisitionImage,
  imageRepositoryPrefix
) && length(imageDigestCandidate) == 64 && empty(imageDigestInvalidCharacters) && !endsWith(
  acquisitionImage,
  rejectedImageDigest
)
  ? acquisitionImage
  : fail('acquisitionImage must use the exact registryServer/athena/wc028-monitoring-acquisition repository and a real lowercase sha256 digest')
var normalizedCollectorIdentityResourceId = toLower(collectorIdentityResourceId)
var normalizedContextIdentityResourceId = toLower(athenaContextIdentityResourceId)
var normalizedRuntimeSupportIdentityResourceId = toLower(runtimeSupportIdentityResourceId)
var collectorIdentitySegments = split(collectorIdentityResourceId, '/')
var collectorIdentityResourceGroupName = length(
  collectorIdentitySegments
) == 9 && toLower(collectorIdentitySegments[1]) == 'subscriptions' && toLower(
  collectorIdentitySegments[2]
) == toLower(subscription().subscriptionId) && toLower(
  collectorIdentitySegments[3]
) == 'resourcegroups' && toLower(collectorIdentitySegments[5]) == 'providers' && toLower(
  collectorIdentitySegments[6]
) == 'microsoft.managedidentity' && toLower(
  collectorIdentitySegments[7]
) == 'userassignedidentities' && !empty(collectorIdentitySegments[4]) && !empty(
  collectorIdentitySegments[8]
)
  ? collectorIdentitySegments[4]
  : fail('collectorIdentityResourceId must identify one user-assigned identity in the deployment subscription')
var collectorIdentityName = collectorIdentitySegments[8]
resource collectorIdentityResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: collectorIdentityResourceGroupName
  scope: subscription()
}
resource collectorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: collectorIdentityName
  scope: collectorIdentityResourceGroup
}
var runtimeSupportIdentitySegments = split(runtimeSupportIdentityResourceId, '/')
var runtimeSupportIdentityResourceGroupName = length(
  runtimeSupportIdentitySegments
) == 9 && toLower(runtimeSupportIdentitySegments[1]) == 'subscriptions' && toLower(
  runtimeSupportIdentitySegments[2]
) == toLower(subscription().subscriptionId) && toLower(
  runtimeSupportIdentitySegments[3]
) == 'resourcegroups' && toLower(runtimeSupportIdentitySegments[5]) == 'providers' && toLower(
  runtimeSupportIdentitySegments[6]
) == 'microsoft.managedidentity' && toLower(
  runtimeSupportIdentitySegments[7]
) == 'userassignedidentities' && !empty(runtimeSupportIdentitySegments[4]) && !empty(
  runtimeSupportIdentitySegments[8]
)
  ? runtimeSupportIdentitySegments[4]
  : fail('runtimeSupportIdentityResourceId must identify one user-assigned identity in the deployment subscription')
var runtimeSupportIdentityName = runtimeSupportIdentitySegments[8]
resource runtimeSupportIdentityResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: runtimeSupportIdentityResourceGroupName
  scope: subscription()
}
resource runtimeSupportIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: runtimeSupportIdentityName
  scope: runtimeSupportIdentityResourceGroup
}
var validatedCollectorIdentityResourceId = normalizedCollectorIdentityResourceId == toLower(
  collectorIdentity.id
) && normalizedCollectorIdentityResourceId != normalizedContextIdentityResourceId && normalizedCollectorIdentityResourceId != normalizedRuntimeSupportIdentityResourceId
  ? collectorIdentity.id
  : fail('WC-028 collector identity must remain separate from support and Athena context identities')
var validatedRuntimeSupportIdentityResourceId = normalizedRuntimeSupportIdentityResourceId == toLower(
  runtimeSupportIdentity.id
) && normalizedRuntimeSupportIdentityResourceId != normalizedContextIdentityResourceId && normalizedRuntimeSupportIdentityResourceId != normalizedCollectorIdentityResourceId
  ? runtimeSupportIdentity.id
  : fail('WC-028 runtime support identity must remain separate from collector and Athena context identities')
var validatedEvidenceStorageAccountResourceId = toLower(monitoringEvidenceStorageAccountResourceId) != toLower(sourceAuthorityStorageAccountResourceId)
  ? monitoringEvidenceStorageAccountResourceId
  : fail('WC-028 source authority and monitoring evidence must use separate storage accounts')
var validatedEvidenceContainerResourceId = startsWith(
  toLower(monitoringEvidenceContainerResourceId),
  '${toLower(validatedEvidenceStorageAccountResourceId)}/blobservices/default/containers/'
) && endsWith(toLower(monitoringEvidenceContainerResourceId), '/monitoring-evidence')
  ? monitoringEvidenceContainerResourceId
  : fail('WC-028 must reuse the WC-024 monitoring-evidence container')
var expectedEvidenceBlobServiceResourceId = '${validatedEvidenceStorageAccountResourceId}/blobServices/default'
var expectedEvidenceImmutabilityPolicyResourceId = '${validatedEvidenceContainerResourceId}/immutabilityPolicies/default'
var nilGuid = '00000000-0000-0000-0000-000000000000'
var validatedConfiguredStorageReadiness = parsedRuntimeConfiguration.schemaVersion == 'athena.wc028MonitoringAcquisitionJobConfiguration.v4' && configuredStorageReadiness.schemaVersion == 'athena.wc028MonitoringEvidenceStorageReadiness.v1' && toLower(
  string(configuredStorageReadiness.storageAccountResourceId)
) == toLower(validatedEvidenceStorageAccountResourceId) && toLower(
  string(configuredStorageReadiness.blobServiceResourceId)
) == toLower(expectedEvidenceBlobServiceResourceId) && toLower(
  string(configuredStorageReadiness.containerResourceId)
) == toLower(validatedEvidenceContainerResourceId) && toLower(
  string(configuredStorageReadiness.immutabilityPolicyResourceId)
) == toLower(expectedEvidenceImmutabilityPolicyResourceId) && configuredStorageReadiness.versioningEnabled == true && configuredStorageReadiness.containerPublicAccess == 'None' && configuredStorageReadiness.immutabilityPolicyState == monitoringEvidenceImmutabilityPolicyState && configuredStorageReadiness.immutabilityRetentionDays == monitoringEvidenceImmutabilityRetentionDays && configuredStorageReadiness.allowProtectedAppendWrites == false && configuredStorageReadiness.allowProtectedAppendWritesAll == false && configuredStorageReadiness.readinessDigest == monitoringEvidenceStorageReadinessDigest && length(
  string(configuredStorageReadiness.readbackBindingId)
) == 36 && toLower(string(configuredStorageReadiness.readbackBindingId)) != nilGuid
  ? configuredStorageReadiness
  : fail('runtime configuration storage readiness does not match the exact reviewed WC-024 readback inputs')
var validatedSigningKeyUri = contains(
  toLower(monitoringCollectorSigningKeyUriWithVersion),
  '/keys/monitoring-evidence-signing/'
)
  ? monitoringCollectorSigningKeyUriWithVersion
  : fail('WC-028 must reuse the exact versioned WC-024 monitoring evidence signing key')
var monitoringIntentKeyResourceSegments = split(monitoringIntentSigningKeyResourceId, '/')
var monitoringIntentKeyUriSegments = split(monitoringIntentSigningKeyUriWithVersion, '/')
var monitoringIntentVaultName = length(monitoringIntentKeyResourceSegments) == 11
  ? monitoringIntentKeyResourceSegments[8]
  : ''
var monitoringIntentKeyName = length(monitoringIntentKeyResourceSegments) == 11
  ? monitoringIntentKeyResourceSegments[10]
  : ''
var monitoringIntentKeyUriPrefix = 'https://${monitoringIntentVaultName}.${environment().suffixes.keyvaultDns}/keys/${monitoringIntentKeyName}/'
var validatedMonitoringIntentSigningKeyResourceId = length(
  monitoringIntentKeyResourceSegments
) == 11 && toLower(monitoringIntentKeyResourceSegments[1]) == 'subscriptions' && toLower(
  monitoringIntentKeyResourceSegments[3]
) == 'resourcegroups' && toLower(monitoringIntentKeyResourceSegments[5]) == 'providers' && toLower(
  monitoringIntentKeyResourceSegments[6]
) == 'microsoft.keyvault' && toLower(monitoringIntentKeyResourceSegments[7]) == 'vaults' && toLower(
  monitoringIntentKeyResourceSegments[9]
) == 'keys' && !empty(monitoringIntentVaultName) && !empty(monitoringIntentKeyName)
  ? monitoringIntentSigningKeyResourceId
  : fail('monitoringIntentSigningKeyResourceId must identify one exact Key Vault key')
var validatedMonitoringIntentSigningKeyUri = length(
  monitoringIntentKeyUriSegments
) == 6 && startsWith(
  toLower(monitoringIntentSigningKeyUriWithVersion),
  toLower(monitoringIntentKeyUriPrefix)
) && !empty(monitoringIntentKeyUriSegments[5])
  ? monitoringIntentSigningKeyUriWithVersion
  : fail('monitoringIntentSigningKeyUriWithVersion must be one exact versioned URI for monitoringIntentSigningKeyResourceId')
var configurationDigestCandidate = replace(acquisitionRuntimeConfigurationDigest, 'sha256:', '')
var configurationDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  configurationDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var configurationDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  configurationDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedConfigurationDigest = acquisitionRuntimeConfigurationDigest == toLower(
  acquisitionRuntimeConfigurationDigest
) && startsWith(acquisitionRuntimeConfigurationDigest, 'sha256:') && length(
  configurationDigestCandidate
) == 64 && empty(configurationDigestInvalidCharacters)
  ? acquisitionRuntimeConfigurationDigest
  : fail('acquisitionRuntimeConfigurationDigest must be a lowercase SHA-256 digest')
var cleanupDigestCandidate = replace(legacyCollectorRbacCleanupDigest, 'sha256:', '')
var cleanupDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  cleanupDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var cleanupDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  cleanupDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var rejectedEvidenceDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
var validatedLegacyCollectorRbacCleanupDigest = legacyCollectorRbacCleanupDigest == toLower(
  legacyCollectorRbacCleanupDigest
) && startsWith(legacyCollectorRbacCleanupDigest, 'sha256:') && length(
  cleanupDigestCandidate
) == 64 && empty(cleanupDigestInvalidCharacters) && legacyCollectorRbacCleanupDigest != rejectedEvidenceDigest
  ? legacyCollectorRbacCleanupDigest
  : fail('legacyCollectorRbacCleanupDigest must be a non-zero lowercase SHA-256 digest from the reviewed cleanup script')
var supportRbacDigestCandidate = replace(runtimeSupportEffectiveRbacInventoryDigest, 'sha256:', '')
var supportRbacDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  supportRbacDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var supportRbacDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  supportRbacDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedRuntimeSupportRbacInventoryDigest = runtimeSupportEffectiveRbacInventoryDigest == toLower(
  runtimeSupportEffectiveRbacInventoryDigest
) && startsWith(runtimeSupportEffectiveRbacInventoryDigest, 'sha256:') && length(
  supportRbacDigestCandidate
) == 64 && empty(supportRbacDigestInvalidCharacters) && runtimeSupportEffectiveRbacInventoryDigest != rejectedEvidenceDigest
  ? runtimeSupportEffectiveRbacInventoryDigest
  : fail('runtimeSupportEffectiveRbacInventoryDigest must be one non-zero lowercase SHA-256 digest')
var supportRbacSourceDigestCandidate = replace(
  runtimeSupportEffectiveRbacSourceManifestDigest,
  'sha256:',
  ''
)
var supportRbacSourceDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  supportRbacSourceDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var supportRbacSourceDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  supportRbacSourceDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedRuntimeSupportRbacSourceManifestDigest = runtimeSupportEffectiveRbacSourceManifestDigest == toLower(
  runtimeSupportEffectiveRbacSourceManifestDigest
) && startsWith(runtimeSupportEffectiveRbacSourceManifestDigest, 'sha256:') && length(
  supportRbacSourceDigestCandidate
) == 64 && empty(supportRbacSourceDigestInvalidCharacters) && runtimeSupportEffectiveRbacSourceManifestDigest != rejectedEvidenceDigest
  ? runtimeSupportEffectiveRbacSourceManifestDigest
  : fail('runtimeSupportEffectiveRbacSourceManifestDigest must be one non-zero lowercase SHA-256 digest')
var resourceTags = union(tags, {
  component: 'wc028-monitoring-acquisition'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
  runtimeConfigurationDigest: validatedConfigurationDigest
  legacyCollectorRbacCleanupDigest: validatedLegacyCollectorRbacCleanupDigest
  runtimeSupportEffectiveRbacInventoryDigest: validatedRuntimeSupportRbacInventoryDigest
  runtimeSupportEffectiveRbacSourceManifestDigest: validatedRuntimeSupportRbacSourceManifestDigest
  monitoringEvidenceStorageReadinessDigest: monitoringEvidenceStorageReadinessDigest
  evidenceStorageAccountResourceId: validatedEvidenceStorageAccountResourceId
  evidenceContainerResourceId: validatedEvidenceContainerResourceId
  signingKeyUri: validatedSigningKeyUri
  monitoringIntentSigningKeyUri: validatedMonitoringIntentSigningKeyUri
})
var acrPullRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource registryResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: registryResourceGroupName
  scope: subscription()
}

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: validatedRegistryName
  scope: registryResourceGroup
}

var validatedRegistryResourceId = toLower(registry.id) == toLower(registryResourceId)
  ? registry.id
  : fail('registryResourceId does not resolve to the reviewed ACR')

module storageReadiness 'modules/storage-readiness.bicep' = {
  name: 'wc028-monitoring-evidence-storage-readiness'
  scope: subscription()
  params: {
    storageAccountResourceId: validatedEvidenceStorageAccountResourceId
    containerResourceId: validatedEvidenceContainerResourceId
    expectedImmutabilityPolicyState: string(validatedConfiguredStorageReadiness.immutabilityPolicyState)
    expectedImmutabilityRetentionDays: int(validatedConfiguredStorageReadiness.immutabilityRetentionDays)
    storageReadinessDigest: string(validatedConfiguredStorageReadiness.readinessDigest)
    expectedReadbackBindingId: string(validatedConfiguredStorageReadiness.readbackBindingId)
  }
}

module acquisitionRbac 'modules/acquisition-rbac.bicep' = {
  name: validatedPr99RuntimeDependencyGate == 'ready'
    ? 'wc028-monitoring-acquisition-rbac'
    : 'wc028-monitoring-acquisition-rbac-blocked'
  scope: subscription()
  params: {
    collectorPrincipalId: collectorIdentity.properties.principalId
    runtimeSupportPrincipalId: runtimeSupportIdentity.properties.principalId
    monitoringEvidenceStorageAccountResourceId: validatedEvidenceStorageAccountResourceId
    monitoringEvidenceContainerResourceId: validatedEvidenceContainerResourceId
    monitoringEvidenceStorageReadinessDigest: storageReadiness.outputs.validatedStorageReadinessDigest
    monitoringIntentSigningKeyResourceId: validatedMonitoringIntentSigningKeyResourceId
  }
}

module runtimeSupportImagePull 'modules/acr-pull-assignment.bicep' = {
  name: validatedPr99RuntimeDependencyGate == 'ready'
    ? 'wc028-runtime-support-acr-pull'
    : 'wc028-runtime-support-acr-pull-blocked'
  scope: registryResourceGroup
  params: {
    registryName: validatedRegistryName
    expectedRegistryResourceId: validatedRegistryResourceId
    runtimeSupportPrincipalId: runtimeSupportIdentity.properties.principalId
    runtimeSupportIdentityResourceId: validatedRuntimeSupportIdentityResourceId
    acrPullRoleDefinitionId: acrPullRoleDefinitionId
  }
  dependsOn: [
    storageReadiness
  ]
}

resource acquisitionJob 'Microsoft.App/jobs@2025-01-01' = {
  name: validatedPr99RuntimeDependencyGate == 'ready'
    ? 'athena-wc028-monitoring-acquisition'
    : 'athena-wc028-monitoring-acquisition-blocked'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validatedCollectorIdentityResourceId}': {}
      '${validatedRuntimeSupportIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Manual'
      replicaTimeout: 600
      replicaRetryLimit: 0
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: validatedRegistryServer
          identity: validatedRuntimeSupportIdentityResourceId
        }
      ]
      secrets: [
        {
          name: 'wc028-runtime-configuration'
          value: acquisitionRuntimeConfigurationJson
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc028-monitoring-acquisition'
          image: validatedAcquisitionImage
          command: [
            'athena-context'
          ]
          args: [
            'wc028-monitoring-acquisition-job'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: collectorIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID'
              value: runtimeSupportIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_RESOURCE_ID'
              value: validatedCollectorIdentityResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID'
              value: collectorIdentity.properties.principalId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_ATHENA_CONTEXT_IDENTITY_RESOURCE_ID'
              value: athenaContextIdentityResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_RESOURCE_ID'
              value: validatedRuntimeSupportIdentityResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_CLIENT_ID'
              value: runtimeSupportIdentity.properties.clientId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_PRINCIPAL_ID'
              value: runtimeSupportIdentity.properties.principalId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_REGISTRY_RESOURCE_ID'
              value: validatedRegistryResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_ACR_PULL_ROLE_DEFINITION_ID'
              value: acrPullRoleDefinitionId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_RESOURCE_ID'
              value: validatedMonitoringIntentSigningKeyResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_INTENT_KEY_READER_ROLE_DEFINITION_ID'
              value: acquisitionRbac.outputs.runtimeSupportMonitoringIntentKeyReaderRoleDefinitionId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_INVENTORY_DIGEST'
              value: validatedRuntimeSupportRbacInventoryDigest
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_SOURCE_MANIFEST_DIGEST'
              value: validatedRuntimeSupportRbacSourceManifestDigest
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_SOURCE_STORAGE_ACCOUNT_RESOURCE_ID'
              value: sourceAuthorityStorageAccountResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID'
              value: validatedEvidenceStorageAccountResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_EVIDENCE_CONTAINER_RESOURCE_ID'
              value: validatedEvidenceContainerResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_MONITORING_EVIDENCE_STORAGE_READINESS_DIGEST'
              value: storageReadiness.outputs.validatedStorageReadinessDigest
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID'
              value: validatedSigningKeyUri
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID'
              value: validatedMonitoringIntentSigningKeyUri
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID'
              value: workloadResourceGroupResourceId
            }
            {
              name: 'ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_JSON'
              secretRef: 'wc028-runtime-configuration'
            }
            {
              name: 'ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_DIGEST'
              value: validatedConfigurationDigest
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST'
              value: validatedLegacyCollectorRbacCleanupDigest
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
    runtimeSupportImagePull
  ]
}

output acquisitionJobResourceId string = acquisitionJob.id
output acquisitionJobName string = acquisitionJob.name
output acquisitionImageDigestPinned string = validatedAcquisitionImage
