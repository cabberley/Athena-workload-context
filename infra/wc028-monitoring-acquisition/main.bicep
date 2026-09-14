targetScope = 'resourceGroup'

metadata name = 'Athena WC-028 monitoring acquisition job'
metadata description = 'Runs the identity-isolated WC-028 monitoring acquisition coordinator on a bounded schedule or by explicit manual job start.'

@description('Azure region of the existing private Container Apps managed environment.')
param location string = resourceGroup().location

@description('Existing internal Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Existing ACR name containing the digest-pinned Athena runtime image.')
param registryName string

@description('Existing ACR login server.')
param registryServer string

@description('Digest-pinned WC-028 acquisition image.')
param acquisitionImage string

@description('Existing WC-024 collector user-assigned identity resource ID.')
param collectorIdentityResourceId string

@description('Athena context identity resource ID, supplied only for fail-closed separation validation.')
param athenaContextIdentityResourceId string

@description('Existing WC-024 monitoring evidence storage account resource ID.')
param monitoringEvidenceStorageAccountResourceId string

@description('Existing WC-024 monitoring evidence container resource ID.')
param monitoringEvidenceContainerResourceId string

@description('Existing exact versioned WC-024 collector signing key URI.')
param monitoringCollectorSigningKeyUriWithVersion string

@description('Existing immutable source-authority storage account resource ID. It must differ from monitoring evidence storage.')
param sourceAuthorityStorageAccountResourceId string

@description('Exact workload resource group whose Activity Log and Resource Graph change history may be read.')
param workloadResourceGroupResourceId string

@description('Exact existing Network Watcher resource used only for IP Flow Verify.')
param networkWatcherResourceId string

@description('Existing WC-025 change-evidence storage account resource ID.')
param changeEvidenceStorageAccountResourceId string

@description('Existing WC-025 change-evidence container resource ID.')
param changeEvidenceContainerResourceId string

@description('SHA-256 digest of the reviewed runtime configuration supplied as a secret.')
@minLength(71)
@maxLength(71)
param acquisitionRuntimeConfigurationDigest string

@secure()
@description('Reviewed WC-028 runtime configuration. It contains no credentials and is secret-backed to avoid command-line or plain environment disclosure.')
param acquisitionRuntimeConfigurationJson string

@description('Bounded five-minute default schedule. The same job may also be started manually.')
param scheduleCronExpression string = '*/5 * * * *'

@description('Tags applied to the WC-028 job.')
param tags object = {}

var validatedRegistryName = registryName == toLower(registryName)
  ? registryName
  : fail('registryName must be lowercase')
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
var collectorIdentityName = last(split(collectorIdentityResourceId, '/'))
resource collectorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: collectorIdentityName
}
var validatedCollectorIdentityResourceId = normalizedCollectorIdentityResourceId == toLower(collectorIdentity.id) && normalizedCollectorIdentityResourceId != normalizedContextIdentityResourceId
  ? collectorIdentity.id
  : fail('WC-028 monitoring acquisition must not attach the Athena context identity')
var validatedEvidenceStorageAccountResourceId = toLower(monitoringEvidenceStorageAccountResourceId) != toLower(sourceAuthorityStorageAccountResourceId)
  ? monitoringEvidenceStorageAccountResourceId
  : fail('WC-028 source authority and monitoring evidence must use separate storage accounts')
var validatedEvidenceContainerResourceId = startsWith(
  toLower(monitoringEvidenceContainerResourceId),
  '${toLower(validatedEvidenceStorageAccountResourceId)}/blobservices/default/containers/'
) && endsWith(toLower(monitoringEvidenceContainerResourceId), '/monitoring-evidence')
  ? monitoringEvidenceContainerResourceId
  : fail('WC-028 must reuse the WC-024 monitoring-evidence container')
var validatedChangeEvidenceContainerResourceId = startsWith(
  toLower(changeEvidenceContainerResourceId),
  '${toLower(changeEvidenceStorageAccountResourceId)}/blobservices/default/containers/'
) && endsWith(toLower(changeEvidenceContainerResourceId), '/change-evidence')
  ? changeEvidenceContainerResourceId
  : fail('WC-028 change artifacts must use the WC-025 change-evidence container')
var validatedSigningKeyUri = contains(
  toLower(monitoringCollectorSigningKeyUriWithVersion),
  '/keys/monitoring-evidence-signing/'
)
  ? monitoringCollectorSigningKeyUriWithVersion
  : fail('WC-028 must reuse the exact versioned WC-024 monitoring evidence signing key')
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
var validatedSchedule = scheduleCronExpression == '*/5 * * * *'
  ? scheduleCronExpression
  : fail('WC-028 production acquisition uses the reviewed bounded five-minute schedule')
var resourceTags = union(tags, {
  component: 'wc028-monitoring-acquisition'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
  runtimeConfigurationDigest: validatedConfigurationDigest
  evidenceStorageAccountResourceId: validatedEvidenceStorageAccountResourceId
  evidenceContainerResourceId: validatedEvidenceContainerResourceId
  changeEvidenceStorageAccountResourceId: changeEvidenceStorageAccountResourceId
  changeEvidenceContainerResourceId: validatedChangeEvidenceContainerResourceId
  signingKeyUri: validatedSigningKeyUri
})
var acrPullRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {
  name: validatedRegistryName
}

module acquisitionRbac 'modules/acquisition-rbac.bicep' = {
  name: 'wc028-monitoring-acquisition-rbac'
  scope: subscription()
  params: {
    collectorPrincipalId: collectorIdentity.properties.principalId
    workloadResourceGroupResourceId: workloadResourceGroupResourceId
    changeEvidenceStorageAccountResourceId: changeEvidenceStorageAccountResourceId
    changeEvidenceContainerResourceId: validatedChangeEvidenceContainerResourceId
  }
}

resource collectorImagePull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, collectorIdentity.id, acrPullRoleDefinitionId)
  scope: registry
  properties: {
    principalId: collectorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleDefinitionId
  }
}

resource acquisitionJob 'Microsoft.App/jobs@2025-01-01' = {
  name: 'athena-wc028-monitoring-acquisition'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validatedCollectorIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 600
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: validatedSchedule
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: validatedRegistryServer
          identity: validatedCollectorIdentityResourceId
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
              name: 'ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID'
              value: validatedSigningKeyUri
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID'
              value: workloadResourceGroupResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_NETWORK_WATCHER_RESOURCE_ID'
              value: networkWatcherResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID'
              value: changeEvidenceStorageAccountResourceId
            }
            {
              name: 'ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_CONTAINER_RESOURCE_ID'
              value: validatedChangeEvidenceContainerResourceId
            }
            {
              name: 'ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_JSON'
              secretRef: 'wc028-runtime-configuration'
            }
            {
              name: 'ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_DIGEST'
              value: validatedConfigurationDigest
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
    acquisitionRbac
    collectorImagePull
  ]
}

output acquisitionJobResourceId string = acquisitionJob.id
output acquisitionJobName string = acquisitionJob.name
output acquisitionImageDigestPinned string = validatedAcquisitionImage
