targetScope = 'subscription'

metadata name = 'Athena WC-025 bounded Azure change ingestion'
metadata description = 'Composes resource-group-bounded Event Grid routing with private transport and identity-isolated change evidence workers.'

@description('Azure region for private WC-025 transport and jobs.')
param location string

@description('Existing resource group containing the private Container Apps environment, ACR, evidence Storage account, and Key Vault.')
@minLength(1)
@maxLength(90)
param hostingResourceGroupName string

@description('The sole resource group from which resource-management events may be accepted.')
@allowed([
  'rg-athena-demo-workload'
])
param workloadResourceGroupName string = 'rg-athena-demo-workload'

@description('Existing internal Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Existing VNet resource ID for the private Service Bus DNS link.')
param virtualNetworkResourceId string

@description('Existing subnet resource ID for the private Service Bus endpoint.')
param privateEndpointSubnetResourceId string

@description('Existing ACR name containing the digest-pinned WC-025 worker image.')
@minLength(5)
@maxLength(50)
param registryName string

@description('Existing ACR login server.')
param registryServer string

@description('Digest-pinned WC-025 change-ingester image.')
param changeIngesterImage string

@description('Dedicated Event Grid delivery identity resource ID.')
param eventGridDeliveryIdentityResourceId string

@description('Dedicated Event Grid delivery identity principal ID.')
param eventGridDeliveryIdentityPrincipalId string

@description('Dedicated Event Grid queue-ingester identity resource ID.')
param eventIngesterIdentityResourceId string

@description('Dedicated Event Grid queue-ingester identity client ID.')
param eventIngesterIdentityClientId string

@description('Dedicated Event Grid queue-ingester identity principal ID.')
param eventIngesterIdentityPrincipalId string

@description('Dedicated Azure Resource Graph change-history identity resource ID.')
param queryIdentityResourceId string

@description('Dedicated Azure Resource Graph change-history identity client ID.')
param queryIdentityClientId string

@description('Dedicated Azure Resource Graph change-history identity principal ID.')
param queryIdentityPrincipalId string

@description('Exact approved resource IDs in rg-athena-demo-workload. No selector is supported.')
@minLength(1)
@maxLength(25)
param approvedResourceIds array

@description('Existing private evidence Storage account name in hostingResourceGroupName.')
@minLength(3)
@maxLength(24)
param evidenceStorageAccountName string

@description('Private container receiving create-only signed change-evidence artifacts.')
@allowed([
  'change-evidence'
])
param evidenceContainerName string = 'change-evidence'

@description('Existing Key Vault name in hostingResourceGroupName containing the dedicated WC-025 key.')
@minLength(3)
@maxLength(24)
param keyVaultName string

@description('Existing versioned signing key name.')
@minLength(1)
@maxLength(127)
param changeSigningKeyName string

@description('Exact versioned Key Vault key URI used by both workers.')
@minLength(1)
@maxLength(512)
param changeSigningKeyUriWithVersion string

@description('Optional resource tags.')
param tags object = {}

var workloadScopePrefix = toLower('/subscriptions/${subscription().subscriptionId}/resourceGroups/${workloadResourceGroupName}/')
var validatedApprovedResourceIds = map(approvedResourceIds, resourceId => length(string(resourceId)) <= 512 && startsWith(toLower(string(resourceId)), workloadScopePrefix) && !endsWith(string(resourceId), '/') && !contains(string(resourceId), '//') && length(split(toLower(string(resourceId)), '/')) >= 9 && (length(split(toLower(string(resourceId)), '/')) - 7) % 2 == 0 && split(toLower(string(resourceId)), '/')[5] == 'providers' && !empty(split(toLower(string(resourceId)), '/')[6]) && !empty(split(toLower(string(resourceId)), '/')[7]) && !empty(split(toLower(string(resourceId)), '/')[8])
  ? toLower(string(resourceId))
  : fail('every approvedResourceIds entry must be one exact resource in rg-athena-demo-workload'))
var uniqueApprovedResourceIds = length(union(validatedApprovedResourceIds, [])) == length(validatedApprovedResourceIds)
  ? validatedApprovedResourceIds
  : fail('approvedResourceIds must be unique after canonicalization')
var distinctWorkerIdentities = eventGridDeliveryIdentityResourceId != eventIngesterIdentityResourceId && eventGridDeliveryIdentityResourceId != queryIdentityResourceId && eventIngesterIdentityResourceId != queryIdentityResourceId && eventGridDeliveryIdentityPrincipalId != eventIngesterIdentityPrincipalId && eventGridDeliveryIdentityPrincipalId != queryIdentityPrincipalId && eventIngesterIdentityPrincipalId != queryIdentityPrincipalId
var validatedEventGridDeliveryIdentityResourceId = distinctWorkerIdentities
  ? eventGridDeliveryIdentityResourceId
  : fail('WC-025 Event Grid delivery, event ingestion, and query workers require separate managed identities')
var validatedEventIngesterIdentityResourceId = distinctWorkerIdentities
  ? eventIngesterIdentityResourceId
  : fail('WC-025 Event Grid delivery, event ingestion, and query workers require separate managed identities')
var validatedQueryIdentityResourceId = distinctWorkerIdentities
  ? queryIdentityResourceId
  : fail('WC-025 Event Grid delivery, event ingestion, and query workers require separate managed identities')
var validatedRegistryName = registryName == toLower(registryName)
  ? registryName
  : fail('registryName must be lowercase')
var expectedRegistryServer = '${validatedRegistryName}.azurecr.io'
var validatedRegistryServer = registryServer == toLower(registryServer) && registryServer == expectedRegistryServer
  ? registryServer
  : fail('registryServer must exactly match registryName.azurecr.io')
var rejectedChangeIngesterImageDigestSuffix = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var changeIngesterImageRepositoryPrefix = '${validatedRegistryServer}/athena/wc025-change-ingester@sha256:'
var changeIngesterImageDigestCandidate = replace(changeIngesterImage, changeIngesterImageRepositoryPrefix, '')
var changeIngesterImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  changeIngesterImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var changeIngesterImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  changeIngesterImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedChangeIngesterImage = changeIngesterImage == toLower(changeIngesterImage) && startsWith(
  changeIngesterImage,
  changeIngesterImageRepositoryPrefix
) && length(changeIngesterImage) == length(changeIngesterImageRepositoryPrefix) + 64 && length(
  changeIngesterImageDigestCandidate
) == 64 && empty(
  changeIngesterImageDigestInvalidCharacters
) && !endsWith(changeIngesterImage, rejectedChangeIngesterImageDigestSuffix)
  ? changeIngesterImage
  : fail('changeIngesterImage must use the exact registryServer/athena/wc025-change-ingester repository and a real 64-character lowercase sha256 digest')
var changeSigningKeyUriSegments = split(changeSigningKeyUriWithVersion, '/')
var expectedChangeSigningKeyUriPrefix = 'https://${keyVaultName}.${environment().suffixes.keyvaultDns}/keys/${changeSigningKeyName}/'
var validatedChangeSigningKeyUriWithVersion = startsWith(
  toLower(changeSigningKeyUriWithVersion),
  toLower(expectedChangeSigningKeyUriPrefix)
) && length(changeSigningKeyUriSegments) == 6 && !empty(changeSigningKeyUriSegments[5])
  ? changeSigningKeyUriWithVersion
  : fail('changeSigningKeyUriWithVersion must be one exact versioned key in keyVaultName')
var approvedChangeScopeJson = string({
  schemaVersion: 'athena.approvedChangeScope.v1'
  subscriptionId: subscription().subscriptionId
  resourceGroupName: workloadResourceGroupName
  approvedResourceIds: uniqueApprovedResourceIds
})
var resourceTags = union(tags, {
  component: 'wc025-change-ingestion'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})

resource hostingResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: hostingResourceGroupName
}

resource workloadResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: workloadResourceGroupName
}

resource evidenceStorageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: evidenceStorageAccountName
  scope: hostingResourceGroup
}

resource evidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: evidenceStorageAccount
  name: 'default'
}

module evidenceBlobVersioningGate 'modules/evidence-blob-versioning-gate.bicep' = {
  name: 'wc025-evidence-blob-versioning-gate'
  scope: hostingResourceGroup
  params: {
    isVersioningEnabled: evidenceBlobService.properties.isVersioningEnabled == true
      ? true
      : fail('WC-025 requires blobServices/default.properties.isVersioningEnabled to be true for version-pinned replay receipts')
  }
}

resource changeHistoryReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'athena-wc025-resource-change-history-reader')
  properties: {
    roleName: 'Athena WC025 Bounded Resource Change History Reader'
    description: 'Read only Microsoft.Resources/changes and Resource Graph results for the one approved Athena demo workload resource group.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.Resources/changes/read'
          'Microsoft.ResourceGraph/resources/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      workloadResourceGroup.id
    ]
  }
}

module privateTransport 'modules/private-transport.bicep' = {
  name: 'wc025-private-transport'
  scope: hostingResourceGroup
  params: {
    location: location
    resourceTags: resourceTags
    virtualNetworkResourceId: virtualNetworkResourceId
    privateEndpointSubnetResourceId: privateEndpointSubnetResourceId
  }
}

module eventGridDeliveryRbac 'modules/event-grid-delivery-rbac.bicep' = {
  name: 'wc025-event-grid-delivery-rbac'
  scope: hostingResourceGroup
  params: {
    namespaceName: privateTransport.outputs.namespaceName
    changeEventsQueueName: privateTransport.outputs.changeEventsQueueName
    eventGridDeliveryPrincipalId: eventGridDeliveryIdentityPrincipalId
  }
}

module resourceGroupRouting 'modules/resource-group-routing.bicep' = {
  name: 'wc025-resource-group-routing'
  scope: workloadResourceGroup
  params: {
    resourceTags: resourceTags
    changeEventsQueueResourceId: privateTransport.outputs.changeEventsQueueResourceId
    eventGridDeliveryIdentityResourceId: validatedEventGridDeliveryIdentityResourceId
    approvedResourceIds: uniqueApprovedResourceIds
  }
  dependsOn: [
    eventGridDeliveryRbac
  ]
}

module queryReaderRbac 'modules/query-reader-rbac.bicep' = {
  name: 'wc025-query-reader-rbac'
  scope: workloadResourceGroup
  params: {
    queryIdentityPrincipalId: queryIdentityPrincipalId
    changeHistoryReaderRoleDefinitionId: changeHistoryReaderRole.id
  }
}

module workers 'modules/workers.bicep' = {
  name: 'wc025-change-evidence-workers'
  scope: hostingResourceGroup
  params: {
    location: location
    resourceTags: resourceTags
    managedEnvironmentResourceId: managedEnvironmentResourceId
    registryName: validatedRegistryName
    registryServer: validatedRegistryServer
    changeIngesterImage: validatedChangeIngesterImage
    namespaceName: privateTransport.outputs.namespaceName
    changeEventsQueueName: privateTransport.outputs.changeEventsQueueName
    eventIngesterIdentityResourceId: validatedEventIngesterIdentityResourceId
    eventIngesterIdentityClientId: eventIngesterIdentityClientId
    eventIngesterIdentityPrincipalId: eventIngesterIdentityPrincipalId
    queryIdentityResourceId: validatedQueryIdentityResourceId
    queryIdentityClientId: queryIdentityClientId
    queryIdentityPrincipalId: queryIdentityPrincipalId
    evidenceStorageAccountName: evidenceStorageAccountName
    evidenceContainerName: evidenceContainerName
    keyVaultName: keyVaultName
    changeSigningKeyName: changeSigningKeyName
    changeSigningKeyUriWithVersion: validatedChangeSigningKeyUriWithVersion
    approvedChangeScopeJson: approvedChangeScopeJson
  }
  dependsOn: [
    evidenceBlobVersioningGate
    eventGridDeliveryRbac
    queryReaderRbac
  ]
}

@description('Private Service Bus namespace for one bounded Event Grid delivery route.')
output namespaceResourceId string = privateTransport.outputs.namespaceResourceId

@description('Private change-event queue name.')
output changeEventsQueueName string = privateTransport.outputs.changeEventsQueueName

@description('Exact deployment-owned approved scope JSON consumed by both workers.')
output approvedChangeScopeJson string = approvedChangeScopeJson

@description('Resource-group-bounded Event Grid system topic ID.')
output resourceChangeSystemTopicId string = resourceGroupRouting.outputs.resourceChangeSystemTopicId

@description('Event Grid queue-ingester Job resource ID.')
output eventIngesterJobResourceId string = workers.outputs.eventIngesterJobResourceId

@description('Identity-isolated Resource Graph change-history Job resource ID.')
output queryWorkerJobResourceId string = workers.outputs.queryWorkerJobResourceId
