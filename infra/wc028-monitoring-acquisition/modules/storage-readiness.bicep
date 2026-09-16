targetScope = 'subscription'

@description('Existing WC-024 monitoring evidence storage account resource ID.')
param storageAccountResourceId string

@description('Existing WC-024 monitoring-evidence container resource ID.')
param containerResourceId string

@description('Exact reviewed immutability policy state read back from WC-024 storage.')
param expectedImmutabilityPolicyState string

@description('Exact reviewed WC-024 monitoring-evidence immutability retention.')
@minValue(1)
param expectedImmutabilityRetentionDays int

@description('Non-zero digest of the reviewed storage-readiness artifact embedded in runtime configuration.')
@minLength(71)
@maxLength(71)
param storageReadinessDigest string

@description('ARM guid() binding computed from the exact runtime storage-readiness preimage.')
param expectedReadbackBindingId string

var normalizedStorageAccountResourceId = toLower(storageAccountResourceId)
var normalizedContainerResourceId = toLower(containerResourceId)
var subscriptionPrefix = toLower('/subscriptions/${subscription().subscriptionId}/')
var storageSegments = split(normalizedStorageAccountResourceId, '/')
var storageResourceGroupName = length(storageSegments) == 9 && startsWith(
  normalizedStorageAccountResourceId,
  '${subscriptionPrefix}resourcegroups/'
) && storageSegments[5] == 'providers' && storageSegments[6] == 'microsoft.storage' && storageSegments[7] == 'storageaccounts' && !empty(storageSegments[8])
  ? storageSegments[4]
  : fail('storageAccountResourceId must identify one WC-024 storage account in the deployment subscription')
var storageAccountName = storageSegments[8]

resource storageResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: storageResourceGroupName
  scope: subscription()
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
  scope: storageResourceGroup
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource monitoringEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: blobService
  name: 'monitoring-evidence'
}

resource monitoringEvidenceImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2025-06-01' existing = {
  parent: monitoringEvidenceContainer
  name: 'default'
}

var expectedContainerResourceId = '${storageAccount.id}/blobServices/default/containers/monitoring-evidence'
var digestCandidate = replace(storageReadinessDigest, 'sha256:', '')
var digestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  digestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var digestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  digestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var rejectedDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
var validatedDigest = storageReadinessDigest == toLower(storageReadinessDigest) && startsWith(
  storageReadinessDigest,
  'sha256:'
) && length(digestCandidate) == 64 && empty(digestInvalidCharacters) && storageReadinessDigest != rejectedDigest
  ? storageReadinessDigest
  : fail('storageReadinessDigest must be one non-zero lowercase SHA-256 digest')
var readinessPreimage = 'athena.wc028MonitoringEvidenceStorageReadiness.v1|${toLower(storageAccount.id)}|${toLower(blobService.id)}|${toLower(monitoringEvidenceContainer.id)}|${toLower(monitoringEvidenceImmutability.id)}|true|${monitoringEvidenceContainer.properties.publicAccess}|${monitoringEvidenceImmutability.properties.state}|${monitoringEvidenceImmutability.properties.immutabilityPeriodSinceCreationInDays}|false|false'
var computedReadbackBindingId = guid(readinessPreimage)
var validatedStorageReadinessDigest = toLower(storageAccount.id) == normalizedStorageAccountResourceId && toLower(
  monitoringEvidenceContainer.id
) == normalizedContainerResourceId && toLower(
  expectedContainerResourceId
) == normalizedContainerResourceId && blobService.properties.isVersioningEnabled == true && monitoringEvidenceContainer.properties.publicAccess == 'None' && monitoringEvidenceImmutability.properties.state == expectedImmutabilityPolicyState && monitoringEvidenceImmutability.properties.immutabilityPeriodSinceCreationInDays == expectedImmutabilityRetentionDays && monitoringEvidenceImmutability.properties.allowProtectedAppendWrites == false && monitoringEvidenceImmutability.properties.allowProtectedAppendWritesAll == false && expectedReadbackBindingId == computedReadbackBindingId
  ? validatedDigest
  : fail('WC-024 monitoring evidence storage is not versioned or does not match the reviewed immutability policy and retention')

output validatedStorageReadinessDigest string = validatedStorageReadinessDigest
output immutabilityPolicyResourceId string = monitoringEvidenceImmutability.id
output readbackBindingId string = computedReadbackBindingId
