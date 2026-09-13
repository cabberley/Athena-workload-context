targetScope = 'resourceGroup'

@description('Expected storage and private-endpoint region.')
@allowed([
  'australiaeast'
])
param location string

@description('Existing monitoring-owned replacement storage account name.')
param storageAccountName string

@description('Existing collector-local Blob private endpoint name.')
param storagePrivateEndpointName string

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2025-06-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' existing = {
  name: storagePrivateEndpointName
}

resource storagePrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' existing = {
  parent: storagePrivateEndpoint
  name: 'default'
}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  #disable-next-line no-hardcoded-env-urls // Azure Blob Private Link requires this service DNS zone.
  name: 'privatelink.blob.core.windows.net'
}

resource collectorBlobPrivateDnsVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' existing = {
  parent: blobPrivateDnsZone
  name: 'athena-demo-monitoring-collector-blob-vnet'
}

var requiredRetentionDays = 30
var collectorVirtualNetworkResourceId = '${resourceGroup().id}/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet'
var collectorPrivateEndpointSubnetResourceId = '${collectorVirtualNetworkResourceId}/subnets/private-endpoints'
var requiredLifecyclePrefixes = [
  'insights-logs-flowlogflowevent/'
  'monitoring-evidence/'
]
var lifecycleRules = lifecyclePolicy.properties.policy.?rules ?? []
var reviewedLifecycleRules = filter(lifecycleRules, rule => rule.name == 'flow-log-evidence-retention' && rule.enabled == true && rule.type == 'Lifecycle' && int(rule.definition.?actions.?baseBlob.?tierToCool.?daysAfterModificationGreaterThan ?? 0) == requiredRetentionDays && int(rule.definition.?actions.?baseBlob.?delete.?daysAfterModificationGreaterThan ?? 0) >= requiredRetentionDays && int(rule.definition.?actions.?version.?delete.?daysAfterCreationGreaterThan ?? 0) >= requiredRetentionDays && length(rule.definition.?filters.?blobTypes ?? []) == 1 && contains(rule.definition.?filters.?blobTypes ?? [], 'blockBlob') && length(rule.definition.?filters.?prefixMatch ?? []) == length(requiredLifecyclePrefixes) && empty(filter(requiredLifecyclePrefixes, prefix => !contains(rule.definition.?filters.?prefixMatch ?? [], prefix))))
var lifecycleRulesApplicableToRequiredPrefixes = filter(lifecycleRules, rule => rule.enabled == true && contains(rule.definition.?filters.?blobTypes ?? [], 'blockBlob') && (empty(rule.definition.?filters.?prefixMatch ?? []) || !empty(filter(requiredLifecyclePrefixes, requiredPrefix => !empty(filter(rule.definition.?filters.?prefixMatch ?? [], rulePrefix => startsWith(requiredPrefix, rulePrefix) || startsWith(rulePrefix, requiredPrefix)))))))
var unsafeRetentionRules = filter(lifecycleRulesApplicableToRequiredPrefixes, rule => int(rule.definition.?actions.?baseBlob.?delete.?daysAfterModificationGreaterThan ?? requiredRetentionDays) < requiredRetentionDays || int(rule.definition.?actions.?baseBlob.?delete.?daysAfterCreationGreaterThan ?? requiredRetentionDays) < requiredRetentionDays || int(rule.definition.?actions.?baseBlob.?delete.?daysAfterLastAccessTimeGreaterThan ?? requiredRetentionDays) < requiredRetentionDays || int(rule.definition.?actions.?baseBlob.?delete.?daysAfterLastTierChangeGreaterThan ?? requiredRetentionDays) < requiredRetentionDays || int(rule.definition.?actions.?version.?delete.?daysAfterCreationGreaterThan ?? requiredRetentionDays) < requiredRetentionDays || int(rule.definition.?actions.?version.?delete.?daysAfterLastTierChangeGreaterThan ?? requiredRetentionDays) < requiredRetentionDays)
var privateLinkServiceConnections = storagePrivateEndpoint.properties.?privateLinkServiceConnections ?? []
var approvedBlobConnections = filter(privateLinkServiceConnections, connection => toLower(connection.properties.privateLinkServiceId) == toLower(storageAccount.id) && length(connection.properties.groupIds) == 1 && contains(connection.properties.groupIds, 'blob') && connection.properties.privateLinkServiceConnectionState.status == 'Approved' && connection.properties.provisioningState == 'Succeeded')
var privateDnsZoneConfigs = storagePrivateDnsZoneGroup.properties.?privateDnsZoneConfigs ?? []
var approvedBlobPrivateDnsZoneConfigs = filter(privateDnsZoneConfigs, config => toLower(config.properties.privateDnsZoneId) == toLower(blobPrivateDnsZone.id))
var storagePostureIsValid = toLower(storageAccount.location) == location && storageAccount.properties.allowBlobPublicAccess == false && storageAccount.properties.allowSharedKeyAccess == false && storageAccount.properties.defaultToOAuthAuthentication == true && storageAccount.properties.minimumTlsVersion == 'TLS1_2' && storageAccount.properties.supportsHttpsTrafficOnly == true && storageAccount.properties.publicNetworkAccess == 'Enabled' && storageAccount.properties.networkAcls.defaultAction == 'Deny' && storageAccount.properties.networkAcls.bypass == 'AzureServices' && empty(storageAccount.properties.networkAcls.ipRules) && empty(storageAccount.properties.networkAcls.virtualNetworkRules)
var retentionPostureIsValid = blobService.properties.isVersioningEnabled == true && blobService.properties.deleteRetentionPolicy.enabled == true && blobService.properties.deleteRetentionPolicy.allowPermanentDelete == false && blobService.properties.deleteRetentionPolicy.days >= requiredRetentionDays && blobService.properties.containerDeleteRetentionPolicy.enabled == true && blobService.properties.containerDeleteRetentionPolicy.days >= requiredRetentionDays && length(reviewedLifecycleRules) == 1 && empty(unsafeRetentionRules)
var privateAccessPostureIsValid = toLower(storagePrivateEndpoint.location) == location && storagePrivateEndpoint.properties.provisioningState == 'Succeeded' && toLower(storagePrivateEndpoint.properties.subnet.id) == toLower(collectorPrivateEndpointSubnetResourceId) && length(privateLinkServiceConnections) == 1 && empty(storagePrivateEndpoint.properties.?manualPrivateLinkServiceConnections ?? []) && length(approvedBlobConnections) == 1 && storagePrivateDnsZoneGroup.properties.provisioningState == 'Succeeded' && length(privateDnsZoneConfigs) == 1 && length(approvedBlobPrivateDnsZoneConfigs) == 1 && collectorBlobPrivateDnsVnetLink.properties.provisioningState == 'Succeeded' && collectorBlobPrivateDnsVnetLink.properties.virtualNetworkLinkState == 'Completed' && collectorBlobPrivateDnsVnetLink.properties.registrationEnabled == false && toLower(collectorBlobPrivateDnsVnetLink.properties.virtualNetwork.id) == toLower(collectorVirtualNetworkResourceId)
var coverageIsValid = storagePostureIsValid && retentionPostureIsValid && privateAccessPostureIsValid
var validatedStorageAccountResourceId = coverageIsValid ? storageAccount.id : fail('Replacement monitoring storage must retain the complete reviewed 30-day lifecycle and soft-delete posture, versioning, an approved Blob private-link connection in the collector subnet with the exact Blob DNS zone and collector-VNet link, default-deny trusted-service ingress, HTTPS, Entra authorization, and disabled shared keys/public blobs.')

output coverage object = {
  storageAccountResourceId: validatedStorageAccountResourceId
  privateEndpointResourceId: storagePrivateEndpoint.id
  lifecyclePolicyResourceId: lifecyclePolicy.id
  retentionDaysMinimum: requiredRetentionDays
  sharedKeyAccessEnabled: false
  blobPublicAccessEnabled: false
  firewallDefaultAction: 'Deny'
  trustedServiceBypass: 'AzureServices'
  privateLinkConnectionStatus: 'Approved'
  privateEndpointSubnetResourceId: collectorPrivateEndpointSubnetResourceId
  blobPrivateDnsZoneResourceId: blobPrivateDnsZone.id
  collectorBlobPrivateDnsVnetLinkResourceId: collectorBlobPrivateDnsVnetLink.id
}
