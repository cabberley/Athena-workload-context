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

var lifecycleRuleNames = map(lifecyclePolicy.properties.policy.rules, rule => rule.name)
var privateEndpointTargetIds = map(storagePrivateEndpoint.properties.privateLinkServiceConnections, connection => toLower(connection.properties.privateLinkServiceId))
var privateEndpointGroupIds = flatten(map(storagePrivateEndpoint.properties.privateLinkServiceConnections, connection => connection.properties.groupIds))
var coverageIsValid = toLower(storageAccount.location) == location && storageAccount.properties.allowBlobPublicAccess == false && storageAccount.properties.allowSharedKeyAccess == false && storageAccount.properties.defaultToOAuthAuthentication == true && storageAccount.properties.minimumTlsVersion == 'TLS1_2' && storageAccount.properties.supportsHttpsTrafficOnly == true && storageAccount.properties.publicNetworkAccess == 'Enabled' && storageAccount.properties.networkAcls.defaultAction == 'Deny' && storageAccount.properties.networkAcls.bypass == 'AzureServices' && empty(storageAccount.properties.networkAcls.ipRules) && empty(storageAccount.properties.networkAcls.virtualNetworkRules) && blobService.properties.isVersioningEnabled == true && blobService.properties.deleteRetentionPolicy.enabled == true && blobService.properties.containerDeleteRetentionPolicy.enabled == true && contains(lifecycleRuleNames, 'flow-log-evidence-retention') && contains(privateEndpointTargetIds, toLower(storageAccount.id)) && contains(privateEndpointGroupIds, 'blob')
var validatedStorageAccountResourceId = coverageIsValid ? storageAccount.id : fail('Replacement monitoring storage must retain private Blob access, default-deny trusted-service flow-log ingress, lifecycle controls, versioning, HTTPS, Entra authorization, and disabled shared keys/public blobs.')

output coverage object = {
  storageAccountResourceId: validatedStorageAccountResourceId
  privateEndpointResourceId: storagePrivateEndpoint.id
  lifecyclePolicyResourceId: lifecyclePolicy.id
  sharedKeyAccessEnabled: false
  blobPublicAccessEnabled: false
  firewallDefaultAction: 'Deny'
  trustedServiceBypass: 'AzureServices'
}
