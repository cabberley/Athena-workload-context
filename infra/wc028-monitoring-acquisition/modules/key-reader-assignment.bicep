targetScope = 'resourceGroup'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param principalId string

@description('Subscription-level custom role permitting only exact Key Vault key reads.')
param roleDefinitionId string

@description('Existing Key Vault containing the monitoring-intent signing key.')
param vaultName string

@description('Exact monitoring-intent signing key name.')
param keyName string

@description('Exact monitoring-intent signing key resource ID.')
param expectedKeyResourceId string

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: vaultName
}

resource key 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: vault
  name: keyName
}

var validatedKeyResourceId = toLower(key.id) == toLower(expectedKeyResourceId)
  ? key.id
  : fail('monitoring intent key reader assignment escaped the reviewed key')

resource collectorMonitoringIntentKeyReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(validatedKeyResourceId, principalId, roleDefinitionId)
  scope: key
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output roleAssignmentResourceId string = collectorMonitoringIntentKeyReader.id
