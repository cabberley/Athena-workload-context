targetScope = 'resourceGroup'

param keyVaultName string
param keyName string
param identityResourceId string

var keyVaultCryptoUserRoleDefinitionId = '12338af0-0e69-4776-bea7-57ae8d297424'

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource key 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: keyName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource signer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(key.id, identity.id, keyVaultCryptoUserRoleDefinitionId)
  scope: key
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultCryptoUserRoleDefinitionId
    )
  }
}

output roleAssignmentResourceId string = signer.id
