targetScope = 'resourceGroup'

@description('Existing Key Vault name.')
param keyVaultName string

@description('Existing Key Vault key name.')
param keyName string

@description('Exact user-assigned identity resource ID receiving verification-only access.')
param identityResourceId string

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource key 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: keyVault
  name: keyName
}

resource verifierRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(key.id, 'athena-wc027-key-verifier')
  properties: {
    roleName: 'Athena WC027 Exact Key Verifier (${keyVaultName}/${keyName})'
    description: 'Read public key material and verify signatures with this exact WC-027 key. No signing, wrapping, unwrapping, decrypting, release, backup, restore, or deletion.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
          'Microsoft.KeyVault/vaults/keys/verify/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource verifier 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(key.id, identityResourceId, verifierRole.id)
  scope: key
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: verifierRole.id
  }
}

output roleDefinitionResourceId string = verifierRole.id
output roleAssignmentResourceId string = verifier.id
output keyResourceId string = key.id
