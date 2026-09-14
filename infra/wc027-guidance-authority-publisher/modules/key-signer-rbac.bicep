targetScope = 'resourceGroup'

param keyVaultName string
param keyName string
param identityResourceId string

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

resource signerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(key.id, 'athena-wc027-key-signer')
  properties: {
    roleName: 'Athena WC027 Exact Key Signer (${keyVaultName}/${keyName})'
    description: 'Sign digests with this exact WC-027 key. No read, verify, encrypt, decrypt, wrap, unwrap, update, backup, restore, release, rotate, or delete.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/sign/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource signer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(key.id, identity.id, signerRole.id)
  scope: key
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: signerRole.id
  }
}

output roleDefinitionResourceId string = signerRole.id
output roleAssignmentResourceId string = signer.id
