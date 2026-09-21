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

resource publicKeyReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(key.id, 'athena-wc027-exact-public-key-reader')
  properties: {
    roleName: 'Athena WC027 Exact Public Key Reader (${keyVaultName}/${keyName})'
    description: 'Read public material for this exact key only. No sign, verify service call, encrypt, decrypt, wrap, unwrap, update, rotate, backup, restore, release, or delete.'
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
        ]
        notDataActions: []
      }
    ]
  }
}

resource publicKeyReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(key.id, identity.id, publicKeyReaderRole.id)
  scope: key
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: publicKeyReaderRole.id
  }
}

output roleDefinitionResourceId string = publicKeyReaderRole.id
output roleAssignmentResourceId string = publicKeyReader.id
