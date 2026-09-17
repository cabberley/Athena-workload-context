targetScope = 'subscription'

@description('Exact reviewer key ARM resource ID whose public material is read during phase two.')
param reviewerKeyArmResourceId string

@description('Exact reviewer-vault resource group that is the custom role assignable scope.')
param assignableScopeResourceId string

var allowedDataActions = [
  'Microsoft.KeyVault/vaults/keys/read'
]

resource reviewerKeyReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-rbac-reviewer-key-reader',
    toLower(reviewerKeyArmResourceId)
  )
  properties: {
    roleName: 'Athena WC028 RBAC Reviewer Public Key Reader'
    description: 'Read only the public material and properties of the exact versioned RBAC inventory reviewer key.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: allowedDataActions
        notDataActions: []
      }
    ]
    assignableScopes: [
      assignableScopeResourceId
    ]
  }
}

output roleDefinitionId string = reviewerKeyReaderRole.id
output roleName string = reviewerKeyReaderRole.properties.roleName
output allowedDataActions array = allowedDataActions
