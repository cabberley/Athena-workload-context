targetScope = 'resourceGroup'

@description('Exact verifier UAMI resource ID.')
param verifierIdentityResourceId string

@description('Exact verifier UAMI principal ID.')
param verifierPrincipalId string

@description('Exact keys/get-only custom role definition ID.')
param roleDefinitionId string

@description('Existing separately governed reviewer Key Vault name.')
param vaultName string

@description('Existing reviewer key name.')
param keyName string

@description('Exact reviewer key ARM resource ID.')
param expectedKeyResourceId string

resource reviewerVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: vaultName
}

resource reviewerKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' existing = {
  parent: reviewerVault
  name: keyName
}

var validatedReviewerKeyResourceId = toLower(reviewerKey.id) == toLower(expectedKeyResourceId)
  ? reviewerKey.id
  : fail('Reviewer key reader assignment escaped the exact separately governed reviewer key.')

resource verifierKeyReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(
    toLower(validatedReviewerKeyResourceId),
    toLower(verifierIdentityResourceId),
    toLower(roleDefinitionId)
  )
  scope: reviewerKey
  properties: {
    principalId: verifierPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output roleAssignmentId string = verifierKeyReader.id
