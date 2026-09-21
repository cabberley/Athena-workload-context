targetScope = 'subscription'

@description('Exact monitoring evidence storage account whose protection state is read live.')
param storageAccountResourceId string

@description('Monitoring resource group used as the custom-role assignable scope.')
param assignableScopeResourceId string

var storageSegments = split(toLower(storageAccountResourceId), '/')
var validatedStorageAccountResourceId = length(storageSegments) == 9 && storageSegments[1] == 'subscriptions' && storageSegments[2] == toLower(subscription().subscriptionId) && storageSegments[3] == 'resourcegroups' && storageSegments[5] == 'providers' && storageSegments[6] == 'microsoft.storage' && storageSegments[7] == 'storageaccounts' && !empty(storageSegments[8])
  ? toLower(storageAccountResourceId)
  : fail('storage readback authorization must target one storage account in this subscription')
var storageReadbackActions = [
  'Microsoft.Storage/storageAccounts/read'
  'Microsoft.Storage/storageAccounts/blobServices/read'
  'Microsoft.Storage/storageAccounts/blobServices/containers/read'
  'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read'
]

resource storageReadbackRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-monitoring-storage-readback',
    toLower(validatedStorageAccountResourceId)
  )
  properties: {
    roleName: 'Athena WC028 Monitoring Storage Protection Reader'
    description: 'Read only the exact storage account, Blob service, evidence container, and immutability policy protection state.'
    type: 'CustomRole'
    permissions: [
      {
        actions: storageReadbackActions
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      assignableScopeResourceId
    ]
  }
}

output roleDefinitionId string = storageReadbackRole.id
output roleName string = storageReadbackRole.properties.roleName
output allowedOperations array = storageReadbackActions
output assignmentScopeId string = validatedStorageAccountResourceId
