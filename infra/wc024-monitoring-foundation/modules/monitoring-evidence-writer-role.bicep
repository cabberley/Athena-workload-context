targetScope = 'subscription'

@description('Exact monitoring-evidence container receiving conditioned known-name reads and add-only writes.')
param monitoringEvidenceContainerResourceId string

@description('Exact monitoring resource group that is the custom role assignable scope.')
param assignableScopeResourceId string

var monitoringEvidenceWriterDataActions = [
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
]

resource monitoringEvidenceCreateOnlyRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-monitoring-evidence-create-only',
    toLower(monitoringEvidenceContainerResourceId)
  )
  properties: {
    roleName: 'Athena WC028 Monitoring Evidence Create-Only Writer'
    description: 'Read exact known monitoring evidence Blobs and create new Blobs without overwrite, list, or delete permission.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: monitoringEvidenceWriterDataActions
        notDataActions: []
      }
    ]
    assignableScopes: [
      assignableScopeResourceId
    ]
  }
}

output roleDefinitionId string = monitoringEvidenceCreateOnlyRole.id
output roleName string = monitoringEvidenceCreateOnlyRole.properties.roleName
output allowedDataActions array = monitoringEvidenceWriterDataActions
