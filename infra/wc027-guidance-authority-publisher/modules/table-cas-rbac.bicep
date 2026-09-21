targetScope = 'resourceGroup'

param storageAccountName string
param tableName string
param identityResourceId string

resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' existing = {
  parent: storage
  name: 'default'
}

resource table 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  parent: tableService
  name: tableName
  properties: {}
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource casRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(table.id, 'athena-wc027-table-cas')
  properties: {
    roleName: 'Athena WC027 Guidance Activation CAS (${storageAccountName}/${tableName})'
    description: 'Read, add, and conditionally update guidance activation entities. No entity or table delete and no table administration.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/tableServices/tables/entities/read'
          'Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action'
          'Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource cas 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(table.id, identity.id, casRole.id)
  scope: table
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: casRole.id
  }
}

output roleDefinitionResourceId string = casRole.id
output roleAssignmentResourceId string = cas.id
