targetScope = 'resourceGroup'

@description('Storage account hosting the guidance activation Table.')
param storageAccountName string

@description('Guidance activation Table name.')
param tableName string

@description('Exact runtime identity resource ID allowed to read and mark feed materialization.')
param identityResourceId string

resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' existing = {
  parent: storage
  name: 'default'
}

resource table 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' existing = {
  parent: tableService
  name: tableName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: last(split(identityResourceId, '/'))
  scope: resourceGroup(split(identityResourceId, '/')[2], split(identityResourceId, '/')[4])
}

resource materializerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(table.id, 'athena-wc027-feed-materializer')
  properties: {
    roleName: 'Athena WC027 Guidance Feed Materializer (${storageAccountName}/${tableName})'
    description: 'Read and conditionally update only the guidance activation materialization marker. No entity add/delete or table administration.'
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
          'Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource materializer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(table.id, identity.id, materializerRole.id)
  scope: table
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: materializerRole.id
  }
}

output roleDefinitionResourceId string = materializerRole.id
output roleAssignmentResourceId string = materializer.id
