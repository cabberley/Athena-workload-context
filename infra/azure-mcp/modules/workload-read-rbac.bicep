targetScope = 'resourceGroup'

metadata name = 'Azure MCP workload resource-group read roles'
metadata description = 'Optional, narrowly scoped read-only role assignments for the MCP identity.'

@description('Principal ID of the dedicated Azure MCP user-assigned identity.')
param mcpIdentityPrincipalId string

@description('Grant Reader at this workload resource group only.')
param grantReader bool = false

@description('Grant Monitoring Reader at this workload resource group only.')
param grantMonitoringReader bool = false

@description('Grant Resource Health Reader at this workload resource group only.')
param grantResourceHealthReader bool = false

var readerRoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
var monitoringReaderRoleDefinitionId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
var resourceHealthReaderRoleDefinitionId = '96aae8d4-72a9-4bc2-ae31-3a10c2c4e526'

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (grantReader) {
  name: guid(resourceGroup().id, mcpIdentityPrincipalId, readerRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      readerRoleDefinitionId
    )
  }
}

resource monitoringReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (grantMonitoringReader) {
  name: guid(resourceGroup().id, mcpIdentityPrincipalId, monitoringReaderRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      monitoringReaderRoleDefinitionId
    )
  }
}

resource resourceHealthReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (grantResourceHealthReader) {
  name: guid(resourceGroup().id, mcpIdentityPrincipalId, resourceHealthReaderRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      resourceHealthReaderRoleDefinitionId
    )
  }
}
