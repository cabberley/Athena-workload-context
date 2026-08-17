targetScope = 'resourceGroup'

metadata name = 'Azure MCP approved workspace log read role'
metadata description = 'Grants log query access to one explicitly approved Log Analytics workspace.'

@description('Name of the approved existing Log Analytics workspace.')
param workspaceName string

@description('Principal ID of the dedicated Azure MCP user-assigned identity.')
param mcpIdentityPrincipalId string

var logAnalyticsDataReaderRoleDefinitionId = '3b03c2da-16b3-4a49-8834-0f8130efdd3b'

resource approvedWorkspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource workspaceLogDataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: approvedWorkspace
  name: guid(approvedWorkspace.id, mcpIdentityPrincipalId, logAnalyticsDataReaderRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      logAnalyticsDataReaderRoleDefinitionId
    )
  }
}
