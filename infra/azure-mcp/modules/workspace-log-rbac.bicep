targetScope = 'resourceGroup'

metadata name = 'Azure MCP approved workspace log read role'
metadata description = 'Grants log query access to one explicitly approved Log Analytics workspace.'

@description('Name of the approved existing Log Analytics workspace.')
param workspaceName string

@description('Principal ID of the dedicated Azure MCP user-assigned identity.')
param mcpIdentityPrincipalId string

var logAnalyticsReaderRoleDefinitionId = '73c42c96-874c-492b-b04d-ab87d138a893'

resource approvedWorkspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource workspaceLogReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: approvedWorkspace
  name: guid(approvedWorkspace.id, mcpIdentityPrincipalId, logAnalyticsReaderRoleDefinitionId)
  properties: {
    principalId: mcpIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      logAnalyticsReaderRoleDefinitionId
    )
  }
}
