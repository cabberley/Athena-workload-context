targetScope = 'subscription'

metadata name = 'Athena private Azure MCP foundation example'
metadata description = 'Example subscription deployment; not shared root orchestration.'

@description('Azure region for the synthetic example.')
param location string = deployment().location

@description('Dedicated resource group for the synthetic example.')
param resourceGroupName string = 'athena-synth-mcp-rg'

@description('Synthetic deterministic resource prefix.')
param namePrefix string = 'athena-synth-dev'

@description('Existing Entra application client ID that protects inbound MCP calls.')
param entraApplicationClientId string

@description('Optional explicit workload resource-group scopes. Keep empty until reviewed.')
param workloadReadScopes array = []

@description('Optional approved Log Analytics workspaces. Keep empty until reviewed.')
param approvedLogWorkspaces array = []

resource foundationResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: resourceGroupName
  location: location
  tags: {
    workload: 'athena-synthetic'
    environment: 'development'
  }
}

module azureMcp '../../azure-mcp/main.bicep' = {
  name: 'wc008-private-azure-mcp-foundation'
  scope: foundationResourceGroup
  params: {
    location: location
    namePrefix: namePrefix
    entraApplicationClientId: entraApplicationClientId
    workloadReadScopes: workloadReadScopes
    approvedLogWorkspaces: approvedLogWorkspaces
    tags: {
      workload: 'athena-synthetic'
      environment: 'development'
    }
  }
}

output azureMcpContainerAppResourceId string = azureMcp.outputs.azureMcpContainerAppResourceId
output managedEnvironmentResourceId string = azureMcp.outputs.managedEnvironmentResourceId
output azureMcpInternalEndpoint string = azureMcp.outputs.azureMcpInternalEndpoint
output azureMcpIdentityResourceId string = azureMcp.outputs.azureMcpIdentityResourceId
output athenaContextIdentityResourceId string = azureMcp.outputs.athenaContextIdentityResourceId
output allowedTools array = azureMcp.outputs.allowedTools
