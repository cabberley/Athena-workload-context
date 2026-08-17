targetScope = 'resourceGroup'

metadata name = 'Athena private Azure MCP foundation'
metadata description = 'Issue-scoped, private, authenticated, read-only Azure MCP evidence plane.'

@description('Azure region for the private Azure MCP foundation.')
param location string = resourceGroup().location

@description('Lowercase prefix used for deterministic customer-hosted resource names.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Reviewed Azure MCP release. A floating or latest tag is rejected.')
@allowed([
  '2.0.5'
])
param azureMcpVersion string = '2.0.5'

@description('Reviewed multi-architecture manifest digest for the pinned Azure MCP release.')
@allowed([
  'sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a'
])
param azureMcpImageDigest string = 'sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a'

@description('Client ID of the existing Entra application that protects inbound MCP requests.')
param entraApplicationClientId string

@description('Tenant that issues inbound MCP access tokens.')
param entraTenantId string = tenant().tenantId

@description('Address prefix for the dedicated private Container Apps virtual network.')
param virtualNetworkAddressPrefix string = '10.42.0.0/16'

@description('Delegated infrastructure subnet prefix. Container Apps requires a dedicated subnet.')
param infrastructureSubnetPrefix string = '10.42.0.0/23'

@description('Optional workload resource-group scopes. Empty means the MCP identity gets no workload access.')
param workloadReadScopes array = []

@description('Optional approved Log Analytics workspaces. Empty means no workspace log access.')
param approvedLogWorkspaces array = []

@description('Resource tags applied to the issue-scoped foundation.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'azure-mcp-evidence'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: '${namePrefix}-mcp-vnet'
  location: location
  tags: resourceTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        virtualNetworkAddressPrefix
      ]
    }
  }
}

resource infrastructureSubnet 'Microsoft.Network/virtualNetworks/subnets@2025-05-01' = {
  parent: virtualNetwork
  name: 'container-apps-infrastructure'
  properties: {
    addressPrefix: infrastructureSubnetPrefix
    delegations: [
      {
        name: 'Microsoft.App.environments'
        properties: {
          serviceName: 'Microsoft.App/environments'
        }
      }
    ]
  }
}

resource mcpIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${namePrefix}-mcp-evidence-id'
  location: location
  tags: union(resourceTags, {
    identityPurpose: 'azure-mcp-read-only-evidence'
  })
}

resource contextIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${namePrefix}-context-id'
  location: location
  tags: union(resourceTags, {
    identityPurpose: 'athena-context-no-workload-reader'
  })
}

resource managedEnvironment 'Microsoft.App/managedEnvironments@2026-01-01' = {
  name: '${namePrefix}-mcp-env'
  location: location
  tags: resourceTags
  properties: {
    publicNetworkAccess: 'Disabled'
    vnetConfiguration: {
      infrastructureSubnetId: infrastructureSubnet.id
      internal: true
    }
    zoneRedundant: false
  }
}

module containerApp 'modules/container-app.bicep' = {
  name: 'private-read-only-azure-mcp'
  params: {
    name: '${namePrefix}-mcp'
    location: location
    managedEnvironmentId: managedEnvironment.id
    mcpIdentityResourceId: mcpIdentity.id
    mcpIdentityClientId: mcpIdentity.properties.clientId
    azureMcpVersion: azureMcpVersion
    azureMcpImageDigest: azureMcpImageDigest
    entraApplicationClientId: entraApplicationClientId
    entraTenantId: entraTenantId
    tags: resourceTags
  }
}

module workloadReadRoleAssignments 'modules/workload-read-rbac.bicep' = [
  for (readScope, index) in workloadReadScopes: {
    name: 'mcp-workload-read-${index}-${uniqueString(readScope.subscriptionId, readScope.resourceGroupName)}'
    scope: resourceGroup(readScope.subscriptionId, readScope.resourceGroupName)
    params: {
      mcpIdentityPrincipalId: mcpIdentity.properties.principalId
    }
  }
]

module workspaceLogRoleAssignments 'modules/workspace-log-rbac.bicep' = [
  for (workspace, index) in approvedLogWorkspaces: {
    name: 'mcp-workspace-log-read-${index}-${uniqueString(workspace.subscriptionId, workspace.resourceGroupName, workspace.name)}'
    scope: resourceGroup(workspace.subscriptionId, workspace.resourceGroupName)
    params: {
      workspaceName: workspace.name
      mcpIdentityPrincipalId: mcpIdentity.properties.principalId
    }
  }
]

@description('Resource ID of the private Azure MCP Container App.')
output azureMcpContainerAppResourceId string = containerApp.outputs.containerAppResourceId

@description('Resource ID of the internal Container Apps environment for approved callers.')
output managedEnvironmentResourceId string = managedEnvironment.id

@description('Environment-local MCP endpoint. It is not reachable through public ingress.')
output azureMcpInternalEndpoint string = containerApp.outputs.internalEndpoint

@description('Dedicated identity used only by the Azure MCP evidence plane.')
output azureMcpIdentityResourceId string = mcpIdentity.id

@description('Athena context identity. This principal receives no workload read role in this deployment.')
output athenaContextIdentityResourceId string = contextIdentity.id

@description('Exact reviewed Azure MCP tools exposed by this foundation.')
output allowedTools array = containerApp.outputs.allowedTools
