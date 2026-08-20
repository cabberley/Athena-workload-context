targetScope = 'resourceGroup'

metadata name = 'Private read-only Azure MCP Container App'
metadata description = 'Hosts a pinned Azure MCP server with exact tools and managed identity.'

@description('Container App name.')
param name string

@description('Azure region.')
param location string

@description('Resource ID of the internal Container Apps managed environment.')
param managedEnvironmentId string

@description('Resource ID of the dedicated Azure MCP user-assigned managed identity.')
param mcpIdentityResourceId string

@description('Client ID of the dedicated Azure MCP user-assigned managed identity.')
param mcpIdentityClientId string

@description('Reviewed Azure MCP version.')
param azureMcpVersion string

@description('Reviewed Azure MCP manifest digest.')
param azureMcpImageDigest string

@description('Client ID of the Entra application used for inbound bearer-token validation.')
param entraApplicationClientId string

@description('Tenant ID used for inbound bearer-token validation.')
param entraTenantId string

@description('Resource tags.')
param tags object = {}

var azureMcpImageRepository = 'mcr.microsoft.com/azure-sdk/azure-mcp'
var azureMcpImage = '${azureMcpImageRepository}:${azureMcpVersion}@${azureMcpImageDigest}'

// Keep this list exact. Every entry is a reviewed read-only Azure MCP 2.0.5 tool.
var approvedTools = [
  'group_resource_list'
  'monitor_activitylog_list'
  'monitor_metrics_definitions'
  'monitor_metrics_query'
  'monitor_resource_log_query'
  'monitor_workspace_log_query'
  'resourcehealth_availability-status_get'
]

var baseServerArgs = [
  '--transport'
  'http'
  '--outgoing-auth-strategy'
  'UseHostingEnvironmentIdentity'
  '--mode'
  'all'
  '--read-only'
]
var toolArgs = [for tool in approvedTools: [
  '--tool'
  tool
]]
var serverArgs = flatten(concat([baseServerArgs], toolArgs))

resource azureMcp 'Microsoft.App/containerApps@2026-01-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${mcpIdentityResourceId}': {}
    }
  }
  properties: {
    managedEnvironmentId: managedEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        // External to the app environment, but VNet-scoped because the environment is internal.
        external: true
        allowInsecure: false
        targetPort: 8080
        transport: 'http'
        traffic: [
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
    }
    template: {
      containers: [
        {
          name: 'azure-mcp'
          image: azureMcpImage
          command: []
          args: serverArgs
          env: [
            {
              name: 'ASPNETCORE_ENVIRONMENT'
              value: 'Production'
            }
            {
              name: 'ASPNETCORE_URLS'
              value: 'http://+:8080'
            }
            {
              name: 'AZURE_CLIENT_ID'
              value: mcpIdentityClientId
            }
            {
              name: 'AZURE_TOKEN_CREDENTIALS'
              value: 'managedidentitycredential'
            }
            {
              name: 'AZURE_MCP_INCLUDE_PRODUCTION_CREDENTIALS'
              value: 'true'
            }
            {
              name: 'AZURE_MCP_COLLECT_TELEMETRY'
              value: 'false'
            }
            {
              name: 'AzureAd__Instance'
              value: environment().authentication.loginEndpoint
            }
            {
              name: 'AzureAd__TenantId'
              value: entraTenantId
            }
            {
              name: 'AzureAd__ClientId'
              value: entraApplicationClientId
            }
            {
              name: 'AZURE_LOG_LEVEL'
              value: 'Information'
            }
            // Envoy terminates TLS at private ingress; the pod listener remains environment-local HTTP.
            {
              name: 'AZURE_MCP_DANGEROUSLY_DISABLE_HTTPS_REDIRECTION'
              value: 'true'
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
        rules: [
          {
            name: 'bounded-http'
            http: {
              metadata: {
                concurrentRequests: '20'
              }
            }
          }
        ]
      }
    }
  }
}

output containerAppResourceId string = azureMcp.id
// With external ingress on an internal environment, this is the VNet-scoped non-.internal FQDN.
output internalEndpoint string = 'https://${azureMcp.properties.configuration.ingress.fqdn}'
output allowedTools array = approvedTools
