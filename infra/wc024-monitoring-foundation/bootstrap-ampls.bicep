targetScope = 'resourceGroup'

metadata name = 'Athena WC-024 one-time AMPLS bootstrap'
metadata description = 'Creates the reviewed Azure Monitor Private Link Scope once with explicit Open access modes. The steady-state foundation only adopts it.'

@description('Resource tags applied only during first creation.')
param tags object = {}

@description('Exact AMPLS name to create in this serialized bootstrap invocation.')
@allowed([
  'athena-demo-monitoring-workload-ampls'
  'athena-demo-monitoring-collector-ampls'
])
param privateLinkScopeName string

var resourceTags = union(tags, {
  component: 'wc024-monitoring-data-platform'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  lifecycle: 'one-time-bootstrap'
})

resource privateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' = {
  name: privateLinkScopeName
  location: 'global'
  tags: resourceTags
  properties: {
    accessModeSettings: {
      exclusions: []
      queryAccessMode: 'Open'
      ingestionAccessMode: 'Open'
    }
  }
}

output privateLinkScopeResourceId string = privateLinkScope.id
