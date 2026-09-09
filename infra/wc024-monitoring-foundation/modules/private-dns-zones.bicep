targetScope = 'resourceGroup'

@description('Resource tags applied when a required private DNS zone is created or adopted.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-private-dns'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})

resource azureMonitorPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.monitor.azure.com'
  location: 'global'
  tags: resourceTags
}

resource omsPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.oms.opinsights.azure.com'
  location: 'global'
  tags: resourceTags
}

resource odsPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.ods.opinsights.azure.com'
  location: 'global'
  tags: resourceTags
}

resource agentServicePrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.agentsvc.azure-automation.net'
  location: 'global'
  tags: resourceTags
}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  #disable-next-line no-hardcoded-env-urls // Azure Blob Private Link requires this service DNS zone.
  name: 'privatelink.blob.core.windows.net'
  location: 'global'
  tags: resourceTags
}

output azureMonitorPrivateDnsZoneResourceIds array = [
  azureMonitorPrivateDnsZone.id
  omsPrivateDnsZone.id
  odsPrivateDnsZone.id
  agentServicePrivateDnsZone.id
]
output storageBlobPrivateDnsZoneResourceId string = blobPrivateDnsZone.id
