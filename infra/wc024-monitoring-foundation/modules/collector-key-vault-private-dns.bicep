targetScope = 'resourceGroup'

@description('Resource tags applied to the collector-only Key Vault DNS zone.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-private-dns'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  accessBoundary: 'collector-only'
})

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: resourceTags
}

output keyVaultPrivateDnsZoneResourceId string = keyVaultPrivateDnsZone.id
