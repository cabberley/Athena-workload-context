targetScope = 'resourceGroup'

@description('Prefix used in the collector Key Vault private DNS VNet link.')
@minLength(3)
@maxLength(48)
param namePrefix string

@description('Dedicated WC-024 collector VNet resource ID.')
param collectorVirtualNetworkResourceId string

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.vaultcore.azure.net'
}

resource keyVaultPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: keyVaultPrivateDnsZone
  name: '${namePrefix}-kv-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorVirtualNetworkResourceId
    }
  }
}
