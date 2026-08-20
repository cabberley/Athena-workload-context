targetScope = 'resourceGroup'

metadata name = 'Internal Container Apps private DNS'
metadata description = 'Resolves VNet-scoped Container App FQDNs to the internal environment static IP.'

@description('Name of the private DNS VNet link.')
param virtualNetworkLinkName string

@description('Default DNS domain assigned to the internal Container Apps environment.')
param environmentDefaultDomain string

@description('Static private IP assigned to the internal Container Apps environment.')
param environmentStaticIp string

@description('Resource ID of the dedicated internal Container Apps virtual network.')
param virtualNetworkResourceId string

@description('Resource tags applied to the private DNS zone.')
param tags object = {}

resource containerAppsPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: environmentDefaultDomain
  location: 'global'
  tags: tags
}

resource containerAppsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: containerAppsPrivateDnsZone
  name: virtualNetworkLinkName
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource containerAppsWildcardRecord 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: containerAppsPrivateDnsZone
  name: '*'
  properties: {
    ttl: 300
    aRecords: [
      {
        ipv4Address: environmentStaticIp
      }
    ]
  }
}
