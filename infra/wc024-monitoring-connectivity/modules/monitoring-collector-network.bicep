targetScope = 'resourceGroup'

@description('Reviewed region for the isolated monitoring collector network.')
param location string

@description('Dedicated WC-024 collector VNet name.')
param collectorVirtualNetworkName string

@description('Dedicated WC-024 collector runtime subnet name.')
param collectorRuntimeSubnetName string

@description('Dedicated collector-local private endpoint subnet name.')
param privateEndpointSubnetName string

@description('Tags applied to connectivity resources.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-connectivity'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})

resource privateEndpointNsg 'Microsoft.Network/networkSecurityGroups@2024-10-01' = {
  name: '${collectorVirtualNetworkName}-pe-nsg'
  location: location
  tags: resourceTags
  properties: {
    securityRules: [
      {
        name: 'AllowCollectorPrivateEndpointHttps'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '10.45.0.0/25'
          destinationAddressPrefix: 'VirtualNetwork'
        }
      }
      {
        name: 'DenyUnreviewedPrivateEndpointInbound'
        properties: {
          priority: 110
          access: 'Deny'
          direction: 'Inbound'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'VirtualNetwork'
        }
      }
    ]
  }
}

resource collectorVirtualNetwork 'Microsoft.Network/virtualNetworks@2024-10-01' = {
  name: collectorVirtualNetworkName
  location: location
  tags: resourceTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.45.0.0/24'
      ]
    }
    subnets: [
      {
        name: collectorRuntimeSubnetName
        properties: {
          addressPrefix: '10.45.0.0/25'
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: privateEndpointSubnetName
        properties: {
          addressPrefix: '10.45.0.128/26'
          networkSecurityGroup: {
            id: privateEndpointNsg.id
          }
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output collectorVirtualNetworkResourceId string = collectorVirtualNetwork.id
output collectorRuntimeSubnetResourceId string = collectorVirtualNetwork.properties.subnets[0].id
output privateEndpointSubnetResourceId string = collectorVirtualNetwork.properties.subnets[1].id
