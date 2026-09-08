targetScope = 'resourceGroup'

@description('Azure region for private endpoints.')
param location string = resourceGroup().location

@description('Lowercase prefix for deterministic private endpoint names.')
param namePrefix string

@description('Resource ID of the dedicated private endpoint subnet.')
param privateEndpointSubnetResourceId string

@description('Resource ID of the Azure Monitor private link scope.')
param azureMonitorPrivateLinkScopeResourceId string

@description('Resource ID of monitoring-owned replacement storage.')
param storageAccountResourceId string

@description('Resource ID of the monitoring collector Key Vault.')
param keyVaultResourceId string

@description('Private DNS zone ID for Blob private endpoints.')
param storageBlobPrivateDnsZoneResourceId string

@description('Private DNS zone ID for Key Vault private endpoints.')
param keyVaultPrivateDnsZoneResourceId string

@description('The four non-Blob private DNS zone IDs required by Azure Monitor private link.')
@minLength(4)
@maxLength(4)
param azureMonitorPrivateDnsZoneResourceIds array

@description('Resource tags applied to private endpoints.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-private-network'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var azureMonitorPrivateDnsZoneConfigs = [
  for (zoneId, index) in azureMonitorPrivateDnsZoneResourceIds: {
    name: 'azure-monitor-${index}'
    properties: {
      privateDnsZoneId: zoneId
    }
  }
]

resource azureMonitorPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-ampls-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'azure-monitor'
        properties: {
          privateLinkServiceId: azureMonitorPrivateLinkScopeResourceId
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
  }
}

resource azureMonitorPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: azureMonitorPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: concat(
      [
        {
          name: 'azure-monitor-blob'
          properties: {
            privateDnsZoneId: storageBlobPrivateDnsZoneResourceId
          }
        }
      ],
      azureMonitorPrivateDnsZoneConfigs
    )
  }
}

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-monitoring-storage-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'monitoring-storage-blob'
        properties: {
          privateLinkServiceId: storageAccountResourceId
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

resource storagePrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: storagePrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: storageBlobPrivateDnsZoneResourceId
        }
      }
    ]
  }
}

resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-monitoring-kv-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'monitoring-collector-key'
        properties: {
          privateLinkServiceId: keyVaultResourceId
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource keyVaultPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: keyVaultPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: keyVaultPrivateDnsZoneResourceId
        }
      }
    ]
  }
}
