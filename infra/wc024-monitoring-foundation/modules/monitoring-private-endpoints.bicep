targetScope = 'resourceGroup'

@description('Azure region for private endpoints.')
param location string = resourceGroup().location

@description('Lowercase prefix for deterministic private endpoint names.')
param namePrefix string

@description('Resource ID of the workload-local private endpoint subnet.')
param workloadPrivateEndpointSubnetResourceId string

@description('Resource ID of the collector-local private endpoint subnet.')
param collectorPrivateEndpointSubnetResourceId string

@description('Resource ID of the workload Azure Monitor private link scope.')
param workloadAzureMonitorPrivateLinkScopeResourceId string

@description('Resource ID of the collector Azure Monitor private link scope.')
param collectorAzureMonitorPrivateLinkScopeResourceId string

@description('Resource ID of monitoring-owned replacement storage.')
param storageAccountResourceId string

@description('Resource ID of the monitoring collector Key Vault.')
param keyVaultResourceId string

@description('Workload-bound private DNS zone ID for Azure Monitor Blob endpoints.')
param workloadStorageBlobPrivateDnsZoneResourceId string

@description('Collector-bound private DNS zone ID for Blob private endpoints.')
param collectorStorageBlobPrivateDnsZoneResourceId string

@description('Collector-bound private DNS zone ID for Key Vault private endpoints.')
param collectorKeyVaultPrivateDnsZoneResourceId string

@description('The four workload-bound non-Blob private DNS zone IDs required by Azure Monitor private link.')
@minLength(4)
@maxLength(4)
param workloadAzureMonitorPrivateDnsZoneResourceIds array

@description('The four collector-bound non-Blob private DNS zone IDs required by Azure Monitor private link.')
@minLength(4)
@maxLength(4)
param collectorAzureMonitorPrivateDnsZoneResourceIds array

@description('Resource tags applied to private endpoints.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-private-network'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})
var workloadAzureMonitorPrivateDnsZoneConfigs = [
  for (zoneId, index) in workloadAzureMonitorPrivateDnsZoneResourceIds: {
    name: 'azure-monitor-${index}'
    properties: {
      privateDnsZoneId: zoneId
    }
  }
]
var collectorAzureMonitorPrivateDnsZoneConfigs = [
  for (zoneId, index) in collectorAzureMonitorPrivateDnsZoneResourceIds: {
    name: 'azure-monitor-${index}'
    properties: {
      privateDnsZoneId: zoneId
    }
  }
]

resource workloadAzureMonitorPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-workload-ampls-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: workloadPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'workload-azure-monitor'
        properties: {
          privateLinkServiceId: workloadAzureMonitorPrivateLinkScopeResourceId
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
  }
}

resource workloadAzureMonitorPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: workloadAzureMonitorPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: concat(
      [
        {
          name: 'azure-monitor-blob'
          properties: {
            privateDnsZoneId: workloadStorageBlobPrivateDnsZoneResourceId
          }
        }
      ],
      workloadAzureMonitorPrivateDnsZoneConfigs
    )
  }
}

resource collectorAzureMonitorPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-collector-ampls-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: collectorPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'collector-azure-monitor'
        properties: {
          privateLinkServiceId: collectorAzureMonitorPrivateLinkScopeResourceId
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
  }
}

resource collectorAzureMonitorPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: collectorAzureMonitorPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: concat(
      [
        {
          name: 'azure-monitor-blob'
          properties: {
            privateDnsZoneId: collectorStorageBlobPrivateDnsZoneResourceId
          }
        }
      ],
      collectorAzureMonitorPrivateDnsZoneConfigs
    )
  }
}

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-monitoring-storage-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: collectorPrivateEndpointSubnetResourceId
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
          privateDnsZoneId: collectorStorageBlobPrivateDnsZoneResourceId
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
      id: collectorPrivateEndpointSubnetResourceId
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
          privateDnsZoneId: collectorKeyVaultPrivateDnsZoneResourceId
        }
      }
    ]
  }
}
