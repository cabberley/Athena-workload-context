targetScope = 'resourceGroup'

@description('Prefix used in deterministic private DNS virtual-network-link names.')
@minLength(3)
@maxLength(48)
param namePrefix string

@description('The sole VNet linked to this isolated private DNS boundary.')
param virtualNetworkResourceId string

resource azureMonitorPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.monitor.azure.com'
}

resource omsPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.oms.opinsights.azure.com'
}

resource odsPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.ods.opinsights.azure.com'
}

resource agentServicePrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.agentsvc.azure-automation.net'
}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  #disable-next-line no-hardcoded-env-urls // Azure Blob Private Link requires this service DNS zone.
  name: 'privatelink.blob.core.windows.net'
}

resource azureMonitorPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: azureMonitorPrivateDnsZone
  name: '${namePrefix}-ampls-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource omsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: omsPrivateDnsZone
  name: '${namePrefix}-oms-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource odsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: odsPrivateDnsZone
  name: '${namePrefix}-ods-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource agentServicePrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: agentServicePrivateDnsZone
  name: '${namePrefix}-agentsvc-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource blobPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: blobPrivateDnsZone
  name: '${namePrefix}-blob-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}
