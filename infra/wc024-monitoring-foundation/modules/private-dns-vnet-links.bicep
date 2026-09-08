targetScope = 'resourceGroup'

@description('Prefix used in deterministic private DNS virtual-network-link names.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Workload VNet that must resolve every private Azure Monitor, Blob, and Key Vault endpoint.')
param workloadVirtualNetworkResourceId string

@description('Collector runtime VNet that must resolve private Blob and Key Vault endpoints and Azure Monitor private-link records. It receives a separate link only when it differs from the workload VNet.')
param collectorRuntimeVirtualNetworkResourceId string

var collectorRuntimeRequiresSeparateLinks = toLower(collectorRuntimeVirtualNetworkResourceId) != toLower(workloadVirtualNetworkResourceId)

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

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.vaultcore.azure.net'
}

resource azureMonitorPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: azureMonitorPrivateDnsZone
  name: '${namePrefix}-ampls-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: workloadVirtualNetworkResourceId
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
      id: workloadVirtualNetworkResourceId
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
      id: workloadVirtualNetworkResourceId
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
      id: workloadVirtualNetworkResourceId
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
      id: workloadVirtualNetworkResourceId
    }
  }
}

resource keyVaultPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: keyVaultPrivateDnsZone
  name: '${namePrefix}-kv-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: workloadVirtualNetworkResourceId
    }
  }
}

resource collectorAzureMonitorPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: azureMonitorPrivateDnsZone
  name: '${namePrefix}-ampls-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

resource collectorOmsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: omsPrivateDnsZone
  name: '${namePrefix}-oms-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

resource collectorOdsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: odsPrivateDnsZone
  name: '${namePrefix}-ods-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

resource collectorAgentServicePrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: agentServicePrivateDnsZone
  name: '${namePrefix}-agentsvc-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

resource collectorBlobPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: blobPrivateDnsZone
  name: '${namePrefix}-blob-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

resource collectorKeyVaultPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (collectorRuntimeRequiresSeparateLinks) {
  parent: keyVaultPrivateDnsZone
  name: '${namePrefix}-kv-collector'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: collectorRuntimeVirtualNetworkResourceId
    }
  }
}

output azureMonitorPrivateDnsZoneResourceIds array = [
  azureMonitorPrivateDnsZone.id
  omsPrivateDnsZone.id
  odsPrivateDnsZone.id
  agentServicePrivateDnsZone.id
]
output storageBlobPrivateDnsZoneResourceId string = blobPrivateDnsZone.id
output keyVaultPrivateDnsZoneResourceId string = keyVaultPrivateDnsZone.id
