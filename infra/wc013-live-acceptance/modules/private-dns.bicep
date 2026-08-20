targetScope = 'resourceGroup'

metadata name = 'WC-013 private endpoint DNS'
metadata description = 'Dedicated private DNS zones and VNet links for the WC-013 Key Vault, Azure Table, and Azure Blob endpoints.'

@description('Prefix used in deterministic private DNS VNet-link names.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Resource ID of the dedicated internal Container Apps virtual network.')
param virtualNetworkResourceId string

@description('Resource tags applied to private DNS resources.')
param tags object = {}

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  #disable-next-line no-hardcoded-env-urls // Key Vault Private Link requires this service DNS zone.
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: tags
}

resource storageTablePrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  #disable-next-line no-hardcoded-env-urls // Azure Table Private Link requires this service DNS zone.
  name: 'privatelink.table.core.windows.net'
  location: 'global'
  tags: tags
}

resource storageBlobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  #disable-next-line no-hardcoded-env-urls // Azure Blob Private Link requires this service DNS zone.
  name: 'privatelink.blob.core.windows.net'
  location: 'global'
  tags: tags
}

resource keyVaultPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: keyVaultPrivateDnsZone
  name: '${namePrefix}-wc013-kv-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource storageTablePrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: storageTablePrivateDnsZone
  name: '${namePrefix}-wc013-table-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource storageBlobPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: storageBlobPrivateDnsZone
  name: '${namePrefix}-wc013-blob-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

@description('Resource ID of the Key Vault private DNS zone used by the AVM private endpoint.')
output keyVaultPrivateDnsZoneResourceId string = keyVaultPrivateDnsZone.id

@description('Resource ID of the Azure Table private DNS zone used by the AVM private endpoint.')
output storageTablePrivateDnsZoneResourceId string = storageTablePrivateDnsZone.id

@description('Resource ID of the Azure Blob private DNS zone used by the AVM private endpoint.')
output storageBlobPrivateDnsZoneResourceId string = storageBlobPrivateDnsZone.id
