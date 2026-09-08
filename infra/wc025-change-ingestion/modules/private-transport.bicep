targetScope = 'resourceGroup'

@description('Azure region for private WC-025 transport.')
param location string

@description('Tags inherited from WC-025 root orchestration.')
param resourceTags object

@description('Existing VNet resource ID for the private Service Bus DNS link.')
param virtualNetworkResourceId string

@description('Existing subnet resource ID for the private Service Bus endpoint.')
param privateEndpointSubnetResourceId string

var namespaceName = take('${uniqueString(resourceGroup().id)}wc025changes', 50)
var changeEventsQueueName = 'change-evidence-events'

resource serviceBusPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
  tags: resourceTags
}

resource namespace 'Microsoft.ServiceBus/namespaces@2026-01-01' = {
  name: namespaceName
  location: location
  tags: resourceTags
  sku: {
    name: 'Premium'
    tier: 'Premium'
    capacity: 1
  }
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    premiumMessagingPartitions: 1
    zoneRedundant: true
  }
}

resource namespaceNetworkRules 'Microsoft.ServiceBus/namespaces/networkRuleSets@2026-01-01' = {
  parent: namespace
  name: 'default'
  properties: {
    defaultAction: 'Deny'
    publicNetworkAccess: 'Enabled'
    trustedServiceAccessEnabled: true
  }
}

resource changeEventsQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: namespace
  name: changeEventsQueueName
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P1D'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    lockDuration: 'PT5M'
    maxDeliveryCount: 5
    requiresSession: false
  }
}

resource serviceBusPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${take(namespaceName, 48)}-pe'
  location: location
  tags: resourceTags
  dependsOn: [
    changeEventsQueue
  ]
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'namespace'
        properties: {
          privateLinkServiceId: namespace.id
          groupIds: [
            'namespace'
          ]
        }
      }
    ]
  }
}

resource serviceBusPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: serviceBusPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'servicebus'
        properties: {
          privateDnsZoneId: serviceBusPrivateDnsZone.id
        }
      }
    ]
  }
}

resource serviceBusPrivateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: serviceBusPrivateDnsZone
  name: '${take(namespaceName, 48)}-vnet'
  location: 'global'
  dependsOn: [
    serviceBusPrivateDnsZoneGroup
  ]
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

output namespaceResourceId string = namespace.id
output namespaceName string = namespace.name
output changeEventsQueueResourceId string = changeEventsQueue.id
output changeEventsQueueName string = changeEventsQueueName
