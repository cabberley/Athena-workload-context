targetScope = 'resourceGroup'

@description('Existing private WC-025 Service Bus namespace name.')
param namespaceName string

@description('Existing private WC-025 queue name.')
param changeEventsQueueName string

@description('System-assigned Event Grid delivery identity principal ID.')
param eventGridDeliveryPrincipalId string

var serviceBusDataSenderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39')

resource namespace 'Microsoft.ServiceBus/namespaces@2026-01-01' existing = {
  name: namespaceName
}

resource changeEventsQueue 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' existing = {
  parent: namespace
  name: changeEventsQueueName
}

resource eventGridQueueSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(changeEventsQueue.id, eventGridDeliveryPrincipalId, serviceBusDataSenderRoleId)
  scope: changeEventsQueue
  properties: {
    principalId: eventGridDeliveryPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusDataSenderRoleId
  }
}
