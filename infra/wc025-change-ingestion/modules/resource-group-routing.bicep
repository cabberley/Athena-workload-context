targetScope = 'resourceGroup'

@description('Tags inherited from WC-025 root orchestration.')
param resourceTags object

@description('Exact private Service Bus queue resource ID for bounded event delivery.')
param changeEventsQueueResourceId string

@description('Dedicated Event Grid user-assigned delivery identity resource ID.')
param eventGridDeliveryIdentityResourceId string

@description('Exact approved resource IDs used by the Event Grid data.resourceUri allowlist.')
param approvedResourceIds array

resource resourceChangeSystemTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' = {
  name: '${take(uniqueString(resourceGroup().id), 40)}-wc025-changes'
  location: 'global'
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${eventGridDeliveryIdentityResourceId}': {}
    }
  }
  properties: {
    source: resourceGroup().id
    topicType: 'Microsoft.Resources.ResourceGroups'
  }
}

resource resourceChangeSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = {
  parent: resourceChangeSystemTopic
  name: 'approved-resource-changes'
  properties: {
    eventDeliverySchema: 'EventGridSchema'
    filter: {
      advancedFilters: [
        {
          key: 'data.resourceUri'
          operatorType: 'StringIn'
          values: approvedResourceIds
        }
      ]
      includedEventTypes: [
        'Microsoft.Resources.ResourceWriteSuccess'
        'Microsoft.Resources.ResourceWriteFailure'
        'Microsoft.Resources.ResourceWriteCancel'
        'Microsoft.Resources.ResourceDeleteSuccess'
        'Microsoft.Resources.ResourceDeleteFailure'
        'Microsoft.Resources.ResourceDeleteCancel'
        'Microsoft.Resources.ResourceActionSuccess'
        'Microsoft.Resources.ResourceActionFailure'
        'Microsoft.Resources.ResourceActionCancel'
      ]
    }
    retryPolicy: {
      eventTimeToLiveInMinutes: 1440
      maxDeliveryAttempts: 5
    }
    deliveryWithResourceIdentity: {
      identity: {
        type: 'UserAssigned'
        userAssignedIdentity: eventGridDeliveryIdentityResourceId
      }
      destination: {
        endpointType: 'ServiceBusQueue'
        properties: {
          resourceId: changeEventsQueueResourceId
        }
      }
    }
  }
}
output resourceChangeSystemTopicId string = resourceChangeSystemTopic.id
