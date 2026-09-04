targetScope = 'resourceGroup'

metadata name = 'Athena WC-016 event-driven reassessment'
metadata description = 'Creates the private, duplicate-safe event transport for governed Athena reassessment.'

@description('Lowercase resource prefix.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Deployment region.')
param location string = resourceGroup().location

@description('Private endpoint subnet resource ID.')
param privateEndpointSubnetId string

@description('Existing privatelink.servicebus.windows.net private DNS zone resource ID.')
param serviceBusPrivateDnsZoneId string

@description('Principal ID of the normalizer worker identity.')
param normalizerPrincipalId string

@description('Principal ID of the incident orchestrator identity.')
param orchestratorPrincipalId string

@description('Approved singleton database VM resource ID.')
param databaseVmResourceId string

@description('Approved web VM resource IDs.')
@minLength(1)
@maxLength(16)
param webVmResourceIds array

@description('Approved Azure Load Balancer resource ID.')
param loadBalancerResourceId string

@description('Pre-authorized Action Group that forwards common-alert-schema payloads to raw-monitor-events.')
param monitorActionGroupResourceId string

@description('Resource tags.')
param tags object = {}

var senderRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
)
var receiverRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'
)
var resourceTags = union(tags, {
  component: 'wc016-event-reassessment'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})

resource namespace 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: '${namePrefix}-events'
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
    publicNetworkAccess: 'Disabled'
    premiumMessagingPartitions: 1
    zoneRedundant: true
  }
}

resource networkRules 'Microsoft.ServiceBus/namespaces/networkRuleSets@2024-01-01' = {
  parent: namespace
  name: 'default'
  properties: {
    defaultAction: 'Deny'
    publicNetworkAccess: 'Disabled'
    trustedServiceAccessEnabled: true
  }
}

resource rawEvents 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: 'raw-monitor-events'
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT1H'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    lockDuration: 'PT1M'
    maxDeliveryCount: 5
  }
}

resource reassessmentRequests 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: 'incident-reassessment-requests'
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P1D'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P1D'
    lockDuration: 'PT5M'
    maxDeliveryCount: 5
    requiresSession: true
  }
}

resource notificationOutbox 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: 'incident-notification-outbox'
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P1D'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P7D'
    lockDuration: 'PT1M'
    maxDeliveryCount: 10
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${namePrefix}-events-pe'
  location: location
  tags: resourceTags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
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

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'servicebus'
        properties: {
          privateDnsZoneId: serviceBusPrivateDnsZoneId
        }
      }
    ]
  }
}

resource normalizerReceive 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(rawEvents.id, normalizerPrincipalId, receiverRoleId)
  scope: rawEvents
  properties: {
    principalId: normalizerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: receiverRoleId
  }
}

resource normalizerSend 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reassessmentRequests.id, normalizerPrincipalId, senderRoleId)
  scope: reassessmentRequests
  properties: {
    principalId: normalizerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: senderRoleId
  }
}

resource orchestratorReceive 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reassessmentRequests.id, orchestratorPrincipalId, receiverRoleId)
  scope: reassessmentRequests
  properties: {
    principalId: orchestratorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: receiverRoleId
  }
}

resource orchestratorSend 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationOutbox.id, orchestratorPrincipalId, senderRoleId)
  scope: notificationOutbox
  properties: {
    principalId: orchestratorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: senderRoleId
  }
}

resource databaseAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = {
    name: '${namePrefix}-database-availability'
    location: 'global'
    tags: resourceTags
    properties: {
      description: 'Detect loss of the approved singleton database VM.'
      severity: 0
      enabled: true
      scopes: [
        databaseVmResourceId
      ]
      evaluationFrequency: 'PT1M'
      windowSize: 'PT5M'
      autoMitigate: true
      targetResourceType: 'Microsoft.Compute/virtualMachines'
      targetResourceRegion: location
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
        allOf: [
          {
            name: 'DatabaseVmUnavailable'
            metricNamespace: 'Microsoft.Compute/virtualMachines'
            metricName: 'VmAvailabilityMetric'
            operator: 'LessThan'
            threshold: 1
            timeAggregation: 'Average'
            criterionType: 'StaticThresholdCriterion'
            skipMetricValidation: false
          }
        ]
      }
      actions: [
        {
          actionGroupId: monitorActionGroupResourceId
        }
      ]
    }
  }

  resource webAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = [for (webVmResourceId, index) in webVmResourceIds: {
    name: '${namePrefix}-web-${index}-availability'
    location: 'global'
    tags: resourceTags
    properties: {
      description: 'Detect loss of one approved web VM.'
      severity: 1
      enabled: true
      scopes: [
        webVmResourceId
      ]
      evaluationFrequency: 'PT1M'
      windowSize: 'PT5M'
      autoMitigate: true
      targetResourceType: 'Microsoft.Compute/virtualMachines'
      targetResourceRegion: location
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
        allOf: [
          {
            name: 'WebVmUnavailable'
            metricNamespace: 'Microsoft.Compute/virtualMachines'
            metricName: 'VmAvailabilityMetric'
            operator: 'LessThan'
            threshold: 1
            timeAggregation: 'Average'
            criterionType: 'StaticThresholdCriterion'
            skipMetricValidation: false
          }
        ]
      }
      actions: [
        {
          actionGroupId: monitorActionGroupResourceId
        }
      ]
    }
  }]

  resource loadBalancerAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = {
    name: '${namePrefix}-load-balancer-vip-availability'
    location: 'global'
    tags: resourceTags
    properties: {
      description: 'Detect loss of Azure Load Balancer VIP availability.'
      severity: 0
      enabled: true
      scopes: [
        loadBalancerResourceId
      ]
      evaluationFrequency: 'PT1M'
      windowSize: 'PT5M'
      autoMitigate: true
      targetResourceType: 'Microsoft.Network/loadBalancers'
      targetResourceRegion: location
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
        allOf: [
          {
            name: 'LoadBalancerVipUnavailable'
            metricNamespace: 'Microsoft.Network/loadBalancers'
            metricName: 'VipAvailability'
            operator: 'LessThan'
            threshold: 100
            timeAggregation: 'Average'
            criterionType: 'StaticThresholdCriterion'
            skipMetricValidation: false
          }
        ]
      }
      actions: [
        {
          actionGroupId: monitorActionGroupResourceId
        }
      ]
    }
    }

    resource loadBalancerDipAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = {
      name: '${namePrefix}-load-balancer-dip-availability'
      location: 'global'
      tags: resourceTags
      properties: {
        description: 'Detect loss of Azure Load Balancer data-path availability.'
        severity: 0
        enabled: true
        scopes: [
          loadBalancerResourceId
        ]
        evaluationFrequency: 'PT1M'
        windowSize: 'PT5M'
        autoMitigate: true
        targetResourceType: 'Microsoft.Network/loadBalancers'
        targetResourceRegion: location
        criteria: {
          'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
          allOf: [
            {
              name: 'LoadBalancerDipUnavailable'
              metricNamespace: 'Microsoft.Network/loadBalancers'
              metricName: 'DipAvailability'
              operator: 'LessThan'
              threshold: 100
              timeAggregation: 'Average'
              criterionType: 'StaticThresholdCriterion'
              skipMetricValidation: false
            }
          ]
        }
        actions: [
          {
            actionGroupId: monitorActionGroupResourceId
          }
        ]
      }
    }
output namespaceId string = namespace.id
output namespaceHostName string = '${namespace.name}.servicebus.windows.net'
output rawEventQueueName string = rawEvents.name
output reassessmentQueueName string = reassessmentRequests.name
output notificationOutboxQueueName string = notificationOutbox.name
output approvedMetricAlertRuleNames array = [
  databaseAvailability.name
  loadBalancerAvailability.name
  loadBalancerDipAvailability.name
]
output approvedWebMetricAlertRuleNames array = [
  for index in range(0, length(webVmResourceIds)): '${namePrefix}-web-${index}-availability'
]
