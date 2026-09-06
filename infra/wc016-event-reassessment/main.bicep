targetScope = 'resourceGroup'

metadata name = 'Athena WC-016 deployable event reassessment runtime'
metadata description = 'Creates private Service Bus transport plus detector, incident orchestrator, signed feed heartbeat, and Teams notification Jobs in an existing private Container Apps environment.'

@description('Lowercase resource prefix shared with the WC-013 deployment.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Deployment region.')
param location string = resourceGroup().location

@description('Existing internal Container Apps managed environment resource ID.')
param managedEnvironmentResourceId string

@description('Existing Container Apps environment VNet resource ID.')
param virtualNetworkResourceId string

@description('Existing private endpoint subnet resource ID.')
param privateEndpointSubnetResourceId string

@description('Existing Azure Container Registry login server.')
param registryServer string

@description('Dedicated WC-016 detector identity resource ID.')
param detectorIdentityResourceId string

@description('Dedicated WC-016 detector identity client ID.')
param detectorIdentityClientId string

@description('Dedicated WC-016 detector identity principal ID.')
param detectorIdentityPrincipalId string

@description('WC-016 orchestrator identity resource ID.')
param orchestratorIdentityResourceId string

@description('WC-016 orchestrator identity client ID.')
param orchestratorIdentityClientId string

@description('WC-016 orchestrator identity principal ID.')
param orchestratorIdentityPrincipalId string

@description('WC-016 Teams notification dispatcher identity resource ID.')
param notificationIdentityResourceId string

@description('WC-016 Teams notification dispatcher identity client ID.')
param notificationIdentityClientId string

@description('WC-016 Teams notification dispatcher identity principal ID.')
param notificationIdentityPrincipalId string

@description('Digest-pinned WC-016 detector image.')
param detectorImage string

@description('Digest-pinned WC-016 incident orchestrator image.')
param orchestratorImage string

@description('Approved singleton database VM resource ID.')
param databaseVmResourceId string

@description('Approved web VM resource IDs.')
@minLength(1)
@maxLength(16)
param webVmResourceIds array

@description('Approved Azure Load Balancer resource ID.')
param loadBalancerResourceId string

@description('Subscription containing the approved synthetic workload resources.')
param workloadSubscriptionId string

@description('Resource group containing every approved detector target.')
param workloadResourceGroupName string

@description('Private Azure Table endpoint used for detector transition state.')
param detectorStateTableEndpoint string

@description('Existing Azure Table name used for detector transition state.')
param detectorStateTableName string

@description('Dedicated detector state partition key.')
@minLength(1)
@maxLength(128)
param detectorStatePartitionKey string

@description('Private Azure Table endpoint used for notification delivery reservations.')
param notificationStateTableEndpoint string

@description('Existing Azure Table name used only for notification delivery reservations.')
param notificationStateTableName string

@description('Dedicated notification delivery reservation partition key.')
@minLength(1)
@maxLength(128)
param notificationStatePartitionKey string

@description('Private Blob endpoint used only for signed incident publication.')
param incidentAssetBlobEndpoint string

@description('Private presentation URL included in bounded notifications.')
param presentationUrl string

@description('Exact versioned Key Vault signing key URI.')
param signingKeyUriWithVersion string

@description('Exact logical signing key ID pinned by the presentation verifier.')
@allowed([
  'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'
])
param signingKeyId string

@description('SHA-256 fingerprint of the approved signing public key.')
@minLength(71)
@maxLength(71)
param signingKeyFingerprint string

@description('Existing authorized Microsoft Teams API connection name.')
param teamsConnectionName string

@description('Logic App workflow receiving bounded notification callbacks.')
param teamsNotifierWorkflowName string

@description('Resource tags.')
param tags object = {}

var senderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39')
var receiverRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0')
var resourceTags = union(tags, {
  component: 'wc016-event-reassessment'
  dataBoundary: 'customer'
  managedBy: 'bicep'
  autoRemediation: 'disabled'
})
var workloadScopePrefix = toLower('/subscriptions/${workloadSubscriptionId}/resourceGroups/${workloadResourceGroupName}/')
var databaseVmResourceIdSegments = split(toLower(databaseVmResourceId), '/')
var validatedDatabaseVmResourceId = startsWith(toLower(databaseVmResourceId), workloadScopePrefix) && length(databaseVmResourceIdSegments) == 9 && databaseVmResourceIdSegments[6] == 'microsoft.compute' && databaseVmResourceIdSegments[7] == 'virtualmachines' && !empty(databaseVmResourceIdSegments[8])
  ? toLower(databaseVmResourceId)
  : fail('databaseVmResourceId must be one VM in the exact approved workload resource group')
var candidateWebVmResourceIds = map(webVmResourceIds, resourceId => startsWith(toLower(string(resourceId)), workloadScopePrefix) && length(split(toLower(string(resourceId)), '/')) == 9 && split(toLower(string(resourceId)), '/')[6] == 'microsoft.compute' && split(toLower(string(resourceId)), '/')[7] == 'virtualmachines' && !empty(split(toLower(string(resourceId)), '/')[8])
  ? toLower(string(resourceId))
  : fail('every webVmResourceIds entry must be one VM in the exact approved workload resource group'))
var validatedWebVmResourceIds = length(union(candidateWebVmResourceIds, [])) == length(candidateWebVmResourceIds) && !contains(
  candidateWebVmResourceIds,
  validatedDatabaseVmResourceId
)
  ? candidateWebVmResourceIds
  : fail('webVmResourceIds must be unique and must not include the approved database VM')
var loadBalancerResourceIdSegments = split(toLower(loadBalancerResourceId), '/')
var validatedLoadBalancerResourceId = startsWith(toLower(loadBalancerResourceId), workloadScopePrefix) && length(loadBalancerResourceIdSegments) == 9 && loadBalancerResourceIdSegments[6] == 'microsoft.network' && loadBalancerResourceIdSegments[7] == 'loadbalancers' && !empty(loadBalancerResourceIdSegments[8])
  ? toLower(loadBalancerResourceId)
  : fail('loadBalancerResourceId must be one load balancer in the exact approved workload resource group')
var webResourceRoles = toObject(validatedWebVmResourceIds, resourceId => resourceId, resourceId => 'web')
var approvedResourceRoles = union({
  '${validatedDatabaseVmResourceId}': 'database-primary'
  '${validatedLoadBalancerResourceId}': 'load-balancer'
}, webResourceRoles)
var approvedAlertRules = [
  'wc016-scheduled-database-primary-power-state'
  'wc016-scheduled-web-power-state'
  'wc016-scheduled-load-balancer-availability'
]
var approvedResourceRolesJson = string(approvedResourceRoles)
var approvedAlertRulesJson = string(approvedAlertRules)
var serviceBusHostName = '${namespace.name}.servicebus.windows.net'
var reassessmentRequestsQueueName = 'incident-reassessment-requests'
var notificationOutboxQueueName = 'incident-notification-outbox'
var jobNamePrefix = take(namePrefix, 18)
var jobResources = {
  cpu: json('0.5')
  memory: '1Gi'
}
var teamsManagedApiId = subscriptionResourceId(
  'Microsoft.Web/locations/managedApis',
  location,
  'teams'
)

resource teamsConnection 'Microsoft.Web/connections@2016-06-01' existing = {
  name: teamsConnectionName
}

resource teamsNotifier 'Microsoft.Logic/workflows@2019-05-01' = {
  name: teamsNotifierWorkflowName
  location: location
  tags: resourceTags
  properties: {
    state: 'Enabled'
    accessControl: any({
      triggers: {
        openAuthenticationPolicies: {
          policies: {
            wc016NotificationIdentity: {
              type: 'AAD'
              claims: [
                {
                  name: 'iss'
                  value: 'https://sts.windows.net/${tenant().tenantId}/'
                }
                {
                  name: 'aud'
                  #disable-next-line no-hardcoded-env-urls // Logic Apps validates the public-cloud ARM token audience.
                  value: 'https://management.azure.com'
                }
                {
                  name: 'appid'
                  value: notificationIdentityClientId
                }
                {
                  name: 'oid'
                  value: notificationIdentityPrincipalId
                }
              ]
            }
          }
        }
        sasAuthenticationPolicy: {
          state: 'Disabled'
        }
      }
    })
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        receive_incident_notification: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              additionalProperties: false
              required: [
                'notificationId'
                'message'
              ]
              properties: {
                notificationId: {
                  type: 'string'
                  pattern: '^notify-[a-f0-9]{64}$'
                }
                message: {
                  type: 'string'
                  minLength: 1
                  maxLength: 4096
                }
              }
            }
          }
        }
      }
      actions: {
        Post_a_message_to_myself: {
          type: 'ApiConnection'
          runAfter: {}
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'teams\'][\'connectionId\']'
              }
            }
            method: 'post'
            body: {
              body: {
                content: '@triggerBody()?[\'message\']'
                contentType: 'text'
              }
            }
            path: '/v1.0/chats/48:notes/messages'
          }
        }
        acknowledge: {
          type: 'Response'
          kind: 'Http'
          runAfter: {
            Post_a_message_to_myself: [
              'Succeeded'
            ]
          }
          inputs: {
            statusCode: 202
            body: {
              accepted: true
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          teams: {
            connectionId: teamsConnection.id
            connectionName: teamsConnection.name
            connectionProperties: {}
            id: teamsManagedApiId
          }
        }
      }
    }
  }
}

var teamsCallback = listCallbackURL(
  '${teamsNotifier.id}/triggers/receive_incident_notification',
  '2019-05-01'
)
var teamsWebhookUrl = '${teamsCallback.basePath}?api-version=${teamsCallback.queries['api-version']}'

resource serviceBusPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  #disable-next-line no-hardcoded-env-urls // Azure Service Bus Private Link requires this zone.
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
  tags: resourceTags
}

resource serviceBusPrivateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: serviceBusPrivateDnsZone
  name: '${namePrefix}-wc016-servicebus-vnet'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource namespace 'Microsoft.ServiceBus/namespaces@2026-01-01' = {
  name: '${namePrefix}-wc016-events'
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

resource networkRules 'Microsoft.ServiceBus/namespaces/networkRuleSets@2026-01-01' = {
  parent: namespace
  name: 'default'
  properties: {
    defaultAction: 'Deny'
    publicNetworkAccess: 'Disabled'
    trustedServiceAccessEnabled: false
  }
}

resource reassessmentRequests 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: namespace
  name: reassessmentRequestsQueueName
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

resource notificationOutbox 'Microsoft.ServiceBus/namespaces/queues@2026-01-01' = {
  parent: namespace
  name: notificationOutboxQueueName
  properties: {
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'P7D'
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P7D'
    lockDuration: 'PT1M'
    maxDeliveryCount: 10
    requiresSession: true
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-10-01' = {
  name: '${namePrefix}-wc016-events-pe'
  location: location
  tags: resourceTags
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

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-10-01' = {
  parent: privateEndpoint
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

resource detectorSend 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reassessmentRequests.id, detectorIdentityPrincipalId, senderRoleId)
  scope: reassessmentRequests
  properties: {
    principalId: detectorIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: senderRoleId
  }
}

resource orchestratorReceive 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reassessmentRequests.id, orchestratorIdentityPrincipalId, receiverRoleId)
  scope: reassessmentRequests
  properties: {
    principalId: orchestratorIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: receiverRoleId
  }
}

resource orchestratorSend 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationOutbox.id, orchestratorIdentityPrincipalId, senderRoleId)
  scope: notificationOutbox
  properties: {
    principalId: orchestratorIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: senderRoleId
  }
}

resource notificationReceive 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(notificationOutbox.id, notificationIdentityPrincipalId, receiverRoleId)
  scope: notificationOutbox
  properties: {
    principalId: notificationIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: receiverRoleId
  }
}

resource detectorJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-w16-det-v2'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${detectorIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 180
      replicaRetryLimit: 0
      scheduleTriggerConfig: {
        cronExpression: '* * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registryServer
          identity: detectorIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc016-signal-detector'
          image: detectorImage
          command: [
            'athena-context'
          ]
          args: [
            'wc016-signal-detector'
            '--service-bus-namespace'
            serviceBusHostName
            '--reassessment-queue'
            reassessmentRequestsQueueName
            '--managed-identity-client-id'
            detectorIdentityClientId
            '--state-table-endpoint'
            detectorStateTableEndpoint
            '--state-table-name'
            detectorStateTableName
            '--state-partition-key'
            detectorStatePartitionKey
            '--metric-window-minutes'
            '5'
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: detectorIdentityClientId
            }
            {
              name: 'ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON'
              value: approvedResourceRolesJson
            }
            {
              name: 'ATHENA_WC016_APPROVED_ALERT_RULES_JSON'
              value: approvedAlertRulesJson
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    detectorSend
    networkRules
    privateDnsZoneGroup
  ]
}

resource orchestratorJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-w16-orch-v2'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Event'
      replicaTimeout: 300
      replicaRetryLimit: 1
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: 4
          pollingInterval: 30
          rules: [
            {
              name: 'incident-reassessment-sessions'
              type: 'azure-servicebus'
              identity: orchestratorIdentityResourceId
              auth: []
              metadata: {
                queueName: reassessmentRequestsQueueName
                namespace: namespace.name
                messageCount: '1'
                cloud: 'AzurePublicCloud'
              }
            }
          ]
        }
      }
      registries: [
        {
          server: registryServer
          identity: orchestratorIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc016-incident-orchestrator'
          image: orchestratorImage
          command: [
            'athena-context'
          ]
          args: [
            'wc016-incident-orchestrator'
            '--service-bus-namespace'
            serviceBusHostName
            '--reassessment-queue'
            reassessmentRequestsQueueName
            '--notification-queue'
            notificationOutboxQueueName
            '--managed-identity-client-id'
            orchestratorIdentityClientId
            '--metric-window-minutes'
            '5'
            '--blob-endpoint'
            incidentAssetBlobEndpoint
            '--presentation-url'
            presentationUrl
            '--key-vault-key-id'
            signingKeyUriWithVersion
            '--signing-key-id'
            signingKeyId
            '--signing-key-fingerprint'
            signingKeyFingerprint
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: orchestratorIdentityClientId
            }
            {
              name: 'ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON'
              value: approvedResourceRolesJson
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    orchestratorReceive
    orchestratorSend
    networkRules
    privateDnsZoneGroup
  ]
}

resource heartbeatJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-w16-feed-v2'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 180
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: '*/5 * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registryServer
          identity: orchestratorIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc016-incident-feed-heartbeat'
          image: orchestratorImage
          command: [
            'athena-context'
          ]
          args: [
            'wc016-incident-feed-heartbeat'
            '--managed-identity-client-id'
            orchestratorIdentityClientId
            '--metric-window-minutes'
            '5'
            '--blob-endpoint'
            incidentAssetBlobEndpoint
            '--key-vault-key-id'
            signingKeyUriWithVersion
            '--signing-key-id'
            signingKeyId
            '--signing-key-fingerprint'
            signingKeyFingerprint
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: orchestratorIdentityClientId
            }
            {
              name: 'ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON'
              value: approvedResourceRolesJson
            }
            {
              name: 'ATHENA_WC016_APPROVED_ALERT_RULES_JSON'
              value: approvedAlertRulesJson
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    networkRules
    privateDnsZoneGroup
  ]
}

resource notificationJob 'Microsoft.App/jobs@2025-01-01' = {
  name: '${jobNamePrefix}-w16-notify-v2'
  location: location
  tags: resourceTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${notificationIdentityResourceId}': {}
    }
  }
  properties: {
    environmentId: managedEnvironmentResourceId
    configuration: {
      triggerType: 'Event'
      replicaTimeout: 180
      replicaRetryLimit: 2
      secrets: [
        {
          name: 'teams-webhook-url'
          value: teamsWebhookUrl
        }
      ]
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: 2
          pollingInterval: 30
          rules: [
            {
              name: 'incident-notification-outbox'
              type: 'azure-servicebus'
              identity: notificationIdentityResourceId
              auth: []
              metadata: {
                queueName: notificationOutboxQueueName
                namespace: namespace.name
                messageCount: '1'
                cloud: 'AzurePublicCloud'
                isSessionsEnabled: 'true'
              }
            }
          ]
        }
      }
      registries: [
        {
          server: registryServer
          identity: notificationIdentityResourceId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'wc016-notification-dispatcher'
          image: orchestratorImage
          command: [
            'athena-context'
          ]
          args: [
            'wc016-notification-dispatcher'
            '--service-bus-namespace'
            serviceBusHostName
            '--notification-queue'
            notificationOutboxQueueName
            '--managed-identity-client-id'
            notificationIdentityClientId
            '--notification-state-table-endpoint'
            notificationStateTableEndpoint
            '--notification-state-table-name'
            notificationStateTableName
            '--notification-state-partition-key'
            notificationStatePartitionKey
          ]
          env: [
            {
              name: 'AZURE_CLIENT_ID'
              value: notificationIdentityClientId
            }
            {
              name: 'ATHENA_WC016_TEAMS_WEBHOOK_URL'
              secretRef: 'teams-webhook-url'
            }
          ]
          resources: jobResources
        }
      ]
    }
  }
  dependsOn: [
    notificationReceive
    networkRules
    privateDnsZoneGroup
  ]
}

@description('Private Service Bus namespace resource ID.')
output namespaceResourceId string = namespace.id

@description('Private Service Bus fully qualified namespace.')
output namespaceHostName string = serviceBusHostName

@description('Context-bound reassessment request queue name.')
output reassessmentQueueName string = reassessmentRequestsQueueName

@description('Bounded incident notification outbox queue name.')
output notificationQueueName string = notificationOutboxQueueName

@description('Private Azure Table endpoint used for notification delivery reservations.')
output notificationStateTableEndpoint string = notificationStateTableEndpoint

@description('Dedicated Azure Table name used only for notification delivery reservations.')
output notificationStateTableName string = notificationStateTableName

@description('Dedicated notification delivery reservation partition key.')
output notificationStatePartitionKey string = notificationStatePartitionKey

@description('Exact JSON for approved-resource-roles.json or ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON.')
output approvedResourceRolesJson string = approvedResourceRolesJson

@description('Exact JSON for approved-alert-rules.json or ATHENA_WC016_APPROVED_ALERT_RULES_JSON.')
output approvedAlertRulesJson string = approvedAlertRulesJson

@description('Hardened v2 scheduled signal detector Job resource ID.')
output detectorJobResourceId string = detectorJob.id

@description('Hardened v2 Service Bus session queue-scaled incident orchestrator Job resource ID.')
output orchestratorJobResourceId string = orchestratorJob.id

@description('Hardened v2 scheduled signed incident feed heartbeat Job resource ID.')
output heartbeatJobResourceId string = heartbeatJob.id

@description('Hardened v2 Service Bus-scaled Teams notification dispatcher Job resource ID.')
output notificationJobResourceId string = notificationJob.id
