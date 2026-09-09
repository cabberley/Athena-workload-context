targetScope = 'resourceGroup'

@description('Azure region for monitoring storage.')
param location string = resourceGroup().location

@description('Globally unique lowercase monitoring storage account name.')
param storageAccountName string

@description('Retention period for flow-log and collector-evidence data.')
@minValue(30)
@maxValue(365)
param retentionDays int

@description('Resource tags applied to monitoring storage.')
param tags object = {}

var resourceTags = union(tags, {
  component: 'wc024-monitoring-storage'
  dataBoundary: 'customer'
  managedBy: 'bicep'
})

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  tags: resourceTags
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    // The retained legacy flow-log account proves Network Watcher can ingest with Shared Key disabled.
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    // Network Watcher flow-log writers require the storage firewall's trusted-service route.
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: []
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: {
          enabled: true
        }
      }
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: {
      enabled: true
      days: retentionDays
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: retentionDays
    }
  }
}

resource monitoringEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  parent: blobService
  name: 'monitoring-evidence'
  properties: {
    publicAccess: 'None'
  }
}

resource monitoringEvidenceImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2025-06-01' = {
  parent: monitoringEvidenceContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
  }
}

resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2025-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'flow-log-evidence-retention'
          type: 'Lifecycle'
          definition: {
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: 30
                }
                delete: {
                  daysAfterModificationGreaterThan: retentionDays
                }
              }
              version: {
                delete: {
                  daysAfterCreationGreaterThan: retentionDays
                }
              }
            }
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                'insights-logs-flowlogflowevent/'
                'monitoring-evidence/'
              ]
            }
          }
        }
      ]
    }
  }
}

output storageAccountResourceId string = storageAccount.id
output monitoringEvidenceContainerResourceId string = monitoringEvidenceContainer.id
