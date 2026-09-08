targetScope = 'resourceGroup'

@description('Actual location of the adopted Log Analytics workspace, retained during the phase-two update.')
param workspaceLocation string

@description('Existing Log Analytics workspace whose public access is disabled only after private connectivity is ready.')
param workspaceName string

@description('Exact existing workspace tags retained during the public-access update.')
param workspaceTags object

@description('Existing data collection endpoint whose public access is disabled only after private connectivity is ready.')
param dataCollectionEndpointName string

@description('Actual location of the adopted data collection endpoint, retained during the phase-two update.')
param dataCollectionEndpointLocation string

@description('Exact existing data collection endpoint tags retained during the public-access update.')
param dataCollectionEndpointTags object

@description('Existing data collection endpoint description retained during the public-access update.')
param dataCollectionEndpointDescription string?

@description('Existing data collection endpoint kind retained during the public-access update.')
param dataCollectionEndpointKind string?

@description('Azure Monitor Private Link Scope switched to private-only access with the adopted monitoring resources.')
param privateLinkScopeName string

@description('Exact existing Azure Monitor Private Link Scope tags retained during the access-mode update.')
param privateLinkScopeTags object

@description('Existing Azure Monitor Private Link Scope per-private-endpoint access-mode exclusions retained during the access-mode update.')
param privateLinkScopeAccessModeExclusions array

@description('Existing workspace SKU retained while private access is enabled.')
param workspaceSkuName string

@description('Reviewed workspace retention retained while private access is enabled.')
@minValue(30)
@maxValue(365)
param workspaceRetentionDays int

@description('Existing workspace daily data-ingestion quota retained while private access is enabled. -1 means unlimited.')
@minValue(-1)
param workspaceDailyQuotaGb int

@description('Exact existing workspace feature settings, including local authentication and resource-context log access, retained while private access is enabled.')
param workspaceFeatures object

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: workspaceName
  location: workspaceLocation
  tags: workspaceTags
  properties: {
    sku: {
      name: workspaceSkuName
    }
    retentionInDays: workspaceRetentionDays
    workspaceCapping: {
      dailyQuotaGb: workspaceDailyQuotaGb
    }
    features: workspaceFeatures
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Disabled'
  }
}

var dataCollectionEndpointProperties = union(
  {
    networkAcls: {
      publicNetworkAccess: 'Disabled'
    }
  },
  dataCollectionEndpointDescription == null ? {} : {
    description: dataCollectionEndpointDescription
  }
)

resource dataCollectionEndpointWithKind 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = if (dataCollectionEndpointKind != null) {
  name: dataCollectionEndpointName
  location: dataCollectionEndpointLocation
  kind: dataCollectionEndpointKind!
  tags: dataCollectionEndpointTags
  properties: dataCollectionEndpointProperties
}

resource dataCollectionEndpointWithoutKind 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = if (dataCollectionEndpointKind == null) {
  name: dataCollectionEndpointName
  location: dataCollectionEndpointLocation
  tags: dataCollectionEndpointTags
  properties: dataCollectionEndpointProperties
}

resource privateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-09-01' = {
  name: privateLinkScopeName
  location: 'global'
  tags: privateLinkScopeTags
  properties: {
    accessModeSettings: {
      exclusions: privateLinkScopeAccessModeExclusions
      queryAccessMode: 'PrivateOnly'
      ingestionAccessMode: 'PrivateOnly'
    }
  }
}
