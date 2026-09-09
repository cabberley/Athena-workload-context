targetScope = 'subscription'

metadata name = 'Athena WC-024 isolated collector connectivity'
metadata description = 'Creates a dedicated collector VNet with its own private-endpoint subnet. It does not peer or otherwise connect the workload and collector networks.'

@description('Reviewed deployment region.')
@allowed([
  'australiaeast'
])
param location string = 'australiaeast'

@description('Existing monitoring resource group that owns the isolated collector network.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string = 'rg-athena-demo-monitoring'

@description('Existing workload resource group.')
@allowed([
  'rg-athena-demo-workload'
])
param workloadResourceGroupName string = 'rg-athena-demo-workload'

@description('Reviewed workload VNet name.')
@allowed([
  'athena-hackathon-vnet'
])
param workloadVirtualNetworkName string = 'athena-hackathon-vnet'

@description('Dedicated WC-024 collector VNet name.')
@allowed([
  'athena-demo-monitoring-collector-vnet'
])
param collectorVirtualNetworkName string = 'athena-demo-monitoring-collector-vnet'

@description('Dedicated WC-024 collector runtime subnet name.')
@allowed([
  'collector-runtime'
])
param collectorRuntimeSubnetName string = 'collector-runtime'

@description('Dedicated collector-local private endpoint subnet name.')
@allowed([
  'private-endpoints'
])
param privateEndpointSubnetName string = 'private-endpoints'

@description('Tags applied to the connectivity resources.')
param tags object = {}

var workloadVirtualNetworkResourceId = resourceId(
  subscription().subscriptionId,
  workloadResourceGroupName,
  'Microsoft.Network/virtualNetworks',
  workloadVirtualNetworkName
)
var workloadPrivateEndpointSubnetResourceId = '${workloadVirtualNetworkResourceId}/subnets/snet-paas-private-endpoints'

resource monitoringResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: monitoringResourceGroupName
}

module collectorNetwork 'modules/monitoring-collector-network.bicep' = {
  name: 'monitoring-collector-network'
  scope: monitoringResourceGroup
  params: {
    location: location
    collectorVirtualNetworkName: collectorVirtualNetworkName
    collectorRuntimeSubnetName: collectorRuntimeSubnetName
    privateEndpointSubnetName: privateEndpointSubnetName
    tags: tags
  }
}

output connectivityContract object = {
  schemaVersion: 'athena.wc024MonitoringConnectivity.v1'
  workloadVirtualNetworkResourceId: workloadVirtualNetworkResourceId
  workloadPrivateEndpointSubnetResourceId: workloadPrivateEndpointSubnetResourceId
  collectorRuntimeVirtualNetworkResourceId: collectorNetwork.outputs.collectorVirtualNetworkResourceId
  collectorRuntimeSubnetResourceId: collectorNetwork.outputs.collectorRuntimeSubnetResourceId
  collectorPrivateEndpointSubnetResourceId: collectorNetwork.outputs.privateEndpointSubnetResourceId
}
