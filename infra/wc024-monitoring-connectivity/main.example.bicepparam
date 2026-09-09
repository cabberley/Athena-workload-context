using './main.bicep'

// Synthetic, non-deployable values document the exact environment-owned topology inputs.
param location = 'australiaeast'
param monitoringResourceGroupName = 'rg-athena-demo-monitoring'
param workloadResourceGroupName = 'rg-athena-demo-workload'
param workloadVirtualNetworkName = 'athena-hackathon-vnet'
param collectorVirtualNetworkName = 'athena-demo-monitoring-collector-vnet'
param collectorRuntimeSubnetName = 'collector-runtime'
param privateEndpointSubnetName = 'private-endpoints'
param tags = {
  environment: 'synthetic'
  workload: 'athena'
}
