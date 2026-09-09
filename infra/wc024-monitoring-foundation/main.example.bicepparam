using './main.bicep'

// Synthetic, non-deployable values document the required reviewed inputs.
param location = 'australiaeast'
param monitoringResourceGroupName = 'rg-athena-demo-monitoring'
param namePrefix = 'athena-demo-monitoring'
param workloadResourceGroupName = 'rg-athena-demo-workload'
param approvedVmNames = [
  'athena-hackathon-client-01'
  'athena-hackathon-ecp-01'
  'athena-hackathon-ecp-02'
  'athena-hackathon-ecp-03'
  'athena-hackathon-iris-01'
  'athena-hackathon-mid-01'
  'athena-hackathon-mid-02'
  'athena-hackathon-sqlvm-01'
  'athena-hackathon-web-01'
  'athena-hackathon-web-02'
  'athena-hackathon-web-03'
]
param workloadVirtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/athena-hackathon-vnet'
param networkWatcherResourceGroupName = 'NetworkWatcherRG'
param networkWatcherName = 'NetworkWatcher_australiaeast'
param workloadPrivateEndpointSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/athena-hackathon-vnet/subnets/snet-paas-private-endpoints'
param collectorRuntimeVirtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet'
param collectorRuntimeSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet/subnets/collector-runtime'
param collectorPrivateEndpointSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet/subnets/private-endpoints'
param monitoringStorageAccountName = 'athenademomonstore'
param monitoringCollectorKeyVaultName = 'athenademomonkv'
param retentionDays = 30
param maximumEvidenceAgeSeconds = 600
param connectionMonitorDeploymentEnabled = false
param legacyFlowLogNames = []
param legacyFlowLogTargetResourceIds = []
param canonicalVnetFlowLogCutoverConfirmed = false
param tags = {
  environment: 'synthetic'
  workload: 'athena'
}
