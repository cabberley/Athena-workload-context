using './main.bicep'

// Synthetic, non-deployable values document the required reviewed inputs.
param location = 'australiaeast'
param monitoringResourceGroupName = 'rg-athena-demo-monitoring'
param namePrefix = 'athena-demo-monitoring'
param workloadResourceGroupName = 'rg-athena-demo-workload'
param approvedVmNames = [
  'synthetic-vm-01'
  'synthetic-vm-02'
  'synthetic-vm-03'
  'synthetic-vm-04'
  'synthetic-vm-05'
  'synthetic-vm-06'
  'synthetic-vm-07'
  'synthetic-vm-08'
  'synthetic-vm-09'
  'synthetic-vm-10'
  'synthetic-vm-11'
]
param workloadVirtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/synthetic-workload-vnet'
param networkWatcherResourceGroupName = 'NetworkWatcherRG'
param networkWatcherName = 'NetworkWatcher_australiaeast'
param privateEndpointSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/synthetic-monitoring-vnet/subnets/private-endpoints'
param privateEndpointVirtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/synthetic-monitoring-vnet'
param collectorRuntimeVirtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/synthetic-collector-vnet'
param collectorRuntimeSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.Network/virtualNetworks/synthetic-collector-vnet/subnets/collector-runtime'
param workloadPrivateEndpointConnectivityConfirmed = true
param collectorRuntimePrivateEndpointConnectivityConfirmed = true
param workloadPrivateDnsResolutionConfirmed = false
param collectorRuntimePrivateDnsResolutionConfirmed = false
param monitoringStorageAccountName = 'athenademomonstore'
param monitoringCollectorKeyVaultName = 'athenademomonkv'
param collectorRoleDefinitionGuid = '14d3d0d4-28bd-45b3-b0e0-18c581d57b5e'
param retentionDays = 30
param maximumEvidenceAgeSeconds = 600
param connectionMonitorDeploymentEnabled = false
param legacyFlowLogNames = []
param legacyFlowLogTargetResourceIds = []
param canonicalVnetFlowLogCutoverConfirmed = false
param privateMonitoringIngestionCutoverConfirmed = false
param createPrivateLinkScope = true
param tags = {
  environment: 'synthetic'
  workload: 'athena'
}
