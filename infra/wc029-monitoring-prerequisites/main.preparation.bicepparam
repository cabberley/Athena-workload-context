using './main.bicep'

// Deployment mutations remain off. Create a separately reviewed artifact before enabling either extension family.
param expectedSubscriptionId = 'a6add389-9978-47ac-ab1e-a09212e321d4'
param location = 'australiaeast'
param workloadResourceGroupName = 'rg-athena-demo-workload'
param monitoringResourceGroupName = 'rg-athena-demo-monitoring'
param networkWatcherResourceGroupName = 'NetworkWatcherRG'
param networkWatcherName = 'NetworkWatcher_australiaeast'
param monitoringStorageAccountName = 'athenademomonchab01'
param monitoringStoragePrivateEndpointName = 'athena-demo-monitoring-monitoring-storage-pe'
param deployVmInsightsDependencyAgent = false
param deployConnectionMonitorAgent = false
param connectionMonitorSourceVmNames = []
param connectionMonitorDefinitionsEnabled = false
param subscriptionActivityLogExportEnabled = false
