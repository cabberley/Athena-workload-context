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
param athenaContextIdentityResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-context/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-demo-context'
param collectorRuntimeResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-wc013-live/providers/Microsoft.App/jobs/athena-wc028-monitoring-acquisition'
param rbacAttestorRuntimeResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.App/jobs/athena-wc028-rbac-attestor'
param runtimeSupportIdentityResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-wc013-live/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-wc028-monitoring-acquisition-support-id'
param rbacInventoryReviewerPrincipalId = '77777777-7777-7777-7777-777777777777'
param rbacInventoryReviewerKeyId = 'https://athenarbacevidencekv.vault.azure.net/keys/monitoring-rbac-inventory-review/0123456789abcdef0123456789abcdef'
param rbacInventoryReviewerKeyArmResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-rbac-review/providers/Microsoft.KeyVault/vaults/athenarbacevidencekv/keys/monitoring-rbac-inventory-review'
param rbacInventoryVerifierIdentityResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-rbac-review/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-wc028-rbac-review-verifier'
param rbacInventoryReviewerPublicKeyModulus = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
param rbacInventoryReviewerPublicKeyExponent = 'AQAB'
param rbacInventoryReviewerPublicKeyFingerprint = 'sha256:abababababababababababababababababababababababababababababababab'
param legacyCollectorRbacCleanupDigest = 'sha256:9999999999999999999999999999999999999999999999999999999999999999'
param monitoringEvidenceStorageReadinessDigest = 'sha256:d6ffd8f9985cee9831ee4950bcf5234ae76de641afdb7133e6dceb9ca80cd103'
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
