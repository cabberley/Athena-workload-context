using './main.bicep'

// Synthetic and intentionally non-deployable until WC-025 images, identities, and key versions are approved.
param location = 'australiaeast'
param hostingResourceGroupName = 'rg-athena-wc013-live'
param workloadResourceGroupName = 'rg-athena-demo-workload'
param subscriptionActivityLogExportEnabled = false
param managedEnvironmentResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-wc013-live/providers/Microsoft.App/managedEnvironments/athena-wc013-live-mcp-env'
param virtualNetworkResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-wc013-live/providers/Microsoft.Network/virtualNetworks/synthetic-private-runtime-vnet'
param privateEndpointSubnetResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-wc013-live/providers/Microsoft.Network/virtualNetworks/synthetic-private-runtime-vnet/subnets/private-endpoints'
param registryName = 'syntheticregistry'
param registryServer = 'syntheticregistry.azurecr.io'
param changeIngesterImage = 'syntheticregistry.azurecr.io/athena/wc025-change-ingester@sha256:1111111111111111111111111111111111111111111111111111111111111111'
param eventGridDeliveryIdentityName = 'synthetic-wc025-event-grid-delivery-id'
param eventIngesterIdentityName = 'synthetic-wc025-event-ingester-id'
param purgeIdentityName = 'synthetic-wc025-dead-letter-purge-id'
param queryIdentityName = 'synthetic-wc025-change-query-id'
param approvedResourceIds = [
  '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-athena-demo-workload/providers/Microsoft.Network/networkSecurityGroups/synthetic-approved-nsg'
]
param evidenceStorageAccountName = 'syntheticwc025store'
param evidenceContainerName = 'change-evidence'
param failureReceiptContainerName = 'change-ingestion-failures'
param keyVaultName = 'synthetic-wc025-kv'
param changeSigningKeyName = 'wc025-change-evidence-signing'
param changeSigningKeyUriWithVersion = 'https://synthetic-wc025-kv.vault.azure.net/keys/wc025-change-evidence-signing/00000000000000000000000000000000'
param tags = {
  environment: 'synthetic'
  workload: 'athena'
}
