targetScope = 'resourceGroup'

@description('Workload VNet whose agents use the workload-local Azure Monitor private endpoint.')
param workloadVirtualNetworkResourceId string

@description('Workload-local private endpoint subnet resource ID.')
param workloadPrivateEndpointSubnetResourceId string

@description('Dedicated WC-024 collector runtime VNet resource ID.')
param collectorRuntimeVirtualNetworkResourceId string

@description('Dedicated WC-024 collector runtime subnet resource ID.')
param collectorRuntimeSubnetResourceId string

@description('Collector-local private endpoint subnet resource ID.')
param collectorPrivateEndpointSubnetResourceId string

var deploymentSubscriptionPrefix = toLower('${subscription().id}/resourcegroups/')
var normalizedWorkloadVirtualNetworkResourceId = toLower(workloadVirtualNetworkResourceId)
var normalizedWorkloadPrivateEndpointSubnetResourceId = toLower(workloadPrivateEndpointSubnetResourceId)
var normalizedCollectorRuntimeVirtualNetworkResourceId = toLower(collectorRuntimeVirtualNetworkResourceId)
var normalizedCollectorRuntimeSubnetResourceId = toLower(collectorRuntimeSubnetResourceId)
var normalizedCollectorPrivateEndpointSubnetResourceId = toLower(collectorPrivateEndpointSubnetResourceId)
var allVnetsAreDeploymentSubscriptionScoped = startsWith(normalizedWorkloadVirtualNetworkResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedCollectorRuntimeVirtualNetworkResourceId, deploymentSubscriptionPrefix)
var allSubnetsAreDeploymentSubscriptionScoped = startsWith(normalizedWorkloadPrivateEndpointSubnetResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedCollectorRuntimeSubnetResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedCollectorPrivateEndpointSubnetResourceId, deploymentSubscriptionPrefix)
var workloadPrivateEndpointSubnetBelongsToWorkloadVnet = startsWith(normalizedWorkloadPrivateEndpointSubnetResourceId, '${normalizedWorkloadVirtualNetworkResourceId}/subnets/') && length(split(normalizedWorkloadPrivateEndpointSubnetResourceId, '/')) == length(split(normalizedWorkloadVirtualNetworkResourceId, '/')) + 2
var collectorRuntimeSubnetBelongsToCollectorVnet = startsWith(normalizedCollectorRuntimeSubnetResourceId, '${normalizedCollectorRuntimeVirtualNetworkResourceId}/subnets/') && length(split(normalizedCollectorRuntimeSubnetResourceId, '/')) == length(split(normalizedCollectorRuntimeVirtualNetworkResourceId, '/')) + 2
var collectorPrivateEndpointSubnetBelongsToCollectorVnet = startsWith(normalizedCollectorPrivateEndpointSubnetResourceId, '${normalizedCollectorRuntimeVirtualNetworkResourceId}/subnets/') && length(split(normalizedCollectorPrivateEndpointSubnetResourceId, '/')) == length(split(normalizedCollectorRuntimeVirtualNetworkResourceId, '/')) + 2
var collectorSubnetsAreDistinct = normalizedCollectorRuntimeSubnetResourceId != normalizedCollectorPrivateEndpointSubnetResourceId
var networksRemainIsolated = normalizedWorkloadVirtualNetworkResourceId != normalizedCollectorRuntimeVirtualNetworkResourceId
var topologyValidated = allVnetsAreDeploymentSubscriptionScoped && allSubnetsAreDeploymentSubscriptionScoped && workloadPrivateEndpointSubnetBelongsToWorkloadVnet && collectorRuntimeSubnetBelongsToCollectorVnet && collectorPrivateEndpointSubnetBelongsToCollectorVnet && collectorSubnetsAreDistinct && networksRemainIsolated
  ? true
  : fail('WC-024 requires exact deployment-subscription workload and dedicated collector network IDs, local private-endpoint subnets, distinct collector runtime/private-endpoint subnets, and no shared workload/collector VNet.')

output workloadVirtualNetworkResourceId string = topologyValidated ? workloadVirtualNetworkResourceId : fail('Unreachable topology validation failure.')
output workloadPrivateEndpointSubnetResourceId string = topologyValidated ? workloadPrivateEndpointSubnetResourceId : fail('Unreachable topology validation failure.')
output collectorRuntimeVirtualNetworkResourceId string = topologyValidated ? collectorRuntimeVirtualNetworkResourceId : fail('Unreachable topology validation failure.')
output collectorRuntimeSubnetResourceId string = topologyValidated ? collectorRuntimeSubnetResourceId : fail('Unreachable topology validation failure.')
output collectorPrivateEndpointSubnetResourceId string = topologyValidated ? collectorPrivateEndpointSubnetResourceId : fail('Unreachable topology validation failure.')
