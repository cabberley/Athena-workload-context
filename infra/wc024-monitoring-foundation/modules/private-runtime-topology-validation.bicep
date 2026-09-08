targetScope = 'resourceGroup'

@description('Workload VNet whose agents use the Azure Monitor private endpoint after cutover.')
param workloadVirtualNetworkResourceId string

@description('VNet containing the dedicated private endpoint subnet.')
param privateEndpointVirtualNetworkResourceId string

@description('Dedicated private endpoint subnet resource ID.')
param privateEndpointSubnetResourceId string

@description('Collector runtime VNet used by the isolated Azure MCP or signed-evidence collector.')
param collectorRuntimeVirtualNetworkResourceId string

@description('Collector runtime subnet resource ID.')
param collectorRuntimeSubnetResourceId string

@description('Reviewed operator attestation that routing or peering permits workload agents to reach the private endpoint VNet when the VNets differ.')
param workloadPrivateEndpointConnectivityConfirmed bool = false

@description('Reviewed operator attestation that routing or peering permits the isolated collector runtime to reach the private endpoint VNet when the VNets differ.')
param collectorRuntimePrivateEndpointConnectivityConfirmed bool = false

@description('Reviewed operator attestation that workload DNS resolution uses the managed private-zone links or equivalent approved forwarding.')
param workloadPrivateDnsResolutionConfirmed bool = false

@description('Reviewed operator attestation that collector runtime DNS resolution uses the managed private-zone links or equivalent approved forwarding.')
param collectorRuntimePrivateDnsResolutionConfirmed bool = false

@description('Set true only for the phase-two private-ingestion cutover, when DNS resolution attestations are mandatory.')
param privateMonitoringIngestionCutoverConfirmed bool = false

var deploymentSubscriptionPrefix = toLower('${subscription().id}/resourcegroups/')
var normalizedWorkloadVirtualNetworkResourceId = toLower(workloadVirtualNetworkResourceId)
var normalizedPrivateEndpointVirtualNetworkResourceId = toLower(privateEndpointVirtualNetworkResourceId)
var normalizedPrivateEndpointSubnetResourceId = toLower(privateEndpointSubnetResourceId)
var normalizedCollectorRuntimeVirtualNetworkResourceId = toLower(collectorRuntimeVirtualNetworkResourceId)
var normalizedCollectorRuntimeSubnetResourceId = toLower(collectorRuntimeSubnetResourceId)
var allVnetsAreDeploymentSubscriptionScoped = startsWith(normalizedWorkloadVirtualNetworkResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedPrivateEndpointVirtualNetworkResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedCollectorRuntimeVirtualNetworkResourceId, deploymentSubscriptionPrefix)
var allSubnetsAreDeploymentSubscriptionScoped = startsWith(normalizedPrivateEndpointSubnetResourceId, deploymentSubscriptionPrefix) && startsWith(normalizedCollectorRuntimeSubnetResourceId, deploymentSubscriptionPrefix)
var privateEndpointSubnetBelongsToDeclaredVnet = startsWith(normalizedPrivateEndpointSubnetResourceId, '${normalizedPrivateEndpointVirtualNetworkResourceId}/subnets/') && length(split(normalizedPrivateEndpointSubnetResourceId, '/')) == length(split(normalizedPrivateEndpointVirtualNetworkResourceId, '/')) + 2
var collectorRuntimeSubnetBelongsToDeclaredVnet = startsWith(normalizedCollectorRuntimeSubnetResourceId, '${normalizedCollectorRuntimeVirtualNetworkResourceId}/subnets/') && length(split(normalizedCollectorRuntimeSubnetResourceId, '/')) == length(split(normalizedCollectorRuntimeVirtualNetworkResourceId, '/')) + 2
var workloadCanReachPrivateEndpoints = normalizedWorkloadVirtualNetworkResourceId == normalizedPrivateEndpointVirtualNetworkResourceId || workloadPrivateEndpointConnectivityConfirmed
var collectorCanReachPrivateEndpoints = normalizedCollectorRuntimeVirtualNetworkResourceId == normalizedPrivateEndpointVirtualNetworkResourceId || collectorRuntimePrivateEndpointConnectivityConfirmed
var privateCutoverDnsResolutionConfirmed = !privateMonitoringIngestionCutoverConfirmed || (workloadPrivateDnsResolutionConfirmed && collectorRuntimePrivateDnsResolutionConfirmed)
var topologyValidated = allVnetsAreDeploymentSubscriptionScoped && allSubnetsAreDeploymentSubscriptionScoped && privateEndpointSubnetBelongsToDeclaredVnet && collectorRuntimeSubnetBelongsToDeclaredVnet && workloadCanReachPrivateEndpoints && collectorCanReachPrivateEndpoints && privateCutoverDnsResolutionConfirmed
  ? true
  : fail('WC-024 requires deployment-subscription VNet and subnet IDs, matching declared subnet parents, private-endpoint routing or peering for distinct workload and collector VNets, and reviewed private DNS resolution for the phase-two private cutover.')

@description('Validated workload VNet ID for private DNS links.')
output workloadVirtualNetworkResourceId string = topologyValidated ? workloadVirtualNetworkResourceId : fail('Unreachable topology validation failure.')

@description('Validated collector runtime VNet ID for private DNS links.')
output collectorRuntimeVirtualNetworkResourceId string = topologyValidated ? collectorRuntimeVirtualNetworkResourceId : fail('Unreachable topology validation failure.')

@description('Validated private endpoint subnet ID.')
output privateEndpointSubnetResourceId string = topologyValidated ? privateEndpointSubnetResourceId : fail('Unreachable topology validation failure.')
