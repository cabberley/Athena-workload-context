targetScope = 'resourceGroup'

@description('Expected VM and DCE region.')
@allowed([
  'australiaeast'
])
param location string

@description('Exact approved Linux VM names.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Resource group containing the adopted DCE.')
@allowed([
  'rg-athena-demo-monitoring'
])
param monitoringResourceGroupName string

@description('Exact adopted DCR resource ID.')
param dataCollectionRuleResourceId string

@description('Exact adopted DCE resource ID.')
param dataCollectionEndpointResourceId string

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' existing = {
  name: 'athena-hackathon-linux-dce'
  scope: resourceGroup(monitoringResourceGroupName)
}

resource approvedVms 'Microsoft.Compute/virtualMachines@2025-04-01' existing = [for vmName in approvedVmNames: {
  name: vmName
}]

resource azureMonitorLinuxAgents 'Microsoft.Compute/virtualMachines/extensions@2024-11-01' existing = [for (vmName, index) in approvedVmNames: {
  parent: approvedVms[index]
  name: 'AzureMonitorLinuxAgent'
}]

resource dataCollectionRuleAssociations 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' existing = [for (vmName, index) in approvedVmNames: {
  scope: approvedVms[index]
  name: 'athena-linux-dcr'
}]

resource dataCollectionEndpointAssociations 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' existing = [for (vmName, index) in approvedVmNames: {
  scope: approvedVms[index]
  name: 'configurationAccessEndpoint'
}]

var dceIsValid = toLower(dataCollectionEndpoint.id) == toLower(dataCollectionEndpointResourceId) && toLower(dataCollectionEndpoint.location) == location && dataCollectionEndpoint.properties.provisioningState == 'Succeeded'
var validatedDataCollectionEndpointResourceId = dceIsValid ? dataCollectionEndpoint.id : fail('The adopted data collection endpoint must exist in australiaeast with a Succeeded provisioning state and the exact reviewed resource ID.')

output validatedVmResourceIds array = [for (vmName, index) in approvedVmNames: toLower(approvedVms[index].location) == location && azureMonitorLinuxAgents[index].properties.provisioningState == 'Succeeded' && azureMonitorLinuxAgents[index].properties.publisher == 'Microsoft.Azure.Monitor' && azureMonitorLinuxAgents[index].properties.type == 'AzureMonitorLinuxAgent' && toLower(dataCollectionRuleAssociations[index].properties.dataCollectionRuleId) == toLower(dataCollectionRuleResourceId) && toLower(dataCollectionEndpointAssociations[index].properties.dataCollectionEndpointId) == toLower(validatedDataCollectionEndpointResourceId) ? approvedVms[index].id : fail('Every approved VM must be in australiaeast with a successful AzureMonitorLinuxAgent and exact athena-linux-dcr/configurationAccessEndpoint associations.')]

output coverage object = {
  vmCount: length(approvedVmNames)
  azureMonitorLinuxAgent: 'validated-existing'
  dataCollectionRuleAssociation: 'validated-existing'
  dataCollectionEndpointAssociation: 'validated-existing'
  dataCollectionEndpointResourceId: validatedDataCollectionEndpointResourceId
  dataCollectionEndpointProvisioningState: dataCollectionEndpoint.properties.provisioningState
}
