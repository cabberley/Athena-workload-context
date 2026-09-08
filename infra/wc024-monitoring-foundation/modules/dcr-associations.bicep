targetScope = 'resourceGroup'

@description('Exactly 11 distinct VM names that have already been approved and have successful Azure Monitor Agent deployment and the adopted DCR association.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Existing private DCE resource ID used by AMA for monitoring ingestion.')
param dataCollectionEndpointResourceId string

@description('Actual region of the adopted DCE. Every approved VM must be in this region for configuration access.')
param dataCollectionEndpointLocation string

@description('Separate DCE-only association created on every approved VM.')
@allowed([
  'configurationAccessEndpoint'
])
param dataCollectionEndpointAssociationName string = 'configurationAccessEndpoint'

@description('Read-only validation results for the existing DCR-only association on every approved VM. This module will not create a DCE association unless every result is present.')
@minLength(11)
@maxLength(11)
param validatedDataCollectionRuleAssociationResourceIds array

var normalizedApprovedVmNames = map(approvedVmNames, vmName => toLower(string(vmName)))
var uniqueApprovedVmNames = union(normalizedApprovedVmNames, [])
var validatedApprovedVmNames = length(approvedVmNames) == length(uniqueApprovedVmNames)
  ? approvedVmNames
  : fail('WC-024 requires exactly 11 distinct approved VM names to avoid duplicate DCR associations.')
var validatedDcrAssociationIds = length(validatedDataCollectionRuleAssociationResourceIds) == length(validatedApprovedVmNames)
  ? validatedDataCollectionRuleAssociationResourceIds
  : fail('WC-024 requires successful validation of every adopted DCR association before creating any DCE association.')

resource approvedVms 'Microsoft.Compute/virtualMachines@2025-04-01' existing = [
  for vmName in validatedApprovedVmNames: {
    name: vmName
  }
]

resource configurationAccessEndpointAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' = [
  for (vmName, index) in validatedApprovedVmNames: {
    scope: approvedVms[index]
    name: dataCollectionEndpointAssociationName
    properties: {
      dataCollectionEndpointId: !empty(validatedDcrAssociationIds[index]) && toLower(approvedVms[index].location) == toLower(dataCollectionEndpointLocation)
        ? dataCollectionEndpointResourceId
        : fail('Every approved VM must pass the prerequisite adopted DCR association validation and use the adopted DCE region before any DCE association is created.')
    }
  }
]

output dataCollectionEndpointAssociationResourceIds array = [
  for (_, index) in validatedApprovedVmNames: configurationAccessEndpointAssociation[index].id
]
