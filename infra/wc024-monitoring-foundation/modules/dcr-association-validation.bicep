targetScope = 'resourceGroup'

@description('Exactly 11 distinct VM names that have already been approved and have successful Azure Monitor Agent deployment and the adopted DCR association.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Existing DCR resource ID that every adopted DCR-only association must already reference.')
param dataCollectionRuleResourceId string

@description('Existing DCR-only association name on every approved VM. WC-024 validates it without rewriting it.')
@minLength(1)
@maxLength(64)
param dataCollectionRuleAssociationName string = 'athena-linux-dcr'

var normalizedApprovedVmNames = map(approvedVmNames, vmName => toLower(string(vmName)))
var uniqueApprovedVmNames = union(normalizedApprovedVmNames, [])
var validatedApprovedVmNames = length(approvedVmNames) == length(uniqueApprovedVmNames)
  ? approvedVmNames
  : fail('WC-024 requires exactly 11 distinct approved VM names to validate adopted DCR associations.')

resource approvedVms 'Microsoft.Compute/virtualMachines@2025-04-01' existing = [
  for vmName in validatedApprovedVmNames: {
    name: vmName
  }
]

resource adoptedDataCollectionRuleAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' existing = [
  for (vmName, index) in validatedApprovedVmNames: {
    scope: approvedVms[index]
    name: dataCollectionRuleAssociationName
  }
]

@description('Verified existing DCR association IDs. Reading this output requires every association to exist and reference the adopted DCR.')
output validatedAdoptedDataCollectionRuleAssociationResourceIds array = [
  for (vmName, index) in validatedApprovedVmNames: toLower(adoptedDataCollectionRuleAssociation[index].properties.dataCollectionRuleId) == toLower(dataCollectionRuleResourceId)
    ? adoptedDataCollectionRuleAssociation[index].id
    : fail('WC-024 requires every approved VM to retain the existing reviewed DCR association; the association is missing or does not reference the adopted data collection rule.')
]
