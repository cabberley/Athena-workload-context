targetScope = 'resourceGroup'

@description('Principal ID of the only identity permitted to read generic monitoring evidence.')
param collectorPrincipalId string

@description('Exact reviewed workload VM names.')
@minLength(11)
@maxLength(11)
param approvedVmNames array

@description('Existing DCR-only association name on every approved VM.')
@allowed([
  'athena-linux-dcr'
])
param dataCollectionRuleAssociationName string

@description('DCE-only association name on every approved VM.')
@allowed([
  'configurationAccessEndpoint'
])
param dataCollectionEndpointAssociationName string

var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7'
)
var signalReaderRoleDefinitionGuid = '2fda1d90-37da-55d9-8ac3-132fb7bdca5d'
var expectedSignalReaderActions = [
  'microsoft.compute/virtualmachines/instanceview/read'
  'microsoft.insights/metrics/read'
]

resource signalReaderRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: signalReaderRoleDefinitionGuid
  scope: subscription()
}

var signalReaderPermission = signalReaderRoleDefinition.properties.permissions[0]
var actualSignalReaderActions = map(
  signalReaderPermission.actions,
  action => toLower(action)
)
var missingSignalReaderActions = filter(
  expectedSignalReaderActions,
  action => !contains(actualSignalReaderActions, action)
)
var unexpectedSignalReaderActions = filter(
  actualSignalReaderActions,
  action => !contains(expectedSignalReaderActions, action)
)
var signalReaderAssignableScopes = map(
  signalReaderRoleDefinition.properties.assignableScopes,
  assignableScope => toLower(assignableScope)
)
var signalReaderRoleIsExact = length(signalReaderRoleDefinition.properties.permissions) == 1 && empty(missingSignalReaderActions) && empty(unexpectedSignalReaderActions) && empty(signalReaderPermission.notActions) && empty(signalReaderPermission.dataActions) && empty(signalReaderPermission.notDataActions) && contains(signalReaderAssignableScopes, toLower(resourceGroup().id))
var validatedSignalReaderRoleDefinitionId = signalReaderRoleIsExact
  ? signalReaderRoleDefinition.id
  : fail('WC-024 requires the exact existing WC-016 signal-reader role and workload resource-group assignable scope.')

resource approvedVms 'Microsoft.Compute/virtualMachines@2025-04-01' existing = [
  for vmName in approvedVmNames: {
    name: vmName
  }
]

resource adoptedDcrAssociations 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' existing = [
  for (vmName, index) in approvedVmNames: {
    name: dataCollectionRuleAssociationName
    scope: approvedVms[index]
  }
]

resource dceAssociations 'Microsoft.Insights/dataCollectionRuleAssociations@2024-03-11' existing = [
  for (vmName, index) in approvedVmNames: {
    name: dataCollectionEndpointAssociationName
    scope: approvedVms[index]
  }
]

resource collectorVmSignalReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (vmName, index) in approvedVmNames: {
    name: guid(approvedVms[index].id, collectorPrincipalId, signalReaderRoleDefinition.id)
    scope: approvedVms[index]
    properties: {
      principalId: collectorPrincipalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: validatedSignalReaderRoleDefinitionId
    }
  }
]

resource collectorDcrAssociationReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (vmName, index) in approvedVmNames: {
    name: guid(adoptedDcrAssociations[index].id, collectorPrincipalId, readerRoleDefinitionId)
    scope: adoptedDcrAssociations[index]
    properties: {
      principalId: collectorPrincipalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: readerRoleDefinitionId
    }
  }
]

resource collectorDceAssociationReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (vmName, index) in approvedVmNames: {
    name: guid(dceAssociations[index].id, collectorPrincipalId, readerRoleDefinitionId)
    scope: dceAssociations[index]
    properties: {
      principalId: collectorPrincipalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: readerRoleDefinitionId
    }
  }
]

output readerRoleDefinitionId string = readerRoleDefinitionId
output signalReaderRoleDefinitionId string = validatedSignalReaderRoleDefinitionId
output signalReadScopeIds array = map(approvedVms, vm => vm.id)
output resourceReadScopeIds array = concat(
  map(adoptedDcrAssociations, association => association.id),
  map(dceAssociations, association => association.id)
)
