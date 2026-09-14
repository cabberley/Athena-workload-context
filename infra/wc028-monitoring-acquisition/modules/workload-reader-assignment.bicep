targetScope = 'resourceGroup'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param collectorPrincipalId string

@description('Subscription-level custom role with only Activity Log and Resource Graph read operations.')
param roleDefinitionId string

resource collectorBoundedAcquisitionReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, collectorPrincipalId, roleDefinitionId)
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

output roleAssignmentResourceId string = collectorBoundedAcquisitionReader.id
