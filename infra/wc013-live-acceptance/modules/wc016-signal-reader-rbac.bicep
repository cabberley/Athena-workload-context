targetScope = 'resourceGroup'

@description('Dedicated WC-016 detector identity principal ID.')
param detectorPrincipalId string

@description('Dedicated WC-016 orchestrator identity principal ID.')
param orchestratorPrincipalId string

@description('Resource ID of the narrow WC-016 signal-reader custom role.')
param roleDefinitionId string

resource detectorSignalRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, detectorPrincipalId, roleDefinitionId)
  properties: {
    principalId: detectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}

resource orchestratorSignalRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, orchestratorPrincipalId, roleDefinitionId)
  properties: {
    principalId: orchestratorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}
