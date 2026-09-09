targetScope = 'resourceGroup'

@description('Principal ID of the only identity permitted to read generic monitoring evidence.')
param collectorPrincipalId string

@description('Resource ID of the custom isolated monitoring evidence-reader role.')
param roleDefinitionId string

resource collectorMonitoringRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, collectorPrincipalId, roleDefinitionId)
  properties: {
    principalId: collectorPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}
