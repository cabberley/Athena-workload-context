targetScope = 'subscription'

@description('Exact approved workload resource group.')
param resourceGroupName string

@description('Deterministic custom-role definition GUID.')
param roleDefinitionGuid string

resource workloadResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: resourceGroupName
}

resource signalReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionGuid
  properties: {
    roleName: 'Athena WC016 Approved Signal Reader ${uniqueString(workloadResourceGroup.id)}'
    description: 'Read only VM instance view and Azure Monitor metrics inside the approved WC-016 resource group; runtime code enforces the exact resource allowlist.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.Compute/virtualMachines/instanceView/read'
          'Microsoft.Insights/metrics/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      workloadResourceGroup.id
    ]
  }
}

output roleDefinitionId string = signalReaderRole.id
