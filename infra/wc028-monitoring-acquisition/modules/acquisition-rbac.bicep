targetScope = 'subscription'

@description('Principal ID of the reused WC-024 monitoring collector identity.')
param collectorPrincipalId string

@description('Exact workload resource group whose Activity Log and Resource Graph change history may be read.')
param workloadResourceGroupResourceId string

@description('Existing WC-025 change-evidence storage account resource ID.')
param changeEvidenceStorageAccountResourceId string

@description('Existing WC-025 change-evidence container resource ID.')
param changeEvidenceContainerResourceId string

var subscriptionPrefix = toLower('/subscriptions/${subscription().subscriptionId}/')
var workloadSegments = split(toLower(workloadResourceGroupResourceId), '/')
var workloadResourceGroupName = length(workloadSegments) == 5 && startsWith(
  toLower(workloadResourceGroupResourceId),
  '${subscriptionPrefix}resourcegroups/'
) && !empty(workloadSegments[4])
  ? workloadSegments[4]
  : fail('workloadResourceGroupResourceId must be one resource group in the deployment subscription')
var changeStorageSegments = split(toLower(changeEvidenceStorageAccountResourceId), '/')
var changeStorageResourceGroupName = length(changeStorageSegments) == 9 && startsWith(
  toLower(changeEvidenceStorageAccountResourceId),
  '${subscriptionPrefix}resourcegroups/'
) && changeStorageSegments[5] == 'providers' && changeStorageSegments[6] == 'microsoft.storage' && changeStorageSegments[7] == 'storageaccounts' && !empty(changeStorageSegments[8])
  ? changeStorageSegments[4]
  : fail('changeEvidenceStorageAccountResourceId must be one storage account in the deployment subscription')
var changeStorageAccountName = changeStorageSegments[8]

resource workloadResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: workloadResourceGroupName
}

resource changeStorageResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: changeStorageResourceGroupName
}

resource changeEvidenceStorage 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: changeStorageAccountName
  scope: changeStorageResourceGroup
}

resource changeEvidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' existing = {
  parent: changeEvidenceStorage
  name: 'default'
}

resource changeEvidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' existing = {
  parent: changeEvidenceBlobService
  name: 'change-evidence'
}

var validatedWorkloadResourceGroupId = toLower(workloadResourceGroup.id) == toLower(
  workloadResourceGroupResourceId
)
  ? workloadResourceGroup.id
  : fail('workloadResourceGroupResourceId does not resolve to the reviewed resource group')
var validatedChangeEvidenceContainerResourceId = toLower(
  changeEvidenceStorage.id
) == toLower(changeEvidenceStorageAccountResourceId) && toLower(
  changeEvidenceContainer.id
) == toLower(changeEvidenceContainerResourceId) && changeEvidenceBlobService.properties.isVersioningEnabled == true
  ? changeEvidenceContainer.id
  : fail('change evidence storage bindings must resolve to the versioned WC-025 container')

resource boundedAcquisitionReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-bounded-acquisition-reader',
    validatedWorkloadResourceGroupId
  )
  properties: {
    roleName: 'Athena WC028 Bounded Acquisition Reader'
    description: 'Read only Activity Log events and Resource Graph change history for the one approved workload resource group.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.Insights/eventtypes/values/read'
          'Microsoft.ResourceGraph/resources/read'
          'Microsoft.Resources/changes/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      validatedWorkloadResourceGroupId
    ]
  }
}

resource createOnlyChangeEvidenceRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(
    subscription().id,
    'athena-wc028-change-evidence-create-only',
    toLower(changeEvidenceContainerResourceId)
  )
  properties: {
    roleName: 'Athena WC028 Change Evidence Create-Only Writer'
    description: 'Read one known Blob and create one conditionally named change-evidence Blob without list or delete permissions.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        ]
        notDataActions: []
      }
    ]
    assignableScopes: [
      changeStorageResourceGroup.id
    ]
  }
}

module collectorBoundedAcquisitionReader 'workload-reader-assignment.bicep' = {
  name: 'wc028-workload-reader-assignment'
  scope: workloadResourceGroup
  params: {
    collectorPrincipalId: collectorPrincipalId
    roleDefinitionId: boundedAcquisitionReaderRole.id
  }
}

module collectorChangeEvidenceWriter 'change-evidence-writer-assignment.bicep' = {
  name: 'wc028-change-evidence-writer-assignment'
  scope: changeStorageResourceGroup
  params: {
    principalId: collectorPrincipalId
    roleDefinitionId: createOnlyChangeEvidenceRole.id
    storageAccountName: changeEvidenceStorage.name
    expectedContainerResourceId: validatedChangeEvidenceContainerResourceId
  }
}

output boundedAcquisitionReaderRoleDefinitionId string = boundedAcquisitionReaderRole.id
output createOnlyChangeEvidenceRoleDefinitionId string = createOnlyChangeEvidenceRole.id
