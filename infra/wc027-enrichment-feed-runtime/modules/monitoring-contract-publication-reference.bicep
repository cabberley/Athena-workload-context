targetScope = 'subscription'

@description('Exact successful WC-024 phase-two subscription deployment.')
param deploymentName string

@description('Server-computed template hash of the reviewed phase-two publication deployment.')
param expectedTemplateHash string

#disable-next-line no-deployments-resources
resource publicationDeployment 'Microsoft.Resources/deployments@2025-04-01' existing = {
  name: deploymentName
}

var validatedPublicationDeployment = publicationDeployment.properties.provisioningState == 'Succeeded' && publicationDeployment.properties.templateHash == expectedTemplateHash
  ? publicationDeployment
  : fail('WC-027 requires the exact successful subscription-scoped WC-024 publication deployment and reviewed template hash.')

output sourceDeploymentId string = validatedPublicationDeployment.id
output sourceTemplateHash string = validatedPublicationDeployment.properties.templateHash
output monitoringAcquisitionCollectorContract object = validatedPublicationDeployment.properties.outputs.monitoringAcquisitionCollectorContract.value
output monitoringContractPublicationHandoff object = validatedPublicationDeployment.properties.outputs.monitoringContractPublicationHandoff.value
