targetScope = 'subscription'

extension microsoftGraphV1

@description('Tenant that owns the single-tenant monitoring identity-proof API.')
param tenantId string

@description('Collector managed-identity principal receiving the one proof app role.')
param collectorPrincipalId string

var applicationUniqueName = 'athena-wc028-monitoring-identity-proof'
var applicationDisplayName = 'Athena WC-028 monitoring identity proof'
var identityProofAudience = 'api://${toLower(tenantId)}/athena-monitoring-identity-proof'
var identityProofAppRoleId = guid(
  tenantId,
  'athena-wc028-monitoring-identity-proof',
  'Athena.MonitoringAcquisition.ProveIdentity'
)
var identityProofRoleValue = 'Athena.MonitoringAcquisition.ProveIdentity'

resource identityProofApplication 'Microsoft.Graph/applications@v1.0' = {
  displayName: applicationDisplayName
  uniqueName: applicationUniqueName
  signInAudience: 'AzureADMyOrg'
  identifierUris: [
    identityProofAudience
  ]
  api: {
    requestedAccessTokenVersion: 1
    oauth2PermissionScopes: []
  }
  optionalClaims: {
    accessToken: [
      {
        name: 'idtyp'
        essential: true
        additionalProperties: []
      }
    ]
  }
  appRoles: [
    {
      id: identityProofAppRoleId
      displayName: 'Prove monitoring acquisition identity'
      description: 'Emit one app-only role claim proving the exact WC-028 monitoring collector managed identity before Azure evidence reads.'
      value: identityProofRoleValue
      allowedMemberTypes: [
        'Application'
      ]
      isEnabled: true
    }
  ]
}

resource identityProofServicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: identityProofApplication.appId
  displayName: applicationDisplayName
  accountEnabled: true
  appRoleAssignmentRequired: true
  tags: [
    'WindowsAzureActiveDirectoryIntegratedApp'
  ]
}

resource collectorIdentityProofRoleAssignment 'Microsoft.Graph/appRoleAssignedTo@v1.0' = {
  appRoleId: identityProofAppRoleId
  principalId: collectorPrincipalId
  resourceDisplayName: applicationDisplayName
  resourceId: identityProofServicePrincipal.id
}

output identityProofAudience string = identityProofAudience
output identityProofApplicationId string = identityProofApplication.appId
output identityProofApplicationObjectId string = identityProofApplication.id
output identityProofServicePrincipalId string = identityProofServicePrincipal.id
output identityProofAppRoleId string = identityProofAppRoleId
output identityProofAppRoleValue string = identityProofRoleValue
output identityProofAppRoleAssignmentId string = collectorIdentityProofRoleAssignment.id
output identityProofAssignedPrincipalId string = collectorPrincipalId
