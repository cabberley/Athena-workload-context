targetScope = 'resourceGroup'

metadata name = 'WC-013 private presentation web'
metadata description = 'Deploys the digest-pinned presentation image with VNet-scoped HTTPS ingress and a dedicated AcrPull-only identity.'

@description('Azure region for the presentation resources.')
param location string

@description('Prefix used in deterministic presentation resource names.')
@minLength(3)
@maxLength(32)
param namePrefix string

@description('Resource ID of the existing internal Container Apps managed environment.')
param managedEnvironmentResourceId string

@description('Digest-pinned private presentation image.')
@minLength(1)
@maxLength(2048)
param presentationImage string

@description('Azure Container Registry login server hosting the presentation image.')
@minLength(1)
@maxLength(255)
param presentationImageRegistryServer string

@description('Resource ID of the existing Azure Container Registry hosting the presentation image.')
@minLength(1)
@maxLength(2048)
param presentationImageRegistryResourceId string

@description('Resource tags applied to presentation resources.')
param tags object = {}

var presentationName = '${namePrefix}-presentation'
var presentationIdentityName = '${namePrefix}-presentation-id'
var rejectedImageDigestSuffix = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var validatedPresentationImage = contains(presentationImage, '@sha256:') && startsWith(
  toLower(presentationImage),
  '${toLower(presentationImageRegistryServer)}/'
) && !endsWith(toLower(presentationImage), rejectedImageDigestSuffix)
  ? presentationImage
  : fail('presentationImage must be hosted in presentationImageRegistryServer and use a real non-placeholder sha256 digest')
var presentationTags = union(tags, {
  component: 'wc013-presentation-web'
  dataBoundary: 'customer'
  identityBoundary: 'acr-pull-only'
  managedBy: 'bicep'
})

module presentationIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  name: 'wc013-presentation-pull-identity'
  params: {
    name: presentationIdentityName
    location: location
    enableTelemetry: false
    isolationScope: 'Regional'
    tags: union(presentationTags, {
      identityPurpose: 'presentation-acr-pull-only'
    })
  }
}

module presentationImagePull './acr-pull-rbac.bicep' = {
  name: 'wc013-presentation-image-pull'
  scope: resourceGroup(
    split(presentationImageRegistryResourceId, '/')[2],
    split(presentationImageRegistryResourceId, '/')[4]
  )
  params: {
    registryName: last(split(presentationImageRegistryResourceId, '/'))
    identityName: presentationIdentityName
    identityPrincipalId: presentationIdentity.outputs.principalId
  }
}

module presentationApp 'br/public:avm/res/app/container-app:0.23.0' = {
  name: 'wc013-private-presentation-app'
  dependsOn: [
    presentationImagePull
  ]
  params: {
    name: presentationName
    location: location
    environmentResourceId: managedEnvironmentResourceId
    enableTelemetry: false
    activeRevisionsMode: 'Single'
    // External to the app environment, but VNet-scoped because the environment is internal
    // and has publicNetworkAccess disabled. This is required for jumpbox/VNet access.
    ingressExternal: true
    ingressAllowInsecure: false
    ingressTargetPort: 8080
    ingressTransport: 'http'
    traffic: [
      {
        latestRevision: true
        weight: 100
      }
    ]
    managedIdentities: {
      userAssignedResourceIds: [
        presentationIdentity.outputs.resourceId
      ]
    }
    registries: [
      {
        server: presentationImageRegistryServer
        identity: presentationIdentity.outputs.resourceId
      }
    ]
    containers: [
      {
        name: 'athena-presentation-web'
        image: validatedPresentationImage
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
        probes: [
          {
            type: 'Liveness'
            httpGet: {
              path: '/healthz'
              port: 8080
              scheme: 'HTTP'
            }
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 2
            failureThreshold: 3
          }
          {
            type: 'Readiness'
            httpGet: {
              path: '/healthz'
              port: 8080
              scheme: 'HTTP'
            }
            initialDelaySeconds: 2
            periodSeconds: 5
            timeoutSeconds: 2
            failureThreshold: 3
            successThreshold: 1
          }
        ]
      }
    ]
    scaleSettings: {
      minReplicas: 1
      maxReplicas: 1
    }
    tags: presentationTags
  }
}

@description('Name of the private presentation Container App.')
output name string = presentationApp.outputs.name

@description('Resource ID of the private presentation Container App.')
output resourceId string = presentationApp.outputs.resourceId

@description('VNet-scoped presentation FQDN.')
output fqdn string = presentationApp.outputs.fqdn

@description('Fully qualified private HTTPS presentation URL.')
output httpsUrl string = 'https://${presentationApp.outputs.fqdn}'

@description('Resource ID of the presentation AcrPull-only identity.')
output identityResourceId string = presentationIdentity.outputs.resourceId

@description('Client ID of the presentation AcrPull-only identity.')
output identityClientId string = presentationIdentity.outputs.clientId

@description('Principal ID of the presentation AcrPull-only identity.')
output identityPrincipalId string = presentationIdentity.outputs.principalId