targetScope = 'resourceGroup'

metadata name = 'WC-013 private presentation web'
metadata description = 'Deploys the digest-pinned presentation web and private Blob gateway sidecar with VNet-scoped HTTPS ingress and a dedicated presentation identity.'

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

@description('Digest-pinned WC-013 delivery image used by the presentation asset gateway sidecar.')
@minLength(1)
@maxLength(2048)
param deliveryImage string

@description('Private HTTPS Blob endpoint containing the presentation-assets container.')
@minLength(12)
@maxLength(2048)
param presentationAssetBlobEndpoint string

@description('Exact private Blob container read by the presentation sidecar.')
@allowed([
  'presentation-assets'
])
param presentationAssetContainerName string

@description('Resource tags applied to presentation resources.')
param tags object = {}

var presentationName = '${namePrefix}-presentation'
var presentationIdentityName = '${namePrefix}-presentation-id'
var rejectedImageDigestSuffix = '@sha256:0000000000000000000000000000000000000000000000000000000000000000'
var expectedPresentationImageRegistryServer = '${toLower(last(split(presentationImageRegistryResourceId, '/')))}.azurecr.io'
var validatedPresentationImageRegistryServer = presentationImageRegistryServer == toLower(presentationImageRegistryServer) && presentationImageRegistryServer == expectedPresentationImageRegistryServer
  ? presentationImageRegistryServer
  : fail('presentationImageRegistryServer must exactly match the supplied Azure Container Registry resource ID')
var presentationImageRepositoryPrefix = '${validatedPresentationImageRegistryServer}/athena/presentation-web@sha256:'
var presentationImageDigestCandidate = replace(presentationImage, presentationImageRepositoryPrefix, '')
var presentationImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  presentationImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var presentationImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  presentationImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedPresentationImage = presentationImage == toLower(presentationImage) && startsWith(
  presentationImage,
  presentationImageRepositoryPrefix
) && length(presentationImage) == length(presentationImageRepositoryPrefix) + 64 && length(
  presentationImageDigestCandidate
) == 64 && empty(
  presentationImageDigestInvalidCharacters
) && !endsWith(presentationImage, rejectedImageDigestSuffix)
  ? presentationImage
  : fail('presentationImage must use the exact presentationImageRegistryServer/athena/presentation-web repository and a real 64-character lowercase sha256 digest')
var deliveryImageRepositoryPrefix = '${validatedPresentationImageRegistryServer}/athena/wc013-live@sha256:'
var deliveryImageDigestCandidate = replace(deliveryImage, deliveryImageRepositoryPrefix, '')
var deliveryImageDigestWithoutDigits = replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
  deliveryImageDigestCandidate,
  '0',
  ''
), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')
var deliveryImageDigestInvalidCharacters = replace(replace(replace(replace(replace(replace(
  deliveryImageDigestWithoutDigits,
  'a',
  ''
), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '')
var validatedDeliveryImage = deliveryImage == toLower(deliveryImage) && startsWith(
  deliveryImage,
  deliveryImageRepositoryPrefix
) && length(deliveryImage) == length(deliveryImageRepositoryPrefix) + 64 && length(
  deliveryImageDigestCandidate
) == 64 && empty(
  deliveryImageDigestInvalidCharacters
) && !endsWith(deliveryImage, rejectedImageDigestSuffix)
  ? deliveryImage
  : fail('deliveryImage must use the exact presentationImageRegistryServer/athena/wc013-live repository and a real 64-character lowercase sha256 digest')
var presentationTags = union(tags, {
  component: 'wc013-presentation-web'
  dataBoundary: 'customer'
  identityBoundary: 'acr-pull-and-presentation-assets-reader-only'
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
      identityPurpose: 'presentation-acr-pull-and-private-assets-reader'
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
      {
        name: 'athena-presentation-asset-gateway'
        image: validatedDeliveryImage
        command: [
          'athena-context'
        ]
        args: [
          'presentation-asset-gateway'
          '--blob-endpoint'
          presentationAssetBlobEndpoint
          '--container'
          presentationAssetContainerName
          '--managed-identity-client-id'
          presentationIdentity.outputs.clientId
          '--port'
          '8081'
        ]
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: presentationIdentity.outputs.clientId
          }
        ]
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
        probes: [
          {
            type: 'Liveness'
            httpGet: {
              path: '/healthz'
              port: 8081
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
              port: 8081
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

@description('Resource ID of the presentation AcrPull and presentation-assets Reader identity.')
output identityResourceId string = presentationIdentity.outputs.resourceId

@description('Client ID of the presentation AcrPull and presentation-assets Reader identity.')
output identityClientId string = presentationIdentity.outputs.clientId

@description('Principal ID of the presentation AcrPull and presentation-assets Reader identity.')
output identityPrincipalId string = presentationIdentity.outputs.principalId