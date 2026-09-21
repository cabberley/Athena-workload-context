targetScope = 'resourceGroup'

@description('Reviewer attestation schema version.')
@allowed([
  'athena.wc028MonitoringEffectiveRbacInventoryAttestation.v2'
])
param attestationSchemaVersion string

@description('Reviewer signature algorithm.')
@allowed([
  'RS256'
])
param signatureAlgorithm string

@description('Exact phase-one bootstrap handoff identifier covered by review.')
param bootstrapHandoffId string

@description('Exact phase-one subscription deployment resource ID covered by review.')
param bootstrapDeploymentId string

@description('Server-computed phase-one template hash covered by review.')
param bootstrapTemplateHash string

@description('Deterministic binding ID of the complete phase-one collectorContractInputs object.')
param bootstrapContractInputsBindingId string

@description('Inventory-attested UAMI with only keys/get on the exact versioned reviewer key.')
param verifierIdentityResourceId string

@description('Separately governed reviewer principal.')
param reviewerPrincipalId string

@description('Runtime-support principal that must remain separate from the reviewer.')
param runtimeSupportIdentityPrincipalId string

@description('Exact versioned reviewer key identifier.')
param reviewerKeyId string

@description('Canonical unpadded RFC 7518 Base64urlUInt RSA modulus for the reviewer public key. Allowed modulus sizes are 2048, 3072, and 4096 bits.')
@minLength(342)
@maxLength(1024)
param publicKeyModulus string

@description('Canonical unpadded RFC 7518 Base64urlUInt exponent. AQAB is the minimal encoding of 65537.')
@allowed([
  'AQAB'
])
param publicKeyExponent string

@description('SHA-256 SPKI fingerprint of the reviewer public key.')
@minLength(71)
@maxLength(71)
param publicKeyFingerprint string

@description('Canonical digest claimed by the reviewed effective-RBAC inventory.')
@minLength(71)
@maxLength(71)
param inventoryDigest string

@description('Immutable source-manifest digest claimed by the reviewed inventory.')
@minLength(71)
@maxLength(71)
param sourceManifestDigest string

@description('Exact cleanup-evidence schema covered by review.')
@allowed([
  'athena.wc028LegacyCollectorRbacCleanup.v3'
])
param legacyCollectorRbacCleanupSchemaVersion string

@description('Non-zero cleanup-evidence digest covered by review.')
@minLength(71)
@maxLength(71)
param legacyCollectorRbacCleanupDigest string

@description('Digest of the exact reviewer-signature preimage.')
@minLength(71)
@maxLength(71)
param signedPreimageDigest string

@description('Detached standard-base64 reviewer signature.')
@minLength(1)
@maxLength(2048)
param signature string

@description('Compact JSON for the complete effective-RBAC inventory.')
@minLength(1)
@maxLength(62000)
param effectiveRbacInventoryJson string

var verifierSourceBase64 = base64(loadTextContent('../scripts/verify-rbac-inventory-attestation.py'))
var callerEnvironmentPayload = join([
  'ATHENA_ATTESTATION_SCHEMA_VERSION=${attestationSchemaVersion}'
  'ATHENA_SIGNATURE_ALGORITHM=${signatureAlgorithm}'
  'ATHENA_BOOTSTRAP_HANDOFF_ID=${bootstrapHandoffId}'
  'ATHENA_BOOTSTRAP_DEPLOYMENT_ID=${bootstrapDeploymentId}'
  'ATHENA_BOOTSTRAP_TEMPLATE_HASH=${bootstrapTemplateHash}'
  'ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID=${bootstrapContractInputsBindingId}'
  'ATHENA_REVIEWER_PRINCIPAL_ID=${reviewerPrincipalId}'
  'ATHENA_RUNTIME_SUPPORT_PRINCIPAL_ID=${runtimeSupportIdentityPrincipalId}'
  'ATHENA_REVIEWER_KEY_ID=${reviewerKeyId}'
  'ATHENA_PUBLIC_KEY_MODULUS=${publicKeyModulus}'
  'ATHENA_PUBLIC_KEY_EXPONENT=${publicKeyExponent}'
  'ATHENA_PUBLIC_KEY_FINGERPRINT=${publicKeyFingerprint}'
  'ATHENA_INVENTORY_DIGEST=${inventoryDigest}'
  'ATHENA_SOURCE_MANIFEST_DIGEST=${sourceManifestDigest}'
  'ATHENA_LEGACY_RBAC_CLEANUP_SCHEMA_VERSION=${legacyCollectorRbacCleanupSchemaVersion}'
  'ATHENA_LEGACY_RBAC_CLEANUP_DIGEST=${legacyCollectorRbacCleanupDigest}'
  'ATHENA_SIGNED_PREIMAGE_DIGEST=${signedPreimageDigest}'
  'ATHENA_SIGNATURE=${signature}'
  'ATHENA_INVENTORY_JSON=${effectiveRbacInventoryJson}'
], '\n')
var validatedEffectiveRbacInventoryJson = length(callerEnvironmentPayload) <= 64000
  ? effectiveRbacInventoryJson
  : fail('monitoring RBAC attestation verification limits caller-supplied environment data to 64,000 characters')

resource attestationVerifier 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'verify-monitoring-rbac-${substring(signedPreimageDigest, 7, 12)}'
  location: resourceGroup().location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${verifierIdentityResourceId}': {}
    }
  }
  properties: {
    azCliVersion: '2.88.0'
    cleanupPreference: 'Always'
    environmentVariables: [
      {
        name: 'ATHENA_ATTESTATION_SCHEMA_VERSION'
        value: attestationSchemaVersion
      }
      {
        name: 'ATHENA_SIGNATURE_ALGORITHM'
        value: signatureAlgorithm
      }
      {
        name: 'ATHENA_BOOTSTRAP_HANDOFF_ID'
        value: bootstrapHandoffId
      }
      {
        name: 'ATHENA_BOOTSTRAP_DEPLOYMENT_ID'
        value: bootstrapDeploymentId
      }
      {
        name: 'ATHENA_BOOTSTRAP_TEMPLATE_HASH'
        value: bootstrapTemplateHash
      }
      {
        name: 'ATHENA_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID'
        value: bootstrapContractInputsBindingId
      }
      {
        name: 'ATHENA_REVIEWER_PRINCIPAL_ID'
        value: reviewerPrincipalId
      }
      {
        name: 'ATHENA_RUNTIME_SUPPORT_PRINCIPAL_ID'
        value: runtimeSupportIdentityPrincipalId
      }
      {
        name: 'ATHENA_REVIEWER_KEY_ID'
        value: reviewerKeyId
      }
      {
        name: 'ATHENA_PUBLIC_KEY_MODULUS'
        value: publicKeyModulus
      }
      {
        name: 'ATHENA_PUBLIC_KEY_EXPONENT'
        value: publicKeyExponent
      }
      {
        name: 'ATHENA_PUBLIC_KEY_FINGERPRINT'
        value: publicKeyFingerprint
      }
      {
        name: 'ATHENA_INVENTORY_DIGEST'
        value: inventoryDigest
      }
      {
        name: 'ATHENA_SOURCE_MANIFEST_DIGEST'
        value: sourceManifestDigest
      }
      {
        name: 'ATHENA_LEGACY_RBAC_CLEANUP_SCHEMA_VERSION'
        value: legacyCollectorRbacCleanupSchemaVersion
      }
      {
        name: 'ATHENA_LEGACY_RBAC_CLEANUP_DIGEST'
        value: legacyCollectorRbacCleanupDigest
      }
      {
        name: 'ATHENA_SIGNED_PREIMAGE_DIGEST'
        value: signedPreimageDigest
      }
      {
        name: 'ATHENA_SIGNATURE'
        value: signature
      }
      {
        name: 'ATHENA_INVENTORY_JSON'
        value: validatedEffectiveRbacInventoryJson
      }
    ]
    forceUpdateTag: signedPreimageDigest
    retentionInterval: 'PT1H'
    // Azure CLI 2.88.0 transforms Key Vault JWK bytes to standard Base64 before applying --query.
    scriptContent: format(
      'set -euo pipefail\nexport ATHENA_REVIEWER_JWK_JSON="$(az keyvault key show --id "$ATHENA_REVIEWER_KEY_ID" --query \'{{kid:key.kid,kty:key.kty,key_ops:key.keyOps,n:key.n,e:key.e}}\' --output json --only-show-errors)"\nprintf \'%s\' \'{0}\' | base64 --decode > /tmp/verify-rbac-inventory-attestation.py\npython3 /tmp/verify-rbac-inventory-attestation.py',
      verifierSourceBase64
    )
    timeout: 'PT5M'
  }
}

output validated bool = attestationVerifier.properties.outputs.validated
output inventoryDigest string = attestationVerifier.properties.outputs.inventoryDigest
output signedPreimageDigest string = attestationVerifier.properties.outputs.signedPreimageDigest
output validationDigest string = attestationVerifier.properties.outputs.validationDigest
