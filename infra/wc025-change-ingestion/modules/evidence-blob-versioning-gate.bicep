targetScope = 'resourceGroup'

@description('Whether the existing default Blob service creates immutable version receipts.')
param isVersioningEnabled bool

var verifiedEvidenceBlobVersioning = isVersioningEnabled == true
  ? true
  : fail('WC-025 requires blobServices/default.properties.isVersioningEnabled to be true for version-pinned replay receipts')

@description('Confirms the existing evidence Blob service is versioning-enabled before workers deploy.')
output versioningVerified bool = verifiedEvidenceBlobVersioning
