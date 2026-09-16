targetScope = 'subscription'

@description('Canonical Microsoft.App/jobs resource ID to resolve from ARM runtime state.')
param jobResourceId string

@description('Full server-returned Job resource ID from ARM reference(..., Full).')
output runtimeJobResourceId string = reference(
  jobResourceId,
  '2025-01-01',
  'Full'
).id
