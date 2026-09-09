targetScope = 'resourceGroup'

@description('Must remain false until a separately reviewed published-intent reconciliation introduces exact endpoint paths.')
param connectionMonitorDeploymentEnabled bool = false

var validatedConnectionMonitorDeploymentEnabled = connectionMonitorDeploymentEnabled
  ? fail('WC-024 provides Connection Monitor capability only; endpoint definitions require a separately reviewed published-intent reconciliation.')
  : false

output deploymentMode string = validatedConnectionMonitorDeploymentEnabled
  ? 'not-supported'
  : 'capability-only'

output supportedEvidence array = [
  'connectionMonitorResults'
  'effectiveNsgRules'
  'effectiveRoutes'
  'nextHop'
  'ipFlowVerification'
]
