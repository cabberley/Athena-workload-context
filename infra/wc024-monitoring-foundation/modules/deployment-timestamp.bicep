targetScope = 'subscription'

@description('Server-evaluated deployment timestamp. Parent modules deliberately omit this parameter so callers cannot override it.')
param deploymentTimestamp string = utcNow('u')

output deploymentTimestamp string = deploymentTimestamp
