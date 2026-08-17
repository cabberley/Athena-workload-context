using './main.bicep'

param location = 'australiaeast'
param resourceGroupName = 'athena-synth-mcp-rg'
param namePrefix = 'athena-synth-dev'

// Replace with the client ID of a reviewed Entra application before deployment.
param entraApplicationClientId = '11111111-1111-1111-1111-111111111111'

// Deliberately deny workload and log access until each target scope is reviewed.
param workloadReadScopes = []
param approvedLogWorkspaces = []
