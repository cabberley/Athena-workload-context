[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('a6add389-9978-47ac-ab1e-a09212e321d4')]
    [string] $SubscriptionId,

    [Parameter(Mandatory)]
    [switch] $ConnectivityValidated,

    [Parameter(Mandatory)]
    [switch] $DnsValidated,

    [Parameter(Mandatory)]
    [switch] $IngestionValidated
)

$ErrorActionPreference = 'Stop'
$ResourceGroupName = 'rg-athena-demo-monitoring'
$WorkspaceName = 'athena-hackathon-law'
$DataCollectionEndpointName = 'athena-hackathon-linux-dce'
$PrivateLinkScopeNames = @(
    'athena-demo-monitoring-workload-ampls',
    'athena-demo-monitoring-collector-ampls'
)
$WorkspaceResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$DataCollectionEndpointResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$DataCollectionEndpointName"
$ExpectedPrivateEndpointIds = @{
    'athena-demo-monitoring-workload-ampls' = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Network/privateEndpoints/athena-demo-monitoring-workload-ampls-pe"
    'athena-demo-monitoring-collector-ampls' = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Network/privateEndpoints/athena-demo-monitoring-collector-ampls-pe"
}

if (-not ($ConnectivityValidated -and $DnsValidated -and $IngestionValidated)) {
    throw 'Private access requires explicit connectivity, DNS, and ingestion validation.'
}

az account set --subscription $SubscriptionId

$scopeStates = @{}
foreach ($scopeName in $PrivateLinkScopeNames) {
    $scopeResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/privateLinkScopes/$scopeName"
    $scope = az rest `
        --method get `
        --uri "$scopeResourceId?api-version=2021-09-01" `
        --only-show-errors `
        --output json | ConvertFrom-Json
    if (
        $LASTEXITCODE -ne 0 -or
        -not $scope.location -or
        $null -eq $scope.properties.accessModeSettings
    ) {
        throw "Failed to read AMPLS '$scopeName' before private-only update."
    }
    $scopedResources = az rest `
        --method get `
        --uri "$scopeResourceId/scopedResources?api-version=2021-09-01" `
        --only-show-errors `
        --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read AMPLS '$scopeName' scoped resources."
    }
    $actualScopedResourceIds = @(
        $scopedResources.value |
            ForEach-Object { $_.properties.linkedResourceId.ToLowerInvariant() } |
            Sort-Object -Unique
    )
    $expectedScopedResourceIds = @(
        $WorkspaceResourceId.ToLowerInvariant(),
        $DataCollectionEndpointResourceId.ToLowerInvariant()
    ) | Sort-Object
    if (
        $actualScopedResourceIds.Count -ne 2 -or
        (Compare-Object $actualScopedResourceIds $expectedScopedResourceIds)
    ) {
        throw "AMPLS '$scopeName' does not contain the exact reviewed LAW and DCE."
    }
    $privateEndpointConnections = az rest `
        --method get `
        --uri "$scopeResourceId/privateEndpointConnections?api-version=2021-09-01" `
        --only-show-errors `
        --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read AMPLS '$scopeName' private endpoint connections."
    }
    $connections = @($privateEndpointConnections.value)
    if (
        $connections.Count -ne 1 -or
        $connections[0].properties.privateEndpoint.id.ToLowerInvariant() -ne
            $ExpectedPrivateEndpointIds[$scopeName].ToLowerInvariant() -or
        $connections[0].properties.privateLinkServiceConnectionState.status -ne
            'Approved'
    ) {
        throw "AMPLS '$scopeName' does not contain the exact approved private endpoint."
    }
    $exclusions = @()
    if ($null -ne $scope.properties.accessModeSettings.exclusions) {
        $exclusions = @($scope.properties.accessModeSettings.exclusions)
    }
    if ($exclusions.Count -ne 0) {
        throw "AMPLS '$scopeName' has access-mode exclusions; private cutover requires an empty exclusion set."
    }
    $scopeStates[$scopeName] = $scope
}

foreach ($scopeName in $PrivateLinkScopeNames) {
    $scopeResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/privateLinkScopes/$scopeName"
    $scope = $scopeStates[$scopeName]
    $exclusions = @()
    if ($null -ne $scope.properties.accessModeSettings.exclusions) {
        $exclusions = @($scope.properties.accessModeSettings.exclusions)
    }
    $expectedTags = $scope.tags | ConvertTo-Json -Depth 20 -Compress
    $expectedExclusions = $exclusions | ConvertTo-Json -Depth 20 -Compress
    $body = @{
        location = $scope.location
        tags = $scope.tags
        properties = @{
            accessModeSettings = @{
                exclusions = $exclusions
                queryAccessMode = 'PrivateOnly'
                ingestionAccessMode = 'PrivateOnly'
            }
        }
    } | ConvertTo-Json -Depth 20 -Compress
    az rest `
        --method put `
        --uri "$scopeResourceId?api-version=2021-09-01" `
        --body $body `
        --only-show-errors `
        --output none
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set AMPLS '$scopeName' private-only access."
    }
    $updatedScope = az rest `
        --method get `
        --uri "$scopeResourceId?api-version=2021-09-01" `
        --only-show-errors `
        --output json | ConvertFrom-Json
    $updatedTags = $updatedScope.tags | ConvertTo-Json -Depth 20 -Compress
    $updatedExclusionsArray = @()
    if ($null -ne $updatedScope.properties.accessModeSettings.exclusions) {
        $updatedExclusionsArray = @(
            $updatedScope.properties.accessModeSettings.exclusions
        )
    }
    $updatedExclusions = $updatedExclusionsArray |
        ConvertTo-Json -Depth 20 -Compress
    if (
        $updatedScope.properties.accessModeSettings.queryAccessMode -ne 'PrivateOnly' -or
        $updatedScope.properties.accessModeSettings.ingestionAccessMode -ne 'PrivateOnly' -or
        $updatedTags -ne $expectedTags -or
        $updatedExclusions -ne $expectedExclusions
    ) {
        throw "AMPLS '$scopeName' update changed unexpected state."
    }
}

az monitor data-collection endpoint update `
    --subscription $SubscriptionId `
    --resource-group $ResourceGroupName `
    --name $DataCollectionEndpointName `
    --public-network-access Disabled `
    --only-show-errors `
    --output none
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to disable DCE public access.'
}

az monitor log-analytics workspace update `
    --subscription $SubscriptionId `
    --resource-group $ResourceGroupName `
    --workspace-name $WorkspaceName `
    --ingestion-access Disabled `
    --query-access Disabled `
    --only-show-errors `
    --output none
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to disable Log Analytics public access.'
}

$workspace = az monitor log-analytics workspace show `
    --subscription $SubscriptionId `
    --resource-group $ResourceGroupName `
    --workspace-name $WorkspaceName `
    --query '{ingestion:publicNetworkAccessForIngestion,query:publicNetworkAccessForQuery}' `
    --output json | ConvertFrom-Json
$endpoint = az monitor data-collection endpoint show `
    --subscription $SubscriptionId `
    --resource-group $ResourceGroupName `
    --name $DataCollectionEndpointName `
    --query 'networkAcls.publicNetworkAccess' `
    --output tsv
if (
    $workspace.ingestion -ne 'Disabled' -or
    $workspace.query -ne 'Disabled' -or
    $endpoint -ne 'Disabled'
) {
    throw 'Private access verification failed after update.'
}
