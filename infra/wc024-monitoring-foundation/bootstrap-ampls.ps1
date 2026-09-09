[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('a6add389-9978-47ac-ab1e-a09212e321d4')]
    [string] $SubscriptionId,

    [Parameter()]
    [ValidateSet('rg-athena-demo-monitoring')]
    [string] $ResourceGroupName = 'rg-athena-demo-monitoring'
)

$ErrorActionPreference = 'Stop'
$scopeNames = @(
    'athena-demo-monitoring-workload-ampls',
    'athena-demo-monitoring-collector-ampls'
)

az account set --subscription $SubscriptionId
foreach ($scopeName in $scopeNames) {
    $resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/privateLinkScopes/$scopeName"
    $lookup = az resource show `
        --ids $resourceId `
        --api-version 2021-09-01 `
        --only-show-errors 2>&1
    if ($LASTEXITCODE -eq 0) {
        $existing = $lookup | ConvertFrom-Json
        if (
            $existing.properties.accessModeSettings.queryAccessMode -ne 'Open' -or
            $existing.properties.accessModeSettings.ingestionAccessMode -ne 'Open' -or
            @($existing.properties.accessModeSettings.exclusions).Count -ne 0 -or
            $existing.tags.component -ne 'wc024-monitoring-data-platform' -or
            $existing.tags.dataBoundary -ne 'customer' -or
            $existing.tags.lifecycle -ne 'one-time-bootstrap'
        ) {
            throw "AMPLS '$scopeName' already exists with non-bootstrap access settings."
        }
        $scopedResources = az rest `
            --method get `
            --uri "$resourceId/scopedResources?api-version=2021-09-01" `
            --only-show-errors `
            --output json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or @($scopedResources.value).Count -ne 0) {
            throw "AMPLS '$scopeName' already has scoped resources; bootstrap cannot adopt it."
        }
        $privateEndpointConnections = az rest `
            --method get `
            --uri "$resourceId/privateEndpointConnections?api-version=2021-09-01" `
            --only-show-errors `
            --output json | ConvertFrom-Json
        if (
            $LASTEXITCODE -ne 0 -or
            @($privateEndpointConnections.value).Count -ne 0
        ) {
            throw "AMPLS '$scopeName' already has private endpoint connections; bootstrap cannot adopt it."
        }
        continue
    }
    if ($LASTEXITCODE -ne 3 -or ($lookup -join "`n") -notmatch 'Code:\s+ResourceNotFound') {
        throw "AMPLS existence check failed closed for '$scopeName'."
    }

    az deployment group create `
        --subscription $SubscriptionId `
        --resource-group $ResourceGroupName `
        --name "wc024-ampls-bootstrap-$scopeName" `
        --template-file (Join-Path $PSScriptRoot 'bootstrap-ampls.bicep') `
        --parameters privateLinkScopeName=$scopeName `
        --only-show-errors
    if ($LASTEXITCODE -ne 0) {
        throw "WC-024 AMPLS bootstrap failed for '$scopeName'."
    }
}
