[CmdletBinding()]
param(
    [ValidateSet('a6add389-9978-47ac-ab1e-a09212e321d4')]
    [string] $SubscriptionId = 'a6add389-9978-47ac-ab1e-a09212e321d4',

    [switch] $RequireDependencyAgent,
    [switch] $RequireConnectionMonitorAgent,
    [switch] $RequireChangeEventRoute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AzJson {
    param([Parameter(Mandatory)][string[]] $AzArguments)

    $raw = & az @AzArguments --subscription $SubscriptionId --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI read failed: az $($AzArguments -join ' ')"
    }
    return $raw | ConvertFrom-Json
}

function Assert-Ready {
    param([Parameter(Mandatory)][bool] $Condition, [Parameter(Mandatory)][string] $Message)
    if (-not $Condition) {
        throw $Message
    }
}

$workloadRg = 'rg-athena-demo-workload'
$monitoringRg = 'rg-athena-demo-monitoring'
$approvedVmNames = @(
    'athena-hackathon-client-01',
    'athena-hackathon-ecp-01',
    'athena-hackathon-ecp-02',
    'athena-hackathon-ecp-03',
    'athena-hackathon-iris-01',
    'athena-hackathon-mid-01',
    'athena-hackathon-mid-02',
    'athena-hackathon-sqlvm-01',
    'athena-hackathon-web-01',
    'athena-hackathon-web-02',
    'athena-hackathon-web-03'
)
$expectedDcrId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.Insights/dataCollectionRules/athena-hackathon-linux-dcr"
$expectedDceId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.Insights/dataCollectionEndpoints/athena-hackathon-linux-dce"
$expectedWorkspaceId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.OperationalInsights/workspaces/athena-hackathon-law"
$expectedVnetId = "/subscriptions/$SubscriptionId/resourceGroups/$workloadRg/providers/Microsoft.Network/virtualNetworks/athena-hackathon-vnet"
$replacementStorageId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.Storage/storageAccounts/athenademomonchab01"
$legacyStorageId = "/subscriptions/$SubscriptionId/resourceGroups/$workloadRg/providers/Microsoft.Storage/storageAccounts/athenahackathonflowwhtco"
$expectedLegacyFlowLogNames = @(
    'snet-data-rg-athena-demo-workload-flowlog',
    'athena-hackathon-web-03-nic-rg-athena-demo-workload-flowlog',
    'athena-hackathon-ecp-01-nic-rg-athena-demo-workload-flowlog',
    'athena-hackathon-web-01-nic-rg-athena-demo-workload-flowlog',
    'snet-management-rg-athena-demo-workload-flowlog',
    'athena-hackathon-ecp-02-nic-rg-athena-demo-workload-flowlog',
    'snet-client-rg-athena-demo-workload-flowlog',
    'athena-hackathon-iris-01-nic-rg-athena-demo-workload-flowlog',
    'snet-middle-rg-athena-demo-workload-flowlog',
    'athena-hackathon-mid-01-nic-rg-athena-demo-workload-flowlog',
    'athena-hackathon-sqlvm-01-nic-rg-athena-demo-workload-flowlog',
    'athena-hackathon-mid-02-nic-rg-athena-demo-workload-flowlog',
    'snet-web-rg-athena-demo-workload-flowlog',
    'athena-hackathon-web-02-nic-rg-athena-demo-workload-flowlog',
    'athena-hackathon-ecp-03-nic-rg-athena-demo-workload-flowlog',
    'snet-appgw-rg-athena-demo-workload-flowlog',
    'athena-hackathon-client-01-nic-rg-athena-demo-workload-flowlog',
    'snet-paas-private-endpoints-rg-athena-demo-workload-flowlog'
)
$requiredStreams = @('Microsoft-Perf', 'Microsoft-InsightsMetrics', 'Microsoft-Syslog', 'Custom-AthenaJson')
$requiredCounters = @(
    '\Processor(_Total)\% Processor Time',
    '\Memory\Available MBytes',
    '\Memory\% Used Memory',
    '\Logical Disk(*)\% Used Space',
    '\Logical Disk(*)\Disk Transfers/sec',
    '\Network(*)\Total Bytes Transmitted',
    '\Network(*)\Total Bytes Received',
    '\VmInsights\DetailedMetrics'
)

$account = Invoke-AzJson @('account', 'show')
Assert-Ready ($account.id -eq $SubscriptionId) 'The active Azure context does not match the reviewed WC-029 subscription.'

$dcr = Invoke-AzJson @('monitor', 'data-collection', 'rule', 'show', '--resource-group', $monitoringRg, '--name', 'athena-hackathon-linux-dcr')
$dcrStreams = @($dcr.dataFlows | ForEach-Object { $_.streams })
$dcrCounters = @($dcr.dataSources.performanceCounters | ForEach-Object { $_.counterSpecifiers })
foreach ($stream in $requiredStreams) {
    Assert-Ready ($stream -cin $dcrStreams) "The adopted DCR is missing required stream $stream."
}
foreach ($counter in $requiredCounters) {
    Assert-Ready ($counter -cin $dcrCounters) "The adopted DCR is missing required counter $counter."
}
Assert-Ready ($expectedWorkspaceId -cin @($dcr.destinations.logAnalytics.workspaceResourceId)) 'The adopted DCR does not target the reviewed monitoring workspace.'

$dependencyAgentCount = 0
$networkWatcherAgentCount = 0
foreach ($vmName in $approvedVmNames) {
    $extensions = @(Invoke-AzJson @('vm', 'extension', 'list', '--resource-group', $workloadRg, '--vm-name', $vmName))
    $ama = @($extensions | Where-Object { $_.name -eq 'AzureMonitorLinuxAgent' })
    Assert-Ready ($ama.Count -eq 1 -and $ama[0].provisioningState -eq 'Succeeded') "$vmName does not have one healthy Azure Monitor Agent."
    if (@($extensions | Where-Object { $_.name -eq 'DependencyAgentLinux' -and $_.provisioningState -eq 'Succeeded' }).Count -eq 1) {
        $dependencyAgentCount++
    }
    if (@($extensions | Where-Object { $_.name -eq 'NetworkWatcherAgentLinux' -and $_.provisioningState -eq 'Succeeded' }).Count -eq 1) {
        $networkWatcherAgentCount++
    }

    $associationUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$workloadRg/providers/Microsoft.Compute/virtualMachines/$vmName/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=2024-03-11"
    $associations = @(Invoke-AzJson @('rest', '--method', 'get', '--uri', $associationUri) | Select-Object -ExpandProperty value)
    $dcrAssociationIds = @($associations | Where-Object { $_.properties.PSObject.Properties['dataCollectionRuleId'] } | ForEach-Object { $_.properties.dataCollectionRuleId })
    $dceAssociationIds = @($associations | Where-Object { $_.properties.PSObject.Properties['dataCollectionEndpointId'] } | ForEach-Object { $_.properties.dataCollectionEndpointId })
    Assert-Ready ($expectedDcrId -cin $dcrAssociationIds) "$vmName is missing the exact adopted DCR association."
    Assert-Ready ($expectedDceId -cin $dceAssociationIds) "$vmName is missing the exact private DCE association."
}
if ($RequireDependencyAgent) {
    Assert-Ready ($dependencyAgentCount -eq $approvedVmNames.Count) 'Dependency Agent is not healthy on every approved VM.'
}
if ($RequireConnectionMonitorAgent) {
    Assert-Ready ($networkWatcherAgentCount -gt 0) 'No approved Connection Monitor source has a healthy Network Watcher Agent.'
}

$flowLogs = @(Invoke-AzJson @('network', 'watcher', 'flow-log', 'list', '--location', 'australiaeast'))
$canonical = @($flowLogs | Where-Object { $_.name -eq 'athena-hackathon-vnet-rg-athena-demo-workload-flowlog' })
Assert-Ready ($canonical.Count -eq 1) 'The canonical VNet flow log is missing or duplicated.'
Assert-Ready ($canonical[0].enabled -and $canonical[0].targetResourceId -ieq $expectedVnetId) 'The canonical VNet flow log is not enabled on the reviewed VNet.'
Assert-Ready ($canonical[0].storageId -ieq $replacementStorageId) 'The canonical VNet flow log does not target monitoring-owned storage.'
$analytics = $canonical[0].flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration
Assert-Ready ($analytics.enabled -and $analytics.workspaceResourceId -ieq $expectedWorkspaceId -and $analytics.trafficAnalyticsInterval -eq 10) 'Traffic Analytics is not enabled with the reviewed workspace and interval.'
$legacyFlowLogs = @($flowLogs | Where-Object { $_.storageId -ieq $legacyStorageId })
Assert-Ready ($legacyFlowLogs.Count -eq $expectedLegacyFlowLogNames.Count) 'The retained legacy flow-log source set does not match the reviewed eighteen-resource allowlist.'
foreach ($legacyName in $expectedLegacyFlowLogNames) {
    Assert-Ready ($legacyName -cin @($legacyFlowLogs.name)) "Reviewed legacy flow log $legacyName is missing from athenahackathonflowwhtco."
}

$storage = Invoke-AzJson @('storage', 'account', 'show', '--resource-group', $monitoringRg, '--name', 'athenademomonchab01')
Assert-Ready ($storage.allowSharedKeyAccess -eq $false) 'Replacement monitoring storage must keep Shared Key disabled.'
Assert-Ready ($storage.allowBlobPublicAccess -eq $false) 'Replacement monitoring storage must keep public Blob access disabled.'
Assert-Ready ($storage.defaultToOAuthAuthentication -eq $true) 'Replacement monitoring storage must default to Microsoft Entra authorization.'
Assert-Ready ($storage.networkRuleSet.defaultAction -eq 'Deny' -and $storage.networkRuleSet.bypass -eq 'AzureServices') 'Replacement monitoring storage must keep default-deny networking and only the trusted-service bypass.'
$policy = Invoke-AzJson @('storage', 'account', 'management-policy', 'show', '--resource-group', $monitoringRg, '--account-name', 'athenademomonchab01')
Assert-Ready ('flow-log-evidence-retention' -cin @($policy.policy.rules.name)) 'Replacement monitoring storage is missing its reviewed lifecycle rule.'
$privateEndpoint = Invoke-AzJson @('network', 'private-endpoint', 'show', '--resource-group', $monitoringRg, '--name', 'athena-demo-monitoring-monitoring-storage-pe')
Assert-Ready ($replacementStorageId -cin @($privateEndpoint.privateLinkServiceConnections.privateLinkServiceId)) 'The storage private endpoint does not target replacement monitoring storage.'
Assert-Ready ('blob' -cin @($privateEndpoint.privateLinkServiceConnections.groupIds)) 'The storage private endpoint is missing the Blob group.'

$subscriptionExports = @(Invoke-AzJson @('monitor', 'diagnostic-settings', 'subscription', 'list') | Select-Object -ExpandProperty value)
Assert-Ready ($subscriptionExports.Count -eq 0) 'An unrestricted subscription diagnostic export exists; WC-029 requires separate security and data-governance approval.'
$changeTopics = @(Invoke-AzJson @('eventgrid', 'system-topic', 'list', '--resource-group', $workloadRg))
$boundedChangeTopics = @($changeTopics | Where-Object { $_.source -ieq "/subscriptions/$SubscriptionId/resourceGroups/$workloadRg" -and $_.topicType -eq 'Microsoft.Resources.ResourceGroups' })
if ($RequireChangeEventRoute) {
    Assert-Ready ($boundedChangeTopics.Count -eq 1) 'The resource-group-bounded WC-025 Event Grid change route is not deployed.'
}

[ordered]@{
    schemaVersion = 'athena.wc029MonitoringReadiness.v1'
    subscriptionId = $SubscriptionId
    approvedVmCount = $approvedVmNames.Count
    healthyAmaCount = $approvedVmNames.Count
    dependencyAgentCount = $dependencyAgentCount
    networkWatcherAgentCount = $networkWatcherAgentCount
    dcrStreams = $requiredStreams
    canonicalFlowLog = $canonical[0].name
    replacementStorage = $storage.name
    retainedLegacyStorage = 'athenahackathonflowwhtco'
    retainedLegacyFlowLogCount = $legacyFlowLogs.Count
    boundedChangeEventRouteCount = $boundedChangeTopics.Count
    subscriptionActivityLogExportCount = $subscriptionExports.Count
    connectionMonitorDefinitions = 'not-validated-until-published-intent-reconciliation'
    noMutationPerformed = $true
} | ConvertTo-Json -Depth 5
