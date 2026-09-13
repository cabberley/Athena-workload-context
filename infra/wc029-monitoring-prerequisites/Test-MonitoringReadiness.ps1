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

function Test-DcrDataCollectionEndpoint {
    param(
        [Parameter(Mandatory)][object] $DataCollectionRule,
        [Parameter(Mandatory)][string] $ExpectedDataCollectionEndpointId
    )

    $endpointProperty = $DataCollectionRule.PSObject.Properties['dataCollectionEndpointId']
    return $null -ne $endpointProperty -and $endpointProperty.Value -ieq $ExpectedDataCollectionEndpointId
}

function Test-DcrStreamFlowsUseExclusiveDestinations {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $DataFlows,
        [Parameter(Mandatory)][string] $Stream,
        [Parameter(Mandatory)][string[]] $ApprovedDestinationNames
    )

    $streamFlows = @($DataFlows | Where-Object { $Stream -cin @($_.streams) })
    if ($streamFlows.Count -eq 0) {
        return $false
    }
    foreach ($flow in $streamFlows) {
        $flowDestinations = @($flow.destinations)
        if (
            $flowDestinations.Count -ne 1 -or
            $flowDestinations[0] -notin $ApprovedDestinationNames
        ) {
            return $false
        }
    }
    return $true
}

function Test-LifecycleRuleHasUnsafeDelete {
    param(
        [Parameter(Mandatory)][object] $Rule,
        [Parameter(Mandatory)][string[]] $RequiredPrefixes,
        [Parameter(Mandatory)][int] $MinimumDays
    )

    $filtersProperty = $Rule.definition.PSObject.Properties['filters']
    $filters = if ($null -ne $filtersProperty) { $filtersProperty.Value } else { $null }
    $blobTypesProperty = if ($null -ne $filters) { $filters.PSObject.Properties['blobTypes'] } else { $null }
    $blobTypes = @(
        if ($null -ne $blobTypesProperty) {
            $blobTypesProperty.Value
        }
    )
    if ($Rule.enabled -ne $true -or 'blockBlob' -cnotin $blobTypes) {
        return $false
    }
    $prefixMatchProperty = if ($null -ne $filters) { $filters.PSObject.Properties['prefixMatch'] } else { $null }
    $rulePrefixes = @(
        if ($null -ne $prefixMatchProperty) {
            $prefixMatchProperty.Value
        }
    )
    $overlapsRequiredPrefix = $rulePrefixes.Count -eq 0
    foreach ($requiredPrefix in $RequiredPrefixes) {
        foreach ($rulePrefix in $rulePrefixes) {
            if (
                $requiredPrefix.StartsWith($rulePrefix, [System.StringComparison]::Ordinal) -or
                $rulePrefix.StartsWith($requiredPrefix, [System.StringComparison]::Ordinal)
            ) {
                $overlapsRequiredPrefix = $true
            }
        }
    }
    if (-not $overlapsRequiredPrefix) {
        return $false
    }

    $deleteActions = @()
    foreach ($actionName in @('baseBlob', 'version')) {
        $actionProperty = $Rule.definition.actions.PSObject.Properties[$actionName]
        if ($null -eq $actionProperty -or $null -eq $actionProperty.Value) {
            continue
        }
        $deleteProperty = $actionProperty.Value.PSObject.Properties['delete']
        if ($null -ne $deleteProperty -and $null -ne $deleteProperty.Value) {
            $deleteActions += $deleteProperty.Value
        }
    }
    $retentionProperties = @(
        'daysAfterModificationGreaterThan',
        'daysAfterCreationGreaterThan',
        'daysAfterLastAccessTimeGreaterThan',
        'daysAfterLastTierChangeGreaterThan'
    )
    foreach ($deleteAction in $deleteActions) {
        foreach ($propertyName in $retentionProperties) {
            $property = $deleteAction.PSObject.Properties[$propertyName]
            if ($null -ne $property -and $null -ne $property.Value -and [double]$property.Value -lt $MinimumDays) {
                return $true
            }
        }
    }
    return $false
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
$expectedCollectorVnetId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.Network/virtualNetworks/athena-demo-monitoring-collector-vnet"
$expectedCollectorPrivateEndpointSubnetId = "$expectedCollectorVnetId/subnets/private-endpoints"
$expectedBlobPrivateDnsZoneId = "/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
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
$dcrCounters = @($dcr.dataSources.performanceCounters | ForEach-Object { $_.counterSpecifiers })
$approvedWorkspaceDestinationNames = @(
    $dcr.destinations.logAnalytics |
        Where-Object { $_.workspaceResourceId -ieq $expectedWorkspaceId } |
        ForEach-Object { $_.name }
)
Assert-Ready ($approvedWorkspaceDestinationNames.Count -gt 0) 'The adopted DCR has no destination bound to the reviewed monitoring workspace.'
Assert-Ready (Test-DcrDataCollectionEndpoint -DataCollectionRule $dcr -ExpectedDataCollectionEndpointId $expectedDceId) 'The adopted DCR does not reference the exact approved data collection endpoint.'
foreach ($stream in $requiredStreams) {
    Assert-Ready (Test-DcrStreamFlowsUseExclusiveDestinations -DataFlows @($dcr.dataFlows) -Stream $stream -ApprovedDestinationNames $approvedWorkspaceDestinationNames) "Required DCR stream $stream is missing or has a flow that is not routed exclusively to the approved workspace destination."
}
foreach ($counter in $requiredCounters) {
    Assert-Ready ($counter -cin $dcrCounters) "The adopted DCR is missing required counter $counter."
}

$dceUri = "https://management.azure.com$expectedDceId`?api-version=2024-03-11"
$dce = Invoke-AzJson @('rest', '--method', 'get', '--uri', $dceUri)
Assert-Ready ($dce.id -ieq $expectedDceId -and $dce.location -eq 'australiaeast' -and $dce.properties.provisioningState -eq 'Succeeded') 'The adopted DCE is missing, outside australiaeast, or not successfully provisioned.'
$vmInsightsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$monitoringRg/providers/Microsoft.OperationsManagement/solutions/VMInsights%28athena-hackathon-law%29?api-version=2015-11-01-preview"
$vmInsights = Invoke-AzJson @('rest', '--method', 'get', '--uri', $vmInsightsUri)
Assert-Ready ($vmInsights.location -eq 'australiaeast' -and $vmInsights.properties.provisioningState -eq 'Succeeded' -and $vmInsights.properties.workspaceResourceId -ieq $expectedWorkspaceId) 'The VM Insights solution is missing, unhealthy, or not bound to the reviewed monitoring workspace.'

$dependencyAgentCount = 0
$networkWatcherAgentCount = 0
foreach ($vmName in $approvedVmNames) {
    $extensions = @(Invoke-AzJson @('vm', 'extension', 'list', '--resource-group', $workloadRg, '--vm-name', $vmName))
    $ama = @($extensions | Where-Object { $_.name -eq 'AzureMonitorLinuxAgent' })
    Assert-Ready ($ama.Count -eq 1 -and $ama[0].publisher -eq 'Microsoft.Azure.Monitor' -and $ama[0].typePropertiesType -eq 'AzureMonitorLinuxAgent' -and $ama[0].provisioningState -eq 'Succeeded') "$vmName does not have one healthy Azure Monitor Agent with the reviewed publisher and type."
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
$blobService = Invoke-AzJson @('storage', 'account', 'blob-service-properties', 'show', '--resource-group', $monitoringRg, '--account-name', 'athenademomonchab01')
Assert-Ready ($blobService.isVersioningEnabled -eq $true) 'Replacement monitoring storage must keep Blob versioning enabled.'
Assert-Ready ($blobService.deleteRetentionPolicy.enabled -eq $true -and $blobService.deleteRetentionPolicy.days -ge 30 -and $blobService.deleteRetentionPolicy.allowPermanentDelete -eq $false) 'Blob soft delete must remain enabled for at least 30 days without permanent delete.'
Assert-Ready ($blobService.containerDeleteRetentionPolicy.enabled -eq $true -and $blobService.containerDeleteRetentionPolicy.days -ge 30) 'Container soft delete must remain enabled for at least 30 days.'
$policy = Invoke-AzJson @('storage', 'account', 'management-policy', 'show', '--resource-group', $monitoringRg, '--account-name', 'athenademomonchab01')
$reviewedRules = @($policy.policy.rules | Where-Object { $_.name -eq 'flow-log-evidence-retention' })
Assert-Ready ($reviewedRules.Count -eq 1) 'Replacement monitoring storage must contain exactly one reviewed lifecycle rule.'
$reviewedRule = $reviewedRules[0]
Assert-Ready ($reviewedRule.enabled -eq $true -and $reviewedRule.type -eq 'Lifecycle') 'The reviewed lifecycle rule must be enabled and retain the Lifecycle type.'
Assert-Ready ($reviewedRule.definition.actions.baseBlob.tierToCool.daysAfterModificationGreaterThan -eq 30) 'The reviewed lifecycle rule must cool base blobs after 30 days.'
Assert-Ready ($reviewedRule.definition.actions.baseBlob.delete.daysAfterModificationGreaterThan -ge 30) 'The reviewed lifecycle rule must retain base blobs for at least 30 days.'
Assert-Ready ($reviewedRule.definition.actions.version.delete.daysAfterCreationGreaterThan -ge 30) 'The reviewed lifecycle rule must retain Blob versions for at least 30 days.'
$reviewedBlobTypes = @($reviewedRule.definition.filters.blobTypes)
$reviewedPrefixes = @($reviewedRule.definition.filters.prefixMatch)
Assert-Ready ($reviewedBlobTypes.Count -eq 1 -and 'blockBlob' -cin $reviewedBlobTypes) 'The reviewed lifecycle rule must apply only to block blobs.'
Assert-Ready ($reviewedPrefixes.Count -eq 2 -and 'insights-logs-flowlogflowevent/' -cin $reviewedPrefixes -and 'monitoring-evidence/' -cin $reviewedPrefixes) 'The reviewed lifecycle rule must retain the exact flow-log and monitoring-evidence prefixes.'
$requiredLifecyclePrefixes = @('insights-logs-flowlogflowevent/', 'monitoring-evidence/')
$unsafeRetentionRules = @(
    $policy.policy.rules |
        Where-Object { Test-LifecycleRuleHasUnsafeDelete -Rule $_ -RequiredPrefixes $requiredLifecyclePrefixes -MinimumDays 30 }
)
Assert-Ready ($unsafeRetentionRules.Count -eq 0) 'An enabled lifecycle rule can delete required monitoring evidence before 30 days.'
$privateEndpoint = Invoke-AzJson @('network', 'private-endpoint', 'show', '--resource-group', $monitoringRg, '--name', 'athena-demo-monitoring-monitoring-storage-pe')
$privateConnections = @($privateEndpoint.privateLinkServiceConnections)
Assert-Ready ($privateEndpoint.location -eq 'australiaeast' -and $privateEndpoint.provisioningState -eq 'Succeeded' -and $privateEndpoint.subnet.id -ieq $expectedCollectorPrivateEndpointSubnetId -and $privateConnections.Count -eq 1 -and @($privateEndpoint.manualPrivateLinkServiceConnections).Count -eq 0) 'The storage private endpoint must be successfully provisioned in the reviewed collector subnet with exactly one automatic connection.'
$blobConnection = $privateConnections[0]
Assert-Ready ($blobConnection.privateLinkServiceId -ieq $replacementStorageId -and @($blobConnection.groupIds).Count -eq 1 -and 'blob' -cin @($blobConnection.groupIds) -and $blobConnection.privateLinkServiceConnectionState.status -eq 'Approved' -and $blobConnection.provisioningState -eq 'Succeeded') 'The storage private endpoint must contain one successfully provisioned, Approved Blob connection to replacement monitoring storage.'
$privateDnsZoneGroup = Invoke-AzJson @('network', 'private-endpoint', 'dns-zone-group', 'show', '--resource-group', $monitoringRg, '--endpoint-name', 'athena-demo-monitoring-monitoring-storage-pe', '--name', 'default')
$privateDnsZoneConfigs = @($privateDnsZoneGroup.privateDnsZoneConfigs)
Assert-Ready ($privateDnsZoneGroup.provisioningState -eq 'Succeeded' -and $privateDnsZoneConfigs.Count -eq 1 -and $privateDnsZoneConfigs[0].privateDnsZoneId -ieq $expectedBlobPrivateDnsZoneId) 'The storage private endpoint must have one successfully provisioned DNS zone group bound to the reviewed Blob private DNS zone.'
$collectorBlobDnsLink = Invoke-AzJson @('network', 'private-dns', 'link', 'vnet', 'show', '--resource-group', $monitoringRg, '--zone-name', 'privatelink.blob.core.windows.net', '--name', 'athena-demo-monitoring-collector-blob-vnet')
Assert-Ready ($collectorBlobDnsLink.provisioningState -eq 'Succeeded' -and $collectorBlobDnsLink.virtualNetworkLinkState -eq 'Completed' -and $collectorBlobDnsLink.registrationEnabled -eq $false -and $collectorBlobDnsLink.virtualNetwork.id -ieq $expectedCollectorVnetId) 'The reviewed Blob private DNS zone must have one completed, non-registering link to the collector VNet.'

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
