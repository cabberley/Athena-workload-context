[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$CollectorPrincipalId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/]+$')]
    [string]$CollectorIdentityResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ContainerRegistry/registries/[^/]+$')]
    [string]$RegistryResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+$')]
    [string]$WorkloadResourceGroupResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/networkWatchers/[^/]+$')]
    [string]$NetworkWatcherResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/[^/]+/blobServices/default/containers/change-evidence$')]
    [string]$ChangeEvidenceContainerResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/[^/]+/blobServices/default/containers/monitoring-evidence$')]
    [string]$MonitoringEvidenceContainerResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[^/]+/keys/[^/]+$')]
    [string]$MonitoringIntentSigningKeyResourceId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AzJson {
    param([Parameter(Mandatory)][string[]]$AzArguments)

    $output = & az @AzArguments --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw "az $($AzArguments -join ' ') failed with exit code $LASTEXITCODE"
    }
    return $output | ConvertFrom-Json
}

function Invoke-AzCommand {
    param([Parameter(Mandatory)][string[]]$AzArguments)

    & az @AzArguments --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "az $($AzArguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Normalize-ResourceId {
    param([Parameter(Mandatory)][string]$ResourceId)

    return $ResourceId.TrimEnd('/').ToLowerInvariant()
}

function Convert-GuidToNetworkBytes {
    param([Parameter(Mandatory)][Guid]$Guid)

    [byte[]]$bytes = $Guid.ToByteArray()
    [Array]::Reverse($bytes, 0, 4)
    [Array]::Reverse($bytes, 4, 2)
    [Array]::Reverse($bytes, 6, 2)
    return ,$bytes
}

function Convert-NetworkBytesToGuid {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Count -ne 16) {
        throw 'A deterministic GUID requires exactly 16 bytes.'
    }
    [byte[]]$localBytes = $Bytes.Clone()
    [Array]::Reverse($localBytes, 0, 4)
    [Array]::Reverse($localBytes, 4, 2)
    [Array]::Reverse($localBytes, 6, 2)
    return [Guid]::new($localBytes)
}

function New-ArmTemplateGuid {
    param([Parameter(Mandatory)][string[]]$Values)

    $emptyValues = @($Values | Where-Object { [string]::IsNullOrEmpty($_) })
    if ($Values.Count -eq 0 -or $emptyValues.Count -ne 0) {
        throw 'ARM guid() inputs must be non-empty strings.'
    }
    $namespace = [Guid]'11fb06fb-712d-4ddd-98c7-e71bbd588830'
    [byte[]]$namespaceBytes = Convert-GuidToNetworkBytes -Guid $namespace
    [byte[]]$nameBytes = [Text.Encoding]::UTF8.GetBytes(($Values -join '-'))
    [byte[]]$hashInput = [byte[]]::new($namespaceBytes.Count + $nameBytes.Count)
    [Array]::Copy($namespaceBytes, 0, $hashInput, 0, $namespaceBytes.Count)
    [Array]::Copy(
        $nameBytes,
        0,
        $hashInput,
        $namespaceBytes.Count,
        $nameBytes.Count
    )
    # ARM guid() is UUID v5; SHA-1 here is the specified name-based identifier algorithm.
    [byte[]]$hash = [Security.Cryptography.SHA1]::HashData($hashInput)
    [byte[]]$guidBytes = $hash[0..15]
    $guidBytes[6] = ($guidBytes[6] -band 0x0f) -bor 0x50
    $guidBytes[8] = ($guidBytes[8] -band 0x3f) -bor 0x80
    return (Convert-NetworkBytesToGuid -Bytes $guidBytes).ToString()
}

function Assert-ResourceSubscription {
    param([Parameter(Mandatory)][string]$ResourceId)

    $segments = $ResourceId.Trim('/').Split('/')
    if (
        $segments.Count -lt 2 -or
        $segments[0].ToLowerInvariant() -ne 'subscriptions' -or
        $segments[1].ToLowerInvariant() -ne $SubscriptionId.ToLowerInvariant()
    ) {
        throw "Resource ID '$ResourceId' is outside SubscriptionId."
    }
}

function Get-ResourceGroupScope {
    param([Parameter(Mandatory)][string]$ResourceId)

    $normalized = Normalize-ResourceId -ResourceId $ResourceId
    $providerIndex = $normalized.IndexOf(
        '/providers/',
        [StringComparison]::OrdinalIgnoreCase
    )
    $resourceGroupScope = if ($providerIndex -lt 0) {
        $normalized
    } else {
        $normalized.Substring(0, $providerIndex)
    }
    $segments = $resourceGroupScope.Trim('/').Split('/')
    if (
        $segments.Count -ne 4 -or
        $segments[0] -ne 'subscriptions' -or
        $segments[1] -ne $SubscriptionId.ToLowerInvariant() -or
        $segments[2] -ne 'resourcegroups' -or
        [string]::IsNullOrEmpty($segments[3])
    ) {
        throw "Resource ID '$ResourceId' does not have one exact resource-group scope."
    }
    return $resourceGroupScope
}

function Get-ExactResourceGroupName {
    param([Parameter(Mandatory)][string]$ResourceGroupResourceId)

    $segments = $ResourceGroupResourceId.Trim('/').Split('/')
    if (
        $segments.Count -ne 4 -or
        $segments[0].ToLowerInvariant() -ne 'subscriptions' -or
        $segments[1].ToLowerInvariant() -ne $SubscriptionId.ToLowerInvariant() -or
        $segments[2].ToLowerInvariant() -ne 'resourcegroups' -or
        [string]::IsNullOrEmpty($segments[3])
    ) {
        throw (
            "Resource ID '$ResourceGroupResourceId' is not one exact resource group " +
            'in SubscriptionId.'
        )
    }
    return $segments[3]
}

function Get-HistoricalNetworkWatcherResourceId {
    param([Parameter(Mandatory)][string]$ResourceId)

    $segments = $ResourceId.Trim('/').Split('/')
    if (
        $segments.Count -ne 8 -or
        $segments[0].ToLowerInvariant() -ne 'subscriptions' -or
        $segments[1].ToLowerInvariant() -ne $SubscriptionId.ToLowerInvariant() -or
        $segments[2].ToLowerInvariant() -ne 'resourcegroups' -or
        $segments[3].ToLowerInvariant() -ne 'networkwatcherrg' -or
        $segments[4].ToLowerInvariant() -ne 'providers' -or
        $segments[5].ToLowerInvariant() -ne 'microsoft.network' -or
        $segments[6].ToLowerInvariant() -ne 'networkwatchers' -or
        $segments[7].ToLowerInvariant() -ne 'networkwatcher_australiaeast'
    ) {
        throw (
            "Resource ID '$ResourceId' is not the reviewed historical " +
            'NetworkWatcherRG/NetworkWatcher_australiaeast resource.'
        )
    }
    return (
        "/subscriptions/$($SubscriptionId.ToLowerInvariant())/resourceGroups/" +
        "$($segments[3].ToLowerInvariant())/providers/Microsoft.Network/networkWatchers/" +
        $segments[7].ToLowerInvariant()
    )
}

function Get-ExactRoleDefinition {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)

    $roleDefinitionGuid = $RoleDefinitionId.TrimEnd('/').Split('/')[-1]
    $matches = @(
        @(
            Invoke-AzJson -AzArguments @(
                'role', 'definition', 'list',
                '--name', $roleDefinitionGuid,
                '--subscription', $SubscriptionId
            )
        ) | Where-Object {
            (Normalize-ResourceId -ResourceId ([string]$_.id)) -eq (
                Normalize-ResourceId -ResourceId $RoleDefinitionId
            )
        }
    )
    if ($matches.Count -gt 1) {
        throw "Role definition '$RoleDefinitionId' resolved ambiguously."
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    return $matches[0]
}

function Assert-ReviewedRoleDefinition {
    param(
        [Parameter(Mandatory)][object]$RoleDefinition,
        [Parameter(Mandatory)][string]$ExpectedRoleDefinitionId,
        [Parameter(Mandatory)][string]$ExpectedAssignableScope,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedActions,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedDataActions
    )

    $permissions = @($RoleDefinition.permissions)
    $assignableScopes = @(
        @($RoleDefinition.assignableScopes) |
            ForEach-Object { Normalize-ResourceId -ResourceId ([string]$_) } |
            Sort-Object
    )
    $actualActions = @(
        @($permissions[0].actions) |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object
    )
    $actualDataActions = @(
        @($permissions[0].dataActions) |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object
    )
    $expectedActionsNormalized = @(
        $ExpectedActions |
            ForEach-Object { $_.ToLowerInvariant() } |
            Sort-Object
    )
    $expectedDataActionsNormalized = @(
        $ExpectedDataActions |
            ForEach-Object { $_.ToLowerInvariant() } |
            Sort-Object
    )
    if (
        (Normalize-ResourceId -ResourceId ([string]$RoleDefinition.id)) -ne (
            Normalize-ResourceId -ResourceId $ExpectedRoleDefinitionId
        ) -or
        [string]$RoleDefinition.roleType -ne 'CustomRole' -or
        $permissions.Count -ne 1 -or
        ($actualActions -join "`n") -ne ($expectedActionsNormalized -join "`n") -or
        @($permissions[0].notActions).Count -ne 0 -or
        ($actualDataActions -join "`n") -ne ($expectedDataActionsNormalized -join "`n") -or
        @($permissions[0].notDataActions).Count -ne 0 -or
        $assignableScopes.Count -ne 1 -or
        $assignableScopes[0] -ne (
            Normalize-ResourceId -ResourceId $ExpectedAssignableScope
        )
    ) {
        throw (
            "Historical role definition '$ExpectedRoleDefinitionId' does not match " +
            'the reviewed deterministic body and assignable scope.'
        )
    }
}

function Assert-RoleDefinitionAbsent {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)

    $roleDefinitionGuid = $RoleDefinitionId.TrimEnd('/').Split('/')[-1]
    $matches = @(
        @(
            Invoke-AzJson -AzArguments @(
                'role', 'definition', 'list',
                '--name', $roleDefinitionGuid,
                '--subscription', $SubscriptionId
            )
        ) | Where-Object {
            (Normalize-ResourceId -ResourceId ([string]$_.id)) -eq (
                Normalize-ResourceId -ResourceId $RoleDefinitionId
            )
        }
    )
    if ($matches.Count -ne 0) {
        throw "Role definition '$RoleDefinitionId' remains after exact cleanup."
    }
}

foreach ($resourceId in @(
    $CollectorIdentityResourceId,
    $RegistryResourceId,
    $WorkloadResourceGroupResourceId,
    $NetworkWatcherResourceId,
    $ChangeEvidenceContainerResourceId,
    $MonitoringEvidenceContainerResourceId,
    $MonitoringIntentSigningKeyResourceId
)) {
    Assert-ResourceSubscription -ResourceId $resourceId
}

Invoke-AzCommand -AzArguments @('account', 'set', '--subscription', $SubscriptionId)

$collectorIdentity = Invoke-AzJson -AzArguments @(
    'identity', 'show',
    '--ids', $CollectorIdentityResourceId,
    '--subscription', $SubscriptionId
)
if (
    (Normalize-ResourceId -ResourceId ([string]$collectorIdentity.id)) -ne (
        Normalize-ResourceId -ResourceId $CollectorIdentityResourceId
    ) -or
    ([string]$collectorIdentity.principalId).ToLowerInvariant() -ne (
        $CollectorPrincipalId.ToLowerInvariant()
    )
) {
    throw 'CollectorIdentityResourceId does not resolve to CollectorPrincipalId.'
}

$networkWatcher = Invoke-AzJson -AzArguments @(
    'resource', 'show',
    '--ids', $NetworkWatcherResourceId,
    '--api-version', '2024-10-01',
    '--subscription', $SubscriptionId
)
if (
    (Normalize-ResourceId -ResourceId ([string]$networkWatcher.id)) -ne (
        Normalize-ResourceId -ResourceId $NetworkWatcherResourceId
    ) -or
    [string]$networkWatcher.name -cne 'NetworkWatcher_australiaeast' -or
    ([string]$networkWatcher.location).ToLowerInvariant() -ne 'australiaeast' -or
    [string]$networkWatcher.properties.provisioningState -cne 'Succeeded'
) {
    throw (
        'NetworkWatcherResourceId does not resolve to the exact reviewed ' +
        'name, location, state, and resource ID.'
    )
}
$networkWatcherId = [string]$networkWatcher.id
$workloadResourceGroupName = Get-ExactResourceGroupName `
    -ResourceGroupResourceId $WorkloadResourceGroupResourceId
$workloadResourceGroup = Invoke-AzJson -AzArguments @(
    'group', 'show',
    '--name', $workloadResourceGroupName,
    '--subscription', $SubscriptionId
)
if (
    (Normalize-ResourceId -ResourceId ([string]$workloadResourceGroup.id)) -ne (
        Normalize-ResourceId -ResourceId $WorkloadResourceGroupResourceId
    ) -or
    [string]$workloadResourceGroup.name -cne $workloadResourceGroupName -or
    ([string]$workloadResourceGroup.location).ToLowerInvariant() -ne 'australiaeast' -or
    [string]$workloadResourceGroup.properties.provisioningState -cne 'Succeeded'
) {
    throw (
        'WorkloadResourceGroupResourceId does not resolve to the exact reviewed ' +
        'name, location, state, and resource ID.'
    )
}
$workloadResourceGroupId = [string]$workloadResourceGroup.id
$workloadResourceGroupSegments = (
    Normalize-ResourceId -ResourceId $workloadResourceGroupId
).Trim('/').Split('/')
$historicalWorkloadResourceGroupId = (
    "/subscriptions/$($SubscriptionId.ToLowerInvariant())/resourceGroups/" +
    $workloadResourceGroupSegments[3]
)
$historicalNetworkWatcherId = Get-HistoricalNetworkWatcherResourceId `
    -ResourceId $networkWatcherId
$networkWatcherResourceGroupId = Get-ResourceGroupScope -ResourceId $networkWatcherId
$changeEvidenceResourceGroupId = Get-ResourceGroupScope `
    -ResourceId $ChangeEvidenceContainerResourceId
$monitoringIntentKeyResourceGroupId = Get-ResourceGroupScope `
    -ResourceId $MonitoringIntentSigningKeyResourceId
$subscriptionScope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
$boundedReaderRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-bounded-acquisition-reader',
    $historicalWorkloadResourceGroupId
)
$boundedReaderRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    $boundedReaderRoleDefinitionGuid
)
$changeWriterRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-change-evidence-create-only',
    (Normalize-ResourceId -ResourceId $ChangeEvidenceContainerResourceId)
)
$changeWriterRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    $changeWriterRoleDefinitionGuid
)
$intentKeyReaderRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-monitoring-intent-key-reader',
    (Normalize-ResourceId -ResourceId $MonitoringIntentSigningKeyResourceId)
)
$intentKeyReaderRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    $intentKeyReaderRoleDefinitionGuid
)
$ipFlowRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-ip-flow-verify',
    $historicalNetworkWatcherId
)
$ipFlowRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    $ipFlowRoleDefinitionGuid
)
$historicalRoleDefinitions = @(
    [pscustomobject]@{
        Name = 'bounded acquisition reader'
        RoleDefinitionId = $boundedReaderRoleDefinitionId
        Definition = Get-ExactRoleDefinition -RoleDefinitionId $boundedReaderRoleDefinitionId
        ExpectedAssignableScope = $historicalWorkloadResourceGroupId
        ExpectedActions = @(
            'Microsoft.Insights/eventtypes/values/read'
            'Microsoft.ResourceGraph/resources/read'
            'Microsoft.Resources/changes/read'
        )
        ExpectedDataActions = @()
    },
    [pscustomobject]@{
        Name = 'change-evidence create-only writer'
        RoleDefinitionId = $changeWriterRoleDefinitionId
        Definition = Get-ExactRoleDefinition -RoleDefinitionId $changeWriterRoleDefinitionId
        ExpectedAssignableScope = $changeEvidenceResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        )
    },
    [pscustomobject]@{
        Name = 'monitoring-intent key reader'
        RoleDefinitionId = $intentKeyReaderRoleDefinitionId
        Definition = Get-ExactRoleDefinition -RoleDefinitionId $intentKeyReaderRoleDefinitionId
        ExpectedAssignableScope = $monitoringIntentKeyResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.KeyVault/vaults/keys/read'
        )
    },
    [pscustomobject]@{
        Name = 'Network Watcher IP Flow verifier'
        RoleDefinitionId = $ipFlowRoleDefinitionId
        Definition = Get-ExactRoleDefinition -RoleDefinitionId $ipFlowRoleDefinitionId
        ExpectedAssignableScope = $networkWatcherResourceGroupId
        ExpectedActions = @(
            'Microsoft.Network/networkWatchers/ipFlowVerify/action'
        )
        ExpectedDataActions = @()
    }
)
foreach ($historicalRole in $historicalRoleDefinitions) {
    if ($null -ne $historicalRole.Definition) {
        Assert-ReviewedRoleDefinition `
            -RoleDefinition $historicalRole.Definition `
            -ExpectedRoleDefinitionId $historicalRole.RoleDefinitionId `
            -ExpectedAssignableScope $historicalRole.ExpectedAssignableScope `
            -ExpectedActions $historicalRole.ExpectedActions `
            -ExpectedDataActions $historicalRole.ExpectedDataActions
    }
}
$ipFlowAssignmentGuid = New-ArmTemplateGuid -Values @(
    $historicalNetworkWatcherId,
    [string]$collectorIdentity.principalId,
    $ipFlowRoleDefinitionId
)
$ipFlowAssignmentId = (
    "$historicalNetworkWatcherId/providers/Microsoft.Authorization/roleAssignments/" +
    $ipFlowAssignmentGuid
)

$acrPullRoleDefinitionId = (
    "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/" +
    '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)
$storageBlobDataContributorRoleDefinitionId = (
    "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/" +
    'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

$targets = @(
    [pscustomobject]@{
        Name = 'collector ACR pull'
        Scope = $RegistryResourceId
        RoleDefinitionId = $acrPullRoleDefinitionId
        ExpectedAssignmentId = $null
    },
    [pscustomobject]@{
        Name = 'collector broad monitoring-evidence contributor'
        Scope = $MonitoringEvidenceContainerResourceId
        RoleDefinitionId = $storageBlobDataContributorRoleDefinitionId
        ExpectedAssignmentId = $null
    },
    [pscustomobject]@{
        Name = 'collector Network Watcher IP Flow verifier'
        Scope = $networkWatcherId
        RoleDefinitionId = $ipFlowRoleDefinitionId
        ExpectedAssignmentId = $ipFlowAssignmentId
    },
    [pscustomobject]@{
        Name = 'collector bounded acquisition reader'
        Scope = $workloadResourceGroupId
        RoleDefinitionId = $boundedReaderRoleDefinitionId
        ExpectedAssignmentId = $null
    },
    [pscustomobject]@{
        Name = 'collector change-evidence writer'
        Scope = $ChangeEvidenceContainerResourceId
        RoleDefinitionId = $changeWriterRoleDefinitionId
        ExpectedAssignmentId = $null
    },
    [pscustomobject]@{
        Name = 'collector monitoring-intent key reader'
        Scope = $MonitoringIntentSigningKeyResourceId
        RoleDefinitionId = $intentKeyReaderRoleDefinitionId
        ExpectedAssignmentId = $null
    }
)

$assignments = @(
    Invoke-AzJson -AzArguments @(
        'role', 'assignment', 'list',
        '--assignee-object-id', $CollectorPrincipalId,
        '--all',
        '--subscription', $SubscriptionId
    )
)
$removedAssignmentIds = [System.Collections.Generic.List[string]]::new()

foreach ($target in $targets) {
    $normalizedScope = Normalize-ResourceId -ResourceId $target.Scope
    $normalizedRole = Normalize-ResourceId -ResourceId $target.RoleDefinitionId
    $scopeRoleMatches = @(
        $assignments | Where-Object {
            ([string]$_.principalId).ToLowerInvariant() -eq (
                $CollectorPrincipalId.ToLowerInvariant()
            ) -and
            (Normalize-ResourceId -ResourceId ([string]$_.scope)) -eq $normalizedScope -and
            (Normalize-ResourceId -ResourceId ([string]$_.roleDefinitionId)) -eq $normalizedRole
        }
    )
    $matches = $scopeRoleMatches
    if ($null -ne $target.ExpectedAssignmentId) {
        $expectedAssignmentId = Normalize-ResourceId `
            -ResourceId ([string]$target.ExpectedAssignmentId)
        $unexpectedIds = @(
            $scopeRoleMatches | Where-Object {
                (Normalize-ResourceId -ResourceId ([string]$_.id)) -ne (
                    $expectedAssignmentId
                )
            }
        )
        if ($unexpectedIds.Count -ne 0) {
            throw "$($target.Name) exists under a non-deterministic assignment ID."
        }
        $matches = @(
            $scopeRoleMatches | Where-Object {
                (Normalize-ResourceId -ResourceId ([string]$_.id)) -eq (
                    $expectedAssignmentId
                )
            }
        )
    }
    if ($matches.Count -gt 1) {
        throw "$($target.Name) resolved to multiple exact role assignments."
    }
    if ($matches.Count -eq 1) {
        $assignmentId = [string]$matches[0].id
        Invoke-AzCommand -AzArguments @('role', 'assignment', 'delete', '--ids', $assignmentId)
        $removedAssignmentIds.Add($assignmentId)
    }
}

$removedRoleDefinitionIds = [System.Collections.Generic.List[string]]::new()
foreach ($historicalRole in $historicalRoleDefinitions) {
    $roleDefinitionId = [string]$historicalRole.RoleDefinitionId
    if ($null -ne $historicalRole.Definition) {
        $roleDefinitionGuid = $roleDefinitionId.TrimEnd('/').Split('/')[-1]
        Invoke-AzCommand -AzArguments @(
            'role', 'definition', 'delete',
            '--name', $roleDefinitionGuid,
            '--subscription', $SubscriptionId
        )
    }
    Assert-RoleDefinitionAbsent -RoleDefinitionId $roleDefinitionId
    if ($null -ne $historicalRole.Definition) {
        $removedRoleDefinitionIds.Add([string]$roleDefinitionId)
    }
}

$remainingAssignments = @(
    Invoke-AzJson -AzArguments @(
        'role', 'assignment', 'list',
        '--assignee-object-id', $CollectorPrincipalId,
        '--all',
        '--subscription', $SubscriptionId
    )
)
foreach ($target in $targets) {
    $normalizedScope = Normalize-ResourceId -ResourceId $target.Scope
    $normalizedRole = Normalize-ResourceId -ResourceId $target.RoleDefinitionId
    if (
        $remainingAssignments | Where-Object {
            (Normalize-ResourceId -ResourceId ([string]$_.scope)) -eq $normalizedScope -and
            (Normalize-ResourceId -ResourceId ([string]$_.roleDefinitionId)) -eq $normalizedRole
        }
    ) {
        throw "$($target.Name) remains assigned after exact cleanup."
    }
}

$evidence = [ordered]@{
    schemaVersion = 'athena.wc028LegacyCollectorRbacCleanup.v3'
    subscriptionId = $SubscriptionId.ToLowerInvariant()
    collectorIdentityResourceId = (Normalize-ResourceId -ResourceId $CollectorIdentityResourceId)
    collectorPrincipalId = $CollectorPrincipalId.ToLowerInvariant()
    networkWatcherResourceId = (Normalize-ResourceId -ResourceId $networkWatcherId)
    historicalIpFlowRoleDefinitionId = (
        Normalize-ResourceId -ResourceId $ipFlowRoleDefinitionId
    )
    historicalIpFlowRoleAssignmentId = (
        Normalize-ResourceId -ResourceId $ipFlowAssignmentId
    )
    removedRoleAssignmentIds = @($removedAssignmentIds | Sort-Object)
    removedRoleDefinitionIds = @($removedRoleDefinitionIds | Sort-Object)
    reviewedRoleAssignmentIds = @(
        $targets |
            Where-Object { $null -ne $_.ExpectedAssignmentId } |
            ForEach-Object {
                Normalize-ResourceId -ResourceId ([string]$_.ExpectedAssignmentId)
            } |
            Sort-Object
    )
    reviewedRoleDefinitionIds = @(
        $historicalRoleDefinitions |
            ForEach-Object {
                Normalize-ResourceId -ResourceId ([string]$_.RoleDefinitionId)
            } |
            Sort-Object
    )
    verifiedAbsentBindings = @(
        $targets |
            ForEach-Object {
                [ordered]@{
                    scope = (Normalize-ResourceId -ResourceId $_.Scope)
                    roleDefinitionId = (Normalize-ResourceId -ResourceId $_.RoleDefinitionId)
                    expectedAssignmentId = if ($null -eq $_.ExpectedAssignmentId) {
                        $null
                    } else {
                        Normalize-ResourceId `
                            -ResourceId ([string]$_.ExpectedAssignmentId)
                    }
                }
            } |
            Sort-Object scope, roleDefinitionId, expectedAssignmentId
    )
}
$evidenceJson = $evidence | ConvertTo-Json -Depth 8 -Compress
$digestBytes = [Text.Encoding]::UTF8.GetBytes($evidenceJson)
$digest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($digestBytes)
).ToLowerInvariant()

[ordered]@{
    cleanupEvidence = $evidence
    cleanupEvidenceDigest = "sha256:$digest"
} | ConvertTo-Json -Depth 10
