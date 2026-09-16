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

    function Get-ExactRoleDefinition {
        param([Parameter(Mandatory)][string]$RoleDefinitionId)

        $roleDefinitionGuid = $RoleDefinitionId.TrimEnd('/').Split('/')[-1]
        $matches = @(
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
        if ($matches.Count -gt 1) {
            throw "Role definition '$RoleDefinitionId' resolved ambiguously."
        }
        if ($matches.Count -eq 0) {
            return $null
        }
        return $matches[0]
    }

    function Assert-ReviewedIpFlowRoleDefinition {
        param(
            [Parameter(Mandatory)][object]$RoleDefinition,
            [Parameter(Mandatory)][string]$ExpectedRoleDefinitionId,
            [Parameter(Mandatory)][string]$ExpectedAssignableScope
        )

        $permissions = @($RoleDefinition.permissions)
        $assignableScopes = @(
            $RoleDefinition.assignableScopes |
                ForEach-Object { Normalize-ResourceId -ResourceId ([string]$_) }
        )
        if (
            (Normalize-ResourceId -ResourceId ([string]$RoleDefinition.id)) -ne (
                Normalize-ResourceId -ResourceId $ExpectedRoleDefinitionId
            ) -or
            [string]$RoleDefinition.roleName -ne 'Athena WC028 IP Flow Verifier' -or
            [string]$RoleDefinition.roleType -ne 'CustomRole' -or
            $permissions.Count -ne 1 -or
            @($permissions[0].actions).Count -ne 1 -or
            [string]$permissions[0].actions[0] -ne (
                'Microsoft.Network/networkWatchers/ipFlowVerify/action'
            ) -or
            @($permissions[0].notActions).Count -ne 0 -or
            @($permissions[0].dataActions).Count -ne 0 -or
            @($permissions[0].notDataActions).Count -ne 0 -or
            $assignableScopes.Count -ne 1 -or
            $assignableScopes[0] -ne (
                Normalize-ResourceId -ResourceId $ExpectedAssignableScope
            )
        ) {
            throw 'Historical IP Flow role definition does not match the reviewed deterministic role.'
        }
    }

    function Find-RoleDefinitionId {
    param([Parameter(Mandatory)][string]$RoleName)

    $matches = @(
        Invoke-AzJson -AzArguments @(
            'role', 'definition', 'list',
            '--name', $RoleName,
            '--subscription', $SubscriptionId
        )
    )
    if ($matches.Count -gt 1) {
        throw "Role name '$RoleName' resolved ambiguously."
    }
    if ($matches.Count -eq 0) {
        return $null
    }
    return [string]$matches[0].id
}

function Assert-RoleDefinitionAbsent {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)

    $roleDefinitionGuid = $RoleDefinitionId.TrimEnd('/').Split('/')[-1]
    $matches = @(
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
    'network', 'watcher', 'show',
    '--ids', $NetworkWatcherResourceId,
    '--subscription', $SubscriptionId
)
if (
    (Normalize-ResourceId -ResourceId ([string]$networkWatcher.id)) -ne (
        Normalize-ResourceId -ResourceId $NetworkWatcherResourceId
    )
) {
    throw 'NetworkWatcherResourceId does not resolve to the exact reviewed Network Watcher.'
}
$networkWatcherId = [string]$networkWatcher.id
$networkWatcherResourceGroupId = $networkWatcherId.Substring(
    0,
    $networkWatcherId.IndexOf('/providers/', [StringComparison]::OrdinalIgnoreCase)
)
$subscriptionScope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
$ipFlowRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-ip-flow-verify',
    $networkWatcherId
)
$ipFlowRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    $ipFlowRoleDefinitionGuid
)
$ipFlowRoleDefinition = Get-ExactRoleDefinition `
    -RoleDefinitionId $ipFlowRoleDefinitionId
if ($null -ne $ipFlowRoleDefinition) {
    Assert-ReviewedIpFlowRoleDefinition `
        -RoleDefinition $ipFlowRoleDefinition `
        -ExpectedRoleDefinitionId $ipFlowRoleDefinitionId `
        -ExpectedAssignableScope $networkWatcherResourceGroupId
}
$ipFlowAssignmentGuid = New-ArmTemplateGuid -Values @(
    $networkWatcherId,
    [string]$collectorIdentity.principalId,
    $ipFlowRoleDefinitionId
)
$ipFlowAssignmentId = (
    "$networkWatcherId/providers/Microsoft.Authorization/roleAssignments/" +
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
$boundedReaderRoleDefinitionId = Find-RoleDefinitionId `
    -RoleName 'Athena WC028 Bounded Acquisition Reader'
$changeWriterRoleDefinitionId = Find-RoleDefinitionId `
    -RoleName 'Athena WC028 Change Evidence Create-Only Writer'
$intentKeyReaderRoleDefinitionId = Find-RoleDefinitionId `
    -RoleName 'Athena WC028 Monitoring Intent Key Reader'

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
    }
)
if ($null -ne $boundedReaderRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector bounded acquisition reader'
        Scope = $WorkloadResourceGroupResourceId
        RoleDefinitionId = $boundedReaderRoleDefinitionId
        ExpectedAssignmentId = $null
    }
}
if ($null -ne $changeWriterRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector change-evidence writer'
        Scope = $ChangeEvidenceContainerResourceId
        RoleDefinitionId = $changeWriterRoleDefinitionId
        ExpectedAssignmentId = $null
    }
}
if ($null -ne $intentKeyReaderRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector monitoring-intent key reader'
        Scope = $MonitoringIntentSigningKeyResourceId
        RoleDefinitionId = $intentKeyReaderRoleDefinitionId
        ExpectedAssignmentId = $null
    }
}

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
$reviewedObsoleteRoleDefinitionIds = @(
    $boundedReaderRoleDefinitionId,
    $changeWriterRoleDefinitionId
)
if ($null -ne $ipFlowRoleDefinition) {
    $reviewedObsoleteRoleDefinitionIds += $ipFlowRoleDefinitionId
}
foreach ($roleDefinitionId in $reviewedObsoleteRoleDefinitionIds) {
    if ($null -ne $roleDefinitionId) {
        $roleDefinitionGuid = $roleDefinitionId.TrimEnd('/').Split('/')[-1]
        Invoke-AzCommand -AzArguments @(
            'role', 'definition', 'delete',
            '--name', $roleDefinitionGuid,
            '--subscription', $SubscriptionId
        )
        Assert-RoleDefinitionAbsent -RoleDefinitionId $roleDefinitionId
        $removedRoleDefinitionIds.Add([string]$roleDefinitionId)
    }
}
Assert-RoleDefinitionAbsent -RoleDefinitionId $ipFlowRoleDefinitionId

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
        $reviewedObsoleteRoleDefinitionIds |
            Where-Object { $null -ne $_ } |
            ForEach-Object {
                Normalize-ResourceId -ResourceId ([string]$_)
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
