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
    return $ResourceId.TrimEnd('/')
}

function Test-NormalizedStringCollection {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actual,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected
    )

    $actualNormalized = @(
        $Actual |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object
    )
    $expectedNormalized = @(
        $Expected |
            ForEach-Object { $_.ToLowerInvariant() } |
            Sort-Object
    )
    return (
        $actualNormalized.Count -eq $expectedNormalized.Count -and
        ($actualNormalized -join "`n") -ceq ($expectedNormalized -join "`n")
    )
}

function Test-ReviewedRoleDefinitionBody {
    param(
        [Parameter(Mandatory)][object]$RoleDefinition,
        [Parameter(Mandatory)][object]$Target
    )

    $permissions = @($RoleDefinition.permissions)
    if (
        [string]$RoleDefinition.roleType -cne 'CustomRole' -or
        $permissions.Count -ne 1
    ) {
        return $false
    }
    $permission = $permissions[0]
    $assignableScopes = @(
        @($RoleDefinition.assignableScopes) |
            ForEach-Object { Normalize-ResourceId -ResourceId ([string]$_) }
    )
    return (
        (
            Test-NormalizedStringCollection `
                -Actual @($permission.actions) `
                -Expected $Target.ExpectedActions
        ) -and
        @($permission.notActions).Count -eq 0 -and
        (
            Test-NormalizedStringCollection `
                -Actual @($permission.dataActions) `
                -Expected $Target.ExpectedDataActions
        ) -and
        @($permission.notDataActions).Count -eq 0 -and
        $assignableScopes.Count -eq 1 -and
        $assignableScopes[0] -ceq (
            Normalize-ResourceId -ResourceId ([string]$Target.ExpectedAssignableScope)
        )
    )
}

function Get-RoleDefinitionGuid {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)

    $normalized = Normalize-ResourceId -ResourceId $RoleDefinitionId
    $expectedPrefix = (
        "/subscriptions/$($SubscriptionId.ToLowerInvariant())/providers/" +
        'microsoft.authorization/roledefinitions/'
    )
    if (-not $normalized.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
        throw "Role definition '$RoleDefinitionId' is not defined in SubscriptionId."
    }
    $guidText = $normalized.Substring($expectedPrefix.Length)
    [Guid]$parsedGuid = [Guid]::Empty
    if (
        $guidText.Contains('/') -or
        -not [Guid]::TryParse($guidText, [ref]$parsedGuid) -or
        $parsedGuid -eq [Guid]::Empty
    ) {
        throw "Role definition '$RoleDefinitionId' does not end in one non-nil GUID."
    }
    return $guidText
}

function Get-RoleAssignmentGuid {
    param(
        [Parameter(Mandatory)][string]$RoleAssignmentId,
        [Parameter(Mandatory)][string]$ExpectedScope
    )

    $normalized = Normalize-ResourceId -ResourceId $RoleAssignmentId
    $expectedPrefix = (
        "$(Normalize-ResourceId -ResourceId $ExpectedScope)/providers/" +
        'microsoft.authorization/roleassignments/'
    )
    if (-not $normalized.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
        throw "Role assignment '$RoleAssignmentId' is outside its exact reviewed scope."
    }
    $guidText = $normalized.Substring($expectedPrefix.Length)
    [Guid]$parsedGuid = [Guid]::Empty
    if (
        $guidText.Contains('/') -or
        -not [Guid]::TryParse($guidText, [ref]$parsedGuid) -or
        $parsedGuid -eq [Guid]::Empty
    ) {
        throw "Role assignment '$RoleAssignmentId' does not end in one non-nil GUID."
    }
    return $guidText
}

function Get-CompleteCustomRoleDefinitionInventory {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('pre-cleanup', 'post-cleanup')]
        [string]$Phase,
        [Parameter(Mandatory)][object]$Target
    )

    $items = @(
        Invoke-AzJson -AzArguments @(
            'role', 'definition', 'list',
            '--custom-role-only', 'true',
            '--scope', ([string]$Target.ExpectedAssignableScope),
            '--subscription', $SubscriptionId
        )
    )
    return [pscustomobject]@{
        Phase = $Phase
        QueryKind = 'complete-known-scope-custom-role-enumeration'
        TargetKey = [string]$Target.Key
        Scope = Normalize-ResourceId -ResourceId ([string]$Target.ExpectedAssignableScope)
        Items = $items
    }
}

function Get-CompleteTargetRoleAssignmentInventory {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('pre-cleanup', 'post-cleanup')]
        [string]$Phase,
        [Parameter(Mandatory)][object]$Target
    )

    $items = @(
        Invoke-AzJson -AzArguments @(
            'role', 'assignment', 'list',
            '--assignee-object-id', $CollectorPrincipalId,
            '--all',
            '--fill-role-definition-name', 'true',
            '--subscription', $SubscriptionId
        )
    )
    return [pscustomobject]@{
        Phase = $Phase
        QueryKind = 'independent-complete-subscription-principal-assignment-enumeration'
        TargetKey = [string]$Target.Key
        Scope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
        RequestedTargetScope = Normalize-ResourceId -ResourceId ([string]$Target.Scope)
        PrincipalId = $CollectorPrincipalId.ToLowerInvariant()
        Items = $items
    }
}

function Resolve-ReviewedHistoricalRoleDefinition {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target
    )

    if (
        [string]$Inventory.QueryKind -cne 'complete-known-scope-custom-role-enumeration' -or
        [string]$Inventory.TargetKey -cne [string]$Target.Key -or
        (Normalize-ResourceId -ResourceId ([string]$Inventory.Scope)) -cne (
            Normalize-ResourceId -ResourceId ([string]$Target.ExpectedAssignableScope)
        )
    ) {
        throw "$($Target.Name) was not resolved from its complete known-scope custom-role query."
    }
    $definitions = @($Inventory.Items)
    $roleNameCandidates = @(
        $definitions | Where-Object {
            [string]$_.roleName -ceq [string]$Target.ExpectedRoleName
        }
    )
    $caseInsensitiveRoleNameCandidates = @(
        $definitions | Where-Object {
            [string]$_.roleName -ieq [string]$Target.ExpectedRoleName
        }
    )
    if ($roleNameCandidates.Count -gt 1) {
        throw "$($Target.Name) resolved to duplicate exact role names."
    }
    if ($caseInsensitiveRoleNameCandidates.Count -gt $roleNameCandidates.Count) {
        throw "$($Target.Name) historical role name was changed in case or duplicated."
    }
    if (
        $roleNameCandidates.Count -eq 1 -and
        -not (
            Test-ReviewedRoleDefinitionBody `
                -RoleDefinition $roleNameCandidates[0] `
                -Target $Target
        )
    ) {
        throw "$($Target.Name) exact role name has unreviewed permissions or assignable scopes."
    }
    $bodyCandidates = @(
        $definitions | Where-Object {
            Test-ReviewedRoleDefinitionBody -RoleDefinition $_ -Target $Target
        }
    )
    if ($bodyCandidates.Count -gt 1) {
        throw "$($Target.Name) exact scope and permission body resolved ambiguously."
    }
    if ($roleNameCandidates.Count -eq 1) {
        if (
            $bodyCandidates.Count -ne 1 -or
            (
                Normalize-ResourceId -ResourceId ([string]$bodyCandidates[0].id)
            ) -cne (
                Normalize-ResourceId -ResourceId ([string]$roleNameCandidates[0].id)
            )
        ) {
            throw "$($Target.Name) exact role identity resolved inconsistently."
        }
        $roleDefinitionId = Normalize-ResourceId -ResourceId (
            [string]$roleNameCandidates[0].id
        )
        Get-RoleDefinitionGuid -RoleDefinitionId $roleDefinitionId | Out-Null
        return [pscustomobject]@{
            Status = 'found'
            RoleDefinition = $roleNameCandidates[0]
            RoleDefinitionId = $roleDefinitionId
            DiscoveryProof = 'exact-name-permissions-assignable-scopes-from-complete-known-scope-query'
        }
    }
    if ($bodyCandidates.Count -eq 1) {
        throw (
            "$($Target.Name) has the reviewed permissions and assignable scopes under " +
            "renamed role '$([string]$bodyCandidates[0].roleName)'; refusing destructive cleanup."
        )
    }
    return [pscustomobject]@{
        Status = 'provedAbsent'
        RoleDefinition = $null
        RoleDefinitionId = $null
        DiscoveryProof = (
            'complete known-scope custom-role enumeration contained neither the exact ' +
            'historical name nor its exact reviewed permissions and assignable scopes'
        )
    }
}

function Assert-ReviewedHistoricalRoleDefinitionAbsent {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target,
        [AllowNull()][string]$PreviouslyResolvedRoleDefinitionId
    )

    if (-not [string]::IsNullOrEmpty($PreviouslyResolvedRoleDefinitionId)) {
        $sameIdCandidates = @(
            @($Inventory.Items) | Where-Object {
                (Normalize-ResourceId -ResourceId ([string]$_.id)) -ceq (
                    Normalize-ResourceId -ResourceId $PreviouslyResolvedRoleDefinitionId
                )
            }
        )
        if ($sameIdCandidates.Count -ne 0) {
            throw "$($Target.Name) trusted role definition ID remains after cleanup."
        }
    }
    $postResolution = Resolve-ReviewedHistoricalRoleDefinition `
        -Inventory $Inventory `
        -Target $Target
    if ([string]$postResolution.Status -cne 'provedAbsent') {
        throw "$($Target.Name) remains after cleanup."
    }
    return [string]$postResolution.DiscoveryProof
}

function Resolve-ReviewedTargetRoleAssignment {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target
    )

    if (
        [string]$Inventory.QueryKind -cne (
            'independent-complete-subscription-principal-assignment-enumeration'
        ) -or
        [string]$Inventory.TargetKey -cne [string]$Target.Key -or
        (Normalize-ResourceId -ResourceId ([string]$Inventory.Scope)) -cne (
            "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
        ) -or
        (Normalize-ResourceId -ResourceId ([string]$Inventory.RequestedTargetScope)) -cne (
            Normalize-ResourceId -ResourceId ([string]$Target.Scope)
        ) -or
        [string]$Inventory.PrincipalId -cne $CollectorPrincipalId.ToLowerInvariant()
    ) {
        throw "$($Target.Name) was not resolved from its independent complete assignment query."
    }
    $normalizedScope = Normalize-ResourceId -ResourceId ([string]$Target.Scope)
    $scopePrincipalAssignments = @(
        @($Inventory.Items) | Where-Object {
            ([string]$_.principalId).ToLowerInvariant() -ceq (
                $CollectorPrincipalId.ToLowerInvariant()
            ) -and
            (Normalize-ResourceId -ResourceId ([string]$_.scope)) -ceq $normalizedScope
        }
    )
    $candidateAssignments = @(
        if ($null -eq $Target.RoleDefinitionId) {
            $unresolvedRoleAssignments = @(
                $scopePrincipalAssignments | Where-Object {
                    [string]::IsNullOrEmpty([string]$_.roleDefinitionName)
                }
            )
            if ($unresolvedRoleAssignments.Count -ne 0) {
                throw (
                    "$($Target.Name) cannot prove assignment absence because the exact scope " +
                    'contains an assignment whose role definition name could not be resolved.'
                )
            }
            $caseInsensitiveNameCandidates = @(
                $scopePrincipalAssignments | Where-Object {
                    [string]$_.roleDefinitionName -ieq [string]$Target.RoleDefinitionName
                }
            )
            $exactNameCandidates = @(
                $caseInsensitiveNameCandidates | Where-Object {
                    [string]$_.roleDefinitionName -ceq [string]$Target.RoleDefinitionName
                }
            )
            if ($caseInsensitiveNameCandidates.Count -gt $exactNameCandidates.Count) {
                throw "$($Target.Name) assignment reports a case-changed historical role name."
            }
            $exactNameCandidates
        } else {
            $normalizedRoleDefinitionId = Normalize-ResourceId -ResourceId (
                [string]$Target.RoleDefinitionId
            )
            $scopePrincipalAssignments | Where-Object {
                (Normalize-ResourceId -ResourceId ([string]$_.roleDefinitionId)) -ceq (
                    $normalizedRoleDefinitionId
                )
            }
        }
    )
    if ($null -eq $Target.RoleDefinitionId -and $candidateAssignments.Count -ne 0) {
        throw (
            "$($Target.Name) assignment reports the historical role name after the complete " +
            'custom-role query proved that role identity absent.'
        )
    }
    if ($candidateAssignments.Count -gt 1) {
        throw "$($Target.Name) resolved to duplicate exact role assignments."
    }
    if ($candidateAssignments.Count -eq 1) {
        $assignment = $candidateAssignments[0]
        $reportedRoleName = [string]$assignment.roleDefinitionName
        if (
            [string]$assignment.principalType -cne 'ServicePrincipal' -or
            (
                -not [string]::IsNullOrEmpty($reportedRoleName) -and
                $reportedRoleName -cne [string]$Target.RoleDefinitionName
            ) -or
            $null -ne $assignment.condition -or
            $null -ne $assignment.conditionVersion
        ) {
            throw "$($Target.Name) role assignment does not match the exact reviewed body."
        }
        Get-RoleAssignmentGuid `
            -RoleAssignmentId ([string]$assignment.id) `
            -ExpectedScope ([string]$Target.Scope) | Out-Null
        return [pscustomobject]@{
            Status = 'found'
            RoleAssignment = $assignment
            RoleAssignmentId = Normalize-ResourceId -ResourceId ([string]$assignment.id)
            DiscoveryProof = (
                'actual returned roleDefinitionId, exact principal, and exact scope from an ' +
                'independent complete assignment enumeration'
            )
        }
    }
    return [pscustomobject]@{
        Status = 'provedAbsent'
        RoleAssignment = $null
        RoleAssignmentId = $null
        DiscoveryProof = (
            'independent complete subscription assignment enumeration for the exact principal ' +
            'contained no assignment with the trusted role identity and exact target scope'
        )
    }
}

function Assert-ReviewedTargetRoleAssignmentsAbsent {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target
    )

    $remainingTargetAssignment = Resolve-ReviewedTargetRoleAssignment `
        -Inventory $Inventory `
        -Target $Target
    if ([string]$remainingTargetAssignment.Status -cne 'provedAbsent') {
        throw "$($Target.Name) remains assigned after exact cleanup."
    }
    return [string]$remainingTargetAssignment.DiscoveryProof
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
    (Normalize-ResourceId -ResourceId ([string]$collectorIdentity.id)) -cne (
        Normalize-ResourceId -ResourceId $CollectorIdentityResourceId
    ) -or
    ([string]$collectorIdentity.principalId).ToLowerInvariant() -cne (
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
    (Normalize-ResourceId -ResourceId ([string]$networkWatcher.id)) -cne (
        Normalize-ResourceId -ResourceId $NetworkWatcherResourceId
    ) -or
    [string]$networkWatcher.name -cne 'NetworkWatcher_australiaeast' -or
    ([string]$networkWatcher.location).ToLowerInvariant() -cne 'australiaeast' -or
    [string]$networkWatcher.properties.provisioningState -cne 'Succeeded'
) {
    throw (
        'NetworkWatcherResourceId does not resolve to the exact reviewed ' +
        'name, location, state, and resource ID.'
    )
}
$networkWatcherId = Get-HistoricalNetworkWatcherResourceId `
    -ResourceId ([string]$networkWatcher.id)

$workloadResourceGroupName = Get-ExactResourceGroupName `
    -ResourceGroupResourceId $WorkloadResourceGroupResourceId
$workloadResourceGroup = Invoke-AzJson -AzArguments @(
    'group', 'show',
    '--name', $workloadResourceGroupName,
    '--subscription', $SubscriptionId
)
if (
    (Normalize-ResourceId -ResourceId ([string]$workloadResourceGroup.id)) -cne (
        Normalize-ResourceId -ResourceId $WorkloadResourceGroupResourceId
    ) -or
    [string]$workloadResourceGroup.name -cne $workloadResourceGroupName -or
    ([string]$workloadResourceGroup.location).ToLowerInvariant() -cne 'australiaeast' -or
    [string]$workloadResourceGroup.properties.provisioningState -cne 'Succeeded'
) {
    throw (
        'WorkloadResourceGroupResourceId does not resolve to the exact reviewed ' +
        'name, location, state, and resource ID.'
    )
}

$workloadResourceGroupId = [string]$workloadResourceGroup.id
$subscriptionScope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
$networkWatcherResourceGroupId = Get-ResourceGroupScope -ResourceId $networkWatcherId
$changeEvidenceResourceGroupId = Get-ResourceGroupScope `
    -ResourceId $ChangeEvidenceContainerResourceId
$monitoringIntentKeyResourceGroupId = Get-ResourceGroupScope `
    -ResourceId $MonitoringIntentSigningKeyResourceId

$historicalRoleDefinitions = @(
    [pscustomobject]@{
        Key = 'bounded-acquisition-reader'
        Name = 'collector bounded acquisition reader'
        ExpectedRoleName = 'Athena WC028 Bounded Acquisition Reader'
        ExpectedAssignableScope = $workloadResourceGroupId
        ExpectedActions = @(
            'Microsoft.Insights/eventtypes/values/read'
            'Microsoft.ResourceGraph/resources/read'
            'Microsoft.Resources/changes/read'
        )
        ExpectedDataActions = @()
        AssignmentScope = $workloadResourceGroupId
    },
    [pscustomobject]@{
        Key = 'change-evidence-create-only-writer'
        Name = 'collector change-evidence writer'
        ExpectedRoleName = 'Athena WC028 Change Evidence Create-Only Writer'
        ExpectedAssignableScope = $changeEvidenceResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        )
        AssignmentScope = $ChangeEvidenceContainerResourceId
    },
    [pscustomobject]@{
        Key = 'monitoring-intent-key-reader'
        Name = 'collector monitoring-intent key reader'
        ExpectedRoleName = 'Athena WC028 Monitoring Intent Key Reader'
        ExpectedAssignableScope = $monitoringIntentKeyResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.KeyVault/vaults/keys/read'
        )
        AssignmentScope = $MonitoringIntentSigningKeyResourceId
    },
    [pscustomobject]@{
        Key = 'network-watcher-ip-flow-verifier'
        Name = 'collector Network Watcher IP Flow verifier'
        ExpectedRoleName = 'Athena WC028 IP Flow Verifier'
        ExpectedAssignableScope = $networkWatcherResourceGroupId
        ExpectedActions = @(
            'Microsoft.Network/networkWatchers/ipFlowVerify/action'
        )
        ExpectedDataActions = @()
        AssignmentScope = $networkWatcherId
    }
)

$roleResolutionsByKey = @{}
foreach ($historicalRole in $historicalRoleDefinitions) {
    $preCleanupRoleInventory = Get-CompleteCustomRoleDefinitionInventory `
        -Phase 'pre-cleanup' `
        -Target $historicalRole
    $roleResolutionsByKey[$historicalRole.Key] = Resolve-ReviewedHistoricalRoleDefinition `
        -Inventory $preCleanupRoleInventory `
        -Target $historicalRole
}

$acrPullRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)
$storageBlobDataContributorRoleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

$targets = @(
    [pscustomobject]@{
        Key = 'collector-acr-pull'
        Name = 'collector ACR pull'
        Scope = $RegistryResourceId
        RoleDefinitionId = $acrPullRoleDefinitionId
        RoleDefinitionName = 'AcrPull'
        RoleDiscoveryProof = 'published built-in role definition ID'
    },
    [pscustomobject]@{
        Key = 'collector-broad-monitoring-evidence-contributor'
        Name = 'collector broad monitoring-evidence contributor'
        Scope = $MonitoringEvidenceContainerResourceId
        RoleDefinitionId = $storageBlobDataContributorRoleDefinitionId
        RoleDefinitionName = 'Storage Blob Data Contributor'
        RoleDiscoveryProof = 'published built-in role definition ID'
    }
)
foreach ($historicalRole in $historicalRoleDefinitions) {
    $resolution = $roleResolutionsByKey[$historicalRole.Key]
    $targets += [pscustomobject]@{
        Key = $historicalRole.Key
        Name = $historicalRole.Name
        Scope = $historicalRole.AssignmentScope
        RoleDefinitionId = $resolution.RoleDefinitionId
        RoleDefinitionName = $historicalRole.ExpectedRoleName
        RoleDiscoveryProof = $resolution.DiscoveryProof
    }
}

$removedAssignmentIds = [System.Collections.Generic.List[string]]::new()
$assignmentOutcomes = [System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    $preCleanupAssignmentInventory = Get-CompleteTargetRoleAssignmentInventory `
        -Phase 'pre-cleanup' `
        -Target $target
    $assignmentResolution = Resolve-ReviewedTargetRoleAssignment `
        -Inventory $preCleanupAssignmentInventory `
        -Target $target
    if ([string]$assignmentResolution.Status -eq 'found') {
        $roleAssignmentId = [string]$assignmentResolution.RoleAssignmentId
        Invoke-AzCommand -AzArguments @(
            'role', 'assignment', 'delete',
            '--ids', $roleAssignmentId
        )
        $removedAssignmentIds.Add($roleAssignmentId)
    }
    $assignmentOutcomes.Add(
        [ordered]@{
            target = $target.Name
            scope = (Normalize-ResourceId -ResourceId ([string]$target.Scope))
            roleDefinitionName = [string]$target.RoleDefinitionName
            roleDefinitionId = if ($null -eq $target.RoleDefinitionId) {
                $null
            } else {
                Normalize-ResourceId -ResourceId ([string]$target.RoleDefinitionId)
            }
            roleDiscoveryProof = [string]$target.RoleDiscoveryProof
            initialResolution = if ([string]$assignmentResolution.Status -eq 'found') {
                'foundAndRemoved'
            } else {
                'provedAbsent'
            }
            removedRoleAssignmentId = $assignmentResolution.RoleAssignmentId
            initialDiscoveryProof = [string]$assignmentResolution.DiscoveryProof
            postCleanupAbsenceProof = $null
        }
    )
}

$removedRoleDefinitionIds = [System.Collections.Generic.List[string]]::new()
foreach ($historicalRole in $historicalRoleDefinitions) {
    $resolution = $roleResolutionsByKey[$historicalRole.Key]
    if ([string]$resolution.Status -eq 'found') {
        $roleDefinitionId = [string]$resolution.RoleDefinitionId
        $roleDefinitionGuid = Get-RoleDefinitionGuid -RoleDefinitionId $roleDefinitionId
        Invoke-AzCommand -AzArguments @(
            'role', 'definition', 'delete',
            '--name', $roleDefinitionGuid,
            '--subscription', $SubscriptionId
        )
        $removedRoleDefinitionIds.Add($roleDefinitionId)
    }
}

$roleDefinitionOutcomes = [System.Collections.Generic.List[object]]::new()
foreach ($historicalRole in $historicalRoleDefinitions) {
    $resolution = $roleResolutionsByKey[$historicalRole.Key]
    $postCleanupRoleInventory = Get-CompleteCustomRoleDefinitionInventory `
        -Phase 'post-cleanup' `
        -Target $historicalRole
    $postCleanupProof = Assert-ReviewedHistoricalRoleDefinitionAbsent `
        -Inventory $postCleanupRoleInventory `
        -Target $historicalRole `
        -PreviouslyResolvedRoleDefinitionId $resolution.RoleDefinitionId
    $roleDefinitionOutcomes.Add(
        [ordered]@{
            target = $historicalRole.Name
            expectedRoleName = $historicalRole.ExpectedRoleName
            expectedAssignableScope = (
                Normalize-ResourceId -ResourceId $historicalRole.ExpectedAssignableScope
            )
            expectedActions = @($historicalRole.ExpectedActions | Sort-Object)
            expectedDataActions = @($historicalRole.ExpectedDataActions | Sort-Object)
            trustedRoleDefinitionId = if ($null -eq $resolution.RoleDefinitionId) {
                $null
            } else {
                Normalize-ResourceId -ResourceId ([string]$resolution.RoleDefinitionId)
            }
            initialResolution = [string]$resolution.Status
            discoveryProof = [string]$resolution.DiscoveryProof
            finalResolution = if ([string]$resolution.Status -eq 'found') {
                'removed'
            } else {
                'provedAbsent'
            }
            postCleanupAbsenceProof = $postCleanupProof
        }
    )
}

foreach ($target in $targets) {
    $postCleanupAssignmentInventory = Get-CompleteTargetRoleAssignmentInventory `
        -Phase 'post-cleanup' `
        -Target $target
    $postCleanupAssignmentProof = Assert-ReviewedTargetRoleAssignmentsAbsent `
        -Inventory $postCleanupAssignmentInventory `
        -Target $target
    $assignmentOutcome = $assignmentOutcomes | Where-Object {
        [string]$_.target -ceq [string]$target.Name
    }
    $assignmentOutcome.postCleanupAbsenceProof = $postCleanupAssignmentProof
}

$evidence = [ordered]@{
    schemaVersion = 'athena.wc028LegacyCollectorRbacCleanup.v5'
    subscriptionId = $SubscriptionId.ToLowerInvariant()
    collectorIdentityResourceId = (Normalize-ResourceId -ResourceId $CollectorIdentityResourceId)
    collectorPrincipalId = $CollectorPrincipalId.ToLowerInvariant()
    networkWatcherResourceId = (Normalize-ResourceId -ResourceId $networkWatcherId)
    enumerationContract = [ordered]@{
        customRoleDefinitions = (
            'independent pre/post complete custom-role enumerations at each exact known ' +
            'assignable scope; no name or GUID filter'
        )
        collectorRoleAssignments = (
            'independent pre/post complete subscription assignment enumerations per target for ' +
            'the exact collector principal, then exact returned roleDefinitionId and scope matching'
        )
    }
    armGuidGroundTruth = [ordered]@{
        deploymentDerivedVectorAvailable = $false
        localComputationSecurityUse = 'none'
        note = (
            'No real deployment-derived ARM guid result was found in reviewed repository, ' +
            'session, or read-only Azure evidence. Cleanup does not calculate, compare, record, ' +
            'or trust locally reconstructed GUID values.'
        )
    }
    roleDefinitionOutcomes = @($roleDefinitionOutcomes)
    roleAssignmentOutcomes = @($assignmentOutcomes)
    removedRoleAssignmentIds = @($removedAssignmentIds | Sort-Object)
    removedRoleDefinitionIds = @($removedRoleDefinitionIds | Sort-Object)
}
$evidenceJson = $evidence | ConvertTo-Json -Depth 12 -Compress
$digestBytes = [Text.Encoding]::UTF8.GetBytes($evidenceJson)
$digest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($digestBytes)
).ToLowerInvariant()

[ordered]@{
    cleanupEvidence = $evidence
    cleanupEvidenceDigest = "sha256:$digest"
} | ConvertTo-Json -Depth 14
