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
        [string]$RoleDefinition.description -cne [string]$Target.ExpectedDescription -or
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
        [string]$Phase
    )

    $items = @(
        Invoke-AzJson -AzArguments @(
            'role', 'definition', 'list',
            '--custom-role-only', 'true',
            '--subscription', $SubscriptionId
        )
    )
    return [pscustomobject]@{
        Phase = $Phase
        QueryKind = 'complete-subscription-custom-role-enumeration'
        Scope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
        Items = $items
    }
}

function Get-CompleteCollectorRoleAssignmentInventory {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('pre-cleanup', 'post-cleanup')]
        [string]$Phase
    )

    $items = @(
        Invoke-AzJson -AzArguments @(
            'role', 'assignment', 'list',
            '--assignee-object-id', $CollectorPrincipalId,
            '--all',
            '--subscription', $SubscriptionId
        )
    )
    return [pscustomobject]@{
        Phase = $Phase
        QueryKind = 'complete-subscription-descendant-principal-assignment-enumeration'
        Scope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
        PrincipalId = $CollectorPrincipalId.ToLowerInvariant()
        Items = $items
    }
}

function Resolve-ReviewedHistoricalRoleDefinition {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target
    )

    $subscriptionScope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
    if (
        [string]$Inventory.QueryKind -cne 'complete-subscription-custom-role-enumeration' -or
        (Normalize-ResourceId -ResourceId ([string]$Inventory.Scope)) -cne $subscriptionScope
    ) {
        throw "$($Target.Name) was not resolved from a complete subscription custom-role query."
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
        throw "$($Target.Name) exact role name has an unreviewed scope, description, or permission body."
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
            DiscoveryProof = 'exact-name-description-scope-permissions-from-complete-enumeration'
        }
    }
    if ($bodyCandidates.Count -eq 1) {
        throw (
            "$($Target.Name) has the reviewed description, scope, and permissions under " +
            "renamed role '$([string]$bodyCandidates[0].roleName)'; refusing destructive cleanup."
        )
    }
    return [pscustomobject]@{
        Status = 'provedAbsent'
        RoleDefinition = $null
        RoleDefinitionId = $null
        DiscoveryProof = (
            'complete subscription custom-role enumeration contained neither the exact ' +
            'historical name nor its exact reviewed description, scope, and permissions'
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

    $subscriptionScope = "/subscriptions/$($SubscriptionId.ToLowerInvariant())"
    if (
        [string]$Inventory.QueryKind -cne (
            'complete-subscription-descendant-principal-assignment-enumeration'
        ) -or
        (Normalize-ResourceId -ResourceId ([string]$Inventory.Scope)) -cne $subscriptionScope -or
        [string]$Inventory.PrincipalId -cne $CollectorPrincipalId.ToLowerInvariant()
    ) {
        throw "$($Target.Name) was not resolved from a complete collector assignment query."
    }
    $normalizedScope = Normalize-ResourceId -ResourceId ([string]$Target.Scope)
    $candidateAssignments = @(
        if ($null -eq $Target.RoleDefinitionId) {
            @($Inventory.Items) | Where-Object {
                ([string]$_.principalId).ToLowerInvariant() -ceq (
                    $CollectorPrincipalId.ToLowerInvariant()
                ) -and
                (Normalize-ResourceId -ResourceId ([string]$_.scope)) -ceq $normalizedScope -and
                [string]$_.roleDefinitionName -ieq [string]$Target.RoleDefinitionName
            }
        } else {
            $normalizedRoleDefinitionId = Normalize-ResourceId -ResourceId (
                [string]$Target.RoleDefinitionId
            )
            @($Inventory.Items) | Where-Object {
                ([string]$_.principalId).ToLowerInvariant() -ceq (
                    $CollectorPrincipalId.ToLowerInvariant()
                ) -and
                (Normalize-ResourceId -ResourceId ([string]$_.scope)) -ceq $normalizedScope -and
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
    }
    return $candidateAssignments
}

function Assert-ReviewedTargetRoleAssignmentsAbsent {
    param(
        [Parameter(Mandatory)][object]$Inventory,
        [Parameter(Mandatory)][object]$Target
    )

    $remainingTargetAssignments = @(
        Resolve-ReviewedTargetRoleAssignment -Inventory $Inventory -Target $Target
    )
    if ($remainingTargetAssignments.Count -ne 0) {
        throw "$($Target.Name) remains assigned after exact cleanup."
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
        ExpectedDescription = (
            'Read only Activity Log events and Resource Graph change history for the one ' +
            'approved workload resource group.'
        )
        ExpectedAssignableScope = $workloadResourceGroupId
        ExpectedActions = @(
            'Microsoft.Insights/eventtypes/values/read'
            'Microsoft.ResourceGraph/resources/read'
            'Microsoft.Resources/changes/read'
        )
        ExpectedDataActions = @()
        ArmGuidPreimage = @(
            $subscriptionScope
            'athena-wc028-bounded-acquisition-reader'
            $workloadResourceGroupId
        )
        AssignmentScope = $workloadResourceGroupId
    },
    [pscustomobject]@{
        Key = 'change-evidence-create-only-writer'
        Name = 'collector change-evidence writer'
        ExpectedRoleName = 'Athena WC028 Change Evidence Create-Only Writer'
        ExpectedDescription = (
            'Read one known Blob and create one conditionally named change-evidence Blob ' +
            'without list or delete permissions.'
        )
        ExpectedAssignableScope = $changeEvidenceResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        )
        ArmGuidPreimage = @(
            $subscriptionScope
            'athena-wc028-change-evidence-create-only'
            (Normalize-ResourceId -ResourceId $ChangeEvidenceContainerResourceId)
        )
        AssignmentScope = $ChangeEvidenceContainerResourceId
    },
    [pscustomobject]@{
        Key = 'monitoring-intent-key-reader'
        Name = 'collector monitoring-intent key reader'
        ExpectedRoleName = 'Athena WC028 Monitoring Intent Key Reader'
        ExpectedDescription = (
            'Read only the public material and properties of the exact monitoring-intent ' +
            'signing key.'
        )
        ExpectedAssignableScope = $monitoringIntentKeyResourceGroupId
        ExpectedActions = @()
        ExpectedDataActions = @(
            'Microsoft.KeyVault/vaults/keys/read'
        )
        ArmGuidPreimage = @(
            $subscriptionScope
            'athena-wc028-monitoring-intent-key-reader'
            (Normalize-ResourceId -ResourceId $MonitoringIntentSigningKeyResourceId)
        )
        AssignmentScope = $MonitoringIntentSigningKeyResourceId
    },
    [pscustomobject]@{
        Key = 'network-watcher-ip-flow-verifier'
        Name = 'collector Network Watcher IP Flow verifier'
        ExpectedRoleName = 'Athena WC028 IP Flow Verifier'
        ExpectedDescription = (
            'Run only the read-only IP Flow Verify diagnostic on the reviewed Network Watcher.'
        )
        ExpectedAssignableScope = $networkWatcherResourceGroupId
        ExpectedActions = @(
            'Microsoft.Network/networkWatchers/ipFlowVerify/action'
        )
        ExpectedDataActions = @()
        ArmGuidPreimage = @(
            $subscriptionScope
            'athena-wc028-ip-flow-verify'
            $networkWatcherId
        )
        AssignmentScope = $networkWatcherId
    }
)

$preCleanupRoleInventory = Get-CompleteCustomRoleDefinitionInventory -Phase 'pre-cleanup'
$roleResolutionsByKey = @{}
foreach ($historicalRole in $historicalRoleDefinitions) {
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

$preCleanupAssignmentInventory = Get-CompleteCollectorRoleAssignmentInventory `
    -Phase 'pre-cleanup'
$removedAssignmentIds = [System.Collections.Generic.List[string]]::new()
$assignmentOutcomes = [System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    $targetAssignments = @(
        Resolve-ReviewedTargetRoleAssignment `
            -Inventory $preCleanupAssignmentInventory `
            -Target $target
    )
    $status = 'provedAbsent'
    $roleAssignmentId = $null
    if ($targetAssignments.Count -eq 1) {
        $roleAssignmentId = Normalize-ResourceId -ResourceId (
            [string]$targetAssignments[0].id
        )
        Invoke-AzCommand -AzArguments @(
            'role', 'assignment', 'delete',
            '--ids', $roleAssignmentId
        )
        $removedAssignmentIds.Add($roleAssignmentId)
        $status = 'foundAndRemoved'
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
            initialResolution = $status
            removedRoleAssignmentId = $roleAssignmentId
            initialAbsenceProof = if ($status -eq 'provedAbsent') {
                (
                    'complete subscription-descendant assignment enumeration for the exact ' +
                    'collector principal contained no exact target scope and trusted role identity'
                )
            } else {
                $null
            }
            postCleanupAbsenceProof = (
                'fresh complete subscription-descendant assignment enumeration for the exact ' +
                'collector principal contained no exact target scope and trusted role identity'
            )
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

$postCleanupRoleInventory = Get-CompleteCustomRoleDefinitionInventory -Phase 'post-cleanup'
$roleDefinitionOutcomes = [System.Collections.Generic.List[object]]::new()
foreach ($historicalRole in $historicalRoleDefinitions) {
    $resolution = $roleResolutionsByKey[$historicalRole.Key]
    $postCleanupProof = Assert-ReviewedHistoricalRoleDefinitionAbsent `
        -Inventory $postCleanupRoleInventory `
        -Target $historicalRole `
        -PreviouslyResolvedRoleDefinitionId $resolution.RoleDefinitionId
    $roleDefinitionOutcomes.Add(
        [ordered]@{
            target = $historicalRole.Name
            expectedRoleName = $historicalRole.ExpectedRoleName
            expectedDescription = $historicalRole.ExpectedDescription
            expectedAssignableScope = (
                Normalize-ResourceId -ResourceId $historicalRole.ExpectedAssignableScope
            )
            expectedActions = @($historicalRole.ExpectedActions | Sort-Object)
            expectedDataActions = @($historicalRole.ExpectedDataActions | Sort-Object)
            armGuidPreimage = @($historicalRole.ArmGuidPreimage)
            armGuidUse = 'recorded readiness evidence only; never locally hashed or trusted'
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

$postCleanupAssignmentInventory = Get-CompleteCollectorRoleAssignmentInventory `
    -Phase 'post-cleanup'
foreach ($target in $targets) {
    Assert-ReviewedTargetRoleAssignmentsAbsent `
        -Inventory $postCleanupAssignmentInventory `
        -Target $target
}

$evidence = [ordered]@{
    schemaVersion = 'athena.wc028LegacyCollectorRbacCleanup.v4'
    subscriptionId = $SubscriptionId.ToLowerInvariant()
    collectorIdentityResourceId = (Normalize-ResourceId -ResourceId $CollectorIdentityResourceId)
    collectorPrincipalId = $CollectorPrincipalId.ToLowerInvariant()
    networkWatcherResourceId = (Normalize-ResourceId -ResourceId $networkWatcherId)
    enumerationContract = [ordered]@{
        customRoleDefinitions = (
            'two independent complete subscription custom-role enumerations; no name or GUID filter'
        )
        collectorRoleAssignments = (
            'two independent complete subscription-descendant enumerations for the exact principal'
        )
    }
    armGuidGroundTruth = [ordered]@{
        deploymentDerivedVectorAvailable = $false
        localComputationSecurityUse = 'none'
        note = (
            'No reviewed deployment-derived ARM guid result is embedded. Historical preimages are ' +
            'recorded for readiness only and cannot prove discovery, deletion, or absence.'
        )
    }
    roleDefinitionOutcomes = @($roleDefinitionOutcomes)
    roleAssignmentOutcomes = @($assignmentOutcomes)
    removedRoleAssignmentIds = @($removedAssignmentIds | Sort-Object)
    removedRoleDefinitionIds = @($removedRoleDefinitionIds | Sort-Object)
    postCleanupAssignmentAbsenceProof = (
        'fresh complete subscription-descendant assignment enumeration for the exact principal'
    )
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
