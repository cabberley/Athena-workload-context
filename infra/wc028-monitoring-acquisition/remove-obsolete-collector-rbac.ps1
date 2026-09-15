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
    },
    [pscustomobject]@{
        Name = 'collector broad monitoring-evidence contributor'
        Scope = $MonitoringEvidenceContainerResourceId
        RoleDefinitionId = $storageBlobDataContributorRoleDefinitionId
    }
)
if ($null -ne $boundedReaderRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector bounded acquisition reader'
        Scope = $WorkloadResourceGroupResourceId
        RoleDefinitionId = $boundedReaderRoleDefinitionId
    }
}
if ($null -ne $changeWriterRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector change-evidence writer'
        Scope = $ChangeEvidenceContainerResourceId
        RoleDefinitionId = $changeWriterRoleDefinitionId
    }
}
if ($null -ne $intentKeyReaderRoleDefinitionId) {
    $targets += [pscustomobject]@{
        Name = 'collector monitoring-intent key reader'
        Scope = $MonitoringIntentSigningKeyResourceId
        RoleDefinitionId = $intentKeyReaderRoleDefinitionId
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
    $matches = @(
        $assignments | Where-Object {
            (Normalize-ResourceId -ResourceId ([string]$_.scope)) -eq $normalizedScope -and
            (Normalize-ResourceId -ResourceId ([string]$_.roleDefinitionId)) -eq $normalizedRole
        }
    )
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
foreach ($roleDefinitionId in @(
    $boundedReaderRoleDefinitionId,
    $changeWriterRoleDefinitionId
)) {
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
    schemaVersion = 'athena.wc028LegacyCollectorRbacCleanup.v2'
    subscriptionId = $SubscriptionId.ToLowerInvariant()
    collectorIdentityResourceId = (Normalize-ResourceId -ResourceId $CollectorIdentityResourceId)
    collectorPrincipalId = $CollectorPrincipalId.ToLowerInvariant()
    removedRoleAssignmentIds = @($removedAssignmentIds | Sort-Object)
    removedRoleDefinitionIds = @($removedRoleDefinitionIds | Sort-Object)
    verifiedAbsentBindings = @(
        $targets |
            ForEach-Object {
                [ordered]@{
                    scope = (Normalize-ResourceId -ResourceId $_.Scope)
                    roleDefinitionId = (Normalize-ResourceId -ResourceId $_.RoleDefinitionId)
                }
            } |
            Sort-Object scope, roleDefinitionId
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
