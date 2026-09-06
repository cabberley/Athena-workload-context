#Requires -Version 7.4

[CmdletBinding()]
param(
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId = 'a6add389-9978-47ac-ab1e-a09212e321d4',

    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName = 'rg-athena-wc013-live',

    [switch]$Apply,

    [string]$ReportPath = '',

    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$LegacyNormalizerPrincipalId = '',

    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$LegacyOrchestratorPrincipalId = '',

    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$LegacyNotificationPrincipalId = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot '.azure\wc016-legacy-cleanup-report.json'
}
$resolvedReportPath = [System.IO.Path]::GetFullPath($ReportPath)

$namespaceName = 'athena-wc013-live-wc016-events'
$logicAppName = 'athena-wc016-teams-notifier'
$evidenceIdentityName = 'athena-wc013-live-mcp-evidence-id'
$senderRoleDefinitionGuid = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
$receiverRoleDefinitionGuid = '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'
$acrPullRoleDefinitionGuid = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
$keyVaultCryptoUserRoleDefinitionGuid = '12338af0-0e69-4776-bea7-57ae8d297424'
$storageBlobDataContributorRoleDefinitionGuid = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
$resourceGroupId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
$namespaceId = "$resourceGroupId/providers/Microsoft.ServiceBus/namespaces/$namespaceName"
$senderRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$senderRoleDefinitionGuid"
$receiverRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$receiverRoleDefinitionGuid"
$acrPullRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$acrPullRoleDefinitionGuid"
$keyVaultCryptoUserRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$keyVaultCryptoUserRoleDefinitionGuid"
$storageBlobDataContributorRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$storageBlobDataContributorRoleDefinitionGuid"
$registryId = "/subscriptions/$SubscriptionId/resourceGroups/rg-athena-platform-dev/providers/Microsoft.ContainerRegistry/registries/athenademoa6add389"
$legacySigningKeyId = "$resourceGroupId/providers/Microsoft.KeyVault/vaults/athenawc013a6add389/keys/wc013-signing"
$legacyPresentationContainerId = "$resourceGroupId/providers/Microsoft.Storage/storageAccounts/athenawc013a6add389/blobServices/default/containers/presentation-assets"

$legacyResources = @(
    [pscustomobject][ordered]@{
        category = 'job'
        name = 'athena-wc013-live-w16-det'
        resourceId = "$resourceGroupId/providers/Microsoft.App/jobs/athena-wc013-live-w16-det"
        apiVersion = '2025-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'job'
        name = 'athena-wc013-live-w16-orch'
        resourceId = "$resourceGroupId/providers/Microsoft.App/jobs/athena-wc013-live-w16-orch"
        apiVersion = '2025-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'job'
        name = 'athena-wc013-live-w16-norm'
        resourceId = "$resourceGroupId/providers/Microsoft.App/jobs/athena-wc013-live-w16-norm"
        apiVersion = '2025-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'job'
        name = 'athena-wc013-live-w16-notify'
        resourceId = "$resourceGroupId/providers/Microsoft.App/jobs/athena-wc013-live-w16-notify"
        apiVersion = '2025-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'queue'
        name = 'raw-monitor-events'
        resourceId = "$namespaceId/queues/raw-monitor-events"
        apiVersion = '2024-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'queue'
        name = 'incident-reassessment-requests'
        resourceId = "$namespaceId/queues/incident-reassessment-requests"
        apiVersion = '2024-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'queue'
        name = 'incident-notification-outbox'
        resourceId = "$namespaceId/queues/incident-notification-outbox"
        apiVersion = '2024-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-database-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-database-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-web-0-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-web-0-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-web-1-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-web-1-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-web-2-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-web-2-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-load-balancer-vip-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-load-balancer-vip-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'metricAlert'
        name = 'athena-wc013-live-load-balancer-dip-availability'
        resourceId = "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/athena-wc013-live-load-balancer-dip-availability"
        apiVersion = '2018-03-01'
    }
    [pscustomobject][ordered]@{
        category = 'identity'
        name = 'athena-wc013-live-wc016-normalizer-id'
        resourceId = "$resourceGroupId/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-wc013-live-wc016-normalizer-id"
        apiVersion = '2024-11-30'
        suppliedPrincipalId = $LegacyNormalizerPrincipalId
    }
    [pscustomobject][ordered]@{
        category = 'identity'
        name = 'athena-wc013-live-wc016-orchestrator-id'
        resourceId = "$resourceGroupId/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-wc013-live-wc016-orchestrator-id"
        apiVersion = '2024-11-30'
        suppliedPrincipalId = $LegacyOrchestratorPrincipalId
    }
    [pscustomobject][ordered]@{
        category = 'identity'
        name = 'athena-wc013-live-wc016-notification-id'
        resourceId = "$resourceGroupId/providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-wc013-live-wc016-notification-id"
        apiVersion = '2024-11-30'
        suppliedPrincipalId = $LegacyNotificationPrincipalId
    }
)

$protectedResources = @(
    [pscustomobject][ordered]@{
        category = 'evidenceIdentity'
        name = $evidenceIdentityName
        resourceId = "$resourceGroupId/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$evidenceIdentityName"
        apiVersion = '2024-11-30'
    }
    [pscustomobject][ordered]@{
        category = 'serviceBusNamespace'
        name = $namespaceName
        resourceId = $namespaceId
        apiVersion = '2024-01-01'
    }
    [pscustomobject][ordered]@{
        category = 'logicApp'
        name = $logicAppName
        resourceId = "$resourceGroupId/providers/Microsoft.Logic/workflows/$logicAppName"
        apiVersion = '2019-05-01'
    }
)

function Test-SameResourceId {
    param(
        [Parameter(Mandatory)]
        [string]$Left,

        [Parameter(Mandatory)]
        [string]$Right
    )

    return [string]::Equals(
        $Left.TrimEnd('/'),
        $Right.TrimEnd('/'),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Invoke-AzJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$AllowNotFound
    )

    $commandArguments = @($Arguments) + @('--only-show-errors', '--output', 'json')
    $output = @(& az @commandArguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = [string]::Join([Environment]::NewLine, [string[]]$output).Trim()

    if ($exitCode -ne 0) {
        if (
            $AllowNotFound -and
            $text -match '(?i)(ResourceNotFound|could not be found|was not found|does not exist|not found)'
        ) {
            return $null
        }
        throw "az $($Arguments -join ' ') failed with exit code ${exitCode}: $text"
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return $text | ConvertFrom-Json -Depth 50
}

function Invoke-AzDelete {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $commandArguments = @($Arguments) + @('--only-show-errors', '--output', 'none')
    $output = @(& az @commandArguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = [string]::Join([Environment]::NewLine, [string[]]$output).Trim()
    if (
        $exitCode -ne 0 -and
        $text -notmatch '(?i)(ResourceNotFound|could not be found|was not found|does not exist|not found)'
    ) {
        throw "az $($Arguments -join ' ') failed with exit code ${exitCode}: $text"
    }
}

function Get-ExactResource {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Descriptor
    )

    $resource = Invoke-AzJson -AllowNotFound -Arguments @(
        'resource'
        'show'
        '--subscription'
        $SubscriptionId
        '--ids'
        [string]$Descriptor.resourceId
        '--api-version'
        [string]$Descriptor.apiVersion
    )
    if ($null -eq $resource) {
        return $null
    }
    if (-not (Test-SameResourceId -Left ([string]$resource.id) -Right ([string]$Descriptor.resourceId))) {
        throw "Resolved resource ID did not exactly match the allowlisted ID: $($Descriptor.resourceId)"
    }
    return $resource
}

function Get-ResourceSnapshot {
    param(
        [Parameter(Mandatory)]
        [object[]]$Descriptors
    )

    $snapshot = foreach ($descriptor in $Descriptors) {
        $resource = Get-ExactResource -Descriptor $descriptor
        [pscustomobject][ordered]@{
            category = [string]$descriptor.category
            name = [string]$descriptor.name
            resourceId = [string]$descriptor.resourceId
            present = $null -ne $resource
        }
    }
    return @($snapshot)
}

function Get-PrincipalRoleAssignments {
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalId,

        [Parameter(Mandatory)]
        [string]$PrincipalName
    )

    $assignmentResult = Invoke-AzJson -Arguments @(
        'role'
        'assignment'
        'list'
        '--subscription'
        $SubscriptionId
        '--assignee-object-id'
        $PrincipalId
        '--all'
    )
    if ($null -eq $assignmentResult) {
        return @()
    }
    $assignments = @($assignmentResult)
    $subscriptionPrefix = "/subscriptions/$SubscriptionId/"
    $normalized = foreach ($assignment in $assignments) {
        if (
            [string]::Equals(
                [string]$assignment.principalId,
                $PrincipalId,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            ([string]$assignment.id).StartsWith(
                $subscriptionPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            [pscustomobject][ordered]@{
                principalName = $PrincipalName
                principalId = $PrincipalId.ToLowerInvariant()
                assignmentId = ([string]$assignment.id).ToLowerInvariant()
                scope = ([string]$assignment.scope).ToLowerInvariant()
                roleDefinitionId = ([string]$assignment.roleDefinitionId).ToLowerInvariant()
            }
        }
    }
    if ($null -eq $normalized) {
        return @()
    }
    return @($normalized | Sort-Object -Property assignmentId)
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

if ($null -eq (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is required.'
}

$account = Invoke-AzJson -Arguments @('account', 'show', '--subscription', $SubscriptionId)
if (
    -not [string]::Equals(
        [string]$account.id,
        $SubscriptionId,
        [System.StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "Azure CLI did not resolve the exact subscription $SubscriptionId."
}

$resourceGroup = Invoke-AzJson -Arguments @(
    'group'
    'show'
    '--subscription'
    $SubscriptionId
    '--name'
    $ResourceGroupName
)
if (-not (Test-SameResourceId -Left ([string]$resourceGroup.id) -Right $resourceGroupId)) {
    throw "Azure CLI did not resolve the exact resource group $resourceGroupId."
}

$protectedIds = @($protectedResources | ForEach-Object { ([string]$_.resourceId).ToLowerInvariant() })
foreach ($legacyResource in $legacyResources) {
    if ($protectedIds -contains ([string]$legacyResource.resourceId).ToLowerInvariant()) {
        throw "A deletion target overlaps a protected resource: $($legacyResource.resourceId)"
    }
}

$startedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
$beforeResources = Get-ResourceSnapshot -Descriptors $legacyResources
$beforeProtectedResources = Get-ResourceSnapshot -Descriptors $protectedResources
$evidenceIdentity = Get-ExactResource -Descriptor $protectedResources[0]
if ($null -eq $evidenceIdentity) {
    throw "Protected evidence identity $evidenceIdentityName was not found; its exact queue sender assignment cannot be audited."
}
$evidencePrincipalId = [string]$evidenceIdentity.properties.principalId

$resolvedLegacyPrincipals = @()
$unresolvedLegacyPrincipals = @()
foreach ($identityDescriptor in @($legacyResources | Where-Object { $_.category -eq 'identity' })) {
    $identity = Get-ExactResource -Descriptor $identityDescriptor
    $resolvedPrincipalId = if ($null -ne $identity) {
        [string]$identity.properties.principalId
    }
    else {
        [string]$identityDescriptor.suppliedPrincipalId
    }

    if ([string]::IsNullOrWhiteSpace($resolvedPrincipalId)) {
        $unresolvedLegacyPrincipals += [string]$identityDescriptor.name
        continue
    }
    if (
        $null -ne $identity -and
        -not [string]::IsNullOrWhiteSpace([string]$identityDescriptor.suppliedPrincipalId) -and
        -not [string]::Equals(
            [string]$identity.properties.principalId,
            [string]$identityDescriptor.suppliedPrincipalId,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Supplied principal ID does not match the exact identity $($identityDescriptor.name)."
    }
    $resolvedLegacyPrincipals += [pscustomobject][ordered]@{
        name = [string]$identityDescriptor.name
        principalId = $resolvedPrincipalId.ToLowerInvariant()
        resolution = if ($null -ne $identity) { 'identityReadback' } else { 'explicitParameter' }
    }
}

$beforeLegacyRoleAssignments = @(
    @(
        foreach ($principal in $resolvedLegacyPrincipals) {
            Get-PrincipalRoleAssignments `
                -PrincipalId ([string]$principal.principalId) `
                -PrincipalName ([string]$principal.name)
        }
    ) | Where-Object { $null -ne $_ } | Sort-Object -Property assignmentId
)
$expectedRoleAssignmentAllowlist = @(
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-normalizer-id'
        scope = "$namespaceId/queues/raw-monitor-events".ToLowerInvariant()
        roleDefinitionId = $receiverRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-normalizer-id'
        scope = "$namespaceId/queues/incident-reassessment-requests".ToLowerInvariant()
        roleDefinitionId = $senderRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-normalizer-id'
        scope = $registryId.ToLowerInvariant()
        roleDefinitionId = $acrPullRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-orchestrator-id'
        scope = "$namespaceId/queues/incident-reassessment-requests".ToLowerInvariant()
        roleDefinitionId = $receiverRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-orchestrator-id'
        scope = "$namespaceId/queues/incident-notification-outbox".ToLowerInvariant()
        roleDefinitionId = $senderRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-orchestrator-id'
        scope = $registryId.ToLowerInvariant()
        roleDefinitionId = $acrPullRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-orchestrator-id'
        scope = $legacySigningKeyId.ToLowerInvariant()
        roleDefinitionId = $keyVaultCryptoUserRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-orchestrator-id'
        scope = $legacyPresentationContainerId.ToLowerInvariant()
        roleDefinitionId = $storageBlobDataContributorRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-notification-id'
        scope = "$namespaceId/queues/incident-notification-outbox".ToLowerInvariant()
        roleDefinitionId = $receiverRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = 'athena-wc013-live-wc016-notification-id'
        scope = $registryId.ToLowerInvariant()
        roleDefinitionId = $acrPullRoleDefinitionId.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{
        principalName = $evidenceIdentityName
        scope = "$namespaceId/queues/incident-reassessment-requests".ToLowerInvariant()
        roleDefinitionId = $senderRoleDefinitionId.ToLowerInvariant()
    }
)
$beforeExpectedLegacyRoleAssignments = @(
    $beforeLegacyRoleAssignments | Where-Object {
        $assignment = $_
        @(
            $expectedRoleAssignmentAllowlist | Where-Object {
                $_.principalName -eq $assignment.principalName -and
                (Test-SameResourceId -Left $_.scope -Right $assignment.scope) -and
                (Test-SameResourceId -Left $_.roleDefinitionId -Right $assignment.roleDefinitionId)
            }
        ).Count -eq 1
    }
)
$beforeUnexpectedLegacyRoleAssignments = @(
    $beforeLegacyRoleAssignments | Where-Object {
        $assignment = $_
        @(
            $expectedRoleAssignmentAllowlist | Where-Object {
                $_.principalName -eq $assignment.principalName -and
                (Test-SameResourceId -Left $_.scope -Right $assignment.scope) -and
                (Test-SameResourceId -Left $_.roleDefinitionId -Right $assignment.roleDefinitionId)
            }
        ).Count -ne 1
    }
)
$beforeEvidenceRoleAssignments = @(
    Get-PrincipalRoleAssignments `
        -PrincipalId $evidencePrincipalId `
        -PrincipalName $evidenceIdentityName |
        Where-Object { $null -ne $_ }
)
$beforeEvidenceSenderAssignments = @(
    $beforeEvidenceRoleAssignments | Where-Object {
        (Test-SameResourceId -Left $_.scope -Right "$namespaceId/queues/incident-reassessment-requests") -and
        (Test-SameResourceId -Left $_.roleDefinitionId -Right $senderRoleDefinitionId)
    }
)
$beforeEvidenceSenderAssignmentIds = @(
    $beforeEvidenceSenderAssignments | ForEach-Object {
        [string]$_.assignmentId
    }
)
$beforeProtectedEvidenceRoleAssignments = @(
    $beforeEvidenceRoleAssignments | Where-Object {
        $beforeEvidenceSenderAssignmentIds -notcontains [string]$_.assignmentId
    }
)
$mutationBlocked = $beforeUnexpectedLegacyRoleAssignments.Count -ne 0

$actions = @()
$operationErrors = @()
foreach ($assignment in @(
    @($beforeExpectedLegacyRoleAssignments) + @($beforeEvidenceSenderAssignments)
)) {
    $action = [pscustomobject][ordered]@{
        operation = 'deleteRoleAssignment'
        target = [string]$assignment.assignmentId
        status = if ($mutationBlocked) {
            'blockedUnexpectedAssignment'
        }
        elseif ($Apply) {
            'pending'
        }
        else {
            'wouldDelete'
        }
    }
    $actions += $action
    Write-Host "$(if ($mutationBlocked) { 'BLOCKED' } elseif ($Apply) { 'DELETE' } else { 'WOULD DELETE' }): $($action.target)"
    if ($Apply -and -not $mutationBlocked) {
        try {
            Invoke-AzDelete -Arguments @(
                'role'
                'assignment'
                'delete'
                '--subscription'
                $SubscriptionId
                '--ids'
                [string]$assignment.assignmentId
            )
            $action.status = 'deleted'
        }
        catch {
            $action.status = 'failed'
            $operationErrors += [pscustomobject][ordered]@{
                target = [string]$assignment.assignmentId
                error = $_.Exception.Message
            }
        }
    }
}

foreach ($category in @('metricAlert', 'job', 'queue', 'identity')) {
    foreach ($descriptor in @($legacyResources | Where-Object { $_.category -eq $category })) {
        $present = @(
            $beforeResources | Where-Object {
                Test-SameResourceId -Left $_.resourceId -Right ([string]$descriptor.resourceId)
            }
        )[0].present
        $action = [pscustomobject][ordered]@{
            operation = 'deleteResource'
            target = [string]$descriptor.resourceId
            status = if ($mutationBlocked) {
                'blockedUnexpectedAssignment'
            }
            elseif (-not $present) {
                'alreadyAbsent'
            }
            elseif ($Apply) {
                'pending'
            }
            else {
                'wouldDelete'
            }
        }
        $actions += $action
        Write-Host "$(if ($mutationBlocked) { 'BLOCKED' } elseif (-not $present) { 'ABSENT' } elseif ($Apply) { 'DELETE' } else { 'WOULD DELETE' }): $($action.target)"
        if ($Apply -and -not $mutationBlocked -and $present) {
            try {
                Invoke-AzDelete -Arguments @(
                    'resource'
                    'delete'
                    '--subscription'
                    $SubscriptionId
                    '--ids'
                    [string]$descriptor.resourceId
                    '--api-version'
                    [string]$descriptor.apiVersion
                )
                $action.status = 'deleted'
            }
            catch {
                $action.status = 'failed'
                $operationErrors += [pscustomobject][ordered]@{
                    target = [string]$descriptor.resourceId
                    error = $_.Exception.Message
                }
            }
        }
    }
}

$afterResources = Get-ResourceSnapshot -Descriptors $legacyResources
$afterProtectedResources = Get-ResourceSnapshot -Descriptors $protectedResources
$afterLegacyRoleAssignments = @(
    @(
        foreach ($principal in $resolvedLegacyPrincipals) {
            Get-PrincipalRoleAssignments `
                -PrincipalId ([string]$principal.principalId) `
                -PrincipalName ([string]$principal.name)
        }
    ) | Where-Object { $null -ne $_ } | Sort-Object -Property assignmentId
)
$afterExpectedLegacyRoleAssignments = @(
    $afterLegacyRoleAssignments | Where-Object {
        $assignment = $_
        @(
            $expectedRoleAssignmentAllowlist | Where-Object {
                $_.principalName -eq $assignment.principalName -and
                (Test-SameResourceId -Left $_.scope -Right $assignment.scope) -and
                (Test-SameResourceId -Left $_.roleDefinitionId -Right $assignment.roleDefinitionId)
            }
        ).Count -eq 1
    }
)
$afterUnexpectedLegacyRoleAssignments = @(
    $afterLegacyRoleAssignments | Where-Object {
        $assignment = $_
        @(
            $expectedRoleAssignmentAllowlist | Where-Object {
                $_.principalName -eq $assignment.principalName -and
                (Test-SameResourceId -Left $_.scope -Right $assignment.scope) -and
                (Test-SameResourceId -Left $_.roleDefinitionId -Right $assignment.roleDefinitionId)
            }
        ).Count -ne 1
    }
)
$afterEvidenceRoleAssignments = @(
    Get-PrincipalRoleAssignments `
        -PrincipalId $evidencePrincipalId `
        -PrincipalName $evidenceIdentityName |
        Where-Object { $null -ne $_ }
)
$afterEvidenceSenderAssignments = @(
    $afterEvidenceRoleAssignments | Where-Object {
        (Test-SameResourceId -Left $_.scope -Right "$namespaceId/queues/incident-reassessment-requests") -and
        (Test-SameResourceId -Left $_.roleDefinitionId -Right $senderRoleDefinitionId)
    }
)
$afterEvidenceSenderAssignmentIds = @(
    $afterEvidenceSenderAssignments | ForEach-Object {
        [string]$_.assignmentId
    }
)
$afterProtectedEvidenceRoleAssignments = @(
    $afterEvidenceRoleAssignments | Where-Object {
        $afterEvidenceSenderAssignmentIds -notcontains [string]$_.assignmentId
    }
)

$protectedChanges = @(
    foreach ($before in $beforeProtectedResources) {
        $after = @(
            $afterProtectedResources | Where-Object {
                Test-SameResourceId -Left $_.resourceId -Right $before.resourceId
            }
        )[0]
        if ($before.present -ne $after.present) {
            [pscustomobject][ordered]@{
                resourceId = $before.resourceId
                beforePresent = $before.present
                afterPresent = $after.present
            }
        }
    }
)
$beforeLegacyMetricAlerts = @(
    $beforeResources | Where-Object { $_.category -eq 'metricAlert' }
)
$afterLegacyMetricAlerts = @(
    $afterResources | Where-Object { $_.category -eq 'metricAlert' }
)
$presentLegacyMetricAlertsBefore = @(
    $beforeLegacyMetricAlerts | Where-Object { $_.present }
)
$residualLegacyMetricAlerts = @(
    $afterLegacyMetricAlerts | Where-Object { $_.present }
)
$residualResources = @($afterResources | Where-Object { $_.present })
$beforeProtectedEvidenceRoleAssignmentIds = @(
    $beforeProtectedEvidenceRoleAssignments.assignmentId
)
$afterProtectedEvidenceRoleAssignmentIds = @(
    $afterProtectedEvidenceRoleAssignments.assignmentId
)
$protectedEvidenceRoleChanges = @(
    foreach ($assignmentId in $beforeProtectedEvidenceRoleAssignmentIds) {
        if ($afterProtectedEvidenceRoleAssignmentIds -notcontains $assignmentId) {
            [pscustomobject][ordered]@{
                assignmentId = $assignmentId
                change = 'removed'
            }
        }
    }
    foreach ($assignmentId in $afterProtectedEvidenceRoleAssignmentIds) {
        if ($beforeProtectedEvidenceRoleAssignmentIds -notcontains $assignmentId) {
            [pscustomobject][ordered]@{
                assignmentId = $assignmentId
                change = 'added'
            }
        }
    }
)
$zeroResidualReadback = (
    $residualResources.Count -eq 0 -and
    $afterExpectedLegacyRoleAssignments.Count -eq 0 -and
    $afterUnexpectedLegacyRoleAssignments.Count -eq 0 -and
    $afterEvidenceSenderAssignments.Count -eq 0 -and
    $unresolvedLegacyPrincipals.Count -eq 0 -and
    $protectedChanges.Count -eq 0 -and
    $protectedEvidenceRoleChanges.Count -eq 0 -and
    $operationErrors.Count -eq 0
)

$payload = [pscustomobject][ordered]@{
    operation = 'wc016LegacyRuntimeCleanup'
    mode = if ($Apply) { 'apply' } else { 'audit' }
    startedAtUtc = $startedAtUtc
    completedAtUtc = [DateTime]::UtcNow.ToString(
        'o',
        [Globalization.CultureInfo]::InvariantCulture
    )
    subscriptionId = $SubscriptionId.ToLowerInvariant()
    resourceGroupName = $ResourceGroupName
    exactLegacyResourceAllowlist = @($legacyResources | ForEach-Object { $_.resourceId })
    expectedRoleAssignmentAllowlist = @($expectedRoleAssignmentAllowlist)
    protectedResourceDenylist = @($protectedResources | ForEach-Object { $_.resourceId })
    resolvedLegacyPrincipals = @($resolvedLegacyPrincipals)
    unresolvedLegacyPrincipals = @($unresolvedLegacyPrincipals | Sort-Object)
    evidencePrincipalId = $evidencePrincipalId.ToLowerInvariant()
    before = [pscustomobject][ordered]@{
        resources = @($beforeResources)
        legacyMetricAlerts = @($beforeLegacyMetricAlerts)
        expectedLegacyPrincipalRoleAssignments = @($beforeExpectedLegacyRoleAssignments)
        unexpectedLegacyPrincipalRoleAssignments = @($beforeUnexpectedLegacyRoleAssignments)
        evidenceReassessmentSenderAssignments = @($beforeEvidenceSenderAssignments)
        protectedEvidenceRoleAssignments = @($beforeProtectedEvidenceRoleAssignments)
        protectedResources = @($beforeProtectedResources)
    }
    actions = @($actions)
    errors = @($operationErrors)
    after = [pscustomobject][ordered]@{
        resources = @($afterResources)
        legacyMetricAlerts = @($afterLegacyMetricAlerts)
        residualExpectedLegacyRoleAssignments = @($afterExpectedLegacyRoleAssignments)
        residualUnexpectedLegacyRoleAssignments = @($afterUnexpectedLegacyRoleAssignments)
        evidenceReassessmentSenderAssignments = @($afterEvidenceSenderAssignments)
        protectedEvidenceRoleAssignments = @($afterProtectedEvidenceRoleAssignments)
        protectedResources = @($afterProtectedResources)
    }
    verification = [pscustomobject][ordered]@{
        residualResourceCount = $residualResources.Count
        expectedLegacyMetricAlertCount = $beforeLegacyMetricAlerts.Count
        presentLegacyMetricAlertCountBefore = $presentLegacyMetricAlertsBefore.Count
        residualLegacyMetricAlertCount = $residualLegacyMetricAlerts.Count
        allLegacyMetricAlertsAbsentBefore = $presentLegacyMetricAlertsBefore.Count -eq 0
        allLegacyMetricAlertsAbsentAfter = $residualLegacyMetricAlerts.Count -eq 0
        expectedLegacyRoleAssignmentCountBefore = $beforeExpectedLegacyRoleAssignments.Count
        unexpectedLegacyRoleAssignmentCountBefore = $beforeUnexpectedLegacyRoleAssignments.Count
        evidenceSenderAssignmentCountBefore = $beforeEvidenceSenderAssignments.Count
        residualExpectedLegacyRoleAssignmentCount = $afterExpectedLegacyRoleAssignments.Count
        residualUnexpectedLegacyRoleAssignmentCount = $afterUnexpectedLegacyRoleAssignments.Count
        residualEvidenceSenderAssignmentCount = $afterEvidenceSenderAssignments.Count
        unresolvedLegacyPrincipalCount = $unresolvedLegacyPrincipals.Count
        protectedResourceChangeCount = $protectedChanges.Count
        protectedEvidenceRoleAssignmentChangeCount = $protectedEvidenceRoleChanges.Count
        operationErrorCount = $operationErrors.Count
        mutationBlockedByUnexpectedAssignment = $mutationBlocked
        zeroResidualReadback = $zeroResidualReadback
    }
}
$canonicalPayloadJson = $payload | ConvertTo-Json -Depth 20 -Compress
$report = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    digestAlgorithm = 'SHA-256'
    digestScope = 'UTF-8 bytes of the compact ordered payload JSON'
    payloadDigestSha256 = "sha256:$(Get-Sha256 -Text $canonicalPayloadJson)"
    payload = $payload
}
$canonicalReportJson = $report | ConvertTo-Json -Depth 20 -Compress
$reportDirectory = Split-Path -Parent $resolvedReportPath
if (-not (Test-Path $reportDirectory)) {
    $null = New-Item -ItemType Directory -Path $reportDirectory -Force
}
[System.IO.File]::WriteAllText(
    $resolvedReportPath,
    $canonicalReportJson + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output $canonicalReportJson
Write-Host "WC-016 cleanup report: $resolvedReportPath"
if ($mutationBlocked) {
    throw 'WC-016 cleanup blocked before mutation because a legacy principal has an unexpected role assignment.'
}
elseif (-not $Apply) {
    Write-Warning 'Audit only: no Azure resource was changed. Use -Apply only after reviewing this exact report.'
}
elseif (-not $zeroResidualReadback) {
    throw 'WC-016 cleanup did not produce a zero-residual readback. Do not confirm runtime activation.'
}
