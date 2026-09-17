[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ContainerRegistry/registries/[^/?#%]+$')]
    [string] $RegistryResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9.-]+\.azurecr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$')]
    [string] $Image,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/resourceGroups/[^/?#%]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/?#%]+$')]
    [string] $ManagedIdentityResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $ManagedIdentityClientId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$')]
    [string] $ManagedIdentityPrincipalId,

    [Parameter(Mandatory)]
    [ValidateSet('LegacyRegistryPermissions', 'AbacRepositoryPermissions')]
    [string] $RegistryRoleAssignmentMode,

    [Parameter(Mandatory)]
    [ValidateLength(1, 2048)]
    [string] $RegistryPullRoleAssignmentResourceId,

    [Parameter(Mandatory)]
    [ValidateLength(2, 65536)]
    [string] $ExpectedPullAssignmentsJson,

    [ValidateRange(1, 20)]
    [int] $MaxAttempts = 10,

    [ValidateRange(1, 60)]
    [int] $DelaySeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RegistryReadback {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceId,

        [Parameter(Mandatory)]
        [string] $SubscriptionId,

        [Parameter(Mandatory)]
        [string] $ExpectedRoleAssignmentMode
    )

    $json = & az resource show `
        --ids $ResourceId `
        --subscription $SubscriptionId `
        --api-version '2025-04-01' `
        --only-show-errors `
        --output json
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($json)) {
        throw 'Live ACR management-plane readback failed.'
    }
    $registry = $json | ConvertFrom-Json
    if (
        [string]::IsNullOrWhiteSpace([string] $registry.id) -or
        -not [string]::Equals(
            [string] $registry.id,
            $ResourceId,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw 'Live ACR resource ID does not match RegistryResourceId.'
    }
    if (
        [string] $registry.properties.roleAssignmentMode -cne
        $ExpectedRoleAssignmentMode
    ) {
        throw 'Live ACR roleAssignmentMode does not match the reviewed mode.'
    }
    if ($registry.properties.anonymousPullEnabled -ne $false) {
        throw 'Live ACR anonymousPullEnabled must be explicitly false.'
    }
    return $registry
}

function Get-ManagedIdentityReadback {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceId,

        [Parameter(Mandatory)]
        [string] $ExpectedClientId,

        [Parameter(Mandatory)]
        [string] $ExpectedPrincipalId
    )

    $identityMatch = [regex]::Match(
        $ResourceId,
        '^/subscriptions/(?<subscription>[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})/resourceGroups/[^/?#%]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/?#%]+$'
    )
    if (-not $identityMatch.Success) {
        throw 'ManagedIdentityResourceId is not one canonical user-assigned identity ID.'
    }
    $json = & az resource show `
        --ids $ResourceId `
        --subscription $identityMatch.Groups['subscription'].Value `
        --api-version '2024-11-30' `
        --only-show-errors `
        --output json
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($json)) {
        throw 'Live managed-identity readback failed.'
    }
    $identity = $json | ConvertFrom-Json
    if (
        -not [string]::Equals(
            [string] $identity.id,
            $ResourceId,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string] $identity.properties.clientId,
            $ExpectedClientId,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string] $identity.properties.principalId,
            $ExpectedPrincipalId,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw 'Live managed-identity resource, client, and principal IDs do not match.'
    }
    return $identity
}

$registryMatch = [regex]::Match(
    $RegistryResourceId,
    '^/subscriptions/(?<subscription>[^/]+)/resourceGroups/(?<resourceGroup>[^/]+)/providers/Microsoft\.ContainerRegistry/registries/(?<registry>[^/?#%]+)$'
)
if (-not $registryMatch.Success) {
    throw 'RegistryResourceId is not one canonical Microsoft.ContainerRegistry/registries ID.'
}

$subscriptionId = $registryMatch.Groups['subscription'].Value
$registryName = $registryMatch.Groups['registry'].Value
$registryServer = "$($registryName.ToLowerInvariant()).azurecr.io"
if (-not $Image.StartsWith("$registryServer/", [System.StringComparison]::Ordinal)) {
    throw 'Image must use the exact registry login server derived from RegistryResourceId.'
}
$imageParts = $Image.Split(
    @('@sha256:'),
    2,
    [System.StringSplitOptions]::None
)
if ($imageParts.Count -ne 2) {
    throw 'Image must contain one exact sha256 digest separator.'
}
$repositoryPrefix = "$registryServer/"
$repositoryReference = $imageParts[0]
if (-not $repositoryReference.StartsWith(
    $repositoryPrefix,
    [System.StringComparison]::Ordinal
)) {
    throw 'Image repository must use the exact registry login server.'
}
$repositoryName = $repositoryReference.Substring($repositoryPrefix.Length)
if (
    [string]::IsNullOrWhiteSpace($repositoryName) -or
    $repositoryName -cne $repositoryName.ToLowerInvariant() -or
    $repositoryName.StartsWith('/') -or
    $repositoryName.EndsWith('/') -or
    $repositoryName.Contains('//') -or
    $repositoryName.IndexOfAny([char[]] '@:?#%') -ge 0
) {
    throw 'Image must identify one exact lowercase ACR repository.'
}

$roleDefinitionId = if ($RegistryRoleAssignmentMode -eq 'LegacyRegistryPermissions') {
    '7f951dda-4ed3-4680-a7ca-43fe172d538d'
}
else {
    'b93aa761-3e63-49ed-ac28-beffa264f7ac'
}
$conditionVersion = if (
    $RegistryRoleAssignmentMode -eq 'AbacRepositoryPermissions'
) {
    '2.0'
}
else {
    $null
}
$condition = if ($RegistryRoleAssignmentMode -eq 'AbacRepositoryPermissions') {
    "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/repositories/content/read'}) AND !(ActionMatches{'Microsoft.ContainerRegistry/registries/repositories/metadata/read'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase '$repositoryName'))"
}
else {
    $null
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required for managed-identity ACR readiness verification.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required for an actual digest-pinned image pull readiness check.'
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python is required for effective ACR assignment verification.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$effectiveAccessVerifier = Join-Path (
    $repoRoot
) 'scripts\verify_wc027_acr_effective_access.py'

function Get-EffectiveAccessEvidence {
    $json = & python `
        $effectiveAccessVerifier `
        --subscription-id $subscriptionId `
        --expected-assignments-json $ExpectedPullAssignmentsJson
    if (
        $LASTEXITCODE -ne 0 -or
        [string]::IsNullOrWhiteSpace($json)
    ) {
        throw 'Effective ACR assignment verification failed.'
    }
    $evidence = $json | ConvertFrom-Json
    if (
        $evidence.schemaVersion -cne
        'athena.wc027AcrEffectiveAccessEvidence.v1' -or
        $evidence.verified -ne $true -or
        $evidence.tenantSubscriptionHierarchyComplete -ne $true -or
        @($evidence.governedSubscriptionIds).Count -lt 1 -or
        $evidence.anonymousPullEnabled -ne $false -or
        $evidence.expectedAssignmentCount -ne 3 -or
        $evidence.pullCapableAssignmentCount -ne 3 -or
        $evidence.roleDefinitionsResolved -ne $true -or
        $evidence.exactAssignmentReadbacksComplete -ne $true -or
        $evidence.directAssignmentsComplete -ne $true -or
        $evidence.inheritedAssignmentsComplete -ne $true -or
        $evidence.transitiveGroupsComplete -ne $true -or
        $evidence.directMembershipTraversalComplete -ne $true -or
        $evidence.convergedMembershipReadbacks -ne $true -or
        $evidence.siblingRegistriesChecked -ne $true -or
        $evidence.acrEscalationPathsChecked -ne $true -or
        @($evidence.expectedAssignmentIds).Count -ne 3 -or
        @($evidence.principalIds).Count -ne 3 -or
        @($evidence.registryResourceIds).Count -lt 1 -or
        @($evidence.reviewedAssignments).Count -ne 3 -or
        @($evidence.extraPullCapableAssignmentIds).Count -ne 0 -or
        [string]::IsNullOrWhiteSpace([string] $evidence.tenantId) -or
        [string]::IsNullOrWhiteSpace([string] $evidence.evidenceDigest) -or
        [string]::IsNullOrWhiteSpace([string] $evidence.verifiedAt)
    ) {
        throw 'Effective ACR assignment evidence is invalid or incomplete.'
    }
    return $evidence
}

function Assert-PublisherAccessBinding {
    param(
        [Parameter(Mandatory)]
        [object] $Evidence
    )

    $publisherAccess = @(
        $Evidence.reviewedAssignments |
            Where-Object { $_.label -ceq 'publisher' }
    )
    if (
        $publisherAccess.Count -ne 1 -or
        -not [string]::Equals(
            [string] $publisherAccess[0].registryResourceId,
            $RegistryResourceId,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string] $publisherAccess[0].principalId,
            $ManagedIdentityPrincipalId,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string] $publisherAccess[0].assignmentResourceId,
            $RegistryPullRoleAssignmentResourceId,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        [string] $publisherAccess[0].repositoryName -cne $repositoryName -or
        [string] $publisherAccess[0].roleAssignmentMode -cne
        $RegistryRoleAssignmentMode -or
        [string] $publisherAccess[0].roleDefinitionId -cne
        $roleDefinitionId -or
        $publisherAccess[0].conditionVersion -cne $conditionVersion -or
        $publisherAccess[0].condition -cne $condition
    ) {
        throw 'Effective ACR assignment evidence does not match the exact publisher binding.'
    }
}

$prePullEffectiveAccessEvidence = Get-EffectiveAccessEvidence
Assert-PublisherAccessBinding -Evidence $prePullEffectiveAccessEvidence

$prePullRegistry = Get-RegistryReadback `
    -ResourceId $RegistryResourceId `
    -SubscriptionId $subscriptionId `
    -ExpectedRoleAssignmentMode $RegistryRoleAssignmentMode
$prePullIdentity = Get-ManagedIdentityReadback `
    -ResourceId $ManagedIdentityResourceId `
    -ExpectedClientId $ManagedIdentityClientId `
    -ExpectedPrincipalId $ManagedIdentityPrincipalId

$originalAzureConfigDir = $env:AZURE_CONFIG_DIR
$isolatedAzureConfigDir = Join-Path (
    [System.IO.Path]::GetTempPath()
) "athena-wc027-acr-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $isolatedAzureConfigDir
$nullGuid = '00000000-0000-0000-0000-000000000000'

try {
    $env:AZURE_CONFIG_DIR = $isolatedAzureConfigDir
    & az login `
        --identity `
        --client-id $ManagedIdentityClientId `
        --allow-no-subscriptions `
        --output none
    if ($LASTEXITCODE -ne 0) {
        throw 'Managed-identity Azure login failed.'
    }
    & az account set --subscription $subscriptionId
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to select the registry subscription for managed-identity pull.'
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $token = $null
        try {
            $token = (& az acr login `
                --name $registryName `
                --expose-token `
                --query accessToken `
                --output tsv).Trim()
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
                throw 'ACR token acquisition is not ready.'
            }

            $token | & docker login `
                $registryServer `
                --username $nullGuid `
                --password-stdin | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Docker login is not ready.'
            }

            & docker pull $Image | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Digest-pinned image pull is not ready.'
            }

            $repoDigestsJson = & docker image inspect `
                $Image `
                --format '{{json .RepoDigests}}'
            if ($LASTEXITCODE -ne 0) {
                throw 'Pulled image digest inspection failed.'
            }
            $repoDigests = @($repoDigestsJson | ConvertFrom-Json)
            if ($Image -notin $repoDigests) {
                throw 'Pulled image RepoDigest does not match the reviewed digest.'
            }

            if ([string]::IsNullOrEmpty($originalAzureConfigDir)) {
                Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
            }
            else {
                $env:AZURE_CONFIG_DIR = $originalAzureConfigDir
            }
            $postPullRegistry = Get-RegistryReadback `
                -ResourceId $RegistryResourceId `
                -SubscriptionId $subscriptionId `
                -ExpectedRoleAssignmentMode $RegistryRoleAssignmentMode
            $postPullIdentity = Get-ManagedIdentityReadback `
                -ResourceId $ManagedIdentityResourceId `
                -ExpectedClientId $ManagedIdentityClientId `
                -ExpectedPrincipalId $ManagedIdentityPrincipalId
            $postPullEffectiveAccessEvidence = Get-EffectiveAccessEvidence
            Assert-PublisherAccessBinding `
                -Evidence $postPullEffectiveAccessEvidence
            if (
                $prePullRegistry.properties.anonymousPullEnabled -ne $false -or
                $postPullRegistry.properties.anonymousPullEnabled -ne $false -or
                -not [string]::Equals(
                    [string] $prePullIdentity.properties.clientId,
                    [string] $postPullIdentity.properties.clientId,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [string] $prePullIdentity.properties.principalId,
                    [string] $postPullIdentity.properties.principalId,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [string] $prePullEffectiveAccessEvidence.evidenceDigest,
                    [string] $postPullEffectiveAccessEvidence.evidenceDigest,
                    [System.StringComparison]::Ordinal
                )
            ) {
                throw 'Registry, identity, or effective ACR access changed during digest-pull verification.'
            }

            [ordered]@{
                schemaVersion = 'athena.wc027AcrDigestPullReadiness.v1'
                registryResourceId = $RegistryResourceId
                registryServer = $registryServer
                image = $Image
                repositoryName = $repositoryName
                managedIdentityResourceId = $ManagedIdentityResourceId
                managedIdentityClientId = $ManagedIdentityClientId.ToLowerInvariant()
                managedIdentityPrincipalId = $ManagedIdentityPrincipalId
                roleAssignmentMode = $RegistryRoleAssignmentMode
                anonymousPullEnabled = $false
                roleDefinitionId = $roleDefinitionId
                roleAssignmentResourceId = $RegistryPullRoleAssignmentResourceId
                conditionVersion = $conditionVersion
                condition = $condition
                effectiveAccess = $postPullEffectiveAccessEvidence
                attempts = $attempt
                maxAttempts = $MaxAttempts
                verifiedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                success = $true
            } | ConvertTo-Json -Depth 8 -Compress
            return
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                throw "Digest-pinned ACR pull did not become ready after $MaxAttempts bounded attempts."
            }
            Start-Sleep -Seconds $DelaySeconds
            $env:AZURE_CONFIG_DIR = $isolatedAzureConfigDir
        }
        finally {
            $token = $null
            & docker logout $registryServer | Out-Null
        }
    }
}
finally {
    if ([string]::IsNullOrEmpty($originalAzureConfigDir)) {
        Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:AZURE_CONFIG_DIR = $originalAzureConfigDir
    }
    if (Test-Path -LiteralPath $isolatedAzureConfigDir) {
        Remove-Item -LiteralPath $isolatedAzureConfigDir -Recurse -Force
    }
}
