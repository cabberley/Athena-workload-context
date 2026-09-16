[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ContainerRegistry/registries/[^/?#%]+$')]
    [string] $RegistryResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9.-]+\.azurecr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$')]
    [string] $Image,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $ManagedIdentityClientId,

    [Parameter(Mandatory)]
    [ValidateSet('LegacyRegistryPermissions', 'AbacRepositoryPermissions')]
    [string] $RegistryRoleAssignmentMode,

    [ValidateRange(1, 20)]
    [int] $MaxAttempts = 10,

    [ValidateRange(1, 60)]
    [int] $DelaySeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required for managed-identity ACR readiness verification.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required for an actual digest-pinned image pull readiness check.'
}

& az login --identity --client-id $ManagedIdentityClientId --allow-no-subscriptions --output none
if ($LASTEXITCODE -ne 0) {
    throw 'Managed-identity Azure login failed.'
}
& az account set --subscription $subscriptionId
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to select the registry subscription.'
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

$nullGuid = '00000000-0000-0000-0000-000000000000'
for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    $token = $null
    try {
        $token = (& az acr login --name $registryName --expose-token --query accessToken --output tsv).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
            throw 'ACR token acquisition is not ready.'
        }

        $token | & docker login $registryServer --username $nullGuid --password-stdin | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Docker login is not ready.'
        }

        & docker pull $Image | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Digest-pinned image pull is not ready.'
        }

        $repoDigestsJson = & docker image inspect $Image --format '{{json .RepoDigests}}'
        if ($LASTEXITCODE -ne 0) {
            throw 'Pulled image digest inspection failed.'
        }
        $repoDigests = @($repoDigestsJson | ConvertFrom-Json)
        if ($Image -notin $repoDigests) {
            throw 'Pulled image RepoDigest does not match the reviewed digest.'
        }

        [ordered]@{
            schemaVersion = 'athena.wc027AcrDigestPullReadiness.v1'
            registryResourceId = $RegistryResourceId
            registryServer = $registryServer
            image = $Image
            repositoryName = $repositoryName
            managedIdentityClientId = $ManagedIdentityClientId.ToLowerInvariant()
            roleAssignmentMode = $RegistryRoleAssignmentMode
            roleDefinitionId = $roleDefinitionId
            conditionVersion = $conditionVersion
            condition = $condition
            attempts = $attempt
            maxAttempts = $MaxAttempts
            verifiedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            success = $true
        } | ConvertTo-Json -Compress
        return
    }
    catch {
        if ($attempt -eq $MaxAttempts) {
            throw "Digest-pinned ACR pull did not become ready after $MaxAttempts bounded attempts."
        }
        Start-Sleep -Seconds $DelaySeconds
    }
    finally {
        $token = $null
        & docker logout $registryServer | Out-Null
    }
}
