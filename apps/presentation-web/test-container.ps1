$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Image = 'athena-presentation-web:container-test'
$Port = 18080
$Root = Split-Path -Parent $PSCommandPath
$ContainerId = $null

function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
}

function Get-Response {
    param(
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][string]$Path
    )
    $Response = $Client.GetAsync("http://127.0.0.1:$Port$Path").GetAwaiter().GetResult()
    $Bytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    return [pscustomobject]@{
        Status = [int]$Response.StatusCode
        ContentType = $Response.Content.Headers.ContentType.MediaType
        CacheControl = ($Response.Headers.GetValues('Cache-Control') -join ', ')
        Csp = ($Response.Headers.GetValues('Content-Security-Policy') -join ', ')
        NoSniff = ($Response.Headers.GetValues('X-Content-Type-Options') -join ', ')
        ReferrerPolicy = ($Response.Headers.GetValues('Referrer-Policy') -join ', ')
        PermissionsPolicy = ($Response.Headers.GetValues('Permissions-Policy') -join ', ')
        Bytes = $Bytes
    }
}

try {
    Push-Location $Root
    try {
        Invoke-Docker -Arguments @('build', '--file', 'Dockerfile', '--tag', $Image, '.')
    }
    finally {
        Pop-Location
    }

    $ContainerId = (& docker run --detach --rm --publish "127.0.0.1:${Port}:8080" $Image).Trim()
    if ($LASTEXITCODE -ne 0 -or $ContainerId -notmatch '^[a-f0-9]{12,64}$') {
        throw 'docker run did not return a container ID'
    }

    $Client = [System.Net.Http.HttpClient]::new()
    try {
        $Ready = $false
        foreach ($Attempt in 1..30) {
            try {
                $Health = Get-Response -Client $Client -Path '/healthz'
                if ($Health.Status -eq 200) {
                    $Ready = $true
                    break
                }
            }
            catch {
                Start-Sleep -Milliseconds 500
            }
        }
        if (-not $Ready) { throw 'presentation container did not become healthy' }

        $NoGatewayManifest = Get-Response -Client $Client -Path '/runtime-manifest.json'
        $PublicKey = Get-Response -Client $Client -Path '/trust/presentation-public-key.jwk.json'
        $MissingJson = Get-Response -Client $Client -Path '/missing.json'
        $Spa = Get-Response -Client $Client -Path '/reviewed/route'
        $Index = Get-Response -Client $Client -Path '/'
        $IndexText = [Text.Encoding]::UTF8.GetString($Index.Bytes)
        $AssetMatch = [regex]::Match($IndexText, '\.(/assets/[^"'']+\.js)')
        if (-not $AssetMatch.Success) { throw 'content-addressed JavaScript asset was not found' }
        $Asset = Get-Response -Client $Client -Path $AssetMatch.Groups[1].Value

        if ($Health.Status -ne 200 -or $Health.ContentType -ne 'text/plain') {
            throw 'health endpoint contract changed'
        }
        if ($NoGatewayManifest.Status -eq 200) {
            throw 'runtime manifest unexpectedly bypassed the private gateway'
        }
        if ($PublicKey.Status -ne 200 -or $PublicKey.ContentType -ne 'application/json') {
            throw 'reviewed public key MIME or status changed'
        }
        $ExpectedPublicKey = [IO.File]::ReadAllBytes(
            (Join-Path $Root 'public/trust/presentation-public-key.jwk.json')
        )
        $ObservedHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($PublicKey.Bytes)
        )
        $ExpectedHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($ExpectedPublicKey)
        )
        if ($ObservedHash -ne $ExpectedHash) {
            throw 'NGINX changed the reviewed public key bytes'
        }
        if (
            $MissingJson.Status -ne 404 -or
            $MissingJson.ContentType -ne 'application/json' -or
            [Text.Encoding]::UTF8.GetString($MissingJson.Bytes).Contains('<!doctype html>')
        ) {
            throw 'missing JSON was rewritten to the SPA document'
        }
        if ($Spa.Status -ne 200 -or -not [Text.Encoding]::UTF8.GetString($Spa.Bytes).Contains('<!doctype html>')) {
            throw 'SPA root fallback changed'
        }
        if ($Index.CacheControl -ne 'no-store' -or $PublicKey.CacheControl -ne 'no-store') {
            throw 'HTML or reviewed public key caching is unsafe'
        }
        if ($Asset.CacheControl -ne 'public, max-age=31536000, immutable') {
            throw 'content-addressed asset caching changed'
        }
        foreach ($Response in @($Health, $NoGatewayManifest, $PublicKey, $MissingJson, $Spa, $Asset)) {
            if (
                -not $Response.Csp.Contains("frame-ancestors 'none'") -or
                $Response.NoSniff -ne 'nosniff' -or
                $Response.ReferrerPolicy -ne 'no-referrer' -or
                -not $Response.PermissionsPolicy.Contains('camera=()')
            ) {
                throw 'required presentation response headers changed'
            }
        }

        $Inspect = (& docker image inspect $Image --format '{{.Config.User}}|{{json .Config.Healthcheck}}')
        if ($LASTEXITCODE -ne 0 -or -not $Inspect.StartsWith('101:101|') -or -not $Inspect.Contains('/healthz')) {
            throw 'container user or healthcheck changed'
        }
    }
    finally {
        $Client.Dispose()
    }

    Write-Host 'Presentation container tests passed.'
}
finally {
    if ($ContainerId) {
        & docker stop $ContainerId | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to stop test container $ContainerId"
        }
    }
}