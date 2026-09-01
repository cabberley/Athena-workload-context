$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Image = 'athena-wc013-controller:container-test'
$Root = Split-Path -Parent $PSCommandPath

function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
}

Push-Location $Root
try {
    $BuildArguments = @(
        'build', '--file', 'Dockerfile.wc013-controller', '--tag', $Image
    )
    if ($env:ATHENA_CONTROLLER_TEST_PIP_INDEX_URL) {
        $BuildArguments += @(
            '--build-arg', "PIP_INDEX_URL=$($env:ATHENA_CONTROLLER_TEST_PIP_INDEX_URL)"
        )
    }
    $BuildArguments += '.'
    Invoke-Docker -Arguments $BuildArguments
}
finally {
    Pop-Location
}

$Inspect = (& docker image inspect $Image --format '{{.Config.User}}|{{json .Config.Entrypoint}}')
if ($LASTEXITCODE -ne 0) { throw 'controller image inspect failed' }
$Expected = '10001:10001|["athena-context","wc013-collector-controller"]'
if ($Inspect -ne $Expected) { throw "unexpected controller image config: $Inspect" }

$Help = (& docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges $Image --help)
if ($LASTEXITCODE -ne 0 -or -not ($Help -join "`n").Contains('--use-arm-access-token-stdin')) {
    throw 'immutable controller entrypoint or stdin token option is unavailable'
}

Write-Host 'WC-013 controller container tests passed.'
