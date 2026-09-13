[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $root 'infra/wc029-monitoring-prerequisites/Test-MonitoringReadiness.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Readiness script contains PowerShell parse errors: $($parseErrors -join '; ')"
}

$functionAst = $ast.Find(
    {
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-LifecycleRuleHasUnsafeDelete'
    },
    $true
)
if ($null -eq $functionAst) {
    throw 'Test-LifecycleRuleHasUnsafeDelete was not found in the readiness script.'
}
Invoke-Expression $functionAst.Extent.Text

function New-TestLifecycleRule {
    param(
        [Parameter(Mandatory)][double] $DeleteAfterDays,
        [AllowNull()][string[]] $Prefixes,
        [bool] $Enabled = $true
    )

    $filters = [ordered]@{
        blobTypes = @('blockBlob')
    }
    if ($null -ne $Prefixes) {
        $filters.prefixMatch = $Prefixes
    }
    return [pscustomobject]@{
        enabled = $Enabled
        definition = [pscustomobject]@{
            filters = [pscustomobject]$filters
            actions = [pscustomobject]@{
                baseBlob = [pscustomobject]@{
                    delete = [pscustomobject]@{
                        daysAfterModificationGreaterThan = $DeleteAfterDays
                    }
                }
            }
        }
    }
}

$requiredPrefixes = @('insights-logs-flowlogflowevent/', 'monitoring-evidence/')
$unsafeAccountWideRule = New-TestLifecycleRule -DeleteAfterDays 29 -Prefixes $null
$safeAccountWideRule = New-TestLifecycleRule -DeleteAfterDays 30 -Prefixes $null
$unsafeNestedRule = New-TestLifecycleRule -DeleteAfterDays 1 -Prefixes @(
    'insights-logs-flowlogflowevent/flowLogResourceID=/SYNTHETIC'
)
$unrelatedRule = New-TestLifecycleRule -DeleteAfterDays 1 -Prefixes @('unrelated/')
$disabledUnsafeRule = New-TestLifecycleRule -DeleteAfterDays 1 -Prefixes $null -Enabled $false

if (-not (Test-LifecycleRuleHasUnsafeDelete -Rule $unsafeAccountWideRule -RequiredPrefixes $requiredPrefixes -MinimumDays 30)) {
    throw 'An account-wide rule deleting before 30 days must be rejected.'
}
if (Test-LifecycleRuleHasUnsafeDelete -Rule $safeAccountWideRule -RequiredPrefixes $requiredPrefixes -MinimumDays 30) {
    throw 'An account-wide rule retaining for 30 days must be accepted.'
}
if (-not (Test-LifecycleRuleHasUnsafeDelete -Rule $unsafeNestedRule -RequiredPrefixes $requiredPrefixes -MinimumDays 30)) {
    throw 'A nested overlapping prefix deleting before 30 days must be rejected.'
}
if (Test-LifecycleRuleHasUnsafeDelete -Rule $unrelatedRule -RequiredPrefixes $requiredPrefixes -MinimumDays 30) {
    throw 'An unrelated prefix must not affect reviewed evidence retention.'
}
if (Test-LifecycleRuleHasUnsafeDelete -Rule $disabledUnsafeRule -RequiredPrefixes $requiredPrefixes -MinimumDays 30) {
    throw 'A disabled lifecycle rule must not affect effective retention.'
}

Write-Output 'WC-029 PowerShell adversarial retention tests passed.'
