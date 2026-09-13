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

foreach ($functionName in @(
    'Test-DcrDataCollectionEndpoint',
    'Test-DcrStreamFlowsUseExclusiveDestinations',
    'Test-LifecycleRuleHasUnsafeDelete'
)) {
    $functionAst = $ast.Find(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        },
        $true
    )
    if ($null -eq $functionAst) {
        throw "$functionName was not found in the readiness script."
    }
    Invoke-Expression $functionAst.Extent.Text
}

$expectedDceId = '/subscriptions/reviewed/providers/Microsoft.Insights/dataCollectionEndpoints/approved'
$approvedDcr = [pscustomobject]@{ dataCollectionEndpointId = $expectedDceId }
$decoyDcr = [pscustomobject]@{
    dataCollectionEndpointId = '/subscriptions/reviewed/providers/Microsoft.Insights/dataCollectionEndpoints/decoy'
}
$missingDceDcr = [pscustomobject]@{ name = 'missing-endpoint-binding' }
if (-not (Test-DcrDataCollectionEndpoint -DataCollectionRule $approvedDcr -ExpectedDataCollectionEndpointId $expectedDceId)) {
    throw 'The exact DCR data collection endpoint binding must be accepted.'
}
if (Test-DcrDataCollectionEndpoint -DataCollectionRule $decoyDcr -ExpectedDataCollectionEndpointId $expectedDceId) {
    throw 'A decoy DCR data collection endpoint binding must be rejected.'
}
if (Test-DcrDataCollectionEndpoint -DataCollectionRule $missingDceDcr -ExpectedDataCollectionEndpointId $expectedDceId) {
    throw 'A missing DCR data collection endpoint binding must be rejected.'
}

$requiredStream = 'Microsoft-Perf'
$approvedDestinationNames = @('approved')
$approvedFlow = [pscustomobject]@{
    streams = @($requiredStream)
    destinations = @('approved')
}
$approvedPlusDecoyFlow = [pscustomobject]@{
    streams = @($requiredStream)
    destinations = @('approved', 'decoy')
}
$separateDecoyFlow = [pscustomobject]@{
    streams = @($requiredStream)
    destinations = @('decoy')
}
if (-not (Test-DcrStreamFlowsUseExclusiveDestinations -DataFlows @($approvedFlow) -Stream $requiredStream -ApprovedDestinationNames $approvedDestinationNames)) {
    throw 'A required stream with one approved destination must be accepted.'
}
if (Test-DcrStreamFlowsUseExclusiveDestinations -DataFlows @($approvedPlusDecoyFlow) -Stream $requiredStream -ApprovedDestinationNames $approvedDestinationNames) {
    throw 'A required stream flow with an additional decoy destination must be rejected.'
}
if (Test-DcrStreamFlowsUseExclusiveDestinations -DataFlows @($approvedFlow, $separateDecoyFlow) -Stream $requiredStream -ApprovedDestinationNames $approvedDestinationNames) {
    throw 'A separate decoy flow for a required stream must be rejected.'
}
if (Test-DcrStreamFlowsUseExclusiveDestinations -DataFlows @() -Stream $requiredStream -ApprovedDestinationNames $approvedDestinationNames) {
    throw 'A missing required stream flow must be rejected.'
}

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

Write-Output 'WC-029 PowerShell adversarial DCR and retention tests passed.'
