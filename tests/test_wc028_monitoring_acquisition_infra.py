import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "wc028-monitoring-acquisition"
BICEP = INFRA / "main.bicep"
STORAGE_READINESS = INFRA / "modules" / "storage-readiness.bicep"


def test_wc028_job_reuses_wc024_identity_key_and_evidence_boundary() -> None:
    source = BICEP.read_text(encoding="utf-8")

    for expected in (
        "Microsoft.App/jobs@2025-01-01",
        "triggerType: 'Manual'",
        "manualTriggerConfig:",
        "replicaTimeout: 600",
        "replicaRetryLimit: 0",
        "'athena-context'",
        "'wc028-monitoring-acquisition-job'",
        "AZURE_CLIENT_ID",
        "ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID",
        "UserAssigned",
        "collectorIdentityResourceId",
        "runtimeSupportIdentityResourceId",
        "registryResourceId",
        "collectorIdentityResourceGroup",
        "runtimeSupportIdentityResourceGroup",
        "registryResourceGroup",
        "scope: subscription()",
        "collectorIdentity.properties.clientId",
        "collectorIdentity.properties.principalId",
        "runtimeSupportIdentity.properties.clientId",
        "runtimeSupportIdentity.properties.principalId",
        "monitoringEvidenceStorageAccountResourceId",
        "monitoringEvidenceContainerResourceId",
        "monitoringEvidenceStorageReadinessDigest",
        "monitoringEvidenceImmutabilityPolicyState",
        "monitoringEvidenceImmutabilityRetentionDays",
        "monitoringCollectorSigningKeyUriWithVersion",
        "monitoringIntentSigningKeyResourceId",
        "monitoringIntentSigningKeyUriWithVersion",
        "ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_JSON",
        "ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_DIGEST",
        "ATHENA_WC028_DEPLOYED_LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST",
        "secretRef: 'wc028-runtime-configuration'",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID",
        "ATHENA_WC028_DEPLOYED_ATHENA_CONTEXT_IDENTITY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_CLIENT_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_IDENTITY_PRINCIPAL_ID",
        "ATHENA_WC028_DEPLOYED_REGISTRY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_ACR_PULL_ROLE_DEFINITION_ID",
        "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_INTENT_KEY_READER_ROLE_DEFINITION_ID",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_INVENTORY_DIGEST",
        "ATHENA_WC028_DEPLOYED_RUNTIME_SUPPORT_RBAC_SOURCE_MANIFEST_DIGEST",
        "ATHENA_WC028_DEPLOYED_SOURCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_CONTAINER_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_MONITORING_EVIDENCE_STORAGE_READINESS_DIGEST",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID",
        "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID",
        "ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID",
        "modules/acquisition-rbac.bicep",
        "modules/storage-readiness.bicep",
        "storageReadiness.outputs.validatedStorageReadinessDigest",
        "legacyCollectorRbacCleanupDigest",
        "runtimeSupportEffectiveRbacInventoryDigest",
        "runtimeSupportEffectiveRbacSourceManifestDigest",
        "rejectedEvidenceDigest",
        "scope: registry",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "configurationDigestInvalidCharacters",
    ):
        assert expected in source

    assert source.count("userAssignedIdentities:") == 1
    assert "'${validatedCollectorIdentityResourceId}': {}" in source
    assert "'${validatedRuntimeSupportIdentityResourceId}': {}" in source
    assert "param collectorIdentityClientId" not in source
    assert "param collectorIdentityPrincipalId" not in source
    assert "param registryName" not in source
    assert "networkWatcherResourceId" not in source
    assert "ATHENA_WC028_DEPLOYED_NETWORK_WATCHER_RESOURCE_ID" not in source
    assert "scheduleTriggerConfig" not in source
    assert "scheduleCronExpression" not in source
    assert "monitoring-evidence" in source


def test_wc028_job_adds_no_broad_reader_or_monitoring_mutation() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(INFRA.rglob("*.bicep")))

    for forbidden in (
        "acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "Microsoft.Insights/diagnosticSettings",
        "Microsoft.Insights/metricAlerts",
        "Microsoft.Insights/scheduledQueryRules",
        "Microsoft.Network/networkWatchers/connectionMonitors",
        "Microsoft.Network/networkWatchers/ipFlowVerify/action",
        "Storage Blob Data Owner",
        "Storage Blob Data Contributor",
        "Owner",
        "Contributor",
        "'*/read'",
        "'*/write'",
        "containers/blobs/delete",
        "containers/blobs/list",
        "Microsoft.KeyVault/vaults/keys/sign/action",
        "Microsoft.KeyVault/vaults/keys/write",
        "Microsoft.KeyVault/vaults/keys/delete",
        "Microsoft.Insights/eventtypes/values/read",
        "Microsoft.ResourceGraph/resources/read",
        "Microsoft.Resources/changes/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        "listKeys(",
        "connectionString",
    ):
        assert forbidden not in source

    assert "Microsoft.KeyVault/vaults/keys/read" in source
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" in source
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action" in source
    assert "SubOperationMatches{\\'Blob.List\\'}" in source
    assert "conditionVersion: '2.0'" in source

    assert source.count("Microsoft.Authorization/roleAssignments") == 3
    for role_name in (
        "monitoringEvidenceCreateOnlyRole",
        "monitoringIntentKeyReaderRole",
    ):
        assert (
            f"resource {role_name} 'Microsoft.Authorization/roleDefinitions@2022-04-01'"
        ) in source
    assert "autoRemediation: 'disabled'" in source
    assert (
        "normalizedCollectorIdentityResourceId != normalizedRuntimeSupportIdentityResourceId"
        in (source)
    )
    assert "normalizedRuntimeSupportIdentityResourceId != normalizedContextIdentityResourceId" in (
        source
    )
    assert (
        "monitoringEvidenceStorageAccountResourceId) != "
        "toLower(sourceAuthorityStorageAccountResourceId)"
    ) in source
    assert "scope: key" in source
    assert "runtimeSupportPrincipalId: runtimeSupportIdentity.properties.principalId" in source
    assert "principalId: runtimeSupportPrincipalId" in source
    assert "collectorPrincipalId: collectorIdentity.properties.principalId" in source
    assert "principalId: collectorPrincipalId" in source


def test_runtime_iac_adds_only_exact_create_and_known_name_read_storage_grant() -> None:
    role_source = (INFRA / "modules" / "acquisition-rbac.bicep").read_text(encoding="utf-8")
    assignment_source = (
        INFRA / "modules" / "monitoring-evidence-writer-assignment.bicep"
    ).read_text(encoding="utf-8")

    assert "collectorPrincipalId" in role_source
    assert "runtimeSupportPrincipalId" in role_source
    assert "containers/blobs/read" in role_source
    assert "containers/blobs/add/action" in role_source
    assert "containers/blobs/write" not in role_source
    assert "containers/blobs/delete" not in role_source
    assert "Blob.List" in assignment_source
    assert "conditionVersion: '2.0'" in assignment_source
    assert "Microsoft.Insights/" not in role_source
    assert "Microsoft.ResourceGraph/" not in role_source
    assert "Microsoft.Resources/changes/read" not in role_source
    assert "monitoringEvidenceStorageReadinessDigest" in role_source
    assert "wc028-monitoring-evidence-writer-${substring(" in role_source


def test_storage_readiness_gates_writer_rbac_and_job_on_exact_wc024_readback() -> None:
    source = STORAGE_READINESS.read_text(encoding="utf-8")
    main = BICEP.read_text(encoding="utf-8")

    for expected in (
        "Microsoft.Storage/storageAccounts@2025-06-01",
        "Microsoft.Storage/storageAccounts/blobServices@2025-06-01",
        "Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01",
        (
            "Microsoft.Storage/storageAccounts/blobServices/containers/"
            "immutabilityPolicies@2025-06-01"
        ),
        "blobService.properties.isVersioningEnabled == true",
        "monitoringEvidenceContainer.properties.publicAccess == 'None'",
        "monitoringEvidenceImmutability.properties.state == expectedImmutabilityPolicyState",
        (
            "monitoringEvidenceImmutability.properties."
            "immutabilityPeriodSinceCreationInDays == expectedImmutabilityRetentionDays"
        ),
        "monitoringEvidenceImmutability.properties.allowProtectedAppendWrites == false",
        "monitoringEvidenceImmutability.properties.allowProtectedAppendWritesAll == false",
        "storageReadinessDigest != rejectedDigest",
        "var readinessPreimage = ",
        "var computedReadbackBindingId = guid(readinessPreimage)",
        "expectedReadbackBindingId == computedReadbackBindingId",
        "output validatedStorageReadinessDigest string",
    ):
        assert expected in source

    assert (
        "monitoringEvidenceStorageReadinessDigest: "
        "storageReadiness.outputs.validatedStorageReadinessDigest"
    ) in main
    assert ("value: storageReadiness.outputs.validatedStorageReadinessDigest") in main
    assert "dependsOn: [\n    storageReadiness\n  ]" in main
    assert "json(acquisitionRuntimeConfigurationJson)" in main
    assert "configuredStorageReadiness.readbackBindingId" in main
    assert (
        "runtime configuration storage readiness does not match the exact reviewed "
        "WC-024 readback inputs"
    ) in main
    assert (
        "configuredStorageReadiness.readinessDigest == monitoringEvidenceStorageReadinessDigest"
    ) in main
    assert (
        "expectedReadbackBindingId: string(validatedConfiguredStorageReadiness.readbackBindingId)"
    ) in main
    assert "param pr99RuntimeDependenciesReady bool = false" in main
    assert (
        "WC-028 deployment remains blocked pending the complete reviewed PR #99 "
        "storage, replay, and ancestor-RBAC contract"
    ) in main
    assert main.count("validatedPr99RuntimeDependencyGate == 'ready'") == 3


def test_upgrade_cleanup_targets_only_exact_legacy_collector_bindings() -> None:
    cleanup = (INFRA / "remove-obsolete-collector-rbac.ps1").read_text(encoding="utf-8")

    for expected in (
        "athena-wc028-bounded-acquisition-reader",
        "athena-wc028-change-evidence-create-only",
        "athena-wc028-monitoring-intent-key-reader",
        "athena-wc028-ip-flow-verify",
        "Microsoft.Network/networkWatchers/ipFlowVerify/action",
        "NetworkWatcherResourceId",
        "NetworkWatcherRG/NetworkWatcher_australiaeast",
        "historicalIpFlowRoleDefinitionId",
        "historicalIpFlowRoleAssignmentId",
        "New-ArmTemplateGuid",
        "11fb06fb-712d-4ddd-98c7-e71bbd588830",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        "'role', 'assignment', 'delete', '--ids'",
        "'role', 'definition', 'delete'",
        "'identity', 'show'",
        "'resource', 'show'",
        "'group', 'show'",
        "'--api-version', '2024-10-01'",
        "'--name', $workloadResourceGroupName",
        "cleanupEvidenceDigest",
        "verifiedAbsentBindings",
        "Assert-ResourceSubscription",
        "Assert-RoleDefinitionAbsent",
        "Assert-ReviewedRoleDefinition",
        "Get-ExactResourceGroupName",
        "Get-ResourceGroupScope",
        "Get-HistoricalNetworkWatcherResourceId",
        "$boundedReaderRoleDefinitionGuid",
        "$changeWriterRoleDefinitionGuid",
        "$intentKeyReaderRoleDefinitionGuid",
        "$historicalRoleDefinitions",
        "$roleDefinitionGuid",
        "reviewedRoleAssignmentIds",
        "reviewedRoleDefinitionIds",
    ):
        assert expected in cleanup

    for forbidden in (
        "'role', 'assignment', 'delete', '--assignee'",
        "Remove-AzRoleAssignment",
        "--scope', '/subscriptions/",
        "Microsoft.Authorization/roleAssignments/delete",
        "Find-RoleDefinitionId",
        "-RoleName",
        "roleName -ne",
        "'network', 'watcher', 'show'",
        "'--ids', $WorkloadResourceGroupResourceId",
    ):
        assert forbidden not in cleanup

    assert "athena.wc028LegacyCollectorRbacCleanup.v3" in cleanup
    assert "ExpectedAssignmentId = $ipFlowAssignmentId" in cleanup
    assert (
        "$historicalNetworkWatcherId/providers/Microsoft.Authorization/roleAssignments/" in cleanup
    )
    assert cleanup.count("ExpectedAssignmentId = $null") == 5
    assert "$boundedReaderRoleDefinitionGuid = New-ArmTemplateGuid -Values @(" in cleanup
    assert (
        "'athena-wc028-bounded-acquisition-reader',\n    $historicalWorkloadResourceGroupId"
    ) in cleanup
    assert (
        """$changeWriterRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-change-evidence-create-only',
    (Normalize-ResourceId -ResourceId $ChangeEvidenceContainerResourceId)
)"""
        in cleanup
    )
    assert (
        """$intentKeyReaderRoleDefinitionGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-monitoring-intent-key-reader',
    (Normalize-ResourceId -ResourceId $MonitoringIntentSigningKeyResourceId)
)"""
        in cleanup
    )
    assert "if ($null -ne $boundedReaderRoleDefinitionId)" not in cleanup
    assert "if ($null -ne $changeWriterRoleDefinitionId)" not in cleanup
    assert "if ($null -ne $intentKeyReaderRoleDefinitionId)" not in cleanup
    assert "[string]$networkWatcher.name -cne 'NetworkWatcher_australiaeast'" in cleanup
    assert "[string]$networkWatcher.properties.provisioningState -cne 'Succeeded'" in cleanup
    assert "[string]$workloadResourceGroup.name -cne $workloadResourceGroupName" in cleanup
    assert "[string]$workloadResourceGroup.properties.provisioningState -cne 'Succeeded'" in cleanup
    assert cleanup.count(").ToLowerInvariant() -ne 'australiaeast'") == 2


def test_upgrade_cleanup_exact_role_helpers_are_script_scoped() -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for cleanup AST validation")
    cleanup_path = str(INFRA / "remove-obsolete-collector-rbac.ps1").replace("'", "''")
    command = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{cleanup_path}',
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {{
    throw ($errors -join [Environment]::NewLine)
}}
@(
    $ast.FindAll(
        {{
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }},
        $true
    ) | ForEach-Object {{
        $parent = $_.Parent
        while (
            $null -ne $parent -and
            $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]
        ) {{
            $parent = $parent.Parent
        }}
        [ordered]@{{
            name = $_.Name
            parent = if ($null -eq $parent) {{ '<script>' }} else {{ $parent.Name }}
        }}
    }}
) | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )
    functions = json.loads(completed.stdout)
    parents = {item["name"]: item["parent"] for item in functions}

    assert parents["Get-ExactRoleDefinition"] == "<script>"
    assert parents["Assert-ReviewedRoleDefinition"] == "<script>"
    assert parents["Assert-RoleDefinitionAbsent"] == "<script>"
    assert parents["Get-ExactResourceGroupName"] == "<script>"


def test_cleanup_lookup_commands_match_installed_azure_cli_parser() -> None:
    azure_cli = shutil.which("az")
    if azure_cli is None:
        pytest.skip("Azure CLI is required for argument-contract validation")
    subscription_id = "00000000-0000-0000-0000-000000000000"
    network_watcher_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/NetworkWatcherRG/providers/"
        "Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast"
    )

    resource_help = subprocess.run(
        [azure_cli, "resource", "show", "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    group_help = subprocess.run(
        [azure_cli, "group", "show", "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "--ids" in resource_help
    assert "--name --resource-group -g -n [Required]" in group_help

    for arguments in (
        (
            "resource",
            "show",
            "--ids",
            network_watcher_id,
            "--api-version",
            "2024-10-01",
            "--subscription",
            subscription_id,
        ),
        (
            "group",
            "show",
            "--name",
            "rg-athena-demo-workload",
            "--subscription",
            subscription_id,
        ),
    ):
        parsed = subprocess.run(
            [azure_cli, *arguments, "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert parsed.returncode == 0

        read_only_probe = subprocess.run(
            [
                azure_cli,
                *arguments,
                "--only-show-errors",
                "--output",
                "none",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        parser_output = (read_only_probe.stdout + read_only_probe.stderr).casefold()
        assert read_only_probe.returncode == 1
        assert "unrecognized arguments" not in parser_output
        assert "the following arguments are required" not in parser_output
        assert "misspelled or not recognized" not in parser_output

    invalid_group = subprocess.run(
        [azure_cli, "group", "show", "--ids", network_watcher_id],
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid_group.returncode == 2
    assert "the following arguments are required" in invalid_group.stderr.casefold()

    invalid_watcher = subprocess.run(
        [azure_cli, "network", "watcher", "show", "--ids", network_watcher_id],
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid_watcher.returncode == 2
    assert "misspelled or not recognized" in invalid_watcher.stderr.casefold()


@pytest.mark.parametrize(
    ("workload_resource_group_id", "expected_error"),
    (
        ("not-an-arm-resource-id", "does not match the"),
        (
            (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-demo-workload"
            ),
            "outside SubscriptionId",
        ),
    ),
)
def test_cleanup_rejects_malformed_or_cross_subscription_before_azure_cli(
    workload_resource_group_id: str,
    expected_error: str,
) -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for cleanup argument validation")
    subscription_id = "00000000-0000-0000-0000-000000000000"
    cleanup = str(INFRA / "remove-obsolete-collector-rbac.ps1")
    arguments = [
        shell,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        cleanup,
        "-SubscriptionId",
        subscription_id,
        "-CollectorPrincipalId",
        "22222222-2222-2222-2222-222222222222",
        "-CollectorIdentityResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/rg-athena-demo-monitoring/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/collector"
        ),
        "-RegistryResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/rg-athena-demo-shared/"
            "providers/Microsoft.ContainerRegistry/registries/athenademoacr"
        ),
        "-WorkloadResourceGroupResourceId",
        workload_resource_group_id,
        "-NetworkWatcherResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/NetworkWatcherRG/providers/"
            "Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast"
        ),
        "-ChangeEvidenceContainerResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/rg-athena-demo-context/"
            "providers/Microsoft.Storage/storageAccounts/athenachange/"
            "blobServices/default/containers/change-evidence"
        ),
        "-MonitoringEvidenceContainerResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/rg-athena-demo-monitoring/"
            "providers/Microsoft.Storage/storageAccounts/athenamonitoring/"
            "blobServices/default/containers/monitoring-evidence"
        ),
        "-MonitoringIntentSigningKeyResourceId",
        (
            f"/subscriptions/{subscription_id}/resourceGroups/rg-athena-demo-context/"
            "providers/Microsoft.KeyVault/vaults/synthetic-context-kv/"
            "keys/monitoring-intent-signing"
        ),
    ]
    environment = dict(os.environ)
    environment["PATH"] = ""

    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode != 0
    assert expected_error.casefold() in (completed.stdout + completed.stderr).casefold()
    assert "az should not run" not in (completed.stdout + completed.stderr).casefold()


def test_upgrade_cleanup_role_helpers_execute_for_absent_deleted_and_renamed_roles() -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for executable cleanup tests")
    cleanup_path = str(INFRA / "remove-obsolete-collector-rbac.ps1").replace("'", "''")
    command = f"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{cleanup_path}',
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {{
    throw ($errors -join [Environment]::NewLine)
}}
foreach ($functionName in @(
    'Normalize-ResourceId',
    'Get-ExactRoleDefinition',
    'Assert-ReviewedRoleDefinition',
    'Assert-RoleDefinitionAbsent'
)) {{
    $functionAst = $ast.Find(
        {{
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        }},
        $true
    )
    if ($null -eq $functionAst) {{
        throw "Missing cleanup function $functionName"
    }}
    Invoke-Expression $functionAst.Extent.Text
}}

$SubscriptionId = '00000000-0000-0000-0000-000000000000'
$roleDefinitionId = (
    '/subscriptions/00000000-0000-0000-0000-000000000000/providers/' +
    'Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
)
$otherRoleDefinitionId = $roleDefinitionId.Replace(
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
)
$assignableScope = (
    '/subscriptions/00000000-0000-0000-0000-000000000000/' +
    'resourceGroups/rg-synthetic'
)
$script:mockRoleDefinitions = @(
    [pscustomobject]@{{ id = $otherRoleDefinitionId }}
)
function Invoke-AzJson {{
    param([Parameter(Mandatory)][string[]]$AzArguments)
    return $script:mockRoleDefinitions
}}

$initiallyAbsent = Get-ExactRoleDefinition -RoleDefinitionId $roleDefinitionId
if ($null -ne $initiallyAbsent) {{
    throw 'An unrelated role ID must filter to no exact role definition.'
}}
Assert-RoleDefinitionAbsent -RoleDefinitionId $roleDefinitionId

$renamedRole = [pscustomobject]@{{
    id = $roleDefinitionId
    roleName = 'Renamed Legacy Role'
    roleType = 'CustomRole'
    permissions = @(
        [pscustomobject]@{{
            actions = @('Microsoft.Test/widgets/read')
            notActions = @()
            dataActions = @()
            notDataActions = @()
        }}
    )
    assignableScopes = @($assignableScope)
}}
$script:mockRoleDefinitions = @($renamedRole)
$resolved = Get-ExactRoleDefinition -RoleDefinitionId $roleDefinitionId
if ($null -eq $resolved) {{
    throw 'The exact deterministic role ID was not resolved.'
}}
Assert-ReviewedRoleDefinition `
    -RoleDefinition $resolved `
    -ExpectedRoleDefinitionId $roleDefinitionId `
    -ExpectedAssignableScope $assignableScope `
    -ExpectedActions @('Microsoft.Test/widgets/read') `
    -ExpectedDataActions @()

$mismatchedRole = $renamedRole.PSObject.Copy()
$mismatchedRole.permissions = @(
    [pscustomobject]@{{
        actions = @('Microsoft.Test/widgets/write')
        notActions = @()
        dataActions = @()
        notDataActions = @()
    }}
)
$mismatchRejected = $false
try {{
    Assert-ReviewedRoleDefinition `
        -RoleDefinition $mismatchedRole `
        -ExpectedRoleDefinitionId $roleDefinitionId `
        -ExpectedAssignableScope $assignableScope `
        -ExpectedActions @('Microsoft.Test/widgets/read') `
        -ExpectedDataActions @()
}} catch {{
    $mismatchRejected = $true
}}
if (-not $mismatchRejected) {{
    throw 'A mismatched historical role body was accepted.'
}}

$scopeMismatchRejected = $false
try {{
    Assert-ReviewedRoleDefinition `
        -RoleDefinition $renamedRole `
        -ExpectedRoleDefinitionId $roleDefinitionId `
        -ExpectedAssignableScope "$assignableScope-other" `
        -ExpectedActions @('Microsoft.Test/widgets/read') `
        -ExpectedDataActions @()
}} catch {{
    $scopeMismatchRejected = $true
}}
if (-not $scopeMismatchRejected) {{
    throw 'A mismatched historical role assignable scope was accepted.'
}}

$script:mockRoleDefinitions = @()
Assert-RoleDefinitionAbsent -RoleDefinitionId $roleDefinitionId

[ordered]@{{
    initiallyAbsent = $true
    renamedRoleAccepted = $true
    mismatchedRoleRejected = $mismatchRejected
    mismatchedScopeRejected = $scopeMismatchRejected
    successfullyDeletedAbsent = $true
}} | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {
        "initiallyAbsent": True,
        "renamedRoleAccepted": True,
        "mismatchedRoleRejected": True,
        "mismatchedScopeRejected": True,
        "successfullyDeletedAbsent": True,
    }


def test_upgrade_cleanup_reconstructs_historical_network_watcher_guid_preimages() -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required for executable cleanup tests")
    cleanup_path = str(INFRA / "remove-obsolete-collector-rbac.ps1").replace("'", "''")
    command = f"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{cleanup_path}',
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {{
    throw ($errors -join [Environment]::NewLine)
}}
foreach ($functionName in @(
    'Convert-GuidToNetworkBytes',
    'Convert-NetworkBytesToGuid',
    'New-ArmTemplateGuid',
    'Get-HistoricalNetworkWatcherResourceId'
)) {{
    $functionAst = $ast.Find(
        {{
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        }},
        $true
    )
    Invoke-Expression $functionAst.Extent.Text
}}

$SubscriptionId = '00000000-0000-0000-0000-000000000000'
$subscriptionScope = '/subscriptions/00000000-0000-0000-0000-000000000000'
$liveNetworkWatcherId = (
    "$subscriptionScope/resourceGroups/NetworkWatcherRG/providers/" +
    'Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast'
)
$historicalNetworkWatcherId = Get-HistoricalNetworkWatcherResourceId `
    -ResourceId $liveNetworkWatcherId
$expectedHistoricalNetworkWatcherId = (
    "$subscriptionScope/resourceGroups/networkwatcherrg/providers/" +
    'Microsoft.Network/networkWatchers/networkwatcher_australiaeast'
)
if ($historicalNetworkWatcherId -cne $expectedHistoricalNetworkWatcherId) {{
    throw 'Historical Network Watcher resource ID casing was not reconstructed exactly.'
}}
$roleGuid = New-ArmTemplateGuid -Values @(
    $subscriptionScope,
    'athena-wc028-ip-flow-verify',
    $historicalNetworkWatcherId
)
if ($roleGuid -ne 'b5e78872-6f8f-5156-ad98-4c5b4704d15e') {{
    throw 'Historical IP Flow role-definition GUID does not match the original ARM preimage.'
}}
$roleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/$roleGuid"
)
$assignmentGuid = New-ArmTemplateGuid -Values @(
    $historicalNetworkWatcherId,
    '44444444-4444-4444-4444-444444444444',
    $roleDefinitionId
)
if ($assignmentGuid -ne '3b53fb0b-abc4-5ad5-b7f8-54199918a930') {{
    throw 'Historical IP Flow assignment GUID does not match the original ARM preimage.'
}}

$wrongWatcherRejected = $false
try {{
    Get-HistoricalNetworkWatcherResourceId -ResourceId (
        "$subscriptionScope/resourceGroups/rg-other/providers/" +
        'Microsoft.Network/networkWatchers/NetworkWatcher_other'
    ) | Out-Null
}} catch {{
    $wrongWatcherRejected = $true
}}
if (-not $wrongWatcherRejected) {{
    throw 'A caller-selected non-historical Network Watcher was accepted.'
}}

[ordered]@{{
    historicalNetworkWatcherId = $historicalNetworkWatcherId
    roleGuid = $roleGuid
    assignmentGuid = $assignmentGuid
    wrongWatcherRejected = $wrongWatcherRejected
}} | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {
        "historicalNetworkWatcherId": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/networkwatcherrg/providers/Microsoft.Network/"
            "networkWatchers/networkwatcher_australiaeast"
        ),
        "roleGuid": "b5e78872-6f8f-5156-ad98-4c5b4704d15e",
        "assignmentGuid": "3b53fb0b-abc4-5ad5-b7f8-54199918a930",
        "wrongWatcherRejected": True,
    }
