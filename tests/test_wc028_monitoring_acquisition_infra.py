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
        "runtimeSupportMonitoringIntentKeyReaderRole",
    ):
        assert (
            f"resource {role_name} 'Microsoft.Authorization/roleDefinitions@2022-04-01'"
        ) in source
    assert "Athena WC028 Runtime Support Monitoring Intent Key Reader" in source
    assert "athena-wc028-runtime-support-monitoring-intent-key-reader" in source
    assert (
        "Allow only public-key material and metadata reads when assigned to the exact "
        "monitoring-intent signing key for the separate runtime-support identity."
    ) in source
    assert "resource collectorMonitoringIntentKeyReader" not in source
    assert "resource runtimeSupportMonitoringIntentKeyReader" in source
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
        "WC-028 deployment remains blocked pending the exact successor collector schema and "
        "digest plus the complete reviewed PR #99 storage, replay, ancestor-RBAC, receipt, "
        "and authority contracts"
    ) in main
    assert main.count("validatedPr99RuntimeDependencyGate == 'ready'") == 3


def test_upgrade_cleanup_targets_only_exact_legacy_collector_bindings() -> None:
    cleanup = (INFRA / "remove-obsolete-collector-rbac.ps1").read_text(encoding="utf-8")

    for expected in (
        "Microsoft.Network/networkWatchers/ipFlowVerify/action",
        "NetworkWatcherResourceId",
        "NetworkWatcherRG/NetworkWatcher_australiaeast",
        "Athena WC028 Bounded Acquisition Reader",
        "Athena WC028 Change Evidence Create-Only Writer",
        "Athena WC028 Monitoring Intent Key Reader",
        "Athena WC028 IP Flow Verifier",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        "'role', 'assignment', 'delete',",
        "'role', 'definition', 'delete'",
        "'role', 'definition', 'list',",
        "'--custom-role-only', 'true'",
        "'role', 'assignment', 'list',",
        "'--assignee-object-id', $CollectorPrincipalId",
        "'--all'",
        "'--fill-role-definition-name', 'true'",
        "'identity', 'show'",
        "'resource', 'show'",
        "'group', 'show'",
        "'--api-version', '2024-10-01'",
        "'--name', $workloadResourceGroupName",
        "cleanupEvidenceDigest",
        "Assert-ResourceSubscription",
        "Resolve-ReviewedHistoricalRoleDefinition",
        "Assert-ReviewedHistoricalRoleDefinitionAbsent",
        "Resolve-ReviewedTargetRoleAssignment",
        "Assert-ReviewedTargetRoleAssignmentsAbsent",
        "Get-CompleteCustomRoleDefinitionInventory",
        "Get-CompleteTargetRoleAssignmentInventory",
        "Get-ExactResourceGroupName",
        "Get-ResourceGroupScope",
        "Get-HistoricalNetworkWatcherResourceId",
        "$historicalRoleDefinitions",
        "$roleDefinitionGuid",
        "$assignmentResolution",
        "complete-known-scope-custom-role-enumeration",
        "independent-complete-subscription-principal-assignment-enumeration",
        "roleDefinitionOutcomes",
        "roleAssignmentOutcomes",
        "armGuidGroundTruth",
        "localComputationSecurityUse = 'none'",
    ):
        assert expected in cleanup

    for forbidden in (
        "'role', 'assignment', 'delete', '--assignee'",
        "Remove-AzRoleAssignment",
        "--scope', '/subscriptions/",
        "Microsoft.Authorization/roleAssignments/delete",
        "Find-RoleDefinitionId",
        "-RoleName",
        "'network', 'watcher', 'show'",
        "'--ids', $WorkloadResourceGroupResourceId",
        "New-ArmTemplateGuid",
        "Convert-GuidToNetworkBytes",
        "Convert-NetworkBytesToGuid",
        "11fb06fb-712d-4ddd-98c7-e71bbd588830",
        "ExpectedAssignmentId",
        "historicalIpFlowRoleDefinitionId",
        "historicalIpFlowRoleAssignmentId",
        "$matches",
        "ExpectedDescription",
        "ArmGuidPreimage",
        "armGuidPreimage",
        "armGuidUse",
    ):
        assert forbidden not in cleanup

    assert "athena.wc028LegacyCollectorRbacCleanup.v5" in cleanup
    assert cleanup.count("ExpectedRoleName = 'Athena WC028") == 4
    assert "'--scope', ([string]$Target.ExpectedAssignableScope)" in cleanup
    assert (
        "Get-CompleteCustomRoleDefinitionInventory `\n        -Phase 'pre-cleanup' `\n"
        "        -Target $historicalRole"
    ) in cleanup
    assert (
        "Get-CompleteCustomRoleDefinitionInventory `\n        -Phase 'post-cleanup' `\n"
        "        -Target $historicalRole"
    ) in cleanup
    assert (
        "Get-CompleteTargetRoleAssignmentInventory `\n"
        "        -Phase 'pre-cleanup' `\n        -Target $target"
    ) in cleanup
    assert (
        "Get-CompleteTargetRoleAssignmentInventory `\n"
        "        -Phase 'post-cleanup' `\n        -Target $target"
    ) in cleanup
    assert "no name or GUID filter" in cleanup
    assert "does not calculate, compare, record" in cleanup
    assert "or trust locally reconstructed GUID values" in cleanup
    assert "[string]$networkWatcher.name -cne 'NetworkWatcher_australiaeast'" in cleanup
    assert "[string]$networkWatcher.properties.provisioningState -cne 'Succeeded'" in cleanup
    assert "[string]$workloadResourceGroup.name -cne $workloadResourceGroupName" in cleanup
    assert "[string]$workloadResourceGroup.properties.provisioningState -cne 'Succeeded'" in cleanup
    assert cleanup.count(").ToLowerInvariant() -cne 'australiaeast'") == 2


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

    assert parents["Resolve-ReviewedHistoricalRoleDefinition"] == "<script>"
    assert parents["Assert-ReviewedHistoricalRoleDefinitionAbsent"] == "<script>"
    assert parents["Resolve-ReviewedTargetRoleAssignment"] == "<script>"
    assert parents["Assert-ReviewedTargetRoleAssignmentsAbsent"] == "<script>"
    assert parents["Test-ReviewedRoleDefinitionBody"] == "<script>"
    assert parents["Get-ExactResourceGroupName"] == "<script>"


def test_cleanup_inventory_queries_are_complete_scoped_and_independent() -> None:
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
    'Get-CompleteCustomRoleDefinitionInventory',
    'Get-CompleteTargetRoleAssignmentInventory'
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
$CollectorPrincipalId = '22222222-2222-2222-2222-222222222222'
$subscriptionScope = "/subscriptions/$SubscriptionId"
$roleTargetA = [pscustomobject]@{{
    Key = 'role-a'
    ExpectedAssignableScope = "$subscriptionScope/resourceGroups/rg-a"
}}
$roleTargetB = [pscustomobject]@{{
    Key = 'role-b'
    ExpectedAssignableScope = "$subscriptionScope/resourceGroups/rg-b"
}}
$assignmentTarget = [pscustomobject]@{{
    Key = 'assignment-a'
    Scope = (
        "$subscriptionScope/resourceGroups/rg-a/providers/" +
        'Microsoft.KeyVault/vaults/synthetic-vault/keys/key-a'
    )
}}
$script:azCalls = [System.Collections.Generic.List[object]]::new()
function Invoke-AzJson {{
    param([Parameter(Mandatory)][string[]]$AzArguments)
    $script:azCalls.Add([pscustomobject]@{{ arguments = @($AzArguments) }})
    return @()
}}

$roleA = Get-CompleteCustomRoleDefinitionInventory `
    -Phase 'pre-cleanup' `
    -Target $roleTargetA
$roleB = Get-CompleteCustomRoleDefinitionInventory `
    -Phase 'pre-cleanup' `
    -Target $roleTargetB
$assignmentPre = Get-CompleteTargetRoleAssignmentInventory `
    -Phase 'pre-cleanup' `
    -Target $assignmentTarget
$assignmentPost = Get-CompleteTargetRoleAssignmentInventory `
    -Phase 'post-cleanup' `
    -Target $assignmentTarget

[ordered]@{{
    calls = @($script:azCalls)
    roleA = $roleA
    roleB = $roleB
    assignmentPre = $assignmentPre
    assignmentPost = $assignmentPost
}} | ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)

    assert result["calls"] == [
        {
            "arguments": [
                "role",
                "definition",
                "list",
                "--custom-role-only",
                "true",
                "--scope",
                (
                    "/subscriptions/00000000-0000-0000-0000-000000000000/"
                    "resourceGroups/rg-a"
                ),
                "--subscription",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
        {
            "arguments": [
                "role",
                "definition",
                "list",
                "--custom-role-only",
                "true",
                "--scope",
                (
                    "/subscriptions/00000000-0000-0000-0000-000000000000/"
                    "resourceGroups/rg-b"
                ),
                "--subscription",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
        {
            "arguments": [
                "role",
                "assignment",
                "list",
                "--assignee-object-id",
                "22222222-2222-2222-2222-222222222222",
                "--all",
                "--fill-role-definition-name",
                "true",
                "--subscription",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
        {
            "arguments": [
                "role",
                "assignment",
                "list",
                "--assignee-object-id",
                "22222222-2222-2222-2222-222222222222",
                "--all",
                "--fill-role-definition-name",
                "true",
                "--subscription",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
    ]
    assert result["roleA"]["TargetKey"] == "role-a"
    assert result["roleB"]["TargetKey"] == "role-b"
    assert result["assignmentPre"]["Phase"] == "pre-cleanup"
    assert result["assignmentPost"]["Phase"] == "post-cleanup"
    assert result["assignmentPre"]["TargetKey"] == "assignment-a"
    assert result["assignmentPost"]["TargetKey"] == "assignment-a"


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
    role_definition_help = subprocess.run(
        [azure_cli, "role", "definition", "list", "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    role_assignment_help = subprocess.run(
        [azure_cli, "role", "assignment", "list", "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "--ids" in resource_help
    assert "--name --resource-group -g -n [Required]" in group_help
    assert "--custom-role-only" in role_definition_help
    assert "--all" in role_assignment_help
    assert "--assignee-object-id" in role_assignment_help
    assert "--fill-role-definition-name" in role_assignment_help

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
        (
            "role",
            "definition",
            "list",
            "--custom-role-only",
            "true",
            "--scope",
            (
                f"/subscriptions/{subscription_id}/"
                "resourceGroups/rg-athena-demo-workload"
            ),
            "--subscription",
            subscription_id,
        ),
        (
            "role",
            "assignment",
            "list",
            "--assignee-object-id",
            "22222222-2222-2222-2222-222222222222",
            "--all",
            "--fill-role-definition-name",
            "true",
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


def test_upgrade_cleanup_ignores_untrusted_id_miss_and_rejects_ambiguity() -> None:
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
    'Test-NormalizedStringCollection',
    'Test-ReviewedRoleDefinitionBody',
    'Get-RoleDefinitionGuid',
    'Resolve-ReviewedHistoricalRoleDefinition',
    'Assert-ReviewedHistoricalRoleDefinitionAbsent',
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
    if ($null -eq $functionAst) {{
        throw "Missing cleanup function $functionName"
    }}
    Invoke-Expression $functionAst.Extent.Text
}}

$SubscriptionId = '00000000-0000-0000-0000-000000000000'
$subscriptionScope = '/subscriptions/00000000-0000-0000-0000-000000000000'
$actualRoleDefinitionId = (
    '/subscriptions/00000000-0000-0000-0000-000000000000/providers/' +
    'Microsoft.Authorization/roleDefinitions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
)
$untrustedGuessedRoleDefinitionId = $actualRoleDefinitionId.Replace(
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
)
$assignableScope = (
    '/subscriptions/00000000-0000-0000-0000-000000000000/' +
    'resourceGroups/rg-synthetic'
)
$target = [pscustomobject]@{{
    Key = 'synthetic-historical-reader'
    Name = 'synthetic historical reader'
    ExpectedRoleName = 'Athena WC028 Synthetic Historical Reader'
    ExpectedAssignableScope = $assignableScope
    ExpectedActions = @('Microsoft.Test/widgets/read')
    ExpectedDataActions = @()
}}
function New-SyntheticRole {{
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$RoleName,
        [Parameter(Mandatory)][string[]]$Actions
    )
    return [pscustomobject]@{{
        id = $Id
        roleName = $RoleName
        description = 'Synthetic exact historical reader.'
        roleType = 'CustomRole'
        permissions = @(
            [pscustomobject]@{{
                actions = $Actions
                notActions = @()
                dataActions = @()
                notDataActions = @()
            }}
        )
        assignableScopes = @($assignableScope)
    }}
}}

$exactRole = New-SyntheticRole `
    -Id $actualRoleDefinitionId `
    -RoleName $target.ExpectedRoleName `
    -Actions $target.ExpectedActions
$completeInventory = [pscustomobject]@{{
    QueryKind = 'complete-known-scope-custom-role-enumeration'
    TargetKey = $target.Key
    Scope = $assignableScope
    Items = @($exactRole)
}}
$untrustedIdZeroMatches = @(
    $completeInventory.Items | Where-Object {{
        (Normalize-ResourceId -ResourceId ([string]$_.id)) -eq (
            Normalize-ResourceId -ResourceId $untrustedGuessedRoleDefinitionId
        )
    }}
).Count -eq 0
$resolved = Resolve-ReviewedHistoricalRoleDefinition `
    -Inventory $completeInventory `
    -Target $target
$untrustedIdMissDidNotHideRole = (
    $untrustedIdZeroMatches -and
    [string]$resolved.Status -eq 'found' -and
    [string]$resolved.RoleDefinitionId -eq (
        Normalize-ResourceId -ResourceId $actualRoleDefinitionId
    )
)

$absent = Resolve-ReviewedHistoricalRoleDefinition `
    -Inventory ([pscustomobject]@{{
        QueryKind = 'complete-known-scope-custom-role-enumeration'
        TargetKey = $target.Key
        Scope = $assignableScope
        Items = @()
    }}) `
    -Target $target
$completeZeroMatchProvedAbsent = (
    [string]$absent.Status -eq 'provedAbsent' -and
    [string]$absent.DiscoveryProof -like 'complete known-scope custom-role enumeration*'
)
$postCleanupAbsentProof = Assert-ReviewedHistoricalRoleDefinitionAbsent `
    -Inventory ([pscustomobject]@{{
        QueryKind = 'complete-known-scope-custom-role-enumeration'
        TargetKey = $target.Key
        Scope = $assignableScope
        Items = @()
    }}) `
    -Target $target `
    -PreviouslyResolvedRoleDefinitionId $null
$initiallyAbsentPostcheckAccepted = (
    $postCleanupAbsentProof -like 'complete known-scope custom-role enumeration*'
)

$duplicateRole = New-SyntheticRole `
    -Id $actualRoleDefinitionId.Replace(
        'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        'cccccccc-cccc-cccc-cccc-cccccccccccc'
    ) `
    -RoleName $target.ExpectedRoleName `
    -Actions $target.ExpectedActions
$duplicateRejected = $false
try {{
    Resolve-ReviewedHistoricalRoleDefinition `
        -Inventory ([pscustomobject]@{{
            QueryKind = 'complete-known-scope-custom-role-enumeration'
            TargetKey = $target.Key
            Scope = $assignableScope
            Items = @($exactRole, $duplicateRole)
        }}) `
        -Target $target | Out-Null
}} catch {{
    $duplicateRejected = $_.Exception.Message -like '*duplicate*'
}}
if (-not $duplicateRejected) {{
    throw 'Duplicate historical role identities were accepted.'
}}

$renamedRole = New-SyntheticRole `
    -Id $actualRoleDefinitionId `
    -RoleName 'Renamed Legacy Role' `
    -Actions $target.ExpectedActions
$renamedRejected = $false
try {{
    Resolve-ReviewedHistoricalRoleDefinition `
        -Inventory ([pscustomobject]@{{
            QueryKind = 'complete-known-scope-custom-role-enumeration'
            TargetKey = $target.Key
            Scope = $assignableScope
            Items = @($renamedRole)
        }}) `
        -Target $target | Out-Null
}} catch {{
    $renamedRejected = $_.Exception.Message -like '*renamed role*'
}}
if (-not $renamedRejected) {{
    throw 'A renamed historical role was treated as absent or deleted automatically.'
}}

$mismatchedRole = New-SyntheticRole `
    -Id $actualRoleDefinitionId `
    -RoleName $target.ExpectedRoleName `
    -Actions @('Microsoft.Test/widgets/write')
$mismatchRejected = $false
try {{
    Resolve-ReviewedHistoricalRoleDefinition `
        -Inventory ([pscustomobject]@{{
            QueryKind = 'complete-known-scope-custom-role-enumeration'
            TargetKey = $target.Key
            Scope = $assignableScope
            Items = @($mismatchedRole)
        }}) `
        -Target $target | Out-Null
}} catch {{
    $mismatchRejected = $_.Exception.Message -like '*unreviewed permissions*'
}}
if (-not $mismatchRejected) {{
    throw 'A same-name role with a mismatched body was accepted.'
}}

$liveNetworkWatcherId = (
    "$subscriptionScope/resourceGroups/NetworkWatcherRG/providers/" +
    'Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast'
)
$historicalNetworkWatcherId = Get-HistoricalNetworkWatcherResourceId `
    -ResourceId $liveNetworkWatcherId
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
    untrustedIdMissDidNotHideRole = $untrustedIdMissDidNotHideRole
    completeZeroMatchProvedAbsent = $completeZeroMatchProvedAbsent
    initiallyAbsentPostcheckAccepted = $initiallyAbsentPostcheckAccepted
    duplicateRejected = $duplicateRejected
    renamedRejected = $renamedRejected
    mismatchedBodyRejected = $mismatchRejected
    historicalWatcherUsesAzureReturnedId = $historicalNetworkWatcherId -ceq $liveNetworkWatcherId
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
        "untrustedIdMissDidNotHideRole": True,
        "completeZeroMatchProvedAbsent": True,
        "initiallyAbsentPostcheckAccepted": True,
        "duplicateRejected": True,
        "renamedRejected": True,
        "mismatchedBodyRejected": True,
        "historicalWatcherUsesAzureReturnedId": True,
        "wrongWatcherRejected": True,
    }


def test_upgrade_cleanup_assignment_helpers_reject_duplicates_and_remaining_bindings() -> None:
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
    'Get-RoleAssignmentGuid',
    'Resolve-ReviewedTargetRoleAssignment',
    'Assert-ReviewedTargetRoleAssignmentsAbsent'
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
$CollectorPrincipalId = '22222222-2222-2222-2222-222222222222'
$subscriptionScope = '/subscriptions/00000000-0000-0000-0000-000000000000'
$targetScope = (
    "$subscriptionScope/resourceGroups/rg-synthetic/providers/" +
    'Microsoft.KeyVault/vaults/synthetic-vault/keys/monitoring-intent'
)
$roleDefinitionId = (
    "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/" +
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
)
$target = [pscustomobject]@{{
    Key = 'synthetic-key-reader'
    Name = 'synthetic collector key reader'
    Scope = $targetScope
    RoleDefinitionId = $roleDefinitionId
    RoleDefinitionName = 'Athena WC028 Synthetic Key Reader'
}}
$assignment = [pscustomobject]@{{
    id = (
        "$targetScope/providers/Microsoft.Authorization/roleAssignments/" +
        'dddddddd-dddd-dddd-dddd-dddddddddddd'
    )
    principalId = $CollectorPrincipalId
    principalType = 'ServicePrincipal'
    roleDefinitionId = $roleDefinitionId
    roleDefinitionName = $target.RoleDefinitionName
    scope = $targetScope
    condition = $null
    conditionVersion = $null
}}
function New-AssignmentInventory {{
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items)
    return [pscustomobject]@{{
        QueryKind = 'independent-complete-subscription-principal-assignment-enumeration'
        TargetKey = $target.Key
        Scope = $subscriptionScope
        RequestedTargetScope = $target.Scope
        PrincipalId = $CollectorPrincipalId
        Items = $Items
    }}
}}

$resolved = Resolve-ReviewedTargetRoleAssignment `
    -Inventory (New-AssignmentInventory -Items @($assignment)) `
    -Target $target
$azureReturnedIdAccepted = (
    [string]$resolved.Status -eq 'found' -and
    [string]$resolved.RoleAssignmentId -eq (
        Normalize-ResourceId -ResourceId ([string]$assignment.id)
    )
)

$duplicateAssignment = $assignment.PSObject.Copy()
$duplicateAssignment.id = ([string]$assignment.id).Replace(
    'dddddddd-dddd-dddd-dddd-dddddddddddd',
    'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
)
$duplicateRejected = $false
try {{
    Resolve-ReviewedTargetRoleAssignment `
        -Inventory (New-AssignmentInventory -Items @($assignment, $duplicateAssignment)) `
        -Target $target | Out-Null
}} catch {{
    $duplicateRejected = $_.Exception.Message -like '*duplicate*'
}}
if (-not $duplicateRejected) {{
    throw 'Duplicate exact assignments were accepted.'
}}

$assignmentRemainsRejected = $false
try {{
    Assert-ReviewedTargetRoleAssignmentsAbsent `
        -Inventory (New-AssignmentInventory -Items @($assignment)) `
        -Target $target
}} catch {{
    $assignmentRemainsRejected = $_.Exception.Message -like '*remains assigned*'
}}
if (-not $assignmentRemainsRejected) {{
    throw 'A remaining exact assignment passed post-cleanup verification.'
}}

$emptyInventory = New-AssignmentInventory -Items @()
$zeroMatchProof = Assert-ReviewedTargetRoleAssignmentsAbsent `
    -Inventory $emptyInventory `
    -Target $target
$zeroMatchAbsentAccepted = (
    $zeroMatchProof -like 'independent complete subscription assignment enumeration*'
)

$absentRoleTarget = [pscustomobject]@{{
    Key = $target.Key
    Name = $target.Name
    Scope = $target.Scope
    RoleDefinitionId = $null
    RoleDefinitionName = $target.RoleDefinitionName
}}
$namedAssignmentAfterRoleAbsenceRejected = $false
try {{
    Resolve-ReviewedTargetRoleAssignment `
        -Inventory (New-AssignmentInventory -Items @($assignment)) `
        -Target $absentRoleTarget | Out-Null
}} catch {{
    $namedAssignmentAfterRoleAbsenceRejected = (
        $_.Exception.Message -like '*proved that role identity absent*'
    )
}}
if (-not $namedAssignmentAfterRoleAbsenceRejected) {{
    throw 'An assignment contradicted a complete role-definition absence proof.'
}}

$unresolvedAssignment = $assignment.PSObject.Copy()
$unresolvedAssignment.roleDefinitionName = $null
$unresolvedAssignmentRejected = $false
try {{
    Resolve-ReviewedTargetRoleAssignment `
        -Inventory (New-AssignmentInventory -Items @($unresolvedAssignment)) `
        -Target $absentRoleTarget | Out-Null
}} catch {{
    $unresolvedAssignmentRejected = (
        $_.Exception.Message -like '*could not be resolved*'
    )
}}
if (-not $unresolvedAssignmentRejected) {{
    throw 'An unresolved assignment was accepted as proof that an absent role was unassigned.'
}}

[ordered]@{{
    azureReturnedIdAccepted = $azureReturnedIdAccepted
    duplicateRejected = $duplicateRejected
    assignmentRemainsRejected = $assignmentRemainsRejected
    zeroMatchAbsentAccepted = $zeroMatchAbsentAccepted
    namedAssignmentAfterRoleAbsenceRejected = $namedAssignmentAfterRoleAbsenceRejected
    unresolvedAssignmentRejected = $unresolvedAssignmentRejected
}} | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {
        "azureReturnedIdAccepted": True,
        "duplicateRejected": True,
        "assignmentRemainsRejected": True,
        "zeroMatchAbsentAccepted": True,
        "namedAssignmentAfterRoleAbsenceRejected": True,
        "unresolvedAssignmentRejected": True,
    }
