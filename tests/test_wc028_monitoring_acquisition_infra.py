from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "wc028-monitoring-acquisition"
BICEP = INFRA / "main.bicep"


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
        "ATHENA_WC028_DEPLOYED_SOURCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_CONTAINER_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID",
        "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID",
        "ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID",
        "modules/acquisition-rbac.bicep",
        "legacyCollectorRbacCleanupDigest",
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


def test_upgrade_cleanup_targets_only_exact_legacy_collector_bindings() -> None:
    cleanup = (INFRA / "remove-obsolete-collector-rbac.ps1").read_text(encoding="utf-8")

    for expected in (
        "Athena WC028 Bounded Acquisition Reader",
        "Athena WC028 Change Evidence Create-Only Writer",
        "Athena WC028 Monitoring Intent Key Reader",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        "'role', 'assignment', 'delete', '--ids'",
        "'role', 'definition', 'delete'",
        "'identity', 'show'",
        "cleanupEvidenceDigest",
        "verifiedAbsentBindings",
        "Assert-ResourceSubscription",
        "Assert-RoleDefinitionAbsent",
        "$roleDefinitionGuid",
    ):
        assert expected in cleanup

    for forbidden in (
        "'role', 'assignment', 'delete', '--assignee'",
        "Remove-AzRoleAssignment",
        "--scope', '/subscriptions/",
        "Microsoft.Authorization/roleAssignments/delete",
    ):
        assert forbidden not in cleanup
