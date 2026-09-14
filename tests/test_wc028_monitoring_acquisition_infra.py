from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "wc028-monitoring-acquisition"
BICEP = INFRA / "main.bicep"


def test_wc028_job_reuses_wc024_identity_key_and_evidence_boundary() -> None:
    source = BICEP.read_text(encoding="utf-8")

    for expected in (
        "Microsoft.App/jobs@2025-01-01",
        "triggerType: 'Schedule'",
        "cronExpression: validatedSchedule",
        "replicaTimeout: 600",
        "replicaRetryLimit: 1",
        "'athena-context'",
        "'wc028-monitoring-acquisition-job'",
        "AZURE_CLIENT_ID",
        "UserAssigned",
        "collectorIdentityResourceId",
        "collectorIdentity.properties.clientId",
        "collectorIdentity.properties.principalId",
        "monitoringEvidenceStorageAccountResourceId",
        "monitoringEvidenceContainerResourceId",
        "monitoringCollectorSigningKeyUriWithVersion",
        "ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_JSON",
        "ATHENA_WC028_MONITORING_ACQUISITION_CONFIG_DIGEST",
        "secretRef: 'wc028-runtime-configuration'",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID",
        "ATHENA_WC028_DEPLOYED_ATHENA_CONTEXT_IDENTITY_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_SOURCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_EVIDENCE_CONTAINER_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_COLLECTOR_SIGNING_KEY_ID",
        "ATHENA_WC028_DEPLOYED_WORKLOAD_RESOURCE_GROUP_ID",
        "ATHENA_WC028_DEPLOYED_NETWORK_WATCHER_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID",
        "ATHENA_WC028_DEPLOYED_CHANGE_EVIDENCE_CONTAINER_RESOURCE_ID",
        "changeEvidenceStorageAccountResourceId",
        "changeEvidenceContainerResourceId",
        "modules/acquisition-rbac.bicep",
        "scope: registry",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "configurationDigestInvalidCharacters",
    ):
        assert expected in source

    assert source.count("userAssignedIdentities:") == 1
    assert "'${validatedCollectorIdentityResourceId}': {}" in source
    assert "param collectorIdentityClientId" not in source
    assert "param collectorIdentityPrincipalId" not in source
    assert "monitoring-evidence" in source


def test_wc028_job_adds_no_broad_reader_or_monitoring_mutation() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(INFRA.rglob("*.bicep"))
    )

    for forbidden in (
        "acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "Microsoft.Insights/diagnosticSettings",
        "Microsoft.Insights/metricAlerts",
        "Microsoft.Insights/scheduledQueryRules",
        "Microsoft.Network/networkWatchers/connectionMonitors",
        "Storage Blob Data Owner",
        "Storage Blob Data Contributor",
        "Owner",
        "Contributor",
        "'*/read'",
        "'*/write'",
        "containers/blobs/delete",
        "containers/blobs/list",
        "listKeys(",
        "connectionString",
    ):
        assert forbidden not in source

    for required_permission in (
        "Microsoft.Insights/eventtypes/values/read",
        "Microsoft.ResourceGraph/resources/read",
        "Microsoft.Resources/changes/read",
        "Microsoft.Network/networkWatchers/ipFlowVerify/action",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        "changeEvidenceBlobService.properties.isVersioningEnabled == true",
    ):
        assert required_permission in source

    assert source.count("Microsoft.Authorization/roleAssignments") == 4
    for role_name in (
        "boundedAcquisitionReaderRole",
        "ipFlowVerifyRole",
        "createOnlyChangeEvidenceRole",
    ):
        assert (
            f"resource {role_name} "
            "'Microsoft.Authorization/roleDefinitions@2022-04-01'"
        ) in source
    assert "autoRemediation: 'disabled'" in source
    assert "normalizedCollectorIdentityResourceId != normalizedContextIdentityResourceId" in source
    assert (
        "monitoringEvidenceStorageAccountResourceId) != "
        "toLower(sourceAuthorityStorageAccountResourceId)"
    ) in source
    assert "scope: workloadResourceGroup" in source
    assert "scope: networkWatcher" in source
    assert "scope: changeEvidenceContainer" in source
