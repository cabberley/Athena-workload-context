from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _job_module(source: str, name: str) -> str:
    pattern = (
        rf"module {name} 'br/public:avm/res/app/job:0\.7\.2' = \{{(?P<body>.*?)\n\}}"
        rf"(?:\n\nmodule|\n\n@description)"
    )
    match = re.search(
        pattern,
        source,
        re.DOTALL,
    )
    assert match is not None
    return match.group(0)


def _loop_role_assignment(source: str, name: str) -> str:
    pattern = (
        rf"resource {name} 'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        rf"\[for .*?: \{{(?P<body>.*?)\n\}}\]"
    )
    match = re.search(pattern, source, re.DOTALL)
    assert match is not None
    return match.group(0)


def _example_object_ids(example: str) -> tuple[str, str]:
    guid_pattern = r"(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    reader = re.search(
        rf"param operatorArtifactReaderObjectIds = \[\s*'{guid_pattern}'\s*\]",
        example,
        re.DOTALL,
    )
    writer = re.search(
        rf"param workloadReceiptWriterObjectIds = \[\s*'{guid_pattern}'\s*\]",
        example,
        re.DOTALL,
    )
    assert reader is not None
    assert writer is not None
    return reader.group('id'), writer.group('id')


def test_wc013_bicep_keeps_runtime_private_keyless_and_least_privileged() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")
    compiled = _read("infra/wc013-live-acceptance/main.json")
    foundation = _read("infra/azure-mcp/main.bicep")
    workload_rbac = _read("infra/azure-mcp/modules/workload-read-rbac.bicep")
    acr_rbac = _read("infra/wc013-live-acceptance/modules/acr-pull-rbac.bicep")

    assert "workloadReadScopes: [" in orchestration
    assert "approvedLogWorkspaces: []" in orchestration
    assert "contains(acceptanceImage, '@sha256:')" in orchestration
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" in workload_rbac
    expected_reader_scope = (
        "scope: resourceGroup(readScope.subscriptionId, readScope.resourceGroupName)"
    )
    assert expected_reader_scope in foundation
    assert "privateEndpointNetworkPolicies: 'Disabled'" in foundation
    assert "publicNetworkAccess: 'Disabled'" in resources
    assert "allowSharedKeyAccess: false" in resources
    assert "defaultToOAuthAuthentication: true" in resources
    assert "service: 'blob'" in resources
    assert "storageBlobPrivateDnsZoneResourceId" in orchestration
    assert "privatelink.blob.core.windows.net" in _read(
        "infra/wc013-live-acceptance/modules/private-dns.bicep"
    )
    assert "isVersioningEnabled: true" in resources
    assert "immutableStorageWithVersioningEnabled: true" in resources
    assert "immutabilityPeriodSinceCreationInDays: artifactRetentionDays" in resources
    assert "allowProtectedAppendWrites: false" in resources
    assert "allowProtectedAppendWritesAll: false" in resources
    assert "scope: artifactContainer" in resources
    assert "storageBlobDataContributorRoleDefinitionId" in resources
    assert "param operatorArtifactReaderObjectIds array" in orchestration
    assert "operatorArtifactReaderObjectIds: operatorArtifactReaderObjectIds" in orchestration
    assert "param workloadReceiptWriterObjectIds array = []" in orchestration
    assert "workloadReceiptWriterObjectIds: workloadReceiptWriterObjectIds" in orchestration
    assert "param workloadReceiptWriterObjectIds array = []" in resources
    assert "storageBlobDataReaderRoleDefinitionId" in resources
    assert "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1" in resources

    reader_rbac = _loop_role_assignment(resources, "operatorArtifactBlobDataReaders")
    assert "scope: artifactContainer" in reader_rbac
    assert "for operatorArtifactReaderObjectId in operatorArtifactReaderObjectIds" in reader_rbac
    assert "principalId: operatorArtifactReaderObjectId" in reader_rbac
    assert "storageBlobDataReaderRoleDefinitionId" in reader_rbac
    assert "storageBlobDataContributorRoleDefinitionId" not in reader_rbac

    writer_rbac = _loop_role_assignment(resources, "workloadReceiptBlobDataContributors")
    assert "scope: artifactContainer" in writer_rbac
    assert "for workloadReceiptWriterObjectId in workloadReceiptWriterObjectIds" in writer_rbac
    assert "principalId: workloadReceiptWriterObjectId" in writer_rbac
    assert "storageBlobDataContributorRoleDefinitionId" in writer_rbac
    for forbidden in (
        "scope: replayTable",
        "storageTableDataContributorRoleDefinitionId",
        "storageBlobDataReaderRoleDefinitionId",
        "roleDefinitionIdOrName: 'Key Vault Crypto User'",
        "acceptanceIdentityPrincipalId",
        "evidenceIdentityResourceId",
    ):
        assert forbidden not in writer_rbac

    assert resources.count("scope: artifactContainer") == 3
    assert "artifactContainerResourceId" in orchestration
    assert "artifactBlobEndpoint" in orchestration
    assert "artifactContainerName" in orchestration
    assert "roleDefinitionIdOrName: 'Key Vault Crypto User'" in resources
    assert "scope: replayTable" in resources
    assert "storageTableDataContributorRoleDefinitionId" in resources
    assert "triggerType: 'Manual'" in resources
    assert "replicaRetryLimit: 0" in resources
    assert "acceptanceIdentityResourceId" in resources
    assert "evidenceIdentityResourceId" in resources
    assert "AZURE_CLIENT_ID" in resources
    assert "operationalPhaseJobNames" in orchestration

    example = _read("infra/wc013-live-acceptance/main.example.bicepparam")
    reader_id, writer_id = _example_object_ids(example)
    assert reader_id == writer_id
    assert reader_id not in orchestration
    assert reader_id not in resources
    assert reader_id not in compiled

    for forbidden_role in (
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "b24988ac-6180-42a0-ab88-20f7382dd24c",
    ):
        assert forbidden_role not in orchestration
        assert forbidden_role not in resources
        assert forbidden_role not in writer_rbac

    assert "workloadReceiptWriterObjectIds" in compiled
    assert "workloadReceiptWriterObjectIds" not in foundation
    assert "workloadReceiptWriterObjectIds" not in workload_rbac
    assert "workloadReceiptWriterObjectIds" not in acr_rbac

    for forbidden in ("passwordSecretRef", "connectionString", "listKeys(", "secrets:"):
        assert forbidden not in resources


def test_wc013_container_images_use_the_packaged_cli_and_only_reviewed_config_files() -> None:
    runner = _read("Dockerfile")
    delivery = _read("Dockerfile.wc013-delivery")
    dockerignore = _read(".dockerignore")

    assert "python -m pip install --no-cache-dir ." in runner
    assert 'ENTRYPOINT ["athena-context"]' in runner
    assert '"wc013-live-acceptance"' in runner
    assert "USER athena" in runner
    assert "wc013-live/ /opt/athena/wc013-live/" in delivery
    assert "wc013-signing-public-key.pem" in delivery
    assert "!src/**" in dockerignore
    assert "!pyproject.toml" in dockerignore



def test_wc013_phase_jobs_are_phase_fixed_direct_commands_with_minimal_rbac() -> None:
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")

    assert resources.count("'operational-phase-job'") == 3
    assert (
        "var operationalPhaseBundlePath = "
        "'/opt/athena/wc013-live/delivery/operational-phase-bundle.json'"
        in resources
    )
    assert "output operationalPhaseJobNames object = {" in resources

    expectations = {
        "baselineOperationalPhaseJob": (
            "baseline",
            "baselineOperationalInputsPath",
            "baselineOperationalHandoffPath",
        ),
        "faultedOperationalPhaseJob": (
            "faulted",
            "faultedOperationalInputsPath",
            "faultedOperationalHandoffPath",
        ),
        "recoveredOperationalPhaseJob": (
            "recovered",
            "recoveredOperationalInputsPath",
            "recoveredOperationalHandoffPath",
        ),
    }
    for module_name, (phase, inputs_path, handoff_path) in expectations.items():
        block = _job_module(resources, module_name)
        lowered = block.casefold()

        assert "triggerType: 'Manual'" in block
        assert "'athena-context'" in block
        assert "'operational-phase-job'" in block
        assert "'--phase'" in block
        assert f"'{phase}'" in block
        assert "'--bundle'" in block
        assert "operationalPhaseBundlePath" in block
        assert "'--inputs-output'" in block
        assert inputs_path in block
        assert "'--handoff-output'" in block
        assert handoff_path in block
        assert "'--artifact-blob-endpoint'" in block
        assert "replayStorage.outputs.serviceEndpoints.blob" in block
        assert "'--artifact-container'" in block
        assert "artifactContainerName" in block
        assert "'--emit-handoff-base64'" in block
        assert "acceptanceIdentityResourceId" in block
        assert "evidenceIdentityResourceId" in block
        assert "AZURE_CLIENT_ID" in block
        assert "/bin/sh" not in block
        assert "passwordsecretref" not in lowered
        assert "connectionstring" not in lowered
        assert "secrets:" not in lowered
        assert " listkeys(" not in lowered
        assert "inject" not in lowered
        assert " reset" not in lowered
        assert " status" not in lowered
