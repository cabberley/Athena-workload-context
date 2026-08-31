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


def _role_assignment(source: str, name: str) -> str:
    pattern = (
        rf"resource {name} 'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        rf"\{{(?P<body>.*?)\n\}}"
    )
    match = re.search(pattern, source, re.DOTALL)
    assert match is not None
    return match.group(0)


def _loop_job_module(source: str, name: str) -> str:
    pattern = (
        rf"module {name} 'br/public:avm/res/app/job:0\.7\.2' = "
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
    foundation = _read("infra/azure-mcp/main.bicep")
    workload_rbac = _read("infra/azure-mcp/modules/workload-read-rbac.bicep")
    acr_rbac = _read("infra/wc013-live-acceptance/modules/acr-pull-rbac.bicep")

    assert "workloadReadScopes: [" in orchestration
    assert "approvedLogWorkspaces: []" in orchestration
    assert "acceptanceImageRepositoryPrefix" in orchestration
    assert "validatedAcceptanceImage" in orchestration
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
    assert (
        "for operatorArtifactReaderObjectId in "
        "validatedOperatorArtifactReaderObjectIds"
        in reader_rbac
    )
    assert "principalId: operatorArtifactReaderObjectId" in reader_rbac
    assert "storageBlobDataReaderRoleDefinitionId" in reader_rbac
    assert "storageBlobDataContributorRoleDefinitionId" not in reader_rbac

    writer_rbac = _loop_role_assignment(resources, "workloadReceiptBlobDataContributors")
    assert "scope: artifactContainer" in writer_rbac
    assert (
        "for workloadReceiptWriterObjectId in validatedWorkloadReceiptWriterObjectIds"
        in writer_rbac
    )
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
    assert "collectorArtifactContainerResourceId" in orchestration
    assert "collectorArtifactContainerName" in orchestration
    assert "roleDefinitionIdOrName: 'Key Vault Crypto User'" in resources
    assert "principalId: evidenceIdentityPrincipalId" in resources
    assert "scope: replayTable" in resources
    assert "storageTableDataContributorRoleDefinitionId" in resources
    assert "triggerType: 'Manual'" in resources
    assert "replicaRetryLimit: 0" in resources
    assert "acceptanceIdentityResourceId" in resources
    assert "evidenceIdentityResourceId" in resources
    assert "AZURE_CLIENT_ID" in resources
    assert "operationalPhaseJobNames" in orchestration
    assert "evidenceCollectorJobNames" in orchestration

    example = _read("infra/wc013-live-acceptance/main.example.bicepparam")
    reader_id, writer_id = _example_object_ids(example)
    assert reader_id != writer_id
    assert reader_id not in orchestration
    assert reader_id not in resources
    assert writer_id not in orchestration
    assert writer_id not in resources

    for forbidden_role in (
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "b24988ac-6180-42a0-ab88-20f7382dd24c",
    ):
        assert forbidden_role not in orchestration
        assert forbidden_role not in resources
        assert forbidden_role not in writer_rbac

    assert "workloadReceiptWriterObjectIds" in orchestration
    assert "workloadReceiptWriterObjectIds" not in foundation
    assert "workloadReceiptWriterObjectIds" not in workload_rbac
    assert "workloadReceiptWriterObjectIds" not in acr_rbac

    for forbidden in ("passwordSecretRef", "connectionString", "listKeys(", "secrets:"):
        assert forbidden not in resources


def _acceptance_image_is_exact(image: str, registry_server: str) -> bool:
    prefix = f"{registry_server}/athena/wc013-live@sha256:"
    digest = image.removeprefix(prefix)
    return (
        re.fullmatch(r"[a-z0-9]{5,50}\.azurecr\.io", registry_server) is not None
        and image == image.casefold()
        and image.startswith(prefix)
        and re.fullmatch(r"[a-f0-9]{64}", digest) is not None
        and digest != "0" * 64
    )


def test_wc013_arm_bicep_rejects_foreign_acceptance_images() -> None:
    registry_server = "athenafixture.azurecr.io"
    prefix = registry_server + "/athena/wc013-live@sha256:"
    valid = prefix + "a" * 64
    repeated_prefix_tail = prefix + "a" * (64 - len(prefix))
    invalid = (
        "mcr.microsoft.com/athena/wc013-live@sha256:" + "a" * 64,
        registry_server + "/other/wc013-live@sha256:" + "a" * 64,
        "otherfixture.azurecr.io/athena/wc013-live@sha256:" + "a" * 64,
        registry_server + "/athena/wc013-live@sha256:" + "A" * 64,
        registry_server + "/athena/wc013-live@sha256:" + "0" * 64,
        registry_server + "/athena/wc013-live:mutable",
        prefix + repeated_prefix_tail,
    )
    assert _acceptance_image_is_exact(valid, registry_server)
    assert all(
        not _acceptance_image_is_exact(image, registry_server) for image in invalid
    )

    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read(
        "infra/wc013-live-acceptance/modules/acceptance-resources.bicep"
    )
    for source in (orchestration, resources):
        assert (
            "acceptanceImageRepositoryPrefix = "
            "'${validatedAcceptanceImageRegistryServer}/athena/wc013-live@sha256:'"
            in source
        )
        assert "acceptanceImage == toLower(acceptanceImage)" in source
        assert (
            "length(acceptanceImage) == length(acceptanceImageRepositoryPrefix) + 64"
            in source
        )
        assert re.search(
            r"length\(\s*acceptanceImageDigestCandidate\s*\) == 64", source
        )
        assert re.search(
            r"empty\(\s*acceptanceImageDigestInvalidCharacters\s*\)", source
        )
        assert "? acceptanceImage" in source
        assert "exact acceptanceImageRegistryServer/athena/wc013-live repository" in source
    assert "expectedAcceptanceImageRegistryServer" in orchestration
    assert (
        "acceptanceImageRegistryServer: validatedAcceptanceImageRegistryServer"
        in orchestration
    )
    assert resources.count("image: validatedAcceptanceImage") == 6
    assert resources.count("server: validatedAcceptanceImageRegistryServer") == 6
    assert "image: acceptanceImage" not in resources
    assert "server: acceptanceImageRegistryServer" not in resources

def test_wc013_bicep_rejects_shared_operator_reader_and_receipt_writer_principals() -> None:
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")

    assert (
        "map(operatorArtifactReaderObjectIds, objectId => toLower(string(objectId)))"
        in resources
    )
    assert (
        "map(workloadReceiptWriterObjectIds, objectId => toLower(string(objectId)))"
        in resources
    )
    assert (
        "var overlappingArtifactAccessObjectIds = intersection(\n"
        "  normalizedOperatorArtifactReaderObjectIds,\n"
        "  normalizedWorkloadReceiptWriterObjectIds\n"
        ")"
        in resources
    )
    assert (
        "var validatedWorkloadReceiptWriterObjectIds = "
        "!empty(overlappingArtifactAccessObjectIds)"
        in resources
    )
    assert (
        "fail('operatorArtifactReaderObjectIds and workloadReceiptWriterObjectIds "
        "must contain distinct principals')"
        in resources
    )

    writer_rbac = _loop_role_assignment(resources, "workloadReceiptBlobDataContributors")
    assert (
        "for workloadReceiptWriterObjectId in validatedWorkloadReceiptWriterObjectIds"
        in writer_rbac
    )


def test_wc013_bicep_rejects_runtime_identities_in_operator_arrays() -> None:
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")

    assert (
        "var normalizedRuntimeIdentityPrincipalIds = [\n"
        "  toLower(acceptanceIdentityPrincipalId)\n"
        "  toLower(evidenceIdentityPrincipalId)\n"
        "]"
        in resources
    )
    assert (
        "var operatorRuntimeIdentityOverlap = intersection(\n"
        "  normalizedOperatorArtifactReaderObjectIds,\n"
        "  normalizedRuntimeIdentityPrincipalIds\n"
        ")"
        in resources
    )
    assert (
        "var workloadRuntimeIdentityOverlap = intersection(\n"
        "  normalizedWorkloadReceiptWriterObjectIds,\n"
        "  normalizedRuntimeIdentityPrincipalIds\n"
        ")"
        in resources
    )
    assert (
        "var validatedOperatorArtifactReaderObjectIds = "
        "empty(operatorRuntimeIdentityOverlap)"
        in resources
    )
    assert (
        "fail('operatorArtifactReaderObjectIds must not contain acceptance or "
        "evidence runtime identities')"
        in resources
    )
    assert (
        "empty(workloadRuntimeIdentityOverlap)\n"
        "    ? workloadReceiptWriterObjectIds\n"
        "    : fail('workloadReceiptWriterObjectIds must not contain acceptance "
        "or evidence runtime identities')"
        in resources
    )

    reader_rbac = _loop_role_assignment(resources, "operatorArtifactBlobDataReaders")
    writer_rbac = _loop_role_assignment(
        resources,
        "workloadReceiptBlobDataContributors",
    )
    assert "validatedOperatorArtifactReaderObjectIds" in reader_rbac
    assert "validatedWorkloadReceiptWriterObjectIds" in writer_rbac


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
        assert "'--evidence-blob-endpoint'" in block
        assert "'--evidence-container'" in block
        assert "collectorArtifactContainerName" in block
        assert "'--emit-handoff-base64'" in block
        assert "acceptanceIdentityResourceId" in block
        assert "evidenceIdentityResourceId" not in block
        assert "AZURE_CLIENT_ID" in block
        assert "/bin/sh" not in block
        assert "passwordsecretref" not in lowered
        assert "connectionstring" not in lowered
        assert "secrets:" not in lowered
        assert " listkeys(" not in lowered
        assert "inject" not in lowered
        assert " reset" not in lowered
        assert " status" not in lowered


def test_wc013_collector_and_athena_jobs_have_disjoint_identities() -> None:
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")
    acceptance = _job_module(resources, "acceptanceJob")
    collectors = _loop_job_module(resources, "evidenceCollectorJobs")

    assert "acceptanceIdentityResourceId" in acceptance
    assert "evidenceIdentityResourceId" not in acceptance
    assert "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID" not in acceptance
    assert "ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64" in acceptance
    assert "collectorArtifactContainerName" in acceptance

    assert "'wc013-evidence-collector-job'" in collectors
    assert "evidenceIdentityResourceId" in collectors
    assert "acceptanceIdentityResourceId" not in collectors
    assert "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID" in collectors
    assert "collectorArtifactContainerName" in collectors

    assert (
        "resource collectorArtifactBlobDataContributor "
        "'Microsoft.Authorization/roleAssignments@2022-04-01'"
        in resources
    )
    assert (
        "resource collectorArtifactBlobDataReader "
        "'Microsoft.Authorization/roleAssignments@2022-04-01'"
        in resources
    )
    assert "scope: collectorArtifactContainer" in resources

    replay_writer = _role_assignment(resources, "replayTableDataContributor")
    assert "principalId: evidenceIdentityPrincipalId" in replay_writer
    assert "acceptanceIdentityPrincipalId" not in replay_writer

    collector_writer = _role_assignment(
        resources,
        "collectorArtifactBlobDataContributor",
    )
    assert "scope: collectorArtifactContainer" in collector_writer
    assert "principalId: evidenceIdentityPrincipalId" in collector_writer
    assert "acceptanceIdentityPrincipalId" not in collector_writer

    collector_reader = _role_assignment(
        resources,
        "collectorArtifactBlobDataReader",
    )
    assert "scope: collectorArtifactContainer" in collector_reader
    assert "principalId: acceptanceIdentityPrincipalId" in collector_reader
    assert "evidenceIdentityPrincipalId" not in collector_reader


def test_wc013_collector_start_is_restricted_to_governed_controller() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read("infra/wc013-live-acceptance/modules/acceptance-resources.bicep")
    operations = _read("docs/operations/wc013-live-acceptance.md")
    acceptance = _job_module(resources, "acceptanceJob")
    collectors = _loop_job_module(resources, "evidenceCollectorJobs")

    assert "param collectorControllerPrincipalId string" not in orchestration
    assert "module collectorControllerIdentity" in orchestration
    assert "collectorControllerRoleDefinition" in orchestration
    assert "'Microsoft.App/jobs/read'" in orchestration
    assert "'Microsoft.App/jobs/start/action'" in orchestration
    assert "'Microsoft.App/jobs/executions/read'" in orchestration
    for forbidden in (
        "'Microsoft.App/jobs/write'",
        "'Microsoft.App/jobs/*/action'",
        "'Microsoft.App/jobs/exec/action'",
    ):
        assert forbidden not in orchestration
    assert (
        "collectorControllerPrincipalId: validatedCollectorControllerPrincipalId"
        in orchestration
    )
    assert "collectorControllerIdentity.outputs.principalId" in orchestration
    assert (
        "collectorControllerRoleDefinitionId: collectorControllerRoleDefinition.id"
        in orchestration
    )
    assert "roleAssignments:" in collectors
    assert "collectorControllerPrincipalId" in collectors
    assert "collectorControllerRoleDefinitionId" in collectors
    assert "roleAssignments:" not in acceptance
    assert "output evidenceCollectorStartContracts array" in resources
    assert "evidenceCollectorStartContracts" in orchestration
    assert "\naz containerapp job start `" not in operations
    assert "wc013-collector-controller" in operations
