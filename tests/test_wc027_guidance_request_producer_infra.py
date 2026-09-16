import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "infra" / "wc027-guidance-publication-request-producer" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
KEY_PUBLIC_READER = (
    ROOT
    / "infra"
    / "wc027-guidance-publication-request-producer"
    / "modules"
    / "key-public-reader-rbac.bicep"
)
BLOB_CREATOR = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "modules" / "blob-create-rbac.bicep"
)
BLOB_READER = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "blob-reader-rbac.bicep"
)
KEY_SIGNER = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "modules" / "key-signer-rbac.bicep"
)
DOCKERFILE = ROOT / "apps" / "guidance-publication-request-producer" / "Dockerfile"
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
ROOT_ACCEPTANCE = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
JOB_RUNTIME_ID = ROOT / "infra" / "wc013-live-acceptance" / "modules" / "job-runtime-id.bicep"


def _evaluate_job_resource_id(
    source: str,
    *,
    prefix: str,
    resource_id: str,
    runtime_resource_id: str,
    expected_subscription_id: str,
    expected_resource_group_name: str,
) -> tuple[list[str], bool]:
    declaration = source.split(
        f"var {prefix}JobResourceIdSegments = concat(",
        maxsplit=1,
    )[1].split(
        f"var {prefix}JobResourceIdShapeValid",
        maxsplit=1,
    )[0]
    raw_segments = resource_id.split("/")
    padding = [""] * 9
    raw_segments_first = declaration.index(f"{prefix}JobResourceIdRawSegments") < declaration.index(
        "["
    )
    segments = [*raw_segments, *padding] if raw_segments_first else [*padding, *raw_segments]
    valid = (
        len(raw_segments) == 9
        and not segments[0]
        and segments[1] == "subscriptions"
        and bool(segments[2])
        and segments[2].casefold() == expected_subscription_id.casefold()
        and segments[3] == "resourceGroups"
        and bool(segments[4])
        and segments[4].casefold() == expected_resource_group_name.casefold()
        and segments[5] == "providers"
        and segments[6] == "Microsoft.App"
        and segments[7] == "jobs"
        and bool(segments[8])
        and not any(alias in resource_id for alias in ("//", "?", "#", "%"))
        and runtime_resource_id.casefold() == resource_id.casefold()
    )
    return segments, valid


def test_request_producer_is_a_separate_private_idempotent_job() -> None:
    source = PRODUCER.read_text(encoding="utf-8")

    for expected in (
        "wc027-guidance-publication-inputs",
        "wc027-guidance-authority-requests",
        "requiresSession: true",
        "requiresDuplicateDetection: true",
        "duplicateDetectionHistoryTimeWindow: 'PT15M'",
        "defaultMessageTimeToLive: 'PT15M'",
        "maxMessageSizeInKilobytes: 12288",
        "maxExecutions: 1",
        "isSessionsEnabled: 'true'",
        "@minLength(1)\n@maxLength(8)\nparam inputSubmitterIdentityResourceIds array",
        "input submitters must be unique and separate from producer identities",
        "must match the embedded WC-027 runtime namespace",
        "request queue must require sessions and duplicate detection",
        "receiverIdentityResourceId",
        "senderIdentityResourceId",
        "incidentReaderIdentityResourceId",
        "contextAuthorityReaderIdentityResourceId",
        "outboxReaderIdentityResourceId",
        "outboxWriterIdentityResourceId",
        "upstreamTrustReaderIdentityResourceId",
        "requestSignerIdentityResourceId",
        "requestVerifierIdentityResourceId",
        "wc027-guidance-request-outbox",
        "modules/blob-container.bicep",
        "outboxContainerDeployment",
        "requestedActions: [",
        "'investigationCheck'",
        "ATHENA_WC027_GUIDANCE_REQUEST_PRODUCER_CONFIG_JSON",
        "wc027-guidance-publication-request-producer",
        "output publisherHandoffJson string",
        "output requestSenderIdentityResourceId string",
        "output requestKeyVaultKeyId string",
        "output inputQueueResourceId string",
        "output outputQueueResourceId string",
        "output requestOutboxBlobEndpoint string",
        "output requestOutboxContainerName string",
    ):
        assert expected in source

    assert "PublishedGuidanceAuthorityBinding" not in source
    assert "runtimeActivation" not in source
    assert "tables/entities" not in source
    assert "listKeys(" not in source
    assert "allowSharedKeyAccess: true" not in source
    assert "publicNetworkAccess: 'Enabled'" not in source


def test_request_producer_rbac_is_exact_and_non_destructive() -> None:
    source = PRODUCER.read_text(encoding="utf-8")
    public_reader = KEY_PUBLIC_READER.read_text(encoding="utf-8")
    signer = KEY_SIGNER.read_text(encoding="utf-8")
    blob_creator = BLOB_CREATOR.read_text(encoding="utf-8")
    blob_reader = BLOB_READER.read_text(encoding="utf-8")

    assert "scope: inputQueue" in source
    assert "scope: outputQueue" not in source
    assert "serviceBusDataReceiverRoleDefinitionId" in source
    assert "serviceBusDataSenderRoleDefinitionId" in source
    assert "modules/key-public-reader-rbac.bicep" in source
    assert "../wc027-guidance-authority-publisher/modules/key-signer-rbac.bicep" in source
    assert "../wc027-guidance-authority-publisher/modules/blob-create-rbac.bicep" in source
    assert "../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep" in source

    assert "Microsoft.KeyVault/vaults/keys/read" in public_reader
    for forbidden in (
        "keys/sign/action",
        "keys/verify/action",
        "keys/encrypt/action",
        "keys/decrypt/action",
        "keys/wrap/action",
        "keys/unwrap/action",
        "keys/update",
        "keys/delete",
    ):
        assert forbidden not in public_reader

    assert "Microsoft.KeyVault/vaults/keys/sign/action" in signer
    assert "keys/read" not in signer
    assert (
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action" in blob_creator
    )
    assert "blobs/read" not in blob_creator
    assert "blobs/delete" not in blob_creator
    assert "SubOperationMatches{\\'Blob.List\\'}" in blob_reader
    assert "blobs/write" not in blob_reader
    assert "blobs/delete" not in blob_reader


def test_request_producer_creates_a_private_outbox_container() -> None:
    source = (PRODUCER.parent / "modules" / "blob-container.bicep").read_text(encoding="utf-8")

    assert "Microsoft.Storage/storageAccounts/blobServices/containers" in source
    assert "publicAccess: 'None'" in source
    assert "allowBlobPublicAccess" not in source


def test_request_producer_image_is_digest_pinned_and_non_root() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")

    assert (
        "FROM python:3.14.7-slim-bookworm@sha256:"
        "416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63" in source
    )
    assert "USER 10001:10001" in source
    assert 'ENTRYPOINT ["athena-context", "wc027-guidance-publication-request-producer"]' in source
    assert "latest" not in source.casefold()


def test_request_producer_configuration_and_publisher_handoff_are_derived() -> None:
    source = PRODUCER.read_text(encoding="utf-8")

    for expected in (
        "parsedRuntimeConfiguration.incidentLifecycleAssets",
        "parsedRuntimeConfiguration.correlationSources.contextAuthority",
        "parsedRuntimeConfiguration.keys.incident",
        "parsedRuntimeConfiguration.keys.correlationBinding",
        "incidentKey.properties.keyUriWithVersion == runtimeIncidentKey.keyVaultKeyId",
        (
            "correlationBindingKey.properties.keyUriWithVersion == "
            "runtimeCorrelationBindingKey.keyVaultKeyId"
        ),
        "guidance publication-request key must be distinct",
        "bindingEvidenceDigest = guid(join(rbacResourceIds, '|'))",
        "attachedIdentityResourceIds: validatedAttachedIdentityResourceIds",
        "rbacResourceIds: rbacResourceIds",
        "schemaVersion: 'athena.wc027GuidancePublicationRequestPublisherHandoff.v1'",
        "requestQueueName: validatedOutputQueueName",
        "senderIdentityResourceId: senderIdentity.id",
        "requestKeyResourceId: requestKey.id",
        "requestOutbox:",
        "blobEndpoint: outboxBlobEndpoint",
        "containerName: outboxContainerName",
        "outboxBlobService.properties.isVersioningEnabled == true",
        "outboxStorageAccountResourceId must have Blob versioning enabled",
    ):
        assert expected in source


def test_delivery_budget_is_bound_across_producer_publisher_and_readiness() -> None:
    producer = PRODUCER.read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")
    runtime = RUNTIME.read_text(encoding="utf-8")
    root = ROOT_ACCEPTANCE.read_text(encoding="utf-8")

    for source in (producer, publisher, runtime):
        for expected in (
            "guidancePublisherKedaPollingIntervalSeconds = 30",
            "guidancePublisherColdStartSeconds = 30",
            "guidancePublisherConnectionSetupSeconds = 30",
            "guidancePublisherProcessingSeconds = 60",
            "guidancePublisherCasMarginSeconds = 5",
            (
                "guidancePublisherMinimumRemainingLifetimeSeconds = "
                "guidancePublisherKedaPollingIntervalSeconds + "
                "guidancePublisherColdStartSeconds + "
                "guidancePublisherConnectionSetupSeconds + "
                "guidancePublisherProcessingSeconds"
            ),
            "guidanceFeedKedaPollingIntervalSeconds = 30",
            "guidanceFeedColdStartSeconds = 30",
            "guidanceFeedConnectionSetupSeconds = 30",
            "guidanceFeedProcessingSeconds = 60",
            "guidanceFeedDeliveryJitterSeconds = 30",
            "guidanceFeedIrreversibleWriteMarginSeconds = 15",
            (
                "guidanceFeedMinimumRemainingLifetimeSeconds = "
                "guidanceFeedKedaPollingIntervalSeconds + "
                "guidanceFeedColdStartSeconds + "
                "guidanceFeedConnectionSetupSeconds + "
                "guidanceFeedProcessingSeconds"
            ),
            "guidanceFeedTriggerRecoverySeconds = 300",
            (
                "guidanceMinimumRemainingLifetimeSeconds = "
                "guidancePublisherMinimumRemainingLifetimeSeconds"
            ),
            "deliveryBudget: guidancePublicationDeliveryBudget",
        ):
            assert expected in source

    assert "pollingInterval: guidancePublisherKedaPollingIntervalSeconds" in publisher
    assert "pollingInterval: guidanceFeedKedaPollingIntervalSeconds" in runtime
    for expected in (
        "wc027ReviewedPublisherKedaPollingIntervalSeconds = 30",
        "wc027ReviewedPublisherColdStartSeconds = 30",
        "wc027ReviewedPublisherConnectionSetupSeconds = 30",
        "wc027ReviewedPublisherProcessingSeconds = 60",
        "wc027ReviewedPublisherCasMarginSeconds = 5",
        "wc027ReviewedPublisherMinimumRemainingLifetimeSeconds",
        "wc027ReviewedFeedKedaPollingIntervalSeconds = 30",
        "wc027ReviewedFeedColdStartSeconds = 30",
        "wc027ReviewedFeedConnectionSetupSeconds = 30",
        "wc027ReviewedFeedProcessingSeconds = 60",
        "wc027ReviewedFeedDeliveryJitterSeconds = 30",
        "wc027ReviewedFeedIrreversibleWriteMarginSeconds = 15",
        "wc027ReviewedFeedMinimumRemainingLifetimeSeconds",
        "wc027ReviewedFeedTriggerRecoverySeconds = 300",
        "wc027ReviewedMinimumRemainingLifetimeSeconds",
        "wc027RequestProducerDeliveryBudgetValid",
        "wc027PublisherDeliveryBudgetValid",
        "wc027RuntimeDeliveryBudgetValid",
        "wc027ProducerPublisherDeliveryBudgetsMatch",
        "wc027RequestProducerRuntimeDeliveryBudgetsMatch",
        "wc027PublisherRuntimeDeliveryBudgetsMatch",
        "producer and publisher delivery budgets do not match",
        "publisher and enrichment runtime delivery budgets do not match",
        "request producer and enrichment runtime delivery budgets do not match",
        (
            "eventTriggerConfig.scale.pollingInterval == "
            "wc027PublisherDeliveryBudget.publisherKedaPollingIntervalSeconds"
        ),
    ):
        assert expected in root


def test_request_producer_image_pull_uses_validated_cross_rg_registry_scope() -> None:
    source = PRODUCER.read_text(encoding="utf-8")
    registry_subscription_id = "11111111-1111-1111-1111-111111111111"
    registry_resource_group = "rg-shared-acr"
    producer_resource_group = "rg-athena-runtime"
    registry_resource_id = (
        f"/subscriptions/{registry_subscription_id}/resourceGroups/"
        f"{registry_resource_group}/providers/Microsoft.ContainerRegistry/"
        "registries/athenashared"
    )

    assert registry_resource_group != producer_resource_group
    assert registry_resource_id.split("/")[2] == registry_subscription_id
    assert registry_resource_id.split("/")[4] == registry_resource_group
    for expected in (
        "registryResourceIdRawSegments = split(registryResourceId, '/')",
        "length(registryResourceIdRawSegments) == 9",
        "empty(registryResourceIdSegments[0])",
        "toLower(registryResourceIdSegments[1]) == 'subscriptions'",
        "toLower(registryResourceIdSegments[3]) == 'resourcegroups'",
        "toLower(registryResourceIdSegments[5]) == 'providers'",
        "toLower(registryResourceIdSegments[6]) == 'microsoft.containerregistry'",
        "toLower(registryResourceIdSegments[7]) == 'registries'",
        "registryResourceId must identify one Microsoft.ContainerRegistry/registries resource",
    ):
        assert expected in source

    registry_block = source.split(
        "resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing =",
        maxsplit=1,
    )[1].split("var expectedRegistryServer", maxsplit=1)[0]
    image_pull_block = source.split(
        "module producerImagePull '../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' =",
        maxsplit=1,
    )[1].split("var incidentContainerResourceId", maxsplit=1)[0]
    for block in (registry_block, image_pull_block):
        assert "scope: resourceGroup(" in block
        assert "validatedRegistryScope.subscriptionId" in block
        assert "validatedRegistryScope.resourceGroupName" in block
        assert "resourceGroup().name" not in block
    for expected in (
        "param registryRoleAssignmentMode string",
        "param receiverIdentityPrincipalId string",
        "identityPrincipalId: receiverIdentityPrincipalId",
        "repositoryName: imageRepositoryName",
        "var imageRepositoryName = 'athena/wc027-guidance-publication-request-producer'",
        "expectedRegistryRoleAssignmentMode: registryRoleAssignmentMode",
        "guid(",
        "registry.id",
        "receiverIdentityPrincipalId",
        "imagePullRoleDefinitionId",
        "imageRepositoryName",
    ):
        assert expected in source


def test_request_producer_rejects_every_runtime_identity_intersection() -> None:
    source = PRODUCER.read_text(encoding="utf-8")

    for expected in (
        "parsedRuntimeConfiguration.serviceBus.brokerIdentityResourceId",
        "parsedRuntimeConfiguration.incidentLifecycleAssets.identityResourceId",
        "parsedRuntimeConfiguration.enrichmentFeedAssets.readerIdentityResourceId",
        "parsedRuntimeConfiguration.enrichmentFeedAssets.writerIdentityResourceId",
        "parsedRuntimeConfiguration.feedRegistry.identityResourceId",
        "parsedRuntimeConfiguration.correlationSources.monitoring.identityResourceId",
        "parsedRuntimeConfiguration.correlationSources.change.identityResourceId",
        "parsedRuntimeConfiguration.correlationSources.contextAuthority.identityResourceId",
        "parsedRuntimeConfiguration.correlationSources.monitoringIntent.identityResourceId",
        "parsedRuntimeConfiguration.guidanceAuthoritySource.identityResourceId",
        "parsedRuntimeConfiguration.guidanceActivation.identityResourceId",
        "parsedRuntimeConfiguration.monitoringCollectorKey.identityResourceId",
        "parsedRuntimeConfiguration.keys.incident.identityResourceId",
        "parsedRuntimeConfiguration.keys.correlationBinding.identityResourceId",
        "parsedRuntimeConfiguration.keys.guidanceBinding.identityResourceId",
        "parsedRuntimeConfiguration.keys.change.identityResourceId",
        "parsedRuntimeConfiguration.keys.monitoringIntent.identityResourceId",
        "parsedRuntimeConfiguration.keys.report.identityResourceId",
        "parsedRuntimeConfiguration.keys.guidance.identityResourceId",
        "parsedRuntimeConfiguration.keys.enrichment.identityResourceId",
        "parsedRuntimeConfiguration.keys.feed.identityResourceId",
        "parsedRuntimeConfiguration.keys.notification.identityResourceId",
        "parsedRuntimeConfiguration.deploymentBinding.attachedIdentityResourceIds",
        "validatedRuntimeIdentityResourceIds",
        "normalizedAttachedIdentityResourceIds",
        "producerRuntimeIdentityOverlap = intersection(",
        "normalizedInputSubmitterIdentityResourceIds",
        "inputSubmitterProducerIdentityOverlap = intersection(",
        "producer identities must be separate from every runtime identity",
    ):
        assert expected in source


def test_readiness_is_false_by_default_and_closes_the_complete_chain() -> None:
    root = ROOT_ACCEPTANCE.read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")

    for expected in (
        "param wc027RequestProducerReady bool = false",
        "param wc027RequestProducerJobResourceId string = ''",
        "param wc027RequestProducerConfigurationDigest string = ''",
        "param wc027RequestProducerConfigurationJson string = ''",
        "param wc027RequestProducerImage string = ''",
        "validatedWc027RequestProducerReady",
        "wc027-guidance-publication-request-producer",
        "ATHENA_WC027_GUIDANCE_REQUEST_PRODUCER_CONFIG_JSON",
        "WC-027 Notification v2 requires an explicitly ready guidance publication-request producer",
        "publisher request queue does not match the request producer output queue",
        "publisher request submitter does not match the dedicated request producer sender",
        "publisher request outbox endpoint does not match the request producer",
        "publisher request outbox container does not match the request producer",
        "publisher request key version does not match the request producer",
        "publisher request key fingerprint does not match the request producer",
    ):
        assert expected in root

    assert "param wc027PublisherReady bool = false" in root
    assert "param wc027FeedV2ProducerReady bool = false" in root
    assert "requestSubmitterIdentityResourceIds" in publisher
    assert "requestSubmitters" in publisher
    for expected in (
        "output requestQueueResourceId string",
        "output requestKeyResourceId string",
        "output requestLogicalKeyId string",
        "output requestKeyVaultKeyId string",
        "output requestKeyFingerprint string",
        "output requestOutboxBlobEndpoint string",
        "output requestOutboxContainerName string",
    ):
        assert expected in publisher


@pytest.mark.parametrize(
    ("prefix", "resource_id_parameter", "runtime_module"),
    (
        (
            "wc027RequestProducer",
            "wc027RequestProducerJobResourceId",
            "wc027RequestProducerRuntimeId",
        ),
        (
            "wc027Publisher",
            "wc027PublisherJobResourceId",
            "wc027PublisherRuntimeId",
        ),
        (
            "wc027Producer",
            "wc027EnrichmentFeedProducerJobResourceId",
            "wc027ProducerRuntimeId",
        ),
    ),
)
@pytest.mark.parametrize(
    ("resource_id_variant", "expected_valid"),
    (
        ("canonical", True),
        ("missing-leading-slash", False),
        ("not-subscriptions", False),
        ("not-resource-groups", False),
        ("not-providers", False),
        ("provider-case-alias", False),
        ("type-case-alias", False),
        ("empty-name", False),
        ("child-suffix", False),
        ("duplicate-separator", False),
        ("query", False),
        ("fragment", False),
        ("encoded-separator", False),
        ("cross-subscription", False),
        ("cross-resource-group", False),
        ("runtime-id-mismatch", False),
    ),
)
def test_all_wc027_job_resource_ids_are_evaluated_as_canonical_syntax(
    prefix: str,
    resource_id_parameter: str,
    runtime_module: str,
    resource_id_variant: str,
    expected_valid: bool,
) -> None:
    source = ROOT_ACCEPTANCE.read_text(encoding="utf-8")
    subscription_id = "11111111-1111-1111-1111-111111111111"
    resource_group_name = "rg-athena-wc013-live"
    canonical = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/"
        "providers/Microsoft.App/jobs/wc027-job"
    )
    variants = {
        "canonical": canonical,
        "missing-leading-slash": canonical.removeprefix("/"),
        "not-subscriptions": canonical.replace("/subscriptions/", "/notSubscriptions/"),
        "not-resource-groups": canonical.replace("/resourceGroups/", "/notResourceGroups/"),
        "not-providers": canonical.replace("/providers/", "/notProviders/"),
        "provider-case-alias": canonical.replace("Microsoft.App", "microsoft.app"),
        "type-case-alias": canonical.replace("/jobs/", "/Jobs/"),
        "empty-name": canonical.removesuffix("wc027-job"),
        "child-suffix": canonical + "/executions/run-1",
        "duplicate-separator": canonical.replace("/providers/", "//providers/"),
        "query": canonical + "?api-version=2025-01-01",
        "fragment": canonical + "#publisher",
        "encoded-separator": canonical.replace("/jobs/", "/jobs%2F"),
        "cross-subscription": canonical.replace(
            subscription_id,
            "22222222-2222-2222-2222-222222222222",
        ),
        "cross-resource-group": canonical.replace(
            resource_group_name,
            "rg-cross-scope",
        ),
        "runtime-id-mismatch": canonical,
    }
    selected_resource_id = variants[resource_id_variant]
    runtime_resource_id = (
        canonical.replace("wc027-job", "different-job")
        if resource_id_variant == "runtime-id-mismatch"
        else selected_resource_id
    )

    segments, valid = _evaluate_job_resource_id(
        source,
        prefix=prefix,
        resource_id=selected_resource_id,
        runtime_resource_id=runtime_resource_id,
        expected_subscription_id=subscription_id,
        expected_resource_group_name=resource_group_name,
    )

    assert valid is expected_valid
    if expected_valid:
        assert segments[2] == subscription_id
        assert segments[4] == resource_group_name
        assert segments[8] == "wc027-job"

    shape = f"var {prefix}JobResourceIdShapeValid"
    assert shape in source
    for expected in (
        f"empty({prefix}JobResourceIdSegments[0])",
        f"{prefix}JobResourceIdSegments[1] == 'subscriptions'",
        (f"toLower({prefix}JobResourceIdSegments[2]) == toLower(subscription().subscriptionId)"),
        f"{prefix}JobResourceIdSegments[3] == 'resourceGroups'",
        (f"toLower({prefix}JobResourceIdSegments[4]) == toLower(foundationResourceGroupName)"),
        f"{prefix}JobResourceIdSegments[5] == 'providers'",
        f"{prefix}JobResourceIdSegments[6] == 'Microsoft.App'",
        f"{prefix}JobResourceIdSegments[7] == 'jobs'",
        f"!contains({resource_id_parameter}, '//')",
        f"!contains({resource_id_parameter}, '?')",
        f"!contains({resource_id_parameter}, '#')",
        f"!contains({resource_id_parameter}, '%')",
        (
            f"toLower({runtime_module}!.outputs.runtimeJobResourceId) == "
            f"toLower({resource_id_parameter})"
        ),
    ):
        assert expected in source
    assert f"var {prefix}RuntimeJobIdMatches" in source


def test_compiled_job_id_validity_uses_guarded_full_runtime_reference() -> None:
    az_cli = shutil.which("az")
    if az_cli is None:
        pytest.fail("az CLI is required to verify the compiled WC-027 root template")
    result = subprocess.run(
        [
            az_cli,
            "bicep",
            "build",
            "--file",
            str(JOB_RUNTIME_ID),
            "--stdout",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    template = json.loads(result.stdout)
    assert template["outputs"]["runtimeJobResourceId"]["value"] == (
        "[reference(parameters('jobResourceId'), '2025-01-01', 'Full').id]"
    )
    assert "resourceId(" not in template["outputs"]["runtimeJobResourceId"]["value"]
    assert "extensionResourceId(" not in template["outputs"]["runtimeJobResourceId"]["value"]

    root_result = subprocess.run(
        [
            az_cli,
            "bicep",
            "build",
            "--file",
            str(ROOT_ACCEPTANCE),
            "--stdout",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert root_result.returncode == 0, root_result.stderr
    deployments = [
        resource
        for resource in json.loads(root_result.stdout)["resources"]
        if resource.get("type") == "Microsoft.Resources/deployments"
        and "runtime-id" in str(resource.get("name"))
    ]
    assert {deployment["name"] for deployment in deployments} == {
        "wc027-feed-runtime-id",
        "wc027-request-producer-runtime-id",
        "wc027-publisher-runtime-id",
    }
    for deployment in deployments:
        assert deployment["condition"].startswith("[and(")
        assert deployment["properties"]["template"]["outputs"]["runtimeJobResourceId"]["value"] == (
            "[reference(parameters('jobResourceId'), '2025-01-01', 'Full').id]"
        )


def test_root_readiness_rejects_identity_overlap_and_unreviewed_job_surfaces() -> None:
    root = ROOT_ACCEPTANCE.read_text(encoding="utf-8")

    for expected in (
        "wc027RequestProducerConfigurationIdentitiesMatchBinding",
        "wc027PublisherConfigurationIdentitiesMatchBinding",
        "wc027RequestProducerRuntimeIdentityOverlap = intersection(",
        "wc027RequestProducerPublisherIdentityOverlap = intersection(",
        "wc027PublisherOwnedRuntimeIdentityOverlap = intersection(",
        "wc027PublisherRequestSubmitterRuntimeIdentityOverlap = intersection(",
        "wc027PublisherRequestSubmitterAttachedIdentityOverlap = intersection(",
        "request producer identities overlap the enrichment runtime identity boundary",
        "request producer identities overlap the publisher identity boundary",
        "publisher-owned identities overlap the enrichment runtime identity boundary",
        "publisher request submitter overlaps the enrichment runtime identity boundary",
        "publisher request submitter does not match the dedicated request producer sender",
        (
            "toLower(wc027ParsedPublisherConfiguration.serviceBus."
            "requestSubmitterIdentityResourceId) != "
            "toLower(wc027ParsedRequestProducerConfiguration.serviceBus."
            "senderIdentityResourceId)"
        ),
    ):
        assert expected in root

    for prefix in ("wc027RequestProducer", "wc027Publisher"):
        assert f"var {prefix}HasExactContainerCount" in root
        assert f"var {prefix}IdentityTypeMatches" in root
        assert f"var {prefix}HasExactScalerRuleCount" in root
        assert f"var {prefix}HasExactRegistryCount" in root
        assert f"var {prefix}TagsMatch" in root
        assert f"length({prefix}Job!.properties.template.containers) == 1" in root
        assert f"({prefix}Job!.identity.?type ?? '') == 'UserAssigned'" in root
        assert f"length({prefix}Job!.properties.template.containers[0].env) == 2" in root
        assert f"empty({prefix}Job!.properties.template.containers[0].?probes ?? [])" in root
        assert f"empty({prefix}Job!.properties.template.containers[0].?volumeMounts ?? [])" in root
        assert f"empty({prefix}Job!.properties.template.?initContainers ?? [])" in root
        assert f"empty({prefix}Job!.properties.template.?volumes ?? [])" in root
        assert f"empty({prefix}Job!.properties.configuration.?identitySettings ?? [])" in root
        assert f"empty({prefix}Job!.properties.configuration.?secrets ?? [])" in root
        assert f"{prefix}Job!.properties.configuration.replicaTimeout == 900" in root
        assert f"{prefix}Job!.properties.configuration.replicaRetryLimit == 0" in root
        assert f"{prefix}Job!.properties.configuration.eventTriggerConfig.parallelism == 1" in root
        assert (
            f"{prefix}Job!.properties.configuration.eventTriggerConfig.replicaCompletionCount == 1"
        ) in root
        assert (
            f"{prefix}Job!.properties.configuration.eventTriggerConfig.scale.minExecutions == 0"
        ) in root
        assert (
            f"{prefix}Job!.properties.configuration.eventTriggerConfig.scale.maxExecutions == 1"
        ) in root
        expected_polling_interval = (
            f"{prefix}Job!.properties.configuration.eventTriggerConfig.scale.pollingInterval == 30"
            if prefix == "wc027RequestProducer"
            else (
                f"{prefix}Job!.properties.configuration.eventTriggerConfig.scale."
                "pollingInterval == "
                "wc027PublisherDeliveryBudget.publisherKedaPollingIntervalSeconds"
            )
        )
        assert expected_polling_interval in root
        assert (
            f"empty({prefix}Job!.properties.configuration.eventTriggerConfig.scale."
            "rules[0].?auth ?? [])"
        ) in root
        assert (
            f"length(items({prefix}Job!.properties.configuration.eventTriggerConfig."
            "scale.rules[0].metadata)) == 5"
        ) in root
        assert (f"length(items({prefix}Job!.properties.configuration.registries[0])) == 2") in root

    request_gate = root.split("var validatedWc027RequestProducerReady =", maxsplit=1)[1].split(
        "var wc027ProducerJobResourceIdRawSegments",
        maxsplit=1,
    )[0]
    publisher_gate = root.split("var validatedWc027PublisherReady =", maxsplit=1)[1].split(
        "var wc027ProducerJobResourceIdSegments",
        maxsplit=1,
    )[0]
    assert "wc027RequestProducerJob!" not in request_gate
    assert "wc027PublisherJob!" not in publisher_gate

    for expected in (
        "wc027ParsedRequestProducerConfiguration.serviceBus.receiverIdentityClientId",
        "wc027ParsedPublisherConfiguration.serviceBus.brokerIdentityClientId",
        "metadata.messageCount == '1'",
        "metadata.cloud == 'AzurePublicCloud'",
        "metadata.isSessionsEnabled == 'true'",
        "properties.environmentId == azureMcp.outputs.managedEnvironmentResourceId",
        "properties.template.containers[0].resources.cpu == 1",
        "properties.template.containers[0].resources.memory == '2Gi'",
    ):
        assert expected in root
