from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
ROOT_DEPLOYMENT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
BLOB_CREATOR = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "blob-create-rbac.bicep"
)
TABLE_CAS = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "table-cas-rbac.bicep"
)
KEY_SIGNER = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "key-signer-rbac.bicep"
)


def _evaluate_registry_resource_id(resource_id: str) -> tuple[list[str], bool]:
    raw_segments = resource_id.split("/")
    segments = [*raw_segments, *([""] * 9)]
    valid = (
        len(raw_segments) == 9
        and not segments[0]
        and segments[1] == "subscriptions"
        and bool(segments[2])
        and segments[3] == "resourceGroups"
        and bool(segments[4])
        and segments[5] == "providers"
        and segments[6] == "Microsoft.ContainerRegistry"
        and segments[7] == "registries"
        and bool(segments[8])
        and not any(alias in resource_id for alias in ("//", "?", "#", "%"))
    )
    return segments, valid


def test_publisher_is_private_idempotent_and_uses_separated_authorities() -> None:
    source = PUBLISHER.read_text(encoding="utf-8")

    for expected in (
        "requiresSession: true",
        "requiresDuplicateDetection: true",
        "defaultMessageTimeToLive: 'PT10M'",
        "maxDeliveryCount: 10",
        "maxMessageSizeInKilobytes: 12288",
        "maxExecutions: 1",
        "wc027-guidance-authority-requests",
        "wc027-enrichment-feed-requests",
        "wc027-guidance-authority",
        "authorityReaderIdentityResourceId",
        "authorityWriterIdentityResourceId",
        "activationWriterIdentityResourceId",
        "bindingSignerIdentityResourceId",
        "requestTrustReaderIdentityResourceId",
        "bindingTrustReaderIdentityResourceId",
        "requestOutboxReaderIdentityResourceId",
        "requestOutboxStorageAccountResourceId",
        "@maxLength(1)\nparam requestSubmitterIdentityResourceIds array",
        "@minLength(5)\n@maxLength(5)\nparam sourceIdentityResourceIds array",
        "requires one dedicated request submitter identity",
        "requestSubmitterIdentityClientId",
        "requestSubmitterIdentityResourceId",
        "requestOutbox:",
        "wc027-guidance-request-outbox",
        "requestOutboxReaderRbac",
        "requestOutboxBlobService.properties.isVersioningEnabled == true",
        "keyId: requestLogicalKeyId",
        "keyId: bindingLogicalKeyId",
        "keyVaultKeyId: requestKey.properties.keyUriWithVersion",
        "keyVaultKeyId: bindingKey.properties.keyUriWithVersion",
        "validatedRequestKeyFingerprint",
        "validatedBindingKeyFingerprint",
        "runtimeTrustDomainFingerprints",
        "validatedRuntimeIdentityResourceIds",
        "validatedSourceIdentityResourceIds",
        "normalizedPublisherOwnedIdentityResourceIds",
        "normalizedAttachedIdentityResourceIds",
        "publisherRuntimeIdentityOverlap = intersection(",
        "requestSubmitterRuntimeIdentityOverlap = intersection(",
        "requestSubmitterAttachedIdentityOverlap = intersection(",
        "binding trust reader must match the embedded runtime trust identity",
        "separate from publisher and runtime identities",
        "public key fingerprints must be distinct",
        "must match runtime guidance trust",
        "authorityStorageAccountResourceId",
        "activationStorageAccountResourceId",
        "runtimeAuthorityAssets.blobEndpoint",
        "runtimeAuthorityAssets.containerName",
        "runtimeActivation.tableEndpoint",
        "runtimeActivation.tableName",
        "runtimeActivation.partitionKey",
        "modules/blob-create-rbac.bicep",
        "modules/table-cas-rbac.bicep",
        "../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep",
        "ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON",
        "auth: []",
        "athena-context",
        "wc027-guidance-authority-publisher",
        "output publisherImage string = validatedPublisherImage",
    ):
        assert expected in source

    assert "listKeys(" not in source
    assert "allowSharedKeyAccess: true" not in source
    assert "publicNetworkAccess: 'Enabled'" not in source
    assert "delete/action" not in source
    for drift_prone_parameter in (
        "param replayStorageAccountName",
        "param authorityContainerName",
        "param activationTableName",
        "param activationPartitionKey",
    ):
        assert drift_prone_parameter not in source


@pytest.mark.parametrize(
    ("variant", "expected_valid"),
    (
        ("canonical", True),
        ("cross-subscription", True),
        ("cross-resource-group", True),
        ("missing-leading-slash", False),
        ("provider-case-alias", False),
        ("type-case-alias", False),
        ("empty-name", False),
        ("child-resource", False),
        ("duplicate-separator", False),
        ("query", False),
        ("fragment", False),
        ("encoded-separator", False),
    ),
)
def test_publisher_registry_id_and_image_pull_scope_are_evaluated_canonically(
    variant: str,
    expected_valid: bool,
) -> None:
    source = PUBLISHER.read_text(encoding="utf-8")
    subscription_id = "11111111-1111-1111-1111-111111111111"
    resource_group_name = "rg-shared-acr"
    canonical = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/"
        "providers/Microsoft.ContainerRegistry/registries/athenashared"
    )
    variants = {
        "canonical": canonical,
        "cross-subscription": canonical.replace(
            subscription_id,
            "22222222-2222-2222-2222-222222222222",
        ),
        "cross-resource-group": canonical.replace(
            resource_group_name,
            "rg-central-acr",
        ),
        "missing-leading-slash": canonical.removeprefix("/"),
        "provider-case-alias": canonical.replace(
            "Microsoft.ContainerRegistry",
            "microsoft.containerregistry",
        ),
        "type-case-alias": canonical.replace("/registries/", "/Registries/"),
        "empty-name": canonical.removesuffix("athenashared"),
        "child-resource": canonical + "/replications/eastus",
        "duplicate-separator": canonical.replace("/providers/", "//providers/"),
        "query": canonical + "?api-version=2025-04-01",
        "fragment": canonical + "#registry",
        "encoded-separator": canonical.replace("/registries/", "/registries%2F"),
    }

    segments, valid = _evaluate_registry_resource_id(variants[variant])

    assert valid is expected_valid
    if expected_valid:
        assert segments[2] in {
            subscription_id,
            "22222222-2222-2222-2222-222222222222",
        }
        assert segments[4] in {resource_group_name, "rg-central-acr"}
        assert segments[8] == "athenashared"

    for expected in (
        "registryResourceIdRawSegments = split(registryResourceId, '/')",
        "length(registryResourceIdRawSegments) == 9",
        "empty(registryResourceIdSegments[0])",
        "registryResourceIdSegments[1] == 'subscriptions'",
        "registryResourceIdSegments[3] == 'resourceGroups'",
        "registryResourceIdSegments[5] == 'providers'",
        "registryResourceIdSegments[6] == 'Microsoft.ContainerRegistry'",
        "registryResourceIdSegments[7] == 'registries'",
        "!contains(registryResourceId, '//')",
        "!contains(registryResourceId, '?')",
        "!contains(registryResourceId, '#')",
        "!contains(registryResourceId, '%')",
        "registryResourceId must identify one canonical "
        "Microsoft.ContainerRegistry/registries resource",
    ):
        assert expected in source

    registry_block = source.split(
        "resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing =",
        maxsplit=1,
    )[1].split("var expectedRegistryServer", maxsplit=1)[0]
    image_pull_block = source.split(
        "module publisherImagePull "
        "'../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' =",
        maxsplit=1,
    )[1].split("var requestKeyVerifierRoleId", maxsplit=1)[0]
    for block in (registry_block, image_pull_block):
        assert "scope: resourceGroup(" in block
        assert "validatedRegistryScope.subscriptionId" in block
        assert "validatedRegistryScope.resourceGroupName" in block
        assert "resourceGroup().name" not in block


def test_publisher_data_plane_roles_are_exact_and_non_destructive() -> None:
    blob = BLOB_CREATOR.read_text(encoding="utf-8")
    table = TABLE_CAS.read_text(encoding="utf-8")
    signer = KEY_SIGNER.read_text(encoding="utf-8")

    assert (
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
        in blob
    )
    for forbidden in (
        "blobs/read",
        "blobs/write",
        "blobs/delete",
        "blobs/move",
        "blobs/tags/write",
        "immutableStorage/runAsSuperUser",
    ):
        assert forbidden not in blob
    assert "scope: container" in blob

    for allowed in (
        "tables/entities/read",
        "tables/entities/add/action",
        "tables/entities/update/action",
    ):
        assert allowed in table
    for forbidden in (
        "tables/entities/delete",
        "tableServices/tables/delete",
        "tableServices/tables/write",
    ):
        assert forbidden not in table
    assert "scope: table" in table

    assert "Microsoft.KeyVault/vaults/keys/sign/action" in signer
    for forbidden in (
        "keys/read",
        "keys/verify/action",
        "keys/encrypt/action",
        "keys/decrypt/action",
        "keys/wrap/action",
        "keys/unwrap/action",
        "keys/update",
        "keys/backup/action",
    ):
        assert forbidden not in signer
    assert "scope: key" in signer
    assert "12338af0-0e69-4776-bea7-57ae8d297424" not in signer


def test_runtime_requires_current_activation_and_logical_binding_key() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "param guidanceActivationReaderIdentityResourceId string" in source
    assert "param guidanceBindingLogicalKeyId string" in source
    assert "tableName: guidanceActivation.name" in source
    assert "keyId: guidanceBindingLogicalKeyId" in source
    assert "storageTableDataReaderRoleDefinitionId" in source
    assert "runtimeTrustDomainFingerprints" in source
    assert "validatedTrustDomainMetadata" in source
    assert "trust-domain public key fingerprints must be distinct" in source


def test_readiness_remains_false_until_deployment_is_proven() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    assert "param wc027FeedV2ProducerReady bool = false" in source
    assert "param wc027PublisherReady bool = false" in source
    assert (
        "WC-027 Notification v2 requires an explicitly ready "
        "PublishedGuidanceAuthorityBinding.v2 publisher"
    ) in source
    assert "wc027ParsedConfiguration.guidanceActivation.identityResourceId" in source
