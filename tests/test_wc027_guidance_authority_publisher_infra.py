from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
REQUEST_PRODUCER = ROOT / "infra" / "wc027-guidance-publication-request-producer" / "main.bicep"
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
ACR_PULL = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "acr-pull-rbac.bicep"
)
DIGEST_PULL_READINESS = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "Test-AcrDigestPullReadiness.ps1"
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


def _repository_condition(repository_name: str) -> str:
    return (
        "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/content/read'}) AND "
        "!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/metadata/read'})) OR "
        "(@Request[Microsoft.ContainerRegistry/registries/repositories:name] "
        f"StringEqualsIgnoreCase '{repository_name}'))"
    )


def _publisher_image_pull_evidence() -> tuple[dict[str, object], dict[str, object]]:
    repository_name = "athena/wc027-guidance-authority-publisher"
    condition = _repository_condition(repository_name)
    binding = {
        "registryResourceId": (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/rg-shared-acr/providers/"
            "Microsoft.ContainerRegistry/registries/athenashared"
        ),
        "registryServer": "athenashared.azurecr.io",
        "image": (
            "athenashared.azurecr.io/athena/"
            "wc027-guidance-authority-publisher@sha256:" + "a" * 64
        ),
        "repositoryName": repository_name,
        "roleAssignmentMode": "AbacRepositoryPermissions",
        "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
        "conditionVersion": "2.0",
        "condition": condition,
        "identityClientId": "22222222-2222-2222-2222-222222222222",
    }
    evidence = {
        "schemaVersion": "athena.wc027AcrDigestPullReadiness.v1",
        "registryResourceId": binding["registryResourceId"],
        "registryServer": binding["registryServer"],
        "image": binding["image"],
        "repositoryName": binding["repositoryName"],
        "managedIdentityClientId": binding["identityClientId"],
        "roleAssignmentMode": binding["roleAssignmentMode"],
        "roleDefinitionId": binding["roleDefinitionId"],
        "conditionVersion": binding["conditionVersion"],
        "condition": binding["condition"],
        "attempts": 3,
        "maxAttempts": 10,
        "verifiedAt": "2026-09-16T02:00:00.000Z",
        "success": True,
    }
    return binding, evidence


def _evaluate_publisher_image_pull_evidence(
    source: str,
    *,
    binding: dict[str, object],
    evidence: dict[str, object],
) -> bool:
    required_predicates = (
        "wc027ParsedPublisherImagePullEvidence.schemaVersion == "
        "'athena.wc027AcrDigestPullReadiness.v1'",
        "wc027ParsedPublisherImagePullEvidence.success == true",
        "wc027ParsedPublisherImagePullEvidence.registryResourceId == "
        "wc027ParsedPublisherConfiguration.imagePull.registryResourceId",
        "wc027ParsedPublisherImagePullEvidence.image == wc027PublisherImage",
        "wc027ParsedPublisherConfiguration.imagePull.image == wc027PublisherImage",
        "wc027ParsedPublisherImagePullEvidence.repositoryName == "
        "wc027ParsedPublisherConfiguration.imagePull.repositoryName",
        "wc027ParsedPublisherImagePullEvidence.roleAssignmentMode == "
        "wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode",
        "wc027ParsedPublisherImagePullEvidence.roleDefinitionId == "
        "wc027ParsedPublisherConfiguration.imagePull.roleDefinitionId",
        "wc027ParsedPublisherImagePullEvidence.conditionVersion == "
        "wc027ParsedPublisherConfiguration.imagePull.conditionVersion",
        "wc027ParsedPublisherImagePullEvidence.condition == "
        "wc027ParsedPublisherConfiguration.imagePull.condition",
        "wc027PublisherImagePullConditionValid",
        "wc027ParsedPublisherImagePullEvidence.attempts >= 1",
        "wc027ParsedPublisherImagePullEvidence.maxAttempts <= 20",
    )
    if any(predicate not in source for predicate in required_predicates):
        return False
    return (
        evidence.get("schemaVersion")
        == "athena.wc027AcrDigestPullReadiness.v1"
        and evidence.get("success") is True
        and evidence.get("registryResourceId") == binding["registryResourceId"]
        and evidence.get("registryServer") == binding["registryServer"]
        and evidence.get("image") == binding["image"]
        and evidence.get("repositoryName") == binding["repositoryName"]
        and str(evidence.get("managedIdentityClientId", "")).casefold()
        == str(binding["identityClientId"]).casefold()
        and evidence.get("roleAssignmentMode") == binding["roleAssignmentMode"]
        and evidence.get("roleDefinitionId") == binding["roleDefinitionId"]
        and evidence.get("conditionVersion") == binding["conditionVersion"]
        and evidence.get("condition") == binding["condition"]
        and isinstance(evidence.get("attempts"), int)
        and isinstance(evidence.get("maxAttempts"), int)
        and 1
        <= int(evidence["attempts"])
        <= int(evidence["maxAttempts"])
        <= 20
        and bool(evidence.get("verifiedAt"))
    )


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
        "param registryRoleAssignmentMode string",
        "param brokerIdentityPrincipalId string",
        "brokerIdentity.properties.principalId == brokerIdentityPrincipalId",
        "imagePull:",
        "repositoryName: publisherImagePull.outputs.repositoryName",
        "conditionVersion: publisherImagePull.outputs.?conditionVersion",
        "condition: publisherImagePull.outputs.?condition",
        "output registryPullConditionVersion string?",
        "output registryPullCondition string?",
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
        "resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing =",
        maxsplit=1,
    )[1].split("var expectedRegistryServer", maxsplit=1)[0]
    image_pull_block = source.split(
        "module publisherImagePull "
        "'../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' =",
        maxsplit=1,
    )[1].split("var requestKeyVerifierRoleId", maxsplit=1)[0]
    assert "scope: resourceGroup(" in registry_block
    assert "validatedRegistryScope.subscriptionId" in registry_block
    assert "validatedRegistryScope.resourceGroupName" in registry_block
    assert "scope: resourceGroup(" in image_pull_block
    assert "registrySubscriptionId" in image_pull_block
    assert "registryResourceGroupName" in image_pull_block
    assert "resourceGroup().name" not in registry_block
    assert "resourceGroup().name" not in image_pull_block


def test_acr_pull_module_matches_pr102_canonical_contract() -> None:
    module = ACR_PULL.read_text(encoding="utf-8")
    repository_condition = (
        "((!(ActionMatches{\\'Microsoft.ContainerRegistry/registries/repositories/"
        "content/read\\'}) AND !(ActionMatches{\\'Microsoft.ContainerRegistry/"
        "registries/repositories/metadata/read\\'})) OR (@Request[Microsoft."
        "ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase "
        "\\'${validatedRepositoryName}\\'))"
    )

    for expected in (
        "param registryResourceId string",
        "param identityPrincipalId string",
        "param image string",
        "param registryRoleAssignmentMode string",
        "reference(registry.id, '2025-04-01', 'Full')",
        "registryRuntime.properties.roleAssignmentMode == registryRoleAssignmentMode",
        "guardedPullRoleDefinitionResourceId",
        "roleDefinitionId: guardedPullRoleDefinitionResourceId",
        "b93aa761-3e63-49ed-ac28-beffa264f7ac",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)",
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId, "
        "validatedRepositoryName)",
        "principalType: 'ServicePrincipal'",
        "conditionVersion: pullConditionVersion",
        "condition: pullCondition",
        f"var repositoryCondition = '{repository_condition}'",
        "var pullConditionVersion = validatedRoleAssignmentMode == "
        "'AbacRepositoryPermissions' ? '2.0' : null",
        "var pullCondition = validatedRoleAssignmentMode == "
        "'AbacRepositoryPermissions'",
        "output registryResourceId string = runtimeRegistryResourceId",
        "output roleAssignmentMode string = validatedRoleAssignmentMode",
        "output repositoryName string = validatedRepositoryName",
        "output conditionVersion string? = pullConditionVersion",
        "output condition string? = pullCondition",
    ):
        assert expected in module
    assert "param identityResourceId string" not in module
    assert "StringStartsWithIgnoreCase" not in module
    assert not (
        ACR_PULL.parent / "acr-pull-role-assignment.bicep"
    ).exists()


@pytest.mark.parametrize(
    ("requested_repository", "allowed"),
    (
        ("athena/wc027-guidance-authority-publisher", True),
        ("ATHENA/WC027-GUIDANCE-AUTHORITY-PUBLISHER", True),
        ("athena/wc027-guidance-authority-publisher-copy", False),
        ("athena/wc027-guidance-publication-request-producer", False),
        ("other/wc027-guidance-authority-publisher", False),
    ),
)
def test_canonical_abac_condition_denies_cross_repository_access(
    requested_repository: str,
    allowed: bool,
) -> None:
    expected_repository = "athena/wc027-guidance-authority-publisher"

    assert (
        requested_repository.casefold() == expected_repository.casefold()
    ) is allowed
    assert _repository_condition(expected_repository).endswith(
        "StringEqualsIgnoreCase "
        f"'{expected_repository}'))"
    )


def test_each_wc027_job_derives_and_exports_exact_acr_repository_evidence() -> None:
    sources = (
        (
            RUNTIME.read_text(encoding="utf-8"),
            "validatedProducerImage",
            "producerImageRepositoryName",
        ),
        (
            PUBLISHER.read_text(encoding="utf-8"),
            "validatedPublisherImage",
            "publisherImageRepositoryName",
        ),
        (
            REQUEST_PRODUCER.read_text(encoding="utf-8"),
            "validatedProducerImage",
            "producerImageRepositoryName",
        ),
    )

    for source, image_name, repository_name in sources:
        assert f"image: {image_name}" in source
        assert f"var {repository_name} = replace(" in source
        assert "registryRoleAssignmentMode == 'AbacRepositoryPermissions'" in source
        assert "registryPullRoleDefinitionId," in source
        assert f"{repository_name}" in source
        assert ".properties.principalId ==" in source
        for expected in (
            "outputs.registryResourceId",
            "outputs.roleAssignmentMode",
            "outputs.repositoryName",
            "outputs.roleDefinitionResourceId",
            "outputs.roleAssignmentResourceId",
            "outputs.?conditionVersion",
            "outputs.?condition",
        ):
            assert expected in source


def test_module_configuration_and_evidence_share_one_canonical_condition() -> None:
    module = ACR_PULL.read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")
    root = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    script = DIGEST_PULL_READINESS.read_text(encoding="utf-8")

    assert (
        "StringEqualsIgnoreCase \\'${validatedRepositoryName}\\'))'"
        in module
    )
    assert "repositoryName: publisherImagePull.outputs.repositoryName" in publisher
    assert "conditionVersion: publisherImagePull.outputs.?conditionVersion" in publisher
    assert "condition: publisherImagePull.outputs.?condition" in publisher
    assert (
        "StringEqualsIgnoreCase "
        "\\'${wc027PublisherImageRepositoryName}\\'))'"
        in root
    )
    assert (
        "StringEqualsIgnoreCase '$repositoryName'))\""
        in script
    )
    assert "conditionVersion = $conditionVersion" in script
    assert "condition = $condition" in script


def test_publisher_digest_pull_readiness_is_bounded_and_activation_gated() -> None:
    script = DIGEST_PULL_READINESS.read_text(encoding="utf-8")
    root = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    for expected in (
        "[ValidateRange(1, 20)]",
        "[int] $MaxAttempts = 10",
        "[ValidateRange(1, 60)]",
        "[int] $DelaySeconds = 30",
        "az login --identity --client-id",
        "az acr login --name $registryName --expose-token",
        "docker login",
        "docker pull $Image",
        "docker image inspect $Image --format '{{json .RepoDigests}}'",
        "if ($Image -notin $repoDigests)",
        "Start-Sleep -Seconds $DelaySeconds",
        "athena.wc027AcrDigestPullReadiness.v1",
        "repositoryName = $repositoryName",
        "roleAssignmentMode = $RegistryRoleAssignmentMode",
        "roleDefinitionId = $roleDefinitionId",
        "conditionVersion = $conditionVersion",
        "condition = $condition",
        "success = $true",
        "docker logout $registryServer",
    ):
        assert expected in script
    assert "Write-Output $token" not in script
    assert "Write-Host $token" not in script

    for expected in (
        "param wc027PublisherImagePullEvidenceJson string = ''",
        "wc027PublisherImagePullEvidenceValid",
        "athena.wc027AcrDigestPullReadiness.v1",
        "managedIdentityClientId",
        "repositoryName",
        "roleAssignmentMode",
        "roleDefinitionId",
        "conditionVersion",
        "condition",
        "wc027PublisherExpectedRepositoryCondition",
        "wc027PublisherImagePullConditionValid",
        "successful bounded managed-identity digest-pull evidence",
    ):
        assert expected in root


def test_publisher_digest_pull_evidence_evaluates_ready() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    binding, evidence = _publisher_image_pull_evidence()

    assert _evaluate_publisher_image_pull_evidence(
        source,
        binding=binding,
        evidence=evidence,
    )


def test_legacy_digest_pull_evidence_uses_null_repository_conditions() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    binding, evidence = _publisher_image_pull_evidence()
    binding["roleAssignmentMode"] = "LegacyRegistryPermissions"
    binding["roleDefinitionId"] = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
    binding["conditionVersion"] = None
    binding["condition"] = None
    evidence["roleAssignmentMode"] = binding["roleAssignmentMode"]
    evidence["roleDefinitionId"] = binding["roleDefinitionId"]
    evidence["conditionVersion"] = None
    evidence["condition"] = None

    assert _evaluate_publisher_image_pull_evidence(
        source,
        binding=binding,
        evidence=evidence,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "success",
        "registry",
        "server",
        "image",
        "identity",
        "repository",
        "mode",
        "role",
        "condition-version",
        "condition",
        "attempts-zero",
        "attempts-over-max",
        "max-over-bound",
        "verified-at",
    ),
)
def test_publisher_digest_pull_evidence_rejects_drift(mutation: str) -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    binding, evidence = _publisher_image_pull_evidence()
    selected = deepcopy(evidence)
    mutations = {
        "schema": ("schemaVersion", "synthetic.invalid"),
        "success": ("success", False),
        "registry": ("registryResourceId", "/synthetic/registry"),
        "server": ("registryServer", "different.azurecr.io"),
        "image": ("image", str(binding["image"]).replace("a" * 64, "b" * 64)),
        "identity": (
            "managedIdentityClientId",
            "33333333-3333-3333-3333-333333333333",
        ),
        "repository": ("repositoryName", "athena/other-repository"),
        "mode": ("roleAssignmentMode", "LegacyRegistryPermissions"),
        "role": (
            "roleDefinitionId",
            "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        ),
        "condition-version": ("conditionVersion", None),
        "condition": (
            "condition",
            _repository_condition("athena/other-repository"),
        ),
        "attempts-zero": ("attempts", 0),
        "attempts-over-max": ("attempts", 11),
        "max-over-bound": ("maxAttempts", 21),
        "verified-at": ("verifiedAt", ""),
    }
    key, value = mutations[mutation]
    selected[key] = value

    assert not _evaluate_publisher_image_pull_evidence(
        source,
        binding=binding,
        evidence=selected,
    )


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
    assert "guidanceActivationMaterializerRbac" in source
    assert "guidanceActivationMaterializerRoleId" in source
    assert "guidanceActivationMaterializerAssignmentId" in source
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
