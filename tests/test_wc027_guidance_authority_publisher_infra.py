from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
ROOT_DEPLOYMENT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
BLOB_CREATOR = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "modules" / "blob-create-rbac.bicep"
)
TABLE_CAS = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "modules" / "table-cas-rbac.bicep"
)
KEY_SIGNER = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "modules" / "key-signer-rbac.bicep"
)
ACR_PULL = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "acr-pull-rbac.bicep"
)


def test_publisher_is_private_idempotent_and_uses_separated_authorities() -> None:
    source = PUBLISHER.read_text(encoding="utf-8")

    for expected in (
        "requiresSession: true",
        "requiresDuplicateDetection: true",
        "defaultMessageTimeToLive: 'PT5M'",
        "autoDeleteOnIdle: 'P10675199DT2H48M5.4775807S'",
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
        "keyId: requestLogicalKeyId",
        "keyId: validatedBindingLogicalKeyId",
        "keyVaultKeyId: requestKey.properties.keyUriWithVersion",
        "keyVaultKeyId: bindingKey.properties.keyUriWithVersion",
        "validatedRequestKeyFingerprint",
        "validatedBindingKeyFingerprint",
        "validatedBindingLogicalKeyId",
        "runtimeTrustDomainFingerprints",
        "public key fingerprints must be distinct",
        "must match runtime guidance trust",
        "binding logical key ID must match runtime guidance trust",
        "authorityStorageAccountResourceId",
        "activationStorageAccountResourceId",
        "registrySubscriptionId = split(registryResourceId, '/')[2]",
        "registryResourceGroupName = split(registryResourceId, '/')[4]",
        "scope: resourceGroup(registrySubscriptionId, registryResourceGroupName)",
        "runtimeAuthorityAssets.blobEndpoint",
        "runtimeAuthorityAssets.containerName",
        "runtimeActivation.tableEndpoint",
        "runtimeActivation.tableName",
        "runtimeActivation.partitionKey",
        "modules/blob-create-rbac.bicep",
        "modules/table-cas-rbac.bicep",
        "ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON",
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


def test_publisher_data_plane_roles_are_exact_and_non_destructive() -> None:
    blob = BLOB_CREATOR.read_text(encoding="utf-8")
    table = TABLE_CAS.read_text(encoding="utf-8")
    signer = KEY_SIGNER.read_text(encoding="utf-8")

    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action" in blob
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


def test_publisher_acr_pull_uses_exact_registry_scope_and_principal_seed() -> None:
    source = PUBLISHER.read_text(encoding="utf-8")
    module = ACR_PULL.read_text(encoding="utf-8")

    for expected in (
        "param brokerIdentityPrincipalId string",
        "brokerIdentity.properties.principalId == brokerIdentityPrincipalId",
        "scope: resourceGroup(registrySubscriptionId, registryResourceGroupName)",
        "registryResourceId: registryResourceId",
        "identityPrincipalId: validatedBrokerIdentityPrincipalId",
        "registryRoleAssignmentMode: registryRoleAssignmentMode",
        "guid(registryScopedResourceId, brokerIdentityPrincipalId, registryPullRoleDefinitionId)",
        "publisherImagePull.outputs.registryResourceId",
        "publisherImagePull.outputs.roleAssignmentMode",
        "publisherImagePull.outputs.roleDefinitionResourceId",
        "publisherImagePull.outputs.roleAssignmentResourceId",
    ):
        assert expected in source
    assert "guid(registry.id, brokerIdentity.id" not in source
    assert (
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)"
        in module
    )


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
