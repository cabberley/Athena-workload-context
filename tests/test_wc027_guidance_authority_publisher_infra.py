from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
ROOT_DEPLOYMENT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"


def test_publisher_is_private_idempotent_and_uses_separated_authorities() -> None:
    source = PUBLISHER.read_text(encoding="utf-8")

    for expected in (
        "requiresSession: true",
        "requiresDuplicateDetection: true",
        "defaultMessageTimeToLive: 'PT5M'",
        "maxMessageSizeInKilobytes: 12288",
        "maxExecutions: 1",
        "wc027-guidance-authority-requests",
        "wc027-enrichment-feed-requests",
        "wc027-guidance-authority",
        "Wc027GuidanceActivation",
        "authorityReaderIdentityResourceId",
        "authorityWriterIdentityResourceId",
        "activationWriterIdentityResourceId",
        "bindingSignerIdentityResourceId",
        "requestTrustReaderIdentityResourceId",
        "bindingTrustReaderIdentityResourceId",
        "keyId: requestLogicalKeyId",
        "keyId: bindingLogicalKeyId",
        "keyVaultKeyId: requestKey.properties.keyUriWithVersion",
        "keyVaultKeyId: bindingKey.properties.keyUriWithVersion",
        "ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON",
        "athena-context",
        "wc027-guidance-authority-publisher",
        "output publisherImage string = validatedPublisherImage",
        "condition: '(!(ActionMatches",
        "SubOperationMatches{\\'Blob.List\\'}",
    ):
        assert expected in source

    assert "listKeys(" not in source
    assert "allowSharedKeyAccess: true" not in source
    assert "publicNetworkAccess: 'Enabled'" not in source
    assert "delete/action" not in source


def test_runtime_requires_current_activation_and_logical_binding_key() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "param guidanceActivationReaderIdentityResourceId string" in source
    assert "param guidanceBindingLogicalKeyId string" in source
    assert "tableName: guidanceActivation.name" in source
    assert "keyId: guidanceBindingLogicalKeyId" in source
    assert "storageTableDataReaderRoleDefinitionId" in source


def test_readiness_remains_false_until_deployment_is_proven() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    assert "param wc027FeedV2ProducerReady bool = false" in source
    assert "param wc027PublisherReady bool = false" in source
    assert (
        "WC-027 Notification v2 requires an explicitly ready "
        "PublishedGuidanceAuthorityBinding.v2 publisher"
    ) in source
