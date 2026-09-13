from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
ROOT_BICEP = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
DOCKERFILE = ROOT / "apps" / "enrichment-feed-producer" / "Dockerfile"
CLI = ROOT / "src" / "athena_context" / "cli.py"


def test_wc027_runtime_is_private_keyless_and_session_ordered() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "requiresSession: true" in source
    assert "requiresDuplicateDetection: true" in source
    assert "duplicateDetectionHistoryTimeWindow: 'P7D'" in source
    assert "maxMessageSizeInKilobytes: 12288" in source
    assert "type: 'azure-servicebus'" in source
    assert "isSessionsEnabled: 'true'" in source
    assert "connectionString" not in source
    assert "listKeys(" not in source
    assert "runtimeConfigurationJson" in source
    assert "triggerSubmitterPrincipalIds" in source
    assert "scope: triggerQueue" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert "'wc027-enrichment-feed-producer'" in source
    assert "managedEnvironmentResourceId" in source


def test_wc027_runtime_uses_separate_identity_and_key_scopes() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    for principal in (
        "incidentReaderPrincipalId",
        "incidentWriterPrincipalId",
        "registryWriterPrincipalId",
        "trustReaderPrincipalId",
        "reportSignerPrincipalId",
        "guidanceSignerPrincipalId",
        "enrichmentSignerPrincipalId",
        "feedSignerPrincipalId",
        "notificationSignerPrincipalId",
    ):
        assert principal in source
    assert "runtime identities and client IDs must be distinct" in source
    assert "storageBlobDataReaderRoleDefinitionId" in source
    assert "storageBlobDataContributorRoleDefinitionId" in source
    assert "storageTableDataContributorRoleDefinitionId" in source
    assert source.count("keyVaultCryptoUserRoleDefinitionId") >= 10
    assert "scope: reportKey" in source
    assert "scope: guidanceKey" in source
    assert "scope: enrichmentKey" in source
    assert "scope: feedKey" in source
    assert "scope: notificationKey" in source
    assert "module producerImagePull" in source


def test_wc027_notification_gate_requires_deployed_job_resource_id() -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")

    assert "param wc027FeedV2ProducerReady bool = false" in source
    assert "param wc027EnrichmentFeedProducerJobResourceId string = ''" in source
    assert (
        "param wc027EnrichmentFeedProducerConfigurationDigest string = ''"
        in source
    )
    assert (
        "param wc027EnrichmentFeedProducerConfigurationJson string = ''"
        in source
    )
    assert "validatedWc027FeedV2ProducerReady" in source
    assert "toLower(wc027ProducerJobResourceIdSegments[6]) == 'microsoft.app'" in source
    assert "toLower(wc027ProducerJobResourceIdSegments[7]) == 'jobs'" in source
    assert "exact deployed producer configuration digest" in source
    assert "wc027ProducerJob!.tags.runtimeConfigurationDigest" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert (
        "notificationV2ProducerReady: validatedWc027FeedV2ProducerReady"
        in source
    )


def test_wc027_producer_image_and_cli_are_executable() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    cli = CLI.read_text(encoding="utf-8")

    assert "COPY requirements-wc016.lock ./" in dockerfile
    assert "--require-hashes" in dockerfile
    assert (
        'ENTRYPOINT ["athena-context", "wc027-enrichment-feed-producer"]'
        in dockerfile
    )
    assert '"wc027-enrichment-feed-submit"' in cli
    assert '"wc027-enrichment-feed-producer"' in cli
