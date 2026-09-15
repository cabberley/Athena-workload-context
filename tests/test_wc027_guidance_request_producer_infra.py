from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "infra" / "wc027-guidance-publication-request-producer" / "main.bicep"
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
    assert "guidanceActivation" not in source
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
