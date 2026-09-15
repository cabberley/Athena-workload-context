from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

import athena_context.enrichment.production as production
from athena_context.contracts import (
    IncidentNotificationEnvelopeV2,
    PublishedGuidanceAuthorityActivation,
    PublishedGuidanceAuthorityActivationAttestation,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.enrichment import (
    Wc027EnrichmentFeedRuntime,
    Wc027EnrichmentSourceNotReadyError,
    parse_wc027_enrichment_trigger,
)
from athena_context.enrichment.feed_pipeline import (
    IncidentEnrichmentFeedPublicationService,
)
from athena_context.enrichment.production import (
    Wc027EnrichmentFeedProductionConfiguration,
    _BlobSource,
    _KeyAuthority,
    _MonitoringCollectorKey,
    _SplitIncidentPresentationReader,
    _TableSource,
    _WritableBlobSource,
    load_wc027_enrichment_feed_configuration,
)
from athena_context.guidance import GuidanceAuthorityActivationSnapshot
from athena_context.guidance.production import (
    Wc027GuidanceAuthorityPublisherConfiguration,
)
from test_wc024_monitoring_contract import _collector_contract
from test_wc026_correlation_contract import NOW
from test_wc027_enrichment_feed_pipeline import (
    PUBLISHED_AT,
    _CurrentReader,
    _IndexPublication,
    _Registry,
    _Writer,
)
from test_wc027_feed_registry import _KEY_ID
from test_wc027_guidance_authority_contract import _binding, _no_runbook_selection
from test_wc027_incident_enrichment_publication import (
    _SIGNATURE,
    _fixture,
    _publication_service,
    _Store,
)


class _Signer:
    def sign_preimage(self, _canonical_preimage: bytes) -> str:
        return _SIGNATURE


def _verify(_preimage: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


class _Correlation:
    def __init__(self, service, operations: list[str]) -> None:
        self._service = service
        self._operations = operations

    def correlate(self, request):
        self._operations.append("correlate")
        return self._service.correlate(request)


class _SignatureVerifier:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[tuple[bytes, str]] = []

    def __call__(self, preimage: bytes, signature: str) -> bool:
        self.calls.append((preimage, signature))
        return self.valid


class _Authority:
    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.calls: list[str] = []

    def read_current_incident_state(self, *, incident_id: str):
        self.calls.append("current")
        return self._delegate.read_current_incident_state(incident_id=incident_id)

    def read_active_incident_index(self):
        self.calls.append("active")
        return self._delegate.read_active_incident_index()


class _Activation:
    def __init__(self, binding, occurrence) -> None:
        payload = {
            "schemaVersion": (
                "athena.wc027PublishedGuidanceAuthorityActivation.v1"
            ),
            "incidentId": (
                binding.incident_bound_request.incident_subject.incident_id
            ),
            "incidentStateDigest": (
                binding.incident_bound_request.incident_subject.incident_state_digest
            ),
            "occurrenceDigest": occurrence.occurrence_digest,
            "publicationRequestId": (
                "guidance-publication-request-" + "8" * 32
            ),
            "publicationRequestDigest": "sha256:" + "8" * 64,
            "bindingId": binding.binding_id,
            "bindingDigest": binding.binding_digest,
            "bindingReference": VersionPinnedBlobReference(
                name=f"guidance-bindings/{binding.binding_id}/binding.json",
                version="synthetic-binding-version",
                contentDigest=sha256_hex(binding.canonical_bytes()),
            ),
            "activatedAt": binding.evaluated_at,
            "expiresAt": (
                binding.incident_bound_request.correlation_request.expires_at
            ),
        }
        digest_payload = {
            **payload,
            "bindingReference": payload["bindingReference"].model_dump(  # type: ignore[union-attr]
                mode="json",
                by_alias=True,
            ),
        }
        attestation = PublishedGuidanceAuthorityActivationAttestation(
            schemaVersion=(
                "athena.wc027PublishedGuidanceAuthorityActivationAttestation.v1"
            ),
            signatureAlgorithm="RS256",
            keyId=binding.binding_attestation.key_id,
            signedPreimageDigest=compute_artifact_digest(digest_payload),
            detachedSignature=_SIGNATURE,
        )
        complete = {**payload, "activationAttestation": attestation}
        digest = compute_artifact_digest(
            {
                **digest_payload,
                "activationAttestation": attestation.model_dump(
                    mode="json",
                    by_alias=True,
                ),
            }
        )
        self.snapshot = GuidanceAuthorityActivationSnapshot(
            activation=PublishedGuidanceAuthorityActivation(
                **complete,
                activationId=(
                    f"guidance-activation-{digest.removeprefix('sha256:')[:32]}"
                ),
                activationDigest=digest,
            ),
            etag='"synthetic"',
        )

    def read_current(self, *, incident_id: str):
        assert incident_id == self.snapshot.activation.incident_id
        return self.snapshot


class _Enrichment:
    def __init__(self, service, operations: list[str]) -> None:
        self._service = service
        self._operations = operations

    def publish(self, **kwargs):
        self._operations.append("enrichment.start")
        result = self._service.publish(**kwargs)
        self._operations.append("enrichment.complete")
        return result


class _Feed:
    def __init__(self, service, operations: list[str]) -> None:
        self._service = service
        self._operations = operations

    def publish(self, enrichment_publication, *, published_at):
        self._operations.append("feed.start")
        result = self._service.publish(
            enrichment_publication,
            published_at=published_at,
        )
        self._operations.append("feed.complete")
        return result


class _Notification:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.calls = 0

    def publish(self, *, incident_id: str, verified_at):
        del verified_at
        self.operations.append("notification")
        self.calls += 1
        notification = SimpleNamespace(incident_id=incident_id)
        return cast(
            IncidentNotificationEnvelopeV2,
            IncidentNotificationEnvelopeV2.model_construct(
                notification=notification,
                attestation=object(),
            ),
        )


class _MissingAuthority:
    def read_current_incident_state(self, *, incident_id: str):
        del incident_id
        return None

    def read_active_incident_index(self):
        return None


class _ArtifactReaderProbe:
    def __init__(self, label: str) -> None:
        self.label = label
        self.calls: list[tuple[str, str]] = []

    def read_current(self, request):
        self.calls.append(("current", request.blob_name))
        return SimpleNamespace(
            blob_name=request.blob_name,
            payload=b"{}",
            payload_sha256="sha256:" + "1" * 64,
            size_bytes=2,
        )

    def read(self, request):
        self.calls.append(("version", request.blob_name))
        return SimpleNamespace(
            blob_name=request.blob_name,
            payload=b"{}",
            payload_sha256=request.expected_payload_sha256,
            size_bytes=2,
        )


def _bicep_generated_runtime_configuration() -> dict[str, object]:
    identity_client_ids = [
        f"00000000-0000-0000-0000-{index:012d}" for index in range(1, 18)
    ]

    def identity_resource_id(index: int) -> str:
        return (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-wc027/providers/Microsoft.ManagedIdentity/"
            f"userAssignedIdentities/wc027-identity-{index}"
        )

    def source(index: int, container_name: str) -> dict[str, str]:
        return {
            "blobEndpoint": "https://athenawc027.blob.core.windows.net",
            "containerName": container_name,
            "identityClientId": identity_client_ids[index],
            "identityResourceId": identity_resource_id(index),
        }
    def key(
        index: int,
        identity_index: int,
        *,
        logical_key_id: str | None = None,
    ) -> dict[str, str]:
        key_vault_key_id = (
            "https://athena-wc027.vault.azure.net/keys/"
            f"key-{index}/{index:032x}"
        )
        return {
            "keyId": logical_key_id or key_vault_key_id,
            "keyVaultKeyId": key_vault_key_id,
            "keyFingerprint": "sha256:" + f"{index:x}"[-1] * 64,
            "identityClientId": identity_client_ids[identity_index],
            "identityResourceId": identity_resource_id(identity_index),
        }

    attached_identity_resource_ids = [
        identity_resource_id(index) for index in range(17)
    ]
    monitoring_collector_key: dict[str, object] = {
        **key(1, 10),
        "activatedAt": NOW.isoformat().replace("+00:00", "Z"),
        "expiresAt": None,
    }
    return {
        "schemaVersion": "athena.wc027EnrichmentFeedRuntimeConfiguration.v1",
        "serviceBus": {
            "namespace": "athena-wc027.servicebus.windows.net",
            "triggerQueueName": "wc027-enrichment-trigger",
            "notificationQueueName": "wc027-notification-v2",
            "brokerIdentityClientId": identity_client_ids[0],
            "brokerIdentityResourceId": identity_resource_id(0),
        },
        "incidentLifecycleAssets": source(1, "incident-assets"),
        "enrichmentFeedAssets": {
            "blobEndpoint": "https://athenawc027.blob.core.windows.net",
            "containerName": "wc027-enrichment-feed-v2",
            "readerIdentityClientId": identity_client_ids[2],
            "readerIdentityResourceId": identity_resource_id(2),
            "writerIdentityClientId": identity_client_ids[3],
            "writerIdentityResourceId": identity_resource_id(3),
        },
        "feedRegistry": {
            "tableEndpoint": "https://athenawc027.table.core.windows.net",
            "tableName": "Wc027FeedRegistry",
            "partitionKey": "wc027-feed-v2",
            "identityClientId": identity_client_ids[4],
            "identityResourceId": identity_resource_id(4),
        },
        "deploymentBinding": {
            "bindingEvidenceId": "00000000-0000-0000-0000-000000000099",
            "attachedIdentityResourceIds": attached_identity_resource_ids,
            "rbacResourceIds": [
                "/subscriptions/00000000-0000-0000-0000-000000000000/"
                "providers/Microsoft.Authorization/roleDefinitions/"
                "00000000-0000-0000-0000-000000000098"
            ],
        },
        "presentationUrl": "https://athena.synthetic.example/incidents",
        "correlationSources": {
            "monitoring": source(5, "wc024-monitoring"),
            "change": source(6, "change-evidence"),
            "contextAuthority": source(7, "context-authority"),
            "monitoringIntent": source(8, "monitoring-intent"),
        },
        "guidanceAuthoritySource": source(9, "wc027-guidance-authority"),
        "guidanceActivation": {
            "tableEndpoint": "https://athenawc027.table.core.windows.net",
            "tableName": "Wc027GuidanceActivation",
            "partitionKey": "wc027-guidance-authority",
            "identityClientId": identity_client_ids[16],
            "identityResourceId": identity_resource_id(16),
        },
        "monitoringCollectorContract": _collector_contract().model_dump(
            mode="json",
            by_alias=True,
        ),
        "monitoringCollectorKey": monitoring_collector_key,
        "keys": {
            "incident": key(
                4,
                10,
                logical_key_id=(
                    "synthetic-key://athena-argus-demo/"
                    "wc016-incidents-rs256-v1"
                ),
            ),
            "correlationBinding": key(5, 10),
            "guidanceBinding": key(6, 10),
            "change": key(2, 10),
            "monitoringIntent": key(3, 10),
            "report": key(7, 11),
            "guidance": key(8, 12),
            "enrichment": key(9, 13),
            "feed": key(10, 14),
            "notification": key(11, 15),
        },
    }


def _bicep_generated_publisher_configuration() -> dict[str, object]:
    runtime = _bicep_generated_runtime_configuration()

    def client_id(index: int) -> str:
        return f"10000000-0000-0000-0000-{index:012d}"

    def identity_resource_id(index: int) -> str:
        return (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-wc027/providers/Microsoft.ManagedIdentity/"
            f"userAssignedIdentities/wc027-publisher-{index}"
        )

    request_key = {
        "keyId": "synthetic-key://athena/wc027-guidance-request-rs256-v1",
        "keyVaultKeyId": (
            "https://athena-wc027.vault.azure.net/keys/"
            "guidance-request/00000000000000000000000000000012"
        ),
        "keyFingerprint": "sha256:" + "c" * 64,
        "identityClientId": client_id(4),
        "identityResourceId": identity_resource_id(4),
    }
    runtime_binding = runtime["keys"]["guidanceBinding"]  # type: ignore[index]
    binding_signing_key = {
        **runtime_binding,  # type: ignore[arg-type]
        "identityClientId": client_id(5),
        "identityResourceId": identity_resource_id(5),
    }
    expected_identities = {
        identity_resource_id(0),
        identity_resource_id(1),
        identity_resource_id(2),
        identity_resource_id(3),
        identity_resource_id(4),
        identity_resource_id(5),
        identity_resource_id(6),
        runtime["incidentLifecycleAssets"]["identityResourceId"],  # type: ignore[index]
        runtime["correlationSources"]["monitoring"]["identityResourceId"],  # type: ignore[index]
        runtime["correlationSources"]["change"]["identityResourceId"],  # type: ignore[index]
        runtime["correlationSources"]["contextAuthority"]["identityResourceId"],  # type: ignore[index]
        runtime["correlationSources"]["monitoringIntent"]["identityResourceId"],  # type: ignore[index]
        runtime["keys"]["guidanceBinding"]["identityResourceId"],  # type: ignore[index]
        runtime["monitoringCollectorKey"]["identityResourceId"],  # type: ignore[index]
        runtime["keys"]["change"]["identityResourceId"],  # type: ignore[index]
        runtime["keys"]["monitoringIntent"]["identityResourceId"],  # type: ignore[index]
        runtime["keys"]["incident"]["identityResourceId"],  # type: ignore[index]
        runtime["keys"]["correlationBinding"]["identityResourceId"],  # type: ignore[index]
    }
    return {
        "schemaVersion": (
            "athena.wc027GuidanceAuthorityPublisherConfiguration.v1"
        ),
        "serviceBus": {
            "namespace": "athena-wc027.servicebus.windows.net",
            "requestQueueName": "wc027-guidance-authority-requests",
            "triggerQueueName": "wc027-enrichment-trigger",
            "brokerIdentityClientId": client_id(0),
            "brokerIdentityResourceId": identity_resource_id(0),
            "requestSubmitterIdentityClientId": client_id(7),
            "requestSubmitterIdentityResourceId": identity_resource_id(7),
        },
        "requestOutbox": {
            "blobEndpoint": "https://athenawc027.blob.core.windows.net",
            "containerName": "wc027-guidance-request-outbox",
            "identityClientId": client_id(6),
            "identityResourceId": identity_resource_id(6),
        },
        "authorityAssets": {
            "blobEndpoint": "https://athenawc027.blob.core.windows.net",
            "containerName": "wc027-guidance-authority",
            "readerIdentityClientId": client_id(1),
            "readerIdentityResourceId": identity_resource_id(1),
            "writerIdentityClientId": client_id(2),
            "writerIdentityResourceId": identity_resource_id(2),
        },
        "guidanceActivation": {
            "tableEndpoint": "https://athenawc027.table.core.windows.net",
            "tableName": "Wc027GuidanceActivation",
            "partitionKey": "wc027-guidance-authority",
            "identityClientId": client_id(3),
            "identityResourceId": identity_resource_id(3),
        },
        "requestKey": request_key,
        "bindingSigningKey": binding_signing_key,
        "enrichmentRuntimeConfiguration": runtime,
        "deploymentBinding": {
            "bindingEvidenceId": "10000000-0000-0000-0000-000000000099",
            "attachedIdentityResourceIds": sorted(expected_identities),
            "rbacResourceIds": [
                "/subscriptions/00000000-0000-0000-0000-000000000000/"
                "providers/Microsoft.Authorization/roleDefinitions/"
                "10000000-0000-0000-0000-000000000098"
            ],
        },
    }


def test_publisher_configuration_preserves_logical_and_physical_binding_keys() -> None:
    payload = _bicep_generated_publisher_configuration()

    configuration = Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
        json.dumps(payload)
    )

    assert configuration.binding_signing_key.key_id == (
        payload["enrichmentRuntimeConfiguration"]["keys"]["guidanceBinding"][
            "keyId"
        ]
    )
    assert configuration.binding_signing_key.key_vault_key_id == (
        payload["enrichmentRuntimeConfiguration"]["keys"]["guidanceBinding"][
            "keyVaultKeyId"
        ]
    )
    assert (
        configuration.binding_signing_key.identity_resource_id
        != configuration.enrichment_runtime.guidance_binding_key.identity_resource_id
    )
    assert (
        configuration.binding_signing_key.key_fingerprint
        == configuration.enrichment_runtime.guidance_binding_key.key_fingerprint
    )


def test_publisher_configuration_rejects_reused_request_authority() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["requestKey"]["keyId"] = payload["enrichmentRuntimeConfiguration"][
        "keys"
    ]["incident"]["keyId"]

    with pytest.raises(ValueError, match="distinct trust domain"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_rejects_reused_request_public_key_material() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["requestKey"]["keyFingerprint"] = payload[  # type: ignore[index]
        "enrichmentRuntimeConfiguration"
    ]["keys"]["incident"]["keyFingerprint"]  # type: ignore[index]

    with pytest.raises(ValueError, match="distinct trust domain"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_rejects_binding_fingerprint_mismatch() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["bindingSigningKey"]["keyFingerprint"] = "sha256:" + "d" * 64  # type: ignore[index]

    with pytest.raises(ValueError, match="does not match runtime guidance trust"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_rejects_reused_managed_identity() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["requestKey"]["identityClientId"] = payload["serviceBus"][
        "brokerIdentityClientId"
    ]
    payload["requestKey"]["identityResourceId"] = payload["serviceBus"][
        "brokerIdentityResourceId"
    ]

    with pytest.raises(ValueError, match="managed identities must be distinct"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_requires_dedicated_request_submitter() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["serviceBus"]["requestSubmitterIdentityClientId"] = payload[  # type: ignore[index]
        "serviceBus"
    ]["brokerIdentityClientId"]  # type: ignore[index]
    payload["serviceBus"]["requestSubmitterIdentityResourceId"] = payload[  # type: ignore[index]
        "serviceBus"
    ]["brokerIdentityResourceId"]  # type: ignore[index]

    with pytest.raises(ValueError, match="submitter identity must be dedicated"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_publisher_configuration_requires_exact_request_outbox() -> None:
    payload = _bicep_generated_publisher_configuration()
    payload["requestOutbox"]["containerName"] = "different-outbox"  # type: ignore[index]

    with pytest.raises(ValueError, match="request outbox"):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    (
        (
            "authorityAssets",
            "blobEndpoint",
            "https://otherwc027.blob.core.windows.net",
            "authority assets do not match",
        ),
        (
            "authorityAssets",
            "containerName",
            "different-guidance-authority",
            "authority assets do not match",
        ),
        (
            "guidanceActivation",
            "tableEndpoint",
            "https://otherwc027.table.core.windows.net",
            "activation store does not match",
        ),
        (
            "guidanceActivation",
            "tableName",
            "OtherGuidanceActivation",
            "activation store does not match",
        ),
        (
            "guidanceActivation",
            "partitionKey",
            "other-guidance-authority",
            "activation store does not match",
        ),
    ),
)
def test_publisher_configuration_rejects_runtime_store_drift(
    section: str,
    field: str,
    value: str,
    message: str,
) -> None:
    payload = _bicep_generated_publisher_configuration()
    payload[section][field] = value

    with pytest.raises(ValueError, match=message):
        Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_runtime_rejects_guidance_authority_storage_domain_reuse() -> None:
    payload = _bicep_generated_runtime_configuration()
    payload["guidanceAuthoritySource"]["containerName"] = payload[
        "correlationSources"
    ]["monitoring"]["containerName"]

    with pytest.raises(ValueError, match="storage domains must be distinct"):
        Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_runtime_rejects_reused_public_key_material_across_trust_domains() -> None:
    payload = _bicep_generated_runtime_configuration()
    payload["keys"]["notification"]["keyFingerprint"] = payload["keys"]["feed"][  # type: ignore[index]
        "keyFingerprint"
    ]

    with pytest.raises(ValueError, match="public key fingerprints must be distinct"):
        Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
            json.dumps(payload)
        )


def test_complete_bicep_generated_configuration_starts_with_bound_key_authorities() -> None:
    payload = _bicep_generated_runtime_configuration()

    configuration = load_wc027_enrichment_feed_configuration(
        path=None,
        environment_json=json.dumps(payload),
    )

    assert (
        configuration.monitoring_collector_key.authority.identity_resource_id
        == payload["monitoringCollectorKey"]["identityResourceId"]  # type: ignore[index]
    )
    assert (
        configuration.incident_key.key_id
        == "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"
    )
    assert (
        configuration.incident_key.key_vault_key_id
        == payload["keys"]["incident"]["keyVaultKeyId"]  # type: ignore[index]
    )
    assert (
        configuration.incident_key.anchor.key_vault_key_id
        == configuration.incident_key.key_vault_key_id
    )


def test_only_lifecycle_and_guidance_binding_may_use_logical_key_ids() -> None:
    allowed = _bicep_generated_runtime_configuration()
    allowed["keys"]["guidanceBinding"]["keyId"] = (  # type: ignore[index]
        "synthetic-key://wc027/guidance-authority-binding"
    )
    configuration = Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
        json.dumps(allowed)
    )
    assert (
        configuration.guidance_binding_key.key_id
        == "synthetic-key://wc027/guidance-authority-binding"
    )
    assert configuration.guidance_binding_key.key_vault_key_id.startswith(
        "https://athena-wc027.vault.azure.net/keys/"
    )

    payload = _bicep_generated_runtime_configuration()
    payload["keys"]["feed"]["keyId"] = "synthetic-key://wc027/feed"  # type: ignore[index]

    with pytest.raises(
        ValueError,
        match=r"keys\.feed\.keyId must equal the referenced key version",
    ):
        Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
            json.dumps(payload)
        )


def _runtime(*, fail_feed_pointer_once: bool = False):
    fixture = _fixture()
    operations: list[str] = []
    enrichment_store = _Store()
    enrichment = _publication_service(fixture, enrichment_store)
    feed_writer = _Writer(operations)
    registry = _Registry(operations)
    index = _IndexPublication(registry, operations)
    feed = IncidentEnrichmentFeedPublicationService(
        current_incident_reader=_CurrentReader(fixture.publication_reader.current),
        artifact_writer=feed_writer,
        registry=registry,
        feed_index_publication=index,
        feed_key_id=_KEY_ID,
        feed_signer=_Signer(),
        feed_signature_verifier=_verify,
    )
    if fail_feed_pointer_once:
        prefix = (
            "incidents/"
            f"{fixture.incident_publication.incident_id}/versions/"
            f"{fixture.incident_publication.occurrence.state_result_digest.removeprefix('sha256:')}"
        )
        feed_writer.fail_after_persist.add(
            f"{prefix}/enrichments/"
            "incident-enrichment-"
            f"{fixture.guidance_binding.binding_digest.removeprefix('sha256:')[:32]}"
            "/feed-pointer.json"
        )
    notification = _Notification(operations)
    binding_verifier = _SignatureVerifier()
    incident_authority = _Authority(fixture.publication_reader)
    runtime = Wc027EnrichmentFeedRuntime(
        guidance_binding_key_id=(
            fixture.guidance_binding.binding_attestation.key_id
        ),
        guidance_binding_signature_verifier=binding_verifier,
        correlation=_Correlation(fixture.correlation_service, operations),
        incident_authority=incident_authority,
        guidance_activation=_Activation(
            fixture.guidance_binding,
            fixture.incident_publication.occurrence,
        ),
        enrichment_publication=_Enrichment(enrichment, operations),
        feed_publication=_Feed(feed, operations),
        notification_publication=notification,
    )
    return (
        fixture,
        runtime,
        enrichment_store,
        feed_writer,
        registry,
        index,
        notification,
        operations,
        binding_verifier,
        incident_authority,
    )


def test_runtime_orders_correlation_enrichment_feed_then_notification() -> None:
    (
        fixture,
        runtime,
        _store,
        _writer,
        _registry,
        _index,
        notification,
        operations,
        _binding_verifier,
        _incident_authority,
    ) = _runtime()

    receipt = runtime.publish(
        fixture.guidance_binding,
        published_at=PUBLISHED_AT,
    )

    assert operations.index("correlate") < operations.index("enrichment.start")
    assert operations.index("enrichment.complete") < operations.index("feed.start")
    assert operations.index("feed.complete") < operations.index("notification")
    assert notification.calls == 1
    assert receipt.binding_id == fixture.guidance_binding.binding_id


def test_runtime_rejects_invalid_outer_signature_before_any_authority_or_storage_call() -> None:
    (
        fixture,
        runtime,
        store,
        writer,
        registry,
        index,
        notification,
        operations,
        binding_verifier,
        incident_authority,
    ) = _runtime()
    binding_verifier.valid = False

    with pytest.raises(ValueError, match="binding signature is invalid"):
        runtime.publish(
            fixture.guidance_binding,
            published_at=PUBLISHED_AT,
        )

    assert len(binding_verifier.calls) == 1
    assert incident_authority.calls == []
    assert operations == []
    assert fixture.incident_reader.calls == []
    assert fixture.authority_reader.calls == []
    assert store.calls == []
    assert writer.values == {}
    assert registry.records == {}
    assert index.calls == 0
    assert notification.calls == 0


def test_production_composition_rejects_outer_signature_before_other_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fixture().guidance_binding
    verifier = _SignatureVerifier(valid=False)
    verifier_instance = SimpleNamespace(verify_preimage=verifier)
    verifier_requests: list[object] = []

    def fake_verifier(authority):
        verifier_requests.append(authority)
        return verifier_instance

    monkeypatch.setattr(production, "_verifier", fake_verifier)
    configuration = SimpleNamespace(
        guidance_binding_key=SimpleNamespace(
            key_id=binding.binding_attestation.key_id,
            key_vault_key_id=(
                "https://athena.vault.azure.net/keys/guidance-binding/"
                "00000000000000000000000000000001"
            ),
        )
    )

    with pytest.raises(ValueError, match="binding signature is invalid"):
        production.build_wc027_enrichment_feed_runtime(
            cast(Any, configuration),
            binding=binding,
            notification_outbox=cast(Any, object()),
        )

    assert verifier_requests == [configuration.guidance_binding_key]
    assert len(verifier.calls) == 1


def test_runtime_rejects_missing_authority_before_correlation_or_writes() -> None:
    (
        fixture,
        runtime,
        store,
        writer,
        registry,
        index,
        notification,
        operations,
        binding_verifier,
        _incident_authority,
    ) = _runtime()
    runtime = Wc027EnrichmentFeedRuntime(
        guidance_binding_key_id=runtime.guidance_binding_key_id,
        guidance_binding_signature_verifier=binding_verifier,
        correlation=runtime.correlation,
        incident_authority=_MissingAuthority(),
        guidance_activation=runtime.guidance_activation,
        enrichment_publication=runtime.enrichment_publication,
        feed_publication=runtime.feed_publication,
        notification_publication=runtime.notification_publication,
    )

    with pytest.raises(Wc027EnrichmentSourceNotReadyError):
        runtime.publish(
            fixture.guidance_binding,
            published_at=PUBLISHED_AT,
        )

    assert operations == []
    assert store.calls == []
    assert writer.values == {}
    assert registry.records == {}
    assert index.calls == 0
    assert notification.calls == 0


def test_runtime_rejects_stale_signed_binding_before_writes() -> None:
    (
        fixture,
        runtime,
        store,
        writer,
        registry,
        index,
        notification,
        operations,
        binding_verifier,
        _incident_authority,
    ) = _runtime()
    stale_current = SimpleNamespace(
        state=fixture.publication_reader.current.state.model_copy(
            update={"updated_at": NOW}
        ),
        occurrence=fixture.publication_reader.current.occurrence,
        pointer_sha256=fixture.publication_reader.current.pointer_sha256,
    )
    runtime = Wc027EnrichmentFeedRuntime(
        guidance_binding_key_id=runtime.guidance_binding_key_id,
        guidance_binding_signature_verifier=binding_verifier,
        correlation=runtime.correlation,
        incident_authority=SimpleNamespace(
            read_current_incident_state=lambda **_kwargs: stale_current,
            read_active_incident_index=lambda: fixture.publication_reader.active_index,
        ),
        guidance_activation=runtime.guidance_activation,
        enrichment_publication=runtime.enrichment_publication,
        feed_publication=runtime.feed_publication,
        notification_publication=runtime.notification_publication,
    )

    with pytest.raises(ValueError, match="stale"):
        runtime.publish(
            fixture.guidance_binding,
            published_at=PUBLISHED_AT,
        )

    assert operations == []
    assert store.calls == []
    assert writer.values == {}
    assert registry.records == {}
    assert index.calls == 0
    assert notification.calls == 0


def test_runtime_rejects_binding_that_is_not_the_current_activation() -> None:
    (
        fixture,
        runtime,
        store,
        writer,
        registry,
        index,
        notification,
        operations,
        binding_verifier,
        incident_authority,
    ) = _runtime()
    correlation_request = (
        fixture.guidance_binding.incident_bound_request.correlation_request
    )
    report = fixture.guidance_binding.correlation_report
    other_binding = _binding(
        request=correlation_request,
        report=report,
        requested_actions=("escalation",),
        selection=_no_runbook_selection(
            request=correlation_request,
            report=report,
            requested_actions=("escalation",),
        ),
    )
    runtime = Wc027EnrichmentFeedRuntime(
        guidance_binding_key_id=runtime.guidance_binding_key_id,
        guidance_binding_signature_verifier=binding_verifier,
        correlation=runtime.correlation,
        incident_authority=runtime.incident_authority,
        guidance_activation=_Activation(
            other_binding,
            fixture.incident_publication.occurrence,
        ),
        enrichment_publication=runtime.enrichment_publication,
        feed_publication=runtime.feed_publication,
        notification_publication=runtime.notification_publication,
    )

    with pytest.raises(ValueError, match="activation is invalid or stale"):
        runtime.publish(
            fixture.guidance_binding,
            published_at=PUBLISHED_AT,
        )

    assert operations == []
    assert store.calls == []
    assert writer.values == {}
    assert registry.records == {}
    assert index.calls == 0
    assert notification.calls == 0
    assert incident_authority.calls == ["current", "active"]


def test_runtime_retry_recovers_partial_feed_without_early_notification() -> None:
    (
        fixture,
        runtime,
        store,
        writer,
        registry,
        index,
        notification,
        operations,
        _binding_verifier,
        _incident_authority,
    ) = _runtime()
    enrichment = runtime.enrichment_publication.publish(
        incident_publication=fixture.incident_publication,
        verified_report=fixture.verified_report,
        guidance_binding=fixture.guidance_binding,
    )
    pointer_path = (
        enrichment.enrichment_asset.manifest_reference.name.removesuffix(
            "/manifest.json"
        )
        + "/feed-pointer.json"
    )
    writer.fail_after_persist.add(pointer_path)
    operations.clear()
    store.calls.clear()

    with pytest.raises(Exception, match="uncertain"):
        runtime.publish(
            fixture.guidance_binding,
            published_at=PUBLISHED_AT,
        )

    assert notification.calls == 0
    assert index.calls == 0
    assert tuple(writer.values) == (pointer_path,)

    receipt = runtime.publish(
        fixture.guidance_binding,
        published_at=PUBLISHED_AT,
    )

    assert notification.calls == 1
    assert len(store.values) == 6
    assert len(writer.values) == 2
    assert len(registry.records) == 1
    assert index.calls == 1
    assert receipt.notification.notification.incident_id == (
        fixture.incident_publication.incident_id
    )


def test_trigger_requires_exact_canonical_signed_binding_bytes() -> None:
    binding = _fixture().guidance_binding

    assert parse_wc027_enrichment_trigger(binding.canonical_bytes()) == binding
    with pytest.raises(ValueError, match="canonical"):
        parse_wc027_enrichment_trigger(
            binding.model_dump_json(by_alias=True, indent=2).encode("utf-8")
        )


def test_notification_reader_never_crosses_v1_and_v2_storage_boundaries() -> None:
    lifecycle = _ArtifactReaderProbe("lifecycle")
    enrichment_feed = _ArtifactReaderProbe("enrichment-feed")
    reader = _SplitIncidentPresentationReader(
        lifecycle_reader=cast(Any, lifecycle),
        enrichment_feed_reader=cast(Any, enrichment_feed),
    )
    digest = "sha256:" + "1" * 64

    reader.read_current(blob_name="incidents/active.json", maximum_bytes=10)
    reader.read_current(blob_name="incidents/feed-v2.json", maximum_bytes=10)
    reader.read_version(
        blob_name="incidents/inc-0123456789ab/versions/" + "a" * 64 + "/state.json",
        version_id="v1",
        expected_payload_sha256=digest,
        maximum_bytes=10,
    )
    reader.read_version(
        blob_name=(
            "incidents/inc-0123456789ab/versions/"
            + "a" * 64
            + "/enrichments/incident-enrichment-"
            + "b" * 32
            + "/manifest.json"
        ),
        version_id="v2",
        expected_payload_sha256=digest,
        maximum_bytes=10,
    )

    assert lifecycle.calls == [
        ("current", "incidents/active.json"),
        (
            "version",
            "incidents/inc-0123456789ab/versions/" + "a" * 64 + "/state.json",
        ),
    ]
    assert enrichment_feed.calls == [
        ("current", "incidents/feed-v2.json"),
        (
            "version",
            "incidents/inc-0123456789ab/versions/"
            + "a" * 64
            + "/enrichments/incident-enrichment-"
            + "b" * 32
            + "/manifest.json",
        ),
    ]


def test_production_configuration_rejects_identity_and_key_reuse() -> None:
    configuration = object.__new__(Wc027EnrichmentFeedProductionConfiguration)
    identity_ids = [f"00000000-0000-0000-0000-{index:012d}" for index in range(1, 18)]

    def resource_id(index: int) -> str:
        return (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/athena/providers/Microsoft.ManagedIdentity/"
            f"userAssignedIdentities/identity-{index}"
        )

    def source(index: int, container: str) -> _BlobSource:
        return _BlobSource(
            endpoint=f"https://storage{index}.blob.core.windows.net",
            container=container,
            identity_client_id=identity_ids[index],
            identity_resource_id=resource_id(index),
        )

    def key(index: int, identity_index: int) -> _KeyAuthority:
        return _KeyAuthority(
            key_id=f"synthetic-key://wc027/{index}",
            key_vault_key_id=(
                "https://synthetic.vault.azure.net/keys/"
                f"key-{index}/{index:032x}"
            ),
            key_fingerprint="sha256:" + f"{index:x}" * 64,
            identity_client_id=identity_ids[identity_index],
            identity_resource_id=resource_id(identity_index),
        )

    values = {
        "broker_identity_client_id": identity_ids[0],
        "broker_identity_resource_id": resource_id(0),
        "incident_lifecycle_assets": source(1, "incident-assets"),
        "enrichment_feed_assets": _WritableBlobSource(
            endpoint="https://storage2.blob.core.windows.net",
            container="wc027-enrichment-feed-v2",
            reader_identity_client_id=identity_ids[2],
            reader_identity_resource_id=resource_id(2),
            writer_identity_client_id=identity_ids[3],
            writer_identity_resource_id=resource_id(3),
        ),
        "registry_identity_client_id": identity_ids[4],
        "registry_identity_resource_id": resource_id(4),
        "monitoring_source": source(5, "monitoring"),
        "change_source": source(6, "changes"),
        "context_authority_source": source(7, "authority"),
        "monitoring_intent_source": source(8, "intent"),
        "guidance_authority_source": source(9, "guidance-authority"),
        "guidance_activation": _TableSource(
            endpoint="https://storage16.table.core.windows.net",
            table="Wc027GuidanceActivation",
            partition_key="wc027-guidance-authority",
            identity_client_id=identity_ids[16],
            identity_resource_id=resource_id(16),
        ),
        "monitoring_collector_key": _MonitoringCollectorKey(
            authority=key(1, 10),
            activated_at=NOW,
            expires_at=None,
        ),
        "change_key": key(2, 10),
        "monitoring_intent_key": key(3, 10),
        "incident_key": key(4, 10),
        "correlation_binding_key": key(5, 10),
        "guidance_binding_key": key(6, 10),
        "report_key": key(7, 11),
        "guidance_key": key(8, 12),
        "enrichment_key": key(9, 13),
        "feed_key": key(10, 14),
        "notification_key": key(11, 15),
        "binding_evidence_id": "00000000-0000-0000-0000-000000000099",
        "attached_identity_resource_ids": tuple(
            resource_id(index) for index in range(17)
        ),
        "rbac_resource_ids": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "providers/Microsoft.Authorization/roleDefinitions/"
            "00000000-0000-0000-0000-000000000098",
        ),
    }
    for name, value in values.items():
        object.__setattr__(configuration, name, value)

    configuration._validate_separation()

    object.__setattr__(
        configuration,
        "enrichment_feed_assets",
        _WritableBlobSource(
            endpoint=configuration.enrichment_feed_assets.endpoint,
            container=configuration.enrichment_feed_assets.container,
            reader_identity_client_id=(
                configuration.enrichment_feed_assets.reader_identity_client_id
            ),
            reader_identity_resource_id=(
                configuration.enrichment_feed_assets.reader_identity_resource_id
            ),
            writer_identity_client_id=(
                configuration.incident_lifecycle_assets.identity_client_id
            ),
            writer_identity_resource_id=(
                configuration.incident_lifecycle_assets.identity_resource_id
            ),
        ),
    )
    with pytest.raises(ValueError, match="I/O managed identities"):
        configuration._validate_separation()

    object.__setattr__(
        configuration,
        "enrichment_feed_assets",
        _WritableBlobSource(
            endpoint="https://storage2.blob.core.windows.net",
            container="wc027-enrichment-feed-v2",
            reader_identity_client_id=identity_ids[2],
            reader_identity_resource_id=resource_id(2),
            writer_identity_client_id=identity_ids[3],
            writer_identity_resource_id=resource_id(3),
        ),
    )
    object.__setattr__(
        configuration,
        "notification_key",
        _KeyAuthority(
            key_id=configuration.feed_key.key_id,
            key_vault_key_id=configuration.feed_key.key_vault_key_id,
            key_fingerprint=configuration.feed_key.key_fingerprint,
            identity_client_id=identity_ids[15],
            identity_resource_id=resource_id(15),
        ),
    )
    with pytest.raises(ValueError, match="key IDs"):
        configuration._validate_separation()
