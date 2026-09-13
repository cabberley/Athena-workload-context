from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from athena_context.contracts import IncidentNotificationEnvelopeV2
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
)
from test_wc026_correlation_contract import NOW
from test_wc027_enrichment_feed_pipeline import (
    PUBLISHED_AT,
    _CurrentReader,
    _IndexPublication,
    _Registry,
    _Writer,
)
from test_wc027_feed_registry import _KEY_ID
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
    runtime = Wc027EnrichmentFeedRuntime(
        correlation=_Correlation(fixture.correlation_service, operations),
        incident_authority=fixture.publication_reader,
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
    )


def test_runtime_orders_correlation_enrichment_feed_then_notification() -> None:
    fixture, runtime, _store, _writer, _registry, _index, notification, operations = (
        _runtime()
    )

    receipt = runtime.publish(
        fixture.guidance_binding,
        published_at=PUBLISHED_AT,
    )

    assert operations.index("correlate") < operations.index("enrichment.start")
    assert operations.index("enrichment.complete") < operations.index("feed.start")
    assert operations.index("feed.complete") < operations.index("notification")
    assert notification.calls == 1
    assert receipt.binding_id == fixture.guidance_binding.binding_id


def test_runtime_rejects_missing_authority_before_correlation_or_writes() -> None:
    fixture, runtime, store, writer, registry, index, notification, operations = _runtime()
    runtime = Wc027EnrichmentFeedRuntime(
        correlation=runtime.correlation,
        incident_authority=_MissingAuthority(),
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
    fixture, runtime, store, writer, registry, index, notification, operations = _runtime()
    stale_current = SimpleNamespace(
        state=fixture.publication_reader.current.state.model_copy(
            update={"updated_at": NOW}
        ),
        occurrence=fixture.publication_reader.current.occurrence,
        pointer_sha256=fixture.publication_reader.current.pointer_sha256,
    )
    runtime = Wc027EnrichmentFeedRuntime(
        correlation=runtime.correlation,
        incident_authority=SimpleNamespace(
            read_current_incident_state=lambda **_kwargs: stale_current,
            read_active_incident_index=lambda: fixture.publication_reader.active_index,
        ),
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


def test_runtime_retry_recovers_partial_feed_without_early_notification() -> None:
    fixture, runtime, store, writer, registry, index, notification, operations = _runtime()
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


def test_production_configuration_rejects_identity_and_key_reuse() -> None:
    configuration = object.__new__(Wc027EnrichmentFeedProductionConfiguration)
    identity_ids = [f"00000000-0000-0000-0000-{index:012d}" for index in range(1, 16)]

    def source(index: int, container: str) -> _BlobSource:
        return _BlobSource(
            endpoint=f"https://storage{index}.blob.core.windows.net",
            container=container,
            identity_client_id=identity_ids[index],
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
        )

    values = {
        "broker_identity_client_id": identity_ids[0],
        "incident_assets": source(1, "incident-assets"),
        "incident_writer_identity_client_id": identity_ids[2],
        "registry_identity_client_id": identity_ids[3],
        "monitoring_source": source(4, "monitoring"),
        "change_source": source(5, "changes"),
        "context_authority_source": source(6, "authority"),
        "monitoring_intent_source": source(7, "intent"),
        "guidance_authority_source": source(8, "guidance-authority"),
        "monitoring_collector_key": _MonitoringCollectorKey(
            authority=key(1, 9),
            activated_at=NOW,
            expires_at=None,
        ),
        "change_key": key(2, 9),
        "monitoring_intent_key": key(3, 9),
        "incident_key": key(4, 9),
        "correlation_binding_key": key(5, 9),
        "guidance_binding_key": key(6, 9),
        "report_key": key(7, 10),
        "guidance_key": key(8, 11),
        "enrichment_key": key(9, 12),
        "feed_key": key(10, 13),
        "notification_key": key(11, 14),
    }
    for name, value in values.items():
        object.__setattr__(configuration, name, value)

    configuration._validate_separation()

    object.__setattr__(
        configuration,
        "incident_writer_identity_client_id",
        configuration.incident_assets.identity_client_id,
    )
    with pytest.raises(ValueError, match="I/O managed identities"):
        configuration._validate_separation()

    object.__setattr__(
        configuration,
        "incident_writer_identity_client_id",
        identity_ids[2],
    )
    object.__setattr__(
        configuration,
        "notification_key",
        _KeyAuthority(
            key_id=configuration.feed_key.key_id,
            key_vault_key_id=configuration.feed_key.key_vault_key_id,
            key_fingerprint=configuration.feed_key.key_fingerprint,
            identity_client_id=identity_ids[14],
        ),
    )
    with pytest.raises(ValueError, match="key IDs"):
        configuration._validate_separation()
