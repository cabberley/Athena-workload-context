from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from athena_context.artifacts import (
    ArtifactWriteError,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    VersionPinnedBlobReference,
    build_incident_feed_index_v2,
    sha256_hex,
)
from athena_context.enrichment import (
    FEED_V2_INDEX_BLOB_NAME,
    MAX_FEED_V2_PUBLICATION_ATTEMPTS,
    IncidentEnrichmentFeedPublicationService,
    IncidentEnrichmentPublicationReceipt,
    IncidentFeedIndexPublicationConflictError,
    IncidentFeedIndexPublicationReceipt,
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryError,
    IncidentFeedRegistryRecord,
)
from athena_context.enrichment.publication import (
    _INCIDENT_ENRICHMENT_PUBLICATION_RECEIPT_TOKEN,
)
from test_wc026_correlation_contract import NOW
from test_wc027_feed_registry import (
    _KEY_FINGERPRINT,
    _KEY_ID,
    _pointer_bundle,
)
from test_wc027_incident_enrichment_publication import (
    _ENRICHMENT_KEY_ID,
    _SIGNATURE,
    _fixture,
    _publish,
    _Store,
)

PUBLISHED_AT = NOW + timedelta(minutes=5)


class _Signer:
    def sign_preimage(self, _canonical_preimage: bytes) -> str:
        return _SIGNATURE


def _verify(_preimage: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


class _CurrentReader:
    def __init__(self, current) -> None:
        self.current = current
        self.calls: list[str] = []

    def read_current_incident_state(self, *, incident_id: str):
        self.calls.append(incident_id)
        if self.current.state.incident_id == incident_id:
            return self.current
        return None


class _Writer:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.values: dict[str, tuple[bytes, str, str]] = {}
        self.fail_after_persist: set[str] = set()

    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference:
        self.operations.append(request.blob_name)
        existing = self.values.get(request.blob_name)
        if existing is None:
            existing = (
                request.payload,
                f"version-{len(self.values) + 1}",
                request.hashes.payload_sha256,
            )
            self.values[request.blob_name] = existing
        payload, version, digest = existing
        if payload != request.payload or digest != request.hashes.payload_sha256:
            raise ArtifactWriteError("synthetic immutable conflict")
        if request.blob_name in self.fail_after_persist:
            self.fail_after_persist.remove(request.blob_name)
            raise ArtifactWriteError("synthetic uncertain create response")
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=version,
            contentDigest=digest,
        )


class _Registry:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.records: dict[str, IncidentFeedRegistryRecord] = {}
        self.raise_after_put: IncidentFeedRegistryError | None = None
        self.forced_record: IncidentFeedRegistryRecord | None = None

    def put(self, record: IncidentFeedRegistryRecord) -> None:
        self.operations.append("registry.put")
        if self.forced_record is not None:
            self.records[record.entry.incident_id] = self.forced_record
            raise IncidentFeedRegistryConflictError("synthetic conflicting replay")
        current = self.records.get(record.entry.incident_id)
        if (
            current is not None
            and current != record
            and current.entry.updated_at >= record.entry.updated_at
        ):
            raise IncidentFeedRegistryConflictError(
                "synthetic stale or conflicting record"
            )
        self.records[record.entry.incident_id] = record
        if self.raise_after_put is not None:
            failure = self.raise_after_put
            self.raise_after_put = None
            raise failure

    def list_records(self, *, as_of):
        del as_of
        self.operations.append("registry.list")
        return tuple(
            self.records[incident_id]
            for incident_id in sorted(self.records)
        )

    def prune_expired(self, plan) -> None:
        del plan


class _IndexPublication:
    feed_key_id = _KEY_ID

    def __init__(
        self,
        registry: _Registry,
        operations: list[str],
    ) -> None:
        self.registry = registry
        self.operations = operations
        self.failures = 0
        self.failure_winner_published_at = None
        self.omit_entry_responses = 0
        self.calls = 0
        self._receipts: dict[bytes, IncidentFeedIndexPublicationReceipt] = {}

    def publish(
        self,
        *,
        published_at,
    ) -> IncidentFeedIndexPublicationReceipt:
        self.operations.append("feed-index.publish")
        self.calls += 1
        if self.failures:
            self.failures -= 1
            winner_published_at = self.failure_winner_published_at
            self.failure_winner_published_at = None
            raise IncidentFeedIndexPublicationConflictError(
                "synthetic feed index CAS conflict",
                winner_published_at=winner_published_at,
            )
        records = tuple(self.registry.records.values())
        if self.omit_entry_responses:
            self.omit_entry_responses -= 1
            records = ()
        active = tuple(
            sorted(
                (
                    record.entry
                    for record in records
                    if record.entry.lifecycle == "active"
                ),
                key=lambda entry: entry.incident_id,
            )
        )
        resolved = tuple(
            sorted(
                (
                    record.entry
                    for record in records
                    if record.entry.lifecycle == "resolved"
                ),
                key=lambda entry: (
                    -entry.updated_at.timestamp(),
                    entry.incident_id,
                    entry.state_result_digest,
                ),
            )
        )
        index = build_incident_feed_index_v2(
            active=active,
            recently_resolved=resolved,
            resolved_retention_start=published_at - timedelta(days=7),
            resolved_history_truncated=False,
            resolved_history_total_count=len(resolved),
            omitted_resolved_count=None,
            source_active_index_digest="sha256:" + "a" * 64,
            key_id=self.feed_key_id,
            key_fingerprint=_KEY_FINGERPRINT,
            published_at=published_at,
        )
        index_bytes = index.canonical_bytes()
        existing = self._receipts.get(index_bytes)
        if existing is not None:
            return existing
        receipt = IncidentFeedIndexPublicationReceipt(
            index=index,
            index_reference=VersionPinnedBlobReference(
                name=FEED_V2_INDEX_BLOB_NAME,
                version=f"index-{len(self._receipts) + 1}",
                contentDigest=sha256_hex(index_bytes),
            ),
            attestation_reference=VersionPinnedBlobReference(
                name=index.index_attestation_path.removeprefix("./"),
                version=f"attestation-{len(self._receipts) + 1}",
                contentDigest="sha256:" + "b" * 64,
            ),
        )
        self._receipts[index_bytes] = receipt
        return receipt


@dataclass(frozen=True, slots=True)
class _PipelineFixture:
    receipt: IncidentEnrichmentPublicationReceipt
    current: object


def _active_fixture() -> _PipelineFixture:
    fixture = _fixture()
    receipt = _publish(fixture, _Store())
    return _PipelineFixture(
        receipt=receipt,
        current=fixture.publication_reader.current,
    )


def _bundle_fixture(
    *,
    lifecycle: str,
    updated_at,
    base: IncidentEnrichmentPublicationReceipt,
) -> _PipelineFixture:
    _entry, pointer, _attestation, current = _pointer_bundle(
        1,
        lifecycle=lifecycle,
        updated_at=updated_at,
    )
    occurrence = current.occurrence
    assert occurrence is not None
    return _PipelineFixture(
        receipt=IncidentEnrichmentPublicationReceipt(
            occurrence=occurrence,
            correlation_report_asset=base.correlation_report_asset.model_copy(
                update={
                    "incident_id": occurrence.incident_id,
                    "incident_state_result_digest": occurrence.state_result_digest,
                }
            ),
            guidance_asset=base.guidance_asset.model_copy(
                update={
                    "incident_id": occurrence.incident_id,
                    "incident_state_digest": occurrence.state_result_digest,
                }
            ),
            enrichment_asset=pointer.enrichment_asset,
            report_key_id=base.report_key_id,
            guidance_key_id=base.guidance_key_id,
            enrichment_key_id=base.enrichment_key_id,
            published_at=max(
                base.published_at,
                occurrence.published_at,
            ),
            _verification_token=(
                _INCIDENT_ENRICHMENT_PUBLICATION_RECEIPT_TOKEN
            ),
        ),
        current=current,
    )


def _pipeline(
    fixture: _PipelineFixture,
    *,
    operations: list[str] | None = None,
    writer: _Writer | None = None,
    registry: _Registry | None = None,
    index: _IndexPublication | None = None,
) -> tuple[
    IncidentEnrichmentFeedPublicationService,
    _Writer,
    _Registry,
    _IndexPublication,
    list[str],
]:
    actual_operations = operations or []
    actual_writer = writer or _Writer(actual_operations)
    actual_registry = registry or _Registry(actual_operations)
    actual_index = index or _IndexPublication(
        actual_registry,
        actual_operations,
    )
    return (
        IncidentEnrichmentFeedPublicationService(
            current_incident_reader=_CurrentReader(fixture.current),
            artifact_writer=actual_writer,
            registry=actual_registry,
            feed_index_publication=actual_index,
            feed_key_id=_KEY_ID,
            feed_signer=_Signer(),
            feed_signature_verifier=_verify,
        ),
        actual_writer,
        actual_registry,
        actual_index,
        actual_operations,
    )


def test_pipeline_creates_pointer_before_registry_and_index() -> None:
    fixture = _active_fixture()
    service, _writer, registry, _index, operations = _pipeline(fixture)

    receipt = service.publish(
        fixture.receipt,
        published_at=PUBLISHED_AT,
    )

    assert operations[:4] == [
        receipt.registry_record.entry.feed_pointer_reference.name,
        receipt.registry_record.entry.feed_pointer_attestation_reference.name,
        "registry.put",
        "registry.list",
    ]
    assert operations[-1] == "feed-index.publish"
    assert registry.records[receipt.pointer.incident_id] == receipt.registry_record
    assert receipt.pointer.enrichment_asset == fixture.receipt.enrichment_asset


def test_pipeline_retry_recovers_partial_pointer_write() -> None:
    fixture = _active_fixture()
    operations: list[str] = []
    writer = _Writer(operations)
    pointer_path = (
        fixture.receipt.enrichment_asset.manifest_reference.name.removesuffix(
            "/manifest.json"
        )
        + "/feed-pointer.json"
    )
    writer.fail_after_persist.add(pointer_path)
    service, _writer, registry, index, _operations = _pipeline(
        fixture,
        operations=operations,
        writer=writer,
    )

    with pytest.raises(ArtifactWriteError, match="uncertain"):
        service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert tuple(writer.values) == (pointer_path,)
    assert registry.records == {}
    assert index.calls == 0

    recovered = service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert len(writer.values) == 2
    assert recovered.registry_record.entry.feed_pointer_reference.version == "version-1"
    assert index.calls == 1


@pytest.mark.parametrize(
    "failure",
    [
        IncidentFeedRegistryConflictError("synthetic uncertain conflict"),
        IncidentFeedRegistryError("synthetic uncertain response"),
    ],
)
def test_pipeline_accepts_exact_registry_replay_after_uncertain_write(
    failure: IncidentFeedRegistryError,
) -> None:
    fixture = _active_fixture()
    service, _writer, registry, index, _operations = _pipeline(fixture)
    registry.raise_after_put = failure

    receipt = service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert registry.records[receipt.pointer.incident_id] == receipt.registry_record
    assert index.calls == 1


def test_pipeline_rejects_conflicting_registry_replay_before_index() -> None:
    fixture = _active_fixture()
    service, _writer, registry, index, _operations = _pipeline(fixture)
    first = service.publish(fixture.receipt, published_at=PUBLISHED_AT)
    conflicting = first.registry_record.model_copy(
        update={"record_digest": "sha256:" + "f" * 64}
    )
    registry.forced_record = conflicting

    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="conflicting incident record",
    ):
        service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert index.calls == 1


def test_pipeline_rejects_non_current_occurrence_before_writes() -> None:
    fixture = _active_fixture()
    stale = _bundle_fixture(
        lifecycle="active",
        updated_at=NOW - timedelta(minutes=1),
        base=fixture.receipt,
    )
    latest = _bundle_fixture(
        lifecycle="active",
        updated_at=NOW,
        base=fixture.receipt,
    )
    service, writer, registry, index, _operations = _pipeline(
        _PipelineFixture(
            receipt=stale.receipt,
            current=latest.current,
        )
    )

    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="authoritative current occurrence",
    ):
        service.publish(stale.receipt, published_at=PUBLISHED_AT)

    assert writer.values == {}
    assert registry.records == {}
    assert index.calls == 0


def test_pipeline_cas_failure_is_retryable_and_gates_notification() -> None:
    fixture = _active_fixture()
    service, writer, registry, index, _operations = _pipeline(fixture)
    index.failures = MAX_FEED_V2_PUBLICATION_ATTEMPTS
    notifications: list[str] = []

    index.failure_winner_published_at = PUBLISHED_AT + timedelta(seconds=2)
    with pytest.raises(IncidentFeedIndexPublicationConflictError) as captured:
        published = service.publish(fixture.receipt, published_at=PUBLISHED_AT)
        notifications.append(published.pointer.pointer_id)

    assert notifications == []
    assert captured.value.winner_published_at == (
        PUBLISHED_AT + timedelta(seconds=2)
    )
    assert len(writer.values) == 2
    assert len(registry.records) == 1

    index.failures = 0
    published = service.publish(fixture.receipt, published_at=PUBLISHED_AT)
    notifications.append(published.pointer.pointer_id)

    assert notifications == [published.pointer.pointer_id]
    assert index.calls == MAX_FEED_V2_PUBLICATION_ATTEMPTS + 1


def test_pipeline_full_retry_is_idempotent() -> None:
    fixture = _active_fixture()
    service, writer, registry, index, _operations = _pipeline(fixture)

    first = service.publish(fixture.receipt, published_at=PUBLISHED_AT)
    second = service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert second == first
    assert len(writer.values) == 2
    assert len(registry.records) == 1
    assert index.calls == 2


def test_pipeline_replaces_active_record_with_resolved_successor() -> None:
    base = _active_fixture()
    active = _bundle_fixture(
        lifecycle="active",
        updated_at=NOW,
        base=base.receipt,
    )
    resolved = _bundle_fixture(
        lifecycle="resolved",
        updated_at=NOW + timedelta(minutes=1),
        base=base.receipt,
    )
    operations: list[str] = []
    writer = _Writer(operations)
    registry = _Registry(operations)
    index = _IndexPublication(registry, operations)
    active_service, *_ = _pipeline(
        active,
        operations=operations,
        writer=writer,
        registry=registry,
        index=index,
    )
    resolved_service, *_ = _pipeline(
        resolved,
        operations=operations,
        writer=writer,
        registry=registry,
        index=index,
    )

    active_result = active_service.publish(
        active.receipt,
        published_at=PUBLISHED_AT,
    )
    resolved_result = resolved_service.publish(
        resolved.receipt,
        published_at=PUBLISHED_AT + timedelta(minutes=1),
    )

    assert active_result.registry_record.entry.lifecycle == "active"
    assert resolved_result.registry_record.entry.lifecycle == "resolved"
    assert resolved_result.feed_index_publication.index.active == ()
    assert resolved_result.feed_index_publication.index.recently_resolved == (
        resolved_result.registry_record.entry,
    )


def test_pipeline_requires_distinct_feed_signing_authority() -> None:
    fixture = _active_fixture()
    operations: list[str] = []
    registry = _Registry(operations)
    index = _IndexPublication(registry, operations)
    index.feed_key_id = _ENRICHMENT_KEY_ID

    service = IncidentEnrichmentFeedPublicationService(
        current_incident_reader=_CurrentReader(fixture.current),
        artifact_writer=_Writer(operations),
        registry=registry,
        feed_index_publication=index,
        feed_key_id=_ENRICHMENT_KEY_ID,
        feed_signer=_Signer(),
        feed_signature_verifier=_verify,
    )

    with pytest.raises(ValueError, match="distinct"):
        service.publish(fixture.receipt, published_at=PUBLISHED_AT)


def test_unverified_enrichment_receipt_cannot_enter_pipeline() -> None:
    fixture = _active_fixture()

    with pytest.raises(TypeError, match="verified publication"):
        IncidentEnrichmentPublicationReceipt(
            occurrence=fixture.receipt.occurrence,
            correlation_report_asset=fixture.receipt.correlation_report_asset,
            guidance_asset=fixture.receipt.guidance_asset,
            enrichment_asset=fixture.receipt.enrichment_asset,
            report_key_id=fixture.receipt.report_key_id,
            guidance_key_id=fixture.receipt.guidance_key_id,
            enrichment_key_id=fixture.receipt.enrichment_key_id,
            published_at=fixture.receipt.published_at,
        )


def test_pipeline_retries_index_without_changing_immutable_pointer() -> None:
    fixture = _active_fixture()
    service, writer, _registry, index, _operations = _pipeline(fixture)
    index.omit_entry_responses = 1

    receipt = service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert len(writer.values) == 2
    assert index.calls == 2
    assert receipt.pointer.published_at == fixture.receipt.published_at
    assert receipt.feed_index_publication.index.published_at == (
        PUBLISHED_AT + timedelta(milliseconds=1)
    )


def test_pipeline_retries_same_timestamp_index_conflict_without_rewriting_pointer() -> None:
    fixture = _active_fixture()
    service, writer, _registry, index, _operations = _pipeline(fixture)
    index.failures = 1
    index.failure_winner_published_at = PUBLISHED_AT + timedelta(seconds=1)

    receipt = service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert len(writer.values) == 2
    assert index.calls == 2
    assert receipt.pointer.published_at == fixture.receipt.published_at
    assert receipt.feed_index_publication.index.published_at == (
        PUBLISHED_AT + timedelta(seconds=1, milliseconds=1)
    )


def test_pipeline_retry_with_fresher_index_time_reuses_pointer_bytes() -> None:
    fixture = _active_fixture()
    service, writer, _registry, _index, _operations = _pipeline(fixture)

    first = service.publish(fixture.receipt, published_at=PUBLISHED_AT)
    second = service.publish(
        fixture.receipt,
        published_at=PUBLISHED_AT + timedelta(seconds=1),
    )

    assert second.pointer == first.pointer
    assert second.registry_record.entry.feed_pointer_reference == (
        first.registry_record.entry.feed_pointer_reference
    )
    assert len(writer.values) == 2


def test_pipeline_requires_exact_entry_in_successful_feed_index() -> None:
    fixture = _active_fixture()
    service, _writer, _registry, index, _operations = _pipeline(fixture)
    index.omit_entry_responses = MAX_FEED_V2_PUBLICATION_ATTEMPTS

    with pytest.raises(
        RuntimeError,
        match="exact durable registry entry",
    ):
        service.publish(fixture.receipt, published_at=PUBLISHED_AT)

    assert index.calls == MAX_FEED_V2_PUBLICATION_ATTEMPTS
