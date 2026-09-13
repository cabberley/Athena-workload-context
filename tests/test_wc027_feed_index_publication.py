from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest
from azure.core import MatchConditions

from athena_context.artifacts import (
    ArtifactNotFoundError,
    ArtifactReadRequest,
    ArtifactReadResult,
)
from athena_context.contracts import (
    ActiveIncidentIndex,
    IncidentFeedIndexAttestationV2,
    VersionPinnedBlobReference,
    build_incident_feed_index_v2,
    sha256_hex,
)
from athena_context.enrichment import (
    FEED_V2_INDEX_BLOB_NAME,
    AzureBlobIncidentFeedIndexPublisher,
    IncidentFeedIndexCommitRequest,
    IncidentFeedIndexPublicationConflictError,
    IncidentFeedIndexPublicationService,
    IncidentFeedIndexSnapshot,
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryIncompleteError,
    build_incident_feed_registry_record,
)
from athena_context.presentation_assets import ActiveIncidentIndexSnapshot
from test_wc026_correlation_contract import NOW
from test_wc027_feed_registry import (
    _KEY_FINGERPRINT,
    _KEY_ID,
    _SIGNATURE,
    _active_index,
    _authority,
    _pointer_bundle,
    _record,
)

PUBLISHED_AT = NOW + timedelta(minutes=2)


class _Signer:
    def sign_preimage(self, _canonical_preimage: bytes) -> str:
        return _SIGNATURE


def _verify(_preimage: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


@dataclass
class _ActiveReader:
    snapshots: list[ActiveIncidentIndexSnapshot | None]
    calls: int = 0

    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None:
        value = self.snapshots[min(self.calls, len(self.snapshots) - 1)]
        self.calls += 1
        return value


@dataclass
class _CurrentReader:
    snapshots: dict[str, object]

    def read_current_incident_state(self, *, incident_id: str):
        return self.snapshots.get(incident_id)


@dataclass
class _Registry:
    record_sets: list[tuple]
    calls: int = 0
    prune_calls: int = 0

    def put(self, record) -> None:
        raise AssertionError(f"unexpected registry write: {record}")

    def list_records(self, *, as_of):
        del as_of
        value = self.record_sets[min(self.calls, len(self.record_sets) - 1)]
        self.calls += 1
        return value

    def prune_expired(self, plan) -> None:
        del plan
        self.prune_calls += 1


class _PointerReader:
    def __init__(self, record_sets: list[tuple]) -> None:
        self.payloads: dict[tuple[str, str], bytes] = {}
        self.calls: list[ArtifactReadRequest] = []
        for records in record_sets:
            for record in records:
                self.payloads[
                    (
                        record.entry.feed_pointer_reference.name,
                        record.entry.feed_pointer_reference.version,
                    )
                ] = record.pointer.canonical_bytes()
                self.payloads[
                    (
                        record.entry.feed_pointer_attestation_reference.name,
                        record.entry.feed_pointer_attestation_reference.version,
                    )
                ] = record.pointer_attestation.canonical_bytes()

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        self.calls.append(request)
        try:
            payload = self.payloads[(request.blob_name, request.version_id)]
        except KeyError as exc:
            raise ArtifactNotFoundError("synthetic missing exact version") from exc
        return ArtifactReadResult(
            container_name="incident-assets",
            blob_name=request.blob_name,
            version_id=request.version_id,
            payload=payload,
            size_bytes=len(payload),
            content_type="application/json",
            payload_sha256=sha256_hex(payload),
        )


class _Publisher:
    def __init__(self) -> None:
        self.current: IncidentFeedIndexSnapshot | None = None
        self.commits: list[IncidentFeedIndexCommitRequest] = []
        self.before_first_commit = None
        self.lost_first_response = False
        self.partial_first_upload = False
        self.attestation_paths: set[str] = set()
        self._version = 0

    def read_current(self) -> IncidentFeedIndexSnapshot | None:
        return self.current

    def compare_and_swap(
        self,
        request: IncidentFeedIndexCommitRequest,
    ) -> IncidentFeedIndexSnapshot:
        self.commits.append(request)
        self.attestation_paths.add(request.index.index_attestation_path.removeprefix("./"))
        if self.partial_first_upload and len(self.commits) == 1:
            raise IncidentFeedIndexPublicationConflictError(
                "synthetic failure after attestation upload"
            )
        if self.before_first_commit is not None and len(self.commits) == 1:
            callback = self.before_first_commit
            self.before_first_commit = None
            callback()
        expected = None if self.current is None else self.current.etag
        if request.expected_etag != expected:
            raise IncidentFeedIndexPublicationConflictError("synthetic lost CAS")
        self.current = _snapshot(
            request.index,
            request.attestation,
            version=self._next_version(),
        )
        if self.lost_first_response and len(self.commits) == 1:
            raise IncidentFeedIndexPublicationConflictError("synthetic response lost after commit")
        return self.current

    def _next_version(self) -> int:
        self._version += 1
        return self._version


def _source(index: ActiveIncidentIndex) -> ActiveIncidentIndexSnapshot:
    return ActiveIncidentIndexSnapshot(
        index=index,
        payload_sha256=sha256_hex(index.canonical_bytes()),
    )


def _snapshot(
    index,
    attestation: IncidentFeedIndexAttestationV2,
    *,
    version: int,
) -> IncidentFeedIndexSnapshot:
    return IncidentFeedIndexSnapshot(
        index=index,
        attestation=attestation,
        index_reference=VersionPinnedBlobReference(
            name=FEED_V2_INDEX_BLOB_NAME,
            version=f"index-version-{version}",
            contentDigest=sha256_hex(index.canonical_bytes()),
        ),
        attestation_reference=VersionPinnedBlobReference(
            name=index.index_attestation_path.removeprefix("./"),
            version=f"attestation-version-{version}",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
        etag=f'"etag-{version}"',
    )


def _service(
    *,
    source: ActiveIncidentIndexSnapshot,
    records: tuple,
    publisher: _Publisher | None = None,
    sources: list[ActiveIncidentIndexSnapshot | None] | None = None,
    record_sets: list[tuple] | None = None,
    pointer_reader: _PointerReader | None = None,
    current_authorities: dict[str, object] | None = None,
    verifier=_verify,
) -> tuple[IncidentFeedIndexPublicationService, _Publisher]:
    actual_publisher = publisher or _Publisher()
    actual_record_sets = record_sets or [records]
    if current_authorities is None:
        latest_records = {
            record.entry.incident_id: record
            for record_set in actual_record_sets
            for record in record_set
        }
        current_authorities = {
            incident_id: _authority(
                int(incident_id.removeprefix("inc-"), 16),
                lifecycle=record.entry.lifecycle,
                updated_at=record.entry.updated_at,
            )
            for incident_id, record in latest_records.items()
        }
    return (
        IncidentFeedIndexPublicationService(
            active_index_reader=_ActiveReader(sources or [source]),
            current_incident_reader=_CurrentReader(current_authorities),
            registry=_Registry(actual_record_sets),
            pointer_reader=pointer_reader or _PointerReader(actual_record_sets),
            publisher=actual_publisher,
            feed_key_id=_KEY_ID,
            feed_key_fingerprint=_KEY_FINGERPRINT,
            signer=_Signer(),
            signature_verifier=verifier,
        ),
        actual_publisher,
    )


def _candidate_snapshot(
    *,
    source: ActiveIncidentIndexSnapshot,
    records: tuple,
    published_at=PUBLISHED_AT,
    version: int = 99,
    current_authorities: dict[str, object] | None = None,
) -> IncidentFeedIndexSnapshot:
    service, _ = _service(
        source=source,
        records=records,
        current_authorities=current_authorities,
    )
    index, attestation, _projection = service._build_candidate(
        source=source,
        published_at=published_at,
    )
    return _snapshot(index, attestation, version=version)


def test_publication_projects_exact_active_and_bounded_resolved_history() -> None:
    active = _record(1, lifecycle="active")
    resolved = tuple(
        _record(
            index,
            lifecycle="resolved",
            updated_at=NOW - timedelta(minutes=index),
        )
        for index in range(2, 68)
    )
    source = _source(_active_index((active.entry,)))
    service, publisher = _service(
        source=source,
        records=(active, *resolved),
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert receipt.index.source_active_index_digest == source.payload_sha256
    assert receipt.index.active == (active.entry,)
    assert len(receipt.index.recently_resolved) == 64
    assert receipt.index.resolved_history_total_count == 66
    assert receipt.index.omitted_resolved_count == 2
    assert receipt.index.resolved_history_truncated is True
    assert receipt.index_reference.name == FEED_V2_INDEX_BLOB_NAME
    assert receipt.attestation_reference.name == (
        receipt.index.index_attestation_path.removeprefix("./")
    )
    assert publisher.current is not None


def test_publication_fails_before_writes_when_active_record_is_missing() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    service, publisher = _service(source=source, records=())

    with pytest.raises(IncidentFeedRegistryIncompleteError, match="missing"):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


def test_same_timestamp_conflict_reports_verified_winner_time() -> None:
    resolved = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(minutes=1),
    )
    source = _source(_active_index(()))
    publisher = _Publisher()
    publisher.current = _candidate_snapshot(
        source=source,
        records=(),
        published_at=PUBLISHED_AT,
    )
    service, _ = _service(
        source=source,
        records=(resolved,),
        publisher=publisher,
    )

    with pytest.raises(
        IncidentFeedIndexPublicationConflictError,
        match="same timestamp",
    ) as captured:
        service.publish(published_at=PUBLISHED_AT)

    assert captured.value.winner_published_at == PUBLISHED_AT


def test_publication_rejects_v1_pointer_digest_mismatch() -> None:
    active = _record(1, lifecycle="active")
    source_index = _active_index((active.entry,))
    mismatched = source_index.model_copy(
        update={
            "incidents": (
                source_index.incidents[0].model_copy(
                    update={"pointer_sha256": "sha256:" + "f" * 64}
                ),
            )
        }
    )
    service, publisher = _service(
        source=_source(mismatched),
        records=(active,),
    )

    with pytest.raises(IncidentFeedRegistryIncompleteError, match="does not match"):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


def test_publication_rejects_stale_or_tampered_registry_records() -> None:
    active = _record(1, lifecycle="active")
    stale = _record(
        1,
        lifecycle="active",
        updated_at=active.entry.updated_at - timedelta(seconds=1),
    )
    source = _source(_active_index((active.entry,)))
    stale_service, stale_publisher = _service(
        source=source,
        records=(stale,),
    )

    with pytest.raises(IncidentFeedRegistryIncompleteError, match="does not match"):
        stale_service.publish(published_at=PUBLISHED_AT)
    assert stale_publisher.commits == []

    tampered = active.model_copy(update={"record_digest": "sha256:" + "f" * 64})
    tampered_service, tampered_publisher = _service(
        source=source,
        records=(tampered,),
    )
    with pytest.raises(ValueError, match="recordDigest"):
        tampered_service.publish(published_at=PUBLISHED_AT)
    assert tampered_publisher.commits == []


def test_publication_rejects_registry_references_to_missing_blob_versions() -> None:
    active = _record(1, lifecycle="active")
    dangling_entry = active.entry.model_copy(
        update={
            "feed_pointer_reference": active.entry.feed_pointer_reference.model_copy(
                update={"version": "missing-version"}
            )
        }
    )
    dangling = build_incident_feed_registry_record(
        dangling_entry,
        active.pointer,
        active.pointer_attestation,
    )
    source = _source(_active_index((active.entry,)))
    service, publisher = _service(
        source=source,
        records=(dangling,),
        pointer_reader=_PointerReader([(active,)]),
    )

    with pytest.raises(
        RuntimeError,
        match="unavailable immutable asset",
    ):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


def test_publication_rejects_replayed_resolved_record_against_current_occurrence() -> None:
    replayed = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=2),
    )
    source = _source(_active_index(()))
    service, publisher = _service(
        source=source,
        records=(replayed,),
        current_authorities={
            replayed.entry.incident_id: _authority(
                2,
                lifecycle="resolved",
                updated_at=NOW - timedelta(hours=1),
            )
        },
    )

    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="authoritative current occurrence",
    ):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


@pytest.mark.parametrize(
    "winner_published_at",
    (
        PUBLISHED_AT,
        PUBLISHED_AT + timedelta(seconds=1),
    ),
)
def test_publication_replaces_invalid_same_source_winner(
    winner_published_at,
) -> None:
    replayed = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=2),
    )
    latest = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=1),
    )
    source = _source(_active_index(()))
    replayed_authority = {
        replayed.entry.incident_id: _authority(
            2,
            lifecycle="resolved",
            updated_at=replayed.entry.updated_at,
        )
    }
    publisher = _Publisher()
    publisher.current = _candidate_snapshot(
        source=source,
        records=(replayed,),
        published_at=winner_published_at,
        current_authorities=replayed_authority,
    )
    pointer_reader = _PointerReader([(replayed,), (latest,)])
    service, _ = _service(
        source=source,
        records=(latest,),
        publisher=publisher,
        pointer_reader=pointer_reader,
        current_authorities={
            latest.entry.incident_id: _authority(
                2,
                lifecycle="resolved",
                updated_at=latest.entry.updated_at,
            )
        },
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert receipt.index.recently_resolved == (latest.entry,)
    assert receipt.index.published_at > winner_published_at
    assert len(publisher.commits) == 1
    assert publisher.commits[0].expected_etag == '"etag-99"'


def test_publication_prunes_only_after_verified_commit() -> None:
    expired = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=8),
    )
    source = _source(_active_index(()))
    service, _publisher = _service(source=source, records=(expired,))
    registry = service.registry
    assert isinstance(registry, _Registry)

    service.publish(published_at=PUBLISHED_AT)

    assert registry.prune_calls == 1


def test_publication_rejects_pointer_and_generated_signature_failures() -> None:
    entry, pointer, attestation, _current = _pointer_bundle(1, lifecycle="active")
    bad_attestation = attestation.model_copy(update={"detached_signature": "AAAA"})
    bad_entry = entry.model_copy(
        update={
            "feed_pointer_attestation_reference": (
                entry.feed_pointer_attestation_reference.model_copy(
                    update={"content_digest": sha256_hex(bad_attestation.canonical_bytes())}
                )
            )
        }
    )
    record = build_incident_feed_registry_record(
        bad_entry,
        pointer,
        bad_attestation,
    )
    source = _source(_active_index((entry,)))
    service, publisher = _service(source=source, records=(record,))
    with pytest.raises(RuntimeError, match="pointer assets.*verification"):
        service.publish(published_at=PUBLISHED_AT)
    assert publisher.commits == []

    valid = _record(1, lifecycle="active")
    signing_service, signing_publisher = _service(
        source=_source(_active_index((valid.entry,))),
        records=(valid,),
        verifier=lambda preimage, _signature: b"athena.wc027IncidentFeedIndex.v2" not in preimage,
    )
    with pytest.raises(ValueError, match="immediate verification"):
        signing_service.publish(published_at=PUBLISHED_AT)
    assert signing_publisher.commits == []


def test_stale_concurrent_publisher_accepts_newer_verified_winner() -> None:
    first = _record(1, lifecycle="active")
    second = _record(2, lifecycle="active")
    first_source = _source(_active_index((first.entry,)))
    second_source = _source(_active_index((first.entry, second.entry)))
    publisher = _Publisher()
    winner = _candidate_snapshot(
        source=second_source,
        records=(first, second),
        published_at=PUBLISHED_AT + timedelta(seconds=1),
    )
    publisher.before_first_commit = lambda: setattr(publisher, "current", winner)
    service, _ = _service(
        source=first_source,
        records=(first,),
        publisher=publisher,
        sources=[first_source, first_source, second_source],
        record_sets=[(first,), (first, second)],
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert receipt.index == winner.index
    assert publisher.current == winner
    assert len(publisher.commits) == 1


def test_lost_cas_response_is_recovered_as_idempotent_success() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    publisher = _Publisher()
    publisher.lost_first_response = True
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert publisher.current is not None
    assert receipt.index == publisher.current.index
    assert len(publisher.commits) == 1


def test_lost_cas_recovery_uses_attempted_candidate_before_registry_reread() -> None:
    active = _record(1, lifecycle="active")
    resolved = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(minutes=1),
    )
    source = _source(_active_index((active.entry,)))
    publisher = _Publisher()
    publisher.lost_first_response = True
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
        record_sets=[(active,), (active, resolved)],
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert publisher.current is not None
    assert receipt.index == publisher.current.index
    assert receipt.index.recently_resolved == ()
    assert len(publisher.commits) == 1


def test_lost_cas_candidate_is_not_accepted_after_v1_authority_advances() -> None:
    first = _record(1, lifecycle="active")
    second = _record(2, lifecycle="active")
    first_source = _source(_active_index((first.entry,)))
    second_source = _source(_active_index((first.entry, second.entry)))
    publisher = _Publisher()
    publisher.lost_first_response = True
    service, _ = _service(
        source=first_source,
        records=(first,),
        publisher=publisher,
        sources=[first_source, first_source, second_source],
        record_sets=[(first,), (first, second)],
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert {entry.incident_id for entry in receipt.index.active} == {
        first.entry.incident_id,
        second.entry.incident_id,
    }
    assert receipt.index.source_active_index_digest == second_source.payload_sha256
    assert len(publisher.commits) == 2


def test_successful_stale_write_is_repaired_when_v1_advances_during_cas() -> None:
    first = _record(1, lifecycle="active")
    second = _record(2, lifecycle="active")
    first_source = _source(_active_index((first.entry,)))
    second_source = _source(_active_index((first.entry, second.entry)))
    publisher = _Publisher()
    service, _ = _service(
        source=first_source,
        records=(first,),
        publisher=publisher,
        sources=[first_source, first_source, second_source],
        record_sets=[(first,), (first, second)],
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert publisher.current is not None
    assert receipt.index == publisher.current.index
    assert receipt.index.source_active_index_digest == second_source.payload_sha256
    assert len(publisher.commits) == 2


def test_preexisting_winner_is_rechecked_before_acceptance() -> None:
    first = _record(1, lifecycle="active")
    second = _record(2, lifecycle="active")
    first_source = _source(_active_index((first.entry,)))
    second_source = _source(_active_index((first.entry, second.entry)))
    publisher = _Publisher()
    publisher.current = _candidate_snapshot(
        source=first_source,
        records=(first,),
        published_at=PUBLISHED_AT + timedelta(seconds=1),
    )
    service, _ = _service(
        source=first_source,
        records=(first,),
        publisher=publisher,
        sources=[first_source, first_source, second_source],
        record_sets=[(first,), (first, second)],
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert publisher.current is not None
    assert receipt.index == publisher.current.index
    assert receipt.index.source_active_index_digest == second_source.payload_sha256
    assert len(publisher.commits) == 1


def test_idempotent_retry_reuses_exact_versioned_winner() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    publisher = _Publisher()
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    first = service.publish(published_at=PUBLISHED_AT)
    second = service.publish(published_at=PUBLISHED_AT)

    assert second == first
    assert len(publisher.commits) == 1


def test_partial_attestation_upload_never_exposes_partial_index() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    publisher = _Publisher()
    publisher.partial_first_upload = True
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert publisher.current is not None
    assert publisher.current.index == receipt.index
    assert len(publisher.attestation_paths) == 1
    assert len(publisher.commits) == 2


def test_publication_rejects_noncanonical_timestamp_precision() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    service, publisher = _service(source=source, records=(active,))

    with pytest.raises(ValueError, match="millisecond precision"):
        service.publish(published_at=PUBLISHED_AT.replace(microsecond=1))

    assert publisher.commits == []


def test_stale_invocation_accepts_winner_for_newer_v1_authority() -> None:
    active = _record(1, lifecycle="active")
    source_index = _active_index((active.entry,)).model_copy(
        update={"published_at": PUBLISHED_AT + timedelta(seconds=2)}
    )
    source = _source(source_index)
    publisher = _Publisher()
    winner = _candidate_snapshot(
        source=source,
        records=(active,),
        published_at=PUBLISHED_AT + timedelta(seconds=3),
    )
    publisher.current = winner
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    receipt = service.publish(published_at=PUBLISHED_AT)

    assert receipt.index == winner.index
    assert publisher.commits == []


def test_winner_active_pointer_digest_must_match_v1_authority() -> None:
    active = _record(1, lifecycle="active")
    source_index = _active_index((active.entry,))
    source_index = source_index.model_copy(
        update={
            "incidents": (
                source_index.incidents[0].model_copy(
                    update={"pointer_sha256": "sha256:" + "f" * 64}
                ),
            ),
            "published_at": PUBLISHED_AT + timedelta(seconds=1),
        }
    )
    source = _source(source_index)
    winner_published_at = PUBLISHED_AT + timedelta(seconds=2)
    winner_index = build_incident_feed_index_v2(
        active=(active.entry,),
        recently_resolved=(),
        resolved_retention_start=winner_published_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=0,
        omitted_resolved_count=None,
        source_active_index_digest=source.payload_sha256,
        key_id=_KEY_ID,
        key_fingerprint=_KEY_FINGERPRINT,
        published_at=winner_published_at,
    )
    winner_attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(winner_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=_KEY_ID,
        detachedSignature=_SIGNATURE,
    )
    publisher = _Publisher()
    publisher.current = _snapshot(
        winner_index,
        winner_attestation,
        version=77,
    )
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="does not match",
    ):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


def test_tampered_current_winner_signature_fails_closed() -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    publisher = _Publisher()
    winner = _candidate_snapshot(source=source, records=(active,))
    publisher.current = IncidentFeedIndexSnapshot(
        index=winner.index,
        attestation=IncidentFeedIndexAttestationV2(
            schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
            indexDigest=winner.attestation.index_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=_KEY_ID,
            detachedSignature="AAAA",
        ),
        index_reference=winner.index_reference,
        attestation_reference=VersionPinnedBlobReference(
            name=winner.attestation_reference.name,
            version=winner.attestation_reference.version,
            contentDigest=sha256_hex(
                IncidentFeedIndexAttestationV2(
                    schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
                    indexDigest=winner.attestation.index_digest,
                    signatureAlgorithm="RS256",
                    keyVaultKeyId=_KEY_ID,
                    detachedSignature="AAAA",
                ).canonical_bytes()
            ),
        ),
        etag=winner.etag,
    )
    service, _ = _service(
        source=source,
        records=(active,),
        publisher=publisher,
    )

    with pytest.raises(ValueError, match="exact content"):
        service.publish(published_at=PUBLISHED_AT)

    assert publisher.commits == []


def test_azure_publisher_uploads_attestation_before_etag_cas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    winner = _candidate_snapshot(source=source, records=(active,))
    request = IncidentFeedIndexCommitRequest(
        index=winner.index,
        attestation=winner.attestation,
        expected_etag='"expected-etag"',
    )
    calls: list[tuple[str, object]] = []

    class _Blob:
        def upload_blob(self, payload: bytes, **kwargs):
            calls.append(("index", (payload, kwargs)))
            return {"version_id": "new-index-version"}

    class _Container:
        @staticmethod
        def get_blob_client(name: str):
            assert name == FEED_V2_INDEX_BLOB_NAME
            return _Blob()

    publisher = object.__new__(AzureBlobIncidentFeedIndexPublisher)
    publisher._container = _Container()
    monkeypatch.setattr(
        AzureBlobIncidentFeedIndexPublisher,
        "_create_or_recover_attestation",
        lambda _self, _request: calls.append(("attestation", _request.attestation)),
    )
    monkeypatch.setattr(
        AzureBlobIncidentFeedIndexPublisher,
        "read_current",
        lambda _self: winner,
    )

    assert publisher.compare_and_swap(request) == winner
    assert [name for name, _value in calls] == ["attestation", "index"]
    _, (_payload, kwargs) = calls[1]
    assert kwargs["etag"] == '"expected-etag"'
    assert kwargs["match_condition"] is MatchConditions.IfNotModified


def test_azure_publisher_never_exposes_index_if_attestation_upload_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _record(1, lifecycle="active")
    source = _source(_active_index((active.entry,)))
    winner = _candidate_snapshot(source=source, records=(active,))
    request = IncidentFeedIndexCommitRequest(
        index=winner.index,
        attestation=winner.attestation,
        expected_etag=None,
    )

    class _Container:
        @staticmethod
        def get_blob_client(_name: str):
            raise AssertionError("stable index must not be opened before attestation succeeds")

    publisher = object.__new__(AzureBlobIncidentFeedIndexPublisher)
    publisher._container = _Container()
    monkeypatch.setattr(
        AzureBlobIncidentFeedIndexPublisher,
        "_create_or_recover_attestation",
        lambda _self, _request: (_ for _ in ()).throw(
            RuntimeError("synthetic attestation failure")
        ),
    )

    with pytest.raises(RuntimeError, match="attestation failure"):
        publisher.compare_and_swap(request)
