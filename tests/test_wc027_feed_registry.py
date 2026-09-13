from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from azure.core.exceptions import ResourceNotFoundError, ServiceResponseError
from pydantic import ValidationError

from athena_context.contracts import (
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedAttestation,
    IncidentFeedEntryV2,
    IncidentFeedPointer,
    IncidentFinding,
    IncidentState,
    IncidentStateAttestation,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    build_incident_occurrence_receipt,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.enrichment import (
    FEED_V2_RESOLVED_RETENTION,
    AzureTableIncidentFeedRegistry,
    IncidentFeedRegistryCapacityError,
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryError,
    IncidentFeedRegistryIncompleteError,
    IncidentFeedRegistryRecord,
    build_incident_feed_registry_record,
    feed_registry_azure,
    project_incident_feed_registry,
)
from athena_context.presentation_assets import CurrentIncidentStateSnapshot
from test_wc026_correlation_contract import NOW
from test_wc027_incident_enrichment_contract import _json_value

_VERSION = "v" * 64
_SIGNATURE = "c3ludGhldGlj"
_KEY_ID = "https://synthetic-wc027.vault.azure.net/keys/feed-v2/0123456789abcdef0123456789abcdef"
_INCIDENT_KEY_ID = (
    "https://synthetic-wc027.vault.azure.net/keys/incident/0123456789abcdef0123456789abcdef"
)
_KEY_FINGERPRINT = "sha256:" + "4" * 64


def _pointer_bundle(
    index: int,
    *,
    lifecycle: str,
    updated_at=NOW,
) -> tuple[
    IncidentFeedEntryV2,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    CurrentIncidentStateSnapshot,
]:
    incident_id = f"inc-{index:012x}"
    detected_at = updated_at - timedelta(minutes=1)
    finding = IncidentFinding(
        clauseId="synthetic.wc027.registry",
        verdict="fail" if lifecycle == "active" else "resolved",
        summary="Synthetic registry lifecycle evidence.",
        evidenceRefs=("synthetic-registry-evidence",),
    )
    unsigned_state: dict[str, object] = {
        "schemaVersion": "athena.incidentState.v1",
        "incidentId": incident_id,
        "transitionId": (
            "wc016-"
            + sha256_hex(f"{index}:{updated_at.isoformat()}:{lifecycle}".encode()).removeprefix(
                "sha256:"
            )
        ),
        "scenario": "webServerFailure",
        "lifecycle": lifecycle,
        "workloadRole": "web",
        "detectedAt": detected_at,
        "updatedAt": updated_at,
        "targetBinding": "sha256:" + "9" * 64,
        "availability": "warning" if lifecycle == "active" else "normal",
        "blastRadius": "web-tier" if lifecycle == "active" else "none",
        "operatorAttention": "required" if lifecycle == "active" else "normal",
        "findings": [finding.model_dump(mode="json", by_alias=True, exclude_none=True)],
        "reasoning": ["Synthetic registry lifecycle assessment."],
        "notificationStatus": "pendingDispatch",
        "noAutoRemediation": True,
    }
    state_digest = sha256_hex(canonicalize_json(unsigned_state).encode())
    state = IncidentState(
        **{
            **unsigned_state,
            "findings": (finding,),
            "reasoning": ("Synthetic registry lifecycle assessment.",),
        },
        resultDigest=state_digest,
    )
    state_attestation = IncidentStateAttestation(
        schemaVersion="athena.incidentStateAttestation.v1",
        resultDigest=state_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_INCIDENT_KEY_ID,
        detachedSignature=_SIGNATURE,
    )
    state_prefix = f"incidents/{incident_id}/versions/{state_digest.removeprefix('sha256:')}"
    state_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/state.json",
        version=_VERSION,
        contentDigest=sha256_hex(state.canonical_bytes()),
    )
    state_attestation_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/attestation.json",
        version=_VERSION,
        contentDigest=sha256_hex(state_attestation.canonical_bytes()),
    )
    source_pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId=incident_id,
        statePath=f"./{state_reference.name}",
        stateSha256=state_reference.content_digest,
        attestationPath=f"./{state_attestation_reference.name}",
        attestationSha256=state_attestation_reference.content_digest,
        pointerAttestationPath=f"./{state_prefix}/pointer-attestation.json",
        keyId=_INCIDENT_KEY_ID,
        keyFingerprint=_KEY_FINGERPRINT,
        publishedAt=max(updated_at, NOW),
    )
    source_pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(source_pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=_INCIDENT_KEY_ID,
        detachedSignature=_SIGNATURE,
    )
    occurrence = build_incident_occurrence_receipt(
        state,
        state_attestation,
        source_pointer,
        source_pointer_attestation,
        state_reference=state_reference,
        state_attestation_reference=state_attestation_reference,
        pointer_reference=VersionPinnedBlobReference(
            name=f"{state_prefix}/pointer.json",
            version=_VERSION,
            contentDigest=sha256_hex(source_pointer.canonical_bytes()),
        ),
        pointer_attestation_reference=VersionPinnedBlobReference(
            name=f"{state_prefix}/pointer-attestation.json",
            version=_VERSION,
            contentDigest=sha256_hex(source_pointer_attestation.canonical_bytes()),
        ),
    )
    enrichment_id = "incident-enrichment-" + f"{index + 1:032x}"
    enrichment_prefix = f"{state_prefix}/enrichments/{enrichment_id}"
    enrichment_payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentEnrichmentAssetReference.v1"),
        "incidentId": incident_id,
        "incidentStateResultDigest": state_digest,
        "enrichmentId": enrichment_id,
        "manifestDigest": "sha256:" + f"{index + 2:064x}",
        "manifestReference": VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/manifest.json",
            version=_VERSION,
            contentDigest="sha256:" + f"{index + 3:064x}",
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/attestation.json",
            version=_VERSION,
            contentDigest="sha256:" + f"{index + 4:064x}",
        ),
    }
    enrichment_digest = compute_artifact_digest(_json_value(enrichment_payload))
    enrichment = IncidentEnrichmentAssetReference(
        **enrichment_payload,
        referenceId=(f"enrichment-asset-{enrichment_digest.removeprefix('sha256:')[:32]}"),
        referenceDigest=enrichment_digest,
    )
    pointer = build_incident_enrichment_feed_pointer(
        occurrence,
        enrichment,
        state,
        published_at=max(updated_at, NOW),
    )
    pointer_attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
        pointerId=pointer.pointer_id,
        pointerDigest=pointer.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_KEY_ID,
        signedPreimageDigest=sha256_hex(pointer.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    entry = IncidentFeedEntryV2(
        incidentId=incident_id,
        lifecycle=lifecycle,
        stateResultDigest=state_digest,
        updatedAt=updated_at,
        feedPointerReference=VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/feed-pointer.json",
            version=_VERSION,
            contentDigest=sha256_hex(pointer.canonical_bytes()),
        ),
        feedPointerAttestationReference=VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/feed-pointer-attestation.json",
            version=_VERSION,
            contentDigest=sha256_hex(pointer_attestation.canonical_bytes()),
        ),
    )
    authority = CurrentIncidentStateSnapshot(
        state=state,
        pointer=source_pointer,
        pointer_sha256=sha256_hex(source_pointer.canonical_bytes()),
        occurrence=occurrence,
    )
    return entry, pointer, pointer_attestation, authority


def _record(
    index: int,
    *,
    lifecycle: str,
    updated_at=NOW,
) -> IncidentFeedRegistryRecord:
    entry, pointer, attestation, _authority = _pointer_bundle(
        index,
        lifecycle=lifecycle,
        updated_at=updated_at,
    )
    return build_incident_feed_registry_record(
        entry,
        pointer,
        attestation,
    )


def _authority(
    index: int,
    *,
    lifecycle: str,
    updated_at=NOW,
) -> CurrentIncidentStateSnapshot:
    return _pointer_bundle(
        index,
        lifecycle=lifecycle,
        updated_at=updated_at,
    )[3]


def _active_index(
    entries: tuple[IncidentFeedEntryV2, ...],
) -> ActiveIncidentIndex:
    return ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=tuple(
            ActiveIncidentEntry(
                incidentId=entry.incident_id,
                scenario="webServerFailure",
                lifecycle="active",
                workloadRole="web",
                pointerPath=(
                    f"./incidents/{entry.incident_id}/versions/"
                    f"{entry.state_result_digest.removeprefix('sha256:')}/"
                    "pointer.json"
                ),
                pointerSha256=(
                    _record(
                        int(entry.incident_id.removeprefix("inc-"), 16),
                        lifecycle="active",
                        updated_at=entry.updated_at,
                    ).pointer.source_pointer_reference.content_digest
                ),
                detectedAt=entry.updated_at - timedelta(minutes=1),
                updatedAt=entry.updated_at,
            )
            for entry in entries
        ),
        indexAttestationPath=("./incidents/index-attestations/" + "a" * 64 + ".json"),
        keyId=_KEY_ID,
        keyFingerprint=_KEY_FINGERPRINT,
        publishedAt=NOW + timedelta(minutes=1),
    )


def _verify(_preimage: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


def test_registry_record_binds_pointer_retention_and_digest() -> None:
    active = _record(1, lifecycle="active")
    resolved = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=1),
    )

    assert active.retained_until is None
    assert resolved.retained_until == (resolved.entry.updated_at + FEED_V2_RESOLVED_RETENTION)
    assert (
        IncidentFeedRegistryRecord.model_validate_json(resolved.model_dump_json(by_alias=True))
        == resolved
    )

    payload = resolved.model_dump(
        mode="python",
        by_alias=True,
    )
    payload["retainedUntil"] = NOW + timedelta(days=30)
    with pytest.raises(ValidationError, match="retention"):
        IncidentFeedRegistryRecord.model_validate(payload)


def test_projection_requires_every_v1_active_incident() -> None:
    active = _record(1, lifecycle="active")

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="missing",
    ):
        project_incident_feed_registry(
            (),
            source_active_index=_active_index((active.entry,)),
            source_current_incidents={},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_registry_rejects_non_millisecond_as_of() -> None:
    active = _record(1, lifecycle="active")
    non_canonical_as_of = NOW.replace(microsecond=1)

    with pytest.raises(ValueError, match="millisecond precision"):
        project_incident_feed_registry(
            (active,),
            source_active_index=_active_index((active.entry,)),
            source_current_incidents={active.entry.incident_id: _authority(1, lifecycle="active")},
            as_of=non_canonical_as_of,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )

    registry = _azure_registry(_Table())
    with pytest.raises(ValueError, match="millisecond precision"):
        registry.list_records(as_of=non_canonical_as_of)


def test_projection_rejects_stale_or_orphaned_active_records() -> None:
    active = _record(1, lifecycle="active")
    stale = _record(
        1,
        lifecycle="active",
        updated_at=active.entry.updated_at - timedelta(seconds=1),
    )
    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="does not match",
    ):
        project_incident_feed_registry(
            (stale,),
            source_active_index=_active_index((active.entry,)),
            source_current_incidents={active.entry.incident_id: _authority(1, lifecycle="active")},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="resolved successor",
    ):
        project_incident_feed_registry(
            (active,),
            source_active_index=_active_index(()),
            source_current_incidents={active.entry.incident_id: _authority(1, lifecycle="active")},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_rejects_active_pointer_digest_not_authorized_by_v1() -> None:
    active = _record(1, lifecycle="active")
    source = _active_index((active.entry,))
    mismatched_source = source.model_copy(
        update={
            "incidents": (
                source.incidents[0].model_copy(update={"pointer_sha256": "sha256:" + "f" * 64}),
            )
        }
    )

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="does not match",
    ):
        project_incident_feed_registry(
            (active,),
            source_active_index=mismatched_source,
            source_current_incidents={active.entry.incident_id: _authority(1, lifecycle="active")},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_rejects_unsigned_resolved_registry_record() -> None:
    entry, pointer, attestation, authority = _pointer_bundle(
        2,
        lifecycle="resolved",
    )
    tampered_attestation = attestation.model_copy(update={"detached_signature": "AAAA"})
    tampered_entry = entry.model_copy(
        update={
            "feed_pointer_attestation_reference": (
                entry.feed_pointer_attestation_reference.model_copy(
                    update={"content_digest": sha256_hex(tampered_attestation.canonical_bytes())}
                )
            )
        }
    )
    tampered = build_incident_feed_registry_record(
        tampered_entry,
        pointer,
        tampered_attestation,
    )

    with pytest.raises(ValueError, match="pointer assets"):
        project_incident_feed_registry(
            (tampered,),
            source_active_index=_active_index(()),
            source_current_incidents={entry.incident_id: authority},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_rejects_replayed_older_resolved_occurrence() -> None:
    replayed = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=2),
    )
    latest = _authority(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=1),
    )

    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="authoritative current occurrence",
    ):
        project_incident_feed_registry(
            (replayed,),
            source_active_index=_active_index(()),
            source_current_incidents={replayed.entry.incident_id: latest},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_rejects_expired_replay_instead_of_silently_omitting_it() -> None:
    replayed = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=8),
    )
    latest = _authority(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=1),
    )

    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="authoritative current occurrence",
    ):
        project_incident_feed_registry(
            (replayed,),
            source_active_index=_active_index(()),
            source_current_incidents={replayed.entry.incident_id: latest},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_fails_closed_without_current_occurrence_authority() -> None:
    resolved = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=1),
    )

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="authoritative current occurrence",
    ):
        project_incident_feed_registry(
            (resolved,),
            source_active_index=_active_index(()),
            source_current_incidents={},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_fails_closed_on_corrupt_current_occurrence_authority() -> None:
    resolved = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=1),
    )
    authority = _authority(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(hours=1),
    )
    occurrence = authority.occurrence
    assert occurrence is not None
    corrupt = CurrentIncidentStateSnapshot(
        state=authority.state,
        pointer=authority.pointer,
        pointer_sha256=authority.pointer_sha256,
        occurrence=occurrence.model_copy(update={"occurrence_digest": "sha256:" + "f" * 64}),
    )

    with pytest.raises(
        IncidentFeedRegistryIncompleteError,
        match="authority is invalid",
    ):
        project_incident_feed_registry(
            (resolved,),
            source_active_index=_active_index(()),
            source_current_incidents={resolved.entry.incident_id: corrupt},
            as_of=NOW,
            trusted_feed_key_id=_KEY_ID,
            feed_signature_verifier=_verify,
        )


def test_projection_keeps_exact_bounded_resolved_history() -> None:
    active = _record(1, lifecycle="active")
    resolved = tuple(
        _record(
            index,
            lifecycle="resolved",
            updated_at=NOW - timedelta(minutes=index),
        )
        for index in range(2, 68)
    )
    expired = _record(
        100,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=8),
    )

    projected = project_incident_feed_registry(
        (
            active,
            *resolved,
            expired,
        ),
        source_active_index=_active_index((active.entry,)),
        source_current_incidents={
            active.entry.incident_id: _authority(1, lifecycle="active"),
            **{
                record.entry.incident_id: _authority(
                    int(record.entry.incident_id.removeprefix("inc-"), 16),
                    lifecycle="resolved",
                    updated_at=record.entry.updated_at,
                )
                for record in resolved
            },
            expired.entry.incident_id: _authority(
                100,
                lifecycle="resolved",
                updated_at=expired.entry.updated_at,
            ),
        },
        as_of=NOW,
        trusted_feed_key_id=_KEY_ID,
        feed_signature_verifier=_verify,
    )

    assert projected.active == (active.entry,)
    assert len(projected.recently_resolved) == 64
    assert projected.resolved_history_total_count == 66
    assert projected.omitted_resolved_count == 2
    assert projected.resolved_history_truncated is True
    assert projected.resolved_retention_start == min(
        entry.updated_at for entry in projected.recently_resolved
    )


class _Entity(dict[str, object]):
    def __init__(self, value: dict[str, object], *, etag: str) -> None:
        super().__init__(value)
        self.metadata = {"etag": etag}


class _Table:
    def __init__(self) -> None:
        self.entities: dict[str, _Entity] = {}
        self.update_count = 0
        self.delete_count = 0
        self.transaction_count = 0
        self.before_submit = None
        self._next_etag = 1

    def _etag(self) -> str:
        value = f"etag-{self._next_etag}"
        self._next_etag += 1
        return value

    def get_entity(
        self,
        _partition_key: str,
        row_key: str,
    ) -> _Entity:
        try:
            return self.entities[row_key]
        except KeyError as exc:
            raise ResourceNotFoundError("synthetic missing") from exc

    def create_entity(self, entity: dict[str, object]) -> None:
        row_key = str(entity["RowKey"])
        if row_key in self.entities:
            from azure.core.exceptions import ResourceExistsError

            raise ResourceExistsError("synthetic duplicate")
        self.entities[row_key] = _Entity(
            entity,
            etag=self._etag(),
        )

    def update_entity(
        self,
        entity: dict[str, object],
        *,
        mode: object,
        etag: str,
        match_condition: object,
    ) -> None:
        assert mode is not None
        assert match_condition is not None
        row_key = str(entity["RowKey"])
        assert self.entities[row_key].metadata["etag"] == etag
        self.update_count += 1
        self.entities[row_key] = _Entity(
            entity,
            etag=self._etag(),
        )

    def delete_entity(
        self,
        _partition_key: str,
        row_key: str,
        *,
        etag: str,
        match_condition: object,
    ) -> None:
        assert self.entities[row_key].metadata["etag"] == etag
        assert match_condition is not None
        self.delete_count += 1
        del self.entities[row_key]

    def submit_transaction(self, operations) -> None:
        if self.before_submit is not None:
            callback = self.before_submit
            self.before_submit = None
            callback()
        candidate = {
            row_key: _Entity(dict(entity), etag=str(entity.metadata["etag"]))
            for row_key, entity in self.entities.items()
        }
        deleted_count = 0
        for operation in operations:
            action, entity, *options = operation
            row_key = str(entity["RowKey"])
            if action == "create":
                if row_key in candidate:
                    from azure.core.exceptions import ResourceExistsError

                    raise ResourceExistsError("synthetic duplicate")
                candidate[row_key] = _Entity(dict(entity), etag=self._etag())
            elif action == "update":
                current = candidate.get(row_key)
                if current is None or not options or current.metadata["etag"] != options[0]["etag"]:
                    from azure.core.exceptions import ResourceModifiedError

                    raise ResourceModifiedError("synthetic stale update")
                candidate[row_key] = _Entity(dict(entity), etag=self._etag())
            elif action == "delete":
                current = candidate.get(row_key)
                if current is None or not options or current.metadata["etag"] != options[0]["etag"]:
                    from azure.core.exceptions import ResourceModifiedError

                    raise ResourceModifiedError("synthetic stale delete")
                del candidate[row_key]
                deleted_count += 1
            else:
                raise AssertionError(f"unsupported synthetic action {action}")
        self.entities = candidate
        self.delete_count += deleted_count
        self.transaction_count += 1

    def query_entities(
        self,
        *,
        query_filter: str,
        results_per_page: int,
    ):
        assert query_filter == "PartitionKey eq 'feed-v2'"
        assert results_per_page > 1
        return tuple(self.entities.values())


def _azure_registry(table: _Table) -> AzureTableIncidentFeedRegistry:
    registry = object.__new__(AzureTableIncidentFeedRegistry)
    registry._table = table
    registry._partition_key = "feed-v2"
    return registry


def test_azure_registry_is_idempotent_and_rejects_stale_updates() -> None:
    table = _Table()
    registry = _azure_registry(table)
    active = _record(1, lifecycle="active")
    resolved = _record(
        1,
        lifecycle="resolved",
        updated_at=NOW + timedelta(minutes=1),
    )

    registry.put(active)
    registry.put(active)
    registry.put(resolved)

    assert registry.list_records(as_of=NOW) == (resolved,)
    assert table.update_count == 1
    assert table.transaction_count == 1
    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="stale",
    ):
        registry.put(active)


def test_azure_registry_surfaces_uncertain_response_as_domain_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = _Table()
    registry = _azure_registry(table)
    active = _record(1, lifecycle="active")
    submit = table.submit_transaction

    def submit_then_lose_response(operations) -> None:
        submit(operations)
        raise ServiceResponseError("synthetic response loss")

    monkeypatch.setattr(table, "submit_transaction", submit_then_lose_response)

    with pytest.raises(
        IncidentFeedRegistryError,
        match="outcome is uncertain",
    ):
        registry.put(active)

    assert registry.list_records(as_of=NOW) == (active,)


def test_azure_registry_prunes_expired_rows() -> None:
    table = _Table()
    registry = _azure_registry(table)
    expired = _record(
        2,
        lifecycle="resolved",
        updated_at=NOW - timedelta(days=8),
    )
    table.entities[expired.entry.incident_id] = _Entity(
        registry._entity(expired),
        etag="expired-etag",
    )

    records = registry.list_records(as_of=NOW)
    assert records == (expired,)
    with pytest.raises(TypeError, match="verified"):
        registry.prune_expired(records)  # type: ignore[arg-type]
    assert registry.list_records(as_of=NOW) == (expired,)
    projection = project_incident_feed_registry(
        records,
        source_active_index=_active_index(()),
        source_current_incidents={
            expired.entry.incident_id: _authority(
                2,
                lifecycle="resolved",
                updated_at=expired.entry.updated_at,
            )
        },
        as_of=NOW,
        trusted_feed_key_id=_KEY_ID,
        feed_signature_verifier=_verify,
    )
    with pytest.raises(TypeError, match="dataclass"):
        replace(projection.prune_plan, records=())
    registry.prune_expired(projection.prune_plan)

    assert registry.list_records(as_of=NOW) == ()
    assert table.delete_count == 1
    assert table.entities["__feed_v2_capacity__"]["retainedCount"] == 0


def test_azure_registry_rejects_corrupt_entity_metadata() -> None:
    table = _Table()
    registry = _azure_registry(table)
    record = _record(1, lifecycle="active")
    registry.put(record)
    table.entities[record.entry.incident_id]["recordDigest"] = "sha256:" + "f" * 64

    with pytest.raises(RuntimeError, match="metadata"):
        registry.list_records(as_of=NOW)


def test_azure_registry_reserves_capacity_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        feed_registry_azure,
        "MAX_FEED_V2_REGISTRY_RECORDS",
        2,
    )
    table = _Table()
    first = _azure_registry(table)
    second = _azure_registry(table)
    first.put(_record(1, lifecycle="active"))

    table.before_submit = lambda: second.put(_record(2, lifecycle="active"))
    with pytest.raises(
        IncidentFeedRegistryConflictError,
        match="conditional write",
    ):
        first.put(_record(3, lifecycle="active"))

    assert first.list_records(as_of=NOW) == (
        _record(1, lifecycle="active"),
        _record(2, lifecycle="active"),
    )
    assert table.entities["__feed_v2_capacity__"]["retainedCount"] == 2
    with pytest.raises(
        IncidentFeedRegistryCapacityError,
        match="cannot accept",
    ):
        first.put(_record(3, lifecycle="active"))
