from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from pydantic import ConfigDict, Field, model_validator

from athena_context.contracts import (
    ActiveIncidentIndex,
    AthenaBaseModel,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedEntryV2,
    IncidentFeedPointer,
    IncidentOccurrenceReceipt,
    IncidentState,
    UtcDateTime,
    compute_artifact_digest,
    sha256_hex,
    validate_incident_enrichment_feed_pointer_assets,
)
from athena_context.presentation_assets import CurrentIncidentStateSnapshot

FEED_V2_RESOLVED_RETENTION = timedelta(days=7)
MAX_FEED_V2_REGISTRY_RECORD_BYTES = 32 * 1024
MAX_FEED_V2_REGISTRY_RECORDS = 4096
MAX_FEED_V2_VISIBLE_RESOLVED = 64
_PRUNE_PLAN_TOKEN = object()


class IncidentFeedRegistryError(RuntimeError):
    """Base failure for the private feed-v2 reconstruction registry."""


class IncidentFeedRegistryConflictError(IncidentFeedRegistryError):
    """A stale or conflicting incident record was rejected."""


class IncidentFeedRegistryIncompleteError(IncidentFeedRegistryError):
    """The registry cannot yet produce a complete v1-active mirror."""


class IncidentFeedRegistryCapacityError(IncidentFeedRegistryError):
    """The bounded registry cannot be processed safely."""


class IncidentFeedRegistryRecord(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    schema_version: Literal["athena.incidentFeedRegistryRecord.v1"] = Field(alias="schemaVersion")
    entry: IncidentFeedEntryV2
    pointer: IncidentEnrichmentFeedPointer
    pointer_attestation: IncidentEnrichmentFeedPointerAttestation = Field(
        alias="pointerAttestation"
    )
    retained_until: UtcDateTime | None = Field(
        default=None,
        alias="retainedUntil",
    )
    record_digest: str = Field(
        alias="recordDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")

    @model_validator(mode="after")
    def validate_record(self) -> IncidentFeedRegistryRecord:
        expected_retained_until = (
            None
            if self.entry.lifecycle == "active"
            else self.entry.updated_at + FEED_V2_RESOLVED_RETENTION
        )
        if (
            self.entry.incident_id != self.pointer.incident_id
            or self.entry.lifecycle != self.pointer.lifecycle
            or self.entry.state_result_digest != self.pointer.state_result_digest
            or self.entry.updated_at != self.pointer.state_updated_at
            or self.entry.feed_pointer_reference.content_digest
            != sha256_hex(self.pointer.canonical_bytes())
            or self.entry.feed_pointer_attestation_reference.content_digest
            != sha256_hex(self.pointer_attestation.canonical_bytes())
            or self.pointer_attestation.pointer_id != self.pointer.pointer_id
            or self.pointer_attestation.pointer_digest != self.pointer.pointer_digest
        ):
            raise ValueError("feed registry record does not bind its signed pointer")
        expected_digest = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude={"record_digest"},
            )
        )
        if self.retained_until != expected_retained_until:
            raise ValueError("feed registry retention does not match entry lifecycle")
        if self.record_digest != expected_digest:
            raise ValueError("recordDigest does not bind the feed registry record")
        if len(self.canonical_bytes()) > MAX_FEED_V2_REGISTRY_RECORD_BYTES:
            raise ValueError("feed registry record exceeds its byte budget")
        return self


def build_incident_feed_registry_record(
    entry: IncidentFeedEntryV2,
    pointer: IncidentEnrichmentFeedPointer,
    pointer_attestation: IncidentEnrichmentFeedPointerAttestation,
) -> IncidentFeedRegistryRecord:
    entry = IncidentFeedEntryV2.model_validate_json(entry.model_dump_json(by_alias=True))
    pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        pointer.model_dump_json(by_alias=True)
    )
    pointer_attestation = IncidentEnrichmentFeedPointerAttestation.model_validate_json(
        pointer_attestation.model_dump_json(by_alias=True)
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.incidentFeedRegistryRecord.v1",
        "entry": entry,
        "pointer": pointer,
        "pointerAttestation": pointer_attestation,
        "retainedUntil": (
            None if entry.lifecycle == "active" else entry.updated_at + FEED_V2_RESOLVED_RETENTION
        ),
    }
    return IncidentFeedRegistryRecord.model_validate(
        {
            **payload,
            "recordDigest": compute_artifact_digest(
                {
                    key: (
                        value.model_dump(
                            mode="json",
                            by_alias=True,
                            exclude_none=True,
                        )
                        if isinstance(value, AthenaBaseModel)
                        else value
                    )
                    for key, value in payload.items()
                    if value is not None
                }
            ),
        }
    )


class IncidentFeedRegistryPort(Protocol):
    def put(self, record: IncidentFeedRegistryRecord) -> None: ...

    def list_records(
        self,
        *,
        as_of: UtcDateTime,
    ) -> tuple[IncidentFeedRegistryRecord, ...]: ...

    def prune_expired(
        self,
        plan: IncidentFeedRegistryPrunePlan,
    ) -> None: ...


class IncidentFeedRegistryPrunePlan:
    __slots__ = ("__as_of", "__records")
    __records: tuple[IncidentFeedRegistryRecord, ...]
    __as_of: UtcDateTime

    def __init__(
        self,
        records: tuple[IncidentFeedRegistryRecord, ...],
        as_of: UtcDateTime,
        *,
        _token: object,
    ) -> None:
        if _token is not _PRUNE_PLAN_TOKEN:
            raise TypeError("feed registry prune plans are created by verified projection")
        object.__setattr__(self, "_IncidentFeedRegistryPrunePlan__records", records)
        object.__setattr__(self, "_IncidentFeedRegistryPrunePlan__as_of", as_of)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("feed registry prune plans are immutable")

    def _validated_payload(
        self,
        token: object,
    ) -> tuple[tuple[IncidentFeedRegistryRecord, ...], UtcDateTime]:
        if token is not _PRUNE_PLAN_TOKEN:
            raise TypeError("feed registry prune plan access is invalid")
        return self.__records, self.__as_of


@dataclass(frozen=True, slots=True)
class IncidentFeedRegistryProjection:
    active: tuple[IncidentFeedEntryV2, ...]
    recently_resolved: tuple[IncidentFeedEntryV2, ...]
    resolved_retention_start: UtcDateTime
    resolved_history_truncated: bool
    resolved_history_total_count: int
    omitted_resolved_count: int | None
    prune_plan: IncidentFeedRegistryPrunePlan


def project_incident_feed_registry(
    records: Sequence[IncidentFeedRegistryRecord],
    *,
    source_active_index: ActiveIncidentIndex,
    source_current_incidents: Mapping[str, CurrentIncidentStateSnapshot],
    as_of: UtcDateTime,
    trusted_feed_key_id: str,
    feed_signature_verifier: Callable[[bytes, str], bool],
) -> IncidentFeedRegistryProjection:
    if (
        not isinstance(as_of, datetime)
        or as_of.tzinfo is None
        or as_of.utcoffset() != UTC.utcoffset(as_of)
        or as_of.microsecond % 1000
    ):
        raise ValueError("as_of must be a UTC timestamp with millisecond precision")
    if len(records) > MAX_FEED_V2_REGISTRY_RECORDS:
        raise IncidentFeedRegistryCapacityError("feed registry exceeds its safe record bound")
    parsed = tuple(
        IncidentFeedRegistryRecord.model_validate_json(record.model_dump_json(by_alias=True))
        for record in records
    )
    by_incident: dict[str, IncidentFeedRegistryRecord] = {}
    for parsed_record in parsed:
        validate_incident_enrichment_feed_pointer_assets(
            parsed_record.entry,
            parsed_record.pointer,
            parsed_record.pointer_attestation,
            trusted_key_id=trusted_feed_key_id,
            signature_verifier=feed_signature_verifier,
        )
        incident_id = parsed_record.entry.incident_id
        if incident_id in by_incident:
            raise IncidentFeedRegistryConflictError(
                "feed registry returned duplicate incident records"
            )
        by_incident[incident_id] = parsed_record

    active_entries: list[IncidentFeedEntryV2] = []
    active_ids = {source.incident_id for source in source_active_index.incidents}
    if any(
        record.entry.lifecycle == "active" and record.entry.incident_id not in active_ids
        for record in parsed
    ):
        raise IncidentFeedRegistryIncompleteError(
            "active registry entries require a verified resolved successor"
        )
    for source in source_active_index.incidents:
        record = by_incident.get(source.incident_id)
        if record is None or record.entry.lifecycle != "active":
            raise IncidentFeedRegistryIncompleteError(
                "feed registry is missing a prepared active incident"
            )
        expected_path = (
            rf"^\./incidents/{re.escape(source.incident_id)}/versions/"
            r"([a-f0-9]{64})/pointer\.json$"
        )
        matched = re.fullmatch(expected_path, source.pointer_path)
        if (
            matched is None
            or record.entry.state_result_digest != f"sha256:{matched.group(1)}"
            or record.entry.updated_at != source.updated_at
            or record.pointer.source_pointer_reference.content_digest != source.pointer_sha256
        ):
            raise IncidentFeedRegistryIncompleteError(
                "prepared active entry does not match lifecycle authority"
            )
        authority, occurrence = _require_current_authority(
            record,
            source_current_incidents=source_current_incidents,
        )
        if (
            source.scenario != authority.state.scenario
            or source.workload_role != authority.state.workload_role
            or source.detected_at != authority.state.detected_at
            or source.pointer_path != f"./{occurrence.pointer_reference.name}"
            or source.pointer_sha256 != occurrence.pointer_reference.content_digest
        ):
            raise IncidentFeedRegistryIncompleteError(
                "prepared active entry does not match lifecycle authority"
            )
        active_entries.append(record.entry)

    retention_start = as_of - FEED_V2_RESOLVED_RETENTION
    resolved_records = [
        record
        for record in parsed
        if record.entry.lifecycle == "resolved" and record.entry.incident_id not in active_ids
    ]
    for record in resolved_records:
        _require_current_authority(
            record,
            source_current_incidents=source_current_incidents,
        )
    retained_resolved_records = [
        record
        for record in resolved_records
        if (
            record.retained_until is not None
            and record.retained_until > as_of
            and record.entry.updated_at >= retention_start
        )
    ]
    retained_resolved = [record.entry for record in retained_resolved_records]
    retained_resolved.sort(
        key=lambda entry: (
            entry.incident_id,
            entry.state_result_digest,
        )
    )
    retained_resolved.sort(
        key=lambda entry: entry.updated_at,
        reverse=True,
    )
    resolved_total = len(retained_resolved)
    visible_resolved = tuple(retained_resolved[:MAX_FEED_V2_VISIBLE_RESOLVED])
    omitted = resolved_total - len(visible_resolved)
    prune_plan = IncidentFeedRegistryPrunePlan(
        records=tuple(
            record
            for record in resolved_records
            if record.retained_until is not None and record.retained_until <= as_of
        ),
        as_of=as_of,
        _token=_PRUNE_PLAN_TOKEN,
    )
    return IncidentFeedRegistryProjection(
        active=tuple(
            sorted(
                active_entries,
                key=lambda entry: entry.incident_id,
            )
        ),
        recently_resolved=visible_resolved,
        resolved_retention_start=(
            min(entry.updated_at for entry in visible_resolved) if omitted else retention_start
        ),
        resolved_history_truncated=omitted > 0,
        resolved_history_total_count=resolved_total,
        omitted_resolved_count=omitted or None,
        prune_plan=prune_plan,
    )


def _require_current_authority(
    record: IncidentFeedRegistryRecord,
    *,
    source_current_incidents: Mapping[str, CurrentIncidentStateSnapshot],
) -> tuple[CurrentIncidentStateSnapshot, IncidentOccurrenceReceipt]:
    authority = source_current_incidents.get(record.entry.incident_id)
    if type(authority) is not CurrentIncidentStateSnapshot or authority.occurrence is None:
        raise IncidentFeedRegistryIncompleteError(
            "feed registry is missing authoritative current occurrence"
        )
    try:
        state = IncidentState.model_validate_json(authority.state.model_dump_json(by_alias=True))
        pointer = IncidentFeedPointer.model_validate_json(
            authority.pointer.model_dump_json(by_alias=True)
        )
        occurrence = IncidentOccurrenceReceipt.model_validate_json(
            authority.occurrence.model_dump_json(by_alias=True)
        )
        authority = CurrentIncidentStateSnapshot(
            state=state,
            pointer=pointer,
            pointer_sha256=authority.pointer_sha256,
            occurrence=occurrence,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise IncidentFeedRegistryIncompleteError(
            "feed registry current occurrence authority is invalid"
        ) from exc
    if (
        occurrence.incident_id != state.incident_id
        or occurrence.transition_id != state.transition_id
        or occurrence.state_result_digest != state.result_digest
        or occurrence.state_reference.name != pointer.state_path.removeprefix("./")
        or occurrence.state_reference.content_digest != sha256_hex(state.canonical_bytes())
        or occurrence.state_attestation_reference.name
        != pointer.attestation_path.removeprefix("./")
        or occurrence.state_attestation_reference.content_digest != pointer.attestation_sha256
        or occurrence.pointer_reference.name
        != pointer.state_path.removesuffix("/state.json").removeprefix("./") + "/pointer.json"
        or occurrence.pointer_reference.content_digest != authority.pointer_sha256
        or occurrence.pointer_attestation_reference.name
        != pointer.pointer_attestation_path.removeprefix("./")
        or occurrence.published_at != pointer.published_at
    ):
        raise IncidentFeedRegistryIncompleteError(
            "feed registry current occurrence authority is invalid"
        )
    if (
        authority.state.incident_id != record.entry.incident_id
        or authority.state.lifecycle != record.entry.lifecycle
        or authority.state.result_digest != record.entry.state_result_digest
        or authority.state.updated_at != record.entry.updated_at
        or occurrence.incident_id != record.entry.incident_id
        or occurrence.state_result_digest != record.entry.state_result_digest
        or record.pointer.occurrence_digest != occurrence.occurrence_digest
        or record.pointer.source_state_reference != occurrence.state_reference
        or record.pointer.source_state_attestation_reference
        != occurrence.state_attestation_reference
        or record.pointer.source_pointer_reference != occurrence.pointer_reference
        or record.pointer.source_pointer_attestation_reference
        != occurrence.pointer_attestation_reference
    ):
        raise IncidentFeedRegistryConflictError(
            "feed registry record does not match authoritative current occurrence"
        )
    return authority, occurrence


def _validated_prune_plan(
    plan: IncidentFeedRegistryPrunePlan,
) -> tuple[tuple[IncidentFeedRegistryRecord, ...], UtcDateTime]:
    if type(plan) is not IncidentFeedRegistryPrunePlan:
        raise TypeError("plan must be a verified feed registry prune plan")
    return plan._validated_payload(_PRUNE_PLAN_TOKEN)


__all__ = [
    "FEED_V2_RESOLVED_RETENTION",
    "MAX_FEED_V2_REGISTRY_RECORD_BYTES",
    "MAX_FEED_V2_REGISTRY_RECORDS",
    "MAX_FEED_V2_VISIBLE_RESOLVED",
    "IncidentFeedRegistryCapacityError",
    "IncidentFeedRegistryConflictError",
    "IncidentFeedRegistryError",
    "IncidentFeedRegistryIncompleteError",
    "IncidentFeedRegistryPort",
    "IncidentFeedRegistryProjection",
    "IncidentFeedRegistryRecord",
    "build_incident_feed_registry_record",
    "project_incident_feed_registry",
]
