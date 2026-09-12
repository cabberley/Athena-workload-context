from __future__ import annotations

import re
from collections.abc import Callable, Sequence
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
    UtcDateTime,
    compute_artifact_digest,
    sha256_hex,
    validate_incident_enrichment_feed_pointer_assets,
)

FEED_V2_RESOLVED_RETENTION = timedelta(days=7)
MAX_FEED_V2_REGISTRY_RECORD_BYTES = 32 * 1024
MAX_FEED_V2_REGISTRY_RECORDS = 4096
MAX_FEED_V2_VISIBLE_RESOLVED = 64


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


@dataclass(frozen=True, slots=True)
class IncidentFeedRegistryProjection:
    active: tuple[IncidentFeedEntryV2, ...]
    recently_resolved: tuple[IncidentFeedEntryV2, ...]
    resolved_retention_start: UtcDateTime
    resolved_history_truncated: bool
    resolved_history_total_count: int
    omitted_resolved_count: int | None


def project_incident_feed_registry(
    records: Sequence[IncidentFeedRegistryRecord],
    *,
    source_active_index: ActiveIncidentIndex,
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
            or record.pointer.source_pointer_reference.content_digest
            != source.pointer_sha256
        ):
            raise IncidentFeedRegistryIncompleteError(
                "prepared active entry does not match lifecycle authority"
            )
        active_entries.append(record.entry)

    retention_start = as_of - FEED_V2_RESOLVED_RETENTION
    retained_resolved = [
        record.entry
        for record in parsed
        if (
            record.entry.lifecycle == "resolved"
            and record.entry.incident_id not in active_ids
            and record.retained_until is not None
            and record.retained_until > as_of
            and record.entry.updated_at >= retention_start
        )
    ]
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
    )


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
