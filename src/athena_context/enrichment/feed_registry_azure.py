from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from typing import Any
from urllib.parse import urlsplit

from azure.core import MatchConditions
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.data.tables import TableServiceClient, UpdateMode
from pydantic import ValidationError

from athena_context.azure_adapters import (
    production_managed_identity_credential,
)
from athena_context.contracts import UtcDateTime
from athena_context.enrichment.feed_registry import (
    MAX_FEED_V2_REGISTRY_RECORDS,
    IncidentFeedRegistryAuthorityReaderPort,
    IncidentFeedRegistryCapacityError,
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryError,
    IncidentFeedRegistryPrunePlan,
    IncidentFeedRegistryRecord,
    _validated_prune_plan,
    validate_incident_feed_registry_record_authority,
)
from athena_context.presentation_assets import CurrentIncidentStateSnapshot

_TABLE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{2,62}$")
_TABLE_ENDPOINT = re.compile(r"^[a-z0-9]{3,24}\.table\.core\.windows\.net$")
_CAPACITY_ROW_KEY = "__feed_v2_capacity__"
_CAPACITY_SCHEMA_VERSION = "athena.incidentFeedRegistryCapacity.v1"
_MAX_TRANSACTION_OPERATIONS = 100
_MAX_EXPIRY_DELETES = _MAX_TRANSACTION_OPERATIONS - 1
_MAX_CLEANUP_PASSES = (
    (MAX_FEED_V2_REGISTRY_RECORDS + _MAX_EXPIRY_DELETES - 1) // _MAX_EXPIRY_DELETES
) + 2


@dataclass(frozen=True, slots=True)
class _RegistrySnapshot:
    capacity_entity: Mapping[str, Any]
    records: tuple[tuple[Mapping[str, Any], IncidentFeedRegistryRecord], ...]


class AzureTableIncidentFeedRegistry:
    """Persist one latest prepared feed-v2 entry per incident."""

    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        partition_key: str,
        managed_identity_client_id: str,
        current_incident_reader: IncidentFeedRegistryAuthorityReaderPort,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or _TABLE_ENDPOINT.fullmatch(parsed.hostname) is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint must be an Azure public-cloud Table HTTPS origin")
        if _TABLE_NAME.fullmatch(table_name) is None:
            raise ValueError("table_name is invalid")
        if (
            type(partition_key) is not str
            or not 1 <= len(partition_key) <= 256
            or any(character in partition_key for character in "/\\#?'")
        ):
            raise ValueError("partition_key is invalid")
        self._table = TableServiceClient(
            endpoint=endpoint,
            credential=production_managed_identity_credential(
                managed_identity_client_id=managed_identity_client_id
            ),
        ).get_table_client(table_name)
        self._partition_key = partition_key
        self._current_incident_reader = current_incident_reader

    def put(
        self,
        record: IncidentFeedRegistryRecord,
        *,
        authority: CurrentIncidentStateSnapshot,
    ) -> None:
        if type(record) is not IncidentFeedRegistryRecord:
            raise TypeError("record must be an exact IncidentFeedRegistryRecord")
        record = IncidentFeedRegistryRecord.model_validate_json(
            record.model_dump_json(by_alias=True)
        )
        expected_authority, _occurrence = (
            validate_incident_feed_registry_record_authority(
                record,
                authority,
            )
        )
        self._require_current_authority(
            record,
            expected=expected_authority,
        )
        snapshot = self._read_snapshot()
        current = next(
            (
                entity
                for entity, existing in snapshot.records
                if existing.entry.incident_id == record.entry.incident_id
            ),
            None,
        )
        if current is None and len(snapshot.records) >= MAX_FEED_V2_REGISTRY_RECORDS:
            raise IncidentFeedRegistryCapacityError(
                "feed registry cannot accept another retained incident"
            )
        if current is not None:
            existing = self._parse_entity(current)
            if existing == record:
                self._require_current_authority(
                    record,
                    expected=expected_authority,
                )
                return
            try:
                validate_incident_feed_registry_record_authority(
                    existing,
                    expected_authority,
                )
            except IncidentFeedRegistryConflictError:
                pass
            else:
                raise IncidentFeedRegistryConflictError(
                    "conflicting feed registry update has the same current authority"
                )

        entity = self._entity(record)
        try:
            self._require_current_authority(
                record,
                expected=expected_authority,
            )
            if current is None:
                capacity_etag = self._entity_etag(
                    snapshot.capacity_entity,
                    context="feed registry capacity entity",
                )
                retained_count = len(snapshot.records)
                self._table.submit_transaction(
                    [
                        ("create", entity),
                        (
                            "update",
                            self._capacity_entity(retained_count + 1),
                            {
                                "mode": UpdateMode.REPLACE,
                                "etag": capacity_etag,
                                "match_condition": MatchConditions.IfNotModified,
                            },
                        ),
                    ]
                )
            else:
                self._table.update_entity(
                    entity,
                    mode=UpdateMode.REPLACE,
                    etag=self._entity_etag(
                        current,
                        context="feed registry entity",
                    ),
                    match_condition=MatchConditions.IfNotModified,
                )
        except (ResourceExistsError, ResourceModifiedError) as exc:
            raise IncidentFeedRegistryConflictError(
                "feed registry changed during conditional write"
            ) from exc
        except HttpResponseError as exc:
            if exc.status_code in {409, 412}:
                raise IncidentFeedRegistryConflictError(
                    "feed registry changed during conditional write"
                ) from exc
            raise IncidentFeedRegistryError("feed registry write failed") from exc
        except (ServiceRequestError, ServiceResponseError) as exc:
            raise IncidentFeedRegistryError(
                "feed registry write outcome is uncertain"
            ) from exc
        self._require_current_authority(
            record,
            expected=expected_authority,
        )

    def list_records(
        self,
        *,
        as_of: UtcDateTime,
    ) -> tuple[IncidentFeedRegistryRecord, ...]:
        if (
            not isinstance(as_of, datetime)
            or as_of.tzinfo is None
            or as_of.utcoffset() != UTC.utcoffset(as_of)
            or as_of.microsecond % 1000
        ):
            raise ValueError("as_of must be a UTC timestamp with millisecond precision")
        snapshot = self._read_snapshot()
        return tuple(
            sorted(
                (record for _entity, record in snapshot.records),
                key=lambda record: record.entry.incident_id,
            )
        )

    def _require_current_authority(
        self,
        record: IncidentFeedRegistryRecord,
        *,
        expected: CurrentIncidentStateSnapshot,
    ) -> CurrentIncidentStateSnapshot:
        current = self._current_incident_reader.read_current_incident_state(
            incident_id=record.entry.incident_id
        )
        validated, _occurrence = validate_incident_feed_registry_record_authority(
            record,
            current,
        )
        if validated != expected:
            raise IncidentFeedRegistryConflictError(
                "feed registry current occurrence changed during admission"
            )
        return validated

    def prune_expired(
        self,
        plan: IncidentFeedRegistryPrunePlan,
    ) -> None:
        records, as_of = _validated_prune_plan(plan)
        if len(records) > MAX_FEED_V2_REGISTRY_RECORDS:
            raise IncidentFeedRegistryCapacityError(
                "feed registry cleanup exceeds its safe record bound"
            )
        parsed = tuple(
            IncidentFeedRegistryRecord.model_validate_json(record.model_dump_json(by_alias=True))
            for record in records
        )
        pending = {
            record.entry.incident_id: record
            for record in parsed
            if record.retained_until is not None and record.retained_until <= as_of
        }
        if len(pending) != sum(
            record.retained_until is not None and record.retained_until <= as_of
            for record in parsed
        ):
            raise IncidentFeedRegistryError(
                "feed registry cleanup received duplicate incident records"
            )
        for _ in range(_MAX_CLEANUP_PASSES):
            snapshot = self._read_snapshot()
            current = {
                record.entry.incident_id: (entity, record) for entity, record in snapshot.records
            }
            for incident_id, expected in tuple(pending.items()):
                actual = current.get(incident_id)
                if actual is None:
                    del pending[incident_id]
                elif actual[1] != expected:
                    raise IncidentFeedRegistryConflictError(
                        "feed registry changed after expiry authority validation"
                    )
            if not pending:
                return
            expired = tuple(
                current[incident_id] for incident_id in sorted(pending)[:_MAX_EXPIRY_DELETES]
            )
            try:
                self._delete_expired_batch(
                    snapshot,
                    expired,
                )
            except IncidentFeedRegistryConflictError:
                continue
            for _entity, record in expired:
                del pending[record.entry.incident_id]
        raise IncidentFeedRegistryCapacityError(
            "feed registry expiry cleanup exceeded its safe pass bound"
        )

    def _read_snapshot(self) -> _RegistrySnapshot:
        for _ in range(3):
            entities = self._read_bounded_partition()
            capacity_entities = tuple(
                entity for entity in entities if entity.get("RowKey") == _CAPACITY_ROW_KEY
            )
            record_entities = tuple(
                entity for entity in entities if entity.get("RowKey") != _CAPACITY_ROW_KEY
            )
            if not capacity_entities:
                self._initialize_capacity_metadata(len(record_entities))
                continue
            if len(capacity_entities) != 1:
                raise IncidentFeedRegistryError(
                    "feed registry returned duplicate capacity metadata"
                )
            if len(record_entities) > MAX_FEED_V2_REGISTRY_RECORDS:
                raise IncidentFeedRegistryCapacityError(
                    "feed registry exceeds its safe retained record bound"
                )
            parsed = tuple((entity, self._parse_entity(entity)) for entity in record_entities)
            incident_ids = tuple(record.entry.incident_id for _entity, record in parsed)
            if len(incident_ids) != len(set(incident_ids)):
                raise IncidentFeedRegistryError("feed registry returned duplicate incident records")
            retained_count = self._parse_capacity_entity(capacity_entities[0])
            if retained_count != len(parsed):
                raise IncidentFeedRegistryError(
                    "feed registry capacity metadata does not match retained records"
                )
            return _RegistrySnapshot(
                capacity_entity=capacity_entities[0],
                records=parsed,
            )
        raise IncidentFeedRegistryConflictError(
            "feed registry capacity metadata changed during initialization"
        )

    def _read_bounded_partition(
        self,
    ) -> tuple[Mapping[str, Any], ...]:
        try:
            return tuple(
                islice(
                    self._table.query_entities(
                        query_filter=(f"PartitionKey eq '{self._partition_key}'"),
                        results_per_page=(MAX_FEED_V2_REGISTRY_RECORDS + 2),
                    ),
                    MAX_FEED_V2_REGISTRY_RECORDS + 2,
                )
            )
        except HttpResponseError as exc:
            raise IncidentFeedRegistryError("feed registry partition read failed") from exc

    def _initialize_capacity_metadata(
        self,
        retained_count: int,
    ) -> None:
        if retained_count > MAX_FEED_V2_REGISTRY_RECORDS:
            raise IncidentFeedRegistryCapacityError(
                "feed registry exceeds its safe retained record bound"
            )
        try:
            self._table.create_entity(self._capacity_entity(retained_count))
        except ResourceExistsError:
            return
        except HttpResponseError as exc:
            if exc.status_code == 409:
                return
            raise IncidentFeedRegistryError("feed registry capacity initialization failed") from exc

    def _delete_expired_batch(
        self,
        snapshot: _RegistrySnapshot,
        expired: tuple[
            tuple[Mapping[str, Any], IncidentFeedRegistryRecord],
            ...,
        ],
    ) -> None:
        retained_count = len(snapshot.records)
        capacity_etag = self._entity_etag(
            snapshot.capacity_entity,
            context="feed registry capacity entity",
        )
        operations: list[
            tuple[str, Mapping[str, object]]
            | tuple[str, Mapping[str, object], Mapping[str, object]]
        ] = []
        for entity, _record in expired:
            row_key = entity.get("RowKey")
            if not isinstance(row_key, str):
                raise IncidentFeedRegistryError(
                    "expired feed registry entity has an invalid identity"
                )
            operations.append(
                (
                    "delete",
                    {
                        "PartitionKey": self._partition_key,
                        "RowKey": row_key,
                    },
                    {
                        "etag": self._entity_etag(
                            entity,
                            context="expired feed registry entity",
                        ),
                        "match_condition": MatchConditions.IfNotModified,
                    },
                )
            )
        operations.append(
            (
                "update",
                self._capacity_entity(retained_count - len(expired)),
                {
                    "mode": UpdateMode.REPLACE,
                    "etag": capacity_etag,
                    "match_condition": MatchConditions.IfNotModified,
                },
            )
        )
        try:
            self._table.submit_transaction(operations)
        except (ResourceNotFoundError, ResourceModifiedError) as exc:
            raise IncidentFeedRegistryConflictError(
                "feed registry expiry changed during cleanup"
            ) from exc
        except HttpResponseError as exc:
            if exc.status_code in {404, 409, 412}:
                raise IncidentFeedRegistryConflictError(
                    "feed registry expiry changed during cleanup"
                ) from exc
            raise IncidentFeedRegistryError("feed registry expiry cleanup failed") from exc

    def _capacity_entity(
        self,
        retained_count: int,
    ) -> dict[str, object]:
        return {
            "PartitionKey": self._partition_key,
            "RowKey": _CAPACITY_ROW_KEY,
            "schemaVersion": _CAPACITY_SCHEMA_VERSION,
            "kind": "capacity",
            "capacityLimit": MAX_FEED_V2_REGISTRY_RECORDS,
            "retainedCount": retained_count,
        }

    def _parse_capacity_entity(
        self,
        entity: Mapping[str, Any],
    ) -> int:
        retained_count = entity.get("retainedCount")
        if (
            entity.get("PartitionKey") != self._partition_key
            or entity.get("RowKey") != _CAPACITY_ROW_KEY
            or entity.get("schemaVersion") != _CAPACITY_SCHEMA_VERSION
            or entity.get("kind") != "capacity"
            or entity.get("capacityLimit") != MAX_FEED_V2_REGISTRY_RECORDS
            or type(retained_count) is not int
            or not 0 <= retained_count <= MAX_FEED_V2_REGISTRY_RECORDS
        ):
            raise IncidentFeedRegistryError("feed registry returned invalid capacity metadata")
        self._entity_etag(
            entity,
            context="feed registry capacity entity",
        )
        return retained_count

    @staticmethod
    def _entity_etag(
        entity: Mapping[str, Any],
        *,
        context: str,
    ) -> str:
        metadata = getattr(entity, "metadata", None)
        etag = metadata.get("etag") if isinstance(metadata, Mapping) else None
        if not isinstance(etag, str) or not etag:
            raise IncidentFeedRegistryError(f"{context} omitted its concurrency token")
        return etag

    def _entity(
        self,
        record: IncidentFeedRegistryRecord,
    ) -> dict[str, object]:
        return {
            "PartitionKey": self._partition_key,
            "RowKey": record.entry.incident_id,
            "schemaVersion": record.schema_version,
            "lifecycle": record.entry.lifecycle,
            "updatedAt": record.entry.updated_at.isoformat(),
            "retainedUntil": (
                None if record.retained_until is None else record.retained_until.isoformat()
            ),
            "recordDigest": record.record_digest,
            "recordJson": record.canonical_bytes().decode("utf-8"),
        }

    def _parse_entity(
        self,
        entity: Mapping[str, Any],
    ) -> IncidentFeedRegistryRecord:
        if (
            entity.get("PartitionKey") != self._partition_key
            or not isinstance(entity.get("RowKey"), str)
            or not isinstance(entity.get("recordJson"), str)
        ):
            raise IncidentFeedRegistryError("feed registry returned an invalid entity identity")
        try:
            record = IncidentFeedRegistryRecord.model_validate_json(entity["recordJson"])
        except (ValidationError, ValueError) as exc:
            raise IncidentFeedRegistryError("feed registry returned an invalid record") from exc
        expected_retained = (
            None if record.retained_until is None else record.retained_until.isoformat()
        )
        if (
            entity["RowKey"] != record.entry.incident_id
            or entity.get("schemaVersion") != record.schema_version
            or entity.get("lifecycle") != record.entry.lifecycle
            or entity.get("updatedAt") != record.entry.updated_at.isoformat()
            or entity.get("retainedUntil") != expected_retained
            or entity.get("recordDigest") != record.record_digest
        ):
            raise IncidentFeedRegistryError(
                "feed registry entity metadata does not match its record"
            )
        return record


__all__ = ["AzureTableIncidentFeedRegistry"]
