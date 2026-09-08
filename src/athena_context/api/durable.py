from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from itertools import islice
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

from azure.core import MatchConditions
from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceModifiedError
from azure.data.tables import TableServiceClient, UpdateMode
from pydantic import BaseModel, ValidationError

from athena_context.api.audit import audit_event_digest, verify_audit_chain
from athena_context.api.cohort_decision_domain import (
    CohortDecisionReceipt,
    CohortDecisionRecord,
    CohortProposalSetVersion,
    rejection_authorities_overlap,
)
from athena_context.api.domain import (
    AuditEvent,
    DraftRecord,
    DraftState,
    MutationReceipt,
    PendingAuditEvent,
    PublishedManifest,
    Supersession,
    WorkloadGrantScope,
)
from athena_context.api.errors import (
    AlreadySupersededError,
    AuthorizationError,
    DuplicateDraftError,
    DuplicateVersionError,
    IdempotencyConflictError,
    PersistenceConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.ports import ContextTransactionPort
from athena_context.api.selector_provenance import DraftSelectorBaseline
from athena_context.api.transaction_lock import InMemoryTransactionLock
from athena_context.azure_adapters import production_managed_identity_credential
from athena_context.contracts import compute_artifact_digest

_CONTEXT_STORE_SCHEMA = "athena.context-store.v1"
_CONTEXT_STORE_ANCHOR_SCHEMA = "athena.context-store-anchor.v1"
_CONTEXT_STATE_ROW_KEY = "meta:state"
_MAX_RECORD_BYTES = 60 * 1024
_MAX_PARTITION_ENTITIES = 4_096
_CAPACITY_WARNING_ENTITY_COUNT = 3_584
_PARTITION_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TABLE_ACCOUNT_PATTERN = re.compile(r"^[a-z0-9]{3,24}\.table\.core\.windows\.net$")
_LOGGER = logging.getLogger(__name__)

type _TableOperation = (
    tuple[str, Mapping[str, Any]]
    | tuple[str, Mapping[str, Any], Mapping[str, Any]]
)


def _validate_configuration(
    *,
    endpoint: str,
    table_name: str,
    partition_key: str,
    managed_identity_client_id: str,
    workload_id: str,
) -> None:
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("context store endpoint is invalid") from exc
    if (
        type(endpoint) is not str
        or parsed.scheme != "https"
        or parsed.hostname is None
        or _TABLE_ACCOUNT_PATTERN.fullmatch(parsed.hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("context store endpoint must be an Azure Table HTTPS origin")
    if not (
        type(table_name) is str
        and table_name.isalnum()
        and 3 <= len(table_name) <= 63
    ):
        raise ValueError("context store table name is invalid")
    if (
        type(partition_key) is not str
        or _PARTITION_KEY_PATTERN.fullmatch(partition_key) is None
    ):
        raise ValueError("context store partition key is invalid")
    if type(managed_identity_client_id) is not str or not managed_identity_client_id:
        raise ValueError("context store managed identity client ID is invalid")
    try:
        WorkloadGrantScope(workload_id=workload_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("context store workload ID is invalid") from exc


def _row_key_for_draft(draft: DraftRecord) -> str:
    return _row_key_for_components("draft", draft.draft_id)


def _row_key_for_draft_selector_baseline(
    baseline: DraftSelectorBaseline,
) -> str:
    return _row_key_for_components(
        "draft-selector-baseline",
        baseline.draft_id,
    )


def _row_key_for_published(published: PublishedManifest) -> str:
    return _row_key_for_components(
        "published",
        published.manifest_id,
        published.manifest_version,
    )


def _row_key_for_supersession(supersession: Supersession) -> str:
    return _row_key_for_components(
        "supersession",
        supersession.manifest_id,
        supersession.superseded_version,
    )


def _row_key_for_receipt(receipt: MutationReceipt) -> str:
    return _row_key_for_components(
        "receipt",
        receipt.actor_id,
        receipt.idempotency_key,
    )


def _row_key_for_cohort_decision(decision: CohortDecisionRecord) -> str:
    return _row_key_for_components(
        "cohort-decision",
        decision.manifest_id,
        decision.decision_id,
    )


def _row_key_for_cohort_decision_receipt(
    receipt: CohortDecisionReceipt,
) -> str:
    return _row_key_for_components(
        "cohort-decision-receipt",
        receipt.actor_id,
        receipt.idempotency_key,
    )


def _row_key_for_audit(event: AuditEvent) -> str:
    return f"audit:{event.sequence:08d}"


def _row_key_for_components(kind: str, *components: str) -> str:
    """Encode logical identifiers as a domain-separated Azure Table-safe key."""

    digest = compute_artifact_digest(
        {
            "schemaVersion": "athena.context-store-row-key.v1",
            "kind": kind,
            "components": list(components),
        }
    )
    return f"{kind}:{digest.removeprefix('sha256:')}"


def _cohort_overlap_binding_key(
    version: CohortProposalSetVersion,
) -> tuple[str, str]:
    return version.authority_overlap_identity()


def _cohort_selected_version_key(
    version: CohortProposalSetVersion,
) -> tuple[str, ...]:
    return version.authority_selected_identity()


def _record_json_fits_table_property_bound(record_json: str) -> bool:
    try:
        return len(record_json.encode("utf-16-le")) <= _MAX_RECORD_BYTES
    except UnicodeEncodeError:
        return False


def _partition_anchor(
    entities: Mapping[str, Mapping[str, Any]],
    audit: list[AuditEvent],
    *,
    generation: int,
    workload_id: str,
) -> dict[str, object]:
    """Return the state-row commitment for every immutable or mutable record."""

    records: list[dict[str, str]] = []
    for row_key, entity in sorted(entities.items()):
        if row_key == _CONTEXT_STATE_ROW_KEY:
            continue
        kind = entity.get("kind")
        record_digest = entity.get("recordDigest")
        if not isinstance(kind, str) or not isinstance(record_digest, str):
            raise RuntimeError("context store record cannot be included in state anchor")
        records.append(
            {
                "rowKey": row_key,
                "kind": kind,
                "recordDigest": record_digest,
            }
        )
    audit_tail = (
        {
            "sequence": audit[-1].sequence,
            "eventDigest": audit[-1].event_digest,
        }
        if audit
        else None
    )
    return {
        "workloadId": workload_id,
        "entityCount": len(records) + 1,
        "auditTailSequence": 0 if audit_tail is None else audit[-1].sequence,
        "auditTailDigest": None if audit_tail is None else audit[-1].event_digest,
        "partitionDigest": compute_artifact_digest(
            {
                "schemaVersion": _CONTEXT_STORE_ANCHOR_SCHEMA,
                "workloadId": workload_id,
                "generation": generation,
                "entities": records,
                "auditTail": audit_tail,
            }
        ),
    }


class AzureTableContextStore:
    """Azure Table persistence with one conditional, atomic Context API commit path.

    The table and partition are dedicated to Context API state. The deployment grants its
    managed identity access to this store; callers and other Athena components use the API.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        partition_key: str,
        managed_identity_client_id: str,
        workload_id: str,
        allow_empty_partition_bootstrap: bool = False,
    ) -> None:
        _validate_configuration(
            endpoint=endpoint,
            table_name=table_name,
            partition_key=partition_key,
            managed_identity_client_id=managed_identity_client_id,
            workload_id=workload_id,
        )
        if type(allow_empty_partition_bootstrap) is not bool:
            raise ValueError("context store bootstrap authorization is invalid")
        self._table = TableServiceClient(
            endpoint=endpoint,
            credential=production_managed_identity_credential(
                managed_identity_client_id=managed_identity_client_id
            ),
        ).get_table_client(table_name)
        self._partition_key = partition_key
        self._workload_id = workload_id
        self._transaction_lock = InMemoryTransactionLock()
        self._lock = self._transaction_lock.lock
        self._allow_empty_partition_bootstrap = allow_empty_partition_bootstrap
        self._bootstrap_consumed = False

    def transaction(self) -> _AzureTableTransaction:
        return _AzureTableTransaction(self)

    def initialize_empty_partition(self) -> None:
        """Create the one-time continuity root for an empty configured partition."""

        with self._lock:
            if not self._allow_empty_partition_bootstrap or self._bootstrap_consumed:
                raise RuntimeError(
                    "context store empty-partition bootstrap is not authorized"
                )
            if self._load_partition():
                raise RuntimeError(
                    "context store bootstrap requires an empty configured partition"
                )
            state_entity = {
                "PartitionKey": self._partition_key,
                "RowKey": _CONTEXT_STATE_ROW_KEY,
                "schemaVersion": _CONTEXT_STORE_SCHEMA,
                "kind": "state",
                "generation": 1,
                **_partition_anchor(
                    {},
                    [],
                    generation=1,
                    workload_id=self._workload_id,
                ),
            }
            try:
                self._table.submit_transaction([("create", state_entity)])
            except (ResourceExistsError, ResourceModifiedError) as exc:
                raise PersistenceConflictError(
                    "context store was initialized concurrently"
                ) from exc
            except HttpResponseError as exc:
                if exc.status_code in {409, 412}:
                    raise PersistenceConflictError(
                        "context store was initialized concurrently"
                    ) from exc
                raise RuntimeError("context store bootstrap failed") from exc
            self._bootstrap_consumed = True

    def _load_partition(self) -> dict[str, Mapping[str, Any]]:
        try:
            entities = list(
                islice(
                    self._table.query_entities(
                        query_filter=f"PartitionKey eq '{self._partition_key}'",
                        results_per_page=_MAX_PARTITION_ENTITIES + 1,
                    ),
                    _MAX_PARTITION_ENTITIES + 1,
                )
            )
        except HttpResponseError as exc:
            raise RuntimeError("context store partition read failed") from exc
        if len(entities) > _MAX_PARTITION_ENTITIES:
            raise RuntimeError("context store partition exceeds its safe entity bound")
        self._warn_if_capacity_near_limit(len(entities))
        result: dict[str, Mapping[str, Any]] = {}
        for entity in entities:
            if not isinstance(entity, Mapping):
                raise RuntimeError("context store returned a non-mapping entity")
            partition_key = entity.get("PartitionKey")
            row_key = entity.get("RowKey")
            if partition_key != self._partition_key or not isinstance(row_key, str):
                raise RuntimeError("context store returned an entity outside its partition")
            if row_key in result:
                raise RuntimeError("context store returned duplicate row keys")
            result[row_key] = entity
        return result

    def _warn_if_capacity_near_limit(self, entity_count: int) -> None:
        if entity_count >= _CAPACITY_WARNING_ENTITY_COUNT:
            _LOGGER.warning(
                "event=athena_context_store_capacity_warning workload_id=%s "
                "entity_count=%s capacity=%s action=complete-approved-"
                "archival-or-per-workload-shard-migration-before-hard-limit",
                self._workload_id,
                entity_count,
                _MAX_PARTITION_ENTITIES,
            )


class _AzureTableTransaction(ContextTransactionPort):
    def __init__(self, store: AzureTableContextStore) -> None:
        self._store = store
        self._active = False
        self._persisted: dict[str, Mapping[str, Any]] = {}
        self._state_entity: Mapping[str, Any] | None = None
        self._generation = 0
        self._drafts: dict[str, DraftRecord] = {}
        self._draft_selector_baselines: dict[str, DraftSelectorBaseline] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}
        self._cohort_decisions: dict[
            tuple[str, str],
            CohortDecisionRecord,
        ] = {}
        self._cohort_decision_versions: dict[
            tuple[str, ...],
            tuple[str, str],
        ] = {}
        self._cohort_decision_receipts: dict[
            tuple[str, str],
            CohortDecisionReceipt,
        ] = {}
        self._creates: dict[str, dict[str, object]] = {}
        self._updates: dict[str, dict[str, object]] = {}
        self._dirty = False

    def __enter__(self) -> _AzureTableTransaction:
        if self._active:
            raise RuntimeError("context transaction is already active")
        self._store._lock.acquire()
        self._active = True
        try:
            self._persisted = self._store._load_partition()
            self._load_models()
            return self
        except BaseException:
            self._active = False
            self._store._lock.release()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_value, traceback
        try:
            if exc_type is None and self._dirty:
                self._commit()
        finally:
            self._active = False
            self._store._lock.release()
        return False

    def _load_models(self) -> None:
        if not self._persisted:
            raise RuntimeError(
                "context store continuity root is absent; explicit initialization is required"
            )
        for row_key, entity in self._persisted.items():
            kind = entity.get("kind")
            if row_key == _CONTEXT_STATE_ROW_KEY:
                self._load_state(entity)
            elif kind == "draft":
                draft = self._decode_model(entity, DraftRecord)
                self._require_persisted_workload(draft.manifest_id)
                if _row_key_for_draft(draft) != row_key or draft.draft_id in self._drafts:
                    raise RuntimeError("context store draft key is invalid")
                self._drafts[draft.draft_id] = draft
            elif kind == "draft-selector-baseline":
                baseline = self._decode_model(entity, DraftSelectorBaseline)
                self._require_persisted_workload(baseline.manifest_id)
                if (
                    _row_key_for_draft_selector_baseline(baseline) != row_key
                    or baseline.draft_id in self._draft_selector_baselines
                ):
                    raise RuntimeError(
                        "context store draft selector baseline key is invalid"
                    )
                self._draft_selector_baselines[baseline.draft_id] = baseline
            elif kind == "published":
                published = self._decode_model(entity, PublishedManifest)
                self._require_persisted_workload(published.manifest_id)
                key = (published.manifest_id, published.manifest_version)
                if _row_key_for_published(published) != row_key or key in self._published:
                    raise RuntimeError("context store published manifest key is invalid")
                self._published[key] = published
            elif kind == "supersession":
                supersession = self._decode_model(entity, Supersession)
                self._require_persisted_workload(supersession.manifest_id)
                key = (supersession.manifest_id, supersession.superseded_version)
                if _row_key_for_supersession(supersession) != row_key or key in self._supersessions:
                    raise RuntimeError("context store supersession key is invalid")
                self._supersessions[key] = supersession
            elif kind == "audit":
                event = self._decode_model(entity, AuditEvent)
                self._require_persisted_workload(event.manifest_id)
                if _row_key_for_audit(event) != row_key:
                    raise RuntimeError("context store audit key is invalid")
                self._audit.append(event)
            elif kind == "receipt":
                receipt = self._decode_model(entity, MutationReceipt)
                key = (receipt.actor_id, receipt.idempotency_key)
                if _row_key_for_receipt(receipt) != row_key or key in self._receipts:
                    raise RuntimeError("context store receipt key is invalid")
                self._receipts[key] = receipt
            elif kind == "cohort-decision":
                decision = self._decode_model(entity, CohortDecisionRecord)
                self._require_persisted_workload(decision.manifest_id)
                key = (decision.manifest_id, decision.decision_id)
                version = decision.proposal_set_version()
                version_key = _cohort_selected_version_key(version)
                if (
                    _row_key_for_cohort_decision(decision) != row_key
                    or key in self._cohort_decisions
                    or version_key in self._cohort_decision_versions
                    or self._overlapping_cohort_decisions(version)
                ):
                    raise RuntimeError(
                        "context store cohort decision key or authority is invalid"
                    )
                self._cohort_decisions[key] = decision
                self._cohort_decision_versions[version_key] = key
            elif kind == "cohort-decision-receipt":
                receipt = self._decode_model(entity, CohortDecisionReceipt)
                key = (receipt.actor_id, receipt.idempotency_key)
                if (
                    _row_key_for_cohort_decision_receipt(receipt) != row_key
                    or key in self._cohort_decision_receipts
                ):
                    raise RuntimeError(
                        "context store cohort decision receipt key is invalid"
                    )
                self._require_cohort_receipt_workload(
                    receipt,
                    persisted=True,
                )
                self._cohort_decision_receipts[key] = receipt
            else:
                raise RuntimeError("context store contains an unknown entity kind")
        if self._state_entity is None and self._persisted:
            raise RuntimeError("context store has state without a commit generation")
        self._audit.sort(key=lambda event: event.sequence)
        verify_audit_chain(self._audit)
        for receipt in self._receipts.values():
            self._require_receipt_workload(receipt, persisted=True)
        if self._state_entity is not None:
            self._verify_state_anchor()

    def _require_persisted_workload(self, manifest_id: str) -> None:
        if manifest_id != self._store._workload_id:
            raise RuntimeError(
                "context store contains a record outside its configured workload"
            )

    def _require_workload(self, manifest_id: str) -> None:
        if manifest_id != self._store._workload_id:
            raise AuthorizationError(
                "context store does not serve the requested workload"
            )

    def _require_receipt_workload(
        self,
        receipt: MutationReceipt,
        *,
        persisted: bool,
    ) -> None:
        manifest_id = receipt.target.manifest_id
        if manifest_id is not None:
            if persisted:
                self._require_persisted_workload(manifest_id)
            else:
                self._require_workload(manifest_id)
            return
        draft_id = receipt.target.draft_id
        assert draft_id is not None
        draft = self._drafts.get(draft_id)
        if draft is None:
            if persisted:
                raise RuntimeError(
                    "context store receipt does not resolve to its workload draft"
                )
            raise ResourceNotFoundError(
                f"draft {draft_id!r} was not found for its idempotency receipt"
            )
        if persisted:
            self._require_persisted_workload(draft.manifest_id)
        else:
            self._require_workload(draft.manifest_id)

    def _require_cohort_receipt_workload(
        self,
        receipt: CohortDecisionReceipt,
        *,
        persisted: bool,
    ) -> None:
        try:
            decision = CohortDecisionRecord.model_validate_json(
                receipt.response_json
            )
        except ValidationError as exc:
            if persisted:
                raise RuntimeError(
                    "context store cohort decision receipt is invalid"
                ) from exc
            raise PersistenceConflictError(
                "cohort decision receipt is invalid"
            ) from exc
        if persisted:
            self._require_persisted_workload(decision.manifest_id)
        else:
            self._require_workload(decision.manifest_id)

    def _overlapping_cohort_decisions(
        self,
        version: CohortProposalSetVersion,
    ) -> list[CohortDecisionRecord]:
        binding_key = _cohort_overlap_binding_key(version)
        batch_key = version.batch_overlap_identity()
        selected_proposal_ids = set(version.source_proposal_ids)
        return [
            decision
            for decision in self._cohort_decisions.values()
            if (
                (
                    _cohort_overlap_binding_key(
                        decision.proposal_set_version()
                    )
                    == binding_key
                    and rejection_authorities_overlap(
                        version.source_rejection_authorities,
                        decision.source_rejection_authorities,
                    )
                )
                or (
                    decision.proposal_set_version().batch_overlap_identity()
                    == batch_key
                    and selected_proposal_ids.intersection(
                        decision.source_proposal_ids
                    )
                )
            )
        ]

    def _load_state(self, entity: Mapping[str, Any]) -> None:
        if self._state_entity is not None or entity.get("kind") != "state":
            raise RuntimeError("context store commit generation is invalid")
        if entity.get("schemaVersion") != _CONTEXT_STORE_SCHEMA:
            raise RuntimeError("context store schema version is invalid")
        generation = entity.get("generation")
        if type(generation) is not int or generation < 1:
            raise RuntimeError("context store generation is invalid")
        self._entity_etag(entity)
        self._state_entity = entity
        self._generation = generation

    def _verify_state_anchor(self) -> None:
        assert self._state_entity is not None
        expected = _partition_anchor(
            self._persisted,
            self._audit,
            generation=self._generation,
            workload_id=self._store._workload_id,
        )
        if any(
            self._state_entity.get(name) != value
            for name, value in expected.items()
        ):
            raise RuntimeError("context store state anchor does not match its partition")

    def _decode_model(
        self,
        entity: Mapping[str, Any],
        model_type: type[BaseModel],
    ) -> Any:
        if entity.get("schemaVersion") != _CONTEXT_STORE_SCHEMA:
            raise RuntimeError("context store schema version is invalid")
        record_json = entity.get("recordJson")
        record_digest = entity.get("recordDigest")
        if (
            not isinstance(record_json, str)
            or not _record_json_fits_table_property_bound(record_json)
            or not isinstance(record_digest, str)
        ):
            raise RuntimeError("context store record is invalid or exceeds its bound")
        self._entity_etag(entity)
        try:
            record = model_type.model_validate_json(record_json)
        except ValidationError as exc:
            raise RuntimeError("context store record does not match its schema") from exc
        canonical_record = record.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        if compute_artifact_digest(canonical_record) != record_digest:
            raise RuntimeError("context store record integrity digest is invalid")
        return record

    @staticmethod
    def _entity_etag(entity: Mapping[str, Any]) -> str:
        metadata = getattr(entity, "metadata", None)
        etag = metadata.get("etag") if isinstance(metadata, Mapping) else None
        if not isinstance(etag, str) or not etag:
            raise RuntimeError("context store entity has no ETag")
        return etag

    def _record_entity(
        self,
        *,
        row_key: str,
        kind: str,
        record: BaseModel,
    ) -> dict[str, object]:
        record_json = record.model_dump_json(by_alias=True, exclude_none=True)
        if not _record_json_fits_table_property_bound(record_json):
            raise ValueError("context store record exceeds the Azure Table property bound")
        return {
            "PartitionKey": self._store._partition_key,
            "RowKey": row_key,
            "schemaVersion": _CONTEXT_STORE_SCHEMA,
            "kind": kind,
            "recordJson": record_json,
            "recordDigest": compute_artifact_digest(
                record.model_dump(mode="json", by_alias=True, exclude_none=True)
            ),
        }

    def _stage_create(self, row_key: str, entity: dict[str, object]) -> None:
        if row_key in self._persisted or row_key in self._creates:
            raise RuntimeError("context store attempted to recreate an existing entity")
        self._creates[row_key] = entity
        self._dirty = True

    def _stage_update(self, row_key: str, entity: dict[str, object]) -> None:
        if row_key not in self._persisted:
            raise RuntimeError("context store attempted to update a missing entity")
        self._updates[row_key] = entity
        self._dirty = True

    def _commit(self) -> None:
        committed_entities = dict(self._persisted)
        committed_entities.update(self._creates)
        committed_entities.update(self._updates)
        committed_entity_count = len(committed_entities) + int(
            _CONTEXT_STATE_ROW_KEY not in committed_entities
        )
        if committed_entity_count > _MAX_PARTITION_ENTITIES:
            raise RuntimeError(
                "context store transaction exceeds the Azure Table partition entity limit"
            )
        self._store._warn_if_capacity_near_limit(committed_entity_count)

        operations: list[_TableOperation] = []
        for row_key in sorted(self._creates):
            operations.append(("create", self._creates[row_key]))
        for row_key in sorted(self._updates):
            previous = self._persisted[row_key]
            operations.append(
                (
                    "update",
                    self._updates[row_key],
                    {
                        "mode": UpdateMode.REPLACE,
                        "etag": self._entity_etag(previous),
                        "match_condition": MatchConditions.IfNotModified,
                    },
                )
            )
        next_generation = self._generation + 1
        state_entity = {
            "PartitionKey": self._store._partition_key,
            "RowKey": _CONTEXT_STATE_ROW_KEY,
            "schemaVersion": _CONTEXT_STORE_SCHEMA,
            "kind": "state",
            "generation": next_generation,
            **_partition_anchor(
                committed_entities,
                self._audit,
                generation=next_generation,
                workload_id=self._store._workload_id,
            ),
        }
        if self._state_entity is None:
            operations.append(("create", state_entity))
        else:
            operations.append(
                (
                    "update",
                    state_entity,
                    {
                        "mode": UpdateMode.REPLACE,
                        "etag": self._entity_etag(self._state_entity),
                        "match_condition": MatchConditions.IfNotModified,
                    },
                )
            )
        if len(operations) > 100:
            raise RuntimeError("context store transaction exceeds Azure Table batch limit")
        try:
            self._store._table.submit_transaction(operations)
        except (ResourceExistsError, ResourceModifiedError) as exc:
            raise PersistenceConflictError(
                "context store changed before the authoritative transaction committed"
            ) from exc
        except HttpResponseError as exc:
            if exc.status_code in {409, 412}:
                raise PersistenceConflictError(
                    "context store changed before the authoritative transaction committed"
                ) from exc
            raise RuntimeError("context store transaction failed") from exc

    def get_draft(self, draft_id: str) -> DraftRecord | None:
        draft = self._drafts.get(draft_id)
        return None if draft is None else draft.model_copy(deep=True)

    def list_drafts(
        self,
        *,
        manifest_id: str | None = None,
        state: DraftState | None = None,
    ) -> list[DraftRecord]:
        if manifest_id is not None:
            self._require_workload(manifest_id)
        matches = sorted(
            (
                draft
                for draft in self._drafts.values()
                if (manifest_id is None or draft.manifest_id == manifest_id)
                and (state is None or draft.state is state)
            ),
            key=lambda draft: draft.draft_id,
        )
        return [draft.model_copy(deep=True) for draft in matches]

    def put_draft(
        self,
        draft: DraftRecord,
        *,
        expected_revision: int | None,
    ) -> None:
        self._require_workload(draft.manifest_id)
        current = self._drafts.get(draft.draft_id)
        if expected_revision is None:
            if current is not None:
                raise DuplicateDraftError(f"draft {draft.draft_id!r} already exists")
        elif current is None:
            raise ResourceNotFoundError(f"draft {draft.draft_id!r} was not found")
        elif current.revision != expected_revision:
            raise StaleRevisionError(
                f"expected draft revision {expected_revision}, found {current.revision}"
            )
        normalized = draft.model_copy(deep=True)
        row_key = _row_key_for_draft(normalized)
        entity = self._record_entity(row_key=row_key, kind="draft", record=normalized)
        if current is None:
            self._stage_create(row_key, entity)
        else:
            self._stage_update(row_key, entity)
        self._drafts[draft.draft_id] = normalized

    def get_draft_selector_baseline(
        self,
        draft_id: str,
    ) -> DraftSelectorBaseline | None:
        baseline = self._draft_selector_baselines.get(draft_id)
        return None if baseline is None else baseline.model_copy(deep=True)

    def list_draft_selector_baselines(
        self,
        *,
        manifest_id: str,
        manifest_version: str | None = None,
    ) -> list[DraftSelectorBaseline]:
        self._require_workload(manifest_id)
        matches = sorted(
            (
                baseline
                for baseline in self._draft_selector_baselines.values()
                if baseline.manifest_id == manifest_id
                and (
                    manifest_version is None
                    or baseline.manifest_version == manifest_version
                )
            ),
            key=lambda baseline: (baseline.captured_at, baseline.draft_id),
        )
        return [baseline.model_copy(deep=True) for baseline in matches]

    def put_draft_selector_baseline(
        self,
        baseline: DraftSelectorBaseline,
    ) -> None:
        self._require_workload(baseline.manifest_id)
        if baseline.draft_id in self._draft_selector_baselines:
            raise PersistenceConflictError(
                "draft selector baseline is immutable"
            )
        normalized = baseline.model_copy(deep=True)
        row_key = _row_key_for_draft_selector_baseline(normalized)
        self._stage_create(
            row_key,
            self._record_entity(
                row_key=row_key,
                kind="draft-selector-baseline",
                record=normalized,
            ),
        )
        self._draft_selector_baselines[baseline.draft_id] = normalized

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest | None:
        self._require_workload(manifest_id)
        published = self._published.get((manifest_id, manifest_version))
        return None if published is None else published.model_copy(deep=True)

    def list_published(self, *, manifest_id: str | None = None) -> list[PublishedManifest]:
        if manifest_id is not None:
            self._require_workload(manifest_id)

        def version_key(version: str) -> tuple[int, int, int]:
            major, minor, patch = version.split(".")
            return int(major), int(minor), int(patch)

        matches = sorted(
            (
                item
                for item in self._published.values()
                if manifest_id is None or item.manifest_id == manifest_id
            ),
            key=lambda item: (item.manifest_id, version_key(item.manifest_version)),
        )
        return [item.model_copy(deep=True) for item in matches]

    def put_published(self, published: PublishedManifest) -> None:
        self._require_workload(published.manifest_id)
        key = (published.manifest_id, published.manifest_version)
        if key in self._published:
            raise DuplicateVersionError(
                f"manifest version {published.manifest_id}/{published.manifest_version} exists"
            )
        normalized = published.model_copy(deep=True)
        self._stage_create(
            _row_key_for_published(normalized),
            self._record_entity(
                row_key=_row_key_for_published(normalized),
                kind="published",
                record=normalized,
            ),
        )
        self._published[key] = normalized

    def get_supersession(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> Supersession | None:
        self._require_workload(manifest_id)
        supersession = self._supersessions.get((manifest_id, manifest_version))
        return None if supersession is None else supersession.model_copy(deep=True)

    def put_supersession(self, supersession: Supersession) -> None:
        self._require_workload(supersession.manifest_id)
        key = (supersession.manifest_id, supersession.superseded_version)
        if key in self._supersessions:
            raise AlreadySupersededError(
                f"manifest version {supersession.superseded_version} is already superseded"
            )
        normalized = supersession.model_copy(deep=True)
        self._stage_create(
            _row_key_for_supersession(normalized),
            self._record_entity(
                row_key=_row_key_for_supersession(normalized),
                kind="supersession",
                record=normalized,
            ),
        )
        self._supersessions[key] = normalized

    def append_audit(self, event: PendingAuditEvent) -> AuditEvent:
        self._require_workload(event.manifest_id)
        verify_audit_chain(self._audit)
        sequence = len(self._audit) + 1
        event_id = f"audit-{sequence:08d}"
        previous_event_digest = None if not self._audit else self._audit[-1].event_digest
        stored = AuditEvent(
            **event.model_dump(),
            sequence=sequence,
            event_id=event_id,
            previous_event_digest=previous_event_digest,
            event_digest=audit_event_digest(
                event,
                sequence=sequence,
                event_id=event_id,
                previous_event_digest=previous_event_digest,
            ),
        )
        self._stage_create(
            _row_key_for_audit(stored),
            self._record_entity(
                row_key=_row_key_for_audit(stored),
                kind="audit",
                record=stored,
            ),
        )
        self._audit.append(stored.model_copy(deep=True))
        return stored

    def list_audit(self, *, manifest_id: str | None = None) -> list[AuditEvent]:
        if manifest_id is not None:
            self._require_workload(manifest_id)
        return [
            event.model_copy(deep=True)
            for event in self._audit
            if manifest_id is None or event.manifest_id == manifest_id
        ]

    def get_receipt(self, actor_id: str, idempotency_key: str) -> MutationReceipt | None:
        receipt = self._receipts.get((actor_id, idempotency_key))
        if receipt is not None:
            self._require_receipt_workload(receipt, persisted=False)
        return None if receipt is None else receipt.model_copy(deep=True)

    def put_receipt(self, receipt: MutationReceipt) -> None:
        self._require_receipt_workload(receipt, persisted=False)
        key = (receipt.actor_id, receipt.idempotency_key)
        if key in self._receipts:
            raise IdempotencyConflictError("idempotency key has already been recorded")
        normalized = receipt.model_copy(deep=True)
        self._stage_create(
            _row_key_for_receipt(normalized),
            self._record_entity(
                row_key=_row_key_for_receipt(normalized),
                kind="receipt",
                record=normalized,
            ),
        )
        self._receipts[key] = normalized

    def get_cohort_decision(
        self,
        manifest_id: str,
        decision_id: str,
    ) -> CohortDecisionRecord | None:
        self._require_workload(manifest_id)
        decision = self._cohort_decisions.get((manifest_id, decision_id))
        return None if decision is None else decision.model_copy(deep=True)

    def list_cohort_decisions(
        self,
        *,
        manifest_id: str,
        profile_id: str | None = None,
        draft_id: str | None = None,
        proposal_set_digest: str | None = None,
    ) -> list[CohortDecisionRecord]:
        self._require_workload(manifest_id)
        matches = sorted(
            (
                decision
                for decision in self._cohort_decisions.values()
                if decision.manifest_id == manifest_id
                and (profile_id is None or decision.profile_id == profile_id)
                and (
                    draft_id is None
                    or decision.source_draft.draft_id == draft_id
                )
                and (
                    proposal_set_digest is None
                    or decision.proposal_set_digest == proposal_set_digest
                )
            ),
            key=lambda decision: (decision.decided_at, decision.decision_id),
        )
        return [decision.model_copy(deep=True) for decision in matches]

    def list_overlapping_cohort_decisions(
        self,
        version: CohortProposalSetVersion,
    ) -> list[CohortDecisionRecord]:
        self._require_workload(version.manifest_id)
        return [
            decision.model_copy(deep=True)
            for decision in sorted(
                self._overlapping_cohort_decisions(version),
                key=lambda item: (item.decided_at, item.decision_id),
            )
        ]

    def put_cohort_decision(self, decision: CohortDecisionRecord) -> None:
        self._require_workload(decision.manifest_id)
        decision_key = (decision.manifest_id, decision.decision_id)
        version = decision.proposal_set_version()
        version_key = _cohort_selected_version_key(version)
        if decision_key in self._cohort_decisions:
            raise PersistenceConflictError(
                "cohort decision identifier already exists"
            )
        if version_key in self._cohort_decision_versions:
            raise PersistenceConflictError(
                "the proposal-set version already has an authoritative decision"
            )
        if self._overlapping_cohort_decisions(version):
            raise PersistenceConflictError(
                "an overlapping selected proposal already has an authoritative decision"
            )
        normalized = decision.model_copy(deep=True)
        row_key = _row_key_for_cohort_decision(normalized)
        self._stage_create(
            row_key,
            self._record_entity(
                row_key=row_key,
                kind="cohort-decision",
                record=normalized,
            ),
        )
        self._cohort_decisions[decision_key] = normalized
        self._cohort_decision_versions[version_key] = decision_key

    def get_cohort_decision_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> CohortDecisionReceipt | None:
        receipt = self._cohort_decision_receipts.get(
            (actor_id, idempotency_key)
        )
        if receipt is not None:
            self._require_cohort_receipt_workload(
                receipt,
                persisted=False,
            )
        return None if receipt is None else receipt.model_copy(deep=True)

    def put_cohort_decision_receipt(
        self,
        receipt: CohortDecisionReceipt,
    ) -> None:
        self._require_cohort_receipt_workload(receipt, persisted=False)
        key = (receipt.actor_id, receipt.idempotency_key)
        if key in self._cohort_decision_receipts:
            raise IdempotencyConflictError(
                "cohort decision idempotency key has already been recorded"
            )
        normalized = receipt.model_copy(deep=True)
        row_key = _row_key_for_cohort_decision_receipt(normalized)
        self._stage_create(
            row_key,
            self._record_entity(
                row_key=row_key,
                kind="cohort-decision-receipt",
                record=normalized,
            ),
        )
        self._cohort_decision_receipts[key] = normalized
