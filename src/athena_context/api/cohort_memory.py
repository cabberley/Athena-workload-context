from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from threading import RLock

from pydantic import BaseModel

from athena_context.api.cohort_domain import (
    CohortBatchCacheKey,
    CohortEvidenceBinding,
    CohortPreviewReceipt,
    CohortProposalBatchResponse,
    StoredEvidenceSnapshot,
)
from athena_context.api.errors import PersistenceConflictError
from athena_context.contracts.models import EvidenceSnapshot


def _model_key(model: BaseModel) -> str:
    return model.model_dump_json(by_alias=True, exclude_none=True)


class InMemoryEvidenceSnapshotRepository:
    """Deterministic test adapter with immutable exact-binding writes."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._snapshots: dict[str, StoredEvidenceSnapshot] = {}

    def put_snapshot(
        self,
        binding: CohortEvidenceBinding,
        snapshot: EvidenceSnapshot,
    ) -> None:
        key = _model_key(binding)
        stored = StoredEvidenceSnapshot(binding=binding, snapshot=snapshot)
        with self._lock:
            existing = self._snapshots.get(key)
            if existing is not None and existing != stored:
                raise PersistenceConflictError(
                    "an immutable cohort snapshot binding already exists"
                )
            self._snapshots.setdefault(key, stored.model_copy(deep=True))

    def get_snapshot(
        self,
        binding: CohortEvidenceBinding,
    ) -> StoredEvidenceSnapshot | None:
        with self._lock:
            stored = self._snapshots.get(_model_key(binding))
            return None if stored is None else stored.model_copy(deep=True)


class EmptyEvidenceSnapshotRepository:
    """Production-safe default until a trusted snapshot repository is injected."""

    def get_snapshot(
        self,
        binding: CohortEvidenceBinding,
    ) -> StoredEvidenceSnapshot | None:
        del binding
        return None


class CallableTrustedEvidenceSnapshotVerifier:
    def __init__(
        self,
        verifier: Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot],
    ) -> None:
        self._verifier = verifier

    def verify(
        self,
        snapshot: EvidenceSnapshot,
        *,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        return self._verifier(snapshot, as_of)


class RejectingTrustedEvidenceSnapshotVerifier:
    """Production-safe default that cannot manufacture a verified capability."""

    def verify(
        self,
        snapshot: EvidenceSnapshot,
        *,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        del snapshot, as_of
        raise ValueError("trusted snapshot verification is not configured")


class InMemoryCohortPersistence:
    """Thread-safe immutable cache and actor-scoped idempotency adapter."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._batches: dict[str, CohortProposalBatchResponse] = {}
        self._receipts: dict[tuple[str, str], CohortPreviewReceipt] = {}
        self._candidates: dict[str, CohortPreviewReceipt] = {}

    def get_batch(
        self,
        key: CohortBatchCacheKey,
    ) -> CohortProposalBatchResponse | None:
        with self._lock:
            batch = self._batches.get(_model_key(key))
            return None if batch is None else batch.model_copy(deep=True)

    def put_batch_if_absent(
        self,
        key: CohortBatchCacheKey,
        batch: CohortProposalBatchResponse,
    ) -> CohortProposalBatchResponse:
        cache_key = _model_key(key)
        with self._lock:
            existing = self._batches.get(cache_key)
            if existing is None:
                existing = batch.model_copy(deep=True)
                self._batches[cache_key] = existing
            return existing.model_copy(deep=True)

    def get_preview_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> CohortPreviewReceipt | None:
        with self._lock:
            receipt = self._receipts.get((actor_id, idempotency_key))
            return None if receipt is None else receipt.model_copy(deep=True)

    def put_preview_receipt_if_absent(
        self,
        receipt: CohortPreviewReceipt,
    ) -> CohortPreviewReceipt:
        key = (receipt.actor_id, receipt.idempotency_key)
        with self._lock:
            existing = self._receipts.get(key)
            if existing is None:
                candidate = self._candidates.get(receipt.candidate.candidate_id)
                if candidate is not None and (
                    candidate.candidate != receipt.candidate
                    or candidate.evidence_binding != receipt.evidence_binding
                ):
                    raise PersistenceConflictError(
                        "an immutable cohort candidate identifier already exists"
                    )
                existing = receipt.model_copy(deep=True)
                self._receipts[key] = existing
                self._candidates.setdefault(receipt.candidate.candidate_id, existing)
            return existing.model_copy(deep=True)

    def get_candidate(
        self,
        candidate_id: str,
    ) -> CohortPreviewReceipt | None:
        with self._lock:
            receipt = self._candidates.get(candidate_id)
            return None if receipt is None else receipt.model_copy(deep=True)


__all__ = [
    "CallableTrustedEvidenceSnapshotVerifier",
    "EmptyEvidenceSnapshotRepository",
    "InMemoryCohortPersistence",
    "InMemoryEvidenceSnapshotRepository",
    "RejectingTrustedEvidenceSnapshotVerifier",
]
