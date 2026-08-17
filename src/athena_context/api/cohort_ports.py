from __future__ import annotations

from datetime import datetime
from typing import Protocol

from athena_context.api.cohort_domain import (
    CohortBatchCacheKey,
    CohortEvidenceBinding,
    CohortPreviewReceipt,
    CohortProposalBatchResponse,
    StoredEvidenceSnapshot,
)
from athena_context.api.domain import Actor, Permission, WorkloadIdentifier
from athena_context.contracts.models import EvidenceSnapshot


class ExplicitWorkloadAuthorizationPort(Protocol):
    def require_explicit(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: WorkloadIdentifier,
    ) -> None: ...


class EvidenceSnapshotRepositoryPort(Protocol):
    """Read-only, exact-binding access to immutable trusted snapshot candidates."""

    def get_snapshot(
        self,
        binding: CohortEvidenceBinding,
    ) -> StoredEvidenceSnapshot | None: ...


class TrustedEvidenceSnapshotVerifierPort(Protocol):
    """Cryptographically verify publication, identity, signature, and envelope bindings."""

    def verify(
        self,
        snapshot: EvidenceSnapshot,
        *,
        as_of: datetime,
    ) -> EvidenceSnapshot: ...


class CohortProposalCachePort(Protocol):
    """Immutable cache keyed by workload, draft, profile, and snapshot."""

    def get_batch(
        self,
        key: CohortBatchCacheKey,
    ) -> CohortProposalBatchResponse | None: ...

    def put_batch_if_absent(
        self,
        key: CohortBatchCacheKey,
        batch: CohortProposalBatchResponse,
    ) -> CohortProposalBatchResponse: ...


class CohortPreviewReceiptPort(Protocol):
    """Actor-scoped immutable idempotency receipts for preview requests."""

    def get_preview_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> CohortPreviewReceipt | None: ...

    def put_preview_receipt_if_absent(
        self,
        receipt: CohortPreviewReceipt,
    ) -> CohortPreviewReceipt: ...


class CohortCandidateRepositoryPort(Protocol):
    """Immutable lookup of server-generated candidates by their stable identifier."""

    def get_candidate(
        self,
        candidate_id: str,
    ) -> CohortPreviewReceipt | None: ...


__all__ = [
    "CohortCandidateRepositoryPort",
    "CohortPreviewReceiptPort",
    "CohortProposalCachePort",
    "EvidenceSnapshotRepositoryPort",
    "ExplicitWorkloadAuthorizationPort",
    "TrustedEvidenceSnapshotVerifierPort",
]
