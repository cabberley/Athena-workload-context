from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol

from athena_context.api.cohort_decision_domain import (
    CohortDecisionReceipt,
    CohortDecisionRecord,
    CohortProposalSetVersion,
)
from athena_context.api.ports import ContextTransactionPort


class CohortDecisionTransactionPort(ContextTransactionPort, Protocol):
    """One transaction spanning WC-007 drafts and cohort decision records."""

    def get_cohort_decision(
        self,
        manifest_id: str,
        decision_id: str,
    ) -> CohortDecisionRecord | None: ...

    def list_cohort_decisions(
        self,
        *,
        manifest_id: str,
        profile_id: str | None = None,
        draft_id: str | None = None,
        proposal_set_digest: str | None = None,
    ) -> list[CohortDecisionRecord]: ...

    def list_overlapping_cohort_decisions(
        self,
        version: CohortProposalSetVersion,
    ) -> list[CohortDecisionRecord]: ...

    def put_cohort_decision(self, decision: CohortDecisionRecord) -> None: ...

    def get_cohort_decision_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> CohortDecisionReceipt | None: ...

    def put_cohort_decision_receipt(
        self,
        receipt: CohortDecisionReceipt,
    ) -> None: ...


class CohortDecisionStorePort(Protocol):
    def transaction(
        self,
    ) -> AbstractContextManager[CohortDecisionTransactionPort]: ...


__all__ = [
    "CohortDecisionStorePort",
    "CohortDecisionTransactionPort",
]
