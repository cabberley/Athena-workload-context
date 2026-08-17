from __future__ import annotations

from threading import RLock
from types import TracebackType
from typing import Literal

from athena_context.api.cohort_decision_domain import (
    CohortDecisionReceipt,
    CohortDecisionRecord,
    CohortProposalSetVersion,
)
from athena_context.api.domain import (
    AuditEvent,
    DraftRecord,
    DraftState,
    MutationReceipt,
    PendingAuditEvent,
    PublishedManifest,
    Supersession,
)
from athena_context.api.errors import (
    AlreadySupersededError,
    DuplicateDraftError,
    DuplicateVersionError,
    IdempotencyConflictError,
    PersistenceConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.ports import ContextTransactionPort
from athena_context.api.selector_provenance import DraftSelectorBaseline


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def _cohort_overlap_binding_key(
    version: CohortProposalSetVersion,
) -> tuple[str, str, str, str, str, str]:
    """Stable authority identity; mutable draft coordinates are deliberately absent."""

    return version.authority_overlap_identity()


def _cohort_selected_version_key(
    version: CohortProposalSetVersion,
) -> tuple[str, ...]:
    return version.authority_selected_identity()


class InMemoryContextStore:
    """Transactional in-memory adapter for WC-007 and cohort decision ports."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._drafts: dict[str, DraftRecord] = {}
        self._draft_selector_baselines: dict[str, DraftSelectorBaseline] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}
        self._cohort_decisions: dict[tuple[str, str], CohortDecisionRecord] = {}
        self._cohort_decision_versions: dict[
            tuple[str, ...],
            tuple[str, str],
        ] = {}
        self._cohort_decision_receipts: dict[
            tuple[str, str],
            CohortDecisionReceipt,
        ] = {}

    def transaction(self) -> _MemoryTransaction:
        return _MemoryTransaction(self)


class _MemoryTransaction(ContextTransactionPort):
    def __init__(self, store: InMemoryContextStore) -> None:
        self._store = store
        self._drafts: dict[str, DraftRecord] = {}
        self._draft_selector_baselines: dict[str, DraftSelectorBaseline] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}
        self._cohort_decisions: dict[tuple[str, str], CohortDecisionRecord] = {}
        self._cohort_decision_versions: dict[
            tuple[str, ...],
            tuple[str, str],
        ] = {}
        self._cohort_decision_receipts: dict[
            tuple[str, str],
            CohortDecisionReceipt,
        ] = {}

    def __enter__(self) -> _MemoryTransaction:
        self._store._lock.acquire()
        self._drafts = dict(self._store._drafts)
        self._draft_selector_baselines = dict(
            self._store._draft_selector_baselines
        )
        self._published = dict(self._store._published)
        self._supersessions = dict(self._store._supersessions)
        self._audit = list(self._store._audit)
        self._receipts = dict(self._store._receipts)
        self._cohort_decisions = dict(self._store._cohort_decisions)
        self._cohort_decision_versions = dict(
            self._store._cohort_decision_versions
        )
        self._cohort_decision_receipts = dict(
            self._store._cohort_decision_receipts
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            if exc_type is None:
                self._store._drafts = self._drafts
                self._store._draft_selector_baselines = (
                    self._draft_selector_baselines
                )
                self._store._published = self._published
                self._store._supersessions = self._supersessions
                self._store._audit = self._audit
                self._store._receipts = self._receipts
                self._store._cohort_decisions = self._cohort_decisions
                self._store._cohort_decision_versions = (
                    self._cohort_decision_versions
                )
                self._store._cohort_decision_receipts = (
                    self._cohort_decision_receipts
                )
        finally:
            self._store._lock.release()
        return False

    def get_draft(self, draft_id: str) -> DraftRecord | None:
        draft = self._drafts.get(draft_id)
        return None if draft is None else draft.model_copy(deep=True)

    def list_drafts(
        self,
        *,
        manifest_id: str | None = None,
        state: DraftState | None = None,
    ) -> list[DraftRecord]:
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
        self._drafts[draft.draft_id] = draft.model_copy(deep=True)

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
        if baseline.draft_id in self._draft_selector_baselines:
            raise PersistenceConflictError(
                "draft selector baseline is immutable"
            )
        self._draft_selector_baselines[baseline.draft_id] = (
            baseline.model_copy(deep=True)
        )

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest | None:
        published = self._published.get((manifest_id, manifest_version))
        return None if published is None else published.model_copy(deep=True)

    def list_published(self, *, manifest_id: str | None = None) -> list[PublishedManifest]:
        matches = sorted(
            (
                item
                for item in self._published.values()
                if manifest_id is None or item.manifest_id == manifest_id
            ),
            key=lambda item: (item.manifest_id, _version_key(item.manifest_version)),
        )
        return [item.model_copy(deep=True) for item in matches]

    def put_published(self, published: PublishedManifest) -> None:
        key = (published.manifest_id, published.manifest_version)
        if key in self._published:
            raise DuplicateVersionError(
                f"manifest version {published.manifest_id}/{published.manifest_version} exists"
            )
        self._published[key] = published.model_copy(deep=True)

    def get_supersession(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> Supersession | None:
        supersession = self._supersessions.get((manifest_id, manifest_version))
        return None if supersession is None else supersession.model_copy(deep=True)

    def put_supersession(self, supersession: Supersession) -> None:
        key = (supersession.manifest_id, supersession.superseded_version)
        if key in self._supersessions:
            raise AlreadySupersededError(
                f"manifest version {supersession.superseded_version} is already superseded"
            )
        self._supersessions[key] = supersession.model_copy(deep=True)

    def append_audit(self, event: PendingAuditEvent) -> AuditEvent:
        sequence = len(self._audit) + 1
        stored = AuditEvent(
            **event.model_dump(),
            sequence=sequence,
            event_id=f"audit-{sequence:08d}",
        )
        self._audit.append(stored.model_copy(deep=True))
        return stored

    def list_audit(self, *, manifest_id: str) -> list[AuditEvent]:
        return [
            event.model_copy(deep=True)
            for event in self._audit
            if event.manifest_id == manifest_id
        ]

    def get_receipt(self, actor_id: str, idempotency_key: str) -> MutationReceipt | None:
        receipt = self._receipts.get((actor_id, idempotency_key))
        return None if receipt is None else receipt.model_copy(deep=True)

    def put_receipt(self, receipt: MutationReceipt) -> None:
        key = (receipt.actor_id, receipt.idempotency_key)
        if key in self._receipts:
            raise IdempotencyConflictError("idempotency key has already been recorded")
        self._receipts[key] = receipt.model_copy(deep=True)

    def get_cohort_decision(
        self,
        manifest_id: str,
        decision_id: str,
    ) -> CohortDecisionRecord | None:
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
        binding_key = _cohort_overlap_binding_key(version)
        selected = set(version.source_proposal_ids)
        matches = sorted(
            (
                decision
                for decision in self._cohort_decisions.values()
                if _cohort_overlap_binding_key(decision.proposal_set_version())
                == binding_key
                and selected.intersection(decision.source_proposal_ids)
            ),
            key=lambda decision: (decision.decided_at, decision.decision_id),
        )
        return [decision.model_copy(deep=True) for decision in matches]

    def put_cohort_decision(self, decision: CohortDecisionRecord) -> None:
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
        if self.list_overlapping_cohort_decisions(version):
            raise PersistenceConflictError(
                "an overlapping selected proposal already has an authoritative decision"
            )
        self._cohort_decisions[decision_key] = decision.model_copy(deep=True)
        self._cohort_decision_versions[version_key] = decision_key

    def get_cohort_decision_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> CohortDecisionReceipt | None:
        receipt = self._cohort_decision_receipts.get(
            (actor_id, idempotency_key)
        )
        return None if receipt is None else receipt.model_copy(deep=True)

    def put_cohort_decision_receipt(
        self,
        receipt: CohortDecisionReceipt,
    ) -> None:
        key = (receipt.actor_id, receipt.idempotency_key)
        if key in self._cohort_decision_receipts:
            raise IdempotencyConflictError(
                "cohort decision idempotency key has already been recorded"
            )
        self._cohort_decision_receipts[key] = receipt.model_copy(deep=True)
