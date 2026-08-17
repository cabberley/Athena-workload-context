from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from threading import RLock
from types import TracebackType
from typing import Literal

from athena_context.api.domain import (
    AuditEvent,
    DraftRecord,
    DraftState,
    MutationReceipt,
    PendingAuditEvent,
    PublishedManifest,
    RoleGrant,
    Supersession,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AlreadySupersededError,
    DemoEvaluationApprovalError,
    DuplicateDraftError,
    DuplicateVersionError,
    EvaluationFailedClosedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.evaluation_domain import (
    AuthorizedSnapshotPublication,
    DemoEvaluationApproval,
    DemoEvaluationResult,
    TrustedKeyAuthorityToken,
    build_authorized_publication,
    build_demo_evaluation_result,
)
from athena_context.api.evaluation_ports import (
    EvaluationArtifactPreparation,
    EvaluationTrustedKeyAuthority,
    PreparedEvaluationArtifact,
    StoredEvaluation,
)
from athena_context.api.ports import ClockPort, ContextTransactionPort
from athena_context.contracts import EvidenceSnapshot, TrustedKeyAnchor


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def _finalize_prepared_evaluation(
    prepared: PreparedEvaluationArtifact,
    *,
    published_at: datetime,
    trusted_key: EvaluationTrustedKeyAuthority,
) -> StoredEvaluation:
    """Sealed, bounded finalizer: no callbacks, lookups, hooks, crypto, or policy."""

    validity = prepared.temporal_validity
    approval = prepared.approval
    snapshot = prepared.snapshot
    if (
        validity.approval_active_from != approval.approved_at
        or validity.approval_expires_at != approval.expires_at
        or approval.status != "authorized"
        or approval.revoked_at is not None
        or not (
            validity.approval_active_from
            <= published_at
            < validity.approval_expires_at
        )
    ):
        raise DemoEvaluationApprovalError(
            "demo evaluation approval is not active at the trusted evaluation time"
        )

    key_record = trusted_key.record
    if (
        not key_record.enabled
        or key_record.activated_at > published_at
        or (
            key_record.retired_at is not None
            and key_record.retired_at <= published_at
        )
        or (
            key_record.expires_at is not None
            and key_record.expires_at <= published_at
        )
        or (
            trusted_key.revoked_at is not None
            and trusted_key.revoked_at <= published_at
        )
    ):
        raise EvaluationFailedClosedError(
            "trusted signing key is disabled, retired, expired, revoked, "
            "or not active at publication time"
        )

    if (
        validity.snapshot_active_from != snapshot.collected_at
        or validity.snapshot_expires_at != snapshot.expires_at
        or not (
            validity.snapshot_active_from
            <= published_at
            < validity.snapshot_expires_at
        )
    ):
        raise EvaluationFailedClosedError(
            "snapshot became stale before publication"
        )
    if (
        validity.governance_active_from is not None
        and published_at < validity.governance_active_from
    ) or (
        validity.governance_expires_at is not None
        and published_at >= validity.governance_expires_at
    ):
        raise EvaluationFailedClosedError(
            "published context/profile is missing, ambiguous, a superseded "
            "context, or has inactive governance"
        )
    if (
        validity.risk_active_from is not None
        and published_at < validity.risk_active_from
    ) or (
        validity.risk_expires_at is not None
        and published_at >= validity.risk_expires_at
    ):
        raise EvaluationFailedClosedError(
            "published context/profile is missing, ambiguous, a superseded "
            "context, or has inactive governance"
        )
    if (
        validity.evidence_fresh_until is not None
        and published_at > validity.evidence_fresh_until
    ):
        raise EvaluationFailedClosedError(
            "policy evidence freshness failed at the authoritative publication time"
        )

    publication = build_authorized_publication(
        snapshot=snapshot,
        approval=approval,
        publisher=prepared.actor,
        publication_actor=prepared.publication_actor,
        published_at=published_at,
        resolved_profile_digest=prepared.resolved_profile_digest,
        endpoint=prepared.private_mcp_endpoint,
        scope=prepared.authorized_scope,
        reason=prepared.reason,
    )
    result = build_demo_evaluation_result(
        publication=publication,
        snapshot=snapshot,
        findings=prepared.findings,
        evaluated_at=published_at,
    )
    artifact = StoredEvaluation(
        actor_id=prepared.actor.actor_id,
        idempotency_key=prepared.idempotency_key,
        request_digest=prepared.request_digest,
        snapshot_id=snapshot.snapshot_id,
        result_json=result.model_dump_json(
            by_alias=True,
            exclude_none=True,
        ),
        snapshot_json=snapshot.canonical_json(),
        publication_json=publication.model_dump_json(exclude_none=True),
        envelope_attempt_id=prepared.envelope_attempt_id,
        envelope=prepared.envelope,
    )
    stored_result = DemoEvaluationResult.model_validate_json(
        artifact.result_json
    )
    stored_snapshot = EvidenceSnapshot.model_validate_json(
        artifact.snapshot_json
    )
    stored_publication = AuthorizedSnapshotPublication.model_validate_json(
        artifact.publication_json
    )
    if (
        stored_result.snapshot.canonical_json()
        != stored_snapshot.canonical_json()
        or stored_result.publication != stored_publication
        or stored_result.publication.snapshot_id != artifact.snapshot_id
    ):
        raise ValueError(
            "stored evaluation components are not canonically identical"
        )
    return artifact


class InMemoryContextStore:
    """Transactional, deterministic in-memory implementation of the storage port."""

    def __init__(
        self,
        *,
        authoritative_clock: ClockPort | None = None,
        demo_evaluation_trusted_key: (
            EvaluationTrustedKeyAuthority | None
        ) = None,
    ) -> None:
        self._transaction_lock = InMemoryTransactionLock()
        self._lock = self._transaction_lock.lock
        self._authoritative_clock = authoritative_clock
        self._drafts: dict[str, DraftRecord] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}
        self._demo_evaluation_approvals: dict[str, DemoEvaluationApproval] = {}
        self._evaluation_grants: tuple[RoleGrant, ...] = ()
        self._evaluation_grant_revision = 0
        self._evaluation_receipts: dict[tuple[str, str], StoredEvaluation] = {}
        self._evaluation_artifacts: dict[str, StoredEvaluation] = {}
        self._demo_evaluation_trusted_keys: dict[
            str,
            EvaluationTrustedKeyAuthority,
        ] = {}
        if demo_evaluation_trusted_key is not None:
            anchor = demo_evaluation_trusted_key.record.anchor
            self._demo_evaluation_trusted_keys[anchor.key_vault_key_id] = (
                demo_evaluation_trusted_key
            )
        self._transaction_generation = 0

    def transaction(self) -> _MemoryTransaction:
        return _MemoryTransaction(self)

    def _before_evaluation_commit_timestamp(self) -> None:
        """Test seam for delay inside persistence before authoritative time."""


class InMemoryTransactionLock:
    """Small internally owned transaction lock for standalone test adapters."""

    def __init__(self) -> None:
        self._lock = RLock()

    @property
    def lock(self) -> RLock:
        return self._lock

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield


class _MemoryTransaction(ContextTransactionPort):
    def __init__(self, store: InMemoryContextStore) -> None:
        self._store = store
        self._drafts: dict[str, DraftRecord] = {}
        self._published: dict[tuple[str, str], PublishedManifest] = {}
        self._supersessions: dict[tuple[str, str], Supersession] = {}
        self._audit: list[AuditEvent] = []
        self._receipts: dict[tuple[str, str], MutationReceipt] = {}
        self._demo_evaluation_approvals: dict[str, DemoEvaluationApproval] = {}
        self._evaluation_grants: tuple[RoleGrant, ...] = ()
        self._evaluation_grant_revision = 0
        self._evaluation_receipts: dict[tuple[str, str], StoredEvaluation] = {}
        self._evaluation_artifacts: dict[str, StoredEvaluation] = {}
        self._demo_evaluation_trusted_keys: dict[
            str,
            EvaluationTrustedKeyAuthority,
        ] = {}
        self._base_generation = 0
        self._dirty = False

    def __enter__(self) -> _MemoryTransaction:
        self._store._lock.acquire()
        self._drafts = dict(self._store._drafts)
        self._published = dict(self._store._published)
        self._supersessions = dict(self._store._supersessions)
        self._audit = list(self._store._audit)
        self._receipts = dict(self._store._receipts)
        self._demo_evaluation_approvals = dict(
            self._store._demo_evaluation_approvals
        )
        self._evaluation_grants = tuple(self._store._evaluation_grants)
        self._evaluation_grant_revision = self._store._evaluation_grant_revision
        self._evaluation_receipts = dict(self._store._evaluation_receipts)
        self._evaluation_artifacts = dict(self._store._evaluation_artifacts)
        self._demo_evaluation_trusted_keys = dict(
            self._store._demo_evaluation_trusted_keys
        )
        self._base_generation = self._store._transaction_generation
        self._dirty = False
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            if exc_type is None:
                if self._store._transaction_generation != self._base_generation:
                    raise StaleRevisionError(
                        "authoritative persistence changed during the transaction"
                    )
                if self._dirty:
                    self._store._drafts = self._drafts
                    self._store._published = self._published
                    self._store._supersessions = self._supersessions
                    self._store._audit = self._audit
                    self._store._receipts = self._receipts
                    self._store._demo_evaluation_approvals = (
                        self._demo_evaluation_approvals
                    )
                    self._store._evaluation_grants = self._evaluation_grants
                    self._store._evaluation_grant_revision = (
                        self._evaluation_grant_revision
                    )
                    self._store._evaluation_receipts = self._evaluation_receipts
                    self._store._evaluation_artifacts = self._evaluation_artifacts
                    self._store._demo_evaluation_trusted_keys = (
                        self._demo_evaluation_trusted_keys
                    )
                    self._store._transaction_generation += 1
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
        self._dirty = True

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
        self._dirty = True

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
        self._dirty = True

    def append_audit(self, event: PendingAuditEvent) -> AuditEvent:
        sequence = len(self._audit) + 1
        stored = AuditEvent(
            **event.model_dump(),
            sequence=sequence,
            event_id=f"audit-{sequence:08d}",
        )
        self._audit.append(stored.model_copy(deep=True))
        self._dirty = True
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
        self._dirty = True

    def get_demo_evaluation_approval(
        self,
        decision_id: str,
    ) -> DemoEvaluationApproval | None:
        approval = self._demo_evaluation_approvals.get(decision_id)
        return None if approval is None else approval.model_copy(deep=True)

    def put_demo_evaluation_approval(
        self,
        approval: DemoEvaluationApproval,
        *,
        expected_revision: int | None,
    ) -> None:
        current = self._demo_evaluation_approvals.get(approval.decision_id)
        if expected_revision is None:
            if current is not None:
                raise DuplicateVersionError(
                    f"demo evaluation approval {approval.decision_id!r} exists"
                )
        elif current is None:
            raise ResourceNotFoundError(
                f"demo evaluation approval {approval.decision_id!r} was not found"
            )
        elif current.revision != expected_revision:
            raise StaleRevisionError(
                f"expected approval revision {expected_revision}, "
                f"found {current.revision}"
            )
        self._demo_evaluation_approvals[approval.decision_id] = (
            approval.model_copy(deep=True)
        )
        self._dirty = True

    def get_evaluation_grants(self) -> tuple[tuple[RoleGrant, ...], int]:
        return (
            tuple(grant.model_copy(deep=True) for grant in self._evaluation_grants),
            self._evaluation_grant_revision,
        )

    def replace_evaluation_grants(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        expected_revision: int,
    ) -> int:
        if self._evaluation_grant_revision != expected_revision:
            raise StaleRevisionError(
                f"expected evaluation grant revision {expected_revision}, "
                f"found {self._evaluation_grant_revision}"
            )
        self._evaluation_grants = tuple(
            grant.model_copy(deep=True) for grant in grants
        )
        self._evaluation_grant_revision += 1
        self._dirty = True
        return self._evaluation_grant_revision

    def get_evaluation_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        return self._evaluation_receipts.get((actor_id, idempotency_key))

    def get_evaluation_artifact(
        self,
        snapshot_id: str,
    ) -> StoredEvaluation | None:
        return self._evaluation_artifacts.get(snapshot_id)

    def get_demo_evaluation_trusted_key(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> EvaluationTrustedKeyAuthority | None:
        authority = self._demo_evaluation_trusted_keys.get(
            trusted_key_anchor.key_vault_key_id
        )
        if (
            authority is None
            or authority.record.anchor != trusted_key_anchor
        ):
            return None
        return authority

    def put_demo_evaluation_trusted_key(
        self,
        authority: EvaluationTrustedKeyAuthority,
        *,
        expected_revision: int,
    ) -> None:
        anchor = authority.record.anchor
        current = self._demo_evaluation_trusted_keys.get(
            anchor.key_vault_key_id
        )
        if current is None:
            raise ResourceNotFoundError(
                "demo evaluation trusted key was not found"
            )
        if current.revision != expected_revision:
            raise StaleRevisionError(
                f"expected trusted key revision {expected_revision}, "
                f"found {current.revision}"
            )
        if authority.revision != expected_revision + 1:
            raise StaleRevisionError(
                "trusted key replacement must use the next revision"
            )
        self._demo_evaluation_trusted_keys[anchor.key_vault_key_id] = authority
        self._dirty = True

    def put_evaluation_conditionally(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
        expected_trusted_key: TrustedKeyAuthorityToken,
        artifact_preparation: EvaluationArtifactPreparation,
    ) -> StoredEvaluation:
        clock = self._store._authoritative_clock
        if clock is None:
            raise RuntimeError(
                "evaluation persistence has no authoritative commit clock"
            )
        # All persistence and cryptographic/policy delay happens before the
        # insertion timestamp. Preparation returns immutable data, never an
        # executable post-time callback.
        self._store._before_evaluation_commit_timestamp()
        trusted_key = self.get_demo_evaluation_trusted_key(
            trusted_key_anchor
        )
        if (
            trusted_key is None
            or trusted_key.authority_token() != expected_trusted_key
        ):
            raise StaleRevisionError(
                "trusted signing-key authority changed before publication"
            )
        prepared = artifact_preparation(trusted_key)
        if self._store._transaction_generation != self._base_generation:
            raise StaleRevisionError(
                "authoritative persistence changed during evaluation preparation"
            )
        published_at = ensure_timestamp(clock.now())
        # No caller-provided or overridable behavior executes after this read.
        # The sealed finalizer only compares captured bounds, builds canonical
        # records, and immediately stages both artifact and receipt.
        artifact = _finalize_prepared_evaluation(
            prepared,
            published_at=published_at,
            trusted_key=trusted_key,
        )
        receipt_key = (artifact.actor_id, artifact.idempotency_key)
        if receipt_key in self._evaluation_receipts:
            raise IdempotencyConflictError(
                "evaluation idempotency key has already been recorded"
            )
        if artifact.snapshot_id in self._evaluation_artifacts:
            raise DuplicateVersionError(
                f"evidence snapshot {artifact.snapshot_id!r} is already published"
            )
        self._evaluation_receipts[receipt_key] = artifact
        self._evaluation_artifacts[artifact.snapshot_id] = artifact
        self._dirty = True
        return artifact

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]:
        return tuple(
            self._evaluation_artifacts[snapshot_id]
            for snapshot_id in sorted(self._evaluation_artifacts)
        )
