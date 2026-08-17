from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Literal

from pydantic import TypeAdapter

from athena_context.api.domain import (
    Actor,
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
    DemoEvaluationConfigurationError,
    DuplicateDraftError,
    DuplicateVersionError,
    EvaluationFailedClosedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.evaluation_authority import (
    TransactionEvaluationAuthorityUnitOfWork,
    build_evaluation_temporal_validity,
    resolve_transaction_evaluation_authority,
)
from athena_context.api.evaluation_domain import (
    AuthorizedSnapshotPublication,
    DemoEvaluationApproval,
    DemoEvaluationResult,
    VerifiedWc008DeploymentConfiguration,
    build_authorized_publication,
    build_demo_evaluation_result,
    seal_approval_authority,
    seal_evaluation_authority,
)
from athena_context.api.evaluation_ports import (
    EvaluationArtifactPreparation,
    EvaluationCollectionAuthority,
    EvaluationCommitAuthorityCondition,
    EvaluationTrustedKeyAuthority,
    PreparedEvaluationArtifact,
    SealedEvaluationTrustedKeyAuthority,
    StoredEvaluation,
    StoredEvaluationMaterial,
    build_demo_evaluation_candidate_digest,
    build_demo_evaluation_request_digest,
    build_evaluation_collection_authority,
    build_evaluation_evidence_binding_digest,
    seal_evaluation_trusted_key_authority,
)
from athena_context.api.evaluation_verification import (
    validate_evaluation_collection_binding,
    verify_and_evaluate_snapshot_for_publication,
)
from athena_context.api.ports import ClockPort, ContextTransactionPort
from athena_context.api.transaction_lock import InMemoryTransactionLock
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    TrustedKeyAnchor,
)
from athena_context.evidence import (
    CollectorTrustConfiguration,
    EvidenceTransportRequest,
    ValidatedEnvelope,
)


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def _finalize_prepared_evaluation(
    prepared: PreparedEvaluationArtifact,
    *,
    actor: Actor,
    idempotency_key: str,
    request_digest: str,
    candidate_digest: str,
    published_at: datetime,
    trusted_key: SealedEvaluationTrustedKeyAuthority,
    material: StoredEvaluationMaterial,
) -> StoredEvaluation:
    """Sealed, bounded finalizer: no callbacks, lookups, hooks, crypto, or policy."""

    if published_at.microsecond % 1000 != 0:
        raise EvaluationFailedClosedError(
            "authoritative publication time exceeds canonical millisecond "
            "precision"
        )
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

    if (
        not trusted_key.enabled
        or trusted_key.activated_at > published_at
        or (
            trusted_key.retired_at is not None
            and trusted_key.retired_at <= published_at
        )
        or (
            trusted_key.expires_at is not None
            and trusted_key.expires_at <= published_at
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

    return StoredEvaluation(
        actor_id=actor.actor_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        candidate_digest=candidate_digest,
        snapshot_id=snapshot.snapshot_id,
        published_at=published_at,
        material=material,
        envelope_attempt_id=prepared.collection_request.attempt_id,
        envelope=prepared.envelope,
    )


@dataclass(frozen=True, slots=True)
class _NormalizedEvaluationPreparation:
    """Base-model-only inputs serialized and validated before final time."""

    prepared: PreparedEvaluationArtifact
    material: StoredEvaluationMaterial
    evidence_binding_digest: str
    authorized_scope_json: str


_EVIDENCE_SCOPE_ADAPTER: TypeAdapter[EvidenceScope] = TypeAdapter(
    EvidenceScope
)


def _normalize_evaluation_preparation(
    prepared: PreparedEvaluationArtifact,
    condition: EvaluationCommitAuthorityCondition,
) -> _NormalizedEvaluationPreparation:
    """Remove caller subclasses and exercise every untrusted serialization path."""

    # This call is intentionally before the authoritative insertion timestamp:
    # a hostile model override can delay or fail, but can never backdate commit.
    supplied_snapshot_json = prepared.snapshot.canonical_json()
    snapshot = EvidenceSnapshot.model_validate_json(supplied_snapshot_json)
    snapshot_json = snapshot.canonical_json()
    actor = Actor.model_validate_json(
        condition.actor.model_dump_json(by_alias=True)
    )
    publication_actor = Actor.model_validate_json(
        condition.publication_actor.model_dump_json(by_alias=True)
    )
    approval = DemoEvaluationApproval.model_validate_json(
        prepared.approval.model_dump_json(by_alias=True)
    )
    authorized_scope_json = condition.command.authorized_scope.canonical_json()
    authorized_scope = _EVIDENCE_SCOPE_ADAPTER.validate_json(
        authorized_scope_json
    )
    findings = tuple(
        ManifestFinding.model_validate_json(
            finding.model_dump_json(by_alias=True)
        )
        for finding in prepared.findings
    )
    envelope = ValidatedEnvelope.from_payload(
        kind=prepared.envelope.kind,
        digest=prepared.envelope.digest,
        payload=prepared.envelope.payload(),
    )
    collection_request = EvidenceTransportRequest.model_validate_json(
        prepared.collection_request.model_dump_json(by_alias=True)
    )
    assertion = condition.collection_authority.deployment_configuration.assertion
    normalized = PreparedEvaluationArtifact(
        snapshot=snapshot,
        approval=approval,
        resolved_profile_digest=str(prepared.resolved_profile_digest),
        findings=findings,
        collection_request=collection_request,
        envelope=envelope,
        temporal_validity=prepared.temporal_validity,
    )
    evidence_binding_digest = build_evaluation_evidence_binding_digest(
        normalized.snapshot,
        collection_request=normalized.collection_request,
        envelope=normalized.envelope,
    )

    # Exercise publication/result model validation, digest construction, JSON
    # serialization, and round-trip parsing before the final clock read. The
    # sealed finalizer later receives only exact base models and primitives.
    validation_time = snapshot.collected_at
    validation_publication = build_authorized_publication(
        snapshot=snapshot,
        approval=approval,
        publisher=actor,
        publication_actor=publication_actor,
        published_at=validation_time,
        resolved_profile_digest=normalized.resolved_profile_digest,
        endpoint=assertion.azure_mcp_internal_endpoint,
        scope=authorized_scope,
        reason=condition.command.reason,
    )
    validation_result = build_demo_evaluation_result(
        publication=validation_publication,
        snapshot=snapshot,
        findings=findings,
        evaluated_at=validation_time,
    )
    result_json = validation_result.model_dump_json(
        by_alias=True,
        exclude_none=True,
    )
    publication_json = validation_publication.model_dump_json(
        exclude_none=True
    )
    stored_result = DemoEvaluationResult.model_validate_json(result_json)
    stored_snapshot = EvidenceSnapshot.model_validate_json(snapshot_json)
    stored_publication = AuthorizedSnapshotPublication.model_validate_json(
        publication_json
    )
    if (
        stored_result.snapshot.canonical_json()
        != stored_snapshot.canonical_json()
        or stored_result.publication != stored_publication
        or stored_result.publication.snapshot_id != snapshot.snapshot_id
    ):
        raise ValueError(
            "stored evaluation components are not canonically identical"
        )
    return _NormalizedEvaluationPreparation(
        prepared=normalized,
        material=StoredEvaluationMaterial(
            snapshot=snapshot,
            snapshot_json=snapshot_json,
            approval=approval,
            actor=actor,
            publication_actor=publication_actor,
            resolved_profile_digest=normalized.resolved_profile_digest,
            private_mcp_endpoint=assertion.azure_mcp_internal_endpoint,
            authorized_scope=authorized_scope,
            reason=condition.command.reason,
            findings=findings,
        ),
        evidence_binding_digest=evidence_binding_digest,
        authorized_scope_json=authorized_scope.canonical_json(),
    )


def _seal_trusted_key_for_finalization(
    trusted_key: EvaluationTrustedKeyAuthority,
) -> SealedEvaluationTrustedKeyAuthority:
    """Perform every key-record property read before authoritative time."""

    return seal_evaluation_trusted_key_authority(trusted_key)


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
        self.__context_service_evaluation_capability: object | None = None
        self.__evaluation_collection_configuration: (
            tuple[
                VerifiedWc008DeploymentConfiguration,
                CollectorTrustConfiguration,
            ]
            | None
        ) = None

    def transaction(self) -> _MemoryTransaction:
        return _MemoryTransaction(self)

    def _bind_context_service_evaluation_publication(
        self,
        capability: object,
    ) -> None:
        """Bind one opaque capability to this concrete store instance."""

        if self.__context_service_evaluation_capability is not None:
            raise DemoEvaluationConfigurationError(
                "evaluation publication is already bound to a ContextService"
            )
        self.__context_service_evaluation_capability = capability

    def _owns_context_service_evaluation_capability(
        self,
        capability: object,
    ) -> bool:
        return (
            self.__context_service_evaluation_capability is not None
            and capability is self.__context_service_evaluation_capability
        )

    def _bind_context_service_evaluation_collection_authority(
        self,
        capability: object,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        trust_configuration: CollectorTrustConfiguration,
    ) -> None:
        """Pin immutable collection authority beside the publication capability."""

        if not self._owns_context_service_evaluation_capability(capability):
            raise EvaluationFailedClosedError(
                "collection authority requires the owning ContextService capability"
            )
        normalized = (
            VerifiedWc008DeploymentConfiguration.model_validate_json(
                deployment_configuration.model_dump_json(by_alias=True)
            ),
            CollectorTrustConfiguration.model_validate_json(
                trust_configuration.model_dump_json(by_alias=True)
            ),
        )
        if (
            self.__evaluation_collection_configuration is not None
            and self.__evaluation_collection_configuration != normalized
        ):
            raise DemoEvaluationConfigurationError(
                "evaluation collection authority is already bound differently"
            )
        self.__evaluation_collection_configuration = normalized

    def _evaluation_collection_authority(
        self,
        *,
        authorized_scope: EvidenceScope,
    ) -> EvaluationCollectionAuthority:
        configured = self.__evaluation_collection_configuration
        if configured is None:
            raise EvaluationFailedClosedError(
                "evaluation persistence has no bound collection authority"
            )
        configuration, trust = configured
        return build_evaluation_collection_authority(
            configuration,
            trust,
            authorized_scope=authorized_scope,
        )

    def _before_evaluation_commit_timestamp(self) -> None:
        """Test seam for delay inside persistence before authoritative time."""


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
        self.__active_entry_epoch: object | None = None
        self.__evaluation_publication_epoch: object | None = None
        self.__evaluation_publication_capability: object | None = None
        self.__evaluation_publication_consumed = False

    def __enter__(self) -> _MemoryTransaction:
        if self.__active_entry_epoch is not None:
            raise RuntimeError("context transaction is already active")
        self._store._lock.acquire()
        self.__active_entry_epoch = object()
        self.__evaluation_publication_epoch = None
        self.__evaluation_publication_capability = None
        self.__evaluation_publication_consumed = False
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
            self.__evaluation_publication_capability = None
            self.__evaluation_publication_epoch = None
            self.__evaluation_publication_consumed = True
            self.__active_entry_epoch = None
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
        artifact = self._evaluation_receipts.get(
            (actor_id, idempotency_key)
        )
        return None if artifact is None else deepcopy(artifact)

    def get_evaluation_artifact(
        self,
        snapshot_id: str,
    ) -> StoredEvaluation | None:
        artifact = self._evaluation_artifacts.get(snapshot_id)
        return None if artifact is None else deepcopy(artifact)

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

    def _open_context_service_evaluation_publication(
        self,
        service_capability: object,
    ) -> object:
        active_entry_epoch = self.__active_entry_epoch
        if active_entry_epoch is None:
            raise EvaluationFailedClosedError(
                "evaluation publication requires an active transaction entry"
            )
        if not self._store._owns_context_service_evaluation_capability(
            service_capability
        ):
            raise EvaluationFailedClosedError(
                "evaluation publication requires the ContextService-owned "
                "transaction capability"
            )
        if self.__evaluation_publication_capability is not None:
            raise EvaluationFailedClosedError(
                "evaluation publication capability was already opened"
            )
        transaction_capability = object()
        self.__evaluation_publication_capability = transaction_capability
        self.__evaluation_publication_epoch = active_entry_epoch
        return transaction_capability

    def _put_context_service_evaluation(
        self,
        transaction_capability: object,
        condition: EvaluationCommitAuthorityCondition,
        artifact_preparation: EvaluationArtifactPreparation,
    ) -> StoredEvaluation:
        if (
            self.__active_entry_epoch is None
            or self.__evaluation_publication_epoch
            is not self.__active_entry_epoch
            or self.__evaluation_publication_consumed
            or transaction_capability
            is not self.__evaluation_publication_capability
        ):
            raise EvaluationFailedClosedError(
                "evaluation publication requires an unused transaction-bound "
                "ContextService capability"
            )
        self.__evaluation_publication_consumed = True
        clock = self._store._authoritative_clock
        if clock is None:
            raise RuntimeError(
                "evaluation persistence has no authoritative commit clock"
            )
        # All persistence and cryptographic/policy delay happens before the
        # insertion timestamp. Preparation returns immutable data, never an
        # executable post-time callback.
        self._store._before_evaluation_commit_timestamp()
        expected_authority = seal_evaluation_authority(
            condition.expected_authority
        )
        trusted_key = self.get_demo_evaluation_trusted_key(
            condition.trusted_key_anchor
        )
        sealed_trusted_key = (
            None
            if trusted_key is None
            else seal_evaluation_trusted_key_authority(trusted_key)
        )
        if trusted_key is None or sealed_trusted_key is None or (
            sealed_trusted_key.authority != expected_authority.trusted_key
        ):
            raise StaleRevisionError(
                "trusted signing-key authority changed before publication"
            )
        prepared = artifact_preparation(trusted_key)
        if self._store._transaction_generation != self._base_generation:
            raise StaleRevisionError(
                "authoritative persistence changed during evaluation preparation"
            )
        try:
            expected_collection_authority = (
                self._store._evaluation_collection_authority(
                    authorized_scope=condition.command.authorized_scope,
                )
            )
            if expected_collection_authority != condition.collection_authority:
                raise ValueError(
                    "configured Reader assignment revision does not match"
                )
            normalized = _normalize_evaluation_preparation(
                prepared,
                condition,
            )
            validate_evaluation_collection_binding(
                command=condition.command,
                snapshot=normalized.prepared.snapshot,
                collection_request=(
                    normalized.prepared.collection_request
                ),
                envelope=normalized.prepared.envelope,
                collection_authority=expected_collection_authority,
            )
        except (AthenaValidationError, ValueError) as exc:
            raise EvaluationFailedClosedError(
                "prepared evaluation artifact failed canonical validation"
            ) from exc
        prepared = normalized.prepared
        collection_authority = expected_collection_authority
        assertion = collection_authority.deployment_configuration.assertion
        command_scope_json = (
            condition.command.authorized_scope.canonical_json()
        )
        request_digest = build_demo_evaluation_request_digest(
            actor=condition.actor,
            command=condition.command,
            collection_authority=collection_authority,
        )
        if self._store._transaction_generation != self._base_generation:
            raise StaleRevisionError(
                "authoritative persistence changed during evaluation "
                "normalization"
            )
        # Preparation and every untrusted/delay-capable serialization are now
        # complete. Resolve authority from this transaction's current local
        # state so same-UoW mutations cannot evade the generation check.
        authority_checked_at = ensure_timestamp(clock.now())
        authority_unit_of_work = TransactionEvaluationAuthorityUnitOfWork(
            context_transaction=self,
            evaluation_transaction=self,
            reader_actor=condition.reader_actor,
        )
        approval, resolved, authority = (
            resolve_transaction_evaluation_authority(
                authority_unit_of_work,
                actor=condition.actor,
                command=condition.command,
                as_of=authority_checked_at,
                private_mcp_endpoint=(
                    assertion.azure_mcp_internal_endpoint
                ),
                evidence_identity_object_id=(
                    assertion.evidence_identity_object_id
                ),
                trusted_key_anchor=condition.trusted_key_anchor,
                expected_authority=condition.expected_authority,
            )
        )
        current_trusted_key = self.get_demo_evaluation_trusted_key(
            condition.trusted_key_anchor
        )
        expected_temporal_validity = build_evaluation_temporal_validity(
            prepared.snapshot,
            approval=approval,
            resolved_profile=resolved.profile,
            manifest=resolved.view.published.manifest,
            as_of=authority_checked_at,
        )
        if authority_checked_at >= prepared.snapshot.expires_at:
            raise EvaluationFailedClosedError(
                "snapshot became stale before publication"
            )
        authoritative_findings = (
            verify_and_evaluate_snapshot_for_publication(
                snapshot=prepared.snapshot,
                approval=approval,
                publisher=condition.actor,
                publication_actor=condition.publication_actor,
                resolved=resolved,
                private_mcp_endpoint=(
                    assertion.azure_mcp_internal_endpoint
                ),
                authorized_scope=condition.command.authorized_scope,
                reason=condition.command.reason,
                envelope_attempt_id=(
                    prepared.collection_request.attempt_id
                ),
                envelope=prepared.envelope,
                trusted_key=current_trusted_key,
                trusted_key_anchor=condition.trusted_key_anchor,
                as_of=authority_checked_at,
            )
            if current_trusted_key is not None
            else ()
        )
        sealed_current_trusted_key = (
            None
            if current_trusted_key is None
            else _seal_trusted_key_for_finalization(current_trusted_key)
        )
        if (
            current_trusted_key is None
            or sealed_current_trusted_key is None
            or sealed_current_trusted_key.authority
            != expected_authority.trusted_key
            or seal_evaluation_authority(authority)
            != expected_authority
            or seal_approval_authority(
                prepared.approval.authority_token()
            )
            != seal_approval_authority(authority.approval)
            or prepared.resolved_profile_digest
            != resolved.profile.resolved_profile_digest
            or normalized.authorized_scope_json
            != command_scope_json
            or prepared.temporal_validity != expected_temporal_validity
            or prepared.findings != authoritative_findings
        ):
            raise StaleRevisionError(
                "complete evaluation authority or evidence binding changed "
                "before publication"
            )
        if self._store._transaction_generation != self._base_generation:
            raise StaleRevisionError(
                "authoritative persistence changed during final authority check"
            )
        candidate_digest = build_demo_evaluation_candidate_digest(
            request_digest=request_digest,
            authority=authority,
            collection_authority=collection_authority,
            evidence_binding_digest=normalized.evidence_binding_digest,
        )
        published_at = ensure_timestamp(clock.now())
        # No caller-provided or overridable behavior executes after this read.
        # The sealed finalizer only compares primitive captured bounds, binds
        # the timestamp to prevalidated material, and immediately stages the
        # artifact and receipt.
        artifact = _finalize_prepared_evaluation(
            prepared,
            actor=condition.actor,
            idempotency_key=condition.idempotency_key,
            request_digest=request_digest,
            candidate_digest=candidate_digest,
            published_at=published_at,
            trusted_key=sealed_current_trusted_key,
            material=normalized.material,
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
            deepcopy(self._evaluation_artifacts[snapshot_id])
            for snapshot_id in sorted(self._evaluation_artifacts)
        )
