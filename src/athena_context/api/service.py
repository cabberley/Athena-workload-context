from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar

from pydantic import ValidationError

from athena_context.api.cohort_decision_domain import (
    CohortDecisionApplyBinding,
    CohortDecisionKind,
    _selector_binding_permits,
)
from athena_context.api.cohort_domain import normalized_identifier
from athena_context.api.domain import (
    Actor,
    ActorKind,
    ApiModel,
    ApprovalDecision,
    AuditAction,
    AuditEvent,
    CreateDraftCommand,
    DraftRecord,
    DraftState,
    MutationReceipt,
    MutationTarget,
    PendingAuditEvent,
    Permission,
    PublicationCandidate,
    PublishCommand,
    PublishedManifest,
    PublishedManifestView,
    ReplaceDraftCommand,
    ReviewSubmission,
    SupersedeCommand,
    Supersession,
    TransitionCommand,
    ValidationRecord,
    VersionComparison,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AlreadySupersededError,
    AmbiguousLookupError,
    DigestMismatchError,
    DuplicateVersionError,
    IdempotencyConflictError,
    InvalidTransitionError,
    ManifestValidationError,
    PersistenceConflictError,
    ResourceNotFoundError,
    StaleApprovalError,
    StaleRevisionError,
    VersionMismatchError,
)
from athena_context.api.ports import (
    AuthorizationPort,
    ClockPort,
    ContextStorePort,
    ContextTransactionPort,
)
from athena_context.api.selector_provenance import (
    DraftSelectorBaseline,
    manifest_selector_provenance,
    selector_role_digests,
)
from athena_context.contracts.common import (
    AthenaValidationError,
    compute_artifact_digest,
)
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    ManifestRole,
    _resolve_manifest_profile_for_cohort_decision,
    canonicalize_manifest_payload,
    resolve_manifest_profile,
    validate_manifest_selector_identity_inheritance,
    validate_manifest_selector_identity_transition,
)

TApiModel = TypeVar("TApiModel", bound=ApiModel)


@dataclass(frozen=True, slots=True)
class _PersistedSelectorAuthority:
    """Selector resolver authority derived only from persisted decisions."""

    bindings: tuple[CohortDecisionApplyBinding, ...]

    def permits_selector_identity_replacement(
        self,
        *,
        manifest_id: str,
        manifest_version: str,
        profile_id: str,
        inherited_role: ManifestRole,
        replacement_role: ManifestRole,
    ) -> bool:
        return any(
            _selector_binding_permits(
                binding,
                manifest_id=manifest_id,
                manifest_version=manifest_version,
                profile_id=profile_id,
                inherited_role=inherited_role,
                replacement_role=replacement_role,
            )
            for binding in self.bindings
        )


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _changed_paths(left: object, right: object, path: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        changes: list[str] = []
        for key in sorted(set(left) | set(right)):
            child_path = f"{path}/{_pointer_token(str(key))}"
            if key not in left or key not in right:
                changes.append(child_path)
            else:
                changes.extend(_changed_paths(left[key], right[key], child_path))
        return changes
    if isinstance(left, list) and isinstance(right, list):
        changes = []
        for index in range(max(len(left), len(right))):
            child_path = f"{path}/{index}"
            if index >= len(left) or index >= len(right):
                changes.append(child_path)
            else:
                changes.extend(_changed_paths(left[index], right[index], child_path))
        return changes
    return [] if left == right else [path or "/"]


class ContextService:
    """Authoritative application service for every manifest state mutation."""

    def __init__(
        self,
        *,
        store: ContextStorePort,
        authorization: AuthorizationPort,
        clock: ClockPort,
        publication_actor: Actor,
    ) -> None:
        if publication_actor.kind is not ActorKind.SERVICE:
            raise ValueError("publication_actor must be a service actor")
        self._store = store
        self._authorization = authorization
        self._clock = clock
        self._publication_actor = publication_actor

    def create_draft(
        self,
        actor: Actor,
        idempotency_key: str,
        command: CreateDraftCommand,
    ) -> DraftRecord:
        manifest_id = command.manifest.manifest_id
        self._authorization.require(actor, Permission.CREATE_DRAFT, manifest_id)

        def create(tx: ContextTransactionPort) -> DraftRecord:
            self._ensure_manifest_digest(command.manifest, command.manifest_digest)
            self._ensure_lineage(
                tx,
                manifest_id=manifest_id,
                new_version=command.manifest.manifest_version,
                previous_version=command.previous_version,
            )
            now = self._now()
            selector_baseline = DraftSelectorBaseline.capture(
                draft_id=command.draft_id,
                manifest=command.manifest,
                manifest_digest=command.manifest_digest,
                actor=actor,
                captured_at=now,
            )
            self._validate_new_draft_selector_baseline(
                tx,
                selector_baseline,
                previous_version=command.previous_version,
            )
            draft = DraftRecord(
                draft_id=command.draft_id,
                manifest_id=manifest_id,
                state=DraftState.DRAFT,
                revision=1,
                manifest=command.manifest,
                manifest_digest=command.manifest_digest,
                previous_version=command.previous_version,
                created_by=actor,
                created_at=now,
                updated_by=actor,
                updated_at=now,
                reason=command.reason,
            )
            tx.put_draft_selector_baseline(selector_baseline)
            tx.put_draft(draft, expected_revision=None)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.DRAFT_CREATED,
                    draft=draft,
                    previous_revision=None,
                    reason=command.reason,
                )
            )
            return draft

        return self._mutate(
            actor,
            idempotency_key,
            "create_draft",
            MutationTarget(
                draft_id=command.draft_id,
                manifest_id=manifest_id,
                manifest_version=command.manifest.manifest_version,
            ),
            command,
            DraftRecord,
            create,
        )

    def replace_draft(
        self,
        actor: Actor,
        draft_id: str,
        idempotency_key: str,
        command: ReplaceDraftCommand,
    ) -> DraftRecord:
        self._authorize_draft(actor, draft_id, Permission.UPDATE_DRAFT)

        def replace(tx: ContextTransactionPort) -> DraftRecord:
            return self.replace_draft_in_transaction(
                tx,
                actor=actor,
                draft_id=draft_id,
                command=command,
            )

        return self._mutate(
            actor,
            idempotency_key,
            "replace_draft",
            MutationTarget(draft_id=draft_id),
            command,
            DraftRecord,
            replace,
        )

    def replace_draft_in_transaction(
        self,
        tx: ContextTransactionPort,
        *,
        actor: Actor,
        draft_id: str,
        command: ReplaceDraftCommand,
        occurred_at: datetime | None = None,
        cohort_decision_id: str | None = None,
    ) -> DraftRecord:
        """Apply WC-007 replacement rules inside a caller-owned atomic transaction."""

        current = self._require_draft(tx, draft_id)
        self._authorization.require(actor, Permission.UPDATE_DRAFT, current.manifest_id)
        self._require_state(current, DraftState.DRAFT)
        self._ensure_expected(
            current,
            command.expected_revision,
            command.expected_manifest_version,
            command.expected_digest,
        )
        if command.replacement_manifest.manifest_id != current.manifest_id:
            raise VersionMismatchError("a replacement cannot change manifestId")
        self._ensure_manifest_digest(
            command.replacement_manifest,
            command.replacement_digest,
        )
        self._ensure_lineage(
            tx,
            manifest_id=current.manifest_id,
            new_version=command.replacement_manifest.manifest_version,
            previous_version=current.previous_version,
        )
        now = self._now() if occurred_at is None else ensure_timestamp(occurred_at)
        selector_baseline = self._require_selector_baseline(tx, current)
        selector_authority = (
            self._persisted_lifecycle_selector_authority(
                tx,
                current=current,
            )
            if cohort_decision_id is None
            else self._require_persisted_cohort_apply(
                tx,
                actor=actor,
                current=current,
                command=command,
                occurred_at=now,
                decision_id=cohort_decision_id,
            )
        )
        self._validate_replacement_profiles(
            current=current,
            replacement=command.replacement_manifest,
            as_of=now,
            selector_baseline=selector_baseline,
            selector_authority=selector_authority,
            selector_change_authorized=cohort_decision_id is not None,
        )
        replacement = current.model_copy(
            update={
                "revision": current.revision + 1,
                "manifest": command.replacement_manifest,
                "manifest_digest": command.replacement_digest,
                "updated_by": actor,
                "updated_at": now,
                "reason": command.reason,
                "validation": None,
                "review": None,
                "approval": None,
            }
        )
        tx.put_draft(replacement, expected_revision=current.revision)
        tx.append_audit(
            self._audit_event(
                now=now,
                actor=actor,
                action=AuditAction.DRAFT_REPLACED,
                draft=replacement,
                previous_revision=current.revision,
                reason=command.reason,
            )
        )
        return replacement

    @staticmethod
    def _validate_replacement_profiles(
        *,
        current: DraftRecord,
        replacement: CanonicalWorkloadManifest,
        as_of: datetime,
        selector_baseline: DraftSelectorBaseline,
        selector_authority: _PersistedSelectorAuthority | None,
        selector_change_authorized: bool,
    ) -> None:
        try:
            current_provenance = manifest_selector_provenance(
                current.manifest
            )
            replacement_provenance = manifest_selector_provenance(
                replacement
            )
            if (
                not selector_change_authorized
                and current_provenance != replacement_provenance
            ):
                raise AthenaValidationError(
                    "ordinary draft replacement cannot alter selector provenance"
                )
            ContextService._validate_manifest_selector_provenance(
                selector_baseline,
                replacement,
                selector_authority,
            )
            if selector_authority is None:
                validate_manifest_selector_identity_transition(
                    current.manifest,
                    replacement,
                )
                validate_manifest_selector_identity_inheritance(
                    replacement,
                )
                return
            for profile in replacement.profiles.values():
                _resolve_manifest_profile_for_cohort_decision(
                    replacement,
                    profile.profile_id,
                    as_of=as_of,
                    selector_capability=selector_authority,
                )
        except (AthenaValidationError, StopIteration) as exc:
            raise ManifestValidationError(
                "replacement manifest profile inheritance is not valid"
            ) from exc

    @staticmethod
    def _require_persisted_cohort_apply(
        tx: ContextTransactionPort,
        *,
        actor: Actor,
        current: DraftRecord,
        command: ReplaceDraftCommand,
        occurred_at: datetime,
        decision_id: str,
    ) -> _PersistedSelectorAuthority:
        """Load and verify immutable decision authority before any mutation."""

        record = tx.get_cohort_decision(current.manifest_id, decision_id)
        authorization = (
            None if record is None else record.apply_authorization
        )
        if authorization is None or record is None:
            raise PersistenceConflictError(
                "cohort draft mutation requires a persisted approved decision"
            )
        binding = authorization.binding
        resulting_revision = current.revision + 1
        matching_audit = next(
            (
                event
                for event in tx.list_audit(manifest_id=current.manifest_id)
                if event.event_id == record.audit.audit_id
            ),
            None,
        )
        if (
            authorization.status != "approved"
            or record.decision
            not in {
                CohortDecisionKind.APPROVE,
                CohortDecisionKind.SPLIT,
                CohortDecisionKind.MERGE,
            }
            or record.decision_id != decision_id
            or record.decided_by != actor
            or record.decided_at != occurred_at
            or record.manifest_id != current.manifest_id
            or record.manifest_version
            != command.replacement_manifest.manifest_version
            or record.candidate_id is None
            or record.candidate_digest is None
            or binding.actor != actor
            or binding.decided_at != occurred_at
            or binding.current_draft.draft_id != current.draft_id
            or binding.current_draft.revision != current.revision
            or binding.current_draft.manifest_digest
            != current.manifest_digest
            or binding.source_draft.draft_id != current.draft_id
            or binding.source_draft.revision > current.revision
            or binding.resulting_draft.draft_id != current.draft_id
            or binding.resulting_draft.revision != resulting_revision
            or binding.resulting_draft.manifest_digest
            != command.replacement_digest
            or record.applied_draft != binding.resulting_draft
            or binding.replacement_manifest_digest
            != command.replacement_digest
            or command.replacement_manifest.compatibility.artifact_digest
            != command.replacement_digest
            or decision_id not in command.reason
            or not authorization.authorizes(command)
            or matching_audit is None
            or matching_audit.action is not AuditAction.COHORT_DECISION_RECORDED
            or matching_audit.actor != actor
            or matching_audit.occurred_at != occurred_at
            or matching_audit.draft_id != current.draft_id
            or matching_audit.revision != resulting_revision
            or matching_audit.manifest_digest != command.replacement_digest
        ):
            raise PersistenceConflictError(
                "persisted cohort decision does not authorize the exact "
                "authenticated draft mutation"
            )
        prior_authority = ContextService._persisted_lifecycle_selector_authority(
            tx,
            current=current,
        )
        bindings = (
            ()
            if prior_authority is None
            else prior_authority.bindings
        )
        return _PersistedSelectorAuthority(
            tuple(
                sorted(
                    (*bindings, binding),
                    key=lambda item: (
                        item.resulting_draft.revision,
                        item.decision_id,
                    ),
                )
            )
        )

    @staticmethod
    def _validate_new_draft_selector_baseline(
        tx: ContextTransactionPort,
        candidate: DraftSelectorBaseline,
        *,
        previous_version: str | None,
    ) -> None:
        same_version = tx.list_draft_selector_baselines(
            manifest_id=candidate.manifest_id,
            manifest_version=candidate.manifest_version,
        )
        if any(
            baseline.selector_provenance_digest
            != candidate.selector_provenance_digest
            or baseline.entries != candidate.entries
            for baseline in same_version
        ):
            raise ManifestValidationError(
                "a fresh draft cannot redefine the immutable selector baseline "
                "for this workload version"
            )
        if same_version:
            return
        expected_entries = None
        if previous_version is not None:
            previous = tx.get_published(
                candidate.manifest_id,
                previous_version,
            )
            if previous is not None:
                expected_entries = manifest_selector_provenance(
                    previous.manifest
                )
        if expected_entries is None:
            workload_baselines = tx.list_draft_selector_baselines(
                manifest_id=candidate.manifest_id,
            )
            if workload_baselines:
                expected_entries = workload_baselines[0].entries
        if (
            expected_entries is not None
            and candidate.entries != expected_entries
        ):
            raise ManifestValidationError(
                "a fresh draft cannot introduce, relocate, or change selectors "
                "outside exact approved cohort provenance"
            )

    @staticmethod
    def _require_selector_baseline(
        tx: ContextTransactionPort,
        current: DraftRecord,
    ) -> DraftSelectorBaseline:
        baseline = tx.get_draft_selector_baseline(current.draft_id)
        if (
            baseline is None
            or baseline.manifest_id != current.manifest_id
            or baseline.manifest_version
            != current.manifest.manifest_version
        ):
            raise PersistenceConflictError(
                "draft selector baseline is missing or inconsistent"
            )
        return baseline

    @staticmethod
    def _validate_manifest_selector_provenance(
        baseline: DraftSelectorBaseline,
        manifest: CanonicalWorkloadManifest,
        authority: _PersistedSelectorAuthority | None,
    ) -> None:
        expected = selector_role_digests(baseline.entries)
        if authority is not None:
            for binding in sorted(
                authority.bindings,
                key=lambda item: (
                    item.resulting_draft.revision,
                    item.decision_id,
                ),
            ):
                expected[
                    (
                        "profile",
                        normalized_identifier(binding.profile_id),
                        normalized_identifier(binding.target_role_id),
                    )
                ] = binding.replacement_selector_provenance_digest
        actual = selector_role_digests(
            manifest_selector_provenance(manifest)
        )
        if actual != expected:
            raise AthenaValidationError(
                "selector identity, variant, semantics, role, and location "
                "must match the immutable baseline and approved provenance"
            )

    def _validate_lifecycle_manifest(
        self,
        tx: ContextTransactionPort,
        *,
        current: DraftRecord,
        manifest: CanonicalWorkloadManifest,
        manifest_digest: str,
        as_of: datetime,
    ) -> None:
        """Resolve every profile before validate, submit, or publish."""

        try:
            validated_manifest = CanonicalWorkloadManifest.model_validate(
                manifest.model_dump(
                    mode="python",
                    by_alias=True,
                    exclude_none=True,
                )
            )
            self._ensure_manifest_digest(validated_manifest, manifest_digest)
        except (ValidationError, ValueError) as exc:
            raise ManifestValidationError(
                "the draft manifest is not valid"
            ) from exc

        baseline = self._require_selector_baseline(tx, current)
        authority = self._persisted_lifecycle_selector_authority(
            tx,
            current=current,
        )
        try:
            self._validate_manifest_selector_provenance(
                baseline,
                validated_manifest,
                authority,
            )
        except AthenaValidationError as exc:
            raise ManifestValidationError(
                "the draft selector provenance is not valid"
            ) from exc
        try:
            validate_manifest_selector_identity_inheritance(
                validated_manifest
            )
            for profile in validated_manifest.profiles.values():
                resolve_manifest_profile(
                    validated_manifest,
                    profile.profile_id,
                    as_of=as_of,
                )
            return
        except AthenaValidationError as generic_error:
            if authority is None:
                raise ManifestValidationError(
                    "the draft manifest profile inheritance is not valid"
                ) from generic_error
            try:
                for profile in validated_manifest.profiles.values():
                    _resolve_manifest_profile_for_cohort_decision(
                        validated_manifest,
                        profile.profile_id,
                        as_of=as_of,
                        selector_capability=authority,
                    )
            except AthenaValidationError as exc:
                raise ManifestValidationError(
                    "the draft manifest profile inheritance is not valid"
                ) from exc

    @staticmethod
    def _persisted_lifecycle_selector_authority(
        tx: ContextTransactionPort,
        *,
        current: DraftRecord,
    ) -> _PersistedSelectorAuthority | None:
        """Recover selector provenance only from immutable applied decisions."""

        applied = [
            decision
            for decision in tx.list_cohort_decisions(
                manifest_id=current.manifest_id,
                draft_id=current.draft_id,
            )
            if decision.manifest_version
            == current.manifest.manifest_version
            and decision.apply_authorization is not None
            and decision.applied_draft is not None
            and decision.applied_draft.revision <= current.revision
            and decision.apply_authorization.status == "approved"
        ]
        if not applied:
            return None
        latest = max(
            applied,
            key=lambda decision: (
                decision.applied_draft.revision
                if decision.applied_draft is not None
                else 0
            ),
        )
        if latest.applied_draft is None:
            return None
        if current.state is DraftState.VALIDATED and (
            current.validation is None
            or current.validation.validated_revision != current.revision
            or current.manifest_digest
            != current.validation.manifest_digest
        ):
            return None
        bindings = tuple(
            sorted(
                (
                    decision.apply_authorization.binding
                    for decision in applied
                    if decision.apply_authorization is not None
                ),
                key=lambda binding: (
                    binding.resulting_draft.revision,
                    binding.decision_id,
                ),
            )
        )
        return _PersistedSelectorAuthority(bindings)

    def validate_draft(
        self,
        actor: Actor,
        draft_id: str,
        idempotency_key: str,
        command: TransitionCommand,
    ) -> DraftRecord:
        self._authorize_draft(actor, draft_id, Permission.VALIDATE)

        def validate(tx: ContextTransactionPort) -> DraftRecord:
            current = self._require_draft(tx, draft_id)
            self._authorization.require(actor, Permission.VALIDATE, current.manifest_id)
            self._require_state(current, DraftState.DRAFT)
            self._ensure_expected_command(current, command)
            now = self._now()
            self._validate_lifecycle_manifest(
                tx,
                current=current,
                manifest=current.manifest,
                manifest_digest=current.manifest_digest,
                as_of=now,
            )
            revision = current.revision + 1
            updated = current.model_copy(
                update={
                    "state": DraftState.VALIDATED,
                    "revision": revision,
                    "updated_by": actor,
                    "updated_at": now,
                    "reason": command.reason,
                    "validation": ValidationRecord(
                        validated_by=actor,
                        validated_at=now,
                        validated_revision=revision,
                        manifest_digest=current.manifest_digest,
                    ),
                }
            )
            tx.put_draft(updated, expected_revision=current.revision)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.DRAFT_VALIDATED,
                    draft=updated,
                    previous_revision=current.revision,
                    reason=command.reason,
                )
            )
            return updated

        return self._mutate(
            actor,
            idempotency_key,
            "validate_draft",
            MutationTarget(draft_id=draft_id),
            command,
            DraftRecord,
            validate,
        )

    def submit_for_review(
        self,
        actor: Actor,
        draft_id: str,
        idempotency_key: str,
        command: TransitionCommand,
    ) -> DraftRecord:
        self._authorize_draft(actor, draft_id, Permission.SUBMIT)

        def submit(tx: ContextTransactionPort) -> DraftRecord:
            current = self._require_draft(tx, draft_id)
            self._authorization.require(actor, Permission.SUBMIT, current.manifest_id)
            self._require_state(current, DraftState.VALIDATED)
            self._ensure_expected_command(current, command)
            now = self._now()
            self._validate_lifecycle_manifest(
                tx,
                current=current,
                manifest=current.manifest,
                manifest_digest=current.manifest_digest,
                as_of=now,
            )
            candidate_manifest = self._finalize_publication_candidate(
                current.manifest,
                finalized_at=now,
            )
            candidate_digest = candidate_manifest.compatibility.artifact_digest
            self._validate_lifecycle_manifest(
                tx,
                current=current,
                manifest=candidate_manifest,
                manifest_digest=candidate_digest,
                as_of=now,
            )
            revision = current.revision + 1
            updated = current.model_copy(
                update={
                    "state": DraftState.IN_REVIEW,
                    "revision": revision,
                    "manifest": candidate_manifest,
                    "manifest_digest": candidate_digest,
                    "updated_by": actor,
                    "updated_at": now,
                    "reason": command.reason,
                    "review": ReviewSubmission(
                        submitted_by=actor,
                        submitted_at=now,
                        submitted_revision=revision,
                        publication_candidate_digest=candidate_digest,
                        reason=command.reason,
                    ),
                    "publication_candidate": PublicationCandidate(
                        finalized_by=self._publication_actor,
                        finalized_at=now,
                        manifest_version=candidate_manifest.manifest_version,
                        manifest_digest=candidate_digest,
                        semantic_digest=(
                            candidate_manifest.compatibility.semantic_digest
                        ),
                        approval_status="approved",
                    ),
                }
            )
            tx.put_draft(updated, expected_revision=current.revision)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.REVIEW_SUBMITTED,
                    draft=updated,
                    previous_revision=current.revision,
                    reason=command.reason,
                    publication_actor=self._publication_actor,
                    publication_timestamp=now,
                )
            )
            return updated

        return self._mutate(
            actor,
            idempotency_key,
            "submit_for_review",
            MutationTarget(draft_id=draft_id),
            command,
            DraftRecord,
            submit,
        )

    def approve_draft(
        self,
        actor: Actor,
        draft_id: str,
        idempotency_key: str,
        command: TransitionCommand,
    ) -> DraftRecord:
        self._authorize_draft(actor, draft_id, Permission.APPROVE)

        def approve(tx: ContextTransactionPort) -> DraftRecord:
            current = self._require_draft(tx, draft_id)
            self._authorization.require(actor, Permission.APPROVE, current.manifest_id)
            self._require_state(current, DraftState.IN_REVIEW)
            self._ensure_expected_command(current, command)
            self._require_current_publication_candidate(current)
            now = self._now()
            self._validate_lifecycle_manifest(
                tx,
                current=current,
                manifest=current.manifest,
                manifest_digest=current.manifest_digest,
                as_of=now,
            )
            revision = current.revision + 1
            decision = ApprovalDecision(
                decision_id=f"{current.draft_id}-r{revision}-approval",
                approved_by=actor,
                approved_at=now,
                approved_revision=revision,
                manifest_version=current.manifest.manifest_version,
                manifest_digest=current.manifest_digest,
                reason=command.reason,
            )
            updated = current.model_copy(
                update={
                    "state": DraftState.APPROVED,
                    "revision": revision,
                    "updated_by": actor,
                    "updated_at": now,
                    "reason": command.reason,
                    "approval": decision,
                }
            )
            tx.put_draft(updated, expected_revision=current.revision)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.DRAFT_APPROVED,
                    draft=updated,
                    previous_revision=current.revision,
                    reason=command.reason,
                )
            )
            return updated

        return self._mutate(
            actor,
            idempotency_key,
            "approve_draft",
            MutationTarget(draft_id=draft_id),
            command,
            DraftRecord,
            approve,
        )

    def publish_draft(
        self,
        actor: Actor,
        draft_id: str,
        idempotency_key: str,
        command: PublishCommand,
    ) -> PublishedManifest:
        self._authorize_draft(actor, draft_id, Permission.PUBLISH)

        def publish(tx: ContextTransactionPort) -> PublishedManifest:
            current = self._require_draft(tx, draft_id)
            self._authorization.require(actor, Permission.PUBLISH, current.manifest_id)
            self._require_state(current, DraftState.APPROVED)
            self._ensure_expected_command(current, command)
            candidate = self._require_current_publication_candidate(current)
            approval = current.approval
            if (
                approval is None
                or approval.decision_id != command.approval_id
                or approval.approved_revision != current.revision
                or approval.manifest_version != current.manifest.manifest_version
                or approval.manifest_digest != current.manifest_digest
            ):
                raise StaleApprovalError("the approval does not authorize this draft revision")
            now = self._now()
            self._validate_lifecycle_manifest(
                tx,
                current=current,
                manifest=current.manifest,
                manifest_digest=current.manifest_digest,
                as_of=now,
            )
            if (
                tx.get_published(current.manifest_id, current.manifest.manifest_version)
                is not None
            ):
                raise DuplicateVersionError("the manifest version is already published")
            self._ensure_lineage(
                tx,
                manifest_id=current.manifest_id,
                new_version=current.manifest.manifest_version,
                previous_version=current.previous_version,
            )
            revision = current.revision + 1
            published = PublishedManifest(
                manifest_id=current.manifest_id,
                manifest_version=current.manifest.manifest_version,
                manifest_digest=current.manifest_digest,
                manifest=current.manifest,
                source_draft_id=current.draft_id,
                source_draft_revision=revision,
                previous_version=current.previous_version,
                approval=approval,
                published_by=self._publication_actor,
                published_at=candidate.finalized_at,
                publication_authorized_by=actor,
                publication_authorized_at=now,
                reason=command.reason,
            )
            updated = current.model_copy(
                update={
                    "state": DraftState.PUBLISHED,
                    "revision": revision,
                    "updated_by": actor,
                    "updated_at": now,
                    "reason": command.reason,
                }
            )
            tx.put_published(published)
            tx.put_draft(updated, expected_revision=current.revision)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.VERSION_PUBLISHED,
                    draft=updated,
                    previous_revision=current.revision,
                    reason=command.reason,
                    publication_actor=self._publication_actor,
                    publication_timestamp=candidate.finalized_at,
                )
            )
            return published

        return self._mutate(
            actor,
            idempotency_key,
            "publish_draft",
            MutationTarget(draft_id=draft_id),
            command,
            PublishedManifest,
            publish,
        )

    def supersede_version(
        self,
        actor: Actor,
        manifest_id: str,
        superseded_version: str,
        idempotency_key: str,
        command: SupersedeCommand,
    ) -> Supersession:
        self._authorization.require(actor, Permission.SUPERSEDE, manifest_id)

        def supersede(tx: ContextTransactionPort) -> Supersession:
            published = self._require_published(tx, manifest_id, superseded_version)
            source = self._require_draft(tx, published.source_draft_id)
            self._require_state(source, DraftState.PUBLISHED)
            self._ensure_expected(
                source,
                command.expected_revision,
                command.expected_manifest_version,
                command.expected_digest,
            )
            if command.expected_manifest_version != superseded_version:
                raise VersionMismatchError("expected version does not match the superseded version")
            if tx.get_supersession(manifest_id, superseded_version) is not None:
                raise AlreadySupersededError("the manifest version is already superseded")
            replacement = self._require_published(
                tx,
                manifest_id,
                command.replacement_version,
            )
            if replacement.manifest_digest != command.replacement_digest:
                raise DigestMismatchError("replacement manifest digest does not match")
            if replacement.previous_version != superseded_version:
                raise VersionMismatchError(
                    "replacement previous_version does not reference the superseded version"
                )
            if replacement.manifest_version == superseded_version:
                raise VersionMismatchError("a version cannot supersede itself")
            now = self._now()
            relation = Supersession(
                manifest_id=manifest_id,
                superseded_version=superseded_version,
                replacement_version=replacement.manifest_version,
                superseded_by=actor,
                superseded_at=now,
                reason=command.reason,
            )
            revision = source.revision + 1
            updated = source.model_copy(
                update={
                    "state": DraftState.SUPERSEDED,
                    "revision": revision,
                    "updated_by": actor,
                    "updated_at": now,
                    "reason": command.reason,
                }
            )
            tx.put_supersession(relation)
            tx.put_draft(updated, expected_revision=source.revision)
            tx.append_audit(
                self._audit_event(
                    now=now,
                    actor=actor,
                    action=AuditAction.VERSION_SUPERSEDED,
                    draft=updated,
                    previous_revision=source.revision,
                    reason=command.reason,
                    replacement_version=replacement.manifest_version,
                )
            )
            return relation

        return self._mutate(
            actor,
            idempotency_key,
            "supersede_version",
            MutationTarget(
                manifest_id=manifest_id,
                manifest_version=superseded_version,
            ),
            command,
            Supersession,
            supersede,
        )

    def get_draft(self, actor: Actor, draft_id: str) -> DraftRecord:
        with self._store.transaction() as tx:
            draft = self._require_draft(tx, draft_id)
            self._authorization.require(actor, Permission.READ, draft.manifest_id)
            return draft

    def list_drafts(
        self,
        actor: Actor,
        *,
        manifest_id: str | None = None,
        state: DraftState | None = None,
    ) -> list[DraftRecord]:
        self._authorization.require(actor, Permission.LIST, manifest_id)
        with self._store.transaction() as tx:
            return tx.list_drafts(manifest_id=manifest_id, state=state)

    def get_published(
        self,
        actor: Actor,
        manifest_version: str,
        *,
        manifest_id: str | None = None,
    ) -> PublishedManifestView:
        with self._store.transaction() as tx:
            if manifest_id is None:
                self._authorization.require(actor, Permission.LIST, None)
                matches = [
                    item
                    for item in tx.list_published()
                    if item.manifest_version == manifest_version
                ]
                if len(matches) > 1:
                    raise AmbiguousLookupError(
                        "manifest_id is required because the version is ambiguous"
                    )
                if not matches:
                    raise ResourceNotFoundError(
                        f"manifest version {manifest_version!r} was not found"
                    )
                published = matches[0]
            else:
                published = self._require_published(tx, manifest_id, manifest_version)
            self._authorization.require(actor, Permission.READ, published.manifest_id)
            return PublishedManifestView(
                published=published,
                supersession=tx.get_supersession(
                    published.manifest_id,
                    published.manifest_version,
                ),
            )

    def list_published(self, actor: Actor, manifest_id: str) -> list[PublishedManifestView]:
        self._authorization.require(actor, Permission.LIST, manifest_id)
        with self._store.transaction() as tx:
            return [
                PublishedManifestView(
                    published=item,
                    supersession=tx.get_supersession(
                        item.manifest_id,
                        item.manifest_version,
                    ),
                )
                for item in tx.list_published(manifest_id=manifest_id)
            ]

    def compare_versions(
        self,
        actor: Actor,
        manifest_id: str,
        from_version: str,
        to_version: str,
    ) -> VersionComparison:
        self._authorization.require(actor, Permission.READ, manifest_id)
        with self._store.transaction() as tx:
            left = self._require_published(tx, manifest_id, from_version)
            right = self._require_published(tx, manifest_id, to_version)
        paths = _changed_paths(
            left.manifest.model_dump(mode="json", by_alias=True),
            right.manifest.model_dump(mode="json", by_alias=True),
        )
        return VersionComparison(
            manifest_id=manifest_id,
            from_version=from_version,
            to_version=to_version,
            from_digest=left.manifest_digest,
            to_digest=right.manifest_digest,
            equivalent=left.manifest_digest == right.manifest_digest,
            changed_paths=paths,
        )

    def audit_history(self, actor: Actor, manifest_id: str) -> list[AuditEvent]:
        self._authorization.require(actor, Permission.AUDIT, manifest_id)
        with self._store.transaction() as tx:
            return tx.list_audit(manifest_id=manifest_id)

    def _mutate(
        self,
        actor: Actor,
        idempotency_key: str,
        operation: str,
        target: MutationTarget,
        command: ApiModel,
        response_type: type[TApiModel],
        mutation: Callable[[ContextTransactionPort], TApiModel],
    ) -> TApiModel:
        request_digest = compute_artifact_digest(
            {
                "operation": operation,
                "actorId": actor.actor_id,
                "target": target.model_dump(
                    mode="json",
                    exclude_none=True,
                ),
                "command": command.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
            }
        )
        with self._store.transaction() as tx:
            receipt = tx.get_receipt(actor.actor_id, idempotency_key)
            if receipt is not None:
                if (
                    receipt.operation != operation
                    or receipt.target != target
                    or receipt.request_digest != request_digest
                    or receipt.response_type != response_type.__name__
                ):
                    raise IdempotencyConflictError(
                        "idempotency key was used for a different mutation"
                    )
                return response_type.model_validate_json(receipt.response_json)
            result = mutation(tx)
            tx.put_receipt(
                MutationReceipt(
                    actor_id=actor.actor_id,
                    idempotency_key=idempotency_key,
                    operation=operation,
                    target=target,
                    request_digest=request_digest,
                    response_type=response_type.__name__,
                    response_json=result.model_dump_json(
                        by_alias=True,
                        exclude_none=True,
                    ),
                )
            )
            return result

    def _now(self) -> datetime:
        return ensure_timestamp(self._clock.now())

    def _authorize_draft(
        self,
        actor: Actor,
        draft_id: str,
        permission: Permission,
    ) -> None:
        with self._store.transaction() as tx:
            draft = self._require_draft(tx, draft_id)
            self._authorization.require(actor, permission, draft.manifest_id)

    @staticmethod
    def _require_draft(tx: ContextTransactionPort, draft_id: str) -> DraftRecord:
        draft = tx.get_draft(draft_id)
        if draft is None:
            raise ResourceNotFoundError(f"draft {draft_id!r} was not found")
        return draft

    @staticmethod
    def _require_published(
        tx: ContextTransactionPort,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest:
        published = tx.get_published(manifest_id, manifest_version)
        if published is None:
            raise ResourceNotFoundError(
                f"manifest version {manifest_id}/{manifest_version} was not found"
            )
        return published

    @staticmethod
    def _require_state(draft: DraftRecord, required: DraftState) -> None:
        if draft.state is not required:
            raise InvalidTransitionError(
                f"draft state {draft.state.value!r} cannot perform transition "
                f"requiring {required.value!r}"
            )

    @staticmethod
    def _ensure_expected(
        draft: DraftRecord,
        expected_revision: int,
        expected_manifest_version: str,
        expected_digest: str,
    ) -> None:
        if draft.revision != expected_revision:
            raise StaleRevisionError(
                f"expected draft revision {expected_revision}, found {draft.revision}"
            )
        if draft.manifest.manifest_version != expected_manifest_version:
            raise VersionMismatchError("expected manifest version does not match the draft")
        if draft.manifest_digest != expected_digest:
            raise DigestMismatchError("expected manifest digest does not match the draft")

    @classmethod
    def _ensure_expected_command(
        cls,
        draft: DraftRecord,
        command: TransitionCommand,
    ) -> None:
        cls._ensure_expected(
            draft,
            command.expected_revision,
            command.expected_manifest_version,
            command.expected_digest,
        )

    @staticmethod
    def _ensure_manifest_digest(
        manifest: CanonicalWorkloadManifest,
        supplied_digest: str,
    ) -> None:
        computed = manifest.compute_artifact_digest_value()
        if (
            manifest.compatibility.artifact_digest != computed
            or supplied_digest != computed
        ):
            raise DigestMismatchError("manifest digest does not match the canonical manifest")

    def _finalize_publication_candidate(
        self,
        manifest: CanonicalWorkloadManifest,
        *,
        finalized_at: datetime,
    ) -> CanonicalWorkloadManifest:
        payload = manifest.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        payload["audit"] = {
            "publishedBy": self._publication_actor.actor_id,
            "publishedAt": finalized_at,
            "approvalStatus": "approved",
        }
        try:
            finalized_payload = canonicalize_manifest_payload(payload)
            return CanonicalWorkloadManifest.model_validate(finalized_payload)
        except (ValidationError, ValueError) as exc:
            raise ManifestValidationError(
                "the server could not finalize the publication candidate"
            ) from exc

    def _require_current_publication_candidate(
        self,
        draft: DraftRecord,
    ) -> PublicationCandidate:
        candidate = draft.publication_candidate
        audit = draft.manifest.audit
        if (
            candidate is None
            or draft.review is None
            or candidate.finalized_by != self._publication_actor
            or candidate.manifest_version != draft.manifest.manifest_version
            or candidate.manifest_digest != draft.manifest_digest
            or candidate.semantic_digest
            != draft.manifest.compatibility.semantic_digest
            or candidate.approval_status != "approved"
            or draft.review.publication_candidate_digest != draft.manifest_digest
            or audit.published_by != self._publication_actor.actor_id
            or audit.published_at != candidate.finalized_at
            or audit.approval_status != candidate.approval_status
        ):
            raise StaleApprovalError(
                "the publication candidate provenance does not match this draft"
            )
        self._ensure_manifest_digest(draft.manifest, draft.manifest_digest)
        return candidate

    @staticmethod
    def _ensure_lineage(
        tx: ContextTransactionPort,
        *,
        manifest_id: str,
        new_version: str,
        previous_version: str | None,
    ) -> None:
        published = tx.list_published(manifest_id=manifest_id)
        active = [
            item
            for item in published
            if tx.get_supersession(manifest_id, item.manifest_version) is None
        ]
        if len(active) > 1:
            raise AmbiguousLookupError("published version lineage has multiple active versions")
        if active:
            current = active[0]
            if previous_version != current.manifest_version:
                raise VersionMismatchError(
                    "previous_version must identify the active published version"
                )
            if _version_key(new_version) <= _version_key(current.manifest_version):
                raise VersionMismatchError(
                    "new manifest version must be greater than previous_version"
                )
        elif previous_version is not None:
            raise VersionMismatchError("previous_version does not identify an active version")

    @staticmethod
    def _audit_event(
        *,
        now: datetime,
        actor: Actor,
        action: AuditAction,
        draft: DraftRecord,
        previous_revision: int | None,
        reason: str,
        replacement_version: str | None = None,
        publication_actor: Actor | None = None,
        publication_timestamp: datetime | None = None,
    ) -> PendingAuditEvent:
        return PendingAuditEvent(
            occurred_at=now,
            actor=actor,
            action=action,
            manifest_id=draft.manifest_id,
            draft_id=draft.draft_id,
            revision=draft.revision,
            previous_revision=previous_revision,
            manifest_version=draft.manifest.manifest_version,
            previous_version=draft.previous_version,
            replacement_version=replacement_version,
            publication_actor=publication_actor,
            publication_timestamp=publication_timestamp,
            manifest_digest=draft.manifest_digest,
            reason=reason,
        )
