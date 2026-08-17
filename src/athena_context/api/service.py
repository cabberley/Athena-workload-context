from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TypeVar

from pydantic import ValidationError

from athena_context.api.authorization import authorize_role_grants
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
    RoleGrant,
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
    ResourceNotFoundError,
    StaleApprovalError,
    StaleRevisionError,
    VersionMismatchError,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    DemoEvaluationApproval,
    PublishedContextSelection,
    ResolvedPublishedContext,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    EvaluationAuthorityTransactionPort,
    EvaluationAuthorityUnitOfWorkPort,
    StoredEvaluation,
)
from athena_context.api.ports import (
    AuthorizationPort,
    ClockPort,
    ContextStorePort,
    ContextTransactionPort,
)
from athena_context.contracts import resolve_manifest_profile
from athena_context.contracts.common import compute_artifact_digest
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
)

TApiModel = TypeVar("TApiModel", bound=ApiModel)
TUnitOfWorkResult = TypeVar("TUnitOfWorkResult")


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


class _ContextServiceEvaluationAuthorityUnitOfWork:
    """Narrow evaluation view over one transaction opened by ContextService."""

    def __init__(
        self,
        *,
        context_transaction: ContextTransactionPort,
        evaluation_transaction: EvaluationAuthorityTransactionPort,
        authorization: AuthorizationPort,
        reader_actor: Actor,
    ) -> None:
        self._context_transaction = context_transaction
        self._evaluation_transaction = evaluation_transaction
        self._authorization = authorization
        self._reader_actor = reader_actor

    def resolve_context(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        tx = self._context_transaction
        if selection.manifest_version is None:
            self._authorization.require(
                self._reader_actor,
                Permission.LIST,
                selection.manifest_id,
            )
            active = [
                item
                for item in tx.list_published(manifest_id=selection.manifest_id)
                if tx.get_supersession(
                    item.manifest_id,
                    item.manifest_version,
                )
                is None
            ]
            if not active:
                raise ResourceNotFoundError(
                    "published manifest has no active version"
                )
            if len(active) != 1:
                raise AmbiguousLookupError(
                    "published manifest has multiple active versions"
                )
            published = active[0]
        else:
            published = self._require_published(
                tx,
                selection.manifest_id,
                selection.manifest_version,
            )
            self._authorization.require(
                self._reader_actor,
                Permission.READ,
                selection.manifest_id,
            )
        view = PublishedManifestView(
            published=published,
            supersession=tx.get_supersession(
                published.manifest_id,
                published.manifest_version,
            ),
        )
        profile = resolve_manifest_profile(
            published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
        return ResolvedPublishedContext(
            view=view,
            profile=profile,
            authority_token=build_published_context_authority_token(
                view,
                profile,
                requested_manifest_version=selection.manifest_version,
            ),
        )

    def resolve_approval(
        self,
        decision_id: str,
    ) -> DemoEvaluationApproval | None:
        return self._evaluation_transaction.get_demo_evaluation_approval(
            decision_id
        )

    def put_approval(
        self,
        approval: DemoEvaluationApproval,
        *,
        expected_revision: int | None,
    ) -> None:
        self._evaluation_transaction.put_demo_evaluation_approval(
            approval,
            expected_revision=expected_revision,
        )

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken:
        grants, revision = self._evaluation_transaction.get_evaluation_grants()
        return authorize_role_grants(
            actor,
            permission,
            manifest_id,
            grants=grants,
            grant_revision=revision,
        )

    def get_grants(self) -> tuple[tuple[RoleGrant, ...], int]:
        return self._evaluation_transaction.get_evaluation_grants()

    def replace_grants(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        expected_revision: int,
    ) -> int:
        return self._evaluation_transaction.replace_evaluation_grants(
            grants,
            expected_revision=expected_revision,
        )

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        return self._evaluation_transaction.get_evaluation_receipt(
            actor_id,
            idempotency_key,
        )

    def load_artifact(self, snapshot_id: str) -> StoredEvaluation | None:
        return self._evaluation_transaction.get_evaluation_artifact(snapshot_id)

    def insert_evaluation(self, artifact: StoredEvaluation) -> None:
        self._evaluation_transaction.put_evaluation(artifact)

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]:
        return self._evaluation_transaction.list_evaluations()

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

    def run_evaluation_authority_transaction(
        self,
        *,
        reader_actor: Actor,
        operation: Callable[
            [EvaluationAuthorityUnitOfWorkPort],
            TUnitOfWorkResult,
        ],
    ) -> TUnitOfWorkResult:
        """Run one narrow UoW on the actual configured persistence transaction."""

        with self._store.transaction() as transaction:
            if not isinstance(
                transaction,
                EvaluationAuthorityTransactionPort,
            ):
                raise RuntimeError(
                    "ContextService persistence does not implement the "
                    "evaluation authority unit of work"
                )
            unit_of_work = _ContextServiceEvaluationAuthorityUnitOfWork(
                context_transaction=transaction,
                evaluation_transaction=transaction,
                authorization=self._authorization,
                reader_actor=reader_actor,
            )
            return operation(unit_of_work)

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
            now = self._now()
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

        return self._mutate(
            actor,
            idempotency_key,
            "replace_draft",
            MutationTarget(draft_id=draft_id),
            command,
            DraftRecord,
            replace,
        )

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
            try:
                validated_manifest = CanonicalWorkloadManifest.model_validate(
                    current.manifest.model_dump(
                        mode="python",
                        by_alias=True,
                        exclude_none=True,
                    )
                )
            except (ValidationError, ValueError) as exc:
                raise ManifestValidationError("the draft manifest is not valid") from exc
            self._ensure_manifest_digest(validated_manifest, current.manifest_digest)
            now = self._now()
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
            candidate_manifest = self._finalize_publication_candidate(
                current.manifest,
                finalized_at=now,
            )
            candidate_digest = candidate_manifest.compatibility.artifact_digest
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
            now = self._now()
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
