from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Literal, TypeVar

from athena_context.api.domain import (
    Actor,
    ActorKind,
    Permission,
    RoleGrant,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationApprovalError,
    EvaluationFailedClosedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    StaleRevisionError,
)
from athena_context.api.evaluation_adapters import (
    ContextServicePublishedContextResolver,
)
from athena_context.api.evaluation_context import (
    resolve_active_manifest_profile,
    validate_demo_evaluation_approval,
    validate_published_context_binding,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    AuthorizedSnapshotPublication,
    DemoEvaluationApproval,
    DemoEvaluationResult,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    build_authorized_publication,
    build_demo_evaluation_result,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    EvaluationAuthorityUnitOfWorkPort,
    EvaluationCommitCandidate,
    StoredEvaluation,
)
from athena_context.api.ports import ClockPort
from athena_context.api.service import ContextService
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceSnapshot,
    ResolvedManifestProfile,
    SnapshotPublicationRecord,
)

TUnitOfWorkResult = TypeVar("TUnitOfWorkResult")


class InMemoryEvaluationAuthorizationRegistry:
    """Evaluation grants persisted through the actual ContextService transaction."""

    def __init__(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        context_service: ContextService,
        context_reader_actor: Actor,
    ) -> None:
        self._context_service = context_service
        self._context_reader_actor = context_reader_actor

        def seed(unit_of_work: EvaluationAuthorityUnitOfWorkPort) -> None:
            current, revision = unit_of_work.get_grants()
            if current or revision != 0:
                raise ValueError("evaluation authorization registry is already seeded")
            unit_of_work.replace_grants(
                grants,
                expected_revision=revision,
            )

        self._run(seed)

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken:
        return self._run(
            lambda unit_of_work: unit_of_work.authorize(
                actor,
                permission,
                manifest_id,
            )
        )

    def remove_grant(self, grant: RoleGrant) -> None:
        def remove(unit_of_work: EvaluationAuthorityUnitOfWorkPort) -> None:
            grants, revision = unit_of_work.get_grants()
            remaining = tuple(candidate for candidate in grants if candidate != grant)
            if remaining == grants:
                return
            unit_of_work.replace_grants(
                remaining,
                expected_revision=revision,
            )

        self._run(remove)

    def _run(
        self,
        operation: Callable[
            [EvaluationAuthorityUnitOfWorkPort],
            TUnitOfWorkResult,
        ],
    ) -> TUnitOfWorkResult:
        return self._context_service.run_evaluation_authority_transaction(
            reader_actor=self._context_reader_actor,
            operation=operation,
        )


class InMemoryEvaluationCommitPort:
    """Conditional publication using one ContextService-owned unit of work."""

    def __init__(
        self,
        *,
        context_service: ContextService,
        context_reader_actor: Actor,
        clock: ClockPort,
        publication_actor: Actor,
        evidence_identity_object_id: str,
    ) -> None:
        if publication_actor.kind is not ActorKind.SERVICE:
            raise ValueError("publication_actor must be a service actor")
        self._context_service = context_service
        self._context_reader_actor = context_reader_actor
        self._context_resolver = ContextServicePublishedContextResolver(
            service=context_service,
            reader_actor=context_reader_actor,
        )
        self._clock = clock
        self._publication_actor = publication_actor
        self._evidence_identity_object_id = evidence_identity_object_id
        self._run(lambda unit_of_work: unit_of_work.list_evaluations())

    @property
    def context_resolver(self) -> ContextServicePublishedContextResolver:
        return self._context_resolver

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        return self._run(
            lambda unit_of_work: unit_of_work.load_receipt(
                actor_id,
                idempotency_key,
            )
        )

    def commit(
        self,
        candidate: EvaluationCommitCandidate,
    ) -> DemoEvaluationResult:
        """Validate every authority and insert under one actual store transaction."""

        try:
            return self._run(
                lambda unit_of_work: self._commit_in_unit_of_work(
                    unit_of_work,
                    candidate,
                )
            )
        except StaleRevisionError as exc:
            raise EvaluationFailedClosedError(
                "authority changed during the publication transaction"
            ) from exc

    def _commit_in_unit_of_work(
        self,
        unit_of_work: EvaluationAuthorityUnitOfWorkPort,
        candidate: EvaluationCommitCandidate,
    ) -> DemoEvaluationResult:
        replay = unit_of_work.load_receipt(
            candidate.actor.actor_id,
            candidate.idempotency_key,
        )
        if replay is not None:
            if replay.request_digest != candidate.request_digest:
                raise IdempotencyConflictError(
                    "idempotency key was concurrently used for a different evaluation"
                )
            return DemoEvaluationResult.model_validate_json(replay.result_json)

        published_at = ensure_timestamp(self._clock.now())
        approval, profile = self._validate_authority(
            unit_of_work,
            candidate,
            published_at=published_at,
        )
        if published_at >= candidate.snapshot.expires_at:
            raise EvaluationFailedClosedError(
                "snapshot became stale before publication"
            )

        self._before_artifact_insert(unit_of_work)

        # Keep the test seam and any future transaction-local hooks outside the
        # final conditional read. No authority mutation can be hidden between
        # this second read and insertion because both use this same unit of work.
        approval, profile = self._validate_authority(
            unit_of_work,
            candidate,
            published_at=published_at,
        )
        publication = build_authorized_publication(
            snapshot=candidate.snapshot,
            approval=approval,
            publisher=candidate.actor,
            publication_actor=self._publication_actor,
            published_at=published_at,
            resolved_profile_digest=profile.resolved_profile_digest,
            endpoint=candidate.private_mcp_endpoint,
            scope=candidate.command.authorized_scope,
            reason=candidate.command.reason,
        )
        result = build_demo_evaluation_result(
            publication=publication,
            snapshot=candidate.snapshot,
            findings=candidate.findings,
            evaluated_at=published_at,
        )
        artifact = StoredEvaluation(
            actor_id=candidate.actor.actor_id,
            idempotency_key=candidate.idempotency_key,
            request_digest=candidate.request_digest,
            snapshot_id=candidate.snapshot.snapshot_id,
            result_json=result.model_dump_json(
                by_alias=True,
                exclude_none=True,
            ),
            snapshot_json=candidate.snapshot.canonical_json(),
            publication_json=publication.model_dump_json(exclude_none=True),
            envelope_attempt_id=candidate.envelope_attempt_id,
            envelope=candidate.envelope,
        )
        self._validate_canonical_components(artifact)
        unit_of_work.insert_evaluation(artifact)
        return result

    def _validate_authority(
        self,
        unit_of_work: EvaluationAuthorityUnitOfWorkPort,
        candidate: EvaluationCommitCandidate,
        *,
        published_at: datetime,
    ) -> tuple[DemoEvaluationApproval, ResolvedManifestProfile]:
        current_authorization = unit_of_work.authorize(
            candidate.actor,
            Permission.PUBLISH,
            candidate.command.manifest_id,
        )
        approval = unit_of_work.resolve_approval(
            candidate.command.approval_decision_id
        )
        if approval is None:
            raise DemoEvaluationApprovalError(
                "trusted demo evaluation approval disappeared before publication"
            )
        validate_demo_evaluation_approval(
            candidate.actor,
            candidate.command,
            approval,
            as_of=published_at,
            private_mcp_endpoint=candidate.private_mcp_endpoint,
            evidence_identity_object_id=self._evidence_identity_object_id,
        )

        expected_context = candidate.expected_authority.context
        expected_selection_mode = (
            "uniqueActiveVersion"
            if candidate.command.manifest_version is None
            else "exactVersion"
        )
        if expected_context.selection_mode != expected_selection_mode:
            raise EvaluationFailedClosedError(
                "published context authority token changed selection mode"
            )
        selection = PublishedContextSelection(
            manifest_id=candidate.command.manifest_id,
            manifest_version=candidate.command.manifest_version,
            profile_id=candidate.command.profile_id,
        )
        try:
            resolved = unit_of_work.resolve_context(
                selection,
                as_of=published_at,
            )
        except (
            AmbiguousLookupError,
            AthenaValidationError,
            ResourceNotFoundError,
            ValueError,
        ) as exc:
            raise EvaluationFailedClosedError(
                "published context is missing, ambiguous, or has inactive "
                "governance at commit time"
            ) from exc
        if resolved.view.supersession is not None:
            raise EvaluationFailedClosedError(
                "published context was superseded before publication"
            )
        try:
            profile = resolve_active_manifest_profile(
                resolved.view.published.manifest,
                selection.profile_id,
                as_of=published_at,
            )
        except (AthenaValidationError, ValueError) as exc:
            raise EvaluationFailedClosedError(
                "published profile has inactive governance at commit time"
            ) from exc
        current_context = ResolvedPublishedContext(
            view=resolved.view,
            profile=profile,
            authority_token=build_published_context_authority_token(
                resolved.view,
                profile,
                requested_manifest_version=selection.manifest_version,
            ),
        )
        validate_published_context_binding(
            candidate.command,
            approval,
            current_context,
        )
        current_authority = EvaluationAuthorityToken(
            context=current_context.authority_token,
            approval=approval.authority_token(),
            authorization=current_authorization,
        )
        if current_authority != candidate.expected_authority:
            raise EvaluationFailedClosedError(
                "evaluation authority revision changed before publication"
            )
        return approval, profile

    def _before_artifact_insert(
        self,
        unit_of_work: EvaluationAuthorityUnitOfWorkPort,
    ) -> None:
        """Test seam reached inside the actual ContextService unit of work."""

        del unit_of_work

    @staticmethod
    def _validate_canonical_components(artifact: StoredEvaluation) -> None:
        result = DemoEvaluationResult.model_validate_json(artifact.result_json)
        snapshot = EvidenceSnapshot.model_validate_json(artifact.snapshot_json)
        publication = AuthorizedSnapshotPublication.model_validate_json(
            artifact.publication_json
        )
        if (
            result.snapshot.canonical_json() != snapshot.canonical_json()
            or result.publication != publication
            or result.publication.snapshot_id != artifact.snapshot_id
        ):
            raise ValueError(
                "stored evaluation components are not canonically identical"
            )

    def resolve_publication(
        self,
        snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        artifact = self._run(
            lambda unit_of_work: unit_of_work.load_artifact(snapshot_id)
        )
        if artifact is None:
            return None
        publication = AuthorizedSnapshotPublication.model_validate_json(
            artifact.publication_json
        )
        return publication.registry_record()

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None:
        artifact = self._run(
            lambda unit_of_work: unit_of_work.load_artifact(snapshot_id)
        )
        if artifact is None:
            return None
        return DemoEvaluationResult.model_validate_json(artifact.result_json)

    def resolve_envelope(
        self,
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> object | None:
        artifacts = self._run(
            lambda unit_of_work: unit_of_work.list_evaluations()
        )
        matches = [
            artifact
            for artifact in artifacts
            if artifact.envelope_attempt_id == attempt_id
            and artifact.envelope.kind == kind
            and artifact.envelope.digest == digest
        ]
        if len(matches) != 1:
            return None
        return matches[0].envelope.payload()

    @property
    def publication_count(self) -> int:
        return len(
            self._run(lambda unit_of_work: unit_of_work.list_evaluations())
        )

    def _run(
        self,
        operation: Callable[
            [EvaluationAuthorityUnitOfWorkPort],
            TUnitOfWorkResult,
        ],
    ) -> TUnitOfWorkResult:
        return self._context_service.run_evaluation_authority_transaction(
            reader_actor=self._context_reader_actor,
            operation=operation,
        )


__all__ = [
    "InMemoryEvaluationAuthorizationRegistry",
    "InMemoryEvaluationCommitPort",
]
