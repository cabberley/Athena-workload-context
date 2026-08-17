from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from athena_context.api.domain import Actor, ActorKind, Permission, ensure_timestamp
from athena_context.api.errors import (
    DemoEvaluationApprovalError,
    DuplicateVersionError,
    EvaluationFailedClosedError,
    IdempotencyConflictError,
)
from athena_context.api.evaluation_context import (
    resolve_active_manifest_profile,
    validate_demo_evaluation_approval,
    validate_published_context_binding,
)
from athena_context.api.evaluation_domain import (
    AuthorizedSnapshotPublication,
    DemoEvaluationResult,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    build_authorized_publication,
    build_demo_evaluation_result,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    DemoEvaluationApprovalResolverPort,
    EvaluationAuthorizationPort,
    EvaluationCommitCandidate,
    PublishedContextResolverPort,
    StoredEvaluation,
)
from athena_context.api.memory import InMemoryAuthorityCoordinator
from athena_context.api.ports import ClockPort
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceSnapshot,
    SnapshotPublicationRecord,
)


@dataclass(frozen=True, slots=True)
class _EvaluationState:
    receipts: dict[tuple[str, str], StoredEvaluation]
    artifacts: dict[str, StoredEvaluation]


class InMemoryEvaluationCommitPort:
    """Conditional publication sharing one lock with every authority source."""

    def __init__(
        self,
        *,
        coordinator: InMemoryAuthorityCoordinator,
        context_resolver: PublishedContextResolverPort,
        approval_resolver: DemoEvaluationApprovalResolverPort,
        authorization: EvaluationAuthorizationPort,
        clock: ClockPort,
        publication_actor: Actor,
        evidence_identity_object_id: str,
    ) -> None:
        if publication_actor.kind is not ActorKind.SERVICE:
            raise ValueError("publication_actor must be a service actor")
        for dependency, label in (
            (context_resolver, "published context resolver"),
            (approval_resolver, "approval registry"),
            (authorization, "authorization registry"),
        ):
            if getattr(dependency, "authority_coordinator", None) is not coordinator:
                raise ValueError(
                    f"in-memory {label} does not share the commit authority coordinator"
                )
        self._coordinator = coordinator
        self._context_resolver = context_resolver
        self._approval_resolver = approval_resolver
        self._authorization = authorization
        self._clock = clock
        self._publication_actor = publication_actor
        self._evidence_identity_object_id = evidence_identity_object_id
        self._state = _EvaluationState(receipts={}, artifacts={})

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        with self._coordinator.transaction():
            return self._state.receipts.get((actor_id, idempotency_key))

    def commit(
        self,
        candidate: EvaluationCommitCandidate,
    ) -> DemoEvaluationResult:
        """Read all authority and insert all artifacts under one transaction lock."""

        receipt_key = (candidate.actor.actor_id, candidate.idempotency_key)
        with self._coordinator.transaction():
            replay = self._state.receipts.get(receipt_key)
            if replay is not None:
                if replay.request_digest != candidate.request_digest:
                    raise IdempotencyConflictError(
                        "idempotency key was concurrently used for a different evaluation"
                    )
                return DemoEvaluationResult.model_validate_json(replay.result_json)

            published_at = ensure_timestamp(self._clock.now())
            current_authorization = self._authorization.authorize(
                candidate.actor,
                Permission.PUBLISH,
                candidate.command.manifest_id,
            )
            approval = self._approval_resolver.resolve(
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
            selection = PublishedContextSelection(
                manifest_id=expected_context.manifest_id,
                manifest_version=expected_context.manifest_version,
                profile_id=expected_context.profile_id,
            )
            try:
                resolved = self._context_resolver.resolve(
                    selection,
                    as_of=published_at,
                )
            except (AthenaValidationError, ValueError) as exc:
                raise EvaluationFailedClosedError(
                    "published profile has inactive governance at commit time"
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
            if published_at >= candidate.snapshot.expires_at:
                raise EvaluationFailedClosedError(
                    "snapshot became stale before publication"
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
            if candidate.snapshot.snapshot_id in self._state.artifacts:
                raise DuplicateVersionError(
                    f"evidence snapshot {candidate.snapshot.snapshot_id!r} "
                    "is already published"
                )
            self._state = _EvaluationState(
                receipts={**self._state.receipts, receipt_key: artifact},
                artifacts={
                    **self._state.artifacts,
                    candidate.snapshot.snapshot_id: artifact,
                },
            )
            return result

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
        with self._coordinator.transaction():
            artifact = self._state.artifacts.get(snapshot_id)
        if artifact is None:
            return None
        publication = AuthorizedSnapshotPublication.model_validate_json(
            artifact.publication_json
        )
        return publication.registry_record()

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None:
        with self._coordinator.transaction():
            artifact = self._state.artifacts.get(snapshot_id)
        if artifact is None:
            return None
        return DemoEvaluationResult.model_validate_json(artifact.result_json)

    def resolve_envelope(
        self,
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> object | None:
        with self._coordinator.transaction():
            matches = [
                artifact
                for artifact in self._state.artifacts.values()
                if artifact.envelope_attempt_id == attempt_id
                and artifact.envelope.kind == kind
                and artifact.envelope.digest == digest
            ]
        if len(matches) != 1:
            return None
        return matches[0].envelope.payload()

    @property
    def publication_count(self) -> int:
        with self._coordinator.transaction():
            return len(self._state.artifacts)


__all__ = ["InMemoryEvaluationCommitPort"]
