from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime
from typing import Literal

from athena_context.api.domain import Actor, Permission, RoleGrant
from athena_context.api.errors import (
    DemoEvaluationConfigurationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    DemoEvaluationApproval,
    DemoEvaluationResult,
)
from athena_context.api.evaluation_ports import (
    EvaluationTrustedKeyAuthority,
    StoredEvaluation,
)
from athena_context.api.service import ContextService
from athena_context.contracts import SnapshotPublicationRecord


class InMemoryEvaluationAuthorizationRegistry:
    """Test registry whose mutations execute through ContextService methods."""

    def __init__(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        context_service: ContextService,
        administration_actor: Actor,
    ) -> None:
        self._context_service = context_service
        self._administration_actor = administration_actor
        current, revision = context_service.get_demo_evaluation_grants(
            administration_actor
        )
        if current or revision != 0:
            raise ValueError("evaluation authorization registry is already seeded")
        context_service.replace_demo_evaluation_grants(
            administration_actor,
            grants,
            expected_revision=revision,
        )

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken:
        return self._context_service.authorize_demo_evaluation(
            actor,
            permission,
            manifest_id,
        )

    def remove_grant(self, grant: RoleGrant) -> None:
        grants, revision = self._context_service.get_demo_evaluation_grants(
            self._administration_actor
        )
        remaining = tuple(candidate for candidate in grants if candidate != grant)
        if remaining == grants:
            return
        self._context_service.replace_demo_evaluation_grants(
            self._administration_actor,
            remaining,
            expected_revision=revision,
        )

    def add_grant(self, grant: RoleGrant) -> None:
        grants, revision = self._context_service.get_demo_evaluation_grants(
            self._administration_actor
        )
        if grant in grants:
            return
        self._context_service.replace_demo_evaluation_grants(
            self._administration_actor,
            (*grants, grant),
            expected_revision=revision,
        )


class InMemoryDemoEvaluationStateReader:
    """Read-only deterministic view of service-owned evaluation state for tests."""

    def __init__(
        self,
        *,
        context_service: ContextService,
        reader_actor: Actor,
        manifest_id: str,
    ) -> None:
        self._context_service = context_service
        self._reader_actor = reader_actor
        self._manifest_id = manifest_id

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        if actor_id != self._reader_actor.actor_id:
            return None
        return self._context_service.load_demo_evaluation_receipt(
            self._reader_actor,
            idempotency_key,
            manifest_id=self._manifest_id,
        )

    def resolve_publication(
        self,
        snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        return self._context_service.get_demo_snapshot_publication(
            self._reader_actor,
            snapshot_id,
        )

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None:
        return self._context_service.get_demo_evaluation_result(
            self._reader_actor,
            snapshot_id,
        )

    def resolve_envelope(
        self,
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> object | None:
        matches = [
            artifact
            for artifact in self._context_service.list_demo_evaluations(
                self._reader_actor
            )
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
            self._context_service.list_demo_evaluations(self._reader_actor)
        )


class InMemoryDemoEvaluationApprovalRegistry:
    """Test approval registry whose writes remain ContextService-authoritative."""

    def __init__(
        self,
        approvals: Iterable[DemoEvaluationApproval],
        *,
        context_service: ContextService,
        approval_actor: Actor,
    ) -> None:
        self._context_service = context_service
        self._approval_actor = approval_actor
        for approval in approvals:
            context_service.put_demo_evaluation_approval(
                approval_actor,
                approval,
                expected_revision=None,
            )

    def resolve(self, decision_id: str) -> DemoEvaluationApproval | None:
        return self._context_service.get_demo_evaluation_approval(
            self._approval_actor,
            decision_id,
        )

    def revoke(self, decision_id: str, *, revoked_at: datetime) -> None:
        current = self.resolve(decision_id)
        if current is None:
            raise ResourceNotFoundError(
                f"demo evaluation approval {decision_id!r} was not found"
            )
        if current.status == "revoked":
            return
        replacement = current.model_copy(
            update={
                "status": "revoked",
                "revision": current.revision + 1,
                "revoked_at": revoked_at,
            }
        )
        self._context_service.put_demo_evaluation_approval(
            self._approval_actor,
            replacement,
            expected_revision=current.revision,
        )

    def replace(self, approval: DemoEvaluationApproval) -> None:
        current = self.resolve(approval.decision_id)
        if current is None or approval.revision != current.revision + 1:
            raise DemoEvaluationConfigurationError(
                "approval replacement requires the next registry revision"
            )
        self._context_service.put_demo_evaluation_approval(
            self._approval_actor,
            approval,
            expected_revision=current.revision,
        )


class InMemoryDemoEvaluationTrustRegistry:
    """Test key-trust registry whose writes remain ContextService-authoritative."""

    def __init__(
        self,
        *,
        context_service: ContextService,
        administration_actor: Actor,
    ) -> None:
        self._context_service = context_service
        self._administration_actor = administration_actor

    def resolve(self) -> EvaluationTrustedKeyAuthority | None:
        return self._context_service.get_demo_evaluation_trusted_key(
            self._administration_actor
        )

    def disable(self, *, revoked_at: datetime) -> None:
        current = self.resolve()
        if current is None:
            raise ResourceNotFoundError(
                "demo evaluation trusted key was not found"
            )
        replacement = EvaluationTrustedKeyAuthority(
            record=replace(current.record, enabled=False),
            revision=current.revision + 1,
            revoked_at=revoked_at,
        )
        self._context_service.put_demo_evaluation_trusted_key(
            self._administration_actor,
            replacement,
            expected_revision=current.revision,
        )


__all__ = [
    "InMemoryDemoEvaluationApprovalRegistry",
    "InMemoryDemoEvaluationStateReader",
    "InMemoryDemoEvaluationTrustRegistry",
    "InMemoryEvaluationAuthorizationRegistry",
]
