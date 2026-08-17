from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from athena_context.api.domain import (
    Actor,
    Permission,
    RoleGrant,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    DemoEvaluationResult,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    VerifiedWc008DeploymentConfiguration,
)
from athena_context.contracts import (
    EvidenceSnapshot,
    ManifestFinding,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
    TrustedKeyResolver,
)
from athena_context.evidence import (
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceCollectionCommand,
    ValidatedEnvelope,
)


@dataclass(frozen=True, slots=True)
class SnapshotSigningRequest:
    canonical_preimage: bytes
    preimage_digest: str
    trusted_key_anchor: TrustedKeyAnchor


@dataclass(frozen=True, slots=True)
class StoredEvaluation:
    actor_id: str
    idempotency_key: str
    request_digest: str
    snapshot_id: str
    result_json: str
    snapshot_json: str
    publication_json: str
    envelope_attempt_id: str
    envelope: ValidatedEnvelope


@runtime_checkable
class EvaluationAuthorityTransactionPort(Protocol):
    """Evaluation state implemented by the actual Context API transaction."""

    def get_demo_evaluation_approval(
        self,
        decision_id: str,
    ) -> DemoEvaluationApproval | None: ...

    def put_demo_evaluation_approval(
        self,
        approval: DemoEvaluationApproval,
        *,
        expected_revision: int | None,
    ) -> None: ...

    def get_evaluation_grants(self) -> tuple[tuple[RoleGrant, ...], int]: ...

    def replace_evaluation_grants(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        expected_revision: int,
    ) -> int: ...

    def get_evaluation_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None: ...

    def get_evaluation_artifact(
        self,
        snapshot_id: str,
    ) -> StoredEvaluation | None: ...

    def put_evaluation(self, artifact: StoredEvaluation) -> None: ...

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]: ...


class EvaluationAuthorityUnitOfWorkPort(Protocol):
    """Narrow unit of work created from one actual ContextService transaction."""

    def resolve_context(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext: ...

    def resolve_approval(
        self,
        decision_id: str,
    ) -> DemoEvaluationApproval | None: ...

    def put_approval(
        self,
        approval: DemoEvaluationApproval,
        *,
        expected_revision: int | None,
    ) -> None: ...

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken: ...

    def get_grants(self) -> tuple[tuple[RoleGrant, ...], int]: ...

    def replace_grants(
        self,
        grants: tuple[RoleGrant, ...],
        *,
        expected_revision: int,
    ) -> int: ...

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None: ...

    def load_artifact(self, snapshot_id: str) -> StoredEvaluation | None: ...

    def insert_evaluation(self, artifact: StoredEvaluation) -> None: ...

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]: ...


@dataclass(frozen=True, slots=True)
class EvaluationCommitCandidate:
    """Evaluated immutable inputs awaiting one conditional authority transaction."""

    actor: Actor
    idempotency_key: str
    request_digest: str
    command: DemoEvaluationCommand
    snapshot: EvidenceSnapshot
    findings: tuple[ManifestFinding, ...]
    envelope_attempt_id: str
    envelope: ValidatedEnvelope
    expected_authority: EvaluationAuthorityToken
    private_mcp_endpoint: str


class ConfiguredEvidenceClientPort(Protocol):
    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration: ...

    @property
    def trust_configuration(self) -> CollectorTrustConfiguration: ...

    @property
    def trusted_key_anchor(self) -> TrustedKeyAnchor: ...

    @property
    def key_resolver(self) -> TrustedKeyResolver: ...

    def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence: ...


class TrustedWc008DeploymentConfigurationPort(Protocol):
    def load_verified(self) -> VerifiedWc008DeploymentConfiguration: ...


class PublishedContextResolverPort(Protocol):
    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext: ...


class DemoEvaluationApprovalResolverPort(Protocol):
    def resolve(self, decision_id: str) -> DemoEvaluationApproval | None: ...


class SnapshotSigningPort(Protocol):
    def sign(self, request: SnapshotSigningRequest) -> str: ...


class EvaluationCommitPort(Protocol):
    """Conditionally finalize and insert an evaluation in one authority transaction.

    Production adapters must own the resolver used before collection, compare
    every typed authority revision/ETag, and perform commit-time authority reads
    plus artifact insertion in the same backing-store transaction or conditional
    batch. A caller-supplied resolver or a resolver call followed by an
    independent write does not implement this port.
    """

    @property
    def context_resolver(self) -> PublishedContextResolverPort: ...

    def load_receipt(self, actor_id: str, idempotency_key: str) -> StoredEvaluation | None: ...

    def commit(self, candidate: EvaluationCommitCandidate) -> DemoEvaluationResult: ...

    def resolve_publication(self, snapshot_id: str) -> SnapshotPublicationRecord | None: ...

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None: ...


class EvaluationAuthorizationPort(Protocol):
    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken: ...


__all__ = [
    "ConfiguredEvidenceClientPort",
    "DemoEvaluationApprovalResolverPort",
    "EvaluationAuthorityTransactionPort",
    "EvaluationAuthorityUnitOfWorkPort",
    "EvaluationCommitCandidate",
    "EvaluationCommitPort",
    "EvaluationAuthorizationPort",
    "PublishedContextResolverPort",
    "SnapshotSigningPort",
    "SnapshotSigningRequest",
    "StoredEvaluation",
    "TrustedWc008DeploymentConfigurationPort",
]
