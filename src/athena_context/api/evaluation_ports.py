from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from athena_context.api.domain import (
    Actor,
    Permission,
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

    Production adapters must compare every typed authority revision/ETag and
    perform the artifact insert in the same backing-store transaction or
    conditional batch. A resolver call followed by an independent write does
    not implement this port.
    """

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
    "EvaluationCommitCandidate",
    "EvaluationCommitPort",
    "EvaluationAuthorizationPort",
    "PublishedContextResolverPort",
    "SnapshotSigningPort",
    "SnapshotSigningRequest",
    "StoredEvaluation",
    "TrustedWc008DeploymentConfigurationPort",
]
