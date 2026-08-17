from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from athena_context.api.domain import (
    Actor,
    Permission,
    RoleGrant,
    ensure_timestamp,
)
from athena_context.api.evaluation_domain import (
    AuthorizationGrantToken,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    TrustedKeyAuthorityToken,
    VerifiedWc008DeploymentConfiguration,
)
from athena_context.contracts import (
    EvidenceSnapshot,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    TrustedKeyResolver,
    compute_artifact_digest,
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
class DemoEvaluationTrustConfiguration:
    """ContextService-owned trust used for authoritative final verification."""

    trusted_key_anchor: TrustedKeyAnchor


@dataclass(frozen=True, slots=True)
class EvaluationTrustedKeyAuthority:
    """Versioned signing-key trust stored in the publication transaction."""

    record: TrustedKeyRecord
    revision: int
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.revision < 1:
            raise ValueError("trusted key authority revision must be positive")
        if self.revoked_at is not None:
            ensure_timestamp(self.revoked_at)

    def authority_token(self) -> TrustedKeyAuthorityToken:
        record = self.record
        anchor = record.anchor
        payload = {
            "keyVaultKeyId": anchor.key_vault_key_id,
            "keyName": anchor.key_name,
            "keyVersion": anchor.key_version,
            "publicKeyFingerprint": anchor.public_key_fingerprint,
            "enabled": record.enabled,
            "activatedAt": record.activated_at,
            "retiredAt": record.retired_at,
            "expiresAt": record.expires_at,
            "revokedAt": self.revoked_at,
            "revision": self.revision,
        }
        return TrustedKeyAuthorityToken(
            key_vault_key_id=anchor.key_vault_key_id,
            key_version=anchor.key_version,
            public_key_fingerprint=anchor.public_key_fingerprint,
            revision=self.revision,
            authority_digest=compute_artifact_digest(payload),
        )


class EvaluationArtifactFactory(Protocol):
    """Pure finalizer invoked with the persistence-owned commit timestamp."""

    def __call__(
        self,
        published_at: datetime,
        trusted_key: EvaluationTrustedKeyAuthority,
    ) -> StoredEvaluation: ...


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

    def get_demo_evaluation_trusted_key(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> EvaluationTrustedKeyAuthority | None: ...

    def put_demo_evaluation_trusted_key(
        self,
        authority: EvaluationTrustedKeyAuthority,
        *,
        expected_revision: int,
    ) -> None: ...

    def put_evaluation_conditionally(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
        expected_trusted_key: TrustedKeyAuthorityToken,
        artifact_factory: EvaluationArtifactFactory,
    ) -> StoredEvaluation:
        """Bind exact key revision, finalize, and insert in this transaction."""
        ...

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

    def resolve_trusted_key(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> EvaluationTrustedKeyAuthority | None: ...

    def put_trusted_key(
        self,
        authority: EvaluationTrustedKeyAuthority,
        *,
        expected_revision: int,
    ) -> None: ...

    def insert_evaluation_conditionally(
        self,
        trusted_key_anchor: TrustedKeyAnchor,
        expected_trusted_key: TrustedKeyAuthorityToken,
        artifact_factory: EvaluationArtifactFactory,
    ) -> StoredEvaluation: ...

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]: ...


@dataclass(frozen=True, slots=True)
class EvaluationCommitCandidate:
    """Evaluated immutable inputs awaiting one conditional authority transaction."""

    actor: Actor
    idempotency_key: str
    request_digest: str
    command: DemoEvaluationCommand
    snapshot: EvidenceSnapshot
    envelope_attempt_id: str
    envelope: ValidatedEnvelope
    expected_authority: EvaluationAuthorityToken
    private_mcp_endpoint: str
    evidence_identity_object_id: str


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


class SnapshotSigningPort(Protocol):
    def sign(self, request: SnapshotSigningRequest) -> str: ...


__all__ = [
    "ConfiguredEvidenceClientPort",
    "EvaluationArtifactFactory",
    "EvaluationAuthorityTransactionPort",
    "EvaluationAuthorityUnitOfWorkPort",
    "EvaluationCommitCandidate",
    "EvaluationTrustedKeyAuthority",
    "DemoEvaluationTrustConfiguration",
    "PublishedContextResolverPort",
    "SnapshotSigningPort",
    "SnapshotSigningRequest",
    "StoredEvaluation",
    "TrustedWc008DeploymentConfigurationPort",
]
