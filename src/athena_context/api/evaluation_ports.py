from __future__ import annotations

from collections.abc import Callable
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
    AuthorizedSnapshotPublication,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    DemoEvaluationResult,
    EvaluationAuthorityToken,
    McpReadAssignment,
    PublishedContextSelection,
    ResolvedPublishedContext,
    TrustedKeyAuthorityToken,
    VerifiedWc008DeploymentConfiguration,
    build_authorized_publication,
    build_demo_evaluation_result,
)
from athena_context.contracts import (
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    TrustedKeyResolver,
    compute_artifact_digest,
)
from athena_context.evidence import (
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceCollectionCommand,
    EvidenceTransportRequest,
    ValidatedEnvelope,
)


@dataclass(frozen=True, slots=True)
class SnapshotSigningRequest:
    canonical_preimage: bytes
    preimage_digest: str
    trusted_key_anchor: TrustedKeyAnchor


@dataclass(frozen=True, slots=True)
class StoredEvaluationMaterial:
    """Validated immutable columns rendered only outside the commit operation."""

    snapshot: EvidenceSnapshot
    snapshot_json: str
    approval: DemoEvaluationApproval
    actor: Actor
    publication_actor: Actor
    resolved_profile_digest: str
    private_mcp_endpoint: str
    authorized_scope: EvidenceScope
    reason: str
    findings: tuple[ManifestFinding, ...]

    def publication(
        self,
        published_at: datetime,
    ) -> AuthorizedSnapshotPublication:
        return build_authorized_publication(
            snapshot=self.snapshot,
            approval=self.approval,
            publisher=self.actor,
            publication_actor=self.publication_actor,
            published_at=published_at,
            resolved_profile_digest=self.resolved_profile_digest,
            endpoint=self.private_mcp_endpoint,
            scope=self.authorized_scope,
            reason=self.reason,
        )

    def result(self, published_at: datetime) -> DemoEvaluationResult:
        return build_demo_evaluation_result(
            publication=self.publication(published_at),
            snapshot=self.snapshot,
            findings=self.findings,
            evaluated_at=published_at,
        )


@dataclass(frozen=True, slots=True)
class StoredEvaluation:
    actor_id: str
    idempotency_key: str
    request_digest: str
    candidate_digest: str
    snapshot_id: str
    published_at: datetime
    material: StoredEvaluationMaterial
    envelope_attempt_id: str
    envelope: ValidatedEnvelope

    @property
    def result_json(self) -> str:
        return self.material.result(self.published_at).model_dump_json(
            by_alias=True,
            exclude_none=True,
        )

    @property
    def snapshot_json(self) -> str:
        return self.material.snapshot_json

    @property
    def publication_json(self) -> str:
        return self.material.publication(self.published_at).model_dump_json(
            exclude_none=True
        )


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


@dataclass(frozen=True, slots=True)
class EvaluationTemporalValidity:
    """Immutable time predicates consumed by the sealed persistence finalizer."""

    approval_active_from: datetime
    approval_expires_at: datetime
    snapshot_active_from: datetime
    snapshot_expires_at: datetime
    governance_active_from: datetime | None
    governance_expires_at: datetime | None
    risk_active_from: datetime | None
    risk_expires_at: datetime | None
    evidence_fresh_until: datetime | None

    def __post_init__(self) -> None:
        for value in (
            self.approval_active_from,
            self.approval_expires_at,
            self.snapshot_active_from,
            self.snapshot_expires_at,
            self.governance_active_from,
            self.governance_expires_at,
            self.risk_active_from,
            self.risk_expires_at,
            self.evidence_fresh_until,
        ):
            if value is not None:
                ensure_timestamp(value)


@dataclass(frozen=True, slots=True)
class PreparedEvaluationArtifact:
    """Fully evaluated immutable inputs for persistence-owned finalization."""

    snapshot: EvidenceSnapshot
    approval: DemoEvaluationApproval
    resolved_profile_digest: str
    findings: tuple[ManifestFinding, ...]
    collection_request: EvidenceTransportRequest
    envelope: ValidatedEnvelope
    temporal_validity: EvaluationTemporalValidity


def build_evaluation_evidence_binding_digest(
    snapshot: EvidenceSnapshot,
    *,
    collection_request: EvidenceTransportRequest,
    envelope: ValidatedEnvelope,
) -> str:
    """Bind the exact immutable snapshot and source envelope checked by policy."""

    return compute_artifact_digest(
        {
            "snapshotCanonicalJson": snapshot.canonical_json(),
            "snapshotArtifactDigest": snapshot.compatibility.artifact_digest,
            "snapshotSemanticDigest": snapshot.compatibility.semantic_digest,
            "collectionRequest": collection_request.model_dump(
                mode="json",
                by_alias=True,
            ),
            "envelopeKind": envelope.kind,
            "envelopeDigest": envelope.digest,
        }
    )


@dataclass(frozen=True, slots=True)
class EvaluationCollectionAuthority:
    """Operator-pinned WC-008 Reader authority bound before collection."""

    deployment_configuration: VerifiedWc008DeploymentConfiguration
    trust_configuration: CollectorTrustConfiguration
    reader_assignment: McpReadAssignment
    reader_assignment_revision: str
    authority_digest: str


def build_evaluation_collection_authority(
    deployment_configuration: VerifiedWc008DeploymentConfiguration,
    trust_configuration: CollectorTrustConfiguration,
    *,
    authorized_scope: EvidenceScope,
) -> EvaluationCollectionAuthority:
    """Normalize and bind the exact configured Reader assignment revision."""

    configuration = VerifiedWc008DeploymentConfiguration.model_validate_json(
        deployment_configuration.model_dump_json(by_alias=True)
    )
    trust = CollectorTrustConfiguration.model_validate_json(
        trust_configuration.model_dump_json(by_alias=True)
    )
    assertion = configuration.assertion
    expected_scope = authorized_scope.canonical_json()
    assignments = tuple(
        assignment
        for assignment in assertion.evidence_read_assignments
        if assignment.role == "Reader"
        and assignment.scope.canonical_json() == expected_scope
    )
    if len(assignments) != 1:
        raise ValueError(
            "evaluation requires one exact operator-pinned WC-008 Reader assignment"
        )
    if (
        trust.managed_identity_object_id
        != assertion.evidence_identity_object_id
        or trust.context_identity_object_id
        != assertion.context_identity_object_id
        or trust.tenant_id
        != getattr(assignments[0].scope, "tenant_id", None)
    ):
        raise ValueError(
            "evaluation collection trust does not match its WC-008 Reader assignment"
        )
    assignment = McpReadAssignment.model_validate_json(
        assignments[0].model_dump_json(by_alias=True)
    )
    approval_digest = compute_artifact_digest(
        configuration.operator_approval.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )
    revision = compute_artifact_digest(
        {
            "deploymentAssertionDigest": assertion.assertion_digest,
            "operatorApprovalDigest": approval_digest,
            "readerAssignment": assignment.model_dump(
                mode="json",
                by_alias=True,
            ),
        }
    )
    authority_payload = {
        "deploymentAssertion": assertion.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "operatorApprovalDigest": approval_digest,
        "trustConfiguration": trust.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "readerAssignment": assignment.model_dump(
            mode="json",
            by_alias=True,
        ),
        "readerAssignmentRevision": revision,
    }
    return EvaluationCollectionAuthority(
        deployment_configuration=configuration,
        trust_configuration=trust,
        reader_assignment=assignment,
        reader_assignment_revision=revision,
        authority_digest=compute_artifact_digest(authority_payload),
    )


def build_demo_evaluation_request_digest(
    *,
    actor: Actor,
    command: DemoEvaluationCommand,
    collection_authority: EvaluationCollectionAuthority,
) -> str:
    """Build the idempotency digest only from service-bound authority."""

    return compute_artifact_digest(
        {
            "operation": "evaluate_demo_workload",
            "actor": actor.model_dump(mode="json"),
            "command": command.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "collectionAuthorityDigest": collection_authority.authority_digest,
            "readerAssignmentRevision": (
                collection_authority.reader_assignment_revision
            ),
        }
    )


def build_demo_evaluation_candidate_digest(
    *,
    request_digest: str,
    authority: EvaluationAuthorityToken,
    collection_authority: EvaluationCollectionAuthority,
    evidence_binding_digest: str,
) -> str:
    """Bind the exact authority and signed evidence selected for insertion."""

    return compute_artifact_digest(
        {
            "requestDigest": request_digest,
            "evaluationAuthority": authority.model_dump(
                mode="json",
                by_alias=True,
            ),
            "collectionAuthorityDigest": collection_authority.authority_digest,
            "readerAssignmentRevision": (
                collection_authority.reader_assignment_revision
            ),
            "evidenceBindingDigest": evidence_binding_digest,
        }
    )


@dataclass(frozen=True, slots=True)
class EvaluationCommitAuthorityCondition:
    """Complete immutable authority and evidence predicate for atomic insertion."""

    reader_actor: Actor
    actor: Actor
    publication_actor: Actor
    command: DemoEvaluationCommand
    expected_authority: EvaluationAuthorityToken
    collection_authority: EvaluationCollectionAuthority
    trusted_key_anchor: TrustedKeyAnchor
    idempotency_key: str


# Delay-capable verification returns data, never executable post-time behavior.
type EvaluationArtifactPreparation = Callable[
    [EvaluationTrustedKeyAuthority],
    PreparedEvaluationArtifact,
]


@runtime_checkable
class EvaluationAuthorityTransactionPort(Protocol):
    """Evaluation state implemented by the actual Context API transaction."""

    def _open_context_service_evaluation_publication(
        self,
        service_capability: object,
    ) -> object:
        """Create one transaction-bound, single-use publication permit."""
        ...

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

    def _put_context_service_evaluation(
        self,
        transaction_capability: object,
        condition: EvaluationCommitAuthorityCondition,
        artifact_preparation: EvaluationArtifactPreparation,
    ) -> StoredEvaluation:
        """Service-private conditional publication; never a general store write."""
        ...

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]: ...


class EvaluationAuthorityUnitOfWorkPort(Protocol):
    """Narrow unit of work created from one actual ContextService transaction."""

    def resolve_context(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> tuple[ResolvedPublishedContext, AuthorizationGrantToken]: ...

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
        condition: EvaluationCommitAuthorityCondition,
        artifact_preparation: EvaluationArtifactPreparation,
    ) -> StoredEvaluation: ...

    def list_evaluations(self) -> tuple[StoredEvaluation, ...]: ...


@runtime_checkable
class ContextServiceEvaluationPublicationStorePort(Protocol):
    """Backend contract that binds publication to one ContextService owner."""

    def _bind_context_service_evaluation_publication(
        self,
        capability: object,
    ) -> None: ...

    def _bind_context_service_evaluation_collection_authority(
        self,
        capability: object,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        trust_configuration: CollectorTrustConfiguration,
    ) -> None:
        """Pin the configuration used by the same publication backend."""
        ...


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
    "ContextServiceEvaluationPublicationStorePort",
    "EvaluationArtifactPreparation",
    "EvaluationCollectionAuthority",
    "EvaluationCommitAuthorityCondition",
    "EvaluationAuthorityTransactionPort",
    "EvaluationAuthorityUnitOfWorkPort",
    "EvaluationTemporalValidity",
    "EvaluationTrustedKeyAuthority",
    "PreparedEvaluationArtifact",
    "DemoEvaluationTrustConfiguration",
    "PublishedContextResolverPort",
    "SnapshotSigningPort",
    "SnapshotSigningRequest",
    "StoredEvaluation",
    "build_demo_evaluation_candidate_digest",
    "build_demo_evaluation_request_digest",
    "build_evaluation_collection_authority",
    "build_evaluation_evidence_binding_digest",
    "TrustedWc008DeploymentConfigurationPort",
]
