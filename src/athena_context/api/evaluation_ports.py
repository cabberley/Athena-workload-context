from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from athena_context.api.domain import (
    Actor,
    Permission,
    PublishedManifestView,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationApproval,
    DemoEvaluationResult,
    VerifiedWc008DeploymentConfiguration,
)
from athena_context.contracts import (
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
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView: ...


class DemoEvaluationApprovalResolverPort(Protocol):
    def resolve(self, decision_id: str) -> DemoEvaluationApproval | None: ...


class SnapshotSigningPort(Protocol):
    def sign(self, request: SnapshotSigningRequest) -> str: ...


class EvaluationArtifactStorePort(Protocol):
    def load_receipt(self, actor_id: str, idempotency_key: str) -> StoredEvaluation | None: ...

    def commit(self, artifact: StoredEvaluation) -> None: ...

    def resolve_publication(self, snapshot_id: str) -> SnapshotPublicationRecord | None: ...

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None: ...


class EvaluationAuthorizationPort(Protocol):
    def require(self, actor: Actor, permission: Permission, manifest_id: str) -> None: ...


__all__ = [
    "ConfiguredEvidenceClientPort",
    "DemoEvaluationApprovalResolverPort",
    "EvaluationArtifactStorePort",
    "EvaluationAuthorizationPort",
    "PublishedContextResolverPort",
    "SnapshotSigningPort",
    "SnapshotSigningRequest",
    "StoredEvaluation",
    "TrustedWc008DeploymentConfigurationPort",
]
