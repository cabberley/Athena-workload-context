from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from athena_context.api.domain import Actor, ensure_timestamp
from athena_context.api.errors import (
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_context import (
    build_resource_evidence_context,
    make_resource_snapshot_context_verifier,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationCommand,
    DemoEvaluationResult,
    VerifiedWc008DeploymentConfiguration,
    build_authorized_publication,
)
from athena_context.api.evaluation_ports import (
    ConfiguredEvidenceClientPort,
    EvaluationCommitCandidate,
    SnapshotSigningPort,
    SnapshotSigningRequest,
    TrustedWc008DeploymentConfigurationPort,
)
from athena_context.api.evaluation_snapshot import (
    finalize_signed_snapshot,
    prepare_snapshot_signing_material,
)
from athena_context.api.ports import ClockPort
from athena_context.api.service import ContextService
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceGapRecord,
    SnapshotPublicationRecord,
    compute_artifact_digest,
)
from athena_context.evidence import (
    CollectedEvidence,
    EvidenceClientError,
    EvidenceCollectionCommand,
)
from athena_context.policy import evaluate_manifest_profile


@dataclass(frozen=True, slots=True)
class DemoEvaluationDependencies:
    """Non-authoritative adapters safe for an app-owned service to compose."""

    deployment_configuration: TrustedWc008DeploymentConfigurationPort
    evidence_client: ConfiguredEvidenceClientPort
    snapshot_signer: SnapshotSigningPort
    clock: ClockPort
    context_reader_actor: Actor


class DemoEvaluationService:
    """Collect and evaluate; ContextService alone owns authoritative publication."""

    def __init__(
        self,
        *,
        context_service: ContextService,
        context_reader_actor: Actor,
        deployment_configuration: TrustedWc008DeploymentConfigurationPort,
        evidence_client: ConfiguredEvidenceClientPort,
        snapshot_signer: SnapshotSigningPort,
        clock: ClockPort,
    ) -> None:
        verified_configuration = deployment_configuration.load_verified()
        if not isinstance(
            verified_configuration,
            VerifiedWc008DeploymentConfiguration,
        ):
            raise DemoEvaluationConfigurationError(
                "WC-008 deployment configuration was not returned as an "
                "operator-verified configuration by a trusted port"
            )
        self._context_service = context_service
        self._context_reader_actor = context_reader_actor
        self._deployment_configuration = verified_configuration
        self._evidence_client = evidence_client
        self._snapshot_signer = snapshot_signer
        self._clock = clock
        self._validate_composition()

    @classmethod
    def from_dependencies(
        cls,
        *,
        context_service: ContextService,
        dependencies: DemoEvaluationDependencies,
    ) -> DemoEvaluationService:
        return cls(
            context_service=context_service,
            context_reader_actor=dependencies.context_reader_actor,
            deployment_configuration=dependencies.deployment_configuration,
            evidence_client=dependencies.evidence_client,
            snapshot_signer=dependencies.snapshot_signer,
            clock=dependencies.clock,
        )

    def _validate_composition(self) -> None:
        configuration = self._deployment_configuration
        assertion = configuration.assertion
        trust = self._evidence_client.trust_configuration
        if self._evidence_client.deployment_configuration != configuration:
            raise DemoEvaluationConfigurationError(
                "actual evidence transport is not bound to the trusted WC-008 "
                "deployment assertion"
            )
        if (
            trust.managed_identity_object_id
            != assertion.evidence_identity_object_id
            or trust.context_identity_object_id
            != assertion.context_identity_object_id
        ):
            raise DemoEvaluationConfigurationError(
                "WC-009 trust identities do not match WC-008 deployment outputs"
            )
        if (
            trust.trust_anchor_ref
            != self._evidence_client.trusted_key_anchor.key_vault_key_id
        ):
            raise DemoEvaluationConfigurationError(
                "trusted snapshot key does not match the evidence ingestion anchor"
            )

    def evaluate(
        self,
        actor: Actor,
        idempotency_key: str,
        command: DemoEvaluationCommand,
    ) -> DemoEvaluationResult:
        request_digest = self._request_digest(actor, command)
        replay = self._context_service.load_demo_evaluation_receipt(
            actor,
            idempotency_key,
            manifest_id=command.manifest_id,
        )
        if replay is not None:
            if replay.request_digest != request_digest:
                raise IdempotencyConflictError(
                    "idempotency key was used for a different demo evaluation"
                )
            return DemoEvaluationResult.model_validate_json(replay.result_json)

        approval, resolved_context, expected_authority = (
            self._context_service.prepare_demo_evaluation_authority(
                reader_actor=self._context_reader_actor,
                actor=actor,
                command=command,
                as_of=self._now(),
                private_mcp_endpoint=self._actual_private_mcp_endpoint,
                evidence_identity_object_id=(
                    self._deployment_configuration.assertion
                    .evidence_identity_object_id
                ),
            )
        )
        profile = resolved_context.profile
        collected = self._collect(command)
        attested_at = self._now()
        try:
            material = prepare_snapshot_signing_material(
                collected,
                snapshot_id=command.snapshot_id,
                trust_configuration=self._evidence_client.trust_configuration,
                trusted_key_anchor=self._evidence_client.trusted_key_anchor,
                attested_at=attested_at,
            )
            signature = self._snapshot_signer.sign(
                SnapshotSigningRequest(
                    canonical_preimage=material.canonical_signing_preimage,
                    preimage_digest=material.signing_preimage_digest,
                    trusted_key_anchor=self._evidence_client.trusted_key_anchor,
                )
            )
            snapshot = finalize_signed_snapshot(material, signature=signature)
        except (AthenaValidationError, ValueError) as exc:
            raise EvaluationFailedClosedError(
                "canonical evidence snapshot assembly or signing failed"
            ) from exc

        evaluated_at = self._now()
        if evaluated_at >= snapshot.expires_at:
            raise EvaluationFailedClosedError(
                "snapshot became stale before publication"
            )
        provisional_publication = build_authorized_publication(
            snapshot=snapshot,
            approval=approval,
            publisher=actor,
            publication_actor=self._context_service.publication_actor,
            published_at=evaluated_at,
            resolved_profile_digest=profile.resolved_profile_digest,
            endpoint=self._actual_private_mcp_endpoint,
            scope=command.authorized_scope,
            reason=command.reason,
        )
        registry_record = provisional_publication.registry_record()

        def publication_resolver(
            snapshot_id: str,
        ) -> SnapshotPublicationRecord | None:
            return registry_record if snapshot_id == snapshot.snapshot_id else None

        def envelope_resolver(
            attempt_id: str,
            kind: Literal["response", "failure"],
            digest: str,
        ) -> object | None:
            envelope = collected.envelope
            if (
                envelope is not None
                and attempt_id == collected.collector_attempt.attempt_id
                and kind == envelope.kind
                and digest == envelope.digest
            ):
                return envelope.payload()
            return None

        try:
            evidence = build_resource_evidence_context(profile, snapshot)
            verifier = make_resource_snapshot_context_verifier(
                snapshot,
                profile,
                as_of=evaluated_at,
                expected_artifact_digest=snapshot.compatibility.artifact_digest,
                publication_resolver=publication_resolver,
                key_resolver=self._evidence_client.key_resolver,
                trusted_key_anchor=self._evidence_client.trusted_key_anchor,
                envelope_resolver=envelope_resolver,
            )
            findings_by_clause = evaluate_manifest_profile(
                profile,
                evidence,
                as_of=evaluated_at,
                verify_evidence_context=verifier,
            )
        except AthenaValidationError as exc:
            raise EvaluationFailedClosedError(
                "verified evidence did not satisfy authoritative manifest evaluation"
            ) from exc

        findings = tuple(
            findings_by_clause[clause_id]
            for clause_id in sorted(findings_by_clause, key=str.casefold)
        )
        envelope = collected.envelope
        if envelope is None:
            raise EvaluationFailedClosedError(
                "successful evidence publication requires a validated source envelope"
            )
        candidate = EvaluationCommitCandidate(
            actor=actor,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            command=command,
            snapshot=snapshot,
            findings=findings,
            envelope_attempt_id=collected.collector_attempt.attempt_id,
            envelope=envelope,
            expected_authority=expected_authority,
            private_mcp_endpoint=self._actual_private_mcp_endpoint,
            evidence_identity_object_id=(
                self._deployment_configuration.assertion
                .evidence_identity_object_id
            ),
        )
        self._before_authoritative_commit()
        return self._context_service.commit_demo_evaluation(
            reader_actor=self._context_reader_actor,
            candidate=candidate,
        )

    def _before_authoritative_commit(self) -> None:
        """Test seam before ContextService opens its authoritative transaction."""

    def _collect(self, command: DemoEvaluationCommand) -> CollectedEvidence:
        assertion = self._deployment_configuration.assertion
        if not assertion.authorizes_inventory_scope(command.authorized_scope):
            raise EvidenceCollectionRejectedError(
                "authorized scope has no exact WC-008 Reader assignment"
            )
        collection_command = EvidenceCollectionCommand(
            attemptId=command.attempt_id,
            evidenceScope=command.authorized_scope,
            authorizedScopes=(command.authorized_scope,),
            bounds=command.bounds,
        )
        try:
            collected = self._evidence_client.collect(collection_command)
        except EvidenceClientError as exc:
            raise EvidenceCollectionRejectedError(
                "typed WC-009 evidence collection failed closed"
            ) from exc
        if (
            collected.request.evidence_scope.canonical_json()
            != command.authorized_scope.canonical_json()
            or tuple(
                scope.canonical_json()
                for scope in collected.request.authorized_scopes
            )
            != (command.authorized_scope.canonical_json(),)
        ):
            raise EvidenceCollectionRejectedError(
                "collected evidence exceeded the explicitly authorized scope"
            )
        identity = collected.collector_identity_evidence
        claims = identity.verified_claims
        if (
            claims.managed_identity_object_id
            != assertion.evidence_identity_object_id
            or claims.managed_identity_object_id
            != self._evidence_client.trust_configuration.managed_identity_object_id
        ):
            raise EvidenceCollectionRejectedError(
                "collected evidence identity does not match the read-only MCP identity"
            )
        gaps = [
            record
            for record in collected.evidence_records
            if isinstance(record, EvidenceGapRecord)
        ]
        if (
            collected.collector_attempt.attempt_type != "successResponse"
            or gaps
            or not collected.evidence_records
            or collected.envelope is None
        ):
            reasons = sorted({gap.gap_reason for gap in gaps})
            detail = (
                ",".join(reasons)
                if reasons
                else collected.collector_attempt.attempt_type
            )
            raise EvidenceCollectionRejectedError(
                f"evidence collection produced a fail-closed outcome: {detail}"
            )
        return collected

    def _request_digest(self, actor: Actor, command: DemoEvaluationCommand) -> str:
        return compute_artifact_digest(
            {
                "operation": "evaluate_demo_workload",
                "actor": actor.model_dump(mode="json"),
                "command": command.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
                "wc008DeploymentAssertionDigest": (
                    self._deployment_configuration.assertion.assertion_digest
                ),
                "actualPrivateMcpEndpoint": self._actual_private_mcp_endpoint,
                "trustConfiguration": (
                    self._evidence_client.trust_configuration
                ).model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
            }
        )

    def _now(self) -> datetime:
        return ensure_timestamp(self._clock.now())

    @property
    def _actual_private_mcp_endpoint(self) -> str:
        return (
            self._evidence_client.deployment_configuration.assertion
            .azure_mcp_internal_endpoint
        )

    def get_result(self, actor: Actor, snapshot_id: str) -> DemoEvaluationResult:
        result = self._context_service.get_demo_evaluation_result(
            actor,
            snapshot_id,
        )
        if result is None:
            raise ResourceNotFoundError(
                f"published evaluation snapshot {snapshot_id!r} was not found"
            )
        return result


__all__ = ["DemoEvaluationDependencies", "DemoEvaluationService"]
