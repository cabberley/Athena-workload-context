from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from athena_context.api.domain import Actor, ensure_timestamp
from athena_context.api.errors import (
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
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
    SealedMcpTransportConfiguration,
    SnapshotSigningPort,
    SnapshotSigningRequest,
    TrustedWc008DeploymentConfigurationPort,
    seal_mcp_transport_configuration,
    sealed_mcp_transport_configuration_primitives,
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
        try:
            normalized_configuration, transport_configuration = (
                seal_mcp_transport_configuration(verified_configuration)
            )
        except ValueError as exc:
            raise DemoEvaluationConfigurationError(
                "WC-008 deployment configuration must use exact verified "
                "base models"
            ) from exc
        self._context_service = context_service
        self._context_reader_actor = context_reader_actor
        self._deployment_configuration = normalized_configuration
        self._transport_configuration: SealedMcpTransportConfiguration = (
            transport_configuration
        )
        self._evidence_client = evidence_client
        self._snapshot_signer = snapshot_signer
        self._clock = clock
        self._validate_composition()
        self.__orchestrator_capability = (
            self._context_service._bind_demo_evaluation_orchestrator(
                deployment_configuration=self._deployment_configuration,
                trust_configuration=self._evidence_client.trust_configuration,
            )
        )

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
        from athena_context.api.evaluation_adapters import (
            Wc009EvidenceClientAdapter,
        )

        if type(self._evidence_client) is not Wc009EvidenceClientAdapter:
            raise DemoEvaluationConfigurationError(
                "demo evaluation requires the exact endpoint-bound WC-009 "
                "evidence client adapter"
            )
        configuration = self._deployment_configuration
        assertion = configuration.assertion
        trust = self._evidence_client.trust_configuration
        self._require_exact_transport_binding()
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
        self._context_service.require_demo_evaluation_trust_anchor(
            self._evidence_client.trusted_key_anchor
        )

    def _require_exact_transport_binding(self) -> None:
        try:
            expected = sealed_mcp_transport_configuration_primitives(
                self._transport_configuration
            )
            actual = sealed_mcp_transport_configuration_primitives(
                self._evidence_client.transport_configuration
            )
        except ValueError as exc:
            raise DemoEvaluationConfigurationError(
                "actual evidence transport does not expose an exact sealed "
                "WC-008 configuration"
            ) from exc
        if actual != expected:
            raise DemoEvaluationConfigurationError(
                "actual evidence transport is not bound to the trusted WC-008 "
                "deployment assertion"
            )

    def evaluate(
        self,
        actor: Actor,
        idempotency_key: str,
        command: DemoEvaluationCommand,
    ) -> DemoEvaluationResult:
        self._require_exact_transport_binding()
        prepared_request = (
            self._context_service._prepare_demo_evaluation_request(
                orchestrator_capability=self.__orchestrator_capability,
                reader_actor=self._context_reader_actor,
                actor=actor,
                idempotency_key=idempotency_key,
                command=command,
                as_of=self._now(),
            )
        )
        if prepared_request.replay is not None:
            return DemoEvaluationResult.model_validate_json(
                prepared_request.replay.result_json
            )
        approval = prepared_request.approval
        resolved_context = prepared_request.resolved
        if approval is None or resolved_context is None:
            self._context_service._discard_demo_evaluation_request(
                prepared_request
            )
            raise EvaluationFailedClosedError(
                "ContextService returned an incomplete evaluation request"
            )
        profile = resolved_context.profile
        try:
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
                snapshot = finalize_signed_snapshot(
                    material,
                    signature=signature,
                )
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
                evaluate_manifest_profile(
                    profile,
                    evidence,
                    as_of=evaluated_at,
                    verify_evidence_context=verifier,
                )
            except AthenaValidationError as exc:
                raise EvaluationFailedClosedError(
                    "verified evidence did not satisfy preflight manifest evaluation"
                ) from exc
            if collected.envelope is None:
                raise EvaluationFailedClosedError(
                    "successful evidence publication requires a validated source envelope"
                )
            self._before_authoritative_commit()
            return self._context_service._commit_prepared_demo_evaluation(
                prepared_request=prepared_request,
                snapshot=snapshot,
                collected=collected,
            )
        finally:
            self._context_service._discard_demo_evaluation_request(
                prepared_request
            )

    def _before_authoritative_commit(self) -> None:
        """Test seam before ContextService opens its authoritative transaction."""

    def _collect(self, command: DemoEvaluationCommand) -> CollectedEvidence:
        self._require_exact_transport_binding()
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

    def _now(self) -> datetime:
        return ensure_timestamp(self._clock.now())

    @property
    def _actual_private_mcp_endpoint(self) -> str:
        return self._transport_configuration.private_mcp_endpoint

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
