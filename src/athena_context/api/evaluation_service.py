from __future__ import annotations

from datetime import datetime
from typing import Literal

from athena_context.api.domain import (
    Actor,
    ActorKind,
    Permission,
    ensure_timestamp,
)
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationApprovalError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_context import (
    build_resource_evidence_context,
    make_resource_snapshot_context_verifier,
    resolve_active_manifest_profile,
    validate_demo_evaluation_approval,
    validate_published_context_binding,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationCommand,
    DemoEvaluationResult,
    EvaluationAuthorityToken,
    PublishedContextSelection,
    ResolvedPublishedContext,
    VerifiedWc008DeploymentConfiguration,
    build_authorized_publication,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    ConfiguredEvidenceClientPort,
    DemoEvaluationApprovalResolverPort,
    EvaluationAuthorizationPort,
    EvaluationCommitCandidate,
    EvaluationCommitPort,
    PublishedContextResolverPort,
    SnapshotSigningPort,
    SnapshotSigningRequest,
    TrustedWc008DeploymentConfigurationPort,
)
from athena_context.api.evaluation_snapshot import (
    finalize_signed_snapshot,
    prepare_snapshot_signing_material,
)
from athena_context.api.ports import ClockPort
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


class DemoEvaluationService:
    """Authoritative collect, attest, publish, resolve, and evaluate orchestration."""

    def __init__(
        self,
        *,
        deployment_configuration: TrustedWc008DeploymentConfigurationPort,
        evidence_client: ConfiguredEvidenceClientPort,
        context_resolver: PublishedContextResolverPort,
        approval_resolver: DemoEvaluationApprovalResolverPort,
        snapshot_signer: SnapshotSigningPort,
        evaluation_commit: EvaluationCommitPort,
        authorization: EvaluationAuthorizationPort,
        clock: ClockPort,
        publication_actor: Actor,
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
        self._deployment_configuration = verified_configuration
        self._evidence_client = evidence_client
        self._context_resolver = context_resolver
        self._approval_resolver = approval_resolver
        self._snapshot_signer = snapshot_signer
        self._evaluation_commit = evaluation_commit
        self._authorization = authorization
        self._clock = clock
        self._publication_actor = publication_actor
        self._validate_composition()

    def _validate_composition(self) -> None:
        configuration = self._deployment_configuration
        assertion = configuration.assertion
        trust = self._evidence_client.trust_configuration
        if self._publication_actor.kind is not ActorKind.SERVICE:
            raise DemoEvaluationConfigurationError(
                "snapshot publication actor must be the Context API service"
            )
        if self._context_resolver is not self._evaluation_commit.context_resolver:
            raise DemoEvaluationConfigurationError(
                "published context resolver must be owned by the transactional "
                "evaluation commit adapter"
            )
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
        authorization_token = self._authorization.authorize(
            actor,
            Permission.PUBLISH,
            command.manifest_id,
        )
        request_digest = self._request_digest(actor, command)
        replay = self._evaluation_commit.load_receipt(
            actor.actor_id,
            idempotency_key,
        )
        if replay is not None:
            if replay.request_digest != request_digest:
                raise IdempotencyConflictError(
                    "idempotency key was used for a different demo evaluation"
                )
            return DemoEvaluationResult.model_validate_json(replay.result_json)

        as_of = self._now()
        approval = self._approval_resolver.resolve(command.approval_decision_id)
        if approval is None:
            raise DemoEvaluationApprovalError(
                "trusted demo evaluation approval decision was not found"
            )
        validate_demo_evaluation_approval(
            actor,
            command,
            approval,
            as_of=as_of,
            private_mcp_endpoint=self._actual_private_mcp_endpoint,
            evidence_identity_object_id=(
                self._deployment_configuration.assertion.evidence_identity_object_id
            ),
        )

        resolved_context = self._resolve_published_context(command, as_of=as_of)
        validate_published_context_binding(command, approval, resolved_context)
        profile = resolved_context.profile
        expected_authority = EvaluationAuthorityToken(
            context=resolved_context.authority_token,
            approval=approval.authority_token(),
            authorization=authorization_token,
        )

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
            raise EvaluationFailedClosedError("snapshot became stale before publication")
        provisional_publication = build_authorized_publication(
            snapshot=snapshot,
            approval=approval,
            publisher=actor,
            publication_actor=self._publication_actor,
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
        return self._evaluation_commit.commit(
            EvaluationCommitCandidate(
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
            )
        )

    def _resolve_published_context(
        self,
        command: DemoEvaluationCommand,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        try:
            resolved = self._context_resolver.resolve(
                PublishedContextSelection(
                    manifest_id=command.manifest_id,
                    manifest_version=command.manifest_version,
                    profile_id=command.profile_id,
                ),
                as_of=as_of,
            )
            if resolved.view.supersession is not None:
                raise AthenaValidationError(
                    "superseded context cannot authorize evaluation"
                )
            canonical_profile = resolve_active_manifest_profile(
                resolved.view.published.manifest,
                command.profile_id,
                as_of=as_of,
            )
            if canonical_profile != resolved.profile:
                raise AthenaValidationError(
                    "trusted resolver profile does not match canonical resolution"
                )
            return ResolvedPublishedContext(
                view=resolved.view,
                profile=canonical_profile,
                authority_token=build_published_context_authority_token(
                    resolved.view,
                    canonical_profile,
                    requested_manifest_version=command.manifest_version,
                ),
            )
        except (
            AmbiguousLookupError,
            AthenaValidationError,
            ResourceNotFoundError,
            ValueError,
        ) as exc:
            raise EvaluationFailedClosedError(
                "published context/profile is missing, ambiguous, a superseded "
                "context, or has inactive governance"
            ) from exc

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
                scope.canonical_json() for scope in collected.request.authorized_scopes
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
            detail = ",".join(reasons) if reasons else collected.collector_attempt.attempt_type
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
        result = self._evaluation_commit.resolve_result(snapshot_id)
        if result is None:
            raise ResourceNotFoundError(
                f"published evaluation snapshot {snapshot_id!r} was not found"
            )
        self._authorization.authorize(
            actor,
            Permission.READ,
            result.publication.manifest_id,
        )
        return result


__all__ = ["DemoEvaluationService"]
