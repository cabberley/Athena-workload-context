from __future__ import annotations

from datetime import datetime, timedelta

from athena_context.api.domain import Actor
from athena_context.api.errors import EvaluationFailedClosedError
from athena_context.api.evaluation_context import (
    build_resource_evidence_context,
    make_resource_snapshot_context_verifier,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    ResolvedPublishedContext,
    build_authorized_publication,
)
from athena_context.api.evaluation_ports import (
    EvaluationCollectionAuthority,
    EvaluationTrustedKeyAuthority,
    build_evaluation_collection_authority,
)
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
    canonicalize_json,
)
from athena_context.evidence import (
    EvidenceTransportRequest,
    ValidatedEnvelope,
)
from athena_context.policy import evaluate_manifest_profile


def validate_evaluation_collection_binding(
    *,
    command: DemoEvaluationCommand,
    snapshot: EvidenceSnapshot,
    collection_request: EvidenceTransportRequest,
    envelope: ValidatedEnvelope,
    collection_authority: EvaluationCollectionAuthority,
) -> None:
    """Bind signed evidence to the exact service-authorized collection request."""

    expected_authority = build_evaluation_collection_authority(
        collection_authority.deployment_configuration,
        collection_authority.trust_configuration,
        authorized_scope=command.authorized_scope,
    )
    if expected_authority != collection_authority:
        raise EvaluationFailedClosedError(
            "configured WC-008 Reader assignment or revision changed"
        )
    assertion = collection_authority.deployment_configuration.assertion
    trust = collection_authority.trust_configuration
    command_scope = command.authorized_scope.canonical_json()
    request_scopes = tuple(
        scope.canonical_json()
        for scope in collection_request.authorized_scopes
    )
    snapshot_scopes = tuple(
        scope.canonical_json() for scope in snapshot.authorized_scopes
    )
    if (
        snapshot.snapshot_id != command.snapshot_id
        or collection_request.attempt_id != command.attempt_id
        or collection_request.evidence_scope.canonical_json()
        != command_scope
        or request_scopes != (command_scope,)
        or snapshot_scopes != (command_scope,)
        or collection_request.bounds != command.bounds
        or collection_request.collector_identity_evidence_ref
        != trust.collector_identity_evidence_ref
        or snapshot.collected_at != collection_request.attempt_started_at
        or snapshot.expires_at
        != collection_request.attempt_started_at
        + timedelta(seconds=command.bounds.freshness_seconds)
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot does not match the approved snapshot ID, attempt, "
            "scope, or collection bounds"
        )
    if (
        len(snapshot.collector_attempts) != 1
        or snapshot.collector_attempts[0].attempt_id != command.attempt_id
        or snapshot.collector_attempts[0].request_digest
        != collection_request.request_digest
        or snapshot.collector_attempts[0].attempt_started_at
        != collection_request.attempt_started_at
        or snapshot.collector_attempts[0].tool_name
        != collection_request.tool_name
        or snapshot.collector_attempts[0].tool_version
        != collection_request.tool_version
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot collector attempt does not match the bounded request"
        )
    attempt = snapshot.collector_attempts[0]
    deadline = collection_request.attempt_started_at + timedelta(
        milliseconds=command.bounds.timeout_milliseconds
    )
    if (
        attempt.attempt_type != "successResponse"
        or attempt.response_received_at > deadline
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot collector attempt exceeded its approved bounds"
        )
    collector = snapshot.collector
    if (
        collector.collector_identity_evidence_ref
        != trust.collector_identity_evidence_ref
        or collector.mcp_host_id != trust.mcp_host_id
        or collector.tenant_id != trust.tenant_id
        or collector.trust_anchor_ref != trust.trust_anchor_ref
        or collector.ingestion_service_id != trust.ingestion_service_id
        or collector.ingestion_audience != trust.ingestion_audience
        or collector.tool_allowlist_digest != trust.tool_allowlist_digest
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot collector does not match configured evidence trust"
        )
    if len(snapshot.identity_evidence) != 1:
        raise EvaluationFailedClosedError(
            "signed snapshot must contain exactly one configured evidence identity"
        )
    identity = snapshot.identity_evidence[0]
    claims = identity.verified_claims
    derivation = identity.ingestion_derivation
    if (
        identity.identity_evidence_id
        != trust.collector_identity_evidence_ref
        or claims.tenant_id != trust.tenant_id
        or claims.managed_identity_object_id
        != assertion.evidence_identity_object_id
        or claims.managed_identity_object_id
        != trust.managed_identity_object_id
        or claims.managed_identity_client_id
        != trust.managed_identity_client_id
        or derivation.mcp_host_tenant_id != trust.tenant_id
        or derivation.mcp_host_managed_identity_object_id
        != assertion.evidence_identity_object_id
        or derivation.mcp_host_managed_identity_client_id
        != trust.managed_identity_client_id
        or derivation.attempt_binding.attempt_id != command.attempt_id
        or derivation.attempt_binding.request_digest
        != collection_request.request_digest
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot evidence identity or resource authority does not "
            "match the configured WC-008 Reader assignment"
        )
    envelope_payload = envelope.payload()
    if (
        envelope_payload.get("attemptId") != command.attempt_id
        or envelope_payload.get("requestDigest")
        != collection_request.request_digest
        or canonicalize_json(envelope_payload.get("evidenceScope"))
        != command_scope
        or len(envelope.canonical_bytes)
        > command.bounds.max_response_bytes
        or len(snapshot.evidence_records) > command.bounds.max_items
        or any(
            len(
                canonicalize_json(
                    record.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                ).encode("utf-8")
            )
            > command.bounds.max_record_bytes
            for record in snapshot.evidence_records
        )
    ):
        raise EvaluationFailedClosedError(
            "signed snapshot envelope or records exceed the approved collection bounds"
        )


def verify_and_evaluate_snapshot_for_publication(
    *,
    snapshot: EvidenceSnapshot,
    approval: DemoEvaluationApproval,
    publisher: Actor,
    publication_actor: Actor,
    resolved: ResolvedPublishedContext,
    private_mcp_endpoint: str,
    authorized_scope: EvidenceScope,
    reason: str,
    envelope_attempt_id: str,
    envelope: ValidatedEnvelope,
    trusted_key: EvaluationTrustedKeyAuthority,
    trusted_key_anchor: TrustedKeyAnchor,
    as_of: datetime,
) -> tuple[ManifestFinding, ...]:
    """Reverify signature/evidence and recompute policy from exact authority."""

    publication = build_authorized_publication(
        snapshot=snapshot,
        approval=approval,
        publisher=publisher,
        publication_actor=publication_actor,
        published_at=as_of,
        resolved_profile_digest=resolved.profile.resolved_profile_digest,
        endpoint=private_mcp_endpoint,
        scope=authorized_scope,
        reason=reason,
    )
    registry_record = publication.registry_record()

    def publication_resolver(
        snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        return (
            registry_record
            if snapshot_id == snapshot.snapshot_id
            else None
        )

    def envelope_resolver(
        attempt_id: str,
        kind: str,
        digest: str,
    ) -> object | None:
        return (
            envelope.payload()
            if (
                attempt_id == envelope_attempt_id
                and kind == envelope.kind
                and digest == envelope.digest
            )
            else None
        )

    try:
        evidence = build_resource_evidence_context(
            resolved.profile,
            snapshot,
        )
        verifier = make_resource_snapshot_context_verifier(
            snapshot,
            resolved.profile,
            as_of=as_of,
            expected_artifact_digest=(
                snapshot.compatibility.artifact_digest
            ),
            publication_resolver=publication_resolver,
            key_resolver=lambda requested: (
                trusted_key.record
                if requested == trusted_key_anchor
                else None
            ),
            trusted_key_anchor=trusted_key_anchor,
            envelope_resolver=envelope_resolver,
        )
        findings_by_clause = evaluate_manifest_profile(
            resolved.profile,
            evidence,
            as_of=as_of,
            verify_evidence_context=verifier,
        )
    except AthenaValidationError as exc:
        raise EvaluationFailedClosedError(
            "snapshot verification or policy evaluation failed at the "
            "authoritative publication time"
        ) from exc

    constraints = {
        constraint.constraint_id: constraint
        for constraint in resolved.profile.constraints
    }
    for clause_id, finding in findings_by_clause.items():
        constraint = constraints[clause_id]
        if (
            constraint.constraint_type == "evidenceFreshness"
            and finding.verdict != constraint.success_verdict
        ):
            raise EvaluationFailedClosedError(
                "policy evidence freshness failed at the authoritative "
                "publication time"
            )
    return tuple(
        findings_by_clause[clause_id]
        for clause_id in sorted(findings_by_clause, key=str.casefold)
    )


__all__ = [
    "validate_evaluation_collection_binding",
    "verify_and_evaluate_snapshot_for_publication",
]
