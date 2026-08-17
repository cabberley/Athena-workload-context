from __future__ import annotations

from datetime import datetime

from athena_context.api.domain import Actor
from athena_context.api.errors import EvaluationFailedClosedError
from athena_context.api.evaluation_context import (
    build_resource_evidence_context,
    make_resource_snapshot_context_verifier,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationApproval,
    ResolvedPublishedContext,
    build_authorized_publication,
)
from athena_context.api.evaluation_ports import EvaluationTrustedKeyAuthority
from athena_context.contracts import (
    AthenaValidationError,
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
)
from athena_context.evidence import ValidatedEnvelope
from athena_context.policy import evaluate_manifest_profile


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


__all__ = ["verify_and_evaluate_snapshot_for_publication"]
