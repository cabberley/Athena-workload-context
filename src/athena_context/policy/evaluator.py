from __future__ import annotations

from datetime import datetime

from athena_context.contracts.common import AthenaValidationError
from athena_context.contracts.manifest import (
    EvidenceContextVerifier,
    EvidenceReferenceContext,
    ManifestFinding,
    ResolvedManifestProfile,
    validate_resolved_manifest_profile,
)
from athena_context.contracts.models import EvidenceScope
from athena_context.policy.domain import evaluate_constraint, normalized_id


def _scope_contains(allowed: EvidenceScope, authorized: EvidenceScope) -> bool:
    if allowed.canonical_json() == authorized.canonical_json():
        return True
    if allowed.scope_type == "subscription" and authorized.scope_type in {
        "resourceGroup",
        "logAnalyticsWorkspace",
    }:
        return (
            allowed.tenant_id == authorized.tenant_id
            and allowed.subscription_id == authorized.subscription_id
        )
    if allowed.scope_type == "subscription" and authorized.scope_type == "resourceId":
        prefix = f"/subscriptions/{allowed.subscription_id}/"
        return authorized.resource_id.casefold().startswith(prefix.casefold())
    if allowed.scope_type == "resourceGroup" and authorized.scope_type == "resourceId":
        prefix = (
            f"/subscriptions/{allowed.subscription_id}/resourceGroups/"
            f"{allowed.resource_group_name}/"
        )
        return authorized.resource_id.casefold().startswith(prefix.casefold())
    if allowed.scope_type == "resourceId" and authorized.scope_type == "resourceId":
        allowed_id = allowed.resource_id.rstrip("/").casefold()
        authorized_id = authorized.resource_id.rstrip("/").casefold()
        return authorized_id == allowed_id or authorized_id.startswith(allowed_id + "/")
    return False


def _validate_evaluation_context(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    *,
    as_of: datetime,
) -> None:
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise AthenaValidationError("trusted as_of must be timezone-aware")
    validate_resolved_manifest_profile(profile, as_of=as_of)
    if (
        evidence.manifest_id != profile.manifest_id
        or normalized_id(evidence.profile_id) != normalized_id(profile.profile_id)
        or evidence.resolved_profile_digest != profile.resolved_profile_digest
    ):
        raise AthenaValidationError(
            "evidence reference context does not match resolved profile"
        )
    if any(
        not any(
            _scope_contains(allowed_scope, authorized_scope)
            for allowed_scope in profile.allowed_evidence_scopes
        )
        for authorized_scope in evidence.authorized_scopes
    ):
        raise AthenaValidationError(
            "evidence reference context exceeds manifest allowedEvidenceScopes"
        )
    if not (evidence.collected_at <= as_of < evidence.expires_at):
        raise AthenaValidationError(
            "evidence reference context is stale at trusted as_of"
        )

def _evaluate_verified_profile(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    *,
    as_of: datetime,
) -> dict[str, ManifestFinding]:
    findings: dict[str, ManifestFinding] = {}
    for constraint in sorted(
        profile.constraints,
        key=lambda item: normalized_id(item.constraint_id),
    ):
        decision = evaluate_constraint(
            profile,
            evidence,
            constraint,
            as_of=as_of,
        )
        if not decision.evidence_refs:
            raise AthenaValidationError(
                f"constraint {constraint.constraint_id} requires typed evidence or gap references"
            )
        findings[constraint.constraint_id] = ManifestFinding(
            clauseId=constraint.constraint_id,
            findingKind=constraint.finding_kind,
            verdict=decision.verdict,
            manifestId=profile.manifest_id,
            manifestVersion=profile.manifest_version,
            profileId=profile.profile_id,
            resolvedProfileDigest=profile.resolved_profile_digest,
            governanceScope=constraint.governance_scope,
            evidenceRefs=list(decision.evidence_refs),
            riskAcceptanceRef=decision.risk_acceptance_ref,
        )
    return findings


def evaluate_manifest_profile(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    *,
    as_of: datetime,
    verify_evidence_context: EvidenceContextVerifier,
) -> dict[str, ManifestFinding]:
    """Evaluate canonical inputs after their evidence boundary verifies provenance."""

    _validate_evaluation_context(profile, evidence, as_of=as_of)
    verify_evidence_context(evidence, as_of)
    return _evaluate_verified_profile(profile, evidence, as_of=as_of)


evaluate_profile = evaluate_manifest_profile
evaluate_policy = evaluate_manifest_profile


__all__ = ["evaluate_manifest_profile", "evaluate_policy", "evaluate_profile"]
