from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from athena_context.api.domain import Actor, ActorKind
from athena_context.api.errors import (
    DemoEvaluationApprovalError,
    EvaluationFailedClosedError,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    ResolvedPublishedContext,
)
from athena_context.binding.selectors import evaluate_selector, normalize_resource_id
from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceContextVerifier,
    EvidenceItemRef,
    EvidenceRecord,
    EvidenceReferenceContext,
    EvidenceSnapshot,
    ResolvedManifestProfile,
    ResourceEvidenceRecord,
    ResourceProofFact,
    RoleBindingProof,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
    compute_artifact_digest,
    resolve_manifest_profile,
    validate_resolved_manifest_profile,
    verified_snapshot_context_verifier,
)
from athena_context.contracts.common import normalize_nfc_text
from athena_context.contracts.manifest import ProofFact


def _normalized(value: str) -> str:
    return value.casefold()


def require_active_manifest_governance(
    manifest: CanonicalWorkloadManifest,
    profile: ResolvedManifestProfile,
    *,
    as_of: datetime,
) -> None:
    """Validate a canonically resolved profile and every resolved risk decision."""

    validate_resolved_manifest_profile(
        profile,
        as_of=as_of,
        require_active_governance=True,
    )
    if (
        profile.manifest_id != manifest.manifest_id
        or profile.manifest_version != manifest.manifest_version
    ):
        raise AthenaValidationError(
            "resolved profile does not belong to the published manifest"
        )
    for acceptance in profile.risk_acceptances:
        if not (
            acceptance.status == "approved"
            and acceptance.accepted_at <= as_of < acceptance.expires_at
        ):
            raise AthenaValidationError(
                "risk acceptance is not active: "
                f"{acceptance.risk_acceptance_id}"
            )


def resolve_active_manifest_profile(
    manifest: CanonicalWorkloadManifest,
    profile_id: str,
    *,
    as_of: datetime,
) -> ResolvedManifestProfile:
    """Canonically re-resolve inheritance and applied governance at trusted time."""

    profile = resolve_manifest_profile(
        manifest,
        profile_id,
        as_of=as_of,
    )
    require_active_manifest_governance(
        manifest,
        profile,
        as_of=as_of,
    )
    return profile


def validate_demo_evaluation_approval(
    actor: Actor,
    command: DemoEvaluationCommand,
    approval: DemoEvaluationApproval,
    *,
    as_of: datetime,
    private_mcp_endpoint: str,
    evidence_identity_object_id: str,
) -> None:
    """Require one active human decision bound to the exact evaluation request."""

    if (
        approval.status != "authorized"
        or approval.approved_at > as_of
        or approval.expires_at <= as_of
        or approval.revoked_at is not None
    ):
        raise DemoEvaluationApprovalError(
            "demo evaluation approval is not active at the trusted evaluation time"
        )
    if (
        approval.decision_id != command.approval_decision_id
        or approval.manifest_id != command.manifest_id
        or (
            command.manifest_version is not None
            and approval.manifest_version != command.manifest_version
        )
        or approval.manifest_digest != command.expected_manifest_digest
        or approval.profile_id != command.profile_id
        or approval.authorized_scope.canonical_json()
        != command.authorized_scope.canonical_json()
        or approval.private_mcp_endpoint != private_mcp_endpoint
        or approval.evidence_identity_object_id != evidence_identity_object_id
    ):
        raise DemoEvaluationApprovalError(
            "approval does not authorize this exact endpoint, identity, context, and scope"
        )
    if actor.kind is not ActorKind.HUMAN:
        raise DemoEvaluationApprovalError(
            "only an authorized human publisher may execute an approval"
        )


def validate_published_context_binding(
    command: DemoEvaluationCommand,
    approval: DemoEvaluationApproval,
    context: ResolvedPublishedContext,
) -> None:
    """Bind an exact or uniquely selected WC-007 version to its approval."""

    published = context.view.published
    profile = context.profile
    if (
        published.manifest_id != command.manifest_id
        or (
            command.manifest_version is not None
            and published.manifest_version != command.manifest_version
        )
        or published.manifest_version != approval.manifest_version
        or published.manifest_digest != command.expected_manifest_digest
        or published.manifest_digest != approval.manifest_digest
        or profile.manifest_id != command.manifest_id
        or profile.manifest_version != published.manifest_version
        or normalize_nfc_text(profile.profile_id).casefold()
        != command.profile_id
    ):
        raise EvaluationFailedClosedError(
            "resolved published context/profile does not match the approved "
            "immutable selection"
        )
    if profile.resolved_profile_digest != command.expected_resolved_profile_digest:
        raise EvaluationFailedClosedError(
            "resolved profile digest does not match the requested authoritative context"
        )


def _select_role_resources(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
) -> dict[str, tuple[ResourceEvidenceRecord, ...]]:
    records = tuple(
        record
        for record in snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
    )
    records_by_id = {
        normalize_resource_id(record.resource_id): record for record in records
    }
    if len(records_by_id) != len(records):
        raise AthenaValidationError(
            "canonical snapshot contains duplicate normalized resource IDs"
        )

    selected_by_role: dict[str, tuple[ResourceEvidenceRecord, ...]] = {}
    memberships: dict[str, list[str]] = {}
    for role in sorted(profile.roles, key=lambda item: _normalized(item.role_id)):
        if role.status != "approved":
            continue
        selected_ids: set[str] = set()
        for selector in role.selectors:
            result = evaluate_selector(selector, records)
            if result.status == "overMaxMatches":
                raise AthenaValidationError(
                    f"role selector exceeded maxMatches: {role.role_id}"
                )
            selected_ids.update(result.matched_resource_ids)
        selected = tuple(
            sorted(
                (records_by_id[resource_id] for resource_id in selected_ids),
                key=lambda item: _normalized(item.resource_id),
            )
        )
        selected_by_role[role.role_id] = selected
        for resource_id in selected_ids:
            memberships.setdefault(resource_id, []).append(role.role_id)

    if any(len(role_ids) != 1 for role_ids in memberships.values()):
        raise AthenaValidationError(
            "published manifest selectors produced ambiguous role bindings"
        )
    if set(memberships) != set(records_by_id):
        raise AthenaValidationError(
            "canonical snapshot contains a resource without one exact role binding"
        )
    return selected_by_role


def _reference_by_item_digest(
    snapshot: EvidenceSnapshot,
) -> dict[str, EvidenceItemRef]:
    references: dict[str, EvidenceItemRef] = {}
    for reference in snapshot.evidence_refs:
        if not isinstance(reference, EvidenceItemRef):
            continue
        if reference.item_digest in references:
            raise AthenaValidationError(
                "canonical snapshot has duplicate item evidence references"
            )
        references[reference.item_digest] = reference
    return references


def _ordered_resource_ids(
    records: tuple[ResourceEvidenceRecord, ...],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            (record.resource_id for record in records),
            key=_normalized,
        )
    )


def build_resource_evidence_context(
    profile: ResolvedManifestProfile,
    snapshot: EvidenceSnapshot,
) -> EvidenceReferenceContext:
    """Build exact resource facts for any supported published manifest profile."""

    selected_by_role = _select_role_resources(profile, snapshot)
    references = _reference_by_item_digest(snapshot)
    resources: list[ResourceProofFact] = []
    bindings: list[RoleBindingProof] = []
    for role_ref in sorted(selected_by_role, key=_normalized):
        selected = selected_by_role[role_ref]
        for record in selected:
            reference = references.get(record.item_digest)
            if reference is None:
                raise AthenaValidationError(
                    "canonical resource record has no evidence reference"
                )
            resources.append(
                ResourceProofFact(
                    resourceId=record.resource_id,
                    roleRef=role_ref,
                    availabilityZone=record.availability_zone or "unknown",
                    state="complete",
                    proofSource="observed",
                    evidenceRef=reference,
                )
            )
        ordered_ids = _ordered_resource_ids(selected)
        bindings.append(
            RoleBindingProof(
                roleRef=role_ref,
                selectedResourceIds=list(ordered_ids),
                selectorResultDigest=compute_artifact_digest(list(ordered_ids)),
                state="complete",
            )
        )

    return EvidenceReferenceContext(
        snapshotId=snapshot.snapshot_id,
        snapshotArtifactDigest=snapshot.compatibility.artifact_digest,
        snapshotSemanticDigest=snapshot.compatibility.semantic_digest,
        collectedAt=snapshot.collected_at,
        expiresAt=snapshot.expires_at,
        authorizedScopes=snapshot.authorized_scopes,
        manifestId=profile.manifest_id,
        profileId=profile.profile_id,
        resolvedProfileDigest=profile.resolved_profile_digest,
        resources=resources,
        roleBindings=bindings,
    )


def make_resource_snapshot_context_verifier(
    snapshot: EvidenceSnapshot,
    profile: ResolvedManifestProfile,
    *,
    as_of: datetime,
    expected_artifact_digest: str,
    publication_resolver: Callable[[str], SnapshotPublicationRecord | None],
    key_resolver: Callable[[TrustedKeyAnchor], Any],
    trusted_key_anchor: TrustedKeyAnchor,
    envelope_resolver: Callable[
        [str, Literal["response", "failure"], str],
        Any,
    ],
) -> EvidenceContextVerifier:
    """Verify facts against the exact immutable snapshot and manifest selectors."""

    expected_by_role = _select_role_resources(profile, snapshot)

    def fact_validator(fact: ProofFact, record: EvidenceRecord) -> bool:
        if not isinstance(fact, ResourceProofFact) or not isinstance(
            record,
            ResourceEvidenceRecord,
        ):
            return False
        selected = expected_by_role.get(fact.role_ref)
        return (
            selected is not None
            and fact.state == "complete"
            and fact.proof_source == "observed"
            and any(
                _normalized(candidate.resource_id)
                == _normalized(record.resource_id)
                for candidate in selected
            )
        )

    def role_binding_validator(
        binding: RoleBindingProof,
        verified_snapshot: EvidenceSnapshot,
    ) -> bool:
        selected = _select_role_resources(profile, verified_snapshot).get(
            binding.role_ref
        )
        if selected is None or binding.state != "complete":
            return False
        expected_ids = _ordered_resource_ids(selected)
        return (
            tuple(binding.selected_resource_ids) == expected_ids
            and binding.selector_result_digest
            == compute_artifact_digest(list(expected_ids))
        )

    return verified_snapshot_context_verifier(
        snapshot,
        as_of=as_of,
        expected_artifact_digest=expected_artifact_digest,
        publication_resolver=publication_resolver,
        identity_evidence=snapshot.identity_evidence,
        key_resolver=key_resolver,
        trusted_key_anchor=trusted_key_anchor,
        envelope_resolver=envelope_resolver,
        fact_validator=fact_validator,
        role_binding_validator=role_binding_validator,
    )


__all__ = [
    "build_resource_evidence_context",
    "make_resource_snapshot_context_verifier",
    "require_active_manifest_governance",
    "resolve_active_manifest_profile",
    "validate_demo_evaluation_approval",
    "validate_published_context_binding",
]
