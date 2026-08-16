from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from datetime import datetime

from athena_context.contracts.common import AthenaValidationError
from athena_context.contracts.manifest import (
    CardinalityProof,
    ControlHealthProof,
    DeclaredManifestRelationship,
    EvidenceFreshnessProof,
    EvidenceReferenceContext,
    ExceptionManifestRelationship,
    FindingVerdict,
    ManifestConstraint,
    ManifestRiskAcceptance,
    ObjectiveThresholdProof,
    RelationshipPresenceProof,
    ResolvedManifestProfile,
    ResourceProofFact,
    RoleEndpoint,
    ZoneColocationProof,
    ZoneDistributionProof,
)
from athena_context.contracts.models import EvidenceReference


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A pure intermediate decision before canonical finding serialization."""

    verdict: FindingVerdict
    evidence_refs: tuple[EvidenceReference, ...]
    risk_acceptance_ref: str | None = None


@dataclass(frozen=True, slots=True)
class _BoundResources:
    resources: tuple[ResourceProofFact, ...]
    gate: FindingVerdict | None


def normalized_id(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _merge_gates(*gates: FindingVerdict | None) -> FindingVerdict | None:
    if "conflicting" in gates:
        return "conflicting"
    if "unknown" in gates:
        return "unknown"
    return None


def _resource_gate(resources: tuple[ResourceProofFact, ...]) -> FindingVerdict | None:
    if not resources:
        return "unknown"
    if any(resource.state == "conflicting" for resource in resources):
        return "conflicting"
    if any(resource.state != "complete" for resource in resources):
        return "unknown"
    if any(resource.proof_source == "inferred" for resource in resources):
        return "unknown"
    return None


def _bound_role_resources(
    evidence: EvidenceReferenceContext,
    role_ref: str,
) -> _BoundResources:
    resources = tuple(
        sorted(
            (
                resource
                for resource in evidence.resources
                if normalized_id(resource.role_ref) == normalized_id(role_ref)
            ),
            key=lambda resource: normalized_id(resource.resource_id),
        )
    )
    bindings = [
        binding
        for binding in evidence.role_bindings
        if normalized_id(binding.role_ref) == normalized_id(role_ref)
    ]
    if len(bindings) != 1:
        return _BoundResources(resources, "unknown")
    binding = bindings[0]
    if binding.state == "conflicting":
        return _BoundResources(resources, "conflicting")
    if binding.state != "complete":
        return _BoundResources(resources, "unknown")
    selected = {normalized_id(resource_id) for resource_id in binding.selected_resource_ids}
    actual = {normalized_id(resource.resource_id) for resource in resources}
    if selected != actual:
        return _BoundResources(resources, "unknown")
    return _BoundResources(resources, None)


def _cardinality_bounds(proof: CardinalityProof) -> tuple[int, int]:
    expected = proof.expected
    if expected.cardinality_kind == "exactlyOne":
        return (1, 1)
    if expected.cardinality_kind == "oneOrMore":
        return (1, 10000)
    if expected.cardinality_kind == "zeroOrMore":
        return (0, 10000)
    return (expected.minimum, expected.maximum)


def _references_for_resources(
    *groups: tuple[ResourceProofFact, ...],
) -> list[EvidenceReference]:
    return [resource.evidence_ref for group in groups for resource in group]


def _evaluate_cardinality(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: CardinalityProof,
) -> PolicyDecision:
    bound = _bound_role_resources(evidence, proof.role_ref)
    references = _references_for_resources(bound.resources)
    gate = _merge_gates(bound.gate, _resource_gate(bound.resources))
    requires_zone = (
        constraint.constraint_type == "supportedSingleton"
        or constraint.finding_kind in {"actualSpof", "riskAcceptance"}
    )
    if gate is not None:
        return PolicyDecision(gate, tuple(references))
    if requires_zone and any(
        resource.availability_zone == "unknown" for resource in bound.resources
    ):
        return PolicyDecision("unknown", tuple(references))

    minimum, maximum = _cardinality_bounds(proof)
    matches = len(bound.resources)
    if constraint.finding_kind in {"actualSpof", "riskAcceptance"}:
        actual_single_zone_spof = (
            matches == 1
            and len({resource.availability_zone for resource in bound.resources}) == 1
        )
        if not actual_single_zone_spof:
            return PolicyDecision(constraint.failure_verdict, tuple(references))
        if not profile.settings.continuity.zone_loss_continuity_required:
            return PolicyDecision("observation", tuple(references))
        return PolicyDecision("violation", tuple(references))

    verdict: FindingVerdict = (
        constraint.success_verdict
        if minimum <= matches <= maximum
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, tuple(references))


def _evaluate_zone_colocation(
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: ZoneColocationProof,
) -> PolicyDecision:
    subjects = _bound_role_resources(evidence, proof.subject_role_ref)
    anchors = _bound_role_resources(evidence, proof.anchor_role_ref)
    references = _references_for_resources(subjects.resources, anchors.resources)
    gate = _merge_gates(
        subjects.gate,
        anchors.gate,
        _resource_gate(subjects.resources),
        _resource_gate(anchors.resources),
    )
    all_resources = (*subjects.resources, *anchors.resources)
    if gate is not None:
        return PolicyDecision(gate, tuple(references))
    if any(resource.availability_zone == "unknown" for resource in all_resources):
        return PolicyDecision("unknown", tuple(references))
    anchor_zones = {resource.availability_zone for resource in anchors.resources}
    subject_zones = {resource.availability_zone for resource in subjects.resources}
    verdict: FindingVerdict = (
        constraint.success_verdict
        if len(anchor_zones) == 1 and subject_zones == anchor_zones
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, tuple(references))


def _evaluate_zone_distribution(
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: ZoneDistributionProof,
) -> PolicyDecision:
    bound = _bound_role_resources(evidence, proof.role_ref)
    references = _references_for_resources(bound.resources)
    gate = _merge_gates(bound.gate, _resource_gate(bound.resources))
    if gate is not None:
        return PolicyDecision(gate, tuple(references))
    if any(resource.availability_zone == "unknown" for resource in bound.resources):
        return PolicyDecision("unknown", tuple(references))
    distinct_zones = {resource.availability_zone for resource in bound.resources}
    verdict: FindingVerdict = (
        constraint.success_verdict
        if len(distinct_zones) >= proof.minimum_distinct_zones
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, tuple(references))


def _declared_relationship(
    profile: ResolvedManifestProfile,
    relationship_ref: str,
) -> DeclaredManifestRelationship:
    relationships = [
        relationship
        for relationship in profile.relationships
        if isinstance(relationship, DeclaredManifestRelationship)
        and normalized_id(relationship.relationship_id) == normalized_id(relationship_ref)
    ]
    if len(relationships) != 1:
        raise AthenaValidationError(
            "relationship proof must resolve to exactly one declared relationship"
        )
    return relationships[0]


def _relationship_role_bindings(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    proof: RelationshipPresenceProof,
) -> tuple[FindingVerdict | None, list[EvidenceReference]]:
    relationship = _declared_relationship(profile, proof.declared_relationship_ref)
    role_refs = {
        normalized_id(endpoint.role_ref): endpoint.role_ref
        for endpoint in (relationship.source, relationship.target)
        if isinstance(endpoint, RoleEndpoint)
    }
    gates: list[FindingVerdict | None] = []
    references: list[EvidenceReference] = []
    for role_ref in sorted(role_refs.values(), key=normalized_id):
        bound = _bound_role_resources(evidence, role_ref)
        gates.extend((bound.gate, _resource_gate(bound.resources)))
        references.extend(_references_for_resources(bound.resources))
    return (_merge_gates(*gates), references)


def _evaluate_relationship(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: RelationshipPresenceProof,
) -> PolicyDecision:
    facts = tuple(
        sorted(
            (
                fact
                for fact in evidence.relationships
                if normalized_id(fact.relationship_ref)
                == normalized_id(proof.declared_relationship_ref)
            ),
            key=lambda fact: fact.evidence_ref.canonical_json(),
        )
    )
    binding_gate, binding_references = _relationship_role_bindings(profile, evidence, proof)
    references = [fact.evidence_ref for fact in facts]
    references.extend(binding_references)
    if any(fact.state == "conflicting" for fact in facts):
        return PolicyDecision("conflicting", tuple(references))
    if binding_gate is not None:
        return PolicyDecision(binding_gate, tuple(references))
    if (
        len(facts) != 1
        or facts[0].state != "complete"
        or facts[0].proof_source == "inferred"
    ):
        return PolicyDecision("unknown", tuple(references))
    relationship_present = facts[0].presence == "present"
    if constraint.constraint_type == "dependencyProhibited":
        verdict: FindingVerdict = (
            constraint.failure_verdict
            if relationship_present
            else constraint.success_verdict
        )
    else:
        verdict = (
            constraint.success_verdict
            if relationship_present
            else constraint.failure_verdict
        )
    return PolicyDecision(verdict, tuple(references))


def _evaluate_control(
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: ControlHealthProof,
) -> PolicyDecision:
    facts = [
        fact
        for fact in evidence.controls
        if normalized_id(fact.control_ref) == normalized_id(proof.control_ref)
    ]
    references = tuple(fact.evidence_ref for fact in facts)
    if any(fact.state == "conflicting" for fact in facts):
        return PolicyDecision("conflicting", references)
    if len(facts) != 1 or facts[0].state != "complete":
        return PolicyDecision("unknown", references)
    verdict: FindingVerdict = (
        constraint.success_verdict
        if facts[0].health == proof.required_health
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, references)


def _evaluate_freshness(
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: EvidenceFreshnessProof,
    *,
    as_of: datetime,
) -> PolicyDecision:
    references = tuple(
        [
            *[fact.evidence_ref for fact in evidence.resources],
            *[fact.evidence_ref for fact in evidence.relationships],
            *[fact.evidence_ref for fact in evidence.controls],
            *[fact.evidence_ref for fact in evidence.objectives],
        ]
    )
    states = [
        *[fact.state for fact in evidence.resources],
        *[fact.state for fact in evidence.relationships],
        *[fact.state for fact in evidence.controls],
        *[fact.state for fact in evidence.objectives],
    ]
    binding_gates: list[FindingVerdict | None] = []
    for binding in evidence.role_bindings:
        bound = _bound_role_resources(evidence, binding.role_ref)
        binding_gates.append(bound.gate)
    binding_gate = _merge_gates(*binding_gates)
    if "conflicting" in states or binding_gate == "conflicting":
        return PolicyDecision("conflicting", references)
    inferred = any(
        resource.proof_source == "inferred" for resource in evidence.resources
    ) or any(
        relationship.proof_source == "inferred"
        for relationship in evidence.relationships
    )
    if (
        not states
        or any(state != "complete" for state in states)
        or inferred
        or binding_gate == "unknown"
    ):
        return PolicyDecision("unknown", references)
    age_seconds = (as_of - evidence.collected_at).total_seconds()
    verdict: FindingVerdict = (
        constraint.success_verdict
        if age_seconds <= proof.maximum_age_seconds
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, references)


def _comparison_matches(actual: float, comparison: str, threshold: float) -> bool:
    if comparison == "lt":
        return actual < threshold
    if comparison == "lte":
        return actual <= threshold
    if comparison == "gt":
        return actual > threshold
    if comparison == "gte":
        return actual >= threshold
    return actual == threshold


def _evaluate_objective(
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    proof: ObjectiveThresholdProof,
) -> PolicyDecision:
    facts = [
        fact
        for fact in evidence.objectives
        if normalized_id(fact.objective_ref) == normalized_id(proof.objective_ref)
    ]
    references = tuple(fact.evidence_ref for fact in facts)
    if any(fact.state == "conflicting" for fact in facts):
        return PolicyDecision("conflicting", references)
    if len(facts) != 1 or facts[0].state != "complete":
        return PolicyDecision("unknown", references)
    if not math.isfinite(facts[0].current_value) or not math.isfinite(proof.threshold):
        return PolicyDecision("unknown", references)
    verdict: FindingVerdict = (
        constraint.success_verdict
        if _comparison_matches(
            facts[0].current_value,
            proof.comparison,
            proof.threshold,
        )
        else constraint.failure_verdict
    )
    return PolicyDecision(verdict, references)


def _proof_role_refs(
    profile: ResolvedManifestProfile,
    constraint: ManifestConstraint,
) -> tuple[str, ...]:
    proof = constraint.proof_requirement
    if isinstance(proof, (CardinalityProof, ZoneDistributionProof)):
        return (proof.role_ref,)
    if isinstance(proof, ZoneColocationProof):
        return (proof.subject_role_ref, proof.anchor_role_ref)
    if isinstance(proof, RelationshipPresenceProof):
        relationship = _declared_relationship(profile, proof.declared_relationship_ref)
        return tuple(
            endpoint.role_ref
            for endpoint in (relationship.source, relationship.target)
            if isinstance(endpoint, RoleEndpoint)
        )
    return ()


def _required_resource_bindings(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
) -> frozenset[tuple[str, str]] | None:
    role_refs = _proof_role_refs(profile, constraint)
    if not role_refs:
        return None
    required: set[tuple[str, str]] = set()
    for role_ref in role_refs:
        bound = _bound_role_resources(evidence, role_ref)
        gate = _merge_gates(bound.gate, _resource_gate(bound.resources))
        if gate is not None or not bound.resources:
            return None
        required.update(
            (normalized_id(role_ref), normalized_id(resource.resource_id))
            for resource in bound.resources
        )
    return frozenset(required)


def _validated_exception_refs(
    profile: ResolvedManifestProfile,
    constraint: ManifestConstraint,
    *,
    as_of: datetime,
) -> set[str]:
    proof = constraint.proof_requirement
    proof_relationship = (
        _declared_relationship(profile, proof.declared_relationship_ref)
        if isinstance(proof, RelationshipPresenceProof)
        else None
    )
    result: set[str] = set()
    for relationship in profile.relationships:
        if not isinstance(relationship, ExceptionManifestRelationship):
            continue
        applies_to_clause = (
            relationship.applies_to_clause_ref is not None
            and normalized_id(relationship.applies_to_clause_ref)
            == normalized_id(constraint.constraint_id)
        )
        applies_to_relationship = (
            proof_relationship is not None
            and relationship.applies_to_relationship_ref is not None
            and normalized_id(relationship.applies_to_relationship_ref)
            == normalized_id(proof_relationship.relationship_id)
            and constraint.governance_scope.clause_path
            == proof_relationship.source_clause
        )
        if not applies_to_clause and not applies_to_relationship:
            continue
        if relationship.expires_at <= as_of:
            continue
        scope = relationship.governance_scope
        if (
            relationship.owner_ref != constraint.owner_ref
            or scope.manifest_id != profile.manifest_id
            or normalized_id(scope.profile_id) != normalized_id(profile.profile_id)
            or scope.clause_path != constraint.governance_scope.clause_path
            or scope.owner_ref != constraint.owner_ref
        ):
            raise AthenaValidationError(
                "exception overlay does not exactly match constraint governance"
            )
        result.add(normalized_id(relationship.risk_acceptance_ref))
    return result


def _matching_acceptance(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    *,
    as_of: datetime,
) -> ManifestRiskAcceptance | None:
    acceptance_refs = _validated_exception_refs(profile, constraint, as_of=as_of)
    if constraint.risk_acceptance_ref is not None:
        acceptance_refs.add(normalized_id(constraint.risk_acceptance_ref))
    if not acceptance_refs:
        return None

    required_bindings = _required_resource_bindings(profile, evidence, constraint)
    if required_bindings is None:
        return None
    acceptance_clause_id = (
        constraint.risk_acceptance_clause_ref
        if constraint.finding_kind == "riskAcceptance"
        and constraint.risk_acceptance_clause_ref is not None
        else constraint.constraint_id
    )
    matches: list[ManifestRiskAcceptance] = []
    for acceptance in profile.risk_acceptances:
        accepted_bindings = frozenset(
            (
                normalized_id(binding.role_ref),
                normalized_id(binding.resource_id),
            )
            for binding in acceptance.accepted_resource_bindings
        )
        if (
            normalized_id(acceptance.risk_acceptance_id) in acceptance_refs
            and acceptance.is_active(
                as_of=as_of,
                manifest_id=profile.manifest_id,
                profile_id=profile.profile_id,
                clause_path=f"/constraints/{acceptance_clause_id}",
                owner_ref=constraint.owner_ref,
            )
            and accepted_bindings == required_bindings
        ):
            matches.append(acceptance)
    if len(matches) > 1:
        raise AthenaValidationError("riskAcceptanceRef resolved ambiguously")
    return matches[0] if matches else None


def _ordered_bounded_references(
    references: tuple[EvidenceReference, ...],
) -> tuple[tuple[EvidenceReference, ...], bool]:
    by_canonical = {reference.canonical_json(): reference for reference in references}
    ordered = tuple(by_canonical[key] for key in sorted(by_canonical))
    return (ordered[:1000], len(ordered) > 1000)


def evaluate_constraint(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    constraint: ManifestConstraint,
    *,
    as_of: datetime,
) -> PolicyDecision:
    """Evaluate one resolved constraint without I/O or ambient time."""

    proof = constraint.proof_requirement
    if isinstance(proof, CardinalityProof):
        decision = _evaluate_cardinality(profile, evidence, constraint, proof)
    elif isinstance(proof, ZoneColocationProof):
        decision = _evaluate_zone_colocation(evidence, constraint, proof)
    elif isinstance(proof, ZoneDistributionProof):
        decision = _evaluate_zone_distribution(evidence, constraint, proof)
    elif isinstance(proof, RelationshipPresenceProof):
        decision = _evaluate_relationship(profile, evidence, constraint, proof)
    elif isinstance(proof, ControlHealthProof):
        decision = _evaluate_control(evidence, constraint, proof)
    elif isinstance(proof, EvidenceFreshnessProof):
        decision = _evaluate_freshness(
            evidence,
            constraint,
            proof,
            as_of=as_of,
        )
    elif isinstance(proof, ObjectiveThresholdProof):
        decision = _evaluate_objective(evidence, constraint, proof)
    else:
        raise AthenaValidationError(f"unsupported proof variant: {proof.proof_kind}")

    references, over_broad = _ordered_bounded_references(decision.evidence_refs)
    verdict = decision.verdict
    if over_broad and verdict != "conflicting":
        verdict = "unknown"

    acceptance: ManifestRiskAcceptance | None = None
    acceptance_semantics_are_eligible = (
        constraint.finding_kind in {"actualSpof", "riskAcceptance"}
        and constraint.constraint_type == "supportedSingleton"
    ) or (
        constraint.finding_kind == "architectureConstraint"
        and constraint.constraint_type
        in {
            "cardinality",
            "zoneColocation",
            "zoneDistribution",
            "dependencyRequired",
            "dependencyProhibited",
        }
    ) or (
        constraint.finding_kind == "relationshipConflict"
        and constraint.constraint_type
        in {"dependencyRequired", "dependencyProhibited"}
    )
    acceptance_eligible = (
        verdict == "violation"
        and normalized_id(constraint.constraint_id) != "db-singleton-supported"
        and acceptance_semantics_are_eligible
        and not isinstance(proof, EvidenceFreshnessProof)
    )
    if acceptance_eligible:
        acceptance = _matching_acceptance(
            profile,
            evidence,
            constraint,
            as_of=as_of,
        )
    if acceptance is not None:
        verdict = "acceptedResidualRisk"
    return PolicyDecision(
        verdict=verdict,
        evidence_refs=references,
        risk_acceptance_ref=(
            acceptance.risk_acceptance_id if acceptance is not None else None
        ),
    )


__all__ = ["PolicyDecision", "evaluate_constraint", "normalized_id"]
