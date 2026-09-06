"""Closed, unpublished proposal contracts for WC-022.

These contracts deliberately model a pre-publication proposal rather than a
runtime manifest. They cannot be used as a substitute for the canonical
WC-001 workload-manifest contract.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, TypeVar

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    model_validator,
)

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    normalize_nfc_text,
)

WC022_PROPOSAL_CONTRACT_VERSION = "athena.wc022.governedProposal.v1"
WC022_RESEARCH_DRAFT_LOCATION = "docs/research/drafts/epic-on-azure.draft.yaml"
WC022_SOURCE_DOSSIER = "docs/research/epic-on-azure-source-dossier.md"
WC022_REVIEWED_DRAFT_DIGEST = (
    "sha256:82bcda3bfaa9f2a1045c37c1f3c93703c3c83742673bc703d5be3c439bafd444"
)
WC022_REVIEWED_DOSSIER_DIGEST = (
    "sha256:de465922b47ca93b2790657392cd74b104010b600d4357fc33d9b180190bc4a0"
)
WC022_REVIEWED_PROPOSAL_DIGEST = (
    "sha256:3ae604242a77d0174f41e584d95d102ef008ffc0d5efbde287b665060e3c439a"
)
_FrozenItem = TypeVar("_FrozenItem")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


class Wc022ContractError(ValueError):
    """Raised when an unpublished WC-022 proposal violates its governance boundary."""


def _frozen_sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError("proposal collections must be JSON arrays")
    return tuple(value)


def _safe_identifier(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("proposal identifiers must be strings")
    try:
        normalized = normalize_nfc_text(value)
    except AthenaValidationError as exc:
        raise ValueError("proposal identifiers must be valid NFC text") from exc
    if normalized != value:
        raise ValueError("proposal identifiers must be NFC-normalized")
    if _SAFE_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("proposal identifiers contain unsupported characters")
    return value


type FrozenList[_FrozenItem] = Annotated[
    tuple[_FrozenItem, ...],
    BeforeValidator(_frozen_sequence),
]
type SafeIdentifier = Annotated[
    str,
    BeforeValidator(_safe_identifier),
    Field(pattern=_SAFE_IDENTIFIER_RE.pattern),
]


def _normalized_identifier(value: str) -> str:
    return normalize_nfc_text(value).casefold()


def _require_unique_identifiers(values: tuple[str, ...], label: str) -> None:
    if len({_normalized_identifier(value) for value in values}) != len(values):
        raise Wc022ContractError(f"{label} must be unique after NFC normalization")


class Wc022BaseModel(BaseModel):
    """Strict base for proposal-only data that has no runtime authority."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_json(self) -> str:
        return canonicalize_json(
            self.model_dump(mode="json", by_alias=True, exclude_none=True)
        )

    @model_validator(mode="after")
    def validate_source_ref_uniqueness(self) -> Wc022BaseModel:
        source_refs = getattr(self, "source_refs", None)
        if source_refs is not None:
            _require_unique_identifiers(
                source_refs,
                f"{self.__class__.__name__} source references",
            )
        return self


class UnknownValue(Wc022BaseModel):
    """An explicitly retained unsupported or customer-specific value gap."""

    state: Literal["unknown"] = "unknown"
    subject: str = Field(..., min_length=1, max_length=160)
    rationale: str = Field(..., min_length=1, max_length=1000)
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class HumanDecision(Wc022BaseModel):
    """A value that only an authorized human owner may provide."""

    state: Literal["humanDecisionRequired"] = "humanDecisionRequired"
    subject: str = Field(..., min_length=1, max_length=160)
    rationale: str = Field(..., min_length=1, max_length=1000)
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class ProposalWorkloadIdentity(Wc022BaseModel):
    workload_id: SafeIdentifier = Field(..., alias="workloadId", min_length=1, max_length=128)
    display_name: str = Field(..., alias="displayName", min_length=1, max_length=200)
    workload_family: SafeIdentifier = Field(
        ..., alias="workloadFamily", min_length=1, max_length=128
    )
    description: str = Field(..., min_length=1, max_length=2000)
    classification: Literal["publicSafeSynthetic"] = Field(
        "publicSafeSynthetic", alias="classification"
    )
    business_criticality: UnknownValue = Field(..., alias="businessCriticality")


class EnvironmentProposal(Wc022BaseModel):
    profile_id: SafeIdentifier = Field(..., alias="profileId", min_length=1, max_length=128)
    profile_type: Literal[
        "production", "development", "training", "test", "disasterRecovery"
    ] = Field(..., alias="profileType")
    declaration_required: Literal[True] = Field(True, alias="declarationRequired")
    objective: HumanDecision
    criticality: UnknownValue
    recovery_intent: HumanDecision = Field(..., alias="recoveryIntent")
    dependency_scope: HumanDecision = Field(..., alias="dependencyScope")
    data_classification: UnknownValue = Field(..., alias="dataClassification")
    monitoring_semantics: FrozenList[HumanDecision] = Field(
        ..., alias="monitoringSemantics", min_length=1, max_length=8
    )
    ownership: FrozenList[HumanDecision] = Field(..., min_length=1, max_length=4)
    unknowns: FrozenList[UnknownValue] = Field(default_factory=tuple, max_length=16)
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class ObjectiveProposal(Wc022BaseModel):
    objective_id: Literal[
        "reliability",
        "security",
        "operationalExcellence",
        "performanceEfficiency",
        "costOptimization",
    ] = Field(..., alias="objectiveId")
    declared_intent: str = Field(..., alias="declaredIntent", min_length=1, max_length=1000)
    target: HumanDecision


class RoleProposal(Wc022BaseModel):
    role_id: SafeIdentifier = Field(..., alias="roleId", min_length=1, max_length=128)
    purpose: str = Field(..., min_length=1, max_length=1000)
    candidate_status: Literal["humanApprovalRequired"] = Field(
        "humanApprovalRequired", alias="candidateStatus"
    )
    runtime_role_kind: HumanDecision = Field(..., alias="runtimeRoleKind")
    discovery_hint: HumanDecision | None = Field(default=None, alias="discoveryHint")
    source_decisions: FrozenList[HumanDecision] = Field(
        ..., alias="sourceDecisions", min_length=1, max_length=16
    )
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class DependencyCategoryProposal(Wc022BaseModel):
    dependency_id: SafeIdentifier = Field(
        ..., alias="dependencyId", min_length=1, max_length=128
    )
    status: Literal["candidateCategory"] = "candidateCategory"
    semantics: str = Field(..., min_length=1, max_length=1000)
    human_decisions: FrozenList[HumanDecision] = Field(
        ..., alias="humanDecisions", min_length=1, max_length=8
    )
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class RelationshipHypothesisProposal(Wc022BaseModel):
    relationship_id: SafeIdentifier = Field(
        ..., alias="relationshipId", min_length=1, max_length=128
    )
    source_role_ref: SafeIdentifier = Field(
        ..., alias="sourceRoleRef", min_length=1, max_length=128
    )
    target_role_ref: SafeIdentifier = Field(
        ..., alias="targetRoleRef", min_length=1, max_length=128
    )
    relationship_category: SafeIdentifier = Field(
        ..., alias="relationshipCategory", min_length=1, max_length=128
    )
    intent: str = Field(..., min_length=1, max_length=1000)
    candidate_status: Literal["humanApprovalRequired"] = Field(
        "humanApprovalRequired", alias="candidateStatus"
    )
    environment_scope: HumanDecision = Field(..., alias="environmentScope")
    semantics: UnknownValue
    confidence: Literal["hypothesis-unvalidated"] = "hypothesis-unvalidated"
    human_validation_required: Literal[True] = Field(True, alias="humanValidationRequired")
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class OwnershipProposal(Wc022BaseModel):
    owner_role: Literal[
        "workloadOwner",
        "applicationOwner",
        "platformOwner",
        "monitoringOwner",
        "recoveryOwner",
        "changeApprover",
    ] = Field(..., alias="ownerRole")
    assignment: HumanDecision


class RecoveryIntentProposal(Wc022BaseModel):
    concepts: FrozenList[str] = Field(..., min_length=1, max_length=16)
    target_values: FrozenList[HumanDecision] = Field(
        ..., alias="targetValues", min_length=1, max_length=8
    )


class MonitoringSemanticsProposal(Wc022BaseModel):
    signal_intent_only: Literal[True] = Field(True, alias="signalIntentOnly")
    platform_evidence_categories: FrozenList[str] = Field(
        ..., alias="platformEvidenceCategories", min_length=1, max_length=16
    )
    workload_evidence_categories: FrozenList[HumanDecision] = Field(
        ..., alias="workloadEvidenceCategories", min_length=1, max_length=16
    )
    prohibited_values: FrozenList[str] = Field(
        ..., alias="prohibitedValues", min_length=1, max_length=16
    )


class EvidenceRequirementsProposal(Wc022BaseModel):
    declared_and_observed_separate: Literal[True] = Field(
        True, alias="declaredAndObservedSeparate"
    )
    evidence_plane: Literal["privateAzureMcpReadOnly"] = Field(
        "privateAzureMcpReadOnly", alias="evidencePlane"
    )
    required_categories: FrozenList[str] = Field(
        ..., alias="requiredCategories", min_length=1, max_length=16
    )
    freshness_and_scope: HumanDecision = Field(..., alias="freshnessAndScope")
    detailed_provenance: HumanDecision = Field(..., alias="detailedProvenance")


class PlacementConstraintProposal(Wc022BaseModel):
    constraint_id: SafeIdentifier = Field(
        ..., alias="constraintId", min_length=1, max_length=128
    )
    human_decisions: FrozenList[HumanDecision] = Field(
        ..., alias="humanDecisions", min_length=1, max_length=16
    )
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class ExceptionCandidate(Wc022BaseModel):
    exception_id: SafeIdentifier = Field(
        ..., alias="exceptionId", min_length=1, max_length=128
    )
    candidate_status: Literal["humanApprovalRequired"] = Field(
        "humanApprovalRequired", alias="candidateStatus"
    )
    required_declarations: FrozenList[str] = Field(
        ..., alias="requiredDeclarations", min_length=1, max_length=16
    )
    human_review: HumanDecision = Field(..., alias="humanReview")
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=8
    )


class ProposalProvenance(Wc022BaseModel):
    source_artifact: str = Field(..., alias="sourceArtifact", min_length=1, max_length=256)
    source_dossier: str = Field(..., alias="sourceDossier", min_length=1, max_length=256)
    source_payload_digest: str = Field(
        ..., alias="sourcePayloadDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    source_dossier_digest: str = Field(
        ..., alias="sourceDossierDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    source_refs: FrozenList[SafeIdentifier] = Field(
        ..., alias="sourceRefs", min_length=1, max_length=16
    )
    conversion_basis: Literal["publicSafeConceptsOnly"] = Field(
        "publicSafeConceptsOnly", alias="conversionBasis"
    )


class ProposalGovernance(Wc022BaseModel):
    publication_state: Literal["unpublished"] = Field("unpublished", alias="publicationState")
    runtime_use: Literal["prohibited"] = Field("prohibited", alias="runtimeUse")
    human_approval_required: Literal[True] = Field(True, alias="humanApprovalRequired")
    authority_boundary: Literal["contextApiHumanPublicationOnly"] = Field(
        "contextApiHumanPublicationOnly", alias="authorityBoundary"
    )


class GovernedWorkloadContextProposal(Wc022BaseModel):
    """The deterministic WC-022 output, intentionally not a runtime manifest."""

    contract_version: Literal["athena.wc022.governedProposal.v1"] = Field(
        "athena.wc022.governedProposal.v1", alias="contractVersion"
    )
    proposal_kind: Literal["governedWorkloadContextProposal"] = Field(
        "governedWorkloadContextProposal", alias="proposalKind"
    )
    proposal_id: SafeIdentifier = Field(..., alias="proposalId", min_length=1, max_length=128)
    governance: ProposalGovernance
    workload: ProposalWorkloadIdentity
    environments: FrozenList[EnvironmentProposal] = Field(
        ..., min_length=1, max_length=8
    )
    objectives: FrozenList[ObjectiveProposal] = Field(..., min_length=1, max_length=8)
    roles: FrozenList[RoleProposal] = Field(..., min_length=1, max_length=32)
    dependencies: FrozenList[DependencyCategoryProposal] = Field(
        ..., min_length=1, max_length=32
    )
    relationship_hypotheses: FrozenList[RelationshipHypothesisProposal] = Field(
        ..., alias="relationshipHypotheses", min_length=1, max_length=64
    )
    ownership: FrozenList[OwnershipProposal] = Field(..., min_length=1, max_length=16)
    recovery_intent: RecoveryIntentProposal = Field(..., alias="recoveryIntent")
    monitoring_semantics: MonitoringSemanticsProposal = Field(
        ..., alias="monitoringSemantics"
    )
    evidence_requirements: EvidenceRequirementsProposal = Field(
        ..., alias="evidenceRequirements"
    )
    placement_constraints: FrozenList[PlacementConstraintProposal] = Field(
        ..., alias="placementConstraints", min_length=1, max_length=16
    )
    exception_candidates: FrozenList[ExceptionCandidate] = Field(
        ..., alias="exceptionCandidates", max_length=16
    )
    provenance: ProposalProvenance
    proposal_digest: str = Field(
        ..., alias="proposalDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )

    def digest_preimage(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("proposalDigest", None)
        return payload

    @model_validator(mode="after")
    def validate_governance_and_references(self) -> GovernedWorkloadContextProposal:
        if self.governance.publication_state != "unpublished":
            raise Wc022ContractError("WC-022 proposals must remain unpublished")
        if self.governance.runtime_use != "prohibited":
            raise Wc022ContractError("WC-022 proposals are not runtime inputs")
        expected_digest = compute_artifact_digest(self.digest_preimage())
        if self.proposal_digest != expected_digest:
            raise Wc022ContractError(
                "proposalDigest does not match the canonical proposal "
                f"(expected {expected_digest}, received {self.proposal_digest})"
            )
        if self.provenance.source_artifact != WC022_RESEARCH_DRAFT_LOCATION:
            raise Wc022ContractError("proposal provenance sourceArtifact is not approved")
        if self.provenance.source_dossier != WC022_SOURCE_DOSSIER:
            raise Wc022ContractError("proposal provenance sourceDossier is not approved")
        if self.provenance.source_payload_digest != WC022_REVIEWED_DRAFT_DIGEST:
            raise Wc022ContractError(
                "proposal provenance sourcePayloadDigest is not the sealed reviewed draft"
            )
        if self.provenance.source_dossier_digest != WC022_REVIEWED_DOSSIER_DIGEST:
            raise Wc022ContractError(
                "proposal provenance sourceDossierDigest is not the sealed reviewed dossier"
            )

        source_refs = set(self.provenance.source_refs)
        decision_values = (
            self.workload.business_criticality,
            *(
                value
                for environment in self.environments
                for value in (
                    environment.objective,
                    environment.criticality,
                    environment.recovery_intent,
                    environment.dependency_scope,
                    environment.data_classification,
                    *environment.monitoring_semantics,
                    *environment.ownership,
                    *environment.unknowns,
                )
            ),
            *(objective.target for objective in self.objectives),
            *(
                value
                for role in self.roles
                for value in (
                    role.runtime_role_kind,
                    *role.source_decisions,
                    *((role.discovery_hint,) if role.discovery_hint is not None else ()),
                )
            ),
            *(
                decision
                for dependency in self.dependencies
                for decision in dependency.human_decisions
            ),
            *(
                value
                for relationship in self.relationship_hypotheses
                for value in (relationship.environment_scope, relationship.semantics)
            ),
            *(owner.assignment for owner in self.ownership),
            *self.recovery_intent.target_values,
            *self.monitoring_semantics.workload_evidence_categories,
            self.evidence_requirements.freshness_and_scope,
            self.evidence_requirements.detailed_provenance,
            *(
                decision
                for constraint in self.placement_constraints
                for decision in constraint.human_decisions
            ),
            *(candidate.human_review for candidate in self.exception_candidates),
        )
        if any(
            source_ref not in source_refs
            for value in decision_values
            for source_ref in value.source_refs
        ):
            raise Wc022ContractError("nested decision provenance must resolve")
        if any(
            ref not in source_refs
            for environment in self.environments
            for ref in environment.source_refs
        ):
            raise Wc022ContractError("environment provenance must resolve")
        if any(
            ref not in source_refs
            for role in self.roles
            for ref in role.source_refs
        ):
            raise Wc022ContractError("role provenance must resolve")
        if any(
            ref not in source_refs
            for dependency in self.dependencies
            for ref in dependency.source_refs
        ):
            raise Wc022ContractError("dependency provenance must resolve")
        if any(
            ref not in source_refs
            for relationship in self.relationship_hypotheses
            for ref in relationship.source_refs
        ):
            raise Wc022ContractError("relationship provenance must resolve")
        if any(
            ref not in source_refs
            for exception in self.exception_candidates
            for ref in exception.source_refs
        ):
            raise Wc022ContractError("exception provenance must resolve")
        if any(
            ref not in source_refs
            for constraint in self.placement_constraints
            for ref in constraint.source_refs
        ):
            raise Wc022ContractError("placement constraint provenance must resolve")

        _require_unique_identifiers(
            tuple(environment.profile_id for environment in self.environments),
            "environment profile identifiers",
        )
        _require_unique_identifiers(
            tuple(objective.objective_id for objective in self.objectives),
            "objective identifiers",
        )
        _require_unique_identifiers(
            tuple(role.role_id for role in self.roles),
            "role identifiers",
        )
        _require_unique_identifiers(
            tuple(dependency.dependency_id for dependency in self.dependencies),
            "dependency identifiers",
        )
        _require_unique_identifiers(
            tuple(relationship.relationship_id for relationship in self.relationship_hypotheses),
            "relationship identifiers",
        )
        _require_unique_identifiers(
            tuple(owner.owner_role for owner in self.ownership),
            "ownership roles",
        )
        _require_unique_identifiers(
            tuple(constraint.constraint_id for constraint in self.placement_constraints),
            "placement constraint identifiers",
        )
        candidate_exception_ids = tuple(
            exception.exception_id for exception in self.exception_candidates
        )
        _require_unique_identifiers(
            candidate_exception_ids,
            "exception identifiers",
        )
        role_ids = {_normalized_identifier(role.role_id) for role in self.roles}
        for relationship in self.relationship_hypotheses:
            if (
                _normalized_identifier(relationship.source_role_ref) not in role_ids
                or _normalized_identifier(relationship.target_role_ref) not in role_ids
            ):
                raise Wc022ContractError("relationship role references must resolve")
        if self.proposal_digest != WC022_REVIEWED_PROPOSAL_DIGEST:
            raise Wc022ContractError(
                "proposalDigest is not the reviewed canonical proposal output"
            )
        return self


__all__ = [
    "DependencyCategoryProposal",
    "EnvironmentProposal",
    "EvidenceRequirementsProposal",
    "ExceptionCandidate",
    "GovernedWorkloadContextProposal",
    "HumanDecision",
    "MonitoringSemanticsProposal",
    "ObjectiveProposal",
    "OwnershipProposal",
    "PlacementConstraintProposal",
    "ProposalGovernance",
    "ProposalProvenance",
    "ProposalWorkloadIdentity",
    "RecoveryIntentProposal",
    "RelationshipHypothesisProposal",
    "RoleProposal",
    "UnknownValue",
    "WC022_PROPOSAL_CONTRACT_VERSION",
    "WC022_RESEARCH_DRAFT_LOCATION",
    "WC022_REVIEWED_DOSSIER_DIGEST",
    "WC022_REVIEWED_DRAFT_DIGEST",
    "WC022_REVIEWED_PROPOSAL_DIGEST",
    "WC022_SOURCE_DOSSIER",
    "Wc022ContractError",
]
