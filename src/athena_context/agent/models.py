from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from athena_context.api.domain import (
    ActorKind,
    AuditAction,
    DraftState,
    VerifiedAuthentication,
)
from athena_context.contracts.manifest import (
    EvidenceReferenceContext,
    FindingVerdict,
    ManifestFinding,
    ResolvedManifestProfile,
)
from athena_context.contracts.models import (
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceReference,
)

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_RESOURCE_ID_PATTERN = (
    r"^/subscriptions/[A-Za-z0-9._-]{1,128}/"
    r"(?:[A-Za-z0-9._~()'!$&+,;=:@%-]+/?)+$"
)

type JsonSchema = dict[str, Any]
type FindingVerdictOrAbsent = FindingVerdict | Literal["notDeclared"]
type ProfileType = Literal[
    "production",
    "development",
    "training",
    "test",
    "disasterRecovery",
    "sandbox",
]
type RoleKind = Literal[
    "singletonDatabase",
    "databaseReplica",
    "worker",
    "webService",
    "loadBalancer",
    "integrationEndpoint",
    "storage",
    "network",
    "identity",
    "observability",
    "externalDependency",
]
type CardinalityKind = Literal[
    "exactlyOne",
    "oneOrMore",
    "zeroOrMore",
    "boundedRange",
]
type ConstraintKind = Literal[
    "cardinality",
    "zoneColocation",
    "zoneDistribution",
    "dependencyRequired",
    "dependencyProhibited",
    "supportedSingleton",
    "objectiveRequired",
    "evidenceFreshness",
    "controlRequired",
]
type FindingKind = Literal[
    "architectureConstraint",
    "technologyConstraint",
    "actualSpof",
    "controlHealth",
    "riskAcceptance",
    "objective",
    "relationshipConflict",
    "evidenceGap",
]
type ControlKind = Literal[
    "backup",
    "restoreTest",
    "manualFailoverRunbook",
    "monitoringAlert",
    "capacityReview",
    "accessReview",
    "changeApproval",
    "vendorSupport",
]
type ControlHealth = Literal[
    "effective",
    "degraded",
    "missing",
    "unknown",
    "expired",
    "notApplicable",
]
type RiskKind = Literal[
    "availability",
    "resilience",
    "operational",
    "security",
    "compliance",
]
type RiskRating = Literal["low", "medium", "high", "critical"]
type ApprovalStatus = Literal["approved", "expired", "revoked", "superseded"]
type ObjectiveKind = Literal[
    "availabilitySlo",
    "latencySlo",
    "throughputSlo",
    "rto",
    "rpo",
    "serviceHours",
    "capacityHeadroom",
    "recoveryPriority",
]
type RelationshipKind = Literal[
    "requires",
    "dependsOn",
    "calls",
    "storesDataIn",
    "replicatesTo",
    "failsOverTo",
    "sharesZoneWith",
    "isolatedFrom",
    "monitors",
    "protectedBy",
    "prohibited",
    "exception",
]
type ContextSection = Literal[
    "roles",
    "relationships",
    "constraints",
    "controls",
    "riskAcceptances",
    "objectives",
]
type EvidenceCitationKind = Literal[
    "evidenceItem",
    "evidenceGap",
    "publishedManifest",
    "historyEvent",
    "draftProposal",
]


class AgentModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_assignment=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )


class ToolCallContext(AgentModel):
    """Verified, transport-supplied identity and exact workload scope."""

    authentication: VerifiedAuthentication
    authorized_workload_ids: tuple[str, ...] = Field(min_length=1, max_length=100)

    @field_validator("authorized_workload_ids")
    @classmethod
    def validate_scope(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(value == "*" or len(value) > 128 for value in values):
            raise ValueError("wildcard or oversized workload scope is forbidden")
        normalized = [value.casefold() for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("workload scope must be unique")
        return values


class EvidenceRefCitation(AgentModel):
    """A bounded projection of an exact authoritative source reference."""

    ref_type: EvidenceCitationKind
    reference: str = Field(min_length=1, max_length=128)
    snapshot_id: str | None = Field(default=None, min_length=1, max_length=128)
    source_pointer: str | None = Field(default=None, min_length=1, max_length=256)


class Citation(AgentModel):
    manifest_id: str = Field(min_length=1, max_length=128)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(min_length=1, max_length=128)
    clause_id: str = Field(min_length=1, max_length=128)
    clause_path: str = Field(min_length=1, max_length=512, pattern=r"^/")
    evidence_refs: tuple[EvidenceRefCitation, ...] = Field(min_length=1, max_length=50)


class GroundedResponse(AgentModel):
    citations: tuple[Citation, ...] = Field(min_length=1, max_length=100)


class AuthoritativePolicyView(AgentModel):
    """A findings-port result whose complete provenance graph is checked locally."""

    evaluated_at: AwareDatetime
    profile: ResolvedManifestProfile
    evidence: EvidenceReferenceContext
    findings: tuple[ManifestFinding, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_grounding_graph(self) -> AuthoritativePolicyView:
        profile = self.profile
        evidence = self.evidence
        if not (evidence.collected_at <= self.evaluated_at < evidence.expires_at):
            raise ValueError("authoritative evidence is not current at evaluation time")
        if (
            evidence.manifest_id != profile.manifest_id
            or evidence.profile_id.casefold() != profile.profile_id.casefold()
            or evidence.resolved_profile_digest != profile.resolved_profile_digest
        ):
            raise ValueError("authoritative evidence does not match the resolved profile")

        constraints = {
            constraint.constraint_id.casefold(): constraint
            for constraint in profile.constraints
        }
        findings = {
            finding.clause_id.casefold(): finding for finding in self.findings
        }
        if len(findings) != len(self.findings) or findings.keys() != constraints.keys():
            raise ValueError("authoritative findings must exactly cover resolved constraints")

        allowed_refs = {
            reference.canonical_json()
            for reference in self._evidence_context_references(evidence)
        }
        for key, finding in findings.items():
            constraint = constraints[key]
            if (
                finding.manifest_id != profile.manifest_id
                or finding.manifest_version != profile.manifest_version
                or finding.profile_id.casefold() != profile.profile_id.casefold()
                or finding.resolved_profile_digest != profile.resolved_profile_digest
                or finding.finding_kind != constraint.finding_kind
                or finding.governance_scope != constraint.governance_scope
            ):
                raise ValueError("authoritative finding metadata does not match its clause")
            if any(
                reference.canonical_json() not in allowed_refs
                for reference in finding.evidence_refs
            ):
                raise ValueError("authoritative finding contains an unbound evidence reference")
        return self

    @staticmethod
    def _evidence_context_references(
        evidence: EvidenceReferenceContext,
    ) -> tuple[EvidenceReference, ...]:
        return tuple(
            item.evidence_ref
            for collection in (
                evidence.resources,
                evidence.relationships,
                evidence.controls,
                evidence.objectives,
            )
            for item in collection
        )


class ListWorkloadsInput(AgentModel):
    profile_id: str = Field(default="production", pattern=_ID_PATTERN)
    offset: int = Field(default=0, ge=0, le=100)
    limit: int = Field(default=20, ge=1, le=50)


class ResolveResourceInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    resource_id: str = Field(min_length=1, max_length=2048, pattern=_RESOURCE_ID_PATTERN)


class GetContextInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    sections: tuple[ContextSection, ...] = Field(
        default=(
            "roles",
            "relationships",
            "constraints",
            "controls",
            "riskAcceptances",
            "objectives",
        ),
        min_length=1,
        max_length=6,
    )
    limit_per_section: int = Field(default=25, ge=1, le=50)

    @field_validator("sections")
    @classmethod
    def validate_sections(
        cls,
        sections: tuple[ContextSection, ...],
    ) -> tuple[ContextSection, ...]:
        if len(sections) != len(set(sections)):
            raise ValueError("context sections must be unique")
        return sections

    @field_validator("sections", mode="before")
    @classmethod
    def accept_json_sections(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class CompareEnvironmentsInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    profile_ids: tuple[str, ...] = Field(min_length=2, max_length=3)
    max_clauses: int = Field(default=25, ge=1, le=25)

    @field_validator("profile_ids")
    @classmethod
    def validate_profiles(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("profile id is invalid")
        normalized = [value.casefold() for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("comparison profiles must be unique")
        return values

    @field_validator("profile_ids", mode="before")
    @classmethod
    def accept_json_profiles(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ExplainFindingInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    clause_id: str = Field(pattern=_ID_PATTERN)


class ReadHistoryInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    before_sequence: int | None = Field(default=None, ge=1)
    limit: int = Field(default=20, ge=1, le=50)


class PatchOperation(AgentModel):
    op: Literal["replace"]
    path: str = Field(min_length=1, max_length=512, pattern=r"^/")
    value: str = Field(min_length=1, max_length=2000)


class ProposeManifestPatchInput(AgentModel):
    workload_id: str = Field(pattern=_ID_PATTERN)
    base_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    proposed_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    reason: str = Field(min_length=3, max_length=500)
    operations: tuple[PatchOperation, ...] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def validate_operations(self) -> ProposeManifestPatchInput:
        paths = [operation.path for operation in self.operations]
        if len(paths) != len(set(paths)):
            raise ValueError("patch paths must be unique")
        return self

    @field_validator("operations", mode="before")
    @classmethod
    def accept_json_operations(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class WorkloadSummary(AgentModel):
    workload_id: str
    display_name: str = Field(min_length=1, max_length=200)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_ids: tuple[str, ...] = Field(min_length=1, max_length=25)


class ListWorkloadsOutput(GroundedResponse):
    workloads: tuple[WorkloadSummary, ...] = Field(min_length=1, max_length=50)
    total_scoped: int = Field(ge=1, le=100)
    next_offset: int | None = Field(default=None, ge=1, le=100)


class ResolvedResourceOutput(GroundedResponse):
    workload_id: str
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str
    resource_id: str = Field(max_length=2048)
    role_id: str
    role_kind: RoleKind
    binding_state: Literal["complete"]
    proof_source: Literal["observed"]
    selector_result_digest: str = Field(pattern=_DIGEST_PATTERN)


class RoleSummary(AgentModel):
    role_id: str
    kind: RoleKind
    cardinality: CardinalityKind
    owner_ref: str
    clause_path: str


class RelationshipSummary(AgentModel):
    relationship_id: str
    relationship_class: Literal["declared", "exception"]
    kind: RelationshipKind
    source_ref: str | None = None
    target_ref: str
    owner_ref: str
    clause_path: str


class ConstraintSummary(AgentModel):
    clause_id: str
    constraint_type: ConstraintKind
    finding_kind: FindingKind
    verdict: FindingVerdict
    owner_ref: str
    clause_path: str


class ControlSummary(AgentModel):
    control_id: str
    control_kind: ControlKind
    health: ControlHealth
    owner_ref: str
    clause_path: str


class RiskAcceptanceSummary(AgentModel):
    risk_acceptance_id: str
    risk_kind: RiskKind
    risk_rating: RiskRating
    status: ApprovalStatus
    owner_ref: str
    clause_path: str


class ObjectiveSummary(AgentModel):
    objective_id: str
    objective_type: ObjectiveKind
    target: float
    owner_ref: str
    clause_path: str


class ContextOutput(GroundedResponse):
    workload_id: str
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_id: str
    profile_type: ProfileType
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    zone_loss_continuity_required: bool
    roles: tuple[RoleSummary, ...] = Field(default=(), max_length=50)
    relationships: tuple[RelationshipSummary, ...] = Field(default=(), max_length=50)
    constraints: tuple[ConstraintSummary, ...] = Field(default=(), max_length=50)
    controls: tuple[ControlSummary, ...] = Field(default=(), max_length=50)
    risk_acceptances: tuple[RiskAcceptanceSummary, ...] = Field(default=(), max_length=50)
    objectives: tuple[ObjectiveSummary, ...] = Field(default=(), max_length=50)
    truncated_sections: tuple[ContextSection, ...] = Field(default=(), max_length=6)


class ProfileFindingVerdict(AgentModel):
    clause_id: str
    verdict: FindingVerdict
    clause_path: str


class EnvironmentSummary(AgentModel):
    profile_id: str
    profile_type: ProfileType
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    zone_loss_continuity_required: bool
    role_count: int = Field(ge=0, le=200)
    findings: tuple[ProfileFindingVerdict, ...] = Field(max_length=50)


class ProfileVerdict(AgentModel):
    profile_id: str
    verdict: FindingVerdictOrAbsent


class ClauseDifference(AgentModel):
    clause_id: str
    clause_paths: tuple[str, ...] = Field(min_length=1, max_length=3)
    verdicts: tuple[ProfileVerdict, ...] = Field(min_length=2, max_length=3)


class EnvironmentComparisonOutput(GroundedResponse):
    workload_id: str
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    environments: tuple[EnvironmentSummary, ...] = Field(min_length=2, max_length=3)
    differences: tuple[ClauseDifference, ...] = Field(max_length=50)
    truncated: bool


class FindingExplanationOutput(GroundedResponse):
    workload_id: str
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str
    clause_id: str
    finding_kind: FindingKind
    verdict: FindingVerdict
    deterministic_explanation: str = Field(min_length=1, max_length=1000)
    requires_human_review: bool


class HistoryEventSummary(AgentModel):
    event_id: str
    sequence: int = Field(ge=1)
    action: AuditAction
    actor_kind: ActorKind
    occurred_at: AwareDatetime
    manifest_version: str | None = Field(default=None, pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)


class HistoryOutput(GroundedResponse):
    workload_id: str
    profile_id: str
    events: tuple[HistoryEventSummary, ...] = Field(min_length=1, max_length=50)
    next_before_sequence: int | None = Field(default=None, ge=1)


class DraftProposalOutput(GroundedResponse):
    workload_id: str
    base_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    proposed_manifest_version: str = Field(pattern=_VERSION_PATTERN)
    draft_id: str
    revision: int = Field(ge=1)
    state: Literal[DraftState.DRAFT] = DraftState.DRAFT
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    changed_paths: tuple[str, ...] = Field(min_length=1, max_length=10)
    requires_human_review: Literal[True] = True
    approval_allowed: Literal[False] = False
    publication_allowed: Literal[False] = False
    remediation_allowed: Literal[False] = False


class ToolAnnotations(AgentModel):
    read_only_hint: bool = Field(alias="readOnlyHint")
    destructive_hint: Literal[False] = Field(default=False, alias="destructiveHint")
    idempotent_hint: bool = Field(alias="idempotentHint")
    open_world_hint: Literal[False] = Field(default=False, alias="openWorldHint")


class ToolDefinition(AgentModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=500)
    input_schema: JsonSchema = Field(alias="inputSchema")
    output_schema: JsonSchema = Field(alias="outputSchema")
    annotations: ToolAnnotations


def exact_evidence_reference(
    reference: EvidenceReference,
) -> EvidenceRefCitation:
    if isinstance(reference, EvidenceItemRef):
        return EvidenceRefCitation(
            ref_type="evidenceItem",
            reference=reference.item_digest,
            snapshot_id=reference.snapshot_id,
            source_pointer=reference.source_response_pointer,
        )
    if isinstance(reference, EvidenceGapRef):
        return EvidenceRefCitation(
            ref_type="evidenceGap",
            reference=reference.gap_record_digest,
            snapshot_id=reference.snapshot_id,
        )
    raise TypeError("unsupported authoritative evidence reference")


def ensure_aware_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


__all__ = [
    "AgentModel",
    "AuthoritativePolicyView",
    "Citation",
    "ClauseDifference",
    "CompareEnvironmentsInput",
    "ConstraintSummary",
    "ContextOutput",
    "ControlSummary",
    "DraftProposalOutput",
    "EnvironmentComparisonOutput",
    "EnvironmentSummary",
    "EvidenceRefCitation",
    "ExplainFindingInput",
    "FindingExplanationOutput",
    "GetContextInput",
    "GroundedResponse",
    "HistoryEventSummary",
    "HistoryOutput",
    "ListWorkloadsInput",
    "ListWorkloadsOutput",
    "ObjectiveSummary",
    "PatchOperation",
    "ProfileFindingVerdict",
    "ProfileVerdict",
    "ProposeManifestPatchInput",
    "ReadHistoryInput",
    "RelationshipSummary",
    "ResolveResourceInput",
    "ResolvedResourceOutput",
    "RiskAcceptanceSummary",
    "RoleSummary",
    "ToolAnnotations",
    "ToolCallContext",
    "ToolDefinition",
    "WorkloadSummary",
    "exact_evidence_reference",
]
