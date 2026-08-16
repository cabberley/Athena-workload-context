from __future__ import annotations

from collections.abc import Callable, Iterable
from copy import deepcopy
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaMode

from athena_context.contracts.common import (
    AthenaValidationError,
    compute_artifact_digest,
    normalize_nfc_text,
)
from athena_context.contracts.models import (
    AthenaBaseModel as BaseAthenaModel,
)
from athena_context.contracts.models import (
    CollectorIdentityEvidence,
    CompatibilityMetadata,
    EvidenceEnvelopeResolver,
    EvidenceGapRecord,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceRecord,
    EvidenceReference,
    EvidenceScope,
    EvidenceSnapshot,
    ObservedRelationshipEvidenceRecord,
    ResourceEvidenceRecord,
    SnapshotPublicationResolver,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    UtcDateTime,
)


class AthenaBaseModel(BaseAthenaModel):
    def _semantic_projection(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=False)

    @classmethod
    def model_json_schema(
        cls,
        by_alias: bool = True,
        ref_template: str = "#/$defs/{model}",
        schema_generator: type[GenerateJsonSchema] = GenerateJsonSchema,
        mode: JsonSchemaMode = "validation",
        *,
        union_format: Literal["any_of", "primitive_type_array"] = "any_of",
    ) -> dict[str, Any]:
        schema = super().model_json_schema(
            by_alias=by_alias,
            ref_template=ref_template,
            schema_generator=schema_generator,
            mode=mode,
            union_format=union_format,
        )
        schema["$id"] = f"https://schemas.athena.invalid/wc-001/{cls.__name__}/1.0.0"
        schema["x-athena-schemaVersion"] = "1.0.0"
        schema["x-athena-semanticContractVersion"] = "1.0.0"
        schema["x-athena-policyContractVersion"] = "1.0.0"
        schema["x-athena-requiresCapabilities"] = []

        def classify(value: Any) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    for property_name, property_schema in properties.items():
                        if isinstance(property_schema, dict):
                            property_schema.setdefault("x-athena-semanticClass", "semantic")
                            if property_name in {"displayName", "schemaVersion"}:
                                property_schema["x-athena-semanticClass"] = "presentation"
                for child in value.values():
                    classify(child)
            elif isinstance(value, list):
                for child in value:
                    classify(child)

        classify(schema)
        return schema


type Environment = Literal[
    "production",
    "development",
    "training",
    "test",
    "disasterRecovery",
    "sandbox",
]
type AzureCloudName = Literal[
    "azureCloud",
    "azureChinaCloud",
    "azureUSGovernment",
    "azureGermanCloud",
]
type ApprovalStatus = Literal["approved", "expired", "revoked", "superseded"]
type OverrideReason = Literal[
    "continuityRelaxation",
    "cardinalityRelaxation",
    "zoneRequirementRelaxation",
    "controlRequirementRelaxation",
    "constraintRequirementRelaxation",
    "disableInheritedItem",
]
type FindingVerdict = Literal[
    "pass",
    "violation",
    "expectedConstraint",
    "acceptedResidualRisk",
    "observation",
    "unknown",
    "conflicting",
]
type ManifestFindingKind = Literal[
    "architectureConstraint",
    "technologyConstraint",
    "actualSpof",
    "controlHealth",
    "riskAcceptance",
    "objective",
    "relationshipConflict",
    "evidenceGap",
]
type FailureVerdict = Literal["violation", "unknown", "conflicting"]
type EvidenceState = Literal["complete", "missing", "gap", "stale", "conflicting"]
type ProofSource = Literal["observed", "inferred"]
type EvidenceContextVerifier = Callable[["EvidenceReferenceContext", datetime], None]
type RoleBindingValidator = Callable[["RoleBindingProof", EvidenceSnapshot], bool]

_PROTECTED_REFS = frozenset(
    {
        "db-singleton-supported",
        "db-zone-loss-spof",
        "db-zone-loss-acceptance",
        "worker-db-zone-colocation",
        "web-zone-distribution",
    }
)
_SUPPORTED_READER_VERSION = (1, 0, 0)


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return (int(major), int(minor), int(patch))


def _require_supported_compatibility(
    compatibility: CompatibilityMetadata,
    *,
    artifact_kind: Literal["workloadManifest", "resolvedProfile"],
) -> None:
    if compatibility.artifact_kind != artifact_kind:
        raise AthenaValidationError(f"compatibility artifactKind must be {artifact_kind}")
    if (
        _version_tuple(compatibility.schema_version)[0] != 1
        or compatibility.semantic_contract_version != "1.0.0"
        or compatibility.policy_contract_version != "1.0.0"
        or _version_tuple(compatibility.minimum_reader_version) > _SUPPORTED_READER_VERSION
        or compatibility.requires_capabilities
    ):
        raise AthenaValidationError("artifact compatibility negotiation outcome is not supported")


def _normalized_id(value: str) -> str:
    return normalize_nfc_text(value).casefold()


def _item_key(item: AthenaBaseModel, attribute: str) -> str:
    if attribute == "relationship_id" and isinstance(item, ExceptionManifestRelationship):
        return item.exception_id
    return str(getattr(item, attribute))


def _require_unique(items: Iterable[AthenaBaseModel], attribute: str, label: str) -> None:
    seen: set[str] = set()
    for item in items:
        key = _normalized_id(_item_key(item, attribute))
        if key in seen:
            raise AthenaValidationError(
                f"duplicate {label} after NFC+casefold normalization: {key}"
            )
        seen.add(key)


def _require_unique_text(values: Iterable[str], label: str) -> None:
    normalized = [_normalized_id(value) for value in values]
    if len(normalized) != len(set(normalized)):
        raise AthenaValidationError(
            f"duplicate {label} after NFC+casefold normalization"
        )


class TagEquals(AthenaBaseModel):
    key: str = Field(..., min_length=1, max_length=128)
    value: str = Field(..., min_length=1, max_length=256)


class ResourceIdListSelector(AthenaBaseModel):
    selector_type: Literal["resourceIdList"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    resource_ids: list[str] = Field(..., alias="resourceIds", min_length=1, max_length=200)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_resource_ids(self) -> ResourceIdListSelector:
        _require_unique_text(self.resource_ids, "selector resource id")
        return self


class TagPredicateSelector(AthenaBaseModel):
    selector_type: Literal["tagPredicate"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    predicates: list[TagEquals] = Field(..., min_length=1, max_length=20)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_predicates(self) -> TagPredicateSelector:
        _require_unique_text(
            (predicate.key for predicate in self.predicates),
            "tag predicate key",
        )
        return self


class NamePredicateSelector(AthenaBaseModel):
    selector_type: Literal["namePredicate"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    prefix: str | None = Field(default=None, min_length=1, max_length=128)
    suffix: str | None = Field(default=None, min_length=1, max_length=128)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_name_predicate(self) -> NamePredicateSelector:
        if self.prefix is None and self.suffix is None:
            raise AthenaValidationError("namePredicate requires prefix or suffix")
        for value in (self.prefix, self.suffix):
            if value is not None and any(
                token in value for token in ("*", "?", "[", "]", "(", ")")
            ):
                raise AthenaValidationError("namePredicate forbids regex and wildcard syntax")
        return self


class ResourceTypeSelector(AthenaBaseModel):
    selector_type: Literal["resourceType"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    resource_type: str = Field(
        ...,
        alias="resourceType",
        min_length=3,
        max_length=200,
        pattern=r"^[A-Za-z0-9.]+/[A-Za-z0-9]+(?:/[A-Za-z0-9]+)*$",
    )
    locations: list[str] = Field(default_factory=list, max_length=20)
    resource_groups: list[str] = Field(default_factory=list, alias="resourceGroups", max_length=20)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_filters(self) -> ResourceTypeSelector:
        _require_unique_text(self.locations, "selector location")
        _require_unique_text(self.resource_groups, "selector resource group")
        return self


class VmssSelector(AthenaBaseModel):
    selector_type: Literal["vmScaleSet"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    scale_set_resource_id: str = Field(
        ..., alias="scaleSetResourceId", min_length=1, max_length=2048
    )
    instance_ids: list[str] = Field(default_factory=list, alias="instanceIds", max_length=200)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_instance_ids(self) -> VmssSelector:
        _require_unique_text(self.instance_ids, "VM scale set instance id")
        return self


class LoadBalancerBackendSelector(AthenaBaseModel):
    selector_type: Literal["loadBalancerBackend"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    load_balancer_resource_id: str = Field(
        ..., alias="loadBalancerResourceId", min_length=1, max_length=2048
    )
    backend_pool_name: str = Field(..., alias="backendPoolName", min_length=1, max_length=128)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)


class SubnetSelector(AthenaBaseModel):
    selector_type: Literal["subnet"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    subnet_resource_id: str = Field(..., alias="subnetResourceId", min_length=1, max_length=2048)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)


class ImageSelector(AthenaBaseModel):
    selector_type: Literal["image"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    publisher: str = Field(..., min_length=1, max_length=128)
    offer: str = Field(..., min_length=1, max_length=128)
    sku: str = Field(..., min_length=1, max_length=128)
    version: str | None = Field(default=None, min_length=1, max_length=64)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)


class ProvenanceSelector(AthenaBaseModel):
    selector_type: Literal["provenance"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    collector_tool_name: str = Field(..., alias="collectorToolName", min_length=1, max_length=128)
    collector_tool_version: str = Field(
        ...,
        alias="collectorToolVersion",
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    )
    identity_evidence_ref: str = Field(
        ..., alias="identityEvidenceRef", min_length=1, max_length=128
    )
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)


type AtomicSelector = Annotated[
    ResourceIdListSelector
    | TagPredicateSelector
    | NamePredicateSelector
    | ResourceTypeSelector
    | VmssSelector
    | LoadBalancerBackendSelector
    | SubnetSelector
    | ImageSelector
    | ProvenanceSelector,
    Field(discriminator="selector_type"),
]


class CompositeAllSelector(AthenaBaseModel):
    selector_type: Literal["compositeAll"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    children: list[AtomicSelector] = Field(..., min_length=1, max_length=10)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_children(self) -> CompositeAllSelector:
        _require_unique(list(self.children), "selector_id", "composite child selector id")
        return self


class CompositeAnySelector(AthenaBaseModel):
    selector_type: Literal["compositeAny"] = Field(..., alias="selectorType")
    selector_id: str = Field(..., alias="selectorId", min_length=1, max_length=128)
    children: list[AtomicSelector] = Field(..., min_length=1, max_length=10)
    max_matches: int = Field(..., alias="maxMatches", ge=1, le=1000)

    @model_validator(mode="after")
    def validate_children(self) -> CompositeAnySelector:
        _require_unique(list(self.children), "selector_id", "composite child selector id")
        return self


type ManifestSelector = Annotated[
    ResourceIdListSelector
    | TagPredicateSelector
    | NamePredicateSelector
    | ResourceTypeSelector
    | VmssSelector
    | LoadBalancerBackendSelector
    | SubnetSelector
    | ImageSelector
    | ProvenanceSelector
    | CompositeAllSelector
    | CompositeAnySelector,
    Field(discriminator="selector_type"),
]


class ExactlyOneCardinality(AthenaBaseModel):
    cardinality_kind: Literal["exactlyOne"] = Field(..., alias="cardinalityKind")


class OneOrMoreCardinality(AthenaBaseModel):
    cardinality_kind: Literal["oneOrMore"] = Field(..., alias="cardinalityKind")


class ZeroOrMoreCardinality(AthenaBaseModel):
    cardinality_kind: Literal["zeroOrMore"] = Field(..., alias="cardinalityKind")


class BoundedCardinality(AthenaBaseModel):
    cardinality_kind: Literal["boundedRange"] = Field(..., alias="cardinalityKind")
    minimum: int = Field(..., ge=0, le=10000)
    maximum: int = Field(..., ge=0, le=10000)

    @model_validator(mode="after")
    def validate_range(self) -> BoundedCardinality:
        if self.maximum < self.minimum:
            raise AthenaValidationError("cardinality maximum must be >= minimum")
        return self


type ManifestCardinality = Annotated[
    ExactlyOneCardinality | OneOrMoreCardinality | ZeroOrMoreCardinality | BoundedCardinality,
    Field(discriminator="cardinality_kind"),
]


class ManifestOwner(AthenaBaseModel):
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    owner_role: Literal[
        "businessOwner",
        "technicalOwner",
        "operationsOwner",
        "securityOwner",
        "vendorOwner",
        "approver",
        "onCallGroup",
    ] = Field(..., alias="ownerRole")
    authority_ref: str = Field(..., alias="authorityRef", min_length=1, max_length=256)


class ManifestRole(AthenaBaseModel):
    role_id: str = Field(..., alias="roleId", min_length=1, max_length=128)
    kind: Literal[
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
    cardinality: ManifestCardinality
    selectors: list[ManifestSelector] = Field(..., min_length=1, max_length=20)
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    status: Literal["approved", "deprecated"] = "approved"

    @model_validator(mode="after")
    def validate_selectors(self) -> ManifestRole:
        _require_unique(list(self.selectors), "selector_id", "selector id")
        return self


class RoleEndpoint(AthenaBaseModel):
    endpoint_type: Literal["role"] = Field(..., alias="endpointType")
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)


class ExternalEndpoint(AthenaBaseModel):
    endpoint_type: Literal["external"] = Field(..., alias="endpointType")
    external_ref: str = Field(..., alias="externalRef", min_length=1, max_length=256)


type ManifestEndpoint = Annotated[
    RoleEndpoint | ExternalEndpoint, Field(discriminator="endpoint_type")
]


class ClauseScope(AthenaBaseModel):
    governance_scope_type: Literal["clause"] = Field(..., alias="governanceScopeType")
    manifest_id: str = Field(..., alias="manifestId", min_length=1, max_length=128)
    profile_id: str = Field(..., alias="profileId", min_length=1, max_length=128)
    clause_path: str = Field(..., alias="clausePath", min_length=1, max_length=512, pattern=r"^/")
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)


class DeclaredManifestRelationship(AthenaBaseModel):
    relationship_class: Literal["declared"] = Field(..., alias="relationshipClass")
    relationship_id: str = Field(..., alias="relationshipId", min_length=1, max_length=128)
    kind: Literal[
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
    ]
    source: ManifestEndpoint
    target: ManifestEndpoint
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    profiles: list[Environment] = Field(..., min_length=1, max_length=25)
    source_clause: str = Field(
        ..., alias="sourceClause", min_length=1, max_length=512, pattern=r"^/"
    )


class ExceptionManifestRelationship(AthenaBaseModel):
    relationship_class: Literal["exception"] = Field(..., alias="relationshipClass")
    exception_id: str = Field(..., alias="exceptionId", min_length=1, max_length=128)
    applies_to_relationship_ref: str | None = Field(
        default=None, alias="appliesToRelationshipRef", min_length=1, max_length=128
    )
    applies_to_clause_ref: str | None = Field(
        default=None, alias="appliesToClauseRef", min_length=1, max_length=128
    )
    risk_acceptance_ref: str = Field(..., alias="riskAcceptanceRef", min_length=1, max_length=128)
    governance_scope: ClauseScope = Field(..., alias="governanceScope")
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    rationale: str = Field(..., min_length=1, max_length=2000)
    expires_at: UtcDateTime = Field(..., alias="expiresAt")

    @model_validator(mode="after")
    def validate_target(self) -> ExceptionManifestRelationship:
        if (self.applies_to_relationship_ref is None) == (self.applies_to_clause_ref is None):
            raise AthenaValidationError(
                "exception requires exactly one relationship or clause target"
            )
        return self


type ManifestRelationship = Annotated[
    DeclaredManifestRelationship | ExceptionManifestRelationship,
    Field(discriminator="relationship_class"),
]


class CardinalityProof(AthenaBaseModel):
    proof_kind: Literal["cardinalityProof"] = Field(..., alias="proofKind")
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)
    expected: ManifestCardinality


class ZoneColocationProof(AthenaBaseModel):
    proof_kind: Literal["zoneColocationProof"] = Field(..., alias="proofKind")
    subject_role_ref: str = Field(..., alias="subjectRoleRef", min_length=1, max_length=128)
    anchor_role_ref: str = Field(..., alias="anchorRoleRef", min_length=1, max_length=128)


class ZoneDistributionProof(AthenaBaseModel):
    proof_kind: Literal["zoneDistributionProof"] = Field(..., alias="proofKind")
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)
    minimum_distinct_zones: int = Field(..., alias="minimumDistinctZones", ge=1, le=3)


class RelationshipPresenceProof(AthenaBaseModel):
    proof_kind: Literal["relationshipPresenceProof"] = Field(..., alias="proofKind")
    declared_relationship_ref: str = Field(
        ..., alias="declaredRelationshipRef", min_length=1, max_length=128
    )


class EvidenceFreshnessProof(AthenaBaseModel):
    proof_kind: Literal["evidenceFreshnessProof"] = Field(..., alias="proofKind")
    maximum_age_seconds: int = Field(..., alias="maximumAgeSeconds", ge=1, le=2592000)


class ControlHealthProof(AthenaBaseModel):
    proof_kind: Literal["controlHealthProof"] = Field(..., alias="proofKind")
    control_ref: str = Field(..., alias="controlRef", min_length=1, max_length=128)
    required_health: Literal["effective"] = Field(..., alias="requiredHealth")


class ObjectiveThresholdProof(AthenaBaseModel):
    proof_kind: Literal["objectiveThresholdProof"] = Field(..., alias="proofKind")
    objective_ref: str = Field(..., alias="objectiveRef", min_length=1, max_length=128)
    comparison: Literal["lt", "lte", "gt", "gte", "eq"]
    threshold: float


type ManifestProof = Annotated[
    CardinalityProof
    | ZoneColocationProof
    | ZoneDistributionProof
    | RelationshipPresenceProof
    | EvidenceFreshnessProof
    | ControlHealthProof
    | ObjectiveThresholdProof,
    Field(discriminator="proof_kind"),
]


class ManifestConstraint(AthenaBaseModel):
    constraint_id: str = Field(
        ...,
        alias="constraintId",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    constraint_type: Literal[
        "cardinality",
        "zoneColocation",
        "zoneDistribution",
        "dependencyRequired",
        "dependencyProhibited",
        "supportedSingleton",
        "objectiveRequired",
        "evidenceFreshness",
        "controlRequired",
    ] = Field(..., alias="constraintType")
    finding_kind: ManifestFindingKind = Field(..., alias="findingKind")
    governance_scope: ClauseScope = Field(..., alias="governanceScope")
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    profiles: list[Environment] = Field(..., min_length=1, max_length=25)
    proof_requirement: ManifestProof = Field(..., alias="proofRequirement")
    failure_verdict: FailureVerdict = Field(..., alias="failureVerdict")
    success_verdict: Literal["pass", "expectedConstraint", "observation"] = Field(
        ..., alias="successVerdict"
    )
    risk_acceptance_ref: str | None = Field(
        default=None, alias="riskAcceptanceRef", min_length=1, max_length=128
    )
    risk_acceptance_clause_ref: str | None = Field(
        default=None, alias="riskAcceptanceClauseRef", min_length=1, max_length=128
    )
    protected: bool = False

    @model_validator(mode="after")
    def validate_constraint_shape(self) -> ManifestConstraint:
        proof_types: dict[str, type[AthenaBaseModel]] = {
            "cardinality": CardinalityProof,
            "supportedSingleton": CardinalityProof,
            "zoneColocation": ZoneColocationProof,
            "zoneDistribution": ZoneDistributionProof,
            "dependencyRequired": RelationshipPresenceProof,
            "dependencyProhibited": RelationshipPresenceProof,
            "objectiveRequired": ObjectiveThresholdProof,
            "evidenceFreshness": EvidenceFreshnessProof,
            "controlRequired": ControlHealthProof,
        }
        if not isinstance(self.proof_requirement, proof_types[self.constraint_type]):
            raise AthenaValidationError("constraintType requires its matching proof variant")
        if self.constraint_type == "dependencyProhibited" and self.failure_verdict != "violation":
            raise AthenaValidationError("dependencyProhibited requires failureVerdict violation")
        if self.risk_acceptance_clause_ref is not None and self.finding_kind != "riskAcceptance":
            raise AthenaValidationError(
                "riskAcceptanceClauseRef is allowed only for riskAcceptance findings"
            )
        return self


class _ControlBase(AthenaBaseModel):
    control_id: str = Field(..., alias="controlId", min_length=1, max_length=128)
    governance_scope: ClauseScope = Field(..., alias="governanceScope")
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    profiles: list[Environment] = Field(..., min_length=1, max_length=25)
    health: Literal[
        "effective",
        "degraded",
        "missing",
        "unknown",
        "expired",
        "notApplicable",
    ]


class BackupControl(_ControlBase):
    control_kind: Literal["backup"] = Field(..., alias="controlKind")
    backup_policy_ref: str = Field(..., alias="backupPolicyRef", min_length=1, max_length=256)
    last_successful_backup_at: UtcDateTime = Field(..., alias="lastSuccessfulBackupAt")
    evidence_refs: list[str] = Field(..., alias="evidenceRefs", min_length=1, max_length=50)


class RestoreTestControl(_ControlBase):
    control_kind: Literal["restoreTest"] = Field(..., alias="controlKind")
    last_tested_at: UtcDateTime = Field(..., alias="lastTestedAt")
    test_outcome: Literal["passed", "failed", "partial", "unknown"] = Field(
        ..., alias="testOutcome"
    )
    rto_observed_seconds: int = Field(..., alias="rtoObservedSeconds", ge=0, le=2592000)
    evidence_refs: list[str] = Field(..., alias="evidenceRefs", min_length=1, max_length=50)


class ManualFailoverRunbookControl(_ControlBase):
    control_kind: Literal["manualFailoverRunbook"] = Field(..., alias="controlKind")
    runbook_ref: str = Field(..., alias="runbookRef", min_length=1, max_length=256)
    last_reviewed_at: UtcDateTime = Field(..., alias="lastReviewedAt")


class MonitoringAlertControl(_ControlBase):
    control_kind: Literal["monitoringAlert"] = Field(..., alias="controlKind")
    alert_rule_ref: str = Field(..., alias="alertRuleRef", min_length=1, max_length=256)
    enabled_state: Literal["enabled", "disabled", "unknown"] = Field(..., alias="enabledState")
    last_fired_at: UtcDateTime | None = Field(default=None, alias="lastFiredAt")
    evidence_refs: list[str] = Field(..., alias="evidenceRefs", min_length=1, max_length=50)


class CapacityReviewControl(_ControlBase):
    control_kind: Literal["capacityReview"] = Field(..., alias="controlKind")
    cadence: Literal["weekly", "monthly", "quarterly", "semiAnnual"]
    last_reviewed_at: UtcDateTime = Field(..., alias="lastReviewedAt")
    next_review_due_at: UtcDateTime = Field(..., alias="nextReviewDueAt")


class AccessReviewControl(_ControlBase):
    control_kind: Literal["accessReview"] = Field(..., alias="controlKind")
    cadence: Literal["monthly", "quarterly", "semiAnnual"]
    last_completed_at: UtcDateTime = Field(..., alias="lastCompletedAt")
    review_system_ref: str = Field(..., alias="reviewSystemRef", min_length=1, max_length=256)


class ChangeApprovalControl(_ControlBase):
    control_kind: Literal["changeApproval"] = Field(..., alias="controlKind")
    approval_system_ref: str = Field(..., alias="approvalSystemRef", min_length=1, max_length=256)
    required_for_change_kinds: list[
        Literal["configuration", "deployment", "identity", "network", "data"]
    ] = Field(..., alias="requiredForChangeKinds", min_length=1, max_length=5)


class VendorSupportControl(_ControlBase):
    control_kind: Literal["vendorSupport"] = Field(..., alias="controlKind")
    support_plan_ref: str = Field(..., alias="supportPlanRef", min_length=1, max_length=256)
    coverage_hours: Literal["businessHours", "24x7"] = Field(..., alias="coverageHours")
    expires_at: UtcDateTime = Field(..., alias="expiresAt")


type ManifestControl = Annotated[
    BackupControl
    | RestoreTestControl
    | ManualFailoverRunbookControl
    | MonitoringAlertControl
    | CapacityReviewControl
    | AccessReviewControl
    | ChangeApprovalControl
    | VendorSupportControl,
    Field(discriminator="control_kind"),
]


class AcceptedResourceBinding(AthenaBaseModel):
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)
    resource_id: str = Field(..., alias="resourceId", min_length=1, max_length=2048)


class ManifestRiskAcceptance(AthenaBaseModel):
    risk_acceptance_id: str = Field(..., alias="riskAcceptanceId", min_length=1, max_length=128)
    governance_scope: ClauseScope = Field(..., alias="governanceScope")
    risk_kind: Literal["availability", "resilience", "operational", "security", "compliance"] = (
        Field(..., alias="riskKind")
    )
    risk_rating: Literal["low", "medium", "high", "critical"] = Field(..., alias="riskRating")
    residual_risk_statement: str = Field(
        ..., alias="residualRiskStatement", min_length=1, max_length=2000
    )
    rationale_ref: str = Field(..., alias="rationaleRef", min_length=1, max_length=256)
    accepted_by: str = Field(..., alias="acceptedBy", min_length=1, max_length=128)
    owned_by: str = Field(..., alias="ownedBy", min_length=1, max_length=128)
    accepted_at: UtcDateTime = Field(..., alias="acceptedAt")
    expires_at: UtcDateTime = Field(..., alias="expiresAt")
    linked_control_refs: list[str] = Field(
        default_factory=list, alias="linkedControlRefs", max_length=50
    )
    accepted_resource_bindings: list[AcceptedResourceBinding] = Field(
        default_factory=list,
        alias="acceptedResourceBindings",
        max_length=1000,
    )
    profiles: list[Environment] = Field(..., min_length=1, max_length=25)
    status: ApprovalStatus

    @model_validator(mode="after")
    def validate_lifetime(self) -> ManifestRiskAcceptance:
        if self.accepted_at >= self.expires_at:
            raise AthenaValidationError("risk acceptance expiresAt must be after acceptedAt")
        binding_keys = {
            (
                _normalized_id(binding.role_ref),
                _normalized_id(binding.resource_id),
            )
            for binding in self.accepted_resource_bindings
        }
        if len(binding_keys) != len(self.accepted_resource_bindings):
            raise AthenaValidationError("acceptedResourceBindings must be unique")
        return self

    def is_active(
        self,
        *,
        as_of: datetime,
        manifest_id: str,
        profile_id: str,
        clause_path: str,
        owner_ref: str,
    ) -> bool:
        scope = self.governance_scope
        return (
            self.status == "approved"
            and self.accepted_at <= as_of < self.expires_at
            and scope.manifest_id == manifest_id
            and _normalized_id(scope.profile_id) == _normalized_id(profile_id)
            and scope.clause_path == clause_path
            and scope.owner_ref == owner_ref
            and self.owned_by == owner_ref
            and _normalized_id(profile_id) in {_normalized_id(item) for item in self.profiles}
        )


class ManifestObjective(AthenaBaseModel):
    objective_id: str = Field(..., alias="objectiveId", min_length=1, max_length=128)
    objective_type: Literal[
        "availabilitySlo",
        "latencySlo",
        "throughputSlo",
        "rto",
        "rpo",
        "serviceHours",
        "capacityHeadroom",
        "recoveryPriority",
    ] = Field(..., alias="objectiveType")
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    target: float = Field(..., ge=0)


class ContinuitySettings(AthenaBaseModel):
    zone_loss_continuity_required: bool = Field(..., alias="zoneLossContinuityRequired")


class ManifestProfileSettings(AthenaBaseModel):
    continuity: ContinuitySettings


class GovernedWeakeningOverride(AthenaBaseModel):
    override_id: str = Field(..., alias="overrideId", min_length=1, max_length=128)
    reason: OverrideReason
    target_path: str = Field(..., alias="targetPath", min_length=1, max_length=512, pattern=r"^/")
    target_ref: str = Field(..., alias="targetRef", min_length=1, max_length=128)
    owner_ref: str = Field(..., alias="ownerRef", min_length=1, max_length=128)
    rationale: str = Field(..., min_length=1, max_length=2000)
    approved_by: str = Field(..., alias="approvedBy", min_length=1, max_length=128)
    status: ApprovalStatus
    accepted_at: UtcDateTime = Field(..., alias="acceptedAt")
    expires_at: UtcDateTime = Field(..., alias="expiresAt")
    profiles: list[Environment] = Field(..., min_length=1, max_length=25)

    def authorizes(
        self,
        *,
        as_of: datetime,
        profile_id: str,
        target_path: str,
        target_ref: str,
        reason: OverrideReason,
    ) -> bool:
        return (
            self.status == "approved"
            and self.accepted_at <= as_of < self.expires_at
            and _normalized_id(profile_id)
            in {_normalized_id(item) for item in self.profiles}
            and self.target_path == target_path
            and _normalized_id(self.target_ref) == _normalized_id(target_ref)
            and self.reason == reason
        )


class DisabledManifestRef(AthenaBaseModel):
    target_kind: Literal[
        "role", "relationship", "constraint", "control", "riskAcceptance", "objective", "owner"
    ] = Field(..., alias="targetKind")
    target_ref: str = Field(..., alias="targetRef", min_length=1, max_length=128)
    governance_override_ref: str = Field(
        ..., alias="governanceOverrideRef", min_length=1, max_length=128
    )


class ManifestProfile(AthenaBaseModel):
    profile_id: str = Field(..., alias="profileId", min_length=1, max_length=128)
    profile_type: Environment = Field(..., alias="profileType")
    extends: str | None = Field(default=None, min_length=1, max_length=128)
    settings: ManifestProfileSettings
    roles: list[ManifestRole] = Field(default_factory=list, max_length=200)
    relationships: list[ManifestRelationship] = Field(default_factory=list, max_length=500)
    constraints: list[ManifestConstraint] = Field(default_factory=list, max_length=500)
    controls: list[ManifestControl] = Field(default_factory=list, max_length=500)
    risk_acceptances: list[ManifestRiskAcceptance] = Field(
        default_factory=list, alias="riskAcceptances", max_length=200
    )
    objectives: list[ManifestObjective] = Field(default_factory=list, max_length=200)
    ownership: list[ManifestOwner] = Field(default_factory=list, max_length=100)
    weakening_overrides: list[GovernedWeakeningOverride] = Field(
        default_factory=list, alias="weakeningOverrides", max_length=100
    )
    disabled_refs: list[DisabledManifestRef] = Field(
        default_factory=list, alias="disabledRefs", max_length=100
    )

    @model_validator(mode="after")
    def validate_local_uniqueness(self) -> ManifestProfile:
        for items, attribute, label in (
            (list(self.roles), "role_id", "role id"),
            (list(self.relationships), "relationship_id", "relationship id"),
            (list(self.constraints), "constraint_id", "constraint id"),
            (list(self.controls), "control_id", "control id"),
            (list(self.risk_acceptances), "risk_acceptance_id", "risk acceptance id"),
            (list(self.objectives), "objective_id", "objective id"),
            (list(self.ownership), "owner_ref", "owner ref"),
            (list(self.weakening_overrides), "override_id", "override id"),
        ):
            _require_unique(items, attribute, label)
        return self


class CanonicalWorkloadIdentity(AthenaBaseModel):
    display_name: str = Field(..., alias="displayName", min_length=1, max_length=200)
    environments: list[Environment] = Field(..., min_length=1, max_length=25)
    allowed_evidence_scopes: list[EvidenceScope] = Field(
        ..., alias="allowedEvidenceScopes", min_length=1, max_length=100
    )


class CanonicalManifestAudit(AthenaBaseModel):
    published_by: str = Field(..., alias="publishedBy", min_length=1, max_length=128)
    published_at: UtcDateTime = Field(..., alias="publishedAt")
    approval_status: Literal["approved"] = Field(..., alias="approvalStatus")


def _manifest_digest_payload(
    value: CanonicalWorkloadManifest | dict[str, Any],
    *,
    semantic: bool,
) -> dict[str, Any]:
    payload = (
        value.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=False,
            exclude_unset=True,
        )
        if isinstance(value, BaseAthenaModel)
        else deepcopy(value)
    )
    _materialize_manifest_defaults(payload)
    _sort_manifest_keyed_collections(payload)
    compatibility = payload.get("compatibility")
    if not isinstance(compatibility, dict):
        raise AthenaValidationError("manifest compatibility object is required")
    compatibility.pop("artifactDigest", None)
    compatibility.pop("semanticDigest", None)
    if semantic:
        workload = payload.get("workload")
        if isinstance(workload, dict):
            workload.pop("displayName", None)
        compatibility.pop("schemaVersion", None)
    return payload


def _materialize_manifest_defaults(canonical: dict[str, Any]) -> None:
    for field_name in (
        "relationships",
        "constraints",
        "controls",
        "riskAcceptances",
        "objectives",
    ):
        canonical.setdefault(field_name, [])

    def materialize_collections(container: dict[str, Any]) -> None:
        roles = container.get("roles")
        if isinstance(roles, list):
            for role in roles:
                if not isinstance(role, dict):
                    continue
                role.setdefault("status", "approved")
                selectors = role.get("selectors")
                if isinstance(selectors, list):
                    for selector in selectors:
                        _materialize_selector_defaults(selector)
        constraints = container.get("constraints")
        if isinstance(constraints, list):
            for constraint in constraints:
                if isinstance(constraint, dict):
                    constraint.setdefault("protected", False)
        risks = container.get("riskAcceptances")
        if isinstance(risks, list):
            for risk in risks:
                if isinstance(risk, dict):
                    risk.setdefault("linkedControlRefs", [])
                    risk.setdefault("acceptedResourceBindings", [])

    def _materialize_selector_defaults(selector: Any) -> None:
        if not isinstance(selector, dict):
            return
        selector_type = selector.get("selectorType")
        if selector_type == "resourceType":
            selector.setdefault("locations", [])
            selector.setdefault("resourceGroups", [])
        elif selector_type == "vmScaleSet":
            selector.setdefault("instanceIds", [])
        children = selector.get("children")
        if isinstance(children, list):
            for child in children:
                _materialize_selector_defaults(child)

    materialize_collections(canonical)
    profiles = canonical.get("profiles")
    if isinstance(profiles, dict):
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            for field_name in (
                "roles",
                "relationships",
                "constraints",
                "controls",
                "riskAcceptances",
                "objectives",
                "ownership",
                "weakeningOverrides",
                "disabledRefs",
            ):
                profile.setdefault(field_name, [])
            materialize_collections(profile)


def _sort_manifest_keyed_collections(payload: dict[str, Any]) -> None:
    key_fields = {
        "roles": ("roleId",),
        "constraints": ("constraintId",),
        "controls": ("controlId",),
        "riskAcceptances": ("riskAcceptanceId",),
        "objectives": ("objectiveId",),
        "ownership": ("ownerRef",),
        "weakeningOverrides": ("overrideId",),
        "disabledRefs": ("targetKind", "targetRef"),
    }

    def sort_collections(container: dict[str, Any]) -> None:
        relationships = container.get("relationships")
        if isinstance(relationships, list):
            relationships.sort(
                key=lambda item: (
                    _normalized_id(str(item.get("relationshipId") or item.get("exceptionId") or ""))
                    if isinstance(item, dict)
                    else ""
                )
            )
        for collection_name, candidate_keys in key_fields.items():
            items = container.get(collection_name)
            if not isinstance(items, list):
                continue
            items.sort(
                key=lambda item: (
                    tuple(_normalized_id(str(item.get(key, ""))) for key in candidate_keys)
                    if isinstance(item, dict)
                    else ("",)
                )
            )
            if collection_name == "roles":
                for role in items:
                    if not isinstance(role, dict):
                        continue
                    selectors = role.get("selectors")
                    if isinstance(selectors, list):
                        selectors.sort(
                            key=lambda selector: (
                                _normalized_id(str(selector.get("selectorId", "")))
                                if isinstance(selector, dict)
                                else ""
                            )
                        )
                        for selector in selectors:
                            _sort_selector_children(selector)

    def _sort_selector_children(selector: Any) -> None:
        if not isinstance(selector, dict):
            return
        children = selector.get("children")
        if not isinstance(children, list):
            return
        children.sort(
            key=lambda child: (
                _normalized_id(str(child.get("selectorId", ""))) if isinstance(child, dict) else ""
            )
        )
        for child in children:
            _sort_selector_children(child)

    sort_collections(payload)
    profiles = payload.get("profiles")
    if isinstance(profiles, dict):
        payload["profiles"] = {key: profiles[key] for key in sorted(profiles, key=_normalized_id)}
        for profile in payload["profiles"].values():
            if isinstance(profile, dict):
                sort_collections(profile)


def canonicalize_manifest_payload(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = deepcopy(payload)
    _materialize_manifest_defaults(canonical)
    _sort_manifest_keyed_collections(canonical)
    compatibility = canonical.get("compatibility")
    if not isinstance(compatibility, dict):
        raise AthenaValidationError("manifest compatibility object is required")
    compatibility["artifactDigest"] = compute_artifact_digest(
        _manifest_digest_payload(canonical, semantic=False)
    )
    compatibility["semanticDigest"] = compute_artifact_digest(
        _manifest_digest_payload(canonical, semantic=True)
    )
    return canonical


class CanonicalWorkloadManifest(AthenaBaseModel):
    manifest_id: str = Field(..., alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        ...,
        alias="manifestVersion",
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    )
    cloud: AzureCloudName
    workload: CanonicalWorkloadIdentity
    profiles: dict[str, ManifestProfile] = Field(..., min_length=1, max_length=25)
    roles: list[ManifestRole] = Field(..., min_length=1, max_length=200)
    relationships: list[ManifestRelationship] = Field(default_factory=list, max_length=500)
    constraints: list[ManifestConstraint] = Field(default_factory=list, max_length=500)
    controls: list[ManifestControl] = Field(default_factory=list, max_length=500)
    risk_acceptances: list[ManifestRiskAcceptance] = Field(
        default_factory=list, alias="riskAcceptances", max_length=200
    )
    objectives: list[ManifestObjective] = Field(default_factory=list, max_length=200)
    ownership: list[ManifestOwner] = Field(..., min_length=1, max_length=100)
    compatibility: CompatibilityMetadata
    audit: CanonicalManifestAudit

    @model_validator(mode="before")
    @classmethod
    def validate_supplied_digests(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        compatibility = value.get("compatibility")
        if not isinstance(compatibility, dict):
            return value
        if compatibility.get("artifactDigest") != compute_artifact_digest(
            _manifest_digest_payload(value, semantic=False)
        ) or compatibility.get("semanticDigest") != compute_artifact_digest(
            _manifest_digest_payload(value, semantic=True)
        ):
            raise AthenaValidationError(
                "manifest compatibility digests do not match canonical preimages"
            )
        return value

    @model_validator(mode="after")
    def validate_manifest_ids(self) -> CanonicalWorkloadManifest:
        _require_supported_compatibility(self.compatibility, artifact_kind="workloadManifest")
        _require_unique_text(self.workload.environments, "workload environment")
        normalized_profiles: set[str] = set()
        for key, profile in self.profiles.items():
            normalized = _normalized_id(key)
            if normalized in normalized_profiles:
                raise AthenaValidationError("duplicate normalized profile id")
            normalized_profiles.add(normalized)
            if normalized != _normalized_id(profile.profile_id):
                raise AthenaValidationError("profile map key must match profileId")
        if not {"production", "development", "training"}.issubset(normalized_profiles):
            raise AthenaValidationError(
                "canonical WC-001 manifest requires production, development, and training"
            )
        profiles_by_id = {
            _normalized_id(profile.profile_id): profile for profile in self.profiles.values()
        }
        for profile in self.profiles.values():
            if (
                profile.extends is not None
                and _normalized_id(profile.extends) not in profiles_by_id
            ):
                raise AthenaValidationError(f"missing parent profile: {profile.extends}")
        completed: set[str] = set()

        def visit(profile_id: str, path: set[str]) -> None:
            if profile_id in path:
                raise AthenaValidationError("profile inheritance cycle detected")
            if profile_id in completed:
                return
            profile = profiles_by_id[profile_id]
            if profile.extends is not None:
                visit(_normalized_id(profile.extends), {*path, profile_id})
            completed.add(profile_id)

        for profile_id in profiles_by_id:
            visit(profile_id, set())
        for items, attribute, label in (
            (list(self.roles), "role_id", "role id"),
            (list(self.relationships), "relationship_id", "relationship id"),
            (list(self.constraints), "constraint_id", "constraint id"),
            (list(self.controls), "control_id", "control id"),
            (list(self.risk_acceptances), "risk_acceptance_id", "risk acceptance id"),
            (list(self.objectives), "objective_id", "objective id"),
            (list(self.ownership), "owner_ref", "owner ref"),
        ):
            _require_unique(items, attribute, label)
        all_roles = [
            *self.roles,
            *[role for profile in self.profiles.values() for role in profile.roles],
        ]
        if any(role.status != "approved" for role in all_roles):
            raise AthenaValidationError("published manifests may contain only approved roles")
        applicable_items = [
            *self.constraints,
            *self.controls,
            *self.risk_acceptances,
            *[
                item
                for profile in self.profiles.values()
                for item in [
                    *profile.constraints,
                    *profile.controls,
                    *profile.risk_acceptances,
                ]
            ],
        ]
        for item in applicable_items:
            _require_unique_text(item.profiles, "profile applicability reference")
            for applicable_profile in item.profiles:
                if _normalized_id(applicable_profile) not in normalized_profiles:
                    raise AthenaValidationError("profile applicability reference is unresolved")
        applicable_relationships = [
            *self.relationships,
            *[item for profile in self.profiles.values() for item in profile.relationships],
        ]
        for relationship in applicable_relationships:
            if isinstance(relationship, DeclaredManifestRelationship):
                _require_unique_text(
                    relationship.profiles,
                    "relationship profile applicability reference",
                )
                for applicable_profile in relationship.profiles:
                    if _normalized_id(applicable_profile) not in normalized_profiles:
                        raise AthenaValidationError(
                            "relationship profile applicability is unresolved"
                        )
        risks = [
            *self.risk_acceptances,
            *[
                risk
                for profile in self.profiles.values()
                for risk in profile.risk_acceptances
            ],
        ]
        for risk in risks:
            _require_unique_text(risk.linked_control_refs, "linked control reference")
        for profile in self.profiles.values():
            for override in profile.weakening_overrides:
                _require_unique_text(
                    override.profiles,
                    "weakening override profile applicability reference",
                )
                for applicable_profile in override.profiles:
                    if _normalized_id(applicable_profile) not in normalized_profiles:
                        raise AthenaValidationError(
                            "weakening override profile applicability is unresolved"
                        )
            disabled_keys = [
                f"{item.target_kind}\0{_normalized_id(item.target_ref)}"
                for item in profile.disabled_refs
            ]
            if len(disabled_keys) != len(set(disabled_keys)):
                raise AthenaValidationError("duplicate normalized disabled reference")
        return self

    def compute_artifact_digest_value(self) -> str:
        return compute_artifact_digest(_manifest_digest_payload(self, semantic=False))

    def compute_semantic_digest_value(self) -> str:
        return compute_artifact_digest(_manifest_digest_payload(self, semantic=True))


class ResolvedManifestProfile(AthenaBaseModel):
    manifest_id: str = Field(..., alias="manifestId")
    manifest_version: str = Field(..., alias="manifestVersion")
    profile_id: str = Field(..., alias="profileId")
    profile_type: Environment = Field(..., alias="profileType")
    allowed_evidence_scopes: list[EvidenceScope] = Field(
        ..., alias="allowedEvidenceScopes", min_length=1, max_length=100
    )
    compatibility: CompatibilityMetadata
    inheritance_chain: list[str] = Field(..., alias="inheritanceChain", min_length=1, max_length=25)
    settings: ManifestProfileSettings
    roles: list[ManifestRole]
    relationships: list[ManifestRelationship]
    constraints: list[ManifestConstraint]
    controls: list[ManifestControl]
    risk_acceptances: list[ManifestRiskAcceptance] = Field(..., alias="riskAcceptances")
    objectives: list[ManifestObjective]
    ownership: list[ManifestOwner]
    resolved_profile_digest: str = Field(
        ..., alias="resolvedProfileDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )

    def _digest_payload(self, *, semantic: bool) -> dict[str, Any]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("resolvedProfileDigest")
        payload["compatibility"].pop("artifactDigest", None)
        payload["compatibility"].pop("semanticDigest", None)
        if semantic:
            payload["compatibility"].pop("schemaVersion", None)
        return payload

    def recompute_artifact_digest(self) -> str:
        return compute_artifact_digest(self._digest_payload(semantic=False))

    def recompute_semantic_digest(self) -> str:
        return compute_artifact_digest(self._digest_payload(semantic=True))

    @model_validator(mode="after")
    def validate_digest(self) -> ResolvedManifestProfile:
        expected_artifact = self.recompute_artifact_digest()
        expected_semantic = self.recompute_semantic_digest()
        if (
            self.compatibility.artifact_digest != expected_artifact
            or self.compatibility.semantic_digest != expected_semantic
            or self.resolved_profile_digest != expected_semantic
        ):
            raise AthenaValidationError("resolvedProfileDigest does not match resolved profile")
        _require_supported_compatibility(self.compatibility, artifact_kind="resolvedProfile")
        return self


def _variant(item: AthenaBaseModel) -> tuple[str, ...]:
    fields = (
        "kind",
        "selector_type",
        "relationship_class",
        "constraint_type",
        "control_kind",
        "objective_type",
        "risk_kind",
    )
    values = tuple(str(getattr(item, field)) for field in fields if hasattr(item, field))
    if isinstance(item, ManifestRole):
        values += (str(item.cardinality.cardinality_kind),)
    if isinstance(item, ManifestConstraint):
        values += (str(item.proof_requirement.proof_kind),)
    if isinstance(item, (CompositeAllSelector, CompositeAnySelector)):
        values += tuple(
            f"{_normalized_id(child.selector_id)}:{child.selector_type}"
            for child in sorted(item.children, key=lambda child: _normalized_id(child.selector_id))
        )
    return values


def _selector_tree(selector: ManifestSelector) -> Iterable[ManifestSelector | AtomicSelector]:
    yield selector
    if isinstance(selector, (CompositeAllSelector, CompositeAnySelector)):
        yield from selector.children


def _selector_semantic_payload(
    selector: ManifestSelector | AtomicSelector,
) -> dict[str, Any]:
    payload = selector.model_dump(mode="json", by_alias=True, exclude_none=True)

    def normalize(value: Any) -> None:
        if not isinstance(value, dict):
            return
        value.pop("selectorId", None)
        value.pop("maxMatches", None)
        for field_name in (
            "resourceIds",
            "locations",
            "resourceGroups",
            "instanceIds",
        ):
            items = value.get(field_name)
            if isinstance(items, list):
                items.sort(key=lambda item: _normalized_id(str(item)))
        predicates = value.get("predicates")
        if isinstance(predicates, list):
            predicates.sort(
                key=lambda item: (
                    _normalized_id(str(item.get("key", "")))
                    if isinstance(item, dict)
                    else ""
                )
            )
        children = value.get("children")
        if isinstance(children, list):
            for child in children:
                normalize(child)
            children.sort(key=compute_artifact_digest)

    normalize(payload)
    return payload


def _selector_fingerprint(selector: ManifestSelector | AtomicSelector) -> str:
    return compute_artifact_digest(_selector_semantic_payload(selector))


def _normalized_filter_is_narrower(previous: list[str], current: list[str]) -> bool:
    previous_values = {_normalized_id(value) for value in previous}
    current_values = {_normalized_id(value) for value in current}
    if not previous_values:
        return True
    return bool(current_values) and current_values.issubset(previous_values)


def _selector_override_is_narrower(
    previous: ManifestSelector | AtomicSelector,
    current: ManifestSelector | AtomicSelector,
) -> bool:
    if (
        previous.selector_type != current.selector_type
        or current.max_matches > previous.max_matches
    ):
        return False
    if isinstance(previous, ResourceIdListSelector) and isinstance(
        current, ResourceIdListSelector
    ):
        return {
            _normalized_id(value) for value in current.resource_ids
        }.issubset({_normalized_id(value) for value in previous.resource_ids})
    if isinstance(previous, TagPredicateSelector) and isinstance(
        current, TagPredicateSelector
    ):
        previous_predicates = {
            _normalized_id(item.key): normalize_nfc_text(item.value)
            for item in previous.predicates
        }
        current_predicates = {
            _normalized_id(item.key): normalize_nfc_text(item.value)
            for item in current.predicates
        }
        return all(
            current_predicates.get(key) == value
            for key, value in previous_predicates.items()
        )
    if isinstance(previous, NamePredicateSelector) and isinstance(
        current, NamePredicateSelector
    ):
        prefix_is_narrower = previous.prefix is None or (
            current.prefix is not None
            and normalize_nfc_text(current.prefix).startswith(normalize_nfc_text(previous.prefix))
        )
        suffix_is_narrower = previous.suffix is None or (
            current.suffix is not None
            and normalize_nfc_text(current.suffix).endswith(normalize_nfc_text(previous.suffix))
        )
        return prefix_is_narrower and suffix_is_narrower
    if isinstance(previous, ResourceTypeSelector) and isinstance(
        current, ResourceTypeSelector
    ):
        return (
            _normalized_id(previous.resource_type) == _normalized_id(current.resource_type)
            and _normalized_filter_is_narrower(previous.locations, current.locations)
            and _normalized_filter_is_narrower(
                previous.resource_groups, current.resource_groups
            )
        )
    if isinstance(previous, VmssSelector) and isinstance(current, VmssSelector):
        return (
            _normalized_id(previous.scale_set_resource_id)
            == _normalized_id(current.scale_set_resource_id)
            and _normalized_filter_is_narrower(
                previous.instance_ids,
                current.instance_ids,
            )
        )
    if isinstance(previous, LoadBalancerBackendSelector) and isinstance(
        current, LoadBalancerBackendSelector
    ):
        return (
            _normalized_id(previous.load_balancer_resource_id)
            == _normalized_id(current.load_balancer_resource_id)
            and _normalized_id(previous.backend_pool_name)
            == _normalized_id(current.backend_pool_name)
        )
    if isinstance(previous, SubnetSelector) and isinstance(current, SubnetSelector):
        return _normalized_id(previous.subnet_resource_id) == _normalized_id(
            current.subnet_resource_id
        )
    if isinstance(previous, ImageSelector) and isinstance(current, ImageSelector):
        same_image = (
            _normalized_id(previous.publisher) == _normalized_id(current.publisher)
            and _normalized_id(previous.offer) == _normalized_id(current.offer)
            and _normalized_id(previous.sku) == _normalized_id(current.sku)
        )
        version_is_narrower = previous.version is None or (
            current.version is not None
            and _normalized_id(previous.version) == _normalized_id(current.version)
        )
        return same_image and version_is_narrower
    if isinstance(previous, ProvenanceSelector) and isinstance(
        current, ProvenanceSelector
    ):
        return (
            _normalized_id(previous.collector_tool_name)
            == _normalized_id(current.collector_tool_name)
            and previous.collector_tool_version == current.collector_tool_version
            and _normalized_id(previous.identity_evidence_ref)
            == _normalized_id(current.identity_evidence_ref)
        )
    if isinstance(previous, (CompositeAllSelector, CompositeAnySelector)) and isinstance(
        current, (CompositeAllSelector, CompositeAnySelector)
    ):
        previous_children = {
            _normalized_id(child.selector_id): child for child in previous.children
        }
        current_children = {
            _normalized_id(child.selector_id): child for child in current.children
        }
        return previous_children.keys() == current_children.keys() and all(
            _selector_override_is_narrower(
                previous_children[child_id],
                current_children[child_id],
            )
            for child_id in previous_children
        )
    return False


def _normalized_filters_overlap(left: list[str], right: list[str]) -> bool:
    if not left or not right:
        return True
    return bool(
        {_normalized_id(value) for value in left}
        & {_normalized_id(value) for value in right}
    )


def _selectors_may_overlap(
    left: ManifestSelector | AtomicSelector,
    right: ManifestSelector | AtomicSelector,
) -> bool:
    if isinstance(left, CompositeAnySelector):
        return any(_selectors_may_overlap(child, right) for child in left.children)
    if isinstance(right, CompositeAnySelector):
        return any(_selectors_may_overlap(left, child) for child in right.children)
    if isinstance(left, CompositeAllSelector):
        return all(_selectors_may_overlap(child, right) for child in left.children)
    if isinstance(right, CompositeAllSelector):
        return all(_selectors_may_overlap(left, child) for child in right.children)
    if isinstance(left, ResourceIdListSelector) and isinstance(
        right, ResourceIdListSelector
    ):
        return bool(
            {_normalized_id(value) for value in left.resource_ids}
            & {_normalized_id(value) for value in right.resource_ids}
        )
    if isinstance(left, TagPredicateSelector) and isinstance(
        right, TagPredicateSelector
    ):
        left_predicates = {
            _normalized_id(item.key): normalize_nfc_text(item.value)
            for item in left.predicates
        }
        right_predicates = {
            _normalized_id(item.key): normalize_nfc_text(item.value)
            for item in right.predicates
        }
        return not any(
            key in right_predicates and right_predicates[key] != value
            for key, value in left_predicates.items()
        )
    if isinstance(left, NamePredicateSelector) and isinstance(
        right, NamePredicateSelector
    ):
        prefixes_overlap = (
            left.prefix is None
            or right.prefix is None
            or normalize_nfc_text(left.prefix).startswith(normalize_nfc_text(right.prefix))
            or normalize_nfc_text(right.prefix).startswith(normalize_nfc_text(left.prefix))
        )
        suffixes_overlap = (
            left.suffix is None
            or right.suffix is None
            or normalize_nfc_text(left.suffix).endswith(normalize_nfc_text(right.suffix))
            or normalize_nfc_text(right.suffix).endswith(normalize_nfc_text(left.suffix))
        )
        return prefixes_overlap and suffixes_overlap
    if isinstance(left, ResourceTypeSelector) and isinstance(
        right, ResourceTypeSelector
    ):
        return (
            _normalized_id(left.resource_type) == _normalized_id(right.resource_type)
            and _normalized_filters_overlap(left.locations, right.locations)
            and _normalized_filters_overlap(left.resource_groups, right.resource_groups)
        )
    if isinstance(left, VmssSelector) and isinstance(right, VmssSelector):
        return (
            _normalized_id(left.scale_set_resource_id)
            == _normalized_id(right.scale_set_resource_id)
            and _normalized_filters_overlap(left.instance_ids, right.instance_ids)
        )
    if isinstance(left, LoadBalancerBackendSelector) and isinstance(
        right, LoadBalancerBackendSelector
    ):
        return (
            _normalized_id(left.load_balancer_resource_id)
            == _normalized_id(right.load_balancer_resource_id)
            and _normalized_id(left.backend_pool_name)
            == _normalized_id(right.backend_pool_name)
        )
    if isinstance(left, SubnetSelector) and isinstance(right, SubnetSelector):
        return _normalized_id(left.subnet_resource_id) == _normalized_id(
            right.subnet_resource_id
        )
    if isinstance(left, ImageSelector) and isinstance(right, ImageSelector):
        return (
            _normalized_id(left.publisher) == _normalized_id(right.publisher)
            and _normalized_id(left.offer) == _normalized_id(right.offer)
            and _normalized_id(left.sku) == _normalized_id(right.sku)
            and (
                left.version is None
                or right.version is None
                or _normalized_id(left.version) == _normalized_id(right.version)
            )
        )
    if isinstance(left, ProvenanceSelector) and isinstance(
        right, ProvenanceSelector
    ):
        return (
            _normalized_id(left.collector_tool_name)
            == _normalized_id(right.collector_tool_name)
            and left.collector_tool_version == right.collector_tool_version
            and _normalized_id(left.identity_evidence_ref)
            == _normalized_id(right.identity_evidence_ref)
        )
    return left.selector_type != right.selector_type


def _validate_resolved_selectors(roles: list[ManifestRole]) -> None:
    selector_ids: dict[str, str] = {}
    selector_fingerprints: dict[str, str] = {}
    selectors: list[tuple[str, ManifestSelector]] = []
    for role in roles:
        for selector in role.selectors:
            for nested in _selector_tree(selector):
                selector_id = _normalized_id(nested.selector_id)
                previous_role = selector_ids.get(selector_id)
                if previous_role is not None:
                    raise AthenaValidationError(
                        "selector refs must resolve exactly once; "
                        f"{nested.selector_id!r} is used by {previous_role!r} and {role.role_id!r}"
                    )
                selector_ids[selector_id] = role.role_id
            fingerprint = _selector_fingerprint(selector)
            previous_role = selector_fingerprints.get(fingerprint)
            if previous_role is not None:
                raise AthenaValidationError(
                    "ambiguous selectors have identical semantics for roles "
                    f"{previous_role!r} and {role.role_id!r}"
                )
            selector_fingerprints[fingerprint] = role.role_id
            for previous_role, previous_selector in selectors:
                if (
                    _normalized_id(previous_role) != _normalized_id(role.role_id)
                    and _selectors_may_overlap(previous_selector, selector)
                ):
                    raise AthenaValidationError(
                        "ambiguous selectors may bind one resource to multiple roles"
                    )
            selectors.append((role.role_id, selector))


_CONTROL_COMMON_FIELDS = frozenset(
    {
        "controlId",
        "controlKind",
        "governanceScope",
        "ownerRef",
        "profiles",
        "health",
    }
)


def _control_variant_payload(control: ManifestControl) -> dict[str, Any]:
    payload = control.model_dump(mode="json", by_alias=True, exclude_none=False)
    return {
        key: value
        for key, value in payload.items()
        if key not in _CONTROL_COMMON_FIELDS
    }


def _normalized_optional_ref_list(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise AthenaValidationError("control evidenceRefs must be a list")
    return tuple(sorted(_normalized_id(str(item)) for item in value))


def _validate_inherited_semantics(
    *,
    child: ManifestProfile,
    inherited_roles: list[ManifestRole],
    roles: list[ManifestRole],
    inherited_relationships: list[ManifestRelationship],
    relationships: list[ManifestRelationship],
    inherited_constraints: list[ManifestConstraint],
    constraints: list[ManifestConstraint],
    inherited_controls: list[ManifestControl],
    controls: list[ManifestControl],
    inherited_risks: list[ManifestRiskAcceptance],
    risks: list[ManifestRiskAcceptance],
    as_of: datetime,
) -> None:
    inherited_roles_by_id = {
        _normalized_id(item.role_id): item for item in inherited_roles
    }
    roles_by_id = {_normalized_id(item.role_id): item for item in roles}
    child_role_ids = {_normalized_id(item.role_id) for item in child.roles}
    for role_id in child_role_ids & inherited_roles_by_id.keys():
        previous = inherited_roles_by_id[role_id]
        current = roles_by_id[role_id]
        previous_selectors = {
            _normalized_id(item.selector_id): item for item in previous.selectors
        }
        current_selectors = {
            _normalized_id(item.selector_id): item for item in current.selectors
        }
        if current_selectors.keys() != previous_selectors.keys():
            raise AthenaValidationError(
                f"direct selector set expansion is ambiguous for inherited role {current.role_id}"
            )
        for selector_id, previous_selector in previous_selectors.items():
            current_selector = current_selectors[selector_id]
            if (
                previous_selector.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
                != current_selector.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
                and not _selector_override_is_narrower(
                    previous_selector,
                    current_selector,
                )
            ):
                raise AthenaValidationError(
                    "direct selector weakening or ambiguous selector override "
                    f"requires a new selector id: {current_selector.selector_id}"
                )

    def reject_applicability_removal(
        inherited: Iterable[AthenaBaseModel],
        resolved: Iterable[AthenaBaseModel],
        *,
        key_attribute: str,
    ) -> None:
        inherited_by_id = {
            _normalized_id(_item_key(item, key_attribute)): item for item in inherited
        }
        for item in resolved:
            previous = inherited_by_id.get(
                _normalized_id(_item_key(item, key_attribute))
            )
            if previous is None or not hasattr(previous, "profiles") or not hasattr(
                item, "profiles"
            ):
                continue
            previous_profiles = {
                _normalized_id(value) for value in previous.profiles
            }
            current_profiles = {_normalized_id(value) for value in item.profiles}
            child_id = _normalized_id(child.profile_id)
            if child_id in previous_profiles and child_id not in current_profiles:
                raise AthenaValidationError(
                    "direct applicability weakening requires an explicit disabledRef"
                )

    reject_applicability_removal(
        inherited_relationships,
        relationships,
        key_attribute="relationship_id",
    )
    reject_applicability_removal(
        inherited_constraints,
        constraints,
        key_attribute="constraint_id",
    )
    reject_applicability_removal(
        inherited_controls,
        controls,
        key_attribute="control_id",
    )
    reject_applicability_removal(
        inherited_risks,
        risks,
        key_attribute="risk_acceptance_id",
    )

    inherited_controls_by_id = {
        _normalized_id(item.control_id): item for item in inherited_controls
    }
    control_health_strength = {
        "effective": 5,
        "degraded": 4,
        "unknown": 3,
        "missing": 2,
        "expired": 2,
        "notApplicable": 1,
    }
    for control in controls:
        previous_control = inherited_controls_by_id.get(
            _normalized_id(control.control_id)
        )
        if (
            previous_control is not None
            and control_health_strength[control.health]
            < control_health_strength[previous_control.health]
        ):
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/controls/"
                    f"{control.control_id}/health"
                ),
                target_ref=control.control_id,
                reason="controlRequirementRelaxation",
            )
        if previous_control is None:
            continue
        previous_variant = _control_variant_payload(previous_control)
        current_variant = _control_variant_payload(control)
        previous_evidence_refs = _normalized_optional_ref_list(
            previous_variant.pop("evidenceRefs", None)
        )
        current_evidence_refs = _normalized_optional_ref_list(
            current_variant.pop("evidenceRefs", None)
        )
        if previous_evidence_refs != current_evidence_refs:
            raise AthenaValidationError(
                "inherited control evidenceRefs are immutable; use a new controlId"
            )
        for field_name in sorted(previous_variant.keys() | current_variant.keys()):
            if previous_variant.get(field_name) == current_variant.get(field_name):
                continue
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/controls/"
                    f"{control.control_id}/{field_name}"
                ),
                target_ref=control.control_id,
                reason="controlRequirementRelaxation",
            )

    inherited_risks_by_id = {
        _normalized_id(item.risk_acceptance_id): item for item in inherited_risks
    }
    for risk in child.risk_acceptances:
        previous_risk = inherited_risks_by_id.get(
            _normalized_id(risk.risk_acceptance_id)
        )
        if previous_risk is not None and previous_risk.model_dump(
            mode="json", by_alias=True, exclude_none=True
        ) != risk.model_dump(mode="json", by_alias=True, exclude_none=True):
            raise AthenaValidationError(
                "inherited risk acceptances are immutable; use a new riskAcceptanceId"
            )

def _merge_keyed[T: AthenaBaseModel](
    current: list[T],
    additions: list[T],
    *,
    key_attribute: str,
) -> list[T]:
    merged = {_normalized_id(_item_key(item, key_attribute)): item for item in current}
    for item in additions:
        key = _normalized_id(_item_key(item, key_attribute))
        previous = merged.get(key)
        if previous is not None and _variant(previous) != _variant(item):
            raise AthenaValidationError(
                f"illegal discriminator or type change for inherited ref {key!r}"
            )
        if (
            isinstance(previous, ManifestConstraint)
            and isinstance(item, ManifestConstraint)
            and (previous.protected or _normalized_id(previous.constraint_id) in _PROTECTED_REFS)
            and not item.protected
        ):
            raise AthenaValidationError(
                f"protected constraint cannot be unprotected: {item.constraint_id}"
            )
        if isinstance(previous, ManifestRole) and isinstance(item, ManifestRole):
            selectors = _merge_keyed(
                list(previous.selectors),
                list(item.selectors),
                key_attribute="selector_id",
            )
            payload = item.model_dump(mode="python", by_alias=True)
            payload["selectors"] = selectors
            item = ManifestRole.model_validate(payload)  # type: ignore[assignment]
        merged[key] = item
    return [merged[key] for key in sorted(merged)]


def _cardinality_bounds(cardinality: ManifestCardinality) -> tuple[int, int]:
    if isinstance(cardinality, ExactlyOneCardinality):
        return (1, 1)
    if isinstance(cardinality, OneOrMoreCardinality):
        return (1, 10000)
    if isinstance(cardinality, ZeroOrMoreCardinality):
        return (0, 10000)
    return (cardinality.minimum, cardinality.maximum)


def _find_override(
    overrides: list[GovernedWeakeningOverride],
    *,
    as_of: datetime,
    profile_id: str,
    target_path: str,
    target_ref: str,
    reason: OverrideReason,
) -> GovernedWeakeningOverride:
    matches = [
        override
        for override in overrides
        if override.authorizes(
            as_of=as_of,
            profile_id=profile_id,
            target_path=target_path,
            target_ref=target_ref,
            reason=reason,
        )
    ]
    if len(matches) != 1:
        raise AthenaValidationError(
            f"weakening requires exactly one active governed override for {target_path}"
        )
    return matches[0]


def _validate_weakening(
    *,
    parent: ResolvedManifestProfile,
    child: ManifestProfile,
    roles: list[ManifestRole],
    constraints: list[ManifestConstraint],
    as_of: datetime,
) -> None:
    overrides = child.weakening_overrides
    if (
        parent.settings.continuity.zone_loss_continuity_required
        and not child.settings.continuity.zone_loss_continuity_required
    ):
        _find_override(
            overrides,
            as_of=as_of,
            profile_id=child.profile_id,
            target_path=(
                f"/resolvedProfiles/{child.profile_id}/settings/continuity/"
                "zoneLossContinuityRequired"
            ),
            target_ref="zoneLossContinuityRequired",
            reason="continuityRelaxation",
        )

    parent_roles = {_normalized_id(role.role_id): role for role in parent.roles}
    for role in roles:
        previous = parent_roles.get(_normalized_id(role.role_id))
        if previous is None:
            continue
        previous_min, previous_max = _cardinality_bounds(previous.cardinality)
        current_min, current_max = _cardinality_bounds(role.cardinality)
        if current_min < previous_min or current_max > previous_max:
            _find_override(
                overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=f"/resolvedProfiles/{child.profile_id}/roles/{role.role_id}/cardinality",
                target_ref=role.role_id,
                reason="cardinalityRelaxation",
            )

    parent_constraints = {
        _normalized_id(constraint.constraint_id): constraint for constraint in parent.constraints
    }
    for constraint in constraints:
        previous_constraint = parent_constraints.get(_normalized_id(constraint.constraint_id))
        if previous_constraint is None:
            continue
        if (
            previous_constraint.failure_verdict == "violation"
            and constraint.failure_verdict != "violation"
        ):
            _find_override(
                overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/failureVerdict"
                ),
                target_ref=constraint.constraint_id,
                reason="constraintRequirementRelaxation",
            )
        if previous_constraint.success_verdict != constraint.success_verdict:
            _find_override(
                overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/successVerdict"
                ),
                target_ref=constraint.constraint_id,
                reason="constraintRequirementRelaxation",
            )
        protected = (
            previous_constraint.protected
            or _normalized_id(previous_constraint.constraint_id) in _PROTECTED_REFS
        )
        if protected and not constraint.protected:
            raise AthenaValidationError(
                f"protected constraint cannot be unprotected: {constraint.constraint_id}"
            )
        if protected and (
            constraint.constraint_type != previous_constraint.constraint_type
            or constraint.finding_kind != previous_constraint.finding_kind
            or constraint.failure_verdict != previous_constraint.failure_verdict
            or constraint.success_verdict != previous_constraint.success_verdict
        ):
            raise AthenaValidationError(
                f"protected constraint semantics are invariant: {constraint.constraint_id}"
            )
        if protected:
            previous_proof = previous_constraint.proof_requirement
            current_proof = constraint.proof_requirement
            if isinstance(previous_proof, ZoneDistributionProof) and isinstance(
                current_proof, ZoneDistributionProof
            ):
                if previous_proof.role_ref != current_proof.role_ref:
                    raise AthenaValidationError(
                        f"protected constraint proof is invariant: {constraint.constraint_id}"
                    )
            elif previous_proof.model_dump(
                mode="json", by_alias=True, exclude_none=True
            ) != current_proof.model_dump(mode="json", by_alias=True, exclude_none=True):
                raise AthenaValidationError(
                    f"protected constraint proof is invariant: {constraint.constraint_id}"
                )
        if (
            isinstance(previous_constraint.proof_requirement, ZoneDistributionProof)
            and isinstance(constraint.proof_requirement, ZoneDistributionProof)
            and constraint.proof_requirement.minimum_distinct_zones
            < previous_constraint.proof_requirement.minimum_distinct_zones
        ):
            _find_override(
                overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/proofRequirement/minimumDistinctZones"
                ),
                target_ref=constraint.constraint_id,
                reason="zoneRequirementRelaxation",
            )


def _validate_role_requirement_weakening(
    inherited: list[ManifestRole],
    resolved: list[ManifestRole],
    *,
    child: ManifestProfile,
    as_of: datetime,
) -> None:
    inherited_by_id = {_normalized_id(item.role_id): item for item in inherited}
    for role in resolved:
        previous = inherited_by_id.get(_normalized_id(role.role_id))
        if previous is None:
            continue
        previous_min, previous_max = _cardinality_bounds(previous.cardinality)
        current_min, current_max = _cardinality_bounds(role.cardinality)
        if current_min < previous_min or current_max > previous_max:
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/roles/{role.role_id}/cardinality"
                ),
                target_ref=role.role_id,
                reason="cardinalityRelaxation",
            )


def _validate_protected_constraint_overrides(
    inherited: list[ManifestConstraint],
    resolved: list[ManifestConstraint],
    *,
    child: ManifestProfile,
    as_of: datetime,
) -> None:
    inherited_by_id = {_normalized_id(item.constraint_id): item for item in inherited}
    for constraint in resolved:
        previous = inherited_by_id.get(_normalized_id(constraint.constraint_id))
        if previous is None:
            continue
        if previous.finding_kind != constraint.finding_kind:
            raise AthenaValidationError(
                f"findingKind requires a new constraint id: {constraint.constraint_id}"
            )
        protected = previous.protected or _normalized_id(previous.constraint_id) in _PROTECTED_REFS
        if not protected:
            continue
        if (
            not constraint.protected
            or constraint.constraint_type != previous.constraint_type
            or constraint.finding_kind != previous.finding_kind
            or constraint.failure_verdict != previous.failure_verdict
            or constraint.success_verdict != previous.success_verdict
        ):
            raise AthenaValidationError(
                f"protected constraint semantics are invariant: {constraint.constraint_id}"
            )
        previous_proof = previous.proof_requirement
        current_proof = constraint.proof_requirement
        if isinstance(previous_proof, ZoneDistributionProof) and isinstance(
            current_proof, ZoneDistributionProof
        ):
            if previous_proof.role_ref != current_proof.role_ref:
                raise AthenaValidationError(
                    f"protected constraint proof is invariant: {constraint.constraint_id}"
                )
            if current_proof.minimum_distinct_zones < previous_proof.minimum_distinct_zones:
                _find_override(
                    child.weakening_overrides,
                    as_of=as_of,
                    profile_id=child.profile_id,
                    target_path=(
                        f"/resolvedProfiles/{child.profile_id}/constraints/"
                        f"{constraint.constraint_id}/proofRequirement/"
                        "minimumDistinctZones"
                    ),
                    target_ref=constraint.constraint_id,
                    reason="zoneRequirementRelaxation",
                )
        elif previous_proof.model_dump(
            mode="json", by_alias=True, exclude_none=True
        ) != current_proof.model_dump(mode="json", by_alias=True, exclude_none=True):
            raise AthenaValidationError(
                f"protected constraint proof is invariant: {constraint.constraint_id}"
            )


def _validate_constraint_requirement_weakening(
    inherited: list[ManifestConstraint],
    resolved: list[ManifestConstraint],
    *,
    child: ManifestProfile,
    as_of: datetime,
) -> None:
    inherited_by_id = {_normalized_id(item.constraint_id): item for item in inherited}
    for constraint in resolved:
        previous = inherited_by_id.get(_normalized_id(constraint.constraint_id))
        if previous is None:
            continue
        if previous.failure_verdict == "violation" and constraint.failure_verdict != "violation":
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/failureVerdict"
                ),
                target_ref=constraint.constraint_id,
                reason="constraintRequirementRelaxation",
            )
        if previous.success_verdict != constraint.success_verdict:
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/successVerdict"
                ),
                target_ref=constraint.constraint_id,
                reason="constraintRequirementRelaxation",
            )
        previous_proof = previous.proof_requirement
        current_proof = constraint.proof_requirement
        if isinstance(previous_proof, CardinalityProof) and isinstance(
            current_proof, CardinalityProof
        ):
            if previous_proof.role_ref != current_proof.role_ref:
                raise AthenaValidationError(
                    f"proof target requires a new constraint id: {constraint.constraint_id}"
                )
            if previous_proof.expected.cardinality_kind != current_proof.expected.cardinality_kind:
                raise AthenaValidationError(
                    f"illegal nested proof discriminator change: {constraint.constraint_id}"
                )
            previous_min, previous_max = _cardinality_bounds(previous_proof.expected)
            current_min, current_max = _cardinality_bounds(current_proof.expected)
            if current_min < previous_min or current_max > previous_max:
                _find_override(
                    child.weakening_overrides,
                    as_of=as_of,
                    profile_id=child.profile_id,
                    target_path=(
                        f"/resolvedProfiles/{child.profile_id}/constraints/"
                        f"{constraint.constraint_id}/proofRequirement/expected"
                    ),
                    target_ref=constraint.constraint_id,
                    reason="constraintRequirementRelaxation",
                )
        if isinstance(previous_proof, ZoneDistributionProof) and isinstance(
            current_proof, ZoneDistributionProof
        ):
            if previous_proof.role_ref != current_proof.role_ref:
                raise AthenaValidationError(
                    f"proof target requires a new constraint id: {constraint.constraint_id}"
                )
            if not (current_proof.minimum_distinct_zones < previous_proof.minimum_distinct_zones):
                continue
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/proofRequirement/"
                    "minimumDistinctZones"
                ),
                target_ref=constraint.constraint_id,
                reason="zoneRequirementRelaxation",
            )
        if (
            isinstance(previous_proof, EvidenceFreshnessProof)
            and isinstance(current_proof, EvidenceFreshnessProof)
            and current_proof.maximum_age_seconds > previous_proof.maximum_age_seconds
        ):
            _find_override(
                child.weakening_overrides,
                as_of=as_of,
                profile_id=child.profile_id,
                target_path=(
                    f"/resolvedProfiles/{child.profile_id}/constraints/"
                    f"{constraint.constraint_id}/proofRequirement/"
                    "maximumAgeSeconds"
                ),
                target_ref=constraint.constraint_id,
                reason="constraintRequirementRelaxation",
            )
        if isinstance(
            previous_proof,
            (
                ZoneColocationProof,
                RelationshipPresenceProof,
                ControlHealthProof,
                ObjectiveThresholdProof,
            ),
        ) and previous_proof.model_dump(
            mode="json", by_alias=True, exclude_none=True
        ) != current_proof.model_dump(mode="json", by_alias=True, exclude_none=True):
            raise AthenaValidationError(
                f"proof semantics require a new constraint id: {constraint.constraint_id}"
            )


def _apply_disabled_refs(
    *,
    profile: ManifestProfile,
    as_of: datetime,
    collections: dict[str, list[AthenaBaseModel]],
) -> None:
    key_attributes = {
        "role": "role_id",
        "relationship": "relationship_id",
        "constraint": "constraint_id",
        "control": "control_id",
        "riskAcceptance": "risk_acceptance_id",
        "objective": "objective_id",
        "owner": "owner_ref",
    }
    for disabled in profile.disabled_refs:
        if _normalized_id(disabled.target_ref) in _PROTECTED_REFS:
            raise AthenaValidationError("protected canonical proof refs cannot be disabled")
        override = next(
            (
                item
                for item in profile.weakening_overrides
                if _normalized_id(item.override_id)
                == _normalized_id(disabled.governance_override_ref)
            ),
            None,
        )
        target_path = (
            f"/resolvedProfiles/{profile.profile_id}/{disabled.target_kind}/{disabled.target_ref}"
        )
        if override is None or not override.authorizes(
            as_of=as_of,
            profile_id=profile.profile_id,
            target_path=target_path,
            target_ref=disabled.target_ref,
            reason=(
                "controlRequirementRelaxation"
                if disabled.target_kind == "control"
                else "disableInheritedItem"
            ),
        ):
            raise AthenaValidationError("disabled ref requires its exact active governed override")
        items = collections[disabled.target_kind]
        attribute = key_attributes[disabled.target_kind]
        before = len(items)
        collections[disabled.target_kind] = [
            item
            for item in items
            if _normalized_id(_item_key(item, attribute)) != _normalized_id(disabled.target_ref)
        ]
        if len(collections[disabled.target_kind]) == before:
            raise AthenaValidationError("disabled ref must resolve exactly once")


def _validate_override_owners(
    profile: ManifestProfile,
    *,
    roles: list[ManifestRole],
    relationships: list[ManifestRelationship],
    constraints: list[ManifestConstraint],
    controls: list[ManifestControl],
    risks: list[ManifestRiskAcceptance],
    objectives: list[ManifestObjective],
    owners: list[ManifestOwner],
) -> None:
    resolved_owners = {_normalized_id(item.owner_ref) for item in owners}

    for override in profile.weakening_overrides:
        if _normalized_id(override.owner_ref) not in resolved_owners:
            raise AthenaValidationError(
                f"unresolved governed override ownerRef: {override.owner_ref}"
            )
        target = _normalized_id(override.target_ref)
        path = override.target_path
        target_owners: list[str] = []
        if "/role/" in path or "/roles/" in path:
            target_owners = [
                item.owner_ref for item in roles if _normalized_id(item.role_id) == target
            ]
        elif "/constraint/" in path or "/constraints/" in path:
            target_owners = [
                item.owner_ref
                for item in constraints
                if _normalized_id(item.constraint_id) == target
            ]
        elif "/relationship/" in path or "/relationships/" in path:
            target_owners = [
                item.owner_ref
                for item in relationships
                if _normalized_id(_item_key(item, "relationship_id")) == target
            ]
        elif "/control/" in path or "/controls/" in path:
            target_owners = [
                item.owner_ref for item in controls if _normalized_id(item.control_id) == target
            ]
        elif "/riskAcceptance/" in path or "/riskAcceptances/" in path:
            target_owners = [
                item.owned_by for item in risks if _normalized_id(item.risk_acceptance_id) == target
            ]
        elif "/objective/" in path or "/objectives/" in path:
            target_owners = [
                item.owner_ref for item in objectives if _normalized_id(item.objective_id) == target
            ]
        continuity_path = (
            f"/resolvedProfiles/{profile.profile_id}/settings/continuity/"
            "zoneLossContinuityRequired"
        )
        if not target_owners and not (
            path == continuity_path
            and override.target_ref == "zoneLossContinuityRequired"
        ):
            raise AthenaValidationError(
                f"unresolved governed override targetRef: {override.target_ref}"
            )
        if len(target_owners) > 1:
            raise AthenaValidationError("governed override target is ambiguous")
        if target_owners and _normalized_id(target_owners[0]) != _normalized_id(override.owner_ref):
            raise AthenaValidationError(
                "governed override owner must match the governed target owner"
            )


def _validate_contradictory_requirements(profile: ResolvedManifestProfile) -> None:
    cardinality_bounds = {
        _normalized_id(role.role_id): _cardinality_bounds(role.cardinality)
        for role in profile.roles
    }
    relationship_requirements: dict[str, set[str]] = {}
    objective_bounds: dict[str, tuple[float | None, bool, float | None, bool]] = {}
    declared_relationships = {
        _normalized_id(item.relationship_id): item
        for item in profile.relationships
        if isinstance(item, DeclaredManifestRelationship)
    }

    for constraint in profile.constraints:
        proof = constraint.proof_requirement
        if isinstance(proof, CardinalityProof):
            role_id = _normalized_id(proof.role_ref)
            current_minimum, current_maximum = cardinality_bounds[role_id]
            required_minimum, required_maximum = _cardinality_bounds(proof.expected)
            intersection = (
                max(current_minimum, required_minimum),
                min(current_maximum, required_maximum),
            )
            if intersection[0] > intersection[1]:
                raise AthenaValidationError(
                    f"contradictory cardinality requirements for role {proof.role_ref}"
                )
            cardinality_bounds[role_id] = intersection
        elif isinstance(proof, RelationshipPresenceProof):
            relationship_id = _normalized_id(proof.declared_relationship_ref)
            relationship_requirements.setdefault(relationship_id, set()).add(
                constraint.constraint_type
            )
            referenced_relationship = declared_relationships[relationship_id]
            if (
                constraint.constraint_type == "dependencyRequired"
                and referenced_relationship.kind == "prohibited"
            ) or (
                constraint.constraint_type == "dependencyProhibited"
                and referenced_relationship.kind != "prohibited"
            ):
                raise AthenaValidationError(
                    "relationship kind contradicts its presence requirement"
                )
        elif isinstance(proof, ObjectiveThresholdProof):
            objective_id = _normalized_id(proof.objective_ref)
            lower, lower_inclusive, upper, upper_inclusive = objective_bounds.get(
                objective_id,
                (None, True, None, True),
            )
            if proof.comparison in {"gt", "gte", "eq"} and (
                lower is None or proof.threshold > lower
            ):
                lower = proof.threshold
                lower_inclusive = proof.comparison in {"gte", "eq"}
            elif proof.comparison in {"gt", "gte", "eq"} and proof.threshold == lower:
                lower_inclusive = lower_inclusive and proof.comparison in {"gte", "eq"}
            if proof.comparison in {"lt", "lte", "eq"} and (
                upper is None or proof.threshold < upper
            ):
                upper = proof.threshold
                upper_inclusive = proof.comparison in {"lte", "eq"}
            elif proof.comparison in {"lt", "lte", "eq"} and proof.threshold == upper:
                upper_inclusive = upper_inclusive and proof.comparison in {"lte", "eq"}
            if lower is not None and upper is not None and (
                lower > upper
                or (lower == upper and not (lower_inclusive and upper_inclusive))
            ):
                raise AthenaValidationError(
                    f"contradictory objective requirements for {proof.objective_ref}"
                )
            objective_bounds[objective_id] = (
                lower,
                lower_inclusive,
                upper,
                upper_inclusive,
            )

    if any(
        {"dependencyRequired", "dependencyProhibited"}.issubset(requirements)
        for requirements in relationship_requirements.values()
    ):
        raise AthenaValidationError(
            "contradictory required and prohibited relationship requirements"
        )

    positive_edges: set[tuple[str, str]] = set()
    prohibited_edges: set[tuple[str, str]] = set()

    def endpoint_key(endpoint: ManifestEndpoint) -> str:
        if isinstance(endpoint, RoleEndpoint):
            return "role:" + _normalized_id(endpoint.role_ref)
        return "external:" + _normalized_id(endpoint.external_ref)

    for declared_relationship in profile.relationships:
        if not isinstance(declared_relationship, DeclaredManifestRelationship):
            continue
        edge = (
            endpoint_key(declared_relationship.source),
            endpoint_key(declared_relationship.target),
        )
        if declared_relationship.kind == "prohibited":
            prohibited_edges.add(edge)
        else:
            positive_edges.add(edge)
    if positive_edges & prohibited_edges:
        raise AthenaValidationError(
            "contradictory declared and prohibited relationship requirements"
        )


def _resolve_cross_references(profile: ResolvedManifestProfile, *, as_of: datetime) -> None:
    _validate_resolved_selectors(profile.roles)
    owners = {_normalized_id(item.owner_ref) for item in profile.ownership}
    roles = {_normalized_id(item.role_id) for item in profile.roles}
    relationships = {
        _normalized_id(item.relationship_id)
        for item in profile.relationships
        if isinstance(item, DeclaredManifestRelationship)
    }
    constraints = {_normalized_id(item.constraint_id) for item in profile.constraints}
    controls = {_normalized_id(item.control_id) for item in profile.controls}
    risks = {_normalized_id(item.risk_acceptance_id) for item in profile.risk_acceptances}
    objectives = {_normalized_id(item.objective_id) for item in profile.objectives}
    clause_paths = {
        f"/constraints/{item.constraint_id}" for item in profile.constraints
    }

    def require_owner(owner_ref: str) -> None:
        if _normalized_id(owner_ref) not in owners:
            raise AthenaValidationError(f"unresolved ownerRef: {owner_ref}")

    for role in profile.roles:
        require_owner(role.owner_ref)
    for relationship in profile.relationships:
        require_owner(relationship.owner_ref)
        if isinstance(relationship, DeclaredManifestRelationship):
            if _normalized_id(profile.profile_id) not in {
                _normalized_id(item) for item in relationship.profiles
            }:
                raise AthenaValidationError("declared relationship profile applicability mismatch")
            for endpoint in (relationship.source, relationship.target):
                if (
                    isinstance(endpoint, RoleEndpoint)
                    and _normalized_id(endpoint.role_ref) not in roles
                ):
                    raise AthenaValidationError(
                        f"unresolved relationship roleRef: {endpoint.role_ref}"
                    )
            if relationship.source_clause not in clause_paths:
                raise AthenaValidationError(
                    f"unresolved relationship sourceClause: {relationship.source_clause}"
                )
        else:
            if relationship.expires_at <= as_of:
                raise AthenaValidationError("exception relationship is expired")
            if (
                relationship.applies_to_relationship_ref is not None
                and _normalized_id(relationship.applies_to_relationship_ref) not in relationships
            ):
                raise AthenaValidationError("exception relationship target is unresolved")
            if (
                relationship.applies_to_clause_ref is not None
                and _normalized_id(relationship.applies_to_clause_ref) not in constraints
            ):
                raise AthenaValidationError("exception clause target is unresolved")
            scope = relationship.governance_scope
            expected_clause_path: str
            if relationship.applies_to_clause_ref is not None:
                expected_clause_path = f"/constraints/{relationship.applies_to_clause_ref}"
            else:
                target_relationship = next(
                    item
                    for item in profile.relationships
                    if isinstance(item, DeclaredManifestRelationship)
                    and _normalized_id(item.relationship_id)
                    == _normalized_id(relationship.applies_to_relationship_ref or "")
                )
                expected_clause_path = target_relationship.source_clause
            if (
                scope.manifest_id != profile.manifest_id
                or _normalized_id(scope.profile_id) != _normalized_id(profile.profile_id)
                or scope.clause_path != expected_clause_path
                or scope.owner_ref != relationship.owner_ref
            ):
                raise AthenaValidationError(
                    "exception governance scope does not match its exact target"
                )
            acceptance = next(
                (
                    item
                    for item in profile.risk_acceptances
                    if _normalized_id(item.risk_acceptance_id)
                    == _normalized_id(relationship.risk_acceptance_ref)
                ),
                None,
            )
            if acceptance is None or not acceptance.is_active(
                as_of=as_of,
                manifest_id=profile.manifest_id,
                profile_id=profile.profile_id,
                clause_path=relationship.governance_scope.clause_path,
                owner_ref=relationship.owner_ref,
            ):
                raise AthenaValidationError(
                    "exception requires a matching active scoped risk acceptance"
                )

    for constraint in profile.constraints:
        require_owner(constraint.owner_ref)
        if _normalized_id(constraint.constraint_id) in _PROTECTED_REFS and not constraint.protected:
            raise AthenaValidationError(
                f"canonical protected constraint must remain protected: {constraint.constraint_id}"
            )
        proof = constraint.proof_requirement
        for role_ref in (
            getattr(proof, "role_ref", None),
            getattr(proof, "subject_role_ref", None),
            getattr(proof, "anchor_role_ref", None),
        ):
            if role_ref is not None and _normalized_id(role_ref) not in roles:
                raise AthenaValidationError(f"unresolved constraint roleRef: {role_ref}")
        relationship_ref = getattr(proof, "declared_relationship_ref", None)
        if relationship_ref is not None and _normalized_id(relationship_ref) not in relationships:
            raise AthenaValidationError("unresolved declared relationship proof ref")
        control_ref = getattr(proof, "control_ref", None)
        if control_ref is not None and _normalized_id(control_ref) not in controls:
            raise AthenaValidationError("unresolved control proof ref")
        objective_ref = getattr(proof, "objective_ref", None)
        if objective_ref is not None and _normalized_id(objective_ref) not in objectives:
            raise AthenaValidationError("unresolved objective proof ref")
        if (
            constraint.risk_acceptance_ref is not None
            and _normalized_id(constraint.risk_acceptance_ref) not in risks
        ):
            raise AthenaValidationError("unresolved constraint riskAcceptanceRef")
        if (
            constraint.risk_acceptance_clause_ref is not None
            and _normalized_id(constraint.risk_acceptance_clause_ref) not in constraints
        ):
            raise AthenaValidationError("unresolved riskAcceptanceClauseRef")
        if constraint.risk_acceptance_ref is not None:
            acceptance = next(
                item
                for item in profile.risk_acceptances
                if _normalized_id(item.risk_acceptance_id)
                == _normalized_id(constraint.risk_acceptance_ref)
            )
            acceptance_clause = constraint.risk_acceptance_clause_ref or constraint.constraint_id
            acceptance_scope = acceptance.governance_scope
            if (
                acceptance_scope.manifest_id != profile.manifest_id
                or _normalized_id(acceptance_scope.profile_id) != _normalized_id(profile.profile_id)
                or acceptance_scope.clause_path != f"/constraints/{acceptance_clause}"
                or acceptance_scope.owner_ref != constraint.owner_ref
                or acceptance.owned_by != constraint.owner_ref
            ):
                raise AthenaValidationError(
                    "risk acceptance scope mismatch for referenced constraint"
                )
        expected_path = f"/constraints/{constraint.constraint_id}"
        if (
            _normalized_id(profile.profile_id)
            not in {_normalized_id(item) for item in constraint.profiles}
            or constraint.governance_scope.manifest_id != profile.manifest_id
            or _normalized_id(constraint.governance_scope.profile_id)
            != _normalized_id(profile.profile_id)
            or constraint.governance_scope.clause_path != expected_path
            or constraint.governance_scope.owner_ref != constraint.owner_ref
        ):
            raise AthenaValidationError("constraint governance scope does not exactly match clause")

    for control in profile.controls:
        require_owner(control.owner_ref)
        scope = control.governance_scope
        if (
            _normalized_id(profile.profile_id)
            not in {_normalized_id(item) for item in control.profiles}
            or scope.manifest_id != profile.manifest_id
            or _normalized_id(scope.profile_id) != _normalized_id(profile.profile_id)
            or scope.clause_path
            not in {f"/constraints/{item.constraint_id}" for item in profile.constraints}
            or scope.owner_ref != control.owner_ref
        ):
            raise AthenaValidationError(
                "control manifest, profile, clause, or owner scope mismatch"
            )
    for risk in profile.risk_acceptances:
        require_owner(risk.owned_by)
        for binding in risk.accepted_resource_bindings:
            if _normalized_id(binding.role_ref) not in roles:
                raise AthenaValidationError("risk acceptance resource binding role is unresolved")
        for control_ref in risk.linked_control_refs:
            if _normalized_id(control_ref) not in controls:
                raise AthenaValidationError("unresolved linked control ref")
        scope = risk.governance_scope
        if (
            scope.manifest_id != profile.manifest_id
            or _normalized_id(scope.profile_id) != _normalized_id(profile.profile_id)
            or scope.clause_path
            not in {f"/constraints/{item.constraint_id}" for item in profile.constraints}
            or scope.owner_ref != risk.owned_by
        ):
            raise AthenaValidationError(
                "risk acceptance manifest, profile, clause, or owner scope mismatch"
            )
    for objective in profile.objectives:
        require_owner(objective.owner_ref)
    _validate_contradictory_requirements(profile)


def resolve_manifest_profile(
    manifest: CanonicalWorkloadManifest,
    profile_id: str,
    *,
    as_of: datetime,
    _validate_complete_graph: bool = True,
) -> ResolvedManifestProfile:
    if (
        manifest.compatibility.artifact_digest != manifest.compute_artifact_digest_value()
        or manifest.compatibility.semantic_digest != manifest.compute_semantic_digest_value()
    ):
        raise AthenaValidationError("manifest changed after digest validation")
    if _validate_complete_graph:
        resolved_profiles = {
            _normalized_id(candidate.profile_id): resolve_manifest_profile(
                manifest,
                candidate.profile_id,
                as_of=as_of,
                _validate_complete_graph=False,
            )
            for candidate in manifest.profiles.values()
        }
        requested_id = _normalized_id(profile_id)
        if requested_id not in resolved_profiles:
            raise AthenaValidationError(f"missing profile: {profile_id}")
        return resolved_profiles[requested_id]
    normalized_profiles = {
        _normalized_id(key): profile for key, profile in manifest.profiles.items()
    }
    requested = _normalized_id(profile_id)
    if requested not in normalized_profiles:
        raise AthenaValidationError(f"missing profile: {profile_id}")

    lineage: list[ManifestProfile] = []
    visiting: set[str] = set()
    current = normalized_profiles[requested]
    while True:
        current_id = _normalized_id(current.profile_id)
        if current_id in visiting:
            raise AthenaValidationError("profile inheritance cycle detected")
        visiting.add(current_id)
        lineage.append(current)
        if current.extends is None:
            break
        parent = normalized_profiles.get(_normalized_id(current.extends))
        if parent is None:
            raise AthenaValidationError(f"missing parent profile: {current.extends}")
        current = parent
    lineage.reverse()

    roles = list(manifest.roles)
    relationships = list(manifest.relationships)
    constraints = list(manifest.constraints)
    controls = list(manifest.controls)
    risks = list(manifest.risk_acceptances)
    objectives = list(manifest.objectives)
    owners = list(manifest.ownership)
    settings = lineage[0].settings
    parent_resolved: ResolvedManifestProfile | None = None

    for profile in lineage:
        inherited_roles = list(roles)
        inherited_relationships = list(relationships)
        inherited_constraints = list(constraints)
        inherited_controls = list(controls)
        inherited_risks = list(risks)
        roles = _merge_keyed(roles, list(profile.roles), key_attribute="role_id")
        _validate_role_requirement_weakening(
            inherited_roles,
            roles,
            child=profile,
            as_of=as_of,
        )
        relationships = _merge_keyed(
            relationships, list(profile.relationships), key_attribute="relationship_id"
        )
        constraints = _merge_keyed(
            constraints, list(profile.constraints), key_attribute="constraint_id"
        )
        _validate_protected_constraint_overrides(
            inherited_constraints,
            constraints,
            child=profile,
            as_of=as_of,
        )
        _validate_constraint_requirement_weakening(
            inherited_constraints,
            constraints,
            child=profile,
            as_of=as_of,
        )
        controls = _merge_keyed(controls, list(profile.controls), key_attribute="control_id")
        risks = _merge_keyed(
            risks, list(profile.risk_acceptances), key_attribute="risk_acceptance_id"
        )
        objectives = _merge_keyed(
            objectives, list(profile.objectives), key_attribute="objective_id"
        )
        owners = _merge_keyed(owners, list(profile.ownership), key_attribute="owner_ref")
        _validate_inherited_semantics(
            child=profile,
            inherited_roles=inherited_roles,
            roles=roles,
            inherited_relationships=inherited_relationships,
            relationships=relationships,
            inherited_constraints=inherited_constraints,
            constraints=constraints,
            inherited_controls=inherited_controls,
            controls=controls,
            inherited_risks=inherited_risks,
            risks=risks,
            as_of=as_of,
        )
        _validate_override_owners(
            profile,
            roles=roles,
            relationships=relationships,
            constraints=constraints,
            controls=controls,
            risks=risks,
            objectives=objectives,
            owners=owners,
        )
        if parent_resolved is not None:
            _validate_weakening(
                parent=parent_resolved,
                child=profile,
                roles=roles,
                constraints=constraints,
                as_of=as_of,
            )
        settings = profile.settings
        collections: dict[str, list[AthenaBaseModel]] = {
            "role": list(roles),
            "relationship": list(relationships),
            "constraint": list(constraints),
            "control": list(controls),
            "riskAcceptance": list(risks),
            "objective": list(objectives),
            "owner": list(owners),
        }
        _apply_disabled_refs(profile=profile, as_of=as_of, collections=collections)
        roles = [item for item in collections["role"] if isinstance(item, ManifestRole)]
        relationships = [
            item
            for item in collections["relationship"]
            if isinstance(item, (DeclaredManifestRelationship, ExceptionManifestRelationship))
        ]
        constraints = [
            item for item in collections["constraint"] if isinstance(item, ManifestConstraint)
        ]
        controls = [
            item
            for item in collections["control"]
            if isinstance(
                item,
                (
                    BackupControl,
                    RestoreTestControl,
                    ManualFailoverRunbookControl,
                    MonitoringAlertControl,
                    CapacityReviewControl,
                    AccessReviewControl,
                    ChangeApprovalControl,
                    VendorSupportControl,
                ),
            )
        ]
        risks = [
            item
            for item in collections["riskAcceptance"]
            if isinstance(item, ManifestRiskAcceptance)
        ]
        objectives = [
            item for item in collections["objective"] if isinstance(item, ManifestObjective)
        ]
        owners = [item for item in collections["owner"] if isinstance(item, ManifestOwner)]
        resolved_relationships = [
            item
            for item in relationships
            if (
                isinstance(item, DeclaredManifestRelationship)
                and _normalized_id(profile.profile_id)
                in {_normalized_id(value) for value in item.profiles}
            )
            or (
                isinstance(item, ExceptionManifestRelationship)
                and _normalized_id(item.governance_scope.profile_id)
                == _normalized_id(profile.profile_id)
            )
        ]
        resolved_constraints = [
            item
            for item in constraints
            if _normalized_id(profile.profile_id)
            in {_normalized_id(value) for value in item.profiles}
        ]
        resolved_controls = [
            item
            for item in controls
            if _normalized_id(profile.profile_id)
            in {_normalized_id(value) for value in item.profiles}
        ]
        resolved_risks = [
            item
            for item in risks
            if _normalized_id(profile.profile_id)
            in {_normalized_id(value) for value in item.profiles}
        ]

        resolved_compatibility = manifest.compatibility.model_dump(
            mode="json", by_alias=True, exclude_none=True
        )
        resolved_compatibility["artifactKind"] = "resolvedProfile"
        resolved_compatibility["artifactDigest"] = None
        resolved_compatibility["semanticDigest"] = None
        payload = {
            "manifestId": manifest.manifest_id,
            "manifestVersion": manifest.manifest_version,
            "profileId": profile.profile_id,
            "profileType": profile.profile_type,
            "allowedEvidenceScopes": manifest.workload.allowed_evidence_scopes,
            "compatibility": resolved_compatibility,
            "inheritanceChain": [item.profile_id for item in lineage[: lineage.index(profile) + 1]],
            "settings": settings,
            "roles": roles,
            "relationships": resolved_relationships,
            "constraints": resolved_constraints,
            "controls": resolved_controls,
            "riskAcceptances": resolved_risks,
            "objectives": objectives,
            "ownership": owners,
        }
        digest_payload: dict[str, object] = {}
        for key, value in payload.items():
            if isinstance(value, BaseAthenaModel):
                digest_payload[key] = value.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
            elif isinstance(value, list):
                digest_payload[key] = [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    if isinstance(item, BaseAthenaModel)
                    else item
                    for item in value
                ]
            else:
                digest_payload[key] = value
        _sort_manifest_keyed_collections(digest_payload)
        artifact_payload = deepcopy(digest_payload)
        artifact_compatibility = artifact_payload["compatibility"]
        if not isinstance(artifact_compatibility, dict):
            raise AthenaValidationError("resolved compatibility preimage is invalid")
        artifact_compatibility.pop("artifactDigest", None)
        artifact_compatibility.pop("semanticDigest", None)
        semantic_payload = deepcopy(artifact_payload)
        semantic_compatibility = semantic_payload["compatibility"]
        if not isinstance(semantic_compatibility, dict):
            raise AthenaValidationError("resolved semantic preimage is invalid")
        semantic_compatibility.pop("schemaVersion", None)
        artifact_digest = compute_artifact_digest(artifact_payload)
        semantic_digest = compute_artifact_digest(semantic_payload)
        resolved_compatibility["artifactDigest"] = artifact_digest
        resolved_compatibility["semanticDigest"] = semantic_digest
        parent_resolved = ResolvedManifestProfile.model_validate(
            {**payload, "resolvedProfileDigest": semantic_digest}
        )

    if parent_resolved is None:
        raise AthenaValidationError("profile resolution produced no profile")
    _resolve_cross_references(parent_resolved, as_of=as_of)
    return parent_resolved


class ResourceProofFact(AthenaBaseModel):
    resource_id: str = Field(..., alias="resourceId", min_length=1, max_length=2048)
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)
    availability_zone: Literal["1", "2", "3", "unknown"] = Field(..., alias="availabilityZone")
    state: EvidenceState
    proof_source: ProofSource = Field(..., alias="proofSource")
    evidence_ref: EvidenceReference = Field(..., alias="evidenceRef")

    @model_validator(mode="after")
    def validate_reference_kind(self) -> ResourceProofFact:
        if self.state == "complete" and not isinstance(self.evidence_ref, EvidenceItemRef):
            raise AthenaValidationError("complete proof facts require EvidenceItemRef")
        if self.state in {"missing", "gap", "stale"} and not isinstance(
            self.evidence_ref, EvidenceGapRef
        ):
            raise AthenaValidationError("incomplete proof facts require EvidenceGapRef")
        return self


class RelationshipProofFact(AthenaBaseModel):
    relationship_ref: str = Field(..., alias="relationshipRef", min_length=1, max_length=128)
    state: EvidenceState
    proof_source: ProofSource = Field(..., alias="proofSource")
    presence: Literal["present", "absent"]
    evidence_ref: EvidenceReference = Field(..., alias="evidenceRef")

    @model_validator(mode="after")
    def validate_reference_kind(self) -> RelationshipProofFact:
        if self.state == "complete" and not isinstance(self.evidence_ref, EvidenceItemRef):
            raise AthenaValidationError("complete proof facts require EvidenceItemRef")
        if self.state in {"missing", "gap", "stale"} and not isinstance(
            self.evidence_ref, EvidenceGapRef
        ):
            raise AthenaValidationError("incomplete proof facts require EvidenceGapRef")
        return self


class ControlProofFact(AthenaBaseModel):
    control_ref: str = Field(..., alias="controlRef", min_length=1, max_length=128)
    state: EvidenceState
    health: Literal["effective", "degraded", "missing", "unknown", "expired"]
    evidence_ref: EvidenceReference = Field(..., alias="evidenceRef")

    @model_validator(mode="after")
    def validate_reference_kind(self) -> ControlProofFact:
        if self.state == "complete" and not isinstance(self.evidence_ref, EvidenceItemRef):
            raise AthenaValidationError("complete proof facts require EvidenceItemRef")
        if self.state in {"missing", "gap", "stale"} and not isinstance(
            self.evidence_ref, EvidenceGapRef
        ):
            raise AthenaValidationError("incomplete proof facts require EvidenceGapRef")
        return self


class ObjectiveProofFact(AthenaBaseModel):
    objective_ref: str = Field(..., alias="objectiveRef", min_length=1, max_length=128)
    state: EvidenceState
    current_value: float = Field(..., alias="currentValue")
    evidence_ref: EvidenceReference = Field(..., alias="evidenceRef")

    @model_validator(mode="after")
    def validate_reference_kind(self) -> ObjectiveProofFact:
        if self.state == "complete" and not isinstance(self.evidence_ref, EvidenceItemRef):
            raise AthenaValidationError("complete proof facts require EvidenceItemRef")
        if self.state in {"missing", "gap", "stale"} and not isinstance(
            self.evidence_ref, EvidenceGapRef
        ):
            raise AthenaValidationError("incomplete proof facts require EvidenceGapRef")
        return self


class RoleBindingProof(AthenaBaseModel):
    role_ref: str = Field(..., alias="roleRef", min_length=1, max_length=128)
    selected_resource_ids: list[str] = Field(..., alias="selectedResourceIds", max_length=1000)
    selector_result_digest: str = Field(
        ..., alias="selectorResultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    state: EvidenceState

    @model_validator(mode="after")
    def validate_selected_ids(self) -> RoleBindingProof:
        normalized = [_normalized_id(item) for item in self.selected_resource_ids]
        if len(normalized) != len(set(normalized)):
            raise AthenaValidationError("role binding selectedResourceIds must be unique")
        return self


class EvidenceReferenceContext(AthenaBaseModel):
    snapshot_id: str = Field(..., alias="snapshotId", min_length=1, max_length=128)
    snapshot_artifact_digest: str = Field(
        ..., alias="snapshotArtifactDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    snapshot_semantic_digest: str = Field(
        ..., alias="snapshotSemanticDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    collected_at: UtcDateTime = Field(..., alias="collectedAt")
    expires_at: UtcDateTime = Field(..., alias="expiresAt")
    authorized_scopes: list[EvidenceScope] = Field(
        ..., alias="authorizedScopes", min_length=1, max_length=100
    )
    manifest_id: str = Field(..., alias="manifestId", min_length=1, max_length=128)
    profile_id: str = Field(..., alias="profileId", min_length=1, max_length=128)
    resolved_profile_digest: str = Field(
        ..., alias="resolvedProfileDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    resources: list[ResourceProofFact] = Field(default_factory=list, max_length=30000)
    relationships: list[RelationshipProofFact] = Field(default_factory=list, max_length=1000)
    controls: list[ControlProofFact] = Field(default_factory=list, max_length=500)
    objectives: list[ObjectiveProofFact] = Field(default_factory=list, max_length=1000)
    role_bindings: list[RoleBindingProof] = Field(
        ..., alias="roleBindings", min_length=1, max_length=200
    )

    @model_validator(mode="after")
    def validate_provenance_binding(self) -> EvidenceReferenceContext:
        if self.expires_at <= self.collected_at:
            raise AthenaValidationError("evidence context expiresAt must be after collectedAt")
        for values, attribute, label in (
            (self.resources, "resource_id", "resource fact"),
            (self.relationships, "relationship_ref", "relationship fact"),
            (self.controls, "control_ref", "control fact"),
            (self.objectives, "objective_ref", "objective fact"),
            (self.role_bindings, "role_ref", "role binding"),
        ):
            normalized = [_normalized_id(str(getattr(item, attribute))) for item in values]
            if len(normalized) != len(set(normalized)):
                raise AthenaValidationError(
                    f"duplicate or conflicting normalized {label} reference"
                )

        def validate_reference(reference: EvidenceReference) -> None:
            if (
                reference.snapshot_id != self.snapshot_id
                or reference.snapshot_artifact_digest != self.snapshot_artifact_digest
                or reference.snapshot_semantic_digest != self.snapshot_semantic_digest
                or not (self.collected_at <= reference.collector_attempt_at < self.expires_at)
            ):
                raise AthenaValidationError(
                    "evidence fact is not bound to the trusted snapshot context"
                )

        for resource in self.resources:
            validate_reference(resource.evidence_ref)
        for relationship in self.relationships:
            validate_reference(relationship.evidence_ref)
        for control in self.controls:
            validate_reference(control.evidence_ref)
        for objective in self.objectives:
            validate_reference(objective.evidence_ref)
        return self


class ManifestFinding(AthenaBaseModel):
    clause_id: str = Field(..., alias="clauseId", min_length=1, max_length=128)
    finding_kind: ManifestFindingKind = Field(..., alias="findingKind")
    verdict: FindingVerdict
    manifest_id: str = Field(..., alias="manifestId")
    manifest_version: str = Field(..., alias="manifestVersion")
    profile_id: str = Field(..., alias="profileId")
    resolved_profile_digest: str = Field(..., alias="resolvedProfileDigest")
    governance_scope: ClauseScope = Field(..., alias="governanceScope")
    evidence_refs: list[EvidenceReference] = Field(
        ..., alias="evidenceRefs", min_length=1, max_length=1000
    )
    risk_acceptance_ref: str | None = Field(default=None, alias="riskAcceptanceRef")


type ProofFact = ResourceProofFact | RelationshipProofFact | ControlProofFact | ObjectiveProofFact
type ProofFactValidator = Callable[[ProofFact, EvidenceRecord], bool]


def verified_snapshot_context_verifier(
    snapshot: EvidenceSnapshot,
    *,
    as_of: datetime,
    expected_artifact_digest: str,
    publication_resolver: SnapshotPublicationResolver,
    identity_evidence: Iterable[CollectorIdentityEvidence] | None = None,
    identity_resolver: Callable[[str], CollectorIdentityEvidence] | None = None,
    key_resolver: TrustedKeyResolver | None = None,
    trusted_key_anchor: TrustedKeyAnchor | None = None,
    envelope_resolver: EvidenceEnvelopeResolver | None = None,
    fact_validator: ProofFactValidator,
    role_binding_validator: RoleBindingValidator,
) -> EvidenceContextVerifier:
    verified_snapshot = snapshot.validate_for_evaluation(
        as_of=as_of,
        expected_artifact_digest=expected_artifact_digest,
        publication_resolver=publication_resolver,
        identity_evidence=identity_evidence,
        identity_resolver=identity_resolver,
        key_resolver=key_resolver,
        trusted_key_anchor=trusted_key_anchor,
        envelope_resolver=envelope_resolver,
    )
    allowed_references = {
        reference.canonical_json() for reference in verified_snapshot.evidence_refs
    }
    records_by_digest: dict[str, list[EvidenceRecord]] = {}
    for record in verified_snapshot.evidence_records:
        records_by_digest.setdefault(record.item_digest, []).append(record)

    def verify(context: EvidenceReferenceContext, evaluation_as_of: datetime) -> None:
        if evaluation_as_of != as_of:
            raise AthenaValidationError(
                "evidence context verifier is bound to a different trusted as_of"
            )
        if (
            context.snapshot_id != verified_snapshot.snapshot_id
            or context.snapshot_artifact_digest != verified_snapshot.compatibility.artifact_digest
            or context.snapshot_semantic_digest != verified_snapshot.compatibility.semantic_digest
            or context.collected_at != verified_snapshot.collected_at
            or context.expires_at != verified_snapshot.expires_at
            or {scope.canonical_json() for scope in context.authorized_scopes}
            != {scope.canonical_json() for scope in verified_snapshot.authorized_scopes}
        ):
            raise AthenaValidationError(
                "evidence context does not match the cryptographically verified snapshot"
            )
        facts: list[ProofFact] = [
            *context.resources,
            *context.relationships,
            *context.controls,
            *context.objectives,
        ]
        used_references: set[str] = set()
        for fact in facts:
            reference = fact.evidence_ref
            canonical_reference = reference.canonical_json()
            if canonical_reference not in allowed_references:
                raise AthenaValidationError(
                    "evidence context reference does not resolve in verified snapshot"
                )
            if canonical_reference in used_references:
                raise AthenaValidationError(
                    "one verified evidence reference cannot authenticate multiple proof facts"
                )
            used_references.add(canonical_reference)
            record_digest = (
                reference.item_digest
                if isinstance(reference, EvidenceItemRef)
                else reference.gap_record_digest
            )
            records = records_by_digest.get(record_digest, [])
            if len(records) != 1:
                raise AthenaValidationError(
                    "evidence reference must resolve to exactly one snapshot record"
                )
            record = records[0]
            if (
                isinstance(fact, ResourceProofFact)
                and isinstance(reference, EvidenceItemRef)
                and (
                    not isinstance(record, ResourceEvidenceRecord)
                    or record.resource_id != fact.resource_id
                    or record.availability_zone != fact.availability_zone
                )
            ):
                raise AthenaValidationError(
                    "resource proof fact does not match its verified snapshot record"
                )
            if (
                isinstance(fact, RelationshipProofFact)
                and isinstance(reference, EvidenceItemRef)
                and fact.presence == "present"
                and not isinstance(record, ObservedRelationshipEvidenceRecord)
            ):
                raise AthenaValidationError(
                    "relationship proof fact requires observed relationship evidence"
                )
            if isinstance(reference, EvidenceGapRef) and not isinstance(record, EvidenceGapRecord):
                raise AthenaValidationError("gap proof fact does not match an evidence gap record")
            if not fact_validator(fact, record):
                raise AthenaValidationError(
                    "trusted proof-fact binding validator rejected snapshot record"
                )
        for binding in context.role_bindings:
            if not role_binding_validator(binding, verified_snapshot):
                raise AthenaValidationError(
                    "trusted role-binding validator rejected selector result"
                )

    return verify


def _evidence_gate(
    resources: list[ResourceProofFact],
    *,
    missing_verdict: FailureVerdict,
) -> FindingVerdict | None:
    if not resources:
        return "unknown"
    if any(item.state == "conflicting" for item in resources):
        return "conflicting"
    if any(item.state != "complete" for item in resources):
        return "unknown"
    if any(item.proof_source == "inferred" for item in resources):
        return "unknown"
    return None


def _matching_acceptance(
    profile: ResolvedManifestProfile,
    constraint: ManifestConstraint,
    evidence: EvidenceReferenceContext,
    *,
    as_of: datetime,
) -> ManifestRiskAcceptance | None:
    acceptance_refs: set[str] = set()
    if constraint.risk_acceptance_ref is not None:
        acceptance_refs.add(_normalized_id(constraint.risk_acceptance_ref))
    proof = constraint.proof_requirement
    for relationship in profile.relationships:
        if not isinstance(relationship, ExceptionManifestRelationship):
            continue
        if relationship.expires_at <= as_of:
            continue
        applies_to_constraint = relationship.applies_to_clause_ref is not None and _normalized_id(
            relationship.applies_to_clause_ref
        ) == _normalized_id(constraint.constraint_id)
        applies_to_relationship = (
            isinstance(proof, RelationshipPresenceProof)
            and relationship.applies_to_relationship_ref is not None
            and _normalized_id(relationship.applies_to_relationship_ref)
            == _normalized_id(proof.declared_relationship_ref)
        )
        if applies_to_constraint or applies_to_relationship:
            acceptance_refs.add(_normalized_id(relationship.risk_acceptance_ref))
    if not acceptance_refs:
        return None
    acceptance_clause_id = (
        constraint.risk_acceptance_clause_ref
        if constraint.finding_kind == "riskAcceptance"
        and constraint.risk_acceptance_clause_ref is not None
        else constraint.constraint_id
    )
    proof_role_refs: set[str] = set()
    if isinstance(proof, (CardinalityProof, ZoneDistributionProof)):
        proof_role_refs.add(_normalized_id(proof.role_ref))
    elif isinstance(proof, ZoneColocationProof):
        proof_role_refs.update(
            {
                _normalized_id(proof.subject_role_ref),
                _normalized_id(proof.anchor_role_ref),
            }
        )
    elif isinstance(proof, RelationshipPresenceProof):
        declared_relationship = next(
            (
                item
                for item in profile.relationships
                if isinstance(item, DeclaredManifestRelationship)
                and _normalized_id(item.relationship_id)
                == _normalized_id(proof.declared_relationship_ref)
            ),
            None,
        )
        if declared_relationship is None:
            return None
        for endpoint in (
            declared_relationship.source,
            declared_relationship.target,
        ):
            if isinstance(endpoint, RoleEndpoint):
                proof_role_refs.add(_normalized_id(endpoint.role_ref))
        if not proof_role_refs:
            return None
    bindings_by_role = {
        role_ref: [
            binding
            for binding in evidence.role_bindings
            if _normalized_id(binding.role_ref) == role_ref
        ]
        for role_ref in proof_role_refs
    }
    if any(
        len(bindings) != 1 or bindings[0].state != "complete"
        for bindings in bindings_by_role.values()
    ):
        return None
    if isinstance(proof, RelationshipPresenceProof) and any(
        not bindings[0].selected_resource_ids
        for bindings in bindings_by_role.values()
    ):
        return None
    required_bindings = {
        (
            _normalized_id(binding.role_ref),
            _normalized_id(resource_id),
        )
        for bindings in bindings_by_role.values()
        for binding in bindings
        for resource_id in binding.selected_resource_ids
    }
    matches: list[ManifestRiskAcceptance] = []
    for acceptance in profile.risk_acceptances:
        accepted_bindings = {
            (
                _normalized_id(binding.role_ref),
                _normalized_id(binding.resource_id),
            )
            for binding in acceptance.accepted_resource_bindings
        }
        if (
            _normalized_id(acceptance.risk_acceptance_id) in acceptance_refs
            and acceptance.is_active(
                as_of=as_of,
                manifest_id=profile.manifest_id,
                profile_id=profile.profile_id,
                clause_path=f"/constraints/{acceptance_clause_id}",
                owner_ref=constraint.owner_ref,
            )
            and (not proof_role_refs or accepted_bindings == required_bindings)
        ):
            matches.append(acceptance)
    if len(matches) > 1:
        raise AthenaValidationError("riskAcceptanceRef resolved ambiguously")
    return matches[0] if matches else None


def _bounded_evidence_refs(
    references: list[EvidenceReference],
) -> tuple[list[EvidenceReference], bool]:
    ordered = sorted(references, key=lambda reference: reference.canonical_json())
    return ordered[:1000], len(ordered) > 1000


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


def _bound_role_resources(
    evidence: EvidenceReferenceContext,
    role_ref: str,
) -> tuple[list[ResourceProofFact], FindingVerdict | None]:
    bindings = [
        binding
        for binding in evidence.role_bindings
        if _normalized_id(binding.role_ref) == _normalized_id(role_ref)
    ]
    if len(bindings) != 1:
        return ([], "unknown")
    binding = bindings[0]
    if binding.state == "conflicting":
        return ([], "conflicting")
    if binding.state != "complete":
        return ([], "unknown")
    resources = [
        item
        for item in evidence.resources
        if _normalized_id(item.role_ref) == _normalized_id(role_ref)
    ]
    selected = {_normalized_id(item) for item in binding.selected_resource_ids}
    actual = {_normalized_id(item.resource_id) for item in resources}
    if selected != actual:
        return (resources, "unknown")
    return (resources, None)


def evaluate_manifest_profile(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
    *,
    as_of: datetime,
    verify_evidence_context: EvidenceContextVerifier,
) -> dict[str, ManifestFinding]:
    if (
        profile.resolved_profile_digest != profile.recompute_semantic_digest()
        or profile.compatibility.artifact_digest != profile.recompute_artifact_digest()
    ):
        raise AthenaValidationError("resolved profile changed after digest validation")
    verify_evidence_context(evidence, as_of)
    if (
        evidence.manifest_id != profile.manifest_id
        or _normalized_id(evidence.profile_id) != _normalized_id(profile.profile_id)
        or evidence.resolved_profile_digest != profile.resolved_profile_digest
    ):
        raise AthenaValidationError("evidence reference context does not match resolved profile")
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
        raise AthenaValidationError("evidence reference context is stale at trusted as_of")

    findings: dict[str, ManifestFinding] = {}
    for constraint in profile.constraints:
        proof = constraint.proof_requirement
        verdict: FindingVerdict
        proof_references: list[EvidenceReference]
        if isinstance(proof, CardinalityProof):
            resources, binding_verdict = _bound_role_resources(evidence, proof.role_ref)
            proof_references = [item.evidence_ref for item in resources]
            gate = binding_verdict or _evidence_gate(
                resources, missing_verdict=constraint.failure_verdict
            )
            if gate is not None:
                verdict = gate
            elif any(item.availability_zone == "unknown" for item in resources):
                verdict = "unknown"
            else:
                minimum, maximum = _cardinality_bounds(proof.expected)
                matches = len(resources)
                if constraint.finding_kind in {"actualSpof", "riskAcceptance"}:
                    if not profile.settings.continuity.zone_loss_continuity_required:
                        verdict = "observation"
                    elif minimum <= matches <= maximum:
                        verdict = "violation"
                    else:
                        verdict = constraint.failure_verdict
                else:
                    verdict = (
                        constraint.success_verdict
                        if minimum <= matches <= maximum
                        else constraint.failure_verdict
                    )
        elif isinstance(proof, ZoneColocationProof):
            subjects, subject_binding_verdict = _bound_role_resources(
                evidence, proof.subject_role_ref
            )
            anchors, anchor_binding_verdict = _bound_role_resources(evidence, proof.anchor_role_ref)
            proof_references = [item.evidence_ref for item in [*subjects, *anchors]]
            gate = (
                subject_binding_verdict
                or anchor_binding_verdict
                or _evidence_gate(
                    [*subjects, *anchors],
                    missing_verdict=constraint.failure_verdict,
                )
            )
            if gate is not None or not subjects or not anchors:
                verdict = gate or "unknown"
            elif any(item.availability_zone == "unknown" for item in [*subjects, *anchors]):
                verdict = "unknown"
            else:
                anchor_zones = {item.availability_zone for item in anchors}
                subject_zones = {item.availability_zone for item in subjects}
                verdict = (
                    constraint.success_verdict
                    if len(anchor_zones) == 1 and subject_zones == anchor_zones
                    else constraint.failure_verdict
                )
        elif isinstance(proof, ZoneDistributionProof):
            resources, binding_verdict = _bound_role_resources(evidence, proof.role_ref)
            proof_references = [item.evidence_ref for item in resources]
            gate = binding_verdict or _evidence_gate(
                resources, missing_verdict=constraint.failure_verdict
            )
            if gate is not None or not resources:
                verdict = gate or "unknown"
            elif any(item.availability_zone == "unknown" for item in resources):
                verdict = "unknown"
            else:
                zones = {item.availability_zone for item in resources}
                verdict = (
                    constraint.success_verdict
                    if len(zones) >= proof.minimum_distinct_zones
                    else constraint.failure_verdict
                )
        elif isinstance(proof, RelationshipPresenceProof):
            relationship_facts = [
                item
                for item in evidence.relationships
                if _normalized_id(item.relationship_ref)
                == _normalized_id(proof.declared_relationship_ref)
            ]
            proof_references = [item.evidence_ref for item in relationship_facts]
            if any(item.state == "conflicting" for item in relationship_facts):
                verdict = "conflicting"
            elif (
                not relationship_facts
                or any(item.state != "complete" for item in relationship_facts)
                or all(item.proof_source == "inferred" for item in relationship_facts)
            ):
                verdict = "unknown"
            else:
                relationship_present = any(
                    item.presence == "present" for item in relationship_facts
                )
                if constraint.constraint_type == "dependencyProhibited":
                    verdict = (
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
        elif isinstance(proof, ControlHealthProof):
            control_facts = [
                item
                for item in evidence.controls
                if _normalized_id(item.control_ref) == _normalized_id(proof.control_ref)
            ]
            proof_references = [item.evidence_ref for item in control_facts]
            if any(item.state == "conflicting" for item in control_facts):
                verdict = "conflicting"
            elif len(control_facts) != 1 or control_facts[0].state != "complete":
                verdict = "unknown"
            elif control_facts[0].health != proof.required_health:
                verdict = constraint.failure_verdict
            else:
                verdict = constraint.success_verdict
        elif isinstance(proof, EvidenceFreshnessProof):
            proof_references = [
                *[item.evidence_ref for item in evidence.resources],
                *[item.evidence_ref for item in evidence.relationships],
                *[item.evidence_ref for item in evidence.controls],
                *[item.evidence_ref for item in evidence.objectives],
            ]
            states = [
                *[item.state for item in evidence.resources],
                *[item.state for item in evidence.relationships],
                *[item.state for item in evidence.controls],
                *[item.state for item in evidence.objectives],
            ]
            inferred = any(item.proof_source == "inferred" for item in evidence.resources) or any(
                item.proof_source == "inferred" for item in evidence.relationships
            )
            if "conflicting" in states:
                verdict = "conflicting"
            elif not states or any(state != "complete" for state in states) or inferred:
                verdict = "unknown"
            else:
                verdict = (
                    constraint.success_verdict
                    if (as_of - evidence.collected_at).total_seconds() <= proof.maximum_age_seconds
                    else constraint.failure_verdict
                )
        elif isinstance(proof, ObjectiveThresholdProof):
            objective_facts = [
                item
                for item in evidence.objectives
                if _normalized_id(item.objective_ref) == _normalized_id(proof.objective_ref)
            ]
            proof_references = [item.evidence_ref for item in objective_facts]
            if any(item.state == "conflicting" for item in objective_facts):
                verdict = "conflicting"
            elif len(objective_facts) != 1 or objective_facts[0].state != "complete":
                verdict = "unknown"
            else:
                verdict = (
                    constraint.success_verdict
                    if _comparison_matches(
                        objective_facts[0].current_value,
                        proof.comparison,
                        proof.threshold,
                    )
                    else constraint.failure_verdict
                )
        else:
            raise AthenaValidationError(f"unsupported proof variant: {proof.proof_kind}")

        if not proof_references:
            raise AthenaValidationError(
                f"constraint {constraint.constraint_id} requires typed evidence or gap references"
            )
        proof_references, over_broad = _bounded_evidence_refs(proof_references)
        if over_broad and verdict != "conflicting":
            verdict = "unknown"

        acceptance = _matching_acceptance(profile, constraint, evidence, as_of=as_of)
        risk_ref: str | None = None
        if (
            verdict == "violation"
            and acceptance is not None
            and constraint.finding_kind
            in {
                "actualSpof",
                "riskAcceptance",
                "architectureConstraint",
                "relationshipConflict",
            }
        ):
            verdict = "acceptedResidualRisk"
            risk_ref = acceptance.risk_acceptance_id
        if verdict == "acceptedResidualRisk" and acceptance is None:
            raise AthenaValidationError(
                "acceptedResidualRisk requires a verified active risk acceptance"
            )
        findings[constraint.constraint_id] = ManifestFinding(
            clauseId=constraint.constraint_id,
            findingKind=constraint.finding_kind,
            verdict=verdict,
            manifestId=profile.manifest_id,
            manifestVersion=profile.manifest_version,
            profileId=profile.profile_id,
            resolvedProfileDigest=profile.resolved_profile_digest,
            governanceScope=constraint.governance_scope,
            evidenceRefs=proof_references,
            riskAcceptanceRef=risk_ref,
        )
    return findings


__all__ = [
    "AccessReviewControl",
    "BackupControl",
    "CanonicalWorkloadManifest",
    "CanonicalWorkloadIdentity",
    "CanonicalManifestAudit",
    "CapacityReviewControl",
    "ChangeApprovalControl",
    "ClauseScope",
    "ControlProofFact",
    "DisabledManifestRef",
    "EvidenceReferenceContext",
    "EvidenceContextVerifier",
    "GovernedWeakeningOverride",
    "ImageSelector",
    "LoadBalancerBackendSelector",
    "ManifestConstraint",
    "ManifestControl",
    "ManifestFinding",
    "ManifestObjective",
    "ManifestOwner",
    "ManifestProfile",
    "ManifestRiskAcceptance",
    "ManifestRole",
    "ManifestSelector",
    "ManualFailoverRunbookControl",
    "MonitoringAlertControl",
    "NamePredicateSelector",
    "ObjectiveProofFact",
    "ProofFactValidator",
    "ProvenanceSelector",
    "RelationshipProofFact",
    "RoleBindingProof",
    "RoleBindingValidator",
    "ResolvedManifestProfile",
    "ResourceProofFact",
    "ResourceTypeSelector",
    "RestoreTestControl",
    "SubnetSelector",
    "VendorSupportControl",
    "VmssSelector",
    "evaluate_manifest_profile",
    "canonicalize_manifest_payload",
    "resolve_manifest_profile",
    "verified_snapshot_context_verifier",
]
