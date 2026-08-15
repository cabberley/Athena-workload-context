from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    compute_semantic_digest,
    normalize_nfc_text,
)


class AthenaBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_json(self) -> str:
        return canonicalize_json(self.model_dump(mode="json", exclude_none=False, by_alias=True))

    def compute_artifact_digest_value(self, *, exclude_paths: Iterable[str] | None = None) -> str:
        payload = self.model_dump(mode="json", exclude_none=False, by_alias=True)
        return compute_artifact_digest(payload, exclude_paths=exclude_paths)

    def compute_semantic_digest_value(self) -> str:
        payload = self._semantic_projection()
        return compute_semantic_digest(payload)

    def _semantic_projection(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            value = getattr(self, field_name)
            if not self._is_semantic_field(field_info):
                continue
            if value is None:
                result[field_name] = None
                continue
            if isinstance(value, AthenaBaseModel):
                result[field_name] = value._semantic_projection()
                continue
            if isinstance(value, list):
                result[field_name] = [
                    item._semantic_projection() if isinstance(item, AthenaBaseModel) else item
                    for item in value
                ]
                continue
            if isinstance(value, dict):
                result[field_name] = {
                    key: item._semantic_projection() if isinstance(item, AthenaBaseModel) else item
                    for key, item in value.items()
                }
                continue
            result[field_name] = value
        return result

    @staticmethod
    def _is_semantic_field(field_info: Any) -> bool:
        extra = field_info.json_schema_extra or {}
        if not isinstance(extra, dict):
            return False
        semantic_value = extra.get("x-athena-semanticClass") or extra.get("x-athena-semantic-class")
        return semantic_value == "semantic"

    @classmethod
    def on_model_validate(cls) -> None:
        return None


type Verdict = Literal[
    "pass",
    "violation",
    "expectedConstraint",
    "acceptedResidualRisk",
    "observation",
    "unknown",
    "conflicting",
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

type ProfileType = Literal[
    "production", "development", "training", "test", "disasterRecovery", "sandbox"
]

type CapConstraint = Literal["critical", "high", "medium", "low", "informational"]

type CapabilityRequiredFor = Literal["read", "publish", "evaluate", "render"]

type ConstraintType = Literal[
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

type ProofKind = Literal[
    "cardinalityProof",
    "zoneColocationProof",
    "zoneDistributionProof",
    "relationshipPresenceProof",
    "evidenceFreshnessProof",
    "controlHealthProof",
    "objectiveThresholdProof",
]

type RelationshipClass = Literal["declared", "observed", "inferred", "exception"]
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
]

type SelectorType = Literal[
    "resourceIdList",
    "tagPredicate",
    "namePattern",
    "resourceTypeScope",
    "compositeAll",
    "compositeAny",
]

type EvidenceRecordType = Literal[
    "resource",
    "observedRelationship",
    "metricAggregate",
    "healthEvent",
    "activitySummary",
    "advisorRecommendation",
    "evidenceGap",
]

type AttemptType = Literal[
    "successResponse",
    "failedResponse",
    "timeoutNoResponse",
    "authorizationFailure",
    "toolUnavailable",
]

type OwnerRole = Literal[
    "businessOwner",
    "technicalOwner",
    "operationsOwner",
    "securityOwner",
    "vendorOwner",
    "approver",
    "onCallGroup",
]

type ScopeType = Literal[
    "subscription", "resourceGroup", "resourceId", "logAnalyticsWorkspace", "serviceHealthRegion"
]
type GovernanceScopeType = Literal[
    "manifest",
    "profile",
    "clause",
    "role",
    "resourceBinding",
    "relationship",
    "control",
    "objective",
]


class CapabilityRequirement(AthenaBaseModel):
    capability_id: str = Field(
        ...,
        alias="capabilityId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    minimum_version: str = Field(
        ...,
        alias="minimumVersion",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_for: CapabilityRequiredFor = Field(
        ..., alias="requiredFor", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ProducerInfo(AthenaBaseModel):
    producer_id: str = Field(
        ..., alias="producerId", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    version: str = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})


class CompatibilityMetadata(AthenaBaseModel):
    artifact_kind: Literal[
        "workloadManifest",
        "resolvedProfile",
        "evidenceSnapshot",
        "contextualFinding",
        "generatedJsonSchema",
    ] = Field(
        ...,
        alias="artifactKind",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    schema_version: str = Field(
        ..., alias="schemaVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    semantic_contract_version: str = Field(
        ...,
        alias="semanticContractVersion",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    policy_contract_version: str = Field(
        ..., alias="policyContractVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum_reader_version: str = Field(
        ..., alias="minimumReaderVersion", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    requires_capabilities: list[CapabilityRequirement] = Field(
        default_factory=list,
        alias="requiresCapabilities",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    produced_by: ProducerInfo = Field(
        ..., alias="producedBy", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    extension_policy: Literal["rejectUnknownDecisionFields"] = Field(
        ..., alias="extensionPolicy", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    artifact_digest: str = Field(
        ..., alias="artifactDigest", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    semantic_digest: str = Field(
        ..., alias="semanticDigest", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class SubscriptionScope(AthenaBaseModel):
    scope_type: Literal["subscription"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ResourceGroupScope(AthenaBaseModel):
    scope_type: Literal["resourceGroup"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_group_name: str = Field(
        ...,
        alias="resourceGroupName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ResourceIdScope(AthenaBaseModel):
    scope_type: Literal["resourceId"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class LogAnalyticsWorkspaceScope(AthenaBaseModel):
    scope_type: Literal["logAnalyticsWorkspace"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tenant_id: str = Field(
        ...,
        alias="tenantId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    subscription_id: str = Field(
        ...,
        alias="subscriptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_group_name: str = Field(
        ...,
        alias="resourceGroupName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    workspace_name: str = Field(
        ...,
        alias="workspaceName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ServiceHealthRegionScope(AthenaBaseModel):
    scope_type: Literal["serviceHealthRegion"] = Field(
        ..., alias="scopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    cloud: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    region: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})


type EvidenceScope = Annotated[
    SubscriptionScope
    | ResourceGroupScope
    | ResourceIdScope
    | LogAnalyticsWorkspaceScope
    | ServiceHealthRegionScope,
    Field(discriminator="scope_type"),
]


class GovernanceManifestScope(AthenaBaseModel):
    governance_scope_type: Literal["manifest"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceProfileScope(AthenaBaseModel):
    governance_scope_type: Literal["profile"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceClauseScope(AthenaBaseModel):
    governance_scope_type: Literal["clause"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    clause_path: str = Field(
        ...,
        alias="clausePath",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceRoleScope(AthenaBaseModel):
    governance_scope_type: Literal["role"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class GovernanceResourceBindingScope(AthenaBaseModel):
    governance_scope_type: Literal["resourceBinding"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceRelationshipScope(AthenaBaseModel):
    governance_scope_type: Literal["relationship"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    relationship_ref: str = Field(
        ...,
        alias="relationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceControlScope(AthenaBaseModel):
    governance_scope_type: Literal["control"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    control_ref: str = Field(
        ...,
        alias="controlRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class GovernanceObjectiveScope(AthenaBaseModel):
    governance_scope_type: Literal["objective"] = Field(
        ..., alias="governanceScopeType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_ids: list[str] = Field(
        ...,
        alias="profileIds",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objective_ref: str = Field(
        ...,
        alias="objectiveRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type GovernanceScope = Annotated[
    GovernanceManifestScope
    | GovernanceProfileScope
    | GovernanceClauseScope
    | GovernanceRoleScope
    | GovernanceResourceBindingScope
    | GovernanceRelationshipScope
    | GovernanceControlScope
    | GovernanceObjectiveScope,
    Field(discriminator="governance_scope_type"),
]


class ProfileContinuitySettings(AthenaBaseModel):
    zone_loss_continuity_required: bool = Field(
        ...,
        alias="zoneLossContinuityRequired",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ProfileSettings(AthenaBaseModel):
    continuity: ProfileContinuitySettings = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ProfileOverride(AthenaBaseModel):
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    extends: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    settings: ProfileSettings = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    disabled_refs: list[str] = Field(
        default_factory=list,
        alias="disabledRefs",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str | None = Field(
        default=None, alias="ownerRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ProfileDefinition(AthenaBaseModel):
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_type: ProfileType = Field(
        ..., alias="profileType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    extends: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    settings: ProfileSettings = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    overrides: list[ProfileOverride] = Field(
        default_factory=list, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityExactlyOne(AthenaBaseModel):
    cardinality_kind: Literal["exactlyOne"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityOneOrMore(AthenaBaseModel):
    cardinality_kind: Literal["oneOrMore"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityZeroOrMore(AthenaBaseModel):
    cardinality_kind: Literal["zeroOrMore"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleCardinalityBoundedRange(AthenaBaseModel):
    cardinality_kind: Literal["boundedRange"] = Field(
        ..., alias="cardinalityKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum: int = Field(
        ..., ge=0, le=10000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    maximum: int = Field(
        ..., ge=0, le=10000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )

    @model_validator(mode="after")
    def validate_bounds(self) -> RoleCardinalityBoundedRange:
        if self.maximum < self.minimum:
            raise AthenaValidationError("bounded range maximum must be >= minimum")
        return self


type RoleCardinality = Annotated[
    RoleCardinalityExactlyOne
    | RoleCardinalityOneOrMore
    | RoleCardinalityZeroOrMore
    | RoleCardinalityBoundedRange,
    Field(discriminator="cardinality_kind"),
]


class ResourceIdListSelector(AthenaBaseModel):
    selector_type: Literal["resourceIdList"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_ids: list[str] = Field(
        ...,
        alias="resourceIds",
        min_length=1,
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class TagPredicateSelector(AthenaBaseModel):
    selector_type: Literal["tagPredicate"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    predicates: list[str] = Field(
        ..., min_length=1, max_length=20, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class NamePatternSelector(AthenaBaseModel):
    selector_type: Literal["namePattern"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    pattern: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ResourceTypeScopeSelector(AthenaBaseModel):
    selector_type: Literal["resourceTypeScope"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_type: str = Field(
        ...,
        alias="resourceType",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    location: str | None = Field(
        default=None, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_group_name: str | None = Field(
        default=None,
        alias="resourceGroupName",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class CompositeAllSelector(AthenaBaseModel):
    selector_type: Literal["compositeAll"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    children: list[Selector] = Field(
        ..., min_length=1, max_length=10, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class CompositeAnySelector(AthenaBaseModel):
    selector_type: Literal["compositeAny"] = Field(
        ..., alias="selectorType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    children: list[Selector] = Field(
        ..., min_length=1, max_length=10, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    max_matches: int = Field(
        default=1000,
        alias="maxMatches",
        ge=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type Selector = Annotated[
    ResourceIdListSelector
    | TagPredicateSelector
    | NamePatternSelector
    | ResourceTypeScopeSelector
    | CompositeAllSelector
    | CompositeAnySelector,
    Field(discriminator="selector_type"),
]


class OwnershipReference(AthenaBaseModel):
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    owner_role: OwnerRole = Field(
        ..., alias="ownerRole", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class WorkloadRole(AthenaBaseModel):
    role_id: str = Field(
        ..., alias="roleId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    kind: RoleKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    display_name: str = Field(
        ...,
        alias="displayName",
        min_length=1,
        max_length=120,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    cardinality: RoleCardinality = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    selectors: list[Selector] = Field(
        default_factory=list,
        min_length=1,
        max_length=20,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_applicability: list[str] = Field(
        default_factory=list,
        alias="profileApplicability",
        min_length=1,
        max_length=25,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    approval_state: Literal["draft", "approved", "deprecated"] = Field(
        ..., alias="approvalState", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RoleRef(AthenaBaseModel):
    ref_kind: Literal["roleRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_id: str = Field(
        ..., alias="roleId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ResourceRef(AthenaBaseModel):
    ref_kind: Literal["resourceRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ExternalRef(AthenaBaseModel):
    ref_kind: Literal["externalRef"] = Field(
        ..., alias="refKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    external_id: str = Field(
        ...,
        alias="externalId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type RelationshipEndpoint = Annotated[
    RoleRef | ResourceRef | ExternalRef, Field(discriminator="ref_kind")
]


class DeclaredRelationship(AthenaBaseModel):
    relationship_class: Literal["declared"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    profiles: list[str] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_clause: str = Field(
        ...,
        alias="sourceClause",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ObservedRelationship(AthenaBaseModel):
    relationship_class: Literal["observed"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_item_ref: str = Field(
        ...,
        alias="evidenceItemRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(
        ..., alias="observedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class InferredRelationship(AthenaBaseModel):
    relationship_class: Literal["inferred"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship_id: str = Field(
        ...,
        alias="relationshipId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    kind: RelationshipKind = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    source: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    target: RelationshipEndpoint = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    input_evidence_refs: list[str] = Field(
        ...,
        alias="inputEvidenceRefs",
        min_length=1,
        max_length=20,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    algorithm_id: str = Field(
        ...,
        alias="algorithmId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ExceptionRelationship(AthenaBaseModel):
    relationship_class: Literal["exception"] = Field(
        ..., alias="relationshipClass", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    exception_id: str = Field(
        ...,
        alias="exceptionId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    applies_to_relationship_ref: str = Field(
        ...,
        alias="appliesToRelationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    risk_acceptance_ref: str = Field(
        ...,
        alias="riskAcceptanceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


type Relationship = Annotated[
    DeclaredRelationship | ObservedRelationship | InferredRelationship | ExceptionRelationship,
    Field(discriminator="relationship_class"),
]


class CardProof(AthenaBaseModel):
    proof_kind: Literal["cardinalityProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expected: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_evidence_refs: list[str] = Field(
        ...,
        alias="resourceEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ZoneColocationProof(AthenaBaseModel):
    proof_kind: Literal["zoneColocationProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    subject_role_ref: str = Field(
        ...,
        alias="subjectRoleRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    anchor_role_ref: str = Field(
        ...,
        alias="anchorRoleRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    zone_evidence_refs: list[str] = Field(
        ...,
        alias="zoneEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ZoneDistributionProof(AthenaBaseModel):
    proof_kind: Literal["zoneDistributionProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    role_ref: str = Field(
        ..., alias="roleRef", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    minimum_distinct_zones: int = Field(
        ...,
        alias="minimumDistinctZones",
        ge=1,
        le=3,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    zone_evidence_refs: list[str] = Field(
        ...,
        alias="zoneEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RelationshipPresenceProof(AthenaBaseModel):
    proof_kind: Literal["relationshipPresenceProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    declared_relationship_ref: str = Field(
        ...,
        alias="declaredRelationshipRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_relationship_evidence_refs: list[str] = Field(
        ...,
        alias="observedRelationshipEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class EvidenceFreshnessProof(AthenaBaseModel):
    proof_kind: Literal["evidenceFreshnessProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    maximum_age: int = Field(
        ...,
        alias="maximumAge",
        ge=1,
        le=30 * 24 * 60 * 60,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_refs: list[str] = Field(
        ...,
        alias="evidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ControlHealthProof(AthenaBaseModel):
    proof_kind: Literal["controlHealthProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    control_ref: str = Field(
        ...,
        alias="controlRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_health: str = Field(
        ...,
        alias="requiredHealth",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    control_evidence_refs: list[str] = Field(
        ...,
        alias="controlEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class ObjectiveThresholdProof(AthenaBaseModel):
    proof_kind: Literal["objectiveThresholdProof"] = Field(
        ..., alias="proofKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    objective_ref: str = Field(
        ...,
        alias="objectiveRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    metric_evidence_refs: list[str] = Field(
        ...,
        alias="metricEvidenceRefs",
        min_length=1,
        max_length=1000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    comparison: Literal["lt", "lte", "gt", "gte", "eq"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    required_evidence_ref_kinds: list[str] = Field(
        default_factory=list,
        alias="requiredEvidenceRefKinds",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    on_missing_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onMissingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    on_conflicting_evidence: Literal["unknown", "conflicting", "violation"] = Field(
        ..., alias="onConflictingEvidence", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


type ProofRequirement = Annotated[
    CardProof
    | ZoneColocationProof
    | ZoneDistributionProof
    | RelationshipPresenceProof
    | EvidenceFreshnessProof
    | ControlHealthProof
    | ObjectiveThresholdProof,
    Field(discriminator="proof_kind"),
]


class Constraint(AthenaBaseModel):
    constraint_id: str = Field(
        ...,
        alias="constraintId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    type: ConstraintType = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    applies_to_role_refs: list[str] = Field(
        ...,
        alias="appliesToRoleRefs",
        min_length=1,
        max_length=50,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profiles: list[str] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    proof_requirement: ProofRequirement = Field(
        ..., alias="proofRequirement", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    source_clause: str = Field(
        ...,
        alias="sourceClause",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_mode: Literal["violation", "unknown", "conflicting"] = Field(
        ..., alias="failureMode", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


class RiskAcceptance(AthenaBaseModel):
    risk_acceptance_id: str = Field(
        ...,
        alias="riskAcceptanceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    rationale: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    accepted_at: datetime = Field(
        ..., alias="acceptedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    active: bool = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    applies_to_clause_path: str | None = Field(
        default=None,
        alias="appliesToClausePath",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class Control(AthenaBaseModel):
    control_id: str = Field(
        ...,
        alias="controlId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    name: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: Literal["healthy", "degraded", "failed", "unknown"] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    risk_acceptance_ref: str | None = Field(
        default=None,
        alias="riskAcceptanceRef",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class Objective(AthenaBaseModel):
    objective_id: str = Field(
        ...,
        alias="objectiveId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objective_type: Literal[
        "availabilitySlo",
        "latencySlo",
        "throughputSlo",
        "rto",
        "rpo",
        "serviceHours",
        "capacityHeadroom",
        "recoveryPriority",
    ] = Field(..., alias="objectiveType", json_schema_extra={"x-athena-semanticClass": "semantic"})
    target_value: float = Field(
        ..., alias="targetValue", ge=0, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    owner_ref: str = Field(
        ...,
        alias="ownerRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_applicability: list[str] = Field(
        ...,
        alias="profileApplicability",
        min_length=1,
        max_length=25,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class WorkloadManifest(AthenaBaseModel):
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    manifest_version: str = Field(
        ...,
        alias="manifestVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    workload: dict[str, Any] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    profiles: dict[str, ProfileDefinition] = Field(
        ..., min_length=1, max_length=25, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    roles: list[WorkloadRole] = Field(
        ..., min_length=1, max_length=200, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationships: dict[str, list[Relationship]] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    constraints: list[Constraint] = Field(
        default_factory=list,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    controls: list[Control] = Field(
        default_factory=list,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    risk_acceptances: list[RiskAcceptance] = Field(
        default_factory=list,
        alias="riskAcceptances",
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    objectives: list[Objective] = Field(
        default_factory=list,
        max_length=200,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    ownership: dict[str, Any] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    compatibility: CompatibilityMetadata = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    audit: dict[str, Any] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})

    @field_validator("profiles")
    @classmethod
    def validate_profile_ids(
        cls, profiles: dict[str, ProfileDefinition]
    ) -> dict[str, ProfileDefinition]:
        if not profiles:
            raise AthenaValidationError("manifest requires at least one profile")
        normalized: set[str] = set()
        for profile_key, profile_def in profiles.items():
            key_normalized = normalize_nfc_text(profile_key)
            if key_normalized in normalized:
                raise AthenaValidationError(f"duplicate profile id: {profile_key!r}")
            normalized.add(key_normalized)
            if profile_def.profile_id != profile_key:
                raise AthenaValidationError("profiles must use stable id keys matching profileId")
        return profiles

    @model_validator(mode="after")
    def validate_manifest(self) -> WorkloadManifest:
        for role in self.roles:
            if not role.selectors and role.approval_state == "approved":
                raise AthenaValidationError("approved role must declare selectors")
        if (
            "production" not in self.profiles
            or "development" not in self.profiles
            or "training" not in self.profiles
        ):
            raise AthenaValidationError(
                "prototype manifest requires production, development, and training profiles"
            )
        return self

    def resolved_profiles(self) -> dict[str, ProfileDefinition]:
        resolved: dict[str, ProfileDefinition] = {}
        for profile_id, profile in self.profiles.items():
            resolved[profile_id] = profile
        return resolved


class EvidenceItemRef(AthenaBaseModel):
    ref_type: Literal["evidenceItem"] = Field(
        ..., alias="refType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_artifact_digest: str = Field(
        ...,
        alias="snapshotArtifactDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_semantic_digest: str = Field(
        ...,
        alias="snapshotSemanticDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_name: str = Field(
        ...,
        alias="collectorToolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_version: str = Field(
        ...,
        alias="collectorToolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_at: datetime = Field(
        ..., alias="collectorAttemptAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_digest: str = Field(
        ...,
        alias="sourceResponseDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    source_response_pointer: str = Field(
        ...,
        alias="sourceResponsePointer",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class EvidenceGapRef(AthenaBaseModel):
    ref_type: Literal["evidenceGap"] = Field(
        ..., alias="refType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_artifact_digest: str = Field(
        ...,
        alias="snapshotArtifactDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    snapshot_semantic_digest: str = Field(
        ...,
        alias="snapshotSemanticDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    gap_id: str = Field(
        ..., alias="gapId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_record_digest: str = Field(
        ...,
        alias="gapRecordDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expected_record_type: EvidenceRecordType = Field(
        ..., alias="expectedRecordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_name: str = Field(
        ...,
        alias="collectorToolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_tool_version: str = Field(
        ...,
        alias="collectorToolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_at: datetime = Field(
        ..., alias="collectorAttemptAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    gap_reason: str = Field(
        ...,
        alias="gapReason",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_digest: str | None = Field(
        default=None,
        alias="failurePayloadDigest",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_payload_pointer: str | None = Field(
        default=None,
        alias="failurePayloadPointer",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type EvidenceReference = Annotated[
    EvidenceItemRef | EvidenceGapRef, Field(discriminator="ref_type")
]


class ContextRef(AthenaBaseModel):
    manifest_id: str = Field(
        ...,
        alias="manifestId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    manifest_version: str = Field(
        ...,
        alias="manifestVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    profile_id: str = Field(
        ...,
        alias="profileId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resolved_profile_digest: str = Field(
        ...,
        alias="resolvedProfileDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    clause_path: str = Field(
        ...,
        alias="clausePath",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class CollectorIdentityEvidence(AthenaBaseModel):
    identity_evidence_id: str = Field(
        ...,
        alias="identityEvidenceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    token_hash: str = Field(
        ...,
        alias="tokenHash",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    jwt_header: dict[str, Any] = Field(
        ..., alias="jwtHeader", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    trust_anchor_ref: str = Field(
        ...,
        alias="trustAnchorRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    verified_claims: dict[str, Any] = Field(
        ..., alias="verifiedClaims", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    token_verification: dict[str, Any] = Field(
        ..., alias="tokenVerification", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ingestion_derivation: dict[str, Any] = Field(
        ..., alias="ingestionDerivation", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ingestion_signature: dict[str, Any] = Field(
        ..., alias="ingestionSignature", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    identity_evidence_digest: str = Field(
        ...,
        alias="identityEvidenceDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class SuccessResponseCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["successResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_digest: str = Field(
        ...,
        alias="responseDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_received_at: datetime = Field(
        ..., alias="responseReceivedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class FailedResponseCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["failedResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_code: str = Field(
        ...,
        alias="failureCode",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_status: str = Field(
        ...,
        alias="failureStatus",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    failure_digest: str = Field(
        ...,
        alias="failureDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    response_received_at: datetime = Field(
        ..., alias="responseReceivedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class TimeoutNoResponseCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["timeoutNoResponse"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    deadline_at: datetime = Field(
        ..., alias="deadlineAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    timed_out_at: datetime = Field(
        ..., alias="timedOutAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class AuthorizationFailureCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["authorizationFailure"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    authorization_status: str = Field(
        ...,
        alias="authorizationStatus",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ToolUnavailableCollectorAttempt(AthenaBaseModel):
    attempt_type: Literal["toolUnavailable"] = Field(
        ..., alias="attemptType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    attempt_id: str = Field(
        ...,
        alias="attemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_started_at: datetime = Field(
        ..., alias="attemptStartedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tool_version: str = Field(
        ...,
        alias="toolVersion",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    request_digest: str = Field(
        ...,
        alias="requestDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    unavailable_reason: str = Field(
        ...,
        alias="unavailableReason",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    attempt_digest: str = Field(
        ...,
        alias="attemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type CollectorAttempt = Annotated[
    SuccessResponseCollectorAttempt
    | FailedResponseCollectorAttempt
    | TimeoutNoResponseCollectorAttempt
    | AuthorizationFailureCollectorAttempt
    | ToolUnavailableCollectorAttempt,
    Field(discriminator="attempt_type"),
]


class ResourceEvidenceRecord(AthenaBaseModel):
    record_type: Literal["resource"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    resource_type: str = Field(
        ...,
        alias="resourceType",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    location: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    availability_zone: str | None = Field(
        default=None,
        alias="availabilityZone",
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    tags: dict[str, str] = Field(
        default_factory=dict, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    state: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ObservedRelationshipEvidenceRecord(AthenaBaseModel):
    record_type: Literal["observedRelationship"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    relationship: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class MetricAggregateEvidenceRecord(AthenaBaseModel):
    record_type: Literal["metricAggregate"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    metric_name: str = Field(
        ...,
        alias="metricName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    aggregation: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_start: datetime = Field(
        ..., alias="windowStart", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_end: datetime = Field(
        ..., alias="windowEnd", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    value: float = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    unit: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class HealthEventEvidenceRecord(AthenaBaseModel):
    record_type: Literal["healthEvent"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    health_kind: str = Field(
        ...,
        alias="healthKind",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    started_at: datetime = Field(
        ..., alias="startedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    ended_at: datetime = Field(
        ..., alias="endedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    summary: str = Field(
        ..., min_length=1, max_length=1000, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class ActivitySummaryEvidenceRecord(AthenaBaseModel):
    record_type: Literal["activitySummary"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    operation_name: str = Field(
        ...,
        alias="operationName",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    status: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    count: int = Field(..., ge=0, json_schema_extra={"x-athena-semanticClass": "semantic"})
    window_start: datetime = Field(
        ..., alias="windowStart", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    window_end: datetime = Field(
        ..., alias="windowEnd", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class AdvisorRecommendationEvidenceRecord(AthenaBaseModel):
    record_type: Literal["advisorRecommendation"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    resource_id: str = Field(
        ...,
        alias="resourceId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    category: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    impact: str = Field(..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"})
    recommendation_code: str = Field(
        ...,
        alias="recommendationCode",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    provenance: dict[str, Any] = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class EvidenceGapRecord(AthenaBaseModel):
    record_type: Literal["evidenceGap"] = Field(
        ..., alias="recordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_id: str = Field(
        ..., alias="gapId", min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_scope: EvidenceScope = Field(
        ..., alias="evidenceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    gap_reason: str = Field(
        ...,
        alias="gapReason",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    expected_record_type: EvidenceRecordType = Field(
        ..., alias="expectedRecordType", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector_attempt_id: str = Field(
        ...,
        alias="collectorAttemptId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collector_attempt_digest: str = Field(
        ...,
        alias="collectorAttemptDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    observed_at: datetime = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    collector_identity_evidence_ref: str = Field(
        ...,
        alias="collectorIdentityEvidenceRef",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    item_digest: str = Field(
        ...,
        alias="itemDigest",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


type EvidenceRecord = Annotated[
    ResourceEvidenceRecord
    | ObservedRelationshipEvidenceRecord
    | MetricAggregateEvidenceRecord
    | HealthEventEvidenceRecord
    | ActivitySummaryEvidenceRecord
    | AdvisorRecommendationEvidenceRecord
    | EvidenceGapRecord,
    Field(discriminator="record_type"),
]


class EvidenceSnapshot(AthenaBaseModel):
    snapshot_id: str = Field(
        ...,
        alias="snapshotId",
        min_length=1,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    compatibility: CompatibilityMetadata = Field(
        ..., json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    authorized_scopes: list[EvidenceScope] = Field(
        ...,
        alias="authorizedScopes",
        min_length=1,
        max_length=100,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    collected_at: datetime = Field(
        ..., alias="collectedAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    expires_at: datetime = Field(
        ..., alias="expiresAt", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    collector: dict[str, Any] = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    collector_attempts: list[CollectorAttempt] = Field(
        ...,
        alias="collectorAttempts",
        min_length=1,
        max_length=500,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )
    evidence_records: list[EvidenceRecord] = Field(
        ...,
        alias="evidenceRecords",
        max_length=30000,
        json_schema_extra={"x-athena-semanticClass": "semantic"},
    )


class Finding(AthenaBaseModel):
    finding_kind: FindingKind = Field(
        ..., alias="findingKind", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    verdict: Verdict = Field(..., json_schema_extra={"x-athena-semanticClass": "semantic"})
    governance_scope: GovernanceScope = Field(
        ..., alias="governanceScope", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    context_ref: ContextRef = Field(
        ..., alias="contextRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    evidence_ref: EvidenceReference = Field(
        ..., alias="evidenceRef", json_schema_extra={"x-athena-semanticClass": "semantic"}
    )
    summary: str = Field(
        ..., min_length=1, json_schema_extra={"x-athena-semanticClass": "semantic"}
    )


__all__ = [
    "AthenaBaseModel",
    "AthenaValidationError",
    "CapabilityRequirement",
    "CompatibilityMetadata",
    "ProducerInfo",
    "SubscriptionScope",
    "ResourceGroupScope",
    "ResourceIdScope",
    "LogAnalyticsWorkspaceScope",
    "ServiceHealthRegionScope",
    "EvidenceScope",
    "GovernanceManifestScope",
    "GovernanceProfileScope",
    "GovernanceClauseScope",
    "GovernanceRoleScope",
    "GovernanceResourceBindingScope",
    "GovernanceRelationshipScope",
    "GovernanceControlScope",
    "GovernanceObjectiveScope",
    "GovernanceScope",
    "ProfileDefinition",
    "ProfileOverride",
    "ProfileContinuitySettings",
    "ProfileSettings",
    "RoleCardinalityExactlyOne",
    "RoleCardinalityOneOrMore",
    "RoleCardinalityZeroOrMore",
    "RoleCardinalityBoundedRange",
    "RoleCardinality",
    "ResourceIdListSelector",
    "TagPredicateSelector",
    "NamePatternSelector",
    "ResourceTypeScopeSelector",
    "CompositeAllSelector",
    "CompositeAnySelector",
    "Selector",
    "OwnershipReference",
    "WorkloadRole",
    "RoleRef",
    "ResourceRef",
    "ExternalRef",
    "Relationship",
    "DeclaredRelationship",
    "ObservedRelationship",
    "InferredRelationship",
    "ExceptionRelationship",
    "Constraint",
    "ProofRequirement",
    "CardProof",
    "ZoneColocationProof",
    "ZoneDistributionProof",
    "RelationshipPresenceProof",
    "EvidenceFreshnessProof",
    "ControlHealthProof",
    "ObjectiveThresholdProof",
    "Control",
    "RiskAcceptance",
    "Objective",
    "WorkloadManifest",
    "EvidenceItemRef",
    "EvidenceGapRef",
    "EvidenceReference",
    "ContextRef",
    "CollectorIdentityEvidence",
    "SuccessResponseCollectorAttempt",
    "FailedResponseCollectorAttempt",
    "TimeoutNoResponseCollectorAttempt",
    "AuthorizationFailureCollectorAttempt",
    "ToolUnavailableCollectorAttempt",
    "CollectorAttempt",
    "ResourceEvidenceRecord",
    "ObservedRelationshipEvidenceRecord",
    "MetricAggregateEvidenceRecord",
    "HealthEventEvidenceRecord",
    "ActivitySummaryEvidenceRecord",
    "AdvisorRecommendationEvidenceRecord",
    "EvidenceGapRecord",
    "EvidenceRecord",
    "EvidenceSnapshot",
    "Finding",
    "Verdict",
    "FindingKind",
    "RoleKind",
    "SelectorType",
    "RelationshipKind",
    "ConstraintType",
    "ProofKind",
    "ProfileType",
]
