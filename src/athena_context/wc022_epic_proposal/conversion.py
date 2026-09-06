"""Deterministic conversion of the explicitly non-runtime public research draft."""

from __future__ import annotations

import re
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import yaml

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    normalize_nfc_text,
)
from athena_context.wc022_epic_proposal.contracts import (
    WC022_RESEARCH_DRAFT_LOCATION,
    WC022_REVIEWED_DOSSIER_DIGEST,
    WC022_REVIEWED_DRAFT_DIGEST,
    WC022_REVIEWED_PROPOSAL_DIGEST,
    WC022_SOURCE_DOSSIER,
    DependencyCategoryProposal,
    EnvironmentProposal,
    EvidenceRequirementsProposal,
    ExceptionCandidate,
    GovernedWorkloadContextProposal,
    HumanDecision,
    MonitoringSemanticsProposal,
    ObjectiveProposal,
    OwnershipProposal,
    PlacementConstraintProposal,
    ProposalGovernance,
    ProposalProvenance,
    ProposalWorkloadIdentity,
    RecoveryIntentProposal,
    RelationshipHypothesisProposal,
    RoleProposal,
    UnknownValue,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CANONICAL_RESEARCH_DRAFT_PATH = (
    _REPOSITORY_ROOT / "docs" / "research" / "drafts" / "epic-on-azure.draft.yaml"
)
_CANONICAL_SOURCE_DOSSIER_PATH = _REPOSITORY_ROOT / WC022_SOURCE_DOSSIER
_MAX_RESEARCH_DRAFT_BYTES = 128 * 1024
_MAX_RESEARCH_DRAFT_ITEMS = 1024
_MAX_RESEARCH_DRAFT_DEPTH = 16
_ENVIRONMENT_TYPES = {
    "Production": ("production", "production"),
    "DR": ("dr", "disasterRecovery"),
    "Development": ("development", "development"),
    "Test": ("test", "test"),
    "Training": ("training", "training"),
}
_ROOT_KEYS = frozenset(
    {
        "schemaStatus",
        "runtimeUse",
        "loadPolicy",
        "classification",
        "createdForIssue",
        "sourceDossier",
        "researchDraftLocation",
        "redactionRules",
        "workloadContextDraft",
    }
)
_DRAFT_KEYS = frozenset(
    {
        "id",
        "displayName",
        "workloadFamily",
        "description",
        "provenanceRefs",
        "authorityCaveat",
        "assumptionGuardrail",
        "objectives",
        "dataBoundary",
        "environments",
        "abstractRoles",
        "dependencyCategories",
        "placementConstraints",
        "relationshipHypotheses",
        "monitoringSemantics",
        "ownershipModel",
        "recoveryModel",
        "acceptedArchitecturalConstraints",
        "conversionNotesForWc001",
    }
)
_OBJECTIVE_IDS = frozenset(
    {
        "reliability",
        "security",
        "operationalExcellence",
        "performanceEfficiency",
        "costOptimization",
    }
)
_ENVIRONMENT_KEYS = frozenset(
    {
        "declarationRequired",
        "objective",
        "criticality",
        "recoveryPosture",
        "dependencyCompleteness",
        "dataRisk",
        "monitoringSemantics",
        "ownership",
        "supportedBy",
        "unknowns",
    }
)
_ROLE_FIELD_SETS = {
    "clientPresentation": frozenset(
        {"purpose", "examplesAreIllustrativeOnly", "discoveryHints", "supportedBy"}
    ),
    "webAndApplicationServices": frozenset(
        {"purpose", "placementIntent", "supportedBy"}
    ),
    "operationalDatabase": frozenset(
        {
            "purpose",
            "acceptedConstraint",
            "requiredRiskRecordIfConstrained",
            "supportedBy",
        }
    ),
    "analyticsAndReporting": frozenset(
        {"purpose", "dependencySemantics", "supportedBy"}
    ),
    "sharedServices": frozenset({"purpose", "dependencySemantics", "supportedBy"}),
    "integrationAndConnectivity": frozenset(
        {"purpose", "prohibitedDetail", "supportedBy"}
    ),
    "monitoringAndOperations": frozenset(
        {"purpose", "prohibitedDetail", "supportedBy"}
    ),
    "backupAndRecovery": frozenset({"purpose", "prohibitedDetail", "supportedBy"}),
}
_DEPENDENCY_DETAIL_FIELDS = {
    "identityAndAccess": "exactProviders",
    "networkAndConnectivity": "exactFlows",
    "computeAndPlacement": "exactSkuOrSize",
    "storageAndDataProtection": "exactSizing",
    "monitoringAndObservability": "rawTelemetryValues",
    "supportAndEscalation": "personalContacts",
    "applicationDelivery": "implementationSettings",
}
_PLACEMENT_KEYS = {
    "primaryPlacement": frozenset(
        {"declarationRequired", "regionIntent", "zoneIntent", "supportedBy"}
    ),
    "alternatePlacement": frozenset(
        {"declarationRequired", "regionIntent", "zoneIntent", "supportedBy"}
    ),
    "rolePlacement": frozenset(
        {
            "webAndApplicationServices",
            "operationalDatabase",
            "workersOrDependentRoles",
            "supportedBy",
        }
    ),
    "networkSegmentation": frozenset(
        {"declarationRequired", "intent", "exactRoutesAndRules", "supportedBy"}
    ),
}
_EXCEPTION_FIELD_SETS = {
    "singletonOrConstrainedDatabase": frozenset(
        {"allowedOnlyWhenDeclared", "requiredFieldsIfDeclared", "supportedBy"}
    ),
    "nonProductionParity": frozenset(
        {
            "allowedOnlyWhenDeclared",
            "defaultState",
            "requiredFieldsIfDeclared",
            "supportedBy",
        }
    ),
    "tagBasedDiscoveryHints": frozenset(
        {"allowedOnlyAsHints", "requiredFieldsIfDeclared", "supportedBy"}
    ),
    "unknownOrLowConfidenceBinding": frozenset(
        {"failClosed", "action", "supportedBy"}
    ),
}
_OWNERSHIP_ROLE_IDS = frozenset(
    {
        "workloadOwner",
        "applicationOwner",
        "platformOwner",
        "monitoringOwner",
        "recoveryOwner",
        "changeApprover",
    }
)
_RELATIONSHIP_ITEM_KEYS = frozenset(
    {
        "id",
        "sourceRole",
        "targetRole",
        "environmentScope",
        "relationshipCategory",
        "intent",
        "provenanceCategory",
        "confidence",
        "unknownState",
        "humanValidationRequired",
    }
)
_SAFE_SOURCE_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


class ResearchDraftConversionError(ValueError):
    """Raised when a source is not the guarded WC-022 public research draft."""


def _read_canonical_reviewed_source() -> Mapping[str, object]:
    """Read and validate the reviewed bytes immediately before conversion."""

    try:
        source_bytes = _CANONICAL_RESEARCH_DRAFT_PATH.read_bytes()
    except OSError as exc:
        raise ResearchDraftConversionError("research draft could not be read") from exc
    if not 0 < len(source_bytes) <= _MAX_RESEARCH_DRAFT_BYTES:
        raise ResearchDraftConversionError("research draft is outside its byte bound")
    source_digest = _content_digest(source_bytes)
    if source_digest != WC022_REVIEWED_DRAFT_DIGEST:
        raise ResearchDraftConversionError(
            "research draft does not match the sealed reviewed source digest"
        )
    try:
        dossier_digest = _content_digest(_CANONICAL_SOURCE_DOSSIER_PATH.read_bytes())
    except OSError as exc:
        raise ResearchDraftConversionError("research source dossier could not be read") from exc
    if dossier_digest != WC022_REVIEWED_DOSSIER_DIGEST:
        raise ResearchDraftConversionError(
            "research source dossier does not match the sealed reviewed dossier digest"
        )
    try:
        loaded = yaml.safe_load(source_bytes)
    except yaml.YAMLError as exc:
        raise ResearchDraftConversionError("research draft is not valid YAML") from exc
    if not isinstance(loaded, dict):
        raise ResearchDraftConversionError("research draft root must be a mapping")
    _validate_mapping_boundary(loaded)
    _validate_source_shape(loaded)
    return cast(Mapping[str, object], loaded)


def convert_canonical_public_safe_research_draft(
) -> GovernedWorkloadContextProposal:
    """Atomically verify and convert the sole reviewed WC-022 source."""

    return _convert_verified_canonical_research_draft()


def _convert_verified_canonical_research_draft() -> GovernedWorkloadContextProposal:
    """Convert freshly verified canonical bytes; this helper accepts no authority input."""

    source = _read_canonical_reviewed_source()
    _require_exact(source, "schemaStatus", "draft-pre-wc-001")
    _require_exact(source, "runtimeUse", "prohibited")
    _require_exact(source, "loadPolicy", "never-load")
    _require_exact(source, "classification", "public-safe-synthetic-draft")
    draft = _mapping(source, "workloadContextDraft")
    source_refs = sorted(_strings(draft, "provenanceRefs"))
    if not source_refs:
        raise ResearchDraftConversionError("research draft must provide provenance references")

    environments_source = _mapping(draft, "environments")
    environments = [
        _environment_proposal(name, _mapping(environments_source, name))
        for name in sorted(environments_source)
    ]

    roles_source = _mapping(draft, "abstractRoles")
    roles = [
        _role_proposal(role_id, _mapping(roles_source, role_id))
        for role_id in sorted(roles_source)
    ]
    relationships_source = _mapping(draft, "relationshipHypotheses")
    relationships = [
        _relationship_proposal(item)
        for item in _sorted_mappings(_list(relationships_source, "items"), "id")
    ]
    objectives_source = _mapping(draft, "objectives")
    objectives = [
        ObjectiveProposal(
            objectiveId=cast(Any, objective_id),
            declaredIntent=_string(objectives_source, objective_id),
            target=_human_decision(
                f"{objective_id} target",
                "The research draft deliberately contains no objective target value.",
                source_refs,
            ),
        )
        for objective_id in sorted(objectives_source)
    ]
    ownership_source = _mapping(draft, "ownershipModel")
    ownership_roles = _mapping(ownership_source, "roles")
    ownership = [
        OwnershipProposal(
            ownerRole=cast(Any, owner_role),
            assignment=_human_decision(
                f"{owner_role} assignment",
                _string(ownership_roles, owner_role),
                list(_strings(ownership_source, "supportedBy")),
            ),
        )
        for owner_role in sorted(ownership_roles)
    ]

    conversion_payload: dict[str, object] = {
        "contractVersion": "athena.wc022.governedProposal.v1",
        "proposalKind": "governedWorkloadContextProposal",
        "proposalId": f"proposal-{_string(draft, 'id')}",
        "governance": ProposalGovernance(
            publicationState="unpublished",
            runtimeUse="prohibited",
            humanApprovalRequired=True,
            authorityBoundary="contextApiHumanPublicationOnly",
        ).model_dump(by_alias=True, mode="json"),
        "workload": ProposalWorkloadIdentity(
            workloadId=_string(draft, "id"),
            displayName=_string(draft, "displayName"),
            workloadFamily=_string(draft, "workloadFamily"),
            description=_string(draft, "description"),
            classification="publicSafeSynthetic",
            businessCriticality=_unknown(
                "workload business criticality",
                "The research draft forbids a default criticality.",
                source_refs,
            ),
        ).model_dump(by_alias=True, mode="json"),
        "environments": _dump_many(environments),
        "objectives": _dump_many(objectives),
        "roles": _dump_many(roles),
        "dependencies": _dump_many(_dependency_proposals(draft)),
        "relationshipHypotheses": _dump_many(relationships),
        "ownership": _dump_many(ownership),
        "recoveryIntent": _recovery_intent(draft).model_dump(
            by_alias=True, mode="json"
        ),
        "monitoringSemantics": _monitoring_semantics(draft).model_dump(
            by_alias=True, mode="json"
        ),
        "evidenceRequirements": _evidence_requirements(draft, source_refs).model_dump(
            by_alias=True, mode="json"
        ),
        "placementConstraints": _dump_many(_placement_constraint_proposals(draft)),
        "exceptionCandidates": _dump_many(_exception_candidates(draft)),
        "provenance": ProposalProvenance(
            sourceArtifact=WC022_RESEARCH_DRAFT_LOCATION,
            sourceDossier=WC022_SOURCE_DOSSIER,
            sourcePayloadDigest=WC022_REVIEWED_DRAFT_DIGEST,
            sourceDossierDigest=WC022_REVIEWED_DOSSIER_DIGEST,
            sourceRefs=tuple(source_refs),
            conversionBasis="publicSafeConceptsOnly",
        ).model_dump(by_alias=True, mode="json"),
    }
    conversion_payload["proposalDigest"] = compute_artifact_digest(conversion_payload)
    if conversion_payload["proposalDigest"] != WC022_REVIEWED_PROPOSAL_DIGEST:
        raise ResearchDraftConversionError(
            "canonical conversion output does not match the reviewed proposal digest"
        )
    return GovernedWorkloadContextProposal.model_validate(conversion_payload)


def _validate_mapping_boundary(source: Mapping[str, object]) -> None:
    """Bound direct Mapping conversion before inspecting its source shape."""

    item_count = 0
    active_containers: set[int] = set()

    def visit(value: object, depth: int) -> object:
        nonlocal item_count
        if depth > _MAX_RESEARCH_DRAFT_DEPTH:
            raise ResearchDraftConversionError("research draft exceeds its depth bound")
        if isinstance(value, Mapping):
            container_id = id(value)
            if container_id in active_containers:
                raise ResearchDraftConversionError("research draft must not contain cycles")
            active_containers.add(container_id)
            try:
                normalized: dict[str, object] = {}
                for key, child in value.items():
                    item_count += 1
                    if item_count > _MAX_RESEARCH_DRAFT_ITEMS:
                        raise ResearchDraftConversionError(
                            "research draft exceeds its item bound"
                        )
                    if not isinstance(key, str):
                        raise ResearchDraftConversionError("research draft keys must be strings")
                    try:
                        normalized_key = normalize_nfc_text(key)
                    except AthenaValidationError as exc:
                        raise ResearchDraftConversionError(
                            "research draft keys must be valid NFC text"
                        ) from exc
                    if normalized_key in normalized:
                        raise ResearchDraftConversionError(
                            "research draft has duplicate NFC-normalized keys"
                        )
                    normalized[normalized_key] = visit(child, depth + 1)
                return normalized
            finally:
                active_containers.remove(container_id)
        if isinstance(value, (list, tuple)):
            container_id = id(value)
            if container_id in active_containers:
                raise ResearchDraftConversionError("research draft must not contain cycles")
            active_containers.add(container_id)
            try:
                normalized_items: list[object] = []
                for item in value:
                    item_count += 1
                    if item_count > _MAX_RESEARCH_DRAFT_ITEMS:
                        raise ResearchDraftConversionError(
                            "research draft exceeds its item bound"
                        )
                    normalized_items.append(visit(item, depth + 1))
                return normalized_items
            finally:
                active_containers.remove(container_id)
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise ResearchDraftConversionError(
            f"research draft contains unsupported value type {type(value).__name__}"
        )

    try:
        canonical = canonicalize_json(visit(source, 1))
    except ResearchDraftConversionError:
        raise
    except (AthenaValidationError, TypeError, ValueError) as exc:
        raise ResearchDraftConversionError(
            "research draft cannot be represented as canonical JSON"
        ) from exc
    if len(canonical.encode("utf-8")) > _MAX_RESEARCH_DRAFT_BYTES:
        raise ResearchDraftConversionError(
            "research draft exceeds its canonical serialized-size bound"
        )


def _validate_source_shape(source: Mapping[str, object]) -> None:
    _require_exact_keys(source, _ROOT_KEYS, "root")
    _require_exact(source, "schemaStatus", "draft-pre-wc-001")
    _require_exact(source, "runtimeUse", "prohibited")
    _require_exact(source, "loadPolicy", "never-load")
    _require_exact(source, "classification", "public-safe-synthetic-draft")
    _require_exact(source, "createdForIssue", 4)
    _require_exact(source, "sourceDossier", WC022_SOURCE_DOSSIER)
    _require_exact(source, "researchDraftLocation", WC022_RESEARCH_DRAFT_LOCATION)

    redaction_rules = _mapping(source, "redactionRules")
    _require_exact_keys(
        redaction_rules,
        frozenset({"prohibitedContent", "permittedContent"}),
        "redactionRules",
    )
    _strings(redaction_rules, "prohibitedContent")
    _strings(redaction_rules, "permittedContent")

    draft = _mapping(source, "workloadContextDraft")
    _require_exact_keys(draft, _DRAFT_KEYS, "workloadContextDraft")
    for key in (
        "id",
        "displayName",
        "workloadFamily",
        "description",
        "authorityCaveat",
        "assumptionGuardrail",
    ):
        _string(draft, key)
    declared_source_refs = _validate_source_refs(
        _strings(draft, "provenanceRefs"),
        "workloadContextDraft.provenanceRefs",
    )
    _strings(draft, "conversionNotesForWc001")
    _validate_objectives_shape(_mapping(draft, "objectives"))
    _validate_data_boundary_shape(_mapping(draft, "dataBoundary"))
    _validate_environments_shape(
        _mapping(draft, "environments"), declared_source_refs
    )
    _validate_roles_shape(_mapping(draft, "abstractRoles"), declared_source_refs)
    _validate_dependencies_shape(
        _mapping(draft, "dependencyCategories"), declared_source_refs
    )
    _validate_placement_shape(
        _mapping(draft, "placementConstraints"), declared_source_refs
    )
    _validate_relationships_shape(
        _mapping(draft, "relationshipHypotheses"), declared_source_refs
    )
    _validate_monitoring_shape(
        _mapping(draft, "monitoringSemantics"), declared_source_refs
    )
    _validate_ownership_shape(
        _mapping(draft, "ownershipModel"), declared_source_refs
    )
    _validate_recovery_shape(_mapping(draft, "recoveryModel"), declared_source_refs)
    _validate_exception_shape(
        _mapping(draft, "acceptedArchitecturalConstraints"), declared_source_refs
    )


def _validate_objectives_shape(objectives: Mapping[str, object]) -> None:
    _require_exact_keys(objectives, _OBJECTIVE_IDS, "workloadContextDraft.objectives")
    for objective_id in _OBJECTIVE_IDS:
        _string(objectives, objective_id)


def _validate_data_boundary_shape(boundary: Mapping[str, object]) -> None:
    _require_exact_keys(
        boundary,
        frozenset(
            {
                "inBoundaryOnly",
                "noDataEgress",
                "defaultDataRisk",
                "environmentNameDoesNotProveDataClass",
                "declarationRequired",
            }
        ),
        "workloadContextDraft.dataBoundary",
    )
    _require_exact(boundary, "inBoundaryOnly", True)
    _require_exact(boundary, "noDataEgress", True)
    _require_exact(boundary, "defaultDataRisk", "unknown-until-declared")
    _require_exact(boundary, "environmentNameDoesNotProveDataClass", True)
    _strings(boundary, "declarationRequired")


def _validate_environments_shape(
    environments: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        environments,
        frozenset(_ENVIRONMENT_TYPES),
        "workloadContextDraft.environments",
    )
    for environment_name in _ENVIRONMENT_TYPES:
        environment = _mapping(environments, environment_name)
        _require_exact_keys(
            environment,
            _ENVIRONMENT_KEYS,
            f"environment {environment_name}",
        )
        _require_exact(environment, "declarationRequired", True)
        for key in (
            "objective",
            "criticality",
            "recoveryPosture",
            "dependencyCompleteness",
            "dataRisk",
        ):
            _string(environment, key)
        _strings(environment, "monitoringSemantics")
        _validate_source_refs(
            _strings(environment, "supportedBy"),
            f"environment {environment_name} supportedBy",
            declared_source_refs,
        )
        _strings(environment, "unknowns")
        ownership = _mapping(environment, "ownership")
        _require_allowed_keys(
            ownership,
            frozenset({"accountable", "consulted"}),
            f"environment {environment_name} ownership",
            require_non_empty=True,
        )
        for role in ownership:
            _string(ownership, role)


def _validate_roles_shape(
    roles: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        roles,
        frozenset(_ROLE_FIELD_SETS),
        "workloadContextDraft.abstractRoles",
    )
    for role_id, expected_fields in _ROLE_FIELD_SETS.items():
        role = _mapping(roles, role_id)
        _require_exact_keys(role, expected_fields, f"abstract role {role_id}")
        _string(role, "purpose")
        _validate_source_refs(
            _strings(role, "supportedBy"),
            f"abstract role {role_id} supportedBy",
            declared_source_refs,
        )
        if role_id == "clientPresentation":
            _require_exact(role, "examplesAreIllustrativeOnly", True)
            hints = _mapping(role, "discoveryHints")
            _require_exact_keys(hints, frozenset({"tags"}), "clientPresentation discoveryHints")
            _string(hints, "tags")
        elif role_id == "operationalDatabase":
            _string(role, "acceptedConstraint")
            _strings(role, "requiredRiskRecordIfConstrained")
        else:
            detail_key = next(
                key for key in expected_fields if key not in {"purpose", "supportedBy"}
            )
            _string(role, detail_key)


def _validate_dependencies_shape(
    dependencies: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        dependencies,
        frozenset(_DEPENDENCY_DETAIL_FIELDS),
        "workloadContextDraft.dependencyCategories",
    )
    for dependency_id, detail_field in _DEPENDENCY_DETAIL_FIELDS.items():
        dependency = _mapping(dependencies, dependency_id)
        _require_exact_keys(
            dependency,
            frozenset(
                {
                    "status",
                    "declarationRequired",
                    "semantics",
                    detail_field,
                    "supportedBy",
                }
            ),
            f"dependency category {dependency_id}",
        )
        _require_exact(dependency, "status", "candidate-category")
        _require_exact(dependency, "declarationRequired", True)
        _string(dependency, "semantics")
        _string(dependency, detail_field)
        _validate_source_refs(
            _strings(dependency, "supportedBy"),
            f"dependency category {dependency_id} supportedBy",
            declared_source_refs,
        )


def _validate_placement_shape(
    placement: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        placement,
        frozenset(_PLACEMENT_KEYS),
        "workloadContextDraft.placementConstraints",
    )
    for constraint_id, expected_fields in _PLACEMENT_KEYS.items():
        constraint = _mapping(placement, constraint_id)
        _require_exact_keys(
            constraint,
            expected_fields,
            f"placement constraint {constraint_id}",
        )
        _validate_source_refs(
            _strings(constraint, "supportedBy"),
            f"placement constraint {constraint_id} supportedBy",
            declared_source_refs,
        )
        for key in expected_fields - {"supportedBy"}:
            if key == "declarationRequired":
                _require_exact(constraint, key, True)
            else:
                _string(constraint, key)


def _validate_relationships_shape(
    relationships: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        relationships,
        frozenset({"guardrail", "items"}),
        "workloadContextDraft.relationshipHypotheses",
    )
    _string(relationships, "guardrail")
    for relationship in _list(relationships, "items"):
        if not isinstance(relationship, Mapping):
            raise ResearchDraftConversionError("relationship hypothesis must be a mapping")
        _require_exact_keys(
            relationship,
            _RELATIONSHIP_ITEM_KEYS,
            "relationship hypothesis",
        )
        for key in _RELATIONSHIP_ITEM_KEYS - {"humanValidationRequired"}:
            _string(relationship, key)
        _require_exact(relationship, "confidence", "hypothesis-unvalidated")
        _require_exact(relationship, "humanValidationRequired", True)
        _validate_source_refs(
            (_string(relationship, "provenanceCategory"),),
            "relationship hypothesis provenanceCategory",
            declared_source_refs,
        )


def _validate_monitoring_shape(
    monitoring: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        monitoring,
        frozenset(
            {
                "signalIntentOnly",
                "platformEvidenceCategories",
                "workloadEvidenceCategories",
                "prohibitedValues",
                "supportedBy",
            }
        ),
        "workloadContextDraft.monitoringSemantics",
    )
    _require_exact(monitoring, "signalIntentOnly", True)
    for key in (
        "platformEvidenceCategories",
        "workloadEvidenceCategories",
        "prohibitedValues",
        "supportedBy",
    ):
        _strings(monitoring, key)
    _validate_source_refs(
        _strings(monitoring, "supportedBy"),
        "monitoringSemantics supportedBy",
        declared_source_refs,
    )


def _validate_ownership_shape(
    ownership: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        ownership,
        frozenset({"roles", "personalIdentifiers", "supportedBy"}),
        "workloadContextDraft.ownershipModel",
    )
    roles = _mapping(ownership, "roles")
    _require_exact_keys(roles, _OWNERSHIP_ROLE_IDS, "ownershipModel roles")
    for role_id in _OWNERSHIP_ROLE_IDS:
        _string(roles, role_id)
    _string(ownership, "personalIdentifiers")
    _validate_source_refs(
        _strings(ownership, "supportedBy"),
        "ownershipModel supportedBy",
        declared_source_refs,
    )


def _validate_recovery_shape(
    recovery: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        recovery,
        frozenset({"concepts", "supportedBy"}),
        "workloadContextDraft.recoveryModel",
    )
    _strings(recovery, "concepts")
    _validate_source_refs(
        _strings(recovery, "supportedBy"),
        "recoveryModel supportedBy",
        declared_source_refs,
    )


def _validate_exception_shape(
    constraints: Mapping[str, object],
    declared_source_refs: frozenset[str],
) -> None:
    _require_exact_keys(
        constraints,
        frozenset(_EXCEPTION_FIELD_SETS),
        "workloadContextDraft.acceptedArchitecturalConstraints",
    )
    for constraint_id, expected_fields in _EXCEPTION_FIELD_SETS.items():
        constraint = _mapping(constraints, constraint_id)
        _require_exact_keys(
            constraint,
            expected_fields,
            f"accepted architectural constraint {constraint_id}",
        )
        _validate_source_refs(
            _strings(constraint, "supportedBy"),
            f"accepted architectural constraint {constraint_id} supportedBy",
            declared_source_refs,
        )
        for key in expected_fields - {"supportedBy"}:
            if key in {
                "allowedOnlyWhenDeclared",
                "allowedOnlyAsHints",
                "failClosed",
            }:
                _require_exact(constraint, key, True)
            elif key == "requiredFieldsIfDeclared":
                _strings(constraint, key)
            else:
                _string(constraint, key)


def _environment_proposal(
    source_name: str,
    environment: Mapping[str, object],
) -> EnvironmentProposal:
    profile_id, profile_type = _ENVIRONMENT_TYPES[source_name]
    sources = sorted(_strings(environment, "supportedBy"))
    monitoring = [
        _human_decision(
            f"{profile_id} monitoring semantics",
            value,
            sources,
        )
        for value in _strings(environment, "monitoringSemantics")
    ]
    ownership = [
        _human_decision(
            f"{profile_id} {role} ownership",
            value,
            sources,
        )
        for role, value in sorted(_mapping(environment, "ownership").items())
        if isinstance(value, str)
    ]
    return EnvironmentProposal(
        profileId=profile_id,
        profileType=cast(Any, profile_type),
        declarationRequired=True,
        objective=_human_decision(
            f"{profile_id} objective", _string(environment, "objective"), sources
        ),
        criticality=_unknown(
            f"{profile_id} criticality", _string(environment, "criticality"), sources
        ),
        recoveryIntent=_human_decision(
            f"{profile_id} recovery intent", _string(environment, "recoveryPosture"), sources
        ),
        dependencyScope=_human_decision(
            f"{profile_id} dependency scope",
            _string(environment, "dependencyCompleteness"),
            sources,
        ),
        dataClassification=_unknown(
            f"{profile_id} data classification", _string(environment, "dataRisk"), sources
        ),
        monitoringSemantics=tuple(monitoring),
        ownership=tuple(ownership),
        unknowns=tuple(
            _unknown(f"{profile_id} unknown", value, sources)
            for value in _strings(environment, "unknowns")
        ),
        sourceRefs=tuple(sources),
    )


def _role_proposal(role_id: str, role: Mapping[str, object]) -> RoleProposal:
    sources = sorted(_strings(role, "supportedBy"))
    discovery_hints = role.get("discoveryHints")
    hint = (
        _human_decision(
            f"{role_id} discovery hint",
            _string(_mapping(role, "discoveryHints"), "tags"),
            sources,
        )
        if isinstance(discovery_hints, Mapping)
        else None
    )
    return RoleProposal(
        roleId=role_id,
        purpose=_string(role, "purpose"),
        candidateStatus="humanApprovalRequired",
        runtimeRoleKind=_human_decision(
            f"{role_id} runtime role kind",
            "A canonical WC-001 role kind must be selected by a human owner.",
            sources,
        ),
        discoveryHint=hint,
        sourceDecisions=tuple(
            _mapping_decisions(
                role_id,
                role,
                sources,
                excluded={"purpose", "discoveryHints", "supportedBy"},
            )
        ),
        sourceRefs=tuple(sources),
    )


def _dependency_proposals(
    draft: Mapping[str, object],
) -> list[DependencyCategoryProposal]:
    dependencies = _mapping(draft, "dependencyCategories")
    result: list[DependencyCategoryProposal] = []
    for dependency_id in sorted(dependencies):
        item = _mapping(dependencies, dependency_id)
        sources = list(_strings(item, "supportedBy"))
        decisions = _mapping_decisions(
            dependency_id,
            item,
            sources,
            excluded={"status", "declarationRequired", "semantics", "supportedBy"},
        )
        decisions.insert(
            0,
            _human_decision(
                f"{dependency_id} declaration",
                "The candidate dependency category requires a human declaration.",
                sources,
            ),
        )
        result.append(
            DependencyCategoryProposal(
                dependencyId=dependency_id,
                semantics=_string(item, "semantics"),
                humanDecisions=tuple(decisions),
                sourceRefs=tuple(sources),
            )
        )
    return result


def _relationship_proposal(relationship: Mapping[str, object]) -> RelationshipHypothesisProposal:
    sources = [_string(relationship, "provenanceCategory")]
    return RelationshipHypothesisProposal(
        relationshipId=_string(relationship, "id"),
        sourceRoleRef=_string(relationship, "sourceRole"),
        targetRoleRef=_string(relationship, "targetRole"),
        relationshipCategory=_string(relationship, "relationshipCategory"),
        intent=_string(relationship, "intent"),
        candidateStatus="humanApprovalRequired",
        environmentScope=_human_decision(
            "relationship environment scope",
            _string(relationship, "environmentScope"),
            sources,
        ),
        semantics=_unknown(
            "relationship semantics",
            _string(relationship, "unknownState"),
            sources,
        ),
        humanValidationRequired=True,
        sourceRefs=tuple(sources),
    )


def _recovery_intent(
    draft: Mapping[str, object],
) -> RecoveryIntentProposal:
    recovery = _mapping(draft, "recoveryModel")
    sources = list(_require_source_refs(_strings(recovery, "supportedBy")))
    return RecoveryIntentProposal(
        concepts=_strings(recovery, "concepts"),
        targetValues=(
            _human_decision(
                "recovery objectives",
                "RTO, RPO, failover readiness, and alternate capacity require human declaration.",
                sources,
            ),
        ),
    )


def _monitoring_semantics(
    draft: Mapping[str, object],
) -> MonitoringSemanticsProposal:
    monitoring = _mapping(draft, "monitoringSemantics")
    sources = list(_require_source_refs(_strings(monitoring, "supportedBy")))
    return MonitoringSemanticsProposal(
        signalIntentOnly=True,
        platformEvidenceCategories=_strings(monitoring, "platformEvidenceCategories"),
        workloadEvidenceCategories=tuple(
            _human_decision("workload evidence category", value, sources)
            for value in _strings(monitoring, "workloadEvidenceCategories")
        ),
        prohibitedValues=_strings(monitoring, "prohibitedValues"),
    )


def _evidence_requirements(
    draft: Mapping[str, object],
    source_refs: list[str],
) -> EvidenceRequirementsProposal:
    boundary = _mapping(draft, "dataBoundary")
    monitoring = _mapping(draft, "monitoringSemantics")
    return EvidenceRequirementsProposal(
        declaredAndObservedSeparate=True,
        evidencePlane="privateAzureMcpReadOnly",
        requiredCategories=tuple(
            sorted(
                {
                    *_strings(boundary, "declarationRequired"),
                    *_strings(monitoring, "platformEvidenceCategories"),
                }
            )
        ),
        freshnessAndScope=_human_decision(
            "evidence freshness and scope",
            "Customer-specific evidence scope and freshness limits are not in the public draft.",
            source_refs,
        ),
        detailedProvenance=_human_decision(
            "detailed evidence provenance",
            "Detailed provenance remains in the approved private evidence system.",
            source_refs,
        ),
    )


def _placement_constraint_proposals(
    draft: Mapping[str, object],
) -> list[PlacementConstraintProposal]:
    constraints = _mapping(draft, "placementConstraints")
    result: list[PlacementConstraintProposal] = []
    for constraint_id in sorted(constraints):
        item = _mapping(constraints, constraint_id)
        sources = sorted(_strings(item, "supportedBy"))
        result.append(
            PlacementConstraintProposal(
                constraintId=constraint_id,
                humanDecisions=tuple(
                    _mapping_decisions(
                        constraint_id,
                        item,
                        sources,
                        excluded={"declarationRequired", "supportedBy"},
                    )
                ),
                sourceRefs=tuple(sources),
            )
        )
    return result


def _exception_candidates(
    draft: Mapping[str, object],
) -> list[ExceptionCandidate]:
    constraints = _mapping(draft, "acceptedArchitecturalConstraints")
    result: list[ExceptionCandidate] = []
    for exception_id in sorted(constraints):
        item = _mapping(constraints, exception_id)
        sources = sorted(_strings(item, "supportedBy"))
        required = (
            _strings(item, "requiredFieldsIfDeclared")
            if "requiredFieldsIfDeclared" in item
            else []
        )
        if not required:
            required = [
                key for key in ("failClosed", "action") if key in item
            ]
        result.append(
            ExceptionCandidate(
                exceptionId=exception_id,
                candidateStatus="humanApprovalRequired",
                requiredDeclarations=tuple(required),
                humanReview=_human_decision(
                    f"{exception_id} human review",
                    (
                        "No exception in the research draft is approved for publication "
                        "or runtime use."
                    ),
                    sources,
                ),
                sourceRefs=tuple(sources),
            )
        )
    return result


def _dump_many(values: list[Any]) -> list[dict[str, object]]:
    return [
        value.model_dump(by_alias=True, exclude_none=True, mode="json")
        for value in values
    ]


def _mapping_decisions(
    subject: str,
    source: Mapping[str, object],
    source_refs: list[str],
    *,
    excluded: set[str],
) -> list[HumanDecision]:
    decisions: list[HumanDecision] = []
    for key in sorted(source):
        if key in excluded:
            continue
        value = source[key]
        decisions.extend(
            _value_decisions(
                f"{subject} {key}",
                value,
                source_refs,
            )
        )
    if not decisions:
        decisions.append(
            _human_decision(
                subject,
                "The public-safe source requires a human declaration.",
                source_refs,
            )
        )
    return decisions


def _value_decisions(
    subject: str,
    value: object,
    source_refs: list[str],
) -> list[HumanDecision]:
    if isinstance(value, str):
        return [_human_decision(subject, value, source_refs)]
    if isinstance(value, bool):
        return [_human_decision(subject, str(value).lower(), source_refs)]
    if isinstance(value, (list, tuple)):
        decisions: list[HumanDecision] = []
        for index, item in enumerate(sorted(value, key=canonicalize_json), start=1):
            decisions.extend(_value_decisions(f"{subject} {index}", item, source_refs))
        return decisions
    if isinstance(value, Mapping):
        nested_decisions: list[HumanDecision] = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise ResearchDraftConversionError("research draft keys must be strings")
            nested_decisions.extend(
                _value_decisions(f"{subject} {key}", value[key], source_refs)
            )
        return nested_decisions
    raise ResearchDraftConversionError(f"research draft {subject} has an unsupported value")


def _unknown(subject: str, rationale: str, source_refs: list[str]) -> UnknownValue:
    return UnknownValue(
        subject=subject,
        rationale=rationale,
        sourceRefs=_require_source_refs(source_refs),
    )


def _human_decision(
    subject: str,
    rationale: str,
    source_refs: list[str],
) -> HumanDecision:
    return HumanDecision(
        subject=subject,
        rationale=rationale,
        sourceRefs=_require_source_refs(source_refs),
    )


def _require_exact(source: Mapping[str, object], key: str, expected: object) -> None:
    if source.get(key) != expected:
        raise ResearchDraftConversionError(f"research draft {key} must be {expected!r}")


def _require_exact_keys(
    source: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    keys = tuple(source)
    if any(not isinstance(key, str) for key in keys):
        raise ResearchDraftConversionError(f"research draft {label} keys must be strings")
    actual = frozenset(cast(str, key) for key in keys)
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unexpected or missing:
        detail = []
        if unexpected:
            detail.append(f"unexpected keys: {', '.join(unexpected)}")
        if missing:
            detail.append(f"missing keys: {', '.join(missing)}")
        raise ResearchDraftConversionError(
            f"research draft {label} has an unreviewed shape ({'; '.join(detail)})"
        )


def _require_allowed_keys(
    source: Mapping[str, object],
    allowed: frozenset[str],
    label: str,
    *,
    require_non_empty: bool = False,
) -> None:
    keys = tuple(source)
    if any(not isinstance(key, str) for key in keys):
        raise ResearchDraftConversionError(f"research draft {label} keys must be strings")
    actual = frozenset(cast(str, key) for key in keys)
    unexpected = sorted(actual - allowed)
    if unexpected:
        raise ResearchDraftConversionError(
            f"research draft {label} has an unreviewed shape "
            f"(unexpected keys: {', '.join(unexpected)})"
        )
    if require_non_empty and not actual:
        raise ResearchDraftConversionError(f"research draft {label} must not be empty")


def _mapping(source: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        raise ResearchDraftConversionError(f"research draft {key} must be a mapping")
    return value


def _list(source: Mapping[str, object], key: str) -> list[object]:
    value = source.get(key)
    if not isinstance(value, (list, tuple)):
        raise ResearchDraftConversionError(f"research draft {key} must be an array")
    return list(value)


def _string(source: Mapping[str, object], key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ResearchDraftConversionError(f"research draft {key} must be a non-empty string")
    return value


def _strings(source: Mapping[str, object], key: str) -> tuple[str, ...]:
    values = _list(source, key)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ResearchDraftConversionError(f"research draft {key} must contain non-empty strings")
    return tuple(sorted(cast(str, value) for value in values))


def _validate_source_refs(
    source_refs: tuple[str, ...],
    label: str,
    declared_source_refs: frozenset[str] | None = None,
) -> frozenset[str]:
    refs = _require_source_refs(source_refs)
    normalized_refs: list[str] = []
    for source_ref in refs:
        try:
            normalized = normalize_nfc_text(source_ref)
        except AthenaValidationError as exc:
            raise ResearchDraftConversionError(
                f"research draft {label} contains an invalid source reference"
            ) from exc
        if normalized != source_ref or _SAFE_SOURCE_REF_RE.fullmatch(source_ref) is None:
            raise ResearchDraftConversionError(
                f"research draft {label} contains an invalid source reference"
            )
        normalized_refs.append(normalized.casefold())
    if len(set(normalized_refs)) != len(normalized_refs):
        raise ResearchDraftConversionError(
            f"research draft {label} source references must be unique"
        )
    resolved_refs = frozenset(refs)
    if declared_source_refs is not None:
        unknown_refs = sorted(resolved_refs - declared_source_refs)
        if unknown_refs:
            raise ResearchDraftConversionError(
                f"research draft {label} has unknown source references: "
                f"{', '.join(unknown_refs)}"
            )
    return resolved_refs


def _require_source_refs(source_refs: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not source_refs:
        raise ResearchDraftConversionError(
            "research draft conversion requires explicit source references"
        )
    return tuple(source_refs)


def _sorted_mappings(values: list[object], key: str) -> list[Mapping[str, object]]:
    mappings: list[Mapping[str, object]] = []
    for value in values:
        if not isinstance(value, Mapping):
            raise ResearchDraftConversionError("research draft item must be a mapping")
        mappings.append(value)
    return sorted(mappings, key=lambda value: _string(value, key))


def _content_digest(content: bytes) -> str:
    return f"sha256:{sha256(content).hexdigest()}"


__all__ = [
    "ResearchDraftConversionError",
    "convert_canonical_public_safe_research_draft",
]
