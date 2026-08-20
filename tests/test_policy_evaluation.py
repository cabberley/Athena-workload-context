from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from athena_context import (
    evaluate_manifest_profile as evaluate_root_profile,
)
from athena_context import (
    evaluate_policy as evaluate_root_policy,
)
from athena_context import (
    evaluate_profile as evaluate_root_profile_alias,
)
from athena_context.contracts import (
    AthenaValidationError,
    CompatibilityMetadata,
    compute_artifact_digest,
)
from athena_context.contracts.manifest import (
    BackupControl,
    CanonicalWorkloadManifest,
    ClauseScope,
    ControlProofFact,
    DeclaredManifestRelationship,
    EvidenceReferenceContext,
    ExceptionManifestRelationship,
    ManifestConstraint,
    ManifestFinding,
    ManifestObjective,
    ManifestOwner,
    ManifestRiskAcceptance,
    ManifestRole,
    ObjectiveProofFact,
    RelationshipProofFact,
    ResolvedManifestProfile,
    ResourceProofFact,
    RoleBindingProof,
    RoleOperationalStateProof,
    canonicalize_manifest_payload,
    resolve_manifest_profile,
)
from athena_context.contracts.manifest import (
    evaluate_manifest_profile as evaluate_contract_profile,
)
from athena_context.contracts.models import (
    EvidenceGapRef,
    EvidenceItemRef,
    ProducerInfo,
    ResourceGroupScope,
    ResourceState,
)
from athena_context.policy import (
    evaluate_manifest_profile as evaluate_policy_profile,
)
from athena_context.policy import (
    evaluate_policy,
    evaluate_profile,
)

AS_OF = datetime(2026, 8, 16, tzinfo=UTC)
MANIFEST_ID = "wl-synthetic-policy-unit"
SNAPSHOT_ID = "snap-111111111111"
SNAPSHOT_ARTIFACT_DIGEST = "sha256:" + "a" * 64
SNAPSHOT_SEMANTIC_DIGEST = "sha256:" + "b" * 64
RESOURCE_PREFIX = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-policy-unit/providers/Microsoft.Compute/"
    "virtualMachines/"
)
RESOURCE_IDS = {
    "database-primary": [RESOURCE_PREFIX + "synthetic-db-01"],
    "worker": [
        RESOURCE_PREFIX + "synthetic-worker-01",
        RESOURCE_PREFIX + "synthetic-worker-02",
    ],
    "web": [
        RESOURCE_PREFIX + "synthetic-web-01",
        RESOURCE_PREFIX + "synthetic-web-02",
    ],
}


def _scope(profile_id: str, clause_id: str) -> ClauseScope:
    return ClauseScope(
        governanceScopeType="clause",
        manifestId=MANIFEST_ID,
        profileId=profile_id,
        clausePath=f"/constraints/{clause_id}",
        ownerRef="owner-operations",
    )


def _constraint(
    profile_id: str,
    clause_id: str,
    constraint_type: str,
    finding_kind: str,
    proof: dict[str, object],
    success_verdict: str,
    *,
    risk_acceptance_ref: str | None = None,
    risk_acceptance_clause_ref: str | None = None,
) -> ManifestConstraint:
    payload: dict[str, object] = {
        "constraintId": clause_id,
        "constraintType": constraint_type,
        "findingKind": finding_kind,
        "governanceScope": _scope(profile_id, clause_id),
        "ownerRef": "owner-operations",
        "profiles": [profile_id],
        "proofRequirement": proof,
        "failureVerdict": "violation",
        "successVerdict": success_verdict,
        "protected": clause_id
        in {
            "db-singleton-supported",
            "db-zone-loss-spof",
            "db-zone-loss-acceptance",
            "worker-db-zone-colocation",
            "web-zone-distribution",
        },
    }
    if risk_acceptance_ref is not None:
        payload["riskAcceptanceRef"] = risk_acceptance_ref
    if risk_acceptance_clause_ref is not None:
        payload["riskAcceptanceClauseRef"] = risk_acceptance_clause_ref
    return ManifestConstraint.model_validate(payload)


def _role(role_id: str, kind: str, cardinality: str) -> ManifestRole:
    return ManifestRole.model_validate(
        {
            "roleId": role_id,
            "kind": kind,
            "cardinality": {"cardinalityKind": cardinality},
            "selectors": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": f"{role_id}-selector",
                    "prefix": f"synthetic-{role_id.split('-')[0]}-",
                    "maxMatches": 10,
                }
            ],
            "ownerRef": "owner-operations",
            "status": "approved",
        }
    )


def _compatibility() -> CompatibilityMetadata:
    return CompatibilityMetadata(
        artifactKind="workloadManifest",
        schemaVersion="1.0.0",
        semanticContractVersion="1.0.0",
        policyContractVersion="1.0.0",
        minimumReaderVersion="1.0.0",
        requiresCapabilities=[],
        producedBy=ProducerInfo(
            producerId="athena.policy.tests",
            version="1.0.0",
        ),
        extensionPolicy="rejectUnknownDecisionFields",
        artifactDigest="sha256:" + "0" * 64,
        semanticDigest="sha256:" + "0" * 64,
    )


def _relationship(
    profile_id: str,
    relationship_id: str,
    kind: str,
    source_role: str,
    target_role: str,
    clause_id: str,
) -> DeclaredManifestRelationship:
    return DeclaredManifestRelationship.model_validate(
        {
            "relationshipClass": "declared",
            "relationshipId": relationship_id,
            "kind": kind,
            "source": {"endpointType": "role", "roleRef": source_role},
            "target": {"endpointType": "role", "roleRef": target_role},
            "ownerRef": "owner-operations",
            "profiles": [profile_id],
            "sourceClause": f"/constraints/{clause_id}",
        }
    )


def _acceptance(profile_id: str) -> ManifestRiskAcceptance:
    return ManifestRiskAcceptance.model_validate(
        {
            "riskAcceptanceId": f"ra-db-zone-loss-{profile_id}",
            "governanceScope": _scope(profile_id, "db-zone-loss-spof"),
            "riskKind": "availability",
            "riskRating": "high",
            "residualRiskStatement": (
                "A zone loss interrupts the synthetic singleton database."
            ),
            "rationaleRef": "synthetic://approval/db-zone-loss",
            "acceptedBy": "synthetic-approver",
            "ownedBy": "owner-operations",
            "acceptedAt": "2026-01-01T00:00:00.000Z",
            "expiresAt": "2027-01-01T00:00:00.000Z",
            "linkedControlRefs": ["backup-control"],
            "acceptedResourceBindings": [
                {
                    "roleRef": "database-primary",
                    "resourceId": RESOURCE_IDS["database-primary"][0],
                }
            ],
            "profiles": [profile_id],
            "status": "approved",
        }
    )


def _clause_acceptance(
    profile_id: str,
    acceptance_id: str,
    clause_id: str,
    bindings: list[tuple[str, str]],
) -> ManifestRiskAcceptance:
    return ManifestRiskAcceptance.model_validate(
        {
            "riskAcceptanceId": acceptance_id,
            "governanceScope": _scope(profile_id, clause_id),
            "riskKind": "availability",
            "riskRating": "medium",
            "residualRiskStatement": "A synthetic scoped policy deviation remains.",
            "rationaleRef": f"synthetic://approval/{acceptance_id}",
            "acceptedBy": "synthetic-approver",
            "ownedBy": "owner-operations",
            "acceptedAt": "2026-01-01T00:00:00.000Z",
            "expiresAt": "2027-01-01T00:00:00.000Z",
            "linkedControlRefs": [],
            "acceptedResourceBindings": [
                {"roleRef": role_ref, "resourceId": resource_id}
                for role_ref, resource_id in bindings
            ],
            "profiles": [profile_id],
            "status": "approved",
        }
    )


def _profile_payload(profile_id: str) -> dict[str, object]:
    web_zones = {"production": 2, "development": 1, "training": 3}[profile_id]
    continuity_required = profile_id != "development"
    acceptance_ref = (
        f"ra-db-zone-loss-{profile_id}" if continuity_required else None
    )
    relationships = [
        _relationship(
            profile_id,
            "worker-requires-database",
            "requires",
            "worker",
            "database-primary",
            "worker-database-required",
        ),
        _relationship(
            profile_id,
            "web-database-prohibited",
            "prohibited",
            "web",
            "database-primary",
            "web-database-prohibited",
        ),
    ]
    constraints = [
        _constraint(
            profile_id,
            "db-singleton-supported",
            "supportedSingleton",
            "technologyConstraint",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "database-primary",
                "expected": {"cardinalityKind": "exactlyOne"},
            },
            "expectedConstraint",
        ),
        _constraint(
            profile_id,
            "db-zone-loss-spof",
            "supportedSingleton",
            "actualSpof",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "database-primary",
                "expected": {"cardinalityKind": "exactlyOne"},
            },
            "observation",
            risk_acceptance_ref=acceptance_ref,
        ),
        _constraint(
            profile_id,
            "db-zone-loss-acceptance",
            "supportedSingleton",
            "riskAcceptance",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "database-primary",
                "expected": {"cardinalityKind": "exactlyOne"},
            },
            "observation",
            risk_acceptance_ref=acceptance_ref,
            risk_acceptance_clause_ref=(
                "db-zone-loss-spof" if acceptance_ref is not None else None
            ),
        ),
        _constraint(
            profile_id,
            "worker-db-zone-colocation",
            "zoneColocation",
            "architectureConstraint",
            {
                "proofKind": "zoneColocationProof",
                "subjectRoleRef": "worker",
                "anchorRoleRef": "database-primary",
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "web-zone-distribution",
            "zoneDistribution",
            "architectureConstraint",
            {
                "proofKind": "zoneDistributionProof",
                "roleRef": "web",
                "minimumDistinctZones": web_zones,
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "worker-database-required",
            "dependencyRequired",
            "architectureConstraint",
            {
                "proofKind": "relationshipPresenceProof",
                "declaredRelationshipRef": "worker-requires-database",
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "web-database-prohibited",
            "dependencyProhibited",
            "relationshipConflict",
            {
                "proofKind": "relationshipPresenceProof",
                "declaredRelationshipRef": "web-database-prohibited",
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "backup-control-health",
            "controlRequired",
            "controlHealth",
            {
                "proofKind": "controlHealthProof",
                "controlRef": "backup-control",
                "requiredHealth": "effective",
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "evidence-freshness",
            "evidenceFreshness",
            "evidenceGap",
            {
                "proofKind": "evidenceFreshnessProof",
                "maximumAgeSeconds": 7200,
            },
            "pass",
        ),
        _constraint(
            profile_id,
            "availability-objective",
            "objectiveRequired",
            "objective",
            {
                "proofKind": "objectiveThresholdProof",
                "objectiveRef": "availability-slo",
                "comparison": "gte",
                "threshold": 99.9,
            },
            "pass",
        ),
    ]
    controls = [
        BackupControl.model_validate(
            {
                "controlKind": "backup",
                "controlId": "backup-control",
                "governanceScope": _scope(profile_id, "db-zone-loss-spof"),
                "ownerRef": "owner-operations",
                "profiles": [profile_id],
                "health": "effective",
                "backupPolicyRef": "synthetic://backup/policy",
                "lastSuccessfulBackupAt": "2026-08-15T20:00:00.000Z",
                "evidenceRefs": ["synthetic-backup-evidence"],
            }
        )
    ]
    objectives = [
        ManifestObjective(
            objectiveId="availability-slo",
            objectiveType="availabilitySlo",
            ownerRef="owner-operations",
            target=99.9,
        )
    ]
    return {
        "profileId": profile_id,
        "profileType": profile_id,
        "settings": {
            "continuity": {
                "zoneLossContinuityRequired": continuity_required,
            }
        },
        "relationships": [
            relationship.model_dump(mode="json", by_alias=True, exclude_none=True)
            for relationship in relationships
        ],
        "constraints": [
            constraint.model_dump(mode="json", by_alias=True, exclude_none=True)
            for constraint in constraints
        ],
        "controls": [
            control.model_dump(mode="json", by_alias=True, exclude_none=True)
            for control in controls
        ],
        "riskAcceptances": [
            acceptance.model_dump(mode="json", by_alias=True, exclude_none=True)
            for acceptance in (
                [_acceptance(profile_id)] if continuity_required else []
            )
        ],
        "objectives": [
            objective.model_dump(mode="json", by_alias=True, exclude_none=True)
            for objective in objectives
        ],
    }


def _canonical_manifest_payload() -> dict[str, object]:
    return {
        "manifestId": MANIFEST_ID,
        "manifestVersion": "1.0.0",
        "cloud": "azureCloud",
        "workload": {
            "displayName": "Synthetic policy unit workload",
            "environments": ["production", "development", "training"],
            "allowedEvidenceScopes": [
                _evidence_scope().model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ],
        },
        "profiles": {
            profile_id: _profile_payload(profile_id)
            for profile_id in ("production", "development", "training")
        },
        "roles": [
            role.model_dump(mode="json", by_alias=True, exclude_none=True)
            for role in (
                _role("database-primary", "singletonDatabase", "exactlyOne"),
                _role("worker", "worker", "oneOrMore"),
                _role("web", "webService", "oneOrMore"),
            )
        ],
        "ownership": [
            ManifestOwner(
                ownerRef="owner-operations",
                ownerRole="operationsOwner",
                authorityRef="synthetic://team/operations",
            ).model_dump(mode="json", by_alias=True, exclude_none=True)
        ],
        "compatibility": _compatibility().model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "audit": {
            "publishedBy": "human-approved-context-api",
            "publishedAt": "2026-01-01T00:00:00.000Z",
            "approvalStatus": "approved",
        },
    }


def _resolve_payload(
    payload: dict[str, object],
    profile_id: str,
) -> ResolvedManifestProfile:
    manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    return resolve_manifest_profile(manifest, profile_id, as_of=AS_OF)


def _resolved_profile(profile_id: str) -> ResolvedManifestProfile:
    return _resolve_payload(_canonical_manifest_payload(), profile_id)


def _evidence_scope() -> ResourceGroupScope:
    return ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId="00000000-0000-0000-0000-000000000000",
        subscriptionId="00000000-0000-0000-0000-000000000000",
        resourceGroupName="rg-athena-policy-unit",
    )


def _resign_profile(profile: ResolvedManifestProfile) -> ResolvedManifestProfile:
    artifact_digest = profile.recompute_artifact_digest()
    semantic_digest = profile.recompute_semantic_digest()
    object.__setattr__(profile.compatibility, "artifact_digest", artifact_digest)
    object.__setattr__(profile.compatibility, "semantic_digest", semantic_digest)
    object.__setattr__(profile, "resolved_profile_digest", semantic_digest)
    return ResolvedManifestProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def _item_ref(index: int) -> EvidenceItemRef:
    return EvidenceItemRef(
        refType="evidenceItem",
        snapshotId=SNAPSHOT_ID,
        snapshotArtifactDigest=SNAPSHOT_ARTIFACT_DIGEST,
        snapshotSemanticDigest=SNAPSHOT_SEMANTIC_DIGEST,
        itemDigest="sha256:" + f"{index + 1:064x}",
        collectorAttemptId=f"attempt-{index + 1:012x}",
        collectorAttemptDigest="sha256:" + f"{index + 101:064x}",
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime(2026, 8, 15, 23, tzinfo=UTC),
        collectorIdentityEvidenceRef="identity-111111111111",
        sourceResponseDigest="sha256:" + f"{index + 201:064x}",
        sourceResponsePointer=f"/value/{index}",
    )


def _gap_ref(index: int, reason: str) -> EvidenceGapRef:
    return EvidenceGapRef.model_validate(
        {
            "refType": "evidenceGap",
            "snapshotId": SNAPSHOT_ID,
            "snapshotArtifactDigest": SNAPSHOT_ARTIFACT_DIGEST,
            "snapshotSemanticDigest": SNAPSHOT_SEMANTIC_DIGEST,
            "gapId": f"gap-{index + 1:012x}",
            "gapRecordDigest": "sha256:" + f"{index + 301:064x}",
            "evidenceScope": _evidence_scope(),
            "expectedRecordType": "resource",
            "collectorAttemptId": f"attempt-{index + 201:012x}",
            "collectorAttemptDigest": "sha256:" + f"{index + 401:064x}",
            "collectorToolName": "azure.resourceInventory.read",
            "collectorToolVersion": "1.0.0",
            "collectorAttemptAt": datetime(2026, 8, 15, 23, tzinfo=UTC),
            "collectorIdentityEvidenceRef": "identity-111111111111",
            "gapReason": reason,
        }
    )


def _binding(role_ref: str) -> RoleBindingProof:
    selected = RESOURCE_IDS[role_ref]
    return RoleBindingProof(
        roleRef=role_ref,
        selectedResourceIds=selected,
        selectorResultDigest=compute_artifact_digest(
            sorted(selected, key=str.casefold)
        ),
        state="complete",
    )


def _evidence(profile: ResolvedManifestProfile) -> EvidenceReferenceContext:
    resources = [
        ResourceProofFact(
            resourceId=RESOURCE_IDS["database-primary"][0],
            roleRef="database-primary",
            availabilityZone="1",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(0),
        ),
        ResourceProofFact(
            resourceId=RESOURCE_IDS["worker"][0],
            roleRef="worker",
            availabilityZone="1",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(1),
        ),
        ResourceProofFact(
            resourceId=RESOURCE_IDS["worker"][1],
            roleRef="worker",
            availabilityZone="1",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(2),
        ),
        ResourceProofFact(
            resourceId=RESOURCE_IDS["web"][0],
            roleRef="web",
            availabilityZone="1",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(3),
        ),
        ResourceProofFact(
            resourceId=RESOURCE_IDS["web"][1],
            roleRef="web",
            availabilityZone="2",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(4),
        ),
    ]
    return EvidenceReferenceContext(
        snapshotId=SNAPSHOT_ID,
        snapshotArtifactDigest=SNAPSHOT_ARTIFACT_DIGEST,
        snapshotSemanticDigest=SNAPSHOT_SEMANTIC_DIGEST,
        collectedAt=datetime(2026, 8, 15, 22, tzinfo=UTC),
        expiresAt=datetime(2026, 8, 17, tzinfo=UTC),
        authorizedScopes=[_evidence_scope()],
        manifestId=MANIFEST_ID,
        profileId=profile.profile_id,
        resolvedProfileDigest=profile.resolved_profile_digest,
        resources=resources,
        relationships=[
            RelationshipProofFact(
                relationshipRef="worker-requires-database",
                state="complete",
                proofSource="observed",
                presence="present",
                evidenceRef=_item_ref(5),
            ),
            RelationshipProofFact(
                relationshipRef="web-database-prohibited",
                state="complete",
                proofSource="observed",
                presence="absent",
                evidenceRef=_item_ref(6),
            ),
        ],
        controls=[
            ControlProofFact(
                controlRef="backup-control",
                state="complete",
                health="effective",
                evidenceRef=_item_ref(7),
            )
        ],
        objectives=[
            ObjectiveProofFact(
                objectiveRef="availability-slo",
                state="complete",
                currentValue=99.95,
                evidenceRef=_item_ref(8),
            )
        ],
        roleBindings=[
            _binding("database-primary"),
            _binding("worker"),
            _binding("web"),
        ],
    )


def _verify_unit_evidence(
    evidence: EvidenceReferenceContext,
    as_of: datetime,
) -> None:
    if (
        as_of != AS_OF
        or evidence.snapshot_id != SNAPSHOT_ID
        or evidence.snapshot_artifact_digest != SNAPSHOT_ARTIFACT_DIGEST
        or evidence.snapshot_semantic_digest != SNAPSHOT_SEMANTIC_DIGEST
    ):
        raise AthenaValidationError("unit evidence context was not verified")
    resources_by_role: dict[str, list[str]] = {}
    for resource in evidence.resources:
        resources_by_role.setdefault(resource.role_ref, []).append(resource.resource_id)
    for binding in evidence.role_bindings:
        selected = sorted(binding.selected_resource_ids, key=str.casefold)
        actual = sorted(resources_by_role.get(binding.role_ref, []), key=str.casefold)
        if (
            selected != actual
            or binding.selector_result_digest != compute_artifact_digest(selected)
        ):
            raise AthenaValidationError("unit selector binding was not verified")


OPERATIONAL_CLAUSE_ID = "web-service-operational-state"


def _operational_constraint(
    profile_id: str,
    minimum_healthy: int,
    *,
    failure_states: tuple[ResourceState, ...] = ("stopped", "deallocated"),
) -> ManifestConstraint:
    return ManifestConstraint.model_validate(
        {
            "constraintId": OPERATIONAL_CLAUSE_ID,
            "constraintType": "roleOperationalState",
            "findingKind": "operationalState",
            "governanceScope": _scope(profile_id, OPERATIONAL_CLAUSE_ID),
            "ownerRef": "owner-operations",
            "profiles": [profile_id],
            "proofRequirement": {
                "proofKind": "roleOperationalStateProof",
                "roleRef": "web",
                "healthyStates": ["running"],
                "failureStates": list(failure_states),
                "minimumHealthy": minimum_healthy,
            },
            "failureVerdict": "violation",
            "successVerdict": "pass",
        }
    )


def _operational_profile(
    profile_id: str,
    minimum_healthy: int,
    *,
    failure_states: tuple[ResourceState, ...] = ("stopped", "deallocated"),
) -> ResolvedManifestProfile:
    profile = _resolved_profile(profile_id)
    profile.constraints.append(
        _operational_constraint(
            profile_id,
            minimum_healthy,
            failure_states=failure_states,
        )
    )
    return _resign_profile(profile)


def _operational_evidence(
    profile: ResolvedManifestProfile,
    states: tuple[ResourceState, ...],
) -> EvidenceReferenceContext:
    evidence = _evidence(profile)
    web_facts = sorted(
        (
            fact
            for fact in evidence.resources
            if fact.role_ref == "web"
        ),
        key=lambda fact: fact.resource_id.casefold(),
    )
    if not 1 <= len(states) <= 3:
        raise AssertionError("operational-state tests support one to three web resources")

    updated_web_facts: list[ResourceProofFact] = []
    zones = ("1", "2", "3")
    for index, operational_state in enumerate(states):
        if index < len(web_facts):
            updated_web_facts.append(
                web_facts[index].model_copy(
                    update={"operational_state": operational_state},
                )
            )
            continue
        updated_web_facts.append(
            ResourceProofFact(
                resourceId=RESOURCE_PREFIX + f"synthetic-web-{index + 1:02d}",
                roleRef="web",
                availabilityZone=zones[index],
                operationalState=operational_state,
                state="complete",
                proofSource="observed",
                evidenceRef=_item_ref(9 + index - len(web_facts)),
            )
        )

    evidence.resources = [
        fact for fact in evidence.resources if fact.role_ref != "web"
    ] + updated_web_facts
    web_binding = next(
        binding for binding in evidence.role_bindings if binding.role_ref == "web"
    )
    selected_ids = sorted(
        (fact.resource_id for fact in updated_web_facts),
        key=str.casefold,
    )
    web_binding.selected_resource_ids = selected_ids
    web_binding.selector_result_digest = compute_artifact_digest(selected_ids)
    return EvidenceReferenceContext.model_validate(
        evidence.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def _operational_finding(
    profile: ResolvedManifestProfile,
    evidence: EvidenceReferenceContext,
) -> ManifestFinding:
    return evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )[OPERATIONAL_CLAUSE_ID]


def test_role_operational_state_contract_is_serialized_and_legacy_facts_fail_closed() -> None:
    proof = RoleOperationalStateProof(
        proofKind="roleOperationalStateProof",
        roleRef="web",
        healthyStates=["running"],
        failureStates=["stopped", "deallocated"],
        minimumHealthy=2,
    )

    assert proof.model_dump(mode="json", by_alias=True) == {
        "proofKind": "roleOperationalStateProof",
        "roleRef": "web",
        "healthyStates": ["running"],
        "failureStates": ["stopped", "deallocated"],
        "minimumHealthy": 2,
    }
    legacy_fact = ResourceProofFact.model_validate(
        {
            "resourceId": RESOURCE_IDS["web"][0],
            "roleRef": "web",
            "availabilityZone": "1",
            "state": "complete",
            "proofSource": "observed",
            "evidenceRef": _item_ref(3),
        }
    )
    assert legacy_fact.operational_state == "unknown"

    for invalid in (
        {
            "proofKind": "roleOperationalStateProof",
            "roleRef": "web",
            "healthyStates": ["running", "running"],
            "failureStates": ["stopped"],
            "minimumHealthy": 1,
        },
        {
            "proofKind": "roleOperationalStateProof",
            "roleRef": "web",
            "healthyStates": ["running"],
            "failureStates": ["running"],
            "minimumHealthy": 1,
        },
        {
            "proofKind": "roleOperationalStateProof",
            "roleRef": "web",
            "healthyStates": ["running"],
            "failureStates": ["unknown"],
            "minimumHealthy": 1,
        },
    ):
        with pytest.raises(ValidationError):
            RoleOperationalStateProof.model_validate(invalid)


@pytest.mark.parametrize(
    ("states", "failure_states", "expected_verdict"),
    [
        (("running", "running", "running"), ("stopped", "deallocated"), "pass"),
        (("running", "running", "stopped"), ("stopped", "deallocated"), "observation"),
        (("running", "running", "deallocated"), ("stopped", "deallocated"), "observation"),
        (("running", "stopped", "deallocated"), ("stopped", "deallocated"), "violation"),
        (("running", "running", "unknown"), ("stopped", "deallocated"), "unknown"),
        (("running", "running", "deallocated"), ("stopped",), "unknown"),
    ],
)
def test_role_operational_state_policy_is_fail_closed_and_deterministic(
    states: tuple[ResourceState, ...],
    failure_states: tuple[ResourceState, ...],
    expected_verdict: str,
) -> None:
    profile = _operational_profile(
        "production",
        2,
        failure_states=failure_states,
    )
    evidence = _operational_evidence(profile, states)

    finding = _operational_finding(profile, evidence)

    assert finding.finding_kind == "operationalState"
    assert finding.verdict == expected_verdict
    expected_references = sorted(
        (_item_ref(3), _item_ref(4), _item_ref(9)),
        key=lambda reference: reference.canonical_json(),
    )
    assert [
        reference.canonical_json() for reference in finding.evidence_refs
    ] == [
        reference.canonical_json() for reference in expected_references
    ]

    reversed_evidence = evidence.model_copy(deep=True)
    reversed_evidence.resources.reverse()
    repeated = _operational_finding(profile, reversed_evidence)
    assert repeated.canonical_json() == finding.canonical_json()


def test_same_web_fault_uses_three_profile_minimum_healthy_policy() -> None:
    expected = {
        "production": (2, "observation"),
        "development": (1, "observation"),
        "training": (3, "violation"),
    }

    for profile_id, (minimum_healthy, expected_verdict) in expected.items():
        profile = _operational_profile(profile_id, minimum_healthy)
        evidence = _operational_evidence(
            profile,
            ("running", "running", "stopped"),
        )

        finding = _operational_finding(profile, evidence)

        assert finding.profile_id == profile_id
        assert finding.verdict == expected_verdict
        assert len(finding.evidence_refs) == 3


def test_same_policy_path_evaluates_all_three_environments() -> None:
    expected = {
        "production": {
            "db-zone-loss-acceptance": "acceptedResidualRisk",
            "db-zone-loss-spof": "acceptedResidualRisk",
            "web-zone-distribution": "pass",
        },
        "development": {
            "db-zone-loss-acceptance": "observation",
            "db-zone-loss-spof": "observation",
            "web-zone-distribution": "pass",
        },
        "training": {
            "db-zone-loss-acceptance": "acceptedResidualRisk",
            "db-zone-loss-spof": "acceptedResidualRisk",
            "web-zone-distribution": "violation",
        },
    }
    common = {
        "availability-objective": "pass",
        "backup-control-health": "pass",
        "db-singleton-supported": "expectedConstraint",
        "evidence-freshness": "pass",
        "web-database-prohibited": "pass",
        "worker-database-required": "pass",
        "worker-db-zone-colocation": "pass",
    }

    for profile_id, differing in expected.items():
        profile = _resolved_profile(profile_id)
        findings = evaluate_profile(
            profile,
            _evidence(profile),
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )
        assert {key: finding.verdict for key, finding in findings.items()} == {
            **common,
            **differing,
        }
        for clause_id, finding in findings.items():
            assert finding.manifest_id == MANIFEST_ID
            assert finding.manifest_version == "1.0.0"
            assert finding.profile_id == profile_id
            assert finding.resolved_profile_digest == profile.resolved_profile_digest
            assert finding.governance_scope == _scope(profile_id, clause_id)
            assert finding.evidence_refs


def test_all_public_evaluator_apis_route_to_authoritative_policy() -> None:
    assert evaluate_profile is evaluate_policy_profile
    assert evaluate_policy is evaluate_policy_profile
    assert evaluate_root_profile is evaluate_policy_profile
    assert evaluate_root_policy is evaluate_policy_profile
    assert evaluate_root_profile_alias is evaluate_policy_profile
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    policy_findings = evaluate_policy_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    contract_findings = evaluate_contract_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert {
        clause_id: finding.canonical_json()
        for clause_id, finding in contract_findings.items()
    } == {
        clause_id: finding.canonical_json()
        for clause_id, finding in policy_findings.items()
    }


def test_policy_results_are_deterministic_and_evidence_citations_are_relevant() -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    first = evaluate_policy(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    second = evaluate_policy(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert {
        key: finding.canonical_json() for key, finding in first.items()
    } == {
        key: finding.canonical_json() for key, finding in second.items()
    }
    objective = first["availability-objective"]
    assert objective.evidence_refs == [evidence.objectives[0].evidence_ref]
    control = first["backup-control-health"]
    assert control.evidence_refs == [evidence.controls[0].evidence_ref]
    accepted = first["db-zone-loss-spof"]
    assert accepted.risk_acceptance_ref == "ra-db-zone-loss-production"
    assert accepted.evidence_refs == [evidence.resources[0].evidence_ref]


@pytest.mark.parametrize(
    ("mutation", "clause_id", "expected_verdict"),
    [
        ("inference", "worker-db-zone-colocation", "unknown"),
        ("incompleteBinding", "worker-db-zone-colocation", "unknown"),
        ("relationshipInference", "worker-database-required", "unknown"),
        ("relationshipConflict", "worker-database-required", "conflicting"),
    ],
)
def test_inference_conflict_and_incomplete_selectors_fail_closed(
    mutation: str,
    clause_id: str,
    expected_verdict: str,
) -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    if mutation == "inference":
        evidence.resources[1].proof_source = "inferred"
    elif mutation == "incompleteBinding":
        evidence.role_bindings[1].state = "missing"
    elif mutation == "relationshipInference":
        evidence.relationships[0].proof_source = "inferred"
    else:
        evidence.relationships[0].state = "conflicting"

    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings[clause_id].verdict == expected_verdict
    assert findings[clause_id].evidence_refs
    if mutation == "incompleteBinding":
        contract_findings = evaluate_contract_profile(
            profile,
            evidence,
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )
        assert contract_findings[clause_id].verdict == "unknown"


def test_topology_relationship_control_objective_and_freshness_failures_are_explicit() -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    evidence.resources[1].availability_zone = "2"
    evidence.resources[4].availability_zone = "1"
    evidence.relationships[0].presence = "absent"
    evidence.relationships[1].presence = "present"
    evidence.controls[0].health = "degraded"
    evidence.objectives[0].current_value = 99.0

    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings["worker-db-zone-colocation"].verdict == "violation"
    assert findings["web-zone-distribution"].verdict == "violation"
    assert findings["worker-database-required"].verdict == "violation"
    assert findings["web-database-prohibited"].verdict == "violation"
    assert findings["backup-control-health"].verdict == "violation"
    assert findings["availability-objective"].verdict == "violation"

    evidence.collected_at = datetime(2026, 8, 15, 21, tzinfo=UTC)
    stale_findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert stale_findings["evidence-freshness"].verdict == "violation"


@pytest.mark.parametrize(
    ("state", "reason"),
    [("gap", "missing"), ("stale", "stale")],
)
def test_missing_gap_and_stale_facts_return_cited_unknown(
    state: str,
    reason: str,
) -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    payload = evidence.resources[4].model_dump(mode="json", by_alias=True)
    payload["state"] = state
    payload["evidenceRef"] = _gap_ref(20, reason).model_dump(
        mode="json",
        by_alias=True,
    )
    evidence.resources[4] = ResourceProofFact.model_validate(payload)

    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    finding = findings["web-zone-distribution"]
    assert finding.verdict == "unknown"
    assert any(reference.ref_type == "evidenceGap" for reference in finding.evidence_refs)


def test_validated_exception_requires_exact_active_resource_acceptance() -> None:
    profile = _resolved_profile("production")
    acceptance = _clause_acceptance(
        "production",
        "ra-web-zone-exception",
        "web-zone-distribution",
        [("web", resource_id) for resource_id in RESOURCE_IDS["web"]],
    )
    profile.risk_acceptances.append(acceptance)
    profile.relationships.append(
        ExceptionManifestRelationship.model_validate(
            {
                "relationshipClass": "exception",
                "exceptionId": "exception-web-zone",
                "appliesToClauseRef": "web-zone-distribution",
                "riskAcceptanceRef": "ra-web-zone-exception",
                "governanceScope": _scope(
                    "production",
                    "web-zone-distribution",
                ),
                "ownerRef": "owner-operations",
                "rationale": "Synthetic scoped zone-distribution exception.",
                "expiresAt": "2027-01-01T00:00:00.000Z",
            }
        )
    )
    profile = _resign_profile(profile)
    evidence = _evidence(profile)
    evidence.resources[4].availability_zone = "1"
    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings["web-zone-distribution"].verdict == "acceptedResidualRisk"
    assert (
        findings["web-zone-distribution"].risk_acceptance_ref
        == "ra-web-zone-exception"
    )

    profile.risk_acceptances[-1].accepted_resource_bindings.pop()
    profile = _resign_profile(profile)
    mismatched = _evidence(profile)
    mismatched.resources[4].availability_zone = "1"
    mismatched_findings = evaluate_profile(
        profile,
        mismatched,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert mismatched_findings["web-zone-distribution"].verdict == "violation"
    assert mismatched_findings["web-zone-distribution"].risk_acceptance_ref is None


def test_relationship_exception_applies_only_to_exact_source_clause() -> None:
    payload = _canonical_manifest_payload()
    production = payload["profiles"]["production"]
    production["constraints"].append(
        _constraint(
            "production",
            "worker-database-secondary",
            "dependencyRequired",
            "architectureConstraint",
            {
                "proofKind": "relationshipPresenceProof",
                "declaredRelationshipRef": "worker-requires-database",
            },
            "pass",
        ).model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    production["riskAcceptances"].append(
        _clause_acceptance(
            "production",
            "ra-worker-relationship",
            "worker-database-required",
            [
                *[
                    ("worker", resource_id)
                    for resource_id in RESOURCE_IDS["worker"]
                ],
                (
                    "database-primary",
                    RESOURCE_IDS["database-primary"][0],
                ),
            ],
        ).model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    production["relationships"].append(
        ExceptionManifestRelationship.model_validate(
            {
                "relationshipClass": "exception",
                "exceptionId": "exception-worker-relationship",
                "appliesToRelationshipRef": "worker-requires-database",
                "riskAcceptanceRef": "ra-worker-relationship",
                "governanceScope": _scope(
                    "production",
                    "worker-database-required",
                ),
                "ownerRef": "owner-operations",
                "rationale": "Synthetic exact relationship exception.",
                "expiresAt": "2027-01-01T00:00:00.000Z",
            }
        ).model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    profile = _resolve_payload(payload, "production")
    evidence = _evidence(profile)
    evidence.relationships[0].presence = "absent"

    findings = evaluate_contract_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings["worker-database-required"].verdict == "acceptedResidualRisk"
    assert findings["worker-database-secondary"].verdict == "violation"
    assert findings["worker-database-secondary"].risk_acceptance_ref is None


@pytest.mark.parametrize(
    ("clause_id", "attribute", "missing_ref", "error"),
    [
        (
            "worker-db-zone-colocation",
            "subject_role_ref",
            "missing-role",
            "unresolved constraint roleRef",
        ),
        (
            "backup-control-health",
            "control_ref",
            "missing-control",
            "unresolved control proof ref",
        ),
        (
            "availability-objective",
            "objective_ref",
            "missing-objective",
            "unresolved objective proof ref",
        ),
        (
            "worker-database-required",
            "declared_relationship_ref",
            "missing-relationship",
            "unresolved declared relationship proof ref",
        ),
    ],
)
def test_policy_boundary_rejects_recomputed_invalid_resolved_references(
    clause_id: str,
    attribute: str,
    missing_ref: str,
    error: str,
) -> None:
    profile = _resolved_profile("production")
    constraint = next(
        item for item in profile.constraints if item.constraint_id == clause_id
    )
    setattr(constraint.proof_requirement, attribute, missing_ref)
    profile = _resign_profile(profile)
    evidence = _evidence(profile)

    with pytest.raises(AthenaValidationError, match=error):
        evaluate_policy_profile(
            profile,
            evidence,
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )


def test_controls_and_renamed_technology_constraints_never_become_accepted_risk() -> None:
    profile = _resolved_profile("production")
    control_acceptance = _clause_acceptance(
        "production",
        "ra-backup-control",
        "backup-control-health",
        [],
    )
    profile.risk_acceptances.append(control_acceptance)
    control_constraint = next(
        constraint
        for constraint in profile.constraints
        if constraint.constraint_id == "backup-control-health"
    )
    control_constraint.risk_acceptance_ref = "ra-backup-control"
    profile = _resign_profile(profile)
    evidence = _evidence(profile)
    evidence.controls[0].health = "degraded"
    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings["backup-control-health"].verdict == "violation"
    assert findings["backup-control-health"].risk_acceptance_ref is None

    profile = _resolved_profile("production")
    second_database_id = RESOURCE_PREFIX + "synthetic-db-02"
    renamed_constraint_id = "renamed-singleton-supported"
    technology_acceptance = _clause_acceptance(
        "production",
        "ra-singleton-technology",
        renamed_constraint_id,
        [
            ("database-primary", RESOURCE_IDS["database-primary"][0]),
            ("database-primary", second_database_id),
        ],
    )
    profile.risk_acceptances.append(technology_acceptance)
    technology_constraint = next(
        constraint
        for constraint in profile.constraints
        if constraint.constraint_id == "db-singleton-supported"
    )
    technology_constraint.constraint_id = renamed_constraint_id
    technology_constraint.governance_scope.clause_path = (
        f"/constraints/{renamed_constraint_id}"
    )
    technology_constraint.risk_acceptance_ref = "ra-singleton-technology"
    technology_constraint.finding_kind = "architectureConstraint"
    profile = _resign_profile(profile)
    evidence = _evidence(profile)
    evidence.resources.append(
        ResourceProofFact(
            resourceId=second_database_id,
            roleRef="database-primary",
            availabilityZone="1",
            state="complete",
            proofSource="observed",
            evidenceRef=_item_ref(30),
        )
    )
    database_binding = evidence.role_bindings[0]
    database_binding.selected_resource_ids = [
        RESOURCE_IDS["database-primary"][0],
        second_database_id,
    ]
    database_binding.selector_result_digest = compute_artifact_digest(
        sorted(database_binding.selected_resource_ids, key=str.casefold)
    )
    with pytest.raises(
        AthenaValidationError,
        match="missing mandatory protected canonical constraints: db-singleton-supported",
    ):
        evaluate_profile(
            profile,
            evidence,
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )


@pytest.mark.parametrize(
    ("clause_id", "attribute", "value"),
    [
        ("db-zone-loss-spof", "finding_kind", "architectureConstraint"),
        (
            "worker-db-zone-colocation",
            "finding_kind",
            "relationshipConflict",
        ),
        ("web-zone-distribution", "success_verdict", "expectedConstraint"),
    ],
)
def test_policy_boundary_enforces_other_protected_canonical_semantics(
    clause_id: str,
    attribute: str,
    value: str,
) -> None:
    profile = _resolved_profile("production")
    constraint = next(
        item for item in profile.constraints if item.constraint_id == clause_id
    )
    setattr(constraint, attribute, value)
    profile = _resign_profile(profile)

    with pytest.raises(
        AthenaValidationError,
        match="protected canonical constraint semantics are invalid",
    ):
        evaluate_policy_profile(
            profile,
            _evidence(profile),
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )


def test_stale_context_and_missing_typed_gap_citations_fail_closed() -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    with pytest.raises(AthenaValidationError, match="stale at trusted as_of"):
        evaluate_profile(
            profile,
            evidence,
            as_of=datetime(2026, 8, 18, tzinfo=UTC),
            verify_evidence_context=_verify_unit_evidence,
        )

    evidence.controls = []
    with pytest.raises(AthenaValidationError, match="requires typed evidence"):
        evaluate_profile(
            profile,
            evidence,
            as_of=AS_OF,
            verify_evidence_context=_verify_unit_evidence,
        )
