from __future__ import annotations

from datetime import UTC, datetime

import pytest

from athena_context.contracts import (
    AthenaValidationError,
    CompatibilityMetadata,
    compute_artifact_digest,
)
from athena_context.contracts.manifest import (
    BackupControl,
    ClauseScope,
    ContinuitySettings,
    ControlProofFact,
    DeclaredManifestRelationship,
    EvidenceReferenceContext,
    ExceptionManifestRelationship,
    ManifestConstraint,
    ManifestObjective,
    ManifestOwner,
    ManifestProfileSettings,
    ManifestRiskAcceptance,
    ManifestRole,
    ObjectiveProofFact,
    RelationshipProofFact,
    ResolvedManifestProfile,
    ResourceProofFact,
    RoleBindingProof,
)
from athena_context.contracts.models import (
    EvidenceGapRef,
    EvidenceItemRef,
    ProducerInfo,
    ResourceGroupScope,
)
from athena_context.policy import evaluate_policy, evaluate_profile

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
            "worker-db-zone-colocation",
            "web-zone-distribution",
        },
    }
    if risk_acceptance_ref is not None:
        payload["riskAcceptanceRef"] = risk_acceptance_ref
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
        artifactKind="resolvedProfile",
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


def _resolved_profile(profile_id: str) -> ResolvedManifestProfile:
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
    draft = ResolvedManifestProfile.model_construct(
        manifest_id=MANIFEST_ID,
        manifest_version="1.0.0",
        profile_id=profile_id,
        profile_type=profile_id,
        allowed_evidence_scopes=[_evidence_scope()],
        compatibility=_compatibility(),
        inheritance_chain=[profile_id],
        settings=ManifestProfileSettings(
            continuity=ContinuitySettings(
                zoneLossContinuityRequired=continuity_required
            )
        ),
        roles=[
            _role("database-primary", "singletonDatabase", "exactlyOne"),
            _role("worker", "worker", "oneOrMore"),
            _role("web", "webService", "oneOrMore"),
        ],
        relationships=relationships,
        constraints=constraints,
        controls=controls,
        risk_acceptances=(
            [_acceptance(profile_id)] if continuity_required else []
        ),
        objectives=objectives,
        ownership=[
            ManifestOwner(
                ownerRef="owner-operations",
                ownerRole="operationsOwner",
                authorityRef="synthetic://team/operations",
            )
        ],
        resolved_profile_digest="sha256:" + "0" * 64,
    )
    payload = draft.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload["compatibility"]["artifactDigest"] = draft.recompute_artifact_digest()
    payload["compatibility"]["semanticDigest"] = draft.recompute_semantic_digest()
    payload["resolvedProfileDigest"] = draft.recompute_semantic_digest()
    return ResolvedManifestProfile.model_validate(payload)


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


def test_same_policy_path_evaluates_all_three_environments() -> None:
    expected = {
        "production": {
            "db-zone-loss-spof": "acceptedResidualRisk",
            "web-zone-distribution": "pass",
        },
        "development": {
            "db-zone-loss-spof": "observation",
            "web-zone-distribution": "pass",
        },
        "training": {
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


def test_controls_and_technology_constraints_never_become_accepted_risk() -> None:
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
    technology_acceptance = _clause_acceptance(
        "production",
        "ra-singleton-technology",
        "db-singleton-supported",
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
    technology_constraint.risk_acceptance_ref = "ra-singleton-technology"
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
    findings = evaluate_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_unit_evidence,
    )
    assert findings["db-singleton-supported"].verdict == "violation"
    assert findings["db-singleton-supported"].risk_acceptance_ref is None


def test_stale_context_and_missing_typed_gap_citations_fail_closed() -> None:
    profile = _resolved_profile("production")
    evidence = _evidence(profile)
    with pytest.raises(AthenaValidationError, match="not verified"):
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
