from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from athena_context import WorkloadManifest as PublicWorkloadManifest
from athena_context.contracts import (
    AthenaValidationError,
    ProfileDefinition,
    ProfileSettings,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest as _CanonicalWorkloadManifest,
)
from athena_context.contracts.manifest import (
    ControlProofFact,
    EvidenceReferenceContext,
    GovernedWeakeningOverride,
    ManifestControl,
    ManifestRiskAcceptance,
    ManifestSelector,
    ObjectiveProofFact,
    RelationshipProofFact,
    ResourceProofFact,
    canonicalize_manifest_payload,
    evaluate_manifest_profile,
    resolve_manifest_profile,
)

AS_OF = datetime(2025, 6, 1, tzinfo=UTC)
ACCEPTED_AT = "2025-01-01T00:00:00.000Z"
EXPIRES_AT = "2025-12-31T00:00:00.000Z"
SNAPSHOT_ID = "snap-111111111111"
SNAPSHOT_ARTIFACT_DIGEST = "sha256:" + "1" * 64
SNAPSHOT_SEMANTIC_DIGEST = "sha256:" + "2" * 64
RESOURCE_PREFIX = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.Compute/"
    "virtualMachines/"
)


class CanonicalWorkloadManifest:
    @staticmethod
    def model_validate(value: dict[str, object]) -> _CanonicalWorkloadManifest:
        return _CanonicalWorkloadManifest.model_validate(canonicalize_manifest_payload(value))

    @staticmethod
    def model_json_schema() -> dict[str, object]:
        return _CanonicalWorkloadManifest.model_json_schema()


def _scope(profile: str, clause: str) -> dict[str, object]:
    return {
        "governanceScopeType": "clause",
        "manifestId": "wl-athena-wc001-canonical",
        "profileId": profile,
        "clausePath": f"/constraints/{clause}",
        "ownerRef": "ops-owner",
    }


def _selector(selector_id: str, prefix: str) -> dict[str, object]:
    return {
        "selectorType": "namePredicate",
        "selectorId": selector_id,
        "prefix": prefix,
        "maxMatches": 100,
    }


def _role(
    role_id: str,
    kind: str,
    cardinality: str,
    prefix: str,
) -> dict[str, object]:
    return {
        "roleId": role_id,
        "kind": kind,
        "cardinality": {"cardinalityKind": cardinality},
        "selectors": [_selector(f"{role_id}-name", prefix)],
        "ownerRef": "ops-owner",
        "status": "approved",
    }


def _constraint(
    profile: str,
    clause: str,
    constraint_type: str,
    finding_kind: str,
    proof: dict[str, object],
    success: str,
    *,
    risk_ref: str | None = None,
    acceptance_clause_ref: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "constraintId": clause,
        "constraintType": constraint_type,
        "findingKind": finding_kind,
        "governanceScope": _scope(profile, clause),
        "ownerRef": "ops-owner",
        "profiles": [profile],
        "proofRequirement": proof,
        "failureVerdict": "violation",
        "successVerdict": success,
        "protected": clause
        in {
            "db-singleton-supported",
            "db-zone-loss-spof",
            "db-zone-loss-acceptance",
            "worker-db-zone-colocation",
            "web-zone-distribution",
        },
    }
    if risk_ref is not None:
        value["riskAcceptanceRef"] = risk_ref
    if acceptance_clause_ref is not None:
        value["riskAcceptanceClauseRef"] = acceptance_clause_ref
    return value


def _constraints(
    profile: str,
    *,
    web_zones: int,
    risk_ref: str | None,
) -> list[dict[str, object]]:
    return [
        _constraint(
            profile,
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
            profile,
            "db-zone-loss-spof",
            "supportedSingleton",
            "actualSpof",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "database-primary",
                "expected": {"cardinalityKind": "exactlyOne"},
            },
            "observation",
            risk_ref=risk_ref,
        ),
        _constraint(
            profile,
            "db-zone-loss-acceptance",
            "supportedSingleton",
            "riskAcceptance",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "database-primary",
                "expected": {"cardinalityKind": "exactlyOne"},
            },
            "observation",
            risk_ref=risk_ref,
            acceptance_clause_ref="db-zone-loss-spof" if risk_ref else None,
        ),
        _constraint(
            profile,
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
            profile,
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
    ]


def _acceptance(profile: str, acceptance_id: str) -> dict[str, object]:
    return {
        "riskAcceptanceId": acceptance_id,
        "governanceScope": _scope(profile, "db-zone-loss-spof"),
        "riskKind": "availability",
        "riskRating": "high",
        "residualRiskStatement": "A zone loss can interrupt the supported singleton database.",
        "rationaleRef": "approval://synthetic/db-zone-loss",
        "acceptedBy": "synthetic-approver",
        "ownedBy": "ops-owner",
        "acceptedAt": ACCEPTED_AT,
        "expiresAt": EXPIRES_AT,
        "linkedControlRefs": [],
        "acceptedResourceBindings": [
            {
                "roleRef": "database-primary",
                "resourceId": RESOURCE_PREFIX + "athena-db-01",
            }
        ],
        "profiles": [profile],
        "status": "approved",
    }


def _item_ref(index: int) -> dict[str, object]:
    attempt_suffix = f"{index + 1:012x}"
    return {
        "refType": "evidenceItem",
        "snapshotId": SNAPSHOT_ID,
        "snapshotArtifactDigest": SNAPSHOT_ARTIFACT_DIGEST,
        "snapshotSemanticDigest": SNAPSHOT_SEMANTIC_DIGEST,
        "itemDigest": "sha256:" + f"{index + 3:064x}",
        "collectorAttemptId": f"attempt-{attempt_suffix}",
        "collectorAttemptDigest": "sha256:" + f"{index + 13:064x}",
        "collectorToolName": "azure.resourceInventory.read",
        "collectorToolVersion": "1.0.0",
        "collectorAttemptAt": "2025-05-31T23:00:00.000Z",
        "collectorIdentityEvidenceRef": "identity-111111111111",
        "sourceResponseDigest": "sha256:" + f"{index + 23:064x}",
        "sourceResponsePointer": f"/value/{index}",
    }


def _gap_ref(index: int, reason: str = "missing") -> dict[str, object]:
    attempt_suffix = f"{index + 101:012x}"
    return {
        "refType": "evidenceGap",
        "snapshotId": SNAPSHOT_ID,
        "snapshotArtifactDigest": SNAPSHOT_ARTIFACT_DIGEST,
        "snapshotSemanticDigest": SNAPSHOT_SEMANTIC_DIGEST,
        "gapId": f"gap-{index + 1:012x}",
        "gapRecordDigest": "sha256:" + f"{index + 33:064x}",
        "evidenceScope": {
            "scopeType": "resourceGroup",
            "tenantId": "00000000-0000-0000-0000-000000000000",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "resourceGroupName": "rg-athena-fixture",
        },
        "expectedRecordType": "resource",
        "collectorAttemptId": f"attempt-{attempt_suffix}",
        "collectorAttemptDigest": "sha256:" + f"{index + 43:064x}",
        "collectorToolName": "azure.resourceInventory.read",
        "collectorToolVersion": "1.0.0",
        "collectorAttemptAt": "2025-05-31T23:00:00.000Z",
        "collectorIdentityEvidenceRef": "identity-111111111111",
        "gapReason": reason,
    }


def build_manifest() -> _CanonicalWorkloadManifest:
    production_constraints = _constraints(
        "production", web_zones=2, risk_ref="ra-db-zone-loss-prod"
    )
    development_constraints = _constraints("development", web_zones=1, risk_ref=None)
    training_constraints = _constraints(
        "training", web_zones=3, risk_ref="ra-db-zone-loss-training"
    )
    payload: dict[str, object] = {
        "manifestId": "wl-athena-wc001-canonical",
        "manifestVersion": "1.0.0",
        "cloud": "azureCloud",
        "workload": {
            "displayName": "Synthetic WC-001 workload",
            "environments": [
                "production",
                "development",
                "training",
            ],
            "allowedEvidenceScopes": [
                {
                    "scopeType": "resourceGroup",
                    "tenantId": "00000000-0000-0000-0000-000000000000",
                    "subscriptionId": "00000000-0000-0000-0000-000000000000",
                    "resourceGroupName": "rg-athena-fixture",
                }
            ],
        },
        "roles": [
            _role(
                "database-primary",
                "singletonDatabase",
                "exactlyOne",
                "athena-db-",
            ),
            _role("worker", "worker", "oneOrMore", "athena-worker-"),
            _role("web", "webService", "oneOrMore", "athena-web-"),
        ],
        "ownership": [
            {
                "ownerRef": "ops-owner",
                "ownerRole": "operationsOwner",
                "authorityRef": "synthetic://teams/operations",
            }
        ],
        "profiles": {
            "production": {
                "profileId": "production",
                "profileType": "production",
                "settings": {"continuity": {"zoneLossContinuityRequired": True}},
                "constraints": production_constraints,
                "riskAcceptances": [_acceptance("production", "ra-db-zone-loss-prod")],
            },
            "development": {
                "profileId": "development",
                "profileType": "development",
                "extends": "production",
                "settings": {"continuity": {"zoneLossContinuityRequired": False}},
                "constraints": development_constraints,
                "weakeningOverrides": [
                    {
                        "overrideId": "dev-continuity",
                        "reason": "continuityRelaxation",
                        "targetPath": (
                            "/resolvedProfiles/development/settings/continuity/"
                            "zoneLossContinuityRequired"
                        ),
                        "targetRef": "zoneLossContinuityRequired",
                        "ownerRef": "ops-owner",
                        "rationale": "Development does not claim continuity through zone loss.",
                        "approvedBy": "synthetic-approver",
                        "status": "approved",
                        "acceptedAt": ACCEPTED_AT,
                        "expiresAt": EXPIRES_AT,
                        "profiles": ["development"],
                    },
                    {
                        "overrideId": "dev-web-zones",
                        "reason": "zoneRequirementRelaxation",
                        "targetPath": (
                            "/resolvedProfiles/development/constraints/"
                            "web-zone-distribution/proofRequirement/"
                            "minimumDistinctZones"
                        ),
                        "targetRef": "web-zone-distribution",
                        "ownerRef": "ops-owner",
                        "rationale": "One web zone is sufficient for synthetic development.",
                        "approvedBy": "synthetic-approver",
                        "status": "approved",
                        "acceptedAt": ACCEPTED_AT,
                        "expiresAt": EXPIRES_AT,
                        "profiles": ["development"],
                    },
                ],
            },
            "training": {
                "profileId": "training",
                "profileType": "training",
                "extends": "production",
                "settings": {"continuity": {"zoneLossContinuityRequired": True}},
                "constraints": training_constraints,
                "riskAcceptances": [_acceptance("training", "ra-db-zone-loss-training")],
            },
        },
        "compatibility": {
            "artifactKind": "workloadManifest",
            "schemaVersion": "1.0.0",
            "semanticContractVersion": "1.0.0",
            "policyContractVersion": "1.0.0",
            "minimumReaderVersion": "1.0.0",
            "requiresCapabilities": [],
            "producedBy": {
                "producerId": "athena.contracts",
                "version": "1.0.0",
            },
            "extensionPolicy": "rejectUnknownDecisionFields",
            "artifactDigest": "sha256:" + "a" * 64,
            "semanticDigest": "sha256:" + "b" * 64,
        },
        "audit": {
            "publishedBy": "human-approved-context-api",
            "publishedAt": ACCEPTED_AT,
            "approvalStatus": "approved",
        },
    }
    digest_payload = deepcopy(payload)
    digest_payload["compatibility"]["artifactDigest"] = None
    digest_payload["compatibility"]["semanticDigest"] = None
    digest = compute_artifact_digest(digest_payload)
    payload["compatibility"]["artifactDigest"] = digest
    payload["compatibility"]["semanticDigest"] = digest
    return CanonicalWorkloadManifest.model_validate(payload)


def _evidence(profile_id: str, digest: str) -> EvidenceReferenceContext:
    resource_prefix = RESOURCE_PREFIX
    return EvidenceReferenceContext(
        snapshotId=SNAPSHOT_ID,
        snapshotArtifactDigest=SNAPSHOT_ARTIFACT_DIGEST,
        snapshotSemanticDigest=SNAPSHOT_SEMANTIC_DIGEST,
        collectedAt="2025-05-31T22:00:00.000Z",
        expiresAt="2025-06-02T00:00:00.000Z",
        authorizedScopes=[
            {
                "scopeType": "resourceGroup",
                "tenantId": "00000000-0000-0000-0000-000000000000",
                "subscriptionId": "00000000-0000-0000-0000-000000000000",
                "resourceGroupName": "rg-athena-fixture",
            }
        ],
        roleBindings=[
            {
                "roleRef": "database-primary",
                "selectedResourceIds": [resource_prefix + "athena-db-01"],
                "selectorResultDigest": compute_artifact_digest([resource_prefix + "athena-db-01"]),
                "state": "complete",
            },
            {
                "roleRef": "worker",
                "selectedResourceIds": [
                    resource_prefix + "athena-worker-01",
                    resource_prefix + "athena-worker-02",
                ],
                "selectorResultDigest": compute_artifact_digest(
                    [
                        resource_prefix + "athena-worker-01",
                        resource_prefix + "athena-worker-02",
                    ]
                ),
                "state": "complete",
            },
            {
                "roleRef": "web",
                "selectedResourceIds": [
                    resource_prefix + "athena-web-01",
                    resource_prefix + "athena-web-02",
                ],
                "selectorResultDigest": compute_artifact_digest(
                    [
                        resource_prefix + "athena-web-01",
                        resource_prefix + "athena-web-02",
                    ]
                ),
                "state": "complete",
            },
        ],
        manifestId="wl-athena-wc001-canonical",
        profileId=profile_id,
        resolvedProfileDigest=digest,
        resources=[
            {
                "resourceId": resource_prefix + "athena-db-01",
                "roleRef": "database-primary",
                "availabilityZone": "1",
                "state": "complete",
                "proofSource": "observed",
                "evidenceRef": _item_ref(0),
            },
            {
                "resourceId": resource_prefix + "athena-worker-01",
                "roleRef": "worker",
                "availabilityZone": "1",
                "state": "complete",
                "proofSource": "observed",
                "evidenceRef": _item_ref(1),
            },
            {
                "resourceId": resource_prefix + "athena-worker-02",
                "roleRef": "worker",
                "availabilityZone": "1",
                "state": "complete",
                "proofSource": "observed",
                "evidenceRef": _item_ref(2),
            },
            {
                "resourceId": resource_prefix + "athena-web-01",
                "roleRef": "web",
                "availabilityZone": "1",
                "state": "complete",
                "proofSource": "observed",
                "evidenceRef": _item_ref(3),
            },
            {
                "resourceId": resource_prefix + "athena-web-02",
                "roleRef": "web",
                "availabilityZone": "2",
                "state": "complete",
                "proofSource": "observed",
                "evidenceRef": _item_ref(4),
            },
        ],
    )


def _verify_fixture_context(
    context: EvidenceReferenceContext,
    as_of: datetime,
) -> None:
    if (
        as_of != AS_OF
        or context.snapshot_id != SNAPSHOT_ID
        or context.snapshot_artifact_digest != SNAPSHOT_ARTIFACT_DIGEST
        or context.snapshot_semantic_digest != SNAPSHOT_SEMANTIC_DIGEST
    ):
        raise AthenaValidationError("fixture context is not trusted")
    facts = [
        *context.resources,
        *context.relationships,
        *context.controls,
        *context.objectives,
    ]
    for fact in facts:
        reference = fact.evidence_ref
        if reference.ref_type == "evidenceItem":
            index = int(reference.source_response_pointer.rsplit("/", 1)[-1])
            expected = _item_ref(index)
        else:
            index = int(reference.gap_id.removeprefix("gap-"), 16) - 1
            expected = _gap_ref(index, reference.gap_reason)
        if canonicalize_json(
            reference.model_dump(mode="json", by_alias=True, exclude_none=True)
        ) != canonicalize_json(expected):
            raise AthenaValidationError("fixture evidence reference is not authenticated")
    resources_by_role: dict[str, list[str]] = {}
    for resource in context.resources:
        resources_by_role.setdefault(resource.role_ref, []).append(resource.resource_id)
    for binding in context.role_bindings:
        selected = sorted(binding.selected_resource_ids, key=str.casefold)
        actual = sorted(resources_by_role.get(binding.role_ref, []), key=str.casefold)
        if selected != actual or binding.selector_result_digest != compute_artifact_digest(
            selected
        ):
            raise AthenaValidationError("fixture role binding is not authenticated")


def test_profile_resolution_rejects_missing_parent_and_cycle() -> None:
    missing = build_manifest().model_dump(mode="json", by_alias=True)
    missing["profiles"]["development"]["extends"] = "missing"
    with pytest.raises((AthenaValidationError, ValidationError), match="missing parent"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(missing),
            "development",
            as_of=AS_OF,
        )

    cycle = build_manifest().model_dump(mode="json", by_alias=True)
    cycle["profiles"]["production"]["extends"] = "development"
    with pytest.raises((AthenaValidationError, ValidationError), match="cycle"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(cycle),
            "development",
            as_of=AS_OF,
        )


def test_manifest_rejects_invalid_profiles_outside_requested_lineage() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["sandbox"] = {
        "profileId": "sandbox",
        "profileType": "sandbox",
        "extends": "missing-parent",
        "settings": {"continuity": {"zoneLossContinuityRequired": False}},
    }
    with pytest.raises(ValidationError, match="missing parent profile"):
        CanonicalWorkloadManifest.model_validate(payload)

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["sandbox"] = {
        "profileId": "sandbox",
        "profileType": "sandbox",
        "settings": {"continuity": {"zoneLossContinuityRequired": False}},
        "relationships": [
            {
                "relationshipClass": "declared",
                "relationshipId": "sandbox-missing-role",
                "kind": "dependsOn",
                "source": {
                    "endpointType": "role",
                    "roleRef": "worker",
                },
                "target": {
                    "endpointType": "role",
                    "roleRef": "missing-role",
                },
                "ownerRef": "ops-owner",
                "profiles": ["sandbox"],
                "sourceClause": "/constraints/sandbox-dependency",
            }
        ],
    }
    manifest = CanonicalWorkloadManifest.model_validate(payload)
    with pytest.raises(AthenaValidationError, match="unresolved relationship roleRef"):
        resolve_manifest_profile(
            manifest,
            "production",
            as_of=AS_OF,
        )


def test_normalized_duplicate_profile_and_role_ids_are_rejected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["Production"] = deepcopy(payload["profiles"]["production"])
    payload["profiles"]["Production"]["profileId"] = "Production"
    with pytest.raises(ValidationError, match="duplicate normalized profile"):
        CanonicalWorkloadManifest.model_validate(payload)

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    duplicate = deepcopy(payload["roles"][0])
    duplicate["roleId"] = "DATABASE-PRIMARY"
    payload["roles"].append(duplicate)
    with pytest.raises(ValidationError, match="duplicate role id"):
        CanonicalWorkloadManifest.model_validate(payload)


def test_profile_applicability_is_normalized_and_deprecated_roles_reject() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    production = payload["profiles"].pop("production")
    production["profileId"] = "Production"
    for constraint in production["constraints"]:
        constraint["governanceScope"]["profileId"] = "Production"
    for acceptance in production["riskAcceptances"]:
        acceptance["governanceScope"]["profileId"] = "Production"
    payload["profiles"]["Production"] = production
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "Production",
        as_of=AS_OF,
    )
    assert len(profile.constraints) == 5
    assert len(profile.risk_acceptances) == 1

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["roles"][2]["status"] = "deprecated"
    with pytest.raises(ValidationError, match="only approved roles"):
        CanonicalWorkloadManifest.model_validate(payload)


def test_direct_weakening_requires_exact_active_governed_overrides() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["development"]["weakeningOverrides"] = []
    manifest = CanonicalWorkloadManifest.model_validate(payload)
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(manifest, "development", as_of=AS_OF)


def test_unprotected_failure_verdict_weakening_requires_governance() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    optional = _constraint(
        "production",
        "optional-zone-policy",
        "zoneDistribution",
        "architectureConstraint",
        {
            "proofKind": "zoneDistributionProof",
            "roleRef": "web",
            "minimumDistinctZones": 2,
        },
        "pass",
    )
    optional["protected"] = False
    payload["profiles"]["production"]["constraints"].append(optional)
    child_optional = deepcopy(optional)
    child_optional["governanceScope"] = _scope("development", "optional-zone-policy")
    child_optional["failureVerdict"] = "unknown"
    payload["profiles"]["development"]["constraints"].append(child_optional)
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    top_level = deepcopy(optional)
    payload["constraints"] = [top_level]
    root_override = deepcopy(top_level)
    root_override["failureVerdict"] = "unknown"
    payload["profiles"]["production"]["constraints"].append(root_override)
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    bounded_worker = deepcopy(payload["roles"][1])
    bounded_worker["cardinality"] = {
        "cardinalityKind": "boundedRange",
        "minimum": 1,
        "maximum": 2,
    }
    payload["roles"][1] = bounded_worker
    root_worker = deepcopy(bounded_worker)
    root_worker["cardinality"] = {
        "cardinalityKind": "boundedRange",
        "minimum": 0,
        "maximum": 10000,
    }
    payload["profiles"]["production"]["roles"] = [root_worker]
    with pytest.raises(AthenaValidationError, match="cardinality"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    freshness = _constraint(
        "production",
        "freshness-policy",
        "evidenceFreshness",
        "architectureConstraint",
        {
            "proofKind": "evidenceFreshnessProof",
            "maximumAgeSeconds": 60,
        },
        "pass",
    )
    freshness["protected"] = False
    payload["constraints"] = [freshness]
    root_freshness = deepcopy(freshness)
    root_freshness["proofRequirement"]["maximumAgeSeconds"] = 2592000
    payload["profiles"]["production"]["constraints"].append(root_freshness)
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_governed_weakening_resolves_and_digest_is_order_stable() -> None:
    manifest = build_manifest()
    resolved = resolve_manifest_profile(manifest, "development", as_of=AS_OF)
    assert resolved.settings.continuity.zone_loss_continuity_required is False
    web = next(
        item for item in resolved.constraints if item.constraint_id == "web-zone-distribution"
    )
    assert web.proof_requirement.minimum_distinct_zones == 1

    payload = manifest.model_dump(mode="json", by_alias=True)
    payload["roles"].reverse()
    payload["profiles"]["development"]["constraints"].reverse()
    reordered = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "development",
        as_of=AS_OF,
    )
    assert reordered.resolved_profile_digest == resolved.resolved_profile_digest

    composite_payload = manifest.model_dump(mode="json", by_alias=True)
    composite_web = next(
        item for item in composite_payload["roles"] if item["roleId"] == "web"
    )
    composite_web["selectors"] = [
        {
            "selectorType": "compositeAll",
            "selectorId": "web-composite",
            "children": [
                {
                    "selectorType": "tagPredicate",
                    "selectorId": "child-b",
                    "predicates": [
                        {"key": "purpose", "value": "synthetic-web"}
                    ],
                    "maxMatches": 10,
                },
                {
                    "selectorType": "namePredicate",
                    "selectorId": "child-a",
                    "prefix": "athena-web-",
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        }
    ]
    composite = CanonicalWorkloadManifest.model_validate(composite_payload)
    reversed_payload = composite.model_dump(mode="json", by_alias=True, exclude_unset=True)
    reversed_web = next(
        item for item in reversed_payload["roles"] if item["roleId"] == "web"
    )
    reversed_web["selectors"][0]["children"].reverse()
    reversed_composite = CanonicalWorkloadManifest.model_validate(reversed_payload)
    assert (
        composite.compute_semantic_digest_value()
        == reversed_composite.compute_semantic_digest_value()
    )
    composite_profile = resolve_manifest_profile(composite, "production", as_of=AS_OF)
    reversed_profile = resolve_manifest_profile(reversed_composite, "production", as_of=AS_OF)
    assert composite_profile.resolved_profile_digest == reversed_profile.resolved_profile_digest


def test_variant_change_and_protected_disable_are_rejected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    web = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "web-zone-distribution"
    )
    web["proofRequirement"] = {
        "proofKind": "cardinalityProof",
        "roleRef": "web",
        "expected": {"cardinalityKind": "oneOrMore"},
    }
    with pytest.raises(
        (AthenaValidationError, ValidationError),
        match="illegal discriminator|matching proof variant",
    ):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["development"]["weakeningOverrides"].append(
        {
            "overrideId": "disable-acceptance",
            "reason": "disableInheritedItem",
            "targetPath": ("/resolvedProfiles/development/constraint/db-zone-loss-acceptance"),
            "targetRef": "db-zone-loss-acceptance",
            "ownerRef": "ops-owner",
            "rationale": "Synthetic negative fixture.",
            "approvedBy": "synthetic-approver",
            "status": "approved",
            "acceptedAt": ACCEPTED_AT,
            "expiresAt": EXPIRES_AT,
            "profiles": ["development"],
        }
    )
    payload["profiles"]["development"]["disabledRefs"] = [
        {
            "targetKind": "constraint",
            "targetRef": "db-zone-loss-acceptance",
            "governanceOverrideRef": "disable-acceptance",
        }
    ]
    with pytest.raises(AthenaValidationError, match="protected"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["development"]["weakeningOverrides"].append(
        {
            "overrideId": "disable-web",
            "reason": "disableInheritedItem",
            "targetPath": ("/resolvedProfiles/development/constraint/web-zone-distribution"),
            "targetRef": "web-zone-distribution",
            "ownerRef": "ops-owner",
            "rationale": "Synthetic negative fixture.",
            "approvedBy": "synthetic-approver",
            "status": "approved",
            "acceptedAt": ACCEPTED_AT,
            "expiresAt": EXPIRES_AT,
            "profiles": ["development"],
        }
    )
    payload["profiles"]["development"]["disabledRefs"] = [
        {
            "targetKind": "constraint",
            "targetRef": "web-zone-distribution",
            "governanceOverrideRef": "disable-web",
        }
    ]
    with pytest.raises(AthenaValidationError, match="protected"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )


def test_selector_variant_and_protected_verdict_changes_are_rejected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["development"]["roles"] = [
        {
            **_role("web", "webService", "oneOrMore", "unused-"),
            "selectors": [
                {
                    "selectorType": "resourceIdList",
                    "selectorId": "web-name",
                    "resourceIds": ["/synthetic/web/1"],
                    "maxMatches": 1,
                }
            ],
        }
    ]
    with pytest.raises(AthenaValidationError, match="illegal discriminator"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    singleton = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "db-singleton-supported"
    )
    singleton["successVerdict"] = "pass"
    with pytest.raises(AthenaValidationError, match="protected constraint semantics"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    singleton = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "db-singleton-supported"
    )
    singleton["proofRequirement"]["expected"] = {"cardinalityKind": "oneOrMore"}
    with pytest.raises(AthenaValidationError, match="protected constraint proof"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    cardinality = _constraint(
        "production",
        "optional-cardinality",
        "cardinality",
        "architectureConstraint",
        {
            "proofKind": "cardinalityProof",
            "roleRef": "worker",
            "expected": {"cardinalityKind": "exactlyOne"},
        },
        "pass",
    )
    cardinality["protected"] = False
    payload["profiles"]["production"]["constraints"].append(cardinality)
    child_cardinality = deepcopy(cardinality)
    child_cardinality["governanceScope"] = _scope("development", "optional-cardinality")
    child_cardinality["proofRequirement"]["expected"] = {"cardinalityKind": "zeroOrMore"}
    payload["profiles"]["development"]["constraints"].append(child_cardinality)
    with pytest.raises(AthenaValidationError, match="nested proof discriminator"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    singleton = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "db-singleton-supported"
    )
    singleton["findingKind"] = "architectureConstraint"
    with pytest.raises(AthenaValidationError, match="findingKind"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    singleton = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "db-singleton-supported"
    )
    singleton["proofRequirement"]["roleRef"] = "web"
    with pytest.raises(
        AthenaValidationError,
        match="proof target|protected constraint proof",
    ):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )


def test_nested_selector_variant_changes_are_rejected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    production_web = {
        **_role("web", "webService", "oneOrMore", "unused-"),
        "selectors": [
            {
                "selectorType": "compositeAll",
                "selectorId": "web-composite",
                "children": [
                    {
                        "selectorType": "namePredicate",
                        "selectorId": "web-child",
                        "prefix": "athena-web-",
                        "maxMatches": 10,
                    }
                ],
                "maxMatches": 10,
            }
        ],
    }
    development_web = deepcopy(production_web)
    development_web["selectors"][0]["children"][0] = {
        "selectorType": "resourceIdList",
        "selectorId": "web-child",
        "resourceIds": ["/synthetic/web/1"],
        "maxMatches": 1,
    }
    inherited_web = next(
        item for item in payload["roles"] if item["roleId"] == "web"
    )
    inherited_web["selectors"] = production_web["selectors"]
    payload["profiles"]["development"]["roles"] = [development_web]
    with pytest.raises(AthenaValidationError, match="illegal discriminator"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    duplicate_children = {
        "selectorType": "compositeAny",
        "selectorId": "duplicate-composite",
        "children": [
            {
                "selectorType": "namePredicate",
                "selectorId": "dup",
                "prefix": "a-",
                "maxMatches": 10,
            },
            {
                "selectorType": "namePredicate",
                "selectorId": "DUP",
                "prefix": "b-",
                "maxMatches": 10,
            },
        ],
        "maxMatches": 10,
    }
    with pytest.raises(ValidationError, match="duplicate composite child"):
        TypeAdapter(ManifestSelector).validate_python(duplicate_children)


@pytest.mark.parametrize(
    "selector",
    [
        {
            "selectorType": "resourceIdList",
            "selectorId": "s1",
            "resourceIds": ["/synthetic/resource/1"],
            "maxMatches": 1,
        },
        {
            "selectorType": "tagPredicate",
            "selectorId": "s1",
            "predicates": [{"key": "environment", "value": "production"}],
            "maxMatches": 10,
        },
        {
            "selectorType": "namePredicate",
            "selectorId": "s1",
            "prefix": "athena-",
            "maxMatches": 10,
        },
        {
            "selectorType": "resourceType",
            "selectorId": "s1",
            "resourceType": "Microsoft.Compute/virtualMachines",
            "maxMatches": 10,
        },
        {
            "selectorType": "vmScaleSet",
            "selectorId": "s1",
            "scaleSetResourceId": "/synthetic/vmss/1",
            "maxMatches": 10,
        },
        {
            "selectorType": "loadBalancerBackend",
            "selectorId": "s1",
            "loadBalancerResourceId": "/synthetic/lb/1",
            "backendPoolName": "backend",
            "maxMatches": 10,
        },
        {
            "selectorType": "subnet",
            "selectorId": "s1",
            "subnetResourceId": "/synthetic/subnet/1",
            "maxMatches": 10,
        },
        {
            "selectorType": "image",
            "selectorId": "s1",
            "publisher": "synthetic",
            "offer": "linux",
            "sku": "v1",
            "maxMatches": 10,
        },
        {
            "selectorType": "provenance",
            "selectorId": "s1",
            "collectorToolName": "azure.resourceInventory.read",
            "collectorToolVersion": "1.0.0",
            "identityEvidenceRef": "identity-synthetic",
            "maxMatches": 10,
        },
        {
            "selectorType": "compositeAll",
            "selectorId": "s1",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "child",
                    "prefix": "athena-",
                    "maxMatches": 10,
                }
            ],
            "maxMatches": 10,
        },
        {
            "selectorType": "compositeAny",
            "selectorId": "s1",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "child",
                    "suffix": "-01",
                    "maxMatches": 10,
                }
            ],
            "maxMatches": 10,
        },
    ],
)
def test_every_selector_variant_has_runtime_schema_parity(
    selector: dict[str, object],
) -> None:
    adapter: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
    adapter.validate_python(selector)
    assert not list(Draft202012Validator(adapter.json_schema()).iter_errors(selector))


def test_selector_bounds_and_expression_syntax_are_closed() -> None:
    adapter: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "selectorType": "namePredicate",
                "selectorId": "unsafe",
                "prefix": "athena-.*",
                "maxMatches": 10,
            }
        )
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "selectorType": "namePredicate",
                "selectorId": "too-broad",
                "prefix": "athena-",
                "maxMatches": 1001,
            }
        )


def _control_payload(kind: str) -> dict[str, object]:
    common: dict[str, object] = {
        "controlKind": kind,
        "controlId": f"control-{kind}",
        "governanceScope": _scope("production", "db-zone-loss-spof"),
        "ownerRef": "ops-owner",
        "profiles": ["production"],
        "health": "effective",
    }
    variants: dict[str, dict[str, object]] = {
        "backup": {
            "backupPolicyRef": "synthetic://backup/policy",
            "lastSuccessfulBackupAt": ACCEPTED_AT,
            "evidenceRefs": ["item-backup"],
        },
        "restoreTest": {
            "lastTestedAt": ACCEPTED_AT,
            "testOutcome": "passed",
            "rtoObservedSeconds": 60,
            "evidenceRefs": ["item-restore"],
        },
        "manualFailoverRunbook": {
            "runbookRef": "synthetic://runbook/failover",
            "lastReviewedAt": ACCEPTED_AT,
        },
        "monitoringAlert": {
            "alertRuleRef": "synthetic://alert/db",
            "enabledState": "enabled",
            "evidenceRefs": ["item-alert"],
        },
        "capacityReview": {
            "cadence": "monthly",
            "lastReviewedAt": ACCEPTED_AT,
            "nextReviewDueAt": EXPIRES_AT,
        },
        "accessReview": {
            "cadence": "quarterly",
            "lastCompletedAt": ACCEPTED_AT,
            "reviewSystemRef": "synthetic://review/access",
        },
        "changeApproval": {
            "approvalSystemRef": "synthetic://approval/change",
            "requiredForChangeKinds": ["deployment"],
        },
        "vendorSupport": {
            "supportPlanRef": "synthetic://support/plan",
            "coverageHours": "24x7",
            "expiresAt": EXPIRES_AT,
        },
    }
    return {**common, **variants[kind]}


@pytest.mark.parametrize(
    "kind",
    [
        "backup",
        "restoreTest",
        "manualFailoverRunbook",
        "monitoringAlert",
        "capacityReview",
        "accessReview",
        "changeApproval",
        "vendorSupport",
    ],
)
def test_every_control_variant_is_closed_and_schema_visible(kind: str) -> None:
    adapter: TypeAdapter[ManifestControl] = TypeAdapter(ManifestControl)
    payload = _control_payload(kind)
    adapter.validate_python(payload)
    assert not list(Draft202012Validator(adapter.json_schema()).iter_errors(payload))
    with pytest.raises(ValidationError):
        adapter.validate_python({**payload, "unexpected": True})


@pytest.mark.parametrize(
    ("risk_kind", "status"),
    [
        ("availability", "approved"),
        ("resilience", "expired"),
        ("operational", "revoked"),
        ("security", "superseded"),
        ("compliance", "approved"),
    ],
)
def test_risk_variants_and_statuses_are_closed(
    risk_kind: str,
    status: str,
) -> None:
    payload = _acceptance("production", "ra-variant")
    payload["riskKind"] = risk_kind
    payload["status"] = status
    acceptance = ManifestRiskAcceptance.model_validate(payload)
    assert acceptance.risk_kind == risk_kind
    if status != "approved":
        assert not acceptance.is_active(
            as_of=AS_OF,
            manifest_id="wl-athena-wc001-canonical",
            profile_id="production",
            clause_path="/constraints/db-zone-loss-spof",
            owner_ref="ops-owner",
        )


def test_unresolved_owner_and_relationship_refs_fail_resolution() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["roles"][0]["ownerRef"] = "missing-owner"
    with pytest.raises(AthenaValidationError, match="unresolved ownerRef"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "declared",
            "relationshipId": "rel-missing",
            "kind": "dependsOn",
            "source": {"endpointType": "role", "roleRef": "worker"},
            "target": {"endpointType": "role", "roleRef": "missing-role"},
            "ownerRef": "ops-owner",
            "profiles": ["production"],
            "sourceClause": "/constraints/worker-db-zone-colocation",
        }
    ]
    with pytest.raises(AthenaValidationError, match="unresolved relationship roleRef"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_all_semantic_reference_kinds_fail_closed() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    control_requirement = _constraint(
        "production",
        "synthetic-control-requirement",
        "controlRequired",
        "controlHealth",
        {
            "proofKind": "controlHealthProof",
            "controlRef": "missing-synthetic-control",
            "requiredHealth": "effective",
        },
        "pass",
    )
    control_requirement["protected"] = False
    payload["profiles"]["production"]["constraints"].append(control_requirement)
    with pytest.raises(AthenaValidationError, match="unresolved control proof ref"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["constraints"][0][
        "riskAcceptanceRef"
    ] = "missing-synthetic-risk"
    with pytest.raises(AthenaValidationError, match="unresolved constraint riskAcceptanceRef"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    objective_requirement = _constraint(
        "production",
        "synthetic-objective-requirement",
        "objectiveRequired",
        "objective",
        {
            "proofKind": "objectiveThresholdProof",
            "objectiveRef": "missing-synthetic-objective",
            "comparison": "gte",
            "threshold": 99.0,
        },
        "pass",
    )
    objective_requirement["protected"] = False
    payload["profiles"]["production"]["constraints"].append(objective_requirement)
    with pytest.raises(AthenaValidationError, match="unresolved objective proof ref"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "declared",
            "relationshipId": "synthetic-unresolved-clause",
            "kind": "dependsOn",
            "source": {"endpointType": "role", "roleRef": "worker"},
            "target": {"endpointType": "role", "roleRef": "database-primary"},
            "ownerRef": "ops-owner",
            "profiles": ["production"],
            "sourceClause": "/constraints/missing-synthetic-clause",
        }
    ]
    with pytest.raises(AthenaValidationError, match="unresolved relationship sourceClause"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["constraints"][0]["profiles"] = ["sandbox"]
    with pytest.raises(ValidationError, match="profile applicability reference is unresolved"):
        CanonicalWorkloadManifest.model_validate(payload)


def test_whole_manifest_validation_checks_contradictions_in_every_profile() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["sandbox"] = {
        "profileId": "sandbox",
        "profileType": "sandbox",
        "settings": {"continuity": {"zoneLossContinuityRequired": False}},
        "relationships": [
            {
                "relationshipClass": "declared",
                "relationshipId": "synthetic-sandbox-dependency",
                "kind": "dependsOn",
                "source": {"endpointType": "role", "roleRef": "worker"},
                "target": {
                    "endpointType": "role",
                    "roleRef": "database-primary",
                },
                "ownerRef": "ops-owner",
                "profiles": ["sandbox"],
                "sourceClause": "/constraints/synthetic-sandbox-required",
            }
        ],
        "constraints": [
            {
                **_constraint(
                    "sandbox",
                    "synthetic-sandbox-required",
                    "dependencyRequired",
                    "architectureConstraint",
                    {
                        "proofKind": "relationshipPresenceProof",
                        "declaredRelationshipRef": "synthetic-sandbox-dependency",
                    },
                    "pass",
                ),
                "protected": False,
            },
            {
                **_constraint(
                    "sandbox",
                    "synthetic-sandbox-prohibited",
                    "dependencyProhibited",
                    "architectureConstraint",
                    {
                        "proofKind": "relationshipPresenceProof",
                        "declaredRelationshipRef": "synthetic-sandbox-dependency",
                    },
                    "pass",
                ),
                "protected": False,
            },
        ],
    }
    with pytest.raises(AthenaValidationError, match="contradict"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_cardinality_and_objective_contradictions_fail_closed() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    cardinality = _constraint(
        "production",
        "synthetic-worker-cardinality",
        "cardinality",
        "architectureConstraint",
        {
            "proofKind": "cardinalityProof",
            "roleRef": "worker",
            "expected": {
                "cardinalityKind": "boundedRange",
                "minimum": 0,
                "maximum": 0,
            },
        },
        "pass",
    )
    cardinality["protected"] = False
    payload["profiles"]["production"]["constraints"].append(cardinality)
    with pytest.raises(AthenaValidationError, match="contradictory cardinality"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["objectives"] = [
        {
            "objectiveId": "synthetic-availability-objective",
            "objectiveType": "availabilitySlo",
            "ownerRef": "ops-owner",
            "target": 99.0,
        }
    ]
    for constraint_id, comparison in (
        ("synthetic-objective-lower-bound", "gte"),
        ("synthetic-objective-upper-bound", "lt"),
    ):
        requirement = _constraint(
            "production",
            constraint_id,
            "objectiveRequired",
            "objective",
            {
                "proofKind": "objectiveThresholdProof",
                "objectiveRef": "synthetic-availability-objective",
                "comparison": comparison,
                "threshold": 99.0,
            },
            "pass",
        )
        requirement["protected"] = False
        payload["profiles"]["production"]["constraints"].append(requirement)
    with pytest.raises(AthenaValidationError, match="contradictory objective"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_ambiguous_selectors_and_normalized_duplicates_fail_closed() -> None:
    selector_adapter: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
    with pytest.raises(ValidationError, match="duplicate selector resource id"):
        selector_adapter.validate_python(
            {
                "selectorType": "resourceIdList",
                "selectorId": "synthetic-duplicate-resources",
                "resourceIds": ["/synthetic/resource-a", "/SYNTHETIC/RESOURCE-A"],
                "maxMatches": 2,
            }
        )
    with pytest.raises(ValidationError, match="duplicate tag predicate key"):
        selector_adapter.validate_python(
            {
                "selectorType": "tagPredicate",
                "selectorId": "synthetic-duplicate-tags",
                "predicates": [
                    {"key": "environment", "value": "development"},
                    {"key": "ENVIRONMENT", "value": "training"},
                ],
                "maxMatches": 2,
            }
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["roles"][1]["selectors"] = deepcopy(payload["roles"][2]["selectors"])
    payload["roles"][1]["selectors"][0]["selectorId"] = (
        "synthetic-worker-overlap"
    )
    payload["roles"][1]["selectors"][0]["prefix"] = "athena-"
    with pytest.raises(AthenaValidationError, match="ambiguous selectors"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["constraints"][0]["profiles"] = [
        "production",
        "production",
    ]
    with pytest.raises(ValidationError, match="duplicate profile applicability"):
        CanonicalWorkloadManifest.model_validate(payload)


def test_composite_selector_ambiguity_ignores_child_identity_and_recurses() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    web = next(item for item in payload["roles"] if item["roleId"] == "web")
    worker = next(item for item in payload["roles"] if item["roleId"] == "worker")
    web["selectors"] = [
        {
            "selectorType": "compositeAny",
            "selectorId": "synthetic-web-composite",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "synthetic-web-alpha",
                    "prefix": "synthetic-alpha-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "namePredicate",
                    "selectorId": "synthetic-web-beta",
                    "prefix": "synthetic-beta-",
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        }
    ]
    worker["selectors"] = [
        {
            "selectorType": "compositeAny",
            "selectorId": "synthetic-worker-composite",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "renamed-worker-beta",
                    "prefix": "synthetic-beta-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "namePredicate",
                    "selectorId": "renamed-worker-alpha",
                    "prefix": "synthetic-alpha-",
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        }
    ]
    with pytest.raises(AthenaValidationError, match="identical semantics"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    web = next(item for item in payload["roles"] if item["roleId"] == "web")
    worker = next(item for item in payload["roles"] if item["roleId"] == "worker")
    web["selectors"] = [
        {
            "selectorType": "compositeAny",
            "selectorId": "synthetic-web-overlap",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "synthetic-shared-prefix",
                    "prefix": "synthetic-shared-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "namePredicate",
                    "selectorId": "synthetic-web-only",
                    "prefix": "synthetic-web-only-",
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        }
    ]
    worker["selectors"] = [
        {
            "selectorType": "compositeAll",
            "selectorId": "synthetic-worker-overlap",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "synthetic-worker-shared-prefix",
                    "prefix": "synthetic-shared-resource-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "tagPredicate",
                    "selectorId": "synthetic-worker-tag",
                    "predicates": [
                        {"key": "purpose", "value": "synthetic-regression"}
                    ],
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        }
    ]
    with pytest.raises(AthenaValidationError, match="ambiguous selectors"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_direct_selector_control_and_applicability_weakening_fail_closed() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    weakened_role = deepcopy(payload["roles"][2])
    weakened_role["selectors"][0]["prefix"] = "athena-"
    payload["profiles"]["development"]["roles"] = [weakened_role]
    with pytest.raises(AthenaValidationError, match="direct selector weakening"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    development_control = _control_payload("backup")
    development_control["profiles"] = ["development"]
    development_control["governanceScope"] = _scope(
        "development", "db-zone-loss-spof"
    )
    payload["controls"] = [development_control]
    weakened_control = deepcopy(development_control)
    weakened_control["health"] = "missing"
    payload["profiles"]["development"]["controls"] = [weakened_control]
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    inherited = _constraint(
        "development",
        "synthetic-inherited-applicability",
        "cardinality",
        "architectureConstraint",
        {
            "proofKind": "cardinalityProof",
            "roleRef": "worker",
            "expected": {"cardinalityKind": "oneOrMore"},
        },
        "pass",
    )
    inherited["protected"] = False
    payload["constraints"] = [inherited]
    hidden = deepcopy(inherited)
    hidden["profiles"] = ["training"]
    hidden["governanceScope"] = _scope(
        "training", "synthetic-inherited-applicability"
    )
    payload["profiles"]["development"]["constraints"].append(hidden)
    with pytest.raises(AthenaValidationError, match="direct applicability weakening"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )


@pytest.mark.parametrize(
    "replacement_selector",
    [
        {
            "selectorType": "namePredicate",
            "selectorId": "replacement-broad",
            "prefix": "athena-worker",
            "maxMatches": 1000,
        },
        {
            "selectorType": "resourceIdList",
            "selectorId": "replacement-explicit",
            "resourceIds": [f"{RESOURCE_PREFIX}athena-worker-001"],
            "maxMatches": 1,
        },
    ],
    ids=["broadening", "unguarded-new-identity"],
)
def test_generic_disjoint_selector_replacement_fails_closed(
    replacement_selector: dict[str, object],
) -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    worker = next(role for role in payload["roles"] if role["roleId"] == "worker")
    worker["selectors"][0]["maxMatches"] = 20
    replacement = deepcopy(worker)
    replacement["selectors"] = [replacement_selector]
    payload["profiles"]["production"]["roles"] = [replacement]

    with pytest.raises(
        AthenaValidationError,
        match="not a provably narrower guarded replacement",
    ):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_inherited_control_fields_require_exact_governance_and_keep_provenance() -> None:
    def development_backup() -> dict[str, object]:
        control = _control_payload("backup")
        control["profiles"] = ["development"]
        control["governanceScope"] = _scope(
            "development", "db-zone-loss-spof"
        )
        return control

    def control_override(field_name: str) -> dict[str, object]:
        return {
            "overrideId": f"synthetic-control-{field_name}",
            "reason": "controlRequirementRelaxation",
            "targetPath": (
                "/resolvedProfiles/development/controls/"
                f"control-backup/{field_name}"
            ),
            "targetRef": "control-backup",
            "ownerRef": "ops-owner",
            "rationale": "Synthetic governed control override regression.",
            "approvedBy": "synthetic-approver",
            "status": "approved",
            "acceptedAt": ACCEPTED_AT,
            "expiresAt": EXPIRES_AT,
            "profiles": ["development"],
        }

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["controls"] = [development_backup()]
    changed_control = development_backup()
    changed_control["backupPolicyRef"] = "synthetic://backup/replacement"
    payload["profiles"]["development"]["controls"] = [changed_control]
    with pytest.raises(AthenaValidationError, match="exactly one active governed override"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload["profiles"]["development"]["weakeningOverrides"].append(
        control_override("backupPolicyRef")
    )
    resolved = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "development",
        as_of=AS_OF,
    )
    assert resolved.controls[0].control_id == "control-backup"

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["controls"] = [development_backup()]
    changed_control = development_backup()
    changed_control["evidenceRefs"] = ["synthetic-replacement-evidence"]
    payload["profiles"]["development"]["controls"] = [changed_control]
    payload["profiles"]["development"]["weakeningOverrides"].append(
        control_override("evidenceRefs")
    )
    with pytest.raises(AthenaValidationError, match="evidenceRefs are immutable"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["controls"] = [development_backup()]
    retargeted_control = development_backup()
    retargeted_control["governanceScope"] = _scope(
        "development", "web-zone-distribution"
    )
    payload["profiles"]["development"]["controls"] = [retargeted_control]
    with pytest.raises(AthenaValidationError, match="governanceScope is immutable"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["ownership"].append(
        {
            "ownerRef": "synthetic-alternate-owner",
            "ownerRole": "technicalOwner",
            "authorityRef": "synthetic://teams/alternate-control-owner",
        }
    )
    payload["controls"] = [development_backup()]
    reassigned_control = development_backup()
    reassigned_control["ownerRef"] = "synthetic-alternate-owner"
    reassigned_control["governanceScope"]["ownerRef"] = (
        "synthetic-alternate-owner"
    )
    payload["profiles"]["development"]["controls"] = [reassigned_control]
    with pytest.raises(AthenaValidationError, match="ownerRef is immutable"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )


def test_governed_override_profile_matching_is_normalized() -> None:
    target_path = (
        "/resolvedProfiles/DEVELOPMENT/settings/continuity/"
        "zoneLossContinuityRequired"
    )
    override = GovernedWeakeningOverride.model_validate(
        {
            "overrideId": "synthetic-normalized-profile",
            "reason": "continuityRelaxation",
            "targetPath": target_path,
            "targetRef": "zoneLossContinuityRequired",
            "ownerRef": "ops-owner",
            "rationale": "Synthetic case-normalization regression.",
            "approvedBy": "synthetic-approver",
            "status": "approved",
            "acceptedAt": ACCEPTED_AT,
            "expiresAt": EXPIRES_AT,
            "profiles": ["development"],
        }
    )
    assert override.authorizes(
        as_of=AS_OF,
        profile_id="DEVELOPMENT",
        target_path=target_path,
        target_ref="ZONELOSSCONTINUITYREQUIRED",
        reason="continuityRelaxation",
    )


def test_inherited_risk_acceptance_mutation_is_invalid() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    inherited = deepcopy(
        payload["profiles"]["production"]["riskAcceptances"][0]
    )
    inherited["expiresAt"] = "2026-12-31T00:00:00.000Z"
    inherited["profiles"] = ["training"]
    inherited["governanceScope"] = _scope("training", "db-zone-loss-spof")
    payload["profiles"]["training"]["riskAcceptances"] = [inherited]
    with pytest.raises(AthenaValidationError, match="risk acceptances are immutable"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "training",
            as_of=AS_OF,
        )


def test_expired_or_scope_mismatched_acceptance_cannot_accept_risk() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    acceptance = payload["profiles"]["production"]["riskAcceptances"][0]
    acceptance["expiresAt"] = "2025-02-01T00:00:00.000Z"
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    findings = evaluate_manifest_profile(
        profile,
        _evidence("production", profile.resolved_profile_digest),
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["db-zone-loss-spof"].verdict == "violation"

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    acceptance = payload["profiles"]["production"]["riskAcceptances"][0]
    acceptance["governanceScope"]["clausePath"] = "/constraints/web-zone-distribution"
    with pytest.raises(AthenaValidationError, match="scope mismatch"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    replacement = _evidence("production", profile.resolved_profile_digest)
    database = next(item for item in replacement.resources if item.role_ref == "database-primary")
    database.resource_id = RESOURCE_PREFIX + "athena-db-02"
    database_binding = next(
        item for item in replacement.role_bindings if item.role_ref == "database-primary"
    )
    database_binding.selected_resource_ids = [database.resource_id]
    database_binding.selector_result_digest = compute_artifact_digest([database.resource_id])
    findings = evaluate_manifest_profile(
        profile,
        replacement,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["db-zone-loss-spof"].verdict == "violation"
    assert findings["db-zone-loss-spof"].risk_acceptance_ref is None


def test_exception_without_matching_active_acceptance_is_rejected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "exception",
            "exceptionId": "exception-db-zone-loss",
            "appliesToClauseRef": "db-zone-loss-spof",
            "riskAcceptanceRef": "ra-db-zone-loss-prod",
            "governanceScope": _scope("production", "db-zone-loss-spof"),
            "ownerRef": "ops-owner",
            "rationale": "Synthetic exception requiring explicit acceptance.",
            "expiresAt": EXPIRES_AT,
        }
    ]
    payload["profiles"]["production"]["riskAcceptances"][0]["status"] = "revoked"
    with pytest.raises(AthenaValidationError, match="matching active"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "exception",
            "exceptionId": "exception-expired",
            "appliesToClauseRef": "db-zone-loss-spof",
            "riskAcceptanceRef": "ra-db-zone-loss-prod",
            "governanceScope": _scope("production", "db-zone-loss-spof"),
            "ownerRef": "ops-owner",
            "rationale": "Synthetic expired exception.",
            "expiresAt": "2025-05-01T00:00:00.000Z",
        }
    ]
    with pytest.raises(AthenaValidationError, match="exception relationship is expired"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_gap_and_inference_only_evidence_never_yield_pass() -> None:
    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    evidence = _evidence("production", profile.resolved_profile_digest)
    missing_web = evidence.resources[-1].model_dump(mode="json", by_alias=True)
    missing_web["state"] = "gap"
    missing_web["evidenceRef"] = _gap_ref(4)
    evidence.resources[-1] = type(evidence.resources[-1]).model_validate(missing_web)
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-zone-distribution"].verdict == "unknown"
    assert findings["web-zone-distribution"].verdict != "pass"

    evidence = _evidence("production", profile.resolved_profile_digest)
    missing_database = evidence.resources[0].model_dump(mode="json", by_alias=True)
    missing_database["state"] = "gap"
    missing_database["evidenceRef"] = _gap_ref(0)
    evidence.resources[0] = type(evidence.resources[0]).model_validate(missing_database)
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["db-zone-loss-spof"].verdict == "unknown"
    assert findings["db-zone-loss-acceptance"].verdict == "unknown"

    evidence = _evidence("production", profile.resolved_profile_digest)
    for item in evidence.resources:
        if item.role_ref == "worker":
            item.proof_source = "inferred"
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["worker-db-zone-colocation"].verdict == "unknown"


def test_database_unknown_zone_and_unbound_provenance_fail_closed() -> None:
    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.resources[0].availability_zone = "unknown"
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["db-singleton-supported"].verdict == "unknown"
    assert findings["db-zone-loss-spof"].verdict == "unknown"

    payload = _evidence("production", profile.resolved_profile_digest).model_dump(
        mode="json", by_alias=True
    )
    payload["resources"][0]["evidenceRef"]["snapshotId"] = "snap-222222222222"
    with pytest.raises(ValidationError, match="trusted snapshot context"):
        EvidenceReferenceContext.model_validate(payload)

    fabricated = _evidence("production", profile.resolved_profile_digest).model_dump(
        mode="json", by_alias=True
    )
    fabricated["resources"][0]["evidenceRef"]["itemDigest"] = "sha256:" + "f" * 64
    fabricated_context = EvidenceReferenceContext.model_validate(fabricated)
    with pytest.raises(AthenaValidationError, match="not authenticated"):
        evaluate_manifest_profile(
            profile,
            fabricated_context,
            as_of=AS_OF,
            verify_evidence_context=_verify_fixture_context,
        )

    omitted = _evidence("production", profile.resolved_profile_digest)
    omitted.resources = [
        item for item in omitted.resources if not item.resource_id.endswith("athena-worker-02")
    ]
    with pytest.raises(AthenaValidationError, match="role binding"):
        evaluate_manifest_profile(
            profile,
            omitted,
            as_of=AS_OF,
            verify_evidence_context=_verify_fixture_context,
        )


def test_relationship_and_control_gaps_cannot_claim_complete_proof() -> None:
    with pytest.raises(ValidationError, match="complete proof facts"):
        RelationshipProofFact(
            relationshipRef="worker-depends-db",
            state="complete",
            proofSource="observed",
            presence="present",
            evidenceRef=_gap_ref(20),
        )
    with pytest.raises(ValidationError, match="complete proof facts"):
        ControlProofFact(
            controlRef="backup-control",
            state="complete",
            health="effective",
            evidenceRef=_gap_ref(21),
        )


def test_legacy_resolver_cannot_bypass_governed_weakening() -> None:
    production = ProfileDefinition(
        profileId="production",
        profileType="production",
        settings=ProfileSettings(continuity={"zoneLossContinuityRequired": True}),
    )
    development = ProfileDefinition(
        profileId="development",
        profileType="development",
        extends="production",
        settings=ProfileSettings(continuity={"zoneLossContinuityRequired": False}),
    )
    with pytest.raises(AthenaValidationError, match="legacy profile weakening"):
        development.resolve(
            {"production": production, "development": development},
            as_of=AS_OF,
        )


def test_controls_protection_and_override_owners_are_profile_safe() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["controls"] = [_control_payload("backup")]
    manifest = CanonicalWorkloadManifest.model_validate(payload)
    production = resolve_manifest_profile(manifest, "production", as_of=AS_OF)
    development = resolve_manifest_profile(manifest, "development", as_of=AS_OF)
    assert len(production.controls) == 1
    assert development.controls == []

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    development_control = _control_payload("backup")
    development_control["controlId"] = "development-backup"
    development_control["profiles"] = ["development"]
    development_control["governanceScope"] = _scope("development", "db-zone-loss-spof")
    payload["controls"] = [development_control]
    development = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "development",
        as_of=AS_OF,
    )
    assert [item.control_id for item in development.controls] == ["development-backup"]

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    singleton = next(
        item
        for item in payload["profiles"]["production"]["constraints"]
        if item["constraintId"] == "db-singleton-supported"
    )
    singleton["protected"] = False
    with pytest.raises(AthenaValidationError, match="must remain protected"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["development"]["weakeningOverrides"][0]["ownerRef"] = "unresolved-owner"
    with pytest.raises(AthenaValidationError, match="override ownerRef"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["ownership"].extend(
        [
            {
                "ownerRef": "constraint-owner",
                "ownerRole": "technicalOwner",
                "authorityRef": "synthetic://teams/constraint",
            },
            {
                "ownerRef": "objective-owner",
                "ownerRole": "businessOwner",
                "authorityRef": "synthetic://teams/objective",
            },
        ]
    )
    web_constraint = next(
        item
        for item in payload["profiles"]["development"]["constraints"]
        if item["constraintId"] == "web-zone-distribution"
    )
    web_constraint["ownerRef"] = "constraint-owner"
    web_constraint["governanceScope"]["ownerRef"] = "constraint-owner"
    payload["profiles"]["development"]["weakeningOverrides"][1]["ownerRef"] = "objective-owner"
    payload["objectives"] = [
        {
            "objectiveId": "web-zone-distribution",
            "objectiveType": "availabilitySlo",
            "ownerRef": "objective-owner",
            "target": 99.0,
        }
    ]
    with pytest.raises(AthenaValidationError, match="target owner"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "development",
            as_of=AS_OF,
        )


def test_control_scope_requires_exact_canonical_clause_pointer() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "wrong-scope",
            "controlRequired",
            "controlHealth",
            {
                "proofKind": "controlHealthProof",
                "controlRef": "control-backup",
                "requiredHealth": "effective",
            },
            "pass",
        )
    )
    control = _control_payload("backup")
    control["governanceScope"]["clausePath"] = "/wrong-scope"
    payload["controls"] = [control]
    with pytest.raises(AthenaValidationError, match="control manifest"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_root_protected_semantics_and_disabled_owner_cannot_be_bypassed() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    top_level = deepcopy(payload["profiles"]["production"]["constraints"][0])
    payload["constraints"] = [top_level]
    root_override = deepcopy(top_level)
    root_override["successVerdict"] = "pass"
    payload["profiles"]["production"]["constraints"][0] = root_override
    with pytest.raises(AthenaValidationError, match="protected constraint semantics"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )

    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["ownership"].append(
        {
            "ownerRef": "wrong-owner",
            "ownerRole": "technicalOwner",
            "authorityRef": "synthetic://teams/wrong",
        }
    )
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "optional-constraint",
            "cardinality",
            "architectureConstraint",
            {
                "proofKind": "cardinalityProof",
                "roleRef": "worker",
                "expected": {"cardinalityKind": "oneOrMore"},
            },
            "pass",
        )
    )
    payload["profiles"]["production"]["weakeningOverrides"] = [
        {
            "overrideId": "disable-optional",
            "reason": "disableInheritedItem",
            "targetPath": ("/resolvedProfiles/production/constraint/optional-constraint"),
            "targetRef": "optional-constraint",
            "ownerRef": "wrong-owner",
            "rationale": "Synthetic negative fixture.",
            "approvedBy": "synthetic-approver",
            "status": "approved",
            "acceptedAt": ACCEPTED_AT,
            "expiresAt": EXPIRES_AT,
            "profiles": ["production"],
        }
    ]
    payload["profiles"]["production"]["disabledRefs"] = [
        {
            "targetKind": "constraint",
            "targetRef": "optional-constraint",
            "governanceOverrideRef": "disable-optional",
        }
    ]
    with pytest.raises(AthenaValidationError, match="target owner"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_exception_scope_must_match_exact_target() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "exception",
            "exceptionId": "exception-wrong-target",
            "appliesToClauseRef": "web-zone-distribution",
            "riskAcceptanceRef": "ra-db-zone-loss-prod",
            "governanceScope": _scope("production", "db-zone-loss-spof"),
            "ownerRef": "ops-owner",
            "rationale": "Synthetic negative fixture.",
            "expiresAt": EXPIRES_AT,
        }
    ]
    with pytest.raises(AthenaValidationError, match="exact target"):
        resolve_manifest_profile(
            CanonicalWorkloadManifest.model_validate(payload),
            "production",
            as_of=AS_OF,
        )


def test_valid_exception_overlay_applies_matching_active_acceptance() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["riskAcceptances"].append(
        {
            **_acceptance("production", "ra-web-zone"),
            "governanceScope": _scope("production", "web-zone-distribution"),
            "acceptedResourceBindings": [
                {
                    "roleRef": "web",
                    "resourceId": RESOURCE_PREFIX + "athena-web-01",
                },
                {
                    "roleRef": "web",
                    "resourceId": RESOURCE_PREFIX + "athena-web-02",
                },
            ],
        }
    )
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "exception",
            "exceptionId": "exception-web-zone",
            "appliesToClauseRef": "web-zone-distribution",
            "riskAcceptanceRef": "ra-web-zone",
            "governanceScope": _scope("production", "web-zone-distribution"),
            "ownerRef": "ops-owner",
            "rationale": "Synthetic scoped web-zone exception.",
            "expiresAt": EXPIRES_AT,
        }
    ]
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    for item in evidence.resources:
        if item.role_ref == "web":
            item.availability_zone = "1"
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-zone-distribution"].verdict == "acceptedResidualRisk"
    assert findings["web-zone-distribution"].risk_acceptance_ref == "ra-web-zone"

    payload["profiles"]["production"]["relationships"][0]["expiresAt"] = "2025-05-01T00:00:00.000Z"
    early_as_of = datetime(2025, 4, 1, tzinfo=UTC)
    early_profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=early_as_of,
    )
    expired_evidence = _evidence("production", early_profile.resolved_profile_digest)
    for item in expired_evidence.resources:
        if item.role_ref == "web":
            item.availability_zone = "1"
    expired_findings = evaluate_manifest_profile(
        early_profile,
        expired_evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert expired_findings["web-zone-distribution"].verdict == "violation"
    assert expired_findings["web-zone-distribution"].risk_acceptance_ref is None


def test_prohibited_relationship_presence_is_a_violation() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "declared",
            "relationshipId": "web-prohibited-db-call",
            "kind": "prohibited",
            "source": {"endpointType": "role", "roleRef": "web"},
            "target": {
                "endpointType": "role",
                "roleRef": "database-primary",
            },
            "ownerRef": "ops-owner",
            "profiles": ["production"],
            "sourceClause": "/constraints/web-db-call-prohibited",
        }
    ]
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "web-db-call-prohibited",
            "dependencyProhibited",
            "architectureConstraint",
            {
                "proofKind": "relationshipPresenceProof",
                "declaredRelationshipRef": "web-prohibited-db-call",
            },
            "pass",
        )
    )
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.relationships = [
        RelationshipProofFact(
            relationshipRef="web-prohibited-db-call",
            state="complete",
            proofSource="observed",
            presence="present",
            evidenceRef=_item_ref(20),
        )
    ]
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-db-call-prohibited"].verdict == "violation"

    absent_evidence = _evidence("production", profile.resolved_profile_digest)
    absent_evidence.relationships = [
        RelationshipProofFact(
            relationshipRef="web-prohibited-db-call",
            state="complete",
            proofSource="observed",
            presence="absent",
            evidenceRef=_item_ref(21),
        )
    ]
    absent_findings = evaluate_manifest_profile(
        profile,
        absent_evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert absent_findings["web-db-call-prohibited"].verdict == "pass"

    invalid = deepcopy(payload)
    prohibited = invalid["profiles"]["production"]["constraints"][-1]
    prohibited["failureVerdict"] = "unknown"
    prohibited["proofRequirement"] = {
        "proofKind": "cardinalityProof",
        "roleRef": "web",
        "expected": {"cardinalityKind": "oneOrMore"},
    }
    with pytest.raises(ValidationError, match="matching proof variant"):
        CanonicalWorkloadManifest.model_validate(invalid)


def test_relationship_acceptance_requires_exact_endpoint_bindings() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["relationships"] = [
        {
            "relationshipClass": "declared",
            "relationshipId": "web-prohibited-db-call",
            "kind": "prohibited",
            "source": {"endpointType": "role", "roleRef": "web"},
            "target": {
                "endpointType": "role",
                "roleRef": "database-primary",
            },
            "ownerRef": "ops-owner",
            "profiles": ["production"],
            "sourceClause": "/constraints/web-db-call-prohibited",
        },
        {
            "relationshipClass": "exception",
            "exceptionId": "exception-web-db-call",
            "appliesToRelationshipRef": "web-prohibited-db-call",
            "riskAcceptanceRef": "ra-web-db-call",
            "governanceScope": _scope("production", "web-db-call-prohibited"),
            "ownerRef": "ops-owner",
            "rationale": "Synthetic relationship exception.",
            "expiresAt": EXPIRES_AT,
        },
    ]
    payload["profiles"]["production"]["riskAcceptances"].append(
        {
            **_acceptance("production", "ra-web-db-call"),
            "governanceScope": _scope("production", "web-db-call-prohibited"),
            "acceptedResourceBindings": [
                {
                    "roleRef": "database-primary",
                    "resourceId": RESOURCE_PREFIX + "athena-db-01",
                },
                {
                    "roleRef": "web",
                    "resourceId": RESOURCE_PREFIX + "athena-web-01",
                },
                {
                    "roleRef": "web",
                    "resourceId": RESOURCE_PREFIX + "athena-web-02",
                },
            ],
        }
    )
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "web-db-call-prohibited",
            "dependencyProhibited",
            "relationshipConflict",
            {
                "proofKind": "relationshipPresenceProof",
                "declaredRelationshipRef": "web-prohibited-db-call",
            },
            "pass",
        )
    )
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.relationships = [
        RelationshipProofFact(
            relationshipRef="web-prohibited-db-call",
            state="complete",
            proofSource="observed",
            presence="present",
            evidenceRef=_item_ref(22),
        )
    ]
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-db-call-prohibited"].verdict == "acceptedResidualRisk"

    replacement = _evidence("production", profile.resolved_profile_digest)
    database = next(item for item in replacement.resources if item.role_ref == "database-primary")
    database.resource_id = RESOURCE_PREFIX + "athena-db-02"
    database_binding = next(
        item for item in replacement.role_bindings if item.role_ref == "database-primary"
    )
    database_binding.selected_resource_ids = [database.resource_id]
    database_binding.selector_result_digest = compute_artifact_digest([database.resource_id])
    replacement.relationships = evidence.relationships
    replacement_findings = evaluate_manifest_profile(
        profile,
        replacement,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert replacement_findings["web-db-call-prohibited"].verdict == "violation"

    missing_binding = _evidence("production", profile.resolved_profile_digest)
    missing_binding.role_bindings = [
        item for item in missing_binding.role_bindings if item.role_ref != "database-primary"
    ]
    missing_binding.relationships = evidence.relationships
    missing_binding_findings = evaluate_manifest_profile(
        profile,
        missing_binding,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert missing_binding_findings["web-db-call-prohibited"].verdict == "unknown"
    assert missing_binding_findings["web-db-call-prohibited"].evidence_refs


def test_acceptance_scope_and_finding_kind_cannot_be_redirected() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    spof = next(
        item
        for item in payload["profiles"]["production"]["constraints"]
        if item["constraintId"] == "db-zone-loss-spof"
    )
    spof["riskAcceptanceClauseRef"] = "web-zone-distribution"
    with pytest.raises(ValidationError, match="riskAcceptanceClauseRef"):
        CanonicalWorkloadManifest.model_validate(payload)


def test_control_health_violation_remains_visible_with_acceptance() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["controls"] = [_control_payload("backup")]
    payload["profiles"]["production"]["riskAcceptances"].append(
        {
            **_acceptance("production", "ra-control-health"),
            "governanceScope": _scope("production", "backup-control-health"),
        }
    )
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "backup-control-health",
            "controlRequired",
            "controlHealth",
            {
                "proofKind": "controlHealthProof",
                "controlRef": "control-backup",
                "requiredHealth": "effective",
            },
            "pass",
            risk_ref="ra-control-health",
        )
    )
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.controls = [
        ControlProofFact(
            controlRef="control-backup",
            state="complete",
            health="degraded",
            evidenceRef=_item_ref(30),
        )
    ]
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["backup-control-health"].verdict == "violation"
    assert findings["backup-control-health"].risk_acceptance_ref is None


def test_large_proofs_are_bounded_without_overflowing_finding_citations() -> None:
    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.resources = [item for item in evidence.resources if item.role_ref != "web"]
    resource_prefix = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-athena-fixture/providers/Microsoft.Compute/virtualMachines/"
    )
    for index in range(1001):
        evidence.resources.append(
            ResourceProofFact(
                resourceId=resource_prefix + f"athena-web-{index:04d}",
                roleRef="web",
                availabilityZone="1" if index % 2 == 0 else "2",
                state="complete",
                proofSource="observed",
                evidenceRef=_item_ref(index + 10),
            )
        )
    web_binding = next(item for item in evidence.role_bindings if item.role_ref == "web")
    selected_resource_ids = [
        item.resource_id for item in evidence.resources if item.role_ref == "web"
    ]
    with pytest.raises(ValidationError):
        web_binding.selected_resource_ids = selected_resource_ids
    evidence.resources = evidence.resources[:-1]
    selected_resource_ids = selected_resource_ids[:-1]
    evidence.role_bindings[evidence.role_bindings.index(web_binding)] = type(web_binding)(
        roleRef="web",
        selectedResourceIds=selected_resource_ids,
        selectorResultDigest=compute_artifact_digest(
            sorted(selected_resource_ids, key=str.casefold)
        ),
        state="complete",
    )
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-zone-distribution"].verdict == "pass"
    assert len(findings["web-zone-distribution"].evidence_refs) == 1000


def test_duplicate_resource_facts_fail_closed() -> None:
    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    payload = _evidence("production", profile.resolved_profile_digest).model_dump(
        mode="json", by_alias=True
    )
    duplicate = deepcopy(payload["resources"][-1])
    duplicate["availabilityZone"] = "3"
    duplicate["evidenceRef"] = _item_ref(50)
    payload["resources"].append(duplicate)
    with pytest.raises(ValidationError, match="duplicate or conflicting"):
        EvidenceReferenceContext.model_validate(payload)


def test_objective_proof_uses_only_matching_objective_evidence() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["objectives"] = [
        {
            "objectiveId": "availability-objective",
            "objectiveType": "availabilitySlo",
            "ownerRef": "ops-owner",
            "target": 99.9,
        }
    ]
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "availability-objective-check",
            "objectiveRequired",
            "objective",
            {
                "proofKind": "objectiveThresholdProof",
                "objectiveRef": "availability-objective",
                "comparison": "gte",
                "threshold": 99.9,
            },
            "pass",
        )
    )
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    evidence.objectives = [
        ObjectiveProofFact(
            objectiveRef="availability-objective",
            state="complete",
            currentValue=99.95,
            evidenceRef=_item_ref(40),
        )
    ]
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    objective = findings["availability-objective-check"]
    assert objective.verdict == "pass"
    assert len(objective.evidence_refs) == 1
    assert objective.evidence_refs[0] == evidence.objectives[0].evidence_ref


def test_freshness_gap_cannot_become_accepted_residual_risk() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["profiles"]["production"]["riskAcceptances"].append(
        {
            **_acceptance("production", "ra-freshness"),
            "governanceScope": _scope("production", "freshness-check"),
        }
    )
    payload["profiles"]["production"]["constraints"].append(
        _constraint(
            "production",
            "freshness-check",
            "evidenceFreshness",
            "architectureConstraint",
            {
                "proofKind": "evidenceFreshnessProof",
                "maximumAgeSeconds": 1,
            },
            "pass",
            risk_ref="ra-freshness",
        )
    )
    profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    evidence = _evidence("production", profile.resolved_profile_digest)
    missing_database = evidence.resources[0].model_dump(mode="json", by_alias=True)
    missing_database["state"] = "gap"
    missing_database["evidenceRef"] = _gap_ref(0)
    evidence.resources[0] = ResourceProofFact.model_validate(missing_database)
    findings = evaluate_manifest_profile(
        profile,
        evidence,
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["freshness-check"].verdict == "unknown"
    assert findings["freshness-check"].risk_acceptance_ref is None


def test_three_profile_oracle_uses_one_contract_path() -> None:
    manifest = build_manifest()
    expected = {
        "production": {
            "db-singleton-supported": "expectedConstraint",
            "db-zone-loss-spof": "acceptedResidualRisk",
            "db-zone-loss-acceptance": "acceptedResidualRisk",
            "worker-db-zone-colocation": "pass",
            "web-zone-distribution": "pass",
        },
        "development": {
            "db-singleton-supported": "expectedConstraint",
            "db-zone-loss-spof": "observation",
            "db-zone-loss-acceptance": "observation",
            "worker-db-zone-colocation": "pass",
            "web-zone-distribution": "pass",
        },
        "training": {
            "db-singleton-supported": "expectedConstraint",
            "db-zone-loss-spof": "acceptedResidualRisk",
            "db-zone-loss-acceptance": "acceptedResidualRisk",
            "worker-db-zone-colocation": "pass",
            "web-zone-distribution": "violation",
        },
    }
    for profile_id, expected_verdicts in expected.items():
        profile = resolve_manifest_profile(manifest, profile_id, as_of=AS_OF)
        findings = evaluate_manifest_profile(
            profile,
            _evidence(profile_id, profile.resolved_profile_digest),
            as_of=AS_OF,
            verify_evidence_context=_verify_fixture_context,
        )
        assert {
            clause_id: finding.verdict for clause_id, finding in findings.items()
        } == expected_verdicts
        for finding in findings.values():
            assert finding.manifest_version == "1.0.0"
            assert finding.governance_scope.profile_id == profile_id
            assert finding.evidence_refs
        assert len(findings["db-singleton-supported"].evidence_refs) == 1
        assert len(findings["web-zone-distribution"].evidence_refs) == 2


def test_manifest_schema_is_closed_and_deterministic() -> None:
    schema_a = CanonicalWorkloadManifest.model_json_schema()
    schema_b = CanonicalWorkloadManifest.model_json_schema()
    assert schema_a == schema_b
    assert schema_a["$id"].endswith("/CanonicalWorkloadManifest/1.0.0")
    assert schema_a["x-athena-schemaVersion"] == "1.0.0"
    assert schema_a["x-athena-semanticContractVersion"] == "1.0.0"
    assert schema_a["x-athena-policyContractVersion"] == "1.0.0"
    assert schema_a["x-athena-requiresCapabilities"] == []
    assert schema_a["additionalProperties"] is False

    def assert_classified(value: object) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                for property_schema in properties.values():
                    assert property_schema["x-athena-semanticClass"] in {"semantic", "presentation"}
            for child in value.values():
                assert_classified(child)
        elif isinstance(value, list):
            for child in value:
                assert_classified(child)

    assert_classified(schema_a)
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    assert not list(Draft202012Validator(schema_a).iter_errors(payload))
    with pytest.raises(ValidationError):
        CanonicalWorkloadManifest.model_validate({**payload, "unexpected": True})

    baseline = build_manifest()
    changed_payload = baseline.model_dump(mode="json", by_alias=True)
    changed_payload["profiles"]["production"]["settings"]["continuity"][
        "zoneLossContinuityRequired"
    ] = False
    changed = CanonicalWorkloadManifest.model_validate(changed_payload)
    assert baseline.compute_semantic_digest_value() != changed.compute_semantic_digest_value()

    presentation_payload = baseline.model_dump(mode="json", by_alias=True, exclude_unset=True)
    presentation_payload["workload"]["displayName"] = "Renamed synthetic workload"
    presentation = CanonicalWorkloadManifest.model_validate(presentation_payload)
    assert baseline.compute_semantic_digest_value() == presentation.compute_semantic_digest_value()
    assert baseline.compute_artifact_digest_value() != presentation.compute_artifact_digest_value()

    tampered = baseline.model_dump(mode="json", by_alias=True)
    tampered["compatibility"]["artifactDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="canonical preimages"):
        _CanonicalWorkloadManifest.model_validate(tampered)
    missing = baseline.model_dump(mode="json", by_alias=True)
    del missing["compatibility"]["semanticDigest"]
    with pytest.raises(ValidationError):
        _CanonicalWorkloadManifest.model_validate(missing)

    one_profile = baseline.model_dump(mode="json", by_alias=True)
    one_profile["profiles"] = {"production": one_profile["profiles"]["production"]}
    with pytest.raises(ValidationError, match="requires production"):
        CanonicalWorkloadManifest.model_validate(one_profile)


def test_compatibility_identity_and_scope_containment_are_resolved() -> None:
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    payload["compatibility"]["artifactKind"] = "evidenceSnapshot"
    with pytest.raises(ValidationError, match="artifactKind"):
        CanonicalWorkloadManifest.model_validate(payload)

    unsupported = build_manifest().model_dump(mode="json", by_alias=True)
    unsupported["compatibility"]["policyContractVersion"] = "2.0.0"
    unsupported["compatibility"]["minimumReaderVersion"] = "99.0.0"
    unsupported["compatibility"]["requiresCapabilities"] = [
        {
            "capabilityId": "athena.unknown.evaluate",
            "minimumVersion": "1.0.0",
            "requiredFor": "evaluate",
        }
    ]
    with pytest.raises(ValidationError, match="not supported"):
        CanonicalWorkloadManifest.model_validate(unsupported)

    manifest = build_manifest()
    original_profile = resolve_manifest_profile(manifest, "production", as_of=AS_OF)
    assert original_profile.compatibility.artifact_kind == "resolvedProfile"
    assert (
        original_profile.compatibility.artifact_digest
        == original_profile.recompute_artifact_digest()
    )
    assert (
        original_profile.compatibility.semantic_digest == original_profile.resolved_profile_digest
    )
    assert (
        original_profile.compatibility.semantic_digest
        == original_profile.recompute_semantic_digest()
    )

    payload = manifest.model_dump(mode="json", by_alias=True)
    payload["workload"]["allowedEvidenceScopes"] = [
        {
            "scopeType": "subscription",
            "tenantId": "00000000-0000-0000-0000-000000000000",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
        }
    ]
    scoped_profile = resolve_manifest_profile(
        CanonicalWorkloadManifest.model_validate(payload),
        "production",
        as_of=AS_OF,
    )
    findings = evaluate_manifest_profile(
        scoped_profile,
        _evidence("production", scoped_profile.resolved_profile_digest),
        as_of=AS_OF,
        verify_evidence_context=_verify_fixture_context,
    )
    assert findings["web-zone-distribution"].verdict == "pass"

    changed_payload = manifest.model_dump(mode="json", by_alias=True)
    changed_payload["compatibility"]["schemaVersion"] = "1.0.1"
    changed_manifest = CanonicalWorkloadManifest.model_validate(changed_payload)
    changed_profile = resolve_manifest_profile(
        changed_manifest,
        "production",
        as_of=AS_OF,
    )
    assert (
        changed_profile.compatibility.semantic_digest
        == original_profile.compatibility.semantic_digest
    )
    assert (
        changed_profile.compatibility.artifact_digest
        != original_profile.compatibility.artifact_digest
    )


def test_public_manifest_api_and_defaulted_digest_round_trip() -> None:
    assert PublicWorkloadManifest is _CanonicalWorkloadManifest
    payload = build_manifest().model_dump(mode="json", by_alias=True)
    for profile in payload["profiles"].values():
        if profile.get("extends") is None:
            profile.pop("extends", None)
    for role in payload["roles"]:
        role.pop("status")
    for constraints in [
        payload["constraints"],
        *[profile["constraints"] for profile in payload["profiles"].values()],
    ]:
        for constraint in constraints:
            constraint.pop("protected")
    payload["roles"][0]["selectors"] = [
        {
            "selectorType": "resourceType",
            "selectorId": "database-type",
            "resourceType": "Microsoft.Compute/virtualMachines",
            "maxMatches": 10,
        }
    ]
    manifest = CanonicalWorkloadManifest.model_validate(payload)
    serialized = manifest.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert _CanonicalWorkloadManifest.model_validate(serialized) == manifest

    absent_null = manifest.model_dump(mode="json", by_alias=True, exclude_unset=True)
    explicit_null = deepcopy(absent_null)
    explicit_null["profiles"]["production"]["extends"] = None
    explicit_manifest = CanonicalWorkloadManifest.model_validate(explicit_null)
    assert (
        manifest.compute_artifact_digest_value()
        != explicit_manifest.compute_artifact_digest_value()
    )
    tampered = explicit_manifest.model_dump(mode="json", by_alias=True, exclude_unset=True)
    del tampered["profiles"]["production"]["extends"]
    with pytest.raises(ValidationError, match="canonical preimages"):
        _CanonicalWorkloadManifest.model_validate(tampered)


def test_mutated_resolved_profile_is_rejected_before_evaluation() -> None:
    profile = resolve_manifest_profile(build_manifest(), "production", as_of=AS_OF)
    web = next(
        item for item in profile.constraints if item.constraint_id == "web-zone-distribution"
    )
    web.proof_requirement.minimum_distinct_zones = 3
    with pytest.raises(AthenaValidationError, match="changed after digest"):
        evaluate_manifest_profile(
            profile,
            _evidence("production", profile.resolved_profile_digest),
            as_of=AS_OF,
            verify_evidence_context=_verify_fixture_context,
        )
