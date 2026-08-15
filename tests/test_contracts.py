from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import TypeAdapter, ValidationError

from athena_context import __version__
from athena_context.contracts import (
    CapabilityRequirement,
    CompatibilityMetadata,
    ContextRef,
    Control,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceScope,
    Finding,
    GovernanceProfileScope,
    NamePatternSelector,
    ProducerInfo,
    ProfileContinuitySettings,
    ProfileDefinition,
    ProfileSettings,
    RiskAcceptance,
    RoleCardinalityBoundedRange,
    RoleCardinalityExactlyOne,
    Selector,
    SubscriptionScope,
    WorkloadManifest,
    WorkloadRole,
    canonicalize_json,
    compute_artifact_digest,
    compute_semantic_digest,
)
from athena_context.contracts.common import NormalizationCollisionError


def build_manifest() -> WorkloadManifest:
    roles = [
        WorkloadRole(
            roleId="database-primary",
            kind="singletonDatabase",
            displayName="Primary database",
            cardinality=RoleCardinalityExactlyOne(cardinalityKind="exactlyOne"),
            selectors=[
                NamePatternSelector(
                    selectorType="namePattern",
                    pattern="athena-db-*",
                    maxMatches=10,
                )
            ],
            profileApplicability=["production", "development", "training"],
            ownerRef="technical-owner",
            approvalState="approved",
        ),
        WorkloadRole(
            roleId="worker",
            kind="worker",
            displayName="Worker tier",
            cardinality=RoleCardinalityBoundedRange(
                cardinalityKind="boundedRange", minimum=1, maximum=2
            ),
            selectors=[
                NamePatternSelector(
                    selectorType="namePattern",
                    pattern="athena-worker-*",
                    maxMatches=10,
                )
            ],
            profileApplicability=["production", "development", "training"],
            ownerRef="technical-owner",
            approvalState="approved",
        ),
        WorkloadRole(
            roleId="web",
            kind="webService",
            displayName="Web tier",
            cardinality=RoleCardinalityBoundedRange(
                cardinalityKind="boundedRange", minimum=1, maximum=4
            ),
            selectors=[
                NamePatternSelector(
                    selectorType="namePattern",
                    pattern="athena-web-*",
                    maxMatches=10,
                )
            ],
            profileApplicability=["production", "development", "training"],
            ownerRef="technical-owner",
            approvalState="approved",
        ),
    ]
    profiles = {
        "production": ProfileDefinition(
            profileId="production",
            profileType="production",
            extends=None,
            settings=ProfileSettings(
                continuity=ProfileContinuitySettings(zoneLossContinuityRequired=True),
            ),
            overrides=[],
        ),
        "development": ProfileDefinition(
            profileId="development",
            profileType="development",
            extends="production",
            settings=ProfileSettings(
                continuity=ProfileContinuitySettings(zoneLossContinuityRequired=False),
            ),
            overrides=[],
        ),
        "training": ProfileDefinition(
            profileId="training",
            profileType="training",
            extends="production",
            settings=ProfileSettings(
                continuity=ProfileContinuitySettings(zoneLossContinuityRequired=True),
            ),
            overrides=[],
        ),
    }
    compatibility = CompatibilityMetadata(
        artifactKind="workloadManifest",
        schemaVersion="1.0.0",
        semanticContractVersion="1.0.0",
        policyContractVersion="1.0.0",
        minimumReaderVersion="1.0.0",
        requiresCapabilities=[],
        producedBy=ProducerInfo(producerId="athena.contracts", version="1.0.0"),
        extensionPolicy="rejectUnknownDecisionFields",
        artifactDigest="sha256:placeholder-artifact",
        semanticDigest="sha256:placeholder-semantic",
    )
    return WorkloadManifest(
        manifestId="wl-synthetic-clinical-platform",
        manifestVersion="0.1.0",
        workload={
            "displayName": "Synthetic clinical platform",
            "businessCriticality": "missionCritical",
            "dataSensitivity": "syntheticOnly",
            "allowedEvidenceScopes": [
                {
                    "scopeType": "resourceGroup",
                    "tenantId": "00000000-0000-0000-0000-000000000000",
                    "subscriptionId": "00000000-0000-0000-0000-000000000000",
                    "resourceGroupName": "rg-athena-fixture",
                }
            ],
        },
        profiles=profiles,
        roles=roles,
        relationships={"declared": [], "exceptions": []},
        constraints=[],
        controls=[],
        riskAcceptances=[],
        objectives=[],
        ownership={"technicalOwner": "owner-1", "operationsOwner": "owner-2"},
        compatibility=compatibility,
        audit={"publishedBy": "human-approved-context-api"},
    )


def test_package_version_is_available() -> None:
    assert __version__ == "0.1.0"


def test_manifest_schema_rejects_unknown_fields() -> None:
    data = build_manifest().model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError):
        WorkloadManifest.model_validate({**data, "unexpected": True})


def test_selector_union_rejects_unknown_variant() -> None:
    adapter: TypeAdapter[Selector] = TypeAdapter(Selector)
    with pytest.raises(ValidationError):
        adapter.validate_python({"selectorType": "unknown", "resourceIds": ["/subscriptions/x"]})


def test_semantic_digest_changes_when_semantic_field_mutates() -> None:
    manifest = build_manifest()
    baseline = manifest.compute_semantic_digest_value()
    manifest.profiles["development"].settings.continuity.zone_loss_continuity_required = True
    changed = manifest.compute_semantic_digest_value()
    assert changed != baseline


def test_digest_stability_and_normalization_collision() -> None:
    payload = {"z": 1, "a": ["é", "e\u0301"], "nested": {"key": "value"}}
    canonical_a = canonicalize_json(payload)
    canonical_b = canonicalize_json({"a": ["é", "e\u0301"], "nested": {"key": "value"}, "z": 1})
    assert canonical_a == canonical_b
    with pytest.raises(NormalizationCollisionError):
        canonicalize_json({"é": 1, "e\u0301": 2})


def test_risk_acceptance_and_finding_valid() -> None:
    acceptance = RiskAcceptance(
        riskAcceptanceId="ra-db-zone-loss-prod",
        governanceScope=GovernanceProfileScope(
            governanceScopeType="profile",
            manifestId="wl-synthetic-clinical-platform",
            profileId="production",
        ),
        ownerRef="technical-owner",
        rationale="Accept singleton database zone-loss risk for the approved production profile.",
        acceptedAt=datetime.now(tz=UTC),
        expiresAt=datetime.now(tz=UTC) + timedelta(days=30),
        active=True,
        appliesToClausePath="/constraints/db-zone-loss-spof",
    )
    assert acceptance.risk_acceptance_id == "ra-db-zone-loss-prod"

    finding = Finding(
        findingKind="actualSpof",
        verdict="acceptedResidualRisk",
        governanceScope=GovernanceProfileScope(
            governanceScopeType="profile",
            manifestId="wl-synthetic-clinical-platform",
            profileId="production",
        ),
        contextRef=ContextRef(
            manifestId="wl-synthetic-clinical-platform",
            manifestVersion="0.1.0",
            profileId="production",
            resolvedProfileDigest="sha256:abc123",
            clausePath="/constraints/db-zone-loss-spof",
        ),
        evidenceRef=EvidenceItemRef(
            refType="evidenceItem",
            snapshotId="snap-wc001-canonical-001",
            snapshotArtifactDigest="sha256:abc",
            snapshotSemanticDigest="sha256:def",
            itemDigest="sha256:item",
            collectorAttemptId="attempt-001",
            collectorAttemptDigest="sha256:attempt",
            collectorToolName="azure.resourceInventory.read",
            collectorToolVersion="1.0.0",
            collectorAttemptAt=datetime.now(tz=UTC),
            collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
            sourceResponseDigest="sha256:source",
            sourceResponsePointer="/value/0",
        ),
        summary="Single point of failure remains but is accepted.",
    )
    assert finding.verdict == "acceptedResidualRisk"


def test_capability_and_scope_variants_are_valid() -> None:
    req = CapabilityRequirement(
        capabilityId="athena.contracts.policy.enabled",
        minimumVersion="1.0.0",
        requiredFor="evaluate",
    )
    assert req.minimum_version == "1.0.0"

    scope: EvidenceScope = SubscriptionScope(
        scopeType="subscription",
        tenantId="00000000-0000-0000-0000-000000000000",
        subscriptionId="00000000-0000-0000-0000-000000000000",
    )
    assert scope.scope_type == "subscription"


def test_evidence_reference_and_gap_models_validate() -> None:
    item_ref = EvidenceItemRef(
        refType="evidenceItem",
        snapshotId="snap-1",
        snapshotArtifactDigest="sha256:a",
        snapshotSemanticDigest="sha256:b",
        itemDigest="sha256:c",
        collectorAttemptId="attempt-1",
        collectorAttemptDigest="sha256:d",
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime.now(tz=UTC),
        collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
        sourceResponseDigest="sha256:e",
        sourceResponsePointer="/value/0",
    )
    assert item_ref.ref_type == "evidenceItem"

    gap_ref = EvidenceGapRef(
        refType="evidenceGap",
        snapshotId="snap-1",
        snapshotArtifactDigest="sha256:a",
        snapshotSemanticDigest="sha256:b",
        gapId="gap-1",
        gapRecordDigest="sha256:g",
        evidenceScope=SubscriptionScope(
            scopeType="subscription",
            tenantId="00000000-0000-0000-0000-000000000000",
            subscriptionId="00000000-0000-0000-0000-000000000000",
        ),
        expectedRecordType="resource",
        collectorAttemptId="attempt-2",
        collectorAttemptDigest="sha256:h",
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime.now(tz=UTC),
        collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
        gapReason="missing",
    )
    assert gap_ref.gap_reason == "missing"


def test_digest_helpers_stable_across_equal_payloads() -> None:
    payload = {"a": 1, "b": ["x", "y"]}
    digest_1 = compute_artifact_digest(payload)
    digest_2 = compute_artifact_digest({"b": ["x", "y"], "a": 1})
    assert digest_1 == digest_2
    assert compute_semantic_digest(payload) == compute_semantic_digest({"b": ["x", "y"], "a": 1})


def test_control_and_profile_settings_are_valid() -> None:
    control = Control(
        controlId="compensating-db-zone-loss",
        name="Database zone-loss compensating control",
        governanceScope=GovernanceProfileScope(
            governanceScopeType="profile",
            manifestId="wl-synthetic-clinical-platform",
            profileId="production",
        ),
        ownerRef="operations-owner",
        status="healthy",
        riskAcceptanceRef="ra-db-zone-loss-prod",
    )
    assert control.status == "healthy"
