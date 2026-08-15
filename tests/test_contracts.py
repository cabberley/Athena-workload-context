from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from athena_context import __version__
from athena_context.contracts import (
    ActivitySummaryEvidenceRecord,
    ApprovedResourceTags,
    AthenaValidationError,
    CapabilityRequirement,
    CollectorAttempt,
    CollectorIdentityEvidence,
    CompatibilityMetadata,
    ContextRef,
    Control,
    EvidenceGapRecord,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceResourceRef,
    EvidenceScope,
    EvidenceSnapshot,
    FailedResponseCollectorAttempt,
    Finding,
    GovernanceProfileScope,
    HealthEventEvidenceRecord,
    IngestionSignature,
    JwtHeader,
    MetricAggregateEvidenceRecord,
    NamePatternSelector,
    ProducerInfo,
    ProfileContinuitySettings,
    ProfileDefinition,
    ProfileSettings,
    ResourceEvidenceRecord,
    ResourceGroupScope,
    RiskAcceptance,
    RoleCardinalityBoundedRange,
    RoleCardinalityExactlyOne,
    Selector,
    ServiceHealthRegionScope,
    SnapshotCollector,
    SubscriptionScope,
    SuccessResponseCollectorAttempt,
    TimeoutNoResponseCollectorAttempt,
    TokenVerification,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    WorkloadManifest,
    WorkloadRole,
    canonicalize_json,
    compute_artifact_digest,
    compute_evidence_record_digest,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    compute_failure_envelope_digest,
    compute_response_envelope_digest,
    compute_semantic_digest,
    compute_token_verification_digest,
    compute_verified_claims_digest,
    sha256_hex,
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


def test_datetime_string_normalization_matches_datetime_object_digest() -> None:
    payload_string = {
        "attemptStartedAt": "2025-01-02T12:00:00+00:00",
        "responseReceivedAt": "2025-01-02T12:00:05Z",
    }
    payload_datetime = {
        "attemptStartedAt": datetime.fromisoformat("2025-01-02T12:00:00+00:00"),
        "responseReceivedAt": datetime.fromisoformat("2025-01-02T12:00:05Z"),
    }
    assert compute_artifact_digest(payload_string) == compute_artifact_digest(payload_datetime)


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
            snapshotId="snap-111111111111",
            snapshotArtifactDigest="sha256:" + "a" * 64,
            snapshotSemanticDigest="sha256:" + "b" * 64,
            itemDigest="sha256:" + "c" * 64,
            collectorAttemptId="attempt-111111111111",
            collectorAttemptDigest="sha256:" + "d" * 64,
            collectorToolName="azure.resourceInventory.read",
            collectorToolVersion="1.0.0",
            collectorAttemptAt=datetime.now(tz=UTC),
            collectorIdentityEvidenceRef="identity-111111111111",
            sourceResponseDigest="sha256:" + "e" * 64,
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
        snapshotId="snap-222222222222",
        snapshotArtifactDigest="sha256:" + "a" * 64,
        snapshotSemanticDigest="sha256:" + "b" * 64,
        itemDigest="sha256:" + "c" * 64,
        collectorAttemptId="attempt-111111111111",
        collectorAttemptDigest="sha256:" + "d" * 64,
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime.now(tz=UTC),
        collectorIdentityEvidenceRef="identity-111111111111",
        sourceResponseDigest="sha256:" + "e" * 64,
        sourceResponsePointer="/value/0",
    )
    assert item_ref.ref_type == "evidenceItem"

    gap_ref = EvidenceGapRef(
        refType="evidenceGap",
        snapshotId="snap-222222222222",
        snapshotArtifactDigest="sha256:" + "a" * 64,
        snapshotSemanticDigest="sha256:" + "b" * 64,
        gapId="gap-111111111111",
        gapRecordDigest="sha256:" + "c" * 64,
        evidenceScope=SubscriptionScope(
            scopeType="subscription",
            tenantId="00000000-0000-0000-0000-000000000000",
            subscriptionId="00000000-0000-0000-0000-000000000000",
        ),
        expectedRecordType="resource",
        collectorAttemptId="attempt-222222222222",
        collectorAttemptDigest="sha256:" + "d" * 64,
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime.now(tz=UTC),
        collectorIdentityEvidenceRef="identity-111111111111",
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


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _valid_response_envelope() -> dict[str, object]:
    return {
        "items": [
            {
                "recordType": "resource",
                "resourceId": (
                    "/subscriptions/11111111-1111-1111-1111-111111111111/"
                    "resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01"
                ),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {
                    "environment": "production",
                    "workloadRole": "database",
                    "application": "app-a1b2c3d4e5f6",
                    "component": "component-012345abcdef",
                    "managedBy": "terraform",
                },
                "state": "running",
            }
        ]
    }


def _build_valid_success_attempt(
    *,
    response_digest: str | None = None,
    attempt_id: str = "attempt-111111111111",
) -> SuccessResponseCollectorAttempt:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    payload = {
        "attemptType": "successResponse",
        "attemptId": attempt_id,
        "attemptStartedAt": now.isoformat(),
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req"),
        "responseDigest": response_digest
        or compute_response_envelope_digest(_valid_response_envelope()),
        "responseReceivedAt": (now + timedelta(seconds=5)).isoformat(),
        "collectorIdentityEvidenceRef": "identity-111111111111",
    }
    payload["attemptDigest"] = compute_artifact_digest(payload)
    return SuccessResponseCollectorAttempt.model_validate(
        {
            **payload,
            "attemptStartedAt": datetime.fromisoformat(payload["attemptStartedAt"]),
            "responseReceivedAt": datetime.fromisoformat(payload["responseReceivedAt"]),
        }
    )


def _build_valid_timeout_attempt() -> TimeoutNoResponseCollectorAttempt:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    payload = {
        "attemptType": "timeoutNoResponse",
        "attemptId": "attempt-222222222222",
        "attemptStartedAt": now.isoformat(),
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req-timeout"),
        "deadlineAt": (now + timedelta(seconds=30)).isoformat(),
        "timedOutAt": (now + timedelta(seconds=45)).isoformat(),
        "collectorIdentityEvidenceRef": "identity-111111111111",
    }
    payload["attemptDigest"] = compute_artifact_digest(payload)
    return TimeoutNoResponseCollectorAttempt.model_validate(
        {
            **payload,
            "attemptStartedAt": datetime.fromisoformat(payload["attemptStartedAt"]),
            "deadlineAt": datetime.fromisoformat(payload["deadlineAt"]),
            "timedOutAt": datetime.fromisoformat(payload["timedOutAt"]),
        }
    )


def _build_valid_failed_attempt(
    failure_envelope: dict[str, object],
) -> FailedResponseCollectorAttempt:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    payload = {
        "attemptType": "failedResponse",
        "attemptId": "attempt-333333333333",
        "attemptStartedAt": now,
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req-failed"),
        "failureCode": "schemaMismatch",
        "failureStatus": "invalid",
        "failureDigest": compute_failure_envelope_digest(failure_envelope),
        "responseReceivedAt": now + timedelta(seconds=5),
        "collectorIdentityEvidenceRef": "identity-111111111111",
    }
    payload["attemptDigest"] = compute_artifact_digest(payload)
    return FailedResponseCollectorAttempt.model_validate(payload)


def _refresh_snapshot_digest(payload: dict[str, object]) -> None:
    semantic_digest = compute_evidence_snapshot_semantic_digest(payload)
    compatibility = payload["compatibility"]
    assert isinstance(compatibility, dict)
    compatibility["semanticDigest"] = semantic_digest
    evidence_refs = payload["evidenceRefs"]
    assert isinstance(evidence_refs, list)
    for evidence_ref in evidence_refs:
        assert isinstance(evidence_ref, dict)
        evidence_ref["snapshotSemanticDigest"] = semantic_digest
    artifact_digest = compute_evidence_snapshot_artifact_digest(payload)
    compatibility["artifactDigest"] = artifact_digest
    for evidence_ref in evidence_refs:
        assert isinstance(evidence_ref, dict)
        evidence_ref["snapshotArtifactDigest"] = artifact_digest


def _build_valid_snapshot(
    *,
    attempt: SuccessResponseCollectorAttempt | None = None,
    identity_evidence: CollectorIdentityEvidence | None = None,
    source_response_pointer: str = "/items/0",
) -> EvidenceSnapshot:
    attempt = attempt or _build_valid_success_attempt()
    tenant_id = "11111111-1111-1111-1111-111111111111"
    scope = SubscriptionScope(
        scopeType="subscription",
        tenantId=tenant_id,
        subscriptionId=tenant_id,
    )
    collector = SnapshotCollector(
        collectorType="azureMcpHost",
        collectorIdentityEvidenceRef="identity-111111111111",
        mcpHostId="mcp-111111111111",
        tenantId=tenant_id,
        trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
        ingestionServiceId="ingestion-111111111111",
        ingestionAudience="api://athena-ingestion",
        toolAllowlistDigest=_sha256("tool-allowlist"),
    )
    record_payload = {
        "recordType": "resource",
        "resourceId": (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01"
        ),
        "resourceType": "Microsoft.Compute/virtualMachines",
        "location": "australiaeast",
        "availabilityZone": "1",
        "tags": {
            "environment": "production",
            "workloadRole": "database",
            "application": "app-a1b2c3d4e5f6",
            "component": "component-012345abcdef",
            "managedBy": "terraform",
        },
        "state": "running",
        "provenance": {
            "collectorAttemptId": attempt.attempt_id,
            "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            "toolName": attempt.tool_name,
            "toolVersion": attempt.tool_version,
            "sourceResponseDigest": attempt.response_digest,
            "sourceResponsePointer": source_response_pointer,
        },
        "collectorAttemptDigest": attempt.attempt_digest,
        "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
    }
    record_payload["itemDigest"] = compute_evidence_record_digest(record_payload)
    resource_record = ResourceEvidenceRecord.model_validate(record_payload)
    semantic_digest = _sha256("snapshot-semantic")
    snapshot_payload = {
        "snapshotId": "snap-333333333333",
        "compatibility": {
            "artifactKind": "evidenceSnapshot",
            "schemaVersion": "1.0.0",
            "semanticContractVersion": "1.0.0",
            "policyContractVersion": "1.0.0",
            "minimumReaderVersion": "1.0.0",
            "requiresCapabilities": [],
            "producedBy": {"producerId": "athena.contracts", "version": "1.0.0"},
            "extensionPolicy": "rejectUnknownDecisionFields",
            "artifactDigest": _sha256("placeholder"),
            "semanticDigest": semantic_digest,
        },
        "authorizedScopes": [scope.model_dump(mode="json", by_alias=True)],
        "collectedAt": datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
        "expiresAt": datetime(2025, 1, 2, 13, 0, tzinfo=UTC),
        "collector": collector.model_dump(mode="json", by_alias=True),
        "collectorAttempts": [attempt.model_dump(mode="python", by_alias=True)],
        "evidenceRecords": [resource_record.model_dump(mode="json", by_alias=True)],
        "identityEvidence": (
            [identity_evidence.model_dump(mode="python", by_alias=True)]
            if identity_evidence is not None
            else []
        ),
        "evidenceRefs": [
            {
                "refType": "evidenceItem",
                "snapshotId": "snap-333333333333",
                "snapshotArtifactDigest": _sha256("placeholder"),
                "snapshotSemanticDigest": semantic_digest,
                "itemDigest": resource_record.item_digest,
                "collectorAttemptId": attempt.attempt_id,
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorToolName": attempt.tool_name,
                "collectorToolVersion": attempt.tool_version,
                "collectorAttemptAt": attempt.response_received_at,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                "sourceResponseDigest": attempt.response_digest,
                "sourceResponsePointer": source_response_pointer,
            }
        ],
    }
    _refresh_snapshot_digest(snapshot_payload)
    return EvidenceSnapshot.model_validate(snapshot_payload)


def _build_valid_gap_snapshot(
    *,
    attempt: CollectorAttempt,
    identity_evidence: CollectorIdentityEvidence | None = None,
    failure_payload_digest: str | None = None,
    failure_payload_pointer: str | None = None,
) -> EvidenceSnapshot:
    tenant_id = "11111111-1111-1111-1111-111111111111"
    scope = SubscriptionScope(
        scopeType="subscription",
        tenantId=tenant_id,
        subscriptionId=tenant_id,
    )
    collector = SnapshotCollector(
        collectorType="azureMcpHost",
        collectorIdentityEvidenceRef="identity-111111111111",
        mcpHostId="mcp-111111111111",
        tenantId=tenant_id,
        trustAnchorRef=(
            "https://contoso.vault.azure.net/keys/athena-key/"
            "0123456789abcdef0123456789abcdef"
        ),
        ingestionServiceId="ingestion-111111111111",
        ingestionAudience="api://athena-ingestion",
        toolAllowlistDigest=_sha256("tool-allowlist"),
    )
    if attempt.attempt_type in {"successResponse", "failedResponse"}:
        observed_at = attempt.response_received_at
    elif attempt.attempt_type == "timeoutNoResponse":
        observed_at = attempt.timed_out_at
    else:
        observed_at = attempt.observed_at
    gap_payload: dict[str, object] = {
        "recordType": "evidenceGap",
        "gapId": "gap-222222222222",
        "evidenceScope": scope.model_dump(mode="json", by_alias=True),
        "gapReason": "malformed" if attempt.attempt_type == "successResponse" else "missing",
        "expectedRecordType": "resource",
        "collectorAttemptId": attempt.attempt_id,
        "collectorAttemptDigest": attempt.attempt_digest,
        "observedAt": observed_at,
        "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
    }
    if failure_payload_digest is not None:
        gap_payload["failurePayloadDigest"] = failure_payload_digest
        gap_payload["failurePayloadPointer"] = failure_payload_pointer
    gap_payload["itemDigest"] = compute_evidence_record_digest(gap_payload)
    gap = EvidenceGapRecord.model_validate(gap_payload)
    semantic_digest = _sha256("snapshot-gap-semantic")
    snapshot_payload: dict[str, object] = {
        "snapshotId": "snap-444444444444",
        "compatibility": {
            "artifactKind": "evidenceSnapshot",
            "schemaVersion": "1.0.0",
            "semanticContractVersion": "1.0.0",
            "policyContractVersion": "1.0.0",
            "minimumReaderVersion": "1.0.0",
            "requiresCapabilities": [],
            "producedBy": {"producerId": "athena.contracts", "version": "1.0.0"},
            "extensionPolicy": "rejectUnknownDecisionFields",
            "artifactDigest": _sha256("placeholder"),
            "semanticDigest": semantic_digest,
        },
        "authorizedScopes": [scope.model_dump(mode="json", by_alias=True)],
        "collectedAt": datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
        "expiresAt": datetime(2025, 1, 2, 13, 0, tzinfo=UTC),
        "collector": collector.model_dump(mode="json", by_alias=True),
        "collectorAttempts": [attempt.model_dump(mode="python", by_alias=True)],
        "evidenceRecords": [gap.model_dump(mode="python", by_alias=True)],
        "evidenceRefs": [
            {
                "refType": "evidenceGap",
                "snapshotId": "snap-444444444444",
                "snapshotArtifactDigest": _sha256("placeholder"),
                "snapshotSemanticDigest": semantic_digest,
                "gapId": gap.gap_id,
                "gapRecordDigest": gap.item_digest,
                "evidenceScope": scope.model_dump(mode="json", by_alias=True),
                "expectedRecordType": gap.expected_record_type,
                "collectorAttemptId": attempt.attempt_id,
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorToolName": attempt.tool_name,
                "collectorToolVersion": attempt.tool_version,
                "collectorAttemptAt": observed_at,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                "gapReason": gap.gap_reason,
                "failurePayloadDigest": failure_payload_digest,
                "failurePayloadPointer": failure_payload_pointer,
            }
        ],
        "identityEvidence": (
            [identity_evidence.model_dump(mode="python", by_alias=True)]
            if identity_evidence is not None
            else []
        ),
    }
    _refresh_snapshot_digest(snapshot_payload)
    return EvidenceSnapshot.model_validate(snapshot_payload)


def test_identity_evidence_rejects_raw_bearer_token_and_customer_proprietary_fields() -> None:
    valid_header = JwtHeader(alg="RS256", kid="abc12345", typ="JWT")
    assert valid_header.alg == "RS256"

    with pytest.raises(ValidationError):
        JwtHeader.model_validate(
            {
                "alg": "RS256",
                "kid": "abc12345",
                "typ": "JWT",
                "rawBearerToken": "Bearer deadbeef",
            }
        )

    with pytest.raises(ValidationError):
        TokenVerification.model_validate(
            {
                "status": "valid",
                "verifiedAt": datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
                "keyId": "abc12345",
                "tokenVerificationDigest": _sha256("token-verify"),
                "customerProprietary": {"apiToken": "secret"},
            }
        )

    with pytest.raises(ValidationError):
        CollectorIdentityEvidence.model_validate(
            {
                **{
                    "identityEvidenceId": "identity-222222222222",
                    "identityEvidenceType": "entraJwtTokenEvidence",
                    "tokenHash": _sha256("token-1"),
                    "jwtHeader": {"alg": "RS256", "kid": "abc12345", "typ": "JWT"},
                    "trustAnchorRef": "https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
                    "verifiedClaims": {
                        "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                        "audience": "api://athena-ingestion",
                        "tenantId": "11111111-1111-1111-1111-111111111111",
                        "managedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
                        "managedIdentityClientId": "33333333-3333-3333-3333-333333333333",
                        "subject": "22222222-2222-2222-2222-222222222222",
                        "jti": "jti-123",
                        "issuedAt": "2025-01-02T11:00:00+00:00",
                        "expiresAt": "2025-01-02T13:00:00+00:00",
                    },
                    "tokenVerification": {
                        "status": "valid",
                        "verifiedAt": "2025-01-02T12:00:00+00:00",
                        "keyId": "abc12345",
                        "tokenVerificationDigest": _sha256("token-verify"),
                    },
                    "ingestionDerivation": {
                        "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
                        "derivationPreimageVersion": "1.0.0",
                        "schemaVersion": "1.0.0",
                        "semanticContractVersion": "1.0.0",
                        "policyContractVersion": "1.0.0",
                        "identityEvidenceId": "identity-222222222222",
                        "tokenHash": _sha256("token-1"),
                        "tokenVerificationStatus": "valid",
                        "tokenVerificationDigest": _sha256("token-verify"),
                        "mcpHostId": "mcp-111111111111",
                        "mcpHostTenantId": "11111111-1111-1111-1111-111111111111",
                        "mcpHostManagedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
                        "mcpHostManagedIdentityClientId": "33333333-3333-3333-3333-333333333333",
                        "ingestionServiceId": "ingestion-111111111111",
                        "ingestionAudience": "api://athena-ingestion",
                        "toolAllowlistDigest": _sha256("tool-allowlist"),
                        "derivedCollectorIdentityRef": "identity-111111111111",
                        "attemptBinding": {
                            "attemptId": "attempt-111111111111",
                            "attemptType": "successResponse",
                            "attemptDigest": _sha256("attempt"),
                            "toolName": "azure.resourceInventory.read",
                            "toolVersion": "1.0.0",
                            "requestDigest": _sha256("req"),
                            "responseDigest": _sha256("resp"),
                            "attemptStartedAt": "2025-01-02T11:00:00+00:00",
                            "responseReceivedAt": "2025-01-02T11:00:05+00:00",
                        },
                        "derivedAt": "2025-01-02T12:00:00+00:00",
                        "derivationDigest": _sha256("derivation"),
                    },
                    "ingestionSignature": {
                        "signatureAlgorithm": "RS256",
                        "keyVaultKeyId": "https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
                        "keyVersion": "0123456789abcdef0123456789abcdef",
                        "signedPreimageDigest": _sha256("derivation"),
                        "signature": "AQID",
                        "signedAt": "2025-01-02T12:00:00+00:00",
                        "trustAnchorRef": "https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
                        "keyStatusAtSigning": "active",
                        "signatureVerification": {
                            "status": "valid",
                            "verifiedAt": "2025-01-02T12:00:01+00:00",
                            "keyVersion": "0123456789abcdef0123456789abcdef",
                        },
                    },
                    "identityEvidenceDigest": _sha256("evidence"),
                    "rawBearerToken": "Bearer anu",
                },
            }
        )


def test_attempt_digest_and_mismatched_attempts_are_rejected() -> None:
    attempt = _build_valid_success_attempt()
    with pytest.raises(ValidationError):
        SuccessResponseCollectorAttempt.model_validate(
            {
                **attempt.model_dump(mode="json", by_alias=True),
                "attemptDigest": _sha256("fabricated"),
            }
        )

    payload = attempt.model_dump(mode="json", by_alias=True)
    payload["attemptId"] = "attempt-999999999999"
    with pytest.raises(ValidationError):
        SuccessResponseCollectorAttempt.model_validate(payload)


def test_snapshot_rejects_invalid_scope_and_expiry_order() -> None:
    with pytest.raises(ValidationError):
        SubscriptionScope(
            scopeType="subscription",
            tenantId="not-a-guid",
            subscriptionId="11111111-1111-1111-1111-111111111111",
        )

    snapshot = _build_valid_snapshot().model_dump(mode="json", by_alias=True)
    snapshot["expiresAt"] = "2025-01-02T11:59:59+00:00"
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(snapshot)


def test_snapshot_rejects_concrete_record_on_timeout_and_replay() -> None:
    snapshot = _build_valid_snapshot()
    timeout = _build_valid_timeout_attempt()
    record_payload = snapshot.evidence_records[0].model_dump(mode="json", by_alias=True)
    record_payload["collectorAttemptDigest"] = timeout.attempt_digest
    record_payload["collectorAttemptId"] = timeout.attempt_id
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(
            {
                **snapshot.model_dump(mode="json", by_alias=True),
                "collectorAttempts": [timeout.model_dump(mode="json", by_alias=True)],
                "evidenceRecords": [record_payload],
            }
        )

    payload = snapshot.model_dump(mode="json", by_alias=True)
    payload["evidenceRefs"] = [payload["evidenceRefs"][0], payload["evidenceRefs"][0]]
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_ingestion_signature_rejects_fabricated_or_none_algorithm() -> None:
    with pytest.raises(ValidationError):
        IngestionSignature(
            signatureAlgorithm="none",
            keyVaultKeyId="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
            keyName="athena-key",
            keyVersion="0123456789abcdef0123456789abcdef",
            signedPreimageDigest=_sha256("payload"),
            signature="alg:none",
            signedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
            trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
        )

    with pytest.raises(ValidationError):
        IngestionSignature(
            signatureAlgorithm="RS256",
            keyVaultKeyId="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
            keyName="athena-key",
            keyVersion="0123456789abcdef0123456789abcdef",
            signedPreimageDigest=_sha256("payload"),
            signature="",
            signedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
            trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
        )

    with pytest.raises(ValidationError):
        IngestionSignature(
            signatureAlgorithm="RS256",
            keyVaultKeyId="https://contoso.vault.azure.net\\keys\\athena-key\\0123456789abcdef0123456789abcdef",
            keyName="athena-key",
            keyVersion="0123456789abcdef0123456789abcdef",
            signedPreimageDigest=_sha256("payload"),
            signature="AQID",
            signedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
            trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
        )


def _build_valid_identity_evidence(
    *,
    private_key: rsa.RSAPrivateKey,
    tenant_id: str = "11111111-1111-1111-1111-111111111111",
    trust_anchor: str = "https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
    response_digest: str | None = None,
    attempt_id: str = "attempt-444444444444",
    collector_attempt: CollectorAttempt | None = None,
    binding_overrides: dict[str, object] | None = None,
    claims_audience: str = "api://athena-ingestion",
    ingestion_audience: str = "api://athena-ingestion",
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    verified_at: datetime | None = None,
    derived_at_override: datetime | None = None,
) -> CollectorIdentityEvidence:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    issued_at = issued_at or now - timedelta(minutes=5)
    not_before = not_before or issued_at
    expires_at = expires_at or now + timedelta(minutes=30)
    verified_at = verified_at or now
    signing_anchor = _trusted_key_anchor(
        private_key.public_key(),
        key_vault_key_id=trust_anchor,
    )
    token_hash = _sha256("token-1")
    verified_claims_payload = {
        "issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "audience": claims_audience,
        "tenantId": tenant_id,
        "managedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
        "managedIdentityClientId": "33333333-3333-3333-3333-333333333333",
        "subject": "22222222-2222-2222-2222-222222222222",
        "jti": "jti-123",
        "issuedAt": issued_at,
        "notBefore": not_before,
        "expiresAt": expires_at,
    }
    verified_claims_digest = compute_verified_claims_digest(verified_claims_payload)
    token_verification_payload = {
        "status": "valid",
        "verifiedAt": verified_at,
        "keyId": "abc12345",
        "verifiedClaims": verified_claims_payload,
        "verifiedClaimsDigest": verified_claims_digest,
    }
    token_verification_digest = compute_token_verification_digest(
        token_verification_payload
    )
    if collector_attempt is None:
        attempt = {
            "attemptType": "successResponse",
            "attemptId": attempt_id,
            "attemptStartedAt": now,
            "toolName": "azure.resourceInventory.read",
            "toolVersion": "1.0.0",
            "requestDigest": _sha256("req-identity"),
            "responseDigest": response_digest or _sha256("resp-identity"),
            "responseReceivedAt": now + timedelta(seconds=5),
            "collectorIdentityEvidenceRef": "identity-111111111111",
        }
        attempt["attemptDigest"] = compute_artifact_digest(attempt)
    else:
        attempt = collector_attempt.model_dump(mode="python", by_alias=True)
    attempt_type = attempt["attemptType"]
    if attempt_type in {"successResponse", "failedResponse"}:
        attempt_observed_at = attempt["responseReceivedAt"]
    elif attempt_type == "timeoutNoResponse":
        attempt_observed_at = attempt["timedOutAt"]
    else:
        attempt_observed_at = attempt["observedAt"]
    assert isinstance(attempt_observed_at, datetime)
    derived_at = derived_at_override or attempt_observed_at
    signed_at = derived_at + timedelta(seconds=1)
    binding_fields = {
        "attemptId",
        "attemptType",
        "attemptDigest",
        "toolName",
        "toolVersion",
        "requestDigest",
        "responseDigest",
        "failureDigest",
        "attemptStartedAt",
        "responseReceivedAt",
        "deadlineAt",
        "timedOutAt",
        "observedAt",
    }
    attempt_binding_payload = {
        key: value for key, value in attempt.items() if key in binding_fields
    }
    attempt_binding_payload.update(binding_overrides or {})
    derivation_payload = {
        "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
        "derivationPreimageVersion": "1.0.0",
        "schemaVersion": "1.0.0",
        "semanticContractVersion": "1.0.0",
        "policyContractVersion": "1.0.0",
        "identityEvidenceId": "identity-111111111111",
        "tokenHash": token_hash,
        "tokenVerificationStatus": "valid",
        "tokenVerificationDigest": token_verification_digest,
        "verifiedClaimsDigest": verified_claims_digest,
        "mcpHostId": "mcp-111111111111",
        "mcpHostTenantId": tenant_id,
        "mcpHostManagedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
        "mcpHostManagedIdentityClientId": "33333333-3333-3333-3333-333333333333",
        "ingestionServiceId": "ingestion-111111111111",
        "ingestionAudience": ingestion_audience,
        "toolAllowlistDigest": _sha256("tool-allowlist"),
        "derivedCollectorIdentityRef": "identity-111111111111",
        "attemptBinding": attempt_binding_payload,
        "derivedAt": derived_at,
    }
    derivation_payload["derivationDigest"] = compute_artifact_digest(derivation_payload)
    derivation_preimage = {
        key: value
        for key, value in derivation_payload.items()
        if key != "derivationDigest"
    }
    signature_preimage = {
        "signaturePreimageType": "athena.trustedIngestionSignature",
        "signaturePreimageVersion": "1.0.0",
        "signatureAlgorithm": "RS256",
        "keyVaultKeyId": trust_anchor,
        "keyName": signing_anchor.key_name,
        "keyVersion": signing_anchor.key_version,
        "signedAt": signed_at,
        "trustAnchorRef": trust_anchor,
        "derivation": derivation_preimage,
    }
    signed_preimage_digest = compute_artifact_digest(signature_preimage)
    canonical_preimage = canonicalize_json(signature_preimage)
    signature = base64.b64encode(
        private_key.sign(
            canonical_preimage.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    identity_payload = {
        "identityEvidenceId": "identity-111111111111",
        "identityEvidenceType": "entraJwtTokenEvidence",
        "tokenHash": token_hash,
        "jwtHeader": {"alg": "RS256", "kid": "abc12345", "typ": "JWT"},
        "trustAnchorRef": trust_anchor,
        "verifiedClaims": verified_claims_payload,
        "tokenVerification": {
            **token_verification_payload,
            "tokenVerificationDigest": token_verification_digest,
        },
        "ingestionDerivation": {
            **derivation_payload,
            "attemptBinding": attempt_binding_payload,
            "derivedAt": derived_at,
        },
        "ingestionSignature": {
            "signatureAlgorithm": "RS256",
            "keyVaultKeyId": trust_anchor,
            "keyName": signing_anchor.key_name,
            "keyVersion": signing_anchor.key_version,
            "signedPreimageDigest": signed_preimage_digest,
            "signature": signature,
            "signedAt": signed_at,
            "trustAnchorRef": trust_anchor,
        },
    }
    identity_payload["identityEvidenceDigest"] = compute_artifact_digest(
        {
            key: value
            for key, value in identity_payload.items()
            if key != "identityEvidenceDigest"
        }
    )
    return CollectorIdentityEvidence.model_validate(identity_payload)


def _trusted_key_resolver(
    public_key: object,
    *,
    key_vault_key_id: str = (
        "https://contoso.vault.azure.net/keys/athena-key/"
        "0123456789abcdef0123456789abcdef"
    ),
    enabled: bool = True,
    activated_at: datetime = datetime(2025, 1, 1, tzinfo=UTC),
    retired_at: datetime | None = None,
    expires_at: datetime | None = datetime(2025, 2, 1, tzinfo=UTC),
) -> Callable[[TrustedKeyAnchor], TrustedKeyRecord | None]:
    anchor = _trusted_key_anchor(public_key, key_vault_key_id=key_vault_key_id)
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=enabled,
        activated_at=activated_at,
        retired_at=retired_at,
        expires_at=expires_at,
    )

    def resolve(lookup: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return record if lookup == anchor else None

    return resolve


def _trusted_key_anchor(
    public_key: object,
    *,
    key_vault_key_id: str = (
        "https://contoso.vault.azure.net/keys/athena-key/"
        "0123456789abcdef0123456789abcdef"
    ),
) -> TrustedKeyAnchor:
    assert hasattr(public_key, "public_bytes")
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustedKeyAnchor.from_key_vault_key_id(
        key_vault_key_id,
        public_key_fingerprint=sha256_hex(encoded),
    )


def test_key_vault_signature_verifies_and_rejects_forgery() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    evidence = _build_valid_identity_evidence(private_key=private_key)
    assert evidence.verify_signature(
        key_resolver=_trusted_key_resolver(public_key),
        trusted_key_anchor=_trusted_key_anchor(public_key),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )

    forged = evidence.model_copy(
        deep=True,
        update={
            "ingestion_signature": evidence.ingestion_signature.model_copy(
                update={
                    "signature": base64.b64encode(
                        private_key.sign(
                            b"forged-preimage",
                            padding.PKCS1v15(),
                            hashes.SHA256(),
                        )
                    ).decode("ascii")
                }
            )
        },
    )
    assert not forged.verify_signature(
        key_resolver=_trusted_key_resolver(public_key),
        trusted_key_anchor=_trusted_key_anchor(public_key),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert not evidence.verify_signature(
        key_resolver=_trusted_key_resolver(other_key.public_key()),
        trusted_key_anchor=_trusted_key_anchor(other_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )
    assert not evidence.verify_signature(
        key_resolver=_trusted_key_resolver(
            public_key,
            key_vault_key_id=(
                "https://different.vault.azure.net/keys/athena-key/"
                "0123456789abcdef0123456789abcdef"
            ),
        ),
        trusted_key_anchor=_trusted_key_anchor(
            public_key,
            key_vault_key_id=(
                "https://different.vault.azure.net/keys/athena-key/"
                "0123456789abcdef0123456789abcdef"
            ),
        ),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )


def test_service_health_region_scope_rejects_wildcards_and_invalid_cloud() -> None:
    with pytest.raises(ValidationError):
        ServiceHealthRegionScope(
            scopeType="serviceHealthRegion",
            cloud="azureCloud",
            region="eastus*",
        )
    with pytest.raises(ValidationError):
        ServiceHealthRegionScope(
            scopeType="serviceHealthRegion",
            cloud="azureCloud",
            region="*",
        )
    with pytest.raises(ValidationError):
        ServiceHealthRegionScope(
            scopeType="serviceHealthRegion",
            cloud="notAzure",
            region="australiaeast",
        )


def test_snapshot_evaluation_rejects_expired_and_out_of_window_values() -> None:
    snapshot = _build_valid_snapshot()
    with pytest.raises(AthenaValidationError):
        snapshot.validate_for_evaluation(as_of=datetime(2026, 8, 15, tzinfo=UTC))

    stale = _build_valid_snapshot()
    with pytest.raises(AthenaValidationError):
        stale.validate_for_evaluation(as_of=datetime(2025, 1, 1, tzinfo=UTC))


def test_snapshot_rejects_cross_snapshot_and_missing_refs() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="json", by_alias=True)
    payload["evidenceRefs"][0]["snapshotId"] = "snap-999999999999"
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)

    payload = snapshot.model_dump(mode="json", by_alias=True)
    payload["evidenceRefs"][0]["itemDigest"] = _sha256("totally-fabricated")
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_record_gap_and_snapshot_digests_reject_mutation() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="python", by_alias=True)
    record = payload["evidenceRecords"][0]
    record["state"] = "deallocated"
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)

    payload = snapshot.model_dump(mode="python", by_alias=True)
    record = payload["evidenceRecords"][0]
    record["state"] = "deallocated"
    record["itemDigest"] = compute_evidence_record_digest(record)
    payload["evidenceRefs"][0]["itemDigest"] = record["itemDigest"]
    with pytest.raises(ValidationError, match="artifactDigest"):
        EvidenceSnapshot.model_validate(payload)

    timeout_gap = _build_valid_gap_snapshot(attempt=_build_valid_timeout_attempt())
    payload = timeout_gap.model_dump(mode="python", by_alias=True)
    payload["evidenceRecords"][0]["gapReason"] = "collectorUnavailable"
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_envelope_resolver_rejects_nonexistent_pointer_and_covers_failure() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    response_envelope = _valid_response_envelope()
    response_digest = compute_response_envelope_digest(response_envelope)
    success_attempt = _build_valid_success_attempt(
        response_digest=response_digest,
        attempt_id="attempt-555555555555",
    )
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=success_attempt,
    )
    valid_snapshot = _build_valid_snapshot(
        attempt=success_attempt,
        identity_evidence=identity,
    )
    resolver_calls: list[tuple[str, str, str]] = []

    def response_resolver(attempt_id: str, kind: str, digest: str) -> object:
        resolver_calls.append((attempt_id, kind, digest))
        return response_envelope

    assert (
        valid_snapshot.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=response_resolver,
        )
        is valid_snapshot
    )
    assert resolver_calls == [(success_attempt.attempt_id, "response", response_digest)]

    nonexistent = _build_valid_snapshot(
        attempt=success_attempt,
        identity_evidence=identity,
        source_response_pointer="/items/1",
    )
    with pytest.raises(AthenaValidationError, match="does not resolve"):
        nonexistent.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=response_resolver,
        )

    failure_envelope: dict[str, object] = {"error": {"code": "SchemaMismatch"}}
    failed_attempt = _build_valid_failed_attempt(failure_envelope)
    failed_identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=failed_attempt,
    )
    failed_snapshot = _build_valid_gap_snapshot(
        attempt=failed_attempt,
        identity_evidence=failed_identity,
        failure_payload_digest=failed_attempt.failure_digest,
        failure_payload_pointer="/error/code",
    )

    def failure_resolver(attempt_id: str, kind: str, digest: str) -> object:
        assert (attempt_id, kind, digest) == (
            failed_attempt.attempt_id,
            "failure",
            failed_attempt.failure_digest,
        )
        return failure_envelope

    assert (
        failed_snapshot.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=failure_resolver,
        )
        is failed_snapshot
    )


def test_gap_ref_exact_equality_and_timeout_payload_prohibition() -> None:
    failure_envelope: dict[str, object] = {"error": {"code": "SchemaMismatch"}}
    failed_attempt = _build_valid_failed_attempt(failure_envelope)
    failed_snapshot = _build_valid_gap_snapshot(
        attempt=failed_attempt,
        failure_payload_digest=failed_attempt.failure_digest,
        failure_payload_pointer="/error/code",
    )
    payload = failed_snapshot.model_dump(mode="python", by_alias=True)
    payload["evidenceRefs"][0]["collectorIdentityEvidenceRef"] = "identity-999999999999"
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="collectorIdentityEvidenceRef"):
        EvidenceSnapshot.model_validate(payload)

    payload = failed_snapshot.model_dump(mode="python", by_alias=True)
    payload["evidenceRefs"][0]["failurePayloadPointer"] = "/error"
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="failure payload fields"):
        EvidenceSnapshot.model_validate(payload)

    timeout_snapshot = _build_valid_gap_snapshot(attempt=_build_valid_timeout_attempt())
    payload = timeout_snapshot.model_dump(mode="python", by_alias=True)
    fabricated_digest = _sha256("fabricated-timeout-payload")
    record = payload["evidenceRecords"][0]
    record["failurePayloadDigest"] = fabricated_digest
    record["failurePayloadPointer"] = "/error"
    record["itemDigest"] = compute_evidence_record_digest(record)
    ref = payload["evidenceRefs"][0]
    ref["gapRecordDigest"] = record["itemDigest"]
    ref["failurePayloadDigest"] = fabricated_digest
    ref["failurePayloadPointer"] = "/error"
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="must not fabricate"):
        EvidenceSnapshot.model_validate(payload)


def test_rfc6901_invalid_escape_remains_rejected() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.evidence_refs[0].model_dump(mode="python", by_alias=True)
    payload["sourceResponsePointer"] = "/properties/~2invalid"
    with pytest.raises(ValidationError, match="pattern"):
        EvidenceItemRef.model_validate(payload)


def test_resource_scope_rejects_subscription_and_component_prefix_confusion() -> None:
    snapshot = _build_valid_snapshot()
    other_subscription = "22222222-2222-2222-2222-222222222222"
    payload = snapshot.model_dump(mode="python", by_alias=True)
    record = payload["evidenceRecords"][0]
    record["resourceId"] = (
        f"/subscriptions/{other_subscription}/resourceGroups/rg-prod/"
        "providers/Microsoft.Compute/virtualMachines/vm-01"
    )
    record["itemDigest"] = compute_evidence_record_digest(record)
    payload["evidenceRefs"][0]["itemDigest"] = record["itemDigest"]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="outside the snapshot authorized scopes"):
        EvidenceSnapshot.model_validate(payload)

    payload = snapshot.model_dump(mode="python", by_alias=True)
    record = payload["evidenceRecords"][0]
    record["resourceId"] = (
        "/subscriptions/11111111-1111-1111-1111-111111111111evil/"
        "resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01"
    )
    record["itemDigest"] = compute_evidence_record_digest(record)
    payload["evidenceRefs"][0]["itemDigest"] = record["itemDigest"]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="pattern"):
        EvidenceSnapshot.model_validate(payload)

    payload = snapshot.model_dump(mode="python", by_alias=True)
    payload["authorizedScopes"] = [
        ResourceGroupScope(
            scopeType="resourceGroup",
            tenantId="11111111-1111-1111-1111-111111111111",
            subscriptionId="11111111-1111-1111-1111-111111111111",
            resourceGroupName="rg-prod",
        ).model_dump(mode="python", by_alias=True)
    ]
    record = payload["evidenceRecords"][0]
    record["resourceId"] = record["resourceId"].replace(
        "/resourceGroups/rg-prod/", "/resourceGroups/rg-prod-evil/"
    )
    record["itemDigest"] = compute_evidence_record_digest(record)
    payload["evidenceRefs"][0]["itemDigest"] = record["itemDigest"]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="outside the snapshot authorized scopes"):
        EvidenceSnapshot.model_validate(payload)


def test_attempt_and_record_chronology_rejects_reverse_time() -> None:
    success = _build_valid_success_attempt()
    payload = success.model_dump(mode="python", by_alias=True)
    payload["responseReceivedAt"] = success.attempt_started_at - timedelta(seconds=1)
    payload.pop("attemptDigest")
    payload["attemptDigest"] = compute_artifact_digest(payload)
    with pytest.raises(ValidationError, match="must not precede"):
        SuccessResponseCollectorAttempt.model_validate(payload)

    failure_envelope: dict[str, object] = {"error": {"code": "SchemaMismatch"}}
    failed = _build_valid_failed_attempt(failure_envelope)
    payload = failed.model_dump(mode="python", by_alias=True)
    payload["responseReceivedAt"] = failed.attempt_started_at - timedelta(seconds=1)
    payload.pop("attemptDigest")
    payload["attemptDigest"] = compute_artifact_digest(payload)
    with pytest.raises(ValidationError, match="must not precede"):
        FailedResponseCollectorAttempt.model_validate(payload)

    timeout = _build_valid_timeout_attempt()
    payload = timeout.model_dump(mode="python", by_alias=True)
    payload["deadlineAt"] = timeout.attempt_started_at - timedelta(seconds=1)
    payload.pop("attemptDigest")
    payload["attemptDigest"] = compute_artifact_digest(payload)
    with pytest.raises(ValidationError, match="deadlineAt"):
        TimeoutNoResponseCollectorAttempt.model_validate(payload)

    provenance = {
        "collectorAttemptId": success.attempt_id,
        "collectorIdentityEvidenceRef": success.collector_identity_evidence_ref,
        "toolName": success.tool_name,
        "toolVersion": success.tool_version,
        "sourceResponseDigest": success.response_digest,
        "sourceResponsePointer": "/items/0",
    }
    base = {
        "collectorAttemptDigest": success.attempt_digest,
        "collectorIdentityEvidenceRef": success.collector_identity_evidence_ref,
        "provenance": provenance,
    }
    metric_payload = {
        **base,
        "recordType": "metricAggregate",
        "resourceId": (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01"
        ),
        "metricName": "percentageCpu",
        "aggregation": "average",
        "windowStart": datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
        "windowEnd": datetime(2025, 1, 2, 12, 4, tzinfo=UTC),
        "value": 1.0,
        "unit": "percent",
    }
    metric_payload["itemDigest"] = compute_evidence_record_digest(metric_payload)
    with pytest.raises(ValidationError, match="windowStart"):
        MetricAggregateEvidenceRecord.model_validate(metric_payload)

    health_payload = {
        **base,
        "recordType": "healthEvent",
        "evidenceScope": {
            "scopeType": "subscription",
            "tenantId": "11111111-1111-1111-1111-111111111111",
            "subscriptionId": "11111111-1111-1111-1111-111111111111",
        },
        "healthKind": "resourceHealth",
        "status": "available",
        "startedAt": datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
        "endedAt": datetime(2025, 1, 2, 12, 4, tzinfo=UTC),
        "summaryCode": "configurationIssue",
    }
    health_payload["itemDigest"] = compute_evidence_record_digest(health_payload)
    with pytest.raises(ValidationError, match="startedAt"):
        HealthEventEvidenceRecord.model_validate(health_payload)

    activity_payload = {
        **base,
        "recordType": "activitySummary",
        "evidenceScope": health_payload["evidenceScope"],
        "operationName": "resourceWrite",
        "status": "succeeded",
        "count": 1,
        "windowStart": datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
        "windowEnd": datetime(2025, 1, 2, 12, 4, tzinfo=UTC),
    }
    activity_payload["itemDigest"] = compute_evidence_record_digest(activity_payload)
    with pytest.raises(ValidationError, match="windowStart"):
        ActivitySummaryEvidenceRecord.model_validate(activity_payload)


def test_exact_signed_attempt_binding_and_utc_timestamps_are_required() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attempt = _build_valid_success_attempt()
    evidence = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
        binding_overrides={
            "attemptStartedAt": attempt.attempt_started_at + timedelta(seconds=1)
        },
    )
    assert not evidence.verify_signature(
        key_resolver=_trusted_key_resolver(private_key.public_key()),
        trusted_key_anchor=_trusted_key_anchor(private_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
        attempt=attempt,
    )

    naive_attempt = attempt.model_dump(mode="python", by_alias=True)
    naive_attempt["attemptStartedAt"] = attempt.attempt_started_at.replace(tzinfo=None)
    naive_attempt["responseReceivedAt"] = attempt.response_received_at.replace(tzinfo=None)
    naive_attempt.pop("attemptDigest")
    naive_attempt["attemptDigest"] = compute_artifact_digest(naive_attempt)
    with pytest.raises(ValidationError, match="timezone-aware"):
        SuccessResponseCollectorAttempt.model_validate(naive_attempt)


def test_resource_id_scope_requires_tenant_bound_parent() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="python", by_alias=True)
    resource_id = payload["evidenceRecords"][0]["resourceId"]
    payload["authorizedScopes"] = [
        {"scopeType": "resourceId", "resourceId": resource_id}
    ]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="tenant-bound parent"):
        EvidenceSnapshot.model_validate(payload)


def test_gap_expected_type_excludes_evidence_gap() -> None:
    snapshot = _build_valid_gap_snapshot(attempt=_build_valid_timeout_attempt())
    payload = snapshot.model_dump(mode="python", by_alias=True)
    payload["evidenceRecords"][0]["expectedRecordType"] = "evidenceGap"
    payload["evidenceRefs"][0]["expectedRecordType"] = "evidenceGap"
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_rfc6901_empty_string_resolves_envelope_root() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    response_envelope = _valid_response_envelope()["items"][0]
    assert isinstance(response_envelope, dict)
    response_digest = compute_response_envelope_digest(response_envelope)
    attempt = _build_valid_success_attempt(response_digest=response_digest)
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
    )
    snapshot = _build_valid_snapshot(
        attempt=attempt,
        identity_evidence=identity,
        source_response_pointer="",
    )
    assert (
        snapshot.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=lambda attempt_id, kind, digest: response_envelope,
        )
        is snapshot
    )


def test_resolved_source_rejects_recomputed_local_mutation() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    response_envelope = _valid_response_envelope()
    response_digest = compute_response_envelope_digest(response_envelope)
    attempt = _build_valid_success_attempt(response_digest=response_digest)
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
    )
    snapshot = _build_valid_snapshot(attempt=attempt, identity_evidence=identity)
    payload = snapshot.model_dump(mode="python", by_alias=True)
    record = payload["evidenceRecords"][0]
    record["state"] = "deallocated"
    record["itemDigest"] = compute_evidence_record_digest(record)
    payload["evidenceRefs"][0]["itemDigest"] = record["itemDigest"]
    _refresh_snapshot_digest(payload)
    mutated = EvidenceSnapshot.model_validate(payload)
    with pytest.raises(AthenaValidationError, match="does not match"):
        mutated.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=lambda attempt_id, kind, digest: response_envelope,
        )


def test_envelope_digest_preserves_explicit_nulls() -> None:
    assert compute_failure_envelope_digest({}) != compute_failure_envelope_digest(
        {"error": None}
    )
    assert compute_response_envelope_digest({}) != compute_response_envelope_digest(
        {"value": None}
    )


def test_gap_rejects_fabricated_attempt_digest_even_when_rehashed() -> None:
    snapshot = _build_valid_gap_snapshot(attempt=_build_valid_timeout_attempt())
    payload = snapshot.model_dump(mode="python", by_alias=True)
    fabricated_digest = _sha256("fabricated-attempt")
    record = payload["evidenceRecords"][0]
    record["collectorAttemptDigest"] = fabricated_digest
    record["itemDigest"] = compute_evidence_record_digest(record)
    ref = payload["evidenceRefs"][0]
    ref["collectorAttemptDigest"] = fabricated_digest
    ref["gapRecordDigest"] = record["itemDigest"]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="unknown collector attempt"):
        EvidenceSnapshot.model_validate(payload)


def test_snapshot_semantic_digest_is_recomputed() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="python", by_alias=True)
    fabricated = _sha256("fabricated-semantic")
    payload["compatibility"]["semanticDigest"] = fabricated
    payload["evidenceRefs"][0]["snapshotSemanticDigest"] = fabricated
    with pytest.raises(ValidationError, match="semanticDigest"):
        EvidenceSnapshot.model_validate(payload)


def test_pointer_cannot_resolve_digest_excluded_transport_field() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    source_projection = _valid_response_envelope()["items"][0]
    envelope = {"requestId": source_projection}
    response_digest = compute_response_envelope_digest(envelope)
    assert response_digest == compute_response_envelope_digest({})
    attempt = _build_valid_success_attempt(response_digest=response_digest)
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
    )
    with pytest.raises(ValidationError, match="pattern"):
        _build_valid_snapshot(
            attempt=attempt,
            identity_evidence=identity,
            source_response_pointer="/requestId",
        )


def test_signed_derivation_must_match_snapshot_collector_metadata() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    envelope = _valid_response_envelope()
    attempt = _build_valid_success_attempt(
        response_digest=compute_response_envelope_digest(envelope)
    )
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
    )
    snapshot = _build_valid_snapshot(attempt=attempt, identity_evidence=identity)
    payload = snapshot.model_dump(mode="python", by_alias=True)
    payload["collector"]["mcpHostId"] = "mcp-999999999999"
    _refresh_snapshot_digest(payload)
    forged = EvidenceSnapshot.model_validate(payload)
    with pytest.raises(AthenaValidationError, match="signed ingestion derivation"):
        forged.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=lambda attempt_id, kind, digest: envelope,
        )


def test_token_verification_digest_audience_and_collection_lifetime_are_bound() -> None:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    claims = {
        "issuer": (
            "https://login.microsoftonline.com/"
            "11111111-1111-1111-1111-111111111111/v2.0"
        ),
        "audience": "api://athena-ingestion",
        "tenantId": "11111111-1111-1111-1111-111111111111",
        "managedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
        "managedIdentityClientId": "33333333-3333-3333-3333-333333333333",
        "subject": "22222222-2222-2222-2222-222222222222",
        "jti": "jti-123",
        "issuedAt": now - timedelta(minutes=5),
        "notBefore": now - timedelta(minutes=5),
        "expiresAt": now + timedelta(minutes=30),
    }
    token_payload = {
        "status": "valid",
        "verifiedAt": now,
        "keyId": "abc12345",
        "verifiedClaims": claims,
        "verifiedClaimsDigest": compute_verified_claims_digest(claims),
        "tokenVerificationDigest": _sha256("fabricated-token-verification"),
    }
    with pytest.raises(ValidationError, match="canonical preimage"):
        TokenVerification.model_validate(token_payload)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ValidationError, match="audience"):
        _build_valid_identity_evidence(
            private_key=private_key,
            claims_audience="api://different-ingestion",
        )

    envelope = _valid_response_envelope()
    attempt = _build_valid_success_attempt(
        response_digest=compute_response_envelope_digest(envelope)
    )
    expired_identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
        verified_at=now - timedelta(minutes=90),
    )
    snapshot = _build_valid_snapshot(
        attempt=attempt,
        identity_evidence=expired_identity,
    )
    with pytest.raises(AthenaValidationError, match="valid at snapshot collectedAt"):
        snapshot.validate_for_evaluation(
            as_of=now + timedelta(minutes=10),
            key_resolver=_trusted_key_resolver(private_key.public_key()),
            trusted_key_anchor=_trusted_key_anchor(private_key.public_key()),
            envelope_resolver=lambda attempt_id, kind, digest: envelope,
        )


@pytest.mark.parametrize(
    ("claim_name", "mutated_value"),
    [
        ("expiresAt", datetime(2025, 1, 2, 12, 40, tzinfo=UTC)),
        (
            "issuer",
            "https://sts.windows.net/11111111-1111-1111-1111-111111111111/",
        ),
        ("jti", "jti-456"),
        ("issuedAt", datetime(2025, 1, 2, 11, 50, tzinfo=UTC)),
        ("subject", "33333333-3333-3333-3333-333333333333"),
    ],
)
def test_signed_verified_claim_mutation_is_rejected(
    claim_name: str,
    mutated_value: object,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    envelope = _valid_response_envelope()
    attempt = _build_valid_success_attempt(
        response_digest=compute_response_envelope_digest(envelope)
    )
    identity = _build_valid_identity_evidence(
        private_key=private_key,
        collector_attempt=attempt,
    )
    identity_payload = identity.model_dump(mode="python", by_alias=True)
    identity_payload["verifiedClaims"][claim_name] = mutated_value
    token_verification = identity_payload["tokenVerification"]
    token_verification["verifiedClaims"][claim_name] = mutated_value
    claims_digest = compute_verified_claims_digest(
        token_verification["verifiedClaims"]
    )
    token_verification["verifiedClaimsDigest"] = claims_digest
    token_verification["tokenVerificationDigest"] = compute_token_verification_digest(
        token_verification
    )
    derivation = identity.ingestion_derivation.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    identity_payload["ingestionDerivation"] = derivation
    derivation["verifiedClaimsDigest"] = claims_digest
    derivation["tokenVerificationDigest"] = token_verification[
        "tokenVerificationDigest"
    ]
    derivation["derivationDigest"] = compute_artifact_digest(
        {
            key: value
            for key, value in derivation.items()
            if key != "derivationDigest"
        }
    )
    identity_payload["ingestionSignature"]["signedPreimageDigest"] = derivation[
        "derivationDigest"
    ]
    identity_payload["identityEvidenceDigest"] = compute_artifact_digest(
        {
            key: value
            for key, value in identity_payload.items()
            if key != "identityEvidenceDigest"
        }
    )
    mutated_identity = CollectorIdentityEvidence.model_validate(identity_payload)
    snapshot = _build_valid_snapshot(
        attempt=attempt,
        identity_evidence=mutated_identity,
    )
    with pytest.raises(
        AthenaValidationError,
        match="identity evidence verification failed",
    ):
        snapshot.validate_for_evaluation(
            as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
            key_resolver=_trusted_key_resolver(public_key),
            trusted_key_anchor=_trusted_key_anchor(public_key),
            envelope_resolver=lambda attempt_id, kind, digest: envelope,
        )


def test_approved_resource_tags_are_closed_and_public_safe() -> None:
    tags = ApprovedResourceTags(
        environment="production",
        workloadRole="web-service",
        application="app-a1b2c3d4e5f6",
        component="component-012345abcdef",
        managedBy="terraform",
    )
    assert tags.environment == "production"
    assert tags.workload_role == "web-service"

    invalid_tags = [
        {"password": "secret"},
        {"patientName": "Jane Doe"},
        {"application": "Jane Doe"},
        {"application": "jane.doe@example.com"},
        {"application": "bearer-token"},
        {"application": "password123"},
        {"application": "john-doe"},
        {"application": "customer-proprietary-payload"},
        {"application": "Server=x;Password=y"},
        {"component": '{"customerProprietary":"payload"}'},
    ]
    for payload in invalid_tags:
        with pytest.raises(ValidationError):
            ApprovedResourceTags.model_validate(payload)


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "password",
        "patientName",
        "Jane Doe",
        "jane.doe@example.com",
        "bearer-token",
        "password123",
        "john-doe",
        "customerProprietaryPayload",
        (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJzeW50aGV0aWMtaWRlbnRpdHkifQ."
            "abcdefghijklmnopqrstuvwxyz0123456789"
        ),
        "Server=x;Password=y",
        '{"customerProprietary":"payload"}',
        (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/rg-prod"
        ),
        (
            "subscriptions/11111111-1111-1111-1111-111111111111/"
            "providers/Microsoft.Compute"
        ),
    ],
)
def test_evidence_text_rejects_sensitive_or_free_form_payloads(
    unsafe_text: str,
) -> None:
    attempt = _build_valid_success_attempt()
    scope = {
        "scopeType": "subscription",
        "tenantId": "11111111-1111-1111-1111-111111111111",
        "subscriptionId": "11111111-1111-1111-1111-111111111111",
    }
    payload = {
        "recordType": "activitySummary",
        "evidenceScope": scope,
        "operationName": unsafe_text,
        "status": "succeeded",
        "count": 1,
        "windowStart": datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
        "windowEnd": datetime(2025, 1, 2, 12, 1, tzinfo=UTC),
        "provenance": {
            "collectorAttemptId": attempt.attempt_id,
            "collectorIdentityEvidenceRef": attempt.collector_identity_evidence_ref,
            "toolName": attempt.tool_name,
            "toolVersion": attempt.tool_version,
            "sourceResponseDigest": attempt.response_digest,
            "sourceResponsePointer": "/items/0",
        },
        "collectorAttemptDigest": attempt.attempt_digest,
        "collectorIdentityEvidenceRef": attempt.collector_identity_evidence_ref,
    }
    payload["itemDigest"] = compute_evidence_record_digest(payload)
    with pytest.raises(ValidationError):
        ActivitySummaryEvidenceRecord.model_validate(payload)


def test_health_evidence_rejects_legacy_free_form_summary() -> None:
    attempt = _build_valid_success_attempt()
    payload = {
        "recordType": "healthEvent",
        "evidenceScope": {
            "scopeType": "subscription",
            "tenantId": "11111111-1111-1111-1111-111111111111",
            "subscriptionId": "11111111-1111-1111-1111-111111111111",
        },
        "healthKind": "resourceHealth",
        "status": "available",
        "startedAt": datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
        "endedAt": datetime(2025, 1, 2, 12, 1, tzinfo=UTC),
        "summaryCode": "configurationIssue",
        "summary": "patientName: Jane Doe; password=secret",
        "provenance": {
            "collectorAttemptId": attempt.attempt_id,
            "collectorIdentityEvidenceRef": attempt.collector_identity_evidence_ref,
            "toolName": attempt.tool_name,
            "toolVersion": attempt.tool_version,
            "sourceResponseDigest": attempt.response_digest,
            "sourceResponsePointer": "/items/0",
        },
        "collectorAttemptDigest": attempt.attempt_digest,
        "collectorIdentityEvidenceRef": attempt.collector_identity_evidence_ref,
    }
    payload["itemDigest"] = compute_evidence_record_digest(payload)
    with pytest.raises(ValidationError):
        HealthEventEvidenceRecord.model_validate(payload)


def test_safe_evidence_constraints_are_present_in_generated_schema() -> None:
    tag_schema = ApprovedResourceTags.model_json_schema()
    assert tag_schema["additionalProperties"] is False
    assert tag_schema["minProperties"] == 1
    assert {tuple(option["required"]) for option in tag_schema["anyOf"]} == {
        ("environment",),
        ("workloadRole",),
        ("application",),
        ("component",),
        ("managedBy",),
    }
    assert (
        tag_schema["$defs"]["ApplicationTagId"]["pattern"]
        == "^app-[a-f0-9]{12}$"
    )
    assert (
        tag_schema["$defs"]["ComponentTagId"]["pattern"]
        == "^component-[a-f0-9]{12}$"
    )

    resource_schema = ResourceEvidenceRecord.model_json_schema()
    assert (
        resource_schema["$defs"]["IdentityEvidenceIdentifier"]["pattern"]
        == "^identity-[a-f0-9]{12}$"
    )
    snapshot_schema = EvidenceSnapshot.model_json_schema()
    assert (
        snapshot_schema["$defs"]["SnapshotIdentifier"]["pattern"]
        == "^snap-[a-f0-9]{12}$"
    )


def test_evidence_gap_record_rejects_sensitive_payload_pointer() -> None:
    failure_envelope: dict[str, object] = {"error": {"code": "SchemaMismatch"}}
    attempt = _build_valid_failed_attempt(failure_envelope)
    snapshot = _build_valid_gap_snapshot(
        attempt=attempt,
        failure_payload_digest=attempt.failure_digest,
        failure_payload_pointer="/error/code",
    )
    payload = snapshot.evidence_records[0].model_dump(mode="python", by_alias=True)
    payload["failurePayloadPointer"] = "/items/0/password"
    payload["itemDigest"] = compute_evidence_record_digest(payload)
    with pytest.raises(ValidationError, match="pattern"):
        EvidenceGapRecord.model_validate(payload)


@pytest.mark.parametrize(
    "pointer",
    [
        "/items/123-45-6789",
        "/items/customerProprietaryPayload",
        "/properties/password",
        "/items/0/email@example.com",
    ],
)
def test_evidence_item_pointer_rejects_arbitrary_persisted_tokens(
    pointer: str,
) -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.evidence_refs[0].model_dump(mode="python", by_alias=True)
    payload["sourceResponsePointer"] = pointer
    with pytest.raises(ValidationError, match="pattern"):
        EvidenceItemRef.model_validate(payload)


def test_configured_trust_anchor_rejects_attacker_key_resolution() -> None:
    trusted_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    contoso_anchor = (
        "https://contoso.vault.azure.net/keys/athena-key/"
        "0123456789abcdef0123456789abcdef"
    )
    attacker_anchor = (
        "https://attacker.vault.azure.net/keys/attacker-key/"
        "fedcba9876543210fedcba9876543210"
    )
    attacker_evidence = _build_valid_identity_evidence(
        private_key=attacker_private_key,
        trust_anchor=attacker_anchor,
    )
    forged = attacker_evidence.model_copy(
        deep=True,
        update={"trust_anchor_ref": contoso_anchor},
    )
    attacker_record = TrustedKeyRecord(
        anchor=_trusted_key_anchor(
            attacker_private_key.public_key(),
            key_vault_key_id=attacker_anchor,
        ),
        public_key=attacker_private_key.public_key(),
        enabled=True,
        activated_at=datetime(2025, 1, 1, tzinfo=UTC),
        expires_at=datetime(2025, 2, 1, tzinfo=UTC),
    )
    assert not forged.verify_signature(
        key_resolver=lambda lookup: attacker_record,
        trusted_key_anchor=_trusted_key_anchor(trusted_private_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )

    trusted_evidence = _build_valid_identity_evidence(
        private_key=trusted_private_key,
    )
    assert not trusted_evidence.verify_signature(
        key_resolver=lambda lookup: attacker_record,
        trusted_key_anchor=_trusted_key_anchor(trusted_private_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )

    contoso_attacker_evidence = _build_valid_identity_evidence(
        private_key=attacker_private_key,
        trust_anchor=contoso_anchor,
    )
    attacker_contoso_record = TrustedKeyRecord(
        anchor=_trusted_key_anchor(
            attacker_private_key.public_key(),
            key_vault_key_id=contoso_anchor,
        ),
        public_key=attacker_private_key.public_key(),
        enabled=True,
        activated_at=datetime(2025, 1, 1, tzinfo=UTC),
        expires_at=datetime(2025, 2, 1, tzinfo=UTC),
    )
    assert not contoso_attacker_evidence.verify_signature(
        key_resolver=lambda lookup: attacker_contoso_record,
        trusted_key_anchor=_trusted_key_anchor(
            trusted_private_key.public_key(),
            key_vault_key_id=contoso_anchor,
        ),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("enabled", "activated_at", "retired_at", "expires_at"),
    [
        (
            False,
            datetime(2025, 1, 1, tzinfo=UTC),
            None,
            datetime(2025, 2, 1, tzinfo=UTC),
        ),
        (
            True,
            datetime(2025, 1, 1, tzinfo=UTC),
            datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
            None,
        ),
        (
            True,
            datetime(2025, 1, 1, tzinfo=UTC),
            None,
            datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
        ),
        (
            True,
            datetime(2025, 1, 2, 12, 5, tzinfo=UTC),
            None,
            datetime(2025, 2, 1, tzinfo=UTC),
        ),
    ],
)
def test_trusted_key_state_and_lifecycle_reject_invalid_records(
    enabled: bool,
    activated_at: datetime,
    retired_at: datetime | None,
    expires_at: datetime | None,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evidence = _build_valid_identity_evidence(private_key=private_key)
    anchor = _trusted_key_anchor(private_key.public_key())
    matching_key_record = TrustedKeyRecord(
        anchor=anchor,
        public_key=private_key.public_key(),
        enabled=enabled,
        activated_at=activated_at,
        retired_at=retired_at,
        expires_at=expires_at,
    )
    assert not evidence.verify_signature(
        key_resolver=lambda lookup: matching_key_record,
        trusted_key_anchor=matching_key_record.anchor,
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )


def test_signature_time_and_artifact_verification_metadata_are_untrusted() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evidence = _build_valid_identity_evidence(private_key=private_key)
    future_signature = evidence.ingestion_signature.model_copy(
        update={"signed_at": datetime(2035, 1, 1, tzinfo=UTC)}
    )
    future_evidence = evidence.model_copy(
        deep=True,
        update={"ingestion_signature": future_signature},
    )
    assert not future_evidence.verify_signature(
        key_resolver=_trusted_key_resolver(
            private_key.public_key(),
            expires_at=datetime(2040, 1, 1, tzinfo=UTC),
        ),
        trusted_key_anchor=_trusted_key_anchor(private_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )

    payload = evidence.model_dump(mode="python", by_alias=True)
    payload["ingestionSignature"]["signatureVerification"] = {
        "status": "valid",
        "verifiedAt": datetime(2035, 1, 1, tzinfo=UTC),
        "keyVersion": "0123456789abcdef0123456789abcdef",
    }
    payload["ingestionSignature"]["keyStatusAtSigning"] = "active"
    with pytest.raises(ValidationError):
        CollectorIdentityEvidence.model_validate(payload)


def test_signed_attempt_chronology_is_required_without_external_attempt() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evidence = _build_valid_identity_evidence(
        private_key=private_key,
        derived_at_override=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
    )
    assert not evidence.verify_signature(
        key_resolver=_trusted_key_resolver(private_key.public_key()),
        trusted_key_anchor=_trusted_key_anchor(private_key.public_key()),
        as_of=datetime(2025, 1, 2, 12, 10, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "password123",
        "bearer-token",
        (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJzeW50aGV0aWMtaWRlbnRpdHkifQ."
            "abcdefghijklmnopqrstuvwxyz0123456789"
        ),
        "patientName",
        "jane.doe@example.com",
        "Server=x;Password=y",
        "client-secret",
        "alice-smith",
    ],
)
def test_generated_schema_matches_runtime_sensitive_text_rejection(
    sensitive_value: str,
) -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.evidence_records[0].model_dump(mode="json", by_alias=True)
    payload["collectorIdentityEvidenceRef"] = sensitive_value
    payload["provenance"]["collectorIdentityEvidenceRef"] = sensitive_value
    schema = ResourceEvidenceRecord.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        ResourceEvidenceRecord.model_validate(payload)


def test_generated_schema_rejects_sensitive_tags_and_pointers() -> None:
    tag_validator = Draft202012Validator(ApprovedResourceTags.model_json_schema())
    for payload in (
        {"application": "password123"},
        {"component": "patientName"},
        {"managedBy": "bearer-token"},
    ):
        assert list(tag_validator.iter_errors(payload))
        with pytest.raises(ValidationError):
            ApprovedResourceTags.model_validate(payload)

    snapshot = _build_valid_snapshot()
    ref_payload = snapshot.evidence_refs[0].model_dump(mode="json", by_alias=True)
    ref_payload["sourceResponsePointer"] = "/items/password123"
    ref_schema = EvidenceItemRef.model_json_schema()
    assert list(Draft202012Validator(ref_schema).iter_errors(ref_payload))
    with pytest.raises(ValidationError):
        EvidenceItemRef.model_validate(ref_payload)


def test_generated_schema_rejects_sensitive_snapshot_identifier() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="json", by_alias=True)
    payload["snapshotId"] = "password123"
    schema = EvidenceSnapshot.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_entra_identity_ids_are_guid_constrained_in_runtime_and_schema() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evidence = _build_valid_identity_evidence(private_key=private_key)
    payload = evidence.model_dump(mode="json", by_alias=True)
    for claims_path in (
        payload["verifiedClaims"],
        payload["tokenVerification"]["verifiedClaims"],
    ):
        claims_path["managedIdentityObjectId"] = "patientName"
        claims_path["managedIdentityClientId"] = "patientName"
        claims_path["subject"] = "patientName"
    derivation = payload["ingestionDerivation"]
    derivation["mcpHostManagedIdentityObjectId"] = "patientName"
    derivation["mcpHostManagedIdentityClientId"] = "patientName"
    schema = CollectorIdentityEvidence.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        CollectorIdentityEvidence.model_validate(payload)


def test_key_vault_anchor_url_is_schema_visible() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evidence = _build_valid_identity_evidence(private_key=private_key)
    snapshot = _build_valid_snapshot(identity_evidence=evidence)
    payload = snapshot.model_dump(mode="json", by_alias=True)
    payload["collector"]["trustAnchorRef"] = "password123"
    identity = payload["identityEvidence"][0]
    identity["trustAnchorRef"] = "password123"
    identity["ingestionSignature"]["keyVaultKeyId"] = "password123"
    identity["ingestionSignature"]["trustAnchorRef"] = "password123"
    schema = EvidenceSnapshot.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        EvidenceSnapshot.model_validate(payload)


def test_observed_relationship_resource_endpoints_are_scope_checked() -> None:
    snapshot = _build_valid_snapshot()
    payload = snapshot.model_dump(mode="python", by_alias=True)
    attempt = snapshot.collector_attempts[0]
    existing_record = snapshot.evidence_records[0]
    relationship_record = {
        "recordType": "observedRelationship",
        "relationship": {
            "relationshipClass": "observed",
            "relationshipId": "relationship-111111111111",
            "kind": "dependsOn",
            "source": {
                "refKind": "resourceRef",
                "resourceId": existing_record.resource_id,
            },
            "target": {
                "refKind": "resourceRef",
                "resourceId": (
                    "/subscriptions/22222222-2222-2222-2222-222222222222/"
                    "resourceGroups/rg-other/providers/Microsoft.Compute/"
                    "virtualMachines/vm-other"
                ),
            },
            "evidenceItemRef": "item-111111111111",
            "observedAt": attempt.response_received_at,
        },
        "provenance": existing_record.provenance.model_dump(
            mode="python",
            by_alias=True,
        ),
        "collectorAttemptDigest": attempt.attempt_digest,
        "collectorIdentityEvidenceRef": attempt.collector_identity_evidence_ref,
    }
    relationship_record["itemDigest"] = compute_evidence_record_digest(
        relationship_record
    )
    payload["evidenceRecords"] = [relationship_record]
    payload["evidenceRefs"][0]["itemDigest"] = relationship_record["itemDigest"]
    _refresh_snapshot_digest(payload)
    with pytest.raises(ValidationError, match="relationship resource endpoint"):
        EvidenceSnapshot.model_validate(payload)


def test_evidence_resource_id_constraint_is_schema_visible() -> None:
    payload = {"refKind": "resourceRef", "resourceId": "patientName"}
    schema = EvidenceResourceRef.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        EvidenceResourceRef.model_validate(payload)
