from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import TypeAdapter, ValidationError

from athena_context import __version__
from athena_context.contracts import (
    CapabilityRequirement,
    CollectorIdentityEvidence,
    CompatibilityMetadata,
    ContextRef,
    Control,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceScope,
    EvidenceSnapshot,
    Finding,
    GovernanceProfileScope,
    IngestionSignature,
    IngestionSignatureVerification,
    JwtHeader,
    NamePatternSelector,
    ProducerInfo,
    ProfileContinuitySettings,
    ProfileDefinition,
    ProfileSettings,
    ResourceEvidenceRecord,
    RiskAcceptance,
    RoleCardinalityBoundedRange,
    RoleCardinalityExactlyOne,
    Selector,
    SnapshotCollector,
    SubscriptionScope,
    SuccessResponseCollectorAttempt,
    TimeoutNoResponseCollectorAttempt,
    TokenVerification,
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
            snapshotId="snap-wc001-canonical-001",
            snapshotArtifactDigest="sha256:" + "a" * 64,
            snapshotSemanticDigest="sha256:" + "b" * 64,
            itemDigest="sha256:" + "c" * 64,
            collectorAttemptId="attempt-001",
            collectorAttemptDigest="sha256:" + "d" * 64,
            collectorToolName="azure.resourceInventory.read",
            collectorToolVersion="1.0.0",
            collectorAttemptAt=datetime.now(tz=UTC),
            collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
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
        snapshotId="snap-1",
        snapshotArtifactDigest="sha256:" + "a" * 64,
        snapshotSemanticDigest="sha256:" + "b" * 64,
        itemDigest="sha256:" + "c" * 64,
        collectorAttemptId="attempt-1",
        collectorAttemptDigest="sha256:" + "d" * 64,
        collectorToolName="azure.resourceInventory.read",
        collectorToolVersion="1.0.0",
        collectorAttemptAt=datetime.now(tz=UTC),
        collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
        sourceResponseDigest="sha256:" + "e" * 64,
        sourceResponsePointer="/value/0",
    )
    assert item_ref.ref_type == "evidenceItem"

    gap_ref = EvidenceGapRef(
        refType="evidenceGap",
        snapshotId="snap-1",
        snapshotArtifactDigest="sha256:" + "a" * 64,
        snapshotSemanticDigest="sha256:" + "b" * 64,
        gapId="gap-1",
        gapRecordDigest="sha256:" + "c" * 64,
        evidenceScope=SubscriptionScope(
            scopeType="subscription",
            tenantId="00000000-0000-0000-0000-000000000000",
            subscriptionId="00000000-0000-0000-0000-000000000000",
        ),
        expectedRecordType="resource",
        collectorAttemptId="attempt-2",
        collectorAttemptDigest="sha256:" + "d" * 64,
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


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _build_valid_success_attempt() -> SuccessResponseCollectorAttempt:
    now = datetime(2025, 1, 2, 12, 0, tzinfo=UTC)
    attempt_id = "attempt-success-001"
    payload = {
        "attemptType": "successResponse",
        "attemptId": attempt_id,
        "attemptStartedAt": now.isoformat(),
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req"),
        "responseDigest": _sha256("response"),
        "responseReceivedAt": (now + timedelta(seconds=5)).isoformat(),
        "collectorIdentityEvidenceRef": "identity-evidence-private-azure-mcp",
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
        "attemptId": "attempt-timeout-001",
        "attemptStartedAt": now.isoformat(),
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req-timeout"),
        "deadlineAt": (now + timedelta(seconds=30)).isoformat(),
        "timedOutAt": (now + timedelta(seconds=45)).isoformat(),
        "collectorIdentityEvidenceRef": "identity-evidence-private-azure-mcp",
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


def _build_valid_snapshot() -> EvidenceSnapshot:
    attempt = _build_valid_success_attempt()
    tenant_id = "11111111-1111-1111-1111-111111111111"
    scope = SubscriptionScope(
        scopeType="subscription",
        tenantId=tenant_id,
        subscriptionId=tenant_id,
    )
    collector = SnapshotCollector(
        collectorType="azureMcpHost",
        collectorIdentityEvidenceRef="identity-evidence-private-azure-mcp",
        mcpHostId="mcp-host-001",
        tenantId=tenant_id,
        trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
        ingestionServiceId="azure-mcp-ingestion",
        ingestionAudience="api://athena-ingestion",
        toolAllowlistDigest=_sha256("tool-allowlist"),
    )
    resource_record = ResourceEvidenceRecord(
        recordType="resource",
        resourceId="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01",
        resourceType="Microsoft.Compute/virtualMachines",
        location="australiaeast",
        availabilityZone="1",
        tags={"env": "prod"},
        state="running",
        provenance={
            "collectorAttemptId": attempt.attempt_id,
            "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            "toolName": attempt.tool_name,
            "toolVersion": attempt.tool_version,
            "sourceResponseDigest": _sha256("source-response"),
            "sourceResponsePointer": "/properties/vmSize",
        },
        itemDigest=_sha256("resource-item"),
        collectorAttemptDigest=attempt.attempt_digest,
        collectorIdentityEvidenceRef=collector.collector_identity_evidence_ref,
    )
    item_ref = EvidenceItemRef(
        refType="evidenceItem",
        snapshotId="snapshot-evidence-001",
        snapshotArtifactDigest=_sha256("snapshot-artifact"),
        snapshotSemanticDigest=_sha256("snapshot-semantic"),
        itemDigest=resource_record.item_digest,
        collectorAttemptId=attempt.attempt_id,
        collectorAttemptDigest=attempt.attempt_digest,
        collectorToolName=attempt.tool_name,
        collectorToolVersion=attempt.tool_version,
        collectorAttemptAt=attempt.response_received_at,
        collectorIdentityEvidenceRef=collector.collector_identity_evidence_ref,
        sourceResponseDigest=_sha256("source-response"),
        sourceResponsePointer="/properties/vmSize",
    )
    snapshot = EvidenceSnapshot(
        snapshotId="snapshot-evidence-001",
        compatibility=CompatibilityMetadata(
            artifactKind="evidenceSnapshot",
            schemaVersion="1.0.0",
            semanticContractVersion="1.0.0",
            policyContractVersion="1.0.0",
            minimumReaderVersion="1.0.0",
            requiresCapabilities=[],
            producedBy={"producerId": "athena.contracts", "version": "1.0.0"},
            extensionPolicy="rejectUnknownDecisionFields",
            artifactDigest=_sha256("snapshot-artifact"),
            semanticDigest=_sha256("snapshot-semantic"),
        ),
        authorizedScopes=[scope],
        collectedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
        expiresAt=datetime(2025, 1, 2, 13, 0, tzinfo=UTC),
        collector=collector,
        collectorAttempts=[attempt],
        evidenceRecords=[resource_record],
        evidenceRefs=[item_ref],
    )
    return snapshot


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
                    "identityEvidenceId": "identity-1",
                    "identityEvidenceType": "entraJwtTokenEvidence",
                    "tokenHash": _sha256("token-1"),
                    "jwtHeader": {"alg": "RS256", "kid": "abc12345", "typ": "JWT"},
                    "trustAnchorRef": "https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
                    "verifiedClaims": {
                        "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                        "audience": "api://athena-ingestion",
                        "tenantId": "11111111-1111-1111-1111-111111111111",
                        "managedIdentityObjectId": "object-123",
                        "managedIdentityClientId": "client-123",
                        "subject": "object-123",
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
                        "identityEvidenceId": "identity-1",
                        "tokenHash": _sha256("token-1"),
                        "tokenVerificationStatus": "valid",
                        "tokenVerificationDigest": _sha256("token-verify"),
                        "mcpHostId": "mcp-host-001",
                        "mcpHostTenantId": "11111111-1111-1111-1111-111111111111",
                        "mcpHostManagedIdentityObjectId": "object-123",
                        "mcpHostManagedIdentityClientId": "client-123",
                        "ingestionServiceId": "azure-mcp-ingestion",
                        "ingestionAudience": "api://athena-ingestion",
                        "toolAllowlistDigest": _sha256("allowlist"),
                        "derivedCollectorIdentityRef": "identity-evidence-private-azure-mcp",
                        "attemptBinding": {
                            "attemptId": "attempt-001",
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
    payload["attemptId"] = "attempt-success-999"
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
            keyVersion="0123456789abcdef0123456789abcdef",
            signedPreimageDigest=_sha256("payload"),
            signature="alg:none",
            signedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
            trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
            keyStatusAtSigning="active",
            signatureVerification=IngestionSignatureVerification(
                status="valid",
                verifiedAt=datetime(2025, 1, 2, 12, 1, tzinfo=UTC),
                keyVersion="0123456789abcdef0123456789abcdef",
            ),
        )

    with pytest.raises(ValidationError):
        IngestionSignature(
            signatureAlgorithm="RS256",
            keyVaultKeyId="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
            keyVersion="0123456789abcdef0123456789abcdef",
            signedPreimageDigest=_sha256("payload"),
            signature="",
            signedAt=datetime(2025, 1, 2, 12, 0, tzinfo=UTC),
            trustAnchorRef="https://contoso.vault.azure.net/keys/athena-key/0123456789abcdef0123456789abcdef",
            keyStatusAtSigning="active",
            signatureVerification=IngestionSignatureVerification(
                status="valid",
                verifiedAt=datetime(2025, 1, 2, 12, 1, tzinfo=UTC),
                keyVersion="0123456789abcdef0123456789abcdef",
            ),
        )
