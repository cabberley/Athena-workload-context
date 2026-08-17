from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from athena_context.contracts import (
    CollectorIdentityEvidence,
    EvidenceGapRecord,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceSnapshot,
    ResourceEvidenceRecord,
    ResourceGroupScope,
    SnapshotCollector,
    SnapshotPublicationRecord,
    SubscriptionScope,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    compute_artifact_digest,
    compute_authorized_scopes_digest,
    compute_collector_attempt_set_digest,
    compute_collector_identity_evidence_digest,
    compute_evidence_record_set_digest,
    compute_evidence_reference_set_digest,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    compute_failure_envelope_digest,
    compute_identity_evidence_set_digest,
    compute_jti_digest,
    compute_response_envelope_digest,
    compute_snapshot_attestation_preimage_digest,
    compute_token_verification_digest,
    compute_verified_claims_digest,
    sha256_hex,
    snapshot_attestation_preimage,
)
from athena_context.evidence import (
    AZURE_RESOURCE_INVENTORY_TOOL,
    AZURE_RESOURCE_INVENTORY_VERSION,
    REVIEWED_TOOL_ALLOWLIST,
    REVIEWED_TOOL_ALLOWLIST_DIGEST,
    AsyncEvidenceClient,
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceBoundaryError,
    EvidenceCollectionCommand,
    EvidenceProjection,
    EvidenceResponseBounds,
    McpAuthorizationFailure,
    McpFailedResponse,
    McpSuccessResponse,
    McpTimeoutNoResponse,
    McpToolUnavailable,
    ReplayDetectedError,
    SnapshotReferenceBinding,
    SyncEvidenceClient,
    TrustedIngestionError,
    prepare_transport_request,
    project_transport_outcome,
)
from athena_context.evidence.models import (
    EvidenceTransportRequest,
    McpTransportOutcome,
    TrustedIngestionBinding,
)

NOW = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
TENANT_ID = "11111111-1111-1111-1111-111111111111"
SUBSCRIPTION_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
MCP_OBJECT_ID = "22222222-2222-2222-2222-222222222222"
MCP_CLIENT_ID = "33333333-3333-3333-3333-333333333333"
CONTEXT_OBJECT_ID = "44444444-4444-4444-4444-444444444444"
TRUST_ANCHOR = (
    "https://athena-test.vault.azure.net/keys/evidence-ingestion/"
    "0123456789abcdef0123456789abcdef"
)
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-synthetic/"
    "providers/Microsoft.Compute/virtualMachines/vm-synthetic-01"
)


def _scope() -> ResourceGroupScope:
    return ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId=TENANT_ID,
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName="rg-synthetic",
    )


def _bounds(
    *,
    response_bytes: int = 32_768,
    items: int = 10,
    record_bytes: int = 4_096,
    freshness: int = 60,
) -> EvidenceResponseBounds:
    return EvidenceResponseBounds(
        maxResponseBytes=response_bytes,
        maxItems=items,
        maxRecordBytes=record_bytes,
        freshnessSeconds=freshness,
        timeoutMilliseconds=1_000,
    )


def _command(
    *,
    attempt_id: str = "attempt-aaaaaaaaaaaa",
    version: str = AZURE_RESOURCE_INVENTORY_VERSION,
    scope: ResourceGroupScope | SubscriptionScope | None = None,
    authorized_scopes: tuple[ResourceGroupScope | SubscriptionScope, ...] | None = None,
    bounds: EvidenceResponseBounds | None = None,
) -> EvidenceCollectionCommand:
    selected_scope = scope or _scope()
    return EvidenceCollectionCommand(
        attemptId=attempt_id,
        toolName=AZURE_RESOURCE_INVENTORY_TOOL,
        toolVersion=version,
        evidenceScope=selected_scope,
        authorizedScopes=authorized_scopes or (selected_scope,),
        bounds=bounds or _bounds(),
    )


def _trust() -> CollectorTrustConfiguration:
    return CollectorTrustConfiguration(
        collectorIdentityEvidenceRef="identity-aaaaaaaaaaaa",
        mcpHostId="mcp-aaaaaaaaaaaa",
        tenantId=TENANT_ID,
        managedIdentityObjectId=MCP_OBJECT_ID,
        managedIdentityClientId=MCP_CLIENT_ID,
        contextIdentityObjectId=CONTEXT_OBJECT_ID,
        ingestionServiceId="ingestion-aaaaaaaaaaaa",
        ingestionAudience="api://athena-ingestion",
        trustAnchorRef=TRUST_ANCHOR,
    )


def _request(
    *,
    command: EvidenceCollectionCommand | None = None,
) -> EvidenceTransportRequest:
    return prepare_transport_request(command or _command(), _trust(), attempt_started_at=NOW)


def _item(
    *,
    observed_at: datetime = NOW,
    resource_id: str = RESOURCE_ID,
) -> dict[str, object]:
    return {
        "recordType": "resource",
        "observedAt": observed_at,
        "resourceId": resource_id,
        "resourceType": "Microsoft.Compute/virtualMachines",
        "location": "australiaeast",
        "availabilityZone": "1",
        "tags": {
            "environment": "production",
            "workloadRole": "database",
            "application": "app-a1b2c3d4e5f6",
            "component": "component-012345abcdef",
            "managedBy": "bicep",
        },
        "state": "running",
    }


def _success_payload(
    request: EvidenceTransportRequest,
    *,
    items: list[object] | None = None,
    observed_at: datetime = NOW,
    scope: ResourceGroupScope | SubscriptionScope | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": "1.0.0",
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "attemptId": request.attempt_id,
        "requestDigest": request.request_digest,
        "evidenceScope": (scope or request.evidence_scope).model_dump(
            mode="json", by_alias=True
        ),
        "observedAt": observed_at,
        "items": items if items is not None else [_item()],
    }


def _failed_payload(
    request: EvidenceTransportRequest,
    *,
    code: str = "serviceFailure",
    status: str = "unavailable",
) -> dict[str, object]:
    return {
        "schemaVersion": "1.0.0",
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "attemptId": request.attempt_id,
        "requestDigest": request.request_digest,
        "error": {"code": code, "status": status},
    }


def _body(payload: object) -> bytes:
    return canonicalize_json(payload).encode("utf-8")


def _project_success(
    payload: dict[str, object],
    *,
    request: EvidenceTransportRequest | None = None,
) -> EvidenceProjection:
    selected_request = request or _request()
    return project_transport_outcome(
        selected_request,
        McpSuccessResponse(body=_body(payload), response_received_at=NOW),
        validated_at=NOW,
    )


def _gap(projection: EvidenceProjection) -> EvidenceGapRecord:
    records = projection.evidence_records
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EvidenceGapRecord)
    return record


class FrozenClock:
    def now(self) -> datetime:
        return NOW


class SyncReplayGuard:
    def __init__(self) -> None:
        self._attempt_ids: set[str] = set()
        self._request_digests: set[str] = set()

    def reserve(self, attempt_id: str, request_digest: str) -> bool:
        if attempt_id in self._attempt_ids or request_digest in self._request_digests:
            return False
        self._attempt_ids.add(attempt_id)
        self._request_digests.add(request_digest)
        return True


class AsyncReplayGuard:
    def __init__(self) -> None:
        self._delegate = SyncReplayGuard()

    async def reserve(self, attempt_id: str, request_digest: str) -> bool:
        return self._delegate.reserve(attempt_id, request_digest)


class FakeSyncTransport:
    def __init__(
        self, outcome_factory: Callable[[EvidenceTransportRequest], McpTransportOutcome]
    ) -> None:
        self._outcome_factory = outcome_factory
        self.calls = 0

    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        self.calls += 1
        return self._outcome_factory(request)


class FakeAsyncTransport:
    def __init__(
        self, outcome_factory: Callable[[EvidenceTransportRequest], McpTransportOutcome]
    ) -> None:
        self._outcome_factory = outcome_factory
        self.calls = 0

    async def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        self.calls += 1
        return self._outcome_factory(request)


class RealTestSigner:
    """Cryptographic test binding for the trusted-ingestion port."""

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        *,
        identity_id: str = "identity-aaaaaaaaaaaa",
    ) -> None:
        self._private_key = private_key
        self._identity_id = identity_id

    def bind_attempt(
        self, binding: TrustedIngestionBinding
    ) -> CollectorIdentityEvidence:
        trust = binding.trust_configuration
        attempt = binding.collector_attempt
        token_hash = sha256_hex(b"synthetic-token-digest-input")
        claims: dict[str, object] = {
            "issuer": f"https://login.microsoftonline.com/{trust.tenant_id}/v2.0",
            "audience": trust.ingestion_audience,
            "tenantId": trust.tenant_id,
            "managedIdentityObjectId": trust.managed_identity_object_id,
            "managedIdentityClientId": trust.managed_identity_client_id,
            "subject": trust.managed_identity_object_id,
            "jtiDigest": compute_jti_digest("synthetic-jti"),
            "issuedAt": binding.request.attempt_started_at - timedelta(minutes=5),
            "notBefore": binding.request.attempt_started_at - timedelta(minutes=5),
            "expiresAt": binding.as_of + timedelta(minutes=30),
        }
        claims_digest = compute_verified_claims_digest(claims)
        verification: dict[str, object] = {
            "status": "valid",
            "verifiedAt": binding.request.attempt_started_at,
            "keyId": "kid-0123456789abcdef",
            "verifiedClaims": claims,
            "verifiedClaimsDigest": claims_digest,
            "jtiDigest": claims["jtiDigest"],
        }
        verification["tokenVerificationDigest"] = compute_token_verification_digest(
            verification
        )
        attempt_payload = attempt.model_dump(
            mode="python", by_alias=True, exclude_none=True
        )
        binding_keys = {
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
        attempt_binding = {
            key: value for key, value in attempt_payload.items() if key in binding_keys
        }
        if attempt.attempt_type in {"successResponse", "failedResponse"}:
            derived_at = attempt.response_received_at
        elif attempt.attempt_type == "timeoutNoResponse":
            derived_at = attempt.timed_out_at
        elif attempt.attempt_type in {"authorizationFailure", "toolUnavailable"}:
            derived_at = attempt.observed_at
        else:
            raise AssertionError("unexpected collector attempt variant")
        derivation: dict[str, object] = {
            "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
            "derivationPreimageVersion": "1.0.0",
            "schemaVersion": trust.schema_version,
            "semanticContractVersion": trust.semantic_contract_version,
            "policyContractVersion": trust.policy_contract_version,
            "identityEvidenceId": self._identity_id,
            "tokenHash": token_hash,
            "tokenVerificationStatus": "valid",
            "tokenVerificationDigest": verification["tokenVerificationDigest"],
            "verifiedClaimsDigest": claims_digest,
            "jtiDigest": claims["jtiDigest"],
            "mcpHostId": trust.mcp_host_id,
            "mcpHostTenantId": trust.tenant_id,
            "mcpHostManagedIdentityObjectId": trust.managed_identity_object_id,
            "mcpHostManagedIdentityClientId": trust.managed_identity_client_id,
            "ingestionServiceId": trust.ingestion_service_id,
            "ingestionAudience": trust.ingestion_audience,
            "toolAllowlistDigest": trust.tool_allowlist_digest,
            "derivedCollectorIdentityRef": self._identity_id,
            "attemptBinding": attempt_binding,
            "derivedAt": derived_at,
        }
        derivation["derivationDigest"] = compute_artifact_digest(derivation)
        derivation_preimage = {
            key: value for key, value in derivation.items() if key != "derivationDigest"
        }
        anchor = _key_anchor(self._private_key.public_key())
        signature_preimage = {
            "signaturePreimageType": "athena.trustedIngestionSignature",
            "signaturePreimageVersion": "1.0.0",
            "signatureAlgorithm": "RS256",
            "keyVaultKeyId": trust.trust_anchor_ref,
            "keyName": anchor.key_name,
            "keyVersion": anchor.key_version,
            "signedAt": binding.as_of,
            "trustAnchorRef": trust.trust_anchor_ref,
            "derivation": derivation_preimage,
        }
        signature = self._private_key.sign(
            canonicalize_json(signature_preimage).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        identity: dict[str, object] = {
            "identityEvidenceId": self._identity_id,
            "identityEvidenceType": "entraJwtTokenEvidence",
            "tokenHash": token_hash,
            "jwtHeader": {
                "alg": "RS256",
                "kid": "kid-0123456789abcdef",
                "typ": "JWT",
            },
            "trustAnchorRef": trust.trust_anchor_ref,
            "verifiedClaims": claims,
            "tokenVerification": verification,
            "ingestionDerivation": derivation,
            "ingestionSignature": {
                "signatureAlgorithm": "RS256",
                "keyVaultKeyId": trust.trust_anchor_ref,
                "keyName": anchor.key_name,
                "keyVersion": anchor.key_version,
                "signedPreimageDigest": compute_artifact_digest(signature_preimage),
                "signature": base64.b64encode(signature).decode("ascii"),
                "signedAt": binding.as_of,
                "trustAnchorRef": trust.trust_anchor_ref,
            },
        }
        identity["identityEvidenceDigest"] = compute_collector_identity_evidence_digest(
            identity
        )
        return CollectorIdentityEvidence.model_validate(identity)


class AsyncRealTestSigner:
    def __init__(self, delegate: RealTestSigner) -> None:
        self._delegate = delegate

    async def bind_attempt(
        self, binding: TrustedIngestionBinding
    ) -> CollectorIdentityEvidence:
        return self._delegate.bind_attempt(binding)


def _key_anchor(public_key: object) -> TrustedKeyAnchor:
    assert hasattr(public_key, "public_bytes")
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustedKeyAnchor.from_key_vault_key_id(
        TRUST_ANCHOR, public_key_fingerprint=sha256_hex(encoded)
    )


def _key_resolver(
    public_key: object,
) -> Callable[[TrustedKeyAnchor], TrustedKeyRecord | None]:
    anchor = _key_anchor(public_key)
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1),
    )

    def resolve(requested: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return record if requested == anchor else None

    return resolve


def _sync_client(
    transport: FakeSyncTransport,
    *,
    guard: SyncReplayGuard | None = None,
    signer: RealTestSigner | None = None,
) -> SyncEvidenceClient:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    selected_signer = signer or RealTestSigner(private_key)
    signer_key = selected_signer._private_key
    return SyncEvidenceClient(
        transport=transport,
        signer=selected_signer,
        replay_guard=guard or SyncReplayGuard(),
        clock=FrozenClock(),
        trust_configuration=_trust(),
        key_resolver=_key_resolver(signer_key.public_key()),
        trusted_key_anchor=_key_anchor(signer_key.public_key()),
    )


def _attempt_observed_at(result: CollectedEvidence) -> datetime:
    attempt = result.collector_attempt
    if attempt.attempt_type in {"successResponse", "failedResponse"}:
        return attempt.response_received_at
    if attempt.attempt_type == "timeoutNoResponse":
        return attempt.timed_out_at
    return attempt.observed_at


def _validate_result_as_snapshot(
    result: CollectedEvidence,
    private_key: rsa.RSAPrivateKey,
    *,
    snapshot_suffix: str,
) -> EvidenceSnapshot:
    snapshot_id = f"snap-{snapshot_suffix}"
    placeholder = "sha256:" + "0" * 64
    references = result.references(
        SnapshotReferenceBinding(
            snapshotId=snapshot_id,
            snapshotArtifactDigest=placeholder,
            snapshotSemanticDigest=placeholder,
        )
    )
    trust = _trust()
    expires_at = result.request.attempt_started_at + timedelta(hours=1)
    payload: dict[str, object] = {
        "snapshotId": snapshot_id,
        "compatibility": {
            "artifactKind": "evidenceSnapshot",
            "schemaVersion": trust.schema_version,
            "semanticContractVersion": trust.semantic_contract_version,
            "policyContractVersion": trust.policy_contract_version,
            "minimumReaderVersion": "1.0.0",
            "requiresCapabilities": [],
            "producedBy": {
                "producerId": "athena.contracts",
                "version": "1.0.0",
            },
            "extensionPolicy": "rejectUnknownDecisionFields",
            "artifactDigest": placeholder,
            "semanticDigest": placeholder,
        },
        "authorizedScopes": [
            scope.model_dump(mode="json", by_alias=True)
            for scope in result.request.authorized_scopes
        ],
        "collectedAt": result.request.attempt_started_at,
        "expiresAt": expires_at,
        "collector": SnapshotCollector(
            collectorType="azureMcpHost",
            collectorIdentityEvidenceRef=trust.collector_identity_evidence_ref,
            mcpHostId=trust.mcp_host_id,
            tenantId=trust.tenant_id,
            trustAnchorRef=trust.trust_anchor_ref,
            ingestionServiceId=trust.ingestion_service_id,
            ingestionAudience=trust.ingestion_audience,
            toolAllowlistDigest=trust.tool_allowlist_digest,
        ).model_dump(mode="python", by_alias=True),
        "collectorAttempts": [
            result.collector_attempt.model_dump(mode="python", by_alias=True)
        ],
        "evidenceRecords": [
            record.model_dump(mode="python", by_alias=True)
            for record in result.evidence_records
        ],
        "evidenceRefs": [
            reference.model_dump(mode="python", by_alias=True)
            for reference in references
        ],
        "identityEvidence": [
            result.collector_identity_evidence.model_dump(
                mode="python", by_alias=True
            )
        ],
    }
    semantic_digest = compute_evidence_snapshot_semantic_digest(payload)
    compatibility = payload["compatibility"]
    assert isinstance(compatibility, dict)
    compatibility["semanticDigest"] = semantic_digest
    reference_payloads = payload["evidenceRefs"]
    assert isinstance(reference_payloads, list)
    for reference in reference_payloads:
        assert isinstance(reference, dict)
        reference["snapshotSemanticDigest"] = semantic_digest
    artifact_digest = compute_evidence_snapshot_artifact_digest(payload)
    compatibility["artifactDigest"] = artifact_digest
    for reference in reference_payloads:
        assert isinstance(reference, dict)
        reference["snapshotArtifactDigest"] = artifact_digest

    attested_at = max(
        _attempt_observed_at(result),
        result.collector_identity_evidence.ingestion_signature.signed_at,
    ) + timedelta(seconds=1)
    anchor = _key_anchor(private_key.public_key())
    identity_digest = result.collector_identity_evidence.identity_evidence_digest
    attestation: dict[str, object] = {
        "attestationType": "trustedSnapshotPublication",
        "attestationVersion": "1.0.0",
        "artifactKind": "evidenceSnapshot",
        "schemaVersion": trust.schema_version,
        "semanticContractVersion": trust.semantic_contract_version,
        "policyContractVersion": trust.policy_contract_version,
        "snapshotId": snapshot_id,
        "artifactDigest": artifact_digest,
        "semanticDigest": semantic_digest,
        "identityEvidenceDigests": [identity_digest],
        "identityEvidenceSetDigest": compute_identity_evidence_set_digest(payload),
        "collectedAt": result.request.attempt_started_at,
        "expiresAt": expires_at,
        "authorizedScopesDigest": compute_authorized_scopes_digest(payload),
        "collectorAttemptSetDigest": compute_collector_attempt_set_digest(payload),
        "evidenceRecordSetDigest": compute_evidence_record_set_digest(payload),
        "evidenceReferenceSetDigest": compute_evidence_reference_set_digest(payload),
        "attestedAt": attested_at,
        "signatureAlgorithm": "RS256",
        "keyVaultKeyId": anchor.key_vault_key_id,
        "keyName": anchor.key_name,
        "keyVersion": anchor.key_version,
        "trustAnchorRef": anchor.key_vault_key_id,
    }
    attestation["signedPreimageDigest"] = (
        compute_snapshot_attestation_preimage_digest(attestation)
    )
    signature = private_key.sign(
        canonicalize_json(snapshot_attestation_preimage(attestation)).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    attestation["signature"] = base64.b64encode(signature).decode("ascii")
    payload["snapshotAttestation"] = attestation
    snapshot = EvidenceSnapshot.model_validate(payload)
    publication = SnapshotPublicationRecord(
        snapshot_id=snapshot.snapshot_id,
        artifact_digest=snapshot.compatibility.artifact_digest,
        semantic_digest=snapshot.compatibility.semantic_digest,
        schema_version=snapshot.compatibility.schema_version,
        semantic_contract_version=snapshot.compatibility.semantic_contract_version,
        published_at=attested_at + timedelta(seconds=1),
    )

    def resolve_publication(
        requested_snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        return publication if requested_snapshot_id == snapshot.snapshot_id else None

    def resolve_envelope(
        attempt_id: str,
        envelope_kind: Literal["response", "failure"],
        digest: str,
    ) -> object | None:
        envelope = result.envelope
        if (
            envelope is not None
            and attempt_id == result.collector_attempt.attempt_id
            and envelope_kind == envelope.kind
            and digest == envelope.digest
        ):
            return envelope.payload()
        return None

    return snapshot.validate_for_evaluation(
        as_of=publication.published_at + timedelta(seconds=1),
        expected_artifact_digest=snapshot.compatibility.artifact_digest,
        publication_resolver=resolve_publication,
        key_resolver=_key_resolver(private_key.public_key()),
        trusted_key_anchor=anchor,
        envelope_resolver=resolve_envelope,
    )


_OUTCOME_MATRIX: dict[str, tuple[str, str | None]] = {
    "success": ("successResponse", None),
    "failure": ("failedResponse", "collectorUnavailable"),
    "timeout": ("timeoutNoResponse", "missing"),
    "authorization": ("authorizationFailure", "unauthorized"),
    "unavailable": ("toolUnavailable", "collectorUnavailable"),
    "malformed": ("successResponse", "malformed"),
    "stale": ("successResponse", "stale"),
    "oversized": ("failedResponse", "responseOversized"),
    "scopeMismatch": ("successResponse", "scopeMismatch"),
    "replayMismatch": ("failedResponse", "malformed"),
}


def _matrix_outcome(
    scenario: str, request: EvidenceTransportRequest
) -> McpTransportOutcome:
    if scenario == "failure":
        return McpFailedResponse(
            body=_body(_failed_payload(request)),
            response_received_at=NOW,
        )
    if scenario == "timeout":
        return McpTimeoutNoResponse(
            deadline_at=NOW + timedelta(seconds=1),
            timed_out_at=NOW + timedelta(seconds=2),
        )
    if scenario == "authorization":
        return McpAuthorizationFailure(
            authorization_status="denied",
            observed_at=NOW,
        )
    if scenario == "unavailable":
        return McpToolUnavailable(
            unavailable_reason="networkUnavailable",
            observed_at=NOW,
        )
    items = [_item()]
    if scenario == "malformed":
        items[0]["availabilityZone"] = "4"
    elif scenario == "stale":
        items = [_item(observed_at=NOW - timedelta(seconds=61))]
    elif scenario == "scopeMismatch":
        items = [
            _item(resource_id=RESOURCE_ID.replace("rg-synthetic", "rg-outside"))
        ]
    payload = _success_payload(request, items=items)
    if scenario == "replayMismatch":
        payload["attemptId"] = "attempt-ffffffffffff"
    return McpSuccessResponse(body=_body(payload), response_received_at=NOW)


def _collect_matrix_result(
    mode: Literal["sync", "async"],
    scenario: str,
    private_key: rsa.RSAPrivateKey,
    *,
    attempt_suffix: str,
) -> CollectedEvidence:
    bounds = _bounds(response_bytes=64) if scenario == "oversized" else _bounds()
    command = _command(
        attempt_id=f"attempt-{attempt_suffix}",
        bounds=bounds,
    )
    if mode == "sync":
        transport = FakeSyncTransport(
            lambda request: _matrix_outcome(scenario, request)
        )
        return _sync_client(
            transport,
            signer=RealTestSigner(private_key),
        ).collect(command)
    transport = FakeAsyncTransport(
        lambda request: _matrix_outcome(scenario, request)
    )
    public_key = private_key.public_key()
    client = AsyncEvidenceClient(
        transport=transport,
        signer=AsyncRealTestSigner(RealTestSigner(private_key)),
        replay_guard=AsyncReplayGuard(),
        clock=FrozenClock(),
        trust_configuration=_trust(),
        key_resolver=_key_resolver(public_key),
        trusted_key_anchor=_key_anchor(public_key),
    )
    return asyncio.run(client.collect(command))


def test_reviewed_tool_allowlist_is_exact_and_digest_bound() -> None:
    assert REVIEWED_TOOL_ALLOWLIST == (("azure.resourceInventory.read", "1.0.0"),)
    assert compute_artifact_digest(
        [{"toolName": "azure.resourceInventory.read", "toolVersion": "1.0.0"}]
    ) == REVIEWED_TOOL_ALLOWLIST_DIGEST
    with pytest.raises(ValidationError):
        EvidenceCollectionCommand(
            **{
                **_command().model_dump(mode="python", by_alias=True),
                "toolName": "azure.compute.write",
            }
        )


def test_request_carries_authorized_scope_and_all_bounds_in_digest() -> None:
    request = _request()
    assert request.authorized_scopes == (_scope(),)
    assert request.bounds.max_response_bytes == 32_768
    mutated = request.model_dump(mode="python", by_alias=True)
    bounds = mutated["bounds"]
    assert isinstance(bounds, dict)
    bounds["maxItems"] = 9
    with pytest.raises(ValidationError, match="requestDigest"):
        EvidenceTransportRequest.model_validate(mutated)


def test_success_projects_normalized_record_digests_envelope_and_reference() -> None:
    request = _request()
    uppercase_id = RESOURCE_ID.replace(SUBSCRIPTION_ID, SUBSCRIPTION_ID.upper()).replace(
        "Microsoft.Compute", "microsoft.compute"
    )
    projection = _project_success(
        _success_payload(request, items=[_item(resource_id=uppercase_id)]),
        request=request,
    )
    assert projection.collector_attempt.attempt_type == "successResponse"
    record = projection.evidence_records[0]
    assert isinstance(record, ResourceEvidenceRecord)
    assert record.resource_id == RESOURCE_ID
    assert record.item_digest.startswith("sha256:")
    assert projection.collector_attempt.attempt_digest.startswith("sha256:")
    assert projection.envelope is not None
    assert projection.envelope.digest == compute_response_envelope_digest(
        projection.envelope.payload()
    )
    response_item = projection.envelope.payload()["items"][0]
    record_projection = record.model_dump(mode="json", by_alias=True)
    for field_name in (
        "provenance",
        "itemDigest",
        "collectorAttemptDigest",
        "collectorIdentityEvidenceRef",
    ):
        record_projection.pop(field_name)
    assert response_item == record_projection
    assert "observedAt" not in response_item

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    identity = RealTestSigner(private_key).bind_attempt(
        TrustedIngestionBinding(
            request=request,
            collector_attempt=projection.collector_attempt,
            trust_configuration=_trust(),
            as_of=NOW,
        )
    )
    result = CollectedEvidence(
        request=request,
        collector_attempt=projection.collector_attempt,
        evidence_records=projection.evidence_records,
        collector_identity_evidence=identity,
        envelope=projection.envelope,
    )
    references = result.references(
        SnapshotReferenceBinding(
            snapshotId="snap-aaaaaaaaaaaa",
            snapshotArtifactDigest="sha256:" + "a" * 64,
            snapshotSemanticDigest="sha256:" + "b" * 64,
        )
    )
    assert isinstance(references[0], EvidenceItemRef)
    assert references[0].source_response_pointer == "/items/0"
    assert references[0].item_digest == record.item_digest


@pytest.mark.parametrize(
    ("code", "status", "reason"),
    [
        ("schemaMismatch", "invalid", "malformed"),
        ("responseOversized", "invalid", "responseOversized"),
        ("staleResponse", "invalid", "stale"),
        ("serviceFailure", "unavailable", "collectorUnavailable"),
    ],
)
def test_failed_response_maps_to_canonical_attempt_gap_and_envelope(
    code: str, status: str, reason: str
) -> None:
    request = _request()
    payload = _failed_payload(request, code=code, status=status)
    projection = project_transport_outcome(
        request,
        McpFailedResponse(body=_body(payload), response_received_at=NOW),
        validated_at=NOW,
    )
    gap = _gap(projection)
    assert projection.collector_attempt.attempt_type == "failedResponse"
    assert gap.gap_reason == reason
    assert gap.failure_payload_pointer == "/error"
    assert projection.envelope is not None
    assert projection.envelope.digest == compute_failure_envelope_digest(payload)


@pytest.mark.parametrize(
    ("outcome", "attempt_type", "reason"),
    [
        (
            McpTimeoutNoResponse(
                deadline_at=NOW + timedelta(seconds=1),
                timed_out_at=NOW + timedelta(seconds=2),
            ),
            "timeoutNoResponse",
            "missing",
        ),
        (
            McpAuthorizationFailure(authorization_status="denied", observed_at=NOW),
            "authorizationFailure",
            "unauthorized",
        ),
        (
            McpToolUnavailable(unavailable_reason="mcpUnavailable", observed_at=NOW),
            "toolUnavailable",
            "collectorUnavailable",
        ),
        (
            McpToolUnavailable(unavailable_reason="notHosted", observed_at=NOW),
            "toolUnavailable",
            "unsupportedTool",
        ),
    ],
)
def test_no_response_outcomes_map_without_fabricated_envelopes(
    outcome: McpTransportOutcome, attempt_type: str, reason: str
) -> None:
    validated_at = (
        outcome.timed_out_at if isinstance(outcome, McpTimeoutNoResponse) else NOW
    )
    projection = project_transport_outcome(
        _request(), outcome, validated_at=validated_at
    )
    gap = _gap(projection)
    assert projection.collector_attempt.attempt_type == attempt_type
    assert gap.gap_reason == reason
    assert gap.failure_payload_digest is None
    assert gap.failure_payload_pointer is None
    assert projection.envelope is None


def test_malformed_stale_and_scope_mismatched_items_are_exactly_pointed() -> None:
    request = _request()
    malformed = _item()
    malformed["rawLogBody"] = "not retained"
    outside = _item(
        resource_id=RESOURCE_ID.replace("rg-synthetic", "rg-outside")
    )
    projection = _project_success(
        _success_payload(
            request,
            items=[
                malformed,
                _item(observed_at=NOW - timedelta(seconds=61)),
                outside,
            ],
        ),
        request=request,
    )
    gaps = projection.evidence_records
    assert [gap.gap_reason for gap in gaps] == [
        "malformed",
        "stale",
        "scopeMismatch",
    ]
    assert [gap.failure_payload_pointer for gap in gaps] == [
        "/items/0",
        "/items/1",
        "/items/2",
    ]
    assert projection.envelope is not None
    assert "rawLogBody" not in projection.envelope.canonical_bytes.decode("utf-8")


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("availabilityZone", "4"),
        ("resourceType", "Microsoft.Compute/disks"),
        ("observedAt", "2026-08-17 01:00:00+00:00"),
    ],
)
def test_original_closed_item_is_validated_before_safe_redaction(
    field_name: str, invalid_value: str
) -> None:
    request = _request()
    item = _item()
    item[field_name] = invalid_value
    projection = _project_success(
        _success_payload(request, items=[item]), request=request
    )
    assert projection.collector_attempt.attempt_type == "successResponse"
    assert _gap(projection).gap_reason == "malformed"


def test_unknown_nested_tag_is_malformed_and_never_retained() -> None:
    request = _request()
    item = _item()
    tags = item["tags"]
    assert isinstance(tags, dict)
    tags["owner"] = "untrusted-free-form"
    projection = _project_success(
        _success_payload(request, items=[item]), request=request
    )
    assert _gap(projection).gap_reason == "malformed"
    assert projection.envelope is not None
    assert "owner" not in projection.envelope.canonical_bytes.decode("utf-8")


def test_invalid_closed_tag_value_is_malformed_not_defaulted() -> None:
    request = _request()
    item = _item()
    tags = item["tags"]
    assert isinstance(tags, dict)
    tags["environment"] = "prod-untrusted"
    projection = _project_success(
        _success_payload(request, items=[item]), request=request
    )
    assert _gap(projection).gap_reason == "malformed"
    assert projection.envelope is not None
    assert "prod-untrusted" not in projection.envelope.canonical_bytes.decode("utf-8")


def test_invalid_top_level_timestamp_uses_closed_utc_lexical_grammar() -> None:
    request = _request()
    body = _body(_success_payload(request)).replace(
        b"2026-08-17T01:00:00.000Z",
        b"2026-08-17T01:00:00+0000",
    )
    projection = project_transport_outcome(
        request,
        McpSuccessResponse(body=body, response_received_at=NOW),
        validated_at=NOW,
    )
    assert projection.collector_attempt.attempt_type == "failedResponse"
    assert _gap(projection).gap_reason == "malformed"


@pytest.mark.parametrize("depth", [40, 1_100])
def test_excessive_or_parser_recursive_json_maps_to_bounded_malformed_gap(
    depth: int,
) -> None:
    request = _request()
    body = (
        b'{"nested":'
        + (b"[" * depth)
        + b"0"
        + (b"]" * depth)
        + b"}"
    )
    projection = project_transport_outcome(
        request,
        McpSuccessResponse(body=body, response_received_at=NOW),
        validated_at=NOW,
    )
    assert projection.collector_attempt.attempt_type == "failedResponse"
    attempt = projection.collector_attempt
    assert attempt.failure_code == "schemaMismatch"
    assert _gap(projection).gap_reason == "malformed"


def test_response_scope_mismatch_points_to_digest_covered_root() -> None:
    request = _request()
    other_scope = ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId=TENANT_ID,
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName="rg-other",
    )
    projection = _project_success(
        _success_payload(request, scope=other_scope), request=request
    )
    gap = _gap(projection)
    assert gap.gap_reason == "scopeMismatch"
    assert gap.failure_payload_pointer == ""
    assert gap.failure_payload_digest == projection.envelope.digest


def test_response_byte_count_and_record_bounds_fail_closed() -> None:
    byte_request = _request(command=_command(bounds=_bounds(response_bytes=64)))
    byte_projection = _project_success(
        _success_payload(byte_request), request=byte_request
    )
    assert _gap(byte_projection).gap_reason == "responseOversized"
    assert byte_projection.collector_attempt.attempt_type == "failedResponse"

    count_request = _request(command=_command(bounds=_bounds(items=1)))
    count_projection = _project_success(
        _success_payload(count_request, items=[_item(), _item()]),
        request=count_request,
    )
    assert _gap(count_projection).gap_reason == "responseOversized"
    assert count_projection.collector_attempt.attempt_type == "failedResponse"

    record_request = _request(command=_command(bounds=_bounds(record_bytes=300)))
    record_projection = _project_success(
        _success_payload(record_request), request=record_request
    )
    record_gap = _gap(record_projection)
    assert record_gap.gap_reason == "responseOversized"
    assert record_gap.failure_payload_pointer == "/items/0"
    assert record_projection.collector_attempt.attempt_type == "successResponse"


def test_tool_identity_version_and_response_replay_mismatch_fail_closed() -> None:
    request = _request()
    wrong_tool = _success_payload(request)
    wrong_tool["toolName"] = "azure.network.list"
    unsupported = _project_success(wrong_tool, request=request)
    assert unsupported.collector_attempt.attempt_type == "toolUnavailable"
    assert _gap(unsupported).gap_reason == "unsupportedTool"

    wrong_version = _success_payload(request)
    wrong_version["toolVersion"] = "2.0.0"
    unavailable = _project_success(wrong_version, request=request)
    assert unavailable.collector_attempt.attempt_type == "toolUnavailable"

    replayed = _success_payload(request)
    replayed["attemptId"] = "attempt-bbbbbbbbbbbb"
    mismatch = _project_success(replayed, request=request)
    assert mismatch.collector_attempt.attempt_type == "failedResponse"
    assert _gap(mismatch).gap_reason == "malformed"

    wrong_digest = _success_payload(request)
    wrong_digest["requestDigest"] = "sha256:" + "f" * 64
    digest_mismatch = _project_success(wrong_digest, request=request)
    assert digest_mismatch.collector_attempt.attempt_type == "failedResponse"


def test_unsupported_version_and_unauthorized_scope_do_not_call_transport() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = FakeSyncTransport(
        lambda request: McpSuccessResponse(
            body=_body(_success_payload(request)), response_received_at=NOW
        )
    )
    client = _sync_client(transport, signer=RealTestSigner(private_key))
    unsupported = client.collect(
        _command(attempt_id="attempt-bbbbbbbbbbbb", version="2.0.0")
    )
    assert unsupported.collector_attempt.attempt_type == "toolUnavailable"
    assert _gap(unsupported).gap_reason == "unsupportedTool"
    gap_refs = unsupported.references(
        SnapshotReferenceBinding(
            snapshotId="snap-bbbbbbbbbbbb",
            snapshotArtifactDigest="sha256:" + "c" * 64,
            snapshotSemanticDigest="sha256:" + "d" * 64,
        )
    )
    assert isinstance(gap_refs[0], EvidenceGapRef)
    assert gap_refs[0].gap_record_digest == unsupported.evidence_records[0].item_digest

    unauthorized_scope = ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId=TENANT_ID,
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName="rg-unapproved",
    )
    unauthorized = client.collect(
        _command(
            attempt_id="attempt-cccccccccccc",
            scope=unauthorized_scope,
            authorized_scopes=(_scope(),),
        )
    )
    assert unauthorized.collector_attempt.attempt_type == "authorizationFailure"
    assert _gap(unauthorized).gap_reason == "unauthorized"
    assert transport.calls == 0


def test_sync_client_uses_typed_transport_real_signing_and_replay_guard() -> None:
    transport = FakeSyncTransport(
        lambda request: McpSuccessResponse(
            body=_body(_success_payload(request)), response_received_at=NOW
        )
    )
    guard = SyncReplayGuard()
    client = _sync_client(transport, guard=guard)
    result = client.collect(_command())
    assert result.collector_attempt.attempt_type == "successResponse"
    assert result.collector_identity_evidence.identity_evidence_id == (
        _trust().collector_identity_evidence_ref
    )
    with pytest.raises(ReplayDetectedError):
        client.collect(_command())
    assert transport.calls == 1


def test_sync_transport_timeout_exception_maps_to_no_response_attempt() -> None:
    def time_out(_: EvidenceTransportRequest) -> McpTransportOutcome:
        raise TimeoutError

    transport = FakeSyncTransport(time_out)
    result = _sync_client(transport).collect(
        _command(attempt_id="attempt-111111111111")
    )
    assert result.collector_attempt.attempt_type == "timeoutNoResponse"
    gap = result.evidence_records[0]
    assert isinstance(gap, EvidenceGapRecord)
    assert gap.gap_reason == "missing"
    assert result.envelope is None


def test_async_client_uses_separate_async_transport_and_signer_ports() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = FakeAsyncTransport(
        lambda request: McpSuccessResponse(
            body=_body(_success_payload(request)), response_received_at=NOW
        )
    )
    public_key = private_key.public_key()
    client = AsyncEvidenceClient(
        transport=transport,
        signer=AsyncRealTestSigner(RealTestSigner(private_key)),
        replay_guard=AsyncReplayGuard(),
        clock=FrozenClock(),
        trust_configuration=_trust(),
        key_resolver=_key_resolver(public_key),
        trusted_key_anchor=_key_anchor(public_key),
    )
    result = asyncio.run(client.collect(_command(attempt_id="attempt-dddddddddddd")))
    assert isinstance(result.evidence_records[0], ResourceEvidenceRecord)
    assert transport.calls == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("scenario", list(_OUTCOME_MATRIX))
def test_transport_outcome_matrix_builds_evaluation_valid_snapshot(
    mode: Literal["sync", "async"],
    scenario: str,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    scenario_index = list(_OUTCOME_MATRIX).index(scenario) + 1
    if mode == "async":
        scenario_index += 0x100
    suffix = f"{scenario_index:012x}"
    result = _collect_matrix_result(
        mode,
        scenario,
        private_key,
        attempt_suffix=suffix,
    )
    expected_attempt_type, expected_gap_reason = _OUTCOME_MATRIX[scenario]
    assert result.collector_attempt.attempt_type == expected_attempt_type
    if expected_gap_reason is None:
        assert isinstance(result.evidence_records[0], ResourceEvidenceRecord)
    else:
        gap = result.evidence_records[0]
        assert isinstance(gap, EvidenceGapRecord)
        assert gap.gap_reason == expected_gap_reason
    validated = _validate_result_as_snapshot(
        result,
        private_key,
        snapshot_suffix=suffix,
    )
    assert validated.snapshot_id == f"snap-{suffix}"
    assert len(validated.evidence_refs) == len(validated.evidence_records)


def test_mismatched_or_unverifiable_signer_output_is_rejected() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class MismatchedSigner:
        def bind_attempt(
            self, binding: TrustedIngestionBinding
        ) -> CollectorIdentityEvidence:
            valid = RealTestSigner(private_key).bind_attempt(binding)
            return valid.model_copy(
                update={"identity_evidence_id": "identity-bbbbbbbbbbbb"}
            )

    transport = FakeSyncTransport(
        lambda request: McpSuccessResponse(
            body=_body(_success_payload(request)), response_received_at=NOW
        )
    )
    public_key = private_key.public_key()
    client = SyncEvidenceClient(
        transport=transport,
        signer=MismatchedSigner(),
        replay_guard=SyncReplayGuard(),
        clock=FrozenClock(),
        trust_configuration=_trust(),
        key_resolver=_key_resolver(public_key),
        trusted_key_anchor=_key_anchor(public_key),
    )
    with pytest.raises(TrustedIngestionError, match="exactly bind"):
        client.collect(_command(attempt_id="attempt-eeeeeeeeeeee"))


def test_identity_configuration_requires_dedicated_mcp_identity_and_exact_digest() -> None:
    payload = _trust().model_dump(mode="python", by_alias=True)
    payload["contextIdentityObjectId"] = MCP_OBJECT_ID
    with pytest.raises(ValidationError, match="must differ"):
        CollectorTrustConfiguration.model_validate(payload)
    payload["contextIdentityObjectId"] = CONTEXT_OBJECT_ID
    payload["toolAllowlistDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="exact reviewed"):
        CollectorTrustConfiguration.model_validate(payload)


def test_request_rejects_cross_tenant_and_unparented_resource_scope() -> None:
    cross_tenant = ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId="99999999-9999-9999-9999-999999999999",
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName="rg-synthetic",
    )
    with pytest.raises(EvidenceBoundaryError, match="configured Azure MCP tenant"):
        _request(command=_command(scope=cross_tenant))

    from athena_context.contracts import ResourceIdScope

    resource_scope = ResourceIdScope(scopeType="resourceId", resourceId=RESOURCE_ID)
    command = EvidenceCollectionCommand(
        attemptId="attempt-ffffffffffff",
        toolName=AZURE_RESOURCE_INVENTORY_TOOL,
        toolVersion=AZURE_RESOURCE_INVENTORY_VERSION,
        evidenceScope=resource_scope,
        authorizedScopes=(resource_scope,),
        bounds=_bounds(),
    )
    with pytest.raises(EvidenceBoundaryError, match="tenant-bound parent"):
        _request(command=command)
