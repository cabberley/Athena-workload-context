from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from athena_context.api import (
    Actor,
    ActorKind,
    ContextService,
    ContextServicePublishedContextResolver,
    CreateDraftCommand,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    DemoEvaluationService,
    InMemoryContextStore,
    InMemoryEvaluationArtifactStore,
    McpReadAssignment,
    PrivateMcpEndpointConfiguration,
    PrivateMcpEvidenceTransport,
    PublishCommand,
    Role,
    RoleBasedAuthorization,
    RoleGrant,
    StaticDemoEvaluationApprovalResolver,
    TransitionCommand,
    Wc009EvidenceClientAdapter,
)
from athena_context.api.domain import (
    DraftRecord,
    PublishedManifestView,
)
from athena_context.api.evaluation_ports import (
    SnapshotSigningRequest,
)
from athena_context.contracts import (
    CollectorIdentityEvidence,
    ResourceGroupScope,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    compute_artifact_digest,
    compute_collector_identity_evidence_digest,
    compute_jti_digest,
    compute_token_verification_digest,
    compute_verified_claims_digest,
    resolve_manifest_profile,
    sha256_hex,
)
from athena_context.evidence import (
    CollectorTrustConfiguration,
    EvidenceResponseBounds,
    EvidenceTransportRequest,
    McpAuthorizationFailure,
    McpFailedResponse,
    McpSuccessResponse,
    McpTimeoutNoResponse,
    McpToolUnavailable,
    SyncEvidenceClient,
    TrustedIngestionBinding,
)
from athena_context.evidence.models import McpTransportOutcome
from athena_context.fixtures import (
    CANONICAL_PRIVATE_KEY,
    load_canonical_snapshot_resource,
)
from athena_context.golden import GOLDEN_PROOF_AS_OF, load_golden_manifest

NOW = datetime(2025, 6, 1, 11, 45, tzinfo=UTC)
TENANT_ID = "11111111-1111-1111-1111-111111111111"
SUBSCRIPTION_ID = TENANT_ID
MCP_OBJECT_ID = "22222222-2222-2222-2222-222222222222"
MCP_CLIENT_ID = "33333333-3333-3333-3333-333333333333"
CONTEXT_OBJECT_ID = "44444444-4444-4444-4444-444444444444"
TRUST_ANCHOR = (
    "https://athena-fixture.vault.azure.net/keys/athena-fixture/"
    "0123456789abcdef0123456789abcdef"
)
PRIVATE_ENDPOINT = "https://athena-synthetic-mcp.internal"

PUBLISHER = Actor(actor_id="wc013-human-publisher", kind=ActorKind.HUMAN)
APPROVER = Actor(actor_id="wc013-human-approver", kind=ActorKind.HUMAN)
PUBLICATION_SERVICE = Actor(actor_id="athena-context-api", kind=ActorKind.SERVICE)
MCP_SERVICE_ACTOR = Actor(actor_id="wc013-mcp-service", kind=ActorKind.SERVICE)
PROPOSER = Actor(actor_id="wc013-proposal-agent", kind=ActorKind.AGENT)


def scope() -> ResourceGroupScope:
    return ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId=TENANT_ID,
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName="rg-athena-fixture",
    )


class StepClock:
    def __init__(self, start: datetime = NOW) -> None:
        self._value = start

    def now(self) -> datetime:
        current = self._value
        self._value += timedelta(seconds=1)
        return current


class ReplayGuard:
    def __init__(self) -> None:
        self._attempts: set[str] = set()
        self._requests: set[str] = set()

    def reserve(self, attempt_id: str, request_digest: str) -> bool:
        if attempt_id in self._attempts or request_digest in self._requests:
            return False
        self._attempts.add(attempt_id)
        self._requests.add(request_digest)
        return True


def key_anchor(public_key: object) -> TrustedKeyAnchor:
    assert hasattr(public_key, "public_bytes")
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustedKeyAnchor.from_key_vault_key_id(
        TRUST_ANCHOR,
        public_key_fingerprint=sha256_hex(encoded),
    )


def key_resolver(
    public_key: object,
) -> Callable[[TrustedKeyAnchor], TrustedKeyRecord | None]:
    anchor = key_anchor(public_key)
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2025, 5, 1, tzinfo=UTC),
        expires_at=datetime(2026, 5, 1, tzinfo=UTC),
    )

    def resolve(requested: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return record if requested == anchor else None

    return resolve


def trust_configuration() -> CollectorTrustConfiguration:
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


class DeterministicIngestionSigner:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    def bind_attempt(
        self,
        binding: TrustedIngestionBinding,
    ) -> CollectorIdentityEvidence:
        trust = binding.trust_configuration
        attempt = binding.collector_attempt
        token_hash = sha256_hex(b"synthetic-wc013-token")
        claims: dict[str, object] = {
            "issuer": f"https://login.microsoftonline.com/{trust.tenant_id}/v2.0",
            "audience": trust.ingestion_audience,
            "tenantId": trust.tenant_id,
            "managedIdentityObjectId": trust.managed_identity_object_id,
            "managedIdentityClientId": trust.managed_identity_client_id,
            "subject": trust.managed_identity_object_id,
            "jtiDigest": compute_jti_digest("synthetic-wc013-jti"),
            "issuedAt": binding.request.attempt_started_at - timedelta(minutes=5),
            "notBefore": binding.request.attempt_started_at - timedelta(minutes=5),
            "expiresAt": binding.as_of + timedelta(minutes=30),
        }
        claims_digest = compute_verified_claims_digest(claims)
        verification: dict[str, object] = {
            "status": "valid",
            "verifiedAt": binding.request.attempt_started_at,
            "keyId": "kid-wc013-synthetic",
            "verifiedClaims": claims,
            "verifiedClaimsDigest": claims_digest,
            "jtiDigest": claims["jtiDigest"],
        }
        verification["tokenVerificationDigest"] = compute_token_verification_digest(
            verification
        )
        attempt_payload = attempt.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
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
        else:
            derived_at = attempt.observed_at
        derivation: dict[str, object] = {
            "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
            "derivationPreimageVersion": "1.0.0",
            "schemaVersion": trust.schema_version,
            "semanticContractVersion": trust.semantic_contract_version,
            "policyContractVersion": trust.policy_contract_version,
            "identityEvidenceId": trust.collector_identity_evidence_ref,
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
            "derivedCollectorIdentityRef": trust.collector_identity_evidence_ref,
            "attemptBinding": attempt_binding,
            "derivedAt": derived_at,
        }
        derivation["derivationDigest"] = compute_artifact_digest(derivation)
        derivation_preimage = {
            key: value for key, value in derivation.items() if key != "derivationDigest"
        }
        anchor = key_anchor(self._private_key.public_key())
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
            "identityEvidenceId": trust.collector_identity_evidence_ref,
            "identityEvidenceType": "entraJwtTokenEvidence",
            "tokenHash": token_hash,
            "jwtHeader": {
                "alg": "RS256",
                "kid": "kid-wc013-synthetic",
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


class DeterministicSnapshotSigner:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key
        self.calls = 0

    def sign(self, request: SnapshotSigningRequest) -> str:
        assert request.trusted_key_anchor == key_anchor(self._private_key.public_key())
        assert request.preimage_digest == sha256_hex(request.canonical_preimage)
        self.calls += 1
        signature = self._private_key.sign(
            request.canonical_preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")


class ScenarioTransport:
    def __init__(self, scenario: str = "success") -> None:
        self.scenario = scenario
        self.calls = 0
        self.endpoints: list[str] = []
        self.deployment_tools: list[str] = []

    def invoke(
        self,
        private_mcp_endpoint: str,
        deployment_tool_name: str,
        request: EvidenceTransportRequest,
    ) -> McpTransportOutcome:
        self.calls += 1
        self.endpoints.append(private_mcp_endpoint)
        self.deployment_tools.append(deployment_tool_name)
        if self.scenario == "authorization":
            return McpAuthorizationFailure(
                authorization_status="denied",
                observed_at=request.attempt_started_at,
            )
        if self.scenario == "unavailable":
            return McpToolUnavailable(
                unavailable_reason="mcpUnavailable",
                observed_at=request.attempt_started_at,
            )
        if self.scenario == "failure":
            payload = {
                "schemaVersion": "1.0.0",
                "toolName": request.tool_name,
                "toolVersion": request.tool_version,
                "attemptId": request.attempt_id,
                "requestDigest": request.request_digest,
                "error": {
                    "code": "serviceFailure",
                    "status": "unavailable",
                },
            }
            return McpFailedResponse(
                body=canonicalize_json(payload).encode("utf-8"),
                response_received_at=request.attempt_started_at,
            )
        if self.scenario == "timeout":
            deadline = request.attempt_started_at + timedelta(seconds=1)
            return McpTimeoutNoResponse(
                deadline_at=deadline,
                timed_out_at=deadline + timedelta(seconds=1),
            )
        if self.scenario == "malformed":
            return McpSuccessResponse(
                body=b"{",
                response_received_at=request.attempt_started_at,
            )

        response_scope = request.evidence_scope
        if self.scenario == "scopeMismatch":
            response_scope = ResourceGroupScope(
                scopeType="resourceGroup",
                tenantId=TENANT_ID,
                subscriptionId=SUBSCRIPTION_ID,
                resourceGroupName="rg-outside-approved-scope",
            )
        observed_at = request.attempt_started_at
        if self.scenario == "stale":
            observed_at -= timedelta(
                seconds=request.bounds.freshness_seconds + 1
            )
        payload = {
            "schemaVersion": "1.0.0",
            "toolName": request.tool_name,
            "toolVersion": request.tool_version,
            "attemptId": request.attempt_id,
            "requestDigest": request.request_digest,
            "evidenceScope": response_scope.model_dump(mode="json", by_alias=True),
            "observedAt": observed_at,
            "items": _golden_resource_items(observed_at),
        }
        return McpSuccessResponse(
            body=canonicalize_json(payload).encode("utf-8"),
            response_received_at=request.attempt_started_at,
        )


def _golden_resource_items(observed_at: datetime) -> list[dict[str, object]]:
    snapshot = load_canonical_snapshot_resource()
    items: list[dict[str, object]] = []
    for record in snapshot["evidenceRecords"]:
        if record["recordType"] != "resource":
            continue
        items.append(
            {
                "recordType": "resource",
                "observedAt": observed_at,
                "resourceId": record["resourceId"],
                "resourceType": record["resourceType"],
                "location": record["location"],
                "availabilityZone": record["availabilityZone"],
                "tags": record["tags"],
                "state": record["state"],
            }
        )
    return items


class GoldenContextResolver:
    def __init__(self) -> None:
        manifest = load_golden_manifest()
        authorization = RoleBasedAuthorization(
            [
                RoleGrant(actor_id=PROPOSER.actor_id, role=Role.PROPOSER),
                RoleGrant(actor_id=APPROVER.actor_id, role=Role.APPROVER),
                RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
            ]
        )
        service = ContextService(
            store=InMemoryContextStore(),
            authorization=authorization,
            clock=StepClock(datetime(2025, 6, 1, 0, 4, 58, tzinfo=UTC)),
            publication_actor=Actor(
                actor_id="human-approved-context-api",
                kind=ActorKind.SERVICE,
            ),
        )
        draft = service.create_draft(
            PROPOSER,
            "wc013-golden-create",
            CreateDraftCommand(
                draft_id="draft-wc005-golden",
                manifest=manifest,
                manifest_digest=manifest.compatibility.artifact_digest,
                previous_version=None,
                reason="Create the immutable WC-005 synthetic golden draft",
            ),
        )
        draft = service.validate_draft(
            PROPOSER,
            draft.draft_id,
            "wc013-golden-validate",
            _transition(draft, "Validate the WC-005 golden manifest"),
        )
        draft = service.submit_for_review(
            PROPOSER,
            draft.draft_id,
            "wc013-golden-submit",
            _transition(draft, "Submit the WC-005 golden manifest"),
        )
        draft = service.approve_draft(
            APPROVER,
            draft.draft_id,
            "wc013-golden-approve",
            _transition(draft, "Approve the WC-005 golden manifest"),
        )
        assert draft.approval is not None
        service.publish_draft(
            PUBLISHER,
            draft.draft_id,
            "wc013-golden-publish",
            PublishCommand(
                **_transition(
                    draft,
                    "Publish the approved WC-005 golden manifest",
                ).model_dump(),
                approval_id=draft.approval.decision_id,
            ),
        )
        self._adapter = ContextServicePublishedContextResolver(
            service=service,
            reader_actor=PUBLISHER,
        )
        self._view = self._adapter.resolve(
            manifest.manifest_id,
            manifest.manifest_version,
        )
        self.calls = 0

    @property
    def view(self) -> PublishedManifestView:
        return self._view

    @view.setter
    def view(self, value: PublishedManifestView) -> None:
        self._view = value

    def resolve(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        self.calls += 1
        if (
            manifest_id != self.view.published.manifest_id
            or manifest_version != self.view.published.manifest_version
        ):
            raise AssertionError("test requested unexpected published context")
        if self.view.supersession is not None:
            return self.view
        return self._adapter.resolve(manifest_id, manifest_version)


def _transition(draft: DraftRecord, reason: str) -> TransitionCommand:
    return TransitionCommand(
        expected_revision=draft.revision,
        expected_manifest_version=draft.manifest.manifest_version,
        expected_digest=draft.manifest_digest,
        reason=reason,
    )


@dataclass(frozen=True, slots=True)
class DemoHarness:
    service: DemoEvaluationService
    command: DemoEvaluationCommand
    store: InMemoryEvaluationArtifactStore
    transport: ScenarioTransport
    snapshot_signer: DeterministicSnapshotSigner
    context_resolver: GoldenContextResolver
    approval: DemoEvaluationApproval


def endpoint_configuration() -> PrivateMcpEndpointConfiguration:
    return PrivateMcpEndpointConfiguration(
        private_mcp_endpoint=PRIVATE_ENDPOINT,
        evidence_identity_resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-fixture/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/mcp-evidence"
        ),
        context_identity_resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-fixture/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-context"
        ),
        evidence_identity_object_id=MCP_OBJECT_ID,
        context_identity_object_id=CONTEXT_OBJECT_ID,
        evidence_read_assignments=(McpReadAssignment(scope=scope(), role="Reader"),),
    )


def build_harness(scenario: str = "success") -> DemoHarness:
    clock = StepClock()
    trust = trust_configuration()
    private_key = CANONICAL_PRIVATE_KEY
    transport = ScenarioTransport(scenario)
    evidence_client = SyncEvidenceClient(
        transport=PrivateMcpEvidenceTransport(
            private_mcp_endpoint=PRIVATE_ENDPOINT,
            invoker=transport,
        ),
        signer=DeterministicIngestionSigner(private_key),
        replay_guard=ReplayGuard(),
        clock=clock,
        trust_configuration=trust,
        key_resolver=key_resolver(private_key.public_key()),
        trusted_key_anchor=key_anchor(private_key.public_key()),
    )
    context_resolver = GoldenContextResolver()
    manifest = context_resolver.view.published.manifest
    profile = resolve_manifest_profile(
        manifest,
        "production",
        as_of=GOLDEN_PROOF_AS_OF,
    )
    approval = DemoEvaluationApproval(
        decision_id="approval-wc013-demo",
        status="authorized",
        approved_by=APPROVER,
        approved_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.manifest_version,
        manifest_digest=manifest.compatibility.artifact_digest,
        profile_id="production",
        authorized_scope=scope(),
        private_mcp_endpoint=PRIVATE_ENDPOINT,
        evidence_identity_object_id=MCP_OBJECT_ID,
        reason="Authorize one bounded synthetic private MCP demonstration",
    )
    command = DemoEvaluationCommand(
        approval_decision_id=approval.decision_id,
        attempt_id="attempt-013013013013",
        snapshot_id="snap-013013013013",
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.manifest_version,
        expected_manifest_digest=manifest.compatibility.artifact_digest,
        profile_id="production",
        expected_resolved_profile_digest=profile.resolved_profile_digest,
        authorized_scope=scope(),
        bounds=EvidenceResponseBounds(
            maxResponseBytes=65_536,
            maxItems=10,
            maxRecordBytes=8_192,
            freshnessSeconds=300,
            timeoutMilliseconds=1_000,
        ),
        reason="Collect, publish, and evaluate the approved synthetic demo",
    )
    store = InMemoryEvaluationArtifactStore()
    snapshot_signer = DeterministicSnapshotSigner(private_key)
    authorization = RoleBasedAuthorization(
        [
            RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
            # This deliberate grant proves the service identity still cannot publish.
            RoleGrant(actor_id=MCP_SERVICE_ACTOR.actor_id, role=Role.PUBLISHER),
        ]
    )
    service = DemoEvaluationService(
        endpoint_configuration=endpoint_configuration(),
        trust_configuration=trust,
        trusted_key_anchor=key_anchor(private_key.public_key()),
        key_resolver=key_resolver(private_key.public_key()),
        evidence_client=Wc009EvidenceClientAdapter(
            private_mcp_endpoint=PRIVATE_ENDPOINT,
            client=evidence_client,
        ),
        context_resolver=context_resolver,
        approval_resolver=StaticDemoEvaluationApprovalResolver([approval]),
        snapshot_signer=snapshot_signer,
        artifact_store=store,
        authorization=authorization,
        clock=clock,
        publication_actor=PUBLICATION_SERVICE,
    )
    return DemoHarness(
        service=service,
        command=command,
        store=store,
        transport=transport,
        snapshot_signer=snapshot_signer,
        context_resolver=context_resolver,
        approval=approval,
    )


__all__ = [
    "APPROVER",
    "CONTEXT_OBJECT_ID",
    "DemoHarness",
    "MCP_OBJECT_ID",
    "MCP_SERVICE_ACTOR",
    "NOW",
    "PRIVATE_ENDPOINT",
    "PUBLICATION_SERVICE",
    "PUBLISHER",
    "TENANT_ID",
    "build_harness",
    "endpoint_configuration",
    "scope",
]
