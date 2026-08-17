from __future__ import annotations

import base64
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

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
    DemoEvaluationResult,
    DemoEvaluationService,
    InMemoryContextStore,
    InMemoryDemoEvaluationApprovalRegistry,
    InMemoryEvaluationCommitPort,
    McpReadAssignment,
    OperatorDeploymentApproval,
    OperatorTrustedWc008ConfigurationPort,
    PrivateMcpEvidenceTransport,
    PublishCommand,
    PublishedContextSelection,
    ResolvedPublishedContext,
    Role,
    RoleBasedAuthorization,
    RoleGrant,
    TransitionCommand,
    VerifiedWc008DeploymentConfiguration,
    Wc008DeploymentOutputAssertion,
    Wc009EvidenceClientAdapter,
    build_wc008_deployment_assertion,
)
from athena_context.api.domain import (
    DraftRecord,
    PublishedManifestView,
    SupersedeCommand,
)
from athena_context.api.evaluation_ports import (
    EvaluationCommitCandidate,
    SnapshotSigningRequest,
    StoredEvaluation,
)
from athena_context.api.memory import InMemoryAuthorityCoordinator
from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CollectorIdentityEvidence,
    ResourceGroupScope,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    canonicalize_manifest_payload,
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
    TrustedIngestionBinding,
)
from athena_context.evidence.models import McpTransportOutcome
from athena_context.fixtures import (
    CANONICAL_PRIVATE_KEY,
    load_canonical_snapshot_resource,
    make_canonical_fixture_from_resources,
)
from athena_context.golden import GOLDEN_PROOF_AS_OF, load_golden_manifest

NOW = GOLDEN_PROOF_AS_OF
CURRENT_NOW = datetime(2026, 8, 17, 5, 30, tzinfo=UTC)
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

    def advance(self, delta: timedelta) -> None:
        self._value += delta

    @property
    def value(self) -> datetime:
        return self._value


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
        expires_at=datetime(2027, 5, 1, tzinfo=UTC),
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


class LifecycleContextResolver:
    def __init__(
        self,
        manifest: CanonicalWorkloadManifest,
        *,
        lifecycle_start: datetime,
    ) -> None:
        self.coordinator = InMemoryAuthorityCoordinator()
        self.authorization = RoleBasedAuthorization(
            [
                RoleGrant(actor_id=PROPOSER.actor_id, role=Role.PROPOSER),
                RoleGrant(actor_id=APPROVER.actor_id, role=Role.APPROVER),
                RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
                # Deliberate grant proves actor-kind checks still reject MCP writes.
                RoleGrant(actor_id=MCP_SERVICE_ACTOR.actor_id, role=Role.PUBLISHER),
            ],
            coordinator=self.coordinator,
        )
        self.store = InMemoryContextStore(coordinator=self.coordinator)
        self.service = ContextService(
            store=self.store,
            authorization=self.authorization,
            clock=StepClock(lifecycle_start),
            publication_actor=Actor(
                actor_id="human-approved-context-api",
                kind=ActorKind.SERVICE,
            ),
        )
        self._manifest_id = manifest.manifest_id
        self._manifest_version = manifest.manifest_version
        self._publish(manifest, previous_version=None)
        self._adapter = ContextServicePublishedContextResolver(
            service=self.service,
            reader_actor=PUBLISHER,
            authority_coordinator=self.coordinator,
        )
        self.calls = 0

    def _publish(
        self,
        manifest: CanonicalWorkloadManifest,
        *,
        previous_version: str | None,
    ) -> None:
        version_key = manifest.manifest_version.replace(".", "-")
        draft = self.service.create_draft(
            PROPOSER,
            f"wc013-{version_key}-create",
            CreateDraftCommand(
                draft_id=f"draft-wc013-{version_key}",
                manifest=manifest,
                manifest_digest=manifest.compatibility.artifact_digest,
                previous_version=previous_version,
                reason="Create the explicitly governed synthetic manifest draft",
            ),
        )
        draft = self.service.validate_draft(
            PROPOSER,
            draft.draft_id,
            f"wc013-{version_key}-validate",
            _transition(draft, "Validate the synthetic canonical manifest"),
        )
        draft = self.service.submit_for_review(
            PROPOSER,
            draft.draft_id,
            f"wc013-{version_key}-submit",
            _transition(draft, "Submit the synthetic manifest for human review"),
        )
        draft = self.service.approve_draft(
            APPROVER,
            draft.draft_id,
            f"wc013-{version_key}-approve",
            _transition(draft, "Human-approve the exact publication candidate"),
        )
        assert draft.approval is not None
        self.service.publish_draft(
            PUBLISHER,
            draft.draft_id,
            f"wc013-{version_key}-publish",
            PublishCommand(
                **_transition(
                    draft,
                    "Human-authorize Context API publication",
                ).model_dump(),
                approval_id=draft.approval.decision_id,
            ),
        )
        self._manifest_id = manifest.manifest_id
        self._manifest_version = manifest.manifest_version

    @property
    def view(self) -> PublishedManifestView:
        return self.service.get_published(
            PUBLISHER,
            self._manifest_version,
            manifest_id=self._manifest_id,
        )

    @property
    def authority_coordinator(self) -> InMemoryAuthorityCoordinator:
        return self.coordinator

    def publish_additional_active(
        self,
        manifest: CanonicalWorkloadManifest,
    ) -> None:
        previous_version = self._manifest_version
        self._publish(manifest, previous_version=previous_version)

    def supersede_with(
        self,
        replacement: CanonicalWorkloadManifest,
    ) -> None:
        original = self.view.published
        self._publish(
            replacement,
            previous_version=original.manifest_version,
        )
        self.service.supersede_version(
            PUBLISHER,
            original.manifest_id,
            original.manifest_version,
            f"wc013-{original.manifest_version}-supersede",
            SupersedeCommand(
                expected_revision=original.source_draft_revision,
                expected_manifest_version=original.manifest_version,
                expected_digest=original.manifest_digest,
                replacement_version=replacement.manifest_version,
                replacement_digest=(
                    self.view.published.manifest_digest
                ),
                reason="Human-authorize a synthetic replacement version",
            ),
        )

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        self.calls += 1
        return self._adapter.resolve(selection, as_of=as_of)


def build_current_synthetic_manifest(
    *,
    as_of: datetime = CURRENT_NOW,
    override_expires_at: datetime | None = None,
    risk_acceptance_expires_at: datetime | None = None,
    production_extends_development: bool = False,
    manifest_version: str = "2.0.0",
    add_prod_east: bool = False,
    additional_profile_ids: tuple[str, ...] = (),
) -> CanonicalWorkloadManifest:
    """Build a new test version; only WC-007 humans may publish it."""

    override_expiry = override_expires_at or (as_of + timedelta(days=30))
    risk_expiry = risk_acceptance_expires_at or (as_of + timedelta(days=30))
    payload = make_canonical_fixture_from_resources().canonical_manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=False,
        exclude_unset=True,
    )
    source_manifest_id = payload["manifestId"]

    def replace_manifest_identity(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "manifestId" and child == source_manifest_id:
                    value[key] = "wl-athena-wc013-current-demo"
                else:
                    replace_manifest_identity(child)
        elif isinstance(value, list):
            for child in value:
                replace_manifest_identity(child)

    replace_manifest_identity(payload)
    payload["manifestVersion"] = manifest_version
    payload["audit"] = {
        "publishedBy": "synthetic-unpublished-candidate",
        "publishedAt": min(override_expiry, risk_expiry) - timedelta(days=60),
        "approvalStatus": "approved",
    }
    for profile in payload["profiles"].values():
        for override in profile["weakeningOverrides"]:
            override["acceptedAt"] = override_expiry - timedelta(days=60)
            override["expiresAt"] = override_expiry
        for acceptance in profile["riskAcceptances"]:
            acceptance["acceptedAt"] = risk_expiry - timedelta(days=60)
            acceptance["expiresAt"] = risk_expiry
    if production_extends_development:
        payload["profiles"]["production"]["extends"] = "development"
    profile_ids = (
        (("prod-east",) if add_prod_east else ())
        + additional_profile_ids
    )
    for profile_id in profile_ids:
        additional_profile = deepcopy(payload["profiles"]["production"])

        def replace_profile_references(
            value: object,
            custom_profile_id: str = profile_id,
        ) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if (
                        key in {"profileId", "extends"}
                        and child == "production"
                    ):
                        value[key] = custom_profile_id
                    elif key == "profiles" and isinstance(child, list):
                        value[key] = [
                            custom_profile_id if item == "production" else item
                            for item in child
                        ]
                    else:
                        replace_profile_references(child)
            elif isinstance(value, list):
                for child in value:
                    replace_profile_references(child)

        replace_profile_references(additional_profile)
        payload["profiles"][profile_id] = additional_profile
    return CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )


def _transition(draft: DraftRecord, reason: str) -> TransitionCommand:
    return TransitionCommand(
        expected_revision=draft.revision,
        expected_manifest_version=draft.manifest.manifest_version,
        expected_digest=draft.manifest_digest,
        reason=reason,
    )


class HookedEvaluationCommitPort:
    """Test barrier that mutates authority after evaluation but before commit."""

    def __init__(self, delegate: InMemoryEvaluationCommitPort) -> None:
        self._delegate = delegate
        self.before_commit: Callable[[], None] | None = None

    def load_receipt(
        self,
        actor_id: str,
        idempotency_key: str,
    ) -> StoredEvaluation | None:
        return self._delegate.load_receipt(actor_id, idempotency_key)

    def commit(
        self,
        candidate: EvaluationCommitCandidate,
    ) -> DemoEvaluationResult:
        if self.before_commit is not None:
            self.before_commit()
        return self._delegate.commit(candidate)

    def resolve_publication(
        self,
        snapshot_id: str,
    ) -> SnapshotPublicationRecord | None:
        return self._delegate.resolve_publication(snapshot_id)

    def resolve_result(self, snapshot_id: str) -> DemoEvaluationResult | None:
        return self._delegate.resolve_result(snapshot_id)


@dataclass(frozen=True, slots=True)
class DemoHarness:
    service: DemoEvaluationService
    command: DemoEvaluationCommand
    store: InMemoryEvaluationCommitPort
    commit_hook: HookedEvaluationCommitPort
    transport: ScenarioTransport
    snapshot_signer: DeterministicSnapshotSigner
    context_resolver: LifecycleContextResolver
    approval_registry: InMemoryDemoEvaluationApprovalRegistry
    authorization: RoleBasedAuthorization
    approval: DemoEvaluationApproval
    deployment_configuration: VerifiedWc008DeploymentConfiguration
    clock: StepClock


def deployment_assertion(
    endpoint: str = PRIVATE_ENDPOINT,
    *,
    internal_environment: bool = True,
    public_network_access: str = "Disabled",
    external_ingress: bool = False,
) -> Wc008DeploymentOutputAssertion:
    resource_group_prefix = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-fixture"
    )
    return build_wc008_deployment_assertion(
        azure_mcp_internal_endpoint=endpoint,
        managed_environment_resource_id=(
            f"{resource_group_prefix}/providers/Microsoft.App/"
            "managedEnvironments/athena-synthetic-mcp-env"
        ),
        azure_mcp_container_app_resource_id=(
            f"{resource_group_prefix}/providers/Microsoft.App/"
            "containerApps/athena-synthetic-mcp"
        ),
        evidence_identity_resource_id=(
            f"{resource_group_prefix}/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/mcp-evidence"
        ),
        context_identity_resource_id=(
            f"{resource_group_prefix}/"
            "providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-context"
        ),
        evidence_identity_object_id=MCP_OBJECT_ID,
        context_identity_object_id=CONTEXT_OBJECT_ID,
        evidence_read_assignments=(McpReadAssignment(scope=scope(), role="Reader"),),
        internal_environment=internal_environment,
        public_network_access=public_network_access,
        external_ingress=external_ingress,
    )


def operator_approval(
    assertion: Wc008DeploymentOutputAssertion,
) -> OperatorDeploymentApproval:
    return OperatorDeploymentApproval(
        approval_id="approval-wc008-deployment",
        status="trusted",
        assertion_digest=assertion.assertion_digest,
        approved_by=APPROVER,
        approved_at=NOW - timedelta(minutes=10),
        reason="Trust the exact synthetic WC-008 private deployment outputs",
    )


def verified_deployment_configuration(
    endpoint: str = PRIVATE_ENDPOINT,
) -> VerifiedWc008DeploymentConfiguration:
    assertion = deployment_assertion(endpoint)
    return OperatorTrustedWc008ConfigurationPort(
        assertion=assertion,
        pinned_assertion_digest=assertion.assertion_digest,
        operator_approval=operator_approval(assertion),
    ).load_verified()


def _trusted_configuration_port(
    configuration: VerifiedWc008DeploymentConfiguration,
) -> OperatorTrustedWc008ConfigurationPort:
    return OperatorTrustedWc008ConfigurationPort(
        assertion=configuration.assertion,
        pinned_assertion_digest=configuration.assertion.assertion_digest,
        operator_approval=configuration.operator_approval,
    )


def build_harness(
    scenario: str = "success",
    *,
    service_configuration: VerifiedWc008DeploymentConfiguration | None = None,
    transport_configuration: VerifiedWc008DeploymentConfiguration | None = None,
    configuration_port: Any | None = None,
    as_of: datetime = NOW,
    manifest: CanonicalWorkloadManifest | None = None,
    profile_resolution_as_of: datetime | None = None,
    approval_expires_at: datetime | None = None,
    profile_id: str = "production",
) -> DemoHarness:
    clock = StepClock(as_of)
    trust = trust_configuration()
    private_key = CANONICAL_PRIVATE_KEY
    trusted_configuration = (
        service_configuration or verified_deployment_configuration()
    )
    actual_transport_configuration = (
        transport_configuration or trusted_configuration
    )
    invoker = ScenarioTransport(scenario)
    transport = PrivateMcpEvidenceTransport(
        deployment_configuration=actual_transport_configuration,
        invoker=invoker,
    )
    evidence_client = Wc009EvidenceClientAdapter(
        transport=transport,
        signer=DeterministicIngestionSigner(private_key),
        replay_guard=ReplayGuard(),
        clock=clock,
        trust_configuration=trust,
        key_resolver=key_resolver(private_key.public_key()),
        trusted_key_anchor=key_anchor(private_key.public_key()),
    )
    source_manifest = manifest or load_golden_manifest()
    lifecycle_start = (
        datetime(2025, 6, 1, 0, 4, 58, tzinfo=UTC)
        if manifest is None
        else as_of - timedelta(minutes=5)
    )
    context_resolver = LifecycleContextResolver(
        source_manifest,
        lifecycle_start=lifecycle_start,
    )
    published_manifest = context_resolver.view.published.manifest
    profile = resolve_manifest_profile(
        published_manifest,
        profile_id,
        as_of=profile_resolution_as_of or as_of,
    )
    approval = DemoEvaluationApproval(
        decision_id="approval-wc013-demo",
        status="authorized",
        approved_by=APPROVER,
        approved_at=as_of - timedelta(minutes=5),
        expires_at=approval_expires_at or (as_of + timedelta(hours=1)),
        manifest_id=published_manifest.manifest_id,
        manifest_version=published_manifest.manifest_version,
        manifest_digest=published_manifest.compatibility.artifact_digest,
        profile_id=profile_id,
        authorized_scope=scope(),
        private_mcp_endpoint=(
            trusted_configuration.assertion.azure_mcp_internal_endpoint
        ),
        evidence_identity_object_id=MCP_OBJECT_ID,
        reason="Authorize one bounded synthetic private MCP demonstration",
    )
    command = DemoEvaluationCommand(
        approval_decision_id=approval.decision_id,
        attempt_id="attempt-013013013013",
        snapshot_id="snap-013013013013",
        manifest_id=published_manifest.manifest_id,
        manifest_version=published_manifest.manifest_version,
        expected_manifest_digest=published_manifest.compatibility.artifact_digest,
        profile_id=profile_id,
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
    snapshot_signer = DeterministicSnapshotSigner(private_key)
    authorization = context_resolver.authorization
    approval_registry = InMemoryDemoEvaluationApprovalRegistry(
        [approval],
        coordinator=context_resolver.coordinator,
    )
    store = InMemoryEvaluationCommitPort(
        coordinator=context_resolver.coordinator,
        context_resolver=context_resolver,
        approval_resolver=approval_registry,
        authorization=authorization,
        clock=clock,
        publication_actor=PUBLICATION_SERVICE,
        evidence_identity_object_id=MCP_OBJECT_ID,
    )
    commit_hook = HookedEvaluationCommitPort(store)
    service = DemoEvaluationService(
        deployment_configuration=(
            configuration_port
            or _trusted_configuration_port(trusted_configuration)
        ),
        evidence_client=evidence_client,
        context_resolver=context_resolver,
        approval_resolver=approval_registry,
        snapshot_signer=snapshot_signer,
        evaluation_commit=commit_hook,
        authorization=authorization,
        clock=clock,
        publication_actor=PUBLICATION_SERVICE,
    )
    return DemoHarness(
        service=service,
        command=command,
        store=store,
        commit_hook=commit_hook,
        transport=invoker,
        snapshot_signer=snapshot_signer,
        context_resolver=context_resolver,
        approval_registry=approval_registry,
        authorization=authorization,
        approval=approval,
        deployment_configuration=trusted_configuration,
        clock=clock,
    )


__all__ = [
    "APPROVER",
    "CONTEXT_OBJECT_ID",
    "CURRENT_NOW",
    "DemoHarness",
    "MCP_OBJECT_ID",
    "MCP_SERVICE_ACTOR",
    "NOW",
    "PRIVATE_ENDPOINT",
    "PUBLICATION_SERVICE",
    "PUBLISHER",
    "TENANT_ID",
    "build_harness",
    "build_current_synthetic_manifest",
    "deployment_assertion",
    "operator_approval",
    "scope",
    "verified_deployment_configuration",
]
