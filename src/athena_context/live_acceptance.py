from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from athena_context.api import (
    Actor,
    ActorKind,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    DemoEvaluationDependencies,
    DemoEvaluationResult,
    DemoEvaluationService,
    DemoEvaluationTrustConfiguration,
    EnvironmentWc007PublishedContextSelectionPort,
    EnvironmentWc008DeploymentConfigurationPort,
    EvaluationTrustedKeyAuthority,
    ManagedIdentityPrivateMcpInvoker,
    McpReadAssignment,
    OperatorDeploymentApproval,
    OperatorTrustedWc008ConfigurationPort,
    PrivateMcpEvidenceTransport,
    PublishedContextSelection,
    RoleBasedAuthorization,
    RoleGrant,
    Wc008DeploymentOutputAssertion,
    Wc009EvidenceClientAdapter,
    build_wc008_deployment_assertion,
)
from athena_context.api.domain import (
    Permission,
    PublishedManifestView,
    WorkloadGrantScope,
)
from athena_context.api.errors import ContextApiError, DemoEvaluationConfigurationError
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.service import ContextService
from athena_context.azure_adapters import (
    AzureTableAttemptReplayGuard,
    DefaultAzureCredentialTrustedIngestionSigner,
    KeyVaultRsaSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import (
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    compute_artifact_digest,
    resolve_manifest_profile,
    sha256_hex,
)
from athena_context.contracts.models import verify_snapshot_attestation_signature
from athena_context.evidence import CollectorTrustConfiguration
from athena_context.evidence.models import (
    AZURE_RESOURCE_INVENTORY_TOOL,
    AZURE_RESOURCE_INVENTORY_VERSION,
    EvidenceClientError,
)

_MAX_CONFIGURATION_BYTES = 131_072
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_GUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class _ConfigurationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Wc013DeploymentFacts(_ConfigurationModel):
    azure_mcp_internal_endpoint: str = Field(min_length=12, max_length=2048)
    managed_environment_resource_id: str = Field(min_length=1, max_length=2048)
    azure_mcp_container_app_resource_id: str = Field(min_length=1, max_length=2048)
    evidence_identity_resource_id: str = Field(min_length=1, max_length=2048)
    context_identity_resource_id: str = Field(min_length=1, max_length=2048)
    evidence_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    context_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    evidence_identity_client_id: str = Field(pattern=_GUID_PATTERN)
    context_identity_client_id: str = Field(pattern=_GUID_PATTERN)
    evidence_read_assignments: tuple[McpReadAssignment, ...] = Field(
        min_length=1,
        max_length=100,
    )


class Wc013OperatorApprovalInput(_ConfigurationModel):
    approval_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    approved_by: Actor
    approved_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def require_human_operator(self) -> Wc013OperatorApprovalInput:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("WC-008 deployment approval requires a human operator")
        return self


class Wc013AuthorityApprovalInput(_ConfigurationModel):
    approval_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    approved_by: Actor
    approved_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def require_human_operator(self) -> Wc013AuthorityApprovalInput:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("WC-007 authority approval requires a human operator")
        return self


class Wc013CollectorTrustInput(_ConfigurationModel):
    collector_identity_evidence_ref: str = Field(min_length=1, max_length=128)
    mcp_host_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=_GUID_PATTERN)
    managed_identity_client_id: str = Field(pattern=_GUID_PATTERN)
    ingestion_service_id: str = Field(min_length=1, max_length=256)
    ingestion_audience: str = Field(min_length=1, max_length=512)


class Wc013TrustedKeyInput(_ConfigurationModel):
    key_vault_key_id: str = Field(min_length=1, max_length=2048)
    public_key_file: str = Field(min_length=1, max_length=2048)
    activated_at: AwareDatetime
    retired_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None


class Wc013ReplayInput(_ConfigurationModel):
    table_endpoint: str = Field(min_length=12, max_length=2048)
    table_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{2,62}$")
    partition_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )

    @model_validator(mode="after")
    def require_table_https_origin(self) -> Wc013ReplayInput:
        _require_https_origin(self.table_endpoint, label="replay table endpoint")
        return self


class Wc013AuthorityInput(_ConfigurationModel):
    published_context: PublishedManifestView
    evaluation_approval: DemoEvaluationApproval
    publisher: Actor
    context_reader: Actor
    evaluation_grants: tuple[RoleGrant, ...] = Field(min_length=2, max_length=20)


class Wc013AuthorityBundle(Wc013AuthorityInput):
    authority_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def verify_authority_digest(self) -> Wc013AuthorityBundle:
        if self.authority_digest != _authority_digest(self):
            raise ValueError("WC-007 authority bundle digest does not match its content")
        return self


class Wc013AuthorityApproval(_ConfigurationModel):
    approval_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    status: str = Field(pattern=r"^trusted$")
    authority_digest: str = Field(pattern=_DIGEST_PATTERN)
    approved_by: Actor
    approved_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def require_human_operator(self) -> Wc013AuthorityApproval:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("WC-007 authority import requires a human operator")
        return self


class Wc013ConfigurationInput(_ConfigurationModel):
    deployment: Wc013DeploymentFacts
    operator_approval: Wc013OperatorApprovalInput
    authority_bundle_file: str = Field(min_length=1, max_length=2048)
    authority_approval: Wc013AuthorityApprovalInput
    selection: PublishedContextSelection
    azure_mcp_audience: str = Field(min_length=1, max_length=512)
    collector_trust: Wc013CollectorTrustInput
    trusted_key: Wc013TrustedKeyInput
    replay: Wc013ReplayInput
    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    evaluation_command: DemoEvaluationCommand

    @model_validator(mode="after")
    def require_exact_selection(self) -> Wc013ConfigurationInput:
        if self.selection.manifest_version is None:
            raise ValueError("live acceptance requires an exact manifest version")
        if (
            self.evaluation_command.manifest_id != self.selection.manifest_id
            or self.evaluation_command.manifest_version
            != self.selection.manifest_version
            or self.evaluation_command.profile_id != self.selection.profile_id
        ):
            raise ValueError("evaluation command must match the exact WC-007 selection")
        _require_audience(self.azure_mcp_audience, label="Azure MCP audience")
        if (
            self.deployment.evidence_identity_client_id
            != self.collector_trust.managed_identity_client_id
        ):
            raise ValueError(
                "collector trust client id must match the WC-008 evidence identity"
            )
        return self


class Wc013LiveAcceptancePlan(_ConfigurationModel):
    wc008_deployment_assertion_file: str = Field(min_length=1, max_length=2048)
    wc008_operator_approval_file: str = Field(min_length=1, max_length=2048)
    wc008_pinned_assertion_digest: str = Field(pattern=_DIGEST_PATTERN)
    wc007_authority_file: str = Field(min_length=1, max_length=2048)
    wc007_authority_approval_file: str = Field(min_length=1, max_length=2048)
    wc007_pinned_authority_digest: str = Field(pattern=_DIGEST_PATTERN)
    selection: PublishedContextSelection
    context_identity_client_id: str = Field(pattern=_GUID_PATTERN)
    evidence_identity_client_id: str = Field(pattern=_GUID_PATTERN)
    azure_mcp_audience: str = Field(min_length=1, max_length=512)
    collector_trust: Wc013CollectorTrustInput
    trusted_key: Wc013TrustedKeyInput
    replay: Wc013ReplayInput
    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    evaluation_command: DemoEvaluationCommand

    @model_validator(mode="after")
    def require_exact_selection(self) -> Wc013LiveAcceptancePlan:
        if self.selection.manifest_version is None:
            raise ValueError("live acceptance requires an exact manifest version")
        if (
            self.evaluation_command.manifest_id != self.selection.manifest_id
            or self.evaluation_command.manifest_version
            != self.selection.manifest_version
            or self.evaluation_command.profile_id != self.selection.profile_id
        ):
            raise ValueError("evaluation command must match the exact WC-007 selection")
        _require_audience(self.azure_mcp_audience, label="Azure MCP audience")
        if (
            self.evidence_identity_client_id
            != self.collector_trust.managed_identity_client_id
            or self.evidence_identity_client_id == self.context_identity_client_id
        ):
            raise ValueError("live acceptance requires separate exact managed identities")
        return self


@dataclass(frozen=True, slots=True)
class RenderedWc013Configuration:
    assertion_path: Path
    approval_path: Path
    authority_path: Path
    authority_approval_path: Path
    plan_path: Path
    powershell_path: Path
    assertion_digest: str
    authority_digest: str


@dataclass(frozen=True, slots=True)
class PreparedWc013LiveAcceptance:
    plan: Wc013LiveAcceptancePlan
    plan_path: Path
    assertion: Wc008DeploymentOutputAssertion
    operator_approval: OperatorDeploymentApproval
    authority: Wc013AuthorityBundle
    authority_approval: Wc013AuthorityApproval
    collector_trust: CollectorTrustConfiguration
    trusted_key_anchor: TrustedKeyAnchor
    trusted_key_record: TrustedKeyRecord


@dataclass(frozen=True, slots=True)
class Wc013LiveAcceptanceResult:
    result: DemoEvaluationResult
    snapshot_path: Path | None


class Wc013LiveAcceptanceError(RuntimeError):
    """A live acceptance prerequisite or fail-closed verification failed."""


def _require_https_origin(value: str, *, label: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"{label} must be an HTTPS origin without credentials")
    return value.rstrip("/")


def _require_audience(value: str, *, label: str) -> str:
    if (
        not value.strip()
        or value != value.strip()
        or any(character in value for character in "\r\n")
    ):
        raise ValueError(f"{label} must be a bounded non-empty value")
    return value


def _read_bounded(path: Path, *, maximum_bytes: int = _MAX_CONFIGURATION_BYTES) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise Wc013LiveAcceptanceError(f"configuration file is unavailable: {path}") from exc
    if not content or len(content) > maximum_bytes:
        raise Wc013LiveAcceptanceError(f"configuration file is empty or oversized: {path}")
    return content


def _parse_model[Model: BaseModel](path: Path, model: type[Model]) -> Model:
    try:
        return model.model_validate_json(_read_bounded(path))
    except ValidationError as exc:
        raise Wc013LiveAcceptanceError(f"configuration file is invalid: {path}") from exc


def _parse_authority_input(path: Path) -> Wc013AuthorityInput:
    try:
        payload = json.loads(_read_bounded(path))
        published_context = payload["published_context"]
        if not isinstance(published_context, dict):
            raise TypeError
        published_context.setdefault("supersession", None)
        return Wc013AuthorityInput.model_validate_json(json.dumps(payload))
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise Wc013LiveAcceptanceError(
            f"configuration file is invalid: {path}"
        ) from exc


def _authority_json(authority: Wc013AuthorityInput) -> str:
    payload = json.loads(
        authority.model_dump_json(
            by_alias=True,
            exclude_none=True,
        )
    )
    published_context = payload["published_context"]
    if not isinstance(published_context, dict):
        raise Wc013LiveAcceptanceError("WC-007 authority serialization failed closed")
    published_context["supersession"] = None
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _authority_digest(authority: Wc013AuthorityInput) -> str:
    return compute_artifact_digest(
        authority.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_digest"},
            exclude_none=True,
        )
    )


def build_wc013_authority_bundle(
    authority: Wc013AuthorityInput,
) -> Wc013AuthorityBundle:
    return Wc013AuthorityBundle(
        published_context=authority.published_context,
        evaluation_approval=authority.evaluation_approval,
        publisher=authority.publisher,
        context_reader=authority.context_reader,
        evaluation_grants=authority.evaluation_grants,
        authority_digest=_authority_digest(authority),
    )


def _validate_authority(
    selection: PublishedContextSelection,
    command: DemoEvaluationCommand,
    authority: Wc013AuthorityInput,
) -> None:
    view = authority.published_context
    published = view.published
    approval = authority.evaluation_approval
    if view.supersession is not None:
        raise Wc013LiveAcceptanceError("WC-007 authority selects a superseded manifest")
    if (
        selection.manifest_version is None
        or published.manifest_id != selection.manifest_id
        or published.manifest_version != selection.manifest_version
        or published.manifest_digest
        != published.manifest.compatibility.artifact_digest
    ):
        raise Wc013LiveAcceptanceError(
            "WC-007 authority does not contain the exact selected published manifest"
        )
    try:
        profile = resolve_manifest_profile(
            published.manifest,
            selection.profile_id,
            as_of=approval.approved_at,
        )
    except ValueError as exc:
        raise Wc013LiveAcceptanceError(
            "WC-007 authority profile could not be resolved"
        ) from exc
    if (
        command.manifest_id != published.manifest_id
        or command.manifest_version != published.manifest_version
        or command.expected_manifest_digest != published.manifest_digest
        or command.profile_id != profile.profile_id
        or command.expected_resolved_profile_digest
        != profile.resolved_profile_digest
        or approval.status != "authorized"
        or approval.decision_id != command.approval_decision_id
        or approval.manifest_id != command.manifest_id
        or approval.manifest_version != command.manifest_version
        or approval.manifest_digest != command.expected_manifest_digest
        or approval.profile_id != command.profile_id
        or approval.authorized_scope.canonical_json()
        != command.authorized_scope.canonical_json()
    ):
        raise Wc013LiveAcceptanceError(
            "WC-007 evaluation authority does not match the exact command"
        )
    workload_id = published.manifest_id
    if (
        authority.publisher.kind is not ActorKind.HUMAN
        or published.published_by.kind is not ActorKind.SERVICE
    ):
        raise Wc013LiveAcceptanceError(
            "WC-007 authority has invalid publication identities"
        )
    for actor, permission in (
        (authority.publisher, Permission.PUBLISH),
        (authority.context_reader, Permission.READ),
    ):
        matching = tuple(
            grant
            for grant in authority.evaluation_grants
            if grant.actor_id == actor.actor_id
            and isinstance(grant.scope, WorkloadGrantScope)
            and grant.scope.workload_id == workload_id
        )
        if not matching:
            raise Wc013LiveAcceptanceError(
                "WC-007 authority is missing an exact workload-scoped evaluation grant"
            )
        try:
            RoleBasedAuthorization(authority.evaluation_grants).authorize(
                actor,
                permission,
                workload_id,
            )
        except Exception as exc:
            raise Wc013LiveAcceptanceError(
                "WC-007 evaluation grant failed closed"
            ) from exc


class _SystemClock:
    def now(self) -> datetime:
        current = datetime.now(UTC)
        return current.replace(microsecond=(current.microsecond // 1000) * 1000)

    def now_epoch_milliseconds(self) -> int:
        return int(self.now().timestamp() * 1_000)


def wc013_configuration_template() -> str:
    digest = "sha256:" + ("0" * 64)
    template = {
        "deployment": {
            "azure_mcp_internal_endpoint": (
                "https://azure-mcp.synthetic-env.australiaeast.azurecontainerapps.io"
            ),
            "managed_environment_resource_id": (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-demo/providers/Microsoft.App/"
                "managedEnvironments/athena-demo-environment"
            ),
            "azure_mcp_container_app_resource_id": (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-demo/providers/Microsoft.App/"
                "containerApps/athena-demo-azure-mcp"
            ),
            "evidence_identity_resource_id": (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-demo/providers/Microsoft.ManagedIdentity/"
                "userAssignedIdentities/athena-demo-evidence"
            ),
            "context_identity_resource_id": (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-demo/providers/Microsoft.ManagedIdentity/"
                "userAssignedIdentities/athena-demo-context"
            ),
            "evidence_identity_object_id": "22222222-2222-2222-2222-222222222222",
            "context_identity_object_id": "33333333-3333-3333-3333-333333333333",
            "evidence_identity_client_id": "55555555-5555-5555-5555-555555555555",
            "context_identity_client_id": "66666666-6666-6666-6666-666666666666",
            "evidence_read_assignments": [
                {
                    "scope": {
                        "scopeType": "resourceGroup",
                        "tenantId": "44444444-4444-4444-4444-444444444444",
                        "subscriptionId": "11111111-1111-1111-1111-111111111111",
                        "resourceGroupName": "rg-athena-demo-workload",
                    },
                    "role": "Reader",
                }
            ],
        },
        "operator_approval": {
            "approval_id": "approval-wc008-live-demo",
            "approved_by": {"actor_id": "operator-live-demo", "kind": "human"},
            "approved_at": "2026-08-19T00:00:00Z",
            "reason": "Trust the exact reviewed WC-008 live demo deployment outputs",
        },
        "authority_bundle_file": "wc013-authority-source.json",
        "authority_approval": {
            "approval_id": "approval-wc007-live-authority",
            "approved_by": {"actor_id": "operator-live-demo", "kind": "human"},
            "approved_at": "2026-08-19T00:00:00Z",
            "reason": "Trust the exact exported WC-007 authority for this one-shot run",
        },
        "selection": {
            "manifest_id": "wl-athena-live-demo",
            "manifest_version": "1.0.0",
            "profile_id": "production",
        },
        "azure_mcp_audience": "api://athena-azure-mcp",
        "collector_trust": {
            "collector_identity_evidence_ref": "identity-wc013-live",
            "mcp_host_id": "mcp-wc013-live",
            "tenant_id": "44444444-4444-4444-4444-444444444444",
            "managed_identity_client_id": "55555555-5555-5555-5555-555555555555",
            "ingestion_service_id": "ingestion-wc013-live",
            "ingestion_audience": "api://athena-trusted-ingestion",
        },
        "trusted_key": {
            "key_vault_key_id": (
                "https://athena-demo.vault.azure.net/keys/"
                "wc013-signing/0123456789abcdef0123456789abcdef"
            ),
            "public_key_file": "wc013-signing-public-key.pem",
            "activated_at": "2026-08-19T00:00:00Z",
            "expires_at": "2027-08-19T00:00:00Z",
        },
        "replay": {
            "table_endpoint": "https://athenademoreplay.table.core.windows.net",
            "table_name": "Wc013Replay",
            "partition_key": "wc013-live-demo",
        },
        "idempotency_key": "wc013-live-acceptance-001",
        "evaluation_command": {
            "approval_decision_id": "approval-wc013-live-demo",
            "attempt_id": "attempt-013013013013",
            "snapshot_id": "snap-013013013013",
            "manifest_id": "wl-athena-live-demo",
            "manifest_version": "1.0.0",
            "expected_manifest_digest": digest,
            "profile_id": "production",
            "expected_resolved_profile_digest": digest,
            "authorized_scope": {
                "scopeType": "resourceGroup",
                "tenantId": "44444444-4444-4444-4444-444444444444",
                "subscriptionId": "11111111-1111-1111-1111-111111111111",
                "resourceGroupName": "rg-athena-demo-workload",
            },
            "bounds": {
                "maxResponseBytes": 1048576,
                "maxItems": 500,
                "maxRecordBytes": 65536,
                "freshnessSeconds": 300,
                "timeoutMilliseconds": 30000,
            },
            "reason": "Run the explicit WC-013 live acceptance gate",
        },
    }
    return json.dumps(template, indent=2, sort_keys=True) + "\n"


def render_wc013_configuration(
    source_path: Path,
    output_directory: Path,
) -> RenderedWc013Configuration:
    source = _parse_model(source_path, Wc013ConfigurationInput)
    try:
        assertion = build_wc008_deployment_assertion(
            azure_mcp_internal_endpoint=source.deployment.azure_mcp_internal_endpoint,
            managed_environment_resource_id=source.deployment.managed_environment_resource_id,
            azure_mcp_container_app_resource_id=(
                source.deployment.azure_mcp_container_app_resource_id
            ),
            evidence_identity_resource_id=source.deployment.evidence_identity_resource_id,
            context_identity_resource_id=source.deployment.context_identity_resource_id,
            evidence_identity_object_id=source.deployment.evidence_identity_object_id,
            context_identity_object_id=source.deployment.context_identity_object_id,
            evidence_read_assignments=source.deployment.evidence_read_assignments,
        )
        approval = OperatorDeploymentApproval(
            approval_id=source.operator_approval.approval_id,
            status="trusted",
            assertion_digest=assertion.assertion_digest,
            approved_by=source.operator_approval.approved_by,
            approved_at=source.operator_approval.approved_at,
            reason=source.operator_approval.reason,
        )
    except (ValueError, ValidationError) as exc:
        raise Wc013LiveAcceptanceError(
            "reviewed WC-013 configuration inputs are inconsistent"
        ) from exc
    authority_source_path = _resolve_plan_path(
        source_path.parent,
        source.authority_bundle_file,
    )
    authority_input = _parse_authority_input(authority_source_path)
    authority = build_wc013_authority_bundle(authority_input)
    authority_approval = Wc013AuthorityApproval(
        approval_id=source.authority_approval.approval_id,
        status="trusted",
        authority_digest=authority.authority_digest,
        approved_by=source.authority_approval.approved_by,
        approved_at=source.authority_approval.approved_at,
        reason=source.authority_approval.reason,
    )
    _validate_authority(source.selection, source.evaluation_command, authority)

    output_directory.mkdir(parents=True, exist_ok=True)
    assertion_path = output_directory / "wc008-deployment-assertion.json"
    approval_path = output_directory / "wc008-operator-approval.json"
    authority_path = output_directory / "wc007-evaluation-authority.json"
    authority_approval_path = output_directory / "wc007-authority-approval.json"
    plan_path = output_directory / "wc013-live-acceptance.json"
    powershell_path = output_directory / "wc013-runtime.ps1"
    paths = (
        assertion_path,
        approval_path,
        authority_path,
        authority_approval_path,
        plan_path,
        powershell_path,
    )
    if any(path.exists() for path in paths):
        raise Wc013LiveAcceptanceError(
            "WC-013 configuration output already exists; refusing to overwrite"
        )

    public_key_path = Path(source.trusted_key.public_key_file)
    if not public_key_path.is_absolute():
        public_key_path = source_path.parent / public_key_path
    relative_public_key = Path(
        os.path.relpath(public_key_path, output_directory)
    ).as_posix()
    trusted_key = source.trusted_key.model_copy(
        update={"public_key_file": relative_public_key}
    )
    plan = Wc013LiveAcceptancePlan(
        wc008_deployment_assertion_file=assertion_path.name,
        wc008_operator_approval_file=approval_path.name,
        wc008_pinned_assertion_digest=assertion.assertion_digest,
        wc007_authority_file=authority_path.name,
        wc007_authority_approval_file=authority_approval_path.name,
        wc007_pinned_authority_digest=authority.authority_digest,
        selection=source.selection,
        context_identity_client_id=source.deployment.context_identity_client_id,
        evidence_identity_client_id=source.deployment.evidence_identity_client_id,
        azure_mcp_audience=source.azure_mcp_audience,
        collector_trust=source.collector_trust,
        trusted_key=trusted_key,
        replay=source.replay,
        idempotency_key=source.idempotency_key,
        evaluation_command=source.evaluation_command,
    )

    assertion_path.write_text(
        assertion.model_dump_json(indent=2),
        encoding="utf-8",
        newline="\n",
    )
    approval_path.write_text(
        approval.model_dump_json(indent=2),
        encoding="utf-8",
        newline="\n",
    )
    authority_path.write_text(
        _authority_json(authority),
        encoding="utf-8",
        newline="\n",
    )
    authority_approval_path.write_text(
        authority_approval.model_dump_json(indent=2),
        encoding="utf-8",
        newline="\n",
    )
    plan_path.write_text(
        plan.model_dump_json(indent=2),
        encoding="utf-8",
        newline="\n",
    )
    powershell_path.write_text(
        _powershell_environment_template(plan),
        encoding="utf-8",
        newline="\n",
    )
    return RenderedWc013Configuration(
        assertion_path=assertion_path,
        approval_path=approval_path,
        authority_path=authority_path,
        authority_approval_path=authority_approval_path,
        plan_path=plan_path,
        powershell_path=powershell_path,
        assertion_digest=assertion.assertion_digest,
        authority_digest=authority.authority_digest,
    )


def _powershell_environment_template(plan: Wc013LiveAcceptancePlan) -> str:
    manifest_version = plan.selection.manifest_version
    if manifest_version is None:
        raise Wc013LiveAcceptanceError("rendered live selection lost its exact version")
    values = {
        "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE": (
            "$configurationRoot\\wc008-deployment-assertion.json"
        ),
        "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE": (
            "$configurationRoot\\wc008-operator-approval.json"
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_MANIFEST_ID": plan.selection.manifest_id,
        "ATHENA_WC013_MANIFEST_VERSION": manifest_version,
        "ATHENA_WC013_PROFILE_ID": plan.selection.profile_id,
        "ATHENA_WC013_WC007_AUTHORITY_FILE": (
            "$configurationRoot\\wc007-evaluation-authority.json"
        ),
        "ATHENA_WC013_WC007_AUTHORITY_APPROVAL_FILE": (
            "$configurationRoot\\wc007-authority-approval.json"
        ),
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID": (
            plan.context_identity_client_id
        ),
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_AZURE_MCP_AUDIENCE": plan.azure_mcp_audience,
        "ATHENA_WC013_REPLAY_TABLE_ENDPOINT": plan.replay.table_endpoint,
        "ATHENA_WC013_REPLAY_TABLE_NAME": plan.replay.table_name,
        "ATHENA_WC013_REPLAY_PARTITION_KEY": plan.replay.partition_key,
        "AZURE_CLIENT_ID": plan.context_identity_client_id,
        "ATHENA_WC013_LIVE": "1",
        "ATHENA_WC013_LIVE_CONFIG": (
            "$configurationRoot\\wc013-live-acceptance.json"
        ),
    }
    lines = [
        "# Generated non-secret WC-013 runtime configuration.",
        "$configurationRoot = Split-Path -Parent $MyInvocation.MyCommand.Path",
    ]
    for name, value in values.items():
        if value.startswith("$configurationRoot"):
            lines.append(f'$env:{name} = "{value}"')
        else:
            escaped = value.replace("'", "''")
            lines.append(f"$env:{name} = '{escaped}'")
    return "\n".join(lines) + "\n"


def prepare_wc013_live_acceptance(plan_path: Path) -> PreparedWc013LiveAcceptance:
    plan = _parse_model(plan_path, Wc013LiveAcceptancePlan)
    root = plan_path.parent
    assertion_path = _resolve_plan_path(root, plan.wc008_deployment_assertion_file)
    approval_path = _resolve_plan_path(root, plan.wc008_operator_approval_file)
    authority_path = _resolve_plan_path(root, plan.wc007_authority_file)
    authority_approval_path = _resolve_plan_path(
        root,
        plan.wc007_authority_approval_file,
    )
    public_key_path = _resolve_plan_path(root, plan.trusted_key.public_key_file)
    environment = {
        "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE": str(assertion_path),
        "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE": str(approval_path),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_MANIFEST_ID": plan.selection.manifest_id,
        "ATHENA_WC013_MANIFEST_VERSION": plan.selection.manifest_version or "",
        "ATHENA_WC013_PROFILE_ID": plan.selection.profile_id,
    }
    try:
        verified = EnvironmentWc008DeploymentConfigurationPort(
            environment
        ).load_verified()
        loaded_selection = EnvironmentWc007PublishedContextSelectionPort(
            environment
        ).load()
    except DemoEvaluationConfigurationError as exc:
        raise Wc013LiveAcceptanceError(
            "rendered WC-007/WC-008 environment configuration failed closed"
        ) from exc
    if loaded_selection != plan.selection:
        raise Wc013LiveAcceptanceError("rendered WC-007 selection changed during parsing")
    authority = _parse_model(authority_path, Wc013AuthorityBundle)
    authority_approval = _parse_model(
        authority_approval_path,
        Wc013AuthorityApproval,
    )
    if (
        authority.authority_digest != plan.wc007_pinned_authority_digest
        or authority_approval.authority_digest
        != plan.wc007_pinned_authority_digest
    ):
        raise Wc013LiveAcceptanceError(
            "WC-007 authority does not match the pinned human trust decision"
        )
    _validate_authority(plan.selection, plan.evaluation_command, authority)

    public_key = _load_rsa_public_key(public_key_path)
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        trusted_key_anchor = TrustedKeyAnchor.from_key_vault_key_id(
            plan.trusted_key.key_vault_key_id,
            public_key_fingerprint=sha256_hex(encoded),
        )
        trusted_key_record = TrustedKeyRecord(
            anchor=trusted_key_anchor,
            public_key=public_key,
            enabled=True,
            activated_at=plan.trusted_key.activated_at,
            retired_at=plan.trusted_key.retired_at,
            expires_at=plan.trusted_key.expires_at,
        )
        collector_trust = CollectorTrustConfiguration(
            collectorIdentityEvidenceRef=(
                plan.collector_trust.collector_identity_evidence_ref
            ),
            mcpHostId=plan.collector_trust.mcp_host_id,
            tenantId=plan.collector_trust.tenant_id,
            managedIdentityObjectId=verified.assertion.evidence_identity_object_id,
            managedIdentityClientId=plan.collector_trust.managed_identity_client_id,
            contextIdentityObjectId=verified.assertion.context_identity_object_id,
            ingestionServiceId=plan.collector_trust.ingestion_service_id,
            ingestionAudience=plan.collector_trust.ingestion_audience,
            trustAnchorRef=trusted_key_anchor.key_vault_key_id,
        )
    except (ValueError, ValidationError) as exc:
        raise Wc013LiveAcceptanceError(
            "trusted key or collector trust configuration is invalid"
        ) from exc
    if not verified.assertion.authorizes_inventory_scope(
        plan.evaluation_command.authorized_scope
    ):
        raise Wc013LiveAcceptanceError(
            "WC-008 Reader assignments do not authorize the evaluation scope"
        )
    evaluation_approval = authority.evaluation_approval
    if (
        evaluation_approval.private_mcp_endpoint
        != verified.assertion.azure_mcp_internal_endpoint
        or evaluation_approval.evidence_identity_object_id
        != verified.assertion.evidence_identity_object_id
    ):
        raise Wc013LiveAcceptanceError(
            "WC-007 evaluation approval is not bound to the WC-008 endpoint and identity"
        )
    return PreparedWc013LiveAcceptance(
        plan=plan,
        plan_path=plan_path,
        assertion=verified.assertion,
        operator_approval=verified.operator_approval,
        authority=authority,
        authority_approval=authority_approval,
        collector_trust=collector_trust,
        trusted_key_anchor=trusted_key_anchor,
        trusted_key_record=trusted_key_record,
    )


def _resolve_plan_path(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    try:
        public_key = serialization.load_pem_public_key(_read_bounded(path))
    except (TypeError, ValueError) as exc:
        raise Wc013LiveAcceptanceError(
            "trusted signing public key is not valid PEM"
        ) from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise Wc013LiveAcceptanceError("trusted signing key must be RSA")
    if public_key.key_size < 2048:
        raise Wc013LiveAcceptanceError("trusted signing RSA key must be at least 2048 bits")
    return public_key


def run_wc013_live_acceptance(
    plan_path: Path,
    *,
    snapshot_output: Path | None = None,
) -> Wc013LiveAcceptanceResult:
    prepared = prepare_wc013_live_acceptance(plan_path)
    _require_runtime_environment(prepared)
    try:
        service = _compose_wc013_one_shot_service(prepared)
        result = service.evaluate(
            prepared.authority.publisher,
            prepared.plan.idempotency_key,
            prepared.plan.evaluation_command,
        )
    except Exception as exc:
        exception_types: list[str] = []
        safe_causes: list[str] = []
        current: BaseException | None = exc
        while current is not None and len(exception_types) < 4:
            exception_types.append(type(current).__name__)
            if isinstance(current, ContextApiError | EvidenceClientError):
                safe_causes.append(f"{type(current).__name__}: {current}")
            elif isinstance(current, ValidationError):
                safe_causes.append(_safe_validation_failure_pointers(current))
            current = current.__cause__
        safe_detail = f": {'; '.join(safe_causes)}" if safe_causes else ""
        raise Wc013LiveAcceptanceError(
            "one-shot WC-013 production composition failed closed "
            f"({' <- '.join(exception_types)}){safe_detail}"
        ) from exc
    verify_wc013_live_result(prepared, result)
    written_path = None
    if snapshot_output is not None:
        written_path = _write_immutable_snapshot(snapshot_output, result)
    return Wc013LiveAcceptanceResult(result=result, snapshot_path=written_path)


def _safe_validation_failure_pointers(error: ValidationError) -> str:
    failures = error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    )[:3]
    pointers = ", ".join(
        f"{'.'.join(str(part) for part in failure['loc'])}:{failure['type']}"
        for failure in failures
    )
    return f"ValidationError[{pointers}]"


def _require_runtime_environment(
    prepared: PreparedWc013LiveAcceptance,
) -> None:
    plan = prepared.plan
    expected = {
        "AZURE_CLIENT_ID": plan.context_identity_client_id,
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID": (
            plan.context_identity_client_id
        ),
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_AZURE_MCP_AUDIENCE": plan.azure_mcp_audience,
        "ATHENA_WC013_REPLAY_TABLE_ENDPOINT": plan.replay.table_endpoint,
        "ATHENA_WC013_REPLAY_TABLE_NAME": plan.replay.table_name,
        "ATHENA_WC013_REPLAY_PARTITION_KEY": plan.replay.partition_key,
    }
    mismatches = [
        name
        for name, expected_value in expected.items()
        if os.getenv(name) != expected_value
    ]
    if mismatches:
        raise Wc013LiveAcceptanceError(
            "runtime environment does not match the reviewed plan: "
            + ", ".join(sorted(mismatches))
        )


def _compose_wc013_one_shot_service(
    prepared: PreparedWc013LiveAcceptance,
) -> DemoEvaluationService:
    plan = prepared.plan
    authority = prepared.authority
    clock = _SystemClock()
    key_resolver = KeyVaultTrustedKeyResolver(
        expected_record=prepared.trusted_key_record,
        managed_identity_client_id=plan.context_identity_client_id,
    )
    trusted_key_record = key_resolver(prepared.trusted_key_anchor)
    if trusted_key_record is None:
        raise Wc013LiveAcceptanceError(
            "the exact versioned Key Vault signing key could not be resolved"
        )
    store = InMemoryContextStore(
        authoritative_clock=clock,
        demo_evaluation_trusted_key=EvaluationTrustedKeyAuthority(
            record=trusted_key_record,
            revision=1,
        ),
    )
    with store.transaction() as transaction:
        state = cast(Any, transaction)
        state.put_published(authority.published_context.published)
        state.put_demo_evaluation_approval(
            authority.evaluation_approval,
            expected_revision=None,
        )
        state.replace_evaluation_grants(
            authority.evaluation_grants,
            expected_revision=0,
        )
    context_service = ContextService(
        store=store,
        authorization=RoleBasedAuthorization(authority.evaluation_grants),
        clock=clock,
        publication_actor=authority.published_context.published.published_by,
        demo_evaluation_trust=DemoEvaluationTrustConfiguration(
            trusted_key_anchor=prepared.trusted_key_anchor,
        ),
    )
    configuration_port = OperatorTrustedWc008ConfigurationPort(
        assertion=prepared.assertion,
        pinned_assertion_digest=prepared.assertion.assertion_digest,
        operator_approval=prepared.operator_approval,
    )
    verified_configuration = configuration_port.load_verified()
    transport = PrivateMcpEvidenceTransport(
        deployment_configuration=verified_configuration,
        invoker=ManagedIdentityPrivateMcpInvoker(
            deployment_configuration=verified_configuration,
            audience=plan.azure_mcp_audience,
        ),
    )
    evidence_client = Wc009EvidenceClientAdapter(
        transport=transport,
        signer=DefaultAzureCredentialTrustedIngestionSigner(
            trusted_key_anchor=prepared.trusted_key_anchor,
            signing_identity_client_id=plan.context_identity_client_id,
            evidence_identity_client_id=plan.evidence_identity_client_id,
        ),
        replay_guard=AzureTableAttemptReplayGuard(
            endpoint=plan.replay.table_endpoint,
            table_name=plan.replay.table_name,
            partition_key=plan.replay.partition_key,
            managed_identity_client_id=plan.context_identity_client_id,
        ),
        clock=clock,
        trust_configuration=prepared.collector_trust,
        key_resolver=key_resolver,
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    return DemoEvaluationService.from_dependencies(
        context_service=context_service,
        dependencies=DemoEvaluationDependencies(
            deployment_configuration=configuration_port,
            evidence_client=evidence_client,
            snapshot_signer=KeyVaultRsaSigner(
                trusted_key_anchor=prepared.trusted_key_anchor,
                managed_identity_client_id=plan.context_identity_client_id,
            ),
            clock=clock,
            context_reader_actor=authority.context_reader,
        ),
    )


def verify_wc013_live_result(
    prepared: PreparedWc013LiveAcceptance,
    result: DemoEvaluationResult,
) -> None:
    plan = prepared.plan
    command = plan.evaluation_command
    snapshot = result.snapshot
    publication = result.publication
    if (
        snapshot.snapshot_id != command.snapshot_id
        or publication.snapshot_id != command.snapshot_id
        or publication.approval_decision_id != command.approval_decision_id
        or publication.manifest_id != command.manifest_id
        or publication.manifest_version != command.manifest_version
        or publication.manifest_digest != command.expected_manifest_digest
        or publication.profile_id != command.profile_id
        or publication.resolved_profile_digest
        != command.expected_resolved_profile_digest
    ):
        raise Wc013LiveAcceptanceError(
            "live publication does not match the exact accepted command"
        )
    expected_endpoint_digest = compute_artifact_digest(
        {
            "privateMcpEndpoint": (
                prepared.assertion.azure_mcp_internal_endpoint
            )
        }
    )
    expected_scope_digest = compute_artifact_digest(
        command.authorized_scope.model_dump(mode="json", by_alias=True)
    )
    if (
        publication.endpoint_digest != expected_endpoint_digest
        or publication.authorized_scope_digest != expected_scope_digest
    ):
        raise Wc013LiveAcceptanceError(
            "live publication is not bound to the pinned endpoint and scope"
        )
    if len(snapshot.collector_attempts) != 1:
        raise Wc013LiveAcceptanceError(
            "live acceptance requires exactly one collector attempt"
        )
    attempt = snapshot.collector_attempts[0]
    if (
        attempt.attempt_type != "successResponse"
        or attempt.attempt_id != command.attempt_id
        or attempt.tool_name != AZURE_RESOURCE_INVENTORY_TOOL
        or attempt.tool_version != AZURE_RESOURCE_INVENTORY_VERSION
        or not snapshot.evidence_records
    ):
        raise Wc013LiveAcceptanceError(
            "live acceptance requires a real successful MCP response with evidence"
        )
    expected_scope = command.authorized_scope.canonical_json()
    if (
        [scope.canonical_json() for scope in snapshot.authorized_scopes]
        != [expected_scope]
        or not snapshot.collected_at <= result.evaluated_at < snapshot.expires_at
    ):
        raise Wc013LiveAcceptanceError(
            "live snapshot scope or freshness does not match the accepted command"
        )
    trust = prepared.collector_trust
    collector = snapshot.collector
    if (
        collector.collector_identity_evidence_ref
        != trust.collector_identity_evidence_ref
        or collector.mcp_host_id != trust.mcp_host_id
        or collector.tenant_id != trust.tenant_id
        or collector.trust_anchor_ref != trust.trust_anchor_ref
        or collector.ingestion_service_id != trust.ingestion_service_id
        or collector.ingestion_audience != trust.ingestion_audience
        or collector.tool_allowlist_digest != trust.tool_allowlist_digest
    ):
        raise Wc013LiveAcceptanceError(
            "snapshot collector metadata does not match configured trust"
        )
    identities = {
        identity.identity_evidence_id: identity
        for identity in snapshot.identity_evidence
    }
    if (
        set(identities) != {trust.collector_identity_evidence_ref}
        or attempt.collector_identity_evidence_ref
        != trust.collector_identity_evidence_ref
        or any(
            record.collector_identity_evidence_ref
            != trust.collector_identity_evidence_ref
            for record in snapshot.evidence_records
        )
    ):
        raise Wc013LiveAcceptanceError(
            "live evidence does not bind exactly one configured collector identity"
        )
    identity = identities[trust.collector_identity_evidence_ref]
    claims = identity.verified_claims
    if (
        claims.tenant_id != trust.tenant_id
        or claims.managed_identity_object_id
        != trust.managed_identity_object_id
        or claims.managed_identity_client_id
        != trust.managed_identity_client_id
    ):
        raise Wc013LiveAcceptanceError(
            "collector token claims do not match the pinned MCP identity"
        )

    key_record = prepared.trusted_key_record

    def resolve_key(anchor: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return key_record if anchor == prepared.trusted_key_anchor else None

    attestation = snapshot.snapshot_attestation
    if (
        attestation.key_vault_key_id
        != prepared.trusted_key_anchor.key_vault_key_id
        or not verify_snapshot_attestation_signature(
            attestation,
            key_resolver=resolve_key,
            trusted_key_anchor=prepared.trusted_key_anchor,
            as_of=result.evaluated_at,
        )
        or not identity.verify_signature(
            key_resolver=resolve_key,
            trusted_key_anchor=prepared.trusted_key_anchor,
            as_of=result.evaluated_at,
            attempt=attempt,
        )
    ):
        raise Wc013LiveAcceptanceError(
            "live EvidenceSnapshot cryptographic verification failed"
        )


def _write_immutable_snapshot(
    path: Path,
    result: DemoEvaluationResult,
) -> Path:
    payload = canonicalize_json(
        result.snapshot.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.write("\n")
        path.chmod(stat.S_IREAD)
    except OSError as exc:
        raise Wc013LiveAcceptanceError(
            "immutable snapshot output could not be created"
        ) from exc
    return path


__all__ = [
    "PreparedWc013LiveAcceptance",
    "RenderedWc013Configuration",
    "Wc013AuthorityApprovalInput",
    "Wc013AuthorityBundle",
    "Wc013AuthorityInput",
    "Wc013ConfigurationInput",
    "Wc013LiveAcceptanceError",
    "Wc013LiveAcceptancePlan",
    "Wc013LiveAcceptanceResult",
    "Wc013ReplayInput",
    "build_wc013_authority_bundle",
    "prepare_wc013_live_acceptance",
    "render_wc013_configuration",
    "run_wc013_live_acceptance",
    "verify_wc013_live_result",
    "wc013_configuration_template",
]
