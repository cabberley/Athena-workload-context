from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, model_validator

from athena_context.api.domain import (
    Actor,
    ActorKind,
    ApiModel,
    PublishedManifestView,
)
from athena_context.contracts import (
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    ResolvedManifestProfile,
    SnapshotPublicationRecord,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.evidence import EvidenceResponseBounds

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_AZURE_RESOURCE_ID_PATTERN = (
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/"
    r"providers/[A-Za-z0-9.]+/[A-Za-z0-9-]+/[^/]+$"
)
_GUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_PLACEHOLDER_DIGEST = "sha256:" + ("0" * 64)

AZURE_MCP_2_0_5_ALLOWED_TOOLS: tuple[str, ...] = (
    "group_resource_list",
    "monitor_activitylog_list",
    "monitor_metrics_definitions",
    "monitor_metrics_query",
    "monitor_resource_log_query",
    "monitor_workspace_log_query",
    "resourcehealth_availability-status_get",
)
AZURE_MCP_2_0_5_CATALOG_HASH: Literal[
    "sha256:032b52ae4214b9df410182292b2bf0a82f9a84eec7b64cc5c8c40f726c4d4a0c"
] = "sha256:032b52ae4214b9df410182292b2bf0a82f9a84eec7b64cc5c8c40f726c4d4a0c"
AZURE_MCP_2_0_5_IMAGE_DIGEST: Literal[
    "sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a"
] = "sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a"


class McpReadAssignment(ApiModel):
    """One reviewed WC-008 read-only role assignment at an explicit evidence scope."""

    scope: EvidenceScope
    role: Literal["Reader", "Log Analytics Data Reader"]


class Wc008DeploymentOutputAssertion(ApiModel):
    """Bounded WC-008 outputs/config before a separate operator trust decision."""

    azure_mcp_internal_endpoint: str = Field(min_length=12, max_length=2048)
    endpoint_output_name: Literal["azureMcpInternalEndpoint"] = "azureMcpInternalEndpoint"
    managed_environment_resource_id: str = Field(pattern=_AZURE_RESOURCE_ID_PATTERN)
    azure_mcp_container_app_resource_id: str = Field(
        pattern=_AZURE_RESOURCE_ID_PATTERN
    )
    evidence_identity_resource_id: str = Field(pattern=_AZURE_RESOURCE_ID_PATTERN)
    context_identity_resource_id: str = Field(pattern=_AZURE_RESOURCE_ID_PATTERN)
    internal_environment: Literal[True]
    public_network_access: Literal["Disabled"]
    external_ingress: Literal[False]
    allow_insecure: Literal[False]
    azure_mcp_version: Literal["2.0.5"] = "2.0.5"
    azure_mcp_image_digest: Literal[
        "sha256:2285f62dc1720ebf5da90498828b27e73d8fae6fd6fb89cab8cf67e3646fce3a"
    ] = AZURE_MCP_2_0_5_IMAGE_DIGEST
    allowed_tools: tuple[str, ...] = AZURE_MCP_2_0_5_ALLOWED_TOOLS
    tool_catalog_hash: Literal[
        "sha256:032b52ae4214b9df410182292b2bf0a82f9a84eec7b64cc5c8c40f726c4d4a0c"
    ] = AZURE_MCP_2_0_5_CATALOG_HASH
    evidence_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    context_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    evidence_read_assignments: tuple[McpReadAssignment, ...] = Field(
        min_length=1,
        max_length=100,
    )
    context_identity_azure_roles: tuple[str, ...] = ()
    evidence_identity_context_permissions: tuple[str, ...] = ()
    assertion_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_private_read_only_boundary(self) -> Wc008DeploymentOutputAssertion:
        parsed = urlsplit(self.azure_mcp_internal_endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("WC-008 MCP endpoint must be an HTTPS origin without credentials")
        if self.allowed_tools != AZURE_MCP_2_0_5_ALLOWED_TOOLS:
            raise ValueError("allowedTools must exactly match the reviewed WC-008 output")
        required_types = (
            (
                self.managed_environment_resource_id,
                "/providers/microsoft.app/managedenvironments/",
                "managed environment",
            ),
            (
                self.azure_mcp_container_app_resource_id,
                "/providers/microsoft.app/containerapps/",
                "MCP container app",
            ),
            (
                self.evidence_identity_resource_id,
                "/providers/microsoft.managedidentity/userassignedidentities/",
                "evidence identity",
            ),
            (
                self.context_identity_resource_id,
                "/providers/microsoft.managedidentity/userassignedidentities/",
                "context identity",
            ),
        )
        for resource_id, expected_segment, label in required_types:
            if expected_segment not in resource_id.casefold():
                raise ValueError(f"WC-008 {label} resource ID has the wrong resource type")
        hosting_scopes = {
            resource_id.casefold().split("/providers/", maxsplit=1)[0]
            for resource_id, _, _ in required_types
        }
        if len(hosting_scopes) != 1:
            raise ValueError("WC-008 deployment resource IDs must share one hosting resource group")
        if (
            self.evidence_identity_resource_id.casefold()
            == self.context_identity_resource_id.casefold()
            or self.evidence_identity_object_id.casefold()
            == self.context_identity_object_id.casefold()
        ):
            raise ValueError("context and evidence identities must remain separate")
        if self.context_identity_azure_roles:
            raise ValueError("Athena context identity must not receive Azure workload read roles")
        if self.evidence_identity_context_permissions:
            raise ValueError(
                "Azure MCP evidence identity must not receive context write permissions"
            )
        canonical_assignments = [
            canonicalize_json(item.model_dump(mode="json", by_alias=True))
            for item in self.evidence_read_assignments
        ]
        if len(canonical_assignments) != len(set(canonical_assignments)):
            raise ValueError("evidence read assignments must be unique")
        if self.assertion_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("WC-008 deployment assertion digest does not match its outputs")
        return self

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("assertion_digest")
        return payload

    def authorizes_inventory_scope(self, scope: EvidenceScope) -> bool:
        expected = scope.canonical_json()
        return any(
            assignment.role == "Reader" and assignment.scope.canonical_json() == expected
            for assignment in self.evidence_read_assignments
        )


class OperatorDeploymentApproval(ApiModel):
    """Separately pinned human trust decision for one exact WC-008 assertion digest."""

    approval_id: str = Field(pattern=_ID_PATTERN)
    status: Literal["trusted"]
    assertion_digest: str = Field(pattern=_DIGEST_PATTERN)
    approved_by: Actor
    approved_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def validate_operator(self) -> OperatorDeploymentApproval:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("WC-008 deployment assertion requires a human operator")
        return self


class VerifiedWc008DeploymentConfiguration(ApiModel):
    """Nominal result produced only by a trusted deployment configuration port."""

    assertion: Wc008DeploymentOutputAssertion
    operator_approval: OperatorDeploymentApproval

    @model_validator(mode="after")
    def validate_exact_trust_binding(self) -> VerifiedWc008DeploymentConfiguration:
        if (
            self.operator_approval.assertion_digest
            != self.assertion.assertion_digest
        ):
            raise ValueError(
                "operator trust decision does not bind the exact WC-008 assertion"
            )
        return self


class PublishedContextSelection(ApiModel):
    """Exact WC-007 context identity, or one manifest with a unique active version."""

    manifest_id: str = Field(min_length=1, max_length=128)
    manifest_version: str | None = Field(
        default=None,
        pattern=_VERSION_PATTERN,
    )
    profile_id: str = Field(min_length=1, max_length=128)


class ResolvedPublishedContext(ApiModel):
    """Published WC-007 record and its profile resolved at trusted application time."""

    view: PublishedManifestView
    profile: ResolvedManifestProfile

    @model_validator(mode="after")
    def validate_identity(self) -> ResolvedPublishedContext:
        published = self.view.published
        if (
            self.profile.manifest_id != published.manifest_id
            or self.profile.manifest_version != published.manifest_version
        ):
            raise ValueError(
                "resolved profile does not match the published manifest identity"
            )
        return self


def build_wc008_deployment_assertion(
    *,
    azure_mcp_internal_endpoint: str,
    managed_environment_resource_id: str,
    azure_mcp_container_app_resource_id: str,
    evidence_identity_resource_id: str,
    context_identity_resource_id: str,
    evidence_identity_object_id: str,
    context_identity_object_id: str,
    evidence_read_assignments: tuple[McpReadAssignment, ...],
    internal_environment: bool = True,
    public_network_access: str = "Disabled",
    external_ingress: bool = False,
    allow_insecure: bool = False,
    context_identity_azure_roles: tuple[str, ...] = (),
    evidence_identity_context_permissions: tuple[str, ...] = (),
) -> Wc008DeploymentOutputAssertion:
    payload: dict[str, object] = {
        "azure_mcp_internal_endpoint": azure_mcp_internal_endpoint,
        "managed_environment_resource_id": managed_environment_resource_id,
        "azure_mcp_container_app_resource_id": azure_mcp_container_app_resource_id,
        "evidence_identity_resource_id": evidence_identity_resource_id,
        "context_identity_resource_id": context_identity_resource_id,
        "internal_environment": internal_environment,
        "public_network_access": public_network_access,
        "external_ingress": external_ingress,
        "allow_insecure": allow_insecure,
        "azure_mcp_version": "2.0.5",
        "azure_mcp_image_digest": AZURE_MCP_2_0_5_IMAGE_DIGEST,
        "allowed_tools": AZURE_MCP_2_0_5_ALLOWED_TOOLS,
        "tool_catalog_hash": AZURE_MCP_2_0_5_CATALOG_HASH,
        "evidence_identity_object_id": evidence_identity_object_id,
        "context_identity_object_id": context_identity_object_id,
        "evidence_read_assignments": evidence_read_assignments,
        "context_identity_azure_roles": context_identity_azure_roles,
        "evidence_identity_context_permissions": (
            evidence_identity_context_permissions
        ),
    }
    unsigned = Wc008DeploymentOutputAssertion.model_construct(
        **cast(Any, payload),
        assertion_digest=_PLACEHOLDER_DIGEST,
    )
    return Wc008DeploymentOutputAssertion.model_validate(
        {
            **payload,
            "assertion_digest": compute_artifact_digest(
                unsigned._digest_payload()
            ),
        }
    )


class DemoEvaluationApproval(ApiModel):
    """Human decision loaded from a trusted approval registry, never from the request body."""

    decision_id: str = Field(pattern=_ID_PATTERN)
    status: Literal["authorized"]
    approved_by: Actor
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    manifest_id: str = Field(min_length=1, max_length=128)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_id: Literal["production", "development", "training"]
    authorized_scope: EvidenceScope
    private_mcp_endpoint: str = Field(min_length=12, max_length=2048)
    evidence_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def validate_human_decision(self) -> DemoEvaluationApproval:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("demo evaluation approval must be a human decision")
        if self.expires_at <= self.approved_at:
            raise ValueError("demo evaluation approval must expire after approval")
        return self


class DemoEvaluationCommand(ApiModel):
    approval_decision_id: str = Field(pattern=_ID_PATTERN)
    attempt_id: str = Field(pattern=r"^attempt-[a-f0-9]{12}$")
    snapshot_id: str = Field(pattern=r"^snap-[a-f0-9]{12}$")
    manifest_id: str = Field(min_length=1, max_length=128)
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    expected_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_id: Literal["production", "development", "training"]
    expected_resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorized_scope: EvidenceScope
    bounds: EvidenceResponseBounds
    reason: str = Field(min_length=3, max_length=500)


class AuthorizedSnapshotPublication(ApiModel):
    """Append-only publication record binding evidence to human and publisher authority."""

    snapshot_id: str
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    semantic_digest: str = Field(pattern=_DIGEST_PATTERN)
    schema_version: str = Field(pattern=_VERSION_PATTERN)
    semantic_contract_version: str = Field(pattern=_VERSION_PATTERN)
    published_at: AwareDatetime
    approval_decision_id: str = Field(pattern=_ID_PATTERN)
    approved_by: Actor
    approved_at: AwareDatetime
    publication_authorized_by: Actor
    publication_authorized_at: AwareDatetime
    published_by: Actor
    manifest_id: str
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_id: str
    resolved_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    endpoint_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorized_scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    reason: str = Field(min_length=3, max_length=500)
    publication_record_digest: str = Field(pattern=_DIGEST_PATTERN)

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude_none=True)
        payload.pop("publication_record_digest")
        return payload

    def canonical_json(self) -> str:
        return canonicalize_json(
            self.model_dump(mode="json", exclude_none=True)
        )

    @model_validator(mode="after")
    def validate_publication_digest(self) -> AuthorizedSnapshotPublication:
        if self.approved_by.kind is not ActorKind.HUMAN:
            raise ValueError("snapshot publication requires a human approval")
        if self.publication_authorized_by.kind is not ActorKind.HUMAN:
            raise ValueError("snapshot publication authorization requires a human publisher")
        if self.published_by.kind is not ActorKind.SERVICE:
            raise ValueError("only the authoritative Context API service may publish snapshots")
        if self.published_at != self.publication_authorized_at:
            raise ValueError("publication timestamps must be bound to the authorization event")
        if self.publication_record_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("publication record digest does not match its canonical payload")
        return self

    def registry_record(self) -> SnapshotPublicationRecord:
        return SnapshotPublicationRecord(
            snapshot_id=self.snapshot_id,
            artifact_digest=self.artifact_digest,
            semantic_digest=self.semantic_digest,
            schema_version=self.schema_version,
            semantic_contract_version=self.semantic_contract_version,
            published_at=self.published_at,
        )


class DemoEvaluationResult(ApiModel):
    publication: AuthorizedSnapshotPublication
    snapshot: EvidenceSnapshot
    findings: tuple[ManifestFinding, ...]
    evaluated_at: AwareDatetime
    citation_count: int = Field(ge=1)
    result_digest: str = Field(pattern=_DIGEST_PATTERN)

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("result_digest")
        return payload

    def canonical_json(self) -> str:
        return canonicalize_json(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        )

    @model_validator(mode="after")
    def validate_result(self) -> DemoEvaluationResult:
        if (
            self.snapshot.snapshot_id != self.publication.snapshot_id
            or self.snapshot.compatibility.artifact_digest
            != self.publication.artifact_digest
            or self.snapshot.compatibility.semantic_digest
            != self.publication.semantic_digest
        ):
            raise ValueError("evaluation result snapshot does not match publication")
        actual_citations = sum(len(finding.evidence_refs) for finding in self.findings)
        if self.citation_count != actual_citations:
            raise ValueError("citation_count must equal the exact finding references")
        if self.result_digest != compute_artifact_digest(self._digest_payload()):
            raise ValueError("result digest does not match its canonical payload")
        return self


def publication_digest_payload(
    *,
    snapshot: EvidenceSnapshot,
    approval: DemoEvaluationApproval,
    publisher: Actor,
    publication_actor: Actor,
    published_at: datetime,
    resolved_profile_digest: str,
    endpoint: str,
    scope: EvidenceScope,
    reason: str,
) -> dict[str, object]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "artifact_digest": snapshot.compatibility.artifact_digest,
        "semantic_digest": snapshot.compatibility.semantic_digest,
        "schema_version": snapshot.compatibility.schema_version,
        "semantic_contract_version": snapshot.compatibility.semantic_contract_version,
        "published_at": published_at,
        "approval_decision_id": approval.decision_id,
        "approved_by": approval.approved_by,
        "approved_at": approval.approved_at,
        "publication_authorized_by": publisher,
        "publication_authorized_at": published_at,
        "published_by": publication_actor,
        "manifest_id": approval.manifest_id,
        "manifest_version": approval.manifest_version,
        "manifest_digest": approval.manifest_digest,
        "profile_id": approval.profile_id,
        "resolved_profile_digest": resolved_profile_digest,
        "endpoint_digest": compute_artifact_digest({"privateMcpEndpoint": endpoint}),
        "authorized_scope_digest": compute_artifact_digest(
            scope.model_dump(mode="json", by_alias=True)
        ),
        "reason": reason,
    }


def build_authorized_publication(
    *,
    snapshot: EvidenceSnapshot,
    approval: DemoEvaluationApproval,
    publisher: Actor,
    publication_actor: Actor,
    published_at: datetime,
    resolved_profile_digest: str,
    endpoint: str,
    scope: EvidenceScope,
    reason: str,
) -> AuthorizedSnapshotPublication:
    payload = publication_digest_payload(
        snapshot=snapshot,
        approval=approval,
        publisher=publisher,
        publication_actor=publication_actor,
        published_at=published_at,
        resolved_profile_digest=resolved_profile_digest,
        endpoint=endpoint,
        scope=scope,
        reason=reason,
    )
    unsigned = AuthorizedSnapshotPublication.model_construct(
        **cast(Any, payload),
        publication_record_digest=_PLACEHOLDER_DIGEST,
    )
    return AuthorizedSnapshotPublication.model_validate(
        {
            **payload,
            "publication_record_digest": compute_artifact_digest(
                unsigned._digest_payload()
            ),
        }
    )


def build_demo_evaluation_result(
    *,
    publication: AuthorizedSnapshotPublication,
    snapshot: EvidenceSnapshot,
    findings: tuple[ManifestFinding, ...],
    evaluated_at: datetime,
) -> DemoEvaluationResult:
    citation_count = sum(len(finding.evidence_refs) for finding in findings)
    unsigned = DemoEvaluationResult.model_construct(
        publication=publication,
        snapshot=snapshot,
        findings=findings,
        evaluated_at=evaluated_at,
        citation_count=citation_count,
        result_digest=_PLACEHOLDER_DIGEST,
    )
    return DemoEvaluationResult.model_validate(
        {
            "publication": publication,
            "snapshot": snapshot,
            "findings": findings,
            "evaluated_at": evaluated_at,
            "citation_count": citation_count,
            "result_digest": compute_artifact_digest(unsigned._digest_payload()),
        }
    )


__all__ = [
    "AZURE_MCP_2_0_5_ALLOWED_TOOLS",
    "AZURE_MCP_2_0_5_CATALOG_HASH",
    "AZURE_MCP_2_0_5_IMAGE_DIGEST",
    "AuthorizedSnapshotPublication",
    "DemoEvaluationApproval",
    "DemoEvaluationCommand",
    "DemoEvaluationResult",
    "McpReadAssignment",
    "OperatorDeploymentApproval",
    "PublishedContextSelection",
    "ResolvedPublishedContext",
    "VerifiedWc008DeploymentConfiguration",
    "Wc008DeploymentOutputAssertion",
    "build_authorized_publication",
    "build_demo_evaluation_result",
    "build_wc008_deployment_assertion",
    "publication_digest_payload",
]
