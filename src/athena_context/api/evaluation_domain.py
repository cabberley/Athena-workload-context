from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, model_validator

from athena_context.api.domain import Actor, ActorKind, ApiModel
from athena_context.contracts import (
    EvidenceScope,
    EvidenceSnapshot,
    ManifestFinding,
    SnapshotPublicationRecord,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.evidence import EvidenceResponseBounds

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_AZURE_RESOURCE_ID_PATTERN = r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/.+$"
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


class McpReadAssignment(ApiModel):
    """One reviewed WC-008 read-only role assignment at an explicit evidence scope."""

    scope: EvidenceScope
    role: Literal["Reader", "Log Analytics Data Reader"]


class PrivateMcpEndpointConfiguration(ApiModel):
    """Trusted WC-008 outputs plus the identity-separation assertions used at runtime."""

    private_mcp_endpoint: str = Field(min_length=12, max_length=2048)
    endpoint_output_name: Literal["azureMcpInternalEndpoint"] = "azureMcpInternalEndpoint"
    network_access: Literal["internalContainerAppsEnvironment"] = (
        "internalContainerAppsEnvironment"
    )
    azure_mcp_version: Literal["2.0.5"] = "2.0.5"
    allowed_tools: tuple[str, ...] = AZURE_MCP_2_0_5_ALLOWED_TOOLS
    evidence_identity_resource_id: str = Field(pattern=_AZURE_RESOURCE_ID_PATTERN)
    context_identity_resource_id: str = Field(pattern=_AZURE_RESOURCE_ID_PATTERN)
    evidence_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    context_identity_object_id: str = Field(pattern=_GUID_PATTERN)
    evidence_read_assignments: tuple[McpReadAssignment, ...] = Field(
        min_length=1,
        max_length=100,
    )
    context_identity_azure_roles: tuple[str, ...] = ()
    evidence_identity_context_permissions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_private_read_only_boundary(self) -> PrivateMcpEndpointConfiguration:
        parsed = urlsplit(self.private_mcp_endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("private MCP endpoint must be an HTTPS origin without credentials")
        try:
            ip_address(parsed.hostname)
        except ValueError:
            hostname = parsed.hostname.casefold()
            if not (
                hostname.endswith(".internal")
                or hostname.endswith(".azurecontainerapps.io")
            ):
                raise ValueError(
                    "private MCP endpoint must be an internal or Container Apps deployment output"
                ) from None
        else:
            raise ValueError("private MCP endpoint must use a private deployment DNS name")
        if self.allowed_tools != AZURE_MCP_2_0_5_ALLOWED_TOOLS:
            raise ValueError("allowedTools must exactly match the reviewed WC-008 output")
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
        return self

    def authorizes_inventory_scope(self, scope: EvidenceScope) -> bool:
        expected = scope.canonical_json()
        return any(
            assignment.role == "Reader" and assignment.scope.canonical_json() == expected
            for assignment in self.evidence_read_assignments
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
    "AuthorizedSnapshotPublication",
    "DemoEvaluationApproval",
    "DemoEvaluationCommand",
    "DemoEvaluationResult",
    "McpReadAssignment",
    "PrivateMcpEndpointConfiguration",
    "build_authorized_publication",
    "build_demo_evaluation_result",
    "publication_digest_payload",
]
