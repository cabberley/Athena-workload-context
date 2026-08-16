from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from athena_context.contracts import (
    AttemptIdentifier,
    AzureGuid,
    CollectorAttempt,
    CollectorIdentityEvidence,
    EvidenceRecord,
    EvidenceReference,
    EvidenceScope,
    IdentityEvidenceIdentifier,
    IngestionAudience,
    IngestionServiceIdentifier,
    McpHostIdentifier,
    Sha256Digest,
    SnapshotIdentifier,
    VersionedKeyVaultKeyId,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.contracts.models import AthenaBaseModel

AZURE_RESOURCE_INVENTORY_TOOL: Final = "azure.resourceInventory.read"
AZURE_RESOURCE_INVENTORY_VERSION: Final = "1.0.0"
AZURE_MCP_RESPONSE_SCHEMA_VERSION: Final = "1.0.0"

REVIEWED_TOOL_ALLOWLIST: tuple[tuple[str, str], ...] = (
    (AZURE_RESOURCE_INVENTORY_TOOL, AZURE_RESOURCE_INVENTORY_VERSION),
)
REVIEWED_TOOL_ALLOWLIST_DIGEST = compute_artifact_digest(
    [
        {"toolName": tool_name, "toolVersion": tool_version}
        for tool_name, tool_version in REVIEWED_TOOL_ALLOWLIST
    ]
)

MAX_RESPONSE_BYTES = 1_048_576
MAX_RESPONSE_ITEMS = 500
MAX_RECORD_BYTES = 65_536
MAX_FRESHNESS_SECONDS = 3_600
MAX_TIMEOUT_MILLISECONDS = 120_000

type ToolName = Literal["azure.resourceInventory.read"]
type ToolVersion = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


class EvidenceResponseBounds(AthenaBaseModel):
    max_response_bytes: int = Field(
        ..., alias="maxResponseBytes", ge=1, le=MAX_RESPONSE_BYTES
    )
    max_items: int = Field(..., alias="maxItems", ge=1, le=MAX_RESPONSE_ITEMS)
    max_record_bytes: int = Field(
        ..., alias="maxRecordBytes", ge=1, le=MAX_RECORD_BYTES
    )
    freshness_seconds: int = Field(
        ..., alias="freshnessSeconds", ge=1, le=MAX_FRESHNESS_SECONDS
    )
    timeout_milliseconds: int = Field(
        ..., alias="timeoutMilliseconds", ge=1, le=MAX_TIMEOUT_MILLISECONDS
    )


class EvidenceCollectionCommand(AthenaBaseModel):
    attempt_id: AttemptIdentifier = Field(..., alias="attemptId")
    tool_name: ToolName = Field(
        default=AZURE_RESOURCE_INVENTORY_TOOL,
        alias="toolName",
    )
    tool_version: ToolVersion = Field(
        default=AZURE_RESOURCE_INVENTORY_VERSION,
        alias="toolVersion",
    )
    evidence_scope: EvidenceScope = Field(..., alias="evidenceScope")
    authorized_scopes: tuple[EvidenceScope, ...] = Field(
        ..., alias="authorizedScopes", min_length=1, max_length=100
    )
    bounds: EvidenceResponseBounds

    @model_validator(mode="after")
    def validate_unique_authorized_scopes(self) -> EvidenceCollectionCommand:
        canonical_scopes = [
            canonicalize_json(scope.model_dump(mode="json", by_alias=True))
            for scope in self.authorized_scopes
        ]
        if len(canonical_scopes) != len(set(canonical_scopes)):
            raise ValueError("authorizedScopes must not contain duplicates")
        return self


class CollectorTrustConfiguration(AthenaBaseModel):
    collector_identity_evidence_ref: IdentityEvidenceIdentifier = Field(
        ..., alias="collectorIdentityEvidenceRef"
    )
    mcp_host_id: McpHostIdentifier = Field(..., alias="mcpHostId")
    tenant_id: AzureGuid = Field(..., alias="tenantId")
    managed_identity_object_id: AzureGuid = Field(..., alias="managedIdentityObjectId")
    managed_identity_client_id: AzureGuid = Field(..., alias="managedIdentityClientId")
    context_identity_object_id: AzureGuid = Field(..., alias="contextIdentityObjectId")
    ingestion_service_id: IngestionServiceIdentifier = Field(
        ..., alias="ingestionServiceId"
    )
    ingestion_audience: IngestionAudience = Field(..., alias="ingestionAudience")
    trust_anchor_ref: VersionedKeyVaultKeyId = Field(..., alias="trustAnchorRef")
    tool_allowlist_digest: Sha256Digest = Field(
        default=REVIEWED_TOOL_ALLOWLIST_DIGEST,
        alias="toolAllowlistDigest",
    )
    schema_version: Literal["1.0.0"] = Field(default="1.0.0", alias="schemaVersion")
    semantic_contract_version: Literal["1.0.0"] = Field(
        default="1.0.0", alias="semanticContractVersion"
    )
    policy_contract_version: Literal["1.0.0"] = Field(
        default="1.0.0", alias="policyContractVersion"
    )

    @model_validator(mode="after")
    def validate_separated_identity(self) -> CollectorTrustConfiguration:
        if self.managed_identity_object_id == self.context_identity_object_id:
            raise ValueError(
                "Azure MCP collector identity must differ from the Athena context identity"
            )
        if self.tool_allowlist_digest != REVIEWED_TOOL_ALLOWLIST_DIGEST:
            raise ValueError("toolAllowlistDigest must match the exact reviewed tool allowlist")
        return self


class EvidenceTransportRequest(AthenaBaseModel):
    attempt_id: AttemptIdentifier = Field(..., alias="attemptId")
    attempt_started_at: datetime = Field(..., alias="attemptStartedAt")
    tool_name: ToolName = Field(..., alias="toolName")
    tool_version: ToolVersion = Field(..., alias="toolVersion")
    expected_record_type: Literal["resource"] = Field(
        default="resource", alias="expectedRecordType"
    )
    evidence_scope: EvidenceScope = Field(..., alias="evidenceScope")
    authorized_scopes: tuple[EvidenceScope, ...] = Field(
        ..., alias="authorizedScopes", min_length=1, max_length=100
    )
    bounds: EvidenceResponseBounds
    collector_identity_evidence_ref: IdentityEvidenceIdentifier = Field(
        ..., alias="collectorIdentityEvidenceRef"
    )
    request_digest: Sha256Digest = Field(..., alias="requestDigest")

    @model_validator(mode="after")
    def validate_request_digest(self) -> EvidenceTransportRequest:
        payload = self.model_dump(mode="json", by_alias=True)
        payload.pop("requestDigest")
        if self.request_digest != compute_artifact_digest(payload):
            raise ValueError("requestDigest mismatched the canonical bounded request")
        return self


class SnapshotReferenceBinding(AthenaBaseModel):
    snapshot_id: SnapshotIdentifier = Field(..., alias="snapshotId")
    snapshot_artifact_digest: Sha256Digest = Field(..., alias="snapshotArtifactDigest")
    snapshot_semantic_digest: Sha256Digest = Field(..., alias="snapshotSemanticDigest")


@dataclass(frozen=True, slots=True)
class McpSuccessResponse:
    body: bytes = field(repr=False)
    response_received_at: datetime


@dataclass(frozen=True, slots=True)
class McpFailedResponse:
    body: bytes = field(repr=False)
    response_received_at: datetime


@dataclass(frozen=True, slots=True)
class McpTimeoutNoResponse:
    deadline_at: datetime
    timed_out_at: datetime


@dataclass(frozen=True, slots=True)
class McpAuthorizationFailure:
    authorization_status: Literal[
        "denied", "expiredCredential", "scopeNotAllowed", "identityMismatch"
    ]
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class McpToolUnavailable:
    unavailable_reason: Literal[
        "notAllowlisted",
        "notHosted",
        "versionUnavailable",
        "networkUnavailable",
        "mcpUnavailable",
    ]
    observed_at: datetime


type McpTransportOutcome = (
    McpSuccessResponse
    | McpFailedResponse
    | McpTimeoutNoResponse
    | McpAuthorizationFailure
    | McpToolUnavailable
)


@dataclass(frozen=True, slots=True)
class ValidatedEnvelope:
    kind: Literal["response", "failure"]
    digest: Sha256Digest
    canonical_bytes: bytes = field(repr=False)

    def payload(self) -> dict[str, object]:
        value = json.loads(self.canonical_bytes)
        if not isinstance(value, dict):
            raise RuntimeError("validated envelope invariant violated")
        return value

    @classmethod
    def from_payload(
        cls,
        *,
        kind: Literal["response", "failure"],
        digest: Sha256Digest,
        payload: dict[str, object],
    ) -> ValidatedEnvelope:
        return cls(
            kind=kind,
            digest=digest,
            canonical_bytes=canonicalize_json(payload).encode("utf-8"),
        )


@dataclass(frozen=True, slots=True)
class EvidenceProjection:
    request: EvidenceTransportRequest
    collector_attempt: CollectorAttempt
    evidence_records: tuple[EvidenceRecord, ...]
    envelope: ValidatedEnvelope | None


@dataclass(frozen=True, slots=True)
class TrustedIngestionBinding:
    request: EvidenceTransportRequest
    collector_attempt: CollectorAttempt
    trust_configuration: CollectorTrustConfiguration
    as_of: datetime


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    request: EvidenceTransportRequest
    collector_attempt: CollectorAttempt
    evidence_records: tuple[EvidenceRecord, ...]
    collector_identity_evidence: CollectorIdentityEvidence
    envelope: ValidatedEnvelope | None

    def references(
        self, binding: SnapshotReferenceBinding
    ) -> tuple[EvidenceReference, ...]:
        from athena_context.evidence.validation import bind_evidence_references

        return bind_evidence_references(self, binding)


class EvidenceClientError(RuntimeError):
    """Base class for fail-closed evidence client errors."""


class EvidenceBoundaryError(EvidenceClientError):
    """The typed MCP boundary could not be represented safely."""


class ReplayDetectedError(EvidenceClientError):
    """An attempt identifier or request digest was reused."""


class TrustedIngestionError(EvidenceClientError):
    """Trusted ingestion returned invalid or mismatched collector evidence."""


__all__ = [
    "AZURE_MCP_RESPONSE_SCHEMA_VERSION",
    "AZURE_RESOURCE_INVENTORY_TOOL",
    "AZURE_RESOURCE_INVENTORY_VERSION",
    "CollectedEvidence",
    "CollectorTrustConfiguration",
    "EvidenceBoundaryError",
    "EvidenceClientError",
    "EvidenceCollectionCommand",
    "EvidenceProjection",
    "EvidenceResponseBounds",
    "EvidenceTransportRequest",
    "MAX_FRESHNESS_SECONDS",
    "MAX_RECORD_BYTES",
    "MAX_RESPONSE_BYTES",
    "MAX_RESPONSE_ITEMS",
    "MAX_TIMEOUT_MILLISECONDS",
    "McpAuthorizationFailure",
    "McpFailedResponse",
    "McpSuccessResponse",
    "McpTimeoutNoResponse",
    "McpToolUnavailable",
    "McpTransportOutcome",
    "REVIEWED_TOOL_ALLOWLIST",
    "REVIEWED_TOOL_ALLOWLIST_DIGEST",
    "ReplayDetectedError",
    "SnapshotReferenceBinding",
    "TrustedIngestionBinding",
    "TrustedIngestionError",
    "ValidatedEnvelope",
]
