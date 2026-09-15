from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol, cast
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import jwt
from azure.core.exceptions import AzureError
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import BearerTokenCredentialPolicy
from azure.core.pipeline.transport import (
    HttpRequest,
    HttpResponse,
    HttpTransport,
    RequestsTransport,
)
from azure.identity import ManagedIdentityCredential
from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts import (
    MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    ActivityLogMonitoringSignal,
    ApprovedChangeScope,
    CorrelationRequest,
    EvidenceCoverageScope,
    LogQueryMonitoringSignal,
    MonitoringAcquisitionExchange,
    MonitoringAcquisitionReceipt,
    MonitoringCollectorContract,
    MonitoringEvidenceAttestation,
    MonitoringIdentityProof,
    MonitoringObservation,
    PublishedMonitoringIntent,
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
    PublishedMonitoringIntentControl,
    PublishedRuntimeContextBinding,
    ResourceHealthMonitoringSignal,
    canonicalize_json,
    compute_artifact_digest,
    monitoring_acquisition_receipt_preimage,
    sha256_hex,
    validate_monitoring_intent_activation_eligible,
    validate_published_monitoring_intent_assets,
)
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.contracts.monitoring import (
    MonitoringEffectiveRbacInventory,
    MonitoringIncidentHealthSampleBinding,
)
from athena_context.contracts.monitoring import (
    MonitoringIncidentSelection as SignedMonitoringIncidentSelection,
)
from athena_context.monitoring_collection import (
    AmaHeartbeatRecord,
    CommittedMonitoringCollection,
    ConnectionMonitorRecord,
    MonitoringCollectionBatch,
    MonitoringCollectionCommitPort,
    MonitoringCollectionRecord,
    MonitoringCollectionTransaction,
    MonitoringCoverageRecord,
    NetworkRuleAttributionEvidence,
    NetworkWatcherFlowRecord,
    PreparedMonitoringCollection,
    ResourceChangeRecord,
    ResourceHealthRecord,
    VmConnectionHealthRecord,
    compute_monitoring_query_execution_digest,
)
from athena_context.monitoring_incident import (
    MonitoringIncidentSample,
    MonitoringIncidentSelectionError,
    monitoring_health_source_record_reference,
    select_monitoring_incident,
)

MAX_ACQUISITION_ROWS = 500
MAX_ACQUISITION_RESPONSE_BYTES = 256 * 1024
MAX_ACQUISITION_WINDOW_SECONDS = 86400
MAX_ACQUISITION_CALLS = 32
EVENT_LOOKBACK_SECONDS = 900
_MAX_IDENTITY_PROOF_TOKEN_BYTES = 32 * 1024
_MIN_IDENTITY_PROOF_TOKEN_REMAINING_SECONDS = 30
_AZURE_ARM_ENDPOINT = "https://management.azure.com"
_AZURE_ARM_SCOPE = "https://management.azure.com/.default"
_AZURE_LOGS_ENDPOINT = "https://api.loganalytics.io"
_AZURE_LOGS_SCOPE = "https://api.loganalytics.io/.default"
_LOG_ANALYTICS_API_VERSION = "v1"
_ACTIVITY_LOG_API_VERSION = "2015-04-01"
_RESOURCE_GRAPH_API_VERSION = "2022-10-01"
_RESOURCE_HEALTH_API_VERSION = "2025-05-01"
_NETWORK_API_VERSION = "2025-09-01"
_MAX_ARM_POLL_SECONDS = 75
_MAX_ARM_POLL_ATTEMPTS = 16
_COMPACT_JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_READER_IDENTITY_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/"
    r"providers/microsoft\.managedidentity/userassignedidentities/[a-z0-9-_]{1,128}$"
)
_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()-]{1,90}/providers/"
    r"[a-z0-9.]+/[a-z0-9._()-]+/[a-z0-9._()-]+"
    r"(?:/[a-z0-9._()-]+/[a-z0-9._()-]+)*$"
)
_GUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_LOG_COLUMNS: dict[str, tuple[str, ...]] = {
    "Heartbeat": (
        "resourceId",
        "observedStart",
        "observedEnd",
        "heartbeatCount",
    ),
    "VMConnection": (
        "sourceAddress",
        "destinationAddress",
        "subjectResourceCandidates",
        "backendResourceCandidates",
        "pathId",
        "observedStart",
        "observedEnd",
        "failedConnectionCount",
    ),
    "NWConnectionMonitorTestResult": (
        "subjectResourceId",
        "pathId",
        "monitorResourceId",
        "sourceResourceId",
        "destinationResourceId",
        "sourceAddress",
        "destinationAddress",
        "direction",
        "protocol",
        "sourcePort",
        "destinationPort",
        "status",
        "testConfigurationReference",
        "testConfigurationDigest",
        "observedStart",
        "observedEnd",
    ),
    "NTANetAnalytics": (
        "subjectResourceCandidates",
        "pathId",
        "decision",
        "direction",
        "protocol",
        "sourceResourceCandidates",
        "destinationResourceCandidates",
        "sourceAddress",
        "destinationAddress",
        "sourcePort",
        "destinationPort",
        "enforcementResourceId",
        "ruleResourceId",
        "observedStart",
        "observedEnd",
    ),
}
_ACTIVITY_COLUMNS = (
    "category",
    "operationName",
    "resultType",
    "level",
    "targetResourceId",
    "correlationId",
    "occurredAt",
)
_RESOURCE_GRAPH_COLUMNS = (
    "targetResourceId",
    "correlationId",
    "occurredAt",
    "operationName",
    "resultType",
    "change",
)
_RESOURCE_HEALTH_COLUMNS = (
    "resourceId",
    "eventStatus",
    "currentStatus",
    "previousStatus",
    "reasonType",
    "observedStart",
    "observedEnd",
)
type AcquisitionSource = Literal[
    "activityLog",
    "ipFlowVerify",
    "logAnalytics",
    "resourceGraph",
    "resourceHealth",
]


class MonitoringAcquisitionError(RuntimeError):
    """Raised when evidence cannot be acquired without weakening the reviewed boundary."""


class _StrictAcquisitionModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


class MonitoringAcquisitionControlBinding(_StrictAcquisitionModel):
    """Authority-reviewed one-to-one binding from a control to required coverage."""

    control_id: str = Field(
        alias="controlId",
        pattern=r"^monitoring-control-[a-f0-9]{32}$",
    )
    control_digest: Sha256Digest = Field(alias="controlDigest")
    scope_digest: Sha256Digest = Field(alias="scopeDigest")
    coverage_scope: EvidenceCoverageScope = Field(alias="coverageScope")

    @model_validator(mode="after")
    def validate_binding(self) -> MonitoringAcquisitionControlBinding:
        if self.coverage_scope.query_scope_digest != self.control_digest:
            raise ValueError("control binding coverage does not bind the control digest")
        return self

    @property
    def coverage_scope_digest(self) -> Sha256Digest:
        return self.coverage_scope.scope_digest


class MonitoringAcquisitionAuthority(_StrictAcquisitionModel):
    """Digest-pinned authorization for the read-only monitoring acquisition boundary."""

    schema_version: Literal[
        "athena.wc028MonitoringAcquisitionAuthority.v1",
        "athena.wc028MonitoringAcquisitionAuthority.v2",
        "athena.wc028MonitoringAcquisitionAuthority.v3",
        "athena.wc028MonitoringAcquisitionAuthority.v4",
        "athena.wc028MonitoringAcquisitionAuthority.v5",
    ] = Field(alias="schemaVersion")
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^monitoring-acquisition-authority-[a-f0-9]{32}$",
    )
    monitoring_reader_identity_id: str = Field(alias="monitoringReaderIdentityId")
    monitoring_reader_principal_id: str | None = Field(
        default=None, alias="monitoringReaderPrincipalId"
    )
    monitoring_reader_client_id: str | None = Field(
        default=None,
        alias="monitoringReaderClientId",
    )
    monitoring_reader_tenant_id: str | None = Field(
        default=None,
        alias="monitoringReaderTenantId",
    )
    athena_context_identity_id: str = Field(alias="athenaContextIdentityId")
    athena_context_principal_id: str | None = Field(default=None, alias="athenaContextPrincipalId")
    collector_contract_digest: Sha256Digest = Field(alias="collectorContractDigest")
    allowed_sources: tuple[AcquisitionSource, ...] = Field(
        alias="allowedSources",
        min_length=1,
        max_length=5,
    )
    allowed_resource_ids: tuple[str, ...] = Field(
        alias="allowedResourceIds",
        min_length=1,
        max_length=256,
    )
    required_control_ids: tuple[str, ...] | None = Field(
        default=None,
        alias="requiredControlIds",
        min_length=1,
        max_length=128,
    )
    required_control_bindings: tuple[MonitoringAcquisitionControlBinding, ...] | None = Field(
        default=None,
        alias="requiredControlBindings",
        min_length=1,
        max_length=100,
    )
    context_binding_digest: Sha256Digest | None = Field(
        default=None,
        alias="contextBindingDigest",
    )
    required_coverage_scope_digests: tuple[Sha256Digest, ...] | None = Field(
        default=None,
        alias="requiredCoverageScopeDigests",
        min_length=1,
        max_length=100,
    )
    control_selection_digest: Sha256Digest | None = Field(
        default=None,
        alias="controlSelectionDigest",
    )
    identity_proof_audience: str | None = Field(
        default=None,
        alias="identityProofAudience",
        pattern=r"^api://[a-z0-9][a-z0-9.-]{2,127}$",
    )
    identity_proof_token_version: Literal["1.0"] | None = Field(
        default=None,
        alias="identityProofTokenVersion",
    )
    identity_proof_required_role: Literal["Athena.MonitoringAcquisition.ProveIdentity"] | None = (
        Field(
            default=None,
            alias="identityProofRequiredRole",
        )
    )
    identity_proof_maximum_lifetime_seconds: Literal[7200] | None = Field(
        default=None,
        alias="identityProofMaximumLifetimeSeconds",
    )
    max_rows: Literal[500] = Field(alias="maxRows")
    max_bytes: Literal[262144] = Field(alias="maxBytes")
    max_window_seconds: Literal[86400] = Field(alias="maxWindowSeconds")
    max_freshness_seconds: int = Field(
        alias="maxFreshnessSeconds",
        ge=60,
        le=3600,
    )
    max_acquisition_calls: int | None = Field(
        default=None,
        alias="maxAcquisitionCalls",
        ge=1,
        le=32,
    )
    receipt_signing_key_id: str | None = Field(
        default=None,
        alias="receiptSigningKeyId",
        pattern=(
            r"^https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/"
            r"[A-Za-z0-9-]{1,127}/[A-Fa-f0-9]{32}$"
        ),
    )
    monitoring_reader_has_read_only_workload_access: Literal[True] | None = Field(
        default=None, alias="monitoringReaderHasReadOnlyWorkloadAccess"
    )
    read_only: Literal[True] | None = Field(default=None, alias="readOnly")
    athena_context_has_workload_reader: Literal[False] | None = Field(
        default=None,
        alias="athenaContextHasWorkloadReader",
    )
    effective_rbac_inventory_digest: Sha256Digest | None = Field(
        default=None,
        alias="effectiveRbacInventoryDigest",
    )
    effective_rbac_source_manifest_digest: Sha256Digest | None = Field(
        default=None,
        alias="effectiveRbacSourceManifestDigest",
    )
    deployment_identity_contract_digest: Sha256Digest | None = Field(
        default=None, alias="deploymentIdentityContractDigest"
    )
    authority_digest: Sha256Digest = Field(alias="authorityDigest")

    @field_validator("monitoring_reader_identity_id", "athena_context_identity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _canonical_identity_id(value)

    @field_validator(
        "monitoring_reader_principal_id",
        "monitoring_reader_client_id",
        "monitoring_reader_tenant_id",
        "athena_context_principal_id",
    )
    @classmethod
    def validate_principal(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.casefold()
        if _GUID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("managed identity principal ID is invalid")
        return normalized

    @field_validator("allowed_sources")
    @classmethod
    def validate_sources(
        cls,
        values: tuple[AcquisitionSource, ...],
    ) -> tuple[AcquisitionSource, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("acquisition sources must be sorted and unique")
        return values

    @field_validator("required_coverage_scope_digests")
    @classmethod
    def validate_coverage_scope_digests(
        cls,
        values: tuple[Sha256Digest, ...] | None,
    ) -> tuple[Sha256Digest, ...] | None:
        if values is None:
            return None
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("required coverage scope digests must be sorted and unique")
        return values

    @field_validator("allowed_resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("acquisition resource IDs must be unique")
        return normalized

    @field_validator("required_control_ids")
    @classmethod
    def validate_control_ids(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if values is None:
            return None
        if (
            values != tuple(sorted(values))
            or len(values) != len(set(values))
            or any(
                re.fullmatch(r"monitoring-control-[a-f0-9]{32}", value) is None for value in values
            )
        ):
            raise ValueError("required control IDs must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_authority(self) -> MonitoringAcquisitionAuthority:
        if self.monitoring_reader_identity_id == self.athena_context_identity_id:
            raise ValueError(
                "monitoring acquisition identity must be separate from the Athena context identity"
            )
        common_receipt_fields = (
            self.max_acquisition_calls,
            self.receipt_signing_key_id,
            self.deployment_identity_contract_digest,
            self.monitoring_reader_principal_id,
            self.athena_context_principal_id,
            self.required_control_ids,
        )
        legacy_assertion_fields = (
            self.monitoring_reader_has_read_only_workload_access,
            self.read_only,
            self.athena_context_has_workload_reader,
        )
        credential_and_scope_fields = (
            self.monitoring_reader_client_id,
            self.monitoring_reader_tenant_id,
            self.context_binding_digest,
            self.required_coverage_scope_digests,
            self.required_control_bindings,
            self.control_selection_digest,
        )
        identity_proof_fields = (
            self.identity_proof_audience,
            self.identity_proof_token_version,
            self.identity_proof_required_role,
            self.identity_proof_maximum_lifetime_seconds,
        )
        effective_rbac_fields = (
            self.effective_rbac_inventory_digest,
            self.effective_rbac_source_manifest_digest,
        )
        if self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v1":
            if any(
                item is not None
                for item in (
                    *common_receipt_fields,
                    *credential_and_scope_fields,
                    *identity_proof_fields,
                    *effective_rbac_fields,
                )
            ) or legacy_assertion_fields != (None, True, False):
                raise ValueError("v1 acquisition authority cannot contain receipt policy")
        elif self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v2":
            if any(
                item is None for item in (*common_receipt_fields, *legacy_assertion_fields)
            ) or any(
                item is not None
                for item in (
                    *credential_and_scope_fields,
                    *identity_proof_fields,
                    *effective_rbac_fields,
                )
            ):
                raise ValueError("v2 acquisition authority requires only legacy receipt policy")
        elif self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v3":
            if any(
                item is None
                for item in (
                    *common_receipt_fields,
                    *legacy_assertion_fields,
                    *credential_and_scope_fields,
                )
            ) or any(item is not None for item in (*identity_proof_fields, *effective_rbac_fields)):
                raise ValueError(
                    "v3 acquisition authority requires legacy credential and runtime-scope policy"
                )
        elif self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v4":
            if any(
                item is None
                for item in (
                    *common_receipt_fields,
                    *legacy_assertion_fields,
                    *credential_and_scope_fields,
                    *identity_proof_fields,
                )
            ) or any(item is not None for item in effective_rbac_fields):
                raise ValueError("v4 acquisition authority requires legacy identity assertions")
        elif any(
            item is None
            for item in (
                *common_receipt_fields,
                *credential_and_scope_fields,
                *identity_proof_fields,
                *effective_rbac_fields,
            )
        ) or any(item is not None for item in legacy_assertion_fields):
            raise ValueError("v5 acquisition authority requires measured effective RBAC evidence")
        if self.schema_version in {
            "athena.wc028MonitoringAcquisitionAuthority.v3",
            "athena.wc028MonitoringAcquisitionAuthority.v4",
            "athena.wc028MonitoringAcquisitionAuthority.v5",
        }:
            required_control_ids = cast(tuple[str, ...], self.required_control_ids)
            required_coverage = cast(
                tuple[Sha256Digest, ...],
                self.required_coverage_scope_digests,
            )
            bindings = cast(
                tuple[MonitoringAcquisitionControlBinding, ...],
                self.required_control_bindings,
            )
            binding_control_ids = tuple(item.control_id for item in bindings)
            binding_coverage = tuple(sorted(item.coverage_scope_digest for item in bindings))
            if (
                bindings != tuple(sorted(bindings, key=lambda item: item.control_id))
                or binding_control_ids != required_control_ids
                or binding_coverage != required_coverage
                or len(binding_coverage) != len(set(binding_coverage))
            ):
                raise ValueError(
                    "required control bindings must exactly cover runtime coverage scopes"
                )
            expected_selection_digest = compute_artifact_digest(
                {
                    "contextBindingDigest": self.context_binding_digest,
                    "requiredCoverageScopeDigests": list(required_coverage),
                    "requiredControlBindings": [
                        item.model_dump(
                            mode="json",
                            by_alias=True,
                            exclude_none=True,
                        )
                        for item in bindings
                    ],
                }
            )
            if self.control_selection_digest != expected_selection_digest:
                raise ValueError(
                    "controlSelectionDigest does not bind required controls and coverage"
                )
        if self.schema_version in {
            "athena.wc028MonitoringAcquisitionAuthority.v4",
            "athena.wc028MonitoringAcquisitionAuthority.v5",
        } and (
            self.identity_proof_audience != MONITORING_IDENTITY_PROOF_AUDIENCE
            or self.identity_proof_token_version != MONITORING_IDENTITY_PROOF_TOKEN_VERSION
            or self.identity_proof_required_role != MONITORING_IDENTITY_PROOF_REQUIRED_ROLE
            or self.identity_proof_maximum_lifetime_seconds
            != MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ):
            raise ValueError("authority does not bind the exact Athena identity proof policy")
        if self.schema_version != "athena.wc028MonitoringAcquisitionAuthority.v1":
            deployment_payload: dict[str, object] = {
                "monitoringReaderIdentityId": self.monitoring_reader_identity_id,
                "monitoringReaderPrincipalId": self.monitoring_reader_principal_id,
                "athenaContextIdentityId": self.athena_context_identity_id,
                "athenaContextPrincipalId": self.athena_context_principal_id,
            }
            if self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v5":
                deployment_payload.update(
                    {
                        "monitoringReaderClientId": self.monitoring_reader_client_id,
                        "monitoringReaderTenantId": self.monitoring_reader_tenant_id,
                        "effectiveRbacInventoryDigest": (self.effective_rbac_inventory_digest),
                        "effectiveRbacSourceManifestDigest": (
                            self.effective_rbac_source_manifest_digest
                        ),
                    }
                )
            else:
                deployment_payload.update(
                    {
                        "monitoringReaderHasReadOnlyWorkloadAccess": (
                            self.monitoring_reader_has_read_only_workload_access
                        ),
                        "athenaContextHasWorkloadReader": (self.athena_context_has_workload_reader),
                        "readOnly": self.read_only,
                    }
                )
                if self.schema_version in {
                    "athena.wc028MonitoringAcquisitionAuthority.v3",
                    "athena.wc028MonitoringAcquisitionAuthority.v4",
                }:
                    deployment_payload.update(
                        {
                            "monitoringReaderClientId": self.monitoring_reader_client_id,
                            "monitoringReaderTenantId": self.monitoring_reader_tenant_id,
                        }
                    )
            deployment_digest = compute_artifact_digest(deployment_payload)
            if (
                self.monitoring_reader_principal_id == self.athena_context_principal_id
                or self.deployment_identity_contract_digest != deployment_digest
            ):
                raise ValueError(
                    "deploymentIdentityContractDigest does not bind identity separation"
                )
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"authority_id", "authority_digest"},
                exclude_none=True,
            )
        )
        if self.authority_digest != expected:
            raise ValueError("authorityDigest does not bind the acquisition authority")
        if self.authority_id != (
            f"monitoring-acquisition-authority-{expected.removeprefix('sha256:')[:32]}"
        ):
            raise ValueError("authorityId is not digest-bound")
        return self


def _canonical_resource_id(value: str) -> str:
    normalized = value.casefold().rstrip("/")
    if _RESOURCE_ID_PATTERN.fullmatch(normalized) is None or len(normalized) > 2048:
        raise ValueError("Azure resource ID is invalid")
    return normalized


def _canonical_identity_id(value: str) -> str:
    normalized = value.casefold().rstrip("/")
    if _READER_IDENTITY_PATTERN.fullmatch(normalized) is None:
        raise ValueError("monitoring reader identity ID is invalid")
    return normalized


def _is_virtual_machine_resource_id(value: str) -> bool:
    segments = _canonical_resource_id(value).split("/")
    return (
        len(segments) == 9
        and segments[5] == "providers"
        and segments[6] == "microsoft.compute"
        and segments[7] == "virtualmachines"
    )


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("network address is invalid") from exc


def _trusted_runtime_time(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value) or value.microsecond % 1000:
        raise MonitoringAcquisitionError(
            "collector runtime time must use UTC with millisecond precision"
        )
    return value


def _traffic_row_five_tuple_digest(row: TrafficAnalyticsRow) -> str:
    if len(row.source_resource_candidates) != 1 or len(row.destination_resource_candidates) != 1:
        raise MonitoringAcquisitionError(
            "Traffic Analytics five-tuple requires unambiguous endpoint resources"
        )
    return compute_artifact_digest(
        {
            "direction": row.direction,
            "protocol": row.protocol,
            "sourceResourceId": row.source_resource_candidates[0],
            "destinationResourceId": row.destination_resource_candidates[0],
            "sourceAddress": row.source_address,
            "destinationAddress": row.destination_address,
            "sourcePort": row.source_port,
            "destinationPort": row.destination_port,
        }
    )


def _json_value(value: object) -> object:
    if isinstance(value, AthenaBaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def compute_monitoring_acquisition_control_selection_digest(
    context_binding: PublishedRuntimeContextBinding,
    bindings: tuple[MonitoringAcquisitionControlBinding, ...],
) -> str:
    """Bind the current context, required coverage, and exact selected controls."""

    if type(context_binding) is not PublishedRuntimeContextBinding:
        raise TypeError("control selection requires an exact published runtime context binding")
    if (
        not bindings
        or bindings != tuple(sorted(bindings, key=lambda item: item.control_id))
        or len({item.control_id for item in bindings}) != len(bindings)
        or tuple(sorted(item.coverage_scope_digest for item in bindings))
        != context_binding.required_coverage_scope_digests
    ):
        raise ValueError("control bindings must be sorted, unique, and exactly cover runtime scope")
    return compute_artifact_digest(
        {
            "contextBindingDigest": context_binding.binding_digest,
            "requiredCoverageScopeDigests": list(context_binding.required_coverage_scope_digests),
            "requiredControlBindings": [
                item.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
                for item in bindings
            ],
        }
    )


def _request_digest(model: _StrictAcquisitionModel) -> str:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_digest"},
            exclude_none=True,
        )
    )


class _AcquisitionRequest(_StrictAcquisitionModel):
    source: AcquisitionSource
    request_digest: Sha256Digest = Field(alias="requestDigest")
    monitoring_reader_identity_id: str = Field(alias="monitoringReaderIdentityId")
    acquisition_authority_id: str = Field(
        alias="acquisitionAuthorityId",
        pattern=r"^monitoring-acquisition-authority-[a-f0-9]{32}$",
    )
    acquisition_authority_digest: Sha256Digest = Field(alias="acquisitionAuthorityDigest")
    collector_contract_digest: Sha256Digest = Field(alias="collectorContractDigest")
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^monitoring-intent-[a-f0-9]{32}$",
    )
    intent_digest: Sha256Digest = Field(alias="intentDigest")
    control_id: str = Field(
        alias="controlId",
        pattern=r"^monitoring-control-[a-f0-9]{32}$",
    )
    control_digest: Sha256Digest = Field(alias="controlDigest")
    scope_digest: Sha256Digest = Field(alias="scopeDigest")
    window_start: UtcDateTime = Field(alias="windowStart")
    window_end: UtcDateTime = Field(alias="windowEnd")
    max_rows: Literal[500] = Field(alias="maxRows")
    max_bytes: Literal[262144] = Field(alias="maxBytes")

    @field_validator("monitoring_reader_identity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _canonical_identity_id(value)

    @model_validator(mode="after")
    def validate_request(self) -> _AcquisitionRequest:
        seconds = (self.window_end - self.window_start).total_seconds()
        if seconds <= 0 or seconds > MAX_ACQUISITION_WINDOW_SECONDS:
            raise ValueError("acquisition window is outside its bound")
        if self.request_digest != _request_digest(self):
            raise ValueError("requestDigest does not bind the exact acquisition request")
        return self


class LogAnalyticsQueryRequest(_AcquisitionRequest):
    schema_version: Literal[
        "athena.wc028LogAnalyticsQueryRequest.v1",
        "athena.wc028LogAnalyticsQueryRequest.v2",
    ] = Field(alias="schemaVersion")
    source: Literal["logAnalytics"]
    table: Literal[
        "Heartbeat",
        "VMConnection",
        "NWConnectionMonitorTestResult",
        "NTANetAnalytics",
    ]
    query: str = Field(min_length=1, max_length=8192)
    query_digest: Sha256Digest = Field(alias="queryDigest")
    query_target_resource_id: str = Field(
        alias="queryTargetResourceId",
        min_length=1,
        max_length=2048,
    )
    expected_columns: tuple[str, ...] = Field(alias="expectedColumns")
    collector_execution_time: UtcDateTime | None = Field(
        default=None,
        alias="collectorExecutionTime",
    )
    coverage_scope: EvidenceCoverageScope | None = Field(
        default=None,
        alias="coverageScope",
    )

    @field_validator("query_target_resource_id")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @model_validator(mode="after")
    def validate_query_request(self) -> LogAnalyticsQueryRequest:
        if self.expected_columns != _LOG_COLUMNS[self.table]:
            raise ValueError("log query expected columns do not match the reviewed source schema")
        if self.query_digest != sha256_hex(self.query.encode("utf-8")):
            raise ValueError("queryDigest does not bind the exact reviewed query")
        if self.schema_version == "athena.wc028LogAnalyticsQueryRequest.v1":
            if self.collector_execution_time is not None or self.coverage_scope is not None:
                raise ValueError("legacy log query request cannot contain execution scope")
        elif (
            self.collector_execution_time is None
            or self.coverage_scope is None
            or self.window_end > self.collector_execution_time
            or self.coverage_scope.query_scope_digest != self.control_digest
        ):
            raise ValueError(
                "production log query request requires exact execution time and coverage scope"
            )
        return self


class ActivityLogQueryRequest(_AcquisitionRequest):
    schema_version: Literal["athena.wc028ActivityLogQueryRequest.v1"] = Field(alias="schemaVersion")
    source: Literal["activityLog"]
    resource_ids: tuple[str, ...] = Field(alias="resourceIds", min_length=1, max_length=128)
    categories: tuple[str, ...] = Field(min_length=1, max_length=16)
    operation_names: tuple[str, ...] = Field(
        alias="operationNames",
        min_length=1,
        max_length=64,
    )
    result_types: tuple[str, ...] = Field(alias="resultTypes", min_length=1, max_length=16)
    levels: tuple[str, ...] = Field(min_length=1, max_length=5)
    expected_columns: tuple[str, ...] = Field(alias="expectedColumns")

    @field_validator("resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("activity-log resource IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_columns(self) -> ActivityLogQueryRequest:
        if self.expected_columns != _ACTIVITY_COLUMNS:
            raise ValueError("Activity Log columns do not match the reviewed source schema")
        return self


class ResourceGraphChangeQueryRequest(_AcquisitionRequest):
    schema_version: Literal["athena.wc028ResourceGraphChangeQueryRequest.v1"] = Field(
        alias="schemaVersion"
    )
    source: Literal["resourceGraph"]
    resource_ids: tuple[str, ...] = Field(alias="resourceIds", min_length=1, max_length=128)
    expected_columns: tuple[str, ...] = Field(alias="expectedColumns")

    @field_validator("resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("Resource Graph resource IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_columns(self) -> ResourceGraphChangeQueryRequest:
        if self.expected_columns != _RESOURCE_GRAPH_COLUMNS:
            raise ValueError("Resource Graph columns do not match the reviewed source schema")
        return self


class ResourceHealthQueryRequest(_AcquisitionRequest):
    schema_version: Literal["athena.wc028ResourceHealthQueryRequest.v1"] = Field(
        alias="schemaVersion"
    )
    source: Literal["resourceHealth"]
    resource_ids: tuple[str, ...] = Field(alias="resourceIds", min_length=1, max_length=128)
    event_statuses: tuple[str, ...] = Field(alias="eventStatuses", min_length=1, max_length=4)
    current_statuses: tuple[str, ...] = Field(
        alias="currentStatuses",
        min_length=1,
        max_length=4,
    )
    previous_statuses: tuple[str, ...] = Field(
        alias="previousStatuses",
        min_length=1,
        max_length=4,
    )
    reason_types: tuple[str, ...] = Field(alias="reasonTypes", min_length=1, max_length=3)
    expected_columns: tuple[str, ...] = Field(alias="expectedColumns")

    @field_validator("resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("Resource Health resource IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_columns(self) -> ResourceHealthQueryRequest:
        if self.expected_columns != _RESOURCE_HEALTH_COLUMNS:
            raise ValueError("Resource Health columns do not match the reviewed source schema")
        return self


class IpFlowVerifyRequest(_AcquisitionRequest):
    schema_version: Literal["athena.wc028IpFlowVerifyRequest.v1"] = Field(alias="schemaVersion")
    source: Literal["ipFlowVerify"]
    checked_at: UtcDateTime = Field(alias="checkedAt")
    target_resource_id: str = Field(alias="targetResourceId")
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_address: str = Field(alias="sourceAddress")
    destination_address: str = Field(alias="destinationAddress")
    source_port: int | None = Field(alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(alias="destinationPort", ge=0, le=65535)

    @field_validator("target_resource_id")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @field_validator("source_address", "destination_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return _canonical_ip(value)

    @model_validator(mode="after")
    def validate_check_time(self) -> IpFlowVerifyRequest:
        if self.checked_at != self.window_end:
            raise ValueError("IP Flow Verify check must bind the requested collection time")
        return self


class _WindowedRow(_StrictAcquisitionModel):
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")

    @model_validator(mode="after")
    def validate_interval(self) -> _WindowedRow:
        if self.observed_start > self.observed_end:
            raise ValueError("source row interval is invalid")
        return self


class HeartbeatRow(_WindowedRow):
    row_kind: Literal["heartbeat"] = Field(alias="rowKind")
    resource_id: str = Field(alias="resourceId")
    heartbeat_count: int | None = Field(alias="heartbeatCount", ge=0)

    @field_validator("resource_id")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)


class VmConnectionRow(_WindowedRow):
    row_kind: Literal["vmConnection"] = Field(alias="rowKind")
    source_address: str = Field(alias="sourceAddress")
    destination_address: str = Field(alias="destinationAddress")
    subject_resource_candidates: tuple[str, ...] = Field(
        alias="subjectResourceCandidates",
        min_length=1,
        max_length=16,
    )
    backend_resource_candidates: tuple[str, ...] = Field(
        alias="backendResourceCandidates",
        min_length=1,
        max_length=16,
    )
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    failed_connection_count: int | None = Field(alias="failedConnectionCount", ge=0)

    @field_validator("source_address", "destination_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return _canonical_ip(value)

    @field_validator("subject_resource_candidates", "backend_resource_candidates")
    @classmethod
    def validate_candidates(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("VMConnection resource candidates must be unique")
        return normalized


class ConnectionMonitorRow(_WindowedRow):
    row_kind: Literal["connectionMonitor"] = Field(alias="rowKind")
    subject_resource_id: str = Field(alias="subjectResourceId")
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    monitor_resource_id: str = Field(alias="monitorResourceId")
    source_resource_id: str = Field(alias="sourceResourceId")
    destination_resource_id: str = Field(alias="destinationResourceId")
    source_address: str = Field(alias="sourceAddress")
    destination_address: str = Field(alias="destinationAddress")
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_port: int | None = Field(alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(alias="destinationPort", ge=0, le=65535)
    status: Literal["succeeded", "failed", "degraded", "unknown"]
    test_configuration_reference: str = Field(
        alias="testConfigurationReference",
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    test_configuration_digest: Sha256Digest = Field(alias="testConfigurationDigest")

    @field_validator(
        "subject_resource_id",
        "monitor_resource_id",
        "source_resource_id",
        "destination_resource_id",
    )
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @field_validator("source_address", "destination_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return _canonical_ip(value)


class IpFlowVerifyResult(_StrictAcquisitionModel):
    schema_version: Literal["athena.wc028IpFlowVerifyResult.v1"] = Field(alias="schemaVersion")
    source: Literal["ipFlowVerify"]
    request_digest: Sha256Digest = Field(alias="requestDigest")
    source_identity_id: str = Field(alias="sourceIdentityId")
    collected_at: UtcDateTime = Field(alias="collectedAt")
    checked_at: UtcDateTime = Field(alias="checkedAt")
    access: Literal["Allow", "Deny"]
    rule_resource_id: str | None = Field(default=None, alias="ruleResourceId")
    response_bytes: int = Field(alias="responseBytes", ge=0, le=MAX_ACQUISITION_RESPONSE_BYTES)
    limitation: Literal["pointInTimeNotHistorical"] = "pointInTimeNotHistorical"

    @field_validator("source_identity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _canonical_identity_id(value)

    @field_validator("rule_resource_id")
    @classmethod
    def validate_rule(cls, value: str | None) -> str | None:
        return None if value is None else _canonical_resource_id(value)


class TrafficAnalyticsRow(_WindowedRow):
    row_kind: Literal["trafficAnalytics"] = Field(alias="rowKind")
    subject_resource_candidates: tuple[str, ...] = Field(
        alias="subjectResourceCandidates",
        min_length=1,
        max_length=16,
    )
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    decision: Literal["allowed", "denied", "unknown"]
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_resource_candidates: tuple[str, ...] = Field(
        alias="sourceResourceCandidates",
        min_length=1,
        max_length=16,
    )
    destination_resource_candidates: tuple[str, ...] = Field(
        alias="destinationResourceCandidates",
        min_length=1,
        max_length=16,
    )
    source_address: str = Field(alias="sourceAddress")
    destination_address: str = Field(alias="destinationAddress")
    source_port: int | None = Field(alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(alias="destinationPort", ge=0, le=65535)
    enforcement_resource_id: str = Field(alias="enforcementResourceId")
    rule_resource_id: str | None = Field(default=None, alias="ruleResourceId")
    traffic_analytics_limitation: Literal["aggregatedNotPacketCausal"] = Field(
        alias="trafficAnalyticsLimitation"
    )

    @field_validator(
        "subject_resource_candidates",
        "source_resource_candidates",
        "destination_resource_candidates",
    )
    @classmethod
    def validate_candidates(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("Traffic Analytics resource candidates must be unique")
        return normalized

    @field_validator("enforcement_resource_id", "rule_resource_id")
    @classmethod
    def validate_resource(cls, value: str | None) -> str | None:
        return None if value is None else _canonical_resource_id(value)

    @field_validator("source_address", "destination_address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return _canonical_ip(value)


type LogAnalyticsRow = Annotated[
    HeartbeatRow | VmConnectionRow | ConnectionMonitorRow | TrafficAnalyticsRow,
    Field(discriminator="row_kind"),
]
type _HealthState = Literal["healthy", "degraded", "unhealthy", "unavailable"]


class LogCoverageDescriptor(_StrictAcquisitionModel):
    resource_ids: tuple[str, ...] = Field(alias="resourceIds", min_length=1, max_length=128)
    path_id: str | None = Field(
        default=None,
        alias="pathId",
        pattern=r"^path-[a-f0-9]{32}$",
    )
    direction: Literal["inbound", "outbound"] | None = None
    five_tuple_digest: Sha256Digest | None = Field(default=None, alias="fiveTupleDigest")
    endpoint_test_reference: str | None = Field(
        default=None,
        alias="endpointTestReference",
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    endpoint_test_digest: Sha256Digest | None = Field(
        default=None,
        alias="endpointTestDigest",
    )

    @field_validator("resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("coverage descriptor resource IDs must be unique")
        return normalized


def _log_coverage_descriptor(
    scope: EvidenceCoverageScope,
) -> LogCoverageDescriptor:
    return LogCoverageDescriptor(
        resourceIds=scope.resource_ids,
        pathId=scope.path_id,
        direction=scope.direction,
        fiveTupleDigest=scope.five_tuple_digest,
        endpointTestReference=scope.endpoint_test_reference,
        endpointTestDigest=scope.endpoint_test_digest,
    )


class ActivityLogRow(_StrictAcquisitionModel):
    category: str = Field(min_length=1, max_length=256)
    operation_name: str = Field(alias="operationName", min_length=1, max_length=256)
    result_type: str = Field(alias="resultType", min_length=1, max_length=256)
    level: Literal["Critical", "Error", "Informational", "Verbose", "Warning"]
    target_resource_id: str = Field(alias="targetResourceId")
    correlation_id: str = Field(alias="correlationId", pattern=_GUID_PATTERN.pattern)
    occurred_at: UtcDateTime = Field(alias="occurredAt")

    @field_validator("target_resource_id")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)


class ResourceGraphChangeRow(_StrictAcquisitionModel):
    target_resource_id: str = Field(alias="targetResourceId")
    correlation_id: str = Field(alias="correlationId", pattern=_GUID_PATTERN.pattern)
    occurred_at: UtcDateTime = Field(alias="occurredAt")
    operation_name: str = Field(alias="operationName", min_length=1, max_length=256)
    result_type: str = Field(alias="resultType", min_length=1, max_length=256)
    change: dict[str, object]

    @field_validator("target_resource_id")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)


class ResourceHealthRow(_WindowedRow):
    resource_id: str = Field(alias="resourceId")
    event_status: Literal["Active", "In Progress", "Resolved", "Updated"] = Field(
        alias="eventStatus"
    )
    current_status: Literal["Available", "Degraded", "Unavailable", "Unknown"] = Field(
        alias="currentStatus"
    )
    previous_status: Literal["Available", "Degraded", "Unavailable", "Unknown"] = Field(
        alias="previousStatus"
    )
    reason_type: Literal["PlatformInitiated", "UserInitiated", "Unknown"] = Field(
        alias="reasonType"
    )

    @field_validator("resource_id")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _canonical_resource_id(value)


class _AcquisitionResult(_StrictAcquisitionModel):
    request_digest: Sha256Digest = Field(alias="requestDigest")
    source_identity_id: str = Field(alias="sourceIdentityId")
    collected_at: UtcDateTime = Field(alias="collectedAt")
    columns: tuple[str, ...]
    truncated: bool
    response_bytes: int = Field(alias="responseBytes", ge=0, le=MAX_ACQUISITION_RESPONSE_BYTES)

    @field_validator("source_identity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _canonical_identity_id(value)


class LogAggregateCompletenessProof(_StrictAcquisitionModel):
    """Positive source proof that a zero aggregate was computed from ingested rows."""

    schema_version: Literal["athena.wc028LogAggregateCompletenessProof.v1"] = Field(
        alias="schemaVersion"
    )
    raw_input_row_count: int = Field(alias="rawInputRowCount", ge=1)
    ingestion_complete_through: UtcDateTime = Field(alias="ingestionCompleteThrough")
    window_start: UtcDateTime = Field(alias="windowStart")
    window_end: UtcDateTime = Field(alias="windowEnd")
    request_digest: Sha256Digest = Field(alias="requestDigest")
    query_digest: Sha256Digest = Field(alias="queryDigest")
    proof_digest: Sha256Digest = Field(alias="proofDigest")

    @model_validator(mode="after")
    def validate_proof(self) -> LogAggregateCompletenessProof:
        if (
            self.window_start >= self.window_end
            or self.ingestion_complete_through < self.window_end
        ):
            raise ValueError("aggregate completeness proof does not cover the query window")
        expected = compute_artifact_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"proof_digest"},
                exclude_none=True,
            )
        )
        if self.proof_digest != expected:
            raise ValueError("proofDigest does not bind aggregate completeness")
        return self


class LogAnalyticsQueryResult(_AcquisitionResult):
    schema_version: Literal["athena.wc028LogAnalyticsQueryResult.v1"] = Field(alias="schemaVersion")
    source: Literal["logAnalytics"]
    table: Literal[
        "Heartbeat",
        "VMConnection",
        "NWConnectionMonitorTestResult",
        "NTANetAnalytics",
    ]
    coverage_descriptor: LogCoverageDescriptor | None = Field(
        default=None,
        alias="coverageDescriptor",
    )
    aggregate_completeness_proof: LogAggregateCompletenessProof | None = Field(
        default=None,
        alias="aggregateCompletenessProof",
    )
    rows: tuple[LogAnalyticsRow, ...] = Field(max_length=MAX_ACQUISITION_ROWS)

    @model_validator(mode="after")
    def validate_coverage_descriptor(self) -> LogAnalyticsQueryResult:
        descriptor = self.coverage_descriptor
        if self.table in {"NWConnectionMonitorTestResult", "NTANetAnalytics"} and (
            descriptor is None
            or descriptor.path_id is None
            or descriptor.direction is None
            or descriptor.five_tuple_digest is None
        ):
            raise ValueError("network query results require an intent-bound coverage descriptor")
        if self.table == "NWConnectionMonitorTestResult" and (
            descriptor is None
            or descriptor.endpoint_test_reference is None
            or descriptor.endpoint_test_digest is None
        ):
            raise ValueError("Connection Monitor results require an exact endpoint test descriptor")
        if self.aggregate_completeness_proof is not None and self.table not in {
            "Heartbeat",
            "VMConnection",
        }:
            raise ValueError(
                "aggregate completeness proof is only valid for reviewed aggregate queries"
            )
        return self


class ActivityLogQueryResult(_AcquisitionResult):
    schema_version: Literal["athena.wc028ActivityLogQueryResult.v1"] = Field(alias="schemaVersion")
    source: Literal["activityLog"]
    rows: tuple[ActivityLogRow, ...] = Field(max_length=MAX_ACQUISITION_ROWS)


class ResourceGraphChangeQueryResult(_AcquisitionResult):
    schema_version: Literal["athena.wc028ResourceGraphChangeQueryResult.v1"] = Field(
        alias="schemaVersion"
    )
    source: Literal["resourceGraph"]
    rows: tuple[ResourceGraphChangeRow, ...] = Field(max_length=MAX_ACQUISITION_ROWS)


class ResourceHealthQueryResult(_AcquisitionResult):
    schema_version: Literal["athena.wc028ResourceHealthQueryResult.v1"] = Field(
        alias="schemaVersion"
    )
    source: Literal["resourceHealth"]
    rows: tuple[ResourceHealthRow, ...] = Field(max_length=MAX_ACQUISITION_ROWS)


class MonitoringLogAnalyticsClient(Protocol):
    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult: ...


class MonitoringActivityLogClient(Protocol):
    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult: ...


class MonitoringResourceGraphClient(Protocol):
    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult: ...


class MonitoringResourceHealthClient(Protocol):
    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult: ...


class MonitoringIpFlowVerifyClient(Protocol):
    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult: ...


type _AzureHttpTransport = HttpTransport[HttpRequest, HttpResponse]


@dataclass(frozen=True, slots=True)
class _AzureJsonResponse:
    status_code: int
    headers: Mapping[str, str]
    payload: object | None
    response_bytes: int


class _AzureJsonPipeline:
    """Bounded Azure SDK pipeline with one fixed endpoint and token audience."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        endpoint: str,
        scope: str,
        transport: _AzureHttpTransport | None = None,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._transport = (
            cast(
                _AzureHttpTransport,
                RequestsTransport(connection_timeout=10, read_timeout=30),
            )
            if transport is None
            else transport
        )
        self._pipeline: Pipeline[HttpRequest, HttpResponse] = Pipeline(
            transport=self._transport,
            policies=[BearerTokenCredentialPolicy(credential, scope)],
        )

    def request_json(
        self,
        *,
        method: Literal["GET", "POST"],
        path: str,
        max_bytes: int,
        accepted_statuses: tuple[int, ...] = (200,),
        body: Mapping[str, object] | None = None,
        headers: Mapping[str, str] | None = None,
        allow_empty: bool = False,
    ) -> _AzureJsonResponse:
        parsed_path = urlsplit(path)
        if (
            not path.startswith("/")
            or parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.fragment
            or max_bytes < 1
        ):
            raise MonitoringAcquisitionError("Azure request escaped its reviewed endpoint")
        request_headers = {"Accept": "application/json"}
        if headers is not None:
            request_headers.update(headers)
        data: bytes | None = None
        if body is not None:
            request_headers["Content-Type"] = "application/json"
            data = json.dumps(
                _json_value(body),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        request = HttpRequest(
            method,
            self._endpoint + path,
            headers=request_headers,
            data=data,
        )
        try:
            pipeline_response = self._pipeline.run(request, stream=True)
            response = pipeline_response.http_response
            chunks: list[bytes] = []
            response_bytes = 0
            for chunk in response.stream_download(self._pipeline):
                normalized_chunk = bytes(chunk)
                response_bytes += len(normalized_chunk)
                if response_bytes > max_bytes:
                    raise MonitoringAcquisitionError(
                        "Azure response exceeded its reviewed byte bound"
                    )
                chunks.append(normalized_chunk)
        except MonitoringAcquisitionError:
            raise
        except (AzureError, OSError, TimeoutError) as exc:
            raise MonitoringAcquisitionError("Azure monitoring transport failed closed") from exc
        if type(response.status_code) is not int or response.status_code not in accepted_statuses:
            raise MonitoringAcquisitionError("Azure monitoring request was unsuccessful")
        response_headers = {
            str(name).casefold(): str(value) for name, value in response.headers.items()
        }
        raw = b"".join(chunks)
        if not raw:
            if allow_empty:
                return _AzureJsonResponse(
                    status_code=response.status_code,
                    headers=response_headers,
                    payload=None,
                    response_bytes=response_bytes,
                )
            raise MonitoringAcquisitionError("Azure monitoring response was empty")
        content_type = response_headers.get("content-type")
        if content_type is None or not content_type.casefold().startswith("application/json"):
            raise MonitoringAcquisitionError("Azure monitoring response was not JSON")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MonitoringAcquisitionError("Azure monitoring response was not JSON") from exc
        return _AzureJsonResponse(
            status_code=response.status_code,
            headers=response_headers,
            payload=payload,
            response_bytes=response_bytes,
        )

    def sleep(self, seconds: int) -> None:
        self._transport.sleep(seconds)


def _azure_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MonitoringAcquisitionError(f"{label} must be one JSON object")
    return cast(Mapping[str, object], value)


def _azure_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise MonitoringAcquisitionError(f"{label} must be one JSON array")
    return value


def _azure_text(value: object, label: str, *, maximum: int = 2048) -> str:
    if isinstance(value, Mapping):
        value = value.get("value")
    if type(value) is not str:
        raise MonitoringAcquisitionError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise MonitoringAcquisitionError(f"{label} is outside its text bound")
    return normalized


def _azure_optional_text(value: object, label: str, *, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    return _azure_text(value, label, maximum=maximum)


def _azure_integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise MonitoringAcquisitionError(f"{label} must be an integer")
    return value


def _azure_optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _azure_integer(value, label)


def _azure_datetime(value: object, label: str) -> datetime:
    text = _azure_text(value, label, maximum=64)
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MonitoringAcquisitionError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise MonitoringAcquisitionError(f"{label} must be UTC")
    utc_value = parsed.astimezone(UTC)
    return utc_value.replace(microsecond=(utc_value.microsecond // 1000) * 1000)


def _azure_datetime_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise MonitoringAcquisitionError("Azure request timestamp must be UTC")
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _azure_resource_candidates(value: object, label: str) -> tuple[str, ...]:
    candidate_value = value
    if type(candidate_value) is str:
        try:
            candidate_value = json.loads(candidate_value)
        except json.JSONDecodeError as exc:
            raise MonitoringAcquisitionError(f"{label} was not a JSON array") from exc
    candidates = _azure_list(candidate_value, label)
    if not candidates:
        raise MonitoringAcquisitionError(f"{label} must not be empty")
    return tuple(_azure_text(item, label) for item in candidates)


def _selected_value(value: str, allowed: tuple[str, ...]) -> str | None:
    matches = tuple(item for item in allowed if item.casefold() == value.casefold())
    if len(matches) > 1:
        raise MonitoringAcquisitionError("Azure response matched an ambiguous reviewed filter")
    return None if not matches else matches[0]


def _azure_direction(value: object) -> Literal["inbound", "outbound"]:
    normalized = _azure_text(value, "Azure direction", maximum=16).casefold()
    if normalized in {"i", "inbound"}:
        return "inbound"
    if normalized in {"o", "outbound"}:
        return "outbound"
    raise MonitoringAcquisitionError("Azure direction was outside the reviewed values")


def _azure_protocol(value: object) -> Literal["Tcp", "Udp", "Icmp", "Any"]:
    normalized = _azure_text(value, "Azure protocol", maximum=16).casefold()
    values: dict[str, Literal["Tcp", "Udp", "Icmp", "Any"]] = {
        "6": "Tcp",
        "17": "Udp",
        "any": "Any",
        "icmp": "Icmp",
        "tcp": "Tcp",
        "udp": "Udp",
    }
    try:
        return values[normalized]
    except KeyError as exc:
        raise MonitoringAcquisitionError("Azure protocol was outside the reviewed values") from exc


def _azure_decision(value: object) -> Literal["allowed", "denied", "unknown"]:
    normalized = _azure_text(value, "Azure flow decision", maximum=16).casefold()
    values: dict[str, Literal["allowed", "denied", "unknown"]] = {
        "allow": "allowed",
        "allowed": "allowed",
        "deny": "denied",
        "denied": "denied",
        "unknown": "unknown",
    }
    try:
        return values[normalized]
    except KeyError as exc:
        raise MonitoringAcquisitionError(
            "Azure flow decision was outside the reviewed values"
        ) from exc


def _azure_connection_status(
    value: object,
) -> Literal["succeeded", "failed", "degraded", "unknown"]:
    normalized = _azure_text(value, "Azure connection status", maximum=16).casefold()
    if normalized not in {"succeeded", "failed", "degraded", "unknown"}:
        raise MonitoringAcquisitionError("Azure connection status was outside the reviewed values")
    return cast(
        Literal["succeeded", "failed", "degraded", "unknown"],
        normalized,
    )


def _azure_health_status(
    value: object,
    label: str,
) -> Literal["Available", "Degraded", "Unavailable", "Unknown"]:
    normalized = _azure_text(value, label, maximum=32).casefold()
    values: dict[
        str,
        Literal["Available", "Degraded", "Unavailable", "Unknown"],
    ] = {
        "available": "Available",
        "degraded": "Degraded",
        "unavailable": "Unavailable",
        "unknown": "Unknown",
    }
    try:
        return values[normalized]
    except KeyError as exc:
        raise MonitoringAcquisitionError(
            "Azure Resource Health status was outside the reviewed values"
        ) from exc


def _azure_reason_type(
    value: object | None,
) -> Literal["PlatformInitiated", "UserInitiated", "Unknown"]:
    if value is None:
        return "Unknown"
    normalized = _azure_text(value, "Azure Resource Health reason", maximum=64).casefold()
    if normalized in {
        "outage",
        "planned",
        "platform initiated",
        "platforminitiated",
        "unplanned",
    }:
        return "PlatformInitiated"
    if normalized in {"user initiated", "userinitiated"}:
        return "UserInitiated"
    return "Unknown"


def _resource_health_event_status(
    current: Literal["Available", "Degraded", "Unavailable", "Unknown"],
    previous: Literal["Available", "Degraded", "Unavailable", "Unknown"],
) -> Literal["Active", "In Progress", "Resolved", "Updated"]:
    if current == previous:
        return "Updated"
    if current == "Available":
        return "Resolved"
    if previous == "Available":
        return "Active"
    return "In Progress"


def _sorted_rows[RowT: _StrictAcquisitionModel](
    rows: list[RowT],
) -> tuple[RowT, ...]:
    return tuple(sorted(rows, key=lambda row: row.canonical_json()))


def _remaining_response_bytes(limit: int, used: int) -> int:
    remaining = limit - used
    if remaining < 1:
        raise MonitoringAcquisitionError("Azure responses exceeded their reviewed byte bound")
    return remaining


def _validated_azure_client_contract(
    reviewed_contract: MonitoringCollectorContract,
) -> MonitoringCollectorContract:
    if type(reviewed_contract) is not MonitoringCollectorContract:
        raise TypeError("Azure acquisition client requires an exact collector contract")
    if reviewed_contract.schema_version != MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION:
        raise MonitoringAcquisitionError(
            "Azure acquisition client requires collector contract schema v7"
        )
    return reviewed_contract


def _arm_subscription_id(resource_id: str) -> str:
    segments = resource_id.strip("/").split("/")
    if (
        len(segments) < 2
        or segments[0].casefold() != "subscriptions"
        or _GUID_PATTERN.fullmatch(segments[1].casefold()) is None
    ):
        raise MonitoringAcquisitionError("Azure request resource has no valid subscription")
    return segments[1].casefold()


def _resource_is_within(resource_id: str, scope_id: str) -> bool:
    resource = resource_id.casefold().rstrip("/")
    scope = scope_id.casefold().rstrip("/")
    return resource == scope or resource.startswith(scope + "/")


class _AzureAcquisitionClientBase:
    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        endpoint: str,
        scope: str,
        transport: _AzureHttpTransport | None,
    ) -> None:
        self._credential = credential
        self._reviewed_contract = _validated_azure_client_contract(reviewed_contract)
        self._reviewed_contract_digest = self._reviewed_contract.compute_artifact_digest_value()
        self._http = _AzureJsonPipeline(
            credential=credential,
            endpoint=endpoint,
            scope=scope,
            transport=transport,
        )

    def _require_request_contract(self, request: _AcquisitionRequest) -> None:
        if (
            request.monitoring_reader_identity_id
            != self._reviewed_contract.collector_identity_resource_id.casefold().rstrip("/")
            or request.collector_contract_digest != self._reviewed_contract_digest
        ):
            raise MonitoringAcquisitionError(
                "Azure request does not bind the reviewed collector contract"
            )


def _normalize_log_analytics_row(
    request: LogAnalyticsQueryRequest,
    values: object,
) -> LogAnalyticsRow:
    row_values = _azure_list(values, "Log Analytics row")
    if len(row_values) != len(request.expected_columns):
        raise MonitoringAcquisitionError(
            "Log Analytics row does not match the reviewed column count"
        )
    row = dict(zip(request.expected_columns, row_values, strict=True))
    if request.table == "Heartbeat":
        return HeartbeatRow(
            rowKind="heartbeat",
            resourceId=_azure_text(row["resourceId"], "Heartbeat resourceId"),
            observedStart=_azure_datetime(row["observedStart"], "Heartbeat observedStart"),
            observedEnd=_azure_datetime(row["observedEnd"], "Heartbeat observedEnd"),
            heartbeatCount=_azure_optional_integer(
                row["heartbeatCount"],
                "Heartbeat heartbeatCount",
            ),
        )
    if request.table == "VMConnection":
        return VmConnectionRow(
            rowKind="vmConnection",
            sourceAddress=_azure_text(row["sourceAddress"], "VMConnection sourceAddress"),
            destinationAddress=_azure_text(
                row["destinationAddress"],
                "VMConnection destinationAddress",
            ),
            subjectResourceCandidates=_azure_resource_candidates(
                row["subjectResourceCandidates"],
                "VMConnection subjectResourceCandidates",
            ),
            backendResourceCandidates=_azure_resource_candidates(
                row["backendResourceCandidates"],
                "VMConnection backendResourceCandidates",
            ),
            pathId=_azure_text(row["pathId"], "VMConnection pathId"),
            observedStart=_azure_datetime(
                row["observedStart"],
                "VMConnection observedStart",
            ),
            observedEnd=_azure_datetime(
                row["observedEnd"],
                "VMConnection observedEnd",
            ),
            failedConnectionCount=_azure_optional_integer(
                row["failedConnectionCount"],
                "VMConnection failedConnectionCount",
            ),
        )
    if request.table == "NWConnectionMonitorTestResult":
        return ConnectionMonitorRow(
            rowKind="connectionMonitor",
            subjectResourceId=_azure_text(
                row["subjectResourceId"],
                "Connection Monitor subjectResourceId",
            ),
            pathId=_azure_text(row["pathId"], "Connection Monitor pathId"),
            monitorResourceId=_azure_text(
                row["monitorResourceId"],
                "Connection Monitor monitorResourceId",
            ),
            sourceResourceId=_azure_text(
                row["sourceResourceId"],
                "Connection Monitor sourceResourceId",
            ),
            destinationResourceId=_azure_text(
                row["destinationResourceId"],
                "Connection Monitor destinationResourceId",
            ),
            sourceAddress=_azure_text(
                row["sourceAddress"],
                "Connection Monitor sourceAddress",
            ),
            destinationAddress=_azure_text(
                row["destinationAddress"],
                "Connection Monitor destinationAddress",
            ),
            direction=_azure_direction(row["direction"]),
            protocol=_azure_protocol(row["protocol"]),
            sourcePort=_azure_optional_integer(
                row["sourcePort"],
                "Connection Monitor sourcePort",
            ),
            destinationPort=_azure_optional_integer(
                row["destinationPort"],
                "Connection Monitor destinationPort",
            ),
            status=_azure_connection_status(row["status"]),
            testConfigurationReference=_azure_text(
                row["testConfigurationReference"],
                "Connection Monitor testConfigurationReference",
            ),
            testConfigurationDigest=_azure_text(
                row["testConfigurationDigest"],
                "Connection Monitor testConfigurationDigest",
            ),
            observedStart=_azure_datetime(
                row["observedStart"],
                "Connection Monitor observedStart",
            ),
            observedEnd=_azure_datetime(
                row["observedEnd"],
                "Connection Monitor observedEnd",
            ),
        )
    return TrafficAnalyticsRow(
        rowKind="trafficAnalytics",
        subjectResourceCandidates=_azure_resource_candidates(
            row["subjectResourceCandidates"],
            "Traffic Analytics subjectResourceCandidates",
        ),
        pathId=_azure_text(row["pathId"], "Traffic Analytics pathId"),
        decision=_azure_decision(row["decision"]),
        direction=_azure_direction(row["direction"]),
        protocol=_azure_protocol(row["protocol"]),
        sourceResourceCandidates=_azure_resource_candidates(
            row["sourceResourceCandidates"],
            "Traffic Analytics sourceResourceCandidates",
        ),
        destinationResourceCandidates=_azure_resource_candidates(
            row["destinationResourceCandidates"],
            "Traffic Analytics destinationResourceCandidates",
        ),
        sourceAddress=_azure_text(
            row["sourceAddress"],
            "Traffic Analytics sourceAddress",
        ),
        destinationAddress=_azure_text(
            row["destinationAddress"],
            "Traffic Analytics destinationAddress",
        ),
        sourcePort=_azure_optional_integer(
            row["sourcePort"],
            "Traffic Analytics sourcePort",
        ),
        destinationPort=_azure_optional_integer(
            row["destinationPort"],
            "Traffic Analytics destinationPort",
        ),
        enforcementResourceId=_azure_text(
            row["enforcementResourceId"],
            "Traffic Analytics enforcementResourceId",
        ),
        ruleResourceId=_azure_optional_text(
            row["ruleResourceId"],
            "Traffic Analytics ruleResourceId",
        ),
        trafficAnalyticsLimitation="aggregatedNotPacketCausal",
        observedStart=_azure_datetime(
            row["observedStart"],
            "Traffic Analytics observedStart",
        ),
        observedEnd=_azure_datetime(
            row["observedEnd"],
            "Traffic Analytics observedEnd",
        ),
    )


class AzureLogAnalyticsAcquisitionClient(_AzureAcquisitionClientBase):
    """Credential-bound resource-centric Azure Monitor Logs client."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        _transport: _AzureHttpTransport | None = None,
    ) -> None:
        super().__init__(
            credential=credential,
            reviewed_contract=reviewed_contract,
            endpoint=_AZURE_LOGS_ENDPOINT,
            scope=_AZURE_LOGS_SCOPE,
            transport=_transport,
        )

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult:
        if type(request) is not LogAnalyticsQueryRequest:
            raise TypeError("Azure Log Analytics requires an exact query request")
        self._require_request_contract(request)
        allowed_targets = {
            *(
                item.casefold().rstrip("/")
                for item in self._reviewed_contract.signal_read_scope_ids
            ),
        }
        if (
            request.table not in self._reviewed_contract.log_analytics_allowed_tables
            or request.query_target_resource_id not in allowed_targets
            or self._reviewed_contract.workspace_access_control_mode
            != "workspaceAndResourceContext"
            or self._reviewed_contract.resource_log_allowed_operations
            != (
                "Microsoft.Insights/logs/Heartbeat/read",
                "Microsoft.Insights/logs/NTANetAnalytics/read",
                "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
                "Microsoft.Insights/logs/VMConnection/read",
            )
            or request.collector_execution_time is None
            or request.coverage_scope is None
        ):
            raise MonitoringAcquisitionError(
                "Log Analytics request escaped the reviewed table or resource scope"
            )
        response = self._http.request_json(
            method="POST",
            path=(
                f"/{_LOG_ANALYTICS_API_VERSION}"
                f"{quote(request.query_target_resource_id, safe='/')}/query"
            ),
            body={
                "query": request.query,
                "timespan": (
                    f"{_azure_datetime_text(request.window_start)}/"
                    f"{_azure_datetime_text(request.window_end)}"
                ),
            },
            max_bytes=request.max_bytes,
        )
        payload = _azure_mapping(response.payload, "Log Analytics response")
        if payload.get("error") is not None:
            raise MonitoringAcquisitionError("Log Analytics returned a partial or failed query")
        tables = _azure_list(payload.get("tables"), "Log Analytics tables")
        if len(tables) != 1:
            raise MonitoringAcquisitionError(
                "Log Analytics response must contain exactly one result table"
            )
        table = _azure_mapping(tables[0], "Log Analytics table")
        columns = tuple(
            _azure_text(
                _azure_mapping(item, "Log Analytics column").get("name"),
                "Log Analytics column name",
                maximum=128,
            )
            for item in _azure_list(table.get("columns"), "Log Analytics columns")
        )
        if columns != request.expected_columns:
            raise MonitoringAcquisitionError(
                "Log Analytics columns do not match the reviewed schema"
            )
        raw_rows = _azure_list(table.get("rows"), "Log Analytics rows")
        normalized_rows = _sorted_rows(
            [_normalize_log_analytics_row(request, row) for row in raw_rows]
        )
        truncated = len(raw_rows) > request.max_rows
        rows = normalized_rows[: request.max_rows]
        return LogAnalyticsQueryResult(
            schemaVersion="athena.wc028LogAnalyticsQueryResult.v1",
            source="logAnalytics",
            table=request.table,
            requestDigest=request.request_digest,
            sourceIdentityId=self._reviewed_contract.collector_identity_resource_id,
            collectedAt=request.collector_execution_time,
            columns=request.expected_columns,
            coverageDescriptor=_log_coverage_descriptor(request.coverage_scope),
            aggregateCompletenessProof=None,
            truncated=truncated,
            responseBytes=response.response_bytes,
            rows=rows,
        )


def _normalize_activity_log_row(
    value: object,
    *,
    requested_resource_id: str,
    request: ActivityLogQueryRequest,
) -> ActivityLogRow | None:
    row = _azure_mapping(value, "Activity Log row")
    target_resource_id = _canonical_resource_id(
        _azure_text(row.get("resourceId"), "Activity Log resourceId")
    )
    if target_resource_id != requested_resource_id:
        raise MonitoringAcquisitionError("Activity Log response escaped its exact resource filter")
    category = _azure_text(row.get("category"), "Activity Log category", maximum=256)
    operation_name = _azure_text(
        row.get("operationName"),
        "Activity Log operationName",
        maximum=256,
    )
    result_type = _azure_text(row.get("status"), "Activity Log status", maximum=256)
    level = _azure_text(row.get("level"), "Activity Log level", maximum=32)
    selected_category = _selected_value(category, request.categories)
    selected_operation = _selected_value(operation_name, request.operation_names)
    selected_result = _selected_value(result_type, request.result_types)
    selected_level = _selected_value(level, request.levels)
    if (
        selected_category is None
        or selected_operation is None
        or selected_result is None
        or selected_level is None
    ):
        return None
    occurred_at = _azure_datetime(
        row.get("eventTimestamp"),
        "Activity Log eventTimestamp",
    )
    if not request.window_start <= occurred_at <= request.window_end:
        raise MonitoringAcquisitionError("Activity Log response escaped its exact time filter")
    return ActivityLogRow(
        category=selected_category,
        operationName=selected_operation,
        resultType=selected_result,
        level=cast(
            Literal["Critical", "Error", "Informational", "Verbose", "Warning"],
            selected_level,
        ),
        targetResourceId=target_resource_id,
        correlationId=_azure_text(
            row.get("correlationId"),
            "Activity Log correlationId",
            maximum=64,
        ).casefold(),
        occurredAt=occurred_at,
    )


class AzureActivityLogAcquisitionClient(_AzureAcquisitionClientBase):
    """Credential-bound Activity Log client scoped to exact requested resources."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        _transport: _AzureHttpTransport | None = None,
    ) -> None:
        super().__init__(
            credential=credential,
            reviewed_contract=reviewed_contract,
            endpoint=_AZURE_ARM_ENDPOINT,
            scope=_AZURE_ARM_SCOPE,
            transport=_transport,
        )

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult:
        if type(request) is not ActivityLogQueryRequest:
            raise TypeError("Azure Activity Log requires an exact query request")
        self._require_request_contract(request)
        subscription_id = _arm_subscription_id(self._reviewed_contract.workload_resource_group_id)
        workload_scope = self._reviewed_contract.workload_resource_group_id
        if any(
            _arm_subscription_id(resource_id) != subscription_id
            or not _resource_is_within(resource_id, workload_scope)
            for resource_id in request.resource_ids
        ):
            raise MonitoringAcquisitionError(
                "Activity Log request escaped the reviewed workload scope"
            )
        rows: list[ActivityLogRow] = []
        response_bytes = 0
        truncated = False
        select = "category,operationName,status,level,resourceId,correlationId,eventTimestamp"
        for resource_id in request.resource_ids:
            filter_value = (
                f"eventTimestamp ge '{_azure_datetime_text(request.window_start)}' and "
                f"eventTimestamp le '{_azure_datetime_text(request.window_end)}' and "
                f"resourceUri eq '{resource_id}'"
            )
            query = urlencode(
                {
                    "api-version": _ACTIVITY_LOG_API_VERSION,
                    "$filter": filter_value,
                    "$select": select,
                },
                quote_via=quote,
            )
            response = self._http.request_json(
                method="GET",
                path=(
                    f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/"
                    f"eventtypes/management/values?{query}"
                ),
                headers={"Prefer": "wait=30"},
                max_bytes=_remaining_response_bytes(request.max_bytes, response_bytes),
            )
            response_bytes += response.response_bytes
            payload = _azure_mapping(response.payload, "Activity Log response")
            next_link = payload.get("nextLink")
            if next_link is not None:
                _azure_text(next_link, "Activity Log nextLink", maximum=4096)
                truncated = True
            for item in _azure_list(payload.get("value"), "Activity Log value"):
                normalized = _normalize_activity_log_row(
                    item,
                    requested_resource_id=resource_id,
                    request=request,
                )
                if normalized is not None:
                    rows.append(normalized)
        normalized_rows = _sorted_rows(rows)
        if len(normalized_rows) > request.max_rows:
            truncated = True
        return ActivityLogQueryResult(
            schemaVersion="athena.wc028ActivityLogQueryResult.v1",
            source="activityLog",
            requestDigest=request.request_digest,
            sourceIdentityId=self._reviewed_contract.collector_identity_resource_id,
            collectedAt=request.window_end,
            columns=request.expected_columns,
            truncated=truncated,
            responseBytes=response_bytes,
            rows=normalized_rows[: request.max_rows],
        )


def _resource_graph_query(request: ResourceGraphChangeQueryRequest) -> str:
    resource_ids = ", ".join(
        f"'{resource_id.replace("'", "''")}'" for resource_id in request.resource_ids
    )
    return "\n".join(
        (
            "resourcechanges",
            (
                "| extend targetResourceId=tolower(tostring(properties.targetResourceId)), "
                "occurredAt=todatetime(properties.changeAttributes.timestamp), "
                "correlationId=tolower(tostring(properties.changeAttributes.correlationId)), "
                "operationName=tostring(properties.changeAttributes.operation)"
            ),
            f"| where targetResourceId in~ ({resource_ids})",
            (
                "| where occurredAt between "
                f"(datetime({_azure_datetime_text(request.window_start)}) .. "
                f"datetime({_azure_datetime_text(request.window_end)}))"
            ),
            (
                "| project targetResourceId, correlationId, occurredAt, operationName, "
                "resultType='Succeeded', id, properties"
            ),
            "| order by occurredAt asc, targetResourceId asc, correlationId asc",
            f"| take {request.max_rows + 1}",
        )
    )


def _normalize_resource_graph_row(
    value: object,
    *,
    request: ResourceGraphChangeQueryRequest,
) -> ResourceGraphChangeRow:
    row = _azure_mapping(value, "Resource Graph row")
    target_resource_id = _canonical_resource_id(
        _azure_text(row.get("targetResourceId"), "Resource Graph targetResourceId")
    )
    if target_resource_id not in request.resource_ids:
        raise MonitoringAcquisitionError(
            "Resource Graph response escaped the reviewed resource scope"
        )
    occurred_at = _azure_datetime(
        row.get("occurredAt"),
        "Resource Graph occurredAt",
    )
    if not request.window_start <= occurred_at <= request.window_end:
        raise MonitoringAcquisitionError("Resource Graph response escaped the reviewed time window")
    properties = _azure_mapping(
        row.get("properties"),
        "Resource Graph change properties",
    )
    return ResourceGraphChangeRow(
        targetResourceId=target_resource_id,
        correlationId=_azure_text(
            row.get("correlationId"),
            "Resource Graph correlationId",
            maximum=64,
        ).casefold(),
        occurredAt=occurred_at,
        operationName=_azure_text(
            row.get("operationName"),
            "Resource Graph operationName",
            maximum=256,
        ),
        resultType=_azure_text(
            row.get("resultType"),
            "Resource Graph resultType",
            maximum=256,
        ),
        change={
            "id": _azure_text(row.get("id"), "Resource Graph change id"),
            "properties": dict(properties),
        },
    )


class AzureResourceGraphAcquisitionClient(_AzureAcquisitionClientBase):
    """Credential-bound Resource Graph change-history client."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        _transport: _AzureHttpTransport | None = None,
    ) -> None:
        super().__init__(
            credential=credential,
            reviewed_contract=reviewed_contract,
            endpoint=_AZURE_ARM_ENDPOINT,
            scope=_AZURE_ARM_SCOPE,
            transport=_transport,
        )

    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult:
        if type(request) is not ResourceGraphChangeQueryRequest:
            raise TypeError("Azure Resource Graph requires an exact query request")
        self._require_request_contract(request)
        subscription_id = _arm_subscription_id(self._reviewed_contract.workload_resource_group_id)
        workload_scope = self._reviewed_contract.workload_resource_group_id
        if any(
            _arm_subscription_id(resource_id) != subscription_id
            or not _resource_is_within(resource_id, workload_scope)
            for resource_id in request.resource_ids
        ):
            raise MonitoringAcquisitionError(
                "Resource Graph request escaped the reviewed workload scope"
            )
        query_text = _resource_graph_query(request)
        if len(query_text.encode("utf-8")) > 32 * 1024:
            raise MonitoringAcquisitionError(
                "Resource Graph generated query exceeded its reviewed byte bound"
            )
        response = self._http.request_json(
            method="POST",
            path=(
                "/providers/Microsoft.ResourceGraph/resources"
                f"?api-version={_RESOURCE_GRAPH_API_VERSION}"
            ),
            body={
                "subscriptions": [subscription_id],
                "query": query_text,
                "options": {
                    "$top": request.max_rows + 1,
                    "resultFormat": "ObjectArray",
                },
            },
            max_bytes=request.max_bytes,
        )
        payload = _azure_mapping(response.payload, "Resource Graph response")
        marker = payload.get("resultTruncated")
        if marker is False or marker == "false":
            truncated = False
        elif marker is True or marker == "true":
            truncated = True
        else:
            raise MonitoringAcquisitionError(
                "Resource Graph response truncation marker was invalid"
            )
        if payload.get("$skipToken") is not None or payload.get("skipToken") is not None:
            truncated = True
        raw_rows = _azure_list(payload.get("data"), "Resource Graph data")
        normalized_rows = _sorted_rows(
            [_normalize_resource_graph_row(row, request=request) for row in raw_rows]
        )
        if len(raw_rows) > request.max_rows:
            truncated = True
        return ResourceGraphChangeQueryResult(
            schemaVersion="athena.wc028ResourceGraphChangeQueryResult.v1",
            source="resourceGraph",
            requestDigest=request.request_digest,
            sourceIdentityId=self._reviewed_contract.collector_identity_resource_id,
            collectedAt=request.window_end,
            columns=request.expected_columns,
            truncated=truncated,
            responseBytes=response.response_bytes,
            rows=normalized_rows[: request.max_rows],
        )


def _normalize_resource_health_row(
    value: object,
    *,
    requested_resource_id: str,
    request: ResourceHealthQueryRequest,
) -> ResourceHealthRow | None:
    row = _azure_mapping(value, "Resource Health row")
    properties = _azure_mapping(
        row.get("properties"),
        "Resource Health properties",
    )
    response_resource_id = properties.get("targetResourceId")
    resource_id = (
        requested_resource_id
        if response_resource_id is None
        else _canonical_resource_id(
            _azure_text(
                response_resource_id,
                "Resource Health targetResourceId",
            )
        )
    )
    if resource_id != requested_resource_id:
        raise MonitoringAcquisitionError(
            "Resource Health response escaped its exact resource scope"
        )
    if properties.get("availabilityState") is None:
        return None
    current_status = _azure_health_status(
        properties.get("availabilityState"),
        "Resource Health availabilityState",
    )
    previous_status = _azure_health_status(
        properties.get("previousAvailabilityState"),
        "Resource Health previousAvailabilityState",
    )
    event_status = _resource_health_event_status(current_status, previous_status)
    reason_type = _azure_reason_type(
        properties.get("healthEventCause", properties.get("reasonType"))
    )
    if (
        _selected_value(event_status, request.event_statuses) is None
        or _selected_value(current_status, request.current_statuses) is None
        or _selected_value(previous_status, request.previous_statuses) is None
        or _selected_value(reason_type, request.reason_types) is None
    ):
        return None
    occurred_at = _azure_datetime(
        properties.get("occurredTime"),
        "Resource Health occurredTime",
    )
    if not request.window_start <= occurred_at <= request.window_end:
        return None
    return ResourceHealthRow(
        resourceId=resource_id,
        eventStatus=event_status,
        currentStatus=current_status,
        previousStatus=previous_status,
        reasonType=reason_type,
        observedStart=occurred_at,
        observedEnd=occurred_at,
    )


class AzureResourceHealthAcquisitionClient(_AzureAcquisitionClientBase):
    """Credential-bound Resource Health availability-history client."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        _transport: _AzureHttpTransport | None = None,
    ) -> None:
        super().__init__(
            credential=credential,
            reviewed_contract=reviewed_contract,
            endpoint=_AZURE_ARM_ENDPOINT,
            scope=_AZURE_ARM_SCOPE,
            transport=_transport,
        )

    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult:
        if type(request) is not ResourceHealthQueryRequest:
            raise TypeError("Azure Resource Health requires an exact query request")
        self._require_request_contract(request)
        approved_resources = {
            item.casefold().rstrip("/")
            for item in cast(
                tuple[str, ...],
                self._reviewed_contract.resource_health_scope_ids,
            )
        }
        if not set(request.resource_ids).issubset(approved_resources):
            raise MonitoringAcquisitionError(
                "Resource Health request escaped the exact reviewed VM scopes"
            )
        rows: list[ResourceHealthRow] = []
        response_bytes = 0
        truncated = False
        for resource_id in request.resource_ids:
            response = self._http.request_json(
                method="GET",
                path=(
                    f"{quote(resource_id, safe='/')}/providers/"
                    "Microsoft.ResourceHealth/availabilityStatuses"
                    f"?api-version={_RESOURCE_HEALTH_API_VERSION}"
                ),
                max_bytes=_remaining_response_bytes(request.max_bytes, response_bytes),
            )
            response_bytes += response.response_bytes
            payload = _azure_mapping(response.payload, "Resource Health response")
            next_link = payload.get("nextLink")
            if next_link is not None:
                _azure_text(next_link, "Resource Health nextLink", maximum=4096)
                truncated = True
            for item in _azure_list(payload.get("value"), "Resource Health value"):
                normalized = _normalize_resource_health_row(
                    item,
                    requested_resource_id=resource_id,
                    request=request,
                )
                if normalized is not None:
                    rows.append(normalized)
        normalized_rows = _sorted_rows(rows)
        if len(normalized_rows) > request.max_rows:
            truncated = True
        return ResourceHealthQueryResult(
            schemaVersion="athena.wc028ResourceHealthQueryResult.v1",
            source="resourceHealth",
            requestDigest=request.request_digest,
            sourceIdentityId=self._reviewed_contract.collector_identity_resource_id,
            collectedAt=request.window_end,
            columns=request.expected_columns,
            truncated=truncated,
            responseBytes=response_bytes,
            rows=normalized_rows[: request.max_rows],
        )


def _arm_poll_path(location: str, *, subscription_id: str) -> str:
    parsed = urlsplit(location)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.hostname.casefold() != "management.azure.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
        or not parsed.path.casefold().startswith(f"/subscriptions/{subscription_id}/")
        or "/providers/microsoft.network/" not in parsed.path.casefold()
        or query not in ({}, {"api-version": [_NETWORK_API_VERSION]})
    ):
        raise MonitoringAcquisitionError("IP Flow Verify polling escaped the reviewed ARM endpoint")
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


class AzureIpFlowVerifyAcquisitionClient(_AzureAcquisitionClientBase):
    """Credential-bound Network Watcher IP Flow Verify client."""

    def __init__(
        self,
        *,
        credential: ManagedIdentityCredential,
        reviewed_contract: MonitoringCollectorContract,
        _transport: _AzureHttpTransport | None = None,
    ) -> None:
        super().__init__(
            credential=credential,
            reviewed_contract=reviewed_contract,
            endpoint=_AZURE_ARM_ENDPOINT,
            scope=_AZURE_ARM_SCOPE,
            transport=_transport,
        )

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult:
        if type(request) is not IpFlowVerifyRequest:
            raise TypeError("Azure IP Flow Verify requires an exact query request")
        self._require_request_contract(request)
        approved_targets = {
            item.casefold().rstrip("/") for item in self._reviewed_contract.signal_read_scope_ids
        }
        watcher_id = _canonical_resource_id(
            cast(str, self._reviewed_contract.ip_flow_verify_scope_id)
        )
        subscription_id = _arm_subscription_id(watcher_id)
        if (
            request.target_resource_id not in approved_targets
            or request.protocol not in {"Tcp", "Udp"}
            or _arm_subscription_id(request.target_resource_id) != subscription_id
            or ipaddress.ip_address(request.source_address).version != 4
            or ipaddress.ip_address(request.destination_address).version != 4
        ):
            raise MonitoringAcquisitionError(
                "IP Flow Verify request escaped the exact reviewed VM or protocol scope"
            )
        if request.direction == "inbound":
            local_address = request.destination_address
            local_port = request.destination_port
            remote_address = request.source_address
            remote_port = request.source_port
        else:
            local_address = request.source_address
            local_port = request.source_port
            remote_address = request.destination_address
            remote_port = request.destination_port
        body = {
            "targetResourceId": request.target_resource_id,
            "direction": request.direction.title(),
            "protocol": request.protocol.upper(),
            "localPort": "*" if local_port is None else str(local_port),
            "remotePort": "*" if remote_port is None else str(remote_port),
            "localIPAddress": local_address,
            "remoteIPAddress": remote_address,
        }
        response_bytes = 0
        response = self._http.request_json(
            method="POST",
            path=(f"{quote(watcher_id, safe='/')}/ipFlowVerify?api-version={_NETWORK_API_VERSION}"),
            body=body,
            max_bytes=request.max_bytes,
            accepted_statuses=(200, 202),
            allow_empty=True,
        )
        response_bytes += response.response_bytes
        elapsed_seconds = 0
        attempts = 1
        while response.status_code == 202:
            if attempts >= _MAX_ARM_POLL_ATTEMPTS:
                raise MonitoringAcquisitionError("IP Flow Verify polling exceeded its bound")
            location = response.headers.get("location")
            if location is None:
                raise MonitoringAcquisitionError(
                    "IP Flow Verify polling response omitted its exact location"
                )
            retry_after_text = response.headers.get("retry-after", "1")
            try:
                retry_after = int(retry_after_text)
            except ValueError as exc:
                raise MonitoringAcquisitionError(
                    "IP Flow Verify polling delay was invalid"
                ) from exc
            if retry_after < 0 or retry_after > 15:
                raise MonitoringAcquisitionError(
                    "IP Flow Verify polling delay was outside its bound"
                )
            elapsed_seconds += retry_after
            if elapsed_seconds > _MAX_ARM_POLL_SECONDS:
                raise MonitoringAcquisitionError("IP Flow Verify polling exceeded its time bound")
            self._http.sleep(retry_after)
            response = self._http.request_json(
                method="GET",
                path=_arm_poll_path(location, subscription_id=subscription_id),
                max_bytes=_remaining_response_bytes(request.max_bytes, response_bytes),
                accepted_statuses=(200, 202),
                allow_empty=True,
            )
            response_bytes += response.response_bytes
            attempts += 1
        payload = _azure_mapping(response.payload, "IP Flow Verify response")
        if payload.get("access") is None and isinstance(payload.get("properties"), Mapping):
            payload = _azure_mapping(
                payload.get("properties"),
                "IP Flow Verify response properties",
            )
        access_text = _azure_text(payload.get("access"), "IP Flow Verify access", maximum=16)
        access_lookup: dict[str, Literal["Allow", "Deny"]] = {
            "allow": "Allow",
            "deny": "Deny",
        }
        try:
            access = access_lookup[access_text.casefold()]
        except KeyError as exc:
            raise MonitoringAcquisitionError(
                "IP Flow Verify access was outside the reviewed values"
            ) from exc
        rule_name = _azure_optional_text(
            payload.get("ruleName"),
            "IP Flow Verify ruleName",
        )
        rule_resource_id = (
            _canonical_resource_id(rule_name)
            if rule_name is not None and rule_name.startswith("/")
            else None
        )
        return IpFlowVerifyResult(
            schemaVersion="athena.wc028IpFlowVerifyResult.v1",
            source="ipFlowVerify",
            requestDigest=request.request_digest,
            sourceIdentityId=self._reviewed_contract.collector_identity_resource_id,
            collectedAt=request.checked_at,
            checkedAt=request.checked_at,
            access=access,
            ruleResourceId=rule_resource_id,
            responseBytes=response_bytes,
            limitation="pointInTimeNotHistorical",
        )


class _AccessToken(Protocol):
    token: str
    expires_on: int


def _system_utc_now() -> datetime:
    value = datetime.now(UTC)
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


@dataclass(frozen=True, slots=True)
class _NormalizedIdentityClaims:
    key_id: str
    audience: str
    token_version: str
    identity_type: str
    roles: tuple[str, ...]
    subject: str
    principal_id: str
    tenant_id: str
    client_id: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime


def _validated_identity_claims(
    header: Mapping[str, object],
    claims: Mapping[str, object],
    *,
    expected_audience: str,
    expected_token_version: str,
    expected_role: str,
    expected_tenant_id: str,
    expected_principal_id: str,
    expected_client_id: str,
) -> _NormalizedIdentityClaims:
    kid = header.get("kid")
    audience = claims.get("aud")
    token_version = claims.get("ver")
    identity_type = claims.get("idtyp")
    roles = claims.get("roles")
    subject = claims.get("sub")
    principal_id = claims.get("oid")
    tenant_id = claims.get("tid")
    client_claims = tuple(
        value for value in (claims.get("appid"), claims.get("azp")) if value is not None
    )
    timestamp_claims = tuple(claims.get(name) for name in ("iat", "nbf", "exp"))
    if (
        header.get("alg") != "RS256"
        or header.get("typ") != "JWT"
        or not isinstance(kid, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{8,256}", kid) is None
        or not isinstance(audience, str)
        or audience != expected_audience
        or token_version != expected_token_version
        or identity_type != "app"
        or not isinstance(roles, list)
        or any(not isinstance(value, str) for value in roles)
        or tuple(sorted(roles)) != (expected_role,)
        or not isinstance(subject, str)
        or not isinstance(principal_id, str)
        or not isinstance(tenant_id, str)
        or not client_claims
        or any(not isinstance(value, str) for value in client_claims)
        or len({cast(str, value).casefold() for value in client_claims}) != 1
        or any(type(value) is not int for value in timestamp_claims)
    ):
        raise MonitoringAcquisitionError("Athena identity proof token claims are invalid")
    client_id = cast(str, client_claims[0]).casefold()
    principal_id = principal_id.casefold()
    tenant_id = tenant_id.casefold()
    subject = subject.casefold()
    if (
        tenant_id != expected_tenant_id
        or principal_id != expected_principal_id
        or client_id != expected_client_id
        or subject not in {expected_principal_id, expected_client_id}
    ):
        raise MonitoringAcquisitionError(
            "Athena identity proof does not match the reviewed collector identity"
        )
    return _NormalizedIdentityClaims(
        key_id=kid,
        audience=audience,
        token_version=cast(str, token_version),
        identity_type=cast(str, identity_type),
        roles=tuple(sorted(cast(list[str], roles))),
        subject=subject,
        principal_id=principal_id,
        tenant_id=tenant_id,
        client_id=client_id,
        issued_at=datetime.fromtimestamp(cast(int, claims["iat"]), tz=UTC),
        not_before=datetime.fromtimestamp(cast(int, claims["nbf"]), tz=UTC),
        expires_at=datetime.fromtimestamp(cast(int, claims["exp"]), tz=UTC),
    )


def _verified_identity_proof(
    access_token: _AccessToken,
    *,
    reviewed_contract: MonitoringCollectorContract,
) -> MonitoringIdentityProof:
    token = access_token.token
    if (
        type(token) is not str
        or not token
        or token != token.strip()
        or len(token.encode("ascii", errors="ignore")) > _MAX_IDENTITY_PROOF_TOKEN_BYTES
        or _COMPACT_JWT_PATTERN.fullmatch(token) is None
    ):
        raise MonitoringAcquisitionError(
            "managed identity returned an invalid bounded Athena identity proof token"
        )
    expected_tenant_id = cast(str, reviewed_contract.collector_tenant_id).casefold()
    expected_principal_id = cast(
        str,
        reviewed_contract.monitoring_reader_principal_id,
    ).casefold()
    expected_client_id = reviewed_contract.collector_identity_client_id.casefold()
    expected_audience = cast(str, reviewed_contract.identity_proof_audience)
    expected_token_version = cast(str, reviewed_contract.identity_proof_token_version)
    expected_role = cast(str, reviewed_contract.identity_proof_required_role)
    expected_maximum_lifetime_seconds = cast(
        int,
        reviewed_contract.identity_proof_maximum_lifetime_seconds,
    )
    expected_issuer = f"https://sts.windows.net/{expected_tenant_id}/"
    try:
        header = jwt.get_unverified_header(token)
        signing_key = (
            jwt.PyJWKClient(
                f"https://login.microsoftonline.com/{expected_tenant_id}/discovery/keys",
                cache_keys=True,
            )
            .get_signing_key_from_jwt(token)
            .key
        )
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=expected_audience,
            issuer=expected_issuer,
            options={
                "require": [
                    "aud",
                    "exp",
                    "idtyp",
                    "iat",
                    "iss",
                    "nbf",
                    "oid",
                    "roles",
                    "sub",
                    "tid",
                    "ver",
                ],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except (jwt.PyJWTError, UnicodeError, ValueError, KeyError) as exc:
        raise MonitoringAcquisitionError(
            "Athena identity proof token cryptographic verification failed"
        ) from exc
    normalized = _validated_identity_claims(
        header,
        claims,
        expected_audience=expected_audience,
        expected_token_version=expected_token_version,
        expected_role=expected_role,
        expected_tenant_id=expected_tenant_id,
        expected_principal_id=expected_principal_id,
        expected_client_id=expected_client_id,
    )
    verified_at = _trusted_runtime_time(_system_utc_now())
    if (
        type(access_token.expires_on) is not int
        or access_token.expires_on != int(normalized.expires_at.timestamp())
        or not normalized.issued_at <= normalized.not_before <= verified_at < normalized.expires_at
        or (normalized.expires_at - normalized.issued_at).total_seconds()
        > expected_maximum_lifetime_seconds
        or (normalized.expires_at - verified_at).total_seconds()
        < _MIN_IDENTITY_PROOF_TOKEN_REMAINING_SECONDS
    ):
        raise MonitoringAcquisitionError("Athena identity proof token is outside its lifetime")
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringIdentityProof.v1",
        "tokenVersion": normalized.token_version,
        "tenantId": normalized.tenant_id,
        "principalId": normalized.principal_id,
        "clientId": normalized.client_id,
        "subject": normalized.subject,
        "issuer": expected_issuer,
        "audience": normalized.audience,
        "identityType": normalized.identity_type,
        "roles": normalized.roles,
        "tokenHash": sha256_hex(token.encode("ascii")),
        "keyId": normalized.key_id,
        "issuedAt": normalized.issued_at,
        "notBefore": normalized.not_before,
        "expiresAt": normalized.expires_at,
        "verifiedAt": verified_at,
    }
    return MonitoringIdentityProof.model_validate(
        {
            **payload,
            "proofDigest": compute_artifact_digest(_json_value(payload)),
        }
    )


@dataclass(frozen=True, slots=True)
class _AzureMonitoringClients:
    log_analytics: MonitoringLogAnalyticsClient
    activity_log: MonitoringActivityLogClient
    resource_graph: MonitoringResourceGraphClient
    resource_health: MonitoringResourceHealthClient
    ip_flow_verify: MonitoringIpFlowVerifyClient


type _AzureMonitoringClientFactory = Callable[
    [ManagedIdentityCredential, MonitoringCollectorContract],
    _AzureMonitoringClients,
]


def _production_azure_monitoring_clients(
    credential: ManagedIdentityCredential,
    reviewed_contract: MonitoringCollectorContract,
) -> _AzureMonitoringClients:
    return _AzureMonitoringClients(
        log_analytics=AzureLogAnalyticsAcquisitionClient(
            credential=credential,
            reviewed_contract=reviewed_contract,
        ),
        activity_log=AzureActivityLogAcquisitionClient(
            credential=credential,
            reviewed_contract=reviewed_contract,
        ),
        resource_graph=AzureResourceGraphAcquisitionClient(
            credential=credential,
            reviewed_contract=reviewed_contract,
        ),
        resource_health=AzureResourceHealthAcquisitionClient(
            credential=credential,
            reviewed_contract=reviewed_contract,
        ),
        ip_flow_verify=AzureIpFlowVerifyAcquisitionClient(
            credential=credential,
            reviewed_contract=reviewed_contract,
        ),
    )


class AzureMonitoringAdapter:
    """Production-only composition root for one managed identity and all Azure clients."""

    def __init__(
        self,
        *,
        reviewed_collector_contract: MonitoringCollectorContract,
    ) -> None:
        if type(reviewed_collector_contract) is not MonitoringCollectorContract:
            raise TypeError("Azure monitoring acquisition requires an exact collector contract")
        self._reviewed_contract = MonitoringCollectorContract.model_validate_json(
            reviewed_collector_contract.model_dump_json(by_alias=True)
        )
        if (
            self._reviewed_contract.schema_version
            != MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION
        ):
            raise MonitoringAcquisitionError(
                "Azure monitoring acquisition requires collector contract schema v7"
            )
        self._credential = ManagedIdentityCredential(
            client_id=self._reviewed_contract.collector_identity_client_id
        )
        self._client_factory: _AzureMonitoringClientFactory = _production_azure_monitoring_clients
        self._identity_proof: MonitoringIdentityProof | None = None
        self._clients: _AzureMonitoringClients | None = None

    @property
    def reviewed_collector_contract(self) -> MonitoringCollectorContract:
        return self._reviewed_contract

    def utc_now(self) -> datetime:
        return _trusted_runtime_time(_system_utc_now())

    def verify_identity(self) -> MonitoringIdentityProof:
        self._identity_proof = None
        proof_scope = f"{cast(str, self._reviewed_contract.identity_proof_audience)}/.default"
        try:
            proof = _verified_identity_proof(
                self._credential.get_token(proof_scope),
                reviewed_contract=self._reviewed_contract,
            )
        except MonitoringAcquisitionError:
            raise
        except Exception as exc:
            raise MonitoringAcquisitionError(
                "managed identity proof acquisition failed before Azure monitoring I/O"
            ) from exc
        if self._clients is None:
            self._clients = self._client_factory(
                self._credential,
                self._reviewed_contract,
            )
        self._identity_proof = proof
        return proof

    def _verified_clients(self) -> _AzureMonitoringClients:
        if self._identity_proof is None or self._clients is None:
            raise MonitoringAcquisitionError(
                "Azure monitoring adapter identity was not verified before source I/O"
            )
        return self._clients

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult:
        return self._verified_clients().log_analytics.query_log_analytics(request)

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult:
        return self._verified_clients().activity_log.query_activity_log(request)

    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult:
        return self._verified_clients().resource_graph.query_resource_graph_changes(request)

    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult:
        return self._verified_clients().resource_health.query_resource_health(request)

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult:
        return self._verified_clients().ip_flow_verify.query_ip_flow_verify(request)


class MonitoringAcquisitionReceiptSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


@dataclass(slots=True)
class _AcquisitionExecution:
    adapter: AzureMonitoringAdapter
    identity_proof: MonitoringIdentityProof
    max_calls: int
    max_freshness_seconds: int
    started_at: datetime
    exchanges: list[MonitoringAcquisitionExchange]

    def _capture_call_start(
        self,
        requested_at_override: datetime | None,
    ) -> datetime:
        if len(self.exchanges) >= self.max_calls:
            raise MonitoringAcquisitionError(
                "monitoring acquisition exceeded its total call budget"
            )
        requested_at = self.adapter.utc_now()
        if (
            requested_at < self.started_at
            or requested_at >= self.identity_proof.expires_at
            or (requested_at - self.started_at).total_seconds() > self.max_freshness_seconds
        ):
            raise MonitoringAcquisitionError(
                "verified monitoring credential is stale before Azure source I/O"
            )
        if (
            requested_at_override is not None
            and _trusted_runtime_time(requested_at_override) != requested_at
        ):
            raise MonitoringAcquisitionError(
                "caller-supplied acquisition time does not equal live call start"
            )
        return requested_at

    def _invoke_at[
        RequestT: _AcquisitionRequest,
        ResultT: _StrictAcquisitionModel,
    ](
        self,
        request: RequestT,
        operation: Callable[[RequestT], ResultT],
        *,
        requested_at: datetime,
    ) -> ResultT:
        checked_at = request.checked_at if isinstance(request, IpFlowVerifyRequest) else None
        if checked_at is not None and checked_at != requested_at:
            raise MonitoringAcquisitionError(
                "IP Flow checkedAt must equal the collector-owned call start"
            )
        result = operation(request)
        received_at = self.adapter.utc_now()
        if received_at < requested_at:
            raise MonitoringAcquisitionError("collector runtime returned non-monotonic time")
        source = cast(AcquisitionSource, request.source)
        self.exchanges.append(
            MonitoringAcquisitionExchange(
                sequence=len(self.exchanges) + 1,
                source=source,
                requestDigest=request.request_digest,
                resultDigest=sha256_hex(result.canonical_bytes()),
                requestedAt=requested_at,
                receivedAt=received_at,
                checkedAt=checked_at,
                identityProofDigest=self.identity_proof.proof_digest,
            )
        )
        return result

    def invoke[RequestT: _AcquisitionRequest, ResultT: _StrictAcquisitionModel](
        self,
        request: RequestT,
        operation: Callable[[RequestT], ResultT],
        *,
        requested_at_override: datetime | None = None,
    ) -> ResultT:
        return self._invoke_at(
            request,
            operation,
            requested_at=self._capture_call_start(requested_at_override),
        )

    def invoke_with_call_start[
        RequestT: _AcquisitionRequest,
        ResultT: _StrictAcquisitionModel,
    ](
        self,
        request_factory: Callable[[datetime], RequestT],
        operation: Callable[[RequestT], ResultT],
    ) -> tuple[RequestT, ResultT]:
        requested_at = self._capture_call_start(None)
        request = request_factory(requested_at)
        return request, self._invoke_at(
            request,
            operation,
            requested_at=requested_at,
        )


@dataclass(frozen=True, slots=True)
class MonitoringAcquisitionOutcome:
    batch: MonitoringCollectionBatch
    prepared: PreparedMonitoringCollection
    committed: CommittedMonitoringCollection
    correlation_request: CorrelationRequest
    manual_investigation_reasons: tuple[str, ...]


def _build_request[RequestT: _AcquisitionRequest](
    model: type[RequestT],
    payload: dict[str, object],
) -> RequestT:
    return model.model_validate(
        {
            **payload,
            "requestDigest": compute_artifact_digest(_json_value(payload)),
        }
    )


def _source_table(signal: LogQueryMonitoringSignal) -> str:
    match = re.match(r"^[A-Za-z][A-Za-z0-9_]*", signal.query)
    table = "" if match is None else match.group(0)
    if table not in _LOG_COLUMNS:
        raise MonitoringAcquisitionError(
            "published log query does not use a supported reviewed source table"
        )
    return table


def _resource_is_contract_published(
    resource_id: str,
    contract: MonitoringCollectorContract,
) -> bool:
    normalized = _canonical_resource_id(resource_id)
    exact_scopes = {
        contract.workspace_resource_id.casefold().rstrip("/"),
        contract.data_collection_rule_resource_id.casefold().rstrip("/"),
        contract.data_collection_endpoint_resource_id.casefold().rstrip("/"),
        contract.workload_virtual_network_resource_id.casefold().rstrip("/"),
        *(item.casefold().rstrip("/") for item in contract.signal_read_scope_ids),
        *(item.casefold().rstrip("/") for item in contract.resource_read_scope_ids),
        *(
            item.casefold().rstrip("/")
            for item in cast(tuple[str, ...], contract.resource_health_scope_ids)
        ),
        cast(str, contract.ip_flow_verify_scope_id).casefold().rstrip("/"),
    }
    return (
        normalized in exact_scopes
        or _resource_is_within(normalized, contract.workload_resource_group_id)
        or _resource_is_within(normalized, contract.monitoring_resource_group_id)
    )


def _required_control_authority_scope(
    controls: tuple[PublishedMonitoringIntentControl, ...],
    contract: MonitoringCollectorContract,
) -> tuple[tuple[AcquisitionSource, ...], tuple[str, ...]]:
    required_sources: set[AcquisitionSource] = set()
    required_resources: set[str] = set()
    signal_scopes = {item.casefold().rstrip("/") for item in contract.signal_read_scope_ids}
    health_scopes = {
        item.casefold().rstrip("/")
        for item in cast(tuple[str, ...], contract.resource_health_scope_ids)
    }
    for control in controls:
        control_resources = {
            *control.scope.resource_ids,
            *(control.scope.evidence_resource_ids or ()),
        }
        signal = control.signal
        if isinstance(signal, LogQueryMonitoringSignal):
            table = _source_table(signal)
            query_target = _canonical_resource_id(signal.query_target_resource_id)
            required_sources.add("logAnalytics")
            required_resources.add(query_target)
            if query_target not in signal_scopes:
                raise MonitoringAcquisitionError(
                    "log query target is outside exact collector VM scopes"
                )
            if table == "NTANetAnalytics":
                required_sources.add("ipFlowVerify")
            for resource_id in control.scope.resource_ids:
                normalized = _canonical_resource_id(resource_id)
                if _is_virtual_machine_resource_id(normalized):
                    if normalized not in signal_scopes:
                        raise MonitoringAcquisitionError(
                            "log control references a VM outside collector signal scopes"
                        )
                elif not _resource_is_within(
                    normalized,
                    contract.workload_resource_group_id,
                ):
                    raise MonitoringAcquisitionError(
                        "log control resource is outside the reviewed workload scope"
                    )
            for resource_id in control.scope.evidence_resource_ids or ():
                normalized = _canonical_resource_id(resource_id)
                if not _resource_is_within(
                    normalized,
                    contract.monitoring_resource_group_id,
                ):
                    raise MonitoringAcquisitionError(
                        "log evidence resource is outside the reviewed monitoring scope"
                    )
        elif isinstance(signal, ActivityLogMonitoringSignal):
            required_sources.update({"activityLog", "resourceGraph"})
            if any(
                not _resource_is_within(
                    resource_id,
                    contract.workload_resource_group_id,
                )
                for resource_id in control.scope.resource_ids
            ):
                raise MonitoringAcquisitionError(
                    "change control is outside the reviewed workload scope"
                )
        elif isinstance(signal, ResourceHealthMonitoringSignal):
            required_sources.add("resourceHealth")
            if set(control.scope.resource_ids) - health_scopes:
                raise MonitoringAcquisitionError(
                    "Resource Health control is outside exact approved VM scopes"
                )
        else:
            raise MonitoringAcquisitionError(
                "published monitoring signal has no reviewed acquisition source"
            )
        if any(
            not _resource_is_contract_published(resource_id, contract)
            for resource_id in control_resources
        ):
            raise MonitoringAcquisitionError(
                "monitoring control references an unpublished collector scope"
            )
        required_resources.update(_canonical_resource_id(item) for item in control_resources)
    return tuple(sorted(required_sources)), tuple(sorted(required_resources))


def _control_binding_matches(
    control: PublishedMonitoringIntentControl,
    binding: MonitoringAcquisitionControlBinding,
) -> bool:
    scope = binding.coverage_scope
    if (
        binding.control_id != control.control_id
        or binding.control_digest != control.control_digest
        or binding.scope_digest != control.scope.scope_digest
        or scope.query_scope_digest != control.control_digest
        or scope.resource_ids != control.scope.resource_ids
        or (scope.path_id is not None and scope.path_id not in control.scope.path_ids)
    ):
        return False
    signal = control.signal
    if isinstance(signal, LogQueryMonitoringSignal):
        table = _source_table(signal)
        if table == "Heartbeat":
            return (
                scope.path_id is None
                and scope.direction is None
                and scope.five_tuple_digest is None
                and scope.endpoint_test_reference is None
                and scope.endpoint_test_digest is None
            )
        if table == "VMConnection":
            return (
                scope.path_id is not None
                and scope.direction is None
                and scope.five_tuple_digest is None
                and scope.endpoint_test_reference is None
                and scope.endpoint_test_digest is None
            )
        if table == "NWConnectionMonitorTestResult":
            return (
                scope.path_id is not None
                and scope.direction is not None
                and scope.five_tuple_digest is not None
                and scope.endpoint_test_reference is not None
                and scope.endpoint_test_digest is not None
            )
        return (
            table == "NTANetAnalytics"
            and scope.path_id is not None
            and scope.direction is not None
            and scope.five_tuple_digest is not None
            and scope.endpoint_test_reference is None
            and scope.endpoint_test_digest is None
        )
    if isinstance(signal, ResourceHealthMonitoringSignal):
        expected_path = control.scope.path_ids[0] if len(control.scope.path_ids) == 1 else None
        return (
            scope.path_id == expected_path
            and scope.direction is None
            and scope.five_tuple_digest is None
            and scope.endpoint_test_reference is None
            and scope.endpoint_test_digest is None
        )
    return False


def _record_id(prefix: str, request_digest: str, row: AthenaBaseModel) -> str:
    digest = compute_artifact_digest(
        {
            "requestDigest": request_digest,
            "row": row.model_dump(mode="json", by_alias=True, exclude_none=True),
        }
    )
    return f"{prefix}-{digest.removeprefix('sha256:')[:32]}"


def _query_execution_digest(
    *,
    control: PublishedMonitoringIntentControl,
    source_record_id: str,
    observed_start: datetime,
    observed_end: datetime,
) -> str:
    signal = control.signal
    if not isinstance(signal, LogQueryMonitoringSignal):
        raise MonitoringAcquisitionError("query execution requires a log-query control")
    return compute_monitoring_query_execution_digest(
        control_id=control.control_id,
        source_record_id=source_record_id,
        query_digest=signal.query_digest,
        query_target_resource_id=signal.query_target_resource_id,
        observed_start=observed_start,
        observed_end=observed_end,
        evaluation_window_seconds=signal.evaluation_window_seconds,
        frequency_seconds=signal.frequency_seconds,
    )


def _require_control_scope(
    control: PublishedMonitoringIntentControl,
    *resource_ids: str,
    evidence: bool = False,
) -> tuple[str, ...]:
    normalized = tuple(_canonical_resource_id(item) for item in resource_ids)
    allowed = control.scope.evidence_resource_ids or () if evidence else control.scope.resource_ids
    if not set(normalized).issubset(allowed):
        scope_kind = "evidence" if evidence else "workload"
        raise MonitoringAcquisitionError(
            f"source row escapes the published {scope_kind} resource scope"
        )
    return normalized


def _require_control_path(
    control: PublishedMonitoringIntentControl,
    path_id: str,
) -> None:
    if path_id not in control.scope.path_ids:
        raise MonitoringAcquisitionError("source row escapes the published dependency-path scope")


def _coverage_scope_digest(
    record: MonitoringCoverageRecord,
    control: PublishedMonitoringIntentControl,
) -> str:
    return compute_artifact_digest(
        _json_value(
            {
                "resourceIds": tuple(
                    sorted(_canonical_resource_id(item) for item in record.resource_ids)
                ),
                "pathId": record.path_id,
                "direction": record.direction,
                "fiveTupleDigest": record.five_tuple_digest,
                "endpointTestReference": record.endpoint_test_reference,
                "endpointTestDigest": record.endpoint_test_digest,
                "queryScopeDigest": control.control_digest,
            }
        )
    )


def _record_scope_resources(record: MonitoringCollectionRecord) -> set[str]:
    if isinstance(record, AmaHeartbeatRecord):
        return {_canonical_resource_id(record.resource_id)}
    if isinstance(record, VmConnectionHealthRecord):
        return {
            _canonical_resource_id(record.subject_resource_id),
            *(_canonical_resource_id(item) for item in record.backend_resource_ids),
        }
    if isinstance(record, ConnectionMonitorRecord):
        return {
            _canonical_resource_id(record.source_resource_id),
            _canonical_resource_id(record.destination_resource_id),
        }
    if isinstance(record, NetworkWatcherFlowRecord):
        resources = {
            _canonical_resource_id(record.subject_resource_id),
            _canonical_resource_id(record.source_resource_id),
            _canonical_resource_id(record.destination_resource_id),
            _canonical_resource_id(record.enforcement_resource_id),
        }
        if record.rule_resource_id is not None:
            resources.add(_canonical_resource_id(record.rule_resource_id))
        if record.ip_flow_rule_resource_id is not None:
            resources.add(_canonical_resource_id(record.ip_flow_rule_resource_id))
        return resources
    if isinstance(record, ResourceHealthRecord):
        return {_canonical_resource_id(record.resource_id)}
    return set()


def _validate_result(
    result: _AcquisitionResult,
    request: _AcquisitionRequest,
    *,
    collector_collection_time: datetime,
    expected_columns: tuple[str, ...],
) -> None:
    if result.request_digest != request.request_digest:
        raise MonitoringAcquisitionError("source response does not bind the exact request")
    expected_collection_time = (
        request.collector_execution_time
        if isinstance(request, LogAnalyticsQueryRequest)
        and request.schema_version == "athena.wc028LogAnalyticsQueryRequest.v2"
        else collector_collection_time
    )
    if result.collected_at != expected_collection_time:
        raise MonitoringAcquisitionError(
            "source response time claim conflicts with the collector clock"
        )
    if (
        isinstance(request, LogAnalyticsQueryRequest)
        and request.schema_version == "athena.wc028LogAnalyticsQueryRequest.v2"
        and (
            not isinstance(result, LogAnalyticsQueryResult)
            or request.coverage_scope is None
            or result.coverage_descriptor != _log_coverage_descriptor(request.coverage_scope)
        )
    ):
        raise MonitoringAcquisitionError(
            "log response does not bind the authority-approved coverage scope"
        )
    if result.columns != expected_columns:
        raise MonitoringAcquisitionError("source response columns do not match the strict schema")
    rows = getattr(result, "rows", ())
    if not isinstance(rows, tuple) or len(rows) > request.max_rows:
        raise MonitoringAcquisitionError("source response exceeds its row bound")
    if result.response_bytes > request.max_bytes:
        raise MonitoringAcquisitionError("source response exceeds its declared byte bound")
    if len(result.canonical_bytes()) > MAX_ACQUISITION_RESPONSE_BYTES:
        raise MonitoringAcquisitionError("source response exceeds its canonical byte bound")


def _validate_row_window(
    row: _WindowedRow,
    request: _AcquisitionRequest,
    *,
    exact: bool,
) -> None:
    if row.observed_start < request.window_start or row.observed_end > request.window_end:
        raise MonitoringAcquisitionError("source row escapes the authorized time window")
    if exact and (
        row.observed_start != request.window_start or row.observed_end != request.window_end
    ):
        raise MonitoringAcquisitionError("log query row does not cover the exact published window")


def _has_positive_aggregate_completeness(
    result: LogAnalyticsQueryResult,
    request: LogAnalyticsQueryRequest,
    *,
    collector_collection_time: datetime,
) -> bool:
    proof = result.aggregate_completeness_proof
    if proof is None:
        return False
    if result.truncated:
        return False
    if (
        proof.window_start != request.window_start
        or proof.window_end != request.window_end
        or proof.request_digest != request.request_digest
        or proof.query_digest != request.query_digest
    ):
        raise MonitoringAcquisitionError(
            "aggregate completeness proof does not bind the exact query execution"
        )
    return proof.ingestion_complete_through <= collector_collection_time


def _validate_ip_flow_result(
    result: IpFlowVerifyResult,
    request: IpFlowVerifyRequest,
    *,
    collector_collection_time: datetime,
) -> None:
    if result.request_digest != request.request_digest:
        raise MonitoringAcquisitionError("IP Flow Verify response does not bind the exact request")
    if result.collected_at != collector_collection_time:
        raise MonitoringAcquisitionError(
            "IP Flow Verify time claim conflicts with the collector clock"
        )
    if result.checked_at != request.checked_at:
        raise MonitoringAcquisitionError("IP Flow Verify response is stale")
    if result.response_bytes > request.max_bytes:
        raise MonitoringAcquisitionError("IP Flow Verify response exceeds its byte bound")
    if len(result.canonical_bytes()) > request.max_bytes:
        raise MonitoringAcquisitionError("IP Flow Verify response exceeds its canonical byte bound")


def _coverage_status(
    *,
    rows_present: bool,
    truncated: bool,
    partial: bool,
    limitations: tuple[str, ...] = (),
) -> tuple[Literal["complete", "partial", "unavailable", "truncated"], str | None]:
    reasons = list(limitations)
    if not rows_present:
        if truncated:
            reasons.append("source response was truncated")
        reasons.append("source returned no data or no usable unambiguous data")
        status: Literal["complete", "partial", "unavailable", "truncated"] = "unavailable"
    elif truncated:
        reasons.append("source response was truncated")
        status = "truncated"
    elif partial:
        status = "partial"
    else:
        status = "complete"
    if status == "complete":
        return status, None
    return status, "manual investigation required: " + "; ".join(sorted(set(reasons)))


def _condition(
    control: PublishedMonitoringIntentControl,
    value: int | None,
) -> bool | None:
    signal = control.signal
    if not isinstance(signal, LogQueryMonitoringSignal):
        return None
    if value is None:
        if control.missing_data_behavior in {"failClosed", "treatAsUnhealthy"}:
            return True
        if control.missing_data_behavior == "treatAsHealthy":
            return False
        return None
    if signal.operator == "greaterThan":
        return value > signal.threshold
    if signal.operator == "greaterThanOrEqual":
        return value >= signal.threshold
    if signal.operator == "lessThan":
        return value < signal.threshold
    if signal.operator == "lessThanOrEqual":
        return value <= signal.threshold
    return value == signal.threshold


def _health_state(
    record: MonitoringCollectionRecord,
    control: PublishedMonitoringIntentControl,
) -> _HealthState | None:
    if isinstance(record, AmaHeartbeatRecord):
        result = _condition(control, record.heartbeat_count)
        return None if result is None else "unhealthy" if result else "healthy"
    if isinstance(record, VmConnectionHealthRecord):
        result = _condition(control, record.failed_connection_count)
        return None if result is None else "unhealthy" if result else "healthy"
    if isinstance(record, ResourceHealthRecord):
        return cast(
            Literal["healthy", "degraded", "unavailable"] | None,
            {
                "Available": "healthy",
                "Degraded": "degraded",
                "Unavailable": "unavailable",
                "Unknown": None,
            }[record.current_status],
        )
    return None


def _incident_sample_binding(
    source_record_id: str,
    *,
    batch: MonitoringCollectionBatch,
    prepared: PreparedMonitoringCollection,
    controls: Mapping[str, PublishedMonitoringIntentControl],
) -> MonitoringIncidentHealthSampleBinding:
    records = {
        item.source_record_id: item
        for item in batch.records
        if isinstance(
            item,
            (
                AmaHeartbeatRecord,
                VmConnectionHealthRecord,
                ResourceHealthRecord,
            ),
        )
    }
    try:
        record = records[source_record_id]
        control = controls[record.control_id]
    except KeyError as exc:
        raise MonitoringAcquisitionError(
            "signed incident selection references an unknown health record"
        ) from exc
    if isinstance(record, AmaHeartbeatRecord):
        record_kind: Literal[
            "amaHeartbeat",
            "vmConnectionHealth",
            "resourceHealth",
        ] = "amaHeartbeat"
        resource_id = record.resource_id
    elif isinstance(record, VmConnectionHealthRecord):
        record_kind = "vmConnectionHealth"
        resource_id = record.subject_resource_id
    else:
        record_kind = "resourceHealth"
        resource_id = record.resource_id
    state = _health_state(record, control)
    if state is None:
        raise MonitoringAcquisitionError(
            "signed incident selection cannot reference unknown health"
        )
    source_reference = monitoring_health_source_record_reference(
        record_kind,
        source_record_id,
    )
    observations: tuple[MonitoringObservation, ...] = tuple(
        item
        for item in prepared.monitoring_bundle.observations
        if item.source_record_reference == source_reference
    )
    if len(observations) != 1:
        raise MonitoringAcquisitionError(
            "signed incident health record must map to exactly one persisted observation"
        )
    observation = observations[0]
    provenance = observation.control_provenance
    if (
        observation.subject_resource_id != _canonical_resource_id(resource_id)
        or observation.observed_start != record.observed_start
        or observation.observed_end != record.observed_end
        or provenance is None
        or provenance.control_id != record.control_id
    ):
        raise MonitoringAcquisitionError(
            "signed incident health record does not match persisted observation"
        )
    payload: dict[str, object] = {
        "recordKind": record_kind,
        "sourceRecordId": source_record_id,
        "sourceRecordReference": source_reference,
        "observationId": observation.observation_id,
        "controlId": record.control_id,
        "resourceId": resource_id,
        "state": state,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
    }
    return MonitoringIncidentHealthSampleBinding.model_validate(
        {
            **payload,
            "sampleDigest": compute_artifact_digest(_json_value(payload)),
        }
    )


def _signed_incident_selection(
    *,
    batch: MonitoringCollectionBatch,
    prepared: PreparedMonitoringCollection,
    monitoring_intent: PublishedMonitoringIntent,
) -> SignedMonitoringIncidentSelection:
    controls = {item.control_id: item for item in monitoring_intent.controls}
    previous = _incident_sample_binding(
        prepared.previous_health_source_record_id,
        batch=batch,
        prepared=prepared,
        controls=controls,
    )
    current = tuple(
        sorted(
            (
                _incident_sample_binding(
                    source_record_id,
                    batch=batch,
                    prepared=prepared,
                    controls=controls,
                )
                for source_record_id in prepared.current_health_source_record_ids
            ),
            key=lambda item: (
                item.source_record_reference,
                item.observation_id,
            ),
        )
    )
    payload: dict[str, object] = {
        "incidentResourceId": prepared.incident_resource_id,
        "previousHealth": previous,
        "currentHealth": current,
    }
    return SignedMonitoringIncidentSelection.model_validate(
        {
            **payload,
            "transitionDigest": compute_artifact_digest(_json_value(payload)),
        }
    )


def _activity_key(
    row: ActivityLogRow | ResourceGraphChangeRow,
) -> tuple[str, str, datetime, str, str]:
    return (
        row.target_resource_id,
        row.correlation_id,
        row.occurred_at,
        row.operation_name.casefold(),
        row.result_type.casefold(),
    )


def _change_introduces_deny(record: ResourceChangeRecord) -> bool:
    properties = record.resource_graph_change.get("properties")
    if not isinstance(properties, dict):
        return False
    changes = properties.get("changes")
    if not isinstance(changes, dict):
        return False
    access = changes.get("properties.access")
    if not isinstance(access, dict):
        return False
    previous = access.get("previousValue")
    current = access.get("newValue")
    return (
        isinstance(previous, str)
        and previous.casefold() == "allow"
        and isinstance(current, str)
        and current.casefold() == "deny"
    )


class MonitoringAcquisitionCoordinator:
    """Acquire one complete reviewed evidence set before entering atomic persistence."""

    def __init__(
        self,
        *,
        acquisition_adapter: AzureMonitoringAdapter,
        acquisition_authority: MonitoringAcquisitionAuthority,
        expected_acquisition_authority_digest: str,
        expected_collector_contract_digest: str,
        monitoring_intent_trusted_key_id: str,
        monitoring_intent_signature_verifier: Callable[[bytes, str], bool],
        monitoring_intent_asset_loader: Callable[
            [PublishedMonitoringIntent],
            tuple[
                PublishedMonitoringIntentAssetReference,
                PublishedMonitoringIntentAttestation,
            ],
        ],
        collection_transaction: MonitoringCollectionTransaction,
        receipt_signer: MonitoringAcquisitionReceiptSigner,
    ) -> None:
        if type(acquisition_adapter) is not AzureMonitoringAdapter:
            raise TypeError("production acquisition requires the exact Azure monitoring adapter")
        self._acquisition_adapter = acquisition_adapter
        self._collector_contract = acquisition_adapter.reviewed_collector_contract
        self._collector_contract_digest = self._collector_contract.compute_artifact_digest_value()
        if self._collector_contract_digest != expected_collector_contract_digest:
            raise MonitoringAcquisitionError(
                "monitoring collector contract is not the configured reviewed contract"
            )
        try:
            self._acquisition_authority = MonitoringAcquisitionAuthority.model_validate_json(
                acquisition_authority.model_dump_json(by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise MonitoringAcquisitionError(str(exc)) from exc
        if type(acquisition_authority) is not MonitoringAcquisitionAuthority:
            raise TypeError("acquisition requires an exact monitoring acquisition authority")
        if self._acquisition_authority.authority_digest != (expected_acquisition_authority_digest):
            raise MonitoringAcquisitionError(
                "monitoring acquisition authority is not the configured authority"
            )
        if (
            self._acquisition_authority.schema_version
            != "athena.wc028MonitoringAcquisitionAuthority.v5"
        ):
            raise MonitoringAcquisitionError(
                "Athena-proven acquisition requires authority schema v5"
            )
        effective_rbac_inventory = self._collector_contract.effective_rbac_inventory
        if (
            effective_rbac_inventory is None
            or self._acquisition_authority.collector_contract_digest
            != self._collector_contract_digest
            or self._acquisition_authority.monitoring_reader_identity_id
            != self._collector_contract.collector_identity_resource_id.casefold().rstrip("/")
            or self._acquisition_authority.monitoring_reader_principal_id
            != self._collector_contract.monitoring_reader_principal_id
            or self._acquisition_authority.monitoring_reader_client_id
            != self._collector_contract.collector_identity_client_id
            or self._acquisition_authority.monitoring_reader_tenant_id
            != self._collector_contract.collector_tenant_id
            or self._acquisition_authority.athena_context_identity_id
            != cast(str, self._collector_contract.athena_context_identity_id).casefold().rstrip("/")
            or self._acquisition_authority.athena_context_principal_id
            != self._collector_contract.athena_context_principal_id
            or self._acquisition_authority.receipt_signing_key_id
            != self._collector_contract.signing_key_resource_id
            or self._acquisition_authority.identity_proof_audience
            != self._collector_contract.identity_proof_audience
            or self._acquisition_authority.identity_proof_token_version
            != self._collector_contract.identity_proof_token_version
            or self._acquisition_authority.identity_proof_required_role
            != self._collector_contract.identity_proof_required_role
            or self._acquisition_authority.identity_proof_maximum_lifetime_seconds
            != self._collector_contract.identity_proof_maximum_lifetime_seconds
            or self._acquisition_authority.effective_rbac_inventory_digest
            != effective_rbac_inventory.inventory_digest
            or self._acquisition_authority.effective_rbac_source_manifest_digest
            != effective_rbac_inventory.source_manifest_digest
            or any(
                not _resource_is_contract_published(
                    resource_id,
                    self._collector_contract,
                )
                for resource_id in self._acquisition_authority.allowed_resource_ids
            )
        ):
            raise MonitoringAcquisitionError(
                "acquisition authority does not bind the reviewed credential contract"
            )
        self._monitoring_reader_identity_id = (
            self._acquisition_authority.monitoring_reader_identity_id
        )
        self._monitoring_intent_trusted_key_id = monitoring_intent_trusted_key_id
        self._monitoring_intent_signature_verifier = monitoring_intent_signature_verifier
        self._monitoring_intent_asset_loader = monitoring_intent_asset_loader
        self._collection_transaction = collection_transaction
        self._receipt_signer = receipt_signer

    def _build_receipt(
        self,
        *,
        execution: _AcquisitionExecution,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        batch: MonitoringCollectionBatch,
        prepared: PreparedMonitoringCollection,
        collection_batch_digest: str,
        normalized_evidence_digest: str,
    ) -> MonitoringAcquisitionReceipt:
        execution_completed_at = execution.adapter.utc_now()
        receipt_issued_at = execution.adapter.utc_now()
        if (
            execution_completed_at < execution.started_at
            or receipt_issued_at < execution_completed_at
        ):
            raise MonitoringAcquisitionError("collector runtime returned non-monotonic time")
        identity_proof = execution.identity_proof
        payload: dict[str, object] = {
            "schemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
            "authenticatedPrincipalId": identity_proof.principal_id,
            "authenticatedClientId": identity_proof.client_id,
            "authenticatedTenantId": identity_proof.tenant_id,
            "monitoringReaderIdentityId": (
                self._acquisition_authority.monitoring_reader_identity_id
            ),
            "athenaContextIdentityId": self._acquisition_authority.athena_context_identity_id,
            "athenaContextPrincipalId": (self._acquisition_authority.athena_context_principal_id),
            "deploymentIdentityContractDigest": (
                cast(
                    str,
                    self._acquisition_authority.deployment_identity_contract_digest,
                )
            ),
            "acquisitionAuthorityDigest": self._acquisition_authority.authority_digest,
            "collectorContractDigest": self._acquisition_authority.collector_contract_digest,
            "intentId": monitoring_intent.intent_id,
            "intentDigest": monitoring_intent.intent_digest,
            "contextBindingDigest": context_binding.binding_digest,
            "collectionBatchDigest": collection_batch_digest,
            "normalizedEvidenceDigest": normalized_evidence_digest,
            "incidentSelection": _signed_incident_selection(
                batch=batch,
                prepared=prepared,
                monitoring_intent=monitoring_intent,
            ),
            "executionStartedAt": execution.started_at,
            "executionCompletedAt": execution_completed_at,
            "receiptIssuedAt": receipt_issued_at,
            "exchanges": tuple(execution.exchanges),
            "identityProof": identity_proof,
        }
        receipt_digest = compute_artifact_digest(_json_value(payload))
        signed_payload = {
            **payload,
            "receiptId": (
                f"monitoring-acquisition-receipt-{receipt_digest.removeprefix('sha256:')[:32]}"
            ),
            "receiptDigest": receipt_digest,
        }
        preimage = monitoring_acquisition_receipt_preimage(
            cast(dict[str, object], _json_value(signed_payload))
        )
        signature = self._receipt_signer.sign_preimage(canonicalize_json(preimage).encode("utf-8"))
        return MonitoringAcquisitionReceipt.model_validate(
            {
                **signed_payload,
                "collectorAttestation": MonitoringEvidenceAttestation(
                    signatureAlgorithm="RS256",
                    trustAnchorRef=cast(
                        str,
                        self._acquisition_authority.receipt_signing_key_id,
                    ),
                    signedPreimageDigest=compute_artifact_digest(preimage),
                    signature=signature,
                ),
            }
        )

    def execute(
        self,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        expected_active_context_authority_digest: str,
        collected_at: datetime,
        change_scope: ApprovedChangeScope,
        commit_port: MonitoringCollectionCommitPort,
        incident_revision: int,
        issued_at: datetime,
        trusted_as_of: datetime,
        expires_at: datetime,
    ) -> MonitoringAcquisitionOutcome:
        if type(monitoring_intent) is not PublishedMonitoringIntent:
            raise TypeError("acquisition requires an exact PublishedMonitoringIntent")
        if type(context_binding) is not PublishedRuntimeContextBinding:
            raise TypeError("acquisition requires an exact PublishedRuntimeContextBinding")
        del collected_at
        controls_by_id = {item.control_id: item for item in monitoring_intent.controls}
        required_control_ids = set(
            cast(
                tuple[str, ...],
                self._acquisition_authority.required_control_ids,
            )
        )
        if not required_control_ids.issubset(controls_by_id):
            raise MonitoringAcquisitionError(
                "acquisition authority references an unknown required control"
            )
        selected_controls = tuple(controls_by_id[item] for item in sorted(required_control_ids))
        required_control_bindings = cast(
            tuple[MonitoringAcquisitionControlBinding, ...],
            self._acquisition_authority.required_control_bindings,
        )
        bindings_by_id = {item.control_id: item for item in required_control_bindings}
        if (
            self._acquisition_authority.context_binding_digest != context_binding.binding_digest
            or self._acquisition_authority.required_coverage_scope_digests
            != context_binding.required_coverage_scope_digests
            or tuple(bindings_by_id) != tuple(control.control_id for control in selected_controls)
            or any(
                not _control_binding_matches(control, binding)
                for control, binding in (
                    (control, bindings_by_id[control.control_id]) for control in selected_controls
                )
            )
            or self._acquisition_authority.control_selection_digest
            != compute_monitoring_acquisition_control_selection_digest(
                context_binding,
                required_control_bindings,
            )
        ):
            raise MonitoringAcquisitionError(
                "acquisition authority does not bind the current context and control selection"
            )
        try:
            intent_reference, intent_attestation = self._monitoring_intent_asset_loader(
                monitoring_intent
            )
            if type(intent_reference) is not PublishedMonitoringIntentAssetReference:
                raise TypeError("acquisition requires an exact published intent reference")
            if type(intent_attestation) is not PublishedMonitoringIntentAttestation:
                raise TypeError("acquisition requires an exact published intent attestation")
            validate_published_monitoring_intent_assets(
                intent_reference,
                monitoring_intent,
                intent_attestation,
                trusted_key_id=self._monitoring_intent_trusted_key_id,
                signature_verifier=self._monitoring_intent_signature_verifier,
            )
            validate_monitoring_intent_activation_eligible(
                monitoring_intent,
                context_binding,
                expected_active_context_authority_digest=(expected_active_context_authority_digest),
            )
            required_sources, required_resources = _required_control_authority_scope(
                selected_controls,
                self._collector_contract,
            )
            if (
                self._acquisition_authority.allowed_resource_ids != required_resources
                or self._acquisition_authority.allowed_sources != required_sources
            ):
                raise MonitoringAcquisitionError(
                    "acquisition authority does not exactly match source-specific contract scope"
                )
        except (TypeError, ValueError) as exc:
            raise MonitoringAcquisitionError(
                "monitoring intent authority is invalid before acquisition"
            ) from exc

        effective_rbac_inventory = cast(
            MonitoringEffectiveRbacInventory,
            self._collector_contract.effective_rbac_inventory,
        )
        inventory_checked_at = self._acquisition_adapter.utc_now()
        if (
            effective_rbac_inventory.collected_at > inventory_checked_at
            or effective_rbac_inventory.expires_at <= inventory_checked_at
            or (inventory_checked_at - effective_rbac_inventory.collected_at).total_seconds()
            > self._acquisition_authority.max_freshness_seconds
        ):
            raise MonitoringAcquisitionError(
                "effective RBAC inventory is stale or invalid before credential acquisition"
            )
        identity_proof = self._acquisition_adapter.verify_identity()
        if (
            identity_proof.principal_id
            != self._acquisition_authority.monitoring_reader_principal_id
            or identity_proof.client_id != self._acquisition_authority.monitoring_reader_client_id
            or identity_proof.tenant_id != self._acquisition_authority.monitoring_reader_tenant_id
            or identity_proof.audience != self._acquisition_authority.identity_proof_audience
            or identity_proof.token_version
            != self._acquisition_authority.identity_proof_token_version
            or identity_proof.roles != (self._acquisition_authority.identity_proof_required_role,)
            or identity_proof.principal_id
            == self._acquisition_authority.athena_context_principal_id
        ):
            raise MonitoringAcquisitionError(
                "Athena identity proof violates acquisition identity policy"
            )
        if identity_proof.verified_at >= effective_rbac_inventory.expires_at:
            raise MonitoringAcquisitionError(
                "effective RBAC inventory expired before Azure source I/O"
            )
        collected_at = identity_proof.verified_at
        if (
            issued_at.utcoffset() != UTC.utcoffset(issued_at)
            or trusted_as_of.utcoffset() != UTC.utcoffset(trusted_as_of)
            or issued_at.microsecond % 1000
            or trusted_as_of.microsecond % 1000
            or not issued_at <= collected_at <= trusted_as_of
            or (trusted_as_of - collected_at).total_seconds()
            > self._acquisition_authority.max_freshness_seconds
        ):
            raise MonitoringAcquisitionError(
                "collection time is outside the acquisition authority freshness bound"
            )
        execution = _AcquisitionExecution(
            adapter=self._acquisition_adapter,
            identity_proof=identity_proof,
            max_calls=cast(int, self._acquisition_authority.max_acquisition_calls),
            max_freshness_seconds=self._acquisition_authority.max_freshness_seconds,
            started_at=collected_at,
            exchanges=[],
        )

        records: list[MonitoringCollectionRecord] = []
        coverage: list[MonitoringCoverageRecord] = []
        manual_reasons: list[str] = []
        attribution_changes: tuple[ResourceChangeRecord, ...] = ()
        if any(
            isinstance(control.signal, ActivityLogMonitoringSignal)
            for control in monitoring_intent.controls
        ):
            manual_reasons.append(
                "supporting control has no required coverage scope and was not executed"
            )

        try:
            for control in selected_controls:
                if isinstance(control.signal, LogQueryMonitoringSignal):
                    new_records, new_coverage, reasons = self._acquire_log_control(
                        control,
                        control_binding=bindings_by_id[control.control_id],
                        monitoring_intent=monitoring_intent,
                        collected_at=collected_at,
                        acquired_changes=attribution_changes,
                        execution=execution,
                    )
                    records.extend(new_records)
                    coverage.extend(new_coverage)
                    manual_reasons.extend(reasons)
                elif isinstance(control.signal, ResourceHealthMonitoringSignal):
                    new_records, health_coverage, reasons = self._acquire_health_control(
                        control,
                        monitoring_intent=monitoring_intent,
                        collected_at=collected_at,
                        trusted_as_of=trusted_as_of,
                        execution=execution,
                    )
                    records.extend(new_records)
                    coverage.append(health_coverage)
                    manual_reasons.extend(reasons)
                elif not isinstance(control.signal, ActivityLogMonitoringSignal):
                    raise MonitoringAcquisitionError(
                        "published monitoring signal has no reviewed acquisition source"
                    )
        except MonitoringAcquisitionError:
            raise
        except Exception as exc:
            raise MonitoringAcquisitionError(
                "monitoring source acquisition failed before transaction entry"
            ) from exc

        required_coverage = set(context_binding.required_coverage_scope_digests)
        selected_coverage = tuple(
            item
            for item in coverage
            if _coverage_scope_digest(item, controls_by_id[item.control_id]) in required_coverage
        )
        if {
            _coverage_scope_digest(item, controls_by_id[item.control_id])
            for item in selected_coverage
        } != required_coverage:
            raise MonitoringAcquisitionError(
                "acquired coverage does not satisfy the exact published runtime scope"
            )
        if len(selected_coverage) != len(coverage):
            raise MonitoringAcquisitionError(
                "executable monitoring controls must belong to required coverage scope"
            )
        required_control_ids = {item.control_id for item in selected_coverage}
        if required_control_ids != set(
            cast(
                tuple[str, ...],
                self._acquisition_authority.required_control_ids,
            )
        ):
            raise MonitoringAcquisitionError(
                "required controls and required coverage scope are not bound as one unit"
            )
        unit_records: list[MonitoringCollectionRecord] = []
        for item in records:
            if isinstance(item, ResourceChangeRecord):
                continue
            if item.control_id not in required_control_ids:
                continue
            if isinstance(item, NetworkWatcherFlowRecord) and (
                item.change_correlation_id is not None or item.attribution_evidence is not None
            ):
                item = item.model_copy(
                    update={
                        "change_correlation_id": None,
                        "attribution_method": None,
                        "attribution_evidence": None,
                    }
                )
                manual_reasons.append(
                    "direct change attribution was omitted because its supporting "
                    "control has no required coverage scope"
                )
            unit_records.append(item)

        previous_id, current_ids, incident_resource_id = self._select_incident(
            unit_records,
            controls_by_id,
        )
        batch = MonitoringCollectionBatch(
            schemaVersion="athena.wc028MonitoringCollectionBatch.v2",
            collectedAt=collected_at,
            incidentResourceId=incident_resource_id,
            previousHealthSourceRecordId=previous_id,
            currentHealthSourceRecordIds=current_ids,
            records=tuple(
                sorted(
                    unit_records,
                    key=lambda item: (
                        item.record_kind,
                        item.source_record_id,
                    ),
                )
            ),
            coverage=tuple(
                sorted(
                    selected_coverage,
                    key=lambda item: (
                        item.family,
                        item.control_id,
                        item.source_record_id,
                    ),
                )
            ),
        )
        preliminary = self._collection_transaction._prepare_receipt_candidate(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
            collector_contract_digest=self._collector_contract_digest,
            change_scope=change_scope,
            trusted_as_of=trusted_as_of,
        )
        acquisition_receipt = self._build_receipt(
            execution=execution,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            batch=batch,
            prepared=preliminary,
            collection_batch_digest=sha256_hex(batch.canonical_bytes()),
            normalized_evidence_digest=(
                preliminary.monitoring_bundle.compute_normalized_evidence_digest_value()
            ),
        )
        prepared, committed, correlation_request = self._collection_transaction.execute(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
            collector_contract_digest=self._collector_contract_digest,
            change_scope=change_scope,
            commit_port=commit_port,
            incident_revision=incident_revision,
            issued_at=issued_at,
            trusted_as_of=trusted_as_of,
            expires_at=expires_at,
            acquisition_receipt=acquisition_receipt,
        )
        return MonitoringAcquisitionOutcome(
            batch=batch,
            prepared=prepared,
            committed=committed,
            correlation_request=correlation_request,
            manual_investigation_reasons=tuple(sorted(set(manual_reasons))),
        )

    def _acquire_log_control(
        self,
        control: PublishedMonitoringIntentControl,
        *,
        control_binding: MonitoringAcquisitionControlBinding,
        monitoring_intent: PublishedMonitoringIntent,
        collected_at: datetime,
        acquired_changes: tuple[ResourceChangeRecord, ...],
        execution: _AcquisitionExecution,
    ) -> tuple[
        tuple[MonitoringCollectionRecord, ...],
        tuple[MonitoringCoverageRecord, ...],
        tuple[str, ...],
    ]:
        signal = cast(LogQueryMonitoringSignal, control.signal)
        table = _source_table(signal)
        current_start = collected_at - timedelta(seconds=signal.evaluation_window_seconds)
        windows = (
            (
                (
                    current_start - timedelta(seconds=signal.evaluation_window_seconds),
                    current_start,
                ),
                (current_start, collected_at),
            )
            if table in {"Heartbeat", "VMConnection"}
            else ((current_start, collected_at),)
        )
        requests = tuple(
            _build_request(
                LogAnalyticsQueryRequest,
                {
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "source": "logAnalytics",
                    "monitoringReaderIdentityId": self._monitoring_reader_identity_id,
                    "acquisitionAuthorityId": self._acquisition_authority.authority_id,
                    "acquisitionAuthorityDigest": (self._acquisition_authority.authority_digest),
                    "collectorContractDigest": (
                        self._acquisition_authority.collector_contract_digest
                    ),
                    "intentId": monitoring_intent.intent_id,
                    "intentDigest": monitoring_intent.intent_digest,
                    "controlId": control.control_id,
                    "controlDigest": control.control_digest,
                    "scopeDigest": control.scope.scope_digest,
                    "windowStart": window_start,
                    "windowEnd": window_end,
                    "maxRows": self._acquisition_authority.max_rows,
                    "maxBytes": self._acquisition_authority.max_bytes,
                    "table": table,
                    "query": signal.query,
                    "queryDigest": signal.query_digest,
                    "queryTargetResourceId": _canonical_resource_id(
                        signal.query_target_resource_id
                    ),
                    "expectedColumns": _LOG_COLUMNS[table],
                    "collectorExecutionTime": collected_at,
                    "coverageScope": control_binding.coverage_scope,
                },
            )
            for window_start, window_end in windows
        )
        responses: list[tuple[LogAnalyticsQueryRequest, LogAnalyticsQueryResult]] = []
        for request in requests:
            result = execution.invoke(
                request,
                execution.adapter.query_log_analytics,
            )
            if type(result) is not LogAnalyticsQueryResult:
                raise MonitoringAcquisitionError("log source returned an unexpected response type")
            if table == "NTANetAnalytics" and len(result.rows) > 1:
                raise MonitoringAcquisitionError(
                    "Traffic Analytics returned multiple rows for one bounded query"
                )
            _validate_result(
                result,
                request,
                collector_collection_time=collected_at,
                expected_columns=_LOG_COLUMNS[table],
            )
            if result.table != table:
                raise MonitoringAcquisitionError("log response table does not match the request")
            responses.append((request, result))

        ip_flow_exchanges_before = sum(
            item.source == "ipFlowVerify" for item in execution.exchanges
        )
        normalized: list[MonitoringCollectionRecord] = []
        partial = False
        reasons: list[str] = []
        for request, result in responses:
            aggregate_complete = _has_positive_aggregate_completeness(
                result,
                request,
                collector_collection_time=collected_at,
            )
            for row in result.rows:
                _validate_row_window(row, request, exact=True)
                if table == "Heartbeat" and isinstance(row, HeartbeatRow):
                    _require_control_scope(control, row.resource_id)
                    if row.heartbeat_count == 0 and not aggregate_complete:
                        partial = True
                        reasons.append(
                            "Heartbeat aggregate zero lacked positive raw-input and "
                            "ingestion-completeness proof"
                        )
                        continue
                    source_record_id = _record_id(
                        "heartbeat",
                        request.request_digest,
                        row,
                    )
                    normalized.append(
                        AmaHeartbeatRecord(
                            recordKind="amaHeartbeat",
                            controlId=control.control_id,
                            sourceRecordId=source_record_id,
                            resourceId=row.resource_id,
                            observedStart=row.observed_start,
                            observedEnd=row.observed_end,
                            queryDigest=signal.query_digest,
                            queryTargetResourceId=signal.query_target_resource_id,
                            evaluationWindowSeconds=signal.evaluation_window_seconds,
                            frequencySeconds=signal.frequency_seconds,
                            queryExecutionDigest=_query_execution_digest(
                                control=control,
                                source_record_id=source_record_id,
                                observed_start=row.observed_start,
                                observed_end=row.observed_end,
                            ),
                            heartbeatCount=row.heartbeat_count,
                        )
                    )
                    if row.heartbeat_count is None:
                        partial = True
                        reasons.append("Heartbeat returned missing data")
                elif table == "VMConnection" and isinstance(row, VmConnectionRow):
                    _require_control_path(control, row.path_id)
                    _require_control_scope(
                        control,
                        *row.subject_resource_candidates,
                        *row.backend_resource_candidates,
                    )
                    if (
                        len(row.subject_resource_candidates) != 1
                        or len(row.backend_resource_candidates) != 1
                    ):
                        partial = True
                        reasons.append(
                            "VMConnection IP-to-resource mapping was ambiguous and no causality "
                            "was claimed"
                        )
                        continue
                    if row.failed_connection_count == 0 and not aggregate_complete:
                        partial = True
                        reasons.append(
                            "VMConnection aggregate zero lacked positive raw-input and "
                            "ingestion-completeness proof"
                        )
                        continue
                    source_record_id = _record_id(
                        "vm-connection",
                        request.request_digest,
                        row,
                    )
                    normalized.append(
                        VmConnectionHealthRecord(
                            recordKind="vmConnectionHealth",
                            controlId=control.control_id,
                            sourceRecordId=source_record_id,
                            subjectResourceId=row.subject_resource_candidates[0],
                            backendResourceIds=row.backend_resource_candidates,
                            pathId=row.path_id,
                            observedStart=row.observed_start,
                            observedEnd=row.observed_end,
                            queryDigest=signal.query_digest,
                            queryTargetResourceId=signal.query_target_resource_id,
                            evaluationWindowSeconds=signal.evaluation_window_seconds,
                            frequencySeconds=signal.frequency_seconds,
                            queryExecutionDigest=_query_execution_digest(
                                control=control,
                                source_record_id=source_record_id,
                                observed_start=row.observed_start,
                                observed_end=row.observed_end,
                            ),
                            failedConnectionCount=row.failed_connection_count,
                        )
                    )
                    if row.failed_connection_count is None:
                        partial = True
                        reasons.append("VMConnection returned missing data")
                elif table == "NWConnectionMonitorTestResult" and isinstance(
                    row, ConnectionMonitorRow
                ):
                    _require_control_path(control, row.path_id)
                    _require_control_scope(
                        control,
                        row.subject_resource_id,
                        row.source_resource_id,
                        row.destination_resource_id,
                    )
                    _require_control_scope(
                        control,
                        row.monitor_resource_id,
                        evidence=True,
                    )
                    source_record_id = _record_id(
                        "connection-monitor",
                        request.request_digest,
                        row,
                    )
                    normalized.append(
                        ConnectionMonitorRecord(
                            recordKind="connectionMonitor",
                            controlId=control.control_id,
                            sourceRecordId=source_record_id,
                            subjectResourceId=row.subject_resource_id,
                            pathId=row.path_id,
                            monitorResourceId=row.monitor_resource_id,
                            sourceResourceId=row.source_resource_id,
                            destinationResourceId=row.destination_resource_id,
                            sourceAddress=row.source_address,
                            destinationAddress=row.destination_address,
                            direction=row.direction,
                            protocol=row.protocol,
                            sourcePort=row.source_port,
                            destinationPort=row.destination_port,
                            status=row.status,
                            testConfigurationReference=row.test_configuration_reference,
                            testConfigurationDigest=row.test_configuration_digest,
                            observedStart=row.observed_start,
                            observedEnd=row.observed_end,
                            queryDigest=signal.query_digest,
                            queryTargetResourceId=signal.query_target_resource_id,
                            evaluationWindowSeconds=signal.evaluation_window_seconds,
                            frequencySeconds=signal.frequency_seconds,
                            queryExecutionDigest=_query_execution_digest(
                                control=control,
                                source_record_id=source_record_id,
                                observed_start=row.observed_start,
                                observed_end=row.observed_end,
                            ),
                        )
                    )
                elif table == "NTANetAnalytics" and isinstance(row, TrafficAnalyticsRow):
                    flow_record, flow_reason = self._normalize_flow_row(
                        row,
                        request=request,
                        control=control,
                        control_binding=control_binding,
                        signal=signal,
                        acquired_changes=acquired_changes,
                        execution=execution,
                    )
                    if flow_record is None:
                        partial = True
                    else:
                        normalized.append(flow_record)
                    if flow_reason is not None:
                        reasons.append(flow_reason)
                else:
                    raise MonitoringAcquisitionError(
                        "log response row schema does not match the requested table"
                    )

        expected_resources = set(control.scope.resource_ids)
        representable_records: list[MonitoringCollectionRecord] = []
        for record in normalized:
            if _record_scope_resources(record) != expected_resources:
                partial = True
                reasons.append(
                    "source rows did not individually bind the complete published resource scope"
                )
                continue
            representable_records.append(record)
        normalized = representable_records
        if table == "NTANetAnalytics":
            ip_flow_exchanges_after = sum(
                item.source == "ipFlowVerify" for item in execution.exchanges
            )
            retained_flow_records = sum(
                isinstance(item, NetworkWatcherFlowRecord) for item in normalized
            )
            if ip_flow_exchanges_after - ip_flow_exchanges_before != retained_flow_records:
                raise MonitoringAcquisitionError(
                    "each IP Flow Verify exchange must bind exactly one retained network-flow row"
                )

        limitations: tuple[str, ...] = ()
        if table == "NTANetAnalytics":
            partial = True
            limitations = (
                "Traffic Analytics is aggregated evidence and not packet-level causal proof",
                "IP Flow Verify is point-in-time and not historical evidence",
            )
        descriptors = tuple(
            result.coverage_descriptor
            for _, result in responses
            if result.coverage_descriptor is not None
        )
        descriptor_digests = {compute_artifact_digest(_json_value(item)) for item in descriptors}
        if len(descriptor_digests) > 1:
            raise MonitoringAcquisitionError(
                "source responses disagree on the reviewed coverage scope"
            )
        descriptor = None if not descriptors else descriptors[0]
        if descriptor is not None and (
            descriptor.resource_ids != control.scope.resource_ids
            or (descriptor.path_id is not None and descriptor.path_id not in control.scope.path_ids)
        ):
            raise MonitoringAcquisitionError(
                "source coverage descriptor escapes the published control scope"
            )
        direction = None if descriptor is None else descriptor.direction
        five_tuple_digest = None if descriptor is None else descriptor.five_tuple_digest
        endpoint_test_reference = None if descriptor is None else descriptor.endpoint_test_reference
        endpoint_test_digest = None if descriptor is None else descriptor.endpoint_test_digest
        if table == "NWConnectionMonitorTestResult":
            monitor_records = tuple(
                item for item in normalized if isinstance(item, ConnectionMonitorRecord)
            )
            monitor_scopes = {
                (
                    item.direction,
                    compute_artifact_digest(
                        {
                            "direction": item.direction,
                            "protocol": item.protocol,
                            "sourceResourceId": item.source_resource_id,
                            "destinationResourceId": item.destination_resource_id,
                            "sourceAddress": item.source_address,
                            "destinationAddress": item.destination_address,
                            "sourcePort": item.source_port,
                            "destinationPort": item.destination_port,
                        }
                    ),
                    item.test_configuration_reference,
                    item.test_configuration_digest,
                )
                for item in monitor_records
            }
            if len(monitor_scopes) == 1:
                observed_scope = monitor_scopes.pop()
                described_scope = (
                    direction,
                    five_tuple_digest,
                    endpoint_test_reference,
                    endpoint_test_digest,
                )
                if descriptor is not None and described_scope != observed_scope:
                    raise MonitoringAcquisitionError(
                        "Connection Monitor rows disagree with the coverage descriptor"
                    )
                (
                    direction,
                    five_tuple_digest,
                    endpoint_test_reference,
                    endpoint_test_digest,
                ) = observed_scope
            elif monitor_records:
                partial = True
                reasons.append("Connection Monitor returned multiple coverage scopes")
        complete_windows = all(bool(result.rows) for _, result in responses)
        if not complete_windows and any(result.rows for _, result in responses):
            partial = True
            reasons.append("one or more required adjacent query windows returned no data")
        path_id = (
            None
            if table == "Heartbeat"
            else descriptor.path_id
            if descriptor is not None
            else control.scope.path_ids[0]
            if len(control.scope.path_ids) == 1
            else None
        )
        family_by_table: dict[
            str,
            Literal[
                "guest",
                "networkFlow",
                "connectionMonitor",
                "endpointHealth",
                "platformHealth",
            ],
        ] = {
            "Heartbeat": "guest",
            "VMConnection": "endpointHealth",
            "NWConnectionMonitorTestResult": "connectionMonitor",
            "NTANetAnalytics": "networkFlow",
        }
        coverage_records: list[MonitoringCoverageRecord] = []
        for request, result in responses:
            request_records = tuple(
                item
                for item in normalized
                if isinstance(
                    item,
                    (
                        AmaHeartbeatRecord,
                        VmConnectionHealthRecord,
                        ConnectionMonitorRecord,
                        NetworkWatcherFlowRecord,
                    ),
                )
                and item.observed_start == request.window_start
                and item.observed_end == request.window_end
            )
            if len(request_records) > 1:
                raise MonitoringAcquisitionError(
                    "source response produced multiple persisted rows for one exact query execution"
                )
            status, detail = _coverage_status(
                rows_present=bool(request_records),
                truncated=result.truncated,
                partial=partial or (bool(result.rows) and not request_records),
                limitations=(*limitations, *reasons),
            )
            if detail is not None:
                reasons.append(detail)
            coverage_records.append(
                MonitoringCoverageRecord(
                    controlId=control.control_id,
                    sourceRecordId=(
                        f"coverage-{request.request_digest.removeprefix('sha256:')[:32]}"
                    ),
                    family=family_by_table[table],
                    resourceIds=control.scope.resource_ids,
                    pathId=path_id,
                    direction=direction,
                    fiveTupleDigest=five_tuple_digest,
                    endpointTestReference=endpoint_test_reference,
                    endpointTestDigest=endpoint_test_digest,
                    observedStart=request.window_start,
                    observedEnd=request.window_end,
                    queryDigest=signal.query_digest,
                    queryTargetResourceId=signal.query_target_resource_id,
                    evaluationWindowSeconds=signal.evaluation_window_seconds,
                    frequencySeconds=signal.frequency_seconds,
                    queryExecutionDigests=tuple(
                        item.query_execution_digest for item in request_records
                    ),
                    status=status,
                    detail=detail,
                )
            )
        return tuple(normalized), tuple(coverage_records), tuple(reasons)

    def _normalize_flow_row(
        self,
        row: TrafficAnalyticsRow,
        *,
        request: LogAnalyticsQueryRequest,
        control: PublishedMonitoringIntentControl,
        control_binding: MonitoringAcquisitionControlBinding,
        signal: LogQueryMonitoringSignal,
        acquired_changes: tuple[ResourceChangeRecord, ...],
        execution: _AcquisitionExecution,
    ) -> tuple[NetworkWatcherFlowRecord | None, str | None]:
        candidate_sets = (
            row.subject_resource_candidates,
            row.source_resource_candidates,
            row.destination_resource_candidates,
        )
        _require_control_path(control, row.path_id)
        _require_control_scope(
            control,
            *(item for candidates in candidate_sets for item in candidates),
            row.enforcement_resource_id,
            *((row.rule_resource_id,) if row.rule_resource_id is not None else ()),
        )
        if any(len(candidates) != 1 for candidates in candidate_sets):
            return (
                None,
                "Traffic Analytics IP-to-resource mapping was ambiguous and no "
                "causality was claimed",
            )
        if row.rule_resource_id is None:
            return (
                None,
                "Traffic Analytics row omitted the ruleResourceId required for "
                "retained network-flow evidence",
            )
        coverage_scope = control_binding.coverage_scope
        local_target_resource_id = (
            row.destination_resource_candidates[0]
            if row.direction == "inbound"
            else row.source_resource_candidates[0]
        )
        if (
            row.protocol not in {"Tcp", "Udp"}
            or row.path_id != coverage_scope.path_id
            or row.direction != coverage_scope.direction
            or _traffic_row_five_tuple_digest(row) != coverage_scope.five_tuple_digest
            or coverage_scope.endpoint_test_reference is not None
            or coverage_scope.endpoint_test_digest is not None
            or not _is_virtual_machine_resource_id(local_target_resource_id)
        ):
            return (
                None,
                "Traffic Analytics row did not match the exact authority-approved "
                "TCP/UDP VM-local IP Flow scope",
            )
        source_record_id = _record_id(
            "traffic-analytics",
            request.request_digest,
            row,
        )
        base_record = NetworkWatcherFlowRecord(
            recordKind="networkWatcherFlow",
            controlId=control.control_id,
            sourceRecordId=source_record_id,
            subjectResourceId=row.subject_resource_candidates[0],
            pathId=row.path_id,
            decision=row.decision,
            direction=row.direction,
            protocol=row.protocol,
            sourceResourceId=row.source_resource_candidates[0],
            destinationResourceId=row.destination_resource_candidates[0],
            sourceAddress=row.source_address,
            destinationAddress=row.destination_address,
            sourcePort=row.source_port,
            destinationPort=row.destination_port,
            enforcementResourceId=row.enforcement_resource_id,
            ruleResourceId=row.rule_resource_id,
            observedStart=row.observed_start,
            observedEnd=row.observed_end,
            queryDigest=signal.query_digest,
            queryTargetResourceId=signal.query_target_resource_id,
            evaluationWindowSeconds=signal.evaluation_window_seconds,
            frequencySeconds=signal.frequency_seconds,
            queryExecutionDigest=_query_execution_digest(
                control=control,
                source_record_id=source_record_id,
                observed_start=row.observed_start,
                observed_end=row.observed_end,
            ),
        )
        if _record_scope_resources(base_record) != set(control.scope.resource_ids):
            return (
                None,
                "Traffic Analytics row could not represent the complete published "
                "network-flow persistence scope",
            )

        def build_verification_request(
            checked_at: datetime,
        ) -> IpFlowVerifyRequest:
            return _build_request(
                IpFlowVerifyRequest,
                {
                    "schemaVersion": "athena.wc028IpFlowVerifyRequest.v1",
                    "source": "ipFlowVerify",
                    "monitoringReaderIdentityId": self._monitoring_reader_identity_id,
                    "acquisitionAuthorityId": request.acquisition_authority_id,
                    "acquisitionAuthorityDigest": request.acquisition_authority_digest,
                    "collectorContractDigest": request.collector_contract_digest,
                    "intentId": request.intent_id,
                    "intentDigest": request.intent_digest,
                    "controlId": request.control_id,
                    "controlDigest": request.control_digest,
                    "scopeDigest": request.scope_digest,
                    "windowStart": checked_at - timedelta(seconds=60),
                    "windowEnd": checked_at,
                    "maxRows": self._acquisition_authority.max_rows,
                    "maxBytes": self._acquisition_authority.max_bytes,
                    "checkedAt": checked_at,
                    "targetResourceId": local_target_resource_id,
                    "direction": row.direction,
                    "protocol": row.protocol,
                    "sourceAddress": row.source_address,
                    "destinationAddress": row.destination_address,
                    "sourcePort": row.source_port,
                    "destinationPort": row.destination_port,
                },
            )

        verification_request, verification = execution.invoke_with_call_start(
            build_verification_request,
            execution.adapter.query_ip_flow_verify,
        )
        if type(verification) is not IpFlowVerifyResult:
            raise MonitoringAcquisitionError("IP Flow Verify returned an unexpected response type")
        _validate_ip_flow_result(
            verification,
            verification_request,
            collector_collection_time=verification_request.checked_at,
        )
        if verification.rule_resource_id is not None:
            _require_control_scope(control, verification.rule_resource_id)
        matched_change: ResourceChangeRecord | None = None
        attribution_rule_id: str | None = None
        if (
            verification.access == "Deny"
            and verification.rule_resource_id is not None
            and row.rule_resource_id == verification.rule_resource_id
            and row.decision == "denied"
        ):
            candidates = tuple(
                item
                for item in acquired_changes
                if item.target_resource_id == verification.rule_resource_id
                and item.result_type.casefold() == "succeeded"
                and item.occurred_at <= row.observed_start
                and _change_introduces_deny(item)
            )
            if len(candidates) == 1:
                matched_change = candidates[0]
                attribution_rule_id = verification.rule_resource_id
        attribution = (
            NetworkRuleAttributionEvidence(
                schemaVersion="athena.wc028NetworkRuleAttributionEvidence.v1",
                method="ipFlowVerify",
                access="Deny",
                previousAccess="Allow",
                currentAccess="Deny",
                ruleResourceId=attribution_rule_id,
                direction=row.direction,
                protocol=row.protocol,
                sourceAddress=row.source_address,
                destinationAddress=row.destination_address,
                sourcePort=row.source_port,
                destinationPort=row.destination_port,
                changeCorrelationId=matched_change.correlation_id,
            )
            if (matched_change is not None and attribution_rule_id is not None)
            else None
        )
        retained_payload = {
            **base_record.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            ),
            "ipFlowAccess": verification.access,
            "ipFlowRuleResourceId": verification.rule_resource_id,
            "ipFlowCheckedAt": verification.checked_at,
            "ipFlowResultDigest": sha256_hex(verification.canonical_bytes()),
        }
        if matched_change is not None and attribution is not None:
            retained_payload.update(
                {
                    "changeCorrelationId": matched_change.correlation_id,
                    "attributionMethod": "ipFlowVerify",
                    "attributionEvidence": attribution,
                }
            )
        retained_record = NetworkWatcherFlowRecord.model_validate(retained_payload)
        return (
            retained_record,
            "IP Flow Verify access was retained as point-in-time semantic evidence and "
            "was combined with change evidence only when one exact denied rule matched",
        )

    def _acquire_change_control(
        self,
        control: PublishedMonitoringIntentControl,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        collected_at: datetime,
        execution: _AcquisitionExecution,
    ) -> tuple[
        tuple[MonitoringCollectionRecord, ...],
        tuple[str, ...],
        tuple[ResourceChangeRecord, ...],
    ]:
        signal = cast(ActivityLogMonitoringSignal, control.signal)
        common: dict[str, object] = {
            "monitoringReaderIdentityId": self._monitoring_reader_identity_id,
            "acquisitionAuthorityId": self._acquisition_authority.authority_id,
            "acquisitionAuthorityDigest": self._acquisition_authority.authority_digest,
            "collectorContractDigest": self._acquisition_authority.collector_contract_digest,
            "intentId": monitoring_intent.intent_id,
            "intentDigest": monitoring_intent.intent_digest,
            "controlId": control.control_id,
            "controlDigest": control.control_digest,
            "scopeDigest": control.scope.scope_digest,
            "windowStart": collected_at - timedelta(seconds=EVENT_LOOKBACK_SECONDS),
            "windowEnd": collected_at,
            "maxRows": self._acquisition_authority.max_rows,
            "maxBytes": self._acquisition_authority.max_bytes,
        }
        activity_request = _build_request(
            ActivityLogQueryRequest,
            {
                **common,
                "schemaVersion": "athena.wc028ActivityLogQueryRequest.v1",
                "source": "activityLog",
                "resourceIds": control.scope.resource_ids,
                "categories": signal.categories,
                "operationNames": signal.operation_names,
                "resultTypes": signal.result_types,
                "levels": signal.levels,
                "expectedColumns": _ACTIVITY_COLUMNS,
            },
        )
        activity = execution.invoke(
            activity_request,
            execution.adapter.query_activity_log,
        )
        if type(activity) is not ActivityLogQueryResult:
            raise MonitoringAcquisitionError(
                "Activity Log source returned an unexpected response type"
            )
        _validate_result(
            activity,
            activity_request,
            collector_collection_time=collected_at,
            expected_columns=_ACTIVITY_COLUMNS,
        )
        graph_request = _build_request(
            ResourceGraphChangeQueryRequest,
            {
                **common,
                "schemaVersion": "athena.wc028ResourceGraphChangeQueryRequest.v1",
                "source": "resourceGraph",
                "resourceIds": control.scope.resource_ids,
                "expectedColumns": _RESOURCE_GRAPH_COLUMNS,
            },
        )
        graph = execution.invoke(
            graph_request,
            execution.adapter.query_resource_graph_changes,
        )
        if type(graph) is not ResourceGraphChangeQueryResult:
            raise MonitoringAcquisitionError(
                "Resource Graph source returned an unexpected response type"
            )
        _validate_result(
            graph,
            graph_request,
            collector_collection_time=collected_at,
            expected_columns=_RESOURCE_GRAPH_COLUMNS,
        )

        activity_by_key: dict[tuple[str, str, datetime, str, str], ActivityLogRow] = {}
        for activity_row in activity.rows:
            _require_control_scope(control, activity_row.target_resource_id)
            if not (
                activity_request.window_start
                <= activity_row.occurred_at
                <= activity_request.window_end
            ):
                raise MonitoringAcquisitionError("Activity Log row escapes the authorized window")
            key = _activity_key(activity_row)
            if key in activity_by_key:
                raise MonitoringAcquisitionError("Activity Log change pairing is not unique")
            activity_by_key[key] = activity_row
        graph_by_key: dict[
            tuple[str, str, datetime, str, str],
            ResourceGraphChangeRow,
        ] = {}
        for graph_row in graph.rows:
            _require_control_scope(control, graph_row.target_resource_id)
            if not (
                graph_request.window_start <= graph_row.occurred_at <= graph_request.window_end
            ):
                raise MonitoringAcquisitionError("Resource Graph row escapes the authorized window")
            key = _activity_key(graph_row)
            if key in graph_by_key:
                raise MonitoringAcquisitionError("Resource Graph change pairing is not unique")
            graph_by_key[key] = graph_row

        shared = tuple(sorted(set(activity_by_key).intersection(graph_by_key)))
        reasons: list[str] = []
        missing_count = len(set(activity_by_key).symmetric_difference(graph_by_key))
        if missing_count:
            reasons.append(
                "manual investigation required: Activity Log and Resource Graph "
                f"had {missing_count} unpaired change record(s)"
            )
        if activity.truncated or graph.truncated:
            reasons.append(
                "manual investigation required: Activity Log or Resource Graph "
                "change evidence was truncated"
            )
        if not activity.rows or not graph.rows:
            reasons.append(
                "manual investigation required: Activity Log or Resource Graph "
                "returned no change data; zero changes were not inferred"
            )
        records = tuple(
            ResourceChangeRecord(
                recordKind="resourceChange",
                controlId=control.control_id,
                sourceRecordId=_record_id(
                    "activity-change",
                    activity_request.request_digest,
                    activity_by_key[key],
                ),
                category=activity_by_key[key].category,
                operationName=activity_by_key[key].operation_name,
                resultType=activity_by_key[key].result_type,
                level=activity_by_key[key].level,
                targetResourceId=activity_by_key[key].target_resource_id,
                correlationId=activity_by_key[key].correlation_id,
                occurredAt=activity_by_key[key].occurred_at,
                resourceGraphChange=graph_by_key[key].change,
            )
            for key in shared
        )
        complete = not activity.truncated and not graph.truncated and missing_count == 0
        return records, tuple(reasons), (records if complete else ())

    def _acquire_health_control(
        self,
        control: PublishedMonitoringIntentControl,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        collected_at: datetime,
        trusted_as_of: datetime,
        execution: _AcquisitionExecution,
    ) -> tuple[
        tuple[MonitoringCollectionRecord, ...],
        MonitoringCoverageRecord,
        tuple[str, ...],
    ]:
        signal = cast(ResourceHealthMonitoringSignal, control.signal)
        request = _build_request(
            ResourceHealthQueryRequest,
            {
                "schemaVersion": "athena.wc028ResourceHealthQueryRequest.v1",
                "source": "resourceHealth",
                "monitoringReaderIdentityId": self._monitoring_reader_identity_id,
                "acquisitionAuthorityId": self._acquisition_authority.authority_id,
                "acquisitionAuthorityDigest": (self._acquisition_authority.authority_digest),
                "collectorContractDigest": (self._acquisition_authority.collector_contract_digest),
                "intentId": monitoring_intent.intent_id,
                "intentDigest": monitoring_intent.intent_digest,
                "controlId": control.control_id,
                "controlDigest": control.control_digest,
                "scopeDigest": control.scope.scope_digest,
                "windowStart": trusted_as_of - timedelta(seconds=signal.maximum_event_age_seconds),
                "windowEnd": collected_at,
                "maxRows": self._acquisition_authority.max_rows,
                "maxBytes": self._acquisition_authority.max_bytes,
                "resourceIds": control.scope.resource_ids,
                "eventStatuses": signal.event_statuses,
                "currentStatuses": signal.current_statuses,
                "previousStatuses": signal.previous_statuses,
                "reasonTypes": signal.reason_types,
                "expectedColumns": _RESOURCE_HEALTH_COLUMNS,
            },
        )
        result = execution.invoke(
            request,
            execution.adapter.query_resource_health,
        )
        if type(result) is not ResourceHealthQueryResult:
            raise MonitoringAcquisitionError(
                "Resource Health source returned an unexpected response type"
            )
        _validate_result(
            result,
            request,
            collector_collection_time=collected_at,
            expected_columns=_RESOURCE_HEALTH_COLUMNS,
        )
        records: list[MonitoringCollectionRecord] = []
        for row in result.rows:
            _validate_row_window(row, request, exact=False)
            _require_control_scope(control, row.resource_id)
            source_record_id = _record_id(
                "resource-health",
                request.request_digest,
                row,
            )
            records.append(
                ResourceHealthRecord(
                    recordKind="resourceHealth",
                    controlId=control.control_id,
                    sourceRecordId=source_record_id,
                    resourceId=row.resource_id,
                    eventStatus=row.event_status,
                    currentStatus=row.current_status,
                    previousStatus=row.previous_status,
                    reasonType=row.reason_type,
                    observedStart=row.observed_start,
                    observedEnd=row.observed_end,
                )
            )
        observed_resources = {_canonical_resource_id(row.resource_id) for row in result.rows}
        expected_resources = set(control.scope.resource_ids)
        scope_partial = bool(observed_resources) and observed_resources != expected_resources
        limitations = (
            (("Resource Health returned data for only part of the published resource scope"),)
            if scope_partial
            else ()
        )
        status, detail = _coverage_status(
            rows_present=bool(result.rows),
            truncated=result.truncated,
            partial=scope_partial,
            limitations=limitations,
        )
        coverage = MonitoringCoverageRecord(
            controlId=control.control_id,
            sourceRecordId=f"coverage-{request.request_digest.removeprefix('sha256:')[:32]}",
            family="platformHealth",
            resourceIds=control.scope.resource_ids,
            pathId=(control.scope.path_ids[0] if len(control.scope.path_ids) == 1 else None),
            observedStart=request.window_start,
            observedEnd=request.window_end,
            status=status,
            detail=detail,
        )
        reasons: tuple[str, ...] = () if detail is None else (detail,)
        return tuple(records), coverage, reasons

    def _select_incident(
        self,
        records: list[MonitoringCollectionRecord],
        controls: dict[str, PublishedMonitoringIntentControl],
    ) -> tuple[str, tuple[str, ...], str]:
        samples: list[MonitoringIncidentSample] = []
        for record in records:
            state = _health_state(record, controls[record.control_id])
            if state is None:
                continue
            resource_id: str
            record_kind: Literal[
                "amaHeartbeat",
                "vmConnectionHealth",
                "resourceHealth",
            ]
            if isinstance(record, AmaHeartbeatRecord):
                resource_id = record.resource_id
                record_kind = "amaHeartbeat"
            elif isinstance(record, VmConnectionHealthRecord):
                resource_id = record.subject_resource_id
                record_kind = "vmConnectionHealth"
            elif isinstance(record, ResourceHealthRecord):
                resource_id = record.resource_id
                record_kind = "resourceHealth"
            else:
                continue
            samples.append(
                MonitoringIncidentSample(
                    resource_id=resource_id,
                    control_id=record.control_id,
                    payload_id=record.source_record_id,
                    selection_key=monitoring_health_source_record_reference(
                        record_kind,
                        record.source_record_id,
                    ),
                    observed_start=record.observed_start,
                    observed_end=record.observed_end,
                    state=state,
                )
            )
        try:
            selection = select_monitoring_incident(tuple(samples))
        except MonitoringIncidentSelectionError as exc:
            raise MonitoringAcquisitionError(str(exc)) from exc
        return (
            selection.previous.payload_id,
            tuple(item.payload_id for item in selection.current),
            selection.incident_resource_id,
        )


__all__ = [
    "ActivityLogQueryRequest",
    "ActivityLogQueryResult",
    "ActivityLogRow",
    "AzureActivityLogAcquisitionClient",
    "AzureIpFlowVerifyAcquisitionClient",
    "AzureLogAnalyticsAcquisitionClient",
    "AzureMonitoringAdapter",
    "AzureResourceGraphAcquisitionClient",
    "AzureResourceHealthAcquisitionClient",
    "ConnectionMonitorRow",
    "EVENT_LOOKBACK_SECONDS",
    "HeartbeatRow",
    "IpFlowVerifyRequest",
    "IpFlowVerifyResult",
    "LogCoverageDescriptor",
    "LogAggregateCompletenessProof",
    "LogAnalyticsQueryRequest",
    "LogAnalyticsQueryResult",
    "MAX_ACQUISITION_CALLS",
    "MAX_ACQUISITION_RESPONSE_BYTES",
    "MAX_ACQUISITION_ROWS",
    "MonitoringAcquisitionAuthority",
    "MonitoringAcquisitionControlBinding",
    "MonitoringAcquisitionCoordinator",
    "MonitoringAcquisitionError",
    "MonitoringAcquisitionOutcome",
    "MonitoringAcquisitionReceiptSigner",
    "MonitoringActivityLogClient",
    "MonitoringIpFlowVerifyClient",
    "MonitoringLogAnalyticsClient",
    "MonitoringResourceGraphClient",
    "MonitoringResourceHealthClient",
    "ResourceGraphChangeQueryRequest",
    "ResourceGraphChangeQueryResult",
    "ResourceGraphChangeRow",
    "ResourceHealthQueryRequest",
    "ResourceHealthQueryResult",
    "ResourceHealthRow",
    "TrafficAnalyticsRow",
    "VmConnectionRow",
    "compute_monitoring_acquisition_control_selection_digest",
]
