from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts import (
    ActivityLogMonitoringSignal,
    ApprovedChangeScope,
    CorrelationRequest,
    LogQueryMonitoringSignal,
    MonitoringAcquisitionExchange,
    MonitoringAcquisitionReceipt,
    MonitoringEvidenceAttestation,
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

MAX_ACQUISITION_ROWS = 500
MAX_ACQUISITION_RESPONSE_BYTES = 256 * 1024
MAX_ACQUISITION_WINDOW_SECONDS = 86400
MAX_ACQUISITION_CALLS = 32
EVENT_LOOKBACK_SECONDS = 900
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


class MonitoringAcquisitionAuthority(_StrictAcquisitionModel):
    """Digest-pinned authorization for the read-only monitoring acquisition boundary."""

    schema_version: Literal[
        "athena.wc028MonitoringAcquisitionAuthority.v1",
        "athena.wc028MonitoringAcquisitionAuthority.v2",
    ] = Field(alias="schemaVersion")
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^monitoring-acquisition-authority-[a-f0-9]{32}$",
    )
    monitoring_reader_identity_id: str = Field(alias="monitoringReaderIdentityId")
    athena_context_identity_id: str = Field(alias="athenaContextIdentityId")
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
    read_only: Literal[True] = Field(alias="readOnly")
    athena_context_has_workload_reader: Literal[False] = Field(
        alias="athenaContextHasWorkloadReader"
    )
    deployment_identity_contract_digest: Sha256Digest | None = Field(
        default=None, alias="deploymentIdentityContractDigest"
    )
    authority_digest: Sha256Digest = Field(alias="authorityDigest")

    @field_validator("monitoring_reader_identity_id", "athena_context_identity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _canonical_identity_id(value)

    @field_validator("allowed_sources")
    @classmethod
    def validate_sources(
        cls,
        values: tuple[AcquisitionSource, ...],
    ) -> tuple[AcquisitionSource, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("acquisition sources must be sorted and unique")
        return values

    @field_validator("allowed_resource_ids")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_canonical_resource_id(item) for item in values))
        if len(normalized) != len(set(normalized)):
            raise ValueError("acquisition resource IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_authority(self) -> MonitoringAcquisitionAuthority:
        if self.monitoring_reader_identity_id == self.athena_context_identity_id:
            raise ValueError(
                "monitoring acquisition identity must be separate from the Athena context identity"
            )
        receipt_fields = (
            self.max_acquisition_calls,
            self.receipt_signing_key_id,
            self.monitoring_reader_has_read_only_workload_access,
            self.deployment_identity_contract_digest,
        )
        if self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v1":
            if any(item is not None for item in receipt_fields):
                raise ValueError("v1 acquisition authority cannot contain receipt policy")
        elif any(item is None for item in receipt_fields):
            raise ValueError("v2 acquisition authority requires receipt policy")
        deployment_digest = compute_artifact_digest(
            {
                "monitoringReaderIdentityId": self.monitoring_reader_identity_id,
                "athenaContextIdentityId": self.athena_context_identity_id,
                "monitoringReaderHasReadOnlyWorkloadAccess": (
                    self.monitoring_reader_has_read_only_workload_access
                ),
                "athenaContextHasWorkloadReader": self.athena_context_has_workload_reader,
                "readOnly": self.read_only,
            }
        )
        if (
            self.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v2"
            and self.deployment_identity_contract_digest != deployment_digest
        ):
            raise ValueError("deploymentIdentityContractDigest does not bind identity separation")
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
    schema_version: Literal["athena.wc028LogAnalyticsQueryRequest.v1"] = Field(
        alias="schemaVersion"
    )
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
type _HealthSample = tuple[str, str, str, datetime, datetime, _HealthState]


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


class MonitoringAcquisitionPort(Protocol):
    """Read-only port implemented behind the dedicated monitoring evidence identity."""

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult: ...

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult: ...

    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult: ...

    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult: ...

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult: ...


class MonitoringAcquisitionRuntime(Protocol):
    """Trusted collector runtime, not the source port or request caller."""

    def authenticated_principal_id(self) -> str: ...

    def utc_now(self) -> datetime: ...


class MonitoringAcquisitionReceiptSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


@dataclass(slots=True)
class _AcquisitionExecution:
    runtime: MonitoringAcquisitionRuntime
    max_calls: int
    started_at: datetime
    exchanges: list[MonitoringAcquisitionExchange]

    def invoke[RequestT: _AcquisitionRequest, ResultT: _StrictAcquisitionModel](
        self,
        request: RequestT,
        operation: Callable[[RequestT], ResultT],
    ) -> ResultT:
        if len(self.exchanges) >= self.max_calls:
            raise MonitoringAcquisitionError(
                "monitoring acquisition exceeded its total call budget"
            )
        requested_at = _trusted_runtime_time(self.runtime.utc_now())
        result = operation(request)
        received_at = _trusted_runtime_time(self.runtime.utc_now())
        if requested_at < self.started_at or received_at < requested_at:
            raise MonitoringAcquisitionError("collector runtime returned non-monotonic time")
        source = cast(AcquisitionSource, request.source)
        checked_at = request.checked_at if isinstance(request, IpFlowVerifyRequest) else None
        self.exchanges.append(
            MonitoringAcquisitionExchange(
                sequence=len(self.exchanges) + 1,
                source=source,
                requestDigest=request.request_digest,
                resultDigest=sha256_hex(result.canonical_bytes()),
                requestedAt=requested_at,
                receivedAt=received_at,
                checkedAt=checked_at,
            )
        )
        return result


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
        return resources
    if isinstance(record, ResourceHealthRecord):
        return {_canonical_resource_id(record.resource_id)}
    return set()


def _validate_result(
    result: _AcquisitionResult,
    request: _AcquisitionRequest,
    *,
    authenticated_principal_id: str,
    collector_collection_time: datetime,
    expected_columns: tuple[str, ...],
) -> None:
    if result.request_digest != request.request_digest:
        raise MonitoringAcquisitionError("source response does not bind the exact request")
    if result.source_identity_id != authenticated_principal_id:
        raise MonitoringAcquisitionError(
            "source response identity claim conflicts with the authenticated principal"
        )
    if result.collected_at != collector_collection_time:
        raise MonitoringAcquisitionError(
            "source response time claim conflicts with the collector clock"
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
    authenticated_principal_id: str,
    collector_collection_time: datetime,
) -> None:
    if result.request_digest != request.request_digest:
        raise MonitoringAcquisitionError("IP Flow Verify response does not bind the exact request")
    if result.source_identity_id != authenticated_principal_id:
        raise MonitoringAcquisitionError(
            "IP Flow Verify identity claim conflicts with the authenticated principal"
        )
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
        acquisition_port: MonitoringAcquisitionPort,
        acquisition_authority: MonitoringAcquisitionAuthority,
        expected_acquisition_authority_digest: str,
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
        runtime: MonitoringAcquisitionRuntime,
        receipt_signer: MonitoringAcquisitionReceiptSigner,
    ) -> None:
        self._acquisition_port = acquisition_port
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
            != "athena.wc028MonitoringAcquisitionAuthority.v2"
        ):
            raise MonitoringAcquisitionError(
                "receipt-bearing acquisition requires authority schema v2"
            )
        self._monitoring_reader_identity_id = (
            self._acquisition_authority.monitoring_reader_identity_id
        )
        self._monitoring_intent_trusted_key_id = monitoring_intent_trusted_key_id
        self._monitoring_intent_signature_verifier = monitoring_intent_signature_verifier
        self._monitoring_intent_asset_loader = monitoring_intent_asset_loader
        self._collection_transaction = collection_transaction
        self._runtime = runtime
        self._receipt_signer = receipt_signer

    def _build_receipt(
        self,
        *,
        execution: _AcquisitionExecution,
        authenticated_principal_id: str,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        collection_batch_digest: str,
        normalized_evidence_digest: str,
    ) -> MonitoringAcquisitionReceipt:
        execution_completed_at = _trusted_runtime_time(self._runtime.utc_now())
        receipt_issued_at = _trusted_runtime_time(self._runtime.utc_now())
        if (
            execution_completed_at < execution.started_at
            or receipt_issued_at < execution_completed_at
        ):
            raise MonitoringAcquisitionError("collector runtime returned non-monotonic time")
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc028MonitoringAcquisitionReceipt.v1",
            "authenticatedPrincipalId": authenticated_principal_id,
            "athenaContextIdentityId": self._acquisition_authority.athena_context_identity_id,
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
            "executionStartedAt": execution.started_at,
            "executionCompletedAt": execution_completed_at,
            "receiptIssuedAt": receipt_issued_at,
            "exchanges": tuple(execution.exchanges),
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
        collector_contract_digest: str,
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
        execution_started_at = _trusted_runtime_time(self._runtime.utc_now())
        authenticated_principal_id = _canonical_identity_id(
            self._runtime.authenticated_principal_id()
        )
        if (
            authenticated_principal_id != self._acquisition_authority.monitoring_reader_identity_id
            or authenticated_principal_id == self._acquisition_authority.athena_context_identity_id
        ):
            raise MonitoringAcquisitionError(
                "authenticated deployment identity violates acquisition separation"
            )
        collected_at = execution_started_at
        execution = _AcquisitionExecution(
            runtime=self._runtime,
            max_calls=cast(int, self._acquisition_authority.max_acquisition_calls),
            started_at=execution_started_at,
            exchanges=[],
        )
        if collector_contract_digest != self._acquisition_authority.collector_contract_digest:
            raise MonitoringAcquisitionError(
                "collector contract digest does not match acquisition authority"
            )
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
            authorized_resources = set(self._acquisition_authority.allowed_resource_ids)
            authorized_sources = set(self._acquisition_authority.allowed_sources)
            for control in monitoring_intent.controls:
                required_resources = {
                    *control.scope.resource_ids,
                    *(control.scope.evidence_resource_ids or ()),
                }
                if isinstance(control.signal, LogQueryMonitoringSignal):
                    required_resources.add(control.signal.query_target_resource_id)
                    required_sources: set[AcquisitionSource] = {"logAnalytics"}
                    if _source_table(control.signal) == "NTANetAnalytics":
                        required_sources.add("ipFlowVerify")
                elif isinstance(control.signal, ActivityLogMonitoringSignal):
                    required_sources = {"activityLog", "resourceGraph"}
                elif isinstance(control.signal, ResourceHealthMonitoringSignal):
                    required_sources = {"resourceHealth"}
                else:
                    raise MonitoringAcquisitionError(
                        "published monitoring signal has no reviewed acquisition source"
                    )
                if not {_canonical_resource_id(item) for item in required_resources}.issubset(
                    authorized_resources
                ):
                    raise MonitoringAcquisitionError(
                        "published monitoring intent escapes acquisition authority scope"
                    )
                if not required_sources.issubset(authorized_sources):
                    raise MonitoringAcquisitionError(
                        "published monitoring intent uses an unauthorized acquisition source"
                    )
        except (TypeError, ValueError) as exc:
            raise MonitoringAcquisitionError(
                "monitoring intent authority is invalid before acquisition"
            ) from exc

        records: list[MonitoringCollectionRecord] = []
        coverage: list[MonitoringCoverageRecord] = []
        manual_reasons: list[str] = []
        attribution_changes: tuple[ResourceChangeRecord, ...] = ()
        controls_by_id = {item.control_id: item for item in monitoring_intent.controls}
        if any(
            isinstance(control.signal, ActivityLogMonitoringSignal)
            for control in monitoring_intent.controls
        ):
            manual_reasons.append(
                "supporting control has no required coverage scope and was not executed"
            )

        try:
            for control in monitoring_intent.controls:
                if isinstance(control.signal, LogQueryMonitoringSignal):
                    new_records, new_coverage, reasons = self._acquire_log_control(
                        control,
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
        preliminary = self._collection_transaction.prepare(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(
                expected_active_context_authority_digest
            ),
            collector_contract_digest=collector_contract_digest,
            change_scope=change_scope,
            trusted_as_of=trusted_as_of,
        )
        acquisition_receipt = self._build_receipt(
            execution=execution,
            authenticated_principal_id=authenticated_principal_id,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
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
            collector_contract_digest=collector_contract_digest,
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
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v1",
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
                },
            )
            for window_start, window_end in windows
        )
        responses: list[tuple[LogAnalyticsQueryRequest, LogAnalyticsQueryResult]] = []
        for request in requests:
            result = execution.invoke(
                request,
                self._acquisition_port.query_log_analytics,
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
                authenticated_principal_id=self._monitoring_reader_identity_id,
                collector_collection_time=collected_at,
                expected_columns=_LOG_COLUMNS[table],
            )
            if result.table != table:
                raise MonitoringAcquisitionError("log response table does not match the request")
            responses.append((request, result))

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
        checked_at = _trusted_runtime_time(self._runtime.utc_now())
        verification_request = _build_request(
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
                "targetResourceId": row.subject_resource_candidates[0],
                "direction": row.direction,
                "protocol": row.protocol,
                "sourceAddress": row.source_address,
                "destinationAddress": row.destination_address,
                "sourcePort": row.source_port,
                "destinationPort": row.destination_port,
            },
        )
        verification = execution.invoke(
            verification_request,
            self._acquisition_port.query_ip_flow_verify,
        )
        if type(verification) is not IpFlowVerifyResult:
            raise MonitoringAcquisitionError("IP Flow Verify returned an unexpected response type")
        _validate_ip_flow_result(
            verification,
            verification_request,
            authenticated_principal_id=self._monitoring_reader_identity_id,
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
        source_record_id = _record_id(
            "traffic-analytics",
            request.request_digest,
            row,
        )
        return (
            NetworkWatcherFlowRecord(
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
                changeCorrelationId=(
                    None if matched_change is None else matched_change.correlation_id
                ),
                attributionMethod=(None if matched_change is None else "ipFlowVerify"),
                attributionEvidence=attribution,
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
            ),
            "IP Flow Verify result was retained only as a point-in-time limitation and "
            "was combined with change evidence only when one exact rule match existed",
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
            self._acquisition_port.query_activity_log,
        )
        if type(activity) is not ActivityLogQueryResult:
            raise MonitoringAcquisitionError(
                "Activity Log source returned an unexpected response type"
            )
        _validate_result(
            activity,
            activity_request,
            authenticated_principal_id=self._monitoring_reader_identity_id,
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
            self._acquisition_port.query_resource_graph_changes,
        )
        if type(graph) is not ResourceGraphChangeQueryResult:
            raise MonitoringAcquisitionError(
                "Resource Graph source returned an unexpected response type"
            )
        _validate_result(
            graph,
            graph_request,
            authenticated_principal_id=self._monitoring_reader_identity_id,
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
            self._acquisition_port.query_resource_health,
        )
        if type(result) is not ResourceHealthQueryResult:
            raise MonitoringAcquisitionError(
                "Resource Health source returned an unexpected response type"
            )
        _validate_result(
            result,
            request,
            authenticated_principal_id=self._monitoring_reader_identity_id,
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
        samples: list[_HealthSample] = []
        for record in records:
            state = _health_state(record, controls[record.control_id])
            if state is None:
                continue
            resource_id: str
            if isinstance(record, AmaHeartbeatRecord):
                resource_id = record.resource_id
            elif isinstance(record, VmConnectionHealthRecord):
                resource_id = record.subject_resource_id
            elif isinstance(record, ResourceHealthRecord):
                resource_id = record.resource_id
            else:
                continue
            samples.append(
                (
                    resource_id,
                    record.control_id,
                    record.source_record_id,
                    record.observed_start,
                    record.observed_end,
                    state,
                )
            )
        state_rank = {"degraded": 1, "unhealthy": 2, "unavailable": 3}
        candidates: dict[str, list[tuple[_HealthSample, tuple[_HealthSample, ...]]]] = {}
        groups = sorted({(item[0], item[1]) for item in samples})
        for resource_id, control_id in groups:
            group_samples = tuple(
                item for item in samples if item[0] == resource_id and item[1] == control_id
            )
            latest_end = max(item[4] for item in group_samples)
            terminal = tuple(item for item in group_samples if item[4] == latest_end)
            terminal_states = {item[5] for item in terminal}
            if len(terminal_states) > 1:
                raise MonitoringAcquisitionError(
                    "latest health evidence is contradictory and requires manual investigation"
                )
            adverse_terminal = tuple(item for item in terminal if item[5] != "healthy")
            if not adverse_terminal:
                continue
            selected_state = max(
                (item[5] for item in adverse_terminal),
                key=lambda item: state_rank[item],
            )
            seed = max(
                (item for item in adverse_terminal if item[5] == selected_state),
                key=lambda item: (item[3], item[2]),
            )
            episode = {seed}
            episode_start = seed[3]
            episode_end = seed[4]
            changed = True
            while changed:
                changed = False
                for item in group_samples:
                    if (
                        item in episode
                        or item[5] != selected_state
                        or item[3] > episode_end
                        or item[4] < episode_start
                    ):
                        continue
                    episode.add(item)
                    episode_start = min(episode_start, item[3])
                    episode_end = max(episode_end, item[4])
                    changed = True
            if any(
                item[5] == "healthy" and item[3] < episode_end and item[4] > episode_start
                for item in group_samples
            ):
                raise MonitoringAcquisitionError(
                    "current health episode conflicts with overlapping healthy evidence"
                )
            predecessors = tuple(
                item for item in group_samples if item[5] == "healthy" and item[4] <= episode_start
            )
            if predecessors:
                candidates.setdefault(resource_id, []).append(
                    (
                        max(predecessors, key=lambda item: (item[4], item[2])),
                        tuple(sorted(episode, key=lambda item: item[2])),
                    )
                )
        if len(candidates) != 1:
            raise MonitoringAcquisitionError(
                "acquired evidence must identify exactly one unambiguous health transition"
            )
        incident_resource_id, resource_candidates = candidates.popitem()
        selected_previous, current = max(
            resource_candidates,
            key=lambda item: (
                state_rank[item[1][0][5]],
                max(sample[4] for sample in item[1]),
                item[1][0][1],
            ),
        )
        return (
            selected_previous[2],
            tuple(sorted(item[2] for item in current)),
            incident_resource_id,
        )


__all__ = [
    "ActivityLogQueryRequest",
    "ActivityLogQueryResult",
    "ActivityLogRow",
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
    "MonitoringAcquisitionCoordinator",
    "MonitoringAcquisitionError",
    "MonitoringAcquisitionOutcome",
    "MonitoringAcquisitionPort",
    "MonitoringAcquisitionReceiptSigner",
    "MonitoringAcquisitionRuntime",
    "ResourceGraphChangeQueryRequest",
    "ResourceGraphChangeQueryResult",
    "ResourceGraphChangeRow",
    "ResourceHealthQueryRequest",
    "ResourceHealthQueryResult",
    "ResourceHealthRow",
    "TrafficAnalyticsRow",
    "VmConnectionRow",
]
