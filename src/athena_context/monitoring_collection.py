from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from athena_context.contracts import (
    CORRELATION_ALGORITHM_ID,
    CORRELATION_REQUEST_SCHEMA_VERSION,
    MONITORING_ACQUISITION_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    PREVIOUS_CORRELATION_REQUEST_SCHEMA_VERSION,
    ActivityLogMonitoringSignal,
    ApprovedChangeScope,
    ChangeEvidenceArtifact,
    ChangeEvidencePersistenceHandoff,
    ConnectionMonitorObservation,
    CorrelationEvidenceCitation,
    CorrelationEvidenceInventory,
    CorrelationRequest,
    EndpointHealthObservation,
    EvidenceCoverage,
    EvidenceCoverageScope,
    EvidenceFamily,
    GuestSignalObservation,
    IncidentHealthTransition,
    LogQueryMonitoringSignal,
    MonitoringAcquisitionEvidenceManifest,
    MonitoringAcquisitionReceipt,
    MonitoringControlProvenance,
    MonitoringEvidenceBundle,
    MonitoringEvidenceHandoff,
    MonitoringIntentEvidenceReference,
    MonitoringIpFlowProvenance,
    MonitoringLogPermissionEvidence,
    MonitoringObservation,
    MonitoringSelectedIncident,
    NetworkFlowObservation,
    NormalizedChangeEvidence,
    PlatformHealthObservation,
    PublishedMonitoringIntent,
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
    PublishedMonitoringIntentControl,
    PublishedRuntimeContextBinding,
    ResourceHealthMonitoringSignal,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    sha256_hex,
    validate_monitoring_intent_activation_eligible,
    validate_published_monitoring_intent_assets,
)
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.correlation.rules import CORRELATION_RULE_CATALOG_DIGEST
from athena_context.eventing.change_ingestion import (
    MAX_CHANGE_EVIDENCE_AGE,
    ChangeEvidenceArtifactSigner,
    build_change_evidence_artifact,
    normalize_resource_graph_change,
)
from athena_context.monitoring_incident import (
    build_selected_incident,
    monitoring_source_record_reference,
)

MONITORING_COLLECTION_BATCH_SCHEMA_VERSION = "athena.wc028MonitoringCollectionBatch.v2"
MAX_MONITORING_COLLECTION_BYTES = 512 * 1024
MAX_MONITORING_COLLECTION_RECORDS = 1000
MAX_COLLECTION_TRUST_DELAY_SECONDS = 1200
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_CAUSAL_NSG_PROPERTY_PREFIXES = (
    "properties.access",
    "properties.direction",
    "properties.priority",
    "properties.protocol",
    "properties.sourceaddressprefix",
    "properties.sourceaddressprefixes",
    "properties.sourceportrange",
    "properties.sourceportranges",
    "properties.destinationaddressprefix",
    "properties.destinationaddressprefixes",
    "properties.destinationportrange",
    "properties.destinationportranges",
)


class MonitoringCollectionError(RuntimeError):
    """Raised when a collection batch cannot be normalized without ambiguity."""


def compute_monitoring_query_execution_digest(
    *,
    control_id: str,
    source_record_id: str,
    query_digest: str,
    query_target_resource_id: str,
    observed_start: datetime,
    observed_end: datetime,
    evaluation_window_seconds: int,
    frequency_seconds: int,
) -> str:
    """Bind one collector result to the exact reviewed query execution coordinates."""

    return compute_artifact_digest(
        {
            "controlId": control_id,
            "sourceRecordId": source_record_id,
            "queryDigest": query_digest,
            "queryTargetResourceId": query_target_resource_id.casefold().rstrip("/"),
            "observedStart": observed_start,
            "observedEnd": observed_end,
            "evaluationWindowSeconds": evaluation_window_seconds,
            "frequencySeconds": frequency_seconds,
        }
    )


class _StrictCollectionModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


class _CollectionRecord(_StrictCollectionModel):
    control_id: str = Field(
        alias="controlId",
        pattern=r"^monitoring-control-[a-f0-9]{32}$",
    )
    source_record_id: str = Field(
        alias="sourceRecordId",
        min_length=1,
        max_length=2048,
    )


class _WindowedCollectionRecord(_CollectionRecord):
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")

    @model_validator(mode="after")
    def validate_interval(self) -> _WindowedCollectionRecord:
        if self.observed_start > self.observed_end:
            raise ValueError("observedStart must not be after observedEnd")
        return self


class _LogQueryCollectionRecord(_WindowedCollectionRecord):
    query_digest: Sha256Digest = Field(alias="queryDigest")
    query_target_resource_id: str = Field(
        alias="queryTargetResourceId",
        min_length=1,
        max_length=2048,
    )
    evaluation_window_seconds: int = Field(
        alias="evaluationWindowSeconds",
        ge=60,
        le=86400,
    )
    frequency_seconds: int = Field(
        alias="frequencySeconds",
        ge=60,
        le=3600,
    )
    query_execution_digest: Sha256Digest = Field(alias="queryExecutionDigest")
    permission_evidence_digest: Sha256Digest | None = Field(
        default=None,
        alias="permissionEvidenceDigest",
    )

    @model_validator(mode="after")
    def validate_query_window(self) -> _LogQueryCollectionRecord:
        if (
            self.frequency_seconds > self.evaluation_window_seconds
            or self.evaluation_window_seconds % self.frequency_seconds != 0
        ):
            raise ValueError("query frequency must divide the evaluation window")
        expected = compute_monitoring_query_execution_digest(
            control_id=self.control_id,
            source_record_id=self.source_record_id,
            query_digest=self.query_digest,
            query_target_resource_id=self.query_target_resource_id,
            observed_start=self.observed_start,
            observed_end=self.observed_end,
            evaluation_window_seconds=self.evaluation_window_seconds,
            frequency_seconds=self.frequency_seconds,
        )
        if self.query_execution_digest != expected:
            raise ValueError("queryExecutionDigest does not bind exact query execution")
        return self


class AmaHeartbeatRecord(_LogQueryCollectionRecord):
    record_kind: Literal["amaHeartbeat"] = Field(alias="recordKind")
    resource_id: str = Field(alias="resourceId", min_length=1, max_length=2048)
    heartbeat_count: int | None = Field(
        alias="heartbeatCount",
        default=None,
        ge=0,
    )


class VmConnectionHealthRecord(_LogQueryCollectionRecord):
    record_kind: Literal["vmConnectionHealth"] = Field(alias="recordKind")
    subject_resource_id: str = Field(
        alias="subjectResourceId",
        min_length=1,
        max_length=2048,
    )
    backend_resource_ids: tuple[str, ...] = Field(
        alias="backendResourceIds",
        min_length=1,
        max_length=128,
    )
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    failed_connection_count: int | None = Field(
        alias="failedConnectionCount",
        default=None,
        ge=0,
    )


class ConnectionMonitorRecord(_LogQueryCollectionRecord):
    record_kind: Literal["connectionMonitor"] = Field(alias="recordKind")
    subject_resource_id: str = Field(
        alias="subjectResourceId",
        min_length=1,
        max_length=2048,
    )
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    monitor_resource_id: str = Field(
        alias="monitorResourceId",
        min_length=1,
        max_length=2048,
    )
    source_resource_id: str = Field(
        alias="sourceResourceId",
        min_length=1,
        max_length=2048,
    )
    destination_resource_id: str = Field(
        alias="destinationResourceId",
        min_length=1,
        max_length=2048,
    )
    source_address: str = Field(alias="sourceAddress", min_length=2, max_length=45)
    destination_address: str = Field(
        alias="destinationAddress",
        min_length=2,
        max_length=45,
    )
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_port: int | None = Field(default=None, alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(
        default=None,
        alias="destinationPort",
        ge=0,
        le=65535,
    )
    status: Literal["succeeded", "failed", "degraded", "unknown"]
    test_configuration_reference: str = Field(
        alias="testConfigurationReference",
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    test_configuration_digest: Sha256Digest = Field(alias="testConfigurationDigest")


class NetworkRuleAttributionEvidence(_StrictCollectionModel):
    schema_version: Literal["athena.wc028NetworkRuleAttributionEvidence.v1"] = Field(
        alias="schemaVersion"
    )
    method: Literal["ipFlowVerify", "effectiveRuleEvaluation"]
    access: Literal["Deny"]
    previous_access: Literal["Allow"] = Field(alias="previousAccess")
    current_access: Literal["Deny"] = Field(alias="currentAccess")
    rule_resource_id: str = Field(
        alias="ruleResourceId",
        min_length=1,
        max_length=2048,
    )
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_address: str = Field(alias="sourceAddress", min_length=2, max_length=45)
    destination_address: str = Field(
        alias="destinationAddress",
        min_length=2,
        max_length=45,
    )
    source_port: int | None = Field(default=None, alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(
        default=None,
        alias="destinationPort",
        ge=0,
        le=65535,
    )
    change_correlation_id: str = Field(
        alias="changeCorrelationId",
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )


class NetworkWatcherFlowRecord(_LogQueryCollectionRecord):
    record_kind: Literal["networkWatcherFlow"] = Field(alias="recordKind")
    subject_resource_id: str = Field(
        alias="subjectResourceId",
        min_length=1,
        max_length=2048,
    )
    path_id: str = Field(alias="pathId", pattern=r"^path-[a-f0-9]{32}$")
    decision: Literal["allowed", "denied", "unknown"]
    direction: Literal["inbound", "outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Any"]
    source_resource_id: str = Field(
        alias="sourceResourceId",
        min_length=1,
        max_length=2048,
    )
    destination_resource_id: str = Field(
        alias="destinationResourceId",
        min_length=1,
        max_length=2048,
    )
    source_address: str = Field(alias="sourceAddress", min_length=2, max_length=45)
    destination_address: str = Field(
        alias="destinationAddress",
        min_length=2,
        max_length=45,
    )
    source_port: int | None = Field(default=None, alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(
        default=None,
        alias="destinationPort",
        ge=0,
        le=65535,
    )
    enforcement_resource_id: str = Field(
        alias="enforcementResourceId",
        min_length=1,
        max_length=2048,
    )
    rule_resource_id: str | None = Field(
        default=None,
        alias="ruleResourceId",
        min_length=1,
        max_length=2048,
    )
    ip_flow_provenance: MonitoringIpFlowProvenance | None = Field(
        default=None,
        alias="ipFlowProvenance",
    )
    change_correlation_id: str | None = Field(
        default=None,
        alias="changeCorrelationId",
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    attribution_method: Literal["ipFlowVerify", "effectiveRuleEvaluation"] | None = Field(
        default=None, alias="attributionMethod"
    )
    attribution_evidence: NetworkRuleAttributionEvidence | None = Field(
        default=None,
        alias="attributionEvidence",
    )

    @model_validator(mode="after")
    def validate_attribution_pair(self) -> NetworkWatcherFlowRecord:
        provenance = self.ip_flow_provenance
        if provenance is not None and provenance.checked_at < self.observed_end:
            raise ValueError("network flow IP Flow checkedAt must not predate historical evidence")
        if provenance is not None and (
            provenance.historical_decision != self.decision
            or self.rule_resource_id is None
            or provenance.historical_rule_resource_id.casefold().rstrip("/")
            != self.rule_resource_id.casefold().rstrip("/")
            or provenance.source_resource_id.casefold().rstrip("/")
            != self.source_resource_id.casefold().rstrip("/")
            or provenance.destination_resource_id.casefold().rstrip("/")
            != self.destination_resource_id.casefold().rstrip("/")
            or provenance.direction != self.direction
            or provenance.protocol != self.protocol
            or provenance.source_address != self.source_address
            or provenance.destination_address != self.destination_address
            or provenance.source_port != self.source_port
            or provenance.destination_port != self.destination_port
            or provenance.causal_change_correlation_id != self.change_correlation_id
        ):
            raise ValueError("network flow IP Flow provenance does not bind the retained flow")
        values = (
            self.change_correlation_id,
            self.attribution_method,
            self.attribution_evidence,
        )
        if any(value is not None for value in values) and not all(
            value is not None for value in values
        ):
            raise ValueError("flow attribution requires correlation ID, method, and exact evidence")
        if self.attribution_method == "ipFlowVerify" and (
            provenance is None
            or provenance.access != "Deny"
            or provenance.result_rule_resource_id is None
            or self.rule_resource_id is None
            or provenance.result_rule_resource_id.casefold().rstrip("/")
            != self.rule_resource_id.casefold().rstrip("/")
        ):
            raise ValueError("IP Flow attribution requires an exact denied point-in-time rule")
        return self


class ResourceHealthRecord(_WindowedCollectionRecord):
    record_kind: Literal["resourceHealth"] = Field(alias="recordKind")
    resource_id: str = Field(alias="resourceId", min_length=1, max_length=2048)
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


class ResourceChangeRecord(_CollectionRecord):
    record_kind: Literal["resourceChange"] = Field(alias="recordKind")
    category: str = Field(min_length=1, max_length=256)
    operation_name: str = Field(
        alias="operationName",
        min_length=1,
        max_length=256,
    )
    result_type: str = Field(alias="resultType", min_length=1, max_length=256)
    level: Literal["Critical", "Error", "Informational", "Verbose", "Warning"]
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    correlation_id: str = Field(
        alias="correlationId",
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    occurred_at: UtcDateTime = Field(alias="occurredAt")
    resource_graph_change: dict[str, object] = Field(alias="resourceGraphChange")


type MonitoringCollectionRecord = Annotated[
    AmaHeartbeatRecord
    | VmConnectionHealthRecord
    | ConnectionMonitorRecord
    | NetworkWatcherFlowRecord
    | ResourceHealthRecord
    | ResourceChangeRecord,
    Field(discriminator="record_kind"),
]


class MonitoringCoverageRecord(_WindowedCollectionRecord):
    family: Literal[
        "guest",
        "networkFlow",
        "connectionMonitor",
        "endpointHealth",
        "platformHealth",
    ]
    resource_ids: tuple[str, ...] = Field(
        alias="resourceIds",
        min_length=1,
        max_length=128,
    )
    path_id: str | None = Field(
        default=None,
        alias="pathId",
        pattern=r"^path-[a-f0-9]{32}$",
    )
    direction: Literal["inbound", "outbound"] | None = None
    five_tuple_digest: Sha256Digest | None = Field(
        default=None,
        alias="fiveTupleDigest",
    )
    endpoint_test_reference: str | None = Field(
        default=None,
        alias="endpointTestReference",
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    endpoint_test_digest: Sha256Digest | None = Field(
        default=None,
        alias="endpointTestDigest",
    )
    query_digest: Sha256Digest | None = Field(default=None, alias="queryDigest")
    query_target_resource_id: str | None = Field(
        default=None,
        alias="queryTargetResourceId",
        min_length=1,
        max_length=2048,
    )
    evaluation_window_seconds: int | None = Field(
        default=None,
        alias="evaluationWindowSeconds",
        ge=60,
        le=86400,
    )
    frequency_seconds: int | None = Field(
        default=None,
        alias="frequencySeconds",
        ge=60,
        le=3600,
    )
    query_execution_digests: tuple[Sha256Digest, ...] = Field(
        default=(),
        alias="queryExecutionDigests",
        max_length=1440,
    )
    log_permission_evidence: MonitoringLogPermissionEvidence | None = Field(
        default=None,
        alias="logPermissionEvidence",
    )
    status: Literal["complete", "partial", "unavailable", "truncated"]
    detail: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_query_binding_shape(self) -> MonitoringCoverageRecord:
        query_values = (
            self.query_digest,
            self.query_target_resource_id,
            self.evaluation_window_seconds,
            self.frequency_seconds,
        )
        if self.family == "platformHealth":
            if (
                any(value is not None for value in query_values)
                or self.query_execution_digests
                or self.log_permission_evidence is not None
            ):
                raise ValueError("platform health coverage cannot claim query execution")
            return self
        if any(value is None for value in query_values):
            raise ValueError("query-derived coverage requires exact query execution binding")
        if self.status == "complete" and not self.query_execution_digests:
            raise ValueError("complete query coverage requires executed query digests")
        if self.status == "unavailable" and self.query_execution_digests:
            raise ValueError("unavailable query coverage cannot claim executed queries")
        if self.query_execution_digests != tuple(sorted(self.query_execution_digests)) or len(
            self.query_execution_digests
        ) != len(set(self.query_execution_digests)):
            raise ValueError("queryExecutionDigests must be sorted unique values")
        return self


class MonitoringCollectionBatch(_StrictCollectionModel):
    schema_version: Literal["athena.wc028MonitoringCollectionBatch.v2"] = Field(
        alias="schemaVersion"
    )
    collected_at: UtcDateTime = Field(alias="collectedAt")
    incident_resource_id: str = Field(
        alias="incidentResourceId",
        min_length=1,
        max_length=2048,
    )
    previous_health_source_record_id: str = Field(
        alias="previousHealthSourceRecordId",
        min_length=1,
        max_length=2048,
    )
    current_health_source_record_ids: tuple[str, ...] = Field(
        alias="currentHealthSourceRecordIds",
        min_length=1,
        max_length=32,
    )
    records: tuple[MonitoringCollectionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_MONITORING_COLLECTION_RECORDS,
    )
    coverage: tuple[MonitoringCoverageRecord, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator("current_health_source_record_ids")
    @classmethod
    def validate_current_health_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("currentHealthSourceRecordIds must be unique deterministic values")
        return values

    @model_validator(mode="after")
    def validate_batch(self) -> MonitoringCollectionBatch:
        record_ids = tuple(item.source_record_id for item in self.records)
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("sourceRecordId must be unique within one collection")
        coverage_ids = tuple(item.source_record_id for item in self.coverage)
        if len(coverage_ids) != len(set(coverage_ids)):
            raise ValueError("coverage sourceRecordId must be unique within one collection")
        selected = {
            self.previous_health_source_record_id,
            *self.current_health_source_record_ids,
        }
        if not selected.issubset(record_ids):
            raise ValueError("incident health records must exist in the collection")
        if len(self.canonical_bytes()) > MAX_MONITORING_COLLECTION_BYTES:
            raise ValueError("monitoring collection exceeds its canonical byte budget")
        return self


@dataclass(frozen=True)
class PreparedMonitoringCollection:
    intent_id: str
    intent_digest: str
    context_binding_digest: str
    monitoring_intent_reference: PublishedMonitoringIntentAssetReference
    monitoring_bundle: MonitoringEvidenceBundle
    change_artifacts: tuple[ChangeEvidenceArtifact, ...]
    incident_resource_id: str
    previous_health_source_record_id: str
    current_health_source_record_ids: tuple[str, ...]
    previous_health_observation_id: str
    current_health_observation_ids: tuple[str, ...]
    current_health_state: Literal["degraded", "unhealthy", "unavailable"]


@dataclass(frozen=True)
class CommittedMonitoringCollection:
    monitoring_handoff: MonitoringEvidenceHandoff
    change_handoffs: tuple[ChangeEvidencePersistenceHandoff, ...]


class MonitoringCollectionCommitPort(Protocol):
    """Atomically persist one prepared monitoring bundle and its change artifacts."""

    def transaction(
        self,
        prepared: PreparedMonitoringCollection,
    ) -> AbstractContextManager[CommittedMonitoringCollection]: ...


def _canonical_resource_id(value: str) -> str:
    normalized = value.casefold().rstrip("/")
    if not normalized.startswith("/subscriptions/") or len(normalized) > 2048:
        raise MonitoringCollectionError("record contains an invalid Azure resource ID")
    return normalized


def _opaque_reference(prefix: str, value: str) -> str:
    return f"{prefix}:sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _source_root(control: PublishedMonitoringIntentControl, intent_digest: str) -> str:
    return _opaque_reference(
        "monitoring-control",
        f"{intent_digest}\0{control.control_id}\0{control.control_digest}",
    )


def _control_provenance(
    control: PublishedMonitoringIntentControl,
) -> MonitoringControlProvenance:
    return MonitoringControlProvenance(
        controlId=control.control_id,
        controlDigest=control.control_digest,
        sourceClausePath=control.source_clause_path,
    )


def _monitoring_intent_evidence_reference(
    reference: PublishedMonitoringIntentAssetReference,
) -> MonitoringIntentEvidenceReference:
    return MonitoringIntentEvidenceReference(
        intentId=reference.intent_id,
        intentDigest=reference.intent_digest,
        assetReferenceId=reference.reference_id,
        assetReferenceDigest=reference.reference_digest,
        intentReference=reference.intent_reference,
        attestationReference=reference.attestation_reference,
    )


def _record_reference(prefix: str, source_record_id: str) -> str:
    return monitoring_source_record_reference(prefix, source_record_id)


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _observation[
    ObservationT: (
        GuestSignalObservation,
        EndpointHealthObservation,
        ConnectionMonitorObservation,
        NetworkFlowObservation,
        PlatformHealthObservation,
    )
](
    model: type[ObservationT],
    payload: dict[str, object],
) -> ObservationT:
    digest = compute_artifact_digest(_json_value(payload))
    return model.model_validate(
        {
            **payload,
            "observationId": f"obs-{digest.removeprefix('sha256:')[:32]}",
            "observationDigest": digest,
        }
    )


def _coverage(
    record: MonitoringCoverageRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
) -> EvidenceCoverage:
    expected_family = _coverage_family(control)
    if record.family != expected_family:
        raise MonitoringCollectionError(
            "coverage family does not match its published monitoring control"
        )
    scope_payload: dict[str, object] = {
        "resourceIds": tuple(sorted(_canonical_resource_id(item) for item in record.resource_ids)),
        "pathId": record.path_id,
        "direction": record.direction,
        "fiveTupleDigest": record.five_tuple_digest,
        "endpointTestReference": record.endpoint_test_reference,
        "endpointTestDigest": record.endpoint_test_digest,
        "queryScopeDigest": control.control_digest,
    }
    scope_digest = compute_artifact_digest(_json_value(scope_payload))
    scope = EvidenceCoverageScope.model_validate(
        {
            **scope_payload,
            "scopeId": f"coverage-scope-{scope_digest.removeprefix('sha256:')[:32]}",
            "scopeDigest": scope_digest,
        }
    )
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "family": record.family,
        "scope": scope,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "coverage-query",
            record.source_record_id,
        ),
        "coverageStart": record.observed_start,
        "coverageEnd": record.observed_end,
        "controlProvenance": _control_provenance(control),
        "status": record.status,
        "detail": record.detail,
    }
    if record.query_execution_digests:
        payload["queryExecutionDigests"] = record.query_execution_digests
    if record.log_permission_evidence is not None:
        payload["logPermissionEvidence"] = record.log_permission_evidence
    digest = compute_artifact_digest(_json_value(payload))
    return EvidenceCoverage.model_validate(
        {
            **payload,
            "coverageId": f"coverage-{digest.removeprefix('sha256:')[:32]}",
            "coverageDigest": digest,
        }
    )


def _condition_matches(
    signal: LogQueryMonitoringSignal,
    value: int | None,
    *,
    missing_data_behavior: str,
) -> bool | None:
    if value is None:
        if missing_data_behavior in {"failClosed", "treatAsUnhealthy"}:
            return True
        if missing_data_behavior == "treatAsHealthy":
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


def _require_log_query(
    control: PublishedMonitoringIntentControl,
    record: _LogQueryCollectionRecord,
    *,
    collected_at: datetime,
    trusted_as_of: datetime,
    required_table: str,
) -> LogQueryMonitoringSignal:
    if not isinstance(control.signal, LogQueryMonitoringSignal):
        raise MonitoringCollectionError(
            "collector record requires an exact published log-query control"
        )
    signal = control.signal
    expected_execution_digest = compute_monitoring_query_execution_digest(
        control_id=record.control_id,
        source_record_id=record.source_record_id,
        query_digest=record.query_digest,
        query_target_resource_id=record.query_target_resource_id,
        observed_start=record.observed_start,
        observed_end=record.observed_end,
        evaluation_window_seconds=record.evaluation_window_seconds,
        frequency_seconds=record.frequency_seconds,
    )
    if (
        signal.query_digest != record.query_digest
        or _canonical_resource_id(signal.query_target_resource_id)
        != _canonical_resource_id(record.query_target_resource_id)
        or signal.evaluation_window_seconds != record.evaluation_window_seconds
        or signal.frequency_seconds != record.frequency_seconds
        or record.query_execution_digest != expected_execution_digest
    ):
        raise MonitoringCollectionError(
            "collector query execution does not match published monitoring intent"
        )
    if _query_source_table(signal) != required_table.casefold():
        raise MonitoringCollectionError(
            "collector record kind does not match the published query source"
        )
    if (
        (record.observed_end - record.observed_start).total_seconds()
        != signal.evaluation_window_seconds
        or record.observed_end > collected_at
        or record.observed_end > trusted_as_of
        or (collected_at - record.observed_end).total_seconds()
        > signal.evaluation_window_seconds + signal.frequency_seconds
        or (trusted_as_of - record.observed_end).total_seconds()
        > signal.evaluation_window_seconds + signal.frequency_seconds
    ):
        raise MonitoringCollectionError(
            "collector query result is outside its published evaluation window"
        )
    return signal


def _query_source_table(signal: LogQueryMonitoringSignal) -> str:
    first_table = re.match(r"^[A-Za-z][A-Za-z0-9_]*", signal.query)
    return "" if first_table is None else first_table.group(0).casefold()


def _coverage_family(
    control: PublishedMonitoringIntentControl,
) -> Literal[
    "guest",
    "networkFlow",
    "connectionMonitor",
    "endpointHealth",
    "platformHealth",
]:
    if isinstance(control.signal, ResourceHealthMonitoringSignal):
        return "platformHealth"
    if not isinstance(control.signal, LogQueryMonitoringSignal):
        raise MonitoringCollectionError("Activity Log controls cannot declare monitoring coverage")
    family_by_table = {
        "heartbeat": "guest",
        "vmconnection": "endpointHealth",
        "nwconnectionmonitortestresult": "connectionMonitor",
        "ntanetanalytics": "networkFlow",
    }
    family = family_by_table.get(_query_source_table(control.signal))
    if family is None:
        raise MonitoringCollectionError(
            "published query source has no supported monitoring coverage family"
        )
    return cast(
        Literal[
            "guest",
            "networkFlow",
            "connectionMonitor",
            "endpointHealth",
            "platformHealth",
        ],
        family,
    )


def _require_resources(
    control: PublishedMonitoringIntentControl,
    *resource_ids: str,
) -> tuple[str, ...]:
    normalized = tuple(_canonical_resource_id(item) for item in resource_ids)
    if not set(normalized).issubset(control.scope.resource_ids):
        raise MonitoringCollectionError(
            "collector record escapes the published monitoring control scope"
        )
    return normalized


def _require_evidence_resources(
    control: PublishedMonitoringIntentControl,
    *resource_ids: str,
) -> tuple[str, ...]:
    normalized = tuple(_canonical_resource_id(item) for item in resource_ids)
    if not set(normalized).issubset(control.scope.evidence_resource_ids or ()):
        raise MonitoringCollectionError(
            "collector evidence resource escapes the published evidence scope"
        )
    return normalized


def _require_path(
    control: PublishedMonitoringIntentControl,
    path_id: str,
    context: PublishedRuntimeContextBinding,
    resource_ids: tuple[str, ...],
) -> None:
    if path_id not in control.scope.path_ids:
        raise MonitoringCollectionError(
            "collector record path is not authorized by monitoring intent"
        )
    path = next(
        (item for item in context.dependency_paths if item.path_id == path_id),
        None,
    )
    if path is None or not set(resource_ids).issubset(path.resource_ids):
        raise MonitoringCollectionError(
            "collector record does not bind one governed dependency path"
        )


def _validate_record_window(
    record: _WindowedCollectionRecord,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> None:
    if record.observed_end > collected_at or record.observed_end > trusted_as_of:
        raise MonitoringCollectionError("collector record is newer than collectedAt or trustedAsOf")


def _heartbeat_observation(
    record: AmaHeartbeatRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> GuestSignalObservation:
    signal = _require_log_query(
        control,
        record,
        collected_at=collected_at,
        trusted_as_of=trusted_as_of,
        required_table="Heartbeat",
    )
    (resource_id,) = _require_resources(control, record.resource_id)
    condition = _condition_matches(
        signal,
        record.heartbeat_count,
        missing_data_behavior=control.missing_data_behavior,
    )
    state = "unknown" if condition is None else "unhealthy" if condition else "healthy"
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "observationKind": "guestSignal",
        "subjectResourceId": resource_id,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "ama-heartbeat",
            record.source_record_id,
        ),
        "controlProvenance": _control_provenance(control),
        "queryExecutionDigest": record.query_execution_digest,
        "permissionEvidenceDigest": record.permission_evidence_digest,
        "summaryCode": (
            "guest.heartbeat-review"
            if condition is None
            else "guest.heartbeat-loss"
            if condition
            else "guest.heartbeat-healthy"
        ),
        "signal": "heartbeatLoss",
        "state": state,
        "value": (None if record.heartbeat_count is None else float(record.heartbeat_count)),
        "unit": signal.unit,
        "thresholdDigest": control.control_digest,
        "serviceReference": None,
    }
    return _observation(GuestSignalObservation, payload)


def _endpoint_observation(
    record: VmConnectionHealthRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
    context: PublishedRuntimeContextBinding,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> EndpointHealthObservation:
    signal = _require_log_query(
        control,
        record,
        collected_at=collected_at,
        trusted_as_of=trusted_as_of,
        required_table="VMConnection",
    )
    subject_id = _canonical_resource_id(record.subject_resource_id)
    backend_ids = tuple(
        sorted(_canonical_resource_id(item) for item in record.backend_resource_ids)
    )
    resources = _require_resources(control, subject_id, *backend_ids)
    _require_path(control, record.path_id, context, resources)
    condition = _condition_matches(
        signal,
        record.failed_connection_count,
        missing_data_behavior=control.missing_data_behavior,
    )
    status = "unknown" if condition is None else "unhealthy" if condition else "healthy"
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "observationKind": "endpointHealth",
        "subjectResourceId": subject_id,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "vm-insights",
            record.source_record_id,
        ),
        "controlProvenance": _control_provenance(control),
        "queryExecutionDigest": record.query_execution_digest,
        "permissionEvidenceDigest": record.permission_evidence_digest,
        "summaryCode": (
            "endpoint.vm-connection-review"
            if condition is None
            else "endpoint.vm-connection-failed"
            if condition
            else "endpoint.vm-connection-healthy"
        ),
        "pathId": record.path_id,
        "status": status,
        "backendResourceIds": backend_ids,
    }
    return _observation(EndpointHealthObservation, payload)


def _tuple_payload(
    record: ConnectionMonitorRecord | NetworkWatcherFlowRecord,
    *,
    source_resource_id: str,
    destination_resource_id: str,
) -> dict[str, object]:
    return {
        "direction": record.direction,
        "protocol": record.protocol,
        "sourceResourceId": source_resource_id,
        "destinationResourceId": destination_resource_id,
        "sourceAddress": record.source_address,
        "destinationAddress": record.destination_address,
        "sourcePort": record.source_port,
        "destinationPort": record.destination_port,
    }


def _record_matches_coverage_scope(
    record: _LogQueryCollectionRecord,
    coverage: MonitoringCoverageRecord,
) -> bool:
    resources = {_canonical_resource_id(item) for item in coverage.resource_ids}
    if isinstance(record, AmaHeartbeatRecord):
        return (
            coverage.path_id is None
            and coverage.direction is None
            and coverage.five_tuple_digest is None
            and resources == {_canonical_resource_id(record.resource_id)}
        )
    if isinstance(record, VmConnectionHealthRecord):
        return (
            coverage.path_id == record.path_id
            and coverage.direction is None
            and coverage.five_tuple_digest is None
            and resources
            == {
                _canonical_resource_id(record.subject_resource_id),
                *(_canonical_resource_id(item) for item in record.backend_resource_ids),
            }
        )
    if not isinstance(record, (ConnectionMonitorRecord, NetworkWatcherFlowRecord)):
        return False
    source_id = _canonical_resource_id(record.source_resource_id)
    destination_id = _canonical_resource_id(record.destination_resource_id)
    tuple_digest = compute_artifact_digest(
        _tuple_payload(
            record,
            source_resource_id=source_id,
            destination_resource_id=destination_id,
        )
    )
    if isinstance(record, ConnectionMonitorRecord):
        return (
            coverage.path_id == record.path_id
            and coverage.direction == record.direction
            and coverage.five_tuple_digest == tuple_digest
            and coverage.endpoint_test_reference == record.test_configuration_reference
            and coverage.endpoint_test_digest == record.test_configuration_digest
            and resources == {source_id, destination_id}
        )
    if not isinstance(record, NetworkWatcherFlowRecord):
        return False
    expected_resources = {
        _canonical_resource_id(record.subject_resource_id),
        source_id,
        destination_id,
        _canonical_resource_id(record.enforcement_resource_id),
    }
    if record.rule_resource_id is not None:
        expected_resources.add(_canonical_resource_id(record.rule_resource_id))
    return (
        coverage.path_id == record.path_id
        and coverage.direction == record.direction
        and coverage.five_tuple_digest == tuple_digest
        and coverage.endpoint_test_reference is None
        and coverage.endpoint_test_digest is None
        and resources == expected_resources
    )


def _validate_coverage_query_binding(
    coverage: MonitoringCoverageRecord,
    control: PublishedMonitoringIntentControl,
    records_by_execution: Mapping[str, _LogQueryCollectionRecord],
    *,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> None:
    if isinstance(control.signal, ResourceHealthMonitoringSignal):
        resource_health_signal = control.signal
        if (
            coverage.observed_end > collected_at
            or coverage.observed_end > trusted_as_of
            or (collected_at - coverage.observed_start).total_seconds()
            > resource_health_signal.maximum_event_age_seconds
            or (collected_at - coverage.observed_end).total_seconds()
            > resource_health_signal.maximum_event_age_seconds
            or (trusted_as_of - coverage.observed_start).total_seconds()
            > resource_health_signal.maximum_event_age_seconds
            or (trusted_as_of - coverage.observed_end).total_seconds()
            > resource_health_signal.maximum_event_age_seconds
        ):
            raise MonitoringCollectionError(
                "resource-health coverage is outside the reviewed freshness limit"
            )
        return
    if not isinstance(control.signal, LogQueryMonitoringSignal):
        raise MonitoringCollectionError("Activity Log controls cannot declare monitoring coverage")
    signal = control.signal
    if (
        coverage.query_digest != signal.query_digest
        or coverage.query_target_resource_id is None
        or _canonical_resource_id(coverage.query_target_resource_id)
        != _canonical_resource_id(signal.query_target_resource_id)
        or coverage.evaluation_window_seconds != signal.evaluation_window_seconds
        or coverage.frequency_seconds != signal.frequency_seconds
    ):
        raise MonitoringCollectionError(
            "coverage query execution does not match published monitoring intent"
        )
    if (
        coverage.observed_end > collected_at
        or coverage.observed_end > trusted_as_of
        or (coverage.observed_end - coverage.observed_start).total_seconds() <= 0
        or (collected_at - coverage.observed_end).total_seconds()
        > signal.evaluation_window_seconds + signal.frequency_seconds
        or (trusted_as_of - coverage.observed_end).total_seconds()
        > signal.evaluation_window_seconds + signal.frequency_seconds
    ):
        raise MonitoringCollectionError("coverage is outside its reviewed freshness window")
    if coverage.status == "unavailable":
        if (
            coverage.observed_end - coverage.observed_start
        ).total_seconds() != signal.evaluation_window_seconds:
            raise MonitoringCollectionError(
                "unavailable coverage must use one reviewed evaluation window"
            )
        return
    try:
        executions = tuple(
            records_by_execution[digest] for digest in coverage.query_execution_digests
        )
    except KeyError as exc:
        raise MonitoringCollectionError("coverage references an unknown query execution") from exc
    if any(
        record.control_id != coverage.control_id
        or record.query_digest != coverage.query_digest
        or record.query_target_resource_id.casefold().rstrip("/")
        != coverage.query_target_resource_id.casefold().rstrip("/")
        or record.evaluation_window_seconds != coverage.evaluation_window_seconds
        or record.frequency_seconds != coverage.frequency_seconds
        or not _record_matches_coverage_scope(record, coverage)
        for record in executions
    ):
        raise MonitoringCollectionError("coverage does not bind exact query executions and scope")
    if coverage.log_permission_evidence is not None and any(
        record.permission_evidence_digest != coverage.log_permission_evidence.evidence_digest
        for record in executions
    ):
        raise MonitoringCollectionError("coverage does not bind exact Logs permission evidence")
    ordered = tuple(
        sorted(
            executions,
            key=lambda item: (
                item.observed_start,
                item.observed_end,
                item.query_execution_digest,
            ),
        )
    )
    if (
        not ordered
        or ordered[0].observed_start != coverage.observed_start
        or ordered[-1].observed_end != coverage.observed_end
        or any(
            (current.observed_start - previous.observed_start).total_seconds()
            != signal.frequency_seconds
            or (current.observed_end - previous.observed_end).total_seconds()
            != signal.frequency_seconds
            for previous, current in zip(ordered, ordered[1:], strict=False)
        )
    ):
        raise MonitoringCollectionError(
            "coverage query executions are not exact contiguous scheduled coverage"
        )


def _connection_monitor_observation(
    record: ConnectionMonitorRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
    context: PublishedRuntimeContextBinding,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> ConnectionMonitorObservation:
    _require_log_query(
        control,
        record,
        collected_at=collected_at,
        trusted_as_of=trusted_as_of,
        required_table="NWConnectionMonitorTestResult",
    )
    (monitor_id,) = _require_evidence_resources(
        control,
        record.monitor_resource_id,
    )
    source_id, destination_id = _require_resources(
        control,
        record.source_resource_id,
        record.destination_resource_id,
    )
    subject_id = _canonical_resource_id(record.subject_resource_id)
    if subject_id not in {source_id, destination_id}:
        raise MonitoringCollectionError("Connection Monitor subject must be one endpoint")
    _require_path(
        control,
        record.path_id,
        context,
        (source_id, destination_id),
    )
    tuple_payload = _tuple_payload(
        record,
        source_resource_id=source_id,
        destination_resource_id=destination_id,
    )
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "observationKind": "connectionMonitor",
        "subjectResourceId": subject_id,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "connection-monitor",
            record.source_record_id,
        ),
        "controlProvenance": _control_provenance(control),
        "queryExecutionDigest": record.query_execution_digest,
        "permissionEvidenceDigest": record.permission_evidence_digest,
        "summaryCode": f"network.connection-monitor-{record.status}",
        "pathId": record.path_id,
        "monitorResourceId": monitor_id,
        **tuple_payload,
        "fiveTupleDigest": compute_artifact_digest(tuple_payload),
        "status": record.status,
        "testConfigurationReference": record.test_configuration_reference,
        "testConfigurationDigest": record.test_configuration_digest,
    }
    return _observation(ConnectionMonitorObservation, payload)


def _causal_property_paths(artifact: ChangeEvidenceArtifact) -> tuple[str, ...]:
    return tuple(
        item.path
        for item in artifact.evidence.changed_properties
        if any(
            item.path.casefold() == prefix or item.path.casefold().startswith(f"{prefix}[")
            for prefix in _CAUSAL_NSG_PROPERTY_PREFIXES
        )
    )


def _matched_change(
    record: NetworkWatcherFlowRecord,
    artifacts: tuple[ChangeEvidenceArtifact, ...],
    deny_introducing_evidence_ids: frozenset[str],
) -> ChangeEvidenceArtifact | None:
    if (
        record.change_correlation_id is None
        or record.rule_resource_id is None
        or record.decision != "denied"
    ):
        return None
    rule_id = _canonical_resource_id(record.rule_resource_id)
    candidates = tuple(
        artifact
        for artifact in artifacts
        if artifact.evidence.target_resource_id == rule_id
        and artifact.evidence.evidence_id in deny_introducing_evidence_ids
        and artifact.evidence.correlation_id == record.change_correlation_id
        and artifact.evidence.result == "succeeded"
        and artifact.evidence.occurred_at <= record.observed_start
        and _causal_property_paths(artifact)
    )
    return candidates[0] if len(candidates) == 1 else None


def _validate_attribution_evidence(record: NetworkWatcherFlowRecord) -> None:
    evidence = record.attribution_evidence
    if evidence is None:
        return
    if (
        record.decision != "denied"
        or record.rule_resource_id is None
        or record.change_correlation_id is None
        or record.attribution_method is None
        or evidence.method != record.attribution_method
        or evidence.rule_resource_id.casefold().rstrip("/")
        != record.rule_resource_id.casefold().rstrip("/")
        or evidence.direction != record.direction
        or evidence.protocol != record.protocol
        or evidence.source_address != record.source_address
        or evidence.destination_address != record.destination_address
        or evidence.source_port != record.source_port
        or evidence.destination_port != record.destination_port
        or evidence.change_correlation_id != record.change_correlation_id
    ):
        raise MonitoringCollectionError(
            "Network Watcher attribution proof does not bind the denied flow"
        )


def _network_flow_observation(
    record: NetworkWatcherFlowRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
    context: PublishedRuntimeContextBinding,
    artifacts: tuple[ChangeEvidenceArtifact, ...],
    deny_introducing_evidence_ids: frozenset[str],
    collected_at: datetime,
    trusted_as_of: datetime,
) -> NetworkFlowObservation:
    _require_log_query(
        control,
        record,
        collected_at=collected_at,
        trusted_as_of=trusted_as_of,
        required_table="NTANetAnalytics",
    )
    _validate_attribution_evidence(record)
    resources_to_authorize = [
        record.subject_resource_id,
        record.source_resource_id,
        record.destination_resource_id,
        record.enforcement_resource_id,
    ]
    if record.rule_resource_id is not None:
        resources_to_authorize.append(record.rule_resource_id)
    normalized = _require_resources(control, *resources_to_authorize)
    subject_id = normalized[0]
    source_id = normalized[1]
    destination_id = normalized[2]
    enforcement_id = normalized[3]
    rule_id = normalized[4] if len(normalized) == 5 else None
    provenance = record.ip_flow_provenance
    if provenance is not None and provenance.result_rule_resource_id is not None:
        _require_resources(control, provenance.result_rule_resource_id)
    _require_path(control, record.path_id, context, normalized)
    tuple_payload = _tuple_payload(
        record,
        source_resource_id=source_id,
        destination_resource_id=destination_id,
    )
    matched = _matched_change(
        record,
        artifacts,
        deny_introducing_evidence_ids,
    )
    if record.attribution_evidence is not None and matched is None:
        raise MonitoringCollectionError(
            "Network Watcher attribution proof does not match one deny-introducing change"
        )
    attributed = (
        matched is not None
        and record.attribution_method is not None
        and record.attribution_evidence is not None
    )
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "observationKind": "networkFlow",
        "subjectResourceId": subject_id,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "network-watcher",
            record.source_record_id,
        ),
        "controlProvenance": _control_provenance(control),
        "queryExecutionDigest": record.query_execution_digest,
        "permissionEvidenceDigest": record.permission_evidence_digest,
        "summaryCode": (
            f"network.flow-{record.decision}"
            if provenance is None
            else f"network.flow-{record.decision}-ipflow-{provenance.access.casefold()}"
        ),
        "pathId": record.path_id,
        "decision": record.decision,
        **tuple_payload,
        "enforcementResourceId": enforcement_id,
        "ruleResourceId": rule_id,
        "ipFlowProvenance": provenance,
        "fiveTupleDigest": compute_artifact_digest(tuple_payload),
        "effectiveRuleAttribution": attributed,
        "attributionMethod": record.attribution_method if attributed else None,
        "causalEffect": "introducedDenyForTuple" if attributed else None,
        "attributionProofDigest": (
            compute_artifact_digest(
                record.attribution_evidence.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            )
            if attributed and record.attribution_evidence is not None
            else None
        ),
        "matchedChangeKey": (
            matched.evidence.change_key if matched is not None and attributed else None
        ),
        "matchedChangeEvidenceId": (
            matched.evidence.evidence_id if matched is not None and attributed else None
        ),
        "matchedChangeArtifactDigest": (
            sha256_hex(matched.canonical_bytes()) if matched is not None and attributed else None
        ),
        "matchedPropertyPaths": (
            _causal_property_paths(matched) if matched is not None and attributed else ()
        ),
    }
    return _observation(NetworkFlowObservation, payload)


def _resource_health_observation(
    record: ResourceHealthRecord,
    control: PublishedMonitoringIntentControl,
    intent_digest: str,
    collected_at: datetime,
    trusted_as_of: datetime,
) -> PlatformHealthObservation:
    if not isinstance(control.signal, ResourceHealthMonitoringSignal):
        raise MonitoringCollectionError(
            "resource-health record requires an exact published health control"
        )
    signal = control.signal
    if (
        record.event_status not in signal.event_statuses
        or record.current_status not in signal.current_statuses
        or record.previous_status not in signal.previous_statuses
        or record.reason_type not in signal.reason_types
    ):
        raise MonitoringCollectionError(
            "resource-health record does not match published event filters"
        )
    if (
        record.observed_end > collected_at
        or record.observed_end > trusted_as_of
        or (collected_at - record.observed_start).total_seconds() > signal.maximum_event_age_seconds
        or (collected_at - record.observed_end).total_seconds() > signal.maximum_event_age_seconds
        or (trusted_as_of - record.observed_start).total_seconds()
        > signal.maximum_event_age_seconds
        or (trusted_as_of - record.observed_end).total_seconds() > signal.maximum_event_age_seconds
    ):
        raise MonitoringCollectionError(
            "resource-health record is outside the reviewed freshness limit"
        )
    (resource_id,) = _require_resources(control, record.resource_id)
    state_by_status = {
        "Available": "healthy",
        "Degraded": "degraded",
        "Unavailable": "unavailable",
        "Unknown": "unknown",
    }
    source_root = _source_root(control, intent_digest)
    payload: dict[str, object] = {
        "observationKind": "platformHealth",
        "subjectResourceId": resource_id,
        "observedStart": record.observed_start,
        "observedEnd": record.observed_end,
        "provenanceRootDigest": sha256_hex(source_root),
        "sourceRootReference": source_root,
        "sourceRecordReference": _record_reference(
            "resource-health",
            record.source_record_id,
        ),
        "controlProvenance": _control_provenance(control),
        "summaryCode": f"health.resource-{record.current_status.casefold()}",
        "healthKind": "resourceHealth",
        "status": state_by_status[record.current_status],
        "eventReference": (
            "resource-health-event."
            + hashlib.sha256(record.source_record_id.encode("utf-8")).hexdigest()[:32]
        ),
    }
    return _observation(PlatformHealthObservation, payload)


def _validate_activity_log_control(
    record: ResourceChangeRecord,
    control: PublishedMonitoringIntentControl,
) -> None:
    if not isinstance(control.signal, ActivityLogMonitoringSignal):
        raise MonitoringCollectionError(
            "resource change requires an exact published Activity Log control"
        )
    signal = control.signal
    expected = (
        (record.category, signal.categories),
        (record.operation_name, signal.operation_names),
        (record.result_type, signal.result_types),
        (record.level, signal.levels),
    )
    if any(
        value.casefold() not in {item.casefold() for item in allowed} for value, allowed in expected
    ):
        raise MonitoringCollectionError(
            "resource change does not match published Activity Log filters"
        )


def _resource_graph_change_introduces_deny(
    record: ResourceChangeRecord,
) -> bool:
    properties = record.resource_graph_change.get("properties")
    if not isinstance(properties, dict):
        return False
    changes = properties.get("changes")
    if not isinstance(changes, dict):
        return False
    access_changes = tuple(
        value
        for path, value in changes.items()
        if isinstance(path, str) and path.casefold() == "properties.access"
    )
    if len(access_changes) != 1 or not isinstance(access_changes[0], dict):
        return False
    access_change = access_changes[0]
    previous = access_change.get("previousValue")
    current = access_change.get("newValue")
    return (
        isinstance(previous, str)
        and isinstance(current, str)
        and previous.casefold() == "allow"
        and current.casefold() == "deny"
    )


def _health_state(observation: MonitoringObservation) -> str | None:
    if isinstance(observation, GuestSignalObservation):
        return observation.state
    if isinstance(observation, EndpointHealthObservation):
        return observation.status
    if isinstance(observation, PlatformHealthObservation):
        return observation.status
    return None


def _validate_request_window(
    *,
    incident_revision: int,
    issued_at: datetime,
    trusted_as_of: datetime,
    expires_at: datetime,
) -> None:
    if type(incident_revision) is not int or incident_revision < 1:
        raise MonitoringCollectionError("incident revision must be positive")
    for value in (issued_at, trusted_as_of, expires_at):
        if value.utcoffset() != UTC.utcoffset(value):
            raise MonitoringCollectionError("correlation request times must use UTC")
        if value.microsecond % 1000:
            raise MonitoringCollectionError(
                "correlation request times must use millisecond precision"
            )
    if (
        not issued_at <= trusted_as_of <= expires_at
        or (expires_at - issued_at).total_seconds() > 900
    ):
        raise MonitoringCollectionError("correlation request window is invalid")


class _MonitoringCollectionTransactionCore:
    """Internal normalization core shared with explicit test compatibility code."""

    def __init__(
        self,
        *,
        change_signer: ChangeEvidenceArtifactSigner,
        change_signing_key_id: str,
        monitoring_intent_trusted_key_id: str,
        monitoring_intent_signature_verifier: Callable[[bytes, str], bool],
        monitoring_intent_asset_loader: Callable[
            [PublishedMonitoringIntent],
            tuple[
                PublishedMonitoringIntentAssetReference,
                PublishedMonitoringIntentAttestation,
            ],
        ],
    ) -> None:
        self._change_signer = change_signer
        self._change_signing_key_id = change_signing_key_id
        self._monitoring_intent_trusted_key_id = monitoring_intent_trusted_key_id
        self._monitoring_intent_signature_verifier = monitoring_intent_signature_verifier
        self._monitoring_intent_asset_loader = monitoring_intent_asset_loader

    def prepare(
        self,
        batch: MonitoringCollectionBatch,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        expected_active_context_authority_digest: str,
        collector_contract_digest: str,
        change_scope: ApprovedChangeScope,
        trusted_as_of: datetime,
        acquisition_receipt: MonitoringAcquisitionReceipt | None = None,
    ) -> PreparedMonitoringCollection:
        if type(batch) is not MonitoringCollectionBatch:
            raise TypeError("collection transaction requires an exact batch")
        try:
            batch = MonitoringCollectionBatch.model_validate_json(
                batch.model_dump_json(by_alias=True)
            )
        except ValidationError as exc:
            raise MonitoringCollectionError(
                "collection batch failed strict query execution/schema revalidation"
            ) from exc
        if type(monitoring_intent) is not PublishedMonitoringIntent:
            raise TypeError("collection transaction requires exact published intent")
        monitoring_intent_reference, monitoring_intent_attestation = (
            self._monitoring_intent_asset_loader(monitoring_intent)
        )
        if type(monitoring_intent_reference) is not PublishedMonitoringIntentAssetReference:
            raise TypeError("collection transaction requires exact published intent reference")
        if type(monitoring_intent_attestation) is not PublishedMonitoringIntentAttestation:
            raise TypeError("collection transaction requires exact published intent attestation")
        if type(context_binding) is not PublishedRuntimeContextBinding:
            raise TypeError("collection transaction requires published runtime context")
        if (
            trusted_as_of.utcoffset() != UTC.utcoffset(trusted_as_of)
            or trusted_as_of.microsecond % 1000
            or trusted_as_of < batch.collected_at
            or (trusted_as_of - batch.collected_at).total_seconds()
            > MAX_COLLECTION_TRUST_DELAY_SECONDS
        ):
            raise MonitoringCollectionError(
                "collection trustedAsOf must be bounded millisecond UTC after collectedAt"
            )
        if _DIGEST_PATTERN.fullmatch(collector_contract_digest) is None:
            raise MonitoringCollectionError("collector contract digest is invalid")
        if acquisition_receipt is not None:
            if type(acquisition_receipt) is not MonitoringAcquisitionReceipt:
                raise TypeError("collection requires an exact acquisition receipt")
            try:
                acquisition_receipt = MonitoringAcquisitionReceipt.model_validate_json(
                    acquisition_receipt.model_dump_json(by_alias=True)
                )
            except ValidationError as exc:
                raise MonitoringCollectionError(
                    "collection acquisition receipt failed strict revalidation"
                ) from exc
            if (
                acquisition_receipt.collector_contract_digest != collector_contract_digest
                or acquisition_receipt.execution_started_at != batch.collected_at
                or acquisition_receipt.receipt_issued_at > trusted_as_of
                or acquisition_receipt.intent_id != monitoring_intent.intent_id
                or acquisition_receipt.intent_digest != monitoring_intent.intent_digest
                or acquisition_receipt.context_binding_digest != context_binding.binding_digest
                or acquisition_receipt.collection_batch_digest
                != sha256_hex(batch.canonical_bytes())
            ):
                raise MonitoringCollectionError(
                    "collection acquisition receipt does not bind its trusted execution"
                )
        validate_published_monitoring_intent_assets(
            monitoring_intent_reference,
            monitoring_intent,
            monitoring_intent_attestation,
            trusted_key_id=self._monitoring_intent_trusted_key_id,
            signature_verifier=self._monitoring_intent_signature_verifier,
        )
        validate_monitoring_intent_activation_eligible(
            monitoring_intent,
            context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
        )
        controls = {item.control_id: item for item in monitoring_intent.controls}
        try:
            selected_controls = {
                item.source_record_id: controls[item.control_id] for item in batch.records
            }
            coverage_controls = {
                item.source_record_id: controls[item.control_id] for item in batch.coverage
            }
        except KeyError as exc:
            raise MonitoringCollectionError(
                "collection references an unknown monitoring control"
            ) from exc

        normalized_changes: list[tuple[NormalizedChangeEvidence, bool]] = []
        change_records = [item for item in batch.records if isinstance(item, ResourceChangeRecord)]
        if acquisition_receipt is not None and change_records:
            raise MonitoringCollectionError(
                "receipt-bearing collection cannot persist changes outside required coverage"
            )
        for change_record in change_records:
            _validate_activity_log_control(
                change_record,
                selected_controls[change_record.source_record_id],
            )
            evidence = normalize_resource_graph_change(
                change_record.resource_graph_change,
                scope=change_scope,
                received_at=batch.collected_at,
            )
            if (
                evidence.occurred_at > trusted_as_of
                or evidence.received_at > trusted_as_of
                or trusted_as_of - evidence.occurred_at > MAX_CHANGE_EVIDENCE_AGE
            ):
                raise MonitoringCollectionError(
                    "resource change is outside its trustedAsOf freshness limit"
                )
            control = selected_controls[change_record.source_record_id]
            _require_resources(control, evidence.target_resource_id)
            if (
                evidence.target_resource_id
                != _canonical_resource_id(change_record.target_resource_id)
                or evidence.correlation_id != change_record.correlation_id
                or evidence.occurred_at != change_record.occurred_at
                or evidence.operation_name != change_record.operation_name.casefold()
                or evidence.result != change_record.result_type.casefold()
            ):
                raise MonitoringCollectionError(
                    "Activity Log and Resource Graph change evidence disagree"
                )
            normalized_changes.append(
                (
                    evidence,
                    _resource_graph_change_introduces_deny(change_record),
                )
            )

        artifacts = tuple(
            sorted(
                (
                    build_change_evidence_artifact(
                        evidence,
                        signer=self._change_signer,
                        signing_key_id=self._change_signing_key_id,
                    )
                    for evidence, _ in normalized_changes
                ),
                key=lambda item: sha256_hex(item.canonical_bytes()),
            )
        )
        deny_introducing_evidence_ids = frozenset(
            evidence.evidence_id
            for evidence, introduces_deny in normalized_changes
            if introduces_deny
        )

        observations_by_source: dict[str, MonitoringObservation] = {}
        for collection_record in batch.records:
            if isinstance(collection_record, ResourceChangeRecord):
                continue
            _validate_record_window(
                collection_record,
                batch.collected_at,
                trusted_as_of,
            )
            control = selected_controls[collection_record.source_record_id]
            observation: MonitoringObservation
            if isinstance(collection_record, AmaHeartbeatRecord):
                observation = _heartbeat_observation(
                    collection_record,
                    control,
                    monitoring_intent.intent_digest,
                    batch.collected_at,
                    trusted_as_of,
                )
            elif isinstance(collection_record, VmConnectionHealthRecord):
                observation = _endpoint_observation(
                    collection_record,
                    control,
                    monitoring_intent.intent_digest,
                    context_binding,
                    batch.collected_at,
                    trusted_as_of,
                )
            elif isinstance(collection_record, ConnectionMonitorRecord):
                observation = _connection_monitor_observation(
                    collection_record,
                    control,
                    monitoring_intent.intent_digest,
                    context_binding,
                    batch.collected_at,
                    trusted_as_of,
                )
            elif isinstance(collection_record, NetworkWatcherFlowRecord):
                observation = _network_flow_observation(
                    collection_record,
                    control,
                    monitoring_intent.intent_digest,
                    context_binding,
                    artifacts,
                    deny_introducing_evidence_ids,
                    batch.collected_at,
                    trusted_as_of,
                )
            elif isinstance(collection_record, ResourceHealthRecord):
                observation = _resource_health_observation(
                    collection_record,
                    control,
                    monitoring_intent.intent_digest,
                    batch.collected_at,
                    trusted_as_of,
                )
            else:
                raise MonitoringCollectionError("unsupported monitoring record")
            observations_by_source[collection_record.source_record_id] = observation

        records_by_execution = {
            item.query_execution_digest: item
            for item in batch.records
            if isinstance(item, _LogQueryCollectionRecord)
        }
        if len(records_by_execution) != sum(
            isinstance(item, _LogQueryCollectionRecord) for item in batch.records
        ):
            raise MonitoringCollectionError("query execution digests must be unique")
        for coverage_record in batch.coverage:
            _validate_coverage_query_binding(
                coverage_record,
                coverage_controls[coverage_record.source_record_id],
                records_by_execution,
                collected_at=batch.collected_at,
                trusted_as_of=trusted_as_of,
            )
        if acquisition_receipt is not None:
            receipt_coverage_ids = {
                f"coverage-{item.request_digest.removeprefix('sha256:')[:32]}"
                for item in acquisition_receipt.exchanges
                if item.source in {"logAnalytics", "resourceHealth"}
            }
            coverage_by_id = {item.source_record_id: item for item in batch.coverage}
            unsupported_coverage = tuple(
                item
                for coverage_id, item in coverage_by_id.items()
                if coverage_id not in receipt_coverage_ids
            )
            if not receipt_coverage_ids.issubset(coverage_by_id) or any(
                item.status != "unavailable"
                or item.family not in {"networkFlow", "connectionMonitor"}
                or item.query_execution_digests
                or item.log_permission_evidence is not None
                for item in unsupported_coverage
            ):
                raise MonitoringCollectionError(
                    "acquisition receipt does not exactly bind collection coverage"
                )
        coverage_counts = dict.fromkeys(records_by_execution, 0)
        for coverage_record in batch.coverage:
            for digest in coverage_record.query_execution_digests:
                if digest in coverage_counts:
                    coverage_counts[digest] += 1
        if any(count != 1 for count in coverage_counts.values()):
            raise MonitoringCollectionError(
                "every persisted query observation must have exactly one compatible coverage"
            )
        coverage_pairs = tuple(
            (
                coverage_record,
                _coverage(
                    coverage_record,
                    coverage_controls[coverage_record.source_record_id],
                    monitoring_intent.intent_digest,
                ),
            )
            for coverage_record in batch.coverage
        )
        for coverage_record, item in coverage_pairs:
            _validate_record_window(
                coverage_record,
                batch.collected_at,
                trusted_as_of,
            )
            control = coverage_controls[coverage_record.source_record_id]
            _require_resources(control, *item.scope.resource_ids)
            if item.scope.path_id is not None:
                _require_path(
                    control,
                    item.scope.path_id,
                    context_binding,
                    item.scope.resource_ids,
                )
        coverage = tuple(
            sorted(
                (item for _, item in coverage_pairs),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        )

        observations = tuple(
            sorted(
                observations_by_source.values(),
                key=lambda item: item.observation_id,
            )
        )
        if not observations:
            raise MonitoringCollectionError("collection must produce monitoring observations")
        observed_start = min(
            (
                *(item.observed_start for item in observations),
                *(item.coverage_start for item in coverage),
            )
        )
        observed_end = max(
            (
                *(item.observed_end for item in observations),
                *(item.coverage_end for item in coverage),
            )
        )
        acquisition_manifest = None
        if acquisition_receipt is not None:
            manifest_payload = {
                "schemaVersion": ("athena.wc028MonitoringAcquisitionEvidenceManifest.v1"),
                "collectionBatchDigest": acquisition_receipt.collection_batch_digest,
                "normalizedEvidenceDigest": (acquisition_receipt.normalized_evidence_digest),
                "exchanges": [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for item in acquisition_receipt.exchanges
                ],
            }
            acquisition_manifest = MonitoringAcquisitionEvidenceManifest(
                schemaVersion=("athena.wc028MonitoringAcquisitionEvidenceManifest.v1"),
                collectionBatchDigest=acquisition_receipt.collection_batch_digest,
                normalizedEvidenceDigest=(acquisition_receipt.normalized_evidence_digest),
                exchanges=acquisition_receipt.exchanges,
                manifestDigest=compute_artifact_digest(manifest_payload),
            )
        bundle = MonitoringEvidenceBundle(
            schemaVersion=(
                MONITORING_ACQUISITION_EVIDENCE_BUNDLE_SCHEMA_VERSION
                if acquisition_receipt is not None
                else MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION
            ),
            workloadId=monitoring_intent.workload_id,
            monitoringContractDigest=collector_contract_digest,
            monitoringIntentReference=_monitoring_intent_evidence_reference(
                monitoring_intent_reference
            ),
            collectedAt=batch.collected_at,
            acquisitionReceipt=acquisition_receipt,
            acquisitionManifest=acquisition_manifest,
            observedStart=observed_start,
            observedEnd=observed_end,
            observations=observations,
            coverage=coverage,
            expectedCoverageScopeDigests=tuple(
                sorted({item.scope.scope_digest for item in coverage})
            ),
        )
        if (
            bundle.expected_coverage_scope_digests
            != context_binding.required_coverage_scope_digests
        ):
            raise MonitoringCollectionError(
                "collection coverage does not match published runtime context"
            )

        incident_resource_id = _canonical_resource_id(batch.incident_resource_id)
        try:
            previous = observations_by_source[batch.previous_health_source_record_id]
            current = tuple(
                observations_by_source[item] for item in batch.current_health_source_record_ids
            )
        except KeyError as exc:
            raise MonitoringCollectionError(
                "incident health selection must reference health observations"
            ) from exc
        records_by_source = {item.source_record_id: item for item in batch.records}
        for source_record_id in batch.current_health_source_record_ids:
            source_record = records_by_source[source_record_id]
            if isinstance(source_record, ResourceHealthRecord) and (
                source_record.previous_status != "Available"
                or source_record.event_status == "Resolved"
            ):
                raise MonitoringCollectionError(
                    "Resource Health incident evidence must be active and transition from Available"
                )
        previous_state = _health_state(previous)
        current_states = tuple(_health_state(item) for item in current)
        selected_current_states = set(current_states)
        if (
            previous.subject_resource_id != incident_resource_id
            or any(item.subject_resource_id != incident_resource_id for item in current)
            or previous_state != "healthy"
            or len(selected_current_states) != 1
            or not selected_current_states.issubset({"degraded", "unhealthy", "unavailable"})
            or previous.observed_end > min(item.observed_start for item in current)
        ):
            raise MonitoringCollectionError(
                "incident health selection is not one healthy-to-unhealthy transition"
            )
        current_health_state = cast(
            Literal["degraded", "unhealthy", "unavailable"],
            selected_current_states.pop(),
        )
        incident_start = min(item.observed_start for item in current)
        incident_end = max(item.observed_end for item in current)
        changed = True
        expanded_current = set(current)
        while changed:
            changed = False
            for candidate_observation in observations:
                if (
                    candidate_observation in expanded_current
                    or candidate_observation.subject_resource_id != incident_resource_id
                    or _health_state(candidate_observation) != current_health_state
                    or candidate_observation.observed_start > incident_end
                    or candidate_observation.observed_end < incident_start
                ):
                    continue
                expanded_current.add(candidate_observation)
                incident_start = min(
                    incident_start,
                    candidate_observation.observed_start,
                )
                incident_end = max(
                    incident_end,
                    candidate_observation.observed_end,
                )
                changed = True

        return PreparedMonitoringCollection(
            intent_id=monitoring_intent.intent_id,
            intent_digest=monitoring_intent.intent_digest,
            context_binding_digest=context_binding.binding_digest,
            monitoring_intent_reference=monitoring_intent_reference,
            monitoring_bundle=bundle,
            change_artifacts=artifacts,
            incident_resource_id=incident_resource_id,
            previous_health_source_record_id=(batch.previous_health_source_record_id),
            current_health_source_record_ids=(batch.current_health_source_record_ids),
            previous_health_observation_id=previous.observation_id,
            current_health_observation_ids=tuple(
                sorted(item.observation_id for item in expanded_current)
            ),
            current_health_state=current_health_state,
        )

    def execute(
        self,
        batch: MonitoringCollectionBatch,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        expected_active_context_authority_digest: str,
        collector_contract_digest: str,
        change_scope: ApprovedChangeScope,
        commit_port: MonitoringCollectionCommitPort,
        incident_revision: int,
        issued_at: datetime,
        trusted_as_of: datetime,
        expires_at: datetime,
        acquisition_receipt: MonitoringAcquisitionReceipt | None = None,
    ) -> tuple[
        PreparedMonitoringCollection,
        CommittedMonitoringCollection,
        CorrelationRequest,
    ]:
        """Persist only after normalization, then expose one verified-shape request."""

        _validate_request_window(
            incident_revision=incident_revision,
            issued_at=issued_at,
            trusted_as_of=trusted_as_of,
            expires_at=expires_at,
        )
        prepared = self.prepare(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
            collector_contract_digest=collector_contract_digest,
            change_scope=change_scope,
            trusted_as_of=trusted_as_of,
            acquisition_receipt=acquisition_receipt,
        )
        with commit_port.transaction(prepared) as committed:
            request = build_collected_correlation_request(
                prepared,
                committed,
                context_binding=context_binding,
                incident_revision=incident_revision,
                issued_at=issued_at,
                trusted_as_of=trusted_as_of,
                expires_at=expires_at,
            )
        return prepared, committed, request


class MonitoringCollectionTransaction(_MonitoringCollectionTransactionCore):
    """Production transaction that requires a trusted acquisition receipt."""

    def __init__(
        self,
        *,
        acquisition_receipt_verifier: Callable[[MonitoringAcquisitionReceipt, datetime], None],
        change_signer: ChangeEvidenceArtifactSigner,
        change_signing_key_id: str,
        monitoring_intent_trusted_key_id: str,
        monitoring_intent_signature_verifier: Callable[[bytes, str], bool],
        monitoring_intent_asset_loader: Callable[
            [PublishedMonitoringIntent],
            tuple[
                PublishedMonitoringIntentAssetReference,
                PublishedMonitoringIntentAttestation,
            ],
        ],
    ) -> None:
        super().__init__(
            change_signer=change_signer,
            change_signing_key_id=change_signing_key_id,
            monitoring_intent_trusted_key_id=monitoring_intent_trusted_key_id,
            monitoring_intent_signature_verifier=monitoring_intent_signature_verifier,
            monitoring_intent_asset_loader=monitoring_intent_asset_loader,
        )
        self._acquisition_receipt_verifier = acquisition_receipt_verifier

    def _prepare_receipt_candidate(
        self,
        batch: MonitoringCollectionBatch,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        expected_active_context_authority_digest: str,
        collector_contract_digest: str,
        change_scope: ApprovedChangeScope,
        trusted_as_of: datetime,
    ) -> PreparedMonitoringCollection:
        """Normalize a candidate only so its digest can be bound into the receipt."""

        return super().prepare(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
            collector_contract_digest=collector_contract_digest,
            change_scope=change_scope,
            trusted_as_of=trusted_as_of,
        )

    def prepare(
        self,
        batch: MonitoringCollectionBatch,
        *,
        monitoring_intent: PublishedMonitoringIntent,
        context_binding: PublishedRuntimeContextBinding,
        expected_active_context_authority_digest: str,
        collector_contract_digest: str,
        change_scope: ApprovedChangeScope,
        trusted_as_of: datetime,
        acquisition_receipt: MonitoringAcquisitionReceipt | None = None,
    ) -> PreparedMonitoringCollection:
        if acquisition_receipt is None:
            raise MonitoringCollectionError(
                "production collection requires a signed acquisition receipt"
            )
        if type(acquisition_receipt) is not MonitoringAcquisitionReceipt:
            raise TypeError("collection requires an exact acquisition receipt")
        try:
            self._acquisition_receipt_verifier(acquisition_receipt, trusted_as_of)
        except (TypeError, ValueError) as exc:
            raise MonitoringCollectionError(
                "collection acquisition receipt cryptographic verification failed"
            ) from exc
        return super().prepare(
            batch,
            monitoring_intent=monitoring_intent,
            context_binding=context_binding,
            expected_active_context_authority_digest=(expected_active_context_authority_digest),
            collector_contract_digest=collector_contract_digest,
            change_scope=change_scope,
            trusted_as_of=trusted_as_of,
            acquisition_receipt=acquisition_receipt,
        )


def _observation_family(observation: MonitoringObservation) -> EvidenceFamily:
    if isinstance(observation, GuestSignalObservation):
        return "guest"
    if isinstance(observation, NetworkFlowObservation):
        return "networkFlow"
    if isinstance(observation, ConnectionMonitorObservation):
        return "connectionMonitor"
    if isinstance(observation, EndpointHealthObservation):
        return "endpointHealth"
    return "platformHealth"


def _observation_resource_ids(
    observation: MonitoringObservation,
) -> tuple[str, ...]:
    resources = {observation.subject_resource_id}
    if isinstance(observation, NetworkFlowObservation):
        resources.update(
            {
                observation.source_resource_id,
                observation.destination_resource_id,
                observation.enforcement_resource_id,
            }
        )
        if observation.rule_resource_id is not None:
            resources.add(observation.rule_resource_id)
    elif isinstance(observation, ConnectionMonitorObservation):
        resources.update(
            {
                observation.monitor_resource_id,
                observation.source_resource_id,
                observation.destination_resource_id,
            }
        )
    elif isinstance(observation, EndpointHealthObservation):
        resources.update(observation.backend_resource_ids)
    return tuple(sorted(resources))


def _build_evidence_index(
    prepared: PreparedMonitoringCollection,
    committed: CommittedMonitoringCollection,
) -> tuple[CorrelationEvidenceCitation, ...]:
    monitoring_reference = committed.monitoring_handoff.evidence
    monitoring_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=observation.observation_id,
            family=_observation_family(observation),
            provenanceRootDigest=observation.provenance_root_digest,
            evidenceDigest=observation.observation_digest,
            sourceReference=monitoring_reference,
            observedStart=observation.observed_start,
            observedEnd=observation.observed_end,
            sourceRootReference=observation.source_root_reference,
            resourceIds=_observation_resource_ids(observation),
            summaryCode=observation.summary_code,
        )
        for observation in prepared.monitoring_bundle.observations
    )
    coverage_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=item.coverage_id,
            family=item.family,
            provenanceRootDigest=item.provenance_root_digest,
            evidenceDigest=item.coverage_digest,
            sourceReference=monitoring_reference,
            observedStart=item.coverage_start,
            observedEnd=item.coverage_end,
            sourceRootReference=item.source_root_reference,
            resourceIds=item.scope.resource_ids,
            summaryCode=f"coverage.{item.family}.{item.status}",
        )
        for item in prepared.monitoring_bundle.coverage
    )
    handoffs = {item.evidence_id: item for item in committed.change_handoffs}
    change_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=artifact.evidence.evidence_id,
            family="resourceChange",
            provenanceRootDigest=sha256_hex(artifact.evidence.source_record_reference),
            evidenceDigest=sha256_hex(artifact.canonical_bytes()),
            sourceReference=handoffs[artifact.evidence.evidence_id].artifact,
            observedStart=artifact.evidence.occurred_at,
            observedEnd=artifact.evidence.occurred_at,
            sourceRootReference=artifact.evidence.source_record_reference,
            resourceIds=(artifact.evidence.target_resource_id,),
            summaryCode=(f"change.{artifact.evidence.operation}.{artifact.evidence.result}"),
        )
        for artifact in prepared.change_artifacts
    )
    return tuple(
        sorted(
            (*monitoring_citations, *coverage_citations, *change_citations),
            key=lambda item: item.evidence_id,
        )
    )


def _build_transition(
    prepared: PreparedMonitoringCollection,
    evidence_index: tuple[CorrelationEvidenceCitation, ...],
) -> tuple[IncidentHealthTransition, MonitoringSelectedIncident]:
    selected = build_selected_incident(
        incident_resource_id=prepared.incident_resource_id,
        previous_record_id=prepared.previous_health_source_record_id,
        current_record_ids=prepared.current_health_source_record_ids,
        current_state=prepared.current_health_state,
    )
    selected_incident = MonitoringSelectedIncident.model_validate(
        {
            "incidentResourceId": selected.incident_resource_id,
            "previousRecordId": selected.previous_record_id,
            "currentRecordIds": selected.current_record_ids,
            "currentState": selected.current_state,
            "transitionDigest": selected.transition_digest,
        }
    )
    citations = {item.evidence_id: item for item in evidence_index}
    previous = citations[prepared.previous_health_observation_id]
    current = tuple(citations[item] for item in prepared.current_health_observation_ids)
    payload: dict[str, object] = {
        "affectedResourceId": prepared.incident_resource_id,
        "previousState": "healthy",
        "currentState": prepared.current_health_state,
        "observedStart": min(item.observed_start for item in current),
        "observedEnd": max(item.observed_end for item in current),
        "previousStateEvidence": (previous,),
        "currentStateEvidence": tuple(sorted(current, key=lambda item: item.evidence_id)),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return (
        IncidentHealthTransition.model_validate(
            {
                **payload,
                "transitionId": f"transition-{digest.removeprefix('sha256:')[:32]}",
                "transitionDigest": digest,
            }
        ),
        selected_incident,
    )


def build_collected_correlation_request(
    prepared: PreparedMonitoringCollection,
    committed: CommittedMonitoringCollection,
    *,
    context_binding: PublishedRuntimeContextBinding,
    incident_revision: int,
    issued_at: datetime,
    trusted_as_of: datetime,
    expires_at: datetime,
) -> CorrelationRequest:
    """Bind an atomically committed collection to the existing correlation contract."""

    if type(context_binding) is not PublishedRuntimeContextBinding:
        raise TypeError("correlation request requires published runtime context")
    if prepared.context_binding_digest != context_binding.binding_digest:
        raise MonitoringCollectionError(
            "prepared collection does not match the supplied runtime context"
        )
    if committed.monitoring_handoff.evidence.content_digest != sha256_hex(
        prepared.monitoring_bundle.canonical_bytes()
    ):
        raise MonitoringCollectionError("monitoring handoff does not reference the prepared bundle")
    acquisition_receipt = prepared.monitoring_bundle.acquisition_receipt
    if (
        acquisition_receipt is not None
        and committed.monitoring_handoff.acquisition_receipt_digest
        != acquisition_receipt.receipt_digest
    ):
        raise MonitoringCollectionError(
            "monitoring handoff does not reference the acquisition receipt"
        )
    artifact_ids = tuple(item.evidence.evidence_id for item in prepared.change_artifacts)
    handoff_ids = tuple(item.evidence_id for item in committed.change_handoffs)
    if set(artifact_ids) != set(handoff_ids) or len(handoff_ids) != len(set(handoff_ids)):
        raise MonitoringCollectionError("change handoffs do not exactly cover prepared artifacts")
    ordered_handoffs = tuple(
        {item.evidence_id: item for item in committed.change_handoffs}[evidence_id]
        for evidence_id in artifact_ids
    )
    committed = CommittedMonitoringCollection(
        monitoring_handoff=committed.monitoring_handoff,
        change_handoffs=ordered_handoffs,
    )
    evidence_index = _build_evidence_index(prepared, committed)
    transition, selected_incident = _build_transition(prepared, evidence_index)
    request_schema_version = (
        CORRELATION_REQUEST_SCHEMA_VERSION
        if acquisition_receipt is not None
        and acquisition_receipt.schema_version == MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
        else PREVIOUS_CORRELATION_REQUEST_SCHEMA_VERSION
    )
    change_digests = tuple(
        sorted(sha256_hex(item.canonical_bytes()) for item in prepared.change_artifacts)
    )
    control_provenance = {
        (
            item.control_provenance.control_id,
            item.control_provenance.control_digest,
            item.control_provenance.source_clause_path,
        )
        for item in (
            *prepared.monitoring_bundle.observations,
            *prepared.monitoring_bundle.coverage,
        )
        if item.control_provenance is not None
    }
    control_provenance_digest = compute_artifact_digest(
        [
            {
                "controlId": control_id,
                "controlDigest": control_digest,
                "sourceClausePath": source_clause_path,
            }
            for control_id, control_digest, source_clause_path in sorted(control_provenance)
        ]
    )
    source_references: tuple[VersionPinnedBlobReference, ...] = tuple(
        sorted(
            (
                committed.monitoring_handoff.evidence,
                context_binding.publication_authority_reference,
                prepared.monitoring_intent_reference.intent_reference,
                prepared.monitoring_intent_reference.attestation_reference,
                *(item.artifact for item in committed.change_handoffs),
            ),
            key=lambda item: (item.name, item.version, item.content_digest),
        )
    )
    inventory_payload: dict[str, object] = {
        "ruleCatalogDigest": CORRELATION_RULE_CATALOG_DIGEST,
        "contextBindingDigest": context_binding.binding_digest,
        "incidentTransitionDigest": (
            selected_incident.transition_digest
            if request_schema_version == CORRELATION_REQUEST_SCHEMA_VERSION
            else transition.transition_digest
        ),
        "monitoringHandoffDigest": (committed.monitoring_handoff.compute_artifact_digest_value()),
        "monitoringBundleDigest": sha256_hex(prepared.monitoring_bundle.canonical_bytes()),
        "changeArtifactDigests": change_digests,
        "evidenceIndexDigest": compute_artifact_digest(
            [
                item.model_dump(mode="json", by_alias=True, exclude_none=True)
                for item in evidence_index
            ]
        ),
        "monitoringIntentAssetReferenceDigest": (
            prepared.monitoring_intent_reference.reference_digest
        ),
        "monitoringControlProvenanceDigest": control_provenance_digest,
        "sourceReferences": source_references,
    }
    inventory_digest = compute_artifact_digest(_json_value(inventory_payload))
    inventory = CorrelationEvidenceInventory.model_validate(
        {
            **inventory_payload,
            "inventoryDigest": inventory_digest,
        }
    )
    request_payload: dict[str, object] = {
        "schemaVersion": request_schema_version,
        "algorithmId": CORRELATION_ALGORITHM_ID,
        "ruleCatalogDigest": CORRELATION_RULE_CATALOG_DIGEST,
        "incidentRevision": incident_revision,
        "issuedAt": issued_at,
        "trustedAsOf": trusted_as_of,
        "expiresAt": expires_at,
        "contextBinding": context_binding,
        "selectedIncident": (
            selected_incident
            if request_schema_version == CORRELATION_REQUEST_SCHEMA_VERSION
            else None
        ),
        "incidentAnchor": transition,
        "monitoringHandoff": committed.monitoring_handoff,
        "monitoringBundle": prepared.monitoring_bundle,
        "changeArtifacts": prepared.change_artifacts,
        "changeHandoffs": committed.change_handoffs,
        "evidenceIndex": evidence_index,
        "evidenceInventory": inventory,
    }
    request_digest = compute_artifact_digest(_json_value(request_payload))
    return CorrelationRequest.model_validate(
        {
            **request_payload,
            "requestId": f"request-{request_digest.removeprefix('sha256:')[:32]}",
            "requestDigest": request_digest,
        }
    )


__all__ = [
    "MONITORING_COLLECTION_BATCH_SCHEMA_VERSION",
    "AmaHeartbeatRecord",
    "CommittedMonitoringCollection",
    "ConnectionMonitorRecord",
    "MAX_COLLECTION_TRUST_DELAY_SECONDS",
    "MAX_MONITORING_COLLECTION_BYTES",
    "MonitoringCollectionBatch",
    "MonitoringCollectionCommitPort",
    "MonitoringCollectionError",
    "MonitoringCollectionTransaction",
    "MonitoringCoverageRecord",
    "NetworkWatcherFlowRecord",
    "PreparedMonitoringCollection",
    "ResourceChangeRecord",
    "ResourceHealthRecord",
    "VmConnectionHealthRecord",
    "build_collected_correlation_request",
    "compute_monitoring_query_execution_digest",
]
