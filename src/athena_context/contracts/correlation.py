from __future__ import annotations

import math
import re
from datetime import timedelta
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.change_ingestion import (
    ChangeEvidenceArtifact,
    ChangeEvidencePersistenceHandoff,
)
from athena_context.contracts.common import compute_artifact_digest, sha256_hex
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.contracts.monitoring import MonitoringEvidenceHandoff
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION = (
    "athena.wc026MonitoringEvidenceBundle.v1"
)
CORRELATION_REQUEST_SCHEMA_VERSION = "athena.wc026CorrelationRequest.v1"
CORRELATION_REPORT_SCHEMA_VERSION = "athena.wc026CorrelationReport.v1"
CORRELATION_ALGORITHM_ID = "athena.wc026.correlation.v1"

type BindingMode = Literal["publishedRuntime", "draftPreview"]
type ConfidenceLevel = Literal["Confirmed", "High", "Medium", "Low", "Unknown"]
type EvidenceFamily = Literal[
    "guest",
    "networkFlow",
    "connectionMonitor",
    "endpointHealth",
    "platformHealth",
    "resourceChange",
    "declaredContext",
]
type HealthState = Literal[
    "healthy",
    "degraded",
    "unhealthy",
    "unavailable",
    "recovered",
    "unknown",
]
type RootCauseCategory = Literal[
    "networkSecurityChange",
    "routingChange",
    "guestResourcePressure",
    "guestServiceFailure",
    "platformHealth",
    "backendHealth",
    "deploymentChange",
    "dependencyFailure",
    "unknown",
]
type CorrelationGateCode = Literal[
    "successfulChange",
    "affectedPath",
    "semanticMatch",
    "effectiveRuleAttribution",
    "matchingDeniedFlow",
    "connectionMonitorFailure",
    "endpointDegradation",
    "independentCorroboration",
    "correctChronology",
    "recoveryEvidence",
    "noHardConflict",
]
type ConfidenceCapCode = Literal[
    "recentChangeOnly",
    "missingAffectedPath",
    "missingIndependentSupport",
    "missingDirectAttribution",
    "ambiguousObservationWindow",
]
type ContradictionCode = Literal[
    "changeFailed",
    "changeAfterDegradation",
    "completeAllowedFlow",
    "completeHealthyConnectionMonitor",
    "recoveryBeforeCorrection",
    "competingCause",
]
type MissingEvidenceCode = Literal[
    "effectiveRuleAttribution",
    "deniedFlow",
    "connectionMonitorResult",
    "endpointHealth",
    "affectedPath",
    "completeObservationWindow",
    "recoveryObservation",
    "changeDetails",
]
type GuestSignal = Literal[
    "heartbeatLoss",
    "diskCapacityPressure",
    "inodePressure",
    "diskLatency",
    "memoryPressure",
    "cpuSaturation",
    "nicErrors",
    "serviceFailure",
]
type FlowDecision = Literal["allowed", "denied", "unknown"]
type FlowDirection = Literal["inbound", "outbound"]
type NetworkProtocol = Literal["Tcp", "Udp", "Icmp", "Any"]
type NetworkAttributionMethod = Literal["ipFlowVerify", "effectiveRuleEvaluation"]
type NetworkRuleCausalEffect = Literal["introducedDenyForTuple"]
type ConnectionMonitorStatus = Literal["succeeded", "failed", "degraded", "unknown"]
type PlatformHealthKind = Literal[
    "resourceHealth",
    "serviceHealth",
    "loadBalancerBackend",
]
type CoverageStatus = Literal["complete", "partial", "unavailable", "truncated"]
type MonitoringEvidenceFamily = Literal[
    "guest",
    "networkFlow",
    "connectionMonitor",
    "endpointHealth",
    "platformHealth",
]
type PathClass = Literal["declared", "observed", "inferred", "exception"]

_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}/resourcegroups/"
    r"[a-z0-9_().-]{1,90}/providers/[a-z0-9.]+"
    r"(?:/[a-z0-9.()_-]+/[a-z0-9.()_-]+)+$"
)
_ID_PATTERNS = {
    "observation": re.compile(r"^obs-[a-f0-9]{32}$"),
    "transition": re.compile(r"^transition-[a-f0-9]{32}$"),
    "hypothesis": re.compile(r"^hyp-[a-f0-9]{32}$"),
    "report": re.compile(r"^report-[a-f0-9]{32}$"),
    "request": re.compile(r"^request-[a-f0-9]{32}$"),
}
_SOURCE_RECORD_REF_PATTERN = r"^[a-z][a-z0-9-]{0,31}:sha256:[a-f0-9]{64}$"
_CONFIDENCE_RANK: dict[ConfidenceLevel, int] = {
    "Unknown": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Confirmed": 4,
}
_NETWORK_SECURITY_CONFIRMED_GATES: frozenset[CorrelationGateCode] = frozenset(
    {
        "successfulChange",
        "affectedPath",
        "semanticMatch",
        "effectiveRuleAttribution",
        "matchingDeniedFlow",
        "connectionMonitorFailure",
        "endpointDegradation",
        "independentCorroboration",
        "correctChronology",
        "noHardConflict",
    }
)
_NSG_CAUSAL_PROPERTY_PREFIXES = (
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
_HARD_CONTRADICTION_CODES: frozenset[ContradictionCode] = frozenset(
    {
        "changeFailed",
        "changeAfterDegradation",
        "completeAllowedFlow",
        "completeHealthyConnectionMonitor",
        "recoveryBeforeCorrection",
    }
)


def _canonical_resource_id(value: str) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or len(value) > 2048
        or "\\" in value
        or "%" in value
    ):
        raise ValueError("resource ID must be one bounded canonical Azure resource ID")
    normalized = value.lower().rstrip("/")
    if _RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
        raise ValueError("resource ID must be one bounded canonical Azure resource ID")
    return normalized


def _require_interval(start: UtcDateTime, end: UtcDateTime) -> None:
    if start > end:
        raise ValueError("observation start must not be after observation end")


def _intervals_overlap(
    first_start: UtcDateTime,
    first_end: UtcDateTime,
    second_start: UtcDateTime,
    second_end: UtcDateTime,
) -> bool:
    return first_start < second_end and first_end > second_start


def _require_sorted_unique(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{field_name} must be unique deterministic ordinal values")
    return values


def _is_nsg_causal_property(path: str) -> bool:
    normalized = path.casefold()
    return any(
        normalized == allowed
        or re.fullmatch(rf"{re.escape(allowed)}\[[0-9]+\]", normalized) is not None
        for allowed in _NSG_CAUSAL_PROPERTY_PREFIXES
    )


def _expected_digest(
    model: AthenaBaseModel,
    *,
    excluded_fields: set[str],
) -> str:
    payload = model.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude=excluded_fields,
    )
    return compute_artifact_digest(payload)


def _require_bound_identifier(
    *,
    identifier: str,
    identifier_kind: str,
    digest: str,
) -> None:
    pattern = _ID_PATTERNS[identifier_kind]
    if pattern.fullmatch(identifier) is None:
        raise ValueError(f"{identifier_kind} identifier is invalid")
    expected = f"{pattern.pattern.split('-')[0][1:]}-{digest.removeprefix('sha256:')[:32]}"
    if identifier != expected:
        raise ValueError(f"{identifier_kind} identifier is not digest-bound")


class _StrictCorrelationModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


class CorrelationEvidenceCitation(_StrictCorrelationModel):
    evidence_id: str = Field(
        alias="evidenceId",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    family: EvidenceFamily
    provenance_root_digest: Sha256Digest = Field(alias="provenanceRootDigest")
    evidence_digest: Sha256Digest = Field(alias="evidenceDigest")
    source_reference: VersionPinnedBlobReference = Field(alias="sourceReference")
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    source_root_reference: str = Field(
        alias="sourceRootReference",
        pattern=_SOURCE_RECORD_REF_PATTERN,
    )
    resource_ids: tuple[str, ...] = Field(
        alias="resourceIds",
        min_length=1,
        max_length=128,
    )
    summary_code: str = Field(
        alias="summaryCode",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][A-Za-z0-9.-]{0,127}$",
    )

    @field_validator("resource_ids")
    @classmethod
    def normalize_resource_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_resource_id(value) for value in values)
        return _require_sorted_unique(normalized, "resourceIds")

    @model_validator(mode="after")
    def validate_interval(self) -> CorrelationEvidenceCitation:
        _require_interval(self.observed_start, self.observed_end)
        if self.provenance_root_digest != sha256_hex(self.source_root_reference):
            raise ValueError(
                "citation provenance root must derive from sourceRootReference"
            )
        return self


class _MonitoringObservation(_StrictCorrelationModel):
    observation_id: str = Field(alias="observationId")
    subject_resource_id: str = Field(
        alias="subjectResourceId",
        min_length=1,
        max_length=2048,
    )
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    provenance_root_digest: Sha256Digest = Field(alias="provenanceRootDigest")
    source_root_reference: str = Field(
        alias="sourceRootReference",
        pattern=_SOURCE_RECORD_REF_PATTERN,
    )
    source_record_reference: str = Field(
        alias="sourceRecordReference",
        pattern=_SOURCE_RECORD_REF_PATTERN,
    )
    summary_code: str = Field(
        alias="summaryCode",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][A-Za-z0-9.-]{0,127}$",
    )
    observation_digest: Sha256Digest = Field(alias="observationDigest")

    @field_validator("subject_resource_id")
    @classmethod
    def normalize_subject_resource_id(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @model_validator(mode="after")
    def validate_common_observation(self) -> _MonitoringObservation:
        _require_interval(self.observed_start, self.observed_end)
        if self.provenance_root_digest != sha256_hex(self.source_root_reference):
            raise ValueError(
                "provenanceRootDigest must derive from sourceRootReference"
            )
        expected = _expected_digest(
            self,
            excluded_fields={"observation_id", "observation_digest"},
        )
        if self.observation_digest != expected:
            raise ValueError("observationDigest does not bind the observation")
        _require_bound_identifier(
            identifier=self.observation_id,
            identifier_kind="observation",
            digest=expected,
        )
        return self


class GuestSignalObservation(_MonitoringObservation):
    observation_kind: Literal["guestSignal"] = Field(alias="observationKind")
    signal: GuestSignal
    state: HealthState
    value: float | None = None
    unit: str | None = Field(default=None, min_length=1, max_length=64)
    threshold_digest: Sha256Digest | None = Field(
        default=None,
        alias="thresholdDigest",
    )
    service_reference: str | None = Field(
        default=None,
        alias="serviceReference",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )

    @field_validator("value")
    @classmethod
    def validate_finite_value(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("guest signal value must be finite")
        return value


class NetworkFlowObservation(_MonitoringObservation):
    observation_kind: Literal["networkFlow"] = Field(alias="observationKind")
    path_id: str = Field(
        alias="pathId",
        pattern=r"^path-[a-f0-9]{32}$",
    )
    decision: FlowDecision
    direction: FlowDirection
    protocol: NetworkProtocol
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
    five_tuple_digest: Sha256Digest = Field(alias="fiveTupleDigest")
    effective_rule_attribution: bool = Field(alias="effectiveRuleAttribution")
    attribution_method: NetworkAttributionMethod | None = Field(
        default=None,
        alias="attributionMethod",
    )
    causal_effect: NetworkRuleCausalEffect | None = Field(
        default=None,
        alias="causalEffect",
    )
    attribution_proof_digest: Sha256Digest | None = Field(
        default=None,
        alias="attributionProofDigest",
    )
    matched_change_key: Sha256Digest | None = Field(
        default=None,
        alias="matchedChangeKey",
    )
    matched_change_evidence_id: str | None = Field(
        default=None,
        alias="matchedChangeEvidenceId",
        pattern=r"^chg-[a-f0-9]{12}$",
    )
    matched_change_artifact_digest: Sha256Digest | None = Field(
        default=None,
        alias="matchedChangeArtifactDigest",
    )
    matched_property_paths: tuple[str, ...] = Field(
        default=(),
        alias="matchedPropertyPaths",
        max_length=32,
    )

    @field_validator(
        "rule_resource_id",
    )
    @classmethod
    def normalize_optional_resource_id(cls, value: str | None) -> str | None:
        return None if value is None else _canonical_resource_id(value)

    @field_validator("enforcement_resource_id")
    @classmethod
    def normalize_enforcement_resource_id(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @field_validator("source_resource_id", "destination_resource_id")
    @classmethod
    def normalize_required_resource_id(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @field_validator("source_address", "destination_address")
    @classmethod
    def normalize_ip_address(cls, value: str) -> str:
        try:
            return ip_address(value).compressed
        except ValueError as exc:
            raise ValueError("network address must be one canonical IP address") from exc

    @model_validator(mode="after")
    def validate_attribution(self) -> NetworkFlowObservation:
        if self.protocol in {"Tcp", "Udp"} and (
            self.source_port is None or self.destination_port is None
        ):
            raise ValueError("TCP and UDP observations require both ports")
        tuple_payload = {
            "direction": self.direction,
            "protocol": self.protocol,
            "sourceResourceId": self.source_resource_id,
            "destinationResourceId": self.destination_resource_id,
            "sourceAddress": self.source_address,
            "destinationAddress": self.destination_address,
            "sourcePort": self.source_port,
            "destinationPort": self.destination_port,
        }
        if self.five_tuple_digest != compute_artifact_digest(tuple_payload):
            raise ValueError("fiveTupleDigest does not bind the exact flow tuple")
        if self.effective_rule_attribution and (
            self.rule_resource_id is None
            or self.attribution_method is None
            or self.causal_effect != "introducedDenyForTuple"
            or self.attribution_proof_digest is None
            or self.matched_change_key is None
            or self.matched_change_evidence_id is None
            or self.matched_change_artifact_digest is None
            or not self.matched_property_paths
        ):
            raise ValueError(
                "effective rule attribution requires direct proof and change binding"
            )
        if not self.effective_rule_attribution and any(
            value is not None
            for value in (
                self.attribution_method,
                self.causal_effect,
                self.attribution_proof_digest,
                self.matched_change_key,
                self.matched_change_evidence_id,
                self.matched_change_artifact_digest,
            )
        ):
            raise ValueError(
                "non-attributed flow must not carry causal attribution fields"
            )
        if not self.effective_rule_attribution and self.matched_property_paths:
            raise ValueError(
                "non-attributed flow must not carry matched property paths"
            )
        if self.matched_property_paths != tuple(sorted(self.matched_property_paths)) or len(
            self.matched_property_paths
        ) != len(set(self.matched_property_paths)):
            raise ValueError(
                "matchedPropertyPaths must be unique deterministic paths"
            )
        if any(not _is_nsg_causal_property(path) for path in self.matched_property_paths):
            raise ValueError("matchedPropertyPaths must use causal NSG rule fields")
        return self


class ConnectionMonitorObservation(_MonitoringObservation):
    observation_kind: Literal["connectionMonitor"] = Field(alias="observationKind")
    path_id: str = Field(
        alias="pathId",
        pattern=r"^path-[a-f0-9]{32}$",
    )
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
    direction: FlowDirection
    protocol: NetworkProtocol
    source_port: int | None = Field(default=None, alias="sourcePort", ge=0, le=65535)
    destination_port: int | None = Field(
        default=None,
        alias="destinationPort",
        ge=0,
        le=65535,
    )
    five_tuple_digest: Sha256Digest = Field(alias="fiveTupleDigest")
    status: ConnectionMonitorStatus
    test_configuration_reference: str = Field(
        alias="testConfigurationReference",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    test_configuration_digest: Sha256Digest = Field(
        alias="testConfigurationDigest"
    )

    @field_validator(
        "monitor_resource_id",
        "source_resource_id",
        "destination_resource_id",
    )
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @field_validator("source_address", "destination_address")
    @classmethod
    def normalize_ip_address(cls, value: str) -> str:
        try:
            return ip_address(value).compressed
        except ValueError as exc:
            raise ValueError("network address must be one canonical IP address") from exc

    @model_validator(mode="after")
    def validate_test_tuple(self) -> ConnectionMonitorObservation:
        if self.protocol in {"Tcp", "Udp"} and (
            self.source_port is None or self.destination_port is None
        ):
            raise ValueError("TCP and UDP tests require both ports")
        tuple_payload = {
            "direction": self.direction,
            "protocol": self.protocol,
            "sourceResourceId": self.source_resource_id,
            "destinationResourceId": self.destination_resource_id,
            "sourceAddress": self.source_address,
            "destinationAddress": self.destination_address,
            "sourcePort": self.source_port,
            "destinationPort": self.destination_port,
        }
        if self.five_tuple_digest != compute_artifact_digest(tuple_payload):
            raise ValueError("fiveTupleDigest does not bind the exact monitor tuple")
        return self


class EndpointHealthObservation(_MonitoringObservation):
    observation_kind: Literal["endpointHealth"] = Field(alias="observationKind")
    path_id: str = Field(
        alias="pathId",
        pattern=r"^path-[a-f0-9]{32}$",
    )
    status: HealthState
    backend_resource_ids: tuple[str, ...] = Field(
        alias="backendResourceIds",
        max_length=128,
    )

    @field_validator("backend_resource_ids")
    @classmethod
    def normalize_backend_resource_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_resource_id(value) for value in values)
        return _require_sorted_unique(normalized, "backendResourceIds")


class PlatformHealthObservation(_MonitoringObservation):
    observation_kind: Literal["platformHealth"] = Field(alias="observationKind")
    health_kind: PlatformHealthKind = Field(alias="healthKind")
    status: HealthState
    event_reference: str = Field(
        alias="eventReference",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )


type MonitoringObservation = Annotated[
    GuestSignalObservation
    | NetworkFlowObservation
    | ConnectionMonitorObservation
    | EndpointHealthObservation
    | PlatformHealthObservation,
    Field(discriminator="observation_kind"),
]


class EvidenceCoverageScope(_StrictCorrelationModel):
    scope_id: str = Field(
        alias="scopeId",
        pattern=r"^coverage-scope-[a-f0-9]{32}$",
    )
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
    direction: FlowDirection | None = None
    five_tuple_digest: Sha256Digest | None = Field(
        default=None,
        alias="fiveTupleDigest",
    )
    endpoint_test_reference: str | None = Field(
        default=None,
        alias="endpointTestReference",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]{0,127}$",
    )
    endpoint_test_digest: Sha256Digest | None = Field(
        default=None,
        alias="endpointTestDigest",
    )
    query_scope_digest: Sha256Digest = Field(alias="queryScopeDigest")
    scope_digest: Sha256Digest = Field(alias="scopeDigest")

    @field_validator("resource_ids")
    @classmethod
    def normalize_resource_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_resource_id(value) for value in values)
        return _require_sorted_unique(normalized, "resourceIds")

    @model_validator(mode="after")
    def validate_scope(self) -> EvidenceCoverageScope:
        expected = _expected_digest(
            self,
            excluded_fields={"scope_id", "scope_digest"},
        )
        if self.scope_digest != expected:
            raise ValueError("scopeDigest does not bind the coverage scope")
        if self.scope_id != f"coverage-scope-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("scopeId is not digest-bound")
        return self


class EvidenceCoverage(_StrictCorrelationModel):
    coverage_id: str = Field(
        alias="coverageId",
        pattern=r"^coverage-[a-f0-9]{32}$",
    )
    family: MonitoringEvidenceFamily
    scope: EvidenceCoverageScope
    provenance_root_digest: Sha256Digest = Field(alias="provenanceRootDigest")
    source_root_reference: str = Field(
        alias="sourceRootReference",
        pattern=_SOURCE_RECORD_REF_PATTERN,
    )
    source_record_reference: str = Field(
        alias="sourceRecordReference",
        pattern=_SOURCE_RECORD_REF_PATTERN,
    )
    coverage_start: UtcDateTime = Field(alias="coverageStart")
    coverage_end: UtcDateTime = Field(alias="coverageEnd")
    status: CoverageStatus
    detail: str | None = Field(default=None, min_length=1, max_length=500)
    coverage_digest: Sha256Digest = Field(alias="coverageDigest")

    @model_validator(mode="after")
    def validate_coverage(self) -> EvidenceCoverage:
        _require_interval(self.coverage_start, self.coverage_end)
        if self.provenance_root_digest != sha256_hex(self.source_root_reference):
            raise ValueError(
                "provenanceRootDigest must derive from sourceRootReference"
            )
        if self.status != "complete" and self.detail is None:
            raise ValueError("incomplete coverage requires detail")
        if self.family == "networkFlow" and self.status == "complete" and (
            self.scope.path_id is None
            or self.scope.direction is None
            or self.scope.five_tuple_digest is None
        ):
            raise ValueError(
                "complete network-flow coverage requires path, direction, and five-tuple"
            )
        if (
            self.family == "connectionMonitor"
            and self.status == "complete"
            and (
                self.scope.path_id is None
                or self.scope.endpoint_test_reference is None
                or self.scope.endpoint_test_digest is None
                or self.scope.direction is None
                or self.scope.five_tuple_digest is None
            )
        ):
            raise ValueError(
                "complete Connection Monitor coverage requires path and endpoint test"
            )
        expected = _expected_digest(
            self,
            excluded_fields={"coverage_id", "coverage_digest"},
        )
        if self.coverage_digest != expected:
            raise ValueError("coverageDigest does not bind the coverage record")
        if self.coverage_id != f"coverage-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("coverageId is not digest-bound")
        return self


class MonitoringEvidenceBundle(_StrictCorrelationModel):
    schema_version: Literal["athena.wc026MonitoringEvidenceBundle.v1"] = Field(
        alias="schemaVersion"
    )
    workload_id: str = Field(
        alias="workloadId",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    monitoring_contract_digest: Sha256Digest = Field(
        alias="monitoringContractDigest"
    )
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    observations: tuple[MonitoringObservation, ...] = Field(max_length=1000)
    coverage: tuple[EvidenceCoverage, ...] = Field(min_length=1, max_length=100)
    expected_coverage_scope_digests: tuple[Sha256Digest, ...] = Field(
        alias="expectedCoverageScopeDigests",
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_bundle(self) -> MonitoringEvidenceBundle:
        _require_interval(self.observed_start, self.observed_end)
        observation_ids = tuple(item.observation_id for item in self.observations)
        if observation_ids != tuple(sorted(observation_ids)):
            raise ValueError("observations must be deterministically ordered")
        observation_bindings = {
            item.observation_id: item.observation_digest for item in self.observations
        }
        if len(observation_bindings) != len(self.observations):
            raise ValueError("duplicate observation IDs are not permitted")
        coverage_keys = tuple(
            (
                item.family,
                item.coverage_start.isoformat(),
                item.coverage_end.isoformat(),
                item.scope.scope_digest,
            )
            for item in self.coverage
        )
        if coverage_keys != tuple(sorted(coverage_keys)) or len(
            coverage_keys
        ) != len(set(coverage_keys)):
            raise ValueError("coverage records must be deterministically ordered")
        if any(
            item.observed_start < self.observed_start
            or item.observed_end > self.observed_end
            for item in self.observations
        ):
            raise ValueError("observations must be contained by the bundle interval")
        if any(
            item.coverage_start < self.observed_start
            or item.coverage_end > self.observed_end
            for item in self.coverage
        ):
            raise ValueError("coverage must be contained by the bundle interval")
        _require_sorted_unique(
            self.expected_coverage_scope_digests,
            "expectedCoverageScopeDigests",
        )
        actual_scope_digests = tuple(
            sorted(item.scope.scope_digest for item in self.coverage)
        )
        if actual_scope_digests != self.expected_coverage_scope_digests:
            raise ValueError(
                "coverage must account for every expected monitoring query scope"
            )
        return self


def _observation_family(observation: MonitoringObservation) -> MonitoringEvidenceFamily:
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
    resource_ids = {observation.subject_resource_id}
    if isinstance(observation, NetworkFlowObservation):
        resource_ids.add(observation.enforcement_resource_id)
        if observation.source_resource_id is not None:
            resource_ids.add(observation.source_resource_id)
        if observation.destination_resource_id is not None:
            resource_ids.add(observation.destination_resource_id)
        if observation.rule_resource_id is not None:
            resource_ids.add(observation.rule_resource_id)
    elif isinstance(observation, ConnectionMonitorObservation):
        resource_ids.update(
            {
                observation.monitor_resource_id,
                observation.source_resource_id,
                observation.destination_resource_id,
            }
        )
    elif isinstance(observation, EndpointHealthObservation):
        resource_ids.update(observation.backend_resource_ids)
    return tuple(sorted(resource_ids))


def _monitoring_evidence_index(
    *,
    bundle: MonitoringEvidenceBundle,
    source_reference: VersionPinnedBlobReference,
) -> tuple[CorrelationEvidenceCitation, ...]:
    observations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=observation.observation_id,
            family=_observation_family(observation),
            provenanceRootDigest=observation.provenance_root_digest,
            evidenceDigest=observation.observation_digest,
            sourceReference=source_reference,
            observedStart=observation.observed_start,
            observedEnd=observation.observed_end,
            sourceRootReference=observation.source_root_reference,
            resourceIds=_observation_resource_ids(observation),
            summaryCode=observation.summary_code,
        )
        for observation in bundle.observations
    )
    coverage = tuple(
        CorrelationEvidenceCitation(
            evidenceId=item.coverage_id,
            family=item.family,
            provenanceRootDigest=item.provenance_root_digest,
            evidenceDigest=item.coverage_digest,
            sourceReference=source_reference,
            observedStart=item.coverage_start,
            observedEnd=item.coverage_end,
            sourceRootReference=item.source_root_reference,
            resourceIds=item.scope.resource_ids,
            summaryCode=f"coverage.{item.family}.{item.status}",
        )
        for item in bundle.coverage
    )
    return observations + coverage


class DependencyPath(_StrictCorrelationModel):
    path_id: str = Field(
        alias="pathId",
        min_length=1,
        max_length=128,
        pattern=r"^path-[a-f0-9]{32}$",
    )
    path_class: PathClass = Field(alias="pathClass")
    source_role_ref: str = Field(
        alias="sourceRoleRef",
        min_length=1,
        max_length=128,
    )
    target_role_ref: str = Field(
        alias="targetRoleRef",
        min_length=1,
        max_length=128,
    )
    relationship_ids: tuple[str, ...] = Field(
        alias="relationshipIds",
        min_length=1,
        max_length=32,
    )
    resource_ids: tuple[str, ...] = Field(
        alias="resourceIds",
        min_length=1,
        max_length=128,
    )
    path_digest: Sha256Digest = Field(alias="pathDigest")

    @field_validator("relationship_ids")
    @classmethod
    def validate_relationship_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique(values, "relationshipIds")

    @field_validator("resource_ids")
    @classmethod
    def normalize_resource_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_resource_id(value) for value in values)
        return _require_sorted_unique(normalized, "resourceIds")

    @model_validator(mode="after")
    def validate_path_digest(self) -> DependencyPath:
        expected = _expected_digest(
            self,
            excluded_fields={"path_id", "path_digest"},
        )
        if self.path_digest != expected:
            raise ValueError("pathDigest does not bind the dependency path")
        if self.path_id != f"path-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("pathId is not digest-bound")
        return self


class PublishedContextAuthority(_StrictCorrelationModel):
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^publication-authority-[a-f0-9]{32}$",
    )
    workload_id: str = Field(
        alias="workloadId",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=128,
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    resolved_profile_digest: Sha256Digest = Field(alias="resolvedProfileDigest")
    dependency_graph_digest: Sha256Digest = Field(alias="dependencyGraphDigest")
    publication_record_digest: Sha256Digest = Field(alias="publicationRecordDigest")
    audit_head_digest: Sha256Digest = Field(alias="auditHeadDigest")
    published_at: UtcDateTime = Field(alias="publishedAt")
    authority_digest: Sha256Digest = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def validate_authority(self) -> PublishedContextAuthority:
        expected = _expected_digest(
            self,
            excluded_fields={"authority_id", "authority_digest"},
        )
        if self.authority_digest != expected:
            raise ValueError("authorityDigest does not bind publication authority")
        if (
            self.authority_id
            != f"publication-authority-{expected.removeprefix('sha256:')[:32]}"
        ):
            raise ValueError("authorityId is not digest-bound")
        return self


class _CorrelationContextBindingBase(_StrictCorrelationModel):
    workload_id: str = Field(
        alias="workloadId",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=128,
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    resolved_profile_digest: Sha256Digest = Field(alias="resolvedProfileDigest")
    dependency_graph_digest: Sha256Digest = Field(alias="dependencyGraphDigest")
    dependency_paths: tuple[DependencyPath, ...] = Field(
        alias="dependencyPaths",
        min_length=1,
        max_length=256,
    )
    required_coverage_scope_digests: tuple[Sha256Digest, ...] = Field(
        alias="requiredCoverageScopeDigests",
        min_length=1,
        max_length=100,
    )
    binding_digest: Sha256Digest = Field(alias="bindingDigest")

    @model_validator(mode="after")
    def validate_common_binding(self) -> _CorrelationContextBindingBase:
        path_ids = tuple(path.path_id for path in self.dependency_paths)
        if path_ids != tuple(sorted(path_ids)) or len(set(path_ids)) != len(path_ids):
            raise ValueError("dependencyPaths must have unique deterministic path IDs")
        _require_sorted_unique(
            self.required_coverage_scope_digests,
            "requiredCoverageScopeDigests",
        )
        expected = _expected_digest(self, excluded_fields={"binding_digest"})
        if self.binding_digest != expected:
            raise ValueError("bindingDigest does not bind the correlation context")
        return self


class PublishedRuntimeContextBinding(_CorrelationContextBindingBase):
    binding_mode: Literal["publishedRuntime"] = Field(alias="bindingMode")
    publication_authority: PublishedContextAuthority = Field(
        alias="publicationAuthority"
    )
    preview_only: Literal[False] = Field(default=False, alias="previewOnly")

    @model_validator(mode="after")
    def validate_publication_authority(self) -> PublishedRuntimeContextBinding:
        authority = self.publication_authority
        if (
            authority.workload_id != self.workload_id
            or authority.manifest_id != self.manifest_id
            or authority.manifest_version != self.manifest_version
            or authority.manifest_digest != self.manifest_digest
            or authority.profile_id != self.profile_id
            or authority.resolved_profile_digest != self.resolved_profile_digest
            or authority.dependency_graph_digest != self.dependency_graph_digest
        ):
            raise ValueError(
                "publication authority does not bind the exact runtime context"
            )
        return self


class DraftPreviewContextBinding(_CorrelationContextBindingBase):
    binding_mode: Literal["draftPreview"] = Field(alias="bindingMode")
    draft_id: str = Field(
        alias="draftId",
        min_length=1,
        max_length=128,
    )
    draft_revision: int = Field(alias="draftRevision", ge=1)
    preview_only: Literal[True] = Field(default=True, alias="previewOnly")


type CorrelationContextBinding = Annotated[
    PublishedRuntimeContextBinding | DraftPreviewContextBinding,
    Field(discriminator="binding_mode"),
]


class IncidentHealthTransition(_StrictCorrelationModel):
    transition_id: str = Field(alias="transitionId")
    affected_resource_id: str = Field(
        alias="affectedResourceId",
        min_length=1,
        max_length=2048,
    )
    previous_state: HealthState = Field(alias="previousState")
    current_state: HealthState = Field(alias="currentState")
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    previous_state_evidence: tuple[CorrelationEvidenceCitation, ...] = Field(
        alias="previousStateEvidence",
        min_length=1,
        max_length=32,
    )
    current_state_evidence: tuple[CorrelationEvidenceCitation, ...] = Field(
        alias="currentStateEvidence",
        min_length=1,
        max_length=32,
    )
    transition_digest: Sha256Digest = Field(alias="transitionDigest")

    @field_validator("affected_resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        return _canonical_resource_id(value)

    @model_validator(mode="after")
    def validate_transition(self) -> IncidentHealthTransition:
        _require_interval(self.observed_start, self.observed_end)
        if self.previous_state == self.current_state:
            raise ValueError("health transition must change state")
        previous_refs = tuple(
            item.evidence_id for item in self.previous_state_evidence
        )
        current_refs = tuple(item.evidence_id for item in self.current_state_evidence)
        if (
            previous_refs != tuple(sorted(previous_refs))
            or current_refs != tuple(sorted(current_refs))
            or len(previous_refs) != len(set(previous_refs))
            or len(current_refs) != len(set(current_refs))
            or set(previous_refs).intersection(current_refs)
        ):
            raise ValueError(
                "transition evidence must have unique deterministic evidence IDs"
            )
        if (
            self.observed_start
            != min(item.observed_start for item in self.current_state_evidence)
            or self.observed_end
            != max(item.observed_end for item in self.current_state_evidence)
        ):
            raise ValueError(
                "transition interval must be derived from current-state evidence"
            )
        if any(
            item.observed_end > self.observed_start
            for item in self.previous_state_evidence
        ):
            raise ValueError(
                "previous-state evidence must not overlap the current-state onset"
            )
        if any(
            self.affected_resource_id not in item.resource_ids
            for item in (*self.previous_state_evidence, *self.current_state_evidence)
        ):
            raise ValueError(
                "transition evidence must reference the affected resource"
            )
        expected = _expected_digest(
            self,
            excluded_fields={"transition_id", "transition_digest"},
        )
        if self.transition_digest != expected:
            raise ValueError("transitionDigest does not bind the health transition")
        _require_bound_identifier(
            identifier=self.transition_id,
            identifier_kind="transition",
            digest=expected,
        )
        return self


class CorrelationEvidenceInventory(_StrictCorrelationModel):
    rule_catalog_digest: Sha256Digest = Field(alias="ruleCatalogDigest")
    context_binding_digest: Sha256Digest = Field(alias="contextBindingDigest")
    incident_transition_digest: Sha256Digest = Field(
        alias="incidentTransitionDigest"
    )
    monitoring_handoff_digest: Sha256Digest = Field(alias="monitoringHandoffDigest")
    monitoring_bundle_digest: Sha256Digest = Field(alias="monitoringBundleDigest")
    change_artifact_digests: tuple[Sha256Digest, ...] = Field(
        alias="changeArtifactDigests",
        max_length=256,
    )
    evidence_index_digest: Sha256Digest = Field(alias="evidenceIndexDigest")
    source_references: tuple[VersionPinnedBlobReference, ...] = Field(
        alias="sourceReferences",
        min_length=1,
        max_length=512,
    )
    inventory_digest: Sha256Digest = Field(alias="inventoryDigest")

    @model_validator(mode="after")
    def validate_inventory(self) -> CorrelationEvidenceInventory:
        _require_sorted_unique(self.change_artifact_digests, "changeArtifactDigests")
        source_keys = tuple(
            (item.name, item.version, item.content_digest)
            for item in self.source_references
        )
        source_identities = tuple((item.name, item.version) for item in self.source_references)
        if (
            source_keys != tuple(sorted(source_keys))
            or len(source_identities) != len(set(source_identities))
        ):
            raise ValueError(
                "sourceReferences must be unique deterministic immutable references"
            )
        expected = _expected_digest(self, excluded_fields={"inventory_digest"})
        if self.inventory_digest != expected:
            raise ValueError("inventoryDigest does not bind the evidence inventory")
        return self


class CorrelationRequest(_StrictCorrelationModel):
    """Untrusted wire envelope that must pass the later verification adapter."""

    schema_version: Literal["athena.wc026CorrelationRequest.v1"] = Field(
        alias="schemaVersion"
    )
    request_id: str = Field(alias="requestId")
    algorithm_id: Literal["athena.wc026.correlation.v1"] = Field(alias="algorithmId")
    rule_catalog_digest: Sha256Digest = Field(alias="ruleCatalogDigest")
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    issued_at: UtcDateTime = Field(alias="issuedAt")
    trusted_as_of: UtcDateTime = Field(alias="trustedAsOf")
    expires_at: UtcDateTime = Field(alias="expiresAt")
    context_binding: CorrelationContextBinding = Field(alias="contextBinding")
    incident_anchor: IncidentHealthTransition = Field(alias="incidentAnchor")
    monitoring_handoff: MonitoringEvidenceHandoff = Field(alias="monitoringHandoff")
    monitoring_bundle: MonitoringEvidenceBundle = Field(alias="monitoringBundle")
    change_artifacts: tuple[ChangeEvidenceArtifact, ...] = Field(
        default=(),
        alias="changeArtifacts",
        max_length=256,
    )
    change_handoffs: tuple[ChangeEvidencePersistenceHandoff, ...] = Field(
        default=(),
        alias="changeHandoffs",
        max_length=256,
    )
    evidence_index: tuple[CorrelationEvidenceCitation, ...] = Field(
        alias="evidenceIndex",
        min_length=1,
        max_length=2048,
    )
    evidence_inventory: CorrelationEvidenceInventory = Field(alias="evidenceInventory")
    request_digest: Sha256Digest = Field(alias="requestDigest")

    @model_validator(mode="after")
    def validate_request(self) -> CorrelationRequest:
        if not (
            self.issued_at <= self.trusted_as_of <= self.expires_at
            and self.expires_at - self.issued_at <= timedelta(minutes=15)
        ):
            raise ValueError(
                "request issuance, trustedAsOf, and expiry must form one bounded window"
            )
        if self.incident_anchor.observed_end > self.trusted_as_of:
            raise ValueError("incident evidence must not be newer than trustedAsOf")
        if self.monitoring_bundle.observed_end > self.trusted_as_of:
            raise ValueError("monitoring evidence must not be newer than trustedAsOf")
        if self.monitoring_handoff.observed_at > self.trusted_as_of:
            raise ValueError("monitoring handoff must not be newer than trustedAsOf")
        if self.monitoring_bundle.observed_end > self.monitoring_handoff.observed_at:
            raise ValueError("monitoring bundle must not end after its handoff")
        if self.context_binding.workload_id != self.monitoring_bundle.workload_id:
            raise ValueError("context and monitoring bundle workload IDs must match")
        if (
            self.context_binding.required_coverage_scope_digests
            != self.monitoring_bundle.expected_coverage_scope_digests
        ):
            raise ValueError(
                "monitoring coverage scopes must match the governed context"
            )
        if any(
            item.observed_end > self.trusted_as_of for item in self.evidence_index
        ):
            raise ValueError("evidenceIndex contains evidence newer than trustedAsOf")
        if isinstance(self.context_binding, PublishedRuntimeContextBinding) and (
            self.context_binding.publication_authority.published_at
            > self.trusted_as_of
        ):
            raise ValueError("publication authority must not be newer than trustedAsOf")
        handoff_digest = self.monitoring_handoff.compute_artifact_digest_value()
        monitoring_bundle_digest = sha256_hex(self.monitoring_bundle.canonical_bytes())
        if (
            self.monitoring_handoff.evidence.content_digest
            != monitoring_bundle_digest
            or self.monitoring_bundle.monitoring_contract_digest
            != self.monitoring_handoff.collector_contract_digest
        ):
            raise ValueError("monitoring bundle is not bound to the exact handoff")
        change_digests = tuple(
            sha256_hex(artifact.canonical_bytes())
            for artifact in self.change_artifacts
        )
        if change_digests != tuple(sorted(change_digests)) or len(
            set(change_digests)
        ) != len(change_digests):
            raise ValueError(
                "changeArtifacts must have unique deterministic artifact digests"
            )
        if any(
            artifact.evidence.occurred_at > self.trusted_as_of
            or artifact.evidence.received_at > self.trusted_as_of
            for artifact in self.change_artifacts
        ):
            raise ValueError("change evidence must not be newer than trustedAsOf")
        if len(self.change_handoffs) != len(self.change_artifacts):
            raise ValueError("each change artifact requires one immutable handoff")
        for artifact, handoff, artifact_digest in zip(
            self.change_artifacts,
            self.change_handoffs,
            change_digests,
            strict=True,
        ):
            if (
                handoff.evidence_id != artifact.evidence.evidence_id
                or handoff.deduplication_key
                != artifact.evidence.deduplication_key
                or handoff.change_key != artifact.evidence.change_key
                or handoff.artifact.content_digest != artifact_digest
            ):
                raise ValueError(
                    "change handoff does not bind the exact change artifact"
                )
        change_by_evidence_id = {
            artifact.evidence.evidence_id: (
                artifact,
                artifact_digest,
            )
            for artifact, artifact_digest in zip(
                self.change_artifacts,
                change_digests,
                strict=True,
            )
        }
        for observation in self.monitoring_bundle.observations:
            if not (
                isinstance(observation, NetworkFlowObservation)
                and observation.effective_rule_attribution
            ):
                continue
            matched_change_evidence_id = observation.matched_change_evidence_id
            if matched_change_evidence_id is None:
                raise ValueError(
                    "effective flow attribution references unknown change evidence"
                )
            matched = change_by_evidence_id.get(matched_change_evidence_id)
            if matched is None:
                raise ValueError(
                    "effective flow attribution references unknown change evidence"
                )
            artifact, artifact_digest = matched
            change = artifact.evidence
            if (
                observation.matched_change_artifact_digest != artifact_digest
                or observation.matched_change_key != change.change_key
                or observation.rule_resource_id != change.target_resource_id
                or change.target_resource_type.casefold()
                != "microsoft.network/networksecuritygroups/securityrules"
                or not set(observation.matched_property_paths).issubset(
                    {item.path for item in change.changed_properties}
                )
            ):
                raise ValueError(
                    "effective flow attribution does not bind the exact NSG change"
                )
        expected_source_references = tuple(
            sorted(
                (
                    self.monitoring_handoff.evidence,
                    *(handoff.artifact for handoff in self.change_handoffs),
                ),
                key=lambda item: (item.name, item.version, item.content_digest),
            )
        )
        change_evidence_index = tuple(
            CorrelationEvidenceCitation(
                evidenceId=artifact.evidence.evidence_id,
                family="resourceChange",
                provenanceRootDigest=sha256_hex(
                    artifact.evidence.source_record_reference
                ),
                evidenceDigest=artifact_digest,
                sourceReference=handoff.artifact,
                observedStart=artifact.evidence.occurred_at,
                observedEnd=artifact.evidence.occurred_at,
                sourceRootReference=artifact.evidence.source_record_reference,
                resourceIds=(artifact.evidence.target_resource_id,),
                summaryCode=(
                    f"change.{artifact.evidence.operation}.{artifact.evidence.result}"
                ),
            )
            for artifact, handoff, artifact_digest in zip(
                self.change_artifacts,
                self.change_handoffs,
                change_digests,
                strict=True,
            )
        )
        expected_evidence_index = tuple(
            sorted(
                (
                    *_monitoring_evidence_index(
                        bundle=self.monitoring_bundle,
                        source_reference=self.monitoring_handoff.evidence,
                    ),
                    *change_evidence_index,
                ),
                key=lambda item: item.evidence_id,
            )
        )
        if self.evidence_index != expected_evidence_index:
            raise ValueError(
                "evidenceIndex must be derived exactly from the supplied evidence"
            )
        evidence_ids = tuple(item.evidence_id for item in self.evidence_index)
        if evidence_ids != tuple(sorted(evidence_ids)) or len(evidence_ids) != len(
            set(evidence_ids)
        ):
            raise ValueError("evidenceIndex must have unique deterministic evidence IDs")
        source_root_bindings: dict[str, str] = {}
        for citation in self.evidence_index:
            existing = source_root_bindings.get(citation.source_root_reference)
            if (
                existing is not None
                and existing != citation.provenance_root_digest
            ):
                raise ValueError(
                    "sourceRootReference cannot bind multiple provenance roots"
                )
            source_root_bindings[citation.source_root_reference] = (
                citation.provenance_root_digest
            )
        if any(
            item.source_reference not in expected_source_references
            for item in self.evidence_index
        ):
            raise ValueError(
                "evidenceIndex contains a source outside the immutable inventory"
            )
        evidence_by_id = {item.evidence_id: item for item in self.evidence_index}
        if any(
            evidence_by_id.get(item.evidence_id) != item
            for item in (
                *self.incident_anchor.previous_state_evidence,
                *self.incident_anchor.current_state_evidence,
            )
        ):
            raise ValueError(
                "incident evidence must resolve exactly in the evidence index"
            )
        observation_by_id = {
            item.observation_id: item for item in self.monitoring_bundle.observations
        }
        def matches_health_state(
            reference: CorrelationEvidenceCitation,
            state: HealthState,
        ) -> bool:
            observation = observation_by_id.get(reference.evidence_id)
            return bool(
                isinstance(observation, GuestSignalObservation)
                and observation.subject_resource_id
                == self.incident_anchor.affected_resource_id
                and observation.state == state
            ) or (
                isinstance(observation, EndpointHealthObservation)
                and observation.subject_resource_id
                == self.incident_anchor.affected_resource_id
                and observation.status == state
            ) or (
                isinstance(observation, PlatformHealthObservation)
                and observation.subject_resource_id
                == self.incident_anchor.affected_resource_id
                and observation.status == state
            )

        if not all(
            matches_health_state(reference, self.incident_anchor.previous_state)
            for reference in self.incident_anchor.previous_state_evidence
        ) or not all(
            matches_health_state(reference, self.incident_anchor.current_state)
            for reference in self.incident_anchor.current_state_evidence
        ):
            raise ValueError(
                "incident transition requires matching previous and current health evidence"
            )
        dependency_paths = {
            path.path_id: path for path in self.context_binding.dependency_paths
        }
        for observation in self.monitoring_bundle.observations:
            path_id = (
                observation.path_id
                if isinstance(
                    observation,
                    (
                        NetworkFlowObservation,
                        ConnectionMonitorObservation,
                        EndpointHealthObservation,
                    ),
                )
                else None
            )
            if path_id is not None and path_id not in dependency_paths:
                raise ValueError(
                    "monitoring observation references an undeclared dependency path"
                )
            if path_id is not None:
                path_resources = set(dependency_paths[path_id].resource_ids)
                if isinstance(observation, NetworkFlowObservation):
                    observation_resources = {
                        observation.subject_resource_id,
                        observation.source_resource_id,
                        observation.destination_resource_id,
                        observation.enforcement_resource_id,
                        *(
                            ()
                            if observation.rule_resource_id is None
                            else (observation.rule_resource_id,)
                        ),
                    }
                elif isinstance(observation, ConnectionMonitorObservation):
                    observation_resources = {
                        observation.subject_resource_id,
                        observation.source_resource_id,
                        observation.destination_resource_id,
                    }
                elif isinstance(observation, EndpointHealthObservation):
                    observation_resources = {
                        observation.subject_resource_id,
                        *observation.backend_resource_ids,
                    }
                else:
                    observation_resources = set()
                if not observation_resources.issubset(path_resources):
                    raise ValueError(
                        "monitoring observation resources are outside the governed path"
                    )
        if any(
            item.scope.path_id is not None
            and item.scope.path_id not in dependency_paths
            for item in self.monitoring_bundle.coverage
        ):
            raise ValueError(
                "monitoring coverage references an undeclared dependency path"
            )
        if any(
            item.scope.path_id is not None
            and not set(item.scope.resource_ids).issubset(
                dependency_paths[item.scope.path_id].resource_ids
            )
            for item in self.monitoring_bundle.coverage
        ):
            raise ValueError(
                "monitoring coverage resources are outside the governed path"
            )
        evidence_index_digest = compute_artifact_digest(
            [
                item.model_dump(mode="json", by_alias=True, exclude_none=True)
                for item in self.evidence_index
            ]
        )
        if (
            self.evidence_inventory.rule_catalog_digest != self.rule_catalog_digest
            or self.evidence_inventory.context_binding_digest
            != self.context_binding.binding_digest
            or self.evidence_inventory.incident_transition_digest
            != self.incident_anchor.transition_digest
            or self.evidence_inventory.monitoring_handoff_digest != handoff_digest
            or self.evidence_inventory.monitoring_bundle_digest
            != monitoring_bundle_digest
            or self.evidence_inventory.change_artifact_digests != change_digests
            or self.evidence_inventory.evidence_index_digest != evidence_index_digest
            or self.evidence_inventory.source_references
            != expected_source_references
        ):
            raise ValueError("evidenceInventory does not match the exact request inputs")
        expected = _expected_digest(
            self,
            excluded_fields={"request_id", "request_digest"},
        )
        if self.request_digest != expected:
            raise ValueError("requestDigest does not bind the correlation request")
        _require_bound_identifier(
            identifier=self.request_id,
            identifier_kind="request",
            digest=expected,
        )
        return self


def _flow_coverage_matches(
    coverage: EvidenceCoverage,
    flow: NetworkFlowObservation,
    *,
    affected_path_id: str | None,
    incident_start: UtcDateTime,
    incident_end: UtcDateTime,
) -> bool:
    return (
        coverage.family == "networkFlow"
        and coverage.status == "complete"
        and affected_path_id == coverage.scope.path_id
        and flow.path_id == coverage.scope.path_id
        and flow.direction == coverage.scope.direction
        and flow.five_tuple_digest == coverage.scope.five_tuple_digest
        and set(_observation_resource_ids(flow)).issubset(
            coverage.scope.resource_ids
        )
        and coverage.coverage_start <= incident_start
        and coverage.coverage_end >= incident_end
        and coverage.coverage_start <= flow.observed_start
        and coverage.coverage_end >= flow.observed_end
        and _intervals_overlap(
            flow.observed_start,
            flow.observed_end,
            incident_start,
            incident_end,
        )
    )


def _monitor_coverage_matches(
    coverage: EvidenceCoverage,
    test: ConnectionMonitorObservation,
    *,
    affected_path_id: str | None,
    incident_start: UtcDateTime,
    incident_end: UtcDateTime,
) -> bool:
    return (
        coverage.family == "connectionMonitor"
        and coverage.status == "complete"
        and affected_path_id == coverage.scope.path_id
        and test.path_id == coverage.scope.path_id
        and coverage.scope.endpoint_test_reference
        == test.test_configuration_reference
        and coverage.scope.endpoint_test_digest == test.test_configuration_digest
        and coverage.scope.direction == test.direction
        and coverage.scope.five_tuple_digest == test.five_tuple_digest
        and {
            test.subject_resource_id,
            test.source_resource_id,
            test.destination_resource_id,
        }.issubset(coverage.scope.resource_ids)
        and coverage.coverage_start <= incident_start
        and coverage.coverage_end >= incident_end
        and coverage.coverage_start <= test.observed_start
        and coverage.coverage_end >= test.observed_end
        and _intervals_overlap(
            test.observed_start,
            test.observed_end,
            incident_start,
            incident_end,
        )
    )


def _same_flow(
    first: NetworkFlowObservation,
    second: NetworkFlowObservation,
) -> bool:
    return (
        first.path_id == second.path_id
        and first.direction == second.direction
        and first.five_tuple_digest == second.five_tuple_digest
        and first.source_resource_id == second.source_resource_id
        and first.destination_resource_id == second.destination_resource_id
        and first.source_address == second.source_address
        and first.destination_address == second.destination_address
        and first.protocol == second.protocol
        and first.source_port == second.source_port
        and first.destination_port == second.destination_port
        and first.enforcement_resource_id == second.enforcement_resource_id
    )


def _same_monitor(
    first: ConnectionMonitorObservation,
    second: ConnectionMonitorObservation,
) -> bool:
    return (
        first.path_id == second.path_id
        and first.direction == second.direction
        and first.five_tuple_digest == second.five_tuple_digest
        and first.source_resource_id == second.source_resource_id
        and first.destination_resource_id == second.destination_resource_id
        and first.source_address == second.source_address
        and first.destination_address == second.destination_address
        and first.protocol == second.protocol
        and first.source_port == second.source_port
        and first.destination_port == second.destination_port
        and first.test_configuration_reference == second.test_configuration_reference
        and first.test_configuration_digest == second.test_configuration_digest
    )


def validate_correlation_report_binding(
    report: CorrelationReport,
    request: CorrelationRequest,
) -> None:
    if (
        report.request_digest != request.request_digest
        or report.transition_digest != request.incident_anchor.transition_digest
        or report.context_binding_digest != request.context_binding.binding_digest
        or report.input_inventory_digest != request.evidence_inventory.inventory_digest
        or report.rule_catalog_digest != request.rule_catalog_digest
        or report.as_of != request.trusted_as_of
        or report.binding_mode != request.context_binding.binding_mode
        or report.preview_only != (request.context_binding.binding_mode == "draftPreview")
        or report.incident_anchor_observed_start
        != request.incident_anchor.observed_start
        or report.incident_anchor_observed_end != request.incident_anchor.observed_end
    ):
        raise ValueError("correlation report does not bind the exact request")

    evidence_index = {item.evidence_id: item for item in request.evidence_index}
    observation_index = {
        item.observation_id: item for item in request.monitoring_bundle.observations
    }
    coverage_index = {
        item.coverage_id: item for item in request.monitoring_bundle.coverage
    }
    change_index = {
        item.evidence.evidence_id: item for item in request.change_artifacts
    }
    dependency_paths = {
        item.path_id: item for item in request.context_binding.dependency_paths
    }

    def require_cap(
        hypothesis: RootCauseHypothesis,
        code: ConfidenceCapCode,
        maximum: ConfidenceLevel,
    ) -> None:
        caps = {item.code: item.maximum_confidence for item in hypothesis.caps}
        if code not in caps or _CONFIDENCE_RANK[caps[code]] > _CONFIDENCE_RANK[maximum]:
            raise ValueError(f"correlation hypothesis requires {code} confidence cap")

    for hypothesis in report.hypotheses:
        if (
            hypothesis.affected_path_id is not None
            and hypothesis.affected_path_id not in dependency_paths
        ):
            raise ValueError("correlation report references an unknown dependency path")
        for citation in hypothesis.supporting_evidence:
            if evidence_index.get(citation.evidence_id) != citation:
                raise ValueError(
                    "correlation report cites evidence outside the verified request"
                )
        referenced_ids = {
            evidence_id
            for gate in hypothesis.gates
            for evidence_id in gate.evidence_ids
        }
        referenced_ids.update(
            evidence_id
            for contradiction in hypothesis.contradictions
            for evidence_id in contradiction.evidence_ids
        )
        if not referenced_ids.issubset(evidence_index):
            raise ValueError(
                "correlation report references unknown gate or contradiction evidence"
            )
        gate_map = {item.code: item for item in hypothesis.gates}
        no_hard_conflict_gate = gate_map.get("noHardConflict")
        if (
            no_hard_conflict_gate is not None
            and no_hard_conflict_gate.satisfied
            and any(item.hard_conflict for item in hypothesis.contradictions)
        ):
            raise ValueError(
                "noHardConflict gate contradicts the reported hard conflicts"
            )
        if any(
            gate.satisfied
            and gate.code != "noHardConflict"
            and not gate.evidence_ids
            for gate in hypothesis.gates
        ):
            raise ValueError("satisfied causal gates require cited evidence")

        affected_path = (
            None
            if hypothesis.affected_path_id is None
            else dependency_paths[hypothesis.affected_path_id]
        )
        if (
            affected_path is not None
            and request.incident_anchor.affected_resource_id
            not in affected_path.resource_ids
        ):
            raise ValueError("affected path does not contain the incident resource")
        for gate in hypothesis.gates:
            if not gate.satisfied:
                continue
            gate_citations = tuple(evidence_index[item] for item in gate.evidence_ids)
            positive_gate_citations = tuple(
                item
                for item in gate_citations
                if item.evidence_id not in coverage_index
            )
            gate_observations = tuple(
                observation_index[item]
                for item in gate.evidence_ids
                if item in observation_index
            )
            gate_changes = tuple(
                change_index[item].evidence
                for item in gate.evidence_ids
                if item in change_index
            )
            path_observations = tuple(
                item
                for item in gate_observations
                if isinstance(
                    item,
                    (
                        NetworkFlowObservation,
                        ConnectionMonitorObservation,
                        EndpointHealthObservation,
                    ),
                )
            )
            if gate.code == "affectedPath" and (
                affected_path is None
                or not gate_citations
                or not path_observations
                or any(
                    item.path_id != hypothesis.affected_path_id
                    for item in path_observations
                )
                or not any(
                    set(citation.resource_ids).issubset(affected_path.resource_ids)
                    for citation in gate_citations
                )
            ):
                raise ValueError("affectedPath gate does not bind the affected path")
            if gate.code == "successfulChange" and (
                not gate_changes
                or any(item.result != "succeeded" for item in gate_changes)
                or (
                    hypothesis.cause_resource_id is not None
                    and any(
                        item.target_resource_id != hypothesis.cause_resource_id
                        for item in gate_changes
                    )
                )
            ):
                raise ValueError("successfulChange gate requires successful change evidence")
            if gate.code == "semanticMatch" and (
                not gate_changes
                or any(not item.changed_properties for item in gate_changes)
                or (
                    hypothesis.category == "networkSecurityChange"
                    and any(
                        not any(
                            _is_nsg_causal_property(changed.path)
                            for changed in item.changed_properties
                        )
                        for item in gate_changes
                    )
                )
            ):
                raise ValueError("semanticMatch gate requires changed-property evidence")
            if gate.code == "effectiveRuleAttribution" and not any(
                isinstance(item, NetworkFlowObservation)
                and item.effective_rule_attribution
                and item.rule_resource_id is not None
                and item.rule_resource_id == hypothesis.cause_resource_id
                and item.path_id == hypothesis.affected_path_id
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                for item in gate_observations
            ):
                raise ValueError(
                    "effectiveRuleAttribution gate requires attributed flow evidence"
                )
            if gate.code == "matchingDeniedFlow" and not any(
                isinstance(item, NetworkFlowObservation)
                and item.decision == "denied"
                and item.path_id == hypothesis.affected_path_id
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                for item in gate_observations
            ):
                raise ValueError("matchingDeniedFlow gate requires denied-flow evidence")
            if gate.code == "connectionMonitorFailure" and not any(
                isinstance(item, ConnectionMonitorObservation)
                and item.status == "failed"
                and item.path_id == hypothesis.affected_path_id
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                for item in gate_observations
            ):
                raise ValueError(
                    "connectionMonitorFailure gate requires failed test evidence"
                )
            if gate.code == "endpointDegradation" and not any(
                isinstance(item, EndpointHealthObservation)
                and item.status in {"degraded", "unhealthy", "unavailable"}
                and item.path_id == hypothesis.affected_path_id
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                for item in gate_observations
            ):
                raise ValueError(
                    "endpointDegradation gate requires degraded endpoint evidence"
                )
            if gate.code == "independentCorroboration":
                if affected_path is None:
                    raise ValueError(
                        "independentCorroboration requires an affected path"
                    )
                monitoring_corroboration = tuple(
                    citation
                    for citation in positive_gate_citations
                    if citation.family != "resourceChange"
                )
                irrelevant_corroboration = False
                for citation in monitoring_corroboration:
                    if citation.evidence_id in change_index:
                        change = change_index[citation.evidence_id].evidence
                        if (
                            hypothesis.cause_resource_id is None
                            or change.target_resource_id
                            != hypothesis.cause_resource_id
                            or change.occurred_at
                            > request.incident_anchor.observed_start
                        ):
                            irrelevant_corroboration = True
                    elif citation.evidence_id in observation_index:
                        observation = observation_index[citation.evidence_id]
                        if hypothesis.category == "networkSecurityChange" and (
                            (
                                isinstance(observation, NetworkFlowObservation)
                                and observation.decision != "denied"
                            )
                            or (
                                isinstance(
                                    observation,
                                    ConnectionMonitorObservation,
                                )
                                and observation.status
                                not in {"failed", "degraded"}
                            )
                            or (
                                isinstance(
                                    observation,
                                    EndpointHealthObservation,
                                )
                                and observation.status
                                not in {"degraded", "unhealthy", "unavailable"}
                            )
                            or isinstance(
                                observation,
                                (GuestSignalObservation, PlatformHealthObservation),
                            )
                        ):
                            irrelevant_corroboration = True
                        if (
                            not set(citation.resource_ids).intersection(
                                affected_path.resource_ids
                            )
                            or not _intervals_overlap(
                                citation.observed_start,
                                citation.observed_end,
                                request.incident_anchor.observed_start,
                                request.incident_anchor.observed_end,
                            )
                            or (
                                isinstance(
                                    observation,
                                    (
                                        NetworkFlowObservation,
                                        ConnectionMonitorObservation,
                                        EndpointHealthObservation,
                                    ),
                                )
                                and observation.path_id
                                != hypothesis.affected_path_id
                            )
                        ):
                            irrelevant_corroboration = True
                if (
                    len({item.family for item in monitoring_corroboration}) < 2
                    or len(
                        {
                            item.provenance_root_digest
                            for item in monitoring_corroboration
                        }
                    )
                    < 2
                    or irrelevant_corroboration
                ):
                    raise ValueError(
                        "independentCorroboration requires independent evidence roots"
                    )
            if gate.code == "correctChronology" and (
                len(gate.evidence_ids) != 1
                or gate.evidence_ids[0] not in change_index
                or len(gate_changes) != 1
                or hypothesis.candidate_causal_at is None
                or any(
                    item.occurred_at > request.incident_anchor.observed_start
                    or item.occurred_at != hypothesis.candidate_causal_at
                    or (
                        hypothesis.cause_resource_id is not None
                        and item.target_resource_id
                        != hypothesis.cause_resource_id
                    )
                    for item in gate_changes
                )
            ):
                raise ValueError(
                    "correctChronology must bind the cited pre-incident change"
                )
            if gate.code == "recoveryEvidence" and not any(
                (
                    isinstance(item, GuestSignalObservation)
                    and item.state == "recovered"
                )
                or (
                    isinstance(item, EndpointHealthObservation)
                    and item.status == "recovered"
                )
                for item in gate_observations
            ):
                raise ValueError("recoveryEvidence gate requires recovered evidence")
        if hypothesis.category == "networkSecurityChange":
            attribution_gate = gate_map.get("effectiveRuleAttribution")
            denied_gate = gate_map.get("matchingDeniedFlow")
            if (
                attribution_gate is not None
                and attribution_gate.satisfied
                and denied_gate is not None
                and denied_gate.satisfied
            ):
                matching_ids = set(attribution_gate.evidence_ids).intersection(
                    denied_gate.evidence_ids
                )
                exact_matching_flow = False
                for evidence_id in matching_ids:
                    candidate = observation_index.get(evidence_id)
                    if (
                        isinstance(candidate, NetworkFlowObservation)
                        and candidate.effective_rule_attribution
                        and candidate.decision == "denied"
                        and candidate.rule_resource_id
                        == hypothesis.cause_resource_id
                        and candidate.path_id == hypothesis.affected_path_id
                        and _intervals_overlap(
                            candidate.observed_start,
                            candidate.observed_end,
                            request.incident_anchor.observed_start,
                            request.incident_anchor.observed_end,
                        )
                    ):
                        exact_matching_flow = True
                if not exact_matching_flow:
                    raise ValueError(
                        "network security attribution and denial must use one exact flow"
                    )
        if any(
            _CONFIDENCE_RANK[hypothesis.confidence]
            >= _CONFIDENCE_RANK[item.required_for_confidence]
            for item in hypothesis.missing_evidence
        ):
            raise ValueError("missing evidence blocks the declared confidence")

        substantive_support = tuple(
            item
            for item in hypothesis.supporting_evidence
            if item.evidence_id not in coverage_index
        )
        support_families = {
            item.family for item in substantive_support
        }
        if support_families == {"resourceChange"}:
            require_cap(hypothesis, "recentChangeOnly", "Low")
        affected_path_gate = gate_map.get("affectedPath")
        if (
            hypothesis.affected_path_id is None
            or affected_path_gate is None
            or not affected_path_gate.satisfied
        ):
            require_cap(hypothesis, "missingAffectedPath", "Low")
        corroboration_gate = gate_map.get("independentCorroboration")
        if corroboration_gate is None or not corroboration_gate.satisfied:
            require_cap(hypothesis, "missingIndependentSupport", "Medium")
        if hypothesis.category == "networkSecurityChange":
            attribution_gate = gate_map.get("effectiveRuleAttribution")
            if attribution_gate is None or not attribution_gate.satisfied:
                require_cap(hypothesis, "missingDirectAttribution", "High")
            if _CONFIDENCE_RANK[hypothesis.confidence] >= _CONFIDENCE_RANK["High"]:
                for required_gate in (
                    "affectedPath",
                    "matchingDeniedFlow",
                    "independentCorroboration",
                    "successfulChange",
                    "semanticMatch",
                    "correctChronology",
                ):
                    required_gate_value = gate_map.get(required_gate)
                    if (
                        required_gate_value is None
                        or not required_gate_value.satisfied
                    ):
                        raise ValueError(
                            f"High network security confidence requires {required_gate}"
                        )
                high_change_ids = gate_map["successfulChange"].evidence_ids
                if (
                    len(high_change_ids) != 1
                    or high_change_ids != gate_map["semanticMatch"].evidence_ids
                    or high_change_ids != gate_map["correctChronology"].evidence_ids
                    or high_change_ids[0] not in change_index
                ):
                    raise ValueError(
                        "High network security confidence requires one exact change artifact"
                    )
                high_change_artifact = change_index[high_change_ids[0]]
                high_change = high_change_artifact.evidence
                high_change_digest = sha256_hex(
                    high_change_artifact.canonical_bytes()
                )
                if (
                    high_change.result != "succeeded"
                    or high_change.target_resource_id
                    != hypothesis.cause_resource_id
                    or high_change.target_resource_type.casefold()
                    != "microsoft.network/networksecuritygroups/securityrules"
                    or not any(
                        _is_nsg_causal_property(item.path)
                        for item in high_change.changed_properties
                    )
                    or hypothesis.candidate_causal_at != high_change.occurred_at
                    or high_change.occurred_at
                    > request.incident_anchor.observed_start
                ):
                    raise ValueError(
                        "High network security confidence requires one causal pre-incident change"
                    )
                if attribution_gate is not None and attribution_gate.satisfied:
                    high_matching_flow_ids = set(
                        attribution_gate.evidence_ids
                    ).intersection(gate_map["matchingDeniedFlow"].evidence_ids)
                    high_matching_flow = False
                    for evidence_id in high_matching_flow_ids:
                        candidate = observation_index.get(evidence_id)
                        if (
                            isinstance(candidate, NetworkFlowObservation)
                            and candidate.effective_rule_attribution
                            and candidate.decision == "denied"
                            and candidate.rule_resource_id
                            == hypothesis.cause_resource_id
                            and candidate.path_id
                            == hypothesis.affected_path_id
                            and _intervals_overlap(
                                candidate.observed_start,
                                candidate.observed_end,
                                request.incident_anchor.observed_start,
                                request.incident_anchor.observed_end,
                            )
                            and candidate.matched_change_evidence_id
                            == high_change.evidence_id
                            and candidate.matched_change_key
                            == high_change.change_key
                            and candidate.matched_change_artifact_digest
                            == high_change_digest
                            and set(candidate.matched_property_paths).issubset(
                                {
                                    item.path
                                    for item in high_change.changed_properties
                                }
                            )
                        ):
                            high_matching_flow = True
                    if not high_matching_flow:
                        raise ValueError(
                            "High network security attribution must bind the selected change"
                        )
        chronology_gate = gate_map.get("correctChronology")
        if (
            chronology_gate is not None
            and chronology_gate.satisfied
        ):
            causal_change = change_index[chronology_gate.evidence_ids[0]].evidence
            causal_monitoring_ids = {
                evidence_id
                for gate in hypothesis.gates
                if gate.satisfied
                for evidence_id in gate.evidence_ids
                if evidence_id in observation_index
            }
            causal_monitoring_observations = [
                observation_index[evidence_id]
                for evidence_id in causal_monitoring_ids
            ]
            if any(
                item.observed_start < causal_change.occurred_at
                for item in causal_monitoring_observations
            ):
                require_cap(
                    hypothesis,
                    "ambiguousObservationWindow",
                    "Medium",
                )

        claimed_flow_ids: set[str] = set()
        denied_gate = gate_map.get("matchingDeniedFlow")
        if denied_gate is not None and denied_gate.satisfied:
            claimed_flow_ids = set(denied_gate.evidence_ids)
        claimed_flows_list: list[NetworkFlowObservation] = []
        for evidence_id in claimed_flow_ids:
            candidate = observation_index.get(evidence_id)
            if (
                isinstance(candidate, NetworkFlowObservation)
                and _intervals_overlap(
                    candidate.observed_start,
                    candidate.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
            ):
                claimed_flows_list.append(candidate)
        claimed_flows = tuple(claimed_flows_list)

        claimed_failed_tests_list: list[ConnectionMonitorObservation] = []
        connection_monitor_gate = gate_map.get("connectionMonitorFailure")
        for evidence_id in (
            ()
            if connection_monitor_gate is None
            or not connection_monitor_gate.satisfied
            else connection_monitor_gate.evidence_ids
        ):
            candidate = observation_index.get(evidence_id)
            if (
                isinstance(candidate, ConnectionMonitorObservation)
                and candidate.status == "failed"
                and candidate.path_id == hypothesis.affected_path_id
                and _intervals_overlap(
                    candidate.observed_start,
                    candidate.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
            ):
                claimed_failed_tests_list.append(candidate)
        claimed_failed_tests = tuple(claimed_failed_tests_list)

        mandatory_hard_conflicts: set[ContradictionCode] = set()
        candidate_change_ids = {
            citation.evidence_id
            for citation in hypothesis.supporting_evidence
            if citation.family == "resourceChange"
            and citation.evidence_id in change_index
            and (
                hypothesis.cause_resource_id is None
                or change_index[citation.evidence_id].evidence.target_resource_id
                == hypothesis.cause_resource_id
            )
        }
        candidate_change_ids.update(
            observation.matched_change_evidence_id
            for observation in claimed_flows
            if observation.matched_change_evidence_id is not None
        )
        candidate_changes = tuple(
            change_index[evidence_id].evidence
            for evidence_id in sorted(candidate_change_ids)
            if evidence_id in change_index
        )
        if any(item.result == "failed" for item in candidate_changes):
            mandatory_hard_conflicts.add("changeFailed")
        if any(
            item.occurred_at > request.incident_anchor.observed_start
            for item in candidate_changes
        ):
            mandatory_hard_conflicts.add("changeAfterDegradation")
        for flow in request.monitoring_bundle.observations:
            if not (
                isinstance(flow, NetworkFlowObservation)
                and flow.decision == "allowed"
                and any(_same_flow(flow, claimed) for claimed in claimed_flows)
            ):
                continue
            if any(
                _flow_coverage_matches(
                    coverage,
                    flow,
                    affected_path_id=hypothesis.affected_path_id,
                    incident_start=request.incident_anchor.observed_start,
                    incident_end=request.incident_anchor.observed_end,
                )
                for coverage in request.monitoring_bundle.coverage
            ):
                mandatory_hard_conflicts.add("completeAllowedFlow")
        for test in request.monitoring_bundle.observations:
            if not (
                isinstance(test, ConnectionMonitorObservation)
                and test.status == "succeeded"
                and any(
                    _same_monitor(test, claimed)
                    for claimed in claimed_failed_tests
                )
            ):
                continue
            if any(
                _monitor_coverage_matches(
                    coverage,
                    test,
                    affected_path_id=hypothesis.affected_path_id,
                    incident_start=request.incident_anchor.observed_start,
                    incident_end=request.incident_anchor.observed_end,
                )
                for coverage in request.monitoring_bundle.coverage
            ):
                mandatory_hard_conflicts.add("completeHealthyConnectionMonitor")
        declared_contradiction_codes = {
            item.code for item in hypothesis.contradictions
        }
        if not mandatory_hard_conflicts.issubset(declared_contradiction_codes):
            raise ValueError(
                "correlation hypothesis omits mandatory hard-conflict evidence"
            )
        if (
            no_hard_conflict_gate is not None
            and no_hard_conflict_gate.satisfied
            and mandatory_hard_conflicts
        ):
            raise ValueError(
                "noHardConflict gate contradicts derived hard-conflict evidence"
            )

        for contradiction in hypothesis.contradictions:
            if contradiction.code == "changeFailed":
                cited_changes = [
                    change_index[evidence_id].evidence
                    for evidence_id in contradiction.evidence_ids
                    if evidence_id in change_index
                ]
                if not cited_changes or not all(
                    item.result == "failed"
                    and (
                        hypothesis.cause_resource_id is None
                        or item.target_resource_id
                        == hypothesis.cause_resource_id
                    )
                    for item in cited_changes
                ):
                    raise ValueError(
                        "changeFailed requires matching failed change evidence"
                    )
            if contradiction.code == "changeAfterDegradation":
                cited_changes = [
                    change_index[evidence_id].evidence
                    for evidence_id in contradiction.evidence_ids
                    if evidence_id in change_index
                ]
                if not cited_changes or not all(
                    item.occurred_at > request.incident_anchor.observed_start
                    and (
                        hypothesis.cause_resource_id is None
                        or item.target_resource_id
                        == hypothesis.cause_resource_id
                    )
                    for item in cited_changes
                ):
                    raise ValueError(
                        "changeAfterDegradation requires matching post-incident change"
                    )
            if contradiction.code == "completeAllowedFlow":
                cited_coverage = [
                    coverage_index[evidence_id]
                    for evidence_id in contradiction.evidence_ids
                    if evidence_id in coverage_index
                ]
                cited_allowed_flows: list[NetworkFlowObservation] = []
                for evidence_id in contradiction.evidence_ids:
                    candidate = observation_index.get(evidence_id)
                    if (
                        isinstance(candidate, NetworkFlowObservation)
                        and candidate.decision == "allowed"
                    ):
                        cited_allowed_flows.append(candidate)
                matching_pair = any(
                    any(_same_flow(flow, claimed) for claimed in claimed_flows)
                    and _flow_coverage_matches(
                        coverage,
                        flow,
                        affected_path_id=hypothesis.affected_path_id,
                        incident_start=request.incident_anchor.observed_start,
                        incident_end=request.incident_anchor.observed_end,
                    )
                    for coverage in cited_coverage
                    for flow in cited_allowed_flows
                )
                if not matching_pair:
                    raise ValueError(
                        "completeAllowedFlow requires complete coverage and allowed-flow evidence"
                    )
            if contradiction.code == "completeHealthyConnectionMonitor":
                cited_coverage = [
                    coverage_index[evidence_id]
                    for evidence_id in contradiction.evidence_ids
                    if evidence_id in coverage_index
                ]
                cited_healthy_tests: list[ConnectionMonitorObservation] = []
                for evidence_id in contradiction.evidence_ids:
                    candidate = observation_index.get(evidence_id)
                    if (
                        isinstance(candidate, ConnectionMonitorObservation)
                        and candidate.status == "succeeded"
                    ):
                        cited_healthy_tests.append(candidate)
                matching_pair = any(
                    any(
                        _same_monitor(test, claimed)
                        for claimed in claimed_failed_tests
                    )
                    and _monitor_coverage_matches(
                        coverage,
                        test,
                        affected_path_id=hypothesis.affected_path_id,
                        incident_start=request.incident_anchor.observed_start,
                        incident_end=request.incident_anchor.observed_end,
                    )
                    for coverage in cited_coverage
                    for test in cited_healthy_tests
                )
                if not matching_pair:
                    raise ValueError(
                        "completeHealthyConnectionMonitor requires complete coverage "
                        "and healthy test evidence"
                    )
            if contradiction.code == "recoveryBeforeCorrection":
                cited_changes = [
                    change_index[evidence_id].evidence
                    for evidence_id in contradiction.evidence_ids
                    if evidence_id in change_index
                    and change_index[evidence_id].evidence.result == "succeeded"
                ]
                cited_recoveries: list[
                    GuestSignalObservation | EndpointHealthObservation
                ] = []
                for evidence_id in contradiction.evidence_ids:
                    candidate = observation_index.get(evidence_id)
                    if (
                        isinstance(candidate, GuestSignalObservation)
                        and candidate.state == "recovered"
                    ) or (
                        isinstance(candidate, EndpointHealthObservation)
                        and candidate.status == "recovered"
                    ):
                        cited_recoveries.append(candidate)
                if not cited_changes or not cited_recoveries or not any(
                    recovery.observed_end < change.occurred_at
                    for recovery in cited_recoveries
                    for change in cited_changes
                ):
                    raise ValueError(
                        "recoveryBeforeCorrection requires recovery before the cited change"
                    )

        if (
            hypothesis.confidence == "Confirmed"
            and hypothesis.category == "networkSecurityChange"
        ):
            cause_resource_id = hypothesis.cause_resource_id

            successful_change_ids = gate_map["successfulChange"].evidence_ids
            semantic_change_ids = gate_map["semanticMatch"].evidence_ids
            chronology_change_ids = gate_map["correctChronology"].evidence_ids
            if (
                len(successful_change_ids) != 1
                or successful_change_ids != semantic_change_ids
                or successful_change_ids != chronology_change_ids
                or successful_change_ids[0] not in change_index
            ):
                raise ValueError(
                    "Confirmed network security cause requires one exact change artifact"
                )
            matching_change_artifact = change_index[successful_change_ids[0]]
            matching_change = matching_change_artifact.evidence
            matching_change_digest = sha256_hex(
                matching_change_artifact.canonical_bytes()
            )
            if (
                matching_change.result != "succeeded"
                or matching_change.target_resource_id != cause_resource_id
                or matching_change.target_resource_type.casefold()
                != "microsoft.network/networksecuritygroups/securityrules"
                or not matching_change.changed_properties
                or not any(
                    _is_nsg_causal_property(changed.path)
                    for changed in matching_change.changed_properties
                )
            ):
                raise ValueError(
                    "Confirmed network security cause requires an exact successful rule change"
                )
            if (
                hypothesis.candidate_causal_at != matching_change.occurred_at
                or matching_change.occurred_at
                > request.incident_anchor.observed_start
            ):
                raise ValueError(
                    "Confirmed network security cause requires one exact pre-incident change"
                )
            matching_flow_ids = set(
                gate_map["effectiveRuleAttribution"].evidence_ids
            ).intersection(gate_map["matchingDeniedFlow"].evidence_ids)
            matching_flows: list[NetworkFlowObservation] = []
            for evidence_id in matching_flow_ids:
                candidate = observation_index.get(evidence_id)
                if isinstance(candidate, NetworkFlowObservation):
                    matching_flows.append(candidate)
            valid_flow_ids = {
                item.observation_id
                for item in matching_flows
                if item.effective_rule_attribution
                and item.decision == "denied"
                and item.rule_resource_id == cause_resource_id
                and item.matched_change_key == matching_change.change_key
                and item.matched_change_evidence_id
                == matching_change.evidence_id
                and item.matched_change_artifact_digest
                == matching_change_digest
                and set(item.matched_property_paths).issubset(
                    {
                        changed.path
                        for changed in matching_change.changed_properties
                    }
                )
                and item.path_id == hypothesis.affected_path_id
                and affected_path is not None
                and {
                    item.source_resource_id,
                    item.destination_resource_id,
                    item.enforcement_resource_id,
                }.issubset(affected_path.resource_ids)
                and item.observed_start >= matching_change.occurred_at
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                and any(
                    _flow_coverage_matches(
                        coverage,
                        item,
                        affected_path_id=hypothesis.affected_path_id,
                        incident_start=request.incident_anchor.observed_start,
                        incident_end=request.incident_anchor.observed_end,
                    )
                    for coverage in request.monitoring_bundle.coverage
                )
            }
            if not valid_flow_ids:
                raise ValueError(
                    "Confirmed network security cause requires one exact attributed denied flow"
                )
            failed_tests: list[ConnectionMonitorObservation] = []
            for evidence_id in gate_map["connectionMonitorFailure"].evidence_ids:
                candidate = observation_index.get(evidence_id)
                if isinstance(candidate, ConnectionMonitorObservation):
                    failed_tests.append(candidate)
            valid_failed_test_ids = {
                item.observation_id
                for item in failed_tests
                if item.status == "failed"
                and item.path_id == hypothesis.affected_path_id
                and affected_path is not None
                and {
                    item.source_resource_id,
                    item.destination_resource_id,
                }.issubset(affected_path.resource_ids)
                and item.observed_start >= matching_change.occurred_at
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                and any(
                    flow.observation_id in valid_flow_ids
                    and
                    flow.path_id == item.path_id
                    and flow.direction == item.direction
                    and flow.five_tuple_digest == item.five_tuple_digest
                    and flow.protocol == item.protocol
                    and flow.source_resource_id == item.source_resource_id
                    and flow.destination_resource_id
                    == item.destination_resource_id
                    and flow.source_address == item.source_address
                    and flow.destination_address == item.destination_address
                    and flow.source_port == item.source_port
                    and flow.destination_port == item.destination_port
                    for flow in matching_flows
                )
                and any(
                    _monitor_coverage_matches(
                        coverage,
                        item,
                        affected_path_id=hypothesis.affected_path_id,
                        incident_start=request.incident_anchor.observed_start,
                        incident_end=request.incident_anchor.observed_end,
                    )
                    for coverage in request.monitoring_bundle.coverage
                )
            }
            if not valid_failed_test_ids:
                raise ValueError(
                    "Confirmed Connection Monitor failure must match the affected path"
                )
            degraded_endpoints: list[EndpointHealthObservation] = []
            for evidence_id in gate_map["endpointDegradation"].evidence_ids:
                candidate = observation_index.get(evidence_id)
                if isinstance(candidate, EndpointHealthObservation):
                    degraded_endpoints.append(candidate)
            valid_endpoint_ids = {
                item.observation_id
                for item in degraded_endpoints
                if item.status in {"degraded", "unhealthy", "unavailable"}
                and item.path_id == hypothesis.affected_path_id
                and affected_path is not None
                and item.subject_resource_id in affected_path.resource_ids
                and item.observed_start >= matching_change.occurred_at
                and _intervals_overlap(
                    item.observed_start,
                    item.observed_end,
                    request.incident_anchor.observed_start,
                    request.incident_anchor.observed_end,
                )
                and any(
                    coverage.family == "endpointHealth"
                    and coverage.status == "complete"
                    and coverage.scope.path_id == item.path_id
                    and item.subject_resource_id in coverage.scope.resource_ids
                    and coverage.coverage_start
                    <= request.incident_anchor.observed_start
                    and coverage.coverage_end
                    >= request.incident_anchor.observed_end
                    for coverage in request.monitoring_bundle.coverage
                )
            }
            if not valid_endpoint_ids:
                raise ValueError(
                    "Confirmed network security cause requires endpoint degradation"
                )
            corroboration_ids = gate_map["independentCorroboration"].evidence_ids
            corroboration = [
                evidence_index[evidence_id]
                for evidence_id in corroboration_ids
                if evidence_id not in coverage_index
            ]
            causal_corroboration_ids = (
                valid_flow_ids | valid_failed_test_ids | valid_endpoint_ids
            )
            causal_corroboration = [
                item
                for item in corroboration
                if item.evidence_id in causal_corroboration_ids
            ]
            if (
                len({item.family for item in causal_corroboration}) < 3
                or len(
                    {
                        item.provenance_root_digest
                        for item in causal_corroboration
                    }
                )
                < 3
                or not valid_flow_ids.intersection(corroboration_ids)
                or not valid_failed_test_ids.intersection(corroboration_ids)
                or not valid_endpoint_ids.intersection(corroboration_ids)
            ):
                raise ValueError(
                    "Confirmed network security cause requires independent corroboration"
                )
        elif hypothesis.confidence == "Confirmed":
            raise ValueError(
                "Confirmed confidence is not defined for this cause category"
            )


def validate_runtime_correlation_report(
    report: CorrelationReport,
    request: CorrelationRequest,
) -> None:
    validate_correlation_report_binding(report, request)
    if (
        not isinstance(request.context_binding, PublishedRuntimeContextBinding)
        or report.binding_mode != "publishedRuntime"
        or report.preview_only
    ):
        raise ValueError("runtime correlation requires published context authority")


class CorrelationScoreComponents(_StrictCorrelationModel):
    topology: int = Field(ge=0, le=25)
    temporal: int = Field(ge=0, le=20)
    semantic: int = Field(ge=0, le=20)
    corroboration: int = Field(ge=0, le=25)
    recovery: int = Field(ge=0, le=10)
    raw_score: int = Field(alias="rawScore", ge=0, le=100)

    @model_validator(mode="after")
    def validate_sum(self) -> CorrelationScoreComponents:
        if self.raw_score != (
            self.topology
            + self.temporal
            + self.semantic
            + self.corroboration
            + self.recovery
        ):
            raise ValueError("rawScore must equal the component score sum")
        return self


class CorrelationGate(_StrictCorrelationModel):
    code: CorrelationGateCode
    satisfied: bool
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        alias="evidenceIds",
        max_length=64,
    )

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique(values, "evidenceIds")


class ConfidenceCap(_StrictCorrelationModel):
    code: ConfidenceCapCode
    maximum_confidence: ConfidenceLevel = Field(alias="maximumConfidence")


class CorrelationContradiction(_StrictCorrelationModel):
    code: ContradictionCode
    detail: str = Field(min_length=1, max_length=1000)
    evidence_ids: tuple[str, ...] = Field(
        alias="evidenceIds",
        min_length=1,
        max_length=64,
    )
    hard_conflict: bool = Field(alias="hardConflict")

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique(values, "evidenceIds")

    @model_validator(mode="after")
    def validate_hard_conflict(self) -> CorrelationContradiction:
        expected = self.code in _HARD_CONTRADICTION_CODES
        if self.hard_conflict != expected:
            raise ValueError("hardConflict must be derived from contradiction code")
        return self


class MissingCorrelationEvidence(_StrictCorrelationModel):
    code: MissingEvidenceCode
    family: EvidenceFamily
    detail: str = Field(min_length=1, max_length=1000)
    required_for_confidence: ConfidenceLevel = Field(alias="requiredForConfidence")


class RootCauseHypothesis(_StrictCorrelationModel):
    hypothesis_id: str = Field(alias="hypothesisId")
    rank: int = Field(ge=1, le=64)
    category: RootCauseCategory
    cause_resource_id: str | None = Field(
        default=None,
        alias="causeResourceId",
        min_length=1,
        max_length=2048,
    )
    affected_path_id: str | None = Field(
        default=None,
        alias="affectedPathId",
        min_length=1,
        max_length=128,
    )
    candidate_causal_at: UtcDateTime | None = Field(
        default=None,
        alias="candidateCausalAt",
    )
    score: CorrelationScoreComponents
    confidence: ConfidenceLevel
    supporting_evidence: tuple[CorrelationEvidenceCitation, ...] = Field(
        alias="supportingEvidence",
        max_length=128,
    )
    contradictions: tuple[CorrelationContradiction, ...] = Field(max_length=64)
    missing_evidence: tuple[MissingCorrelationEvidence, ...] = Field(
        alias="missingEvidence",
        max_length=64,
    )
    gates: tuple[CorrelationGate, ...] = Field(max_length=32)
    caps: tuple[ConfidenceCap, ...] = Field(max_length=16)
    hypothesis_digest: Sha256Digest = Field(alias="hypothesisDigest")

    @field_validator("cause_resource_id")
    @classmethod
    def normalize_cause_resource_id(cls, value: str | None) -> str | None:
        return None if value is None else _canonical_resource_id(value)

    @model_validator(mode="after")
    def validate_hypothesis(self) -> RootCauseHypothesis:
        evidence_ids = tuple(item.evidence_id for item in self.supporting_evidence)
        if evidence_ids != tuple(sorted(evidence_ids)) or len(evidence_ids) != len(
            set(evidence_ids)
        ):
            raise ValueError(
                "supportingEvidence must have unique deterministic evidence IDs"
            )
        gate_codes = tuple(item.code for item in self.gates)
        if gate_codes != tuple(sorted(gate_codes)) or len(gate_codes) != len(
            set(gate_codes)
        ):
            raise ValueError("gates must have unique deterministic codes")
        cap_codes = tuple(item.code for item in self.caps)
        if cap_codes != tuple(sorted(cap_codes)) or len(cap_codes) != len(set(cap_codes)):
            raise ValueError("caps must have unique deterministic codes")
        contradiction_keys = tuple(
            (item.code, item.evidence_ids, item.detail, item.hard_conflict)
            for item in self.contradictions
        )
        if contradiction_keys != tuple(sorted(contradiction_keys)) or len(
            contradiction_keys
        ) != len(set(contradiction_keys)):
            raise ValueError("contradictions must be deterministically ordered")
        missing_keys = tuple(
            (
                item.code,
                item.family,
                item.detail,
                item.required_for_confidence,
            )
            for item in self.missing_evidence
        )
        if missing_keys != tuple(sorted(missing_keys)) or len(missing_keys) != len(
            set(missing_keys)
        ):
            raise ValueError("missingEvidence must be deterministically ordered")
        if any(item.hard_conflict for item in self.contradictions) and (
            self.confidence != "Unknown"
        ):
            raise ValueError("hard conflicts require Unknown confidence")
        minimum_scores: dict[ConfidenceLevel, int] = {
            "Unknown": 0,
            "Low": 30,
            "Medium": 55,
            "High": 75,
            "Confirmed": 90,
        }
        if self.score.raw_score < minimum_scores[self.confidence]:
            raise ValueError("rawScore is below the declared confidence threshold")
        if self.caps:
            strongest_cap = min(
                (_CONFIDENCE_RANK[item.maximum_confidence] for item in self.caps),
            )
            if _CONFIDENCE_RANK[self.confidence] > strongest_cap:
                raise ValueError("confidence exceeds a declared cap")
        if self.confidence == "Confirmed" and (
            not self.gates or not all(gate.satisfied for gate in self.gates)
        ):
            raise ValueError("Confirmed confidence requires every declared gate")
        if self.confidence == "Confirmed" and not self.supporting_evidence:
            raise ValueError("Confirmed confidence requires supporting evidence")
        if (
            self.confidence == "Confirmed"
            and self.category == "networkSecurityChange"
            and set(gate_codes) != _NETWORK_SECURITY_CONFIRMED_GATES
        ):
            raise ValueError(
                "Confirmed network security cause requires the complete gate set"
            )
        expected = _expected_digest(
            self,
            excluded_fields={"rank", "hypothesis_id", "hypothesis_digest"},
        )
        if self.hypothesis_digest != expected:
            raise ValueError("hypothesisDigest does not bind the hypothesis")
        _require_bound_identifier(
            identifier=self.hypothesis_id,
            identifier_kind="hypothesis",
            digest=expected,
        )
        return self


class CorrelationReport(_StrictCorrelationModel):
    """Deterministic engine output that must be checked against its exact request."""

    schema_version: Literal["athena.wc026CorrelationReport.v1"] = Field(
        alias="schemaVersion"
    )
    report_id: str = Field(alias="reportId")
    algorithm_id: Literal["athena.wc026.correlation.v1"] = Field(alias="algorithmId")
    rule_catalog_digest: Sha256Digest = Field(alias="ruleCatalogDigest")
    as_of: UtcDateTime = Field(alias="asOf")
    binding_mode: BindingMode = Field(alias="bindingMode")
    context_binding_digest: Sha256Digest = Field(alias="contextBindingDigest")
    input_inventory_digest: Sha256Digest = Field(alias="inputInventoryDigest")
    request_digest: Sha256Digest = Field(alias="requestDigest")
    transition_digest: Sha256Digest = Field(alias="transitionDigest")
    incident_anchor_observed_start: UtcDateTime = Field(
        alias="incidentAnchorObservedStart"
    )
    incident_anchor_observed_end: UtcDateTime = Field(
        alias="incidentAnchorObservedEnd"
    )
    hypotheses: tuple[RootCauseHypothesis, ...] = Field(min_length=1, max_length=64)
    preview_only: bool = Field(alias="previewOnly")
    no_auto_remediation: Literal[True] = Field(alias="noAutoRemediation")
    report_digest: Sha256Digest = Field(alias="reportDigest")

    @model_validator(mode="after")
    def validate_report(self) -> CorrelationReport:
        _require_interval(
            self.incident_anchor_observed_start,
            self.incident_anchor_observed_end,
        )
        if self.preview_only != (self.binding_mode == "draftPreview"):
            raise ValueError("previewOnly must match the report binding mode")
        ranks = tuple(item.rank for item in self.hypotheses)
        if ranks != tuple(range(1, len(self.hypotheses) + 1)):
            raise ValueError("hypotheses must use contiguous deterministic ranks")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypotheses)
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("duplicate hypothesis IDs are not permitted")
        if any(
            item.candidate_causal_at is not None
            and item.candidate_causal_at > self.incident_anchor_observed_start
            for item in self.hypotheses
        ):
            raise ValueError(
                "candidate causal time must not follow the incident degradation"
            )
        expected = _expected_digest(
            self,
            excluded_fields={"report_id", "report_digest"},
        )
        if self.report_digest != expected:
            raise ValueError("reportDigest does not bind the correlation report")
        _require_bound_identifier(
            identifier=self.report_id,
            identifier_kind="report",
            digest=expected,
        )
        return self


__all__ = [
    "CORRELATION_ALGORITHM_ID",
    "CORRELATION_REPORT_SCHEMA_VERSION",
    "CORRELATION_REQUEST_SCHEMA_VERSION",
    "MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION",
    "BindingMode",
    "ConfidenceCap",
    "ConfidenceCapCode",
    "ConfidenceLevel",
    "ConnectionMonitorObservation",
    "ConnectionMonitorStatus",
    "ContradictionCode",
    "CorrelationContextBinding",
    "CorrelationContradiction",
    "CorrelationEvidenceCitation",
    "CorrelationEvidenceInventory",
    "CorrelationGate",
    "CorrelationGateCode",
    "CorrelationReport",
    "CorrelationRequest",
    "CorrelationScoreComponents",
    "CoverageStatus",
    "DependencyPath",
    "DraftPreviewContextBinding",
    "EndpointHealthObservation",
    "EvidenceCoverage",
    "EvidenceCoverageScope",
    "EvidenceFamily",
    "FlowDecision",
    "FlowDirection",
    "GuestSignal",
    "GuestSignalObservation",
    "HealthState",
    "IncidentHealthTransition",
    "MissingCorrelationEvidence",
    "MissingEvidenceCode",
    "MonitoringEvidenceBundle",
    "MonitoringEvidenceFamily",
    "MonitoringObservation",
    "NetworkFlowObservation",
    "NetworkAttributionMethod",
    "NetworkProtocol",
    "NetworkRuleCausalEffect",
    "PathClass",
    "PlatformHealthKind",
    "PlatformHealthObservation",
    "PublishedContextAuthority",
    "PublishedRuntimeContextBinding",
    "RootCauseCategory",
    "RootCauseHypothesis",
    "validate_correlation_report_binding",
    "validate_runtime_correlation_report",
]
