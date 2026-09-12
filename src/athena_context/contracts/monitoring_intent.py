from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import compute_artifact_digest, sha256_hex
from athena_context.contracts.correlation import PublishedRuntimeContextBinding
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MAX_PUBLISHED_MONITORING_INTENT_BYTES = 64 * 1024

type MonitoringEnvironment = Literal["production", "development", "training"]
type MonitoringSeverity = Literal[0, 1, 2, 3, 4]
type MonitoringComparisonOperator = Literal[
    "greaterThan",
    "greaterThanOrEqual",
    "lessThan",
    "lessThanOrEqual",
    "equal",
]
type MonitoringAggregation = Literal[
    "average",
    "count",
    "maximum",
    "minimum",
    "total",
]
type MonitoringMissingDataBehavior = Literal[
    "failClosed",
    "treatAsHealthy",
    "treatAsUnhealthy",
    "reviewRequired",
]
type MonitoringUnit = Literal[
    "bytes",
    "bytesPerSecond",
    "count",
    "milliseconds",
    "percent",
    "seconds",
]

_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}/resourcegroups/"
    r"[a-z0-9_().-]{1,90}/providers/[a-z0-9.]+"
    r"(?:/[a-z0-9.()_-]+/[a-z0-9.()_-]+)+$"
)


class _StrictMonitoringIntentModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


def _expected_digest(
    model: AthenaBaseModel,
    *,
    excluded_fields: set[str],
) -> Sha256Digest:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude=excluded_fields,
        )
    )


def _sorted_unique(
    values: tuple[str, ...],
    field_name: str,
) -> tuple[str, ...]:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{field_name} must be sorted unique values")
    return values


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items() if item is not None}
    return value


class MonitoringIntentDimension(_StrictMonitoringIntentModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9._-]{0,127}$",
    )
    operator: Literal["include", "exclude"]
    values: tuple[str, ...] = Field(min_length=1, max_length=64)

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) > 256 or not value or any(character < " " for character in value)
            for value in values
        ):
            raise ValueError("dimension values must be bounded visible text")
        return _sorted_unique(values, "dimension values")


class MonitoringIntentScope(_StrictMonitoringIntentModel):
    resource_ids: tuple[str, ...] = Field(
        alias="resourceIds",
        min_length=1,
        max_length=128,
    )
    path_ids: tuple[str, ...] = Field(
        alias="pathIds",
        min_length=1,
        max_length=64,
    )
    role_refs: tuple[str, ...] = Field(
        alias="roleRefs",
        min_length=1,
        max_length=64,
    )
    scope_digest: Sha256Digest = Field(alias="scopeDigest")

    @field_validator("resource_ids")
    @classmethod
    def validate_resource_ids(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(value.casefold() for value in values)
        if any(_RESOURCE_ID_PATTERN.fullmatch(value) is None for value in normalized):
            raise ValueError("monitoring scope contains an invalid resource ID")
        return _sorted_unique(normalized, "resourceIds")

    @field_validator("path_ids")
    @classmethod
    def validate_path_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"path-[a-f0-9]{32}", value) is None for value in values):
            raise ValueError("monitoring scope contains an invalid path ID")
        return _sorted_unique(values, "pathIds")

    @field_validator("role_refs")
    @classmethod
    def validate_role_refs(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None for value in values
        ):
            raise ValueError("monitoring scope contains an invalid role reference")
        return _sorted_unique(values, "roleRefs")

    @model_validator(mode="after")
    def validate_digest(self) -> MonitoringIntentScope:
        expected = _expected_digest(
            self,
            excluded_fields={"scope_digest"},
        )
        if self.scope_digest != expected:
            raise ValueError("scopeDigest does not bind monitoring scope")
        return self


class MetricMonitoringSignal(_StrictMonitoringIntentModel):
    signal_kind: Literal["metric"] = Field(alias="signalKind")
    metric_namespace: str = Field(
        alias="metricNamespace",
        min_length=1,
        max_length=256,
    )
    metric_name: str = Field(
        alias="metricName",
        min_length=1,
        max_length=256,
    )
    unit: MonitoringUnit
    aggregation: MonitoringAggregation
    operator: MonitoringComparisonOperator
    threshold: float
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
    dimensions: tuple[MonitoringIntentDimension, ...] = Field(
        max_length=16,
    )

    @model_validator(mode="after")
    def validate_frequency(self) -> MetricMonitoringSignal:
        if (
            self.frequency_seconds > self.evaluation_window_seconds
            or self.evaluation_window_seconds % self.frequency_seconds != 0
        ):
            raise ValueError("metric frequency must evenly divide its evaluation window")
        dimension_names = tuple(item.name.casefold() for item in self.dimensions)
        if dimension_names != tuple(sorted(dimension_names)) or len(dimension_names) != len(
            set(dimension_names)
        ):
            raise ValueError("metric dimensions must use unique sorted names")
        return self


class LogQueryMonitoringSignal(_StrictMonitoringIntentModel):
    signal_kind: Literal["logQuery"] = Field(alias="signalKind")
    query: str = Field(min_length=1, max_length=8192)
    query_digest: Sha256Digest = Field(alias="queryDigest")
    query_target_resource_id: str = Field(
        alias="queryTargetResourceId",
        min_length=1,
        max_length=2048,
    )
    unit: MonitoringUnit
    aggregation: MonitoringAggregation
    operator: MonitoringComparisonOperator
    threshold: float
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

    @model_validator(mode="after")
    def validate_query(self) -> LogQueryMonitoringSignal:
        if self.query != self.query.strip():
            raise ValueError("log query must not contain outer whitespace")
        if self.query_digest != sha256_hex(self.query.encode("utf-8")):
            raise ValueError("queryDigest does not bind the exact query text")
        if _RESOURCE_ID_PATTERN.fullmatch(self.query_target_resource_id.casefold()) is None:
            raise ValueError("query target resource ID is invalid")
        if (
            "//" in self.query
            or "/*" in self.query
            or re.search(
                r"\b(?:adx|app|arg|cluster|database|evaluate|"
                r"externaldata|resource|workspace)\b",
                self.query,
                re.IGNORECASE,
            )
        ):
            raise ValueError("log query must not cross declared workspace boundaries")
        if (
            self.frequency_seconds > self.evaluation_window_seconds
            or self.evaluation_window_seconds % self.frequency_seconds != 0
        ):
            raise ValueError("query frequency must evenly divide its evaluation window")
        return self


class ActivityLogMonitoringSignal(_StrictMonitoringIntentModel):
    signal_kind: Literal["activityLog"] = Field(alias="signalKind")
    categories: tuple[str, ...] = Field(min_length=1, max_length=16)
    operation_names: tuple[str, ...] = Field(
        alias="operationNames",
        min_length=1,
        max_length=64,
    )
    result_types: tuple[str, ...] = Field(
        alias="resultTypes",
        min_length=1,
        max_length=16,
    )
    levels: tuple[
        Literal[
            "Critical",
            "Error",
            "Informational",
            "Verbose",
            "Warning",
        ],
        ...,
    ] = Field(
        min_length=1,
        max_length=5,
    )

    @field_validator(
        "categories",
        "operation_names",
        "result_types",
        "levels",
    )
    @classmethod
    def validate_filters(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(not value or len(value) > 256 for value in values):
            raise ValueError("activity-log filters must be bounded")
        return _sorted_unique(values, "activity-log filters")


class ResourceHealthMonitoringSignal(_StrictMonitoringIntentModel):
    signal_kind: Literal["resourceHealth"] = Field(alias="signalKind")
    event_statuses: tuple[
        Literal["Active", "In Progress", "Resolved", "Updated"],
        ...,
    ] = Field(alias="eventStatuses", min_length=1, max_length=4)
    current_statuses: tuple[
        Literal["Available", "Degraded", "Unavailable", "Unknown"],
        ...,
    ] = Field(alias="currentStatuses", min_length=1, max_length=4)
    previous_statuses: tuple[
        Literal["Available", "Degraded", "Unavailable", "Unknown"],
        ...,
    ] = Field(alias="previousStatuses", min_length=1, max_length=4)
    reason_types: tuple[
        Literal["PlatformInitiated", "UserInitiated", "Unknown"],
        ...,
    ] = Field(alias="reasonTypes", min_length=1, max_length=3)

    @field_validator(
        "event_statuses",
        "current_statuses",
        "previous_statuses",
        "reason_types",
    )
    @classmethod
    def validate_filters(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _sorted_unique(values, "resource-health filters")


type MonitoringSignal = Annotated[
    MetricMonitoringSignal
    | LogQueryMonitoringSignal
    | ActivityLogMonitoringSignal
    | ResourceHealthMonitoringSignal,
    Field(discriminator="signal_kind"),
]


class PublishedMonitoringIntentControl(_StrictMonitoringIntentModel):
    control_id: str = Field(
        alias="controlId",
        pattern=r"^monitoring-control-[a-f0-9]{32}$",
    )
    source_clause_path: str = Field(
        alias="sourceClausePath",
        pattern=r"^/[A-Za-z0-9._~/-]{1,511}$",
    )
    owner_ref: str = Field(
        alias="ownerRef",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    severity: MonitoringSeverity
    missing_data_behavior: MonitoringMissingDataBehavior = Field(alias="missingDataBehavior")
    action_behavior: Literal["none"] = Field(alias="actionBehavior")
    dry_run_only: bool = Field(alias="dryRunOnly")
    scope: MonitoringIntentScope
    signal: MonitoringSignal
    control_digest: Sha256Digest = Field(alias="controlDigest")

    @model_validator(mode="after")
    def validate_control(self) -> PublishedMonitoringIntentControl:
        expected = _expected_digest(
            self,
            excluded_fields={"control_id", "control_digest"},
        )
        if self.control_digest != expected:
            raise ValueError("controlDigest does not bind monitoring control")
        if self.control_id != f"monitoring-control-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("controlId is not digest-bound")
        return self


class PublishedMonitoringIntent(_StrictMonitoringIntentModel):
    schema_version: Literal["athena.wc028PublishedMonitoringIntent.v1"] = Field(
        alias="schemaVersion"
    )
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^monitoring-intent-[a-f0-9]{32}$",
    )
    environment: MonitoringEnvironment
    workload_id: str = Field(alias="workloadId", min_length=1, max_length=128)
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
    context_binding_digest: Sha256Digest = Field(alias="contextBindingDigest")
    context_authority_id: str = Field(
        alias="contextAuthorityId",
        pattern=r"^publication-authority-[a-f0-9]{32}$",
    )
    context_authority_digest: Sha256Digest = Field(alias="contextAuthorityDigest")
    context_authority_reference: VersionPinnedBlobReference = Field(
        alias="contextAuthorityReference"
    )
    publication_record_digest: Sha256Digest = Field(alias="publicationRecordDigest")
    audit_head_digest: Sha256Digest = Field(alias="auditHeadDigest")
    published_at: UtcDateTime = Field(alias="publishedAt")
    controls: tuple[PublishedMonitoringIntentControl, ...] = Field(
        min_length=1,
        max_length=256,
    )
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    intent_digest: Sha256Digest = Field(alias="intentDigest")

    @model_validator(mode="after")
    def validate_intent(self) -> PublishedMonitoringIntent:
        control_ids = tuple(item.control_id for item in self.controls)
        if control_ids != tuple(sorted(control_ids)) or len(control_ids) != len(set(control_ids)):
            raise ValueError("monitoring controls must be unique and sorted")
        expected = _expected_digest(
            self,
            excluded_fields={"intent_id", "intent_digest"},
        )
        if self.intent_digest != expected:
            raise ValueError("intentDigest does not bind monitoring intent")
        if self.intent_id != f"monitoring-intent-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("intentId is not digest-bound")
        if len(self.canonical_bytes()) > MAX_PUBLISHED_MONITORING_INTENT_BYTES:
            raise ValueError("published monitoring intent exceeds its canonical byte budget")
        return self


class PublishedMonitoringIntentAttestation(_StrictMonitoringIntentModel):
    schema_version: Literal["athena.wc028PublishedMonitoringIntentAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    intent_id: str = Field(alias="intentId")
    intent_digest: Sha256Digest = Field(alias="intentDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class PublishedMonitoringIntentAssetReference(_StrictMonitoringIntentModel):
    schema_version: Literal["athena.wc028PublishedMonitoringIntentAssetReference.v1"] = Field(
        alias="schemaVersion"
    )
    reference_id: str = Field(
        alias="referenceId",
        pattern=r"^monitoring-intent-asset-[a-f0-9]{32}$",
    )
    intent_id: str = Field(alias="intentId")
    intent_digest: Sha256Digest = Field(alias="intentDigest")
    intent_reference: VersionPinnedBlobReference = Field(alias="intentReference")
    attestation_reference: VersionPinnedBlobReference = Field(alias="attestationReference")
    reference_digest: Sha256Digest = Field(alias="referenceDigest")

    @model_validator(mode="after")
    def validate_reference(
        self,
    ) -> PublishedMonitoringIntentAssetReference:
        prefix = f"monitoring-intent/{self.intent_id}"
        if (
            self.intent_reference.name != f"{prefix}/intent.json"
            or self.attestation_reference.name != f"{prefix}/attestation.json"
        ):
            raise ValueError("monitoring intent asset paths are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"reference_id", "reference_digest"},
        )
        if self.reference_digest != expected:
            raise ValueError("referenceDigest does not bind monitoring assets")
        if self.reference_id != f"monitoring-intent-asset-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("referenceId is not digest-bound")
        return self


def _validate_control_scopes(
    context: PublishedRuntimeContextBinding,
    controls: tuple[PublishedMonitoringIntentControl, ...],
) -> None:
    paths_by_id = {path.path_id: path for path in context.dependency_paths}
    for control in controls:
        selected_paths = tuple(paths_by_id[path_id] for path_id in control.scope.path_ids)
        governed_resources = {
            resource_id for path in selected_paths for resource_id in path.resource_ids
        }
        governed_roles = {
            role_ref
            for path in selected_paths
            for role_ref in (path.source_role_ref, path.target_role_ref)
        }
        if not set(control.scope.resource_ids).issubset(governed_resources) or not set(
            control.scope.role_refs
        ).issubset(governed_roles):
            raise ValueError("monitoring control scope is outside selected published paths")
        if isinstance(
            control.signal, LogQueryMonitoringSignal
        ) and control.signal.query_target_resource_id.casefold() not in set(
            control.scope.resource_ids
        ):
            raise ValueError("log query target is outside the reviewed control scope")
        if (
            isinstance(control.signal, MetricMonitoringSignal)
            and len(control.scope.resource_ids) != 1
        ):
            raise ValueError("metric monitoring controls require exactly one resource")


def build_published_monitoring_intent(
    context: PublishedRuntimeContextBinding,
    *,
    environment: MonitoringEnvironment,
    controls: tuple[PublishedMonitoringIntentControl, ...],
    expected_active_context_authority_digest: Sha256Digest,
) -> PublishedMonitoringIntent:
    if type(context) is not PublishedRuntimeContextBinding:
        raise TypeError("monitoring intent requires exact PublishedRuntimeContextBinding")
    context = PublishedRuntimeContextBinding.model_validate_json(
        context.model_dump_json(by_alias=True)
    )
    controls = tuple(
        PublishedMonitoringIntentControl.model_validate_json(item.model_dump_json(by_alias=True))
        for item in controls
    )
    authority = context.publication_authority
    if authority.authority_digest != expected_active_context_authority_digest:
        raise ValueError("published context authority is not currently active")
    if environment != context.profile_id.casefold():
        raise ValueError("monitoring environment must match the published profile ID")
    path_ids = {path.path_id for path in context.dependency_paths}
    if any(not set(control.scope.path_ids).issubset(path_ids) for control in controls):
        raise ValueError("monitoring control references an unknown path")
    _validate_control_scopes(context, controls)
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028PublishedMonitoringIntent.v1",
        "environment": environment,
        "workloadId": context.workload_id,
        "manifestId": context.manifest_id,
        "manifestVersion": context.manifest_version,
        "manifestDigest": context.manifest_digest,
        "profileId": context.profile_id,
        "resolvedProfileDigest": context.resolved_profile_digest,
        "dependencyGraphDigest": context.dependency_graph_digest,
        "contextBindingDigest": context.binding_digest,
        "contextAuthorityId": authority.authority_id,
        "contextAuthorityDigest": authority.authority_digest,
        "contextAuthorityReference": context.publication_authority_reference,
        "publicationRecordDigest": authority.publication_record_digest,
        "auditHeadDigest": authority.audit_head_digest,
        "publishedAt": authority.published_at,
        "controls": tuple(sorted(controls, key=lambda item: item.control_id)),
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedMonitoringIntent.model_validate(
        {
            **payload,
            "intentId": (f"monitoring-intent-{digest.removeprefix('sha256:')[:32]}"),
            "intentDigest": digest,
        }
    )


def validate_published_monitoring_intent_context(
    intent: PublishedMonitoringIntent,
    context: PublishedRuntimeContextBinding,
    *,
    expected_active_context_authority_digest: Sha256Digest,
) -> None:
    intent = PublishedMonitoringIntent.model_validate_json(intent.model_dump_json(by_alias=True))
    if type(context) is not PublishedRuntimeContextBinding:
        raise TypeError("monitoring intent requires exact PublishedRuntimeContextBinding")
    context = PublishedRuntimeContextBinding.model_validate_json(
        context.model_dump_json(by_alias=True)
    )
    authority = context.publication_authority
    if (
        authority.authority_digest != expected_active_context_authority_digest
        or intent.environment != context.profile_id.casefold()
        or intent.workload_id != context.workload_id
        or intent.manifest_id != context.manifest_id
        or intent.manifest_version != context.manifest_version
        or intent.manifest_digest != context.manifest_digest
        or intent.profile_id != context.profile_id
        or intent.resolved_profile_digest != context.resolved_profile_digest
        or intent.dependency_graph_digest != context.dependency_graph_digest
        or intent.context_binding_digest != context.binding_digest
        or intent.context_authority_id != authority.authority_id
        or intent.context_authority_digest != authority.authority_digest
        or intent.context_authority_reference != context.publication_authority_reference
        or intent.publication_record_digest != authority.publication_record_digest
        or intent.audit_head_digest != authority.audit_head_digest
        or intent.published_at != authority.published_at
    ):
        raise ValueError("published monitoring intent does not match exact active context")
    path_ids = {path.path_id for path in context.dependency_paths}
    if any(not set(control.scope.path_ids).issubset(path_ids) for control in intent.controls):
        raise ValueError("monitoring control references an unknown path")
    _validate_control_scopes(context, intent.controls)


def validate_monitoring_intent_activation_eligible(
    intent: PublishedMonitoringIntent,
    context: PublishedRuntimeContextBinding,
    *,
    expected_active_context_authority_digest: Sha256Digest,
) -> None:
    validate_published_monitoring_intent_context(
        intent,
        context,
        expected_active_context_authority_digest=(expected_active_context_authority_digest),
    )
    intent = PublishedMonitoringIntent.model_validate_json(intent.model_dump_json(by_alias=True))
    if any(item.dry_run_only for item in intent.controls):
        raise ValueError("dry-run-only monitoring intent cannot be activated")


def validate_published_monitoring_intent_assets(
    reference: PublishedMonitoringIntentAssetReference,
    intent: PublishedMonitoringIntent,
    attestation: PublishedMonitoringIntentAttestation,
    *,
    trusted_key_id: str,
    signature_verifier: Callable[[bytes, str], bool],
) -> None:
    reference = PublishedMonitoringIntentAssetReference.model_validate_json(
        reference.model_dump_json(by_alias=True)
    )
    intent = PublishedMonitoringIntent.model_validate_json(intent.model_dump_json(by_alias=True))
    attestation = PublishedMonitoringIntentAttestation.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    preimage = intent.canonical_bytes()
    if (
        reference.intent_id != intent.intent_id
        or reference.intent_digest != intent.intent_digest
        or reference.intent_reference.content_digest != sha256_hex(preimage)
        or attestation.intent_id != intent.intent_id
        or attestation.intent_digest != intent.intent_digest
        or attestation.key_vault_key_id != trusted_key_id
        or attestation.signed_preimage_digest != sha256_hex(preimage)
        or signature_verifier(preimage, attestation.detached_signature) is not True
        or reference.attestation_reference.content_digest
        != sha256_hex(attestation.canonical_bytes())
    ):
        raise ValueError("published monitoring intent assets do not match exact content")


__all__ = [
    "MAX_PUBLISHED_MONITORING_INTENT_BYTES",
    "ActivityLogMonitoringSignal",
    "LogQueryMonitoringSignal",
    "MetricMonitoringSignal",
    "MonitoringAggregation",
    "MonitoringComparisonOperator",
    "MonitoringEnvironment",
    "MonitoringIntentDimension",
    "MonitoringIntentScope",
    "MonitoringMissingDataBehavior",
    "MonitoringSeverity",
    "MonitoringSignal",
    "MonitoringUnit",
    "PublishedMonitoringIntent",
    "PublishedMonitoringIntentAssetReference",
    "PublishedMonitoringIntentAttestation",
    "PublishedMonitoringIntentControl",
    "ResourceHealthMonitoringSignal",
    "build_published_monitoring_intent",
    "validate_monitoring_intent_activation_eligible",
    "validate_published_monitoring_intent_context",
    "validate_published_monitoring_intent_assets",
]
