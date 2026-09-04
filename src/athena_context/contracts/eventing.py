from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import canonicalize_json

EventLifecycle = Literal["activated", "resolved", "changed", "unknown"]
EventSource = Literal["azureEventGrid", "azureMonitorCommonAlert"]
SignalKind = Literal["activityLog", "resourceHealth", "metricAlert"]
IncidentScenario = Literal[
    "singletonDatabaseFailure",
    "webServerFailure",
    "loadBalancerFailure",
]
IncidentLifecycle = Literal[
    "detected",
    "queued",
    "reassessing",
    "active",
    "recoveryObserved",
    "resolved",
    "failedClosed",
]
WorkloadRole = Literal["database-primary", "web", "load-balancer"]


class _StrictEventModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
    )

    def canonical_bytes(self) -> bytes:
        return (
            canonicalize_json(
                self.model_dump(mode="json", by_alias=True, exclude_none=True)
            )
            + "\n"
        ).encode("utf-8")


class NormalizedMonitorEvent(_StrictEventModel):
    schema_version: Literal["athena.monitorEvent.normalized.v1"] = Field(
        alias="schemaVersion"
    )
    event_id: str = Field(alias="eventId", pattern=r"^evt-[a-f0-9]{12}$")
    deduplication_key: str = Field(
        alias="deduplicationKey", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    source_system: EventSource = Field(alias="sourceSystem")
    signal_kind: SignalKind = Field(alias="signalKind")
    lifecycle: EventLifecycle
    severity: Literal["critical", "warning", "informational", "unknown"]
    subscription_id: str = Field(
        alias="subscriptionId",
        pattern=r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-"
        r"[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
    )
    resource_group_name: str = Field(
        alias="resourceGroupName", min_length=1, max_length=90
    )
    target_resource_id: str = Field(
        alias="targetResourceId", min_length=1, max_length=2048
    )
    target_resource_type: Literal[
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Network/loadBalancers",
    ] = Field(alias="targetResourceType")
    operation_name: str = Field(alias="operationName", min_length=1, max_length=256)
    observed_at: datetime = Field(alias="observedAt")
    received_at: datetime = Field(alias="receivedAt")
    source_digest: str = Field(
        alias="sourceDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )

    @field_validator("target_resource_id")
    @classmethod
    def normalize_resource_id(cls, value: str) -> str:
        if not value.startswith("/subscriptions/") or "\\" in value or "%" in value:
            raise ValueError("targetResourceId must be one canonical Azure resource ID")
        return value.lower()

    @field_validator("observed_at", "received_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError("event timestamps must use UTC")
        return value

    @model_validator(mode="after")
    def validate_freshness_order(self) -> NormalizedMonitorEvent:
        if self.received_at < self.observed_at:
            raise ValueError("receivedAt must not precede observedAt")
        if (self.received_at - self.observed_at).total_seconds() > 600:
            raise ValueError("event is outside the ten-minute reassessment window")
        return self


class ReassessmentRequest(_StrictEventModel):
    schema_version: Literal["athena.incidentReassessmentRequest.v1"] = Field(
        alias="schemaVersion"
    )
    request_id: str = Field(alias="requestId", pattern=r"^reassess-[a-f0-9]{12}$")
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    trigger_event_id: str = Field(
        alias="triggerEventId", pattern=r"^evt-[a-f0-9]{12}$"
    )
    trigger_event: NormalizedMonitorEvent = Field(alias="triggerEvent")
    scenario: IncidentScenario
    workload_role: WorkloadRole = Field(alias="workloadRole")
    target_resource_id: str = Field(alias="targetResourceId", min_length=1, max_length=2048)
    lifecycle: EventLifecycle
    idempotency_key: str = Field(
        alias="idempotencyKey", pattern=r"^wc016-[a-f0-9]{64}$"
    )
    no_auto_remediation: Literal[True] = Field(alias="noAutoRemediation")


class IncidentFinding(_StrictEventModel):
    clause_id: str = Field(alias="clauseId", min_length=1, max_length=128)
    verdict: Literal["pass", "fail", "resolved", "review"]
    summary: str = Field(min_length=1, max_length=512)
    evidence_refs: tuple[str, ...] = Field(
        alias="evidenceRefs", min_length=1, max_length=32
    )


class IncidentState(_StrictEventModel):
    schema_version: Literal["athena.incidentState.v1"] = Field(alias="schemaVersion")
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    scenario: IncidentScenario
    lifecycle: IncidentLifecycle
    workload_role: WorkloadRole = Field(alias="workloadRole")
    detected_at: datetime = Field(alias="detectedAt")
    updated_at: datetime = Field(alias="updatedAt")
    target_binding: str = Field(
        alias="targetBinding", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    availability: Literal["normal", "warning", "critical", "unknown"]
    blast_radius: Literal[
        "none",
        "web-tier",
        "ingress-edge",
        "data-tier",
        "whole-workload",
        "unknown",
    ] = Field(alias="blastRadius")
    operator_attention: Literal["normal", "required", "urgent"] = Field(
        alias="operatorAttention"
    )
    findings: tuple[IncidentFinding, ...] = Field(min_length=1, max_length=32)
    reasoning: tuple[str, ...] = Field(min_length=1, max_length=16)
    notification_status: Literal["notRequired", "pending", "sent", "failed"] = Field(
        alias="notificationStatus"
    )
    result_digest: str = Field(
        alias="resultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    no_auto_remediation: Literal[True] = Field(alias="noAutoRemediation")

    @model_validator(mode="after")
    def validate_lifecycle_claim(self) -> IncidentState:
        if self.updated_at < self.detected_at:
            raise ValueError("updatedAt must not precede detectedAt")
        if self.lifecycle == "active" and self.availability == "normal":
            raise ValueError("active incidents cannot claim normal availability")
        if self.lifecycle == "resolved" and self.availability != "normal":
            raise ValueError("resolved incidents must claim normal availability")
        return self


class IncidentStateAttestation(_StrictEventModel):
    schema_version: Literal["athena.incidentStateAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    result_digest: str = Field(
        alias="resultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    detached_signature: str = Field(
        alias="detachedSignature", pattern=r"^[A-Za-z0-9_-]+$", min_length=1
    )


class VerifiedReassessmentResult(_StrictEventModel):
    schema_version: Literal["athena.incidentReassessmentResult.v1"] = Field(
        alias="schemaVersion"
    )
    request_id: str = Field(alias="requestId", pattern=r"^reassess-[a-f0-9]{12}$")
    snapshot_id: str = Field(alias="snapshotId", min_length=1, max_length=128)
    target_binding: str = Field(
        alias="targetBinding", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    verified_healthy: bool = Field(alias="verifiedHealthy")
    findings: tuple[IncidentFinding, ...] = Field(min_length=1, max_length=32)
    reasoning: tuple[str, ...] = Field(min_length=1, max_length=16)


class IncidentFeedPointer(_StrictEventModel):
    schema_version: Literal["athena.incidentFeed.v1"] = Field(alias="schemaVersion")
    state_path: str = Field(alias="statePath", pattern=r"^\./incidents/[a-z0-9./-]+\.json$")
    state_sha256: str = Field(
        alias="stateSha256", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    attestation_path: str = Field(
        alias="attestationPath", pattern=r"^\./incidents/[a-z0-9./-]+\.json$"
    )
    attestation_sha256: str = Field(
        alias="attestationSha256", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    pointer_attestation_path: str = Field(
        alias="pointerAttestationPath",
        pattern=r"^\./incidents/[a-z0-9./-]+\.json$",
    )
    key_id: str = Field(alias="keyId", min_length=1, max_length=512)
    key_fingerprint: str = Field(
        alias="keyFingerprint", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    published_at: datetime = Field(alias="publishedAt")


class IncidentFeedAttestation(_StrictEventModel):
    schema_version: Literal["athena.incidentFeedAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    pointer_digest: str = Field(
        alias="pointerDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    detached_signature: str = Field(
        alias="detachedSignature", pattern=r"^[A-Za-z0-9_-]+$", min_length=1
    )


__all__ = [
    "EventLifecycle",
    "EventSource",
    "IncidentFeedAttestation",
    "IncidentFeedPointer",
    "IncidentFinding",
    "IncidentLifecycle",
    "IncidentScenario",
    "IncidentState",
    "IncidentStateAttestation",
    "NormalizedMonitorEvent",
    "ReassessmentRequest",
    "SignalKind",
    "WorkloadRole",
    "VerifiedReassessmentResult",
]
