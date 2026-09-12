from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

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
]
WorkloadRole = Literal["database-primary", "web", "load-balancer"]


def _require_utc_timestamp(value: datetime) -> datetime:
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("incident timestamps must use UTC")
    return value


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
        segments = self.target_resource_id.split("/")
        if (
            len(segments) != 9
            or segments[1] != "subscriptions"
            or segments[2] != self.subscription_id.lower()
            or segments[3] != "resourcegroups"
            or segments[4] != self.resource_group_name.lower()
            or segments[5] != "providers"
        ):
            raise ValueError("event scope fields do not match targetResourceId")
        expected_type = "/".join((segments[6], segments[7]))
        if expected_type.casefold() != self.target_resource_type.casefold():
            raise ValueError("event resource type does not match targetResourceId")
        expected_event_id = (
            "evt-"
            + hashlib.sha256(self.deduplication_key.encode("utf-8")).hexdigest()[:12]
        )
        if self.event_id != expected_event_id:
            raise ValueError("eventId does not match deduplicationKey")
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

    @model_validator(mode="after")
    def validate_request_binding(self) -> ReassessmentRequest:
        event = self.trigger_event
        expected_role_and_scenario = {
            "Microsoft.Compute/virtualMachines": {
                "database-primary": "singletonDatabaseFailure",
                "web": "webServerFailure",
            },
            "Microsoft.Network/loadBalancers": {
                "load-balancer": "loadBalancerFailure",
            },
        }
        expected_scenario = expected_role_and_scenario.get(
            event.target_resource_type, {}
        ).get(self.workload_role)
        digest = event.deduplication_key.removeprefix("sha256:")
        expected_incident_id = (
            "inc-"
            + hashlib.sha256(event.target_resource_id.encode("utf-8")).hexdigest()[:12]
        )
        if (
            self.trigger_event_id != event.event_id
            or self.target_resource_id != event.target_resource_id
            or self.lifecycle != event.lifecycle
            or self.request_id != f"reassess-{digest[:12]}"
            or self.incident_id != expected_incident_id
            or self.idempotency_key != f"wc016-{digest}"
            or expected_scenario != self.scenario
        ):
            raise ValueError("reassessment request is not deterministically bound")
        return self


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
    transition_id: str = Field(
        alias="transitionId", pattern=r"^wc016-[a-f0-9]{64}$"
    )
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
    notification_status: Literal["notRequired", "pendingDispatch"] = Field(
        alias="notificationStatus"
    )
    result_digest: str = Field(
        alias="resultDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    no_auto_remediation: Literal[True] = Field(alias="noAutoRemediation")

    @field_validator("detected_at", "updated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_lifecycle_claim(self) -> IncidentState:
        if self.updated_at < self.detected_at:
            raise ValueError("updatedAt must not precede detectedAt")
        if self.lifecycle == "active" and self.availability == "normal":
            raise ValueError("active incidents cannot claim normal availability")
        if self.lifecycle == "resolved" and self.availability != "normal":
            raise ValueError("resolved incidents must claim normal availability")
        if (
            self.lifecycle in {"active", "resolved"}
            and self.notification_status != "pendingDispatch"
        ):
            raise ValueError("notifiable incidents must record pending dispatch")
        if (
            self.lifecycle not in {"active", "resolved"}
            and self.notification_status != "notRequired"
        ):
            raise ValueError("non-notifiable incidents cannot claim outbox enqueue")
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


def incident_state_signature_preimage(state: IncidentState) -> bytes:
    state = IncidentState.model_validate_json(
        state.model_dump_json(by_alias=True)
    )
    unsigned = state.model_dump(
        mode="json",
        by_alias=True,
        exclude={"result_digest"},
    )
    return canonicalize_json(unsigned).encode("utf-8")


class IncidentNotification(_StrictEventModel):
    schema_version: Literal["athena.incidentNotification.v1"] = Field(
        alias="schemaVersion"
    )
    notification_id: str = Field(
        alias="notificationId", pattern=r"^notify-[a-f0-9]{64}$"
    )
    transition_id: str = Field(
        alias="transitionId", pattern=r"^wc016-[a-f0-9]{64}$"
    )
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    lifecycle: Literal["active", "resolved"]
    message: str = Field(min_length=1, max_length=4096)


class VerifiedReassessmentResult(_StrictEventModel):
    schema_version: Literal["athena.incidentReassessmentResult.v1"] = Field(
        alias="schemaVersion"
    )
    request_id: str = Field(alias="requestId", pattern=r"^reassess-[a-f0-9]{12}$")
    snapshot_id: str = Field(alias="snapshotId", min_length=1, max_length=128)
    observed_at: datetime = Field(alias="observedAt")
    target_binding: str = Field(
        alias="targetBinding", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    verified_healthy: bool = Field(alias="verifiedHealthy")
    findings: tuple[IncidentFinding, ...] = Field(min_length=1, max_length=32)
    reasoning: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("observed_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)


class IncidentFeedPointer(_StrictEventModel):
    schema_version: Literal["athena.incidentFeed.v1"] = Field(alias="schemaVersion")
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
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

    @field_validator("published_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_incident_paths(self) -> IncidentFeedPointer:
        prefix = f"./incidents/{self.incident_id}/versions/"
        if not self.state_path.startswith(prefix) or not self.state_path.endswith(
            "/state.json"
        ):
            raise ValueError("incident state path is invalid")
        version = self.state_path[len(prefix) : -len("/state.json")]
        if (
            len(version) != 64
            or any(character not in "0123456789abcdef" for character in version)
            or self.attestation_path != f"{prefix}{version}/attestation.json"
            or self.pointer_attestation_path
            != f"{prefix}{version}/pointer-attestation.json"
        ):
            raise ValueError("incident pointer paths must bind one immutable version")
        return self


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


def incident_pointer_signature_preimage(
    pointer: IncidentFeedPointer,
) -> bytes:
    pointer = IncidentFeedPointer.model_validate_json(
        pointer.model_dump_json(by_alias=True)
    )
    return pointer.canonical_bytes()


class IncidentOccurrenceReceipt(_StrictEventModel):
    schema_version: Literal["athena.incidentOccurrenceReceipt.v1"] = Field(
        alias="schemaVersion"
    )
    occurrence_id: str = Field(
        alias="occurrenceId",
        pattern=r"^incident-occurrence-[a-f0-9]{32}$",
    )
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    transition_id: str = Field(
        alias="transitionId",
        pattern=r"^wc016-[a-f0-9]{64}$",
    )
    state_result_digest: str = Field(
        alias="stateResultDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    state_reference: VersionPinnedBlobReference = Field(
        alias="stateReference"
    )
    state_attestation_reference: VersionPinnedBlobReference = Field(
        alias="stateAttestationReference"
    )
    pointer_reference: VersionPinnedBlobReference = Field(
        alias="pointerReference"
    )
    pointer_attestation_reference: VersionPinnedBlobReference = Field(
        alias="pointerAttestationReference"
    )
    published_at: datetime = Field(alias="publishedAt")
    occurrence_digest: str = Field(
        alias="occurrenceDigest",
        pattern=r"^sha256:[a-f0-9]{64}$",
    )

    @field_validator("published_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_receipt(self) -> IncidentOccurrenceReceipt:
        suffix = self.state_result_digest.removeprefix("sha256:")
        prefix = f"incidents/{self.incident_id}/versions/{suffix}"
        if (
            self.state_reference.name != f"{prefix}/state.json"
            or self.state_attestation_reference.name
            != f"{prefix}/attestation.json"
            or self.pointer_reference.name != f"{prefix}/pointer.json"
            or self.pointer_attestation_reference.name
            != f"{prefix}/pointer-attestation.json"
        ):
            raise ValueError(
                "incident occurrence references do not bind one state version"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"occurrence_id", "occurrence_digest"},
        )
        expected = compute_artifact_digest(payload)
        if self.occurrence_digest != expected:
            raise ValueError(
                "occurrenceDigest does not bind incident occurrence receipt"
            )
        if (
            self.occurrence_id
            != f"incident-occurrence-{expected.removeprefix('sha256:')[:32]}"
        ):
            raise ValueError("occurrenceId is not digest-bound")
        if len(self.canonical_bytes()) > 16 * 1024:
            raise ValueError(
                "incident occurrence receipt exceeds its byte budget"
            )
        return self


def build_incident_occurrence_receipt(
    state: IncidentState,
    state_attestation: IncidentStateAttestation,
    pointer: IncidentFeedPointer,
    pointer_attestation: IncidentFeedAttestation,
    *,
    state_reference: VersionPinnedBlobReference,
    state_attestation_reference: VersionPinnedBlobReference,
    pointer_reference: VersionPinnedBlobReference,
    pointer_attestation_reference: VersionPinnedBlobReference,
) -> IncidentOccurrenceReceipt:
    state = IncidentState.model_validate_json(
        state.model_dump_json(by_alias=True)
    )
    state_attestation = IncidentStateAttestation.model_validate_json(
        state_attestation.model_dump_json(by_alias=True)
    )
    pointer = IncidentFeedPointer.model_validate_json(
        pointer.model_dump_json(by_alias=True)
    )
    pointer_attestation = IncidentFeedAttestation.model_validate_json(
        pointer_attestation.model_dump_json(by_alias=True)
    )
    state_bytes = state.canonical_bytes()
    state_attestation_bytes = state_attestation.canonical_bytes()
    pointer_bytes = pointer.canonical_bytes()
    pointer_attestation_bytes = pointer_attestation.canonical_bytes()
    if (
        state.result_digest != sha256_hex(
            incident_state_signature_preimage(state)
        )
        or state_attestation.result_digest != state.result_digest
        or state_attestation.key_vault_key_id != pointer.key_id
        or pointer_attestation.key_vault_key_id != pointer.key_id
        or pointer.incident_id != state.incident_id
        or pointer.state_sha256 != sha256_hex(state_bytes)
        or pointer.state_path.removeprefix("./")
        != state_reference.name
        or pointer.attestation_sha256
        != sha256_hex(state_attestation_bytes)
        or pointer.attestation_path.removeprefix("./")
        != state_attestation_reference.name
        or pointer.state_path.removesuffix("/state.json").removeprefix("./")
        + "/pointer.json"
        != pointer_reference.name
        or pointer.pointer_attestation_path.removeprefix("./")
        != pointer_attestation_reference.name
        or pointer_attestation.pointer_digest != sha256_hex(pointer_bytes)
        or state_reference.content_digest != sha256_hex(state_bytes)
        or state_attestation_reference.content_digest
        != sha256_hex(state_attestation_bytes)
        or pointer_reference.content_digest != sha256_hex(pointer_bytes)
        or pointer_attestation_reference.content_digest
        != sha256_hex(pointer_attestation_bytes)
        or pointer.published_at < state.updated_at
    ):
        raise ValueError(
            "incident occurrence receipt inputs do not match exact artifacts"
        )
    payload: dict[str, object] = {
        "schemaVersion": "athena.incidentOccurrenceReceipt.v1",
        "incidentId": state.incident_id,
        "transitionId": state.transition_id,
        "stateResultDigest": state.result_digest,
        "stateReference": state_reference,
        "stateAttestationReference": state_attestation_reference,
        "pointerReference": pointer_reference,
        "pointerAttestationReference": pointer_attestation_reference,
        "publishedAt": pointer.published_at,
    }
    digest_payload = {
        key: (
            value.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            if isinstance(value, BaseModel)
            else value
        )
        for key, value in payload.items()
    }
    digest = compute_artifact_digest(digest_payload)
    return IncidentOccurrenceReceipt.model_validate(
        {
            **payload,
            "occurrenceId": (
                f"incident-occurrence-{digest.removeprefix('sha256:')[:32]}"
            ),
            "occurrenceDigest": digest,
        }
    )


class ActiveIncidentEntry(_StrictEventModel):
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    scenario: IncidentScenario
    lifecycle: Literal["active"]
    workload_role: WorkloadRole = Field(alias="workloadRole")
    pointer_path: str = Field(
        alias="pointerPath",
        pattern=(
            r"^\./incidents/inc-[a-f0-9]{12}/versions/"
            r"[a-f0-9]{64}/pointer\.json$"
        ),
    )
    pointer_sha256: str = Field(
        alias="pointerSha256", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    detected_at: datetime = Field(alias="detectedAt")
    updated_at: datetime = Field(alias="updatedAt")

    @field_validator("detected_at", "updated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_pointer_path(self) -> ActiveIncidentEntry:
        if not self.pointer_path.startswith(
            f"./incidents/{self.incident_id}/versions/"
        ):
            raise ValueError("active incident entry pointer path is invalid")
        if self.updated_at < self.detected_at:
            raise ValueError("active incident entry timestamps are invalid")
        return self


class ActiveIncidentIndex(_StrictEventModel):
    schema_version: Literal["athena.activeIncidentIndex.v1"] = Field(
        alias="schemaVersion"
    )
    incidents: tuple[ActiveIncidentEntry, ...] = Field(max_length=64)
    index_attestation_path: str = Field(
        alias="indexAttestationPath",
        pattern=r"^\./incidents/index-attestations/[a-f0-9]{64}\.json$",
    )
    key_id: str = Field(alias="keyId", min_length=1, max_length=512)
    key_fingerprint: str = Field(
        alias="keyFingerprint", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    published_at: datetime = Field(alias="publishedAt")

    @field_validator("published_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_deterministic_order(self) -> ActiveIncidentIndex:
        incident_ids = [entry.incident_id for entry in self.incidents]
        if incident_ids != sorted(incident_ids) or len(incident_ids) != len(
            set(incident_ids)
        ):
            raise ValueError("active incidents must be uniquely sorted by incidentId")
        return self


class ActiveIncidentIndexAttestation(_StrictEventModel):
    schema_version: Literal["athena.activeIncidentIndexAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    index_digest: str = Field(
        alias="indexDigest", pattern=r"^sha256:[a-f0-9]{64}$"
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    detached_signature: str = Field(
        alias="detachedSignature", pattern=r"^[A-Za-z0-9_-]+$", min_length=1
    )


__all__ = [
    "ActiveIncidentEntry",
    "ActiveIncidentIndex",
    "ActiveIncidentIndexAttestation",
    "EventLifecycle",
    "EventSource",
    "IncidentFeedAttestation",
    "IncidentFeedPointer",
    "IncidentFinding",
    "IncidentLifecycle",
    "IncidentNotification",
    "IncidentOccurrenceReceipt",
    "IncidentScenario",
    "IncidentState",
    "IncidentStateAttestation",
    "NormalizedMonitorEvent",
    "ReassessmentRequest",
    "SignalKind",
    "VerifiedReassessmentResult",
    "WorkloadRole",
    "build_incident_occurrence_receipt",
    "incident_pointer_signature_preimage",
    "incident_state_signature_preimage",
]
