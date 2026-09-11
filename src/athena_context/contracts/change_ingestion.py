from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import canonicalize_json, sha256_hex
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

ChangeEvidenceSource = Literal["azureEventGrid", "azureResourceGraphChangeHistory"]
ChangeOperation = Literal["create", "update", "createOrUpdate", "delete", "action"]
ChangeResult = Literal["succeeded", "failed", "unknown"]
ActorKind = Literal["user", "application", "managedIdentity", "system", "unknown"]
DeploymentSourceKind = Literal[
    "azurePortal",
    "automation",
    "resourceManager",
    "policy",
    "unknown",
]
PolicyEnforcementMode = Literal["default", "doNotEnforce", "unknown"]
DeadLetterSubqueue = Literal["deadLetter", "transferDeadLetter"]

_AZURE_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourcegroups/"
    r"(?P<resource_group>[a-z0-9_().-]{1,90})/providers/"
    r"(?P<provider>[a-z0-9.]{1,128})/"
    r"(?P<resource_path>(?:[a-z0-9.]{1,128}/[a-z0-9_.-]{1,260})"
    r"(?:/[a-z0-9.]{1,128}/[a-z0-9_.-]{1,260})*)$"
)
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_EVIDENCE_REF_PATTERN = r"^[a-z][a-z0-9-]{0,31}:sha256:[a-f0-9]{64}$"
_PROPERTY_PATH_PATTERN = r"^[A-Za-z][A-Za-z0-9_.\[\]-]{0,511}$"


def _canonical_azure_resource_id(value: str) -> str:
    if (
        type(value) is not str
        or len(value) > 2048
        or "\\" in value
        or "%" in value
        or value != value.strip()
    ):
        raise ValueError("resource ID must be a bounded canonical Azure resource ID")
    normalized = value.lower().rstrip("/")
    if _AZURE_RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
        raise ValueError("resource ID must be one exact Azure resource ID")
    return normalized


def _resource_type_from_azure_resource_id(resource_id: str) -> str:
    segments = resource_id.split("/")
    return f"{segments[6]}/{'/'.join(segments[7::2])}"


def _require_utc_timestamp(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use UTC")
    if value.microsecond % 1000:
        raise ValueError("timestamp precision must be exactly representable in milliseconds")
    return value


def _opaque_ref(prefix: str, value: str) -> str:
    return f"{prefix}:sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _delivery_key(source_system: ChangeEvidenceSource, source_record_ref: str) -> str:
    return sha256_hex(f"{source_system}\0{source_record_ref}".encode())


def _change_key(
    *,
    target_resource_id: str,
    operation: ChangeOperation,
    result: ChangeResult,
    correlation_id: str,
) -> str:
    operation_family = "write" if operation in {"create", "update", "createOrUpdate"} else operation
    return sha256_hex(
        "\0".join((target_resource_id, operation_family, result, correlation_id.lower())).encode(
            "utf-8"
        )
    )


class _StrictChangeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (
            canonicalize_json(self.model_dump(mode="json", by_alias=True, exclude_none=True)) + "\n"
        ).encode("utf-8")


class ApprovedChangeScope(_StrictChangeModel):
    """Deployment-owned allowlist for one workload's Azure change evidence."""

    schema_version: Literal["athena.approvedChangeScope.v1"] = Field(alias="schemaVersion")
    subscription_id: str = Field(alias="subscriptionId")
    resource_group_name: str = Field(
        alias="resourceGroupName",
        min_length=1,
        max_length=90,
    )
    approved_resource_ids: tuple[str, ...] = Field(
        alias="approvedResourceIds",
        min_length=1,
        max_length=128,
    )

    @field_validator("subscription_id")
    @classmethod
    def validate_subscription_id(cls, value: str) -> str:
        try:
            return str(UUID(value)).lower()
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("subscriptionId must be a UUID") from exc

    @field_validator("resource_group_name")
    @classmethod
    def validate_resource_group_name(cls, value: str) -> str:
        if (
            type(value) is not str
            or value != value.strip()
            or re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", value) is None
            or value.endswith(".")
        ):
            raise ValueError("resourceGroupName is invalid")
        return value.lower()

    @field_validator("approved_resource_ids")
    @classmethod
    def normalize_approved_resource_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_azure_resource_id(resource_id) for resource_id in value)
        if normalized != tuple(sorted(normalized)) or len(set(normalized)) != len(normalized):
            raise ValueError(
                "approvedResourceIds must be unique deterministic ordinal resource IDs"
            )
        return normalized

    @model_validator(mode="after")
    def validate_approved_scope(self) -> ApprovedChangeScope:
        for resource_id in self.approved_resource_ids:
            match = _AZURE_RESOURCE_ID_PATTERN.fullmatch(resource_id)
            assert match is not None
            if (
                match.group("subscription") != self.subscription_id
                or match.group("resource_group") != self.resource_group_name
            ):
                raise ValueError("approvedResourceIds must belong to the exact approved scope")
        return self

    def contains(self, resource_id: str) -> bool:
        try:
            normalized = _canonical_azure_resource_id(resource_id)
        except ValueError:
            return False
        return normalized in self.approved_resource_ids


class ChangeActor(_StrictChangeModel):
    kind: ActorKind
    reference: str = Field(alias="reference", pattern=_EVIDENCE_REF_PATTERN)


class DeploymentSource(_StrictChangeModel):
    kind: DeploymentSourceKind
    reference: str = Field(alias="reference", pattern=_EVIDENCE_REF_PATTERN)


class ChangePolicyContext(_StrictChangeModel):
    assignment_reference: str | None = Field(
        default=None,
        alias="assignmentReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    definition_reference: str | None = Field(
        default=None,
        alias="definitionReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    enforcement_mode: PolicyEnforcementMode = Field(
        alias="enforcementMode",
    )


class ChangedProperty(_StrictChangeModel):
    path: str = Field(min_length=1, max_length=512, pattern=_PROPERTY_PATH_PATTERN)
    before_evidence_reference: str | None = Field(
        default=None,
        alias="beforeEvidenceReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    after_evidence_reference: str | None = Field(
        default=None,
        alias="afterEvidenceReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    is_truncated: bool = Field(alias="isTruncated")

    @model_validator(mode="after")
    def validate_evidence_reference(self) -> ChangedProperty:
        if self.before_evidence_reference is None and self.after_evidence_reference is None:
            raise ValueError("changed property must reference before or after evidence")
        return self


class NormalizedChangeEvidence(_StrictChangeModel):
    schema_version: Literal["athena.changeEvidence.normalized.v1"] = Field(alias="schemaVersion")
    evidence_id: str = Field(alias="evidenceId", pattern=r"^chg-[a-f0-9]{12}$")
    deduplication_key: str = Field(
        alias="deduplicationKey",
        pattern=_SHA256_PATTERN,
    )
    change_key: str = Field(alias="changeKey", pattern=_SHA256_PATTERN)
    source_system: ChangeEvidenceSource = Field(alias="sourceSystem")
    source_record_reference: str = Field(
        alias="sourceRecordReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    source_digest: str = Field(alias="sourceDigest", pattern=_SHA256_PATTERN)
    target_resource_id: str = Field(
        alias="targetResourceId",
        min_length=1,
        max_length=2048,
    )
    target_resource_type: str = Field(
        alias="targetResourceType",
        min_length=1,
        max_length=256,
    )
    operation: ChangeOperation
    operation_name: str = Field(alias="operationName", min_length=1, max_length=256)
    result: ChangeResult
    changed_properties: tuple[ChangedProperty, ...] = Field(
        alias="changedProperties",
        max_length=64,
    )
    actor: ChangeActor
    occurred_at: datetime = Field(alias="occurredAt")
    received_at: datetime = Field(alias="receivedAt")
    correlation_id: str = Field(alias="correlationId")
    deployment_source: DeploymentSource = Field(alias="deploymentSource")
    policy_context: ChangePolicyContext = Field(alias="policyContext")
    before_evidence_reference: str | None = Field(
        default=None,
        alias="beforeEvidenceReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    after_evidence_reference: str | None = Field(
        default=None,
        alias="afterEvidenceReference",
        pattern=_EVIDENCE_REF_PATTERN,
    )

    @field_validator("target_resource_id")
    @classmethod
    def validate_resource_id(cls, value: str) -> str:
        return _canonical_azure_resource_id(value)

    @field_validator("target_resource_type")
    @classmethod
    def validate_resource_type(cls, value: str) -> str:
        if (
            type(value) is not str
            or value != value.strip()
            or re.fullmatch(
                r"Microsoft\.[A-Za-z0-9.]+/[A-Za-z0-9.]+(?:/[A-Za-z0-9.]+)*",
                value,
                flags=re.IGNORECASE,
            )
            is None
        ):
            raise ValueError("targetResourceType is invalid")
        return value

    @field_validator("operation_name")
    @classmethod
    def normalize_operation_name(cls, value: str) -> str:
        if type(value) is not str or value != value.strip():
            raise ValueError("operationName is invalid")
        return value.lower()

    @field_validator("occurred_at", "received_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _require_utc_timestamp(value)

    @field_validator("correlation_id")
    @classmethod
    def normalize_correlation_id(cls, value: str) -> str:
        try:
            return str(UUID(value)).lower()
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("correlationId must be a UUID") from exc

    @model_validator(mode="after")
    def validate_deterministic_binding(self) -> NormalizedChangeEvidence:
        expected_type = _resource_type_from_azure_resource_id(self.target_resource_id)
        if expected_type.casefold() != self.target_resource_type.casefold():
            raise ValueError("targetResourceType does not match targetResourceId")
        if self.received_at < self.occurred_at:
            raise ValueError("receivedAt must not precede occurredAt")
        paths = [item.path for item in self.changed_properties]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("changedProperties must have uniquely sorted paths")
        normalized_paths = [path.casefold() for path in paths]
        if len(normalized_paths) != len(set(normalized_paths)):
            raise ValueError(
                "changedProperties must be unique case-insensitive paths"
            )
        expected_deduplication_key = _delivery_key(
            self.source_system,
            self.source_record_reference,
        )
        expected_change_key = _change_key(
            target_resource_id=self.target_resource_id,
            operation=self.operation,
            result=self.result,
            correlation_id=self.correlation_id,
        )
        expected_evidence_id = (
            "chg-" + hashlib.sha256(expected_deduplication_key.encode("utf-8")).hexdigest()[:12]
        )
        if (
            self.deduplication_key != expected_deduplication_key
            or self.change_key != expected_change_key
            or self.evidence_id != expected_evidence_id
        ):
            raise ValueError("change evidence is not deterministically bound")
        return self


class ChangeEvidenceAttestation(_StrictChangeModel):
    schema_version: Literal["athena.changeEvidenceAttestation.v1"] = Field(alias="schemaVersion")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: str = Field(
        alias="signedPreimageDigest",
        pattern=_SHA256_PATTERN,
    )
    signature: str = Field(min_length=1, max_length=8192)


class ChangeEvidenceArtifact(_StrictChangeModel):
    schema_version: Literal["athena.changeEvidenceArtifact.v1"] = Field(alias="schemaVersion")
    evidence: NormalizedChangeEvidence
    attestation: ChangeEvidenceAttestation

    @model_validator(mode="after")
    def validate_attestation_binding(self) -> ChangeEvidenceArtifact:
        preimage = change_evidence_attestation_preimage(self.evidence)
        if self.attestation.signed_preimage_digest != sha256_hex(
            canonicalize_json(preimage).encode("utf-8")
        ):
            raise ValueError("change evidence attestation does not bind the artifact")
        return self


class ChangeEvidencePersistenceHandoff(_StrictChangeModel):
    schema_version: Literal["athena.changeEvidencePersistenceHandoff.v1"] = Field(
        alias="schemaVersion"
    )
    evidence_id: str = Field(alias="evidenceId", pattern=r"^chg-[a-f0-9]{12}$")
    deduplication_key: str = Field(
        alias="deduplicationKey",
        pattern=_SHA256_PATTERN,
    )
    change_key: str = Field(alias="changeKey", pattern=_SHA256_PATTERN)
    artifact: VersionPinnedBlobReference

    @model_validator(mode="after")
    def validate_artifact_reference(self) -> ChangeEvidencePersistenceHandoff:
        digest = self.deduplication_key.removeprefix("sha256:")
        if (
            self.artifact.name != f"change-evidence/{digest}/evidence.json"
            or self.evidence_id
            != "chg-" + hashlib.sha256(self.deduplication_key.encode("utf-8")).hexdigest()[:12]
        ):
            raise ValueError("change evidence handoff is not deterministically bound")
        return self


class ChangeDeliveryFailureReceipt(_StrictChangeModel):
    """Non-authoritative proof that a raw poison delivery was durably discarded."""

    schema_version: Literal["athena.changeDeliveryFailureReceipt.v1"] = Field(
        alias="schemaVersion"
    )
    failure_id: str = Field(
        alias="failureId",
        pattern=r"^chg-failure-[a-f0-9]{12}$",
    )
    source_message_digest: str = Field(
        alias="sourceMessageDigest",
        pattern=_SHA256_PATTERN,
    )
    dead_letter_subqueue: DeadLetterSubqueue = Field(alias="deadLetterSubqueue")
    disposition: Literal["rawMessageCompletedAfterReceipt"]

    @model_validator(mode="after")
    def validate_failure_id(self) -> ChangeDeliveryFailureReceipt:
        expected = (
            "chg-failure-"
            + hashlib.sha256(
                f"{self.dead_letter_subqueue}\0{self.source_message_digest}".encode()
            ).hexdigest()[:12]
        )
        if self.failure_id != expected:
            raise ValueError("change delivery failure receipt is not deterministically bound")
        return self


def change_evidence_attestation_preimage(
    evidence: NormalizedChangeEvidence,
) -> dict[str, object]:
    return {
        "domain": "athena.changeEvidenceArtifact.v1",
        "evidence": evidence.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    }


__all__ = [
    "ActorKind",
    "ApprovedChangeScope",
    "ChangeActor",
    "ChangeEvidenceArtifact",
    "ChangeEvidenceAttestation",
    "ChangeDeliveryFailureReceipt",
    "ChangeEvidencePersistenceHandoff",
    "ChangeEvidenceSource",
    "ChangeOperation",
    "ChangePolicyContext",
    "ChangeResult",
    "ChangedProperty",
    "DeploymentSource",
    "DeploymentSourceKind",
    "DeadLetterSubqueue",
    "NormalizedChangeEvidence",
    "PolicyEnforcementMode",
    "change_evidence_attestation_preimage",
]
