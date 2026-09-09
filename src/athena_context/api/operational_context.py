from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from athena_context.api.domain import (
    Actor,
    ApiModel,
    WorkloadIdentifier,
    ensure_timestamp,
)
from athena_context.contracts import compute_artifact_digest

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_EVIDENCE_REF_PATTERN = r"^[\x21-\x7e]{1,512}$"


def _timestamp_text(value: datetime) -> str:
    return (
        ensure_timestamp(value)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class OperationalEvidenceInventoryItem(ApiModel):
    evidence_ref: str = Field(
        alias="evidenceRef",
        pattern=_EVIDENCE_REF_PATTERN,
    )
    evidence_digest: str = Field(
        alias="evidenceDigest",
        pattern=_DIGEST_PATTERN,
    )


def compute_operational_evidence_inventory_digest(
    inventory: list[OperationalEvidenceInventoryItem],
) -> str:
    payload = [
        {
            "evidenceDigest": item.evidence_digest,
            "evidenceRef": item.evidence_ref,
        }
        for item in sorted(inventory, key=lambda item: item.evidence_ref)
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def compute_operational_content_digest(
    *,
    evidence_source: str,
    confidence: float | None,
    relationships: list[Any],
    findings: list[Any],
) -> str:
    return compute_artifact_digest(
        {
            "schemaVersion": (
                "athena.contextStudio.operationalContent.v1"
            ),
            "evidenceSource": evidence_source,
            "confidence": confidence,
            "relationships": relationships,
            "findings": findings,
        }
    )


def compute_operational_binding_digest(
    *,
    workload_id: str,
    manifest_version: str,
    profile_id: str,
    draft_id: str,
    draft_revision: int,
    manifest_digest: str,
    profile_digest: str,
    snapshot_id: str,
    collected_at: datetime,
    expires_at: datetime,
    evidence_inventory_digest: str,
    content_digest: str,
) -> str:
    payload = {
        "workloadId": workload_id,
        "manifestVersion": manifest_version,
        "profileId": profile_id,
        "draftId": draft_id,
        "draftRevision": draft_revision,
        "manifestDigest": manifest_digest,
        "profileDigest": profile_digest,
        "snapshotId": snapshot_id,
        "collectedAt": _timestamp_text(collected_at),
        "expiresAt": _timestamp_text(expires_at),
        "evidenceInventoryDigest": evidence_inventory_digest,
        "contentDigest": content_digest,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class IssueOperationalContextReceiptCommand(ApiModel):
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    draft_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    snapshot_id: str = Field(pattern=_ID_PATTERN)
    collected_at: AwareDatetime = Field(strict=False)
    expires_at: AwareDatetime = Field(strict=False)
    evidence_inventory: list[OperationalEvidenceInventoryItem] = Field(
        min_length=1,
        max_length=1000,
    )
    evidence_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    binding_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("collected_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return ensure_timestamp(value)

    @model_validator(mode="after")
    def validate_binding(self) -> IssueOperationalContextReceiptCommand:
        references = [item.evidence_ref for item in self.evidence_inventory]
        if len(references) != len(set(references)):
            raise ValueError("operational evidence references must be unique")
        if self.collected_at >= self.expires_at:
            raise ValueError(
                "operational context expiry must follow collection time"
            )
        if (
            compute_operational_evidence_inventory_digest(
                self.evidence_inventory
            )
            != self.evidence_inventory_digest
        ):
            raise ValueError("operational evidence inventory digest is invalid")
        if (
            compute_operational_binding_digest(
                workload_id=self.manifest_id,
                manifest_version=self.manifest_version,
                profile_id=self.profile_id,
                draft_id=self.draft_id,
                draft_revision=self.draft_revision,
                manifest_digest=self.manifest_digest,
                profile_digest=self.profile_digest,
                snapshot_id=self.snapshot_id,
                collected_at=self.collected_at,
                expires_at=self.expires_at,
                evidence_inventory_digest=self.evidence_inventory_digest,
                content_digest=self.content_digest,
            )
            != self.binding_digest
        ):
            raise ValueError("operational context binding digest is invalid")
        return self


class OperationalContextReceipt(ApiModel):
    schema_version: Literal[
        "athena.context-api.operational-context-receipt.v1"
    ] = "athena.context-api.operational-context-receipt.v1"
    receipt_id: str = Field(pattern=_ID_PATTERN)
    issued_by: Actor
    issued_at: AwareDatetime
    manifest_id: WorkloadIdentifier
    manifest_version: str = Field(pattern=_VERSION_PATTERN)
    profile_id: str = Field(pattern=_ID_PATTERN)
    draft_id: str = Field(pattern=_ID_PATTERN)
    draft_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    snapshot_id: str = Field(pattern=_ID_PATTERN)
    collected_at: AwareDatetime
    expires_at: AwareDatetime
    evidence_count: int = Field(ge=1, le=1000)
    evidence_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    binding_digest: str = Field(pattern=_DIGEST_PATTERN)
    receipt_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "collected_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return ensure_timestamp(value)

    @model_validator(mode="after")
    def validate_receipt(self) -> OperationalContextReceipt:
        if not self.collected_at <= self.issued_at < self.expires_at:
            raise ValueError(
                "operational receipt time is outside its evidence validity"
            )
        if self.receipt_id != operational_context_receipt_id(
            self.issued_by,
            manifest_id=self.manifest_id,
            manifest_version=self.manifest_version,
            profile_id=self.profile_id,
            draft_id=self.draft_id,
            draft_revision=self.draft_revision,
            manifest_digest=self.manifest_digest,
            profile_digest=self.profile_digest,
            snapshot_id=self.snapshot_id,
            collected_at=self.collected_at,
            expires_at=self.expires_at,
            evidence_inventory_digest=self.evidence_inventory_digest,
            content_digest=self.content_digest,
            binding_digest=self.binding_digest,
        ):
            raise ValueError("operational receipt identifier is invalid")
        if self.receipt_digest != operational_context_receipt_digest(self):
            raise ValueError("operational receipt digest is invalid")
        return self


def operational_context_receipt_id(
    issuer: Actor,
    *,
    manifest_id: str,
    manifest_version: str,
    profile_id: str,
    draft_id: str,
    draft_revision: int,
    manifest_digest: str,
    profile_digest: str,
    snapshot_id: str,
    collected_at: datetime,
    expires_at: datetime,
    evidence_inventory_digest: str,
    content_digest: str,
    binding_digest: str,
) -> str:
    digest = compute_artifact_digest(
        {
            "schemaVersion": (
                "athena.context-api.operational-context-receipt-id.v1"
            ),
            "issuedBy": issuer.model_dump(mode="json"),
            "manifestId": manifest_id,
            "manifestVersion": manifest_version,
            "profileId": profile_id,
            "draftId": draft_id,
            "draftRevision": draft_revision,
            "manifestDigest": manifest_digest,
            "profileDigest": profile_digest,
            "snapshotId": snapshot_id,
            "collectedAt": _timestamp_text(collected_at),
            "expiresAt": _timestamp_text(expires_at),
            "evidenceInventoryDigest": evidence_inventory_digest,
            "contentDigest": content_digest,
            "bindingDigest": binding_digest,
        }
    )
    return f"operational-{digest.removeprefix('sha256:')[:32]}"


def operational_context_receipt_digest(
    receipt: OperationalContextReceipt,
) -> str:
    return compute_artifact_digest(
        receipt.model_dump(
            mode="json",
            exclude={"receipt_digest"},
        )
    )


def build_operational_context_receipt(
    issuer: Actor,
    command: IssueOperationalContextReceiptCommand,
    *,
    issued_at: datetime,
) -> OperationalContextReceipt:
    normalized_issued_at = ensure_timestamp(issued_at)
    receipt_id = operational_context_receipt_id(
        issuer,
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
        draft_id=command.draft_id,
        draft_revision=command.draft_revision,
        manifest_digest=command.manifest_digest,
        profile_digest=command.profile_digest,
        snapshot_id=command.snapshot_id,
        collected_at=command.collected_at,
        expires_at=command.expires_at,
        evidence_inventory_digest=command.evidence_inventory_digest,
        content_digest=command.content_digest,
        binding_digest=command.binding_digest,
    )
    payload = {
        "schema_version": (
            "athena.context-api.operational-context-receipt.v1"
        ),
        "receipt_id": receipt_id,
        "issued_by": issuer.model_dump(mode="json"),
        "issued_at": normalized_issued_at,
        "manifest_id": command.manifest_id,
        "manifest_version": command.manifest_version,
        "profile_id": command.profile_id,
        "draft_id": command.draft_id,
        "draft_revision": command.draft_revision,
        "manifest_digest": command.manifest_digest,
        "profile_digest": command.profile_digest,
        "snapshot_id": command.snapshot_id,
        "collected_at": command.collected_at,
        "expires_at": command.expires_at,
        "evidence_count": len(command.evidence_inventory),
        "evidence_inventory_digest": command.evidence_inventory_digest,
        "content_digest": command.content_digest,
        "binding_digest": command.binding_digest,
    }
    return OperationalContextReceipt(
        receipt_id=receipt_id,
        issued_by=issuer,
        issued_at=normalized_issued_at,
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
        draft_id=command.draft_id,
        draft_revision=command.draft_revision,
        manifest_digest=command.manifest_digest,
        profile_digest=command.profile_digest,
        snapshot_id=command.snapshot_id,
        collected_at=command.collected_at,
        expires_at=command.expires_at,
        evidence_count=len(command.evidence_inventory),
        evidence_inventory_digest=command.evidence_inventory_digest,
        content_digest=command.content_digest,
        binding_digest=command.binding_digest,
        receipt_digest=compute_artifact_digest(payload),
    )


__all__ = [
    "IssueOperationalContextReceiptCommand",
    "OperationalContextReceipt",
    "OperationalEvidenceInventoryItem",
    "build_operational_context_receipt",
    "compute_operational_binding_digest",
    "compute_operational_content_digest",
    "compute_operational_evidence_inventory_digest",
    "operational_context_receipt_digest",
    "operational_context_receipt_id",
]
