from __future__ import annotations

import base64
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from athena_context.contracts import (
    AthenaBaseModel,
    CollectorIdentityEvidence,
    EvidenceGapRecord,
    EvidenceRecord,
    SuccessResponseCollectorAttempt,
    VersionPinnedBlobReference,
    compute_artifact_digest,
    compute_response_envelope_digest,
)
from athena_context.evidence import CollectedEvidence, EvidenceTransportRequest, ValidatedEnvelope

COLLECTED_EVIDENCE_HANDOFF_BASE64_PREFIX = (
    "ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64="
)
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_MAX_HANDOFF_BYTES = 16 * 1024


class Wc013CollectedEvidenceArtifact(AthenaBaseModel):
    """Versioned collector output consumed by a context-only Athena job."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    schema_version: Literal["athena.wc013CollectedEvidence.v1"] = Field(
        alias="schemaVersion"
    )
    plan_digest: str = Field(alias="planDigest", pattern=_DIGEST_PATTERN)
    collection_request: EvidenceTransportRequest = Field(alias="collectionRequest")
    collector_attempt: SuccessResponseCollectorAttempt = Field(alias="collectorAttempt")
    evidence_records: tuple[EvidenceRecord, ...] = Field(
        alias="evidenceRecords",
        min_length=1,
        max_length=500,
    )
    collector_identity_evidence: CollectorIdentityEvidence = Field(
        alias="collectorIdentityEvidence"
    )
    source_envelope: dict[str, JsonValue] = Field(alias="sourceEnvelope")

    @model_validator(mode="after")
    def validate_collector_output(self) -> Wc013CollectedEvidenceArtifact:
        request = self.collection_request
        attempt = self.collector_attempt
        identity = self.collector_identity_evidence
        if (
            attempt.attempt_id != request.attempt_id
            or attempt.request_digest != request.request_digest
            or attempt.tool_name != request.tool_name
            or attempt.tool_version != request.tool_version
        ):
            raise ValueError("collector attempt does not match its exact request")
        if attempt.response_digest != compute_response_envelope_digest(
            self.source_envelope
        ):
            raise ValueError("collector source envelope digest does not match the attempt")
        if (
            attempt.collector_identity_evidence_ref
            != identity.identity_evidence_id
            or any(
                record.collector_identity_evidence_ref
                != identity.identity_evidence_id
                for record in self.evidence_records
            )
            or any(isinstance(record, EvidenceGapRecord) for record in self.evidence_records)
        ):
            raise ValueError(
                "collector output does not bind one successful evidence identity"
            )
        return self

    def collected_evidence(self) -> CollectedEvidence:
        return CollectedEvidence(
            request=self.collection_request,
            collector_attempt=self.collector_attempt,
            evidence_records=self.evidence_records,
            collector_identity_evidence=self.collector_identity_evidence,
            envelope=ValidatedEnvelope.from_payload(
                kind="response",
                digest=self.collector_attempt.response_digest,
                payload=dict(self.source_envelope),
            ),
        )


class Wc013CollectedEvidenceHandoff(AthenaBaseModel):
    """Bounded reference emitted by the collector for one exact evaluated plan."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    schema_version: Literal["athena.wc013CollectedEvidenceHandoff.v1"] = Field(
        alias="schemaVersion"
    )
    plan_digest: str = Field(alias="planDigest", pattern=_DIGEST_PATTERN)
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=128)
    evidence: VersionPinnedBlobReference

    @model_validator(mode="after")
    def validate_reference_name(self) -> Wc013CollectedEvidenceHandoff:
        expected_name = f"wc013-evidence/{self.attempt_id}/collected-evidence.json"
        if self.evidence.name != expected_name:
            raise ValueError("collected evidence reference name is not deterministic")
        return self

    def base64(self) -> str:
        return base64.b64encode(self.canonical_json().encode("utf-8")).decode("ascii")


def build_collected_evidence_artifact(
    *,
    plan_digest: str,
    collected: CollectedEvidence,
) -> Wc013CollectedEvidenceArtifact:
    if (
        collected.envelope is None
        or collected.envelope.kind != "response"
        or not isinstance(
            collected.collector_attempt,
            SuccessResponseCollectorAttempt,
        )
    ):
        raise ValueError("collector must produce one validated success response envelope")
    return Wc013CollectedEvidenceArtifact(
        schemaVersion="athena.wc013CollectedEvidence.v1",
        planDigest=plan_digest,
        collectionRequest=collected.request,
        collectorAttempt=collected.collector_attempt,
        evidenceRecords=collected.evidence_records,
        collectorIdentityEvidence=collected.collector_identity_evidence,
        sourceEnvelope=cast(dict[str, JsonValue], collected.envelope.payload()),
    )


def wc013_plan_digest(plan: BaseModel) -> str:
    return compute_artifact_digest(
        plan.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def parse_collected_evidence_handoff(
    value: str,
) -> Wc013CollectedEvidenceHandoff:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > _MAX_HANDOFF_BYTES * 2
    ):
        raise ValueError("collected evidence handoff is missing or invalid")
    try:
        payload = base64.b64decode(value, validate=True)
        if not payload or len(payload) > _MAX_HANDOFF_BYTES:
            raise ValueError("collected evidence handoff is empty or oversized")
        return Wc013CollectedEvidenceHandoff.model_validate_json(payload)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ValueError("collected evidence handoff failed closed validation") from exc


__all__ = [
    "COLLECTED_EVIDENCE_HANDOFF_BASE64_PREFIX",
    "Wc013CollectedEvidenceArtifact",
    "Wc013CollectedEvidenceHandoff",
    "build_collected_evidence_artifact",
    "parse_collected_evidence_handoff",
    "wc013_plan_digest",
]
