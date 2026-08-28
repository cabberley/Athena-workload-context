from __future__ import annotations

import base64
import json
from typing import Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from athena_context.api.evaluation_domain import VerifiedWc008DeploymentConfiguration
from athena_context.api.evaluation_ports import (
    seal_mcp_transport_configuration,
    sealed_mcp_transport_configuration_primitives,
)
from athena_context.artifacts import MAX_ARTIFACT_TRANSFER_BYTES
from athena_context.contracts import (
    AthenaBaseModel,
    CollectorIdentityEvidence,
    EvidenceGapRecord,
    EvidenceRecord,
    SuccessResponseCollectorAttempt,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    compute_response_envelope_digest,
)
from athena_context.evidence import CollectedEvidence, EvidenceTransportRequest, ValidatedEnvelope
from athena_context.evidence.models import MAX_RESPONSE_BYTES, MAX_RESPONSE_ITEMS

COLLECTED_EVIDENCE_HANDOFF_BASE64_PREFIX = (
    "ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64="
)
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_MAX_HANDOFF_BYTES = 16 * 1024
MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES = MAX_ARTIFACT_TRANSFER_BYTES
_MAX_PROJECTED_RECORD_OVERHEAD_BYTES = 8 * 1024
_MAX_FIXED_ARTIFACT_OVERHEAD_BYTES = 1024 * 1024
_REQUIRED_COLLECTED_EVIDENCE_CAPACITY = (
    (2 * MAX_RESPONSE_BYTES)
    + (MAX_RESPONSE_ITEMS * _MAX_PROJECTED_RECORD_OVERHEAD_BYTES)
    + _MAX_FIXED_ARTIFACT_OVERHEAD_BYTES
)
if MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES < _REQUIRED_COLLECTED_EVIDENCE_CAPACITY:
    raise RuntimeError("collected evidence artifact capacity is below its contract bound")


class Wc013CollectedEvidenceTransportBinding(AthenaBaseModel):
    """Exact reviewed WC-008 transport used by the isolated collector."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    assertion_digest: str = Field(alias="assertionDigest", pattern=_DIGEST_PATTERN)
    sealed_transport_digest: str = Field(
        alias="sealedTransportDigest",
        pattern=_DIGEST_PATTERN,
    )


class Wc013CollectedEvidenceAttestation(AthenaBaseModel):
    """Detached RSA signature over the artifact and its WC-008 transport binding."""

    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    trust_anchor_ref: str = Field(alias="trustAnchorRef", min_length=1, max_length=2048)
    signed_preimage_digest: str = Field(
        alias="signedPreimageDigest",
        pattern=_DIGEST_PATTERN,
    )
    signature: str = Field(min_length=1, max_length=8192)

    @field_validator("signature")
    @classmethod
    def validate_signature_encoding(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("collector artifact signature must be standard base64") from exc
        if not decoded:
            raise ValueError("collector artifact signature must not be empty")
        return value


class Wc013CollectedEvidenceArtifactSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...


class Wc013CollectedEvidenceArtifact(AthenaBaseModel):
    """Versioned collector output consumed by a context-only Athena job."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    schema_version: Literal["athena.wc013CollectedEvidence.v2"] = Field(
        alias="schemaVersion"
    )
    plan_digest: str = Field(alias="planDigest", pattern=_DIGEST_PATTERN)
    transport_binding: Wc013CollectedEvidenceTransportBinding = Field(
        alias="transportBinding"
    )
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
    collector_attestation: Wc013CollectedEvidenceAttestation = Field(
        alias="collectorAttestation"
    )

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
        if (
            self.collector_attestation.signed_preimage_digest
            != compute_artifact_digest(_collected_evidence_attestation_preimage(self))
        ):
            raise ValueError(
                "collector artifact attestation digest does not bind the exact artifact"
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

    schema_version: Literal["athena.wc013CollectedEvidenceHandoff.v2"] = Field(
        alias="schemaVersion"
    )
    plan_digest: str = Field(alias="planDigest", pattern=_DIGEST_PATTERN)
    transport_binding: Wc013CollectedEvidenceTransportBinding = Field(
        alias="transportBinding"
    )
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
    transport_binding: Wc013CollectedEvidenceTransportBinding,
    collected: CollectedEvidence,
    signer: Wc013CollectedEvidenceArtifactSigner,
    trusted_key_anchor: TrustedKeyAnchor,
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
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc013CollectedEvidence.v2",
        "planDigest": plan_digest,
        "transportBinding": transport_binding.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "collectionRequest": collected.request.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "collectorAttempt": collected.collector_attempt.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "evidenceRecords": [
            record.model_dump(mode="json", by_alias=True, exclude_none=True)
            for record in collected.evidence_records
        ],
        "collectorIdentityEvidence": collected.collector_identity_evidence.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "sourceEnvelope": cast(dict[str, JsonValue], collected.envelope.payload()),
    }
    preimage = _collected_evidence_attestation_preimage(payload)
    artifact = Wc013CollectedEvidenceArtifact.model_validate_json(
        canonicalize_json(
            {
                **payload,
                "collectorAttestation": {
                    "signatureAlgorithm": "RS256",
                    "trustAnchorRef": trusted_key_anchor.key_vault_key_id,
                    "signedPreimageDigest": compute_artifact_digest(preimage),
                    "signature": signer.sign_preimage(
                        canonicalize_json(preimage).encode("utf-8")
                    ),
                },
            }
        )
    )
    payload_size = len(artifact.canonical_json().encode("utf-8"))
    if payload_size > MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES:
        raise ValueError(
            "collected evidence artifact exceeds its dedicated bounded capacity"
        )
    return artifact


def _collected_evidence_attestation_preimage(
    artifact: Wc013CollectedEvidenceArtifact | dict[str, object],
) -> dict[str, object]:
    if isinstance(artifact, Wc013CollectedEvidenceArtifact):
        payload = artifact.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"collector_attestation"},
        )
    else:
        payload = artifact
    return {
        "domain": "athena.wc013CollectedEvidence.v2",
        "artifact": payload,
    }


def verify_collected_evidence_artifact_attestation(
    artifact: Wc013CollectedEvidenceArtifact,
    *,
    trusted_key_anchor: TrustedKeyAnchor,
    key_resolver: TrustedKeyResolver,
) -> None:
    attestation = artifact.collector_attestation
    if attestation.trust_anchor_ref != trusted_key_anchor.key_vault_key_id:
        raise ValueError("collector artifact attestation uses an untrusted key")
    record = key_resolver(trusted_key_anchor)
    signed_at = artifact.collector_identity_evidence.ingestion_signature.signed_at
    if (
        record is None
        or not record.enabled
        or record.activated_at > signed_at
        or (record.retired_at is not None and record.retired_at <= signed_at)
        or (record.expires_at is not None and record.expires_at <= signed_at)
        or not isinstance(record.public_key, rsa.RSAPublicKey)
    ):
        raise ValueError("collector artifact attestation key is not trusted")
    preimage = _collected_evidence_attestation_preimage(artifact)
    if attestation.signed_preimage_digest != compute_artifact_digest(preimage):
        raise ValueError("collector artifact attestation digest is invalid")
    try:
        signature = base64.b64decode(attestation.signature, validate=True)
        record.public_key.verify(
            signature,
            canonicalize_json(preimage).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("collector artifact attestation signature is invalid") from exc


def wc013_transport_binding(
    configuration: VerifiedWc008DeploymentConfiguration,
) -> Wc013CollectedEvidenceTransportBinding:
    normalized, sealed = seal_mcp_transport_configuration(configuration)
    configuration_json, endpoint = sealed_mcp_transport_configuration_primitives(
        sealed
    )
    return Wc013CollectedEvidenceTransportBinding(
        assertionDigest=normalized.assertion.assertion_digest,
        sealedTransportDigest=compute_artifact_digest(
            {
                "configuration": json.loads(configuration_json),
                "privateMcpEndpoint": endpoint,
            }
        ),
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
    "MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES",
    "Wc013CollectedEvidenceArtifact",
    "Wc013CollectedEvidenceArtifactSigner",
    "Wc013CollectedEvidenceAttestation",
    "Wc013CollectedEvidenceHandoff",
    "Wc013CollectedEvidenceTransportBinding",
    "build_collected_evidence_artifact",
    "parse_collected_evidence_handoff",
    "verify_collected_evidence_artifact_attestation",
    "wc013_plan_digest",
    "wc013_transport_binding",
]
