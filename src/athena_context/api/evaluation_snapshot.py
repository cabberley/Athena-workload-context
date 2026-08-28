from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from athena_context.contracts import (
    EvidenceSnapshot,
    SnapshotCollector,
    TrustedKeyAnchor,
    canonicalize_json,
    compute_authorized_scopes_digest,
    compute_collector_attempt_set_digest,
    compute_evidence_record_set_digest,
    compute_evidence_reference_set_digest,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    compute_identity_evidence_set_digest,
    compute_snapshot_attestation_preimage_digest,
    snapshot_attestation_preimage,
)
from athena_context.evidence import (
    CollectedEvidence,
    CollectorTrustConfiguration,
    SnapshotReferenceBinding,
)

_PLACEHOLDER_DIGEST = "sha256:" + ("0" * 64)


@dataclass(frozen=True, slots=True)
class SnapshotSigningMaterial:
    snapshot_payload_json: str
    attestation_payload_json: str
    canonical_signing_preimage: bytes
    signing_preimage_digest: str


def _attempt_observed_at(collected: CollectedEvidence) -> datetime:
    attempt = collected.collector_attempt
    if attempt.attempt_type == "successResponse":
        return attempt.response_received_at
    if attempt.attempt_type == "failedResponse":
        return attempt.response_received_at
    if attempt.attempt_type == "timeoutNoResponse":
        return attempt.timed_out_at
    return attempt.observed_at


def prepare_snapshot_signing_material(
    collected: CollectedEvidence,
    *,
    snapshot_id: str,
    trust_configuration: CollectorTrustConfiguration,
    trusted_key_anchor: TrustedKeyAnchor,
    attested_at: datetime,
) -> SnapshotSigningMaterial:
    """Purely assemble canonical snapshot components before calling a signing port."""

    if collected.request.collector_identity_evidence_ref != (
        trust_configuration.collector_identity_evidence_ref
    ):
        raise ValueError("collected evidence identity does not match configured trust")
    if trusted_key_anchor.key_vault_key_id != trust_configuration.trust_anchor_ref:
        raise ValueError("snapshot signing anchor does not match ingestion trust")
    expires_at = collected.request.attempt_started_at + timedelta(
        seconds=collected.request.bounds.freshness_seconds
    )
    latest_signed_component = max(
        _attempt_observed_at(collected),
        collected.collector_identity_evidence.ingestion_signature.signed_at,
    )
    if attested_at < latest_signed_component or attested_at >= expires_at:
        raise ValueError("snapshot attestation time must follow collection and remain fresh")

    references = collected.references(
        SnapshotReferenceBinding(
            snapshotId=snapshot_id,
            snapshotArtifactDigest=_PLACEHOLDER_DIGEST,
            snapshotSemanticDigest=_PLACEHOLDER_DIGEST,
        )
    )
    compatibility: dict[str, object] = {
        "artifactKind": "evidenceSnapshot",
        "schemaVersion": trust_configuration.schema_version,
        "semanticContractVersion": trust_configuration.semantic_contract_version,
        "policyContractVersion": trust_configuration.policy_contract_version,
        "minimumReaderVersion": "1.0.0",
        "requiresCapabilities": [],
        "producedBy": {
            "producerId": "athena.context-api",
            "version": "1.0.0",
        },
        "extensionPolicy": "rejectUnknownDecisionFields",
        "artifactDigest": _PLACEHOLDER_DIGEST,
        "semanticDigest": _PLACEHOLDER_DIGEST,
    }
    payload: dict[str, object] = {
        "snapshotId": snapshot_id,
        "compatibility": compatibility,
        "authorizedScopes": [
            scope.model_dump(mode="json", by_alias=True)
            for scope in collected.request.authorized_scopes
        ],
        "collectedAt": collected.request.attempt_started_at,
        "expiresAt": expires_at,
        "collector": SnapshotCollector(
            collectorType="azureMcpHost",
            collectorIdentityEvidenceRef=(
                trust_configuration.collector_identity_evidence_ref
            ),
            mcpHostId=trust_configuration.mcp_host_id,
            tenantId=trust_configuration.tenant_id,
            trustAnchorRef=trust_configuration.trust_anchor_ref,
            ingestionServiceId=trust_configuration.ingestion_service_id,
            ingestionAudience=trust_configuration.ingestion_audience,
            toolAllowlistDigest=trust_configuration.tool_allowlist_digest,
        ).model_dump(mode="python", by_alias=True),
        "collectorAttempts": [
            collected.collector_attempt.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
        ],
        "evidenceRecords": [
            record.model_dump(mode="python", by_alias=True, exclude_none=True)
            for record in collected.evidence_records
        ],
        "evidenceRefs": [
            reference.model_dump(mode="python", by_alias=True, exclude_none=True)
            for reference in references
        ],
        "identityEvidence": [
            collected.collector_identity_evidence.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
        ],
    }

    semantic_digest = compute_evidence_snapshot_semantic_digest(payload)
    compatibility["semanticDigest"] = semantic_digest
    reference_payloads = payload["evidenceRefs"]
    if not isinstance(reference_payloads, list):
        raise ValueError("snapshot evidence references must be a list")
    for reference in reference_payloads:
        if not isinstance(reference, dict):
            raise ValueError("snapshot evidence references must be objects")
        reference["snapshotSemanticDigest"] = semantic_digest

    artifact_digest = compute_evidence_snapshot_artifact_digest(payload)
    compatibility["artifactDigest"] = artifact_digest
    for reference in reference_payloads:
        reference["snapshotArtifactDigest"] = artifact_digest

    identity_digest = collected.collector_identity_evidence.identity_evidence_digest
    attestation: dict[str, object] = {
        "attestationType": "trustedSnapshotPublication",
        "attestationVersion": "1.0.0",
        "artifactKind": "evidenceSnapshot",
        "schemaVersion": trust_configuration.schema_version,
        "semanticContractVersion": trust_configuration.semantic_contract_version,
        "policyContractVersion": trust_configuration.policy_contract_version,
        "snapshotId": snapshot_id,
        "artifactDigest": artifact_digest,
        "semanticDigest": semantic_digest,
        "identityEvidenceDigests": [identity_digest],
        "identityEvidenceSetDigest": compute_identity_evidence_set_digest(payload),
        "collectedAt": collected.request.attempt_started_at,
        "expiresAt": expires_at,
        "authorizedScopesDigest": compute_authorized_scopes_digest(payload),
        "collectorAttemptSetDigest": compute_collector_attempt_set_digest(payload),
        "evidenceRecordSetDigest": compute_evidence_record_set_digest(payload),
        "evidenceReferenceSetDigest": compute_evidence_reference_set_digest(payload),
        "attestedAt": attested_at,
        "signatureAlgorithm": "RS256",
        "keyVaultKeyId": trusted_key_anchor.key_vault_key_id,
        "keyName": trusted_key_anchor.key_name,
        "keyVersion": trusted_key_anchor.key_version,
        "trustAnchorRef": trusted_key_anchor.key_vault_key_id,
    }
    preimage_digest = compute_snapshot_attestation_preimage_digest(attestation)
    preimage = canonicalize_json(snapshot_attestation_preimage(attestation)).encode("utf-8")
    return SnapshotSigningMaterial(
        snapshot_payload_json=canonicalize_json(payload),
        attestation_payload_json=canonicalize_json(attestation),
        canonical_signing_preimage=preimage,
        signing_preimage_digest=preimage_digest,
    )


def finalize_signed_snapshot(
    material: SnapshotSigningMaterial,
    *,
    signature: str,
) -> EvidenceSnapshot:
    """Purely finalize and validate a signed immutable canonical EvidenceSnapshot."""

    payload = json.loads(material.snapshot_payload_json)
    attestation = json.loads(material.attestation_payload_json)
    if not isinstance(payload, dict) or not isinstance(attestation, dict):
        raise ValueError("snapshot signing material must contain canonical objects")
    attestation["signedPreimageDigest"] = material.signing_preimage_digest
    attestation["signature"] = signature
    payload["snapshotAttestation"] = attestation
    return EvidenceSnapshot.model_validate(payload)


__all__ = [
    "SnapshotSigningMaterial",
    "finalize_signed_snapshot",
    "prepare_snapshot_signing_material",
]
