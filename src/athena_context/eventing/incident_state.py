from __future__ import annotations

import base64
from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from athena_context.contracts import canonicalize_json, sha256_hex
from athena_context.contracts.eventing import (
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentFinding,
    IncidentLifecycle,
    IncidentScenario,
    IncidentState,
    IncidentStateAttestation,
    ReassessmentRequest,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    IncidentPublicationRequest,
    PresentationAsset,
)

Availability = Literal["normal", "warning", "critical", "unknown"]
BlastRadius = Literal[
    "none",
    "web-tier",
    "ingress-edge",
    "data-tier",
    "whole-workload",
    "unknown",
]
OperatorAttention = Literal["normal", "required", "urgent"]

_ACTIVE_IMPACT: dict[
    IncidentScenario,
    tuple[Availability, BlastRadius, OperatorAttention],
] = {
    "singletonDatabaseFailure": ("critical", "whole-workload", "urgent"),
    "webServerFailure": ("warning", "web-tier", "required"),
    "loadBalancerFailure": ("critical", "ingress-edge", "urgent"),
}


def build_signed_incident_state(
    request: ReassessmentRequest,
    *,
    detected_at: datetime,
    updated_at: datetime,
    target_binding: str,
    reassessment_verified_healthy: bool,
    findings: Sequence[IncidentFinding],
    reasoning: Sequence[str],
    signer: PresentationSigner,
    signing_key_id: str,
) -> tuple[IncidentState, IncidentStateAttestation]:
    if not findings or not reasoning:
        raise ValueError("verified findings and reasoning are required")
    lifecycle: IncidentLifecycle
    availability: Availability
    blast_radius: BlastRadius
    attention: OperatorAttention
    if request.lifecycle == "resolved" and not reassessment_verified_healthy:
        lifecycle = "failedClosed"
        availability, blast_radius, attention = "unknown", "unknown", "urgent"
    elif request.lifecycle == "resolved":
        lifecycle = "resolved"
        availability, blast_radius, attention = "normal", "none", "normal"
    elif reassessment_verified_healthy:
        lifecycle = "failedClosed"
        availability, blast_radius, attention = "unknown", "unknown", "required"
    else:
        lifecycle = "active"
        availability, blast_radius, attention = _ACTIVE_IMPACT[request.scenario]
    unsigned = {
        "schemaVersion": "athena.incidentState.v1",
        "incidentId": request.incident_id,
        "scenario": request.scenario,
        "lifecycle": lifecycle,
        "workloadRole": request.workload_role,
        "detectedAt": detected_at,
        "updatedAt": updated_at,
        "targetBinding": target_binding,
        "availability": availability,
        "blastRadius": blast_radius,
        "operatorAttention": attention,
        "findings": [
            finding.model_dump(mode="json", by_alias=True) for finding in findings
        ],
        "reasoning": list(reasoning),
        "notificationStatus": (
            "pending" if lifecycle in {"active", "resolved"} else "notRequired"
        ),
        "noAutoRemediation": True,
    }
    preimage = canonicalize_json(unsigned).encode("utf-8")
    result_digest = sha256_hex(preimage)
    state = IncidentState(
        schemaVersion="athena.incidentState.v1",
        incidentId=request.incident_id,
        scenario=request.scenario,
        lifecycle=lifecycle,
        workloadRole=request.workload_role,
        detectedAt=detected_at,
        updatedAt=updated_at,
        targetBinding=target_binding,
        availability=availability,
        blastRadius=blast_radius,
        operatorAttention=attention,
        findings=tuple(findings),
        reasoning=tuple(reasoning),
        notificationStatus=(
            "pending" if lifecycle in {"active", "resolved"} else "notRequired"
        ),
        resultDigest=result_digest,
        noAutoRemediation=True,
    )
    attestation = IncidentStateAttestation(
        schemaVersion="athena.incidentStateAttestation.v1",
        resultDigest=result_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=signing_key_id,
        detachedSignature=_base64url_signature(signer.sign_preimage(preimage)),
    )
    return state, attestation


def notification_message(state: IncidentState, *, presentation_url: str) -> str | None:
    if state.lifecycle not in {"active", "resolved"}:
        return None
    status = "ACTIVE" if state.lifecycle == "active" else "RESOLVED"
    return (
        f"Athena incident {status}: {state.scenario}\n"
        f"Role: {state.workload_role}\n"
        f"Availability: {state.availability}\n"
        f"Blast radius: {state.blast_radius}\n"
        f"Operator attention: {state.operator_attention}\n"
        f"Evidence: {state.findings[0].summary}\n"
        f"Presentation: {presentation_url}\n\n"
        "Athena did not perform remediation."
    )


def build_incident_publication(
    state: IncidentState,
    attestation: IncidentStateAttestation,
    *,
    published_at: datetime,
    key_id: str,
    key_fingerprint: str,
    signer: PresentationSigner,
) -> IncidentPublicationRequest:
    digest_suffix = state.result_digest.removeprefix("sha256:")
    prefix = f"incidents/{state.incident_id}/{digest_suffix}"
    state_bytes = state.canonical_bytes()
    attestation_bytes = attestation.canonical_bytes()
    state_asset = PresentationAsset(
        blob_name=f"{prefix}/state.json",
        payload=state_bytes,
        payload_sha256=sha256_hex(state_bytes),
        maximum_bytes=MAX_INCIDENT_STATE_BYTES,
    )
    attestation_asset = PresentationAsset(
        blob_name=f"{prefix}/attestation.json",
        payload=attestation_bytes,
        payload_sha256=sha256_hex(attestation_bytes),
        maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
    )
    pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        statePath=f"./{state_asset.blob_name}",
        stateSha256=state_asset.payload_sha256,
        attestationPath=f"./{attestation_asset.blob_name}",
        attestationSha256=attestation_asset.payload_sha256,
        pointerAttestationPath=f"./{prefix}/pointer-attestation.json",
        keyId=key_id,
        keyFingerprint=key_fingerprint,
        publishedAt=published_at,
    )
    pointer_bytes = pointer.canonical_bytes()
    pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(pointer_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=key_id,
        detachedSignature=_base64url_signature(signer.sign_preimage(pointer_bytes)),
    )
    pointer_attestation_bytes = pointer_attestation.canonical_bytes()
    return IncidentPublicationRequest(
        pointer=pointer,
        pointer_attestation=pointer_attestation,
        pointer_attestation_asset=PresentationAsset(
            blob_name=pointer.pointer_attestation_path.removeprefix("./"),
            payload=pointer_attestation_bytes,
            payload_sha256=sha256_hex(pointer_attestation_bytes),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        ),
        state=state_asset,
        attestation=attestation_asset,
    )


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("incident signer returned invalid base64") from exc
    if not signature:
        raise ValueError("incident signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
