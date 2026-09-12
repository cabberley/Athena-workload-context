from __future__ import annotations

import base64
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Literal

from athena_context.contracts import canonicalize_json, sha256_hex
from athena_context.contracts.eventing import (
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
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
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    ActiveIncidentIndexPublicationRequest,
    ActiveIncidentIndexSnapshot,
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
    if reassessment_verified_healthy:
        lifecycle = "resolved"
        availability, blast_radius, attention = "normal", "none", "normal"
    else:
        lifecycle = "active"
        availability, blast_radius, attention = _ACTIVE_IMPACT[request.scenario]
    unsigned = {
        "schemaVersion": "athena.incidentState.v1",
        "incidentId": request.incident_id,
        "transitionId": request.idempotency_key,
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
            "pendingDispatch"
            if lifecycle in {"active", "resolved"}
            else "notRequired"
        ),
        "noAutoRemediation": True,
    }
    preimage = canonicalize_json(unsigned).encode("utf-8")
    result_digest = sha256_hex(preimage)
    state = IncidentState(
        schemaVersion="athena.incidentState.v1",
        incidentId=request.incident_id,
        transitionId=request.idempotency_key,
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
            "pendingDispatch"
            if lifecycle in {"active", "resolved"}
            else "notRequired"
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
        "Athena did not perform remediation.\n\n"
        "Sent by Kanga, my AI sidekick 🦘"
    )


def build_active_incident_index_heartbeat(
    *,
    published_at: datetime,
    key_id: str,
    key_fingerprint: str,
    signer: PresentationSigner,
    active_index_snapshot: ActiveIncidentIndexSnapshot | None,
) -> ActiveIncidentIndexPublicationRequest:
    entries = (
        ()
        if active_index_snapshot is None
        else active_index_snapshot.index.incidents
    )
    return _build_active_incident_index_publication(
        entries=entries,
        published_at=published_at,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
        signer=signer,
        active_index_snapshot=active_index_snapshot,
        reuse_unchanged=False,
    )


def build_incident_publication(
    state: IncidentState,
    attestation: IncidentStateAttestation,
    *,
    published_at: datetime,
    key_id: str,
    key_fingerprint: str,
    signer: PresentationSigner,
    active_index_snapshot: ActiveIncidentIndexSnapshot | None = None,
) -> IncidentPublicationRequest:
    published_at = max(published_at, state.updated_at)
    digest_suffix = state.result_digest.removeprefix("sha256:")
    prefix = f"incidents/{state.incident_id}/versions/{digest_suffix}"
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
        incidentId=state.incident_id,
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
    pointer_sha256 = sha256_hex(pointer_bytes)
    pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(pointer_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=key_id,
        detachedSignature=_base64url_signature(signer.sign_preimage(pointer_bytes)),
    )
    pointer_attestation_bytes = pointer_attestation.canonical_bytes()
    pointer_asset = PresentationAsset(
        blob_name=f"{prefix}/pointer.json",
        payload=pointer_bytes,
        payload_sha256=pointer_sha256,
        maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
    )
    current_pointer_asset = PresentationAsset(
        blob_name=f"incidents/{state.incident_id}/current.json",
        payload=pointer_bytes,
        payload_sha256=pointer_sha256,
        maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
    )
    previous_index = (
        active_index_snapshot.index if active_index_snapshot is not None else None
    )
    entries = {
        entry.incident_id: entry
        for entry in (() if previous_index is None else previous_index.incidents)
    }
    if state.lifecycle == "active":
        entries[state.incident_id] = ActiveIncidentEntry(
            incidentId=state.incident_id,
            scenario=state.scenario,
            lifecycle=state.lifecycle,
            workloadRole=state.workload_role,
            pointerPath=f"./{pointer_asset.blob_name}",
            pointerSha256=pointer_sha256,
            detectedAt=state.detected_at,
            updatedAt=state.updated_at,
        )
    else:
        entries.pop(state.incident_id, None)
    ordered_entries = tuple(entries[key] for key in sorted(entries))
    index_publication = _build_active_incident_index_publication(
        entries=ordered_entries,
        published_at=published_at,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
        signer=signer,
        active_index_snapshot=active_index_snapshot,
        reuse_unchanged=True,
    )
    return IncidentPublicationRequest(
        pointer=pointer,
        pointer_attestation=pointer_attestation,
        pointer_asset=pointer_asset,
        current_pointer_asset=current_pointer_asset,
        pointer_attestation_asset=PresentationAsset(
            blob_name=pointer.pointer_attestation_path.removeprefix("./"),
            payload=pointer_attestation_bytes,
            payload_sha256=sha256_hex(pointer_attestation_bytes),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        ),
        state=state_asset,
        attestation=attestation_asset,
        active_index=index_publication.active_index,
        active_index_attestation=index_publication.active_index_attestation,
        active_index_asset=index_publication.active_index_asset,
        active_index_attestation_asset=(
            index_publication.active_index_attestation_asset
        ),
        previous_active_index_sha256=(
            index_publication.previous_active_index_sha256
        ),
    )


def _build_active_incident_index_publication(
    *,
    entries: Sequence[ActiveIncidentEntry],
    published_at: datetime,
    key_id: str,
    key_fingerprint: str,
    signer: PresentationSigner,
    active_index_snapshot: ActiveIncidentIndexSnapshot | None,
    reuse_unchanged: bool,
) -> ActiveIncidentIndexPublicationRequest:
    previous_index = (
        active_index_snapshot.index if active_index_snapshot is not None else None
    )
    entries_by_id = {entry.incident_id: entry for entry in entries}
    if len(entries_by_id) != len(entries):
        raise ValueError("active incident heartbeat entries must be unique")
    ordered_entries = tuple(entries_by_id[key] for key in sorted(entries_by_id))
    if (
        reuse_unchanged
        and previous_index is not None
        and ordered_entries == previous_index.incidents
        and previous_index.key_id == key_id
        and previous_index.key_fingerprint == key_fingerprint
    ):
        active_index = previous_index
    else:
        minimum_published_at = (
            previous_index.published_at
            if previous_index is not None
            else published_at
        )
        index_published_at = max(published_at, minimum_published_at)
        if previous_index is not None and index_published_at == previous_index.published_at:
            index_published_at += timedelta(milliseconds=1)
        index_seed = canonicalize_json(
            {
                "incidents": [
                    entry.model_dump(mode="json", by_alias=True)
                    for entry in ordered_entries
                ],
                "keyId": key_id,
                "keyFingerprint": key_fingerprint,
                "publishedAt": index_published_at,
            }
        )
        index_version = sha256_hex(index_seed).removeprefix("sha256:")
        active_index = ActiveIncidentIndex(
            schemaVersion="athena.activeIncidentIndex.v1",
            incidents=ordered_entries,
            indexAttestationPath=(
                f"./incidents/index-attestations/{index_version}.json"
            ),
            keyId=key_id,
            keyFingerprint=key_fingerprint,
            publishedAt=index_published_at,
        )
    active_index_bytes = active_index.canonical_bytes()
    active_index_attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(active_index_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=key_id,
        detachedSignature=_base64url_signature(
            signer.sign_preimage(active_index_bytes)
        ),
    )
    active_index_attestation_bytes = active_index_attestation.canonical_bytes()
    return ActiveIncidentIndexPublicationRequest(
        active_index=active_index,
        active_index_attestation=active_index_attestation,
        active_index_asset=PresentationAsset(
            blob_name="incidents/active.json",
            payload=active_index_bytes,
            payload_sha256=sha256_hex(active_index_bytes),
            maximum_bytes=MAX_INCIDENT_STATE_BYTES,
        ),
        active_index_attestation_asset=PresentationAsset(
            blob_name=active_index.index_attestation_path.removeprefix("./"),
            payload=active_index_attestation_bytes,
            payload_sha256=sha256_hex(active_index_attestation_bytes),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        ),
        previous_active_index_sha256=(
            active_index_snapshot.payload_sha256
            if active_index_snapshot is not None
            else None
        ),
    )


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("incident signer returned invalid base64") from exc
    if not signature:
        raise ValueError("incident signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
