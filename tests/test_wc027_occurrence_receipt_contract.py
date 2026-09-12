from __future__ import annotations

import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from athena_context.contracts import (
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentOccurrenceReceipt,
    VersionPinnedBlobReference,
    build_incident_occurrence_receipt,
    incident_pointer_signature_preimage,
    incident_state_signature_preimage,
    sha256_hex,
)
from test_wc027_incident_subject_contract import _incident_state

_VERSION = "2026-09-12T03:00:00.0000000Z"


def _artifacts():
    state, state_attestation = _incident_state()
    suffix = state.result_digest.removeprefix("sha256:")
    prefix = f"incidents/{state.incident_id}/versions/{suffix}"
    state_reference = VersionPinnedBlobReference(
        name=f"{prefix}/state.json",
        version=_VERSION,
        contentDigest=sha256_hex(state.canonical_bytes()),
    )
    state_attestation_reference = VersionPinnedBlobReference(
        name=f"{prefix}/attestation.json",
        version=_VERSION,
        contentDigest=sha256_hex(state_attestation.canonical_bytes()),
    )
    pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId=state.incident_id,
        statePath=f"./{state_reference.name}",
        stateSha256=state_reference.content_digest,
        attestationPath=f"./{state_attestation_reference.name}",
        attestationSha256=state_attestation_reference.content_digest,
        pointerAttestationPath=f"./{prefix}/pointer-attestation.json",
        keyId=state_attestation.key_vault_key_id,
        keyFingerprint="sha256:" + "4" * 64,
        publishedAt=state.updated_at + timedelta(seconds=1),
    )
    pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=state_attestation.key_vault_key_id,
        detachedSignature="c3ludGhldGlj",
    )
    pointer_reference = VersionPinnedBlobReference(
        name=f"{prefix}/pointer.json",
        version=_VERSION,
        contentDigest=sha256_hex(pointer.canonical_bytes()),
    )
    pointer_attestation_reference = VersionPinnedBlobReference(
        name=f"{prefix}/pointer-attestation.json",
        version=_VERSION,
        contentDigest=sha256_hex(pointer_attestation.canonical_bytes()),
    )
    return (
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference,
        state_attestation_reference,
        pointer_reference,
        pointer_attestation_reference,
    )


def _receipt() -> IncidentOccurrenceReceipt:
    (
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference,
        state_attestation_reference,
        pointer_reference,
        pointer_attestation_reference,
    ) = _artifacts()
    return build_incident_occurrence_receipt(
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference=state_reference,
        state_attestation_reference=state_attestation_reference,
        pointer_reference=pointer_reference,
        pointer_attestation_reference=pointer_attestation_reference,
    )


def test_occurrence_receipt_round_trip_and_preimages() -> None:
    artifacts = _artifacts()
    state, _, pointer, *_ = artifacts

    assert state.result_digest == sha256_hex(incident_state_signature_preimage(state))
    assert incident_pointer_signature_preimage(pointer) == (pointer.canonical_bytes())

    first = _receipt()
    second = _receipt()

    assert first == second
    assert first.occurrence_digest == second.occurrence_digest
    assert (
        IncidentOccurrenceReceipt.model_validate_json(first.model_dump_json(by_alias=True)) == first
    )


def test_occurrence_receipt_rejects_path_substitution() -> None:
    receipt = _receipt()
    payload = receipt.model_dump(
        mode="python",
        by_alias=True,
        exclude={"occurrence_id", "occurrence_digest"},
    )
    payload["pointerReference"] = VersionPinnedBlobReference(
        name=receipt.pointer_reference.name.replace(
            "/pointer.json",
            "/other.json",
        ),
        version=receipt.pointer_reference.version,
        contentDigest=receipt.pointer_reference.content_digest,
    )

    with pytest.raises(ValidationError, match="one state version"):
        IncidentOccurrenceReceipt(
            **payload,
            occurrenceId="incident-occurrence-" + "0" * 32,
            occurrenceDigest="sha256:" + "0" * 64,
        )


def test_occurrence_builder_rejects_content_substitution() -> None:
    (
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference,
        state_attestation_reference,
        pointer_reference,
        pointer_attestation_reference,
    ) = _artifacts()
    bad_state_reference = VersionPinnedBlobReference(
        name=state_reference.name,
        version=state_reference.version,
        contentDigest="sha256:" + "f" * 64,
    )

    with pytest.raises(ValueError, match="exact artifacts"):
        build_incident_occurrence_receipt(
            state,
            state_attestation,
            pointer,
            pointer_attestation,
            state_reference=bad_state_reference,
            state_attestation_reference=state_attestation_reference,
            pointer_reference=pointer_reference,
            pointer_attestation_reference=pointer_attestation_reference,
        )


def test_occurrence_builder_rejects_stale_pointer_time() -> None:
    (
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference,
        state_attestation_reference,
        _,
        pointer_attestation_reference,
    ) = _artifacts()
    payload = pointer.model_dump(mode="python", by_alias=True)
    payload["publishedAt"] = state.updated_at - timedelta(seconds=1)
    stale_pointer = IncidentFeedPointer(**payload)
    stale_pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(stale_pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=pointer_attestation.key_vault_key_id,
        detachedSignature="c3ludGhldGlj",
    )
    prefix = state_reference.name.removesuffix("/state.json")
    stale_pointer_reference = VersionPinnedBlobReference(
        name=f"{prefix}/pointer.json",
        version=_VERSION,
        contentDigest=sha256_hex(stale_pointer.canonical_bytes()),
    )
    stale_attestation_reference = VersionPinnedBlobReference(
        name=f"{prefix}/pointer-attestation.json",
        version=_VERSION,
        contentDigest=sha256_hex(stale_pointer_attestation.canonical_bytes()),
    )

    with pytest.raises(ValueError, match="exact artifacts"):
        build_incident_occurrence_receipt(
            state,
            state_attestation,
            stale_pointer,
            stale_pointer_attestation,
            state_reference=state_reference,
            state_attestation_reference=state_attestation_reference,
            pointer_reference=stale_pointer_reference,
            pointer_attestation_reference=stale_attestation_reference,
        )


def test_occurrence_builder_rejects_mismatched_key_ids() -> None:
    (
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference,
        state_attestation_reference,
        pointer_reference,
        _,
    ) = _artifacts()
    mismatched = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=pointer_attestation.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId="synthetic-other-key",
        detachedSignature=pointer_attestation.detached_signature,
    )
    prefix = pointer_reference.name.removesuffix("/pointer.json")
    mismatched_reference = VersionPinnedBlobReference(
        name=f"{prefix}/pointer-attestation.json",
        version=_VERSION,
        contentDigest=sha256_hex(mismatched.canonical_bytes()),
    )

    with pytest.raises(ValueError, match="exact artifacts"):
        build_incident_occurrence_receipt(
            state,
            state_attestation,
            pointer,
            mismatched,
            state_reference=state_reference,
            state_attestation_reference=state_attestation_reference,
            pointer_reference=pointer_reference,
            pointer_attestation_reference=mismatched_reference,
        )


def test_occurrence_receipt_rejects_digest_and_id_substitution() -> None:
    receipt = _receipt()
    bad_digest = receipt.model_copy(
        update={"occurrence_digest": "sha256:" + "f" * 64}
    )
    with pytest.raises(ValidationError, match="occurrenceDigest"):
        IncidentOccurrenceReceipt.model_validate_json(
            bad_digest.model_dump_json(by_alias=True)
        )

    bad_id = receipt.model_copy(
        update={"occurrence_id": "incident-occurrence-" + "f" * 32}
    )
    with pytest.raises(ValidationError, match="occurrenceId"):
        IncidentOccurrenceReceipt.model_validate_json(
            bad_id.model_dump_json(by_alias=True)
        )


def test_occurrence_receipt_rejects_extra_fields() -> None:
    payload = _receipt().model_dump(mode="json", by_alias=True)
    payload["published"] = True

    with pytest.raises(ValidationError, match="Extra inputs"):
        IncidentOccurrenceReceipt.model_validate_json(
            json.dumps(payload)
        )
