from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedAttestation,
    IncidentFeedEntryV2,
    IncidentFeedIndexAttestationV2,
    IncidentFeedPointer,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    build_incident_feed_index_v2,
    build_incident_occurrence_receipt,
    compute_artifact_digest,
    sha256_hex,
    validate_incident_enrichment_feed_pointer_assets,
    validate_incident_feed_index_assets,
)
from test_wc026_correlation_contract import NOW
from test_wc027_incident_subject_contract import _incident_state

_KEY_ID = "https://synthetic-wc027.vault.azure.net/keys/feed-v2/0123456789abcdef0123456789abcdef"
_SIGNATURE = "c3ludGhldGlj"
_VERSION = "v" * 64


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _occurrence(*, lifecycle: str):
    state, state_attestation = _incident_state(lifecycle=lifecycle)
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
        detachedSignature=_SIGNATURE,
    )
    occurrence = build_incident_occurrence_receipt(
        state,
        state_attestation,
        pointer,
        pointer_attestation,
        state_reference=state_reference,
        state_attestation_reference=state_attestation_reference,
        pointer_reference=VersionPinnedBlobReference(
            name=f"{prefix}/pointer.json",
            version=_VERSION,
            contentDigest=sha256_hex(pointer.canonical_bytes()),
        ),
        pointer_attestation_reference=VersionPinnedBlobReference(
            name=f"{prefix}/pointer-attestation.json",
            version=_VERSION,
            contentDigest=sha256_hex(pointer_attestation.canonical_bytes()),
        ),
    )
    return state, occurrence


def _enrichment(occurrence) -> IncidentEnrichmentAssetReference:
    enrichment_id = "incident-enrichment-" + "a" * 32
    suffix = occurrence.state_result_digest.removeprefix("sha256:")
    prefix = f"incidents/{occurrence.incident_id}/versions/{suffix}/enrichments/{enrichment_id}"
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentEnrichmentAssetReference.v1"),
        "incidentId": occurrence.incident_id,
        "incidentStateResultDigest": occurrence.state_result_digest,
        "enrichmentId": enrichment_id,
        "manifestDigest": "sha256:" + "b" * 64,
        "manifestReference": VersionPinnedBlobReference(
            name=f"{prefix}/manifest.json",
            version=_VERSION,
            contentDigest="sha256:" + "c" * 64,
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version=_VERSION,
            contentDigest="sha256:" + "d" * 64,
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentEnrichmentAssetReference(
        **payload,
        referenceId=(f"enrichment-asset-{digest.removeprefix('sha256:')[:32]}"),
        referenceDigest=digest,
    )


def _pointer_assets(*, lifecycle: str = "active"):
    state, occurrence = _occurrence(lifecycle=lifecycle)
    enrichment = _enrichment(occurrence)
    pointer = build_incident_enrichment_feed_pointer(
        occurrence,
        enrichment,
        state,
        published_at=occurrence.published_at + timedelta(seconds=1),
    )
    attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=("athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"),
        pointerId=pointer.pointer_id,
        pointerDigest=pointer.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=_KEY_ID,
        signedPreimageDigest=sha256_hex(pointer.canonical_bytes()),
        detachedSignature=_SIGNATURE,
    )
    prefix = enrichment.manifest_reference.name.removesuffix("/manifest.json")
    entry = IncidentFeedEntryV2(
        incidentId=pointer.incident_id,
        lifecycle=pointer.lifecycle,
        stateResultDigest=pointer.state_result_digest,
        updatedAt=pointer.state_updated_at,
        feedPointerReference=VersionPinnedBlobReference(
            name=f"{prefix}/feed-pointer.json",
            version=_VERSION,
            contentDigest=sha256_hex(pointer.canonical_bytes()),
        ),
        feedPointerAttestationReference=VersionPinnedBlobReference(
            name=f"{prefix}/feed-pointer-attestation.json",
            version=_VERSION,
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    )
    return state, occurrence, enrichment, pointer, attestation, entry


def _verify(_: bytes, signature: str) -> bool:
    return signature == _SIGNATURE


def test_feed_v2_pointer_round_trip_and_signature_binding() -> None:
    state, _, _, pointer, attestation, entry = _pointer_assets()

    validate_incident_enrichment_feed_pointer_assets(
        entry,
        pointer,
        attestation,
        trusted_key_id=_KEY_ID,
        signature_verifier=_verify,
    )

    assert pointer.lifecycle == state.lifecycle
    assert pointer.state_updated_at == state.updated_at
    assert pointer.no_auto_remediation is True


def test_feed_v2_lifecycle_is_derived_from_v1_state() -> None:
    state, occurrence = _occurrence(lifecycle="active")
    enrichment = _enrichment(occurrence)
    resolved_state, _ = _occurrence(lifecycle="resolved")

    with pytest.raises(ValueError, match="published occurrence"):
        build_incident_enrichment_feed_pointer(
            occurrence,
            enrichment,
            resolved_state,
            published_at=NOW,
        )

    pointer = build_incident_enrichment_feed_pointer(
        occurrence,
        enrichment,
        state,
        published_at=occurrence.published_at + timedelta(seconds=1),
    )
    assert pointer.lifecycle == "active"

    tampered = state.model_copy(
        update={
            "lifecycle": "resolved",
            "availability": "normal",
        }
    )
    with pytest.raises(ValueError, match="published occurrence"):
        build_incident_enrichment_feed_pointer(
            occurrence,
            enrichment,
            tampered,
            published_at=occurrence.published_at + timedelta(seconds=1),
        )


def test_feed_v2_pointer_asset_substitution_fails() -> None:
    _, _, _, pointer, attestation, entry = _pointer_assets()
    wrong_prefix = entry.feed_pointer_reference.name.replace(
        pointer.enrichment_asset.enrichment_id,
        "incident-enrichment-" + "f" * 32,
    )
    substituted = entry.model_copy(
        update={
            "feed_pointer_reference": VersionPinnedBlobReference(
                name=wrong_prefix,
                version=entry.feed_pointer_reference.version,
                contentDigest=entry.feed_pointer_reference.content_digest,
            ),
            "feed_pointer_attestation_reference": (
                VersionPinnedBlobReference(
                    name=entry.feed_pointer_attestation_reference.name.replace(
                        pointer.enrichment_asset.enrichment_id,
                        "incident-enrichment-" + "f" * 32,
                    ),
                    version=(entry.feed_pointer_attestation_reference.version),
                    contentDigest=(entry.feed_pointer_attestation_reference.content_digest),
                )
            ),
        }
    )

    with pytest.raises(ValueError, match="exact content"):
        validate_incident_enrichment_feed_pointer_assets(
            substituted,
            pointer,
            attestation,
            trusted_key_id=_KEY_ID,
            signature_verifier=_verify,
        )


def _index(active, resolved, *, truncated=False):
    published_at = max(
        (item.updated_at for item in (*active, *resolved)),
        default=NOW,
    ) + timedelta(seconds=1)
    retention_start = (
        min(item.updated_at for item in resolved)
        if truncated and resolved
        else published_at - timedelta(days=7)
    )
    return build_incident_feed_index_v2(
        active=active,
        recently_resolved=resolved,
        resolved_retention_start=retention_start,
        resolved_history_truncated=truncated,
        resolved_history_total_count=(len(resolved) + (1 if truncated else 0)),
        omitted_resolved_count=1 if truncated else None,
        source_active_index_digest="sha256:" + "e" * 64,
        key_id=_KEY_ID,
        key_fingerprint="sha256:" + "b" * 64,
        published_at=published_at,
    )


def test_feed_v2_index_and_signature_binding() -> None:
    _, _, _, _, _, active = _pointer_assets(lifecycle="active")
    _, _, _, _, _, resolved = _pointer_assets(lifecycle="resolved")
    resolved = resolved.model_copy(
        update={
            "incident_id": "inc-" + "f" * 12,
            "feed_pointer_reference": VersionPinnedBlobReference(
                name=resolved.feed_pointer_reference.name.replace(
                    resolved.incident_id,
                    "inc-" + "f" * 12,
                ),
                version=resolved.feed_pointer_reference.version,
                contentDigest=resolved.feed_pointer_reference.content_digest,
            ),
            "feed_pointer_attestation_reference": VersionPinnedBlobReference(
                name=(
                    resolved.feed_pointer_attestation_reference.name.replace(
                        resolved.incident_id,
                        "inc-" + "f" * 12,
                    )
                ),
                version=(resolved.feed_pointer_attestation_reference.version),
                contentDigest=(resolved.feed_pointer_attestation_reference.content_digest),
            ),
        }
    )
    index = _index((active,), (resolved,))
    index_bytes = index.canonical_bytes()
    attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(index_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=_KEY_ID,
        detachedSignature=_SIGNATURE,
    )

    validate_incident_feed_index_assets(
        index,
        attestation,
        trusted_key_id=_KEY_ID,
        trusted_key_fingerprint="sha256:" + "b" * 64,
        expected_source_active_index_digest="sha256:" + "e" * 64,
        not_older_than=index.published_at - timedelta(seconds=1),
        signature_verifier=_verify,
    )
    with pytest.raises(ValueError, match="exact content"):
        validate_incident_feed_index_assets(
            index,
            attestation,
            trusted_key_id=_KEY_ID,
            trusted_key_fingerprint="sha256:" + "f" * 64,
            expected_source_active_index_digest="sha256:" + "e" * 64,
            not_older_than=index.published_at - timedelta(seconds=1),
            signature_verifier=_verify,
        )
    with pytest.raises(ValueError, match="exact content"):
        validate_incident_feed_index_assets(
            index,
            attestation,
            trusted_key_id=_KEY_ID,
            trusted_key_fingerprint="sha256:" + "b" * 64,
            expected_source_active_index_digest="sha256:" + "f" * 64,
            not_older_than=index.published_at - timedelta(seconds=1),
            signature_verifier=_verify,
        )


def test_feed_v2_index_rejects_duplicate_lifecycle_heads() -> None:
    _, _, _, _, _, active = _pointer_assets(lifecycle="active")
    _, _, _, _, _, resolved = _pointer_assets(lifecycle="resolved")

    with pytest.raises(ValidationError, match="lifecycle or retention"):
        _index((active,), (resolved,))


def test_feed_v2_truncation_is_explicit() -> None:
    _, _, _, _, _, resolved = _pointer_assets(lifecycle="resolved")
    index = _index((), (resolved,), truncated=True)

    assert index.resolved_history_truncated is True
    assert index.omitted_resolved_count == 1


def test_resolved_order_uses_datetime_not_variable_width_text() -> None:
    _, _, _, _, _, first = _pointer_assets(lifecycle="resolved")
    first_time = first.updated_at.replace(microsecond=500000)
    second_time = first.updated_at.replace(microsecond=0)

    def moved(
        entry: IncidentFeedEntryV2,
        incident_id: str,
        updated_at,
    ) -> IncidentFeedEntryV2:
        return IncidentFeedEntryV2(
            incidentId=incident_id,
            lifecycle="resolved",
            stateResultDigest=entry.state_result_digest,
            updatedAt=updated_at,
            feedPointerReference=VersionPinnedBlobReference(
                name=entry.feed_pointer_reference.name.replace(
                    entry.incident_id,
                    incident_id,
                ),
                version=entry.feed_pointer_reference.version,
                contentDigest=entry.feed_pointer_reference.content_digest,
            ),
            feedPointerAttestationReference=VersionPinnedBlobReference(
                name=(
                    entry.feed_pointer_attestation_reference.name.replace(
                        entry.incident_id,
                        incident_id,
                    )
                ),
                version=(entry.feed_pointer_attestation_reference.version),
                contentDigest=(entry.feed_pointer_attestation_reference.content_digest),
            ),
        )

    newer = moved(first, "inc-" + "e" * 12, first_time)
    older = moved(first, "inc-" + "f" * 12, second_time)
    assert _index((), (newer, older))

    with pytest.raises(ValidationError, match="latest unique incidents"):
        _index((), (older, newer))


def test_feed_v2_maximum_collections_fit_byte_budget() -> None:
    def entry(index: int, lifecycle: str) -> IncidentFeedEntryV2:
        incident_id = f"inc-{index:012x}"
        state_digest = f"sha256:{index + 1:064x}"
        enrichment_id = f"incident-enrichment-{index + 1:032x}"
        prefix = (
            f"incidents/{incident_id}/versions/"
            f"{state_digest.removeprefix('sha256:')}/enrichments/"
            f"{enrichment_id}"
        )
        return IncidentFeedEntryV2(
            incidentId=incident_id,
            lifecycle=lifecycle,
            stateResultDigest=state_digest,
            updatedAt=NOW - timedelta(minutes=index),
            feedPointerReference=VersionPinnedBlobReference(
                name=f"{prefix}/feed-pointer.json",
                version=_VERSION,
                contentDigest=f"sha256:{index + 2:064x}",
            ),
            feedPointerAttestationReference=VersionPinnedBlobReference(
                name=f"{prefix}/feed-pointer-attestation.json",
                version=_VERSION,
                contentDigest=f"sha256:{index + 3:064x}",
            ),
        )

    active = tuple(entry(index, "active") for index in range(64))
    resolved = tuple(entry(index + 64, "resolved") for index in range(64))
    resolved = tuple(
        sorted(
            resolved,
            key=lambda item: (
                -item.updated_at.timestamp(),
                item.incident_id,
                item.state_result_digest,
            ),
        )
    )
    index = build_incident_feed_index_v2(
        active=active,
        recently_resolved=resolved,
        resolved_retention_start=(min(item.updated_at for item in resolved) - timedelta(minutes=1)),
        resolved_history_truncated=False,
        resolved_history_total_count=len(resolved),
        omitted_resolved_count=None,
        source_active_index_digest="sha256:" + "e" * 64,
        key_id=_KEY_ID,
        key_fingerprint="sha256:" + "b" * 64,
        published_at=NOW + timedelta(seconds=1),
    )

    assert len(index.active) == 64
    assert len(index.recently_resolved) == 64
    assert len(index.canonical_bytes()) <= 128 * 1024


def test_feed_v2_contracts_reject_extra_fields() -> None:
    _, _, _, pointer, _, _ = _pointer_assets()
    payload = pointer.model_dump(mode="json", by_alias=True)
    payload["fallbackToV1"] = True

    with pytest.raises(ValidationError, match="Extra inputs"):
        type(pointer).model_validate(payload)
