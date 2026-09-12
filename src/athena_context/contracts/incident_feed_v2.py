from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.eventing import (
    IncidentOccurrenceReceipt,
    IncidentState,
    incident_state_signature_preimage,
)
from athena_context.contracts.incident_enrichment import (
    IncidentEnrichmentAssetReference,
)
from athena_context.contracts.models import (
    AthenaBaseModel,
    Sha256Digest,
    UtcDateTime,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MAX_INCIDENT_FEED_V2_BYTES = 128 * 1024
MAX_INCIDENT_FEED_V2_POINTER_BYTES = 16 * 1024


class _StrictIncidentFeedV2Model(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


def _expected_digest(
    model: AthenaBaseModel,
    *,
    excluded_fields: set[str],
) -> Sha256Digest:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude=excluded_fields,
        )
    )


def _occurrence_prefix(
    incident_id: str,
    state_result_digest: str,
) -> str:
    return f"incidents/{incident_id}/versions/{state_result_digest.removeprefix('sha256:')}"


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items() if item is not None}
    return value


def _index_version_digest(
    *,
    active: tuple[IncidentFeedEntryV2, ...],
    recently_resolved: tuple[IncidentFeedEntryV2, ...],
    resolved_retention_start: UtcDateTime,
    resolved_history_truncated: bool,
    resolved_history_total_count: int,
    omitted_resolved_count: int | None,
    source_active_index_digest: Sha256Digest,
    key_id: str,
    key_fingerprint: Sha256Digest,
    published_at: UtcDateTime,
) -> Sha256Digest:
    return compute_artifact_digest(
        _json_value(
            {
                "active": active,
                "recentlyResolved": recently_resolved,
                "resolvedRetentionStart": resolved_retention_start,
                "resolvedHistoryTruncated": (resolved_history_truncated),
                "resolvedHistoryTotalCount": resolved_history_total_count,
                "omittedResolvedCount": omitted_resolved_count,
                "sourceActiveIndexDigest": source_active_index_digest,
                "keyId": key_id,
                "keyFingerprint": key_fingerprint,
                "publishedAt": published_at,
            }
        )
    )


class IncidentEnrichmentFeedPointer(_StrictIncidentFeedV2Model):
    schema_version: Literal["athena.wc027IncidentEnrichmentFeedPointer.v2"] = Field(
        alias="schemaVersion"
    )
    pointer_id: str = Field(
        alias="pointerId",
        pattern=r"^incident-feed-v2-pointer-[a-f0-9]{32}$",
    )
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    lifecycle: Literal["active", "resolved"]
    state_result_digest: Sha256Digest = Field(alias="stateResultDigest")
    state_updated_at: UtcDateTime = Field(alias="stateUpdatedAt")
    occurrence_digest: Sha256Digest = Field(alias="occurrenceDigest")
    source_state_reference: VersionPinnedBlobReference = Field(alias="sourceStateReference")
    source_state_attestation_reference: VersionPinnedBlobReference = Field(
        alias="sourceStateAttestationReference"
    )
    source_pointer_reference: VersionPinnedBlobReference = Field(alias="sourcePointerReference")
    source_pointer_attestation_reference: VersionPinnedBlobReference = Field(
        alias="sourcePointerAttestationReference"
    )
    enrichment_asset: IncidentEnrichmentAssetReference = Field(alias="enrichmentAsset")
    published_at: UtcDateTime = Field(alias="publishedAt")
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    pointer_digest: Sha256Digest = Field(alias="pointerDigest")

    @model_validator(mode="after")
    def validate_pointer(self) -> IncidentEnrichmentFeedPointer:
        prefix = _occurrence_prefix(
            self.incident_id,
            self.state_result_digest,
        )
        if (
            self.source_state_reference.name != f"{prefix}/state.json"
            or self.source_state_attestation_reference.name != f"{prefix}/attestation.json"
            or self.source_pointer_reference.name != f"{prefix}/pointer.json"
            or self.source_pointer_attestation_reference.name
            != f"{prefix}/pointer-attestation.json"
            or self.enrichment_asset.incident_id != self.incident_id
            or self.enrichment_asset.incident_state_result_digest != self.state_result_digest
        ):
            raise ValueError("feed v2 pointer does not bind one exact v1 occurrence")
        expected = _expected_digest(
            self,
            excluded_fields={"pointer_id", "pointer_digest"},
        )
        if self.pointer_digest != expected:
            raise ValueError("pointerDigest does not bind feed v2 pointer")
        if self.pointer_id != f"incident-feed-v2-pointer-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("pointerId is not digest-bound")
        if len(self.canonical_bytes()) > MAX_INCIDENT_FEED_V2_POINTER_BYTES:
            raise ValueError("feed v2 pointer exceeds its byte budget")
        return self


class IncidentEnrichmentFeedPointerAttestation(_StrictIncidentFeedV2Model):
    schema_version: Literal["athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"] = Field(
        alias="schemaVersion"
    )
    pointer_id: str = Field(alias="pointerId")
    pointer_digest: Sha256Digest = Field(alias="pointerDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class IncidentFeedEntryV2(_StrictIncidentFeedV2Model):
    incident_id: str = Field(
        alias="incidentId",
        pattern=r"^inc-[a-f0-9]{12}$",
    )
    lifecycle: Literal["active", "resolved"]
    state_result_digest: Sha256Digest = Field(alias="stateResultDigest")
    updated_at: UtcDateTime = Field(alias="updatedAt")
    feed_pointer_reference: VersionPinnedBlobReference = Field(alias="feedPointerReference")
    feed_pointer_attestation_reference: VersionPinnedBlobReference = Field(
        alias="feedPointerAttestationReference"
    )

    @model_validator(mode="after")
    def validate_paths(self) -> IncidentFeedEntryV2:
        prefix = _occurrence_prefix(
            self.incident_id,
            self.state_result_digest,
        )
        pointer_name = self.feed_pointer_reference.name
        pattern = (
            re.escape(f"{prefix}/enrichments/")
            + r"incident-enrichment-[a-f0-9]{32}/feed-pointer\.json"
        )
        if re.fullmatch(pattern, pointer_name) is None:
            raise ValueError("feed v2 entry pointer path is invalid")
        entry_prefix = pointer_name.removesuffix("/feed-pointer.json")
        if (
            self.feed_pointer_attestation_reference.name
            != f"{entry_prefix}/feed-pointer-attestation.json"
        ):
            raise ValueError("feed v2 entry attestation path is invalid")
        if (
            len(self.feed_pointer_reference.version) > 64
            or len(self.feed_pointer_attestation_reference.version) > 64
        ):
            raise ValueError("feed v2 entry Blob versions exceed their bound")
        return self


class IncidentFeedIndexV2(_StrictIncidentFeedV2Model):
    schema_version: Literal["athena.wc027IncidentFeedIndex.v2"] = Field(alias="schemaVersion")
    active: tuple[IncidentFeedEntryV2, ...] = Field(max_length=64)
    recently_resolved: tuple[IncidentFeedEntryV2, ...] = Field(
        alias="recentlyResolved",
        max_length=64,
    )
    resolved_retention_start: UtcDateTime = Field(alias="resolvedRetentionStart")
    resolved_history_truncated: bool = Field(alias="resolvedHistoryTruncated")
    resolved_history_total_count: int = Field(
        alias="resolvedHistoryTotalCount",
        ge=0,
    )
    omitted_resolved_count: int | None = Field(
        default=None,
        alias="omittedResolvedCount",
        ge=1,
    )
    source_active_index_digest: Sha256Digest = Field(alias="sourceActiveIndexDigest")
    index_attestation_path: str = Field(
        alias="indexAttestationPath",
        pattern=(
            r"^\./incidents/feed-v2-index-attestations/"
            r"[a-f0-9]{64}\.json$"
        ),
    )
    key_id: str = Field(alias="keyId", min_length=1, max_length=512)
    key_fingerprint: Sha256Digest = Field(alias="keyFingerprint")
    published_at: UtcDateTime = Field(alias="publishedAt")

    @field_validator("active")
    @classmethod
    def validate_active(
        cls,
        values: tuple[IncidentFeedEntryV2, ...],
    ) -> tuple[IncidentFeedEntryV2, ...]:
        if any(item.lifecycle != "active" for item in values):
            raise ValueError("active feed entries require active lifecycle")
        keys = tuple(item.incident_id for item in values)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("active feed entries must be uniquely sorted by incidentId")
        return values

    @field_validator("recently_resolved")
    @classmethod
    def validate_resolved(
        cls,
        values: tuple[IncidentFeedEntryV2, ...],
    ) -> tuple[IncidentFeedEntryV2, ...]:
        if any(item.lifecycle != "resolved" for item in values):
            raise ValueError("recently resolved entries require resolved lifecycle")
        keys = tuple(
            (
                item.updated_at,
                item.incident_id,
                item.state_result_digest,
            )
            for item in values
        )
        ordered = all(
            previous[0] > current[0] or (previous[0] == current[0] and previous[1:] < current[1:])
            for previous, current in zip(keys, keys[1:], strict=False)
        )
        if not ordered or len({item.incident_id for item in values}) != len(values):
            raise ValueError("recently resolved entries must be latest unique incidents")
        return values

    @model_validator(mode="after")
    def validate_index(self) -> IncidentFeedIndexV2:
        active_ids = {item.incident_id for item in self.active}
        resolved_ids = {item.incident_id for item in self.recently_resolved}
        if (
            active_ids.intersection(resolved_ids)
            or self.resolved_retention_start > self.published_at
            or any(
                item.updated_at < self.resolved_retention_start
                or item.updated_at > self.published_at
                for item in self.recently_resolved
            )
            or any(item.updated_at > self.published_at for item in self.active)
            or (self.resolved_history_truncated != (self.omitted_resolved_count is not None))
            or self.resolved_history_total_count
            != (len(self.recently_resolved) + (self.omitted_resolved_count or 0))
            or self.resolved_history_truncated
            != (self.resolved_history_total_count > len(self.recently_resolved))
            or (
                self.resolved_history_truncated
                and (
                    not self.recently_resolved
                    or self.resolved_retention_start
                    != min(item.updated_at for item in self.recently_resolved)
                )
            )
        ):
            raise ValueError("feed v2 lifecycle or retention interval is invalid")
        if len(self.canonical_bytes()) > MAX_INCIDENT_FEED_V2_BYTES:
            raise ValueError("feed v2 index exceeds its byte budget")
        version_digest = _index_version_digest(
            active=self.active,
            recently_resolved=self.recently_resolved,
            resolved_retention_start=self.resolved_retention_start,
            resolved_history_truncated=self.resolved_history_truncated,
            resolved_history_total_count=self.resolved_history_total_count,
            omitted_resolved_count=self.omitted_resolved_count,
            source_active_index_digest=self.source_active_index_digest,
            key_id=self.key_id,
            key_fingerprint=self.key_fingerprint,
            published_at=self.published_at,
        )
        if self.index_attestation_path != (
            f"./incidents/feed-v2-index-attestations/{version_digest.removeprefix('sha256:')}.json"
        ):
            raise ValueError("feed v2 index attestation path is not digest-bound")
        return self


class IncidentFeedIndexAttestationV2(_StrictIncidentFeedV2Model):
    schema_version: Literal["athena.wc027IncidentFeedIndexAttestation.v2"] = Field(
        alias="schemaVersion"
    )
    index_digest: Sha256Digest = Field(alias="indexDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(
        alias="keyVaultKeyId",
        min_length=1,
        max_length=512,
    )
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


def build_incident_enrichment_feed_pointer(
    occurrence: IncidentOccurrenceReceipt,
    enrichment_asset: IncidentEnrichmentAssetReference,
    state: IncidentState,
    *,
    published_at: UtcDateTime,
) -> IncidentEnrichmentFeedPointer:
    occurrence = IncidentOccurrenceReceipt.model_validate_json(
        occurrence.model_dump_json(by_alias=True)
    )
    enrichment_asset = IncidentEnrichmentAssetReference.model_validate_json(
        enrichment_asset.model_dump_json(by_alias=True)
    )
    state = IncidentState.model_validate_json(state.model_dump_json(by_alias=True))
    if (
        enrichment_asset.incident_id != occurrence.incident_id
        or enrichment_asset.incident_state_result_digest != occurrence.state_result_digest
        or state.incident_id != occurrence.incident_id
        or state.transition_id != occurrence.transition_id
        or state.result_digest != occurrence.state_result_digest
        or state.result_digest != sha256_hex(incident_state_signature_preimage(state))
        or occurrence.state_reference.content_digest != sha256_hex(state.canonical_bytes())
        or state.lifecycle not in {"active", "resolved"}
        or state.updated_at > occurrence.published_at
        or published_at < occurrence.published_at
    ):
        raise ValueError("feed v2 pointer inputs do not bind one published occurrence")
    payload: dict[str, object] = {
        "schemaVersion": ("athena.wc027IncidentEnrichmentFeedPointer.v2"),
        "incidentId": occurrence.incident_id,
        "lifecycle": state.lifecycle,
        "stateResultDigest": occurrence.state_result_digest,
        "stateUpdatedAt": state.updated_at,
        "occurrenceDigest": occurrence.occurrence_digest,
        "sourceStateReference": occurrence.state_reference,
        "sourceStateAttestationReference": (occurrence.state_attestation_reference),
        "sourcePointerReference": occurrence.pointer_reference,
        "sourcePointerAttestationReference": (occurrence.pointer_attestation_reference),
        "enrichmentAsset": enrichment_asset,
        "publishedAt": published_at,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentEnrichmentFeedPointer.model_validate(
        {
            **payload,
            "pointerId": (f"incident-feed-v2-pointer-{digest.removeprefix('sha256:')[:32]}"),
            "pointerDigest": digest,
        }
    )


def validate_incident_enrichment_feed_pointer_assets(
    entry: IncidentFeedEntryV2,
    pointer: IncidentEnrichmentFeedPointer,
    attestation: IncidentEnrichmentFeedPointerAttestation,
    *,
    trusted_key_id: str,
    signature_verifier: Callable[[bytes, str], bool],
) -> None:
    entry = IncidentFeedEntryV2.model_validate_json(entry.model_dump_json(by_alias=True))
    pointer = IncidentEnrichmentFeedPointer.model_validate_json(
        pointer.model_dump_json(by_alias=True)
    )
    attestation = IncidentEnrichmentFeedPointerAttestation.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    pointer_bytes = pointer.canonical_bytes()
    if (
        entry.incident_id != pointer.incident_id
        or entry.lifecycle != pointer.lifecycle
        or entry.state_result_digest != pointer.state_result_digest
        or entry.updated_at != pointer.state_updated_at
        or entry.feed_pointer_reference.name
        != (
            pointer.enrichment_asset.manifest_reference.name.removesuffix("/manifest.json")
            + "/feed-pointer.json"
        )
        or entry.feed_pointer_attestation_reference.name
        != (
            pointer.enrichment_asset.manifest_reference.name.removesuffix("/manifest.json")
            + "/feed-pointer-attestation.json"
        )
        or entry.feed_pointer_reference.content_digest != sha256_hex(pointer_bytes)
        or attestation.pointer_id != pointer.pointer_id
        or attestation.pointer_digest != pointer.pointer_digest
        or attestation.key_vault_key_id != trusted_key_id
        or attestation.signed_preimage_digest != sha256_hex(pointer_bytes)
        or signature_verifier(
            pointer_bytes,
            attestation.detached_signature,
        )
        is not True
        or entry.feed_pointer_attestation_reference.content_digest
        != sha256_hex(attestation.canonical_bytes())
    ):
        raise ValueError("feed v2 pointer assets do not match exact content")


def build_incident_feed_index_v2(
    *,
    active: tuple[IncidentFeedEntryV2, ...],
    recently_resolved: tuple[IncidentFeedEntryV2, ...],
    resolved_retention_start: UtcDateTime,
    resolved_history_truncated: bool,
    resolved_history_total_count: int,
    omitted_resolved_count: int | None,
    source_active_index_digest: Sha256Digest,
    key_id: str,
    key_fingerprint: Sha256Digest,
    published_at: UtcDateTime,
) -> IncidentFeedIndexV2:
    version_digest = _index_version_digest(
        active=active,
        recently_resolved=recently_resolved,
        resolved_retention_start=resolved_retention_start,
        resolved_history_truncated=resolved_history_truncated,
        resolved_history_total_count=resolved_history_total_count,
        omitted_resolved_count=omitted_resolved_count,
        source_active_index_digest=source_active_index_digest,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
        published_at=published_at,
    )
    return IncidentFeedIndexV2(
        schemaVersion="athena.wc027IncidentFeedIndex.v2",
        active=active,
        recentlyResolved=recently_resolved,
        resolvedRetentionStart=resolved_retention_start,
        resolvedHistoryTruncated=resolved_history_truncated,
        resolvedHistoryTotalCount=resolved_history_total_count,
        omittedResolvedCount=omitted_resolved_count,
        sourceActiveIndexDigest=source_active_index_digest,
        indexAttestationPath=(
            f"./incidents/feed-v2-index-attestations/{version_digest.removeprefix('sha256:')}.json"
        ),
        keyId=key_id,
        keyFingerprint=key_fingerprint,
        publishedAt=published_at,
    )


def validate_incident_feed_index_assets(
    index: IncidentFeedIndexV2,
    attestation: IncidentFeedIndexAttestationV2,
    *,
    trusted_key_id: str,
    trusted_key_fingerprint: Sha256Digest,
    expected_source_active_index_digest: Sha256Digest,
    not_older_than: UtcDateTime,
    signature_verifier: Callable[[bytes, str], bool],
) -> None:
    index = IncidentFeedIndexV2.model_validate_json(index.model_dump_json(by_alias=True))
    attestation = IncidentFeedIndexAttestationV2.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    index_bytes = index.canonical_bytes()
    digest = sha256_hex(index_bytes)
    if (
        index.key_id != trusted_key_id
        or index.key_fingerprint != trusted_key_fingerprint
        or index.source_active_index_digest != expected_source_active_index_digest
        or index.published_at < not_older_than
        or attestation.index_digest != digest
        or attestation.key_vault_key_id != trusted_key_id
        or signature_verifier(
            index_bytes,
            attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("incident feed v2 index assets do not match exact content")


__all__ = [
    "MAX_INCIDENT_FEED_V2_BYTES",
    "MAX_INCIDENT_FEED_V2_POINTER_BYTES",
    "IncidentEnrichmentFeedPointer",
    "IncidentEnrichmentFeedPointerAttestation",
    "IncidentFeedEntryV2",
    "IncidentFeedIndexAttestationV2",
    "IncidentFeedIndexV2",
    "build_incident_enrichment_feed_pointer",
    "build_incident_feed_index_v2",
    "validate_incident_enrichment_feed_pointer_assets",
    "validate_incident_feed_index_assets",
]
