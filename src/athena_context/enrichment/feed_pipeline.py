from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from athena_context.artifacts import (
    ArtifactMetadataHashes,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    MAX_INCIDENT_FEED_V2_POINTER_BYTES,
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedEntryV2,
    IncidentOccurrenceReceipt,
    UtcDateTime,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    sha256_hex,
    validate_incident_enrichment_feed_pointer_assets,
)
from athena_context.enrichment.feed_index_publication import (
    MAX_FEED_V2_PUBLICATION_ATTEMPTS,
    IncidentFeedIndexPublicationConflictError,
    IncidentFeedIndexPublicationError,
    IncidentFeedIndexPublicationReceipt,
    VerifiedCurrentIncidentStateReaderPort,
)
from athena_context.enrichment.feed_registry import (
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryError,
    IncidentFeedRegistryIncompleteError,
    IncidentFeedRegistryPort,
    IncidentFeedRegistryRecord,
    build_incident_feed_registry_record,
    validate_incident_feed_registry_record_authority,
)
from athena_context.enrichment.publication import (
    IncidentEnrichmentArtifactWriterPort,
    IncidentEnrichmentPublicationReceipt,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import CurrentIncidentStateSnapshot

SignatureVerifier = Callable[[bytes, str], bool]


class IncidentFeedIndexPublicationPort(Protocol):
    feed_key_id: str

    def publish(
        self,
        *,
        published_at: UtcDateTime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentFeedIndexPublicationReceipt: ...


@dataclass(frozen=True, slots=True)
class IncidentEnrichmentFeedPublicationReceipt:
    enrichment_publication: IncidentEnrichmentPublicationReceipt
    pointer: IncidentEnrichmentFeedPointer
    pointer_attestation: IncidentEnrichmentFeedPointerAttestation
    registry_record: IncidentFeedRegistryRecord
    feed_index_publication: IncidentFeedIndexPublicationReceipt

    def __post_init__(self) -> None:
        entry = self.registry_record.entry
        collection = (
            self.feed_index_publication.index.active
            if entry.lifecycle == "active"
            else self.feed_index_publication.index.recently_resolved
        )
        if (
            self.pointer.enrichment_asset
            != self.enrichment_publication.enrichment_asset
            or self.registry_record.pointer != self.pointer
            or self.registry_record.pointer_attestation != self.pointer_attestation
            or tuple(item for item in collection if item.incident_id == entry.incident_id)
            != (entry,)
        ):
            raise ValueError(
                "feed publication receipt does not prove exact indexed enrichment"
            )


@dataclass(frozen=True, slots=True)
class IncidentEnrichmentFeedPublicationService:
    current_incident_reader: VerifiedCurrentIncidentStateReaderPort
    artifact_writer: IncidentEnrichmentArtifactWriterPort
    registry: IncidentFeedRegistryPort
    feed_index_publication: IncidentFeedIndexPublicationPort
    feed_key_id: str
    feed_signer: PresentationSigner
    feed_signature_verifier: SignatureVerifier

    def __post_init__(self) -> None:
        if type(self.feed_key_id) is not str or not self.feed_key_id:
            raise ValueError("feed_key_id must be a non-empty string")
        if self.feed_index_publication.feed_key_id != self.feed_key_id:
            raise ValueError(
                "feed pointer and feed index must use the same feed signing authority"
            )

    def publish(
        self,
        enrichment_publication: IncidentEnrichmentPublicationReceipt,
        *,
        published_at: UtcDateTime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentEnrichmentFeedPublicationReceipt:
        if type(enrichment_publication) is not IncidentEnrichmentPublicationReceipt:
            raise TypeError(
                "enrichment_publication must be an exact "
                "IncidentEnrichmentPublicationReceipt"
            )
        _require_canonical_timestamp(published_at)
        if published_at < enrichment_publication.published_at:
            raise ValueError(
                "feed index publication cannot predate enrichment publication"
            )
        if self.feed_key_id in {
            enrichment_publication.report_key_id,
            enrichment_publication.guidance_key_id,
            enrichment_publication.enrichment_key_id,
        }:
            raise ValueError(
                "feed signing authority must be distinct from enrichment authorities"
            )
        occurrence = IncidentOccurrenceReceipt.model_validate_json(
            enrichment_publication.occurrence.model_dump_json(by_alias=True)
        )
        enrichment_asset = IncidentEnrichmentAssetReference.model_validate_json(
            enrichment_publication.enrichment_asset.model_dump_json(by_alias=True)
        )
        current = self._read_current_occurrence(
            enrichment_publication,
            occurrence=occurrence,
        )
        pointer = build_incident_enrichment_feed_pointer(
            occurrence,
            enrichment_asset,
            current.state,
            published_at=enrichment_publication.published_at,
        )
        pointer_bytes = pointer.canonical_bytes()
        signature = _base64url_signature(
            self.feed_signer.sign_preimage(pointer_bytes)
        )
        if self.feed_signature_verifier(pointer_bytes, signature) is not True:
            raise ValueError("feed pointer signer failed immediate verification")
        pointer_attestation = IncidentEnrichmentFeedPointerAttestation(
            schemaVersion=(
                "athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"
            ),
            pointerId=pointer.pointer_id,
            pointerDigest=pointer.pointer_digest,
            signatureAlgorithm="RS256",
            keyVaultKeyId=self.feed_key_id,
            signedPreimageDigest=sha256_hex(pointer_bytes),
            detachedSignature=signature,
        )
        prefix = enrichment_asset.manifest_reference.name.removesuffix(
            "/manifest.json"
        )
        pointer_reference = self._write_asset(
            _artifact_request(
                f"{prefix}/feed-pointer.json",
                pointer_bytes,
            ),
            before_irreversible_write=before_irreversible_write,
        )
        attestation_reference = self._write_asset(
            _artifact_request(
                f"{prefix}/feed-pointer-attestation.json",
                pointer_attestation.canonical_bytes(),
            ),
            before_irreversible_write=before_irreversible_write,
        )
        entry = IncidentFeedEntryV2(
            incidentId=occurrence.incident_id,
            lifecycle=pointer.lifecycle,
            stateResultDigest=occurrence.state_result_digest,
            updatedAt=pointer.state_updated_at,
            feedPointerReference=pointer_reference,
            feedPointerAttestationReference=attestation_reference,
        )
        validate_incident_enrichment_feed_pointer_assets(
            entry,
            pointer,
            pointer_attestation,
            trusted_key_id=self.feed_key_id,
            signature_verifier=self.feed_signature_verifier,
        )
        record = build_incident_feed_registry_record(
            entry,
            pointer,
            pointer_attestation,
        )
        validate_incident_feed_registry_record_authority(record, current)
        self._put_or_recover_record(
            record,
            current=current,
            as_of=published_at,
            before_irreversible_write=before_irreversible_write,
        )
        index_published_at = published_at
        last_conflict: IncidentFeedIndexPublicationConflictError | None = None
        last_winner_published_at: UtcDateTime | None = None
        for _attempt in range(MAX_FEED_V2_PUBLICATION_ATTEMPTS):
            try:
                index_publication = self._publish_index(
                    published_at=index_published_at,
                    before_irreversible_write=before_irreversible_write,
                )
            except IncidentFeedIndexPublicationConflictError as exc:
                last_conflict = exc
                retry_after = exc.winner_published_at
                if retry_after is not None:
                    last_winner_published_at = max(
                        retry_after,
                        last_winner_published_at or retry_after,
                    )
                index_published_at = max(
                    index_published_at + timedelta(milliseconds=1),
                    (
                        index_published_at
                        if retry_after is None
                        else retry_after + timedelta(milliseconds=1)
                    ),
                )
                continue
            if self._contains_exact_index_entry(
                entry,
                index_publication=index_publication,
            ):
                return IncidentEnrichmentFeedPublicationReceipt(
                    enrichment_publication=enrichment_publication,
                    pointer=pointer,
                    pointer_attestation=pointer_attestation,
                    registry_record=record,
                    feed_index_publication=index_publication,
                )
            index_published_at = max(
                index_published_at,
                index_publication.index.published_at
                + timedelta(milliseconds=1),
            )
        if last_conflict is not None:
            raise IncidentFeedIndexPublicationConflictError(
                "feed index publication did not converge on the exact entry",
                winner_published_at=last_winner_published_at,
            ) from last_conflict
        raise IncidentFeedIndexPublicationError(
            "feed index did not publish the exact durable registry entry"
        )

    def _read_current_occurrence(
        self,
        enrichment_publication: IncidentEnrichmentPublicationReceipt,
        *,
        occurrence: IncidentOccurrenceReceipt,
    ) -> CurrentIncidentStateSnapshot:
        current = self.current_incident_reader.read_current_incident_state(
            incident_id=occurrence.incident_id
        )
        if type(current) is not CurrentIncidentStateSnapshot or current.occurrence is None:
            raise IncidentFeedRegistryIncompleteError(
                "feed pipeline requires authoritative current occurrence"
            )
        if (
            current.occurrence != occurrence
            or current.state.incident_id != occurrence.incident_id
            or current.state.transition_id != occurrence.transition_id
            or current.state.result_digest != occurrence.state_result_digest
            or current.pointer_sha256
            != occurrence.pointer_reference.content_digest
            or enrichment_publication.enrichment_asset.incident_id
            != occurrence.incident_id
            or enrichment_publication.enrichment_asset.incident_state_result_digest
            != occurrence.state_result_digest
        ):
            raise IncidentFeedRegistryConflictError(
                "enrichment publication does not match authoritative current occurrence"
            )
        return current

    def _write_asset(
        self,
        request: ArtifactWriteRequest,
        *,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> VersionPinnedBlobReference:
        if before_irreversible_write is not None:
            before_irreversible_write()
        reference = self.artifact_writer.create_or_recover(request)
        if (
            type(reference) is not VersionPinnedBlobReference
            or reference.name != request.blob_name
            or reference.content_digest != request.hashes.payload_sha256
        ):
            raise ValueError("feed pointer writer returned a mismatched reference")
        return reference

    def _put_or_recover_record(
        self,
        record: IncidentFeedRegistryRecord,
        *,
        current: CurrentIncidentStateSnapshot,
        as_of: UtcDateTime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> None:
        failure: IncidentFeedRegistryError | None = None
        try:
            if before_irreversible_write is None:
                self.registry.put(
                    record,
                    authority=current,
                )
            else:
                self.registry.put(
                    record,
                    authority=current,
                    before_irreversible_write=before_irreversible_write,
                )
        except IncidentFeedRegistryError as exc:
            failure = exc
        try:
            if before_irreversible_write is None:
                records = self.registry.list_records(as_of=as_of)
            else:
                records = self.registry.list_records(
                    as_of=as_of,
                    before_irreversible_write=before_irreversible_write,
                )
        except IncidentFeedRegistryError as recovery_error:
            if failure is not None:
                raise failure from recovery_error
            raise
        matches = tuple(
            item
            for item in records
            if item.entry.incident_id == record.entry.incident_id
        )
        if matches == (record,):
            latest = self.current_incident_reader.read_current_incident_state(
                incident_id=record.entry.incident_id
            )
            validate_incident_feed_registry_record_authority(
                record,
                latest,
            )
            return
        if matches:
            raise IncidentFeedRegistryConflictError(
                "feed registry contains a conflicting incident record"
            ) from failure
        if failure is not None:
            raise failure
        raise IncidentFeedRegistryIncompleteError(
            "feed registry did not durably retain the incident record"
        )

    def _publish_index(
        self,
        *,
        published_at: UtcDateTime,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentFeedIndexPublicationReceipt:
        if before_irreversible_write is None:
            return self.feed_index_publication.publish(published_at=published_at)
        return self.feed_index_publication.publish(
            published_at=published_at,
            before_irreversible_write=before_irreversible_write,
        )

    @staticmethod
    def _contains_exact_index_entry(
        entry: IncidentFeedEntryV2,
        *,
        index_publication: IncidentFeedIndexPublicationReceipt,
    ) -> bool:
        collection = (
            index_publication.index.active
            if entry.lifecycle == "active"
            else index_publication.index.recently_resolved
        )
        matches = tuple(
            item for item in collection if item.incident_id == entry.incident_id
        )
        return matches == (entry,)


def _artifact_request(
    blob_name: str,
    payload: bytes,
) -> ArtifactWriteRequest:
    return ArtifactWriteRequest(
        blob_name=blob_name,
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
        maximum_payload_bytes=MAX_INCIDENT_FEED_V2_POINTER_BYTES,
    )


def _require_canonical_timestamp(value: UtcDateTime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond % 1000
    ):
        raise ValueError(
            "published_at must be a UTC timestamp with millisecond precision"
        )


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("feed pointer signer returned invalid base64") from exc
    if not signature:
        raise ValueError("feed pointer signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


__all__ = [
    "IncidentEnrichmentFeedPublicationReceipt",
    "IncidentEnrichmentFeedPublicationService",
    "IncidentFeedIndexPublicationPort",
]
