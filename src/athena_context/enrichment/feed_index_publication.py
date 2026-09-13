from __future__ import annotations

import base64
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from athena_context.artifacts import (
    ArtifactReadError,
    ArtifactReadRequest,
    VersionPinnedArtifactReaderPort,
)
from athena_context.contracts import (
    ActiveIncidentIndex,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedEntryV2,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    UtcDateTime,
    VersionPinnedBlobReference,
    build_incident_feed_index_v2,
    sha256_hex,
    validate_incident_enrichment_feed_pointer_assets,
    validate_incident_feed_index_assets,
)
from athena_context.enrichment.feed_registry import (
    IncidentFeedRegistryConflictError,
    IncidentFeedRegistryIncompleteError,
    IncidentFeedRegistryPort,
    IncidentFeedRegistryProjection,
    IncidentFeedRegistryRecord,
    build_incident_feed_registry_record,
    project_incident_feed_registry,
    validate_incident_feed_registry_record_authority,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
)

FEED_V2_INDEX_BLOB_NAME = "incidents/feed-v2.json"
MAX_FEED_V2_PUBLICATION_ATTEMPTS = 4


class IncidentFeedIndexPublicationError(RuntimeError):
    """Base failure while publishing the stable feed-v2 discovery head."""


class IncidentFeedIndexPublicationConflictError(IncidentFeedIndexPublicationError):
    """The stable feed-v2 head changed during a conditional publication."""


class VerifiedActiveIncidentIndexReaderPort(Protocol):
    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None: ...


class VerifiedCurrentIncidentStateReaderPort(Protocol):
    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None: ...


@dataclass(frozen=True, slots=True)
class IncidentFeedIndexSnapshot:
    index: IncidentFeedIndexV2
    attestation: IncidentFeedIndexAttestationV2
    index_reference: VersionPinnedBlobReference
    attestation_reference: VersionPinnedBlobReference
    etag: str

    def __post_init__(self) -> None:
        index_bytes = self.index.canonical_bytes()
        attestation_bytes = self.attestation.canonical_bytes()
        if (
            self.index_reference.name != FEED_V2_INDEX_BLOB_NAME
            or self.index_reference.content_digest != sha256_hex(index_bytes)
            or self.attestation_reference.name
            != self.index.index_attestation_path.removeprefix("./")
            or self.attestation_reference.content_digest != sha256_hex(attestation_bytes)
            or self.attestation.index_digest != sha256_hex(index_bytes)
            or type(self.etag) is not str
            or not self.etag
        ):
            raise ValueError("feed v2 snapshot does not bind exact versioned assets")


@dataclass(frozen=True, slots=True)
class IncidentFeedIndexCommitRequest:
    index: IncidentFeedIndexV2
    attestation: IncidentFeedIndexAttestationV2
    expected_etag: str | None

    def __post_init__(self) -> None:
        if self.attestation.index_digest != sha256_hex(self.index.canonical_bytes()):
            raise ValueError("feed v2 attestation does not bind the index")
        if self.expected_etag is not None and (
            type(self.expected_etag) is not str or not self.expected_etag
        ):
            raise ValueError("expected_etag must be a non-empty opaque value")


class IncidentFeedIndexPublisherPort(Protocol):
    def read_current(self) -> IncidentFeedIndexSnapshot | None: ...

    def compare_and_swap(
        self,
        request: IncidentFeedIndexCommitRequest,
    ) -> IncidentFeedIndexSnapshot: ...


@dataclass(frozen=True, slots=True)
class IncidentFeedIndexPublicationReceipt:
    index: IncidentFeedIndexV2
    index_reference: VersionPinnedBlobReference
    attestation_reference: VersionPinnedBlobReference


@dataclass(frozen=True, slots=True)
class IncidentFeedIndexPublicationService:
    active_index_reader: VerifiedActiveIncidentIndexReaderPort
    current_incident_reader: VerifiedCurrentIncidentStateReaderPort
    registry: IncidentFeedRegistryPort
    pointer_reader: VersionPinnedArtifactReaderPort
    publisher: IncidentFeedIndexPublisherPort
    feed_key_id: str
    feed_key_fingerprint: str
    signer: PresentationSigner
    signature_verifier: Callable[[bytes, str], bool]

    def __post_init__(self) -> None:
        if type(self.feed_key_id) is not str or not self.feed_key_id:
            raise ValueError("feed_key_id must be a non-empty string")
        if (
            type(self.feed_key_fingerprint) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}", self.feed_key_fingerprint) is None
        ):
            raise ValueError("feed_key_fingerprint must be a lowercase sha256 digest")

    def publish(
        self,
        *,
        published_at: UtcDateTime,
    ) -> IncidentFeedIndexPublicationReceipt:
        _require_canonical_timestamp(published_at)
        for _attempt in range(MAX_FEED_V2_PUBLICATION_ATTEMPTS):
            source = self._read_source_authority()
            if published_at < source.index.published_at:
                winner = self.publisher.read_current()
                if winner is not None:
                    winner_pointers = self._verify_snapshot(winner)
                    if (
                        winner.index.source_active_index_digest == source.payload_sha256
                        and winner.index.published_at >= source.index.published_at
                    ):
                        if self._winner_matches_current_authority(
                            winner,
                            pointers=winner_pointers,
                        ):
                            return self._receipt(winner)
                        continue
            effective_published_at = max(published_at, source.index.published_at)
            candidate, attestation, projection = self._build_candidate(
                source=source,
                published_at=effective_published_at,
            )
            current = self.publisher.read_current()
            current_pointers: dict[
                str,
                tuple[
                    IncidentEnrichmentFeedPointer,
                    IncidentEnrichmentFeedPointerAttestation,
                ],
            ] | None = None
            if current is not None:
                current_pointers = self._verify_snapshot(current)
            fresh_source = self._read_source_authority()
            if fresh_source.payload_sha256 != source.payload_sha256:
                continue
            source = fresh_source
            if current is not None:
                assert current_pointers is not None
                decision = self._classify_current(
                    current=current,
                    current_pointers=current_pointers,
                    candidate=candidate,
                    source=source,
                )
                if decision == "accept":
                    if self._winner_matches_current_authority(
                        current,
                        pointers=current_pointers,
                    ):
                        self.registry.prune_expired(projection.prune_plan)
                        return self._receipt(current)
                    continue
                if decision == "retry":
                    continue
            try:
                committed = self.publisher.compare_and_swap(
                    IncidentFeedIndexCommitRequest(
                        index=candidate,
                        attestation=attestation,
                        expected_etag=None if current is None else current.etag,
                    )
                )
            except IncidentFeedIndexPublicationConflictError:
                winner = self.publisher.read_current()
                if winner is not None:
                    winner_pointers = self._verify_snapshot(winner)
                    if winner.index.canonical_bytes() == candidate.canonical_bytes():
                        if self._winner_matches_current_authority(
                            winner,
                            pointers=winner_pointers,
                        ):
                            self.registry.prune_expired(projection.prune_plan)
                            return self._receipt(winner)
                        continue
                    decision = self._classify_current(
                        current=winner,
                        current_pointers=winner_pointers,
                        candidate=candidate,
                        source=source,
                    )
                    if decision == "accept" and self._winner_matches_current_authority(
                        winner,
                        pointers=winner_pointers,
                    ):
                        self.registry.prune_expired(projection.prune_plan)
                        return self._receipt(winner)
                continue
            committed_pointers = self._verify_snapshot(committed)
            if committed.index.canonical_bytes() != candidate.canonical_bytes():
                continue
            latest_source = self._read_source_authority()
            if latest_source.payload_sha256 != candidate.source_active_index_digest:
                continue
            if not self._winner_matches_current_authority(
                committed,
                pointers=committed_pointers,
            ):
                continue
            self.registry.prune_expired(projection.prune_plan)
            return self._receipt(committed)
        raise IncidentFeedIndexPublicationConflictError(
            "feed v2 publication did not converge within its bounded retry limit"
        )

    def _build_candidate(
        self,
        *,
        source: ActiveIncidentIndexSnapshot,
        published_at: UtcDateTime,
    ) -> tuple[
        IncidentFeedIndexV2,
        IncidentFeedIndexAttestationV2,
        IncidentFeedRegistryProjection,
    ]:
        projection = self._project_registry(
            source=source,
            published_at=published_at,
        )
        index = build_incident_feed_index_v2(
            active=projection.active,
            recently_resolved=projection.recently_resolved,
            resolved_retention_start=projection.resolved_retention_start,
            resolved_history_truncated=projection.resolved_history_truncated,
            resolved_history_total_count=projection.resolved_history_total_count,
            omitted_resolved_count=projection.omitted_resolved_count,
            source_active_index_digest=source.payload_sha256,
            key_id=self.feed_key_id,
            key_fingerprint=self.feed_key_fingerprint,
            published_at=published_at,
        )
        index_bytes = index.canonical_bytes()
        signature = _base64url_signature(self.signer.sign_preimage(index_bytes))
        if self.signature_verifier(index_bytes, signature) is not True:
            raise ValueError("feed v2 index signer failed immediate verification")
        attestation = IncidentFeedIndexAttestationV2(
            schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
            indexDigest=sha256_hex(index_bytes),
            signatureAlgorithm="RS256",
            keyVaultKeyId=self.feed_key_id,
            detachedSignature=signature,
        )
        validate_incident_feed_index_assets(
            index,
            attestation,
            trusted_key_id=self.feed_key_id,
            trusted_key_fingerprint=self.feed_key_fingerprint,
            expected_source_active_index_digest=source.payload_sha256,
            not_older_than=source.index.published_at,
            signature_verifier=self.signature_verifier,
        )
        return index, attestation, projection

    def _classify_current(
        self,
        *,
        current: IncidentFeedIndexSnapshot,
        current_pointers: dict[
            str,
            tuple[
                IncidentEnrichmentFeedPointer,
                IncidentEnrichmentFeedPointerAttestation,
            ],
        ],
        candidate: IncidentFeedIndexV2,
        source: ActiveIncidentIndexSnapshot,
    ) -> Literal["accept", "replace", "retry"]:
        current_bytes = current.index.canonical_bytes()
        if current_bytes == candidate.canonical_bytes():
            _validate_active_mirror(
                current.index,
                source.index,
                pointers=current_pointers,
            )
            return "accept"
        if current.index.source_active_index_digest == source.payload_sha256:
            _validate_active_mirror(
                current.index,
                source.index,
                pointers=current_pointers,
            )
            if current.index.published_at > candidate.published_at:
                return "accept"
            if current.index.published_at == candidate.published_at:
                raise IncidentFeedIndexPublicationConflictError(
                    "feed v2 authority has conflicting content at the same timestamp"
                )
            return "replace"

        latest_source = self._read_source_authority()
        if latest_source.payload_sha256 == current.index.source_active_index_digest:
            _validate_active_mirror(
                current.index,
                latest_source.index,
                pointers=current_pointers,
            )
            if current.index.published_at < latest_source.index.published_at:
                raise IncidentFeedIndexPublicationConflictError(
                    "feed v2 winner predates its v1 lifecycle authority"
                )
            return "accept"
        if latest_source.payload_sha256 != source.payload_sha256:
            return "retry"
        return "replace"

    def _winner_matches_current_authority(
        self,
        winner: IncidentFeedIndexSnapshot,
        *,
        pointers: dict[
            str,
            tuple[
                IncidentEnrichmentFeedPointer,
                IncidentEnrichmentFeedPointerAttestation,
            ],
        ],
    ) -> bool:
        latest_source = self._read_source_authority()
        if (
            winner.index.source_active_index_digest != latest_source.payload_sha256
            or winner.index.published_at < latest_source.index.published_at
        ):
            return False
        try:
            _validate_active_mirror(
                winner.index,
                latest_source.index,
                pointers=pointers,
            )
            for entry in (*winner.index.active, *winner.index.recently_resolved):
                pointer, attestation = pointers[entry.incident_id]
                current = self.current_incident_reader.read_current_incident_state(
                    incident_id=entry.incident_id
                )
                validate_incident_feed_registry_record_authority(
                    build_incident_feed_registry_record(
                        entry,
                        pointer,
                        attestation,
                    ),
                    current,
                )
        except (
            IncidentFeedRegistryConflictError,
            IncidentFeedRegistryIncompleteError,
        ):
            return False
        return True

    def _project_registry(
        self,
        *,
        source: ActiveIncidentIndexSnapshot,
        published_at: UtcDateTime,
    ) -> IncidentFeedRegistryProjection:
        records = self._read_verified_registry_records(published_at=published_at)
        current_incidents: dict[str, CurrentIncidentStateSnapshot] = {}
        for incident_id in sorted({record.entry.incident_id for record in records}):
            current = self.current_incident_reader.read_current_incident_state(
                incident_id=incident_id
            )
            if current is None:
                raise IncidentFeedRegistryIncompleteError(
                    "feed registry is missing authoritative current occurrence"
                )
            current_incidents[incident_id] = current
        return project_incident_feed_registry(
            records,
            source_active_index=source.index,
            source_current_incidents=current_incidents,
            as_of=published_at,
            trusted_feed_key_id=self.feed_key_id,
            feed_signature_verifier=self.signature_verifier,
        )

    def _read_verified_registry_records(
        self,
        *,
        published_at: UtcDateTime,
    ) -> tuple[IncidentFeedRegistryRecord, ...]:
        records = self.registry.list_records(as_of=published_at)
        for record in records:
            pointer, attestation = self._read_pointer_assets(record.entry)
            if pointer != record.pointer or attestation != record.pointer_attestation:
                raise IncidentFeedIndexPublicationError(
                    "feed registry immutable asset does not match its retained record"
                )
        return records

    def _read_pointer_assets(
        self,
        entry: IncidentFeedEntryV2,
    ) -> tuple[
        IncidentEnrichmentFeedPointer,
        IncidentEnrichmentFeedPointerAttestation,
    ]:
        payloads: list[bytes] = []
        for reference in (
            entry.feed_pointer_reference,
            entry.feed_pointer_attestation_reference,
        ):
            try:
                result = self.pointer_reader.read(
                    ArtifactReadRequest(
                        blob_name=reference.name,
                        version_id=reference.version,
                        expected_payload_sha256=reference.content_digest,
                    )
                )
            except ArtifactReadError as exc:
                raise IncidentFeedIndexPublicationError(
                    "feed v2 references an unavailable immutable asset"
                ) from exc
            if (
                result.blob_name != reference.name
                or result.version_id != reference.version
                or result.payload_sha256 != reference.content_digest
                or sha256_hex(result.payload) != reference.content_digest
                or result.size_bytes != len(result.payload)
                or result.content_type != "application/json"
            ):
                raise IncidentFeedIndexPublicationError(
                    "feed v2 immutable asset does not match its exact reference"
                )
            payloads.append(result.payload)
        try:
            pointer = IncidentEnrichmentFeedPointer.model_validate_json(payloads[0])
            attestation = IncidentEnrichmentFeedPointerAttestation.model_validate_json(payloads[1])
        except ValueError as exc:
            raise IncidentFeedIndexPublicationError(
                "feed v2 immutable pointer assets are invalid"
            ) from exc
        if payloads[0] != pointer.canonical_bytes() or payloads[1] != attestation.canonical_bytes():
            raise IncidentFeedIndexPublicationError(
                "feed v2 immutable pointer assets are not canonical"
            )
        try:
            validate_incident_enrichment_feed_pointer_assets(
                entry,
                pointer,
                attestation,
                trusted_key_id=self.feed_key_id,
                signature_verifier=self.signature_verifier,
            )
        except ValueError as exc:
            raise IncidentFeedIndexPublicationError(
                "feed v2 immutable pointer assets failed verification"
            ) from exc
        return pointer, attestation

    def _verify_snapshot(
        self,
        snapshot: IncidentFeedIndexSnapshot,
    ) -> dict[
        str,
        tuple[
            IncidentEnrichmentFeedPointer,
            IncidentEnrichmentFeedPointerAttestation,
        ],
    ]:
        validate_incident_feed_index_assets(
            snapshot.index,
            snapshot.attestation,
            trusted_key_id=self.feed_key_id,
            trusted_key_fingerprint=self.feed_key_fingerprint,
            expected_source_active_index_digest=(snapshot.index.source_active_index_digest),
            not_older_than=snapshot.index.published_at,
            signature_verifier=self.signature_verifier,
        )
        pointers: dict[
            str,
            tuple[
                IncidentEnrichmentFeedPointer,
                IncidentEnrichmentFeedPointerAttestation,
            ],
        ] = {}
        for entry in (*snapshot.index.active, *snapshot.index.recently_resolved):
            pointers[entry.incident_id] = self._read_pointer_assets(entry)
        return pointers

    def _read_source_authority(self) -> ActiveIncidentIndexSnapshot:
        source = self.active_index_reader.read_active_incident_index()
        if source is None:
            raise IncidentFeedRegistryIncompleteError(
                "signed v1 active incident index is unavailable"
            )
        if source.payload_sha256 != sha256_hex(source.index.canonical_bytes()):
            raise IncidentFeedRegistryIncompleteError(
                "signed v1 active incident index digest is invalid"
            )
        return source

    @staticmethod
    def _receipt(
        snapshot: IncidentFeedIndexSnapshot,
    ) -> IncidentFeedIndexPublicationReceipt:
        return IncidentFeedIndexPublicationReceipt(
            index=snapshot.index,
            index_reference=snapshot.index_reference,
            attestation_reference=snapshot.attestation_reference,
        )


def _validate_active_mirror(
    index: IncidentFeedIndexV2,
    source: ActiveIncidentIndex,
    *,
    pointers: dict[
        str,
        tuple[
            IncidentEnrichmentFeedPointer,
            IncidentEnrichmentFeedPointerAttestation,
        ],
    ]
    | None = None,
) -> None:
    source_by_id = {entry.incident_id: entry for entry in source.incidents}
    if {entry.incident_id for entry in index.active} != set(source_by_id):
        raise IncidentFeedIndexPublicationConflictError(
            "feed v2 active set does not match the v1 lifecycle authority"
        )
    for entry in index.active:
        source_entry = source_by_id[entry.incident_id]
        expected_digest = source_entry.pointer_path.removeprefix(
            f"./incidents/{entry.incident_id}/versions/"
        ).removesuffix("/pointer.json")
        if (
            entry.state_result_digest != f"sha256:{expected_digest}"
            or entry.updated_at != source_entry.updated_at
            or (
                pointers is not None
                and (
                    pointers[entry.incident_id][0].source_pointer_reference.name
                    != source_entry.pointer_path.removeprefix("./")
                    or pointers[entry.incident_id][0].source_pointer_reference.content_digest
                    != source_entry.pointer_sha256
                )
            )
        ):
            raise IncidentFeedIndexPublicationConflictError(
                "feed v2 active entry does not match the v1 lifecycle authority"
            )


def _require_canonical_timestamp(value: UtcDateTime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond % 1000
    ):
        raise ValueError("published_at must be a UTC timestamp with millisecond precision")


def _base64url_signature(value: str) -> str:
    try:
        signature = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("feed v2 signer returned invalid base64") from exc
    if not signature:
        raise ValueError("feed v2 signer returned an empty signature")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


__all__ = [
    "FEED_V2_INDEX_BLOB_NAME",
    "MAX_FEED_V2_PUBLICATION_ATTEMPTS",
    "IncidentFeedIndexCommitRequest",
    "IncidentFeedIndexPublicationConflictError",
    "IncidentFeedIndexPublicationError",
    "IncidentFeedIndexPublicationReceipt",
    "IncidentFeedIndexPublicationService",
    "IncidentFeedIndexPublisherPort",
    "IncidentFeedIndexSnapshot",
    "VerifiedActiveIncidentIndexReaderPort",
    "VerifiedCurrentIncidentStateReaderPort",
]
