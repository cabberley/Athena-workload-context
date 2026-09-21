from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from azure.core import MatchConditions
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.storage.blob import BlobServiceClient, BlobType, ContentSettings
from pydantic import ValidationError

from athena_context.azure_adapters import (
    _validate_blob_endpoint,
    _validate_container_name,
    production_managed_identity_credential,
)
from athena_context.contracts import (
    MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
    MAX_INCIDENT_FEED_V2_BYTES,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    VersionPinnedBlobReference,
    sha256_hex,
    validate_incident_feed_index_assets,
)
from athena_context.enrichment.feed_index_publication import (
    FEED_V2_INDEX_BLOB_NAME,
    IncidentFeedIndexCommitRequest,
    IncidentFeedIndexPublicationConflictError,
    IncidentFeedIndexPublicationError,
    IncidentFeedIndexSnapshot,
)


@dataclass(frozen=True, slots=True)
class _BlobValue:
    payload: bytes
    version_id: str
    etag: str


class AzureBlobIncidentFeedIndexPublisher:
    """Publish the signed feed-v2 head in the isolated v2 container without listing."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
        feed_key_id: str,
        feed_key_fingerprint: str,
        signature_verifier: Callable[[bytes, str], bool],
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if container_name != "wc027-enrichment-feed-v2":
            raise ValueError(
                "container_name must be exactly wc027-enrichment-feed-v2"
            )
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_put_size=MAX_INCIDENT_FEED_V2_BYTES,
            max_single_get_size=MAX_INCIDENT_FEED_V2_BYTES + 1,
            max_chunk_get_size=MAX_INCIDENT_FEED_V2_BYTES + 1,
        )
        self._container = service.get_container_client(container_name)
        self._feed_key_id = feed_key_id
        self._feed_key_fingerprint = feed_key_fingerprint
        self._signature_verifier = signature_verifier

    def read_current(self) -> IncidentFeedIndexSnapshot | None:
        index_value = self._read_blob(
            FEED_V2_INDEX_BLOB_NAME,
            maximum_bytes=MAX_INCIDENT_FEED_V2_BYTES,
            allow_missing=True,
        )
        if index_value is None:
            return None
        try:
            index = IncidentFeedIndexV2.model_validate_json(index_value.payload)
        except (ValidationError, ValueError) as exc:
            raise IncidentFeedIndexPublicationError("stable feed v2 index is invalid") from exc
        if index_value.payload != index.canonical_bytes():
            raise IncidentFeedIndexPublicationError("stable feed v2 index bytes are not canonical")
        attestation_value = self._read_blob(
            index.index_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            allow_missing=False,
        )
        assert attestation_value is not None
        try:
            attestation = IncidentFeedIndexAttestationV2.model_validate_json(
                attestation_value.payload
            )
        except (ValidationError, ValueError) as exc:
            raise IncidentFeedIndexPublicationError("feed v2 index attestation is invalid") from exc
        if attestation_value.payload != attestation.canonical_bytes():
            raise IncidentFeedIndexPublicationError(
                "feed v2 index attestation bytes are not canonical"
            )
        try:
            validate_incident_feed_index_assets(
                index,
                attestation,
                trusted_key_id=self._feed_key_id,
                trusted_key_fingerprint=self._feed_key_fingerprint,
                expected_source_active_index_digest=index.source_active_index_digest,
                not_older_than=index.published_at,
                signature_verifier=self._signature_verifier,
            )
        except ValueError as exc:
            raise IncidentFeedIndexPublicationError(
                "stable feed v2 index signature is invalid"
            ) from exc
        return IncidentFeedIndexSnapshot(
            index=index,
            attestation=attestation,
            index_reference=VersionPinnedBlobReference(
                name=FEED_V2_INDEX_BLOB_NAME,
                version=index_value.version_id,
                contentDigest=sha256_hex(index_value.payload),
            ),
            attestation_reference=VersionPinnedBlobReference(
                name=index.index_attestation_path.removeprefix("./"),
                version=attestation_value.version_id,
                contentDigest=sha256_hex(attestation_value.payload),
            ),
            etag=index_value.etag,
        )

    def compare_and_swap(
        self,
        request: IncidentFeedIndexCommitRequest,
        *,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> IncidentFeedIndexSnapshot:
        if type(request) is not IncidentFeedIndexCommitRequest:
            raise TypeError("request must be an exact IncidentFeedIndexCommitRequest")
        if before_irreversible_write is None:
            self._create_or_recover_attestation(request)
        else:
            self._create_or_recover_attestation(
                request,
                before_irreversible_write=before_irreversible_write,
            )
        blob = self._container.get_blob_client(FEED_V2_INDEX_BLOB_NAME)
        index_bytes = request.index.canonical_bytes()
        if before_irreversible_write is not None:
            before_irreversible_write()
        try:
            if request.expected_etag is None:
                response = blob.upload_blob(
                    index_bytes,
                    blob_type=BlobType.BLOCKBLOB,
                    length=len(index_bytes),
                    metadata={"payload_sha256": sha256_hex(index_bytes)},
                    overwrite=False,
                    match_condition=MatchConditions.IfMissing,
                    content_settings=ContentSettings(content_type="application/json"),
                )
            else:
                response = blob.upload_blob(
                    index_bytes,
                    blob_type=BlobType.BLOCKBLOB,
                    length=len(index_bytes),
                    metadata={"payload_sha256": sha256_hex(index_bytes)},
                    overwrite=True,
                    etag=request.expected_etag,
                    match_condition=MatchConditions.IfNotModified,
                    content_settings=ContentSettings(content_type="application/json"),
                )
        except (ResourceExistsError, ResourceModifiedError) as exc:
            raise IncidentFeedIndexPublicationConflictError(
                "stable feed v2 index changed during conditional publication"
            ) from exc
        except HttpResponseError as exc:
            if exc.status_code in {409, 412}:
                raise IncidentFeedIndexPublicationConflictError(
                    "stable feed v2 index changed during conditional publication"
                ) from exc
            raise IncidentFeedIndexPublicationError(
                "stable feed v2 index publication failed"
            ) from exc
        except (ServiceRequestError, ServiceResponseError) as exc:
            raise IncidentFeedIndexPublicationConflictError(
                "stable feed v2 index publication outcome is uncertain"
            ) from exc
        version_id = self._version_id(response)
        if version_id is None:
            current = self.read_current()
            if current is not None:
                return current
            raise IncidentFeedIndexPublicationError(
                "stable feed v2 upload omitted its version identifier"
            )
        current = self.read_current()
        if current is None:
            raise IncidentFeedIndexPublicationError(
                "stable feed v2 index disappeared after publication"
            )
        return current

    def _create_or_recover_attestation(
        self,
        request: IncidentFeedIndexCommitRequest,
        *,
        before_irreversible_write: Callable[[], None] | None = None,
    ) -> VersionPinnedBlobReference:
        attestation_bytes = request.attestation.canonical_bytes()
        blob_name = request.index.index_attestation_path.removeprefix("./")
        blob = self._container.get_blob_client(blob_name)
        if before_irreversible_write is not None:
            before_irreversible_write()
        try:
            response = blob.upload_blob(
                attestation_bytes,
                blob_type=BlobType.BLOCKBLOB,
                length=len(attestation_bytes),
                metadata={"payload_sha256": sha256_hex(attestation_bytes)},
                overwrite=False,
                match_condition=MatchConditions.IfMissing,
                content_settings=ContentSettings(content_type="application/json"),
            )
        except ResourceExistsError as exc:
            return self._recover_attestation(
                blob_name,
                attestation_bytes,
                cause=exc,
            )
        except (ServiceRequestError, ServiceResponseError) as exc:
            return self._recover_attestation(
                blob_name,
                attestation_bytes,
                cause=exc,
            )
        except HttpResponseError as exc:
            if exc.status_code == 409:
                return self._recover_attestation(
                    blob_name,
                    attestation_bytes,
                    cause=exc,
                )
            raise IncidentFeedIndexPublicationError(
                "feed v2 index attestation publication failed"
            ) from exc
        version_id = self._version_id(response)
        if version_id is None:
            return self._recover_attestation(
                blob_name,
                attestation_bytes,
                cause=IncidentFeedIndexPublicationError(
                    "feed v2 attestation upload omitted its version identifier"
                ),
            )
        return VersionPinnedBlobReference(
            name=blob_name,
            version=version_id,
            contentDigest=sha256_hex(attestation_bytes),
        )

    def _recover_attestation(
        self,
        blob_name: str,
        expected_payload: bytes,
        *,
        cause: BaseException,
    ) -> VersionPinnedBlobReference:
        existing = self._read_blob(
            blob_name,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
            allow_missing=False,
        )
        if existing is None or existing.payload != expected_payload:
            raise IncidentFeedIndexPublicationError(
                "feed v2 index attestation could not be recovered exactly"
            ) from cause
        return VersionPinnedBlobReference(
            name=blob_name,
            version=existing.version_id,
            contentDigest=sha256_hex(existing.payload),
        )

    def _read_blob(
        self,
        blob_name: str,
        *,
        maximum_bytes: int,
        allow_missing: bool,
    ) -> _BlobValue | None:
        blob = self._container.get_blob_client(blob_name)
        try:
            downloader = blob.download_blob(
                offset=0,
                length=maximum_bytes + 1,
                max_concurrency=1,
            )
            properties = downloader.properties
            payload = downloader.readall()
        except ResourceNotFoundError:
            if allow_missing:
                return None
            raise IncidentFeedIndexPublicationError(
                "feed v2 publication asset is unavailable"
            ) from None
        except HttpResponseError as exc:
            raise IncidentFeedIndexPublicationError(
                "feed v2 publication asset is unavailable"
            ) from exc
        content_settings = getattr(properties, "content_settings", None)
        metadata = getattr(properties, "metadata", None)
        version_id = self._version_id(properties)
        etag = getattr(properties, "etag", None)
        if (
            type(payload) is not bytes
            or not 1 <= len(payload) <= maximum_bytes
            or getattr(content_settings, "content_type", None) != "application/json"
            or type(metadata) is not dict
            or metadata.get("payload_sha256") != sha256_hex(payload)
            or version_id is None
            or type(etag) is not str
            or not etag
        ):
            raise IncidentFeedIndexPublicationError(
                "feed v2 publication asset metadata or version is invalid"
            )
        return _BlobValue(
            payload=payload,
            version_id=version_id,
            etag=etag,
        )

    @staticmethod
    def _version_id(value: object) -> str | None:
        candidate = (
            (value.get("version_id") or value.get("versionId"))
            if isinstance(value, dict)
            else getattr(value, "version_id", None)
        )
        return candidate if isinstance(candidate, str) and candidate else None


__all__ = ["AzureBlobIncidentFeedIndexPublisher"]
