from __future__ import annotations

import re

from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)

from athena_context.artifacts import (
    MAX_ARTIFACT_TRANSFER_BYTES,
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactReadError,
    ArtifactReadRequest,
    ArtifactWriteError,
    ArtifactWriteRequest,
)
from athena_context.azure_adapters import (
    AzureBlobCreateOnlyArtifactWriter,
    AzureBlobVersionPinnedArtifactReader,
)
from athena_context.contracts import VersionPinnedBlobReference

_ENRICHMENT_ASSET_PATH = re.compile(
    r"^incidents/inc-[a-f0-9]{12}/versions/[a-f0-9]{64}/"
    r"(?:"
    r"correlation-reports/report-[a-f0-9]{32}/(?:report|attestation)\.json"
    r"|guidance/incident-guidance-[a-f0-9]{32}/(?:guidance|attestation)\.json"
    r"|enrichments/incident-enrichment-[a-f0-9]{32}/(?:manifest|attestation)\.json"
    r")$"
)


class AzureBlobIncidentEnrichmentArtifactWriter:
    """Create or recover only immutable WC-027 incident-enrichment assets."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        if container_name != "incident-assets":
            raise ValueError("container_name must be exactly incident-assets")
        self._writer = AzureBlobCreateOnlyArtifactWriter(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
            max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
        )
        self._reader = AzureBlobVersionPinnedArtifactReader(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
            max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
        )

    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference:
        if type(request) is not ArtifactWriteRequest:
            raise TypeError("request must be an exact ArtifactWriteRequest")
        if _ENRICHMENT_ASSET_PATH.fullmatch(request.blob_name) is None:
            raise ValueError("artifact path is outside the incident enrichment boundary")
        try:
            receipt = self._writer.create(request)
        except (
            ArtifactAlreadyExistsError,
            ArtifactWriteError,
            ServiceRequestError,
            ServiceResponseError,
        ) as exc:
            return self._recover(request, cause=exc)
        if (
            receipt.blob_name != request.blob_name
            or receipt.payload_sha256 != request.hashes.payload_sha256
            or receipt.size_bytes != len(request.payload)
            or not receipt.version_id
        ):
            return self._recover(
                request,
                cause=ArtifactWriteError("create-only writer returned an invalid version receipt"),
            )
        exact = self._reader.read(
            ArtifactReadRequest(
                blob_name=request.blob_name,
                version_id=receipt.version_id,
                expected_payload_sha256=request.hashes.payload_sha256,
            )
        )
        if exact.payload != request.payload:
            raise ArtifactWriteError(
                "created incident enrichment version does not match requested bytes"
            )
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=receipt.version_id,
            contentDigest=request.hashes.payload_sha256,
        )

    def _recover(
        self,
        request: ArtifactWriteRequest,
        *,
        cause: BaseException,
    ) -> VersionPinnedBlobReference:
        try:
            current = self._reader.read_current(
                ArtifactCurrentReadRequest(blob_name=request.blob_name)
            )
        except (
            ArtifactReadError,
            HttpResponseError,
            ServiceRequestError,
            ServiceResponseError,
        ):
            raise ArtifactWriteError(
                "incident enrichment artifact could not be recovered"
            ) from cause
        if (
            current.payload != request.payload
            or current.payload_sha256 != request.hashes.payload_sha256
            or current.size_bytes != len(request.payload)
            or current.content_type != request.content_type
        ):
            raise ArtifactAlreadyExistsError(
                "incident enrichment artifact already exists with different content"
            ) from cause
        exact = self._reader.read(
            ArtifactReadRequest(
                blob_name=request.blob_name,
                version_id=current.version_id,
                expected_payload_sha256=request.hashes.payload_sha256,
            )
        )
        if exact != current:
            raise ArtifactWriteError(
                "recovered incident enrichment version changed during verification"
            ) from cause
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=current.version_id,
            contentDigest=request.hashes.payload_sha256,
        )


__all__ = ["AzureBlobIncidentEnrichmentArtifactWriter"]
