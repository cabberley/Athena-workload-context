from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from datetime import timedelta
from typing import Any, cast

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
from athena_context.contracts import (
    WC027_GUIDANCE_FEED_TRIGGER_RECOVERY_SECONDS,
    WC027_GUIDANCE_PUBLICATION_REQUEST_MAX_LIFETIME_SECONDS,
    GuidanceAuthorityPublicationRequest,
    VersionPinnedBlobReference,
)
from athena_context.guidance.request_publication import (
    GuidancePublicationRequestDeliveryBudget,
    GuidancePublicationRequestSenderSessionPort,
    guidance_publication_request_broker_properties,
)

_GUIDANCE_REQUEST_OUTBOX_PATH = re.compile(
    r"^guidance-publication-requests/"
    r"incident-occurrence-[a-f0-9]{32}/request\.json$"
)


class AzureBlobGuidancePublicationRequestOutbox:
    """Create or recover one immutable publication request per occurrence."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        writer_managed_identity_client_id: str,
        reader_managed_identity_client_id: str,
    ) -> None:
        if container_name != "wc027-guidance-request-outbox":
            raise ValueError("container_name must be exactly wc027-guidance-request-outbox")
        self._writer = AzureBlobCreateOnlyArtifactWriter(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=writer_managed_identity_client_id,
            max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
        )
        self._reader = AzureBlobVersionPinnedArtifactReader(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=reader_managed_identity_client_id,
            max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
        )

    def create_or_recover(
        self,
        request: ArtifactWriteRequest,
    ) -> VersionPinnedBlobReference:
        if type(request) is not ArtifactWriteRequest:
            raise TypeError("request must be an exact ArtifactWriteRequest")
        if _GUIDANCE_REQUEST_OUTBOX_PATH.fullmatch(request.blob_name) is None:
            raise ValueError("artifact path is outside the guidance request outbox")
        try:
            receipt = self._writer.create(request)
        except (
            ArtifactAlreadyExistsError,
            ArtifactWriteError,
            ServiceRequestError,
            ServiceResponseError,
        ) as exc:
            return self._recover(request, cause=exc)
        try:
            exact = self._reader.read(
                ArtifactReadRequest(
                    blob_name=request.blob_name,
                    version_id=receipt.version_id,
                    expected_payload_sha256=request.hashes.payload_sha256,
                )
            )
        except (
            ArtifactReadError,
            HttpResponseError,
            ServiceRequestError,
            ServiceResponseError,
        ) as exc:
            raise ArtifactWriteError(
                "created guidance request outbox version could not be verified"
            ) from exc
        if (
            receipt.blob_name != request.blob_name
            or receipt.payload_sha256 != request.hashes.payload_sha256
            or receipt.size_bytes != len(request.payload)
            or exact.payload != request.payload
            or exact.content_type != request.content_type
        ):
            raise ArtifactWriteError(
                "created guidance request outbox version does not match requested bytes"
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
                "guidance request outbox artifact could not be recovered"
            ) from cause
        if (
            current.payload != request.payload
            or current.payload_sha256 != request.hashes.payload_sha256
            or current.size_bytes != len(request.payload)
            or current.content_type != request.content_type
        ):
            raise ArtifactAlreadyExistsError(
                "guidance request occurrence slot contains different content"
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
                "recovered guidance request outbox version changed during verification"
            ) from cause
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=current.version_id,
            contentDigest=request.hashes.payload_sha256,
        )


class AzureServiceBusGuidancePublicationRequestSender:
    def __init__(self, sender: object) -> None:
        self._sender = sender

    def open(
        self,
    ) -> AbstractContextManager[GuidancePublicationRequestSenderSessionPort]:
        return nullcontext(self)

    def enqueue(
        self,
        request: GuidanceAuthorityPublicationRequest,
        *,
        outbox_reference: VersionPinnedBlobReference,
        time_to_live_seconds: int,
        delivery_budget: GuidancePublicationRequestDeliveryBudget,
    ) -> None:
        from azure.servicebus import ServiceBusMessage

        if type(request) is not GuidanceAuthorityPublicationRequest:
            raise TypeError("request must be an exact GuidanceAuthorityPublicationRequest")
        if type(delivery_budget) is not GuidancePublicationRequestDeliveryBudget:
            raise TypeError(
                "delivery_budget must be an exact GuidancePublicationRequestDeliveryBudget"
            )
        if not (
            delivery_budget.minimum_remaining_lifetime_seconds
            + delivery_budget.feed_trigger_recovery_seconds
            - delivery_budget.publisher_processing_seconds
            <= time_to_live_seconds
            <= WC027_GUIDANCE_PUBLICATION_REQUEST_MAX_LIFETIME_SECONDS
            + WC027_GUIDANCE_FEED_TRIGGER_RECOVERY_SECONDS
            - delivery_budget.publisher_processing_seconds
        ):
            raise ValueError(
                "guidance publication request TTL does not retain the reviewed "
                "downstream delivery budget"
            )
        message = ServiceBusMessage(
            request.canonical_bytes(),
            content_type="application/json",
            message_id=request.request_id,
            session_id=request.incident_bound_request.incident_subject.incident_id,
            time_to_live=timedelta(seconds=time_to_live_seconds),
            application_properties=guidance_publication_request_broker_properties(
                request,
                outbox_reference=outbox_reference,
                delivery_budget=delivery_budget,
            ),
        )
        cast(Any, self._sender).send_messages(message)


class ManagedIdentityGuidancePublicationRequestSender:
    """Open the output queue only after all request verification and persistence."""

    def __init__(
        self,
        *,
        fully_qualified_namespace: str,
        queue_name: str,
        managed_identity_client_id: str,
    ) -> None:
        self._fully_qualified_namespace = fully_qualified_namespace
        self._queue_name = queue_name
        self._managed_identity_client_id = managed_identity_client_id

    @contextmanager
    def open(self) -> Iterator[GuidancePublicationRequestSenderSessionPort]:
        from azure.identity import ManagedIdentityCredential
        from azure.servicebus import ServiceBusClient

        credential = ManagedIdentityCredential(client_id=self._managed_identity_client_id)
        with (
            ServiceBusClient(
                fully_qualified_namespace=self._fully_qualified_namespace,
                credential=credential,
                logging_enable=False,
            ) as client,
            client.get_queue_sender(queue_name=self._queue_name) as sender,
        ):
            yield AzureServiceBusGuidancePublicationRequestSender(sender)


__all__ = [
    "AzureBlobGuidancePublicationRequestOutbox",
    "AzureServiceBusGuidancePublicationRequestSender",
    "ManagedIdentityGuidancePublicationRequestSender",
]
