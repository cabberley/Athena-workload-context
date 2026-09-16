from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, cast

from azure.core import MatchConditions
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.data.tables import TableClient, UpdateMode

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
    production_managed_identity_credential,
)
from athena_context.contracts import (
    WC027_GUIDANCE_ACTIVATION_MAX_LIFETIME_SECONDS,
    GuidancePublicationRequestDeliveryBudget,
    PublishedGuidanceAuthorityActivation,
    PublishedGuidanceAuthorityBinding,
    VersionPinnedBlobReference,
)
from athena_context.guidance.publication import (
    GuidanceAuthorityActivationConflictError,
    GuidanceAuthorityActivationSnapshot,
)

_GUIDANCE_AUTHORITY_ASSET_PATH = re.compile(
    r"^(?:guidance-authority/guidance-authority-[a-f0-9]{32}/authority"
    r"|guidance-bindings/guidance-binding-[a-f0-9]{32}/binding)\.json$"
)


class AzureBlobGuidanceAuthorityArtifactWriter:
    """Create or recover exact immutable WC-027 authority assets."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        writer_managed_identity_client_id: str,
        reader_managed_identity_client_id: str,
    ) -> None:
        if container_name != "wc027-guidance-authority":
            raise ValueError(
                "container_name must be exactly wc027-guidance-authority"
            )
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
        if _GUIDANCE_AUTHORITY_ASSET_PATH.fullmatch(request.blob_name) is None:
            raise ValueError("artifact path is outside guidance authority storage")
        try:
            receipt = self._writer.create(request)
        except (
            ArtifactAlreadyExistsError,
            ArtifactWriteError,
            ServiceRequestError,
            ServiceResponseError,
        ) as exc:
            return self._recover(request, cause=exc)
        exact = self._reader.read(
            ArtifactReadRequest(
                blob_name=request.blob_name,
                version_id=receipt.version_id,
                expected_payload_sha256=request.hashes.payload_sha256,
            )
        )
        if (
            receipt.blob_name != request.blob_name
            or receipt.payload_sha256 != request.hashes.payload_sha256
            or receipt.size_bytes != len(request.payload)
            or exact.payload != request.payload
        ):
            raise ArtifactWriteError(
                "created guidance authority version does not match requested bytes"
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
                "guidance authority artifact could not be recovered"
            ) from cause
        if (
            current.payload != request.payload
            or current.payload_sha256 != request.hashes.payload_sha256
            or current.size_bytes != len(request.payload)
            or current.content_type != request.content_type
        ):
            raise ArtifactAlreadyExistsError(
                "guidance authority artifact exists with different content"
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
                "recovered guidance authority version changed during verification"
            ) from cause
        return VersionPinnedBlobReference(
            name=request.blob_name,
            version=current.version_id,
            contentDigest=request.hashes.payload_sha256,
        )

    def read_reference(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes:
        if type(reference) is not VersionPinnedBlobReference:
            raise TypeError(
                "reference must be an exact VersionPinnedBlobReference"
            )
        if _GUIDANCE_AUTHORITY_ASSET_PATH.fullmatch(reference.name) is None:
            raise ValueError("artifact path is outside guidance authority storage")
        return self._reader.read(
            ArtifactReadRequest(
                blob_name=reference.name,
                version_id=reference.version,
                expected_payload_sha256=reference.content_digest,
            )
        ).payload


class AzureTableGuidanceAuthorityActivationStore:
    """CAS store for one active authority binding per incident."""

    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        partition_key: str,
        managed_identity_client_id: str,
    ) -> None:
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        self._table = TableClient(
            endpoint=endpoint,
            table_name=table_name,
            credential=credential,
        )
        self._partition_key = partition_key

    def read_current(
        self,
        *,
        incident_id: str,
    ) -> GuidanceAuthorityActivationSnapshot | None:
        try:
            entity = self._table.get_entity(
                partition_key=self._partition_key,
                row_key=incident_id,
            )
        except ResourceNotFoundError:
            return None
        return self._snapshot(entity)

    def compare_and_swap(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        *,
        expected_etag: str | None,
    ) -> GuidanceAuthorityActivationSnapshot:
        entity = {
            "PartitionKey": self._partition_key,
            "RowKey": activation.incident_id,
            "activationDigest": activation.activation_digest,
            "payload": activation.canonical_bytes().decode("utf-8"),
            "triggerDeliveryStatus": "pending",
        }
        try:
            if expected_etag is None:
                metadata = self._table.create_entity(entity=entity)
            else:
                metadata = self._table.update_entity(
                    entity=entity,
                    mode=UpdateMode.REPLACE,
                    etag=expected_etag,
                    match_condition=MatchConditions.IfNotModified,
                )
        except (ResourceExistsError, ResourceModifiedError) as exc:
            raise GuidanceAuthorityActivationConflictError(
                "guidance authority activation CAS conflict"
            ) from exc
        etag = self._operation_etag(metadata)
        return GuidanceAuthorityActivationSnapshot(
            activation=activation,
            etag=etag,
            trigger_delivery_status="pending",
        )

    def mark_feed_materialized(
        self,
        activation: PublishedGuidanceAuthorityActivation,
        *,
        expected_etag: str,
    ) -> GuidanceAuthorityActivationSnapshot:
        entity = {
            "PartitionKey": self._partition_key,
            "RowKey": activation.incident_id,
            "activationDigest": activation.activation_digest,
            "payload": activation.canonical_bytes().decode("utf-8"),
            "triggerDeliveryStatus": "materialized",
        }
        try:
            metadata = self._table.update_entity(
                entity=entity,
                mode=UpdateMode.REPLACE,
                etag=expected_etag,
                match_condition=MatchConditions.IfNotModified,
            )
        except (ResourceModifiedError, ResourceNotFoundError) as exc:
            raise GuidanceAuthorityActivationConflictError(
                "guidance feed materialization status CAS conflict"
            ) from exc
        except (
            HttpResponseError,
            ServiceRequestError,
            ServiceResponseError,
        ):
            current = self.read_current(incident_id=activation.incident_id)
            if (
                current is None
                or current.activation != activation
                or current.trigger_delivery_status != "materialized"
            ):
                raise
            return current
        return GuidanceAuthorityActivationSnapshot(
            activation=activation,
            etag=self._operation_etag(metadata),
            trigger_delivery_status="materialized",
        )

    def _snapshot(
        self,
        entity: Any,
    ) -> GuidanceAuthorityActivationSnapshot:
        payload = entity.get("payload")
        if not isinstance(payload, str) or not payload:
            raise ValueError("guidance activation row payload is invalid")
        activation = PublishedGuidanceAuthorityActivation.model_validate_json(
            payload
        )
        stored_status = entity.get("triggerDeliveryStatus")
        if (
            activation.incident_id != entity.get("RowKey")
            or activation.activation_digest != entity.get("activationDigest")
            or payload.encode("utf-8") != activation.canonical_bytes()
            or stored_status not in {"pending", "submitted", "materialized"}
        ):
            raise ValueError("guidance activation row is not canonical")
        return GuidanceAuthorityActivationSnapshot(
            activation=activation,
            etag=self._entity_etag(entity),
            trigger_delivery_status=(
                "pending" if stored_status == "submitted" else stored_status
            ),
        )

    @staticmethod
    def _operation_etag(metadata: Any) -> str:
        if not isinstance(metadata, dict):
            metadata = getattr(metadata, "metadata", None)
        etag = metadata.get("etag") if isinstance(metadata, dict) else None
        if not isinstance(etag, str) or not etag:
            raise ValueError("guidance activation write returned no etag")
        return etag

    @staticmethod
    def _entity_etag(entity: Any) -> str:
        metadata = getattr(entity, "metadata", None)
        etag = metadata.get("etag") if isinstance(metadata, dict) else None
        if not isinstance(etag, str) or not etag:
            raise ValueError("guidance activation row has no etag")
        return etag


class AzureServiceBusGuidanceAuthorityTrigger:
    def __init__(self, sender: object) -> None:
        self._sender = sender

    def enqueue(
        self,
        binding: PublishedGuidanceAuthorityBinding,
        *,
        time_to_live_seconds: int,
        delivery_budget: GuidancePublicationRequestDeliveryBudget,
    ) -> None:
        from azure.servicebus import ServiceBusMessage

        if (
            type(delivery_budget)
            is not GuidancePublicationRequestDeliveryBudget
        ):
            raise TypeError(
                "delivery_budget must be an exact "
                "GuidancePublicationRequestDeliveryBudget"
            )
        if not (
            delivery_budget.feed_trigger_minimum_time_to_live_seconds
            <= time_to_live_seconds
            <= WC027_GUIDANCE_ACTIVATION_MAX_LIFETIME_SECONDS
            - delivery_budget.feed_processing_seconds
        ):
            raise ValueError(
                "guidance trigger TTL does not retain the reviewed feed "
                "delivery budget"
            )
        application_properties: dict[str | bytes, Any] = {
            "schemaVersion": (
                "athena.wc027PublishedGuidanceAuthorityBinding.v2"
            ),
            "bindingDigest": binding.binding_digest,
        }
        application_properties.update(delivery_budget.broker_properties())
        message = ServiceBusMessage(
            binding.canonical_bytes(),
            content_type="application/json",
            message_id=binding.binding_id,
            session_id=(
                binding.incident_bound_request.incident_subject.incident_id
            ),
            time_to_live=timedelta(seconds=time_to_live_seconds),
            application_properties=application_properties,
        )
        cast(Any, self._sender).send_messages(message)


__all__ = [
    "AzureBlobGuidanceAuthorityArtifactWriter",
    "AzureServiceBusGuidanceAuthorityTrigger",
    "AzureTableGuidanceAuthorityActivationStore",
]
