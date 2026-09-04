from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from pydantic import ValidationError

from athena_context.azure_adapters import (
    AzureBlobPresentationAssetPublisher,
    KeyVaultRsaSigner,
)
from athena_context.contracts import TrustedKeyAnchor
from athena_context.contracts.eventing import (
    ReassessmentRequest,
    VerifiedReassessmentResult,
)
from athena_context.eventing.orchestrator import (
    NotificationOutboxPort,
    ScopedReassessmentPort,
    run_incident_reassessment,
)

_MAX_REASSESSMENT_RESPONSE_BYTES = 128 * 1024


class ManagedIdentityReassessmentClient(ScopedReassessmentPort):
    def __init__(
        self,
        *,
        endpoint: str,
        audience: str,
        managed_identity_client_id: str,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("reassessment endpoint must be one exact HTTPS URL")
        if (
            not audience.startswith("api://")
            or "/" in audience.removeprefix("api://")
        ):
            raise ValueError("reassessment audience must be one exact application ID URI")
        from azure.identity import ManagedIdentityCredential

        self._endpoint = endpoint
        self._scope = audience + "/.default"
        self._credential = ManagedIdentityCredential(client_id=managed_identity_client_id)

    def reassess(self, request: ReassessmentRequest) -> VerifiedReassessmentResult:
        token = self._credential.get_token(self._scope)
        http_request = Request(  # noqa: S310 - constructor receives a validated HTTPS URL.
            self._endpoint,
            data=request.canonical_bytes(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        http_request.add_unredirected_header(
            "Authorization",
            "Bearer " + token.token,
        )
        try:
            with urlopen(http_request, timeout=30) as response:  # noqa: S310
                payload = response.read(_MAX_REASSESSMENT_RESPONSE_BYTES + 1)
                if len(payload) > _MAX_REASSESSMENT_RESPONSE_BYTES:
                    raise RuntimeError("reassessment response exceeded its byte bound")
                if response.status != 200:
                    raise RuntimeError("reassessment endpoint returned a non-success status")
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise RuntimeError("scoped reassessment request failed") from exc
        try:
            return VerifiedReassessmentResult.model_validate_json(payload)
        except ValidationError as exc:
            raise RuntimeError("scoped reassessment returned an invalid result") from exc


class AzureServiceBusNotificationOutbox(NotificationOutboxPort):
    def __init__(self, sender: object) -> None:
        self._sender = sender

    def enqueue(
        self,
        *,
        incident_id: str,
        lifecycle: str,
        message: str,
    ) -> None:
        from azure.servicebus import ServiceBusMessage

        payload = json.dumps(
            {
                "schemaVersion": "athena.incidentNotification.v1",
                "incidentId": incident_id,
                "lifecycle": lifecycle,
                "message": message,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._sender.send_messages(  # type: ignore[attr-defined]
            ServiceBusMessage(
                payload,
                content_type="application/json",
                message_id=f"{incident_id}:{lifecycle}",
                application_properties={
                    "schemaVersion": "athena.incidentNotification.v1",
                    "lifecycle": lifecycle,
                },
            )
        )


def run_incident_orchestrator_worker(
    *,
    fully_qualified_namespace: str,
    reassessment_queue_name: str,
    notification_queue_name: str,
    managed_identity_client_id: str,
    reassessment_endpoint: str,
    reassessment_audience: str,
    blob_endpoint: str,
    presentation_url: str,
    key_vault_key_id: str,
    signing_key_id: str,
    signing_key_fingerprint: str,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import NEXT_AVAILABLE_SESSION, ServiceBusClient

    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or not presentation_url.startswith("https://")
        or not 1 <= max_wait_time_seconds <= 300
    ):
        raise ValueError("incident orchestrator worker configuration is invalid")
    trusted_key = TrustedKeyAnchor.from_key_vault_key_id(
        key_vault_key_id,
        public_key_fingerprint=signing_key_fingerprint,
    )
    signer = KeyVaultRsaSigner(
        trusted_key_anchor=trusted_key,
        managed_identity_client_id=managed_identity_client_id,
    )
    publisher = AzureBlobPresentationAssetPublisher(
        blob_endpoint=blob_endpoint,
        container_name="presentation-assets",
        managed_identity_client_id=managed_identity_client_id,
    )
    reassessment = ManagedIdentityReassessmentClient(
        endpoint=reassessment_endpoint,
        audience=reassessment_audience,
        managed_identity_client_id=managed_identity_client_id,
    )
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    with (
        ServiceBusClient(
            fully_qualified_namespace=fully_qualified_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_receiver(
            queue_name=reassessment_queue_name,
            session_id=NEXT_AVAILABLE_SESSION,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
        client.get_queue_sender(queue_name=notification_queue_name) as notification_sender,
    ):
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return False
        message = messages[0]
        try:
            body = b"".join(bytes(item) for item in message.body)
            if not 1 <= len(body) <= 128 * 1024:
                raise ValueError("reassessment request is outside its byte bound")
            request = ReassessmentRequest.model_validate_json(body)
            now = datetime.now(tz=UTC)
            run_incident_reassessment(
                request,
                detected_at=request.trigger_event.observed_at,
                updated_at=now,
                published_at=now,
                presentation_url=presentation_url,
                signing_key_id=signing_key_id,
                signing_key_fingerprint=signing_key_fingerprint,
                reassessment=reassessment,
                signer=signer,
                publisher=publisher,
                notifications=AzureServiceBusNotificationOutbox(notification_sender),
            )
            receiver.complete_message(message)
            return True
        except (ValidationError, ValueError):
            receiver.dead_letter_message(
                message,
                reason="AthenaReassessmentRejected",
                error_description="request failed bounded validation or trust binding",
            )
            return False
        except (OSError, RuntimeError):
            receiver.abandon_message(message)
            raise


__all__ = [
    "AzureServiceBusNotificationOutbox",
    "ManagedIdentityReassessmentClient",
    "run_incident_orchestrator_worker",
]
