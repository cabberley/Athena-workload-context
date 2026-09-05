from __future__ import annotations

from typing import Any, Protocol

from athena_context.contracts.eventing import ReassessmentRequest


class ReassessmentRequestSenderPort(Protocol):
    def send(
        self,
        request: ReassessmentRequest,
        *,
        message_id: str,
        session_id: str,
    ) -> None: ...


class ServiceBusSenderPort(Protocol):
    def send_messages(
        self,
        message: Any,
        *,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None: ...


class AzureServiceBusReassessmentSender:
    def __init__(self, sender: ServiceBusSenderPort) -> None:
        self._sender = sender

    def send(
        self,
        request: ReassessmentRequest,
        *,
        message_id: str,
        session_id: str,
    ) -> None:
        from azure.servicebus import ServiceBusMessage

        self._sender.send_messages(
            ServiceBusMessage(
                request.canonical_bytes(),
                content_type="application/json",
                message_id=message_id,
                session_id=session_id,
                application_properties={
                    "schemaVersion": "athena.incidentReassessmentRequest.v1",
                    "scenario": request.scenario,
                    "lifecycle": request.lifecycle,
                },
            )
        )
