from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from typing import Protocol

from athena_context.contracts.eventing import ReassessmentRequest, WorkloadRole
from athena_context.eventing.normalization import (
    EventNormalizationError,
    normalize_monitor_event,
)
from athena_context.eventing.routing import EventRoutingError, build_reassessment_request


class RawEventMessagePort(Protocol):
    @property
    def body(self) -> bytes: ...

    def complete(self) -> None: ...

    def abandon(self) -> None: ...

    def dead_letter(self, *, reason: str) -> None: ...


class ReassessmentRequestSenderPort(Protocol):
    def send(
        self,
        request: ReassessmentRequest,
        *,
        message_id: str,
        session_id: str,
    ) -> None: ...


def process_raw_event_message(
    message: RawEventMessagePort,
    *,
    sender: ReassessmentRequestSenderPort,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str] = (),
    received_at: datetime | None = None,
) -> ReassessmentRequest | None:
    now = received_at or datetime.now(tz=UTC)
    try:
        if not 1 <= len(message.body) <= 256 * 1024:
            raise EventNormalizationError("raw event is outside its byte bound")
        raw = json.loads(message.body)
        event = normalize_monitor_event(
            raw,
            received_at=now,
            approved_metric_alert_rules=approved_metric_alert_rules,
        )
        request = build_reassessment_request(
            event,
            approved_resource_roles=approved_resource_roles,
        )
        sender.send(
            request,
            message_id=request.idempotency_key,
            session_id=request.incident_id,
        )
        message.complete()
        return request
    except (UnicodeError, json.JSONDecodeError, EventNormalizationError, EventRoutingError):
        message.dead_letter(reason="event failed bounded normalization or context binding")
        return None
    except (OSError, RuntimeError):
        message.abandon()
        raise


class AzureServiceBusRawMessage:
    def __init__(self, receiver: object, message: object) -> None:
        self._receiver = receiver
        self._message = message
        self._body = b"".join(bytes(item) for item in message.body)  # type: ignore[attr-defined]

    @property
    def body(self) -> bytes:
        return self._body

    def complete(self) -> None:
        self._receiver.complete_message(self._message)  # type: ignore[attr-defined]

    def abandon(self) -> None:
        self._receiver.abandon_message(self._message)  # type: ignore[attr-defined]

    def dead_letter(self, *, reason: str) -> None:
        self._receiver.dead_letter_message(  # type: ignore[attr-defined]
            self._message,
            reason="AthenaEventRejected",
            error_description=reason,
        )


class AzureServiceBusReassessmentSender:
    def __init__(self, sender: object) -> None:
        self._sender = sender

    def send(
        self,
        request: ReassessmentRequest,
        *,
        message_id: str,
        session_id: str,
    ) -> None:
        from azure.servicebus import ServiceBusMessage

        self._sender.send_messages(  # type: ignore[attr-defined]
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


def run_event_processor(
    *,
    fully_qualified_namespace: str,
    raw_queue_name: str,
    reassessment_queue_name: str,
    managed_identity_client_id: str,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import ServiceBusClient

    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or not 1 <= max_wait_time_seconds <= 300
    ):
        raise ValueError("Service Bus worker configuration is invalid")
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    with (
        ServiceBusClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=credential,
        logging_enable=False,
    ) as client, client.get_queue_receiver(
            queue_name=raw_queue_name,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
        client.get_queue_sender(queue_name=reassessment_queue_name) as sender,
    ):
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return False
        process_raw_event_message(
            AzureServiceBusRawMessage(receiver, messages[0]),
            sender=AzureServiceBusReassessmentSender(sender),
            approved_resource_roles=approved_resource_roles,
            approved_metric_alert_rules=approved_metric_alert_rules,
        )
        return True
