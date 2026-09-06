from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import islice
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
from uuid import UUID

from pydantic import ValidationError

from athena_context.azure_adapters import (
    AzureBlobIncidentAssetPublisher,
    KeyVaultRsaSigner,
    production_managed_identity_credential,
)
from athena_context.contracts import TrustedKeyAnchor, canonicalize_json, sha256_hex
from athena_context.contracts.eventing import (
    IncidentFinding,
    IncidentNotification,
    ReassessmentRequest,
    VerifiedReassessmentResult,
    WorkloadRole,
)
from athena_context.eventing.detector import (
    ArmJsonReaderPort,
    ManagedIdentityArmJsonReader,
    build_signal_reassessment_request,
    read_approved_signal,
    validate_approved_resource_roles,
)
from athena_context.eventing.orchestrator import (
    NotificationOutboxPort,
    ScopedReassessmentPort,
    run_active_incident_index_heartbeat,
    run_incident_reassessment,
)

_MONITOR_EVENT_CLAUSES = {
    "singletonDatabaseFailure": "wc016-singleton-database-operational-state",
    "webServerFailure": "wc016-web-server-operational-state",
    "loadBalancerFailure": "wc016-load-balancer-operational-state",
}
_LOGIC_APPS_SCOPE = "https://management.azure.com/.default"
ServiceBusApplicationProperty = int | float | bytes | bool | str | UUID


@dataclass(frozen=True)
class NotificationDeliveryClaim:
    disposition: Literal["acquired", "busy", "dispatching", "delivered"]
    etag: str | None = None


class ServiceBusSenderPort(Protocol):
    def send_messages(
        self,
        message: Any,
        *,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None: ...


class ServiceBusMessageFactory(Protocol):
    def __call__(
        self,
        body: bytes,
        *,
        content_type: str,
        message_id: str,
        session_id: str,
        application_properties: dict[
            str | bytes,
            ServiceBusApplicationProperty,
        ],
    ) -> object: ...


class NotificationDeliveryStorePort(Protocol):
    def acquire(
        self,
        *,
        notification_id: str,
        reserved_at: datetime,
    ) -> NotificationDeliveryClaim: ...

    def mark_dispatching(
        self,
        *,
        notification_id: str,
        etag: str,
        dispatching_at: datetime,
    ) -> str | None: ...

    def mark_delivered(
        self,
        *,
        notification_id: str,
        etag: str,
        delivered_at: datetime,
    ) -> bool: ...

    def reset_for_retry(
        self,
        *,
        notification_id: str,
        etag: str,
        reserved_at: datetime,
    ) -> bool: ...


def _now_utc_millisecond() -> datetime:
    current = datetime.now(tz=UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


class ApprovedLiveReassessmentAdapter(ScopedReassessmentPort):
    """Treat the queued request as a hint and independently verify current state."""

    def __init__(
        self,
        *,
        reader: ArmJsonReaderPort,
        approved_resource_roles: Mapping[str, WorkloadRole],
        metric_window_minutes: int = 5,
        clock: Callable[[], datetime] = _now_utc_millisecond,
    ) -> None:
        self._reader = reader
        self._approved_resource_roles = validate_approved_resource_roles(
            approved_resource_roles
        )
        if not 2 <= metric_window_minutes <= 10:
            raise ValueError("metric window must be between two and ten minutes")
        self._metric_window_minutes = metric_window_minutes
        self._clock = clock

    def reassess(self, request: ReassessmentRequest) -> VerifiedReassessmentResult:
        from athena_context.eventing.routing import build_reassessment_request

        expected_request = build_reassessment_request(
            request.trigger_event,
            approved_resource_roles=self._approved_resource_roles,
        )
        expected_rule = (
            f"wc016-scheduled-{request.workload_role}-power-state"
            if request.workload_role in {"database-primary", "web"}
            else "wc016-scheduled-load-balancer-availability"
        )
        if (
            request.canonical_bytes() != expected_request.canonical_bytes()
            or request.trigger_event.source_system != "azureMonitorCommonAlert"
            or request.trigger_event.signal_kind != "metricAlert"
            or request.trigger_event.operation_name.casefold()
            != expected_rule.casefold()
        ):
            raise ValueError("queued reassessment hint failed deterministic rederivation")
        observed_at = self._clock()
        observation = read_approved_signal(
            reader=self._reader,
            resource_id=request.target_resource_id,
            workload_role=request.workload_role,
            observed_at=observed_at,
            metric_window_minutes=self._metric_window_minutes,
        )
        target_binding = sha256_hex(
            canonicalize_json(
                {
                    "approvedResourceRoles": self._approved_resource_roles,
                    "liveEvidence": dict(observation.evidence),
                    "observedAt": observed_at,
                    "targetResourceId": request.target_resource_id,
                    "workloadRole": request.workload_role,
                    "scenario": request.scenario,
                }
            )
        )
        finding = IncidentFinding(
            clauseId=_MONITOR_EVENT_CLAUSES[request.scenario],
            verdict="resolved" if observation.healthy else "fail",
            summary=observation.summary,
            evidenceRefs=(f"arm-live:{target_binding}",),
        )
        return VerifiedReassessmentResult(
            schemaVersion="athena.incidentReassessmentResult.v1",
            requestId=request.request_id,
            snapshotId=f"arm-live-{target_binding.removeprefix('sha256:')[:12]}",
            observedAt=observed_at,
            targetBinding=target_binding,
            verifiedHealthy=observation.healthy,
            findings=(finding,),
            reasoning=(
                "The queue message was treated only as an untrusted reassessment hint.",
                "The exact resource, role, scenario, and transition identifiers were "
                "rederived from the deployment-owned allowlist.",
                "Current state was independently queried through the bounded approved "
                "ARM signal adapter and reconciled against the signed active index.",
            ),
        )


class AzureServiceBusNotificationOutbox(NotificationOutboxPort):
    def __init__(
        self,
        sender: ServiceBusSenderPort,
        *,
        message_factory: ServiceBusMessageFactory | None = None,
    ) -> None:
        self._sender = sender
        self._message_factory = message_factory or _service_bus_message

    def enqueue(
        self,
        *,
        incident_id: str,
        lifecycle: str,
        transition_id: str,
        message: str,
    ) -> None:
        notification_lifecycle: Literal["active", "resolved"]
        if lifecycle == "active":
            notification_lifecycle = "active"
        elif lifecycle == "resolved":
            notification_lifecycle = "resolved"
        else:
            raise ValueError("notification lifecycle must be active or resolved")
        notification_id = "notify-" + hashlib.sha256(
            f"{transition_id}\0{notification_lifecycle}".encode()
        ).hexdigest()
        notification = IncidentNotification(
            schemaVersion="athena.incidentNotification.v1",
            notificationId=notification_id,
            transitionId=transition_id,
            incidentId=incident_id,
            lifecycle=notification_lifecycle,
            message=message,
        )
        self._sender.send_messages(
            self._message_factory(
                notification.canonical_bytes(),
                content_type="application/json",
                message_id=notification.notification_id,
                session_id=incident_id,
                application_properties={
                    "schemaVersion": "athena.incidentNotification.v1",
                    "lifecycle": lifecycle,
                    "transitionId": transition_id,
                },
            )
        )


class AzureTableNotificationDeliveryStore:
    """Persist explicit at-most-once Logic App dispatch states."""

    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        partition_key: str,
        managed_identity_client_id: str,
    ) -> None:
        from azure.core import MatchConditions
        from azure.core.exceptions import (
            HttpResponseError,
            ResourceExistsError,
            ResourceModifiedError,
            ResourceNotFoundError,
        )
        from azure.data.tables import TableServiceClient, UpdateMode

        parsed_endpoint = urlsplit(endpoint)
        if (
            parsed_endpoint.scheme != "https"
            or parsed_endpoint.hostname is None
            or not parsed_endpoint.hostname.endswith(".table.core.windows.net")
            or parsed_endpoint.path not in {"", "/"}
            or parsed_endpoint.query
            or parsed_endpoint.fragment
            or not table_name.isalnum()
            or not 3 <= len(table_name) <= 63
            or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", partition_key) is None
        ):
            raise ValueError("notification delivery store configuration is invalid")
        self._http_error = HttpResponseError
        self._exists = ResourceExistsError
        self._modified = ResourceModifiedError
        self._not_found = ResourceNotFoundError
        self._if_not_modified = MatchConditions.IfNotModified
        self._replace = UpdateMode.REPLACE
        self._table = TableServiceClient(
            endpoint=endpoint,
            credential=production_managed_identity_credential(
                managed_identity_client_id=managed_identity_client_id
            ),
        ).get_table_client(table_name)
        self._partition_key = partition_key

    def acquire(
        self,
        *,
        notification_id: str,
        reserved_at: datetime,
    ) -> NotificationDeliveryClaim:
        self._prune_expired(reserved_at)
        entity = {
            "PartitionKey": self._partition_key,
            "RowKey": notification_id,
            "kind": "wc016-notification-delivery-reservation",
            "notificationId": notification_id,
            "state": "reserved",
            "reservedAt": reserved_at.isoformat(),
            "expiresUnix": int((reserved_at + timedelta(days=8)).timestamp()),
        }
        try:
            result = self._table.create_entity(entity)
            return NotificationDeliveryClaim(
                disposition="acquired",
                etag=self._operation_etag(result),
            )
        except self._exists:
            try:
                current = self._table.get_entity(
                    self._partition_key,
                    notification_id,
                )
            except self._not_found:
                return NotificationDeliveryClaim(disposition="busy")
            except self._http_error as exc:
                raise RuntimeError(
                    "notification delivery reservation read failed"
                ) from exc
            state, etag = self._validate_entity(
                current,
                notification_id=notification_id,
            )
            if state == "delivered":
                return NotificationDeliveryClaim(disposition="delivered")
            if state == "dispatching":
                return NotificationDeliveryClaim(disposition="dispatching")
            try:
                result = self._table.update_entity(
                    entity,
                    mode=self._replace,
                    etag=etag,
                    match_condition=self._if_not_modified,
                )
            except self._modified:
                return NotificationDeliveryClaim(disposition="busy")
            except self._http_error as exc:
                raise RuntimeError(
                    "notification delivery reservation reacquisition failed"
                ) from exc
            return NotificationDeliveryClaim(
                disposition="acquired",
                etag=self._operation_etag(result),
            )
        except self._http_error as exc:
            raise RuntimeError("notification delivery reservation failed") from exc

    def mark_dispatching(
        self,
        *,
        notification_id: str,
        etag: str,
        dispatching_at: datetime,
    ) -> str | None:
        try:
            result = self._table.update_entity(
                {
                    "PartitionKey": self._partition_key,
                    "RowKey": notification_id,
                    "state": "dispatching",
                    "dispatchingAt": dispatching_at.isoformat(),
                },
                etag=etag,
                match_condition=self._if_not_modified,
            )
            return self._operation_etag(result)
        except self._modified:
            return None
        except self._http_error as exc:
            raise RuntimeError(
                "notification delivery dispatch transition failed"
            ) from exc

    def mark_delivered(
        self,
        *,
        notification_id: str,
        etag: str,
        delivered_at: datetime,
    ) -> bool:
        try:
            self._table.update_entity(
                {
                    "PartitionKey": self._partition_key,
                    "RowKey": notification_id,
                    "state": "delivered",
                    "deliveredAt": delivered_at.isoformat(),
                },
                etag=etag,
                match_condition=self._if_not_modified,
            )
            return True
        except self._modified:
            return False
        except self._http_error as exc:
            raise RuntimeError(
                "notification delivery completion transition failed"
            ) from exc

    def reset_for_retry(
        self,
        *,
        notification_id: str,
        etag: str,
        reserved_at: datetime,
    ) -> bool:
        try:
            self._table.update_entity(
                {
                    "PartitionKey": self._partition_key,
                    "RowKey": notification_id,
                    "state": "reserved",
                    "reservedAt": reserved_at.isoformat(),
                    "expiresUnix": int((reserved_at + timedelta(days=8)).timestamp()),
                },
                etag=etag,
                match_condition=self._if_not_modified,
            )
            return True
        except self._modified:
            return False
        except self._http_error as exc:
            raise RuntimeError("notification delivery retry reset failed") from exc

    @staticmethod
    def _operation_etag(metadata: Mapping[str, Any]) -> str:
        etag = metadata.get("etag")
        if not isinstance(etag, str) or not etag:
            raise RuntimeError("notification delivery state update returned no ETag")
        return etag

    @staticmethod
    def _entity_etag(entity: object) -> str:
        metadata = getattr(entity, "metadata", None)
        if not isinstance(metadata, Mapping):
            raise RuntimeError("notification delivery state record has no metadata")
        return AzureTableNotificationDeliveryStore._operation_etag(metadata)

    @staticmethod
    def _validate_entity(
        entity: Mapping[str, Any],
        *,
        notification_id: str,
    ) -> tuple[Literal["reserved", "dispatching", "delivered"], str]:
        state = entity.get("state")
        if (
            entity.get("kind") != "wc016-notification-delivery-reservation"
            or entity.get("notificationId") != notification_id
            or state not in {"reserved", "dispatching", "delivered"}
            or not isinstance(entity.get("reservedAt"), str)
            or not isinstance(entity.get("expiresUnix"), int)
            or isinstance(entity.get("expiresUnix"), bool)
            or (
                state in {"dispatching", "delivered"}
                and not isinstance(entity.get("dispatchingAt"), str)
            )
            or (
                state == "delivered"
                and not isinstance(entity.get("deliveredAt"), str)
            )
        ):
            raise RuntimeError("notification delivery reservation is invalid")
        return state, AzureTableNotificationDeliveryStore._entity_etag(entity)

    def _prune_expired(self, now: datetime) -> None:
        try:
            expired = self._table.query_entities(
                query_filter=(
                    f"PartitionKey eq '{self._partition_key}' and "
                    "state eq 'reserved' and "
                    f"expiresUnix lt {int(now.timestamp())}"
                ),
                select=["PartitionKey", "RowKey", "state"],
                results_per_page=32,
            )
            for entity in islice(expired, 32):
                partition_key = entity.get("PartitionKey")
                row_key = entity.get("RowKey")
                if (
                    partition_key != self._partition_key
                    or not isinstance(row_key, str)
                    or entity.get("state") != "reserved"
                ):
                    raise RuntimeError(
                        "expired notification reservation query was invalid"
                    )
                self._table.delete_entity(
                    entity,
                    etag=self._entity_etag(entity),
                    match_condition=self._if_not_modified,
                )
        except self._not_found:
            return
        except self._modified:
            return
        except self._http_error as exc:
            raise RuntimeError("notification reservation cleanup failed") from exc


def _service_bus_message(
    body: bytes,
    *,
    content_type: str,
    message_id: str,
    session_id: str,
    application_properties: dict[
        str | bytes,
        ServiceBusApplicationProperty,
    ],
) -> object:
    from azure.servicebus import ServiceBusMessage

    return ServiceBusMessage(
        body,
        content_type=content_type,
        message_id=message_id,
        session_id=session_id,
        application_properties=application_properties,
    )


def run_notification_dispatcher_worker(
    *,
    fully_qualified_namespace: str,
    notification_queue_name: str,
    managed_identity_client_id: str,
    webhook_url: str,
    notification_state_table_endpoint: str,
    notification_state_table_name: str,
    notification_state_partition_key: str,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import (
        NEXT_AVAILABLE_SESSION,
        ServiceBusClient,
    )

    parsed_webhook = urlsplit(webhook_url)
    query = parse_qs(parsed_webhook.query, keep_blank_values=True)
    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or parsed_webhook.scheme != "https"
        or parsed_webhook.hostname is None
        or not parsed_webhook.hostname.endswith(".logic.azure.com")
        or parsed_webhook.username is not None
        or parsed_webhook.password is not None
        or parsed_webhook.fragment
        or not parsed_webhook.path.startswith("/workflows/")
        or query != {"api-version": ["2019-05-01"]}
        or not 1 <= max_wait_time_seconds <= 300
    ):
        raise ValueError("notification dispatcher configuration is invalid")
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    delivery_store = AzureTableNotificationDeliveryStore(
        endpoint=notification_state_table_endpoint,
        table_name=notification_state_table_name,
        partition_key=notification_state_partition_key,
        managed_identity_client_id=managed_identity_client_id,
    )
    with (
        ServiceBusClient(
            fully_qualified_namespace=fully_qualified_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_receiver(
            queue_name=notification_queue_name,
            session_id=NEXT_AVAILABLE_SESSION,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
    ):
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return False
        message = messages[0]
        return _dispatch_notification_message(
            message=message,
            receiver=receiver,
            credential=credential,
            webhook_url=webhook_url,
            delivery_store=delivery_store,
        )


def _dispatch_notification_message(
    *,
    message: object,
    receiver: Any,
    credential: Any,
    webhook_url: str,
    delivery_store: NotificationDeliveryStorePort,
) -> bool:
    try:
        body = _message_body(message)
        if not 1 <= len(body) <= 16 * 1024:
            raise ValueError("notification is outside its byte bound")
        notification = IncidentNotification.model_validate_json(body)
        _validate_notification_broker_metadata(message, notification)
        access_token = credential.get_token(_LOGIC_APPS_SCOPE).token
        claim = delivery_store.acquire(
            notification_id=notification.notification_id,
            reserved_at=_now_utc_millisecond(),
        )
        if claim.disposition == "delivered":
            receiver.complete_message(message)
            return True
        if claim.disposition == "dispatching":
            receiver.dead_letter_message(
                message,
                reason="AthenaNotificationDeliveryUncertain",
                error_description=(
                    "notification was already dispatching; retry and duplicate send suppressed"
                ),
            )
            return False
        if claim.disposition == "busy":
            receiver.abandon_message(message)
            return False
        if claim.etag is None:
            raise RuntimeError("notification delivery reservation returned no lease ETag")
        request_body = json.dumps(
            {
                "notificationId": notification.notification_id,
                "message": notification.message,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(  # noqa: S310 - webhook_url is validated as Azure Logic Apps HTTPS.
            webhook_url,
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        request.add_unredirected_header(
            "Authorization",
            "Bearer " + access_token,
        )
        dispatching_etag = delivery_store.mark_dispatching(
            notification_id=notification.notification_id,
            etag=claim.etag,
            dispatching_at=_now_utc_millisecond(),
        )
        if dispatching_etag is None:
            receiver.abandon_message(message)
            return False
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310
                response.read(4097)
                if not 200 <= response.status < 300:
                    raise RuntimeError("notification webhook returned non-success")
        except HTTPError as exc:
            if exc.code in {408, 429}:
                if not delivery_store.reset_for_retry(
                    notification_id=notification.notification_id,
                    etag=dispatching_etag,
                    reserved_at=_now_utc_millisecond(),
                ):
                    raise RuntimeError(
                        "notification retry reset lost its dispatch lease"
                    ) from exc
                receiver.abandon_message(message)
                return False
            receiver.dead_letter_message(
                message,
                reason=(
                    "AthenaNotificationRejected"
                    if _notification_http_error_is_permanent(exc.code)
                    else "AthenaNotificationDeliveryUncertain"
                ),
                error_description=(
                    "notification webhook rejected the bounded request"
                    if _notification_http_error_is_permanent(exc.code)
                    else "notification outcome was ambiguous; retry suppressed"
                ),
            )
            return False
        except (URLError, TimeoutError, OSError):
            receiver.dead_letter_message(
                message,
                reason="AthenaNotificationDeliveryUncertain",
                error_description="notification outcome was ambiguous; retry suppressed",
            )
            return False
        if not delivery_store.mark_delivered(
            notification_id=notification.notification_id,
            etag=dispatching_etag,
            delivered_at=_now_utc_millisecond(),
        ):
            raise RuntimeError("notification delivered transition lost its dispatch lease")
        receiver.complete_message(message)
        return True
    except (ValidationError, ValueError):
        receiver.dead_letter_message(
            message,
            reason="AthenaNotificationRejected",
            error_description="notification failed bounded validation",
        )
        return False


def _notification_http_error_is_permanent(status_code: int) -> bool:
    return 400 <= status_code < 500 and status_code not in {408, 429}


def run_incident_feed_heartbeat(
    *,
    managed_identity_client_id: str,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
    blob_endpoint: str,
    key_vault_key_id: str,
    signing_key_id: str,
    signing_key_fingerprint: str,
    metric_window_minutes: int = 5,
) -> None:
    roles = validate_approved_resource_roles(approved_resource_roles)
    alert_rules = {rule.casefold() for rule in approved_metric_alert_rules}
    observed_at = _now_utc_millisecond()
    reader = ManagedIdentityArmJsonReader(
        managed_identity_client_id=managed_identity_client_id
    )
    observations = tuple(
        read_approved_signal(
            reader=reader,
            resource_id=resource_id,
            workload_role=role,
            observed_at=observed_at,
            metric_window_minutes=metric_window_minutes,
        )
        for resource_id, role in roles.items()
    )
    reassessment_observations = tuple(
        build_signal_reassessment_request(
            observation,
            approved_resource_roles=roles,
            approved_metric_alert_rules=alert_rules,
        )
        for observation in observations
    )
    trusted_key = TrustedKeyAnchor.from_key_vault_key_id(
        key_vault_key_id,
        public_key_fingerprint=signing_key_fingerprint,
    )
    signer = KeyVaultRsaSigner(
        trusted_key_anchor=trusted_key,
        managed_identity_client_id=managed_identity_client_id,
    )
    publisher = AzureBlobIncidentAssetPublisher(
        blob_endpoint=blob_endpoint,
        container_name="incident-assets",
        managed_identity_client_id=managed_identity_client_id,
        signing_key_id=signing_key_id,
        signing_key_fingerprint=signing_key_fingerprint,
        signature_verifier=signer.verify_preimage,
    )
    run_active_incident_index_heartbeat(
        reassessment_observations,
        published_at=observed_at,
        signing_key_id=signing_key_id,
        signing_key_fingerprint=signing_key_fingerprint,
        signer=signer,
        publisher=publisher,
    )


def run_incident_orchestrator_worker(
    *,
    fully_qualified_namespace: str,
    reassessment_queue_name: str,
    notification_queue_name: str,
    managed_identity_client_id: str,
    approved_resource_roles: Mapping[str, WorkloadRole],
    blob_endpoint: str,
    presentation_url: str,
    key_vault_key_id: str,
    signing_key_id: str,
    signing_key_fingerprint: str,
    metric_window_minutes: int = 5,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import (
        NEXT_AVAILABLE_SESSION,
        ServiceBusClient,
    )

    parsed_presentation_url = urlsplit(presentation_url)
    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or parsed_presentation_url.scheme != "https"
        or not parsed_presentation_url.netloc
        or parsed_presentation_url.username is not None
        or parsed_presentation_url.password is not None
        or parsed_presentation_url.query
        or parsed_presentation_url.fragment
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
    publisher = AzureBlobIncidentAssetPublisher(
        blob_endpoint=blob_endpoint,
        container_name="incident-assets",
        managed_identity_client_id=managed_identity_client_id,
        signing_key_id=signing_key_id,
        signing_key_fingerprint=signing_key_fingerprint,
        signature_verifier=signer.verify_preimage,
    )
    reassessment: ScopedReassessmentPort = ApprovedLiveReassessmentAdapter(
        reader=ManagedIdentityArmJsonReader(
            managed_identity_client_id=managed_identity_client_id
        ),
        approved_resource_roles=approved_resource_roles,
        metric_window_minutes=metric_window_minutes,
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
            body = _message_body(message)
            if not 1 <= len(body) <= 128 * 1024:
                raise ValueError("reassessment request is outside its byte bound")
            request = ReassessmentRequest.model_validate_json(body)
            _validate_reassessment_broker_metadata(message, request)
            now = _now_utc_millisecond()
            _validate_reassessment_age(request, now=now)
            run_incident_reassessment(
                request,
                detected_at=request.trigger_event.observed_at,
                updated_at=request.trigger_event.received_at,
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
        except ValidationError, ValueError:
            receiver.dead_letter_message(
                message,
                reason="AthenaReassessmentRejected",
                error_description="request failed bounded validation or trust binding",
            )
            return False
        except OSError, RuntimeError:
            receiver.abandon_message(message)
            raise


def _message_body(message: object) -> bytes:
    body = getattr(message, "body", None)
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if body is None:
        raise ValueError("broker message body is missing")
    try:
        return b"".join(bytes(item) for item in body)
    except (TypeError, ValueError) as exc:
        raise ValueError("broker message body is invalid") from exc


def _validate_reassessment_age(
    request: ReassessmentRequest,
    *,
    now: datetime,
) -> None:
    if (
        request.trigger_event.received_at > now
        or now - request.trigger_event.received_at > timedelta(days=1)
    ):
        raise ValueError("reassessment request is outside its one-day queue lifetime")


def _broker_text(value: object, *, label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError(f"{label} is not UTF-8") from exc
    raise ValueError(f"{label} is missing or invalid")


def _application_properties(message: object) -> dict[str, str]:
    value = getattr(message, "application_properties", None)
    if not isinstance(value, Mapping):
        raise ValueError("broker application properties are missing")
    properties: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _broker_text(raw_key, label="broker property name")
        if key in properties:
            raise ValueError("broker application properties contain duplicates")
        properties[key] = _broker_text(raw_value, label=f"broker property {key}")
    return properties


def _validate_reassessment_broker_metadata(
    message: object,
    request: ReassessmentRequest,
) -> None:
    properties = _application_properties(message)
    if (
        _broker_text(getattr(message, "content_type", None), label="content type")
        != "application/json"
        or _broker_text(getattr(message, "message_id", None), label="message ID")
        != request.idempotency_key
        or _broker_text(getattr(message, "session_id", None), label="session ID")
        != request.incident_id
        or properties
        != {
            "schemaVersion": "athena.incidentReassessmentRequest.v1",
            "scenario": request.scenario,
            "lifecycle": request.lifecycle,
        }
    ):
        raise ValueError("reassessment broker metadata failed exact validation")


def _validate_notification_broker_metadata(
    message: object,
    notification: IncidentNotification,
) -> None:
    properties = _application_properties(message)
    if (
        _broker_text(getattr(message, "content_type", None), label="content type")
        != "application/json"
        or _broker_text(getattr(message, "message_id", None), label="message ID")
        != notification.notification_id
        or _broker_text(getattr(message, "session_id", None), label="session ID")
        != notification.incident_id
        or properties
        != {
            "schemaVersion": "athena.incidentNotification.v1",
            "lifecycle": notification.lifecycle,
            "transitionId": notification.transition_id,
        }
    ):
        raise ValueError("notification broker metadata failed exact validation")


__all__ = [
    "ApprovedLiveReassessmentAdapter",
    "AzureServiceBusNotificationOutbox",
    "AzureTableNotificationDeliveryStore",
    "run_incident_orchestrator_worker",
    "run_notification_dispatcher_worker",
]
