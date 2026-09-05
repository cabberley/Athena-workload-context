from __future__ import annotations

import json
import math
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from pydantic import ValidationError

from athena_context.contracts.eventing import ReassessmentRequest, WorkloadRole
from athena_context.eventing.normalization import EventNormalizationError, normalize_monitor_event
from athena_context.eventing.routing import EventRoutingError, build_reassessment_request
from athena_context.eventing.service_bus import ReassessmentRequestSenderPort

_ARM_SCOPE = "https://management.azure.com/.default"
_VM_API_VERSION = "2024-11-01"
_METRICS_API_VERSION = "2023-10-01"
_MAX_ARM_RESPONSE_BYTES = 256 * 1024
_VM_INSTANCE_VIEW_SUFFIX = "/instanceView"
_METRICS_SUFFIX = "/providers/microsoft.insights/metrics"
_VM_TYPE_SEGMENT = "/providers/microsoft.compute/virtualmachines/"
_LB_TYPE_SEGMENT = "/providers/microsoft.network/loadbalancers/"
_VM_RUNNING = "powerstate/running"
_VM_KNOWN_UNHEALTHY = {
    "powerstate/starting",
    "powerstate/stopping",
    "powerstate/stopped",
    "powerstate/deallocating",
    "powerstate/deallocated",
    "powerstate/hibernated",
}
_LB_METRICS = ("VipAvailability", "DipAvailability")
_RUN_LEASE_SECONDS = 240
_RUN_LEASE_ROW_KEY = "wc016-detector-run-lease"
_ARM_TIMESPAN_PATTERN = re.compile(
    r"^(?P<start>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z)/"
    r"(?P<end>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z)$"
)


class SignalDetectionError(RuntimeError):
    """Raised when the approved Azure signal set cannot be evaluated safely."""


class ArmJsonReaderPort(Protocol):
    def get_json(self, resource_id: str, *, query: Mapping[str, str]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class SignalCheckpoint:
    committed_health: bool | None
    pending_healthy: bool | None = None
    pending_request: ReassessmentRequest | None = None

    def __post_init__(self) -> None:
        if (self.pending_healthy is None) != (self.pending_request is None):
            raise ValueError("pending detector state must be complete")


@dataclass(frozen=True, slots=True)
class ApprovedSignalObservation:
    resource_id: str
    workload_role: WorkloadRole
    healthy: bool
    observed_at: datetime
    evidence: Mapping[str, object]
    summary: str


class SignalStateStorePort(Protocol):
    def acquire_run_lease(self, *, observed_at: datetime) -> bool: ...

    def release_run_lease(self) -> None: ...

    def load_checkpoint(self, *, resource_id: str) -> SignalCheckpoint: ...

    def record_initial_health(
        self,
        *,
        resource_id: str,
        observed_at: datetime,
    ) -> None: ...

    def stage_transition(
        self,
        *,
        resource_id: str,
        healthy: bool,
        observed_at: datetime,
        request: ReassessmentRequest,
    ) -> None: ...

    def complete_transition(
        self,
        *,
        resource_id: str,
        request_id: str,
        observed_at: datetime,
    ) -> None: ...


class InMemorySignalStateStore:
    def __init__(self, initial: Mapping[str, bool] | None = None) -> None:
        self._state = {
            resource_id.lower(): SignalCheckpoint(committed_health=healthy)
            for resource_id, healthy in (initial or {}).items()
        }
        self._lease_held = False

    def acquire_run_lease(self, *, observed_at: datetime) -> bool:
        del observed_at
        if self._lease_held:
            return False
        self._lease_held = True
        return True

    def release_run_lease(self) -> None:
        self._lease_held = False

    def load_checkpoint(self, *, resource_id: str) -> SignalCheckpoint:
        return self._state.get(
            resource_id.lower(),
            SignalCheckpoint(committed_health=None),
        )

    def record_initial_health(
        self,
        *,
        resource_id: str,
        observed_at: datetime,
    ) -> None:
        del observed_at
        self._state[resource_id.lower()] = SignalCheckpoint(committed_health=True)

    def stage_transition(
        self,
        *,
        resource_id: str,
        healthy: bool,
        observed_at: datetime,
        request: ReassessmentRequest,
    ) -> None:
        del observed_at
        current = self.load_checkpoint(resource_id=resource_id)
        if current.pending_request is not None:
            raise SignalDetectionError("detector transition is already pending")
        self._state[resource_id.lower()] = SignalCheckpoint(
            committed_health=current.committed_health,
            pending_healthy=healthy,
            pending_request=request,
        )

    def complete_transition(
        self,
        *,
        resource_id: str,
        request_id: str,
        observed_at: datetime,
    ) -> None:
        del observed_at
        current = self.load_checkpoint(resource_id=resource_id)
        if (
            current.pending_request is None
            or current.pending_request.request_id != request_id
            or current.pending_healthy is None
        ):
            raise SignalDetectionError("detector pending transition changed before commit")
        self._state[resource_id.lower()] = SignalCheckpoint(
            committed_health=current.pending_healthy
        )


class ManagedIdentityArmJsonReader:
    def __init__(self, *, managed_identity_client_id: str) -> None:
        from azure.identity import ManagedIdentityCredential

        self._credential = ManagedIdentityCredential(client_id=managed_identity_client_id)

    def get_json(self, resource_id: str, *, query: Mapping[str, str]) -> Mapping[str, Any]:
        canonical_id = _canonical_arm_operation(resource_id, query=query)
        url = (
            "https://management.azure.com" + canonical_id + "?" + urlencode(query, quote_via=quote)
        )
        request = Request(url, headers={"Accept": "application/json"}, method="GET")  # noqa: S310
        token = self._credential.get_token(_ARM_SCOPE)
        request.add_unredirected_header("Authorization", "Bearer " + token.token)
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310
                payload = response.read(_MAX_ARM_RESPONSE_BYTES + 1)
                if response.status != 200 or len(payload) > _MAX_ARM_RESPONSE_BYTES:
                    raise SignalDetectionError(
                        "ARM response was unsuccessful or outside its byte bound"
                    )
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise SignalDetectionError("approved ARM signal query failed") from exc
        try:
            value = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SignalDetectionError("ARM response was not bounded JSON") from exc
        if not isinstance(value, dict):
            raise SignalDetectionError("ARM response must be one JSON object")
        return value


class AzureTableSignalStateStore:
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
            ResourceNotFoundError,
        )
        from azure.data.tables import TableServiceClient, UpdateMode

        from athena_context.azure_adapters import production_managed_identity_credential

        self._http_error = HttpResponseError
        self._exists = ResourceExistsError
        self._not_found = ResourceNotFoundError
        self._if_not_modified = MatchConditions.IfNotModified
        self._replace_mode = UpdateMode.REPLACE
        self._table = TableServiceClient(
            endpoint=endpoint,
            credential=production_managed_identity_credential(
                managed_identity_client_id=managed_identity_client_id
            ),
        ).get_table_client(table_name)
        self._partition_key = partition_key
        self._lease_owner: str | None = None

    def acquire_run_lease(self, *, observed_at: datetime) -> bool:
        now_unix = int(observed_at.timestamp())
        owner = str(uuid4())
        entity: dict[str, object] = {
            "PartitionKey": self._partition_key,
            "RowKey": _RUN_LEASE_ROW_KEY,
            "kind": "wc016-detector-run-lease",
            "owner": owner,
            "expiresUnix": now_unix + _RUN_LEASE_SECONDS,
        }
        try:
            self._table.create_entity(entity)
        except self._exists:
            try:
                current = self._table.get_entity(
                    self._partition_key,
                    _RUN_LEASE_ROW_KEY,
                )
            except self._http_error as exc:
                raise SignalDetectionError("detector run lease read failed") from exc
            expires_unix = current.get("expiresUnix")
            current_owner = current.get("owner")
            if (
                not isinstance(expires_unix, int)
                or isinstance(expires_unix, bool)
                or not isinstance(current_owner, str)
                or not current_owner
            ):
                raise SignalDetectionError("detector run lease was invalid") from None
            if expires_unix > now_unix:
                return False
            try:
                self._table.update_entity(
                    entity,
                    mode=self._replace_mode,
                    etag=current.metadata["etag"],
                    match_condition=self._if_not_modified,
                )
            except self._http_error as exc:
                raise SignalDetectionError(
                    "expired detector run lease could not be claimed"
                ) from exc
        except self._http_error as exc:
            raise SignalDetectionError("detector run lease creation failed") from exc
        self._lease_owner = owner
        return True

    def release_run_lease(self) -> None:
        if self._lease_owner is None:
            return
        try:
            current = self._table.get_entity(
                self._partition_key,
                _RUN_LEASE_ROW_KEY,
            )
            if current.get("owner") != self._lease_owner:
                raise SignalDetectionError("detector run lease ownership changed")
            self._table.delete_entity(
                self._partition_key,
                _RUN_LEASE_ROW_KEY,
                etag=current.metadata["etag"],
                match_condition=self._if_not_modified,
            )
        except self._http_error as exc:
            raise SignalDetectionError("detector run lease release failed") from exc
        finally:
            self._lease_owner = None

    def load_checkpoint(self, *, resource_id: str) -> SignalCheckpoint:
        import hashlib

        row_key = hashlib.sha256(resource_id.lower().encode("utf-8")).hexdigest()
        try:
            current = self._table.get_entity(self._partition_key, row_key)
        except self._not_found:
            current = None
        except self._http_error as exc:
            raise SignalDetectionError("detector state read failed") from exc
        if current is None:
            return SignalCheckpoint(committed_health=None)
        stored_resource_id = current.get("resourceId")
        if stored_resource_id != resource_id.lower():
            raise SignalDetectionError("detector state resource binding is invalid")
        previous = current.get("committedHealthy", current.get("healthy"))
        if previous is not None and not isinstance(previous, bool):
            raise SignalDetectionError("detector state contained an invalid health value")
        pending_healthy = current.get("pendingHealthy")
        pending_json = current.get("pendingRequestJson")
        if pending_healthy is None and pending_json is None:
            return SignalCheckpoint(committed_health=previous)
        if not isinstance(pending_healthy, bool) or not isinstance(pending_json, str):
            raise SignalDetectionError("detector pending transition state is incomplete")
        try:
            pending_request = ReassessmentRequest.model_validate_json(pending_json)
        except ValidationError as exc:
            raise SignalDetectionError("detector pending transition is invalid") from exc
        if pending_request.target_resource_id != resource_id.lower():
            raise SignalDetectionError("detector pending transition target is invalid")
        return SignalCheckpoint(
            committed_health=previous,
            pending_healthy=pending_healthy,
            pending_request=pending_request,
        )

    def record_initial_health(
        self,
        *,
        resource_id: str,
        observed_at: datetime,
    ) -> None:
        self._write_state(
            resource_id=resource_id,
            committed_health=True,
            pending_healthy=None,
            pending_request=None,
            observed_at=observed_at,
        )

    def stage_transition(
        self,
        *,
        resource_id: str,
        healthy: bool,
        observed_at: datetime,
        request: ReassessmentRequest,
    ) -> None:
        current = self.load_checkpoint(resource_id=resource_id)
        if current.pending_request is not None:
            raise SignalDetectionError("detector transition is already pending")
        self._write_state(
            resource_id=resource_id,
            committed_health=current.committed_health,
            pending_healthy=healthy,
            pending_request=request,
            observed_at=observed_at,
        )

    def complete_transition(
        self,
        *,
        resource_id: str,
        request_id: str,
        observed_at: datetime,
    ) -> None:
        current = self.load_checkpoint(resource_id=resource_id)
        if (
            current.pending_request is None
            or current.pending_request.request_id != request_id
            or current.pending_healthy is None
        ):
            raise SignalDetectionError("detector pending transition changed before commit")
        self._write_state(
            resource_id=resource_id,
            committed_health=current.pending_healthy,
            pending_healthy=None,
            pending_request=None,
            observed_at=observed_at,
        )

    def _write_state(
        self,
        *,
        resource_id: str,
        committed_health: bool | None,
        pending_healthy: bool | None,
        pending_request: ReassessmentRequest | None,
        observed_at: datetime,
    ) -> None:
        import hashlib

        row_key = hashlib.sha256(resource_id.lower().encode("utf-8")).hexdigest()
        try:
            current = self._table.get_entity(self._partition_key, row_key)
        except self._not_found:
            current = None
        except self._http_error as exc:
            raise SignalDetectionError("detector state read before write failed") from exc
        entity: dict[str, object] = {
            "PartitionKey": self._partition_key,
            "RowKey": row_key,
            "resourceId": resource_id.lower(),
            "observedAt": observed_at.isoformat(),
        }
        if committed_health is not None:
            entity["committedHealthy"] = committed_health
        if pending_request is not None and pending_healthy is not None:
            entity["pendingHealthy"] = pending_healthy
            entity["pendingRequestJson"] = pending_request.canonical_bytes().decode(
                "utf-8"
            )
        try:
            if current is None:
                self._table.create_entity(entity)
            else:
                self._table.update_entity(
                    entity,
                    mode=self._replace_mode,
                    etag=current.metadata["etag"],
                    match_condition=self._if_not_modified,
                )
        except self._http_error as exc:
            raise SignalDetectionError("detector state write failed") from exc


def detect_signal_requests(
    *,
    reader: ArmJsonReaderPort,
    state_store: SignalStateStorePort,
    sender: ReassessmentRequestSenderPort,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
    observed_at: datetime,
    metric_window_minutes: int = 5,
) -> tuple[ReassessmentRequest, ...]:
    if observed_at.utcoffset() != UTC.utcoffset(observed_at):
        raise SignalDetectionError("observed_at must use UTC")
    if not 2 <= metric_window_minutes <= 10:
        raise SignalDetectionError("metric window must be between two and ten minutes")
    if not state_store.acquire_run_lease(observed_at=observed_at):
        return ()
    try:
        return _detect_signal_requests_with_lease(
            reader=reader,
            state_store=state_store,
            sender=sender,
            approved_resource_roles=approved_resource_roles,
            approved_metric_alert_rules=approved_metric_alert_rules,
            observed_at=observed_at,
            metric_window_minutes=metric_window_minutes,
        )
    finally:
        state_store.release_run_lease()


def _detect_signal_requests_with_lease(
    *,
    reader: ArmJsonReaderPort,
    state_store: SignalStateStorePort,
    sender: ReassessmentRequestSenderPort,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
    observed_at: datetime,
    metric_window_minutes: int,
) -> tuple[ReassessmentRequest, ...]:
    roles = validate_approved_resource_roles(approved_resource_roles)
    alert_rules = {rule.casefold() for rule in approved_metric_alert_rules}
    checkpoints: dict[str, SignalCheckpoint] = {}
    sent: list[ReassessmentRequest] = []
    for resource_id, role in roles.items():
        rule_name = _signal_rule_name(role)
        if rule_name.casefold() not in alert_rules:
            raise SignalDetectionError(
                "detector signal rule is not in the exact approved allowlist"
            )
        checkpoint = state_store.load_checkpoint(resource_id=resource_id)
        if checkpoint.pending_request is None:
            checkpoints[resource_id] = checkpoint
            continue
        pending_request = checkpoint.pending_request
        expected_request = build_reassessment_request(
            pending_request.trigger_event,
            approved_resource_roles=roles,
        )
        if (
            checkpoint.pending_healthy is None
            or checkpoint.pending_healthy
            != (pending_request.lifecycle == "resolved")
            or pending_request.canonical_bytes() != expected_request.canonical_bytes()
            or pending_request.trigger_event.operation_name.casefold()
            != rule_name.casefold()
        ):
            raise SignalDetectionError("pending detector transition lost its binding")
        sender.send(
            pending_request,
            message_id=pending_request.idempotency_key,
            session_id=pending_request.incident_id,
        )
        state_store.complete_transition(
            resource_id=resource_id,
            request_id=pending_request.request_id,
            observed_at=observed_at,
        )
        sent.append(pending_request)

    observations: list[tuple[ApprovedSignalObservation, str]] = []
    for resource_id, role in roles.items():
        if resource_id not in checkpoints:
            continue
        observation = read_approved_signal(
            reader=reader,
            resource_id=resource_id,
            workload_role=role,
            observed_at=observed_at,
            metric_window_minutes=metric_window_minutes,
        )
        rule_name = _signal_rule_name(role)
        observations.append((observation, rule_name))

    initial_healthy: list[str] = []
    pending: list[tuple[str, bool, ReassessmentRequest]] = []
    for observation, _rule_name in observations:
        resource_id = observation.resource_id
        checkpoint = checkpoints[resource_id]
        previous = checkpoint.committed_health
        emit = (previous is None and not observation.healthy) or (
            previous is not None and previous != observation.healthy
        )
        if not emit:
            if previous is None:
                initial_healthy.append(resource_id)
            continue
        reassessment = build_signal_reassessment_request(
            observation,
            approved_resource_roles=roles,
            approved_metric_alert_rules=alert_rules,
        )
        state_store.stage_transition(
            resource_id=resource_id,
            healthy=observation.healthy,
            observed_at=observed_at,
            request=reassessment,
        )
        pending.append((resource_id, observation.healthy, reassessment))

    for resource_id in initial_healthy:
        state_store.record_initial_health(
            resource_id=resource_id,
            observed_at=observed_at,
        )

    for resource_id, _healthy, reassessment in pending:
        sender.send(
            reassessment,
            message_id=reassessment.idempotency_key,
            session_id=reassessment.incident_id,
        )
        state_store.complete_transition(
            resource_id=resource_id,
            request_id=reassessment.request_id,
            observed_at=observed_at,
        )
        sent.append(reassessment)
    return tuple(sent)


def build_signal_reassessment_request(
    observation: ApprovedSignalObservation,
    *,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
) -> ReassessmentRequest:
    roles = validate_approved_resource_roles(approved_resource_roles)
    resource_id = observation.resource_id.lower()
    if roles.get(resource_id) != observation.workload_role:
        raise SignalDetectionError("signal observation is outside the approved resource roles")
    rule_name = _signal_rule_name(observation.workload_role)
    alert_rules = {rule.casefold() for rule in approved_metric_alert_rules}
    if rule_name.casefold() not in alert_rules:
        raise SignalDetectionError(
            "detector signal rule is not in the exact approved allowlist"
        )
    raw_event = _synthetic_monitor_event(
        resource_id=resource_id,
        rule_name=rule_name,
        lifecycle="resolved" if observation.healthy else "activated",
        observed_at=observation.observed_at,
    )
    try:
        normalized = normalize_monitor_event(
            raw_event,
            received_at=observation.observed_at,
            approved_metric_alert_rules=alert_rules,
        )
        return build_reassessment_request(
            normalized,
            approved_resource_roles=roles,
        )
    except (EventNormalizationError, EventRoutingError) as exc:
        raise SignalDetectionError(
            "detected signal failed exact normalization or routing"
        ) from exc


def _signal_rule_name(role: WorkloadRole) -> str:
    return (
        f"wc016-scheduled-{role}-power-state"
        if role in {"database-primary", "web"}
        else "wc016-scheduled-load-balancer-availability"
    )


def run_scheduled_signal_detector(
    *,
    fully_qualified_namespace: str,
    reassessment_queue_name: str,
    managed_identity_client_id: str,
    approved_resource_roles: Mapping[str, WorkloadRole],
    approved_metric_alert_rules: Collection[str],
    detector_state_table_endpoint: str,
    detector_state_table_name: str,
    detector_state_partition_key: str,
    metric_window_minutes: int = 5,
) -> int:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import ServiceBusClient

    from athena_context.eventing.service_bus import AzureServiceBusReassessmentSender

    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
    ):
        raise SignalDetectionError("Service Bus namespace is invalid")
    reader = ManagedIdentityArmJsonReader(managed_identity_client_id=managed_identity_client_id)
    state_store = AzureTableSignalStateStore(
        endpoint=detector_state_table_endpoint,
        table_name=detector_state_table_name,
        partition_key=detector_state_partition_key,
        managed_identity_client_id=managed_identity_client_id,
    )
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    with (
        ServiceBusClient(
            fully_qualified_namespace=fully_qualified_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_sender(queue_name=reassessment_queue_name) as queue_sender,
    ):
        return len(
            detect_signal_requests(
                reader=reader,
                state_store=state_store,
                sender=AzureServiceBusReassessmentSender(queue_sender),
                approved_resource_roles=approved_resource_roles,
                approved_metric_alert_rules=approved_metric_alert_rules,
                observed_at=datetime.now(tz=UTC).replace(second=0, microsecond=0),
                metric_window_minutes=metric_window_minutes,
            )
        )


def _canonical_resource_id(resource_id: str) -> str:
    canonical = resource_id.strip().rstrip("/").lower()
    segments = canonical.split("/")
    if (
        not canonical.startswith("/subscriptions/")
        or len(canonical) > 2048
        or any(character in canonical for character in ("\\", "%", "?", "#"))
        or len(segments) != 9
        or segments[1] != "subscriptions"
        or segments[3] != "resourcegroups"
        or not segments[4]
        or segments[5] != "providers"
    ):
        raise SignalDetectionError("approved resource ID is invalid")
    try:
        subscription_id = str(UUID(segments[2]))
    except ValueError as exc:
        raise SignalDetectionError("approved resource subscription ID is invalid") from exc
    if subscription_id != segments[2]:
        raise SignalDetectionError("approved resource subscription ID is not canonical")
    return canonical


def _canonical_arm_operation(
    resource_id: str,
    *,
    query: Mapping[str, str],
) -> str:
    if resource_id.endswith(_VM_INSTANCE_VIEW_SUFFIX):
        suffix = _VM_INSTANCE_VIEW_SUFFIX
        base_resource_id = resource_id[: -len(suffix)]
        if dict(query) != {"api-version": _VM_API_VERSION}:
            raise SignalDetectionError(
                "VM instanceView request must use the exact reviewed query"
            )
    elif resource_id.endswith(_METRICS_SUFFIX):
        suffix = _METRICS_SUFFIX
        base_resource_id = resource_id[: -len(suffix)]
        expected_keys = {
            "api-version",
            "metricnames",
            "metricnamespace",
            "timespan",
            "interval",
            "aggregation",
            "AutoAdjustTimegrain",
            "ValidateDimensions",
        }
        if (
            set(query) != expected_keys
            or query.get("api-version") != _METRICS_API_VERSION
            or query.get("metricnames") != ",".join(_LB_METRICS)
            or query.get("metricnamespace") != "Microsoft.Network/loadBalancers"
            or query.get("interval") != "PT1M"
            or query.get("aggregation") != "Average"
            or query.get("AutoAdjustTimegrain") != "false"
            or query.get("ValidateDimensions") != "true"
            or not _valid_metrics_timespan(query.get("timespan"))
        ):
            raise SignalDetectionError(
                "Azure Monitor metrics request must use the exact reviewed query"
            )
    else:
        raise SignalDetectionError("ARM operation path is not allowlisted")
    return _canonical_resource_id(base_resource_id) + suffix


def _valid_metrics_timespan(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = _ARM_TIMESPAN_PATTERN.fullmatch(value)
    if match is None:
        return False
    try:
        start = datetime.fromisoformat(match.group("start").replace("Z", "+00:00"))
        end = datetime.fromisoformat(match.group("end").replace("Z", "+00:00"))
    except ValueError:
        return False
    duration = end - start
    return (
        start.utcoffset() == UTC.utcoffset(start)
        and end.utcoffset() == UTC.utcoffset(end)
        and timedelta(minutes=2) <= duration <= timedelta(minutes=10)
    )


def validate_approved_resource_roles(
    roles: Mapping[str, WorkloadRole],
) -> dict[str, WorkloadRole]:
    if not 3 <= len(roles) <= 18:
        raise SignalDetectionError(
            "detector requires one database, one or more web VMs, and one load balancer"
        )
    normalized: dict[str, WorkloadRole] = {}
    for resource_id, role in roles.items():
        canonical = _canonical_resource_id(resource_id)
        segments = canonical.split("/")
        expected_provider = (
            "microsoft.network" if role == "load-balancer" else "microsoft.compute"
        )
        expected_type = "loadbalancers" if role == "load-balancer" else "virtualmachines"
        if (
            segments[6] != expected_provider
            or segments[7] != expected_type
            or not segments[8]
            or canonical in normalized
        ):
            raise SignalDetectionError("approved resource role binding is invalid or ambiguous")
        normalized[canonical] = role
    counts = {role: list(normalized.values()).count(role) for role in set(normalized.values())}
    if (
        counts.get("database-primary") != 1
        or counts.get("load-balancer") != 1
        or not 1 <= counts.get("web", 0) <= 16
    ):
        raise SignalDetectionError("approved resource roles have invalid cardinality")
    scopes = {tuple(resource_id.split("/")[2:5:2]) for resource_id in normalized}
    if len(scopes) != 1:
        raise SignalDetectionError(
            "approved resources must share one subscription and resource group"
        )
    return normalized


def read_approved_signal(
    *,
    reader: ArmJsonReaderPort,
    resource_id: str,
    workload_role: WorkloadRole,
    observed_at: datetime,
    metric_window_minutes: int,
) -> ApprovedSignalObservation:
    canonical = _canonical_resource_id(resource_id)
    if workload_role in {"database-primary", "web"}:
        if _VM_TYPE_SEGMENT not in canonical:
            raise SignalDetectionError("approved VM signal target has the wrong type")
        power_state = _vm_power_state(
            reader.get_json(
                canonical + "/instanceView",
                query={"api-version": _VM_API_VERSION},
            )
        )
        healthy = power_state == _VM_RUNNING
        return ApprovedSignalObservation(
            resource_id=canonical,
            workload_role=workload_role,
            healthy=healthy,
            observed_at=observed_at,
            evidence={"powerState": power_state},
            summary=(
                "The approved virtual machine is running."
                if healthy
                else f"The approved virtual machine reports {power_state}."
            ),
        )
    if workload_role != "load-balancer" or _LB_TYPE_SEGMENT not in canonical:
        raise SignalDetectionError("approved signal target has an invalid role or type")
    vip_average, dip_average = _load_balancer_availability(
        reader.get_json(
            canonical + "/providers/microsoft.insights/metrics",
            query={
                "api-version": _METRICS_API_VERSION,
                "metricnames": ",".join(_LB_METRICS),
                "metricnamespace": "Microsoft.Network/loadBalancers",
                "timespan": _timespan(observed_at, metric_window_minutes),
                "interval": "PT1M",
                "aggregation": "Average",
                "AutoAdjustTimegrain": "false",
                "ValidateDimensions": "true",
            },
        )
    )
    healthy = vip_average >= 100.0
    if not healthy:
        summary = "The approved load balancer VIP availability is degraded."
    elif dip_average < 100.0:
        summary = (
            "The load balancer VIP is available; DipAvailability indicates backend "
            "degradation, not a load balancer failure."
        )
    else:
        summary = "The approved load balancer VIP and backend availability are healthy."
    return ApprovedSignalObservation(
        resource_id=canonical,
        workload_role=workload_role,
        healthy=healthy,
        observed_at=observed_at,
        evidence={
            "vipAvailabilityMinimum": vip_average,
            "dipAvailabilityMinimum": dip_average,
        },
        summary=summary,
    )


def _vm_power_state(value: Mapping[str, Any]) -> str:
    statuses = value.get("statuses")
    if not isinstance(statuses, list):
        raise SignalDetectionError("VM instanceView omitted statuses")
    codes = [item.get("code", "").casefold() for item in statuses if isinstance(item, dict)]
    power_states = [code for code in codes if code.startswith("powerstate/")]
    if len(power_states) != 1:
        raise SignalDetectionError("VM instanceView power state was missing or ambiguous")
    power_state = power_states[0]
    if power_state == _VM_RUNNING or power_state in _VM_KNOWN_UNHEALTHY:
        return power_state
    raise SignalDetectionError("VM instanceView power state was unknown")


def _load_balancer_availability(value: Mapping[str, Any]) -> tuple[float, float]:
    metrics = value.get("value")
    if not isinstance(metrics, list) or len(metrics) != 2:
        raise SignalDetectionError("load balancer metrics were missing or ambiguous")
    by_name: dict[str, Mapping[str, Any]] = {}
    for metric in metrics:
        if not isinstance(metric, dict):
            raise SignalDetectionError("load balancer metric entry is invalid")
        name = metric.get("name")
        metric_name = name.get("value") if isinstance(name, dict) else None
        if not isinstance(metric_name, str) or metric_name in by_name:
            raise SignalDetectionError("load balancer metric names were missing or duplicated")
        by_name[metric_name] = metric
    averages: dict[str, float] = {}
    for metric_name in _LB_METRICS:
        metric = by_name.get(metric_name)
        if metric is None:
            raise SignalDetectionError("required load balancer metric was absent")
        timeseries = metric.get("timeseries")
        if not isinstance(timeseries, list) or not timeseries:
            raise SignalDetectionError("load balancer metric contained no time series")
        for series in timeseries:
            points = series.get("data") if isinstance(series, dict) else None
            if not isinstance(points, list):
                raise SignalDetectionError("load balancer metric series was invalid")
            values: list[float] = []
            for point in points:
                average = point.get("average") if isinstance(point, dict) else None
                if (
                    isinstance(average, (int, float))
                    and not isinstance(average, bool)
                    and math.isfinite(float(average))
                ):
                    values.append(float(average))
            if not values:
                raise SignalDetectionError("load balancer metric series had no numeric samples")
            minimum = min(values)
            current = averages.get(metric_name)
            averages[metric_name] = (
                minimum if current is None else min(current, minimum)
            )
    return averages["VipAvailability"], averages["DipAvailability"]


def _timespan(observed_at: datetime, metric_window_minutes: int) -> str:
    start = observed_at - timedelta(minutes=metric_window_minutes)
    start_text = start.isoformat().replace("+00:00", "Z")
    end_text = observed_at.isoformat().replace("+00:00", "Z")
    return f"{start_text}/{end_text}"


def _synthetic_monitor_event(
    *,
    resource_id: str,
    rule_name: str,
    lifecycle: str,
    observed_at: datetime,
) -> dict[str, object]:
    timestamp = observed_at.isoformat().replace("+00:00", "Z")
    digest_seed = f"{resource_id}\0{rule_name}\0{lifecycle}\0{timestamp}"
    import hashlib

    source_id = "scheduled-" + hashlib.sha256(digest_seed.encode("utf-8")).hexdigest()[:24]
    return {
        "schemaId": "azureMonitorCommonAlertSchema",
        "data": {
            "essentials": {
                "alertId": source_id,
                "signalType": "Metric",
                "monitorCondition": "Resolved" if lifecycle == "resolved" else "Fired",
                "severity": "Sev1",
                "alertRule": rule_name,
                "alertTargetIDs": [resource_id],
                "firedDateTime": timestamp,
                "resolvedDateTime": timestamp,
            }
        },
    }


__all__ = [
    "ApprovedSignalObservation",
    "ArmJsonReaderPort",
    "InMemorySignalStateStore",
    "ManagedIdentityArmJsonReader",
    "SignalCheckpoint",
    "SignalDetectionError",
    "SignalStateStorePort",
    "detect_signal_requests",
    "read_approved_signal",
    "run_scheduled_signal_detector",
    "validate_approved_resource_roles",
]
