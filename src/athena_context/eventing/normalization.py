from __future__ import annotations

import hashlib
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from athena_context.contracts import canonicalize_json, sha256_hex
from athena_context.contracts.eventing import NormalizedMonitorEvent

_VM_TYPE = "Microsoft.Compute/virtualMachines"
_LB_TYPE = "Microsoft.Network/loadBalancers"
_ACTIVE_STATES = {
    "unavailable",
    "degraded",
    "fired",
    "activated",
    "deallocate",
    "poweroff",
    "delete",
}
_RESOLVED_STATES = {"available", "resolved", "start", "restart"}
_ACTIVE_ACTIONS = ("/deallocate/", "/poweroff/", "/delete")
_RESOLVED_ACTIONS = ("/start/", "/restart/")


class EventNormalizationError(ValueError):
    """Raised when an Azure event cannot be safely normalized."""


def normalize_monitor_event(
    value: object,
    *,
    received_at: datetime,
    approved_metric_alert_rules: Collection[str] = (),
) -> NormalizedMonitorEvent:
    if received_at.utcoffset() is None or received_at.utcoffset() != UTC.utcoffset(received_at):
        raise EventNormalizationError("received_at must use UTC")
    event = _record(value, "event")
    if "eventType" in event and "data" in event:
        normalized = _from_event_grid(event, received_at=received_at)
    elif "schemaId" in event and event.get("schemaId") == "azureMonitorCommonAlertSchema":
        normalized = _from_common_alert(
            event,
            received_at=received_at,
            approved_metric_alert_rules=approved_metric_alert_rules,
        )
    else:
        raise EventNormalizationError("unsupported Azure event envelope")
    try:
        return NormalizedMonitorEvent.model_validate(normalized)
    except ValidationError as exc:
        raise EventNormalizationError("normalized event contract is invalid") from exc


def _from_event_grid(event: dict[str, Any], *, received_at: datetime) -> dict[str, object]:
    data = _record(event.get("data"), "event data")
    resource_id = _resource_id(
        data.get("resourceUri") or data.get("resourceId") or event.get("subject")
    )
    resource_type = _resource_type(resource_id, data.get("resourceProvider"))
    operation = _bounded_text(
        data.get("operationName") or data.get("status") or event.get("eventType"),
        "operation",
    )
    category = str(data.get("category", "")).lower()
    signal_kind = "resourceHealth" if category == "resourcehealth" else "activityLog"
    observed_at = _timestamp(event.get("eventTime") or data.get("eventTimestamp"))
    status = " ".join(
        str(item)
        for item in (operation, data.get("status"), data.get("currentHealthStatus"))
        if item
    )
    return _normalized(
        source_system="azureEventGrid",
        signal_kind=signal_kind,
        source_id=_bounded_text(event.get("id"), "event id"),
        resource_id=resource_id,
        resource_type=resource_type,
        operation=operation,
        lifecycle=_lifecycle(status),
        severity=_severity(data.get("level") or data.get("currentHealthStatus")),
        observed_at=observed_at,
        received_at=received_at,
        raw_safe={
            "id": event.get("id"),
            "eventType": event.get("eventType"),
            "subject": event.get("subject"),
            "eventTime": event.get("eventTime"),
            "data": {
                "resourceUri": data.get("resourceUri"),
                "resourceProvider": data.get("resourceProvider"),
                "operationName": data.get("operationName"),
                "status": data.get("status"),
                "category": data.get("category"),
                "currentHealthStatus": data.get("currentHealthStatus"),
            },
        },
    )


def _from_common_alert(
    event: dict[str, Any],
    *,
    received_at: datetime,
    approved_metric_alert_rules: Collection[str],
) -> dict[str, object]:
    data = _record(event.get("data"), "alert data")
    essentials = _record(data.get("essentials"), "alert essentials")
    targets = essentials.get("alertTargetIDs")
    if not isinstance(targets, list) or len(targets) != 1:
        raise EventNormalizationError("alert must target exactly one Azure resource")
    resource_id = _resource_id(targets[0])
    resource_type = _resource_type(resource_id, None)
    signal_type = _bounded_text(essentials.get("signalType"), "signal type")
    monitor_condition = _bounded_text(
        essentials.get("monitorCondition"), "monitor condition"
    )
    operation = _bounded_text(
        essentials.get("alertRule") or signal_type, "alert rule"
    )
    signal_type_lower = signal_type.lower()
    monitor_condition_lower = monitor_condition.lower()
    if resource_type == _LB_TYPE and signal_type.lower() not in {
        "metric",
        "resource health",
    }:
        raise EventNormalizationError(
            "load balancer failures require metric or resource-health evidence"
        )
    approved_rules = {rule.casefold() for rule in approved_metric_alert_rules}
    if signal_type_lower == "metric" and operation.casefold() not in approved_rules:
        raise EventNormalizationError(
            "metric alert rule is not an approved workload availability signal"
        )
    observed_value = (
        essentials.get("resolvedDateTime")
        if monitor_condition_lower == "resolved"
        else essentials.get("firedDateTime")
    )
    return _normalized(
        source_system="azureMonitorCommonAlert",
        signal_kind=(
            "resourceHealth"
            if signal_type_lower == "resource health"
            else "metricAlert"
        ),
        source_id=_bounded_text(essentials.get("alertId"), "alert id"),
        resource_id=resource_id,
        resource_type=resource_type,
        operation=operation,
        lifecycle=_lifecycle(monitor_condition),
        severity=_severity(essentials.get("severity")),
        observed_at=_timestamp(observed_value),
        received_at=received_at,
        raw_safe={
            "schemaId": event.get("schemaId"),
            "data": {
                "essentials": {
                    "alertId": essentials.get("alertId"),
                    "signalType": essentials.get("signalType"),
                    "monitorCondition": essentials.get("monitorCondition"),
                    "severity": essentials.get("severity"),
                    "alertRule": essentials.get("alertRule"),
                    "alertTargetIDs": targets,
                    "firedDateTime": essentials.get("firedDateTime"),
                    "resolvedDateTime": essentials.get("resolvedDateTime"),
                }
            },
        },
    )


def _normalized(
    *,
    source_system: str,
    signal_kind: str,
    source_id: str,
    resource_id: str,
    resource_type: str,
    operation: str,
    lifecycle: str,
    severity: str,
    observed_at: datetime,
    received_at: datetime,
    raw_safe: dict[str, object],
) -> dict[str, object]:
    subscription_id, resource_group = _scope(resource_id)
    source_digest = sha256_hex(canonicalize_json(raw_safe))
    deduplication_key = sha256_hex(
        "\0".join(
            (
                source_system,
                source_id.lower(),
                resource_id,
                lifecycle,
                observed_at.isoformat(),
            )
        )
    )
    return {
        "schemaVersion": "athena.monitorEvent.normalized.v1",
        "eventId": f"evt-{hashlib.sha256(deduplication_key.encode()).hexdigest()[:12]}",
        "deduplicationKey": deduplication_key,
        "sourceSystem": source_system,
        "signalKind": signal_kind,
        "lifecycle": lifecycle,
        "severity": severity,
        "subscriptionId": subscription_id,
        "resourceGroupName": resource_group,
        "targetResourceId": resource_id,
        "targetResourceType": resource_type,
        "operationName": operation,
        "observedAt": observed_at,
        "receivedAt": received_at,
        "sourceDigest": source_digest,
    }


def _record(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EventNormalizationError(f"{label} must be an object")
    return value


def _bounded_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise EventNormalizationError(f"{label} is missing or outside its bound")
    return value.strip()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise EventNormalizationError("event timestamp is missing or invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventNormalizationError("event timestamp is invalid") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EventNormalizationError("event timestamp must use UTC")
    return parsed


def _resource_id(value: object) -> str:
    if not isinstance(value, str):
        raise EventNormalizationError("target resource ID is missing")
    normalized = value.strip().rstrip("/").lower()
    if not normalized.startswith("/subscriptions/") or len(normalized) > 2048:
        raise EventNormalizationError("target resource ID is invalid")
    return normalized


def _resource_type(resource_id: str, provider: object) -> str:
    lowered = resource_id.lower()
    if "/providers/microsoft.compute/virtualmachines/" in lowered:
        return _VM_TYPE
    if "/providers/microsoft.network/loadbalancers/" in lowered:
        return _LB_TYPE
    if isinstance(provider, str):
        normalized = provider.strip().lower()
        if normalized == "microsoft.compute":
            return _VM_TYPE
        if normalized == "microsoft.network":
            return _LB_TYPE
    raise EventNormalizationError("target resource type is not allowlisted")


def _scope(resource_id: str) -> tuple[str, str]:
    segments = resource_id.split("/")
    try:
        return segments[2], segments[4]
    except IndexError as exc:
        raise EventNormalizationError("target resource scope is invalid") from exc


def _lifecycle(value: str) -> str:
    lowered = value.lower().strip()
    tokens = {
        token.strip(" :,")
        for token in lowered.replace("\n", " ").split()
        if token.strip(" :,")
    }
    if tokens & _ACTIVE_STATES or any(action in lowered for action in _ACTIVE_ACTIONS):
        return "activated"
    if tokens & _RESOLVED_STATES or any(
        action in lowered for action in _RESOLVED_ACTIONS
    ):
        return "resolved"
    return "unknown"


def _severity(value: object) -> str:
    lowered = str(value or "").lower()
    if lowered in {"sev0", "sev1", "critical", "error", "unavailable"}:
        return "critical"
    if lowered in {"sev2", "sev3", "warning", "degraded"}:
        return "warning"
    if lowered in {"sev4", "informational", "info", "available"}:
        return "informational"
    return "unknown"
