from __future__ import annotations

import hashlib
from collections.abc import Mapping

from athena_context.contracts.eventing import (
    IncidentScenario,
    NormalizedMonitorEvent,
    ReassessmentRequest,
    WorkloadRole,
)

_SCENARIOS: dict[WorkloadRole, IncidentScenario] = {
    "database-primary": "singletonDatabaseFailure",
    "web": "webServerFailure",
    "load-balancer": "loadBalancerFailure",
}


class EventRoutingError(ValueError):
    """Raised when an event cannot be bound to approved workload context."""


def build_reassessment_request(
    event: NormalizedMonitorEvent,
    *,
    approved_resource_roles: Mapping[str, WorkloadRole],
) -> ReassessmentRequest:
    role = approved_resource_roles.get(event.target_resource_id)
    if role is None:
        raise EventRoutingError("event target is not bound to one approved workload role")
    if (
        event.target_resource_type == "Microsoft.Network/loadBalancers"
        and role != "load-balancer"
    ):
        raise EventRoutingError("load balancer event has an inconsistent workload role")
    if (
        event.target_resource_type == "Microsoft.Compute/virtualMachines"
        and role == "load-balancer"
    ):
        raise EventRoutingError("virtual machine event has an inconsistent workload role")
    if event.lifecycle not in {"activated", "resolved"}:
        raise EventRoutingError("event lifecycle is not actionable")
    seed = event.deduplication_key.removeprefix("sha256:")
    incident_seed = hashlib.sha256(event.target_resource_id.encode()).hexdigest()
    return ReassessmentRequest(
        schemaVersion="athena.incidentReassessmentRequest.v1",
        requestId=f"reassess-{seed[:12]}",
        incidentId=f"inc-{incident_seed[:12]}",
        triggerEventId=event.event_id,
        triggerEvent=event,
        scenario=_SCENARIOS[role],
        workloadRole=role,
        targetResourceId=event.target_resource_id,
        lifecycle=event.lifecycle,
        idempotencyKey=f"wc016-{seed}",
        noAutoRemediation=True,
    )
