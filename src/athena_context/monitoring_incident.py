from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from athena_context.contracts.common import compute_artifact_digest

type MonitoringIncidentHealthState = Literal[
    "healthy",
    "degraded",
    "unhealthy",
    "unavailable",
]
type MonitoringHealthRecordKind = Literal[
    "amaHeartbeat",
    "vmConnectionHealth",
    "resourceHealth",
]

_HEALTH_RECORD_REFERENCE_PREFIX: dict[MonitoringHealthRecordKind, str] = {
    "amaHeartbeat": "ama-heartbeat",
    "vmConnectionHealth": "vm-insights",
    "resourceHealth": "resource-health",
}


class MonitoringIncidentSelectionError(ValueError):
    """Raised when monitoring evidence cannot select one canonical incident."""


def monitoring_source_record_reference(prefix: str, source_record_id: str) -> str:
    if (
        type(prefix) is not str
        or not prefix
        or type(source_record_id) is not str
        or not source_record_id
    ):
        raise ValueError("monitoring source-record reference inputs must be non-empty text")
    return f"{prefix}:sha256:" + hashlib.sha256(source_record_id.encode("utf-8")).hexdigest()


def monitoring_health_source_record_reference(
    record_kind: MonitoringHealthRecordKind,
    source_record_id: str,
) -> str:
    return monitoring_source_record_reference(
        _HEALTH_RECORD_REFERENCE_PREFIX[record_kind],
        source_record_id,
    )


@dataclass(frozen=True, slots=True)
class MonitoringIncidentSample:
    resource_id: str
    control_id: str
    payload_id: str
    selection_key: str
    observed_start: datetime
    observed_end: datetime
    state: MonitoringIncidentHealthState


@dataclass(frozen=True, slots=True)
class MonitoringIncidentSelection:
    incident_resource_id: str
    previous: MonitoringIncidentSample
    current: tuple[MonitoringIncidentSample, ...]
    current_state: Literal["degraded", "unhealthy", "unavailable"]


@dataclass(frozen=True, slots=True)
class SelectedIncident:
    incident_resource_id: str
    previous_record_id: str
    current_record_ids: tuple[str, ...]
    current_state: Literal["degraded", "unhealthy", "unavailable"]
    transition_digest: str


def build_selected_incident(
    *,
    incident_resource_id: str,
    previous_record_id: str,
    current_record_ids: tuple[str, ...],
    current_state: Literal["degraded", "unhealthy", "unavailable"],
) -> SelectedIncident:
    normalized_resource_id = incident_resource_id.casefold().rstrip("/")
    normalized_current_ids = tuple(sorted(current_record_ids))
    resource_segments = normalized_resource_id.strip("/").split("/")
    try:
        subscription_id_is_valid = (
            len(resource_segments) >= 8
            and resource_segments[0] == "subscriptions"
            and str(UUID(resource_segments[1])) == resource_segments[1]
            and resource_segments[2] == "resourcegroups"
            and bool(resource_segments[3])
            and resource_segments[4] == "providers"
            and bool(resource_segments[5])
            and bool(resource_segments[6])
            and bool(resource_segments[7])
            and (len(resource_segments) - 6) % 2 == 0
        )
    except ValueError, IndexError:
        subscription_id_is_valid = False
    if (
        not subscription_id_is_valid
        or not 1 <= len(previous_record_id) <= 2048
        or not normalized_current_ids
        or len(normalized_current_ids) != len(set(normalized_current_ids))
        or previous_record_id in normalized_current_ids
        or any(not 1 <= len(item) <= 2048 for item in normalized_current_ids)
        or current_state not in {"degraded", "unhealthy", "unavailable"}
    ):
        raise MonitoringIncidentSelectionError(
            "selected incident record IDs and resource must be canonical and unique"
        )
    payload = {
        "incidentResourceId": normalized_resource_id,
        "previousRecordId": previous_record_id,
        "currentRecordIds": list(normalized_current_ids),
        "currentState": current_state,
    }
    return SelectedIncident(
        incident_resource_id=normalized_resource_id,
        previous_record_id=previous_record_id,
        current_record_ids=normalized_current_ids,
        current_state=current_state,
        transition_digest=compute_artifact_digest(payload),
    )


def _expand_monitoring_incident_current(
    samples: tuple[MonitoringIncidentSample, ...],
    *,
    incident_resource_id: str,
    seed_current: tuple[MonitoringIncidentSample, ...],
    current_state: Literal["degraded", "unhealthy", "unavailable"],
) -> tuple[MonitoringIncidentSample, ...]:
    candidates = tuple(
        item
        for item in samples
        if item.resource_id == incident_resource_id and item.state == current_state
    )
    components: list[
        tuple[
            str,
            datetime,
            datetime,
            tuple[MonitoringIncidentSample, ...],
        ]
    ] = []
    for control_id in sorted({item.control_id for item in candidates}):
        ordered = sorted(
            (item for item in candidates if item.control_id == control_id),
            key=lambda item: (
                item.observed_start,
                item.observed_end,
                item.selection_key,
            ),
        )
        component_start = ordered[0].observed_start
        component_end = ordered[0].observed_end
        component_samples = [ordered[0]]
        for candidate in ordered[1:]:
            if candidate.observed_start <= component_end:
                component_end = max(component_end, candidate.observed_end)
                component_samples.append(candidate)
                continue
            components.append(
                (
                    control_id,
                    component_start,
                    component_end,
                    tuple(component_samples),
                )
            )
            component_start = candidate.observed_start
            component_end = candidate.observed_end
            component_samples = [candidate]
        components.append(
            (
                control_id,
                component_start,
                component_end,
                tuple(component_samples),
            )
        )

    seed_component_indexes = {
        index
        for index, (_, _, _, component_samples) in enumerate(components)
        if any(item in component_samples for item in seed_current)
    }
    if len(seed_component_indexes) != 1 or any(
        not any(item in component_samples for _, _, _, component_samples in components)
        for item in seed_current
    ):
        raise MonitoringIncidentSelectionError(
            "selected health evidence does not form one connected primary episode"
        )

    selected_components = set(seed_component_indexes)
    selected_control_ids = {components[index][0] for index in selected_components}
    incident_start = min(components[index][1] for index in selected_components)
    incident_end = max(components[index][2] for index in selected_components)
    changed = True
    while changed:
        changed = False
        for index, (
            control_id,
            component_start,
            component_end,
            _,
        ) in enumerate(components):
            if index in selected_components:
                continue
            if component_start > incident_end or component_end < incident_start:
                continue
            if control_id in selected_control_ids:
                raise MonitoringIncidentSelectionError(
                    "current health evidence spans disconnected intervals in one control"
                )
            selected_components.add(index)
            selected_control_ids.add(control_id)
            incident_start = min(incident_start, component_start)
            incident_end = max(incident_end, component_end)
            changed = True

    for index in selected_components:
        control_id, component_start, component_end, _ = components[index]
        if any(
            item.resource_id == incident_resource_id
            and item.control_id == control_id
            and item.state == "healthy"
            and item.observed_start < component_end
            and item.observed_end > component_start
            for item in samples
        ):
            raise MonitoringIncidentSelectionError(
                "current health episode conflicts with overlapping healthy evidence"
            )

    return tuple(
        sorted(
            (item for index in selected_components for item in components[index][3]),
            key=lambda item: item.selection_key,
        )
    )


def select_monitoring_incident(
    samples: tuple[MonitoringIncidentSample, ...],
) -> MonitoringIncidentSelection:
    if (
        len({item.payload_id for item in samples}) != len(samples)
        or len({item.selection_key for item in samples}) != len(samples)
        or any(item.observed_start > item.observed_end for item in samples)
    ):
        raise MonitoringIncidentSelectionError(
            "monitoring incident samples must be unique with valid intervals"
        )
    state_rank = {"degraded": 1, "unhealthy": 2, "unavailable": 3}
    candidates: dict[
        str,
        list[
            tuple[
                MonitoringIncidentSample,
                tuple[MonitoringIncidentSample, ...],
            ]
        ],
    ] = {}
    groups = sorted({(item.resource_id, item.control_id) for item in samples})
    for resource_id, control_id in groups:
        group_samples = tuple(
            item
            for item in samples
            if item.resource_id == resource_id and item.control_id == control_id
        )
        latest_end = max(item.observed_end for item in group_samples)
        terminal = tuple(item for item in group_samples if item.observed_end == latest_end)
        terminal_states = {item.state for item in terminal}
        if len(terminal_states) > 1:
            raise MonitoringIncidentSelectionError(
                "latest health evidence is contradictory and requires manual investigation"
            )
        adverse_terminal = tuple(item for item in terminal if item.state != "healthy")
        if not adverse_terminal:
            continue
        selected_state = max(
            (item.state for item in adverse_terminal),
            key=lambda item: state_rank[item],
        )
        seed = max(
            (item for item in adverse_terminal if item.state == selected_state),
            key=lambda item: (item.observed_start, item.selection_key),
        )
        episode = {seed}
        episode_start = seed.observed_start
        episode_end = seed.observed_end
        changed = True
        while changed:
            changed = False
            for item in group_samples:
                if (
                    item in episode
                    or item.state != selected_state
                    or item.observed_start > episode_end
                    or item.observed_end < episode_start
                ):
                    continue
                episode.add(item)
                episode_start = min(episode_start, item.observed_start)
                episode_end = max(episode_end, item.observed_end)
                changed = True
        if any(
            item.state == "healthy"
            and item.observed_start < episode_end
            and item.observed_end > episode_start
            for item in group_samples
        ):
            raise MonitoringIncidentSelectionError(
                "current health episode conflicts with overlapping healthy evidence"
            )
        predecessors = tuple(
            item
            for item in group_samples
            if item.state == "healthy" and item.observed_end <= episode_start
        )
        if predecessors:
            candidates.setdefault(resource_id, []).append(
                (
                    max(
                        predecessors,
                        key=lambda item: (
                            item.observed_end,
                            item.selection_key,
                        ),
                    ),
                    tuple(
                        sorted(
                            episode,
                            key=lambda item: item.selection_key,
                        )
                    ),
                )
            )
    if len(candidates) != 1:
        raise MonitoringIncidentSelectionError(
            "acquired evidence must identify exactly one unambiguous health transition"
        )
    incident_resource_id, resource_candidates = candidates.popitem()
    selected_previous, selected_current = max(
        resource_candidates,
        key=lambda item: (
            state_rank[item[1][0].state],
            max(sample.observed_end for sample in item[1]),
            item[1][0].control_id,
        ),
    )
    selected_state = cast(
        Literal["degraded", "unhealthy", "unavailable"],
        selected_current[0].state,
    )
    expanded_current = _expand_monitoring_incident_current(
        samples,
        incident_resource_id=incident_resource_id,
        seed_current=selected_current,
        current_state=selected_state,
    )
    expanded_start = min(item.observed_start for item in expanded_current)
    expanded_predecessors = tuple(
        item
        for item in samples
        if item.resource_id == incident_resource_id
        and item.state == "healthy"
        and item.observed_end <= expanded_start
    )
    if not expanded_predecessors:
        raise MonitoringIncidentSelectionError(
            "expanded incident evidence has no canonical healthy predecessor"
        )
    expanded_control_ids = {item.control_id for item in expanded_current}
    selected_previous = max(
        expanded_predecessors,
        key=lambda item: (
            item.observed_end,
            item.control_id in expanded_control_ids,
            item.observed_start,
            item.selection_key,
        ),
    )
    return MonitoringIncidentSelection(
        incident_resource_id=incident_resource_id,
        previous=selected_previous,
        current=expanded_current,
        current_state=selected_state,
    )


__all__ = [
    "MonitoringHealthRecordKind",
    "MonitoringIncidentHealthState",
    "MonitoringIncidentSample",
    "MonitoringIncidentSelection",
    "MonitoringIncidentSelectionError",
    "SelectedIncident",
    "build_selected_incident",
    "monitoring_health_source_record_reference",
    "monitoring_source_record_reference",
    "select_monitoring_incident",
]
