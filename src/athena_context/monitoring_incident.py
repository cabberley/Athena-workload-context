from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

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
    return MonitoringIncidentSelection(
        incident_resource_id=incident_resource_id,
        previous=selected_previous,
        current=selected_current,
        current_state=cast(
            Literal["degraded", "unhealthy", "unavailable"],
            selected_current[0].state,
        ),
    )


__all__ = [
    "MonitoringHealthRecordKind",
    "MonitoringIncidentHealthState",
    "MonitoringIncidentSample",
    "MonitoringIncidentSelection",
    "MonitoringIncidentSelectionError",
    "monitoring_health_source_record_reference",
    "monitoring_source_record_reference",
    "select_monitoring_incident",
]
