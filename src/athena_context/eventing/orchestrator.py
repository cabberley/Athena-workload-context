from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from athena_context.contracts.eventing import (
    IncidentState,
    ReassessmentRequest,
    VerifiedReassessmentResult,
)
from athena_context.eventing.incident_state import (
    build_active_incident_index_heartbeat,
    build_incident_publication,
    build_signed_incident_state,
    notification_message,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    ActiveIncidentIndexSnapshot,
    IncidentAssetPublisherPort,
    IncidentPublicationReceipt,
    PresentationAssetAlreadyExistsError,
)


class ScopedReassessmentPort(Protocol):
    def reassess(self, request: ReassessmentRequest) -> VerifiedReassessmentResult: ...


class NotificationOutboxPort(Protocol):
    def enqueue(
        self,
        *,
        incident_id: str,
        lifecycle: str,
        transition_id: str,
        message: str,
    ) -> None: ...


def run_active_incident_index_heartbeat(
    observations: Sequence[ReassessmentRequest],
    *,
    published_at: datetime,
    signing_key_id: str,
    signing_key_fingerprint: str,
    signer: PresentationSigner,
    publisher: IncidentAssetPublisherPort,
) -> ActiveIncidentIndexSnapshot:
    if not observations:
        raise ValueError("incident feed heartbeat requires approved observations")
    observed_resources = {
        request.target_resource_id: request for request in observations
    }
    if len(observed_resources) != len(observations):
        raise ValueError("incident feed heartbeat observations must be unique")

    last_conflict: PresentationAssetAlreadyExistsError | None = None
    for _attempt in range(3):
        active_index_snapshot = publisher.read_active_incident_index()
        _validate_active_index_health(
            active_index_snapshot,
            observations=observations,
        )
        publication = build_active_incident_index_heartbeat(
            published_at=published_at,
            key_id=signing_key_id,
            key_fingerprint=signing_key_fingerprint,
            signer=signer,
            active_index_snapshot=active_index_snapshot,
        )
        try:
            return publisher.publish_active_incident_index(publication)
        except PresentationAssetAlreadyExistsError as exc:
            last_conflict = exc
            latest = publisher.read_active_incident_index()
            _validate_active_index_health(latest, observations=observations)
            if (
                latest is not None
                and latest.index.published_at
                >= publication.active_index.published_at
            ):
                return latest
    assert last_conflict is not None
    raise last_conflict


def _validate_active_index_health(
    snapshot: ActiveIncidentIndexSnapshot | None,
    *,
    observations: Sequence[ReassessmentRequest],
) -> None:
    expected = {
        request.incident_id: request
        for request in observations
        if request.lifecycle == "activated"
    }
    actual = {
        entry.incident_id: entry
        for entry in (() if snapshot is None else snapshot.index.incidents)
    }
    if set(actual) != set(expected):
        raise ValueError(
            "active incident index does not match independently verified live health"
        )
    for incident_id, request in expected.items():
        entry = actual[incident_id]
        if (
            entry.scenario != request.scenario
            or entry.workload_role != request.workload_role
        ):
            raise ValueError(
                "active incident index binding does not match verified live health"
            )


def run_incident_reassessment(
    request: ReassessmentRequest,
    *,
    detected_at: datetime,
    updated_at: datetime,
    published_at: datetime,
    presentation_url: str,
    signing_key_id: str,
    signing_key_fingerprint: str,
    reassessment: ScopedReassessmentPort,
    signer: PresentationSigner,
    publisher: IncidentAssetPublisherPort,
    notifications: NotificationOutboxPort,
) -> tuple[IncidentState, IncidentPublicationReceipt] | None:
    result = reassessment.reassess(request)
    if result.request_id != request.request_id:
        raise ValueError("reassessment result does not match its request")
    active_index_snapshot = publisher.read_active_incident_index()
    active_entry = next(
        (
            entry
            for entry in (
                ()
                if active_index_snapshot is None
                else active_index_snapshot.index.incidents
            )
            if entry.incident_id == request.incident_id
        ),
        None,
    )
    if active_entry is not None and (
        active_entry.scenario != request.scenario
        or active_entry.workload_role != request.workload_role
    ):
        raise ValueError("active incident index binding does not match reassessment")
    is_noop_reconciliation = (result.verified_healthy and active_entry is None) or (
        not result.verified_healthy and active_entry is not None
    )
    if is_noop_reconciliation:
        latest = publisher.read_current_incident_state(
            incident_id=request.incident_id
        )
        expected_lifecycle = "resolved" if result.verified_healthy else "active"
        if (
            latest is not None
            and latest.state.transition_id == request.idempotency_key
            and latest.state.lifecycle == expected_lifecycle
            and latest.state.scenario == request.scenario
            and latest.state.workload_role == request.workload_role
        ):
            if expected_lifecycle == "active":
                if (
                    active_entry is None
                    or active_entry.pointer_sha256
                    != latest.pointer_sha256
                    or active_entry.pointer_path
                    != (
                        "./"
                        + latest.pointer.state_path.removesuffix(
                            "/state.json"
                        ).removeprefix("./")
                        + "/pointer.json"
                    )
                    or active_entry.detected_at
                    != latest.state.detected_at
                    or active_entry.updated_at != latest.state.updated_at
                ):
                    raise RuntimeError(
                        "active incident index is not coherent with current occurrence"
                    )
            elif active_entry is not None:
                raise RuntimeError(
                    "resolved occurrence remains in the active incident index"
                )
            message = notification_message(
                latest.state,
                presentation_url=presentation_url,
            )
            if message is not None:
                notifications.enqueue(
                    incident_id=latest.state.incident_id,
                    lifecycle=latest.state.lifecycle,
                    transition_id=latest.state.transition_id,
                    message=message,
                )
            if (
                latest.occurrence is not None
                and active_index_snapshot is not None
            ):
                return latest.state, IncidentPublicationReceipt(
                    incident_id=latest.state.incident_id,
                    pointer_sha256=latest.pointer_sha256,
                    active_index_sha256=(
                        active_index_snapshot.payload_sha256
                    ),
                    occurrence=latest.occurrence,
                )
        return None
    incident_detected_at = (
        active_entry.detected_at if active_entry is not None else detected_at
    )
    state, attestation = build_signed_incident_state(
        request,
        detected_at=incident_detected_at,
        updated_at=max(updated_at, result.observed_at),
        target_binding=result.target_binding,
        reassessment_verified_healthy=result.verified_healthy,
        findings=result.findings,
        reasoning=result.reasoning,
        signer=signer,
        signing_key_id=signing_key_id,
    )
    publication = build_incident_publication(
        state,
        attestation,
        published_at=published_at,
        key_id=signing_key_id,
        key_fingerprint=signing_key_fingerprint,
        signer=signer,
        active_index_snapshot=active_index_snapshot,
    )
    receipt = publisher.publish_incident(publication)
    message = notification_message(state, presentation_url=presentation_url)
    if message is not None:
        notifications.enqueue(
            incident_id=state.incident_id,
            lifecycle=state.lifecycle,
            transition_id=state.transition_id,
            message=message,
        )
    return state, receipt
