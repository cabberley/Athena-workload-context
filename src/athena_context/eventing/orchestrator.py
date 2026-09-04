from __future__ import annotations

from datetime import datetime
from typing import Protocol

from athena_context.contracts.eventing import (
    IncidentState,
    ReassessmentRequest,
    VerifiedReassessmentResult,
)
from athena_context.eventing.incident_state import (
    build_incident_publication,
    build_signed_incident_state,
    notification_message,
)
from athena_context.presentation import PresentationSigner
from athena_context.presentation_assets import (
    IncidentAssetPublisherPort,
    IncidentPublicationReceipt,
)


class ScopedReassessmentPort(Protocol):
    def reassess(self, request: ReassessmentRequest) -> VerifiedReassessmentResult: ...


class NotificationOutboxPort(Protocol):
    def enqueue(
        self,
        *,
        incident_id: str,
        lifecycle: str,
        message: str,
    ) -> None: ...


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
) -> tuple[IncidentState, IncidentPublicationReceipt]:
    result = reassessment.reassess(request)
    if result.request_id != request.request_id:
        raise ValueError("reassessment result does not match its request")
    state, attestation = build_signed_incident_state(
        request,
        detected_at=detected_at,
        updated_at=updated_at,
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
    )
    receipt = publisher.publish_incident(publication)
    message = notification_message(state, presentation_url=presentation_url)
    if message is not None:
        notifications.enqueue(
            incident_id=state.incident_id,
            lifecycle=state.lifecycle,
            message=message,
        )
    return state, receipt
