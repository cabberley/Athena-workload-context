from __future__ import annotations

from athena_context.api.domain import AuditEvent, PendingAuditEvent
from athena_context.api.errors import AuditIntegrityError
from athena_context.contracts import compute_artifact_digest


def audit_event_digest(
    event: PendingAuditEvent,
    *,
    sequence: int,
    event_id: str,
    previous_event_digest: str | None,
) -> str:
    """Build the canonical, append-only integrity value for one audit event."""

    return compute_artifact_digest(
        {
            "schemaVersion": "athena.context-audit.v1",
            "sequence": sequence,
            "eventId": event_id,
            "previousEventDigest": previous_event_digest,
            "event": event.model_dump(mode="json", exclude_none=True),
        }
    )


def verify_audit_chain(events: list[AuditEvent]) -> None:
    """Reject gaps, reordered records, and any modified audit event."""

    previous_event_digest: str | None = None
    for sequence, event in enumerate(events, start=1):
        expected_event_id = f"audit-{sequence:08d}"
        if (
            event.sequence != sequence
            or event.event_id != expected_event_id
            or event.previous_event_digest != previous_event_digest
        ):
            raise AuditIntegrityError("audit history ordering or linkage is invalid")
        pending = PendingAuditEvent.model_validate(
            event.model_dump(
                mode="python",
                exclude={"sequence", "event_id", "previous_event_digest", "event_digest"},
            )
        )
        expected_digest = audit_event_digest(
            pending,
            sequence=sequence,
            event_id=expected_event_id,
            previous_event_digest=previous_event_digest,
        )
        if event.event_digest != expected_digest:
            raise AuditIntegrityError("audit history integrity digest is invalid")
        previous_event_digest = event.event_digest
