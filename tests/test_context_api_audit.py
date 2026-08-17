from __future__ import annotations

import pytest

from athena_context.api.domain import AuditAction, PublishCommand
from athena_context.api.errors import AuthorizationError
from context_api_support import (
    AGENT,
    AUDITOR,
    approve_draft,
    build_service,
    canonical_manifest,
    create_draft,
    publish_draft,
    transition,
)


def test_audit_history_is_ordered_complete_and_records_lineage() -> None:
    service = build_service()
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="audited"),
        key_prefix="audited",
    )
    publish_draft(service, approved, key_prefix="audited")

    events = service.audit_history(AUDITOR, approved.manifest_id)

    assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
    assert [event.event_id for event in events] == [
        "audit-00000001",
        "audit-00000002",
        "audit-00000003",
        "audit-00000004",
        "audit-00000005",
    ]
    assert [event.action for event in events] == [
        AuditAction.DRAFT_CREATED,
        AuditAction.DRAFT_VALIDATED,
        AuditAction.REVIEW_SUBMITTED,
        AuditAction.DRAFT_APPROVED,
        AuditAction.VERSION_PUBLISHED,
    ]
    assert events[-1].previous_revision == 4
    assert events[-1].revision == 5
    assert all(event.actor.actor_id for event in events)
    assert all(event.reason for event in events)
    assert all(event.occurred_at.tzinfo is not None for event in events)


def test_denied_publication_does_not_write_state_audit_or_receipt() -> None:
    service = build_service()
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="denied-audit"),
        key_prefix="denied-audit",
    )
    assert approved.approval is not None
    command = PublishCommand(
        **transition(approved, "Agent publication must be rejected").model_dump(),
        approval_id=approved.approval.decision_id,
    )

    for _ in range(2):
        with pytest.raises(AuthorizationError):
            service.publish_draft(
                AGENT,
                approved.draft_id,
                "denied-publication-key",
                command,
            )

    events = service.audit_history(AUDITOR, approved.manifest_id)
    assert len(events) == 4
    assert service.get_draft(AGENT, approved.draft_id).state.value == "approved"
