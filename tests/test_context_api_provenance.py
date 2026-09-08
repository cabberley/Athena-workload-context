from __future__ import annotations

from datetime import UTC, datetime

import pytest

from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import PublishCommand, Role, RoleGrant
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.service import ContextService
from context_api_support import (
    AGENT,
    APPROVER,
    PUBLICATION_SERVICE,
    PUBLISHER,
    build_service,
    canonical_manifest,
    create_draft,
    transition,
)


class NaiveClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 17)


def test_untrusted_clock_value_fails_before_storage_commit() -> None:
    manifest = canonical_manifest()
    service = ContextService(
        store=InMemoryContextStore(),
        authorization=RoleBasedAuthorization(
            [RoleGrant(actor_id=AGENT.actor_id, role=Role.PROPOSER)]
        ),
        clock=NaiveClock(),
        publication_actor=PUBLICATION_SERVICE,
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        create_draft(service, manifest, draft_id="invalid-clock")

    assert service.list_drafts(AGENT, manifest_id=manifest.manifest_id) == []


def test_submission_finalizes_exact_publication_candidate_before_approval() -> None:
    service = build_service()
    draft = create_draft(service, canonical_manifest(), draft_id="provenance")
    untrusted_digest = draft.manifest_digest
    untrusted_audit = draft.manifest.audit
    validated = service.validate_draft(
        AGENT,
        draft.draft_id,
        "provenance-validate",
        transition(draft, "Validate before finalization"),
    )

    submitted = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "provenance-submit",
        transition(validated, "Finalize publication candidate"),
    )

    candidate = submitted.publication_candidate
    assert candidate is not None
    assert submitted.review is not None
    assert submitted.manifest_digest != untrusted_digest
    assert submitted.manifest.audit != untrusted_audit
    assert submitted.manifest.audit.published_by == PUBLICATION_SERVICE.actor_id
    assert submitted.manifest.audit.published_at == datetime(
        2025, 6, 1, 0, 0, 2, tzinfo=UTC
    )
    assert submitted.manifest.audit.approval_status == "approved"
    assert submitted.manifest.compute_artifact_digest_value() == submitted.manifest_digest
    assert candidate.finalized_by == PUBLICATION_SERVICE
    assert candidate.finalized_at == submitted.manifest.audit.published_at
    assert candidate.manifest_digest == submitted.manifest_digest
    assert submitted.review.publication_candidate_digest == submitted.manifest_digest


def test_approval_and_publication_preserve_candidate_and_record_human_authority() -> None:
    service = build_service()
    draft = create_draft(service, canonical_manifest(), draft_id="bound-candidate")
    validated = service.validate_draft(
        AGENT,
        draft.draft_id,
        "bound-validate",
        transition(draft, "Validate candidate"),
    )
    submitted = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "bound-submit",
        transition(validated, "Finalize candidate"),
    )
    approved = service.approve_draft(
        APPROVER,
        draft.draft_id,
        "bound-approve",
        transition(submitted, "Approve exact finalized artifact"),
    )
    assert approved.approval is not None
    approved_artifact = approved.manifest.canonical_json()

    published = service.publish_draft(
        PUBLISHER,
        approved.draft_id,
        "bound-publish",
        PublishCommand(
            **transition(approved, "Authorize immutable publication").model_dump(),
            approval_id=approved.approval.decision_id,
        ),
    )

    assert approved.approval.manifest_digest == approved.manifest_digest
    assert published.manifest.canonical_json() == approved_artifact
    assert published.manifest_digest == approved.approval.manifest_digest
    assert published.manifest.audit.published_by == published.published_by.actor_id
    assert published.manifest.audit.published_at == published.published_at
    assert published.published_by == PUBLICATION_SERVICE
    assert published.publication_authorized_by == PUBLISHER
    assert published.publication_authorized_at == datetime(
        2025, 6, 1, 0, 0, 4, tzinfo=UTC
    )
    publication_event = service.audit_history(PUBLISHER, published.manifest_id)[-1]
    assert publication_event.actor == PUBLISHER
    assert publication_event.occurred_at == published.publication_authorized_at
    assert publication_event.publication_actor == published.published_by
    assert publication_event.publication_timestamp == published.published_at
