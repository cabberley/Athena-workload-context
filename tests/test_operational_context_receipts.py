from __future__ import annotations

import pytest
from pydantic import ValidationError

from athena_context.api.domain import (
    ApproveCommand,
    PublishCommand,
    ReviewCommand,
    ReviewDecisionKind,
)
from athena_context.api.errors import (
    AuthorizationError,
    OperationalContextReceiptError,
)
from athena_context.api.operational_context import (
    IssueOperationalContextReceiptCommand,
)
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
)
from context_api_support import (
    AGENT,
    APPROVER,
    OPERATIONAL_CONTEXT_SERVICE,
    PUBLISHER,
    REVIEWER,
    build_service,
    canonical_manifest,
    create_draft,
    issue_operational_context_receipt,
    operational_context_command,
    transition,
)


def _submitted_draft():
    service = build_service()
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="operational-receipt-draft",
    )
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "operational-receipt-validate",
        transition(draft, "Validate the operational receipt candidate"),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "operational-receipt-submit",
        transition(draft, "Submit the operational receipt candidate"),
    )
    draft = service.review_draft(
        REVIEWER,
        draft.draft_id,
        "operational-receipt-review",
        ReviewCommand(
            **transition(
                draft,
                "Review the operational receipt candidate",
            ).model_dump(),
            decision=ReviewDecisionKind.APPROVED,
            comments="Reviewed the exact operational receipt candidate.",
        ),
    )
    return service, draft


def test_only_explicit_service_authority_can_issue_exact_receipt() -> None:
    service, draft = _submitted_draft()
    command = operational_context_command(service, draft)

    with pytest.raises(
        AuthorizationError,
        match="verified service actor",
    ):
        service.issue_operational_context_receipt(
            APPROVER,
            "human-cannot-issue-operational-receipt",
            command,
        )

    receipt = service.issue_operational_context_receipt(
        OPERATIONAL_CONTEXT_SERVICE,
        "service-issues-operational-receipt",
        command,
    )
    replay = service.issue_operational_context_receipt(
        OPERATIONAL_CONTEXT_SERVICE,
        "service-issues-operational-receipt",
        command,
    )

    assert replay == receipt
    assert receipt.issued_by == OPERATIONAL_CONTEXT_SERVICE
    assert receipt.draft_id == draft.draft_id
    assert receipt.draft_revision == draft.revision
    assert receipt.manifest_digest == draft.manifest_digest
    assert receipt.evidence_count == len(command.evidence_inventory)
    with service.persistence_store.transaction() as tx:
        assert (
            tx.get_operational_context_receipt(receipt.receipt_id)
            == receipt
        )


def test_operational_receipt_requires_at_least_one_evidence_item() -> None:
    service, draft = _submitted_draft()
    command = operational_context_command(service, draft)

    with pytest.raises(ValidationError, match="at least 1 item"):
        IssueOperationalContextReceiptCommand.model_validate(
            {
                **command.model_dump(mode="python"),
                "evidence_inventory": [],
            }
        )


def test_approval_fails_atomically_without_exact_operational_receipt() -> None:
    service, draft = _submitted_draft()
    audit_before = service.audit_history(APPROVER, draft.manifest_id)

    with pytest.raises(
        OperationalContextReceiptError,
        match="not found",
    ):
        service.approve_draft(
            APPROVER,
            draft.draft_id,
            "missing-operational-receipt",
            ApproveCommand(
                **transition(
                    draft,
                    "Reject approval without operational evidence",
                ).model_dump(),
                operational_context_receipt_id="operational-missing",
            ),
        )

    assert service.get_draft(APPROVER, draft.draft_id) == draft
    assert service.audit_history(APPROVER, draft.manifest_id) == audit_before
    with service.persistence_store.transaction() as tx:
        assert tx.get_receipt(
            APPROVER.actor_id,
            "missing-operational-receipt",
        ) is None


def test_approval_and_publication_each_require_current_exact_receipt() -> None:
    service, submitted = _submitted_draft()
    approval_receipt = issue_operational_context_receipt(
        service,
        submitted,
        key_prefix="exact-approval",
    )
    approved = service.approve_draft(
        APPROVER,
        submitted.draft_id,
        "exact-approval",
        ApproveCommand(
            **transition(
                submitted,
                "Approve with exact operational evidence",
            ).model_dump(),
            operational_context_receipt_id=approval_receipt.receipt_id,
        ),
    )
    assert approved.approval is not None
    assert (
        approved.approval.operational_context_receipt_id
        == approval_receipt.receipt_id
    )

    stale_publish_command = PublishCommand(
        **transition(
            approved,
            "Reject publication with the pre-approval receipt",
        ).model_dump(),
        approval_id=approved.approval.decision_id,
        operational_context_receipt_id=approval_receipt.receipt_id,
    )
    with pytest.raises(
        OperationalContextReceiptError,
        match="does not authorize",
    ):
        service.publish_draft(
            PUBLISHER,
            approved.draft_id,
            "stale-publication-operational-receipt",
            stale_publish_command,
        )
    assert service.get_draft(PUBLISHER, approved.draft_id) == approved

    publication_receipt = issue_operational_context_receipt(
        service,
        approved,
        key_prefix="exact-publication",
    )
    published = service.publish_draft(
        PUBLISHER,
        approved.draft_id,
        "exact-publication",
        PublishCommand(
            **transition(
                approved,
                "Publish with current operational evidence",
            ).model_dump(),
            approval_id=approved.approval.decision_id,
            operational_context_receipt_id=publication_receipt.receipt_id,
        ),
    )

    assert (
        published.operational_context_receipt_id
        == publication_receipt.receipt_id
    )
    assert (
        published.approval.operational_context_receipt_id
        == approval_receipt.receipt_id
    )


def test_environment_order_cannot_select_a_weaker_approval_profile() -> None:
    manifest = canonical_manifest()
    payload = manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["workload"]["environments"] = [
        "development",
        "production",
        "training",
    ]
    reordered = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    service = build_service()
    draft = create_draft(
        service,
        reordered,
        draft_id="reordered-environments",
    )
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "reordered-environments-validate",
        transition(draft, "Validate reordered environments"),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "reordered-environments-submit",
        transition(draft, "Submit reordered environments"),
    )
    draft = service.review_draft(
        REVIEWER,
        draft.draft_id,
        "reordered-environments-review",
        ReviewCommand(
            **transition(
                draft,
                "Review reordered environments",
            ).model_dump(),
            decision=ReviewDecisionKind.APPROVED,
            comments="Reviewed the canonical production candidate.",
        ),
    )
    development_receipt = issue_operational_context_receipt(
        service,
        draft,
        key_prefix="reordered-development",
        profile_id="development",
    )

    with pytest.raises(
        OperationalContextReceiptError,
        match="active environment profile",
    ):
        service.approve_draft(
            APPROVER,
            draft.draft_id,
            "reordered-development-approval",
            ApproveCommand(
                **transition(
                    draft,
                    "Reject development-only operational evidence",
                ).model_dump(),
                operational_context_receipt_id=(
                    development_receipt.receipt_id
                ),
            ),
        )

    production_receipt = issue_operational_context_receipt(
        service,
        draft,
        key_prefix="reordered-production",
        profile_id="production",
    )
    approved = service.approve_draft(
        APPROVER,
        draft.draft_id,
        "reordered-production-approval",
        ApproveCommand(
            **transition(
                draft,
                "Approve canonical production evidence",
            ).model_dump(),
            operational_context_receipt_id=production_receipt.receipt_id,
        ),
    )

    assert approved.state.value == "approved"
