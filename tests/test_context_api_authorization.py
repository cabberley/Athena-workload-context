from __future__ import annotations

import pytest
from pydantic import ValidationError

from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import (
    AllWorkloadsGrantScope,
    Permission,
    PublishCommand,
    Role,
    RoleGrant,
    WorkloadGrantScope,
)
from athena_context.api.errors import AuthorizationError
from context_api_support import (
    AGENT,
    APPROVER,
    OUTSIDER,
    approve_draft,
    build_service,
    canonical_manifest,
    create_draft,
    transition,
)


def test_agent_cannot_approve_even_with_accidental_approver_grant() -> None:
    service = build_service()
    draft = create_draft(service, canonical_manifest(), draft_id="agent-approval")
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "agent-approval-validate",
        transition(draft, "Validate before review"),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "agent-approval-submit",
        transition(draft, "Submit for review"),
    )

    with pytest.raises(AuthorizationError, match="requires a human actor"):
        service.approve_draft(
            AGENT,
            draft.draft_id,
            "agent-approval-denied",
            transition(draft, "Agent attempts approval"),
        )


def test_agent_cannot_publish_even_with_accidental_publisher_grant() -> None:
    service = build_service()
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="agent-publish"),
        key_prefix="agent-publish",
    )
    assert approved.approval is not None

    with pytest.raises(AuthorizationError, match="requires a human actor"):
        service.publish_draft(
            AGENT,
            approved.draft_id,
            "agent-publish-denied",
            PublishCommand(
                **transition(approved, "Agent attempts publication").model_dump(),
                approval_id=approved.approval.decision_id,
            ),
        )


def test_human_approval_does_not_implicitly_authorize_publication() -> None:
    service = build_service()
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="separate-publisher"),
        key_prefix="separate-publisher",
    )
    assert approved.approval is not None

    with pytest.raises(AuthorizationError):
        service.publish_draft(
            APPROVER,
            approved.draft_id,
            "approver-publish-denied",
            PublishCommand(
                **transition(approved, "Approver lacks publisher role").model_dump(),
                approval_id=approved.approval.decision_id,
            ),
        )


def test_human_roles_are_separated_and_manifest_access_is_denied_by_default() -> None:
    service = build_service()
    draft = create_draft(service, canonical_manifest(), draft_id="role-separation")

    with pytest.raises(AuthorizationError):
        service.get_draft(OUTSIDER, draft.draft_id)
    with pytest.raises(AuthorizationError):
        service.validate_draft(
            APPROVER,
            draft.draft_id,
            "approver-cannot-author",
            transition(draft, "Approver attempts author action"),
        )


def test_typed_all_workloads_scope_cannot_alias_a_concrete_workload_grant() -> None:
    workload_id = canonical_manifest().manifest_id
    wildcard_only = RoleBasedAuthorization(
        [
            RoleGrant(
                actor_id=OUTSIDER.actor_id,
                role=Role.READER,
                scope=AllWorkloadsGrantScope(),
            )
        ]
    )
    explicit = RoleBasedAuthorization(
        [
            RoleGrant(
                actor_id=OUTSIDER.actor_id,
                role=Role.READER,
                scope=WorkloadGrantScope(workload_id=workload_id),
            )
        ]
    )

    with pytest.raises(ValidationError, match="reserved"):
        WorkloadGrantScope(workload_id="*")
    with pytest.raises(AuthorizationError):
        wildcard_only.require_explicit(OUTSIDER, Permission.READ, workload_id)
    with pytest.raises(AuthorizationError, match="not a workload identifier"):
        wildcard_only.require_explicit(OUTSIDER, Permission.READ, "*")
    explicit.require_explicit(OUTSIDER, Permission.READ, workload_id)
