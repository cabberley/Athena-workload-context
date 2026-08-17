from __future__ import annotations

import pytest

from athena_context.api.domain import (
    CreateDraftCommand,
    DraftState,
    PublishCommand,
    ReplaceDraftCommand,
    SupersedeCommand,
)
from athena_context.api.errors import (
    DigestMismatchError,
    DuplicateVersionError,
    IdempotencyConflictError,
    InvalidTransitionError,
    StaleApprovalError,
    StaleRevisionError,
    VersionMismatchError,
)
from context_api_support import (
    AGENT,
    APPROVER,
    PUBLISHER,
    approve_draft,
    build_service,
    canonical_manifest,
    create_draft,
    publish_draft,
    transition,
)

BAD_DIGEST = "sha256:" + ("0" * 64)


def test_full_lifecycle_compare_and_supersede_is_deterministic() -> None:
    service = build_service()
    first = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="draft-v1"),
        key_prefix="v1",
    )
    published_v1 = publish_draft(service, first, key_prefix="v1")

    second_manifest = canonical_manifest(version="1.1.0", display_suffix=" revision")
    second = approve_draft(
        service,
        create_draft(
            service,
            second_manifest,
            draft_id="draft-v2",
            previous_version="1.0.0",
        ),
        key_prefix="v2",
    )
    published_v2 = publish_draft(service, second, key_prefix="v2")

    comparison = service.compare_versions(
        PUBLISHER,
        published_v1.manifest_id,
        "1.0.0",
        "1.1.0",
    )
    assert comparison.equivalent is False
    assert comparison.changed_paths == sorted(comparison.changed_paths)
    assert "/manifestVersion" in comparison.changed_paths
    assert "/workload/displayName" in comparison.changed_paths

    supersession = service.supersede_version(
        PUBLISHER,
        published_v1.manifest_id,
        "1.0.0",
        "v1-supersede",
        SupersedeCommand(
            expected_revision=published_v1.source_draft_revision,
            expected_manifest_version="1.0.0",
            expected_digest=published_v1.manifest_digest,
            replacement_version="1.1.0",
            replacement_digest=published_v2.manifest_digest,
            reason="Supersede with the approved replacement",
        ),
    )

    original_name = published_v1.manifest.workload.display_name
    published_v1.manifest.workload.display_name = "Caller-side mutation"
    assert supersession.replacement_version == "1.1.0"
    old_view = service.get_published(PUBLISHER, "1.0.0", manifest_id=published_v1.manifest_id)
    assert old_view.published.manifest.workload.display_name == original_name
    assert old_view.supersession == supersession
    assert service.get_draft(PUBLISHER, "draft-v1").state is DraftState.SUPERSEDED
    assert service.audit_history(PUBLISHER, published_v1.manifest_id)[-1].replacement_version == (
        "1.1.0"
    )


def test_replace_uses_revision_version_and_both_digests() -> None:
    service = build_service()
    initial = canonical_manifest()
    draft = create_draft(service, initial, draft_id="replace-me")
    replacement = canonical_manifest(version="1.0.1", display_suffix=" replacement")
    command = ReplaceDraftCommand(
        expected_revision=draft.revision,
        expected_manifest_version=draft.manifest.manifest_version,
        expected_digest=draft.manifest_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason="Replace the draft manifest",
    )

    updated = service.replace_draft(AGENT, draft.draft_id, "replace-key", command)

    assert updated.revision == 2
    assert updated.manifest.manifest_version == "1.0.1"
    with pytest.raises(StaleRevisionError):
        service.replace_draft(AGENT, draft.draft_id, "stale-key", command)
    with pytest.raises(DigestMismatchError):
        service.replace_draft(
            AGENT,
            "replace-me",
            "bad-digest-key",
            command.model_copy(
                update={
                    "expected_revision": updated.revision,
                    "expected_manifest_version": updated.manifest.manifest_version,
                    "expected_digest": updated.manifest_digest,
                    "replacement_digest": BAD_DIGEST,
                }
            ),
        )


def test_mutations_are_idempotent_and_key_reuse_fails_closed() -> None:
    service = build_service()
    manifest = canonical_manifest()
    command = CreateDraftCommand(
        draft_id="idempotent-draft",
        manifest=manifest,
        manifest_digest=manifest.compatibility.artifact_digest,
        reason="Create an idempotent proposal",
    )

    first = service.create_draft(AGENT, "stable-key", command)
    replay = service.create_draft(AGENT, "stable-key", command)

    assert replay == first
    assert len(service.list_drafts(AGENT, manifest_id=manifest.manifest_id)) == 1
    with pytest.raises(IdempotencyConflictError):
        service.create_draft(
            AGENT,
            "stable-key",
            command.model_copy(update={"reason": "A conflicting idempotency payload"}),
        )


def test_idempotency_key_is_bound_to_the_draft_route_target() -> None:
    service = build_service()
    manifest = canonical_manifest()
    first = create_draft(service, manifest, draft_id="target-one")
    second = create_draft(service, manifest, draft_id="target-two")
    shared_command = transition(first, "Validate one route target")

    validated = service.validate_draft(
        AGENT,
        first.draft_id,
        "shared-target-key",
        shared_command,
    )

    assert validated.state is DraftState.VALIDATED
    with pytest.raises(IdempotencyConflictError):
        service.validate_draft(
            AGENT,
            second.draft_id,
            "shared-target-key",
            shared_command,
        )
    assert service.get_draft(AGENT, second.draft_id).state is DraftState.DRAFT


def test_invalid_transition_and_stale_approval_fail_closed() -> None:
    service = build_service()
    draft = create_draft(service, canonical_manifest(), draft_id="approval-guard")

    with pytest.raises(InvalidTransitionError):
        service.approve_draft(
            APPROVER,
            draft.draft_id,
            "approve-too-soon",
            transition(draft, "Attempt approval before review"),
        )

    approved = approve_draft(service, draft, key_prefix="approval")
    with pytest.raises(StaleApprovalError):
        service.publish_draft(
            PUBLISHER,
            approved.draft_id,
            "stale-approval",
            PublishCommand(
                **transition(approved, "Attempt stale approval publication").model_dump(),
                approval_id="different-approval",
            ),
        )


def test_duplicate_version_and_non_linear_version_fail_closed() -> None:
    service = build_service()
    manifest = canonical_manifest()
    first = approve_draft(
        service,
        create_draft(service, manifest, draft_id="winner"),
        key_prefix="winner",
    )
    loser = approve_draft(
        service,
        create_draft(service, manifest, draft_id="loser"),
        key_prefix="loser",
    )
    publish_draft(service, first, key_prefix="winner")

    with pytest.raises(DuplicateVersionError):
        publish_draft(service, loser, key_prefix="loser")
    with pytest.raises(VersionMismatchError):
        create_draft(
            service,
            canonical_manifest(version="0.9.0"),
            draft_id="older",
            previous_version="1.0.0",
        )
