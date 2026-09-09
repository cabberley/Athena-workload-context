from __future__ import annotations

import json

import pytest

from athena_context.api.domain import (
    ApproveCommand,
    CreateDraftCommand,
    DraftState,
    PublishCommand,
    PublishedManifest,
    ReplaceDraftCommand,
    ReviewCommand,
    ReviewDecisionKind,
    SupersedeCommand,
    Supersession,
)
from athena_context.api.errors import (
    DigestMismatchError,
    DuplicateVersionError,
    IdempotencyConflictError,
    InvalidTransitionError,
    PersistenceConflictError,
    StaleApprovalError,
    StaleRevisionError,
    VersionMismatchError,
)
from athena_context.api.memory import InMemoryContextStore
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
)
from context_api_support import (
    AGENT,
    APPROVER,
    PUBLISHER,
    REVIEWER,
    approve_draft,
    build_service,
    canonical_manifest,
    create_draft,
    issue_operational_context_receipt,
    publish_draft,
    transition,
)

BAD_DIGEST = "sha256:" + ("0" * 64)


def test_pre_receipt_published_records_remain_readable() -> None:
    service = build_service()
    approved = approve_draft(
        service,
        create_draft(
            service,
            canonical_manifest(),
            draft_id="legacy-published-record",
        ),
        key_prefix="legacy-published-record",
    )
    published = publish_draft(
        service,
        approved,
        key_prefix="legacy-published-record",
    )
    payload = json.loads(
        published.model_dump_json(
            by_alias=True,
            exclude_none=True,
        )
    )
    payload.pop("operational_context_receipt_id")
    approval = payload["approval"]
    assert isinstance(approval, dict)
    approval.pop("operational_context_receipt_id")

    legacy = PublishedManifest.model_validate_json(json.dumps(payload))

    assert legacy.operational_context_receipt_id is None
    assert legacy.approval.operational_context_receipt_id is None


def _manifest_with_selector_prefix(
    manifest: CanonicalWorkloadManifest,
    *,
    version: str,
    prefix: str,
) -> CanonicalWorkloadManifest:
    payload = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload["manifestVersion"] = version
    role = next(item for item in payload["roles"] if item["roleId"] == "web")
    role["selectors"][0]["prefix"] = prefix
    return CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )


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
    with pytest.raises(VersionMismatchError, match="from_version before"):
        service.compare_versions(
            PUBLISHER,
            published_v1.manifest_id,
            "1.1.0",
            "1.0.0",
        )

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


def test_rollback_draft_uses_older_published_selector_provenance() -> None:
    store = InMemoryContextStore()
    service = build_service(store=store)
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="rollback-v1"),
        key_prefix="rollback-v1",
    )
    published_v1 = publish_draft(service, approved, key_prefix="rollback-v1")
    manifest_v2 = _manifest_with_selector_prefix(
        published_v1.manifest,
        version="1.1.0",
        prefix="athena-web-v2-",
    )
    published_v2 = published_v1.model_copy(
        update={
            "manifest_version": "1.1.0",
            "manifest_digest": manifest_v2.compatibility.artifact_digest,
            "manifest": manifest_v2,
            "source_draft_id": "synthetic-v2-source",
            "source_draft_revision": 1,
            "previous_version": "1.0.0",
        }
    )
    with store.transaction() as transaction:
        transaction.put_published(published_v2)
        transaction.put_supersession(
            Supersession(
                manifest_id=published_v1.manifest_id,
                superseded_version="1.0.0",
                replacement_version="1.1.0",
                superseded_by=PUBLISHER,
                superseded_at=published_v1.published_at,
                reason="Synthetic selector-changing successor",
            )
        )
    rollback_manifest = _manifest_with_selector_prefix(
        published_v1.manifest,
        version="1.2.0",
        prefix="athena-web-",
    )

    rollback = service.create_draft(
        AGENT,
        "rollback-create",
        CreateDraftCommand(
            draft_id="rollback-v3",
            manifest=rollback_manifest,
            manifest_digest=rollback_manifest.compatibility.artifact_digest,
            previous_version="1.1.0",
            rollback_source_version="1.0.0",
            reason="Create a new version from the older reviewed selectors",
        ),
    )

    assert rollback.previous_version == "1.1.0"
    assert rollback.rollback_source_version == "1.0.0"
    web_role = next(role for role in rollback.manifest.roles if role.role_id == "web")
    assert web_role.selectors[0].prefix == "athena-web-"
    approved_rollback = approve_draft(
        service,
        rollback,
        key_prefix="rollback-v3",
    )
    published_rollback = publish_draft(
        service,
        approved_rollback,
        key_prefix="rollback-v3",
    )
    assert published_rollback.manifest_version == "1.2.0"


def test_replace_uses_revision_version_and_both_digests() -> None:
    service = build_service()
    initial = canonical_manifest()
    draft = create_draft(service, initial, draft_id="replace-me")
    replacement = canonical_manifest(version="1.0.0", display_suffix=" replacement")
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
    assert updated.manifest.manifest_version == "1.0.0"
    version_change = canonical_manifest(
        version="1.0.1",
        display_suffix=" forbidden version change",
    )
    with pytest.raises(VersionMismatchError, match="manifestVersion"):
        service.replace_draft(
            AGENT,
            updated.draft_id,
            "replace-version-change",
            ReplaceDraftCommand(
                expected_revision=updated.revision,
                expected_manifest_version=updated.manifest.manifest_version,
                expected_digest=updated.manifest_digest,
                replacement_manifest=version_change,
                replacement_digest=version_change.compatibility.artifact_digest,
                reason="Attempt to change the immutable candidate version",
            ),
        )
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


def test_legacy_draft_selector_baseline_is_backfilled_before_validation() -> None:
    store = InMemoryContextStore()
    service = build_service(store=store)
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="legacy-baseline-draft",
    )
    store._draft_selector_baselines.clear()

    validated = service.validate_draft(
        AGENT,
        draft.draft_id,
        "legacy-baseline-validate",
        transition(draft, "Validate a migrated pre-WC-023 draft"),
    )

    assert validated.state is DraftState.VALIDATED
    with store.transaction() as transaction:
        baseline = transaction.get_draft_selector_baseline(draft.draft_id)
    assert baseline is not None
    assert baseline.source_manifest_digest == draft.manifest_digest


def test_legacy_successor_baseline_rejects_unapproved_selector_changes() -> None:
    store = InMemoryContextStore()
    service = build_service(store=store)
    approved = approve_draft(
        service,
        create_draft(service, canonical_manifest(), draft_id="legacy-source"),
        key_prefix="legacy-source",
    )
    publish_draft(service, approved, key_prefix="legacy-source")
    successor = create_draft(
        service,
        canonical_manifest(version="1.1.0"),
        draft_id="legacy-successor",
        previous_version="1.0.0",
    )
    changed = _manifest_with_selector_prefix(
        successor.manifest,
        version="1.1.0",
        prefix="unauthorized-web-",
    )
    store._draft_selector_baselines.clear()
    store._drafts[successor.draft_id] = successor.model_copy(
        update={
            "manifest": changed,
            "manifest_digest": changed.compatibility.artifact_digest,
        }
    )
    tampered = store._drafts[successor.draft_id]

    with pytest.raises(PersistenceConflictError, match="published source"):
        service.validate_draft(
            AGENT,
            tampered.draft_id,
            "legacy-tampered-validate",
            transition(tampered, "Reject unauthorized legacy selector changes"),
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
    receipt = issue_operational_context_receipt(
        service,
        approved,
        key_prefix="stale-approval",
    )
    with pytest.raises(StaleApprovalError):
        service.publish_draft(
            PUBLISHER,
            approved.draft_id,
            "stale-approval",
            PublishCommand(
                **transition(approved, "Attempt stale approval publication").model_dump(),
                approval_id="different-approval",
                operational_context_receipt_id=receipt.receipt_id,
            ),
        )


def test_review_decision_is_required_and_corrections_return_to_draft() -> None:
    service = build_service()
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="authoritative-review",
    )
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "authoritative-review-validate",
        transition(draft, "Validate before authoritative review"),
    )
    submitted = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "authoritative-review-submit",
        transition(draft, "Submit for authoritative review"),
    )

    with pytest.raises(
        InvalidTransitionError,
        match="authoritative approved review",
    ):
        service.approve_draft(
            APPROVER,
            submitted.draft_id,
            "authoritative-review-bypass",
            ApproveCommand(
                **transition(
                    submitted,
                    "Attempt approval without review",
                ).model_dump(),
                operational_context_receipt_id="operational-missing",
            ),
        )

    corrected = service.review_draft(
        REVIEWER,
        submitted.draft_id,
        "authoritative-review-corrections",
        ReviewCommand(
            **transition(
                submitted,
                "Record required corrections",
            ).model_dump(),
            decision=ReviewDecisionKind.CHANGES_REQUESTED,
            comments="The recovery control needs an exact runbook reference.",
            rejected_fields=["/profiles/production/controls/0/runbookRef"],
            required_corrections=[
                "Add the approved production recovery runbook reference."
            ],
        ),
    )

    assert corrected.state is DraftState.DRAFT
    assert corrected.validation is None
    assert corrected.review is None
    assert corrected.publication_candidate is None
    assert corrected.approval is None
    assert corrected.review_decisions[-1].rejected_fields == [
        "/profiles/production/controls/0/runbookRef"
    ]


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
