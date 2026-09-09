from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.resources import files

from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import (
    Actor,
    ActorKind,
    ApproveCommand,
    CreateDraftCommand,
    DraftRecord,
    PublishCommand,
    PublishedManifest,
    ReviewCommand,
    ReviewDecisionKind,
    Role,
    RoleGrant,
    TransitionCommand,
)
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.operational_context import (
    IssueOperationalContextReceiptCommand,
    OperationalContextReceipt,
    OperationalEvidenceInventoryItem,
    compute_operational_binding_digest,
    compute_operational_content_digest,
    compute_operational_evidence_inventory_digest,
)
from athena_context.api.service import ContextService
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
)

AGENT = Actor(actor_id="proposal-agent", kind=ActorKind.AGENT)
AUTHOR = Actor(actor_id="human-author", kind=ActorKind.HUMAN)
APPROVER = Actor(actor_id="human-approver", kind=ActorKind.HUMAN)
REVIEWER = Actor(actor_id="human-reviewer", kind=ActorKind.HUMAN)
PUBLISHER = Actor(actor_id="human-publisher", kind=ActorKind.HUMAN)
AUDITOR = Actor(actor_id="human-auditor", kind=ActorKind.HUMAN)
OUTSIDER = Actor(actor_id="human-outsider", kind=ActorKind.HUMAN)
PUBLICATION_SERVICE = Actor(actor_id="athena-context-api", kind=ActorKind.SERVICE)
OPERATIONAL_CONTEXT_SERVICE = Actor(
    actor_id="athena-operational-context",
    kind=ActorKind.SERVICE,
)


class StepClock:
    def __init__(self) -> None:
        self._value = datetime(2025, 6, 1, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        value = self._value
        self._value += timedelta(seconds=1)
        return value


def build_service(
    *,
    store: InMemoryContextStore | None = None,
) -> ContextService:
    grants = [
        RoleGrant(actor_id=AGENT.actor_id, role=Role.PROPOSER),
        # Deliberately privileged grants prove that actor-kind checks remain authoritative.
        RoleGrant(actor_id=AGENT.actor_id, role=Role.REVIEWER),
        RoleGrant(actor_id=AGENT.actor_id, role=Role.APPROVER),
        RoleGrant(actor_id=AGENT.actor_id, role=Role.PUBLISHER),
        RoleGrant(actor_id=AUTHOR.actor_id, role=Role.PROPOSER),
        RoleGrant(actor_id=APPROVER.actor_id, role=Role.APPROVER),
        RoleGrant(actor_id=REVIEWER.actor_id, role=Role.REVIEWER),
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
        RoleGrant(actor_id=AUDITOR.actor_id, role=Role.AUDITOR),
        RoleGrant(
            actor_id=OPERATIONAL_CONTEXT_SERVICE.actor_id,
            role=Role.OPERATIONAL_CONTEXT_ISSUER,
        ),
    ]
    return ContextService(
        store=store or InMemoryContextStore(),
        authorization=RoleBasedAuthorization(grants),
        clock=StepClock(),
        publication_actor=PUBLICATION_SERVICE,
    )


def canonical_manifest(
    *,
    manifest_id: str = "wl-athena-wc002-canonical",
    version: str = "1.0.0",
    display_suffix: str = "",
) -> CanonicalWorkloadManifest:
    fixture = files("athena_context.data.fixtures").joinpath("canonical-manifest.json")
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    original_manifest_id = payload["manifestId"]
    if manifest_id != "*" and manifest_id != original_manifest_id:
        def replace_manifest_scope(value: object) -> object:
            if isinstance(value, dict):
                return {
                    key: replace_manifest_scope(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [replace_manifest_scope(item) for item in value]
            return manifest_id if value == original_manifest_id else value

        payload = replace_manifest_scope(payload)
        assert isinstance(payload, dict)
    payload["manifestId"] = manifest_id
    payload["manifestVersion"] = version
    if display_suffix:
        payload["workload"]["displayName"] += display_suffix
    return CanonicalWorkloadManifest.model_validate(canonicalize_manifest_payload(payload))


def transition(draft: DraftRecord, reason: str) -> TransitionCommand:
    return TransitionCommand(
        expected_revision=draft.revision,
        expected_manifest_version=draft.manifest.manifest_version,
        expected_digest=draft.manifest_digest,
        reason=reason,
    )


def operational_context_command(
    service: ContextService,
    draft: DraftRecord,
    *,
    profile_id: str | None = None,
) -> IssueOperationalContextReceiptCommand:
    selected_profile = profile_id or draft.manifest.workload.environments[0]
    authority = service.resolve_draft_profile_authority(
        OPERATIONAL_CONTEXT_SERVICE,
        draft.draft_id,
        selected_profile,
    )
    inventory = [
        OperationalEvidenceInventoryItem(
            evidenceRef=f"synthetic://operational/{draft.draft_id}/{draft.revision}",
            evidenceDigest="sha256:" + "a" * 64,
        )
    ]
    inventory_digest = compute_operational_evidence_inventory_digest(
        inventory
    )
    content_digest = compute_operational_content_digest(
        evidence_source="Synthetic operational context.",
        confidence=0.9,
        relationships=[],
        findings=[],
    )
    collected_at = datetime(2000, 1, 1, tzinfo=UTC)
    expires_at = datetime(2100, 1, 1, tzinfo=UTC)
    return IssueOperationalContextReceiptCommand(
        manifest_id=draft.manifest_id,
        manifest_version=draft.manifest.manifest_version,
        profile_id=authority.profile_id,
        draft_id=draft.draft_id,
        draft_revision=draft.revision,
        manifest_digest=draft.manifest_digest,
        profile_digest=authority.resolved_profile_digest,
        snapshot_id=f"snapshot-{draft.draft_id}-r{draft.revision}",
        collected_at=collected_at,
        expires_at=expires_at,
        evidence_inventory=inventory,
        evidence_inventory_digest=inventory_digest,
        content_digest=content_digest,
        binding_digest=compute_operational_binding_digest(
            workload_id=draft.manifest_id,
            manifest_version=draft.manifest.manifest_version,
            profile_id=authority.profile_id,
            draft_id=draft.draft_id,
            draft_revision=draft.revision,
            manifest_digest=draft.manifest_digest,
            profile_digest=authority.resolved_profile_digest,
            snapshot_id=f"snapshot-{draft.draft_id}-r{draft.revision}",
            collected_at=collected_at,
            expires_at=expires_at,
            evidence_inventory_digest=inventory_digest,
            content_digest=content_digest,
        ),
    )


def issue_operational_context_receipt(
    service: ContextService,
    draft: DraftRecord,
    *,
    key_prefix: str,
    profile_id: str | None = None,
) -> OperationalContextReceipt:
    command = operational_context_command(
        service,
        draft,
        profile_id=profile_id,
    )
    return service.issue_operational_context_receipt(
        OPERATIONAL_CONTEXT_SERVICE,
        f"{key_prefix}-operational",
        command,
    )


def create_draft(
    service: ContextService,
    manifest: CanonicalWorkloadManifest,
    *,
    draft_id: str,
    previous_version: str | None = None,
    actor: Actor = AGENT,
) -> DraftRecord:
    return service.create_draft(
        actor,
        f"{draft_id}-create",
        CreateDraftCommand(
            draft_id=draft_id,
            manifest=manifest,
            manifest_digest=manifest.compatibility.artifact_digest,
            previous_version=previous_version,
            reason="Propose a synthetic manifest draft",
        ),
    )


def approve_draft(
    service: ContextService,
    draft: DraftRecord,
    *,
    key_prefix: str,
) -> DraftRecord:
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        f"{key_prefix}-validate",
        transition(draft, "Validate canonical manifest"),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        f"{key_prefix}-submit",
        transition(draft, "Submit for human review"),
    )
    draft = service.review_draft(
        REVIEWER,
        draft.draft_id,
        f"{key_prefix}-review",
        ReviewCommand(
            **transition(
                draft,
                "Record an authoritative human review",
            ).model_dump(),
            decision=ReviewDecisionKind.APPROVED,
            comments="Reviewed the exact canonical publication candidate.",
        ),
    )
    receipt = issue_operational_context_receipt(
        service,
        draft,
        key_prefix=key_prefix,
    )
    return service.approve_draft(
        APPROVER,
        draft.draft_id,
        f"{key_prefix}-approve",
        ApproveCommand(
            **transition(
                draft,
                "Human approval after review",
            ).model_dump(),
            operational_context_receipt_id=receipt.receipt_id,
        ),
    )


def publish_draft(
    service: ContextService,
    draft: DraftRecord,
    *,
    key_prefix: str,
) -> PublishedManifest:
    assert draft.approval is not None
    receipt = issue_operational_context_receipt(
        service,
        draft,
        key_prefix=f"{key_prefix}-publish",
    )
    return service.publish_draft(
        PUBLISHER,
        draft.draft_id,
        f"{key_prefix}-publish",
        PublishCommand(
            **transition(draft, "Publish approved immutable version").model_dump(),
            approval_id=draft.approval.decision_id,
            operational_context_receipt_id=receipt.receipt_id,
        ),
    )
