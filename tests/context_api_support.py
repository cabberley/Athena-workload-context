from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.resources import files

from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import (
    Actor,
    ActorKind,
    CreateDraftCommand,
    DraftRecord,
    PublishCommand,
    PublishedManifest,
    Role,
    RoleGrant,
    TransitionCommand,
)
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.service import ContextService
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
)

AGENT = Actor(actor_id="proposal-agent", kind=ActorKind.AGENT)
AUTHOR = Actor(actor_id="human-author", kind=ActorKind.HUMAN)
APPROVER = Actor(actor_id="human-approver", kind=ActorKind.HUMAN)
PUBLISHER = Actor(actor_id="human-publisher", kind=ActorKind.HUMAN)
AUDITOR = Actor(actor_id="human-auditor", kind=ActorKind.HUMAN)
OUTSIDER = Actor(actor_id="human-outsider", kind=ActorKind.HUMAN)


class StepClock:
    def __init__(self) -> None:
        self._value = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        value = self._value
        self._value += timedelta(seconds=1)
        return value


def build_service() -> ContextService:
    grants = [
        RoleGrant(actor_id=AGENT.actor_id, role=Role.PROPOSER),
        # Deliberately privileged grants prove that actor-kind checks remain authoritative.
        RoleGrant(actor_id=AGENT.actor_id, role=Role.APPROVER),
        RoleGrant(actor_id=AGENT.actor_id, role=Role.PUBLISHER),
        RoleGrant(actor_id=AUTHOR.actor_id, role=Role.PROPOSER),
        RoleGrant(actor_id=APPROVER.actor_id, role=Role.APPROVER),
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
        RoleGrant(actor_id=AUDITOR.actor_id, role=Role.AUDITOR),
    ]
    return ContextService(
        store=InMemoryContextStore(),
        authorization=RoleBasedAuthorization(grants),
        clock=StepClock(),
    )


def canonical_manifest(
    *,
    manifest_id: str = "wl-athena-wc002-canonical",
    version: str = "1.0.0",
    display_suffix: str = "",
) -> CanonicalWorkloadManifest:
    fixture = files("athena_context.data.fixtures").joinpath("canonical-manifest.json")
    payload = json.loads(fixture.read_text(encoding="utf-8"))
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
    return service.approve_draft(
        APPROVER,
        draft.draft_id,
        f"{key_prefix}-approve",
        transition(draft, "Human approval after review"),
    )


def publish_draft(
    service: ContextService,
    draft: DraftRecord,
    *,
    key_prefix: str,
) -> PublishedManifest:
    assert draft.approval is not None
    return service.publish_draft(
        PUBLISHER,
        draft.draft_id,
        f"{key_prefix}-publish",
        PublishCommand(
            **transition(draft, "Publish approved immutable version").model_dump(),
            approval_id=draft.approval.decision_id,
        ),
    )
