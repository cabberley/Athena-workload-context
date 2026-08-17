from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from athena_context import golden
from athena_context.agent import (
    AuthoritativePolicyView,
    ContextMcpServer,
    ToolCallContext,
)
from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import (
    Actor,
    ActorKind,
    AuthenticationMethod,
    CreateDraftCommand,
    PublishCommand,
    Role,
    RoleGrant,
    TransitionCommand,
    VerifiedAuthentication,
)
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.service import ContextService
from athena_context.contracts import resolve_manifest_profile
from athena_context.fixtures import make_canonical_fixture_from_resources
from athena_context.policy import evaluate_manifest_profile

WORKLOAD_ID = golden.WC002_MANIFEST_ID
AGENT = Actor(actor_id="synthetic-context-mcp", kind=ActorKind.AGENT)
APPROVER = Actor(actor_id="synthetic-human-approver", kind=ActorKind.HUMAN)
PUBLISHER = Actor(actor_id="synthetic-human-publisher", kind=ActorKind.HUMAN)
PUBLICATION_SERVICE = Actor(
    actor_id="synthetic-context-api",
    kind=ActorKind.SERVICE,
)


class StepClock:
    def __init__(self) -> None:
        self._value = datetime(2025, 6, 1, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        value = self._value
        self._value += timedelta(seconds=1)
        return value


class FindingsPort:
    def __init__(
        self,
        views: dict[tuple[str, str, str], AuthoritativePolicyView],
    ) -> None:
        self.views = views
        self.calls: list[tuple[str, str, str, str]] = []

    def get_policy_view(
        self,
        actor: Actor,
        *,
        manifest_id: str,
        manifest_version: str,
        profile_id: str,
    ) -> AuthoritativePolicyView:
        self.calls.append(
            (actor.actor_id, manifest_id, manifest_version, profile_id.casefold())
        )
        if actor != AGENT or manifest_id != WORKLOAD_ID:
            raise AssertionError("findings port received an unauthorized scope")
        return self.views[(manifest_id, manifest_version, profile_id.casefold())]


@dataclass(frozen=True)
class Harness:
    server: ContextMcpServer
    service: ContextService
    findings: FindingsPort
    context: ToolCallContext
    policy_views: dict[str, AuthoritativePolicyView]


def _transition(
    draft_revision: int,
    manifest_version: str,
    manifest_digest: str,
    reason: str,
) -> TransitionCommand:
    return TransitionCommand(
        expected_revision=draft_revision,
        expected_manifest_version=manifest_version,
        expected_digest=manifest_digest,
        reason=reason,
    )


@pytest.fixture
def harness() -> Harness:
    service = ContextService(
        store=InMemoryContextStore(),
        authorization=RoleBasedAuthorization(
            [
                RoleGrant(
                    actor_id=AGENT.actor_id,
                    role=Role.PROPOSER,
                    manifest_id=WORKLOAD_ID,
                ),
                RoleGrant(
                    actor_id=AGENT.actor_id,
                    role=Role.AUDITOR,
                    manifest_id=WORKLOAD_ID,
                ),
                RoleGrant(
                    actor_id=APPROVER.actor_id,
                    role=Role.APPROVER,
                    manifest_id=WORKLOAD_ID,
                ),
                RoleGrant(
                    actor_id=PUBLISHER.actor_id,
                    role=Role.PUBLISHER,
                    manifest_id=WORKLOAD_ID,
                ),
            ]
        ),
        clock=StepClock(),
        publication_actor=PUBLICATION_SERVICE,
    )
    manifest = golden.load_golden_manifest()
    draft = service.create_draft(
        AGENT,
        "seed-create",
        CreateDraftCommand(
            draft_id="seed-published-manifest",
            manifest=manifest,
            manifest_digest=manifest.compatibility.artifact_digest,
            reason="Create a clearly synthetic publication seed",
        ),
    )
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "seed-validate",
        _transition(
            draft.revision,
            draft.manifest.manifest_version,
            draft.manifest_digest,
            "Validate the synthetic seed",
        ),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "seed-submit",
        _transition(
            draft.revision,
            draft.manifest.manifest_version,
            draft.manifest_digest,
            "Submit the synthetic seed for review",
        ),
    )
    draft = service.approve_draft(
        APPROVER,
        draft.draft_id,
        "seed-approve",
        _transition(
            draft.revision,
            draft.manifest.manifest_version,
            draft.manifest_digest,
            "Approve the exact synthetic candidate",
        ),
    )
    assert draft.approval is not None
    published = service.publish_draft(
        PUBLISHER,
        draft.draft_id,
        "seed-publish",
        PublishCommand(
            **_transition(
                draft.revision,
                draft.manifest.manifest_version,
                draft.manifest_digest,
                "Publish the human-approved synthetic candidate",
            ).model_dump(),
            approval_id=draft.approval.decision_id,
        ),
    )

    bundle = make_canonical_fixture_from_resources()
    policy_views: dict[str, AuthoritativePolicyView] = {}
    for profile_id in golden.GOLDEN_PROFILE_IDS:
        profile = resolve_manifest_profile(
            published.manifest,
            profile_id,
            as_of=golden.GOLDEN_PROOF_AS_OF,
        )
        evidence = golden._build_evidence_context(
            profile,
            bundle.canonical_snapshot,
        )
        findings = evaluate_manifest_profile(
            profile,
            evidence,
            as_of=golden.GOLDEN_PROOF_AS_OF,
            verify_evidence_context=golden._make_context_verifier(
                bundle,
                profile,
                as_of=golden.GOLDEN_PROOF_AS_OF,
            ),
        )
        policy_views[profile_id] = AuthoritativePolicyView(
            evaluated_at=golden.GOLDEN_PROOF_AS_OF,
            profile=profile,
            evidence=evidence,
            findings=tuple(
                findings[key] for key in sorted(findings, key=str.casefold)
            ),
        )
    findings_port = FindingsPort(
        {
            (
                WORKLOAD_ID,
                published.manifest_version,
                profile_id,
            ): view
            for profile_id, view in policy_views.items()
        }
    )
    context = ToolCallContext(
        authentication=VerifiedAuthentication(
            actor=AGENT,
            subject_id="synthetic-context-mcp-subject",
            issuer="https://issuer.invalid/synthetic",
            audience="api://athena-context-mcp-test",
            method=AuthenticationMethod.TEST,
        ),
        authorized_workload_ids=(WORKLOAD_ID,),
    )
    return Harness(
        server=ContextMcpServer(context_api=service, findings=findings_port),
        service=service,
        findings=findings_port,
        context=context,
        policy_views=policy_views,
    )
