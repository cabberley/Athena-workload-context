from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

import athena_context.fixtures as fixture_factory
from athena_context.api.authorization import (
    RoleBasedAuthorization,
    StaticTestAuthenticator,
)
from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.cohort_domain import (
    CohortBatchCacheKey,
    CohortEvidenceBinding,
    CohortProposalBatchResponse,
    CohortProposalQuery,
    StoredEvidenceSnapshot,
)
from athena_context.api.cohort_memory import (
    CallableTrustedEvidenceSnapshotVerifier,
    InMemoryCohortPersistence,
    InMemoryEvidenceSnapshotRepository,
)
from athena_context.api.cohort_service import CohortProposalService
from athena_context.api.domain import (
    Actor,
    ActorKind,
    AllWorkloadsGrantScope,
    AuthenticationMethod,
    CreateDraftCommand,
    ReplaceDraftCommand,
    Role,
    RoleGrant,
    VerifiedAuthentication,
    WorkloadGrantScope,
)
from athena_context.api.http import create_app
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.service import ContextService
from athena_context.binding import evaluate_selector
from athena_context.binding.domain import (
    CohortProposal,
    SelectorPreview,
)
from athena_context.contracts import (
    CanonicalWorkloadManifest,
    EvidenceSnapshot,
    ResourceEvidenceRecord,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    resolve_manifest_profile,
)
from athena_context.contracts.manifest import ResourceIdListSelector
from test_cohort_binding import _build_attested_snapshot

AS_OF = datetime(2025, 6, 1, 12, tzinfo=UTC)
HUMAN = Actor(actor_id="human-cohort-reviewer", kind=ActorKind.HUMAN)
SECOND_REVIEWER = Actor(
    actor_id="human-cohort-reviewer-two",
    kind=ActorKind.HUMAN,
)
OUTSIDER = Actor(actor_id="human-cohort-outsider", kind=ActorKind.HUMAN)
WILDCARD = Actor(actor_id="human-wildcard-reader", kind=ActorKind.HUMAN)
AGENT = Actor(actor_id="cohort-agent", kind=ActorKind.AGENT)
PUBLICATION_SERVICE = Actor(actor_id="context-api-service", kind=ActorKind.SERVICE)
TOKENS = {
    HUMAN.actor_id: "cohort-human-token",
    SECOND_REVIEWER.actor_id: "cohort-human-two-token",
    OUTSIDER.actor_id: "cohort-outsider-token",
    WILDCARD.actor_id: "cohort-wildcard-token",
    AGENT.actor_id: "cohort-agent-token",
}


class MutableClock:
    def __init__(self, value: datetime = AS_OF) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


@dataclass(slots=True)
class Harness:
    client: TestClient
    actor: Actor
    clock: MutableClock
    store: InMemoryContextStore
    lifecycle: ContextService
    cohorts: CohortProposalService
    decisions: CohortDecisionService
    snapshots: InMemoryEvidenceSnapshotRepository
    persistence: InMemoryCohortPersistence
    authorization: RoleBasedAuthorization
    manifest: CanonicalWorkloadManifest
    snapshot: EvidenceSnapshot
    verifier: Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]
    draft_id: str
    draft_revision: int
    draft_digest: str
    verifier_calls: list[str]

    def register_profile(self, profile_id: str) -> CohortEvidenceBinding:
        profile = resolve_manifest_profile(self.manifest, profile_id, as_of=self.clock.now())
        binding = CohortEvidenceBinding(
            manifest_id=self.manifest.manifest_id,
            manifest_version=self.manifest.manifest_version,
            profile_id=profile.profile_id,
            profile_type=profile.profile_type,
            resolved_profile_digest=profile.resolved_profile_digest,
            draft_id=self.draft_id,
            draft_revision=self.draft_revision,
            draft_digest=self.draft_digest,
        )
        self.snapshots.put_snapshot(binding, self.snapshot)
        return binding


def _verified(actor: Actor) -> VerifiedAuthentication:
    return VerifiedAuthentication(
        actor=actor,
        subject_id=f"synthetic-subject-{actor.actor_id}",
        issuer="https://issuer.invalid/wc-031",
        audience="api://athena-context-wc-031",
        method=AuthenticationMethod.TEST,
    )


def _bundle_verifier(
    bundle: fixture_factory.FixtureBundle,
) -> Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]:
    def verify(snapshot: EvidenceSnapshot, as_of: datetime) -> EvidenceSnapshot:
        return snapshot.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=bundle.snapshot_artifact_digest,
            publication_resolver=bundle.publication_resolver,
            key_resolver=bundle.key_resolver,
            trusted_key_anchor=bundle.trusted_key_anchor,
            envelope_resolver=bundle.envelope_resolver,
        )

    return verify


def _build_harness(
    *,
    manifest: CanonicalWorkloadManifest | None = None,
    snapshot: EvidenceSnapshot | None = None,
    verifier: Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot] | None = None,
    profiles: tuple[str, ...] = ("production",),
) -> Harness:
    bundle = fixture_factory.make_canonical_fixture_from_resources()
    selected_manifest = manifest or bundle.manifest
    selected_snapshot = snapshot or bundle.snapshot
    selected_verifier = verifier or _bundle_verifier(bundle)
    clock = MutableClock()
    grants = [
        RoleGrant(
            actor_id=HUMAN.actor_id,
            role=Role.PROPOSER,
            scope=WorkloadGrantScope(workload_id=selected_manifest.manifest_id),
        ),
        RoleGrant(
            actor_id=SECOND_REVIEWER.actor_id,
            role=Role.PROPOSER,
            scope=WorkloadGrantScope(workload_id=selected_manifest.manifest_id),
        ),
        RoleGrant(
            actor_id=AGENT.actor_id,
            role=Role.READER,
            scope=WorkloadGrantScope(workload_id=selected_manifest.manifest_id),
        ),
        RoleGrant(
            actor_id=WILDCARD.actor_id,
            role=Role.READER,
            scope=AllWorkloadsGrantScope(),
        ),
    ]
    authorization = RoleBasedAuthorization(grants)
    store = InMemoryContextStore()
    lifecycle = ContextService(
        store=store,
        authorization=authorization,
        clock=clock,
        publication_actor=PUBLICATION_SERVICE,
    )
    draft = lifecycle.create_draft(
        HUMAN,
        "create-wc-031-draft",
        CreateDraftCommand(
            draft_id="draft-wc-031-synthetic",
            manifest=selected_manifest,
            manifest_digest=selected_manifest.compatibility.artifact_digest,
            reason="Create a clearly synthetic cohort API draft",
        ),
    )
    snapshots = InMemoryEvidenceSnapshotRepository()
    persistence = InMemoryCohortPersistence()
    verifier_calls: list[str] = []

    def recording_verifier(
        candidate: EvidenceSnapshot,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        verifier_calls.append(candidate.compatibility.artifact_digest)
        return selected_verifier(candidate, as_of)

    cohorts = CohortProposalService(
        context_store=store,
        authorization=authorization,
        clock=clock,
        snapshot_repository=snapshots,
        snapshot_verifier=CallableTrustedEvidenceSnapshotVerifier(recording_verifier),
        proposal_cache=persistence,
        preview_receipts=persistence,
    )
    decisions = CohortDecisionService(
        store=store,
        authorization=authorization,
        clock=clock,
        context_service=lifecycle,
        proposal_service=cohorts,
        candidate_repository=persistence,
    )
    identities = {
        TOKENS[actor.actor_id]: _verified(actor)
        for actor in (HUMAN, SECOND_REVIEWER, OUTSIDER, WILDCARD, AGENT)
    }
    client = TestClient(
        create_app(
            service=lifecycle,
            authentication=StaticTestAuthenticator(identities),
            cohort_service=cohorts,
            cohort_decision_service=decisions,
        )
    )
    harness = Harness(
        client=client,
        actor=HUMAN,
        clock=clock,
        store=store,
        lifecycle=lifecycle,
        cohorts=cohorts,
        decisions=decisions,
        snapshots=snapshots,
        persistence=persistence,
        authorization=authorization,
        manifest=selected_manifest,
        snapshot=selected_snapshot,
        verifier=selected_verifier,
        draft_id=draft.draft_id,
        draft_revision=draft.revision,
        draft_digest=draft.manifest_digest,
        verifier_calls=verifier_calls,
    )
    for profile_id in profiles:
        harness.register_profile(profile_id)
    return harness


def _headers(
    actor: Actor = HUMAN,
    *,
    idempotency_key: str | None = None,
) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {TOKENS[actor.actor_id]}"}
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _params(harness: Harness, profile_id: str = "production") -> dict[str, object]:
    return {
        "manifest_id": harness.manifest.manifest_id,
        "manifest_version": harness.manifest.manifest_version,
        "profile_id": profile_id,
        "draft_id": harness.draft_id,
        "expected_revision": harness.draft_revision,
        "expected_digest": harness.draft_digest,
    }


def _load(harness: Harness, profile_id: str = "production") -> dict[str, Any]:
    response = harness.client.get(
        "/v1/cohort-proposals",
        params=_params(harness, profile_id),
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _preview_body(
    harness: Harness,
    batch: dict[str, Any],
    *,
    action: str = "split",
    proposal_ids: list[str] | None = None,
    resolution: str = "Human reviewed this exact bounded selector transformation.",
) -> dict[str, Any]:
    selected_ids = proposal_ids or [
        next(
            proposal["proposalId"]
            for proposal in batch["proposals"]
            if len(proposal["members"]) >= 2 and proposal["selectorPreview"] is not None
        )
    ]
    role_refs = list(
        dict.fromkeys(
            proposal["role"]["roleId"]
            for proposal in batch["proposals"]
            if proposal["proposalId"] in selected_ids
        )
    )
    return {
        "action": action,
        **_params(harness),
        "proposal_ids": selected_ids,
        "source_role_refs": role_refs,
        "proposal_set_digest": batch["proposalSetDigest"],
        "snapshot_artifact_digest": batch["snapshot"]["artifactDigest"],
        "resolution": resolution,
    }


def test_routes_return_exact_wc012_batch_wire_model_and_source_bindings() -> None:
    harness = _build_harness()
    batch = _load(harness)
    schema = harness.client.get("/openapi.json").json()

    assert "/v1/cohort-proposals" in schema["paths"]
    assert "/v1/cohort-proposals/preview" in schema["paths"]
    assert batch["sourceDraft"] == {
        "draftId": harness.draft_id,
        "revision": 1,
        "manifestDigest": harness.draft_digest,
    }
    assert batch["scope"] == {
        "manifestId": harness.manifest.manifest_id,
        "manifestVersion": harness.manifest.manifest_version,
        "profileId": "production",
        "profileType": "production",
        "resolvedProfileDigest": batch["scope"]["resolvedProfileDigest"],
    }
    assert batch["snapshot"]["artifactDigest"] == harness.snapshot.compatibility.artifact_digest
    assert batch["requiresHumanReview"] is True
    assert batch["publicationAllowed"] is False
    assert batch["manifestMutated"] is False
    assert all(len(proposal["members"]) <= 1000 for proposal in batch["proposals"])
    assert all(
        len(evidence["evidenceRefs"]) <= 1000
        for proposal in batch["proposals"]
        for evidence in proposal["supportingEvidence"]
    )
    assert len(harness.verifier_calls) == 1


def test_verified_human_requires_explicit_workload_grant_without_wildcard() -> None:
    harness = _build_harness()
    path = "/v1/cohort-proposals"
    batch = _load(harness)
    preview_body = _preview_body(harness, batch)

    unauthenticated = harness.client.get(path, params=_params(harness))
    outsider = harness.client.get(
        path,
        params=_params(harness),
        headers=_headers(OUTSIDER),
    )
    wildcard = harness.client.get(
        path,
        params=_params(harness),
        headers=_headers(WILDCARD),
    )
    agent = harness.client.get(
        path,
        params=_params(harness),
        headers=_headers(AGENT),
    )
    wildcard_preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(
            WILDCARD,
            idempotency_key="wc-031-wildcard-preview-denied",
        ),
    )
    explicit_preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-031-explicit-preview-allowed"),
    )

    assert unauthenticated.status_code == 401
    assert outsider.status_code == 403
    assert wildcard.status_code == 403
    assert agent.status_code == 403
    assert wildcard_preview.status_code == 403
    assert explicit_preview.status_code == 200
    assert all(
        response.json()["error"]["code"] == "authorization_denied"
        for response in (outsider, wildcard, agent, wildcard_preview)
    )


def test_reserved_wildcard_is_rejected_by_both_cohort_endpoint_models() -> None:
    harness = _build_harness()
    batch = _load(harness)
    get_response = harness.client.get(
        "/v1/cohort-proposals",
        params={**_params(harness), "manifest_id": "*"},
        headers=_headers(),
    )
    preview_response = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**_preview_body(harness, batch), "manifest_id": "*"},
        headers=_headers(idempotency_key="wc-031-reserved-wildcard"),
    )

    assert get_response.status_code == 422
    assert preview_response.status_code == 422
    assert get_response.json()["detail"][0]["loc"][-1] == "manifest_id"
    assert preview_response.json()["detail"][0]["loc"][-1] == "manifest_id"


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"expected_revision": 2}, "stale_revision"),
        ({"expected_digest": "sha256:" + ("0" * 64)}, "digest_mismatch"),
        ({"manifest_version": "2.0.0"}, "version_mismatch"),
        ({"profile_id": "missing-profile"}, "cohort_profile_mismatch"),
    ],
)
def test_get_rejects_stale_concurrency_digest_version_and_profile(
    override: dict[str, object],
    code: str,
) -> None:
    harness = _build_harness()
    params = {**_params(harness), **override}

    response = harness.client.get(
        "/v1/cohort-proposals",
        params=params,
        headers=_headers(),
    )

    assert response.status_code in {404, 409}
    assert response.json()["error"]["code"] == code
    assert not harness.verifier_calls


def test_snapshot_is_cryptographically_verified_on_cache_hits_and_staleness_fails() -> None:
    harness = _build_harness()
    first = _load(harness)
    second = _load(harness)
    assert first == second
    assert len(harness.verifier_calls) == 2

    harness.clock.value = harness.snapshot.expires_at
    stale = harness.client.get(
        "/v1/cohort-proposals",
        params=_params(harness),
        headers=_headers(),
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_evidence_snapshot"


def test_snapshot_signature_failure_and_evidence_bounds_fail_closed() -> None:
    bundle = fixture_factory.make_canonical_fixture_from_resources()

    def reject_verification(
        snapshot: EvidenceSnapshot,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        del snapshot, as_of
        raise ValueError("synthetic invalid signature")

    rejected = _build_harness(verifier=reject_verification)
    signature = rejected.client.get(
        "/v1/cohort-proposals",
        params=_params(rejected),
        headers=_headers(),
    )
    assert signature.status_code == 409
    assert signature.json()["error"]["code"] == "evidence_snapshot_mismatch"
    assert "signature" not in signature.text

    oversized = _build_harness()
    binding = oversized.register_profile("production")
    oversized_snapshot = bundle.snapshot.model_copy(
        update={"evidence_records": [bundle.snapshot.evidence_records[0]] * 2001}
    )

    class OversizedRepository:
        def get_snapshot(
            self,
            requested: CohortEvidenceBinding,
        ) -> StoredEvidenceSnapshot | None:
            assert requested == binding
            return StoredEvidenceSnapshot.model_construct(
                binding=binding,
                snapshot=oversized_snapshot,
            )

    oversized.cohorts = CohortProposalService(
        context_store=oversized.store,
        authorization=oversized.authorization,
        clock=oversized.clock,
        snapshot_repository=OversizedRepository(),
        snapshot_verifier=CallableTrustedEvidenceSnapshotVerifier(oversized.verifier),
        proposal_cache=oversized.persistence,
        preview_receipts=oversized.persistence,
    )
    oversized.client = TestClient(
        create_app(
            service=oversized.lifecycle,
            authentication=StaticTestAuthenticator(
                {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
            ),
            cohort_service=oversized.cohorts,
        )
    )
    boundary = oversized.client.get(
        "/v1/cohort-proposals",
        params=_params(oversized),
        headers=_headers(),
    )
    assert boundary.status_code == 413
    assert boundary.json()["error"]["code"] == "cohort_boundary_exceeded"


def test_split_preview_is_selector_only_exact_and_non_authoritative() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _preview_body(harness, batch)
    source = next(
        proposal
        for proposal in batch["proposals"]
        if proposal["proposalId"] == body["proposal_ids"][0]
    )

    response = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=body,
        headers=_headers(idempotency_key="wc-031-split"),
    )

    assert response.status_code == 200, response.text
    candidate = response.json()
    assert candidate["sourceDraft"] == batch["sourceDraft"]
    assert candidate["scope"] == batch["scope"]
    assert candidate["snapshot"] == batch["snapshot"]
    assert candidate["sourceProposalIds"] == body["proposal_ids"]
    assert candidate["replaceRoleRefs"] == body["source_role_refs"]
    assert candidate["requiresHumanReview"] is True
    assert candidate["publicationAllowed"] is False
    assert candidate["manifestMutated"] is False
    update = candidate["roleUpdates"][0]
    assert {
        key: update["role"][key]
        for key in ("kind", "cardinality", "ownerRef", "status")
    } == {
        key: source["role"][key]
        for key in ("kind", "cardinality", "ownerRef", "status")
    }
    preview_members = [
        member
        for preview in update["selectorPreviews"]
        for member in preview["matchedResourceIds"]
    ]
    assert sorted(preview_members) == sorted(source["members"])
    assert len(preview_members) == len(set(preview_members))
    assert update["memberCount"] == len(source["members"])
    assert all(
        preview["maxMatches"]
        == preview["selector"]["maxMatches"]
        == len(preview["matchedResourceIds"])
        for preview in update["selectorPreviews"]
    )
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 1
    assert draft.manifest_digest == harness.draft_digest


def test_preview_rejects_malformed_and_mismatched_batch_bindings() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _preview_body(harness, batch)
    malformed = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**body, "resolution": "short"},
        headers=_headers(idempotency_key="wc-031-malformed"),
    )
    wrong_digest = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**body, "proposal_set_digest": "sha256:" + ("0" * 64)},
        headers=_headers(idempotency_key="wc-031-wrong-digest"),
    )
    wrong_role = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**body, "source_role_refs": ["unrelated-role"]},
        headers=_headers(idempotency_key="wc-031-wrong-role"),
    )
    invalid_merge = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**body, "action": "merge"},
        headers=_headers(idempotency_key="wc-031-invalid-merge"),
    )

    assert malformed.status_code == 422
    assert wrong_digest.status_code == 409
    assert wrong_digest.json()["error"]["code"] == "evidence_snapshot_mismatch"
    assert wrong_role.status_code == 409
    assert wrong_role.json()["error"]["code"] == "cohort_contract_invalid"
    assert invalid_merge.status_code == 422


def test_preview_rejects_a_draft_changed_after_proposal_load() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _preview_body(harness, batch)
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["workload"]["displayName"] += " revised"
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    harness.lifecycle.replace_draft(
        HUMAN,
        harness.draft_id,
        "wc-031-concurrent-replace",
        ReplaceDraftCommand(
            expected_revision=harness.draft_revision,
            expected_manifest_version=harness.manifest.manifest_version,
            expected_digest=harness.draft_digest,
            replacement_manifest=replacement,
            replacement_digest=replacement.compatibility.artifact_digest,
            reason="Simulate a concurrent synthetic draft replacement",
        ),
    )

    response = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=body,
        headers=_headers(idempotency_key="wc-031-stale-preview"),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stale_revision"


def test_preview_idempotency_replays_exactly_and_rejects_changed_payload() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _preview_body(harness, batch)
    headers = _headers(idempotency_key="wc-031-replay")

    first = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=body,
        headers=headers,
    )
    replay = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=body,
        headers=headers,
    )
    conflict = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={**body, "resolution": body["resolution"] + " Changed."},
        headers=headers,
    )

    assert first.status_code == replay.status_code == 200
    assert first.json() == replay.json()
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "idempotency_conflict"


def test_idempotency_key_cannot_replay_across_profile_environments() -> None:
    harness = _build_harness(profiles=("production", "development"))
    production = _load(harness, "production")
    development = _load(harness, "development")
    key = "wc-031-cross-environment"
    first = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=_preview_body(harness, production),
        headers=_headers(idempotency_key=key),
    )
    development_proposal = development["proposals"][0]
    cross_environment_body = {
        "action": "split",
        **_params(harness, "development"),
        "proposal_ids": [development_proposal["proposalId"]],
        "source_role_refs": [development_proposal["role"]["roleId"]],
        "proposal_set_digest": development["proposalSetDigest"],
        "snapshot_artifact_digest": development["snapshot"]["artifactDigest"],
        "resolution": "Human reviewed a different synthetic environment binding.",
    }
    replay = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=cross_environment_body,
        headers=_headers(idempotency_key=key),
    )

    assert first.status_code == 200
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "idempotency_conflict"


def _synthetic_merge_batch(
    harness: Harness,
    binding: CohortEvidenceBinding,
) -> CohortProposalBatchResponse:
    query = CohortProposalQuery(
        **_params(harness),
    )
    base = harness.cohorts.get_proposals(HUMAN, query)
    source = next(proposal for proposal in base.proposals if len(proposal.members) >= 2)
    resources = [
        record
        for record in harness.snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
    ]
    proposals: list[CohortProposal] = []
    for index, member in enumerate(source.members[:2], start=1):
        selector = ResourceIdListSelector(
            selectorType="resourceIdList",
            selectorId=f"merge-source-{index}",
            resourceIds=[member],
            maxMatches=1,
        )
        result = evaluate_selector(selector, resources)
        preview = SelectorPreview(
            selector=selector,
            matchedResourceIds=result.matched_resource_ids,
            selectorResultDigest=result.selector_result_digest,
            maxMatches=1,
        )
        payload = source.model_dump(mode="python", by_alias=True, exclude_none=True)
        payload.update(
            {
                "proposalId": f"proposal-{index:016x}",
                "members": [member],
                "confidence": 0.5,
                "confidenceBand": "low",
                "supportingEvidence": [],
                "dissent": [],
                "rejectedCandidates": [],
                "conflicts": [],
                "selectorPreview": preview,
                "disposition": "humanResolution",
                "bulkReviewEligible": False,
            }
        )
        proposals.append(CohortProposal.model_validate(payload))
    proposal_digest = compute_artifact_digest(
        [
            proposal.model_dump(mode="json", by_alias=True, exclude_none=True)
            for proposal in proposals
        ]
    )
    payload = base.model_dump(mode="python", by_alias=True, exclude_none=True)
    payload["proposals"] = proposals
    payload["proposalSetDigest"] = proposal_digest
    merged = CohortProposalBatchResponse.model_validate(payload)
    fresh_persistence = InMemoryCohortPersistence()
    fresh_persistence.put_batch_if_absent(
        CohortBatchCacheKey(
            evidence_binding=binding,
            snapshot_artifact_digest=harness.snapshot.compatibility.artifact_digest,
        ),
        merged,
    )
    harness.persistence = fresh_persistence
    harness.cohorts = CohortProposalService(
        context_store=harness.store,
        authorization=harness.authorization,
        clock=harness.clock,
        snapshot_repository=harness.snapshots,
        snapshot_verifier=CallableTrustedEvidenceSnapshotVerifier(harness.verifier),
        proposal_cache=fresh_persistence,
        preview_receipts=fresh_persistence,
    )
    harness.decisions = CohortDecisionService(
        store=harness.store,
        authorization=harness.authorization,
        clock=harness.clock,
        context_service=harness.lifecycle,
        proposal_service=harness.cohorts,
        candidate_repository=fresh_persistence,
    )
    harness.client = TestClient(
        create_app(
            service=harness.lifecycle,
            authentication=StaticTestAuthenticator(
                {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
            ),
            cohort_service=harness.cohorts,
            cohort_decision_service=harness.decisions,
        )
    )
    return merged


def test_merge_preview_preserves_disjoint_exact_source_union() -> None:
    harness = _build_harness()
    binding = harness.register_profile("production")
    batch = _synthetic_merge_batch(harness, binding)
    proposal_ids = [proposal.proposal_id for proposal in batch.proposals]
    response = harness.client.post(
        "/v1/cohort-proposals/preview",
        json={
            "action": "merge",
            **_params(harness),
            "proposal_ids": proposal_ids,
            "source_role_refs": [batch.proposals[0].role.role_id],
            "proposal_set_digest": batch.proposal_set_digest,
            "snapshot_artifact_digest": batch.snapshot.artifact_digest,
            "resolution": "Human reviewed the exact disjoint synthetic merge union.",
        },
        headers=_headers(idempotency_key="wc-031-merge"),
    )

    assert response.status_code == 200, response.text
    candidate = response.json()
    previews = candidate["roleUpdates"][0]["selectorPreviews"]
    members = [
        member
        for preview in previews
        for member in preview["matchedResourceIds"]
    ]
    source_members = [
        member for proposal in batch.proposals for member in proposal.members
    ]
    assert sorted(members) == sorted(source_members)
    assert len(members) == len(set(members))
    assert candidate["roleUpdates"][0]["memberCount"] == len(source_members)


def test_get_rejects_manifest_selectors_over_max_matches() -> None:
    payload = deepcopy(fixture_factory.load_canonical_manifest_resource())
    worker = next(role for role in payload["roles"] if role["roleId"] == "worker")
    worker["selectors"][0]["maxMatches"] = 1
    manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    harness = _build_harness(manifest=manifest)

    response = harness.client.get(
        "/v1/cohort-proposals",
        params=_params(harness),
        headers=_headers(),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "cohort_contract_invalid"


def test_get_is_deterministic_for_1000_members_and_within_wc012_bounds() -> None:
    trusted = _build_attested_snapshot(1000)
    payload = deepcopy(fixture_factory.load_canonical_manifest_resource())
    worker = next(role for role in payload["roles"] if role["roleId"] == "worker")
    worker["selectors"][0]["maxMatches"] = 1000
    manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    harness = _build_harness(
        manifest=manifest,
        snapshot=trusted.snapshot,
        verifier=trusted.verifier,
    )

    first_response = harness.client.get(
        "/v1/cohort-proposals",
        params=_params(harness),
        headers=_headers(),
    )
    second_response = harness.client.get(
        "/v1/cohort-proposals",
        params=_params(harness),
        headers=_headers(),
    )

    assert first_response.status_code == second_response.status_code == 200
    first = first_response.json()
    second = second_response.json()
    worker_proposal = next(
        proposal
        for proposal in first["proposals"]
        if proposal["role"]["roleId"] == "worker"
    )
    assert len(worker_proposal["members"]) == 1000
    assert worker_proposal["selectorPreview"]["maxMatches"] == 1000
    assert first == second
    assert len(first_response.content) <= 8 * 1024 * 1024

    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=_preview_body(
            harness,
            first,
            proposal_ids=[worker_proposal["proposalId"]],
        ),
        headers=_headers(idempotency_key="wc-031-scale-split"),
    )
    assert preview.status_code == 200, preview.text
    selector_previews = preview.json()["roleUpdates"][0]["selectorPreviews"]
    assert len(selector_previews) == 5
    assert sum(
        len(item["matchedResourceIds"]) for item in selector_previews
    ) == 1000
    assert all(item["maxMatches"] == 200 for item in selector_previews)
