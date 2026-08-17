from __future__ import annotations

from copy import deepcopy
from types import TracebackType
from typing import Any

from fastapi.testclient import TestClient

import athena_context.fixtures as fixture_factory
from athena_context.api.authorization import StaticTestAuthenticator
from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.domain import ReplaceDraftCommand
from athena_context.api.errors import PersistenceConflictError
from athena_context.api.http import create_app
from athena_context.contracts import (
    CanonicalWorkloadManifest,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    resolve_manifest_profile,
)
from test_cohort_binding import _build_attested_snapshot
from test_context_api_cohorts import (
    AGENT,
    HUMAN,
    OUTSIDER,
    TOKENS,
    WILDCARD,
    Harness,
    _build_harness,
    _headers,
    _load,
    _params,
    _preview_body,
    _synthetic_merge_batch,
    _verified,
)


def _proposal(
    batch: dict[str, Any],
    *,
    require_multiple_members: bool = False,
) -> dict[str, Any]:
    return next(
        proposal
        for proposal in batch["proposals"]
        if proposal["selectorPreview"] is not None
        and (not require_multiple_members or len(proposal["members"]) >= 2)
    )


def _decision_body(
    harness: Harness,
    batch: dict[str, Any],
    *,
    decision: str = "approve",
    proposal_ids: list[str] | None = None,
    candidate: dict[str, Any] | None = None,
    rationale: str = "Human accepted the exact bounded synthetic selector.",
) -> dict[str, Any]:
    selected_ids = proposal_ids or [_proposal(batch)["proposalId"]]
    selected = [
        proposal
        for proposal in batch["proposals"]
        if proposal["proposalId"] in selected_ids
    ]
    role_refs = list(
        dict.fromkeys(proposal["role"]["roleId"] for proposal in selected)
    )
    if decision == "approve" and candidate is None:
        proposal = selected[0]
        preview = proposal["selectorPreview"]
        candidate = {
            "candidateId": f"review-{proposal['proposalId']}",
            "action": "approve",
            "sourceDraft": batch["sourceDraft"],
            "scope": batch["scope"],
            "sourceProposalIds": selected_ids,
            "proposalSetDigest": batch["proposalSetDigest"],
            "snapshot": batch["snapshot"],
            "roleUpdates": [
                {
                    "role": {
                        **proposal["role"],
                        "selectors": [preview["selector"]],
                    },
                    "selectorPreviews": [preview],
                    "memberCount": len(proposal["members"]),
                }
            ],
            "replaceRoleRefs": role_refs,
            "resolution": rationale,
            "generatedAt": batch["evaluatedAt"],
            "expiresAt": batch["snapshot"]["expiresAt"],
            "requiresHumanReview": True,
            "publicationAllowed": False,
            "manifestMutated": False,
        }
    body: dict[str, Any] = {
        "action": decision,
        **_params(harness),
        "scope": batch["scope"],
        "proposal_set_digest": batch["proposalSetDigest"],
        "proposal_ids": selected_ids,
        "snapshot_artifact_digest": batch["snapshot"]["artifactDigest"],
        "candidate": candidate,
        "rationale": rationale,
    }
    return body


def _post_decision(
    harness: Harness,
    body: dict[str, Any],
    key: str,
    *,
    actor=HUMAN,
):
    return harness.client.post(
        "/v1/cohort-proposals/decisions",
        json=body,
        headers=_headers(actor, idempotency_key=key),
    )


def _decision_list_params(
    harness: Harness,
    batch: dict[str, Any],
) -> dict[str, Any]:
    return {
        "manifest_id": harness.manifest.manifest_id,
        "manifest_version": harness.manifest.manifest_version,
        "profile_id": batch["scope"]["profileId"],
        "profile_type": batch["scope"]["profileType"],
        "resolved_profile_digest": batch["scope"]["resolvedProfileDigest"],
        "draft_id": harness.draft_id,
        "expected_revision": harness.draft_revision,
        "expected_digest": harness.draft_digest,
        "proposal_ids": [
            proposal["proposalId"] for proposal in batch["proposals"]
        ],
        "proposal_set_digest": batch["proposalSetDigest"],
        "snapshot_artifact_digest": batch["snapshot"]["artifactDigest"],
    }


def test_approve_persists_audited_decision_and_atomically_replaces_selectors() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch)
    rationale = "R" * 2000
    body = _decision_body(harness, batch, rationale=rationale)

    response = _post_decision(harness, body, "wc-034-approve")

    assert response.status_code == 201, response.text
    schema = harness.client.get("/openapi.json").json()
    assert set(
        schema["paths"]["/v1/cohort-proposals/decisions"]
    ) >= {"get", "post"}
    assert (
        "/v1/cohort-proposals/decisions/{decision_id}" in schema["paths"]
    )
    decision = response.json()
    assert set(decision) == {
        "decisionId",
        "action",
        "sourceDraft",
        "scope",
        "proposalIds",
        "proposalSetDigest",
        "snapshotArtifactDigest",
        "candidateId",
        "rationale",
        "state",
        "decidedBy",
        "decidedAt",
        "draftResult",
        "publicationAllowed",
    }
    assert decision["action"] == "approve"
    assert decision["rationale"] == rationale
    assert decision["decidedBy"] == HUMAN.actor_id
    assert decision["state"] == "applied"
    assert decision["sourceDraft"] == batch["sourceDraft"]
    assert decision["scope"] == batch["scope"]
    assert decision["proposalIds"] == [proposal["proposalId"]]
    assert decision["snapshotArtifactDigest"] == batch["snapshot"]["artifactDigest"]
    assert decision["draftResult"]["revision"] == 2
    assert decision["candidateId"] == f"review-{proposal['proposalId']}"
    assert decision["publicationAllowed"] is False

    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 2
    assert len(draft.reason) <= 500
    assert decision["decisionId"] in draft.reason
    assert rationale not in draft.reason
    profile = resolve_manifest_profile(
        draft.manifest,
        "production",
        as_of=harness.clock.now(),
    )
    role = next(
        role
        for role in profile.roles
        if role.role_id == proposal["role"]["roleId"]
    )
    approved_role = body["candidate"]["roleUpdates"][0]["role"]
    assert proposal["selectorPreview"]["selector"]["selectorId"] == (
        proposal["role"]["selectors"][0]["selectorId"]
    )
    assert role.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    ) == approved_role
    assert [
        selector.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        for selector in role.selectors
    ] == approved_role["selectors"]
    with harness.store.transaction() as tx:
        audit = tx.list_audit(manifest_id=harness.manifest.manifest_id)
        stored = tx.get_cohort_decision(
            harness.manifest.manifest_id,
            decision["decisionId"],
        )
        assert audit[-2].reason == draft.reason
        assert audit[-1].action == "cohort_decision_recorded"
        assert decision["decisionId"] in audit[-1].reason
        assert audit[-1].revision == 2
        assert stored is not None
        assert stored.candidate_digest == compute_artifact_digest(
            body["candidate"]
        )
        assert tx.list_published(manifest_id=harness.manifest.manifest_id) == []

    read = harness.client.get(
        f"/v1/cohort-proposals/decisions/{decision['decisionId']}",
        params={"manifest_id": harness.manifest.manifest_id},
        headers=_headers(),
    )
    listed = harness.client.get(
        "/v1/cohort-proposals/decisions",
        params=_decision_list_params(harness, batch),
        headers=_headers(),
    )
    assert read.status_code == listed.status_code == 200
    assert read.json() == decision
    assert listed.json() == [decision]


def test_global_role_fixture_materializes_only_production_local_override() -> None:
    harness = _build_harness(profiles=("production", "development", "training"))
    batch = _load(harness)
    proposal = _proposal(batch)
    as_of = harness.clock.now()
    before_profiles = {
        profile_id: resolve_manifest_profile(
            harness.manifest,
            profile_id,
            as_of=as_of,
        )
        for profile_id in ("production", "development", "training")
    }
    before_global_roles = harness.manifest.roles
    body = _decision_body(harness, batch)

    response = _post_decision(
        harness,
        body,
        "wc-034-global-role-regression",
    )

    assert response.status_code == 201, response.text
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.manifest.roles == before_global_roles
    production = draft.manifest.profiles["production"]
    local_role = next(
        role
        for role in production.roles
        if role.role_id == proposal["role"]["roleId"]
    )
    assert {
        "kind": local_role.kind,
        "cardinality": local_role.cardinality,
        "owner_ref": local_role.owner_ref,
        "status": local_role.status,
    } == {
        "kind": proposal["role"]["kind"],
        "cardinality": next(
            role.cardinality
            for role in before_profiles["production"].roles
            if role.role_id == local_role.role_id
        ),
        "owner_ref": proposal["role"]["ownerRef"],
        "status": proposal["role"]["status"],
    }
    assert local_role.selectors[0].selector_id == (
        proposal["role"]["selectors"][0]["selectorId"]
    )
    assert local_role.selectors[0].max_matches == len(proposal["members"])
    assert [
        selector.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        for selector in local_role.selectors
    ] == body["candidate"]["roleUpdates"][0]["role"]["selectors"]
    assert all(
        profile.weakening_overrides
        == harness.manifest.profiles[profile_id].weakening_overrides
        for profile_id, profile in draft.manifest.profiles.items()
    )

    after_profiles = {
        profile_id: resolve_manifest_profile(
            draft.manifest,
            profile_id,
            as_of=as_of,
        )
        for profile_id in ("production", "development", "training")
    }
    for profile_id in ("development", "training"):
        assert after_profiles[profile_id].roles == before_profiles[profile_id].roles
        assert (
            after_profiles[profile_id].compatibility.semantic_digest
            == before_profiles[profile_id].compatibility.semantic_digest
        )
        assert (
            after_profiles[profile_id].resolved_profile_digest
            == before_profiles[profile_id].resolved_profile_digest
        )
    before_production_roles = {
        role.role_id: role for role in before_profiles["production"].roles
    }
    after_production_roles = {
        role.role_id: role for role in after_profiles["production"].roles
    }
    assert set(after_production_roles) == set(before_production_roles)
    assert all(
        after_production_roles[role_id] == role
        for role_id, role in before_production_roles.items()
        if role_id != local_role.role_id
    )
    assert (
        after_profiles["production"].compatibility.semantic_digest
        != before_profiles["production"].compatibility.semantic_digest
    )


def test_local_override_rejects_when_it_would_change_descendant_profile() -> None:
    payload = deepcopy(fixture_factory.load_canonical_manifest_resource())
    payload["profiles"]["development"]["extends"] = "production"
    manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    harness = _build_harness(manifest=manifest)
    batch = _load(harness)

    response = _post_decision(
        harness,
        _decision_body(harness, batch),
        "wc-034-descendant-profile-block",
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "cohort_contract_invalid"
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 1
    assert draft.manifest == manifest
    with harness.store.transaction() as tx:
        assert tx.list_cohort_decisions(manifest_id=manifest.manifest_id) == []


def test_reject_is_durable_idempotent_and_permanently_blocks_apply() -> None:
    harness = _build_harness()
    batch = _load(harness)
    reject = _decision_body(
        harness,
        batch,
        decision="reject",
        rationale="Do not apply this proposal-set version.",
    )
    headers = _headers(idempotency_key="wc-034-reject")

    first = harness.client.post(
        "/v1/cohort-proposals/decisions",
        json=reject,
        headers=headers,
    )
    replay = harness.client.post(
        "/v1/cohort-proposals/decisions",
        json=reject,
        headers=headers,
    )
    changed_replay = harness.client.post(
        "/v1/cohort-proposals/decisions",
        json={**reject, "rationale": reject["rationale"] + " Changed."},
        headers=headers,
    )
    blocked = _post_decision(
        harness,
        _decision_body(harness, batch),
        "wc-034-apply-after-reject",
    )

    assert first.status_code == replay.status_code == 201
    assert first.json() == replay.json()
    assert first.json()["state"] == "rejected"
    assert first.json()["candidateId"] is None
    assert first.json()["draftResult"] is None
    assert changed_replay.status_code == 409
    assert changed_replay.json()["error"]["code"] == "idempotency_conflict"
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "cohort_proposal_set_rejected"
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 1
    with harness.store.transaction() as tx:
        audit = tx.list_audit(manifest_id=harness.manifest.manifest_id)
        assert audit[-1].action == "cohort_decision_recorded"
        assert first.json()["decisionId"] in audit[-1].reason


def test_four_proposal_batch_allows_disjoint_authoritative_decisions() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal_ids = [
        proposal["proposalId"] for proposal in batch["proposals"]
    ]
    assert len(proposal_ids) == 4
    first_selection = list(reversed(proposal_ids[:2]))
    first_body = _decision_body(
        harness,
        batch,
        decision="reject",
        proposal_ids=first_selection,
        rationale="Reject the first exact synthetic proposal selection.",
    )
    second_body = _decision_body(
        harness,
        batch,
        decision="reject",
        proposal_ids=proposal_ids[2:],
        rationale="Reject the disjoint second synthetic proposal selection.",
    )

    first = _post_decision(harness, first_body, "wc-034-four-first")
    replay = _post_decision(harness, first_body, "wc-034-four-first")
    canonical_set_replay = _post_decision(
        harness,
        {
            **first_body,
            "proposal_ids": sorted(first_selection),
        },
        "wc-034-four-first",
    )
    exact_new_receipt = _post_decision(
        harness,
        first_body,
        "wc-034-four-first-new-receipt",
    )
    disjoint = _post_decision(
        harness,
        second_body,
        "wc-034-four-second",
    )
    overlapping = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=proposal_ids[1:3],
            rationale="This selection overlaps both exact synthetic decisions.",
        ),
        "wc-034-four-overlap",
    )

    assert (
        first.status_code
        == replay.status_code
        == canonical_set_replay.status_code
        == disjoint.status_code
        == 201
    )
    assert first.json() == replay.json() == canonical_set_replay.json()
    assert exact_new_receipt.status_code == overlapping.status_code == 409
    assert exact_new_receipt.json()["error"]["code"] == (
        "cohort_decision_conflict"
    )
    assert overlapping.json()["error"]["code"] == "cohort_decision_conflict"
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert {
        frozenset(decision.source_proposal_ids)
        for decision in decisions
    } == {
        frozenset(proposal_ids[:2]),
        frozenset(proposal_ids[2:]),
    }
    assert all(
        decision.proposal_set_version().source_proposal_ids
        == sorted(decision.source_proposal_ids)
        for decision in decisions
    )


def test_four_proposal_rejection_blocks_only_overlapping_apply() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposals = batch["proposals"]
    assert len(proposals) == 4
    rejected_id = proposals[0]["proposalId"]
    allowed_id = proposals[1]["proposalId"]
    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[rejected_id],
            rationale="Reject only this exact synthetic proposal.",
        ),
        "wc-034-four-reject-one",
    )

    blocked = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            proposal_ids=[rejected_id],
        ),
        "wc-034-four-blocked-overlap",
    )
    allowed_body = _decision_body(
        harness,
        batch,
        proposal_ids=[allowed_id],
    )
    allowed = _post_decision(
        harness,
        allowed_body,
        "wc-034-four-allowed-disjoint",
    )

    assert rejected.status_code == allowed.status_code == 201
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "cohort_proposal_set_rejected"
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    profile = resolve_manifest_profile(
        draft.manifest,
        "production",
        as_of=harness.clock.now(),
    )
    applied_role = next(
        role
        for role in profile.roles
        if role.role_id == proposals[1]["role"]["roleId"]
    )
    assert [
        selector.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        for selector in applied_role.selectors
    ] == allowed_body["candidate"]["roleUpdates"][0]["role"]["selectors"]
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert {
        proposal_id
        for decision in decisions
        for proposal_id in decision.source_proposal_ids
    } == {rejected_id, allowed_id}


def test_decisions_require_verified_human_explicit_workload_scope() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _decision_body(harness, batch)

    missing = harness.client.post(
        "/v1/cohort-proposals/decisions",
        json=body,
        headers={"Idempotency-Key": "wc-034-no-auth"},
    )
    outsider = _post_decision(
        harness,
        body,
        "wc-034-outsider",
        actor=OUTSIDER,
    )
    agent = _post_decision(harness, body, "wc-034-agent", actor=AGENT)
    wildcard_list = harness.client.get(
        "/v1/cohort-proposals/decisions",
        params=_decision_list_params(harness, batch),
        headers=_headers(WILDCARD),
    )
    cross_workload = harness.client.get(
        "/v1/cohort-proposals/decisions/not-present",
        params={"manifest_id": "wl-other-synthetic"},
        headers=_headers(),
    )

    assert missing.status_code == 401
    assert outsider.status_code == agent.status_code == 403
    assert wildcard_list.status_code == cross_workload.status_code == 403
    assert harness.lifecycle.get_draft(HUMAN, harness.draft_id).revision == 1


def test_stale_batch_candidate_substitution_and_binding_changes_fail_closed() -> None:
    substituted = _build_harness()
    batch = _load(substituted)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        substituted,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = substituted.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-preview-substitution"),
    )
    assert preview.status_code == 200, preview.text
    decision = _decision_body(
        substituted,
        batch,
        decision="split",
        proposal_ids=[proposal["proposalId"]],
        candidate={
            **preview.json(),
            "candidateId": "candidate-substituted",
        },
        rationale=preview_body["resolution"],
    )
    wrong_candidate = _post_decision(
        substituted,
        decision,
        "wc-034-wrong-candidate",
    )
    changed_snapshot = _post_decision(
        substituted,
        {
            **decision,
            "candidate": preview.json(),
            "snapshot_artifact_digest": "sha256:" + ("0" * 64),
        },
        "wc-034-wrong-snapshot",
    )
    assert wrong_candidate.status_code == changed_snapshot.status_code == 409
    assert wrong_candidate.json()["error"]["code"] == "cohort_contract_invalid"
    assert changed_snapshot.json()["error"]["code"] == "cohort_contract_invalid"

    stale = _build_harness()
    stale_batch = _load(stale)
    payload = stale.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["workload"]["displayName"] += " concurrent"
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    stale.lifecycle.replace_draft(
        HUMAN,
        stale.draft_id,
        "wc-034-concurrent-replace",
        ReplaceDraftCommand(
            expected_revision=stale.draft_revision,
            expected_manifest_version=stale.manifest.manifest_version,
            expected_digest=stale.draft_digest,
            replacement_manifest=replacement,
            replacement_digest=replacement.compatibility.artifact_digest,
            reason="Synthetic concurrent update before cohort decision",
        ),
    )
    stale_response = _post_decision(
        stale,
        _decision_body(stale, stale_batch),
        "wc-034-stale",
    )
    assert stale_response.status_code == 409
    assert stale_response.json()["error"]["code"] == "stale_revision"


def test_split_and_merge_reject_when_no_local_same_variant_override_exists() -> None:
    split = _build_harness()
    split_batch = _load(split)
    split_proposal = _proposal(split_batch, require_multiple_members=True)
    split_preview_body = _preview_body(
        split,
        split_batch,
        proposal_ids=[split_proposal["proposalId"]],
    )
    split_preview = split.client.post(
        "/v1/cohort-proposals/preview",
        json=split_preview_body,
        headers=_headers(idempotency_key="wc-034-split-preview"),
    )
    split_apply = _post_decision(
        split,
        _decision_body(
            split,
            split_batch,
            decision="split",
            proposal_ids=[split_proposal["proposalId"]],
            candidate=split_preview.json(),
            rationale=split_preview_body["resolution"],
        ),
        "wc-034-split-apply",
    )
    assert split_preview.status_code == 200
    assert {
        selector["selectorType"]
        for selector in split_preview.json()["roleUpdates"][0]["role"]["selectors"]
    } == {"resourceIdList"}
    assert split_apply.status_code == 409
    assert split_apply.json()["error"]["code"] == "cohort_contract_invalid"
    split_draft = split.lifecycle.get_draft(HUMAN, split.draft_id)
    assert split_draft.revision == 1
    assert split_draft.manifest == split.manifest

    merge = _build_harness()
    binding = merge.register_profile("production")
    merged_batch = _synthetic_merge_batch(merge, binding)
    merged_wire = merged_batch.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    proposal_ids = [proposal["proposalId"] for proposal in merged_wire["proposals"]]
    merge_preview_body = _preview_body(
        merge,
        merged_wire,
        action="merge",
        proposal_ids=proposal_ids,
        resolution="Human reviewed the exact synthetic merge candidate.",
    )
    merge_preview = merge.client.post(
        "/v1/cohort-proposals/preview",
        json=merge_preview_body,
        headers=_headers(idempotency_key="wc-034-merge-preview"),
    )
    merge_apply = _post_decision(
        merge,
        _decision_body(
            merge,
            merged_wire,
            decision="merge",
            proposal_ids=proposal_ids,
            candidate=merge_preview.json(),
            rationale=merge_preview_body["resolution"],
        ),
        "wc-034-merge-apply",
    )
    assert merge_preview.status_code == 200, merge_preview.text
    assert {
        selector["selectorType"]
        for selector in merge_preview.json()["roleUpdates"][0]["role"]["selectors"]
    } == {"resourceIdList"}
    assert merge_apply.status_code == 409
    assert merge_apply.json()["error"]["code"] == "cohort_contract_invalid"
    merge_draft = merge.lifecycle.get_draft(HUMAN, merge.draft_id)
    assert merge_draft.revision == 1
    assert merge_draft.manifest == merge.manifest
    with split.store.transaction() as tx:
        assert tx.list_cohort_decisions(
            manifest_id=split.manifest.manifest_id
        ) == []
    with merge.store.transaction() as tx:
        assert tx.list_cohort_decisions(
            manifest_id=merge.manifest.manifest_id
        ) == []


class _FailAfterDraftTransaction:
    def __init__(self, inner) -> None:
        self._manager = inner
        self._transaction = None

    def __enter__(self):
        self._transaction = self._manager.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        return self._manager.__exit__(exc_type, exc_value, traceback)

    def __getattr__(self, name: str):
        if self._transaction is None:
            raise AttributeError(name)
        return getattr(self._transaction, name)

    def put_cohort_decision(self, decision) -> None:
        del decision
        raise PersistenceConflictError(
            "synthetic decision persistence failure after draft update"
        )


class _FailAfterDraftStore:
    def __init__(self, store) -> None:
        self._store = store

    def transaction(self) -> _FailAfterDraftTransaction:
        return _FailAfterDraftTransaction(self._store.transaction())


def test_decision_and_draft_roll_back_together_on_persistence_failure() -> None:
    harness = _build_harness()
    batch = _load(harness)
    failing = CohortDecisionService(
        store=_FailAfterDraftStore(harness.store),
        authorization=harness.authorization,
        clock=harness.clock,
        context_service=harness.lifecycle,
        proposal_service=harness.cohorts,
        candidate_repository=harness.persistence,
    )
    client = TestClient(
        create_app(
            service=harness.lifecycle,
            authentication=StaticTestAuthenticator(
                {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
            ),
            cohort_service=harness.cohorts,
            cohort_decision_service=failing,
        )
    )

    response = client.post(
        "/v1/cohort-proposals/decisions",
        json=_decision_body(harness, batch),
        headers=_headers(idempotency_key="wc-034-rollback"),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "persistence_conflict"
    assert harness.lifecycle.get_draft(HUMAN, harness.draft_id).revision == 1
    with harness.store.transaction() as tx:
        assert tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        ) == []
        assert tx.get_cohort_decision_receipt(
            HUMAN.actor_id,
            "wc-034-rollback",
        ) is None


def test_approve_applies_exact_1000_member_selector_without_publication() -> None:
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
    batch = _load(harness)
    proposal = next(
        proposal
        for proposal in batch["proposals"]
        if proposal["role"]["roleId"] == "worker"
    )

    response = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            proposal_ids=[proposal["proposalId"]],
        ),
        "wc-034-1000-approve",
    )

    assert response.status_code == 201, response.text
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    profile = resolve_manifest_profile(
        draft.manifest,
        "production",
        as_of=harness.clock.now(),
    )
    updated = next(role for role in profile.roles if role.role_id == "worker")
    assert updated.selectors[0].max_matches == 1000
    with harness.store.transaction() as tx:
        assert tx.list_published(manifest_id=harness.manifest.manifest_id) == []
