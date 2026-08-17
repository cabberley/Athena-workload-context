from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from types import TracebackType
from typing import Any

import pytest
from fastapi.testclient import TestClient

import athena_context.fixtures as fixture_factory
from athena_context.api.authorization import StaticTestAuthenticator
from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.cohort_memory import (
    CallableTrustedEvidenceSnapshotVerifier,
    InMemoryCohortPersistence,
)
from athena_context.api.cohort_service import CohortProposalService
from athena_context.api.domain import (
    CreateDraftCommand,
    ReplaceDraftCommand,
    TransitionCommand,
)
from athena_context.api.errors import PersistenceConflictError
from athena_context.api.http import create_app
from athena_context.api.selector_provenance import (
    manifest_selector_provenance,
)
from athena_context.contracts import (
    AthenaValidationError,
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
    SECOND_REVIEWER,
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


def _replace_only_proposal_cache(harness: Harness) -> None:
    fresh_cache = InMemoryCohortPersistence()
    cohorts = CohortProposalService(
        context_store=harness.store,
        authorization=harness.authorization,
        clock=harness.clock,
        snapshot_repository=harness.snapshots,
        snapshot_verifier=CallableTrustedEvidenceSnapshotVerifier(
            harness.verifier
        ),
        proposal_cache=fresh_cache,
        preview_receipts=harness.persistence,
    )
    decisions = CohortDecisionService(
        store=harness.store,
        authorization=harness.authorization,
        clock=harness.clock,
        context_service=harness.lifecycle,
        proposal_service=cohorts,
        candidate_repository=harness.persistence,
    )
    harness.cohorts = cohorts
    harness.decisions = decisions
    harness.client = TestClient(
        create_app(
            service=harness.lifecycle,
            authentication=StaticTestAuthenticator(
                {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
            ),
            cohort_service=cohorts,
            cohort_decision_service=decisions,
        )
    )


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
        assert audit[-1].reason == draft.reason
        assert audit[-2].action == "cohort_decision_recorded"
        assert decision["decisionId"] in audit[-2].reason
        assert audit[-2].revision == 2
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


def test_rejected_split_candidate_cannot_bypass_decision_api_with_generic_put() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-rejected-put-preview"),
    )
    assert preview.status_code == 200, preview.text

    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[proposal["proposalId"]],
            candidate=None,
            rationale="Reject this exact split proposal before generic PUT.",
        ),
        "wc-034-rejected-before-generic-put",
    )
    assert rejected.status_code == 201, rejected.text
    assert rejected.json()["state"] == "rejected"

    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    local_roles = payload["profiles"]["production"]["roles"]
    local_roles[:] = [
        role
        for role in local_roles
        if role["roleId"] != candidate_role["roleId"]
    ]
    local_roles.append(candidate_role)
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    command = ReplaceDraftCommand(
        expected_revision=harness.draft_revision,
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=harness.draft_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason="Attempt rejected cohort selectors through ordinary draft PUT",
    )
    bypass = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-rejected-candidate-generic-put",
        ),
        json=command.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )

    assert bypass.status_code == 422, bypass.text
    assert bypass.json()["error"]["code"] == "manifest_validation_failed"
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 1
    assert draft.manifest == harness.manifest
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
        audit = tx.list_audit(manifest_id=harness.manifest.manifest_id)
    assert len(decisions) == 1
    assert decisions[0].decision.value == "reject"
    assert all(event.action.value != "draft_replaced" for event in audit)


def test_rejected_split_candidate_cannot_become_global_role_with_generic_put() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-rejected-global-preview"),
    )
    assert preview.status_code == 200, preview.text

    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[proposal["proposalId"]],
            candidate=None,
            rationale="Reject this exact split proposal before a global PUT.",
        ),
        "wc-034-rejected-before-global-put",
    )
    assert rejected.status_code == 201, rejected.text
    assert rejected.json()["state"] == "rejected"

    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    matching_global = next(
        role
        for role in payload["roles"]
        if role["roleId"] == candidate_role["roleId"]
    )
    payload["roles"][payload["roles"].index(matching_global)] = candidate_role
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    assert next(
        role
        for role in replacement.roles
        if role.role_id == candidate_role["roleId"]
    ).model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    ) == candidate_role
    command = ReplaceDraftCommand(
        expected_revision=harness.draft_revision,
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=harness.draft_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason="Attempt rejected selectors as the global role baseline",
    )
    bypass = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-rejected-candidate-global-put",
        ),
        json=command.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )

    assert bypass.status_code == 422, bypass.text
    assert bypass.json()["error"]["code"] == "manifest_validation_failed"
    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == harness.draft_revision
    assert draft.manifest == harness.manifest
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
        audit = tx.list_audit(manifest_id=harness.manifest.manifest_id)
    assert len(decisions) == 1
    assert decisions[0].decision.value == "reject"
    assert all(event.action.value != "draft_replaced" for event in audit)


@pytest.mark.parametrize(
    "attack",
    [
        "remove-global-role",
        "same-id-new-variant",
        "same-id-new-semantics",
        "move-to-other-profile",
        "move-to-other-role",
        "copy-to-new-role",
    ],
)
def test_rejected_selectors_cannot_change_immutable_provenance(
    attack: str,
) -> None:
    harness = _build_harness(profiles=("production", "development"))
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(
            idempotency_key=f"wc-034-provenance-{attack}-preview",
        ),
    )
    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[proposal["proposalId"]],
            candidate=None,
            rationale="Reject selectors before a provenance laundering attempt.",
        ),
        f"wc-034-provenance-{attack}-reject",
    )
    assert preview.status_code == 200, preview.text
    assert rejected.status_code == 201, rejected.text
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    target_role_id = candidate_role["roleId"]
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    target_global = next(
        role for role in payload["roles"] if role["roleId"] == target_role_id
    )
    if attack == "remove-global-role":
        payload["roles"] = [
            role
            for role in payload["roles"]
            if role["roleId"] != target_role_id
        ]
    elif attack == "same-id-new-variant":
        original_selector_id = target_global["selectors"][0]["selectorId"]
        target_global["selectors"] = [
            {
                "selectorType": "resourceIdList",
                "selectorId": original_selector_id,
                "resourceIds": proposal["members"],
                "maxMatches": len(proposal["members"]),
            }
        ]
    elif attack == "same-id-new-semantics":
        target_global["selectors"][0]["maxMatches"] += 1
    elif attack == "move-to-other-profile":
        development_roles = payload["profiles"]["development"]["roles"]
        development_roles[:] = [
            role
            for role in development_roles
            if role["roleId"] != target_role_id
        ]
        development_roles.append(candidate_role)
    elif attack == "move-to-other-role":
        other_role = next(
            role
            for role in payload["roles"]
            if role["roleId"] != target_role_id
        )
        other_role["selectors"] = candidate_role["selectors"]
    else:
        copied_role = deepcopy(candidate_role)
        copied_role["roleId"] = "rejected-selector-copy"
        payload["roles"].append(copied_role)
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    command = ReplaceDraftCommand(
        expected_revision=harness.draft_revision,
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=harness.draft_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason="Attempt to launder rejected selector provenance",
    )
    with harness.store.transaction() as tx:
        audit_before = tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        )

    response = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key=f"wc-034-provenance-{attack}-put",
        ),
        json=command.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "manifest_validation_failed"
    unchanged = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert unchanged.revision == harness.draft_revision
    assert unchanged.manifest_digest == harness.draft_digest
    assert unchanged.manifest == harness.manifest
    with harness.store.transaction() as tx:
        assert tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        ) == audit_before
        assert tx.get_receipt(
            HUMAN.actor_id,
            f"wc-034-provenance-{attack}-put",
        ) is None


@pytest.mark.parametrize("fresh_version", ["1.0.0", "1.0.1"])
def test_rejected_selectors_cannot_be_laundered_as_fresh_draft_baseline(
    fresh_version: str,
) -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-fresh-launder-preview"),
    )
    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[proposal["proposalId"]],
            candidate=None,
            rationale="Reject selectors before fresh draft laundering.",
        ),
        "wc-034-fresh-launder-reject",
    )
    assert preview.status_code == 200, preview.text
    assert rejected.status_code == 201, rejected.text
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["manifestVersion"] = fresh_version
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    local_roles = payload["profiles"]["production"]["roles"]
    local_roles[:] = [
        role
        for role in local_roles
        if role["roleId"] != candidate_role["roleId"]
    ]
    local_roles.append(candidate_role)
    laundering_manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    command = CreateDraftCommand(
        draft_id=(
            "draft-wc-034-fresh-selector-launder-"
            + fresh_version.replace(".", "-")
        ),
        manifest=laundering_manifest,
        manifest_digest=(
            laundering_manifest.compatibility.artifact_digest
        ),
        reason="Attempt rejected selectors as a fresh draft baseline",
    )
    with harness.store.transaction() as tx:
        audit_before = tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        )

    response = harness.client.post(
        "/v1/drafts",
        headers=_headers(
            HUMAN,
            idempotency_key=(
                "wc-034-fresh-selector-launder-"
                + fresh_version.replace(".", "-")
            ),
        ),
        json=command.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "manifest_validation_failed"
    with harness.store.transaction() as tx:
        assert tx.get_draft(command.draft_id) is None
        assert tx.get_draft_selector_baseline(command.draft_id) is None
        assert tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        ) == audit_before
        assert tx.get_receipt(
            HUMAN.actor_id,
            "wc-034-fresh-selector-launder-"
            + fresh_version.replace(".", "-"),
        ) is None


def test_remove_readd_and_lifecycle_cannot_escape_selector_baseline() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-baseline-preview"),
    )
    rejected = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="reject",
            proposal_ids=[proposal["proposalId"]],
            candidate=None,
            rationale="Reject selectors before lifecycle baseline validation.",
        ),
        "wc-034-baseline-reject",
    )
    assert preview.status_code == 200, preview.text
    assert rejected.status_code == 201, rejected.text
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    payload["roles"] = [
        role
        for role in payload["roles"]
        if role["roleId"] != candidate_role["roleId"]
    ]
    removed_manifest = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    with harness.store.transaction() as tx:
        current = tx.get_draft(harness.draft_id)
        assert current is not None
        tampered = current.model_copy(
            update={
                "revision": current.revision + 1,
                "manifest": removed_manifest,
                "manifest_digest": (
                    removed_manifest.compatibility.artifact_digest
                ),
            }
        )
        tx.put_draft(tampered, expected_revision=current.revision)
        audit_before = tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        )

    restore_payload = removed_manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    restore_payload["roles"].append(candidate_role)
    restored_candidate = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(restore_payload)
    )
    restore = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-baseline-readd-put",
        ),
        json=ReplaceDraftCommand(
            expected_revision=tampered.revision,
            expected_manifest_version=tampered.manifest.manifest_version,
            expected_digest=tampered.manifest_digest,
            replacement_manifest=restored_candidate,
            replacement_digest=(
                restored_candidate.compatibility.artifact_digest
            ),
            reason="Attempt to re-add exact rejected selectors after removal",
        ).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )
    validate = harness.client.post(
        f"/v1/drafts/{harness.draft_id}/validate",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-baseline-lifecycle-validate",
        ),
        json=TransitionCommand(
            expected_revision=tampered.revision,
            expected_manifest_version=(
                tampered.manifest.manifest_version
            ),
            expected_digest=tampered.manifest_digest,
            reason="Reject selector state without approved provenance",
        ).model_dump(mode="json"),
    )

    assert restore.status_code == 422, restore.text
    assert restore.json()["error"]["code"] == "manifest_validation_failed"
    assert validate.status_code == 422, validate.text
    assert validate.json()["error"]["code"] == "manifest_validation_failed"
    assert harness.lifecycle.get_draft(HUMAN, harness.draft_id) == tampered
    with harness.store.transaction() as tx:
        assert tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        ) == audit_before
        assert tx.get_receipt(
            HUMAN.actor_id,
            "wc-034-baseline-lifecycle-validate",
        ) is None
        assert tx.get_receipt(
            HUMAN.actor_id,
            "wc-034-baseline-readd-put",
        ) is None


def test_generic_put_allows_global_role_non_selector_edit() -> None:
    harness = _build_harness()
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["ownership"].append(
        {
            "ownerRef": "synthetic-platform-owner",
            "ownerRole": "technicalOwner",
            "authorityRef": "synthetic://authority/platform",
        }
    )
    worker = next(
        role for role in payload["roles"] if role["roleId"] == "worker"
    )
    original_selectors = deepcopy(worker["selectors"])
    worker["ownerRef"] = "synthetic-platform-owner"
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    command = ReplaceDraftCommand(
        expected_revision=harness.draft_revision,
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=harness.draft_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason="Apply a legal global non-selector role edit",
    )

    response = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-legal-global-non-selector-put",
        ),
        json=command.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )

    assert response.status_code == 200, response.text
    assert response.json()["revision"] == harness.draft_revision + 1
    updated_worker = next(
        role
        for role in response.json()["manifest"]["roles"]
        if role["roleId"] == "worker"
    )
    assert updated_worker["ownerRef"] == "synthetic-platform-owner"
    assert updated_worker["selectors"] == original_selectors


def test_direct_replace_cannot_fabricate_cohort_authority_without_decision() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-direct-fabrication-preview"),
    )
    assert preview.status_code == 200, preview.text
    payload = harness.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    candidate_role = preview.json()["roleUpdates"][0]["role"]
    payload["profiles"]["production"]["roles"].append(candidate_role)
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )
    fabricated_decision_id = "cohort-decision-fabricated-authority"
    command = ReplaceDraftCommand(
        expected_revision=harness.draft_revision,
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=harness.draft_digest,
        replacement_manifest=replacement,
        replacement_digest=replacement.compatibility.artifact_digest,
        reason=(
            f"Attempt selector mutation with {fabricated_decision_id} "
            "but no persisted decision"
        ),
    )
    with harness.store.transaction() as tx:
        audit_before = tx.list_audit(manifest_id=harness.manifest.manifest_id)

    with pytest.raises(
        PersistenceConflictError,
        match="requires a persisted approved decision",
    ), harness.store.transaction() as tx:
        harness.lifecycle.replace_draft_in_transaction(
            tx,
            actor=HUMAN,
            draft_id=harness.draft_id,
            command=command,
            occurred_at=harness.clock.now(),
            cohort_decision_id=fabricated_decision_id,
        )

    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == harness.draft_revision
    assert draft.manifest == harness.manifest
    with harness.store.transaction() as tx:
        assert tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        ) == audit_before
        assert tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        ) == []
        assert tx.get_receipt(
            HUMAN.actor_id,
            "fabricated-cohort-authority",
        ) is None


def test_reject_survives_proposal_cache_regeneration_at_a_later_time() -> None:
    harness = _build_harness()
    original_batch = _load(harness)
    proposal_id = _proposal(original_batch)["proposalId"]
    reject_body = _decision_body(
        harness,
        original_batch,
        decision="reject",
        proposal_ids=[proposal_id],
        rationale="Reject this proposal across deterministic cache regeneration.",
    )
    rejected = _post_decision(
        harness,
        reject_body,
        "wc-034-reject-before-cache-regeneration",
    )
    assert rejected.status_code == 201, rejected.text

    harness.clock.value += timedelta(seconds=1)
    _replace_only_proposal_cache(harness)
    regenerated_batch = _load(harness)

    assert regenerated_batch["evaluatedAt"] != original_batch["evaluatedAt"]
    assert regenerated_batch["inputDigest"] != original_batch["inputDigest"]
    assert regenerated_batch["proposalSetDigest"] == (
        original_batch["proposalSetDigest"]
    )
    assert [
        proposal["proposalId"] for proposal in regenerated_batch["proposals"]
    ] == [
        proposal["proposalId"] for proposal in original_batch["proposals"]
    ]

    replay = _post_decision(
        harness,
        reject_body,
        "wc-034-reject-before-cache-regeneration",
    )
    blocked = _post_decision(
        harness,
        _decision_body(
            harness,
            regenerated_batch,
            proposal_ids=[proposal_id],
        ),
        "wc-034-apply-after-cache-regeneration",
    )

    assert replay.status_code == 201
    assert replay.json() == rejected.json()
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "cohort_proposal_set_rejected"
    assert harness.lifecycle.get_draft(HUMAN, harness.draft_id).revision == 1
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert len(decisions) == 1
    assert decisions[0].batch_input_digest == original_batch["inputDigest"]


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
    assert first.json()["proposalIds"] == sorted(first_selection)
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
        decision.source_proposal_ids == sorted(decision.source_proposal_ids)
        and decision.audit.source_proposal_ids
        == decision.source_proposal_ids
        and decision.proposal_set_version().source_proposal_ids
        == decision.source_proposal_ids
        for decision in decisions
    )


def test_four_proposal_batch_rebases_disjoint_applies_and_preserves_both() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposals = batch["proposals"]
    assert len(proposals) == 4
    first_body = _decision_body(
        harness,
        batch,
        proposal_ids=[proposals[0]["proposalId"]],
        rationale="Apply the first disjoint synthetic selector.",
    )
    second_body = _decision_body(
        harness,
        batch,
        proposal_ids=[proposals[1]["proposalId"]],
        rationale="Apply the second disjoint synthetic selector.",
    )

    first = _post_decision(
        harness,
        first_body,
        "wc-034-four-apply-first",
    )
    second = _post_decision(
        harness,
        second_body,
        "wc-034-four-apply-second",
    )
    replay_after_rebase = _post_decision(
        harness,
        first_body,
        "wc-034-four-apply-first",
    )

    assert first.status_code == second.status_code == 201
    assert replay_after_rebase.status_code == 201
    assert replay_after_rebase.json() == first.json()
    assert first.json()["sourceDraft"] == second.json()["sourceDraft"]
    assert first.json()["draftResult"]["revision"] == 2
    assert second.json()["draftResult"]["revision"] == 3

    draft = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert draft.revision == 3
    profile = resolve_manifest_profile(
        draft.manifest,
        "production",
        as_of=harness.clock.now(),
    )
    roles = {role.role_id: role for role in profile.roles}
    for proposal, body in (
        (proposals[0], first_body),
        (proposals[1], second_body),
    ):
        assert [
            selector.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for selector in roles[proposal["role"]["roleId"]].selectors
        ] == body["candidate"]["roleUpdates"][0]["role"]["selectors"]

    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert {
        decision.source_proposal_ids[0]: decision.applied_draft.revision
        for decision in decisions
        if decision.applied_draft is not None
    } == {
        proposals[0]["proposalId"]: 2,
        proposals[1]["proposalId"]: 3,
    }


def test_apply_then_new_key_overlap_conflicts_before_draft_freshness() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal_id = batch["proposals"][0]["proposalId"]
    body = _decision_body(
        harness,
        batch,
        proposal_ids=[proposal_id],
        rationale="Apply one exact synthetic proposal once.",
    )

    first = _post_decision(harness, body, "wc-034-apply-overlap-first")
    overlap = _post_decision(
        harness,
        body,
        "wc-034-apply-overlap-new-key",
    )
    replay = _post_decision(
        harness,
        body,
        "wc-034-apply-overlap-first",
    )

    assert first.status_code == replay.status_code == 201
    assert replay.json() == first.json()
    assert overlap.status_code == 409
    assert overlap.json()["error"]["code"] == "cohort_decision_conflict"
    assert harness.lifecycle.get_draft(HUMAN, harness.draft_id).revision == 2
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert len(decisions) == 1
    assert decisions[0].source_proposal_ids == [proposal_id]


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


def test_split_and_merge_apply_exact_profile_local_selector_replacements() -> None:
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
    } == {"compositeAll"}
    assert all(
        {
            child["selectorType"]
            for child in selector["children"]
        }
        == {"namePredicate", "resourceIdList"}
        for selector in split_preview.json()["roleUpdates"][0]["role"]["selectors"]
    )
    assert {
        selector["selectorId"]
        for selector in split_preview.json()["roleUpdates"][0]["role"]["selectors"]
    }.isdisjoint(
        {
            selector["selectorId"]
            for selector in split_proposal["role"]["selectors"]
        }
    )
    assert split_apply.status_code == 201, split_apply.text
    assert split_apply.json()["action"] == "split"
    assert split_apply.json()["draftResult"]["revision"] == 2
    split_draft = split.lifecycle.get_draft(HUMAN, split.draft_id)
    assert split_draft.revision == 2
    assert split_draft.manifest.roles == split.manifest.roles
    with pytest.raises(
        AthenaValidationError,
        match="selector identities are immutable",
    ):
        resolve_manifest_profile(
            split_draft.manifest,
            "production",
            as_of=split.clock.now(),
        )
    split_role = next(
        role
        for role in split_draft.manifest.profiles["production"].roles
        if role.role_id == split_proposal["role"]["roleId"]
    )
    assert split_role.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    ) == split_preview.json()["roleUpdates"][0]["role"]
    for profile_id in ("development", "training"):
        assert split_draft.manifest.profiles[profile_id] == (
            split.manifest.profiles[profile_id]
        )

    merge = _build_harness()
    binding = merge.register_profile("production")
    merged_batch = _synthetic_merge_batch(merge, binding)
    merged_wire = merged_batch.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    proposal_ids = list(
        reversed(
            [
                proposal["proposalId"]
                for proposal in merged_wire["proposals"]
            ]
        )
    )
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
    canonical_merge_preview = merge.client.post(
        "/v1/cohort-proposals/preview",
        json={
            **merge_preview_body,
            "proposal_ids": sorted(proposal_ids),
        },
        headers=_headers(idempotency_key="wc-034-merge-preview-canonical"),
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
    assert merge_preview.status_code == canonical_merge_preview.status_code == 200
    assert merge_preview.json() == canonical_merge_preview.json()
    assert merge_preview.json()["sourceProposalIds"] == sorted(proposal_ids)
    assert {
        selector["selectorType"]
        for selector in merge_preview.json()["roleUpdates"][0]["role"]["selectors"]
    } == {"compositeAll"}
    assert all(
        {
            child["selectorType"]
            for child in selector["children"]
        }
        == {"namePredicate", "resourceIdList"}
        for selector in merge_preview.json()["roleUpdates"][0]["role"]["selectors"]
    )
    assert {
        selector["selectorId"]
        for selector in merge_preview.json()["roleUpdates"][0]["role"]["selectors"]
    }.isdisjoint(
        {
            selector["selectorId"]
            for selector in merged_wire["proposals"][0]["role"]["selectors"]
        }
    )
    assert merge_apply.status_code == 201, merge_apply.text
    assert merge_apply.json()["action"] == "merge"
    assert merge_apply.json()["proposalIds"] == sorted(proposal_ids)
    assert merge_apply.json()["draftResult"]["revision"] == 2
    merge_draft = merge.lifecycle.get_draft(HUMAN, merge.draft_id)
    assert merge_draft.revision == 2
    assert merge_draft.manifest.roles == merge.manifest.roles
    with pytest.raises(
        AthenaValidationError,
        match="selector identities are immutable",
    ):
        resolve_manifest_profile(
            merge_draft.manifest,
            "production",
            as_of=merge.clock.now(),
        )
    merge_role = next(
        role
        for role in merge_draft.manifest.profiles["production"].roles
        if role.role_id == merged_wire["proposals"][0]["role"]["roleId"]
    )
    assert merge_role.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    ) == merge_preview.json()["roleUpdates"][0]["role"]
    with split.store.transaction() as tx:
        assert len(tx.list_cohort_decisions(
            manifest_id=split.manifest.manifest_id
        )) == 1
    with merge.store.transaction() as tx:
        assert len(tx.list_cohort_decisions(
            manifest_id=merge.manifest.manifest_id
        )) == 1


def test_persisted_split_authority_survives_validate_and_submit_rechecks() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-lifecycle-split-preview"),
    )
    applied = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="split",
            proposal_ids=[proposal["proposalId"]],
            candidate=preview.json(),
            rationale=preview_body["resolution"],
        ),
        "wc-034-lifecycle-split-apply",
    )
    assert preview.status_code == 200, preview.text
    assert applied.status_code == 201, applied.text
    draft_result = applied.json()["draftResult"]
    validate_command = TransitionCommand(
        expected_revision=draft_result["revision"],
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=draft_result["manifestDigest"],
        reason="Validate exact selectors authorized by the persisted decision",
    )
    validated = harness.client.post(
        f"/v1/drafts/{harness.draft_id}/validate",
        json=validate_command.model_dump(mode="json"),
        headers=_headers(idempotency_key="wc-034-lifecycle-validate"),
    )
    assert validated.status_code == 200, validated.text
    submit_command = TransitionCommand(
        expected_revision=validated.json()["revision"],
        expected_manifest_version=harness.manifest.manifest_version,
        expected_digest=validated.json()["manifest_digest"],
        reason="Submit exact persisted decision selectors for normal review",
    )
    submitted = harness.client.post(
        f"/v1/drafts/{harness.draft_id}/submit",
        json=submit_command.model_dump(mode="json"),
        headers=_headers(idempotency_key="wc-034-lifecycle-submit"),
    )

    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["state"] == "in_review"
    assert submitted.json()["revision"] == draft_result["revision"] + 2
    with harness.store.transaction() as tx:
        decisions = tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        )
    assert len(decisions) == 1
    assert decisions[0].apply_authorization is not None
    assert decisions[0].apply_authorization.status == "approved"


def test_display_name_only_put_after_approved_split_preserves_selectors() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposal = _proposal(batch, require_multiple_members=True)
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[proposal["proposalId"]],
    )
    preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(idempotency_key="wc-034-approved-edit-preview"),
    )
    applied = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="split",
            proposal_ids=[proposal["proposalId"]],
            candidate=preview.json(),
            rationale=preview_body["resolution"],
        ),
        "wc-034-approved-edit-apply",
    )
    assert preview.status_code == 200, preview.text
    assert applied.status_code == 201, applied.text
    current = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    payload = current.manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload["workload"]["displayName"] += " reviewed"
    replacement = CanonicalWorkloadManifest.model_validate(
        canonicalize_manifest_payload(payload)
    )

    replaced = harness.client.put(
        f"/v1/drafts/{harness.draft_id}",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-approved-non-selector-edit",
        ),
        json=ReplaceDraftCommand(
            expected_revision=current.revision,
            expected_manifest_version=current.manifest.manifest_version,
            expected_digest=current.manifest_digest,
            replacement_manifest=replacement,
            replacement_digest=replacement.compatibility.artifact_digest,
            reason="Apply a legal non-selector edit after cohort approval",
        ).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    )
    assert replaced.status_code == 200, replaced.text
    updated = harness.lifecycle.get_draft(HUMAN, harness.draft_id)
    assert updated.manifest.workload.display_name == (
        replacement.workload.display_name
    )
    assert manifest_selector_provenance(updated.manifest) == (
        manifest_selector_provenance(current.manifest)
    )

    validated = harness.client.post(
        f"/v1/drafts/{harness.draft_id}/validate",
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-approved-edit-validate",
        ),
        json=TransitionCommand(
            expected_revision=updated.revision,
            expected_manifest_version=updated.manifest.manifest_version,
            expected_digest=updated.manifest_digest,
            reason="Validate preserved approved selector provenance",
        ).model_dump(mode="json"),
    )
    assert validated.status_code == 200, validated.text


def test_preview_candidates_are_actor_bound_for_two_authorized_reviewers() -> None:
    harness = _build_harness()
    batch = _load(harness)
    proposals = [
        proposal
        for proposal in batch["proposals"]
        if len(proposal["members"]) >= 2
    ]
    assert len(proposals) >= 2
    first_proposal, second_proposal = proposals[:2]
    preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[first_proposal["proposalId"]],
    )
    second_own_preview_body = _preview_body(
        harness,
        batch,
        proposal_ids=[second_proposal["proposalId"]],
    )

    first_preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(
            HUMAN,
            idempotency_key="wc-034-first-reviewer-preview",
        ),
    )
    second_preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=preview_body,
        headers=_headers(
            SECOND_REVIEWER,
            idempotency_key="wc-034-second-reviewer-preview",
        ),
    )
    second_own_preview = harness.client.post(
        "/v1/cohort-proposals/preview",
        json=second_own_preview_body,
        headers=_headers(
            SECOND_REVIEWER,
            idempotency_key="wc-034-second-reviewer-own-preview",
        ),
    )

    assert (
        first_preview.status_code
        == second_preview.status_code
        == second_own_preview.status_code
        == 200
    )
    assert first_preview.json()["candidateId"] != (
        second_preview.json()["candidateId"]
    )
    assert first_preview.json()["sourceProposalIds"] == (
        second_preview.json()["sourceProposalIds"]
    )

    cross_actor = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="split",
            proposal_ids=[first_proposal["proposalId"]],
            candidate=first_preview.json(),
            rationale=preview_body["resolution"],
        ),
        "wc-034-cross-reviewer-candidate",
        actor=SECOND_REVIEWER,
    )
    first_own_candidate = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="split",
            proposal_ids=[first_proposal["proposalId"]],
            candidate=first_preview.json(),
            rationale=preview_body["resolution"],
        ),
        "wc-034-first-reviewer-own-candidate",
        actor=HUMAN,
    )
    second_own_candidate = _post_decision(
        harness,
        _decision_body(
            harness,
            batch,
            decision="split",
            proposal_ids=[second_proposal["proposalId"]],
            candidate=second_own_preview.json(),
            rationale=second_own_preview_body["resolution"],
        ),
        "wc-034-second-reviewer-own-candidate",
        actor=SECOND_REVIEWER,
    )

    assert cross_actor.status_code == 409
    assert cross_actor.json()["error"]["code"] == "cohort_contract_invalid"
    assert first_own_candidate.status_code == 201, first_own_candidate.text
    assert second_own_candidate.status_code == 201, second_own_candidate.text
    assert first_own_candidate.json()["candidateId"] == (
        first_preview.json()["candidateId"]
    )
    assert second_own_candidate.json()["candidateId"] == (
        second_own_preview.json()["candidateId"]
    )
    assert first_own_candidate.json()["decidedBy"] == HUMAN.actor_id
    assert second_own_candidate.json()["decidedBy"] == SECOND_REVIEWER.actor_id
    assert first_own_candidate.json()["draftResult"]["revision"] == 2
    assert second_own_candidate.json()["draftResult"]["revision"] == 3


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

    def put_cohort_decision_receipt(self, receipt) -> None:
        del receipt
        raise PersistenceConflictError(
            "synthetic receipt persistence failure after decision and draft"
        )


class _FailAfterDraftStore:
    def __init__(self, store) -> None:
        self._store = store

    def transaction(self) -> _FailAfterDraftTransaction:
        return _FailAfterDraftTransaction(self._store.transaction())


class _AdvanceClockTransaction:
    def __init__(
        self,
        inner,
        *,
        harness: Harness,
        advance: bool,
    ) -> None:
        self._manager = inner
        self._transaction = None
        self._harness = harness
        self._advance = advance

    def __enter__(self):
        self._transaction = self._manager.__enter__()
        if self._advance:
            self._harness.clock.value = (
                self._harness.snapshot.expires_at
                + timedelta(seconds=1)
            )
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


class _AdvanceClockOnFinalDecisionStore:
    def __init__(self, harness: Harness) -> None:
        self._harness = harness
        self._transactions = 0

    @property
    def transactions(self) -> int:
        return self._transactions

    def transaction(self) -> _AdvanceClockTransaction:
        self._transactions += 1
        return _AdvanceClockTransaction(
            self._harness.store.transaction(),
            harness=self._harness,
            advance=self._transactions == 3,
        )


def test_snapshot_expiry_crossing_at_final_transaction_rolls_back() -> None:
    harness = _build_harness()
    batch = _load(harness)
    body = _decision_body(
        harness,
        batch,
        rationale="Reject commit after the exact snapshot expiry boundary.",
    )
    harness.clock.value = (
        harness.snapshot.expires_at - timedelta(seconds=1)
    )
    store = _AdvanceClockOnFinalDecisionStore(harness)
    decisions = CohortDecisionService(
        store=store,
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
            cohort_decision_service=decisions,
        )
    )
    with harness.store.transaction() as tx:
        audit_before = tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        )

    response = client.post(
        "/v1/cohort-proposals/decisions",
        json=body,
        headers=_headers(
            idempotency_key="wc-034-expiry-at-final-transaction",
        ),
    )

    assert store.transactions == 3
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "stale_evidence_snapshot"
    assert harness.lifecycle.get_draft(
        HUMAN,
        harness.draft_id,
    ).revision == harness.draft_revision
    with harness.store.transaction() as tx:
        assert tx.list_cohort_decisions(
            manifest_id=harness.manifest.manifest_id
        ) == []
        assert tx.list_audit(
            manifest_id=harness.manifest.manifest_id
        ) == audit_before
        assert tx.get_cohort_decision_receipt(
            HUMAN.actor_id,
            "wc-034-expiry-at-final-transaction",
        ) is None


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
