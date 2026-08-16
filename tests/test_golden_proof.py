from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import Any

import pytest

import athena_context.golden_proof as golden
from athena_context import run_golden_proof as run_root_golden_proof
from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceContextVerifier,
    EvidenceReferenceContext,
    ResolvedManifestProfile,
    ResourceProofFact,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    resolve_manifest_profile,
)
from athena_context.fixtures import (
    FixtureBundle,
    load_canonical_manifest_resource,
    load_canonical_snapshot_resource,
    make_canonical_fixture_from_resources,
    make_tampered_fixture,
)
from athena_context.policy import evaluate_manifest_profile

EXPECTED_MANIFEST_DIGEST = "sha256:48ce3405aa547ae6df3180223b0a99bc5fa70a848d3a7be48f507ab0ffadc9f8"
EXPECTED_SNAPSHOT_DIGEST = "sha256:2a8a6a0e946d01944a1e262d1448bda53ddbd3e06a77a788ab791d99f35dda79"
EXPECTED_SNAPSHOT_REFERENCE_SET_DIGEST = (
    "sha256:1b19ac486a4d26a8594a035ffa619589301d1cf048be2cb0c5f053908767e953"
)
EXPECTED_PROOF_DIGEST = "sha256:8b542d40a4a1666c9eed6b345e31c0dc5dd1a46a1637ba3eaa66df0473d6104e"
EXPECTED_BY_PROFILE = {
    "production": {
        "db-singleton-supported": "expectedConstraint",
        "db-zone-loss-spof": "acceptedResidualRisk",
        "db-zone-loss-acceptance": "acceptedResidualRisk",
        "worker-db-zone-colocation": "pass",
        "web-zone-distribution": "pass",
    },
    "development": {
        "db-singleton-supported": "expectedConstraint",
        "db-zone-loss-spof": "observation",
        "db-zone-loss-acceptance": "observation",
        "worker-db-zone-colocation": "pass",
        "web-zone-distribution": "pass",
    },
    "training": {
        "db-singleton-supported": "expectedConstraint",
        "db-zone-loss-spof": "acceptedResidualRisk",
        "db-zone-loss-acceptance": "acceptedResidualRisk",
        "worker-db-zone-colocation": "pass",
        "web-zone-distribution": "violation",
    },
}


def _fixture_with_manifest(
    mutate: Callable[[dict[str, Any]], None],
) -> FixtureBundle:
    bundle = make_canonical_fixture_from_resources()
    payload = deepcopy(load_canonical_manifest_resource())
    mutate(payload)
    manifest = CanonicalWorkloadManifest.model_validate(canonicalize_manifest_payload(payload))
    return replace(
        bundle,
        canonical_manifest=manifest,
        manifest_digest=manifest.compatibility.artifact_digest,
    )


def _verified_production_boundary() -> tuple[
    FixtureBundle,
    ResolvedManifestProfile,
    EvidenceReferenceContext,
    EvidenceContextVerifier,
]:
    bundle = make_canonical_fixture_from_resources()
    profile = resolve_manifest_profile(
        bundle.canonical_manifest,
        "production",
        as_of=golden.GOLDEN_PROOF_AS_OF,
    )
    evidence = golden._build_evidence_context(profile, bundle.canonical_snapshot)
    verifier = golden._make_context_verifier(
        bundle,
        profile,
        as_of=golden.GOLDEN_PROOF_AS_OF,
    )
    return bundle, profile, evidence, verifier


def test_public_runner_emits_exact_immutable_release_evidence() -> None:
    packaged_before = load_canonical_snapshot_resource()
    result = golden.run_golden_proof()

    assert run_root_golden_proof is golden.run_golden_proof
    assert result.manifest_artifact_digest == EXPECTED_MANIFEST_DIGEST
    assert result.snapshot_artifact_digest == EXPECTED_SNAPSHOT_DIGEST
    assert result.snapshot_semantic_digest == EXPECTED_SNAPSHOT_DIGEST
    assert result.snapshot_evidence_reference_set_digest == EXPECTED_SNAPSHOT_REFERENCE_SET_DIGEST
    assert result.proof_digest == EXPECTED_PROOF_DIGEST
    assert tuple(profile.profile_id for profile in result.profiles) == golden.GOLDEN_PROFILE_IDS
    assert {
        profile.profile_id: dict(profile.verdicts) for profile in result.profiles
    } == EXPECTED_BY_PROFILE
    assert load_canonical_snapshot_resource() == packaged_before

    payload = result.to_payload()
    digest_payload = {key: value for key, value in payload.items() if key != "proofDigest"}
    assert compute_artifact_digest(digest_payload) == result.proof_digest
    assert json.loads(result.canonical_json()) == payload
    with pytest.raises(FrozenInstanceError):
        result.snapshot_id = "snap-mutated"  # type: ignore[misc]


def test_every_profile_reuses_identical_snapshot_and_finding_evidence_refs() -> None:
    result = golden.run_golden_proof()
    first = result.profiles[0]

    for profile in result.profiles:
        assert profile.snapshot_artifact_digest == result.snapshot_artifact_digest
        assert profile.snapshot_semantic_digest == result.snapshot_semantic_digest
        assert profile.evidence_refs == first.evidence_refs
        assert len(profile.evidence_refs) == 7
        for reference_text in profile.evidence_refs:
            reference = json.loads(reference_text)
            assert reference["snapshotId"] == result.snapshot_id
            assert reference["snapshotArtifactDigest"] == result.snapshot_artifact_digest
            assert reference["snapshotSemanticDigest"] == result.snapshot_semantic_digest

    for finding_index in range(len(first.findings)):
        expected_refs = json.loads(first.findings[finding_index])["evidenceRefs"]
        for profile in result.profiles[1:]:
            assert json.loads(profile.findings[finding_index])["evidenceRefs"] == expected_refs


def test_golden_artifact_is_byte_deterministic() -> None:
    first = golden.run_golden_proof()
    second = golden.run_golden_proof()

    assert first.canonical_json() == second.canonical_json()
    assert first.proof_digest == second.proof_digest


def test_removing_required_constraint_fails_closed() -> None:
    def remove_constraint(payload: dict[str, Any]) -> None:
        payload["constraints"] = [
            item
            for item in payload["constraints"]
            if item["constraintId"] != "worker-db-zone-colocation"
        ]
        for profile in payload["profiles"].values():
            profile["constraints"] = [
                item
                for item in profile["constraints"]
                if item["constraintId"] != "worker-db-zone-colocation"
            ]

    fixture = _fixture_with_manifest(remove_constraint)
    with pytest.raises(
        AthenaValidationError,
        match="unresolved relationship sourceClause|missing mandatory protected",
    ):
        golden.run_golden_proof(fixture=fixture)


def test_expired_risk_acceptance_cannot_match_the_oracle() -> None:
    def expire_acceptances(payload: dict[str, Any]) -> None:
        for profile in payload["profiles"].values():
            for acceptance in profile["riskAcceptances"]:
                acceptance["expiresAt"] = "2025-05-31T00:00:00.000Z"

    fixture = _fixture_with_manifest(expire_acceptances)
    with pytest.raises(
        AthenaValidationError,
        match="active|golden oracle",
    ):
        golden.run_golden_proof(fixture=fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "move-worker-zone",
        "collapse-web-zones",
        "omit-zone-evidence",
        "add-conflicting-evidence",
        "ambiguous-role-binding",
        "incomplete-role-binding",
        "stale-reference",
    ],
)
def test_verified_snapshot_and_role_binding_boundary_rejects_negative_contexts(
    mutation: str,
) -> None:
    _, profile, evidence, verifier = _verified_production_boundary()
    if mutation == "move-worker-zone":
        worker = next(item for item in evidence.resources if item.role_ref == "worker")
        worker.availability_zone = "2"
    elif mutation == "collapse-web-zones":
        for resource in evidence.resources:
            if resource.role_ref == "web":
                resource.availability_zone = "1"
    elif mutation == "omit-zone-evidence":
        web = next(item for item in evidence.resources if item.role_ref == "web")
        web.availability_zone = "unknown"
    elif mutation == "add-conflicting-evidence":
        web = next(item for item in evidence.resources if item.role_ref == "web")
        evidence.resources.append(
            ResourceProofFact(
                resourceId=web.resource_id + "-conflict",
                roleRef="web",
                availabilityZone="2",
                state="conflicting",
                proofSource="observed",
                evidenceRef=web.evidence_ref,
            )
        )
    elif mutation == "ambiguous-role-binding":
        database_id = next(
            item.resource_id for item in evidence.resources if item.role_ref == "database-primary"
        )
        worker_binding = next(item for item in evidence.role_bindings if item.role_ref == "worker")
        worker_binding.selected_resource_ids.append(database_id)
        worker_binding.selected_resource_ids.sort(key=str.casefold)
        worker_binding.selector_result_digest = compute_artifact_digest(
            worker_binding.selected_resource_ids
        )
    elif mutation == "incomplete-role-binding":
        worker_binding = next(item for item in evidence.role_bindings if item.role_ref == "worker")
        worker_binding.state = "missing"
    else:
        evidence.resources[0].evidence_ref.snapshot_semantic_digest = "sha256:" + "9" * 64

    with pytest.raises(AthenaValidationError):
        evaluate_manifest_profile(
            profile,
            evidence,
            as_of=golden.GOLDEN_PROOF_AS_OF,
            verify_evidence_context=verifier,
        )


def test_mutated_and_stale_snapshots_fail_closed() -> None:
    with pytest.raises(AthenaValidationError):
        golden.run_golden_proof(fixture=make_tampered_fixture(kind="resource-zone"))

    with pytest.raises(AthenaValidationError, match="fresh|expired|stale"):
        golden.run_golden_proof(
            as_of=datetime(2025, 6, 3, tzinfo=UTC),
        )
