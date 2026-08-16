from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import pytest

import athena_context.fixtures as fixture_factory
import athena_context.golden as golden
from athena_context import run_golden_proof as run_root_golden_proof
from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceContextVerifier,
    EvidenceReferenceContext,
    EvidenceSnapshot,
    ResolvedManifestProfile,
    ResourceProofFact,
    SnapshotPublicationRecord,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    compute_response_envelope_digest,
    resolve_manifest_profile,
)
from athena_context.fixtures import (
    FixtureBundle,
    load_canonical_fixture_resource,
    load_canonical_manifest_resource,
    load_canonical_snapshot_resource,
    make_canonical_fixture_from_resources,
    make_tampered_fixture,
)
from athena_context.policy import evaluate_manifest_profile

EXPECTED_WC002_MANIFEST_DIGEST = (
    "sha256:b6623ba1d2102223b27597f9ae64c1a83769fa4665fb86d9580492ff0bc25ab6"
)
EXPECTED_WC002_MANIFEST_SEMANTIC_DIGEST = (
    "sha256:4cb99758a49d39da2191ddaa583cd00b43c504d1cf0dad3b636fcda9468e7ec0"
)
EXPECTED_GOLDEN_MANIFEST_DIGEST = (
    "sha256:8caf0c329053f4032a5c9d620cd135315fe4d96af03c06e96f0578be2780bb19"
)
EXPECTED_GOLDEN_MANIFEST_SEMANTIC_DIGEST = (
    "sha256:b4bfd3debffe8fd150312f32ff54a7e0a25b2ffe3772d10dc9131b749a674796"
)
EXPECTED_SNAPSHOT_DIGEST = "sha256:eebe798248175c34217cda5d602ee7c6341aa312a1305c9879291b45345dfad2"
EXPECTED_SNAPSHOT_REFERENCE_SET_DIGEST = (
    "sha256:ce17a211904ff0dd4bbe6359e74c427799227b2d99ff1fcb2a27f2c598b6dc9c"
)
EXPECTED_PROOF_DIGEST = "sha256:b59ff0414e1bb1f6add7a22a0c6e7807e13fc89094ed4cbe11754bcbfa7c7174"
EXPECTED_OBSERVED_BY_PROFILE = {
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
        "web-zone-distribution": "pass",
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


def _golden_manifest_with(
    mutate: Callable[[dict[str, Any]], None],
) -> CanonicalWorkloadManifest:
    payload = golden.load_golden_manifest().model_dump(
        mode="json",
        by_alias=True,
        exclude_none=False,
        exclude_unset=True,
    )
    mutate(payload)
    return CanonicalWorkloadManifest.model_validate(canonicalize_manifest_payload(payload))


def _verified_production_boundary() -> tuple[
    FixtureBundle,
    ResolvedManifestProfile,
    EvidenceReferenceContext,
    EvidenceContextVerifier,
]:
    bundle = make_canonical_fixture_from_resources()
    profile = resolve_manifest_profile(
        golden.load_golden_manifest(),
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


def _collapsed_web_snapshot_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> FixtureBundle:
    bundle = make_canonical_fixture_from_resources()
    collapsed_envelope = fixture_factory._build_response_envelope()
    for item in collapsed_envelope["items"]:
        if "athena-web-" in item.get("resourceId", ""):
            item["availabilityZone"] = "1"
    response_digest = compute_response_envelope_digest(collapsed_envelope)
    original_attempt = bundle.canonical_snapshot.collector_attempts[0]
    attempt_payload = original_attempt.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    attempt_payload["responseDigest"] = response_digest
    attempt_payload.pop("attemptDigest")
    attempt_digest = compute_artifact_digest(attempt_payload)

    record_materials: list[dict[str, Any]] = []
    for record in bundle.canonical_snapshot.evidence_records:
        material = record.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
        )
        material.pop("itemDigest")
        material["collectorAttemptDigest"] = attempt_digest
        material["provenance"]["sourceResponseDigest"] = response_digest
        if "athena-web-" in material.get("resourceId", ""):
            material["availabilityZone"] = "1"
        record_materials.append(material)

    monkeypatch.setattr(
        fixture_factory,
        "_build_response_envelope",
        lambda: deepcopy(collapsed_envelope),
    )
    snapshot = EvidenceSnapshot.model_validate(
        fixture_factory._canonical_snapshot_payload(record_materials=record_materials)
    )
    publication = SnapshotPublicationRecord(
        snapshot_id=snapshot.snapshot_id,
        artifact_digest=snapshot.compatibility.artifact_digest,
        semantic_digest=snapshot.compatibility.semantic_digest,
        schema_version=snapshot.compatibility.schema_version,
        semantic_contract_version=snapshot.compatibility.semantic_contract_version,
        published_at=snapshot.snapshot_attestation.attested_at + timedelta(seconds=1),
    )

    def publication_resolver(snapshot_id: str) -> SnapshotPublicationRecord | None:
        return publication if snapshot_id == publication.snapshot_id else None

    def envelope_resolver(
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> dict[str, Any] | None:
        if (
            attempt_id == snapshot.collector_attempts[0].attempt_id
            and kind == "response"
            and digest == response_digest
        ):
            return deepcopy(collapsed_envelope)
        return None

    return replace(
        bundle,
        canonical_snapshot=snapshot,
        publication_record=publication,
        publication_resolver=publication_resolver,
        envelope_resolver=envelope_resolver,
        snapshot_artifact_digest=snapshot.compatibility.artifact_digest,
        snapshot_semantic_digest=snapshot.compatibility.semantic_digest,
    )


def test_public_runner_emits_exact_immutable_release_evidence() -> None:
    manifest_before = load_canonical_manifest_resource()
    packaged_before = load_canonical_snapshot_resource()
    combined_before = load_canonical_fixture_resource()
    result = golden.run_golden_proof()
    source_manifest = make_canonical_fixture_from_resources().canonical_manifest

    assert run_root_golden_proof is golden.run_golden_proof
    assert result.manifest_id == golden.WC002_MANIFEST_ID
    assert result.manifest_version == golden.GOLDEN_MANIFEST_VERSION
    assert result.manifest_artifact_digest == EXPECTED_GOLDEN_MANIFEST_DIGEST
    assert result.manifest_semantic_digest == EXPECTED_GOLDEN_MANIFEST_SEMANTIC_DIGEST
    assert source_manifest.compatibility.artifact_digest == EXPECTED_WC002_MANIFEST_DIGEST
    assert source_manifest.compatibility.semantic_digest == EXPECTED_WC002_MANIFEST_SEMANTIC_DIGEST
    assert result.snapshot_id == golden.WC002_SNAPSHOT_ID
    assert result.snapshot_artifact_digest == EXPECTED_SNAPSHOT_DIGEST
    assert result.snapshot_semantic_digest == EXPECTED_SNAPSHOT_DIGEST
    assert result.snapshot_evidence_reference_set_digest == EXPECTED_SNAPSHOT_REFERENCE_SET_DIGEST
    assert result.proof_digest == EXPECTED_PROOF_DIGEST
    assert result.oracle_status == "complete"
    assert result.pending_decisions == ()
    assert golden.GOLDEN_VERDICT_MATRIX[-1] == (
        "web-zone-distribution",
        ("pass", "pass", "pass"),
    )
    assert tuple(profile.profile_id for profile in result.profiles) == golden.GOLDEN_PROFILE_IDS
    assert {
        profile.profile_id: dict(profile.verdicts) for profile in result.profiles
    } == EXPECTED_OBSERVED_BY_PROFILE
    assert load_canonical_manifest_resource() == manifest_before
    assert load_canonical_snapshot_resource() == packaged_before
    assert load_canonical_fixture_resource() == combined_before

    payload = result.to_payload()
    digest_payload = {key: value for key, value in payload.items() if key != "proofDigest"}
    assert compute_artifact_digest(digest_payload) == result.proof_digest
    assert json.loads(result.canonical_json()) == payload
    rendered = result.render_text()
    assert f"Proof digest: `{result.proof_digest}`" in rendered
    assert "| web-zone-distribution | pass | pass | pass |" in rendered
    with pytest.raises(FrozenInstanceError):
        result.snapshot_id = "snap-mutated"  # type: ignore[misc]


def test_versioned_golden_manifest_is_exact_approved_wc002_derivation() -> None:
    manifest = golden.load_golden_manifest()
    source = make_canonical_fixture_from_resources().canonical_manifest

    assert manifest.manifest_id == source.manifest_id
    assert manifest.manifest_version == "1.1.0"
    assert manifest.workload == source.workload
    assert manifest.audit.model_dump(mode="json", by_alias=True) == {
        "publishedBy": "human-approved-context-api",
        "publishedAt": "2025-06-01T00:05:00Z",
        "approvalStatus": "approved",
    }
    assert manifest.compatibility.artifact_digest == EXPECTED_GOLDEN_MANIFEST_DIGEST
    assert manifest.compatibility.semantic_digest == EXPECTED_GOLDEN_MANIFEST_SEMANTIC_DIGEST
    assert manifest.canonical_json() == golden._derive_golden_manifest(source).canonical_json()

    for profile_id, expected_minimum in golden.GOLDEN_WEB_MINIMUM_DISTINCT_ZONES:
        profile = resolve_manifest_profile(
            manifest,
            profile_id,
            as_of=golden.GOLDEN_PROOF_AS_OF,
        )
        constraint = next(
            item for item in profile.constraints if item.constraint_id == "web-zone-distribution"
        )
        assert constraint.proof_requirement.minimum_distinct_zones == expected_minimum
        assert golden.golden_web_minimum_distinct_zones(profile_id) == expected_minimum

    assert "disasterRecovery" not in manifest.profiles
    assert golden.golden_web_minimum_distinct_zones("disasterRecovery") == 2
    assert golden.GOLDEN_DISASTER_RECOVERY_WEB_MINIMUM_DISTINCT_ZONES == 2
    assert [
        override.override_id for override in manifest.profiles["training"].weakening_overrides
    ] == ["training-web-zones"]


def test_one_zone_web_topology_violates_only_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _collapsed_web_snapshot_fixture(monkeypatch)
    manifest = golden.load_golden_manifest()
    observed: dict[str, str] = {}

    for profile_id in golden.GOLDEN_PROFILE_IDS:
        profile = resolve_manifest_profile(
            manifest,
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
        observed[profile_id] = findings["web-zone-distribution"].verdict

    assert observed == {
        "production": "violation",
        "development": "pass",
        "training": "pass",
    }


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


def test_full_finding_projection_is_exact_for_every_profile() -> None:
    result = golden.run_golden_proof()
    expected_kinds = {
        "db-singleton-supported": "technologyConstraint",
        "db-zone-loss-spof": "actualSpof",
        "db-zone-loss-acceptance": "riskAcceptance",
        "worker-db-zone-colocation": "architectureConstraint",
        "web-zone-distribution": "architectureConstraint",
    }
    expected_pointers = {
        "db-singleton-supported": ["/items/0"],
        "db-zone-loss-spof": ["/items/0"],
        "db-zone-loss-acceptance": ["/items/0"],
        "worker-db-zone-colocation": ["/items/1", "/items/0", "/items/2"],
        "web-zone-distribution": ["/items/5", "/items/3", "/items/4"],
    }
    expected_acceptances = {
        "production": "ra-db-zone-loss-production",
        "development": None,
        "training": "ra-db-zone-loss-training",
    }

    for profile in result.profiles:
        for finding_text in profile.findings:
            finding = json.loads(finding_text)
            clause_id = finding["clauseId"]
            assert finding["findingKind"] == expected_kinds[clause_id]
            assert finding["verdict"] == EXPECTED_OBSERVED_BY_PROFILE[profile.profile_id][clause_id]
            assert finding["manifestId"] == golden.WC002_MANIFEST_ID
            assert finding["manifestVersion"] == golden.GOLDEN_MANIFEST_VERSION
            assert finding["profileId"] == profile.profile_id
            assert finding["resolvedProfileDigest"] == profile.resolved_profile_digest
            assert finding["governanceScope"] == {
                "governanceScopeType": "clause",
                "manifestId": golden.WC002_MANIFEST_ID,
                "profileId": profile.profile_id,
                "clausePath": f"/constraints/{clause_id}",
                "ownerRef": "ops-owner",
            }
            assert [
                reference["sourceResponsePointer"] for reference in finding["evidenceRefs"]
            ] == expected_pointers[clause_id]
            assert all(
                reference["snapshotArtifactDigest"] == EXPECTED_SNAPSHOT_DIGEST
                and reference["snapshotSemanticDigest"] == EXPECTED_SNAPSHOT_DIGEST
                for reference in finding["evidenceRefs"]
            )
            expected_acceptance = (
                expected_acceptances[profile.profile_id]
                if clause_id in {"db-zone-loss-spof", "db-zone-loss-acceptance"}
                else None
            )
            assert finding.get("riskAcceptanceRef") == expected_acceptance


def test_golden_artifact_is_byte_deterministic() -> None:
    first = golden.run_golden_proof()
    second = golden.run_golden_proof()

    assert first.canonical_json() == second.canonical_json()
    assert first.proof_digest == second.proof_digest


def test_internally_consistent_non_wc002_fixture_is_rejected() -> None:
    def mutate_display_name(payload: dict[str, Any]) -> None:
        payload["workload"]["displayName"] = "Synthetic non-approved consistent workload"

    fixture = _fixture_with_manifest(mutate_display_name)
    assert (
        fixture.canonical_manifest.compatibility.artifact_digest
        == fixture.canonical_manifest.compute_artifact_digest_value()
    )
    assert (
        fixture.canonical_manifest.compatibility.semantic_digest
        == fixture.canonical_manifest.compute_semantic_digest_value()
    )
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="approved immutable WC-002",
    ):
        golden.run_golden_proof(fixture=fixture)


def test_renamed_acceptances_are_rejected_even_when_manifest_graph_is_consistent() -> None:
    def rename_acceptances(payload: dict[str, Any]) -> None:
        for profile in payload["profiles"].values():
            old_id = profile["riskAcceptances"][0]["riskAcceptanceId"]
            new_id = old_id + "-renamed"
            profile["riskAcceptances"][0]["riskAcceptanceId"] = new_id
            for constraint in profile["constraints"]:
                if constraint.get("riskAcceptanceRef") == old_id:
                    constraint["riskAcceptanceRef"] = new_id

    manifest = _golden_manifest_with(rename_acceptances)
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="approved WC-005 golden",
    ):
        golden.run_golden_proof(manifest=manifest)


def test_finding_projection_rejects_renamed_acceptance_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authoritative_evaluator = golden.evaluate_manifest_profile

    def renamed_acceptance(*args: Any, **kwargs: Any) -> Any:
        findings = authoritative_evaluator(*args, **kwargs)
        findings["db-zone-loss-spof"].risk_acceptance_ref = "renamed-acceptance"
        return findings

    monkeypatch.setattr(golden, "evaluate_manifest_profile", renamed_acceptance)
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="production/db-zone-loss-spof finding projection",
    ):
        golden.run_golden_proof()


@pytest.mark.parametrize("mutation", ["finding-kind", "scope", "evidence-refs"])
def test_finding_projection_rejects_non_verdict_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    authoritative_evaluator = golden.evaluate_manifest_profile

    def drifted_projection(*args: Any, **kwargs: Any) -> Any:
        findings = authoritative_evaluator(*args, **kwargs)
        finding = findings["db-singleton-supported"]
        if mutation == "finding-kind":
            finding.finding_kind = "architectureConstraint"
        elif mutation == "scope":
            finding.governance_scope.owner_ref = "renamed-owner"
        else:
            finding.evidence_refs = findings["web-zone-distribution"].evidence_refs
        return findings

    monkeypatch.setattr(golden, "evaluate_manifest_profile", drifted_projection)
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="production/db-singleton-supported finding projection",
    ):
        golden.run_golden_proof()


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

    manifest = _golden_manifest_with(remove_constraint)
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="approved WC-005 golden",
    ):
        golden.run_golden_proof(manifest=manifest)


def test_expired_risk_acceptance_cannot_match_the_oracle() -> None:
    def expire_acceptances(payload: dict[str, Any]) -> None:
        for profile in payload["profiles"].values():
            for acceptance in profile["riskAcceptances"]:
                acceptance["expiresAt"] = "2025-05-31T00:00:00.000Z"

    manifest = _golden_manifest_with(expire_acceptances)
    with pytest.raises(
        golden.GoldenProofMismatchError,
        match="approved WC-005 golden",
    ):
        golden.run_golden_proof(manifest=manifest)


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
