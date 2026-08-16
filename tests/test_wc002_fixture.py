from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import pytest

from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceSnapshot,
    compute_evidence_record_set_digest,
    compute_evidence_reference_set_digest,
    compute_response_envelope_digest,
)
from athena_context.contracts.manifest import resolve_manifest_profile
from athena_context.fixtures import (
    _canonical_manifest_payload,
    _resource_id,
    load_canonical_fixture_resource,
    load_canonical_manifest_resource,
    load_canonical_snapshot_resource,
    make_canonical_fixture,
    make_canonical_fixture_from_resources,
    make_conflicting_evidence_fixture,
    make_missing_evidence_fixture,
    make_mutation_fixture,
    make_tampered_fixture,
)


def _as_of() -> datetime:
    return datetime(2025, 6, 1, 12, 0, tzinfo=UTC)


def test_canonical_fixture_real_verification_and_digest_order_stability() -> None:
    bundle = make_canonical_fixture()
    snapshot = bundle.canonical_snapshot
    assert snapshot.compatibility.artifact_digest == bundle.snapshot_artifact_digest
    assert snapshot.compatibility.semantic_digest == bundle.snapshot_semantic_digest

    attempt = snapshot.collector_attempts[0]
    assert attempt.attempt_type == "successResponse"
    envelope = bundle.envelope_resolver(attempt.attempt_id, "response", attempt.response_digest)
    assert envelope is not None
    assert attempt.response_digest == compute_response_envelope_digest(envelope)

    snapshot.validate_for_evaluation(
        as_of=_as_of(),
        expected_artifact_digest=snapshot.compatibility.artifact_digest,
        publication_resolver=bundle.publication_resolver,
        key_resolver=bundle.key_resolver,
        trusted_key_anchor=bundle.trusted_key_anchor,
        envelope_resolver=bundle.envelope_resolver,
        identity_evidence=snapshot.identity_evidence,
    )

    reversed_payload = snapshot.model_dump(mode="json", by_alias=True)
    reversed_payload["evidenceRecords"].reverse()
    reversed_payload["evidenceRefs"].reverse()
    reversed_payload["collectorAttempts"].reverse()
    reversed_payload["identityEvidence"].reverse()
    reversed_snapshot = EvidenceSnapshot.model_validate(reversed_payload)

    assert compute_evidence_record_set_digest(snapshot) == compute_evidence_record_set_digest(
        reversed_snapshot
    )
    assert compute_evidence_reference_set_digest(snapshot) == compute_evidence_reference_set_digest(
        reversed_snapshot
    )


def test_all_profiles_resolve_with_exact_active_governed_overrides() -> None:
    manifest = make_canonical_fixture().canonical_manifest
    for profile_id in ("production", "development", "training"):
        resolved = resolve_manifest_profile(manifest, profile_id, as_of=_as_of())
        assert resolved.profile_id == profile_id
        if profile_id == "development":
            assert resolved.settings.continuity.zone_loss_continuity_required is False
        else:
            assert resolved.settings.continuity.zone_loss_continuity_required is True
        web_constraint = next(
            item
            for item in resolved.constraints
            if item.constraint_id == "web-zone-distribution"
        )
        proof = web_constraint.proof_requirement
        assert proof.proof_kind == "zoneDistributionProof"
        assert proof.minimum_distinct_zones == {
            "production": 2,
            "development": 1,
            "training": 3,
        }[profile_id]


def test_negative_fixture_constructors_are_isolated_and_tampered_objects_fail_later() -> None:
    canonical = make_canonical_fixture()
    original = canonical.canonical_snapshot.model_dump(mode="json", by_alias=True)

    for builder in (
        make_mutation_fixture,
        make_missing_evidence_fixture,
        make_conflicting_evidence_fixture,
    ):
        mutated = builder()
        assert canonical.canonical_snapshot.model_dump(mode="json", by_alias=True) == original
        assert mutated is not canonical
        assert mutated.canonical_snapshot is not canonical.canonical_snapshot

    tampered = make_tampered_fixture(kind="resource-zone")
    assert tampered is not canonical
    assert tampered.canonical_snapshot is not canonical.canonical_snapshot
    with pytest.raises((AthenaValidationError, AssertionError, TypeError, ValueError)):
        tampered.canonical_snapshot.validate_for_evaluation(
            as_of=_as_of(),
            expected_artifact_digest=tampered.canonical_snapshot.compatibility.artifact_digest,
            publication_resolver=tampered.publication_resolver,
            key_resolver=tampered.key_resolver,
            trusted_key_anchor=tampered.trusted_key_anchor,
            envelope_resolver=tampered.envelope_resolver,
            identity_evidence=tampered.canonical_snapshot.identity_evidence,
        )


def test_package_fixture_resources_are_loaded_via_importlib_resources() -> None:
    resource_root = files("athena_context.data.fixtures")
    fixture_data = json.loads(
        resource_root.joinpath("canonical-fixture.json").read_text(encoding="utf-8")
    )
    manifest_data = json.loads(
        resource_root.joinpath("canonical-manifest.json").read_text(encoding="utf-8")
    )
    snapshot_data = json.loads(
        resource_root.joinpath("canonical-evidence-snapshot.json").read_text(encoding="utf-8")
    )

    assert fixture_data["manifest"]["manifestId"] == manifest_data["manifestId"]
    assert fixture_data["snapshot"]["snapshotId"] == snapshot_data["snapshotId"]
    assert snapshot_data["snapshotId"] == "snap-111111111111"
    assert manifest_data["manifestId"] == "wl-athena-wc002-canonical"


def test_packaged_manifest_resource_is_valid_and_matches_runtime_canonical_payload() -> None:
    runtime_manifest = _canonical_manifest_payload()
    packaged_manifest = load_canonical_manifest_resource()
    expected_digest = runtime_manifest["compatibility"]["artifactDigest"]

    assert packaged_manifest == runtime_manifest
    validated = CanonicalWorkloadManifest.model_validate(packaged_manifest)
    assert validated.compatibility.artifact_digest == expected_digest

    round_tripped = json.loads(json.dumps(packaged_manifest))
    reloaded = CanonicalWorkloadManifest.model_validate(round_tripped)
    assert reloaded.compatibility.artifact_digest == expected_digest


def test_make_canonical_fixture_from_resources_round_trips_valid_bundle() -> None:
    runtime_manifest = _canonical_manifest_payload()
    expected_digest = runtime_manifest["compatibility"]["artifactDigest"]
    fixture_data = load_canonical_fixture_resource()
    bundled_manifest = fixture_data["manifest"]

    assert bundled_manifest == runtime_manifest
    assert (
        CanonicalWorkloadManifest.model_validate(bundled_manifest).compatibility.artifact_digest
        == expected_digest
    )

    from_resources = make_canonical_fixture_from_resources()
    assert from_resources.manifest_digest == expected_digest
    snapshot_digest = fixture_data["snapshot"]["compatibility"]["artifactDigest"]
    assert from_resources.snapshot_artifact_digest == snapshot_digest
    assert from_resources.canonical_manifest.compatibility.artifact_digest == expected_digest

    round_tripped = json.loads(json.dumps(fixture_data))
    reloaded = CanonicalWorkloadManifest.model_validate(round_tripped["manifest"])
    assert reloaded.compatibility.artifact_digest == expected_digest


def test_embedded_combined_snapshot_is_valid_and_matches_packaged_and_runtime_snapshot() -> None:
    bundle = make_canonical_fixture()
    fixture_data = load_canonical_fixture_resource()
    packaged_snapshot = load_canonical_snapshot_resource()
    embedded_snapshot_data = fixture_data["snapshot"]

    reloaded_snapshot = EvidenceSnapshot.model_validate(embedded_snapshot_data)
    round_tripped = json.loads(json.dumps(embedded_snapshot_data))
    reloaded_round_trip = EvidenceSnapshot.model_validate(round_tripped)
    embedded_dump = reloaded_snapshot.model_dump(mode="json", by_alias=True)
    canonical_dump = bundle.canonical_snapshot.model_dump(mode="json", by_alias=True)
    expected_artifact_digest = packaged_snapshot["compatibility"]["artifactDigest"]
    expected_semantic_digest = packaged_snapshot["compatibility"]["semanticDigest"]

    assert embedded_dump == packaged_snapshot
    assert embedded_dump == canonical_dump
    assert reloaded_round_trip.model_dump(mode="json", by_alias=True) == embedded_dump
    assert reloaded_snapshot.compatibility.artifact_digest == expected_artifact_digest
    assert reloaded_snapshot.compatibility.artifact_digest == bundle.snapshot_artifact_digest
    assert reloaded_snapshot.compatibility.semantic_digest == expected_semantic_digest
    assert reloaded_snapshot.compatibility.semantic_digest == bundle.snapshot_semantic_digest

    reloaded_snapshot.validate_for_evaluation(
        as_of=_as_of(),
        expected_artifact_digest=reloaded_snapshot.compatibility.artifact_digest,
        publication_resolver=bundle.publication_resolver,
        key_resolver=bundle.key_resolver,
        trusted_key_anchor=bundle.trusted_key_anchor,
        envelope_resolver=bundle.envelope_resolver,
        identity_evidence=reloaded_snapshot.identity_evidence,
    )


def test_no_stale_non_package_canonical_assets_exist() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for base in (repo_root / "content", repo_root / "src" / "content"):
        assert list(base.glob("**/canonical-*.json")) == []


def test_load_balancer_topology_uses_network_resource_path() -> None:
    bundle = make_canonical_fixture()
    lb_id = _resource_id("athena-lb-01", resource_type="Microsoft.Network/loadBalancers")
    lb_record = next(
        record
        for record in bundle.canonical_snapshot.evidence_records
        if getattr(record, "resource_id", None) == lb_id
    )
    assert lb_record.resource_type == "Microsoft.Network/loadBalancers"
    assert lb_record.resource_id.startswith(
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        "resourceGroups/rg-athena-fixture/providers/"
        "Microsoft.Network/loadBalancers/athena-lb-01"
    )
    assert "Microsoft.Compute/virtualMachines" not in lb_record.resource_id
