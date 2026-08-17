from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Any, Literal, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter

import athena_context.fixtures as fixture_factory
from athena_context.binding import (
    TrustedSnapshotVerifier,
    VerifiedCohortSnapshot,
    evaluate_selector,
    normalize_resource_id,
    propose_cohorts,
    selector_runtime_variants,
    verify_cohort_snapshot,
)
from athena_context.contracts import (
    AthenaValidationError,
    CanonicalWorkloadManifest,
    EvidenceSnapshot,
    ManifestSelector,
    ResourceEvidenceRecord,
    SnapshotPublicationRecord,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    compute_evidence_record_digest,
    compute_response_envelope_digest,
    resolve_manifest_profile,
    sha256_hex,
)

AS_OF = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
TENANT_ID = "11111111-1111-1111-1111-111111111111"
CROSS_TENANT_ID = "22222222-2222-2222-2222-222222222222"
VMSS_ID = (
    f"/subscriptions/{TENANT_ID}/resourceGroups/rg-athena-fixture/"
    "providers/Microsoft.Compute/virtualMachineScaleSets/athena-worker-vmss"
)
LB_ID = (
    f"/subscriptions/{TENANT_ID}/resourceGroups/rg-athena-fixture/"
    "providers/Microsoft.Network/loadBalancers/athena-lb-01"
)
SUBNET_ID = (
    f"/subscriptions/{TENANT_ID}/resourceGroups/rg-athena-fixture/"
    "providers/Microsoft.Network/virtualNetworks/athena-vnet/subnets/workers"
)


@dataclass(frozen=True, slots=True)
class _TrustedSnapshot:
    snapshot: EvidenceSnapshot
    envelope: dict[str, Any]
    verifier: TrustedSnapshotVerifier
    model_validation_seconds: float


def _profile(
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> Any:
    payload = deepcopy(fixture_factory.load_canonical_manifest_resource())
    if mutate is not None:
        mutate(payload)
    manifest = CanonicalWorkloadManifest.model_validate(canonicalize_manifest_payload(payload))
    return resolve_manifest_profile(manifest, "production", as_of=AS_OF)


def _resources(snapshot: EvidenceSnapshot) -> list[ResourceEvidenceRecord]:
    return [
        record
        for record in snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
    ]


def _worker_proposal(result: Any) -> Any:
    return next(item for item in result.proposals if item.role.role_id == "worker")


def _bundle_verifier(bundle: fixture_factory.FixtureBundle) -> TrustedSnapshotVerifier:
    def verify(candidate: EvidenceSnapshot, as_of: datetime) -> EvidenceSnapshot:
        return candidate.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=bundle.snapshot_artifact_digest,
            publication_resolver=bundle.publication_resolver,
            key_resolver=bundle.key_resolver,
            trusted_key_anchor=bundle.trusted_key_anchor,
            envelope_resolver=bundle.envelope_resolver,
        )

    return verify


def _verified_bundle() -> tuple[fixture_factory.FixtureBundle, VerifiedCohortSnapshot]:
    bundle = fixture_factory.make_canonical_fixture_from_resources()
    verified = verify_cohort_snapshot(
        bundle.canonical_snapshot,
        as_of=AS_OF,
        verifier=_bundle_verifier(bundle),
    )
    return bundle, verified


def _vmss_resource_id(index: int) -> str:
    return f"{VMSS_ID}/virtualMachines/athena-worker-{index:04d}"


def _response_envelope(
    count: int,
    *,
    workload_role: str,
    environment: str = "production",
) -> dict[str, Any]:
    return {
        "requestId": "req-wc010-scale",
        "correlationId": "corr-wc010-scale",
        "retryCount": 0,
        "transportLatencyMs": 42,
        "receivedAt": "2025-06-01T11:45:00.000Z",
        "items": [
            {
                "recordType": "resource",
                "resourceId": _vmss_resource_id(index),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": str(index % 3 + 1),
                "tags": {
                    "environment": environment,
                    "workloadRole": workload_role,
                    "managedBy": "bicep",
                },
                "state": "running",
            }
            for index in range(count)
        ],
    }


def _build_attested_snapshot(
    count: int,
    *,
    workload_role: str = "worker",
    environment: str = "production",
) -> _TrustedSnapshot:
    envelope = _response_envelope(
        count,
        workload_role=workload_role,
        environment=environment,
    )
    response_digest = compute_response_envelope_digest(envelope)
    attempt_payload: dict[str, Any] = {
        "attemptType": "successResponse",
        "attemptId": "attempt-111111111111",
        "attemptStartedAt": datetime(2025, 6, 1, 11, 45, tzinfo=UTC),
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": sha256_hex("req-wc002-canonical"),
        "responseDigest": response_digest,
        "responseReceivedAt": datetime(2025, 6, 1, 11, 46, tzinfo=UTC),
        "collectorIdentityEvidenceRef": "identity-111111111111",
    }
    attempt_digest = compute_artifact_digest(attempt_payload)
    materials: list[dict[str, Any]] = []
    for index, item in enumerate(envelope["items"]):
        materials.append(
            {
                **deepcopy(item),
                "provenance": {
                    "collectorAttemptId": attempt_payload["attemptId"],
                    "collectorIdentityEvidenceRef": "identity-111111111111",
                    "toolName": attempt_payload["toolName"],
                    "toolVersion": attempt_payload["toolVersion"],
                    "sourceResponseDigest": response_digest,
                    "sourceResponsePointer": f"/items/{index}",
                },
                "collectorAttemptDigest": attempt_digest,
                "collectorIdentityEvidenceRef": "identity-111111111111",
            }
        )

    original_envelope_builder = fixture_factory._build_response_envelope
    fixture_factory._build_response_envelope = lambda: deepcopy(envelope)
    try:
        payload = fixture_factory._canonical_snapshot_payload(record_materials=materials)
    finally:
        fixture_factory._build_response_envelope = original_envelope_builder

    validation_started = perf_counter()
    snapshot = EvidenceSnapshot.model_validate(payload)
    validation_seconds = perf_counter() - validation_started
    trusted_key_anchor = fixture_factory._trusted_key_anchor()
    trusted_key_record = fixture_factory._make_trusted_key_record()
    publication = SnapshotPublicationRecord(
        snapshot_id=snapshot.snapshot_id,
        artifact_digest=snapshot.compatibility.artifact_digest,
        semantic_digest=snapshot.compatibility.semantic_digest,
        schema_version=snapshot.compatibility.schema_version,
        semantic_contract_version=snapshot.compatibility.semantic_contract_version,
        published_at=snapshot.snapshot_attestation.attested_at + timedelta(seconds=1),
    )

    def key_resolver(resolved_anchor: Any) -> Any:
        return trusted_key_record if resolved_anchor == trusted_key_anchor else None

    def publication_resolver(snapshot_id: str) -> SnapshotPublicationRecord | None:
        return publication if snapshot_id == publication.snapshot_id else None

    def envelope_resolver(
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> dict[str, Any] | None:
        expected_attempt = snapshot.collector_attempts[0]
        if (
            attempt_id == expected_attempt.attempt_id
            and kind == "response"
            and digest == response_digest
        ):
            return envelope
        return None

    def verifier(candidate: EvidenceSnapshot, as_of: datetime) -> EvidenceSnapshot:
        return candidate.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=snapshot.compatibility.artifact_digest,
            publication_resolver=publication_resolver,
            key_resolver=key_resolver,
            trusted_key_anchor=trusted_key_anchor,
            envelope_resolver=envelope_resolver,
        )

    return _TrustedSnapshot(
        snapshot=snapshot,
        envelope=envelope,
        verifier=verifier,
        model_validation_seconds=validation_seconds,
    )


@pytest.fixture(scope="module")
def trusted_scale_snapshot() -> _TrustedSnapshot:
    return _build_attested_snapshot(1000)


@pytest.fixture(scope="module")
def verified_scale_snapshot(
    trusted_scale_snapshot: _TrustedSnapshot,
) -> VerifiedCohortSnapshot:
    return verify_cohort_snapshot(
        trusted_scale_snapshot.snapshot,
        as_of=AS_OF,
        verifier=trusted_scale_snapshot.verifier,
    )


def _scale_profile(*, max_matches: int = 1000) -> Any:
    def permit_bounded_worker_cohort(payload: dict[str, Any]) -> None:
        worker = next(role for role in payload["roles"] if role["roleId"] == "worker")
        worker["selectors"][0]["maxMatches"] = max_matches

    return _profile(permit_bounded_worker_cohort)


def test_selector_runtime_uses_only_claims_present_in_canonical_records() -> None:
    bundle = fixture_factory.make_canonical_fixture_from_resources()
    normal_worker = next(
        record
        for record in _resources(bundle.canonical_snapshot)
        if "worker-01" in record.resource_id
    )
    vmss_payload = normal_worker.model_dump(mode="python", by_alias=True, exclude_none=True)
    vmss_payload.pop("itemDigest")
    vmss_payload["resourceId"] = _vmss_resource_id(1)
    vmss_payload["itemDigest"] = compute_evidence_record_digest(vmss_payload)
    vmss_worker = ResourceEvidenceRecord.model_validate(vmss_payload)
    resources = [normal_worker, vmss_worker]
    selectors: list[dict[str, object]] = [
        {
            "selectorType": "resourceIdList",
            "selectorId": "ids",
            "resourceIds": [normal_worker.resource_id.upper()],
            "maxMatches": 1,
        },
        {
            "selectorType": "tagPredicate",
            "selectorId": "tags",
            "predicates": [{"key": "workloadRole", "value": "worker"}],
            "maxMatches": 2,
        },
        {
            "selectorType": "namePredicate",
            "selectorId": "name",
            "prefix": "athena-worker-",
            "maxMatches": 2,
        },
        {
            "selectorType": "resourceType",
            "selectorId": "type",
            "resourceType": "Microsoft.Compute/virtualMachines",
            "maxMatches": 2,
        },
        {
            "selectorType": "vmScaleSet",
            "selectorId": "vmss",
            "scaleSetResourceId": VMSS_ID,
            "instanceIds": ["athena-worker-0001"],
            "maxMatches": 1,
        },
        {
            "selectorType": "loadBalancerBackend",
            "selectorId": "backend",
            "loadBalancerResourceId": LB_ID,
            "backendPoolName": "workers",
            "maxMatches": 1,
        },
        {
            "selectorType": "subnet",
            "selectorId": "subnet",
            "subnetResourceId": SUBNET_ID,
            "maxMatches": 1,
        },
        {
            "selectorType": "image",
            "selectorId": "image",
            "publisher": "synthetic",
            "offer": "linux",
            "sku": "worker",
            "maxMatches": 1,
        },
        {
            "selectorType": "provenance",
            "selectorId": "provenance",
            "collectorToolName": normal_worker.provenance.tool_name,
            "collectorToolVersion": normal_worker.provenance.tool_version,
            "identityEvidenceRef": normal_worker.collector_identity_evidence_ref,
            "maxMatches": 2,
        },
        {
            "selectorType": "compositeAll",
            "selectorId": "all",
            "children": [
                {
                    "selectorType": "tagPredicate",
                    "selectorId": "all-tag",
                    "predicates": [{"key": "workloadRole", "value": "worker"}],
                    "maxMatches": 2,
                }
            ],
            "maxMatches": 2,
        },
        {
            "selectorType": "compositeAny",
            "selectorId": "any",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "any-name",
                    "prefix": "athena-worker-",
                    "maxMatches": 2,
                }
            ],
            "maxMatches": 2,
        },
    ]
    adapter: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
    results: dict[str, Any] = {}
    for payload in selectors:
        assert not list(Draft202012Validator(adapter.json_schema()).iter_errors(payload))
        selector = adapter.validate_python(payload)
        results[selector.selector_type] = evaluate_selector(selector, resources)

    assert set(results) == selector_runtime_variants()
    assert results["vmScaleSet"].matched_resource_ids == [
        normalize_resource_id(vmss_worker.resource_id)
    ]
    for unsupported in ("loadBalancerBackend", "subnet", "image"):
        assert results[unsupported].status == "noMatches"


def test_invented_vmss_and_reused_reference_labels_cannot_raise_confidence() -> None:
    bundle, verified = _verified_bundle()
    profile = _profile()
    normal_worker = next(
        record
        for record in _resources(bundle.canonical_snapshot)
        if "worker-01" in record.resource_id
    )
    invented_vmss = TypeAdapter(ManifestSelector).validate_python(
        {
            "selectorType": "vmScaleSet",
            "selectorId": "invented",
            "scaleSetResourceId": VMSS_ID,
            "maxMatches": 10,
        }
    )
    assert evaluate_selector(invented_vmss, [normal_worker]).status == "noMatches"
    with pytest.raises(TypeError):
        propose_cohorts(
            profile,
            verified,
            as_of=AS_OF,
            signals=[{"invented": "vmss"}],  # type: ignore[call-arg]
        )

    result = propose_cohorts(profile, verified, as_of=AS_OF)
    worker = _worker_proposal(result)
    resource_support = [
        item
        for item in worker.supporting_evidence
        if item.signal_type in {"namePredicate", "approvedTags"}
    ]
    assert len(resource_support) == 2
    assert {
        tuple(ref.item_digest for ref in item.evidence_refs)
        for item in resource_support
    } == {
        tuple(ref.item_digest for ref in resource_support[0].evidence_refs)
    }
    assert worker.confidence_band != "high"
    assert not worker.bulk_review_eligible


def test_proposal_boundary_requires_exact_trusted_snapshot_verification() -> None:
    bundle = fixture_factory.make_canonical_fixture_from_resources()
    profile = _profile()
    with pytest.raises(AthenaValidationError, match="VerifiedCohortSnapshot"):
        propose_cohorts(
            profile,
            cast(Any, bundle.canonical_snapshot),
            as_of=AS_OF,
        )
    with pytest.raises(AthenaValidationError, match="VerifiedCohortSnapshot"):
        propose_cohorts(
            profile,
            cast(Any, VerifiedCohortSnapshot()),
            as_of=AS_OF,
        )

    tampered_digest = bundle.canonical_snapshot.model_copy(deep=True)
    object.__setattr__(
        tampered_digest.compatibility,
        "artifact_digest",
        "sha256:" + "9" * 64,
    )
    with pytest.raises(AthenaValidationError, match="canonical digests"):
        verify_cohort_snapshot(
            tampered_digest,
            as_of=AS_OF,
            verifier=_bundle_verifier(bundle),
        )

    tampered_attestation = bundle.canonical_snapshot.model_copy(deep=True)
    object.__setattr__(
        tampered_attestation.snapshot_attestation,
        "evidence_record_set_digest",
        "sha256:" + "8" * 64,
    )
    with pytest.raises(AthenaValidationError, match="attestation"):
        verify_cohort_snapshot(
            tampered_attestation,
            as_of=AS_OF,
            verifier=_bundle_verifier(bundle),
        )

    tampered_signature = bundle.canonical_snapshot.model_copy(deep=True)
    signature = tampered_signature.snapshot_attestation.signature
    replacement = "A" if signature[0] != "A" else "B"
    object.__setattr__(
        tampered_signature.snapshot_attestation,
        "signature",
        replacement + signature[1:],
    )
    with pytest.raises(AthenaValidationError, match="cryptographic verification"):
        verify_cohort_snapshot(
            tampered_signature,
            as_of=AS_OF,
            verifier=_bundle_verifier(bundle),
        )


@pytest.mark.parametrize("mutation", ["selector", "scope"])
def test_proposal_boundary_rejects_profile_changed_after_resolution(
    mutation: str,
) -> None:
    _, verified = _verified_bundle()
    profile = _profile().model_copy(deep=True)
    if mutation == "selector":
        worker = next(role for role in profile.roles if role.role_id == "worker")
        worker.selectors[0].prefix = "mutated-worker-"
    else:
        scope = profile.allowed_evidence_scopes[0]
        scope.resource_group_name = "rg-mutated-synthetic"

    with pytest.raises(AthenaValidationError, match="changed after digest validation"):
        propose_cohorts(profile, verified, as_of=AS_OF)


def test_proposal_roles_and_selectors_are_detached_from_approved_profile() -> None:
    _, verified = _verified_bundle()
    profile = _profile()
    original_digest = profile.resolved_profile_digest
    profile_worker = next(role for role in profile.roles if role.role_id == "worker")
    profile_selector = profile_worker.selectors[0]

    result = propose_cohorts(profile, verified, as_of=AS_OF)
    proposal_worker = _worker_proposal(result)
    proposal_selector = proposal_worker.role.selectors[0]

    assert proposal_worker.role is not profile_worker
    assert proposal_worker.role.selectors is not profile_worker.selectors
    assert proposal_selector is not profile_selector

    proposal_selector.prefix = "review-only-worker-"
    assert proposal_selector.prefix == "review-only-worker-"
    assert profile_selector.prefix == "athena-worker-"
    assert profile.resolved_profile_digest == original_digest
    assert profile.recompute_semantic_digest() == original_digest


def test_cross_tenant_same_subscription_and_resource_group_is_out_of_scope() -> None:
    def cross_tenant_scope(payload: dict[str, Any]) -> None:
        payload["workload"]["allowedEvidenceScopes"][0]["tenantId"] = CROSS_TENANT_ID

    _, verified = _verified_bundle()
    result = propose_cohorts(_profile(cross_tenant_scope), verified, as_of=AS_OF)

    assert all(proposal.members == [] for proposal in result.proposals)
    assert all(proposal.disposition == "humanResolution" for proposal in result.proposals)
    assert any(
        "outOfProfileScope" in rejected.reasons
        for proposal in result.proposals
        for rejected in proposal.rejected_candidates
    )
    assert any(
        conflict.code == "outOfScope"
        for proposal in result.proposals
        for conflict in proposal.conflicts
    )


def test_conflicting_role_evidence_and_stale_snapshot_fail_closed() -> None:
    trusted = _build_attested_snapshot(1, workload_role="web-service")
    verified = verify_cohort_snapshot(
        trusted.snapshot,
        as_of=AS_OF,
        verifier=trusted.verifier,
    )
    result = propose_cohorts(_scale_profile(), verified, as_of=AS_OF)
    assert any(conflict.code == "ambiguousRole" for conflict in result.conflicts)
    assert all(not proposal.members for proposal in result.proposals)

    bundle = fixture_factory.make_canonical_fixture_from_resources()
    with pytest.raises(AthenaValidationError):
        verify_cohort_snapshot(
            bundle.canonical_snapshot,
            as_of=bundle.canonical_snapshot.expires_at,
            verifier=_bundle_verifier(bundle),
        )


def test_over_max_matches_fails_closed(
    verified_scale_snapshot: VerifiedCohortSnapshot,
) -> None:
    result = propose_cohorts(
        _scale_profile(max_matches=999),
        verified_scale_snapshot,
        as_of=AS_OF,
    )
    worker = _worker_proposal(result)
    assert worker.members == []
    assert worker.confidence_band != "high"
    assert worker.disposition == "humanResolution"
    assert any(conflict.code == "overMaxMatches" for conflict in worker.conflicts)
    assert len(worker.rejected_candidates) == 1000


def test_attested_1000_resource_cohort_and_performance(
    trusted_scale_snapshot: _TrustedSnapshot,
    verified_scale_snapshot: VerifiedCohortSnapshot,
) -> None:
    # The module fixture was accepted by EvidenceSnapshot.model_validate and the
    # verified capability was accepted by validate_for_evaluation.
    assert len(_resources(trusted_scale_snapshot.snapshot)) == 1000
    started = perf_counter()
    result = propose_cohorts(
        _scale_profile(),
        verified_scale_snapshot,
        as_of=AS_OF,
    )
    proposal_seconds = perf_counter() - started
    worker = _worker_proposal(result)

    assert len(worker.members) == 1000
    assert len([item for item in result.proposals if item.members]) == 1
    assert worker.confidence_band == "low"
    assert worker.disposition == "humanResolution"
    assert not worker.bulk_review_eligible
    assert worker.selector_preview is not None
    assert worker.selector_preview.matched_resource_ids == worker.members
    assert worker.selector_preview.max_matches == 1000
    assert proposal_seconds < 8.0


def test_reordered_verified_snapshot_has_stable_proposal_digests(
    trusted_scale_snapshot: _TrustedSnapshot,
    verified_scale_snapshot: VerifiedCohortSnapshot,
) -> None:
    profile = _scale_profile()
    first = propose_cohorts(profile, verified_scale_snapshot, as_of=AS_OF)
    reordered_snapshot = trusted_scale_snapshot.snapshot.model_copy(
        update={
            "evidence_records": list(
                reversed(trusted_scale_snapshot.snapshot.evidence_records)
            ),
            "evidence_refs": list(reversed(trusted_scale_snapshot.snapshot.evidence_refs)),
        }
    )
    reordered_verified = verify_cohort_snapshot(
        reordered_snapshot,
        as_of=AS_OF,
        verifier=trusted_scale_snapshot.verifier,
    )
    second = propose_cohorts(profile, reordered_verified, as_of=AS_OF)

    assert first.input_digest == second.input_digest
    assert first.proposal_set_digest == second.proposal_set_digest
    assert [proposal.proposal_id for proposal in first.proposals] == [
        proposal.proposal_id for proposal in second.proposals
    ]
