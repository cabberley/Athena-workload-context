from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter

from athena_context.binding import (
    DeploymentProvenanceSignalEvidence,
    ImageSignalEvidence,
    LoadBalancerBackendSignalEvidence,
    SubnetSignalEvidence,
    VmssSignalEvidence,
    evaluate_selector,
    normalize_resource_id,
    propose_cohorts,
    selector_runtime_variants,
)
from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CompatibilityMetadata,
    EvidenceItemRef,
    EvidenceScope,
    EvidenceSnapshot,
    ManifestSelector,
    ResourceEvidenceRecord,
    canonicalize_manifest_payload,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    resolve_manifest_profile,
)
from athena_context.fixtures import (
    _canonical_snapshot_payload,
    load_canonical_manifest_resource,
    make_canonical_fixture_from_resources,
)

AS_OF = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
VMSS_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.Compute/"
    "virtualMachineScaleSets/athena-worker-vmss"
)
LB_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.Network/"
    "loadBalancers/athena-lb-01"
)
SUBNET_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.Network/"
    "virtualNetworks/athena-vnet/subnets/workers"
)


def _profile(
    mutate: Any | None = None,
) -> Any:
    payload = deepcopy(load_canonical_manifest_resource())
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


def _refs_by_digest(snapshot: EvidenceSnapshot) -> dict[str, EvidenceItemRef]:
    return {
        ref.item_digest: ref
        for ref in snapshot.evidence_refs
        if isinstance(ref, EvidenceItemRef)
    }


def _worker_records(snapshot: EvidenceSnapshot) -> list[ResourceEvidenceRecord]:
    return [
        record
        for record in _resources(snapshot)
        if record.tags.workload_role == "worker"
    ]


def _signals_for_worker(
    record: ResourceEvidenceRecord,
    evidence_ref: EvidenceItemRef,
) -> list[Any]:
    return [
        VmssSignalEvidence(
            signalType="vmScaleSet",
            resourceId=record.resource_id,
            scaleSetResourceId=VMSS_ID,
            instanceId=record.resource_id.rsplit("/", 1)[-1],
            evidenceRef=evidence_ref,
        ),
        LoadBalancerBackendSignalEvidence(
            signalType="loadBalancerBackend",
            resourceId=record.resource_id,
            loadBalancerResourceId=LB_ID,
            backendPoolName="workers",
            evidenceRef=evidence_ref,
        ),
        SubnetSignalEvidence(
            signalType="subnet",
            resourceId=record.resource_id,
            subnetResourceId=SUBNET_ID,
            evidenceRef=evidence_ref,
        ),
        ImageSignalEvidence(
            signalType="image",
            resourceId=record.resource_id,
            publisher="synthetic",
            offer="athena-linux",
            sku="worker-v1",
            version="1.0.0",
            evidenceRef=evidence_ref,
        ),
        DeploymentProvenanceSignalEvidence(
            signalType="deploymentProvenance",
            resourceId=record.resource_id,
            deploymentId="synthetic-deployment-workers",
            deploymentSystem="bicep",
            identityRef="synthetic://identity/workers",
            evidenceRef=evidence_ref,
        ),
    ]


def test_selector_runtime_covers_frozen_schema_variants_and_enforces_bounds() -> None:
    bundle = make_canonical_fixture_from_resources()
    resources = _resources(bundle.canonical_snapshot)
    worker = _worker_records(bundle.canonical_snapshot)[0]
    ref = _refs_by_digest(bundle.canonical_snapshot)[worker.item_digest]
    signals = _signals_for_worker(worker, ref)
    selectors: list[dict[str, object]] = [
        {
            "selectorType": "resourceIdList",
            "selectorId": "ids",
            "resourceIds": [worker.resource_id.upper()],
            "maxMatches": 1,
        },
        {
            "selectorType": "tagPredicate",
            "selectorId": "tags",
            "predicates": [{"key": "workloadRole", "value": "worker"}],
            "maxMatches": 10,
        },
        {
            "selectorType": "namePredicate",
            "selectorId": "name",
            "prefix": "athena-worker-",
            "maxMatches": 10,
        },
        {
            "selectorType": "resourceType",
            "selectorId": "type",
            "resourceType": "Microsoft.Compute/virtualMachines",
            "locations": ["australiaeast"],
            "resourceGroups": ["rg-athena-fixture"],
            "maxMatches": 10,
        },
        {
            "selectorType": "vmScaleSet",
            "selectorId": "vmss",
            "scaleSetResourceId": VMSS_ID,
            "instanceIds": [worker.resource_id.rsplit("/", 1)[-1]],
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
            "offer": "athena-linux",
            "sku": "worker-v1",
            "version": "1.0.0",
            "maxMatches": 1,
        },
        {
            "selectorType": "provenance",
            "selectorId": "provenance",
            "collectorToolName": worker.provenance.tool_name,
            "collectorToolVersion": worker.provenance.tool_version,
            "identityEvidenceRef": worker.collector_identity_evidence_ref,
            "maxMatches": 10,
        },
        {
            "selectorType": "compositeAll",
            "selectorId": "all",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "all-name",
                    "prefix": "athena-worker-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "tagPredicate",
                    "selectorId": "all-tag",
                    "predicates": [{"key": "environment", "value": "production"}],
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        },
        {
            "selectorType": "compositeAny",
            "selectorId": "any",
            "children": [
                {
                    "selectorType": "namePredicate",
                    "selectorId": "any-worker",
                    "prefix": "athena-worker-",
                    "maxMatches": 10,
                },
                {
                    "selectorType": "namePredicate",
                    "selectorId": "any-web",
                    "prefix": "athena-web-",
                    "maxMatches": 10,
                },
            ],
            "maxMatches": 10,
        },
    ]
    adapter: TypeAdapter[ManifestSelector] = TypeAdapter(ManifestSelector)
    observed_variants: set[str] = set()
    for payload in selectors:
        assert not list(Draft202012Validator(adapter.json_schema()).iter_errors(payload))
        selector = adapter.validate_python(payload)
        observed_variants.add(selector.selector_type)
        result = evaluate_selector(selector, resources, signals=signals)
        assert result.selector_result_digest.startswith("sha256:")

    assert observed_variants == selector_runtime_variants()
    over_broad = adapter.validate_python(
        {
            "selectorType": "tagPredicate",
            "selectorId": "bounded",
            "predicates": [{"key": "environment", "value": "production"}],
            "maxMatches": 1,
        }
    )
    over_result = evaluate_selector(over_broad, resources)
    assert over_result.status == "overMaxMatches"
    assert over_result.max_match_violations == ["bounded"]


def test_proposals_cite_dissent_and_never_publish_or_mutate() -> None:
    bundle = make_canonical_fixture_from_resources()
    profile = _profile()
    result = propose_cohorts(profile, bundle.canonical_snapshot, as_of=AS_OF)
    worker = next(item for item in result.proposals if item.role.role_id == "worker")

    assert worker.confidence_band == "conflicting"
    assert {item.signal_type for item in worker.dissent} == {"observedCommunication"}
    assert worker.disposition == "humanResolution"
    assert not worker.bulk_review_eligible
    assert not worker.publication_allowed
    assert not worker.manifest_mutated
    assert result.requires_human_review
    assert not result.publication_allowed
    assert profile.resolved_profile_digest == worker.scope.resolved_profile_digest
    assert (
        worker.snapshot.semantic_digest
        == bundle.canonical_snapshot.compatibility.semantic_digest
    )


def test_ambiguous_role_evidence_is_rejected_with_exact_exclusivity() -> None:
    bundle = make_canonical_fixture_from_resources()
    worker_record = _worker_records(bundle.canonical_snapshot)[0]
    material = worker_record.model_dump(mode="python", by_alias=True, exclude_none=True)
    material.pop("itemDigest")
    material["provenance"]["sourceResponsePointer"] = "/items/0"
    material["tags"]["workloadRole"] = "web-service"
    result = propose_cohorts(
        _profile(),
        _fast_snapshot([material]),
        as_of=AS_OF,
    )
    worker_ids = {normalize_resource_id(worker_record.resource_id)}
    ambiguous = {
        resource_id
        for proposal in result.proposals
        for rejected in proposal.rejected_candidates
        if "conflictingRoleEvidence" in rejected.reasons
        for resource_id in [rejected.resource_id]
    }

    assert worker_ids.issubset(ambiguous)
    assert all(
        not worker_ids.intersection(proposal.members)
        for proposal in result.proposals
    )
    assert any(conflict.code == "ambiguousRole" for conflict in result.conflicts)


def test_stale_missing_cross_environment_and_out_of_scope_fail_closed() -> None:
    bundle = make_canonical_fixture_from_resources()
    stale = propose_cohorts(
        _profile(),
        bundle.canonical_snapshot,
        as_of=datetime(2025, 6, 2, tzinfo=UTC),
    )
    assert all(proposal.confidence_band != "high" for proposal in stale.proposals)
    assert all(
        any(conflict.code == "staleEvidence" for conflict in proposal.conflicts)
        for proposal in stale.proposals
    )

    worker_records = _worker_records(bundle.canonical_snapshot)
    development_material = worker_records[0].model_dump(
        mode="python", by_alias=True, exclude_none=True
    )
    development_material.pop("itemDigest")
    development_material["provenance"]["sourceResponsePointer"] = "/items/0"
    development_material["tags"]["environment"] = "development"
    cross_environment = propose_cohorts(
        _profile(),
        _fast_snapshot([development_material]),
        as_of=AS_OF,
    )
    cross_worker = next(
        item for item in cross_environment.proposals if item.role.role_id == "worker"
    )
    assert any(
        "crossEnvironment" in candidate.reasons
        for candidate in cross_worker.rejected_candidates
    )

    outside_material = worker_records[1].model_dump(
        mode="python", by_alias=True, exclude_none=True
    )
    outside_material.pop("itemDigest")
    outside_material["provenance"]["sourceResponsePointer"] = "/items/0"
    outside_material["resourceId"] = outside_material["resourceId"].replace(
        "resourceGroups/rg-athena-fixture",
        "resourceGroups/rg-outside-synthetic",
    )
    outside_profile = propose_cohorts(
        _profile(),
        _fast_snapshot(
            [outside_material],
            authorized_resource_group="rg-outside-synthetic",
        ),
        as_of=AS_OF,
    )
    outside_worker = next(
        item for item in outside_profile.proposals if item.role.role_id == "worker"
    )
    assert any(
        "outOfProfileScope" in candidate.reasons
        for candidate in outside_worker.rejected_candidates
    )
    assert outside_worker.members == []
    assert outside_worker.disposition == "humanResolution"

    outside_snapshot = propose_cohorts(
        _profile(),
        _fast_snapshot(
            [
                development_material
                | {
                    "tags": {
                        "environment": "production",
                        "workloadRole": "worker",
                    }
                }
            ],
            authorized_resource_group="rg-outside-synthetic",
        ),
        as_of=AS_OF,
    )
    unauthorized_worker = next(
        item for item in outside_snapshot.proposals if item.role.role_id == "worker"
    )
    assert any(
        "outOfSnapshotScope" in candidate.reasons
        for candidate in unauthorized_worker.rejected_candidates
    )

    missing_refs = bundle.canonical_snapshot.model_copy(
        update={
            "evidence_refs": [
                ref
                for ref in bundle.canonical_snapshot.evidence_refs
                if not (
                    isinstance(ref, EvidenceItemRef)
                    and ref.item_digest == worker_records[0].item_digest
                )
            ]
        }
    )
    missing = propose_cohorts(_profile(), missing_refs, as_of=AS_OF)
    missing_worker = next(item for item in missing.proposals if item.role.role_id == "worker")
    assert any(
        "invalidEvidenceReference" in candidate.reasons
        for candidate in missing_worker.rejected_candidates
    )
    assert missing_worker.confidence_band != "high"


def test_medium_confidence_and_over_max_matches_require_human_resolution() -> None:
    bundle = make_canonical_fixture_from_resources()
    template = _worker_records(bundle.canonical_snapshot)[0].model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    template.pop("itemDigest")
    template["provenance"]["sourceResponsePointer"] = "/items/0"
    medium_result = propose_cohorts(
        _profile(),
        _fast_snapshot([template]),
        as_of=AS_OF,
    )
    medium_worker = next(
        item for item in medium_result.proposals if item.role.role_id == "worker"
    )
    assert medium_worker.confidence_band == "medium"
    assert medium_worker.disposition == "humanResolution"
    assert not medium_worker.bulk_review_eligible

    materials: list[dict[str, Any]] = []
    for index in range(21):
        material = deepcopy(template)
        material["resourceId"] = material["resourceId"].rsplit("/", 1)[0] + (
            f"/athena-worker-{index:02d}"
        )
        material["provenance"]["sourceResponsePointer"] = f"/items/{index}"
        materials.append(material)
    bounded_result = propose_cohorts(
        _profile(),
        _fast_snapshot(materials),
        as_of=AS_OF,
    )
    bounded_worker = next(
        item for item in bounded_result.proposals if item.role.role_id == "worker"
    )
    assert bounded_worker.members == []
    assert bounded_worker.confidence_band != "high"
    assert any(conflict.code == "overMaxMatches" for conflict in bounded_worker.conflicts)
    assert all(
        "overMaxMatches" in candidate.reasons
        for candidate in bounded_worker.rejected_candidates
    )


def _scale_profile() -> Any:
    def permit_bounded_cohort(payload: dict[str, Any]) -> None:
        worker = next(role for role in payload["roles"] if role["roleId"] == "worker")
        worker["selectors"][0]["maxMatches"] = 1000

    return _profile(permit_bounded_cohort)


def _fast_snapshot(
    materials: list[dict[str, Any]],
    *,
    authorized_resource_group: str = "rg-athena-fixture",
) -> EvidenceSnapshot:
    payload = _canonical_snapshot_payload(record_materials=materials)
    payload["authorizedScopes"][0]["resourceGroupName"] = authorized_resource_group
    semantic_digest = compute_evidence_snapshot_semantic_digest(payload)
    payload["compatibility"]["semanticDigest"] = semantic_digest
    for evidence_ref in payload["evidenceRefs"]:
        evidence_ref["snapshotSemanticDigest"] = semantic_digest
    artifact_digest = compute_evidence_snapshot_artifact_digest(payload)
    payload["compatibility"]["artifactDigest"] = artifact_digest
    for evidence_ref in payload["evidenceRefs"]:
        evidence_ref["snapshotArtifactDigest"] = artifact_digest

    base = make_canonical_fixture_from_resources().canonical_snapshot
    scope_adapter: TypeAdapter[EvidenceScope] = TypeAdapter(EvidenceScope)
    return base.model_copy(
        update={
            "compatibility": CompatibilityMetadata.model_validate(payload["compatibility"]),
            "authorized_scopes": [
                scope_adapter.validate_python(scope) for scope in payload["authorizedScopes"]
            ],
            "evidence_records": [
                ResourceEvidenceRecord.model_validate(record)
                for record in payload["evidenceRecords"]
            ],
            "evidence_refs": [
                EvidenceItemRef.model_validate(ref) for ref in payload["evidenceRefs"]
            ],
        }
    )


def _scale_snapshot(count: int = 1000) -> EvidenceSnapshot:
    bundle = make_canonical_fixture_from_resources()
    template = _worker_records(bundle.canonical_snapshot)[0].model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    template.pop("itemDigest")
    materials: list[dict[str, Any]] = []
    for index in range(count):
        material = deepcopy(template)
        material["resourceId"] = material["resourceId"].rsplit("/", 1)[0] + (
            f"/athena-worker-{index:04d}"
        )
        material["provenance"]["sourceResponsePointer"] = f"/items/{index}"
        materials.append(material)
    return _fast_snapshot(materials)


@pytest.mark.parametrize("reverse_input", [False, True])
def test_deterministic_1000_resource_cohort_is_bulk_review_only(
    reverse_input: bool,
) -> None:
    snapshot = _scale_snapshot()
    if reverse_input:
        snapshot = snapshot.model_copy(
            update={
                "evidence_records": list(reversed(snapshot.evidence_records)),
                "evidence_refs": list(reversed(snapshot.evidence_refs)),
            }
        )
    refs = _refs_by_digest(snapshot)
    signals = [
        VmssSignalEvidence(
            signalType="vmScaleSet",
            resourceId=record.resource_id,
            scaleSetResourceId=VMSS_ID,
            instanceId=f"{index}",
            evidenceRef=refs[record.item_digest],
        )
        for index, record in enumerate(_worker_records(snapshot))
    ]
    if reverse_input:
        signals.reverse()

    started = perf_counter()
    result = propose_cohorts(
        _scale_profile(),
        snapshot,
        as_of=AS_OF,
        signals=signals,
    )
    duration = perf_counter() - started
    worker = next(item for item in result.proposals if item.role.role_id == "worker")

    assert len(worker.members) == 1000
    assert worker.confidence_band == "high"
    assert worker.bulk_review_eligible
    assert worker.disposition == "bulkHumanReview"
    assert worker.requires_human_review
    assert not worker.publication_allowed
    assert worker.selector_preview is not None
    assert worker.selector_preview.max_matches == 1000
    assert worker.selector_preview.matched_resource_ids == worker.members
    assert duration < 5.0


def test_reordered_scale_input_has_stable_digests() -> None:
    snapshot = _scale_snapshot()
    refs = _refs_by_digest(snapshot)
    signals = [
        VmssSignalEvidence(
            signalType="vmScaleSet",
            resourceId=record.resource_id,
            scaleSetResourceId=VMSS_ID,
            instanceId=record.resource_id.rsplit("/", 1)[-1],
            evidenceRef=refs[record.item_digest],
        )
        for record in _worker_records(snapshot)
    ]
    profile = _scale_profile()
    first = propose_cohorts(profile, snapshot, as_of=AS_OF, signals=signals)
    reordered_snapshot = snapshot.model_copy(
        update={
            "evidence_records": list(reversed(snapshot.evidence_records)),
            "evidence_refs": list(reversed(snapshot.evidence_refs)),
        }
    )
    second = propose_cohorts(
        profile,
        reordered_snapshot,
        as_of=AS_OF,
        signals=list(reversed(signals)),
    )

    assert first.input_digest == second.input_digest
    assert first.proposal_set_digest == second.proposal_set_digest
    assert [item.proposal_id for item in first.proposals] == [
        item.proposal_id for item in second.proposals
    ]
