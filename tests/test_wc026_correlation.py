from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import athena_context.correlation as correlation_package
import athena_context.correlation.engine as correlation_engine
from athena_context.azure_adapters import AzureBlobVersionPinnedArtifactReader
from athena_context.contracts import compute_artifact_digest, sha256_hex
from athena_context.correlation import (
    CORRELATION_RULE_CATALOG,
    CORRELATION_RULE_CATALOG_DIGEST,
    AzureBlobCorrelationArtifactReader,
    CorrelationService,
    TrustedChangeArtifactVerifier,
    TrustedMonitoringHandoffVerifier,
    VerifiedCorrelationReport,
    classify_confidence,
)
from athena_context.correlation.engine import (
    _SCORE_WEIGHTS,
    _enforce_candidate_budget,
    _is_exact_corrective_change,
)
from athena_context.correlation.rules import assert_catalog_digest
from test_wc026_correlation_contract import (
    DB_ID,
    NOW,
    NSG_ID,
    NSG_RULE_ID,
    WEB_ID,
    _bound_observation,
    _bundle,
    _change_pair,
    _connection_monitor_observation,
    _coverage,
    _coverage_scope,
    _dependency_path,
    _endpoint_health_observation,
    _network_flow_observation,
    _nsg_bundle,
    _request,
)


class _ArtifactReader:
    def __init__(self, request) -> None:
        self._payloads = {
            (
                request.monitoring_handoff.evidence.name,
                request.monitoring_handoff.evidence.version,
            ): request.monitoring_bundle.canonical_bytes(),
            **{
                (handoff.artifact.name, handoff.artifact.version): artifact.canonical_bytes()
                for artifact, handoff in zip(
                    request.change_artifacts,
                    request.change_handoffs,
                    strict=True,
                )
            },
        }
        authority_reference = getattr(
            request.context_binding,
            "publication_authority_reference",
            None,
        )
        authority = getattr(request.context_binding, "publication_authority", None)
        if authority_reference is not None and authority is not None:
            self._payloads[(authority_reference.name, authority_reference.version)] = (
                authority.canonical_bytes()
            )

    def read(self, reference):
        return self._payloads[(reference.name, reference.version)]


def _production_reader_stub(
    *,
    container_name: str,
    managed_identity_client_id: str,
    required_prefix: str,
) -> AzureBlobCorrelationArtifactReader:
    reader = object.__new__(AzureBlobVersionPinnedArtifactReader)
    object.__setattr__(reader, "_blob_endpoint", "https://synthetic.blob.core.windows.net")
    object.__setattr__(reader, "_container_name", container_name)
    object.__setattr__(
        reader,
        "_managed_identity_client_id",
        managed_identity_client_id,
    )
    return AzureBlobCorrelationArtifactReader(
        reader=reader,
        required_prefix=required_prefix,
    )


class _MonitoringVerifier:
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def verify(self, handoff, *, as_of):
        self._calls.append(f"monitoring:{as_of.isoformat()}")
        return handoff.compute_artifact_digest_value()


class _ChangeVerifier:
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def verify(self, artifact, *, as_of):
        self._calls.append(f"change:{as_of.isoformat()}")
        return sha256_hex(artifact.canonical_bytes())


def _verified(request):
    return request


def _test_service(
    request,
    *,
    calls: list[str] | None = None,
) -> CorrelationService:
    service = object.__new__(CorrelationService)
    object.__setattr__(service, "monitoring_reader", _ArtifactReader(request))
    object.__setattr__(service, "change_reader", _ArtifactReader(request))
    object.__setattr__(service, "authority_reader", _ArtifactReader(request))
    object.__setattr__(
        service,
        "monitoring_verifier",
        _MonitoringVerifier([] if calls is None else calls),
    )
    object.__setattr__(
        service,
        "change_verifier",
        _ChangeVerifier([] if calls is None else calls),
    )
    object.__setattr__(
        service,
        "_sealing_key",
        b"0123456789abcdef0123456789abcdef",
    )
    object.__setattr__(
        service,
        "_clock",
        lambda: request.trusted_as_of,
    )
    return service


def correlate_incident(request):
    service = _test_service(request)
    result = service.correlate(request)
    assert service.validate_result(result) == result.report
    return result.report


def test_atomic_service_runs_both_verifiers_without_returning_a_capability() -> None:
    change_pair = _change_pair()
    request = _request(change_pair=change_pair)
    calls: list[str] = []
    service = _test_service(request, calls=calls)
    result = service.correlate(request)

    assert isinstance(result, VerifiedCorrelationReport)
    report = service.validate_result(result)
    assert report.request_digest == request.request_digest
    assert calls == [
        f"monitoring:{request.trusted_as_of.isoformat()}",
        f"change:{request.trusted_as_of.isoformat()}",
    ]
    assert not hasattr(CorrelationService, "verify")
    assert "VerifiedCorrelationInput" not in correlation_package.__all__
    assert not hasattr(correlation_engine, "_correlate_request")
    with pytest.raises(ValueError, match="receipt is invalid"):
        service.validate_result(
            replace(
                result,
                verification_receipt="hmac-sha256:" + "f" * 64,
            )
        )
    with pytest.raises(ValueError):
        service.validate_result(
            replace(
                result,
                report=result.report.model_copy(update={"hypotheses": ()}),
            )
        )


def test_service_revalidates_request_and_uses_trusted_clock() -> None:
    request = _request()
    forged_binding = request.context_binding.model_copy(update={"dependency_paths": ()})
    forged_request = request.model_copy(update={"context_binding": forged_binding})
    service = _test_service(request)

    with pytest.raises(ValueError):
        service.correlate(forged_request)

    object.__setattr__(
        service,
        "_clock",
        lambda: request.expires_at + timedelta(milliseconds=1),
    )
    with pytest.raises(ValueError, match="outside its validity window"):
        service.correlate(request)


def test_verification_rejects_untrusted_rule_catalog() -> None:
    assert _request().rule_catalog_digest == CORRELATION_RULE_CATALOG_DIGEST
    request = _request(rule_catalog_digest="sha256:" + "f" * 64)
    service = _test_service(request)

    with pytest.raises(ValueError, match="trusted engine catalog"):
        service.correlate(request)


def test_verification_rejects_case_insensitive_change_path_collisions() -> None:
    with pytest.raises(RuntimeError, match="normalized change evidence is invalid"):
        _change_pair(
            changed_properties={
                "properties.Access": ("Allow", "Deny"),
                "properties.access": ("Deny", "Allow"),
            }
        )


def test_verification_rejects_rule_from_different_enforcement_nsg() -> None:
    artifact, _ = _change_pair()
    other_nsg_id = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/rg-synthetic-wc026/providers/Microsoft.Network/"
        "networkSecurityGroups/synthetic-other-nsg"
    ).lower()
    path = _dependency_path(
        resource_ids=(
            WEB_ID.lower(),
            DB_ID.lower(),
            NSG_ID.lower(),
            NSG_RULE_ID.lower(),
            other_nsg_id,
        )
    )
    with pytest.raises(ValueError, match="must belong to enforcementResourceId"):
        _nsg_bundle(
            matched_change_key=artifact.evidence.change_key,
            matched_change_evidence_id=artifact.evidence.evidence_id,
            matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
            enforcement_resource_id=other_nsg_id,
            path_override=path,
        )


def test_verification_rejects_modified_publication_authority_blob() -> None:
    request = _request()
    reader = _ArtifactReader(request)
    reference = request.context_binding.publication_authority_reference
    reader._payloads[(reference.name, reference.version)] = b"{}"
    service = _test_service(request)
    object.__setattr__(service, "authority_reader", reader)

    with pytest.raises(ValueError, match="publication authority Blob bytes"):
        service.correlate(request)


def test_verification_rejects_narrowed_incident_interval() -> None:
    base_bundle = _bundle()
    incident = next(
        item for item in base_bundle.observations if getattr(item, "state", None) == "unhealthy"
    )
    overlapping = _bound_observation(
        observedStart=incident.observed_start - timedelta(minutes=1),
        observedEnd=incident.observed_start + timedelta(minutes=1),
        sourceRootReference="azure-monitor-source:sha256:" + "5" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "5" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, overlapping),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=incident.observation_id,
    )

    with pytest.raises(ValueError, match="complete current-state evidence interval"):
        correlate_incident(request)


def test_verification_rejects_boundary_adjacent_incident_evidence_omission() -> None:
    base_bundle = _bundle()
    incident = next(
        item for item in base_bundle.observations if getattr(item, "state", None) == "unhealthy"
    )
    adjacent = _bound_observation(
        observedStart=incident.observed_end,
        observedEnd=incident.observed_end,
        sourceRootReference="azure-monitor-source:sha256:" + "6" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "6" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, adjacent),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=incident.observation_id,
    )

    with pytest.raises(ValueError, match="complete current-state evidence interval"):
        correlate_incident(request)


def test_verification_rejects_disconnected_incident_evidence() -> None:
    base_bundle = _bundle()
    incident = next(
        item for item in base_bundle.observations if getattr(item, "state", None) == "unhealthy"
    )
    previous = _bound_observation(
        observedStart=incident.observed_start - timedelta(minutes=5),
        observedEnd=incident.observed_start - timedelta(minutes=4),
        state="healthy",
        summaryCode="guest.heartbeat-healthy",
        sourceRecordReference="azure-monitor:sha256:" + "3" * 64,
    )
    disconnected = _bound_observation(
        observedStart=incident.observed_start - timedelta(minutes=3),
        observedEnd=incident.observed_start - timedelta(minutes=2),
        sourceRootReference="azure-monitor-source:sha256:" + "4" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "4" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (previous, disconnected, incident),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_ids=(
            disconnected.observation_id,
            incident.observation_id,
        ),
    )

    with pytest.raises(ValueError, match="disconnected intervals"):
        correlate_incident(request)


def test_different_health_stream_cannot_bridge_disconnected_evidence() -> None:
    previous = _bound_observation(
        observedStart=NOW - timedelta(minutes=10),
        observedEnd=NOW - timedelta(minutes=9),
        state="healthy",
        summaryCode="guest.heartbeat-healthy",
        sourceRecordReference="azure-monitor:sha256:" + "1" * 64,
    )
    first_guest = _bound_observation(
        observedStart=NOW - timedelta(minutes=8),
        observedEnd=NOW - timedelta(minutes=6),
        sourceRecordReference="azure-monitor:sha256:" + "2" * 64,
    )
    second_guest = _bound_observation(
        observedStart=NOW - timedelta(minutes=4),
        observedEnd=NOW,
        sourceRecordReference="azure-monitor:sha256:" + "3" * 64,
    )
    bridging_endpoint = _endpoint_health_observation(
        path=_dependency_path(),
        observed_start=NOW - timedelta(minutes=7),
        observed_end=NOW - timedelta(minutes=3),
        status="unhealthy",
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (
                    previous,
                    first_guest,
                    second_guest,
                    bridging_endpoint,
                ),
                key=lambda item: item.observation_id,
            )
        )
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_ids=(
            first_guest.observation_id,
            second_guest.observation_id,
            bridging_endpoint.observation_id,
        ),
    )

    with pytest.raises(ValueError, match="disconnected intervals"):
        correlate_incident(request)


def test_public_service_rejects_untrusted_verifier_implementations() -> None:
    request = _request()

    with pytest.raises(TypeError, match="production correlation requires"):
        CorrelationService(
            monitoring_reader=cast(Any, _ArtifactReader(request)),
            change_reader=cast(Any, _ArtifactReader(request)),
            authority_reader=cast(Any, _ArtifactReader(request)),
            monitoring_verifier=cast(Any, _MonitoringVerifier([])),
            change_verifier=cast(Any, _ChangeVerifier([])),
        )


def test_public_service_requires_separate_reader_identities() -> None:
    shared_identity = "00000000-0000-0000-0000-000000000001"

    with pytest.raises(ValueError, match="reader identities must be distinct"):
        CorrelationService(
            monitoring_reader=_production_reader_stub(
                container_name="monitoring",
                managed_identity_client_id=shared_identity,
                required_prefix="wc024-monitoring/",
            ),
            change_reader=_production_reader_stub(
                container_name="changes",
                managed_identity_client_id=shared_identity,
                required_prefix="change-evidence/",
            ),
            authority_reader=_production_reader_stub(
                container_name="authority",
                managed_identity_client_id=shared_identity,
                required_prefix="context-authority/",
            ),
            monitoring_verifier=object.__new__(TrustedMonitoringHandoffVerifier),
            change_verifier=object.__new__(TrustedChangeArtifactVerifier),
        )


def test_public_service_requires_separate_storage_containers() -> None:
    with pytest.raises(ValueError, match="storage containers must be distinct"):
        CorrelationService(
            monitoring_reader=_production_reader_stub(
                container_name="shared",
                managed_identity_client_id="00000000-0000-0000-0000-000000000001",
                required_prefix="wc024-monitoring/",
            ),
            change_reader=_production_reader_stub(
                container_name="shared",
                managed_identity_client_id="00000000-0000-0000-0000-000000000002",
                required_prefix="change-evidence/",
            ),
            authority_reader=_production_reader_stub(
                container_name="shared",
                managed_identity_client_id="00000000-0000-0000-0000-000000000003",
                required_prefix="context-authority/",
            ),
            monitoring_verifier=object.__new__(TrustedMonitoringHandoffVerifier),
            change_verifier=object.__new__(TrustedChangeArtifactVerifier),
        )


def test_public_service_rejects_draft_preview_requests() -> None:
    request = _request(binding_mode="draftPreview")
    service = object.__new__(CorrelationService)

    with pytest.raises(ValueError, match="published runtime context"):
        service.correlate(request)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (29, "Unknown"),
        (30, "Low"),
        (54, "Low"),
        (55, "Medium"),
        (74, "Medium"),
        (75, "High"),
        (89, "High"),
        (90, "High"),
    ],
)
def test_confidence_thresholds_are_exact(score: int, expected: str) -> None:
    assert classify_confidence(score) == expected


def test_confirmed_requires_explicit_causal_gate_result() -> None:
    assert classify_confidence(100) == "High"
    assert classify_confidence(90, confirmed=True) == "Confirmed"
    assert classify_confidence(100, hard_conflict=True) == "Unknown"


def test_runtime_rule_tables_are_immutable() -> None:
    with pytest.raises(TypeError):
        cast(dict[str, int], _SCORE_WEIGHTS)["observationSemantic"] = 0


def test_catalog_digest_binds_temporal_windows_and_routing_paths() -> None:
    temporal_catalog = replace(
        CORRELATION_RULE_CATALOG,
        temporal_score_windows=((301, 20), *CORRELATION_RULE_CATALOG.temporal_score_windows[1:]),
    )
    routing_catalog = replace(
        CORRELATION_RULE_CATALOG,
        routing_property_paths=(
            *CORRELATION_RULE_CATALOG.routing_property_paths,
            "properties.syntheticroutefield",
        ),
    )

    assert (
        compute_artifact_digest(temporal_catalog.canonical_payload())
        != CORRELATION_RULE_CATALOG_DIGEST
    )
    assert (
        compute_artifact_digest(routing_catalog.canonical_payload())
        != CORRELATION_RULE_CATALOG_DIGEST
    )


def test_catalog_digest_guard_rejects_runtime_mutation() -> None:
    original = CORRELATION_RULE_CATALOG.maximum_candidate_hypotheses
    object.__setattr__(
        CORRELATION_RULE_CATALOG,
        "maximum_candidate_hypotheses",
        original + 1,
    )
    try:
        with pytest.raises(RuntimeError, match="catalog was mutated"):
            assert_catalog_digest()
    finally:
        object.__setattr__(
            CORRELATION_RULE_CATALOG,
            "maximum_candidate_hypotheses",
            original,
        )


def test_adverse_observations_are_indexed_once_per_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    original = correlation_engine._is_adverse_observation
    calls = 0

    def counting_classifier(observation: object) -> bool:
        nonlocal calls
        calls += 1
        return original(observation)

    monkeypatch.setattr(
        correlation_engine,
        "_is_adverse_observation",
        counting_classifier,
    )

    correlate_incident(request)

    assert calls == len(request.monitoring_bundle.observations)


def test_candidate_budget_fails_closed_before_hypothesis_materialization() -> None:
    request = _request(change_pair=_change_pair())

    with pytest.raises(ValueError, match="candidate budget exceeded"):
        _enforce_candidate_budget(request, maximum=1)
    with pytest.raises(ValueError, match="candidate budget exceeded"):
        _enforce_candidate_budget(
            request,
            maximum=4096,
            maximum_work_units=1,
        )


def test_default_guest_health_change_is_conservative_and_deterministic() -> None:
    request = _request()

    first = correlate_incident(_verified(request))
    second = correlate_incident(_verified(request))

    assert first == second
    assert first.report_digest == second.report_digest
    assert [(item.category, item.confidence) for item in first.hypotheses] == [
        ("guestServiceFailure", "Low")
    ]
    assert {item.code for item in first.hypotheses[0].caps} == {
        "missingAffectedPath",
        "missingDirectAttribution",
        "missingIndependentSupport",
    }


def test_golden_nsg_connectivity_loss_is_confirmed() -> None:
    artifact, handoff = _change_pair()
    bundle, flow, monitor, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    report = correlate_incident(_verified(request))
    hypothesis = report.hypotheses[0]

    assert hypothesis.category == "networkSecurityChange"
    assert hypothesis.confidence == "Confirmed"
    assert hypothesis.score.raw_score == 90
    assert hypothesis.cause_resource_id == artifact.evidence.target_resource_id
    assert {item.evidence_id for item in hypothesis.supporting_evidence} >= {
        artifact.evidence.evidence_id,
        flow.observation_id,
        monitor.observation_id,
        endpoint.observation_id,
    }
    assert {item.code for item in hypothesis.gates} == {
        "affectedPath",
        "connectionMonitorFailure",
        "correctChronology",
        "effectiveRuleAttribution",
        "endpointDegradation",
        "independentCorroboration",
        "matchingDeniedFlow",
        "noHardConflict",
        "semanticMatch",
        "successfulChange",
    }


def test_nsg_without_direct_attribution_is_capped_at_high() -> None:
    artifact, handoff = _change_pair()
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        effective_rule_attribution=False,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.category == "networkSecurityChange"
    assert hypothesis.confidence == "High"
    assert "effectiveRuleAttribution" in {item.code for item in hypothesis.missing_evidence}
    assert ("missingDirectAttribution", "High") in {
        (item.code, item.maximum_confidence) for item in hypothesis.caps
    }


def test_non_attributed_flow_matches_parent_nsg_without_rule_id() -> None:
    artifact, handoff = _change_pair()
    path = _dependency_path()
    flow = _network_flow_observation(
        path=path,
        effective_rule_attribution=False,
        include_rule_resource_id=False,
    )
    monitor = _connection_monitor_observation(
        path=path,
        five_tuple_digest=flow.five_tuple_digest,
    )
    endpoint = _endpoint_health_observation(path=path)
    previous_endpoint = _endpoint_health_observation(
        path=path,
        observed_start=NOW - timedelta(minutes=10),
        observed_end=NOW - timedelta(minutes=5),
        status="healthy",
    )
    flow_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                {
                    WEB_ID.lower(),
                    DB_ID.lower(),
                    NSG_ID.lower(),
                }
            )
        ),
        pathId=flow.path_id,
        direction=flow.direction,
        fiveTupleDigest=flow.five_tuple_digest,
    )
    monitor_scope = _coverage_scope(
        resourceIds=tuple(sorted({WEB_ID.lower(), DB_ID.lower()})),
        pathId=monitor.path_id,
        direction=monitor.direction,
        fiveTupleDigest=monitor.five_tuple_digest,
        endpointTestReference=monitor.test_configuration_reference,
        endpointTestDigest=monitor.test_configuration_digest,
    )
    endpoint_scope = _coverage_scope(
        resourceIds=tuple(sorted({WEB_ID.lower(), DB_ID.lower()})),
        pathId=endpoint.path_id,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (flow, monitor, previous_endpoint, endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=tuple(
            sorted(
                (
                    _coverage(family="networkFlow", scope=flow_scope),
                    _coverage(family="connectionMonitor", scope=monitor_scope),
                    _coverage(family="endpointHealth", scope=endpoint_scope),
                ),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        ),
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(request).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "High"
    assert flow.observation_id in {item.evidence_id for item in hypothesis.supporting_evidence}


def test_explicit_sibling_nsg_rule_does_not_match_changed_rule() -> None:
    artifact, handoff = _change_pair()
    sibling_rule_id = f"{NSG_ID}/securityRules/allow-other"
    path = _dependency_path(
        resource_ids=(
            WEB_ID.lower(),
            DB_ID.lower(),
            NSG_ID.lower(),
            NSG_RULE_ID.lower(),
            sibling_rule_id.lower(),
        )
    )
    bundle, flow, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        effective_rule_attribution=False,
        rule_resource_id=sibling_rule_id,
        path_override=path,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
        dependency_paths=(path,),
    )

    hypothesis = next(
        item
        for item in correlate_incident(request).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Low"
    assert flow.observation_id not in {item.evidence_id for item in hypothesis.supporting_evidence}


def test_nsg_noncausal_property_change_cannot_reach_high_confidence() -> None:
    artifact, handoff = _change_pair(
        changed_property_path="tags.owner",
        previous_value="synthetic-team-a",
        new_value="synthetic-team-b",
    )
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        effective_rule_attribution=False,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Medium"
    assert hypothesis.score.semantic == 0
    assert "semanticMatch" not in {item.code for item in hypothesis.gates}


def test_nsg_non_numeric_property_index_is_not_treated_as_causal() -> None:
    artifact, handoff = _change_pair(
        changed_property_path="properties.access[foo]",
        previous_value="Allow",
        new_value="Deny",
    )
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        effective_rule_attribution=False,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Medium"
    assert hypothesis.score.semantic == 0
    assert "semanticMatch" not in {item.code for item in hypothesis.gates}


def test_nsg_chain_preserves_attributed_counterevidence_when_selecting_support() -> None:
    artifact, handoff = _change_pair()
    bundle, direct_flow, direct_monitor, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    allowed_direct_flow = _network_flow_observation(
        path=_dependency_path(),
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        decision="allowed",
        source_seed="6",
    )
    unconflicted_flow = _network_flow_observation(
        path=_dependency_path(),
        direction="outbound",
        source_seed="7",
        effective_rule_attribution=False,
    )
    unconflicted_monitor = _connection_monitor_observation(
        path=_dependency_path(),
        five_tuple_digest=unconflicted_flow.five_tuple_digest,
        direction="outbound",
        source_seed="8",
    )
    flow_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                {
                    WEB_ID.lower(),
                    DB_ID.lower(),
                    NSG_ID.lower(),
                    NSG_RULE_ID.lower(),
                }
            )
        ),
        pathId=unconflicted_flow.path_id,
        direction=unconflicted_flow.direction,
        fiveTupleDigest=unconflicted_flow.five_tuple_digest,
    )
    monitor_scope = _coverage_scope(
        resourceIds=tuple(sorted({WEB_ID.lower(), DB_ID.lower()})),
        pathId=unconflicted_monitor.path_id,
        direction=unconflicted_monitor.direction,
        fiveTupleDigest=unconflicted_monitor.five_tuple_digest,
        endpointTestReference=unconflicted_monitor.test_configuration_reference,
        endpointTestDigest=unconflicted_monitor.test_configuration_digest,
    )
    combined = _bundle(
        observations=tuple(
            sorted(
                (
                    *bundle.observations,
                    allowed_direct_flow,
                    unconflicted_flow,
                    unconflicted_monitor,
                ),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=tuple(
            sorted(
                (
                    *bundle.coverage,
                    _coverage(family="networkFlow", scope=flow_scope),
                    _coverage(family="connectionMonitor", scope=monitor_scope),
                ),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        ),
    )
    request = _request(
        bundle_override=combined,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypotheses = [
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    ]
    selected = next(
        item
        for item in hypotheses
        if unconflicted_flow.observation_id
        in {citation.evidence_id for citation in item.supporting_evidence}
    )
    conflicted = next(
        item
        for item in hypotheses
        if direct_flow.observation_id
        in {citation.evidence_id for citation in item.supporting_evidence}
    )

    assert selected.confidence == "High"
    assert selected.score.semantic == 14
    assert unconflicted_monitor.observation_id in {
        item.evidence_id for item in selected.supporting_evidence
    }
    assert "completeAllowedFlow" not in {item.code for item in selected.contradictions}
    assert conflicted.confidence == "Unknown"
    assert direct_monitor.observation_id in {
        item.evidence_id for item in conflicted.supporting_evidence
    }
    assert "completeAllowedFlow" in {item.code for item in conflicted.contradictions}


def test_nsg_chain_prefers_post_change_monitor_and_endpoint() -> None:
    artifact, handoff = _change_pair()
    bundle, _, current_monitor, current_endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    historical_monitor = _connection_monitor_observation(
        path=_dependency_path(),
        five_tuple_digest=current_monitor.five_tuple_digest,
        observed_start=current_monitor.observed_start - timedelta(minutes=3),
        observed_end=current_monitor.observed_end - timedelta(minutes=3),
        source_seed="1",
    )
    historical_endpoint = _endpoint_health_observation(
        path=_dependency_path(),
        observed_start=current_endpoint.observed_start - timedelta(minutes=3),
        observed_end=current_endpoint.observed_start,
        status="degraded",
    )
    assert historical_monitor.observation_id < current_monitor.observation_id
    combined = _bundle(
        observations=tuple(
            sorted(
                (
                    *bundle.observations,
                    historical_monitor,
                    historical_endpoint,
                ),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=combined,
        incident_evidence_id=current_endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )
    support_ids = {item.evidence_id for item in hypothesis.supporting_evidence}

    assert hypothesis.confidence == "Confirmed"
    assert current_monitor.observation_id in support_ids
    assert current_endpoint.observation_id in support_ids
    assert historical_monitor.observation_id not in support_ids
    assert historical_endpoint.observation_id not in support_ids


def test_standalone_network_failure_produces_dependency_hypothesis() -> None:
    bundle, flow, monitor, endpoint = _nsg_bundle(
        matched_change_key="sha256:" + "c" * 64,
        matched_change_evidence_id="chg-000000000000",
        matched_change_artifact_digest="sha256:" + "c" * 64,
        effective_rule_attribution=False,
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "dependencyFailure"
    )

    assert hypothesis.confidence == "Medium"
    assert hypothesis.affected_path_id == flow.path_id
    assert hypothesis.cause_resource_id == flow.destination_resource_id
    assert {item.evidence_id for item in hypothesis.supporting_evidence} >= {
        flow.observation_id,
        monitor.observation_id,
        endpoint.observation_id,
    }


def test_recent_change_without_causal_monitoring_stays_low() -> None:
    artifact, handoff = _change_pair()
    request = _request(change_pair=(artifact, handoff))

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Low"
    assert "recentChangeOnly" in {item.code for item in hypothesis.caps}


def test_exact_allowed_flow_counterevidence_forces_unknown() -> None:
    artifact, handoff = _change_pair()
    bundle, denied_flow, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    allowed_flow = _network_flow_observation(
        path=_dependency_path(),
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        decision="allowed",
        source_seed="6",
    )
    contradictory_bundle = _bundle(
        observations=tuple(
            sorted(
                (*bundle.observations, allowed_flow),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=contradictory_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Unknown"
    assert "completeAllowedFlow" in {item.code for item in hypothesis.contradictions}
    assert denied_flow.observation_id in {
        item.evidence_id for item in hypothesis.supporting_evidence
    }


def test_allowed_flow_from_sibling_rule_is_not_counterevidence() -> None:
    artifact, handoff = _change_pair()
    sibling_rule_id = f"{NSG_ID}/securityRules/allow-other"
    path = _dependency_path(
        resource_ids=(
            WEB_ID.lower(),
            DB_ID.lower(),
            NSG_ID.lower(),
            NSG_RULE_ID.lower(),
            sibling_rule_id.lower(),
        )
    )
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
        path_override=path,
    )
    sibling_allowed = _network_flow_observation(
        path=path,
        decision="allowed",
        source_seed="6",
        effective_rule_attribution=False,
        rule_resource_id=sibling_rule_id,
    )
    sibling_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                {
                    WEB_ID.lower(),
                    DB_ID.lower(),
                    NSG_ID.lower(),
                    sibling_rule_id.lower(),
                }
            )
        ),
        pathId=path.path_id,
        direction=sibling_allowed.direction,
        fiveTupleDigest=sibling_allowed.five_tuple_digest,
    )
    contradictory_bundle = _bundle(
        observations=tuple(
            sorted(
                (*bundle.observations, sibling_allowed),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=tuple(
            sorted(
                (
                    *bundle.coverage,
                    _coverage(family="networkFlow", scope=sibling_scope),
                ),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        ),
    )
    request = _request(
        bundle_override=contradictory_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
        dependency_paths=(path,),
    )

    hypothesis = next(
        item
        for item in correlate_incident(request).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert "completeAllowedFlow" not in {item.code for item in hypothesis.contradictions}


def test_missing_connection_monitor_blocks_confirmation() -> None:
    artifact, handoff = _change_pair()
    bundle, _, monitor, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    without_monitor = _bundle(
        observations=tuple(
            item for item in bundle.observations if item.observation_id != monitor.observation_id
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=without_monitor,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = correlate_incident(_verified(request)).hypotheses[0]

    assert hypothesis.confidence == "High"
    assert "connectionMonitorResult" in {item.code for item in hypothesis.missing_evidence}


def test_exact_healthy_monitor_counterevidence_cannot_be_skipped() -> None:
    artifact, handoff = _change_pair()
    bundle, flow, failed_monitor, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    healthy_monitor = _connection_monitor_observation(
        path=_dependency_path(),
        five_tuple_digest=flow.five_tuple_digest,
        status="succeeded",
        source_seed="9",
    )
    contradictory_bundle = _bundle(
        observations=tuple(
            sorted(
                (*bundle.observations, healthy_monitor),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=contradictory_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )

    assert hypothesis.confidence == "Unknown"
    assert failed_monitor.observation_id in {
        item.evidence_id for item in hypothesis.supporting_evidence
    }
    assert "completeHealthyConnectionMonitor" in {item.code for item in hypothesis.contradictions}


def test_degraded_monitor_alone_does_not_create_dependency_cause() -> None:
    base_bundle = _bundle()
    monitor = _connection_monitor_observation(
        path=_dependency_path(),
        status="degraded",
        observed_start=NOW - timedelta(minutes=5),
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, monitor),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(_verified(_request(bundle_override=bundle)))

    assert all(item.category != "dependencyFailure" for item in report.hypotheses)


def test_post_incident_observation_is_not_a_causal_candidate() -> None:
    base_bundle = _bundle()
    later = _bound_observation(
        subjectResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-synthetic-wc026/providers/Microsoft.Compute/"
            "virtualMachines/synthetic-later-01"
        ).lower(),
        observedStart=base_bundle.observed_end - timedelta(minutes=1),
        observedEnd=base_bundle.observed_end,
        signal="cpuSaturation",
        summaryCode="guest.cpu-saturation",
        sourceRootReference="azure-monitor-source:sha256:" + "9" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "9" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, later),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(_verified(_request(bundle_override=bundle)))

    assert all(item.cause_resource_id != later.subject_resource_id for item in report.hypotheses)


def test_unconnected_guest_observation_is_not_a_root_cause_candidate() -> None:
    base_bundle = _bundle()
    unconnected = _bound_observation(
        subjectResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-synthetic-wc026/providers/Microsoft.Compute/"
            "virtualMachines/synthetic-unconnected-01"
        ).lower(),
        signal="cpuSaturation",
        summaryCode="guest.cpu-saturation",
        sourceRootReference="azure-monitor-source:sha256:" + "6" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "6" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, unconnected),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(_verified(_request(bundle_override=bundle)))

    assert all(
        item.cause_resource_id != unconnected.subject_resource_id for item in report.hypotheses
    )


def test_boundary_touching_endpoint_is_not_a_causal_candidate() -> None:
    base_bundle = _bundle()
    stale_endpoint = _endpoint_health_observation(
        path=_dependency_path(),
        observed_start=NOW - timedelta(minutes=10),
        observed_end=NOW - timedelta(minutes=5),
        status="degraded",
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, stale_endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(_verified(_request(bundle_override=bundle)))

    assert all(item.category != "backendHealth" for item in report.hypotheses)


def test_shared_resource_paths_do_not_splice_path_specific_evidence() -> None:
    paths = tuple(
        sorted(
            (
                _dependency_path(),
                _dependency_path(
                    source_role_ref="web-secondary",
                    relationship_id="relationship-web-db-secondary",
                ),
            ),
            key=lambda item: item.path_id,
        )
    )
    selected_path, other_path = paths
    flow = _network_flow_observation(
        path=other_path,
        observed_start=NOW - timedelta(minutes=5),
        effective_rule_attribution=False,
    )
    flow_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                {
                    WEB_ID.lower(),
                    DB_ID.lower(),
                    NSG_ID.lower(),
                    NSG_RULE_ID.lower(),
                }
            )
        ),
        pathId=flow.path_id,
        direction=flow.direction,
        fiveTupleDigest=flow.five_tuple_digest,
    )
    base_bundle = _bundle()
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, flow),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=tuple(
            sorted(
                (*base_bundle.coverage, _coverage(family="networkFlow", scope=flow_scope)),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        ),
    )
    request = _request(
        bundle_override=bundle,
        dependency_paths=paths,
    )

    report = correlate_incident(_verified(request))
    guest = next(item for item in report.hypotheses if item.category == "guestServiceFailure")

    assert selected_path.path_id != other_path.path_id
    assert flow.observation_id not in {item.evidence_id for item in guest.supporting_evidence}
    assert guest.affected_path_id is None


def test_monitor_only_dependency_evidence_fails_closed_without_path_gate() -> None:
    base_bundle = _bundle()
    path = _dependency_path()
    monitor = _connection_monitor_observation(
        path=path,
        observed_start=NOW - timedelta(minutes=5),
        observed_end=NOW,
    )
    monitor_scope = _coverage_scope(
        resourceIds=tuple(sorted({WEB_ID.lower(), DB_ID.lower()})),
        pathId=monitor.path_id,
        direction=monitor.direction,
        fiveTupleDigest=monitor.five_tuple_digest,
        endpointTestReference=monitor.test_configuration_reference,
        endpointTestDigest=monitor.test_configuration_digest,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, monitor),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=tuple(
            sorted(
                (*base_bundle.coverage, _coverage(family="connectionMonitor", scope=monitor_scope)),
                key=lambda item: (
                    item.family,
                    item.coverage_start.isoformat(),
                    item.coverage_end.isoformat(),
                    item.scope.scope_digest,
                ),
            )
        ),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(_request(bundle_override=bundle))).hypotheses
        if item.category == "dependencyFailure"
    )

    assert hypothesis.confidence == "Low"
    assert "affectedPath" not in {item.code for item in hypothesis.gates}
    assert ("missingAffectedPath", "Low") in {
        (item.code, item.maximum_confidence) for item in hypothesis.caps
    }


def test_recovery_observation_contributes_auditable_score() -> None:
    base_bundle = _bundle()
    recovered = _bound_observation(
        observedStart=base_bundle.observed_end,
        observedEnd=base_bundle.observed_end,
        state="recovered",
        summaryCode="guest.heartbeat-recovered",
        sourceRootReference="azure-monitor-source:sha256:" + "8" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "8" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, recovered),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    hypothesis = correlate_incident(_verified(_request(bundle_override=bundle))).hypotheses[0]

    assert hypothesis.score.recovery == 4
    assert recovered.observation_id in {item.evidence_id for item in hypothesis.supporting_evidence}


def test_unrelated_recovery_signal_does_not_contribute_score() -> None:
    base_bundle = _bundle()
    unrelated_recovery = _bound_observation(
        observedStart=base_bundle.observed_end,
        observedEnd=base_bundle.observed_end,
        signal="cpuSaturation",
        state="recovered",
        summaryCode="guest.cpu-recovered",
        sourceRootReference="azure-monitor-source:sha256:" + "7" * 64,
        sourceRecordReference="azure-monitor:sha256:" + "7" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, unrelated_recovery),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    hypothesis = correlate_incident(_verified(_request(bundle_override=bundle))).hypotheses[0]

    assert hypothesis.score.recovery == 0
    assert "recoveryEvidence" not in {item.code for item in hypothesis.gates}


def test_recovery_must_start_after_the_exact_degraded_observation() -> None:
    previous = _bound_observation(
        observedStart=NOW - timedelta(minutes=10),
        observedEnd=NOW - timedelta(minutes=5),
        state="healthy",
        summaryCode="guest.heartbeat-healthy",
        sourceRecordReference="azure-monitor:sha256:" + "1" * 64,
    )
    long_degradation = _bound_observation(
        observedStart=NOW - timedelta(minutes=5),
        observedEnd=NOW,
        sourceRecordReference="azure-monitor:sha256:" + "2" * 64,
    )
    overlapping_recovery = _bound_observation(
        observedStart=NOW - timedelta(seconds=30),
        observedEnd=NOW,
        state="recovered",
        summaryCode="guest.heartbeat-recovered",
        sourceRecordReference="azure-monitor:sha256:" + "4" * 64,
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (
                    previous,
                    long_degradation,
                    overlapping_recovery,
                ),
                key=lambda item: item.observation_id,
            )
        )
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=long_degradation.observation_id,
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.candidate_causal_at == long_degradation.observed_start
    )

    assert hypothesis.score.recovery == 0
    assert overlapping_recovery.observation_id not in {
        item.evidence_id for item in hypothesis.supporting_evidence
    }


def test_corrective_recovery_requires_the_exact_same_property_set() -> None:
    candidate, _ = _change_pair()
    reversal, _ = _change_pair(previous_value="Deny", new_value="Allow")
    additional, _ = _change_pair(
        changed_property_path="properties.priority",
        previous_value="100",
        new_value="200",
    )
    case_variant, _ = _change_pair(
        changed_property_path="properties.Access",
        previous_value="Allow",
        new_value="Deny",
    )
    expanded_reversal = reversal.model_copy(
        update={
            "evidence": reversal.evidence.model_copy(
                update={
                    "changed_properties": tuple(
                        sorted(
                            (
                                *reversal.evidence.changed_properties,
                                *additional.evidence.changed_properties,
                            ),
                            key=lambda item: item.path,
                        )
                    )
                }
            )
        }
    )
    collision_candidate = candidate.model_copy(
        update={
            "evidence": candidate.evidence.model_copy(
                update={
                    "changed_properties": tuple(
                        sorted(
                            (
                                *candidate.evidence.changed_properties,
                                *case_variant.evidence.changed_properties,
                            ),
                            key=lambda item: item.path,
                        )
                    )
                }
            )
        }
    )

    assert _is_exact_corrective_change(candidate, reversal)
    assert not _is_exact_corrective_change(candidate, expanded_reversal)
    assert not _is_exact_corrective_change(collision_candidate, reversal)


def test_exact_corrective_recovery_is_auditable_without_becoming_causal() -> None:
    candidate_pair = _change_pair()
    corrective_pair = _change_pair(
        previous_value="Deny",
        new_value="Allow",
        change_suffix="002",
        correlation_id="22222222-2222-2222-2222-222222222222",
        occurred_at=NOW - timedelta(minutes=1),
    )
    candidate, _ = candidate_pair
    bundle, _, monitor, endpoint = _nsg_bundle(
        matched_change_key=candidate.evidence.change_key,
        matched_change_evidence_id=candidate.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(candidate.canonical_bytes()),
    )
    recovered = _endpoint_health_observation(
        path=_dependency_path(),
        observed_start=NOW,
        observed_end=NOW,
        status="recovered",
    )
    recovery_bundle = _bundle(
        observations=tuple(
            sorted(
                (
                    *(
                        item
                        for item in bundle.observations
                        if item.observation_id != monitor.observation_id
                    ),
                    recovered,
                ),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=recovery_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pairs=(candidate_pair, corrective_pair),
    )

    hypothesis = next(
        item
        for item in correlate_incident(request).hypotheses
        if item.category == "networkSecurityChange"
        and item.candidate_causal_at == candidate.evidence.occurred_at
    )
    recovery_gate = next(item for item in hypothesis.gates if item.code == "recoveryEvidence")

    assert hypothesis.confidence == "High"
    assert hypothesis.score.recovery == 10
    assert set(recovery_gate.evidence_ids) == {
        corrective_pair[0].evidence.evidence_id,
        recovered.observation_id,
    }
    assert corrective_pair[0].evidence.evidence_id not in {
        item.evidence_id for item in hypothesis.supporting_evidence
    }


def test_many_matching_counterevidence_records_are_aggregated() -> None:
    artifact, handoff = _change_pair()
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    allowed_flows = tuple(
        _network_flow_observation(
            path=_dependency_path(),
            matched_change_key=artifact.evidence.change_key,
            matched_change_evidence_id=artifact.evidence.evidence_id,
            matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
            decision="allowed",
            observed_start=NOW - timedelta(minutes=4, milliseconds=index),
            source_seed="6",
        )
        for index in range(65)
    )
    combined = _bundle(
        observations=tuple(
            sorted(
                (*bundle.observations, *allowed_flows),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=combined,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    hypothesis = next(
        item
        for item in correlate_incident(_verified(request)).hypotheses
        if item.category == "networkSecurityChange"
    )
    allowed_contradictions = [
        item for item in hypothesis.contradictions if item.code == "completeAllowedFlow"
    ]

    assert hypothesis.confidence == "Unknown"
    assert len(allowed_contradictions) == 1
    assert "65 exact allowed flow record(s)" in allowed_contradictions[0].detail


def test_report_capacity_is_bounded_and_omissions_are_disclosed() -> None:
    base_bundle = _bundle()
    extra_resource_ids = tuple(
        (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-synthetic-wc026/providers/Microsoft.Compute/"
            f"virtualMachines/synthetic-extra-{index:03d}"
        ).lower()
        for index in range(70)
    )
    extra = tuple(
        _bound_observation(
            subjectResourceId=resource_id,
            signal="cpuSaturation",
            summaryCode="guest.cpu-saturation",
            sourceRecordReference=(f"azure-monitor:sha256:{index:064x}"),
        )
        for index, resource_id in enumerate(extra_resource_ids)
    )
    paths = tuple(
        sorted(
            (
                _dependency_path(),
                *(
                    _dependency_path(
                        source_role_ref="web",
                        target_role_ref=f"extra-{index:03d}",
                        relationship_id=f"relationship-web-extra-{index:03d}",
                        resource_ids=(WEB_ID.lower(), resource_id),
                    )
                    for index, resource_id in enumerate(extra_resource_ids)
                ),
            ),
            key=lambda item: item.path_id,
        )
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, *extra),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )

    report = correlate_incident(
        _verified(
            _request(
                bundle_override=bundle,
                dependency_paths=paths,
            )
        )
    )

    assert len(report.hypotheses) == 64
    assert report.hypotheses[-1].category == "unknown"
    assert "omitted" in report.hypotheses[-1].missing_evidence[0].detail


def test_rank_order_is_stable_for_multiple_candidates() -> None:
    artifact, handoff = _change_pair()
    bundle, _, _, endpoint = _nsg_bundle(
        matched_change_key=artifact.evidence.change_key,
        matched_change_evidence_id=artifact.evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(artifact.canonical_bytes()),
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=(artifact, handoff),
    )

    report = correlate_incident(_verified(request))

    assert [item.rank for item in report.hypotheses] == list(range(1, len(report.hypotheses) + 1))
    assert report.hypotheses[0].category == "networkSecurityChange"
    assert report.hypotheses[0].confidence == "Confirmed"


def test_hash_seed_does_not_change_report_digest(tmp_path: Path) -> None:
    request = _request()
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json(by_alias=True), encoding="utf-8")
    script = (
        "from pathlib import Path;"
        "from athena_context.contracts import CorrelationRequest;"
        "from test_wc026_correlation import _verified, correlate_incident;"
        f"r=CorrelationRequest.model_validate_json(Path(r'{request_path}').read_text());"
        "print(correlate_incident(_verified(r)).report_digest)"
    )
    digests: list[str] = []
    for seed in ("1", "7"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = os.pathsep.join(
            (
                str(Path(__file__).parents[1] / "src"),
                str(Path(__file__).parent),
            )
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env=environment,
        )
        digests.append(result.stdout.strip())

    assert len(set(digests)) == 1
