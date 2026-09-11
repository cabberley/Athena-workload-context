from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from types import MappingProxyType
from typing import cast

from athena_context.contracts.change_ingestion import ChangeEvidenceArtifact
from athena_context.contracts.common import compute_artifact_digest, sha256_hex
from athena_context.contracts.correlation import (
    ConfidenceCap,
    ConfidenceCapCode,
    ConfidenceLevel,
    ConnectionMonitorObservation,
    ContradictionCode,
    CorrelationContradiction,
    CorrelationEvidenceCitation,
    CorrelationGate,
    CorrelationGateCode,
    CorrelationRequest,
    CorrelationScoreComponents,
    DependencyPath,
    EndpointHealthObservation,
    EvidenceCoverage,
    EvidenceFamily,
    GuestSignalObservation,
    MissingCorrelationEvidence,
    MissingEvidenceCode,
    NetworkFlowObservation,
    PlatformHealthObservation,
    RootCauseCategory,
    RootCauseHypothesis,
)
from athena_context.correlation.rules import (
    CORRELATION_RULE_CATALOG,
    CORRELATION_RULE_CATALOG_DIGEST,
    assert_catalog_digest,
    assert_contract_compatibility,
)

assert_catalog_digest()
assert_contract_compatibility()

_CONFIDENCE_THRESHOLDS: Mapping[ConfidenceLevel, int] = MappingProxyType(
    dict(CORRELATION_RULE_CATALOG.confidence_thresholds)
)
_SCORE_WEIGHTS: Mapping[str, int] = MappingProxyType(dict(CORRELATION_RULE_CATALOG.score_weights))
_CAP_LEVELS: Mapping[ConfidenceCapCode, ConfidenceLevel] = MappingProxyType(
    cast(
        dict[ConfidenceCapCode, ConfidenceLevel],
        dict(CORRELATION_RULE_CATALOG.confidence_caps),
    )
)
_CONFIDENCE_RANK: Mapping[ConfidenceLevel, int] = MappingProxyType(
    {
        "Unknown": 0,
        **{
            confidence: index
            for index, (confidence, _) in enumerate(
                CORRELATION_RULE_CATALOG.confidence_thresholds,
                start=1,
            )
        },
    }
)
_CATEGORY_ORDER: Mapping[RootCauseCategory, int] = MappingProxyType(
    {category: index for index, category in enumerate(CORRELATION_RULE_CATALOG.category_order)}
)
_NSG_PROPERTY_PATHS = frozenset(CORRELATION_RULE_CATALOG.nsg_property_paths)
_CONFIDENCE_BY_RANK: Mapping[int, ConfidenceLevel] = MappingProxyType(
    {rank: name for name, rank in _CONFIDENCE_RANK.items()}
)


def classify_confidence(
    raw_score: int,
    *,
    caps: Iterable[ConfidenceCap] = (),
    hard_conflict: bool = False,
    confirmed: bool = False,
) -> ConfidenceLevel:
    if hard_conflict or raw_score < _CONFIDENCE_THRESHOLDS["Low"]:
        return "Unknown"
    if confirmed and raw_score >= _CONFIDENCE_THRESHOLDS["Confirmed"]:
        level: ConfidenceLevel = "Confirmed"
    elif raw_score >= _CONFIDENCE_THRESHOLDS["High"]:
        level = "High"
    elif raw_score >= _CONFIDENCE_THRESHOLDS["Medium"]:
        level = "Medium"
    else:
        level = "Low"
    cap_rank = min(
        (_CONFIDENCE_RANK[item.maximum_confidence] for item in caps),
        default=_CONFIDENCE_RANK["Confirmed"],
    )
    return _CONFIDENCE_BY_RANK[min(_CONFIDENCE_RANK[level], cap_rank)]


def _compute_hypotheses(
    request: CorrelationRequest,
    *,
    adverse_observation_ids: frozenset[str] | None = None,
    budget_prechecked: bool = False,
) -> tuple[RootCauseHypothesis, ...]:
    if type(request) is not CorrelationRequest:
        raise TypeError("correlation engine requires an exact CorrelationRequest")
    assert_catalog_digest()
    assert_contract_compatibility()
    if request.rule_catalog_digest != CORRELATION_RULE_CATALOG_DIGEST:
        raise ValueError("verified request does not match the engine rule catalog")
    citations = {item.evidence_id: item for item in request.evidence_index}
    paths = {item.path_id: item for item in request.context_binding.dependency_paths}
    observations = request.monitoring_bundle.observations
    observation_by_id = {item.observation_id: item for item in observations}
    selected_adverse_ids = (
        _adverse_observation_ids(request)
        if adverse_observation_ids is None
        else adverse_observation_ids
    )
    if not budget_prechecked:
        _enforce_candidate_budget(
            request,
            adverse_observation_ids=selected_adverse_ids,
        )
    hypotheses: list[RootCauseHypothesis] = []

    for artifact in request.change_artifacts:
        if artifact.evidence.occurred_at > request.incident_anchor.observed_start:
            continue
        if (
            artifact.evidence.target_resource_type.casefold()
            == "microsoft.network/networksecuritygroups/securityrules"
        ):
            hypotheses.extend(
                _network_security_hypotheses(
                    request=request,
                    artifact=artifact,
                    citations=citations,
                    paths=paths,
                )
            )
        else:
            hypotheses.append(
                _change_hypothesis(
                    request=request,
                    artifact=artifact,
                    citations=citations,
                    paths=paths,
                    observation_by_id=observation_by_id,
                    adverse_observation_ids=selected_adverse_ids,
                )
            )

    hypotheses.extend(
        _dependency_hypotheses(
            request=request,
            citations=citations,
            paths=paths,
        )
    )

    for observation in observations:
        if (
            observation.observed_start > request.incident_anchor.observed_start
            or not _strict_overlap(
                observation.observed_start,
                observation.observed_end,
                request.incident_anchor.observed_start,
                request.incident_anchor.observed_end,
            )
        ):
            continue
        if (
            isinstance(observation, GuestSignalObservation)
            and observation.state
            in {
                "degraded",
                "unhealthy",
                "unavailable",
            }
            and _observation_has_governed_connection(observation, request, paths)
        ):
            hypotheses.append(
                _guest_hypothesis(
                    request=request,
                    observation=observation,
                    citations=citations,
                    paths=paths,
                    observation_by_id=observation_by_id,
                    adverse_observation_ids=selected_adverse_ids,
                )
            )
        elif (
            isinstance(observation, PlatformHealthObservation)
            and observation.status
            in {
                "degraded",
                "unhealthy",
                "unavailable",
            }
            and _observation_has_governed_connection(observation, request, paths)
        ):
            hypotheses.append(
                _observation_hypothesis(
                    request=request,
                    observation=observation,
                    category="platformHealth",
                    citations=citations,
                    paths=paths,
                    observation_by_id=observation_by_id,
                    adverse_observation_ids=selected_adverse_ids,
                )
            )
        elif (
            isinstance(observation, EndpointHealthObservation)
            and observation.status
            in {
                "degraded",
                "unhealthy",
                "unavailable",
            }
            and (
                observation.path_id in paths
                and request.incident_anchor.affected_resource_id
                in paths[observation.path_id].resource_ids
            )
        ):
            hypotheses.append(
                _observation_hypothesis(
                    request=request,
                    observation=observation,
                    category="backendHealth",
                    citations=citations,
                    paths=paths,
                    observation_by_id=observation_by_id,
                    adverse_observation_ids=selected_adverse_ids,
                )
            )

    hypotheses = _deduplicate_hypotheses(hypotheses)
    if not hypotheses:
        hypotheses.append(_unknown_hypothesis(request))

    ordered = sorted(hypotheses, key=_hypothesis_sort_key)
    if len(ordered) > CORRELATION_RULE_CATALOG.maximum_hypotheses:
        retained_count = CORRELATION_RULE_CATALOG.maximum_hypotheses - 1
        omitted = ordered[retained_count:]
        ordered = [
            *ordered[:retained_count],
            _overflow_hypothesis(request, omitted),
        ]
    ranked = tuple(
        RootCauseHypothesis.model_validate(
            {
                **item.model_dump(mode="python", by_alias=True),
                "rank": index,
            }
        )
        for index, item in enumerate(ordered, start=1)
    )
    assert_catalog_digest()
    assert_contract_compatibility()
    return ranked


def _adverse_observation_ids(
    request: CorrelationRequest,
) -> frozenset[str]:
    return frozenset(
        item.observation_id
        for item in request.monitoring_bundle.observations
        if _is_adverse_observation(item)
    )


def _enforce_candidate_budget(
    request: CorrelationRequest,
    *,
    adverse_observation_ids: frozenset[str] | None = None,
    maximum: int | None = None,
    maximum_work_units: int | None = None,
) -> None:
    limit = CORRELATION_RULE_CATALOG.maximum_candidate_hypotheses if maximum is None else maximum
    work_limit = (
        CORRELATION_RULE_CATALOG.maximum_evaluation_work_units
        if maximum_work_units is None
        else maximum_work_units
    )
    if type(limit) is not int or limit < 1:
        raise ValueError("correlation candidate limit must be a positive integer")
    if type(work_limit) is not int or work_limit < 1:
        raise ValueError("correlation work limit must be a positive integer")
    estimated = 0
    work_units = 0
    observations = request.monitoring_bundle.observations
    observation_count = max(1, len(observations))
    failed_monitor_roots: dict[tuple[str, ...], set[str]] = {}
    endpoint_roots: dict[tuple[str, str], set[str]] = {}
    for observation in observations:
        if (
            isinstance(observation, ConnectionMonitorObservation)
            and observation.status == "failed"
            and observation.observed_start <= request.incident_anchor.observed_start
            and _overlaps_incident(observation, request)
        ):
            failed_monitor_roots.setdefault(
                _network_tuple_key(observation),
                set(),
            ).add(observation.provenance_root_digest)
        elif (
            isinstance(observation, EndpointHealthObservation)
            and observation.status in {"degraded", "unhealthy", "unavailable"}
            and observation.observed_start <= request.incident_anchor.observed_start
            and _overlaps_incident(observation, request)
        ):
            for resource_id in (
                observation.subject_resource_id,
                *observation.backend_resource_ids,
            ):
                endpoint_roots.setdefault(
                    (observation.path_id, resource_id),
                    set(),
                ).add(observation.provenance_root_digest)
    for artifact in request.change_artifacts:
        if artifact.evidence.occurred_at > request.incident_anchor.observed_start:
            continue
        if (
            artifact.evidence.target_resource_type.casefold()
            != "microsoft.network/networksecuritygroups/securityrules"
        ):
            estimated += 1
            work_units += len(request.evidence_index) + observation_count
        else:
            artifact_digest = sha256_hex(artifact.canonical_bytes())
            matching_flows = tuple(
                observation
                for observation in observations
                if isinstance(observation, NetworkFlowObservation)
                and observation.decision == "denied"
                and observation.observed_start <= request.incident_anchor.observed_start
                and _overlaps_incident(observation, request)
                and (
                    _flow_binds_change(
                        observation,
                        artifact,
                        artifact_digest,
                    )
                    or (
                        not observation.effective_rule_attribution
                        and _flow_matches_changed_nsg(observation, artifact)
                    )
                )
            )
            groups = {_nsg_chain_key(observation) for observation in matching_flows}
            estimated += max(1, len(groups))
            flow_work = sum(
                max(
                    1,
                    len(
                        failed_monitor_roots.get(
                            _network_tuple_key(flow),
                            set(),
                        )
                    ),
                )
                * max(
                    1,
                    1
                    + len(
                        endpoint_roots.get(
                            (flow.path_id, flow.destination_resource_id),
                            set(),
                        )
                    ),
                )
                for flow in matching_flows
            )
            work_units += max(1, flow_work) * observation_count * 3
        if estimated > limit or work_units > work_limit:
            raise ValueError("correlation candidate budget exceeded")

    dependency_groups = {
        _network_tuple_key(observation)
        for observation in observations
        if observation.observed_start <= request.incident_anchor.observed_start
        and _overlaps_incident(observation, request)
        and (
            (isinstance(observation, NetworkFlowObservation) and observation.decision == "denied")
            or (
                isinstance(observation, ConnectionMonitorObservation)
                and observation.status == "failed"
            )
        )
    }
    estimated += len(dependency_groups)
    work_units += observation_count + len(dependency_groups) * observation_count
    generic_count = sum(
        1
        for observation in observations
        if observation.observed_start <= request.incident_anchor.observed_start
        and _overlaps_incident(observation, request)
        and isinstance(
            observation,
            (
                GuestSignalObservation,
                EndpointHealthObservation,
                PlatformHealthObservation,
            ),
        )
        and (
            observation.observation_id in adverse_observation_ids
            if adverse_observation_ids is not None
            else _is_adverse_observation(observation)
        )
    )
    estimated += generic_count
    work_units += observation_count + generic_count * (
        len(request.evidence_index) + observation_count
    )
    if estimated > limit or work_units > work_limit:
        raise ValueError("correlation candidate budget exceeded")


def _network_security_hypotheses(
    *,
    request: CorrelationRequest,
    artifact: ChangeEvidenceArtifact,
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
) -> list[RootCauseHypothesis]:
    artifact_digest = sha256_hex(artifact.canonical_bytes())
    grouped_flows: dict[tuple[str, ...], list[NetworkFlowObservation]] = {}
    for observation in request.monitoring_bundle.observations:
        if not (
            isinstance(observation, NetworkFlowObservation)
            and observation.decision == "denied"
            and observation.observed_start <= request.incident_anchor.observed_start
            and _overlaps_incident(observation, request)
            and (
                _flow_binds_change(observation, artifact, artifact_digest)
                or (
                    not observation.effective_rule_attribution
                    and _flow_matches_changed_nsg(observation, artifact)
                )
            )
        ):
            continue
        path = paths.get(observation.path_id)
        if path is None or request.incident_anchor.affected_resource_id not in path.resource_ids:
            continue
        endpoints = _matching_degraded_endpoints(
            request.monitoring_bundle.observations,
            destination_resource_id=observation.destination_resource_id,
            path=path,
            request=request,
        )
        if (
            request.incident_anchor.affected_resource_id
            not in {
                observation.subject_resource_id,
                observation.source_resource_id,
                observation.destination_resource_id,
            }
            and not endpoints
        ):
            continue
        grouped_flows.setdefault(_nsg_chain_key(observation), []).append(observation)

    if not grouped_flows:
        return [
            _network_security_hypothesis(
                request=request,
                artifact=artifact,
                artifact_digest=artifact_digest,
                candidate_flows=(),
                citations=citations,
                paths=paths,
            )
        ]
    return [
        _network_security_hypothesis(
            request=request,
            artifact=artifact,
            artifact_digest=artifact_digest,
            candidate_flows=tuple(sorted(grouped_flows[key], key=lambda item: item.observation_id)),
            citations=citations,
            paths=paths,
        )
        for key in sorted(grouped_flows)
    ]


def _select_nsg_chain(
    *,
    request: CorrelationRequest,
    artifact: ChangeEvidenceArtifact,
    artifact_digest: str,
    candidate_flows: Iterable[NetworkFlowObservation],
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
) -> tuple[
    NetworkFlowObservation | None,
    ConnectionMonitorObservation | None,
    EndpointHealthObservation | None,
    DependencyPath | None,
]:
    change = artifact.evidence
    observations = request.monitoring_bundle.observations
    best_chain: (
        tuple[
            tuple[object, ...],
            NetworkFlowObservation,
            ConnectionMonitorObservation | None,
            EndpointHealthObservation | None,
            DependencyPath | None,
        ]
        | None
    ) = None
    for flow in sorted(candidate_flows, key=lambda item: item.observation_id):
        path = paths.get(flow.path_id)
        monitors = _matching_failed_monitors(observations, flow, request)
        endpoints = (
            _matching_degraded_endpoints(
                observations,
                destination_resource_id=flow.destination_resource_id,
                path=path,
                request=request,
            )
            if path is not None
            else ()
        )
        best_monitors_by_root: dict[str, ConnectionMonitorObservation] = {}
        for monitor in sorted(
            monitors,
            key=lambda item: (
                int(_chain_has_hard_conflict(request, flow, item)),
                int(item.observed_start < change.occurred_at),
                int(_matching_monitor_coverage(request, item) is None),
                (request.incident_anchor.observed_start - item.observed_start).total_seconds(),
                item.observation_id,
            ),
        ):
            best_monitors_by_root.setdefault(monitor.provenance_root_digest, monitor)
        monitor_options: tuple[ConnectionMonitorObservation | None, ...] = (
            tuple(best_monitors_by_root.values()) if best_monitors_by_root else (None,)
        )

        best_endpoints_by_root: dict[str, EndpointHealthObservation] = {}
        for endpoint in sorted(
            endpoints,
            key=lambda item: (
                int(item.observed_start < change.occurred_at),
                int(_matching_endpoint_coverage(request, item) is None),
                (request.incident_anchor.observed_start - item.observed_start).total_seconds(),
                item.observation_id,
            ),
        ):
            best_endpoints_by_root.setdefault(endpoint.provenance_root_digest, endpoint)
        endpoint_roots = tuple(best_endpoints_by_root.values())

        for monitor_option in monitor_options:
            excluded_roots = {
                flow.provenance_root_digest,
                *(() if monitor_option is None else (monitor_option.provenance_root_digest,)),
            }
            endpoint_options: dict[str, EndpointHealthObservation | None] = {"": None}
            if endpoint_roots:
                endpoint_options[endpoint_roots[0].observation_id] = endpoint_roots[0]
            for endpoint_candidate in endpoint_roots:
                if endpoint_candidate.provenance_root_digest in excluded_roots:
                    endpoint_options[endpoint_candidate.observation_id] = endpoint_candidate
                elif "independent" not in endpoint_options:
                    endpoint_options["independent"] = endpoint_candidate

            for endpoint_option in endpoint_options.values():
                selected = tuple(
                    item for item in (flow, monitor_option, endpoint_option) if item is not None
                )
                independent = _independent_citations(
                    citations[item.observation_id] for item in selected
                )
                chronology_valid = all(
                    item.observed_start >= change.occurred_at for item in selected
                )
                complete = _has_complete_nsg_coverage(
                    request,
                    flow,
                    monitor_option,
                    endpoint_option,
                    path,
                )
                no_hard_conflict = not _chain_has_hard_conflict(
                    request,
                    flow,
                    monitor_option,
                )
                rank_key: tuple[object, ...] = (
                    -int(no_hard_conflict),
                    -int(chronology_valid),
                    -int(complete),
                    -int(monitor_option is not None and endpoint_option is not None),
                    -len(independent),
                    -int(_flow_binds_change(flow, artifact, artifact_digest)),
                    flow.observation_id,
                    "" if monitor_option is None else monitor_option.observation_id,
                    "" if endpoint_option is None else endpoint_option.observation_id,
                )
                candidate = (
                    rank_key,
                    flow,
                    monitor_option,
                    endpoint_option,
                    path,
                )
                if best_chain is None or candidate[0] < best_chain[0]:
                    best_chain = candidate

    if best_chain is not None:
        _, selected_flow, selected_monitor, selected_endpoint, selected_path = best_chain
        return selected_flow, selected_monitor, selected_endpoint, selected_path
    return (
        None,
        None,
        None,
        _path_for_resources(
            paths.values(),
            request.incident_anchor.affected_resource_id,
            change.target_resource_id,
        ),
    )


def _network_security_hypothesis(
    *,
    request: CorrelationRequest,
    artifact: ChangeEvidenceArtifact,
    artifact_digest: str,
    candidate_flows: tuple[NetworkFlowObservation, ...],
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
) -> RootCauseHypothesis:
    change = artifact.evidence
    change_citation = citations[change.evidence_id]
    incident = request.incident_anchor
    denied_flow, failed_monitor, degraded_endpoint, path = _select_nsg_chain(
        request=request,
        artifact=artifact,
        artifact_digest=artifact_digest,
        candidate_flows=candidate_flows,
        citations=citations,
        paths=paths,
    )
    attributed_candidates = sorted(
        (
            item
            for item in request.monitoring_bundle.observations
            if isinstance(item, NetworkFlowObservation)
            and item.observed_start <= incident.observed_start
            and _overlaps_incident(item, request)
            and _flow_binds_change(item, artifact, artifact_digest)
            and _nsg_chain_key(item)
            == (None if denied_flow is None else _nsg_chain_key(denied_flow))
        ),
        key=lambda item: (
            -int(_chain_has_hard_conflict(request, item, None)),
            item.observation_id,
        ),
    )
    claimed_flows_by_id: dict[str, NetworkFlowObservation] = {}
    if denied_flow is not None:
        claimed_flows_by_id[denied_flow.observation_id] = denied_flow
    for candidate in attributed_candidates:
        if len(claimed_flows_by_id) >= CORRELATION_RULE_CATALOG.maximum_gate_evidence_ids:
            break
        claimed_flows_by_id.setdefault(candidate.observation_id, candidate)
    claimed_flows = tuple(claimed_flows_by_id.values())
    selected_attributed_flow = (
        denied_flow
        if denied_flow is not None and _flow_binds_change(denied_flow, artifact, artifact_digest)
        else None
    )

    support = [change_citation]
    support.extend(citations[item.observation_id] for item in claimed_flows)
    if failed_monitor is not None:
        support.append(citations[failed_monitor.observation_id])
    if degraded_endpoint is not None:
        support.append(citations[degraded_endpoint.observation_id])

    semantic_match = any(_is_nsg_property(item.path) for item in change.changed_properties)
    topology = _topology_score(
        path,
        cause_resource_id=change.target_resource_id,
        affected_resource_id=incident.affected_resource_id,
    )
    temporal = _temporal_score(change.occurred_at, incident.observed_start)
    semantic = (
        _SCORE_WEIGHTS["nsgDirectSemantic"]
        if denied_flow is not None and _flow_binds_change(denied_flow, artifact, artifact_digest)
        else (_SCORE_WEIGHTS["nsgCausalSemantic"] if semantic_match else 0)
    )
    corroboration, corroboration_support = _nsg_corroboration(
        denied_flow,
        failed_monitor,
        degraded_endpoint,
        citations,
    )
    recovery, recovery_support, recovery_evidence_ids = (
        _recovery_assessment(
            request,
            cause_resource_id=change.target_resource_id,
            citations=citations,
            candidate_artifact=artifact,
            candidate_observation=degraded_endpoint,
        )
        if semantic_match
        else (0, [], ())
    )
    support.extend(recovery_support)
    score = _score(topology, temporal, semantic, corroboration, recovery)

    gates: list[CorrelationGate] = []
    path_observation = None
    if change.result == "succeeded":
        gates.append(_gate("successfulChange", change_citation))
    if path is not None:
        path_observation = degraded_endpoint or denied_flow or failed_monitor
        if path_observation is not None:
            gates.append(_gate("affectedPath", citations[path_observation.observation_id]))
    if semantic_match:
        gates.append(_gate("semanticMatch", change_citation))
    if claimed_flows:
        gates.append(
            CorrelationGate(
                code="matchingDeniedFlow",
                satisfied=True,
                evidenceIds=tuple(sorted(item.observation_id for item in claimed_flows)),
            )
        )
    if selected_attributed_flow is not None:
        gates.append(
            _gate(
                "effectiveRuleAttribution",
                citations[selected_attributed_flow.observation_id],
            )
        )
    if failed_monitor is not None:
        gates.append(
            _gate(
                "connectionMonitorFailure",
                citations[failed_monitor.observation_id],
            )
        )
    if degraded_endpoint is not None:
        gates.append(
            _gate(
                "endpointDegradation",
                citations[degraded_endpoint.observation_id],
            )
        )
    independent = _independent_citations(corroboration_support)
    if len(independent) >= 2 and path_observation is not None:
        gates.append(
            CorrelationGate(
                code="independentCorroboration",
                satisfied=True,
                evidenceIds=tuple(item.evidence_id for item in independent),
            )
        )
    if change.result == "succeeded" and change.occurred_at <= incident.observed_start:
        gates.append(_gate("correctChronology", change_citation))

    contradictions = _network_contradictions(
        request=request,
        artifact=artifact,
        denied_flows=claimed_flows,
        failed_monitor=failed_monitor,
        citations=citations,
    )
    hard_conflict = any(item.hard_conflict for item in contradictions)
    if not hard_conflict:
        gates.append(
            CorrelationGate(
                code="noHardConflict",
                satisfied=True,
                evidenceIds=(),
            )
        )

    missing: list[MissingCorrelationEvidence] = []
    caps: list[ConfidenceCap] = []
    monitoring_support = [item for item in support if item.family != "resourceChange"]
    if not monitoring_support:
        caps.append(_cap("recentChangeOnly"))
    if path_observation is None:
        caps.append(_cap("missingAffectedPath"))
        missing.append(
            _missing(
                "affectedPath",
                "declaredContext",
                "No governed dependency path binds the change to the incident resource.",
                "Medium",
            )
        )
    if len(_independent_citations(corroboration_support)) < 2 or path_observation is None:
        caps.append(_cap("missingIndependentSupport"))
    if selected_attributed_flow is None:
        caps.append(
            _cap(
                "missingDirectAttribution",
                CORRELATION_RULE_CATALOG.unattributed_nsg_max_confidence,
            )
        )
        missing.append(
            _missing(
                "effectiveRuleAttribution",
                "networkFlow",
                "No direct effective-rule or IP Flow Verify attribution is available.",
                "Confirmed",
            )
        )
    if denied_flow is None:
        missing.append(
            _missing(
                "deniedFlow",
                "networkFlow",
                "No incident-overlapping denied flow matches the changed rule.",
                "High",
            )
        )
    if failed_monitor is None:
        missing.append(
            _missing(
                "connectionMonitorResult",
                "connectionMonitor",
                "No matching failed Connection Monitor result is available.",
                "Confirmed",
            )
        )
    if degraded_endpoint is None:
        missing.append(
            _missing(
                "endpointHealth",
                "endpointHealth",
                "No matching endpoint degradation is available.",
                "Confirmed",
            )
        )
    if not _has_complete_nsg_coverage(
        request,
        denied_flow,
        failed_monitor,
        degraded_endpoint,
        path,
    ):
        missing.append(
            _missing(
                "completeObservationWindow",
                "networkFlow",
                "Complete path and test coverage is not available for the incident interval.",
                "Confirmed",
            )
        )
    if any(
        item.family != "resourceChange" and item.observed_start < change.occurred_at
        for item in support
    ):
        caps.append(_cap("ambiguousObservationWindow"))

    confirmed = (
        score.raw_score - recovery >= _CONFIDENCE_THRESHOLDS["Confirmed"]
        and change.result == "succeeded"
        and semantic_match
        and path is not None
        and denied_flow is not None
        and denied_flow.effective_rule_attribution
        and failed_monitor is not None
        and degraded_endpoint is not None
        and len(independent) >= 3
        and not hard_conflict
        and not any(item.required_for_confidence == "Confirmed" for item in missing)
    )
    if confirmed and recovery_support:
        recovery_ids = {item.evidence_id for item in recovery_support}
        support = [item for item in support if item.evidence_id not in recovery_ids]
        recovery = 0
        recovery_support = []
        recovery_evidence_ids = ()
        score = _score(topology, temporal, semantic, corroboration, recovery)
    confidence = classify_confidence(
        score.raw_score,
        caps=caps,
        hard_conflict=hard_conflict,
        confirmed=confirmed,
    )
    if confirmed:
        required = {
            "successfulChange",
            "affectedPath",
            "semanticMatch",
            "effectiveRuleAttribution",
            "matchingDeniedFlow",
            "connectionMonitorFailure",
            "endpointDegradation",
            "independentCorroboration",
            "correctChronology",
            "noHardConflict",
        }
        gates = [item for item in gates if item.code in required]
    elif recovery_evidence_ids:
        gates.append(
            CorrelationGate(
                code="recoveryEvidence",
                satisfied=True,
                evidenceIds=recovery_evidence_ids,
            )
        )

    return _make_hypothesis(
        category="networkSecurityChange",
        cause_resource_id=change.target_resource_id,
        path_id=None if path is None else path.path_id,
        candidate_causal_at=change.occurred_at,
        score=score,
        confidence=confidence,
        support=support,
        contradictions=contradictions,
        missing=missing,
        gates=gates,
        caps=caps,
    )


def _change_hypothesis(
    *,
    request: CorrelationRequest,
    artifact: ChangeEvidenceArtifact,
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
    observation_by_id: Mapping[str, object],
    adverse_observation_ids: frozenset[str],
) -> RootCauseHypothesis:
    change = artifact.evidence
    citation = citations[change.evidence_id]
    category: RootCauseCategory = (
        "routingChange"
        if "routetables/routes" in change.target_resource_type.casefold()
        else "deploymentChange"
    )
    path = _path_for_resources(
        paths.values(),
        request.incident_anchor.affected_resource_id,
        change.target_resource_id,
    )
    monitoring = [
        item
        for item in request.evidence_index
        if item.evidence_id in adverse_observation_ids
        and _citation_relevant(
            item,
            path,
            request,
            observation_by_id,
        )
    ]
    support = [citation, *monitoring[:4]]
    contradictions: list[CorrelationContradiction] = []
    if change.result == "failed":
        contradictions.append(
            _contradiction(
                "changeFailed",
                "The candidate change did not succeed.",
                (citation,),
            )
        )
    if change.occurred_at > request.incident_anchor.observed_start:
        contradictions.append(
            _contradiction(
                "changeAfterDegradation",
                "The candidate change occurred after degradation began.",
                (citation,),
            )
        )
    independent = _independent_citations(monitoring)
    semantic_score = _change_semantic_score(artifact, category)
    recovery, recovery_support, recovery_evidence_ids = _recovery_assessment(
        request,
        cause_resource_id=change.target_resource_id,
        citations=citations,
        candidate_artifact=artifact,
    )
    support.extend(recovery_support)
    score = _score(
        _topology_score(
            path,
            cause_resource_id=change.target_resource_id,
            affected_resource_id=request.incident_anchor.affected_resource_id,
        ),
        _temporal_score(change.occurred_at, request.incident_anchor.observed_start),
        semantic_score,
        min(
            _SCORE_WEIGHTS["maximumComponent"],
            _SCORE_WEIGHTS["independentCorroboration"] * len(independent),
        ),
        recovery,
    )
    gates: list[CorrelationGate] = []
    if change.result == "succeeded":
        gates.append(_gate("successfulChange", citation))
    if semantic_score > 0:
        gates.append(_gate("semanticMatch", citation))
    if change.occurred_at <= request.incident_anchor.observed_start:
        gates.append(_gate("correctChronology", citation))
    path_evidence = _first_path_citation(
        monitoring,
        path,
        observation_by_id,
    )
    if path_evidence is not None:
        gates.append(_gate("affectedPath", path_evidence))
    if len(independent) >= 2 and path_evidence is not None:
        gates.append(
            CorrelationGate(
                code="independentCorroboration",
                satisfied=True,
                evidenceIds=tuple(item.evidence_id for item in independent),
            )
        )
    if recovery_evidence_ids:
        gates.append(
            CorrelationGate(
                code="recoveryEvidence",
                satisfied=True,
                evidenceIds=recovery_evidence_ids,
            )
        )
    hard_conflict = any(item.hard_conflict for item in contradictions)
    if not hard_conflict:
        gates.append(CorrelationGate(code="noHardConflict", satisfied=True, evidenceIds=()))
    caps: list[ConfidenceCap] = []
    missing: list[MissingCorrelationEvidence] = []
    if not monitoring:
        caps.append(_cap("recentChangeOnly"))
    if path_evidence is None:
        caps.append(_cap("missingAffectedPath"))
    if len(independent) < 2 or path_evidence is None:
        caps.append(_cap("missingIndependentSupport"))
    if category in {"deploymentChange", "routingChange"}:
        caps.append(
            _cap(
                "missingDirectAttribution",
                CORRELATION_RULE_CATALOG.generic_max_confidence,
            )
        )
    if any(item.observed_start < change.occurred_at for item in monitoring):
        caps.append(_cap("ambiguousObservationWindow"))
    confidence = classify_confidence(
        score.raw_score,
        caps=caps,
        hard_conflict=hard_conflict,
    )
    return _make_hypothesis(
        category=category,
        cause_resource_id=change.target_resource_id,
        path_id=None if path is None else path.path_id,
        candidate_causal_at=change.occurred_at,
        score=score,
        confidence=confidence,
        support=support,
        contradictions=contradictions,
        missing=missing,
        gates=gates,
        caps=caps,
    )


def _dependency_hypotheses(
    *,
    request: CorrelationRequest,
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
) -> list[RootCauseHypothesis]:
    flow_groups: dict[tuple[str, ...], list[NetworkFlowObservation]] = {}
    monitor_groups: dict[tuple[str, ...], list[ConnectionMonitorObservation]] = {}
    for observation in request.monitoring_bundle.observations:
        if (
            observation.observed_start > request.incident_anchor.observed_start
            or not _overlaps_incident(observation, request)
        ):
            continue
        if isinstance(observation, NetworkFlowObservation) and observation.decision == "denied":
            flow_groups.setdefault(_network_tuple_key(observation), []).append(observation)
        elif (
            isinstance(observation, ConnectionMonitorObservation) and observation.status == "failed"
        ):
            monitor_groups.setdefault(_network_tuple_key(observation), []).append(observation)

    hypotheses: list[RootCauseHypothesis] = []
    for key in sorted(set(flow_groups).union(monitor_groups)):
        flows = sorted(
            flow_groups.get(key, ()),
            key=lambda item: (
                int(_matching_flow_coverage(request, item) is None),
                (request.incident_anchor.observed_start - item.observed_start).total_seconds(),
                item.observation_id,
            ),
        )
        monitors = sorted(
            monitor_groups.get(key, ()),
            key=lambda item: (
                int(_matching_monitor_coverage(request, item) is None),
                (request.incident_anchor.observed_start - item.observed_start).total_seconds(),
                item.observation_id,
            ),
        )
        flow = flows[0] if flows else None
        monitor = monitors[0] if monitors else None
        if flow is None and monitor is None:
            continue
        if flow is not None:
            path_id = flow.path_id
            source_resource_id = flow.source_resource_id
            destination_resource_id = flow.destination_resource_id
        else:
            if monitor is None:
                continue
            path_id = monitor.path_id
            source_resource_id = monitor.source_resource_id
            destination_resource_id = monitor.destination_resource_id
        path = paths.get(path_id)
        endpoint = (
            _best_dependency_endpoint(
                request=request,
                observations=request.monitoring_bundle.observations,
                destination_resource_id=destination_resource_id,
                path=path,
            )
            if path is not None
            else None
        )
        if path is None or request.incident_anchor.affected_resource_id not in path.resource_ids:
            continue
        directly_connected = request.incident_anchor.affected_resource_id in {
            source_resource_id,
            destination_resource_id,
        }
        endpoint_bridge = (
            endpoint is not None
            and endpoint.subject_resource_id == request.incident_anchor.affected_resource_id
            and (
                endpoint.subject_resource_id == destination_resource_id
                or destination_resource_id in endpoint.backend_resource_ids
            )
        )
        if not directly_connected and not endpoint_bridge:
            continue
        hypotheses.append(
            _dependency_hypothesis(
                request=request,
                flow=flow,
                monitor=monitor,
                endpoint=endpoint,
                path=path,
                citations=citations,
            )
        )
    return hypotheses


def _dependency_hypothesis(
    *,
    request: CorrelationRequest,
    flow: NetworkFlowObservation | None,
    monitor: ConnectionMonitorObservation | None,
    endpoint: EndpointHealthObservation | None,
    path: DependencyPath | None,
    citations: dict[str, CorrelationEvidenceCitation],
) -> RootCauseHypothesis:
    selected = tuple(item for item in (flow, monitor, endpoint) if item is not None)
    support = [citations[item.observation_id] for item in selected]
    independent = _independent_citations(support)
    if flow is not None:
        cause_resource_id = flow.destination_resource_id
    elif monitor is not None:
        cause_resource_id = monitor.destination_resource_id
    else:
        raise ValueError("dependency hypothesis requires flow or monitor evidence")
    candidate_causal_at = min(item.observed_start for item in selected)
    recovery, recovery_support, recovery_evidence_ids = _recovery_assessment(
        request,
        cause_resource_id=cause_resource_id,
        citations=citations,
        candidate_observation=endpoint,
    )
    support.extend(recovery_support)
    topology = _topology_score(
        path,
        cause_resource_id=cause_resource_id,
        affected_resource_id=request.incident_anchor.affected_resource_id,
    )
    temporal = max(
        _temporal_score(item.observed_start, request.incident_anchor.observed_start)
        for item in selected
    )
    score = _score(
        topology,
        temporal,
        _SCORE_WEIGHTS["observationSemantic"],
        min(
            _SCORE_WEIGHTS["maximumComponent"],
            _SCORE_WEIGHTS["independentCorroboration"] * max(0, len(independent) - 1),
        ),
        recovery,
    )
    gates: list[CorrelationGate] = []
    path_citation = _path_gate_citation(
        path,
        flow=flow,
        endpoint=endpoint,
        citations=citations,
    )
    if path_citation is not None:
        gates.append(_gate("affectedPath", path_citation))
    if flow is not None:
        gates.append(_gate("matchingDeniedFlow", citations[flow.observation_id]))
    if monitor is not None and monitor.status == "failed":
        gates.append(_gate("connectionMonitorFailure", citations[monitor.observation_id]))
    if endpoint is not None:
        gates.append(_gate("endpointDegradation", citations[endpoint.observation_id]))
    if len(independent) >= 2 and path_citation is not None:
        gates.append(
            CorrelationGate(
                code="independentCorroboration",
                satisfied=True,
                evidenceIds=tuple(item.evidence_id for item in independent),
            )
        )
    if recovery_evidence_ids:
        gates.append(
            CorrelationGate(
                code="recoveryEvidence",
                satisfied=True,
                evidenceIds=recovery_evidence_ids,
            )
        )
    contradictions = _network_observation_contradictions(
        request=request,
        denied_flows=(() if flow is None else (flow,)),
        failed_monitors=(() if monitor is None or monitor.status != "failed" else (monitor,)),
        citations=citations,
    )
    hard_conflict = any(item.hard_conflict for item in contradictions)
    if not hard_conflict:
        gates.append(CorrelationGate(code="noHardConflict", satisfied=True, evidenceIds=()))

    caps: list[ConfidenceCap] = [
        _cap(
            "missingDirectAttribution",
            CORRELATION_RULE_CATALOG.generic_max_confidence,
        )
    ]
    missing: list[MissingCorrelationEvidence] = []
    if path_citation is None:
        caps.append(_cap("missingAffectedPath"))
        missing.append(
            _missing(
                "affectedPath",
                "declaredContext",
                "No governed dependency path binds the failed connection.",
                "Medium",
            )
        )
    if len(independent) < 2 or path_citation is None:
        caps.append(_cap("missingIndependentSupport"))
    if flow is None:
        missing.append(
            _missing(
                "deniedFlow",
                "networkFlow",
                "No matching denied flow is available for the failed dependency.",
                "High",
            )
        )
    if monitor is None:
        missing.append(
            _missing(
                "connectionMonitorResult",
                "connectionMonitor",
                "No matching failed Connection Monitor result is available.",
                "High",
            )
        )
    if endpoint is None:
        missing.append(
            _missing(
                "endpointHealth",
                "endpointHealth",
                "No matching endpoint degradation is available.",
                "High",
            )
        )
    complete_window = all(
        (
            _matching_flow_coverage(request, item)
            if isinstance(item, NetworkFlowObservation)
            else _matching_monitor_coverage(request, item)
            if isinstance(item, ConnectionMonitorObservation)
            else _matching_endpoint_coverage(request, item)
        )
        is not None
        for item in selected
    )
    if not complete_window:
        caps.append(_cap("ambiguousObservationWindow"))
        missing.append(
            _missing(
                "completeObservationWindow",
                "networkFlow" if flow is not None else "connectionMonitor",
                "Complete incident-window dependency evidence is unavailable.",
                "High",
            )
        )
    confidence = classify_confidence(
        score.raw_score,
        caps=caps,
        hard_conflict=hard_conflict,
    )
    return _make_hypothesis(
        category="dependencyFailure",
        cause_resource_id=cause_resource_id,
        path_id=None if path is None else path.path_id,
        candidate_causal_at=candidate_causal_at,
        score=score,
        confidence=confidence,
        support=support,
        contradictions=contradictions,
        missing=missing,
        gates=gates,
        caps=caps,
    )


def _guest_hypothesis(
    *,
    request: CorrelationRequest,
    observation: GuestSignalObservation,
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
    observation_by_id: Mapping[str, object],
    adverse_observation_ids: frozenset[str],
) -> RootCauseHypothesis:
    category: RootCauseCategory = (
        "guestServiceFailure"
        if observation.signal in {"heartbeatLoss", "serviceFailure"}
        else "guestResourcePressure"
    )
    return _observation_hypothesis(
        request=request,
        observation=observation,
        category=category,
        citations=citations,
        paths=paths,
        observation_by_id=observation_by_id,
        adverse_observation_ids=adverse_observation_ids,
    )


def _observation_has_governed_connection(
    observation: GuestSignalObservation | PlatformHealthObservation,
    request: CorrelationRequest,
    paths: Mapping[str, DependencyPath],
) -> bool:
    affected_resource_id = request.incident_anchor.affected_resource_id
    return (
        observation.subject_resource_id == affected_resource_id
        or _path_for_resources(
            paths.values(),
            affected_resource_id,
            observation.subject_resource_id,
        )
        is not None
    )


def _observation_hypothesis(
    *,
    request: CorrelationRequest,
    observation: GuestSignalObservation | EndpointHealthObservation | PlatformHealthObservation,
    category: RootCauseCategory,
    citations: dict[str, CorrelationEvidenceCitation],
    paths: dict[str, DependencyPath],
    observation_by_id: Mapping[str, object],
    adverse_observation_ids: frozenset[str],
) -> RootCauseHypothesis:
    citation = citations[observation.observation_id]
    path = (
        paths.get(observation.path_id)
        if isinstance(observation, EndpointHealthObservation)
        else _path_for_resources(
            paths.values(),
            request.incident_anchor.affected_resource_id,
            observation.subject_resource_id,
        )
    )
    related = [
        item
        for item in request.evidence_index
        if item.evidence_id != citation.evidence_id
        and item.family != "resourceChange"
        and item.evidence_id in adverse_observation_ids
        and _citation_relevant(
            item,
            path,
            request,
            observation_by_id,
        )
    ]
    support = [citation, *related[:4]]
    independent = _independent_citations(support)
    path_evidence = _first_path_citation(
        support,
        path,
        observation_by_id,
    )
    topology = (
        _SCORE_WEIGHTS["topologyExactPath"]
        if path_evidence is not None
        else (
            _SCORE_WEIGHTS["topologyDeclaredPath"]
            if observation.subject_resource_id == request.incident_anchor.affected_resource_id
            else 0
        )
    )
    recovery, recovery_support, recovery_evidence_ids = _recovery_assessment(
        request,
        cause_resource_id=observation.subject_resource_id,
        citations=citations,
        candidate_observation=(
            observation
            if isinstance(observation, (GuestSignalObservation, EndpointHealthObservation))
            else None
        ),
    )
    support.extend(recovery_support)
    score = _score(
        topology,
        _temporal_score(observation.observed_start, request.incident_anchor.observed_start),
        _SCORE_WEIGHTS["observationSemantic"],
        min(
            _SCORE_WEIGHTS["maximumComponent"],
            _SCORE_WEIGHTS["independentCorroboration"] * max(0, len(independent) - 1),
        ),
        recovery,
    )
    gates: list[CorrelationGate] = []
    if path_evidence is not None:
        gates.append(_gate("affectedPath", path_evidence))
    if len(independent) >= 2 and path_evidence is not None:
        gates.append(
            CorrelationGate(
                code="independentCorroboration",
                satisfied=True,
                evidenceIds=tuple(item.evidence_id for item in independent),
            )
        )
    if recovery_evidence_ids:
        gates.append(
            CorrelationGate(
                code="recoveryEvidence",
                satisfied=True,
                evidenceIds=recovery_evidence_ids,
            )
        )
    gates.append(CorrelationGate(code="noHardConflict", satisfied=True, evidenceIds=()))
    caps: list[ConfidenceCap] = [
        _cap(
            "missingDirectAttribution",
            CORRELATION_RULE_CATALOG.generic_max_confidence,
        ),
    ]
    missing: list[MissingCorrelationEvidence] = []
    if path_evidence is None:
        caps.append(_cap("missingAffectedPath"))
    if len(independent) < 2 or path_evidence is None:
        caps.append(_cap("missingIndependentSupport"))
    family = citations[observation.observation_id].family
    if not _has_complete_coverage(
        request,
        family=family,
        path=path,
        resource_id=observation.subject_resource_id,
    ):
        caps.append(_cap("ambiguousObservationWindow"))
        missing.append(
            _missing(
                "completeObservationWindow",
                family,
                "Complete incident-window coverage is unavailable for this signal.",
                "High",
            )
        )
    confidence = classify_confidence(score.raw_score, caps=caps)
    return _make_hypothesis(
        category=category,
        cause_resource_id=observation.subject_resource_id,
        path_id=None if path_evidence is None or path is None else path.path_id,
        candidate_causal_at=observation.observed_start,
        score=score,
        confidence=confidence,
        support=support,
        contradictions=[],
        missing=missing,
        gates=gates,
        caps=caps,
    )


def _unknown_hypothesis(request: CorrelationRequest) -> RootCauseHypothesis:
    support = list(request.incident_anchor.current_state_evidence)
    score = _score(0, 0, 0, 0, 0)
    return _make_hypothesis(
        category="unknown",
        cause_resource_id=None,
        path_id=None,
        candidate_causal_at=None,
        score=score,
        confidence="Unknown",
        support=support,
        contradictions=[],
        missing=[
            _missing(
                "changeDetails",
                "resourceChange",
                "No sufficiently bound causal evidence produced a ranked explanation.",
                "Low",
            )
        ],
        gates=[],
        caps=[
            _cap("missingAffectedPath"),
            _cap("missingIndependentSupport"),
        ],
    )


def _overflow_hypothesis(
    request: CorrelationRequest,
    omitted: list[RootCauseHypothesis],
) -> RootCauseHypothesis:
    omitted_digest = compute_artifact_digest([item.hypothesis_digest for item in omitted])
    return _make_hypothesis(
        category="unknown",
        cause_resource_id=None,
        path_id=None,
        candidate_causal_at=None,
        score=_score(0, 0, 0, 0, 0),
        confidence="Unknown",
        support=request.incident_anchor.current_state_evidence,
        contradictions=[],
        missing=[
            _missing(
                "changeDetails",
                "resourceChange",
                (
                    f"{len(omitted)} lower-ranked candidates were omitted from the "
                    f"bounded report; digest {omitted_digest}."
                ),
                "Low",
            )
        ],
        gates=[],
        caps=[
            _cap("missingAffectedPath"),
            _cap("missingIndependentSupport"),
        ],
    )


def _network_contradictions(
    *,
    request: CorrelationRequest,
    artifact: ChangeEvidenceArtifact,
    denied_flows: Iterable[NetworkFlowObservation],
    failed_monitor: ConnectionMonitorObservation | None,
    citations: dict[str, CorrelationEvidenceCitation],
) -> list[CorrelationContradiction]:
    change = artifact.evidence
    contradictions: list[CorrelationContradiction] = []
    if change.result == "failed":
        contradictions.append(
            _contradiction(
                "changeFailed",
                "The candidate NSG change did not succeed.",
                (citations[change.evidence_id],),
            )
        )
    if change.occurred_at > request.incident_anchor.observed_start:
        contradictions.append(
            _contradiction(
                "changeAfterDegradation",
                "The candidate NSG change occurred after degradation began.",
                (citations[change.evidence_id],),
            )
        )
    contradictions.extend(
        _network_observation_contradictions(
            request=request,
            denied_flows=denied_flows,
            failed_monitors=(() if failed_monitor is None else (failed_monitor,)),
            citations=citations,
        )
    )
    return contradictions


def _network_observation_contradictions(
    *,
    request: CorrelationRequest,
    denied_flows: Iterable[NetworkFlowObservation],
    failed_monitors: Iterable[ConnectionMonitorObservation],
    citations: dict[str, CorrelationEvidenceCitation],
) -> list[CorrelationContradiction]:
    contradictions: list[CorrelationContradiction] = []
    claimed_flows = tuple(denied_flows)
    allowed_matches = sorted(
        (
            (coverage, observation)
            for observation in request.monitoring_bundle.observations
            if isinstance(observation, NetworkFlowObservation)
            and observation.decision == "allowed"
            and any(
                _nsg_chain_key(observation) == _nsg_chain_key(denied_flow)
                for denied_flow in claimed_flows
            )
            and _overlaps_incident(observation, request)
            and (coverage := _matching_flow_coverage(request, observation)) is not None
        ),
        key=lambda item: (item[1].observation_id, item[0].coverage_id),
    )
    if allowed_matches:
        coverage, allowed_observation = allowed_matches[0]
        omitted_digest = compute_artifact_digest(
            [
                [item_coverage.coverage_id, item_observation.observation_id]
                for item_coverage, item_observation in allowed_matches
            ]
        )
        contradictions.append(
            _contradiction(
                "completeAllowedFlow",
                (
                    "Complete incident-window evidence contains "
                    f"{len(allowed_matches)} exact allowed flow record(s); "
                    f"evidence-set digest {omitted_digest}."
                ),
                (
                    citations[coverage.coverage_id],
                    citations[allowed_observation.observation_id],
                ),
            )
        )
    claimed_monitors = tuple(failed_monitors)
    healthy_matches = sorted(
        (
            (coverage, observation)
            for observation in request.monitoring_bundle.observations
            if isinstance(observation, ConnectionMonitorObservation)
            and observation.status == "succeeded"
            and any(_same_monitor(observation, monitor) for monitor in claimed_monitors)
            and _overlaps_incident(observation, request)
            and (coverage := _matching_monitor_coverage(request, observation)) is not None
        ),
        key=lambda item: (item[1].observation_id, item[0].coverage_id),
    )
    if healthy_matches:
        coverage, healthy_observation = healthy_matches[0]
        omitted_digest = compute_artifact_digest(
            [
                [item_coverage.coverage_id, item_observation.observation_id]
                for item_coverage, item_observation in healthy_matches
            ]
        )
        contradictions.append(
            _contradiction(
                "completeHealthyConnectionMonitor",
                (
                    "Complete incident-window monitoring contains "
                    f"{len(healthy_matches)} exact healthy test record(s); "
                    f"evidence-set digest {omitted_digest}."
                ),
                (
                    citations[coverage.coverage_id],
                    citations[healthy_observation.observation_id],
                ),
            )
        )
    return contradictions


def _chain_has_hard_conflict(
    request: CorrelationRequest,
    flow: NetworkFlowObservation,
    monitor: ConnectionMonitorObservation | None,
) -> bool:
    if any(
        isinstance(item, NetworkFlowObservation)
        and item.decision == "allowed"
        and _same_flow(item, flow)
        and _overlaps_incident(item, request)
        and _matching_flow_coverage(request, item) is not None
        for item in request.monitoring_bundle.observations
    ):
        return True
    return bool(
        monitor is not None
        and any(
            isinstance(item, ConnectionMonitorObservation)
            and item.status == "succeeded"
            and _same_monitor(item, monitor)
            and _overlaps_incident(item, request)
            and _matching_monitor_coverage(request, item) is not None
            for item in request.monitoring_bundle.observations
        )
    )


def _nsg_corroboration(
    flow: NetworkFlowObservation | None,
    monitor: ConnectionMonitorObservation | None,
    endpoint: EndpointHealthObservation | None,
    citations: dict[str, CorrelationEvidenceCitation],
) -> tuple[int, list[CorrelationEvidenceCitation]]:
    score = 0
    support: list[CorrelationEvidenceCitation] = []
    used_roots: set[str] = set()
    for observation, value in (
        (flow, _SCORE_WEIGHTS["flowCorroboration"]),
        (monitor, _SCORE_WEIGHTS["monitorCorroboration"]),
        (endpoint, _SCORE_WEIGHTS["endpointCorroboration"]),
    ):
        if observation is None:
            continue
        citation = citations[observation.observation_id]
        support.append(citation)
        if citation.provenance_root_digest not in used_roots:
            used_roots.add(citation.provenance_root_digest)
            score += value
    return min(_SCORE_WEIGHTS["maximumComponent"], score), support


def _matching_failed_monitors(
    observations: Iterable[object],
    flow: NetworkFlowObservation,
    request: CorrelationRequest,
) -> tuple[ConnectionMonitorObservation, ...]:
    return tuple(
        sorted(
            (
                item
                for item in observations
                if isinstance(item, ConnectionMonitorObservation)
                and item.status == "failed"
                and item.path_id == flow.path_id
                and item.direction == flow.direction
                and item.five_tuple_digest == flow.five_tuple_digest
                and item.source_resource_id == flow.source_resource_id
                and item.destination_resource_id == flow.destination_resource_id
                and item.source_address == flow.source_address
                and item.destination_address == flow.destination_address
                and item.protocol == flow.protocol
                and item.source_port == flow.source_port
                and item.destination_port == flow.destination_port
                and item.observed_start <= request.incident_anchor.observed_start
                and _overlaps_incident(item, request)
            ),
            key=lambda item: item.observation_id,
        )
    )


def _flow_binds_change(
    flow: NetworkFlowObservation,
    artifact: ChangeEvidenceArtifact,
    artifact_digest: str,
) -> bool:
    change = artifact.evidence
    return (
        flow.effective_rule_attribution
        and flow.decision == "denied"
        and flow.rule_resource_id == change.target_resource_id
        and flow.enforcement_resource_id == _parent_nsg_id(change.target_resource_id)
        and flow.matched_change_evidence_id == change.evidence_id
        and flow.matched_change_key == change.change_key
        and flow.matched_change_artifact_digest == artifact_digest
        and set(flow.matched_property_paths).issubset(
            {item.path for item in change.changed_properties}
        )
    )


def _flow_matches_changed_nsg(
    flow: NetworkFlowObservation,
    artifact: ChangeEvidenceArtifact,
) -> bool:
    changed_rule_id = artifact.evidence.target_resource_id
    parent_nsg_id = _parent_nsg_id(changed_rule_id)
    if flow.rule_resource_id is not None:
        return (
            flow.rule_resource_id == changed_rule_id
            and flow.enforcement_resource_id == parent_nsg_id
        )
    return flow.enforcement_resource_id == parent_nsg_id


def _parent_nsg_id(rule_resource_id: str) -> str:
    marker = "/securityrules/"
    parent_nsg_id, separator, _ = rule_resource_id.rpartition(marker)
    if not separator or not parent_nsg_id:
        raise ValueError("NSG rule resource ID does not contain a parent NSG")
    return parent_nsg_id


def _matching_degraded_endpoints(
    observations: Iterable[object],
    *,
    destination_resource_id: str,
    path: DependencyPath,
    request: CorrelationRequest,
) -> tuple[EndpointHealthObservation, ...]:
    return tuple(
        sorted(
            (
                item
                for item in observations
                if isinstance(item, EndpointHealthObservation)
                and item.path_id == path.path_id
                and item.subject_resource_id == request.incident_anchor.affected_resource_id
                and (
                    item.subject_resource_id == destination_resource_id
                    or destination_resource_id in item.backend_resource_ids
                )
                and item.status in {"degraded", "unhealthy", "unavailable"}
                and item.observed_start <= request.incident_anchor.observed_start
                and _overlaps_incident(item, request)
            ),
            key=lambda item: item.observation_id,
        )
    )


def _best_dependency_endpoint(
    *,
    request: CorrelationRequest,
    observations: Iterable[object],
    destination_resource_id: str,
    path: DependencyPath,
) -> EndpointHealthObservation | None:
    matches = _matching_degraded_endpoints(
        observations,
        destination_resource_id=destination_resource_id,
        path=path,
        request=request,
    )
    ordered = sorted(
        matches,
        key=lambda item: (
            int(_matching_endpoint_coverage(request, item) is None),
            (request.incident_anchor.observed_start - item.observed_start).total_seconds(),
            item.observation_id,
        ),
    )
    return ordered[0] if ordered else None


def _matching_flow_coverage(
    request: CorrelationRequest,
    flow: NetworkFlowObservation,
) -> EvidenceCoverage | None:
    matches = sorted(
        (
            item
            for item in request.monitoring_bundle.coverage
            if item.family == "networkFlow"
            and item.status == "complete"
            and item.scope.path_id == flow.path_id
            and item.scope.direction == flow.direction
            and item.scope.five_tuple_digest == flow.five_tuple_digest
            and set(_flow_resource_ids(flow)).issubset(item.scope.resource_ids)
            and item.coverage_start <= request.incident_anchor.observed_start
            and item.coverage_end >= request.incident_anchor.observed_end
            and item.coverage_start <= flow.observed_start
            and item.coverage_end >= flow.observed_end
        ),
        key=lambda item: item.coverage_id,
    )
    return matches[0] if matches else None


def _matching_monitor_coverage(
    request: CorrelationRequest,
    monitor: ConnectionMonitorObservation,
) -> EvidenceCoverage | None:
    matches = sorted(
        (
            item
            for item in request.monitoring_bundle.coverage
            if item.family == "connectionMonitor"
            and item.status == "complete"
            and item.scope.path_id == monitor.path_id
            and item.scope.direction == monitor.direction
            and item.scope.five_tuple_digest == monitor.five_tuple_digest
            and item.scope.endpoint_test_reference == monitor.test_configuration_reference
            and item.scope.endpoint_test_digest == monitor.test_configuration_digest
            and {
                monitor.subject_resource_id,
                monitor.source_resource_id,
                monitor.destination_resource_id,
            }.issubset(item.scope.resource_ids)
            and item.coverage_start <= request.incident_anchor.observed_start
            and item.coverage_end >= request.incident_anchor.observed_end
            and item.coverage_start <= monitor.observed_start
            and item.coverage_end >= monitor.observed_end
        ),
        key=lambda item: item.coverage_id,
    )
    return matches[0] if matches else None


def _matching_endpoint_coverage(
    request: CorrelationRequest,
    endpoint: EndpointHealthObservation,
) -> EvidenceCoverage | None:
    matches = sorted(
        (
            item
            for item in request.monitoring_bundle.coverage
            if item.family == "endpointHealth"
            and item.status == "complete"
            and item.scope.path_id == endpoint.path_id
            and {
                endpoint.subject_resource_id,
                *endpoint.backend_resource_ids,
            }.issubset(item.scope.resource_ids)
            and item.coverage_start <= request.incident_anchor.observed_start
            and item.coverage_end >= request.incident_anchor.observed_end
            and item.coverage_start <= endpoint.observed_start
            and item.coverage_end >= endpoint.observed_end
        ),
        key=lambda item: item.coverage_id,
    )
    return matches[0] if matches else None


def _has_complete_nsg_coverage(
    request: CorrelationRequest,
    flow: NetworkFlowObservation | None,
    monitor: ConnectionMonitorObservation | None,
    endpoint: EndpointHealthObservation | None,
    path: DependencyPath | None,
) -> bool:
    if flow is None or monitor is None or endpoint is None or path is None:
        return False
    return (
        _matching_flow_coverage(request, flow) is not None
        and _matching_monitor_coverage(request, monitor) is not None
        and _matching_endpoint_coverage(request, endpoint) is not None
    )


def _has_complete_coverage(
    request: CorrelationRequest,
    *,
    family: EvidenceFamily,
    path: DependencyPath | None,
    resource_id: str,
) -> bool:
    return any(
        item.family == family
        and item.status == "complete"
        and resource_id in item.scope.resource_ids
        and (path is None or item.scope.path_id in {None, path.path_id})
        and item.coverage_start <= request.incident_anchor.observed_start
        and item.coverage_end >= request.incident_anchor.observed_end
        for item in request.monitoring_bundle.coverage
    )


def _recovery_assessment(
    request: CorrelationRequest,
    *,
    cause_resource_id: str,
    citations: dict[str, CorrelationEvidenceCitation],
    candidate_artifact: ChangeEvidenceArtifact | None = None,
    candidate_observation: GuestSignalObservation | EndpointHealthObservation | None = None,
) -> tuple[int, list[CorrelationEvidenceCitation], tuple[str, ...]]:
    if candidate_observation is None:
        return 0, [], ()
    recoveries = sorted(
        (
            item
            for item in request.monitoring_bundle.observations
            if (
                (
                    isinstance(candidate_observation, GuestSignalObservation)
                    and isinstance(item, GuestSignalObservation)
                    and item.state == "recovered"
                    and item.subject_resource_id == candidate_observation.subject_resource_id
                    and item.signal == candidate_observation.signal
                    and item.service_reference == candidate_observation.service_reference
                )
                or (
                    isinstance(candidate_observation, EndpointHealthObservation)
                    and isinstance(item, EndpointHealthObservation)
                    and item.status == "recovered"
                    and item.subject_resource_id == candidate_observation.subject_resource_id
                    and item.path_id == candidate_observation.path_id
                    and item.backend_resource_ids == candidate_observation.backend_resource_ids
                )
            )
            and item.observed_start >= request.incident_anchor.observed_end
            and item.observed_start >= candidate_observation.observed_end
        ),
        key=lambda item: (item.observed_start, item.observation_id),
    )
    if not recoveries:
        return 0, [], ()
    recovery = recoveries[0]
    recovery_citation = citations[recovery.observation_id]
    corrective_changes = sorted(
        (
            item
            for item in request.change_artifacts
            if item.evidence.target_resource_id == cause_resource_id
            and item.evidence.result == "succeeded"
            and request.incident_anchor.observed_start
            < item.evidence.occurred_at
            <= recovery.observed_start
            and candidate_artifact is not None
            and _is_exact_corrective_change(candidate_artifact, item)
        ),
        key=lambda item: (
            item.evidence.occurred_at,
            item.evidence.evidence_id,
        ),
    )
    if corrective_changes:
        return (
            _SCORE_WEIGHTS["correctiveRecovery"],
            [recovery_citation],
            tuple(
                sorted(
                    (
                        corrective_changes[0].evidence.evidence_id,
                        recovery_citation.evidence_id,
                    )
                )
            ),
        )
    return (
        _SCORE_WEIGHTS["observedRecovery"],
        [recovery_citation],
        (recovery_citation.evidence_id,),
    )


def _is_exact_corrective_change(
    candidate: ChangeEvidenceArtifact,
    corrective: ChangeEvidenceArtifact,
) -> bool:
    candidate_properties = tuple(
        sorted(
            (
                item.path.casefold(),
                item.before_evidence_reference,
                item.after_evidence_reference,
                item.is_truncated,
            )
            for item in candidate.evidence.changed_properties
        )
    )
    corrective_properties = tuple(
        sorted(
            (
                item.path.casefold(),
                item.before_evidence_reference,
                item.after_evidence_reference,
                item.is_truncated,
            )
            for item in corrective.evidence.changed_properties
        )
    )
    candidate_paths = tuple(item[0] for item in candidate_properties)
    corrective_paths = tuple(item[0] for item in corrective_properties)
    return (
        bool(candidate_properties)
        and len(candidate_paths) == len(set(candidate_paths))
        and len(corrective_paths) == len(set(corrective_paths))
        and candidate_paths == corrective_paths
        and all(
            not candidate_truncated
            and not corrective_truncated
            and candidate_before is not None
            and candidate_after is not None
            and corrective_before == candidate_after
            and corrective_after == candidate_before
            for (
                _,
                candidate_before,
                candidate_after,
                candidate_truncated,
            ), (
                _,
                corrective_before,
                corrective_after,
                corrective_truncated,
            ) in zip(
                candidate_properties,
                corrective_properties,
                strict=True,
            )
        )
    )


def _path_for_resources(
    paths: Iterable[DependencyPath],
    *resource_ids: str,
) -> DependencyPath | None:
    required = set(resource_ids)
    matches = sorted(
        (item for item in paths if required.issubset(item.resource_ids)),
        key=lambda item: item.path_id,
    )
    return matches[0] if matches else None


def _path_gate_citation(
    path: DependencyPath | None,
    *,
    flow: NetworkFlowObservation | None,
    endpoint: EndpointHealthObservation | None,
    citations: dict[str, CorrelationEvidenceCitation],
) -> CorrelationEvidenceCitation | None:
    if path is None:
        return None
    path_resources = set(path.resource_ids)
    for observation in (flow, endpoint):
        if observation is None:
            continue
        citation = citations[observation.observation_id]
        if set(citation.resource_ids).issubset(path_resources):
            return citation
    return None


def _first_path_citation(
    citations: Iterable[CorrelationEvidenceCitation],
    path: DependencyPath | None,
    observation_by_id: Mapping[str, object],
) -> CorrelationEvidenceCitation | None:
    if path is None:
        return None
    path_ids = set(path.resource_ids)
    matches = sorted(
        (
            item
            for item in citations
            if item.family in {"networkFlow", "connectionMonitor", "endpointHealth"}
            and not item.summary_code.startswith("coverage.")
            and set(item.resource_ids).issubset(path_ids)
            and _citation_matches_path(
                item,
                path,
                observation_by_id,
            )
        ),
        key=lambda item: item.evidence_id,
    )
    return matches[0] if matches else None


def _citation_relevant(
    citation: CorrelationEvidenceCitation,
    path: DependencyPath | None,
    request: CorrelationRequest,
    observation_by_id: Mapping[str, object],
) -> bool:
    if citation.observed_start > request.incident_anchor.observed_start:
        return False
    if not _strict_overlap(
        citation.observed_start,
        citation.observed_end,
        request.incident_anchor.observed_start,
        request.incident_anchor.observed_end,
    ):
        return False
    if path is None:
        return request.incident_anchor.affected_resource_id in citation.resource_ids
    return _citation_matches_path(
        citation,
        path,
        observation_by_id,
    )


def _citation_matches_path(
    citation: CorrelationEvidenceCitation,
    path: DependencyPath,
    observation_by_id: Mapping[str, object],
) -> bool:
    if not set(citation.resource_ids).intersection(path.resource_ids):
        return False
    observation = observation_by_id.get(citation.evidence_id)
    if isinstance(
        observation,
        (
            NetworkFlowObservation,
            ConnectionMonitorObservation,
            EndpointHealthObservation,
        ),
    ):
        return observation.path_id == path.path_id
    return True


def _independent_citations(
    citations: Iterable[CorrelationEvidenceCitation],
) -> list[CorrelationEvidenceCitation]:
    result: list[CorrelationEvidenceCitation] = []
    seen_families: set[str] = set()
    seen_roots: set[str] = set()
    for citation in sorted(citations, key=lambda item: item.evidence_id):
        if citation.summary_code.startswith("coverage."):
            continue
        if citation.family in seen_families or citation.provenance_root_digest in seen_roots:
            continue
        seen_families.add(citation.family)
        seen_roots.add(citation.provenance_root_digest)
        result.append(citation)
    return result


def _is_adverse_observation(observation: object) -> bool:
    if isinstance(observation, GuestSignalObservation):
        return observation.state in {"degraded", "unhealthy", "unavailable"}
    if isinstance(observation, NetworkFlowObservation):
        return observation.decision == "denied"
    if isinstance(observation, ConnectionMonitorObservation):
        return observation.status in {"failed", "degraded"}
    if isinstance(observation, EndpointHealthObservation):
        return observation.status in {"degraded", "unhealthy", "unavailable"}
    if isinstance(observation, PlatformHealthObservation):
        return observation.status in {"degraded", "unhealthy", "unavailable"}
    return False


def _change_semantic_score(
    artifact: ChangeEvidenceArtifact,
    category: RootCauseCategory,
) -> int:
    paths = tuple(item.path.casefold() for item in artifact.evidence.changed_properties)
    if category == "routingChange":
        relevant = set(CORRELATION_RULE_CATALOG.routing_property_paths)
        return (
            _SCORE_WEIGHTS["routingChangeSemantic"]
            if any(path in relevant for path in paths)
            else 0
        )
    non_metadata = tuple(path for path in paths if not path.startswith("tags.") and path != "tags")
    return _SCORE_WEIGHTS["genericChangeSemantic"] if non_metadata else 0


def _topology_score(
    path: DependencyPath | None,
    *,
    cause_resource_id: str,
    affected_resource_id: str,
) -> int:
    if path is None:
        return 0
    resources = set(path.resource_ids)
    if cause_resource_id in resources and affected_resource_id in resources:
        return _SCORE_WEIGHTS["topologyExactPath"]
    if affected_resource_id in resources:
        return _SCORE_WEIGHTS["topologyAffectedPath"]
    return _SCORE_WEIGHTS["topologyDeclaredPath"]


def _temporal_score(candidate: datetime, degradation: datetime) -> int:
    seconds = (degradation - candidate).total_seconds()
    if seconds < 0:
        return 0
    for maximum_seconds, score in CORRELATION_RULE_CATALOG.temporal_score_windows:
        if seconds <= maximum_seconds:
            return score
    return 0


def _score(
    topology: int,
    temporal: int,
    semantic: int,
    corroboration: int,
    recovery: int,
) -> CorrelationScoreComponents:
    return CorrelationScoreComponents(
        topology=topology,
        temporal=temporal,
        semantic=semantic,
        corroboration=corroboration,
        recovery=recovery,
        rawScore=topology + temporal + semantic + corroboration + recovery,
    )


def _gate(
    code: CorrelationGateCode,
    citation: CorrelationEvidenceCitation,
) -> CorrelationGate:
    return CorrelationGate(
        code=code,
        satisfied=True,
        evidenceIds=(citation.evidence_id,),
    )


def _cap(
    code: ConfidenceCapCode,
    maximum: ConfidenceLevel | None = None,
) -> ConfidenceCap:
    resolved = _CAP_LEVELS[code] if maximum is None else maximum
    return ConfidenceCap(code=code, maximumConfidence=resolved)


def _missing(
    code: MissingEvidenceCode,
    family: EvidenceFamily,
    detail: str,
    required: ConfidenceLevel,
) -> MissingCorrelationEvidence:
    return MissingCorrelationEvidence(
        code=code,
        family=family,
        detail=detail,
        requiredForConfidence=required,
    )


def _contradiction(
    code: ContradictionCode,
    detail: str,
    citations: Iterable[CorrelationEvidenceCitation],
) -> CorrelationContradiction:
    hard = code in {
        "changeFailed",
        "changeAfterDegradation",
        "completeAllowedFlow",
        "completeHealthyConnectionMonitor",
        "recoveryBeforeCorrection",
    }
    return CorrelationContradiction(
        code=code,
        detail=detail,
        evidenceIds=tuple(sorted(item.evidence_id for item in citations)),
        hardConflict=hard,
    )


def _make_hypothesis(
    *,
    category: RootCauseCategory,
    cause_resource_id: str | None,
    path_id: str | None,
    candidate_causal_at: datetime | None,
    score: CorrelationScoreComponents,
    confidence: ConfidenceLevel,
    support: Iterable[CorrelationEvidenceCitation],
    contradictions: Iterable[CorrelationContradiction],
    missing: Iterable[MissingCorrelationEvidence],
    gates: Iterable[CorrelationGate],
    caps: Iterable[ConfidenceCap],
) -> RootCauseHypothesis:
    sorted_support = tuple(
        sorted(
            {item.evidence_id: item for item in support}.values(),
            key=lambda item: item.evidence_id,
        )
    )
    sorted_contradictions = tuple(
        sorted(
            contradictions,
            key=lambda item: (
                item.code,
                item.evidence_ids,
                item.detail,
                item.hard_conflict,
            ),
        )
    )
    sorted_missing = tuple(
        sorted(
            missing,
            key=lambda item: (
                item.code,
                item.family,
                item.detail,
                item.required_for_confidence,
            ),
        )
    )
    sorted_gates = tuple(
        sorted(
            {item.code: item for item in gates}.values(),
            key=lambda item: item.code,
        )
    )
    cap_by_code: dict[str, ConfidenceCap] = {}
    for item in caps:
        current = cap_by_code.get(item.code)
        if current is None or (
            _CONFIDENCE_RANK[item.maximum_confidence] < _CONFIDENCE_RANK[current.maximum_confidence]
        ):
            cap_by_code[item.code] = item
    sorted_caps = tuple(sorted(cap_by_code.values(), key=lambda item: item.code))
    values = {
        "rank": 1,
        "category": category,
        "causeResourceId": cause_resource_id,
        "affectedPathId": path_id,
        "candidateCausalAt": candidate_causal_at,
        "score": score,
        "confidence": confidence,
        "supportingEvidence": sorted_support,
        "contradictions": sorted_contradictions,
        "missingEvidence": sorted_missing,
        "gates": sorted_gates,
        "caps": sorted_caps,
    }
    digest_payload = {
        "category": category,
        "causeResourceId": cause_resource_id,
        "affectedPathId": path_id,
        "candidateCausalAt": candidate_causal_at,
        "score": score.model_dump(mode="json", by_alias=True),
        "confidence": confidence,
        "supportingEvidence": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            for item in sorted_support
        ],
        "contradictions": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            for item in sorted_contradictions
        ],
        "missingEvidence": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            for item in sorted_missing
        ],
        "gates": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in sorted_gates
        ],
        "caps": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in sorted_caps
        ],
    }
    digest_payload = {key: value for key, value in digest_payload.items() if value is not None}
    digest = compute_artifact_digest(digest_payload)
    return RootCauseHypothesis.model_validate(
        {
            **values,
            "hypothesisId": f"hyp-{digest.removeprefix('sha256:')[:32]}",
            "hypothesisDigest": digest,
        }
    )


def _deduplicate_hypotheses(
    hypotheses: Iterable[RootCauseHypothesis],
) -> list[RootCauseHypothesis]:
    return list(
        {
            (
                item.category,
                item.cause_resource_id,
                item.affected_path_id,
                item.hypothesis_digest,
            ): item
            for item in hypotheses
        }.values()
    )


def _hypothesis_sort_key(item: RootCauseHypothesis) -> tuple[object, ...]:
    hard_conflicts = sum(1 for contradiction in item.contradictions if contradiction.hard_conflict)
    causal_timestamp = (
        -item.candidate_causal_at.timestamp()
        if item.candidate_causal_at is not None
        else float("inf")
    )
    return (
        -_CONFIDENCE_RANK[item.confidence],
        -item.score.raw_score,
        hard_conflicts,
        len(item.contradictions),
        len(item.missing_evidence),
        causal_timestamp,
        _CATEGORY_ORDER[item.category],
        (item.cause_resource_id or "").casefold(),
        item.hypothesis_digest,
    )


def _flow_resource_ids(flow: NetworkFlowObservation) -> tuple[str, ...]:
    values = {
        flow.subject_resource_id,
        flow.source_resource_id,
        flow.destination_resource_id,
        flow.enforcement_resource_id,
    }
    if flow.rule_resource_id is not None:
        values.add(flow.rule_resource_id)
    return tuple(sorted(values))


def _network_tuple_key(
    observation: NetworkFlowObservation | ConnectionMonitorObservation,
) -> tuple[str, ...]:
    return (
        observation.path_id,
        observation.direction,
        observation.five_tuple_digest,
        observation.source_resource_id,
        observation.destination_resource_id,
        observation.source_address,
        observation.destination_address,
        observation.protocol,
        "" if observation.source_port is None else str(observation.source_port),
        "" if observation.destination_port is None else str(observation.destination_port),
    )


def _nsg_chain_key(observation: NetworkFlowObservation) -> tuple[str, ...]:
    return (
        *_network_tuple_key(observation),
        observation.enforcement_resource_id,
        observation.rule_resource_id or "",
    )


def _same_flow(
    first: NetworkFlowObservation,
    second: NetworkFlowObservation,
) -> bool:
    return (
        first.path_id == second.path_id
        and first.direction == second.direction
        and first.five_tuple_digest == second.five_tuple_digest
        and first.source_resource_id == second.source_resource_id
        and first.destination_resource_id == second.destination_resource_id
        and first.source_address == second.source_address
        and first.destination_address == second.destination_address
        and first.protocol == second.protocol
        and first.source_port == second.source_port
        and first.destination_port == second.destination_port
        and first.enforcement_resource_id == second.enforcement_resource_id
        and first.rule_resource_id == second.rule_resource_id
    )


def _same_monitor(
    first: ConnectionMonitorObservation,
    second: ConnectionMonitorObservation,
) -> bool:
    return (
        first.path_id == second.path_id
        and first.direction == second.direction
        and first.five_tuple_digest == second.five_tuple_digest
        and first.source_resource_id == second.source_resource_id
        and first.destination_resource_id == second.destination_resource_id
        and first.source_address == second.source_address
        and first.destination_address == second.destination_address
        and first.protocol == second.protocol
        and first.source_port == second.source_port
        and first.destination_port == second.destination_port
        and first.test_configuration_reference == second.test_configuration_reference
        and first.test_configuration_digest == second.test_configuration_digest
    )


def _strict_overlap(
    start: datetime,
    end: datetime,
    incident_start: datetime,
    incident_end: datetime,
) -> bool:
    return start < incident_end and end > incident_start


def _overlaps_incident(
    observation: (
        GuestSignalObservation
        | NetworkFlowObservation
        | ConnectionMonitorObservation
        | EndpointHealthObservation
        | PlatformHealthObservation
    ),
    request: CorrelationRequest,
) -> bool:
    return _strict_overlap(
        observation.observed_start,
        observation.observed_end,
        request.incident_anchor.observed_start,
        request.incident_anchor.observed_end,
    )


def _is_nsg_property(path: str) -> bool:
    normalized = path.casefold()
    return normalized in _NSG_PROPERTY_PATHS or any(
        normalized.startswith(f"{item}[")
        and normalized.endswith("]")
        and normalized[len(item) + 1 : -1].isdigit()
        for item in _NSG_PROPERTY_PATHS
    )


__all__ = [
    "classify_confidence",
]
