from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    CORRELATION_ALGORITHM_ID,
    CORRELATION_REPORT_SCHEMA_VERSION,
    CORRELATION_REQUEST_SCHEMA_VERSION,
    MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    ApprovedChangeScope,
    ChangeEvidenceArtifact,
    ChangeEvidenceAttestation,
    ChangeEvidencePersistenceHandoff,
    ConfidenceCap,
    ConnectionMonitorObservation,
    CorrelationContradiction,
    CorrelationEvidenceCitation,
    CorrelationEvidenceInventory,
    CorrelationGate,
    CorrelationReport,
    CorrelationRequest,
    CorrelationScoreComponents,
    DependencyPath,
    DraftPreviewContextBinding,
    EndpointHealthObservation,
    EvidenceCoverage,
    EvidenceCoverageScope,
    GuestSignalObservation,
    IncidentHealthTransition,
    MissingCorrelationEvidence,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceBundle,
    MonitoringEvidenceHandoff,
    MonitoringObservation,
    NetworkFlowObservation,
    PublishedContextAuthority,
    PublishedRuntimeContextBinding,
    RootCauseHypothesis,
    VersionPinnedBlobReference,
    canonicalize_json,
    change_evidence_attestation_preimage,
    compute_artifact_digest,
    monitoring_handoff_preimage,
    sha256_hex,
    validate_correlation_report_binding,
    validate_runtime_correlation_report,
)
from athena_context.eventing.change_ingestion import normalize_resource_graph_change

SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
RESOURCE_GROUP = "rg-synthetic-wc026"
WEB_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
    "providers/Microsoft.Compute/virtualMachines/synthetic-web-01"
)
DB_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
    "providers/Microsoft.Compute/virtualMachines/synthetic-db-01"
)
NOW = datetime(2026, 9, 10, 2, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
NSG_RULE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
    "providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg/"
    "securityRules/deny-web"
)


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _json_value(item)
            for key, item in value.items()
            if item is not None
        }
    return value


def _source_reference(
    *,
    content_digest: str = DIGEST_A,
) -> VersionPinnedBlobReference:
    return VersionPinnedBlobReference(
        name="wc024-monitoring/wc024-0123456789ab/evidence.json",
        version="2026-09-10T02:00:00.0000000Z",
        contentDigest=content_digest,
    )


def _bound_observation(
    **overrides: object,
) -> GuestSignalObservation:
    source_root_reference = "azure-monitor-source:sha256:" + "a" * 64
    source_record_reference = "azure-monitor:sha256:" + "d" * 64
    payload: dict[str, object] = {
        "observationKind": "guestSignal",
        "subjectResourceId": WEB_ID.lower(),
        "observedStart": NOW - timedelta(minutes=5),
        "observedEnd": NOW,
        "provenanceRootDigest": sha256_hex(source_root_reference),
        "sourceRootReference": source_root_reference,
        "sourceRecordReference": source_record_reference,
        "summaryCode": "guest.heartbeat-loss",
        "signal": "heartbeatLoss",
        "state": "unhealthy",
        "value": None,
        "unit": None,
        "thresholdDigest": None,
        "serviceReference": None,
    }
    payload.update(overrides)
    if (
        "sourceRootReference" in overrides
        and "provenanceRootDigest" not in overrides
    ):
        payload["provenanceRootDigest"] = sha256_hex(
            str(payload["sourceRootReference"])
        )
    digest = compute_artifact_digest(_json_value(payload))
    return GuestSignalObservation(
        **payload,
        observationId=f"obs-{digest.removeprefix('sha256:')[:32]}",
        observationDigest=digest,
    )


def _network_flow_observation(
    *,
    path: DependencyPath,
    matched_change_key: str = DIGEST_C,
    matched_change_evidence_id: str = "chg-000000000000",
    matched_change_artifact_digest: str = DIGEST_C,
    decision: str = "denied",
    direction: str = "inbound",
    observed_start: datetime | None = None,
    observed_end: datetime | None = None,
    source_seed: str = "1",
    effective_rule_attribution: bool = True,
) -> NetworkFlowObservation:
    source_root_reference = "network-flow-source:sha256:" + "1" * 64
    source_record_reference = "network-flow:sha256:" + source_seed * 64
    tuple_payload = {
        "direction": direction,
        "protocol": "Tcp",
        "sourceResourceId": WEB_ID.lower(),
        "destinationResourceId": DB_ID.lower(),
        "sourceAddress": "192.0.2.10",
        "destinationAddress": "192.0.2.20",
        "sourcePort": 443,
        "destinationPort": 1433,
    }
    payload: dict[str, object] = {
        "observationKind": "networkFlow",
        "subjectResourceId": WEB_ID.lower(),
        "observedStart": observed_start or NOW - timedelta(minutes=4),
        "observedEnd": observed_end or NOW,
        "provenanceRootDigest": sha256_hex(source_root_reference),
        "sourceRootReference": source_root_reference,
        "sourceRecordReference": source_record_reference,
        "summaryCode": f"network.flow-{decision}",
        "pathId": path.path_id,
        "decision": decision,
        "direction": direction,
        "protocol": "Tcp",
        "sourceResourceId": WEB_ID.lower(),
        "destinationResourceId": DB_ID.lower(),
        "sourceAddress": "192.0.2.10",
        "destinationAddress": "192.0.2.20",
        "sourcePort": 443,
        "destinationPort": 1433,
        "enforcementResourceId": NSG_RULE_ID.lower(),
        "ruleResourceId": NSG_RULE_ID.lower(),
        "fiveTupleDigest": compute_artifact_digest(tuple_payload),
        "effectiveRuleAttribution": effective_rule_attribution,
        "attributionMethod": (
            "ipFlowVerify" if effective_rule_attribution else None
        ),
        "causalEffect": (
            "introducedDenyForTuple" if effective_rule_attribution else None
        ),
        "attributionProofDigest": (
            "sha256:" + "7" * 64 if effective_rule_attribution else None
        ),
        "matchedChangeKey": (
            matched_change_key if effective_rule_attribution else None
        ),
        "matchedChangeEvidenceId": (
            matched_change_evidence_id if effective_rule_attribution else None
        ),
        "matchedChangeArtifactDigest": (
            matched_change_artifact_digest if effective_rule_attribution else None
        ),
        "matchedPropertyPaths": (
            ("properties.access",) if effective_rule_attribution else ()
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return NetworkFlowObservation(
        **payload,
        observationId=f"obs-{digest.removeprefix('sha256:')[:32]}",
        observationDigest=digest,
    )


def _connection_monitor_observation(
    *,
    path: DependencyPath,
    five_tuple_digest: str | None = None,
    direction: str = "inbound",
    observed_start: datetime | None = None,
    observed_end: datetime | None = None,
    status: str = "failed",
    source_seed: str = "2",
) -> ConnectionMonitorObservation:
    source_root_reference = "connection-monitor-source:sha256:" + "2" * 64
    source_record_reference = "connection-monitor:sha256:" + source_seed * 64
    tuple_digest = compute_artifact_digest(
        {
            "direction": direction,
            "protocol": "Tcp",
            "sourceResourceId": WEB_ID.lower(),
            "destinationResourceId": DB_ID.lower(),
            "sourceAddress": "192.0.2.10",
            "destinationAddress": "192.0.2.20",
            "sourcePort": 443,
            "destinationPort": 1433,
        }
    )
    payload: dict[str, object] = {
        "observationKind": "connectionMonitor",
        "subjectResourceId": WEB_ID.lower(),
        "observedStart": observed_start or NOW - timedelta(minutes=4),
        "observedEnd": observed_end or NOW,
        "provenanceRootDigest": sha256_hex(source_root_reference),
        "sourceRootReference": source_root_reference,
        "sourceRecordReference": source_record_reference,
        "summaryCode": f"connection-monitor.{status}",
        "pathId": path.path_id,
        "monitorResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
            "providers/Microsoft.Network/networkWatchers/synthetic-watcher/"
            "connectionMonitors/synthetic-web-db"
        ).lower(),
        "sourceResourceId": WEB_ID.lower(),
        "destinationResourceId": DB_ID.lower(),
        "sourceAddress": "192.0.2.10",
        "destinationAddress": "192.0.2.20",
        "direction": direction,
        "protocol": "Tcp",
        "sourcePort": 443,
        "destinationPort": 1433,
        "fiveTupleDigest": five_tuple_digest or tuple_digest,
        "status": status,
        "testConfigurationReference": "synthetic-web-db-test",
        "testConfigurationDigest": "sha256:" + "3" * 64,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return ConnectionMonitorObservation(
        **payload,
        observationId=f"obs-{digest.removeprefix('sha256:')[:32]}",
        observationDigest=digest,
    )


def _endpoint_health_observation(
    *,
    path: DependencyPath,
    observed_start: datetime | None = None,
    observed_end: datetime | None = None,
    status: str = "unhealthy",
) -> EndpointHealthObservation:
    source_root_reference = "endpoint-health-source:sha256:" + "4" * 64
    source_record_reference = "endpoint-health:sha256:" + "4" * 64
    payload: dict[str, object] = {
        "observationKind": "endpointHealth",
        "subjectResourceId": WEB_ID.lower(),
        "observedStart": observed_start or NOW - timedelta(minutes=4),
        "observedEnd": observed_end or NOW,
        "provenanceRootDigest": sha256_hex(source_root_reference),
        "sourceRootReference": source_root_reference,
        "sourceRecordReference": source_record_reference,
        "summaryCode": f"endpoint.{status}",
        "pathId": path.path_id,
        "status": status,
        "backendResourceIds": (DB_ID.lower(),),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return EndpointHealthObservation(
        **payload,
        observationId=f"obs-{digest.removeprefix('sha256:')[:32]}",
        observationDigest=digest,
    )


def _coverage_scope(**overrides: object) -> EvidenceCoverageScope:
    payload: dict[str, object] = {
        "resourceIds": (WEB_ID.lower(),),
        "pathId": None,
        "direction": None,
        "fiveTupleDigest": None,
        "endpointTestReference": None,
        "queryScopeDigest": DIGEST_C,
    }
    payload.update(overrides)
    digest = compute_artifact_digest(_json_value(payload))
    return EvidenceCoverageScope(
        **payload,
        scopeId=f"coverage-scope-{digest.removeprefix('sha256:')[:32]}",
        scopeDigest=digest,
    )


def _coverage(**overrides: object) -> EvidenceCoverage:
    source_root_reference = "coverage-query-source:sha256:" + "5" * 64
    source_record_reference = "coverage-query:sha256:" + "5" * 64
    payload: dict[str, object] = {
        "family": "guest",
        "scope": _coverage_scope(),
        "provenanceRootDigest": sha256_hex(source_root_reference),
        "sourceRootReference": source_root_reference,
        "sourceRecordReference": source_record_reference,
        "coverageStart": NOW - timedelta(minutes=10),
        "coverageEnd": NOW,
        "status": "complete",
        "detail": None,
    }
    payload.update(overrides)
    digest = compute_artifact_digest(_json_value(payload))
    return EvidenceCoverage(
        **payload,
        coverageId=f"coverage-{digest.removeprefix('sha256:')[:32]}",
        coverageDigest=digest,
    )


def _monitoring_handoff(
    *,
    bundle: MonitoringEvidenceBundle,
) -> MonitoringEvidenceHandoff:
    reference = _source_reference(
        content_digest=sha256_hex(bundle.canonical_bytes()),
    )
    payload = {
        "schemaVersion": "athena.wc024MonitoringEvidenceHandoff.v1",
        "collectorContractDigest": DIGEST_C,
        "collectionId": "wc024-0123456789ab",
        "observedAt": NOW,
        "evidence": reference.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
    }
    signed_preimage_digest = compute_artifact_digest(monitoring_handoff_preimage(payload))
    return MonitoringEvidenceHandoff(
        **payload,
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=(
                "https://synthetic-wc026.vault.azure.net/keys/"
                "monitoring-signing/0123456789abcdef0123456789abcdef"
            ),
            signedPreimageDigest=signed_preimage_digest,
            signature=base64.b64encode(b"synthetic-signature").decode("ascii"),
        ),
    )


def _change_pair() -> tuple[ChangeEvidenceArtifact, ChangeEvidencePersistenceHandoff]:
    scope = ApprovedChangeScope(
        schemaVersion="athena.approvedChangeScope.v1",
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName=RESOURCE_GROUP,
        approvedResourceIds=(NSG_RULE_ID.lower(),),
    )
    change = {
        "id": (
            f"{NSG_RULE_ID}/providers/Microsoft.Resources/changes/"
            "synthetic-wc026-change-001"
        ),
        "properties": {
            "targetResourceId": NSG_RULE_ID,
            "targetResourceType": (
                "microsoft.network/networksecuritygroups/securityrules"
            ),
            "changeType": "Update",
            "changeAttributes": {
                "previousResourceSnapshotId": "synthetic-before",
                "newResourceSnapshotId": "synthetic-after",
                "changesCount": 1,
                "changedByType": "Application",
                "changedBy": "synthetic-wc026-deployer",
                "clientType": "Automation",
                "operation": (
                    "Microsoft.Network/networkSecurityGroups/securityRules/write"
                ),
                "timestamp": (
                    NOW - timedelta(minutes=6)
                ).isoformat().replace("+00:00", "Z"),
                "correlationId": "11111111-1111-1111-1111-111111111111",
            },
            "changes": {
                "properties.access": {
                    "previousValue": "Allow",
                    "newValue": "Deny",
                }
            },
        },
    }
    evidence = normalize_resource_graph_change(
        change,
        scope=scope,
        received_at=NOW - timedelta(minutes=5),
    )
    attestation_digest = sha256_hex(
        canonicalize_json(change_evidence_attestation_preimage(evidence)).encode(
            "utf-8"
        )
    )
    artifact = ChangeEvidenceArtifact(
        schemaVersion="athena.changeEvidenceArtifact.v1",
        evidence=evidence,
        attestation=ChangeEvidenceAttestation(
            schemaVersion="athena.changeEvidenceAttestation.v1",
            signatureAlgorithm="RS256",
            keyVaultKeyId=(
                "https://synthetic-wc026.vault.azure.net/keys/"
                "change-signing/0123456789abcdef0123456789abcdef"
            ),
            signedPreimageDigest=attestation_digest,
            signature=base64.b64encode(b"synthetic-change-signature").decode("ascii"),
        ),
    )
    artifact_digest = sha256_hex(artifact.canonical_bytes())
    handoff = ChangeEvidencePersistenceHandoff(
        schemaVersion="athena.changeEvidencePersistenceHandoff.v1",
        evidenceId=evidence.evidence_id,
        deduplicationKey=evidence.deduplication_key,
        changeKey=evidence.change_key,
        artifact=VersionPinnedBlobReference(
            name=(
                "change-evidence/"
                f"{evidence.deduplication_key.removeprefix('sha256:')}/evidence.json"
            ),
            version="2026-09-10T01:55:00.0000000Z",
            contentDigest=artifact_digest,
        ),
    )
    return artifact, handoff


def _bundle(
    *,
    observations: tuple[MonitoringObservation, ...] | None = None,
    coverage: tuple[EvidenceCoverage, ...] | None = None,
) -> MonitoringEvidenceBundle:
    bundle_observations = (
        tuple(
            sorted(
                (
                    _bound_observation(
                        observedStart=NOW - timedelta(minutes=10),
                        observedEnd=NOW - timedelta(minutes=5),
                        state="healthy",
                        summaryCode="guest.heartbeat-healthy",
                        sourceRootReference=(
                            "azure-monitor-source:sha256:" + "a" * 64
                        ),
                        sourceRecordReference="azure-monitor:sha256:" + "0" * 64,
                    ),
                    _bound_observation(),
                ),
                key=lambda item: item.observation_id,
            )
        )
        if observations is None
        else observations
    )
    bundle_coverage = (_coverage(),) if coverage is None else coverage
    payload: dict[str, object] = {
        "schemaVersion": MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "workloadId": "synthetic-wc026",
        "monitoringContractDigest": DIGEST_C,
        "observedStart": NOW - timedelta(minutes=10),
        "observedEnd": NOW,
        "observations": bundle_observations,
        "coverage": bundle_coverage,
        "expectedCoverageScopeDigests": tuple(
            sorted(item.scope.scope_digest for item in bundle_coverage)
        ),
    }
    return MonitoringEvidenceBundle(**payload)


def _nsg_bundle(
    *,
    matched_change_key: str,
    matched_change_evidence_id: str,
    matched_change_artifact_digest: str,
    flow_decision: str = "denied",
    effective_rule_attribution: bool = True,
) -> tuple[
    MonitoringEvidenceBundle,
    NetworkFlowObservation,
    ConnectionMonitorObservation,
    EndpointHealthObservation,
]:
    path = _dependency_path()
    flow = _network_flow_observation(
        path=path,
        matched_change_key=matched_change_key,
        matched_change_evidence_id=matched_change_evidence_id,
        matched_change_artifact_digest=matched_change_artifact_digest,
        decision=flow_decision,
        effective_rule_attribution=effective_rule_attribution,
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
    network_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                (
                    WEB_ID.lower(),
                    DB_ID.lower(),
                    NSG_RULE_ID.lower(),
                )
            )
        ),
        pathId=path.path_id,
        direction=flow.direction,
        fiveTupleDigest=flow.five_tuple_digest,
    )
    monitor_scope = _coverage_scope(
        resourceIds=tuple(
            sorted(
                (
                    WEB_ID.lower(),
                    DB_ID.lower(),
                )
            )
        ),
        pathId=path.path_id,
        direction=monitor.direction,
        fiveTupleDigest=monitor.five_tuple_digest,
        endpointTestReference=monitor.test_configuration_reference,
        endpointTestDigest=monitor.test_configuration_digest,
    )
    endpoint_scope = _coverage_scope(
        resourceIds=tuple(sorted((WEB_ID.lower(), DB_ID.lower()))),
        pathId=path.path_id,
    )
    coverage = tuple(
        sorted(
            (
                _coverage(family="networkFlow", scope=network_scope),
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
    )
    bundle = _bundle(
        observations=tuple(
            sorted(
                (flow, monitor, previous_endpoint, endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=coverage,
    )
    return bundle, flow, monitor, endpoint


def _dependency_path() -> DependencyPath:
    payload: dict[str, object] = {
        "pathClass": "declared",
        "sourceRoleRef": "web",
        "targetRoleRef": "database",
        "relationshipIds": ("relationship-web-db",),
        "resourceIds": tuple(
            sorted((DB_ID.lower(), NSG_RULE_ID.lower(), WEB_ID.lower()))
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return DependencyPath(
        **payload,
        pathId=f"path-{digest.removeprefix('sha256:')[:32]}",
        pathDigest=digest,
    )


def _context_binding(
    *,
    binding_mode: str = "publishedRuntime",
    required_coverage_scope_digests: tuple[str, ...] | None = None,
) -> PublishedRuntimeContextBinding | DraftPreviewContextBinding:
    common: dict[str, object] = {
        "workloadId": "synthetic-wc026",
        "manifestId": "manifest-synthetic",
        "manifestVersion": "2026.09.10.1",
        "manifestDigest": DIGEST_A,
        "profileId": "production",
        "resolvedProfileDigest": DIGEST_B,
        "dependencyGraphDigest": DIGEST_C,
        "dependencyPaths": (_dependency_path(),),
        "requiredCoverageScopeDigests": (
            (_coverage().scope.scope_digest,)
            if required_coverage_scope_digests is None
            else required_coverage_scope_digests
        ),
    }
    if binding_mode == "publishedRuntime":
        authority_payload: dict[str, object] = {
            "workloadId": common["workloadId"],
            "manifestId": common["manifestId"],
            "manifestVersion": common["manifestVersion"],
            "manifestDigest": common["manifestDigest"],
            "profileId": common["profileId"],
            "resolvedProfileDigest": common["resolvedProfileDigest"],
            "dependencyGraphDigest": common["dependencyGraphDigest"],
            "publicationRecordDigest": DIGEST_A,
            "auditHeadDigest": DIGEST_B,
            "publishedAt": NOW - timedelta(hours=1),
        }
        authority_digest = compute_artifact_digest(_json_value(authority_payload))
        authority = PublishedContextAuthority(
            **authority_payload,
            authorityId=(
                "publication-authority-"
                + authority_digest.removeprefix("sha256:")[:32]
            ),
            authorityDigest=authority_digest,
        )
        payload = {
            **common,
            "bindingMode": "publishedRuntime",
            "publicationAuthority": authority,
            "previewOnly": False,
        }
        digest = compute_artifact_digest(_json_value(payload))
        return PublishedRuntimeContextBinding(**payload, bindingDigest=digest)

    payload = {
        **common,
        "bindingMode": "draftPreview",
        "draftId": "draft-synthetic",
        "draftRevision": 3,
        "previewOnly": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return DraftPreviewContextBinding(**payload, bindingDigest=digest)


def _citation(
    *,
    observation: GuestSignalObservation,
    source_reference: VersionPinnedBlobReference,
) -> CorrelationEvidenceCitation:
    return CorrelationEvidenceCitation(
        evidenceId=observation.observation_id,
        family="guest",
        provenanceRootDigest=observation.provenance_root_digest,
        evidenceDigest=observation.observation_digest,
        sourceReference=source_reference,
        observedStart=observation.observed_start,
        observedEnd=observation.observed_end,
        sourceRootReference=observation.source_root_reference,
        resourceIds=(observation.subject_resource_id,),
        summaryCode=observation.summary_code,
    )


def _transition(
    *,
    previous_citation: CorrelationEvidenceCitation,
    current_citation: CorrelationEvidenceCitation,
) -> IncidentHealthTransition:
    payload: dict[str, object] = {
        "affectedResourceId": WEB_ID.lower(),
        "previousState": "healthy",
        "currentState": "unhealthy",
        "observedStart": current_citation.observed_start,
        "observedEnd": current_citation.observed_end,
        "previousStateEvidence": (previous_citation,),
        "currentStateEvidence": (current_citation,),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return IncidentHealthTransition(
        **payload,
        transitionId=f"transition-{digest.removeprefix('sha256:')[:32]}",
        transitionDigest=digest,
    )


def _inventory(
    *,
    handoff: MonitoringEvidenceHandoff,
    bundle: MonitoringEvidenceBundle,
    context_binding: PublishedRuntimeContextBinding | DraftPreviewContextBinding,
    transition: IncidentHealthTransition,
    evidence_index: tuple[CorrelationEvidenceCitation, ...],
    change_artifacts: tuple[ChangeEvidenceArtifact, ...] = (),
    change_handoffs: tuple[ChangeEvidencePersistenceHandoff, ...] = (),
) -> CorrelationEvidenceInventory:
    change_digests = tuple(
        sorted(sha256_hex(artifact.canonical_bytes()) for artifact in change_artifacts)
    )
    source_references = tuple(
        sorted(
            (
                handoff.evidence,
                *(item.artifact for item in change_handoffs),
            ),
            key=lambda item: (item.name, item.version, item.content_digest),
        )
    )
    payload: dict[str, object] = {
        "ruleCatalogDigest": DIGEST_C,
        "contextBindingDigest": context_binding.binding_digest,
        "incidentTransitionDigest": transition.transition_digest,
        "monitoringHandoffDigest": handoff.compute_artifact_digest_value(),
        "monitoringBundleDigest": sha256_hex(bundle.canonical_bytes()),
        "changeArtifactDigests": change_digests,
        "evidenceIndexDigest": compute_artifact_digest(
            [
                item.model_dump(mode="json", by_alias=True, exclude_none=True)
                for item in evidence_index
            ]
        ),
        "sourceReferences": source_references,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return CorrelationEvidenceInventory(**payload, inventoryDigest=digest)


def _request(
    *,
    binding_mode: str = "publishedRuntime",
    change_pair: tuple[
        ChangeEvidenceArtifact,
        ChangeEvidencePersistenceHandoff,
    ]
    | None = None,
    bundle_override: MonitoringEvidenceBundle | None = None,
    incident_evidence_id: str | None = None,
) -> CorrelationRequest:
    bundle = bundle_override or _bundle()
    handoff = _monitoring_handoff(bundle=bundle)
    context_binding = _context_binding(
        binding_mode=binding_mode,
        required_coverage_scope_digests=bundle.expected_coverage_scope_digests,
    )
    observation_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=observation.observation_id,
            family=(
                "guest"
                if isinstance(observation, GuestSignalObservation)
                else "networkFlow"
                if isinstance(observation, NetworkFlowObservation)
                else "connectionMonitor"
                if isinstance(observation, ConnectionMonitorObservation)
                else "endpointHealth"
                if isinstance(observation, EndpointHealthObservation)
                else "platformHealth"
            ),
            provenanceRootDigest=observation.provenance_root_digest,
            evidenceDigest=observation.observation_digest,
            sourceReference=handoff.evidence,
            observedStart=observation.observed_start,
            observedEnd=observation.observed_end,
            sourceRootReference=observation.source_root_reference,
            resourceIds=(
                (observation.subject_resource_id,)
                if isinstance(observation, GuestSignalObservation)
                else tuple(
                    sorted(
                        {
                            observation.subject_resource_id,
                            *(
                                {
                                    observation.source_resource_id,
                                    observation.destination_resource_id,
                                    observation.enforcement_resource_id,
                                    *(
                                        ()
                                        if observation.rule_resource_id is None
                                        else (observation.rule_resource_id,)
                                    ),
                                }
                                if isinstance(observation, NetworkFlowObservation)
                                else {
                                    observation.monitor_resource_id,
                                    observation.source_resource_id,
                                    observation.destination_resource_id,
                                }
                                if isinstance(
                                    observation,
                                    ConnectionMonitorObservation,
                                )
                                else set(observation.backend_resource_ids)
                                if isinstance(observation, EndpointHealthObservation)
                                else set()
                            ),
                        }
                    )
                )
            ),
            summaryCode=observation.summary_code,
        )
        for observation in bundle.observations
    )
    coverage_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=coverage.coverage_id,
            family=coverage.family,
            provenanceRootDigest=coverage.provenance_root_digest,
            evidenceDigest=coverage.coverage_digest,
            sourceReference=handoff.evidence,
            observedStart=coverage.coverage_start,
            observedEnd=coverage.coverage_end,
            sourceRootReference=coverage.source_root_reference,
            resourceIds=coverage.scope.resource_ids,
            summaryCode=f"coverage.{coverage.family}.{coverage.status}",
        )
        for coverage in bundle.coverage
    )
    change_artifacts = () if change_pair is None else (change_pair[0],)
    change_handoffs = () if change_pair is None else (change_pair[1],)
    change_citations = tuple(
        CorrelationEvidenceCitation(
            evidenceId=artifact.evidence.evidence_id,
            family="resourceChange",
            provenanceRootDigest=sha256_hex(
                artifact.evidence.source_record_reference
            ),
            evidenceDigest=sha256_hex(artifact.canonical_bytes()),
            sourceReference=change_handoff.artifact,
            observedStart=artifact.evidence.occurred_at,
            observedEnd=artifact.evidence.occurred_at,
            sourceRootReference=artifact.evidence.source_record_reference,
            resourceIds=(artifact.evidence.target_resource_id,),
            summaryCode=(
                f"change.{artifact.evidence.operation}.{artifact.evidence.result}"
            ),
        )
        for artifact, change_handoff in zip(
            change_artifacts,
            change_handoffs,
            strict=True,
        )
    )
    evidence_index = tuple(
        sorted(
            (*observation_citations, *coverage_citations, *change_citations),
            key=lambda item: item.evidence_id,
        )
    )
    selected_incident_id = incident_evidence_id or next(
        observation.observation_id
        for observation in bundle.observations
        if isinstance(
            observation,
            (GuestSignalObservation, EndpointHealthObservation),
        )
        and observation.subject_resource_id == WEB_ID.lower()
        and (
            (
                isinstance(observation, GuestSignalObservation)
                and observation.state == "unhealthy"
            )
            or (
                isinstance(observation, EndpointHealthObservation)
                and observation.status == "unhealthy"
            )
        )
    )
    current_citation = next(
        item for item in evidence_index if item.evidence_id == selected_incident_id
    )
    previous_health_id = next(
        observation.observation_id
        for observation in bundle.observations
        if (
            isinstance(observation, GuestSignalObservation)
            and observation.subject_resource_id == WEB_ID.lower()
            and observation.state == "healthy"
        )
        or (
            isinstance(observation, EndpointHealthObservation)
            and observation.subject_resource_id == WEB_ID.lower()
            and observation.status == "healthy"
        )
    )
    previous_citation = next(
        item for item in evidence_index if item.evidence_id == previous_health_id
    )
    transition = _transition(
        previous_citation=previous_citation,
        current_citation=current_citation,
    )
    payload: dict[str, object] = {
        "schemaVersion": CORRELATION_REQUEST_SCHEMA_VERSION,
        "algorithmId": CORRELATION_ALGORITHM_ID,
        "ruleCatalogDigest": DIGEST_C,
        "incidentRevision": 1,
        "issuedAt": NOW,
        "trustedAsOf": NOW + timedelta(minutes=1),
        "expiresAt": NOW + timedelta(minutes=10),
        "contextBinding": context_binding,
        "incidentAnchor": transition,
        "monitoringHandoff": handoff,
        "monitoringBundle": bundle,
        "changeArtifacts": change_artifacts,
        "changeHandoffs": change_handoffs,
        "evidenceIndex": evidence_index,
        "evidenceInventory": _inventory(
            handoff=handoff,
            bundle=bundle,
            context_binding=context_binding,
            transition=transition,
            evidence_index=evidence_index,
            change_artifacts=change_artifacts,
            change_handoffs=change_handoffs,
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return CorrelationRequest(
        **payload,
        requestId=f"request-{digest.removeprefix('sha256:')[:32]}",
        requestDigest=digest,
    )


def _hypothesis(
    *,
    rank: int = 1,
    category: str = "networkSecurityChange",
    score: CorrelationScoreComponents | None = None,
    confidence: str = "Low",
    contradictions: tuple[CorrelationContradiction, ...] = (),
    gates: tuple[CorrelationGate, ...] = (),
    caps: tuple[ConfidenceCap, ...] | None = None,
    citation: CorrelationEvidenceCitation | None = None,
    supporting_evidence: tuple[CorrelationEvidenceCitation, ...] | None = None,
    missing_evidence: tuple[MissingCorrelationEvidence, ...] | None = None,
) -> RootCauseHypothesis:
    supporting_citation = citation or _request().evidence_index[0]
    supporting = (
        (supporting_citation,)
        if supporting_evidence is None
        else supporting_evidence
    )
    payload: dict[str, object] = {
        "rank": rank,
        "category": category,
        "causeResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
            "providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg/"
            "securityRules/deny-web"
        ).lower(),
        "affectedPathId": _dependency_path().path_id,
        "candidateCausalAt": NOW - timedelta(minutes=6),
        "score": score
        or CorrelationScoreComponents(
            topology=25,
            temporal=20,
            semantic=14,
            corroboration=25,
            recovery=0,
            rawScore=84,
        ),
        "confidence": confidence,
        "supportingEvidence": supporting,
        "contradictions": contradictions,
        "missingEvidence": missing_evidence
        if missing_evidence is not None
        else (
            MissingCorrelationEvidence(
                code="recoveryObservation",
                family="endpointHealth",
                detail="Synthetic recovery evidence is not yet present.",
                requiredForConfidence="Confirmed",
            ),
        ),
        "gates": gates,
        "caps": caps
        if caps is not None
        else (
            ConfidenceCap(
                code="missingAffectedPath",
                maximumConfidence="Low",
            ),
            ConfidenceCap(
                code="missingDirectAttribution",
                maximumConfidence="High",
            ),
            ConfidenceCap(
                code="missingIndependentSupport",
                maximumConfidence="Medium",
            ),
        ),
    }
    digest = compute_artifact_digest(
        _json_value(
            {
                key: value
                for key, value in payload.items()
                if key not in {"rank"}
            }
        )
    )
    return RootCauseHypothesis(
        **payload,
        hypothesisId=f"hyp-{digest.removeprefix('sha256:')[:32]}",
        hypothesisDigest=digest,
    )


def _report_for(
    request: CorrelationRequest,
    hypothesis: RootCauseHypothesis,
) -> CorrelationReport:
    payload: dict[str, object] = {
        "schemaVersion": CORRELATION_REPORT_SCHEMA_VERSION,
        "algorithmId": CORRELATION_ALGORITHM_ID,
        "ruleCatalogDigest": request.rule_catalog_digest,
        "asOf": request.trusted_as_of,
        "bindingMode": request.context_binding.binding_mode,
        "contextBindingDigest": request.context_binding.binding_digest,
        "inputInventoryDigest": request.evidence_inventory.inventory_digest,
        "requestDigest": request.request_digest,
        "transitionDigest": request.incident_anchor.transition_digest,
        "incidentAnchorObservedStart": request.incident_anchor.observed_start,
        "incidentAnchorObservedEnd": request.incident_anchor.observed_end,
        "hypotheses": (hypothesis,),
        "previewOnly": request.context_binding.binding_mode == "draftPreview",
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return CorrelationReport(
        **payload,
        reportId=f"report-{digest.removeprefix('sha256:')[:32]}",
        reportDigest=digest,
    )


def _report(
    *,
    binding_mode: str = "publishedRuntime",
) -> CorrelationReport:
    request = _request(binding_mode=binding_mode)
    hypothesis = _hypothesis(citation=request.evidence_index[0])
    return _report_for(request, hypothesis)


def _confirmed_nsg_hypothesis(
    *,
    request: CorrelationRequest,
    flow: NetworkFlowObservation,
    monitor: ConnectionMonitorObservation,
    endpoint: EndpointHealthObservation,
    change_id: str,
) -> RootCauseHypothesis:
    citations = {item.evidence_id: item for item in request.evidence_index}
    gate_evidence = {
        "affectedPath": (endpoint.observation_id,),
        "connectionMonitorFailure": (monitor.observation_id,),
        "correctChronology": (change_id,),
        "effectiveRuleAttribution": (flow.observation_id,),
        "endpointDegradation": (endpoint.observation_id,),
        "independentCorroboration": (
            flow.observation_id,
            monitor.observation_id,
            endpoint.observation_id,
        ),
        "matchingDeniedFlow": (flow.observation_id,),
        "noHardConflict": (),
        "semanticMatch": (change_id,),
        "successfulChange": (change_id,),
    }
    gates = tuple(
        CorrelationGate(
            code=code,
            satisfied=True,
            evidenceIds=tuple(sorted(gate_evidence[code])),
        )
        for code in sorted(gate_evidence)
    )
    supporting = tuple(
        sorted(
            (
                citations[change_id],
                citations[flow.observation_id],
                citations[monitor.observation_id],
                citations[endpoint.observation_id],
            ),
            key=lambda item: item.evidence_id,
        )
    )
    return _hypothesis(
        score=CorrelationScoreComponents(
            topology=25,
            temporal=20,
            semantic=20,
            corroboration=25,
            recovery=10,
            rawScore=100,
        ),
        confidence="Confirmed",
        gates=gates,
        caps=(),
        supporting_evidence=supporting,
        missing_evidence=(),
    )


def test_monitoring_bundle_is_strict_digest_bound_and_canonical() -> None:
    payload = _bound_observation().model_dump(mode="python", by_alias=True)
    payload["subjectResourceId"] = WEB_ID.upper()
    observation = GuestSignalObservation(**payload)
    bundle = _bundle(observations=(observation,))

    assert observation.subject_resource_id == WEB_ID.lower()
    assert MonitoringEvidenceBundle.model_validate_json(bundle.model_dump_json()) == bundle

    payload = bundle.model_dump(mode="python", by_alias=True)
    payload["verified"] = True
    with pytest.raises(ValidationError):
        MonitoringEvidenceBundle(**payload)


@pytest.mark.parametrize(
    "change",
    [
        {"observedEnd": NOW - timedelta(minutes=11)},
        {"value": float("nan")},
        {"observationId": "obs-" + "f" * 32},
        {"observationDigest": DIGEST_A},
    ],
)
def test_observation_rejects_invalid_interval_value_or_binding(
    change: dict[str, object],
) -> None:
    payload = _bound_observation().model_dump(mode="python", by_alias=True)
    payload.update(change)

    with pytest.raises(ValidationError):
        GuestSignalObservation(**payload)


def test_bundle_rejects_duplicate_ids_and_unsorted_coverage() -> None:
    first = _bound_observation()
    duplicate = first.model_copy()
    with pytest.raises(ValidationError, match="duplicate observation"):
        _bundle(observations=(first, duplicate))

    guest = _coverage()
    network = _coverage(
        family="platformHealth",
        scope=_coverage_scope(resourceIds=(DB_ID.lower(),)),
    )
    with pytest.raises(ValidationError, match="deterministically ordered"):
        _bundle(coverage=(network, guest))


def test_context_binding_separates_published_runtime_and_draft_preview() -> None:
    assert _context_binding().binding_mode == "publishedRuntime"
    assert _context_binding(binding_mode="draftPreview").draft_revision == 3

    published = _context_binding().model_dump(mode="python", by_alias=True)
    published["draftId"] = "draft-not-allowed"
    with pytest.raises(ValidationError):
        PublishedRuntimeContextBinding(**published)

    draft = _context_binding(binding_mode="draftPreview").model_dump(
        mode="python",
        by_alias=True,
    )
    draft["publicationAuthority"] = _context_binding().publication_authority
    with pytest.raises(ValidationError):
        DraftPreviewContextBinding(**draft)

    runtime = _context_binding()
    authority_payload = runtime.publication_authority.model_dump(
        mode="python",
        by_alias=True,
        exclude={"authority_id", "authority_digest"},
    )
    authority_payload["workloadId"] = "other-synthetic-workload"
    authority_digest = compute_artifact_digest(_json_value(authority_payload))
    other_authority = PublishedContextAuthority(
        **authority_payload,
        authorityId=(
            "publication-authority-"
            + authority_digest.removeprefix("sha256:")[:32]
        ),
        authorityDigest=authority_digest,
    )
    runtime_payload = runtime.model_dump(
        mode="python",
        by_alias=True,
        exclude={"binding_digest"},
    )
    runtime_payload["publicationAuthority"] = other_authority
    runtime_digest = compute_artifact_digest(_json_value(runtime_payload))
    with pytest.raises(ValidationError, match="runtime context"):
        PublishedRuntimeContextBinding(
            **runtime_payload,
            bindingDigest=runtime_digest,
        )


def test_request_binds_exact_handoff_bundle_inventory_and_as_of() -> None:
    request = _request()

    assert CorrelationRequest.model_validate_json(request.model_dump_json()) == request
    assert request.request_digest == compute_artifact_digest(
        request.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"request_id", "request_digest"},
        )
    )

    payload = request.model_dump(mode="python", by_alias=True)
    payload["verified"] = True
    with pytest.raises(ValidationError):
        CorrelationRequest(**payload)

    payload = request.model_dump(mode="python", by_alias=True)
    payload["trustedAsOf"] = NOW - timedelta(minutes=3)
    with pytest.raises(ValidationError, match="trustedAsOf"):
        CorrelationRequest(**payload)


def test_request_rejects_monitoring_blob_substitution() -> None:
    request = _request()
    replacement = _bundle(
        observations=(
            _bound_observation(
                signal="cpuSaturation",
                summaryCode="guest.cpu-saturation",
            ),
        )
    )
    payload = request.model_dump(mode="python", by_alias=True)
    payload["monitoringBundle"] = replacement

    with pytest.raises(ValidationError, match="exact handoff"):
        CorrelationRequest(**payload)


def test_request_requires_bijective_evidence_index() -> None:
    request = _request()
    payload = request.model_dump(mode="python", by_alias=True)
    payload["evidenceIndex"] = (request.evidence_index[0],)

    with pytest.raises(ValidationError, match="derived exactly"):
        CorrelationRequest(**payload)


def test_incident_transition_requires_matching_typed_health_evidence() -> None:
    request = _request()
    coverage_citation = next(
        item
        for item in request.evidence_index
        if item.evidence_id.startswith("coverage-")
    )
    payload = request.model_dump(mode="python", by_alias=True)
    payload["incidentAnchor"] = request.incident_anchor.model_copy(
        update={
            "current_state_evidence": (coverage_citation,),
            "observed_start": coverage_citation.observed_start,
            "observed_end": coverage_citation.observed_end,
        }
    )

    with pytest.raises(
        ValidationError,
        match="previous-state evidence|matching typed health",
    ):
        CorrelationRequest(**payload)


def test_request_uses_wc025_newline_terminated_artifact_digest() -> None:
    artifact, handoff = _change_pair()
    request = _request(change_pair=(artifact, handoff))

    assert request.evidence_inventory.change_artifact_digests == (
        sha256_hex(artifact.canonical_bytes()),
    )

    bad_handoff = handoff.model_copy(
        update={
            "artifact": handoff.artifact.model_copy(
                update={
                    "content_digest": compute_artifact_digest(
                        artifact.model_dump(
                            mode="json",
                            by_alias=True,
                            exclude_none=True,
                        )
                    )
                }
            )
        }
    )
    payload = request.model_dump(mode="python", by_alias=True)
    payload["changeHandoffs"] = (bad_handoff,)
    with pytest.raises(ValidationError, match="exact change artifact"):
        CorrelationRequest(**payload)


def test_inventory_rejects_conflicting_digest_for_one_immutable_blob_version() -> None:
    request = _request()
    payload = request.evidence_inventory.model_dump(mode="python", by_alias=True)
    original = request.monitoring_handoff.evidence
    payload["sourceReferences"] = (
        original,
        original.model_copy(update={"content_digest": DIGEST_B}),
    )

    with pytest.raises(ValidationError, match="unique deterministic"):
        CorrelationEvidenceInventory(**payload)


def test_bundle_allows_complete_zero_result_collection() -> None:
    bundle = _bundle(observations=())
    assert bundle.observations == ()
    assert bundle.coverage[0].status == "complete"


def test_complete_network_coverage_requires_exact_path_and_flow_scope() -> None:
    with pytest.raises(ValidationError, match="network-flow coverage"):
        _coverage(
            family="networkFlow",
            scope=_coverage_scope(),
        )

    network_scope = _coverage_scope(
        pathId=_dependency_path().path_id,
        direction="inbound",
        fiveTupleDigest=DIGEST_A,
    )
    assert (
        _coverage(
            family="networkFlow",
            scope=network_scope,
        ).scope
        == network_scope
    )


def test_network_tuple_and_nsg_property_bindings_are_exact() -> None:
    change_pair = _change_pair()
    path = _dependency_path()
    flow = _network_flow_observation(
        path=path,
        matched_change_key=change_pair[0].evidence.change_key,
    )

    changed_address = flow.model_dump(mode="python", by_alias=True)
    changed_address["sourceAddress"] = "192.0.2.99"
    changed_address.pop("observationId")
    changed_address.pop("observationDigest")
    changed_digest = compute_artifact_digest(_json_value(changed_address))
    with pytest.raises(ValidationError, match="exact flow tuple"):
        NetworkFlowObservation(
            **changed_address,
            observationId=(
                f"obs-{changed_digest.removeprefix('sha256:')[:32]}"
            ),
            observationDigest=changed_digest,
        )

    unrelated_property = flow.model_dump(mode="python", by_alias=True)
    unrelated_property["matchedPropertyPaths"] = ("properties.accessibility",)
    unrelated_property.pop("observationId")
    unrelated_property.pop("observationDigest")
    unrelated_digest = compute_artifact_digest(_json_value(unrelated_property))
    with pytest.raises(ValidationError, match="causal NSG"):
        NetworkFlowObservation(
            **unrelated_property,
            observationId=(
                f"obs-{unrelated_digest.removeprefix('sha256:')[:32]}"
            ),
            observationDigest=unrelated_digest,
        )


@pytest.mark.parametrize(
    ("raw_score", "parts"),
    [
        (29, (10, 5, 8, 6, 0)),
        (30, (10, 5, 8, 7, 0)),
        (54, (18, 10, 14, 12, 0)),
        (55, (18, 10, 14, 13, 0)),
        (74, (25, 15, 14, 20, 0)),
        (75, (25, 15, 20, 15, 0)),
        (89, (25, 20, 20, 24, 0)),
        (90, (25, 20, 20, 25, 0)),
    ],
)
def test_score_components_accept_exact_threshold_boundaries(
    raw_score: int,
    parts: tuple[int, int, int, int, int],
) -> None:
    score = CorrelationScoreComponents(
        topology=parts[0],
        temporal=parts[1],
        semantic=parts[2],
        corroboration=parts[3],
        recovery=parts[4],
        rawScore=raw_score,
    )
    assert score.raw_score == raw_score

    with pytest.raises(ValidationError, match="component score sum"):
        CorrelationScoreComponents(
            topology=parts[0],
            temporal=parts[1],
            semantic=parts[2],
            corroboration=parts[3],
            recovery=parts[4],
            rawScore=min(100, raw_score + 1),
        )


def test_confidence_cannot_exceed_raw_score_band() -> None:
    with pytest.raises(ValidationError, match="confidence threshold"):
        _hypothesis(
            confidence="High",
            caps=(),
            score=CorrelationScoreComponents(
                topology=0,
                temporal=0,
                semantic=0,
                corroboration=0,
                recovery=0,
                rawScore=0,
            ),
        )


def test_hypothesis_and_report_bind_conflicts_gates_and_no_remediation() -> None:
    report = _report()

    assert report.no_auto_remediation is True
    assert CorrelationReport.model_validate_json(report.model_dump_json()) == report

    hard_conflict = CorrelationContradiction(
        code="completeAllowedFlow",
        detail="Complete synthetic flow evidence remained allowed.",
        evidenceIds=("endpoint-health.synthetic",),
        hardConflict=True,
    )
    with pytest.raises(ValidationError, match="Unknown"):
        _hypothesis(confidence="High", contradictions=(hard_conflict,), caps=())

    unsatisfied_gate = CorrelationGate(
        code="effectiveRuleAttribution",
        satisfied=False,
        evidenceIds=(),
    )
    confirmed_score = CorrelationScoreComponents(
        topology=25,
        temporal=20,
        semantic=20,
        corroboration=25,
        recovery=10,
        rawScore=100,
    )
    with pytest.raises(ValidationError, match="Confirmed"):
        _hypothesis(
            confidence="Confirmed",
            gates=(unsatisfied_gate,),
            caps=(),
            score=confirmed_score,
        )
    with pytest.raises(ValidationError, match="Confirmed"):
        _hypothesis(
            confidence="Confirmed",
            gates=(),
            caps=(),
            score=confirmed_score,
        )
    with pytest.raises(ValidationError, match="declared cap"):
        _hypothesis(
            confidence="High",
            caps=(
                ConfidenceCap(
                    code="recentChangeOnly",
                    maximumConfidence="Low",
                ),
            ),
        )

    payload = report.model_dump(mode="python", by_alias=True)
    payload["noAutoRemediation"] = False
    with pytest.raises(ValidationError):
        CorrelationReport(**payload)

    with pytest.raises(ValidationError, match="derived from contradiction code"):
        CorrelationContradiction(
            code="changeFailed",
            detail="Synthetic failed change.",
            evidenceIds=("change.synthetic",),
            hardConflict=False,
        )


def test_complete_counter_evidence_cannot_be_omitted() -> None:
    change_pair = _change_pair()
    bundle, denied_flow, monitor, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
    )
    allowed_flow = _network_flow_observation(
        path=_dependency_path(),
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
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
        change_pair=change_pair,
    )
    hypothesis = _confirmed_nsg_hypothesis(
        request=request,
        flow=denied_flow,
        monitor=monitor,
        endpoint=endpoint,
        change_id=change_pair[0].evidence.evidence_id,
    )
    report = _report_for(request, hypothesis)

    with pytest.raises(ValueError, match="omits mandatory hard-conflict"):
        validate_correlation_report_binding(report, request)

    omitted_denied_gate = tuple(
        gate for gate in hypothesis.gates if gate.code != "matchingDeniedFlow"
    )
    omitted_hypothesis = _hypothesis(
        confidence="High",
        gates=omitted_denied_gate,
        caps=hypothesis.caps,
        supporting_evidence=hypothesis.supporting_evidence,
        missing_evidence=(),
    )
    with pytest.raises(ValueError, match="requires matchingDeniedFlow"):
        validate_correlation_report_binding(
            _report_for(request, omitted_hypothesis),
            request,
        )


def test_healthy_monitor_counterevidence_is_derived_from_failure_gate() -> None:
    change_pair = _change_pair()
    bundle, _, failed_monitor, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
    )
    healthy_monitor = _connection_monitor_observation(
        path=_dependency_path(),
        five_tuple_digest=failed_monitor.five_tuple_digest,
        status="succeeded",
        source_seed="8",
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
        change_pair=change_pair,
    )
    citations = {item.evidence_id: item for item in request.evidence_index}
    gates = (
        CorrelationGate(
            code="affectedPath",
            satisfied=True,
            evidenceIds=(endpoint.observation_id,),
        ),
        CorrelationGate(
            code="connectionMonitorFailure",
            satisfied=True,
            evidenceIds=(failed_monitor.observation_id,),
        ),
        CorrelationGate(
            code="independentCorroboration",
            satisfied=True,
            evidenceIds=tuple(
                sorted(
                    (
                        failed_monitor.observation_id,
                        endpoint.observation_id,
                    )
                )
            ),
        ),
        CorrelationGate(
            code="noHardConflict",
            satisfied=True,
            evidenceIds=(),
        ),
    )
    hypothesis = _hypothesis(
        confidence="Medium",
        gates=tuple(sorted(gates, key=lambda item: item.code)),
        caps=(
            ConfidenceCap(
                code="missingDirectAttribution",
                maximumConfidence="High",
            ),
        ),
        supporting_evidence=tuple(
            sorted(
                (
                    citations[failed_monitor.observation_id],
                    citations[endpoint.observation_id],
                ),
                key=lambda item: item.evidence_id,
            )
        ),
    )

    with pytest.raises(ValueError, match="omits mandatory hard-conflict"):
        validate_correlation_report_binding(_report_for(request, hypothesis), request)


def test_boundary_touching_monitor_failure_is_not_incident_evidence() -> None:
    change_pair = _change_pair()
    bundle, flow, _, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
    )
    stale_failure = _connection_monitor_observation(
        path=_dependency_path(),
        five_tuple_digest=flow.five_tuple_digest,
        observed_start=NOW - timedelta(minutes=5),
        observed_end=NOW - timedelta(minutes=4),
        status="failed",
        source_seed="9",
    )
    previous_endpoint = next(
        item
        for item in bundle.observations
        if isinstance(item, EndpointHealthObservation) and item.status == "healthy"
    )
    stale_bundle = _bundle(
        observations=tuple(
            sorted(
                (flow, stale_failure, previous_endpoint, endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=stale_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=change_pair,
    )
    citations = {item.evidence_id: item for item in request.evidence_index}
    hypothesis = _hypothesis(
        confidence="Medium",
        gates=tuple(
            sorted(
                (
                    CorrelationGate(
                        code="affectedPath",
                        satisfied=True,
                        evidenceIds=(endpoint.observation_id,),
                    ),
                    CorrelationGate(
                        code="connectionMonitorFailure",
                        satisfied=True,
                        evidenceIds=(stale_failure.observation_id,),
                    ),
                    CorrelationGate(
                        code="independentCorroboration",
                        satisfied=True,
                        evidenceIds=tuple(
                            sorted(
                                (
                                    stale_failure.observation_id,
                                    endpoint.observation_id,
                                )
                            )
                        ),
                    ),
                ),
                key=lambda item: item.code,
            )
        ),
        caps=(
            ConfidenceCap(
                code="missingDirectAttribution",
                maximumConfidence="High",
            ),
        ),
        supporting_evidence=tuple(
            sorted(
                (
                    citations[stale_failure.observation_id],
                    citations[endpoint.observation_id],
                ),
                key=lambda item: item.evidence_id,
            )
        ),
    )

    with pytest.raises(ValueError, match="failed test evidence"):
        validate_correlation_report_binding(_report_for(request, hypothesis), request)


def test_boundary_touching_attribution_cannot_support_high_confidence() -> None:
    change_pair = _change_pair()
    bundle, _, monitor, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
    )
    stale_attribution = _network_flow_observation(
        path=_dependency_path(),
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
        observed_start=NOW - timedelta(minutes=5),
        observed_end=NOW - timedelta(minutes=4),
        source_seed="9",
    )
    current_denial = _network_flow_observation(
        path=_dependency_path(),
        decision="denied",
        source_seed="8",
        effective_rule_attribution=False,
    )
    previous_endpoint = next(
        item
        for item in bundle.observations
        if isinstance(item, EndpointHealthObservation) and item.status == "healthy"
    )
    stale_bundle = _bundle(
        observations=tuple(
            sorted(
                (
                    stale_attribution,
                    current_denial,
                    monitor,
                    previous_endpoint,
                    endpoint,
                ),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    request = _request(
        bundle_override=stale_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=change_pair,
    )
    citations = {item.evidence_id: item for item in request.evidence_index}
    change_id = change_pair[0].evidence.evidence_id
    gate_evidence = {
        "affectedPath": (endpoint.observation_id,),
        "correctChronology": (change_id,),
        "effectiveRuleAttribution": (stale_attribution.observation_id,),
        "independentCorroboration": (
            current_denial.observation_id,
            monitor.observation_id,
            endpoint.observation_id,
        ),
        "matchingDeniedFlow": (
            current_denial.observation_id,
            stale_attribution.observation_id,
        ),
        "semanticMatch": (change_id,),
        "successfulChange": (change_id,),
    }
    hypothesis = _hypothesis(
        confidence="High",
        gates=tuple(
            CorrelationGate(
                code=code,
                satisfied=True,
                evidenceIds=tuple(sorted(gate_evidence[code])),
            )
            for code in sorted(gate_evidence)
        ),
        caps=(),
        supporting_evidence=tuple(
            sorted(
                (
                    citations[change_id],
                    citations[stale_attribution.observation_id],
                    citations[current_denial.observation_id],
                    citations[monitor.observation_id],
                    citations[endpoint.observation_id],
                ),
                key=lambda item: item.evidence_id,
            )
        ),
        missing_evidence=(),
    )

    with pytest.raises(ValueError, match="attributed flow evidence"):
        validate_correlation_report_binding(_report_for(request, hypothesis), request)


def test_high_nsg_without_attribution_still_requires_counterevidence() -> None:
    change_pair = _change_pair()
    bundle, denied_flow, monitor, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
        effective_rule_attribution=False,
    )
    allowed_flow = _network_flow_observation(
        path=_dependency_path(),
        decision="allowed",
        source_seed="6",
        effective_rule_attribution=False,
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
        change_pair=change_pair,
    )
    citations = {item.evidence_id: item for item in request.evidence_index}
    gate_evidence = {
        "affectedPath": (endpoint.observation_id,),
        "independentCorroboration": (
            denied_flow.observation_id,
            monitor.observation_id,
            endpoint.observation_id,
        ),
        "matchingDeniedFlow": (denied_flow.observation_id,),
        "noHardConflict": (),
        "correctChronology": (change_pair[0].evidence.evidence_id,),
        "semanticMatch": (change_pair[0].evidence.evidence_id,),
        "successfulChange": (change_pair[0].evidence.evidence_id,),
    }
    gates = tuple(
        CorrelationGate(
            code=code,
            satisfied=True,
            evidenceIds=tuple(sorted(gate_evidence[code])),
        )
        for code in sorted(gate_evidence)
    )
    supporting = tuple(
        sorted(
            (
                citations[denied_flow.observation_id],
                citations[monitor.observation_id],
                citations[endpoint.observation_id],
                citations[change_pair[0].evidence.evidence_id],
            ),
            key=lambda item: item.evidence_id,
        )
    )
    hypothesis = _hypothesis(
        confidence="High",
        gates=gates,
        caps=(
            ConfidenceCap(
                code="missingDirectAttribution",
                maximumConfidence="High",
            ),
        ),
        supporting_evidence=supporting,
        missing_evidence=(),
    )
    report = _report_for(request, hypothesis)

    with pytest.raises(ValueError, match="omits mandatory hard-conflict"):
        validate_correlation_report_binding(report, request)


def test_prechange_observation_requires_ambiguity_cap_for_every_category() -> None:
    change_pair = _change_pair()
    path = _dependency_path()
    early_endpoint = _endpoint_health_observation(
        path=path,
        observed_start=NOW - timedelta(minutes=7),
    )
    base_bundle = _bundle()
    bundle = _bundle(
        observations=tuple(
            sorted(
                (*base_bundle.observations, early_endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=base_bundle.coverage,
    )
    base_unhealthy_guest = next(
        item
        for item in base_bundle.observations
        if isinstance(item, GuestSignalObservation) and item.state == "unhealthy"
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=base_unhealthy_guest.observation_id,
        change_pair=change_pair,
    )
    citations = {item.evidence_id: item for item in request.evidence_index}
    change_id = change_pair[0].evidence.evidence_id
    unhealthy_guest = next(
        item
        for item in request.monitoring_bundle.observations
        if isinstance(item, GuestSignalObservation) and item.state == "unhealthy"
    )
    gates = (
        CorrelationGate(
            code="affectedPath",
            satisfied=True,
            evidenceIds=(early_endpoint.observation_id,),
        ),
        CorrelationGate(
            code="correctChronology",
            satisfied=True,
            evidenceIds=(change_id,),
        ),
        CorrelationGate(
            code="independentCorroboration",
            satisfied=True,
            evidenceIds=tuple(
                sorted(
                    (
                        early_endpoint.observation_id,
                        unhealthy_guest.observation_id,
                    )
                )
            ),
        ),
    )
    hypothesis = _hypothesis(
        category="routingChange",
        confidence="Medium",
        gates=gates,
        caps=(),
        supporting_evidence=tuple(
            sorted(
                (
                    citations[change_id],
                    citations[early_endpoint.observation_id],
                    citations[unhealthy_guest.observation_id],
                ),
                key=lambda item: item.evidence_id,
            )
        ),
    )

    with pytest.raises(ValueError, match="ambiguousObservationWindow"):
        validate_correlation_report_binding(_report_for(request, hypothesis), request)

    extra_chronology_gates = tuple(
        gate.model_copy(
            update={
                "evidence_ids": tuple(
                    sorted(
                        (
                            change_id,
                            unhealthy_guest.observation_id,
                        )
                    )
                )
            }
        )
        if gate.code == "correctChronology"
        else gate
        for gate in gates
    )
    extra_chronology_hypothesis = _hypothesis(
        category="routingChange",
        confidence="Medium",
        gates=extra_chronology_gates,
        caps=(
            ConfidenceCap(
                code="ambiguousObservationWindow",
                maximumConfidence="Medium",
            ),
        ),
        supporting_evidence=hypothesis.supporting_evidence,
    )
    with pytest.raises(ValueError, match="correctChronology"):
        validate_correlation_report_binding(
            _report_for(request, extra_chronology_hypothesis),
            request,
        )


def test_confirmed_nsg_gates_require_typed_causal_evidence() -> None:
    request = _request()
    guest = next(
        item for item in request.evidence_index if item.evidence_id.startswith("obs-")
    )
    gate_codes = (
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
    )
    gates = tuple(
        CorrelationGate(
            code=code,
            satisfied=True,
            evidenceIds=() if code == "noHardConflict" else (guest.evidence_id,),
        )
        for code in gate_codes
    )
    hypothesis = _hypothesis(
        score=CorrelationScoreComponents(
            topology=25,
            temporal=20,
            semantic=20,
            corroboration=25,
            recovery=10,
            rawScore=100,
        ),
        confidence="Confirmed",
        gates=gates,
        caps=(),
        citation=guest,
        missing_evidence=(),
    )
    report = _report_for(request, hypothesis)

    with pytest.raises(ValueError, match="affectedPath|requires"):
        validate_correlation_report_binding(report, request)


def test_confirmed_nsg_contract_binds_one_exact_causal_flow() -> None:
    change_pair = _change_pair()
    bundle, flow, monitor, endpoint = _nsg_bundle(
        matched_change_key=change_pair[0].evidence.change_key,
        matched_change_evidence_id=change_pair[0].evidence.evidence_id,
        matched_change_artifact_digest=sha256_hex(
            change_pair[0].canonical_bytes()
        ),
    )
    request = _request(
        bundle_override=bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=change_pair,
    )
    change_id = change_pair[0].evidence.evidence_id
    hypothesis = _confirmed_nsg_hypothesis(
        request=request,
        flow=flow,
        monitor=monitor,
        endpoint=endpoint,
        change_id=change_id,
    )
    report = _report_for(request, hypothesis)

    validate_correlation_report_binding(report, request)

    mismatched_monitor = _connection_monitor_observation(
        path=_dependency_path(),
        direction="outbound",
    )
    previous_endpoint = next(
        item
        for item in bundle.observations
        if isinstance(item, EndpointHealthObservation) and item.status == "healthy"
    )
    bad_bundle = _bundle(
        observations=tuple(
            sorted(
                (flow, mismatched_monitor, previous_endpoint, endpoint),
                key=lambda item: item.observation_id,
            )
        ),
        coverage=bundle.coverage,
    )
    bad_request = _request(
        bundle_override=bad_bundle,
        incident_evidence_id=endpoint.observation_id,
        change_pair=change_pair,
    )
    bad_hypothesis = _confirmed_nsg_hypothesis(
        request=bad_request,
        flow=flow,
        monitor=mismatched_monitor,
        endpoint=endpoint,
        change_id=change_id,
    )
    bad_report = _report_for(bad_request, bad_hypothesis)
    with pytest.raises(ValueError, match="match the affected path"):
        validate_correlation_report_binding(bad_report, bad_request)


def test_report_is_bound_to_exact_request_and_transition() -> None:
    request = _request()
    report = _report()
    validate_correlation_report_binding(report, request)

    payload = report.model_dump(mode="python", by_alias=True)
    payload["requestDigest"] = DIGEST_A
    payload_without_identity = {
        key: value
        for key, value in payload.items()
        if key not in {"reportId", "reportDigest"}
    }
    digest = compute_artifact_digest(_json_value(payload_without_identity))
    changed = CorrelationReport(
        **payload_without_identity,
        reportId=f"report-{digest.removeprefix('sha256:')[:32]}",
        reportDigest=digest,
    )

    with pytest.raises(ValueError, match="exact request"):
        validate_correlation_report_binding(changed, request)

    outside = report.hypotheses[0].supporting_evidence[0].model_copy(
        update={"evidence_id": "guest.synthetic-outside-index"}
    )
    hypothesis_payload = report.hypotheses[0].model_dump(
        mode="python",
        by_alias=True,
        exclude={"hypothesis_id", "hypothesis_digest"},
    )
    hypothesis_payload["supportingEvidence"] = (outside,)
    hypothesis_digest = compute_artifact_digest(
        _json_value(
            {
                key: value
                for key, value in hypothesis_payload.items()
                if key != "rank"
            }
        )
    )
    outside_hypothesis = RootCauseHypothesis(
        **hypothesis_payload,
        hypothesisId=f"hyp-{hypothesis_digest.removeprefix('sha256:')[:32]}",
        hypothesisDigest=hypothesis_digest,
    )
    report_payload = report.model_dump(
        mode="python",
        by_alias=True,
        exclude={"report_id", "report_digest"},
    )
    report_payload["hypotheses"] = (outside_hypothesis,)
    report_digest = compute_artifact_digest(_json_value(report_payload))
    outside_report = CorrelationReport(
        **report_payload,
        reportId=f"report-{report_digest.removeprefix('sha256:')[:32]}",
        reportDigest=report_digest,
    )
    with pytest.raises(ValueError, match="outside the verified request"):
        validate_correlation_report_binding(outside_report, request)


def test_runtime_report_validator_rejects_draft_preview() -> None:
    runtime_request = _request()
    runtime_report = _report()
    validate_runtime_correlation_report(
        runtime_report,
        runtime_request,
        evaluated_at=runtime_request.trusted_as_of,
    )

    preview_request = _request(binding_mode="draftPreview")
    preview_report = _report(binding_mode="draftPreview")
    validate_correlation_report_binding(preview_report, preview_request)
    with pytest.raises(ValueError, match="published context"):
        validate_runtime_correlation_report(
            preview_report,
            preview_request,
            evaluated_at=preview_request.trusted_as_of,
        )

    with pytest.raises(ValueError, match="validity window"):
        validate_runtime_correlation_report(
            runtime_report,
            runtime_request,
            evaluated_at=runtime_request.expires_at + timedelta(milliseconds=1),
        )


def test_report_rejects_non_contiguous_ranks_and_digest_changes() -> None:
    first = _hypothesis(rank=1)
    second_payload = first.model_dump(mode="python", by_alias=True)
    second_payload["rank"] = 3
    second = RootCauseHypothesis(**second_payload)
    request = _request()
    payload: dict[str, object] = {
        "schemaVersion": CORRELATION_REPORT_SCHEMA_VERSION,
        "algorithmId": CORRELATION_ALGORITHM_ID,
        "ruleCatalogDigest": request.rule_catalog_digest,
        "asOf": request.trusted_as_of,
        "bindingMode": request.context_binding.binding_mode,
        "contextBindingDigest": request.context_binding.binding_digest,
        "inputInventoryDigest": request.evidence_inventory.inventory_digest,
        "requestDigest": request.request_digest,
        "transitionDigest": request.incident_anchor.transition_digest,
        "incidentAnchorObservedStart": request.incident_anchor.observed_start,
        "incidentAnchorObservedEnd": request.incident_anchor.observed_end,
        "hypotheses": (first, second),
        "previewOnly": False,
        "noAutoRemediation": True,
        "reportId": "report-" + "f" * 32,
        "reportDigest": DIGEST_A,
    }

    with pytest.raises(ValidationError, match="contiguous"):
        CorrelationReport(**payload)

    valid = _report().model_dump(mode="python", by_alias=True)
    valid["ruleCatalogDigest"] = DIGEST_A
    with pytest.raises(ValidationError, match="reportDigest"):
        CorrelationReport(**valid)
