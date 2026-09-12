from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from athena_context.contracts import (
    ActivityLogMonitoringSignal,
    ApprovedChangeScope,
    ChangeEvidencePersistenceHandoff,
    LogQueryMonitoringSignal,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceHandoff,
    MonitoringIntentScope,
    PublishedMonitoringIntentControl,
    ResourceHealthMonitoringSignal,
    VersionPinnedBlobReference,
    build_published_monitoring_intent,
    compute_artifact_digest,
    monitoring_handoff_preimage,
    sha256_hex,
)
from athena_context.monitoring_collection import (
    AmaHeartbeatRecord,
    CommittedMonitoringCollection,
    ConnectionMonitorRecord,
    MonitoringCollectionBatch,
    MonitoringCollectionError,
    MonitoringCollectionTransaction,
    MonitoringCoverageRecord,
    NetworkWatcherFlowRecord,
    ResourceChangeRecord,
    ResourceHealthRecord,
    VmConnectionHealthRecord,
)
from test_wc026_correlation import _test_service
from test_wc026_correlation_contract import (
    DB_ID,
    DIGEST_C,
    NOW,
    NSG_ID,
    NSG_RULE_ID,
    RESOURCE_GROUP,
    SUBSCRIPTION_ID,
    WEB_ID,
    _context_binding,
    _dependency_path,
)

MONITOR_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-synthetic-monitoring/"
    "providers/Microsoft.Network/networkWatchers/synthetic-watcher/"
    "connectionMonitors/synthetic-web-db"
)
CHANGE_CORRELATION_ID = "11111111-1111-1111-1111-111111111111"
CHANGE_KEY_ID = (
    "https://synthetic-wc028.vault.azure.net/keys/change-signing/0123456789abcdef0123456789abcdef"
)
MONITORING_KEY_ID = (
    "https://synthetic-wc028.vault.azure.net/keys/"
    "monitoring-signing/0123456789abcdef0123456789abcdef"
)


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _scope(resources: tuple[str, ...]) -> MonitoringIntentScope:
    path = _dependency_path()
    payload: dict[str, object] = {
        "resourceIds": tuple(sorted(item.casefold() for item in resources)),
        "pathIds": (path.path_id,),
        "roleRefs": tuple(sorted((path.source_role_ref, path.target_role_ref))),
    }
    return MonitoringIntentScope(
        **payload,
        scopeDigest=compute_artifact_digest(_json_value(payload)),
    )


def _query_signal(query: str, *, operator: str, threshold: float) -> LogQueryMonitoringSignal:
    return LogQueryMonitoringSignal(
        signalKind="logQuery",
        query=query,
        queryDigest=sha256_hex(query.encode("utf-8")),
        queryTargetResourceId=WEB_ID,
        unit="count",
        aggregation="count",
        operator=operator,
        threshold=threshold,
        evaluationWindowSeconds=300,
        frequencySeconds=60,
    )


def _control(
    *,
    source_clause: str,
    resources: tuple[str, ...],
    signal: object,
) -> PublishedMonitoringIntentControl:
    payload: dict[str, object] = {
        "sourceClausePath": source_clause,
        "ownerRef": "synthetic-platform-owner",
        "severity": 1,
        "missingDataBehavior": "reviewRequired",
        "actionBehavior": "none",
        "dryRunOnly": False,
        "scope": _scope(resources),
        "signal": signal,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedMonitoringIntentControl(
        **payload,
        controlId=f"monitoring-control-{digest.removeprefix('sha256:')[:32]}",
        controlDigest=digest,
    )


def _controls() -> dict[str, PublishedMonitoringIntentControl]:
    path_resources = (
        WEB_ID,
        DB_ID,
        NSG_ID,
        NSG_RULE_ID,
    )
    return {
        "heartbeat": _control(
            source_clause="/controls/heartbeat",
            resources=(WEB_ID,),
            signal=_query_signal(
                "Heartbeat | summarize heartbeatCount=count()",
                operator="lessThan",
                threshold=1,
            ),
        ),
        "endpoint": _control(
            source_clause="/controls/vm-connection-health",
            resources=(WEB_ID, DB_ID),
            signal=_query_signal(
                "VMConnection | summarize failedConnectionCount=count()",
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "monitor": _control(
            source_clause="/controls/connection-monitor",
            resources=(WEB_ID, DB_ID),
            signal=_query_signal(
                "NWConnectionMonitorTestResult | summarize count()",
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "flow": _control(
            source_clause="/controls/network-flow",
            resources=path_resources,
            signal=_query_signal(
                "NTANetAnalytics | summarize count()",
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "change": _control(
            source_clause="/controls/activity-change",
            resources=(NSG_RULE_ID,),
            signal=ActivityLogMonitoringSignal(
                signalKind="activityLog",
                categories=("Administrative",),
                operationNames=("Microsoft.Network/networkSecurityGroups/securityRules/write",),
                resultTypes=("Succeeded",),
                levels=("Informational",),
            ),
        ),
        "health": _control(
            source_clause="/controls/resource-health",
            resources=(WEB_ID,),
            signal=ResourceHealthMonitoringSignal(
                signalKind="resourceHealth",
                eventStatuses=("Active", "Resolved"),
                currentStatuses=("Available", "Unavailable"),
                previousStatuses=("Available", "Unavailable"),
                reasonTypes=("PlatformInitiated",),
            ),
        ),
    }


def _five_tuple_digest() -> str:
    return compute_artifact_digest(
        {
            "direction": "inbound",
            "protocol": "Tcp",
            "sourceResourceId": WEB_ID.casefold(),
            "destinationResourceId": DB_ID.casefold(),
            "sourceAddress": "192.0.2.10",
            "destinationAddress": "192.0.2.20",
            "sourcePort": 443,
            "destinationPort": 1433,
        }
    )


def _coverage_scope_digest(
    *,
    control: PublishedMonitoringIntentControl,
    resource_ids: tuple[str, ...],
    path_id: str,
    direction: str | None = None,
    five_tuple_digest: str | None = None,
    endpoint_test_reference: str | None = None,
    endpoint_test_digest: str | None = None,
) -> str:
    return compute_artifact_digest(
        _json_value(
            {
                "resourceIds": tuple(sorted(item.casefold() for item in resource_ids)),
                "pathId": path_id,
                "direction": direction,
                "fiveTupleDigest": five_tuple_digest,
                "endpointTestReference": endpoint_test_reference,
                "endpointTestDigest": endpoint_test_digest,
                "queryScopeDigest": control.control_digest,
            }
        )
    )


def _authority() -> tuple[object, object, dict[str, PublishedMonitoringIntentControl]]:
    controls = _controls()
    path = _dependency_path()
    tuple_digest = _five_tuple_digest()
    test_reference = "synthetic-web-db-test"
    test_digest = "sha256:" + "9" * 64
    required = tuple(
        sorted(
            (
                _coverage_scope_digest(
                    control=controls["flow"],
                    resource_ids=(WEB_ID, DB_ID, NSG_ID, NSG_RULE_ID),
                    path_id=path.path_id,
                    direction="inbound",
                    five_tuple_digest=tuple_digest,
                ),
                _coverage_scope_digest(
                    control=controls["monitor"],
                    resource_ids=(WEB_ID, DB_ID),
                    path_id=path.path_id,
                    direction="inbound",
                    five_tuple_digest=tuple_digest,
                    endpoint_test_reference=test_reference,
                    endpoint_test_digest=test_digest,
                ),
                _coverage_scope_digest(
                    control=controls["endpoint"],
                    resource_ids=(WEB_ID, DB_ID),
                    path_id=path.path_id,
                ),
            )
        )
    )
    context = _context_binding(
        required_coverage_scope_digests=required,
        dependency_paths=(path,),
    )
    intent = build_published_monitoring_intent(
        context,
        environment="production",
        controls=tuple(sorted(controls.values(), key=lambda item: item.control_id)),
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
    )
    return context, intent, controls


def _change_record(control: PublishedMonitoringIntentControl) -> ResourceChangeRecord:
    return ResourceChangeRecord(
        recordKind="resourceChange",
        controlId=control.control_id,
        sourceRecordId="activity-change-001",
        category="Administrative",
        operationName=("Microsoft.Network/networkSecurityGroups/securityRules/write"),
        resultType="Succeeded",
        level="Informational",
        targetResourceId=NSG_RULE_ID,
        correlationId=CHANGE_CORRELATION_ID,
        occurredAt=NOW - timedelta(minutes=6),
        resourceGraphChange={
            "id": (
                f"{NSG_RULE_ID}/providers/Microsoft.Resources/changes/synthetic-wc028-change-001"
            ),
            "properties": {
                "targetResourceId": NSG_RULE_ID,
                "targetResourceType": ("microsoft.network/networksecuritygroups/securityrules"),
                "changeType": "Update",
                "changeAttributes": {
                    "previousResourceSnapshotId": "synthetic-before",
                    "newResourceSnapshotId": "synthetic-after",
                    "changesCount": 1,
                    "changedByType": "Application",
                    "changedBy": "synthetic-wc028-deployer",
                    "clientType": "Automation",
                    "operation": ("Microsoft.Network/networkSecurityGroups/securityRules/write"),
                    "timestamp": (NOW - timedelta(minutes=6)).isoformat().replace("+00:00", "Z"),
                    "correlationId": CHANGE_CORRELATION_ID,
                },
                "changes": {
                    "properties.access": {
                        "previousValue": "Allow",
                        "newValue": "Deny",
                    }
                },
            },
        },
    )


def _batch(
    controls: dict[str, PublishedMonitoringIntentControl],
    *,
    direct_attribution: bool = True,
) -> MonitoringCollectionBatch:
    path = _dependency_path()
    tuple_digest = _five_tuple_digest()
    test_reference = "synthetic-web-db-test"
    test_digest = "sha256:" + "9" * 64
    records = (
        _change_record(controls["change"]),
        AmaHeartbeatRecord(
            recordKind="amaHeartbeat",
            controlId=controls["heartbeat"].control_id,
            sourceRecordId="heartbeat-healthy",
            resourceId=WEB_ID,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW - timedelta(minutes=5),
            queryDigest=controls["heartbeat"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            heartbeatCount=1,
        ),
        AmaHeartbeatRecord(
            recordKind="amaHeartbeat",
            controlId=controls["heartbeat"].control_id,
            sourceRecordId="heartbeat-unhealthy",
            resourceId=WEB_ID,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            queryDigest=controls["heartbeat"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            heartbeatCount=0,
        ),
        VmConnectionHealthRecord(
            recordKind="vmConnectionHealth",
            controlId=controls["endpoint"].control_id,
            sourceRecordId="endpoint-healthy",
            subjectResourceId=WEB_ID,
            backendResourceIds=(DB_ID,),
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW - timedelta(minutes=5),
            queryDigest=controls["endpoint"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            failedConnectionCount=0,
        ),
        VmConnectionHealthRecord(
            recordKind="vmConnectionHealth",
            controlId=controls["endpoint"].control_id,
            sourceRecordId="endpoint-unhealthy",
            subjectResourceId=WEB_ID,
            backendResourceIds=(DB_ID,),
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            queryDigest=controls["endpoint"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            failedConnectionCount=3,
        ),
        NetworkWatcherFlowRecord(
            recordKind="networkWatcherFlow",
            controlId=controls["flow"].control_id,
            sourceRecordId="flow-denied",
            subjectResourceId=WEB_ID,
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            queryDigest=controls["flow"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            decision="denied",
            direction="inbound",
            protocol="Tcp",
            sourceResourceId=WEB_ID,
            destinationResourceId=DB_ID,
            sourceAddress="192.0.2.10",
            destinationAddress="192.0.2.20",
            sourcePort=443,
            destinationPort=1433,
            enforcementResourceId=NSG_ID,
            ruleResourceId=NSG_RULE_ID,
            changeCorrelationId=(CHANGE_CORRELATION_ID if direct_attribution else None),
            attributionMethod=("ipFlowVerify" if direct_attribution else None),
            attributionEvidence=(
                {
                    "schemaVersion": ("athena.wc028NetworkRuleAttributionEvidence.v1"),
                    "method": "ipFlowVerify",
                    "access": "Deny",
                    "previousAccess": "Allow",
                    "currentAccess": "Deny",
                    "ruleResourceId": NSG_RULE_ID,
                    "direction": "inbound",
                    "protocol": "Tcp",
                    "sourceAddress": "192.0.2.10",
                    "destinationAddress": "192.0.2.20",
                    "sourcePort": 443,
                    "destinationPort": 1433,
                    "changeCorrelationId": CHANGE_CORRELATION_ID,
                }
                if direct_attribution
                else None
            ),
        ),
        ConnectionMonitorRecord(
            recordKind="connectionMonitor",
            controlId=controls["monitor"].control_id,
            sourceRecordId="connection-monitor-failed",
            subjectResourceId=WEB_ID,
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            queryDigest=controls["monitor"].signal.query_digest,
            queryTargetResourceId=WEB_ID,
            evaluationWindowSeconds=300,
            frequencySeconds=60,
            monitorResourceId=MONITOR_ID,
            sourceResourceId=WEB_ID,
            destinationResourceId=DB_ID,
            sourceAddress="192.0.2.10",
            destinationAddress="192.0.2.20",
            direction="inbound",
            protocol="Tcp",
            sourcePort=443,
            destinationPort=1433,
            status="failed",
            testConfigurationReference=test_reference,
            testConfigurationDigest=test_digest,
        ),
        ResourceHealthRecord(
            recordKind="resourceHealth",
            controlId=controls["health"].control_id,
            sourceRecordId="resource-health-resolved",
            resourceId=WEB_ID,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW - timedelta(minutes=5),
            eventStatus="Resolved",
            currentStatus="Available",
            previousStatus="Unavailable",
            reasonType="PlatformInitiated",
        ),
        ResourceHealthRecord(
            recordKind="resourceHealth",
            controlId=controls["health"].control_id,
            sourceRecordId="resource-health-active",
            resourceId=WEB_ID,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            eventStatus="Active",
            currentStatus="Unavailable",
            previousStatus="Available",
            reasonType="PlatformInitiated",
        ),
    )
    coverage = (
        MonitoringCoverageRecord(
            controlId=controls["flow"].control_id,
            sourceRecordId="coverage-flow",
            family="networkFlow",
            resourceIds=tuple(
                sorted(
                    (
                        WEB_ID.casefold(),
                        DB_ID.casefold(),
                        NSG_ID.casefold(),
                        NSG_RULE_ID.casefold(),
                    )
                )
            ),
            pathId=path.path_id,
            direction="inbound",
            fiveTupleDigest=tuple_digest,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW,
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["monitor"].control_id,
            sourceRecordId="coverage-monitor",
            family="connectionMonitor",
            resourceIds=tuple(sorted((WEB_ID.casefold(), DB_ID.casefold()))),
            pathId=path.path_id,
            direction="inbound",
            fiveTupleDigest=tuple_digest,
            endpointTestReference=test_reference,
            endpointTestDigest=test_digest,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW,
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["endpoint"].control_id,
            sourceRecordId="coverage-endpoint",
            family="endpointHealth",
            resourceIds=tuple(sorted((WEB_ID.casefold(), DB_ID.casefold()))),
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW,
            status="complete",
        ),
    )
    return MonitoringCollectionBatch(
        schemaVersion="athena.wc028MonitoringCollectionBatch.v1",
        collectedAt=NOW,
        incidentResourceId=WEB_ID,
        previousHealthSourceRecordId="endpoint-healthy",
        currentHealthSourceRecordIds=("endpoint-unhealthy",),
        records=records,
        coverage=coverage,
    )


class _Signer:
    def sign_preimage(self, canonical_preimage: bytes) -> str:
        assert canonical_preimage
        return base64.b64encode(b"synthetic-change-signature").decode("ascii")

    def verify_preimage(self, canonical_preimage: bytes, signature: bytes) -> bool:
        return bool(canonical_preimage and signature)


class _CommitPort:
    def __init__(self) -> None:
        self.calls = 0

    @contextmanager
    def transaction(
        self,
        prepared,
    ) -> Iterator[CommittedMonitoringCollection]:
        bundle = prepared.monitoring_bundle
        bundle_digest = sha256_hex(bundle.canonical_bytes())
        collection_id = f"wc024-{bundle_digest.removeprefix('sha256:')[:12]}"
        reference = VersionPinnedBlobReference(
            name=f"wc024-monitoring/{collection_id}/evidence.json",
            version="2026-09-13T03:00:00.0000000Z",
            contentDigest=bundle_digest,
        )
        payload: dict[str, object] = {
            "schemaVersion": "athena.wc024MonitoringEvidenceHandoff.v1",
            "collectorContractDigest": DIGEST_C,
            "collectionId": collection_id,
            "observedAt": NOW,
            "evidence": reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
        handoff = MonitoringEvidenceHandoff(
            **payload,
            collectorAttestation=MonitoringEvidenceAttestation(
                signatureAlgorithm="RS256",
                trustAnchorRef=MONITORING_KEY_ID,
                signedPreimageDigest=compute_artifact_digest(monitoring_handoff_preimage(payload)),
                signature=base64.b64encode(b"synthetic-monitoring-signature").decode("ascii"),
            ),
        )
        change_handoffs = tuple(
            ChangeEvidencePersistenceHandoff(
                schemaVersion="athena.changeEvidencePersistenceHandoff.v1",
                evidenceId=artifact.evidence.evidence_id,
                deduplicationKey=artifact.evidence.deduplication_key,
                changeKey=artifact.evidence.change_key,
                artifact=VersionPinnedBlobReference(
                    name=(
                        "change-evidence/"
                        f"{artifact.evidence.deduplication_key.removeprefix('sha256:')}/"
                        "evidence.json"
                    ),
                    version="2026-09-13T02:55:00.0000000Z",
                    contentDigest=sha256_hex(artifact.canonical_bytes()),
                ),
            )
            for artifact in prepared.change_artifacts
        )
        committed = CommittedMonitoringCollection(
            monitoring_handoff=handoff,
            change_handoffs=change_handoffs,
        )
        try:
            yield committed
        except Exception:
            raise
        else:
            self.calls += 1


def _transaction() -> MonitoringCollectionTransaction:
    return MonitoringCollectionTransaction(
        change_signer=_Signer(),
        change_signing_key_id=CHANGE_KEY_ID,
    )


def _scope_contract() -> ApprovedChangeScope:
    return ApprovedChangeScope(
        schemaVersion="athena.approvedChangeScope.v1",
        subscriptionId=SUBSCRIPTION_ID,
        resourceGroupName=RESOURCE_GROUP,
        approvedResourceIds=(NSG_RULE_ID.casefold(),),
    )


def _execute(*, direct_attribution: bool):
    context, intent, controls = _authority()
    commit = _CommitPort()
    prepared, committed, request = _transaction().execute(
        _batch(controls, direct_attribution=direct_attribution),
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
        commit_port=commit,
        incident_revision=1,
        issued_at=NOW,
        trusted_as_of=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    return prepared, committed, request, commit


def test_collection_transaction_drives_confirmed_nsg_connectivity_correlation() -> None:
    prepared, _, request, commit = _execute(direct_attribution=True)
    service = _test_service(request)
    report = service.validate_result(service.correlate(request))
    hypothesis = report.hypotheses[0]

    assert commit.calls == 1
    assert prepared.intent_digest
    assert hypothesis.category == "networkSecurityChange"
    assert hypothesis.confidence == "Confirmed"
    assert hypothesis.cause_resource_id == NSG_RULE_ID.casefold()
    assert {item.family for item in hypothesis.supporting_evidence} >= {
        "resourceChange",
        "networkFlow",
        "connectionMonitor",
        "endpointHealth",
    }


def test_missing_direct_attribution_exposes_manual_investigation_evidence() -> None:
    _, _, request, _ = _execute(direct_attribution=False)
    service = _test_service(request)
    hypothesis = service.validate_result(service.correlate(request)).hypotheses[0]

    assert hypothesis.category == "networkSecurityChange"
    assert hypothesis.confidence == "High"
    assert {item.code for item in hypothesis.missing_evidence} >= {"effectiveRuleAttribution"}
    assert any(
        "IP Flow Verify" in item.detail
        for item in hypothesis.missing_evidence
        if item.code == "effectiveRuleAttribution"
    )


def test_invalid_query_fails_before_transaction_commit() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(update={"query_digest": "sha256:" + "f" * 64})
        if isinstance(item, AmaHeartbeatRecord) and item.source_record_id == "heartbeat-unhealthy"
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="query"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_log_query_source_must_match_the_collector_record_kind() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    heartbeat = controls["heartbeat"]
    records = tuple(
        item.model_copy(
            update={
                "control_id": heartbeat.control_id,
                "query_digest": heartbeat.signal.query_digest,
                "query_target_resource_id": WEB_ID,
            }
        )
        if isinstance(item, ConnectionMonitorRecord)
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="record kind"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_resource_outside_published_control_scope_fails_before_commit() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    outside_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
        "providers/Microsoft.Compute/virtualMachines/synthetic-outside"
    )
    records = tuple(
        item.model_copy(update={"destination_resource_id": outside_id})
        if isinstance(item, ConnectionMonitorRecord)
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="scope"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_unbound_network_attribution_proof_fails_before_commit() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(
            update={
                "attribution_evidence": item.attribution_evidence.model_copy(
                    update={"destination_address": "192.0.2.99"}
                )
            }
        )
        if isinstance(item, NetworkWatcherFlowRecord) and item.attribution_evidence is not None
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="attribution proof"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_activity_log_and_resource_graph_pair_must_match() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(update={"correlation_id": "22222222-2222-2222-2222-222222222222"})
        if isinstance(item, ResourceChangeRecord)
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="disagree"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_non_denying_nsg_change_cannot_receive_direct_attribution() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = []
    for item in batch.records:
        if not isinstance(item, ResourceChangeRecord):
            records.append(item)
            continue
        payload = item.model_dump(mode="python", by_alias=True)
        change = payload["resourceGraphChange"]
        assert isinstance(change, dict)
        properties = change["properties"]
        assert isinstance(properties, dict)
        changes = properties["changes"]
        assert isinstance(changes, dict)
        access = changes["properties.access"]
        assert isinstance(access, dict)
        access["previousValue"] = "Deny"
        access["newValue"] = "Allow"
        records.append(ResourceChangeRecord.model_validate(payload))
    invalid = batch.model_copy(update={"records": tuple(records)})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="deny-introducing"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0


def test_stale_query_and_invalid_request_window_do_not_commit() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(
            update={
                "observed_start": NOW - timedelta(days=1, minutes=5),
                "observed_end": NOW - timedelta(days=1),
            }
        )
        if isinstance(item, AmaHeartbeatRecord) and item.source_record_id == "heartbeat-healthy"
        else item
        for item in batch.records
    )
    stale = batch.model_copy(update={"records": records})
    stale_commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="evaluation window"):
        _transaction().execute(
            stale,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=stale_commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert stale_commit.calls == 0

    invalid_window_commit = _CommitPort()
    with pytest.raises(MonitoringCollectionError, match="revision"):
        _transaction().execute(
            batch,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=invalid_window_commit,
            incident_revision=0,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert invalid_window_commit.calls == 0


def test_future_or_duplicate_coverage_is_rejected() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    future_coverage = tuple(
        item.model_copy(update={"observed_end": NOW + timedelta(seconds=30)})
        if item.source_record_id == "coverage-flow"
        else item
        for item in batch.coverage
    )
    future = batch.model_copy(update={"coverage": future_coverage})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="newer"):
        _transaction().execute(
            future,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0

    payload = batch.model_dump(mode="python", by_alias=True)
    payload["coverage"][1]["sourceRecordId"] = payload["coverage"][0]["sourceRecordId"]
    with pytest.raises(ValidationError, match="coverage sourceRecordId"):
        MonitoringCollectionBatch.model_validate(payload)


def test_coverage_family_must_match_published_query_source() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    coverage = tuple(
        item.model_copy(update={"family": "guest"})
        if item.source_record_id == "coverage-flow"
        else item
        for item in batch.coverage
    )
    invalid = batch.model_copy(update={"coverage": coverage})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="coverage family"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_change_record_cannot_be_selected_as_incident_health() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls).model_copy(
        update={"previous_health_source_record_id": "activity-change-001"}
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="health observations"):
        _transaction().execute(
            batch,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_resource_health_unavailability_can_anchor_the_incident() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls).model_copy(
        update={
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    commit = _CommitPort()

    _, _, request = _transaction().execute(
        batch,
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
        commit_port=commit,
        incident_revision=1,
        issued_at=NOW,
        trusted_as_of=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )

    assert request.incident_anchor.current_state == "unavailable"
    assert commit.calls == 1


def test_resource_health_incident_must_report_available_to_adverse_transition() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(update={"previous_status": "Unavailable"})
        if isinstance(item, ResourceHealthRecord)
        and item.source_record_id == "resource-health-active"
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(
        update={
            "records": records,
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="active and transition"):
        _transaction().execute(
            invalid,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0

    resolved_records = tuple(
        item.model_copy(
            update={
                "previous_status": "Available",
                "event_status": "Resolved",
            }
        )
        if isinstance(item, ResourceHealthRecord)
        and item.source_record_id == "resource-health-active"
        else item
        for item in batch.records
    )
    resolved = batch.model_copy(
        update={
            "records": resolved_records,
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    resolved_commit = _CommitPort()
    with pytest.raises(MonitoringCollectionError, match="active and transition"):
        _transaction().execute(
            resolved,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=resolved_commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert resolved_commit.calls == 0


def test_preparation_is_deterministic_for_input_order() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    reversed_batch = batch.model_copy(
        update={
            "records": tuple(reversed(batch.records)),
            "coverage": tuple(reversed(batch.coverage)),
        }
    )
    transaction = _transaction()
    expected = transaction.prepare(
        batch,
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
    )
    actual = transaction.prepare(
        reversed_batch,
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
    )

    assert actual.monitoring_bundle.canonical_bytes() == (
        expected.monitoring_bundle.canonical_bytes()
    )
    assert tuple(sha256_hex(item.canonical_bytes()) for item in actual.change_artifacts) == tuple(
        sha256_hex(item.canonical_bytes()) for item in expected.change_artifacts
    )
