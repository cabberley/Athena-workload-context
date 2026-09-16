from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

import athena_context.correlation.engine as correlation_engine
from athena_context.contracts import (
    LEGACY_CORRELATION_REQUEST_SCHEMA_VERSION,
    LEGACY_MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    PREVIOUS_CORRELATION_REQUEST_SCHEMA_VERSION,
    ActivityLogMonitoringSignal,
    ApprovedChangeScope,
    ChangeEvidencePersistenceHandoff,
    EndpointHealthObservation,
    LogQueryMonitoringSignal,
    MonitoringAcquisitionReceipt,
    MonitoringControlProvenance,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceBundle,
    MonitoringEvidenceHandoff,
    MonitoringIntentScope,
    PublishedMonitoringIntent,
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
    PublishedMonitoringIntentControl,
    ResourceHealthMonitoringSignal,
    VersionPinnedBlobReference,
    build_published_monitoring_intent,
    compute_artifact_digest,
    monitoring_handoff_preimage,
    sha256_hex,
    validate_published_monitoring_intent_assets,
)
from athena_context.correlation.verification import _verify_signed_monitoring_intent
from athena_context.monitoring_collection import (
    MAX_COLLECTION_TRUST_DELAY_SECONDS,
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
    _MonitoringCollectionTransactionCore,
    compute_monitoring_query_execution_digest,
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
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
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
INTENT_KEY_ID = (
    "https://synthetic-wc028.vault.azure.net/keys/"
    "monitoring-intent-signing/0123456789abcdef0123456789abcdef"
)
INTENT_SIGNATURE = "c3ludGhldGljLW1vbml0b3JpbmctaW50ZW50LXNpZ25hdHVyZQ"


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


def _ip_flow_provenance(*, direct_attribution: bool) -> dict[str, object]:
    tuple_payload = {
        "direction": "inbound",
        "protocol": "Tcp",
        "sourceResourceId": WEB_ID.casefold(),
        "destinationResourceId": DB_ID.casefold(),
        "sourceAddress": "192.0.2.10",
        "destinationAddress": "192.0.2.20",
        "sourcePort": 443,
        "destinationPort": 1433,
    }
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringIpFlowProvenance.v1",
        "exchangeSequence": 1,
        "ipFlowRequestDigest": "sha256:" + "a" * 64,
        "ipFlowResultDigest": "sha256:" + "b" * 64,
        "trafficAnalyticsRequestDigest": "sha256:" + "c" * 64,
        "correlationRequestId": "93e948cc-df1e-4caf-8a91-c31aa3803793",
        "targetResourceId": DB_ID.casefold(),
        **tuple_payload,
        "fiveTupleDigest": compute_artifact_digest(tuple_payload),
        "historicalDecision": "denied",
        "historicalRuleResourceId": NSG_RULE_ID.casefold(),
        "access": "Deny",
        "resultRuleResourceId": NSG_RULE_ID.casefold(),
        "causalChangeCorrelationId": (CHANGE_CORRELATION_ID if direct_attribution else None),
        "requestedAt": NOW,
        "checkedAt": NOW,
        "receivedAt": NOW,
    }
    return {
        **payload,
        "provenanceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _scope(
    resources: tuple[str, ...],
    *,
    evidence_resources: tuple[str, ...] = (),
) -> MonitoringIntentScope:
    path = _dependency_path()
    payload: dict[str, object] = {
        "resourceIds": tuple(sorted(item.casefold() for item in resources)),
        "pathIds": (path.path_id,),
        "roleRefs": tuple(sorted((path.source_role_ref, path.target_role_ref))),
    }
    if evidence_resources:
        payload["evidenceResourceIds"] = tuple(
            sorted(item.casefold() for item in evidence_resources)
        )
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
    dry_run_only: bool = False,
    evidence_resources: tuple[str, ...] = (),
) -> PublishedMonitoringIntentControl:
    payload: dict[str, object] = {
        "sourceClausePath": source_clause,
        "ownerRef": "synthetic-platform-owner",
        "severity": 1,
        "missingDataBehavior": "reviewRequired",
        "actionBehavior": "none",
        "dryRunOnly": dry_run_only,
        "scope": _scope(resources, evidence_resources=evidence_resources),
        "signal": signal,
    }
    digest = compute_artifact_digest(_json_value(payload))
    return PublishedMonitoringIntentControl(
        **payload,
        controlId=f"monitoring-control-{digest.removeprefix('sha256:')[:32]}",
        controlDigest=digest,
    )


def _controls(
    *,
    dry_run_only: bool = False,
    health_evidence_resources: tuple[str, ...] = (),
) -> dict[str, PublishedMonitoringIntentControl]:
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
            dry_run_only=dry_run_only,
            signal=_query_signal(
                (
                    "Heartbeat "
                    f"| where _ResourceId =~ '{WEB_ID.lower()}' "
                    "| summarize heartbeatCount=count() by _ResourceId"
                ),
                operator="lessThan",
                threshold=1,
            ),
        ),
        "endpoint": _control(
            source_clause="/controls/vm-connection-health",
            resources=(WEB_ID, DB_ID),
            dry_run_only=dry_run_only,
            signal=_query_signal(
                (
                    "VMConnection "
                    f"| where _ResourceId =~ '{WEB_ID.lower()}' "
                    "| summarize failedConnectionCount=count() by _ResourceId"
                ),
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "monitor": _control(
            source_clause="/controls/connection-monitor",
            resources=(WEB_ID, DB_ID),
            dry_run_only=dry_run_only,
            evidence_resources=(MONITOR_ID,),
            signal=_query_signal(
                "NWConnectionMonitorTestResult | summarize count()",
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "flow": _control(
            source_clause="/controls/network-flow",
            resources=path_resources,
            dry_run_only=dry_run_only,
            signal=_query_signal(
                "NTANetAnalytics | summarize count()",
                operator="greaterThan",
                threshold=0,
            ),
        ),
        "change": _control(
            source_clause="/controls/activity-change",
            resources=(NSG_RULE_ID,),
            dry_run_only=dry_run_only,
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
            dry_run_only=dry_run_only,
            evidence_resources=health_evidence_resources,
            signal=ResourceHealthMonitoringSignal(
                signalKind="resourceHealth",
                maximumEventAgeSeconds=900,
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
    path_id: str | None,
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


def _authority(
    *,
    dry_run_only: bool = False,
    health_evidence_resources: tuple[str, ...] = (),
) -> tuple[object, object, dict[str, PublishedMonitoringIntentControl]]:
    controls = _controls(
        dry_run_only=dry_run_only,
        health_evidence_resources=health_evidence_resources,
    )
    path = _dependency_path()
    tuple_digest = _five_tuple_digest()
    test_reference = "synthetic-web-db-test"
    test_digest = "sha256:" + "9" * 64
    required = tuple(
        sorted(
            (
                _coverage_scope_digest(
                    control=controls["heartbeat"],
                    resource_ids=(WEB_ID,),
                    path_id=None,
                ),
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


def _intent_assets(
    intent,
) -> tuple[
    PublishedMonitoringIntentAssetReference,
    PublishedMonitoringIntentAttestation,
]:
    attestation = PublishedMonitoringIntentAttestation(
        schemaVersion="athena.wc028PublishedMonitoringIntentAttestation.v1",
        intentId=intent.intent_id,
        intentDigest=intent.intent_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=INTENT_KEY_ID,
        signedPreimageDigest=sha256_hex(intent.canonical_bytes()),
        detachedSignature=INTENT_SIGNATURE,
    )
    prefix = f"monitoring-intent/{intent.intent_id}"
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028PublishedMonitoringIntentAssetReference.v1",
        "intentId": intent.intent_id,
        "intentDigest": intent.intent_digest,
        "intentReference": VersionPinnedBlobReference(
            name=f"{prefix}/intent.json",
            version="2026-09-13T01:00:00.0000000Z",
            contentDigest=sha256_hex(intent.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{prefix}/attestation.json",
            version="2026-09-13T01:00:01.0000000Z",
            contentDigest=sha256_hex(attestation.canonical_bytes()),
        ),
    }
    digest = compute_artifact_digest(_json_value(payload))
    return (
        PublishedMonitoringIntentAssetReference(
            **payload,
            referenceId=f"monitoring-intent-asset-{digest.removeprefix('sha256:')[:32]}",
            referenceDigest=digest,
        ),
        attestation,
    )


def _query_execution_fields(
    control: PublishedMonitoringIntentControl,
    *,
    source_record_id: str,
    observed_start: datetime,
    observed_end: datetime,
) -> dict[str, object]:
    signal = control.signal
    assert isinstance(signal, LogQueryMonitoringSignal)
    digest = compute_monitoring_query_execution_digest(
        control_id=control.control_id,
        source_record_id=source_record_id,
        query_digest=signal.query_digest,
        query_target_resource_id=signal.query_target_resource_id,
        observed_start=observed_start,
        observed_end=observed_end,
        evaluation_window_seconds=signal.evaluation_window_seconds,
        frequency_seconds=signal.frequency_seconds,
    )
    return {
        "queryDigest": signal.query_digest,
        "queryTargetResourceId": signal.query_target_resource_id,
        "evaluationWindowSeconds": signal.evaluation_window_seconds,
        "frequencySeconds": signal.frequency_seconds,
        "queryExecutionDigest": digest,
    }


def _coverage_query_fields(
    control: PublishedMonitoringIntentControl,
    records: tuple[
        AmaHeartbeatRecord
        | VmConnectionHealthRecord
        | ConnectionMonitorRecord
        | NetworkWatcherFlowRecord,
        ...,
    ],
) -> dict[str, object]:
    signal = control.signal
    assert isinstance(signal, LogQueryMonitoringSignal)
    return {
        "queryDigest": signal.query_digest,
        "queryTargetResourceId": signal.query_target_resource_id,
        "evaluationWindowSeconds": signal.evaluation_window_seconds,
        "frequencySeconds": signal.frequency_seconds,
        "queryExecutionDigests": tuple(sorted(item.query_execution_digest for item in records)),
    }


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
            **_query_execution_fields(
                controls["heartbeat"],
                source_record_id="heartbeat-healthy",
                observed_start=NOW - timedelta(minutes=10),
                observed_end=NOW - timedelta(minutes=5),
            ),
            heartbeatCount=1,
        ),
        AmaHeartbeatRecord(
            recordKind="amaHeartbeat",
            controlId=controls["heartbeat"].control_id,
            sourceRecordId="heartbeat-unhealthy",
            resourceId=WEB_ID,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            **_query_execution_fields(
                controls["heartbeat"],
                source_record_id="heartbeat-unhealthy",
                observed_start=NOW - timedelta(minutes=5),
                observed_end=NOW,
            ),
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
            **_query_execution_fields(
                controls["endpoint"],
                source_record_id="endpoint-healthy",
                observed_start=NOW - timedelta(minutes=10),
                observed_end=NOW - timedelta(minutes=5),
            ),
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
            **_query_execution_fields(
                controls["endpoint"],
                source_record_id="endpoint-unhealthy",
                observed_start=NOW - timedelta(minutes=5),
                observed_end=NOW,
            ),
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
            **_query_execution_fields(
                controls["flow"],
                source_record_id="flow-denied",
                observed_start=NOW - timedelta(minutes=5),
                observed_end=NOW,
            ),
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
            ipFlowProvenance=_ip_flow_provenance(direct_attribution=direct_attribution),
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
            **_query_execution_fields(
                controls["monitor"],
                source_record_id="connection-monitor-failed",
                observed_start=NOW - timedelta(minutes=5),
                observed_end=NOW,
            ),
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
    records_by_id = {item.source_record_id: item for item in records}
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
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            **_coverage_query_fields(
                controls["flow"],
                (records_by_id["flow-denied"],),
            ),
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
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            **_coverage_query_fields(
                controls["monitor"],
                (records_by_id["connection-monitor-failed"],),
            ),
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["endpoint"].control_id,
            sourceRecordId="coverage-endpoint",
            family="endpointHealth",
            resourceIds=tuple(sorted((WEB_ID.casefold(), DB_ID.casefold()))),
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            **_coverage_query_fields(
                controls["endpoint"],
                (records_by_id["endpoint-unhealthy"],),
            ),
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["endpoint"].control_id,
            sourceRecordId="coverage-endpoint-healthy",
            family="endpointHealth",
            resourceIds=tuple(sorted((WEB_ID.casefold(), DB_ID.casefold()))),
            pathId=path.path_id,
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW - timedelta(minutes=5),
            **_coverage_query_fields(
                controls["endpoint"],
                (records_by_id["endpoint-healthy"],),
            ),
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["heartbeat"].control_id,
            sourceRecordId="coverage-heartbeat-healthy",
            family="guest",
            resourceIds=(WEB_ID.casefold(),),
            observedStart=NOW - timedelta(minutes=10),
            observedEnd=NOW - timedelta(minutes=5),
            **_coverage_query_fields(
                controls["heartbeat"],
                (records_by_id["heartbeat-healthy"],),
            ),
            status="complete",
        ),
        MonitoringCoverageRecord(
            controlId=controls["heartbeat"].control_id,
            sourceRecordId="coverage-heartbeat-unhealthy",
            family="guest",
            resourceIds=(WEB_ID.casefold(),),
            observedStart=NOW - timedelta(minutes=5),
            observedEnd=NOW,
            **_coverage_query_fields(
                controls["heartbeat"],
                (records_by_id["heartbeat-unhealthy"],),
            ),
            status="complete",
        ),
    )
    return MonitoringCollectionBatch(
        schemaVersion="athena.wc028MonitoringCollectionBatch.v2",
        collectedAt=NOW,
        incidentResourceId=WEB_ID,
        previousHealthSourceRecordId="resource-health-resolved",
        currentHealthSourceRecordIds=("resource-health-active",),
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
            "schemaVersion": (
                "athena.wc028MonitoringEvidenceHandoff.v2"
                if bundle.acquisition_receipt is not None
                else "athena.wc024MonitoringEvidenceHandoff.v1"
            ),
            "collectorContractDigest": bundle.monitoring_contract_digest,
            "collectionId": collection_id,
            "observedAt": bundle.observed_end,
            "evidence": reference.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        }
        if bundle.acquisition_receipt is not None:
            payload["acquisitionReceiptDigest"] = bundle.acquisition_receipt.receipt_digest
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


class _LegacyTestMonitoringCollectionTransaction(_MonitoringCollectionTransactionCore):
    """Test-only compatibility path for pre-receipt collection fixtures."""


def _transaction(
    *,
    asset_loader: Callable[
        [object],
        tuple[
            PublishedMonitoringIntentAssetReference,
            PublishedMonitoringIntentAttestation,
        ],
    ] = _intent_assets,
) -> _LegacyTestMonitoringCollectionTransaction:
    return _LegacyTestMonitoringCollectionTransaction(
        change_signer=_Signer(),
        change_signing_key_id=CHANGE_KEY_ID,
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=asset_loader,
    )


def _production_transaction(
    *,
    asset_loader: Callable[
        [object],
        tuple[
            PublishedMonitoringIntentAssetReference,
            PublishedMonitoringIntentAttestation,
        ],
    ] = _intent_assets,
) -> MonitoringCollectionTransaction:
    def verify_receipt(
        receipt: MonitoringAcquisitionReceipt,
        _trusted_as_of: datetime,
    ) -> None:
        expected = base64.b64encode(b"synthetic-acquisition-receipt").decode("ascii")
        if receipt.collector_attestation.signature != expected:
            raise ValueError("synthetic receipt signature is invalid")

    return MonitoringCollectionTransaction(
        acquisition_receipt_verifier=verify_receipt,
        change_signer=_Signer(),
        change_signing_key_id=CHANGE_KEY_ID,
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=asset_loader,
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
    assert prepared.monitoring_bundle.schema_version == MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION
    assert request.schema_version == PREVIOUS_CORRELATION_REQUEST_SCHEMA_VERSION
    assert prepared.monitoring_bundle.monitoring_intent_reference is not None
    assert prepared.monitoring_bundle.collected_at == NOW
    query_observation_digests = {
        item.query_execution_digest
        for item in prepared.monitoring_bundle.observations
        if item.query_execution_digest is not None
    }
    covered_query_digests = [
        digest
        for item in prepared.monitoring_bundle.coverage
        for digest in item.query_execution_digests
    ]
    assert query_observation_digests
    assert sorted(query_observation_digests) == sorted(covered_query_digests)
    assert len(covered_query_digests) == len(set(covered_query_digests))
    assert all(
        item.control_provenance is not None
        for item in (
            *prepared.monitoring_bundle.observations,
            *prepared.monitoring_bundle.coverage,
        )
    )
    intent_reference = prepared.monitoring_bundle.monitoring_intent_reference
    assert intent_reference.intent_reference in request.evidence_inventory.source_references
    assert intent_reference.attestation_reference in request.evidence_inventory.source_references
    assert (
        request.evidence_inventory.monitoring_intent_asset_reference_digest
        == intent_reference.asset_reference_digest
    )
    assert request.evidence_inventory.monitoring_control_provenance_digest
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


def test_unattested_monitoring_intent_fails_before_transaction_commit() -> None:
    context, intent, controls = _authority()
    commit = _CommitPort()

    def invalid_assets(
        selected_intent: object,
    ) -> tuple[
        PublishedMonitoringIntentAssetReference,
        PublishedMonitoringIntentAttestation,
    ]:
        reference, attestation = _intent_assets(selected_intent)
        return reference, attestation.model_copy(update={"detached_signature": "aW52YWxpZA"})

    with pytest.raises(ValueError, match="assets"):
        _transaction(asset_loader=invalid_assets).execute(
            _batch(controls),
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


def test_signed_dry_run_intent_fails_before_transaction_commit() -> None:
    context, intent, controls = _authority(dry_run_only=True)
    commit = _CommitPort()

    with pytest.raises(ValueError, match="dry-run-only"):
        _transaction().execute(
            _batch(controls),
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

    with pytest.raises(MonitoringCollectionError, match="query execution"):
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


@pytest.mark.parametrize(
    "monitor_resource_id",
    (
        MONITOR_ID.replace("synthetic-web-db", "unreviewed-monitor"),
        WEB_ID,
    ),
)
def test_connection_monitor_resource_requires_signed_evidence_scope(
    monitor_resource_id: str,
) -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(update={"monitor_resource_id": monitor_resource_id})
        if isinstance(item, ConnectionMonitorRecord)
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(update={"records": records})
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="evidence scope"):
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


def test_evidence_resource_cannot_become_resource_health_incident_subject() -> None:
    context, intent, controls = _authority(
        health_evidence_resources=(MONITOR_ID,),
    )
    batch = _batch(controls)
    records = tuple(
        item.model_copy(update={"resource_id": MONITOR_ID})
        if isinstance(item, ResourceHealthRecord)
        else item
        for item in batch.records
    )
    invalid = batch.model_copy(
        update={
            "incident_resource_id": MONITOR_ID,
            "records": records,
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="control scope"):
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

    with pytest.raises(MonitoringCollectionError, match="query execution"):
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

    with pytest.raises(MonitoringCollectionError, match="freshness"):
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


def test_complete_coverage_cannot_extend_beyond_bound_query_executions() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    coverage = tuple(
        item.model_copy(update={"observed_start": NOW - timedelta(minutes=10)})
        if item.source_record_id == "coverage-flow"
        else item
        for item in batch.coverage
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="exact contiguous"):
        _transaction().execute(
            batch.model_copy(update={"coverage": coverage}),
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


def test_complete_coverage_requires_reviewed_execution_frequency() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records_by_id = {item.source_record_id: item for item in batch.records}
    coverage = tuple(
        item.model_copy(
            update={
                "observed_start": NOW - timedelta(minutes=10),
                "query_execution_digests": tuple(
                    sorted(
                        (
                            records_by_id["endpoint-healthy"].query_execution_digest,
                            records_by_id["endpoint-unhealthy"].query_execution_digest,
                        )
                    )
                ),
            }
        )
        if item.source_record_id == "coverage-endpoint"
        else item
        for item in batch.coverage
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="scheduled coverage"):
        _transaction().execute(
            batch.model_copy(update={"coverage": coverage}),
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


def test_complete_coverage_rejects_unknown_query_execution_digest() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    coverage = tuple(
        item.model_copy(update={"query_execution_digests": ("sha256:" + "f" * 64,)})
        if item.source_record_id == "coverage-flow"
        else item
        for item in batch.coverage
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="unknown query execution"):
        _transaction().execute(
            batch.model_copy(update={"coverage": coverage}),
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


def test_every_query_observation_requires_exactly_one_compatible_coverage() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    uncovered = tuple(
        item.model_copy(
            update={
                "status": "unavailable",
                "detail": "synthetic query outage",
                "query_execution_digests": (),
            }
        )
        if item.source_record_id == "coverage-heartbeat-healthy"
        else item
        for item in batch.coverage
    )

    with pytest.raises(MonitoringCollectionError, match="exactly one compatible coverage"):
        _transaction().prepare(
            batch.model_copy(update={"coverage": uncovered}),
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=1),
        )

    flow = next(item for item in batch.coverage if item.source_record_id == "coverage-flow")
    duplicated = (*batch.coverage, flow.model_copy(update={"source_record_id": "coverage-flow-2"}))
    with pytest.raises(MonitoringCollectionError, match="exactly one compatible coverage"):
        _transaction().prepare(
            batch.model_copy(update={"coverage": duplicated}),
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=1),
        )


def test_confidence_matcher_rejects_unrelated_complete_query_coverage() -> None:
    _, _, request, _ = _execute(direct_attribution=True)
    endpoint = next(
        item
        for item in request.monitoring_bundle.observations
        if isinstance(item, EndpointHealthObservation) and item.status == "unhealthy"
    )
    exact = next(
        item
        for item in request.monitoring_bundle.coverage
        if item.query_execution_digests == (endpoint.query_execution_digest,)
    )
    healthy_endpoint = next(
        item
        for item in request.monitoring_bundle.observations
        if isinstance(item, EndpointHealthObservation) and item.status == "healthy"
    )
    partial_exact = exact.model_copy(
        update={"status": "partial", "detail": "synthetic partial result"}
    )
    unrelated_complete = exact.model_copy(
        update={
            "coverage_id": "coverage-" + "f" * 32,
            "coverage_digest": "sha256:" + "f" * 64,
            "query_execution_digests": (healthy_endpoint.query_execution_digest,),
        }
    )
    coverage = tuple(
        item for item in request.monitoring_bundle.coverage if item.coverage_id != exact.coverage_id
    ) + (partial_exact, unrelated_complete)
    forged_request = request.model_copy(
        update={
            "monitoring_bundle": request.monitoring_bundle.model_copy(update={"coverage": coverage})
        }
    )

    assert (
        correlation_engine._matching_endpoint_coverage(
            forged_request,
            endpoint,
        )
        is None
    )


def test_v1_collection_batch_is_rejected_after_query_binding_upgrade() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls).model_copy(
        update={"schema_version": "athena.wc028MonitoringCollectionBatch.v1"}
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="strict .* revalidation"):
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


def test_stale_resource_health_cannot_open_an_incident() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls)
    records = tuple(
        item.model_copy(
            update={
                "observed_start": NOW - timedelta(minutes=20),
                "observed_end": NOW - timedelta(minutes=16),
            }
        )
        if isinstance(item, ResourceHealthRecord)
        and item.source_record_id == "resource-health-active"
        else item
        for item in batch.records
    )
    stale = batch.model_copy(
        update={
            "records": records,
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    commit = _CommitPort()

    with pytest.raises(MonitoringCollectionError, match="freshness limit"):
        _transaction().execute(
            stale,
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


def test_resource_health_freshness_is_rechecked_at_trusted_as_of() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls).model_copy(
        update={
            "previous_health_source_record_id": "resource-health-resolved",
            "current_health_source_record_ids": ("resource-health-active",),
        }
    )
    commit = _CommitPort()
    trusted_as_of = NOW + timedelta(minutes=15, seconds=1)

    with pytest.raises(MonitoringCollectionError, match="freshness limit"):
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
            issued_at=NOW + timedelta(minutes=1),
            trusted_as_of=trusted_as_of,
            expires_at=trusted_as_of,
        )

    assert commit.calls == 0


def test_collection_to_trusted_as_of_delay_is_bounded() -> None:
    context, intent, controls = _authority()

    with pytest.raises(MonitoringCollectionError, match="bounded"):
        _transaction().prepare(
            _batch(controls),
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(seconds=MAX_COLLECTION_TRUST_DELAY_SECONDS + 1),
        )


def test_query_freshness_is_reapplied_at_trusted_as_of() -> None:
    context, intent, controls = _authority()
    batch = _batch(controls, direct_attribution=False)
    current_heartbeat = next(
        item for item in batch.records if item.source_record_id == "heartbeat-unhealthy"
    )
    without_change = batch.model_copy(
        update={
            "records": (
                current_heartbeat,
                *(
                    item
                    for item in batch.records
                    if not isinstance(item, ResourceChangeRecord) and item is not current_heartbeat
                ),
            )
        }
    )

    with pytest.raises(MonitoringCollectionError, match="evaluation window"):
        _transaction().prepare(
            without_change,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=20),
        )


def test_resource_graph_freshness_is_reapplied_at_trusted_as_of() -> None:
    context, intent, controls = _authority()

    with pytest.raises(MonitoringCollectionError, match="trustedAsOf freshness limit"):
        _transaction().prepare(
            _batch(controls),
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=20),
        )


def test_legacy_schema_versions_reject_wc028_wire_fields() -> None:
    prepared, _, request, _ = _execute(direct_attribution=True)
    legacy_bundle_payload = prepared.monitoring_bundle.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    legacy_bundle_payload["schemaVersion"] = LEGACY_MONITORING_EVIDENCE_BUNDLE_SCHEMA_VERSION
    with pytest.raises(ValidationError, match="legacy monitoring bundle"):
        MonitoringEvidenceBundle.model_validate(legacy_bundle_payload)

    legacy_request_payload = request.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    legacy_request_payload["schemaVersion"] = LEGACY_CORRELATION_REQUEST_SCHEMA_VERSION
    with pytest.raises(ValidationError, match="legacy correlation request"):
        type(request).model_validate(legacy_request_payload)


class _IntentAssetReader:
    def __init__(
        self,
        reference: PublishedMonitoringIntentAssetReference,
        intent: PublishedMonitoringIntent,
        attestation: PublishedMonitoringIntentAttestation,
    ) -> None:
        self.references: list[VersionPinnedBlobReference] = []
        self.payloads = {
            reference.intent_reference: intent.canonical_bytes(),
            reference.attestation_reference: attestation.canonical_bytes(),
        }

    def read(self, reference: VersionPinnedBlobReference) -> bytes:
        self.references.append(reference)
        return self.payloads[reference]


class _IntentAssetVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, reference, intent, attestation) -> str:
        self.calls += 1
        validate_published_monitoring_intent_assets(
            reference,
            intent,
            attestation,
            trusted_key_id=INTENT_KEY_ID,
            signature_verifier=(lambda _payload, signature: signature == INTENT_SIGNATURE),
        )
        return reference.reference_digest


def test_downstream_verification_rereads_signed_intent_and_resolves_controls() -> None:
    _, intent, _ = _authority()
    reference, attestation = _intent_assets(intent)
    _, _, request, _ = _execute(direct_attribution=True)
    reader = _IntentAssetReader(reference, intent, attestation)
    verifier = _IntentAssetVerifier()

    _verify_signed_monitoring_intent(
        request,
        reader=reader,
        verifier=verifier,
    )

    assert reader.references == [
        reference.intent_reference,
        reference.attestation_reference,
    ]
    assert verifier.calls == 1

    reader.payloads[reference.intent_reference] = b"{}\n"
    with pytest.raises(ValueError, match="immutable references"):
        _verify_signed_monitoring_intent(
            request,
            reader=reader,
            verifier=verifier,
        )
    reader.payloads[reference.intent_reference] = intent.canonical_bytes()

    observation = request.monitoring_bundle.observations[0]
    assert observation.control_provenance is not None
    forged_provenance = MonitoringControlProvenance(
        controlId="monitoring-control-" + "f" * 32,
        controlDigest="sha256:" + "f" * 64,
        sourceClausePath="/controls/forged",
    )
    forged_observation = observation.model_copy(update={"control_provenance": forged_provenance})
    forged_bundle = request.monitoring_bundle.model_copy(
        update={
            "observations": (
                forged_observation,
                *request.monitoring_bundle.observations[1:],
            )
        }
    )
    forged_request = request.model_copy(update={"monitoring_bundle": forged_bundle})
    with pytest.raises(ValueError, match="does not resolve"):
        _verify_signed_monitoring_intent(
            forged_request,
            reader=reader,
            verifier=verifier,
        )


def test_production_verification_rejects_historical_v3_request() -> None:
    _, intent, _ = _authority()
    reference, attestation = _intent_assets(intent)
    _, _, request, _ = _execute(direct_attribution=True)
    trusted_as_of = NOW + timedelta(minutes=20)
    payload = request.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
        exclude={"request_id", "request_digest"},
    )
    payload.update(
        {
            "issuedAt": trusted_as_of - timedelta(minutes=1),
            "trustedAsOf": trusted_as_of,
            "expiresAt": trusted_as_of + timedelta(minutes=5),
        }
    )
    request_digest = compute_artifact_digest(_json_value(payload))
    reissued_request = type(request).model_validate(
        {
            **payload,
            "requestId": f"request-{request_digest.removeprefix('sha256:')[:32]}",
            "requestDigest": request_digest,
        }
    )
    service = _test_service(reissued_request)
    object.__setattr__(
        service,
        "monitoring_intent_reader",
        _IntentAssetReader(reference, intent, attestation),
    )
    object.__setattr__(
        service,
        "monitoring_intent_verifier",
        _IntentAssetVerifier(),
    )
    object.__setattr__(service, "_require_signed_monitoring_intent", True)

    assert reissued_request.schema_version == PREVIOUS_CORRELATION_REQUEST_SCHEMA_VERSION
    assert reissued_request.trusted_as_of == trusted_as_of
    with pytest.raises(ValueError, match="incident-bound request v4"):
        service.correlate(reissued_request)


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
        trusted_as_of=NOW + timedelta(minutes=1),
    )
    actual = transaction.prepare(
        reversed_batch,
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
        trusted_as_of=NOW + timedelta(minutes=1),
    )

    assert actual.monitoring_bundle.canonical_bytes() == (
        expected.monitoring_bundle.canonical_bytes()
    )
    assert tuple(sha256_hex(item.canonical_bytes()) for item in actual.change_artifacts) == tuple(
        sha256_hex(item.canonical_bytes()) for item in expected.change_artifacts
    )
