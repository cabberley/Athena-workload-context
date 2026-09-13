from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from athena_context.contracts import (
    ResourceHealthMonitoringSignal,
    build_published_monitoring_intent,
    compute_artifact_digest,
)
from athena_context.monitoring_acquisition import (
    MAX_ACQUISITION_RESPONSE_BYTES,
    MAX_ACQUISITION_ROWS,
    ActivityLogQueryRequest,
    ActivityLogQueryResult,
    ActivityLogRow,
    ConnectionMonitorRow,
    HeartbeatRow,
    IpFlowVerifyRequest,
    IpFlowVerifyResult,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResult,
    LogCoverageDescriptor,
    MonitoringAcquisitionAuthority,
    MonitoringAcquisitionCoordinator,
    MonitoringAcquisitionError,
    ResourceGraphChangeQueryRequest,
    ResourceGraphChangeQueryResult,
    ResourceGraphChangeRow,
    ResourceHealthQueryRequest,
    ResourceHealthQueryResult,
    ResourceHealthRow,
    TrafficAnalyticsRow,
    VmConnectionRow,
)
from athena_context.monitoring_collection import (
    AmaHeartbeatRecord,
    NetworkWatcherFlowRecord,
    ResourceChangeRecord,
    VmConnectionHealthRecord,
)
from test_wc026_correlation_contract import (
    DB_ID,
    DIGEST_C,
    NOW,
    NSG_ID,
    NSG_RULE_ID,
    WEB_ID,
    _context_binding,
    _dependency_path,
)
from test_wc028_monitoring_collection import (
    CHANGE_CORRELATION_ID,
    INTENT_KEY_ID,
    INTENT_SIGNATURE,
    MONITOR_ID,
    _CommitPort,
    _control,
    _controls,
    _coverage_scope_digest,
    _five_tuple_digest,
    _intent_assets,
    _scope_contract,
    _transaction,
)

READER_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-synthetic-monitoring/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/synthetic-monitoring-reader"
)
CONTEXT_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-synthetic-athena/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/synthetic-athena-context"
)
OUT_OF_SCOPE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-synthetic-other/providers/Microsoft.Compute/"
    "virtualMachines/synthetic-out-of-scope"
)


def _acquisition_authority(
    *,
    reader_identity_id: str = READER_ID,
    context_identity_id: str = CONTEXT_ID,
    max_freshness_seconds: int = 900,
) -> MonitoringAcquisitionAuthority:
    allowed_sources = (
        "activityLog",
        "ipFlowVerify",
        "logAnalytics",
        "resourceGraph",
        "resourceHealth",
    )
    allowed_resources = tuple(
        sorted(item.casefold() for item in (WEB_ID, DB_ID, NSG_ID, NSG_RULE_ID, MONITOR_ID))
    )
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v1",
        "monitoringReaderIdentityId": reader_identity_id.casefold(),
        "athenaContextIdentityId": context_identity_id.casefold(),
        "collectorContractDigest": DIGEST_C,
        "allowedSources": list(allowed_sources),
        "allowedResourceIds": list(allowed_resources),
        "maxRows": MAX_ACQUISITION_ROWS,
        "maxBytes": MAX_ACQUISITION_RESPONSE_BYTES,
        "maxWindowSeconds": 86400,
        "maxFreshnessSeconds": max_freshness_seconds,
        "readOnly": True,
        "athenaContextHasWorkloadReader": False,
    }
    digest = compute_artifact_digest(payload)
    return MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": allowed_sources,
            "allowedResourceIds": allowed_resources,
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )


def _authority(controls=None):
    controls = _controls() if controls is None else controls
    path = _dependency_path()
    required_values = []
    for name, control in controls.items():
        if name == "change":
            continue
        coverage_kwargs: dict[str, object] = {}
        if name == "monitor":
            coverage_kwargs = {
                "direction": "inbound",
                "five_tuple_digest": _five_tuple_digest(),
                "endpoint_test_reference": "synthetic-web-db-test",
                "endpoint_test_digest": "sha256:" + "9" * 64,
            }
        elif name == "flow":
            coverage_kwargs = {
                "direction": "inbound",
                "five_tuple_digest": _five_tuple_digest(),
            }
        required_values.append(
            _coverage_scope_digest(
                control=control,
                resource_ids=control.scope.resource_ids,
                path_id=None if name == "heartbeat" else path.path_id,
                **coverage_kwargs,
            )
        )
    required = tuple(sorted(required_values))
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


class _AcquisitionPort:
    def __init__(
        self,
        *,
        reverse_rows: bool = False,
        ambiguous_vm_mapping: bool = False,
        truncated_flow: bool = False,
        stale: bool = False,
        duplicate_activity: bool = False,
        fail_resource_graph: bool = False,
        absent_heartbeat: bool = False,
        recovered: bool = False,
        mismatched_ip_flow: bool = False,
        healthy_heartbeat: bool = False,
        truncated_change: bool = False,
        missing_current_heartbeat: bool = False,
        single_active_health: bool = False,
        absent_connection_monitor: bool = False,
        source_identity_id: str = READER_ID,
        out_of_scope_heartbeat: bool = False,
        multiple_current_vm_rows: bool = False,
        all_vm_mappings_ambiguous: bool = False,
        multiple_heartbeat_rows: bool = False,
        missing_current_db_heartbeat: bool = False,
    ) -> None:
        self.reverse_rows = reverse_rows
        self.ambiguous_vm_mapping = ambiguous_vm_mapping
        self.truncated_flow = truncated_flow
        self.stale = stale
        self.duplicate_activity = duplicate_activity
        self.fail_resource_graph = fail_resource_graph
        self.absent_heartbeat = absent_heartbeat
        self.recovered = recovered
        self.mismatched_ip_flow = mismatched_ip_flow
        self.healthy_heartbeat = healthy_heartbeat
        self.truncated_change = truncated_change
        self.missing_current_heartbeat = missing_current_heartbeat
        self.single_active_health = single_active_health
        self.absent_connection_monitor = absent_connection_monitor
        self.source_identity_id = source_identity_id
        self.out_of_scope_heartbeat = out_of_scope_heartbeat
        self.multiple_current_vm_rows = multiple_current_vm_rows
        self.all_vm_mappings_ambiguous = all_vm_mappings_ambiguous
        self.multiple_heartbeat_rows = multiple_heartbeat_rows
        self.missing_current_db_heartbeat = missing_current_db_heartbeat
        self.requests: list[object] = []

    def _collected_at(self):
        return NOW - timedelta(minutes=1) if self.stale else NOW

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult:
        self.requests.append(request)
        is_current = request.window_end == NOW
        path = _dependency_path()
        if request.table == "Heartbeat":
            if self.absent_heartbeat or (self.missing_current_heartbeat and is_current):
                rows = ()
            else:
                heartbeat_rows = [
                    HeartbeatRow(
                        rowKind="heartbeat",
                        resourceId=(OUT_OF_SCOPE_ID if self.out_of_scope_heartbeat else WEB_ID),
                        observedStart=request.window_start,
                        observedEnd=request.window_end,
                        heartbeatCount=(1 if self.healthy_heartbeat or self.recovered else 0)
                        if is_current
                        else 1,
                    ),
                ]
                if self.multiple_heartbeat_rows and not (
                    self.missing_current_db_heartbeat and is_current
                ):
                    heartbeat_rows.append(
                        HeartbeatRow(
                            rowKind="heartbeat",
                            resourceId=DB_ID,
                            observedStart=request.window_start,
                            observedEnd=request.window_end,
                            heartbeatCount=1,
                        )
                    )
                rows = tuple(heartbeat_rows)
        elif request.table == "VMConnection":
            rows = [
                VmConnectionRow(
                    rowKind="vmConnection",
                    sourceAddress="192.0.2.10",
                    destinationAddress="192.0.2.20",
                    subjectResourceCandidates=(
                        (WEB_ID, DB_ID)
                        if self.all_vm_mappings_ambiguous
                        or (self.ambiguous_vm_mapping and is_current)
                        else (WEB_ID,)
                    ),
                    backendResourceCandidates=(DB_ID,),
                    pathId=path.path_id,
                    observedStart=request.window_start,
                    observedEnd=request.window_end,
                    failedConnectionCount=(0 if self.recovered else 3) if is_current else 0,
                ),
            ]
            if self.multiple_current_vm_rows and is_current:
                rows.append(
                    rows[0].model_copy(
                        update={"failed_connection_count": 4},
                    )
                )
            rows = tuple(rows)
        elif request.table == "NWConnectionMonitorTestResult":
            rows = (
                ()
                if self.absent_connection_monitor
                else (
                    ConnectionMonitorRow(
                        rowKind="connectionMonitor",
                        subjectResourceId=WEB_ID,
                        pathId=path.path_id,
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
                        testConfigurationReference="synthetic-web-db-test",
                        testConfigurationDigest="sha256:" + "9" * 64,
                        observedStart=request.window_start,
                        observedEnd=request.window_end,
                    ),
                )
            )
        else:
            rows = (
                TrafficAnalyticsRow(
                    rowKind="trafficAnalytics",
                    subjectResourceCandidates=(WEB_ID,),
                    pathId=path.path_id,
                    decision="denied",
                    direction="inbound",
                    protocol="Tcp",
                    sourceResourceCandidates=(WEB_ID,),
                    destinationResourceCandidates=(DB_ID,),
                    sourceAddress="192.0.2.10",
                    destinationAddress="192.0.2.20",
                    sourcePort=443,
                    destinationPort=1433,
                    enforcementResourceId=NSG_ID,
                    ruleResourceId=NSG_RULE_ID,
                    trafficAnalyticsLimitation="aggregatedNotPacketCausal",
                    observedStart=request.window_start,
                    observedEnd=request.window_end,
                ),
            )
        coverage_descriptor = None
        if request.table == "NWConnectionMonitorTestResult":
            coverage_descriptor = LogCoverageDescriptor(
                resourceIds=tuple(sorted((WEB_ID, DB_ID))),
                pathId=path.path_id,
                direction="inbound",
                fiveTupleDigest=_five_tuple_digest(),
                endpointTestReference="synthetic-web-db-test",
                endpointTestDigest="sha256:" + "9" * 64,
            )
        elif request.table == "NTANetAnalytics":
            coverage_descriptor = LogCoverageDescriptor(
                resourceIds=tuple(sorted((WEB_ID, DB_ID, NSG_ID, NSG_RULE_ID))),
                pathId=path.path_id,
                direction="inbound",
                fiveTupleDigest=_five_tuple_digest(),
            )
        return LogAnalyticsQueryResult(
            schemaVersion="athena.wc028LogAnalyticsQueryResult.v1",
            source="logAnalytics",
            table=request.table,
            requestDigest=request.request_digest,
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            columns=request.expected_columns,
            coverageDescriptor=coverage_descriptor,
            truncated=self.truncated_flow and request.table == "NTANetAnalytics",
            responseBytes=4096,
            rows=rows,
        )

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult:
        self.requests.append(request)
        return IpFlowVerifyResult(
            schemaVersion="athena.wc028IpFlowVerifyResult.v1",
            source="ipFlowVerify",
            requestDigest=(
                "sha256:" + "0" * 64 if self.mismatched_ip_flow else request.request_digest
            ),
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            checkedAt=request.checked_at,
            access="Deny",
            ruleResourceId=NSG_RULE_ID,
            responseBytes=1024,
            limitation="pointInTimeNotHistorical",
        )

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult:
        self.requests.append(request)
        row = ActivityLogRow(
            category="Administrative",
            operationName="Microsoft.Network/networkSecurityGroups/securityRules/write",
            resultType="Succeeded",
            level="Informational",
            targetResourceId=NSG_RULE_ID,
            correlationId=CHANGE_CORRELATION_ID,
            occurredAt=NOW - timedelta(minutes=6),
        )
        rows = (row, row) if self.duplicate_activity else (row,)
        return ActivityLogQueryResult(
            schemaVersion="athena.wc028ActivityLogQueryResult.v1",
            source="activityLog",
            requestDigest=request.request_digest,
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            columns=request.expected_columns,
            truncated=self.truncated_change,
            responseBytes=2048,
            rows=rows,
        )

    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult:
        self.requests.append(request)
        if self.fail_resource_graph:
            raise TimeoutError("synthetic source timeout")
        change_control = _controls()["change"]
        change = ResourceChangeRecord(
            recordKind="resourceChange",
            controlId=change_control.control_id,
            sourceRecordId="synthetic-source",
            category="Administrative",
            operationName="Microsoft.Network/networkSecurityGroups/securityRules/write",
            resultType="Succeeded",
            level="Informational",
            targetResourceId=NSG_RULE_ID,
            correlationId=CHANGE_CORRELATION_ID,
            occurredAt=NOW - timedelta(minutes=6),
            resourceGraphChange={
                "id": (
                    f"{NSG_RULE_ID}/providers/Microsoft.Resources/changes/"
                    "synthetic-wc028-change-001"
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
                        "operation": (
                            "Microsoft.Network/networkSecurityGroups/securityRules/write"
                        ),
                        "timestamp": (NOW - timedelta(minutes=6))
                        .isoformat()
                        .replace("+00:00", "Z"),
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
        ).resource_graph_change
        row = ResourceGraphChangeRow(
            targetResourceId=NSG_RULE_ID,
            correlationId=CHANGE_CORRELATION_ID,
            occurredAt=NOW - timedelta(minutes=6),
            operationName="Microsoft.Network/networkSecurityGroups/securityRules/write",
            resultType="Succeeded",
            change=change,
        )
        return ResourceGraphChangeQueryResult(
            schemaVersion="athena.wc028ResourceGraphChangeQueryResult.v1",
            source="resourceGraph",
            requestDigest=request.request_digest,
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            columns=request.expected_columns,
            truncated=self.truncated_change,
            responseBytes=4096,
            rows=(row,),
        )

    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult:
        self.requests.append(request)
        rows = (
            ResourceHealthRow(
                resourceId=WEB_ID,
                eventStatus="Active" if self.recovered else "Resolved",
                currentStatus="Unavailable" if self.recovered else "Available",
                previousStatus="Available" if self.recovered else "Unavailable",
                reasonType="PlatformInitiated",
                observedStart=NOW - timedelta(minutes=10),
                observedEnd=NOW - timedelta(minutes=5),
            ),
            ResourceHealthRow(
                resourceId=WEB_ID,
                eventStatus="Resolved" if self.recovered else "Active",
                currentStatus="Available" if self.recovered else "Unavailable",
                previousStatus="Unavailable" if self.recovered else "Available",
                reasonType="PlatformInitiated",
                observedStart=NOW - timedelta(minutes=5),
                observedEnd=NOW,
            ),
        )
        if self.reverse_rows:
            rows = tuple(reversed(rows))
        if self.single_active_health:
            rows = (rows[-1],)
        return ResourceHealthQueryResult(
            schemaVersion="athena.wc028ResourceHealthQueryResult.v1",
            source="resourceHealth",
            requestDigest=request.request_digest,
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            columns=request.expected_columns,
            truncated=False,
            responseBytes=2048,
            rows=rows,
        )


def _execute(port: _AcquisitionPort, *, authority=None):
    context, intent, _ = _authority() if authority is None else authority
    commit = _CommitPort()
    acquisition_authority = _acquisition_authority()
    outcome = MonitoringAcquisitionCoordinator(
        acquisition_port=port,
        acquisition_authority=acquisition_authority,
        expected_acquisition_authority_digest=(acquisition_authority.authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    ).execute(
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collected_at=NOW,
        collector_contract_digest=DIGEST_C,
        change_scope=_scope_contract(),
        commit_port=commit,
        incident_revision=1,
        issued_at=NOW,
        trusted_as_of=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    return outcome, commit, intent


def test_acquisition_derives_strict_requests_and_commits_one_batch() -> None:
    port = _AcquisitionPort()
    outcome, commit, intent = _execute(port)

    assert commit.calls == 1
    assert outcome.batch == outcome.batch.model_copy()
    assert outcome.prepared.intent_id == intent.intent_id
    assert (
        len([item for item in outcome.batch.records if isinstance(item, ResourceChangeRecord)]) == 1
    )
    acquisition_authority = _acquisition_authority()
    assert all(
        request.monitoring_reader_identity_id == READER_ID.casefold()
        and request.acquisition_authority_id == acquisition_authority.authority_id
        and request.acquisition_authority_digest == acquisition_authority.authority_digest
        and request.collector_contract_digest == DIGEST_C
        and request.intent_id == intent.intent_id
        and request.intent_digest == intent.intent_digest
        and request.max_rows == MAX_ACQUISITION_ROWS
        and request.max_bytes == MAX_ACQUISITION_RESPONSE_BYTES
        for request in port.requests
    )
    controls_by_id = {item.control_id: item for item in intent.controls}
    assert all(
        request.control_digest == controls_by_id[request.control_id].control_digest
        and request.scope_digest == controls_by_id[request.control_id].scope.scope_digest
        for request in port.requests
    )
    log_requests = [
        request for request in port.requests if isinstance(request, LogAnalyticsQueryRequest)
    ]
    assert all(
        request.query_digest
        == next(
            control.signal.query_digest
            for control in intent.controls
            if control.control_id == request.control_id
        )
        for request in log_requests
    )
    tampered_request = log_requests[0].model_dump(mode="python", by_alias=True)
    tampered_request["query"] = f"{tampered_request['query']} | take 1"
    with pytest.raises(ValidationError, match="requestDigest"):
        LogAnalyticsQueryRequest.model_validate(tampered_request)
    assert any("Traffic Analytics" in item for item in outcome.manual_investigation_reasons)
    assert any("IP Flow Verify" in item for item in outcome.manual_investigation_reasons)
    flow = next(
        item for item in outcome.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    assert flow.attribution_evidence is not None
    assert flow.change_correlation_id == CHANGE_CORRELATION_ID


def test_ambiguous_vm_mapping_and_truncation_degrade_coverage() -> None:
    outcome, commit, _ = _execute(
        _AcquisitionPort(
            ambiguous_vm_mapping=True,
            truncated_flow=True,
        )
    )

    assert commit.calls == 1
    endpoint_records = [
        item for item in outcome.batch.records if isinstance(item, VmConnectionHealthRecord)
    ]
    assert len(endpoint_records) == 1
    endpoint_coverage = next(
        item for item in outcome.batch.coverage if item.family == "endpointHealth"
    )
    flow_coverage = next(item for item in outcome.batch.coverage if item.family == "networkFlow")
    assert endpoint_coverage.status == "partial"
    assert endpoint_coverage.detail is not None
    assert "ambiguous" in endpoint_coverage.detail
    assert "ambiguous" in " ".join(outcome.manual_investigation_reasons)
    assert flow_coverage.status == "truncated"
    assert flow_coverage.detail is not None
    assert "Traffic Analytics is aggregated" in flow_coverage.detail
    assert "IP Flow Verify is point-in-time" in flow_coverage.detail


def test_fully_ambiguous_vm_mapping_is_unavailable_without_false_evidence() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(all_vm_mappings_ambiguous=True))

    assert commit.calls == 1
    assert not any(isinstance(item, VmConnectionHealthRecord) for item in outcome.batch.records)
    endpoint_coverage = next(
        item for item in outcome.batch.coverage if item.family == "endpointHealth"
    )
    assert endpoint_coverage.status == "unavailable"
    assert endpoint_coverage.query_execution_digests == ()
    assert endpoint_coverage.detail is not None
    assert "ambiguous" in endpoint_coverage.detail


def test_absent_data_is_unavailable_and_never_inferred_as_zero() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(absent_heartbeat=True))

    assert commit.calls == 1
    guest_coverage = next(item for item in outcome.batch.coverage if item.family == "guest")
    assert guest_coverage.status == "unavailable"
    assert guest_coverage.detail is not None
    assert "returned no data" in guest_coverage.detail
    assert not any(isinstance(item, AmaHeartbeatRecord) for item in outcome.batch.records)


def test_missing_adjacent_window_is_partial_not_complete() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(missing_current_heartbeat=True))

    assert commit.calls == 1
    guest_coverage = next(item for item in outcome.batch.coverage if item.family == "guest")
    assert guest_coverage.status == "partial"
    assert guest_coverage.detail is not None
    assert "adjacent query windows" in guest_coverage.detail


def test_absent_connection_monitor_retains_reviewed_coverage_scope() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(absent_connection_monitor=True))

    assert commit.calls == 1
    monitor_coverage = next(
        item for item in outcome.batch.coverage if item.family == "connectionMonitor"
    )
    assert monitor_coverage.status == "unavailable"
    assert monitor_coverage.endpoint_test_reference == "synthetic-web-db-test"
    assert monitor_coverage.five_tuple_digest == _five_tuple_digest()


def test_resource_health_previous_status_cannot_synthesize_transition() -> None:
    with pytest.raises(
        MonitoringAcquisitionError,
        match="exactly one unambiguous health transition",
    ):
        _execute(
            _AcquisitionPort(
                absent_heartbeat=True,
                ambiguous_vm_mapping=True,
                single_active_health=True,
            )
        )


def test_resource_health_previous_status_filter_cannot_replace_prior_evidence() -> None:
    controls = _controls()
    controls["health"] = _control(
        source_clause="/controls/resource-health",
        resources=(WEB_ID,),
        signal=ResourceHealthMonitoringSignal(
            signalKind="resourceHealth",
            maximumEventAgeSeconds=900,
            eventStatuses=("Active",),
            currentStatuses=("Unavailable",),
            previousStatuses=("Available",),
            reasonTypes=("PlatformInitiated",),
        ),
    )
    authority = _authority(controls)

    with pytest.raises(
        MonitoringAcquisitionError,
        match="exactly one unambiguous health transition",
    ):
        _execute(
            _AcquisitionPort(
                absent_heartbeat=True,
                ambiguous_vm_mapping=True,
                single_active_health=True,
            ),
            authority=authority,
        )


def test_ip_flow_verify_must_bind_the_exact_network_tuple() -> None:
    context, intent, _ = _authority()
    commit = _CommitPort()
    acquisition_authority = _acquisition_authority()
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_port=_AcquisitionPort(mismatched_ip_flow=True),
        acquisition_authority=acquisition_authority,
        expected_acquisition_authority_digest=(acquisition_authority.authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    )

    with pytest.raises(MonitoringAcquisitionError, match="exact request"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_healthy_guest_signal_does_not_block_endpoint_incident() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(healthy_heartbeat=True))

    assert commit.calls == 1
    assert outcome.batch.incident_resource_id == WEB_ID.casefold()


def test_incomplete_change_sources_cannot_support_direct_attribution() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(truncated_change=True))

    assert commit.calls == 1
    flow = next(
        item for item in outcome.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    assert flow.attribution_evidence is None
    assert flow.change_correlation_id is None
    assert any("truncated" in item for item in outcome.manual_investigation_reasons)


def test_source_failure_or_stale_response_never_enters_commit() -> None:
    context, intent, _ = _authority()
    for port, message in (
        (_AcquisitionPort(fail_resource_graph=True), "source acquisition failed"),
        (_AcquisitionPort(stale=True), "stale"),
    ):
        commit = _CommitPort()
        coordinator = MonitoringAcquisitionCoordinator(
            acquisition_port=port,
            acquisition_authority=_acquisition_authority(),
            expected_acquisition_authority_digest=(_acquisition_authority().authority_digest),
            monitoring_intent_trusted_key_id=INTENT_KEY_ID,
            monitoring_intent_signature_verifier=(
                lambda _payload, signature: signature == INTENT_SIGNATURE
            ),
            monitoring_intent_asset_loader=_intent_assets,
            collection_transaction=_transaction(),
        )
        with pytest.raises(MonitoringAcquisitionError, match=message):
            coordinator.execute(
                monitoring_intent=intent,
                context_binding=context,
                expected_active_context_authority_digest=(
                    context.publication_authority.authority_digest
                ),
                collected_at=NOW,
                collector_contract_digest=DIGEST_C,
                change_scope=_scope_contract(),
                commit_port=commit,
                incident_revision=1,
                issued_at=NOW,
                trusted_as_of=NOW + timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=10),
            )
        assert commit.calls == 0


def test_recovered_historical_outage_is_not_selected_as_current() -> None:
    context, intent, _ = _authority()
    commit = _CommitPort()
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_port=_AcquisitionPort(recovered=True),
        acquisition_authority=_acquisition_authority(),
        expected_acquisition_authority_digest=(_acquisition_authority().authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    )

    with pytest.raises(MonitoringAcquisitionError, match="exactly one unambiguous"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_activity_and_change_pairing_must_be_unique() -> None:
    context, intent, _ = _authority()
    commit = _CommitPort()
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_port=_AcquisitionPort(duplicate_activity=True),
        acquisition_authority=_acquisition_authority(),
        expected_acquisition_authority_digest=(_acquisition_authority().authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    )

    with pytest.raises(MonitoringAcquisitionError, match="pairing is not unique"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_acquisition_batch_is_deterministic_under_source_row_reordering() -> None:
    first, _, _ = _execute(_AcquisitionPort())
    second, _, _ = _execute(_AcquisitionPort(reverse_rows=True))

    assert first.batch.canonical_bytes() == second.batch.canonical_bytes()


def test_multiple_rows_from_one_query_execution_fail_closed() -> None:
    with pytest.raises(
        MonitoringAcquisitionError,
        match="multiple persisted rows for one exact query execution",
    ):
        _execute(_AcquisitionPort(multiple_current_vm_rows=True))


def test_multi_resource_query_rows_without_exact_scope_are_unavailable() -> None:
    controls = _controls()
    controls["heartbeat"] = _control(
        source_clause="/controls/heartbeat",
        resources=(WEB_ID, DB_ID),
        signal=controls["heartbeat"].signal,
    )
    outcome, commit, _ = _execute(
        _AcquisitionPort(multiple_heartbeat_rows=True),
        authority=_authority(controls),
    )

    assert commit.calls == 1
    guest_coverage = next(item for item in outcome.batch.coverage if item.family == "guest")
    assert guest_coverage.resource_ids == tuple(sorted((WEB_ID.casefold(), DB_ID.casefold())))
    assert guest_coverage.status == "unavailable"
    assert guest_coverage.query_execution_digests == ()
    assert guest_coverage.detail is not None
    assert "complete published resource scope" in guest_coverage.detail


def test_multi_resource_query_missing_subset_is_unavailable() -> None:
    controls = _controls()
    controls["heartbeat"] = _control(
        source_clause="/controls/heartbeat",
        resources=(WEB_ID, DB_ID),
        signal=controls["heartbeat"].signal,
    )
    outcome, commit, _ = _execute(
        _AcquisitionPort(),
        authority=_authority(controls),
    )

    assert commit.calls == 1
    guest_coverage = next(item for item in outcome.batch.coverage if item.family == "guest")
    assert guest_coverage.status == "unavailable"
    assert guest_coverage.detail is not None
    assert "complete published resource scope" in guest_coverage.detail


def test_current_window_scope_gap_is_unavailable_even_when_prior_window_was_complete() -> None:
    controls = _controls()
    controls["heartbeat"] = _control(
        source_clause="/controls/heartbeat",
        resources=(WEB_ID, DB_ID),
        signal=controls["heartbeat"].signal,
    )
    outcome, commit, _ = _execute(
        _AcquisitionPort(
            multiple_heartbeat_rows=True,
            missing_current_db_heartbeat=True,
        ),
        authority=_authority(controls),
    )

    assert commit.calls == 1
    guest_coverage = next(item for item in outcome.batch.coverage if item.family == "guest")
    assert guest_coverage.status == "unavailable"
    assert guest_coverage.detail is not None
    assert "complete published resource scope" in guest_coverage.detail


def test_resource_health_missing_scope_subset_is_partial() -> None:
    controls = _controls()
    controls["health"] = _control(
        source_clause="/controls/resource-health",
        resources=(WEB_ID, DB_ID),
        signal=controls["health"].signal,
    )
    authority = _authority(controls)
    outcome, commit, _ = _execute(
        _AcquisitionPort(),
        authority=authority,
    )

    assert commit.calls == 1
    health_coverage = next(
        item for item in outcome.batch.coverage if item.family == "platformHealth"
    )
    assert health_coverage.status == "partial"
    assert health_coverage.detail is not None
    assert "part of the published resource scope" in health_coverage.detail


def test_batch_version_remains_schema_v2_with_or_without_resource_health() -> None:
    with_health, _, _ = _execute(_AcquisitionPort())
    controls = _controls()
    controls.pop("health")
    without_health, _, _ = _execute(
        _AcquisitionPort(),
        authority=_authority(controls),
    )

    assert with_health.batch.schema_version == "athena.wc028MonitoringCollectionBatch.v2"
    assert without_health.batch.schema_version == "athena.wc028MonitoringCollectionBatch.v2"


def test_strict_source_schema_rejects_extra_columns() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ActivityLogRow(
            category="Administrative",
            operationName="Microsoft.Compute/virtualMachines/write",
            resultType="Succeeded",
            level="Informational",
            targetResourceId=WEB_ID,
            correlationId=CHANGE_CORRELATION_ID,
            occurredAt=NOW,
            unexpectedColumn=True,
        )


def test_signed_intent_is_verified_before_any_source_query() -> None:
    context, intent, _ = _authority()
    port = _AcquisitionPort()
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_port=port,
        acquisition_authority=_acquisition_authority(),
        expected_acquisition_authority_digest=(_acquisition_authority().authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=lambda _payload, _signature: False,
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    )

    with pytest.raises(MonitoringAcquisitionError, match="authority is invalid"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=_CommitPort(),
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert port.requests == []


def test_acquisition_authority_and_freshness_are_checked_before_reads() -> None:
    context, intent, _ = _authority()
    for expected_digest, trusted_as_of, message in (
        (
            "sha256:" + "f" * 64,
            NOW + timedelta(minutes=1),
            "configured authority",
        ),
        (
            _acquisition_authority().authority_digest,
            NOW + timedelta(hours=1),
            "freshness bound",
        ),
    ):
        port = _AcquisitionPort()
        acquisition_authority = _acquisition_authority()
        with pytest.raises(MonitoringAcquisitionError, match=message):
            coordinator = MonitoringAcquisitionCoordinator(
                acquisition_port=port,
                acquisition_authority=acquisition_authority,
                expected_acquisition_authority_digest=expected_digest,
                monitoring_intent_trusted_key_id=INTENT_KEY_ID,
                monitoring_intent_signature_verifier=(
                    lambda _payload, signature: signature == INTENT_SIGNATURE
                ),
                monitoring_intent_asset_loader=_intent_assets,
                collection_transaction=_transaction(),
            )
            coordinator.execute(
                monitoring_intent=intent,
                context_binding=context,
                expected_active_context_authority_digest=(
                    context.publication_authority.authority_digest
                ),
                collected_at=NOW,
                collector_contract_digest=DIGEST_C,
                change_scope=_scope_contract(),
                commit_port=_CommitPort(),
                incident_revision=1,
                issued_at=NOW,
                trusted_as_of=trusted_as_of,
                expires_at=trusted_as_of + timedelta(minutes=5),
            )

        assert port.requests == []


def test_acquisition_identity_must_be_separate_from_context_identity() -> None:
    with pytest.raises(ValidationError, match="must be separate"):
        _acquisition_authority(
            reader_identity_id=READER_ID,
            context_identity_id=READER_ID,
        )


@pytest.mark.parametrize(
    "port, message",
    (
        (
            _AcquisitionPort(source_identity_id=CONTEXT_ID),
            "unexpected Azure identity",
        ),
        (
            _AcquisitionPort(out_of_scope_heartbeat=True),
            "published workload resource scope",
        ),
    ),
)
def test_source_identity_and_resource_scope_are_fail_closed(
    port: _AcquisitionPort,
    message: str,
) -> None:
    context, intent, _ = _authority()
    commit = _CommitPort()
    acquisition_authority = _acquisition_authority()
    coordinator = MonitoringAcquisitionCoordinator(
        acquisition_port=port,
        acquisition_authority=acquisition_authority,
        expected_acquisition_authority_digest=(acquisition_authority.authority_digest),
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            lambda _payload, signature: signature == INTENT_SIGNATURE
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
    )

    with pytest.raises(MonitoringAcquisitionError, match=message):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            collector_contract_digest=DIGEST_C,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0
