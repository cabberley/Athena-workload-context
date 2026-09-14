from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from athena_context.contracts import (
    EvidenceCoverageScope,
    ResourceHealthMonitoringSignal,
    build_published_monitoring_intent,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.monitoring_acquisition import (
    MAX_ACQUISITION_RESPONSE_BYTES,
    MAX_ACQUISITION_ROWS,
    ActivityLogQueryRequest,
    ActivityLogQueryResult,
    ActivityLogRow,
    ConnectionMonitorRow,
    CredentialBoundMonitoringAcquisitionAdapter,
    HeartbeatRow,
    IpFlowVerifyRequest,
    IpFlowVerifyResult,
    LogAggregateCompletenessProof,
    LogAnalyticsQueryRequest,
    LogAnalyticsQueryResult,
    LogCoverageDescriptor,
    MonitoringAcquisitionAuthority,
    MonitoringAcquisitionControlBinding,
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
    compute_monitoring_acquisition_control_selection_digest,
)
from athena_context.monitoring_collection import (
    AmaHeartbeatRecord,
    MonitoringCollectionError,
    NetworkWatcherFlowRecord,
    ResourceChangeRecord,
    VmConnectionHealthRecord,
)
from test_wc024_monitoring_contract import (
    COLLECTOR_TENANT_ID,
    _acquisition_collector_contract,
)
from test_wc026_correlation_contract import (
    DB_ID,
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
)
from test_wc028_monitoring_collection import (
    _production_transaction as _transaction,
)

READER_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/athena-demo-monitoring-monitoring-collector-id"
)
CONTEXT_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-athena-demo-monitoring/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/synthetic-athena-context"
)
READER_PRINCIPAL_ID = "11111111-1111-1111-1111-111111111111"
CONTEXT_PRINCIPAL_ID = "22222222-2222-2222-2222-222222222222"
READER_CLIENT_ID = "00000000-0000-0000-0000-000000000001"
COLLECTOR_CONTRACT_DIGEST = _acquisition_collector_contract().compute_artifact_digest_value()
OUT_OF_SCOPE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-synthetic-other/providers/Microsoft.Compute/"
    "virtualMachines/synthetic-out-of-scope"
)


_TOKEN_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass(frozen=True, slots=True)
class _SyntheticAccessToken:
    token: str
    expires_on: int


class _Credential:
    def __init__(
        self,
        *,
        principal_id: str = READER_PRINCIPAL_ID,
        client_id: str = READER_CLIENT_ID,
        tenant_id: str = COLLECTOR_TENANT_ID,
        now: datetime = NOW,
        lifetime_seconds: int = 3600,
    ) -> None:
        self.principal_id = principal_id
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.now = now
        self.lifetime_seconds = lifetime_seconds
        self.calls = 0

    def get_token(self, *scopes: str, **_kwargs: object) -> _SyntheticAccessToken:
        assert len(scopes) == 1
        scope = scopes[0]
        audience = {
            "https://api.loganalytics.io/.default": "https://api.loganalytics.io",
            "https://management.azure.com/.default": "https://management.azure.com/",
        }[scope]
        self.calls += 1
        issued_at = int(self.now.timestamp())
        expires_on = issued_at + self.lifetime_seconds
        token = jwt.encode(
            {
                "aud": audience,
                "exp": expires_on,
                "iat": issued_at,
                "iss": f"https://sts.windows.net/{self.tenant_id}/",
                "nbf": issued_at,
                "oid": self.principal_id,
                "sub": self.principal_id,
                "tid": self.tenant_id,
                "appid": self.client_id,
            },
            _TOKEN_PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "synthetic-kid", "typ": "JWT"},
        )
        return _SyntheticAccessToken(token=token, expires_on=expires_on)


@pytest.fixture(autouse=True)
def _trust_synthetic_managed_identity_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class _SigningKey:
        key = _TOKEN_PRIVATE_KEY.public_key()

    class _JwkClient:
        def __init__(self, url: str, *, cache_keys: bool) -> None:
            assert url == (
                f"https://login.microsoftonline.com/{COLLECTOR_TENANT_ID}/discovery/keys"
            )
            assert cache_keys is True

        def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
            return _SigningKey()

    monkeypatch.setattr(jwt, "PyJWKClient", _JwkClient)


class _ReceiptSigner:
    def sign_preimage(self, canonical_preimage: bytes) -> str:
        assert canonical_preimage
        return base64.b64encode(b"synthetic-acquisition-receipt").decode("ascii")


def _aggregate_proof(
    request: LogAnalyticsQueryRequest,
    *,
    ingestion_complete_through: datetime | None = None,
) -> LogAggregateCompletenessProof:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028LogAggregateCompletenessProof.v1",
        "rawInputRowCount": 1,
        "ingestionCompleteThrough": (
            request.window_end if ingestion_complete_through is None else ingestion_complete_through
        ),
        "windowStart": request.window_start,
        "windowEnd": request.window_end,
        "requestDigest": request.request_digest,
        "queryDigest": request.query_digest,
    }
    return LogAggregateCompletenessProof(
        **payload,
        proofDigest=compute_artifact_digest(payload),
    )


def _acquisition_authority(
    *,
    reader_identity_id: str = READER_ID,
    reader_principal_id: str = READER_PRINCIPAL_ID,
    reader_client_id: str = READER_CLIENT_ID,
    reader_tenant_id: str = COLLECTOR_TENANT_ID,
    context_identity_id: str = CONTEXT_ID,
    context_principal_id: str = CONTEXT_PRINCIPAL_ID,
    max_freshness_seconds: int = 900,
    max_acquisition_calls: int = 32,
    required_control_ids: tuple[str, ...] | None = None,
    required_control_bindings: tuple[MonitoringAcquisitionControlBinding, ...] | None = None,
    context_binding=None,
    controls=None,
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
    if context_binding is None or controls is None:
        context_binding, _, controls = _authority()
    if required_control_bindings is None:
        required_control_bindings = _required_control_bindings(
            context_binding,
            controls,
        )
    if required_control_ids is None:
        required_control_ids = tuple(item.control_id for item in required_control_bindings)
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v3",
        "monitoringReaderIdentityId": reader_identity_id.casefold(),
        "monitoringReaderPrincipalId": reader_principal_id,
        "monitoringReaderClientId": reader_client_id,
        "monitoringReaderTenantId": reader_tenant_id,
        "athenaContextIdentityId": context_identity_id.casefold(),
        "athenaContextPrincipalId": context_principal_id,
        "collectorContractDigest": COLLECTOR_CONTRACT_DIGEST,
        "allowedSources": list(allowed_sources),
        "allowedResourceIds": list(allowed_resources),
        "requiredControlIds": list(required_control_ids),
        "requiredControlBindings": [
            item.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for item in required_control_bindings
        ],
        "contextBindingDigest": context_binding.binding_digest,
        "requiredCoverageScopeDigests": list(context_binding.required_coverage_scope_digests),
        "controlSelectionDigest": compute_monitoring_acquisition_control_selection_digest(
            context_binding,
            required_control_bindings,
        ),
        "maxRows": MAX_ACQUISITION_ROWS,
        "maxBytes": MAX_ACQUISITION_RESPONSE_BYTES,
        "maxWindowSeconds": 86400,
        "maxFreshnessSeconds": max_freshness_seconds,
        "maxAcquisitionCalls": max_acquisition_calls,
        "receiptSigningKeyId": (_acquisition_collector_contract().signing_key_resource_id),
        "monitoringReaderHasReadOnlyWorkloadAccess": True,
        "readOnly": True,
        "athenaContextHasWorkloadReader": False,
    }
    payload["deploymentIdentityContractDigest"] = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": reader_identity_id.casefold(),
            "monitoringReaderPrincipalId": reader_principal_id,
            "monitoringReaderClientId": reader_client_id,
            "monitoringReaderTenantId": reader_tenant_id,
            "athenaContextIdentityId": context_identity_id.casefold(),
            "athenaContextPrincipalId": context_principal_id,
            "monitoringReaderHasReadOnlyWorkloadAccess": True,
            "athenaContextHasWorkloadReader": False,
            "readOnly": True,
        }
    )
    digest = compute_artifact_digest(payload)
    return MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": allowed_sources,
            "allowedResourceIds": allowed_resources,
            "requiredControlIds": required_control_ids,
            "requiredControlBindings": required_control_bindings,
            "requiredCoverageScopeDigests": (context_binding.required_coverage_scope_digests),
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )


def _authority(controls=None, *, required_control_names: set[str] | None = None):
    controls = _controls() if controls is None else controls
    path = _dependency_path()
    required_values = []
    for name, control in controls.items():
        if name == "change" or (
            required_control_names is not None and name not in required_control_names
        ):
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


def _required_control_bindings(
    context,
    controls,
) -> tuple[MonitoringAcquisitionControlBinding, ...]:
    required = set(context.required_coverage_scope_digests)
    path = _dependency_path()
    selected: list[MonitoringAcquisitionControlBinding] = []
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
        digest = _coverage_scope_digest(
            control=control,
            resource_ids=control.scope.resource_ids,
            path_id=None if name == "heartbeat" else path.path_id,
            **coverage_kwargs,
        )
        if digest in required:
            scope_payload: dict[str, object] = {
                "resourceIds": tuple(
                    sorted(item.casefold() for item in control.scope.resource_ids)
                ),
                "pathId": None if name == "heartbeat" else path.path_id,
                "direction": coverage_kwargs.get("direction"),
                "fiveTupleDigest": coverage_kwargs.get("five_tuple_digest"),
                "endpointTestReference": coverage_kwargs.get("endpoint_test_reference"),
                "endpointTestDigest": coverage_kwargs.get("endpoint_test_digest"),
                "queryScopeDigest": control.control_digest,
            }
            selected.append(
                MonitoringAcquisitionControlBinding(
                    controlId=control.control_id,
                    controlDigest=control.control_digest,
                    scopeDigest=control.scope.scope_digest,
                    coverageScope=EvidenceCoverageScope(
                        **scope_payload,
                        scopeId=f"coverage-scope-{digest.removeprefix('sha256:')[:32]}",
                        scopeDigest=digest,
                    ),
                )
            )
    return tuple(sorted(selected, key=lambda item: item.control_id))


def _required_control_ids(context, controls) -> tuple[str, ...]:
    return tuple(item.control_id for item in _required_control_bindings(context, controls))


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
        unproven_current_heartbeat_zero: bool = False,
        traffic_analytics_rows: int = 1,
        backdated_ip_flow: bool = False,
        mismatched_aggregate_proof: bool = False,
        future_aggregate_proof: bool = False,
        truncated_heartbeat: bool = False,
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
        self.unproven_current_heartbeat_zero = unproven_current_heartbeat_zero
        self.traffic_analytics_rows = traffic_analytics_rows
        self.backdated_ip_flow = backdated_ip_flow
        self.mismatched_aggregate_proof = mismatched_aggregate_proof
        self.future_aggregate_proof = future_aggregate_proof
        self.truncated_heartbeat = truncated_heartbeat
        self.ip_flow_calls = 0
        self.access_token_calls = 0
        self.access_token_audiences: list[tuple[str, str]] = []
        self.requests: list[object] = []

    def _collected_at(self):
        return NOW - timedelta(minutes=1) if self.stale else NOW

    def _record_request(self, request: object, access_token: str) -> None:
        assert access_token.count(".") == 2
        claims = jwt.decode(access_token, options={"verify_signature": False})
        source = request.source  # type: ignore[attr-defined]
        audience = claims["aud"]
        assert isinstance(source, str)
        assert isinstance(audience, str)
        self.access_token_audiences.append((source, audience))
        self.access_token_calls += 1
        self.requests.append(request)

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
        *,
        access_token: str,
    ) -> LogAnalyticsQueryResult:
        self._record_request(request, access_token)
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
            traffic_row = TrafficAnalyticsRow(
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
            )
            rows = tuple(traffic_row for _ in range(self.traffic_analytics_rows))
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
        aggregate_proof = (
            None
            if request.table not in {"Heartbeat", "VMConnection"}
            or (
                request.table == "Heartbeat" and is_current and self.unproven_current_heartbeat_zero
            )
            else _aggregate_proof(
                request,
                ingestion_complete_through=(
                    NOW + timedelta(minutes=1) if self.future_aggregate_proof else None
                ),
            )
        )
        if aggregate_proof is not None and self.mismatched_aggregate_proof:
            proof_payload = aggregate_proof.model_dump(
                mode="python",
                by_alias=True,
                exclude={"proof_digest"},
            )
            proof_payload["requestDigest"] = "sha256:" + "f" * 64
            aggregate_proof = LogAggregateCompletenessProof(
                **proof_payload,
                proofDigest=compute_artifact_digest(proof_payload),
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
            aggregateCompletenessProof=aggregate_proof,
            truncated=(self.truncated_flow and request.table == "NTANetAnalytics")
            or (self.truncated_heartbeat and request.table == "Heartbeat"),
            responseBytes=4096,
            rows=rows,
        )

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
        *,
        access_token: str,
    ) -> IpFlowVerifyResult:
        self._record_request(request, access_token)
        self.ip_flow_calls += 1
        return IpFlowVerifyResult(
            schemaVersion="athena.wc028IpFlowVerifyResult.v1",
            source="ipFlowVerify",
            requestDigest=(
                "sha256:" + "0" * 64 if self.mismatched_ip_flow else request.request_digest
            ),
            sourceIdentityId=self.source_identity_id,
            collectedAt=self._collected_at(),
            checkedAt=(
                request.checked_at - timedelta(minutes=1)
                if self.backdated_ip_flow
                else request.checked_at
            ),
            access="Deny",
            ruleResourceId=NSG_RULE_ID,
            responseBytes=1024,
            limitation="pointInTimeNotHistorical",
        )

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
        *,
        access_token: str,
    ) -> ActivityLogQueryResult:
        self._record_request(request, access_token)
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
        *,
        access_token: str,
    ) -> ResourceGraphChangeQueryResult:
        self._record_request(request, access_token)
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
        *,
        access_token: str,
    ) -> ResourceHealthQueryResult:
        self._record_request(request, access_token)
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


def _adapter(
    port: _AcquisitionPort,
    *,
    credential: _Credential | None = None,
    now: datetime = NOW,
):
    return CredentialBoundMonitoringAcquisitionAdapter(
        reviewed_collector_contract=_acquisition_collector_contract(),
        acquisition_port=port,
        credential=_Credential(now=now) if credential is None else credential,
        utc_now=lambda: now,
    )


def _coordinator(
    port: _AcquisitionPort,
    authority: MonitoringAcquisitionAuthority,
    *,
    expected_authority_digest: str | None = None,
    credential: _Credential | None = None,
    now: datetime = NOW,
    signature_verifier=None,
) -> MonitoringAcquisitionCoordinator:
    return MonitoringAcquisitionCoordinator(
        acquisition_adapter=_adapter(
            port,
            credential=credential,
            now=now,
        ),
        acquisition_authority=authority,
        expected_acquisition_authority_digest=(
            authority.authority_digest
            if expected_authority_digest is None
            else expected_authority_digest
        ),
        expected_collector_contract_digest=COLLECTOR_CONTRACT_DIGEST,
        monitoring_intent_trusted_key_id=INTENT_KEY_ID,
        monitoring_intent_signature_verifier=(
            (lambda _payload, signature: signature == INTENT_SIGNATURE)
            if signature_verifier is None
            else signature_verifier
        ),
        monitoring_intent_asset_loader=_intent_assets,
        collection_transaction=_transaction(),
        receipt_signer=_ReceiptSigner(),
    )


def _execute(
    port: _AcquisitionPort,
    *,
    authority=None,
    credential: _Credential | None = None,
    now: datetime = NOW,
    collected_at: datetime = NOW,
    acquisition_authority: MonitoringAcquisitionAuthority | None = None,
):
    context, intent, controls = _authority() if authority is None else authority
    commit = _CommitPort()
    acquisition_authority = (
        _acquisition_authority(
            required_control_ids=_required_control_ids(context, controls),
            context_binding=context,
            controls=controls,
        )
        if acquisition_authority is None
        else acquisition_authority
    )
    outcome = _coordinator(
        port,
        acquisition_authority,
        credential=credential,
        now=now,
    ).execute(
        monitoring_intent=intent,
        context_binding=context,
        expected_active_context_authority_digest=(context.publication_authority.authority_digest),
        collected_at=collected_at,
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
    assert not any(isinstance(item, ResourceChangeRecord) for item in outcome.batch.records)
    context, _, controls = _authority()
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    assert all(
        request.monitoring_reader_identity_id == READER_ID.casefold()
        and request.acquisition_authority_id == acquisition_authority.authority_id
        and request.acquisition_authority_digest == acquisition_authority.authority_digest
        and request.collector_contract_digest == COLLECTOR_CONTRACT_DIGEST
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
    assert not any(
        isinstance(request, (ActivityLogQueryRequest, ResourceGraphChangeQueryRequest))
        for request in port.requests
    )
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
    assert flow.attribution_evidence is None
    assert flow.change_correlation_id is None
    assert any(
        "supporting control has no required coverage scope" in item
        for item in outcome.manual_investigation_reasons
    )
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    manifest = outcome.prepared.monitoring_bundle.acquisition_manifest
    assert receipt is not None
    assert manifest is not None
    assert (
        outcome.prepared.monitoring_bundle.schema_version
        == "athena.wc028MonitoringEvidenceBundle.v3"
    )
    assert (
        outcome.committed.monitoring_handoff.schema_version
        == "athena.wc028MonitoringEvidenceHandoff.v2"
    )
    assert receipt.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v3"
    assert receipt.authenticated_principal_id == READER_PRINCIPAL_ID
    assert receipt.authenticated_client_id == READER_CLIENT_ID
    assert receipt.authenticated_tenant_id == COLLECTOR_TENANT_ID
    assert receipt.monitoring_reader_identity_id == READER_ID.casefold()
    assert receipt.credential_proofs is not None
    assert {item.audience for item in receipt.credential_proofs} == {
        "https://api.loganalytics.io",
        "https://management.azure.com/",
    }
    assert all(
        item.principal_id == READER_PRINCIPAL_ID
        and item.client_id == READER_CLIENT_ID
        and item.tenant_id == COLLECTOR_TENANT_ID
        for item in receipt.credential_proofs
    )
    assert receipt.acquisition_authority_digest == acquisition_authority.authority_digest
    assert receipt.collection_batch_digest == sha256_hex(outcome.batch.canonical_bytes())
    assert manifest.collection_batch_digest == receipt.collection_batch_digest
    assert (
        receipt.normalized_evidence_digest
        == outcome.prepared.monitoring_bundle.compute_normalized_evidence_digest_value()
    )
    assert manifest.normalized_evidence_digest == receipt.normalized_evidence_digest
    assert manifest.exchanges == receipt.exchanges
    assert len(receipt.exchanges) == len(port.requests)
    assert port.access_token_calls == len(port.requests)
    proof_by_digest = {item.proof_digest: item for item in receipt.credential_proofs}
    assert all(item.credential_proof_digest in proof_by_digest for item in receipt.exchanges)
    assert all(
        proof_by_digest[item.credential_proof_digest].audience
        == (
            "https://api.loganalytics.io"
            if item.source == "logAnalytics"
            else "https://management.azure.com/"
        )
        for item in receipt.exchanges
    )
    assert all(
        audience
        == (
            "https://api.loganalytics.io"
            if source == "logAnalytics"
            else "https://management.azure.com/"
        )
        for source, audience in port.access_token_audiences
    )
    assert tuple(item.request_digest for item in receipt.exchanges) == tuple(
        request.request_digest for request in port.requests
    )
    ip_flow_exchange = next(item for item in receipt.exchanges if item.source == "ipFlowVerify")
    assert ip_flow_exchange.checked_at == NOW
    assert outcome.committed.monitoring_handoff.acquisition_receipt_digest == receipt.receipt_digest
    tampered_bundle = outcome.prepared.monitoring_bundle.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    tampered_manifest = tampered_bundle["acquisitionManifest"]
    assert isinstance(tampered_manifest, dict)
    tampered_manifest["collectionBatchDigest"] = "sha256:" + "f" * 64
    tampered_manifest["manifestDigest"] = compute_artifact_digest(
        {key: value for key, value in tampered_manifest.items() if key != "manifestDigest"}
    )
    with pytest.raises(ValidationError, match="does not bind the monitoring bundle"):
        type(outcome.prepared.monitoring_bundle).model_validate_json(json.dumps(tampered_bundle))
    tampered_evidence = outcome.prepared.monitoring_bundle.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    tampered_observation = tampered_evidence["observations"][0]
    assert isinstance(tampered_observation, dict)
    tampered_observation["summaryCode"] = "tamperedEvidence"
    observation_digest = compute_artifact_digest(
        {
            key: value
            for key, value in tampered_observation.items()
            if key not in {"observationId", "observationDigest"}
        }
    )
    tampered_observation["observationDigest"] = observation_digest
    tampered_observation["observationId"] = f"obs-{observation_digest.removeprefix('sha256:')[:32]}"
    tampered_evidence["observations"] = sorted(
        tampered_evidence["observations"],
        key=lambda item: item["observationId"],
    )
    with pytest.raises(ValidationError, match="does not bind the monitoring bundle"):
        type(outcome.prepared.monitoring_bundle).model_validate_json(json.dumps(tampered_evidence))


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
        item
        for item in outcome.batch.coverage
        if item.family == "endpointHealth" and item.status == "partial"
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
    guest_coverage = tuple(item for item in outcome.batch.coverage if item.family == "guest")
    current = next(item for item in guest_coverage if item.observed_end == NOW)
    prior = next(item for item in guest_coverage if item.observed_end != NOW)
    assert current.status == "unavailable"
    assert prior.status == "partial"
    assert current.detail is not None
    assert "adjacent query windows" in current.detail


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
    context, intent, controls = _authority()
    commit = _CommitPort()
    port = _AcquisitionPort(mismatched_ip_flow=True)
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, acquisition_authority)

    with pytest.raises(MonitoringAcquisitionError, match="exact request"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
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


def test_optional_change_controls_are_not_executed_or_attributed() -> None:
    port = _AcquisitionPort(
        truncated_change=True,
        duplicate_activity=True,
        fail_resource_graph=True,
    )
    outcome, commit, _ = _execute(port)

    assert commit.calls == 1
    assert not any(
        isinstance(request, (ActivityLogQueryRequest, ResourceGraphChangeQueryRequest))
        for request in port.requests
    )
    flow = next(
        item for item in outcome.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    assert flow.attribution_evidence is None
    assert flow.change_correlation_id is None
    assert any(
        "supporting control has no required coverage scope and was not executed" in item
        for item in outcome.manual_investigation_reasons
    )


def test_source_failure_never_enters_commit() -> None:
    context, intent, controls = _authority()
    commit = _CommitPort()
    port = _AcquisitionPort(stale=True)
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, acquisition_authority)
    with pytest.raises(MonitoringAcquisitionError, match="collector clock"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    assert commit.calls == 0


def test_recovered_historical_outage_is_not_selected_as_current() -> None:
    context, intent, controls = _authority()
    commit = _CommitPort()
    port = _AcquisitionPort(recovered=True)
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, acquisition_authority)

    with pytest.raises(MonitoringAcquisitionError, match="exactly one unambiguous"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
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
    context, intent, controls = _authority()
    port = _AcquisitionPort()
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(
        port,
        acquisition_authority,
        signature_verifier=lambda _payload, _signature: False,
    )

    with pytest.raises(MonitoringAcquisitionError, match="authority is invalid"):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            change_scope=_scope_contract(),
            commit_port=_CommitPort(),
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert port.requests == []


def test_acquisition_authority_and_freshness_are_checked_before_reads() -> None:
    context, intent, controls = _authority()
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    for expected_digest, trusted_as_of, message in (
        (
            "sha256:" + "f" * 64,
            NOW + timedelta(minutes=1),
            "configured authority",
        ),
        (
            acquisition_authority.authority_digest,
            NOW + timedelta(hours=1),
            "freshness bound",
        ),
    ):
        port = _AcquisitionPort()
        with pytest.raises(MonitoringAcquisitionError, match=message):
            coordinator = _coordinator(
                port,
                acquisition_authority,
                expected_authority_digest=expected_digest,
            )
            coordinator.execute(
                monitoring_intent=intent,
                context_binding=context,
                expected_active_context_authority_digest=(
                    context.publication_authority.authority_digest
                ),
                collected_at=NOW,
                change_scope=_scope_contract(),
                commit_port=_CommitPort(),
                incident_revision=1,
                issued_at=NOW,
                trusted_as_of=trusted_as_of,
                expires_at=trusted_as_of + timedelta(minutes=5),
            )

        assert port.requests == []


def test_stale_context_bound_authority_fails_before_credential_or_source_io() -> None:
    context, intent, _ = _authority()
    stale_context, _, stale_controls = _authority(
        required_control_names={"heartbeat", "endpoint", "monitor", "flow"}
    )
    stale_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(stale_context, stale_controls),
        context_binding=stale_context,
        controls=stale_controls,
    )
    credential = _Credential()
    port = _AcquisitionPort()
    coordinator = _coordinator(
        port,
        stale_authority,
        credential=credential,
    )

    with pytest.raises(
        MonitoringAcquisitionError,
        match="current context and control selection",
    ):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            change_scope=_scope_contract(),
            commit_port=_CommitPort(),
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert credential.calls == 0
    assert port.requests == []


def test_added_replaced_or_omitted_control_binding_fails_before_external_io() -> None:
    context, _, controls = _authority(
        required_control_names={"heartbeat", "endpoint", "monitor", "flow"}
    )
    authority = _acquisition_authority(
        context_binding=context,
        controls=controls,
    )
    bindings = list(authority.required_control_bindings or ())
    health = controls["health"]
    replaced_binding = bindings[0].model_copy(
        update={
            "control_id": health.control_id,
            "control_digest": health.control_digest,
            "scope_digest": health.scope.scope_digest,
        }
    )
    added = authority.model_copy(
        update={
            "required_control_ids": tuple(
                sorted((*(authority.required_control_ids or ()), health.control_id))
            ),
            "required_control_bindings": tuple(
                sorted((*bindings, replaced_binding), key=lambda item: item.control_id)
            ),
        }
    )
    omitted_binding = bindings[0]
    replaced = authority.model_copy(
        update={
            "required_control_ids": tuple(
                sorted(
                    (
                        *(
                            item
                            for item in (authority.required_control_ids or ())
                            if item != omitted_binding.control_id
                        ),
                        health.control_id,
                    )
                )
            ),
            "required_control_bindings": tuple(
                sorted(
                    (*bindings[1:], replaced_binding),
                    key=lambda item: item.control_id,
                )
            ),
        }
    )
    omitted = authority.model_copy(
        update={
            "required_control_ids": tuple(
                item
                for item in (authority.required_control_ids or ())
                if item != omitted_binding.control_id
            ),
            "required_control_bindings": tuple(bindings[1:]),
        }
    )

    for invalid in (added, replaced, omitted):
        credential = _Credential()
        port = _AcquisitionPort()
        with pytest.raises(
            MonitoringAcquisitionError,
            match="control binding coverage|required control bindings",
        ):
            _coordinator(
                port,
                invalid,
                credential=credential,
            )
        assert credential.calls == 0
        assert port.requests == []


def test_incorrect_ip_flow_permission_contract_fails_before_external_io() -> None:
    reviewed = _acquisition_collector_contract()
    invalid = reviewed.model_copy(
        update={
            "ip_flow_verify_allowed_operations": (
                "Microsoft.Network/networkWatchers/ipFlowVerify/read",
                "Microsoft.Network/networkWatchers/ipFlowVerify/read",
            )
        }
    )
    credential = _Credential()
    port = _AcquisitionPort()

    with pytest.raises(ValidationError, match="IP Flow Verify operations"):
        CredentialBoundMonitoringAcquisitionAdapter(
            reviewed_collector_contract=invalid,
            acquisition_port=port,
            credential=credential,
            utc_now=lambda: NOW,
        )

    assert credential.calls == 0
    assert port.requests == []


def test_acquisition_identity_must_be_separate_from_context_identity() -> None:
    with pytest.raises(ValidationError, match="must be separate"):
        _acquisition_authority(
            reader_identity_id=READER_ID,
            context_identity_id=READER_ID,
        )


def test_legacy_acquisition_authority_remains_readable_but_not_executable() -> None:
    payload = _acquisition_authority().model_dump(
        mode="json",
        by_alias=True,
        exclude={
            "authority_id",
            "authority_digest",
            "max_acquisition_calls",
            "receipt_signing_key_id",
            "monitoring_reader_has_read_only_workload_access",
            "deployment_identity_contract_digest",
            "monitoring_reader_principal_id",
            "monitoring_reader_client_id",
            "monitoring_reader_tenant_id",
            "athena_context_principal_id",
            "required_control_ids",
            "required_control_bindings",
            "context_binding_digest",
            "required_coverage_scope_digests",
            "control_selection_digest",
        },
    )
    payload["schemaVersion"] = "athena.wc028MonitoringAcquisitionAuthority.v1"
    digest = compute_artifact_digest(payload)
    payload["allowedSources"] = tuple(payload["allowedSources"])
    payload["allowedResourceIds"] = tuple(payload["allowedResourceIds"])
    authority = MonitoringAcquisitionAuthority(
        **payload,
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )

    assert authority.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v1"
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v3"):
        _coordinator(_AcquisitionPort(), authority)


def test_v2_acquisition_authority_remains_readable_but_not_executable() -> None:
    current = _acquisition_authority()
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude={
            "authority_id",
            "authority_digest",
            "monitoring_reader_client_id",
            "monitoring_reader_tenant_id",
            "context_binding_digest",
            "required_coverage_scope_digests",
            "required_control_bindings",
            "control_selection_digest",
        },
    )
    payload["schemaVersion"] = "athena.wc028MonitoringAcquisitionAuthority.v2"
    payload["deploymentIdentityContractDigest"] = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": current.monitoring_reader_identity_id,
            "monitoringReaderPrincipalId": current.monitoring_reader_principal_id,
            "athenaContextIdentityId": current.athena_context_identity_id,
            "athenaContextPrincipalId": current.athena_context_principal_id,
            "monitoringReaderHasReadOnlyWorkloadAccess": True,
            "athenaContextHasWorkloadReader": False,
            "readOnly": True,
        }
    )
    digest = compute_artifact_digest(payload)
    payload["allowedSources"] = tuple(payload["allowedSources"])
    payload["allowedResourceIds"] = tuple(payload["allowedResourceIds"])
    payload["requiredControlIds"] = tuple(payload["requiredControlIds"])
    authority = MonitoringAcquisitionAuthority(
        **payload,
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )

    assert authority.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v2"
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v3"):
        _coordinator(_AcquisitionPort(), authority)


def test_forged_port_identity_cannot_override_authenticated_principal() -> None:
    port = _AcquisitionPort(source_identity_id=CONTEXT_ID)
    with pytest.raises(
        MonitoringAcquisitionError,
        match="conflicts with the authenticated principal",
    ):
        _execute(port)


@pytest.mark.parametrize(
    "credential",
    (
        _Credential(principal_id=CONTEXT_PRINCIPAL_ID),
        _Credential(client_id="33333333-3333-3333-3333-333333333333"),
        _Credential(tenant_id="44444444-4444-4444-4444-444444444444"),
    ),
)
def test_alternate_credential_is_fail_closed_before_reads(
    credential: _Credential,
) -> None:
    port = _AcquisitionPort()
    with pytest.raises(
        MonitoringAcquisitionError,
        match=("does not match the reviewed collector identity|cryptographic verification failed"),
    ):
        _execute(
            port,
            credential=credential,
        )
    assert port.requests == []


def test_managed_identity_day_lifetime_is_accepted_and_bound() -> None:
    outcome, commit, _ = _execute(
        _AcquisitionPort(),
        credential=_Credential(lifetime_seconds=24 * 60 * 60),
    )

    assert commit.calls == 1
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert receipt.credential_proofs is not None
    assert all(
        (item.expires_at - item.issued_at).total_seconds() == 24 * 60 * 60
        for item in receipt.credential_proofs
    )


def test_caller_collection_time_cannot_backdate_collector_receipt() -> None:
    outcome, commit, _ = _execute(
        _AcquisitionPort(),
        now=NOW,
        collected_at=NOW - timedelta(minutes=5),
    )

    assert commit.calls == 1
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert receipt.execution_started_at == NOW
    assert outcome.batch.collected_at == NOW


def test_backdated_ip_flow_result_is_rejected() -> None:
    port = _AcquisitionPort(backdated_ip_flow=True)
    with pytest.raises(MonitoringAcquisitionError, match="IP Flow Verify response is stale"):
        _execute(port)
    assert port.ip_flow_calls == 1


def test_unproven_empty_aggregate_is_unavailable_not_healthy() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(unproven_current_heartbeat_zero=True))

    assert commit.calls == 1
    assert not any(
        isinstance(item, AmaHeartbeatRecord) and item.observed_end == NOW
        for item in outcome.batch.records
    )
    current_guest_coverage = next(
        item
        for item in outcome.batch.coverage
        if item.family == "guest" and item.observed_end == NOW
    )
    assert current_guest_coverage.status == "unavailable"
    assert current_guest_coverage.detail is not None
    assert "aggregate zero lacked positive raw-input" in current_guest_coverage.detail


def test_aggregate_completeness_proof_cannot_be_reused_for_another_request() -> None:
    with pytest.raises(
        MonitoringAcquisitionError,
        match="exact query execution",
    ):
        _execute(_AcquisitionPort(mismatched_aggregate_proof=True))


def test_truncated_zero_aggregate_is_not_persisted_as_health_evidence() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(truncated_heartbeat=True))

    assert commit.calls == 1
    assert not any(
        isinstance(item, AmaHeartbeatRecord)
        and item.observed_end == NOW
        and item.heartbeat_count == 0
        for item in outcome.batch.records
    )
    current_guest_coverage = next(
        item
        for item in outcome.batch.coverage
        if item.family == "guest" and item.observed_end == NOW
    )
    assert current_guest_coverage.status == "unavailable"


def test_future_aggregate_ingestion_proof_is_unavailable_not_healthy() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort(future_aggregate_proof=True))

    assert commit.calls == 1
    assert not any(
        isinstance(item, AmaHeartbeatRecord)
        and item.observed_end == NOW
        and item.heartbeat_count == 0
        for item in outcome.batch.records
    )
    current_guest_coverage = next(
        item
        for item in outcome.batch.coverage
        if item.family == "guest" and item.observed_end == NOW
    )
    assert current_guest_coverage.status == "unavailable"
    assert current_guest_coverage.detail is not None
    assert "aggregate zero lacked positive raw-input" in current_guest_coverage.detail


def test_optional_control_is_not_called_or_allowed_to_select_incident() -> None:
    authority = _authority(required_control_names={"heartbeat", "endpoint", "monitor", "flow"})
    outcome, commit, _ = _execute(_AcquisitionPort(), authority=authority)

    assert commit.calls == 1
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert all(item.source != "resourceHealth" for item in receipt.exchanges)
    assert all(item.family != "platformHealth" for item in outcome.batch.coverage)


def test_transaction_rejects_receipt_replay_with_altered_batch() -> None:
    outcome, _, intent = _execute(_AcquisitionPort())
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    context, _, _ = _authority()
    altered_records = tuple(
        item.model_copy(update={"failed_connection_count": 999})
        if isinstance(item, VmConnectionHealthRecord)
        else item
        for item in outcome.batch.records
    )
    altered_batch = outcome.batch.model_copy(update={"records": altered_records})

    with pytest.raises(
        MonitoringCollectionError,
        match="does not bind its trusted execution",
    ):
        _transaction().prepare(
            altered_batch,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=COLLECTOR_CONTRACT_DIGEST,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=1),
            acquisition_receipt=receipt,
        )


def test_production_transaction_rejects_unsigned_direct_bypass() -> None:
    outcome, _, intent = _execute(_AcquisitionPort())
    context, _, _ = _authority()

    with pytest.raises(MonitoringCollectionError, match="requires a signed acquisition receipt"):
        _transaction().prepare(
            outcome.batch,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=COLLECTOR_CONTRACT_DIGEST,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=1),
        )


def test_production_transaction_rejects_forged_receipt_signature() -> None:
    outcome, _, intent = _execute(_AcquisitionPort())
    context, _, _ = _authority()
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    forged = receipt.model_copy(
        update={
            "collector_attestation": receipt.collector_attestation.model_copy(
                update={"signature": base64.b64encode(b"forged").decode("ascii")}
            )
        }
    )

    with pytest.raises(MonitoringCollectionError, match="cryptographic verification failed"):
        _transaction().prepare(
            outcome.batch,
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collector_contract_digest=COLLECTOR_CONTRACT_DIGEST,
            change_scope=_scope_contract(),
            trusted_as_of=NOW + timedelta(minutes=1),
            acquisition_receipt=forged,
        )


def test_traffic_analytics_cardinality_is_rejected_before_ip_flow_calls() -> None:
    port = _AcquisitionPort(traffic_analytics_rows=500)
    with pytest.raises(
        MonitoringAcquisitionError,
        match="Traffic Analytics returned multiple rows",
    ):
        _execute(port)
    assert port.ip_flow_calls == 0
    assert len(port.requests) <= 32


def test_total_acquisition_call_budget_fails_before_extra_read() -> None:
    port = _AcquisitionPort()
    with pytest.raises(
        MonitoringAcquisitionError,
        match="total call budget",
    ):
        _execute(
            port,
            acquisition_authority=_acquisition_authority(max_acquisition_calls=1),
        )
    assert len(port.requests) == 1


@pytest.mark.parametrize(
    "port, message",
    (
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
    context, intent, controls = _authority()
    commit = _CommitPort()
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, acquisition_authority)

    with pytest.raises(MonitoringAcquisitionError, match=message):
        coordinator.execute(
            monitoring_intent=intent,
            context_binding=context,
            expected_active_context_authority_digest=(
                context.publication_authority.authority_digest
            ),
            collected_at=NOW,
            change_scope=_scope_contract(),
            commit_port=commit,
            incident_revision=1,
            issued_at=NOW,
            trusted_as_of=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    assert commit.calls == 0
