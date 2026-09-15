from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
import pytest
from azure.identity import DefaultAzureCredential
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

import athena_context.monitoring_acquisition as monitoring_acquisition_module
from athena_context.contracts import (
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    CorrelationRequest,
    EvidenceCoverageScope,
    IncidentHealthTransition,
    MonitoringCollectorContract,
    NetworkFlowObservation,
    ResourceHealthMonitoringSignal,
    build_published_monitoring_intent,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.correlation.verification import (
    TrustedMonitoringHandoffVerifier,
    _verify_collector_incident_selection,
)
from athena_context.monitoring_acquisition import (
    MAX_ACQUISITION_RESPONSE_BYTES,
    MAX_ACQUISITION_ROWS,
    ActivityLogQueryRequest,
    ActivityLogQueryResult,
    ActivityLogRow,
    AzureMonitoringAdapter,
    ConnectionMonitorRow,
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
from athena_context.monitoring_incident import build_selected_incident
from test_wc024_monitoring_contract import (
    COLLECTOR_TENANT_ID,
    _acquisition_collector_contract,
)
from test_wc026_correlation import _test_service
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


class _SyntheticClock:
    now = NOW


class _SyntheticJwks:
    advance_clock_seconds = 0


class _SyntheticJwt:
    advance_clock_seconds = 0


class _SyntheticClaims:
    advance_clock_seconds = 0


@dataclass(frozen=True, slots=True)
class _SyntheticAccessToken:
    token: str
    expires_on: int


class _SyntheticManagedIdentityCredential:
    instances: list[_SyntheticManagedIdentityCredential] = []
    claim_overrides: dict[str, object] = {}
    lifetime_seconds = 3600
    advance_clock_seconds = 0

    def __init__(self, *, client_id: str) -> None:
        assert client_id == READER_CLIENT_ID
        self.client_id = client_id
        self.calls = 0
        self.instances.append(self)

    def get_token(self, *scopes: str, **_kwargs: object) -> _SyntheticAccessToken:
        assert scopes == (f"{MONITORING_IDENTITY_PROOF_AUDIENCE}/.default",)
        self.calls += 1
        issued_at = int(NOW.timestamp())
        expires_on = issued_at + self.lifetime_seconds
        claims: dict[str, object] = {
            "aud": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "exp": expires_on,
            "iat": issued_at,
            "idtyp": "app",
            "iss": f"https://sts.windows.net/{COLLECTOR_TENANT_ID}/",
            "nbf": issued_at,
            "oid": READER_PRINCIPAL_ID,
            "roles": [MONITORING_IDENTITY_PROOF_REQUIRED_ROLE],
            "sub": READER_PRINCIPAL_ID,
            "tid": COLLECTOR_TENANT_ID,
            "ver": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "appid": self.client_id,
        }
        claims.update(self.claim_overrides)
        token = jwt.encode(
            claims,
            _TOKEN_PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "synthetic-kid", "typ": "JWT"},
        )
        _SyntheticClock.now += timedelta(seconds=self.advance_clock_seconds)
        return _SyntheticAccessToken(token=token, expires_on=expires_on)


@pytest.fixture(autouse=True)
def _trust_synthetic_managed_identity_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _SyntheticManagedIdentityCredential.instances.clear()
    _SyntheticManagedIdentityCredential.claim_overrides = {}
    _SyntheticManagedIdentityCredential.lifetime_seconds = 3600
    _SyntheticManagedIdentityCredential.advance_clock_seconds = 0
    _SyntheticClock.now = NOW
    _SyntheticJwks.advance_clock_seconds = 0
    _SyntheticJwt.advance_clock_seconds = 0
    _SyntheticClaims.advance_clock_seconds = 0

    class _SigningKey:
        key = _TOKEN_PRIVATE_KEY.public_key()

    class _JwkClient:
        def __init__(self, url: str, *, cache_keys: bool) -> None:
            assert url == (
                f"https://login.microsoftonline.com/{COLLECTOR_TENANT_ID}/discovery/keys"
            )
            assert cache_keys is True

        def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
            _SyntheticClock.now += timedelta(seconds=_SyntheticJwks.advance_clock_seconds)
            return _SigningKey()

    monkeypatch.setattr(jwt, "PyJWKClient", _JwkClient)
    original_decode = jwt.decode

    def _decode(*args, **kwargs):
        result = original_decode(*args, **kwargs)
        _SyntheticClock.now += timedelta(seconds=_SyntheticJwt.advance_clock_seconds)
        return result

    monkeypatch.setattr(jwt, "decode", _decode)
    original_claim_validator = monitoring_acquisition_module._validated_identity_claims

    def _validate_claims(*args, **kwargs):
        result = original_claim_validator(*args, **kwargs)
        _SyntheticClock.now += timedelta(seconds=_SyntheticClaims.advance_clock_seconds)
        return result

    monkeypatch.setattr(
        monitoring_acquisition_module,
        "_validated_identity_claims",
        _validate_claims,
    )
    monkeypatch.setattr(
        monitoring_acquisition_module,
        "ManagedIdentityCredential",
        _SyntheticManagedIdentityCredential,
    )
    monkeypatch.setattr(
        monitoring_acquisition_module,
        "_system_utc_now",
        lambda: _SyntheticClock.now,
    )


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
    collector_contract=None,
) -> MonitoringAcquisitionAuthority:
    if context_binding is None or controls is None:
        context_binding, _, controls = _authority()
    if required_control_bindings is None:
        required_control_bindings = _required_control_bindings(
            context_binding,
            controls,
        )
    if required_control_ids is None:
        required_control_ids = tuple(item.control_id for item in required_control_bindings)
    contract = (
        _acquisition_collector_contract() if collector_contract is None else collector_contract
    )
    controls_by_id = {item.control_id: item for item in controls.values()}
    selected_controls = tuple(controls_by_id[control_id] for control_id in required_control_ids)
    allowed_sources, allowed_resources = (
        monitoring_acquisition_module._required_control_authority_scope(
            selected_controls,
            contract,
        )
    )
    effective_rbac_inventory = contract.effective_rbac_inventory
    assert effective_rbac_inventory is not None
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v5",
        "monitoringReaderIdentityId": reader_identity_id.casefold(),
        "monitoringReaderPrincipalId": reader_principal_id,
        "monitoringReaderClientId": reader_client_id,
        "monitoringReaderTenantId": reader_tenant_id,
        "athenaContextIdentityId": context_identity_id.casefold(),
        "athenaContextPrincipalId": context_principal_id,
        "collectorContractDigest": contract.compute_artifact_digest_value(),
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
        "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
        "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        "identityProofMaximumLifetimeSeconds": (MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS),
        "maxRows": MAX_ACQUISITION_ROWS,
        "maxBytes": MAX_ACQUISITION_RESPONSE_BYTES,
        "maxWindowSeconds": 86400,
        "maxFreshnessSeconds": max_freshness_seconds,
        "maxAcquisitionCalls": max_acquisition_calls,
        "receiptSigningKeyId": contract.signing_key_resource_id,
        "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
        "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
    }
    payload["deploymentIdentityContractDigest"] = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": reader_identity_id.casefold(),
            "monitoringReaderPrincipalId": reader_principal_id,
            "monitoringReaderClientId": reader_client_id,
            "monitoringReaderTenantId": reader_tenant_id,
            "athenaContextIdentityId": context_identity_id.casefold(),
            "athenaContextPrincipalId": context_principal_id,
            "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
            "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
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
        traffic_direction: str = "inbound",
        traffic_protocol: str = "Tcp",
        traffic_destination_port: int = 1433,
        traffic_destination_resource_id: str = DB_ID,
        traffic_enforcement_resource_id: str = NSG_ID,
        traffic_rule_resource_id: str | None = NSG_RULE_ID,
        ip_flow_access: str = "Deny",
        ip_flow_rule_resource_id: str | None = NSG_RULE_ID,
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
        self.traffic_direction = traffic_direction
        self.traffic_protocol = traffic_protocol
        self.traffic_destination_port = traffic_destination_port
        self.traffic_destination_resource_id = traffic_destination_resource_id
        self.traffic_enforcement_resource_id = traffic_enforcement_resource_id
        self.traffic_rule_resource_id = traffic_rule_resource_id
        self.ip_flow_access = ip_flow_access
        self.ip_flow_rule_resource_id = ip_flow_rule_resource_id
        self.backdated_ip_flow = backdated_ip_flow
        self.mismatched_aggregate_proof = mismatched_aggregate_proof
        self.future_aggregate_proof = future_aggregate_proof
        self.truncated_heartbeat = truncated_heartbeat
        self.ip_flow_calls = 0
        self.requests: list[object] = []
        self.azure_client_credentials: list[object] = []
        self.azure_client_contracts: list[object] = []

    def _collected_at(self):
        return NOW - timedelta(minutes=1) if self.stale else NOW

    def _record_request(self, request: object) -> None:
        self.requests.append(request)

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult:
        self._record_request(request)
        assert request.collector_execution_time is not None
        assert request.coverage_scope is not None
        is_current = request.window_end == request.collector_execution_time
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
                direction=self.traffic_direction,
                protocol=self.traffic_protocol,
                sourceResourceCandidates=(WEB_ID,),
                destinationResourceCandidates=(self.traffic_destination_resource_id,),
                sourceAddress="192.0.2.10",
                destinationAddress="192.0.2.20",
                sourcePort=443,
                destinationPort=self.traffic_destination_port,
                enforcementResourceId=self.traffic_enforcement_resource_id,
                ruleResourceId=self.traffic_rule_resource_id,
                trafficAnalyticsLimitation="aggregatedNotPacketCausal",
                observedStart=request.window_start,
                observedEnd=request.window_end,
            )
            rows = tuple(traffic_row for _ in range(self.traffic_analytics_rows))
        coverage_descriptor = LogCoverageDescriptor(
            resourceIds=request.coverage_scope.resource_ids,
            pathId=request.coverage_scope.path_id,
            direction=request.coverage_scope.direction,
            fiveTupleDigest=request.coverage_scope.five_tuple_digest,
            endpointTestReference=request.coverage_scope.endpoint_test_reference,
            endpointTestDigest=request.coverage_scope.endpoint_test_digest,
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
                    request.collector_execution_time + timedelta(minutes=1)
                    if self.future_aggregate_proof
                    else None
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
            collectedAt=(
                request.collector_execution_time - timedelta(minutes=1)
                if self.stale
                else request.collector_execution_time
            ),
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
    ) -> IpFlowVerifyResult:
        self._record_request(request)
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
            correlationRequestId="93e948cc-df1e-4caf-8a91-c31aa3803793",
            access=self.ip_flow_access,
            ruleResourceId=self.ip_flow_rule_resource_id,
            responseBytes=1024,
            limitation="pointInTimeNotHistorical",
        )

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult:
        self._record_request(request)
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
        self._record_request(request)
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
        self._record_request(request)
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


class _SyntheticAzureClient:
    def __init__(
        self,
        *,
        port: _AcquisitionPort,
        credential: object,
        reviewed_contract: object,
    ) -> None:
        self.port = port
        port.azure_client_credentials.append(credential)
        port.azure_client_contracts.append(reviewed_contract)

    def query_log_analytics(
        self,
        request: LogAnalyticsQueryRequest,
    ) -> LogAnalyticsQueryResult:
        return self.port.query_log_analytics(request)

    def query_activity_log(
        self,
        request: ActivityLogQueryRequest,
    ) -> ActivityLogQueryResult:
        return self.port.query_activity_log(request)

    def query_resource_graph_changes(
        self,
        request: ResourceGraphChangeQueryRequest,
    ) -> ResourceGraphChangeQueryResult:
        return self.port.query_resource_graph_changes(request)

    def query_resource_health(
        self,
        request: ResourceHealthQueryRequest,
    ) -> ResourceHealthQueryResult:
        return self.port.query_resource_health(request)

    def query_ip_flow_verify(
        self,
        request: IpFlowVerifyRequest,
    ) -> IpFlowVerifyResult:
        return self.port.query_ip_flow_verify(request)


def _synthetic_client_factory(port: _AcquisitionPort):
    def create_clients(credential, reviewed_contract):
        clients = tuple(
            _SyntheticAzureClient(
                port=port,
                credential=credential,
                reviewed_contract=reviewed_contract,
            )
            for _ in range(5)
        )
        return monitoring_acquisition_module._AzureMonitoringClients(
            log_analytics=clients[0],
            activity_log=clients[1],
            resource_graph=clients[2],
            resource_health=clients[3],
            ip_flow_verify=clients[4],
        )

    return create_clients


def _adapter(
    port: _AcquisitionPort,
    *,
    collector_contract=None,
):
    adapter = AzureMonitoringAdapter(
        reviewed_collector_contract=(
            _acquisition_collector_contract() if collector_contract is None else collector_contract
        ),
    )
    adapter._client_factory = _synthetic_client_factory(port)
    return adapter


def _coordinator(
    port: _AcquisitionPort,
    authority: MonitoringAcquisitionAuthority,
    *,
    expected_authority_digest: str | None = None,
    signature_verifier=None,
    collector_contract=None,
) -> MonitoringAcquisitionCoordinator:
    reviewed_contract = (
        _acquisition_collector_contract() if collector_contract is None else collector_contract
    )
    return MonitoringAcquisitionCoordinator(
        acquisition_adapter=_adapter(
            port,
            collector_contract=reviewed_contract,
        ),
        acquisition_authority=authority,
        expected_acquisition_authority_digest=(
            authority.authority_digest
            if expected_authority_digest is None
            else expected_authority_digest
        ),
        expected_collector_contract_digest=(reviewed_contract.compute_artifact_digest_value()),
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
    collected_at: datetime = NOW,
    acquisition_authority: MonitoringAcquisitionAuthority | None = None,
    collector_contract=None,
):
    context, intent, controls = _authority() if authority is None else authority
    commit = _CommitPort()
    acquisition_authority = (
        _acquisition_authority(
            required_control_ids=_required_control_ids(context, controls),
            context_binding=context,
            controls=controls,
            collector_contract=collector_contract,
        )
        if acquisition_authority is None
        else acquisition_authority
    )
    outcome = _coordinator(
        port,
        acquisition_authority,
        collector_contract=collector_contract,
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
    effective_rbac_inventory = _acquisition_collector_contract().effective_rbac_inventory
    assert effective_rbac_inventory is not None
    assert acquisition_authority.schema_version == ("athena.wc028MonitoringAcquisitionAuthority.v5")
    assert acquisition_authority.read_only is None
    assert acquisition_authority.athena_context_has_workload_reader is None
    assert acquisition_authority.monitoring_reader_has_read_only_workload_access is None
    assert (
        acquisition_authority.effective_rbac_inventory_digest
        == effective_rbac_inventory.inventory_digest
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
    bindings_by_id = {
        item.control_id: item for item in (acquisition_authority.required_control_bindings or ())
    }
    assert all(
        request.schema_version == "athena.wc028LogAnalyticsQueryRequest.v2"
        and request.collector_execution_time == NOW
        and request.coverage_scope == bindings_by_id[request.control_id].coverage_scope
        for request in log_requests
    )
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
    assert flow.ip_flow_provenance is not None
    assert flow.ip_flow_provenance.causal_change_correlation_id is None
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
    assert outcome.correlation_request.schema_version == "athena.wc028CorrelationRequest.v4"
    assert receipt.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v5"
    assert receipt.selected_incident is not None
    assert receipt.selected_incident.incident_resource_id == (outcome.batch.incident_resource_id)
    assert receipt.selected_incident.previous_record_id == (
        outcome.batch.previous_health_source_record_id
    )
    assert (
        receipt.selected_incident.current_record_ids
        == outcome.batch.current_health_source_record_ids
    )
    assert outcome.correlation_request.selected_incident == receipt.selected_incident
    assert receipt.authenticated_principal_id == READER_PRINCIPAL_ID
    assert receipt.authenticated_client_id == READER_CLIENT_ID
    assert receipt.authenticated_tenant_id == COLLECTOR_TENANT_ID
    assert receipt.monitoring_reader_identity_id == READER_ID.casefold()
    assert receipt.identity_proof is not None
    assert receipt.identity_proof.principal_id == READER_PRINCIPAL_ID
    assert receipt.identity_proof.client_id == READER_CLIENT_ID
    assert receipt.identity_proof.tenant_id == COLLECTOR_TENANT_ID
    assert receipt.identity_proof.audience == MONITORING_IDENTITY_PROOF_AUDIENCE
    assert receipt.identity_proof.token_version == MONITORING_IDENTITY_PROOF_TOKEN_VERSION
    assert receipt.identity_proof.identity_type == "app"
    assert receipt.identity_proof.roles == (MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,)
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
    assert all(
        item.identity_proof_digest == receipt.identity_proof.proof_digest
        for item in receipt.exchanges
    )
    assert tuple(item.request_digest for item in receipt.exchanges) == tuple(
        request.request_digest for request in port.requests
    )
    ip_flow_exchange = next(item for item in receipt.exchanges if item.source == "ipFlowVerify")
    ip_flow_request = next(item for item in port.requests if isinstance(item, IpFlowVerifyRequest))
    assert ip_flow_exchange.checked_at == NOW
    assert ip_flow_request.target_resource_id == DB_ID.casefold()
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


def test_signed_receipt_blocks_recomputed_alternate_incident_anchor() -> None:
    outcome, _, _ = _execute(_AcquisitionPort())
    request = outcome.correlation_request
    selected_previous_id = request.incident_anchor.previous_state_evidence[0].evidence_id
    alternate_previous = next(
        citation
        for citation in request.evidence_index
        if citation.evidence_id != selected_previous_id
        and citation.summary_code.endswith("healthy")
        and request.incident_anchor.affected_resource_id in citation.resource_ids
        and citation.observed_end <= request.incident_anchor.observed_start
    )
    transition_payload = request.incident_anchor.model_dump(
        mode="python",
        by_alias=True,
        exclude={"transition_id", "transition_digest"},
    )
    transition_payload["previousStateEvidence"] = (alternate_previous,)
    transition_digest = compute_artifact_digest(
        monitoring_acquisition_module._json_value(transition_payload)
    )
    alternate_transition = IncidentHealthTransition.model_validate(
        {
            **transition_payload,
            "transitionId": (f"transition-{transition_digest.removeprefix('sha256:')[:32]}"),
            "transitionDigest": transition_digest,
        }
    )
    request_payload = request.model_dump(
        mode="python",
        by_alias=True,
        exclude={"request_id", "request_digest"},
    )
    request_payload["incidentAnchor"] = alternate_transition
    request_digest = compute_artifact_digest(
        monitoring_acquisition_module._json_value(request_payload)
    )
    tampered_request = CorrelationRequest.model_validate(
        {
            **request_payload,
            "requestId": f"request-{request_digest.removeprefix('sha256:')[:32]}",
            "requestDigest": request_digest,
        }
    )

    with pytest.raises(
        ValueError,
        match="does not match signed selectedIncident",
    ):
        _test_service(tampered_request).correlate(tampered_request)


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected_error"),
    (
        (
            "incident_resource_id",
            DB_ID.casefold(),
            "reconstructed incident",
        ),
        (
            "previous_record_id",
            "tampered-previous-record",
            "record ID must resolve",
        ),
        (
            "current_record_ids",
            ("tampered-current-record",),
            "record ID must resolve",
        ),
        (
            "current_state",
            "degraded",
            "reconstructed incident",
        ),
        (
            "transition_digest",
            "sha256:" + "f" * 64,
            "reconstructed incident",
        ),
    ),
)
def test_every_selected_incident_field_is_independently_tamper_evident(
    field_name: str,
    replacement: object,
    expected_error: str,
) -> None:
    outcome, _, _ = _execute(_AcquisitionPort())
    request = outcome.correlation_request
    assert request.selected_incident is not None
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    selected_values = {
        "incident_resource_id": request.selected_incident.incident_resource_id,
        "previous_record_id": request.selected_incident.previous_record_id,
        "current_record_ids": request.selected_incident.current_record_ids,
        "current_state": request.selected_incident.current_state,
    }
    if field_name == "transition_digest":
        tampered_selection = request.selected_incident.model_copy(update={field_name: replacement})
    else:
        selected_values[field_name] = replacement
        rebuilt = build_selected_incident(
            incident_resource_id=selected_values["incident_resource_id"],
            previous_record_id=selected_values["previous_record_id"],
            current_record_ids=selected_values["current_record_ids"],
            current_state=selected_values["current_state"],
        )
        tampered_selection = request.selected_incident.model_copy(
            update={
                "incident_resource_id": rebuilt.incident_resource_id,
                "previous_record_id": rebuilt.previous_record_id,
                "current_record_ids": rebuilt.current_record_ids,
                "current_state": rebuilt.current_state,
                "transition_digest": rebuilt.transition_digest,
            }
        )
    tampered_request = request.model_copy(update={"selected_incident": tampered_selection})
    tampered_receipt = receipt.model_copy(update={"selected_incident": tampered_selection})

    with pytest.raises(ValueError, match=expected_error):
        _verify_collector_incident_selection(
            tampered_request,
            tampered_receipt,
        )


def test_correlation_revalidates_persisted_observation_contract_scope() -> None:
    outcome, _, intent = _execute(_AcquisitionPort())
    bundle = outcome.prepared.monitoring_bundle
    flow = next(item for item in bundle.observations if isinstance(item, NetworkFlowObservation))
    tampered_flow = flow.model_copy(update={"source_resource_id": OUT_OF_SCOPE_ID.casefold()})
    tampered_bundle = bundle.model_copy(
        update={
            "observations": tuple(
                sorted(
                    (
                        tampered_flow if item.observation_id == flow.observation_id else item
                        for item in bundle.observations
                    ),
                    key=lambda item: item.observation_id,
                )
            )
        }
    )
    verifier = object.__new__(TrustedMonitoringHandoffVerifier)
    object.__setattr__(
        verifier,
        "reviewed_contract",
        _acquisition_collector_contract(),
    )

    with pytest.raises(ValueError, match="escapes collector scopes"):
        verifier.verify_persisted_scope(tampered_bundle, intent)


def test_production_adapter_passes_one_managed_identity_object_to_every_client() -> None:
    adapter = AzureMonitoringAdapter(
        reviewed_collector_contract=_acquisition_collector_contract(),
    )

    proof = adapter.verify_identity()

    assert proof.client_id == READER_CLIENT_ID
    assert len(_SyntheticManagedIdentityCredential.instances) == 1
    credential = _SyntheticManagedIdentityCredential.instances[0]
    clients = adapter._clients
    assert clients is not None
    client_values = (
        clients.log_analytics,
        clients.activity_log,
        clients.resource_graph,
        clients.resource_health,
        clients.ip_flow_verify,
    )
    assert [item._credential for item in client_values] == [credential] * 5
    assert [item._reviewed_contract for item in client_values] == [
        adapter.reviewed_collector_contract
    ] * 5


def test_production_adapter_refreshes_identity_proof_for_each_execution() -> None:
    adapter = AzureMonitoringAdapter(
        reviewed_collector_contract=_acquisition_collector_contract(),
    )

    first = adapter.verify_identity()
    _SyntheticClock.now = NOW + timedelta(seconds=30)
    second = adapter.verify_identity()

    assert first.verified_at == NOW
    assert second.verified_at == NOW + timedelta(seconds=30)
    assert first.proof_digest != second.proof_digest
    assert _SyntheticManagedIdentityCredential.instances[0].calls == 2
    clients = adapter._clients
    assert clients is not None
    assert (
        len(
            {
                id(clients.log_analytics),
                id(clients.activity_log),
                id(clients.resource_graph),
                id(clients.resource_health),
                id(clients.ip_flow_verify),
            }
        )
        == 5
    )


def test_synthetic_client_factories_are_isolated_per_adapter() -> None:
    context, intent, controls = _authority()
    acquisition_authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    first_port = _AcquisitionPort()
    second_port = _AcquisitionPort(traffic_analytics_rows=0)
    first_coordinator = _coordinator(first_port, acquisition_authority)
    second_coordinator = _coordinator(second_port, acquisition_authority)

    def execute(coordinator, commit):
        return coordinator.execute(
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

    first_commit = _CommitPort()
    first = execute(first_coordinator, first_commit)
    second_commit = _CommitPort()
    second = execute(second_coordinator, second_commit)

    assert first_commit.calls == second_commit.calls == 1
    assert first_port.ip_flow_calls == 1
    assert second_port.ip_flow_calls == 0
    assert len(first_port.azure_client_credentials) == 5
    assert len(second_port.azure_client_credentials) == 5
    assert len({id(item) for item in first_port.azure_client_credentials}) == 1
    assert len({id(item) for item in second_port.azure_client_credentials}) == 1
    assert first_port.azure_client_credentials[0] is not second_port.azure_client_credentials[0]
    first_receipt = first.prepared.monitoring_bundle.acquisition_receipt
    second_receipt = second.prepared.monitoring_bundle.acquisition_receipt
    assert first_receipt is not None
    assert second_receipt is not None
    assert any(item.source == "ipFlowVerify" for item in first_receipt.exchanges)
    assert not any(item.source == "ipFlowVerify" for item in second_receipt.exchanges)


def test_identity_proof_time_follows_token_jwks_signature_and_claim_validation() -> None:
    _SyntheticManagedIdentityCredential.advance_clock_seconds = 5
    _SyntheticJwks.advance_clock_seconds = 7
    _SyntheticJwt.advance_clock_seconds = 11
    _SyntheticClaims.advance_clock_seconds = 13
    authority = _authority(required_control_names={"heartbeat", "endpoint", "monitor"})
    port = _AcquisitionPort()
    outcome, commit, _ = _execute(port, authority=authority)

    assert commit.calls == 1
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert receipt.identity_proof is not None
    expected_verification_time = NOW + timedelta(seconds=36)
    assert receipt.identity_proof.verified_at == expected_verification_time
    assert receipt.execution_started_at == expected_verification_time
    assert outcome.batch.collected_at == expected_verification_time
    assert all(
        request.collector_execution_time == expected_verification_time
        for request in port.requests
        if isinstance(request, LogAnalyticsQueryRequest)
    )


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
    port = _AcquisitionPort()
    coordinator = _coordinator(port, stale_authority)

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

    assert len(_SyntheticManagedIdentityCredential.instances) == 1
    assert _SyntheticManagedIdentityCredential.instances[0].calls == 0
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
        port = _AcquisitionPort()
        with pytest.raises(
            MonitoringAcquisitionError,
            match="control binding coverage|required control bindings",
        ):
            _coordinator(port, invalid)
        assert _SyntheticManagedIdentityCredential.instances[-1].calls == 0
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
    port = _AcquisitionPort()

    with pytest.raises(ValidationError, match="IP Flow Verify operations"):
        AzureMonitoringAdapter(
            reviewed_collector_contract=invalid,
        )

    assert _SyntheticManagedIdentityCredential.instances == []
    assert port.requests == []


def test_acquisition_identity_must_be_separate_from_context_identity() -> None:
    with pytest.raises(ValidationError, match="must be separate"):
        _acquisition_authority(
            reader_identity_id=READER_ID,
            context_identity_id=READER_ID,
        )


def test_authority_unpublished_resource_fails_before_identity_or_source_io() -> None:
    current = _acquisition_authority()
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"authority_id", "authority_digest"},
    )
    payload["allowedResourceIds"] = sorted(
        (*current.allowed_resource_ids, OUT_OF_SCOPE_ID.casefold())
    )
    digest = compute_artifact_digest(payload)
    authority = MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": current.allowed_sources,
            "allowedResourceIds": tuple(payload["allowedResourceIds"]),
            "requiredControlIds": current.required_control_ids,
            "requiredControlBindings": current.required_control_bindings,
            "requiredCoverageScopeDigests": (current.required_coverage_scope_digests),
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )
    port = _AcquisitionPort()

    with pytest.raises(
        MonitoringAcquisitionError,
        match="reviewed credential contract",
    ):
        _coordinator(port, authority)

    assert _SyntheticManagedIdentityCredential.instances[0].calls == 0
    assert port.requests == []


def test_authority_extra_published_resource_fails_exact_scope_before_identity() -> None:
    current = _acquisition_authority()
    contract = _acquisition_collector_contract()
    extra_resource = next(
        item.casefold()
        for item in contract.signal_read_scope_ids
        if item.casefold() not in current.allowed_resource_ids
    )
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"authority_id", "authority_digest"},
    )
    payload["allowedResourceIds"] = sorted((*current.allowed_resource_ids, extra_resource))
    digest = compute_artifact_digest(payload)
    authority = MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": current.allowed_sources,
            "allowedResourceIds": tuple(payload["allowedResourceIds"]),
            "requiredControlIds": current.required_control_ids,
            "requiredControlBindings": current.required_control_bindings,
            "requiredCoverageScopeDigests": (current.required_coverage_scope_digests),
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )
    port = _AcquisitionPort()

    with pytest.raises(
        MonitoringAcquisitionError,
        match="source-specific contract scope",
    ):
        _execute(port, acquisition_authority=authority)

    assert _SyntheticManagedIdentityCredential.instances[0].calls == 0
    assert port.requests == []


def test_effective_rbac_inventory_expiry_blocks_credential_and_source_io() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory.update(
        {
            "collectedAt": NOW - timedelta(minutes=20),
            "expiresAt": NOW - timedelta(minutes=10),
        }
    )
    inventory.pop("inventoryDigest")
    inventory["inventoryDigest"] = compute_artifact_digest(
        monitoring_acquisition_module._json_value(inventory)
    )
    contract = MonitoringCollectorContract(**payload)
    port = _AcquisitionPort()

    with pytest.raises(
        MonitoringAcquisitionError,
        match="effective RBAC inventory is stale",
    ):
        _execute(port, collector_contract=contract)

    assert _SyntheticManagedIdentityCredential.instances[0].calls == 0
    assert port.requests == []


def test_authority_effective_rbac_digest_mismatch_fails_before_identity() -> None:
    current = _acquisition_authority()
    contract = _acquisition_collector_contract()
    inventory = contract.effective_rbac_inventory
    assert inventory is not None
    wrong_inventory_digest = "sha256:" + "0" * 64
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"authority_id", "authority_digest"},
    )
    payload["effectiveRbacInventoryDigest"] = wrong_inventory_digest
    payload["deploymentIdentityContractDigest"] = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": current.monitoring_reader_identity_id,
            "monitoringReaderPrincipalId": current.monitoring_reader_principal_id,
            "monitoringReaderClientId": current.monitoring_reader_client_id,
            "monitoringReaderTenantId": current.monitoring_reader_tenant_id,
            "athenaContextIdentityId": current.athena_context_identity_id,
            "athenaContextPrincipalId": current.athena_context_principal_id,
            "effectiveRbacInventoryDigest": wrong_inventory_digest,
            "effectiveRbacSourceManifestDigest": inventory.source_manifest_digest,
        }
    )
    digest = compute_artifact_digest(payload)
    authority = MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": current.allowed_sources,
            "allowedResourceIds": current.allowed_resource_ids,
            "requiredControlIds": current.required_control_ids,
            "requiredControlBindings": current.required_control_bindings,
            "requiredCoverageScopeDigests": (current.required_coverage_scope_digests),
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )
    port = _AcquisitionPort()

    with pytest.raises(
        MonitoringAcquisitionError,
        match="reviewed credential contract",
    ):
        _coordinator(port, authority)

    assert _SyntheticManagedIdentityCredential.instances[0].calls == 0
    assert port.requests == []


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
            "identity_proof_audience",
            "identity_proof_token_version",
            "identity_proof_required_role",
            "identity_proof_maximum_lifetime_seconds",
            "effective_rbac_inventory_digest",
            "effective_rbac_source_manifest_digest",
        },
    )
    payload["schemaVersion"] = "athena.wc028MonitoringAcquisitionAuthority.v1"
    payload["readOnly"] = True
    payload["athenaContextHasWorkloadReader"] = False
    digest = compute_artifact_digest(payload)
    payload["allowedSources"] = tuple(payload["allowedSources"])
    payload["allowedResourceIds"] = tuple(payload["allowedResourceIds"])
    authority = MonitoringAcquisitionAuthority(
        **payload,
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )

    assert authority.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v1"
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v5"):
        _coordinator(_AcquisitionPort(), authority)


def test_v2_acquisition_authority_remains_readable_but_not_executable() -> None:
    current = _acquisition_authority()
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "authority_id",
            "authority_digest",
            "monitoring_reader_client_id",
            "monitoring_reader_tenant_id",
            "context_binding_digest",
            "required_coverage_scope_digests",
            "required_control_bindings",
            "control_selection_digest",
            "identity_proof_audience",
            "identity_proof_token_version",
            "identity_proof_required_role",
            "identity_proof_maximum_lifetime_seconds",
            "effective_rbac_inventory_digest",
            "effective_rbac_source_manifest_digest",
        },
    )
    payload["schemaVersion"] = "athena.wc028MonitoringAcquisitionAuthority.v2"
    payload["monitoringReaderHasReadOnlyWorkloadAccess"] = True
    payload["readOnly"] = True
    payload["athenaContextHasWorkloadReader"] = False
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
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v5"):
        _coordinator(_AcquisitionPort(), authority)


def test_v3_acquisition_authority_remains_readable_but_not_executable() -> None:
    current = _acquisition_authority()
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "authority_id",
            "authority_digest",
            "identity_proof_audience",
            "identity_proof_token_version",
            "identity_proof_required_role",
            "identity_proof_maximum_lifetime_seconds",
            "effective_rbac_inventory_digest",
            "effective_rbac_source_manifest_digest",
        },
    )
    payload["schemaVersion"] = "athena.wc028MonitoringAcquisitionAuthority.v3"
    payload["monitoringReaderHasReadOnlyWorkloadAccess"] = True
    payload["readOnly"] = True
    payload["athenaContextHasWorkloadReader"] = False
    payload["deploymentIdentityContractDigest"] = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": current.monitoring_reader_identity_id,
            "monitoringReaderPrincipalId": current.monitoring_reader_principal_id,
            "monitoringReaderClientId": current.monitoring_reader_client_id,
            "monitoringReaderTenantId": current.monitoring_reader_tenant_id,
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
    payload["requiredControlBindings"] = current.required_control_bindings
    payload["requiredCoverageScopeDigests"] = current.required_coverage_scope_digests
    authority = MonitoringAcquisitionAuthority(
        **payload,
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )

    assert authority.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v3"
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v5"):
        _coordinator(_AcquisitionPort(), authority)


def test_v4_acquisition_authority_remains_readable_but_not_executable() -> None:
    current = _acquisition_authority()
    payload = current.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "authority_id",
            "authority_digest",
            "effective_rbac_inventory_digest",
            "effective_rbac_source_manifest_digest",
        },
    )
    payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v4",
            "monitoringReaderHasReadOnlyWorkloadAccess": True,
            "readOnly": True,
            "athenaContextHasWorkloadReader": False,
            "deploymentIdentityContractDigest": compute_artifact_digest(
                {
                    "monitoringReaderIdentityId": current.monitoring_reader_identity_id,
                    "monitoringReaderPrincipalId": current.monitoring_reader_principal_id,
                    "monitoringReaderClientId": current.monitoring_reader_client_id,
                    "monitoringReaderTenantId": current.monitoring_reader_tenant_id,
                    "athenaContextIdentityId": current.athena_context_identity_id,
                    "athenaContextPrincipalId": current.athena_context_principal_id,
                    "monitoringReaderHasReadOnlyWorkloadAccess": True,
                    "athenaContextHasWorkloadReader": False,
                    "readOnly": True,
                }
            ),
        }
    )
    digest = compute_artifact_digest(payload)
    authority = MonitoringAcquisitionAuthority(
        **{
            **payload,
            "allowedSources": tuple(payload["allowedSources"]),
            "allowedResourceIds": tuple(payload["allowedResourceIds"]),
            "requiredControlIds": tuple(payload["requiredControlIds"]),
            "requiredControlBindings": current.required_control_bindings,
            "requiredCoverageScopeDigests": (current.required_coverage_scope_digests),
        },
        authorityId=(f"monitoring-acquisition-authority-{digest.removeprefix('sha256:')[:32]}"),
        authorityDigest=digest,
    )

    assert authority.schema_version == "athena.wc028MonitoringAcquisitionAuthority.v4"
    with pytest.raises(MonitoringAcquisitionError, match="authority schema v5"):
        _coordinator(_AcquisitionPort(), authority)


def test_fake_source_identity_cannot_override_adapter_identity_proof() -> None:
    port = _AcquisitionPort(source_identity_id=CONTEXT_ID)
    outcome, commit, _ = _execute(port)

    assert commit.calls == 1
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert receipt.authenticated_principal_id == READER_PRINCIPAL_ID
    assert receipt.identity_proof is not None
    assert receipt.identity_proof.principal_id == READER_PRINCIPAL_ID


@pytest.mark.parametrize(
    "claim_overrides",
    (
        {"oid": CONTEXT_PRINCIPAL_ID},
        {"appid": "33333333-3333-3333-3333-333333333333"},
        {"tid": "44444444-4444-4444-4444-444444444444"},
        {"aud": "api://unreviewed-proof"},
        {"ver": "2.0"},
        {"idtyp": "user"},
        {"roles": ["Athena.MonitoringAcquisition.Other"]},
        {"exp": int(NOW.timestamp()) - 1},
    ),
)
def test_invalid_identity_proof_fails_before_first_source_io(
    claim_overrides: dict[str, object],
) -> None:
    _SyntheticManagedIdentityCredential.claim_overrides = claim_overrides
    port = _AcquisitionPort()
    context, intent, controls = _authority()
    authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, authority)

    with pytest.raises(
        MonitoringAcquisitionError,
        match="identity proof",
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

    assert len(_SyntheticManagedIdentityCredential.instances) == 1
    assert _SyntheticManagedIdentityCredential.instances[0].calls == 1
    assert port.azure_client_credentials == []
    assert port.requests == []


def test_overlong_identity_proof_fails_before_first_source_io() -> None:
    _SyntheticManagedIdentityCredential.lifetime_seconds = (
        MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS + 1
    )
    port = _AcquisitionPort()
    context, intent, controls = _authority()
    authority = _acquisition_authority(
        required_control_ids=_required_control_ids(context, controls),
        context_binding=context,
        controls=controls,
    )
    coordinator = _coordinator(port, authority)

    with pytest.raises(MonitoringAcquisitionError, match="outside its lifetime"):
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

    assert port.azure_client_credentials == []
    assert port.requests == []


def test_default_azure_credential_cannot_be_injected_into_production_adapter() -> None:
    kwargs = {
        "reviewed_collector_contract": _acquisition_collector_contract(),
        "credential": DefaultAzureCredential(),
    }

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        AzureMonitoringAdapter(**kwargs)  # type: ignore[arg-type]

    assert _SyntheticManagedIdentityCredential.instances == []


def test_caller_collection_time_cannot_backdate_collector_receipt() -> None:
    outcome, commit, _ = _execute(
        _AcquisitionPort(),
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


@pytest.mark.parametrize(
    ("live_time", "message"),
    (
        (NOW + timedelta(seconds=1), "does not equal live call start"),
        (NOW + timedelta(hours=1), "credential is stale"),
    ),
)
def test_ip_flow_override_is_rejected_before_operation(
    live_time: datetime,
    message: str,
) -> None:
    source_port = _AcquisitionPort()
    _execute(source_port)
    request = next(item for item in source_port.requests if isinstance(item, IpFlowVerifyRequest))
    adapter = _adapter(_AcquisitionPort())
    proof = adapter.verify_identity()
    execution = monitoring_acquisition_module._AcquisitionExecution(
        adapter=adapter,
        identity_proof=proof,
        max_calls=32,
        max_freshness_seconds=900,
        started_at=proof.verified_at,
        exchanges=[],
    )
    operation_calls = 0

    def operation(_request):
        nonlocal operation_calls
        operation_calls += 1
        raise AssertionError("stale or mismatched call time must fail before I/O")

    _SyntheticClock.now = live_time
    with pytest.raises(MonitoringAcquisitionError, match=message):
        execution.invoke(
            request,
            operation,
            requested_at_override=request.checked_at,
        )

    assert operation_calls == 0
    assert execution.exchanges == []


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


def test_empty_traffic_analytics_emits_no_ip_flow_exchange_or_orphan_proof() -> None:
    first_port = _AcquisitionPort(traffic_analytics_rows=0)
    first, first_commit, _ = _execute(first_port)
    second_port = _AcquisitionPort(traffic_analytics_rows=0)
    second, second_commit, _ = _execute(second_port)

    assert first_commit.calls == second_commit.calls == 1
    assert first_port.ip_flow_calls == second_port.ip_flow_calls == 0
    network_coverage = next(item for item in first.batch.coverage if item.family == "networkFlow")
    assert network_coverage.status == "unavailable"
    receipt = first.prepared.monitoring_bundle.acquisition_receipt
    second_receipt = second.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert second_receipt is not None
    assert receipt.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v5"
    assert receipt.selected_incident is not None
    assert receipt.collector_contract_digest == COLLECTOR_CONTRACT_DIGEST
    assert receipt.credential_proofs is None
    assert receipt.identity_proof is not None
    assert not any(item.source == "ipFlowVerify" for item in receipt.exchanges)
    assert all(
        item.identity_proof_digest == receipt.identity_proof.proof_digest
        for item in receipt.exchanges
    )
    assert type(receipt).model_validate_json(receipt.model_dump_json(by_alias=True)) == receipt
    assert first.batch.canonical_bytes() == second.batch.canonical_bytes()
    assert receipt.canonical_json() == second_receipt.canonical_json()


def test_each_ip_flow_exchange_maps_one_retained_network_flow_record() -> None:
    outcome, commit, _ = _execute(_AcquisitionPort())

    assert commit.calls == 1
    retained = tuple(
        item for item in outcome.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    exchanges = tuple(item for item in receipt.exchanges if item.source == "ipFlowVerify")
    assert len(exchanges) == len(retained) == 1
    provenance = retained[0].ip_flow_provenance
    assert provenance is not None
    assert provenance.exchange_sequence == exchanges[0].sequence
    assert provenance.ip_flow_request_digest == exchanges[0].request_digest
    assert provenance.ip_flow_result_digest == exchanges[0].result_digest
    assert provenance.requested_at == exchanges[0].requested_at
    assert provenance.checked_at == exchanges[0].checked_at
    assert provenance.received_at == exchanges[0].received_at


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected_error"),
    (
        (
            "ipFlowRequestDigest",
            "sha256:" + "f" * 64,
            "exact signed exchange",
        ),
        (
            "ipFlowResultDigest",
            "sha256:" + "e" * 64,
            "exact signed exchange",
        ),
        (
            "exchangeSequence",
            32,
            "map each exchange",
        ),
        (
            "correlationRequestId",
            "84ba07fb-0911-4d67-946a-67a9eac90506",
            "receipt does not bind the monitoring bundle",
        ),
    ),
)
def test_ip_flow_provenance_tampering_is_rejected(
    field_name: str,
    replacement: object,
    expected_error: str,
) -> None:
    outcome, _, _ = _execute(_AcquisitionPort())
    bundle_payload = outcome.prepared.monitoring_bundle.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    flow_payload = next(
        item for item in bundle_payload["observations"] if item["observationKind"] == "networkFlow"
    )
    provenance_payload = flow_payload["ipFlowProvenance"]
    provenance_payload[field_name] = replacement
    provenance_payload["provenanceDigest"] = compute_artifact_digest(
        {key: value for key, value in provenance_payload.items() if key != "provenanceDigest"}
    )
    observation_digest = compute_artifact_digest(
        {
            key: value
            for key, value in flow_payload.items()
            if key not in {"observationId", "observationDigest"}
        }
    )
    flow_payload["observationId"] = f"obs-{observation_digest.removeprefix('sha256:')[:32]}"
    flow_payload["observationDigest"] = observation_digest
    bundle_payload["observations"] = sorted(
        bundle_payload["observations"],
        key=lambda item: item["observationId"],
    )

    with pytest.raises(ValidationError, match=expected_error):
        type(outcome.prepared.monitoring_bundle).model_validate_json(json.dumps(bundle_payload))


def test_production_bundle_rejects_historical_loose_ip_flow_fields() -> None:
    outcome, _, _ = _execute(_AcquisitionPort())
    bundle_payload = outcome.prepared.monitoring_bundle.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    flow_payload = next(
        item
        for item in bundle_payload["observations"]
        if item["observationKind"] == "networkFlow"
    )
    provenance = flow_payload.pop("ipFlowProvenance")
    flow_payload.update(
        {
            "ipFlowAccess": provenance["access"],
            "ipFlowRuleResourceId": provenance["resultRuleResourceId"],
            "ipFlowCheckedAt": provenance["checkedAt"],
            "ipFlowResultDigest": provenance["ipFlowResultDigest"],
        }
    )
    observation_digest = compute_artifact_digest(
        {
            key: value
            for key, value in flow_payload.items()
            if key not in {"observationId", "observationDigest"}
        }
    )
    flow_payload["observationId"] = (
        f"obs-{observation_digest.removeprefix('sha256:')[:32]}"
    )
    flow_payload["observationDigest"] = observation_digest
    bundle_payload["observations"] = sorted(
        bundle_payload["observations"],
        key=lambda item: item["observationId"],
    )

    with pytest.raises(ValidationError, match="exactly one semantic IP Flow provenance"):
        type(outcome.prepared.monitoring_bundle).model_validate_json(
            json.dumps(bundle_payload)
        )


def test_ip_flow_allow_and_deny_change_persisted_and_correlated_semantics() -> None:
    denied, _, _ = _execute(_AcquisitionPort(ip_flow_access="Deny"))
    allowed, _, _ = _execute(_AcquisitionPort(ip_flow_access="Allow"))

    denied_record = next(
        item for item in denied.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    allowed_record = next(
        item for item in allowed.batch.records if isinstance(item, NetworkWatcherFlowRecord)
    )
    denied_observation = next(
        item
        for item in denied.prepared.monitoring_bundle.observations
        if isinstance(item, NetworkFlowObservation)
    )
    allowed_observation = next(
        item
        for item in allowed.prepared.monitoring_bundle.observations
        if isinstance(item, NetworkFlowObservation)
    )
    denied_report = (
        _test_service(denied.correlation_request).correlate(denied.correlation_request).report
    )
    allowed_report = (
        _test_service(allowed.correlation_request).correlate(allowed.correlation_request).report
    )

    assert denied_record.ip_flow_provenance is not None
    assert allowed_record.ip_flow_provenance is not None
    assert denied_record.ip_flow_provenance.access == "Deny"
    assert allowed_record.ip_flow_provenance.access == "Allow"
    assert denied.batch.canonical_bytes() != allowed.batch.canonical_bytes()
    assert denied_observation.ip_flow_provenance is not None
    assert allowed_observation.ip_flow_provenance is not None
    assert denied_observation.ip_flow_provenance.access == "Deny"
    assert allowed_observation.ip_flow_provenance.access == "Allow"
    assert (
        denied.prepared.monitoring_bundle.compute_normalized_evidence_digest_value()
        != allowed.prepared.monitoring_bundle.compute_normalized_evidence_digest_value()
    )
    assert any(
        denied_observation.observation_id
        in {item.evidence_id for item in hypothesis.supporting_evidence}
        for hypothesis in denied_report.hypotheses
    )
    assert all(
        allowed_observation.observation_id
        not in {item.evidence_id for item in hypothesis.supporting_evidence}
        for hypothesis in allowed_report.hypotheses
    )


@pytest.mark.parametrize(
    "port",
    (
        _AcquisitionPort(traffic_rule_resource_id=None),
        _AcquisitionPort(traffic_enforcement_resource_id=NSG_RULE_ID),
    ),
)
def test_unpersistable_traffic_rows_skip_ip_flow_before_exchange(
    port: _AcquisitionPort,
) -> None:
    outcome, commit, _ = _execute(port)

    assert commit.calls == 1
    assert port.ip_flow_calls == 0
    assert not any(isinstance(item, NetworkWatcherFlowRecord) for item in outcome.batch.records)
    coverage = next(item for item in outcome.batch.coverage if item.family == "networkFlow")
    assert coverage.status == "unavailable"
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert not any(item.source == "ipFlowVerify" for item in receipt.exchanges)


@pytest.mark.parametrize(
    "port",
    (
        _AcquisitionPort(traffic_destination_port=443),
        _AcquisitionPort(traffic_protocol="Icmp"),
        _AcquisitionPort(traffic_direction="outbound"),
        _AcquisitionPort(traffic_destination_resource_id=NSG_ID),
    ),
)
def test_unapproved_traffic_tuple_or_local_target_skips_ip_flow(
    port: _AcquisitionPort,
) -> None:
    outcome, commit, _ = _execute(port)

    assert commit.calls == 1
    assert port.ip_flow_calls == 0
    network_coverage = next(item for item in outcome.batch.coverage if item.family == "networkFlow")
    assert network_coverage.status == "unavailable"
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    assert not any(item.source == "ipFlowVerify" for item in receipt.exchanges)


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
