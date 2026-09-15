from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from azure.core.credentials import AccessToken
from azure.core.pipeline import Pipeline
from azure.core.pipeline.transport import HttpRequest, HttpResponse, HttpTransport

import athena_context.monitoring_acquisition as monitoring_acquisition_module
from athena_context.contracts import EvidenceCoverageScope, compute_artifact_digest, sha256_hex
from athena_context.monitoring_acquisition import (
    MAX_ACQUISITION_RESPONSE_BYTES,
    MAX_ACQUISITION_ROWS,
    ActivityLogQueryRequest,
    AzureActivityLogAcquisitionClient,
    AzureIpFlowVerifyAcquisitionClient,
    AzureLogAnalyticsAcquisitionClient,
    AzureResourceGraphAcquisitionClient,
    AzureResourceHealthAcquisitionClient,
    IpFlowVerifyRequest,
    LogAnalyticsQueryRequest,
    MonitoringAcquisitionError,
    ResourceGraphChangeQueryRequest,
    ResourceHealthQueryRequest,
)
from test_wc024_monitoring_contract import _acquisition_collector_contract
from test_wc026_correlation_contract import NOW

_REVIEWED_CONTRACT = _acquisition_collector_contract()
PRODUCTION_WEB_ID = next(
    item
    for item in _REVIEWED_CONTRACT.signal_read_scope_ids
    if item.casefold().endswith("/virtualmachines/athena-hackathon-web-01")
)
PRODUCTION_DB_ID = next(
    item
    for item in _REVIEWED_CONTRACT.signal_read_scope_ids
    if item.casefold().endswith("/virtualmachines/athena-hackathon-sqlvm-01")
)
PRODUCTION_NSG_RULE_ID = (
    f"{_REVIEWED_CONTRACT.workload_resource_group_id}/providers/Microsoft.Network/"
    "networkSecurityGroups/athena-hackathon-nsg/securityRules/deny-web"
)
OUT_OF_SCOPE_VM_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/rg-synthetic-other/providers/Microsoft.Compute/"
    "virtualMachines/synthetic-out-of-scope"
)
_CONTROL_ID = "monitoring-control-" + "1" * 32
_CONTROL_DIGEST = "sha256:" + "2" * 64
_SCOPE_DIGEST = "sha256:" + "3" * 64
_AUTHORITY_ID = "monitoring-acquisition-authority-" + "4" * 32
_AUTHORITY_DIGEST = "sha256:" + "5" * 64
_INTENT_ID = "monitoring-intent-" + "6" * 32
_INTENT_DIGEST = "sha256:" + "7" * 64


def _utc_text(value) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class _ResponseSpec:
    payload: object | None
    status_code: int = 200
    headers: dict[str, str] | None = None


class _MockResponse(HttpResponse):
    def __init__(self, request: HttpRequest, spec: _ResponseSpec) -> None:
        super().__init__(request, None)
        self.status_code = spec.status_code
        self.reason = "synthetic"
        self.headers = dict(spec.headers or {})
        self._body = (
            b""
            if spec.payload is None
            else spec.payload
            if isinstance(spec.payload, bytes)
            else json.dumps(
                spec.payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        if self._body and not any(name.casefold() == "content-type" for name in self.headers):
            self.headers["Content-Type"] = "application/json"

    def body(self) -> bytes:
        return self._body

    def stream_download(
        self,
        pipeline: Pipeline[HttpRequest, HttpResponse],
        **_kwargs: object,
    ):
        del pipeline
        yield self._body


class _MockTransport(HttpTransport[HttpRequest, HttpResponse]):
    def __init__(self, *responses: _ResponseSpec) -> None:
        self._responses = list(responses)
        self.requests: list[HttpRequest] = []
        self.sleeps: list[float] = []

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)

    def send(self, request: HttpRequest, **_kwargs: object) -> HttpResponse:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("unexpected Azure transport request")
        return _MockResponse(request, self._responses.pop(0))


class _Credential:
    def __init__(self) -> None:
        self.scopes: list[tuple[str, ...]] = []

    def get_token(self, *scopes: str, **_kwargs: object) -> AccessToken:
        self.scopes.append(scopes)
        return AccessToken("synthetic-azure-access-token", 2_147_483_647)


def _common_payload(source: str, *, resource_ids: tuple[str, ...]) -> dict[str, object]:
    contract = _acquisition_collector_contract()
    return {
        "source": source,
        "monitoringReaderIdentityId": contract.collector_identity_resource_id.casefold(),
        "acquisitionAuthorityId": _AUTHORITY_ID,
        "acquisitionAuthorityDigest": _AUTHORITY_DIGEST,
        "collectorContractDigest": contract.compute_artifact_digest_value(),
        "intentId": _INTENT_ID,
        "intentDigest": _INTENT_DIGEST,
        "controlId": _CONTROL_ID,
        "controlDigest": _CONTROL_DIGEST,
        "scopeDigest": _SCOPE_DIGEST,
        "windowStart": NOW - timedelta(minutes=10),
        "windowEnd": NOW,
        "maxRows": MAX_ACQUISITION_ROWS,
        "maxBytes": MAX_ACQUISITION_RESPONSE_BYTES,
        "resourceIds": tuple(sorted(item.casefold() for item in resource_ids)),
    }


def _coverage_scope(resource_ids: tuple[str, ...]) -> EvidenceCoverageScope:
    payload: dict[str, object] = {
        "resourceIds": tuple(sorted(item.casefold() for item in resource_ids)),
        "pathId": None,
        "direction": None,
        "fiveTupleDigest": None,
        "endpointTestReference": None,
        "endpointTestDigest": None,
        "queryScopeDigest": _CONTROL_DIGEST,
    }
    digest = compute_artifact_digest(monitoring_acquisition_module._json_value(payload))
    return EvidenceCoverageScope(
        **payload,
        scopeId=f"coverage-scope-{digest.removeprefix('sha256:')[:32]}",
        scopeDigest=digest,
    )


def _log_request(
    *,
    target_resource_id: str = PRODUCTION_WEB_ID,
) -> LogAnalyticsQueryRequest:
    target_resource_id = target_resource_id.casefold()
    query = "Heartbeat | project resourceId, observedStart, observedEnd, heartbeatCount"
    payload = {
        **_common_payload("logAnalytics", resource_ids=(target_resource_id,)),
        "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
        "table": "Heartbeat",
        "query": query,
        "queryDigest": sha256_hex(query.encode("utf-8")),
        "queryTargetResourceId": target_resource_id,
        "expectedColumns": (
            "resourceId",
            "observedStart",
            "observedEnd",
            "heartbeatCount",
        ),
        "collectorExecutionTime": NOW,
        "coverageScope": _coverage_scope((target_resource_id,)),
    }
    payload.pop("resourceIds")
    return monitoring_acquisition_module._build_request(
        LogAnalyticsQueryRequest,
        payload,
    )


def _activity_request(
    *,
    resource_id: str = PRODUCTION_NSG_RULE_ID,
) -> ActivityLogQueryRequest:
    resource_id = resource_id.casefold()
    return monitoring_acquisition_module._build_request(
        ActivityLogQueryRequest,
        {
            **_common_payload("activityLog", resource_ids=(resource_id,)),
            "schemaVersion": "athena.wc028ActivityLogQueryRequest.v1",
            "categories": ("Administrative",),
            "operationNames": ("Microsoft.Network/networkSecurityGroups/securityRules/write",),
            "resultTypes": ("Succeeded",),
            "levels": ("Informational",),
            "expectedColumns": (
                "category",
                "operationName",
                "resultType",
                "level",
                "targetResourceId",
                "correlationId",
                "occurredAt",
            ),
        },
    )


def _resource_graph_request(
    *,
    resource_id: str = PRODUCTION_NSG_RULE_ID,
) -> ResourceGraphChangeQueryRequest:
    resource_id = resource_id.casefold()
    return monitoring_acquisition_module._build_request(
        ResourceGraphChangeQueryRequest,
        {
            **_common_payload("resourceGraph", resource_ids=(resource_id,)),
            "schemaVersion": "athena.wc028ResourceGraphChangeQueryRequest.v1",
            "expectedColumns": (
                "targetResourceId",
                "correlationId",
                "occurredAt",
                "operationName",
                "resultType",
                "change",
            ),
        },
    )


def _resource_health_request(
    *,
    resource_id: str = PRODUCTION_WEB_ID,
) -> ResourceHealthQueryRequest:
    resource_id = resource_id.casefold()
    return monitoring_acquisition_module._build_request(
        ResourceHealthQueryRequest,
        {
            **_common_payload("resourceHealth", resource_ids=(resource_id,)),
            "schemaVersion": "athena.wc028ResourceHealthQueryRequest.v1",
            "eventStatuses": ("Active", "Resolved"),
            "currentStatuses": ("Available", "Unavailable"),
            "previousStatuses": ("Available", "Unavailable"),
            "reasonTypes": ("PlatformInitiated",),
            "expectedColumns": (
                "resourceId",
                "eventStatus",
                "currentStatus",
                "previousStatus",
                "reasonType",
                "observedStart",
                "observedEnd",
            ),
        },
    )


def _ip_flow_request(
    *,
    target_resource_id: str = PRODUCTION_DB_ID,
) -> IpFlowVerifyRequest:
    target_resource_id = target_resource_id.casefold()
    payload = {
        **_common_payload("ipFlowVerify", resource_ids=(target_resource_id,)),
        "schemaVersion": "athena.wc028IpFlowVerifyRequest.v1",
        "checkedAt": NOW,
        "targetResourceId": target_resource_id,
        "direction": "inbound",
        "protocol": "Tcp",
        "sourceAddress": "192.0.2.10",
        "destinationAddress": "192.0.2.20",
        "sourcePort": 443,
        "destinationPort": 1433,
    }
    payload.pop("resourceIds")
    return monitoring_acquisition_module._build_request(
        IpFlowVerifyRequest,
        payload,
    )


def test_log_analytics_client_uses_bound_resource_endpoint_and_normalizes_rows() -> None:
    request = _log_request()
    transport = _MockTransport(
        _ResponseSpec(
            {
                "tables": [
                    {
                        "name": "PrimaryResult",
                        "columns": [
                            {"name": name, "type": "string"} for name in request.expected_columns
                        ],
                        "rows": [
                            [
                                PRODUCTION_WEB_ID.upper(),
                                (NOW - timedelta(minutes=10)).isoformat(),
                                NOW.isoformat(),
                                2,
                            ]
                        ],
                    }
                ]
            }
        )
    )
    credential = _Credential()
    client = AzureLogAnalyticsAcquisitionClient(
        credential=credential,
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    result = client.query_log_analytics(request)

    assert credential.scopes == [("https://api.loganalytics.io/.default",)]
    assert len(result.rows) == 1
    assert result.rows[0].resource_id == PRODUCTION_WEB_ID.casefold()
    assert result.rows[0].heartbeat_count == 2
    sent = transport.requests[0]
    assert sent.url == (f"https://api.loganalytics.io/v1{PRODUCTION_WEB_ID.casefold()}/query")
    assert sent.headers["Authorization"] == "Bearer synthetic-azure-access-token"
    assert json.loads(sent.body) == {
        "query": request.query,
        "timespan": (f"{_utc_text(request.window_start)}/{_utc_text(request.window_end)}"),
    }


def test_log_analytics_client_preserves_duplicate_rows_for_ambiguity_checks() -> None:
    request = _log_request()
    source_row = [
        PRODUCTION_WEB_ID,
        (NOW - timedelta(minutes=10)).isoformat(),
        NOW.isoformat(),
        2,
    ]
    transport = _MockTransport(
        _ResponseSpec(
            {
                "tables": [
                    {
                        "name": "PrimaryResult",
                        "columns": [
                            {"name": name, "type": "string"} for name in request.expected_columns
                        ],
                        "rows": [source_row, source_row],
                    }
                ]
            }
        )
    )
    client = AzureLogAnalyticsAcquisitionClient(
        credential=_Credential(),
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    result = client.query_log_analytics(request)

    assert len(result.rows) == 2
    assert result.rows[0] == result.rows[1]


def test_log_analytics_client_rejects_workspace_context_fallback() -> None:
    transport = _MockTransport()
    client = AzureLogAnalyticsAcquisitionClient(
        credential=_Credential(),
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    with pytest.raises(MonitoringAcquisitionError, match="resource scope"):
        client.query_log_analytics(
            _log_request(
                target_resource_id=(_acquisition_collector_contract().workspace_resource_id)
            )
        )

    assert transport.requests == []


def test_activity_log_client_uses_exact_resource_filter_and_service_values() -> None:
    request = _activity_request()
    transport = _MockTransport(
        _ResponseSpec(
            {
                "value": [
                    {
                        "category": {"value": "Administrative"},
                        "operationName": {
                            "value": ("Microsoft.Network/networkSecurityGroups/securityRules/write")
                        },
                        "status": {"value": "Succeeded"},
                        "level": "Informational",
                        "resourceId": PRODUCTION_NSG_RULE_ID.upper(),
                        "correlationId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        "eventTimestamp": (NOW - timedelta(minutes=5)).isoformat(),
                    }
                ]
            }
        )
    )
    credential = _Credential()
    client = AzureActivityLogAcquisitionClient(
        credential=credential,
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    result = client.query_activity_log(request)

    assert credential.scopes == [("https://management.azure.com/.default",)]
    assert len(result.rows) == 1
    assert result.rows[0].correlation_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    sent = transport.requests[0]
    parsed = urlsplit(sent.url)
    assert parsed.path.endswith("/providers/Microsoft.Insights/eventtypes/management/values")
    query = parse_qs(parsed.query)
    assert query["api-version"] == ["2015-04-01"]
    assert query["$filter"] == [
        (
            f"eventTimestamp ge '{_utc_text(request.window_start)}' and "
            f"eventTimestamp le '{_utc_text(request.window_end)}' and "
            f"resourceUri eq '{PRODUCTION_NSG_RULE_ID.casefold()}'"
        )
    ]


def test_resource_graph_client_uses_generated_bounded_change_query() -> None:
    request = _resource_graph_request()
    occurred_at = NOW - timedelta(minutes=5)
    change_properties = {
        "targetResourceId": PRODUCTION_NSG_RULE_ID,
        "changeType": "Update",
        "changeAttributes": {
            "timestamp": occurred_at.isoformat(),
            "correlationId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "operation": "Microsoft.Network/networkSecurityGroups/securityRules/write",
        },
        "changes": {
            "properties.access": {
                "previousValue": "Allow",
                "newValue": "Deny",
            }
        },
    }
    transport = _MockTransport(
        _ResponseSpec(
            {
                "data": [
                    {
                        "targetResourceId": PRODUCTION_NSG_RULE_ID.upper(),
                        "correlationId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        "occurredAt": occurred_at.isoformat(),
                        "operationName": (
                            "Microsoft.Network/networkSecurityGroups/securityRules/write"
                        ),
                        "resultType": "Succeeded",
                        "id": (
                            f"{PRODUCTION_NSG_RULE_ID}/providers/"
                            "Microsoft.Resources/changes/synthetic"
                        ),
                        "properties": change_properties,
                    }
                ],
                "resultTruncated": False,
            }
        )
    )
    credential = _Credential()
    client = AzureResourceGraphAcquisitionClient(
        credential=credential,
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    result = client.query_resource_graph_changes(request)

    assert credential.scopes == [("https://management.azure.com/.default",)]
    assert len(result.rows) == 1
    assert result.rows[0].change["properties"] == change_properties
    sent = transport.requests[0]
    assert sent.url.endswith("/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01")
    body = json.loads(sent.body)
    assert body["subscriptions"] == ["00000000-0000-0000-0000-000000000000"]
    assert body["options"] == {"$top": 501, "resultFormat": "ObjectArray"}
    assert PRODUCTION_NSG_RULE_ID.casefold() in body["query"]
    assert "| take 501" in body["query"]


def test_resource_health_client_reads_historical_availability_transitions() -> None:
    request = _resource_health_request()
    transport = _MockTransport(
        _ResponseSpec(
            {
                "value": [
                    {
                        "properties": {
                            "targetResourceId": PRODUCTION_WEB_ID.upper(),
                            "occurredTime": (NOW - timedelta(minutes=2)).isoformat(),
                            "previousAvailabilityState": "Available",
                            "availabilityState": "Unavailable",
                            "reasonType": "PlatformInitiated",
                        }
                    },
                    {
                        "properties": {
                            "targetResourceId": PRODUCTION_WEB_ID,
                            "occurredTime": (NOW - timedelta(minutes=8)).isoformat(),
                            "previousAvailabilityState": "Unavailable",
                            "availabilityState": "Available",
                            "reasonType": "PlatformInitiated",
                        }
                    },
                ]
            }
        )
    )
    credential = _Credential()
    client = AzureResourceHealthAcquisitionClient(
        credential=credential,
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    result = client.query_resource_health(request)

    assert credential.scopes == [("https://management.azure.com/.default",)]
    assert {row.event_status for row in result.rows} == {"Active", "Resolved"}
    assert {row.current_status for row in result.rows} == {"Available", "Unavailable"}
    assert transport.requests[0].url == (
        f"https://management.azure.com{PRODUCTION_WEB_ID.casefold()}/providers/"
        "Microsoft.ResourceHealth/availabilityStatuses?api-version=2025-05-01"
    )


def test_ip_flow_client_maps_local_tuple_and_polls_only_bound_arm_location() -> None:
    request = _ip_flow_request()
    operation_url = (
        "https://management.azure.com/subscriptions/"
        "00000000-0000-0000-0000-000000000000/providers/Microsoft.Network/"
        "locations/australiaeast/operations/synthetic"
        "?api-version=2025-09-01"
    )
    transport = _MockTransport(
        _ResponseSpec(
            None,
            status_code=202,
            headers={"Location": operation_url, "Retry-After": "0"},
        ),
        _ResponseSpec({"access": "Deny", "ruleName": PRODUCTION_NSG_RULE_ID}),
    )
    credential = _Credential()
    contract = _acquisition_collector_contract()
    client = AzureIpFlowVerifyAcquisitionClient(
        credential=credential,
        reviewed_contract=contract,
        _transport=transport,
    )

    result = client.query_ip_flow_verify(request)

    assert credential.scopes == [("https://management.azure.com/.default",)]
    assert result.access == "Deny"
    assert result.rule_resource_id == PRODUCTION_NSG_RULE_ID.casefold()
    assert transport.sleeps == [0]
    assert len(transport.requests) == 2
    initial = transport.requests[0]
    assert initial.url == (
        f"https://management.azure.com{contract.ip_flow_verify_scope_id.casefold()}/"
        "ipFlowVerify?api-version=2025-09-01"
    )
    assert json.loads(initial.body) == {
        "targetResourceId": PRODUCTION_DB_ID.casefold(),
        "direction": "Inbound",
        "protocol": "TCP",
        "localPort": "1433",
        "remotePort": "443",
        "localIPAddress": "192.0.2.20",
        "remoteIPAddress": "192.0.2.10",
    }
    assert transport.requests[1].url == operation_url


def test_ip_flow_client_rejects_polling_endpoint_escape_before_follow() -> None:
    transport = _MockTransport(
        _ResponseSpec(
            None,
            status_code=202,
            headers={
                "Location": (
                    "https://example.invalid/subscriptions/"
                    "00000000-0000-0000-0000-000000000000/providers/"
                    "Microsoft.Network/locations/australiaeast/operations/synthetic"
                    "?api-version=2025-09-01"
                ),
                "Retry-After": "0",
            },
        )
    )
    client = AzureIpFlowVerifyAcquisitionClient(
        credential=_Credential(),
        reviewed_contract=_acquisition_collector_contract(),
        _transport=transport,
    )

    with pytest.raises(MonitoringAcquisitionError, match="polling escaped"):
        client.query_ip_flow_verify(_ip_flow_request())

    assert len(transport.requests) == 1


def test_production_clients_reject_unreviewed_scopes_before_transport() -> None:
    cases = (
        (
            AzureLogAnalyticsAcquisitionClient,
            "query_log_analytics",
            _log_request(target_resource_id=OUT_OF_SCOPE_VM_ID),
        ),
        (
            AzureActivityLogAcquisitionClient,
            "query_activity_log",
            _activity_request(resource_id=OUT_OF_SCOPE_VM_ID),
        ),
        (
            AzureResourceGraphAcquisitionClient,
            "query_resource_graph_changes",
            _resource_graph_request(resource_id=OUT_OF_SCOPE_VM_ID),
        ),
        (
            AzureResourceHealthAcquisitionClient,
            "query_resource_health",
            _resource_health_request(resource_id=OUT_OF_SCOPE_VM_ID),
        ),
        (
            AzureIpFlowVerifyAcquisitionClient,
            "query_ip_flow_verify",
            _ip_flow_request(target_resource_id=OUT_OF_SCOPE_VM_ID),
        ),
    )
    for client_type, method_name, request in cases:
        transport = _MockTransport()
        client = client_type(
            credential=_Credential(),
            reviewed_contract=_acquisition_collector_contract(),
            _transport=transport,
        )
        with pytest.raises(MonitoringAcquisitionError, match="scope"):
            getattr(client, method_name)(request)
        assert transport.requests == []


def test_production_transport_rejects_errors_and_oversized_payloads() -> None:
    request = _log_request()
    for response in (
        _ResponseSpec({"error": {"code": "Forbidden"}}, status_code=403),
        _ResponseSpec(b"x" * (MAX_ACQUISITION_RESPONSE_BYTES + 1)),
    ):
        transport = _MockTransport(response)
        client = AzureLogAnalyticsAcquisitionClient(
            credential=_Credential(),
            reviewed_contract=_acquisition_collector_contract(),
            _transport=transport,
        )
        with pytest.raises(MonitoringAcquisitionError):
            client.query_log_analytics(request)
