from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest

from athena_context.api import evaluation_adapters
from athena_context.api.errors import DemoEvaluationConfigurationError
from athena_context.contracts.models import ResourceState
from athena_context.evidence import (
    EvidenceCollectionCommand,
    EvidenceTransportRequest,
    McpSuccessResponse,
    McpTimeoutNoResponse,
    prepare_transport_request,
)
from wc013_support import NOW, PRIVATE_ENDPOINT, build_harness


@pytest.fixture(scope="module")
def transport_request() -> EvidenceTransportRequest:
    harness = build_harness()
    command = EvidenceCollectionCommand(
        attemptId=harness.command.attempt_id,
        evidenceScope=harness.command.authorized_scope,
        authorizedScopes=(harness.command.authorized_scope,),
        bounds=harness.command.bounds,
    )
    return prepare_transport_request(
        command,
        harness.dependencies.evidence_client.trust_configuration,
        attempt_started_at=NOW,
    )


def _vm_resource(
    request: EvidenceTransportRequest,
    name: str,
    *,
    subscription_id: str | None = None,
    resource_group: str | None = None,
) -> dict[str, str]:
    return {
        "name": name,
        "id": (
            f"/subscriptions/{subscription_id or request.evidence_scope.subscription_id}"
            f"/resourceGroups/"
            f"{resource_group or request.evidence_scope.resource_group_name}"
            f"/providers/Microsoft.Compute/virtualMachines/{name}"
        ),
        "type": "Microsoft.Compute/virtualMachines",
        "location": "australiaeast",
    }


def _storage_resource(
    request: EvidenceTransportRequest,
    name: str,
) -> dict[str, str]:
    return {
        "name": name,
        "id": (
            f"/subscriptions/{request.evidence_scope.subscription_id}"
            f"/resourceGroups/{request.evidence_scope.resource_group_name}"
            f"/providers/Microsoft.Storage/storageAccounts/{name}"
        ),
        "type": "Microsoft.Storage/storageAccounts",
        "location": "australiaeast",
    }


def _inventory_content(
    request: EvidenceTransportRequest,
    resources: list[dict[str, str]],
) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request.attempt_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": 200,
                                "message": "",
                                "results": {"resources": resources},
                                "duration": 1,
                            }
                        ),
                    }
                ],
                "isError": False,
            },
        }
    ).encode()


def _inventory_outcome(
    request: EvidenceTransportRequest,
    resources: list[dict[str, str]],
    *,
    vm_states: Mapping[str, ResourceState] | None = None,
    vm_observed_at: Mapping[str, datetime] | None = None,
    inventory_observed_at: datetime | None = None,
    response_received_at: datetime = NOW,
) -> McpSuccessResponse:
    outcome = evaluation_adapters._project_azure_mcp_response(
        _inventory_content(request, resources),
        request,
        deployment_tool_name="group_resource_list",
        response_received_at=response_received_at,
        vm_states=vm_states,
        vm_observed_at=vm_observed_at,
        inventory_observed_at=inventory_observed_at,
    )
    assert isinstance(outcome, McpSuccessResponse)
    return outcome


def _target(
    request: EvidenceTransportRequest,
    name: str,
) -> evaluation_adapters._VmInventoryTarget:
    resource = _vm_resource(request, name)
    return evaluation_adapters._VmInventoryTarget(
        resource_id=resource["id"],
        vm_name=name,
    )


def _vm_response(
    request_id: str,
    target: evaluation_adapters._VmInventoryTarget,
    *,
    status_codes: list[object],
    power_state: object | None,
    command_wrapper: bool = True,
    sse_wrapper: bool = False,
    response_id: str | None = None,
    vm_resource_id: str | None = None,
    is_error: bool = False,
) -> bytes:
    statuses = [
        code if isinstance(code, dict) else {"code": code}
        for code in status_codes
    ]
    results = {
        "vm": {
            "name": target.vm_name,
            "id": vm_resource_id or target.resource_id,
            "location": "australiaeast",
            "provisioningState": "Succeeded",
        },
        "instanceView": {
            "name": target.vm_name,
            "powerState": power_state,
            "provisioningState": "Succeeded",
            "statuses": statuses,
        },
    }
    tool_payload: object = (
        {
            "status": 200,
            "message": "",
            "results": results,
            "duration": 1,
        }
        if command_wrapper
        else results
    )
    response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": response_id or request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(tool_payload),
                    }
                ],
                "isError": is_error,
            },
        },
        separators=(",", ":"),
    )
    if sse_wrapper:
        return f"event: message\ndata: {response}\n\n".encode()
    return response.encode()


@pytest.mark.parametrize(
    ("code", "power_state", "expected"),
    [
        ("PowerState/running", "running", "running"),
        ("PowerState/stopped", "stopped", "stopped"),
        ("PowerState/deallocated", "deallocated", "deallocated"),
    ],
)
def test_exact_instance_view_power_states_are_normalized(
    transport_request: EvidenceTransportRequest,
    code: str,
    power_state: str,
    expected: ResourceState,
) -> None:
    target = _target(transport_request, "vm-state-01")
    request_id = "synthetic-vm-state-call"

    state = evaluation_adapters._parse_vm_power_state_response(
        _vm_response(
            request_id,
            target,
            status_codes=[
                "ProvisioningState/succeeded",
                code,
            ],
            power_state=power_state,
        ),
        request_id=request_id,
        target=target,
    )

    assert state == expected


@pytest.mark.parametrize(
    ("command_wrapper", "sse_wrapper"),
    [
        (True, False),
        (False, False),
        (True, True),
    ],
)
def test_compute_response_wrappers_are_bounded_and_supported(
    transport_request: EvidenceTransportRequest,
    command_wrapper: bool,
    sse_wrapper: bool,
) -> None:
    target = _target(transport_request, "vm-wrapper-01")
    request_id = "synthetic-wrapper-call"

    state = evaluation_adapters._parse_vm_power_state_response(
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/running"],
            power_state="running",
            command_wrapper=command_wrapper,
            sse_wrapper=sse_wrapper,
        ),
        request_id=request_id,
        target=target,
    )

    assert state == "running"


def test_missing_conflicting_unclassified_and_malformed_states_are_unknown(
    transport_request: EvidenceTransportRequest,
) -> None:
    target = _target(transport_request, "vm-unknown-01")
    request_id = "synthetic-unknown-call"
    outside_id = _vm_resource(
        transport_request,
        target.vm_name,
        resource_group="rg-outside-authorized-scope",
    )["id"]
    responses = [
        _vm_response(
            request_id,
            target,
            status_codes=["ProvisioningState/succeeded"],
            power_state="running",
        ),
        _vm_response(
            request_id,
            target,
            status_codes=[
                "PowerState/running",
                "PowerState/stopped",
            ],
            power_state="running",
        ),
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/starting"],
            power_state="starting",
        ),
        _vm_response(
            request_id,
            target,
            status_codes=[
                "ProvisioningState/succeeded",
                "HealthState/Available",
            ],
            power_state=None,
        ),
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/running"],
            power_state="stopped",
        ),
        _vm_response(
            request_id,
            target,
            status_codes=[{"code": 7}],
            power_state=None,
        ),
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/running"],
            power_state="running",
            response_id="wrong-response-id",
        ),
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/running"],
            power_state="running",
            vm_resource_id=outside_id,
        ),
        _vm_response(
            request_id,
            target,
            status_codes=["PowerState/running"],
            power_state="running",
            is_error=True,
        ),
        b"{",
    ]

    assert all(
        evaluation_adapters._parse_vm_power_state_response(
            response,
            request_id=request_id,
            target=target,
        )
        == "unknown"
        for response in responses
    )


def test_vm_calls_are_once_each_sorted_and_non_vm_projection_is_unchanged(
    transport_request: EvidenceTransportRequest,
) -> None:
    resources = [
        _vm_resource(transport_request, "vm-c"),
        _storage_resource(transport_request, "storageone"),
        _vm_resource(transport_request, "vm-a"),
        _vm_resource(transport_request, "vm-b"),
    ]
    inventory = _inventory_outcome(transport_request, resources)
    targets = {
        target.vm_name: target
        for target in evaluation_adapters._projected_vm_targets(
            inventory,
            transport_request,
        )
    }
    desired: dict[str, tuple[str, ResourceState]] = {
        "vm-a": ("PowerState/running", "running"),
        "vm-b": ("PowerState/stopped", "stopped"),
        "vm-c": ("PowerState/deallocated", "deallocated"),
    }
    calls: list[tuple[str, str, dict[str, object], float, int]] = []

    def invoke(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        copied_arguments = dict(arguments)
        calls.append(
            (
                request_id,
                tool_name,
                copied_arguments,
                timeout_seconds,
                max_response_bytes,
            )
        )
        vm_name = cast(str, copied_arguments["vm-name"])
        code, state = desired[vm_name]
        return _vm_response(
            request_id,
            targets[vm_name],
            status_codes=[code],
            power_state=state,
        )

    deadline = transport_request.attempt_started_at + timedelta(seconds=30)
    collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=invoke,
        deadline_at=deadline,
        response_byte_budget=100_000,
        now=lambda: transport_request.attempt_started_at,
        inventory_observed_at=transport_request.attempt_started_at,
    )
    states = collection.states
    enriched = _inventory_outcome(
        transport_request,
        resources,
        vm_states=states,
    )
    items = json.loads(enriched.body)["items"]

    assert [call[2]["vm-name"] for call in calls] == [
        "vm-a",
        "vm-b",
        "vm-c",
    ]
    assert len({call[0] for call in calls}) == 3
    assert all(call[1] == "compute_vm_get" for call in calls)
    assert all(
        call[2]
        == {
            "subscription": transport_request.evidence_scope.subscription_id,
            "resource-group": (
                transport_request.evidence_scope.resource_group_name
            ),
            "vm-name": call[2]["vm-name"],
            "instance-view": True,
        }
        for call in calls
    )
    assert all(call[3] == 30 for call in calls)
    assert calls[0][4] > calls[1][4] > calls[2][4]
    assert [item["resourceId"].rsplit("/", 1)[-1] for item in items] == [
        "vm-c",
        "storageone",
        "vm-a",
        "vm-b",
    ]
    assert [item["state"] for item in items] == [
        "deallocated",
        "unknown",
        "running",
        "stopped",
    ]
    assert enriched.body == _inventory_outcome(
        transport_request,
        resources,
        vm_states=states,
    ).body


def test_vm_and_non_vm_observation_times_preserve_actual_query_times(
    transport_request: EvidenceTransportRequest,
) -> None:
    resources = [
        _vm_resource(transport_request, "vm-b"),
        _storage_resource(transport_request, "storageone"),
        _vm_resource(transport_request, "vm-a"),
    ]
    inventory = _inventory_outcome(transport_request, resources)
    targets = {
        target.vm_name: target
        for target in evaluation_adapters._projected_vm_targets(
            inventory,
            transport_request,
        )
    }
    times = iter(
        [
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=4),
        ]
    )

    def invoke(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        del tool_name, timeout_seconds, max_response_bytes
        vm_name = cast(str, arguments["vm-name"])
        return _vm_response(
            request_id,
            targets[vm_name],
            status_codes=["PowerState/running"],
            power_state="running",
        )

    collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=invoke,
        deadline_at=NOW + timedelta(seconds=30),
        response_byte_budget=100_000,
        now=lambda: next(times),
        inventory_observed_at=NOW,
    )
    enriched = _inventory_outcome(
        transport_request,
        resources,
        vm_states=collection.states,
        vm_observed_at=collection.observed_at,
        inventory_observed_at=NOW,
        response_received_at=collection.completed_at,
    )
    payload = json.loads(enriched.body)

    assert collection.completed_at == NOW + timedelta(seconds=4)
    assert payload["observedAt"] == "2025-06-01T12:00:04.000Z"
    assert [
        (item["resourceId"].rsplit("/", 1)[-1], item["observedAt"])
        for item in payload["items"]
    ] == [
        ("vm-b", "2025-06-01T12:00:04.000Z"),
        ("storageone", "2025-06-01T12:00:00.000Z"),
        ("vm-a", "2025-06-01T12:00:02.000Z"),
    ]


def test_partial_timeout_and_deadline_exhaustion_leave_only_affected_vms_unknown(
    transport_request: EvidenceTransportRequest,
) -> None:
    resources = [
        _vm_resource(transport_request, "vm-a"),
        _vm_resource(transport_request, "vm-b"),
        _vm_resource(transport_request, "vm-c"),
    ]
    inventory = _inventory_outcome(transport_request, resources)
    targets = {
        target.vm_name: target
        for target in evaluation_adapters._projected_vm_targets(
            inventory,
            transport_request,
        )
    }
    calls: list[str] = []

    def partial(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        del tool_name, timeout_seconds, max_response_bytes
        vm_name = cast(str, arguments["vm-name"])
        calls.append(vm_name)
        if vm_name == "vm-b":
            raise TimeoutError
        state = "running" if vm_name == "vm-a" else "deallocated"
        return _vm_response(
            request_id,
            targets[vm_name],
            status_codes=[f"PowerState/{state}"],
            power_state=state,
        )

    deadline = transport_request.attempt_started_at + timedelta(seconds=30)
    collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=partial,
        deadline_at=deadline,
        response_byte_budget=100_000,
        now=lambda: transport_request.attempt_started_at,
        inventory_observed_at=transport_request.attempt_started_at,
    )
    states = collection.states

    assert calls == ["vm-a", "vm-b", "vm-c"]
    assert [states[targets[name].resource_id.casefold()] for name in calls] == [
        "running",
        "unknown",
        "deallocated",
    ]

    deadline_calls: list[str] = []
    times = iter(
        [
            transport_request.attempt_started_at,
            transport_request.attempt_started_at,
            deadline,
        ]
    )

    def one_before_deadline(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        del tool_name, timeout_seconds, max_response_bytes
        vm_name = cast(str, arguments["vm-name"])
        deadline_calls.append(vm_name)
        return _vm_response(
            request_id,
            targets[vm_name],
            status_codes=["PowerState/running"],
            power_state="running",
        )

    deadline_collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=one_before_deadline,
        deadline_at=deadline,
        response_byte_budget=100_000,
        now=lambda: next(times),
        inventory_observed_at=transport_request.attempt_started_at,
    )
    deadline_states = deadline_collection.states

    assert deadline_calls == ["vm-a"]
    assert deadline_states[targets["vm-a"].resource_id.casefold()] == "running"
    assert deadline_states[targets["vm-b"].resource_id.casefold()] == "unknown"
    assert deadline_states[targets["vm-c"].resource_id.casefold()] == "unknown"

    late_times = iter(
        [
            transport_request.attempt_started_at,
            deadline + timedelta(milliseconds=1),
        ]
    )
    late_collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=one_before_deadline,
        deadline_at=deadline,
        response_byte_budget=100_000,
        now=lambda: next(late_times),
        inventory_observed_at=transport_request.attempt_started_at,
    )
    assert late_collection.deadline_exceeded is True
    assert all(state == "unknown" for state in late_collection.states.values())


def test_response_byte_budget_stops_additional_vm_calls(
    transport_request: EvidenceTransportRequest,
) -> None:
    resources = [
        _vm_resource(transport_request, "vm-a"),
        _vm_resource(transport_request, "vm-b"),
        _vm_resource(transport_request, "vm-c"),
    ]
    inventory = _inventory_outcome(transport_request, resources)
    targets = {
        target.vm_name: target
        for target in evaluation_adapters._projected_vm_targets(
            inventory,
            transport_request,
        )
    }
    first = _vm_response(
        f"{transport_request.attempt_id}-vm-state-0001",
        targets["vm-a"],
        status_codes=["PowerState/running"],
        power_state="running",
    )
    calls: list[str] = []

    def invoke(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        del tool_name, timeout_seconds
        vm_name = cast(str, arguments["vm-name"])
        calls.append(vm_name)
        if vm_name == "vm-a":
            return _vm_response(
                request_id,
                targets[vm_name],
                status_codes=["PowerState/running"],
                power_state="running",
            )
        return b"x" * (max_response_bytes + 1)

    collection = evaluation_adapters._collect_vm_power_states(
        inventory,
        transport_request,
        invoke_tool=invoke,
        deadline_at=transport_request.attempt_started_at
        + timedelta(seconds=30),
        response_byte_budget=len(first) + 1,
        now=lambda: transport_request.attempt_started_at,
        inventory_observed_at=transport_request.attempt_started_at,
    )
    states = collection.states

    assert calls == ["vm-a", "vm-b"]
    assert states[targets["vm-a"].resource_id.casefold()] == "running"
    assert states[targets["vm-b"].resource_id.casefold()] == "unknown"
    assert states[targets["vm-c"].resource_id.casefold()] == "unknown"


def test_scope_and_item_bounds_are_checked_before_vm_calls(
    transport_request: EvidenceTransportRequest,
) -> None:
    target = _target(transport_request, "vm-scope-01")
    assert evaluation_adapters._azure_mcp_vm_arguments(
        transport_request,
        target,
    ) == {
        "subscription": transport_request.evidence_scope.subscription_id,
        "resource-group": transport_request.evidence_scope.resource_group_name,
        "vm-name": target.vm_name,
        "instance-view": True,
    }
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="authorized resource-group scope",
    ):
        evaluation_adapters._scoped_vm_target(
            _vm_resource(
                transport_request,
                "vm-scope-01",
                resource_group="rg-outside-authorized-scope",
            )["id"],
            transport_request,
        )

    harness = build_harness()
    one_item_bounds = harness.command.bounds.model_copy(
        update={"max_items": 1}
    )
    bounded_command = EvidenceCollectionCommand(
        attemptId="attempt-abcdef123456",
        evidenceScope=harness.command.authorized_scope,
        authorizedScopes=(harness.command.authorized_scope,),
        bounds=one_item_bounds,
    )
    bounded_request = prepare_transport_request(
        bounded_command,
        harness.dependencies.evidence_client.trust_configuration,
        attempt_started_at=NOW,
    )
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="responseOversized",
    ):
        _inventory_outcome(
            bounded_request,
            [
                _vm_resource(bounded_request, "vm-a"),
                _vm_resource(bounded_request, "vm-b"),
            ],
        )


def test_inventory_and_vm_calls_share_the_initialized_mcp_session() -> None:
    session = evaluation_adapters._InitializedMcpSession(
        endpoint=f"{PRIVATE_ENDPOINT}/",
        credential="synthetic-managed-identity-token",
        session_id="synthetic-mcp-session",
    )
    inventory = evaluation_adapters._mcp_session_tool_request(
        session,
        request_id="attempt-inventory",
        tool_name="group_resource_list",
        arguments={
            "subscription": "11111111-1111-1111-1111-111111111111",
            "resource-group": "rg-synthetic",
            "tenant": "11111111-1111-1111-1111-111111111111",
        },
    )
    vm = evaluation_adapters._mcp_session_tool_request(
        session,
        request_id="attempt-vm-state-0001",
        tool_name="compute_vm_get",
        arguments={
            "subscription": "11111111-1111-1111-1111-111111111111",
            "resource-group": "rg-synthetic",
            "vm-name": "vm-synthetic-01",
            "instance-view": True,
        },
    )

    assert inventory.get_header("Mcp-session-id") == "synthetic-mcp-session"
    assert vm.get_header("Mcp-session-id") == "synthetic-mcp-session"
    assert json.loads(cast(bytes, inventory.data))["params"]["name"] == (
        "group_resource_list"
    )
    assert json.loads(cast(bytes, vm.data))["params"] == {
        "name": "compute_vm_get",
        "arguments": {
            "subscription": "11111111-1111-1111-1111-111111111111",
            "resource-group": "rg-synthetic",
            "vm-name": "vm-synthetic-01",
            "instance-view": True,
        },
    }
    assert "synthetic-managed-identity-token" not in repr(session)


def test_production_http_path_rejects_initialize_after_overall_deadline(
    monkeypatch: pytest.MonkeyPatch,
    transport_request: EvidenceTransportRequest,
) -> None:
    endpoint = f"{PRIVATE_ENDPOINT}/"
    deadline = transport_request.attempt_started_at + timedelta(
        milliseconds=transport_request.bounds.timeout_milliseconds
    )
    times = iter(
        [
            transport_request.attempt_started_at,
            deadline + timedelta(milliseconds=1),
            deadline + timedelta(milliseconds=1),
        ]
    )
    observed_timeouts: list[float] = []

    class SyntheticCredential:
        def get_token(self, scope: str) -> SimpleNamespace:
            assert scope == "api://athena-private-mcp/.default"
            return SimpleNamespace(token="synthetic-managed-identity-token")

    def open_response(
        http_stack: object,
        opener: object,
        request: object,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[str, int, bytes, Mapping[str, str]]:
        del http_stack, opener, max_response_bytes
        observed_timeouts.append(timeout_seconds)
        payload = json.loads(cast(bytes, request.data))
        return (
            endpoint,
            200,
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "protocolVersion": "2025-11-25",
                    },
                }
            ).encode(),
            {"mcp-session-id": "synthetic-session-001"},
        )

    monkeypatch.setattr(
        evaluation_adapters,
        "_DEFAULT_AZURE_CREDENTIAL_TYPE",
        SyntheticCredential,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION",
        SyntheticCredential.get_token,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION",
        open_response,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_now_utc_millisecond",
        lambda: next(times),
    )
    sealed = evaluation_adapters._SealedManagedIdentityPrivateMcpInvoker(
        audience="api://athena-private-mcp",
        http_stack=evaluation_adapters._ManagedIdentityPrivateMcpHttpStack(),
        private_mcp_endpoint=PRIVATE_ENDPOINT,
    )

    outcome = evaluation_adapters._invoke_managed_identity_private_mcp(
        sealed,
        PRIVATE_ENDPOINT,
        "group_resource_list",
        transport_request,
    )

    assert isinstance(outcome, McpTimeoutNoResponse)
    assert outcome.deadline_at == deadline
    assert outcome.timed_out_at > deadline
    assert observed_timeouts == [
        transport_request.bounds.timeout_milliseconds / 1_000
    ]


def test_production_http_path_enriches_each_vm_in_the_same_session(
    monkeypatch: pytest.MonkeyPatch,
    transport_request: EvidenceTransportRequest,
) -> None:
    endpoint = f"{PRIVATE_ENDPOINT}/"
    resources = [
        _vm_resource(transport_request, "vm-b"),
        _vm_resource(transport_request, "vm-a"),
        _storage_resource(transport_request, "storageone"),
    ]
    targets = {
        name: _target(transport_request, name)
        for name in ("vm-a", "vm-b")
    }
    requests: list[tuple[str, str | None, dict[str, object]]] = []

    class SyntheticCredential:
        def get_token(self, scope: str) -> SimpleNamespace:
            assert scope == "api://athena-private-mcp/.default"
            return SimpleNamespace(token="synthetic-managed-identity-token")

    def open_response(
        http_stack: object,
        opener: object,
        request: object,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[str, int, bytes, Mapping[str, str]]:
        del http_stack, opener
        assert timeout_seconds > 0
        assert max_response_bytes > 0
        http_request = cast(object, request)
        payload = json.loads(cast(bytes, http_request.data))
        method = cast(str, payload["method"])
        requests.append(
            (
                method,
                http_request.get_header("Mcp-session-id"),
                payload,
            )
        )
        if method == "initialize":
            return (
                endpoint,
                200,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "result": {
                            "protocolVersion": "2025-11-25",
                        },
                    }
                ).encode(),
                {"mcp-session-id": "synthetic-session-001"},
            )
        if method == "notifications/initialized":
            return endpoint, 202, b"", {}
        params = cast(dict[str, object], payload["params"])
        tool_name = params["name"]
        if tool_name == "group_resource_list":
            return (
                endpoint,
                200,
                _inventory_content(transport_request, resources),
                {},
            )
        assert tool_name == "compute_vm_get"
        arguments = cast(dict[str, object], params["arguments"])
        vm_name = cast(str, arguments["vm-name"])
        state = "running" if vm_name == "vm-a" else "stopped"
        return (
            endpoint,
            200,
            _vm_response(
                cast(str, payload["id"]),
                targets[vm_name],
                status_codes=[f"PowerState/{state}"],
                power_state=state,
            ),
            {},
        )

    monkeypatch.setattr(
        evaluation_adapters,
        "_DEFAULT_AZURE_CREDENTIAL_TYPE",
        SyntheticCredential,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION",
        SyntheticCredential.get_token,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION",
        open_response,
    )
    monkeypatch.setattr(
        evaluation_adapters,
        "_now_utc_millisecond",
        lambda: NOW,
    )
    sealed = evaluation_adapters._SealedManagedIdentityPrivateMcpInvoker(
        audience="api://athena-private-mcp",
        http_stack=evaluation_adapters._ManagedIdentityPrivateMcpHttpStack(),
        private_mcp_endpoint=PRIVATE_ENDPOINT,
    )

    outcome = evaluation_adapters._invoke_managed_identity_private_mcp(
        sealed,
        PRIVATE_ENDPOINT,
        "group_resource_list",
        transport_request,
    )

    assert isinstance(outcome, McpSuccessResponse)
    items = json.loads(outcome.body)["items"]
    assert [item["resourceId"].rsplit("/", 1)[-1] for item in items] == [
        "vm-b",
        "vm-a",
        "storageone",
    ]
    assert [item["state"] for item in items] == [
        "stopped",
        "running",
        "unknown",
    ]
    tool_requests = [
        entry for entry in requests if entry[0] == "tools/call"
    ]
    assert [
        cast(dict[str, object], entry[2]["params"])["name"]
        for entry in tool_requests
    ] == [
        "group_resource_list",
        "compute_vm_get",
        "compute_vm_get",
    ]
    assert [
        cast(
            dict[str, object],
            cast(dict[str, object], entry[2]["params"])["arguments"],
        ).get("vm-name")
        for entry in tool_requests[1:]
    ] == ["vm-a", "vm-b"]
    assert all(
        entry[1] == "synthetic-session-001"
        for entry in requests[1:]
    )
