from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from inspect import getattr_static
from pathlib import Path
from types import FunctionType, MappingProxyType
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    Request,
    build_opener,
)

from azure.identity import DefaultAzureCredential
from pydantic import TypeAdapter, ValidationError

from athena_context.api.domain import Actor, PublishedManifestView
from athena_context.api.errors import (
    AmbiguousLookupError,
    DemoEvaluationConfigurationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    OperatorDeploymentApproval,
    PublishedContextSelection,
    ResolvedPublishedContext,
    VerifiedWc008DeploymentConfiguration,
    Wc008DeploymentOutputAssertion,
    build_published_context_authority_token,
)
from athena_context.api.evaluation_ports import (
    SealedMcpTransportConfiguration,
    seal_mcp_transport_configuration,
    sealed_mcp_transport_configuration_primitives,
)
from athena_context.api.service import ContextService
from athena_context.contracts import (
    EvidenceGapRecord,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    canonicalize_json,
    resolve_manifest_profile,
)
from athena_context.contracts.models import ResourceState
from athena_context.evidence import (
    AZURE_RESOURCE_INVENTORY_TOOL,
    Clock,
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceClientCompositionError,
    EvidenceCollectionCommand,
    McpAuthorizationFailure,
    McpFailedResponse,
    McpSuccessResponse,
    McpTimeoutNoResponse,
    McpToolUnavailable,
    SyncAttemptReplayGuard,
    SyncEvidenceClient,
    SyncEvidenceTransport,
    SyncTrustedIngestionSigner,
    project_transport_outcome,
)
from athena_context.evidence.models import (
    EvidenceTransportRequest,
    McpTransportOutcome,
    ResourceResponseItem,
)

AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL = "group_resource_list"
AZURE_VM_GET_DEPLOYMENT_TOOL = "compute_vm_get"
_AZURE_MCP_JSON_RPC_VERSION = "2.0"
_AZURE_MCP_PROTOCOL_VERSION = "2025-11-25"
_AZURE_MCP_CLIENT_NAME = "athena-wc013-live-acceptance"
_AZURE_MCP_CLIENT_VERSION = "1.0.0"
_SUPPORTED_INVENTORY_RESOURCE_TYPES = frozenset(
    {
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Network/loadBalancers",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.OperationalInsights/workspaces",
    }
)
_VM_RESOURCE_TYPE = "Microsoft.Compute/virtualMachines"
_NORMALIZED_VM_STATES: Mapping[str, ResourceState] = MappingProxyType(
    {
        "PowerState/running": "running",
        "PowerState/stopped": "stopped",
        "PowerState/deallocated": "deallocated",
    }
)


class PrivateMcpInvokerPort(Protocol):
    def invoke(
        self,
        private_mcp_endpoint: str,
        deployment_tool_name: str,
        request: EvidenceTransportRequest,
    ) -> McpTransportOutcome: ...


class PrivateMcpAccessTokenPort(Protocol):
    def get_token(self, private_mcp_endpoint: str) -> str: ...


class ContextApiAccessTokenPort(Protocol):
    def get_token(self, audience: str) -> str: ...


def _now_utc_millisecond() -> datetime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


def _azure_mcp_tool_arguments(
    request: EvidenceTransportRequest,
) -> dict[str, str]:
    scope = request.evidence_scope.model_dump(mode="json", by_alias=True)
    if scope.get("scopeType") != "resourceGroup":
        raise DemoEvaluationConfigurationError(
            "Azure MCP resource inventory requires a resource-group scope"
        )
    subscription_id = scope.get("subscriptionId")
    resource_group_name = scope.get("resourceGroupName")
    tenant_id = scope.get("tenantId")
    if not all(
        type(value) is str and value
        for value in (subscription_id, resource_group_name, tenant_id)
    ):
        raise DemoEvaluationConfigurationError(
            "Azure MCP resource inventory scope is incomplete"
        )
    return {
        "subscription": cast(str, subscription_id),
        "resource-group": cast(str, resource_group_name),
        "tenant": cast(str, tenant_id),
    }


@dataclass(frozen=True, slots=True)
class _VmInventoryTarget:
    resource_id: str
    vm_name: str


def _azure_mcp_vm_arguments(
    request: EvidenceTransportRequest,
    target: _VmInventoryTarget,
) -> dict[str, object]:
    inventory_arguments = _azure_mcp_tool_arguments(request)
    return {
        "subscription": inventory_arguments["subscription"],
        "resource-group": inventory_arguments["resource-group"],
        "vm-name": target.vm_name,
        "instance-view": True,
    }


def _azure_mcp_failure_body(request: EvidenceTransportRequest) -> bytes:
    return canonicalize_json(
        {
            "schemaVersion": "1.0.0",
            "toolName": request.tool_name,
            "toolVersion": request.tool_version,
            "attemptId": request.attempt_id,
            "requestDigest": request.request_digest,
            "error": {
                "code": "serviceFailure",
                "status": "unavailable",
            },
        }
    ).encode("utf-8")


def _parse_mcp_json_rpc_content(content: bytes) -> object | None:
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    events = [
        event
        for event in text.replace("\r\n", "\n").split("\n\n")
        if any(line.startswith("data:") for line in event.splitlines())
    ]
    if len(events) != 1:
        return None
    data = "\n".join(
        line.removeprefix("data:").lstrip()
        for line in events[0].splitlines()
        if line.startswith("data:")
    )
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None


def _project_azure_mcp_response(
    content: bytes,
    request: EvidenceTransportRequest,
    *,
    deployment_tool_name: str,
    response_received_at: datetime,
    vm_states: Mapping[str, ResourceState] | None = None,
    vm_observed_at: Mapping[str, datetime] | None = None,
    inventory_observed_at: datetime | None = None,
) -> McpTransportOutcome:
    response = _parse_mcp_json_rpc_content(content)
    if response is None:
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    if (
        type(response) is not dict
        or response.get("jsonrpc") != _AZURE_MCP_JSON_RPC_VERSION
        or response.get("id") != request.attempt_id
    ):
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    result = response.get("result")
    if type(result) is not dict:
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    blocks = result.get("content")
    if type(blocks) is not list or len(blocks) != 1:
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    block = blocks[0]
    if (
        type(block) is not dict
        or block.get("type") != "text"
        or type(block.get("text")) is not str
    ):
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    if result.get("isError") is True:
        error_text = cast(str, block["text"]).casefold()
        if "required option" in error_text or "required parameter" in error_text:
            category = "invalidArguments"
        elif "not found" in error_text:
            category = "notFound"
        elif "forbidden" in error_text or "unauthorized" in error_text:
            category = "authorization"
        else:
            category = "unclassified"
        raise DemoEvaluationConfigurationError(
            f"private MCP tool returned a bounded error category: {category}"
        )
    try:
        tool_payload = json.loads(cast(str, block["text"]))
    except json.JSONDecodeError as exc:
        raise DemoEvaluationConfigurationError(
            "private MCP tool returned non-JSON text"
        ) from exc
    if type(tool_payload) is not dict:
        raise DemoEvaluationConfigurationError(
            "private MCP tool returned an unexpected result shape"
        )
    if set(tool_payload) == {"status", "message", "results", "duration"}:
        if (
            tool_payload.get("status") != 200
            or type(tool_payload.get("message")) is not str
            or type(tool_payload.get("duration")) is not int
            or type(tool_payload.get("results")) is not dict
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP command response failed its closed success schema"
            )
        inventory_payload = cast(dict[str, object], tool_payload["results"])
    elif set(tool_payload) == {"resources"}:
        inventory_payload = tool_payload
    else:
        raise DemoEvaluationConfigurationError(
            "private MCP tool returned an unexpected result shape"
        )
    if set(inventory_payload) not in ({"resources"}, {"Resources"}):
        raise DemoEvaluationConfigurationError(
            "private MCP inventory result failed its closed schema"
        )
    resources = (
        inventory_payload.get("resources")
        if "resources" in inventory_payload
        else inventory_payload.get("Resources")
    )
    if type(resources) is not list:
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    items: list[dict[str, object]] = []
    for resource in resources:
        if type(resource) is not dict:
            continue
        if set(resource) == {"name", "id", "type", "location"}:
            resource_id = resource.get("id")
            resource_type = resource.get("type")
            location = resource.get("location")
        elif set(resource) == {"Name", "Id", "Type", "Location"}:
            resource_id = resource.get("Id")
            resource_type = resource.get("Type")
            location = resource.get("Location")
        else:
            continue
        if resource_type not in _SUPPORTED_INVENTORY_RESOURCE_TYPES:
            continue
        normalized_resource_id = (
            cast(str, resource_id).casefold()
            if type(resource_id) is str
            else ""
        )
        item_observed_at = (
            (vm_observed_at or {}).get(
                normalized_resource_id,
                inventory_observed_at or response_received_at,
            )
            if resource_type == _VM_RESOURCE_TYPE
            else inventory_observed_at or response_received_at
        )
        projected_item = {
            "recordType": "resource",
            "observedAt": item_observed_at,
            "resourceId": resource_id,
            "resourceType": resource_type,
            "location": location,
            "availabilityZone": "unknown",
            "tags": {"managedBy": "unknown"},
            "state": (
                (vm_states or {}).get(normalized_resource_id, "unknown")
                if resource_type == _VM_RESOURCE_TYPE
                and type(resource_id) is str
                else "unknown"
            ),
        }
        try:
            validated_item = ResourceResponseItem.model_validate(projected_item)
        except ValidationError as exc:
            first_error = exc.errors(include_url=False, include_context=False)[0]
            location_path = ".".join(str(part) for part in first_error["loc"])
            raise DemoEvaluationConfigurationError(
                "private MCP inventory item failed the closed schema at "
                f"{location_path}"
            ) from exc
        items.append(
            cast(
                dict[str, object],
                validated_item.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                ),
            )
        )
    envelope = {
        "schemaVersion": "1.0.0",
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "attemptId": request.attempt_id,
        "requestDigest": request.request_digest,
        "evidenceScope": request.evidence_scope.model_dump(
            mode="json",
            by_alias=True,
        ),
        "observedAt": response_received_at,
        "items": items,
    }
    if deployment_tool_name != AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL:
        return McpSuccessResponse(
            body=content,
            response_received_at=response_received_at,
        )
    outcome = McpSuccessResponse(
        body=canonicalize_json(envelope).encode("utf-8"),
        response_received_at=response_received_at,
    )
    projection = project_transport_outcome(
        request,
        outcome,
        validated_at=response_received_at,
    )
    gaps = [
        record
        for record in projection.evidence_records
        if isinstance(record, EvidenceGapRecord)
    ]
    if gaps:
        first_gap = gaps[0]
        raise DemoEvaluationConfigurationError(
            "private MCP inventory projection failed closed: "
            f"{first_gap.gap_reason} at "
            f"{first_gap.failure_payload_pointer or 'response'}"
        )
    return outcome


def _scoped_vm_target(
    resource_id: str,
    request: EvidenceTransportRequest,
) -> _VmInventoryTarget:
    scope_arguments = _azure_mcp_tool_arguments(request)
    parts = resource_id.strip("/").split("/")
    if (
        len(parts) != 8
        or parts[0].casefold() != "subscriptions"
        or parts[2].casefold() != "resourcegroups"
        or parts[4].casefold() != "providers"
        or parts[5].casefold() != "microsoft.compute"
        or parts[6].casefold() != "virtualmachines"
        or parts[1].casefold()
        != scope_arguments["subscription"].casefold()
        or parts[3].casefold()
        != scope_arguments["resource-group"].casefold()
        or not parts[7]
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP inventory VM escaped the authorized resource-group scope"
        )
    return _VmInventoryTarget(
        resource_id=resource_id,
        vm_name=parts[7],
    )


def _projected_vm_targets(
    outcome: McpTransportOutcome,
    request: EvidenceTransportRequest,
) -> tuple[_VmInventoryTarget, ...]:
    if not isinstance(outcome, McpSuccessResponse):
        return ()
    try:
        envelope = json.loads(outcome.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ()
    expected_keys = {
        "schemaVersion",
        "toolName",
        "toolVersion",
        "attemptId",
        "requestDigest",
        "evidenceScope",
        "observedAt",
        "items",
    }
    if type(envelope) is not dict or set(envelope) != expected_keys:
        return ()
    items = envelope.get("items")
    if type(items) is not list:
        return ()
    if len(items) > request.bounds.max_items:
        raise DemoEvaluationConfigurationError(
            "private MCP inventory exceeded the approved item bound"
        )
    targets_by_id: dict[str, _VmInventoryTarget] = {}
    for item in items:
        if type(item) is not dict or item.get("resourceType") != _VM_RESOURCE_TYPE:
            continue
        resource_id = item.get("resourceId")
        if type(resource_id) is not str:
            raise DemoEvaluationConfigurationError(
                "private MCP inventory VM omitted its resource ID"
            )
        target = _scoped_vm_target(resource_id, request)
        normalized_id = target.resource_id.casefold()
        if normalized_id in targets_by_id:
            raise DemoEvaluationConfigurationError(
                "private MCP inventory returned a duplicate VM resource"
            )
        targets_by_id[normalized_id] = target
    return tuple(
        sorted(
            targets_by_id.values(),
            key=lambda target: target.resource_id.casefold(),
        )
    )


def _mcp_tool_result_payload(
    content: bytes,
    *,
    request_id: str,
) -> dict[str, object] | None:
    response = _parse_mcp_json_rpc_content(content)
    if (
        type(response) is not dict
        or set(response) != {"jsonrpc", "id", "result"}
        or response.get("jsonrpc") != _AZURE_MCP_JSON_RPC_VERSION
        or response.get("id") != request_id
    ):
        return None
    result = response.get("result")
    if (
        type(result) is not dict
        or set(result) != {"content", "isError"}
        or result.get("isError") is not False
    ):
        return None
    blocks = result.get("content")
    if type(blocks) is not list or len(blocks) != 1:
        return None
    block = blocks[0]
    if (
        type(block) is not dict
        or set(block) != {"type", "text"}
        or block.get("type") != "text"
        or type(block.get("text")) is not str
    ):
        return None
    try:
        tool_payload = json.loads(cast(str, block["text"]))
    except json.JSONDecodeError:
        return None
    if type(tool_payload) is not dict:
        return None
    if set(tool_payload) == {"status", "message", "results", "duration"}:
        if (
            tool_payload.get("status") != 200
            or type(tool_payload.get("message")) is not str
            or type(tool_payload.get("duration")) is not int
            or type(tool_payload.get("results")) is not dict
        ):
            return None
        return cast(dict[str, object], tool_payload["results"])
    return cast(dict[str, object], tool_payload)


def _parse_vm_power_state_response(
    content: bytes,
    *,
    request_id: str,
    target: _VmInventoryTarget,
) -> ResourceState:
    payload = _mcp_tool_result_payload(
        content,
        request_id=request_id,
    )
    if payload is None:
        return "unknown"
    if set(payload) == {"vm", "instanceView"}:
        vm = payload.get("vm")
        instance_view = payload.get("instanceView")
    elif set(payload) == {"Vm", "InstanceView"}:
        vm = payload.get("Vm")
        instance_view = payload.get("InstanceView")
    else:
        return "unknown"

    allowed_vm_keys = {
        "name",
        "id",
        "location",
        "vmSize",
        "provisioningState",
        "osType",
        "licenseType",
        "zones",
        "tags",
    }
    if (
        type(vm) is not dict
        or not {"name", "id"}.issubset(vm)
        or not set(vm).issubset(allowed_vm_keys)
        or type(vm.get("name")) is not str
        or type(vm.get("id")) is not str
        or cast(str, vm["name"]).casefold() != target.vm_name.casefold()
        or cast(str, vm["id"]).casefold()
        != target.resource_id.casefold()
    ):
        return "unknown"

    allowed_instance_view_keys = {
        "name",
        "powerState",
        "provisioningState",
        "vmAgent",
        "disks",
        "extensions",
        "statuses",
    }
    if (
        type(instance_view) is not dict
        or not {"name", "statuses"}.issubset(instance_view)
        or not set(instance_view).issubset(allowed_instance_view_keys)
        or type(instance_view.get("name")) is not str
        or cast(str, instance_view["name"]).casefold()
        != target.vm_name.casefold()
        or type(instance_view.get("statuses")) is not list
    ):
        return "unknown"

    status_codes: list[str] = []
    allowed_status_keys = {
        "code",
        "level",
        "displayStatus",
        "message",
        "time",
    }
    for status in cast(list[object], instance_view["statuses"]):
        if (
            type(status) is not dict
            or "code" not in status
            or not set(status).issubset(allowed_status_keys)
            or type(status.get("code")) is not str
            or any(
                value is not None and type(value) is not str
                for key, value in status.items()
                if key != "code"
            )
        ):
            return "unknown"
        code = cast(str, status["code"])
        if code.startswith("PowerState/"):
            status_codes.append(code)
    if len(status_codes) != 1:
        return "unknown"
    normalized_state = _NORMALIZED_VM_STATES.get(status_codes[0])
    if normalized_state is None:
        return "unknown"
    declared_power_state = instance_view.get("powerState")
    if declared_power_state is not None and (
        type(declared_power_state) is not str
        or cast(str, declared_power_state).casefold() != normalized_state
    ):
        return "unknown"
    return normalized_state


type _VmToolInvoker = Callable[
    [str, str, Mapping[str, object], float, int],
    bytes | None,
]


@dataclass(frozen=True, slots=True)
class _VmPowerStateCollection:
    states: Mapping[str, ResourceState]
    observed_at: Mapping[str, datetime]
    completed_at: datetime
    deadline_exceeded: bool


def _collect_vm_power_states(
    inventory_outcome: McpTransportOutcome,
    request: EvidenceTransportRequest,
    *,
    invoke_tool: _VmToolInvoker,
    deadline_at: datetime,
    response_byte_budget: int,
    now: Callable[[], datetime],
    inventory_observed_at: datetime | None = None,
) -> _VmPowerStateCollection:
    targets = _projected_vm_targets(inventory_outcome, request)
    states: dict[str, ResourceState] = {
        target.resource_id.casefold(): "unknown"
        for target in targets
    }
    baseline_observed_at = inventory_observed_at or request.attempt_started_at
    observed_at = {
        target.resource_id.casefold(): baseline_observed_at
        for target in targets
    }
    completed_at = baseline_observed_at
    remaining_bytes = max(response_byte_budget, 0)
    for index, target in enumerate(targets, start=1):
        current = now()
        if current >= deadline_at or remaining_bytes <= 0:
            break
        request_id = f"{request.attempt_id}-vm-state-{index:04d}"
        timeout_seconds = max(
            (deadline_at - current).total_seconds(),
            0.001,
        )
        try:
            content = invoke_tool(
                request_id,
                AZURE_VM_GET_DEPLOYMENT_TOOL,
                _azure_mcp_vm_arguments(request, target),
                timeout_seconds,
                remaining_bytes,
            )
        except TimeoutError:
            content = None
        received_at = now()
        if received_at > deadline_at:
            return _VmPowerStateCollection(
                states=MappingProxyType(states),
                observed_at=MappingProxyType(observed_at),
                completed_at=received_at,
                deadline_exceeded=True,
            )
        normalized_id = target.resource_id.casefold()
        observed_at[normalized_id] = received_at
        completed_at = max(completed_at, received_at)
        if content is None:
            continue
        if len(content) > remaining_bytes:
            break
        remaining_bytes -= len(content)
        states[normalized_id] = _parse_vm_power_state_response(
            content,
            request_id=request_id,
            target=target,
        )
    return _VmPowerStateCollection(
        states=MappingProxyType(states),
        observed_at=MappingProxyType(observed_at),
        completed_at=completed_at,
        deadline_exceeded=False,
    )


class PublishedContextReaderPort(Protocol):
    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView: ...

    def list_published(self, manifest_id: str) -> tuple[PublishedManifestView, ...]: ...


class _RejectRedirectHandler(HTTPRedirectHandler):
    """Never forward an Athena managed-identity bearer token through a redirect."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


_REJECT_REDIRECT_IMPLEMENTATION = _RejectRedirectHandler.redirect_request
_URLLIB_BUILD_OPENER_IMPLEMENTATION = build_opener
_URLLIB_OPENER_OPEN_IMPLEMENTATION = OpenerDirector.open


class DefaultAzureCredentialContextApiToken:
    """Keyless Context API token provider for explicitly configured live runs."""

    def __init__(self) -> None:
        self._credential = DefaultAzureCredential()

    def get_token(self, audience: str) -> str:
        scope = f"{audience.rstrip('/')}/.default"
        return self._credential.get_token(scope).token


class DefaultAzureCredentialPrivateMcpToken:
    """Keyless token provider pinned to one private MCP endpoint and audience."""

    _audience: str
    _credential: DefaultAzureCredential
    _private_mcp_endpoint: str

    __slots__ = (
        "_audience",
        "_credential",
        "_private_mcp_endpoint",
    )

    def __init__(
        self,
        *,
        private_mcp_endpoint: str,
        audience: str,
    ) -> None:
        parsed = urlsplit(private_mcp_endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP token endpoint must be a trusted HTTPS origin"
            )
        if (
            type(audience) is not str
            or not audience.strip()
            or audience != audience.strip()
            or len(audience) > 512
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP managed identity audience is required"
            )
        object.__setattr__(self, "_private_mcp_endpoint", private_mcp_endpoint.rstrip("/"))
        object.__setattr__(self, "_audience", audience)
        object.__setattr__(self, "_credential", DefaultAzureCredential())

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP token provider composition is immutable")

    def get_token(self, private_mcp_endpoint: str) -> str:
        if private_mcp_endpoint.rstrip("/") != self._private_mcp_endpoint:
            raise DemoEvaluationConfigurationError(
                "private MCP token request did not match its pinned endpoint"
            )
        credential = object.__getattribute__(self, "_credential")
        if (
            type(credential) is not _DEFAULT_AZURE_CREDENTIAL_TYPE
            or getattr_static(
                _DEFAULT_AZURE_CREDENTIAL_TYPE,
                "get_token",
                None,
            )
            is not _DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP managed identity credential composition changed"
            )
        scope = f"{self._audience.rstrip('/')}/.default"
        return _DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION(
            credential,
            scope,
        ).token


_DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION = (
    DefaultAzureCredential.get_token
)
_DEFAULT_AZURE_CREDENTIAL_TYPE = DefaultAzureCredential


class _ManagedIdentityPrivateMcpHttpStack:
    """Zero-state HTTP stack constructed only by the production invoker."""

    __slots__ = ()

    def build_opener(self) -> OpenerDirector:
        if (
            getattr_static(_RejectRedirectHandler, "redirect_request", None)
            is not _REJECT_REDIRECT_IMPLEMENTATION
            or getattr_static(OpenerDirector, "open", None)
            is not _URLLIB_OPENER_OPEN_IMPLEMENTATION
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP redirect rejection stack changed"
            )
        opener = _URLLIB_BUILD_OPENER_IMPLEMENTATION(
            _RejectRedirectHandler()
        )
        if type(opener) is not OpenerDirector:
            raise DemoEvaluationConfigurationError(
                "private MCP HTTP stack construction was not concrete"
            )
        return opener

    def open(
        self,
        opener: OpenerDirector,
        request: Request,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[str, int, bytes, Mapping[str, str]]:
        if type(opener) is not OpenerDirector:
            raise DemoEvaluationConfigurationError(
                "private MCP HTTP opener changed before invocation"
            )
        with _URLLIB_OPENER_OPEN_IMPLEMENTATION(
            opener,
            request,
            timeout=timeout_seconds,
        ) as response:
            response_url = response.geturl()
            status_code = response.getcode()
            headers = MappingProxyType(
                {
                    name.lower(): value
                    for name, value in response.headers.items()
                }
            )
            content = response.read(max_response_bytes + 1)
        return response_url, status_code, content, headers


_MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION = (
    _ManagedIdentityPrivateMcpHttpStack.open
)
_MANAGED_IDENTITY_HTTP_BUILD_IMPLEMENTATION = (
    _ManagedIdentityPrivateMcpHttpStack.build_opener
)


class ManagedIdentityPrivateMcpInvoker:
    """Production MCP boundary with no caller-injected bearer or HTTP dependency."""

    _audience: str
    _http_stack: _ManagedIdentityPrivateMcpHttpStack
    _private_mcp_endpoint: str

    __slots__ = (
        "_audience",
        "_http_stack",
        "_private_mcp_endpoint",
    )

    def __init__(
        self,
        *,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        audience: str,
    ) -> None:
        try:
            _, sealed = seal_mcp_transport_configuration(
                deployment_configuration
            )
            _, endpoint = sealed_mcp_transport_configuration_primitives(sealed)
        except ValueError as exc:
            raise DemoEvaluationConfigurationError(
                "managed identity MCP invoker requires exact trusted WC-008 "
                "deployment configuration"
            ) from exc
        if (
            type(audience) is not str
            or not audience.strip()
            or audience != audience.strip()
            or len(audience) > 512
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP managed identity audience is required"
            )
        object.__setattr__(self, "_private_mcp_endpoint", endpoint)
        object.__setattr__(self, "_audience", str.__str__(audience))
        object.__setattr__(
            self,
            "_http_stack",
            _ManagedIdentityPrivateMcpHttpStack(),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP invoker composition is immutable")

    def invoke(
        self,
        private_mcp_endpoint: str,
        deployment_tool_name: str,
        request: EvidenceTransportRequest,
    ) -> McpTransportOutcome:
        sealed = _seal_managed_identity_private_mcp_invoker(self)
        return _invoke_managed_identity_private_mcp(
            sealed,
            private_mcp_endpoint,
            deployment_tool_name,
            request,
        )


_MANAGED_IDENTITY_MCP_INVOKE_IMPLEMENTATION = (
    ManagedIdentityPrivateMcpInvoker.invoke
)


@dataclass(frozen=True, slots=True)
class _SealedManagedIdentityPrivateMcpInvoker:
    audience: str
    http_stack: _ManagedIdentityPrivateMcpHttpStack
    private_mcp_endpoint: str


def _seal_managed_identity_private_mcp_invoker(
    invoker: ManagedIdentityPrivateMcpInvoker,
) -> _SealedManagedIdentityPrivateMcpInvoker:
    try:
        audience = object.__getattribute__(invoker, "_audience")
        http_stack = object.__getattribute__(invoker, "_http_stack")
        endpoint = object.__getattribute__(invoker, "_private_mcp_endpoint")
    except AttributeError as exc:
        raise DemoEvaluationConfigurationError(
            "private MCP managed identity composition is incomplete"
        ) from exc
    if (
        type(invoker) is not ManagedIdentityPrivateMcpInvoker
        or type(audience) is not str
        or type(endpoint) is not str
        or type(http_stack) is not _ManagedIdentityPrivateMcpHttpStack
        or getattr_static(
            _DEFAULT_AZURE_CREDENTIAL_TYPE,
            "get_token",
            None,
        )
        is not _DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION
        or getattr_static(_ManagedIdentityPrivateMcpHttpStack, "open", None)
        is not _MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION
        or getattr_static(
            _ManagedIdentityPrivateMcpHttpStack,
            "build_opener",
            None,
        )
        is not _MANAGED_IDENTITY_HTTP_BUILD_IMPLEMENTATION
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP managed identity composition changed"
        )
    return _SealedManagedIdentityPrivateMcpInvoker(
        audience=str.__str__(audience),
        http_stack=http_stack,
        private_mcp_endpoint=str.__str__(endpoint),
    )


def _mcp_http_request(
    endpoint: str,
    credential: str,
    payload: Mapping[str, object],
    *,
    protocol_version: str | None = None,
    session_id: str | None = None,
) -> Request:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer" + " " + credential,
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
    }
    if protocol_version is not None:
        headers["MCP-Protocol-Version"] = protocol_version
    if session_id is not None:
        if (
            not session_id
            or session_id != session_id.strip()
            or any(character in session_id for character in "\r\n")
        ):
            raise DemoEvaluationConfigurationError(
                "private MCP returned an invalid session identifier"
            )
        headers["Mcp-Session-Id"] = session_id
    body = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return Request(  # noqa: S310 - endpoint was operator-sealed as HTTPS
        endpoint,
        data=body,
        headers=headers,
        method="POST",
    )


@dataclass(frozen=True, slots=True)
class _InitializedMcpSession:
    endpoint: str
    credential: str = field(repr=False)
    session_id: str | None


def _mcp_session_tool_request(
    session: _InitializedMcpSession,
    *,
    request_id: str,
    tool_name: str,
    arguments: Mapping[str, object],
) -> Request:
    return _mcp_http_request(
        session.endpoint,
        session.credential,
        {
            "jsonrpc": _AZURE_MCP_JSON_RPC_VERSION,
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": dict(arguments),
            },
        },
        protocol_version=_AZURE_MCP_PROTOCOL_VERSION,
        session_id=session.session_id,
    )


def _validate_mcp_initialize_response(
    content: bytes,
    *,
    request_id: str,
) -> None:
    response = _parse_mcp_json_rpc_content(content)
    if (
        type(response) is not dict
        or response.get("jsonrpc") != _AZURE_MCP_JSON_RPC_VERSION
        or response.get("id") != request_id
        or type(response.get("result")) is not dict
        or response["result"].get("protocolVersion")
        != _AZURE_MCP_PROTOCOL_VERSION
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP initialize response did not match the reviewed protocol"
        )


def _remaining_mcp_timeout_seconds(deadline_at: datetime) -> float | None:
    remaining = (deadline_at - _now_utc_millisecond()).total_seconds()
    return max(remaining, 0.001) if remaining > 0 else None


def _mcp_deadline_timeout(
    deadline_at: datetime,
) -> McpTimeoutNoResponse:
    timed_out_at = _now_utc_millisecond()
    if timed_out_at <= deadline_at:
        timed_out_at = deadline_at + timedelta(milliseconds=1)
    return McpTimeoutNoResponse(
        deadline_at=deadline_at,
        timed_out_at=timed_out_at,
    )


def _invoke_managed_identity_private_mcp(
    sealed: _SealedManagedIdentityPrivateMcpInvoker,
    private_mcp_endpoint: str,
    deployment_tool_name: str,
    request: EvidenceTransportRequest,
) -> McpTransportOutcome:
    endpoint_origin = str.__str__(private_mcp_endpoint).rstrip("/")
    if endpoint_origin != sealed.private_mcp_endpoint:
        raise DemoEvaluationConfigurationError(
            "private MCP invocation did not match the credential endpoint"
        )
    deadline_at = request.attempt_started_at + timedelta(
        milliseconds=request.bounds.timeout_milliseconds
    )
    opener = _MANAGED_IDENTITY_HTTP_BUILD_IMPLEMENTATION(sealed.http_stack)
    scope = f"{sealed.audience.rstrip('/')}/.default"
    credential_provider = _DEFAULT_AZURE_CREDENTIAL_TYPE()
    if type(credential_provider) is not _DEFAULT_AZURE_CREDENTIAL_TYPE:
        raise DemoEvaluationConfigurationError(
            "private MCP managed identity credential construction changed"
        )
    credential = _DEFAULT_AZURE_CREDENTIAL_GET_TOKEN_IMPLEMENTATION(
        credential_provider,
        scope,
    ).token
    if (
        type(credential) is not str
        or not credential
        or credential != credential.strip()
        or any(character in credential for character in "\r\n")
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP managed identity returned an invalid credential"
        )
    endpoint = f"{endpoint_origin}/"
    initialize_id = f"{request.attempt_id}-initialize"
    initialize = _mcp_http_request(
        endpoint,
        credential,
        {
            "jsonrpc": _AZURE_MCP_JSON_RPC_VERSION,
            "id": initialize_id,
            "method": "initialize",
            "params": {
                "protocolVersion": _AZURE_MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": _AZURE_MCP_CLIENT_NAME,
                    "version": _AZURE_MCP_CLIENT_VERSION,
                },
            },
        },
    )
    initialize_timeout = _remaining_mcp_timeout_seconds(deadline_at)
    if initialize_timeout is None:
        return _mcp_deadline_timeout(deadline_at)
    try:
        initialize_url, initialize_status, initialize_content, initialize_headers = (
            _MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION(
                sealed.http_stack,
                opener,
                initialize,
                timeout_seconds=initialize_timeout,
                max_response_bytes=request.bounds.max_response_bytes,
            )
        )
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DemoEvaluationConfigurationError(
                "private MCP initialize redirect was rejected"
            ) from exc
        if exc.code in {401, 403}:
            return McpAuthorizationFailure(
                authorization_status="denied",
                observed_at=_now_utc_millisecond(),
            )
        raise DemoEvaluationConfigurationError(
            f"private MCP initialize returned HTTP {exc.code}"
        ) from exc
    except TimeoutError:
        return _mcp_deadline_timeout(deadline_at)
    except URLError:
        return McpToolUnavailable(
            unavailable_reason="networkUnavailable",
            observed_at=_now_utc_millisecond(),
        )
    if _now_utc_millisecond() > deadline_at:
        return _mcp_deadline_timeout(deadline_at)
    if (
        initialize_url != endpoint
        or not 200 <= initialize_status < 300
        or not initialize_content
        or len(initialize_content) > request.bounds.max_response_bytes
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP returned an untrusted initialize response"
        )
    _validate_mcp_initialize_response(
        initialize_content,
        request_id=initialize_id,
    )
    session_id = initialize_headers.get("mcp-session-id")
    session = _InitializedMcpSession(
        endpoint=endpoint,
        credential=credential,
        session_id=session_id,
    )
    initialized = _mcp_http_request(
        endpoint,
        credential,
        {
            "jsonrpc": _AZURE_MCP_JSON_RPC_VERSION,
            "method": "notifications/initialized",
            "params": {},
        },
        protocol_version=_AZURE_MCP_PROTOCOL_VERSION,
        session_id=session_id,
    )
    initialized_timeout = _remaining_mcp_timeout_seconds(deadline_at)
    if initialized_timeout is None:
        return _mcp_deadline_timeout(deadline_at)
    try:
        initialized_url, initialized_status, initialized_content, _ = (
            _MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION(
                sealed.http_stack,
                opener,
                initialized,
                timeout_seconds=initialized_timeout,
                max_response_bytes=request.bounds.max_response_bytes,
            )
        )
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DemoEvaluationConfigurationError(
                "private MCP initialized notification redirect was rejected"
            ) from exc
        if exc.code in {401, 403}:
            return McpAuthorizationFailure(
                authorization_status="denied",
                observed_at=_now_utc_millisecond(),
            )
        raise DemoEvaluationConfigurationError(
            f"private MCP initialized notification returned HTTP {exc.code}"
        ) from exc
    except TimeoutError:
        return _mcp_deadline_timeout(deadline_at)
    except URLError:
        return McpToolUnavailable(
            unavailable_reason="networkUnavailable",
            observed_at=_now_utc_millisecond(),
        )
    if _now_utc_millisecond() > deadline_at:
        return _mcp_deadline_timeout(deadline_at)
    if (
        initialized_url != endpoint
        or not 200 <= initialized_status < 300
        or len(initialized_content) > request.bounds.max_response_bytes
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP rejected the initialized notification"
        )
    outbound = _mcp_session_tool_request(
        session,
        request_id=request.attempt_id,
        tool_name=deployment_tool_name,
        arguments=_azure_mcp_tool_arguments(request),
    )
    inventory_timeout = _remaining_mcp_timeout_seconds(deadline_at)
    if inventory_timeout is None:
        return _mcp_deadline_timeout(deadline_at)
    try:
        response_url, status_code, content, _ = (
            _MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION(
                sealed.http_stack,
                opener,
                outbound,
                timeout_seconds=inventory_timeout,
                max_response_bytes=request.bounds.max_response_bytes,
            )
        )
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DemoEvaluationConfigurationError(
                "private MCP HTTP redirect was rejected"
            ) from exc
        observed_at = _now_utc_millisecond()
        if exc.code in {401, 403}:
            return McpAuthorizationFailure(
                authorization_status="denied",
                observed_at=observed_at,
            )
        content = exc.read(request.bounds.max_response_bytes + 1)
        if not content or len(content) > request.bounds.max_response_bytes:
            return McpToolUnavailable(
                unavailable_reason="mcpUnavailable",
                observed_at=observed_at,
            )
        return McpFailedResponse(
            body=_azure_mcp_failure_body(request),
            response_received_at=observed_at,
        )
    except TimeoutError:
        return _mcp_deadline_timeout(deadline_at)
    except URLError:
        return McpToolUnavailable(
            unavailable_reason="networkUnavailable",
            observed_at=_now_utc_millisecond(),
        )
    inventory_received_at = _now_utc_millisecond()
    if inventory_received_at > deadline_at:
        return _mcp_deadline_timeout(deadline_at)
    if (
        response_url != endpoint
        or not 200 <= status_code < 300
        or not content
        or len(content) > request.bounds.max_response_bytes
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP returned an untrusted HTTP response"
        )
    inventory_outcome = _project_azure_mcp_response(
        content,
        request,
        deployment_tool_name=deployment_tool_name,
        response_received_at=inventory_received_at,
    )

    def invoke_vm_tool(
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        remaining_timeout_seconds: float,
        remaining_response_bytes: int,
    ) -> bytes | None:
        vm_request = _mcp_session_tool_request(
            session,
            request_id=request_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        try:
            vm_url, vm_status, vm_content, _ = (
                _MANAGED_IDENTITY_HTTP_OPEN_IMPLEMENTATION(
                    sealed.http_stack,
                    opener,
                    vm_request,
                    timeout_seconds=remaining_timeout_seconds,
                    max_response_bytes=remaining_response_bytes,
                )
            )
        except (HTTPError, URLError, TimeoutError):
            return None
        if (
            vm_url != endpoint
            or not 200 <= vm_status < 300
            or not vm_content
        ):
            return None
        return vm_content

    vm_collection = _collect_vm_power_states(
        inventory_outcome,
        request,
        invoke_tool=invoke_vm_tool,
        deadline_at=deadline_at,
        response_byte_budget=request.bounds.max_response_bytes - len(content),
        now=_now_utc_millisecond,
        inventory_observed_at=inventory_received_at,
    )
    if vm_collection.deadline_exceeded:
        return _mcp_deadline_timeout(deadline_at)
    if not vm_collection.states:
        return inventory_outcome
    return _project_azure_mcp_response(
        content,
        request,
        deployment_tool_name=deployment_tool_name,
        response_received_at=vm_collection.completed_at,
        vm_states=vm_collection.states,
        vm_observed_at=vm_collection.observed_at,
        inventory_observed_at=inventory_received_at,
    )


class EnvironmentContextApiPublishedContextReader:
    """Bounded HTTPS reader for the authoritative deployed Context API."""

    _MAX_RESPONSE_BYTES = 4_194_304

    def __init__(
        self,
        environment: Mapping[str, str] | None = None,
        *,
        token_provider: ContextApiAccessTokenPort | None = None,
    ) -> None:
        values = dict(os.environ if environment is None else environment)
        endpoint = values.get("ATHENA_WC013_CONTEXT_API_ENDPOINT", "").rstrip("/")
        audience = values.get("ATHENA_WC013_CONTEXT_API_AUDIENCE", "")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise DemoEvaluationConfigurationError(
                "live Context API endpoint must be a trusted HTTPS origin"
            )
        if (
            not audience.strip()
            or audience != audience.strip()
            or len(audience) > 512
        ):
            raise DemoEvaluationConfigurationError(
                "live Context API managed identity audience is required"
            )
        self._endpoint = endpoint
        self._audience = audience
        self._token_provider = (
            token_provider or DefaultAzureCredentialContextApiToken()
        )
        self._opener = build_opener(_RejectRedirectHandler())

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        path = (
            f"/v1/manifests/{quote(manifest_id, safe='')}/versions/"
            f"{quote(manifest_version, safe='')}"
        )
        return PublishedManifestView.model_validate_json(self._request(path))

    def list_published(
        self,
        manifest_id: str,
    ) -> tuple[PublishedManifestView, ...]:
        path = f"/v1/manifests/{quote(manifest_id, safe='')}/versions"
        return tuple(
            TypeAdapter(list[PublishedManifestView]).validate_json(
                self._request(path)
            )
        )

    def _request(self, path: str) -> bytes:
        credential = self._token_provider.get_token(self._audience)
        request = Request(  # noqa: S310 - endpoint was restricted to HTTPS above
            f"{self._endpoint}{path}",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Authorization": f"Bearer {credential}",
            },
            method="GET",
        )
        try:
            with self._opener.open(  # noqa: S310
                request,
                timeout=10,
            ) as response:
                content = response.read(self._MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404:
                raise ResourceNotFoundError(
                    "selected published Context API record was not found"
                ) from exc
            raise DemoEvaluationConfigurationError(
                "authoritative Context API rejected the live resolution"
            ) from exc
        except URLError as exc:
            raise DemoEvaluationConfigurationError(
                "authoritative Context API is unavailable"
            ) from exc
        if not content or len(content) > self._MAX_RESPONSE_BYTES:
            raise DemoEvaluationConfigurationError(
                "authoritative Context API response exceeded its bound"
            )
        return content


type _PrivateMcpInvokeImplementation = Callable[
    [object, str, str, EvidenceTransportRequest],
    McpTransportOutcome,
]


@dataclass(frozen=True, slots=True)
class _PrivateMcpInvokerBinding:
    invoker: PrivateMcpInvokerPort
    invoker_type: type[object]
    invoke_implementation: _PrivateMcpInvokeImplementation
    managed_identity: _SealedManagedIdentityPrivateMcpInvoker | None


def _static_instance_state(instance: object) -> Mapping[str, object] | None:
    try:
        state = object.__getattribute__(instance, "__dict__")
    except AttributeError:
        return None
    if type(state) is not dict:
        raise DemoEvaluationConfigurationError(
            "private MCP invoker has non-concrete instance state"
        )
    return MappingProxyType(cast(dict[str, object], state))


def _has_instance_invoke_override(instance: object) -> bool:
    state = _static_instance_state(instance)
    return state is not None and "invoke" in state


def _validate_invoker_instance_state(invoker: object) -> Mapping[str, object] | None:
    state = _static_instance_state(invoker)
    if state is None:
        return None
    for value in state.values():
        if callable(value):
            raise DemoEvaluationConfigurationError(
                "private MCP invoker instance state contains mutable dispatch"
            )
    return state


def _copy_invoker_with_sealed_state[Invoker: PrivateMcpInvokerPort](
    invoker: Invoker,
) -> Invoker:
    state = _validate_invoker_instance_state(invoker)
    if state is None:
        return invoker
    sealed = object.__new__(type(invoker))
    sealed_state = object.__getattribute__(sealed, "__dict__")
    if type(sealed_state) is not dict:
        raise DemoEvaluationConfigurationError(
            "private MCP invoker has non-concrete instance state"
        )
    for name, value in state.items():
        sealed_state[str.__str__(name)] = value
    return cast(Invoker, sealed)


def _seal_private_mcp_invoker(
    invoker: PrivateMcpInvokerPort,
) -> _PrivateMcpInvokerBinding:
    invoker_type = type(invoker)
    implementation = getattr_static(invoker_type, "invoke", None)
    if (
        type(implementation) is not FunctionType
        or (
            invoker_type is ManagedIdentityPrivateMcpInvoker
            and implementation is not _MANAGED_IDENTITY_MCP_INVOKE_IMPLEMENTATION
        )
        or _has_instance_invoke_override(invoker)
    ):
        raise DemoEvaluationConfigurationError(
            "private MCP invoker must expose one concrete unmodified implementation"
        )
    sealed_invoker = _copy_invoker_with_sealed_state(invoker)
    managed_identity = (
        _seal_managed_identity_private_mcp_invoker(
            cast(ManagedIdentityPrivateMcpInvoker, sealed_invoker)
        )
        if invoker_type is ManagedIdentityPrivateMcpInvoker
        else None
    )
    return _PrivateMcpInvokerBinding(
        invoker=sealed_invoker,
        invoker_type=invoker_type,
        invoke_implementation=cast(
            _PrivateMcpInvokeImplementation,
            implementation,
        ),
        managed_identity=managed_identity,
    )


def _require_exact_private_mcp_invoker(
    binding: _PrivateMcpInvokerBinding,
) -> None:
    try:
        current_managed_identity = (
            _seal_managed_identity_private_mcp_invoker(
                cast(ManagedIdentityPrivateMcpInvoker, binding.invoker)
            )
            if binding.managed_identity is not None
            else None
        )
        invalid = (
            type(binding.invoker) is not binding.invoker_type
            or getattr_static(binding.invoker_type, "invoke", None)
            is not binding.invoke_implementation
            or _has_instance_invoke_override(binding.invoker)
            or not _same_managed_identity_invoker_seal(
                current_managed_identity,
                binding.managed_identity,
            )
        )
        _validate_invoker_instance_state(binding.invoker)
    except DemoEvaluationConfigurationError as exc:
        raise EvidenceClientCompositionError(
            "private MCP invoker composition changed after composition"
        ) from exc
    if invalid:
        raise EvidenceClientCompositionError(
            "private MCP invoker implementation changed after composition"
        )


def _same_managed_identity_invoker_seal(
    current: _SealedManagedIdentityPrivateMcpInvoker | None,
    expected: _SealedManagedIdentityPrivateMcpInvoker | None,
) -> bool:
    if current is None or expected is None:
        return current is expected
    return (
        current.audience == expected.audience
        and current.private_mcp_endpoint == expected.private_mcp_endpoint
        and current.http_stack is expected.http_stack
    )


class PrivateMcpEvidenceTransport:
    """Own the immutable verified WC-008 identity used for every MCP invocation."""

    _deployment_configuration: VerifiedWc008DeploymentConfiguration
    _invoker_binding: _PrivateMcpInvokerBinding
    _transport_configuration: SealedMcpTransportConfiguration

    __slots__ = (
        "_deployment_configuration",
        "_invoker_binding",
        "_transport_configuration",
    )

    def __init__(
        self,
        *,
        deployment_configuration: VerifiedWc008DeploymentConfiguration,
        invoker: PrivateMcpInvokerPort,
    ) -> None:
        try:
            normalized, sealed = seal_mcp_transport_configuration(
                deployment_configuration
            )
        except ValueError as exc:
            raise DemoEvaluationConfigurationError(
                "private MCP transport requires an exact operator-verified "
                "WC-008 configuration"
            ) from exc
        object.__setattr__(self, "_deployment_configuration", normalized)
        object.__setattr__(self, "_transport_configuration", sealed)
        object.__setattr__(
            self,
            "_invoker_binding",
            _seal_private_mcp_invoker(invoker),
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("private MCP transport composition is immutable")

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        return self._deployment_configuration

    @property
    def transport_configuration(self) -> SealedMcpTransportConfiguration:
        """Return the same sealed primitives consumed by invoke()."""

        return self._transport_configuration

    def invoke(self, request: EvidenceTransportRequest) -> McpTransportOutcome:
        return _invoke_exact_private_mcp_transport(self, request)


_PRIVATE_MCP_TRANSPORT_INVOKE_IMPLEMENTATION = PrivateMcpEvidenceTransport.invoke


def _require_exact_private_mcp_transport(
    transport: PrivateMcpEvidenceTransport,
) -> None:
    if (
        type(transport) is not PrivateMcpEvidenceTransport
        or getattr_static(PrivateMcpEvidenceTransport, "invoke", None)
        is not _PRIVATE_MCP_TRANSPORT_INVOKE_IMPLEMENTATION
        or _has_instance_invoke_override(transport)
    ):
        raise EvidenceClientCompositionError(
            "private MCP transport implementation changed after composition"
        )
    configuration = object.__getattribute__(
        transport,
        "_transport_configuration",
    )
    try:
        sealed_mcp_transport_configuration_primitives(configuration)
    except ValueError as exc:
        raise EvidenceClientCompositionError(
            "private MCP transport configuration is not sealed"
        ) from exc
    _require_exact_private_mcp_invoker(
        object.__getattribute__(transport, "_invoker_binding")
    )


def _invoke_exact_private_mcp_transport(
    transport: SyncEvidenceTransport,
    request: EvidenceTransportRequest,
) -> McpTransportOutcome:
    if type(transport) is not PrivateMcpEvidenceTransport:
        raise EvidenceClientCompositionError(
            "private MCP invocation did not receive the exact transport"
        )
    concrete_transport = cast(PrivateMcpEvidenceTransport, transport)
    _require_exact_private_mcp_transport(concrete_transport)
    if request.tool_name != AZURE_RESOURCE_INVENTORY_TOOL:
        raise ValueError("private MCP transport received an unsupported semantic tool")
    _, endpoint = sealed_mcp_transport_configuration_primitives(
        object.__getattribute__(
            concrete_transport,
            "_transport_configuration",
        )
    )
    binding = object.__getattribute__(
        concrete_transport,
        "_invoker_binding",
    )
    if binding.managed_identity is not None:
        return _invoke_managed_identity_private_mcp(
            binding.managed_identity,
            endpoint,
            AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
            request,
        )
    return binding.invoke_implementation(
        binding.invoker,
        endpoint,
        AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
        request,
    )


class Wc009EvidenceClientAdapter:
    """Construct WC-009 around the endpoint-owning transport; no independent label exists."""

    _client: SyncEvidenceClient
    _key_resolver: TrustedKeyResolver
    _transport: PrivateMcpEvidenceTransport
    _trust_configuration: CollectorTrustConfiguration
    _trusted_key_anchor: TrustedKeyAnchor

    __slots__ = (
        "_client",
        "_key_resolver",
        "_transport",
        "_trust_configuration",
        "_trusted_key_anchor",
    )

    def __init__(
        self,
        *,
        transport: PrivateMcpEvidenceTransport,
        signer: SyncTrustedIngestionSigner,
        replay_guard: SyncAttemptReplayGuard,
        clock: Clock,
        trust_configuration: CollectorTrustConfiguration,
        key_resolver: TrustedKeyResolver,
        trusted_key_anchor: TrustedKeyAnchor,
    ) -> None:
        if type(transport) is not PrivateMcpEvidenceTransport:
            raise DemoEvaluationConfigurationError(
                "WC-009 requires the exact endpoint-owning private MCP transport"
            )
        object.__setattr__(self, "_transport", transport)
        object.__setattr__(self, "_trust_configuration", trust_configuration)
        object.__setattr__(self, "_key_resolver", key_resolver)
        object.__setattr__(self, "_trusted_key_anchor", trusted_key_anchor)
        object.__setattr__(
            self,
            "_client",
            SyncEvidenceClient(
                transport=transport,
                signer=signer,
                replay_guard=replay_guard,
                clock=clock,
                trust_configuration=trust_configuration,
                key_resolver=key_resolver,
                trusted_key_anchor=trusted_key_anchor,
            ),
        )
        self._require_exact_runtime_transport()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("WC-009 evidence client composition is immutable")

    def _require_exact_runtime_transport(self) -> PrivateMcpEvidenceTransport:
        """Bind advertised configuration to the object WC-009 will invoke."""

        if (
            type(self) is not Wc009EvidenceClientAdapter
            or type(self._transport) is not PrivateMcpEvidenceTransport
            or type(self._client) is not SyncEvidenceClient
            or self._client._transport is not self._transport
        ):
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport is not the exact sealed private "
                "MCP transport"
            )
        try:
            _require_exact_private_mcp_transport(self._transport)
        except EvidenceClientCompositionError as exc:
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport or invoker composition changed"
            ) from exc
        return self._transport

    @property
    def deployment_configuration(self) -> VerifiedWc008DeploymentConfiguration:
        self._require_exact_runtime_transport()
        return object.__getattribute__(
            self._transport,
            "_deployment_configuration",
        )

    @property
    def transport_configuration(self) -> SealedMcpTransportConfiguration:
        self._require_exact_runtime_transport()
        return object.__getattribute__(
            self._transport,
            "_transport_configuration",
        )

    @property
    def trust_configuration(self) -> CollectorTrustConfiguration:
        return self._trust_configuration

    @property
    def key_resolver(self) -> TrustedKeyResolver:
        return self._key_resolver

    @property
    def trusted_key_anchor(self) -> TrustedKeyAnchor:
        return self._trusted_key_anchor

    def collect(self, command: EvidenceCollectionCommand) -> CollectedEvidence:
        transport = self._require_exact_runtime_transport()
        try:
            collected = SyncEvidenceClient._collect_with_bound_transport(
                self._client,
                command,
                transport=transport,
                transport_invoke=_invoke_exact_private_mcp_transport,
            )
        except EvidenceClientCompositionError as exc:
            raise DemoEvaluationConfigurationError(
                "WC-009 runtime transport changed before MCP invocation"
            ) from exc
        self._require_exact_runtime_transport()
        return collected


class OperatorTrustedWc008ConfigurationPort:
    """Verify a raw assertion against a separately pinned operator decision."""

    def __init__(
        self,
        *,
        assertion: Wc008DeploymentOutputAssertion,
        pinned_assertion_digest: str,
        operator_approval: OperatorDeploymentApproval,
    ) -> None:
        self._assertion = assertion
        self._pinned_assertion_digest = pinned_assertion_digest
        self._operator_approval = operator_approval

    def load_verified(self) -> VerifiedWc008DeploymentConfiguration:
        if (
            self._assertion.assertion_digest != self._pinned_assertion_digest
            or self._operator_approval.assertion_digest
            != self._pinned_assertion_digest
        ):
            raise DemoEvaluationConfigurationError(
                "WC-008 deployment outputs do not match the pinned assertion digest "
                "and operator trust decision"
            )
        return VerifiedWc008DeploymentConfiguration(
            assertion=self._assertion,
            operator_approval=self._operator_approval,
        )


class EnvironmentWc008DeploymentConfigurationPort:
    """Live adapter loading bounded operator-pinned WC-008 output files."""

    _MAX_CONFIG_BYTES = 131_072

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = dict(os.environ if environment is None else environment)

    def load_verified(self) -> VerifiedWc008DeploymentConfiguration:
        assertion_path = self._required_path(
            "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE"
        )
        approval_path = self._required_path(
            "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE"
        )
        pinned_digest = self._environment.get(
            "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST"
        )
        if pinned_digest is None:
            raise DemoEvaluationConfigurationError(
                "live WC-008 pinned assertion digest is required"
            )
        try:
            assertion = Wc008DeploymentOutputAssertion.model_validate_json(
                self._read_bounded(assertion_path)
            )
            approval = OperatorDeploymentApproval.model_validate_json(
                self._read_bounded(approval_path)
            )
        except ValidationError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is malformed or untrusted"
            ) from exc
        return OperatorTrustedWc008ConfigurationPort(
            assertion=assertion,
            pinned_assertion_digest=pinned_digest,
            operator_approval=approval,
        ).load_verified()

    def _required_path(self, variable: str) -> Path:
        value = self._environment.get(variable)
        if value is None:
            raise DemoEvaluationConfigurationError(
                f"live WC-008 configuration variable {variable} is required"
            )
        return Path(value)

    def _read_bounded(self, path: Path) -> str:
        try:
            with path.open("rb") as stream:
                content = stream.read(self._MAX_CONFIG_BYTES + 1)
        except OSError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is unavailable"
            ) from exc
        if not content or len(content) > self._MAX_CONFIG_BYTES:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file exceeds its trusted bound"
            )
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DemoEvaluationConfigurationError(
                "live WC-008 configuration file is not valid UTF-8"
            ) from exc


class EnvironmentWc007PublishedContextSelectionPort:
    """Load an exact live WC-007 manifest version and profile selection."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = dict(os.environ if environment is None else environment)

    def load(self) -> PublishedContextSelection:
        return PublishedContextSelection(
            manifest_id=self._required("ATHENA_WC013_MANIFEST_ID"),
            manifest_version=self._required("ATHENA_WC013_MANIFEST_VERSION"),
            profile_id=self._required("ATHENA_WC013_PROFILE_ID"),
        )

    def _required(self, variable: str) -> str:
        value = self._environment.get(variable)
        if value is None or not value.strip():
            raise DemoEvaluationConfigurationError(
                f"live WC-007 context variable {variable} is required"
            )
        return value


class ContextApiPublishedContextResolver:
    """Production read adapter resolving only authoritative Context API responses."""

    def __init__(self, reader: PublishedContextReaderPort) -> None:
        self._reader = reader

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        if selection.manifest_version is None:
            active = [
                view
                for view in self._reader.list_published(selection.manifest_id)
                if view.supersession is None
            ]
            if not active:
                raise ResourceNotFoundError(
                    "published manifest has no active version"
                )
            if len(active) != 1:
                raise AmbiguousLookupError(
                    "published manifest has multiple active versions"
                )
            view = active[0]
        else:
            view = self._reader.get_published(
                selection.manifest_id,
                selection.manifest_version,
            )
        profile = resolve_manifest_profile(
            view.published.manifest,
            selection.profile_id,
            as_of=as_of,
        )
        return ResolvedPublishedContext(
            view=view,
            profile=profile,
            authority_token=build_published_context_authority_token(
                view,
                profile,
                requested_manifest_version=selection.manifest_version,
            ),
        )


class ContextServicePublishedContextReader:
    """Authorized in-process reader backed by real ContextService state."""

    def __init__(self, *, service: ContextService, reader_actor: Actor) -> None:
        self._service = service
        self._reader_actor = reader_actor

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifestView:
        return self._service.get_published(
            self._reader_actor,
            manifest_version,
            manifest_id=manifest_id,
        )

    def list_published(
        self,
        manifest_id: str,
    ) -> tuple[PublishedManifestView, ...]:
        return tuple(
            self._service.list_published(
                self._reader_actor,
                manifest_id,
            )
        )


class ContextServicePublishedContextResolver:
    """Resolve context only through the authorized WC-007 service, never its store."""

    def __init__(
        self,
        *,
        service: ContextService,
        reader_actor: Actor,
    ) -> None:
        self._resolver = ContextApiPublishedContextResolver(
            ContextServicePublishedContextReader(
                service=service,
                reader_actor=reader_actor,
            )
        )

    def resolve(
        self,
        selection: PublishedContextSelection,
        *,
        as_of: datetime,
    ) -> ResolvedPublishedContext:
        return self._resolver.resolve(selection, as_of=as_of)


__all__ = [
    "AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL",
    "ContextApiPublishedContextResolver",
    "ContextServicePublishedContextReader",
    "ContextServicePublishedContextResolver",
    "DefaultAzureCredentialContextApiToken",
    "DefaultAzureCredentialPrivateMcpToken",
    "EnvironmentContextApiPublishedContextReader",
    "EnvironmentWc007PublishedContextSelectionPort",
    "EnvironmentWc008DeploymentConfigurationPort",
    "ManagedIdentityPrivateMcpInvoker",
    "OperatorTrustedWc008ConfigurationPort",
    "PrivateMcpAccessTokenPort",
    "PrivateMcpEvidenceTransport",
    "PrivateMcpInvokerPort",
    "Wc009EvidenceClientAdapter",
]
