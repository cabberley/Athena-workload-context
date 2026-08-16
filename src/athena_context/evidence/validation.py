from __future__ import annotations

import json
import re
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from pydantic import TypeAdapter, ValidationError

from athena_context.contracts import (
    ActivitySummaryEvidenceRecord,
    AdvisorRecommendationEvidenceRecord,
    AuthorizationFailureCollectorAttempt,
    AzureGuid,
    CollectorAttempt,
    CollectorIdentityEvidence,
    EvidenceGapRecord,
    EvidenceGapRef,
    EvidenceItemRef,
    EvidenceRecord,
    EvidenceReference,
    FailedResponseCollectorAttempt,
    HealthEventEvidenceRecord,
    LogAnalyticsWorkspaceScope,
    MetricAggregateEvidenceRecord,
    ObservedRelationshipEvidenceRecord,
    ResourceEvidenceRecord,
    ResourceGroupScope,
    ResourceIdScope,
    ServiceHealthRegionScope,
    SubscriptionScope,
    SuccessResponseCollectorAttempt,
    TimeoutNoResponseCollectorAttempt,
    ToolUnavailableCollectorAttempt,
    TrustedKeyAnchor,
    TrustedKeyResolver,
    canonicalize_json,
    compute_artifact_digest,
    compute_evidence_record_digest,
    compute_failure_envelope_digest,
    compute_response_envelope_digest,
)
from athena_context.evidence.models import (
    AZURE_MCP_RESPONSE_SCHEMA_VERSION,
    AZURE_RESOURCE_INVENTORY_TOOL,
    AZURE_RESOURCE_INVENTORY_VERSION,
    CollectedEvidence,
    CollectorTrustConfiguration,
    EvidenceBoundaryError,
    EvidenceCollectionCommand,
    EvidenceProjection,
    EvidenceTransportRequest,
    McpAuthorizationFailure,
    McpFailedResponse,
    McpSuccessResponse,
    McpTimeoutNoResponse,
    McpToolUnavailable,
    McpTransportOutcome,
    SnapshotReferenceBinding,
    TrustedIngestionError,
    ValidatedEnvelope,
)

_EVIDENCE_SCOPE_ADAPTER: TypeAdapter[
    SubscriptionScope
    | ResourceGroupScope
    | ResourceIdScope
    | LogAnalyticsWorkspaceScope
    | ServiceHealthRegionScope
] = TypeAdapter(
    SubscriptionScope
    | ResourceGroupScope
    | ResourceIdScope
    | LogAnalyticsWorkspaceScope
    | ServiceHealthRegionScope
)
_ALLOWED_RESOURCE_TYPES = {
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Network/loadBalancers",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.OperationalInsights/workspaces",
}
_ALLOWED_LOCATIONS = {
    "australiaeast",
    "australiasoutheast",
    "eastus",
    "eastus2",
    "westus2",
    "westeurope",
    "northeurope",
}
_ALLOWED_ZONES = {"1", "2", "3", "unknown"}
_ALLOWED_STATES = {"running", "stopped", "deallocated", "unknown"}
_ALLOWED_TAGS: dict[str, set[str] | None] = {
    "environment": {
        "production",
        "development",
        "training",
        "test",
        "disaster-recovery",
        "sandbox",
    },
    "workloadRole": {
        "database",
        "worker",
        "web-service",
        "load-balancer",
        "integration",
        "storage",
        "network",
        "identity",
        "observability",
        "external-dependency",
    },
    "application": None,
    "component": None,
    "managedBy": {
        "terraform",
        "bicep",
        "arm",
        "azure-policy",
        "manual",
        "unknown",
    },
}
_RESOURCE_ITEM_KEYS = {
    "recordType",
    "observedAt",
    "resourceId",
    "resourceType",
    "location",
    "availabilityZone",
    "tags",
    "state",
}
_SUCCESS_ENVELOPE_KEYS = {
    "schemaVersion",
    "toolName",
    "toolVersion",
    "attemptId",
    "requestDigest",
    "evidenceScope",
    "observedAt",
    "items",
}
_FAILURE_ENVELOPE_KEYS = {
    "schemaVersion",
    "toolName",
    "toolVersion",
    "attemptId",
    "requestDigest",
    "error",
}
_FAILURE_CODES = {
    "schemaMismatch",
    "responseOversized",
    "staleResponse",
    "serviceFailure",
}
_FAILURE_STATUSES = {"invalid", "failed", "unavailable"}
type ConcreteEvidenceRecord = (
    ResourceEvidenceRecord
    | ObservedRelationshipEvidenceRecord
    | MetricAggregateEvidenceRecord
    | HealthEventEvidenceRecord
    | ActivitySummaryEvidenceRecord
    | AdvisorRecommendationEvidenceRecord
)
_AZURE_GUID_ADAPTER: TypeAdapter[AzureGuid] = TypeAdapter(AzureGuid)


def _require_utc_millisecond(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise EvidenceBoundaryError(f"{field_name} must be UTC")
    if value.microsecond % 1000:
        raise EvidenceBoundaryError(f"{field_name} must use millisecond precision")


def prepare_transport_request(
    command: EvidenceCollectionCommand,
    trust_configuration: CollectorTrustConfiguration,
    *,
    attempt_started_at: datetime,
) -> EvidenceTransportRequest:
    _require_utc_millisecond(attempt_started_at, field_name="attempt_started_at")
    for scope in (command.evidence_scope, *command.authorized_scopes):
        tenant_id = getattr(scope, "tenant_id", None)
        if tenant_id is not None and tenant_id != trust_configuration.tenant_id:
            raise EvidenceBoundaryError(
                "evidence scopes must use the configured Azure MCP tenant"
            )
    for scope in command.authorized_scopes:
        if isinstance(scope, ResourceIdScope) and not any(
            isinstance(parent, (SubscriptionScope, ResourceGroupScope))
            and scope_contains(parent, scope)
            for parent in command.authorized_scopes
        ):
            raise EvidenceBoundaryError(
                "resourceId authorized scopes require a tenant-bound parent scope"
            )
    payload = {
        **command.model_dump(mode="python", by_alias=True),
        "attemptStartedAt": attempt_started_at,
        "expectedRecordType": "resource",
        "collectorIdentityEvidenceRef": (
            trust_configuration.collector_identity_evidence_ref
        ),
    }
    digest_payload = {
        **command.model_dump(mode="json", by_alias=True),
        "attemptStartedAt": attempt_started_at,
        "expectedRecordType": "resource",
        "collectorIdentityEvidenceRef": (
            trust_configuration.collector_identity_evidence_ref
        ),
    }
    payload["requestDigest"] = compute_artifact_digest(digest_payload)
    return EvidenceTransportRequest.model_validate(payload)


def _resource_components(value: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in value.split("/")[1:])


def normalize_resource_id(value: str, resource_type: str | None = None) -> str:
    if value != value.strip() or "\\" in value or "*" in value or "?" in value:
        raise EvidenceBoundaryError("resourceId contains invalid path characters")
    raw = value.split("/")
    if not raw or raw[0] != "" or any(not part for part in raw[1:]):
        raise EvidenceBoundaryError("resourceId must be an absolute Azure resource path")
    parts = raw[1:]
    if len(parts) < 6 or parts[0].casefold() != "subscriptions":
        raise EvidenceBoundaryError("resourceId must begin with /subscriptions/{guid}")
    try:
        subscription = str(_AZURE_GUID_ADAPTER.validate_python(parts[1].casefold()))
    except ValidationError as exc:
        raise EvidenceBoundaryError("resourceId contains an invalid subscription id") from exc
    normalized = ["subscriptions", subscription]
    index = 2
    if index < len(parts) and parts[index].casefold() == "resourcegroups":
        if index + 1 >= len(parts):
            raise EvidenceBoundaryError("resourceId resource group path is incomplete")
        normalized.extend(["resourceGroups", parts[index + 1]])
        index += 2
    if index >= len(parts) or parts[index].casefold() != "providers":
        raise EvidenceBoundaryError("resourceId must contain a providers segment")
    if index + 3 >= len(parts) or (len(parts) - index - 2) % 2:
        raise EvidenceBoundaryError("resourceId provider type/name path is incomplete")
    normalized.extend(["providers", parts[index + 1]])
    index += 2
    while index < len(parts):
        normalized.extend([parts[index], parts[index + 1]])
        index += 2
    if resource_type is not None:
        if resource_type not in _ALLOWED_RESOURCE_TYPES:
            raise EvidenceBoundaryError("resourceType is not in the closed evidence contract")
        expected_namespace, expected_type = resource_type.split("/", 1)
        provider_index = normalized.index("providers")
        if (
            normalized[provider_index + 1].casefold() != expected_namespace.casefold()
            or normalized[provider_index + 2].casefold() != expected_type.casefold()
            or len(normalized) != provider_index + 4
        ):
            raise EvidenceBoundaryError("resourceId does not match resourceType")
        normalized[provider_index + 1] = expected_namespace
        normalized[provider_index + 2] = expected_type
    return "/" + "/".join(normalized)


def _scope_resource_prefix(scope: object) -> tuple[str, ...] | None:
    if isinstance(scope, SubscriptionScope):
        return ("subscriptions", scope.subscription_id.casefold())
    if isinstance(scope, ResourceGroupScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
        )
    if isinstance(scope, ResourceIdScope):
        return _resource_components(normalize_resource_id(scope.resource_id))
    if isinstance(scope, LogAnalyticsWorkspaceScope):
        return (
            "subscriptions",
            scope.subscription_id.casefold(),
            "resourcegroups",
            scope.resource_group_name.casefold(),
            "providers",
            "microsoft.operationalinsights",
            "workspaces",
            scope.workspace_name.casefold(),
        )
    return None


def scope_contains(container: object, candidate: object) -> bool:
    if container.__class__ is candidate.__class__:
        container_prefix = _scope_resource_prefix(container)
        candidate_prefix = _scope_resource_prefix(candidate)
        if container_prefix is not None and candidate_prefix is not None:
            container_tenant = getattr(container, "tenant_id", None)
            candidate_tenant = getattr(candidate, "tenant_id", None)
            return (
                container_prefix == candidate_prefix
                and container_tenant == candidate_tenant
            )
        if hasattr(container, "model_dump") and hasattr(candidate, "model_dump"):
            container_payload = container.model_dump(mode="json", by_alias=True)
            candidate_payload = candidate.model_dump(mode="json", by_alias=True)
            return canonicalize_json(container_payload) == canonicalize_json(candidate_payload)
    container_prefix = _scope_resource_prefix(container)
    candidate_prefix = _scope_resource_prefix(candidate)
    if container_prefix is not None and candidate_prefix is not None:
        return (
            len(container_prefix) <= len(candidate_prefix)
            and candidate_prefix[: len(container_prefix)] == container_prefix
        )
    if isinstance(container, ServiceHealthRegionScope) and isinstance(
        candidate, ServiceHealthRegionScope
    ):
        return container.cloud == candidate.cloud and container.region == candidate.region
    return False


def _resource_in_scope(resource_id: str, scope: object) -> bool:
    prefix = _scope_resource_prefix(scope)
    components = _resource_components(resource_id)
    return (
        prefix is not None
        and len(prefix) <= len(components)
        and components[: len(prefix)] == prefix
    )


def _scope_is_authorized(request: EvidenceTransportRequest) -> bool:
    return any(
        scope_contains(scope, request.evidence_scope)
        for scope in request.authorized_scopes
    )


def preflight_outcome(
    request: EvidenceTransportRequest,
) -> McpAuthorizationFailure | McpToolUnavailable | None:
    if request.tool_name != AZURE_RESOURCE_INVENTORY_TOOL:
        return McpToolUnavailable(
            unavailable_reason="notAllowlisted",
            observed_at=request.attempt_started_at,
        )
    if request.tool_version != AZURE_RESOURCE_INVENTORY_VERSION:
        return McpToolUnavailable(
            unavailable_reason="versionUnavailable",
            observed_at=request.attempt_started_at,
        )
    if not isinstance(
        request.evidence_scope,
        (SubscriptionScope, ResourceGroupScope, ResourceIdScope),
    ) or not _scope_is_authorized(request):
        return McpAuthorizationFailure(
            authorization_status="scopeNotAllowed",
            observed_at=request.attempt_started_at,
        )
    return None


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_json_object(body: bytes) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceBoundaryError("response is not canonicalizable strict JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceBoundaryError("response envelope must be a JSON object")
    return value


def _parse_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceBoundaryError(f"{field_name} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceBoundaryError(f"{field_name} is not a valid timestamp") from exc
    _require_utc_millisecond(parsed, field_name=field_name)
    return parsed


def _is_fresh(
    observed_at: datetime,
    *,
    received_at: datetime,
    validated_at: datetime,
    freshness_seconds: int,
) -> bool:
    return (
        observed_at <= received_at <= validated_at
        and observed_at >= validated_at - timedelta(seconds=freshness_seconds)
    )


def _attempt_payload(
    request: EvidenceTransportRequest,
    *,
    attempt_type: str,
    variant: dict[str, object],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "attemptType": attempt_type,
        "attemptId": request.attempt_id,
        "attemptStartedAt": request.attempt_started_at,
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "requestDigest": request.request_digest,
        **variant,
        "collectorIdentityEvidenceRef": request.collector_identity_evidence_ref,
    }
    payload["attemptDigest"] = compute_artifact_digest(payload)
    return payload


def _gap_id(
    request: EvidenceTransportRequest,
    *,
    reason: str,
    pointer: str | None,
) -> str:
    digest = compute_artifact_digest(
        {
            "attemptId": request.attempt_id,
            "requestDigest": request.request_digest,
            "gapReason": reason,
            "pointer": pointer,
        }
    )
    return "gap-" + digest.removeprefix("sha256:")[:12]


def _gap_record(
    request: EvidenceTransportRequest,
    attempt: CollectorAttempt,
    *,
    reason: Literal[
        "missing",
        "stale",
        "unauthorized",
        "filtered",
        "malformed",
        "collectorUnavailable",
        "scopeMismatch",
        "responseOversized",
        "unsupportedTool",
    ],
    observed_at: datetime,
    payload_digest: str | None = None,
    payload_pointer: str | None = None,
) -> EvidenceGapRecord:
    payload: dict[str, object] = {
        "recordType": "evidenceGap",
        "gapId": _gap_id(request, reason=reason, pointer=payload_pointer),
        "evidenceScope": request.evidence_scope.model_dump(mode="json", by_alias=True),
        "gapReason": reason,
        "expectedRecordType": request.expected_record_type,
        "collectorAttemptId": attempt.attempt_id,
        "collectorAttemptDigest": attempt.attempt_digest,
        "observedAt": observed_at,
        "collectorIdentityEvidenceRef": request.collector_identity_evidence_ref,
    }
    if payload_digest is not None:
        payload["failurePayloadDigest"] = payload_digest
        payload["failurePayloadPointer"] = payload_pointer
    payload["itemDigest"] = compute_evidence_record_digest(payload)
    return EvidenceGapRecord.model_validate(payload)


def _generated_failure_envelope(
    request: EvidenceTransportRequest,
    *,
    failure_code: Literal[
        "schemaMismatch", "responseOversized", "staleResponse", "serviceFailure"
    ],
    failure_status: Literal["invalid", "failed", "unavailable"],
) -> dict[str, object]:
    return {
        "schemaVersion": AZURE_MCP_RESPONSE_SCHEMA_VERSION,
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "attemptId": request.attempt_id,
        "requestDigest": request.request_digest,
        "error": {"code": failure_code, "status": failure_status},
    }


def _failed_projection(
    request: EvidenceTransportRequest,
    *,
    response_received_at: datetime,
    failure_code: Literal[
        "schemaMismatch", "responseOversized", "staleResponse", "serviceFailure"
    ],
    failure_status: Literal["invalid", "failed", "unavailable"],
    gap_reason: Literal[
        "missing", "stale", "malformed", "collectorUnavailable", "responseOversized"
    ],
    envelope_payload: dict[str, object] | None = None,
    pointer: str = "/error",
) -> EvidenceProjection:
    payload = envelope_payload or _generated_failure_envelope(
        request,
        failure_code=failure_code,
        failure_status=failure_status,
    )
    failure_digest = compute_failure_envelope_digest(payload)
    attempt = FailedResponseCollectorAttempt.model_validate(
        _attempt_payload(
            request,
            attempt_type="failedResponse",
            variant={
                "failureCode": failure_code,
                "failureStatus": failure_status,
                "failureDigest": failure_digest,
                "responseReceivedAt": response_received_at,
            },
        )
    )
    gap = _gap_record(
        request,
        attempt,
        reason=gap_reason,
        observed_at=response_received_at,
        payload_digest=failure_digest,
        payload_pointer=pointer,
    )
    return EvidenceProjection(
        request=request,
        collector_attempt=attempt,
        evidence_records=(gap,),
        envelope=ValidatedEnvelope.from_payload(
            kind="failure", digest=failure_digest, payload=payload
        ),
    )


def _no_response_projection(
    request: EvidenceTransportRequest,
    outcome: McpTimeoutNoResponse
    | McpAuthorizationFailure
    | McpToolUnavailable,
) -> EvidenceProjection:
    attempt: CollectorAttempt
    if isinstance(outcome, McpTimeoutNoResponse):
        attempt = TimeoutNoResponseCollectorAttempt.model_validate(
            _attempt_payload(
                request,
                attempt_type="timeoutNoResponse",
                variant={
                    "deadlineAt": outcome.deadline_at,
                    "timedOutAt": outcome.timed_out_at,
                },
            )
        )
        reason: Literal[
            "missing", "unauthorized", "collectorUnavailable", "unsupportedTool"
        ] = "missing"
        observed_at = outcome.timed_out_at
    elif isinstance(outcome, McpAuthorizationFailure):
        attempt = AuthorizationFailureCollectorAttempt.model_validate(
            _attempt_payload(
                request,
                attempt_type="authorizationFailure",
                variant={
                    "authorizationStatus": outcome.authorization_status,
                    "observedAt": outcome.observed_at,
                },
            )
        )
        reason = "unauthorized"
        observed_at = outcome.observed_at
    else:
        attempt = ToolUnavailableCollectorAttempt.model_validate(
            _attempt_payload(
                request,
                attempt_type="toolUnavailable",
                variant={
                    "unavailableReason": outcome.unavailable_reason,
                    "observedAt": outcome.observed_at,
                },
            )
        )
        reason = (
            "unsupportedTool"
            if outcome.unavailable_reason
            in {"notAllowlisted", "notHosted", "versionUnavailable"}
            else "collectorUnavailable"
        )
        observed_at = outcome.observed_at
    gap = _gap_record(request, attempt, reason=reason, observed_at=observed_at)
    return EvidenceProjection(
        request=request,
        collector_attempt=attempt,
        evidence_records=(gap,),
        envelope=None,
    )


def _validate_common_response_identity(
    request: EvidenceTransportRequest,
    payload: dict[str, Any],
) -> Literal["match", "unsupported", "mismatch"]:
    if payload.get("toolName") != request.tool_name:
        return "unsupported"
    if payload.get("toolVersion") != request.tool_version:
        return "unsupported"
    if (
        payload.get("attemptId") != request.attempt_id
        or payload.get("requestDigest") != request.request_digest
    ):
        return "mismatch"
    return "match"


def _safe_tag_value(key: str, value: object) -> object | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    allowed = _ALLOWED_TAGS[key]
    if allowed is not None:
        return value if value in allowed else None
    if key == "application":
        return value if re.fullmatch(r"app-[a-f0-9]{12}", value) else None
    if key == "component":
        return value if re.fullmatch(r"component-[a-f0-9]{12}", value) else None
    return None


def _sanitize_resource_item(item: object) -> dict[str, object]:
    if not isinstance(item, dict):
        return {}
    safe: dict[str, object] = {}
    if item.get("recordType") == "resource":
        safe["recordType"] = "resource"
    for key, allowed in (
        ("resourceType", _ALLOWED_RESOURCE_TYPES),
        ("location", _ALLOWED_LOCATIONS),
        ("availabilityZone", _ALLOWED_ZONES),
        ("state", _ALLOWED_STATES),
    ):
        value = item.get(key)
        if isinstance(value, str) and value in allowed:
            safe[key] = value
    observed_at = item.get("observedAt")
    if isinstance(observed_at, str):
        try:
            _parse_datetime(observed_at, field_name="items.observedAt")
            safe["observedAt"] = observed_at
        except EvidenceBoundaryError:
            pass
    resource_id = item.get("resourceId")
    resource_type = safe.get("resourceType")
    if isinstance(resource_id, str) and isinstance(resource_type, str):
        with suppress(EvidenceBoundaryError):
            safe["resourceId"] = normalize_resource_id(resource_id, resource_type)
    tags = item.get("tags")
    if isinstance(tags, dict):
        safe_tags: dict[str, object] = {}
        for key in _ALLOWED_TAGS:
            if key in tags:
                value = _safe_tag_value(key, tags[key])
                if value is not None:
                    safe_tags[key] = value
        if safe_tags:
            safe["tags"] = safe_tags
    return safe


def _normalized_scope_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise EvidenceBoundaryError("evidenceScope must be an object")
    normalized = dict(payload)
    for field_name in ("tenantId", "subscriptionId"):
        value = normalized.get(field_name)
        if isinstance(value, str):
            normalized[field_name] = value.casefold()
    if normalized.get("scopeType") == "resourceId":
        resource_id = normalized.get("resourceId")
        if not isinstance(resource_id, str):
            raise EvidenceBoundaryError("resourceId scope requires resourceId")
        normalized["resourceId"] = normalize_resource_id(resource_id)
    return cast(dict[str, object], normalized)


def _success_projection(
    request: EvidenceTransportRequest,
    outcome: McpSuccessResponse,
    *,
    validated_at: datetime,
) -> EvidenceProjection:
    if len(outcome.body) > request.bounds.max_response_bytes:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="responseOversized",
            failure_status="invalid",
            gap_reason="responseOversized",
        )
    try:
        payload = _parse_json_object(outcome.body)
    except EvidenceBoundaryError:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    identity = _validate_common_response_identity(request, payload)
    if identity == "unsupported":
        return _no_response_projection(
            request,
            McpToolUnavailable(
                unavailable_reason=(
                    "notAllowlisted"
                    if payload.get("toolName") != request.tool_name
                    else "versionUnavailable"
                ),
                observed_at=outcome.response_received_at,
            ),
        )
    if identity == "mismatch":
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    if set(payload) != _SUCCESS_ENVELOPE_KEYS:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    if payload.get("schemaVersion") != AZURE_MCP_RESPONSE_SCHEMA_VERSION:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    items = payload.get("items")
    if not isinstance(items, list):
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    if not items:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="serviceFailure",
            failure_status="failed",
            gap_reason="missing",
        )
    if len(items) > request.bounds.max_items:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="responseOversized",
            failure_status="invalid",
            gap_reason="responseOversized",
        )
    try:
        response_scope = _EVIDENCE_SCOPE_ADAPTER.validate_python(
            _normalized_scope_payload(payload.get("evidenceScope"))
        )
        response_observed_at = _parse_datetime(
            payload.get("observedAt"), field_name="observedAt"
        )
    except (ValidationError, EvidenceBoundaryError):
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    if not _is_fresh(
        response_observed_at,
        received_at=outcome.response_received_at,
        validated_at=validated_at,
        freshness_seconds=request.bounds.freshness_seconds,
    ):
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="staleResponse",
            failure_status="invalid",
            gap_reason="stale",
        )
    safe_items = [_sanitize_resource_item(item) for item in items]
    safe_envelope: dict[str, object] = {
        "schemaVersion": AZURE_MCP_RESPONSE_SCHEMA_VERSION,
        "toolName": request.tool_name,
        "toolVersion": request.tool_version,
        "attemptId": request.attempt_id,
        "requestDigest": request.request_digest,
        "evidenceScope": response_scope.model_dump(mode="json", by_alias=True),
        "observedAt": response_observed_at,
        "items": safe_items,
    }
    response_digest = compute_response_envelope_digest(safe_envelope)
    attempt = SuccessResponseCollectorAttempt.model_validate(
        _attempt_payload(
            request,
            attempt_type="successResponse",
            variant={
                "responseDigest": response_digest,
                "responseReceivedAt": outcome.response_received_at,
            },
        )
    )
    envelope = ValidatedEnvelope.from_payload(
        kind="response", digest=response_digest, payload=safe_envelope
    )
    if not scope_contains(request.evidence_scope, response_scope) or not scope_contains(
        response_scope, request.evidence_scope
    ):
        gap = _gap_record(
            request,
            attempt,
            reason="scopeMismatch",
            observed_at=outcome.response_received_at,
            payload_digest=response_digest,
            payload_pointer="",
        )
        return EvidenceProjection(request, attempt, (gap,), envelope)

    records: list[EvidenceRecord] = []
    for index, (item, safe_item) in enumerate(zip(items, safe_items, strict=True)):
        pointer = f"/items/{index}"
        try:
            item_size = len(canonicalize_json(item).encode("utf-8"))
        except (TypeError, ValueError):
            item_size = request.bounds.max_record_bytes + 1
        if item_size > request.bounds.max_record_bytes:
            records.append(
                _gap_record(
                    request,
                    attempt,
                    reason="responseOversized",
                    observed_at=outcome.response_received_at,
                    payload_digest=response_digest,
                    payload_pointer=pointer,
                )
            )
            continue
        if not isinstance(item, dict) or set(item) != _RESOURCE_ITEM_KEYS:
            records.append(
                _gap_record(
                    request,
                    attempt,
                    reason="malformed",
                    observed_at=outcome.response_received_at,
                    payload_digest=response_digest,
                    payload_pointer=pointer,
                )
            )
            continue
        try:
            item_observed_at = _parse_datetime(
                item.get("observedAt"), field_name=f"items[{index}].observedAt"
            )
        except EvidenceBoundaryError:
            records.append(
                _gap_record(
                    request,
                    attempt,
                    reason="malformed",
                    observed_at=outcome.response_received_at,
                    payload_digest=response_digest,
                    payload_pointer=pointer,
                )
            )
            continue
        if not _is_fresh(
            item_observed_at,
            received_at=outcome.response_received_at,
            validated_at=validated_at,
            freshness_seconds=request.bounds.freshness_seconds,
        ):
            records.append(
                _gap_record(
                    request,
                    attempt,
                    reason="stale",
                    observed_at=outcome.response_received_at,
                    payload_digest=response_digest,
                    payload_pointer=pointer,
                )
            )
            continue
        try:
            resource_type = item["resourceType"]
            resource_id = item["resourceId"]
            if not isinstance(resource_type, str) or not isinstance(resource_id, str):
                raise EvidenceBoundaryError("resource fields must be strings")
            normalized_id = normalize_resource_id(resource_id, resource_type)
            if not _resource_in_scope(normalized_id, request.evidence_scope) or not any(
                _resource_in_scope(normalized_id, scope)
                for scope in request.authorized_scopes
            ):
                records.append(
                    _gap_record(
                        request,
                        attempt,
                        reason="scopeMismatch",
                        observed_at=outcome.response_received_at,
                        payload_digest=response_digest,
                        payload_pointer=pointer,
                    )
                )
                continue
            record_payload = {
                key: value
                for key, value in safe_item.items()
                if key != "observedAt"
            }
            record_payload["provenance"] = {
                "collectorAttemptId": attempt.attempt_id,
                "collectorIdentityEvidenceRef": (
                    request.collector_identity_evidence_ref
                ),
                "toolName": attempt.tool_name,
                "toolVersion": attempt.tool_version,
                "sourceResponseDigest": response_digest,
                "sourceResponsePointer": pointer,
            }
            record_payload["collectorAttemptDigest"] = attempt.attempt_digest
            record_payload["collectorIdentityEvidenceRef"] = (
                request.collector_identity_evidence_ref
            )
            record_payload["itemDigest"] = compute_evidence_record_digest(record_payload)
            records.append(ResourceEvidenceRecord.model_validate(record_payload))
        except (EvidenceBoundaryError, ValidationError, KeyError, TypeError):
            records.append(
                _gap_record(
                    request,
                    attempt,
                    reason="malformed",
                    observed_at=outcome.response_received_at,
                    payload_digest=response_digest,
                    payload_pointer=pointer,
                )
            )
    return EvidenceProjection(request, attempt, tuple(records), envelope)


def _failed_response_projection(
    request: EvidenceTransportRequest,
    outcome: McpFailedResponse,
) -> EvidenceProjection:
    if len(outcome.body) > request.bounds.max_response_bytes:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="responseOversized",
            failure_status="invalid",
            gap_reason="responseOversized",
        )
    try:
        payload = _parse_json_object(outcome.body)
    except EvidenceBoundaryError:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    identity = _validate_common_response_identity(request, payload)
    if identity != "match" or set(payload) != _FAILURE_ENVELOPE_KEYS:
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    error = payload.get("error")
    if (
        payload.get("schemaVersion") != AZURE_MCP_RESPONSE_SCHEMA_VERSION
        or not isinstance(error, dict)
        or set(error) != {"code", "status"}
        or error.get("code") not in _FAILURE_CODES
        or error.get("status") not in _FAILURE_STATUSES
    ):
        return _failed_projection(
            request,
            response_received_at=outcome.response_received_at,
            failure_code="schemaMismatch",
            failure_status="invalid",
            gap_reason="malformed",
        )
    failure_code = cast(
        Literal[
            "schemaMismatch", "responseOversized", "staleResponse", "serviceFailure"
        ],
        error["code"],
    )
    failure_status = cast(
        Literal["invalid", "failed", "unavailable"], error["status"]
    )
    reason_map: dict[
        str,
        Literal["malformed", "responseOversized", "stale", "collectorUnavailable"],
    ] = {
        "schemaMismatch": "malformed",
        "responseOversized": "responseOversized",
        "staleResponse": "stale",
        "serviceFailure": "collectorUnavailable",
    }
    return _failed_projection(
        request,
        response_received_at=outcome.response_received_at,
        failure_code=failure_code,
        failure_status=failure_status,
        gap_reason=reason_map[failure_code],
        envelope_payload=cast(dict[str, object], payload),
    )


def project_transport_outcome(
    request: EvidenceTransportRequest,
    outcome: McpTransportOutcome,
    *,
    validated_at: datetime,
) -> EvidenceProjection:
    _require_utc_millisecond(validated_at, field_name="validated_at")
    if validated_at < request.attempt_started_at:
        raise EvidenceBoundaryError("validated_at must not precede attemptStartedAt")
    if isinstance(outcome, McpSuccessResponse):
        _require_utc_millisecond(
            outcome.response_received_at, field_name="response_received_at"
        )
        if not request.attempt_started_at <= outcome.response_received_at <= validated_at:
            raise EvidenceBoundaryError("response timestamp is outside the attempt window")
        return _success_projection(request, outcome, validated_at=validated_at)
    if isinstance(outcome, McpFailedResponse):
        _require_utc_millisecond(
            outcome.response_received_at, field_name="response_received_at"
        )
        if not request.attempt_started_at <= outcome.response_received_at <= validated_at:
            raise EvidenceBoundaryError("failure timestamp is outside the attempt window")
        return _failed_response_projection(request, outcome)
    if isinstance(outcome, McpTimeoutNoResponse):
        _require_utc_millisecond(outcome.deadline_at, field_name="deadline_at")
        _require_utc_millisecond(outcome.timed_out_at, field_name="timed_out_at")
        if (
            outcome.deadline_at < request.attempt_started_at
            or outcome.timed_out_at <= outcome.deadline_at
            or outcome.timed_out_at > validated_at
        ):
            raise EvidenceBoundaryError("timeout timestamps are outside the attempt window")
    else:
        _require_utc_millisecond(outcome.observed_at, field_name="observed_at")
        if not request.attempt_started_at <= outcome.observed_at <= validated_at:
            raise EvidenceBoundaryError("outcome observation is outside the attempt window")
    return _no_response_projection(request, outcome)


def _expected_attempt_binding(attempt: CollectorAttempt) -> dict[str, object]:
    payload = attempt.model_dump(mode="python", by_alias=True, exclude_none=True)
    return {
        key: value
        for key, value in payload.items()
        if key
        in {
            "attemptId",
            "attemptType",
            "attemptDigest",
            "toolName",
            "toolVersion",
            "requestDigest",
            "responseDigest",
            "failureDigest",
            "attemptStartedAt",
            "responseReceivedAt",
            "deadlineAt",
            "timedOutAt",
            "observedAt",
        }
    }


def validate_trusted_identity(
    identity: CollectorIdentityEvidence,
    projection: EvidenceProjection,
    trust_configuration: CollectorTrustConfiguration,
    *,
    key_resolver: TrustedKeyResolver,
    trusted_key_anchor: TrustedKeyAnchor,
    as_of: datetime,
) -> None:
    _require_utc_millisecond(as_of, field_name="as_of")
    derivation = identity.ingestion_derivation
    claims = identity.verified_claims
    expected_binding = _expected_attempt_binding(projection.collector_attempt)
    actual_binding = derivation.attempt_binding.model_dump(
        mode="python", by_alias=True, exclude_none=True
    )
    if (
        identity.identity_evidence_id
        != trust_configuration.collector_identity_evidence_ref
        or identity.trust_anchor_ref != trust_configuration.trust_anchor_ref
        or trusted_key_anchor.key_vault_key_id != trust_configuration.trust_anchor_ref
        or claims.tenant_id != trust_configuration.tenant_id
        or claims.managed_identity_object_id
        != trust_configuration.managed_identity_object_id
        or claims.managed_identity_client_id
        != trust_configuration.managed_identity_client_id
        or derivation.mcp_host_id != trust_configuration.mcp_host_id
        or derivation.mcp_host_tenant_id != trust_configuration.tenant_id
        or derivation.mcp_host_managed_identity_object_id
        != trust_configuration.managed_identity_object_id
        or derivation.mcp_host_managed_identity_client_id
        != trust_configuration.managed_identity_client_id
        or derivation.ingestion_service_id
        != trust_configuration.ingestion_service_id
        or derivation.ingestion_audience != trust_configuration.ingestion_audience
        or derivation.tool_allowlist_digest
        != trust_configuration.tool_allowlist_digest
        or derivation.schema_version != trust_configuration.schema_version
        or derivation.semantic_contract_version
        != trust_configuration.semantic_contract_version
        or derivation.policy_contract_version
        != trust_configuration.policy_contract_version
        or derivation.derived_collector_identity_ref
        != trust_configuration.collector_identity_evidence_ref
        or actual_binding != expected_binding
    ):
        raise TrustedIngestionError(
            "collector identity evidence does not exactly bind the configured attempt"
        )
    if not identity.verify_signature(
        key_resolver=key_resolver,
        trusted_key_anchor=trusted_key_anchor,
        as_of=as_of,
        attempt=projection.collector_attempt,
    ):
        raise TrustedIngestionError(
            "collector identity evidence failed trusted ingestion verification"
        )


def _attempt_observed_at(attempt: CollectorAttempt) -> datetime:
    if attempt.attempt_type in {"successResponse", "failedResponse"}:
        return attempt.response_received_at
    if attempt.attempt_type == "timeoutNoResponse":
        return attempt.timed_out_at
    if isinstance(
        attempt, (AuthorizationFailureCollectorAttempt, ToolUnavailableCollectorAttempt)
    ):
        return attempt.observed_at
    raise EvidenceBoundaryError("unknown collector attempt variant")


def bind_evidence_references(
    result: CollectedEvidence,
    binding: SnapshotReferenceBinding,
) -> tuple[EvidenceReference, ...]:
    references: list[EvidenceReference] = []
    attempt = result.collector_attempt
    attempt_at = _attempt_observed_at(attempt)
    for record in result.evidence_records:
        if isinstance(record, EvidenceGapRecord):
            references.append(
                EvidenceGapRef(
                    refType="evidenceGap",
                    snapshotId=binding.snapshot_id,
                    snapshotArtifactDigest=binding.snapshot_artifact_digest,
                    snapshotSemanticDigest=binding.snapshot_semantic_digest,
                    gapId=record.gap_id,
                    gapRecordDigest=record.item_digest,
                    evidenceScope=record.evidence_scope,
                    expectedRecordType=record.expected_record_type,
                    collectorAttemptId=record.collector_attempt_id,
                    collectorAttemptDigest=record.collector_attempt_digest,
                    collectorToolName=attempt.tool_name,
                    collectorToolVersion=attempt.tool_version,
                    collectorAttemptAt=attempt_at,
                    collectorIdentityEvidenceRef=record.collector_identity_evidence_ref,
                    gapReason=record.gap_reason,
                    failurePayloadDigest=record.failure_payload_digest,
                    failurePayloadPointer=record.failure_payload_pointer,
                )
            )
            continue
        concrete = cast(ConcreteEvidenceRecord, record)
        provenance = concrete.provenance
        if (
            provenance.source_response_digest is None
            or provenance.source_response_pointer is None
        ):
            raise EvidenceBoundaryError(
                "concrete evidence record is missing exact response provenance"
            )
        references.append(
            EvidenceItemRef(
                refType="evidenceItem",
                snapshotId=binding.snapshot_id,
                snapshotArtifactDigest=binding.snapshot_artifact_digest,
                snapshotSemanticDigest=binding.snapshot_semantic_digest,
                itemDigest=concrete.item_digest,
                collectorAttemptId=provenance.collector_attempt_id,
                collectorAttemptDigest=concrete.collector_attempt_digest,
                collectorToolName=attempt.tool_name,
                collectorToolVersion=attempt.tool_version,
                collectorAttemptAt=attempt_at,
                collectorIdentityEvidenceRef=(
                    concrete.collector_identity_evidence_ref
                ),
                sourceResponseDigest=provenance.source_response_digest,
                sourceResponsePointer=provenance.source_response_pointer,
            )
        )
    return tuple(references)


__all__ = [
    "bind_evidence_references",
    "normalize_resource_id",
    "preflight_outcome",
    "prepare_transport_request",
    "project_transport_outcome",
    "scope_contains",
    "validate_trusted_identity",
]
