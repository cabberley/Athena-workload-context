from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactMetadataHashes,
    ArtifactNotFoundError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactWriteReceipt,
    ArtifactWriteRequest,
)
from athena_context.azure_adapters import production_managed_identity_credential
from athena_context.contracts import canonicalize_json, sha256_hex
from athena_context.contracts.change_ingestion import (
    ApprovedChangeScope,
    ChangeActor,
    ChangeDeliveryFailureReceipt,
    ChangedProperty,
    ChangeEvidenceArtifact,
    ChangeEvidenceAttestation,
    ChangeEvidencePersistenceHandoff,
    ChangePolicyContext,
    DeploymentSource,
    NormalizedChangeEvidence,
    change_evidence_attestation_preimage,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

MAX_CHANGE_EVENT_BYTES = 64 * 1024
MAX_RESOURCE_GRAPH_RESPONSE_BYTES = 256 * 1024
MAX_RESOURCE_GRAPH_RESULTS = 100
MAX_RESOURCE_GRAPH_QUERY_RESULTS = MAX_RESOURCE_GRAPH_RESULTS + 1
MAX_CHANGE_EVIDENCE_AGE = timedelta(minutes=15)
MAX_DEAD_LETTER_MESSAGE_BYTES = 1024 * 1024
_ARM_SCOPE = "https://management.azure.com/.default"
_RESOURCE_GRAPH_ENDPOINT = (
    "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
    "?api-version=2022-10-01"
)
_KEY_VAULT_KEY_ID_PATTERN = re.compile(
    r"^https://[a-z0-9-]{3,24}\.vault\.azure\.net/keys/"
    r"[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]{1,127}$"
)
_LOGGER = logging.getLogger(__name__)


class ChangeIngestionError(RuntimeError):
    """Raised when untrusted Azure change evidence cannot be accepted safely."""


class ChangeEvidenceArtifactSigner(Protocol):
    def sign_preimage(self, canonical_preimage: bytes) -> str: ...

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool: ...


class ChangeEvidenceReplayStorePort(Protocol):
    """Create and narrowly recover immutable evidence without Blob enumeration."""

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt: ...

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult: ...

    def read_current(self, request: ArtifactCurrentReadRequest) -> ArtifactReadResult: ...


class ResourceGraphChangeHistoryQueryPort(Protocol):
    def query_resource_changes(
        self,
        *,
        query: str,
        subscriptions: tuple[str, ...],
    ) -> Sequence[Mapping[str, object]]: ...


def _bearer_authorization(access_token: object) -> str:
    if (
        type(access_token) is not str
        or not access_token
        or any(character.isspace() for character in access_token)
    ):
        raise ChangeIngestionError("managed identity access token is invalid")
    return " ".join(("Bearer", access_token))


class _ServiceBusReceiverPort(Protocol):
    def receive_messages(
        self,
        *,
        max_message_count: int,
        max_wait_time: int,
    ) -> Sequence[object]: ...

    def complete_message(self, message: object) -> None: ...

    def dead_letter_message(
        self,
        message: object,
        *,
        reason: str,
        error_description: str,
    ) -> None: ...


def _require_utc(value: datetime, label: str) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise ChangeIngestionError(f"{label} must use UTC")
    if value.microsecond % 1000:
        raise ChangeIngestionError(
            f"{label} precision must be exactly representable in milliseconds"
        )
    return value


def _now_utc_millisecond() -> datetime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ChangeIngestionError(f"{label} must be an object")
    return value


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ChangeIngestionError(f"{label} is missing or outside its bound")
    return value


def _optional_text(value: object, label: str, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=maximum)


def _canonical_json_bytes(value: object, label: str, *, maximum: int) -> bytes:
    try:
        payload = canonicalize_json(value).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ChangeIngestionError(f"{label} is not canonical JSON") from exc
    if not 1 <= len(payload) <= maximum:
        raise ChangeIngestionError(f"{label} is outside its byte bound")
    return payload


def _parse_utc_timestamp(value: object, label: str) -> datetime:
    text = _text(value, label, maximum=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ChangeIngestionError(f"{label} is invalid") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ChangeIngestionError(f"{label} must use UTC")
    return parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)


def _opaque_reference(prefix: str, value: str) -> str:
    return f"{prefix}:sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _value_reference(prefix: str, value: object) -> str:
    payload = _canonical_json_bytes(value, "value", maximum=4096)
    return f"{prefix}:sha256:{hashlib.sha256(payload).hexdigest()}"


def _resource_type(resource_id: str) -> str:
    segments = resource_id.split("/")
    try:
        provider = segments[6]
        resource_types = segments[7::2]
    except IndexError as exc:
        raise ChangeIngestionError("target resource ID has no resource type") from exc
    if not resource_types:
        raise ChangeIngestionError("target resource ID has no resource type")
    return f"{provider}/{'/'.join(resource_types)}"


def _ensure_approved_resource(
    *,
    scope: ApprovedChangeScope,
    resource_id: str,
) -> None:
    if not scope.contains(resource_id):
        raise ChangeIngestionError(
            "change evidence target is not one exact approved workload resource"
        )


def _validate_freshness(
    *,
    occurred_at: datetime,
    received_at: datetime,
    maximum_age: timedelta,
) -> None:
    _require_utc(received_at, "received_at")
    if received_at < occurred_at:
        raise ChangeIngestionError("received_at must not precede occurred_at")
    if received_at - occurred_at > maximum_age:
        raise ChangeIngestionError("change evidence is stale")


def _actor(
    *,
    changed_by: object,
    changed_by_type: object,
    fallback: str,
) -> ChangeActor:
    raw = _optional_text(changed_by, "changedBy")
    raw_kind = (_optional_text(changed_by_type, "changedByType") or "").casefold()
    if raw is None:
        return ChangeActor(
            kind="unknown",
            reference=_opaque_reference("actor", fallback),
        )
    if raw_kind in {"user", "user, group"} or "@" in raw:
        kind: Literal["user", "application", "managedIdentity", "system", "unknown"] = "user"
    elif raw_kind in {"managedidentity", "managed identity"}:
        kind = "managedIdentity"
    elif raw_kind in {"application", "serviceprincipal", "service principal"}:
        kind = "application"
    elif raw_kind in {"system", "unknown"} or raw.casefold() in {
        "system",
        "unspecified",
        "unknown",
    }:
        kind = "system" if raw.casefold() == "system" else "unknown"
    else:
        kind = "unknown"
    return ChangeActor(kind=kind, reference=_opaque_reference("actor", raw))


def _deployment_source(
    *,
    client_type: object,
    actor_reference: str,
) -> DeploymentSource:
    raw = _optional_text(client_type, "clientType")
    lowered = "" if raw is None else raw.casefold()
    if "portal" in lowered:
        kind: Literal[
            "azurePortal",
            "automation",
            "resourceManager",
            "policy",
            "unknown",
        ] = "azurePortal"
    elif "policy" in lowered:
        kind = "policy"
    elif "resource manager" in lowered or lowered == "arm":
        kind = "resourceManager"
    elif raw is not None:
        kind = "automation"
    else:
        kind = "unknown"
    return DeploymentSource(
        kind=kind,
        reference=(
            _opaque_reference("deployment-source", raw) if raw is not None else actor_reference
        ),
    )


def _policy_context(
    *,
    assignment_id: object,
    definition_id: object,
    enforcement_mode: object,
) -> ChangePolicyContext:
    assignment = _optional_text(
        assignment_id,
        "policy assignment",
        maximum=2048,
    )
    definition = _optional_text(
        definition_id,
        "policy definition",
        maximum=2048,
    )
    raw_mode = _optional_text(enforcement_mode, "policy enforcement mode")
    normalized_mode = "" if raw_mode is None else raw_mode.casefold()
    if normalized_mode in {"default", "enabled"}:
        mode: Literal["default", "doNotEnforce", "unknown"] = "default"
    elif normalized_mode in {"donotenforce", "do not enforce", "disabled"}:
        mode = "doNotEnforce"
    else:
        mode = "unknown"
    return ChangePolicyContext(
        assignmentReference=(
            _opaque_reference("policy-assignment", assignment) if assignment is not None else None
        ),
        definitionReference=(
            _opaque_reference("policy-definition", definition) if definition is not None else None
        ),
        enforcementMode=mode,
    )


def _build_evidence(
    *,
    source_system: Literal["azureEventGrid", "azureResourceGraphChangeHistory"],
    source_record_id: str,
    source_digest: str,
    target_resource_id: str,
    operation: Literal["create", "update", "createOrUpdate", "delete", "action"],
    operation_name: str,
    result: Literal["succeeded", "failed", "unknown"],
    changed_properties: tuple[ChangedProperty, ...],
    actor: ChangeActor,
    occurred_at: datetime,
    received_at: datetime,
    correlation_id: str,
    deployment_source: DeploymentSource,
    policy_context: ChangePolicyContext,
    before_evidence_reference: str | None,
    after_evidence_reference: str | None,
) -> NormalizedChangeEvidence:
    source_record_reference = _opaque_reference("source-record", source_record_id)
    deduplication_key = sha256_hex(f"{source_system}\0{source_record_reference}".encode())
    operation_family = "write" if operation in {"create", "update", "createOrUpdate"} else operation
    change_key = sha256_hex(
        "\0".join(
            (
                target_resource_id,
                operation_family,
                result,
                correlation_id.lower(),
            )
        ).encode("utf-8")
    )
    try:
        return NormalizedChangeEvidence(
            schemaVersion="athena.changeEvidence.normalized.v1",
            evidenceId=(
                "chg-" + hashlib.sha256(deduplication_key.encode("utf-8")).hexdigest()[:12]
            ),
            deduplicationKey=deduplication_key,
            changeKey=change_key,
            sourceSystem=source_system,
            sourceRecordReference=source_record_reference,
            sourceDigest=source_digest,
            targetResourceId=target_resource_id,
            targetResourceType=_resource_type(target_resource_id),
            operation=operation,
            operationName=operation_name,
            result=result,
            changedProperties=changed_properties,
            actor=actor,
            occurredAt=occurred_at,
            receivedAt=received_at,
            correlationId=correlation_id,
            deploymentSource=deployment_source,
            policyContext=policy_context,
            beforeEvidenceReference=before_evidence_reference,
            afterEvidenceReference=after_evidence_reference,
        )
    except ValidationError as exc:
        raise ChangeIngestionError("normalized change evidence is invalid") from exc


def _event_grid_operation(
    event_type: str,
    operation_name: str,
) -> Literal["createOrUpdate", "delete", "action"]:
    lowered_event_type = event_type.casefold()
    lowered_operation = operation_name.casefold()
    if "resourceaction" in lowered_event_type or "/action" in lowered_operation:
        return "action"
    if "delete" in lowered_event_type or "/delete" in lowered_operation:
        return "delete"
    if "write" in lowered_event_type or "/write" in lowered_operation:
        return "createOrUpdate"
    raise ChangeIngestionError("Event Grid event operation is not an approved change")


def _event_grid_result(
    event_type: str,
    status: object,
) -> Literal["succeeded", "failed", "unknown"]:
    raw = _optional_text(status, "status")
    event_type_lowered = event_type.casefold()
    lowered = "" if raw is None else raw.casefold()
    if "success" in event_type_lowered or lowered in {"succeeded", "success"}:
        return "succeeded"
    if (
        "failure" in event_type_lowered
        or "cancel" in event_type_lowered
        or lowered in {"failed", "failure", "canceled", "cancelled"}
    ):
        return "failed"
    return "unknown"


def normalize_event_grid_change(
    value: object,
    *,
    scope: ApprovedChangeScope,
    received_at: datetime,
    maximum_evidence_age: timedelta = MAX_CHANGE_EVIDENCE_AGE,
) -> NormalizedChangeEvidence:
    """Normalize one resource-group Event Grid delivery without retaining raw identity data."""

    source_bytes = _canonical_json_bytes(
        value,
        "Event Grid change event",
        maximum=MAX_CHANGE_EVENT_BYTES,
    )
    event = _mapping(value, "Event Grid change event")
    data = _mapping(event.get("data"), "Event Grid event data")
    event_type = _text(event.get("eventType"), "eventType")
    source_record_id = _text(event.get("id"), "event id")
    operation_name = _text(data.get("operationName"), "operationName", maximum=256)
    target_resource_id = (
        _text(
            data.get("resourceUri") or data.get("resourceId") or event.get("subject"),
            "target resource ID",
            maximum=2048,
        )
        .lower()
        .rstrip("/")
    )
    _ensure_approved_resource(scope=scope, resource_id=target_resource_id)
    occurred_at = _parse_utc_timestamp(event.get("eventTime"), "eventTime")
    _validate_freshness(
        occurred_at=occurred_at,
        received_at=received_at,
        maximum_age=maximum_evidence_age,
    )
    correlation_id = _text(data.get("correlationId"), "correlationId", maximum=64)
    claims = data.get("claims")
    claims_map = _mapping(claims, "claims") if claims is not None else {}
    user_claim_keys = (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        "upn",
        "unique_name",
    )
    actor = _actor(
        changed_by=next(
            (claims_map[key] for key in user_claim_keys if claims_map.get(key) is not None),
            claims_map.get("appid"),
        ),
        changed_by_type=(
            "user"
            if any(claims_map.get(key) is not None for key in user_claim_keys)
            else "application"
            if claims_map.get("appid") is not None
            else None
        ),
        fallback=source_record_id,
    )
    policy = data.get("policyContext")
    policy_map = _mapping(policy, "policyContext") if policy is not None else {}
    return _build_evidence(
        source_system="azureEventGrid",
        source_record_id=source_record_id,
        source_digest=sha256_hex(source_bytes),
        target_resource_id=target_resource_id,
        operation=_event_grid_operation(event_type, operation_name),
        operation_name=operation_name,
        result=_event_grid_result(event_type, data.get("status")),
        changed_properties=(),
        actor=actor,
        occurred_at=occurred_at,
        received_at=received_at,
        correlation_id=correlation_id,
        deployment_source=_deployment_source(
            client_type=data.get("clientType") or claims_map.get("appid"),
            actor_reference=actor.reference,
        ),
        policy_context=_policy_context(
            assignment_id=policy_map.get("assignmentId") or data.get("policyAssignmentId"),
            definition_id=policy_map.get("definitionId") or data.get("policyDefinitionId"),
            enforcement_mode=policy_map.get("enforcementMode") or data.get("policyEnforcementMode"),
        ),
        before_evidence_reference=None,
        after_evidence_reference=None,
    )


def _resource_graph_operation(value: object) -> Literal["create", "update", "delete"]:
    change_type = _text(value, "changeType").casefold()
    operations: dict[str, Literal["create", "update", "delete"]] = {
        "create": "create",
        "update": "update",
        "delete": "delete",
    }
    try:
        return operations[change_type]
    except KeyError as exc:
        raise ChangeIngestionError("resource change type is not allowlisted") from exc


def _changes_count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ChangeIngestionError("changesCount is invalid")
    if value > 64:
        raise ChangeIngestionError("changesCount exceeds the property bound")
    return value


def _is_truncated(value: object) -> bool:
    if value is True or (type(value) is str and value == "true"):
        return True
    if value is False or (type(value) is str and value == "false"):
        return False
    raise ChangeIngestionError("changed property truncation marker is invalid")


def _changed_properties(
    value: object,
    *,
    changes_count: int,
) -> tuple[ChangedProperty, ...]:
    if value is None:
        if changes_count:
            raise ChangeIngestionError("Resource Graph changed-property details are incomplete")
        return ()
    changes = _mapping(value, "changes")
    if len(changes) > 64:
        raise ChangeIngestionError("changes exceeds the property bound")
    if len(changes) != changes_count:
        raise ChangeIngestionError("Resource Graph changed-property details are incomplete")
    normalized: list[ChangedProperty] = []
    for path, detail_value in changes.items():
        if type(path) is not str:
            raise ChangeIngestionError("changed property path is invalid")
        detail = _mapping(detail_value, "changed property")
        if not set(detail).issubset({"previousValue", "newValue", "isTruncated"}):
            raise ChangeIngestionError("changed property contains unsupported fields")
        before = (
            _value_reference("arg-property", detail["previousValue"])
            if "previousValue" in detail
            else None
        )
        after = (
            _value_reference("arg-property", detail["newValue"]) if "newValue" in detail else None
        )
        if before is None and after is None:
            raise ChangeIngestionError("changed property contains no value evidence")
        truncated = _is_truncated(detail.get("isTruncated", False))
        try:
            normalized.append(
                ChangedProperty(
                    path=path,
                    beforeEvidenceReference=before,
                    afterEvidenceReference=after,
                    isTruncated=truncated,
                )
            )
        except ValidationError as exc:
            raise ChangeIngestionError("changed property is invalid") from exc
    return tuple(sorted(normalized, key=lambda item: item.path))


def _snapshot_reference(value: object) -> str | None:
    snapshot = _optional_text(value, "snapshot ID", maximum=512)
    return None if snapshot is None else _opaque_reference("arg-snapshot", snapshot)


def normalize_resource_graph_change(
    value: object,
    *,
    scope: ApprovedChangeScope,
    received_at: datetime,
    maximum_evidence_age: timedelta = MAX_CHANGE_EVIDENCE_AGE,
) -> NormalizedChangeEvidence:
    """Normalize one narrow Resource Graph ``resourcechanges`` record."""

    source_bytes = _canonical_json_bytes(
        value,
        "Resource Graph change record",
        maximum=MAX_CHANGE_EVENT_BYTES,
    )
    record = _mapping(value, "Resource Graph change record")
    source_record_id = _text(record.get("id"), "Resource Graph change id", maximum=2048)
    properties = _mapping(record.get("properties"), "Resource Graph properties")
    attributes = _mapping(
        properties.get("changeAttributes"),
        "Resource Graph change attributes",
    )
    target_resource_id = (
        _text(
            properties.get("targetResourceId"),
            "target resource ID",
            maximum=2048,
        )
        .lower()
        .rstrip("/")
    )
    _ensure_approved_resource(scope=scope, resource_id=target_resource_id)
    target_resource_type = _text(
        properties.get("targetResourceType"),
        "target resource type",
        maximum=256,
    )
    if target_resource_type.casefold() != _resource_type(target_resource_id).casefold():
        raise ChangeIngestionError("target resource type does not match target resource ID")
    occurred_at = _parse_utc_timestamp(attributes.get("timestamp"), "change timestamp")
    _validate_freshness(
        occurred_at=occurred_at,
        received_at=received_at,
        maximum_age=maximum_evidence_age,
    )
    correlation_id = _text(attributes.get("correlationId"), "correlationId", maximum=64)
    actor = _actor(
        changed_by=attributes.get("changedBy"),
        changed_by_type=attributes.get("changedByType"),
        fallback=source_record_id,
    )
    return _build_evidence(
        source_system="azureResourceGraphChangeHistory",
        source_record_id=source_record_id,
        source_digest=sha256_hex(source_bytes),
        target_resource_id=target_resource_id,
        operation=_resource_graph_operation(properties.get("changeType")),
        operation_name=(
            _optional_text(attributes.get("operation"), "operation", maximum=256) or "unspecified"
        ),
        result="succeeded",
        changed_properties=_changed_properties(
            properties.get("changes"),
            changes_count=_changes_count(attributes.get("changesCount")),
        ),
        actor=actor,
        occurred_at=occurred_at,
        received_at=received_at,
        correlation_id=correlation_id,
        deployment_source=_deployment_source(
            client_type=attributes.get("clientType"),
            actor_reference=actor.reference,
        ),
        policy_context=_policy_context(
            assignment_id=attributes.get("policyAssignmentId"),
            definition_id=attributes.get("policyDefinitionId"),
            enforcement_mode=attributes.get("policyEnforcementMode"),
        ),
        before_evidence_reference=_snapshot_reference(attributes.get("previousResourceSnapshotId")),
        after_evidence_reference=_snapshot_reference(attributes.get("newResourceSnapshotId")),
    )


def build_resource_graph_change_history_query(
    *,
    scope: ApprovedChangeScope,
    since: datetime,
    until: datetime,
) -> str:
    """Build the only query the Resource Graph adapter can submit."""

    _require_utc(since, "since")
    _require_utc(until, "until")
    if since > until or until - since > MAX_CHANGE_EVIDENCE_AGE:
        raise ChangeIngestionError("Resource Graph query window is outside its bound")
    resource_ids = ", ".join(f"'{resource_id}'" for resource_id in scope.approved_resource_ids)
    since_text = since.isoformat().replace("+00:00", "Z")
    until_text = until.isoformat().replace("+00:00", "Z")
    return "\n".join(
        (
            "resourcechanges",
            (
                f"| where subscriptionId =~ '{scope.subscription_id}' and "
                f"resourceGroup =~ '{scope.resource_group_name}'"
            ),
            (
                "| extend targetResourceId=tostring(properties.targetResourceId), "
                "changeTime=todatetime(properties.changeAttributes.timestamp)"
            ),
            f"| where targetResourceId in~ ({resource_ids})",
            (f"| where changeTime between (datetime({since_text}) .. datetime({until_text}))"),
            "| order by changeTime asc",
            f"| take {MAX_RESOURCE_GRAPH_QUERY_RESULTS}",
            "| project id, properties",
        )
    )


class AzureResourceGraphChangeHistoryAdapter:
    """Query a generated, exact resourcechanges query through an isolated port."""

    def __init__(
        self,
        *,
        query_port: ResourceGraphChangeHistoryQueryPort,
        scope: ApprovedChangeScope,
        clock: Callable[[], datetime] = _now_utc_millisecond,
    ) -> None:
        self._query_port = query_port
        self._scope = scope
        self._clock = clock

    def collect(self, *, lookback: timedelta) -> tuple[NormalizedChangeEvidence, ...]:
        now = _require_utc(self._clock(), "query clock")
        if not timedelta(minutes=1) <= lookback <= MAX_CHANGE_EVIDENCE_AGE:
            raise ChangeIngestionError("Resource Graph lookback is outside its bound")
        query = build_resource_graph_change_history_query(
            scope=self._scope,
            since=now - lookback,
            until=now,
        )
        rows = self._query_port.query_resource_changes(
            query=query,
            subscriptions=(self._scope.subscription_id,),
        )
        if len(rows) > MAX_RESOURCE_GRAPH_RESULTS:
            raise ChangeIngestionError("Resource Graph returned too many change records")
        normalized = tuple(
            normalize_resource_graph_change(
                row,
                scope=self._scope,
                received_at=now,
            )
            for row in rows
        )
        if [item.occurred_at for item in normalized] != sorted(
            item.occurred_at for item in normalized
        ):
            raise ChangeIngestionError("Resource Graph change records are not ordered")
        return normalized


class ManagedIdentityResourceGraphChangeHistoryClient:
    """Managed-identity REST adapter with no caller-selected endpoint or query."""

    def __init__(self, *, managed_identity_client_id: str) -> None:
        from azure.identity import ManagedIdentityCredential

        self._credential = ManagedIdentityCredential(client_id=managed_identity_client_id)

    def query_resource_changes(
        self,
        *,
        query: str,
        subscriptions: tuple[str, ...],
    ) -> Sequence[Mapping[str, object]]:
        if (
            type(query) is not str
            or not query.startswith("resourcechanges\n")
            or len(query.encode("utf-8")) > 32 * 1024
            or len(subscriptions) != 1
        ):
            raise ChangeIngestionError("Resource Graph request is not the bounded query")
        request = Request(
            _RESOURCE_GRAPH_ENDPOINT,
            data=json.dumps(
                {
                    "subscriptions": list(subscriptions),
                    "query": query,
                    "options": {
                        "$top": MAX_RESOURCE_GRAPH_QUERY_RESULTS,
                        "resultFormat": "ObjectArray",
                    },
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        token = self._credential.get_token(_ARM_SCOPE)
        request.add_unredirected_header(
            "Authorization",
            _bearer_authorization(token.token),
        )
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310
                payload = response.read(MAX_RESOURCE_GRAPH_RESPONSE_BYTES + 1)
                if response.status != 200 or len(payload) > MAX_RESOURCE_GRAPH_RESPONSE_BYTES:
                    raise ChangeIngestionError(
                        "Resource Graph response was unsuccessful or outside its byte bound"
                    )
        except ChangeIngestionError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ChangeIngestionError("Resource Graph query failed") from exc
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChangeIngestionError("Resource Graph response was not JSON") from exc
        response_body = _mapping(parsed, "Resource Graph response")
        if any(marker in response_body for marker in ("$skipToken", "skipToken")):
            raise ChangeIngestionError("Resource Graph response is incomplete")
        result_truncated = response_body.get("resultTruncated")
        if result_truncated is False or (
            type(result_truncated) is str and result_truncated == "false"
        ):
            pass
        elif result_truncated is True or (
            type(result_truncated) is str and result_truncated == "true"
        ):
            raise ChangeIngestionError("Resource Graph response is incomplete")
        else:
            raise ChangeIngestionError("Resource Graph response truncation marker is invalid")
        rows = response_body.get("data")
        if not isinstance(rows, list) or len(rows) > MAX_RESOURCE_GRAPH_QUERY_RESULTS:
            raise ChangeIngestionError("Resource Graph response data is invalid")
        return tuple(_mapping(row, "Resource Graph response row") for row in rows)


class KeyVaultChangeEvidenceSigner:
    """Sign bounded artifacts with one exact, versioned Key Vault key."""

    def __init__(
        self,
        *,
        key_vault_key_id: str,
        managed_identity_client_id: str,
    ) -> None:
        from azure.keyvault.keys.crypto import CryptographyClient

        if _KEY_VAULT_KEY_ID_PATTERN.fullmatch(key_vault_key_id) is None:
            raise ValueError("key_vault_key_id must be one exact versioned Key Vault key")
        self._client = CryptographyClient(
            key_vault_key_id,
            production_managed_identity_credential(
                managed_identity_client_id=managed_identity_client_id
            ),
        )

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        from azure.keyvault.keys.crypto import SignatureAlgorithm

        if not canonical_preimage or len(canonical_preimage) > MAX_CHANGE_EVENT_BYTES:
            raise ChangeIngestionError("change evidence signature preimage is invalid")
        result = self._client.sign(
            SignatureAlgorithm.rs256,
            hashlib.sha256(canonical_preimage).digest(),
        )
        signature = bytes(result.signature)
        if not signature:
            raise ChangeIngestionError("Key Vault returned an empty change evidence signature")
        return base64.b64encode(signature).decode("ascii")

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool:
        from azure.keyvault.keys.crypto import SignatureAlgorithm

        if (
            type(canonical_preimage) is not bytes
            or not canonical_preimage
            or len(canonical_preimage) > MAX_CHANGE_EVENT_BYTES
            or type(signature) is not bytes
            or not signature
        ):
            return False
        result = self._client.verify(
            SignatureAlgorithm.rs256,
            hashlib.sha256(canonical_preimage).digest(),
            signature,
        )
        return result.is_valid is True


def build_change_evidence_artifact(
    evidence: NormalizedChangeEvidence,
    *,
    signer: ChangeEvidenceArtifactSigner,
    signing_key_id: str,
) -> ChangeEvidenceArtifact:
    preimage = change_evidence_attestation_preimage(evidence)
    canonical_preimage = canonicalize_json(preimage).encode("utf-8")
    try:
        return ChangeEvidenceArtifact(
            schemaVersion="athena.changeEvidenceArtifact.v1",
            evidence=evidence,
            attestation=ChangeEvidenceAttestation(
                schemaVersion="athena.changeEvidenceAttestation.v1",
                signatureAlgorithm="RS256",
                keyVaultKeyId=signing_key_id,
                signedPreimageDigest=sha256_hex(canonical_preimage),
                signature=signer.sign_preimage(canonical_preimage),
            ),
        )
    except ValidationError as exc:
        raise ChangeIngestionError("signed change evidence artifact is invalid") from exc


def _artifact_blob_name(evidence: NormalizedChangeEvidence) -> str:
    return f"change-evidence/{evidence.deduplication_key.removeprefix('sha256:')}/evidence.json"


def _handoff_blob_name(evidence: NormalizedChangeEvidence) -> str:
    return (
        f"change-evidence/{evidence.deduplication_key.removeprefix('sha256:')}/"
        "persistence-handoff.json"
    )


def _version_pinned_reference(
    *,
    blob_name: str,
    version_id: str,
    payload_sha256: str,
) -> VersionPinnedBlobReference:
    return VersionPinnedBlobReference(
        name=blob_name,
        version=version_id,
        contentDigest=payload_sha256,
    )


def _persistence_handoff(
    *,
    evidence: NormalizedChangeEvidence,
    artifact: VersionPinnedBlobReference,
) -> ChangeEvidencePersistenceHandoff:
    return ChangeEvidencePersistenceHandoff(
        schemaVersion="athena.changeEvidencePersistenceHandoff.v1",
        evidenceId=evidence.evidence_id,
        deduplicationKey=evidence.deduplication_key,
        changeKey=evidence.change_key,
        artifact=artifact,
    )


def _validate_recovered_artifact(
    result: ArtifactReadResult,
    *,
    evidence: NormalizedChangeEvidence,
    signing_key_id: str,
    signer: ChangeEvidenceArtifactSigner,
) -> None:
    try:
        artifact = ChangeEvidenceArtifact.model_validate_json(result.payload)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ChangeIngestionError("recovered change evidence artifact is invalid") from exc
    recovered = artifact.evidence
    if (
        _source_record_evidence_bytes(recovered)
        != _source_record_evidence_bytes(evidence)
        or artifact.attestation.key_vault_key_id != signing_key_id
    ):
        raise ChangeIngestionError(
            "recovered change evidence artifact does not match the bounded source record"
        )
    canonical_preimage = canonicalize_json(change_evidence_attestation_preimage(recovered)).encode(
        "utf-8"
    )
    try:
        signature = base64.b64decode(artifact.attestation.signature, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ChangeIngestionError(
            "recovered change evidence artifact signature is malformed"
        ) from exc
    if (
        not signature
        or base64.b64encode(signature).decode("ascii") != artifact.attestation.signature
    ):
        raise ChangeIngestionError("recovered change evidence artifact signature is malformed")
    verified = signer.verify_preimage(canonical_preimage, signature)
    if verified is not True:
        raise ChangeIngestionError(
            "recovered change evidence artifact signature verification failed"
        )


def _source_record_evidence_bytes(
    evidence: NormalizedChangeEvidence,
) -> bytes:
    payload = evidence.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"received_at"},
    )
    return (canonicalize_json(payload) + "\n").encode("utf-8")


def _recover_durable_handoff(
    *,
    evidence: NormalizedChangeEvidence,
    store: ChangeEvidenceReplayStorePort,
    signing_key_id: str,
    signer: ChangeEvidenceArtifactSigner,
) -> ChangeEvidencePersistenceHandoff | None:
    try:
        result = store.read_current(
            ArtifactCurrentReadRequest(blob_name=_handoff_blob_name(evidence))
        )
    except ArtifactNotFoundError:
        return None
    try:
        handoff = ChangeEvidencePersistenceHandoff.model_validate_json(result.payload)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ChangeIngestionError("recovered persistence handoff is invalid") from exc
    if (
        handoff.evidence_id != evidence.evidence_id
        or handoff.deduplication_key != evidence.deduplication_key
        or handoff.change_key != evidence.change_key
    ):
        raise ChangeIngestionError(
            "recovered persistence handoff does not match the bounded source record"
        )
    artifact = store.read(
        ArtifactReadRequest(
            blob_name=handoff.artifact.name,
            version_id=handoff.artifact.version,
            expected_payload_sha256=handoff.artifact.content_digest,
        )
    )
    _validate_recovered_artifact(
        artifact,
        evidence=evidence,
        signing_key_id=signing_key_id,
        signer=signer,
    )
    return handoff


def _recover_existing_artifact(
    *,
    evidence: NormalizedChangeEvidence,
    store: ChangeEvidenceReplayStorePort,
    signing_key_id: str,
    signer: ChangeEvidenceArtifactSigner,
) -> VersionPinnedBlobReference:
    result = store.read_current(ArtifactCurrentReadRequest(blob_name=_artifact_blob_name(evidence)))
    _validate_recovered_artifact(
        result,
        evidence=evidence,
        signing_key_id=signing_key_id,
        signer=signer,
    )
    return _version_pinned_reference(
        blob_name=result.blob_name,
        version_id=result.version_id,
        payload_sha256=result.payload_sha256,
    )


def persist_change_evidence(
    evidence: NormalizedChangeEvidence,
    *,
    writer: ChangeEvidenceReplayStorePort,
    signer: ChangeEvidenceArtifactSigner,
    signing_key_id: str,
) -> ChangeEvidencePersistenceHandoff:
    """Persist a signed artifact and durable handoff before accepting the source record."""

    if handoff := _recover_durable_handoff(
        evidence=evidence,
        store=writer,
        signing_key_id=signing_key_id,
        signer=signer,
    ):
        return handoff

    try:
        artifact_reference = _recover_existing_artifact(
            evidence=evidence,
            store=writer,
            signing_key_id=signing_key_id,
            signer=signer,
        )
    except ArtifactNotFoundError:
        artifact = build_change_evidence_artifact(
            evidence=evidence,
            signer=signer,
            signing_key_id=signing_key_id,
        )
        artifact_payload = artifact.canonical_bytes()
        artifact_request = ArtifactWriteRequest(
            blob_name=_artifact_blob_name(evidence),
            payload=artifact_payload,
            content_type="application/json",
            hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(artifact_payload)),
            maximum_payload_bytes=MAX_CHANGE_EVENT_BYTES,
        )
        try:
            receipt = writer.create(artifact_request)
        except ArtifactAlreadyExistsError:
            artifact_reference = _recover_existing_artifact(
                evidence=evidence,
                store=writer,
                signing_key_id=signing_key_id,
                signer=signer,
            )
        else:
            artifact_reference = _version_pinned_reference(
                blob_name=receipt.blob_name,
                version_id=receipt.version_id,
                payload_sha256=receipt.payload_sha256,
            )
    handoff = _persistence_handoff(evidence=evidence, artifact=artifact_reference)
    handoff_payload = handoff.canonical_bytes()
    handoff_request = ArtifactWriteRequest(
        blob_name=_handoff_blob_name(evidence),
        payload=handoff_payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(handoff_payload)),
        maximum_payload_bytes=MAX_CHANGE_EVENT_BYTES,
    )
    try:
        writer.create(handoff_request)
    except ArtifactAlreadyExistsError:
        recovered_handoff = _recover_durable_handoff(
            evidence=evidence,
            store=writer,
            signing_key_id=signing_key_id,
            signer=signer,
        )
        if recovered_handoff is None:
            raise ChangeIngestionError("persistence handoff disappeared during recovery") from None
        if recovered_handoff != handoff:
            raise ChangeIngestionError(
                "recovered persistence handoff does not match the created artifact"
            ) from None
        return recovered_handoff
    return handoff


def ingest_event_grid_delivery(
    value: object,
    *,
    scope: ApprovedChangeScope,
    received_at: datetime,
    writer: ChangeEvidenceReplayStorePort,
    signer: ChangeEvidenceArtifactSigner,
    signing_key_id: str,
) -> ChangeEvidencePersistenceHandoff:
    evidence = normalize_event_grid_change(
        value,
        scope=scope,
        received_at=received_at,
    )
    return persist_change_evidence(
        evidence,
        writer=writer,
        signer=signer,
        signing_key_id=signing_key_id,
    )


def ingest_resource_graph_changes(
    evidence: Sequence[NormalizedChangeEvidence],
    *,
    writer: ChangeEvidenceReplayStorePort,
    signer: ChangeEvidenceArtifactSigner,
    signing_key_id: str,
) -> tuple[ChangeEvidencePersistenceHandoff, ...]:
    handoffs = [
        persist_change_evidence(
            item,
            writer=writer,
            signer=signer,
            signing_key_id=signing_key_id,
        )
        for item in evidence
    ]
    return tuple(handoffs)


def _message_body(message: object) -> bytes:
    body = getattr(message, "body", None)
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    if body is not None:
        try:
            return b"".join(body)
        except TypeError:
            pass
    raise ChangeIngestionError("Service Bus message body is invalid")


def _event_grid_records(message: object) -> tuple[Mapping[str, object], ...]:
    body = _message_body(message)
    if not 1 <= len(body) <= MAX_CHANGE_EVENT_BYTES:
        raise ChangeIngestionError("Event Grid message is outside its byte bound")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChangeIngestionError("Event Grid message is not JSON") from exc
    records = value if isinstance(value, list) else [value]
    if not 1 <= len(records) <= 16:
        raise ChangeIngestionError("Event Grid delivery batch is outside its bound")
    return tuple(_mapping(record, "Event Grid delivery record") for record in records)


def _message_digest(message: object) -> str:
    try:
        return sha256_hex(_message_body(message))
    except ChangeIngestionError:
        return "unavailable"


def _process_event_grid_message(
    *,
    receiver: _ServiceBusReceiverPort,
    message: object,
    scope: ApprovedChangeScope,
    received_at: datetime,
    writer: ChangeEvidenceReplayStorePort,
    signer: ChangeEvidenceArtifactSigner,
    signing_key_id: str,
) -> int:
    try:
        records = _event_grid_records(message)
        evidence = tuple(
            normalize_event_grid_change(
                record,
                scope=scope,
                received_at=received_at,
            )
            for record in records
        )
    except (ChangeIngestionError, ValueError) as exc:
        _LOGGER.warning(
            "Discarding definitively rejected WC-025 delivery category=%s digest=%s",
            exc.__class__.__name__,
            _message_digest(message),
        )
        receiver.complete_message(message)
        return 0
    for item in evidence:
        persist_change_evidence(
            item,
            writer=writer,
            signer=signer,
            signing_key_id=signing_key_id,
        )
    receiver.complete_message(message)
    return len(records)


def run_event_grid_change_ingestion_worker(
    *,
    fully_qualified_namespace: str,
    queue_name: str,
    managed_identity_client_id: str,
    scope: ApprovedChangeScope,
    artifact_blob_endpoint: str,
    artifact_container_name: str,
    signing_key_id: str,
    max_wait_time_seconds: int = 30,
) -> int:
    """Consume one resource-group Event Grid batch and hand off signed evidence."""

    from azure.identity import ManagedIdentityCredential

    from athena_context.azure_adapters import AzureBlobChangeEvidenceReplayStore

    service_bus_client = import_module("azure.servicebus").ServiceBusClient
    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or not 1 <= max_wait_time_seconds <= 300
    ):
        raise ValueError("change ingestion worker configuration is invalid")
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    writer = AzureBlobChangeEvidenceReplayStore(
        blob_endpoint=artifact_blob_endpoint,
        container_name=artifact_container_name,
        managed_identity_client_id=managed_identity_client_id,
        max_payload_bytes=MAX_CHANGE_EVENT_BYTES,
    )
    signer = KeyVaultChangeEvidenceSigner(
        key_vault_key_id=signing_key_id,
        managed_identity_client_id=managed_identity_client_id,
    )
    with (
        service_bus_client(
            fully_qualified_namespace=fully_qualified_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_receiver(
            queue_name=queue_name,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
    ):
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return 0
        return _process_event_grid_message(
            receiver=receiver,
            message=messages[0],
            scope=scope,
            received_at=_now_utc_millisecond(),
            writer=writer,
            signer=signer,
            signing_key_id=signing_key_id,
        )


def run_event_grid_dead_letter_purge_worker(
    *,
    fully_qualified_namespace: str,
    queue_name: str,
    managed_identity_client_id: str,
    artifact_blob_endpoint: str,
    failure_container_name: str,
    maximum_messages_per_subqueue: int = 100,
    max_wait_time_seconds: int = 5,
) -> int:
    """Permanently discard raw poison deliveries from both Service Bus DLQ paths."""

    from azure.identity import ManagedIdentityCredential

    from athena_context.azure_adapters import AzureBlobChangeEvidenceReplayStore

    service_bus = import_module("azure.servicebus")
    if (
        not fully_qualified_namespace.endswith(".servicebus.windows.net")
        or "/" in fully_qualified_namespace
        or not 1 <= maximum_messages_per_subqueue <= 1_000
        or not 1 <= max_wait_time_seconds <= 60
    ):
        raise ValueError("change dead-letter purge configuration is invalid")
    credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    writer = AzureBlobChangeEvidenceReplayStore(
        blob_endpoint=artifact_blob_endpoint,
        container_name=failure_container_name,
        managed_identity_client_id=managed_identity_client_id,
        max_payload_bytes=MAX_CHANGE_EVENT_BYTES,
    )
    purged = 0
    with service_bus.ServiceBusClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=credential,
        logging_enable=False,
    ) as client:
        for sub_queue in (
            ("deadLetter", service_bus.ServiceBusSubQueue.DEAD_LETTER),
            (
                "transferDeadLetter",
                service_bus.ServiceBusSubQueue.TRANSFER_DEAD_LETTER,
            ),
        ):
            with client.get_queue_receiver(
                queue_name=queue_name,
                sub_queue=sub_queue[1],
                max_wait_time=max_wait_time_seconds,
            ) as receiver:
                messages = receiver.receive_messages(
                    max_message_count=maximum_messages_per_subqueue,
                    max_wait_time=max_wait_time_seconds,
                )
                for message in messages:
                    _persist_change_delivery_failure_receipt(
                        message=message,
                        dead_letter_subqueue=sub_queue[0],
                        writer=writer,
                    )
                    receiver.complete_message(message)
                purged += len(messages)
    return purged


def _persist_change_delivery_failure_receipt(
    *,
    message: object,
    dead_letter_subqueue: Literal["deadLetter", "transferDeadLetter"],
    writer: ChangeEvidenceReplayStorePort,
) -> None:
    body = _message_body(message)
    if len(body) > MAX_DEAD_LETTER_MESSAGE_BYTES:
        raise ChangeIngestionError("dead-letter message is outside its byte bound")
    source_message_digest = sha256_hex(body)
    failure_id = (
        "chg-failure-"
        + hashlib.sha256(
            f"{dead_letter_subqueue}\0{source_message_digest}".encode()
        ).hexdigest()[:12]
    )
    receipt = ChangeDeliveryFailureReceipt(
        schemaVersion="athena.changeDeliveryFailureReceipt.v1",
        failureId=failure_id,
        sourceMessageDigest=source_message_digest,
        deadLetterSubqueue=dead_letter_subqueue,
        disposition="rawMessageCompletedAfterReceipt",
    )
    payload = receipt.canonical_bytes()
    payload_sha256 = sha256_hex(payload)
    blob_name = f"change-delivery-failures/{failure_id}/receipt.json"
    request = ArtifactWriteRequest(
        blob_name=blob_name,
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(payload_sha256=payload_sha256),
        maximum_payload_bytes=MAX_CHANGE_EVENT_BYTES,
    )
    try:
        writer.create(request)
    except ArtifactAlreadyExistsError:
        recovered = writer.read_current(
            ArtifactCurrentReadRequest(blob_name=blob_name)
        )
        if (
            recovered.payload != payload
            or recovered.payload_sha256 != payload_sha256
            or sha256_hex(recovered.payload) != payload_sha256
        ):
            raise ChangeIngestionError(
                "recovered change delivery failure receipt is invalid"
            ) from None


def run_resource_graph_change_history_worker(
    *,
    managed_identity_client_id: str,
    scope: ApprovedChangeScope,
    artifact_blob_endpoint: str,
    artifact_container_name: str,
    signing_key_id: str,
    lookback: timedelta = timedelta(minutes=10),
) -> int:
    """Query only the bounded change-history window and persist signed evidence."""

    from athena_context.azure_adapters import AzureBlobChangeEvidenceReplayStore

    evidence = AzureResourceGraphChangeHistoryAdapter(
        query_port=ManagedIdentityResourceGraphChangeHistoryClient(
            managed_identity_client_id=managed_identity_client_id
        ),
        scope=scope,
    ).collect(lookback=lookback)
    handoffs = ingest_resource_graph_changes(
        evidence,
        writer=AzureBlobChangeEvidenceReplayStore(
            blob_endpoint=artifact_blob_endpoint,
            container_name=artifact_container_name,
            managed_identity_client_id=managed_identity_client_id,
            max_payload_bytes=MAX_CHANGE_EVENT_BYTES,
        ),
        signer=KeyVaultChangeEvidenceSigner(
            key_vault_key_id=signing_key_id,
            managed_identity_client_id=managed_identity_client_id,
        ),
        signing_key_id=signing_key_id,
    )
    return len(handoffs)


__all__ = [
    "AzureResourceGraphChangeHistoryAdapter",
    "ChangeEvidenceArtifactSigner",
    "ChangeEvidenceReplayStorePort",
    "ChangeIngestionError",
    "KeyVaultChangeEvidenceSigner",
    "MAX_CHANGE_EVIDENCE_AGE",
    "MAX_CHANGE_EVENT_BYTES",
    "MAX_RESOURCE_GRAPH_RESPONSE_BYTES",
    "ManagedIdentityResourceGraphChangeHistoryClient",
    "ResourceGraphChangeHistoryQueryPort",
    "build_change_evidence_artifact",
    "build_resource_graph_change_history_query",
    "ingest_event_grid_delivery",
    "ingest_resource_graph_changes",
    "normalize_event_grid_change",
    "normalize_resource_graph_change",
    "persist_change_evidence",
    "run_event_grid_dead_letter_purge_worker",
    "run_event_grid_change_ingestion_worker",
    "run_resource_graph_change_history_worker",
]
