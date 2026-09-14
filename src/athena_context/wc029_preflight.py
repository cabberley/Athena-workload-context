from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, TextIO

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CHANGES = 5000
MAX_ASSIGNMENTS = 10000
MAX_POLICY_ITEMS = 512
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100000
MAX_JSON_INTEGER_DIGITS = 1024

_BROAD_ROLES = frozenset(
    {
        "owner",
        "contributor",
        "reader",
        "role based access control administrator",
        "user access administrator",
    }
)
_ROLE_ID_TO_NAME = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "reader",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": ("role based access control administrator"),
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": ("user access administrator"),
}
_BROAD_ROLE_IDS = frozenset(_ROLE_ID_TO_NAME)
_GUID_PATTERN = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
_GUID = re.compile(rf"^{_GUID_PATTERN}$", re.IGNORECASE)
_SUBSCRIPTION_SCOPE = re.compile(
    rf"^/subscriptions/{_GUID_PATTERN}$",
    re.IGNORECASE,
)
_RESOURCE_GROUP_SCOPE = re.compile(
    rf"^/subscriptions/{_GUID_PATTERN}/resourcegroups/[^/]+$",
    re.IGNORECASE,
)
_MANAGEMENT_GROUP_SCOPE = re.compile(
    r"^/providers/microsoft.management/managementgroups/[^/]+$",
    re.IGNORECASE,
)
_STORAGE_ACCOUNT_TYPE = "microsoft.storage/storageaccounts"
_STORAGE_CONTAINER_TYPE = "microsoft.storage/storageaccounts/blobservices/containers"
_KEY_VAULT_TYPE = "microsoft.keyvault/vaults"
_CONTAINER_APP_TYPE = "microsoft.app/containerapps"
_CONTAINER_ENVIRONMENT_TYPE = "microsoft.app/managedenvironments"


class PreflightInputError(ValueError):
    """Raised when a preflight artifact or policy is malformed."""


@dataclass(frozen=True, slots=True)
class PreflightViolation:
    code: str
    subject: str
    detail: str


@dataclass(frozen=True, slots=True)
class BroadAssignmentAllowance:
    principal_id: str
    role_name: str
    scope: str


@dataclass(frozen=True, slots=True)
class SeparationRule:
    principal_id: str
    forbidden_role_names: frozenset[str]
    forbidden_scope_prefixes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RbacPolicy:
    allowed_broad_assignments: frozenset[BroadAssignmentAllowance]
    separation_rules: tuple[SeparationRule, ...]
    expected_principal_ids: frozenset[str]


type PreflightKind = Literal["rbac", "what-if"]
type PreflightOutputFormat = Literal["json", "text"]


def _normalized(value: str) -> str:
    return value.strip().casefold()


def _resource_type(resource_id: str) -> str:
    segments = [segment for segment in resource_id.strip("/").casefold().split("/") if segment]
    if len(segments) >= 5 and segments[0] == "subscriptions":
        initial_provider_index = 4 if segments[2] == "resourcegroups" else 2
    elif segments and segments[0] == "providers":
        initial_provider_index = 0
    else:
        raise PreflightInputError("resourceId has an unsupported ARM scope")
    if initial_provider_index >= len(segments) or segments[initial_provider_index] != "providers":
        raise PreflightInputError("resourceId is missing its structural provider boundary")
    provider_indices = [initial_provider_index]
    provider_indices.extend(
        index
        for index in range(
            initial_provider_index + 4,
            len(segments),
            2,
        )
        if segments[index] == "providers"
    )
    provider_index = provider_indices[-1]
    try:
        namespace = segments[provider_index + 1]
    except IndexError as exc:
        raise PreflightInputError("resourceId provider boundary is incomplete") from exc
    type_segments = segments[provider_index + 2 :: 2]
    name_segments = segments[provider_index + 3 :: 2]
    if not type_segments or len(type_segments) != len(name_segments):
        raise PreflightInputError("resourceId does not contain a resource type")
    return "/".join((namespace, *type_segments))


def _reject_json_constant(value: str) -> None:
    raise PreflightInputError(f"invalid JSON constant: {value}")


def _parse_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise PreflightInputError(
            f"JSON integer exceeds {MAX_JSON_INTEGER_DIGITS} digits"
        )
    try:
        return int(value)
    except ValueError as exc:
        raise PreflightInputError("JSON integer is invalid") from exc


def _reject_ambiguous_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    casefolded_keys: set[str] = set()
    for key, value in pairs:
        if key in result:
            raise PreflightInputError("JSON object contains a duplicate key")
        casefolded = key.casefold()
        if casefolded in casefolded_keys:
            raise PreflightInputError(
                "JSON object contains a case-insensitive key collision"
            )
        result[key] = value
        casefolded_keys.add(casefolded)
    return result


def _canonical_role_key(value: str) -> str:
    normalized = _normalized(value).rsplit("/", 1)[-1]
    return _ROLE_ID_TO_NAME.get(normalized, normalized)


def _canonical_role_id(value: str) -> str:
    normalized = _normalized(value)
    if "/" not in normalized:
        if _GUID.fullmatch(normalized) is None:
            raise PreflightInputError("roleDefinitionId must end in a role GUID")
        return normalized
    canonical = _canonical_scope(normalized)
    segments = canonical.strip("/").split("/")
    if (
        len(segments) < 4
        or segments[-3] != "microsoft.authorization"
        or segments[-2] != "roledefinitions"
        or _GUID.fullmatch(segments[-1]) is None
    ):
        raise PreflightInputError(
            "roleDefinitionId must identify a Microsoft.Authorization role definition"
        )
    return segments[-1]


def _canonical_property_path(value: str) -> str:
    normalized = value.casefold()
    prefix = "<resource>."
    return normalized.removeprefix(prefix) if normalized.startswith(prefix) else normalized


def _canonical_scope(value: str) -> str:
    normalized = _normalized(value)
    canonical = normalized.rstrip("/") or "/"
    if (
        not canonical.startswith("/")
        or "//" in canonical
        or any(character in canonical for character in ("\\", "?", "#", "%"))
    ):
        raise PreflightInputError("scope must be a canonical ARM scope")
    if canonical == "/":
        return canonical
    segments = canonical[1:].split("/")
    if any(
        not segment
        or segment in {".", ".."}
        or segment != segment.strip()
        for segment in segments
    ):
        raise PreflightInputError("scope must be a canonical ARM scope")
    if segments[0] == "subscriptions":
        if len(segments) < 2 or _GUID.fullmatch(segments[1]) is None:
            raise PreflightInputError("scope must contain a valid subscription ID")
        if len(segments) == 2:
            return canonical
        if segments[2] == "resourcegroups":
            if len(segments) < 4:
                raise PreflightInputError("resource-group scope is incomplete")
            if len(segments) == 4:
                return canonical
            provider_index = 4
        elif segments[2] == "providers":
            provider_index = 2
        else:
            raise PreflightInputError("scope has an unsupported subscription boundary")
    elif segments[0] == "providers":
        provider_index = 0
    else:
        raise PreflightInputError("scope has an unsupported ARM boundary")
    index = provider_index
    while index < len(segments):
        if segments[index] != "providers" or index + 3 >= len(segments):
            raise PreflightInputError("scope has an incomplete provider boundary")
        index += 2
        resource_pairs = 0
        while index < len(segments) and segments[index] != "providers":
            if index + 1 >= len(segments) or segments[index + 1] == "providers":
                raise PreflightInputError("scope has an incomplete resource boundary")
            resource_pairs += 1
            index += 2
        if resource_pairs == 0:
            raise PreflightInputError("scope has an incomplete provider boundary")
    return canonical


def _scope_contains(ancestor: str, descendant: str) -> bool:
    return (
        ancestor == "/"
        or descendant == ancestor
        or descendant.startswith(ancestor + "/")
    )


def _require_string(
    value: object,
    *,
    field_name: str,
    maximum_length: int = 4096,
) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > maximum_length
        or not value.isprintable()
    ):
        raise PreflightInputError(f"{field_name} must be a bounded string")
    return value.strip()


def load_json_file(
    path: Path,
    *,
    maximum_bytes: int = MAX_INPUT_BYTES,
) -> object:
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("maximum_bytes must be a positive integer")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PreflightInputError(f"cannot read {path}") from exc
    if size < 1 or size > maximum_bytes:
        raise PreflightInputError(f"{path} must contain between 1 and {maximum_bytes} bytes")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
            parse_int=_parse_json_integer,
            object_pairs_hook=_reject_ambiguous_object_pairs,
        )
        _validate_json_shape(document)
        return document
    except PreflightInputError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise PreflightInputError(f"{path} is not valid UTF-8 JSON") from exc


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise PreflightInputError("JSON structure exceeds depth or node bounds")
        if isinstance(item, dict):
            if any(
                type(key) is not str
                or len(key) > 4096
                or not key.isprintable()
                for key in item
            ):
                raise PreflightInputError("JSON object keys are invalid")
            casefolded_keys = [key.casefold() for key in item]
            if len(casefolded_keys) != len(set(casefolded_keys)):
                raise PreflightInputError(
                    "JSON object contains a case-insensitive key collision"
                )
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_INPUT_BYTES:
                raise PreflightInputError("JSON string exceeds its bound")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise PreflightInputError("JSON contains a non-finite number")
        elif item is not None and not isinstance(item, (bool, int)):
            raise PreflightInputError("JSON contains an unsupported value")


def _mapping(value: object, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise PreflightInputError(f"{field_name} must be an object")
    return value


def _sequence(
    value: object,
    *,
    field_name: str,
    maximum_items: int,
) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise PreflightInputError(
            f"{field_name} must be an array with at most {maximum_items} items"
        )
    return value


def _get_case_insensitive(mapping: dict[str, Any], name: str) -> object:
    expected = name.casefold()
    for key, value in mapping.items():
        if key.casefold() == expected:
            return value
    return None


def _what_if_changes(document: object) -> list[object]:
    _validate_json_shape(document)
    root = _mapping(document, field_name="what-if document")
    status = _normalized(
        _require_string(
            _get_case_insensitive(root, "status"),
            field_name="status",
            maximum_length=64,
        )
    )
    error = _get_case_insensitive(root, "error")
    if status != "succeeded" or (error is not None and error != {}):
        raise PreflightInputError("what-if operation did not succeed")
    properties = _get_case_insensitive(root, "properties")
    container = _mapping(properties, field_name="properties") if properties is not None else root
    changes = _get_case_insensitive(container, "changes")
    return _sequence(
        changes,
        field_name="changes",
        maximum_items=MAX_CHANGES,
    )


def _delta_entries(change: dict[str, Any]) -> list[dict[str, Any]]:
    raw = _get_case_insensitive(change, "delta")
    if raw is None:
        return []
    return [
        _mapping(item, field_name="delta item")
        for item in _sequence(
            raw,
            field_name="delta",
            maximum_items=MAX_CHANGES,
        )
    ]


def _walk_delta(
    items: list[dict[str, Any]],
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[dict[str, Any], str]] = [(item, "") for item in reversed(items)]
    while stack:
        item, parent_path = stack.pop()
        own_path = _require_string(
            _get_case_insensitive(item, "path"),
            field_name="delta path",
        )
        path = ".".join(part for part in (parent_path, own_path) if part)
        children = _get_case_insensitive(item, "children")
        raw_change_type = _get_case_insensitive(
            item,
            "propertyChangeType",
        )
        property_change_type = (
            "array"
            if raw_change_type is None and children is not None
            else _normalized(
                _require_string(
                    raw_change_type,
                    field_name="propertyChangeType",
                    maximum_length=64,
                )
            )
        )
        if property_change_type not in {
            "array",
            "create",
            "delete",
            "modify",
            "noeffect",
            "remove",
        }:
            raise PreflightInputError("delta propertyChangeType is unsupported")
        after = _get_case_insensitive(item, "after")
        if (
            property_change_type not in {"delete", "remove", "noeffect"}
            and after is None
            and children is None
        ):
            raise PreflightInputError("delta item lacks inspectable after value or children")
        values.append(
            (
                path,
                after,
                property_change_type,
            )
        )
        if children is not None:
            child_items = [
                _mapping(child, field_name="delta child")
                for child in _sequence(
                    children,
                    field_name="delta children",
                    maximum_items=MAX_CHANGES,
                )
            ]
            stack.extend((child, path) for child in reversed(child_items))
    return values


def _flatten_after(
    value: object,
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[object, str]] = [(value, "<resource>")]
    while stack:
        item, path = stack.pop()
        if isinstance(item, dict):
            stack.extend((child, f"{path}.{key}") for key, child in reversed(list(item.items())))
        elif isinstance(item, list):
            stack.extend(
                (child, f"{path}[{index}]") for index, child in reversed(list(enumerate(item)))
            )
        else:
            values.append((path, item, "set"))
    return values


def _enabled(value: object) -> bool:
    return value is True or (
        isinstance(value, str) and value.strip().casefold() in {"allow", "enabled", "true"}
    )


def _unsafe_property_violations(
    resource_id: str,
    change: dict[str, Any],
) -> tuple[PreflightViolation, ...]:
    resource_type = _resource_type(resource_id)
    change_type = _normalized(
        _require_string(
            _get_case_insensitive(change, "changeType"),
            field_name="changeType",
            maximum_length=64,
        )
    )
    violations: list[PreflightViolation] = []
    delta = _delta_entries(change)
    candidates = _walk_delta(delta) if delta else []
    after_payload = _get_case_insensitive(change, "after")
    if isinstance(after_payload, (dict, list)):
        candidates.extend(_flatten_after(after_payload))
    if resource_type == _STORAGE_ACCOUNT_TYPE and change_type == "create":
        values_by_path = {_canonical_property_path(path): value for path, value, _ in candidates}

        shared_key = values_by_path.get("properties.allowsharedkeyaccess")
        public_blob_access = values_by_path.get("properties.allowblobpublicaccess")
        public_network = values_by_path.get("properties.publicnetworkaccess")
        default_action = values_by_path.get("properties.networkacls.defaultaction")
        if (
            shared_key is not False
            or public_blob_access is not False
            or _normalized(str(public_network or "")) != "disabled"
            or _normalized(str(default_action or "")) != "deny"
        ):
            violations.append(
                PreflightViolation(
                    code="storage-protection-missing",
                    subject=resource_id,
                    detail=(
                        "storage create must explicitly disable shared key "
                        "and public blob/network access and set network "
                        "default action Deny"
                    ),
                )
            )
    if resource_type == _KEY_VAULT_TYPE and change_type == "create":
        values_by_path = {_canonical_property_path(path): value for path, value, _ in candidates}
        public_network = values_by_path.get("properties.publicnetworkaccess")
        default_action = values_by_path.get("properties.networkacls.defaultaction")
        if (
            _normalized(str(public_network or "")) != "disabled"
            or _normalized(str(default_action or "")) != "deny"
        ):
            violations.append(
                PreflightViolation(
                    code="key-vault-protection-missing",
                    subject=resource_id,
                    detail=(
                        "Key Vault create must explicitly disable public "
                        "network access and set network default action Deny"
                    ),
                )
            )
    if resource_type == _STORAGE_CONTAINER_TYPE and change_type == "create":
        values_by_path = {_canonical_property_path(path): value for path, value, _ in candidates}
        public_access = values_by_path.get("properties.publicaccess")
        if _normalized(str(public_access or "")) != "none":
            violations.append(
                PreflightViolation(
                    code="storage-container-public-access",
                    subject=resource_id,
                    detail=("blob container create must explicitly set publicAccess to None"),
                )
            )
    if not candidates:
        if violations:
            return tuple(violations)
        return (
            PreflightViolation(
                code="uninspectable-change",
                subject=resource_id,
                detail=("change lacks FullResourcePayloads or inspectable delta"),
            ),
        )
    for raw_path, after, property_change_type in candidates:
        path = _canonical_property_path(raw_path)
        removed = property_change_type in {"delete", "remove"}
        if (resource_type in {_CONTAINER_APP_TYPE, _CONTAINER_ENVIRONMENT_TYPE}) and (
            (
                "ingress.external" in path
                or "publicnetworkaccess" in path
                or "vnetconfiguration.internal" in path
            )
            and (
                _enabled(after)
                or removed
                or ("vnetconfiguration.internal" in path and after is False)
            )
        ):
            violations.append(
                PreflightViolation(
                    code="public-container-apps-exposure",
                    subject=resource_id,
                    detail=f"unsafe public Container Apps setting at {path}",
                )
            )
        if (
            resource_type == _STORAGE_ACCOUNT_TYPE
            and path == "properties.allowsharedkeyaccess"
            and (_enabled(after) or removed)
        ):
            violations.append(
                PreflightViolation(
                    code="storage-shared-key-enabled",
                    subject=resource_id,
                    detail=f"shared-key access enabled at {path}",
                )
            )
        if (
            resource_type == _STORAGE_ACCOUNT_TYPE
            and path == "properties.allowblobpublicaccess"
            and (_enabled(after) or removed)
        ):
            violations.append(
                PreflightViolation(
                    code="storage-public-blob-access",
                    subject=resource_id,
                    detail=f"public blob access enabled at {path}",
                )
            )
        if (
            resource_type in {_STORAGE_ACCOUNT_TYPE, _KEY_VAULT_TYPE}
            and path
            in {
                "properties.publicnetworkaccess",
                "properties.networkacls.defaultaction",
            }
            and (_enabled(after) or removed)
        ):
            violations.append(
                PreflightViolation(
                    code="public-data-plane-access",
                    subject=resource_id,
                    detail=f"public data-plane access enabled at {path}",
                )
            )
        if (
            resource_type == _STORAGE_CONTAINER_TYPE
            and path == "properties.publicaccess"
            and (_normalized(str(after or "")) in {"blob", "container"} or removed)
        ):
            violations.append(
                PreflightViolation(
                    code="storage-container-public-access",
                    subject=resource_id,
                    detail=f"public container access enabled at {path}",
                )
            )
    return tuple(violations)


def evaluate_what_if(
    document: object,
    *,
    allowed_change_ids: frozenset[str] = frozenset(),
) -> tuple[PreflightViolation, ...]:
    normalized_allowlist = frozenset(_normalized(value) for value in allowed_change_ids)
    violations: list[PreflightViolation] = []
    for raw_change in _what_if_changes(document):
        change = _mapping(raw_change, field_name="change")
        resource_id = _require_string(
            _get_case_insensitive(change, "resourceId"),
            field_name="resourceId",
        )
        change_type = _normalized(
            _require_string(
                _get_case_insensitive(change, "changeType"),
                field_name="changeType",
                maximum_length=64,
            )
        )
        if change_type == "nochange":
            continue
        if change_type == "ignore":
            violations.append(
                PreflightViolation(
                    code="ignored-change",
                    subject=resource_id,
                    detail="ARM what-if did not inspect this resource",
                )
            )
            continue
        if change_type == "delete":
            violations.append(
                PreflightViolation(
                    code="delete",
                    subject=resource_id,
                    detail="resource deletion is never permitted",
                )
            )
            continue
        if change_type == "deploy":
            violations.append(
                PreflightViolation(
                    code="unpredictable-change",
                    subject=resource_id,
                    detail=("ARM what-if could not predict the deployed state"),
                )
            )
            continue
        if change_type not in {"create", "modify"}:
            violations.append(
                PreflightViolation(
                    code="unsupported-change-type",
                    subject=resource_id,
                    detail=f"unsupported change type {change_type}",
                )
            )
            continue
        if _normalized(resource_id) not in normalized_allowlist:
            violations.append(
                PreflightViolation(
                    code="unapproved-change",
                    subject=resource_id,
                    detail=f"{change_type} is absent from the reviewed allowlist",
                )
            )
        violations.extend(_unsafe_property_violations(resource_id, change))
    return tuple(violations)


def _parse_policy(document: object | None) -> RbacPolicy:
    if document is None:
        return RbacPolicy(
            allowed_broad_assignments=frozenset(),
            separation_rules=(),
            expected_principal_ids=frozenset(),
        )
    _validate_json_shape(document)
    root = _mapping(document, field_name="RBAC policy")
    raw_allowances = _get_case_insensitive(
        root,
        "allowedBroadAssignments",
    )
    allowances: set[BroadAssignmentAllowance] = set()
    if raw_allowances is not None:
        for raw_item in _sequence(
            raw_allowances,
            field_name="allowedBroadAssignments",
            maximum_items=MAX_POLICY_ITEMS,
        ):
            item = _mapping(raw_item, field_name="broad assignment allowance")
            role_value = _get_case_insensitive(
                item,
                "roleDefinitionId",
            )
            role_name_value = _get_case_insensitive(
                item,
                "roleDefinitionName",
            )
            if role_value is None and role_name_value is None:
                raise PreflightInputError(
                    "broad assignment allowance requires "
                    "roleDefinitionName or roleDefinitionId"
                )
            if role_value is not None:
                allowance_role_id = _canonical_role_id(
                    _require_string(
                        role_value,
                        field_name="roleDefinitionId",
                    )
                )
                allowance_role = _ROLE_ID_TO_NAME.get(
                    allowance_role_id,
                    allowance_role_id,
                )
            else:
                allowance_role = _canonical_role_key(
                    _require_string(
                        role_name_value,
                        field_name="roleDefinitionName",
                    )
                )
            allowances.add(
                BroadAssignmentAllowance(
                    principal_id=_normalized(
                        _require_string(
                            _get_case_insensitive(item, "principalId"),
                            field_name="principalId",
                        )
                    ),
                    role_name=allowance_role,
                    scope=_canonical_scope(
                        _require_string(
                            _get_case_insensitive(item, "scope"),
                            field_name="scope",
                        )
                    ),
                )
            )
    raw_rules = _get_case_insensitive(root, "separationRules")
    rules: list[SeparationRule] = []
    if raw_rules is not None:
        for raw_item in _sequence(
            raw_rules,
            field_name="separationRules",
            maximum_items=MAX_POLICY_ITEMS,
        ):
            item = _mapping(raw_item, field_name="separation rule")
            role_names = _sequence(
                _get_case_insensitive(item, "forbiddenRoleNames"),
                field_name="forbiddenRoleNames",
                maximum_items=MAX_POLICY_ITEMS,
            )
            scope_prefixes = _sequence(
                _get_case_insensitive(item, "forbiddenScopePrefixes"),
                field_name="forbiddenScopePrefixes",
                maximum_items=MAX_POLICY_ITEMS,
            )
            if not role_names or not scope_prefixes:
                raise PreflightInputError(
                    "separation rule requires forbidden roles and scope prefixes"
                )
            rules.append(
                SeparationRule(
                    principal_id=_normalized(
                        _require_string(
                            _get_case_insensitive(item, "principalId"),
                            field_name="principalId",
                        )
                    ),
                    forbidden_role_names=frozenset(
                        _canonical_role_key(
                            _require_string(
                                role,
                                field_name="forbidden role",
                            )
                        )
                        for role in role_names
                    ),
                    forbidden_scope_prefixes=tuple(
                        sorted(
                            _canonical_scope(
                                _require_string(
                                    prefix,
                                    field_name="forbidden scope prefix",
                                )
                            )
                            for prefix in scope_prefixes
                        )
                    ),
                )
            )
    raw_expected_principals = _get_case_insensitive(
        root,
        "expectedPrincipalIds",
    )
    expected_principal_ids: set[str] = set()
    if raw_expected_principals is not None:
        for raw_principal_id in _sequence(
            raw_expected_principals,
            field_name="expectedPrincipalIds",
            maximum_items=MAX_POLICY_ITEMS,
        ):
            principal_id = _normalized(
                _require_string(
                    raw_principal_id,
                    field_name="expected principalId",
                )
            )
            if principal_id in expected_principal_ids:
                raise PreflightInputError(
                    "expectedPrincipalIds contains a duplicate principalId"
                )
            expected_principal_ids.add(principal_id)
    return RbacPolicy(
        allowed_broad_assignments=frozenset(allowances),
        separation_rules=tuple(rules),
        expected_principal_ids=frozenset(expected_principal_ids),
    )


def _role_assignments(document: object) -> list[object]:
    if isinstance(document, list):
        return _sequence(
            document,
            field_name="role assignments",
            maximum_items=MAX_ASSIGNMENTS,
        )
    root = _mapping(document, field_name="role-assignment document")
    for key, value in root.items():
        if (
            key.casefold() in {"nextlink", "@odata.nextlink", "odata.nextlink"}
            and value is not None
        ):
            raise PreflightInputError(
                "role-assignment evidence must not contain a continuation link"
            )
    return _sequence(
        _get_case_insensitive(root, "value"),
        field_name="value",
        maximum_items=MAX_ASSIGNMENTS,
    )


def evaluate_role_assignments(
    document: object,
    *,
    policy_document: object | None = None,
    require_separation_rules: bool = False,
) -> tuple[PreflightViolation, ...]:
    _validate_json_shape(document)
    policy = _parse_policy(policy_document)
    if require_separation_rules and not policy.separation_rules:
        raise PreflightInputError(
            "RBAC policy requires at least one separation rule"
        )
    if require_separation_rules and not policy.expected_principal_ids:
        raise PreflightInputError(
            "RBAC policy requires expectedPrincipalIds"
        )
    rule_principal_ids = frozenset(
        rule.principal_id for rule in policy.separation_rules
    )
    if (
        require_separation_rules
        and rule_principal_ids != policy.expected_principal_ids
    ):
        raise PreflightInputError(
            "separationRules principals must exactly match expectedPrincipalIds"
        )
    allowance_principal_ids = frozenset(
        allowance.principal_id for allowance in policy.allowed_broad_assignments
    )
    if (
        require_separation_rules
        and not allowance_principal_ids.issubset(policy.expected_principal_ids)
    ):
        raise PreflightInputError(
            "RBAC policy principals must be listed in expectedPrincipalIds"
        )
    raw_assignments = _role_assignments(document)
    if require_separation_rules and not raw_assignments:
        raise PreflightInputError("role-assignment evidence must not be empty")
    violations: list[PreflightViolation] = []
    assignment_principal_ids: set[str] = set()
    for raw_assignment in raw_assignments:
        assignment = _mapping(
            raw_assignment,
            field_name="role assignment",
        )
        principal_id = _normalized(
            _require_string(
                _get_case_insensitive(assignment, "principalId"),
                field_name="principalId",
            )
        )
        assignment_principal_ids.add(principal_id)
        raw_role_name = _get_case_insensitive(
            assignment,
            "roleDefinitionName",
        )
        raw_role_id = _get_case_insensitive(
            assignment,
            "roleDefinitionId",
        )
        role_name = (
            ""
            if raw_role_name is None
            else _canonical_role_key(
                _require_string(
                    raw_role_name,
                    field_name="roleDefinitionName",
                )
            )
        )
        role_id = (
            ""
            if raw_role_id is None
            else _canonical_role_id(
                _require_string(
                    raw_role_id,
                    field_name="roleDefinitionId",
                )
            )
        )
        mapped_role_id = _ROLE_ID_TO_NAME.get(role_id)
        if role_name and mapped_role_id is not None and role_name != mapped_role_id:
            raise PreflightInputError("roleDefinitionName and roleDefinitionId conflict")
        canonical_role = role_name or mapped_role_id or role_id
        if not canonical_role:
            raise PreflightInputError(
                "role assignment requires roleDefinitionName or roleDefinitionId"
            )
        scope = _canonical_scope(
            _require_string(
                _get_case_insensitive(assignment, "scope"),
                field_name="scope",
            )
        )
        broad_scope = (
            scope == "/"
            or _SUBSCRIPTION_SCOPE.fullmatch(scope) is not None
            or _RESOURCE_GROUP_SCOPE.fullmatch(scope) is not None
            or _MANAGEMENT_GROUP_SCOPE.fullmatch(scope) is not None
        )
        allowed = (
            BroadAssignmentAllowance(
                principal_id=principal_id,
                role_name=canonical_role,
                scope=scope,
            )
            in policy.allowed_broad_assignments
        )
        if (
            (canonical_role in _BROAD_ROLES or role_id in _BROAD_ROLE_IDS)
            and broad_scope
            and not allowed
        ):
            violations.append(
                PreflightViolation(
                    code="broad-role-assignment",
                    subject=principal_id,
                    detail=(f"{canonical_role} at broad scope {scope}"),
                )
            )
        for rule in policy.separation_rules:
            if (
                principal_id == rule.principal_id
                and canonical_role in rule.forbidden_role_names
                and any(
                    _scope_contains(scope, prefix) or _scope_contains(prefix, scope)
                    for prefix in rule.forbidden_scope_prefixes
                )
            ):
                violations.append(
                    PreflightViolation(
                        code="identity-separation",
                        subject=principal_id,
                        detail=(f"{canonical_role} is forbidden at scope {scope}"),
                    )
                )
    if (
        require_separation_rules
        and not assignment_principal_ids.issubset(policy.expected_principal_ids)
    ):
        raise PreflightInputError(
            "role assignment principal is not covered by expectedPrincipalIds"
        )
    if (
        require_separation_rules
        and assignment_principal_ids != policy.expected_principal_ids
    ):
        raise PreflightInputError(
            "role-assignment evidence does not cover every expectedPrincipalId"
        )
    return tuple(violations)


def render_preflight_json(
    *,
    kind: PreflightKind,
    violations: tuple[PreflightViolation, ...],
) -> str:
    ordered_violations = sorted(
        violations,
        key=lambda item: (item.code, item.subject.casefold(), item.detail),
    )
    return json.dumps(
        {
            "kind": kind,
            "safe": not ordered_violations,
            "violations": [asdict(item) for item in ordered_violations],
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def render_preflight_text(
    *,
    kind: PreflightKind,
    violations: tuple[PreflightViolation, ...],
) -> str:
    ordered_violations = sorted(
        violations,
        key=lambda item: (item.code, item.subject.casefold(), item.detail),
    )
    lines = [
        f"WC-029 preflight: {'SAFE' if not ordered_violations else 'BLOCKED'}",
        f"Check: {kind}",
        f"Blockers: {len(ordered_violations)}",
    ]
    lines.extend(
        f"- {_escaped_text(item.code)}"
        f" | {_escaped_text(item.subject)}"
        f" | {_escaped_text(item.detail)}"
        for item in ordered_violations
    )
    return "\n".join(lines) + "\n"


def _escaped_text(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def run_preflight_check(
    *,
    kind: PreflightKind,
    input_path: Path,
    output_format: PreflightOutputFormat,
    stdout: TextIO,
    stderr: TextIO,
    allowed_change_ids: frozenset[str] = frozenset(),
    policy_path: Path | None = None,
    require_rbac_policy: bool = False,
) -> int:
    """Run one offline preflight check without adding policy or Azure I/O."""

    try:
        document = load_json_file(input_path)
        if kind == "what-if":
            violations = evaluate_what_if(
                document,
                allowed_change_ids=allowed_change_ids,
            )
        elif kind == "rbac":
            if require_rbac_policy and policy_path is None:
                raise PreflightInputError("reviewed RBAC policy is required")
            policy_document = (
                None
                if policy_path is None
                else load_json_file(policy_path, maximum_bytes=1024 * 1024)
            )
            violations = evaluate_role_assignments(
                document,
                policy_document=policy_document,
                require_separation_rules=require_rbac_policy,
            )
        else:
            raise ValueError(f"unsupported preflight kind: {kind}")
    except PreflightInputError as exc:
        if output_format == "json":
            stderr.write(
                json.dumps(
                    {
                        "error": str(exc),
                        "kind": kind,
                        "safe": False,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
        elif output_format == "text":
            stderr.write(
                f"WC-029 preflight {kind} failed: {_escaped_text(str(exc))}\n"
            )
        else:
            raise ValueError(f"unsupported output format: {output_format}") from None
        return 3

    if output_format == "json":
        stdout.write(render_preflight_json(kind=kind, violations=violations))
    elif output_format == "text":
        stdout.write(render_preflight_text(kind=kind, violations=violations))
    else:
        raise ValueError(f"unsupported output format: {output_format}")
    return 0 if not violations else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate saved WC-029 what-if and RBAC JSON offline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    what_if = subparsers.add_parser("what-if")
    what_if.add_argument("input", type=Path)
    what_if.add_argument(
        "--allow-change",
        action="append",
        default=[],
        metavar="RESOURCE_ID",
    )
    what_if.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
    )
    rbac = subparsers.add_parser("rbac")
    rbac.add_argument("input", type=Path)
    rbac.add_argument("--policy", type=Path)
    rbac.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _parser().parse_args(argv)
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    return run_preflight_check(
        kind=args.command,
        input_path=args.input,
        allowed_change_ids=frozenset(
            args.allow_change if args.command == "what-if" else ()
        ),
        policy_path=args.policy if args.command == "rbac" else None,
        output_format=args.format,
        stdout=output,
        stderr=errors,
    )


if __name__ == "__main__":
    raise SystemExit(main())
