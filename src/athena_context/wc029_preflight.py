from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, TextIO
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit

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
_ROLE_NAME_TO_ID = {role_name: role_id for role_id, role_name in _ROLE_ID_TO_NAME.items()}
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
_ARM_ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
_GRAPH_MEMBERSHIP_METHODS = frozenset(
    {
        "getmembergroups",
        "transitivememberof",
    }
)
_NON_EFFECTIVE_RESOURCE_METADATA_ROOTS = frozenset(
    {
        "apiversion",
        "etag",
        "id",
        "name",
        "resourceid",
        "systemdata",
        "type",
    }
)


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
    effective_principal_id: str
    principal_type: str
    role_name: str
    role_definition_id: str
    scope: str
    condition: str | None
    condition_version: str | None
    role_name_supplied: bool
    effective_principal_id_supplied: bool = field(compare=False)
    principal_type_supplied: bool = field(compare=False)
    assigned_principal_fields_supplied: bool = field(compare=False)


@dataclass(frozen=True, slots=True)
class RbacAssignment:
    principal_id: str
    effective_principal_id: str
    principal_type: str
    role_name: str
    role_definition_id: str
    scope: str
    condition: str | None
    condition_version: str | None
    role_name_supplied: bool
    effective_principal_id_supplied: bool = field(compare=False)
    principal_type_supplied: bool = field(compare=False)
    assigned_principal_fields_supplied: bool = field(compare=False)


@dataclass(frozen=True, slots=True)
class RbacCollection:
    tenant_id: str
    subscription_id: str
    subscription_scope: str
    resource_group_scope: str
    management_group_ancestry: tuple[str, ...]
    effective_principal_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class SeparationRule:
    principal_id: str
    forbidden_role_names: frozenset[str]
    forbidden_role_ids: frozenset[str]
    forbidden_scope_prefixes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RbacPolicy:
    allowed_broad_assignments: frozenset[BroadAssignmentAllowance]
    separation_rules: tuple[SeparationRule, ...]
    expected_principal_ids: frozenset[str]
    approved_assignments: frozenset[RbacAssignment]
    legacy_expected_assignments: frozenset[RbacAssignment]
    target: RbacCollection | None
    approved_assignments_supplied: bool = field(compare=False)
    legacy_expected_assignments_supplied: bool = field(compare=False)


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
        raise PreflightInputError(f"JSON integer exceeds {MAX_JSON_INTEGER_DIGITS} digits")
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
            raise PreflightInputError("JSON object contains a case-insensitive key collision")
        if key.lower() != casefolded:
            raise PreflightInputError("JSON object key has ambiguous Unicode case folding")
        if _contains_non_ascii_case_alias(key):
            raise PreflightInputError("JSON object key contains a non-ASCII case alias")
        result[key] = value
        casefolded_keys.add(casefolded)
    return result


def _canonical_role_key(value: str) -> str:
    normalized = _normalized(value).rsplit("/", 1)[-1]
    return _ROLE_ID_TO_NAME.get(normalized, normalized)


def _contains_non_ascii_case_alias(value: str) -> bool:
    return any(
        not character.isascii() and (character.lower().isascii() or character.casefold().isascii())
        for character in value
    )


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
        or segments[-4] != "providers"
        or segments[-3] != "microsoft.authorization"
        or segments[-2] != "roledefinitions"
        or _GUID.fullmatch(segments[-1]) is None
    ):
        raise PreflightInputError(
            "roleDefinitionId must identify a Microsoft.Authorization role definition"
        )
    return segments[-1]


def _canonical_property_path(value: str) -> str:
    normalized = value.lower()
    if normalized != value.casefold():
        raise PreflightInputError("property path has ambiguous Unicode case folding")
    if _contains_non_ascii_case_alias(value):
        raise PreflightInputError("property path contains a non-ASCII case alias")
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
        not segment or segment in {".", ".."} or segment != segment.strip() for segment in segments
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


def _canonical_guid(value: object, *, field_name: str) -> str:
    guid = _normalized(
        _require_string(
            value,
            field_name=field_name,
            maximum_length=64,
        )
    )
    if _GUID.fullmatch(guid) is None:
        raise PreflightInputError(f"{field_name} must be a GUID")
    return guid


def _canonical_management_group_scope(
    value: object,
    *,
    field_name: str,
) -> str:
    scope = _canonical_scope(
        _require_string(
            value,
            field_name=field_name,
        )
    )
    if _MANAGEMENT_GROUP_SCOPE.fullmatch(scope) is None:
        raise PreflightInputError(f"{field_name} must be a management-group scope")
    return scope


def _require_http_success(value: object, *, field_name: str) -> None:
    if type(value) is not int:
        raise PreflightInputError(f"{field_name} statusCode must be an integer")
    if value != 200:
        raise PreflightInputError(f"{field_name} returned HTTP {value}")


def _resource_group_subscription_id(scope: str) -> str:
    segments = scope.strip("/").split("/")
    if len(segments) != 4 or segments[0] != "subscriptions" or segments[2] != "resourcegroups":
        raise PreflightInputError("resourceGroupId must be a resource-group scope")
    return segments[1]


def _scope_contains(ancestor: str, descendant: str) -> bool:
    return ancestor == "/" or descendant == ancestor or descendant.startswith(ancestor + "/")


def _separation_scope_matches(
    assignment_scope: str,
    forbidden_scope_prefix: str,
) -> bool:
    if _scope_contains(
        assignment_scope,
        forbidden_scope_prefix,
    ) or _scope_contains(
        forbidden_scope_prefix,
        assignment_scope,
    ):
        return True
    return _MANAGEMENT_GROUP_SCOPE.fullmatch(
        assignment_scope
    ) is not None and forbidden_scope_prefix.startswith("/subscriptions/")


def _allowance_matches(
    allowance: BroadAssignmentAllowance,
    assignment: BroadAssignmentAllowance,
) -> bool:
    return (
        allowance.principal_id == assignment.principal_id
        and allowance.effective_principal_id == assignment.effective_principal_id
        and (not allowance.principal_type or allowance.principal_type == assignment.principal_type)
        and allowance.role_name == assignment.role_name
        and allowance.scope == assignment.scope
        and allowance.condition == assignment.condition
        and allowance.condition_version == assignment.condition_version
        and (
            not allowance.role_definition_id
            or allowance.role_definition_id == assignment.role_definition_id
        )
    )


def _has_case_insensitive(mapping: dict[str, Any], name: str) -> bool:
    expected = name.lower()
    return any(key.lower() == expected for key in mapping)


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
                type(key) is not str or len(key) > 4096 or not key.isprintable() for key in item
            ):
                raise PreflightInputError("JSON object keys are invalid")
            lowered_keys = [key.lower() for key in item]
            if any(key.lower() != key.casefold() for key in item):
                raise PreflightInputError("JSON object key has ambiguous Unicode case folding")
            if any(_contains_non_ascii_case_alias(key) for key in item):
                raise PreflightInputError("JSON object key contains a non-ASCII case alias")
            if len(lowered_keys) != len(set(lowered_keys)):
                raise PreflightInputError("JSON object contains a case-insensitive key collision")
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
    expected = name.lower()
    for key, value in mapping.items():
        if key.lower() == expected:
            return value
    return None


def _what_if_changes(
    document: object,
) -> tuple[list[object], list[object]]:
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
    if properties is not None:
        if _has_case_insensitive(root, "changes") or _has_case_insensitive(
            root,
            "potentialChanges",
        ):
            raise PreflightInputError("what-if document contains mixed result envelopes")
        container = _mapping(properties, field_name="properties")
    else:
        container = root
    changes = _get_case_insensitive(container, "changes")
    potential_changes = _get_case_insensitive(
        container,
        "potentialChanges",
    )
    return (
        _sequence(
            changes,
            field_name="changes",
            maximum_items=MAX_CHANGES,
        ),
        (
            []
            if potential_changes is None
            else _sequence(
                potential_changes,
                field_name="potentialChanges",
                maximum_items=MAX_CHANGES,
            )
        ),
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


def _property_child_path(parent: str, key: str) -> str:
    escaped_key = key.replace("~", "~0").replace(".", "~1")
    return f"{parent}.{escaped_key}"


def _json_values_equal(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _derive_snapshot_delta(
    before: object,
    after: object,
    *,
    root: str = "<resource>",
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[object, object, str]] = [(before, after, root)]
    while stack:
        old_value, new_value, path = stack.pop()
        if _json_values_equal(old_value, new_value):
            continue
        if isinstance(old_value, dict) and isinstance(new_value, dict):
            keys = sorted(set(old_value) | set(new_value))
            for key in reversed(keys):
                child_path = _property_child_path(path, key)
                if key not in new_value:
                    values.append((child_path, None, "delete"))
                elif key not in old_value:
                    child = new_value[key]
                    values.append((child_path, child, "create"))
                    if isinstance(child, (dict, list)):
                        values.extend(
                            _flatten_after(
                                child,
                                root=child_path,
                            )
                        )
                else:
                    stack.append(
                        (
                            old_value[key],
                            new_value[key],
                            child_path,
                        )
                    )
            continue
        values.append((path, new_value, "modify"))
        if isinstance(new_value, (dict, list)):
            values.extend(_flatten_after(new_value, root=path))
    return values


def _is_meaningful_delta_candidate(path: str, value: object) -> bool:
    canonical = _canonical_property_path(path)
    root = re.split(r"[.\[]", canonical, maxsplit=1)[0]
    return root not in _NON_EFFECTIVE_RESOURCE_METADATA_ROOTS and not (
        canonical == "<resource>" and isinstance(value, (dict, list))
    )


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
        before_supplied = _has_case_insensitive(item, "before")
        after_supplied = _has_case_insensitive(item, "after")
        before = _get_case_insensitive(item, "before")
        after = _get_case_insensitive(item, "after")
        if (
            property_change_type not in {"delete", "remove", "noeffect"}
            and not after_supplied
            and children is None
        ):
            raise PreflightInputError("delta item lacks inspectable after value or children")
        child_items: list[dict[str, Any]] = []
        if children is not None:
            child_items = [
                _mapping(child, field_name="delta child")
                for child in _sequence(
                    children,
                    field_name="delta children",
                    maximum_items=MAX_CHANGES,
                )
            ]
            if not child_items:
                raise PreflightInputError("delta item contains no inspectable children")
        if property_change_type in {"delete", "remove"}:
            values.append(
                (
                    path,
                    after,
                    property_change_type,
                )
            )
        elif property_change_type != "noeffect" and after_supplied:
            if before_supplied:
                values.extend(
                    _derive_snapshot_delta(
                        before,
                        after,
                        root=path,
                    )
                )
            else:
                values.append(
                    (
                        path,
                        after,
                        property_change_type,
                    )
                )
                if isinstance(after, (dict, list)):
                    values.extend(_flatten_after(after, root=path))
        if child_items:
            stack.extend((child, path) for child in reversed(child_items))
    return values


def _flatten_after(
    value: object,
    *,
    root: str = "<resource>",
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[object, str]] = [(value, root)]
    while stack:
        item, path = stack.pop()
        if isinstance(item, dict):
            stack.extend(
                (
                    child,
                    _property_child_path(path, key),
                )
                for key, child in reversed(list(item.items()))
            )
        elif isinstance(item, list):
            stack.extend(
                (child, f"{path}[{index}]") for index, child in reversed(list(enumerate(item)))
            )
        else:
            values.append((path, item, "set"))
    return values


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
    declared_delta_candidates = _walk_delta(delta) if delta else []
    before_payload_supplied = _has_case_insensitive(change, "before")
    after_payload_supplied = _has_case_insensitive(change, "after")
    before_payload = _get_case_insensitive(change, "before")
    after_payload = _get_case_insensitive(change, "after")
    snapshot_delta_candidates: list[tuple[str, object, str]] = []
    complete_snapshots = (
        change_type == "modify" and before_payload_supplied and after_payload_supplied
    )
    if complete_snapshots:
        if not isinstance(before_payload, dict) or not isinstance(
            after_payload,
            dict,
        ):
            raise PreflightInputError("Modify before and after snapshots must both be objects")
        snapshot_delta_candidates = _derive_snapshot_delta(
            before_payload,
            after_payload,
        )
    effective_delta_candidates = (
        snapshot_delta_candidates if complete_snapshots else declared_delta_candidates
    )
    if change_type == "modify" and not any(
        _is_meaningful_delta_candidate(path, value) for path, value, _ in effective_delta_candidates
    ):
        violations.append(
            PreflightViolation(
                code="uninspectable-change",
                subject=resource_id,
                detail="Modify lacks a meaningful effective property delta",
            )
        )
    delta_candidates = [
        *declared_delta_candidates,
        *snapshot_delta_candidates,
    ]
    candidates = list(delta_candidates)
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
    if resource_type == _CONTAINER_ENVIRONMENT_TYPE and change_type == "create":
        values_by_path = {_canonical_property_path(path): value for path, value, _ in candidates}
        public_network = values_by_path.get("properties.publicnetworkaccess")
        internal = values_by_path.get("properties.vnetconfiguration.internal")
        if (
            not isinstance(public_network, str)
            or _normalized(public_network) != "disabled"
            or internal is not True
        ):
            violations.append(
                PreflightViolation(
                    code="public-container-apps-exposure",
                    subject=resource_id,
                    detail=(
                        "managed environment create must explicitly disable "
                        "public network access and set internal to true"
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

    def delta_touches(target: str) -> bool:
        return any(
            (path := _canonical_property_path(raw_path)) == target or target.startswith(path + ".")
            for raw_path, _, _ in delta_candidates
        )

    def has_exact_evidence(target: str) -> bool:
        return any(_canonical_property_path(raw_path) == target for raw_path, _, _ in candidates)

    def ancestor_removed(target: str) -> bool:
        return any(
            property_change_type in {"delete", "remove"}
            and (path := _canonical_property_path(raw_path)) != target
            and target.startswith(path + ".")
            for raw_path, _, property_change_type in delta_candidates
        )

    if (
        resource_type == _STORAGE_ACCOUNT_TYPE
        and delta_touches("properties.allowsharedkeyaccess")
        and (
            ancestor_removed("properties.allowsharedkeyaccess")
            or not has_exact_evidence("properties.allowsharedkeyaccess")
        )
    ):
        violations.append(
            PreflightViolation(
                code="storage-shared-key-enabled",
                subject=resource_id,
                detail="ancestor change omits explicit shared-key protection",
            )
        )
    if (
        resource_type == _STORAGE_ACCOUNT_TYPE
        and delta_touches("properties.allowblobpublicaccess")
        and (
            ancestor_removed("properties.allowblobpublicaccess")
            or not has_exact_evidence("properties.allowblobpublicaccess")
        )
    ):
        violations.append(
            PreflightViolation(
                code="storage-public-blob-access",
                subject=resource_id,
                detail="ancestor change omits explicit public-blob protection",
            )
        )
    if (
        resource_type == _STORAGE_CONTAINER_TYPE
        and delta_touches("properties.publicaccess")
        and (
            ancestor_removed("properties.publicaccess")
            or not has_exact_evidence("properties.publicaccess")
        )
    ):
        violations.append(
            PreflightViolation(
                code="storage-container-public-access",
                subject=resource_id,
                detail="ancestor change omits explicit private-container protection",
            )
        )
    if resource_type in {_STORAGE_ACCOUNT_TYPE, _KEY_VAULT_TYPE}:
        network_acl_touched = any(
            (
                (path := _canonical_property_path(raw_path)) == "properties.networkacls"
                or path.startswith("properties.networkacls.")
                or "properties.networkacls".startswith(path + ".")
            )
            for raw_path, _, _ in delta_candidates
        )
        if network_acl_touched:
            protected_parent_removed = any(
                (
                    (path := _canonical_property_path(raw_path)) == "properties.networkacls"
                    or "properties.networkacls".startswith(path + ".")
                )
                and property_change_type in {"delete", "remove"}
                for raw_path, _, property_change_type in delta_candidates
            )
            protected_values = {
                "properties.publicnetworkaccess": "disabled",
                "properties.networkacls.defaultaction": "deny",
            }
            explicit_unsafe = False
            complete_safe = True
            for protected_path, expected_value in protected_values.items():
                matching = [
                    (after, property_change_type)
                    for raw_path, after, property_change_type in candidates
                    if _canonical_property_path(raw_path) == protected_path
                ]
                safe_values = [
                    after
                    for after, property_change_type in matching
                    if property_change_type not in {"delete", "remove"}
                    and isinstance(after, str)
                    and _normalized(after) == expected_value
                ]
                unsafe_values = [
                    after
                    for after, property_change_type in matching
                    if property_change_type in {"delete", "remove"}
                    or not isinstance(after, str)
                    or _normalized(after) != expected_value
                ]
                complete_safe = complete_safe and bool(safe_values) and not unsafe_values
                explicit_unsafe = explicit_unsafe or bool(unsafe_values)
            if protected_parent_removed or (not explicit_unsafe and not complete_safe):
                violations.append(
                    PreflightViolation(
                        code="public-data-plane-access",
                        subject=resource_id,
                        detail=(
                            "network ACL protection was removed or lacks explicit "
                            "publicNetworkAccess Disabled and defaultAction Deny"
                        ),
                    )
                )
    container_network_targets: tuple[str, ...] = ()
    if resource_type == _CONTAINER_APP_TYPE:
        container_network_targets = (
            "properties.configuration.ingress.external",
            "properties.publicnetworkaccess",
        )
    elif resource_type == _CONTAINER_ENVIRONMENT_TYPE:
        container_network_targets = (
            "properties.publicnetworkaccess",
            "properties.vnetconfiguration.internal",
        )
    for target in container_network_targets:
        related_delta = [
            (raw_path, property_change_type)
            for raw_path, _, property_change_type in delta_candidates
            if (
                (path := _canonical_property_path(raw_path)) == target
                or target.startswith(path + ".")
            )
        ]
        exact_values = [
            (after, property_change_type)
            for raw_path, after, property_change_type in candidates
            if _canonical_property_path(raw_path) == target
        ]
        parent_removed = any(
            _canonical_property_path(raw_path) != target
            and property_change_type in {"delete", "remove"}
            for raw_path, property_change_type in related_delta
        )
        if parent_removed or (related_delta and not exact_values):
            violations.append(
                PreflightViolation(
                    code="public-container-apps-exposure",
                    subject=resource_id,
                    detail=f"network change lacks explicit safe value at {target}",
                )
            )
    for raw_path, after, property_change_type in candidates:
        path = _canonical_property_path(raw_path)
        removed = property_change_type in {"delete", "remove"}
        if path in container_network_targets:
            unsafe_container_network = removed
            if not removed and path == "properties.configuration.ingress.external":
                if type(after) is not bool:
                    raise PreflightInputError("Container Apps ingress.external must be boolean")
                unsafe_container_network = after
            elif not removed and path == "properties.vnetconfiguration.internal":
                if type(after) is not bool:
                    raise PreflightInputError(
                        "Container Apps vnetConfiguration.internal must be boolean"
                    )
                unsafe_container_network = not after
            elif not removed and path == "properties.publicnetworkaccess":
                public_network_access = _normalized(
                    _require_string(
                        after,
                        field_name="publicNetworkAccess",
                        maximum_length=64,
                    )
                )
                if public_network_access not in {"disabled", "enabled"}:
                    raise PreflightInputError("Container Apps publicNetworkAccess is unsupported")
                unsafe_container_network = public_network_access != "disabled"
            if unsafe_container_network:
                violations.append(
                    PreflightViolation(
                        code="public-container-apps-exposure",
                        subject=resource_id,
                        detail=f"unsafe public Container Apps setting at {path}",
                    )
                )
        if resource_type == _STORAGE_ACCOUNT_TYPE and path == "properties.allowsharedkeyaccess":
            if not removed and type(after) is not bool:
                raise PreflightInputError("allowSharedKeyAccess must be boolean")
            if removed or after is True:
                violations.append(
                    PreflightViolation(
                        code="storage-shared-key-enabled",
                        subject=resource_id,
                        detail=f"shared-key access enabled at {path}",
                    )
                )
        if resource_type == _STORAGE_ACCOUNT_TYPE and path == "properties.allowblobpublicaccess":
            if not removed and type(after) is not bool:
                raise PreflightInputError("allowBlobPublicAccess must be boolean")
            if removed or after is True:
                violations.append(
                    PreflightViolation(
                        code="storage-public-blob-access",
                        subject=resource_id,
                        detail=f"public blob access enabled at {path}",
                    )
                )
        if resource_type in {_STORAGE_ACCOUNT_TYPE, _KEY_VAULT_TYPE} and path in {
            "properties.publicnetworkaccess",
            "properties.networkacls.defaultaction",
        }:
            if removed:
                unsafe_network_value = True
            else:
                value = _normalized(
                    _require_string(
                        after,
                        field_name=path,
                        maximum_length=64,
                    )
                )
                allowed_values = (
                    {"disabled", "enabled", "securedbyperimeter"}
                    if path == "properties.publicnetworkaccess"
                    else {"allow", "deny"}
                )
                if value not in allowed_values:
                    raise PreflightInputError(f"{path} has an unsupported value")
                unsafe_network_value = value != (
                    "disabled" if path == "properties.publicnetworkaccess" else "deny"
                )
            if unsafe_network_value:
                violations.append(
                    PreflightViolation(
                        code="public-data-plane-access",
                        subject=resource_id,
                        detail=f"unsafe public data-plane setting at {path}",
                    )
                )
        if resource_type == _STORAGE_CONTAINER_TYPE and path == "properties.publicaccess":
            if removed:
                public_access = ""
            else:
                public_access = _normalized(
                    _require_string(
                        after,
                        field_name="publicAccess",
                        maximum_length=64,
                    )
                )
                if public_access not in {"none", "blob", "container"}:
                    raise PreflightInputError("publicAccess has an unsupported value")
            if removed or public_access != "none":
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
    changes, potential_changes = _what_if_changes(document)
    for raw_change in potential_changes:
        potential_change = _mapping(
            raw_change,
            field_name="potential change",
        )
        resource_id = _require_string(
            _get_case_insensitive(potential_change, "resourceId"),
            field_name="potential change resourceId",
        )
        violations.append(
            PreflightViolation(
                code="unpredictable-change",
                subject=resource_id,
                detail="ARM what-if reported an unresolved potential change",
            )
        )
    for raw_change in changes:
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


def _parse_rbac_assignment(
    value: object,
    *,
    field_name: str,
) -> RbacAssignment:
    assignment = _mapping(value, field_name=field_name)
    has_assigned_principal_id = _has_case_insensitive(
        assignment,
        "assignedPrincipalId",
    )
    has_assigned_principal_type = _has_case_insensitive(
        assignment,
        "assignedPrincipalType",
    )
    has_legacy_principal_id = _has_case_insensitive(
        assignment,
        "principalId",
    )
    has_legacy_principal_type = _has_case_insensitive(
        assignment,
        "principalType",
    )
    if has_assigned_principal_id or has_assigned_principal_type:
        if (
            not has_assigned_principal_id
            or not has_assigned_principal_type
            or has_legacy_principal_id
            or has_legacy_principal_type
        ):
            raise PreflightInputError(
                f"{field_name} must use one complete assigned-principal field set"
            )
        raw_principal_id = _get_case_insensitive(
            assignment,
            "assignedPrincipalId",
        )
        raw_principal_type = _get_case_insensitive(
            assignment,
            "assignedPrincipalType",
        )
        assigned_principal_fields_supplied = True
    else:
        raw_principal_id = _get_case_insensitive(
            assignment,
            "principalId",
        )
        raw_principal_type = _get_case_insensitive(
            assignment,
            "principalType",
        )
        assigned_principal_fields_supplied = False
    principal_id = _normalized(
        _require_string(
            raw_principal_id,
            field_name=(
                "assignedPrincipalId" if assigned_principal_fields_supplied else "principalId"
            ),
        )
    )
    raw_effective_principal_id = _get_case_insensitive(
        assignment,
        "effectivePrincipalId",
    )
    effective_principal_id = (
        principal_id
        if raw_effective_principal_id is None
        else _normalized(
            _require_string(
                raw_effective_principal_id,
                field_name="effectivePrincipalId",
            )
        )
    )
    if raw_principal_type is None:
        principal_type = ""
    else:
        principal_type_value = _require_string(
            raw_principal_type,
            field_name=(
                "assignedPrincipalType" if assigned_principal_fields_supplied else "principalType"
            ),
            maximum_length=64,
        )
        if not principal_type_value.isascii():
            raise PreflightInputError("principalType must use ASCII")
        principal_type = _normalized(principal_type_value)
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
    expected_role_id = _ROLE_NAME_TO_ID.get(role_name)
    if (
        role_name
        and role_id
        and (
            (mapped_role_id is not None and role_name != mapped_role_id)
            or (expected_role_id is not None and role_id != expected_role_id)
        )
    ):
        raise PreflightInputError("roleDefinitionName and roleDefinitionId conflict")
    canonical_role = role_name or mapped_role_id or role_id
    if not canonical_role:
        raise PreflightInputError("role assignment requires roleDefinitionName or roleDefinitionId")
    raw_condition = _get_case_insensitive(assignment, "condition")
    condition = (
        None
        if raw_condition is None
        else _require_string(
            raw_condition,
            field_name="condition",
        )
    )
    raw_condition_version = _get_case_insensitive(
        assignment,
        "conditionVersion",
    )
    condition_version = (
        None
        if raw_condition_version is None
        else _require_string(
            raw_condition_version,
            field_name="conditionVersion",
            maximum_length=64,
        )
    )
    if (condition is None) != (condition_version is None):
        raise PreflightInputError("condition and conditionVersion must be supplied together")
    return RbacAssignment(
        principal_id=principal_id,
        effective_principal_id=effective_principal_id,
        principal_type=principal_type,
        role_name=canonical_role,
        role_definition_id=role_id,
        scope=_canonical_scope(
            _require_string(
                _get_case_insensitive(assignment, "scope"),
                field_name="scope",
            )
        ),
        condition=condition,
        condition_version=condition_version,
        role_name_supplied=raw_role_name is not None,
        effective_principal_id_supplied=raw_effective_principal_id is not None,
        principal_type_supplied=raw_principal_type is not None,
        assigned_principal_fields_supplied=(assigned_principal_fields_supplied),
    )


def _parse_management_group_chain(
    value: object,
    *,
    field_name: str,
) -> tuple[str, ...]:
    chain: list[str] = []
    seen: set[str] = set()
    for item in _sequence(
        value,
        field_name=field_name,
        maximum_items=MAX_POLICY_ITEMS,
    ):
        scope = _canonical_management_group_scope(
            item,
            field_name="management-group ancestor",
        )
        if scope in seen:
            raise PreflightInputError(f"{field_name} contains a duplicate or cyclic ancestor")
        seen.add(scope)
        chain.append(scope)
    if not chain:
        raise PreflightInputError(f"{field_name} must not be empty")
    return tuple(chain)


def _parse_policy_target(
    value: object,
    *,
    expected_principal_ids: frozenset[str],
) -> RbacCollection:
    target = _mapping(value, field_name="RBAC policy target")
    tenant_id = _canonical_guid(
        _get_case_insensitive(target, "tenantId"),
        field_name="target tenantId",
    )
    subscription_id = _canonical_guid(
        _get_case_insensitive(target, "subscriptionId"),
        field_name="target subscriptionId",
    )
    subscription_scope = f"/subscriptions/{subscription_id}"
    resource_group_scope = _canonical_scope(
        _require_string(
            _get_case_insensitive(target, "resourceGroupId"),
            field_name="target resourceGroupId",
        )
    )
    if (
        _RESOURCE_GROUP_SCOPE.fullmatch(resource_group_scope) is None
        or _resource_group_subscription_id(resource_group_scope) != subscription_id
    ):
        raise PreflightInputError("target resourceGroupId must belong to target subscriptionId")
    ancestry = _parse_management_group_chain(
        _get_case_insensitive(
            target,
            "approvedManagementGroupAncestry",
        ),
        field_name="approvedManagementGroupAncestry",
    )
    return RbacCollection(
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        subscription_scope=subscription_scope,
        resource_group_scope=resource_group_scope,
        management_group_ancestry=ancestry,
        effective_principal_ids=expected_principal_ids,
    )


def _assignment_key(
    assignment: RbacAssignment | BroadAssignmentAllowance,
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    str | None,
    str | None,
]:
    return (
        assignment.principal_id,
        assignment.principal_type,
        assignment.effective_principal_id,
        assignment.role_definition_id,
        assignment.scope,
        assignment.condition,
        assignment.condition_version,
    )


def _parse_policy(document: object | None) -> RbacPolicy:
    if document is None:
        return RbacPolicy(
            allowed_broad_assignments=frozenset(),
            separation_rules=(),
            expected_principal_ids=frozenset(),
            approved_assignments=frozenset(),
            legacy_expected_assignments=frozenset(),
            target=None,
            approved_assignments_supplied=False,
            legacy_expected_assignments_supplied=False,
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
            parsed_allowance = _parse_rbac_assignment(
                raw_item,
                field_name="broad assignment allowance",
            )
            allowance = BroadAssignmentAllowance(
                principal_id=parsed_allowance.principal_id,
                effective_principal_id=(parsed_allowance.effective_principal_id),
                principal_type=parsed_allowance.principal_type,
                role_name=parsed_allowance.role_name,
                role_definition_id=parsed_allowance.role_definition_id,
                scope=parsed_allowance.scope,
                condition=parsed_allowance.condition,
                condition_version=parsed_allowance.condition_version,
                role_name_supplied=parsed_allowance.role_name_supplied,
                effective_principal_id_supplied=(parsed_allowance.effective_principal_id_supplied),
                principal_type_supplied=(parsed_allowance.principal_type_supplied),
                assigned_principal_fields_supplied=(
                    parsed_allowance.assigned_principal_fields_supplied
                ),
            )
            if allowance in allowances:
                raise PreflightInputError("allowedBroadAssignments contains a duplicate assignment")
            allowances.add(allowance)
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
            raw_role_ids = _get_case_insensitive(
                item,
                "forbiddenRoleDefinitionIds",
            )
            role_ids = (
                []
                if raw_role_ids is None
                else _sequence(
                    raw_role_ids,
                    field_name="forbiddenRoleDefinitionIds",
                    maximum_items=MAX_POLICY_ITEMS,
                )
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
                    forbidden_role_ids=frozenset(
                        _canonical_role_id(
                            _require_string(
                                role_id,
                                field_name="forbidden roleDefinitionId",
                            )
                        )
                        for role_id in role_ids
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
                raise PreflightInputError("expectedPrincipalIds contains a duplicate principalId")
            expected_principal_ids.add(principal_id)
    raw_approved_assignments = _get_case_insensitive(
        root,
        "approvedAssignments",
    )
    approved_assignments: set[RbacAssignment] = set()
    approved_assignment_keys: set[
        tuple[
            str,
            str,
            str,
            str,
            str,
            str | None,
            str | None,
        ]
    ] = set()
    if raw_approved_assignments is not None:
        for raw_assignment in _sequence(
            raw_approved_assignments,
            field_name="approvedAssignments",
            maximum_items=MAX_ASSIGNMENTS,
        ):
            approved_assignment = _parse_rbac_assignment(
                raw_assignment,
                field_name="approved assignment",
            )
            key = _assignment_key(approved_assignment)
            if key in approved_assignment_keys:
                raise PreflightInputError("approvedAssignments contains a duplicate assignment")
            approved_assignment_keys.add(key)
            approved_assignments.add(approved_assignment)
    raw_expected_assignments = _get_case_insensitive(
        root,
        "expectedAssignments",
    )
    expected_assignments: set[RbacAssignment] = set()
    if raw_expected_assignments is not None:
        for raw_assignment in _sequence(
            raw_expected_assignments,
            field_name="expectedAssignments",
            maximum_items=MAX_ASSIGNMENTS,
        ):
            expected_assignment = _parse_rbac_assignment(
                raw_assignment,
                field_name="expected assignment",
            )
            if expected_assignment in expected_assignments:
                raise PreflightInputError("expectedAssignments contains a duplicate assignment")
            expected_assignments.add(expected_assignment)
    return RbacPolicy(
        allowed_broad_assignments=frozenset(allowances),
        separation_rules=tuple(rules),
        expected_principal_ids=frozenset(expected_principal_ids),
        approved_assignments=frozenset(approved_assignments),
        legacy_expected_assignments=frozenset(expected_assignments),
        target=(
            None
            if _get_case_insensitive(root, "target") is None
            else _parse_policy_target(
                _get_case_insensitive(root, "target"),
                expected_principal_ids=frozenset(expected_principal_ids),
            )
        ),
        approved_assignments_supplied=raw_approved_assignments is not None,
        legacy_expected_assignments_supplied=(raw_expected_assignments is not None),
    )


def _validate_guarded_assignment_binding(
    assignment: RbacAssignment | BroadAssignmentAllowance,
    *,
    field_name: str,
) -> None:
    if not assignment.assigned_principal_fields_supplied:
        raise PreflightInputError(
            f"{field_name} requires assignedPrincipalId and assignedPrincipalType"
        )
    if not assignment.effective_principal_id_supplied:
        raise PreflightInputError(f"{field_name} requires effectivePrincipalId")
    if not assignment.principal_type_supplied:
        raise PreflightInputError(f"{field_name} requires assignedPrincipalType")
    if assignment.principal_type not in {"group", "serviceprincipal"}:
        raise PreflightInputError(
            f"{field_name} assignedPrincipalType must be Group or ServicePrincipal"
        )
    _canonical_guid(
        assignment.principal_id,
        field_name=f"{field_name} assignedPrincipalId",
    )
    _canonical_guid(
        assignment.effective_principal_id,
        field_name=f"{field_name} effectivePrincipalId",
    )
    if (
        assignment.principal_type == "group"
        and assignment.principal_id == assignment.effective_principal_id
    ):
        raise PreflightInputError(
            f"{field_name} group assignment requires a distinct effectivePrincipalId"
        )
    if (
        assignment.principal_type == "serviceprincipal"
        and assignment.principal_id != assignment.effective_principal_id
    ):
        raise PreflightInputError(
            f"{field_name} ServicePrincipal assignment must target the same effectivePrincipalId"
        )


def _split_url(value: str, *, field_name: str) -> SplitResult:
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise PreflightInputError(f"{field_name} is not a valid URL") from exc


def _paged_values(
    value: object,
    *,
    field_name: str,
    next_link_field: str,
    maximum_items: int,
    allowed_host: str,
) -> tuple[list[object], tuple[str, ...]]:
    pages = _sequence(
        value,
        field_name=f"{field_name} pages",
        maximum_items=MAX_POLICY_ITEMS,
    )
    if not pages:
        raise PreflightInputError(f"{field_name} pages must not be empty")
    values: list[object] = []
    expected_request_url: str | None = None
    request_urls: list[str] = []
    seen_request_urls: set[str] = set()
    for index, raw_page in enumerate(pages):
        page = _mapping(raw_page, field_name=f"{field_name} page")
        request_url = _require_string(
            _get_case_insensitive(page, "requestUrl"),
            field_name=f"{field_name} requestUrl",
        )
        parts = _split_url(
            request_url,
            field_name=f"{field_name} requestUrl",
        )
        if parts.scheme.casefold() != "https" or parts.netloc.casefold() != allowed_host:
            raise PreflightInputError(f"{field_name} requestUrl must use https://{allowed_host}")
        if request_url in seen_request_urls:
            raise PreflightInputError(f"{field_name} pagination contains a repeated requestUrl")
        seen_request_urls.add(request_url)
        if index > 0 and expected_request_url != request_url:
            raise PreflightInputError(f"{field_name} pagination has a nextLink gap")
        request_urls.append(request_url)
        _require_http_success(
            _get_case_insensitive(page, "statusCode"),
            field_name=f"{field_name} page",
        )
        page_values = _sequence(
            _get_case_insensitive(page, "value"),
            field_name=f"{field_name} page value",
            maximum_items=maximum_items,
        )
        if len(values) + len(page_values) > maximum_items:
            raise PreflightInputError(f"{field_name} must contain at most {maximum_items} items")
        values.extend(page_values)
        raw_next_link = _get_case_insensitive(page, next_link_field)
        expected_request_url = (
            None
            if raw_next_link is None
            else _require_string(
                raw_next_link,
                field_name=f"{field_name} nextLink",
            )
        )
        if index < len(pages) - 1 and expected_request_url is None:
            raise PreflightInputError(f"{field_name} pagination ended before the supplied pages")
    if expected_request_url is not None:
        raise PreflightInputError(f"{field_name} pagination is incomplete")
    return values, tuple(request_urls)


def _parse_evidence_target(value: object) -> RbacCollection:
    target = _mapping(value, field_name="RBAC evidence target")
    tenant_id = _canonical_guid(
        _get_case_insensitive(target, "tenantId"),
        field_name="evidence target tenantId",
    )
    subscription_id = _canonical_guid(
        _get_case_insensitive(target, "subscriptionId"),
        field_name="evidence target subscriptionId",
    )
    subscription_scope = f"/subscriptions/{subscription_id}"
    resource_group_scope = _canonical_scope(
        _require_string(
            _get_case_insensitive(target, "resourceGroupId"),
            field_name="evidence target resourceGroupId",
        )
    )
    if (
        _RESOURCE_GROUP_SCOPE.fullmatch(resource_group_scope) is None
        or _resource_group_subscription_id(resource_group_scope) != subscription_id
    ):
        raise PreflightInputError("evidence target resourceGroupId must belong to subscriptionId")
    return RbacCollection(
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        subscription_scope=subscription_scope,
        resource_group_scope=resource_group_scope,
        management_group_ancestry=(),
        effective_principal_ids=frozenset(),
    )


def _validate_arm_get_url(
    value: object,
    *,
    expected_path: str,
    expected_query: dict[str, str],
    field_name: str,
) -> None:
    request_url = _require_string(
        value,
        field_name=field_name,
    )
    parts = _split_url(request_url, field_name=field_name)
    if (
        parts.scheme.casefold() != "https"
        or parts.netloc.casefold() != "management.azure.com"
        or unquote(parts.path).casefold() != expected_path.casefold()
        or parts.fragment
    ):
        raise PreflightInputError(f"{field_name} is not canonical")
    query = {
        key.casefold(): values
        for key, values in parse_qs(
            parts.query,
            keep_blank_values=True,
        ).items()
    }
    normalized_expected = {
        key.casefold(): [expected_value] for key, expected_value in expected_query.items()
    }
    if query != normalized_expected:
        raise PreflightInputError(f"{field_name} is not canonical")


def _derive_management_group_ancestry(
    value: object,
    *,
    target: RbacCollection,
) -> tuple[str, ...]:
    hierarchy = _mapping(value, field_name="management-group hierarchy")
    resource_graph = _mapping(
        _get_case_insensitive(hierarchy, "resourceGraph"),
        field_name="Resource Graph hierarchy evidence",
    )
    request = _mapping(
        _get_case_insensitive(resource_graph, "request"),
        field_name="Resource Graph hierarchy request",
    )
    if (
        _canonical_guid(
            _get_case_insensitive(request, "tenantId"),
            field_name="Resource Graph request tenantId",
        )
        != target.tenant_id
    ):
        raise PreflightInputError("Resource Graph hierarchy request crosses tenants")
    if (
        _canonical_guid(
            _get_case_insensitive(request, "subscriptionId"),
            field_name="Resource Graph request subscriptionId",
        )
        != target.subscription_id
    ):
        raise PreflightInputError("Resource Graph hierarchy request targets another subscription")
    query_text = _require_string(
        _get_case_insensitive(request, "query"),
        field_name="Resource Graph hierarchy query",
    )
    if "managementgroupancestorschain" not in query_text.casefold():
        raise PreflightInputError(
            "Resource Graph hierarchy query omits managementGroupAncestorsChain"
        )
    _require_http_success(
        _get_case_insensitive(resource_graph, "statusCode"),
        field_name="Resource Graph hierarchy evidence",
    )
    body = _mapping(
        _get_case_insensitive(resource_graph, "body"),
        field_name="Resource Graph hierarchy body",
    )
    if _get_case_insensitive(body, "skipToken") is not None:
        raise PreflightInputError("Resource Graph hierarchy evidence is paginated or incomplete")
    rows = _sequence(
        _get_case_insensitive(body, "data"),
        field_name="Resource Graph hierarchy data",
        maximum_items=2,
    )
    if len(rows) != 1:
        raise PreflightInputError("Resource Graph hierarchy evidence must contain one subscription")
    row = _mapping(
        rows[0],
        field_name="Resource Graph subscription row",
    )
    if (
        _canonical_guid(
            _get_case_insensitive(row, "tenantId"),
            field_name="Resource Graph tenantId",
        )
        != target.tenant_id
    ):
        raise PreflightInputError("Resource Graph hierarchy evidence crosses tenants")
    if (
        _canonical_guid(
            _get_case_insensitive(row, "subscriptionId"),
            field_name="Resource Graph subscriptionId",
        )
        != target.subscription_id
    ):
        raise PreflightInputError("Resource Graph hierarchy evidence targets another subscription")
    properties = _mapping(
        _get_case_insensitive(row, "properties"),
        field_name="Resource Graph subscription properties",
    )
    resource_graph_chain: list[str] = []
    resource_graph_seen: set[str] = set()
    for raw_ancestor in _sequence(
        _get_case_insensitive(
            properties,
            "managementGroupAncestorsChain",
        ),
        field_name="managementGroupAncestorsChain",
        maximum_items=MAX_POLICY_ITEMS,
    ):
        ancestor = _mapping(
            raw_ancestor,
            field_name="Resource Graph management-group ancestor",
        )
        name = _require_string(
            _get_case_insensitive(ancestor, "name"),
            field_name="Resource Graph management-group name",
            maximum_length=256,
        )
        scope = _canonical_management_group_scope(
            (f"/providers/Microsoft.Management/managementGroups/{name}"),
            field_name="Resource Graph management-group ancestor",
        )
        if scope in resource_graph_seen:
            raise PreflightInputError("Resource Graph management-group ancestry is cyclic")
        resource_graph_seen.add(scope)
        resource_graph_chain.append(scope)
    if not resource_graph_chain:
        raise PreflightInputError("Resource Graph managementGroupAncestorsChain is missing")

    arm = _mapping(
        _get_case_insensitive(hierarchy, "arm"),
        field_name="ARM hierarchy evidence",
    )
    subscription_artifact = _mapping(
        _get_case_insensitive(arm, "subscription"),
        field_name="ARM subscription hierarchy evidence",
    )
    _require_http_success(
        _get_case_insensitive(subscription_artifact, "statusCode"),
        field_name="ARM subscription hierarchy evidence",
    )
    subscription_body = _mapping(
        _get_case_insensitive(subscription_artifact, "body"),
        field_name="ARM subscription hierarchy body",
    )
    subscription_properties = _mapping(
        _get_case_insensitive(subscription_body, "properties"),
        field_name="ARM subscription hierarchy properties",
    )
    if (
        _canonical_guid(
            _get_case_insensitive(subscription_properties, "tenantId"),
            field_name="ARM subscription tenantId",
        )
        != target.tenant_id
    ):
        raise PreflightInputError("ARM subscription hierarchy evidence crosses tenants")
    parent = _mapping(
        _get_case_insensitive(subscription_properties, "parent"),
        field_name="ARM subscription hierarchy parent",
    )
    leaf_management_group = _canonical_management_group_scope(
        _get_case_insensitive(parent, "id"),
        field_name="ARM subscription parent id",
    )
    expected_subscription_id = f"{leaf_management_group}/subscriptions/{target.subscription_id}"
    if (
        _canonical_scope(
            _require_string(
                _get_case_insensitive(subscription_body, "id"),
                field_name="ARM subscription association id",
            )
        )
        != expected_subscription_id
        or _normalized(
            _require_string(
                _get_case_insensitive(subscription_body, "type"),
                field_name="ARM subscription association type",
                maximum_length=128,
            )
        )
        != "microsoft.management/managementgroups/subscriptions"
        or _canonical_guid(
            _get_case_insensitive(subscription_body, "name"),
            field_name="ARM subscription association name",
        )
        != target.subscription_id
    ):
        raise PreflightInputError("ARM subscription hierarchy body is inconsistent")
    _validate_arm_get_url(
        _get_case_insensitive(subscription_artifact, "requestUrl"),
        expected_path=expected_subscription_id,
        expected_query={"api-version": "2020-05-01"},
        field_name="ARM subscription hierarchy requestUrl",
    )

    resource_group_artifact = _mapping(
        _get_case_insensitive(arm, "resourceGroup"),
        field_name="ARM resource-group hierarchy evidence",
    )
    _require_http_success(
        _get_case_insensitive(resource_group_artifact, "statusCode"),
        field_name="ARM resource-group hierarchy evidence",
    )
    resource_group_body = _mapping(
        _get_case_insensitive(resource_group_artifact, "body"),
        field_name="ARM resource-group hierarchy body",
    )
    if (
        _canonical_scope(
            _require_string(
                _get_case_insensitive(resource_group_body, "id"),
                field_name="ARM resource-group id",
            )
        )
        != target.resource_group_scope
        or _normalized(
            _require_string(
                _get_case_insensitive(resource_group_body, "type"),
                field_name="ARM resource-group type",
                maximum_length=128,
            )
        )
        != "microsoft.resources/resourcegroups"
    ):
        raise PreflightInputError("ARM resource-group hierarchy body is inconsistent")
    _validate_arm_get_url(
        _get_case_insensitive(resource_group_artifact, "requestUrl"),
        expected_path=target.resource_group_scope,
        expected_query={"api-version": "2021-04-01"},
        field_name="ARM resource-group hierarchy requestUrl",
    )

    parent_by_management_group: dict[str, str | None] = {}
    for raw_artifact in _sequence(
        _get_case_insensitive(arm, "managementGroups"),
        field_name="ARM managementGroups",
        maximum_items=MAX_POLICY_ITEMS,
    ):
        artifact = _mapping(
            raw_artifact,
            field_name="ARM management-group hierarchy evidence",
        )
        _require_http_success(
            _get_case_insensitive(artifact, "statusCode"),
            field_name="ARM management-group hierarchy evidence",
        )
        management_group = _mapping(
            _get_case_insensitive(artifact, "body"),
            field_name="ARM management-group hierarchy body",
        )
        management_group_id = _canonical_management_group_scope(
            _get_case_insensitive(management_group, "id"),
            field_name="ARM management-group id",
        )
        if (
            _normalized(
                _require_string(
                    _get_case_insensitive(management_group, "type"),
                    field_name="ARM management-group type",
                    maximum_length=128,
                )
            )
            != "microsoft.management/managementgroups"
        ):
            raise PreflightInputError("ARM management-group hierarchy body has the wrong type")
        properties = _mapping(
            _get_case_insensitive(management_group, "properties"),
            field_name="ARM management-group properties",
        )
        if (
            _canonical_guid(
                _get_case_insensitive(properties, "tenantId"),
                field_name="ARM management-group tenantId",
            )
            != target.tenant_id
        ):
            raise PreflightInputError("ARM management-group hierarchy evidence crosses tenants")
        details = _mapping(
            _get_case_insensitive(properties, "details"),
            field_name="ARM management-group details",
        )
        if not _has_case_insensitive(details, "parent"):
            raise PreflightInputError("ARM management-group hierarchy omits details.parent")
        raw_parent = _get_case_insensitive(details, "parent")
        parent_id = (
            None
            if raw_parent is None
            else _canonical_management_group_scope(
                _get_case_insensitive(
                    _mapping(
                        raw_parent,
                        field_name="ARM management-group parent",
                    ),
                    "id",
                ),
                field_name="ARM management-group parent id",
            )
        )
        if management_group_id in parent_by_management_group:
            raise PreflightInputError("ARM management-group hierarchy contains a duplicate node")
        parent_by_management_group[management_group_id] = parent_id
        _validate_arm_get_url(
            _get_case_insensitive(artifact, "requestUrl"),
            expected_path=management_group_id,
            expected_query={
                "api-version": "2020-05-01",
                "$expand": "path",
            },
            field_name="ARM management-group hierarchy requestUrl",
        )
    if not parent_by_management_group:
        raise PreflightInputError("ARM management-group hierarchy evidence is missing")

    arm_chain: list[str] = []
    seen: set[str] = set()
    current: str | None = leaf_management_group
    while current is not None:
        if current in seen:
            raise PreflightInputError("ARM management-group hierarchy is cyclic")
        seen.add(current)
        if current not in parent_by_management_group:
            raise PreflightInputError("ARM management-group hierarchy omits an ancestor")
        arm_chain.append(current)
        current = parent_by_management_group[current]
    if seen != set(parent_by_management_group):
        raise PreflightInputError("ARM management-group hierarchy contains disconnected nodes")
    if tuple(resource_graph_chain) != tuple(arm_chain):
        raise PreflightInputError("Resource Graph and ARM management-group hierarchies disagree")
    return tuple(arm_chain)


def _validate_graph_urls(
    request_urls: tuple[str, ...],
    *,
    effective_principal_id: str,
    method: str,
) -> None:
    expected_path = f"/v1.0/serviceprincipals/{effective_principal_id}/{method}"
    for index, request_url in enumerate(request_urls):
        parts = _split_url(
            request_url,
            field_name="Graph membership requestUrl",
        )
        path = unquote(parts.path).casefold()
        if path != expected_path:
            raise PreflightInputError(
                "Graph membership requestUrl does not match the effective "
                "service-principal object ID"
            )
        query = {
            key.casefold(): values
            for key, values in parse_qs(
                parts.query,
                keep_blank_values=True,
            ).items()
        }
        if parts.fragment or (index == 0 and query):
            raise PreflightInputError("initial Graph membership requestUrl must be unfiltered")
        if index > 0 and (
            not query
            or not set(query).issubset({"$skiptoken", "$skip"})
            or any(len(values) != 1 for values in query.values())
        ):
            raise PreflightInputError("Graph membership continuation URL is not canonical")


def _parse_security_group_membership(
    value: object,
    *,
    effective_principal_id: str,
    target: RbacCollection,
) -> frozenset[str]:
    membership = _mapping(value, field_name="Graph group-membership evidence")
    if (
        _canonical_guid(
            _get_case_insensitive(membership, "tenantId"),
            field_name="Graph group-membership tenantId",
        )
        != target.tenant_id
    ):
        raise PreflightInputError("Graph group-membership evidence crosses tenants")
    raw_method = _require_string(
        _get_case_insensitive(membership, "method"),
        field_name="Graph membership method",
        maximum_length=64,
    )
    if not raw_method.isascii():
        raise PreflightInputError("Graph membership method must use ASCII")
    method = _normalized(raw_method)
    if method not in _GRAPH_MEMBERSHIP_METHODS:
        raise PreflightInputError("Graph membership method is unsupported")
    values, request_urls = _paged_values(
        _get_case_insensitive(membership, "pages"),
        field_name="Graph group-membership evidence",
        next_link_field="@odata.nextLink",
        maximum_items=MAX_ASSIGNMENTS,
        allowed_host="graph.microsoft.com",
    )
    _validate_graph_urls(
        request_urls,
        effective_principal_id=effective_principal_id,
        method=method,
    )
    groups: set[str] = set()
    if method == "getmembergroups":
        if _get_case_insensitive(membership, "securityEnabledOnly") is not True:
            raise PreflightInputError("getMemberGroups evidence must set securityEnabledOnly true")
        if len(request_urls) != 1:
            raise PreflightInputError("getMemberGroups evidence must contain exactly one response")
        for raw_group_id in values:
            group_id = _canonical_guid(
                raw_group_id,
                field_name="Graph security-group id",
            )
            if group_id in groups:
                raise PreflightInputError(
                    "Graph group-membership evidence contains a duplicate group"
                )
            groups.add(group_id)
    else:
        for raw_item in values:
            item = _mapping(
                raw_item,
                field_name="Graph transitiveMemberOf item",
            )
            object_type = _normalized(
                _require_string(
                    _get_case_insensitive(item, "@odata.type"),
                    field_name="Graph transitiveMemberOf @odata.type",
                    maximum_length=128,
                )
            )
            object_id = _canonical_guid(
                _get_case_insensitive(item, "id"),
                field_name="Graph transitiveMemberOf id",
            )
            if object_type != "#microsoft.graph.group":
                continue
            security_enabled = _get_case_insensitive(
                item,
                "securityEnabled",
            )
            if type(security_enabled) is not bool:
                raise PreflightInputError("Graph group membership omits securityEnabled")
            if security_enabled:
                if object_id in groups:
                    raise PreflightInputError(
                        "Graph group-membership evidence contains a duplicate group"
                    )
                groups.add(object_id)
    return frozenset(groups)


def _parse_service_principal(
    value: object,
    *,
    effective_principal_id: str,
    target: RbacCollection,
) -> None:
    service_principal = _mapping(
        value,
        field_name="Graph service-principal evidence",
    )
    _require_http_success(
        _get_case_insensitive(service_principal, "statusCode"),
        field_name="Graph service-principal evidence",
    )
    if (
        _canonical_guid(
            _get_case_insensitive(service_principal, "tenantId"),
            field_name="Graph service-principal tenantId",
        )
        != target.tenant_id
    ):
        raise PreflightInputError("Graph service-principal evidence crosses tenants")
    object_id = _canonical_guid(
        _get_case_insensitive(service_principal, "id"),
        field_name="Graph service-principal object id",
    )
    client_id = _canonical_guid(
        _get_case_insensitive(service_principal, "appId"),
        field_name="Graph service-principal appId",
    )
    if object_id == client_id:
        raise PreflightInputError("service-principal object ID and client ID must differ")
    if effective_principal_id == client_id:
        raise PreflightInputError("effectivePrincipalId is a client ID, not an object ID")
    if effective_principal_id != object_id:
        raise PreflightInputError(
            "effectivePrincipalId does not match the service-principal object ID"
        )


def _validate_assigned_to_filter(
    value: object,
    *,
    effective_principal_id: str,
    field_name: str,
) -> str:
    filter_value = _require_string(
        value,
        field_name=field_name,
    )
    match = re.fullmatch(
        rf"atScope\(\)\s+and\s+assignedTo\('({_GUID_PATTERN})'\)",
        filter_value,
        re.IGNORECASE,
    )
    if match is None:
        raise PreflightInputError(f"{field_name} must use atScope() and assignedTo(object-id)")
    if match.group(1).casefold() != effective_principal_id:
        raise PreflightInputError(f"{field_name} uses a different principal")
    return filter_value


def _validate_arm_role_assignment_urls(
    request_urls: tuple[str, ...],
    *,
    target: RbacCollection,
    effective_principal_id: str,
) -> None:
    expected_path = (
        target.resource_group_scope + "/providers/microsoft.authorization/roleassignments"
    )
    for index, request_url in enumerate(request_urls):
        parts = _split_url(
            request_url,
            field_name="ARM role-assignment requestUrl",
        )
        if unquote(parts.path).casefold() != expected_path:
            raise PreflightInputError("ARM role-assignment requestUrl uses the wrong scope")
        query = {
            key.casefold(): values
            for key, values in parse_qs(
                parts.query,
                keep_blank_values=True,
            ).items()
        }
        allowed_keys = {"api-version", "$filter"}
        if index > 0:
            allowed_keys.add("$skiptoken")
        if (
            parts.fragment
            or set(query) - allowed_keys
            or query.get("api-version") != [_ARM_ROLE_ASSIGNMENTS_API_VERSION]
            or len(query.get("$filter", [])) != 1
            or (index == 0 and "$skiptoken" in query)
            or (index > 0 and len(query.get("$skiptoken", [])) != 1)
        ):
            raise PreflightInputError("ARM role-assignment requestUrl is not canonical")
        _validate_assigned_to_filter(
            query["$filter"][0],
            effective_principal_id=effective_principal_id,
            field_name="ARM role-assignment requestUrl filter",
        )


def _parse_arm_role_assignment(
    value: object,
    *,
    effective_principal_id: str,
) -> RbacAssignment:
    resource = _mapping(
        value,
        field_name="ARM role assignment",
    )
    resource_type = _normalized(
        _require_string(
            _get_case_insensitive(resource, "type"),
            field_name="ARM role-assignment type",
            maximum_length=128,
        )
    )
    if resource_type != "microsoft.authorization/roleassignments":
        raise PreflightInputError("ARM role-assignment resource has the wrong type")
    resource_id = _canonical_scope(
        _require_string(
            _get_case_insensitive(resource, "id"),
            field_name="ARM role-assignment id",
        )
    )
    marker = "/providers/microsoft.authorization/roleassignments/"
    marker_index = resource_id.rfind(marker)
    if marker_index < 0:
        raise PreflightInputError("ARM role-assignment id is malformed")
    assignment_name = resource_id[marker_index + len(marker) :]
    if "/" in assignment_name or _GUID.fullmatch(assignment_name) is None:
        raise PreflightInputError("ARM role-assignment id must end in an assignment GUID")
    id_scope = resource_id[:marker_index] if marker_index > 0 else "/"
    id_scope = _canonical_scope(id_scope)
    properties = _mapping(
        _get_case_insensitive(resource, "properties"),
        field_name="ARM role-assignment properties",
    )
    property_scope = _canonical_scope(
        _require_string(
            _get_case_insensitive(properties, "scope"),
            field_name="ARM role-assignment scope",
        )
    )
    if property_scope != id_scope:
        raise PreflightInputError("ARM role-assignment id and properties.scope disagree")
    normalized_assignment: dict[str, object] = {
        "principalId": _get_case_insensitive(properties, "principalId"),
        "principalType": _get_case_insensitive(
            properties,
            "principalType",
        ),
        "effectivePrincipalId": effective_principal_id,
        "roleDefinitionId": _get_case_insensitive(
            properties,
            "roleDefinitionId",
        ),
        "scope": property_scope,
    }
    for field_name in (
        "roleDefinitionName",
        "condition",
        "conditionVersion",
    ):
        if _has_case_insensitive(properties, field_name):
            normalized_assignment[field_name] = _get_case_insensitive(
                properties,
                field_name,
            )
    return _parse_rbac_assignment(
        normalized_assignment,
        field_name="ARM role assignment",
    )


def _validate_cli_arguments(
    value: object,
    *,
    target: RbacCollection,
    effective_principal_id: str,
) -> None:
    arguments = [
        _require_string(
            argument,
            field_name="Azure CLI role-assignment argument",
            maximum_length=4096,
        )
        for argument in _sequence(
            value,
            field_name="Azure CLI role-assignment arguments",
            maximum_items=64,
        )
    ]
    normalized = [argument.casefold() for argument in arguments]
    if any(argument.startswith("--") and "=" in argument for argument in normalized):
        raise PreflightInputError("Azure CLI role collection does not allow equals-form arguments")
    switch_flags = {
        "--include-groups",
        "--include-inherited",
        "--only-show-errors",
    }
    expected_values = {
        "--subscription": target.subscription_id,
        "--scope": target.resource_group_scope,
        "--assignee-object-id": effective_principal_id,
        "--output": "json",
        "--fill-principal-name": "false",
        "--fill-role-definition-name": "true",
    }
    required_flags = {
        "--assignee-object-id",
        "--include-groups",
        "--include-inherited",
        "--output",
        "--scope",
        "--subscription",
    }
    seen: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = normalized[index]
        if argument in seen:
            raise PreflightInputError(f"Azure CLI role collection repeats {argument}")
        if argument in switch_flags:
            seen.add(argument)
            index += 1
            continue
        if argument not in expected_values:
            raise PreflightInputError(
                f"Azure CLI role collection contains unsupported argument {arguments[index]}"
            )
        if index + 1 >= len(arguments):
            raise PreflightInputError(f"Azure CLI role collection omits the value for {argument}")
        seen.add(argument)
        actual_value = arguments[index + 1]
        if actual_value.startswith("--"):
            raise PreflightInputError(f"Azure CLI role collection omits the value for {argument}")
        if argument == "--scope":
            actual_value = _canonical_scope(actual_value)
        else:
            actual_value = _normalized(actual_value)
        if actual_value != expected_values[argument]:
            raise PreflightInputError(f"Azure CLI role collection uses the wrong {argument}")
        index += 2
    missing = sorted(required_flags - seen)
    if missing:
        raise PreflightInputError(
            "Azure CLI role collection is missing required arguments: " + ", ".join(missing)
        )


def _validate_effective_assignment_principal(
    assignment: RbacAssignment,
    *,
    effective_principal_id: str,
    security_group_ids: frozenset[str],
) -> None:
    assigned_principal_id = _canonical_guid(
        assignment.principal_id,
        field_name="assigned principal ID",
    )
    if assignment.principal_type == "serviceprincipal":
        if assigned_principal_id != effective_principal_id:
            raise PreflightInputError(
                "direct ARM role assignment does not target the effective service principal"
            )
        return
    if assignment.principal_type != "group":
        raise PreflightInputError(
            "effective role assignment principalType must be ServicePrincipal or Group"
        )
    if assigned_principal_id not in security_group_ids:
        raise PreflightInputError("ARM group-derived assignment disagrees with Graph membership")


def _scope_is_effective_for_target(
    scope: str,
    *,
    collection: RbacCollection,
) -> bool:
    return (
        scope
        in {
            "/",
            collection.subscription_scope,
            collection.resource_group_scope,
        }
        or scope in collection.management_group_ancestry
    )


def _parse_effective_role_assignments(
    value: object,
    *,
    effective_principal_id: str,
    security_group_ids: frozenset[str],
    collection: RbacCollection,
) -> list[RbacAssignment]:
    evidence = _mapping(
        value,
        field_name="effective role-assignment evidence",
    )
    raw_method = _require_string(
        _get_case_insensitive(evidence, "method"),
        field_name="role-assignment collection method",
        maximum_length=64,
    )
    if not raw_method.isascii():
        raise PreflightInputError("role-assignment collection method must use ASCII")
    method = _normalized(raw_method)
    assignments: list[RbacAssignment] = []
    if method == "arm":
        api_version = _require_string(
            _get_case_insensitive(evidence, "apiVersion"),
            field_name="ARM role-assignment apiVersion",
            maximum_length=64,
        )
        if api_version != _ARM_ROLE_ASSIGNMENTS_API_VERSION:
            raise PreflightInputError("ARM role-assignment evidence requires apiVersion 2022-04-01")
        scope = _canonical_scope(
            _require_string(
                _get_case_insensitive(evidence, "scope"),
                field_name="ARM role-assignment request scope",
            )
        )
        if scope != collection.resource_group_scope:
            raise PreflightInputError("ARM role-assignment evidence uses the wrong target scope")
        _validate_assigned_to_filter(
            _get_case_insensitive(evidence, "filter"),
            effective_principal_id=effective_principal_id,
            field_name="ARM role-assignment filter",
        )
        raw_assignments, request_urls = _paged_values(
            _get_case_insensitive(evidence, "pages"),
            field_name="ARM role-assignment evidence",
            next_link_field="nextLink",
            maximum_items=MAX_ASSIGNMENTS,
            allowed_host="management.azure.com",
        )
        _validate_arm_role_assignment_urls(
            request_urls,
            target=collection,
            effective_principal_id=effective_principal_id,
        )
        assignments = [
            _parse_arm_role_assignment(
                assignment,
                effective_principal_id=effective_principal_id,
            )
            for assignment in raw_assignments
        ]
    elif method == "azure-cli":
        exit_code = _get_case_insensitive(evidence, "exitCode")
        if type(exit_code) is not int or exit_code != 0:
            raise PreflightInputError("Azure CLI role-assignment collection did not succeed")
        _validate_cli_arguments(
            _get_case_insensitive(evidence, "arguments"),
            target=collection,
            effective_principal_id=effective_principal_id,
        )
        for raw_assignment in _sequence(
            _get_case_insensitive(evidence, "value"),
            field_name="Azure CLI role assignments",
            maximum_items=MAX_ASSIGNMENTS,
        ):
            assignment = _parse_rbac_assignment(
                raw_assignment,
                field_name="Azure CLI role assignment",
            )
            if (
                assignment.effective_principal_id_supplied
                and assignment.effective_principal_id != effective_principal_id
            ):
                raise PreflightInputError(
                    "Azure CLI assignment effectivePrincipalId disagrees with its collection"
                )
            assignments.append(
                replace(
                    assignment,
                    effective_principal_id=effective_principal_id,
                    effective_principal_id_supplied=True,
                )
            )
    else:
        raise PreflightInputError("role-assignment collection method must be arm or azure-cli")
    unique_assignments: set[RbacAssignment] = set()
    for assignment in assignments:
        if not assignment.role_definition_id:
            raise PreflightInputError("effective role assignment requires roleDefinitionId")
        if not assignment.principal_type_supplied:
            raise PreflightInputError("effective role assignment requires principalType")
        _validate_effective_assignment_principal(
            assignment,
            effective_principal_id=effective_principal_id,
            security_group_ids=security_group_ids,
        )
        if not _scope_is_effective_for_target(
            assignment.scope,
            collection=collection,
        ):
            raise PreflightInputError(
                "effective role assignment scope is outside the attested target ancestry"
            )
        if assignment in unique_assignments:
            raise PreflightInputError(
                "effective role-assignment evidence contains a duplicate assignment"
            )
        unique_assignments.add(assignment)
    return assignments


def _derive_guarded_role_assignments(
    document: object,
    *,
    policy: RbacPolicy,
) -> tuple[list[RbacAssignment], RbacCollection]:
    root = _mapping(document, field_name="guarded RBAC evidence")
    if any(
        _has_case_insensitive(root, legacy_name)
        for legacy_name in ("value", "queries", "collection")
    ):
        raise PreflightInputError(
            "guarded RBAC evidence requires raw target, hierarchy, and principal artifacts"
        )
    target = _parse_evidence_target(_get_case_insensitive(root, "target"))
    if policy.target is None:
        raise PreflightInputError("RBAC policy requires a reviewed target")
    if (
        target.tenant_id != policy.target.tenant_id
        or target.subscription_id != policy.target.subscription_id
        or target.resource_group_scope != policy.target.resource_group_scope
    ):
        raise PreflightInputError("RBAC evidence target does not match the reviewed policy target")
    ancestry = _derive_management_group_ancestry(
        _get_case_insensitive(root, "hierarchy"),
        target=target,
    )
    if ancestry != policy.target.management_group_ancestry:
        raise PreflightInputError("management-group hierarchy changed from the reviewed policy")
    target = replace(
        target,
        management_group_ancestry=ancestry,
    )
    assignments: list[RbacAssignment] = []
    effective_principal_ids: set[str] = set()
    unique_assignment_keys: set[
        tuple[
            str,
            str,
            str,
            str,
            str,
            str | None,
            str | None,
        ]
    ] = set()
    for raw_principal in _sequence(
        _get_case_insensitive(root, "principals"),
        field_name="RBAC evidence principals",
        maximum_items=MAX_POLICY_ITEMS,
    ):
        principal = _mapping(
            raw_principal,
            field_name="RBAC evidence principal",
        )
        effective_principal_id = _canonical_guid(
            _get_case_insensitive(principal, "effectivePrincipalId"),
            field_name="effectivePrincipalId",
        )
        if effective_principal_id in effective_principal_ids:
            raise PreflightInputError("RBAC evidence contains a duplicate effectivePrincipalId")
        effective_principal_ids.add(effective_principal_id)
        _parse_service_principal(
            _get_case_insensitive(principal, "servicePrincipal"),
            effective_principal_id=effective_principal_id,
            target=target,
        )
        security_group_ids = _parse_security_group_membership(
            _get_case_insensitive(principal, "groupMembership"),
            effective_principal_id=effective_principal_id,
            target=target,
        )
        for assignment in _parse_effective_role_assignments(
            _get_case_insensitive(principal, "roleAssignments"),
            effective_principal_id=effective_principal_id,
            security_group_ids=security_group_ids,
            collection=target,
        ):
            key = _assignment_key(assignment)
            if key in unique_assignment_keys:
                raise PreflightInputError(
                    "guarded RBAC evidence contains a duplicate effective assignment"
                )
            unique_assignment_keys.add(key)
            assignments.append(assignment)
    if not effective_principal_ids:
        raise PreflightInputError("RBAC evidence principals must not be empty")
    return (
        assignments,
        replace(
            target,
            effective_principal_ids=frozenset(effective_principal_ids),
        ),
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
        if key.lower() in {"nextlink", "@odata.nextlink", "odata.nextlink"} and value is not None:
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
    if require_separation_rules:
        if not policy.separation_rules:
            raise PreflightInputError("RBAC policy requires at least one separation rule")
        if not policy.expected_principal_ids:
            raise PreflightInputError("RBAC policy requires expectedPrincipalIds")
        if policy.legacy_expected_assignments_supplied:
            raise PreflightInputError(
                "guarded RBAC policy must use approvedAssignments, not expectedAssignments"
            )
        if not policy.approved_assignments_supplied:
            raise PreflightInputError("RBAC policy requires approvedAssignments")
        if not policy.approved_assignments:
            raise PreflightInputError("approvedAssignments must not be empty")
        if policy.target is None:
            raise PreflightInputError("RBAC policy requires a reviewed target")
        for assignment in policy.approved_assignments:
            if not assignment.role_definition_id:
                raise PreflightInputError("approvedAssignments require roleDefinitionId")
            if not assignment.role_name_supplied:
                raise PreflightInputError("approvedAssignments require roleDefinitionName")
            _validate_guarded_assignment_binding(
                assignment,
                field_name="approvedAssignments",
            )
            _canonical_guid(
                assignment.principal_id,
                field_name="approved assignedPrincipalId",
            )
            _canonical_guid(
                assignment.effective_principal_id,
                field_name="approved effectivePrincipalId",
            )
            if not _scope_is_effective_for_target(
                assignment.scope,
                collection=policy.target,
            ):
                raise PreflightInputError(
                    "approvedAssignments scope is outside the reviewed target ancestry"
                )
        for allowance in policy.allowed_broad_assignments:
            if not allowance.role_definition_id:
                raise PreflightInputError("allowedBroadAssignments require roleDefinitionId")
            if not allowance.role_name_supplied:
                raise PreflightInputError("allowedBroadAssignments require roleDefinitionName")
            _validate_guarded_assignment_binding(
                allowance,
                field_name="allowedBroadAssignments",
            )
        rule_principal_ids = frozenset(rule.principal_id for rule in policy.separation_rules)
        if rule_principal_ids != policy.expected_principal_ids:
            raise PreflightInputError(
                "separationRules principals must exactly match expectedPrincipalIds"
            )
        if any(not rule.forbidden_role_ids for rule in policy.separation_rules):
            raise PreflightInputError("separation rule requires forbiddenRoleDefinitionIds")
        allowance_principal_ids = frozenset(
            allowance.effective_principal_id for allowance in policy.allowed_broad_assignments
        )
        if not allowance_principal_ids.issubset(policy.expected_principal_ids):
            raise PreflightInputError(
                "RBAC policy principals must be listed in expectedPrincipalIds"
            )
        approved_assignment_principal_ids = frozenset(
            assignment.effective_principal_id for assignment in policy.approved_assignments
        )
        if approved_assignment_principal_ids != policy.expected_principal_ids:
            raise PreflightInputError(
                "approvedAssignments principals must exactly match expectedPrincipalIds"
            )
        approved_assignment_keys = {
            _assignment_key(assignment) for assignment in policy.approved_assignments
        }
        approved_allowances = tuple(
            BroadAssignmentAllowance(
                principal_id=assignment.principal_id,
                effective_principal_id=(assignment.effective_principal_id),
                principal_type=assignment.principal_type,
                role_name=assignment.role_name,
                role_definition_id=assignment.role_definition_id,
                scope=assignment.scope,
                condition=assignment.condition,
                condition_version=assignment.condition_version,
                role_name_supplied=assignment.role_name_supplied,
                effective_principal_id_supplied=(assignment.effective_principal_id_supplied),
                principal_type_supplied=(assignment.principal_type_supplied),
                assigned_principal_fields_supplied=(assignment.assigned_principal_fields_supplied),
            )
            for assignment in policy.approved_assignments
        )
        if not all(
            any(_allowance_matches(allowance, approved) for approved in approved_allowances)
            for allowance in policy.allowed_broad_assignments
        ):
            raise PreflightInputError(
                "allowedBroadAssignments must be listed in approvedAssignments"
            )
        observed_assignments, collection = _derive_guarded_role_assignments(
            document,
            policy=policy,
        )
        if not observed_assignments:
            raise PreflightInputError("effective role-assignment evidence must not be empty")
        if collection.effective_principal_ids != policy.expected_principal_ids:
            raise PreflightInputError(
                "RBAC evidence effectivePrincipalIds must exactly match expectedPrincipalIds"
            )
        observed_assignment_keys = {
            _assignment_key(assignment) for assignment in observed_assignments
        }
        if observed_assignment_keys != approved_assignment_keys:
            raise PreflightInputError(
                "derived effective assignments do not exactly match approvedAssignments"
            )
        approved_by_key = {
            _assignment_key(assignment): assignment for assignment in policy.approved_assignments
        }
        assignments = [
            approved_by_key[_assignment_key(assignment)] for assignment in observed_assignments
        ]
    else:
        assignments = []
        unique_assignments: set[RbacAssignment] = set()
        for raw_assignment in _role_assignments(document):
            assignment = _parse_rbac_assignment(
                raw_assignment,
                field_name="role assignment",
            )
            if assignment in unique_assignments:
                raise PreflightInputError(
                    "role-assignment evidence contains a duplicate assignment"
                )
            unique_assignments.add(assignment)
            assignments.append(assignment)

    violations: list[PreflightViolation] = []
    for assignment in assignments:
        assignment_principal_id = assignment.principal_id
        effective_principal_id = assignment.effective_principal_id
        canonical_role = assignment.role_name
        role_id = assignment.role_definition_id
        scope = assignment.scope
        access_path = (
            f"{canonical_role} via group {assignment_principal_id}"
            if assignment.principal_type == "group"
            else canonical_role
        )
        broad_scope = (
            scope == "/"
            or _SUBSCRIPTION_SCOPE.fullmatch(scope) is not None
            or _RESOURCE_GROUP_SCOPE.fullmatch(scope) is not None
            or _MANAGEMENT_GROUP_SCOPE.fullmatch(scope) is not None
        )
        allowed = any(
            _allowance_matches(
                allowance,
                BroadAssignmentAllowance(
                    principal_id=assignment_principal_id,
                    effective_principal_id=effective_principal_id,
                    principal_type=assignment.principal_type,
                    role_name=canonical_role,
                    role_definition_id=role_id,
                    scope=scope,
                    condition=assignment.condition,
                    condition_version=assignment.condition_version,
                    role_name_supplied=assignment.role_name_supplied,
                    effective_principal_id_supplied=(assignment.effective_principal_id_supplied),
                    principal_type_supplied=(assignment.principal_type_supplied),
                    assigned_principal_fields_supplied=(
                        assignment.assigned_principal_fields_supplied
                    ),
                ),
            )
            for allowance in policy.allowed_broad_assignments
        )
        if (
            (canonical_role in _BROAD_ROLES or role_id in _BROAD_ROLE_IDS)
            and broad_scope
            and not allowed
        ):
            violations.append(
                PreflightViolation(
                    code="broad-role-assignment",
                    subject=effective_principal_id,
                    detail=(f"{access_path} at broad scope {scope}"),
                )
            )
        for rule in policy.separation_rules:
            if (
                effective_principal_id == rule.principal_id
                and (
                    canonical_role in rule.forbidden_role_names
                    or role_id in rule.forbidden_role_ids
                )
                and any(
                    _separation_scope_matches(scope, prefix)
                    for prefix in rule.forbidden_scope_prefixes
                )
            ):
                violations.append(
                    PreflightViolation(
                        code="identity-separation",
                        subject=effective_principal_id,
                        detail=(f"{access_path} is forbidden at scope {scope}"),
                    )
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
    return (
        json.dumps(
            {
                "kind": kind,
                "safe": not ordered_violations,
                "violations": [asdict(item) for item in ordered_violations],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


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
            stderr.write(f"WC-029 preflight {kind} failed: {_escaped_text(str(exc))}\n")
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
        allowed_change_ids=frozenset(args.allow_change if args.command == "what-if" else ()),
        policy_path=args.policy if args.command == "rbac" else None,
        output_format=args.format,
        stdout=output,
        stderr=errors,
    )


if __name__ == "__main__":
    raise SystemExit(main())
