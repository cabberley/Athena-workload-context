from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CHANGES = 5000
MAX_ASSIGNMENTS = 10000
MAX_POLICY_ITEMS = 512
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100000

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
_SUBSCRIPTION_SCOPE = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}$",
    re.IGNORECASE,
)
_RESOURCE_GROUP_SCOPE = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[^/]+$",
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


def _canonical_role_key(value: str) -> str:
    normalized = _normalized(value).rsplit("/", 1)[-1]
    return _ROLE_ID_TO_NAME.get(normalized, normalized)


def _canonical_property_path(value: str) -> str:
    normalized = value.casefold()
    prefix = "<resource>."
    return normalized.removeprefix(prefix) if normalized.startswith(prefix) else normalized


def _scope_contains(ancestor: str, descendant: str) -> bool:
    normalized_ancestor = ancestor.rstrip("/") or "/"
    normalized_descendant = descendant.rstrip("/") or "/"
    return (
        normalized_ancestor == "/"
        or normalized_descendant == normalized_ancestor
        or normalized_descendant.startswith(normalized_ancestor + "/")
    )


def _require_string(
    value: object,
    *,
    field_name: str,
    maximum_length: int = 4096,
) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum_length:
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
        )
        _validate_json_shape(document)
        return document
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
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
            if any(type(key) is not str or len(key) > 4096 for key in item):
                raise PreflightInputError("JSON object keys are invalid")
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
            if role_value is None:
                role_value = _get_case_insensitive(
                    item,
                    "roleDefinitionName",
                )
            allowances.add(
                BroadAssignmentAllowance(
                    principal_id=_normalized(
                        _require_string(
                            _get_case_insensitive(item, "principalId"),
                            field_name="principalId",
                        )
                    ),
                    role_name=_canonical_role_key(
                        _require_string(
                            role_value,
                            field_name=("roleDefinitionName or roleDefinitionId"),
                        )
                    ),
                    scope=_normalized(
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
                            _normalized(
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
    return RbacPolicy(
        allowed_broad_assignments=frozenset(allowances),
        separation_rules=tuple(rules),
    )


def _role_assignments(document: object) -> list[object]:
    if isinstance(document, list):
        return _sequence(
            document,
            field_name="role assignments",
            maximum_items=MAX_ASSIGNMENTS,
        )
    root = _mapping(document, field_name="role-assignment document")
    return _sequence(
        _get_case_insensitive(root, "value"),
        field_name="value",
        maximum_items=MAX_ASSIGNMENTS,
    )


def evaluate_role_assignments(
    document: object,
    *,
    policy_document: object | None = None,
) -> tuple[PreflightViolation, ...]:
    _validate_json_shape(document)
    policy = _parse_policy(policy_document)
    violations: list[PreflightViolation] = []
    for raw_assignment in _role_assignments(document):
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
            else _normalized(
                _require_string(
                    raw_role_id,
                    field_name="roleDefinitionId",
                )
            ).rsplit("/", 1)[-1]
        )
        mapped_role_id = _ROLE_ID_TO_NAME.get(role_id)
        if role_name and mapped_role_id is not None and role_name != mapped_role_id:
            raise PreflightInputError("roleDefinitionName and roleDefinitionId conflict")
        canonical_role = role_name or mapped_role_id or role_id
        if not canonical_role:
            raise PreflightInputError(
                "role assignment requires roleDefinitionName or roleDefinitionId"
            )
        scope = _normalized(
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
    return tuple(violations)


def _render_result(
    *,
    kind: str,
    violations: tuple[PreflightViolation, ...],
) -> str:
    return json.dumps(
        {
            "kind": kind,
            "safe": not violations,
            "violations": [asdict(item) for item in violations],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


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
    rbac = subparsers.add_parser("rbac")
    rbac.add_argument("input", type=Path)
    rbac.add_argument("--policy", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = load_json_file(args.input)
        if args.command == "what-if":
            violations = evaluate_what_if(
                document,
                allowed_change_ids=frozenset(args.allow_change),
            )
        else:
            policy = (
                None
                if args.policy is None
                else load_json_file(args.policy, maximum_bytes=1024 * 1024)
            )
            violations = evaluate_role_assignments(
                document,
                policy_document=policy,
            )
    except PreflightInputError as exc:
        print(
            json.dumps(
                {"safe": False, "error": str(exc)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 3
    print(_render_result(kind=args.command, violations=violations))
    return 0 if not violations else 2


if __name__ == "__main__":
    raise SystemExit(main())
