from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, TextIO
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CHANGES = 5000
MAX_ASSIGNMENTS = 10000
MAX_POLICY_ITEMS = 512
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100000
MAX_JSON_INTEGER_DIGITS = 1024
MAX_JSON_DECIMAL_DIGITS = 1024
MAX_JSON_DECIMAL_EXPONENT = 1024
MAX_VIOLATIONS = 256
MAX_RENDER_BYTES = 1024 * 1024
MAX_PROPERTY_PATH_LENGTH = 4096
MAX_PROPERTY_PATH_ITEMS = 50000
MAX_PROPERTY_PATH_CHARACTERS = 4 * 1024 * 1024
MAX_PROPERTY_LOOKUP_WORK = 500000
MAX_ATTESTATION_LIFETIME = timedelta(minutes=30)
MAX_ATTESTATION_CLOCK_SKEW = timedelta(minutes=5)

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
_RESOURCE_ROOT_PATH = "<resource>"
_RESOURCE_ROOT_ALIASES = frozenset(
    {
        ".",
        _RESOURCE_ROOT_PATH,
        f"{_RESOURCE_ROOT_PATH}.",
    }
)
_PROPERTY_NAME_PATTERN = r"[A-Za-z_$][A-Za-z0-9_$-]*"
_PROPERTY_NAME = re.compile(rf"^{_PROPERTY_NAME_PATTERN}$")
_PROPERTY_COMPONENT = re.compile(
    rf"^(?P<name>{_PROPERTY_NAME_PATTERN})"
    r"(?P<indexes>(?:\[(?:0|[1-9][0-9]*)\])*)$"
)
_PROPERTY_INDEX = re.compile(r"\[(0|[1-9][0-9]*)\]")
_UNSUPPORTED_MUTATION_PREFIXES = (
    "microsoft.authorization/",
    "microsoft.managedservices/",
)
_UNSUPPORTED_IMPERATIVE_TYPES = frozenset(
    {
        "microsoft.resources/deploymentscripts",
    }
)
_MANIFEST_SCHEMA_VERSION = "athena.wc029PreflightManifest.v1"
_ARM_ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
_GRAPH_MEMBERSHIP_METHODS = frozenset(
    {
        "getmembergroups",
        "transitivememberof",
    }
)
_MANIFEST_BINDING_NAMES = frozenset(
    {
        "allowChangeIdsDigest",
        "deploymentDigest",
        "parametersDigest",
        "policyDigest",
        "rbacEvidenceDigest",
        "templateDigest",
        "whatIfDigest",
        "whatIfRequestDigest",
    }
)
_MANIFEST_FIELD_NAMES = frozenset(
    {
        "bindings",
        "collectedat",
        "collectionrunid",
        "deploymentexecutionid",
        "deploymenttarget",
        "expiresat",
        "schemaversion",
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
class DeploymentTarget:
    tenant_id: str
    subscription_id: str
    resource_group_scopes: tuple[str, ...]


@dataclass(slots=True)
class _PropertyPathBudget:
    items: int = 0
    characters: int = 0
    lookup_work: int = 0

    def charge(self, path: str) -> None:
        if len(path) > MAX_PROPERTY_PATH_LENGTH:
            raise PreflightInputError(
                f"property path exceeds {MAX_PROPERTY_PATH_LENGTH} characters"
            )
        self.items += 1
        self.characters += len(path)
        if self.items > MAX_PROPERTY_PATH_ITEMS or self.characters > MAX_PROPERTY_PATH_CHARACTERS:
            raise PreflightInputError("property path generation exceeds its aggregate work budget")

    def charge_lookup(self, work: int) -> None:
        self.lookup_work += work
        if self.lookup_work > MAX_PROPERTY_LOOKUP_WORK:
            raise PreflightInputError("property snapshot lookup exceeds its aggregate work budget")


@dataclass(frozen=True, slots=True)
class AttestationManifest:
    collection_run_id: str
    deployment_execution_id: str
    deployment_target: DeploymentTarget
    collected_at: datetime
    expires_at: datetime
    bindings: dict[str, str]
    digest: str


def _finalize_violations(
    values: Sequence[PreflightViolation],
) -> tuple[PreflightViolation, ...]:
    violations: list[PreflightViolation] = []
    seen: set[PreflightViolation] = set()
    for violation in values:
        if violation in seen:
            continue
        if len(violations) >= MAX_VIOLATIONS:
            raise PreflightInputError(f"violation count exceeds {MAX_VIOLATIONS}")
        seen.add(violation)
        violations.append(violation)
    return tuple(violations)


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
type PropertyPathToken = str | int


def _normalized(value: str) -> str:
    return value.strip().casefold()


def _resource_type(resource_id: str) -> str:
    canonical_resource_id = _canonical_scope(resource_id)
    segments = [segment for segment in canonical_resource_id.strip("/").split("/") if segment]
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


def _is_unsupported_authorization_or_imperative_type(resource_type: str) -> bool:
    return resource_type.startswith(_UNSUPPORTED_MUTATION_PREFIXES) or any(
        resource_type == imperative_type or resource_type.startswith(imperative_type + "/")
        for imperative_type in _UNSUPPORTED_IMPERATIVE_TYPES
    )


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


def _parse_json_decimal(value: str) -> Decimal:
    digits = sum(character.isdigit() for character in value)
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise PreflightInputError("JSON decimal is invalid") from exc
    exponent = parsed.as_tuple().exponent
    if (
        digits > MAX_JSON_DECIMAL_DIGITS
        or not parsed.is_finite()
        or not isinstance(exponent, int)
        or abs(exponent) > MAX_JSON_DECIMAL_EXPONENT
    ):
        raise PreflightInputError("JSON decimal exceeds its precision or exponent bound")
    return parsed


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
    stripped = value.strip()
    if not stripped.isascii():
        raise PreflightInputError("roleDefinitionId contains non-ASCII characters")
    normalized = stripped.lower()
    if "/" not in normalized:
        if _GUID.fullmatch(normalized) is None:
            raise PreflightInputError("roleDefinitionId must end in a role GUID")
        return normalized
    canonical = _canonical_scope(stripped)
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


def _property_path_tokens(value: str) -> tuple[PropertyPathToken, ...]:
    if len(value) > MAX_PROPERTY_PATH_LENGTH:
        raise PreflightInputError(f"property path exceeds {MAX_PROPERTY_PATH_LENGTH} characters")
    normalized = value.lower()
    if normalized != value.casefold():
        raise PreflightInputError("property path has ambiguous Unicode case folding")
    if _contains_non_ascii_case_alias(value):
        raise PreflightInputError("property path contains a non-ASCII case alias")
    if value in _RESOURCE_ROOT_ALIASES:
        return ()
    if not value.isascii():
        raise PreflightInputError("property path must use ASCII")
    prefix = f"{_RESOURCE_ROOT_PATH}."
    if normalized.startswith(_RESOURCE_ROOT_PATH):
        if not value.startswith(prefix):
            raise PreflightInputError("property path has an unsupported resource-root suffix")
        normalized = normalized.removeprefix(prefix)
    if not normalized:
        raise PreflightInputError("property path is empty")
    tokens: list[PropertyPathToken] = []
    for component in normalized.split("."):
        match = _PROPERTY_COMPONENT.fullmatch(component)
        if match is None:
            raise PreflightInputError(
                "property path must use dotted ASCII names and canonical numeric indexes"
            )
        tokens.append(match.group("name"))
        tokens.extend(
            int(index.group(1)) for index in _PROPERTY_INDEX.finditer(match.group("indexes"))
        )
    return tuple(tokens)


def _format_property_path(tokens: Sequence[PropertyPathToken]) -> str:
    if not tokens:
        return _RESOURCE_ROOT_PATH
    components: list[str] = []
    for token in tokens:
        if isinstance(token, str):
            components.append(token)
        elif not components:
            raise PreflightInputError("property path cannot start with an array index")
        else:
            components[-1] += f"[{token}]"
    path = ".".join(components)
    if len(path) > MAX_PROPERTY_PATH_LENGTH:
        raise PreflightInputError(f"property path exceeds {MAX_PROPERTY_PATH_LENGTH} characters")
    return path


def _canonical_property_path(value: str) -> str:
    return _format_property_path(_property_path_tokens(value))


def _accumulated_property_path(
    parent_path: str,
    own_path: str,
    *,
    budget: _PropertyPathBudget,
) -> str:
    if parent_path:
        if len(parent_path) + len(own_path) + 1 > MAX_PROPERTY_PATH_LENGTH:
            raise PreflightInputError(
                f"property path exceeds {MAX_PROPERTY_PATH_LENGTH} characters"
            )
        raw_path = f"{parent_path}.{own_path}"
    else:
        raw_path = own_path
    canonical_path = _canonical_property_path(raw_path)
    budget.charge(canonical_path)
    return canonical_path


def _property_path_contains(ancestor: str, descendant: str) -> bool:
    ancestor_tokens = _property_path_tokens(ancestor)
    descendant_tokens = _property_path_tokens(descendant)
    return descendant_tokens[: len(ancestor_tokens)] == ancestor_tokens


def _canonical_scope(value: str) -> str:
    stripped = value.strip()
    if not stripped.isascii():
        raise PreflightInputError("scope contains non-ASCII characters")
    normalized = stripped.lower()
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


def _length_prefixed(tag: bytes, payload: bytes) -> bytes:
    return tag + str(len(payload)).encode("ascii") + b":" + payload


def _canonical_json_bytes(value: object) -> bytes:
    if value is None:
        return b"n;"
    if type(value) is bool:
        return b"b1;" if value else b"b0;"
    if type(value) is int:
        return b"i" + str(value).encode("ascii") + b";"
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise PreflightInputError("JSON decimal must be finite")
        decimal_tuple = value.as_tuple()
        if not isinstance(decimal_tuple.exponent, int):
            raise PreflightInputError("JSON decimal exponent is invalid")
        digits = "".join(str(digit) for digit in decimal_tuple.digits) or "0"
        payload = f"{decimal_tuple.sign}:{decimal_tuple.exponent}:{digits}".encode("ascii")
        return _length_prefixed(b"d", payload)
    if type(value) is str:
        return _length_prefixed(b"s", value.encode("utf-8"))
    if isinstance(value, list):
        payload = b"".join(_canonical_json_bytes(item) for item in value)
        return b"l" + str(len(value)).encode("ascii") + b":" + payload
    if isinstance(value, dict) and all(type(key) is str for key in value):
        payload = b"".join(
            _canonical_json_bytes(key) + _canonical_json_bytes(value[key]) for key in sorted(value)
        )
        return b"o" + str(len(value)).encode("ascii") + b":" + payload
    raise PreflightInputError("canonical JSON contains an unsupported value")


def _canonical_json_digest(value: object) -> str:
    serialized = _canonical_json_bytes(value)
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


def _canonical_sha256_digest(
    value: object,
    *,
    field_name: str,
) -> str:
    digest = _normalized(
        _require_string(
            value,
            field_name=field_name,
            maximum_length=71,
        )
    )
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise PreflightInputError(f"{field_name} must be a sha256 digest")
    return digest


def _parse_utc_timestamp(
    value: object,
    *,
    field_name: str,
) -> datetime:
    timestamp = _require_string(
        value,
        field_name=field_name,
        maximum_length=64,
    )
    try:
        parsed = datetime.fromisoformat(
            timestamp.removesuffix("Z") + ("+00:00" if timestamp.endswith("Z") else "")
        )
    except ValueError as exc:
        raise PreflightInputError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise PreflightInputError(f"{field_name} must use UTC")
    return parsed.astimezone(UTC)


def _current_utc(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise PreflightInputError("current time must be timezone-aware")
    return now.astimezone(UTC)


def _validate_attestation_window(
    *,
    collected_at: datetime,
    expires_at: datetime,
    now: datetime,
) -> None:
    if expires_at <= collected_at or expires_at - collected_at > MAX_ATTESTATION_LIFETIME:
        raise PreflightInputError("attestation validity window is invalid or too long")
    if collected_at - now > MAX_ATTESTATION_CLOCK_SKEW:
        raise PreflightInputError("attestation collectedAt is in the future")
    if now >= expires_at:
        raise PreflightInputError("attestation has expired")


def _parse_deployment_target(value: object) -> DeploymentTarget:
    target = _mapping(
        value,
        field_name="manifest deploymentTarget",
    )
    if {key.casefold() for key in target} != {
        "resourcegroupids",
        "subscriptionid",
        "tenantid",
    }:
        raise PreflightInputError("manifest deploymentTarget has an invalid envelope")
    tenant_id = _canonical_guid(
        _get_case_insensitive(target, "tenantId"),
        field_name="manifest deploymentTarget tenantId",
    )
    subscription_id = _canonical_guid(
        _get_case_insensitive(target, "subscriptionId"),
        field_name="manifest deploymentTarget subscriptionId",
    )
    resource_group_scopes: set[str] = set()
    for raw_scope in _sequence(
        _get_case_insensitive(target, "resourceGroupIds"),
        field_name="manifest deploymentTarget resourceGroupIds",
        maximum_items=MAX_POLICY_ITEMS,
    ):
        scope = _canonical_scope(
            _require_string(
                raw_scope,
                field_name="manifest deploymentTarget resourceGroupId",
            )
        )
        if (
            _RESOURCE_GROUP_SCOPE.fullmatch(scope) is None
            or _resource_group_subscription_id(scope) != subscription_id
        ):
            raise PreflightInputError(
                "manifest deploymentTarget resourceGroupIds must belong to subscriptionId"
            )
        if scope in resource_group_scopes:
            raise PreflightInputError(
                "manifest deploymentTarget contains a duplicate resourceGroupId"
            )
        resource_group_scopes.add(scope)
    if not resource_group_scopes:
        raise PreflightInputError("manifest deploymentTarget resourceGroupIds must not be empty")
    return DeploymentTarget(
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        resource_group_scopes=tuple(sorted(resource_group_scopes)),
    )


def _deployment_target_payload(target: DeploymentTarget) -> dict[str, object]:
    return {
        "tenantId": target.tenant_id,
        "subscriptionId": target.subscription_id,
        "resourceGroupIds": list(target.resource_group_scopes),
    }


def _parse_attestation_manifest(
    value: object,
    *,
    expected_collection_run_id: str,
    expected_deployment_execution_id: str,
    expected_manifest_digest: str,
    now: datetime,
) -> AttestationManifest:
    manifest = _mapping(
        value,
        field_name="attestation manifest",
    )
    if {key.casefold() for key in manifest} != _MANIFEST_FIELD_NAMES:
        raise PreflightInputError("attestation manifest has an invalid envelope")
    if (
        _require_string(
            _get_case_insensitive(manifest, "schemaVersion"),
            field_name="manifest schemaVersion",
            maximum_length=64,
        )
        != _MANIFEST_SCHEMA_VERSION
    ):
        raise PreflightInputError("attestation manifest schemaVersion is unsupported")
    collection_run_id = _canonical_guid(
        _get_case_insensitive(manifest, "collectionRunId"),
        field_name="manifest collectionRunId",
    )
    if collection_run_id != _canonical_guid(
        expected_collection_run_id,
        field_name="expected collectionRunId",
    ):
        raise PreflightInputError("manifest collectionRunId does not match the reviewed run")
    deployment_execution_id = _canonical_guid(
        _get_case_insensitive(manifest, "deploymentExecutionId"),
        field_name="manifest deploymentExecutionId",
    )
    if deployment_execution_id != _canonical_guid(
        expected_deployment_execution_id,
        field_name="expected deploymentExecutionId",
    ):
        raise PreflightInputError(
            "manifest deploymentExecutionId does not match the immutable deployment execution"
        )
    deployment_target = _parse_deployment_target(
        _get_case_insensitive(manifest, "deploymentTarget")
    )
    collected_at = _parse_utc_timestamp(
        _get_case_insensitive(manifest, "collectedAt"),
        field_name="manifest collectedAt",
    )
    expires_at = _parse_utc_timestamp(
        _get_case_insensitive(manifest, "expiresAt"),
        field_name="manifest expiresAt",
    )
    _validate_attestation_window(
        collected_at=collected_at,
        expires_at=expires_at,
        now=now,
    )
    digest = _canonical_json_digest(manifest)
    if digest != _canonical_sha256_digest(
        expected_manifest_digest,
        field_name="reviewed attestation manifest digest",
    ):
        raise PreflightInputError("attestation manifest digest does not match the reviewed digest")
    bindings = _mapping(
        _get_case_insensitive(manifest, "bindings"),
        field_name="manifest bindings",
    )
    if set(bindings) != _MANIFEST_BINDING_NAMES:
        raise PreflightInputError("attestation manifest bindings are incomplete")
    normalized_bindings = {
        binding_name: _canonical_sha256_digest(
            _get_case_insensitive(bindings, binding_name),
            field_name=f"manifest {binding_name}",
        )
        for binding_name in _MANIFEST_BINDING_NAMES
    }
    return AttestationManifest(
        collection_run_id=collection_run_id,
        deployment_execution_id=deployment_execution_id,
        deployment_target=deployment_target,
        collected_at=collected_at,
        expires_at=expires_at,
        bindings=normalized_bindings,
        digest=digest,
    )


def _validate_artifact_attestation(
    value: object,
    *,
    artifact_kind: PreflightKind,
    manifest: AttestationManifest,
    expected_binding_names: frozenset[str],
) -> None:
    attestation = _mapping(
        value,
        field_name=f"{artifact_kind} attestation",
    )
    if (
        _normalized(
            _require_string(
                _get_case_insensitive(attestation, "artifactKind"),
                field_name="attestation artifactKind",
                maximum_length=32,
            )
        )
        != artifact_kind
    ):
        raise PreflightInputError("attestation artifactKind does not match the check")
    if (
        _canonical_guid(
            _get_case_insensitive(attestation, "collectionRunId"),
            field_name="attestation collectionRunId",
        )
        != manifest.collection_run_id
        or _parse_utc_timestamp(
            _get_case_insensitive(attestation, "collectedAt"),
            field_name="attestation collectedAt",
        )
        != manifest.collected_at
        or _parse_utc_timestamp(
            _get_case_insensitive(attestation, "expiresAt"),
            field_name="attestation expiresAt",
        )
        != manifest.expires_at
        or _canonical_guid(
            _get_case_insensitive(attestation, "deploymentExecutionId"),
            field_name="attestation deploymentExecutionId",
        )
        != manifest.deployment_execution_id
    ):
        raise PreflightInputError("artifact attestation does not match the reviewed manifest")
    if (
        _canonical_sha256_digest(
            _get_case_insensitive(attestation, "manifestDigest"),
            field_name="attestation manifestDigest",
        )
        != manifest.digest
    ):
        raise PreflightInputError("artifact attestation manifestDigest does not match")
    bindings = _mapping(
        _get_case_insensitive(attestation, "bindings"),
        field_name="attestation bindings",
    )
    if set(bindings) != expected_binding_names:
        raise PreflightInputError("artifact attestation bindings do not match the manifest subset")
    for binding_name in expected_binding_names:
        if (
            _canonical_sha256_digest(
                _get_case_insensitive(bindings, binding_name),
                field_name=f"attestation {binding_name}",
            )
            != manifest.bindings[binding_name]
        ):
            raise PreflightInputError(f"attestation {binding_name} does not match the manifest")


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


def _allow_change_binding(
    values: frozenset[str],
) -> tuple[frozenset[str], str]:
    records: list[dict[str, str]] = []
    canonical_values: set[str] = set()
    for value in values:
        raw_value = _require_string(
            value,
            field_name="allow-change resource ID",
        )
        if not raw_value.isascii():
            raise PreflightInputError("allow-change resource ID contains non-ASCII characters")
        canonical_value = _canonical_scope(raw_value)
        records.append(
            {
                "canonical": canonical_value,
                "raw": raw_value,
            }
        )
        canonical_values.add(canonical_value)
    records.sort(key=lambda item: (item["raw"], item["canonical"]))
    return (
        frozenset(canonical_values),
        _canonical_json_digest({"allowChangeIds": records}),
    )


def _scope_contains(ancestor: str, descendant: str) -> bool:
    return ancestor == "/" or descendant == ancestor or descendant.startswith(ancestor + "/")


def _validate_deployment_resource_id(
    resource_id: str,
    *,
    deployment_target: DeploymentTarget,
    field_name: str,
) -> str:
    canonical_resource_id = _canonical_scope(resource_id)
    subscription_prefix = f"/subscriptions/{deployment_target.subscription_id}/"
    if not canonical_resource_id.startswith(subscription_prefix):
        raise PreflightInputError(f"{field_name} is outside the reviewed deployment subscription")
    if not any(
        _scope_contains(resource_group_scope, canonical_resource_id)
        for resource_group_scope in deployment_target.resource_group_scopes
    ):
        raise PreflightInputError(
            f"{field_name} is outside the reviewed deployment resource-group boundary"
        )
    return canonical_resource_id


def _validate_rbac_deployment_target(
    collection: RbacCollection,
    *,
    deployment_target: DeploymentTarget,
) -> None:
    if (
        collection.tenant_id != deployment_target.tenant_id
        or collection.subscription_id != deployment_target.subscription_id
        or collection.resource_group_scope not in deployment_target.resource_group_scopes
    ):
        raise PreflightInputError(
            "RBAC evidence target does not match the reviewed manifest deploymentTarget"
        )


def _validate_what_if_snapshot_ids(
    change: dict[str, Any],
    *,
    canonical_resource_id: str,
    deployment_target: DeploymentTarget | None,
) -> None:
    for snapshot_name in ("before", "after"):
        if not _has_case_insensitive(change, snapshot_name):
            continue
        snapshot = _get_case_insensitive(change, snapshot_name)
        if not isinstance(snapshot, dict) or not any(
            _has_case_insensitive(snapshot, field_name) for field_name in ("id", "name", "type")
        ):
            continue
        _validate_resource_snapshot(
            snapshot,
            resource_id=canonical_resource_id,
            field_name=f"{snapshot_name} snapshot",
            deployment_target=deployment_target,
        )


def _minimal_scope_prefixes(values: Sequence[str]) -> tuple[str, ...]:
    unique = sorted(set(values))
    return tuple(
        value
        for value in unique
        if not any(other != value and _scope_contains(other, value) for other in unique)
    )


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
            parse_float=_parse_json_decimal,
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
        elif isinstance(item, Decimal):
            if not item.is_finite():
                raise PreflightInputError("JSON contains a non-finite number")
        elif isinstance(item, float):
            raise PreflightInputError("JSON floating-point values must be parsed exactly")
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


def _require_exact_cli_token(
    value: object,
    *,
    field_name: str,
    maximum_length: int = 4096,
) -> str:
    if type(value) is not str or value != value.strip():
        raise PreflightInputError(f"{field_name} must not contain surrounding whitespace")
    return _require_string(
        value,
        field_name=field_name,
        maximum_length=maximum_length,
    )


def _validate_what_if_request(
    value: object,
    *,
    deployment_target: DeploymentTarget,
) -> None:
    request = _mapping(
        value,
        field_name="what-if request",
    )
    if {key.casefold() for key in request} != {"arguments", "command"}:
        raise PreflightInputError("what-if request has an invalid envelope")
    command = [
        _require_exact_cli_token(
            token,
            field_name="what-if command token",
            maximum_length=64,
        )
        for token in _sequence(
            _get_case_insensitive(request, "command"),
            field_name="what-if command",
            maximum_items=4,
        )
    ]
    if any(not token.isascii() for token in command):
        raise PreflightInputError("what-if command tokens must use ASCII")
    if len(command) != 4 or command[:2] != ["az", "deployment"] or command[3] != "what-if":
        raise PreflightInputError("what-if command must use az deployment <scope> what-if")
    deployment_scope = command[2]
    if deployment_scope not in {"group", "sub"}:
        raise PreflightInputError("what-if command scope is unsupported")

    arguments = [
        _require_exact_cli_token(
            argument,
            field_name="what-if command argument",
            maximum_length=4096,
        )
        for argument in _sequence(
            _get_case_insensitive(request, "arguments"),
            field_name="what-if command arguments",
            maximum_items=32,
        )
    ]
    if any(not argument.isascii() for argument in arguments):
        raise PreflightInputError("what-if command arguments must use ASCII")
    allowed_options = {
        "--location",
        "--name",
        "--output",
        "--parameters",
        "--resource-group",
        "--result-format",
        "--subscription",
        "--template-file",
        "--validation-level",
    }
    switch_options = {"--no-pretty-print"}
    parsed: dict[str, str] = {}
    switches: set[str] = set()
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in switch_options:
            if option in switches:
                raise PreflightInputError("what-if command contains a duplicate switch")
            switches.add(option)
            index += 1
            continue
        if (
            option not in allowed_options
            or "=" in option
            or option in parsed
            or index + 1 >= len(arguments)
        ):
            raise PreflightInputError(
                "what-if command contains an unsupported, duplicate, or incomplete option"
            )
        option_value = arguments[index + 1]
        if option_value.startswith("--"):
            raise PreflightInputError("what-if command option is missing its value")
        parsed[option] = option_value
        index += 2
    required_options = {
        "--name",
        "--output",
        "--parameters",
        "--result-format",
        "--subscription",
        "--validation-level",
        "--location" if deployment_scope == "sub" else "--resource-group",
    }
    parameters_value = parsed.get("--parameters", "")
    json_parameters = parameters_value.startswith("@")
    if json_parameters:
        required_options.add("--template-file")
    if set(parsed) != required_options or switches != {"--no-pretty-print"}:
        raise PreflightInputError("what-if command options are incomplete or unsupported")
    if parsed["--subscription"] != deployment_target.subscription_id:
        raise PreflightInputError("what-if command uses the wrong subscription")
    if parsed["--result-format"] != "FullResourcePayloads":
        raise PreflightInputError("what-if command requires FullResourcePayloads")
    if parsed["--validation-level"] != "Provider":
        raise PreflightInputError("what-if command requires full Provider validation")
    if parsed["--output"] != "json":
        raise PreflightInputError("what-if command output must be exact json")
    if json_parameters:
        if (
            len(parameters_value) == 1
            or not parameters_value.casefold().endswith(".json")
            or parsed["--template-file"].startswith("-")
        ):
            raise PreflightInputError(
                "what-if JSON parameters require one @file and one template file"
            )
    elif not parameters_value.casefold().endswith(".bicepparam") or "--template-file" in parsed:
        raise PreflightInputError(
            "what-if bicepparam mode requires one direct .bicepparam path without --template-file"
        )
    if deployment_scope == "sub":
        if re.fullmatch(r"[a-z0-9-]+", parsed["--location"]) is None:
            raise PreflightInputError("what-if command location is not canonical")
    else:
        reviewed_resource_groups = {
            scope.rsplit("/", 1)[-1] for scope in deployment_target.resource_group_scopes
        }
        if parsed["--resource-group"] not in reviewed_resource_groups:
            raise PreflightInputError("what-if command resource group is outside deploymentTarget")


def _reject_nonempty_what_if_diagnostics(document: object) -> None:
    stack: list[object] = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key.casefold() in {"diagnostics", "validationdiagnostics"}:
                    if child is None or (isinstance(child, (dict, list, str)) and len(child) == 0):
                        continue
                    raise PreflightInputError(
                        "what-if diagnostics must be absent or empty for the release gate"
                    )
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def _what_if_changes(
    document: object,
) -> tuple[list[object], list[object]]:
    _validate_json_shape(document)
    _reject_nonempty_what_if_diagnostics(document)
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


def _property_child_path(
    parent: str,
    key: str,
    *,
    budget: _PropertyPathBudget,
) -> str | None:
    if (
        not key.isascii()
        or key.lower() != key.casefold()
        or _contains_non_ascii_case_alias(key)
        or _PROPERTY_NAME.fullmatch(key) is None
    ):
        return None
    path = _format_property_path((*_property_path_tokens(parent), key.lower()))
    budget.charge(path)
    return path


def _property_index_path(
    parent: str,
    index: int,
    *,
    budget: _PropertyPathBudget,
) -> str:
    path = _format_property_path((*_property_path_tokens(parent), index))
    budget.charge(path)
    return path


def _json_values_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_values_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _derive_snapshot_delta(
    before: object,
    after: object,
    *,
    root: str = "<resource>",
    budget: _PropertyPathBudget,
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
                child_path = _property_child_path(
                    path,
                    key,
                    budget=budget,
                )
                if child_path is None:
                    budget.charge(path)
                    values.append((path, new_value.get(key), "modify"))
                    continue
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
                                budget=budget,
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
            values.extend(
                _flatten_after(
                    new_value,
                    root=path,
                    budget=budget,
                )
            )
    return values


def _is_meaningful_delta_candidate(path: str, value: object) -> bool:
    canonical = _canonical_property_path(path)
    root = re.split(r"[.\[]", canonical, maxsplit=1)[0]
    return root not in _NON_EFFECTIVE_RESOURCE_METADATA_ROOTS and not (
        canonical == "<resource>" and isinstance(value, (dict, list))
    )


def _walk_delta(
    items: list[dict[str, Any]],
    *,
    budget: _PropertyPathBudget,
    snapshot_index: _SnapshotPairIndex | None = None,
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[dict[str, Any], str]] = [(item, "") for item in reversed(items)]
    while stack:
        item, parent_path = stack.pop()
        own_path = _require_string(
            _get_case_insensitive(item, "path"),
            field_name="delta path",
        )
        canonical_path = _accumulated_property_path(
            parent_path,
            own_path,
            budget=budget,
        )
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
            canonical_path == _RESOURCE_ROOT_PATH
            and property_change_type not in {"delete", "remove", "noeffect"}
            and (not after_supplied or not isinstance(after, dict))
        ):
            raise PreflightInputError("resource-root delta after value must be an object")
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
                    canonical_path,
                    after,
                    property_change_type,
                )
            )
        elif property_change_type == "noeffect":
            _validate_no_effect_entry(
                item,
                canonical_path=canonical_path,
                snapshot_index=snapshot_index,
                budget=budget,
            )
        elif after_supplied:
            if before_supplied:
                values.extend(
                    _derive_snapshot_delta(
                        before,
                        after,
                        root=canonical_path,
                        budget=budget,
                    )
                )
            else:
                values.append(
                    (
                        canonical_path,
                        after,
                        property_change_type,
                    )
                )
                if isinstance(after, (dict, list)):
                    values.extend(
                        _flatten_after(
                            after,
                            root=canonical_path,
                            budget=budget,
                        )
                    )
        if child_items:
            stack.extend((child, canonical_path) for child in reversed(child_items))
    return values


@dataclass(frozen=True, slots=True)
class _SnapshotPairIndex:
    before: dict[str, object]
    after: dict[str, object]


def _build_snapshot_index(
    snapshot: dict[str, Any],
    *,
    budget: _PropertyPathBudget,
) -> dict[str, object]:
    values: dict[str, object] = {}
    stack: list[tuple[object, str]] = [(snapshot, _RESOURCE_ROOT_PATH)]
    while stack:
        item, path = stack.pop()
        budget.charge_lookup(1)
        values[path] = item
        if isinstance(item, dict):
            budget.charge_lookup(len(item))
            lowered = {key.lower(): (key, child) for key, child in item.items()}
            for key, child in reversed(list(lowered.values())):
                child_path = _property_child_path(
                    path,
                    key,
                    budget=budget,
                )
                if child_path is not None:
                    stack.append((child, child_path))
        elif isinstance(item, list):
            budget.charge_lookup(len(item))
            stack.extend(
                (
                    child,
                    _property_index_path(
                        path,
                        index,
                        budget=budget,
                    ),
                )
                for index, child in reversed(list(enumerate(item)))
            )
    return values


def _build_snapshot_pair_index(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    budget: _PropertyPathBudget,
) -> _SnapshotPairIndex:
    return _SnapshotPairIndex(
        before=_build_snapshot_index(before, budget=budget),
        after=_build_snapshot_index(after, budget=budget),
    )


def _snapshot_pair_values(
    snapshot_index: _SnapshotPairIndex,
    canonical_path: str,
    *,
    budget: _PropertyPathBudget,
) -> tuple[bool, object, bool, object]:
    budget.charge_lookup(len(_property_path_tokens(canonical_path)) + 2)
    return (
        canonical_path in snapshot_index.before,
        snapshot_index.before.get(canonical_path),
        canonical_path in snapshot_index.after,
        snapshot_index.after.get(canonical_path),
    )


def _validate_no_effect_entry(
    item: dict[str, Any],
    *,
    canonical_path: str,
    snapshot_index: _SnapshotPairIndex | None,
    budget: _PropertyPathBudget,
) -> None:
    if not _has_case_insensitive(item, "before") or not _has_case_insensitive(
        item,
        "after",
    ):
        raise PreflightInputError("NoEffect requires before and after evidence")
    before = _get_case_insensitive(item, "before")
    after = _get_case_insensitive(item, "after")
    if not _json_values_equal(before, after):
        raise PreflightInputError("NoEffect before and after values conflict")
    if snapshot_index is None:
        raise PreflightInputError("NoEffect requires complete resource snapshots")
    before_exists, root_before, after_exists, root_after = _snapshot_pair_values(
        snapshot_index,
        canonical_path,
        budget=budget,
    )
    if (
        not before_exists
        or not after_exists
        or not _json_values_equal(root_before, root_after)
        or not _json_values_equal(before, root_before)
        or not _json_values_equal(after, root_after)
    ):
        raise PreflightInputError("NoEffect does not reconcile with resource snapshots")


def _validate_resource_snapshot(
    snapshot: dict[str, Any],
    *,
    resource_id: str,
    field_name: str,
    deployment_target: DeploymentTarget | None = None,
) -> None:
    raw_snapshot_id = _require_string(
        _get_case_insensitive(snapshot, "id"),
        field_name=f"{field_name} id",
    )
    snapshot_id = (
        _canonical_scope(raw_snapshot_id)
        if deployment_target is None
        else _validate_deployment_resource_id(
            raw_snapshot_id,
            deployment_target=deployment_target,
            field_name=f"{field_name} id",
        )
    )
    canonical_resource_id = _canonical_scope(resource_id)
    if snapshot_id != canonical_resource_id:
        raise PreflightInputError(f"{field_name} id does not match resourceId")
    snapshot_name = _require_string(
        _get_case_insensitive(snapshot, "name"),
        field_name=f"{field_name} name",
    )
    if (
        not snapshot_name.isascii()
        or snapshot_name.lower() != canonical_resource_id.rsplit("/", 1)[-1]
    ):
        raise PreflightInputError(f"{field_name} name does not match resourceId")
    snapshot_type = _require_string(
        _get_case_insensitive(snapshot, "type"),
        field_name=f"{field_name} type",
    )
    if not snapshot_type.isascii() or snapshot_type.lower() != _resource_type(resource_id):
        raise PreflightInputError(f"{field_name} type does not match resourceId")
    _mapping(
        _get_case_insensitive(snapshot, "properties"),
        field_name=f"{field_name} properties",
    )


def _validate_no_change(
    resource_id: str,
    change: dict[str, Any],
    *,
    budget: _PropertyPathBudget,
) -> None:
    if not _has_case_insensitive(
        change,
        "before",
    ) or not _has_case_insensitive(change, "after"):
        raise PreflightInputError("NoChange requires complete before and after snapshots")
    before = _get_case_insensitive(change, "before")
    after = _get_case_insensitive(change, "after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise PreflightInputError("NoChange before and after snapshots must be objects")
    _validate_resource_snapshot(
        before,
        resource_id=resource_id,
        field_name="NoChange before snapshot",
    )
    _validate_resource_snapshot(
        after,
        resource_id=resource_id,
        field_name="NoChange after snapshot",
    )
    if not _json_values_equal(before, after):
        raise PreflightInputError("NoChange before and after snapshots conflict")
    snapshot_index = _build_snapshot_pair_index(
        before,
        after,
        budget=budget,
    )
    delta = _delta_entries(change)
    stack: list[tuple[dict[str, Any], str]] = [(item, "") for item in reversed(delta)]
    seen_paths: set[str] = set()
    while stack:
        item, parent_path = stack.pop()
        own_path = _require_string(
            _get_case_insensitive(item, "path"),
            field_name="delta path",
        )
        canonical_path = _accumulated_property_path(
            parent_path,
            own_path,
            budget=budget,
        )
        if canonical_path in seen_paths:
            raise PreflightInputError("NoChange contains duplicate delta paths")
        seen_paths.add(canonical_path)
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
        if property_change_type not in {"array", "noeffect"}:
            raise PreflightInputError("NoChange contains a non-NoEffect property delta")
        if property_change_type == "noeffect":
            _validate_no_effect_entry(
                item,
                canonical_path=canonical_path,
                snapshot_index=snapshot_index,
                budget=budget,
            )
        before_supplied = _has_case_insensitive(item, "before")
        after_supplied = _has_case_insensitive(item, "after")
        item_after = _get_case_insensitive(item, "after")
        if (
            canonical_path == _RESOURCE_ROOT_PATH
            and property_change_type == "array"
            and (not after_supplied or not isinstance(item_after, dict))
        ):
            raise PreflightInputError("resource-root delta after value must be an object")
        if property_change_type == "array" and not after_supplied and children is None:
            raise PreflightInputError("delta item lacks inspectable after value or children")
        if property_change_type == "array" and (
            before_supplied != after_supplied
            or (
                before_supplied
                and not _json_values_equal(
                    _get_case_insensitive(item, "before"),
                    _get_case_insensitive(item, "after"),
                )
            )
        ):
            raise PreflightInputError("NoChange delta conflicts with its snapshots")
        before_exists, snapshot_before, after_exists, snapshot_after = _snapshot_pair_values(
            snapshot_index,
            canonical_path,
            budget=budget,
        )
        if (
            not before_exists
            or not after_exists
            or not _json_values_equal(
                snapshot_before,
                snapshot_after,
            )
        ):
            raise PreflightInputError("NoChange delta path is absent or inconsistent in snapshots")
        if (
            property_change_type == "array"
            and before_supplied
            and (
                not _json_values_equal(
                    _get_case_insensitive(item, "before"),
                    snapshot_before,
                )
                or not _json_values_equal(
                    _get_case_insensitive(item, "after"),
                    snapshot_after,
                )
            )
        ):
            raise PreflightInputError("NoChange delta conflicts with root snapshots")
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
            stack.extend((child, canonical_path) for child in reversed(child_items))
    _canonical_scope(resource_id)


def _flatten_after(
    value: object,
    *,
    root: str = "<resource>",
    budget: _PropertyPathBudget,
) -> list[tuple[str, object, str]]:
    values: list[tuple[str, object, str]] = []
    stack: list[tuple[object, str]] = [(value, root)]
    while stack:
        item, path = stack.pop()
        if isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                child_path = _property_child_path(
                    path,
                    key,
                    budget=budget,
                )
                if child_path is not None:
                    stack.append((child, child_path))
        elif isinstance(item, list):
            stack.extend(
                (
                    child,
                    _property_index_path(
                        path,
                        index,
                        budget=budget,
                    ),
                )
                for index, child in reversed(list(enumerate(item)))
            )
        else:
            values.append((path, item, "set"))
    return values


def _unsafe_property_violations(
    resource_id: str,
    change: dict[str, Any],
    *,
    budget: _PropertyPathBudget,
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
    before_payload_supplied = _has_case_insensitive(change, "before")
    after_payload_supplied = _has_case_insensitive(change, "after")
    before_payload = _get_case_insensitive(change, "before")
    after_payload = _get_case_insensitive(change, "after")
    snapshot_delta_candidates: list[tuple[str, object, str]] = []
    snapshot_index: _SnapshotPairIndex | None = None
    complete_snapshots = (
        change_type == "modify" and before_payload_supplied and after_payload_supplied
    )
    if complete_snapshots:
        if not isinstance(before_payload, dict) or not isinstance(
            after_payload,
            dict,
        ):
            raise PreflightInputError("Modify before and after snapshots must both be objects")
        _validate_resource_snapshot(
            before_payload,
            resource_id=resource_id,
            field_name="Modify before snapshot",
        )
        _validate_resource_snapshot(
            after_payload,
            resource_id=resource_id,
            field_name="Modify after snapshot",
        )
        snapshot_index = _build_snapshot_pair_index(
            before_payload,
            after_payload,
            budget=budget,
        )
        snapshot_delta_candidates = _derive_snapshot_delta(
            before_payload,
            after_payload,
            budget=budget,
        )
    declared_delta_candidates = (
        _walk_delta(
            delta,
            budget=budget,
            snapshot_index=snapshot_index,
        )
        if delta
        else []
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
        candidates.extend(
            _flatten_after(
                after_payload,
                budget=budget,
            )
        )
    if change_type != "delete" and any(
        property_change_type in {"delete", "remove"}
        and _canonical_property_path(raw_path) == _RESOURCE_ROOT_PATH
        for raw_path, _, property_change_type in delta_candidates
    ):
        violations.append(
            PreflightViolation(
                code="delete",
                subject=resource_id,
                detail=(f"resource-root deletion is never permitted under {change_type}"),
            )
        )
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
            return _finalize_violations(violations)
        return (
            PreflightViolation(
                code="uninspectable-change",
                subject=resource_id,
                detail=("change lacks FullResourcePayloads or inspectable delta"),
            ),
        )

    def delta_touches(target: str) -> bool:
        return any(
            _property_path_contains(
                _canonical_property_path(raw_path),
                target,
            )
            for raw_path, _, _ in delta_candidates
        )

    def has_exact_evidence(target: str) -> bool:
        return any(_canonical_property_path(raw_path) == target for raw_path, _, _ in candidates)

    def ancestor_removed(target: str) -> bool:
        return any(
            property_change_type in {"delete", "remove"}
            and (path := _canonical_property_path(raw_path)) != target
            and _property_path_contains(path, target)
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
            _property_path_contains(
                (path := _canonical_property_path(raw_path)),
                "properties.networkacls",
            )
            or _property_path_contains(
                "properties.networkacls",
                path,
            )
            for raw_path, _, _ in delta_candidates
        )
        if network_acl_touched:
            protected_parent_removed = any(
                _property_path_contains(
                    (path := _canonical_property_path(raw_path)),
                    "properties.networkacls",
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
            if _property_path_contains(
                _canonical_property_path(raw_path),
                target,
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
    return _finalize_violations(violations)


def evaluate_what_if(
    document: object,
    *,
    allowed_change_ids: frozenset[str] = frozenset(),
    require_attestation: bool = False,
    expected_collection_run_id: str | None = None,
    expected_deployment_execution_id: str | None = None,
    attestation_manifest_digest: str | None = None,
    deployment_digest: str | None = None,
    template_digest: str | None = None,
    parameters_digest: str | None = None,
    now: datetime | None = None,
) -> tuple[PreflightViolation, ...]:
    _validate_json_shape(document)
    normalized_allowlist, allow_change_ids_digest = _allow_change_binding(allowed_change_ids)
    deployment_target: DeploymentTarget | None = None
    if require_attestation:
        if (
            expected_collection_run_id is None
            or expected_deployment_execution_id is None
            or attestation_manifest_digest is None
            or deployment_digest is None
            or template_digest is None
            or parameters_digest is None
        ):
            raise PreflightInputError("reviewed what-if attestation inputs are required")
        root = _mapping(
            document,
            field_name="attested what-if artifact",
        )
        if {key.casefold() for key in root} != {
            "attestation",
            "manifest",
            "whatif",
            "whatifrequest",
        }:
            raise PreflightInputError("attested what-if artifact has an invalid envelope")
        what_if_document = _get_case_insensitive(root, "whatIf")
        what_if_request = _get_case_insensitive(root, "whatIfRequest")
        manifest = _parse_attestation_manifest(
            _get_case_insensitive(root, "manifest"),
            expected_collection_run_id=expected_collection_run_id,
            expected_deployment_execution_id=expected_deployment_execution_id,
            expected_manifest_digest=attestation_manifest_digest,
            now=_current_utc(now),
        )
        deployment_target = manifest.deployment_target
        _validate_what_if_request(
            what_if_request,
            deployment_target=deployment_target,
        )
        for allowed_change_id in normalized_allowlist:
            _validate_deployment_resource_id(
                allowed_change_id,
                deployment_target=deployment_target,
                field_name="allow-change resource ID",
            )
        expected_bindings = {
            "allowChangeIdsDigest": allow_change_ids_digest,
            "deploymentDigest": _canonical_sha256_digest(
                deployment_digest,
                field_name="reviewed deployment digest",
            ),
            "parametersDigest": _canonical_sha256_digest(
                parameters_digest,
                field_name="reviewed parameters digest",
            ),
            "templateDigest": _canonical_sha256_digest(
                template_digest,
                field_name="reviewed template digest",
            ),
            "whatIfDigest": _canonical_json_digest(what_if_document),
            "whatIfRequestDigest": _canonical_json_digest(what_if_request),
        }
        for binding_name, expected_digest in expected_bindings.items():
            if manifest.bindings[binding_name] != expected_digest:
                raise PreflightInputError(
                    f"manifest {binding_name} does not match the reviewed input"
                )
        _validate_artifact_attestation(
            _get_case_insensitive(root, "attestation"),
            artifact_kind="what-if",
            manifest=manifest,
            expected_binding_names=frozenset(expected_bindings),
        )
        document = what_if_document
    violations: list[PreflightViolation] = []
    path_budget = _PropertyPathBudget()
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
        if deployment_target is None:
            _canonical_scope(resource_id)
        else:
            _validate_deployment_resource_id(
                resource_id,
                deployment_target=deployment_target,
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
        canonical_resource_id = (
            _canonical_scope(resource_id)
            if deployment_target is None
            else _validate_deployment_resource_id(
                resource_id,
                deployment_target=deployment_target,
                field_name="resourceId",
            )
        )
        _validate_what_if_snapshot_ids(
            change,
            canonical_resource_id=canonical_resource_id,
            deployment_target=deployment_target,
        )
        change_type = _normalized(
            _require_string(
                _get_case_insensitive(change, "changeType"),
                field_name="changeType",
                maximum_length=64,
            )
        )
        if change_type == "nochange":
            _validate_no_change(
                resource_id,
                change,
                budget=path_budget,
            )
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
        if _is_unsupported_authorization_or_imperative_type(_resource_type(canonical_resource_id)):
            violations.append(
                PreflightViolation(
                    code="authorization-change-unsupported",
                    subject=resource_id,
                    detail=(
                        "planned authorization-affecting or imperative mutations require "
                        "a future separation-aware evaluator"
                    ),
                )
            )
            continue
        if canonical_resource_id not in normalized_allowlist:
            violations.append(
                PreflightViolation(
                    code="unapproved-change",
                    subject=resource_id,
                    detail=f"{change_type} is absent from the reviewed allowlist",
                )
            )
        violations.extend(
            _unsafe_property_violations(
                resource_id,
                change,
                budget=path_budget,
            )
        )
    return _finalize_violations(violations)


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


def _effective_rule_role_matchers(
    rule: SeparationRule,
) -> frozenset[str]:
    matchers = {
        (
            f"id:{_ROLE_NAME_TO_ID[role_name]}"
            if role_name in _ROLE_NAME_TO_ID
            else f"name:{role_name}"
        )
        for role_name in rule.forbidden_role_names
    }
    matchers.update(f"id:{role_id}" for role_id in rule.forbidden_role_ids)
    return frozenset(matchers)


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
    rule_keys: set[
        tuple[
            str,
            frozenset[str],
            tuple[str, ...],
        ]
    ] = set()
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
            rule = SeparationRule(
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
                forbidden_scope_prefixes=_minimal_scope_prefixes(
                    [
                        _canonical_scope(
                            _require_string(
                                prefix,
                                field_name="forbidden scope prefix",
                            )
                        )
                        for prefix in scope_prefixes
                    ]
                ),
            )
            rule_key = (
                rule.principal_id,
                _effective_rule_role_matchers(rule),
                rule.forbidden_scope_prefixes,
            )
            if rule_key in rule_keys:
                raise PreflightInputError("separationRules contains an equivalent duplicate rule")
            rule_keys.add(rule_key)
            rules.append(rule)
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
    if not value.isascii() or not unquote(value).isascii():
        raise PreflightInputError(f"{field_name} contains non-ASCII characters")
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise PreflightInputError(f"{field_name} is not a valid URL") from exc


def _parse_exact_query(
    parts: SplitResult,
    *,
    field_name: str,
) -> dict[str, list[str]]:
    try:
        pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError as exc:
        raise PreflightInputError(f"{field_name} query is malformed") from exc
    query: dict[str, list[str]] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded_key = key.casefold()
        if not key.isascii() or key != folded_key:
            raise PreflightInputError(f"{field_name} query keys must use exact lowercase ASCII")
        if folded_key in seen:
            raise PreflightInputError(f"{field_name} query contains a duplicate decoded key")
        if not value.isascii():
            raise PreflightInputError(f"{field_name} query values must use ASCII")
        seen.add(folded_key)
        query[key] = [value]
    return query


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
    query = _parse_exact_query(parts, field_name=field_name)
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
    if any(
        key.casefold() in {"skiptoken", "$skiptoken"} and token is not None
        for key, token in body.items()
    ):
        raise PreflightInputError("Resource Graph hierarchy evidence is paginated or incomplete")
    result_truncated = _get_case_insensitive(
        body,
        "resultTruncated",
    )
    if not (
        result_truncated is False or (type(result_truncated) is str and result_truncated == "false")
    ):
        raise PreflightInputError(
            "Resource Graph hierarchy result must be explicitly non-truncated"
        )
    rows = _sequence(
        _get_case_insensitive(body, "data"),
        field_name="Resource Graph hierarchy data",
        maximum_items=2,
    )
    count = _get_case_insensitive(body, "count")
    total_records = _get_case_insensitive(body, "totalRecords")
    if (
        type(count) is not int
        or type(total_records) is not int
        or count != total_records
        or count != len(rows)
        or count != 1
    ):
        raise PreflightInputError(
            "Resource Graph hierarchy count and totalRecords must match exactly one result row"
        )
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
        query = _parse_exact_query(
            parts,
            field_name="Graph membership requestUrl",
        )
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
        query = _parse_exact_query(
            parts,
            field_name="ARM role-assignment requestUrl",
        )
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


def _validate_principal_id_filter(
    value: object,
    *,
    assigned_principal_id: str,
    field_name: str,
) -> str:
    filter_value = _require_string(
        value,
        field_name=field_name,
    )
    match = re.fullmatch(
        rf"principalId\s+eq\s+'({_GUID_PATTERN})'",
        filter_value,
        re.IGNORECASE,
    )
    if match is None:
        raise PreflightInputError(f"{field_name} must use principalId eq assigned-object-id")
    if match.group(1).casefold() != assigned_principal_id:
        raise PreflightInputError(f"{field_name} uses a different assigned principal")
    return filter_value


def _validate_descendant_arm_urls(
    request_urls: tuple[str, ...],
    *,
    target: RbacCollection,
    assigned_principal_id: str,
) -> None:
    expected_path = target.subscription_scope + "/providers/microsoft.authorization/roleassignments"
    for index, request_url in enumerate(request_urls):
        parts = _split_url(
            request_url,
            field_name="ARM descendant role-assignment requestUrl",
        )
        if unquote(parts.path).casefold() != expected_path:
            raise PreflightInputError(
                "ARM descendant role-assignment requestUrl uses the wrong subscription"
            )
        query = _parse_exact_query(
            parts,
            field_name="ARM descendant role-assignment requestUrl",
        )
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
            raise PreflightInputError("ARM descendant role-assignment requestUrl is not canonical")
        _validate_principal_id_filter(
            query["$filter"][0],
            assigned_principal_id=assigned_principal_id,
            field_name="ARM descendant requestUrl filter",
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
    include_descendants: bool = False,
) -> None:
    arguments = [
        _require_exact_cli_token(
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
    if any(not argument.isascii() for argument in arguments):
        raise PreflightInputError("Azure CLI role collection arguments must use ASCII")
    if any(argument.startswith("--") and "=" in argument for argument in arguments):
        raise PreflightInputError("Azure CLI role collection does not allow equals-form arguments")
    switch_flags = {"--include-groups", "--only-show-errors"}
    if include_descendants:
        switch_flags.add("--all")
    else:
        switch_flags.add("--include-inherited")
    expected_values = {
        "--subscription": target.subscription_id,
        "--assignee-object-id": effective_principal_id,
        "--output": "json",
        "--fill-principal-name": "false",
        "--fill-role-definition-name": "true",
    }
    if not include_descendants:
        expected_values["--scope"] = target.resource_group_scope
    required_flags = {
        "--assignee-object-id",
        "--include-groups",
        "--output",
        "--subscription",
    }
    if include_descendants:
        required_flags.add("--all")
    else:
        required_flags.update({"--include-inherited", "--scope"})
    seen: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
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


def _scope_is_ancestor_or_target(
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


def _scope_is_within_reviewed_boundary(
    scope: str,
    *,
    collection: RbacCollection,
) -> bool:
    return (
        scope == "/"
        or scope in collection.management_group_ancestry
        or _scope_contains(collection.subscription_scope, scope)
    )


def _parse_ancestor_role_assignments(
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
        if not _scope_is_ancestor_or_target(
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


def _parse_descendant_role_assignments(
    value: object,
    *,
    effective_principal_id: str,
    security_group_ids: frozenset[str],
    collection: RbacCollection,
) -> list[RbacAssignment]:
    evidence = _mapping(
        value,
        field_name="subscription-descendant role-assignment evidence",
    )
    raw_method = _require_string(
        _get_case_insensitive(evidence, "method"),
        field_name="descendant role-assignment collection method",
        maximum_length=64,
    )
    if not raw_method.isascii():
        raise PreflightInputError("descendant role-assignment collection method must use ASCII")
    method = _normalized(raw_method)
    assignments: list[RbacAssignment] = []
    if method == "arm":
        required_principal_ids = {
            effective_principal_id,
            *security_group_ids,
        }
        collected_principal_ids: set[str] = set()
        for raw_collection in _sequence(
            _get_case_insensitive(evidence, "collections"),
            field_name="ARM descendant role-assignment collections",
            maximum_items=MAX_ASSIGNMENTS,
        ):
            descendant_collection = _mapping(
                raw_collection,
                field_name="ARM descendant role-assignment collection",
            )
            assigned_principal_id = _canonical_guid(
                _get_case_insensitive(
                    descendant_collection,
                    "assignedToPrincipalId",
                ),
                field_name="descendant assignedToPrincipalId",
            )
            if (
                assigned_principal_id not in required_principal_ids
                or assigned_principal_id in collected_principal_ids
            ):
                raise PreflightInputError(
                    "ARM descendant collections do not exactly cover the "
                    "effective principal and security groups"
                )
            collected_principal_ids.add(assigned_principal_id)
            api_version = _require_string(
                _get_case_insensitive(
                    descendant_collection,
                    "apiVersion",
                ),
                field_name="ARM descendant apiVersion",
                maximum_length=64,
            )
            if api_version != _ARM_ROLE_ASSIGNMENTS_API_VERSION:
                raise PreflightInputError("ARM descendant evidence requires apiVersion 2022-04-01")
            scope = _canonical_scope(
                _require_string(
                    _get_case_insensitive(
                        descendant_collection,
                        "scope",
                    ),
                    field_name="ARM descendant request scope",
                )
            )
            if scope != collection.subscription_scope:
                raise PreflightInputError("ARM descendant evidence uses the wrong subscription")
            _validate_principal_id_filter(
                _get_case_insensitive(
                    descendant_collection,
                    "filter",
                ),
                assigned_principal_id=assigned_principal_id,
                field_name="ARM descendant role-assignment filter",
            )
            raw_assignments, request_urls = _paged_values(
                _get_case_insensitive(
                    descendant_collection,
                    "pages",
                ),
                field_name="ARM descendant role-assignment evidence",
                next_link_field="nextLink",
                maximum_items=MAX_ASSIGNMENTS,
                allowed_host="management.azure.com",
            )
            _validate_descendant_arm_urls(
                request_urls,
                target=collection,
                assigned_principal_id=assigned_principal_id,
            )
            for raw_assignment in raw_assignments:
                assignment = _parse_arm_role_assignment(
                    raw_assignment,
                    effective_principal_id=effective_principal_id,
                )
                if assignment.principal_id != assigned_principal_id:
                    raise PreflightInputError(
                        "ARM descendant assignment does not match its principal collection"
                    )
                if assigned_principal_id == effective_principal_id:
                    if assignment.principal_type != "serviceprincipal":
                        raise PreflightInputError(
                            "effective-principal descendant assignment must be ServicePrincipal"
                        )
                elif (
                    assigned_principal_id not in security_group_ids
                    or assignment.principal_type != "group"
                ):
                    raise PreflightInputError(
                        "group descendant assignment disagrees with Graph membership"
                    )
                assignments.append(assignment)
        if collected_principal_ids != required_principal_ids:
            raise PreflightInputError(
                "ARM descendant collections do not exactly cover the "
                "effective principal and security groups"
            )
    elif method == "azure-cli":
        exit_code = _get_case_insensitive(evidence, "exitCode")
        if type(exit_code) is not int or exit_code != 0:
            raise PreflightInputError("Azure CLI descendant role collection did not succeed")
        _validate_cli_arguments(
            _get_case_insensitive(evidence, "arguments"),
            target=collection,
            effective_principal_id=effective_principal_id,
            include_descendants=True,
        )
        for raw_assignment in _sequence(
            _get_case_insensitive(evidence, "value"),
            field_name="Azure CLI descendant role assignments",
            maximum_items=MAX_ASSIGNMENTS,
        ):
            assignment = _parse_rbac_assignment(
                raw_assignment,
                field_name="Azure CLI descendant role assignment",
            )
            if (
                assignment.effective_principal_id_supplied
                and assignment.effective_principal_id != effective_principal_id
            ):
                raise PreflightInputError(
                    "Azure CLI descendant assignment effectivePrincipalId "
                    "disagrees with its collection"
                )
            assignments.append(
                replace(
                    assignment,
                    effective_principal_id=effective_principal_id,
                    effective_principal_id_supplied=True,
                )
            )
    else:
        raise PreflightInputError(
            "descendant role-assignment collection method must be arm or azure-cli"
        )

    unique_keys: set[
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
    for assignment in assignments:
        if not assignment.role_definition_id:
            raise PreflightInputError("descendant role assignment requires roleDefinitionId")
        if not assignment.principal_type_supplied:
            raise PreflightInputError("descendant role assignment requires principalType")
        _validate_effective_assignment_principal(
            assignment,
            effective_principal_id=effective_principal_id,
            security_group_ids=security_group_ids,
        )
        if not _scope_is_within_reviewed_boundary(
            assignment.scope,
            collection=collection,
        ):
            raise PreflightInputError("descendant role assignment is outside the reviewed boundary")
        key = _assignment_key(assignment)
        if key in unique_keys:
            raise PreflightInputError(
                "descendant role-assignment evidence contains a duplicate assignment"
            )
        unique_keys.add(key)
    return assignments


def _derive_guarded_role_assignments(
    document: object,
    *,
    policy: RbacPolicy,
    policy_document: object,
    require_attestation: bool,
    expected_collection_run_id: str | None,
    expected_deployment_execution_id: str | None,
    attestation_manifest_digest: str | None,
    now: datetime | None,
) -> tuple[list[RbacAssignment], RbacCollection]:
    root = _mapping(document, field_name="guarded RBAC evidence")
    manifest: AttestationManifest | None = None
    if require_attestation:
        if (
            expected_collection_run_id is None
            or expected_deployment_execution_id is None
            or attestation_manifest_digest is None
        ):
            raise PreflightInputError(
                "reviewed RBAC collectionRunId, deploymentExecutionId, "
                "and manifest digest are required"
            )
        if {key.casefold() for key in root} != {
            "attestation",
            "hierarchy",
            "manifest",
            "principals",
            "target",
        }:
            raise PreflightInputError("attested RBAC artifact has an invalid envelope")
        manifest = _parse_attestation_manifest(
            _get_case_insensitive(root, "manifest"),
            expected_collection_run_id=expected_collection_run_id,
            expected_deployment_execution_id=expected_deployment_execution_id,
            expected_manifest_digest=attestation_manifest_digest,
            now=_current_utc(now),
        )
        rbac_payload = {
            key: item
            for key, item in root.items()
            if key.casefold() not in {"attestation", "manifest"}
        }
        expected_bindings = {
            "policyDigest": _canonical_json_digest(policy_document),
            "rbacEvidenceDigest": _canonical_json_digest(rbac_payload),
        }
        for binding_name, expected_digest in expected_bindings.items():
            if manifest.bindings[binding_name] != expected_digest:
                raise PreflightInputError(
                    f"manifest {binding_name} does not match the reviewed input"
                )
        _validate_artifact_attestation(
            _get_case_insensitive(root, "attestation"),
            artifact_kind="rbac",
            manifest=manifest,
            expected_binding_names=frozenset(expected_bindings),
        )
    if any(
        _has_case_insensitive(root, legacy_name)
        for legacy_name in ("value", "queries", "collection")
    ):
        raise PreflightInputError(
            "guarded RBAC evidence requires raw target, hierarchy, and principal artifacts"
        )
    target = _parse_evidence_target(_get_case_insensitive(root, "target"))
    if manifest is not None:
        _validate_rbac_deployment_target(
            target,
            deployment_target=manifest.deployment_target,
        )
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
        role_assignment_evidence = _mapping(
            _get_case_insensitive(principal, "roleAssignments"),
            field_name="principal roleAssignments",
        )
        principal_assignments = [
            *_parse_ancestor_role_assignments(
                _get_case_insensitive(
                    role_assignment_evidence,
                    "ancestors",
                ),
                effective_principal_id=effective_principal_id,
                security_group_ids=security_group_ids,
                collection=target,
            ),
            *_parse_descendant_role_assignments(
                _get_case_insensitive(
                    role_assignment_evidence,
                    "descendants",
                ),
                effective_principal_id=effective_principal_id,
                security_group_ids=security_group_ids,
                collection=target,
            ),
        ]
        for assignment in principal_assignments:
            key = _assignment_key(assignment)
            if key in unique_assignment_keys:
                continue
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
    require_attestation: bool = False,
    expected_collection_run_id: str | None = None,
    expected_deployment_execution_id: str | None = None,
    attestation_manifest_digest: str | None = None,
    now: datetime | None = None,
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
            if not _scope_is_within_reviewed_boundary(
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
            policy_document=policy_document,
            require_attestation=(require_attestation or require_separation_rules),
            expected_collection_run_id=expected_collection_run_id,
            expected_deployment_execution_id=expected_deployment_execution_id,
            attestation_manifest_digest=attestation_manifest_digest,
            now=now,
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
    return _finalize_violations(violations)


def render_preflight_json(
    *,
    kind: PreflightKind,
    violations: tuple[PreflightViolation, ...],
) -> str:
    bounded_violations = _finalize_violations(violations)
    ordered_violations = sorted(
        bounded_violations,
        key=lambda item: (item.code, item.subject.casefold(), item.detail),
    )
    rendered = (
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
    if len(rendered.encode("utf-8")) > MAX_RENDER_BYTES:
        raise PreflightInputError(f"rendered output exceeds {MAX_RENDER_BYTES} bytes")
    return rendered


def render_preflight_text(
    *,
    kind: PreflightKind,
    violations: tuple[PreflightViolation, ...],
) -> str:
    bounded_violations = _finalize_violations(violations)
    ordered_violations = sorted(
        bounded_violations,
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
    rendered = "\n".join(lines) + "\n"
    if len(rendered.encode("utf-8")) > MAX_RENDER_BYTES:
        raise PreflightInputError(f"rendered output exceeds {MAX_RENDER_BYTES} bytes")
    return rendered


def _escaped_text(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _is_link_or_reparse_point(path: Path, path_stat: os.stat_result) -> bool:
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(path_stat, "st_file_attributes", 0)
    is_junction = getattr(os.path, "isjunction", None)
    return (
        stat.S_ISLNK(path_stat.st_mode)
        or bool(file_attributes & reparse_attribute)
        or (is_junction is not None and is_junction(path))
    )


def _validated_directory_without_links(path: Path, *, field_name: str) -> Path:
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute_path.anchor)
    try:
        current_stat = os.lstat(current)
    except OSError as exc:
        raise PreflightInputError(f"{field_name} anchor is unavailable") from exc
    if _is_link_or_reparse_point(current, current_stat):
        raise PreflightInputError(
            f"{field_name} must not contain a symlink, junction, or reparse point"
        )
    if not stat.S_ISDIR(current_stat.st_mode):
        raise PreflightInputError(f"{field_name} anchor must be a directory")
    components = absolute_path.parts[1:]
    for component in components:
        current /= component
        try:
            current_stat = os.lstat(current)
        except OSError as exc:
            raise PreflightInputError(f"{field_name} component is unavailable") from exc
        if _is_link_or_reparse_point(current, current_stat):
            raise PreflightInputError(
                f"{field_name} must not contain a symlink, junction, or reparse point"
            )
        if not stat.S_ISDIR(current_stat.st_mode):
            raise PreflightInputError(f"{field_name} components must be directories")
    return absolute_path


def _validated_release_ledger_paths(
    ledger_path: Path,
    trusted_root: Path,
) -> tuple[Path, Path]:
    root_candidate = Path(os.path.abspath(os.fspath(trusted_root)))
    ledger_candidate = Path(os.path.abspath(os.fspath(ledger_path)))
    root_key = os.path.normcase(os.fspath(root_candidate))
    ledger_key = os.path.normcase(os.fspath(ledger_candidate))
    try:
        common = os.path.commonpath((root_key, ledger_key))
    except ValueError as exc:
        raise PreflightInputError(
            "release ledger is outside the trusted release-ledger root"
        ) from exc
    if common != root_key or ledger_key == root_key:
        raise PreflightInputError("release ledger must be beneath the trusted release-ledger root")
    root = _validated_directory_without_links(
        root_candidate,
        field_name="trusted release-ledger root",
    )
    ledger = _validated_directory_without_links(
        ledger_candidate,
        field_name="release ledger",
    )
    return root, ledger


def _secure_directory_handles_supported() -> bool:
    return (
        os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
    )


def _normalized_windows_handle_path(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return os.path.normcase(os.path.abspath(path))


def _windows_handle_details(handle: int) -> tuple[str, bool]:
    import ctypes
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    information = FileAttributeTagInfo()
    if not kernel32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandleEx failed")
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle),
        buffer,
        len(buffer),
        0,
    )
    if length == 0 or length >= len(buffer):
        raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
    return (
        _normalized_windows_handle_path(buffer.value),
        bool(information.FileAttributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),
    )


def _open_windows_directory_handle(path: Path) -> tuple[int, str]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        os.fspath(path),
        0,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    handle_value = int(handle)
    try:
        final_path, is_reparse = _windows_handle_details(handle_value)
        if is_reparse:
            raise PreflightInputError("release ledger directory handle resolves to a reparse point")
        expected_path = os.path.normcase(os.path.abspath(os.fspath(path)))
        if final_path != expected_path:
            raise PreflightInputError("release ledger directory escaped the trusted path")
        return handle_value, final_path
    except BaseException:
        kernel32.CloseHandle(wintypes.HANDLE(handle_value))
        raise


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        raise OSError(ctypes.get_last_error(), "CloseHandle failed")


def _validate_windows_file_descriptor(
    file_descriptor: int,
    *,
    expected_directory: str,
    name: str,
) -> None:
    import msvcrt

    handle = msvcrt.get_osfhandle(file_descriptor)
    final_path, is_reparse = _windows_handle_details(handle)
    if is_reparse:
        raise PreflightInputError("release ledger record handle resolves to a reparse point")
    expected_path = os.path.normcase(os.path.abspath(os.path.join(expected_directory, name)))
    if final_path != expected_path:
        raise PreflightInputError("release ledger record escaped the securely opened directory")


class _SecureLedgerDirectory:
    def __init__(self, ledger_path: Path, trusted_root: Path) -> None:
        self._requested_ledger_path = ledger_path
        self._requested_trusted_root = trusted_root
        self._ledger_path: Path | None = None
        self._trusted_root: Path | None = None
        self._directory_fd: int | None = None
        self._windows_directory_handle: int | None = None
        self._windows_final_path: str | None = None

    def __enter__(self) -> _SecureLedgerDirectory:
        trusted_root, ledger_path = _validated_release_ledger_paths(
            self._requested_ledger_path,
            self._requested_trusted_root,
        )
        self._trusted_root = trusted_root
        self._ledger_path = ledger_path
        if _secure_directory_handles_supported():
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            current_fd = os.open(trusted_root.anchor, flags)
            try:
                relative_components = [
                    *trusted_root.parts[1:],
                    *Path(os.path.relpath(ledger_path, trusted_root)).parts,
                ]
                for component in relative_components:
                    next_fd = os.open(
                        component,
                        flags,
                        dir_fd=current_fd,
                    )
                    os.close(current_fd)
                    current_fd = next_fd
            except BaseException:
                os.close(current_fd)
                raise
            self._directory_fd = current_fd
        elif os.name == "nt":
            (
                self._windows_directory_handle,
                self._windows_final_path,
            ) = _open_windows_directory_handle(ledger_path)
        else:
            raise PreflightInputError("secure release-ledger directory operations are unsupported")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        if self._directory_fd is not None:
            os.close(self._directory_fd)
            self._directory_fd = None
        if self._windows_directory_handle is not None:
            _close_windows_handle(self._windows_directory_handle)
            self._windows_directory_handle = None
            self._windows_final_path = None

    def _fallback_file_path(self, name: str, *, require_existing: bool) -> Path:
        trusted_root, ledger_path = _validated_release_ledger_paths(
            self._requested_ledger_path,
            self._requested_trusted_root,
        )
        self._trusted_root = trusted_root
        self._ledger_path = ledger_path
        file_path = ledger_path / name
        if require_existing:
            try:
                file_stat = os.lstat(file_path)
            except OSError as exc:
                raise PreflightInputError("release ledger record is unavailable") from exc
            if _is_link_or_reparse_point(file_path, file_stat):
                raise PreflightInputError(
                    "release ledger record must not be a symlink or reparse point"
                )
            if not stat.S_ISREG(file_stat.st_mode):
                raise PreflightInputError("release ledger record must be a regular file")
        return file_path

    def _verify_file_descriptor(self, file_descriptor: int, name: str) -> None:
        if os.name != "nt":
            return
        if self._windows_final_path is None:
            raise PreflightInputError("release ledger Windows directory handle is unavailable")
        _validate_windows_file_descriptor(
            file_descriptor,
            expected_directory=self._windows_final_path,
            name=name,
        )

    def create_json(self, name: str, payload: dict[str, object]) -> None:
        if Path(name).name != name:
            raise PreflightInputError("release ledger record name is invalid")
        rendered = (
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if self._directory_fd is None:
            file_descriptor = os.open(
                self._fallback_file_path(name, require_existing=False),
                flags,
                0o600,
            )
        else:
            file_descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=self._directory_fd,
            )
        try:
            self._verify_file_descriptor(file_descriptor, name)
        except BaseException:
            os.close(file_descriptor)
            raise
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as stream:
            stream.write(rendered)

    def read_json(self, name: str, *, maximum_bytes: int) -> object:
        if Path(name).name != name:
            raise PreflightInputError("release ledger record name is invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        file_descriptor: int | None = None
        try:
            try:
                if self._directory_fd is None:
                    file_descriptor = os.open(
                        self._fallback_file_path(name, require_existing=True),
                        flags,
                    )
                else:
                    file_descriptor = os.open(
                        name,
                        flags,
                        dir_fd=self._directory_fd,
                    )
            except PreflightInputError:
                raise
            except OSError as exc:
                raise PreflightInputError("release ledger record is unavailable") from exc
            self._verify_file_descriptor(file_descriptor, name)
            with os.fdopen(file_descriptor, "r", encoding="utf-8") as stream:
                file_descriptor = None
                content = stream.read(maximum_bytes + 1)
            if not 1 <= len(content.encode("utf-8")) <= maximum_bytes:
                raise PreflightInputError("release ledger record exceeds its byte bound")
            document = json.loads(
                content,
                parse_constant=_reject_json_constant,
                parse_float=_parse_json_decimal,
                parse_int=_parse_json_integer,
                object_pairs_hook=_reject_ambiguous_object_pairs,
            )
            _validate_json_shape(document)
            return document
        except PreflightInputError:
            raise
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise PreflightInputError("release ledger record is not valid JSON") from exc
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)


def _validate_release_ledger_directory(
    ledger_path: Path,
    trusted_root: Path,
) -> None:
    _validated_release_ledger_paths(ledger_path, trusted_root)


def _consume_release_ledger(
    *,
    ledger_path: Path,
    trusted_root: Path,
    manifest: AttestationManifest,
    kind: PreflightKind,
    rendered: str,
    safe: bool,
) -> None:
    collection_binding: dict[str, object] = {
        "schemaVersion": "athena.wc029CollectionBinding.v1",
        "collectionRunId": manifest.collection_run_id,
        "deploymentExecutionId": manifest.deployment_execution_id,
        "deploymentTarget": _deployment_target_payload(manifest.deployment_target),
        "manifestDigest": manifest.digest,
    }
    binding: dict[str, object] = {
        "schemaVersion": "athena.wc029ReleaseBinding.v1",
        "collectionRunId": manifest.collection_run_id,
        "deploymentExecutionId": manifest.deployment_execution_id,
        "deploymentTarget": _deployment_target_payload(manifest.deployment_target),
        "manifestDigest": manifest.digest,
    }
    consumption: dict[str, object] = {
        **binding,
        "schemaVersion": "athena.wc029ReleaseConsumption.v1",
        "artifactKind": kind,
        "resultDigest": "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "safe": safe,
    }
    try:
        with _SecureLedgerDirectory(ledger_path, trusted_root) as secure_ledger:
            for name, payload, mismatch_message, create_message in (
                (
                    f"{manifest.collection_run_id}.collection.json",
                    collection_binding,
                    "release ledger collectionRunId is already bound to another "
                    "deployment execution or manifest",
                    "release ledger collection binding could not be created",
                ),
                (
                    f"{manifest.deployment_execution_id}.binding.json",
                    binding,
                    "release ledger deployment binding does not match this manifest",
                    "release ledger binding could not be created",
                ),
            ):
                try:
                    secure_ledger.create_json(name, payload)
                except FileExistsError:
                    existing = secure_ledger.read_json(
                        name,
                        maximum_bytes=64 * 1024,
                    )
                    if not _json_values_equal(existing, payload):
                        raise PreflightInputError(mismatch_message) from None
                except OSError as exc:
                    raise PreflightInputError(create_message) from exc
            try:
                secure_ledger.create_json(
                    f"{manifest.deployment_execution_id}.{kind}.consumed.json",
                    consumption,
                )
            except FileExistsError as exc:
                raise PreflightInputError(
                    f"release ledger already consumed {kind} for this deployment execution"
                ) from exc
            except OSError as exc:
                raise PreflightInputError(
                    "release ledger consumption could not be recorded"
                ) from exc
    except OSError as exc:
        raise PreflightInputError("release ledger directory could not be opened securely") from exc


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
    require_attestation: bool = False,
    expected_collection_run_id: str | None = None,
    expected_deployment_execution_id: str | None = None,
    attestation_manifest_digest: str | None = None,
    deployment_digest: str | None = None,
    template_digest: str | None = None,
    parameters_digest: str | None = None,
    release_ledger_path: Path | None = None,
    trusted_release_ledger_root: Path | None = None,
    now: datetime | None = None,
) -> int:
    """Run one offline preflight check without adding policy or Azure I/O."""

    try:
        document = load_json_file(input_path)
        validation_now = _current_utc(now) if require_attestation else now
        if require_attestation:
            if (
                expected_collection_run_id is None
                or expected_deployment_execution_id is None
                or attestation_manifest_digest is None
                or release_ledger_path is None
                or trusted_release_ledger_root is None
            ):
                raise PreflightInputError(
                    "reviewed deployment execution, manifest, and release ledger are required"
                )
            _validate_release_ledger_directory(
                release_ledger_path,
                trusted_release_ledger_root,
            )
        if kind == "what-if":
            violations = evaluate_what_if(
                document,
                allowed_change_ids=allowed_change_ids,
                require_attestation=require_attestation,
                expected_collection_run_id=(expected_collection_run_id),
                expected_deployment_execution_id=(expected_deployment_execution_id),
                attestation_manifest_digest=(attestation_manifest_digest),
                deployment_digest=deployment_digest,
                template_digest=template_digest,
                parameters_digest=parameters_digest,
                now=validation_now,
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
                require_attestation=require_attestation,
                expected_collection_run_id=(expected_collection_run_id),
                expected_deployment_execution_id=(expected_deployment_execution_id),
                attestation_manifest_digest=(attestation_manifest_digest),
                now=validation_now,
            )
        else:
            raise ValueError(f"unsupported preflight kind: {kind}")
        if output_format == "json":
            rendered = render_preflight_json(
                kind=kind,
                violations=violations,
            )
        elif output_format == "text":
            rendered = render_preflight_text(
                kind=kind,
                violations=violations,
            )
        else:
            raise ValueError(f"unsupported output format: {output_format}")
        if require_attestation:
            assert expected_collection_run_id is not None
            assert expected_deployment_execution_id is not None
            assert attestation_manifest_digest is not None
            assert release_ledger_path is not None
            assert trusted_release_ledger_root is not None
            artifact_root = _mapping(
                document,
                field_name=f"attested {kind} artifact",
            )
            reviewed_manifest = _parse_attestation_manifest(
                _get_case_insensitive(artifact_root, "manifest"),
                expected_collection_run_id=expected_collection_run_id,
                expected_deployment_execution_id=expected_deployment_execution_id,
                expected_manifest_digest=attestation_manifest_digest,
                now=_current_utc(validation_now),
            )
            _consume_release_ledger(
                ledger_path=release_ledger_path,
                trusted_root=trusted_release_ledger_root,
                manifest=reviewed_manifest,
                kind=kind,
                rendered=rendered,
                safe=not violations,
            )
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

    stdout.write(rendered)
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
