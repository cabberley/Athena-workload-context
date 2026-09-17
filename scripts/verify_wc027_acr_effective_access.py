from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID

SCHEMA_VERSION = "athena.wc027AcrEffectiveAccessEvidence.v1"
GRAPH_HOST = "graph.microsoft.com"
ARM_HOST = "management.azure.com"
MAX_GRAPH_MEMBERSHIP_PAGES = 16
MAX_TRANSITIVE_GROUPS = 4096
MAX_TENANT_HIERARCHY_PAGES = 64
MAX_GOVERNED_SUBSCRIPTIONS = 4096
ACR_LEGACY_PULL_ACTION = "Microsoft.ContainerRegistry/registries/pull/read"
ACR_REPOSITORY_CONTENT_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/repositories/content/read"
)
ACR_ESCALATION_ACTIONS = (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.ContainerRegistry/registries/write",
    "Microsoft.ContainerRegistry/registries/listCredentials/action",
    "Microsoft.ContainerRegistry/registries/regenerateCredential/action",
    "Microsoft.ContainerRegistry/registries/generateCredentials/action",
    "Microsoft.ContainerRegistry/registries/tokens/write",
    "Microsoft.ContainerRegistry/registries/scopeMaps/write",
)
ACR_PULL_ROLE_ID = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
ACR_REPOSITORY_READER_ROLE_ID = "b93aa761-3e63-49ed-ac28-beffa264f7ac"
LEGACY_ROLE_ASSIGNMENT_MODE = "LegacyRegistryPermissions"
ABAC_ROLE_ASSIGNMENT_MODE = "AbacRepositoryPermissions"
_EXPECTED_LABELS = frozenset(
    {
        "request-producer",
        "feed-producer",
        "publisher",
    }
)
_EXPECTED_REPOSITORIES_BY_LABEL = {
    "request-producer": "athena/wc027-guidance-publication-request-producer",
    "feed-producer": "athena/wc027-enrichment-feed-producer",
    "publisher": "athena/wc027-guidance-authority-publisher",
}
type JsonRunner = Callable[[Sequence[str], str], object]


class EffectiveAccessError(ValueError):
    """The effective ACR access set is incomplete or broader than reviewed."""


@dataclass(frozen=True, slots=True)
class ExpectedAssignment:
    label: str
    principal_id: str
    assignment_resource_id: str
    registry_resource_id: str
    repository_name: str
    role_assignment_mode: str


@dataclass(frozen=True, slots=True)
class _RolePermissionProfile:
    actions: frozenset[str]
    not_actions: frozenset[str]
    data_actions: frozenset[str]
    not_data_actions: frozenset[str]


def verify_effective_access(
    expected_assignments: Sequence[ExpectedAssignment],
    *,
    subscription_id: str,
    run_json: JsonRunner,
    verified_at: datetime | None = None,
) -> dict[str, object]:
    canonical_subscription_id = _canonical_uuid(
        subscription_id,
        field="subscription ID",
    )
    tenant_id, governed_subscription_ids = _governed_tenant_subscriptions(
        canonical_subscription_id,
        run_json=run_json,
    )
    governed_subscription_id_set = frozenset(governed_subscription_ids)
    normalized = _validate_expected_assignments(
        expected_assignments,
        subscription_id=canonical_subscription_id,
    )
    reviewed_modes = {item.role_assignment_mode for item in normalized}
    if len(reviewed_modes) != 1:
        raise EffectiveAccessError(
            "expected ACR assignments must use one reviewed role-assignment mode"
        )
    registry_ids: dict[str, str] = {}
    registry_modes: dict[str, str] = {}
    for item in normalized:
        normalized_registry_id = item.registry_resource_id.casefold()
        registry_ids[normalized_registry_id] = item.registry_resource_id
        previous_mode = registry_modes.setdefault(
            normalized_registry_id,
            item.role_assignment_mode,
        )
        if previous_mode != item.role_assignment_mode:
            raise EffectiveAccessError(
                "expected ACR assignments disagree on one registry role-assignment mode"
            )
    for normalized_registry_id in sorted(registry_ids):
        _require_registry_posture(
            registry_ids[normalized_registry_id],
            expected_role_assignment_mode=registry_modes[normalized_registry_id],
            subscription_id=canonical_subscription_id,
            run_json=run_json,
        )

    expected_by_principal: dict[str, set[str]] = {}
    for expected_assignment in normalized:
        expected_by_principal.setdefault(
            expected_assignment.principal_id,
            set(),
        ).add(expected_assignment.assignment_resource_id.casefold())
    expected_by_id = {item.assignment_resource_id.casefold(): item for item in normalized}

    role_definitions: dict[str, dict[str, Any]] = {}
    for expected_assignment in normalized:
        exact_assignment = _get_role_assignment(
            expected_assignment.assignment_resource_id,
            subscription_id=canonical_subscription_id,
            run_json=run_json,
        )
        exact_role_definition_id = _string(
            exact_assignment.get("roleDefinitionId"),
            field=f"{expected_assignment.label} exact role definition ID",
        )
        normalized_role_id = exact_role_definition_id.casefold()
        role_definition = role_definitions.get(normalized_role_id)
        if role_definition is None:
            role_definition = _get_role_definition(
                exact_role_definition_id,
                governed_subscription_ids=governed_subscription_id_set,
                run_json=run_json,
            )
            role_definitions[normalized_role_id] = role_definition
        if not _role_definition_grants_acr_pull(role_definition):
            raise EffectiveAccessError(
                f"{expected_assignment.label} exact assignment is not pull-capable"
            )
        _require_exact_expected_assignment(
            expected_assignment,
            exact_assignment,
            role_definition_id=exact_role_definition_id,
            governed_subscription_ids=governed_subscription_id_set,
        )

    observed_expected_ids: set[str] = set()
    for principal_id in sorted(expected_by_principal):
        assignments = _resolved_effective_role_assignments(
            principal_id,
            subscription_ids=governed_subscription_ids,
            run_json=run_json,
        )
        for index, raw_assignment in enumerate(assignments):
            observed_assignment = _mapping(
                raw_assignment,
                field=f"effective ACR assignment {index}",
            )
            role_definition_id = _string(
                observed_assignment.get("roleDefinitionId"),
                field=f"effective ACR assignment {index} role definition ID",
            )
            normalized_role_id = role_definition_id.casefold()
            role_definition = role_definitions.get(normalized_role_id)
            if role_definition is None:
                role_definition = _get_role_definition(
                    role_definition_id,
                    governed_subscription_ids=governed_subscription_id_set,
                    run_json=run_json,
                )
                role_definitions[normalized_role_id] = role_definition
            if not _role_assignment_grants_acr_pull_or_escalation(
                observed_assignment,
                role_definition,
            ):
                continue
            assignment_id = _string(
                observed_assignment.get("id"),
                field=f"effective ACR assignment {index} ID",
            ).casefold()
            assignment_principal_id = _canonical_uuid(
                observed_assignment.get("principalId"),
                field=f"effective ACR assignment {index} principal ID",
            )
            matched_expected = expected_by_id.get(assignment_id)
            if matched_expected is None or assignment_principal_id != principal_id:
                raise EffectiveAccessError(
                    "effective ACR access contains an unreviewed direct, inherited, "
                    "group-derived, custom-role, or sibling-registry pull-capable "
                    "assignment"
                )
            _require_exact_expected_assignment(
                matched_expected,
                observed_assignment,
                role_definition_id=role_definition_id,
                governed_subscription_ids=governed_subscription_id_set,
            )
            observed_expected_ids.add(assignment_id)

    expected_ids = {item.assignment_resource_id.casefold() for item in normalized}
    if observed_expected_ids != expected_ids:
        raise EffectiveAccessError(
            "effective ACR access is missing an exact reviewed pull assignment"
        )

    timestamp = verified_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
        raise EffectiveAccessError("verified_at must be a UTC timestamp")
    evidence: dict[str, object] = {
        "schemaVersion": SCHEMA_VERSION,
        "verified": True,
        "tenantId": tenant_id,
        "tenantSubscriptionHierarchyComplete": True,
        "governedSubscriptionIds": list(governed_subscription_ids),
        "anonymousPullEnabled": False,
        "expectedAssignmentCount": len(expected_ids),
        "pullCapableAssignmentCount": len(observed_expected_ids),
        "roleDefinitionsResolved": True,
        "exactAssignmentReadbacksComplete": True,
        "directAssignmentsComplete": True,
        "inheritedAssignmentsComplete": True,
        "transitiveGroupsComplete": True,
        "directMembershipTraversalComplete": True,
        "convergedMembershipReadbacks": True,
        "siblingRegistriesChecked": True,
        "acrEscalationPathsChecked": True,
        "expectedAssignmentIds": sorted(expected_ids),
        "principalIds": sorted(expected_by_principal),
        "registryResourceIds": sorted(
            {item.registry_resource_id for item in normalized},
            key=str.casefold,
        ),
        "reviewedAssignments": [
            {
                "label": item.label,
                "principalId": item.principal_id,
                "assignmentResourceId": item.assignment_resource_id,
                "registryResourceId": item.registry_resource_id,
                "repositoryName": item.repository_name,
                "roleAssignmentMode": item.role_assignment_mode,
                "roleDefinitionId": _expected_role_definition_id(item),
                "conditionVersion": _expected_condition_version(item),
                "condition": _expected_condition(item),
            }
            for item in normalized
        ],
        "extraPullCapableAssignmentIds": [],
    }
    evidence["evidenceDigest"] = (
        "sha256:"
        + sha256(
            json.dumps(
                evidence,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )
    evidence["verifiedAt"] = (
        timestamp.astimezone(UTC)
        .isoformat(timespec="milliseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )
    return evidence


def _governed_tenant_subscriptions(
    subscription_id: str,
    *,
    run_json: JsonRunner,
) -> tuple[str, tuple[str, ...]]:
    account = _mapping(
        run_json(
            [
                "az",
                "account",
                "show",
                "--subscription",
                subscription_id,
                "--only-show-errors",
                "--output",
                "json",
            ],
            "governed Azure account",
        ),
        field="governed Azure account",
    )
    account_subscription_id = _canonical_uuid(
        account.get("id"),
        field="governed Azure account subscription ID",
    )
    if account_subscription_id != subscription_id:
        raise EffectiveAccessError(
            "governed Azure account does not match the registry subscription"
        )
    tenant_id = _canonical_uuid(
        account.get("tenantId"),
        field="governed Azure tenant ID",
    )
    root_path = f"/providers/Microsoft.Management/managementGroups/{tenant_id}/descendants"
    next_url: str | None = f"https://{ARM_HOST}{root_path}?api-version=2020-05-01&%24top=1000"
    seen_urls: set[str] = set()
    subscriptions: set[str] = set()
    for page_number in range(1, MAX_TENANT_HIERARCHY_PAGES + 1):
        if next_url is None:
            break
        _validate_tenant_hierarchy_url(
            next_url,
            tenant_id=tenant_id,
            first_page=page_number == 1,
        )
        if next_url in seen_urls:
            raise EffectiveAccessError("tenant subscription hierarchy pagination contains a cycle")
        seen_urls.add(next_url)
        page = _mapping(
            run_json(
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    next_url,
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                f"tenant subscription hierarchy page {page_number}",
            ),
            field="tenant subscription hierarchy page",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise EffectiveAccessError("tenant subscription hierarchy page must contain an array")
        for raw_item in values:
            item = _mapping(
                raw_item,
                field="tenant subscription hierarchy item",
            )
            item_type = _string(
                item.get("type"),
                field="tenant subscription hierarchy item type",
            )
            if item_type.casefold() == ("microsoft.management/managementgroups/subscriptions"):
                item_subscription_id = _canonical_uuid(
                    item.get("name"),
                    field="tenant hierarchy subscription ID",
                )
                if (
                    str(item.get("id", "")).casefold()
                    != (f"/subscriptions/{item_subscription_id}").casefold()
                ):
                    raise EffectiveAccessError("tenant hierarchy subscription ID is not canonical")
                if item_subscription_id in subscriptions:
                    raise EffectiveAccessError("tenant subscription hierarchy contains a duplicate")
                subscriptions.add(item_subscription_id)
                if len(subscriptions) > MAX_GOVERNED_SUBSCRIPTIONS:
                    raise EffectiveAccessError("tenant subscription hierarchy exceeds its bound")
            elif item_type.casefold() != "microsoft.management/managementgroups":
                raise EffectiveAccessError(
                    "tenant subscription hierarchy returned an unsupported item"
                )
        continuation = page.get("nextLink")
        if continuation is None:
            next_url = None
        elif isinstance(continuation, str) and continuation:
            next_url = continuation
        else:
            raise EffectiveAccessError("tenant subscription hierarchy continuation is invalid")
    else:
        raise EffectiveAccessError("tenant subscription hierarchy pagination exceeded its bound")
    if subscription_id not in subscriptions:
        raise EffectiveAccessError(
            "registry subscription is missing from the tenant root hierarchy"
        )
    return tenant_id, tuple(sorted(subscriptions))


def _validate_tenant_hierarchy_url(
    url: str,
    *,
    tenant_id: str,
    first_page: bool,
) -> None:
    if len(url) > 16_384:
        raise EffectiveAccessError("tenant subscription hierarchy continuation is oversized")
    parsed = urlparse(url)
    expected_path = f"/providers/Microsoft.Management/managementGroups/{tenant_id}/descendants"
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != ARM_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or query.get("api-version") != ["2020-05-01"]
        or any(key not in {"api-version", "$top", "$skiptoken"} for key in query)
        or any(len(values) != 1 or not values[0] for values in query.values())
        or ("$top" in query and query["$top"] != ["1000"])
        or (first_page and (query.get("$top") != ["1000"] or "$skiptoken" in query))
        or (not first_page and "$skiptoken" not in query)
    ):
        raise EffectiveAccessError("tenant subscription hierarchy continuation is invalid")


def _validate_expected_assignments(
    values: Sequence[ExpectedAssignment],
    *,
    subscription_id: str,
) -> tuple[ExpectedAssignment, ...]:
    if len(values) != len(_EXPECTED_LABELS):
        raise EffectiveAccessError(
            "expected ACR assignments must contain exactly the three PR #103 identities"
        )
    labels = {item.label for item in values}
    if labels != _EXPECTED_LABELS:
        raise EffectiveAccessError(
            "expected ACR assignment labels do not match the PR #103 identity set"
        )
    normalized: list[ExpectedAssignment] = []
    principal_ids: set[str] = set()
    assignment_ids: set[str] = set()
    for item in values:
        principal_id = _canonical_uuid(
            item.principal_id,
            field=f"{item.label} principal ID",
        )
        registry_id = _canonical_registry_id(
            item.registry_resource_id,
            subscription_id=subscription_id,
            field=f"{item.label} registry resource ID",
        )
        assignment_id = _canonical_role_assignment_id(
            item.assignment_resource_id,
            registry_id=registry_id,
            field=f"{item.label} assignment resource ID",
        )
        repository_name = _canonical_repository_name(
            item.repository_name,
            field=f"{item.label} repository name",
        )
        if repository_name != _EXPECTED_REPOSITORIES_BY_LABEL[item.label]:
            raise EffectiveAccessError(
                f"{item.label} repository does not match its digest-pinned image contract"
            )
        if item.role_assignment_mode not in {
            LEGACY_ROLE_ASSIGNMENT_MODE,
            ABAC_ROLE_ASSIGNMENT_MODE,
        }:
            raise EffectiveAccessError(f"{item.label} role assignment mode is invalid")
        if principal_id in principal_ids or assignment_id.casefold() in assignment_ids:
            raise EffectiveAccessError(
                "expected ACR assignment principals and IDs must be distinct"
            )
        principal_ids.add(principal_id)
        assignment_ids.add(assignment_id.casefold())
        normalized.append(
            ExpectedAssignment(
                label=item.label,
                principal_id=principal_id,
                assignment_resource_id=assignment_id,
                registry_resource_id=registry_id,
                repository_name=repository_name,
                role_assignment_mode=item.role_assignment_mode,
            )
        )
    return tuple(sorted(normalized, key=lambda item: item.label))


def _require_exact_expected_assignment(
    expected: ExpectedAssignment,
    assignment: Mapping[str, object],
    *,
    role_definition_id: str,
    governed_subscription_ids: frozenset[str],
) -> None:
    assignment_principal_id = _canonical_uuid(
        assignment.get("principalId"),
        field=f"{expected.label} assignment principal ID",
    )
    if assignment_principal_id != expected.principal_id:
        raise EffectiveAccessError(f"{expected.label} assignment principal is not exact")
    if assignment.get("principalType") != "ServicePrincipal":
        raise EffectiveAccessError(
            f"{expected.label} assignment principal type must be ServicePrincipal"
        )
    assignment_scope = _string(
        assignment.get("scope"),
        field=f"{expected.label} assignment scope",
    )
    if assignment_scope.casefold() != expected.registry_resource_id.casefold():
        raise EffectiveAccessError(
            f"{expected.label} assignment is not scoped to its exact registry"
        )
    canonical_role_definition_id = _canonical_role_definition_id(
        role_definition_id,
        governed_subscription_ids=governed_subscription_ids,
    )
    observed_role_id = canonical_role_definition_id.rsplit("/", 1)[-1]
    if observed_role_id != _expected_role_definition_id(expected):
        raise EffectiveAccessError(f"{expected.label} assignment role definition is not exact")
    if assignment.get("conditionVersion") != _expected_condition_version(
        expected
    ) or assignment.get("condition") != _expected_condition(expected):
        raise EffectiveAccessError(f"{expected.label} assignment condition is not exact")


def _expected_role_definition_id(expected: ExpectedAssignment) -> str:
    if expected.role_assignment_mode == ABAC_ROLE_ASSIGNMENT_MODE:
        return ACR_REPOSITORY_READER_ROLE_ID
    return ACR_PULL_ROLE_ID


def _expected_condition_version(expected: ExpectedAssignment) -> str | None:
    if expected.role_assignment_mode == ABAC_ROLE_ASSIGNMENT_MODE:
        return "2.0"
    return None


def _expected_condition(expected: ExpectedAssignment) -> str | None:
    if expected.role_assignment_mode == ABAC_ROLE_ASSIGNMENT_MODE:
        return _repository_condition(expected.repository_name)
    return None


def _repository_condition(repository_name: str) -> str:
    return (
        "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/content/read'}) AND "
        "!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/metadata/read'})) OR "
        "(@Request[Microsoft.ContainerRegistry/registries/repositories:name] "
        f"StringEqualsIgnoreCase '{repository_name}'))"
    )


def _canonical_repository_name(value: object, *, field: str) -> str:
    repository_name = _string(value, field=field)
    if (
        len(repository_name) > 256
        or repository_name != repository_name.casefold()
        or re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*",
            repository_name,
        )
        is None
    ):
        raise EffectiveAccessError(f"{field} is not canonical")
    return repository_name


def _require_registry_posture(
    registry_id: str,
    *,
    expected_role_assignment_mode: str,
    subscription_id: str,
    run_json: JsonRunner,
) -> None:
    registry = _mapping(
        run_json(
            [
                "az",
                "resource",
                "show",
                "--ids",
                registry_id,
                "--subscription",
                subscription_id,
                "--api-version",
                "2025-04-01",
                "--only-show-errors",
                "--output",
                "json",
            ],
            f"live ACR readback for {registry_id}",
        ),
        field="live ACR readback",
    )
    if str(registry.get("id", "")).casefold() != registry_id.casefold():
        raise EffectiveAccessError("live ACR readback does not match its expected registry")
    properties = _mapping(
        registry.get("properties"),
        field="live ACR properties",
    )
    if properties.get("roleAssignmentMode") != expected_role_assignment_mode:
        raise EffectiveAccessError("live ACR roleAssignmentMode does not match the reviewed mode")
    if properties.get("anonymousPullEnabled") is not False:
        raise EffectiveAccessError("live ACR anonymousPullEnabled must be explicitly false")


def _resolved_effective_role_assignments(
    principal_id: str,
    *,
    subscription_ids: Sequence[str],
    run_json: JsonRunner,
) -> list[dict[str, Any]]:
    documents: list[object] = []
    for subscription_id in subscription_ids:
        documents.append(
            _effective_role_assignments(
                principal_id,
                subscription_id=subscription_id,
                run_json=run_json,
            )
        )
    for group_id in sorted(
        _transitive_group_ids(
            principal_id,
            run_json=run_json,
        )
    ):
        for subscription_id in subscription_ids:
            documents.append(
                _effective_role_assignments(
                    group_id,
                    subscription_id=subscription_id,
                    run_json=run_json,
                )
            )
    return _merge_assignment_documents(
        documents,
        field=f"effective ACR assignments for {principal_id}",
    )


def _effective_role_assignments(
    principal_id: str,
    *,
    subscription_id: str,
    run_json: JsonRunner,
) -> list[dict[str, Any]]:
    subscription_scope = f"/subscriptions/{subscription_id}"
    return _merge_assignment_documents(
        (
            run_json(
                [
                    "az",
                    "role",
                    "assignment",
                    "list",
                    "--subscription",
                    subscription_id,
                    "--assignee-object-id",
                    principal_id,
                    "--all",
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                f"effective ACR assignments for {principal_id}",
            ),
            run_json(
                [
                    "az",
                    "role",
                    "assignment",
                    "list",
                    "--subscription",
                    subscription_id,
                    "--assignee-object-id",
                    principal_id,
                    "--scope",
                    subscription_scope,
                    "--include-inherited",
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                f"inherited ACR assignments for {principal_id}",
            ),
        ),
        field=f"effective ACR assignments for {principal_id}",
    )


def _get_role_assignment(
    assignment_resource_id: str,
    *,
    subscription_id: str,
    run_json: JsonRunner,
) -> dict[str, Any]:
    canonical_id = _canonical_role_assignment_resource_id(
        assignment_resource_id,
        subscription_id=subscription_id,
    )
    resource = _mapping(
        run_json(
            [
                "az",
                "rest",
                "--method",
                "get",
                "--url",
                f"https://{ARM_HOST}{canonical_id}?api-version=2022-04-01",
                "--only-show-errors",
                "--output",
                "json",
            ],
            f"exact ACR role assignment {canonical_id}",
        ),
        field="exact ACR role assignment",
    )
    if str(resource.get("id", "")).casefold() != canonical_id.casefold():
        raise EffectiveAccessError(
            "exact ACR role assignment readback does not match its expected ID"
        )
    properties = _mapping(
        resource.get("properties"),
        field="exact ACR role assignment properties",
    )
    return {
        "id": resource["id"],
        **properties,
    }


def _transitive_group_ids(
    principal_id: str,
    *,
    run_json: JsonRunner,
) -> set[str]:
    first = _transitive_group_ids_once(
        principal_id,
        run_json=run_json,
    )
    second = _transitive_group_ids_once(
        principal_id,
        run_json=run_json,
    )
    if first != second:
        raise EffectiveAccessError(
            "Microsoft Graph direct group-membership traversal did not converge"
        )
    return first


def _transitive_group_ids_once(
    principal_id: str,
    *,
    run_json: JsonRunner,
) -> set[str]:
    group_ids: set[str] = set()
    queue: list[tuple[str, str]] = [("servicePrincipals", principal_id)]
    read_index = 0
    while read_index < len(queue):
        object_kind, object_id = queue[read_index]
        read_index += 1
        for group_id in sorted(
            _direct_parent_group_ids(
                object_kind,
                object_id,
                run_json=run_json,
            )
        ):
            if group_id in group_ids:
                continue
            group_ids.add(group_id)
            if len(group_ids) > MAX_TRANSITIVE_GROUPS:
                raise EffectiveAccessError("Microsoft Graph group membership exceeds its bound")
            queue.append(("groups", group_id))
    return group_ids


def _direct_parent_group_ids(
    object_kind: str,
    object_id: str,
    *,
    run_json: JsonRunner,
) -> set[str]:
    if object_kind not in {"servicePrincipals", "groups"}:
        raise EffectiveAccessError("Microsoft Graph membership object type is invalid")
    next_url: str | None = f"https://{GRAPH_HOST}/v1.0/{object_kind}/{object_id}/memberOf"
    group_ids: set[str] = set()
    seen_urls: set[str] = set()
    for page_number in range(1, MAX_GRAPH_MEMBERSHIP_PAGES + 1):
        if next_url is None:
            break
        _validate_graph_membership_url(
            next_url,
            object_kind=object_kind,
            object_id=object_id,
            first_page=page_number == 1,
        )
        if next_url in seen_urls:
            raise EffectiveAccessError("Microsoft Graph group-membership continuation is invalid")
        seen_urls.add(next_url)
        page = _mapping(
            run_json(
                [
                    "az",
                    "rest",
                    "--method",
                    "get",
                    "--url",
                    next_url,
                    "--only-show-errors",
                    "--output",
                    "json",
                ],
                (f"direct parent groups for {object_kind}/{object_id} page {page_number}"),
            ),
            field="Microsoft Graph group-membership page",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise EffectiveAccessError(
                "Microsoft Graph group-membership page must contain an array"
            )
        for raw_group in values:
            group = _mapping(raw_group, field="Microsoft Graph group")
            object_type = group.get("@odata.type")
            if object_type != "#microsoft.graph.group":
                if isinstance(object_type, str) and object_type.startswith("#microsoft.graph."):
                    continue
                raise EffectiveAccessError(
                    "Microsoft Graph membership item type is missing or invalid"
                )
            group_id = _canonical_uuid(
                group.get("id"),
                field="Microsoft Graph group ID",
            )
            if group_id in group_ids:
                raise EffectiveAccessError(
                    "Microsoft Graph group-membership pages contain a duplicate"
                )
            group_ids.add(group_id)
        continuation = page.get("@odata.nextLink")
        if continuation is None:
            next_url = None
        elif isinstance(continuation, str) and continuation:
            next_url = continuation
        else:
            raise EffectiveAccessError("Microsoft Graph group-membership continuation is invalid")
    else:
        raise EffectiveAccessError("Microsoft Graph group-membership pagination exceeded its bound")
    return group_ids


def _validate_graph_membership_url(
    url: str,
    *,
    object_kind: str,
    object_id: str,
    first_page: bool,
) -> None:
    if len(url) > 16_384:
        raise EffectiveAccessError("Microsoft Graph group-membership continuation is oversized")
    parsed = urlparse(url)
    expected_path = f"/v1.0/{object_kind}/{object_id}/memberOf"
    query = parse_qs(parsed.query, keep_blank_values=True)
    allowed_query_keys = {"$top", "$skiptoken", "$skip"}
    top_values = query.get("$top")
    top_invalid = top_values is not None and (
        len(top_values) != 1 or not top_values[0].isdigit() or not 1 <= int(top_values[0]) <= 999
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != GRAPH_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(key not in allowed_query_keys for key in query)
        or any(len(values) != 1 or not values[0] for values in query.values())
        or top_invalid
        or (first_page and (bool(query) or "$skiptoken" in query or "$skip" in query))
        or (not first_page and "$skiptoken" not in query and "$skip" not in query)
    ):
        raise EffectiveAccessError("Microsoft Graph group-membership continuation is invalid")


def _merge_assignment_documents(
    documents: Sequence[object],
    *,
    field: str,
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for document_index, document in enumerate(documents):
        if not isinstance(document, list):
            raise EffectiveAccessError(f"{field} document {document_index} must be an array")
        for assignment_index, raw_assignment in enumerate(document):
            assignment = _mapping(
                raw_assignment,
                field=f"{field} item {assignment_index}",
            )
            assignment_id = _string(
                assignment.get("id"),
                field=f"{field} assignment ID",
            ).casefold()
            existing = merged.get(assignment_id)
            if existing is None:
                merged[assignment_id] = assignment
                continue
            for property_name in (
                "principalId",
                "roleDefinitionId",
                "scope",
            ):
                existing_value = existing.get(property_name)
                incoming_value = assignment.get(property_name)
                if (
                    existing_value not in (None, "")
                    and incoming_value not in (None, "")
                    and str(existing_value).casefold() != str(incoming_value).casefold()
                ):
                    raise EffectiveAccessError(f"{field} returned conflicting duplicate assignment")
                if existing_value in (None, "") and incoming_value not in (None, ""):
                    existing[property_name] = incoming_value
    return list(merged.values())


def _get_role_definition(
    role_definition_id: str,
    *,
    governed_subscription_ids: frozenset[str],
    run_json: JsonRunner,
) -> dict[str, Any]:
    canonical_id = _canonical_role_definition_id(
        role_definition_id,
        governed_subscription_ids=governed_subscription_ids,
    )
    role = _mapping(
        run_json(
            [
                "az",
                "rest",
                "--method",
                "get",
                "--url",
                f"https://{ARM_HOST}{canonical_id}?api-version=2022-04-01",
                "--only-show-errors",
                "--output",
                "json",
            ],
            f"effective ACR role definition {canonical_id}",
        ),
        field="effective ACR role definition",
    )
    if str(role.get("id", "")).casefold() != canonical_id.casefold():
        raise EffectiveAccessError(
            "effective ACR role definition readback does not match its assignment"
        )
    return role


def _role_definition_grants_acr_pull(
    resource: Mapping[str, object],
) -> bool:
    profiles = _role_permission_profiles(resource)
    required_reads = (
        (ACR_LEGACY_PULL_ACTION, False),
        (ACR_LEGACY_PULL_ACTION, True),
        (ACR_REPOSITORY_CONTENT_READ_DATA_ACTION, False),
        (ACR_REPOSITORY_CONTENT_READ_DATA_ACTION, True),
    )
    return any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=is_data_action,
        )
        for profile in profiles
        for action, is_data_action in required_reads
    )


def _role_assignment_grants_acr_pull_or_escalation(
    assignment: Mapping[str, object],
    role_definition: Mapping[str, object],
) -> bool:
    if _role_definition_grants_acr_pull(role_definition):
        return True
    scope = _string(
        assignment.get("scope"),
        field="effective ACR assignment scope",
    )
    return _scope_can_govern_acr(scope) and _role_definition_grants_acr_escalation(role_definition)


def _role_definition_grants_acr_escalation(
    resource: Mapping[str, object],
) -> bool:
    profiles = _role_permission_profiles(resource)
    return any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=False,
        )
        for profile in profiles
        for action in ACR_ESCALATION_ACTIONS
    )


def _scope_can_govern_acr(scope: str) -> bool:
    if scope == "/":
        return True
    normalized = scope.rstrip("/").casefold()
    if normalized.startswith("/providers/microsoft.management/managementgroups/"):
        return True
    segments = normalized.split("/")
    if len(segments) == 3 and segments[0] == "" and segments[1] == "subscriptions":
        return True
    if (
        len(segments) == 5
        and segments[0] == ""
        and segments[1] == "subscriptions"
        and segments[3] == "resourcegroups"
    ):
        return True
    return (
        len(segments) >= 9
        and segments[0] == ""
        and segments[1] == "subscriptions"
        and segments[3] == "resourcegroups"
        and segments[5] == "providers"
        and segments[6] == "microsoft.containerregistry"
        and segments[7] == "registries"
        and bool(segments[8])
    )


def _role_permission_profiles(
    resource: Mapping[str, object],
) -> tuple[_RolePermissionProfile, ...]:
    properties = _mapping(
        resource.get("properties"),
        field="effective ACR role definition properties",
    )
    permissions = properties.get("permissions")
    if not isinstance(permissions, list) or not 1 <= len(permissions) <= 64:
        raise EffectiveAccessError("effective ACR role definition permissions are invalid")
    profiles: list[_RolePermissionProfile] = []
    for permission_index, raw_permission in enumerate(permissions):
        permission = _mapping(
            raw_permission,
            field=f"effective ACR role permission {permission_index}",
        )

        def permission_set(
            name: str,
            *,
            source: Mapping[str, object] = permission,
        ) -> frozenset[str]:
            values = source.get(name)
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not item or item != item.strip() or len(item) > 512
                for item in values
            ):
                raise EffectiveAccessError(f"effective ACR role permission {name} is invalid")
            normalized = [item.casefold() for item in values]
            if len(set(normalized)) != len(normalized):
                raise EffectiveAccessError(
                    f"effective ACR role permission {name} contains duplicates"
                )
            return frozenset(values)

        profiles.append(
            _RolePermissionProfile(
                actions=permission_set("actions"),
                not_actions=permission_set("notActions"),
                data_actions=permission_set("dataActions"),
                not_data_actions=permission_set("notDataActions"),
            )
        )
    return tuple(profiles)


def _permission_profile_grants_action(
    profile: _RolePermissionProfile,
    action: str,
    *,
    is_data_action: bool,
) -> bool:
    granted = profile.data_actions if is_data_action else profile.actions
    excluded = profile.not_data_actions if is_data_action else profile.not_actions
    return any(_permission_pattern_matches(pattern, action) for pattern in granted) and not any(
        _permission_pattern_matches(pattern, action) for pattern in excluded
    )


def _permission_pattern_matches(pattern: str, action: str) -> bool:
    expression = re.escape(pattern.casefold()).replace(r"\*", ".*")
    return re.fullmatch(expression, action.casefold()) is not None


def _canonical_role_definition_id(
    value: object,
    *,
    governed_subscription_ids: frozenset[str],
) -> str:
    role_definition_id = _string(
        value,
        field="effective ACR role definition ID",
    )
    parsed = urlparse(role_definition_id)
    if (
        parsed.query
        or parsed.fragment
        or role_definition_id.endswith("/")
        or role_definition_id != role_definition_id.strip()
    ):
        raise EffectiveAccessError("effective ACR role definition ID is not canonical")
    role_guid = _canonical_uuid(
        role_definition_id.rsplit("/", 1)[-1],
        field="effective ACR role definition UUID",
    )
    segments = role_definition_id.split("/")
    normalized = role_definition_id.casefold()
    if normalized.startswith("/subscriptions/"):
        if (
            len(segments) != 7
            or segments[0] != ""
            or segments[1].casefold() != "subscriptions"
            or segments[3].casefold() != "providers"
            or segments[4].casefold() != "microsoft.authorization"
            or segments[5].casefold() != "roledefinitions"
            or segments[6] != role_guid
        ):
            raise EffectiveAccessError("effective ACR subscription role definition ID is invalid")
        role_subscription_id = _canonical_uuid(
            segments[2],
            field="role subscription ID",
        )
        if role_subscription_id not in governed_subscription_ids:
            raise EffectiveAccessError(
                "effective ACR role definition is outside the governed subscriptions"
            )
    elif normalized.startswith("/providers/microsoft.management/managementgroups/"):
        if (
            len(segments) != 9
            or segments[0] != ""
            or segments[1].casefold() != "providers"
            or segments[2].casefold() != "microsoft.management"
            or segments[3].casefold() != "managementgroups"
            or not segments[4]
            or segments[5].casefold() != "providers"
            or segments[6].casefold() != "microsoft.authorization"
            or segments[7].casefold() != "roledefinitions"
            or segments[8] != role_guid
        ):
            raise EffectiveAccessError(
                "effective ACR management-group role definition ID is invalid"
            )
    elif normalized.startswith("/providers/microsoft.authorization/roledefinitions/"):
        if (
            len(segments) != 5
            or segments[0] != ""
            or segments[1].casefold() != "providers"
            or segments[2].casefold() != "microsoft.authorization"
            or segments[3].casefold() != "roledefinitions"
            or segments[4] != role_guid
        ):
            raise EffectiveAccessError("effective ACR tenant role definition ID is invalid")
    else:
        raise EffectiveAccessError(
            "effective ACR role definition is outside the governed hierarchy"
        )
    return role_definition_id


def _canonical_registry_id(
    value: object,
    *,
    subscription_id: str,
    field: str,
) -> str:
    resource_id = _string(value, field=field)
    segments = resource_id.split("/")
    if (
        any(alias in resource_id for alias in ("//", "?", "#", "%"))
        or resource_id.endswith("/")
        or len(segments) != 9
        or segments[0] != ""
        or segments[1].casefold() != "subscriptions"
        or _canonical_uuid(segments[2], field=f"{field} subscription") != subscription_id
        or segments[3].casefold() != "resourcegroups"
        or not segments[4]
        or segments[5].casefold() != "providers"
        or segments[6].casefold() != "microsoft.containerregistry"
        or segments[7].casefold() != "registries"
        or not segments[8]
    ):
        raise EffectiveAccessError(f"{field} is not a canonical ACR resource ID")
    return resource_id


def _canonical_role_assignment_id(
    value: object,
    *,
    registry_id: str,
    field: str,
) -> str:
    assignment_id = _string(value, field=field)
    prefix = f"{registry_id}/providers/Microsoft.Authorization/roleAssignments/"
    if not assignment_id.casefold().startswith(prefix.casefold()):
        raise EffectiveAccessError(f"{field} is not scoped to its exact expected registry")
    suffix = assignment_id[len(prefix) :]
    if suffix != _canonical_uuid(suffix, field=f"{field} UUID"):
        raise EffectiveAccessError(f"{field} UUID is not canonical")
    return assignment_id


def _canonical_role_assignment_resource_id(
    value: object,
    *,
    subscription_id: str,
) -> str:
    assignment_id = _string(
        value,
        field="exact ACR role assignment resource ID",
    )
    segments = assignment_id.split("/")
    if (
        any(alias in assignment_id for alias in ("//", "?", "#", "%"))
        or assignment_id.endswith("/")
        or len(segments) != 13
        or segments[0] != ""
        or segments[1].casefold() != "subscriptions"
        or _canonical_uuid(
            segments[2],
            field="exact ACR role assignment subscription ID",
        )
        != subscription_id
        or segments[3].casefold() != "resourcegroups"
        or not segments[4]
        or segments[5].casefold() != "providers"
        or segments[6].casefold() != "microsoft.containerregistry"
        or segments[7].casefold() != "registries"
        or not segments[8]
        or segments[9].casefold() != "providers"
        or segments[10].casefold() != "microsoft.authorization"
        or segments[11].casefold() != "roleassignments"
        or segments[12]
        != _canonical_uuid(
            segments[12],
            field="exact ACR role assignment UUID",
        )
    ):
        raise EffectiveAccessError("exact ACR role assignment resource ID is not canonical")
    return assignment_id


def _canonical_uuid(value: object, *, field: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise EffectiveAccessError(f"{field} must be a canonical UUID")
    try:
        canonical = str(UUID(value))
    except ValueError as exc:
        raise EffectiveAccessError(f"{field} must be a canonical UUID") from exc
    if value.casefold() != canonical:
        raise EffectiveAccessError(f"{field} must use canonical lowercase UUID form")
    return canonical


def _mapping(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EffectiveAccessError(f"{field} must be an object")
    return value


def _string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EffectiveAccessError(f"{field} must be a non-empty string")
    return value


def _run_json(command: Sequence[str], field: str) -> object:
    try:
        completed = subprocess.run(  # noqa: S603
            list(command),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise EffectiveAccessError(f"{field} command timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise EffectiveAccessError(
            f"{field} command failed with exit code {completed.returncode}: {detail}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise EffectiveAccessError(f"{field} did not return valid JSON") from exc


def _expected_assignments(value: object) -> tuple[ExpectedAssignment, ...]:
    if not isinstance(value, list):
        raise EffectiveAccessError("expected assignments JSON must be an array")
    assignments: list[ExpectedAssignment] = []
    for index, raw_item in enumerate(value):
        item = _mapping(
            raw_item,
            field=f"expected assignment {index}",
        )
        if set(item) != {
            "label",
            "principalId",
            "assignmentResourceId",
            "registryResourceId",
            "repositoryName",
            "roleAssignmentMode",
        }:
            raise EffectiveAccessError(f"expected assignment {index} has missing or unknown fields")
        assignments.append(
            ExpectedAssignment(
                label=_string(item["label"], field=f"assignment {index} label"),
                principal_id=_string(
                    item["principalId"],
                    field=f"assignment {index} principal ID",
                ),
                assignment_resource_id=_string(
                    item["assignmentResourceId"],
                    field=f"assignment {index} resource ID",
                ),
                registry_resource_id=_string(
                    item["registryResourceId"],
                    field=f"assignment {index} registry resource ID",
                ),
                repository_name=_string(
                    item["repositoryName"],
                    field=f"assignment {index} repository name",
                ),
                role_assignment_mode=_string(
                    item["roleAssignmentMode"],
                    field=f"assignment {index} role assignment mode",
                ),
            )
        )
    return tuple(assignments)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the complete effective ACR pull-capable assignment set for "
            "the three PR #103 identities."
        )
    )
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--expected-assignments-json", required=True)
    args = parser.parse_args()
    try:
        expected = _expected_assignments(json.loads(args.expected_assignments_json))
        evidence = verify_effective_access(
            expected,
            subscription_id=args.subscription_id,
            run_json=_run_json,
        )
    except (EffectiveAccessError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            evidence,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
