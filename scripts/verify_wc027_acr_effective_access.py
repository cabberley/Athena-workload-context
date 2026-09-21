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
from urllib.parse import parse_qs, quote, urlencode, urlparse
from uuid import UUID

SCHEMA_VERSION = "athena.wc027AcrEffectiveAccessEvidence.v1"
GRAPH_HOST = "graph.microsoft.com"
ARM_HOST = "management.azure.com"
MAX_GRAPH_MEMBERSHIP_PAGES = 16
MAX_TRANSITIVE_GROUPS = 4096
MAX_TENANT_HIERARCHY_PAGES = 64
MAX_GOVERNED_SUBSCRIPTIONS = 4096
MAX_CLASSIC_ROLE_ASSIGNMENT_PAGES = 64
MAX_CLASSIC_ROLE_ASSIGNMENT_API_CALLS = 16_384
MAX_CLASSIC_ROLE_ASSIGNMENTS = 65_536
MAX_ROLE_ASSIGNMENT_SCHEDULE_PAGES = 64
MAX_ROLE_ASSIGNMENT_SCHEDULE_API_CALLS = 16_384
MAX_ROLE_ASSIGNMENT_SCHEDULE_INSTANCES = 65_536
ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
ROLE_ASSIGNMENT_SCHEDULE_API_VERSION = "2020-10-01"
ACR_LEGACY_PULL_ACTION = "Microsoft.ContainerRegistry/registries/pull/read"
ACR_REPOSITORY_CONTENT_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/repositories/content/read"
)
ACR_QUARANTINE_READ_ACTION = "Microsoft.ContainerRegistry/registries/quarantine/read"
ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION = (
    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read"
)
ACR_PULL_ACTIONS = (
    ACR_LEGACY_PULL_ACTION,
    ACR_QUARANTINE_READ_ACTION,
)
ACR_PULL_DATA_ACTIONS = (
    ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
    ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,
)
ACR_ESCALATION_ACTIONS = (
    "Microsoft.Authorization/elevateAccess/action",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignmentScheduleRequests/write",
    "Microsoft.Authorization/roleEligibilityScheduleRequests/write",
    "Microsoft.Authorization/roleEligibilityScheduleRequests/whenApprovalRequired/write",
    "Microsoft.Authorization/roleManagementPolicies/write",
    "Microsoft.Authorization/roleManagementPolicies/approvalRule/action",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.ContainerRegistry/registries/write",
    "Microsoft.ContainerRegistry/registries/listCredentials/action",
    "Microsoft.ContainerRegistry/registries/regenerateCredential/action",
    "Microsoft.ContainerRegistry/registries/generateCredentials/action",
    "Microsoft.ContainerRegistry/registries/tokens/write",
    "Microsoft.ContainerRegistry/registries/scopeMaps/write",
    "Microsoft.ContainerRegistry/registries/quarantine/write",
    "Microsoft.ContainerRegistry/registries/scheduleRun/action",
    "Microsoft.ContainerRegistry/registries/tasks/listDetails/action",
    "Microsoft.ContainerRegistry/registries/tasks/write",
    "Microsoft.ContainerRegistry/registries/taskruns/listDetails/action",
    "Microsoft.ContainerRegistry/registries/taskruns/write",
    "Microsoft.ContainerRegistry/registries/updatePolicies/write",
)
ACR_ESCALATION_DATA_ACTIONS = (
    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write",
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
_ROLE_ASSIGNMENT_SCHEDULE_STATUSES = frozenset(
    {
        "Accepted",
        "PendingEvaluation",
        "Granted",
        "Denied",
        "PendingProvisioning",
        "Provisioned",
        "PendingRevocation",
        "Revoked",
        "Canceled",
        "Failed",
        "PendingApprovalProvisioning",
        "PendingApproval",
        "FailedAsResourceIsLocked",
        "PendingAdminDecision",
        "AdminApproved",
        "AdminDenied",
        "TimedOut",
        "ProvisioningStarted",
        "Invalid",
        "PendingScheduleCreation",
        "ScheduleCreated",
        "PendingExternalProvisioning",
    }
)
_INACTIVE_ROLE_ASSIGNMENT_SCHEDULE_STATUSES = frozenset(
    {
        "Denied",
        "Revoked",
        "Canceled",
        "Failed",
        "FailedAsResourceIsLocked",
        "AdminDenied",
        "TimedOut",
        "Invalid",
    }
)
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


@dataclass(slots=True)
class _RoleAssignmentScheduleScanBudget:
    api_calls: int = 0
    instances: int = 0


@dataclass(slots=True)
class _ClassicRoleAssignmentScanBudget:
    api_calls: int = 0
    assignments: int = 0


def _pagination_budgets() -> dict[str, int]:
    return {
        "tenantHierarchyMaxPages": MAX_TENANT_HIERARCHY_PAGES,
        "governedSubscriptionMaxCount": MAX_GOVERNED_SUBSCRIPTIONS,
        "graphMembershipMaxPagesPerObject": MAX_GRAPH_MEMBERSHIP_PAGES,
        "transitiveGroupMaxCountPerPrincipal": MAX_TRANSITIVE_GROUPS,
        "classicRoleAssignmentMaxPagesPerQuery": MAX_CLASSIC_ROLE_ASSIGNMENT_PAGES,
        "classicRoleAssignmentMaxApiCalls": MAX_CLASSIC_ROLE_ASSIGNMENT_API_CALLS,
        "classicRoleAssignmentMaxItems": MAX_CLASSIC_ROLE_ASSIGNMENTS,
        "roleAssignmentScheduleMaxPagesPerQuery": MAX_ROLE_ASSIGNMENT_SCHEDULE_PAGES,
        "roleAssignmentScheduleMaxApiCalls": MAX_ROLE_ASSIGNMENT_SCHEDULE_API_CALLS,
        "roleAssignmentScheduleMaxInstances": MAX_ROLE_ASSIGNMENT_SCHEDULE_INSTANCES,
    }


def verify_effective_access(
    expected_assignments: Sequence[ExpectedAssignment],
    *,
    subscription_id: str,
    run_json: JsonRunner,
    verified_at: datetime | None = None,
) -> dict[str, object]:
    timestamp = verified_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
        raise EffectiveAccessError("verified_at must be a UTC timestamp")
    timestamp = timestamp.astimezone(UTC)
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
    transitive_groups_by_principal = {
        principal_id: _transitive_group_ids(
            principal_id,
            run_json=run_json,
        )
        for principal_id in sorted(expected_by_principal)
    }
    principal_subscription_queries = sum(
        (1 + len(group_ids)) * len(governed_subscription_ids)
        for group_ids in transitive_groups_by_principal.values()
    )
    if principal_subscription_queries > MAX_ROLE_ASSIGNMENT_SCHEDULE_API_CALLS:
        raise EffectiveAccessError(
            "active role-assignment schedule query set exceeds its API call bound"
        )
    if principal_subscription_queries > MAX_CLASSIC_ROLE_ASSIGNMENT_API_CALLS:
        raise EffectiveAccessError(
            "classic role-assignment query set exceeds its API call bound"
        )
    classic_budget = _ClassicRoleAssignmentScanBudget()
    schedule_budget = _RoleAssignmentScheduleScanBudget()
    for principal_id in sorted(expected_by_principal):
        assignments = _resolved_effective_role_assignments(
            principal_id,
            group_ids=transitive_groups_by_principal[principal_id],
            subscription_ids=governed_subscription_ids,
            governed_subscription_ids=governed_subscription_id_set,
            active_at=timestamp,
            classic_budget=classic_budget,
            schedule_budget=schedule_budget,
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
                    "group-derived, active-PIM, custom-role, or sibling-registry "
                    "pull-capable assignment"
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
        "roleAssignmentScheduleInstancesComplete": True,
        "siblingRegistriesChecked": True,
        "acrEscalationPathsChecked": True,
        "completeness": {
            "classicRoleAssignments": True,
            "pimRoleAssignmentScheduleInstances": True,
            "transitiveGroups": True,
            "siblingRegistries": True,
            "acrEscalationPaths": True,
            "exactAssignmentReadbacks": True,
            "paginationBudgets": True,
        },
        "paginationBudgets": _pagination_budgets(),
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
            break
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
    group_ids: Sequence[str],
    subscription_ids: Sequence[str],
    governed_subscription_ids: frozenset[str],
    active_at: datetime,
    classic_budget: _ClassicRoleAssignmentScanBudget,
    schedule_budget: _RoleAssignmentScheduleScanBudget,
    run_json: JsonRunner,
) -> list[dict[str, Any]]:
    documents: list[object] = []
    principal_types = (
        (principal_id, "ServicePrincipal"),
        *((group_id, "Group") for group_id in sorted(group_ids)),
    )
    for effective_principal_id, principal_type in principal_types:
        for subscription_id in subscription_ids:
            documents.append(
                _effective_role_assignments(
                    effective_principal_id,
                    principal_type=principal_type,
                    subscription_id=subscription_id,
                    governed_subscription_ids=governed_subscription_ids,
                    classic_budget=classic_budget,
                    run_json=run_json,
                )
            )
            documents.append(
                _active_role_assignment_schedule_instances(
                    effective_principal_id,
                    principal_type=principal_type,
                    subscription_id=subscription_id,
                    governed_subscription_ids=governed_subscription_ids,
                    active_at=active_at,
                    schedule_budget=schedule_budget,
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
    principal_type: str,
    subscription_id: str,
    governed_subscription_ids: frozenset[str],
    classic_budget: _ClassicRoleAssignmentScanBudget,
    run_json: JsonRunner,
) -> list[dict[str, Any]]:
    subscription_scope = f"/subscriptions/{subscription_id}"
    filter_value = f"principalId eq '{principal_id}'"
    query = urlencode(
        (
            ("api-version", ROLE_ASSIGNMENTS_API_VERSION),
            ("$filter", filter_value),
        ),
        quote_via=quote,
    )
    next_url: str | None = (
        f"https://{ARM_HOST}{subscription_scope}/providers/"
        f"Microsoft.Authorization/roleAssignments?{query}"
    )
    assignments: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    seen_assignment_ids: set[str] = set()
    for page_number in range(1, MAX_CLASSIC_ROLE_ASSIGNMENT_PAGES + 1):
        if next_url is None:
            return assignments
        _validate_classic_role_assignments_url(
            next_url,
            subscription_id=subscription_id,
            principal_id=principal_id,
            first_page=page_number == 1,
        )
        if next_url in seen_urls:
            raise EffectiveAccessError(
                "classic role-assignment pagination contains a cycle"
            )
        seen_urls.add(next_url)
        if classic_budget.api_calls >= MAX_CLASSIC_ROLE_ASSIGNMENT_API_CALLS:
            raise EffectiveAccessError(
                "classic role-assignment API calls exceed their bound"
            )
        classic_budget.api_calls += 1
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
                (
                    "classic role assignments for "
                    f"{principal_type} {principal_id} in {subscription_scope} "
                    f"page {page_number}"
                ),
            ),
            field="classic role-assignment page",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise EffectiveAccessError(
                "classic role-assignment page must contain an array"
            )
        for assignment_index, raw_assignment in enumerate(values):
            if classic_budget.assignments >= MAX_CLASSIC_ROLE_ASSIGNMENTS:
                raise EffectiveAccessError(
                    "classic role-assignment items exceed their bound"
                )
            classic_budget.assignments += 1
            assignment = _classic_role_assignment(
                raw_assignment,
                principal_id=principal_id,
                principal_type=principal_type,
                governed_subscription_ids=governed_subscription_ids,
                field=(
                    "classic role-assignment "
                    f"page {page_number} item {assignment_index}"
                ),
            )
            assignment_id = _string(
                assignment.get("id"),
                field="classic role-assignment ID",
            ).casefold()
            if assignment_id in seen_assignment_ids:
                raise EffectiveAccessError(
                    "classic role-assignment pages contain a duplicate"
                )
            seen_assignment_ids.add(assignment_id)
            assignments.append(assignment)
        continuation = page.get("nextLink")
        if continuation is None:
            return assignments
        if not isinstance(continuation, str) or not continuation:
            raise EffectiveAccessError(
                "classic role-assignment continuation is invalid"
            )
        next_url = continuation
    raise EffectiveAccessError(
        "classic role-assignment pagination exceeded its bound"
    )


def _validate_classic_role_assignments_url(
    url: str,
    *,
    subscription_id: str,
    principal_id: str,
    first_page: bool,
) -> None:
    if len(url) > 16_384:
        raise EffectiveAccessError(
            "classic role-assignment continuation is oversized"
        )
    parsed = urlparse(url)
    expected_path = (
        f"/subscriptions/{subscription_id}/providers/"
        "Microsoft.Authorization/roleAssignments"
    )
    query = parse_qs(parsed.query, keep_blank_values=True)
    normalized_query: dict[str, list[str]] = {}
    for key, values in query.items():
        normalized_key = key.casefold()
        if normalized_key in normalized_query:
            raise EffectiveAccessError(
                "classic role-assignment continuation is invalid"
            )
        normalized_query[normalized_key] = values
    continuation_keys = {"$skiptoken"} & normalized_query.keys()
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != ARM_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(
            key not in {"api-version", "$filter", "$skiptoken"}
            for key in normalized_query
        )
        or any(len(values) != 1 or not values[0] for values in normalized_query.values())
        or normalized_query.get("api-version") != [ROLE_ASSIGNMENTS_API_VERSION]
        or normalized_query.get("$filter")
        != [f"principalId eq '{principal_id}'"]
        or (first_page and continuation_keys)
        or (not first_page and continuation_keys != {"$skiptoken"})
    ):
        raise EffectiveAccessError(
            "classic role-assignment continuation is invalid"
        )


def _classic_role_assignment(
    value: object,
    *,
    principal_id: str,
    principal_type: str,
    governed_subscription_ids: frozenset[str],
    field: str,
) -> dict[str, Any]:
    resource = _mapping(value, field=field)
    assignment_name = _canonical_uuid(
        resource.get("name"),
        field=f"{field} name",
    )
    if str(resource.get("type", "")).casefold() != (
        "Microsoft.Authorization/roleAssignments"
    ).casefold():
        raise EffectiveAccessError(f"{field} type is invalid")
    properties = _mapping(
        resource.get("properties"),
        field=f"{field} properties",
    )
    assignment_principal_id = _canonical_uuid(
        properties.get("principalId"),
        field=f"{field} principal ID",
    )
    if assignment_principal_id != principal_id:
        raise EffectiveAccessError(f"{field} principal does not match its query")
    if properties.get("principalType") != principal_type:
        raise EffectiveAccessError(f"{field} principal type does not match its query")
    scope = _canonical_governed_scope(
        properties.get("scope"),
        governed_subscription_ids=governed_subscription_ids,
        field=f"{field} scope",
    )
    assignment_id = _canonical_role_assignment_origin_id(
        resource.get("id"),
        scope=scope,
        field=f"{field} ID",
    )
    if assignment_id.rsplit("/", 1)[-1] != assignment_name:
        raise EffectiveAccessError(f"{field} name does not match its ID")
    return {
        "id": assignment_id,
        "principalId": assignment_principal_id,
        "principalType": principal_type,
        "roleDefinitionId": _string(
            properties.get("roleDefinitionId"),
            field=f"{field} role definition ID",
        ),
        "scope": scope,
        "conditionVersion": _optional_string(
            properties.get("conditionVersion"),
            field=f"{field} conditionVersion",
        ),
        "condition": _optional_string(
            properties.get("condition"),
            field=f"{field} condition",
        ),
    }


def _active_role_assignment_schedule_instances(
    principal_id: str,
    *,
    principal_type: str,
    subscription_id: str,
    governed_subscription_ids: frozenset[str],
    active_at: datetime,
    schedule_budget: _RoleAssignmentScheduleScanBudget,
    run_json: JsonRunner,
) -> list[dict[str, Any]]:
    subscription_scope = f"/subscriptions/{subscription_id}"
    query = urlencode(
        (
            ("api-version", ROLE_ASSIGNMENT_SCHEDULE_API_VERSION),
            ("$filter", f"principalId eq {principal_id}"),
        ),
        quote_via=quote,
    )
    next_url: str | None = (
        f"https://{ARM_HOST}{subscription_scope}/providers/"
        f"Microsoft.Authorization/roleAssignmentScheduleInstances?{query}"
    )
    active_assignments: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    seen_instance_ids: set[str] = set()
    for page_number in range(1, MAX_ROLE_ASSIGNMENT_SCHEDULE_PAGES + 1):
        if next_url is None:
            return active_assignments
        _validate_role_assignment_schedule_instances_url(
            next_url,
            subscription_id=subscription_id,
            principal_id=principal_id,
            first_page=page_number == 1,
        )
        if next_url in seen_urls:
            raise EffectiveAccessError(
                "active role-assignment schedule pagination contains a cycle"
            )
        seen_urls.add(next_url)
        if schedule_budget.api_calls >= MAX_ROLE_ASSIGNMENT_SCHEDULE_API_CALLS:
            raise EffectiveAccessError(
                "active role-assignment schedule API calls exceed their bound"
            )
        schedule_budget.api_calls += 1
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
                (
                    "active role-assignment schedules for "
                    f"{principal_type} {principal_id} in {subscription_scope} "
                    f"page {page_number}"
                ),
            ),
            field="active role-assignment schedule page",
        )
        values = page.get("value")
        if not isinstance(values, list):
            raise EffectiveAccessError(
                "active role-assignment schedule page must contain an array"
            )
        schedule_budget.instances += len(values)
        if schedule_budget.instances > MAX_ROLE_ASSIGNMENT_SCHEDULE_INSTANCES:
            raise EffectiveAccessError(
                "active role-assignment schedule instances exceed their bound"
            )
        for instance_index, raw_instance in enumerate(values):
            instance_id, active_assignment = _role_assignment_schedule_instance(
                raw_instance,
                principal_id=principal_id,
                principal_type=principal_type,
                governed_subscription_ids=governed_subscription_ids,
                active_at=active_at,
                field=(
                    "active role-assignment schedule "
                    f"page {page_number} item {instance_index}"
                ),
            )
            normalized_instance_id = instance_id.casefold()
            if normalized_instance_id in seen_instance_ids:
                raise EffectiveAccessError(
                    "active role-assignment schedule pages contain a duplicate"
                )
            seen_instance_ids.add(normalized_instance_id)
            if active_assignment is not None:
                active_assignments.append(active_assignment)
        continuation = page.get("nextLink")
        if continuation is None:
            return active_assignments
        elif isinstance(continuation, str) and continuation:
            next_url = continuation
        else:
            raise EffectiveAccessError(
                "active role-assignment schedule continuation is invalid"
            )
    raise EffectiveAccessError(
        "active role-assignment schedule pagination exceeded its bound"
    )


def _validate_role_assignment_schedule_instances_url(
    url: str,
    *,
    subscription_id: str,
    principal_id: str,
    first_page: bool,
) -> None:
    if len(url) > 16_384:
        raise EffectiveAccessError(
            "active role-assignment schedule continuation is oversized"
        )
    parsed = urlparse(url)
    expected_path = (
        f"/subscriptions/{subscription_id}/providers/"
        "Microsoft.Authorization/roleAssignmentScheduleInstances"
    )
    query = parse_qs(parsed.query, keep_blank_values=True)
    normalized_query: dict[str, list[str]] = {}
    for key, values in query.items():
        normalized_key = key.casefold()
        if normalized_key in normalized_query:
            raise EffectiveAccessError(
                "active role-assignment schedule continuation is invalid"
            )
        normalized_query[normalized_key] = values
    allowed_query_keys = {
        "api-version",
        "$filter",
        "$skiptoken",
    }
    continuation_keys = {"$skiptoken"} & normalized_query.keys()
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != ARM_HOST
        or parsed.path.casefold() != expected_path.casefold()
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(key not in allowed_query_keys for key in normalized_query)
        or any(len(values) != 1 or not values[0] for values in normalized_query.values())
        or normalized_query.get("api-version")
        != [ROLE_ASSIGNMENT_SCHEDULE_API_VERSION]
        or normalized_query.get("$filter") != [f"principalId eq {principal_id}"]
        or (first_page and continuation_keys)
        or (not first_page and len(continuation_keys) != 1)
    ):
        raise EffectiveAccessError(
            "active role-assignment schedule continuation is invalid"
        )


def _role_assignment_schedule_instance(
    value: object,
    *,
    principal_id: str,
    principal_type: str,
    governed_subscription_ids: frozenset[str],
    active_at: datetime,
    field: str,
) -> tuple[str, dict[str, Any] | None]:
    resource = _mapping(value, field=field)
    instance_name = _canonical_uuid(
        resource.get("name"),
        field=f"{field} name",
    )
    if str(resource.get("type", "")).casefold() != (
        "Microsoft.Authorization/roleAssignmentScheduleInstances"
    ).casefold():
        raise EffectiveAccessError(f"{field} type is invalid")
    properties = _mapping(
        resource.get("properties"),
        field=f"{field} properties",
    )
    schedule_principal_id = _canonical_uuid(
        properties.get("principalId"),
        field=f"{field} principal ID",
    )
    if schedule_principal_id != principal_id:
        raise EffectiveAccessError(f"{field} principal does not match its query")
    if properties.get("principalType") != principal_type:
        raise EffectiveAccessError(f"{field} principal type does not match its query")
    scope = _canonical_governed_scope(
        properties.get("scope"),
        governed_subscription_ids=governed_subscription_ids,
        field=f"{field} scope",
    )
    instance_id = _string(
        resource.get("id"),
        field=f"{field} ID",
    )
    scope_prefix = "" if scope == "/" else scope
    expected_instance_id = (
        f"{scope_prefix}/providers/Microsoft.Authorization/"
        f"roleAssignmentScheduleInstances/{instance_name}"
    )
    if instance_id.casefold() != expected_instance_id.casefold():
        raise EffectiveAccessError(f"{field} ID is not canonical for its scope")
    origin_role_assignment_id = _canonical_role_assignment_origin_id(
        properties.get("originRoleAssignmentId"),
        scope=scope,
        field=f"{field} origin role assignment ID",
    )
    role_definition_id = _string(
        properties.get("roleDefinitionId"),
        field=f"{field} role definition ID",
    )
    assignment_type = properties.get("assignmentType")
    if assignment_type not in {"Activated", "Assigned"}:
        raise EffectiveAccessError(f"{field} assignment type is invalid")
    member_type = properties.get("memberType")
    if member_type not in {"Direct", "Inherited", "Group"}:
        raise EffectiveAccessError(f"{field} member type is invalid")
    status = properties.get("status")
    if status not in _ROLE_ASSIGNMENT_SCHEDULE_STATUSES:
        raise EffectiveAccessError(f"{field} status is invalid")
    start_at = _utc_datetime(
        properties.get("startDateTime"),
        field=f"{field} startDateTime",
    )
    if "endDateTime" not in properties:
        raise EffectiveAccessError(f"{field} endDateTime is missing")
    raw_end_at = properties["endDateTime"]
    end_at = (
        None
        if raw_end_at is None
        else _utc_datetime(
            raw_end_at,
            field=f"{field} endDateTime",
        )
    )
    if end_at is not None and end_at <= start_at:
        raise EffectiveAccessError(f"{field} time window is invalid")
    condition_version = _optional_string(
        properties.get("conditionVersion"),
        field=f"{field} conditionVersion",
    )
    condition = _optional_string(
        properties.get("condition"),
        field=f"{field} condition",
    )
    if (
        active_at < start_at
        or (end_at is not None and active_at >= end_at)
        or status in _INACTIVE_ROLE_ASSIGNMENT_SCHEDULE_STATUSES
    ):
        return instance_id, None
    return (
        instance_id,
        {
            "id": origin_role_assignment_id,
            "principalId": schedule_principal_id,
            "principalType": principal_type,
            "roleDefinitionId": role_definition_id,
            "scope": scope,
            "conditionVersion": condition_version,
            "condition": condition,
        },
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
            return group_ids
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
                "principalType",
                "roleDefinitionId",
                "scope",
                "conditionVersion",
                "condition",
            ):
                existing_value = existing.get(property_name)
                incoming_value = assignment.get(property_name)
                if (
                    existing_value not in (None, "")
                    and incoming_value not in (None, "")
                    and (
                        (
                            property_name
                            in {
                                "principalId",
                                "principalType",
                                "roleDefinitionId",
                                "scope",
                            }
                            and str(existing_value).casefold()
                            != str(incoming_value).casefold()
                        )
                        or (
                            property_name in {"conditionVersion", "condition"}
                            and existing_value != incoming_value
                        )
                    )
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
    return any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=False,
        )
        for profile in profiles
        for action in ACR_PULL_ACTIONS
    ) or any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=True,
        )
        for profile in profiles
        for action in ACR_PULL_DATA_ACTIONS
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
    ) or any(
        _permission_profile_grants_action(
            profile,
            action,
            is_data_action=True,
        )
        for profile in profiles
        for action in ACR_ESCALATION_DATA_ACTIONS
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


def _canonical_governed_scope(
    value: object,
    *,
    governed_subscription_ids: frozenset[str],
    field: str,
) -> str:
    scope = _string(value, field=field)
    if scope == "/":
        return scope
    if (
        any(alias in scope for alias in ("//", "?", "#", "%"))
        or scope.endswith("/")
    ):
        raise EffectiveAccessError(f"{field} is not canonical")
    segments = scope.split("/")
    normalized = scope.casefold()
    if normalized.startswith("/subscriptions/"):
        if (
            len(segments) < 3
            or segments[0] != ""
            or segments[1].casefold() != "subscriptions"
            or any(not segment for segment in segments[1:])
        ):
            raise EffectiveAccessError(f"{field} is not canonical")
        scope_subscription_id = _canonical_uuid(
            segments[2],
            field=f"{field} subscription ID",
        )
        if scope_subscription_id not in governed_subscription_ids:
            raise EffectiveAccessError(f"{field} is outside the governed subscriptions")
        return scope
    if normalized.startswith("/providers/microsoft.management/managementgroups/"):
        if (
            len(segments) != 5
            or segments[0] != ""
            or segments[1].casefold() != "providers"
            or segments[2].casefold() != "microsoft.management"
            or segments[3].casefold() != "managementgroups"
            or not segments[4]
        ):
            raise EffectiveAccessError(f"{field} is not canonical")
        return scope
    raise EffectiveAccessError(f"{field} is outside the governed hierarchy")


def _canonical_role_assignment_origin_id(
    value: object,
    *,
    scope: str,
    field: str,
) -> str:
    origin_role_assignment_id = _string(value, field=field)
    assignment_guid = _canonical_uuid(
        origin_role_assignment_id.rsplit("/", 1)[-1],
        field=f"{field} UUID",
    )
    scope_prefix = "" if scope == "/" else scope
    expected_id = (
        f"{scope_prefix}/providers/Microsoft.Authorization/"
        f"roleAssignments/{assignment_guid}"
    )
    if origin_role_assignment_id.casefold() != expected_id.casefold():
        raise EffectiveAccessError(f"{field} is not canonical for its scope")
    return origin_role_assignment_id


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


def _optional_string(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field=field)


def _utc_datetime(value: object, *, field: str) -> datetime:
    timestamp = _string(value, field=field)
    if not (timestamp.endswith("Z") or timestamp.endswith("+00:00")):
        raise EffectiveAccessError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EffectiveAccessError(f"{field} must be a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EffectiveAccessError(f"{field} must be a UTC timestamp")
    return parsed.astimezone(UTC)


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
