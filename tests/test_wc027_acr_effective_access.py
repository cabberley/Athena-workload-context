from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import pytest
import scripts.verify_wc027_acr_effective_access as acr_verifier
from scripts.verify_wc027_acr_effective_access import (
    ABAC_ROLE_ASSIGNMENT_MODE,
    ACR_ESCALATION_ACTIONS,
    ACR_ESCALATION_DATA_ACTIONS,
    ACR_PULL_ACTIONS,
    ACR_PULL_DATA_ACTIONS,
    ACR_PULL_ROLE_ID,
    ACR_QUARANTINE_READ_ACTION,
    ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,
    ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
    ACR_REPOSITORY_READER_ROLE_ID,
    EffectiveAccessError,
    ExpectedAssignment,
    _repository_condition,
    _role_definition_grants_acr_pull,
    verify_effective_access,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
TENANT_ID = "10101010-1010-4010-8010-101010101010"
CROSS_SUBSCRIPTION_ID = "12121212-1212-4212-8212-121212121212"
REGISTRY_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-shared-acr/"
    "providers/Microsoft.ContainerRegistry/registries/athenashared"
)
SIBLING_REGISTRY_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-shared-acr/"
    "providers/Microsoft.ContainerRegistry/registries/athenasibling"
)
CROSS_SUBSCRIPTION_REGISTRY_ID = (
    f"/subscriptions/{CROSS_SUBSCRIPTION_ID}/resourceGroups/rg-shared-acr/"
    "providers/Microsoft.ContainerRegistry/registries/athenacrosssub"
)
PRINCIPAL_IDS = (
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
)
LABELS = ("request-producer", "feed-producer", "publisher")
REPOSITORIES = (
    "athena/wc027-guidance-publication-request-producer",
    "athena/wc027-enrichment-feed-producer",
    "athena/wc027-guidance-authority-publisher",
)
ASSIGNMENT_GUIDS = (
    "55555555-5555-4555-8555-555555555555",
    "66666666-6666-4666-8666-666666666666",
    "77777777-7777-4777-8777-777777777777",
)
SCHEDULE_INSTANCE_GUIDS = (
    "51515151-5151-4151-8151-515151515151",
    "61616161-6161-4161-8161-616161616161",
    "71717171-7171-4171-8171-717171717171",
)
REPOSITORY_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
    f"Microsoft.Authorization/roleDefinitions/{ACR_REPOSITORY_READER_ROLE_ID}"
)
EXPECTED_ESCALATION_ACTIONS = (
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
EXPECTED_ESCALATION_DATA_ACTIONS = (
    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write",
)
EXPECTED_PULL_ACTIONS = (
    "Microsoft.ContainerRegistry/registries/pull/read",
    "Microsoft.ContainerRegistry/registries/quarantine/read",
)
EXPECTED_PULL_DATA_ACTIONS = (
    "Microsoft.ContainerRegistry/registries/repositories/content/read",
    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read",
)


def _expected_assignments() -> tuple[ExpectedAssignment, ...]:
    return tuple(
        ExpectedAssignment(
            label=label,
            principal_id=principal_id,
            assignment_resource_id=(
                f"{REGISTRY_ID}/providers/Microsoft.Authorization/roleAssignments/{assignment_guid}"
            ),
            registry_resource_id=REGISTRY_ID,
            repository_name=repository_name,
            role_assignment_mode=ABAC_ROLE_ASSIGNMENT_MODE,
        )
        for label, principal_id, repository_name, assignment_guid in zip(
            LABELS,
            PRINCIPAL_IDS,
            REPOSITORIES,
            ASSIGNMENT_GUIDS,
            strict=True,
        )
    )


def _permission(
    *,
    actions: Sequence[str] = (),
    not_actions: Sequence[str] = (),
    data_actions: Sequence[str] = (),
    not_data_actions: Sequence[str] = (),
) -> dict[str, object]:
    return {
        "actions": list(actions),
        "notActions": list(not_actions),
        "dataActions": list(data_actions),
        "notDataActions": list(not_data_actions),
    }


def _role_definition(
    role_definition_id: str,
    permission: dict[str, object],
) -> dict[str, object]:
    return {
        "id": role_definition_id,
        "properties": {
            "permissions": [permission],
        },
    }


def _grants_acr_pull(permission: dict[str, object]) -> bool:
    return _role_definition_grants_acr_pull(
        _role_definition(
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                "98989898-9898-4898-8898-989898989898"
            ),
            permission,
        )
    )


def _assignment(
    expected: ExpectedAssignment,
    *,
    assignment_id: str | None = None,
    principal_id: str | None = None,
    role_definition_id: str = REPOSITORY_READER_ROLE_DEFINITION_ID,
    scope: str = REGISTRY_ID,
    condition_version: str | None = "2.0",
    condition: str | None = None,
) -> dict[str, object]:
    return {
        "id": assignment_id or expected.assignment_resource_id,
        "principalId": principal_id or expected.principal_id,
        "principalType": "ServicePrincipal",
        "roleDefinitionId": role_definition_id,
        "scope": scope,
        "conditionVersion": condition_version,
        "condition": condition or _repository_condition(expected.repository_name),
    }


def _classic_role_assignment_resource(
    assignment: dict[str, object],
) -> dict[str, object]:
    assignment_id = str(assignment["id"])
    return {
        "id": assignment_id,
        "name": assignment_id.rsplit("/", 1)[-1],
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            key: value for key, value in assignment.items() if key != "id"
        },
    }


class StubAzure:
    def __init__(self) -> None:
        expected = _expected_assignments()
        self.anonymous_pull_enabled: object = False
        self.registry_role_assignment_mode: object = ABAC_ROLE_ASSIGNMENT_MODE
        self.tenant_subscription_ids = [SUBSCRIPTION_ID]
        self.direct: dict[str, object] = {
            item.principal_id: [_assignment(item)] for item in expected
        }
        self.inherited: dict[str, object] = {item.principal_id: [] for item in expected}
        self.cross_subscription_direct: dict[str, object] = {}
        self.cross_subscription_inherited: dict[str, object] = {}
        self.classic_pages: dict[
            tuple[str, str],
            list[dict[str, object]],
        ] = {}
        self.group_pages: dict[str, list[dict[str, object]]] = {
            item.principal_id: [{"value": []}] for item in expected
        }
        self.schedule_pages: dict[
            tuple[str, str],
            list[dict[str, object]],
        ] = {}
        self.assignment_readbacks: dict[str, dict[str, object]] = {
            item.assignment_resource_id.casefold(): {
                "id": item.assignment_resource_id,
                "properties": {
                    key: value for key, value in _assignment(item).items() if key != "id"
                },
            }
            for item in expected
        }
        self.roles: dict[str, dict[str, object]] = {
            REPOSITORY_READER_ROLE_DEFINITION_ID.casefold(): _role_definition(
                REPOSITORY_READER_ROLE_DEFINITION_ID,
                _permission(
                    data_actions=(
                        "Microsoft.ContainerRegistry/registries/repositories/content/read",
                        "Microsoft.ContainerRegistry/registries/repositories/metadata/read",
                    )
                ),
            )
        }
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str], field: str) -> object:
        del field
        command_tuple = tuple(command)
        self.commands.append(command_tuple)
        if command_tuple[1:3] == ("account", "show"):
            return {
                "id": SUBSCRIPTION_ID,
                "tenantId": TENANT_ID,
            }
        if command_tuple[1:3] == ("resource", "show"):
            resource_id = command_tuple[command_tuple.index("--ids") + 1]
            return {
                "id": resource_id,
                "properties": {
                    "roleAssignmentMode": self.registry_role_assignment_mode,
                    "anonymousPullEnabled": self.anonymous_pull_enabled,
                },
            }
        if command_tuple[1] == "rest":
            url = command_tuple[command_tuple.index("--url") + 1]
            if url.startswith("https://graph.microsoft.com/"):
                if "/servicePrincipals/" in url:
                    principal_id = url.split("/servicePrincipals/", 1)[1].split("/", 1)[0]
                else:
                    principal_id = url.split("/groups/", 1)[1].split("/", 1)[0]
                pages = self.group_pages.get(
                    principal_id,
                    [{"value": []}],
                )
                page_index = 0
                page_marker = (
                    "%24skiptoken=page" if "%24skiptoken=page" in url else "$skiptoken=page"
                )
                if page_marker in url:
                    page_index = int(url.rsplit(page_marker, 1)[1]) - 1
                return deepcopy(pages[page_index])
            if "/roleAssignments?" in url:
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                assignment_filter = query["$filter"][0]
                prefix = "principalId eq '"
                assert assignment_filter.startswith(prefix)
                assert assignment_filter.endswith("'")
                principal_id = assignment_filter[len(prefix) : -1]
                subscription_id = parsed.path.split("/subscriptions/", 1)[1].split("/", 1)[0]
                pages = self.classic_pages.get((subscription_id, principal_id))
                if pages is None:
                    if subscription_id == SUBSCRIPTION_ID:
                        direct_source = self.direct
                        inherited_source = self.inherited
                    else:
                        direct_source = self.cross_subscription_direct
                        inherited_source = self.cross_subscription_inherited
                    direct = direct_source.get(principal_id, [])
                    inherited = inherited_source.get(principal_id, [])
                    if not isinstance(direct, list):
                        return {"value": deepcopy(direct), "nextLink": None}
                    if not isinstance(inherited, list):
                        return {"value": deepcopy(inherited), "nextLink": None}
                    return {
                        "value": [
                            _classic_role_assignment_resource(assignment)
                            for assignment in [*direct, *inherited]
                        ],
                        "nextLink": None,
                    }
                page_index = 0
                continuation = query.get("$skiptoken")
                if continuation is not None:
                    page_index = int(continuation[0].removeprefix("page")) - 1
                return deepcopy(pages[page_index])
            if "/roleAssignmentScheduleInstances?" in url:
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                schedule_filter = query["$filter"][0]
                principal_id = schedule_filter.removeprefix("principalId eq ")
                subscription_id = parsed.path.split("/subscriptions/", 1)[1].split("/", 1)[0]
                pages = self.schedule_pages.get(
                    (subscription_id, principal_id),
                    [{"value": [], "nextLink": None}],
                )
                page_index = 0
                continuation = query.get("$skiptoken") or query.get("$skip")
                if continuation is not None:
                    page_index = int(continuation[0].removeprefix("page")) - 1
                return deepcopy(pages[page_index])
            if "/managementGroups/" in url and "/descendants?" in url:
                return {
                    "value": [
                        {
                            "id": f"/subscriptions/{subscription_id}",
                            "type": ("Microsoft.Management/managementGroups/subscriptions"),
                            "name": subscription_id,
                        }
                        for subscription_id in self.tenant_subscription_ids
                    ],
                    "nextLink": None,
                }
            role_definition_id = url.removeprefix("https://management.azure.com").split("?", 1)[0]
            if "/roleAssignments/" in role_definition_id:
                return deepcopy(self.assignment_readbacks[role_definition_id.casefold()])
            return deepcopy(self.roles[role_definition_id.casefold()])
        raise AssertionError(f"unexpected Azure command: {command_tuple}")


def _verify(stub: StubAzure) -> dict[str, object]:
    return verify_effective_access(
        _expected_assignments(),
        subscription_id=SUBSCRIPTION_ID,
        run_json=stub,
        verified_at=datetime(2026, 9, 17, 2, tzinfo=UTC),
    )


def _extra_assignment(
    *,
    principal_id: str,
    role_definition_id: str,
    principal_type: str = "ServicePrincipal",
    assignment_guid: str = "88888888-8888-4888-8888-888888888888",
    scope: str = SIBLING_REGISTRY_ID,
) -> dict[str, object]:
    return {
        "id": (f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_guid}"),
        "principalId": principal_id,
        "principalType": principal_type,
        "roleDefinitionId": role_definition_id,
        "scope": scope,
        "conditionVersion": None,
        "condition": None,
    }


def _schedule_instance(
    *,
    principal_id: str,
    principal_type: str,
    role_definition_id: str,
    instance_guid: str = "89898989-8989-4989-8989-898989898989",
    origin_role_assignment_id: str | None = None,
    scope: str = SIBLING_REGISTRY_ID,
    assignment_type: str = "Activated",
    status: str = "Provisioned",
    start_date_time: str = "2026-09-17T01:00:00Z",
    end_date_time: str | None = "2026-09-17T03:00:00Z",
    condition_version: str | None = None,
    condition: str | None = None,
) -> dict[str, object]:
    scope_prefix = "" if scope == "/" else scope
    effective_origin_role_assignment_id = origin_role_assignment_id or (
        f"{scope_prefix}/providers/Microsoft.Authorization/"
        f"roleAssignments/{instance_guid}"
    )
    return {
        "id": (
            f"{scope_prefix}/providers/Microsoft.Authorization/"
            f"roleAssignmentScheduleInstances/{instance_guid}"
        ),
        "name": instance_guid,
        "type": "Microsoft.Authorization/roleAssignmentScheduleInstances",
        "properties": {
            "principalId": principal_id,
            "principalType": principal_type,
            "roleDefinitionId": role_definition_id,
            "originRoleAssignmentId": effective_origin_role_assignment_id,
            "scope": scope,
            "assignmentType": assignment_type,
            "memberType": "Direct",
            "status": status,
            "startDateTime": start_date_time,
            "endDateTime": end_date_time,
            "conditionVersion": condition_version,
            "condition": condition,
        },
    }


def _schedule_next_link(principal_id: str, page_number: int) -> str:
    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleAssignmentScheduleInstances?"
        f"api-version=2020-10-01&%24filter=principalId%20eq%20{principal_id}"
        f"&%24skiptoken=page{page_number}"
    )


def _classic_next_link(principal_id: str, page_number: int) -> str:
    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleAssignments?"
        f"api-version=2022-04-01&%24filter=principalId%20eq%20%27{principal_id}%27"
        f"&%24skiptoken=page{page_number}"
    )


def test_acr_pull_action_contract_uses_exact_control_and_data_planes() -> None:
    assert ACR_PULL_ACTIONS == EXPECTED_PULL_ACTIONS
    assert ACR_PULL_DATA_ACTIONS == EXPECTED_PULL_DATA_ACTIONS


@pytest.mark.parametrize(
    "permission",
    (
        _permission(actions=(EXPECTED_PULL_ACTIONS[0],)),
        _permission(actions=(EXPECTED_PULL_ACTIONS[1],)),
        _permission(data_actions=(EXPECTED_PULL_DATA_ACTIONS[0],)),
        _permission(data_actions=(EXPECTED_PULL_DATA_ACTIONS[1],)),
    ),
)
def test_acr_pull_classifier_accepts_each_exact_pull_permission(
    permission: dict[str, object],
) -> None:
    assert _grants_acr_pull(permission)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(data_actions=(EXPECTED_PULL_ACTIONS[0],)),
        _permission(data_actions=(EXPECTED_PULL_ACTIONS[1],)),
        _permission(actions=(EXPECTED_PULL_DATA_ACTIONS[0],)),
        _permission(actions=(EXPECTED_PULL_DATA_ACTIONS[1],)),
    ),
)
def test_acr_pull_classifier_rejects_pull_permissions_in_the_wrong_plane(
    permission: dict[str, object],
) -> None:
    assert not _grants_acr_pull(permission)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(actions=("Microsoft.ContainerRegistry/registries/*",)),
        _permission(data_actions=("Microsoft.ContainerRegistry/registries/*",)),
    ),
)
def test_acr_pull_classifier_honors_wildcards_in_each_permission_plane(
    permission: dict[str, object],
) -> None:
    assert _grants_acr_pull(permission)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(
            actions=("Microsoft.ContainerRegistry/registries/*",),
            not_actions=EXPECTED_PULL_ACTIONS,
        ),
        _permission(
            data_actions=("Microsoft.ContainerRegistry/registries/*",),
            not_data_actions=EXPECTED_PULL_DATA_ACTIONS,
        ),
    ),
)
def test_acr_pull_classifier_honors_same_role_exclusions(
    permission: dict[str, object],
) -> None:
    assert not _grants_acr_pull(permission)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(actions=(EXPECTED_PULL_ACTIONS[0].upper(),)),
        _permission(actions=(EXPECTED_PULL_ACTIONS[1].upper(),)),
        _permission(data_actions=(EXPECTED_PULL_DATA_ACTIONS[0].upper(),)),
        _permission(data_actions=(EXPECTED_PULL_DATA_ACTIONS[1].upper(),)),
    ),
)
def test_acr_pull_classifier_is_case_insensitive(
    permission: dict[str, object],
) -> None:
    assert _grants_acr_pull(permission)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(
            data_actions=(
                "Microsoft.ContainerRegistry/registries/repositories/metadata/read",
            )
        ),
        _permission(
            data_actions=(
                "Microsoft.ContainerRegistry/registries/repositories/catalog/read",
            )
        ),
        _permission(actions=("Microsoft.ContainerRegistry/registries/read",)),
        _permission(
            actions=(
                "Microsoft.ContainerRegistry/registries/listCredentials/action",
            )
        ),
    ),
)
def test_acr_pull_classifier_rejects_non_pull_registry_permissions(
    permission: dict[str, object],
) -> None:
    assert not _grants_acr_pull(permission)


@pytest.mark.parametrize(
    ("role_name", "permission"),
    (
        (
            "AcrPull",
            _permission(actions=(ACR_PULL_ACTIONS[0],)),
        ),
        (
            "Container Registry Repository Reader",
            _permission(
                data_actions=(
                    ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                    "Microsoft.ContainerRegistry/registries/repositories/metadata/read",
                )
            ),
        ),
        (
            "AcrQuarantineReader",
            _permission(
                actions=(ACR_QUARANTINE_READ_ACTION,),
                data_actions=(ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,),
            ),
        ),
        (
            "AcrQuarantineWriter",
            _permission(
                actions=(
                    ACR_QUARANTINE_READ_ACTION,
                    "Microsoft.ContainerRegistry/registries/quarantine/write",
                ),
                data_actions=(
                    ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,
                    "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write",
                ),
            ),
        ),
    ),
)
def test_acr_pull_classifier_recognizes_pull_capable_built_in_role_shapes(
    role_name: str,
    permission: dict[str, object],
) -> None:
    assert role_name
    assert _grants_acr_pull(permission)


def test_effective_access_accepts_only_the_three_exact_direct_assignments() -> None:
    stub = StubAzure()

    evidence = _verify(stub)

    assert evidence["verified"] is True
    assert evidence["tenantId"] == TENANT_ID
    assert evidence["tenantSubscriptionHierarchyComplete"] is True
    assert evidence["governedSubscriptionIds"] == [SUBSCRIPTION_ID]
    assert evidence["anonymousPullEnabled"] is False
    assert evidence["expectedAssignmentCount"] == 3
    assert evidence["pullCapableAssignmentCount"] == 3
    assert evidence["exactAssignmentReadbacksComplete"] is True
    assert evidence["directMembershipTraversalComplete"] is True
    assert evidence["convergedMembershipReadbacks"] is True
    assert evidence["roleAssignmentScheduleInstancesComplete"] is True
    assert evidence["acrEscalationPathsChecked"] is True
    assert evidence["completeness"] == {
        "classicRoleAssignments": True,
        "pimRoleAssignmentScheduleInstances": True,
        "transitiveGroups": True,
        "siblingRegistries": True,
        "acrEscalationPaths": True,
        "exactAssignmentReadbacks": True,
        "paginationBudgets": True,
    }
    assert evidence["paginationBudgets"] == {
        "tenantHierarchyMaxPages": 64,
        "governedSubscriptionMaxCount": 4096,
        "graphMembershipMaxPagesPerObject": 16,
        "transitiveGroupMaxCountPerPrincipal": 4096,
        "classicRoleAssignmentMaxPagesPerQuery": 64,
        "classicRoleAssignmentMaxApiCalls": 16_384,
        "classicRoleAssignmentMaxItems": 65_536,
        "roleAssignmentScheduleMaxPagesPerQuery": 64,
        "roleAssignmentScheduleMaxApiCalls": 16_384,
        "roleAssignmentScheduleMaxInstances": 65_536,
    }
    assert str(evidence["evidenceDigest"]).startswith("sha256:")
    assert evidence["extraPullCapableAssignmentIds"] == []
    reviewed = evidence["reviewedAssignments"]
    assert isinstance(reviewed, list)
    assert {item["label"] for item in reviewed} == set(LABELS)
    assert all(item["conditionVersion"] == "2.0" for item in reviewed)
    assert all(
        item["condition"] == _repository_condition(item["repositoryName"]) for item in reviewed
    )
    assert sum(
        command[1] == "rest"
        and "/roleAssignments?" in command[command.index("--url") + 1]
        for command in stub.commands
    ) == 3
    assert sum(
        command[1] == "rest"
        and "/roleAssignmentScheduleInstances?" in command[command.index("--url") + 1]
        for command in stub.commands
    ) == 3


def test_effective_access_accepts_expected_assignment_schedule_mirrors() -> None:
    stub = StubAzure()
    for expected, schedule_instance_guid in zip(
        _expected_assignments(),
        SCHEDULE_INSTANCE_GUIDS,
        strict=True,
    ):
        stub.schedule_pages[(SUBSCRIPTION_ID, expected.principal_id)] = [
            {
                "value": [
                    _schedule_instance(
                        principal_id=expected.principal_id,
                        principal_type="ServicePrincipal",
                        role_definition_id=REPOSITORY_READER_ROLE_DEFINITION_ID,
                        instance_guid=schedule_instance_guid,
                        origin_role_assignment_id=expected.assignment_resource_id,
                        scope=REGISTRY_ID,
                        assignment_type="Assigned",
                        status="Accepted",
                        end_date_time=None,
                        condition_version="2.0",
                        condition=_repository_condition(expected.repository_name),
                    )
                ],
                "nextLink": None,
            }
        ]

    evidence = _verify(stub)

    assert evidence["verified"] is True
    assert evidence["pullCapableAssignmentCount"] == 3


def test_effective_access_accepts_legacy_acr_pull_only_with_null_conditions() -> None:
    stub = StubAzure()
    expected = tuple(
        replace(item, role_assignment_mode="LegacyRegistryPermissions")
        for item in _expected_assignments()
    )
    stub.registry_role_assignment_mode = "LegacyRegistryPermissions"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.direct = {
        item.principal_id: [
            {
                "id": item.assignment_resource_id,
                "principalId": item.principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_ID,
                "conditionVersion": None,
                "condition": None,
            }
        ]
        for item in expected
    }
    stub.assignment_readbacks = {
        item.assignment_resource_id.casefold(): {
            "id": item.assignment_resource_id,
            "properties": {
                key: value
                for key, value in stub.direct[item.principal_id][0].items()
                if key != "id"
            },
        }
        for item in expected
    }

    evidence = verify_effective_access(
        expected,
        subscription_id=SUBSCRIPTION_ID,
        run_json=stub,
        verified_at=datetime(2026, 9, 17, 2, tzinfo=UTC),
    )

    reviewed = evidence["reviewedAssignments"]
    assert isinstance(reviewed, list)
    assert all(item["roleDefinitionId"] == ACR_PULL_ROLE_ID for item in reviewed)
    assert all(item["conditionVersion"] is None for item in reviewed)
    assert all(item["condition"] is None for item in reviewed)


@pytest.mark.parametrize("anonymous_pull_enabled", (True, None))
def test_effective_access_rejects_anonymous_or_missing_posture(
    anonymous_pull_enabled: object,
) -> None:
    stub = StubAzure()
    stub.anonymous_pull_enabled = anonymous_pull_enabled

    with pytest.raises(
        EffectiveAccessError,
        match="anonymousPullEnabled must be explicitly false",
    ):
        _verify(stub)


def test_effective_access_rejects_live_registry_mode_drift() -> None:
    stub = StubAzure()
    stub.registry_role_assignment_mode = "LegacyRegistryPermissions"

    with pytest.raises(
        EffectiveAccessError,
        match="roleAssignmentMode does not match the reviewed mode",
    ):
        _verify(stub)


def test_effective_access_rejects_mixed_expected_modes_for_one_registry() -> None:
    stub = StubAzure()
    expected = list(_expected_assignments())
    expected[0] = replace(
        expected[0],
        role_assignment_mode="LegacyRegistryPermissions",
    )

    with pytest.raises(
        EffectiveAccessError,
        match="must use one reviewed role-assignment mode",
    ):
        verify_effective_access(
            expected,
            subscription_id=SUBSCRIPTION_ID,
            run_json=stub,
        )


def test_effective_access_rejects_mixed_modes_across_different_registries() -> None:
    stub = StubAzure()
    expected = list(_expected_assignments())
    expected[0] = replace(
        expected[0],
        registry_resource_id=SIBLING_REGISTRY_ID,
        assignment_resource_id=(
            f"{SIBLING_REGISTRY_ID}/providers/Microsoft.Authorization/"
            f"roleAssignments/{ASSIGNMENT_GUIDS[0]}"
        ),
        role_assignment_mode="LegacyRegistryPermissions",
    )

    with pytest.raises(
        EffectiveAccessError,
        match="must use one reviewed role-assignment mode",
    ):
        verify_effective_access(
            expected,
            subscription_id=SUBSCRIPTION_ID,
            run_json=stub,
        )


@pytest.mark.parametrize(
    ("case_name", "permission"),
    (
        (
            "acr-pull",
            _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
        ),
        (
            "acr-push",
            _permission(
                data_actions=("Microsoft.ContainerRegistry/registries/repositories/content/*",)
            ),
        ),
        (
            "repository-writer",
            _permission(
                data_actions=("Microsoft.ContainerRegistry/registries/repositories/content/read",)
            ),
        ),
        (
            "repository-contributor",
            _permission(actions=("Microsoft.ContainerRegistry/*",)),
        ),
        ("custom-wildcard", _permission(actions=("*",))),
        (
            "custom-content-read",
            _permission(
                data_actions=("Microsoft.ContainerRegistry/registries/repositories/content/read",)
            ),
        ),
        (
            "custom-quarantine-read",
            _permission(actions=(ACR_QUARANTINE_READ_ACTION,)),
        ),
        (
            "custom-quarantined-artifacts-read",
            _permission(
                data_actions=(ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,)
            ),
        ),
        (
            "role-assignment-writer",
            _permission(actions=("Microsoft.Authorization/roleAssignments/write",)),
        ),
        (
            "role-definition-writer",
            _permission(actions=("Microsoft.Authorization/roleDefinitions/write",)),
        ),
        (
            "acr-credential-admin",
            _permission(actions=("Microsoft.ContainerRegistry/registries/listCredentials/action",)),
        ),
    ),
)
def test_effective_access_rejects_extra_sibling_registry_pull_roles(
    case_name: str,
    permission: dict[str, object],
) -> None:
    stub = StubAzure()
    role_guid = {
        "acr-pull": ACR_PULL_ROLE_ID,
        "acr-push": "8311e382-0749-4cb8-b61a-304f252e45ec",
        "repository-writer": "2a1e307c-b015-4ebd-883e-5b7698d27924",
        "repository-contributor": "41077137-e803-4205-871c-5a86e6a753b4",
        "custom-wildcard": "99999999-9999-4999-8999-999999999991",
        "custom-content-read": "99999999-9999-4999-8999-999999999992",
        "custom-quarantine-read": "99999999-9999-4999-8999-999999999989",
        "custom-quarantined-artifacts-read": "99999999-9999-4999-8999-999999999988",
        "role-assignment-writer": "99999999-9999-4999-8999-999999999994",
        "role-definition-writer": "99999999-9999-4999-8999-999999999995",
        "acr-credential-admin": "99999999-9999-4999-8999-999999999996",
    }[case_name]
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{role_guid}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        permission,
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
        )
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


def test_effective_access_rejects_cross_subscription_sibling_registry_pull() -> None:
    stub = StubAzure()
    stub.tenant_subscription_ids.append(CROSS_SUBSCRIPTION_ID)
    role_definition_id = (
        f"/subscriptions/{CROSS_SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.cross_subscription_direct[PRINCIPAL_IDS[0]] = [
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
            scope=CROSS_SUBSCRIPTION_REGISTRY_ID,
        )
    ]

    with pytest.raises(EffectiveAccessError, match="sibling-registry"):
        _verify(stub)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(actions=("Microsoft.Authorization/roleAssignments/write",)),
        _permission(actions=("Microsoft.Authorization/roleDefinitions/write",)),
        _permission(actions=("Microsoft.ContainerRegistry/registries/listCredentials/action",)),
    ),
)
def test_effective_access_rejects_root_scope_escalation_paths(
    permission: dict[str, object],
) -> None:
    stub = StubAzure()
    role_definition_id = (
        "/providers/Microsoft.Authorization/roleDefinitions/99999999-9999-4999-8999-999999999997"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        permission,
    )
    inherited = stub.inherited[PRINCIPAL_IDS[0]]
    assert isinstance(inherited, list)
    inherited.append(
        {
            "id": (
                "/providers/Microsoft.Authorization/roleAssignments/"
                "98989898-9898-4898-8898-989898989898"
            ),
            "principalId": PRINCIPAL_IDS[0],
            "principalType": "ServicePrincipal",
            "roleDefinitionId": role_definition_id,
            "scope": "/",
            "conditionVersion": None,
            "condition": None,
        }
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


def test_effective_access_escalation_action_contract_is_complete() -> None:
    assert set(ACR_ESCALATION_ACTIONS) == set(EXPECTED_ESCALATION_ACTIONS)
    assert set(ACR_ESCALATION_DATA_ACTIONS) == set(
        EXPECTED_ESCALATION_DATA_ACTIONS
    )


@pytest.mark.parametrize("action", EXPECTED_ESCALATION_ACTIONS)
def test_effective_access_rejects_every_control_plane_escalation_action(
    action: str,
) -> None:
    stub = StubAzure()
    is_authorization_action = action.startswith("Microsoft.Authorization/")
    role_definition_id = (
        "/providers/Microsoft.Authorization/roleDefinitions/"
        "95959595-9595-4595-8595-959595959595"
        if is_authorization_action
        else (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "95959595-9595-4595-8595-959595959595"
        )
    )
    scope = "/" if is_authorization_action else SIBLING_REGISTRY_ID
    scope_prefix = "" if scope == "/" else scope
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=(action,)),
    )
    inherited = stub.inherited[PRINCIPAL_IDS[0]]
    assert isinstance(inherited, list)
    inherited.append(
        {
            "id": (
                f"{scope_prefix}/providers/Microsoft.Authorization/roleAssignments/"
                "94949494-9494-4494-8494-949494949494"
            ),
            "principalId": PRINCIPAL_IDS[0],
            "principalType": "ServicePrincipal",
            "roleDefinitionId": role_definition_id,
            "scope": scope,
            "conditionVersion": None,
            "condition": None,
        }
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


@pytest.mark.parametrize("action", EXPECTED_ESCALATION_DATA_ACTIONS)
def test_effective_access_rejects_every_data_plane_escalation_action(
    action: str,
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "96969696-9696-4696-8696-969696969696"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(data_actions=(action,)),
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
        )
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


def test_effective_access_rejects_inherited_pull_assignment() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    inherited = stub.inherited[PRINCIPAL_IDS[1]]
    assert isinstance(inherited, list)
    inherited.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[1],
            role_definition_id=role_definition_id,
        )
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


def test_effective_access_rejects_transitive_group_pull_assignment() -> None:
    stub = StubAzure()
    group_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.group_pages[PRINCIPAL_IDS[2]] = [
        {
            "@odata.count": 1,
            "value": [
                {
                    "@odata.type": "#microsoft.graph.group",
                    "id": group_id,
                }
            ],
        }
    ]
    stub.direct[group_id] = [
        _extra_assignment(
            principal_id=group_id,
            principal_type="Group",
            role_definition_id=role_definition_id,
        )
    ]
    stub.inherited[group_id] = []

    with pytest.raises(EffectiveAccessError, match="group-derived"):
        _verify(stub)


@pytest.mark.parametrize("assignment_type", ("Activated", "Assigned"))
def test_effective_access_rejects_unreviewed_active_schedule_assignment(
    assignment_type: str,
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[0],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                    assignment_type=assignment_type,
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(EffectiveAccessError, match="active-PIM"):
        _verify(stub)


def test_effective_access_rejects_schedule_instance_without_origin_assignment() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    instance = _schedule_instance(
        principal_id=PRINCIPAL_IDS[0],
        principal_type="ServicePrincipal",
        role_definition_id=role_definition_id,
    )
    properties = instance["properties"]
    assert isinstance(properties, dict)
    del properties["originRoleAssignmentId"]
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [instance],
            "nextLink": None,
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="origin role assignment ID must be a non-empty string",
    ):
        _verify(stub)


def test_effective_access_rejects_expected_schedule_mirror_condition_drift() -> None:
    stub = StubAzure()
    expected = _expected_assignments()[0]
    stub.schedule_pages[(SUBSCRIPTION_ID, expected.principal_id)] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=expected.principal_id,
                    principal_type="ServicePrincipal",
                    role_definition_id=REPOSITORY_READER_ROLE_DEFINITION_ID,
                    instance_guid=ASSIGNMENT_GUIDS[0],
                    origin_role_assignment_id=expected.assignment_resource_id,
                    scope=REGISTRY_ID,
                    assignment_type="Assigned",
                    status="Accepted",
                    condition_version="2.0",
                    condition=_repository_condition("athena/other-repository"),
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="conflicting duplicate assignment",
    ):
        _verify(stub)


def test_effective_access_rejects_cross_subscription_active_pim_assignment() -> None:
    stub = StubAzure()
    stub.tenant_subscription_ids.append(CROSS_SUBSCRIPTION_ID)
    role_definition_id = (
        f"/subscriptions/{CROSS_SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.schedule_pages[(CROSS_SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[0],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                    scope=CROSS_SUBSCRIPTION_REGISTRY_ID,
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(EffectiveAccessError, match="sibling-registry"):
        _verify(stub)


def test_effective_access_ignores_not_yet_active_assignment_schedule_instance() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[0],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                    start_date_time="2026-09-17T03:00:00Z",
                    end_date_time="2026-09-17T04:00:00Z",
                )
            ],
            "nextLink": None,
        }
    ]

    assert _verify(stub)["verified"] is True


def test_effective_access_rejects_schedule_instance_principal_mismatch() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[1],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="principal does not match its query",
    ):
        _verify(stub)


@pytest.mark.parametrize(
    "action",
    (
        "Microsoft.Authorization/roleAssignmentScheduleRequests/write",
        "Microsoft.Authorization/roleEligibilityScheduleRequests/write",
        (
            "Microsoft.Authorization/roleEligibilityScheduleRequests/"
            "whenApprovalRequired/write"
        ),
        "Microsoft.Authorization/roleManagementPolicies/write",
        "Microsoft.Authorization/roleManagementPolicies/approvalRule/action",
    ),
)
def test_effective_access_rejects_schedule_administration_custom_roles(
    action: str,
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "90909090-9090-4090-8090-909090909090"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=(action,)),
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
        )
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


def test_effective_access_rejects_active_pim_schedule_administration_role() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "93939393-9393-4393-8393-939393939393"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(
            actions=("Microsoft.Authorization/roleAssignmentScheduleRequests/write",)
        ),
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[1])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[1],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(EffectiveAccessError, match="active-PIM"):
        _verify(stub)


def test_effective_access_rejects_transitive_group_active_pim_assignment() -> None:
    stub = StubAzure()
    group_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.group_pages[PRINCIPAL_IDS[1]] = [
        {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.group",
                    "id": group_id,
                }
            ]
        }
    ]
    stub.schedule_pages[(SUBSCRIPTION_ID, group_id)] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=group_id,
                    principal_type="Group",
                    role_definition_id=role_definition_id,
                )
            ],
            "nextLink": None,
        }
    ]

    with pytest.raises(EffectiveAccessError, match="group-derived"):
        _verify(stub)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(actions=(ACR_QUARANTINE_READ_ACTION,)),
        _permission(
            data_actions=(ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,)
        ),
    ),
)
@pytest.mark.parametrize("assignment_source", ("direct", "inherited", "transitive-group"))
def test_effective_access_rejects_quarantine_pull_paths(
    permission: dict[str, object],
    assignment_source: str,
) -> None:
    stub = StubAzure()
    group_id = "abababab-abab-4bab-8bab-abababababab"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "91919191-9191-4191-8191-919191919191"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        permission,
    )
    assignment_principal_id = (
        group_id if assignment_source == "transitive-group" else PRINCIPAL_IDS[2]
    )
    assignment = _extra_assignment(
        principal_id=assignment_principal_id,
        principal_type=(
            "Group" if assignment_source == "transitive-group" else "ServicePrincipal"
        ),
        role_definition_id=role_definition_id,
    )
    if assignment_source == "direct":
        direct = stub.direct[PRINCIPAL_IDS[2]]
        assert isinstance(direct, list)
        direct.append(assignment)
    elif assignment_source == "inherited":
        inherited = stub.inherited[PRINCIPAL_IDS[2]]
        assert isinstance(inherited, list)
        inherited.append(assignment)
    else:
        stub.group_pages[PRINCIPAL_IDS[2]] = [
            {
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.group",
                        "id": group_id,
                    }
                ]
            }
        ]
        stub.direct[group_id] = [assignment]
        stub.inherited[group_id] = []

    with pytest.raises(EffectiveAccessError, match="pull-capable assignment"):
        _verify(stub)


@pytest.mark.parametrize(
    "permission",
    (
        _permission(data_actions=(ACR_QUARANTINE_READ_ACTION,)),
        _permission(actions=(ACR_QUARANTINED_ARTIFACTS_READ_DATA_ACTION,)),
    ),
)
def test_effective_access_ignores_quarantine_permissions_in_the_wrong_plane(
    permission: dict[str, object],
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "92929292-9292-4292-8292-929292929292"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        permission,
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
        )
    )

    assert _verify(stub)["verified"] is True


def test_effective_access_rejects_missing_expected_assignment() -> None:
    stub = StubAzure()
    stub.direct[PRINCIPAL_IDS[0]] = []

    with pytest.raises(EffectiveAccessError, match="missing an exact reviewed"):
        _verify(stub)


def test_effective_access_rejects_cross_component_expected_repository() -> None:
    stub = StubAzure()
    expected = list(_expected_assignments())
    expected[0] = replace(
        expected[0],
        repository_name="athena/wc027-guidance-authority-publisher",
    )

    with pytest.raises(
        EffectiveAccessError,
        match="does not match its digest-pinned image contract",
    ):
        verify_effective_access(
            expected,
            subscription_id=SUBSCRIPTION_ID,
            run_json=stub,
        )


@pytest.mark.parametrize(
    "permission",
    (
        _permission(
            actions=("*",),
            not_actions=(
                "Microsoft.ContainerRegistry/registries/pull/read",
                "Microsoft.ContainerRegistry/registries/quarantine/read",
                "Microsoft.Authorization/elevateAccess/action",
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleAssignmentScheduleRequests/write",
                "Microsoft.Authorization/roleEligibilityScheduleRequests/write",
                (
                    "Microsoft.Authorization/roleEligibilityScheduleRequests/"
                    "whenApprovalRequired/write"
                ),
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
            ),
        ),
        _permission(
            data_actions=("*",),
            not_data_actions=(
                "Microsoft.ContainerRegistry/registries/repositories/content/read",
                "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read",
                "Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write",
            ),
        ),
    ),
)
def test_effective_access_honors_not_actions_and_not_data_actions(
    permission: dict[str, object],
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "99999999-9999-4999-8999-999999999993"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        permission,
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.append(
        _extra_assignment(
            principal_id=PRINCIPAL_IDS[0],
            role_definition_id=role_definition_id,
        )
    )

    assert _verify(stub)["verified"] is True


@pytest.mark.parametrize(
    ("excluded_permission", "regrant_permission"),
    (
        (
            _permission(
                actions=("*",),
                not_actions=EXPECTED_PULL_ACTIONS + EXPECTED_ESCALATION_ACTIONS,
            ),
            _permission(actions=(EXPECTED_PULL_ACTIONS[0],)),
        ),
        (
            _permission(
                data_actions=("*",),
                not_data_actions=(
                    EXPECTED_PULL_DATA_ACTIONS + EXPECTED_ESCALATION_DATA_ACTIONS
                ),
            ),
            _permission(data_actions=(EXPECTED_PULL_DATA_ACTIONS[0],)),
        ),
    ),
)
def test_effective_access_second_role_regrant_wins_over_other_role_exclusion(
    excluded_permission: dict[str, object],
    regrant_permission: dict[str, object],
) -> None:
    stub = StubAzure()
    excluded_role_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "97979797-9797-4797-8797-979797979797"
    )
    regrant_role_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "98989898-9898-4898-8898-989898989897"
    )
    stub.roles[excluded_role_id.casefold()] = _role_definition(
        excluded_role_id,
        excluded_permission,
    )
    stub.roles[regrant_role_id.casefold()] = _role_definition(
        regrant_role_id,
        regrant_permission,
    )
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    direct.extend(
        (
            _extra_assignment(
                principal_id=PRINCIPAL_IDS[0],
                role_definition_id=excluded_role_id,
                assignment_guid="97979797-9797-4797-8797-979797979798",
            ),
            _extra_assignment(
                principal_id=PRINCIPAL_IDS[0],
                role_definition_id=regrant_role_id,
                assignment_guid="98989898-9898-4898-8898-989898989899",
            ),
        )
    )

    with pytest.raises(EffectiveAccessError, match="unreviewed direct"):
        _verify(stub)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("conditionVersion", None),
        ("condition", _repository_condition("athena/other-repository")),
        ("scope", SIBLING_REGISTRY_ID),
        ("principalType", "Group"),
        (
            "roleDefinitionId",
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
            ),
        ),
    ),
)
def test_effective_access_rejects_expected_assignment_profile_drift(
    field: str,
    value: object,
) -> None:
    stub = StubAzure()
    direct = stub.direct[PRINCIPAL_IDS[0]]
    assert isinstance(direct, list)
    assignment = direct[0]
    assert isinstance(assignment, dict)
    assignment[field] = value
    if field == "roleDefinitionId":
        role_definition_id = str(value)
        stub.roles[role_definition_id.casefold()] = _role_definition(
            role_definition_id,
            _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
        )

    with pytest.raises(
        EffectiveAccessError,
        match="not exact|exact registry|principal type|canonical for its scope",
    ):
        _verify(stub)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        (
            "condition",
            _repository_condition("athena/other-repository"),
            "assignment condition is not exact",
        ),
        (
            "principalId",
            PRINCIPAL_IDS[1],
            "assignment principal is not exact",
        ),
        (
            "principalType",
            "Group",
            "assignment principal type must be ServicePrincipal",
        ),
    ),
)
def test_effective_access_rejects_exact_assignment_readback_drift(
    field: str,
    value: object,
    match: str,
) -> None:
    stub = StubAzure()
    expected = _expected_assignments()[0]
    readback = stub.assignment_readbacks[expected.assignment_resource_id.casefold()]
    properties = readback["properties"]
    assert isinstance(properties, dict)
    properties[field] = value

    with pytest.raises(EffectiveAccessError, match=match):
        _verify(stub)


@pytest.mark.parametrize(
    "registry_resource_id",
    (
        f"{REGISTRY_ID}?api-version=2025-04-01",
        f"{REGISTRY_ID}#fragment",
        f"{REGISTRY_ID}%2Fchild",
        REGISTRY_ID.replace("/resourceGroups/", "//resourceGroups/"),
        f"{REGISTRY_ID}/",
    ),
)
def test_effective_access_rejects_noncanonical_registry_resource_id(
    registry_resource_id: str,
) -> None:
    stub = StubAzure()
    expected = list(_expected_assignments())
    expected[0] = replace(
        expected[0],
        registry_resource_id=registry_resource_id,
        assignment_resource_id=(
            f"{registry_resource_id}/providers/Microsoft.Authorization/"
            f"roleAssignments/{ASSIGNMENT_GUIDS[0]}"
        ),
    )

    with pytest.raises(
        EffectiveAccessError,
        match="canonical ACR resource ID",
    ):
        verify_effective_access(
            expected,
            subscription_id=SUBSCRIPTION_ID,
            run_json=stub,
        )


def test_effective_access_follows_classic_role_assignment_pagination() -> None:
    stub = StubAzure()
    expected = _expected_assignments()[0]
    stub.classic_pages[(SUBSCRIPTION_ID, expected.principal_id)] = [
        {
            "value": [],
            "nextLink": _classic_next_link(expected.principal_id, 2),
        },
        {
            "value": [
                _classic_role_assignment_resource(_assignment(expected))
            ],
            "nextLink": None,
        },
    ]

    assert _verify(stub)["verified"] is True


def test_effective_access_rejects_untrusted_classic_assignment_continuation() -> None:
    stub = StubAzure()
    stub.classic_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [],
            "nextLink": (
                "https://evil.example/subscriptions/"
                f"{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments?"
                "api-version=2022-04-01&"
                f"%24filter=principalId%20eq%20%27{PRINCIPAL_IDS[0]}%27&"
                "%24skiptoken=page2"
            ),
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="classic role-assignment continuation is invalid",
    ):
        _verify(stub)


def test_effective_access_rejects_classic_pagination_over_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    expected = _expected_assignments()[0]
    stub.classic_pages[(SUBSCRIPTION_ID, expected.principal_id)] = [
        {
            "value": [
                _classic_role_assignment_resource(_assignment(expected))
            ],
            "nextLink": _classic_next_link(expected.principal_id, 2),
        }
    ]
    monkeypatch.setattr(acr_verifier, "MAX_CLASSIC_ROLE_ASSIGNMENT_PAGES", 1)

    with pytest.raises(
        EffectiveAccessError,
        match="classic role-assignment pagination exceeded its bound",
    ):
        _verify(stub)


def test_effective_access_accepts_terminal_pages_at_exact_page_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    monkeypatch.setattr(acr_verifier, "MAX_TENANT_HIERARCHY_PAGES", 1)
    monkeypatch.setattr(acr_verifier, "MAX_GRAPH_MEMBERSHIP_PAGES", 1)
    monkeypatch.setattr(acr_verifier, "MAX_CLASSIC_ROLE_ASSIGNMENT_PAGES", 1)
    monkeypatch.setattr(acr_verifier, "MAX_ROLE_ASSIGNMENT_SCHEDULE_PAGES", 1)

    assert _verify(stub)["verified"] is True


def test_effective_access_follows_role_assignment_schedule_pagination() -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.roles[role_definition_id.casefold()] = _role_definition(
        role_definition_id,
        _permission(actions=("Microsoft.ContainerRegistry/registries/pull/read",)),
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [],
            "nextLink": _schedule_next_link(PRINCIPAL_IDS[0], 2),
        },
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[0],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                )
            ],
            "nextLink": None,
        },
    ]

    with pytest.raises(EffectiveAccessError, match="active-PIM"):
        _verify(stub)


def test_effective_access_rejects_untrusted_schedule_continuation() -> None:
    stub = StubAzure()
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [],
            "nextLink": (
                "https://evil.example/subscriptions/"
                f"{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
                "roleAssignmentScheduleInstances?"
                f"api-version=2020-10-01&%24filter=principalId%20eq%20{PRINCIPAL_IDS[0]}"
                "&%24skiptoken=page2"
            ),
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="role-assignment schedule continuation is invalid",
    ):
        _verify(stub)


def test_effective_access_rejects_schedule_pagination_over_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [],
            "nextLink": _schedule_next_link(PRINCIPAL_IDS[0], 2),
        }
    ]
    monkeypatch.setattr(acr_verifier, "MAX_ROLE_ASSIGNMENT_SCHEDULE_PAGES", 1)

    with pytest.raises(
        EffectiveAccessError,
        match="schedule pagination exceeded its bound",
    ):
        _verify(stub)


def test_effective_access_rejects_schedule_query_set_over_call_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    monkeypatch.setattr(acr_verifier, "MAX_ROLE_ASSIGNMENT_SCHEDULE_API_CALLS", 2)

    with pytest.raises(
        EffectiveAccessError,
        match="query set exceeds its API call bound",
    ):
        _verify(stub)


def test_effective_access_rejects_classic_query_set_over_call_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    monkeypatch.setattr(acr_verifier, "MAX_CLASSIC_ROLE_ASSIGNMENT_API_CALLS", 2)

    with pytest.raises(
        EffectiveAccessError,
        match="classic role-assignment query set exceeds its API call bound",
    ):
        _verify(stub)


def test_effective_access_rejects_classic_assignment_items_over_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    monkeypatch.setattr(acr_verifier, "MAX_CLASSIC_ROLE_ASSIGNMENTS", 2)

    with pytest.raises(
        EffectiveAccessError,
        match="classic role-assignment items exceed their bound",
    ):
        _verify(stub)


def test_effective_access_rejects_schedule_instance_count_over_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAzure()
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ACR_PULL_ROLE_ID}"
    )
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "value": [
                _schedule_instance(
                    principal_id=PRINCIPAL_IDS[0],
                    principal_type="ServicePrincipal",
                    role_definition_id=role_definition_id,
                    start_date_time="2026-09-17T03:00:00Z",
                    end_date_time="2026-09-17T04:00:00Z",
                )
            ],
            "nextLink": None,
        }
    ]
    monkeypatch.setattr(acr_verifier, "MAX_ROLE_ASSIGNMENT_SCHEDULE_INSTANCES", 0)

    with pytest.raises(
        EffectiveAccessError,
        match="schedule instances exceed their bound",
    ):
        _verify(stub)


def test_effective_access_fails_closed_when_schedule_read_fails() -> None:
    stub = StubAzure()

    def failing_schedule_read(command: Sequence[str], field: str) -> object:
        command_tuple = tuple(command)
        if command_tuple[1] == "rest":
            url = command_tuple[command_tuple.index("--url") + 1]
            if "/roleAssignmentScheduleInstances?" in url:
                raise EffectiveAccessError("synthetic schedule read failed")
        return stub(command, field)

    with pytest.raises(EffectiveAccessError, match="synthetic schedule read failed"):
        verify_effective_access(
            _expected_assignments(),
            subscription_id=SUBSCRIPTION_ID,
            run_json=failing_schedule_read,
        )


def test_effective_access_rejects_incomplete_schedule_page() -> None:
    stub = StubAzure()
    stub.schedule_pages[(SUBSCRIPTION_ID, PRINCIPAL_IDS[0])] = [
        {
            "notValue": [],
            "nextLink": None,
        }
    ]

    with pytest.raises(
        EffectiveAccessError,
        match="schedule page must contain an array",
    ):
        _verify(stub)


def test_effective_access_rejects_incomplete_graph_pagination() -> None:
    stub = StubAzure()
    stub.group_pages[PRINCIPAL_IDS[0]] = [
        {
            "value": [],
            "@odata.nextLink": (
                "https://graph.microsoft.com/v1.0/servicePrincipals/"
                f"{PRINCIPAL_IDS[0]}/memberOf?%24skiptoken=page2"
            ),
        },
        {
            "notValue": [],
        },
    ]

    with pytest.raises(EffectiveAccessError, match="must contain an array"):
        _verify(stub)


def test_effective_access_rejects_untrusted_graph_continuation() -> None:
    stub = StubAzure()
    stub.group_pages[PRINCIPAL_IDS[0]] = [
        {
            "value": [],
            "@odata.nextLink": (
                "https://evil.example/v1.0/servicePrincipals/"
                f"{PRINCIPAL_IDS[0]}/memberOf?%24skiptoken=opaque"
            ),
        }
    ]

    with pytest.raises(EffectiveAccessError, match="continuation is invalid"):
        _verify(stub)


def test_effective_access_requires_converged_direct_membership_reads() -> None:
    stub = StubAzure()
    group_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    membership_calls = 0

    def changing_membership(command: Sequence[str], field: str) -> object:
        nonlocal membership_calls
        command_tuple = tuple(command)
        if command_tuple[1] == "rest":
            url = command_tuple[command_tuple.index("--url") + 1]
            if (
                url.startswith("https://graph.microsoft.com/")
                and f"/servicePrincipals/{PRINCIPAL_IDS[0]}/memberOf" in url
            ):
                membership_calls += 1
                if membership_calls == 1:
                    return {"value": []}
                return {
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.group",
                            "id": group_id,
                        }
                    ]
                }
        return stub(command, field)

    with pytest.raises(EffectiveAccessError, match="did not converge"):
        verify_effective_access(
            _expected_assignments(),
            subscription_id=SUBSCRIPTION_ID,
            run_json=changing_membership,
        )


def test_effective_access_rejects_incomplete_assignment_document() -> None:
    stub = StubAzure()
    stub.direct[PRINCIPAL_IDS[0]] = {"value": []}

    with pytest.raises(EffectiveAccessError, match="must contain an array"):
        _verify(stub)
