from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from scripts.verify_wc027_acr_effective_access import (
    ABAC_ROLE_ASSIGNMENT_MODE,
    ACR_PULL_ROLE_ID,
    ACR_REPOSITORY_READER_ROLE_ID,
    EffectiveAccessError,
    ExpectedAssignment,
    _repository_condition,
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
REPOSITORY_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
    f"Microsoft.Authorization/roleDefinitions/{ACR_REPOSITORY_READER_ROLE_ID}"
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
        self.group_pages: dict[str, list[dict[str, object]]] = {
            item.principal_id: [{"value": []}] for item in expected
        }
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
        if command_tuple[1:4] == ("role", "assignment", "list"):
            principal_id = command_tuple[command_tuple.index("--assignee-object-id") + 1]
            subscription_id = command_tuple[command_tuple.index("--subscription") + 1]
            if subscription_id == SUBSCRIPTION_ID:
                source = self.inherited if "--include-inherited" in command_tuple else self.direct
            else:
                source = (
                    self.cross_subscription_inherited
                    if "--include-inherited" in command_tuple
                    else self.cross_subscription_direct
                )
            return deepcopy(source.get(principal_id, []))
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
    assignment_guid: str = "88888888-8888-4888-8888-888888888888",
    scope: str = SIBLING_REGISTRY_ID,
) -> dict[str, object]:
    return {
        "id": (f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_guid}"),
        "principalId": principal_id,
        "principalType": "ServicePrincipal",
        "roleDefinitionId": role_definition_id,
        "scope": scope,
        "conditionVersion": None,
        "condition": None,
    }


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
    assert evidence["acrEscalationPathsChecked"] is True
    assert str(evidence["evidenceDigest"]).startswith("sha256:")
    assert evidence["extraPullCapableAssignmentIds"] == []
    reviewed = evidence["reviewedAssignments"]
    assert isinstance(reviewed, list)
    assert {item["label"] for item in reviewed} == set(LABELS)
    assert all(item["conditionVersion"] == "2.0" for item in reviewed)
    assert all(
        item["condition"] == _repository_condition(item["repositoryName"]) for item in reviewed
    )
    assert sum(command[1:4] == ("role", "assignment", "list") for command in stub.commands) == 6


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
            role_definition_id=role_definition_id,
        )
    ]
    stub.inherited[group_id] = []

    with pytest.raises(EffectiveAccessError, match="group-derived"):
        _verify(stub)


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
                "Microsoft.ContainerRegistry/registries/repositories/content/read",
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleDefinitions/write",
                "Microsoft.ContainerRegistry/registries/write",
                "Microsoft.ContainerRegistry/registries/listCredentials/action",
                "Microsoft.ContainerRegistry/registries/regenerateCredential/action",
                "Microsoft.ContainerRegistry/registries/generateCredentials/action",
                "Microsoft.ContainerRegistry/registries/tokens/write",
                "Microsoft.ContainerRegistry/registries/scopeMaps/write",
            ),
        ),
        _permission(
            data_actions=("*",),
            not_data_actions=(
                "Microsoft.ContainerRegistry/registries/pull/read",
                "Microsoft.ContainerRegistry/registries/repositories/content/read",
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
        match="not exact|exact registry|principal type",
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

    with pytest.raises(EffectiveAccessError, match="must be an array"):
        _verify(stub)
