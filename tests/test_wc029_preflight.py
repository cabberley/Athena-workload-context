from __future__ import annotations

import json
from io import StringIO

import pytest

from athena_context.cli import main as cli_main
from athena_context.wc029_preflight import (
    PreflightInputError,
    evaluate_role_assignments,
    evaluate_what_if,
    load_json_file,
    main,
)

_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
_RG_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload"
_CONTAINER_APP_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/"
    "rg-athena-wc013-live/providers/Microsoft.App/containerApps/"
    "athena-presentation"
)
_CONTAINER_ENVIRONMENT_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/"
    "rg-athena-wc013-live/providers/Microsoft.App/managedEnvironments/"
    "athena-runtime"
)
_STORAGE_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/"
    "rg-athena-wc013-live/providers/Microsoft.Storage/storageAccounts/"
    "athenawc013synthetic"
)
_KEY_VAULT_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/"
    "rg-athena-wc013-live/providers/Microsoft.KeyVault/vaults/"
    "athena-synthetic-kv"
)
_STORAGE_CONTAINER_ID = f"{_STORAGE_ID}/blobServices/default/containers/evidence"
_KEY_VAULT_KEY_ID = f"{_KEY_VAULT_ID}/keys/report-signing"


def _what_if(*changes: object) -> dict[str, object]:
    return {
        "status": "Succeeded",
        "properties": {"changes": list(changes)},
    }


def _change(
    resource_id: str,
    change_type: str,
    *,
    path: str | None = None,
    after: object = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "resourceId": resource_id,
        "changeType": change_type,
    }
    if path is not None:
        value["delta"] = [
            {
                "path": path,
                "after": after,
                "propertyChangeType": "Modify",
            }
        ]
    return value


def _assignment(
    *,
    principal_id: str = "11111111-1111-1111-1111-111111111111",
    role_name: str | None = "Reader",
    role_id: str | None = None,
    scope: str = _RG_SCOPE,
    condition: str | None = None,
    condition_version: str | None = None,
) -> dict[str, str]:
    value = {
        "principalId": principal_id,
        "scope": scope,
    }
    if role_name is not None:
        value["roleDefinitionName"] = role_name
    if role_id is not None:
        value["roleDefinitionId"] = role_id
    if condition is not None:
        value["condition"] = condition
    if condition_version is not None:
        value["conditionVersion"] = condition_version
    return value


def _production_policy(
    *principal_ids: str,
    expected_assignments: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "expectedPrincipalIds": list(principal_ids),
        "expectedAssignments": (
            expected_assignments
            if expected_assignments is not None
            else [
                _assignment(principal_id=principal_id)
                for principal_id in principal_ids
            ]
        ),
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["Owner"],
                "forbiddenScopePrefixes": [
                    f"/subscriptions/{_SUBSCRIPTION_ID}",
                ],
            }
            for principal_id in principal_ids
        ],
    }


def test_what_if_accepts_no_change_and_exact_allowlist() -> None:
    document = _what_if(
        _change(_STORAGE_ID, "NoChange"),
        _change(
            _CONTAINER_APP_ID,
            "Modify",
            path="properties.template.containers[0].image",
            after="synthetic.azurecr.io/athena@sha256:" + "a" * 64,
        ),
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_CONTAINER_APP_ID.upper()}),
    )

    assert violations == ()


def test_what_if_requires_successful_complete_result() -> None:
    with pytest.raises(PreflightInputError, match="did not succeed"):
        evaluate_what_if(
            {
                "status": "Failed",
                "error": {"code": "SyntheticFailure"},
                "properties": {"changes": []},
            }
        )


def test_what_if_rejects_unresolved_potential_changes() -> None:
    document = {
        "status": "Succeeded",
        "properties": {
            "changes": [],
            "potentialChanges": [
                {
                    "resourceId": _STORAGE_ID,
                    "changeType": "Delete",
                }
            ],
        },
    }

    violations = evaluate_what_if(document)

    assert len(violations) == 1
    assert violations[0].code == "unpredictable-change"
    assert violations[0].subject == _STORAGE_ID


def test_what_if_rejects_malformed_potential_changes() -> None:
    document = {
        "status": "Succeeded",
        "properties": {
            "changes": [],
            "potentialChanges": [{"changeType": "Delete"}],
        },
    }

    with pytest.raises(
        PreflightInputError,
        match="potential change resourceId",
    ):
        evaluate_what_if(document)


@pytest.mark.parametrize(
    ("document", "code"),
    [
        (
            _what_if(_change(_STORAGE_ID, "Delete")),
            "delete",
        ),
        (
            _what_if(_change(_STORAGE_ID, "Create")),
            "unapproved-change",
        ),
        (
            _what_if(_change(_STORAGE_ID, "Replace")),
            "unsupported-change-type",
        ),
        (
            _what_if(_change(_STORAGE_ID, "Ignore")),
            "ignored-change",
        ),
        (
            _what_if(_change(_STORAGE_ID, "Deploy")),
            "unpredictable-change",
        ),
    ],
)
def test_what_if_rejects_unreviewed_changes(
    document: object,
    code: str,
) -> None:
    assert code in {item.code for item in evaluate_what_if(document)}


def test_what_if_never_allows_public_container_apps_exposure() -> None:
    document = _what_if(
        _change(
            _CONTAINER_APP_ID,
            "Modify",
            path="properties.configuration.ingress.external",
            after=True,
        )
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
    )

    assert {item.code for item in violations} == {"public-container-apps-exposure"}


@pytest.mark.parametrize(
    ("resource_id", "path", "safe_value", "unsafe_value"),
    [
        (
            _CONTAINER_APP_ID,
            "properties.configuration.ingress.external",
            False,
            True,
        ),
        (
            _CONTAINER_APP_ID,
            "properties.publicNetworkAccess",
            "Disabled",
            "Enabled",
        ),
        (
            _CONTAINER_ENVIRONMENT_ID,
            "properties.vnetConfiguration.internal",
            True,
            False,
        ),
        (
            _CONTAINER_ENVIRONMENT_ID,
            "properties.publicNetworkAccess",
            "Disabled",
            "Enabled",
        ),
    ],
)
def test_container_apps_network_properties_use_strict_safe_values(
    resource_id: str,
    path: str,
    safe_value: object,
    unsafe_value: object,
) -> None:
    safe = _what_if(
        _change(
            resource_id,
            "Modify",
            path=path,
            after=safe_value,
        )
    )
    unsafe = _what_if(
        _change(
            resource_id,
            "Modify",
            path=path,
            after=unsafe_value,
        )
    )

    assert (
        evaluate_what_if(
            safe,
            allowed_change_ids=frozenset({resource_id}),
        )
        == ()
    )
    assert {
        item.code
        for item in evaluate_what_if(
            unsafe,
            allowed_change_ids=frozenset({resource_id}),
        )
    } == {"public-container-apps-exposure"}


@pytest.mark.parametrize(
    ("resource_id", "path", "value"),
    [
        (
            _CONTAINER_APP_ID,
            "properties.configuration.ingress.external",
            "false",
        ),
        (
            _CONTAINER_APP_ID,
            "properties.publicNetworkAccess",
            "Bogus",
        ),
        (
            _CONTAINER_ENVIRONMENT_ID,
            "properties.vnetConfiguration.internal",
            "true",
        ),
    ],
)
def test_container_apps_network_properties_reject_malformed_values(
    resource_id: str,
    path: str,
    value: object,
) -> None:
    with pytest.raises(PreflightInputError, match="Container Apps"):
        evaluate_what_if(
            _what_if(
                _change(
                    resource_id,
                    "Modify",
                    path=path,
                    after=value,
                )
            ),
            allowed_change_ids=frozenset({resource_id}),
        )


def test_container_apps_network_parent_delta_requires_safe_leaf() -> None:
    safe = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.configuration.ingress",
                    "propertyChangeType": "Modify",
                    "after": {"external": False},
                }
            ],
        }
    )
    incomplete = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.configuration.ingress",
                    "propertyChangeType": "Modify",
                    "after": {"targetPort": 443},
                }
            ],
        }
    )

    assert (
        evaluate_what_if(
            safe,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )
        == ()
    )
    assert {
        item.code
        for item in evaluate_what_if(
            incomplete,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )
    } == {"public-container-apps-exposure"}


def test_what_if_inspects_full_resource_payloads() -> None:
    document = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "allowSharedKeyAccess": True,
                    "publicNetworkAccess": "Enabled",
                }
            },
        }
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_STORAGE_ID}),
    )

    assert {item.code for item in violations} == {
        "storage-shared-key-enabled",
        "public-data-plane-access",
        "storage-protection-missing",
    }


def test_storage_create_requires_explicit_safe_defaults() -> None:
    missing = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {"properties": {}},
        }
    )
    assert {
        item.code
        for item in evaluate_what_if(
            missing,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"storage-protection-missing"}

    safe = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "allowSharedKeyAccess": False,
                    "allowBlobPublicAccess": False,
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                }
            },
        }
    )
    assert (
        evaluate_what_if(
            safe,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
        == ()
    )


def test_resource_group_named_providers_cannot_bypass_type_checks() -> None:
    resource_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/providers/"
        "providers/Microsoft.Storage/storageAccounts/ambiguous"
    )
    document = _what_if(
        {
            "resourceId": resource_id,
            "changeType": "Create",
            "after": {
                "properties": {
                    "allowSharedKeyAccess": True,
                    "allowBlobPublicAccess": True,
                    "publicNetworkAccess": "Enabled",
                    "networkAcls": {"defaultAction": "Allow"},
                }
            },
        }
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({resource_id}),
    )

    assert "storage-protection-missing" in {item.code for item in violations}


def test_key_vault_create_requires_explicit_private_defaults() -> None:
    missing = _what_if(
        {
            "resourceId": _KEY_VAULT_ID,
            "changeType": "Create",
            "after": {"properties": {}},
        }
    )
    assert {
        item.code
        for item in evaluate_what_if(
            missing,
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
    } == {"key-vault-protection-missing"}

    safe = _what_if(
        {
            "resourceId": _KEY_VAULT_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                }
            },
        }
    )
    assert (
        evaluate_what_if(
            safe,
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        == ()
    )


def test_child_resource_creates_do_not_require_parent_defaults() -> None:
    document = _what_if(
        {
            "resourceId": _STORAGE_CONTAINER_ID,
            "changeType": "Create",
            "after": {"properties": {"publicAccess": "None"}},
        },
        {
            "resourceId": _KEY_VAULT_KEY_ID,
            "changeType": "Create",
            "after": {"properties": {"keySize": 2048}},
        },
    )

    assert (
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_STORAGE_CONTAINER_ID, _KEY_VAULT_KEY_ID}),
        )
        == ()
    )


@pytest.mark.parametrize("public_access", ["Blob", "Container"])
def test_blob_container_public_access_is_rejected(
    public_access: str,
) -> None:
    create = _what_if(
        {
            "resourceId": _STORAGE_CONTAINER_ID,
            "changeType": "Create",
            "after": {"properties": {"publicAccess": public_access}},
        }
    )
    modify = _what_if(
        _change(
            _STORAGE_CONTAINER_ID,
            "Modify",
            path="properties.publicAccess",
            after=public_access,
        )
    )

    for document in (create, modify):
        assert {
            item.code
            for item in evaluate_what_if(
                document,
                allowed_change_ids=frozenset({_STORAGE_CONTAINER_ID}),
            )
        } == {"storage-container-public-access"}


def test_key_vault_tags_cannot_spoof_private_properties() -> None:
    document = _what_if(
        {
            "resourceId": _KEY_VAULT_ID,
            "changeType": "Create",
            "after": {
                "properties": {},
                "tags": {
                    "publicNetworkAccess": "Disabled",
                    "networkAcls.defaultAction": "Deny",
                },
            },
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
    } == {"key-vault-protection-missing"}


def test_what_if_rejects_resource_id_only_and_nested_unsafe_delta() -> None:
    assert {
        item.code
        for item in evaluate_what_if(
            _what_if(_change(_STORAGE_ID, "Modify")),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"uninspectable-change"}

    nested = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "children": [
                        {
                            "path": "allowSharedKeyAccess",
                            "after": True,
                            "propertyChangeType": "Modify",
                        }
                    ],
                }
            ],
        }
    )
    assert {
        item.code
        for item in evaluate_what_if(
            nested,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"storage-shared-key-enabled"}

    mixed = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "tags.release",
                    "after": "wc029",
                    "propertyChangeType": "Modify",
                }
            ],
            "after": {"properties": {"allowSharedKeyAccess": True}},
        }
    )
    assert {
        item.code
        for item in evaluate_what_if(
            mixed,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"storage-shared-key-enabled"}

    malformed = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [{}],
        }
    )
    with pytest.raises(PreflightInputError, match="delta path"):
        evaluate_what_if(
            malformed,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize(
    ("path", "after", "code"),
    [
        (
            "properties.allowSharedKeyAccess",
            True,
            "storage-shared-key-enabled",
        ),
        (
            "properties.publicNetworkAccess",
            "Enabled",
            "public-data-plane-access",
        ),
        (
            "properties.allowBlobPublicAccess",
            True,
            "storage-public-blob-access",
        ),
        (
            "properties.networkAcls.defaultAction",
            "Allow",
            "public-data-plane-access",
        ),
    ],
)
def test_what_if_never_allows_unsafe_storage_settings(
    path: str,
    after: object,
    code: str,
) -> None:
    document = _what_if(
        _change(
            _STORAGE_ID,
            "Modify",
            path=path,
            after=after,
        )
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_STORAGE_ID}),
    )

    assert code in {item.code for item in violations}


@pytest.mark.parametrize("resource_id", [_STORAGE_ID, _KEY_VAULT_ID])
def test_what_if_rejects_network_perimeter_without_perimeter_evidence(
    resource_id: str,
) -> None:
    secured_by_perimeter = _what_if(
        _change(
            resource_id,
            "Modify",
            path="properties.publicNetworkAccess",
            after="SecuredByPerimeter",
        )
    )
    disabled = _what_if(
        _change(
            resource_id,
            "Modify",
            path="properties.publicNetworkAccess",
            after="Disabled",
        )
    )

    assert {
        item.code
        for item in evaluate_what_if(
            secured_by_perimeter,
            allowed_change_ids=frozenset({resource_id}),
        )
    } == {"public-data-plane-access"}
    assert (
        evaluate_what_if(
            disabled,
            allowed_change_ids=frozenset({resource_id}),
        )
        == ()
    )


@pytest.mark.parametrize("resource_id", [_STORAGE_ID, _KEY_VAULT_ID])
@pytest.mark.parametrize(
    "delta",
    [
        {
            "path": "properties.networkAcls",
            "propertyChangeType": "Delete",
        },
        {
            "path": "properties.networkAcls",
            "propertyChangeType": "Modify",
            "after": {"defaultAction": "Allow"},
        },
        {
            "path": "properties.networkAcls.ipRules",
            "propertyChangeType": "Modify",
            "after": [{"value": "203.0.113.10"}],
        },
    ],
)
def test_what_if_network_acl_changes_require_complete_private_evidence(
    resource_id: str,
    delta: dict[str, object],
) -> None:
    document = _what_if(
        {
            "resourceId": resource_id,
            "changeType": "Modify",
            "delta": [delta],
        }
    )

    assert "public-data-plane-access" in {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({resource_id}),
        )
    }


@pytest.mark.parametrize("resource_id", [_STORAGE_ID, _KEY_VAULT_ID])
def test_what_if_network_acl_change_accepts_complete_private_after_state(
    resource_id: str,
) -> None:
    document = _what_if(
        {
            "resourceId": resource_id,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.networkAcls.ipRules",
                    "propertyChangeType": "Modify",
                    "after": [],
                }
            ],
            "after": {
                "properties": {
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {
                        "defaultAction": "Deny",
                        "ipRules": [],
                    },
                }
            },
        }
    )

    assert (
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({resource_id}),
        )
        == ()
    )


def test_what_if_rejects_removal_of_protective_storage_settings() -> None:
    document = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.allowSharedKeyAccess",
                    "before": False,
                    "propertyChangeType": "Delete",
                }
            ],
        }
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_STORAGE_ID}),
    )

    assert {item.code for item in violations} == {"storage-shared-key-enabled"}


def test_what_if_rejects_removal_of_private_container_setting() -> None:
    document = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.publicNetworkAccess",
                    "before": "Disabled",
                    "propertyChangeType": "Delete",
                }
            ],
        }
    )

    violations = evaluate_what_if(
        document,
        allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
    )

    assert {item.code for item in violations} == {"public-container-apps-exposure"}


def test_rbac_rejects_broad_roles_and_allows_exact_exception() -> None:
    assignment = _assignment()

    assert {item.code for item in evaluate_role_assignments([assignment])} == {
        "broad-role-assignment"
    }

    policy = {
        "allowedBroadAssignments": [assignment],
        "separationRules": [],
    }
    assert (
        evaluate_role_assignments(
            [assignment],
            policy_document=policy,
        )
        == ()
    )


def test_rbac_case_normalization_and_identity_separation() -> None:
    principal_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    assignment = _assignment(
        principal_id=principal_id,
        role_name="Log Analytics Reader",
        scope=_RG_SCOPE.upper(),
    )
    policy = {
        "separationRules": [
            {
                "principalId": principal_id.lower(),
                "forbiddenRoleNames": ["log analytics reader"],
                "forbiddenScopePrefixes": [_RG_SCOPE.lower()],
            }
        ]
    }

    violations = evaluate_role_assignments(
        [assignment],
        policy_document=policy,
    )

    assert {item.code for item in violations} == {"identity-separation"}


@pytest.mark.parametrize(
    "assignment",
    [
        _assignment(
            role_name="Owner",
            scope=("/providers/Microsoft.Management/managementGroups/synthetic"),
        ),
        _assignment(
            role_name="User Access Administrator",
            scope="/",
        ),
        _assignment(
            role_name=None,
            role_id=(
                f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
            ),
            scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
        ),
    ],
)
def test_rbac_rejects_privileged_roles_by_scope_and_id(
    assignment: dict[str, str],
) -> None:
    assert {item.code for item in evaluate_role_assignments([assignment])} == {
        "broad-role-assignment"
    }


@pytest.mark.parametrize(
    "scope",
    [
        f"/subscriptions/{_SUBSCRIPTION_ID}/",
        f"{_RG_SCOPE}/",
    ],
)
def test_rbac_trailing_slash_cannot_bypass_broad_scope_detection(
    scope: str,
) -> None:
    assignment = _assignment(role_name="Owner", scope=scope)

    violations = evaluate_role_assignments([assignment])

    assert {item.code for item in violations} == {"broad-role-assignment"}
    assert violations[0].detail.endswith(scope.rstrip("/").casefold())


@pytest.mark.parametrize(
    "scope",
    [
        f"/subscriptions/{_SUBSCRIPTION_ID}/.",
        f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/..",
        f"/subscriptions/{_SUBSCRIPTION_ID}/notResourceGroups/synthetic",
        (
            f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/"
            "synthetic/providers/Microsoft.Storage/storageAccounts"
        ),
    ],
)
def test_rbac_rejects_noncanonical_or_incomplete_arm_scopes(
    scope: str,
) -> None:
    with pytest.raises(PreflightInputError, match="scope"):
        evaluate_role_assignments(
            [_assignment(role_name="Owner", scope=scope)]
        )


def test_rbac_trailing_slash_role_id_cannot_hide_privileged_role() -> None:
    owner_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635/"
    )
    assignment = _assignment(
        role_name=None,
        role_id=owner_role_id,
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )

    assert {
        item.code for item in evaluate_role_assignments([assignment])
    } == {"broad-role-assignment"}

    with pytest.raises(PreflightInputError, match="conflict"):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="AcrPull",
                    role_id=owner_role_id,
                    scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
                )
            ]
        )


def test_rbac_rejects_role_id_without_authorization_provider_boundary() -> None:
    malformed_role_id = (
        "/providers/Contoso.Fake/things/"
        "Microsoft.Authorization/roleDefinitions/"
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )

    with pytest.raises(
        PreflightInputError,
        match="Microsoft.Authorization role definition",
    ):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="Owner",
                    role_id=malformed_role_id,
                    scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
                )
            ]
        )


def test_rbac_accepts_root_authorization_provider_role_id() -> None:
    owner_role_id = (
        "/providers/Microsoft.Authorization/roleDefinitions/"
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )

    assert {
        item.code
        for item in evaluate_role_assignments(
            [
                _assignment(
                    role_name="Owner",
                    role_id=owner_role_id,
                    scope="/",
                )
            ]
        )
    } == {"broad-role-assignment"}


def test_rbac_name_only_allowance_matches_canonical_builtin_role_id() -> None:
    owner_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )
    assignment = _assignment(
        role_name="Owner",
        role_id=owner_role_id,
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    allowance = _assignment(
        role_name="Owner",
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )

    assert evaluate_role_assignments(
        [assignment],
        policy_document={"allowedBroadAssignments": [allowance]},
    ) == ()


def test_rbac_separation_applies_to_ancestor_assignments() -> None:
    principal_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    subscription_scope = f"/subscriptions/{_SUBSCRIPTION_ID}"
    policy = {
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["Reader"],
                "forbiddenScopePrefixes": [_RG_SCOPE],
            }
        ]
    }

    violations = evaluate_role_assignments(
        [
            _assignment(
                principal_id=principal_id,
                role_name="Reader",
                scope=subscription_scope,
            )
        ],
        policy_document=policy,
    )

    assert "identity-separation" in {item.code for item in violations}


def test_rbac_id_only_assignments_match_named_separation_rules() -> None:
    principal_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    policy = {
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["Reader"],
                "forbiddenScopePrefixes": [_RG_SCOPE],
            }
        ]
    }
    assignment = _assignment(
        principal_id=principal_id,
        role_name=None,
        role_id=(
            f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "acdd72a7-3385-48ef-bd42-f606fba81ae7"
        ),
        scope=_RG_SCOPE,
    )

    assert "identity-separation" in {
        item.code
        for item in evaluate_role_assignments(
            [assignment],
            policy_document=policy,
        )
    }


def test_rbac_rejects_conflicting_role_name_and_id() -> None:
    assignment = _assignment(
        role_name="Reader",
        role_id=(
            f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        ),
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    policy = {
        "allowedBroadAssignments": [
            _assignment(
                role_name="Reader",
                scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
            )
        ]
    }

    with pytest.raises(PreflightInputError, match="conflict"):
        evaluate_role_assignments(
            [assignment],
            policy_document=policy,
        )


def test_rbac_accepts_unmapped_id_with_cli_role_name() -> None:
    assignment = _assignment(
        role_name="AcrPull",
        role_id=(
            f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "7f951dda-4ed3-4680-a7ca-43fe172d538d"
        ),
        scope=(f"{_RG_SCOPE}/providers/Microsoft.ContainerRegistry/registries/synthetic"),
    )

    assert evaluate_role_assignments([assignment]) == ()


def test_inputs_are_strict_and_bounded(tmp_path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(PreflightInputError, match="valid UTF-8 JSON"):
        load_json_file(malformed)

    nonstandard = tmp_path / "nonstandard.json"
    nonstandard.write_text(
        '{"status":"Succeeded","properties":{"changes":[]},"value":NaN}',
        encoding="utf-8",
    )
    with pytest.raises(PreflightInputError, match="invalid JSON constant"):
        load_json_file(nonstandard)

    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"value":"' + "x" * 128 + '"}', encoding="utf-8")
    with pytest.raises(PreflightInputError, match="between 1 and 32 bytes"):
        load_json_file(oversized, maximum_bytes=32)

    with pytest.raises(PreflightInputError, match="changes"):
        evaluate_what_if({"status": "Succeeded", "properties": {}})

    deeply_nested: object = []
    for _ in range(80):
        deeply_nested = [deeply_nested]
    nested = tmp_path / "nested.json"
    nested.write_text(json.dumps(deeply_nested), encoding="utf-8")
    with pytest.raises(PreflightInputError, match="depth or node"):
        load_json_file(nested)


def test_json_parser_rejects_exact_duplicate_keys(tmp_path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"status":"Succeeded","status":"Failed","properties":{"changes":[]}}',
        encoding="utf-8",
    )

    with pytest.raises(PreflightInputError, match="duplicate key"):
        load_json_file(duplicate)


@pytest.mark.parametrize(
    "content",
    [
        (
            '{"status":"Succeeded","\u017ftatus":"Failed",'
            '"properties":{"changes":[]}}'
        ),
        (
            '[{"principalId":"11111111-1111-1111-1111-111111111111",'
            '"PRINCIPALID":"22222222-2222-2222-2222-222222222222",'
            '"roleDefinitionName":"AcrPull","scope":'
            f'"{_RG_SCOPE}/providers/Microsoft.ContainerRegistry/registries/synthetic"}}]'
        ),
    ],
)
def test_json_parser_rejects_casefold_key_collisions(
    tmp_path,
    content: str,
) -> None:
    collision = tmp_path / "collision.json"
    collision.write_text(content, encoding="utf-8")

    with pytest.raises(PreflightInputError, match="case-insensitive key collision"):
        load_json_file(collision)


def test_cli_exit_codes_and_json_output(tmp_path, capsys) -> None:
    safe_path = tmp_path / "safe.json"
    safe_path.write_text(
        json.dumps(_what_if(_change(_STORAGE_ID, "NoChange"))),
        encoding="utf-8",
    )
    assert main(["what-if", str(safe_path)]) == 0
    safe_output = json.loads(capsys.readouterr().out)
    assert safe_output == {
        "kind": "what-if",
        "safe": True,
        "violations": [],
    }

    unsafe_path = tmp_path / "unsafe.json"
    unsafe_path.write_text(
        json.dumps(_what_if(_change(_STORAGE_ID, "Delete"))),
        encoding="utf-8",
    )
    assert main(["what-if", str(unsafe_path)]) == 2
    unsafe_output = json.loads(capsys.readouterr().out)
    assert unsafe_output["safe"] is False
    assert unsafe_output["violations"][0]["code"] == "delete"

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("not-json", encoding="utf-8")
    assert main(["rbac", str(invalid_path)]) == 3
    error_output = json.loads(capsys.readouterr().err)
    assert error_output["safe"] is False


def test_public_cli_emits_deterministic_human_readable_success(tmp_path) -> None:
    safe_path = tmp_path / "safe.json"
    safe_path.write_text(
        json.dumps(_what_if(_change(_STORAGE_ID, "NoChange"))),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        ["wc029-preflight", "what-if", str(safe_path)],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stdout.getvalue() == (
        "WC-029 preflight: SAFE\n"
        "Check: what-if\n"
        "Blockers: 0\n"
    )
    assert stderr.getvalue() == ""


def test_public_cli_emits_deterministic_json_and_blocks_delete(tmp_path) -> None:
    unsafe_path = tmp_path / "unsafe.json"
    unsafe_path.write_text(
        json.dumps(
            _what_if(
                _change(_KEY_VAULT_KEY_ID, "Create", path="tags.release", after="wc029"),
                _change(_CONTAINER_APP_ID, "Delete"),
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "what-if",
            str(unsafe_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == (
        '{"kind":"what-if","safe":false,"violations":['
        f'{{"code":"delete","detail":"resource deletion is never permitted",'
        f'"subject":"{_CONTAINER_APP_ID}"}},'
        f'{{"code":"unapproved-change","detail":"create is absent from the reviewed '
        f'allowlist","subject":"{_KEY_VAULT_KEY_ID}"}}]}}\n'
    )
    assert stderr.getvalue() == ""


def test_public_cli_reports_malformed_policy_without_partial_success(tmp_path) -> None:
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text("[]", encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{", encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": f"{policy_path} is not valid UTF-8 JSON",
        "kind": "rbac",
        "safe": False,
    }


def test_public_cli_reports_bounded_integer_error_without_traceback(tmp_path) -> None:
    unsafe_path = tmp_path / "oversized-integer.json"
    unsafe_path.write_text(
        '{"status":"Succeeded","properties":{"changes":[]},"padding":'
        + "9" * 5000
        + "}",
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "what-if",
            str(unsafe_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": "JSON integer exceeds 1024 digits",
        "kind": "what-if",
        "safe": False,
    }


def test_public_cli_rejects_terminal_control_characters(tmp_path) -> None:
    unsafe_path = tmp_path / "terminal-injection.json"
    unsafe_path.write_text(
        json.dumps(
            _what_if(
                _change(
                    _CONTAINER_APP_ID + "\nWC-029 preflight: SAFE",
                    "Delete",
                )
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        ["wc029-preflight", "what-if", str(unsafe_path)],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight what-if failed: "
        "resourceId must be a bounded string\n"
    )


def test_public_cli_rejects_nonprintable_nested_json_keys(tmp_path) -> None:
    unsafe_path = tmp_path / "nested-key-injection.json"
    unsafe_path.write_text(
        json.dumps(
            _what_if(
                {
                    "resourceId": _CONTAINER_APP_ID,
                    "changeType": "Modify",
                    "after": {
                        "properties": {
                            "configuration": {
                                "ingress": {"external\u001b[2J": True}
                            }
                        }
                    },
                }
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        ["wc029-preflight", "what-if", str(unsafe_path)],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight what-if failed: JSON object keys are invalid\n"
    )


def test_public_cli_rejects_empty_rbac_separation_policy(tmp_path) -> None:
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            [
                _assignment(
                    role_name="Log Analytics Reader",
                    scope=f"{_RG_SCOPE}/providers/Microsoft.OperationalInsights/workspaces/synthetic",
                )
            ]
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}", encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "RBAC policy requires at least one separation rule\n"
    )


def test_public_cli_accepts_complete_expected_principal_coverage(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignments = [
        _assignment(
            principal_id=principal_id,
            role_name="AcrPull",
            scope=(
                f"{_RG_SCOPE}/providers/"
                "Microsoft.ContainerRegistry/registries/synthetic"
            ),
        )
    ]
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(assignments),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            _production_policy(
                principal_id,
                expected_assignments=assignments,
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stdout.getvalue() == (
        "WC-029 preflight: SAFE\n"
        "Check: rbac\n"
        "Blockers: 0\n"
    )
    assert stderr.getvalue() == ""


def test_public_cli_rejects_empty_assignment_evidence(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text("[]", encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(_production_policy(principal_id)),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "role-assignment evidence must not be empty\n"
    )


@pytest.mark.parametrize("continuation_key", ["nextLink", "@odata.nextLink"])
def test_public_cli_rejects_paginated_assignment_evidence(
    tmp_path,
    continuation_key: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignments = [
        _assignment(
            principal_id=principal_id,
            role_name="AcrPull",
            scope=(
                f"{_RG_SCOPE}/providers/"
                "Microsoft.ContainerRegistry/registries/synthetic"
            ),
        )
    ]
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            {
                "value": assignments,
                continuation_key: "https://management.azure.com/continuation",
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            _production_policy(
                principal_id,
                expected_assignments=assignments,
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": (
            "role-assignment evidence must not contain a continuation link"
        ),
        "kind": "rbac",
        "safe": False,
    }


@pytest.mark.parametrize(
    ("assignments", "policy", "message"),
    [
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                "separationRules": [
                    {
                        "principalId": "11111111-1111-1111-1111-111111111111",
                        "forbiddenRoleNames": ["Owner"],
                        "forbiddenScopePrefixes": [
                            f"/subscriptions/{_SUBSCRIPTION_ID}",
                        ],
                    }
                ],
            },
            "RBAC policy requires expectedPrincipalIds",
        ),
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                "expectedPrincipalIds": [
                    "11111111-1111-1111-1111-111111111111",
                ],
                "separationRules": [
                    {
                        "principalId": "11111111-1111-1111-1111-111111111111",
                        "forbiddenRoleNames": ["Owner"],
                        "forbiddenScopePrefixes": [
                            f"/subscriptions/{_SUBSCRIPTION_ID}",
                        ],
                    }
                ],
            },
            "RBAC policy requires expectedAssignments",
        ),
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            _production_policy("22222222-2222-2222-2222-222222222222"),
            "role assignment principal is not covered by expectedPrincipalIds",
        ),
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                **_production_policy(
                    "11111111-1111-1111-1111-111111111111",
                    "22222222-2222-2222-2222-222222222222",
                ),
            },
            "role-assignment evidence does not cover every expectedPrincipalId",
        ),
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                "expectedPrincipalIds": [
                    "11111111-1111-1111-1111-111111111111",
                ],
                "expectedAssignments": [
                    _assignment(
                        principal_id="11111111-1111-1111-1111-111111111111",
                    )
                ],
                "separationRules": [
                    {
                        "principalId": "22222222-2222-2222-2222-222222222222",
                        "forbiddenRoleNames": ["Owner"],
                        "forbiddenScopePrefixes": [
                            f"/subscriptions/{_SUBSCRIPTION_ID}",
                        ],
                    }
                ],
            },
            "separationRules principals must exactly match expectedPrincipalIds",
        ),
        (
            [_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                **_production_policy(
                    "11111111-1111-1111-1111-111111111111",
                ),
                "allowedBroadAssignments": [
                    _assignment(
                        principal_id="22222222-2222-2222-2222-222222222222",
                    )
                ],
            },
            "RBAC policy principals must be listed in expectedPrincipalIds",
        ),
    ],
)
def test_public_cli_rejects_incomplete_or_unmatched_principal_coverage(
    tmp_path,
    assignments: list[dict[str, str]],
    policy: dict[str, object],
    message: str,
) -> None:
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(json.dumps(assignments), encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == f"WC-029 preflight rbac failed: {message}\n"


def test_public_cli_rejects_truncated_assignment_inventory(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    safe_assignment = _assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=(
            f"{_RG_SCOPE}/providers/"
            "Microsoft.ContainerRegistry/registries/synthetic"
        ),
    )
    omitted_owner = _assignment(
        principal_id=principal_id,
        role_name="Owner",
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps([safe_assignment]),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            _production_policy(
                principal_id,
                expected_assignments=[safe_assignment, omitted_owner],
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": (
            "role-assignment evidence does not exactly match "
            "expectedAssignments"
        ),
        "kind": "rbac",
        "safe": False,
    }


def test_public_cli_requires_exact_rbac_condition_inventory(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    condition = (
        "@Resource[Microsoft.Storage/storageAccounts/"
        "blobServices/containers:name] StringEquals 'evidence'"
    )
    conditional_assignment = _assignment(
        principal_id=principal_id,
        role_name="Storage Blob Data Reader",
        scope=(
            f"{_RG_SCOPE}/providers/Microsoft.Storage/"
            "storageAccounts/synthetic/blobServices/default/containers/evidence"
        ),
        condition=condition,
        condition_version="2.0",
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps([conditional_assignment]),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            _production_policy(
                principal_id,
                expected_assignments=[conditional_assignment],
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    assert (
        cli_main(
            [
                "wc029-preflight",
                "rbac",
                str(assignments_path),
                "--policy",
                str(policy_path),
            ],
            stdout=stdout,
            stderr=stderr,
        )
        == 0
    )
    assert stderr.getvalue() == ""

    assignments_path.write_text(
        json.dumps(
            [
                _assignment(
                    principal_id=principal_id,
                    role_name="Storage Blob Data Reader",
                    scope=conditional_assignment["scope"],
                )
            ]
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": (
            "role-assignment evidence does not exactly match "
            "expectedAssignments"
        ),
        "kind": "rbac",
        "safe": False,
    }


def test_rbac_condition_and_version_must_be_supplied_together() -> None:
    with pytest.raises(PreflightInputError, match="supplied together"):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="Storage Blob Data Reader",
                    condition="@Resource[x:y] StringEquals 'z'",
                )
            ]
        )


def test_public_cli_rejects_conflicting_allowance_role_name_and_id(
    tmp_path,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    owner_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    )
    owner_assignment = _assignment(
        principal_id=principal_id,
        role_name="Owner",
        role_id=owner_role_id,
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps([owner_assignment]),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[owner_assignment],
    )
    policy["allowedBroadAssignments"] = [
        _assignment(
            principal_id=principal_id,
            role_name="Reader",
            role_id=owner_role_id,
            scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
        )
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "roleDefinitionName and roleDefinitionId conflict\n"
    )


def test_public_cli_requires_allowance_role_id_to_match_inventory(
    tmp_path,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    expected_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )
    different_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    )
    owner_assignment = _assignment(
        principal_id=principal_id,
        role_name="Owner",
        role_id=expected_role_id,
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps([owner_assignment]),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[owner_assignment],
    )
    policy["allowedBroadAssignments"] = [
        _assignment(
            principal_id=principal_id,
            role_name="Owner",
            role_id=different_role_id,
            scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
        )
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "allowedBroadAssignments must be listed in expectedAssignments\n"
    )


def test_public_cli_rejects_vacuous_rbac_separation_rule(tmp_path) -> None:
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text("[]", encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "separationRules": [
                    {
                        "principalId": "11111111-1111-1111-1111-111111111111",
                        "forbiddenRoleNames": [],
                        "forbiddenScopePrefixes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        [
            "wc029-preflight",
            "rbac",
            str(assignments_path),
            "--policy",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "separation rule requires forbidden roles and scope prefixes\n"
    )


def test_public_cli_requires_a_check_and_input(capsys) -> None:
    with pytest.raises(SystemExit) as missing_check:
        cli_main(["wc029-preflight"])
    assert missing_check.value.code == 2
    assert "the following arguments are required: preflight_kind" in capsys.readouterr().err

    with pytest.raises(SystemExit) as missing_input:
        cli_main(["wc029-preflight", "what-if"])
    assert missing_input.value.code == 2
    assert "the following arguments are required: input" in capsys.readouterr().err

    with pytest.raises(SystemExit) as missing_policy:
        cli_main(["wc029-preflight", "rbac", "role-assignments.json"])
    assert missing_policy.value.code == 2
    assert "the following arguments are required: --policy" in capsys.readouterr().err
