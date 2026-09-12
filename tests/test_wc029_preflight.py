from __future__ import annotations

import json

import pytest

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
) -> dict[str, str]:
    value = {
        "principalId": principal_id,
        "scope": scope,
    }
    if role_name is not None:
        value["roleDefinitionName"] = role_name
    if role_id is not None:
        value["roleDefinitionId"] = role_id
    return value


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
