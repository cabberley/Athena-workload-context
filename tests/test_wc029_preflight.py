from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from urllib.parse import urlencode

import pytest

from athena_context.cli import main as cli_main
from athena_context.wc029_preflight import (
    PreflightInputError,
    PreflightViolation,
    evaluate_role_assignments,
    evaluate_what_if,
    load_json_file,
    main,
    render_preflight_json,
)

_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
_TENANT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_RG_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload"
_SUBSCRIPTION_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}"
_SIBLING_RG_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-sibling"
_WORKLOAD_RESOURCE_SCOPE = (
    f"{_RG_SCOPE}/providers/Microsoft.Compute/virtualMachines/synthetic-workload"
)
_MG_LEAF_SCOPE = "/providers/Microsoft.Management/managementGroups/synthetic-workloads"
_MG_ROOT_SCOPE = "/providers/Microsoft.Management/managementGroups/synthetic-root"
_MANAGEMENT_GROUP_ANCESTRY = [_MG_LEAF_SCOPE, _MG_ROOT_SCOPE]
_COLLECTION_RUN_ID = "44444444-4444-4444-4444-444444444444"
_DEPLOYMENT_DIGEST = "sha256:" + "d" * 64
_TEMPLATE_DIGEST = "sha256:" + "e" * 64
_PARAMETERS_DIGEST = "sha256:" + "f" * 64
_EMPTY_DIGEST = "sha256:" + "0" * 64
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
_ROLE_DEFINITION_PREFIX = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/"
)
_TEST_ROLE_IDS = {
    "owner": _ROLE_DEFINITION_PREFIX + "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "reader": _ROLE_DEFINITION_PREFIX + "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "acrpull": _ROLE_DEFINITION_PREFIX + "7f951dda-4ed3-4680-a7ca-43fe172d538d",
    "log analytics reader": (_ROLE_DEFINITION_PREFIX + "73c42c96-874c-492b-b04d-ab87d138a893"),
    "storage blob data reader": (_ROLE_DEFINITION_PREFIX + "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"),
}


def _json_digest(value: object) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


def _manifest(
    bindings: dict[str, str],
    *,
    collection_run_id: str = _COLLECTION_RUN_ID,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    collected = datetime.now(UTC).replace(microsecond=0) if collected_at is None else collected_at
    expires = collected + timedelta(minutes=10) if expires_at is None else expires_at
    return {
        "collectionRunId": collection_run_id,
        "collectedAt": collected.isoformat(),
        "expiresAt": expires.isoformat(),
        "bindings": bindings,
    }


def _attestation(
    kind: str,
    manifest: dict[str, object],
    binding_names: tuple[str, ...],
) -> dict[str, object]:
    bindings = manifest["bindings"]
    assert isinstance(bindings, dict)
    return {
        "artifactKind": kind,
        "collectionRunId": manifest["collectionRunId"],
        "collectedAt": manifest["collectedAt"],
        "expiresAt": manifest["expiresAt"],
        "manifestDigest": _json_digest(manifest),
        "bindings": {binding_name: bindings[binding_name] for binding_name in binding_names},
    }


def _attested_what_if(
    document: object,
    *,
    allowed_change_ids: frozenset[str] = frozenset(),
    collection_run_id: str = _COLLECTION_RUN_ID,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    normalized_allowlist = sorted(value.strip().casefold() for value in allowed_change_ids)
    manifest = _manifest(
        {
            "allowChangeIdsDigest": _json_digest({"allowChangeIds": normalized_allowlist}),
            "deploymentDigest": _DEPLOYMENT_DIGEST,
            "parametersDigest": _PARAMETERS_DIGEST,
            "policyDigest": _EMPTY_DIGEST,
            "rbacEvidenceDigest": _EMPTY_DIGEST,
            "templateDigest": _TEMPLATE_DIGEST,
            "whatIfDigest": _json_digest(document),
        },
        collection_run_id=collection_run_id,
        collected_at=collected_at,
        expires_at=expires_at,
    )
    return {
        "attestation": _attestation(
            "what-if",
            manifest,
            (
                "allowChangeIdsDigest",
                "deploymentDigest",
                "parametersDigest",
                "templateDigest",
                "whatIfDigest",
            ),
        ),
        "manifest": manifest,
        "whatIf": document,
    }


def _attested_rbac(
    evidence: dict[str, object],
    policy: dict[str, object],
    *,
    collection_run_id: str = _COLLECTION_RUN_ID,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    artifact = copy.deepcopy(evidence)
    manifest = _manifest(
        {
            "allowChangeIdsDigest": _EMPTY_DIGEST,
            "deploymentDigest": _DEPLOYMENT_DIGEST,
            "parametersDigest": _PARAMETERS_DIGEST,
            "policyDigest": _json_digest(policy),
            "rbacEvidenceDigest": _json_digest(artifact),
            "templateDigest": _TEMPLATE_DIGEST,
            "whatIfDigest": _EMPTY_DIGEST,
        },
        collection_run_id=collection_run_id,
        collected_at=collected_at,
        expires_at=expires_at,
    )
    artifact["attestation"] = _attestation(
        "rbac",
        manifest,
        ("policyDigest", "rbacEvidenceDigest"),
    )
    artifact["manifest"] = manifest
    return artifact


def _artifact_manifest_digest(input_path: object) -> str:
    try:
        document = json.loads(Path(str(input_path)).read_text(encoding="utf-8"))
        return _json_digest(document["manifest"])
    except OSError, KeyError, TypeError, ValueError, json.JSONDecodeError:
        return _EMPTY_DIGEST


def _what_if_cli_args(
    input_path: object,
    *extra: str,
) -> list[str]:
    return [
        "wc029-preflight",
        "what-if",
        str(input_path),
        "--collection-run-id",
        _COLLECTION_RUN_ID,
        "--attestation-manifest-digest",
        _artifact_manifest_digest(input_path),
        "--deployment-digest",
        _DEPLOYMENT_DIGEST,
        "--template-digest",
        _TEMPLATE_DIGEST,
        "--parameters-digest",
        _PARAMETERS_DIGEST,
        *extra,
    ]


def _rbac_cli_args(
    input_path: object,
    policy_path: object,
    *extra: str,
) -> list[str]:
    return [
        "wc029-preflight",
        "rbac",
        str(input_path),
        "--policy",
        str(policy_path),
        "--collection-run-id",
        _COLLECTION_RUN_ID,
        "--attestation-manifest-digest",
        _artifact_manifest_digest(input_path),
        *extra,
    ]


def _evaluate_guarded_rbac(
    evidence: dict[str, object],
    policy: dict[str, object],
    *,
    now: datetime | None = None,
) -> tuple[PreflightViolation, ...]:
    artifact = evidence if "attestation" in evidence else _attested_rbac(evidence, policy)
    return evaluate_role_assignments(
        artifact,
        policy_document=policy,
        require_separation_rules=True,
        require_attestation=True,
        expected_collection_run_id=_COLLECTION_RUN_ID,
        attestation_manifest_digest=_json_digest(artifact["manifest"]),
        now=now,
    )


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
    effective_principal_id: str | None = None,
    principal_type: str | None = None,
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
    if effective_principal_id is not None:
        value["effectivePrincipalId"] = effective_principal_id
    if principal_type is not None:
        value["principalType"] = principal_type
    if role_name is not None:
        value["roleDefinitionName"] = role_name
    if role_id is not None:
        value["roleDefinitionId"] = role_id
    if condition is not None:
        value["condition"] = condition
    if condition_version is not None:
        value["conditionVersion"] = condition_version
    return value


def _guarded_assignment(
    *,
    principal_id: str = "11111111-1111-1111-1111-111111111111",
    effective_principal_id: str | None = None,
    principal_type: str = "ServicePrincipal",
    role_name: str = "Reader",
    scope: str = _RG_SCOPE,
    condition: str | None = None,
    condition_version: str | None = None,
) -> dict[str, str]:
    value = {
        "assignedPrincipalId": principal_id,
        "assignedPrincipalType": principal_type,
        "effectivePrincipalId": (
            principal_id if effective_principal_id is None else effective_principal_id
        ),
        "roleDefinitionName": role_name,
        "roleDefinitionId": _TEST_ROLE_IDS[role_name.casefold()],
        "scope": scope,
    }
    if condition is not None:
        value["condition"] = condition
    if condition_version is not None:
        value["conditionVersion"] = condition_version
    return value


def _assignment_field(
    assignment: dict[str, str],
    assigned_name: str,
    legacy_name: str,
) -> str:
    if assigned_name in assignment:
        return assignment[assigned_name]
    return assignment[legacy_name]


def _client_id(principal_id: str) -> str:
    return str(
        uuid.UUID(
            int=uuid.UUID(principal_id).int ^ (1 << 64),
        )
    )


def _raw_arm_assignment(
    assignment: dict[str, str],
    *,
    index: int,
) -> dict[str, object]:
    scope = assignment["scope"]
    assignment_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        (
            f"{_assignment_field(assignment, 'effectivePrincipalId', 'principalId')}:"
            f"{assignment.get('roleDefinitionId', '')}:{scope}:{index}"
        ),
    )
    resource_id = (
        f"/providers/Microsoft.Authorization/roleAssignments/{assignment_id}"
        if scope == "/"
        else (f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}")
    )
    properties: dict[str, object] = {
        "principalId": _assignment_field(
            assignment,
            "assignedPrincipalId",
            "principalId",
        ),
        "principalType": _assignment_field(
            assignment,
            "assignedPrincipalType",
            "principalType",
        ),
        "roleDefinitionId": assignment.get("roleDefinitionId"),
        "scope": scope,
    }
    for field_name in ("condition", "conditionVersion"):
        if field_name in assignment:
            properties[field_name] = assignment[field_name]
    return {
        "id": resource_id,
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": properties,
    }


def _hierarchy_evidence() -> dict[str, object]:
    subscription_association_id = f"{_MG_LEAF_SCOPE}/subscriptions/{_SUBSCRIPTION_ID}"
    return {
        "resourceGraph": {
            "request": {
                "tenantId": _TENANT_ID,
                "subscriptionId": _SUBSCRIPTION_ID,
                "query": (
                    "ResourceContainers | where type =~ "
                    "'microsoft.resources/subscriptions' | project "
                    "tenantId, subscriptionId, "
                    "properties.managementGroupAncestorsChain"
                ),
            },
            "statusCode": 200,
            "body": {
                "data": [
                    {
                        "tenantId": _TENANT_ID,
                        "subscriptionId": _SUBSCRIPTION_ID,
                        "properties": {
                            "managementGroupAncestorsChain": [
                                {"name": scope.rsplit("/", 1)[-1]}
                                for scope in (_MANAGEMENT_GROUP_ANCESTRY)
                            ]
                        },
                    }
                ],
                "skipToken": None,
                "resultTruncated": False,
                "count": 1,
                "totalRecords": 1,
            },
        },
        "arm": {
            "subscription": {
                "requestUrl": (
                    "https://management.azure.com"
                    f"{subscription_association_id}"
                    "?api-version=2020-05-01"
                ),
                "statusCode": 200,
                "body": {
                    "id": subscription_association_id,
                    "type": ("Microsoft.Management/managementGroups/subscriptions"),
                    "name": _SUBSCRIPTION_ID,
                    "properties": {
                        "tenantId": _TENANT_ID,
                        "parent": {"id": _MG_LEAF_SCOPE},
                    },
                },
            },
            "resourceGroup": {
                "requestUrl": (f"https://management.azure.com{_RG_SCOPE}?api-version=2021-04-01"),
                "statusCode": 200,
                "body": {
                    "id": _RG_SCOPE,
                    "type": "Microsoft.Resources/resourceGroups",
                },
            },
            "managementGroups": [
                {
                    "requestUrl": (
                        "https://management.azure.com"
                        f"{_MG_LEAF_SCOPE}?api-version=2020-05-01"
                        "&%24expand=path"
                    ),
                    "statusCode": 200,
                    "body": {
                        "id": _MG_LEAF_SCOPE,
                        "type": ("Microsoft.Management/managementGroups"),
                        "properties": {
                            "tenantId": _TENANT_ID,
                            "details": {
                                "parent": {"id": _MG_ROOT_SCOPE},
                            },
                        },
                    },
                },
                {
                    "requestUrl": (
                        "https://management.azure.com"
                        f"{_MG_ROOT_SCOPE}?api-version=2020-05-01"
                        "&%24expand=path"
                    ),
                    "statusCode": 200,
                    "body": {
                        "id": _MG_ROOT_SCOPE,
                        "type": ("Microsoft.Management/managementGroups"),
                        "properties": {
                            "tenantId": _TENANT_ID,
                            "details": {"parent": None},
                        },
                    },
                },
            ],
        },
    }


def _group_membership_evidence(
    effective_principal_id: str,
    group_ids: list[str],
) -> dict[str, object]:
    return {
        "tenantId": _TENANT_ID,
        "method": "getMemberGroups",
        "securityEnabledOnly": True,
        "pages": [
            {
                "requestUrl": (
                    "https://graph.microsoft.com/v1.0/servicePrincipals/"
                    f"{effective_principal_id}/getMemberGroups"
                ),
                "statusCode": 200,
                "value": group_ids,
                "@odata.nextLink": None,
            }
        ],
    }


def _guarded_evidence(
    assignments: list[dict[str, str]],
    *,
    effective_principal_ids: list[str] | None = None,
) -> dict[str, object]:
    assignment_principal_ids = list(
        dict.fromkeys(
            _assignment_field(
                assignment,
                "effectivePrincipalId",
                "principalId",
            )
            for assignment in assignments
        )
    )
    if effective_principal_ids is None:
        effective_principal_ids = assignment_principal_ids
    else:
        effective_principal_ids = [
            *effective_principal_ids,
            *(
                principal_id
                for principal_id in assignment_principal_ids
                if principal_id not in effective_principal_ids
            ),
        ]
    principals: list[dict[str, object]] = []
    for effective_principal_id in effective_principal_ids:
        identity_assignments = [
            assignment
            for assignment in assignments
            if _assignment_field(
                assignment,
                "effectivePrincipalId",
                "principalId",
            )
            == effective_principal_id
        ]
        group_ids = list(
            dict.fromkeys(
                _assignment_field(
                    assignment,
                    "assignedPrincipalId",
                    "principalId",
                )
                for assignment in identity_assignments
                if _assignment_field(
                    assignment,
                    "assignedPrincipalType",
                    "principalType",
                ).casefold()
                == "group"
            )
        )
        assignment_filter = f"atScope() and assignedTo('{effective_principal_id}')"
        request_query = urlencode(
            {
                "api-version": "2022-04-01",
                "$filter": assignment_filter,
            }
        )
        ancestor_scopes = {
            "/",
            _SUBSCRIPTION_SCOPE.casefold(),
            _RG_SCOPE.casefold(),
            *(scope.casefold() for scope in _MANAGEMENT_GROUP_ANCESTRY),
        }
        ancestor_assignments = [
            assignment
            for assignment in identity_assignments
            if assignment["scope"].casefold() in ancestor_scopes
        ]
        descendant_collections: list[dict[str, object]] = []
        for assigned_principal_id in [
            effective_principal_id,
            *group_ids,
        ]:
            descendant_filter = f"principalId eq '{assigned_principal_id}'"
            descendant_query = urlencode(
                {
                    "api-version": "2022-04-01",
                    "$filter": descendant_filter,
                }
            )
            descendant_assignments = [
                assignment
                for assignment in identity_assignments
                if _assignment_field(
                    assignment,
                    "assignedPrincipalId",
                    "principalId",
                )
                == assigned_principal_id
                and (
                    assignment["scope"] == "/"
                    or assignment["scope"].casefold().startswith(_SUBSCRIPTION_SCOPE.casefold())
                    or assignment["scope"].casefold()
                    in {scope.casefold() for scope in _MANAGEMENT_GROUP_ANCESTRY}
                )
            ]
            descendant_collections.append(
                {
                    "assignedToPrincipalId": assigned_principal_id,
                    "apiVersion": "2022-04-01",
                    "scope": _SUBSCRIPTION_SCOPE,
                    "filter": descendant_filter,
                    "pages": [
                        {
                            "requestUrl": (
                                "https://management.azure.com"
                                f"{_SUBSCRIPTION_SCOPE}/providers/"
                                "Microsoft.Authorization/"
                                "roleAssignments?"
                                f"{descendant_query}"
                            ),
                            "statusCode": 200,
                            "value": [
                                _raw_arm_assignment(
                                    assignment,
                                    index=index,
                                )
                                for index, assignment in enumerate(
                                    descendant_assignments,
                                )
                            ],
                            "nextLink": None,
                        }
                    ],
                }
            )
        principals.append(
            {
                "effectivePrincipalId": effective_principal_id,
                "servicePrincipal": {
                    "statusCode": 200,
                    "tenantId": _TENANT_ID,
                    "id": effective_principal_id,
                    "appId": _client_id(effective_principal_id),
                },
                "groupMembership": _group_membership_evidence(
                    effective_principal_id,
                    group_ids,
                ),
                "roleAssignments": {
                    "ancestors": {
                        "method": "arm",
                        "apiVersion": "2022-04-01",
                        "scope": _RG_SCOPE,
                        "filter": assignment_filter,
                        "pages": [
                            {
                                "requestUrl": (
                                    "https://management.azure.com"
                                    f"{_RG_SCOPE}/providers/"
                                    "Microsoft.Authorization/"
                                    "roleAssignments?"
                                    f"{request_query}"
                                ),
                                "statusCode": 200,
                                "value": [
                                    _raw_arm_assignment(
                                        assignment,
                                        index=index,
                                    )
                                    for index, assignment in enumerate(
                                        ancestor_assignments,
                                    )
                                ],
                                "nextLink": None,
                            }
                        ],
                    },
                    "descendants": {
                        "method": "arm",
                        "collections": descendant_collections,
                    },
                },
            }
        )
    return {
        "target": {
            "tenantId": _TENANT_ID,
            "subscriptionId": _SUBSCRIPTION_ID,
            "resourceGroupId": _RG_SCOPE,
        },
        "hierarchy": _hierarchy_evidence(),
        "principals": principals,
    }


def _first_principal_artifact(
    evidence: dict[str, object],
) -> dict[str, object]:
    principals = evidence["principals"]
    assert isinstance(principals, list)
    principal = principals[0]
    assert isinstance(principal, dict)
    return principal


def _cli_assignment(
    assignment: dict[str, str],
) -> dict[str, str]:
    value = {
        "principalId": _assignment_field(
            assignment,
            "assignedPrincipalId",
            "principalId",
        ),
        "principalType": _assignment_field(
            assignment,
            "assignedPrincipalType",
            "principalType",
        ),
        "effectivePrincipalId": _assignment_field(
            assignment,
            "effectivePrincipalId",
            "principalId",
        ),
        "roleDefinitionName": assignment["roleDefinitionName"],
        "roleDefinitionId": assignment["roleDefinitionId"],
        "scope": assignment["scope"],
    }
    for field_name in ("condition", "conditionVersion"):
        if field_name in assignment:
            value[field_name] = assignment[field_name]
    return value


def _production_policy(
    *principal_ids: str,
    expected_assignments: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "target": {
            "tenantId": _TENANT_ID,
            "subscriptionId": _SUBSCRIPTION_ID,
            "resourceGroupId": _RG_SCOPE,
            "approvedManagementGroupAncestry": (_MANAGEMENT_GROUP_ANCESTRY),
        },
        "expectedPrincipalIds": list(principal_ids),
        "approvedAssignments": (
            expected_assignments
            if expected_assignments is not None
            else [_guarded_assignment(principal_id=principal_id) for principal_id in principal_ids]
        ),
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["Owner"],
                "forbiddenRoleDefinitionIds": [
                    _TEST_ROLE_IDS["owner"],
                ],
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


def test_what_if_rejects_mixed_result_envelopes() -> None:
    document = {
        "status": "Succeeded",
        "changes": [
            {
                "resourceId": _STORAGE_ID,
                "changeType": "Delete",
            }
        ],
        "properties": {"changes": []},
    }

    with pytest.raises(PreflightInputError, match="mixed result envelopes"):
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


def test_managed_environment_create_requires_explicit_private_network() -> None:
    missing = _what_if(
        {
            "resourceId": _CONTAINER_ENVIRONMENT_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "zoneRedundant": False,
                }
            },
        }
    )
    safe = _what_if(
        {
            "resourceId": _CONTAINER_ENVIRONMENT_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "publicNetworkAccess": "Disabled",
                    "vnetConfiguration": {"internal": True},
                }
            },
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            missing,
            allowed_change_ids=frozenset({_CONTAINER_ENVIRONMENT_ID}),
        )
    } == {"public-container-apps-exposure"}
    assert (
        evaluate_what_if(
            safe,
            allowed_change_ids=frozenset({_CONTAINER_ENVIRONMENT_ID}),
        )
        == ()
    )


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
    "change",
    [
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "after": {
                "id": _CONTAINER_APP_ID,
                "name": "athena-presentation",
                "type": "Microsoft.App/containerApps",
            },
        },
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [],
            "after": {
                "properties": {
                    "template": {"revisionSuffix": "synthetic"},
                }
            },
        },
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "<resource>",
                    "propertyChangeType": "Modify",
                    "after": {
                        "id": _CONTAINER_APP_ID,
                        "name": "athena-presentation",
                        "type": "Microsoft.App/containerApps",
                    },
                }
            ],
        },
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.template.revisionSuffix",
                    "propertyChangeType": "NoEffect",
                    "before": "same",
                    "after": "different",
                }
            ],
        },
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties.template.revisionSuffix",
                    "propertyChangeType": "Modify",
                    "before": "same",
                    "after": "same",
                }
            ],
        },
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "before": {
                "id": _CONTAINER_APP_ID,
                "name": "athena-presentation-before",
                "type": "Microsoft.App/containerApps",
            },
            "after": {
                "id": _CONTAINER_APP_ID,
                "name": "athena-presentation-after",
                "type": "Microsoft.App/containerApps",
            },
        },
    ],
)
def test_modify_requires_meaningful_effective_property_delta(
    change: dict[str, object],
) -> None:
    violations = evaluate_what_if(
        _what_if(change),
        allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
    )

    assert "uninspectable-change" in {item.code for item in violations}


def test_modify_derives_and_validates_complete_snapshot_delta() -> None:
    safe = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "before": {
                "id": _CONTAINER_APP_ID,
                "properties": {
                    "template": {"revisionSuffix": "before"},
                },
            },
            "after": {
                "id": _CONTAINER_APP_ID,
                "properties": {
                    "template": {"revisionSuffix": "after"},
                },
            },
        }
    )
    unsafe = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "before": {
                "id": _STORAGE_ID,
                "properties": {"allowSharedKeyAccess": False},
            },
            "after": {
                "id": _STORAGE_ID,
                "properties": {"allowSharedKeyAccess": True},
            },
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
            unsafe,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"storage-shared-key-enabled"}


@pytest.mark.parametrize(
    "path",
    ["<resource>", "<resource>.", "."],
)
@pytest.mark.parametrize(
    "property_change_type",
    ["Delete", "Remove"],
)
def test_modify_rejects_resource_root_removal_aliases(
    path: str,
    property_change_type: str,
) -> None:
    document = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": path,
                    "propertyChangeType": property_change_type,
                }
            ],
            "after": {
                "properties": {
                    "publicNetworkAccess": "Disabled",
                    "configuration": {
                        "ingress": {"external": False},
                    },
                }
            },
        }
    )

    assert "delete" in {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )
    }


def test_modify_requires_object_resource_root_after_value() -> None:
    for root_delta in (
        {
            "path": "<resource>.",
            "propertyChangeType": "Modify",
            "after": "synthetic",
        },
        {
            "path": "<resource>.",
            "propertyChangeType": "Modify",
            "children": [
                {
                    "path": "properties.template.revisionSuffix",
                    "propertyChangeType": "Modify",
                    "after": "synthetic",
                }
            ],
        },
    ):
        with pytest.raises(
            PreflightInputError,
            match="resource-root delta after value must be an object",
        ):
            evaluate_what_if(
                _what_if(
                    {
                        "resourceId": _CONTAINER_APP_ID,
                        "changeType": "Modify",
                        "delta": [root_delta],
                    }
                ),
                allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
            )


def test_what_if_bounds_unique_violation_count() -> None:
    changes = [
        _change(
            f"{_KEY_VAULT_ID}/keys/synthetic-{index}",
            "Modify",
            path="tags.release",
            after="wc029",
        )
        for index in range(257)
    ]

    with pytest.raises(
        PreflightInputError,
        match="violation count exceeds 256",
    ):
        evaluate_what_if(_what_if(*changes))


def test_rendering_rejects_oversized_deterministic_output() -> None:
    violations = tuple(
        PreflightViolation(
            code="synthetic",
            subject=f"subject-{index}",
            detail="x" * 4096,
        )
        for index in range(256)
    )

    with pytest.raises(
        PreflightInputError,
        match="rendered output exceeds",
    ):
        render_preflight_json(
            kind="what-if",
            violations=violations,
        )


def test_what_if_rejects_empty_delta_children() -> None:
    document = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "children": [],
                }
            ],
        }
    )

    with pytest.raises(PreflightInputError, match="no inspectable children"):
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_dotted_payload_keys_cannot_spoof_storage_protection() -> None:
    document = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {
                "properties.allowSharedKeyAccess": False,
                "properties.allowBlobPublicAccess": False,
                "properties.publicNetworkAccess": "Disabled",
                "properties.networkAcls.defaultAction": "Deny",
            },
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"storage-protection-missing"}


def test_unicode_folded_property_keys_and_paths_are_rejected() -> None:
    spoofed_payload = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {
                "propertie\u017f": {
                    "allowSharedKeyAcce\u017f\u017f": False,
                    "allowBlobPublicAcce\u017f\u017f": False,
                    "publicNetworkAcce\u017f\u017f": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                }
            },
        }
    )
    with pytest.raises(PreflightInputError, match="ambiguous Unicode"):
        evaluate_what_if(
            spoofed_payload,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )

    spoofed_delta = _what_if(
        _change(
            _STORAGE_ID,
            "Modify",
            path="propertie\u017f.allowSharedKeyAcce\u017f\u017f",
            after=False,
        )
    )
    with pytest.raises(PreflightInputError, match="ambiguous Unicode"):
        evaluate_what_if(
            spoofed_delta,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )

    kelvin_alias = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Create",
            "after": {
                "properties": {
                    "allowShared\u212aeyAccess": False,
                    "allowBlobPublicAccess": False,
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                }
            },
        }
    )
    with pytest.raises(PreflightInputError, match="non-ASCII case alias"):
        evaluate_what_if(
            kelvin_alias,
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


@pytest.mark.parametrize(
    ("resource_id", "expected_codes"),
    [
        (
            _STORAGE_ID,
            {
                "public-data-plane-access",
                "storage-public-blob-access",
                "storage-shared-key-enabled",
            },
        ),
        (
            _KEY_VAULT_ID,
            {"public-data-plane-access"},
        ),
    ],
)
def test_what_if_rejects_protected_properties_ancestor_removal(
    resource_id: str,
    expected_codes: set[str],
) -> None:
    document = _what_if(
        {
            "resourceId": resource_id,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "propertyChangeType": "Delete",
                }
            ],
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({resource_id}),
        )
    } == expected_codes


def test_storage_ancestor_modify_requires_complete_protected_after_state() -> None:
    incomplete = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "propertyChangeType": "Modify",
                    "before": {
                        "allowSharedKeyAccess": False,
                        "allowBlobPublicAccess": False,
                    },
                    "after": {
                        "publicNetworkAccess": "Disabled",
                        "networkAcls": {"defaultAction": "Deny"},
                    },
                }
            ],
        }
    )
    complete = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "propertyChangeType": "Modify",
                    "after": {
                        "allowSharedKeyAccess": False,
                        "allowBlobPublicAccess": False,
                        "publicNetworkAccess": "Disabled",
                        "networkAcls": {"defaultAction": "Deny"},
                    },
                }
            ],
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            incomplete,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {
        "storage-public-blob-access",
        "storage-shared-key-enabled",
    }
    assert (
        evaluate_what_if(
            complete,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("resource_id", "after", "expected_codes"),
    [
        (
            _STORAGE_ID,
            {
                "properties": {
                    "allowSharedKeyAccess": False,
                    "allowBlobPublicAccess": False,
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                }
            },
            {
                "public-data-plane-access",
                "storage-public-blob-access",
                "storage-shared-key-enabled",
            },
        ),
        (
            _STORAGE_CONTAINER_ID,
            {"properties": {"publicAccess": "None"}},
            {"storage-container-public-access"},
        ),
    ],
)
def test_ancestor_deletion_blocks_despite_separate_safe_after_payload(
    resource_id: str,
    after: dict[str, object],
    expected_codes: set[str],
) -> None:
    document = _what_if(
        {
            "resourceId": resource_id,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "properties",
                    "propertyChangeType": "Delete",
                }
            ],
            "after": after,
        }
    )

    assert {
        item.code
        for item in evaluate_what_if(
            document,
            allowed_change_ids=frozenset({resource_id}),
        )
    } == expected_codes


@pytest.mark.parametrize(
    ("resource_id", "path", "value", "message"),
    [
        (
            _STORAGE_ID,
            "properties.allowSharedKeyAccess",
            "false",
            "allowSharedKeyAccess must be boolean",
        ),
        (
            _STORAGE_ID,
            "properties.allowBlobPublicAccess",
            {},
            "allowBlobPublicAccess must be boolean",
        ),
        (
            _STORAGE_ID,
            "properties.publicNetworkAccess",
            "Bogus",
            "unsupported value",
        ),
        (
            _STORAGE_ID,
            "properties.networkAcls.defaultAction",
            "Maybe",
            "unsupported value",
        ),
        (
            _STORAGE_CONTAINER_ID,
            "properties.publicAccess",
            {},
            "publicAccess must be a bounded string",
        ),
    ],
)
def test_storage_protection_properties_reject_malformed_values(
    resource_id: str,
    path: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(PreflightInputError, match=message):
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
        evaluate_role_assignments([_assignment(role_name="Owner", scope=scope)])


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

    assert {item.code for item in evaluate_role_assignments([assignment])} == {
        "broad-role-assignment"
    }

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
        "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
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

    assert (
        evaluate_role_assignments(
            [assignment],
            policy_document={"allowedBroadAssignments": [allowance]},
        )
        == ()
    )


def test_legacy_name_allowance_matches_id_only_builtin_assignment() -> None:
    reader_role_id = (
        f"/subscriptions/{_SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "acdd72a7-3385-48ef-bd42-f606fba81ae7"
    )
    assignment = _assignment(
        role_name=None,
        role_id=reader_role_id,
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    allowance = _assignment(
        role_name="Reader",
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )

    assert (
        evaluate_role_assignments(
            [assignment],
            policy_document={"allowedBroadAssignments": [allowance]},
        )
        == ()
    )


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


def test_rbac_management_group_assignment_is_conservative_ancestor() -> None:
    principal_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    management_group_scope = "/providers/Microsoft.Management/managementGroups/synthetic-parent"
    assignment = _assignment(
        principal_id=principal_id,
        role_name="Reader",
        scope=management_group_scope,
    )
    policy = {
        "allowedBroadAssignments": [assignment],
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["Reader"],
                "forbiddenScopePrefixes": [_RG_SCOPE],
            }
        ],
    }

    violations = evaluate_role_assignments(
        [assignment],
        policy_document=policy,
    )

    assert {item.code for item in violations} == {"identity-separation"}


def test_guarded_rbac_management_group_assignment_cannot_bypass_separation() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="Reader",
        scope=_MG_LEAF_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy["allowedBroadAssignments"] = [assignment]
    policy["separationRules"] = [
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Reader"],
            "forbiddenRoleDefinitionIds": [_TEST_ROLE_IDS["reader"]],
            "forbiddenScopePrefixes": [_RG_SCOPE],
        }
    ]

    violations = _evaluate_guarded_rbac(
        _guarded_evidence(
            [assignment],
            effective_principal_ids=[principal_id],
        ),
        policy,
    )

    assert {item.code for item in violations} == {"identity-separation"}


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


def test_rbac_rejects_builtin_role_name_with_unknown_role_id() -> None:
    with pytest.raises(PreflightInputError, match="conflict"):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="Reader",
                    role_id=(_ROLE_DEFINITION_PREFIX + "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                    scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
                )
            ]
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
        ('{"status":"Succeeded","\u017ftatus":"Failed","properties":{"changes":[]}}'),
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
    document = _what_if(_change(_STORAGE_ID, "NoChange"))
    safe_path.write_text(
        json.dumps(_attested_what_if(document)),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _what_if_cli_args(safe_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stdout.getvalue() == ("WC-029 preflight: SAFE\nCheck: what-if\nBlockers: 0\n")
    assert stderr.getvalue() == ""


def test_public_cli_emits_deterministic_json_and_blocks_delete(tmp_path) -> None:
    unsafe_path = tmp_path / "unsafe.json"
    document = _what_if(
        _change(
            _KEY_VAULT_KEY_ID,
            "Create",
            path="tags.release",
            after="wc029",
        ),
        _change(_CONTAINER_APP_ID, "Delete"),
    )
    unsafe_path.write_text(
        json.dumps(_attested_what_if(document)),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _what_if_cli_args(
            unsafe_path,
            "--format",
            "json",
        ),
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


def test_what_if_attestation_rejects_stale_replay_and_digest_changes() -> None:
    now = datetime(2026, 9, 15, 1, 0, tzinfo=UTC)
    document = _what_if(_change(_STORAGE_ID, "NoChange"))
    stale = _attested_what_if(
        document,
        collected_at=now - timedelta(hours=1),
        expires_at=now - timedelta(minutes=30),
    )
    with pytest.raises(PreflightInputError, match="has expired"):
        evaluate_what_if(
            stale,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=_json_digest(stale["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
            now=now,
        )

    changed = _attested_what_if(document)
    changed["whatIf"] = _what_if(_change(_CONTAINER_APP_ID, "Delete"))
    with pytest.raises(
        PreflightInputError,
        match="whatIfDigest does not match",
    ):
        evaluate_what_if(
            changed,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=_json_digest(changed["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    regenerated = _attested_what_if(document)
    trusted_manifest_digest = _json_digest(regenerated["manifest"])
    regenerated["whatIf"] = _what_if(_change(_CONTAINER_APP_ID, "Delete"))
    manifest = regenerated["manifest"]
    assert isinstance(manifest, dict)
    bindings = manifest["bindings"]
    assert isinstance(bindings, dict)
    bindings["whatIfDigest"] = _json_digest(regenerated["whatIf"])
    regenerated["attestation"] = _attestation(
        "what-if",
        manifest,
        (
            "allowChangeIdsDigest",
            "deploymentDigest",
            "parametersDigest",
            "templateDigest",
            "whatIfDigest",
        ),
    )
    with pytest.raises(
        PreflightInputError,
        match="manifest digest does not match",
    ):
        evaluate_what_if(
            regenerated,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=trusted_manifest_digest,
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    with pytest.raises(
        PreflightInputError,
        match="collectionRunId does not match",
    ):
        artifact = _attested_what_if(document)
        evaluate_what_if(
            artifact,
            require_attestation=True,
            expected_collection_run_id=("55555555-5555-5555-5555-555555555555"),
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    with pytest.raises(
        PreflightInputError,
        match="allowChangeIdsDigest does not match",
    ):
        artifact = _attested_what_if(document)
        evaluate_what_if(
            artifact,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


@pytest.mark.parametrize(
    "binding_input",
    ["policy", "hierarchy", "membership", "roleAssignments"],
)
def test_rbac_attestation_binds_reviewed_inputs(
    binding_input: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    evidence = _attested_rbac(
        _guarded_evidence([assignment]),
        policy,
    )
    evaluated_policy = copy.deepcopy(policy)
    if binding_input == "policy":
        target = evaluated_policy["target"]
        assert isinstance(target, dict)
        target["tenantId"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    elif binding_input == "hierarchy":
        hierarchy = evidence["hierarchy"]
        assert isinstance(hierarchy, dict)
        resource_graph = hierarchy["resourceGraph"]
        assert isinstance(resource_graph, dict)
        request = resource_graph["request"]
        assert isinstance(request, dict)
        request["query"] = str(request["query"]) + " "
    else:
        principal = _first_principal_artifact(evidence)
        artifact_name = "groupMembership" if binding_input == "membership" else "roleAssignments"
        artifact = principal[artifact_name]
        assert isinstance(artifact, dict)
        artifact["syntheticMutation"] = True

    with pytest.raises(
        PreflightInputError,
        match="does not match the reviewed input",
    ):
        evaluate_role_assignments(
            evidence,
            policy_document=evaluated_policy,
            require_separation_rules=True,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=_json_digest(evidence["manifest"]),
        )


def test_rbac_attestation_requires_the_shared_collection_run() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )

    with pytest.raises(
        PreflightInputError,
        match="collectionRunId does not match",
    ):
        artifact = _attested_rbac(
            _guarded_evidence([assignment]),
            policy,
        )
        evaluate_role_assignments(
            artifact,
            policy_document=policy,
            require_separation_rules=True,
            require_attestation=True,
            expected_collection_run_id=("55555555-5555-5555-5555-555555555555"),
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
        )


def test_rbac_attestation_cannot_be_regenerated_after_tampering() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    artifact = _attested_rbac(
        _guarded_evidence([assignment]),
        policy,
    )
    trusted_manifest_digest = _json_digest(artifact["manifest"])
    principal = _first_principal_artifact(artifact)
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    ancestors = role_assignments["ancestors"]
    descendants = role_assignments["descendants"]
    assert isinstance(ancestors, dict)
    assert isinstance(descendants, dict)
    ancestor_pages = ancestors["pages"]
    descendant_collections = descendants["collections"]
    assert isinstance(ancestor_pages, list)
    assert isinstance(descendant_collections, list)
    ancestor_page = ancestor_pages[0]
    descendant_collection = descendant_collections[0]
    assert isinstance(ancestor_page, dict)
    assert isinstance(descendant_collection, dict)
    descendant_pages = descendant_collection["pages"]
    assert isinstance(descendant_pages, list)
    descendant_page = descendant_pages[0]
    assert isinstance(descendant_page, dict)
    ancestor_page["value"] = []
    descendant_page["value"] = []
    manifest = artifact["manifest"]
    assert isinstance(manifest, dict)
    bindings = manifest["bindings"]
    assert isinstance(bindings, dict)
    rbac_payload = {
        key: value for key, value in artifact.items() if key not in {"attestation", "manifest"}
    }
    bindings["rbacEvidenceDigest"] = _json_digest(rbac_payload)
    artifact["attestation"] = _attestation(
        "rbac",
        manifest,
        ("policyDigest", "rbacEvidenceDigest"),
    )

    with pytest.raises(
        PreflightInputError,
        match="manifest digest does not match",
    ):
        evaluate_role_assignments(
            artifact,
            policy_document=policy,
            require_separation_rules=True,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            attestation_manifest_digest=trusted_manifest_digest,
        )


def test_public_cli_reports_malformed_policy_without_partial_success(tmp_path) -> None:
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text("[]", encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{", encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(
            assignments_path,
            policy_path,
            "--format",
            "json",
        ),
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
        '{"status":"Succeeded","properties":{"changes":[]},"padding":' + "9" * 5000 + "}",
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _what_if_cli_args(
            unsafe_path,
            "--format",
            "json",
        ),
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
    document = _what_if(
        _change(
            _CONTAINER_APP_ID + "\nWC-029 preflight: SAFE",
            "Delete",
        )
    )
    unsafe_path.write_text(
        json.dumps(_attested_what_if(document)),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _what_if_cli_args(unsafe_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight what-if failed: resourceId must be a bounded string\n"
    )


def test_public_cli_rejects_nonprintable_nested_json_keys(tmp_path) -> None:
    unsafe_path = tmp_path / "nested-key-injection.json"
    document = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "after": {"properties": {"configuration": {"ingress": {"external\u001b[2J": True}}}},
        }
    )
    unsafe_path.write_text(
        json.dumps(_attested_what_if(document)),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _what_if_cli_args(unsafe_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == ("WC-029 preflight what-if failed: JSON object keys are invalid\n")


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
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: RBAC policy requires at least one separation rule\n"
    )


def test_public_cli_accepts_complete_expected_principal_coverage(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignments = [
        _guarded_assignment(
            principal_id=principal_id,
            role_name="AcrPull",
            scope=_RG_SCOPE,
        )
    ]
    policy = _production_policy(
        principal_id,
        expected_assignments=assignments,
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    assignments,
                    effective_principal_ids=[principal_id],
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stdout.getvalue() == ("WC-029 preflight: SAFE\nCheck: rbac\nBlockers: 0\n")
    assert stderr.getvalue() == ""


def test_public_cli_rejects_empty_assignment_evidence(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    policy = _production_policy(principal_id)
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    [],
                    effective_principal_ids=[principal_id],
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: effective role-assignment evidence must not be empty\n"
    )


def test_public_cli_requires_role_ids_in_guarded_inventory(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(principal_id=principal_id)
    assignment.pop("roleDefinitionId")
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _guarded_evidence(
                [assignment],
                effective_principal_ids=[principal_id],
            )
        ),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: approvedAssignments require roleDefinitionId\n"
    )


def test_public_cli_requires_role_names_for_separation_matching(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    id_only_assignment = _guarded_assignment(
        principal_id=principal_id,
        scope=_RG_SCOPE,
    )
    id_only_assignment["roleDefinitionId"] = (
        _ROLE_DEFINITION_PREFIX + "73c42c96-874c-492b-b04d-ab87d138a893"
    )
    id_only_assignment.pop("roleDefinitionName")
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _guarded_evidence(
                [id_only_assignment],
                effective_principal_ids=[principal_id],
            )
        ),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[id_only_assignment],
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: approvedAssignments require roleDefinitionName\n"
    )


def test_public_cli_requires_separation_role_ids(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(principal_id=principal_id)
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _guarded_evidence(
                [assignment],
                effective_principal_ids=[principal_id],
            )
        ),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    separation_rule = policy["separationRules"][0]
    assert isinstance(separation_rule, dict)
    separation_rule.pop("forbiddenRoleDefinitionIds")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: separation rule requires forbiddenRoleDefinitionIds\n"
    )


def test_separation_rule_matches_role_id_despite_false_display_name() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    log_analytics_reader_id = _ROLE_DEFINITION_PREFIX + "73c42c96-874c-492b-b04d-ab87d138a893"
    approved_assignment = {
        "assignedPrincipalId": principal_id,
        "assignedPrincipalType": "ServicePrincipal",
        "effectivePrincipalId": principal_id,
        "roleDefinitionName": "AcrPull",
        "roleDefinitionId": log_analytics_reader_id,
        "scope": _RG_SCOPE,
    }
    policy = _production_policy(
        principal_id,
        expected_assignments=[approved_assignment],
    )
    policy["separationRules"] = [
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Log Analytics Reader"],
            "forbiddenRoleDefinitionIds": [
                log_analytics_reader_id,
            ],
            "forbiddenScopePrefixes": [_RG_SCOPE],
        }
    ]

    assert {
        item.code
        for item in _evaluate_guarded_rbac(
            _guarded_evidence(
                [approved_assignment],
                effective_principal_ids=[principal_id],
            ),
            policy,
        )
    } == {"identity-separation"}


def test_group_derived_forbidden_role_binds_to_effective_identity() -> None:
    identity_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=identity_principal_id,
        principal_type="Group",
        role_name="Log Analytics Reader",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        identity_principal_id,
        expected_assignments=[assignment],
    )
    policy["separationRules"] = [
        {
            "principalId": identity_principal_id,
            "forbiddenRoleNames": ["Log Analytics Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["log analytics reader"],
            ],
            "forbiddenScopePrefixes": [_RG_SCOPE],
        }
    ]

    violations = _evaluate_guarded_rbac(
        _guarded_evidence(
            [assignment],
            effective_principal_ids=[identity_principal_id],
        ),
        policy,
    )

    assert {item.code for item in violations} == {"identity-separation"}
    assert violations[0].subject == identity_principal_id
    assert f"via group {group_principal_id}" in violations[0].detail


@pytest.mark.parametrize(
    "scope",
    [_WORKLOAD_RESOURCE_SCOPE, _SIBLING_RG_SCOPE],
)
def test_guarded_rbac_evaluates_descendant_and_sibling_scopes(
    scope: str,
) -> None:
    identity_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=identity_principal_id,
        principal_type="Group",
        role_name="Log Analytics Reader",
        scope=scope,
    )
    policy = _production_policy(
        identity_principal_id,
        expected_assignments=[assignment],
    )
    policy["separationRules"] = [
        {
            "principalId": identity_principal_id,
            "forbiddenRoleNames": ["Log Analytics Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["log analytics reader"],
            ],
            "forbiddenScopePrefixes": [scope],
        }
    ]

    assert {
        item.code
        for item in _evaluate_guarded_rbac(
            _guarded_evidence([assignment]),
            policy,
        )
    } == {"identity-separation"}


def test_guarded_rbac_requires_complete_descendant_group_collections() -> None:
    identity_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=identity_principal_id,
        principal_type="Group",
        role_name="Log Analytics Reader",
        scope=_SIBLING_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    descendants = role_assignments["descendants"]
    assert isinstance(descendants, dict)
    collections = descendants["collections"]
    assert isinstance(collections, list)
    collections.pop()

    with pytest.raises(
        PreflightInputError,
        match="do not exactly cover",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                identity_principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_equivalent_separation_rules() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy["separationRules"] = [
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Owner"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["owner"],
                _TEST_ROLE_IDS["reader"],
            ],
            "forbiddenScopePrefixes": [_SUBSCRIPTION_SCOPE],
        },
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Owner", "Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["reader"],
                _TEST_ROLE_IDS["owner"],
            ],
            "forbiddenScopePrefixes": [
                _SUBSCRIPTION_SCOPE,
                _RG_SCOPE,
            ],
        },
    ]

    with pytest.raises(
        PreflightInputError,
        match="equivalent duplicate rule",
    ):
        _evaluate_guarded_rbac(
            _guarded_evidence([assignment]),
            policy,
        )


def test_guarded_rbac_deduplicates_matching_rule_violations() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="Reader",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy["allowedBroadAssignments"] = [assignment]
    policy["separationRules"] = [
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["reader"],
            ],
            "forbiddenScopePrefixes": [_RG_SCOPE],
        },
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["reader"],
            ],
            "forbiddenScopePrefixes": [_SUBSCRIPTION_SCOPE],
        },
    ]

    violations = _evaluate_guarded_rbac(
        _guarded_evidence([assignment]),
        policy,
    )

    assert [item.code for item in violations] == ["identity-separation"]


def test_guarded_rbac_rejects_flat_or_self_asserted_inventory() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    for evidence in (
        [assignment],
        {
            "collection": {
                "effectivePrincipalIds": [principal_id],
                "includeGroups": True,
                "includeInherited": True,
                "allScopes": True,
            },
            "value": [assignment],
        },
    ):
        with pytest.raises(
            PreflightInputError,
            match="RBAC",
        ):
            evaluate_role_assignments(
                evidence,
                policy_document=_production_policy(
                    principal_id,
                    expected_assignments=[assignment],
                ),
                require_separation_rules=True,
                require_attestation=True,
                expected_collection_run_id=_COLLECTION_RUN_ID,
            )


@pytest.mark.parametrize(
    "evidence_kind",
    ["arm", "graph"],
)
def test_guarded_rbac_rejects_pagination_gaps(
    evidence_kind: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence(
        [assignment],
        effective_principal_ids=[principal_id],
    )
    principal = _first_principal_artifact(evidence)
    if evidence_kind == "arm":
        role_assignments = principal["roleAssignments"]
        assert isinstance(role_assignments, dict)
        container = role_assignments["ancestors"]
    else:
        container = principal["groupMembership"]
    assert isinstance(container, dict)
    pages = container["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    next_link_name = "nextLink" if evidence_kind == "arm" else "@odata.nextLink"
    page[next_link_name] = (
        "https://management.azure.com/next"
        if evidence_kind == "arm"
        else "https://graph.microsoft.com/next"
    )

    with pytest.raises(
        PreflightInputError,
        match="pagination is incomplete",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("evidence_kind", "query_suffix", "message"),
    [
        (
            "arm",
            "&%24skipToken=synthetic",
            "requestUrl is not canonical",
        ),
        (
            "arm",
            "&tenantId=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "requestUrl is not canonical",
        ),
        (
            "graph",
            "?%24skiptoken=synthetic",
            "must be unfiltered",
        ),
        (
            "graph",
            "?%24filter=securityEnabled%20eq%20true",
            "must be unfiltered",
        ),
    ],
)
def test_guarded_rbac_rejects_partial_initial_requests(
    evidence_kind: str,
    query_suffix: str,
    message: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    if evidence_kind == "arm":
        role_assignments = principal["roleAssignments"]
        assert isinstance(role_assignments, dict)
        container = role_assignments["ancestors"]
    else:
        container = principal["groupMembership"]
    assert isinstance(container, dict)
    pages = container["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page["requestUrl"] = str(page["requestUrl"]) + query_suffix

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_public_cli_reports_malformed_evidence_url(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    ancestors = role_assignments["ancestors"]
    assert isinstance(ancestors, dict)
    pages = ancestors["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page["requestUrl"] = "https://[invalid"
    evidence_path = tmp_path / "rbac.json"
    policy_path = tmp_path / "policy.json"
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    evidence_path.write_text(
        json.dumps(_attested_rbac(evidence, policy)),
        encoding="utf-8",
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(evidence_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert "is not a valid URL" in stderr.getvalue()


def test_guarded_rbac_rejects_inconsistent_hierarchy_sources() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    hierarchy = evidence["hierarchy"]
    assert isinstance(hierarchy, dict)
    resource_graph = hierarchy["resourceGraph"]
    assert isinstance(resource_graph, dict)
    body = resource_graph["body"]
    assert isinstance(body, dict)
    data = body["data"]
    assert isinstance(data, list)
    row = data[0]
    assert isinstance(row, dict)
    properties = row["properties"]
    assert isinstance(properties, dict)
    chain = properties["managementGroupAncestorsChain"]
    assert isinstance(chain, list)
    properties["managementGroupAncestorsChain"] = list(reversed(chain))

    with pytest.raises(
        PreflightInputError,
        match="Resource Graph and ARM management-group hierarchies disagree",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("field_name", "field_value", "message"),
    [
        ("skipToken", "synthetic", "paginated or incomplete"),
        ("$skipToken", "synthetic", "paginated or incomplete"),
        ("resultTruncated", True, "explicitly non-truncated"),
        ("resultTruncated", None, "explicitly non-truncated"),
        ("count", 0, "count and totalRecords"),
        ("totalRecords", 2, "count and totalRecords"),
    ],
)
def test_guarded_rbac_requires_complete_resource_graph_result(
    field_name: str,
    field_value: object,
    message: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    hierarchy = evidence["hierarchy"]
    assert isinstance(hierarchy, dict)
    resource_graph = hierarchy["resourceGraph"]
    assert isinstance(resource_graph, dict)
    body = resource_graph["body"]
    assert isinstance(body, dict)
    body[field_name] = field_value

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_cyclic_or_missing_arm_hierarchy() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    cyclic = _guarded_evidence([assignment])
    hierarchy = cyclic["hierarchy"]
    assert isinstance(hierarchy, dict)
    arm = hierarchy["arm"]
    assert isinstance(arm, dict)
    groups = arm["managementGroups"]
    assert isinstance(groups, list)
    root = groups[1]
    assert isinstance(root, dict)
    root_body = root["body"]
    assert isinstance(root_body, dict)
    root_properties = root_body["properties"]
    assert isinstance(root_properties, dict)
    root_details = root_properties["details"]
    assert isinstance(root_details, dict)
    root_details["parent"] = {"id": _MG_LEAF_SCOPE}
    with pytest.raises(PreflightInputError, match="hierarchy is cyclic"):
        _evaluate_guarded_rbac(
            cyclic,
            policy,
        )

    missing = _guarded_evidence([assignment])
    hierarchy = missing["hierarchy"]
    assert isinstance(hierarchy, dict)
    arm = hierarchy["arm"]
    assert isinstance(arm, dict)
    groups = arm["managementGroups"]
    assert isinstance(groups, list)
    groups.pop()
    with pytest.raises(
        PreflightInputError,
        match="omits an ancestor",
    ):
        _evaluate_guarded_rbac(
            missing,
            policy,
        )


def test_guarded_rbac_rejects_cross_tenant_or_changed_hierarchy() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    cross_tenant = _guarded_evidence([assignment])
    hierarchy = cross_tenant["hierarchy"]
    assert isinstance(hierarchy, dict)
    arm = hierarchy["arm"]
    assert isinstance(arm, dict)
    groups = arm["managementGroups"]
    assert isinstance(groups, list)
    leaf = groups[0]
    assert isinstance(leaf, dict)
    leaf_body = leaf["body"]
    assert isinstance(leaf_body, dict)
    leaf_properties = leaf_body["properties"]
    assert isinstance(leaf_properties, dict)
    leaf_properties["tenantId"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    with pytest.raises(PreflightInputError, match="crosses tenants"):
        _evaluate_guarded_rbac(
            cross_tenant,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )

    changed_policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    target = changed_policy["target"]
    assert isinstance(target, dict)
    target["approvedManagementGroupAncestry"] = [
        _MG_ROOT_SCOPE,
        _MG_LEAF_SCOPE,
    ]
    with pytest.raises(
        PreflightInputError,
        match="hierarchy changed from the reviewed policy",
    ):
        _evaluate_guarded_rbac(
            _guarded_evidence([assignment]),
            changed_policy,
        )


@pytest.mark.parametrize(
    ("component", "status_code"),
    [
        ("servicePrincipal", 404),
        ("groupMembership", 403),
        ("roleAssignments", 404),
        ("hierarchy", 403),
    ],
)
def test_guarded_rbac_rejects_failed_evidence_requests(
    component: str,
    status_code: int,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    if component == "hierarchy":
        hierarchy = evidence["hierarchy"]
        assert isinstance(hierarchy, dict)
        resource_graph = hierarchy["resourceGraph"]
        assert isinstance(resource_graph, dict)
        resource_graph["statusCode"] = status_code
    else:
        principal = _first_principal_artifact(evidence)
        artifact = principal[component]
        assert isinstance(artifact, dict)
        if component == "servicePrincipal":
            artifact["statusCode"] = status_code
        else:
            if component == "roleAssignments":
                artifact = artifact["ancestors"]
                assert isinstance(artifact, dict)
            pages = artifact["pages"]
            assert isinstance(pages, list)
            page = pages[0]
            assert isinstance(page, dict)
            page["statusCode"] = status_code

    with pytest.raises(PreflightInputError, match=f"HTTP {status_code}"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_graph_arm_membership_disagreement() -> None:
    identity_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=identity_principal_id,
        principal_type="Group",
        role_name="Log Analytics Reader",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    membership = principal["groupMembership"]
    assert isinstance(membership, dict)
    pages = membership["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page["value"] = []

    with pytest.raises(
        PreflightInputError,
        match="disagrees with Graph membership",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                identity_principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_direct_assignment_to_another_object() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    ancestors = role_assignments["ancestors"]
    assert isinstance(ancestors, dict)
    pages = ancestors["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    values = page["value"]
    assert isinstance(values, list)
    raw_assignment = values[0]
    assert isinstance(raw_assignment, dict)
    properties = raw_assignment["properties"]
    assert isinstance(properties, dict)
    properties["principalId"] = "33333333-3333-3333-3333-333333333333"

    with pytest.raises(
        PreflightInputError,
        match="does not target the effective service principal",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_expected_assignments_as_completeness() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy["expectedAssignments"] = policy.pop("approvedAssignments")

    with pytest.raises(
        PreflightInputError,
        match="must use approvedAssignments, not expectedAssignments",
    ):
        _evaluate_guarded_rbac(
            _guarded_evidence([assignment]),
            policy,
        )


def test_guarded_rbac_rejects_client_id_as_effective_principal() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    service_principal = principal["servicePrincipal"]
    assert isinstance(service_principal, dict)
    principal["effectivePrincipalId"] = service_principal["appId"]

    with pytest.raises(
        PreflightInputError,
        match="client ID, not an object ID",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_accepts_paged_transitive_security_groups() -> None:
    identity_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=identity_principal_id,
        principal_type="Group",
        role_name="Log Analytics Reader",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    second_url = (
        "https://graph.microsoft.com/v1.0/servicePrincipals/"
        f"{identity_principal_id}/transitiveMemberOf?$skiptoken=synthetic"
    )
    principal["groupMembership"] = {
        "tenantId": _TENANT_ID,
        "method": "transitiveMemberOf",
        "pages": [
            {
                "requestUrl": (
                    "https://graph.microsoft.com/v1.0/servicePrincipals/"
                    f"{identity_principal_id}/transitiveMemberOf"
                ),
                "statusCode": 200,
                "value": [],
                "@odata.nextLink": second_url,
            },
            {
                "requestUrl": second_url,
                "statusCode": 200,
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.group",
                        "id": group_principal_id,
                        "securityEnabled": True,
                    }
                ],
                "@odata.nextLink": None,
            },
        ],
    }
    policy = _production_policy(
        identity_principal_id,
        expected_assignments=[assignment],
    )
    policy["separationRules"] = [
        {
            "principalId": identity_principal_id,
            "forbiddenRoleNames": ["Log Analytics Reader"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["log analytics reader"],
            ],
            "forbiddenScopePrefixes": [_RG_SCOPE],
        }
    ]

    assert {
        item.code
        for item in _evaluate_guarded_rbac(
            evidence,
            policy,
        )
    } == {"identity-separation"}


def test_guarded_rbac_cli_equivalent_requires_exact_flags() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    principal["roleAssignments"] = {
        "ancestors": {
            "method": "azure-cli",
            "exitCode": 0,
            "arguments": [
                "--subscription",
                _SUBSCRIPTION_ID,
                "--scope",
                _RG_SCOPE,
                "--assignee-object-id",
                principal_id,
                "--include-inherited",
                "--include-groups",
                "--output",
                "json",
            ],
            "value": [_cli_assignment(assignment)],
        },
        "descendants": {
            "method": "azure-cli",
            "exitCode": 0,
            "arguments": [
                "--subscription",
                _SUBSCRIPTION_ID,
                "--assignee-object-id",
                principal_id,
                "--include-groups",
                "--all",
                "--output",
                "json",
            ],
            "value": [_cli_assignment(assignment)],
        },
    }
    assert (
        _evaluate_guarded_rbac(
            evidence,
            policy,
        )
        == ()
    )

    for bad_arguments in (
        [
            "--subscription",
            _SUBSCRIPTION_ID,
            "--assignee-object-id",
            principal_id,
            "--all",
            "--output",
            "json",
        ],
        [
            "--subscription",
            _SUBSCRIPTION_ID,
            "--scope",
            _RG_SCOPE,
            "--assignee-object-id",
            principal_id,
            "--include-groups",
            "--all",
            "--output",
            "json",
        ],
        [
            "--subscription",
            _SUBSCRIPTION_ID,
            "--assignee-object-id",
            principal_id,
            "--include-groups",
            "--all",
            "--output",
            "json",
            "--query",
            "[?roleDefinitionName=='AcrPull']",
        ],
        [
            "--subscription",
            _SUBSCRIPTION_ID,
            f"--scope={_SUBSCRIPTION_SCOPE}",
            "--assignee-object-id",
            principal_id,
            "--include-groups",
            "--all",
            "--output",
            "json",
        ],
    ):
        invalid = copy.deepcopy(evidence)
        invalid_principal = _first_principal_artifact(invalid)
        role_assignments = invalid_principal["roleAssignments"]
        assert isinstance(role_assignments, dict)
        descendants = role_assignments["descendants"]
        assert isinstance(descendants, dict)
        descendants["arguments"] = bad_arguments
        with pytest.raises(PreflightInputError):
            _evaluate_guarded_rbac(
                invalid,
                policy,
            )


def test_public_cli_requires_role_ids_in_broad_allowances(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="Reader",
    )
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps([assignment]),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[assignment],
    )
    policy["allowedBroadAssignments"] = [
        _assignment(
            principal_id=principal_id,
            role_name="Reader",
        )
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: allowedBroadAssignments require roleDefinitionId\n"
    )


@pytest.mark.parametrize(
    ("assignments", "policy", "message"),
    [
        (
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
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
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
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
            "RBAC policy requires approvedAssignments",
        ),
        (
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            _production_policy("22222222-2222-2222-2222-222222222222"),
            "RBAC evidence effectivePrincipalIds must exactly match expectedPrincipalIds",
        ),
        (
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                **_production_policy(
                    "11111111-1111-1111-1111-111111111111",
                    "22222222-2222-2222-2222-222222222222",
                ),
            },
            "derived effective assignments do not exactly match approvedAssignments",
        ),
        (
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                **_production_policy(
                    "11111111-1111-1111-1111-111111111111",
                ),
                "separationRules": [
                    {
                        "principalId": "22222222-2222-2222-2222-222222222222",
                        "forbiddenRoleNames": ["Owner"],
                        "forbiddenRoleDefinitionIds": [
                            _TEST_ROLE_IDS["owner"],
                        ],
                        "forbiddenScopePrefixes": [
                            f"/subscriptions/{_SUBSCRIPTION_ID}",
                        ],
                    }
                ],
            },
            "separationRules principals must exactly match expectedPrincipalIds",
        ),
        (
            [_guarded_assignment(principal_id="11111111-1111-1111-1111-111111111111")],
            {
                **_production_policy(
                    "11111111-1111-1111-1111-111111111111",
                ),
                "allowedBroadAssignments": [
                    _guarded_assignment(
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
    expected_principal_ids = policy.get("expectedPrincipalIds")
    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    assignments,
                    effective_principal_ids=(
                        expected_principal_ids if isinstance(expected_principal_ids, list) else None
                    ),
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == f"WC-029 preflight rbac failed: {message}\n"


def test_public_cli_rejects_truncated_assignment_inventory(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    safe_assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    omitted_owner = _guarded_assignment(
        principal_id=principal_id,
        role_name="Owner",
        scope=f"/subscriptions/{_SUBSCRIPTION_ID}",
    )
    assignments_path = tmp_path / "assignments.json"
    policy_path = tmp_path / "policy.json"
    policy = _production_policy(
        principal_id,
        expected_assignments=[safe_assignment, omitted_owner],
    )
    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    [safe_assignment],
                    effective_principal_ids=[principal_id],
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(
            assignments_path,
            policy_path,
            "--format",
            "json",
        ),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": ("derived effective assignments do not exactly match approvedAssignments"),
        "kind": "rbac",
        "safe": False,
    }


def test_public_cli_requires_exact_rbac_condition_inventory(tmp_path) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    condition = (
        "@Resource[Microsoft.Storage/storageAccounts/"
        "blobServices/containers:name] StringEquals 'evidence'"
    )
    conditional_assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="Storage Blob Data Reader",
        scope=_RG_SCOPE,
        condition=condition,
        condition_version="2.0",
    )
    assignments_path = tmp_path / "assignments.json"
    policy_path = tmp_path / "policy.json"
    policy = _production_policy(
        principal_id,
        expected_assignments=[conditional_assignment],
    )
    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    [conditional_assignment],
                    effective_principal_ids=[principal_id],
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    assert (
        cli_main(
            _rbac_cli_args(assignments_path, policy_path),
            stdout=stdout,
            stderr=stderr,
        )
        == 0
    )
    assert stderr.getvalue() == ""

    assignments_path.write_text(
        json.dumps(
            _attested_rbac(
                _guarded_evidence(
                    [
                        _guarded_assignment(
                            principal_id=principal_id,
                            role_name="Storage Blob Data Reader",
                            scope=conditional_assignment["scope"],
                        )
                    ],
                    effective_principal_ids=[principal_id],
                ),
                policy,
            )
        ),
        encoding="utf-8",
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(
            assignments_path,
            policy_path,
            "--format",
            "json",
        ),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue()) == {
        "error": ("derived effective assignments do not exactly match approvedAssignments"),
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
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: roleDefinitionName and roleDefinitionId conflict\n"
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
    expected_assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    expected_assignment["roleDefinitionId"] = expected_role_id
    assignments_path = tmp_path / "assignments.json"
    assignments_path.write_text(
        json.dumps(
            _guarded_evidence(
                [expected_assignment],
                effective_principal_ids=[principal_id],
            )
        ),
        encoding="utf-8",
    )
    policy = _production_policy(
        principal_id,
        expected_assignments=[expected_assignment],
    )
    policy["allowedBroadAssignments"] = [
        {
            **expected_assignment,
            "roleDefinitionId": different_role_id,
        }
    ]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = cli_main(
        _rbac_cli_args(assignments_path, policy_path),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 3
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "WC-029 preflight rbac failed: "
        "allowedBroadAssignments must be listed in approvedAssignments\n"
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
        _rbac_cli_args(assignments_path, policy_path),
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
