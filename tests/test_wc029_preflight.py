from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import StringIO
from pathlib import Path
from threading import Barrier
from urllib.parse import urlencode

import pytest

import athena_context.wc029_preflight as wc029_preflight_module
from athena_context.cli import main as cli_main
from athena_context.wc029_preflight import (
    MAX_RELEASE_LEDGER_RECORD_BYTES,
    PreflightInputError,
    PreflightViolation,
    _build_snapshot_pair_index,
    _canonical_json_digest,
    _PropertyPathBudget,
    _SecureLedgerDirectory,
    _walk_delta,
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
_DEPLOYMENT_EXECUTION_ID = "55555555-5555-5555-5555-555555555555"
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
_DEPLOYMENT_STACK_ID = f"{_RG_SCOPE}/providers/Microsoft.Resources/deploymentStacks/synthetic-stack"
_STORAGE_CONTAINER_ID = f"{_STORAGE_ID}/blobServices/default/containers/evidence"
_STORAGE_LOCAL_USER_ID = f"{_STORAGE_ID}/localUsers/synthetic-user"
_KEY_VAULT_KEY_ID = f"{_KEY_VAULT_ID}/keys/report-signing"
_WC013_RG_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/rg-athena-wc013-live"
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


def _deployment_target(
    *,
    tenant_id: str = _TENANT_ID,
    subscription_id: str = _SUBSCRIPTION_ID,
    resource_group_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    reviewed_resource_groups = (
        (_RG_SCOPE, _WC013_RG_SCOPE) if resource_group_ids is None else resource_group_ids
    )
    return {
        "tenantId": tenant_id,
        "subscriptionId": subscription_id,
        "resourceGroupIds": sorted(
            scope.strip().lower().rstrip("/") for scope in reviewed_resource_groups
        ),
    }


def _what_if_request(
    *,
    deployment_target: dict[str, object] | None = None,
) -> dict[str, object]:
    target = _deployment_target() if deployment_target is None else deployment_target
    subscription_id = target["subscriptionId"]
    assert isinstance(subscription_id, str)
    return {
        "command": ["az", "deployment", "sub", "what-if"],
        "arguments": [
            "--subscription",
            subscription_id,
            "--location",
            "australiaeast",
            "--name",
            "synthetic-wc029",
            "--parameters",
            "infra/main.bicepparam",
            "--result-format",
            "FullResourcePayloads",
            "--validation-level",
            "Provider",
            "--no-prompt",
            "true",
            "--no-pretty-print",
            "--output",
            "json",
        ],
    }


def _group_what_if_request(
    *,
    deployment_target: dict[str, object] | None = None,
) -> dict[str, object]:
    request = _what_if_request(deployment_target=deployment_target)
    command = request["command"]
    arguments = request["arguments"]
    assert isinstance(command, list)
    assert isinstance(arguments, list)
    command[2] = "group"
    location_index = arguments.index("--location")
    arguments[location_index : location_index + 2] = [
        "--resource-group",
        _RG_SCOPE.rsplit("/", 1)[-1],
    ]
    return request


def _json_digest(value: object) -> str:
    return _canonical_json_digest(value)


def _manifest(
    bindings: dict[str, str],
    *,
    collection_run_id: str = _COLLECTION_RUN_ID,
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
    deployment_target: dict[str, object] | None = None,
    what_if_request: dict[str, object] | None = None,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    collected = datetime.now(UTC).replace(microsecond=0) if collected_at is None else collected_at
    expires = collected + timedelta(minutes=10) if expires_at is None else expires_at
    return {
        "schemaVersion": "athena.wc029PreflightManifest.v1",
        "collectionRunId": collection_run_id,
        "deploymentExecutionId": deployment_execution_id,
        "deploymentTarget": (
            _deployment_target() if deployment_target is None else copy.deepcopy(deployment_target)
        ),
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
        "deploymentExecutionId": manifest["deploymentExecutionId"],
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
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
    deployment_target: dict[str, object] | None = None,
    what_if_request: dict[str, object] | None = None,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    allowlist_records = sorted(
        (
            {
                "canonical": value.strip().lower().rstrip("/"),
                "raw": value.strip(),
            }
            for value in allowed_change_ids
        ),
        key=lambda item: (item["raw"], item["canonical"]),
    )
    request = (
        _what_if_request(deployment_target=deployment_target)
        if what_if_request is None
        else copy.deepcopy(what_if_request)
    )
    manifest = _manifest(
        {
            "allowChangeIdsDigest": _json_digest({"allowChangeIds": allowlist_records}),
            "deploymentDigest": _DEPLOYMENT_DIGEST,
            "parametersDigest": _PARAMETERS_DIGEST,
            "policyDigest": _EMPTY_DIGEST,
            "rbacEvidenceDigest": _EMPTY_DIGEST,
            "templateDigest": _TEMPLATE_DIGEST,
            "whatIfDigest": _json_digest(document),
            "whatIfRequestDigest": _json_digest(request),
        },
        collection_run_id=collection_run_id,
        deployment_execution_id=deployment_execution_id,
        deployment_target=deployment_target,
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
                "whatIfRequestDigest",
            ),
        ),
        "manifest": manifest,
        "whatIf": document,
        "whatIfRequest": request,
    }


def _attested_rbac(
    evidence: dict[str, object],
    policy: dict[str, object],
    *,
    collection_run_id: str = _COLLECTION_RUN_ID,
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
    deployment_target: dict[str, object] | None = None,
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
            "whatIfRequestDigest": _EMPTY_DIGEST,
        },
        collection_run_id=collection_run_id,
        deployment_execution_id=deployment_execution_id,
        deployment_target=deployment_target,
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


def _attested_pair(
    what_if: object,
    evidence: dict[str, object],
    policy: dict[str, object],
    *,
    allowed_change_ids: frozenset[str] = frozenset(),
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
    deployment_target: dict[str, object] | None = None,
    what_if_request: dict[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    allowlist_records = sorted(
        (
            {
                "canonical": value.strip().lower().rstrip("/"),
                "raw": value.strip(),
            }
            for value in allowed_change_ids
        ),
        key=lambda item: (item["raw"], item["canonical"]),
    )
    request = (
        _what_if_request(deployment_target=deployment_target)
        if what_if_request is None
        else copy.deepcopy(what_if_request)
    )
    rbac_payload = copy.deepcopy(evidence)
    manifest = _manifest(
        {
            "allowChangeIdsDigest": _json_digest({"allowChangeIds": allowlist_records}),
            "deploymentDigest": _DEPLOYMENT_DIGEST,
            "parametersDigest": _PARAMETERS_DIGEST,
            "policyDigest": _json_digest(policy),
            "rbacEvidenceDigest": _json_digest(rbac_payload),
            "templateDigest": _TEMPLATE_DIGEST,
            "whatIfDigest": _json_digest(what_if),
            "whatIfRequestDigest": _json_digest(request),
        },
        deployment_execution_id=deployment_execution_id,
        deployment_target=deployment_target,
    )
    what_if_manifest = copy.deepcopy(manifest)
    rbac_manifest = copy.deepcopy(manifest)
    return (
        {
            "attestation": _attestation(
                "what-if",
                what_if_manifest,
                (
                    "allowChangeIdsDigest",
                    "deploymentDigest",
                    "parametersDigest",
                    "templateDigest",
                    "whatIfDigest",
                    "whatIfRequestDigest",
                ),
            ),
            "manifest": what_if_manifest,
            "whatIf": what_if,
            "whatIfRequest": request,
        },
        {
            **rbac_payload,
            "attestation": _attestation(
                "rbac",
                rbac_manifest,
                ("policyDigest", "rbacEvidenceDigest"),
            ),
            "manifest": rbac_manifest,
        },
    )


def _artifact_manifest_digest(input_path: object) -> str:
    try:
        document = json.loads(Path(str(input_path)).read_text(encoding="utf-8"))
        return _json_digest(document["manifest"])
    except OSError, KeyError, TypeError, ValueError, json.JSONDecodeError:
        return _EMPTY_DIGEST


def _what_if_cli_args(
    input_path: object,
    *extra: str,
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
) -> list[str]:
    trusted_root = Path(str(input_path)).parent / "trusted-release-ledger-root"
    release_ledger = trusted_root / "release-ledger"
    release_ledger.mkdir(parents=True, exist_ok=True)
    return [
        "wc029-preflight",
        "what-if",
        str(input_path),
        "--collection-run-id",
        _COLLECTION_RUN_ID,
        "--deployment-execution-id",
        deployment_execution_id,
        "--release-ledger",
        str(release_ledger),
        "--trusted-release-ledger-root",
        str(trusted_root),
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
    deployment_execution_id: str = _DEPLOYMENT_EXECUTION_ID,
) -> list[str]:
    trusted_root = Path(str(input_path)).parent / "trusted-release-ledger-root"
    release_ledger = trusted_root / "release-ledger"
    release_ledger.mkdir(parents=True, exist_ok=True)
    return [
        "wc029-preflight",
        "rbac",
        str(input_path),
        "--policy",
        str(policy_path),
        "--collection-run-id",
        _COLLECTION_RUN_ID,
        "--deployment-execution-id",
        deployment_execution_id,
        "--release-ledger",
        str(release_ledger),
        "--trusted-release-ledger-root",
        str(trusted_root),
        "--attestation-manifest-digest",
        _artifact_manifest_digest(input_path),
        *extra,
    ]


def _replace_cli_option(arguments: list[str], option: str, value: Path) -> None:
    arguments[arguments.index(option) + 1] = str(value)


def _create_windows_junction(link: Path, target: Path) -> None:
    subprocess.run(
        [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(link),
            str(target),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


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
        expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
        attestation_manifest_digest=_json_digest(artifact["manifest"]),
        now=now,
    )


def _evaluate_attested_what_if(
    document: object,
    *,
    allowed_change_ids: frozenset[str] = frozenset(),
    deployment_target: dict[str, object] | None = None,
) -> tuple[PreflightViolation, ...]:
    artifact = _attested_what_if(
        document,
        allowed_change_ids=allowed_change_ids,
        deployment_target=deployment_target,
    )
    return evaluate_what_if(
        artifact,
        allowed_change_ids=allowed_change_ids,
        require_attestation=True,
        expected_collection_run_id=_COLLECTION_RUN_ID,
        expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
        attestation_manifest_digest=_json_digest(artifact["manifest"]),
        deployment_digest=_DEPLOYMENT_DIGEST,
        template_digest=_TEMPLATE_DIGEST,
        parameters_digest=_PARAMETERS_DIGEST,
    )


def _what_if(*changes: object) -> dict[str, object]:
    return {
        "status": "Succeeded",
        "properties": {"changes": list(changes)},
    }


def _resource_type_for_test(resource_id: str) -> str:
    segments = resource_id.strip("/").split("/")
    if (
        len(segments) == 4
        and segments[0].casefold() == "subscriptions"
        and segments[2].casefold() == "resourcegroups"
    ):
        return "Microsoft.Resources/resourceGroups"
    provider_index = max(
        index for index, segment in enumerate(segments) if segment.casefold() == "providers"
    )
    namespace = segments[provider_index + 1]
    type_segments = segments[provider_index + 2 :: 2]
    return "/".join((namespace, *type_segments))


def _resource_snapshot(
    resource_id: str,
    *,
    properties: dict[str, object] | None = None,
    **values: object,
) -> dict[str, object]:
    snapshot: dict[str, object] = {
        "id": resource_id,
        "name": resource_id.rstrip("/").rsplit("/", 1)[-1],
        "type": _resource_type_for_test(resource_id),
        "properties": {} if properties is None else properties,
    }
    snapshot.update(values)
    return snapshot


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
    if change_type.casefold() == "nochange":
        snapshot = {
            "id": resource_id,
            "name": resource_id.rstrip("/").rsplit("/", 1)[-1],
            "type": _resource_type_for_test(resource_id),
            "properties": {},
        }
        value["before"] = copy.deepcopy(snapshot)
        value["after"] = snapshot
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


def _raw_arm_deny_assignment(
    *,
    scope: str = _RG_SCOPE,
    principals: list[tuple[str, str]] | None = None,
    exclude_principals: list[tuple[str, str]] | None = None,
    do_not_apply_to_child_scopes: bool = False,
    condition: str | None = None,
    index: int = 0,
) -> dict[str, object]:
    reviewed_principals = (
        [("11111111-1111-1111-1111-111111111111", "ServicePrincipal")]
        if principals is None
        else principals
    )
    reviewed_exclusions = [] if exclude_principals is None else exclude_principals
    assignment_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        (
            f"deny:{scope}:{reviewed_principals}:{reviewed_exclusions}:"
            f"{do_not_apply_to_child_scopes}:{condition}:{index}"
        ),
    )
    resource_id = (
        f"/providers/Microsoft.Authorization/denyAssignments/{assignment_id}"
        if scope == "/"
        else f"{scope}/providers/Microsoft.Authorization/denyAssignments/{assignment_id}"
    )
    properties: dict[str, object] = {
        "permissions": [
            {
                "actions": ["Microsoft.Storage/storageAccounts/read"],
                "notActions": [],
                "dataActions": [],
                "notDataActions": [],
            }
        ],
        "scope": scope,
        "doNotApplyToChildScopes": do_not_apply_to_child_scopes,
        "principals": [
            {
                "id": principal_id,
                "type": principal_type,
            }
            for principal_id, principal_type in reviewed_principals
        ],
        "excludePrincipals": [
            {
                "id": principal_id,
                "type": principal_type,
            }
            for principal_id, principal_type in reviewed_exclusions
        ],
        "isSystemProtected": True,
    }
    if condition is not None:
        properties["condition"] = condition
        properties["conditionVersion"] = "2.0"
    return {
        "id": resource_id,
        "type": "Microsoft.Authorization/denyAssignments",
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
                        "displayName": "Synthetic Workload Subscription",
                        "parent": {"id": _MG_LEAF_SCOPE},
                        "state": "Active",
                        "tenant": _TENANT_ID,
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


def _deny_assignment_evidence() -> dict[str, object]:
    target_query = urlencode(
        {
            "api-version": "2022-04-01",
            "$filter": "atScope()",
        }
    )
    subscription_query = urlencode(
        {
            "api-version": "2022-04-01",
        }
    )
    return {
        "method": "arm",
        "collections": [
            {
                "collectionType": "target-and-ancestors",
                "apiVersion": "2022-04-01",
                "scope": _RG_SCOPE,
                "filter": "atScope()",
                "pages": [
                    {
                        "requestUrl": (
                            "https://management.azure.com"
                            f"{_RG_SCOPE}/providers/Microsoft.Authorization/"
                            f"denyAssignments?{target_query}"
                        ),
                        "statusCode": 200,
                        "value": [],
                        "nextLink": None,
                    }
                ],
            },
            {
                "collectionType": "subscription-inventory",
                "apiVersion": "2022-04-01",
                "scope": _SUBSCRIPTION_SCOPE,
                "pages": [
                    {
                        "requestUrl": (
                            "https://management.azure.com"
                            f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/"
                            f"denyAssignments?{subscription_query}"
                        ),
                        "statusCode": 200,
                        "value": [],
                        "nextLink": None,
                    }
                ],
            },
        ],
    }


def _deny_assignment_collection(
    evidence: dict[str, object],
    collection_type: str,
) -> dict[str, object]:
    principal = _first_principal_artifact(evidence)
    deny_assignments = principal["denyAssignments"]
    assert isinstance(deny_assignments, dict)
    collections = deny_assignments["collections"]
    assert isinstance(collections, list)
    for raw_collection in collections:
        assert isinstance(raw_collection, dict)
        if raw_collection["collectionType"] == collection_type:
            return raw_collection
    raise AssertionError(f"missing deny-assignment collection {collection_type}")


def _add_deny_assignment(
    evidence: dict[str, object],
    assignment: dict[str, object],
    *,
    target_and_ancestors: bool,
    subscription_inventory: bool,
) -> None:
    for collection_type, include in (
        ("target-and-ancestors", target_and_ancestors),
        ("subscription-inventory", subscription_inventory),
    ):
        if not include:
            continue
        collection = _deny_assignment_collection(
            evidence,
            collection_type,
        )
        pages = collection["pages"]
        assert isinstance(pages, list)
        page = pages[0]
        assert isinstance(page, dict)
        values = page["value"]
        assert isinstance(values, list)
        values.append(copy.deepcopy(assignment))


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
                "denyAssignments": _deny_assignment_evidence(),
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


def _management_group_subscription_properties(
    evidence: dict[str, object],
) -> dict[str, object]:
    hierarchy = evidence["hierarchy"]
    assert isinstance(hierarchy, dict)
    arm = hierarchy["arm"]
    assert isinstance(arm, dict)
    subscription = arm["subscription"]
    assert isinstance(subscription, dict)
    body = subscription["body"]
    assert isinstance(body, dict)
    properties = body["properties"]
    assert isinstance(properties, dict)
    return properties


def _arm_role_assignment_pages(
    evidence: dict[str, object],
    *,
    collection_kind: str,
) -> list[object]:
    principal = _first_principal_artifact(evidence)
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    if collection_kind == "ancestors":
        collection = role_assignments["ancestors"]
    else:
        assert collection_kind == "descendants"
        descendants = role_assignments["descendants"]
        assert isinstance(descendants, dict)
        collections = descendants["collections"]
        assert isinstance(collections, list)
        collection = collections[0]
    assert isinstance(collection, dict)
    pages = collection["pages"]
    assert isinstance(pages, list)
    return pages


def _set_two_page_arm_role_assignments(
    evidence: dict[str, object],
    *,
    collection_kind: str,
    continuation_query: str = "%24skipToken=synthetic",
) -> None:
    pages = _arm_role_assignment_pages(
        evidence,
        collection_kind=collection_kind,
    )
    first_page = pages[0]
    assert isinstance(first_page, dict)
    first_values = first_page["value"]
    assert isinstance(first_values, list)
    continuation_url = f"{first_page['requestUrl']}&{continuation_query}"
    first_page["value"] = []
    first_page["nextLink"] = continuation_url
    pages.append(
        {
            "requestUrl": continuation_url,
            "statusCode": 200,
            "value": first_values,
            "nextLink": None,
        }
    )


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


def test_no_change_requires_complete_consistent_zero_delta_evidence() -> None:
    no_change = _change(_STORAGE_ID, "NoChange")
    assert isinstance(no_change["before"], dict)
    assert isinstance(no_change["after"], dict)
    no_change["before"]["properties"] = {"allowSharedKeyAccess": False}
    no_change["after"]["properties"] = {"allowSharedKeyAccess": False}
    no_change["delta"] = [
        {
            "path": "properties.allowSharedKeyAccess",
            "propertyChangeType": "NoEffect",
            "before": False,
            "after": False,
        }
    ]

    assert evaluate_what_if(_what_if(no_change)) == ()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda change: change.pop("before"),
            "requires complete before and after",
        ),
        (
            lambda change: (
                change["before"]["properties"].update({"allowSharedKeyAccess": False}),
                change["after"]["properties"].update({"allowSharedKeyAccess": True}),
            ),
            "snapshots conflict",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "<resource>",
                            "propertyChangeType": "Delete",
                        }
                    ]
                }
            ),
            "non-NoEffect property delta",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "<resource>.",
                            "propertyChangeType": "Remove",
                        }
                    ]
                }
            ),
            "non-NoEffect property delta",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "properties",
                            "children": [
                                {
                                    "path": "allowSharedKeyAccess",
                                    "propertyChangeType": "Remove",
                                }
                            ],
                        }
                    ]
                }
            ),
            "non-NoEffect property delta",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "properties",
                            "children": [
                                {
                                    "path": "allowSharedKeyAccess",
                                    "propertyChangeType": "Delete",
                                }
                            ],
                        }
                    ]
                }
            ),
            "non-NoEffect property delta",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "properties.publicNetworkAccess",
                            "propertyChangeType": "NoEffect",
                            "before": "Disabled",
                            "after": "Enabled",
                        }
                    ]
                }
            ),
            "NoEffect before and after values conflict",
        ),
        (
            lambda change: change.update(
                {
                    "delta": [
                        {
                            "path": "properties..allowSharedKeyAccess",
                            "propertyChangeType": "NoEffect",
                        }
                    ]
                }
            ),
            "property path",
        ),
    ],
)
def test_no_change_rejects_hidden_or_conflicting_effects(
    mutation,
    message: str,
) -> None:
    change = _change(_STORAGE_ID, "NoChange")
    mutation(change)

    with pytest.raises(PreflightInputError, match=message):
        evaluate_what_if(_what_if(change))


def test_no_change_reconciles_snapshot_identity_and_delta_values() -> None:
    incomplete = _change(_STORAGE_ID, "NoChange")
    incomplete["before"] = {}
    incomplete["after"] = {}
    with pytest.raises(PreflightInputError, match="snapshot id"):
        evaluate_what_if(_what_if(incomplete))

    wrong_id = _change(_STORAGE_ID, "NoChange")
    assert isinstance(wrong_id["before"], dict)
    assert isinstance(wrong_id["after"], dict)
    wrong_id["before"]["id"] = _KEY_VAULT_ID
    wrong_id["after"]["id"] = _KEY_VAULT_ID
    with pytest.raises(PreflightInputError, match="does not match resourceId"):
        evaluate_what_if(_what_if(wrong_id))

    contradictory = _change(_STORAGE_ID, "NoChange")
    assert isinstance(contradictory["before"], dict)
    assert isinstance(contradictory["after"], dict)
    contradictory["before"]["properties"] = {"allowSharedKeyAccess": False}
    contradictory["after"]["properties"] = {"allowSharedKeyAccess": False}
    contradictory["delta"] = [
        {
            "path": "properties.allowSharedKeyAccess",
            "propertyChangeType": "NoEffect",
            "before": True,
            "after": True,
        }
    ]
    with pytest.raises(
        PreflightInputError,
        match="does not reconcile with resource snapshots",
    ):
        evaluate_what_if(_what_if(contradictory))

    nested_type_change = _change(_STORAGE_ID, "NoChange")
    assert isinstance(nested_type_change["before"], dict)
    assert isinstance(nested_type_change["after"], dict)
    nested_type_change["before"]["properties"] = {"allowSharedKeyAccess": False}
    nested_type_change["after"]["properties"] = {"allowSharedKeyAccess": 0}
    with pytest.raises(PreflightInputError, match="snapshots conflict"):
        evaluate_what_if(_what_if(nested_type_change))

    object_delta = _change(_STORAGE_ID, "NoChange")
    object_delta["delta"] = [
        {
            "path": "properties",
            "propertyChangeType": "NoEffect",
            "before": {"enabled": False},
            "after": {"enabled": 0},
        }
    ]
    with pytest.raises(
        PreflightInputError,
        match="NoEffect before and after values conflict",
    ):
        evaluate_what_if(_what_if(object_delta))


def test_no_change_single_pass_retains_array_and_root_validation() -> None:
    uninspectable = _change(_STORAGE_ID, "NoChange")
    uninspectable["delta"] = [
        {
            "path": "properties",
            "propertyChangeType": "Array",
        }
    ]
    with pytest.raises(PreflightInputError, match="lacks inspectable after"):
        evaluate_what_if(_what_if(uninspectable))

    missing_root_after = _change(_STORAGE_ID, "NoChange")
    missing_root_after["delta"] = [
        {
            "path": "<resource>",
            "propertyChangeType": "Array",
            "children": [
                {
                    "path": "properties",
                    "before": {},
                    "after": {},
                    "propertyChangeType": "NoEffect",
                }
            ],
        }
    ]
    with pytest.raises(
        PreflightInputError,
        match="resource-root delta after value must be an object",
    ):
        evaluate_what_if(_what_if(missing_root_after))


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


def test_attested_what_if_rejects_duplicate_canonical_resource_rows_before_evaluation(
    monkeypatch,
) -> None:
    alias_resource_id = _STORAGE_ID.upper() + "/"
    modify = _change(
        _STORAGE_ID,
        "Modify",
        path="properties.allowSharedKeyAccess",
        after=False,
    )
    no_change = _change(alias_resource_id, "NoChange")

    def unexpected_property_evaluation(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("duplicate resources must fail before property evaluation")

    monkeypatch.setattr(
        wc029_preflight_module,
        "_unsafe_property_violations",
        unexpected_property_evaluation,
    )

    with pytest.raises(
        PreflightInputError,
        match="duplicate canonical resourceId",
    ):
        _evaluate_attested_what_if(
            _what_if(modify, no_change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_what_if_rejects_duplicate_resource_across_changes_and_potential_changes() -> None:
    modify = _change(
        _KEY_VAULT_ID,
        "Modify",
        path="properties.enabledForDeployment",
        after=False,
    )
    document = _what_if(modify)
    properties = document["properties"]
    assert isinstance(properties, dict)
    properties["potentialChanges"] = [
        {
            "resourceId": _KEY_VAULT_ID.upper() + "/",
            "changeType": "Delete",
        }
    ]

    with pytest.raises(
        PreflightInputError,
        match="duplicate canonical resourceId",
    ):
        _evaluate_attested_what_if(
            document,
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


def test_attested_key_vault_rejects_contradictory_modify_and_nochange_rows() -> None:
    modify = _change(
        _KEY_VAULT_ID,
        "Modify",
        path="properties.enabledForDeployment",
        after=False,
    )
    no_change = _change(_KEY_VAULT_ID.upper() + "/", "NoChange")

    with pytest.raises(
        PreflightInputError,
        match="duplicate canonical resourceId",
    ):
        _evaluate_attested_what_if(
            _what_if(modify, no_change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


def test_attested_what_if_rejects_percent_encoded_resource_alias() -> None:
    encoded_alias = _STORAGE_ID.replace(
        "/resourceGroups/",
        "%2FresourceGroups%2F",
    )

    with pytest.raises(
        PreflightInputError,
        match="canonical ARM scope",
    ):
        _evaluate_attested_what_if(
            _what_if(_change(encoded_alias, "NoChange")),
        )


def test_post_attestation_duplicate_resource_injection_breaks_digest_binding() -> None:
    document = _what_if(
        _change(
            _STORAGE_ID,
            "Modify",
            path="properties.allowSharedKeyAccess",
            after=False,
        )
    )
    artifact = _attested_what_if(
        document,
        allowed_change_ids=frozenset({_STORAGE_ID}),
    )
    attested_document = artifact["whatIf"]
    assert isinstance(attested_document, dict)
    properties = attested_document["properties"]
    assert isinstance(properties, dict)
    changes = properties["changes"]
    assert isinstance(changes, list)
    changes.append(_change(_STORAGE_ID.upper() + "/", "NoChange"))

    with pytest.raises(
        PreflightInputError,
        match="whatIfDigest does not match",
    ):
        evaluate_what_if(
            artifact,
            allowed_change_ids=frozenset({_STORAGE_ID}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


@pytest.mark.parametrize(
    ("resource_id", "path", "after"),
    [
        (
            _STORAGE_ID,
            "properties.allowSharedKeyAccess.value",
            False,
        ),
        (
            _KEY_VAULT_ID,
            "properties.publicNetworkAccess.value",
            "Disabled",
        ),
        (
            _CONTAINER_APP_ID,
            "properties.configuration.ingress.external.value",
            False,
        ),
        (
            _KEY_VAULT_ID,
            "properties[0].enableRbacAuthorization",
            False,
        ),
        (
            _KEY_VAULT_ID,
            "properties.networkAcls[0].defaultAction",
            "Deny",
        ),
    ],
)
def test_attested_what_if_rejects_protected_path_schema_divergence(
    resource_id: str,
    path: str,
    after: object,
) -> None:
    with pytest.raises(
        PreflightInputError,
        match="delta path diverges from protected property schema",
    ):
        _evaluate_attested_what_if(
            _what_if(
                _change(
                    resource_id,
                    "Modify",
                    path=path,
                    after=after,
                )
            ),
            allowed_change_ids=frozenset({resource_id}),
        )


@pytest.mark.parametrize(
    ("resource_id", "path", "after", "expected_kind"),
    [
        (
            _STORAGE_ID,
            "properties",
            [],
            "object",
        ),
        (
            _CONTAINER_APP_ID,
            "properties.configuration.ingress",
            [],
            "object",
        ),
        (
            _KEY_VAULT_ID,
            "properties.accessPolicies",
            {},
            "array",
        ),
    ],
)
def test_attested_what_if_rejects_invalid_protected_ancestor_values(
    resource_id: str,
    path: str,
    after: object,
    expected_kind: str,
) -> None:
    with pytest.raises(
        PreflightInputError,
        match=rf"must remain {expected_kind}-valued",
    ):
        _evaluate_attested_what_if(
            _what_if(
                _change(
                    resource_id,
                    "Modify",
                    path=path,
                    after=after,
                )
            ),
            allowed_change_ids=frozenset({resource_id}),
        )


@pytest.mark.parametrize(
    ("resource_id", "alias_key", "alias_value"),
    [
        (
            _STORAGE_ID,
            "allowSharedKeyAccess.value",
            False,
        ),
        (
            _STORAGE_ID,
            "..allowSharedKeyAccess",
            True,
        ),
        (
            _KEY_VAULT_ID,
            "accessPolicies[00]",
            [],
        ),
        (
            _CONTAINER_APP_ID,
            "configuration.ingress.external",
            False,
        ),
    ],
)
def test_attested_no_change_rejects_malformed_protected_snapshot_alias(
    resource_id: str,
    alias_key: str,
    alias_value: object,
) -> None:
    change = _change(resource_id, "NoChange")
    for snapshot_name in ("before", "after"):
        snapshot = change[snapshot_name]
        assert isinstance(snapshot, dict)
        properties = snapshot["properties"]
        assert isinstance(properties, dict)
        properties[alias_key] = copy.deepcopy(alias_value)

    with pytest.raises(
        PreflightInputError,
        match="malformed property alias",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
        )


@pytest.mark.parametrize(
    "alias_key",
    [
        "properties.allowSharedKeyAccess",
        "<resource>..properties.allowSharedKeyAccess",
    ],
)
def test_attested_no_change_rejects_root_level_protected_snapshot_alias(
    alias_key: str,
) -> None:
    change = _change(_STORAGE_ID, "NoChange")
    for snapshot_name in ("before", "after"):
        snapshot = change[snapshot_name]
        assert isinstance(snapshot, dict)
        snapshot[alias_key] = False

    with pytest.raises(
        PreflightInputError,
        match="malformed property alias",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
        )


def test_attested_modify_rejects_conflicting_protected_full_snapshot_alias() -> None:
    safe_properties = {
        "allowSharedKeyAccess": False,
        "allowBlobPublicAccess": False,
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
    }
    before = _resource_snapshot(
        _STORAGE_ID,
        properties=copy.deepcopy(safe_properties),
        tags={"release": "before"},
    )
    after = _resource_snapshot(
        _STORAGE_ID,
        properties={
            **copy.deepcopy(safe_properties),
            "publicNetworkAccess.value": "Enabled",
        },
        tags={"release": "after"},
    )
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": "tags.release",
                "propertyChangeType": "Modify",
                "before": "before",
                "after": "after",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="malformed property alias",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_modify_rejects_malformed_protected_alias_in_ancestor_value() -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": "properties",
                "propertyChangeType": "Modify",
                "after": {
                    "allowSharedKeyAccess": False,
                    "allowSharedKeyAccess.value": True,
                },
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="malformed property alias",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_dynamic_object_array_divergence(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.networkAcls.ipRules.name",
            "propertyChangeType": "Modify",
            "after": "synthetic-rule",
        },
        {
            "path": "properties.networkAcls.ipRules[0]",
            "propertyChangeType": "Modify",
            "after": "192.0.2.10",
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="container representations conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize("snapshot_stage", ["before", "after"])
def test_attested_what_if_rejects_partial_snapshot_dynamic_object_array_divergence(
    snapshot_stage: str,
) -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        snapshot_stage: {
            "properties": {
                "networkAcls": {
                    "ipRules": {},
                }
            }
        },
        "delta": [
            {
                "path": "properties.networkAcls.ipRules[0]",
                "propertyChangeType": "Modify",
                "before": "192.0.2.10",
                "after": "192.0.2.11",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="container representations conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize("snapshot_stage", ["before", "after"])
def test_attested_what_if_rejects_partial_snapshot_dynamic_value_conflict(
    snapshot_stage: str,
) -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        snapshot_stage: {
            "properties": {
                "networkAcls": {
                    "ipRules": [
                        {
                            "value": "192.0.2.10",
                        }
                    ],
                },
            },
        },
        "delta": [
            {
                "path": "properties.networkAcls.ipRules[0].value",
                "propertyChangeType": "Modify",
                "before": "192.0.2.99",
                "after": "192.0.2.11",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="representations conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_what_if_does_not_treat_partial_snapshot_omission_as_absence() -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "before": {
            "properties": {
                "allowSharedKeyAccess": False,
                "allowBlobPublicAccess": False,
                "publicNetworkAccess": "Disabled",
                "networkAcls": {
                    "defaultAction": "Deny",
                },
            }
        },
        "delta": [
            {
                "path": "properties.networkAcls.ipRules[0]",
                "propertyChangeType": "Create",
                "after": {
                    "value": "192.0.2.10",
                },
            }
        ],
    }

    assert {
        violation.code
        for violation in _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )
    } == {"public-data-plane-access"}


def test_attested_what_if_rejects_mixed_exact_and_array_protected_paths() -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": "properties.allowSharedKeyAccess",
                "propertyChangeType": "Modify",
                "after": False,
            },
            {
                "path": "properties[0].allowSharedKeyAccess",
                "propertyChangeType": "Modify",
                "after": False,
            },
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="delta path diverges from protected property schema",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_what_if_rejects_conflicting_protected_delta_representations() -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": "properties",
                "propertyChangeType": "Modify",
                "after": {"allowSharedKeyAccess": False},
            },
            {
                "path": "properties.allowSharedKeyAccess",
                "propertyChangeType": "Modify",
                "after": True,
            },
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_what_if_rejects_delta_conflicting_with_full_snapshot() -> None:
    safe_properties = {
        "allowSharedKeyAccess": False,
        "allowBlobPublicAccess": False,
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
    }
    before = _resource_snapshot(
        _STORAGE_ID,
        properties=copy.deepcopy(safe_properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": "properties.allowSharedKeyAccess",
                "propertyChangeType": "Modify",
                "after": True,
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


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
            _CONTAINER_APP_ID,
            "properties.configuration.ingress.external",
            "false",
            "Container Apps ingress.external must be boolean",
        ),
        (
            _KEY_VAULT_ID,
            "properties.publicNetworkAccess",
            False,
            "must remain string-valued",
        ),
    ],
)
def test_attested_what_if_rejects_equal_malformed_protected_delta_values(
    resource_id: str,
    path: str,
    value: object,
    message: str,
) -> None:
    change = {
        "resourceId": resource_id,
        "changeType": "Modify",
        "delta": [
            {
                "path": path,
                "propertyChangeType": "Modify",
                "before": value,
                "after": value,
            },
            {
                "path": "tags.release",
                "propertyChangeType": "Modify",
                "after": "wc029",
            },
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match=message,
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({resource_id}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_rejects_malformed_before_with_exact_false_after(
    field_name: str,
) -> None:
    change = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": f"properties.{field_name}",
                "propertyChangeType": "Modify",
                "before": "not-a-boolean",
                "after": False,
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="must remain boolean-valued",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_create_rejects_explicit_existing_before(
    field_name: str,
) -> None:
    safe_properties = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
    }
    change = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": "Modify",
        "before": _resource_snapshot(
            _KEY_VAULT_ID,
            properties={
                **safe_properties,
                field_name: True,
            },
        ),
        "after": _resource_snapshot(
            _KEY_VAULT_ID,
            properties={
                **safe_properties,
                field_name: False,
            },
        ),
        "delta": [
            {
                "path": f"properties.{field_name}",
                "propertyChangeType": "Create",
                "before": True,
                "after": False,
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="Create delta cannot supply before at protected path",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_missing_after_still_validates_before_type(
    field_name: str,
) -> None:
    safe_properties = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: False,
    }
    before = _resource_snapshot(
        _KEY_VAULT_ID,
        properties=copy.deepcopy(safe_properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    change = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": f"properties.{field_name}",
                "propertyChangeType": "Modify",
                "before": "not-a-boolean",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="must remain boolean-valued",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


def test_attested_what_if_rejects_protected_descendant_missing_from_full_snapshot() -> None:
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties={},
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": "properties.configuration.foo",
                "propertyChangeType": "Create",
                "after": "synthetic",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_attested_what_if_rejects_value_less_delete_missing_from_before_snapshot() -> None:
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties={},
        tags={"release": "before"},
    )
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "delta": [
            {
                "path": "properties.configuration.foo",
                "propertyChangeType": "Delete",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_attested_what_if_rejects_value_less_create_present_in_before_snapshot() -> None:
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties={
            "configuration": {
                "foo": "existing",
            }
        },
        tags={"release": "before"},
    )
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "delta": [
            {
                "path": "properties.configuration.foo",
                "propertyChangeType": "Create",
                "after": "replacement",
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_conflicting_implicit_create_presence(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.allowSharedKeyAccess",
            "propertyChangeType": "Modify",
            "before": True,
            "after": False,
        },
        {
            "path": "properties.allowSharedKeyAccess",
            "propertyChangeType": "Create",
            "after": False,
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="protected path presence representations conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_parent_child_presence_conflict(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.networkAcls",
            "propertyChangeType": "Modify",
            "before": {},
            "after": {},
        },
        {
            "path": "properties.networkAcls.defaultAction",
            "propertyChangeType": "Modify",
            "before": "Allow",
            "after": "Deny",
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_deleted_parent_with_created_descendant(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.configuration.foo",
            "propertyChangeType": "Delete",
            "before": {"bar": "old"},
        },
        {
            "path": "properties.configuration.foo.bar",
            "propertyChangeType": "Create",
            "after": "new",
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_created_parent_with_existing_descendant(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.configuration.foo",
            "propertyChangeType": "Create",
            "after": {"bar": "new"},
        },
        {
            "path": "properties.configuration.foo.bar",
            "propertyChangeType": "Modify",
            "before": "old",
            "after": "new",
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


@pytest.mark.parametrize("reverse_order", [False, True])
def test_attested_what_if_rejects_conflicting_parent_child_values(
    reverse_order: bool,
) -> None:
    deltas = [
        {
            "path": "properties.configuration.foo",
            "propertyChangeType": "Modify",
            "before": {"bar": "before"},
            "after": {"bar": "parent"},
        },
        {
            "path": "properties.configuration.foo.bar",
            "propertyChangeType": "Modify",
            "before": "before",
            "after": "child",
        },
    ]
    if reverse_order:
        deltas.reverse()
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "delta": deltas,
    }

    with pytest.raises(
        PreflightInputError,
        match="protected path representations conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_attested_protected_snapshot_reconciliation_is_indexed_and_budgeted(
    monkeypatch,
) -> None:
    leaf_count = 2000
    delta_count = 1000
    properties: dict[str, object] = {
        "configuration": {
            "ingress": {
                "external": False,
            }
        },
        **{f"leaf{index:04d}": f"value-{index:04d}" for index in range(leaf_count)},
    }
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties=copy.deepcopy(properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": f"properties.leaf{index:04d}",
                "propertyChangeType": "NoEffect",
                "before": f"value-{index:04d}",
                "after": f"value-{index:04d}",
            }
            for index in range(delta_count)
        ],
    }
    original_resolve = wc029_preflight_module._ProtectedPropertyEvidence._resolve_value
    raw_snapshot_resolutions = 0
    original_charge_lookup = _PropertyPathBudget.charge_lookup
    charged_lookup_work = 0

    def counted_resolve(
        evidence: object,
        value: object,
        tokens: object,
    ) -> tuple[bool, object]:
        nonlocal raw_snapshot_resolutions
        raw_snapshot_resolutions += 1
        return original_resolve(evidence, value, tokens)

    def counted_charge_lookup(
        budget: _PropertyPathBudget,
        work: int,
    ) -> None:
        nonlocal charged_lookup_work
        charged_lookup_work += work
        original_charge_lookup(budget, work)

    monkeypatch.setattr(
        wc029_preflight_module._ProtectedPropertyEvidence,
        "_resolve_value",
        counted_resolve,
    )
    monkeypatch.setattr(
        _PropertyPathBudget,
        "charge_lookup",
        counted_charge_lookup,
    )

    assert (
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )
        == ()
    )
    schema_entry_count = len(
        wc029_preflight_module._PROTECTED_PROPERTY_SCHEMAS[
            wc029_preflight_module._CONTAINER_APP_TYPE
        ]
    )
    assert raw_snapshot_resolutions <= 2 * schema_entry_count
    assert delta_count < charged_lookup_work < wc029_preflight_module.MAX_PROPERTY_LOOKUP_WORK


def test_attested_wide_protected_delta_observation_consumes_lookup_budget() -> None:
    inert_key_count = 63000
    properties: dict[str, object] = {
        **{f"leaf{index:05d}": f"value-{index:05d}" for index in range(inert_key_count)},
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        "enabledForDeployment": False,
    }
    change = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": "properties",
                "propertyChangeType": "Modify",
                "after": properties,
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="property snapshot lookup exceeds its aggregate work budget",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    ("resource_id", "properties", "message"),
    [
        (
            _STORAGE_ID,
            {
                "allowSharedKeyAccess": False,
                "allowBlobPublicAccess": False,
                "publicNetworkAccess": " Disabled ",
                "networkAcls": {"defaultAction": "Deny"},
            },
            "publicNetworkAccess must be an exact trimmed ASCII token",
        ),
        (
            _STORAGE_ID,
            {
                "allowSharedKeyAccess": False,
                "allowBlobPublicAccess": False,
                "publicNetworkAccess": "Disabled",
                "networkAcls": {"defaultAction": " Deny "},
            },
            "properties.networkacls.defaultaction must be an exact trimmed ASCII token",
        ),
        (
            _STORAGE_CONTAINER_ID,
            {
                "publicAccess": " None ",
            },
            "publicAccess must be an exact trimmed ASCII token",
        ),
    ],
)
def test_attested_no_change_rejects_noncanonical_protected_string(
    resource_id: str,
    properties: dict[str, object],
    message: str,
) -> None:
    change = _change(resource_id, "NoChange")
    assert isinstance(change["before"], dict)
    assert isinstance(change["after"], dict)
    change["before"]["properties"] = copy.deepcopy(properties)
    change["after"]["properties"] = copy.deepcopy(properties)

    with pytest.raises(
        PreflightInputError,
        match=message,
    ):
        _evaluate_attested_what_if(
            _what_if(change),
        )


def test_attested_modify_rejects_equal_noncanonical_protected_string() -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Modify",
        "delta": [
            {
                "path": "properties.publicNetworkAccess",
                "propertyChangeType": "Modify",
                "before": " Disabled ",
                "after": " Disabled ",
            },
            {
                "path": "tags.release",
                "propertyChangeType": "Modify",
                "after": "wc029",
            },
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="publicNetworkAccess must be an exact trimmed ASCII token",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_attested_what_if_rejects_protected_descendant_conflicting_with_full_snapshot() -> None:
    properties = {
        "configuration": {
            "ingress": {
                "external": False,
                "targetPort": 443,
            }
        }
    }
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties=copy.deepcopy(properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
        "delta": [
            {
                "path": "properties.configuration.ingress.targetPort",
                "propertyChangeType": "Modify",
                "after": 80,
            }
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


@pytest.mark.parametrize(
    ("resource_id", "properties", "message"),
    [
        (
            _STORAGE_ID,
            {"allowSharedKeyAccess": {"value": False}},
            "allowSharedKeyAccess must be boolean",
        ),
        (
            _CONTAINER_APP_ID,
            {
                "configuration": {
                    "ingress": {
                        "external": {"value": False},
                    }
                }
            },
            "Container Apps ingress.external must be boolean",
        ),
    ],
)
def test_attested_no_change_rejects_invalid_protected_snapshot_schema(
    resource_id: str,
    properties: dict[str, object],
    message: str,
) -> None:
    change = _change(resource_id, "NoChange")
    assert isinstance(change["before"], dict)
    assert isinstance(change["after"], dict)
    change["before"]["properties"] = copy.deepcopy(properties)
    change["after"]["properties"] = copy.deepcopy(properties)

    with pytest.raises(
        PreflightInputError,
        match=message,
    ):
        _evaluate_attested_what_if(
            _what_if(change),
        )


@pytest.mark.parametrize(
    ("resource_id", "change_type"),
    [
        (
            f"{_RG_SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
            "66666666-6666-6666-6666-666666666666",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Authorization/roleAssignments/"
            "66666666-6666-6666-6666-666666666666",
            "Modify",
        ),
        (
            f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/"
            "77777777-7777-7777-7777-777777777777",
            "Create",
        ),
        (
            f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/"
            "77777777-7777-7777-7777-777777777777",
            "Modify",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Authorization/"
            "roleAssignmentScheduleRequests/"
            "88888888-8888-8888-8888-888888888888",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Authorization/"
            "roleEligibilityScheduleRequests/"
            "99999999-9999-9999-9999-999999999999",
            "Modify",
        ),
        (
            f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.ManagedServices/"
            "registrationAssignments/"
            "12121212-1212-1212-1212-121212121212",
            "Create",
        ),
        (
            f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.ManagedServices/"
            "registrationDefinitions/"
            "13131313-1313-1313-1313-131313131313",
            "Modify",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Resources/deploymentScripts/synthetic-script",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Resources/deploymentScripts/synthetic-script",
            "Modify",
        ),
        (
            f"{_KEY_VAULT_ID}/accessPolicies/add",
            "Create",
        ),
        (
            f"{_KEY_VAULT_ID}/accessPolicies/replace",
            "Modify",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
            "synthetic-identity/federatedIdentityCredentials/synthetic-federation",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
            "synthetic-identity/federatedIdentityCredentials/synthetic-federation",
            "Modify",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Graph/applications/"
            "14141414-1414-1414-1414-141414141414/federatedIdentityCredentials/"
            "synthetic-federation",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Graph/oauth2PermissionGrants/"
            "15151515-1515-1515-1515-151515151515",
            "Modify",
        ),
        (
            f"{_RG_SCOPE}/providers/Microsoft.Graph/servicePrincipals/"
            "16161616-1616-1616-1616-161616161616/appRoleAssignedTo/"
            "17171717-1717-1717-1717-171717171717",
            "Create",
        ),
        (
            f"{_RG_SCOPE}/providers/Synthetic.Identity/workloadIdentities/"
            "synthetic/federatedIdentityCredentials/synthetic-federation",
            "Modify",
        ),
    ],
)
def test_what_if_fails_closed_on_authorization_mutations(
    resource_id: str,
    change_type: str,
) -> None:
    change = _change(
        resource_id,
        change_type,
        path="tags.release",
        after="wc029",
    )

    violations = evaluate_what_if(
        _what_if(change),
        allowed_change_ids=frozenset({resource_id}),
    )

    assert {violation.code for violation in violations} == {"authorization-change-unsupported"}


@pytest.mark.parametrize(
    ("change_type", "path", "after"),
    [
        ("Create", "properties.denySettings.mode", "denyWriteAndDelete"),
        ("Create", "properties.actionOnUnmanage.resources", "delete"),
        ("Modify", "properties.denySettings.excludedPrincipals", []),
        ("Modify", "properties.actionOnUnmanage.resourceGroups", "delete"),
        ("Delete", "properties.denySettings.mode", "none"),
        ("Delete", "properties.actionOnUnmanage.resources", "detach"),
    ],
)
def test_attested_what_if_unconditionally_blocks_deployment_stacks(
    change_type: str,
    path: str,
    after: object,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            _change(
                _DEPLOYMENT_STACK_ID,
                change_type,
                path=path,
                after=after,
            )
        ),
        allowed_change_ids=frozenset({_DEPLOYMENT_STACK_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}
    assert ("delete" in {violation.code for violation in violations}) == (change_type == "Delete")


@pytest.mark.parametrize(
    ("path", "after"),
    [
        (
            "properties.sshAuthorizedKeys[0].key",
            "ssh-ed25519 SYNTHETIC-KEY",
        ),
        ("properties.hasSshPassword", True),
        ("properties.permissionScopes[0].permissions", "rwlc"),
    ],
)
@pytest.mark.parametrize(
    "change_type",
    ["Create", "Modify", "Delete"],
)
def test_attested_what_if_unconditionally_blocks_storage_local_users(
    change_type: str,
    path: str,
    after: object,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            _change(
                _STORAGE_LOCAL_USER_ID,
                change_type,
                path=path,
                after=after,
            )
        ),
        allowed_change_ids=frozenset({_STORAGE_LOCAL_USER_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}
    assert ("delete" in {violation.code for violation in violations}) == (change_type == "Delete")


@pytest.mark.parametrize(
    ("change_type", "path", "after"),
    [
        (
            "Modify",
            "properties.accessPolicies",
            [],
        ),
        (
            "Modify",
            "properties.accessPolicies[0].objectId",
            "11111111-1111-1111-1111-111111111111",
        ),
        ("Modify", "properties.enableRbacAuthorization", True),
        (
            "Modify",
            "properties",
            {
                "accessPolicies": [],
                "enableRbacAuthorization": True,
            },
        ),
    ],
)
def test_what_if_fails_closed_on_key_vault_authorization_property_mutations(
    change_type: str,
    path: str,
    after: object,
) -> None:
    violations = evaluate_what_if(
        _what_if(
            _change(
                _KEY_VAULT_ID,
                change_type,
                path=path,
                after=after,
            )
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("accessPolicies", []),
        ("enableRbacAuthorization", True),
    ],
)
def test_what_if_fails_closed_on_key_vault_create_authorization_properties(
    field_name: str,
    field_value: object,
) -> None:
    properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: field_value,
    }

    violations = evaluate_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Create",
                "after": {"properties": properties},
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert {violation.code for violation in violations} == {"authorization-change-unsupported"}


def test_what_if_fails_closed_on_partial_key_vault_authorization_snapshot() -> None:
    change = _change(
        _KEY_VAULT_ID,
        "Modify",
        path="tags.release",
        after="wc029",
    )
    change["after"] = {
        "properties": {
            "enableRbacAuthorization": True,
        }
    }

    violations = evaluate_what_if(
        _what_if(change),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize(
    "change_type",
    ["Create", "Modify"],
)
def test_attested_key_vault_deployment_access_enablement_delta_fails(
    field_name: str,
    change_type: str,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            _change(
                _KEY_VAULT_ID,
                change_type,
                path=f"properties.{field_name}",
                after=True,
            )
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize(
    "change_type",
    ["Create", "Modify"],
)
def test_attested_key_vault_deployment_access_enablement_snapshot_fails(
    field_name: str,
    change_type: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: False,
    }
    before = _resource_snapshot(
        _KEY_VAULT_ID,
        properties=copy.deepcopy(safe_properties),
    )
    after = _resource_snapshot(
        _KEY_VAULT_ID,
        properties={
            **safe_properties,
            field_name: True,
        },
    )
    change: dict[str, object] = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": change_type,
        "after": after,
    }
    if change_type == "Modify":
        change["before"] = before

    violations = _evaluate_attested_what_if(
        _what_if(change),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert {violation.code for violation in violations} == {"authorization-change-unsupported"}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize(
    "change_type",
    ["Create", "Modify"],
)
def test_attested_key_vault_deployment_access_disablement_is_allowed(
    field_name: str,
    change_type: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: False,
    }
    after = _resource_snapshot(
        _KEY_VAULT_ID,
        properties=copy.deepcopy(safe_properties),
    )
    change: dict[str, object] = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": change_type,
        "after": after,
    }
    if change_type == "Modify":
        change["before"] = _resource_snapshot(
            _KEY_VAULT_ID,
            properties={
                **safe_properties,
                field_name: True,
            },
        )

    assert (
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        == ()
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_non_boolean_is_unsupported(
    field_name: str,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            _change(
                _KEY_VAULT_ID,
                "Modify",
                path=f"properties.{field_name}",
                after="true",
            )
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_exact_delta_disablement_is_allowed(
    field_name: str,
) -> None:
    assert (
        _evaluate_attested_what_if(
            _what_if(
                _change(
                    _KEY_VAULT_ID,
                    "Modify",
                    path=f"properties.{field_name}",
                    after=False,
                )
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        == ()
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize(
    "after",
    [
        0,
        None,
    ],
)
def test_attested_key_vault_deployment_access_other_non_boolean_values_are_unsupported(
    field_name: str,
    after: object,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            _change(
                _KEY_VAULT_ID,
                "Modify",
                path=f"properties.{field_name}",
                after=after,
            )
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize(
    "property_change_type",
    [
        "Delete",
        "Remove",
        "Modify",
    ],
)
def test_attested_key_vault_deployment_access_requires_exact_final_false(
    field_name: str,
    property_change_type: str,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Modify",
                "delta": [
                    {
                        "path": f"properties.{field_name}",
                        "propertyChangeType": property_change_type,
                    }
                ],
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_rejects_child_only_evidence(
    field_name: str,
) -> None:
    with pytest.raises(
        PreflightInputError,
        match="delta path diverges from protected property schema",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "children": [
                                {
                                    "path": "value",
                                    "propertyChangeType": "Modify",
                                    "after": False,
                                }
                            ],
                        }
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_rejects_incomplete_snapshot(
    field_name: str,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Modify",
                "after": _resource_snapshot(
                    _KEY_VAULT_ID,
                    properties={
                        "publicNetworkAccess": "Disabled",
                        "networkAcls": {"defaultAction": "Deny"},
                        field_name: False,
                    },
                ),
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_rejects_missing_final_snapshot_value(
    field_name: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
    }
    violations = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Modify",
                "before": _resource_snapshot(
                    _KEY_VAULT_ID,
                    properties={
                        **safe_properties,
                        field_name: True,
                    },
                ),
                "after": _resource_snapshot(
                    _KEY_VAULT_ID,
                    properties=copy.deepcopy(safe_properties),
                ),
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_rejects_conflicting_snapshot_and_delta(
    field_name: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
    }
    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "before": _resource_snapshot(
                        _KEY_VAULT_ID,
                        properties={
                            **safe_properties,
                            field_name: True,
                        },
                    ),
                    "after": _resource_snapshot(
                        _KEY_VAULT_ID,
                        properties={
                            **safe_properties,
                            field_name: False,
                        },
                    ),
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "after": True,
                        }
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_deployment_access_rejects_conflicting_delta_observations(
    field_name: str,
) -> None:
    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "before": True,
                            "after": True,
                        },
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "after": False,
                        },
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize("include_final_snapshot", [False, True])
def test_attested_key_vault_create_rejects_true_observation(
    field_name: str,
    include_final_snapshot: bool,
) -> None:
    change: dict[str, object] = {
        "resourceId": _KEY_VAULT_ID,
        "changeType": "Create",
        "delta": [
            {
                "path": f"properties.{field_name}",
                "propertyChangeType": "Modify",
                "before": True,
                "after": True,
            },
            {
                "path": "properties.publicNetworkAccess",
                "propertyChangeType": "Modify",
                "after": "Disabled",
            },
            {
                "path": "properties.networkAcls.defaultAction",
                "propertyChangeType": "Modify",
                "after": "Deny",
            },
        ],
    }
    if include_final_snapshot:
        change["after"] = _resource_snapshot(
            _KEY_VAULT_ID,
            properties={
                "publicNetworkAccess": "Disabled",
                "networkAcls": {"defaultAction": "Deny"},
                field_name: False,
            },
        )

    if include_final_snapshot:
        with pytest.raises(
            PreflightInputError,
            match="conflict",
        ):
            _evaluate_attested_what_if(
                _what_if(change),
                allowed_change_ids=frozenset({_KEY_VAULT_ID}),
            )
    else:
        violations = _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_modify_rejects_true_delta_observation(
    field_name: str,
) -> None:
    violations = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Modify",
                "delta": [
                    {
                        "path": f"properties.{field_name}",
                        "propertyChangeType": "Modify",
                        "before": True,
                        "after": True,
                    },
                    {
                        "path": "tags.release",
                        "propertyChangeType": "Modify",
                        "after": "wc029",
                    },
                ],
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_modify_rejects_true_noeffect_observation(
    field_name: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: True,
    }
    before = _resource_snapshot(
        _KEY_VAULT_ID,
        properties=copy.deepcopy(safe_properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}
    violations = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Modify",
                "before": before,
                "after": after,
                "delta": [
                    {
                        "path": f"properties.{field_name}",
                        "propertyChangeType": "NoEffect",
                        "before": True,
                        "after": True,
                    }
                ],
            }
        ),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )

    assert "authorization-change-unsupported" in {violation.code for violation in violations}


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
@pytest.mark.parametrize("property_change_type", ["Modify", "NoEffect"])
def test_attested_key_vault_modify_allows_false_noop_observation(
    field_name: str,
    property_change_type: str,
) -> None:
    safe_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        field_name: False,
    }
    before = _resource_snapshot(
        _KEY_VAULT_ID,
        properties=copy.deepcopy(safe_properties),
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}

    assert (
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "before": before,
                    "after": after,
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": property_change_type,
                            "before": False,
                            "after": False,
                        }
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        == ()
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_exact_false_does_not_mask_ambiguous_ancestor_observation(
    field_name: str,
) -> None:
    other_deployment_access = {
        other_field: False
        for other_field in (
            "enabledForDeployment",
            "enabledForDiskEncryption",
            "enabledForTemplateDeployment",
        )
        if other_field != field_name
    }
    observed_properties: dict[str, object] = {
        "publicNetworkAccess": "Disabled",
        "networkAcls": {"defaultAction": "Deny"},
        **other_deployment_access,
    }
    with pytest.raises(
        PreflightInputError,
        match="conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "before": False,
                            "after": False,
                        },
                        {
                            "path": "properties",
                            "propertyChangeType": "Modify",
                            "before": copy.deepcopy(observed_properties),
                            "after": copy.deepcopy(observed_properties),
                        },
                        {
                            "path": "tags.release",
                            "propertyChangeType": "Modify",
                            "after": "wc029",
                        },
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "enabledForDeployment",
        "enabledForDiskEncryption",
        "enabledForTemplateDeployment",
    ],
)
def test_attested_key_vault_false_observation_rejects_one_sided_snapshot_omission(
    field_name: str,
) -> None:
    with pytest.raises(
        PreflightInputError,
        match="delta and full snapshot conflict",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "after": _resource_snapshot(
                        _KEY_VAULT_ID,
                        properties={
                            "publicNetworkAccess": "Disabled",
                            "networkAcls": {"defaultAction": "Deny"},
                        },
                        tags={"release": "after"},
                    ),
                    "delta": [
                        {
                            "path": f"properties.{field_name}",
                            "propertyChangeType": "Modify",
                            "before": False,
                            "after": False,
                        },
                        {
                            "path": "tags.release",
                            "propertyChangeType": "Modify",
                            "after": "after",
                        },
                    ],
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )


def test_what_if_allows_unchanged_key_vault_authorization_mode() -> None:
    before = _resource_snapshot(
        _KEY_VAULT_ID,
        properties={
            "enableRbacAuthorization": True,
            "publicNetworkAccess": "Disabled",
            "networkAcls": {"defaultAction": "Deny"},
        },
        tags={"release": "before"},
    )
    after = copy.deepcopy(before)
    after["tags"] = {"release": "after"}

    assert (
        evaluate_what_if(
            _what_if(
                {
                    "resourceId": _KEY_VAULT_ID,
                    "changeType": "Modify",
                    "before": before,
                    "after": after,
                }
            ),
            allowed_change_ids=frozenset({_KEY_VAULT_ID}),
        )
        == ()
    )


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


def test_attested_what_if_accepts_exact_resource_group_no_change() -> None:
    assert (
        _evaluate_attested_what_if(
            _what_if(
                _change(
                    _RG_SCOPE,
                    "NoChange",
                )
            )
        )
        == ()
    )


@pytest.mark.parametrize(
    "change_type",
    ["Create", "Modify"],
)
def test_attested_what_if_accepts_allowlisted_resource_group_changes(
    change_type: str,
) -> None:
    before = _resource_snapshot(
        _RG_SCOPE,
        properties={},
        location="australiaeast",
        tags={"release": "before"},
    )
    after = _resource_snapshot(
        _RG_SCOPE,
        properties={},
        location="australiaeast",
        tags={"release": "after"},
    )
    change: dict[str, object] = {
        "resourceId": _RG_SCOPE,
        "changeType": change_type,
        "after": after,
    }
    if change_type == "Modify":
        change["before"] = before

    assert (
        _evaluate_attested_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_RG_SCOPE}),
        )
        == ()
    )


def test_attested_what_if_applies_resource_group_allowlist_and_delta_checks() -> None:
    before = _resource_snapshot(
        _RG_SCOPE,
        properties={},
        location="australiaeast",
        tags={"release": "same"},
    )
    unchanged = copy.deepcopy(before)

    unapproved = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _RG_SCOPE,
                "changeType": "Modify",
                "before": before,
                "after": _resource_snapshot(
                    _RG_SCOPE,
                    properties={},
                    location="australiaeast",
                    tags={"release": "different"},
                ),
            }
        )
    )
    uninspectable = _evaluate_attested_what_if(
        _what_if(
            {
                "resourceId": _RG_SCOPE,
                "changeType": "Modify",
                "before": before,
                "after": unchanged,
            }
        ),
        allowed_change_ids=frozenset({_RG_SCOPE}),
    )

    assert {violation.code for violation in unapproved} == {"unapproved-change"}
    assert {violation.code for violation in uninspectable} == {"uninspectable-change"}


def test_attested_what_if_rejects_resource_group_outside_reviewed_boundary() -> None:
    with pytest.raises(
        PreflightInputError,
        match="outside the reviewed deployment resource-group boundary",
    ):
        _evaluate_attested_what_if(
            _what_if(
                {
                    "resourceId": _SIBLING_RG_SCOPE,
                    "changeType": "Create",
                    "after": _resource_snapshot(
                        _SIBLING_RG_SCOPE,
                        properties={},
                        location="australiaeast",
                    ),
                }
            ),
            allowed_change_ids=frozenset({_SIBLING_RG_SCOPE}),
        )


def test_attested_what_if_rejects_resource_group_snapshot_type_mismatch() -> None:
    change = _change(
        _RG_SCOPE,
        "NoChange",
    )
    before = change["before"]
    after = change["after"]
    assert isinstance(before, dict)
    assert isinstance(after, dict)
    before["type"] = "Microsoft.Resources/subscriptions"
    after["type"] = "Microsoft.Resources/subscriptions"

    with pytest.raises(
        PreflightInputError,
        match="type does not match resourceId",
    ):
        _evaluate_attested_what_if(
            _what_if(change),
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
                "properties": {},
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
                "name": "athena-presentation",
                "type": "Microsoft.App/containerApps",
                "properties": {},
            },
            "after": {
                "id": _CONTAINER_APP_ID,
                "name": "athena-presentation",
                "type": "Microsoft.App/containerApps",
                "properties": {},
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


@pytest.mark.parametrize(
    "delta",
    [
        {
            "path": "tags.release",
            "propertyChangeType": "NoEffect",
            "after": "wc029",
        },
        {
            "path": "tags.release",
            "propertyChangeType": "NoEffect",
            "before": "wc029",
        },
        {
            "path": "tags.release",
            "propertyChangeType": "NoEffect",
            "before": "wc029",
            "after": "changed",
        },
        {
            "path": "properties.configuration.ingress.external",
            "propertyChangeType": "NoEffect",
            "before": False,
            "after": 0,
        },
    ],
)
def test_modify_rejects_incomplete_or_changed_noeffect(
    delta: dict[str, object],
) -> None:
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": _resource_snapshot(
            _CONTAINER_APP_ID,
            properties={
                "configuration": {"ingress": {"external": False}},
            },
            tags={"release": "wc029"},
        ),
        "after": _resource_snapshot(
            _CONTAINER_APP_ID,
            properties={
                "configuration": {"ingress": {"external": False}},
            },
            tags={"release": "wc029"},
        ),
        "delta": [delta],
    }

    with pytest.raises(
        PreflightInputError,
        match="NoEffect requires before and after|NoEffect before and after values conflict",
    ):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_modify_requires_noeffect_resource_snapshot_reconciliation() -> None:
    without_snapshots = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "delta": [
                {
                    "path": "tags.release",
                    "propertyChangeType": "NoEffect",
                    "before": "wc029",
                    "after": "wc029",
                }
            ],
        }
    )
    with pytest.raises(PreflightInputError, match="complete resource snapshots"):
        evaluate_what_if(
            without_snapshots,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )

    conflicting_snapshot = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "before": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={"template": {"revisionSuffix": "before"}},
                tags={"release": "wc029"},
            ),
            "after": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={"template": {"revisionSuffix": "after"}},
                tags={"release": "changed"},
            ),
            "delta": [
                {
                    "path": "tags.release",
                    "propertyChangeType": "NoEffect",
                    "before": "wc029",
                    "after": "wc029",
                },
                {
                    "path": "properties.template.revisionSuffix",
                    "propertyChangeType": "Modify",
                    "before": "before",
                    "after": "after",
                },
            ],
        }
    )
    with pytest.raises(PreflightInputError, match="does not reconcile"):
        evaluate_what_if(
            conflicting_snapshot,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_modify_accepts_reconciled_noeffect_with_meaningful_delta() -> None:
    change = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "before": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={"template": {"revisionSuffix": "before"}},
                tags={"release": "wc029"},
            ),
            "after": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={"template": {"revisionSuffix": "after"}},
                tags={"release": "wc029"},
            ),
            "delta": [
                {
                    "path": "tags.release",
                    "propertyChangeType": "NoEffect",
                    "before": "wc029",
                    "after": "wc029",
                },
                {
                    "path": "properties.template.revisionSuffix",
                    "propertyChangeType": "Modify",
                    "before": "before",
                    "after": "after",
                },
            ],
        }
    )

    assert (
        evaluate_what_if(
            change,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )
        == ()
    )


@pytest.mark.parametrize(
    "missing_field",
    ["id", "name", "type", "properties"],
)
def test_modify_complete_snapshots_require_full_resource_identity(
    missing_field: str,
) -> None:
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties={"template": {"revisionSuffix": "before"}},
    )
    after = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties={"template": {"revisionSuffix": "after"}},
    )
    before.pop(missing_field)
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "before": before,
        "after": after,
    }

    with pytest.raises(PreflightInputError, match=missing_field):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


@pytest.mark.parametrize(
    "after",
    [
        {
            "type": "Microsoft.Authorization/roleAssignments",
            "properties": {},
        },
        {
            **_resource_snapshot(
                _STORAGE_ID,
                properties={},
                tags={"release": "wc029"},
            ),
            "type": "Microsoft.Authorization/roleAssignments",
        },
    ],
)
def test_snapshot_type_cannot_reclassify_authorization_change(
    after: dict[str, object],
) -> None:
    change = {
        "resourceId": _STORAGE_ID,
        "changeType": "Create",
        "after": after,
    }

    with pytest.raises(
        PreflightInputError,
        match="snapshot id|type does not match resourceId",
    ):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_modify_derives_and_validates_complete_snapshot_delta() -> None:
    safe = _what_if(
        {
            "resourceId": _CONTAINER_APP_ID,
            "changeType": "Modify",
            "before": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={
                    "template": {"revisionSuffix": "before"},
                },
            ),
            "after": _resource_snapshot(
                _CONTAINER_APP_ID,
                properties={
                    "template": {"revisionSuffix": "after"},
                },
            ),
        }
    )
    unsafe = _what_if(
        {
            "resourceId": _STORAGE_ID,
            "changeType": "Modify",
            "before": _resource_snapshot(
                _STORAGE_ID,
                properties={"allowSharedKeyAccess": False},
            ),
            "after": _resource_snapshot(
                _STORAGE_ID,
                properties={"allowSharedKeyAccess": True},
            ),
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

    with pytest.raises(
        PreflightInputError,
        match="protected path presence representations conflict",
    ):
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


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


def test_dotted_payload_keys_fail_closed_in_storage_protection() -> None:
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

    with pytest.raises(
        PreflightInputError,
        match="malformed property alias",
    ):
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


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


def test_security_decision_tokens_require_exact_trimmed_ascii() -> None:
    malformed_what_if_documents = [
        {
            "status": "ſucceeded",
            "properties": {"changes": []},
        },
        _what_if(
            {
                "resourceId": _CONTAINER_APP_ID,
                "changeType": " Modify ",
                "delta": [],
            }
        ),
        _what_if(
            {
                "resourceId": _CONTAINER_APP_ID,
                "changeType": "Modify",
                "delta": [
                    {
                        "path": "tags.release",
                        "propertyChangeType": "Modify ",
                        "after": "wc029",
                    }
                ],
            }
        ),
        _what_if(
            {
                "resourceId": _STORAGE_ID,
                "changeType": "Create",
                "after": {
                    "properties": {
                        "allowSharedKeyAccess": False,
                        "allowBlobPublicAccess": False,
                        "publicNetworkAccess": "Diſabled",
                        "networkAcls": {"defaultAction": "Deny"},
                    }
                },
            }
        ),
        _what_if(
            {
                "resourceId": _KEY_VAULT_ID,
                "changeType": "Create",
                "after": {
                    "properties": {
                        "publicNetworkAccess": "DisabledK",
                        "networkAcls": {"defaultAction": "Deny "},
                    }
                },
            }
        ),
        _what_if(
            {
                "resourceId": _STORAGE_CONTAINER_ID,
                "changeType": "Create",
                "after": {"properties": {"publicAccess": " None"}},
            }
        ),
    ]
    for document in malformed_what_if_documents:
        with pytest.raises(
            PreflightInputError,
            match="exact trimmed ASCII token",
        ):
            evaluate_what_if(
                document,
                allowed_change_ids=frozenset(
                    {
                        _CONTAINER_APP_ID,
                        _STORAGE_ID,
                        _KEY_VAULT_ID,
                        _STORAGE_CONTAINER_ID,
                    }
                ),
            )

    for invalid_role_name in (
        "Uſer Access Administrator",
        " Reader ",
    ):
        spoofed_role = _assignment(
            role_name=invalid_role_name,
            scope=_RG_SCOPE,
        )
        with pytest.raises(
            PreflightInputError,
            match="exact trimmed ASCII token",
        ):
            evaluate_role_assignments([spoofed_role])

    padded_principal_type = _assignment(
        role_name="Reader",
        scope=_RG_SCOPE,
    )
    padded_principal_type["principalType"] = " ServicePrincipal"
    with pytest.raises(
        PreflightInputError,
        match="exact trimmed ASCII token",
    ):
        evaluate_role_assignments([padded_principal_type])

    padded_forbidden_role_policy = {
        "separationRules": [
            {
                "principalId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "forbiddenRoleNames": [" Reader "],
                "forbiddenScopePrefixes": [_RG_SCOPE],
            }
        ]
    }
    with pytest.raises(
        PreflightInputError,
        match="exact trimmed ASCII token",
    ):
        evaluate_role_assignments(
            [],
            policy_document=padded_forbidden_role_policy,
        )

    padded_snapshot_type = _change(_STORAGE_ID, "NoChange")
    assert isinstance(padded_snapshot_type["before"], dict)
    assert isinstance(padded_snapshot_type["after"], dict)
    padded_snapshot_type["before"]["type"] = " Microsoft.Storage/storageAccounts "
    padded_snapshot_type["after"]["type"] = " Microsoft.Storage/storageAccounts "
    with pytest.raises(
        PreflightInputError,
        match="exact trimmed ASCII token",
    ):
        evaluate_what_if(_what_if(padded_snapshot_type))

    padded_schema = _attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))
    manifest = padded_schema["manifest"]
    assert isinstance(manifest, dict)
    manifest["schemaVersion"] = " athena.wc029PreflightManifest.v1 "
    padded_schema["attestation"] = _attestation(
        "what-if",
        manifest,
        (
            "allowChangeIdsDigest",
            "deploymentDigest",
            "parametersDigest",
            "templateDigest",
            "whatIfDigest",
            "whatIfRequestDigest",
        ),
    )
    with pytest.raises(
        PreflightInputError,
        match="exact trimmed ASCII token",
    ):
        evaluate_what_if(
            padded_schema,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(manifest),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


@pytest.mark.parametrize(
    ("path", "property_change_type"),
    [
        ("properties.", "Remove"),
        (".properties.allowSharedKeyAccess", "Modify"),
        ("properties..allowSharedKeyAccess", "Modify"),
        ("properties.allowSharedKeyAccess.", "Modify"),
        ("<resource>..properties.allowSharedKeyAccess", "Modify"),
        ("<resource>/", "Delete"),
        ("<resource>\\", "Delete"),
        ("<RESOURCE>", "Delete"),
        ("/", "Delete"),
        ("\\", "Delete"),
        ("properties/allowSharedKeyAccess", "Modify"),
        ("properties\\allowSharedKeyAccess", "Modify"),
        ("properties~1allowSharedKeyAccess", "Modify"),
        ("properties~0allowSharedKeyAccess", "Modify"),
        ("properties.allowSharedKeyAccess[", "Modify"),
        ("properties.allowSharedKeyAccess[]", "Modify"),
        ("properties.allowSharedKeyAccess[-1]", "Modify"),
        ("properties.allowSharedKeyAccess[01]", "Modify"),
        ("properties.allowSharedKeyAccess[0]suffix", "Modify"),
        ("[0].properties.allowSharedKeyAccess", "Modify"),
    ],
)
def test_property_paths_reject_every_unsupported_grammar_form(
    path: str,
    property_change_type: str,
) -> None:
    change = _change(
        _STORAGE_ID,
        "Modify",
        path=path,
        after=True,
    )
    delta = change["delta"]
    assert isinstance(delta, list)
    item = delta[0]
    assert isinstance(item, dict)
    item["propertyChangeType"] = property_change_type

    with pytest.raises(PreflightInputError, match="property path"):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_STORAGE_ID}),
        )


def test_nested_delta_path_accumulation_is_bounded_before_materialization() -> None:
    nested: dict[str, object] = {
        "path": "leaf" + "x" * 296,
        "propertyChangeType": "Modify",
        "after": True,
    }
    for index in range(14):
        nested = {
            "path": f"parent{index:02d}" + "x" * 292,
            "children": [nested],
        }
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "delta": [nested],
    }

    with pytest.raises(PreflightInputError, match="property path exceeds"):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_delta_path_generation_has_an_aggregate_work_budget() -> None:
    delta = [
        {
            "path": f"path{index:04d}" + "x" * 2980,
            "propertyChangeType": "Modify",
            "after": index,
        }
        for index in range(1500)
    ]
    change = {
        "resourceId": _CONTAINER_APP_ID,
        "changeType": "Modify",
        "delta": delta,
    }

    with pytest.raises(PreflightInputError, match="aggregate work budget"):
        evaluate_what_if(
            _what_if(change),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )


def test_noeffect_wide_snapshot_lookup_work_is_linear_and_bounded() -> None:
    leaf_count = 14000
    properties = {f"leaf{index:05d}": f"value-{index:05d}" for index in range(leaf_count)}
    before = _resource_snapshot(
        _CONTAINER_APP_ID,
        properties=properties,
    )
    after = copy.deepcopy(before)
    delta = [
        {
            "path": f"properties.leaf{index:05d}",
            "propertyChangeType": "NoEffect",
            "before": f"value-{index:05d}",
            "after": f"value-{index:05d}",
        }
        for index in range(leaf_count)
    ]
    budget = _PropertyPathBudget()

    snapshot_index = _build_snapshot_pair_index(
        before,
        after,
        budget=budget,
    )
    assert (
        _walk_delta(
            delta,
            budget=budget,
            snapshot_index=snapshot_index,
        )
        == []
    )
    assert budget.lookup_work == 112018
    assert budget.items == 42008


def test_security_identifiers_reject_kelvin_aliases_and_bind_raw_allowlists() -> None:
    kelvin_scope = _RG_SCOPE.replace("workload", "wor\u212aload")
    with pytest.raises(PreflightInputError, match="non-ASCII"):
        evaluate_what_if(
            _what_if(
                _change(
                    kelvin_scope + "/providers/Microsoft.Storage/storageAccounts/synthetic",
                    "Create",
                    path="tags.release",
                    after="wc029",
                )
            ),
        )

    ascii_artifact = _attested_what_if(
        _what_if(_change(_KEY_VAULT_ID, "NoChange")),
        allowed_change_ids=frozenset({_KEY_VAULT_ID}),
    )
    kelvin_allowlist_id = _KEY_VAULT_ID.replace(
        "KeyVault",
        "\u212aeyVault",
    )
    kelvin_artifact = _attested_what_if(
        _what_if(_change(_KEY_VAULT_ID, "NoChange")),
        allowed_change_ids=frozenset({kelvin_allowlist_id}),
    )
    ascii_manifest = ascii_artifact["manifest"]
    kelvin_manifest = kelvin_artifact["manifest"]
    assert isinstance(ascii_manifest, dict)
    assert isinstance(kelvin_manifest, dict)
    ascii_bindings = ascii_manifest["bindings"]
    kelvin_bindings = kelvin_manifest["bindings"]
    assert isinstance(ascii_bindings, dict)
    assert isinstance(kelvin_bindings, dict)
    assert ascii_bindings["allowChangeIdsDigest"] != kelvin_bindings["allowChangeIdsDigest"]

    with pytest.raises(
        PreflightInputError,
        match="allowChangeIdsDigest does not match",
    ):
        evaluate_what_if(
            ascii_artifact,
            allowed_change_ids=frozenset({_KEY_VAULT_ID.upper()}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(ascii_artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    with pytest.raises(
        PreflightInputError,
        match="allow-change resource ID contains non-ASCII",
    ):
        evaluate_what_if(
            ascii_artifact,
            allowed_change_ids=frozenset({kelvin_allowlist_id}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(ascii_artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    with pytest.raises(PreflightInputError, match="non-ASCII"):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="Reader",
                    scope=kelvin_scope,
                )
            ]
        )

    spoofed_role_id = _TEST_ROLE_IDS["acrpull"].replace(
        "Microsoft.Authorization",
        "Micro\u017foft.Authorization",
    )
    with pytest.raises(
        PreflightInputError,
        match="roleDefinitionId contains non-ASCII",
    ):
        evaluate_role_assignments(
            [
                _assignment(
                    role_name="AcrPull",
                    role_id=spoofed_role_id,
                    scope=_RG_SCOPE,
                )
            ]
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
            {
                "authorization-change-unsupported",
                "public-data-plane-access",
            },
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
    ("resource_id", "after"),
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
        ),
        (
            _STORAGE_CONTAINER_ID,
            {"properties": {"publicAccess": "None"}},
        ),
    ],
)
def test_ancestor_deletion_blocks_despite_separate_safe_after_payload(
    resource_id: str,
    after: dict[str, object],
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

    with pytest.raises(
        PreflightInputError,
        match="protected path presence representations conflict",
    ):
        evaluate_what_if(
            document,
            allowed_change_ids=frozenset({resource_id}),
        )


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
            "publicAccess must be an exact trimmed ASCII token",
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


def test_rbac_management_group_assignment_requires_reviewed_hierarchy() -> None:
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

    assert violations == ()


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


@pytest.mark.parametrize(
    ("assignment_scope", "forbidden_scope"),
    [
        (_MG_LEAF_SCOPE, _MG_ROOT_SCOPE),
        (_MG_ROOT_SCOPE, _MG_LEAF_SCOPE),
        (_SUBSCRIPTION_SCOPE, _MG_ROOT_SCOPE),
        (_RG_SCOPE, _MG_LEAF_SCOPE),
        (_WORKLOAD_RESOURCE_SCOPE, _MG_ROOT_SCOPE),
    ],
)
def test_guarded_rbac_separation_uses_management_group_hierarchy_both_directions(
    assignment_scope: str,
    forbidden_scope: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="Reader",
        scope=assignment_scope,
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
            "forbiddenScopePrefixes": [forbidden_scope],
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


def test_guarded_rbac_does_not_invent_unreviewed_management_group_ancestry() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    unrelated_management_group = "/providers/Microsoft.Management/managementGroups/unrelated"
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
            "forbiddenRoleDefinitionIds": [_TEST_ROLE_IDS["reader"]],
            "forbiddenScopePrefixes": [unrelated_management_group],
        }
    ]

    assert (
        _evaluate_guarded_rbac(
            _guarded_evidence(
                [assignment],
                effective_principal_ids=[principal_id],
            ),
            policy,
        )
        == ()
    )


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


def test_load_json_file_uses_one_bounded_binary_descriptor(
    tmp_path,
    monkeypatch,
) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"value":"synthetic"}', encoding="utf-8")
    real_open = os.open
    open_flags: list[int] = []

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        open_flags.append(flags)
        return real_open(path, flags, mode)

    def unexpected_path_read(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("path-level stat/read must not be used")

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(Path, "stat", unexpected_path_read)
    monkeypatch.setattr(Path, "read_text", unexpected_path_read)

    assert load_json_file(artifact) == {"value": "synthetic"}
    assert len(open_flags) == 1
    for flag_name in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK"):
        flag = getattr(os, flag_name, 0)
        if flag:
            assert open_flags[0] & flag


def test_load_json_file_rejects_descriptor_growth_beyond_bound(
    tmp_path,
    monkeypatch,
) -> None:
    artifact = tmp_path / "growing.json"
    initial_payload = b'{"value":"synthetic"}'
    artifact.write_bytes(initial_payload)
    simulated_growth = initial_payload + (b"x" * 64)
    offset = 0
    requested_bytes = 0

    def growing_read(_descriptor: int, count: int) -> bytes:
        nonlocal offset, requested_bytes
        requested_bytes += count
        chunk = simulated_growth[offset : offset + count]
        offset += len(chunk)
        return chunk

    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(PreflightInputError, match="between 1 and 32 bytes"):
        load_json_file(artifact, maximum_bytes=32)
    assert offset == 33
    assert requested_bytes == 33


@pytest.mark.skipif(os.name == "nt", reason="POSIX replacement semantics")
def test_load_json_file_reads_open_descriptor_across_path_replacement(
    tmp_path,
    monkeypatch,
) -> None:
    artifact = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    artifact.write_text('{"value":"opened"}', encoding="utf-8")
    replacement.write_text('{"value":"replacement"}', encoding="utf-8")
    real_open = os.open
    replaced = False

    def replacing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal replaced
        descriptor = real_open(path, flags, mode)
        if Path(path) == artifact:
            os.replace(replacement, artifact)
            replaced = True
        return descriptor

    monkeypatch.setattr(os, "open", replacing_open)

    assert load_json_file(artifact) == {"value": "opened"}
    assert replaced
    assert json.loads(artifact.read_text(encoding="utf-8")) == {"value": "replacement"}


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX no-follow regression",
)
def test_load_json_file_rejects_final_symlink(tmp_path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"value":"target"}', encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    with pytest.raises(PreflightInputError, match="cannot read"):
        load_json_file(link)


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "mkfifo"),
    reason="POSIX nonblocking special-file regression",
)
def test_load_json_file_rejects_fifo_without_blocking(tmp_path) -> None:
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)

    with pytest.raises(PreflightInputError, match="cannot read"):
        load_json_file(fifo)


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


def test_json_decimals_remain_exact_for_digest_and_noeffect(
    tmp_path,
) -> None:
    lower_path = tmp_path / "lower.json"
    higher_path = tmp_path / "higher.json"
    lower_path.write_text('{"value":9007199254740992.0}', encoding="utf-8")
    higher_path.write_text('{"value":9007199254740993.0}', encoding="utf-8")
    lower = load_json_file(lower_path)
    higher = load_json_file(higher_path)

    assert lower != higher
    assert _json_digest(lower) != _json_digest(higher)

    wide_lower_path = tmp_path / "wide-lower.json"
    wide_higher_path = tmp_path / "wide-higher.json"
    integer_path = tmp_path / "integer.json"
    decimal_path = tmp_path / "decimal.json"
    wide_lower_path.write_text(
        '{"value":123456789012345678901234567890.1}',
        encoding="utf-8",
    )
    wide_higher_path.write_text(
        '{"value":123456789012345678901234567890.2}',
        encoding="utf-8",
    )
    integer_path.write_text('{"value":1}', encoding="utf-8")
    decimal_path.write_text('{"value":1.0}', encoding="utf-8")

    assert _json_digest(load_json_file(wide_lower_path)) != _json_digest(
        load_json_file(wide_higher_path)
    )
    assert _json_digest(load_json_file(integer_path)) != _json_digest(load_json_file(decimal_path))

    change = _change(_STORAGE_ID, "NoChange")
    assert isinstance(change["before"], dict)
    assert isinstance(change["after"], dict)
    change["before"]["properties"] = {"ratio": "EXACT_LOWER"}
    change["after"]["properties"] = {"ratio": "EXACT_LOWER"}
    change["delta"] = [
        {
            "path": "properties.ratio",
            "propertyChangeType": "NoEffect",
            "before": "EXACT_LOWER",
            "after": "EXACT_HIGHER",
        }
    ]
    exact_path = tmp_path / "exact-noeffect.json"
    exact_path.write_text(
        json.dumps(_what_if(change))
        .replace('"EXACT_LOWER"', "9007199254740992.0")
        .replace('"EXACT_HIGHER"', "9007199254740993.0"),
        encoding="utf-8",
    )

    with pytest.raises(
        PreflightInputError,
        match="NoEffect before and after values conflict",
    ):
        evaluate_what_if(load_json_file(exact_path))


def test_json_and_rendering_reject_lone_surrogates_deterministically(
    tmp_path,
) -> None:
    surrogate_value = tmp_path / "surrogate-value.json"
    surrogate_key = tmp_path / "surrogate-key.json"
    surrogate_value.write_text('{"value":"\\ud800"}', encoding="utf-8")
    surrogate_key.write_text('{"\\ud800":"value"}', encoding="utf-8")

    with pytest.raises(PreflightInputError, match="strict UTF-8"):
        load_json_file(surrogate_value)
    with pytest.raises(PreflightInputError, match="JSON object keys are invalid"):
        load_json_file(surrogate_key)

    with pytest.raises(PreflightInputError, match="strict UTF-8"):
        evaluate_what_if(
            _what_if(
                _change(
                    _CONTAINER_APP_ID,
                    "Modify",
                    path="tags.release",
                    after="\ud800",
                )
            ),
            allowed_change_ids=frozenset({_CONTAINER_APP_ID}),
        )

    with pytest.raises(PreflightInputError, match="strict UTF-8"):
        render_preflight_json(
            kind="what-if",
            violations=(
                PreflightViolation(
                    code="synthetic",
                    subject="\ud800",
                    detail="synthetic",
                ),
            ),
        )

    stdout = StringIO()
    stderr = StringIO()
    assert (
        cli_main(
            _what_if_cli_args(surrogate_value),
            stdout=stdout,
            stderr=stderr,
        )
        == 3
    )
    assert stdout.getvalue() == ""
    assert "strict UTF-8" in stderr.getvalue()


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


def test_public_cli_consumes_shared_manifest_once_per_artifact_kind(
    tmp_path,
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
    what_if_artifact, rbac_artifact = _attested_pair(
        _what_if(_change(_STORAGE_ID, "NoChange")),
        _guarded_evidence([assignment]),
        policy,
    )
    what_if_path = tmp_path / "what-if.json"
    rbac_path = tmp_path / "rbac.json"
    policy_path = tmp_path / "policy.json"
    what_if_path.write_text(json.dumps(what_if_artifact), encoding="utf-8")
    rbac_path.write_text(json.dumps(rbac_artifact), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    assert (
        cli_main(
            _what_if_cli_args(what_if_path),
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 0
    )
    assert (
        cli_main(
            _rbac_cli_args(rbac_path, policy_path),
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 0
    )

    what_if_error = StringIO()
    assert (
        cli_main(
            _what_if_cli_args(what_if_path),
            stdout=StringIO(),
            stderr=what_if_error,
        )
        == 3
    )
    assert "already consumed what-if" in what_if_error.getvalue()

    rbac_error = StringIO()
    assert (
        cli_main(
            _rbac_cli_args(rbac_path, policy_path),
            stdout=StringIO(),
            stderr=rbac_error,
        )
        == 3
    )
    assert "already consumed rbac" in rbac_error.getvalue()

    ledger_files = sorted(
        path.name
        for path in (tmp_path / "trusted-release-ledger-root" / "release-ledger").iterdir()
    )
    assert ledger_files == [
        f"{_COLLECTION_RUN_ID}.collection.json",
        f"{_DEPLOYMENT_EXECUTION_ID}.binding.json",
        f"{_DEPLOYMENT_EXECUTION_ID}.rbac.consumed.json",
        f"{_DEPLOYMENT_EXECUTION_ID}.what-if.consumed.json",
    ]


def test_public_cli_requires_ledger_beneath_trusted_root(tmp_path) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    outside_ledger = tmp_path / "outside-ledger"
    outside_ledger.mkdir()
    for candidate in (
        outside_ledger,
        tmp_path / "missing-outside-parent" / "ledger",
    ):
        arguments = _what_if_cli_args(input_path)
        _replace_cli_option(arguments, "--release-ledger", candidate)
        stderr = StringIO()

        assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
        assert "beneath the trusted release-ledger root" in stderr.getvalue()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
@pytest.mark.parametrize(
    "redirect_mode",
    ["ledger", "ledger-parent", "trusted-root-parent"],
)
def test_windows_release_ledger_rejects_junctions_and_redirected_parents(
    tmp_path,
    redirect_mode: str,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    if redirect_mode == "trusted-root-parent":
        (outside / "trusted-root" / "ledger").mkdir(parents=True)
        junction = tmp_path / "redirected-root-parent"
        trusted_root = junction / "trusted-root"
        ledger_path = trusted_root / "ledger"
    else:
        trusted_root = tmp_path / "trusted-root"
        trusted_root.mkdir()
        junction = trusted_root / (
            "redirected-parent" if redirect_mode == "ledger-parent" else "ledger"
        )
    if redirect_mode == "ledger-parent":
        (outside / "ledger").mkdir()
        ledger_path = junction / "ledger"
    elif redirect_mode == "ledger":
        ledger_path = junction
    _create_windows_junction(junction, outside)
    try:
        arguments = _what_if_cli_args(input_path)
        _replace_cli_option(
            arguments,
            "--trusted-release-ledger-root",
            trusted_root,
        )
        _replace_cli_option(arguments, "--release-ledger", ledger_path)
        stderr = StringIO()

        assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
        assert "symlink, junction, or reparse point" in stderr.getvalue()
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction-swap regression")
def test_windows_release_ledger_detects_junction_swap_after_validation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    arguments = _what_if_cli_args(input_path)
    ledger_path = tmp_path / "trusted-release-ledger-root" / "release-ledger"
    outside = tmp_path / "outside-race-target"
    outside.mkdir()
    original = _SecureLedgerDirectory._fallback_file_path
    swapped = False

    def swap_after_validation(
        ledger: _SecureLedgerDirectory,
        name: str,
        *,
        require_existing: bool,
    ) -> Path:
        nonlocal swapped
        file_path = original(
            ledger,
            name,
            require_existing=require_existing,
        )
        if not require_existing and not swapped:
            os.rmdir(ledger_path)
            _create_windows_junction(ledger_path, outside)
            swapped = True
        return file_path

    monkeypatch.setattr(
        _SecureLedgerDirectory,
        "_fallback_file_path",
        swap_after_validation,
    )
    stderr = StringIO()
    try:
        assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
        assert "escaped the securely opened directory" in stderr.getvalue()
    finally:
        if ledger_path.exists():
            os.rmdir(ledger_path)
        for outside_file in outside.iterdir():
            outside_file.unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink regression")
@pytest.mark.parametrize(
    "redirect_mode",
    ["ledger", "ledger-parent", "trusted-root-parent"],
)
def test_posix_release_ledger_rejects_symlinks_and_redirected_parents(
    tmp_path,
    redirect_mode: str,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    if redirect_mode == "trusted-root-parent":
        (outside / "trusted-root" / "ledger").mkdir(parents=True)
        link = tmp_path / "redirected-root-parent"
        trusted_root = link / "trusted-root"
        ledger_path = trusted_root / "ledger"
    else:
        trusted_root = tmp_path / "trusted-root"
        trusted_root.mkdir()
        link = trusted_root / (
            "redirected-parent" if redirect_mode == "ledger-parent" else "ledger"
        )
    if redirect_mode == "ledger-parent":
        (outside / "ledger").mkdir()
        ledger_path = link / "ledger"
    elif redirect_mode == "ledger":
        ledger_path = link
    link.symlink_to(outside, target_is_directory=True)
    try:
        arguments = _what_if_cli_args(input_path)
        _replace_cli_option(
            arguments,
            "--trusted-release-ledger-root",
            trusted_root,
        )
        _replace_cli_option(arguments, "--release-ledger", ledger_path)
        stderr = StringIO()

        assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
        assert "symlink, junction, or reparse point" in stderr.getvalue()
    finally:
        link.unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow regression")
def test_posix_release_ledger_does_not_follow_existing_record_symlink(
    tmp_path,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    arguments = _what_if_cli_args(input_path)
    ledger_path = tmp_path / "trusted-release-ledger-root" / "release-ledger"
    outside = tmp_path / "outside.json"
    outside.write_text("unchanged", encoding="utf-8")
    record_link = ledger_path / f"{_COLLECTION_RUN_ID}.collection.json"
    record_link.symlink_to(outside)
    stderr = StringIO()

    assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
    assert "release ledger record is unavailable" in stderr.getvalue()
    assert outside.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.skipif(os.name == "nt", reason="POSIX special-file regression")
@pytest.mark.parametrize("record_kind", ["fifo", "socket"])
def test_posix_release_ledger_rejects_special_files_without_blocking(
    tmp_path,
    record_kind: str,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    arguments = _what_if_cli_args(input_path)
    with tempfile.TemporaryDirectory(prefix="wc029-", dir="/tmp") as root_value:
        trusted_root = Path(root_value)
        ledger_path = trusted_root / "l"
        ledger_path.mkdir()
        _replace_cli_option(
            arguments,
            "--trusted-release-ledger-root",
            trusted_root,
        )
        _replace_cli_option(arguments, "--release-ledger", ledger_path)
        record_path = ledger_path / f"{_COLLECTION_RUN_ID}.collection.json"
        active_socket: socket.socket | None = None
        if record_kind == "fifo":
            os.mkfifo(record_path)
        else:
            active_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            active_socket.bind(os.fspath(record_path))
        stderr = StringIO()
        try:
            assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
            assert (
                "release ledger record must be a regular file" in stderr.getvalue()
                or "release ledger record is unavailable" in stderr.getvalue()
            )
        finally:
            if active_socket is not None:
                active_socket.close()
            record_path.unlink()


@pytest.mark.parametrize("record_kind", ["collection", "binding"])
def test_public_cli_reports_invalid_utf8_existing_ledger_records(
    tmp_path,
    record_kind: str,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    arguments = _what_if_cli_args(input_path)
    ledger_path = tmp_path / "trusted-release-ledger-root" / "release-ledger"
    collection_path = ledger_path / f"{_COLLECTION_RUN_ID}.collection.json"
    binding_path = ledger_path / f"{_DEPLOYMENT_EXECUTION_ID}.binding.json"
    consumption_path = ledger_path / f"{_DEPLOYMENT_EXECUTION_ID}.what-if.consumed.json"
    if record_kind == "collection":
        collection_path.write_bytes(b"\xff")
    else:
        assert cli_main(arguments, stdout=StringIO(), stderr=StringIO()) == 0
        binding_path.unlink()
        consumption_path.unlink()
        binding_path.write_bytes(b"\xff")
    stderr = StringIO()

    assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
    assert "release ledger record is not valid JSON" in stderr.getvalue()


def test_release_ledger_writer_and_reader_share_one_record_bound(
    tmp_path,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    ledger_path = trusted_root / "ledger"
    ledger_path.mkdir(parents=True)
    readable_payload = {
        "value": "x" * (MAX_RELEASE_LEDGER_RECORD_BYTES - 128),
    }
    oversized_payload = {
        "value": "x" * MAX_RELEASE_LEDGER_RECORD_BYTES,
    }
    empty_rendered = (
        json.dumps(
            {"value": ""},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")
    exact_payload = {
        "value": "x" * (MAX_RELEASE_LEDGER_RECORD_BYTES - len(empty_rendered)),
    }

    with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
        ledger.create_json("readable.json", readable_payload)
        assert ledger.read_json("readable.json") == readable_payload
        ledger.create_json("exact-bound.json", exact_payload)
        assert ledger.read_json("exact-bound.json") == exact_payload
        with pytest.raises(
            PreflightInputError,
            match="release ledger record exceeds its byte bound",
        ):
            ledger.create_json("oversized.json", oversized_payload)

    assert not (ledger_path / "oversized.json").exists()
    assert (ledger_path / "exact-bound.json").stat().st_size == MAX_RELEASE_LEDGER_RECORD_BYTES


@pytest.mark.parametrize(
    "orphaned_content",
    [
        b"",
        b'{"value":"partial"',
    ],
)
def test_release_ledger_orphaned_staging_record_does_not_reserve_final_name(
    tmp_path,
    orphaned_content: bytes,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    ledger_path = trusted_root / "ledger"
    ledger_path.mkdir(parents=True)
    orphaned_staging = ledger_path / ".wc029-orphaned.tmp"
    orphaned_staging.write_bytes(orphaned_content)
    payload = {"value": "complete"}

    with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
        ledger.create_json("complete.json", payload)
        assert ledger.read_json("complete.json") == payload

    assert orphaned_staging.read_bytes() == orphaned_content


def test_release_ledger_fsyncs_staging_before_atomic_publication(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    ledger_path = trusted_root / "ledger"
    ledger_path.mkdir(parents=True)
    events: list[str] = []
    original_fsync = os.fsync
    original_publish = _SecureLedgerDirectory._publish_staged_record

    def tracked_fsync(file_descriptor: int) -> None:
        events.append("fsync")
        original_fsync(file_descriptor)

    def tracked_publish(
        ledger: _SecureLedgerDirectory,
        staging_name: str,
        final_name: str,
    ) -> None:
        assert events == ["fsync"]
        events.append("publish")
        original_publish(
            ledger,
            staging_name,
            final_name,
        )

    monkeypatch.setattr(os, "fsync", tracked_fsync)
    monkeypatch.setattr(
        _SecureLedgerDirectory,
        "_publish_staged_record",
        tracked_publish,
    )

    with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
        ledger.create_json("durable.json", {"value": "complete"})

    assert events[:2] == ["fsync", "publish"]


def test_release_ledger_publication_failure_does_not_poison_retry(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    ledger_path = trusted_root / "ledger"
    ledger_path.mkdir(parents=True)
    payload = {"value": "complete"}
    original_publish = _SecureLedgerDirectory._publish_staged_record
    publish_attempts = 0

    def fail_first_publish(
        ledger: _SecureLedgerDirectory,
        staging_name: str,
        final_name: str,
    ) -> None:
        nonlocal publish_attempts
        publish_attempts += 1
        if publish_attempts == 1:
            raise OSError("synthetic pre-publication failure")
        original_publish(
            ledger,
            staging_name,
            final_name,
        )

    monkeypatch.setattr(
        _SecureLedgerDirectory,
        "_publish_staged_record",
        fail_first_publish,
    )

    with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
        with pytest.raises(
            OSError,
            match="synthetic pre-publication failure",
        ):
            ledger.create_json("retry.json", payload)
        assert not (ledger_path / "retry.json").exists()
        ledger.create_json("retry.json", payload)
        assert ledger.read_json("retry.json") == payload

    assert not list(ledger_path.glob(".wc029-*.tmp"))


def test_release_ledger_concurrent_writers_publish_one_complete_record(
    tmp_path,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    ledger_path = trusted_root / "ledger"
    ledger_path.mkdir(parents=True)
    payload = {"value": "complete"}
    ready = Barrier(2)

    def write_record() -> str:
        with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
            ready.wait()
            try:
                ledger.create_json("concurrent.json", payload)
            except FileExistsError:
                return "exists"
            return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: write_record(), range(2)))

    assert outcomes == ["created", "exists"]
    with _SecureLedgerDirectory(ledger_path, trusted_root) as ledger:
        assert ledger.read_json("concurrent.json") == payload
    assert not list(ledger_path.glob(".wc029-*.tmp"))


@pytest.mark.parametrize(
    "poisoned_content",
    [
        b"",
        b'{"schemaVersion":',
    ],
)
def test_public_cli_rejects_poisoned_consumption_record_as_invalid(
    tmp_path,
    poisoned_content: bytes,
) -> None:
    input_path = tmp_path / "what-if.json"
    input_path.write_text(
        json.dumps(_attested_what_if(_what_if(_change(_STORAGE_ID, "NoChange")))),
        encoding="utf-8",
    )
    arguments = _what_if_cli_args(input_path)
    ledger_path = tmp_path / "trusted-release-ledger-root" / "release-ledger"
    consumption_path = ledger_path / f"{_DEPLOYMENT_EXECUTION_ID}.what-if.consumed.json"
    consumption_path.write_bytes(poisoned_content)
    stderr = StringIO()

    assert cli_main(arguments, stdout=StringIO(), stderr=stderr) == 3
    assert "already consumed" not in stderr.getvalue()
    assert "release ledger record" in stderr.getvalue()


def test_public_cli_rejects_cross_artifact_manifest_rebinding(tmp_path) -> None:
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
    what_if_document = _what_if(_change(_STORAGE_ID, "NoChange"))
    what_if_artifact, _ = _attested_pair(
        what_if_document,
        _guarded_evidence([assignment]),
        policy,
    )
    _, rebound_rbac_artifact = _attested_pair(
        what_if_document,
        _guarded_evidence([assignment]),
        policy,
        deployment_target=_deployment_target(
            resource_group_ids=(
                _RG_SCOPE,
                _WC013_RG_SCOPE,
                _SIBLING_RG_SCOPE,
            ),
        ),
    )
    what_if_path = tmp_path / "what-if.json"
    rbac_path = tmp_path / "rbac.json"
    policy_path = tmp_path / "policy.json"
    what_if_path.write_text(json.dumps(what_if_artifact), encoding="utf-8")
    rbac_path.write_text(json.dumps(rebound_rbac_artifact), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    assert (
        cli_main(
            _what_if_cli_args(what_if_path),
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 0
    )
    stderr = StringIO()
    assert (
        cli_main(
            _rbac_cli_args(rbac_path, policy_path),
            stdout=StringIO(),
            stderr=stderr,
        )
        == 3
    )
    assert "collectionRunId is already bound" in stderr.getvalue()


def test_public_cli_binds_collection_run_to_one_deployment_execution(
    tmp_path,
) -> None:
    second_execution_id = "88888888-8888-8888-8888-888888888888"
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
    what_if_document = _what_if(_change(_STORAGE_ID, "NoChange"))
    what_if_artifact, _ = _attested_pair(
        what_if_document,
        _guarded_evidence([assignment]),
        policy,
    )
    _, rebound_rbac_artifact = _attested_pair(
        what_if_document,
        _guarded_evidence([assignment]),
        policy,
        deployment_execution_id=second_execution_id,
    )
    what_if_path = tmp_path / "what-if.json"
    rbac_path = tmp_path / "rbac.json"
    policy_path = tmp_path / "policy.json"
    what_if_path.write_text(json.dumps(what_if_artifact), encoding="utf-8")
    rbac_path.write_text(json.dumps(rebound_rbac_artifact), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    assert (
        cli_main(
            _what_if_cli_args(what_if_path),
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 0
    )
    stderr = StringIO()
    assert (
        cli_main(
            _rbac_cli_args(
                rbac_path,
                policy_path,
                deployment_execution_id=second_execution_id,
            ),
            stdout=StringIO(),
            stderr=stderr,
        )
        == 3
    )
    assert "collectionRunId is already bound" in stderr.getvalue()


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


def test_attested_what_if_requires_exact_full_analysis_request() -> None:
    document = _what_if(_change(_STORAGE_ID, "NoChange"))

    def replace_value(request: dict[str, object], option: str, value: str) -> None:
        arguments = request["arguments"]
        assert isinstance(arguments, list)
        arguments[arguments.index(option) + 1] = value

    invalid_requests: list[dict[str, object]] = []
    wrong_command = _what_if_request()
    command = wrong_command["command"]
    assert isinstance(command, list)
    command[-1] = "create"
    invalid_requests.append(wrong_command)

    for option, value in (
        ("--result-format", "ResourceIdOnly"),
        ("--validation-level", "ProviderNoRbac"),
        ("--output", "tsv"),
    ):
        request = _what_if_request()
        replace_value(request, option, value)
        invalid_requests.append(request)

    for option, value in (
        ("--query", "properties.changes"),
        ("--exclude-change-types", "NoChange"),
        ("--what-if-exclude-change-types", "NoChange"),
    ):
        request = _what_if_request()
        arguments = request["arguments"]
        assert isinstance(arguments, list)
        arguments.extend([option, value])
        invalid_requests.append(request)

    fuzzy_option = _what_if_request()
    fuzzy_arguments = fuzzy_option["arguments"]
    assert isinstance(fuzzy_arguments, list)
    fuzzy_arguments[fuzzy_arguments.index("--result-format")] = "--Result-Format"
    invalid_requests.append(fuzzy_option)

    missing_no_pretty = _what_if_request()
    missing_no_pretty_arguments = missing_no_pretty["arguments"]
    assert isinstance(missing_no_pretty_arguments, list)
    missing_no_pretty_arguments.remove("--no-pretty-print")
    invalid_requests.append(missing_no_pretty)

    padded_option = _what_if_request()
    padded_option_arguments = padded_option["arguments"]
    assert isinstance(padded_option_arguments, list)
    padded_option_arguments[padded_option_arguments.index("--subscription")] = " --subscription "
    invalid_requests.append(padded_option)

    padded_value = _what_if_request()
    padded_value_arguments = padded_value["arguments"]
    assert isinstance(padded_value_arguments, list)
    padded_value_arguments[padded_value_arguments.index("--output") + 1] = " json "
    invalid_requests.append(padded_value)

    single_dash_value = _what_if_request()
    replace_value(single_dash_value, "--output", "-json")
    invalid_requests.append(single_dash_value)

    for invalid_name in ("bad/name", "x" * 65):
        request = _what_if_request()
        replace_value(request, "--name", invalid_name)
        invalid_requests.append(request)

    for invalid_parameters in (
        "-main.bicepparam",
        "../main.bicepparam",
        "https://example.invalid/main.bicepparam",
        "main bicepparam",
        "infra/main.json",
    ):
        request = _what_if_request()
        replace_value(request, "--parameters", invalid_parameters)
        invalid_requests.append(request)

    for invalid_json_parameters, invalid_template in (
        ("@../main.parameters.json", "infra/main.bicep"),
        ("@infra/main.parameters.json", "../main.bicep"),
    ):
        request = _what_if_request()
        request_arguments = request["arguments"]
        assert isinstance(request_arguments, list)
        parameters_index = request_arguments.index("--parameters")
        request_arguments[parameters_index + 1] = invalid_json_parameters
        request_arguments[parameters_index:parameters_index] = [
            "--template-file",
            invalid_template,
        ]
        invalid_requests.append(request)

    for request in invalid_requests:
        artifact = _attested_what_if(
            document,
            what_if_request=request,
        )
        with pytest.raises(PreflightInputError, match="what-if"):
            evaluate_what_if(
                artifact,
                require_attestation=True,
                expected_collection_run_id=_COLLECTION_RUN_ID,
                expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
                attestation_manifest_digest=_json_digest(artifact["manifest"]),
                deployment_digest=_DEPLOYMENT_DIGEST,
                template_digest=_TEMPLATE_DIGEST,
                parameters_digest=_PARAMETERS_DIGEST,
            )

    json_request = _what_if_request()
    json_arguments = json_request["arguments"]
    assert isinstance(json_arguments, list)
    parameters_index = json_arguments.index("--parameters")
    json_arguments[parameters_index + 1] = "@infra/main.parameters.json"
    json_arguments[parameters_index:parameters_index] = [
        "--template-file",
        "infra/main.bicep",
    ]
    json_artifact = _attested_what_if(
        document,
        what_if_request=json_request,
    )
    assert (
        evaluate_what_if(
            json_artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(json_artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )
        == ()
    )

    windows_path_request = _what_if_request()
    replace_value(
        windows_path_request,
        "--parameters",
        "infra\\main.preparation.bicepparam",
    )
    windows_path_artifact = _attested_what_if(
        document,
        what_if_request=windows_path_request,
    )
    assert (
        evaluate_what_if(
            windows_path_artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(windows_path_artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )
        == ()
    )


@pytest.mark.parametrize(
    "deployment_scope",
    ["sub", "group"],
)
def test_attested_what_if_accepts_exact_no_prompt_true(
    deployment_scope: str,
) -> None:
    resource_id = _STORAGE_ID if deployment_scope == "sub" else _WORKLOAD_RESOURCE_SCOPE
    document = _what_if(_change(resource_id, "NoChange"))
    request = _what_if_request() if deployment_scope == "sub" else _group_what_if_request()
    artifact = _attested_what_if(
        document,
        what_if_request=request,
    )

    assert (
        evaluate_what_if(
            artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )
        == ()
    )


@pytest.mark.parametrize(
    "deployment_scope",
    ["sub", "group"],
)
@pytest.mark.parametrize(
    "mutation",
    [
        "omitted",
        "false",
        "uppercase-value",
        "interactive-value",
        "numeric-value",
        "padded-value",
        "duplicate",
        "alias",
        "equals-form",
        "missing-value",
    ],
)
def test_attested_what_if_rejects_non_exact_no_prompt_pair(
    deployment_scope: str,
    mutation: str,
) -> None:
    resource_id = _STORAGE_ID if deployment_scope == "sub" else _WORKLOAD_RESOURCE_SCOPE
    document = _what_if(_change(resource_id, "NoChange"))
    request = _what_if_request() if deployment_scope == "sub" else _group_what_if_request()
    arguments = request["arguments"]
    assert isinstance(arguments, list)
    option_index = arguments.index("--no-prompt")
    if mutation == "omitted":
        del arguments[option_index : option_index + 2]
    elif mutation == "false":
        arguments[option_index + 1] = "false"
    elif mutation == "uppercase-value":
        arguments[option_index + 1] = "True"
    elif mutation == "interactive-value":
        arguments[option_index + 1] = "yes"
    elif mutation == "numeric-value":
        arguments[option_index + 1] = "1"
    elif mutation == "padded-value":
        arguments[option_index + 1] = " true "
    elif mutation == "duplicate":
        arguments.extend(["--no-prompt", "true"])
    elif mutation == "alias":
        arguments[option_index] = "--noPrompt"
    elif mutation == "equals-form":
        arguments[option_index : option_index + 2] = ["--no-prompt=true"]
    else:
        assert mutation == "missing-value"
        del arguments[option_index + 1]
    artifact = _attested_what_if(
        document,
        what_if_request=request,
    )

    with pytest.raises(PreflightInputError, match="what-if command"):
        evaluate_what_if(
            artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


def test_attested_what_if_binds_request_and_rejects_diagnostics() -> None:
    document = _what_if(_change(_STORAGE_ID, "NoChange"))
    artifact = _attested_what_if(document)
    request = artifact["whatIfRequest"]
    assert isinstance(request, dict)
    arguments = request["arguments"]
    assert isinstance(arguments, list)
    arguments[arguments.index("--name") + 1] = "different-valid-name"
    with pytest.raises(
        PreflightInputError,
        match="whatIfRequestDigest does not match",
    ):
        evaluate_what_if(
            artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    for diagnostic_document in (
        {
            **_what_if(_change(_STORAGE_ID, "NoChange")),
            "diagnostics": [{"level": "Warning", "message": "synthetic"}],
        },
        {
            "status": "Succeeded",
            "properties": {
                "changes": [_change(_STORAGE_ID, "NoChange")],
                "diagnostics": {"code": "IncompleteAnalysis"},
            },
        },
        {
            "status": "Succeeded",
            "properties": {
                "changes": [
                    {
                        **_change(_STORAGE_ID, "NoChange"),
                        "validationDiagnostics": "synthetic",
                    }
                ],
            },
        },
    ):
        diagnostic_artifact = _attested_what_if(diagnostic_document)
        with pytest.raises(PreflightInputError, match="diagnostics"):
            evaluate_what_if(
                diagnostic_artifact,
                require_attestation=True,
                expected_collection_run_id=_COLLECTION_RUN_ID,
                expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
                attestation_manifest_digest=_json_digest(diagnostic_artifact["manifest"]),
                deployment_digest=_DEPLOYMENT_DIGEST,
                template_digest=_TEMPLATE_DIGEST,
                parameters_digest=_PARAMETERS_DIGEST,
            )

    empty_diagnostics = {
        **document,
        "diagnostics": [],
    }
    empty_artifact = _attested_what_if(empty_diagnostics)
    assert (
        evaluate_what_if(
            empty_artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(empty_artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )
        == ()
    )


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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            "whatIfRequestDigest",
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


def test_what_if_attestation_binds_deployment_execution_and_boundary() -> None:
    document = _what_if(_change(_STORAGE_ID, "NoChange"))
    artifact = _attested_what_if(document)
    with pytest.raises(
        PreflightInputError,
        match="deploymentExecutionId does not match",
    ):
        evaluate_what_if(
            artifact,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=("66666666-6666-6666-6666-666666666666"),
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    wrong_boundary = _attested_what_if(
        document,
        deployment_target=_deployment_target(
            resource_group_ids=(_RG_SCOPE,),
        ),
    )
    with pytest.raises(
        PreflightInputError,
        match="outside the reviewed deployment resource-group boundary",
    ):
        evaluate_what_if(
            wrong_boundary,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(wrong_boundary["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    other_subscription = "99999999-9999-9999-9999-999999999999"
    wrong_subscription = _attested_what_if(
        document,
        deployment_target=_deployment_target(
            subscription_id=other_subscription,
            resource_group_ids=(f"/subscriptions/{other_subscription}/resourceGroups/synthetic",),
        ),
    )
    with pytest.raises(
        PreflightInputError,
        match="outside the reviewed deployment subscription",
    ):
        evaluate_what_if(
            wrong_subscription,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(wrong_subscription["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    sibling_resource = f"{_SIBLING_RG_SCOPE}/providers/Microsoft.Storage/storageAccounts/synthetic"
    out_of_boundary_allowlist = _attested_what_if(
        document,
        allowed_change_ids=frozenset({sibling_resource}),
    )
    with pytest.raises(
        PreflightInputError,
        match="allow-change resource ID is outside the reviewed deployment resource-group boundary",
    ):
        evaluate_what_if(
            out_of_boundary_allowlist,
            allowed_change_ids=frozenset({sibling_resource}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(out_of_boundary_allowlist["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )

    snapshot_change = _change(
        _STORAGE_ID,
        "Create",
        path="tags.release",
        after="wc029",
    )
    snapshot_change["after"] = {
        "id": sibling_resource,
        "tags": {"release": "wc029"},
    }
    out_of_boundary_snapshot = _attested_what_if(
        _what_if(snapshot_change),
        allowed_change_ids=frozenset({_STORAGE_ID}),
    )
    with pytest.raises(
        PreflightInputError,
        match="after snapshot id is outside the reviewed deployment resource-group boundary",
    ):
        evaluate_what_if(
            out_of_boundary_snapshot,
            allowed_change_ids=frozenset({_STORAGE_ID}),
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(out_of_boundary_snapshot["manifest"]),
            deployment_digest=_DEPLOYMENT_DIGEST,
            template_digest=_TEMPLATE_DIGEST,
            parameters_digest=_PARAMETERS_DIGEST,
        )


@pytest.mark.parametrize(
    "deployment_target",
    [
        _deployment_target(
            tenant_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        ),
        _deployment_target(
            resource_group_ids=(_WC013_RG_SCOPE,),
        ),
    ],
)
def test_rbac_attestation_binds_manifest_deployment_target(
    deployment_target: dict[str, object],
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
    artifact = _attested_rbac(
        _guarded_evidence([assignment]),
        policy,
        deployment_target=deployment_target,
    )

    with pytest.raises(
        PreflightInputError,
        match="does not match the reviewed manifest deploymentTarget",
    ):
        evaluate_role_assignments(
            artifact,
            policy_document=policy,
            require_separation_rules=True,
            require_attestation=True,
            expected_collection_run_id=_COLLECTION_RUN_ID,
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
            attestation_manifest_digest=_json_digest(artifact["manifest"]),
        )


@pytest.mark.parametrize(
    "binding_input",
    [
        "policy",
        "hierarchy",
        "subscriptionTenant",
        "membership",
        "denyAssignments",
        "roleAssignments",
    ],
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
    elif binding_input == "subscriptionTenant":
        _management_group_subscription_properties(evidence)["tenant"] = (
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        )
    else:
        principal = _first_principal_artifact(evidence)
        artifact_name = "groupMembership" if binding_input == "membership" else binding_input
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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
            expected_deployment_execution_id=_DEPLOYMENT_EXECUTION_ID,
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


def test_guarded_rbac_bounds_400_assignments_against_256_matching_rules(
    monkeypatch,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment_count = 400
    rule_count = 256
    assignments = [
        _guarded_assignment(
            principal_id=principal_id,
            role_name="AcrPull",
            scope=_RG_SCOPE,
            condition=f"synthetic-condition-{index:03d}",
            condition_version="2.0",
        )
        for index in range(assignment_count)
    ]
    policy = _production_policy(
        principal_id,
        expected_assignments=assignments,
    )
    policy["separationRules"] = [
        {
            "principalId": principal_id,
            "forbiddenRoleNames": ["AcrPull"],
            "forbiddenRoleDefinitionIds": [
                _TEST_ROLE_IDS["acrpull"],
            ],
            "forbiddenScopePrefixes": [
                (f"{_RG_SCOPE}/providers/Microsoft.Storage/storageAccounts/synthetic{index:03d}")
            ],
        }
        for index in range(rule_count)
    ]
    original_scope_match = wc029_preflight_module._separation_scope_matches
    scope_evaluations = 0

    def counted_scope_match(
        assignment_scope: str,
        forbidden_scope_prefix: str,
        *,
        collection: object,
    ) -> bool:
        nonlocal scope_evaluations
        scope_evaluations += 1
        return original_scope_match(
            assignment_scope,
            forbidden_scope_prefix,
            collection=collection,
        )

    monkeypatch.setattr(
        wc029_preflight_module,
        "_separation_scope_matches",
        counted_scope_match,
    )

    violations = _evaluate_guarded_rbac(
        _guarded_evidence(assignments),
        policy,
    )

    assert [item.code for item in violations] == ["identity-separation"]
    assert scope_evaluations == assignment_count


def test_rbac_violation_cap_stops_generation_before_remaining_assignments(
    monkeypatch,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignments = [
        _assignment(
            principal_id=principal_id,
            role_name="AcrPull",
            role_id=_TEST_ROLE_IDS["acrpull"],
            scope=(f"{_RG_SCOPE}/providers/Microsoft.Storage/storageAccounts/synthetic{index:03d}"),
        )
        for index in range(400)
    ]
    policy = {
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["AcrPull"],
                "forbiddenRoleDefinitionIds": [
                    _TEST_ROLE_IDS["acrpull"],
                ],
                "forbiddenScopePrefixes": [_RG_SCOPE],
            }
        ]
    }
    original_scope_match = wc029_preflight_module._separation_scope_matches
    scope_evaluations = 0

    def counted_scope_match(
        assignment_scope: str,
        forbidden_scope_prefix: str,
        *,
        collection: object,
    ) -> bool:
        nonlocal scope_evaluations
        scope_evaluations += 1
        return original_scope_match(
            assignment_scope,
            forbidden_scope_prefix,
            collection=collection,
        )

    monkeypatch.setattr(
        wc029_preflight_module,
        "_separation_scope_matches",
        counted_scope_match,
    )

    with pytest.raises(
        PreflightInputError,
        match="violation count exceeds 256",
    ):
        evaluate_role_assignments(
            assignments,
            policy_document=policy,
        )

    assert scope_evaluations == 257


def test_rbac_separation_rule_work_budget_fails_closed(
    monkeypatch,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        role_id=_TEST_ROLE_IDS["acrpull"],
        scope=_RG_SCOPE,
    )
    policy = {
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["AcrPull"],
                "forbiddenRoleDefinitionIds": [
                    _TEST_ROLE_IDS["acrpull"],
                ],
                "forbiddenScopePrefixes": [
                    f"/subscriptions/{index:08x}-0000-0000-0000-000000000000"
                ],
            }
            for index in range(1, 6)
        ]
    }
    monkeypatch.setattr(
        wc029_preflight_module,
        "MAX_SEPARATION_RULE_WORK",
        25,
    )

    with pytest.raises(
        PreflightInputError,
        match="identity-separation rule evaluation exceeds its deterministic work budget",
    ):
        evaluate_role_assignments(
            [assignment],
            policy_document=policy,
        )


def test_rbac_scope_prefix_minimization_is_linear_and_budgeted(
    monkeypatch,
) -> None:
    prefixes = [
        (f"{_RG_SCOPE}/providers/Microsoft.Storage/storageAccounts/synthetic{index:03d}")
        for index in range(512)
    ]
    original_scope_contains = wc029_preflight_module._scope_contains
    containment_checks = 0

    def counted_scope_contains(ancestor: str, descendant: str) -> bool:
        nonlocal containment_checks
        containment_checks += 1
        return original_scope_contains(ancestor, descendant)

    monkeypatch.setattr(
        wc029_preflight_module,
        "_scope_contains",
        counted_scope_contains,
    )
    budget = wc029_preflight_module._SeparationRuleWorkBudget()

    minimal = wc029_preflight_module._minimal_scope_prefixes(
        prefixes,
        budget=budget,
    )

    assert minimal == tuple(prefixes)
    assert containment_checks == len(prefixes) - 1
    expected_token_work = sum(1 + len(prefix.strip("/").split("/")) for prefix in prefixes)
    assert budget.work == expected_token_work + len(prefixes) - 1


def test_rbac_scope_prefix_minimization_handles_interleaved_sibling_names() -> None:
    ancestor = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/rg".lower()
    sibling = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/rg-archive".lower()
    descendant = f"{ancestor}/providers/Microsoft.Storage/storageAccounts/synthetic".lower()
    budget = wc029_preflight_module._SeparationRuleWorkBudget()

    assert wc029_preflight_module._minimal_scope_prefixes(
        [ancestor, sibling, descendant],
        budget=budget,
    ) == (
        ancestor,
        sibling,
    )


def test_rbac_rejects_equivalent_rules_with_interleaved_redundant_descendant() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        role_id=_TEST_ROLE_IDS["acrpull"],
        scope=_RG_SCOPE,
    )
    ancestor = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/rg"
    sibling = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/rg-archive"
    descendant = f"{ancestor}/providers/Microsoft.Storage/storageAccounts/synthetic"
    policy = {
        "separationRules": [
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["AcrPull"],
                "forbiddenRoleDefinitionIds": [
                    _TEST_ROLE_IDS["acrpull"],
                ],
                "forbiddenScopePrefixes": [ancestor, sibling],
            },
            {
                "principalId": principal_id,
                "forbiddenRoleNames": ["AcrPull"],
                "forbiddenRoleDefinitionIds": [
                    _TEST_ROLE_IDS["acrpull"],
                ],
                "forbiddenScopePrefixes": [
                    ancestor,
                    sibling,
                    descendant,
                ],
            },
        ]
    }

    with pytest.raises(
        PreflightInputError,
        match="equivalent duplicate rule",
    ):
        evaluate_role_assignments(
            [assignment],
            policy_document=policy,
        )


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
    ("evidence_kind", "alias_field"),
    [
        ("arm", "@odata.nextLink"),
        ("arm", "NextLink"),
        ("graph", "nextLink"),
        ("graph", "@odata.nextlink"),
    ],
)
@pytest.mark.parametrize(
    "mutation",
    ["replacement", "collision"],
)
def test_guarded_rbac_rejects_endpoint_inappropriate_next_link_fields(
    evidence_kind: str,
    alias_field: str,
    mutation: str,
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
        expected_field = "nextLink"
    else:
        container = principal["groupMembership"]
        expected_field = "@odata.nextLink"
    assert isinstance(container, dict)
    pages = container["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    if mutation == "replacement":
        page[alias_field] = page.pop(expected_field)
    else:
        assert mutation == "collision"
        page[alias_field] = None

    with pytest.raises(
        PreflightInputError,
        match="must contain only the exact|case-insensitive key collision",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    "evidence_kind",
    ["arm", "graph"],
)
def test_guarded_rbac_rejects_whitespace_next_link_values(
    evidence_kind: str,
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
        next_link_field = "nextLink"
        padded_url = " https://management.azure.com/synthetic"
    else:
        container = principal["groupMembership"]
        next_link_field = "@odata.nextLink"
        padded_url = "https://graph.microsoft.com/synthetic "
    assert isinstance(container, dict)
    pages = container["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page[next_link_field] = padded_url

    with pytest.raises(PreflightInputError, match="whitespace"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    "collection_kind",
    ["ancestors", "descendants"],
)
def test_guarded_rbac_accepts_exact_arm_skip_token_pagination(
    collection_kind: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    _set_two_page_arm_role_assignments(
        evidence,
        collection_kind=collection_kind,
    )

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
    )


@pytest.mark.parametrize(
    "evidence_kind",
    [
        "arm-role",
        "graph",
        "deny",
    ],
)
def test_guarded_rbac_rejects_canonical_pagination_request_and_cursor_reuse(
    evidence_kind: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    if evidence_kind == "graph":
        initial_url = (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}/transitiveMemberOf"
        )
        continuation_url = f"{initial_url}?%24skiptoken=synthetic-reused"
        aliased_url = (
            "HTTPS://GRAPH.MICROSOFT.COM/V1.0/servicePrincipals/"
            f"{principal_id}/transitiveMember%4Ff"
            "?%24skiptoken=%73ynthetic-reused"
        )
        principal["groupMembership"] = {
            "tenantId": _TENANT_ID,
            "method": "transitiveMemberOf",
            "pages": [
                {
                    "requestUrl": initial_url,
                    "statusCode": 200,
                    "value": [],
                    "@odata.nextLink": continuation_url,
                },
                {
                    "requestUrl": continuation_url,
                    "statusCode": 200,
                    "value": [],
                    "@odata.nextLink": aliased_url,
                },
                {
                    "requestUrl": aliased_url,
                    "statusCode": 200,
                    "value": [],
                    "@odata.nextLink": None,
                },
            ],
        }
    else:
        if evidence_kind == "arm-role":
            pages = _arm_role_assignment_pages(
                evidence,
                collection_kind="ancestors",
            )
        else:
            deny_collection = _deny_assignment_collection(
                evidence,
                "target-and-ancestors",
            )
            pages = deny_collection["pages"]
            assert isinstance(pages, list)
        first_page = pages[0]
        assert isinstance(first_page, dict)
        initial_url = str(first_page["requestUrl"])
        initial_path, initial_query = initial_url.split("?", 1)
        query_parts = initial_query.split("&")
        continuation_url = f"{initial_url}&%24skipToken=synthetic-reused"
        aliased_path = initial_path.replace(
            "/providers/Microsoft.Authorization/",
            "/PROVIDERS/Microsoft.Authorization/",
        ).replace(
            "Assignments",
            "%41ssignments",
        )
        aliased_url = (
            f"{aliased_path}?%24skipToken=%73ynthetic-reused&{query_parts[-1]}&{query_parts[0]}"
        )
        first_page["nextLink"] = continuation_url
        pages.extend(
            [
                {
                    "requestUrl": continuation_url,
                    "statusCode": 200,
                    "value": [],
                    "nextLink": aliased_url,
                },
                {
                    "requestUrl": aliased_url,
                    "statusCode": 200,
                    "value": [],
                    "nextLink": None,
                },
            ]
        )

    with pytest.raises(
        PreflightInputError,
        match="repeated canonical request|reuses a decoded cursor",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("continuation_query", "message"),
    [
        ("%24skipToken=", "requestUrl is not canonical"),
        ("%24skipToken=%20", "requestUrl is not canonical"),
        ("%24skipToken=synthetic%20token", "requestUrl is not canonical"),
        ("%24skiptoken=synthetic", "not canonical for this endpoint"),
        ("%24SkipToken=synthetic", "not canonical for this endpoint"),
        (
            "%24skipToken=synthetic&%24skipToken=duplicate",
            "duplicate decoded key",
        ),
        (
            "%24skipToken=synthetic&%24skiptoken=collision",
            "duplicate decoded key",
        ),
    ],
)
def test_guarded_rbac_rejects_arm_skip_token_spelling_and_collisions(
    continuation_query: str,
    message: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    _set_two_page_arm_role_assignments(
        evidence,
        collection_kind="ancestors",
        continuation_query=continuation_query,
    )

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("continuation_query", "message"),
    [
        ("%24skiptoken=", "continuation URL is not canonical"),
        ("%24skiptoken=%20", "continuation URL is not canonical"),
        ("%24skiptoken=synthetic%20token", "continuation URL is not canonical"),
        ("%24skipToken=synthetic", "not canonical for this endpoint"),
        ("%24Skiptoken=synthetic", "not canonical for this endpoint"),
        (
            "%24skiptoken=synthetic&%24skiptoken=duplicate",
            "duplicate decoded key",
        ),
        (
            "%24skiptoken=synthetic&%24skipToken=collision",
            "duplicate decoded key",
        ),
        (
            "%24skiptoken=synthetic&%24skip=1",
            "not canonical for this endpoint",
        ),
    ],
)
def test_guarded_rbac_rejects_graph_skiptoken_spelling_and_collisions(
    continuation_query: str,
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
    initial_url = (
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}/transitiveMemberOf"
    )
    continuation_url = f"{initial_url}?{continuation_query}"
    principal["groupMembership"] = {
        "tenantId": _TENANT_ID,
        "method": "transitiveMemberOf",
        "pages": [
            {
                "requestUrl": initial_url,
                "statusCode": 200,
                "value": [],
                "@odata.nextLink": continuation_url,
            },
            {
                "requestUrl": continuation_url,
                "statusCode": 200,
                "value": [],
                "@odata.nextLink": None,
            },
        ],
    }

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "missing-target",
        "missing-subscription",
        "duplicate-target",
        "filtered-subscription",
        "unfiltered-target",
    ],
)
def test_guarded_rbac_requires_complete_deny_assignment_evidence(
    mutation: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    deny_assignments = principal["denyAssignments"]
    assert isinstance(deny_assignments, dict)
    collections = deny_assignments["collections"]
    assert isinstance(collections, list)
    if mutation == "missing":
        principal.pop("denyAssignments")
    elif mutation == "missing-target":
        collections[:] = [
            item
            for item in collections
            if isinstance(item, dict) and item["collectionType"] != "target-and-ancestors"
        ]
    elif mutation == "missing-subscription":
        collections[:] = [
            item
            for item in collections
            if isinstance(item, dict) and item["collectionType"] != "subscription-inventory"
        ]
    elif mutation == "duplicate-target":
        collections[1] = copy.deepcopy(collections[0])
    elif mutation == "filtered-subscription":
        subscription = _deny_assignment_collection(
            evidence,
            "subscription-inventory",
        )
        subscription["filter"] = "atScope()"
    else:
        assert mutation == "unfiltered-target"
        target = _deny_assignment_collection(
            evidence,
            "target-and-ancestors",
        )
        target.pop("filter")

    with pytest.raises(PreflightInputError, match="deny"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_requires_identical_deny_evidence_for_all_principals() -> None:
    first_principal_id = "11111111-1111-1111-1111-111111111111"
    second_principal_id = "22222222-2222-2222-2222-222222222222"
    assignments = [
        _guarded_assignment(
            principal_id=first_principal_id,
            role_name="AcrPull",
            scope=_RG_SCOPE,
        ),
        _guarded_assignment(
            principal_id=second_principal_id,
            role_name="Storage Blob Data Reader",
            scope=_RG_SCOPE,
        ),
    ]
    evidence = _guarded_evidence(assignments)
    principals = evidence["principals"]
    assert isinstance(principals, list)
    second_principal = principals[1]
    assert isinstance(second_principal, dict)
    deny_assignments = second_principal["denyAssignments"]
    assert isinstance(deny_assignments, dict)
    deny_assignments["syntheticMutation"] = True

    with pytest.raises(
        PreflightInputError,
        match="principals disagree on complete deny-assignment evidence",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                first_principal_id,
                second_principal_id,
                expected_assignments=assignments,
            ),
        )


def test_guarded_rbac_accepts_complete_paged_empty_deny_assignment_evidence() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    target = _deny_assignment_collection(
        evidence,
        "target-and-ancestors",
    )
    pages = target["pages"]
    assert isinstance(pages, list)
    first_page = pages[0]
    assert isinstance(first_page, dict)
    continuation_url = f"{first_page['requestUrl']}&%24skipToken=synthetic"
    first_page["nextLink"] = continuation_url
    pages.append(
        {
            "requestUrl": continuation_url,
            "statusCode": 200,
            "value": [],
            "nextLink": None,
        }
    )

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("continuation_query", "message"),
    [
        ("%24skipToken=", "requestUrl is not canonical"),
        ("%24skipToken=%20", "requestUrl is not canonical"),
        ("%24skiptoken=synthetic", "not canonical for this endpoint"),
        (
            "%24skipToken=synthetic&%24skipToken=duplicate",
            "duplicate decoded key",
        ),
    ],
)
def test_guarded_rbac_rejects_invalid_deny_assignment_cursors(
    continuation_query: str,
    message: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    target = _deny_assignment_collection(
        evidence,
        "target-and-ancestors",
    )
    pages = target["pages"]
    assert isinstance(pages, list)
    first_page = pages[0]
    assert isinstance(first_page, dict)
    continuation_url = f"{first_page['requestUrl']}&{continuation_query}"
    first_page["nextLink"] = continuation_url
    pages.append(
        {
            "requestUrl": continuation_url,
            "statusCode": 200,
            "value": [],
            "nextLink": None,
        }
    )

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_odata_next_link_in_deny_assignment_pages() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    target = _deny_assignment_collection(
        evidence,
        "target-and-ancestors",
    )
    pages = target["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page["@odata.nextLink"] = page.pop("nextLink")

    with pytest.raises(PreflightInputError, match="only the exact nextLink"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("deny_kind", "do_not_apply_to_child_scopes", "condition"),
    [
        ("direct", False, None),
        ("group", False, None),
        ("all-principals", False, None),
        ("direct", False, "@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'x'"),
    ],
)
def test_guarded_rbac_fails_when_deny_might_invalidate_approved_access(
    deny_kind: str,
    do_not_apply_to_child_scopes: bool,
    condition: str | None,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    group_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_id if deny_kind == "group" else principal_id,
        effective_principal_id=principal_id,
        principal_type="Group" if deny_kind == "group" else "ServicePrincipal",
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    if deny_kind == "group":
        principals = [(group_id, "Group")]
        deny_scope = _RG_SCOPE
    elif deny_kind == "all-principals":
        principals = [("00000000-0000-0000-0000-000000000000", "SystemDefined")]
        deny_scope = _RG_SCOPE
    else:
        principals = [(principal_id, "ServicePrincipal")]
        deny_scope = _RG_SCOPE if not do_not_apply_to_child_scopes else _SUBSCRIPTION_SCOPE
    deny = _raw_arm_deny_assignment(
        scope=deny_scope,
        principals=principals,
        do_not_apply_to_child_scopes=do_not_apply_to_child_scopes,
        condition=condition,
    )
    _add_deny_assignment(
        evidence,
        deny,
        target_and_ancestors=True,
        subscription_inventory=True,
    )

    expected_message = "with a condition" if condition is not None else "may invalidate"
    with pytest.raises(PreflightInputError, match=expected_message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    "exclusion_kind",
    ["principal", "group"],
)
def test_guarded_rbac_honors_all_principals_exclusion(
    exclusion_kind: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    group_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_id if exclusion_kind == "group" else principal_id,
        effective_principal_id=principal_id,
        principal_type="Group" if exclusion_kind == "group" else "ServicePrincipal",
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    exclusion = (
        (group_id, "Group") if exclusion_kind == "group" else (principal_id, "ServicePrincipal")
    )
    deny = _raw_arm_deny_assignment(
        principals=[("00000000-0000-0000-0000-000000000000", "SystemDefined")],
        exclude_principals=[exclusion],
    )
    _add_deny_assignment(
        evidence,
        deny,
        target_and_ancestors=True,
        subscription_inventory=True,
    )

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
    )


def test_guarded_rbac_honors_non_inherited_and_unrelated_denies() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    non_inherited = _raw_arm_deny_assignment(
        scope=_SUBSCRIPTION_SCOPE,
        principals=[(principal_id, "ServicePrincipal")],
        do_not_apply_to_child_scopes=True,
    )
    unrelated_principal = _raw_arm_deny_assignment(
        principals=[("33333333-3333-3333-3333-333333333333", "ServicePrincipal")],
        index=1,
    )
    unrelated_scope = _raw_arm_deny_assignment(
        scope=_SIBLING_RG_SCOPE,
        principals=[(principal_id, "ServicePrincipal")],
        index=2,
    )
    _add_deny_assignment(
        evidence,
        non_inherited,
        target_and_ancestors=True,
        subscription_inventory=True,
    )
    _add_deny_assignment(
        evidence,
        unrelated_principal,
        target_and_ancestors=True,
        subscription_inventory=True,
    )
    _add_deny_assignment(
        evidence,
        unrelated_scope,
        target_and_ancestors=False,
        subscription_inventory=True,
    )

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("evidence_kind", "query_suffix", "message"),
    [
        (
            "arm",
            "&%24skipToken=synthetic",
            "not canonical",
        ),
        (
            "arm",
            "&tenantId=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "not canonical for this endpoint",
        ),
        (
            "graph",
            "?%24skiptoken=synthetic",
            "must be unfiltered",
        ),
        (
            "graph",
            "?%24filter=securityEnabled%20eq%20true",
            "not canonical for this endpoint",
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


def test_guarded_rbac_rejects_percent_encoded_kelvin_url_alias() -> None:
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
    page["requestUrl"] = str(page["requestUrl"]).replace(
        "workload",
        "wor%E2%84%AAload",
    )

    with pytest.raises(PreflightInputError, match="non-ASCII"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    ("query_suffix", "message"),
    [
        ("&%61pi-version=2022-04-01", "duplicate decoded key"),
        ("&API-VERSION=2022-04-01", "duplicate decoded key"),
        ("&%24filter=duplicate", "duplicate decoded key"),
    ],
)
def test_guarded_rbac_rejects_query_key_aliases(
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
    role_assignments = principal["roleAssignments"]
    assert isinstance(role_assignments, dict)
    ancestors = role_assignments["ancestors"]
    assert isinstance(ancestors, dict)
    pages = ancestors["pages"]
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


def test_guarded_rbac_accepts_official_management_group_subscription_shape() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])

    assert _management_group_subscription_properties(evidence) == {
        "displayName": "Synthetic Workload Subscription",
        "parent": {"id": _MG_LEAF_SCOPE},
        "state": "Active",
        "tenant": _TENANT_ID,
    }
    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("mismatch", "crosses tenants"),
        ("case-alias", "literal tenant key"),
        ("legacy-tenant-id", "literal tenant key"),
        ("case-collision", "case-insensitive key collision"),
        ("legacy-conflict", "literal tenant key"),
    ],
)
def test_guarded_rbac_rejects_invalid_management_group_subscription_tenant(
    mutation: str,
    message: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    properties = _management_group_subscription_properties(evidence)
    if mutation == "mismatch":
        properties["tenant"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    elif mutation == "case-alias":
        properties["Tenant"] = properties.pop("tenant")
    elif mutation == "legacy-tenant-id":
        properties["tenantId"] = properties.pop("tenant")
    elif mutation == "case-collision":
        properties["Tenant"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    else:
        assert mutation == "legacy-conflict"
        properties["tenantId"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    with pytest.raises(PreflightInputError, match=message):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_json_parser_rejects_duplicate_literal_subscription_tenant(tmp_path) -> None:
    artifact = tmp_path / "duplicate-tenant.json"
    artifact.write_text(
        (
            '{"properties":{"tenant":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",'
            '"tenant":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}'
        ),
        encoding="utf-8",
    )

    with pytest.raises(PreflightInputError, match="duplicate key"):
        load_json_file(artifact)


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
        ("resultTruncated", "False", "explicitly non-truncated"),
        ("resultTruncated", "FALSE", "explicitly non-truncated"),
        ("resultTruncated", " false", "explicitly non-truncated"),
        ("resultTruncated", "false ", "explicitly non-truncated"),
        ("resultTruncated", "true", "explicitly non-truncated"),
        ("resultTruncated", "0", "explicitly non-truncated"),
        ("resultTruncated", 0, "explicitly non-truncated"),
        ("resultTruncated", Decimal("0.0"), "explicitly non-truncated"),
        ("resultTruncated", 1, "explicitly non-truncated"),
        ("resultTruncated", [], "explicitly non-truncated"),
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


def test_guarded_rbac_requires_resource_graph_truncation_marker() -> None:
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
    body.pop("resultTruncated")

    with pytest.raises(PreflightInputError, match="explicitly non-truncated"):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_accepts_resource_graph_string_false_transport() -> None:
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
    body["resultTruncated"] = "false"

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )
        == ()
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


@pytest.mark.parametrize("reverse_principals", [False, True])
def test_guarded_rbac_rejects_tenant_wide_identity_membership_type_conflict(
    reverse_principals: bool,
) -> None:
    first_principal_id = "11111111-1111-1111-1111-111111111111"
    second_principal_id = "22222222-2222-2222-2222-222222222222"
    assignments = [
        _guarded_assignment(
            principal_id=first_principal_id,
            role_name="AcrPull",
            scope=_RG_SCOPE,
        ),
        _guarded_assignment(
            principal_id=second_principal_id,
            role_name="Storage Blob Data Reader",
            scope=_RG_SCOPE,
        ),
    ]
    evidence = _guarded_evidence(assignments)
    principals = evidence["principals"]
    assert isinstance(principals, list)
    first_principal = principals[0]
    assert isinstance(first_principal, dict)
    membership = first_principal["groupMembership"]
    assert isinstance(membership, dict)
    pages = membership["pages"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    values = page["value"]
    assert isinstance(values, list)
    values.append(second_principal_id)
    if reverse_principals:
        principals.reverse()

    with pytest.raises(
        PreflightInputError,
        match="tenant-wide principal type",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                first_principal_id,
                second_principal_id,
                expected_assignments=assignments,
            ),
        )


@pytest.mark.parametrize(
    "claim_source",
    [
        "role-assignment",
        "deny-principal",
        "deny-exclusion",
        "transitive-membership",
    ],
)
def test_guarded_rbac_rejects_tenant_wide_principal_type_conflicts(
    claim_source: str,
) -> None:
    effective_principal_id = "11111111-1111-1111-1111-111111111111"
    group_principal_id = "22222222-2222-2222-2222-222222222222"
    assignment = _guarded_assignment(
        principal_id=group_principal_id,
        effective_principal_id=effective_principal_id,
        principal_type="Group",
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    if claim_source == "role-assignment":
        pages = _arm_role_assignment_pages(
            evidence,
            collection_kind="ancestors",
        )
        page = pages[0]
        assert isinstance(page, dict)
        values = page["value"]
        assert isinstance(values, list)
        raw_assignment = values[0]
        assert isinstance(raw_assignment, dict)
        properties = raw_assignment["properties"]
        assert isinstance(properties, dict)
        properties["principalType"] = "ServicePrincipal"
    elif claim_source in {"deny-principal", "deny-exclusion"}:
        deny = _raw_arm_deny_assignment(
            principals=(
                [(group_principal_id, "User")]
                if claim_source == "deny-principal"
                else [("00000000-0000-0000-0000-000000000000", "SystemDefined")]
            ),
            exclude_principals=(
                [(group_principal_id, "User")] if claim_source == "deny-exclusion" else []
            ),
        )
        _add_deny_assignment(
            evidence,
            deny,
            target_and_ancestors=True,
            subscription_inventory=True,
        )
    else:
        principal["groupMembership"] = {
            "tenantId": _TENANT_ID,
            "method": "transitiveMemberOf",
            "pages": [
                {
                    "requestUrl": (
                        "https://graph.microsoft.com/v1.0/servicePrincipals/"
                        f"{effective_principal_id}/transitiveMemberOf"
                    ),
                    "statusCode": 200,
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.user",
                            "id": group_principal_id,
                        }
                    ],
                    "@odata.nextLink": None,
                }
            ],
        }

    with pytest.raises(
        PreflightInputError,
        match="tenant-wide principal type",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                effective_principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_principal_type_conflict_across_deny_pages() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    unrelated_principal_id = "33333333-3333-3333-3333-333333333333"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    group_deny = _raw_arm_deny_assignment(
        principals=[(unrelated_principal_id, "Group")],
        index=1,
    )
    user_deny = _raw_arm_deny_assignment(
        principals=[(unrelated_principal_id, "User")],
        index=2,
    )
    target_collection = _deny_assignment_collection(
        evidence,
        "target-and-ancestors",
    )
    target_pages = target_collection["pages"]
    assert isinstance(target_pages, list)
    target_page = target_pages[0]
    assert isinstance(target_page, dict)
    continuation_url = f"{target_page['requestUrl']}&%24skipToken=principal-type-conflict"
    target_page["value"] = [group_deny]
    target_page["nextLink"] = continuation_url
    target_pages.append(
        {
            "requestUrl": continuation_url,
            "statusCode": 200,
            "value": [user_deny],
            "nextLink": None,
        }
    )

    with pytest.raises(
        PreflightInputError,
        match="tenant-wide principal type",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_rejects_unknown_graph_type_conflict_across_pages() -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    conflicting_principal_id = "33333333-3333-3333-3333-333333333333"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    principal = _first_principal_artifact(evidence)
    initial_url = (
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}/transitiveMemberOf"
    )
    continuation_url = f"{initial_url}?%24skiptoken=synthetic-types"
    principal["groupMembership"] = {
        "tenantId": _TENANT_ID,
        "method": "transitiveMemberOf",
        "pages": [
            {
                "requestUrl": initial_url,
                "statusCode": 200,
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.directoryRole",
                        "id": conflicting_principal_id,
                    }
                ],
                "@odata.nextLink": continuation_url,
            },
            {
                "requestUrl": continuation_url,
                "statusCode": 200,
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.group",
                        "id": conflicting_principal_id,
                        "securityEnabled": True,
                    }
                ],
                "@odata.nextLink": None,
            },
        ],
    }

    with pytest.raises(
        PreflightInputError,
        match="tenant-wide principal type",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


@pytest.mark.parametrize(
    "conflict_field",
    [
        "condition",
        "principal",
        "principal-type",
        "role",
        "scope",
    ],
)
@pytest.mark.parametrize("conflict_location", ["collection", "page"])
def test_guarded_rbac_rejects_conflicting_raw_body_for_one_assignment_id(
    conflict_location: str,
    conflict_field: str,
) -> None:
    principal_id = "11111111-1111-1111-1111-111111111111"
    assignment = _guarded_assignment(
        principal_id=principal_id,
        role_name="AcrPull",
        scope=_RG_SCOPE,
    )
    evidence = _guarded_evidence([assignment])
    ancestor_pages = _arm_role_assignment_pages(
        evidence,
        collection_kind="ancestors",
    )
    ancestor_page = ancestor_pages[0]
    assert isinstance(ancestor_page, dict)
    ancestor_values = ancestor_page["value"]
    assert isinstance(ancestor_values, list)
    conflicting_assignment = copy.deepcopy(ancestor_values[0])
    assert isinstance(conflicting_assignment, dict)
    conflicting_properties = conflicting_assignment["properties"]
    assert isinstance(conflicting_properties, dict)
    if conflict_field == "condition":
        conflicting_properties["condition"] = (
            "@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'synthetic'"
        )
        conflicting_properties["conditionVersion"] = "2.0"
    elif conflict_field == "principal":
        conflicting_properties["principalId"] = "33333333-3333-3333-3333-333333333333"
    elif conflict_field == "principal-type":
        conflicting_properties["principalType"] = "Group"
    elif conflict_field == "role":
        conflicting_properties["roleDefinitionId"] = _TEST_ROLE_IDS["reader"]
    else:
        assert conflict_field == "scope"
        conflicting_properties["scope"] = _SUBSCRIPTION_SCOPE
    if conflict_location == "page":
        continuation_url = f"{ancestor_page['requestUrl']}&%24skipToken=synthetic-conflict"
        ancestor_page["nextLink"] = continuation_url
        ancestor_pages.append(
            {
                "requestUrl": continuation_url,
                "statusCode": 200,
                "value": [conflicting_assignment],
                "nextLink": None,
            }
        )
    else:
        descendant_pages = _arm_role_assignment_pages(
            evidence,
            collection_kind="descendants",
        )
        descendant_page = descendant_pages[0]
        assert isinstance(descendant_page, dict)
        descendant_page["value"] = [conflicting_assignment]

    with pytest.raises(
        PreflightInputError,
        match="conflicting raw assignment bodies|id and properties.scope disagree",
    ):
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                principal_id,
                expected_assignments=[assignment],
            ),
        )


def test_guarded_rbac_allows_identical_group_assignment_id_for_multiple_effective_principals() -> (
    None
):
    first_principal_id = "11111111-1111-1111-1111-111111111111"
    second_principal_id = "22222222-2222-2222-2222-222222222222"
    group_principal_id = "33333333-3333-3333-3333-333333333333"
    assignments = [
        _guarded_assignment(
            principal_id=group_principal_id,
            effective_principal_id=first_principal_id,
            principal_type="Group",
            role_name="AcrPull",
            scope=_RG_SCOPE,
        ),
        _guarded_assignment(
            principal_id=group_principal_id,
            effective_principal_id=second_principal_id,
            principal_type="Group",
            role_name="AcrPull",
            scope=_RG_SCOPE,
        ),
    ]
    evidence = _guarded_evidence(assignments)
    principals = evidence["principals"]
    assert isinstance(principals, list)

    def raw_assignments(principal: dict[str, object]) -> list[dict[str, object]]:
        role_assignments = principal["roleAssignments"]
        assert isinstance(role_assignments, dict)
        ancestors = role_assignments["ancestors"]
        assert isinstance(ancestors, dict)
        descendants = role_assignments["descendants"]
        assert isinstance(descendants, dict)
        raw_values: list[dict[str, object]] = []
        collections = [ancestors, *descendants["collections"]]
        for collection in collections:
            assert isinstance(collection, dict)
            pages = collection["pages"]
            assert isinstance(pages, list)
            for page in pages:
                assert isinstance(page, dict)
                values = page["value"]
                assert isinstance(values, list)
                for raw_assignment in values:
                    assert isinstance(raw_assignment, dict)
                    raw_values.append(raw_assignment)
        return raw_values

    first_principal = principals[0]
    second_principal = principals[1]
    assert isinstance(first_principal, dict)
    assert isinstance(second_principal, dict)
    first_raw_assignments = raw_assignments(first_principal)
    canonical_assignment_id = first_raw_assignments[0]["id"]
    for raw_assignment in raw_assignments(second_principal):
        raw_assignment["id"] = canonical_assignment_id

    assert (
        _evaluate_guarded_rbac(
            evidence,
            _production_policy(
                first_principal_id,
                second_principal_id,
                expected_assignments=assignments,
            ),
        )
        == ()
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
            "--ſubscription",
            _SUBSCRIPTION_ID,
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
            "--include-Groups",
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
            "--OUTPUT",
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
            "JSON",
        ],
        [
            " --subscription ",
            _SUBSCRIPTION_ID,
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
            " json ",
        ],
        [
            "--subscription",
            _SUBSCRIPTION_ID,
            "--assignee-object-id",
            principal_id,
            "--include-groups",
            "--all",
            "--output",
            "-json",
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
