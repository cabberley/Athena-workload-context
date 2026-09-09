from __future__ import annotations

import json
import os
from collections.abc import Iterable

from pydantic import ValidationError

from athena_context.api.domain import (
    RoleGrant,
    WorkloadGrantScope,
)
from athena_context.api.durable import AzureTableContextStore

_MAX_ROLE_GRANTS_CONFIGURATION_BYTES = 16 * 1024
_MAX_ROLE_GRANTS = 64


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise RuntimeError(f"{name} must be configured for the Context API")
    return value


def configured_workload_id() -> str:
    value = required_environment("ATHENA_CONTEXT_STORE_WORKLOAD_ID")
    try:
        return WorkloadGrantScope(workload_id=value).workload_id
    except ValidationError as exc:
        raise RuntimeError(
            "ATHENA_CONTEXT_STORE_WORKLOAD_ID must be a concrete route-safe "
            "workload identifier"
        ) from exc


def _reject_duplicate_json_keys(
    pairs: Iterable[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def deployment_role_grants(
    *,
    workload_id: str,
) -> tuple[RoleGrant, ...]:
    raw = required_environment("ATHENA_CONTEXT_ROLE_GRANTS_JSON")
    if len(raw.encode("utf-8")) > _MAX_ROLE_GRANTS_CONFIGURATION_BYTES:
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON exceeds its safe bound"
        )
    try:
        configured = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON is invalid JSON"
        ) from exc
    if (
        type(configured) is not list
        or not configured
        or len(configured) > _MAX_ROLE_GRANTS
        or any(type(item) is not dict for item in configured)
    ):
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON must be a bounded "
            "non-empty grant array"
        )
    try:
        grants = tuple(
            RoleGrant.model_validate_json(json.dumps(item))
            for item in configured
        )
    except ValidationError as exc:
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON contains an invalid grant"
        ) from exc
    identities: set[tuple[str, object, str]] = set()
    for grant in grants:
        scope = grant.scope
        if (
            not isinstance(scope, WorkloadGrantScope)
            or scope.workload_id != workload_id
        ):
            raise RuntimeError(
                "ATHENA_CONTEXT_ROLE_GRANTS_JSON requires exact "
                "configured-workload grants"
            )
        identities.add((grant.actor_id, grant.role, scope.workload_id))
    if len(identities) != len(grants):
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON contains duplicate grants"
        )
    return grants


def create_configured_context_store(
    *,
    workload_id: str,
    allow_empty_partition_bootstrap: bool = False,
) -> AzureTableContextStore:
    return AzureTableContextStore(
        endpoint=required_environment("ATHENA_CONTEXT_STORE_ENDPOINT"),
        table_name=required_environment("ATHENA_CONTEXT_STORE_TABLE_NAME"),
        partition_key=required_environment("ATHENA_CONTEXT_STORE_PARTITION_KEY"),
        managed_identity_client_id=required_environment(
            "ATHENA_CONTEXT_IDENTITY_CLIENT_ID"
        ),
        workload_id=workload_id,
        allow_empty_partition_bootstrap=allow_empty_partition_bootstrap,
    )
