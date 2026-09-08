"""ASGI composition root for the authoritative Athena Context API."""

import json
import os
from collections.abc import Iterable

from fastapi import FastAPI
from pydantic import ValidationError

from athena_context.api.authorization import EntraJwtAuthenticator, RoleBasedAuthorization
from athena_context.api.domain import RoleGrant, WorkloadGrantScope
from athena_context.api.http import create_app
from athena_context.api.production import (
    configured_workload_id,
    create_configured_context_store,
    required_environment,
)

_MAX_ROLE_GRANTS_CONFIGURATION_BYTES = 16 * 1024
_MAX_ROLE_GRANTS = 64


def _reject_duplicate_json_keys(
    pairs: Iterable[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _deployment_role_grants(
    *,
    workload_id: str,
) -> tuple[RoleGrant, ...]:
    raw = required_environment("ATHENA_CONTEXT_ROLE_GRANTS_JSON")
    if len(raw.encode("utf-8")) > _MAX_ROLE_GRANTS_CONFIGURATION_BYTES:
        raise RuntimeError("ATHENA_CONTEXT_ROLE_GRANTS_JSON exceeds its safe bound")
    try:
        configured = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("ATHENA_CONTEXT_ROLE_GRANTS_JSON is invalid JSON") from exc
    if (
        type(configured) is not list
        or not configured
        or len(configured) > _MAX_ROLE_GRANTS
        or any(type(item) is not dict for item in configured)
    ):
        raise RuntimeError(
            "ATHENA_CONTEXT_ROLE_GRANTS_JSON must be a bounded non-empty grant array"
        )
    try:
        grants = tuple(
            RoleGrant.model_validate_json(json.dumps(item))
            for item in configured
        )
    except ValidationError as exc:
        raise RuntimeError("ATHENA_CONTEXT_ROLE_GRANTS_JSON contains an invalid grant") from exc
    identities: set[tuple[str, object, str]] = set()
    for grant in grants:
        scope = grant.scope
        if not isinstance(scope, WorkloadGrantScope) or scope.workload_id != workload_id:
            raise RuntimeError(
                "ATHENA_CONTEXT_ROLE_GRANTS_JSON requires exact configured-workload grants"
            )
        identities.add((grant.actor_id, grant.role, scope.workload_id))
    if len(identities) != len(grants):
        raise RuntimeError("ATHENA_CONTEXT_ROLE_GRANTS_JSON contains duplicate grants")
    return grants


def create_production_app() -> FastAPI:
    """Build the production API only with its durable, managed-identity store."""

    if "ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED" in os.environ:
        raise RuntimeError(
            "ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED is not supported by API startup; "
            "run apps/context-api/bootstrap.py as a one-shot deployment step"
        )
    workload_id = configured_workload_id()
    authenticator = EntraJwtAuthenticator(
        tenant_id=required_environment("ATHENA_CONTEXT_AUTH_TENANT_ID"),
        audience=required_environment("ATHENA_CONTEXT_AUTH_AUDIENCE"),
        delegated_scope=required_environment(
            "ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE"
        ),
    )
    authorization = RoleBasedAuthorization(
        _deployment_role_grants(workload_id=workload_id)
    )
    store = create_configured_context_store(
        workload_id=workload_id,
    )
    with store.transaction():
        pass
    return create_app(
        store=store,
        authentication=authenticator,
        authorization=authorization,
    )


app = create_production_app()

__all__ = ["app", "create_production_app"]
