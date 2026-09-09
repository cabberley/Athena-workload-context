"""ASGI composition root for the authoritative Athena Context API."""

import os

from fastapi import FastAPI

from athena_context.api.authorization import EntraJwtAuthenticator, RoleBasedAuthorization
from athena_context.api.domain import RoleGrant
from athena_context.api.http import create_app
from athena_context.api.production import (
    configured_workload_id,
    create_configured_context_store,
    deployment_role_grants,
    required_environment,
)


def _deployment_role_grants(
    *,
    workload_id: str,
) -> tuple[RoleGrant, ...]:
    return deployment_role_grants(workload_id=workload_id)


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
