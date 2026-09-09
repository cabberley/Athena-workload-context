from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from fastapi import FastAPI

from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.cohort_service import CohortProposalService
from athena_context.api.http import create_app
from athena_context.api.ports import AuthenticationPort
from athena_context.api.service import ContextService

_FACTORY_PATTERN = re.compile(
    r"^athena_context(?:\.[A-Za-z_][A-Za-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*$"
)


@dataclass(frozen=True, slots=True)
class CohortApplicationServices:
    lifecycle_service: ContextService
    proposal_service: CohortProposalService
    decision_service: CohortDecisionService
    authentication: AuthenticationPort


def create_cohort_application(
    services: CohortApplicationServices,
) -> FastAPI:
    """Compose only an explicitly supplied, internally shared cohort graph."""

    if (
        not isinstance(services.lifecycle_service, ContextService)
        or not isinstance(services.proposal_service, CohortProposalService)
        or not isinstance(services.decision_service, CohortDecisionService)
        or not callable(
            getattr(services.authentication, "authenticate_bearer", None)
        )
    ):
        raise RuntimeError(
            "cohort application requires complete explicit production services"
        )
    application = create_app(
        service=services.lifecycle_service,
        authentication=services.authentication,
        cohort_service=services.proposal_service,
        cohort_decision_service=services.decision_service,
    )
    allowed_paths = {
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }
    def include_route(route: object) -> bool:
        path = getattr(route, "path", "")
        if path in allowed_paths or path.startswith("/v1/cohort-proposals"):
            return True
        original_router = getattr(route, "original_router", None)
        nested_routes = getattr(original_router, "routes", ())
        nested_paths = [
            getattr(candidate, "path", "")
            for candidate in nested_routes
        ]
        return bool(nested_paths) and all(
            nested_path.startswith("/v1/cohort-proposals")
            for nested_path in nested_paths
        )

    application.router.routes = [
        route for route in application.router.routes if include_route(route)
    ]
    application.openapi_schema = None
    if "/v1/cohort-proposals" not in application.openapi()["paths"]:
        raise RuntimeError("cohort application did not register its required routes")
    return application


def load_configured_cohort_application() -> FastAPI:
    """Load a deployment-owned factory from the installed Athena package."""

    factory_reference = os.environ.get("ATHENA_COHORT_SERVICE_FACTORY", "")
    if _FACTORY_PATTERN.fullmatch(factory_reference) is None:
        raise RuntimeError(
            "ATHENA_COHORT_SERVICE_FACTORY must name an installed "
            "athena_context module factory"
        )
    module_name, function_name = factory_reference.split(":", 1)
    try:
        module = importlib.import_module(module_name)
        factory = cast(
            Callable[[], object],
            getattr(module, function_name),
        )
        services = factory()
    except (AttributeError, ImportError, TypeError) as exc:
        raise RuntimeError("configured cohort service factory could not be loaded") from exc
    if type(services) is not CohortApplicationServices:
        raise RuntimeError(
            "configured cohort service factory returned an invalid dependency graph"
        )
    return create_cohort_application(services)


__all__ = [
    "CohortApplicationServices",
    "create_cohort_application",
    "load_configured_cohort_application",
]
