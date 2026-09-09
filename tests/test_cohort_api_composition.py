from __future__ import annotations

import sys
from types import ModuleType
from typing import cast

import pytest
from fastapi.testclient import TestClient

import athena_context.api.cohort_production as cohort_production
from athena_context.api.authorization import StaticTestAuthenticator
from athena_context.api.cohort_composition import (
    CohortApplicationServices,
    create_cohort_application,
    load_configured_cohort_application,
)
from athena_context.api.cohort_production import (
    CohortProductionPorts,
    create_production_cohort_services,
    load_cohort_production_ports,
)
from athena_context.api.service import ContextService
from test_context_api_cohorts import HUMAN, TOKENS, _build_harness, _verified


def _services() -> CohortApplicationServices:
    harness = _build_harness()
    return CohortApplicationServices(
        lifecycle_service=harness.lifecycle,
        proposal_service=harness.cohorts,
        decision_service=harness.decisions,
        authentication=StaticTestAuthenticator(
            {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
        ),
    )


def test_explicit_cohort_application_registers_the_complete_route_set() -> None:
    schema = TestClient(create_cohort_application(_services())).get(
        "/openapi.json"
    ).json()

    assert "/v1/cohort-proposals" in schema["paths"]
    assert "/v1/cohort-proposals/preview" in schema["paths"]
    assert "/v1/cohort-proposals/decisions" in schema["paths"]
    assert "/v1/drafts" not in schema["paths"]
    assert not any(
        path.startswith("/v1/manifests/")
        for path in schema["paths"]
    )


def test_configured_cohort_factory_is_required_and_type_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ATHENA_COHORT_SERVICE_FACTORY", raising=False)
    with pytest.raises(RuntimeError, match="must name"):
        load_configured_cohort_application()

    module = ModuleType("athena_context.synthetic_cohort_factory")
    module.build = _services  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv(
        "ATHENA_COHORT_SERVICE_FACTORY",
        f"{module.__name__}:build",
    )

    app = load_configured_cohort_application()
    assert "/v1/cohort-proposals" in app.openapi()["paths"]


def test_cohort_application_rejects_missing_runtime_dependencies() -> None:
    services = _services()
    invalid = CohortApplicationServices(
        lifecycle_service=cast(ContextService, None),
        proposal_service=services.proposal_service,
        decision_service=services.decision_service,
        authentication=services.authentication,
    )

    with pytest.raises(RuntimeError, match="complete explicit"):
        create_cohort_application(invalid)


def test_repository_owned_production_factory_composes_shared_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness()

    class DurablePersistence:
        persistence_identity = object()

        def __getattr__(self, name: str):
            return getattr(harness.persistence, name)

    class DurableSnapshots:
        persistence_identity = object()

        def get_snapshot(self, binding):
            return harness.snapshots.get_snapshot(binding)

    class TrustedVerifier:
        trust_identity = object()

        def verify(self, snapshot, *, as_of):
            return harness.verifier(snapshot, as_of)

    ports = CohortProductionPorts(
        snapshot_repository=DurableSnapshots(),
        snapshot_verifier=TrustedVerifier(),
        persistence=DurablePersistence(),
    )
    module = ModuleType("athena_context.synthetic_cohort_ports")
    module.build = lambda: ports  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv(
        "ATHENA_COHORT_PORTS_FACTORY",
        f"{module.__name__}:build",
    )
    assert load_cohort_production_ports() is ports

    monkeypatch.setattr(
        cohort_production,
        "configured_workload_id",
        lambda: harness.manifest.manifest_id,
    )
    monkeypatch.setattr(
        cohort_production,
        "create_configured_context_store",
        lambda *, workload_id: harness.store,
    )
    monkeypatch.setattr(
        cohort_production,
        "deployment_role_grants",
        lambda *, workload_id: harness.authorization._grants,
    )
    monkeypatch.setattr(
        cohort_production,
        "required_environment",
        lambda name: {
            "ATHENA_CONTEXT_AUTH_TENANT_ID": (
                "11111111-1111-1111-1111-111111111111"
            ),
            "ATHENA_CONTEXT_AUTH_AUDIENCE": "api://athena-context",
            "ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE": "Athena.Context.Access",
        }[name],
    )
    monkeypatch.setattr(
        cohort_production,
        "EntraJwtAuthenticator",
        lambda **_kwargs: StaticTestAuthenticator(
            {TOKENS[HUMAN.actor_id]: _verified(HUMAN)}
        ),
    )
    monkeypatch.setattr(
        cohort_production,
        "load_cohort_production_ports",
        lambda: ports,
    )

    services = create_production_cohort_services()

    assert services.lifecycle_service.persistence_store is harness.store
    assert services.proposal_service.context_store is harness.store
    assert services.decision_service.context_service is (
        services.lifecycle_service
    )
