from __future__ import annotations

import importlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from athena_context.api.authorization import (
    EntraJwtAuthenticator,
    RoleBasedAuthorization,
)
from athena_context.api.cohort_composition import CohortApplicationServices
from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.cohort_memory import (
    EmptyEvidenceSnapshotRepository,
    InMemoryCohortPersistence,
    InMemoryEvidenceSnapshotRepository,
    RejectingTrustedEvidenceSnapshotVerifier,
)
from athena_context.api.cohort_ports import (
    CohortCandidateRepositoryPort,
    CohortPreviewReceiptPort,
    CohortProposalCachePort,
    EvidenceSnapshotRepositoryPort,
    TrustedEvidenceSnapshotVerifierPort,
)
from athena_context.api.cohort_service import CohortProposalService
from athena_context.api.domain import Actor, ActorKind
from athena_context.api.production import (
    configured_workload_id,
    create_configured_context_store,
    deployment_role_grants,
    required_environment,
)
from athena_context.api.service import ContextService

_FACTORY_PATTERN = re.compile(
    r"^athena_context(?:\.[A-Za-z_][A-Za-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*$"
)


class DurableCohortPersistencePort(
    CohortProposalCachePort,
    CohortPreviewReceiptPort,
    CohortCandidateRepositoryPort,
    Protocol,
):
    @property
    def persistence_identity(self) -> object: ...


class DurableEvidenceSnapshotRepositoryPort(
    EvidenceSnapshotRepositoryPort,
    Protocol,
):
    @property
    def persistence_identity(self) -> object: ...


class ProductionSnapshotVerifierPort(
    TrustedEvidenceSnapshotVerifierPort,
    Protocol,
):
    @property
    def trust_identity(self) -> object: ...


@dataclass(frozen=True, slots=True)
class CohortProductionPorts:
    snapshot_repository: DurableEvidenceSnapshotRepositoryPort
    snapshot_verifier: ProductionSnapshotVerifierPort
    persistence: DurableCohortPersistencePort


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(tz=UTC)


def _require_methods(value: object, *names: str) -> None:
    if any(not callable(getattr(value, name, None)) for name in names):
        raise RuntimeError(
            "cohort production ports are missing required operations"
        )


def load_cohort_production_ports() -> CohortProductionPorts:
    reference = required_environment("ATHENA_COHORT_PORTS_FACTORY")
    if _FACTORY_PATTERN.fullmatch(reference) is None:
        raise RuntimeError(
            "ATHENA_COHORT_PORTS_FACTORY must name an installed "
            "athena_context module factory"
        )
    module_name, function_name = reference.split(":", 1)
    try:
        module = importlib.import_module(module_name)
        factory = cast(Callable[[], object], getattr(module, function_name))
        ports = factory()
    except (AttributeError, ImportError, TypeError) as exc:
        raise RuntimeError(
            "configured cohort production ports could not be loaded"
        ) from exc
    if type(ports) is not CohortProductionPorts:
        raise RuntimeError(
            "configured cohort production ports returned an invalid graph"
        )
    if isinstance(
        ports.persistence,
        InMemoryCohortPersistence,
    ) or isinstance(
        ports.snapshot_repository,
        (EmptyEvidenceSnapshotRepository, InMemoryEvidenceSnapshotRepository),
    ) or isinstance(
        ports.snapshot_verifier,
        RejectingTrustedEvidenceSnapshotVerifier,
    ):
        raise RuntimeError(
            "cohort production ports cannot use test or rejecting adapters"
        )
    _require_methods(
        ports.persistence,
        "get_batch",
        "put_batch_if_absent",
        "get_preview_receipt",
        "put_preview_receipt_if_absent",
        "get_candidate",
    )
    _require_methods(ports.snapshot_repository, "get_snapshot")
    _require_methods(ports.snapshot_verifier, "verify")
    if (
        getattr(ports.persistence, "persistence_identity", None) is None
        or getattr(
            ports.snapshot_repository,
            "persistence_identity",
            None,
        )
        is None
        or getattr(ports.snapshot_verifier, "trust_identity", None) is None
    ):
        raise RuntimeError(
            "cohort production ports require durable and trust identities"
        )
    return ports


def create_production_cohort_services() -> CohortApplicationServices:
    workload_id = configured_workload_id()
    authentication = EntraJwtAuthenticator(
        tenant_id=required_environment("ATHENA_CONTEXT_AUTH_TENANT_ID"),
        audience=required_environment("ATHENA_CONTEXT_AUTH_AUDIENCE"),
        delegated_scope=required_environment(
            "ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE"
        ),
    )
    authorization = RoleBasedAuthorization(
        deployment_role_grants(workload_id=workload_id)
    )
    store = create_configured_context_store(workload_id=workload_id)
    with store.transaction():
        pass
    clock = _SystemClock()
    lifecycle = ContextService(
        store=store,
        authorization=authorization,
        clock=clock,
        publication_actor=Actor(
            actor_id="athena-context-api",
            kind=ActorKind.SERVICE,
        ),
    )
    ports = load_cohort_production_ports()
    proposal = CohortProposalService(
        context_store=store,
        authorization=authorization,
        clock=clock,
        snapshot_repository=ports.snapshot_repository,
        snapshot_verifier=ports.snapshot_verifier,
        proposal_cache=ports.persistence,
        preview_receipts=ports.persistence,
    )
    decision = CohortDecisionService(
        store=store,
        authorization=authorization,
        clock=clock,
        context_service=lifecycle,
        proposal_service=proposal,
        candidate_repository=ports.persistence,
    )
    return CohortApplicationServices(
        lifecycle_service=lifecycle,
        proposal_service=proposal,
        decision_service=decision,
        authentication=authentication,
    )


__all__ = [
    "CohortProductionPorts",
    "create_production_cohort_services",
    "load_cohort_production_ports",
]
