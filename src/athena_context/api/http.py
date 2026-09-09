from __future__ import annotations

from datetime import UTC, datetime
from time import time_ns
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Depends, FastAPI, Header, Path, Query, Request, status
from fastapi.responses import JSONResponse

from athena_context.api.authorization import (
    RejectUnverifiedAuthentication,
    RoleBasedAuthorization,
)
from athena_context.api.cohort_decision_domain import (
    CohortDecisionRequest,
    CohortDecisionResponse,
    decision_response,
)
from athena_context.api.cohort_decision_service import CohortDecisionService
from athena_context.api.cohort_domain import (
    CohortDraftBinding,
    CohortProposalBatchResponse,
    CohortProposalQuery,
    CohortReviewCandidate,
    CohortReviewPreviewRequest,
    ProfileType,
)
from athena_context.api.cohort_ports import ExplicitWorkloadAuthorizationPort
from athena_context.api.cohort_service import CohortProposalService
from athena_context.api.domain import (
    Actor,
    ActorKind,
    ApiModel,
    ApproveCommand,
    AuditEvent,
    CreateDraftCommand,
    DraftRecord,
    DraftState,
    PublishCommand,
    PublishedManifest,
    PublishedManifestView,
    ReplaceDraftCommand,
    ResolvedProfileAuthority,
    ReviewCommand,
    SupersedeCommand,
    Supersession,
    TransitionCommand,
    VersionComparison,
    WorkloadIdentifier,
)
from athena_context.api.errors import (
    AuthenticationError,
    AuthorizationError,
    CohortBoundaryError,
    ContextApiError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    ManifestValidationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    CreateDemoEvaluationApprovalCommand,
    DemoEvaluationApproval,
    DemoEvaluationCommand,
    DemoEvaluationResult,
    RevokeDemoEvaluationApprovalCommand,
)
from athena_context.api.evaluation_ports import (
    DemoEvaluationTrustConfiguration,
    EvaluationTrustedKeyAuthority,
)
from athena_context.api.evaluation_service import (
    DemoEvaluationDependencies,
    DemoEvaluationService,
)
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.operational_context import (
    IssueOperationalContextReceiptCommand,
    OperationalContextReceipt,
)
from athena_context.api.ports import (
    AuthenticationPort,
    AuthorizationPort,
    ContextStorePort,
)
from athena_context.api.service import ContextService
from athena_context.binding.domain import ProposalScope

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
AuthorizationHeader = Annotated[
    str | None,
    Header(alias="Authorization", max_length=8192),
]
IdempotencyHeader = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=1, max_length=128, pattern=_ID_PATTERN),
]
VersionQuery = Annotated[str, Query(pattern=_VERSION_PATTERN)]
WorkloadQuery = Annotated[WorkloadIdentifier, Query()]
WorkloadPath = Annotated[WorkloadIdentifier, Path()]


class _ApplicationAuthorizationPort(
    AuthorizationPort,
    ExplicitWorkloadAuthorizationPort,
    Protocol,
):
    pass


class ErrorDetail(ApiModel):
    code: str
    message: str


class ErrorResponse(ApiModel):
    error: ErrorDetail


class SystemClock:
    """Infrastructure clock used only by the default ASGI composition root."""

    def now(self) -> datetime:
        current = datetime.now(tz=UTC)
        return current.replace(
            microsecond=(current.microsecond // 1000) * 1000
        )

    def now_epoch_milliseconds(self) -> int:
        """Return the persistence timestamp as an exact, non-polymorphic value."""

        return time_ns() // 1_000_000


def _current_actor(
    request: Request,
    authorization: AuthorizationHeader = None,
) -> Actor:
    if authorization is None:
        raise AuthenticationError("verified bearer credentials are required")
    scheme, separator, credential = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not separator or not credential.strip():
        raise AuthenticationError("verified bearer credentials are required")
    authenticator = cast(AuthenticationPort, request.app.state.authenticator)
    verified = authenticator.authenticate_bearer(credential.strip())
    return verified.actor


ActorDependency = Annotated[Actor, Depends(_current_actor)]


def _dependency_identity(value: object) -> object:
    return getattr(value, "persistence_identity", value)


def create_app(
    *,
    service: ContextService | None = None,
    store: ContextStorePort | None = None,
    authentication: AuthenticationPort | None = None,
    authorization: _ApplicationAuthorizationPort | None = None,
    demo_evaluation_dependencies: DemoEvaluationDependencies | None = None,
    demo_evaluation_service: DemoEvaluationService | None = None,
    cohort_service: CohortProposalService | None = None,
    cohort_decision_service: CohortDecisionService | None = None,
) -> FastAPI:
    if service is not None and store is not None:
        raise ValueError("provide either a ContextService or its context store, not both")
    if demo_evaluation_service is not None:
        raise DemoEvaluationConfigurationError(
            "preconstructed demo evaluation services are rejected; provide only "
            "non-authoritative dependencies for composition with the app-owned "
            "ContextService"
        )
    default_store: ContextStorePort | None = None
    effective_authorization: _ApplicationAuthorizationPort = (
        authorization or RoleBasedAuthorization()
    )
    if service is None:
        default_clock = SystemClock()
        demo_trust: DemoEvaluationTrustConfiguration | None = None
        trusted_key: EvaluationTrustedKeyAuthority | None = None
        if demo_evaluation_dependencies is not None:
            evidence_client = demo_evaluation_dependencies.evidence_client
            anchor = evidence_client.trusted_key_anchor
            record = evidence_client.key_resolver(anchor)
            if record is None:
                raise DemoEvaluationConfigurationError(
                    "demo evaluation signing key was not found while seeding "
                    "the ContextService trust authority"
                )
            demo_trust = DemoEvaluationTrustConfiguration(
                trusted_key_anchor=anchor,
            )
            trusted_key = EvaluationTrustedKeyAuthority(
                record=record,
                revision=1,
            )
        default_store = store or InMemoryContextStore(
            authoritative_clock=default_clock,
            demo_evaluation_trusted_key=trusted_key,
        )
        service = ContextService(
            store=default_store,
            authorization=effective_authorization,
            clock=default_clock,
            publication_actor=Actor(
                actor_id="athena-context-api",
                kind=ActorKind.SERVICE,
            ),
            demo_evaluation_trust=demo_trust,
        )
    if (cohort_service is None) != (cohort_decision_service is None):
        raise ValueError(
            "cohort proposal and decision services must be supplied together "
            "from one shared dependency set"
        )
    if (
        cohort_service is not None
        and cohort_decision_service is not None
        and (
            _dependency_identity(cohort_service.context_store)
            is not _dependency_identity(service.persistence_store)
            or _dependency_identity(cohort_decision_service.persistence_store)
            is not _dependency_identity(service.persistence_store)
            or cohort_decision_service.context_service is not service
            or cohort_decision_service.proposal_service is not cohort_service
            or _dependency_identity(cohort_decision_service.candidate_repository)
            is not _dependency_identity(cohort_service.candidate_repository)
            or _dependency_identity(cohort_service.authorization)
            is not _dependency_identity(service.authorization)
            or _dependency_identity(cohort_decision_service.authorization)
            is not _dependency_identity(service.authorization)
        )
    ):
        raise ValueError(
            "cohort services must share the app-owned ContextService, store, "
            "proposal service, and candidate repository"
        )
    authenticator = authentication or RejectUnverifiedAuthentication()
    bound_demo_evaluation = (
        None
        if demo_evaluation_dependencies is None
        else DemoEvaluationService.from_dependencies(
            context_service=service,
            dependencies=demo_evaluation_dependencies,
        )
    )
    application = FastAPI(
        title="Athena Context API",
        version="1.0.0",
        description="Authoritative, human-governed workload manifest lifecycle API.",
        separate_input_output_schemas=False,
    )
    application.state.authenticator = authenticator
    cohort_router = APIRouter()

    def configured_cohort_service() -> CohortProposalService:
        if cohort_service is None:
            raise DemoEvaluationConfigurationError(
                "cohort APIs require an explicitly configured trusted snapshot "
                "repository, verifier, cache, and shared Context store"
            )
        return cohort_service

    def configured_cohort_decision_service() -> CohortDecisionService:
        if cohort_decision_service is None:
            raise DemoEvaluationConfigurationError(
                "cohort decision APIs require the same explicitly configured "
                "proposal and Context persistence dependencies"
            )
        return cohort_decision_service

    @application.exception_handler(ContextApiError)
    async def context_error_handler(
        _request: Request,
        exc: ContextApiError,
    ) -> JSONResponse:
        if isinstance(exc, AuthenticationError):
            http_status = status.HTTP_401_UNAUTHORIZED
        elif isinstance(exc, AuthorizationError):
            http_status = status.HTTP_403_FORBIDDEN
        elif isinstance(exc, ResourceNotFoundError):
            http_status = status.HTTP_404_NOT_FOUND
        elif isinstance(exc, CohortBoundaryError):
            http_status = status.HTTP_413_CONTENT_TOO_LARGE
        elif isinstance(
            exc,
            (
                ManifestValidationError,
                EvidenceCollectionRejectedError,
                EvaluationFailedClosedError,
            ),
        ):
            http_status = status.HTTP_422_UNPROCESSABLE_CONTENT
        elif isinstance(exc, DemoEvaluationConfigurationError):
            http_status = status.HTTP_503_SERVICE_UNAVAILABLE
        else:
            http_status = status.HTTP_409_CONFLICT
        body = ErrorResponse(error=ErrorDetail(code=exc.code, message=exc.message))
        return JSONResponse(status_code=http_status, content=body.model_dump(mode="json"))

    @cohort_router.get(
        "/v1/cohort-proposals",
        response_model=CohortProposalBatchResponse,
        response_model_exclude_none=True,
        responses={
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
        },
    )
    def get_cohort_proposals(
        actor: ActorDependency,
        manifest_id: WorkloadQuery,
        manifest_version: Annotated[str, Query(pattern=_VERSION_PATTERN)],
        profile_id: Annotated[str, Query(pattern=_ID_PATTERN)],
        draft_id: Annotated[str, Query(pattern=_ID_PATTERN)],
        expected_revision: Annotated[
            int,
            Query(ge=1, le=9_007_199_254_740_991),
        ],
        expected_digest: Annotated[
            str,
            Query(pattern=r"^sha256:[a-f0-9]{64}$"),
        ],
    ) -> CohortProposalBatchResponse:
        return configured_cohort_service().get_proposals(
            actor,
            CohortProposalQuery(
                manifest_id=manifest_id,
                manifest_version=manifest_version,
                profile_id=profile_id,
                draft_id=draft_id,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            ),
        )

    @cohort_router.post(
        "/v1/cohort-proposals/preview",
        response_model=CohortReviewCandidate,
        response_model_exclude_none=True,
        responses={
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
        },
    )
    def preview_cohort_proposals(
        command: CohortReviewPreviewRequest,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> CohortReviewCandidate:
        return configured_cohort_service().preview(
            actor,
            idempotency_key,
            command,
        )

    @cohort_router.post(
        "/v1/cohort-proposals/decisions",
        response_model=CohortDecisionResponse,
        response_model_exclude_none=False,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
        },
    )
    def decide_cohort_proposals(
        command: CohortDecisionRequest,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> CohortDecisionResponse:
        return decision_response(
            configured_cohort_decision_service().decide(
                actor,
                idempotency_key,
                command,
            )
        )

    @cohort_router.get(
        "/v1/cohort-proposals/decisions/{decision_id}",
        response_model=CohortDecisionResponse,
        response_model_exclude_none=False,
        responses={
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
        },
    )
    def get_cohort_decision(
        decision_id: Annotated[str, Path(pattern=_ID_PATTERN)],
        manifest_id: WorkloadQuery,
        actor: ActorDependency,
    ) -> CohortDecisionResponse:
        return decision_response(
            configured_cohort_decision_service().get(
                actor,
                manifest_id=manifest_id,
                decision_id=decision_id,
            )
        )

    @cohort_router.get(
        "/v1/cohort-proposals/decisions",
        response_model=list[CohortDecisionResponse],
        response_model_exclude_none=False,
        responses={
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
        },
    )
    def list_cohort_decisions(
        manifest_id: WorkloadQuery,
        manifest_version: Annotated[str, Query(pattern=_VERSION_PATTERN)],
        profile_id: Annotated[str, Query(pattern=_ID_PATTERN)],
        profile_type: Annotated[
            ProfileType,
            Query(
                pattern=(
                    "^(production|development|training|test|"
                    "disasterRecovery|sandbox)$"
                )
            ),
        ],
        resolved_profile_digest: Annotated[
            str,
            Query(pattern=r"^sha256:[a-f0-9]{64}$"),
        ],
        draft_id: Annotated[str, Query(pattern=_ID_PATTERN)],
        expected_revision: Annotated[
            int,
            Query(ge=1, le=9_007_199_254_740_991),
        ],
        expected_digest: Annotated[
            str,
            Query(pattern=r"^sha256:[a-f0-9]{64}$"),
        ],
        proposal_ids: Annotated[
            list[str],
            Query(min_length=1, max_length=200),
        ],
        proposal_set_digest: Annotated[
            str,
            Query(pattern=r"^sha256:[a-f0-9]{64}$"),
        ],
        snapshot_artifact_digest: Annotated[
            str,
            Query(pattern=r"^sha256:[a-f0-9]{64}$"),
        ],
        actor: ActorDependency,
        limit: Annotated[int, Query(ge=1, le=200)] = 200,
    ) -> list[CohortDecisionResponse]:
        scope = ProposalScope(
            manifestId=manifest_id,
            manifestVersion=manifest_version,
            profileId=profile_id,
            profileType=profile_type,
            resolvedProfileDigest=resolved_profile_digest,
        )
        source_draft = CohortDraftBinding(
            draftId=draft_id,
            revision=expected_revision,
            manifestDigest=expected_digest,
        )
        return [
            decision_response(decision)
            for decision in configured_cohort_decision_service().list_decisions(
                actor,
                manifest_id=manifest_id,
                scope=scope,
                source_draft=source_draft,
                proposal_ids=proposal_ids,
                proposal_set_digest=proposal_set_digest,
                snapshot_artifact_digest=snapshot_artifact_digest,
                limit=limit,
            )
        ]

    if cohort_service is not None and cohort_decision_service is not None:
        application.include_router(cohort_router)

    @application.post(
        "/v1/drafts",
        response_model=DraftRecord,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
        responses={409: {"model": ErrorResponse}},
    )
    def create_draft(
        command: CreateDraftCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.create_draft(actor, idempotency_key, command)

    @application.get(
        "/v1/drafts/{draft_id}",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def get_draft(
        draft_id: str,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.get_draft(actor, draft_id)

    @application.get(
        "/v1/drafts",
        response_model=list[DraftRecord],
        response_model_exclude_none=True,
    )
    def list_drafts(
        actor: ActorDependency,
        manifest_id: Annotated[WorkloadIdentifier | None, Query()] = None,
        draft_state: Annotated[DraftState | None, Query(alias="state")] = None,
    ) -> list[DraftRecord]:
        return service.list_drafts(actor, manifest_id=manifest_id, state=draft_state)

    @application.put(
        "/v1/drafts/{draft_id}",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def replace_draft(
        draft_id: str,
        command: ReplaceDraftCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.replace_draft(actor, draft_id, idempotency_key, command)

    @application.post(
        "/v1/operational-context-receipts",
        response_model=OperationalContextReceipt,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    def issue_operational_context_receipt(
        command: IssueOperationalContextReceiptCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> OperationalContextReceipt:
        return service.issue_operational_context_receipt(
            actor,
            idempotency_key,
            command,
        )

    @application.post(
        "/v1/drafts/{draft_id}/validate",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def validate_draft(
        draft_id: str,
        command: TransitionCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.validate_draft(actor, draft_id, idempotency_key, command)

    @application.post(
        "/v1/drafts/{draft_id}/submit",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def submit_for_review(
        draft_id: str,
        command: TransitionCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.submit_for_review(actor, draft_id, idempotency_key, command)

    @application.post(
        "/v1/drafts/{draft_id}/review",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def review_draft(
        draft_id: str,
        command: ReviewCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.review_draft(
            actor,
            draft_id,
            idempotency_key,
            command,
        )

    @application.post(
        "/v1/drafts/{draft_id}/approve",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def approve_draft(
        draft_id: str,
        command: ApproveCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> DraftRecord:
        return service.approve_draft(actor, draft_id, idempotency_key, command)

    @application.post(
        "/v1/drafts/{draft_id}/publish",
        response_model=PublishedManifest,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    def publish_draft(
        draft_id: str,
        command: PublishCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> PublishedManifest:
        return service.publish_draft(actor, draft_id, idempotency_key, command)

    @application.get(
        "/v1/manifests/{manifest_id}/versions/{manifest_version}",
        response_model=PublishedManifestView,
        response_model_exclude_none=True,
    )
    def get_published(
        manifest_id: WorkloadPath,
        manifest_version: str,
        actor: ActorDependency,
    ) -> PublishedManifestView:
        return service.get_published(
            actor,
            manifest_version,
            manifest_id=manifest_id,
        )

    @application.get(
        "/v1/manifests/{manifest_id}/versions",
        response_model=list[PublishedManifestView],
        response_model_exclude_none=True,
    )
    def list_published(
        manifest_id: WorkloadPath,
        actor: ActorDependency,
    ) -> list[PublishedManifestView]:
        return service.list_published(actor, manifest_id)

    @application.get(
        "/v1/versions/{manifest_version}",
        response_model=PublishedManifestView,
        response_model_exclude_none=True,
    )
    def resolve_published(
        manifest_version: str,
        actor: ActorDependency,
        manifest_id: Annotated[WorkloadIdentifier | None, Query()] = None,
    ) -> PublishedManifestView:
        return service.get_published(
            actor,
            manifest_version,
            manifest_id=manifest_id,
        )

    @application.post(
        "/v1/manifests/{manifest_id}/versions/{manifest_version}/supersede",
        response_model=Supersession,
    )
    def supersede_version(
        manifest_id: WorkloadPath,
        manifest_version: str,
        command: SupersedeCommand,
        idempotency_key: IdempotencyHeader,
        actor: ActorDependency,
    ) -> Supersession:
        return service.supersede_version(
            actor,
            manifest_id,
            manifest_version,
            idempotency_key,
            command,
        )

    @application.get(
        "/v1/manifests/{manifest_id}/compare",
        response_model=VersionComparison,
    )
    def compare_versions(
        manifest_id: WorkloadPath,
        from_version: VersionQuery,
        to_version: VersionQuery,
        actor: ActorDependency,
    ) -> VersionComparison:
        return service.compare_versions(actor, manifest_id, from_version, to_version)

    @application.get(
        "/v1/drafts/{draft_id}/profiles/{profile_id}/authority",
        response_model=ResolvedProfileAuthority,
    )
    def resolve_draft_profile_authority(
        draft_id: Annotated[str, Path(pattern=_ID_PATTERN)],
        profile_id: Annotated[str, Path(pattern=_ID_PATTERN)],
        actor: ActorDependency,
    ) -> ResolvedProfileAuthority:
        return service.resolve_draft_profile_authority(
            actor,
            draft_id,
            profile_id,
        )

    @application.get(
        "/v1/manifests/{manifest_id}/versions/{manifest_version}/profiles/"
        "{profile_id}/authority",
        response_model=ResolvedProfileAuthority,
    )
    def resolve_published_profile_authority(
        manifest_id: WorkloadPath,
        manifest_version: Annotated[str, Path(pattern=_VERSION_PATTERN)],
        profile_id: Annotated[str, Path(pattern=_ID_PATTERN)],
        actor: ActorDependency,
    ) -> ResolvedProfileAuthority:
        return service.resolve_published_profile_authority(
            actor,
            manifest_id,
            manifest_version,
            profile_id,
        )

    @application.get(
        "/v1/manifests/{manifest_id}/audit",
        response_model=list[AuditEvent],
    )
    def audit_history(
        manifest_id: WorkloadPath,
        actor: ActorDependency,
    ) -> list[AuditEvent]:
        return service.audit_history(actor, manifest_id)

    if bound_demo_evaluation is not None:

        @application.post(
            "/v1/demo-evaluation-approvals",
            response_model=DemoEvaluationApproval,
            response_model_exclude_none=True,
            status_code=status.HTTP_201_CREATED,
        )
        def create_demo_evaluation_approval(
            command: CreateDemoEvaluationApprovalCommand,
            idempotency_key: IdempotencyHeader,
            actor: ActorDependency,
        ) -> DemoEvaluationApproval:
            return service.create_demo_evaluation_approval(
                actor,
                idempotency_key,
                command,
            )

        @application.get(
            "/v1/demo-evaluation-approvals/{decision_id}",
            response_model=DemoEvaluationApproval,
            response_model_exclude_none=True,
        )
        def get_demo_evaluation_approval(
            decision_id: Annotated[str, Path(pattern=_ID_PATTERN)],
            actor: ActorDependency,
        ) -> DemoEvaluationApproval:
            approval = service.get_demo_evaluation_approval(
                actor,
                decision_id,
            )
            if approval is None:
                raise ResourceNotFoundError(
                    f"demo evaluation approval {decision_id!r} was not found"
                )
            return approval

        @application.post(
            "/v1/demo-evaluation-approvals/{decision_id}/revoke",
            response_model=DemoEvaluationApproval,
            response_model_exclude_none=True,
        )
        def revoke_demo_evaluation_approval(
            decision_id: Annotated[str, Path(pattern=_ID_PATTERN)],
            command: RevokeDemoEvaluationApprovalCommand,
            idempotency_key: IdempotencyHeader,
            actor: ActorDependency,
        ) -> DemoEvaluationApproval:
            return service.revoke_demo_evaluation_approval(
                actor,
                decision_id,
                idempotency_key,
                command,
            )

        @application.post(
            "/v1/demo-evaluations",
            response_model=DemoEvaluationResult,
            response_model_exclude_none=True,
            status_code=status.HTTP_201_CREATED,
        )
        def evaluate_demo(
            command: DemoEvaluationCommand,
            idempotency_key: IdempotencyHeader,
            actor: ActorDependency,
        ) -> DemoEvaluationResult:
            return bound_demo_evaluation.evaluate(
                actor,
                idempotency_key,
                command,
            )

        @application.get(
            "/v1/demo-evaluations/{snapshot_id}",
            response_model=DemoEvaluationResult,
            response_model_exclude_none=True,
        )
        def get_demo_evaluation(
            snapshot_id: str,
            actor: ActorDependency,
        ) -> DemoEvaluationResult:
            return bound_demo_evaluation.get_result(actor, snapshot_id)

    return application


app = create_app()
