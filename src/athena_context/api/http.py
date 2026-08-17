from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import Depends, FastAPI, Header, Query, Request, status
from fastapi.responses import JSONResponse

from athena_context.api.authorization import (
    RejectUnverifiedAuthentication,
    RoleBasedAuthorization,
)
from athena_context.api.domain import (
    Actor,
    ActorKind,
    ApiModel,
    AuditEvent,
    CreateDraftCommand,
    DraftRecord,
    DraftState,
    PublishCommand,
    PublishedManifest,
    PublishedManifestView,
    ReplaceDraftCommand,
    SupersedeCommand,
    Supersession,
    TransitionCommand,
    VersionComparison,
)
from athena_context.api.errors import (
    AuthenticationError,
    AuthorizationError,
    ContextApiError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    ManifestValidationError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_domain import (
    DemoEvaluationCommand,
    DemoEvaluationResult,
)
from athena_context.api.evaluation_service import DemoEvaluationService
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.ports import AuthenticationPort
from athena_context.api.service import ContextService

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


class ErrorDetail(ApiModel):
    code: str
    message: str


class ErrorResponse(ApiModel):
    error: ErrorDetail


class SystemClock:
    """Infrastructure clock used only by the default ASGI composition root."""

    def now(self) -> datetime:
        return datetime.now(tz=UTC).replace(microsecond=0)


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


def create_app(
    *,
    service: ContextService | None = None,
    authentication: AuthenticationPort | None = None,
    demo_evaluation_service: DemoEvaluationService | None = None,
) -> FastAPI:
    if service is None:
        service = ContextService(
            store=InMemoryContextStore(),
            authorization=RoleBasedAuthorization(),
            clock=SystemClock(),
            publication_actor=Actor(
                actor_id="athena-context-api",
                kind=ActorKind.SERVICE,
            ),
        )
    authenticator = authentication or RejectUnverifiedAuthentication()
    application = FastAPI(
        title="Athena Context API",
        version="1.0.0",
        description="Authoritative, human-governed workload manifest lifecycle API.",
    )
    application.state.authenticator = authenticator

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
        manifest_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
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
        "/v1/drafts/{draft_id}/approve",
        response_model=DraftRecord,
        response_model_exclude_none=True,
    )
    def approve_draft(
        draft_id: str,
        command: TransitionCommand,
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
        manifest_id: str,
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
        manifest_id: str,
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
        manifest_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
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
        manifest_id: str,
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
        manifest_id: str,
        from_version: VersionQuery,
        to_version: VersionQuery,
        actor: ActorDependency,
    ) -> VersionComparison:
        return service.compare_versions(actor, manifest_id, from_version, to_version)

    @application.get(
        "/v1/manifests/{manifest_id}/audit",
        response_model=list[AuditEvent],
    )
    def audit_history(
        manifest_id: str,
        actor: ActorDependency,
    ) -> list[AuditEvent]:
        return service.audit_history(actor, manifest_id)

    if demo_evaluation_service is not None:

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
            return demo_evaluation_service.evaluate(
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
            return demo_evaluation_service.get_result(actor, snapshot_id)

    return application


app = create_app()
