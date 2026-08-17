from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol

from athena_context.api.domain import (
    Actor,
    AuditEvent,
    DraftRecord,
    DraftState,
    MutationReceipt,
    PendingAuditEvent,
    Permission,
    PublishedManifest,
    Supersession,
    VerifiedAuthentication,
    WorkloadIdentifier,
)


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class AuthenticationPort(Protocol):
    def authenticate_bearer(self, credential: str) -> VerifiedAuthentication: ...


class AuthorizationPort(Protocol):
    def require(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: WorkloadIdentifier | None,
    ) -> None: ...


class ContextTransactionPort(Protocol):
    def get_draft(self, draft_id: str) -> DraftRecord | None: ...

    def list_drafts(
        self,
        *,
        manifest_id: str | None = None,
        state: DraftState | None = None,
    ) -> list[DraftRecord]: ...

    def put_draft(
        self,
        draft: DraftRecord,
        *,
        expected_revision: int | None,
    ) -> None: ...

    def get_published(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> PublishedManifest | None: ...

    def list_published(self, *, manifest_id: str | None = None) -> list[PublishedManifest]: ...

    def put_published(self, published: PublishedManifest) -> None: ...

    def get_supersession(
        self,
        manifest_id: str,
        manifest_version: str,
    ) -> Supersession | None: ...

    def put_supersession(self, supersession: Supersession) -> None: ...

    def append_audit(self, event: PendingAuditEvent) -> AuditEvent: ...

    def list_audit(self, *, manifest_id: str) -> list[AuditEvent]: ...

    def get_receipt(self, actor_id: str, idempotency_key: str) -> MutationReceipt | None: ...

    def put_receipt(self, receipt: MutationReceipt) -> None: ...


class ContextStorePort(Protocol):
    def transaction(self) -> AbstractContextManager[ContextTransactionPort]: ...
