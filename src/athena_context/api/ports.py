from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
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


@dataclass(frozen=True, eq=False, slots=True)
class ContextTransactionBackendIdentity:
    """Opaque identity for one authoritative persistence transaction backend.

    Equality is deliberately object identity. Recreating a value cannot impersonate
    the backend-owned capability issued to its transaction participants.
    """


class ContextAuthorityTransactionBackendPort(Protocol):
    """Backend-owned transaction capability used by conditional publications."""

    @property
    def identity(self) -> ContextTransactionBackendIdentity: ...

    def transaction(self) -> AbstractContextManager[None]: ...


class ContextTransactionPort(Protocol):
    @property
    def authority_transaction_backend_identity(
        self,
    ) -> ContextTransactionBackendIdentity: ...

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
