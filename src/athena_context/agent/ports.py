from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Protocol

from athena_context.agent.models import (
    AgentModel,
    AuthoritativePolicyView,
    ConfirmationBinding,
    ConfirmationClaims,
    ToolCallContext,
    ToolDefinition,
)
from athena_context.api.domain import (
    Actor,
    AuditEvent,
    CreateDraftCommand,
    DraftRecord,
    PublishedManifestView,
)


class ContextApiPort(Protocol):
    """Only the WC-007 read and draft-create operations used by Context MCP."""

    def get_published(
        self,
        actor: Actor,
        manifest_version: str,
        *,
        manifest_id: str | None = None,
    ) -> PublishedManifestView: ...

    def list_published(
        self,
        actor: Actor,
        manifest_id: str,
    ) -> list[PublishedManifestView]: ...

    def audit_history(self, actor: Actor, manifest_id: str) -> list[AuditEvent]: ...

    def create_draft(
        self,
        actor: Actor,
        idempotency_key: str,
        command: CreateDraftCommand,
    ) -> DraftRecord: ...


class AuthoritativeFindingsPort(Protocol):
    """Authorization-aware access to already evaluated deterministic findings."""

    def get_policy_view(
        self,
        actor: Actor,
        *,
        manifest_id: str,
        manifest_version: str,
        profile_id: str,
    ) -> AuthoritativePolicyView: ...


class ConfirmationClockPort(Protocol):
    def now(self) -> datetime: ...


class ConfirmationSignerPort(Protocol):
    def sign(self, claims: ConfirmationClaims) -> str: ...

    def verify(self, token: str) -> ConfirmationClaims: ...


class ConfirmationStorePort(Protocol):
    """Atomic one-time confirmation reservation and consumption."""

    def reserve(self, binding: ConfirmationBinding) -> str: ...

    def consume(
        self,
        challenge_id: str,
        binding: ConfirmationBinding,
        *,
        now: datetime,
    ) -> bool: ...


type ToolDispatch = Callable[
    [str, Mapping[str, object], ToolCallContext],
    AgentModel,
]


class McpTransportPort(Protocol):
    """Transport host for a typed tool registry; authentication stays out of arguments."""

    def run(
        self,
        *,
        system_guidance: str,
        tools: Sequence[ToolDefinition],
        dispatch: ToolDispatch,
    ) -> None: ...


__all__ = [
    "AuthoritativeFindingsPort",
    "ConfirmationClockPort",
    "ConfirmationSignerPort",
    "ConfirmationStorePort",
    "ContextApiPort",
    "McpTransportPort",
    "ToolDispatch",
]
