from __future__ import annotations

from collections.abc import Iterable, Mapping

from athena_context.api.domain import (
    Actor,
    ActorKind,
    Permission,
    Role,
    RoleGrant,
    VerifiedAuthentication,
)
from athena_context.api.errors import AuthenticationError, AuthorizationError

_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.PROPOSER: frozenset(
        {
            Permission.CREATE_DRAFT,
            Permission.READ,
            Permission.LIST,
            Permission.UPDATE_DRAFT,
            Permission.VALIDATE,
            Permission.SUBMIT,
        }
    ),
    Role.REVIEWER: frozenset({Permission.READ, Permission.LIST, Permission.AUDIT}),
    Role.APPROVER: frozenset(
        {Permission.READ, Permission.LIST, Permission.AUDIT, Permission.APPROVE}
    ),
    Role.PUBLISHER: frozenset(
        {
            Permission.READ,
            Permission.LIST,
            Permission.AUDIT,
            Permission.PUBLISH,
            Permission.SUPERSEDE,
        }
    ),
    Role.READER: frozenset({Permission.READ, Permission.LIST}),
    Role.AUDITOR: frozenset({Permission.READ, Permission.LIST, Permission.AUDIT}),
}
_HUMAN_ONLY = frozenset(
    {Permission.APPROVE, Permission.PUBLISH, Permission.SUPERSEDE}
)


class RejectUnverifiedAuthentication:
    """Production-safe default that rejects credentials until a verifier is configured."""

    def authenticate_bearer(self, credential: str) -> VerifiedAuthentication:
        del credential
        raise AuthenticationError("bearer credentials were not verified")


class StaticTestAuthenticator:
    """Deterministic test-only adapter returning pre-verified synthetic identities."""

    def __init__(self, identities: Mapping[str, VerifiedAuthentication]) -> None:
        self._identities = dict(identities)

    def authenticate_bearer(self, credential: str) -> VerifiedAuthentication:
        identity = self._identities.get(credential)
        if identity is None:
            raise AuthenticationError("bearer credentials were not verified")
        return identity


class RoleBasedAuthorization:
    """Deterministic role and manifest-scope authorization adapter."""

    def __init__(self, grants: Iterable[RoleGrant] = ()) -> None:
        self._grants = tuple(grants)

    def require(self, actor: Actor, permission: Permission, manifest_id: str) -> None:
        if permission in _HUMAN_ONLY and actor.kind is not ActorKind.HUMAN:
            raise AuthorizationError(f"{permission.value} requires a human actor")
        authorized = any(
            grant.actor_id == actor.actor_id
            and permission in _ROLE_PERMISSIONS[grant.role]
            and grant.manifest_id in {"*", manifest_id}
            for grant in self._grants
        )
        if not authorized:
            raise AuthorizationError(
                f"actor {actor.actor_id!r} is not authorized for {permission.value}"
            )
