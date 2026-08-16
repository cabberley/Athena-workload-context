from __future__ import annotations

from collections.abc import Iterable

from athena_context.api.domain import (
    Actor,
    ActorKind,
    Permission,
    Role,
    RoleGrant,
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


class InMemoryActorDirectory:
    """Server-owned principal metadata; clients cannot assert actor kind or roles."""

    def __init__(self, actors: Iterable[Actor] = ()) -> None:
        self._actors = {actor.actor_id: actor for actor in actors}

    def resolve(self, actor_id: str) -> Actor:
        actor = self._actors.get(actor_id)
        if actor is None:
            raise AuthenticationError("the supplied actor is not authenticated")
        return actor


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
