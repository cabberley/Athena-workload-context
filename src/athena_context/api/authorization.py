from __future__ import annotations

from collections.abc import Iterable, Mapping

from athena_context.api.domain import (
    Actor,
    ActorKind,
    AllWorkloadsGrantScope,
    Permission,
    Role,
    RoleGrant,
    VerifiedAuthentication,
    WorkloadGrantScope,
    ensure_concrete_workload_id,
)
from athena_context.api.errors import AuthenticationError, AuthorizationError
from athena_context.api.evaluation_domain import AuthorizationGrantToken
from athena_context.api.memory import InMemoryAuthorityCoordinator
from athena_context.api.ports import (
    ContextAuthorityTransactionBackendPort,
    ContextTransactionBackendIdentity,
)
from athena_context.contracts import compute_artifact_digest

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

    def __init__(
        self,
        grants: Iterable[RoleGrant] = (),
        *,
        transaction_backend: ContextAuthorityTransactionBackendPort | None = None,
    ) -> None:
        self._transaction_backend = (
            transaction_backend or InMemoryAuthorityCoordinator()
        )
        self._grants = tuple(grants)
        self._grant_revision = 1

    def require(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str | None,
    ) -> None:
        with self._transaction_backend.transaction():
            self._require_actor_kind(actor, permission)
            self._require_concrete_manifest_id(manifest_id)
            if not self._matching_grants(
                actor,
                permission,
                manifest_id,
                explicit_only=False,
            ):
                raise AuthorizationError(
                    f"actor {actor.actor_id!r} is not authorized for "
                    f"{permission.value}"
                )

    def authorize(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> AuthorizationGrantToken:
        with self._transaction_backend.transaction():
            self._require_actor_kind(actor, permission)
            self._require_concrete_manifest_id(manifest_id)
            matching = self._matching_grants(
                actor,
                permission,
                manifest_id,
                explicit_only=False,
            )
            if not matching:
                raise AuthorizationError(
                    f"actor {actor.actor_id!r} is not authorized for "
                    f"{permission.value}"
                )
            grants = sorted(
                (
                    grant.model_dump(mode="json")
                    for grant in matching
                ),
                key=compute_artifact_digest,
            )
            return AuthorizationGrantToken(
                actor_id=actor.actor_id,
                permission=permission,
                manifest_id=manifest_id,
                grant_revision=self._grant_revision,
                grant_digest=compute_artifact_digest(
                    {
                        "actorId": actor.actor_id,
                        "permission": permission.value,
                        "manifestId": manifest_id,
                        "grants": grants,
                    }
                ),
            )

    def require_explicit(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> None:
        """Require a concrete workload grant; wildcard grants never satisfy this boundary."""

        with self._transaction_backend.transaction():
            self._require_actor_kind(actor, permission)
            self._require_concrete_manifest_id(manifest_id)
            if not self._matching_grants(
                actor,
                permission,
                manifest_id,
                explicit_only=True,
            ):
                raise AuthorizationError(
                    f"actor {actor.actor_id!r} has no explicit grant for "
                    f"{permission.value}"
                )

    @staticmethod
    def _require_actor_kind(actor: Actor, permission: Permission) -> None:
        if permission in _HUMAN_ONLY and actor.kind is not ActorKind.HUMAN:
            raise AuthorizationError(f"{permission.value} requires a human actor")

    @staticmethod
    def _require_concrete_manifest_id(manifest_id: str | None) -> None:
        if manifest_id is None:
            return
        try:
            ensure_concrete_workload_id(manifest_id)
        except ValueError as exc:
            raise AuthorizationError("'*' is not a workload identifier") from exc

    def _matching_grants(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str | None,
        *,
        explicit_only: bool,
    ) -> tuple[RoleGrant, ...]:
        return tuple(
            grant
            for grant in self._grants
            if grant.actor_id == actor.actor_id
            and permission in _ROLE_PERMISSIONS[grant.role]
            and (
                (
                    not explicit_only
                    and isinstance(grant.scope, AllWorkloadsGrantScope)
                )
                or (
                    manifest_id is not None
                    and isinstance(grant.scope, WorkloadGrantScope)
                    and grant.scope.workload_id == manifest_id
                )
            )
        )

    def remove_grant(self, grant: RoleGrant) -> None:
        """Revoke one exact in-memory grant under the shared authority lock."""

        with self._transaction_backend.transaction():
            remaining = tuple(candidate for candidate in self._grants if candidate != grant)
            if len(remaining) == len(self._grants):
                return
            self._grants = remaining
            self._grant_revision += 1

    @property
    def transaction_backend_identity(self) -> ContextTransactionBackendIdentity:
        return self._transaction_backend.identity
