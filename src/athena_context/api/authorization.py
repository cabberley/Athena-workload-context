from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

import jwt

from athena_context.api.domain import (
    Actor,
    ActorKind,
    AllWorkloadsGrantScope,
    AuthenticationMethod,
    Permission,
    Role,
    RoleGrant,
    VerifiedAuthentication,
    WorkloadGrantScope,
    ensure_concrete_workload_id,
)
from athena_context.api.errors import AuthenticationError, AuthorizationError
from athena_context.api.evaluation_domain import AuthorizationGrantToken
from athena_context.api.transaction_lock import InMemoryTransactionLock
from athena_context.contracts import compute_artifact_digest

_ENTRA_TENANT_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MAX_BEARER_TOKEN_BYTES = 8_192
_MAX_AUDIENCE_LENGTH = 256
_MAX_ISSUER_LENGTH = 512
_MAX_SUBJECT_LENGTH = 256
_MAX_SCOPE_LENGTH = 4_096
_DELEGATED_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_AGENT_IDENTITY_CLAIMS = frozenset(
    {
        "xms_act_fct",
        "xms_sub_fct",
        "xms_tnt_fct",
        "xms_par_app_azp",
    }
)

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


def authorize_role_grants(
    actor: Actor,
    permission: Permission,
    manifest_id: str,
    *,
    grants: tuple[RoleGrant, ...],
    grant_revision: int,
) -> AuthorizationGrantToken:
    """Authorize from one transaction-owned immutable grant snapshot."""

    RoleBasedAuthorization._require_actor_kind(actor, permission)
    RoleBasedAuthorization._require_concrete_manifest_id(manifest_id)
    matching = tuple(
        grant
        for grant in grants
        if grant.actor_id == actor.actor_id
        and permission in _ROLE_PERMISSIONS[grant.role]
        and (
            isinstance(grant.scope, AllWorkloadsGrantScope)
            or (
                isinstance(grant.scope, WorkloadGrantScope)
                and grant.scope.workload_id == manifest_id
            )
        )
    )
    if not matching:
        raise AuthorizationError(
            f"actor {actor.actor_id!r} is not authorized for {permission.value}"
        )
    canonical_grants = sorted(
        (grant.model_dump(mode="json") for grant in matching),
        key=compute_artifact_digest,
    )
    return AuthorizationGrantToken(
        actor_id=actor.actor_id,
        permission=permission,
        manifest_id=manifest_id,
        grant_revision=grant_revision,
        grant_digest=compute_artifact_digest(
            {
                "actorId": actor.actor_id,
                "permission": permission.value,
                "manifestId": manifest_id,
                "grants": canonical_grants,
            }
        ),
    )


class RejectUnverifiedAuthentication:
    """Production-safe default that rejects credentials until a verifier is configured."""

    def authenticate_bearer(self, credential: str) -> VerifiedAuthentication:
        del credential
        raise AuthenticationError("bearer credentials were not verified")


class EntraJwtAuthenticator:
    """Verify an Entra access token before exposing a stable typed actor identity."""

    def __init__(
        self,
        *,
        tenant_id: str,
        audience: str,
        delegated_scope: str,
    ) -> None:
        if (
            type(tenant_id) is not str
            or _ENTRA_TENANT_ID_PATTERN.fullmatch(tenant_id) is None
        ):
            raise ValueError("Context API Entra tenant ID is invalid")
        if (
            type(audience) is not str
            or not audience
            or len(audience) > _MAX_AUDIENCE_LENGTH
            or audience != audience.strip()
            or any(character in audience for character in "\r\n")
        ):
            raise ValueError("Context API Entra audience is invalid")
        if (
            type(delegated_scope) is not str
            or _DELEGATED_SCOPE_PATTERN.fullmatch(delegated_scope) is None
        ):
            raise ValueError("Context API Entra delegated scope is invalid")
        self._tenant_id = tenant_id.casefold()
        self._audience = audience
        self._delegated_scope = delegated_scope
        self._issuer = (
            f"https://login.microsoftonline.com/{self._tenant_id}/v2.0"
        )
        self._jwks_client = jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{self._tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
        )

    def authenticate_bearer(self, credential: str) -> VerifiedAuthentication:
        if (
            type(credential) is not str
            or not credential
            or credential != credential.strip()
            or len(credential.encode("utf-8")) > _MAX_BEARER_TOKEN_BYTES
            or any(character in credential for character in "\r\n")
        ):
            raise AuthenticationError("bearer credentials were not verified")
        try:
            header = jwt.get_unverified_header(credential)
            if (
                not isinstance(header, dict)
                or header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
                or not header["kid"]
            ):
                raise ValueError("access token header is invalid")
            signing_key = self._jwks_client.get_signing_key_from_jwt(credential).key
            claims = jwt.decode(
                credential,
                signing_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=0,
                options={
                    "require": [
                        "aud",
                        "exp",
                        "iat",
                        "iss",
                        "nbf",
                        "oid",
                        "sub",
                        "tid",
                    ],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                },
            )
            if not isinstance(claims, dict):
                raise ValueError("access token claims are invalid")
            audience = self._required_text(claims, "aud", _MAX_AUDIENCE_LENGTH)
            issuer = self._required_text(claims, "iss", _MAX_ISSUER_LENGTH)
            tenant_id = self._required_text(claims, "tid", 36).casefold()
            subject_id = self._required_text(claims, "sub", _MAX_SUBJECT_LENGTH)
            object_id = self._required_object_id(claims, "oid")
            if (
                audience != self._audience
                or issuer != self._issuer
                or tenant_id != self._tenant_id
            ):
                raise ValueError("access token tenant binding is invalid")
            identity_type = claims.get("idtyp")
            if identity_type == "app":
                if claims.get("scp") not in (None, "", "/"):
                    raise ValueError("application access token has delegated scopes")
                actor_kind = ActorKind.SERVICE
                self._service_client_id(claims)
            elif identity_type in (None, "user"):
                self._required_delegated_scope(claims)
                actor_kind = (
                    ActorKind.AGENT
                    if any(name in claims for name in _AGENT_IDENTITY_CLAIMS)
                    else ActorKind.HUMAN
                )
            else:
                raise ValueError("access token identity type is invalid")
        except (jwt.PyJWTError, TypeError, ValueError, KeyError):
            raise AuthenticationError(
                "bearer credentials were not verified"
            ) from None
        return VerifiedAuthentication(
            actor=Actor(actor_id=object_id, kind=actor_kind),
            subject_id=subject_id,
            issuer=self._issuer,
            audience=self._audience,
            method=AuthenticationMethod.ENTRA_JWT,
        )

    @staticmethod
    def _required_text(
        claims: Mapping[str, Any],
        name: str,
        maximum_length: int,
    ) -> str:
        value = claims.get(name)
        if (
            type(value) is not str
            or not value
            or len(value) > maximum_length
            or value != value.strip()
            or any(character in value for character in "\r\n")
        ):
            raise ValueError(f"access token claim {name!r} is invalid")
        return value

    @classmethod
    def _required_object_id(
        cls,
        claims: Mapping[str, Any],
        name: str,
    ) -> str:
        value = cls._required_text(claims, name, 36)
        if _ENTRA_TENANT_ID_PATTERN.fullmatch(value) is None:
            raise ValueError(f"access token claim {name!r} is invalid")
        return value.casefold()

    @classmethod
    def _service_client_id(cls, claims: Mapping[str, Any]) -> None:
        client_ids: list[str] = []
        for name in ("azp", "appid"):
            value = claims.get(name)
            if value is None:
                continue
            client_ids.append(cls._required_object_id(claims, name))
        if not client_ids or len(set(client_ids)) != 1:
            raise ValueError("application access token client ID is invalid")

    def _required_delegated_scope(self, claims: Mapping[str, Any]) -> str:
        scope = self._required_text(claims, "scp", _MAX_SCOPE_LENGTH)
        scopes = scope.split(" ")
        if (
            scope == "/"
            or any(not item or item == "/" for item in scopes)
            or self._delegated_scope not in scopes
        ):
            raise ValueError("delegated access token scope is invalid")
        return scope


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
    ) -> None:
        self._transaction_lock = InMemoryTransactionLock()
        self._grants = tuple(grants)
        self._grant_revision = 1

    def require(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str | None,
    ) -> None:
        with self._transaction_lock.transaction():
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
        with self._transaction_lock.transaction():
            return authorize_role_grants(
                actor,
                permission,
                manifest_id,
                grants=self._grants,
                grant_revision=self._grant_revision,
            )

    def require_explicit(
        self,
        actor: Actor,
        permission: Permission,
        manifest_id: str,
    ) -> None:
        """Require a concrete workload grant; wildcard grants never satisfy this boundary."""

        with self._transaction_lock.transaction():
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

        with self._transaction_lock.transaction():
            remaining = tuple(candidate for candidate in self._grants if candidate != grant)
            if len(remaining) == len(self._grants):
                return
            self._grants = remaining
            self._grant_revision += 1
