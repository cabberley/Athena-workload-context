from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import athena_context.api.authorization as authorization_module
from athena_context.api.authorization import EntraJwtAuthenticator
from athena_context.api.domain import ActorKind, AuthenticationMethod
from athena_context.api.errors import AuthenticationError

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_OTHER_TENANT_ID = "33333333-3333-3333-3333-333333333333"
_AUDIENCE = "api://athena-context"
_DELEGATED_SCOPE = "Athena.Context.Access"
_HUMAN_OBJECT_ID = "22222222-2222-2222-2222-222222222222"
_SERVICE_OBJECT_ID = "44444444-4444-4444-4444-444444444444"
_SERVICE_CLIENT_ID = "55555555-5555-5555-5555-555555555555"


def _claims(*, identity_type: str | None = None) -> dict[str, object]:
    now = datetime.now(tz=UTC)
    claims: dict[str, object] = {
        "iss": f"https://login.microsoftonline.com/{_TENANT_ID}/v2.0",
        "aud": _AUDIENCE,
        "tid": _TENANT_ID,
        "oid": _HUMAN_OBJECT_ID,
        "sub": "synthetic-subject",
        "scp": _DELEGATED_SCOPE,
        "iat": int((now - timedelta(minutes=1)).timestamp()),
        "nbf": int((now - timedelta(minutes=1)).timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    if identity_type is not None:
        claims["idtyp"] = identity_type
    if identity_type == "app":
        claims["oid"] = _SERVICE_OBJECT_ID
        claims["appid"] = _SERVICE_CLIENT_ID
        del claims["scp"]
    return claims


def _token(
    claims: dict[str, object],
    private_key: Any,
    *,
    algorithm: str = "RS256",
) -> str:
    key: Any = (
        private_key
        if algorithm == "RS256"
        else "synthetic-hmac-secret-with-at-least-32-bytes"
    )
    return jwt.encode(
        claims,
        key,
        algorithm=algorithm,
        headers={"kid": "synthetic-context-api-key"},
    )


@pytest.fixture
def authenticator(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[EntraJwtAuthenticator, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class _JwkClient:
        def __init__(self, uri: str, *, cache_keys: bool) -> None:
            assert uri == (
                f"https://login.microsoftonline.com/{_TENANT_ID}/"
                "discovery/v2.0/keys"
            )
            assert cache_keys

        def get_signing_key_from_jwt(self, _token: str) -> object:
            return SimpleNamespace(key=private_key.public_key())

    monkeypatch.setattr(authorization_module.jwt, "PyJWKClient", _JwkClient)
    return (
        EntraJwtAuthenticator(
            tenant_id=_TENANT_ID,
            audience=_AUDIENCE,
            delegated_scope=_DELEGATED_SCOPE,
        ),
        private_key,
    )


def test_entra_jwt_authenticator_maps_signed_identity_types_deterministically(
    authenticator: tuple[EntraJwtAuthenticator, Any],
) -> None:
    verifier, private_key = authenticator

    human = verifier.authenticate_bearer(_token(_claims(), private_key))
    service = verifier.authenticate_bearer(
        _token(_claims(identity_type="app"), private_key)
    )
    explicit_user = verifier.authenticate_bearer(
        _token(_claims(identity_type="user"), private_key)
    )

    assert human.actor.actor_id == _HUMAN_OBJECT_ID
    assert human.actor.kind is ActorKind.HUMAN
    assert explicit_user.actor.kind is ActorKind.HUMAN
    assert service.actor.actor_id == _SERVICE_OBJECT_ID
    assert service.actor.kind is ActorKind.SERVICE
    assert human.method is AuthenticationMethod.ENTRA_JWT


def test_entra_jwt_authenticator_does_not_treat_agent_delegation_as_human(
    authenticator: tuple[EntraJwtAuthenticator, Any],
) -> None:
    verifier, private_key = authenticator
    claims = _claims(identity_type="user")
    claims["xms_act_fct"] = "11"
    claims["xms_sub_fct"] = "13"

    identity = verifier.authenticate_bearer(_token(claims, private_key))

    assert identity.actor.actor_id == _HUMAN_OBJECT_ID
    assert identity.actor.kind is ActorKind.AGENT


@pytest.mark.parametrize(
    "invalid_case",
    [
        "tenant",
        "audience",
        "issuer",
        "algorithm",
        "expired",
        "missing_delegated_scope",
        "unrelated_delegated_scope",
        "conflicting_app_scope",
        "conflicting_app_client_ids",
        "unknown_identity_type",
    ],
)
def test_entra_jwt_authenticator_rejects_invalid_signed_token_bindings(
    authenticator: tuple[EntraJwtAuthenticator, Any],
    invalid_case: str,
) -> None:
    verifier, private_key = authenticator
    claims = _claims()
    algorithm = "RS256"
    if invalid_case == "tenant":
        claims["tid"] = _OTHER_TENANT_ID
    elif invalid_case == "audience":
        claims["aud"] = "api://foreign-context"
    elif invalid_case == "issuer":
        claims["iss"] = (
            f"https://login.microsoftonline.com/{_OTHER_TENANT_ID}/v2.0"
        )
    elif invalid_case == "algorithm":
        algorithm = "HS256"
    elif invalid_case == "expired":
        now = datetime.now(tz=UTC)
        claims["iat"] = int((now - timedelta(minutes=20)).timestamp())
        claims["nbf"] = int((now - timedelta(minutes=20)).timestamp())
        claims["exp"] = int((now - timedelta(minutes=10)).timestamp())
    elif invalid_case == "missing_delegated_scope":
        del claims["scp"]
    elif invalid_case == "unrelated_delegated_scope":
        claims["scp"] = "Unrelated.Read"
    elif invalid_case == "conflicting_app_scope":
        claims = _claims(identity_type="app")
        claims["scp"] = _DELEGATED_SCOPE
    elif invalid_case == "conflicting_app_client_ids":
        claims = _claims(identity_type="app")
        claims["azp"] = _OTHER_TENANT_ID
    else:
        claims["idtyp"] = "agent"

    with pytest.raises(AuthenticationError, match="not verified"):
        verifier.authenticate_bearer(
            _token(claims, private_key, algorithm=algorithm)
        )


def test_entra_jwt_authenticator_rejects_oversized_bearer_input(
    authenticator: tuple[EntraJwtAuthenticator, Any],
) -> None:
    verifier, _private_key = authenticator

    with pytest.raises(AuthenticationError, match="not verified"):
        verifier.authenticate_bearer("a" * 8_193)


def test_entra_jwt_authenticator_rejects_configuration_exceeding_output_contract() -> None:
    with pytest.raises(ValueError, match="audience"):
        EntraJwtAuthenticator(
            tenant_id=_TENANT_ID,
            audience="a" * 257,
            delegated_scope=_DELEGATED_SCOPE,
        )

    with pytest.raises(ValueError, match="delegated scope"):
        EntraJwtAuthenticator(
            tenant_id=_TENANT_ID,
            audience=_AUDIENCE,
            delegated_scope="Athena Context Access",
        )
