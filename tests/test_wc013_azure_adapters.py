from __future__ import annotations

import hashlib
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from azure.core.exceptions import ResourceExistsError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import athena_context.azure_adapters as azure_adapters
from athena_context.api.evaluation_ports import SnapshotSigningRequest
from athena_context.azure_adapters import (
    AzureTableAttemptReplayGuard,
    DefaultAzureCredentialTrustedIngestionSigner,
    KeyVaultRsaSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import sha256_hex
from wc013_support import (
    CURRENT_NOW,
    MCP_CLIENT_ID,
    MCP_OBJECT_ID,
    TENANT_ID,
    key_anchor,
    key_resolver,
    trust_configuration,
)


class _Credential:
    pass


def test_key_vault_signer_hashes_preimage_and_uses_exact_rs256_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    anchor = key_anchor(private_key.public_key())
    calls: list[tuple[object, bytes]] = []

    class _CryptographyClient:
        def __init__(self, key_id: str, credential: object) -> None:
            assert key_id == anchor.key_vault_key_id
            assert isinstance(credential, _Credential)

        def sign(self, algorithm: object, digest: bytes) -> object:
            calls.append((algorithm, digest))
            return SimpleNamespace(signature=b"s" * 256)

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "CryptographyClient", _CryptographyClient)
    signer = KeyVaultRsaSigner(
        trusted_key_anchor=anchor,
        managed_identity_client_id=MCP_CLIENT_ID,
    )
    preimage = b'{"bounded":"canonical"}'
    signature = signer.sign(
        SnapshotSigningRequest(
            canonical_preimage=preimage,
            preimage_digest=sha256_hex(preimage),
            trusted_key_anchor=anchor,
        )
    )

    assert signature
    assert calls == [
        (
            azure_adapters.SignatureAlgorithm.rs256,
            hashlib.sha256(preimage).digest(),
        )
    ]


def test_key_vault_resolver_requires_exact_version_and_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    anchor = key_anchor(private_key.public_key())
    expected = key_resolver(private_key.public_key())(anchor)
    assert expected is not None
    expected_expires_at = expected.expires_at

    class _KeyClient:
        def __init__(self, *, vault_url: str, credential: object) -> None:
            assert vault_url == anchor.key_vault_key_id.split("/keys/", maxsplit=1)[0]
            assert isinstance(credential, _Credential)

        def get_key(self, name: str, version: str) -> object:
            assert (name, version) == (anchor.key_name, anchor.key_version)
            return SimpleNamespace(
                id=anchor.key_vault_key_id,
                key=SimpleNamespace(
                    n=public_numbers.n.to_bytes(
                        (public_numbers.n.bit_length() + 7) // 8,
                        "big",
                    ),
                    e=public_numbers.e.to_bytes(
                        (public_numbers.e.bit_length() + 7) // 8,
                        "big",
                    ),
                ),
                properties=SimpleNamespace(
                    enabled=True,
                    not_before=None,
                    expires_on=expected_expires_at,
                ),
            )

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "KeyClient", _KeyClient)
    resolver = KeyVaultTrustedKeyResolver(
        expected_record=expected,
        managed_identity_client_id=MCP_CLIENT_ID,
    )

    resolved = resolver(anchor)

    assert resolved is not None
    encoded = resolved.public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert sha256_hex(encoded) == anchor.public_key_fingerprint


def test_table_replay_guard_reserves_attempt_and_request_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batches: list[list[tuple[str, dict[str, object]]]] = []

    class _Table:
        def submit_transaction(
            self,
            operations: list[tuple[str, dict[str, object]]],
        ) -> None:
            if batches:
                raise ResourceExistsError("duplicate")
            batches.append(operations)

    class _TableServiceClient:
        def __init__(self, *, endpoint: str, credential: object) -> None:
            assert endpoint == "https://athenareplay.table.core.windows.net"
            assert isinstance(credential, _Credential)

        def get_table_client(self, table_name: str) -> _Table:
            assert table_name == "Wc013Replay"
            return _Table()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(
        azure_adapters,
        "TableServiceClient",
        _TableServiceClient,
    )
    guard = AzureTableAttemptReplayGuard(
        endpoint="https://athenareplay.table.core.windows.net",
        table_name="Wc013Replay",
        partition_key="wc013-live",
        managed_identity_client_id=MCP_CLIENT_ID,
    )

    assert guard.reserve("attempt-001", "sha256:" + ("1" * 64))
    assert not guard.reserve("attempt-001", "sha256:" + ("1" * 64))
    assert [operation for operation, _entity in batches[0]] == ["create", "create"]


def test_ingestion_token_verification_requires_exact_evidence_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    trust = trust_configuration()
    claims: dict[str, Any] = {
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "aud": trust.ingestion_audience,
        "tid": TENANT_ID,
        "oid": MCP_OBJECT_ID,
        "appid": MCP_CLIENT_ID,
        "sub": MCP_OBJECT_ID,
        "uti": "wc013-production-token-id",
        "iat": int((CURRENT_NOW - timedelta(minutes=1)).timestamp()),
        "nbf": int((CURRENT_NOW - timedelta(minutes=1)).timestamp()),
        "exp": int((CURRENT_NOW + timedelta(minutes=10)).timestamp()),
    }
    token = jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "wc013-key-id"},
    )

    class _JwkClient:
        def __init__(self, _uri: str, *, cache_keys: bool) -> None:
            assert cache_keys

        def get_signing_key_from_jwt(self, _token: str) -> object:
            return SimpleNamespace(key=private_key.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", _JwkClient)

    verified = DefaultAzureCredentialTrustedIngestionSigner._verify_token(
        token,
        tenant_id=TENANT_ID,
        audience=trust.ingestion_audience,
        managed_identity_object_id=MCP_OBJECT_ID,
        managed_identity_client_id=MCP_CLIENT_ID,
        as_of=CURRENT_NOW,
    )

    assert verified["claims"]["managedIdentityObjectId"] == MCP_OBJECT_ID
    assert verified["claims"]["managedIdentityClientId"] == MCP_CLIENT_ID
