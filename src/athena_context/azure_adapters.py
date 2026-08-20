from __future__ import annotations

import base64
import hashlib
import re
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlsplit

import jwt
from azure.core import MatchConditions
from azure.core.exceptions import HttpResponseError, ResourceExistsError
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from azure.storage.blob import BlobServiceClient, BlobType, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa

from athena_context.api.evaluation_ports import SnapshotSigningRequest
from athena_context.artifacts import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    ArtifactAlreadyExistsError,
    ArtifactPayloadTooLargeError,
    ArtifactWriteError,
    ArtifactWriteReceipt,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.models import (
    CollectorIdentityEvidence,
    compute_collector_identity_evidence_digest,
    compute_jti_digest,
    compute_token_verification_digest,
    compute_verified_claims_digest,
)
from athena_context.evidence import TrustedIngestionBinding

_GUID_CLAIMS = ("tid", "oid", "sub")
_JWT_REQUIRED_CLAIMS = ("aud", "exp", "iat", "iss", "nbf", "oid", "sub", "tid")


def _production_credential(
    *,
    managed_identity_client_id: str,
) -> DefaultAzureCredential:
    return DefaultAzureCredential(
        managed_identity_client_id=managed_identity_client_id,
        exclude_environment_credential=True,
        exclude_shared_token_cache_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_cli_credential=True,
        exclude_powershell_credential=True,
        exclude_developer_cli_credential=True,
        exclude_workload_identity_credential=True,
        exclude_broker_credential=True,
    )


def _minimum_datetime(
    first: datetime | None,
    second: datetime | None,
) -> datetime | None:
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


class KeyVaultRsaSigner:
    """RS256 signer backed by one exact non-exportable Key Vault key version."""

    def __init__(
        self,
        *,
        trusted_key_anchor: TrustedKeyAnchor,
        managed_identity_client_id: str,
    ) -> None:
        self._trusted_key_anchor = trusted_key_anchor
        credential = _production_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        self._client = CryptographyClient(
            trusted_key_anchor.key_vault_key_id,
            credential,
        )

    def sign(self, request: SnapshotSigningRequest) -> str:
        if (
            request.trusted_key_anchor != self._trusted_key_anchor
            or request.preimage_digest != sha256_hex(request.canonical_preimage)
        ):
            raise ValueError("snapshot signing request does not match the pinned key or digest")
        return self.sign_preimage(request.canonical_preimage)

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        digest = hashlib.sha256(canonical_preimage).digest()
        result = self._client.sign(SignatureAlgorithm.rs256, digest)
        signature = bytes(result.signature)
        if not signature:
            raise ValueError("Key Vault returned an empty RS256 signature")
        return base64.b64encode(signature).decode("ascii")


class KeyVaultTrustedKeyResolver:
    """Resolve only one operator-pinned Key Vault key version and public key."""

    def __init__(
        self,
        *,
        expected_record: TrustedKeyRecord,
        managed_identity_client_id: str,
    ) -> None:
        self._expected_record = expected_record
        anchor = expected_record.anchor
        vault_url = anchor.key_vault_key_id.split("/keys/", maxsplit=1)[0]
        credential = _production_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        self._client = KeyClient(vault_url=vault_url, credential=credential)

    def __call__(
        self,
        requested_anchor: TrustedKeyAnchor,
    ) -> TrustedKeyRecord | None:
        expected = self._expected_record
        if requested_anchor != expected.anchor:
            return None
        key = self._client.get_key(
            requested_anchor.key_name,
            requested_anchor.key_version,
        )
        key_id = str(key.id)
        if key_id != requested_anchor.key_vault_key_id:
            return None
        key_material = cast(Any, key.key)
        modulus = key_material.n
        exponent = key_material.e
        if not isinstance(modulus, bytes | bytearray) or not isinstance(
            exponent, bytes | bytearray
        ):
            return None
        public_key = rsa.RSAPublicNumbers(
            e=int.from_bytes(exponent, "big"),
            n=int.from_bytes(modulus, "big"),
        ).public_key()
        properties = key.properties
        if properties.enabled is False:
            return None
        activated_at = max(
            expected.activated_at,
            properties.not_before or expected.activated_at,
        )
        expires_at = _minimum_datetime(
            expected.expires_at,
            properties.expires_on,
        )
        try:
            return TrustedKeyRecord(
                anchor=requested_anchor,
                public_key=public_key,
                enabled=expected.enabled,
                activated_at=activated_at,
                retired_at=expected.retired_at,
                expires_at=expires_at,
            )
        except ValueError:
            return None


class AzureTableAttemptReplayGuard:
    """Atomically reserve attempt and request identities in one durable table batch."""

    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        partition_key: str,
        managed_identity_client_id: str,
    ) -> None:
        credential = _production_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        self._table = TableServiceClient(
            endpoint=endpoint,
            credential=credential,
        ).get_table_client(table_name)
        self._partition_key = partition_key

    def reserve(self, attempt_id: str, request_digest: str) -> bool:
        attempt_key = "attempt-" + hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()
        request_key = "request-" + hashlib.sha256(
            request_digest.encode("utf-8")
        ).hexdigest()
        operations = [
            (
                "create",
                {
                    "PartitionKey": self._partition_key,
                    "RowKey": attempt_key,
                    "kind": "attempt",
                    "digest": sha256_hex(attempt_id.encode("utf-8")),
                },
            ),
            (
                "create",
                {
                    "PartitionKey": self._partition_key,
                    "RowKey": request_key,
                    "kind": "request",
                    "digest": request_digest,
                },
            ),
        ]
        try:
            self._table.submit_transaction(operations)
        except ResourceExistsError:
            return False
        except HttpResponseError as exc:
            if exc.status_code == 409:
                return False
            raise
        return True


class AzureBlobCreateOnlyArtifactWriter:
    """Write one bounded JSON blob version without overwrite, listing, or deletion."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
        max_payload_bytes: int = MAX_ARTIFACT_PAYLOAD_BYTES,
    ) -> None:
        self._validate_blob_endpoint(blob_endpoint)
        if (
            type(container_name) is not str
            or re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?",
                container_name,
            )
            is None
            or "--" in container_name
        ):
            raise ValueError("container_name must be a valid lowercase Azure Blob container")
        if (
            type(max_payload_bytes) is not int
            or not 1 <= max_payload_bytes <= MAX_ARTIFACT_PAYLOAD_BYTES
        ):
            raise ValueError(
                f"max_payload_bytes must be between 1 and {MAX_ARTIFACT_PAYLOAD_BYTES}"
            )
        credential = _production_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_put_size=max_payload_bytes,
        )
        self._container = service.get_container_client(container_name)
        self._container_name = container_name
        self._max_payload_bytes = max_payload_bytes

    @staticmethod
    def _validate_blob_endpoint(blob_endpoint: str) -> None:
        if type(blob_endpoint) is not str:
            raise TypeError("blob_endpoint must be an exact string")
        parsed = urlsplit(blob_endpoint)
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or hostname is None
            or re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", hostname)
            is None
        ):
            raise ValueError("blob_endpoint must be an Azure public-cloud Blob HTTPS origin")

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt:
        if type(request) is not ArtifactWriteRequest:
            raise TypeError("request must be an exact ArtifactWriteRequest")
        size_bytes = len(request.payload)
        if size_bytes > self._max_payload_bytes:
            raise ArtifactPayloadTooLargeError(
                f"artifact payload exceeds {self._max_payload_bytes} bytes"
            )
        blob = self._container.get_blob_client(request.blob_name)
        try:
            response = blob.upload_blob(
                request.payload,
                blob_type=BlobType.BLOCKBLOB,
                length=size_bytes,
                metadata=request.hashes.as_blob_metadata(),
                overwrite=False,
                match_condition=MatchConditions.IfMissing,
                content_settings=ContentSettings(content_type=request.content_type),
            )
        except ResourceExistsError as exc:
            error_code = getattr(exc, "error_code", None)
            normalized_code = getattr(error_code, "value", error_code)
            if normalized_code != "BlobAlreadyExists":
                raise
            raise ArtifactAlreadyExistsError(
                f"artifact blob already exists: {request.blob_name}"
            ) from exc

        etag = response.get("etag")
        version_id = response.get("version_id")
        last_modified = response.get("last_modified")
        if (
            type(etag) is not str
            or not etag
            or type(version_id) is not str
            or not version_id
            or not isinstance(last_modified, datetime)
            or last_modified.tzinfo is None
        ):
            raise ArtifactWriteError(
                "Blob upload response omitted the version-pinned immutable receipt"
            )
        return ArtifactWriteReceipt(
            container_name=self._container_name,
            blob_name=request.blob_name,
            version_id=version_id,
            etag=etag,
            last_modified=last_modified,
            size_bytes=size_bytes,
            payload_sha256=request.hashes.payload_sha256,
        )


class DefaultAzureCredentialTrustedIngestionSigner:
    """Verify an evidence-identity Entra token and bind it with Key Vault RS256."""

    def __init__(
        self,
        *,
        trusted_key_anchor: TrustedKeyAnchor,
        signing_identity_client_id: str,
        evidence_identity_client_id: str,
    ) -> None:
        self._trusted_key_anchor = trusted_key_anchor
        self._evidence_identity_client_id = evidence_identity_client_id
        self._credential = _production_credential(
            managed_identity_client_id=evidence_identity_client_id
        )
        self._signer = KeyVaultRsaSigner(
            trusted_key_anchor=trusted_key_anchor,
            managed_identity_client_id=signing_identity_client_id,
        )

    def bind_attempt(
        self,
        binding: TrustedIngestionBinding,
    ) -> CollectorIdentityEvidence:
        trust = binding.trust_configuration
        if (
            trust.trust_anchor_ref != self._trusted_key_anchor.key_vault_key_id
            or trust.managed_identity_client_id != self._evidence_identity_client_id
        ):
            raise ValueError("trusted ingestion identity or signing anchor changed")
        token = self._credential.get_token(
            f"{trust.ingestion_audience.rstrip('/')}/.default"
        ).token
        verified = self._verify_token(
            token,
            tenant_id=trust.tenant_id,
            audience=trust.ingestion_audience,
            managed_identity_object_id=trust.managed_identity_object_id,
            managed_identity_client_id=trust.managed_identity_client_id,
            as_of=binding.as_of,
        )
        attempt = binding.collector_attempt
        attempt_payload = attempt.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
        )
        attempt_binding = {
            key: value
            for key, value in attempt_payload.items()
            if key
            in {
                "attemptId",
                "attemptType",
                "attemptDigest",
                "toolName",
                "toolVersion",
                "requestDigest",
                "responseDigest",
                "failureDigest",
                "attemptStartedAt",
                "responseReceivedAt",
                "deadlineAt",
                "timedOutAt",
                "observedAt",
            }
        }
        derivation: dict[str, object] = {
            "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
            "derivationPreimageVersion": "1.0.0",
            "schemaVersion": trust.schema_version,
            "semanticContractVersion": trust.semantic_contract_version,
            "policyContractVersion": trust.policy_contract_version,
            "identityEvidenceId": trust.collector_identity_evidence_ref,
            "tokenHash": verified["token_hash"],
            "tokenVerificationStatus": "valid",
            "tokenVerificationDigest": verified["verification"]["tokenVerificationDigest"],
            "verifiedClaimsDigest": verified["claims_digest"],
            "jtiDigest": verified["claims"]["jtiDigest"],
            "mcpHostId": trust.mcp_host_id,
            "mcpHostTenantId": trust.tenant_id,
            "mcpHostManagedIdentityObjectId": trust.managed_identity_object_id,
            "mcpHostManagedIdentityClientId": trust.managed_identity_client_id,
            "ingestionServiceId": trust.ingestion_service_id,
            "ingestionAudience": trust.ingestion_audience,
            "toolAllowlistDigest": trust.tool_allowlist_digest,
            "derivedCollectorIdentityRef": trust.collector_identity_evidence_ref,
            "attemptBinding": attempt_binding,
            "derivedAt": binding.as_of,
        }
        derivation["derivationDigest"] = compute_artifact_digest(derivation)
        derivation_preimage = {
            key: value for key, value in derivation.items() if key != "derivationDigest"
        }
        anchor = self._trusted_key_anchor
        signature_preimage: dict[str, object] = {
            "signaturePreimageType": "athena.trustedIngestionSignature",
            "signaturePreimageVersion": "1.0.0",
            "signatureAlgorithm": "RS256",
            "keyVaultKeyId": anchor.key_vault_key_id,
            "keyName": anchor.key_name,
            "keyVersion": anchor.key_version,
            "signedAt": binding.as_of,
            "trustAnchorRef": anchor.key_vault_key_id,
            "derivation": derivation_preimage,
        }
        signature = self._signer.sign_preimage(
            canonicalize_json(signature_preimage).encode("utf-8")
        )
        identity: dict[str, object] = {
            "identityEvidenceId": trust.collector_identity_evidence_ref,
            "identityEvidenceType": "entraJwtTokenEvidence",
            "tokenHash": verified["token_hash"],
            "jwtHeader": verified["header"],
            "trustAnchorRef": anchor.key_vault_key_id,
            "verifiedClaims": verified["claims"],
            "tokenVerification": verified["verification"],
            "ingestionDerivation": derivation,
            "ingestionSignature": {
                "signatureAlgorithm": "RS256",
                "keyVaultKeyId": anchor.key_vault_key_id,
                "keyName": anchor.key_name,
                "keyVersion": anchor.key_version,
                "signedPreimageDigest": compute_artifact_digest(signature_preimage),
                "signature": signature,
                "signedAt": binding.as_of,
                "trustAnchorRef": anchor.key_vault_key_id,
            },
        }
        identity["identityEvidenceDigest"] = compute_collector_identity_evidence_digest(
            identity
        )
        return CollectorIdentityEvidence.model_validate(identity)

    @staticmethod
    def _verify_token(
        token: str,
        *,
        tenant_id: str,
        audience: str,
        managed_identity_object_id: str,
        managed_identity_client_id: str,
        as_of: datetime,
    ) -> dict[str, Any]:
        if not token or token != token.strip() or any(character in token for character in "\r\n"):
            raise ValueError("managed identity returned an invalid ingestion token")
        header = jwt.get_unverified_header(token)
        issuer = cast(str, jwt.decode(token, options={"verify_signature": False})["iss"])
        allowed_issuers = {
            f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            f"https://sts.windows.net/{tenant_id}/",
        }
        if issuer not in allowed_issuers:
            raise ValueError("ingestion token issuer is not the configured tenant")
        jwks_client = jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
        )
        signing_key = jwks_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={
                "require": list(_JWT_REQUIRED_CLAIMS),
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        for claim in _GUID_CLAIMS:
            if not isinstance(claims.get(claim), str):
                raise ValueError(f"ingestion token claim {claim!r} is invalid")
        client_id = claims.get("appid", claims.get("azp"))
        if (
            claims["tid"] != tenant_id
            or claims["oid"] != managed_identity_object_id
            or client_id != managed_identity_client_id
            or claims["sub"] not in {managed_identity_object_id, managed_identity_client_id}
        ):
            raise ValueError("ingestion token identity claims do not match WC-008")
        issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=UTC)
        not_before = datetime.fromtimestamp(int(claims["nbf"]), tz=UTC)
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
        normalized_as_of = as_of.astimezone(UTC)
        if not issued_at <= not_before <= normalized_as_of < expires_at:
            raise ValueError("ingestion token is outside its trusted lifetime")
        token_identifier = claims.get("jti", claims.get("uti"))
        kid = header.get("kid")
        if (
            header.get("alg") != "RS256"
            or header.get("typ") != "JWT"
            or not isinstance(kid, str)
            or not isinstance(token_identifier, str)
        ):
            raise ValueError("ingestion token JOSE metadata is invalid")
        verified_claims: dict[str, object] = {
            "issuer": issuer,
            "audience": audience,
            "tenantId": tenant_id,
            "managedIdentityObjectId": managed_identity_object_id,
            "managedIdentityClientId": managed_identity_client_id,
            "subject": claims["sub"],
            "jtiDigest": compute_jti_digest(token_identifier),
            "issuedAt": issued_at,
            "notBefore": not_before,
            "expiresAt": expires_at,
        }
        claims_digest = compute_verified_claims_digest(verified_claims)
        verification: dict[str, object] = {
            "status": "valid",
            "verifiedAt": normalized_as_of,
            "keyId": kid,
            "verifiedClaims": verified_claims,
            "verifiedClaimsDigest": claims_digest,
            "jtiDigest": verified_claims["jtiDigest"],
        }
        verification["tokenVerificationDigest"] = compute_token_verification_digest(
            verification
        )
        return {
            "token_hash": sha256_hex(token.encode("utf-8")),
            "header": {"alg": "RS256", "kid": kid, "typ": "JWT"},
            "claims": verified_claims,
            "claims_digest": claims_digest,
            "verification": verification,
        }


__all__ = [
    "AzureBlobCreateOnlyArtifactWriter",
    "AzureTableAttemptReplayGuard",
    "DefaultAzureCredentialTrustedIngestionSigner",
    "KeyVaultRsaSigner",
    "KeyVaultTrustedKeyResolver",
]
