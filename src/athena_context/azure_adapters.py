from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn, cast
from urllib.parse import urlsplit

import jwt
from azure.core import MatchConditions
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
)
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from azure.storage.blob import BlobServiceClient, BlobType, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa

from athena_context.artifacts import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    MAX_ARTIFACT_TRANSFER_BYTES,
    ArtifactAlreadyExistsError,
    ArtifactCurrentReadRequest,
    ArtifactNotFoundError,
    ArtifactPayloadTooLargeError,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactReadTooLargeError,
    ArtifactVerificationError,
    ArtifactWriteError,
    ArtifactWriteReceipt,
    ArtifactWriteRequest,
)
from athena_context.contracts import (
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentState,
    IncidentStateAttestation,
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
from athena_context.presentation_assets import (
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    ActiveIncidentIndexPublicationRequest,
    ActiveIncidentIndexSnapshot,
    CurrentIncidentStateSnapshot,
    IncidentPublicationReceipt,
    IncidentPublicationRequest,
    PresentationAssetAlreadyExistsError,
    PresentationAssetReadResult,
    PresentationAssetUnavailableError,
    PresentationPublicationReceipt,
    PresentationPublicationRequest,
)

if TYPE_CHECKING:
    from athena_context.api.evaluation_ports import SnapshotSigningRequest

_GUID_CLAIMS = ("tid", "oid", "sub")
_JWT_REQUIRED_CLAIMS = ("aud", "exp", "iat", "iss", "nbf", "oid", "sub", "tid")
_BLOB_CONTAINER_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?"
)


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


def production_managed_identity_credential(
    *,
    managed_identity_client_id: str,
) -> DefaultAzureCredential:
    """Build the production managed-identity-only credential chain."""

    return _production_credential(
        managed_identity_client_id=managed_identity_client_id
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


def _validate_container_name(container_name: str) -> None:
    if (
        type(container_name) is not str
        or _BLOB_CONTAINER_PATTERN.fullmatch(container_name) is None
        or "--" in container_name
    ):
        raise ValueError("container_name must be a valid lowercase Azure Blob container")


def _reject_non_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON constant is not allowed: {value}")


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

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        detached_signature: str,
    ) -> bool:
        try:
            signature = base64.urlsafe_b64decode(
                detached_signature + "=" * (-len(detached_signature) % 4)
            )
        except (TypeError, ValueError):
            return False
        if not signature:
            return False
        digest = hashlib.sha256(canonical_preimage).digest()
        return bool(
            self._client.verify(
                SignatureAlgorithm.rs256,
                digest,
                signature,
            ).is_valid
        )


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
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if (
            type(max_payload_bytes) is not int
            or not 1 <= max_payload_bytes <= MAX_ARTIFACT_TRANSFER_BYTES
        ):
            raise ValueError(
                f"max_payload_bytes must be between 1 and {MAX_ARTIFACT_TRANSFER_BYTES}"
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

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt:
        if type(request) is not ArtifactWriteRequest:
            raise TypeError("request must be an exact ArtifactWriteRequest")
        if request.maximum_payload_bytes > self._max_payload_bytes:
            raise ArtifactPayloadTooLargeError(
                "artifact request bound exceeds the writer's configured bound"
            )
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


class AzureBlobPresentationAssetPublisher:
    """Publish only to the private presentation-assets Blob container."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if container_name != "presentation-assets":
            raise ValueError("container_name must be exactly presentation-assets")
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_put_size=MAX_ARTIFACT_PAYLOAD_BYTES,
        )
        self._container = service.get_container_client(container_name)

    def publish(
        self,
        request: PresentationPublicationRequest,
    ) -> PresentationPublicationReceipt:
        if type(request) is not PresentationPublicationRequest:
            raise TypeError(
                "request must be an exact PresentationPublicationRequest"
            )
        for asset in request.assets:
            blob = self._container.get_blob_client(asset.blob_name)
            try:
                blob.upload_blob(
                    asset.payload,
                    blob_type=BlobType.BLOCKBLOB,
                    length=len(asset.payload),
                    metadata={"payload_sha256": asset.payload_sha256},
                    overwrite=False,
                    match_condition=MatchConditions.IfMissing,
                    content_settings=ContentSettings(
                        content_type="application/json"
                    ),
                )
            except ResourceExistsError as exc:
                error_code = getattr(exc, "error_code", None)
                normalized_code = getattr(error_code, "value", error_code)
                if normalized_code != "BlobAlreadyExists":
                    raise
                try:
                    downloader = blob.download_blob(
                        offset=0,
                        length=asset.maximum_bytes + 1,
                        max_concurrency=1,
                    )
                    properties = downloader.properties
                    size = getattr(downloader, "size", None)
                    content_settings = getattr(properties, "content_settings", None)
                    metadata = getattr(properties, "metadata", None)
                    existing_payload = downloader.readall()
                except Exception as read_exc:  # noqa: BLE001 - Blob is a trust boundary.
                    raise PresentationAssetAlreadyExistsError(
                        "an immutable presentation run asset could not be verified"
                    ) from read_exc
                if (
                    size != len(asset.payload)
                    or existing_payload != asset.payload
                    or getattr(content_settings, "content_type", None)
                    != "application/json"
                    or type(metadata) is not dict
                    or metadata.get("payload_sha256") != asset.payload_sha256
                ):
                    raise PresentationAssetAlreadyExistsError(
                        "an immutable presentation run asset already exists with different content"
                    ) from exc
        manifest_bytes = request.manifest.canonical_bytes()
        manifest_sha256 = sha256_hex(manifest_bytes)
        manifest_blob = self._container.get_blob_client("runtime-manifest.json")
        manifest_blob.upload_blob(
            manifest_bytes,
            blob_type=BlobType.BLOCKBLOB,
            length=len(manifest_bytes),
            metadata={"payload_sha256": manifest_sha256},
            overwrite=True,
            content_settings=ContentSettings(content_type="application/json"),
        )
        return PresentationPublicationReceipt(
            run_id=request.manifest.run_id,
            manifest_blob_name="runtime-manifest.json",
            manifest_sha256=manifest_sha256,
        )

class AzureBlobPresentationAssetReader:
    """Read current blobs only from the private presentation-assets container."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if container_name != "presentation-assets":
            raise ValueError("container_name must be exactly presentation-assets")
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_get_size=MAX_ARTIFACT_PAYLOAD_BYTES + 1,
            max_chunk_get_size=MAX_ARTIFACT_PAYLOAD_BYTES + 1,
        )
        self._container = service.get_container_client(container_name)

    def read_current(
        self,
        *,
        blob_name: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        if (
            type(blob_name) is not str
            or not blob_name
            or blob_name.startswith("/")
            or "\\" in blob_name
            or "%" in blob_name
            or any(segment in {"", ".", ".."} for segment in blob_name.split("/"))
        ):
            raise ValueError("blob_name is not a bounded relative path")
        if (
            type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= MAX_ARTIFACT_PAYLOAD_BYTES
        ):
            raise ValueError("maximum_bytes is outside the presentation bound")
        blob = self._container.get_blob_client(blob_name)
        try:
            downloader = blob.download_blob(
                offset=0,
                length=maximum_bytes + 1,
                max_concurrency=1,
            )
            properties = downloader.properties
            size = getattr(downloader, "size", None)
            if type(size) is not int or not 1 <= size <= maximum_bytes:
                raise PresentationAssetUnavailableError(
                    "presentation asset size is invalid"
                )
            content_settings = getattr(properties, "content_settings", None)
            if getattr(content_settings, "content_type", None) != "application/json":
                raise PresentationAssetUnavailableError(
                    "presentation asset content type is invalid"
                )
            payload = downloader.readall()
            if type(payload) is not bytes or not 1 <= len(payload) <= maximum_bytes:
                raise PresentationAssetUnavailableError(
                    "presentation asset transfer is invalid"
                )
            payload_sha256 = sha256_hex(payload)
            metadata = getattr(properties, "metadata", None)
            if (
                type(metadata) is not dict
                or metadata.get("payload_sha256") != payload_sha256
            ):
                raise PresentationAssetUnavailableError(
                    "presentation asset metadata digest is invalid"
                )
        except ResourceNotFoundError as exc:
            raise PresentationAssetUnavailableError(
                "presentation asset is unavailable"
            ) from exc
        except HttpResponseError as exc:
            raise PresentationAssetUnavailableError(
                "presentation asset is unavailable"
            ) from exc
        return PresentationAssetReadResult(
            blob_name=blob_name,
            payload=payload,
            payload_sha256=payload_sha256,
        )


class AzureBlobIncidentAssetPublisher:
    """Publish only signed WC-016 assets to the private incident-assets container."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
        signing_key_id: str,
        signing_key_fingerprint: str,
        signature_verifier: Callable[[bytes, str], bool],
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if container_name != "incident-assets":
            raise ValueError("container_name must be exactly incident-assets")
        if not signing_key_id or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", signing_key_fingerprint
        ):
            raise ValueError("incident signing trust anchor is invalid")
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_put_size=MAX_ARTIFACT_PAYLOAD_BYTES,
            max_single_get_size=MAX_INCIDENT_STATE_BYTES + 1,
            max_chunk_get_size=MAX_INCIDENT_STATE_BYTES + 1,
        )
        self._container = service.get_container_client(container_name)
        self._signing_key_id = signing_key_id
        self._signing_key_fingerprint = signing_key_fingerprint
        self._signature_verifier = signature_verifier

    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None:
        blob = self._container.get_blob_client("incidents/active.json")
        try:
            downloader = blob.download_blob(
                offset=0,
                length=MAX_INCIDENT_STATE_BYTES + 1,
                max_concurrency=1,
            )
            payload = downloader.readall()
        except ResourceNotFoundError:
            return None
        except HttpResponseError as exc:
            raise PresentationAssetUnavailableError(
                "active incident index is unavailable"
            ) from exc
        if not 1 <= len(payload) <= MAX_INCIDENT_STATE_BYTES:
            raise PresentationAssetUnavailableError(
                "active incident index is outside its byte bound"
            )
        index = ActiveIncidentIndex.model_validate_json(payload)
        if (
            payload != index.canonical_bytes()
            or index.key_id != self._signing_key_id
            or index.key_fingerprint != self._signing_key_fingerprint
        ):
            raise PresentationAssetUnavailableError(
                "active incident index trust binding is invalid"
            )
        attestation_blob = self._container.get_blob_client(
            index.index_attestation_path.removeprefix("./")
        )
        try:
            attestation_payload = attestation_blob.download_blob(
                offset=0,
                length=MAX_PRESENTATION_ATTESTATION_BYTES + 1,
                max_concurrency=1,
            ).readall()
        except (ResourceNotFoundError, HttpResponseError) as exc:
            raise PresentationAssetUnavailableError(
                "active incident index attestation is unavailable"
            ) from exc
        if not 1 <= len(attestation_payload) <= MAX_PRESENTATION_ATTESTATION_BYTES:
            raise PresentationAssetUnavailableError(
                "active incident index attestation is outside its byte bound"
            )
        try:
            attestation = ActiveIncidentIndexAttestation.model_validate_json(
                attestation_payload
            )
        except ValueError as exc:
            raise PresentationAssetUnavailableError(
                "active incident index attestation is invalid"
            ) from exc
        if (
            attestation_payload != attestation.canonical_bytes()
            or attestation.index_digest != sha256_hex(payload)
            or attestation.key_vault_key_id != self._signing_key_id
            or not self._signature_verifier(
                payload,
                attestation.detached_signature,
            )
        ):
            raise PresentationAssetUnavailableError(
                "active incident index signature is invalid"
            )
        return ActiveIncidentIndexSnapshot(
            index=index,
            payload_sha256=sha256_hex(payload),
        )

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None:
        if re.fullmatch(r"inc-[a-f0-9]{12}", incident_id) is None:
            raise ValueError("incident_id is invalid")
        pointer_payload = self._read_incident_json_blob(
            f"incidents/{incident_id}/current.json",
            maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
            allow_missing=True,
        )
        if pointer_payload is None:
            return None
        try:
            pointer = IncidentFeedPointer.model_validate_json(pointer_payload)
        except ValueError as exc:
            raise PresentationAssetUnavailableError(
                "current incident pointer is invalid"
            ) from exc
        if (
            pointer_payload != pointer.canonical_bytes()
            or pointer.incident_id != incident_id
            or pointer.key_id != self._signing_key_id
            or pointer.key_fingerprint != self._signing_key_fingerprint
        ):
            raise PresentationAssetUnavailableError(
                "current incident pointer trust binding is invalid"
            )
        pointer_attestation_payload = self._read_incident_json_blob(
            pointer.pointer_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        state_payload = self._read_incident_json_blob(
            pointer.state_path.removeprefix("./"),
            maximum_bytes=MAX_INCIDENT_STATE_BYTES,
        )
        state_attestation_payload = self._read_incident_json_blob(
            pointer.attestation_path.removeprefix("./"),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        if (
            pointer_attestation_payload is None
            or state_payload is None
            or state_attestation_payload is None
        ):
            raise PresentationAssetUnavailableError(
                "current incident state is unavailable"
            )
        try:
            pointer_attestation = IncidentFeedAttestation.model_validate_json(
                pointer_attestation_payload
            )
            state = IncidentState.model_validate_json(state_payload)
            state_attestation = IncidentStateAttestation.model_validate_json(
                state_attestation_payload
            )
        except ValueError as exc:
            raise PresentationAssetUnavailableError(
                "current incident state is invalid"
            ) from exc
        unsigned_state = state.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
        )
        state_preimage = canonicalize_json(unsigned_state).encode("utf-8")
        state_version = pointer.state_path.removeprefix(
            f"./incidents/{incident_id}/versions/"
        ).removesuffix("/state.json")
        if (
            pointer_attestation_payload != pointer_attestation.canonical_bytes()
            or pointer_attestation.pointer_digest != sha256_hex(pointer_payload)
            or pointer_attestation.key_vault_key_id != self._signing_key_id
            or not self._signature_verifier(
                pointer_payload,
                pointer_attestation.detached_signature,
            )
            or state_payload != state.canonical_bytes()
            or pointer.state_sha256 != sha256_hex(state_payload)
            or state.incident_id != incident_id
            or state.result_digest != sha256_hex(state_preimage)
            or state_version != state.result_digest.removeprefix("sha256:")
            or state_attestation_payload != state_attestation.canonical_bytes()
            or pointer.attestation_sha256 != sha256_hex(state_attestation_payload)
            or state_attestation.result_digest != state.result_digest
            or state_attestation.key_vault_key_id != self._signing_key_id
            or not self._signature_verifier(
                state_preimage,
                state_attestation.detached_signature,
            )
            or pointer.published_at < state.updated_at
        ):
            raise PresentationAssetUnavailableError(
                "current incident state trust binding is invalid"
            )
        return CurrentIncidentStateSnapshot(
            state=state,
            pointer=pointer,
            pointer_sha256=sha256_hex(pointer_payload),
        )

    def publish_incident(
        self,
        request: IncidentPublicationRequest,
    ) -> IncidentPublicationReceipt:
        if type(request) is not IncidentPublicationRequest:
            raise TypeError("request must be an exact IncidentPublicationRequest")
        if (
            request.pointer.key_id != self._signing_key_id
            or request.pointer.key_fingerprint != self._signing_key_fingerprint
            or request.active_index.key_id != self._signing_key_id
            or request.active_index.key_fingerprint
            != self._signing_key_fingerprint
        ):
            raise ValueError("incident publication trust anchor is invalid")
        for asset in (
            request.state,
            request.attestation,
            request.pointer_asset,
            request.pointer_attestation_asset,
            request.active_index_attestation_asset,
        ):
            self._upload_immutable(asset)
        self._publish_current_pointer(request)
        self._publish_active_index(request)
        return IncidentPublicationReceipt(
            incident_id=request.pointer.incident_id,
            pointer_sha256=request.pointer_asset.payload_sha256,
            active_index_sha256=request.active_index_asset.payload_sha256,
        )

    def publish_active_incident_index(
        self,
        request: ActiveIncidentIndexPublicationRequest,
    ) -> ActiveIncidentIndexSnapshot:
        if type(request) is not ActiveIncidentIndexPublicationRequest:
            raise TypeError(
                "request must be an exact ActiveIncidentIndexPublicationRequest"
            )
        if (
            request.active_index.key_id != self._signing_key_id
            or request.active_index.key_fingerprint
            != self._signing_key_fingerprint
        ):
            raise ValueError("active incident index trust anchor is invalid")
        self._upload_immutable(request.active_index_attestation_asset)
        self._publish_active_index(request)
        return ActiveIncidentIndexSnapshot(
            index=request.active_index,
            payload_sha256=request.active_index_asset.payload_sha256,
        )

    def _upload_immutable(self, asset: Any) -> None:
        blob = self._container.get_blob_client(asset.blob_name)
        try:
            blob.upload_blob(
                asset.payload,
                blob_type=BlobType.BLOCKBLOB,
                length=len(asset.payload),
                metadata={"payload_sha256": asset.payload_sha256},
                overwrite=False,
                match_condition=MatchConditions.IfMissing,
                content_settings=ContentSettings(content_type="application/json"),
            )
        except ResourceExistsError as exc:
            error_code = getattr(exc, "error_code", None)
            normalized_code = getattr(error_code, "value", error_code)
            if normalized_code != "BlobAlreadyExists":
                raise
            try:
                downloader = blob.download_blob(
                    offset=0,
                    length=asset.maximum_bytes + 1,
                    max_concurrency=1,
                )
                properties = downloader.properties
                existing_payload = downloader.readall()
            except Exception as read_exc:  # noqa: BLE001 - Blob is a trust boundary.
                raise PresentationAssetAlreadyExistsError(
                    "an immutable incident asset could not be verified"
                ) from read_exc
            content_settings = getattr(properties, "content_settings", None)
            metadata = getattr(properties, "metadata", None)
            if (
                existing_payload != asset.payload
                or getattr(content_settings, "content_type", None)
                != "application/json"
                or type(metadata) is not dict
                or metadata.get("payload_sha256") != asset.payload_sha256
            ):
                raise PresentationAssetAlreadyExistsError(
                    "an immutable incident asset already exists with different content"
                ) from exc

    def _read_incident_json_blob(
        self,
        blob_name: str,
        *,
        maximum_bytes: int,
        allow_missing: bool = False,
    ) -> bytes | None:
        blob = self._container.get_blob_client(blob_name)
        try:
            downloader = blob.download_blob(
                offset=0,
                length=maximum_bytes + 1,
                max_concurrency=1,
            )
            properties = downloader.properties
            payload = downloader.readall()
        except ResourceNotFoundError:
            if allow_missing:
                return None
            raise PresentationAssetUnavailableError(
                "current incident asset is unavailable"
            ) from None
        except HttpResponseError as exc:
            raise PresentationAssetUnavailableError(
                "current incident asset is unavailable"
            ) from exc
        content_settings = getattr(properties, "content_settings", None)
        metadata = getattr(properties, "metadata", None)
        if (
            type(payload) is not bytes
            or not 1 <= len(payload) <= maximum_bytes
            or getattr(content_settings, "content_type", None) != "application/json"
            or type(metadata) is not dict
            or metadata.get("payload_sha256") != sha256_hex(payload)
        ):
            raise PresentationAssetUnavailableError(
                "current incident asset metadata is invalid"
            )
        return payload

    def _publish_current_pointer(self, request: IncidentPublicationRequest) -> None:
        asset = request.current_pointer_asset
        blob = self._container.get_blob_client(asset.blob_name)
        try:
            current = blob.download_blob(
                offset=0,
                length=asset.maximum_bytes + 1,
                max_concurrency=1,
            )
            current_bytes = current.readall()
        except ResourceNotFoundError:
            self._upload_missing_mutable(blob, asset)
            return
        except HttpResponseError as exc:
            raise PresentationAssetAlreadyExistsError(
                "current incident pointer is unavailable"
            ) from exc
        content_settings = getattr(current.properties, "content_settings", None)
        metadata = getattr(current.properties, "metadata", None)
        if (
            type(current_bytes) is not bytes
            or not 1 <= len(current_bytes) <= asset.maximum_bytes
            or getattr(content_settings, "content_type", None) != "application/json"
            or type(metadata) is not dict
            or metadata.get("payload_sha256") != sha256_hex(current_bytes)
        ):
            raise PresentationAssetAlreadyExistsError(
                "current incident pointer is invalid"
            )
        if current_bytes == asset.payload:
            return
        try:
            current_pointer = IncidentFeedPointer.model_validate_json(current_bytes)
        except ValueError as exc:
            raise PresentationAssetAlreadyExistsError(
                "current incident pointer is invalid"
            ) from exc
        if (
            current_bytes != current_pointer.canonical_bytes()
            or current_pointer.incident_id != request.pointer.incident_id
            or current_pointer.key_id != self._signing_key_id
            or current_pointer.key_fingerprint != self._signing_key_fingerprint
            or request.pointer.published_at <= current_pointer.published_at
        ):
            raise PresentationAssetAlreadyExistsError(
                "current incident pointer publication is not newer and trusted"
            )
        self._replace_mutable(blob, asset, current)

    def _publish_active_index(
        self,
        request: IncidentPublicationRequest | ActiveIncidentIndexPublicationRequest,
    ) -> None:
        blob = self._container.get_blob_client(request.active_index_asset.blob_name)
        try:
            current = blob.download_blob(
                offset=0,
                length=request.active_index_asset.maximum_bytes + 1,
                max_concurrency=1,
            )
            current_bytes = current.readall()
        except ResourceNotFoundError:
            if request.previous_active_index_sha256 is not None:
                raise PresentationAssetAlreadyExistsError(
                    "active incident index disappeared during publication"
                ) from None
            self._upload_missing_mutable(blob, request.active_index_asset)
            return
        if current_bytes == request.active_index_asset.payload:
            return
        if (
            request.previous_active_index_sha256 is None
            or sha256_hex(current_bytes) != request.previous_active_index_sha256
        ):
            raise PresentationAssetAlreadyExistsError(
                "active incident index changed during publication"
            )
        current_index = ActiveIncidentIndex.model_validate_json(current_bytes)
        if (
            current_bytes != current_index.canonical_bytes()
            or current_index.key_id != self._signing_key_id
            or current_index.key_fingerprint != self._signing_key_fingerprint
            or request.active_index.published_at <= current_index.published_at
        ):
            raise PresentationAssetAlreadyExistsError(
                "active incident index publication is not newer and trusted"
            )
        self._replace_mutable(blob, request.active_index_asset, current)

    @staticmethod
    def _upload_missing_mutable(blob: Any, asset: Any) -> None:
        try:
            blob.upload_blob(
                asset.payload,
                blob_type=BlobType.BLOCKBLOB,
                length=len(asset.payload),
                metadata={"payload_sha256": asset.payload_sha256},
                overwrite=False,
                match_condition=MatchConditions.IfMissing,
                content_settings=ContentSettings(content_type="application/json"),
            )
        except ResourceExistsError as exc:
            raise PresentationAssetAlreadyExistsError(
                "mutable incident asset was created concurrently"
            ) from exc

    @staticmethod
    def _replace_mutable(blob: Any, asset: Any, current: Any) -> None:
        etag = getattr(current.properties, "etag", None)
        if not isinstance(etag, str) or not etag:
            raise PresentationAssetAlreadyExistsError(
                "mutable incident asset omitted its concurrency token"
            )
        try:
            blob.upload_blob(
                asset.payload,
                blob_type=BlobType.BLOCKBLOB,
                length=len(asset.payload),
                metadata={"payload_sha256": asset.payload_sha256},
                overwrite=True,
                etag=etag,
                match_condition=MatchConditions.IfNotModified,
                content_settings=ContentSettings(content_type="application/json"),
            )
        except ResourceModifiedError as exc:
            raise PresentationAssetAlreadyExistsError(
                "mutable incident asset changed during conditional publication"
            ) from exc


class AzureBlobIncidentAssetReader(AzureBlobPresentationAssetReader):
    """Read only from the dedicated private incident-assets container."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if container_name != "incident-assets":
            raise ValueError("container_name must be exactly incident-assets")
        credential = production_managed_identity_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_get_size=MAX_ARTIFACT_PAYLOAD_BYTES + 1,
            max_chunk_get_size=MAX_ARTIFACT_PAYLOAD_BYTES + 1,
        )
        self._container = service.get_container_client(container_name)


class AzureBlobVersionPinnedArtifactReader:
    """Read one exact Blob version and return it only after bounded verification."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
        max_payload_bytes: int = MAX_ARTIFACT_PAYLOAD_BYTES,
    ) -> None:
        _validate_blob_endpoint(blob_endpoint)
        _validate_container_name(container_name)
        if (
            type(max_payload_bytes) is not int
            or not 1 <= max_payload_bytes <= MAX_ARTIFACT_TRANSFER_BYTES
        ):
            raise ValueError(
                f"max_payload_bytes must be between 1 and {MAX_ARTIFACT_TRANSFER_BYTES}"
            )
        credential = _production_credential(
            managed_identity_client_id=managed_identity_client_id
        )
        service = BlobServiceClient(
            account_url=blob_endpoint,
            credential=credential,
            max_single_get_size=max_payload_bytes + 1,
            max_chunk_get_size=max_payload_bytes + 1,
        )
        self._container = service.get_container_client(container_name)
        self._blob_endpoint = blob_endpoint
        self._container_name = container_name
        self._managed_identity_client_id = managed_identity_client_id
        self._max_payload_bytes = max_payload_bytes

    @property
    def blob_endpoint(self) -> str:
        return self._blob_endpoint

    @property
    def container_name(self) -> str:
        return self._container_name

    @property
    def managed_identity_client_id(self) -> str:
        return self._managed_identity_client_id

    @staticmethod
    def _raise_if_blob_not_found(exc: ResourceNotFoundError) -> NoReturn:
        error_code = getattr(exc, "error_code", None)
        normalized_code = getattr(error_code, "value", error_code)
        if normalized_code != "BlobNotFound":
            raise exc
        raise ArtifactNotFoundError(
            "the exact requested artifact Blob version does not exist"
        ) from exc

    @staticmethod
    def _raise_if_empty_blob_range(exc: HttpResponseError) -> None:
        error_code = getattr(exc, "error_code", None)
        normalized_code = getattr(error_code, "value", error_code)
        if exc.status_code == 416 and normalized_code == "InvalidRange":
            raise ArtifactVerificationError(
                "Blob version is empty and cannot be a JSON artifact"
            ) from exc

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        if type(request) is not ArtifactReadRequest:
            raise TypeError("request must be an exact ArtifactReadRequest")
        blob = self._container.get_blob_client(
            request.blob_name,
            version_id=request.version_id,
        )
        try:
            downloader = blob.download_blob(
                offset=0,
                length=self._max_payload_bytes + 1,
                max_concurrency=1,
            )
            properties = downloader.properties
            version_id = getattr(properties, "version_id", None)
            if type(version_id) is not str or version_id != request.version_id:
                raise ArtifactVerificationError(
                    "Blob response version does not match the exact requested version"
                )
            size = getattr(downloader, "size", None)
            if type(size) is not int or size < 1:
                raise ArtifactVerificationError(
                    "Blob response omitted a valid positive content length"
                )
            if size > self._max_payload_bytes:
                raise ArtifactReadTooLargeError(
                    f"artifact payload exceeds {self._max_payload_bytes} bytes"
                )
            content_settings = getattr(properties, "content_settings", None)
            content_type = getattr(content_settings, "content_type", None)
            if content_type != "application/json":
                raise ArtifactVerificationError(
                    "Blob version content type is not exactly application/json"
                )
            metadata = getattr(properties, "metadata", None)
            metadata_digest = (
                metadata.get("payload_sha256")
                if type(metadata) is dict
                else None
            )
            if (
                type(metadata_digest) is not str
                or metadata_digest != request.expected_payload_sha256
            ):
                raise ArtifactVerificationError(
                    "Blob payload hash metadata is missing or does not match the expected digest"
                )
            payload = downloader.readall()
        except ResourceNotFoundError as exc:
            self._raise_if_blob_not_found(exc)
        except HttpResponseError as exc:
            self._raise_if_empty_blob_range(exc)
            raise

        if type(payload) is not bytes:
            raise ArtifactVerificationError("Blob download did not return immutable bytes")
        if len(payload) != size or len(payload) > self._max_payload_bytes:
            raise ArtifactVerificationError(
                "Blob download length does not match the bounded response metadata"
            )
        computed_digest = sha256_hex(payload)
        if (
            computed_digest != request.expected_payload_sha256
            or computed_digest != metadata_digest
        ):
            raise ArtifactVerificationError(
                "Blob payload bytes do not match the expected SHA-256 digest"
            )
        try:
            json.loads(
                payload.decode("utf-8"),
                parse_constant=_reject_non_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArtifactVerificationError(
                "Blob payload is not valid UTF-8 JSON"
            ) from exc
        return ArtifactReadResult(
            container_name=self._container_name,
            blob_name=request.blob_name,
            version_id=request.version_id,
            payload=payload,
            size_bytes=size,
            content_type="application/json",
            payload_sha256=computed_digest,
        )


    def read_current(self, request: ArtifactCurrentReadRequest) -> ArtifactReadResult:
        """Recover one known current Blob version only after bounded integrity validation."""

        if type(request) is not ArtifactCurrentReadRequest:
            raise TypeError("request must be an exact ArtifactCurrentReadRequest")
        blob = self._container.get_blob_client(request.blob_name)
        try:
            downloader = blob.download_blob(
                offset=0,
                length=self._max_payload_bytes + 1,
                max_concurrency=1,
            )
            properties = downloader.properties
            version_id = getattr(properties, "version_id", None)
            if type(version_id) is not str or not version_id:
                raise ArtifactVerificationError(
                    "Blob response omitted the current version identity"
                )
            size = getattr(downloader, "size", None)
            if type(size) is not int or size < 1:
                raise ArtifactVerificationError(
                    "Blob response omitted a valid positive content length"
                )
            if size > self._max_payload_bytes:
                raise ArtifactReadTooLargeError(
                    f"artifact payload exceeds {self._max_payload_bytes} bytes"
                )
            content_settings = getattr(properties, "content_settings", None)
            content_type = getattr(content_settings, "content_type", None)
            if content_type != "application/json":
                raise ArtifactVerificationError(
                    "Blob version content type is not exactly application/json"
                )
            metadata = getattr(properties, "metadata", None)
            metadata_digest = (
                metadata.get("payload_sha256")
                if type(metadata) is dict
                else None
            )
            if type(metadata_digest) is not str:
                raise ArtifactVerificationError(
                    "Blob payload hash metadata is missing or invalid"
                )
            payload = downloader.readall()
        except ResourceNotFoundError as exc:
            self._raise_if_blob_not_found(exc)
        except HttpResponseError as exc:
            self._raise_if_empty_blob_range(exc)
            raise

        if type(payload) is not bytes:
            raise ArtifactVerificationError("Blob download did not return immutable bytes")
        if len(payload) != size or len(payload) > self._max_payload_bytes:
            raise ArtifactVerificationError(
                "Blob download length does not match the bounded response metadata"
            )
        computed_digest = sha256_hex(payload)
        if computed_digest != metadata_digest:
            raise ArtifactVerificationError(
                "Blob payload bytes do not match the metadata SHA-256 digest"
            )
        try:
            json.loads(
                payload.decode("utf-8"),
                parse_constant=_reject_non_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArtifactVerificationError(
                "Blob payload is not valid UTF-8 JSON"
            ) from exc
        return ArtifactReadResult(
            container_name=self._container_name,
            blob_name=request.blob_name,
            version_id=version_id,
            payload=payload,
            size_bytes=size,
            content_type="application/json",
            payload_sha256=computed_digest,
        )


class AzureBlobChangeEvidenceReplayStore:
    """Create and recover WC-025 artifacts without listing or unverified reads."""

    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
        max_payload_bytes: int = MAX_ARTIFACT_PAYLOAD_BYTES,
    ) -> None:
        self._writer = AzureBlobCreateOnlyArtifactWriter(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
            max_payload_bytes=max_payload_bytes,
        )
        self._reader = AzureBlobVersionPinnedArtifactReader(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
            max_payload_bytes=max_payload_bytes,
        )

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt:
        return self._writer.create(request)

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        return self._reader.read(request)

    def read_current(self, request: ArtifactCurrentReadRequest) -> ArtifactReadResult:
        return self._reader.read_current(request)


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
    "AzureBlobIncidentAssetPublisher",
    "AzureBlobIncidentAssetReader",
    "AzureBlobPresentationAssetPublisher",
    "AzureBlobPresentationAssetReader",
    "AzureBlobVersionPinnedArtifactReader",
    "AzureTableAttemptReplayGuard",
    "DefaultAzureCredentialTrustedIngestionSigner",
    "KeyVaultRsaSigner",
    "KeyVaultTrustedKeyResolver",
    "production_managed_identity_credential",
]
