from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from athena_context.azure_adapters import (
    AzureBlobIncidentAssetReader,
    AzureBlobPresentationAssetReader,
)
from athena_context.contracts import (
    PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    IncidentFeedAttestation,
    IncidentFeedPointer,
    PresentationRuntimeManifestV2,
    sha256_hex,
)
from athena_context.presentation_assets import (
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    MAX_PRESENTATION_PAYLOAD_BYTES,
    MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES,
    PresentationAssetReaderPort,
    PresentationAssetReadResult,
)

_JSON_CONTENT_TYPE = "application/json; charset=utf-8"
_ERROR_NOT_FOUND = b'{"error":"not found"}\n'
_ERROR_METHOD = b'{"error":"method not allowed"}\n'
_ERROR_UNAVAILABLE = b'{"error":"presentation assets unavailable"}\n'
_HEALTHY = b'{"status":"healthy"}\n'


class PresentationAssetGatewayError(RuntimeError):
    """Raised when the presentation asset gateway cannot start."""


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    status: int
    payload: bytes
    content_type: str = _JSON_CONTENT_TYPE
    allow: str | None = None


class PresentationAssetGatewayApplication:
    """Serve only the current validated manifest and its allowlisted live assets."""

    def __init__(
        self,
        reader: PresentationAssetReaderPort,
        *,
        incident_reader: PresentationAssetReaderPort | None = None,
        incident_key_id: str | None = None,
        incident_key_fingerprint: str | None = None,
        incident_public_key: rsa.RSAPublicKey | None = None,
    ) -> None:
        incident_values = (
            incident_reader,
            incident_key_id,
            incident_key_fingerprint,
            incident_public_key,
        )
        if any(value is not None for value in incident_values) and any(
            value is None for value in incident_values
        ):
            raise ValueError("incident gateway trust configuration must be complete")
        self._reader = reader
        self._incident_reader = incident_reader
        self._incident_key_id = incident_key_id
        self._incident_key_fingerprint = incident_key_fingerprint
        self._incident_public_key = incident_public_key
        if incident_public_key is not None:
            encoded = incident_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fingerprint = "sha256:" + hashlib.sha256(encoded).hexdigest()
            if fingerprint != incident_key_fingerprint:
                raise ValueError("incident public key does not match its pinned fingerprint")

    def handle(self, *, method: str, raw_path: str) -> GatewayResponse:
        if method not in {"GET", "HEAD"}:
            return GatewayResponse(
                status=405,
                payload=_ERROR_METHOD,
                allow="GET, HEAD",
            )
        path = self._validate_request_path(raw_path)
        if path is None:
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        if path == "/healthz":
            return GatewayResponse(status=200, payload=_HEALTHY)
        try:
            if path.startswith("/incidents/"):
                index, index_bytes = self._load_active_incident_index()
                if path == "/incidents/active.json":
                    return GatewayResponse(status=200, payload=index_bytes)
                if path == "/" + index.index_attestation_path.removeprefix("./"):
                    result = self._read_incident_asset(
                        blob_name=path.removeprefix("/"),
                        maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
                    )
                    index_attestation = ActiveIncidentIndexAttestation.model_validate_json(
                        result.payload
                    )
                    if (
                        index_attestation.index_digest != sha256_hex(index_bytes)
                        or index_attestation.key_vault_key_id != self._incident_key_id
                        or result.payload != index_attestation.canonical_bytes()
                        or not self._verify_incident_signature(
                            payload=index_bytes,
                            detached_signature=index_attestation.detached_signature,
                        )
                    ):
                        raise ValueError(
                            "active incident index attestation trust binding is invalid"
                        )
                    return GatewayResponse(status=200, payload=result.payload)
                entry = self._active_entry_for_path(index, path)
                if entry is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                pointer, pointer_bytes = self._load_incident_pointer(entry)
                if path == "/" + entry.pointer_path.removeprefix("./"):
                    return GatewayResponse(status=200, payload=pointer_bytes)
                if path == "/" + pointer.pointer_attestation_path.removeprefix("./"):
                    result = self._read_incident_asset(
                        blob_name=path.removeprefix("/"),
                        maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
                    )
                    pointer_attestation = IncidentFeedAttestation.model_validate_json(
                        result.payload
                    )
                    if (
                        pointer_attestation.pointer_digest != sha256_hex(pointer_bytes)
                        or pointer_attestation.key_vault_key_id != self._incident_key_id
                        or result.payload != pointer_attestation.canonical_bytes()
                        or not self._verify_incident_signature(
                            payload=pointer_bytes,
                            detached_signature=pointer_attestation.detached_signature,
                        )
                    ):
                        raise ValueError(
                            "incident pointer attestation trust binding is invalid"
                        )
                    return GatewayResponse(status=200, payload=result.payload)
                digest, maximum_bytes = self._allowlisted_incident_asset(
                    pointer, path
                )
                if digest is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                result = self._read_incident_asset(
                    blob_name=path.removeprefix("/"),
                    maximum_bytes=maximum_bytes,
                )
                if result.payload_sha256 != digest:
                    return GatewayResponse(status=503, payload=_ERROR_UNAVAILABLE)
                return GatewayResponse(status=200, payload=result.payload)
            manifest, manifest_bytes = self._load_manifest()
            if path == "/runtime-manifest.json":
                return GatewayResponse(status=200, payload=manifest_bytes)
            digest, maximum_bytes = self._allowlisted_asset(manifest, path)
            if digest is None:
                return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
            result = self._reader.read_current(
                blob_name=path.removeprefix("/"),
                maximum_bytes=maximum_bytes,
            )
            if result.payload_sha256 != digest:
                return GatewayResponse(status=503, payload=_ERROR_UNAVAILABLE)
            return GatewayResponse(status=200, payload=result.payload)
        except (OSError, RuntimeError, TypeError, ValueError, ValidationError):
            return GatewayResponse(status=503, payload=_ERROR_UNAVAILABLE)

    @staticmethod
    def _validate_request_path(raw_path: str) -> str | None:
        if (
            type(raw_path) is not str
            or not raw_path
            or len(raw_path) > 512
            or "%" in raw_path
            or "\\" in raw_path
        ):
            return None
        parsed = urlsplit(raw_path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            return None
        if parsed.path in {
            "/healthz",
            "/runtime-manifest.json",
            "/incidents/active.json",
        }:
            return parsed.path
        if parsed.path.startswith("/incidents/"):
            if any(segment in {"", ".", ".."} for segment in parsed.path[1:].split("/")):
                return None
            return parsed.path
        if not parsed.path.startswith("/live/runs/"):
            return None
        if any(segment in {"", ".", ".."} for segment in parsed.path[1:].split("/")):
            return None
        return parsed.path

    def _load_manifest(
        self,
    ) -> tuple[PresentationRuntimeManifestV2, bytes]:
        result = self._reader.read_current(
            blob_name=PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
            maximum_bytes=MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES,
        )
        manifest = PresentationRuntimeManifestV2.model_validate_json(
            result.payload
        )
        if result.payload != manifest.canonical_bytes():
            raise ValueError("runtime manifest bytes are not canonical")
        return manifest, result.payload

    def _load_active_incident_index(self) -> tuple[ActiveIncidentIndex, bytes]:
        result = self._read_incident_asset(
            blob_name="incidents/active.json",
            maximum_bytes=MAX_INCIDENT_STATE_BYTES,
        )
        index = ActiveIncidentIndex.model_validate_json(result.payload)
        if (
            result.payload != index.canonical_bytes()
            or index.key_id != self._incident_key_id
            or index.key_fingerprint != self._incident_key_fingerprint
        ):
            raise ValueError("active incident index trust binding is invalid")
        attestation_result = self._read_incident_asset(
            blob_name=index.index_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        attestation = ActiveIncidentIndexAttestation.model_validate_json(
            attestation_result.payload
        )
        if (
            attestation_result.payload != attestation.canonical_bytes()
            or attestation.index_digest != sha256_hex(result.payload)
            or attestation.key_vault_key_id != self._incident_key_id
            or not self._verify_incident_signature(
                payload=result.payload,
                detached_signature=attestation.detached_signature,
            )
        ):
            raise ValueError("active incident index signature is invalid")
        return index, result.payload

    def _load_incident_pointer(
        self,
        entry: ActiveIncidentEntry,
    ) -> tuple[IncidentFeedPointer, bytes]:
        result = self._read_incident_asset(
            blob_name=entry.pointer_path.removeprefix("./"),
            maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
        )
        pointer = IncidentFeedPointer.model_validate_json(result.payload)
        if (
            result.payload != pointer.canonical_bytes()
            or result.payload_sha256 != entry.pointer_sha256
            or pointer.incident_id != entry.incident_id
            or pointer.key_id != self._incident_key_id
            or pointer.key_fingerprint != self._incident_key_fingerprint
            or entry.pointer_path
            != pointer.state_path.removesuffix("/state.json") + "/pointer.json"
        ):
            raise ValueError("incident feed pointer trust binding is invalid")
        attestation_result = self._read_incident_asset(
            blob_name=pointer.pointer_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        attestation = IncidentFeedAttestation.model_validate_json(
            attestation_result.payload
        )
        if (
            attestation_result.payload != attestation.canonical_bytes()
            or attestation.pointer_digest != sha256_hex(result.payload)
            or attestation.key_vault_key_id != self._incident_key_id
            or not self._verify_incident_signature(
                payload=result.payload,
                detached_signature=attestation.detached_signature,
            )
        ):
            raise ValueError("incident feed pointer signature is invalid")
        return pointer, result.payload

    def _read_incident_asset(
        self,
        *,
        blob_name: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        if self._incident_reader is None:
            raise ValueError("incident asset boundary is not configured")
        return self._incident_reader.read_current(
            blob_name=blob_name,
            maximum_bytes=maximum_bytes,
        )

    def _verify_incident_signature(
        self,
        *,
        payload: bytes,
        detached_signature: str,
    ) -> bool:
        if self._incident_public_key is None:
            return False
        try:
            signature = base64.urlsafe_b64decode(
                detached_signature
                + "=" * (-len(detached_signature) % 4)
            )
            self._incident_public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def _active_entry_for_path(
        index: ActiveIncidentIndex,
        path: str,
    ) -> ActiveIncidentEntry | None:
        for entry in index.incidents:
            prefix = f"/incidents/{entry.incident_id}/"
            if path == "/" + entry.pointer_path.removeprefix("./") or path.startswith(
                prefix + "versions/"
            ):
                return entry
        return None

    @staticmethod
    def _allowlisted_incident_asset(
        pointer: IncidentFeedPointer,
        path: str,
    ) -> tuple[str | None, int]:
        if path == "/" + pointer.state_path.removeprefix("./"):
            return pointer.state_sha256, MAX_INCIDENT_STATE_BYTES
        if path == "/" + pointer.attestation_path.removeprefix("./"):
            return pointer.attestation_sha256, MAX_PRESENTATION_ATTESTATION_BYTES
        return None, 0

    @staticmethod
    def _allowlisted_asset(
        manifest: PresentationRuntimeManifestV2,
        path: str,
    ) -> tuple[str | None, int]:
        for phase in manifest.phases:
            if path == "/" + phase.payload_path.removeprefix("./"):
                return phase.payload_sha256, MAX_PRESENTATION_PAYLOAD_BYTES
            if path == "/" + phase.attestation_path.removeprefix("./"):
                return (
                    phase.attestation_sha256,
                    MAX_PRESENTATION_ATTESTATION_BYTES,
                )
        return None, 0


def run_presentation_asset_gateway(
    *,
    blob_endpoint: str,
    container_name: str,
    incident_container_name: str,
    incident_key_id: str,
    incident_key_fingerprint: str,
    incident_public_key_path: Path,
    managed_identity_client_id: str,
    port: int = 8081,
    reader: PresentationAssetReaderPort | None = None,
) -> None:
    if type(port) is not int or not 1 <= port <= 65535:
        raise PresentationAssetGatewayError(
            "presentation asset gateway port must be between 1 and 65535"
        )
    try:
        active_reader = reader or AzureBlobPresentationAssetReader(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
        )
        incident_reader = (
            reader
            if reader is not None
            else AzureBlobIncidentAssetReader(
                blob_endpoint=blob_endpoint,
                container_name=incident_container_name,
                managed_identity_client_id=managed_identity_client_id,
            )
        )
        public_key_value = serialization.load_pem_public_key(
            incident_public_key_path.read_bytes()
        )
        if not isinstance(public_key_value, rsa.RSAPublicKey):
            raise ValueError("incident trust anchor must be an RSA public key")
        application = PresentationAssetGatewayApplication(
            active_reader,
            incident_reader=incident_reader,
            incident_key_id=incident_key_id,
            incident_key_fingerprint=incident_key_fingerprint,
            incident_public_key=public_key_value,
        )

        class Handler(BaseHTTPRequestHandler):
            server_version = "athena-presentation-gateway"
            sys_version = ""

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_PUT(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler contract.
                self._serve()

            def _serve(self) -> None:
                response = application.handle(
                    method=self.command,
                    raw_path=self.path,
                )
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("Content-Length", str(len(response.payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if response.allow is not None:
                    self.send_header("Allow", "GET, HEAD")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response.payload)

            def send_error(
                self,
                code: int,
                message: str | None = None,
                explain: str | None = None,
            ) -> None:
                del code, message, explain
                response = GatewayResponse(
                    status=405,
                    payload=_ERROR_METHOD,
                    allow="GET, HEAD",
                )
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("Content-Length", str(len(response.payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Allow", "GET, HEAD")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response.payload)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = ThreadingHTTPServer(
            ("0.0.0.0", port),  # noqa: S104 - private sidecar listener.
            Handler,
        )
        server.serve_forever()
    except PresentationAssetGatewayError:
        raise
    except Exception as exc:  # noqa: BLE001 - process boundary redacts details.
        raise PresentationAssetGatewayError(
            "presentation asset gateway failed closed"
        ) from exc


__all__ = [
    "GatewayResponse",
    "PresentationAssetGatewayApplication",
    "PresentationAssetGatewayError",
    "run_presentation_asset_gateway",
]
