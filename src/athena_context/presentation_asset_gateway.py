from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from pydantic import ValidationError

from athena_context.azure_adapters import AzureBlobPresentationAssetReader
from athena_context.contracts import (
    PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
    IncidentFeedPointer,
    PresentationRuntimeManifestV2,
)
from athena_context.presentation_assets import (
    MAX_INCIDENT_FEED_POINTER_BYTES,
    MAX_INCIDENT_STATE_BYTES,
    MAX_PRESENTATION_ATTESTATION_BYTES,
    MAX_PRESENTATION_PAYLOAD_BYTES,
    MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES,
    PresentationAssetReaderPort,
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

    def __init__(self, reader: PresentationAssetReaderPort) -> None:
        self._reader = reader

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
            if path == "/incidents/current.json":
                _, pointer_bytes = self._load_incident_pointer()
                return GatewayResponse(status=200, payload=pointer_bytes)
            if path.startswith("/incidents/"):
                pointer, _ = self._load_incident_pointer()
                if path == "/" + pointer.pointer_attestation_path.removeprefix("./"):
                    result = self._reader.read_current(
                        blob_name=path.removeprefix("/"),
                        maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
                    )
                    return GatewayResponse(status=200, payload=result.payload)
                digest, maximum_bytes = self._allowlisted_incident_asset(pointer, path)
                if digest is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                result = self._reader.read_current(
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
            "/incidents/current.json",
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

    def _load_incident_pointer(self) -> tuple[IncidentFeedPointer, bytes]:
        result = self._reader.read_current(
            blob_name="incidents/current.json",
            maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
        )
        pointer = IncidentFeedPointer.model_validate_json(result.payload)
        if result.payload != pointer.canonical_bytes():
            raise ValueError("incident feed pointer bytes are not canonical")
        return pointer, result.payload

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
        application = PresentationAssetGatewayApplication(active_reader)

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
