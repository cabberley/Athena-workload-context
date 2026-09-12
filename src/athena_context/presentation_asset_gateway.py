from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointer,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentEnrichmentManifest,
    IncidentFeedAttestation,
    IncidentFeedEntryV2,
    IncidentFeedIndexAttestationV2,
    IncidentFeedIndexV2,
    IncidentFeedPointer,
    IncidentGuidance,
    IncidentGuidanceAttestation,
    PresentationRuntimeManifestV2,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_feed_pointer_assets,
    validate_incident_feed_index_assets,
    validate_incident_guidance_assets,
)
from athena_context.contracts.guidance import MAX_INCIDENT_GUIDANCE_BYTES
from athena_context.contracts.incident_enrichment import (
    MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
    MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
)
from athena_context.contracts.incident_feed_v2 import (
    MAX_INCIDENT_FEED_V2_BYTES,
    MAX_INCIDENT_FEED_V2_POINTER_BYTES,
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


@dataclass(frozen=True, slots=True)
class GatewayTrustAnchor:
    key_id: str
    fingerprint: str
    public_key: rsa.RSAPublicKey
    browser_path: str

    def __post_init__(self) -> None:
        encoded = self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if "sha256:" + hashlib.sha256(encoded).hexdigest() != self.fingerprint:
            raise ValueError("gateway public key does not match its pinned fingerprint")


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
        feed_v2_trust: GatewayTrustAnchor | None = None,
        enrichment_trust: GatewayTrustAnchor | None = None,
        guidance_trust: GatewayTrustAnchor | None = None,
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
        guidance_values = (feed_v2_trust, enrichment_trust, guidance_trust)
        if any(value is not None for value in guidance_values) and any(
            value is None for value in guidance_values
        ):
            raise ValueError("WC-027 gateway trust configuration must be complete")
        self._feed_v2_trust = feed_v2_trust
        self._enrichment_trust = enrichment_trust
        self._guidance_trust = guidance_trust
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
        request = self._validate_request_path(raw_path)
        if request is None:
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        path, version = request
        if path == "/healthz":
            return GatewayResponse(status=200, payload=_HEALTHY)
        try:
            trust_asset = self._wc027_public_key_asset(path)
            if trust_asset is not None:
                if version is not None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                return GatewayResponse(status=200, payload=trust_asset)
            if (
                path == "/incidents/feed-v2.json"
                or path.startswith("/incidents/feed-v2-index-attestations/")
                or version is not None
            ):
                return self._handle_wc027_asset(path=path, version=version)
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
    def _validate_request_path(raw_path: str) -> tuple[str, str | None] | None:
        if (
            type(raw_path) is not str
            or not raw_path
            or len(raw_path) > 1024
            or "\\" in raw_path
        ):
            return None
        parsed = urlsplit(raw_path)
        if parsed.scheme or parsed.netloc or parsed.fragment or "%" in parsed.path:
            return None
        version: str | None = None
        if parsed.query:
            try:
                parameters = parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                )
            except ValueError:
                return None
            values = parameters.get("version")
            if (
                set(parameters) != {"version"}
                or values is None
                or len(values) != 1
                or not values[0]
                or len(values[0]) > 256
                or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}",
                    values[0],
                )
                is None
            ):
                return None
            version = values[0]
        if parsed.path in {
            "/healthz",
            "/runtime-manifest.json",
            "/incidents/active.json",
            "/incidents/feed-v2.json",
            "/trust/wc027-feed-public-key.jwk.json",
            "/trust/wc027-enrichment-public-key.jwk.json",
            "/trust/wc027-guidance-public-key.jwk.json",
        }:
            return (parsed.path, version)
        if parsed.path.startswith("/incidents/"):
            if any(segment in {"", ".", ".."} for segment in parsed.path[1:].split("/")):
                return None
            return (parsed.path, version)
        if not parsed.path.startswith("/live/runs/"):
            return None
        if any(segment in {"", ".", ".."} for segment in parsed.path[1:].split("/")):
            return None
        return (parsed.path, version)

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

    def _read_incident_version(
        self,
        *,
        blob_name: str,
        version: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        if self._incident_reader is None:
            raise ValueError("incident asset boundary is not configured")
        reader = self._incident_reader
        if not hasattr(reader, "read_version"):
            raise ValueError("exact-version incident reads are not configured")
        versioned_reader = reader
        return versioned_reader.read_version(
            blob_name=blob_name,
            version=version,
            maximum_bytes=maximum_bytes,
        )

    def _wc027_public_key_asset(self, path: str) -> bytes | None:
        anchors = (
            self._feed_v2_trust,
            self._enrichment_trust,
            self._guidance_trust,
        )
        for anchor in anchors:
            if anchor is not None and path == anchor.browser_path:
                numbers = anchor.public_key.public_numbers()

                def encode(value: int) -> str:
                    size = (value.bit_length() + 7) // 8
                    return base64.urlsafe_b64encode(
                        value.to_bytes(size, "big")
                    ).decode("ascii").rstrip("=")

                payload = {
                    "schemaVersion": "athena.presentationWeb.publicKey.v1",
                    "keyId": anchor.key_id,
                    "fingerprint": anchor.fingerprint,
                    "jwk": {
                        "kty": "RSA",
                        "n": encode(numbers.n),
                        "e": encode(numbers.e),
                        "alg": "RS256",
                        "key_ops": ["verify"],
                        "ext": True,
                    },
                }
                return (
                    json.dumps(
                        payload,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
        return None

    def _handle_wc027_asset(
        self,
        *,
        path: str,
        version: str | None,
    ) -> GatewayResponse:
        if (
            self._feed_v2_trust is None
            or self._enrichment_trust is None
            or self._guidance_trust is None
        ):
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        index, index_bytes, _, index_attestation_bytes = (
            self._load_wc027_index()
        )
        if path == "/incidents/feed-v2.json" and version is None:
            return GatewayResponse(status=200, payload=index_bytes)
        if (
            path == "/" + index.index_attestation_path.removeprefix("./")
            and version is None
        ):
            return GatewayResponse(status=200, payload=index_attestation_bytes)
        if version is None:
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        requested_name = path.removeprefix("/")
        entry = next(
            (
                item
                for item in (*index.active, *index.recently_resolved)
                if requested_name.startswith(
                    f"incidents/{item.incident_id}/versions/"
                    f"{item.state_result_digest.removeprefix('sha256:')}/"
                )
            ),
            None,
        )
        if entry is None:
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        pointer, pointer_bytes, _, pointer_attestation_bytes = (
            self._load_wc027_pointer(entry)
        )
        pointer_assets = {
            (
                entry.feed_pointer_reference.name,
                entry.feed_pointer_reference.version,
            ): pointer_bytes,
            (
                entry.feed_pointer_attestation_reference.name,
                entry.feed_pointer_attestation_reference.version,
            ): pointer_attestation_bytes,
        }
        direct = pointer_assets.get((requested_name, version))
        if direct is not None:
            return GatewayResponse(status=200, payload=direct)
        manifest, manifest_bytes, _, enrichment_attestation_bytes = (
            self._load_wc027_enrichment(pointer)
        )
        enrichment_assets = {
            (
                pointer.enrichment_asset.manifest_reference.name,
                pointer.enrichment_asset.manifest_reference.version,
            ): manifest_bytes,
            (
                pointer.enrichment_asset.attestation_reference.name,
                pointer.enrichment_asset.attestation_reference.version,
            ): enrichment_attestation_bytes,
        }
        direct = enrichment_assets.get((requested_name, version))
        if direct is not None:
            return GatewayResponse(status=200, payload=direct)
        guidance_reference = manifest.guidance_asset
        guidance_trust = self._guidance_trust
        assert guidance_trust is not None
        guidance_result = self._read_incident_version(
            blob_name=guidance_reference.guidance_reference.name,
            version=guidance_reference.guidance_reference.version,
            maximum_bytes=MAX_INCIDENT_GUIDANCE_BYTES,
        )
        guidance_attestation_result = self._read_incident_version(
            blob_name=guidance_reference.attestation_reference.name,
            version=guidance_reference.attestation_reference.version,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        guidance = IncidentGuidance.model_validate_json(guidance_result.payload)
        guidance_attestation = IncidentGuidanceAttestation.model_validate_json(
            guidance_attestation_result.payload
        )
        if (
            guidance_result.payload != guidance.canonical_bytes()
            or guidance_attestation_result.payload
            != guidance_attestation.canonical_bytes()
        ):
            raise ValueError("incident guidance bytes are not canonical")
        validate_incident_guidance_assets(
            guidance_reference,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=guidance_trust.key_id,
            guidance_signature_verifier=lambda payload, signature: (
                self._verify_with_anchor(
                    guidance_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        guidance_assets = {
            (
                guidance_reference.guidance_reference.name,
                guidance_reference.guidance_reference.version,
            ): guidance_result.payload,
            (
                guidance_reference.attestation_reference.name,
                guidance_reference.attestation_reference.version,
            ): guidance_attestation_result.payload,
        }
        payload = guidance_assets.get((requested_name, version))
        if payload is None:
            return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
        return GatewayResponse(status=200, payload=payload)

    def _load_wc027_index(
        self,
    ) -> tuple[
        IncidentFeedIndexV2,
        bytes,
        IncidentFeedIndexAttestationV2,
        bytes,
    ]:
        feed_v2_trust = self._feed_v2_trust
        assert feed_v2_trust is not None
        _, active_index_bytes = self._load_active_incident_index()
        result = self._read_incident_asset(
            blob_name="incidents/feed-v2.json",
            maximum_bytes=MAX_INCIDENT_FEED_V2_BYTES,
        )
        index = IncidentFeedIndexV2.model_validate_json(result.payload)
        attestation_result = self._read_incident_asset(
            blob_name=index.index_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        attestation = IncidentFeedIndexAttestationV2.model_validate_json(
            attestation_result.payload
        )
        if (
            result.payload != index.canonical_bytes()
            or attestation_result.payload != attestation.canonical_bytes()
        ):
            raise ValueError("incident feed v2 index bytes are not canonical")
        validate_incident_feed_index_assets(
            index,
            attestation,
            trusted_key_id=feed_v2_trust.key_id,
            trusted_key_fingerprint=feed_v2_trust.fingerprint,
            expected_source_active_index_digest=sha256_hex(active_index_bytes),
            not_older_than=datetime.now(UTC) - timedelta(minutes=15),
            signature_verifier=lambda payload, signature: (
                self._verify_with_anchor(
                    feed_v2_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        return index, result.payload, attestation, attestation_result.payload

    def _load_wc027_pointer(
        self,
        entry: IncidentFeedEntryV2,
    ) -> tuple[
        IncidentEnrichmentFeedPointer,
        bytes,
        IncidentEnrichmentFeedPointerAttestation,
        bytes,
    ]:
        feed_v2_trust = self._feed_v2_trust
        assert feed_v2_trust is not None
        pointer_result = self._read_incident_version(
            blob_name=entry.feed_pointer_reference.name,
            version=entry.feed_pointer_reference.version,
            maximum_bytes=MAX_INCIDENT_FEED_V2_POINTER_BYTES,
        )
        attestation_result = self._read_incident_version(
            blob_name=entry.feed_pointer_attestation_reference.name,
            version=entry.feed_pointer_attestation_reference.version,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        pointer = IncidentEnrichmentFeedPointer.model_validate_json(
            pointer_result.payload
        )
        attestation = IncidentEnrichmentFeedPointerAttestation.model_validate_json(
            attestation_result.payload
        )
        if (
            pointer_result.payload != pointer.canonical_bytes()
            or attestation_result.payload != attestation.canonical_bytes()
        ):
            raise ValueError("incident feed v2 pointer bytes are not canonical")
        validate_incident_enrichment_feed_pointer_assets(
            entry,
            pointer,
            attestation,
            trusted_key_id=feed_v2_trust.key_id,
            signature_verifier=lambda payload, signature: (
                self._verify_with_anchor(
                    feed_v2_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        return pointer, pointer_result.payload, attestation, attestation_result.payload

    def _load_wc027_enrichment(
        self,
        pointer: IncidentEnrichmentFeedPointer,
    ) -> tuple[
        IncidentEnrichmentManifest,
        bytes,
        IncidentEnrichmentAttestation,
        bytes,
    ]:
        enrichment_trust = self._enrichment_trust
        assert enrichment_trust is not None
        reference = pointer.enrichment_asset
        manifest_result = self._read_incident_version(
            blob_name=reference.manifest_reference.name,
            version=reference.manifest_reference.version,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
        )
        attestation_result = self._read_incident_version(
            blob_name=reference.attestation_reference.name,
            version=reference.attestation_reference.version,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        manifest = IncidentEnrichmentManifest.model_validate_json(
            manifest_result.payload
        )
        attestation = IncidentEnrichmentAttestation.model_validate_json(
            attestation_result.payload
        )
        if (
            manifest_result.payload != manifest.canonical_bytes()
            or attestation_result.payload != attestation.canonical_bytes()
        ):
            raise ValueError("incident enrichment bytes are not canonical")
        validate_incident_enrichment_assets(
            reference,
            manifest,
            attestation,
            trusted_enrichment_key_id=enrichment_trust.key_id,
            enrichment_signature_verifier=lambda payload, signature: (
                self._verify_with_anchor(
                    enrichment_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        return manifest, manifest_result.payload, attestation, attestation_result.payload

    @staticmethod
    def _verify_with_anchor(
        anchor: GatewayTrustAnchor,
        *,
        payload: bytes,
        detached_signature: str,
    ) -> bool:
        try:
            signature = base64.urlsafe_b64decode(
                detached_signature + "=" * (-len(detached_signature) % 4)
            )
            anchor.public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError):
            return False

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
    wc027_feed_key_id: str | None = None,
    wc027_feed_key_fingerprint: str | None = None,
    wc027_feed_public_key_path: Path | None = None,
    wc027_enrichment_key_id: str | None = None,
    wc027_enrichment_key_fingerprint: str | None = None,
    wc027_enrichment_public_key_path: Path | None = None,
    wc027_guidance_key_id: str | None = None,
    wc027_guidance_key_fingerprint: str | None = None,
    wc027_guidance_public_key_path: Path | None = None,
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
        wc027_values = (
            wc027_feed_key_id,
            wc027_feed_key_fingerprint,
            wc027_feed_public_key_path,
            wc027_enrichment_key_id,
            wc027_enrichment_key_fingerprint,
            wc027_enrichment_public_key_path,
            wc027_guidance_key_id,
            wc027_guidance_key_fingerprint,
            wc027_guidance_public_key_path,
        )
        if any(value is not None for value in wc027_values) and any(
            value is None for value in wc027_values
        ):
            raise ValueError("WC-027 trust arguments must be supplied together")

        def load_anchor(
            key_id: str | None,
            fingerprint: str | None,
            key_path: Path | None,
            browser_path: str,
        ) -> GatewayTrustAnchor | None:
            if key_id is None or fingerprint is None or key_path is None:
                return None
            value = serialization.load_pem_public_key(key_path.read_bytes())
            if not isinstance(value, rsa.RSAPublicKey):
                raise ValueError("WC-027 trust anchor must be an RSA public key")
            return GatewayTrustAnchor(
                key_id=key_id,
                fingerprint=fingerprint,
                public_key=value,
                browser_path=browser_path,
            )

        application = PresentationAssetGatewayApplication(
            active_reader,
            incident_reader=incident_reader,
            incident_key_id=incident_key_id,
            incident_key_fingerprint=incident_key_fingerprint,
            incident_public_key=public_key_value,
            feed_v2_trust=load_anchor(
                wc027_feed_key_id,
                wc027_feed_key_fingerprint,
                wc027_feed_public_key_path,
                "/trust/wc027-feed-public-key.jwk.json",
            ),
            enrichment_trust=load_anchor(
                wc027_enrichment_key_id,
                wc027_enrichment_key_fingerprint,
                wc027_enrichment_public_key_path,
                "/trust/wc027-enrichment-public-key.jwk.json",
            ),
            guidance_trust=load_anchor(
                wc027_guidance_key_id,
                wc027_guidance_key_fingerprint,
                wc027_guidance_public_key_path,
                "/trust/wc027-guidance-public-key.jwk.json",
            ),
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
