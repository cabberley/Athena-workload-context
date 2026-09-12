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
    MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
    MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
    MAX_INCIDENT_FEED_V2_BYTES,
    MAX_INCIDENT_FEED_V2_POINTER_BYTES,
    MAX_INCIDENT_GUIDANCE_BYTES,
    MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
    PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    CorrelationReport,
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
    IncidentState,
    IncidentStateAttestation,
    PresentationRuntimeManifestV2,
    PublishedCorrelationReportAssetReference,
    PublishedCorrelationReportAttestation,
    VersionPinnedBlobReference,
    build_incident_occurrence_receipt,
    incident_state_signature_preimage,
    sha256_hex,
    validate_incident_enrichment_assets,
    validate_incident_enrichment_feed_pointer_assets,
    validate_incident_feed_index_assets,
    validate_incident_guidance_assets,
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
_INCIDENT_FEED_V2_BLOB_NAME = "incidents/feed-v2.json"


class PresentationAssetGatewayError(RuntimeError):
    """Raised when the presentation asset gateway cannot start."""


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    status: int
    payload: bytes
    content_type: str = _JSON_CONTENT_TYPE
    allow: str | None = None


@dataclass(frozen=True, slots=True)
class GatewaySignatureTrustAnchor:
    key_id: str
    key_fingerprint: str
    public_key: rsa.RSAPublicKey

    def __post_init__(self) -> None:
        if type(self.key_id) is not str or not self.key_id:
            raise ValueError("gateway trust anchor key ID is invalid")
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise TypeError("gateway trust anchor must use an RSA public key")
        encoded = self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if self.key_fingerprint != fingerprint:
            raise ValueError(
                "gateway trust anchor public key does not match its pinned fingerprint"
            )


@dataclass(frozen=True, slots=True)
class _VerifiedIncidentFeedV2Entry:
    assets: dict[str, bytes]

    def payload_for(self, path: str) -> bytes | None:
        return self.assets.get(path.removeprefix("/"))


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
        incident_feed_v2_trust: GatewaySignatureTrustAnchor | None = None,
        incident_report_trust: GatewaySignatureTrustAnchor | None = None,
        incident_guidance_trust: GatewaySignatureTrustAnchor | None = None,
        incident_enrichment_trust: GatewaySignatureTrustAnchor | None = None,
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
        v2_trust = (
            incident_feed_v2_trust,
            incident_report_trust,
            incident_guidance_trust,
            incident_enrichment_trust,
        )
        if any(value is not None for value in v2_trust) and any(
            value is None for value in v2_trust
        ):
            raise ValueError("incident feed v2 trust configuration must be complete")
        configured_v2_trust = tuple(
            value for value in v2_trust if value is not None
        )
        if configured_v2_trust and incident_reader is None:
            raise ValueError(
                "incident feed v2 trust requires the incident asset boundary"
            )
        if configured_v2_trust and (
            len({value.key_id for value in configured_v2_trust}) != 4
            or len(
                {value.key_fingerprint for value in configured_v2_trust}
            )
            != 4
        ):
            raise ValueError(
                "incident feed v2 trust anchors must use separate keys"
            )
        self._incident_feed_v2_trust = incident_feed_v2_trust
        self._incident_report_trust = incident_report_trust
        self._incident_guidance_trust = incident_guidance_trust
        self._incident_enrichment_trust = incident_enrichment_trust
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
                if entry is not None:
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
                    if digest is not None:
                        result = self._read_incident_asset(
                            blob_name=path.removeprefix("/"),
                            maximum_bytes=maximum_bytes,
                        )
                        if result.payload_sha256 != digest:
                            return GatewayResponse(
                                status=503,
                                payload=_ERROR_UNAVAILABLE,
                            )
                        return GatewayResponse(status=200, payload=result.payload)
                if self._incident_feed_v2_trust is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                feed_index, feed_index_bytes, feed_attestation_bytes = (
                    self._load_incident_feed_v2(
                        source_active_index=index,
                        source_active_index_bytes=index_bytes,
                    )
                )
                if path == "/" + _INCIDENT_FEED_V2_BLOB_NAME:
                    return GatewayResponse(status=200, payload=feed_index_bytes)
                if path == "/" + feed_index.index_attestation_path.removeprefix("./"):
                    return GatewayResponse(
                        status=200,
                        payload=feed_attestation_bytes,
                    )
                feed_entry = self._incident_feed_v2_entry_for_path(
                    feed_index,
                    path,
                )
                if feed_entry is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                verified = self._load_incident_feed_v2_entry(feed_entry)
                payload = verified.payload_for(path)
                if payload is None:
                    return GatewayResponse(status=404, payload=_ERROR_NOT_FOUND)
                return GatewayResponse(status=200, payload=payload)
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

    def _load_incident_feed_v2(
        self,
        *,
        source_active_index: ActiveIncidentIndex,
        source_active_index_bytes: bytes,
    ) -> tuple[IncidentFeedIndexV2, bytes, bytes]:
        trust = self._require_v2_trust(self._incident_feed_v2_trust)
        result = self._read_incident_asset(
            blob_name=_INCIDENT_FEED_V2_BLOB_NAME,
            maximum_bytes=MAX_INCIDENT_FEED_V2_BYTES,
        )
        index = IncidentFeedIndexV2.model_validate_json(result.payload)
        if result.payload != index.canonical_bytes():
            raise ValueError("incident feed v2 index bytes are not canonical")
        attestation_result = self._read_incident_asset(
            blob_name=index.index_attestation_path.removeprefix("./"),
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        attestation = IncidentFeedIndexAttestationV2.model_validate_json(
            attestation_result.payload
        )
        if attestation_result.payload != attestation.canonical_bytes():
            raise ValueError("incident feed v2 index attestation is not canonical")
        validate_incident_feed_index_assets(
            index,
            attestation,
            trusted_key_id=trust.key_id,
            trusted_key_fingerprint=trust.key_fingerprint,
            expected_source_active_index_digest=sha256_hex(
                source_active_index_bytes
            ),
            not_older_than=source_active_index.published_at,
            signature_verifier=lambda payload, signature: self._verify_signature(
                trust,
                payload=payload,
                detached_signature=signature,
            ),
        )
        return index, result.payload, attestation_result.payload

    @staticmethod
    def _incident_feed_v2_entry_for_path(
        index: IncidentFeedIndexV2,
        path: str,
    ) -> IncidentFeedEntryV2 | None:
        for entry in (*index.active, *index.recently_resolved):
            prefix = (
                f"/incidents/{entry.incident_id}/versions/"
                f"{entry.state_result_digest.removeprefix('sha256:')}/"
            )
            if path.startswith(prefix):
                return entry
        return None

    def _load_incident_feed_v2_entry(
        self,
        entry: IncidentFeedEntryV2,
    ) -> _VerifiedIncidentFeedV2Entry:
        feed_trust = self._require_v2_trust(self._incident_feed_v2_trust)
        report_trust = self._require_v2_trust(self._incident_report_trust)
        guidance_trust = self._require_v2_trust(self._incident_guidance_trust)
        enrichment_trust = self._require_v2_trust(
            self._incident_enrichment_trust
        )

        pointer_result = self._read_versioned_incident_asset(
            entry.feed_pointer_reference,
            maximum_bytes=MAX_INCIDENT_FEED_V2_POINTER_BYTES,
        )
        pointer = IncidentEnrichmentFeedPointer.model_validate_json(
            pointer_result.payload
        )
        if pointer_result.payload != pointer.canonical_bytes():
            raise ValueError("incident feed v2 pointer bytes are not canonical")
        pointer_attestation_result = self._read_versioned_incident_asset(
            entry.feed_pointer_attestation_reference,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        pointer_attestation = (
            IncidentEnrichmentFeedPointerAttestation.model_validate_json(
                pointer_attestation_result.payload
            )
        )
        if (
            pointer_attestation_result.payload
            != pointer_attestation.canonical_bytes()
        ):
            raise ValueError(
                "incident feed v2 pointer attestation is not canonical"
            )
        validate_incident_enrichment_feed_pointer_assets(
            entry,
            pointer,
            pointer_attestation,
            trusted_key_id=feed_trust.key_id,
            signature_verifier=lambda payload, signature: self._verify_signature(
                feed_trust,
                payload=payload,
                detached_signature=signature,
            ),
        )

        source_assets, state = self._load_v2_source_occurrence(pointer)
        if (
            pointer.lifecycle != state.lifecycle
            or pointer.state_updated_at != state.updated_at
        ):
            raise ValueError(
                "incident feed v2 pointer lifecycle does not match v1"
            )

        manifest_result = self._read_versioned_incident_asset(
            pointer.enrichment_asset.manifest_reference,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_MANIFEST_BYTES,
        )
        manifest = IncidentEnrichmentManifest.model_validate_json(
            manifest_result.payload
        )
        if manifest_result.payload != manifest.canonical_bytes():
            raise ValueError("incident enrichment manifest is not canonical")
        enrichment_attestation_result = self._read_versioned_incident_asset(
            pointer.enrichment_asset.attestation_reference,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        enrichment_attestation = IncidentEnrichmentAttestation.model_validate_json(
            enrichment_attestation_result.payload
        )
        if (
            enrichment_attestation_result.payload
            != enrichment_attestation.canonical_bytes()
        ):
            raise ValueError("incident enrichment attestation is not canonical")
        validate_incident_enrichment_assets(
            pointer.enrichment_asset,
            manifest,
            enrichment_attestation,
            trusted_enrichment_key_id=enrichment_trust.key_id,
            enrichment_signature_verifier=lambda payload, signature: (
                self._verify_signature(
                    enrichment_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        if (
            manifest.incident_state_reference
            != pointer.source_state_reference
            or manifest.incident_state_attestation_reference
            != pointer.source_state_attestation_reference
        ):
            raise ValueError(
                "incident enrichment state references do not match feed v2"
            )

        report_reference = manifest.correlation_report_asset
        report_result = self._read_versioned_incident_asset(
            report_reference.report_reference,
            maximum_bytes=MAX_PUBLISHED_CORRELATION_REPORT_BYTES,
        )
        report = CorrelationReport.model_validate_json(report_result.payload)
        if report_result.payload != report.canonical_bytes():
            raise ValueError("published correlation report is not canonical")
        report_attestation_result = self._read_versioned_incident_asset(
            report_reference.attestation_reference,
            maximum_bytes=MAX_INCIDENT_ENRICHMENT_ATTESTATION_BYTES,
        )
        report_attestation = PublishedCorrelationReportAttestation.model_validate_json(
            report_attestation_result.payload
        )
        if report_attestation_result.payload != report_attestation.canonical_bytes():
            raise ValueError(
                "published correlation report attestation is not canonical"
            )
        self._validate_published_report_assets(
            report_reference,
            report,
            report_attestation,
            trust=report_trust,
        )

        guidance_reference = manifest.guidance_asset
        guidance_result = self._read_versioned_incident_asset(
            guidance_reference.guidance_reference,
            maximum_bytes=MAX_INCIDENT_GUIDANCE_BYTES,
        )
        guidance = IncidentGuidance.model_validate_json(guidance_result.payload)
        if guidance_result.payload != guidance.canonical_bytes():
            raise ValueError("incident guidance is not canonical")
        guidance_attestation_result = self._read_versioned_incident_asset(
            guidance_reference.attestation_reference,
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        guidance_attestation = IncidentGuidanceAttestation.model_validate_json(
            guidance_attestation_result.payload
        )
        if (
            guidance_attestation_result.payload
            != guidance_attestation.canonical_bytes()
        ):
            raise ValueError("incident guidance attestation is not canonical")
        validate_incident_guidance_assets(
            guidance_reference,
            guidance,
            guidance_attestation,
            trusted_guidance_key_id=guidance_trust.key_id,
            guidance_signature_verifier=lambda payload, signature: (
                self._verify_signature(
                    guidance_trust,
                    payload=payload,
                    detached_signature=signature,
                )
            ),
        )
        self._validate_enrichment_content_binding(
            manifest,
            report,
            report_attestation,
            guidance,
        )

        assets = {
            entry.feed_pointer_reference.name: pointer_result.payload,
            entry.feed_pointer_attestation_reference.name: (
                pointer_attestation_result.payload
            ),
            pointer.enrichment_asset.manifest_reference.name: (
                manifest_result.payload
            ),
            pointer.enrichment_asset.attestation_reference.name: (
                enrichment_attestation_result.payload
            ),
            report_reference.report_reference.name: report_result.payload,
            report_reference.attestation_reference.name: (
                report_attestation_result.payload
            ),
            guidance_reference.guidance_reference.name: guidance_result.payload,
            guidance_reference.attestation_reference.name: (
                guidance_attestation_result.payload
            ),
            **source_assets,
        }
        return _VerifiedIncidentFeedV2Entry(assets=assets)

    def _load_v2_source_occurrence(
        self,
        pointer: IncidentEnrichmentFeedPointer,
    ) -> tuple[dict[str, bytes], IncidentState]:
        state_result = self._read_versioned_incident_asset(
            pointer.source_state_reference,
            maximum_bytes=MAX_INCIDENT_STATE_BYTES,
        )
        state_attestation_result = self._read_versioned_incident_asset(
            pointer.source_state_attestation_reference,
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        source_pointer_result = self._read_versioned_incident_asset(
            pointer.source_pointer_reference,
            maximum_bytes=MAX_INCIDENT_FEED_POINTER_BYTES,
        )
        source_pointer_attestation_result = self._read_versioned_incident_asset(
            pointer.source_pointer_attestation_reference,
            maximum_bytes=MAX_PRESENTATION_ATTESTATION_BYTES,
        )
        state = IncidentState.model_validate_json(state_result.payload)
        state_attestation = IncidentStateAttestation.model_validate_json(
            state_attestation_result.payload
        )
        source_pointer = IncidentFeedPointer.model_validate_json(
            source_pointer_result.payload
        )
        source_pointer_attestation = IncidentFeedAttestation.model_validate_json(
            source_pointer_attestation_result.payload
        )
        canonical_assets = (
            (state_result.payload, state.canonical_bytes()),
            (
                state_attestation_result.payload,
                state_attestation.canonical_bytes(),
            ),
            (source_pointer_result.payload, source_pointer.canonical_bytes()),
            (
                source_pointer_attestation_result.payload,
                source_pointer_attestation.canonical_bytes(),
            ),
        )
        if any(actual != expected for actual, expected in canonical_assets):
            raise ValueError("incident feed v2 source occurrence is not canonical")
        if (
            source_pointer.key_id != self._incident_key_id
            or source_pointer.key_fingerprint
            != self._incident_key_fingerprint
            or state_attestation.key_vault_key_id != self._incident_key_id
            or source_pointer_attestation.key_vault_key_id
            != self._incident_key_id
            or state.result_digest
            != sha256_hex(incident_state_signature_preimage(state))
            or not self._verify_incident_signature(
                payload=incident_state_signature_preimage(state),
                detached_signature=state_attestation.detached_signature,
            )
            or not self._verify_incident_signature(
                payload=source_pointer_result.payload,
                detached_signature=(
                    source_pointer_attestation.detached_signature
                ),
            )
        ):
            raise ValueError("incident feed v2 source occurrence signature is invalid")
        occurrence = build_incident_occurrence_receipt(
            state,
            state_attestation,
            source_pointer,
            source_pointer_attestation,
            state_reference=pointer.source_state_reference,
            state_attestation_reference=(
                pointer.source_state_attestation_reference
            ),
            pointer_reference=pointer.source_pointer_reference,
            pointer_attestation_reference=(
                pointer.source_pointer_attestation_reference
            ),
        )
        if occurrence.occurrence_digest != pointer.occurrence_digest:
            raise ValueError(
                "incident feed v2 pointer occurrence digest is invalid"
            )
        return (
            {
                pointer.source_state_reference.name: state_result.payload,
                pointer.source_state_attestation_reference.name: (
                    state_attestation_result.payload
                ),
                pointer.source_pointer_reference.name: (
                    source_pointer_result.payload
                ),
                pointer.source_pointer_attestation_reference.name: (
                    source_pointer_attestation_result.payload
                ),
            },
            state,
        )

    def _read_versioned_incident_asset(
        self,
        reference: VersionPinnedBlobReference,
        *,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        if self._incident_reader is None:
            raise ValueError("incident asset boundary is not configured")
        return self._incident_reader.read_version(
            blob_name=reference.name,
            version_id=reference.version,
            expected_payload_sha256=reference.content_digest,
            maximum_bytes=maximum_bytes,
        )

    def _validate_published_report_assets(
        self,
        reference: PublishedCorrelationReportAssetReference,
        report: CorrelationReport,
        attestation: PublishedCorrelationReportAttestation,
        *,
        trust: GatewaySignatureTrustAnchor,
    ) -> None:
        statement = attestation.statement
        report_bytes = report.canonical_bytes()
        if (
            reference.incident_id != statement.incident_id
            or reference.incident_transition_id
            != statement.incident_transition_id
            or reference.incident_revision != statement.incident_revision
            or reference.incident_state_result_digest
            != statement.incident_state_result_digest
            or reference.incident_subject_id != statement.incident_subject_id
            or reference.incident_subject_digest
            != statement.incident_subject_digest
            or reference.incident_bound_request_id
            != statement.incident_bound_request_id
            or reference.incident_bound_request_digest
            != statement.incident_bound_request_digest
            or reference.correlation_request_digest
            != statement.correlation_request_digest
            or reference.correlation_transition_digest
            != statement.correlation_transition_digest
            or reference.authority_proof_digest
            != statement.authority_proof_digest
            or reference.report_id != report.report_id
            or reference.report_digest != report.report_digest
            or reference.report_content_digest != sha256_hex(report_bytes)
            or reference.publication_statement_id != statement.statement_id
            or reference.publication_statement_digest
            != statement.statement_digest
            or statement.report_id != report.report_id
            or statement.report_digest != report.report_digest
            or statement.report_content_digest != sha256_hex(report_bytes)
            or statement.correlation_request_digest != report.request_digest
            or statement.correlation_transition_digest
            != report.transition_digest
            or attestation.key_vault_key_id != trust.key_id
            or not self._verify_signature(
                trust,
                payload=statement.canonical_bytes(),
                detached_signature=attestation.detached_signature,
            )
        ):
            raise ValueError(
                "published correlation report assets do not match exact content"
            )

    @staticmethod
    def _validate_enrichment_content_binding(
        manifest: IncidentEnrichmentManifest,
        report: CorrelationReport,
        report_attestation: PublishedCorrelationReportAttestation,
        guidance: IncidentGuidance,
    ) -> None:
        source = guidance.source_binding
        statement = report_attestation.statement
        if (
            statement.incident_state_reference
            != manifest.incident_state_reference
            or statement.incident_state_attestation_reference
            != manifest.incident_state_attestation_reference
            or source.incident_id != manifest.incident_id
            or source.incident_revision != manifest.incident_revision
            or source.incident_state_digest
            != manifest.incident_state_result_digest
            or source.incident_subject_id != manifest.incident_subject_id
            or source.incident_subject_digest
            != manifest.incident_subject_digest
            or source.incident_bound_request_id
            != manifest.incident_bound_request_id
            or source.incident_bound_request_digest
            != manifest.incident_bound_request_digest
            or source.correlation_report_id != report.report_id
            or source.correlation_report_digest != report.report_digest
            or source.correlation_request_digest != report.request_digest
            or source.transition_digest != report.transition_digest
        ):
            raise ValueError(
                "incident enrichment content does not bind one exact occurrence"
            )

    @staticmethod
    def _require_v2_trust(
        trust: GatewaySignatureTrustAnchor | None,
    ) -> GatewaySignatureTrustAnchor:
        if trust is None:
            raise ValueError("incident feed v2 trust is unavailable")
        return trust

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
        return self._verify_rsa_signature(
            self._incident_public_key,
            payload=payload,
            detached_signature=detached_signature,
        )

    @staticmethod
    def _verify_signature(
        trust: GatewaySignatureTrustAnchor,
        *,
        payload: bytes,
        detached_signature: str,
    ) -> bool:
        return PresentationAssetGatewayApplication._verify_rsa_signature(
            trust.public_key,
            payload=payload,
            detached_signature=detached_signature,
        )

    @staticmethod
    def _verify_rsa_signature(
        public_key: rsa.RSAPublicKey,
        *,
        payload: bytes,
        detached_signature: str,
    ) -> bool:
        try:
            signature = base64.urlsafe_b64decode(
                detached_signature
                + "=" * (-len(detached_signature) % 4)
            )
            public_key.verify(
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
    incident_feed_v2_key_id: str | None = None,
    incident_feed_v2_key_fingerprint: str | None = None,
    incident_feed_v2_public_key_path: Path | None = None,
    incident_report_key_id: str | None = None,
    incident_report_key_fingerprint: str | None = None,
    incident_report_public_key_path: Path | None = None,
    incident_guidance_key_id: str | None = None,
    incident_guidance_key_fingerprint: str | None = None,
    incident_guidance_public_key_path: Path | None = None,
    incident_enrichment_key_id: str | None = None,
    incident_enrichment_key_fingerprint: str | None = None,
    incident_enrichment_public_key_path: Path | None = None,
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
        v2_values = (
            incident_feed_v2_key_id,
            incident_feed_v2_key_fingerprint,
            incident_feed_v2_public_key_path,
            incident_report_key_id,
            incident_report_key_fingerprint,
            incident_report_public_key_path,
            incident_guidance_key_id,
            incident_guidance_key_fingerprint,
            incident_guidance_public_key_path,
            incident_enrichment_key_id,
            incident_enrichment_key_fingerprint,
            incident_enrichment_public_key_path,
        )
        if any(value is not None for value in v2_values) and any(
            value is None for value in v2_values
        ):
            raise ValueError(
                "incident feed v2 runtime trust configuration must be complete"
            )

        def load_v2_trust(
            key_id: str | None,
            key_fingerprint: str | None,
            public_key_path: Path | None,
        ) -> GatewaySignatureTrustAnchor | None:
            if (
                key_id is None
                or key_fingerprint is None
                or public_key_path is None
            ):
                return None
            loaded = serialization.load_pem_public_key(
                public_key_path.read_bytes()
            )
            if not isinstance(loaded, rsa.RSAPublicKey):
                raise ValueError(
                    "incident feed v2 trust anchor must be an RSA public key"
                )
            return GatewaySignatureTrustAnchor(
                key_id=key_id,
                key_fingerprint=key_fingerprint,
                public_key=loaded,
            )

        application = PresentationAssetGatewayApplication(
            active_reader,
            incident_reader=incident_reader,
            incident_key_id=incident_key_id,
            incident_key_fingerprint=incident_key_fingerprint,
            incident_public_key=public_key_value,
            incident_feed_v2_trust=load_v2_trust(
                incident_feed_v2_key_id,
                incident_feed_v2_key_fingerprint,
                incident_feed_v2_public_key_path,
            ),
            incident_report_trust=load_v2_trust(
                incident_report_key_id,
                incident_report_key_fingerprint,
                incident_report_public_key_path,
            ),
            incident_guidance_trust=load_v2_trust(
                incident_guidance_key_id,
                incident_guidance_key_fingerprint,
                incident_guidance_public_key_path,
            ),
            incident_enrichment_trust=load_v2_trust(
                incident_enrichment_key_id,
                incident_enrichment_key_fingerprint,
                incident_enrichment_public_key_path,
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
    "GatewaySignatureTrustAnchor",
    "PresentationAssetGatewayApplication",
    "PresentationAssetGatewayError",
    "run_presentation_asset_gateway",
]
