from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from athena_context.cli import build_parser
from athena_context.contracts import (
    PRESENTATION_PUBLIC_KEY_ASSET_SHA256,
    PRESENTATION_PUBLIC_KEY_FINGERPRINT,
    PRESENTATION_PUBLIC_KEY_ID,
    PRESENTATION_PUBLIC_KEY_PATH,
    ActiveIncidentEntry,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    IncidentEnrichmentAssetReference,
    IncidentEnrichmentAttestation,
    IncidentEnrichmentFeedPointerAttestation,
    IncidentFeedAttestation,
    IncidentFeedEntryV2,
    IncidentFeedIndexAttestationV2,
    IncidentFeedPointer,
    IncidentGuidanceAssetReference,
    PresentationRuntimeKey,
    PresentationRuntimeManifestV2,
    PresentationRuntimePhaseAsset,
    PublishedCorrelationReportAssetReference,
    PublishedGuidanceAuthorityBinding,
    PublishedGuidanceAuthorityBindingAttestation,
    VersionPinnedBlobReference,
    build_incident_enrichment_feed_pointer,
    build_incident_enrichment_manifest,
    build_incident_feed_index_v2,
    build_incident_occurrence_receipt,
    compute_artifact_digest,
    incident_state_signature_preimage,
    sha256_hex,
)
from athena_context.presentation_asset_gateway import (
    GatewaySignatureTrustAnchor,
    PresentationAssetGatewayApplication,
)
from athena_context.presentation_assets import PresentationAssetReadResult
from test_wc026_correlation_contract import _hypothesis, _report_for, _request
from test_wc027_guidance_authority_contract import (
    _authority,
    _no_runbook_selection,
)
from test_wc027_incident_enrichment_contract import (
    _guidance_assets,
    _json_value,
    _report_assets,
)
from test_wc027_incident_subject_contract import (
    _bound_request,
    _incident_state,
    _subject,
)

RUN_ID = "synthetic-run-live-001"
ROOT = Path(__file__).parents[1]


class InMemoryPresentationReader:
    def __init__(
        self,
        content: dict[str, bytes],
        versioned_content: dict[tuple[str, str], bytes] | None = None,
    ) -> None:
        self.content = content
        self.versioned_content = versioned_content or {}
        self.requests: list[tuple[str, int]] = []
        self.version_requests: list[tuple[str, str, str, int]] = []

    def read_current(
        self,
        *,
        blob_name: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        self.requests.append((blob_name, maximum_bytes))
        payload = self.content[blob_name]
        if len(payload) > maximum_bytes:
            raise RuntimeError("too large")
        return PresentationAssetReadResult(
            blob_name=blob_name,
            payload=payload,
            payload_sha256=sha256_hex(payload),
        )

    def read_version(
        self,
        *,
        blob_name: str,
        version_id: str,
        expected_payload_sha256: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult:
        self.version_requests.append(
            (
                blob_name,
                version_id,
                expected_payload_sha256,
                maximum_bytes,
            )
        )
        try:
            payload = self.versioned_content[(blob_name, version_id)]
        except KeyError as exc:
            raise RuntimeError("versioned asset is unavailable") from exc
        digest = sha256_hex(payload)
        if len(payload) > maximum_bytes or digest != expected_payload_sha256:
            raise RuntimeError("versioned asset is unavailable")
        return PresentationAssetReadResult(
            blob_name=blob_name,
            payload=payload,
            payload_sha256=digest,
        )


def test_incident_gateway_and_browser_pin_the_same_public_key() -> None:
    public_key = serialization.load_pem_public_key(
        (ROOT / "wc016-incident-public-key.pem").read_bytes()
    )
    assert isinstance(public_key, rsa.RSAPublicKey)
    numbers = public_key.public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

    def encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    browser_key = json.loads(
        (
            ROOT
            / "apps"
            / "presentation-web"
            / "public"
            / "trust"
            / "incident-public-key.jwk.json"
        ).read_text(encoding="utf-8")
    )
    fingerprint = "sha256:" + hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()

    assert browser_key["jwk"]["n"] == encode(modulus)
    assert browser_key["jwk"]["e"] == encode(exponent)
    assert browser_key["fingerprint"] == fingerprint
    parameters = json.loads(
        (ROOT / ".azure" / "wc013.parameters.json").read_text(encoding="utf-8")
    )
    assert (
        parameters["parameters"]["signingKeyFingerprint"]["value"]
        == fingerprint
    )
    verification_source = (
        ROOT / "apps" / "presentation-web" / "src" / "verification.ts"
    ).read_text(encoding="utf-8")
    match = re.search(
        r"PINNED_INCIDENT_KEY_FINGERPRINT\s*=\s*\n\s*'([^']+)'",
        verification_source,
    )
    assert match is not None
    assert match.group(1) == fingerprint


def _asset_bytes(phase: str, kind: str) -> bytes:
    return (
        json.dumps(
            {"phase": phase, "kind": kind},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _manifest_and_content() -> tuple[
    PresentationRuntimeManifestV2,
    dict[str, bytes],
]:
    content: dict[str, bytes] = {}
    phases: list[PresentationRuntimePhaseAsset] = []
    for phase in ("baseline", "faulted", "recovered"):
        payload_path = (
            f"./live/runs/{RUN_ID}/{phase}/argus-presentation.json"
        )
        attestation_path = (
            f"./live/runs/{RUN_ID}/{phase}/presentation-attestation.json"
        )
        payload = _asset_bytes(phase, "payload")
        attestation = _asset_bytes(phase, "attestation")
        content[payload_path.removeprefix("./")] = payload
        content[attestation_path.removeprefix("./")] = attestation
        phases.append(
            PresentationRuntimePhaseAsset(
                phase=phase,
                payloadPath=payload_path,
                payloadSha256=sha256_hex(payload),
                attestationPath=attestation_path,
                attestationSha256=sha256_hex(attestation),
            )
        )
    manifest = PresentationRuntimeManifestV2(
        schemaVersion="athena.presentationWeb.runtime.v2",
        classification="live-workload-evaluation",
        runId=RUN_ID,
        targetResourceGroup="athena-synthetic-workload-rg",
        evaluatedAt=datetime(2026, 9, 1, 23, 59, tzinfo=UTC),
        publishedAt=datetime(2026, 9, 2, tzinfo=UTC),
        key=PresentationRuntimeKey(
            path=PRESENTATION_PUBLIC_KEY_PATH,
            assetSha256=PRESENTATION_PUBLIC_KEY_ASSET_SHA256,
            keyId=PRESENTATION_PUBLIC_KEY_ID,
            fingerprint=PRESENTATION_PUBLIC_KEY_FINGERPRINT,
        ),
        phases=tuple(phases),  # type: ignore[arg-type]
    )
    content["runtime-manifest.json"] = manifest.canonical_bytes()
    return manifest, content


def test_gateway_serves_only_current_manifest_allowlisted_assets_and_health() -> None:
    manifest, content = _manifest_and_content()
    reader = InMemoryPresentationReader(content)
    app = PresentationAssetGatewayApplication(reader)

    health = app.handle(method="GET", raw_path="/healthz")
    runtime = app.handle(method="HEAD", raw_path="/runtime-manifest.json")
    payload_path = "/" + manifest.phases[1].payload_path.removeprefix("./")
    payload = app.handle(method="GET", raw_path=payload_path)

    assert health.status == 200
    assert runtime.status == 200
    assert runtime.payload == manifest.canonical_bytes()
    assert payload.status == 200
    assert payload.payload == content[payload_path.removeprefix("/")]
    assert reader.requests == [
        ("runtime-manifest.json", 16 * 1024),
        ("runtime-manifest.json", 16 * 1024),
        (payload_path.removeprefix("/"), 128 * 1024),
    ]


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("POST", "/runtime-manifest.json", 405),
        ("GET", "/live/", 404),
        ("GET", "/live/runs/other/baseline/argus-presentation.json", 404),
        ("GET", "/trust/presentation-public-key.jwk.json", 404),
        ("GET", "/runtime-manifest.json?list=true", 404),
        ("GET", "/live/runs/%2e%2e/private.json", 404),
    ],
)
def test_gateway_rejects_write_listing_and_arbitrary_paths(
    method: str,
    path: str,
    status: int,
) -> None:
    _, content = _manifest_and_content()
    app = PresentationAssetGatewayApplication(InMemoryPresentationReader(content))

    response = app.handle(method=method, raw_path=path)

    assert response.status == status
    assert response.payload.startswith(b'{"error":')


def test_gateway_revalidates_manifest_and_asset_digests_on_every_request() -> None:
    manifest, content = _manifest_and_content()
    payload_path = manifest.phases[0].payload_path.removeprefix("./")
    reader = InMemoryPresentationReader(content)
    app = PresentationAssetGatewayApplication(reader)

    assert app.handle(method="GET", raw_path="/" + payload_path).status == 200
    reader.content[payload_path] += b" "

    response = app.handle(method="GET", raw_path="/" + payload_path)

    assert response.status == 503
    assert response.payload == b'{"error":"presentation assets unavailable"}\n'
    assert [item[0] for item in reader.requests].count("runtime-manifest.json") == 2


def test_runtime_manifest_v2_rejects_run_path_drift() -> None:
    manifest, _ = _manifest_and_content()
    payload = manifest.model_dump(mode="json", by_alias=True)
    payload["phases"][0]["payloadPath"] = (
        f"./live/runs/{RUN_ID}/faulted/argus-presentation.json"
    )

    with pytest.raises(ValueError, match="payload path"):
        PresentationRuntimeManifestV2.model_validate_json(json.dumps(payload))


def test_gateway_cli_defaults_to_the_bounded_private_sidecar_port() -> None:
    args = build_parser().parse_args(
        [
            "presentation-asset-gateway",
            "--blob-endpoint",
            "https://athenareplay.blob.core.windows.net",
            "--managed-identity-client-id",
            "11111111-1111-1111-1111-111111111111",
            "--incident-key-id",
            "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1",
            "--incident-key-fingerprint",
            "sha256:" + "1" * 64,
            "--incident-public-key",
            "wc016-incident-public-key.pem",
        ]
    )

    assert args.container == "presentation-assets"
    assert args.port == 8081


def test_gateway_serves_only_the_current_incident_pointer_allowlist() -> None:
    _, content = _manifest_and_content()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    fingerprint = "sha256:" + hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    key_id = "synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"
    state = _asset_bytes("active", "incident-state")
    attestation = _asset_bytes("active", "incident-attestation")
    version = "a" * 64
    state_path = f"./incidents/inc-123456789abc/versions/{version}/state.json"
    attestation_path = (
        f"./incidents/inc-123456789abc/versions/{version}/attestation.json"
    )
    pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId="inc-123456789abc",
        statePath=state_path,
        stateSha256=sha256_hex(state),
        attestationPath=attestation_path,
        attestationSha256=sha256_hex(attestation),
        pointerAttestationPath=(
            f"./incidents/inc-123456789abc/versions/{version}/pointer-attestation.json"
        ),
        keyId=key_id,
        keyFingerprint=fingerprint,
        publishedAt=datetime(2026, 9, 4, tzinfo=UTC),
    )
    pointer_bytes = pointer.canonical_bytes()
    pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(pointer_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=key_id,
        detachedSignature=_signature(private_key, pointer_bytes),
    )
    pointer_path = f"incidents/inc-123456789abc/versions/{version}/pointer.json"
    index = ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=(
            ActiveIncidentEntry(
                incidentId="inc-123456789abc",
                scenario="webServerFailure",
                lifecycle="active",
                workloadRole="web",
                pointerPath=f"./{pointer_path}",
                pointerSha256=sha256_hex(pointer_bytes),
                detectedAt=datetime(2026, 9, 4, tzinfo=UTC),
                updatedAt=datetime(2026, 9, 4, tzinfo=UTC),
            ),
        ),
        indexAttestationPath="./incidents/index-attestations/" + "a" * 64 + ".json",
        keyId=key_id,
        keyFingerprint=fingerprint,
        publishedAt=datetime(2026, 9, 4, tzinfo=UTC),
    )
    index_bytes = index.canonical_bytes()
    index_attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(index_bytes),
        signatureAlgorithm="RS256",
        keyVaultKeyId=key_id,
        detachedSignature=_signature(private_key, index_bytes),
    )
    content["incidents/active.json"] = index_bytes
    content[index.index_attestation_path.removeprefix("./")] = (
        index_attestation.canonical_bytes()
    )
    content[pointer_path] = pointer_bytes
    content[pointer.pointer_attestation_path.removeprefix("./")] = (
        pointer_attestation.canonical_bytes()
    )
    content[state_path.removeprefix("./")] = state
    content[attestation_path.removeprefix("./")] = attestation
    reader = InMemoryPresentationReader(content)
    app = PresentationAssetGatewayApplication(
        reader,
        incident_reader=reader,
        incident_key_id=key_id,
        incident_key_fingerprint=fingerprint,
        incident_public_key=public_key,
    )

    current = app.handle(method="GET", raw_path="/incidents/active.json")
    incident_pointer = app.handle(method="GET", raw_path="/" + pointer_path)
    current_attestation = app.handle(
        method="GET",
        raw_path="/" + pointer.pointer_attestation_path.removeprefix("./"),
    )
    incident = app.handle(
        method="GET",
        raw_path="/" + state_path.removeprefix("./"),
    )
    arbitrary = app.handle(
        method="GET",
        raw_path="/incidents/inc-123456789abc/private.json",
    )

    assert current.status == 200
    assert incident_pointer.status == 200
    assert current_attestation.status == 200
    assert incident.status == 200
    assert arbitrary.status == 404

    content[index.index_attestation_path.removeprefix("./")] = (
        index_attestation.model_copy(
            update={"detached_signature": "AAAA"}
        ).canonical_bytes()
    )
    assert app.handle(method="GET", raw_path="/incidents/active.json").status == 503
    content[index.index_attestation_path.removeprefix("./")] = (
        index_attestation.canonical_bytes()
    )
    content[pointer.pointer_attestation_path.removeprefix("./")] = (
        pointer_attestation.model_copy(
            update={"detached_signature": "AAAA"}
        ).canonical_bytes()
    )
    assert (
        app.handle(
            method="GET",
            raw_path="/" + state_path.removeprefix("./"),
        ).status
        == 503
    )


def _signature(private_key: rsa.RSAPrivateKey, payload: bytes) -> str:
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _trust(
    name: str,
) -> tuple[rsa.RSAPrivateKey, GatewaySignatureTrustAnchor]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    fingerprint = "sha256:" + hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    return private_key, GatewaySignatureTrustAnchor(
        key_id=f"https://synthetic-wc027.vault.azure.net/keys/{name}/version-1",
        key_fingerprint=fingerprint,
        public_key=public_key,
    )


def _reference_with_attestation_digest(
    reference,
    *,
    attestation_digest: str,
    model_type,
    id_prefix: str,
):
    payload = reference.model_dump(
        mode="python",
        by_alias=True,
        exclude={"reference_id", "reference_digest"},
    )
    payload["attestationReference"] = reference.attestation_reference.model_copy(
        update={"content_digest": attestation_digest}
    )
    digest = compute_artifact_digest(_json_value(payload))
    return model_type(
        **payload,
        referenceId=f"{id_prefix}-{digest.removeprefix('sha256:')[:32]}",
        referenceDigest=digest,
    )


def _feed_v2_gateway_fixture():
    lifecycle_private, lifecycle_trust = _trust("lifecycle")
    feed_private, feed_trust = _trust("feed")
    report_private, report_trust = _trust("report")
    guidance_private, guidance_trust = _trust("guidance")
    enrichment_private, enrichment_trust = _trust("enrichment")

    state, unsigned_state_attestation = _incident_state()
    state_attestation = unsigned_state_attestation.model_copy(
        update={
            "key_vault_key_id": lifecycle_trust.key_id,
            "detached_signature": _signature(
                lifecycle_private,
                incident_state_signature_preimage(state),
            ),
        }
    )
    correlation_request = _request()
    report = _report_for(
        correlation_request,
        _hypothesis(citation=correlation_request.evidence_index[0]),
    )
    subject = _subject(state=state, attestation=state_attestation)
    bound_request = _bound_request(
        subject=subject,
        correlation_request=correlation_request,
    )
    authority = _authority(request=correlation_request)
    selection = _no_runbook_selection(
        request=correlation_request,
        report=report,
    )
    authority_reference = VersionPinnedBlobReference(
        name=f"guidance-authority/{authority.authority_id}/authority.json",
        version="authority-version",
        contentDigest=sha256_hex(authority.canonical_bytes()),
    )
    binding_payload: dict[str, object] = {
        "schemaVersion": "athena.wc027PublishedGuidanceAuthorityBinding.v2",
        "incidentBoundRequest": bound_request,
        "correlationReport": report,
        "guidanceAuthority": authority,
        "guidanceAuthorityReference": authority_reference,
        "requestedActions": ("investigationCheck",),
        "evaluatedAt": report.as_of,
        "selection": selection,
    }
    binding_attestation = PublishedGuidanceAuthorityBindingAttestation(
        schemaVersion=(
            "athena.wc027PublishedGuidanceAuthorityBindingAttestation.v2"
        ),
        signatureAlgorithm="RS256",
        keyVaultKeyId="synthetic-key://guidance-binding",
        signedPreimageDigest=compute_artifact_digest(
            _json_value(binding_payload)
        ),
        detachedSignature="c3ludGhldGlj",
    )
    binding_payload["bindingAttestation"] = binding_attestation
    binding_digest = compute_artifact_digest(_json_value(binding_payload))
    binding = PublishedGuidanceAuthorityBinding(
        **binding_payload,
        bindingId=(
            f"guidance-binding-{binding_digest.removeprefix('sha256:')[:32]}"
        ),
        bindingDigest=binding_digest,
    )

    fake_report_reference, report, fake_report_attestation, _ = _report_assets(
        binding
    )
    report_attestation = fake_report_attestation.model_copy(
        update={
            "key_vault_key_id": report_trust.key_id,
            "detached_signature": _signature(
                report_private,
                fake_report_attestation.statement.canonical_bytes(),
            ),
        }
    )
    report_reference = _reference_with_attestation_digest(
        fake_report_reference,
        attestation_digest=sha256_hex(report_attestation.canonical_bytes()),
        model_type=PublishedCorrelationReportAssetReference,
        id_prefix="report-asset",
    )

    fake_guidance_reference, guidance, fake_guidance_attestation = (
        _guidance_assets(binding)
    )
    guidance_attestation = fake_guidance_attestation.model_copy(
        update={
            "key_vault_key_id": guidance_trust.key_id,
            "detached_signature": _signature(
                guidance_private,
                guidance.canonical_bytes(),
            ),
        }
    )
    guidance_reference = _reference_with_attestation_digest(
        fake_guidance_reference,
        attestation_digest=sha256_hex(guidance_attestation.canonical_bytes()),
        model_type=IncidentGuidanceAssetReference,
        id_prefix="guidance-asset",
    )

    manifest = build_incident_enrichment_manifest(
        bound_request,
        report_reference,
        report,
        guidance_reference,
        guidance,
    )
    enrichment_attestation = IncidentEnrichmentAttestation(
        schemaVersion="athena.wc027IncidentEnrichmentAttestation.v1",
        enrichmentId=manifest.enrichment_id,
        manifestDigest=manifest.manifest_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=enrichment_trust.key_id,
        signedPreimageDigest=sha256_hex(manifest.canonical_bytes()),
        detachedSignature=_signature(
            enrichment_private,
            manifest.canonical_bytes(),
        ),
    )
    enrichment_prefix = (
        f"incidents/{state.incident_id}/versions/"
        f"{state.result_digest.removeprefix('sha256:')}/enrichments/"
        f"{manifest.enrichment_id}"
    )
    enrichment_payload: dict[str, object] = {
        "schemaVersion": (
            "athena.wc027IncidentEnrichmentAssetReference.v1"
        ),
        "incidentId": state.incident_id,
        "incidentStateResultDigest": state.result_digest,
        "enrichmentId": manifest.enrichment_id,
        "manifestDigest": manifest.manifest_digest,
        "manifestReference": VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/manifest.json",
            version="manifest-version",
            contentDigest=sha256_hex(manifest.canonical_bytes()),
        ),
        "attestationReference": VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/attestation.json",
            version="enrichment-attestation-version",
            contentDigest=sha256_hex(enrichment_attestation.canonical_bytes()),
        ),
    }
    enrichment_digest = compute_artifact_digest(
        _json_value(enrichment_payload)
    )
    enrichment_reference = IncidentEnrichmentAssetReference(
        **enrichment_payload,
        referenceId=(
            f"enrichment-asset-"
            f"{enrichment_digest.removeprefix('sha256:')[:32]}"
        ),
        referenceDigest=enrichment_digest,
    )

    state_reference = subject.state_reference
    state_attestation_reference = subject.attestation_reference
    state_prefix = state_reference.name.removesuffix("/state.json")
    source_pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        incidentId=state.incident_id,
        statePath=f"./{state_reference.name}",
        stateSha256=state_reference.content_digest,
        attestationPath=f"./{state_attestation_reference.name}",
        attestationSha256=state_attestation_reference.content_digest,
        pointerAttestationPath=f"./{state_prefix}/pointer-attestation.json",
        keyId=lifecycle_trust.key_id,
        keyFingerprint=lifecycle_trust.key_fingerprint,
        publishedAt=state.updated_at + timedelta(seconds=1),
    )
    source_pointer_attestation = IncidentFeedAttestation(
        schemaVersion="athena.incidentFeedAttestation.v1",
        pointerDigest=sha256_hex(source_pointer.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=lifecycle_trust.key_id,
        detachedSignature=_signature(
            lifecycle_private,
            source_pointer.canonical_bytes(),
        ),
    )
    source_pointer_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/pointer.json",
        version="pointer-version",
        contentDigest=sha256_hex(source_pointer.canonical_bytes()),
    )
    source_pointer_attestation_reference = VersionPinnedBlobReference(
        name=f"{state_prefix}/pointer-attestation.json",
        version="pointer-attestation-version",
        contentDigest=sha256_hex(
            source_pointer_attestation.canonical_bytes()
        ),
    )
    occurrence = build_incident_occurrence_receipt(
        state,
        state_attestation,
        source_pointer,
        source_pointer_attestation,
        state_reference=state_reference,
        state_attestation_reference=state_attestation_reference,
        pointer_reference=source_pointer_reference,
        pointer_attestation_reference=source_pointer_attestation_reference,
    )
    feed_pointer = build_incident_enrichment_feed_pointer(
        occurrence,
        enrichment_reference,
        state,
        published_at=occurrence.published_at + timedelta(seconds=1),
    )
    feed_pointer_attestation = IncidentEnrichmentFeedPointerAttestation(
        schemaVersion=(
            "athena.wc027IncidentEnrichmentFeedPointerAttestation.v2"
        ),
        pointerId=feed_pointer.pointer_id,
        pointerDigest=feed_pointer.pointer_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=feed_trust.key_id,
        signedPreimageDigest=sha256_hex(feed_pointer.canonical_bytes()),
        detachedSignature=_signature(
            feed_private,
            feed_pointer.canonical_bytes(),
        ),
    )
    feed_entry = IncidentFeedEntryV2(
        incidentId=state.incident_id,
        lifecycle=state.lifecycle,
        stateResultDigest=state.result_digest,
        updatedAt=state.updated_at,
        feedPointerReference=VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/feed-pointer.json",
            version="feed-pointer-version",
            contentDigest=sha256_hex(feed_pointer.canonical_bytes()),
        ),
        feedPointerAttestationReference=VersionPinnedBlobReference(
            name=f"{enrichment_prefix}/feed-pointer-attestation.json",
            version="feed-pointer-attestation-version",
            contentDigest=sha256_hex(
                feed_pointer_attestation.canonical_bytes()
            ),
        ),
    )

    active_index = ActiveIncidentIndex(
        schemaVersion="athena.activeIncidentIndex.v1",
        incidents=(
            ActiveIncidentEntry(
                incidentId=state.incident_id,
                scenario=state.scenario,
                lifecycle="active",
                workloadRole=state.workload_role,
                pointerPath=f"./{source_pointer_reference.name}",
                pointerSha256=source_pointer_reference.content_digest,
                detectedAt=state.detected_at,
                updatedAt=state.updated_at,
            ),
        ),
        indexAttestationPath="./incidents/index-attestations/" + "a" * 64 + ".json",
        keyId=lifecycle_trust.key_id,
        keyFingerprint=lifecycle_trust.key_fingerprint,
        publishedAt=source_pointer.published_at,
    )
    active_index_attestation = ActiveIncidentIndexAttestation(
        schemaVersion="athena.activeIncidentIndexAttestation.v1",
        indexDigest=sha256_hex(active_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=lifecycle_trust.key_id,
        detachedSignature=_signature(
            lifecycle_private,
            active_index.canonical_bytes(),
        ),
    )
    feed_index = build_incident_feed_index_v2(
        active=(feed_entry,),
        recently_resolved=(),
        resolved_retention_start=state.updated_at - timedelta(days=7),
        resolved_history_truncated=False,
        resolved_history_total_count=0,
        omitted_resolved_count=None,
        source_active_index_digest=sha256_hex(
            active_index.canonical_bytes()
        ),
        key_id=feed_trust.key_id,
        key_fingerprint=feed_trust.key_fingerprint,
        published_at=feed_pointer.published_at + timedelta(seconds=1),
    )
    feed_index_attestation = IncidentFeedIndexAttestationV2(
        schemaVersion="athena.wc027IncidentFeedIndexAttestation.v2",
        indexDigest=sha256_hex(feed_index.canonical_bytes()),
        signatureAlgorithm="RS256",
        keyVaultKeyId=feed_trust.key_id,
        detachedSignature=_signature(
            feed_private,
            feed_index.canonical_bytes(),
        ),
    )

    current = {
        "incidents/active.json": active_index.canonical_bytes(),
        active_index.index_attestation_path.removeprefix(
            "./"
        ): active_index_attestation.canonical_bytes(),
        source_pointer_reference.name: source_pointer.canonical_bytes(),
        source_pointer_attestation_reference.name: (
            source_pointer_attestation.canonical_bytes()
        ),
        state_reference.name: state.canonical_bytes(),
        state_attestation_reference.name: state_attestation.canonical_bytes(),
        "incidents/feed-v2.json": feed_index.canonical_bytes(),
        feed_index.index_attestation_path.removeprefix(
            "./"
        ): feed_index_attestation.canonical_bytes(),
    }
    versioned = {
        (state_reference.name, state_reference.version): state.canonical_bytes(),
        (
            state_attestation_reference.name,
            state_attestation_reference.version,
        ): state_attestation.canonical_bytes(),
        (
            source_pointer_reference.name,
            source_pointer_reference.version,
        ): source_pointer.canonical_bytes(),
        (
            source_pointer_attestation_reference.name,
            source_pointer_attestation_reference.version,
        ): source_pointer_attestation.canonical_bytes(),
        (
            enrichment_reference.manifest_reference.name,
            enrichment_reference.manifest_reference.version,
        ): manifest.canonical_bytes(),
        (
            enrichment_reference.attestation_reference.name,
            enrichment_reference.attestation_reference.version,
        ): enrichment_attestation.canonical_bytes(),
        (
            report_reference.report_reference.name,
            report_reference.report_reference.version,
        ): report.canonical_bytes(),
        (
            report_reference.attestation_reference.name,
            report_reference.attestation_reference.version,
        ): report_attestation.canonical_bytes(),
        (
            guidance_reference.guidance_reference.name,
            guidance_reference.guidance_reference.version,
        ): guidance.canonical_bytes(),
        (
            guidance_reference.attestation_reference.name,
            guidance_reference.attestation_reference.version,
        ): guidance_attestation.canonical_bytes(),
        (
            feed_entry.feed_pointer_reference.name,
            feed_entry.feed_pointer_reference.version,
        ): feed_pointer.canonical_bytes(),
        (
            feed_entry.feed_pointer_attestation_reference.name,
            feed_entry.feed_pointer_attestation_reference.version,
        ): feed_pointer_attestation.canonical_bytes(),
    }
    reader = InMemoryPresentationReader(current, versioned)
    app = PresentationAssetGatewayApplication(
        reader,
        incident_reader=reader,
        incident_key_id=lifecycle_trust.key_id,
        incident_key_fingerprint=lifecycle_trust.key_fingerprint,
        incident_public_key=lifecycle_trust.public_key,
        incident_feed_v2_trust=feed_trust,
        incident_report_trust=report_trust,
        incident_guidance_trust=guidance_trust,
        incident_enrichment_trust=enrichment_trust,
    )
    return {
        "app": app,
        "reader": reader,
        "feed_index": feed_index,
        "feed_index_attestation": feed_index_attestation,
        "feed_entry": feed_entry,
        "state": state,
        "guidance": guidance,
        "guidance_reference": guidance_reference,
        "guidance_attestation": guidance_attestation,
        "state_reference": state_reference,
    }


def test_gateway_serves_only_fully_verified_feed_v2_assets_by_exact_version() -> None:
    fixture = _feed_v2_gateway_fixture()
    app = fixture["app"]
    reader = fixture["reader"]
    feed_index = fixture["feed_index"]
    guidance = fixture["guidance"]
    guidance_reference = fixture["guidance_reference"]

    index_response = app.handle(
        method="GET",
        raw_path="/incidents/feed-v2.json",
    )
    guidance_response = app.handle(
        method="GET",
        raw_path="/" + guidance_reference.guidance_reference.name,
    )

    assert index_response.status == 200
    assert index_response.payload == feed_index.canonical_bytes()
    assert guidance_response.status == 200
    assert guidance_response.payload == guidance.canonical_bytes()
    assert (
        guidance_reference.guidance_reference.name,
        guidance_reference.guidance_reference.version,
        guidance_reference.guidance_reference.content_digest,
        64 * 1024,
    ) in reader.version_requests


def test_invalid_v2_guidance_fails_closed_without_hiding_verified_v1_lifecycle() -> None:
    fixture = _feed_v2_gateway_fixture()
    app = fixture["app"]
    reader = fixture["reader"]
    guidance_reference = fixture["guidance_reference"]
    state_reference = fixture["state_reference"]

    key = (
        guidance_reference.attestation_reference.name,
        guidance_reference.attestation_reference.version,
    )
    reader.versioned_content[key] = fixture[
        "guidance_attestation"
    ].model_copy(update={"detached_signature": "AAAA"}).canonical_bytes()

    enriched = app.handle(
        method="GET",
        raw_path="/" + guidance_reference.guidance_reference.name,
    )
    lifecycle = app.handle(
        method="GET",
        raw_path="/" + state_reference.name,
    )

    assert enriched.status == 503
    assert enriched.payload == b'{"error":"presentation assets unavailable"}\n'
    assert lifecycle.status == 200
    assert lifecycle.payload == fixture["state"].canonical_bytes()


def test_invalid_v2_index_attestation_does_not_replace_v1_lifecycle() -> None:
    fixture = _feed_v2_gateway_fixture()
    app = fixture["app"]
    reader = fixture["reader"]
    feed_index = fixture["feed_index"]
    state_reference = fixture["state_reference"]
    attestation_path = feed_index.index_attestation_path.removeprefix("./")
    reader.content[attestation_path] = fixture[
        "feed_index_attestation"
    ].model_copy(update={"detached_signature": "AAAA"}).canonical_bytes()

    feed = app.handle(method="GET", raw_path="/incidents/feed-v2.json")
    lifecycle = app.handle(
        method="GET",
        raw_path="/" + state_reference.name,
    )

    assert feed.status == 503
    assert lifecycle.status == 200
    assert lifecycle.payload == fixture["state"].canonical_bytes()
