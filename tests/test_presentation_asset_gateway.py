from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
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
    IncidentFeedAttestation,
    IncidentFeedPointer,
    PresentationRuntimeKey,
    PresentationRuntimeManifestV2,
    PresentationRuntimePhaseAsset,
    sha256_hex,
)
from athena_context.presentation_asset_gateway import (
    PresentationAssetGatewayApplication,
)
from athena_context.presentation_assets import PresentationAssetReadResult

RUN_ID = "synthetic-run-live-001"
ROOT = Path(__file__).parents[1]


class InMemoryPresentationReader:
    def __init__(self, content: dict[str, bytes]) -> None:
        self.content = content
        self.requests: list[tuple[str, int]] = []

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
