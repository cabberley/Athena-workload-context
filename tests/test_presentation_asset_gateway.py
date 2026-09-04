from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from athena_context.cli import build_parser
from athena_context.contracts import (
    PRESENTATION_PUBLIC_KEY_ASSET_SHA256,
    PRESENTATION_PUBLIC_KEY_FINGERPRINT,
    PRESENTATION_PUBLIC_KEY_ID,
    PRESENTATION_PUBLIC_KEY_PATH,
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
        ]
    )

    assert args.container == "presentation-assets"
    assert args.port == 8081


def test_gateway_serves_only_the_current_incident_pointer_allowlist() -> None:
    _, content = _manifest_and_content()
    state = _asset_bytes("active", "incident-state")
    attestation = _asset_bytes("active", "incident-attestation")
    state_path = "./incidents/inc-123456789abc/state.json"
    attestation_path = "./incidents/inc-123456789abc/attestation.json"
    pointer = IncidentFeedPointer(
        schemaVersion="athena.incidentFeed.v1",
        statePath=state_path,
        stateSha256=sha256_hex(state),
        attestationPath=attestation_path,
        attestationSha256=sha256_hex(attestation),
        pointerAttestationPath="./incidents/inc-123456789abc/pointer-attestation.json",
        keyId=PRESENTATION_PUBLIC_KEY_ID,
        keyFingerprint=PRESENTATION_PUBLIC_KEY_FINGERPRINT,
        publishedAt=datetime(2026, 9, 4, tzinfo=UTC),
    )
    content["incidents/current.json"] = pointer.canonical_bytes()
    content["incidents/inc-123456789abc/pointer-attestation.json"] = _asset_bytes(
        "active",
        "pointer-attestation",
    )
    content[state_path.removeprefix("./")] = state
    content[attestation_path.removeprefix("./")] = attestation
    app = PresentationAssetGatewayApplication(InMemoryPresentationReader(content))

    current = app.handle(method="GET", raw_path="/incidents/current.json")
    current_attestation = app.handle(
        method="GET",
        raw_path="/incidents/inc-123456789abc/pointer-attestation.json",
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
    assert current_attestation.status == 200
    assert incident.status == 200
    assert arbitrary.status == 404
