from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobType

import athena_context.azure_adapters as azure_adapters
from athena_context.azure_adapters import (
    AzureBlobPresentationAssetPublisher,
    AzureBlobPresentationAssetReader,
)
from athena_context.contracts import (
    PRESENTATION_PUBLIC_KEY_ASSET_SHA256,
    PRESENTATION_PUBLIC_KEY_FINGERPRINT,
    PRESENTATION_PUBLIC_KEY_ID,
    PRESENTATION_PUBLIC_KEY_PATH,
    PresentationRuntimeKey,
    PresentationRuntimeManifestV2,
    PresentationRuntimePhaseAsset,
    sha256_hex,
)
from athena_context.presentation_assets import (
    PresentationAsset,
    PresentationPublicationRequest,
)


class _Credential:
    pass


def _publication_request() -> PresentationPublicationRequest:
    run_id = "synthetic-run-store-001"
    phases: list[PresentationRuntimePhaseAsset] = []
    assets: list[PresentationAsset] = []
    for phase in ("baseline", "faulted", "recovered"):
        payload_path = (
            f"./live/runs/{run_id}/{phase}/argus-presentation.json"
        )
        attestation_path = (
            f"./live/runs/{run_id}/{phase}/presentation-attestation.json"
        )
        payload = f'{{"phase":"{phase}","kind":"payload"}}\n'.encode()
        attestation = f'{{"phase":"{phase}","kind":"attestation"}}\n'.encode()
        phases.append(
            PresentationRuntimePhaseAsset(
                phase=phase,
                payloadPath=payload_path,
                payloadSha256=sha256_hex(payload),
                attestationPath=attestation_path,
                attestationSha256=sha256_hex(attestation),
            )
        )
        assets.extend(
            (
                PresentationAsset(
                    blob_name=payload_path.removeprefix("./"),
                    payload=payload,
                    payload_sha256=sha256_hex(payload),
                    maximum_bytes=128 * 1024,
                ),
                PresentationAsset(
                    blob_name=attestation_path.removeprefix("./"),
                    payload=attestation,
                    payload_sha256=sha256_hex(attestation),
                    maximum_bytes=24 * 1024,
                ),
            )
        )
    manifest = PresentationRuntimeManifestV2(
        schemaVersion="athena.presentationWeb.runtime.v2",
        classification="live-workload-evaluation",
        runId=run_id,
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
    return PresentationPublicationRequest(
        manifest=manifest,
        assets=tuple(assets),  # type: ignore[arg-type]
    )


def test_presentation_store_uses_create_only_assets_then_atomic_pointer_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uploads: list[tuple[str, bytes, dict[str, object]]] = []

    class _Blob:
        def __init__(self, name: str) -> None:
            self.name = name

        def upload_blob(self, data: bytes, **kwargs: object) -> dict[str, object]:
            uploads.append((self.name, data, kwargs))
            return {}

    class _Container:
        def get_blob_client(self, blob_name: str) -> _Blob:
            return _Blob(blob_name)

    class _BlobServiceClient:
        def __init__(
            self,
            *,
            account_url: str,
            credential: object,
            max_single_put_size: int,
        ) -> None:
            assert account_url == "https://athenareplay.blob.core.windows.net"
            assert isinstance(credential, _Credential)
            assert max_single_put_size == 1024 * 1024

        def get_container_client(self, container_name: str) -> _Container:
            assert container_name == "presentation-assets"
            return _Container()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "BlobServiceClient", _BlobServiceClient)
    store = AzureBlobPresentationAssetPublisher(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="presentation-assets",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )
    request = _publication_request()

    receipt = store.publish(request)

    assert [name for name, _, _ in uploads[:-1]] == [
        asset.blob_name for asset in request.assets
    ]
    for upload, asset in zip(uploads[:-1], request.assets, strict=True):
        _, data, kwargs = upload
        assert data == asset.payload
        assert kwargs["blob_type"] == BlobType.BLOCKBLOB
        assert kwargs["overwrite"] is False
        assert kwargs["match_condition"] == MatchConditions.IfMissing
        assert kwargs["metadata"] == {"payload_sha256": asset.payload_sha256}
        assert kwargs["content_settings"].content_type == "application/json"
    pointer_name, pointer_bytes, pointer_kwargs = uploads[-1]
    assert pointer_name == "runtime-manifest.json"
    assert pointer_bytes == request.manifest.canonical_bytes()
    assert pointer_kwargs["overwrite"] is True
    assert "match_condition" not in pointer_kwargs
    assert pointer_kwargs["metadata"] == {
        "payload_sha256": sha256_hex(pointer_bytes)
    }
    assert receipt.manifest_sha256 == sha256_hex(pointer_bytes)


def test_presentation_store_retry_accepts_exact_existing_immutable_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _publication_request()
    existing = {asset.blob_name: asset for asset in request.assets}
    pointer_uploads: list[bytes] = []

    class _Downloader:
        def __init__(self, asset: PresentationAsset) -> None:
            self.size = len(asset.payload)
            self.properties = SimpleNamespace(
                content_settings=SimpleNamespace(content_type="application/json"),
                metadata={"payload_sha256": asset.payload_sha256},
            )
            self._payload = asset.payload

        def readall(self) -> bytes:
            return self._payload

    class _Blob:
        def __init__(self, name: str) -> None:
            self.name = name

        def upload_blob(self, data: bytes, **_kwargs: object) -> dict[str, object]:
            if self.name == "runtime-manifest.json":
                pointer_uploads.append(data)
                return {}
            error = ResourceExistsError("exists")
            error.error_code = "BlobAlreadyExists"
            raise error

        def download_blob(self, **kwargs: object) -> _Downloader:
            asset = existing[self.name]
            assert kwargs == {
                "offset": 0,
                "length": asset.maximum_bytes + 1,
                "max_concurrency": 1,
            }
            return _Downloader(asset)

    class _Container:
        def get_blob_client(self, blob_name: str) -> _Blob:
            return _Blob(blob_name)

    class _BlobServiceClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def get_container_client(self, _container_name: str) -> _Container:
            return _Container()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "BlobServiceClient", _BlobServiceClient)
    store = AzureBlobPresentationAssetPublisher(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="presentation-assets",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )

    receipt = store.publish(request)

    assert pointer_uploads == [request.manifest.canonical_bytes()]
    assert receipt.manifest_sha256 == sha256_hex(pointer_uploads[0])


def test_presentation_store_reads_current_json_with_matching_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"schemaVersion":"synthetic"}\n'
    properties = SimpleNamespace(
        content_settings=SimpleNamespace(content_type="application/json"),
        metadata={"payload_sha256": sha256_hex(payload)},
    )

    class _Downloader:
        size = len(payload)

        def __init__(self) -> None:
            self.properties = properties

        def readall(self) -> bytes:
            return payload

    class _Blob:
        def download_blob(self, **kwargs: object) -> _Downloader:
            assert kwargs == {
                "offset": 0,
                "length": 4097,
                "max_concurrency": 1,
            }
            return _Downloader()

    class _Container:
        def get_blob_client(self, blob_name: str) -> _Blob:
            assert blob_name == "runtime-manifest.json"
            return _Blob()

    class _BlobServiceClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def get_container_client(self, container_name: str) -> _Container:
            assert container_name == "presentation-assets"
            return _Container()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "BlobServiceClient", _BlobServiceClient)
    store = AzureBlobPresentationAssetReader(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="presentation-assets",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )

    result = store.read_current(
        blob_name="runtime-manifest.json",
        maximum_bytes=4096,
    )

    assert result.payload == payload
    assert result.payload_sha256 == sha256_hex(payload)
