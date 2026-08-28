from __future__ import annotations

from datetime import UTC, datetime

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobType

import athena_context.azure_adapters as azure_adapters
from athena_context.artifacts import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    ArtifactAlreadyExistsError,
    ArtifactMetadataHashes,
    ArtifactPayloadTooLargeError,
    ArtifactWriteRequest,
    CreateOnlyArtifactWriterPort,
)
from athena_context.azure_adapters import AzureBlobCreateOnlyArtifactWriter
from athena_context.contracts import sha256_hex


class _Credential:
    pass


def _request(payload: bytes = b'{"artifact":"synthetic"}') -> ArtifactWriteRequest:
    return ArtifactWriteRequest(
        blob_name="runs/run-0001/result.json",
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(
            payload_sha256=sha256_hex(payload),
            artifact_sha256="sha256:" + ("1" * 64),
            semantic_sha256="sha256:" + ("2" * 64),
        ),
    )


def test_create_only_writer_uses_managed_identity_single_put_and_if_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uploads: list[dict[str, object]] = []

    class _Blob:
        def upload_blob(self, data: bytes, **kwargs: object) -> dict[str, object]:
            uploads.append({"data": data, **kwargs})
            return {
                "etag": '"synthetic-etag"',
                "version_id": "2026-08-20T07:00:00.0000000Z",
                "last_modified": datetime(2026, 8, 20, 7, tzinfo=UTC),
            }

    class _Container:
        def get_blob_client(self, blob_name: str) -> _Blob:
            assert blob_name == "runs/run-0001/result.json"
            return _Blob()

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
            assert max_single_put_size == MAX_ARTIFACT_PAYLOAD_BYTES

        def get_container_client(self, container_name: str) -> _Container:
            assert container_name == "operational-artifacts"
            return _Container()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "BlobServiceClient", _BlobServiceClient)

    writer = AzureBlobCreateOnlyArtifactWriter(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="operational-artifacts",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )
    request = _request()
    receipt = writer.create(request)

    assert receipt.version_id == "2026-08-20T07:00:00.0000000Z"
    assert receipt.payload_sha256 == request.hashes.payload_sha256
    assert uploads == [
        {
            "data": request.payload,
            "blob_type": BlobType.BLOCKBLOB,
            "length": len(request.payload),
            "metadata": {
                "payload_sha256": request.hashes.payload_sha256,
                "artifact_sha256": request.hashes.artifact_sha256,
                "semantic_sha256": request.hashes.semantic_sha256,
            },
            "overwrite": False,
            "match_condition": MatchConditions.IfMissing,
            "content_settings": uploads[0]["content_settings"],
        }
    ]
    assert uploads[0]["content_settings"].content_type == "application/json"


def test_writer_rejects_oversized_payload_before_blob_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected: list[str] = []

    class _Container:
        def get_blob_client(self, blob_name: str) -> object:
            selected.append(blob_name)
            raise AssertionError("oversized payload reached the Blob client")

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
    writer = AzureBlobCreateOnlyArtifactWriter(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="operational-artifacts",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
        max_payload_bytes=16,
    )

    with pytest.raises(ArtifactPayloadTooLargeError):
        writer.create(_request(b'{"artifact":"too-large"}'))

    assert selected == []


def test_writer_maps_only_blob_already_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = ResourceExistsError("duplicate")
    error.error_code = "BlobAlreadyExists"

    class _Blob:
        def upload_blob(self, _data: bytes, **_kwargs: object) -> dict[str, object]:
            raise error

    class _Container:
        def get_blob_client(self, _blob_name: str) -> _Blob:
            return _Blob()

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
    writer = AzureBlobCreateOnlyArtifactWriter(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="operational-artifacts",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )

    with pytest.raises(ArtifactAlreadyExistsError):
        writer.create(_request())

    unrelated = ResourceExistsError("container is being deleted")
    unrelated.error_code = "ContainerBeingDeleted"
    error.error_code = unrelated.error_code
    with pytest.raises(ResourceExistsError):
        writer.create(_request())


def test_artifact_request_validates_path_content_type_and_payload_hash() -> None:
    payload = b"{}"
    hashes = ArtifactMetadataHashes(payload_sha256=sha256_hex(payload))

    with pytest.raises(ValueError, match="payload_sha256"):
        ArtifactWriteRequest(
            blob_name="runs/run-0001/result.json",
            payload=payload,
            content_type="application/json",
            hashes=ArtifactMetadataHashes(payload_sha256="sha256:" + ("0" * 64)),
        )
    with pytest.raises(ValueError, match="content_type"):
        ArtifactWriteRequest(
            blob_name="runs/run-0001/result.json",
            payload=payload,
            content_type="text/plain",  # type: ignore[arg-type]
            hashes=hashes,
        )
    with pytest.raises(ValueError, match="blob_name"):
        ArtifactWriteRequest(
            blob_name="../result.json",
            payload=payload,
            content_type="application/json",
            hashes=hashes,
        )


def test_artifact_request_enforces_the_port_payload_boundary() -> None:
    maximum_payload = b"x" * MAX_ARTIFACT_PAYLOAD_BYTES

    request = ArtifactWriteRequest(
        blob_name="runs/run-0001/maximum.json",
        payload=maximum_payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(
            payload_sha256=sha256_hex(maximum_payload)
        ),
    )

    assert len(request.payload) == MAX_ARTIFACT_PAYLOAD_BYTES
    with pytest.raises(ArtifactPayloadTooLargeError):
        ArtifactWriteRequest(
            blob_name="runs/run-0001/oversized.json",
            payload=maximum_payload + b"x",
            content_type="application/json",
            hashes=ArtifactMetadataHashes(
                payload_sha256=sha256_hex(maximum_payload + b"x")
            ),
        )


def test_artifact_port_exposes_only_create() -> None:
    methods = {
        name
        for name, value in vars(CreateOnlyArtifactWriterPort).items()
        if not name.startswith("_") and callable(value)
    }

    assert methods == {"create"}


def test_production_credential_excludes_non_managed_identity_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _DefaultAzureCredential:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(
        azure_adapters,
        "DefaultAzureCredential",
        _DefaultAzureCredential,
    )

    azure_adapters._production_credential(
        managed_identity_client_id="11111111-1111-1111-1111-111111111111"
    )

    assert captured["managed_identity_client_id"] == (
        "11111111-1111-1111-1111-111111111111"
    )
    assert captured["exclude_workload_identity_credential"] is True
    assert all(
        captured[name] is True
        for name in (
            "exclude_environment_credential",
            "exclude_shared_token_cache_credential",
            "exclude_visual_studio_code_credential",
            "exclude_cli_credential",
            "exclude_powershell_credential",
            "exclude_developer_cli_credential",
            "exclude_broker_credential",
        )
    )
