from __future__ import annotations

from types import SimpleNamespace

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

import athena_context.azure_adapters as azure_adapters
from athena_context.artifacts import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    ArtifactNotFoundError,
    ArtifactReadRequest,
    ArtifactReadTooLargeError,
    ArtifactVerificationError,
    VersionPinnedArtifactReaderPort,
)
from athena_context.azure_adapters import AzureBlobVersionPinnedArtifactReader
from athena_context.contracts import sha256_hex

VERSION_ID = "2026-08-20T23:50:41.2983616Z"


class _Credential:
    pass


def _request(payload: bytes = b'{"artifact":"synthetic"}') -> ArtifactReadRequest:
    return ArtifactReadRequest(
        blob_name="runs/run-0001/result.json",
        version_id=VERSION_ID,
        expected_payload_sha256=sha256_hex(payload),
    )


def _properties(
    *,
    payload_digest: str,
    version_id: object = VERSION_ID,
    content_type: object = "application/json",
    metadata: object | None = None,
) -> object:
    return SimpleNamespace(
        version_id=version_id,
        content_settings=SimpleNamespace(content_type=content_type),
        metadata=(
            {"payload_sha256": payload_digest}
            if metadata is None
            else metadata
        ),
    )


def _reader(
    monkeypatch: pytest.MonkeyPatch,
    downloader: object,
    calls: list[tuple[object, ...]],
) -> AzureBlobVersionPinnedArtifactReader:
    class _Blob:
        def download_blob(self, **kwargs: object) -> object:
            calls.append(("download_blob", kwargs))
            if isinstance(downloader, BaseException):
                raise downloader
            return downloader

    class _Container:
        def get_blob_client(self, blob_name: str, *, version_id: str) -> _Blob:
            calls.append(("get_blob_client", blob_name, version_id))
            return _Blob()

    class _BlobServiceClient:
        def __init__(
            self,
            *,
            account_url: str,
            credential: object,
            max_single_get_size: int,
            max_chunk_get_size: int,
        ) -> None:
            assert account_url == "https://athenareplay.blob.core.windows.net"
            assert isinstance(credential, _Credential)
            assert max_single_get_size == MAX_ARTIFACT_PAYLOAD_BYTES + 1
            assert max_chunk_get_size == MAX_ARTIFACT_PAYLOAD_BYTES + 1

        def get_container_client(self, container_name: str) -> _Container:
            assert container_name == "operational-artifacts"
            return _Container()

    monkeypatch.setattr(
        azure_adapters,
        "_production_credential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(azure_adapters, "BlobServiceClient", _BlobServiceClient)
    return AzureBlobVersionPinnedArtifactReader(
        blob_endpoint="https://athenareplay.blob.core.windows.net",
        container_name="operational-artifacts",
        managed_identity_client_id="11111111-1111-1111-1111-111111111111",
    )


def test_reader_downloads_only_the_exact_version_and_verifies_three_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"artifact":"synthetic"}'
    digest = sha256_hex(payload)
    calls: list[tuple[object, ...]] = []
    downloader = SimpleNamespace(
        size=len(payload),
        properties=_properties(payload_digest=digest),
        readall=lambda: payload,
    )
    reader = _reader(monkeypatch, downloader, calls)

    result = reader.read(_request(payload))

    assert result.payload == payload
    assert result.version_id == VERSION_ID
    assert result.payload_sha256 == digest
    assert result.parsed_json() == {"artifact": "synthetic"}
    assert calls == [
        ("get_blob_client", "runs/run-0001/result.json", VERSION_ID),
        (
            "download_blob",
            {
                "offset": 0,
                "length": MAX_ARTIFACT_PAYLOAD_BYTES + 1,
                "max_concurrency": 1,
            },
        ),
    ]


def test_reader_accepts_exactly_one_mib_of_valid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'"' + (b"x" * (MAX_ARTIFACT_PAYLOAD_BYTES - 2)) + b'"'
    digest = sha256_hex(payload)
    downloader = SimpleNamespace(
        size=len(payload),
        properties=_properties(payload_digest=digest),
        readall=lambda: payload,
    )
    reader = _reader(monkeypatch, downloader, [])

    result = reader.read(_request(payload))

    assert result.size_bytes == MAX_ARTIFACT_PAYLOAD_BYTES


def test_reader_rejects_oversize_before_consuming_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumed = False

    def _readall() -> bytes:
        nonlocal consumed
        consumed = True
        return b"never"

    digest = sha256_hex(b"never")
    downloader = SimpleNamespace(
        size=MAX_ARTIFACT_PAYLOAD_BYTES + 1,
        properties=_properties(payload_digest=digest),
        readall=_readall,
    )
    reader = _reader(monkeypatch, downloader, [])

    with pytest.raises(ArtifactReadTooLargeError):
        reader.read(
            ArtifactReadRequest(
                blob_name="runs/run-0001/result.json",
                version_id=VERSION_ID,
                expected_payload_sha256=digest,
            )
        )

    assert not consumed


@pytest.mark.parametrize(
    ("properties", "match"),
    [
        (
            _properties(payload_digest=sha256_hex(b"{}"), version_id=None),
            "version",
        ),
        (
            _properties(payload_digest=sha256_hex(b"{}"), version_id="other"),
            "version",
        ),
        (
            _properties(payload_digest=sha256_hex(b"{}"), metadata={}),
            "metadata",
        ),
        (
            _properties(payload_digest="sha256:" + ("0" * 64)),
            "metadata",
        ),
        (
            _properties(
                payload_digest=sha256_hex(b"{}"),
                content_type="text/plain",
            ),
            "content type",
        ),
    ],
)
def test_reader_fails_closed_on_response_binding_drift(
    monkeypatch: pytest.MonkeyPatch,
    properties: object,
    match: str,
) -> None:
    payload = b"{}"
    downloader = SimpleNamespace(
        size=len(payload),
        properties=properties,
        readall=lambda: payload,
    )
    reader = _reader(monkeypatch, downloader, [])

    with pytest.raises(ArtifactVerificationError, match=match):
        reader.read(_request(payload))


@pytest.mark.parametrize("size", [None, 0, "2"])
def test_reader_rejects_missing_or_malformed_size(
    monkeypatch: pytest.MonkeyPatch,
    size: object,
) -> None:
    payload = b"{}"
    digest = sha256_hex(payload)
    downloader = SimpleNamespace(
        size=size,
        properties=_properties(payload_digest=digest),
        readall=lambda: payload,
    )
    reader = _reader(monkeypatch, downloader, [])

    with pytest.raises(ArtifactVerificationError, match="content length"):
        reader.read(_request(payload))


def test_reader_rejects_post_read_length_hash_and_json_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"{}"
    digest = sha256_hex(expected)

    length_reader = _reader(
        monkeypatch,
        SimpleNamespace(
            size=len(expected) + 1,
            properties=_properties(payload_digest=digest),
            readall=lambda: expected,
        ),
        [],
    )
    with pytest.raises(ArtifactVerificationError, match="length"):
        length_reader.read(_request(expected))

    hash_reader = _reader(
        monkeypatch,
        SimpleNamespace(
            size=len(expected),
            properties=_properties(payload_digest=digest),
            readall=lambda: b"[]",
        ),
        [],
    )
    with pytest.raises(ArtifactVerificationError, match="SHA-256"):
        hash_reader.read(_request(expected))

    invalid_json = b"no"
    invalid_digest = sha256_hex(invalid_json)
    json_reader = _reader(
        monkeypatch,
        SimpleNamespace(
            size=len(invalid_json),
            properties=_properties(payload_digest=invalid_digest),
            readall=lambda: invalid_json,
        ),
        [],
    )
    with pytest.raises(ArtifactVerificationError, match="UTF-8 JSON"):
        json_reader.read(_request(invalid_json))


@pytest.mark.parametrize("payload", [b"NaN", b"Infinity", b"-Infinity"])
def test_reader_rejects_non_standard_json_constants(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    digest = sha256_hex(payload)
    reader = _reader(
        monkeypatch,
        SimpleNamespace(
            size=len(payload),
            properties=_properties(payload_digest=digest),
            readall=lambda: payload,
        ),
        [],
    )

    with pytest.raises(ArtifactVerificationError, match="UTF-8 JSON"):
        reader.read(_request(payload))


def test_reader_maps_empty_blob_invalid_range_to_verification_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_range = HttpResponseError("requested range is not satisfiable")
    invalid_range.status_code = 416
    invalid_range.error_code = "InvalidRange"
    reader = _reader(monkeypatch, invalid_range, [])

    with pytest.raises(ArtifactVerificationError, match="empty"):
        reader.read(
            ArtifactReadRequest(
                blob_name="runs/run-0001/empty.json",
                version_id=VERSION_ID,
                expected_payload_sha256=sha256_hex(b""),
            )
        )


def test_reader_maps_only_exact_blob_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob_missing = ResourceNotFoundError("missing")
    blob_missing.error_code = "BlobNotFound"

    class _Downloader:
        size = 2
        properties = _properties(payload_digest=sha256_hex(b"{}"))

        def readall(self) -> bytes:
            raise blob_missing

    reader = _reader(monkeypatch, _Downloader(), [])
    with pytest.raises(ArtifactNotFoundError):
        reader.read(_request(b"{}"))

    container_missing = ResourceNotFoundError("container missing")
    container_missing.error_code = "ContainerNotFound"

    class _ContainerDownloader:
        size = 2
        properties = _properties(payload_digest=sha256_hex(b"{}"))

        def readall(self) -> bytes:
            raise container_missing

    reader = _reader(monkeypatch, _ContainerDownloader(), [])
    with pytest.raises(ResourceNotFoundError):
        reader.read(_request(b"{}"))


def test_reader_request_requires_exact_name_version_and_digest() -> None:
    with pytest.raises(ValueError, match="version_id"):
        ArtifactReadRequest(
            blob_name="runs/run-0001/result.json",
            version_id="",
            expected_payload_sha256="sha256:" + ("1" * 64),
        )
    with pytest.raises(ValueError, match="blob_name"):
        ArtifactReadRequest(
            blob_name="../result.json",
            version_id=VERSION_ID,
            expected_payload_sha256="sha256:" + ("1" * 64),
        )
    with pytest.raises(ValueError, match="expected_payload_sha256"):
        ArtifactReadRequest(
            blob_name="runs/run-0001/result.json",
            version_id=VERSION_ID,
            expected_payload_sha256="sha256:invalid",
        )


def test_reader_port_exposes_only_read() -> None:
    methods = {
        name
        for name, value in vars(VersionPinnedArtifactReaderPort).items()
        if not name.startswith("_") and callable(value)
    }

    assert methods == {"read"}
