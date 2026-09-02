from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from athena_context.contracts import (
    PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
    PresentationRuntimeManifestV2,
    sha256_hex,
)

MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES = 16 * 1024
MAX_PRESENTATION_PAYLOAD_BYTES = 128 * 1024
MAX_PRESENTATION_ATTESTATION_BYTES = 24 * 1024


class PresentationAssetError(RuntimeError):
    """Base error for the private presentation asset boundary."""


class PresentationAssetAlreadyExistsError(PresentationAssetError):
    """An immutable run-scoped presentation asset already exists."""


class PresentationAssetUnavailableError(PresentationAssetError):
    """A requested current presentation asset is missing or invalid."""


@dataclass(frozen=True, slots=True)
class PresentationAsset:
    blob_name: str
    payload: bytes
    payload_sha256: str
    maximum_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.blob_name) is not str
            or not self.blob_name
            or self.blob_name.startswith("/")
            or self.blob_name.endswith("/")
            or "\\" in self.blob_name
            or "%" in self.blob_name
            or any(segment in {"", ".", ".."} for segment in self.blob_name.split("/"))
        ):
            raise ValueError("blob_name must be one bounded relative presentation path")
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("payload must be non-empty immutable bytes")
        if (
            type(self.maximum_bytes) is not int
            or self.maximum_bytes < 1
            or len(self.payload) > self.maximum_bytes
        ):
            raise ValueError("presentation asset exceeds its configured byte bound")
        if self.payload_sha256 != sha256_hex(self.payload):
            raise ValueError("presentation asset digest does not match its bytes")


@dataclass(frozen=True, slots=True)
class PresentationPublicationRequest:
    manifest: PresentationRuntimeManifestV2
    assets: tuple[
        PresentationAsset,
        PresentationAsset,
        PresentationAsset,
        PresentationAsset,
        PresentationAsset,
        PresentationAsset,
    ]

    def __post_init__(self) -> None:
        expected: list[tuple[str, str]] = []
        for phase in self.manifest.phases:
            expected.extend(
                (
                    (
                        phase.payload_path.removeprefix("./"),
                        phase.payload_sha256,
                    ),
                    (
                        phase.attestation_path.removeprefix("./"),
                        phase.attestation_sha256,
                    ),
                )
            )
        actual = [(asset.blob_name, asset.payload_sha256) for asset in self.assets]
        if actual != expected:
            raise ValueError(
                "publication assets do not exactly match the runtime manifest"
            )
        manifest_bytes = self.manifest.canonical_bytes()
        if len(manifest_bytes) > MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES:
            raise ValueError("runtime manifest exceeds its byte bound")


@dataclass(frozen=True, slots=True)
class PresentationPublicationReceipt:
    run_id: str
    manifest_blob_name: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        if self.manifest_blob_name != PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME:
            raise ValueError("publication receipt has the wrong manifest blob name")


@dataclass(frozen=True, slots=True)
class PresentationAssetReadResult:
    blob_name: str
    payload: bytes
    payload_sha256: str


class PresentationAssetPublisherPort(Protocol):
    def publish(
        self,
        request: PresentationPublicationRequest,
    ) -> PresentationPublicationReceipt: ...


class PresentationAssetReaderPort(Protocol):
    def read_current(
        self,
        *,
        blob_name: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult: ...


__all__ = [
    "MAX_PRESENTATION_ATTESTATION_BYTES",
    "MAX_PRESENTATION_PAYLOAD_BYTES",
    "MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES",
    "PresentationAsset",
    "PresentationAssetAlreadyExistsError",
    "PresentationAssetError",
    "PresentationAssetPublisherPort",
    "PresentationAssetReadResult",
    "PresentationAssetReaderPort",
    "PresentationAssetUnavailableError",
    "PresentationPublicationReceipt",
    "PresentationPublicationRequest",
]
