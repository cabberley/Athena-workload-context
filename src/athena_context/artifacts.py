from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from athena_context.contracts import sha256_hex

MAX_ARTIFACT_PAYLOAD_BYTES = 1024 * 1024
ArtifactContentType = Literal["application/json"]

_BLOB_SEGMENT_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class ArtifactWriteError(RuntimeError):
    """Base error for create-only artifact persistence."""


class ArtifactAlreadyExistsError(ArtifactWriteError):
    """The immutable logical artifact name has already been claimed."""


class ArtifactPayloadTooLargeError(ArtifactWriteError):
    """The artifact exceeds the writer's configured single-upload bound."""


@dataclass(frozen=True, slots=True)
class ArtifactMetadataHashes:
    """Fixed hash metadata persisted with an operational artifact."""

    payload_sha256: str
    artifact_sha256: str | None = None
    semantic_sha256: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("payload_sha256", "artifact_sha256", "semantic_sha256"):
            digest = getattr(self, field_name)
            if digest is not None and (
                type(digest) is not str or _SHA256_PATTERN.fullmatch(digest) is None
            ):
                raise ValueError(f"{field_name} must be a lowercase sha256 digest")

    def as_blob_metadata(self) -> dict[str, str]:
        metadata = {"payload_sha256": self.payload_sha256}
        if self.artifact_sha256 is not None:
            metadata["artifact_sha256"] = self.artifact_sha256
        if self.semantic_sha256 is not None:
            metadata["semantic_sha256"] = self.semantic_sha256
        return metadata


@dataclass(frozen=True, slots=True)
class ArtifactWriteRequest:
    """One bounded immutable JSON artifact and its independently verified hashes."""

    blob_name: str
    payload: bytes
    content_type: ArtifactContentType
    hashes: ArtifactMetadataHashes

    def __post_init__(self) -> None:
        if type(self.blob_name) is not str:
            raise TypeError("blob_name must be an exact string")
        if not 1 <= len(self.blob_name) <= 1024:
            raise ValueError("blob_name must contain between 1 and 1024 characters")
        segments = self.blob_name.split("/")
        if (
            len(segments) > 64
            or any(
                not segment
                or len(segment) > 255
                or _BLOB_SEGMENT_PATTERN.fullmatch(segment) is None
                for segment in segments
            )
        ):
            raise ValueError("blob_name must be a bounded lowercase relative artifact path")
        if type(self.payload) is not bytes:
            raise TypeError("payload must be immutable bytes")
        if not self.payload:
            raise ValueError("payload must not be empty")
        if len(self.payload) > MAX_ARTIFACT_PAYLOAD_BYTES:
            raise ArtifactPayloadTooLargeError(
                f"artifact payload exceeds {MAX_ARTIFACT_PAYLOAD_BYTES} bytes"
            )
        if self.content_type != "application/json":
            raise ValueError("content_type must be application/json")
        if type(self.hashes) is not ArtifactMetadataHashes:
            raise TypeError("hashes must be exact ArtifactMetadataHashes")
        if self.hashes.payload_sha256 != sha256_hex(self.payload):
            raise ValueError("payload_sha256 does not match payload bytes")


@dataclass(frozen=True, slots=True)
class ArtifactWriteReceipt:
    """Version-pinned identity returned only after a create-only upload succeeds."""

    container_name: str
    blob_name: str
    version_id: str
    etag: str
    last_modified: datetime
    size_bytes: int
    payload_sha256: str


class CreateOnlyArtifactWriterPort(Protocol):
    """Capability-minimized artifact persistence: create exactly once or fail."""

    def create(self, request: ArtifactWriteRequest) -> ArtifactWriteReceipt: ...


__all__ = [
    "ArtifactAlreadyExistsError",
    "ArtifactContentType",
    "ArtifactMetadataHashes",
    "ArtifactPayloadTooLargeError",
    "ArtifactWriteError",
    "ArtifactWriteReceipt",
    "ArtifactWriteRequest",
    "CreateOnlyArtifactWriterPort",
    "MAX_ARTIFACT_PAYLOAD_BYTES",
]
