from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from athena_context.contracts import (
    PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME,
    ActiveIncidentIndex,
    ActiveIncidentIndexAttestation,
    IncidentFeedAttestation,
    IncidentFeedPointer,
    IncidentOccurrenceReceipt,
    IncidentState,
    PresentationRuntimeManifestV2,
    sha256_hex,
)

MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES = 16 * 1024
MAX_PRESENTATION_PAYLOAD_BYTES = 128 * 1024
MAX_PRESENTATION_ATTESTATION_BYTES = 24 * 1024
MAX_INCIDENT_FEED_POINTER_BYTES = 16 * 1024
MAX_INCIDENT_STATE_BYTES = 64 * 1024


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


def _validate_active_incident_index_assets(
    *,
    active_index: ActiveIncidentIndex,
    active_index_attestation: ActiveIncidentIndexAttestation,
    active_index_asset: PresentationAsset,
    active_index_attestation_asset: PresentationAsset,
    previous_active_index_sha256: str | None,
) -> None:
    index_bytes = active_index.canonical_bytes()
    if (
        active_index_asset.blob_name != "incidents/active.json"
        or active_index_asset.payload != index_bytes
        or active_index_asset.payload_sha256 != sha256_hex(index_bytes)
        or active_index_attestation.index_digest != sha256_hex(index_bytes)
        or active_index_attestation_asset.blob_name
        != active_index.index_attestation_path.removeprefix("./")
        or active_index_attestation_asset.payload
        != active_index_attestation.canonical_bytes()
    ):
        raise ValueError("active incident index assets are invalid")
    if (
        previous_active_index_sha256 is not None
        and not previous_active_index_sha256.startswith("sha256:")
    ):
        raise ValueError("previous active incident index digest is invalid")


@dataclass(frozen=True, slots=True)
class ActiveIncidentIndexPublicationRequest:
    active_index: ActiveIncidentIndex
    active_index_attestation: ActiveIncidentIndexAttestation
    active_index_asset: PresentationAsset
    active_index_attestation_asset: PresentationAsset
    previous_active_index_sha256: str | None

    def __post_init__(self) -> None:
        _validate_active_incident_index_assets(
            active_index=self.active_index,
            active_index_attestation=self.active_index_attestation,
            active_index_asset=self.active_index_asset,
            active_index_attestation_asset=self.active_index_attestation_asset,
            previous_active_index_sha256=self.previous_active_index_sha256,
        )


@dataclass(frozen=True, slots=True)
class IncidentPublicationRequest:
    pointer: IncidentFeedPointer
    pointer_attestation: IncidentFeedAttestation
    pointer_asset: PresentationAsset
    current_pointer_asset: PresentationAsset
    pointer_attestation_asset: PresentationAsset
    state: PresentationAsset
    attestation: PresentationAsset
    active_index: ActiveIncidentIndex
    active_index_attestation: ActiveIncidentIndexAttestation
    active_index_asset: PresentationAsset
    active_index_attestation_asset: PresentationAsset
    previous_active_index_sha256: str | None

    def __post_init__(self) -> None:
        pointer_bytes = self.pointer.canonical_bytes()
        if self.pointer_attestation.pointer_digest != sha256_hex(pointer_bytes):
            raise ValueError("incident pointer attestation does not bind the pointer")
        if (
            self.pointer_asset.blob_name
            != self.pointer.state_path.removesuffix("/state.json").removeprefix("./")
            + "/pointer.json"
            or self.pointer_asset.payload != pointer_bytes
            or self.pointer_asset.payload_sha256 != sha256_hex(pointer_bytes)
        ):
            raise ValueError("incident pointer asset is invalid")
        if (
            self.current_pointer_asset.blob_name
            != f"incidents/{self.pointer.incident_id}/current.json"
            or self.current_pointer_asset.payload != pointer_bytes
            or self.current_pointer_asset.payload_sha256 != sha256_hex(pointer_bytes)
        ):
            raise ValueError("current incident pointer asset is invalid")
        if (
            self.pointer_attestation_asset.blob_name
            != self.pointer.pointer_attestation_path.removeprefix("./")
            or self.pointer_attestation_asset.payload
            != self.pointer_attestation.canonical_bytes()
        ):
            raise ValueError("incident pointer attestation asset is invalid")
        expected = (
            (
                self.pointer.state_path.removeprefix("./"),
                self.pointer.state_sha256,
            ),
            (
                self.pointer.attestation_path.removeprefix("./"),
                self.pointer.attestation_sha256,
            ),
        )
        actual = (
            (self.state.blob_name, self.state.payload_sha256),
            (self.attestation.blob_name, self.attestation.payload_sha256),
        )
        if actual != expected:
            raise ValueError("incident assets do not exactly match their current pointer")
        state = IncidentState.model_validate_json(self.state.payload)
        entry = next(
            (
                item
                for item in self.active_index.incidents
                if item.incident_id == state.incident_id
            ),
            None,
        )
        if state.lifecycle == "active":
            if (
                entry is None
                or entry.scenario != state.scenario
                or entry.workload_role != state.workload_role
                or entry.pointer_path
                != f"./{self.pointer_asset.blob_name}"
                or entry.pointer_sha256
                != self.pointer_asset.payload_sha256
                or entry.detected_at != state.detected_at
                or entry.updated_at != state.updated_at
            ):
                raise ValueError(
                    "active incident index does not match the occurrence"
                )
        elif entry is not None:
            raise ValueError(
                "resolved incident must not remain in the active index"
            )
        _validate_active_incident_index_assets(
            active_index=self.active_index,
            active_index_attestation=self.active_index_attestation,
            active_index_asset=self.active_index_asset,
            active_index_attestation_asset=self.active_index_attestation_asset,
            previous_active_index_sha256=self.previous_active_index_sha256,
        )


@dataclass(frozen=True, slots=True)
class IncidentPublicationReceipt:
    incident_id: str
    pointer_sha256: str
    active_index_sha256: str
    occurrence: IncidentOccurrenceReceipt | None = None

    def __post_init__(self) -> None:
        if self.occurrence is not None and (
            self.occurrence.incident_id != self.incident_id
            or self.occurrence.pointer_reference.content_digest
            != self.pointer_sha256
        ):
            raise ValueError(
                "incident publication receipt occurrence is invalid"
            )


@dataclass(frozen=True, slots=True)
class ActiveIncidentIndexSnapshot:
    index: ActiveIncidentIndex
    payload_sha256: str

    def __post_init__(self) -> None:
        if self.payload_sha256 != sha256_hex(self.index.canonical_bytes()):
            raise ValueError("active incident index snapshot digest is invalid")


@dataclass(frozen=True, slots=True)
class CurrentIncidentStateSnapshot:
    state: IncidentState
    pointer: IncidentFeedPointer
    pointer_sha256: str
    occurrence: IncidentOccurrenceReceipt | None = None

    def __post_init__(self) -> None:
        if (
            self.pointer.incident_id != self.state.incident_id
            or self.pointer.state_sha256 != sha256_hex(self.state.canonical_bytes())
            or self.pointer_sha256 != sha256_hex(self.pointer.canonical_bytes())
            or (
                self.occurrence is not None
                and (
                    self.occurrence.incident_id != self.state.incident_id
                    or self.occurrence.transition_id
                    != self.state.transition_id
                    or self.occurrence.pointer_reference.content_digest
                    != self.pointer_sha256
                )
            )
        ):
            raise ValueError("current incident state snapshot binding is invalid")


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


class IncidentAssetPublisherPort(Protocol):
    def read_active_incident_index(self) -> ActiveIncidentIndexSnapshot | None: ...

    def read_current_incident_state(
        self,
        *,
        incident_id: str,
    ) -> CurrentIncidentStateSnapshot | None: ...

    def publish_incident(
        self,
        request: IncidentPublicationRequest,
    ) -> IncidentPublicationReceipt: ...

    def publish_active_incident_index(
        self,
        request: ActiveIncidentIndexPublicationRequest,
    ) -> ActiveIncidentIndexSnapshot: ...


class PresentationAssetReaderPort(Protocol):
    def read_current(
        self,
        *,
        blob_name: str,
        maximum_bytes: int,
    ) -> PresentationAssetReadResult: ...


__all__ = [
    "MAX_PRESENTATION_ATTESTATION_BYTES",
    "MAX_INCIDENT_FEED_POINTER_BYTES",
    "MAX_INCIDENT_STATE_BYTES",
    "MAX_PRESENTATION_PAYLOAD_BYTES",
    "MAX_PRESENTATION_RUNTIME_MANIFEST_BYTES",
    "ActiveIncidentIndexPublicationRequest",
    "ActiveIncidentIndexSnapshot",
    "CurrentIncidentStateSnapshot",
    "IncidentAssetPublisherPort",
    "IncidentPublicationReceipt",
    "IncidentPublicationRequest",
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
