from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import AthenaValidationError, canonicalize_json
from athena_context.contracts.models import UtcDateTime
from athena_context.contracts.presentation import ArgusPresentationPhase

PRESENTATION_RUNTIME_SCHEMA_VERSION: Final[
    Literal["athena.presentationWeb.runtime.v2"]
] = "athena.presentationWeb.runtime.v2"
PRESENTATION_RUNTIME_CLASSIFICATION: Final[
    Literal["live-workload-evaluation"]
] = "live-workload-evaluation"
PRESENTATION_ASSET_CONTAINER_NAME: Final[Literal["presentation-assets"]] = (
    "presentation-assets"
)
PRESENTATION_PUBLIC_KEY_PATH: Final[
    Literal["./trust/live-presentation-public-key.jwk.json"]
] = "./trust/live-presentation-public-key.jwk.json"
PRESENTATION_PUBLIC_KEY_ASSET_SHA256: Final[
    Literal[
        "sha256:3f7fed42e04eb015245fb08dec57e0441ca1b5077a6a9389853f01d339352539"
    ]
] = (
    "sha256:3f7fed42e04eb015245fb08dec57e0441ca1b5077a6a9389853f01d339352539"
)
PRESENTATION_PUBLIC_KEY_ID: Final[
    Literal["synthetic-key://athena-argus-demo/rs256-v1"]
] = "synthetic-key://athena-argus-demo/rs256-v1"
PRESENTATION_PUBLIC_KEY_FINGERPRINT: Final[
    Literal[
        "sha256:b2e63939232aa747228751288082c7310996c4e00e45b4bf167d269a61d1f515"
    ]
] = (
    "sha256:b2e63939232aa747228751288082c7310996c4e00e45b4bf167d269a61d1f515"
)
PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME: Final[
    Literal["runtime-manifest.json"]
] = "runtime-manifest.json"

_RUN_ID_PATTERN = r"^synthetic-run-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
_RESOURCE_GROUP_PATTERN = r"^[A-Za-z0-9_().-]{1,90}$"
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_ASSET_PATH_PATTERN = re.compile(
    r"^\./live/runs/synthetic-run-[a-z0-9-]+/"
    r"(?:baseline|faulted|recovered)/"
    r"(?:argus-presentation|presentation-attestation)\.json$"
)


class _StrictPresentationRuntimeModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
    )

    def canonical_json(self) -> str:
        return canonicalize_json(
            self.model_dump(mode="json", by_alias=True, exclude_none=True)
        )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


class PresentationRuntimeKey(_StrictPresentationRuntimeModel):
    path: Literal["./trust/live-presentation-public-key.jwk.json"]
    asset_sha256: Literal[
        "sha256:3f7fed42e04eb015245fb08dec57e0441ca1b5077a6a9389853f01d339352539"
    ] = Field(alias="assetSha256")
    key_id: Literal["synthetic-key://athena-argus-demo/rs256-v1"] = Field(
        alias="keyId"
    )
    fingerprint: Literal[
        "sha256:b2e63939232aa747228751288082c7310996c4e00e45b4bf167d269a61d1f515"
    ]


class PresentationRuntimePhaseAsset(_StrictPresentationRuntimeModel):
    phase: ArgusPresentationPhase
    payload_path: str = Field(alias="payloadPath", min_length=1, max_length=256)
    payload_sha256: str = Field(alias="payloadSha256", pattern=_DIGEST_PATTERN)
    attestation_path: str = Field(
        alias="attestationPath",
        min_length=1,
        max_length=256,
    )
    attestation_sha256: str = Field(
        alias="attestationSha256",
        pattern=_DIGEST_PATTERN,
    )

    @field_validator("payload_path", "attestation_path")
    @classmethod
    def validate_asset_path(cls, value: str) -> str:
        if (
            _ASSET_PATH_PATTERN.fullmatch(value) is None
            or ".." in value
            or "//" in value
            or "\\" in value
            or "%" in value
        ):
            raise AthenaValidationError(
                "presentation runtime asset path is not one bounded live-run JSON path"
            )
        return value


class PresentationRuntimeManifestV2(_StrictPresentationRuntimeModel):
    schema_version: Literal["athena.presentationWeb.runtime.v2"] = Field(
        alias="schemaVersion"
    )
    classification: Literal["live-workload-evaluation"]
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    target_resource_group: str = Field(
        alias="targetResourceGroup",
        pattern=_RESOURCE_GROUP_PATTERN,
    )
    evaluated_at: UtcDateTime = Field(alias="evaluatedAt")
    published_at: UtcDateTime = Field(alias="publishedAt")
    key: PresentationRuntimeKey
    phases: tuple[
        PresentationRuntimePhaseAsset,
        PresentationRuntimePhaseAsset,
        PresentationRuntimePhaseAsset,
    ]

    @field_validator("target_resource_group")
    @classmethod
    def validate_target_resource_group(cls, value: str) -> str:
        if value.endswith("."):
            raise AthenaValidationError(
                "targetResourceGroup must not end with a period"
            )
        return value

    @model_validator(mode="after")
    def validate_live_asset_set(self) -> PresentationRuntimeManifestV2:
        if self.published_at < self.evaluated_at:
            raise AthenaValidationError(
                "runtime manifest publishedAt must not precede evaluatedAt"
            )
        expected_phases: tuple[ArgusPresentationPhase, ...] = (
            "baseline",
            "faulted",
            "recovered",
        )
        if tuple(item.phase for item in self.phases) != expected_phases:
            raise AthenaValidationError(
                "runtime manifest phases must be baseline, faulted, recovered"
            )
        for item in self.phases:
            prefix = f"./live/runs/{self.run_id}/{item.phase}"
            if item.payload_path != f"{prefix}/argus-presentation.json":
                raise AthenaValidationError(
                    "runtime manifest payload path does not match its run and phase"
                )
            if (
                item.attestation_path
                != f"{prefix}/presentation-attestation.json"
            ):
                raise AthenaValidationError(
                    "runtime manifest attestation path does not match its run and phase"
                )
        paths = [
            path
            for item in self.phases
            for path in (item.payload_path, item.attestation_path)
        ]
        if len(set(paths)) != 6:
            raise AthenaValidationError(
                "runtime manifest live asset paths must be unique"
            )
        return self

    def phase(self, phase: ArgusPresentationPhase) -> PresentationRuntimePhaseAsset:
        return next(item for item in self.phases if item.phase == phase)


def live_presentation_asset_paths(
    run_id: str,
    phase: ArgusPresentationPhase,
) -> tuple[str, str]:
    prefix = f"./live/runs/{run_id}/{phase}"
    return (
        f"{prefix}/argus-presentation.json",
        f"{prefix}/presentation-attestation.json",
    )


__all__ = [
    "PRESENTATION_ASSET_CONTAINER_NAME",
    "PRESENTATION_PUBLIC_KEY_ASSET_SHA256",
    "PRESENTATION_PUBLIC_KEY_FINGERPRINT",
    "PRESENTATION_PUBLIC_KEY_ID",
    "PRESENTATION_PUBLIC_KEY_PATH",
    "PRESENTATION_RUNTIME_CLASSIFICATION",
    "PRESENTATION_RUNTIME_MANIFEST_BLOB_NAME",
    "PRESENTATION_RUNTIME_SCHEMA_VERSION",
    "PresentationRuntimeKey",
    "PresentationRuntimeManifestV2",
    "PresentationRuntimePhaseAsset",
    "live_presentation_asset_paths",
]
