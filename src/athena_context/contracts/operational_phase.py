from __future__ import annotations

import re
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.contracts.presentation import (
    ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
    ArgusPresentationPhase,
)

OPERATIONAL_PHASES: tuple[
    Literal["baseline"],
    Literal["faulted"],
    Literal["recovered"],
] = ("baseline", "faulted", "recovered")
OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION = (
    "athena.operationalPhaseDeliveryBundle.v1"
)
OPERATIONAL_PHASE_RECEIPT_SCHEMA_VERSION = "athena.operationalPhaseReceipt.v1"

type OperationalArtifactKind = Literal[
    "evaluationResult",
    "evidenceSnapshot",
    "argusPresentation",
    "presentationAttestation",
    "phaseReceipt",
]

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_ATTEMPT_ID_PATTERN = r"^attempt-[a-f0-9]{12}$"
_SNAPSHOT_ID_PATTERN = r"^snap-[a-f0-9]{12}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_RELATIVE_FILE_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,254}[A-Za-z0-9])?$"
)
_SYNTHETIC_KEY_PATTERN = r"^synthetic-key://[a-z0-9][a-z0-9._/-]{0,199}$"
_ZERO_DIGEST = "sha256:" + "0" * 64


class _StrictOperationalContract(BaseModel):
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


def _validate_relative_delivery_file(value: str) -> str:
    if (
        value != value.strip()
        or "\\" in value
        or not _RELATIVE_FILE_PATTERN.fullmatch(value)
    ):
        raise AthenaValidationError(
            "delivery file must be one bounded portable relative path"
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AthenaValidationError(
            "delivery file must not contain empty or traversing path segments"
        )
    return value


class OperationalPhaseConfiguration(_StrictOperationalContract):
    phase: ArgusPresentationPhase
    wc013_configuration_file: str = Field(
        alias="wc013ConfigurationFile",
        min_length=1,
        max_length=256,
    )
    wc013_configuration_digest: str = Field(
        alias="wc013ConfigurationDigest",
        pattern=_DIGEST_PATTERN,
    )
    fault_receipt_file: str = Field(
        alias="faultReceiptFile",
        min_length=1,
        max_length=256,
    )
    fault_receipt_digest: str = Field(
        alias="faultReceiptDigest",
        pattern=_DIGEST_PATTERN,
    )
    attempt_id: str = Field(alias="attemptId", pattern=_ATTEMPT_ID_PATTERN)
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    idempotency_key: str = Field(
        alias="idempotencyKey",
        pattern=_IDEMPOTENCY_PATTERN,
    )

    @field_validator("wc013_configuration_file", "fault_receipt_file")
    @classmethod
    def validate_delivery_file(cls, value: str) -> str:
        return _validate_relative_delivery_file(value)

    @model_validator(mode="after")
    def require_separate_input_files(self) -> OperationalPhaseConfiguration:
        if self.wc013_configuration_file == self.fault_receipt_file:
            raise AthenaValidationError(
                "WC-013 configuration and fault receipt files must be different"
            )
        return self


class OperationalPhaseConfigurations(_StrictOperationalContract):
    baseline: OperationalPhaseConfiguration
    faulted: OperationalPhaseConfiguration
    recovered: OperationalPhaseConfiguration

    @model_validator(mode="after")
    def require_phase_key_binding(self) -> OperationalPhaseConfigurations:
        for expected, configuration in (
            ("baseline", self.baseline),
            ("faulted", self.faulted),
            ("recovered", self.recovered),
        ):
            if configuration.phase != expected:
                raise AthenaValidationError(
                    "delivery configuration phase does not match its allowlisted key"
                )
        return self

    def select(
        self,
        phase: ArgusPresentationPhase,
    ) -> OperationalPhaseConfiguration:
        return cast(OperationalPhaseConfiguration, getattr(self, phase))


class OperationalPhaseDeliveryBundle(_StrictOperationalContract):
    schema_version: Literal[
        "athena.operationalPhaseDeliveryBundle.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    allowed_phases: tuple[
        Literal["baseline"],
        Literal["faulted"],
        Literal["recovered"],
    ] = Field(alias="allowedPhases")
    synthetic_presentation_key_id: str = Field(
        alias="syntheticPresentationKeyId",
        pattern=_SYNTHETIC_KEY_PATTERN,
    )
    configurations: OperationalPhaseConfigurations
    bundle_digest: str = Field(alias="bundleDigest", pattern=_DIGEST_PATTERN)

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        payload.pop("bundleDigest")
        return payload

    @model_validator(mode="after")
    def validate_bundle(self) -> OperationalPhaseDeliveryBundle:
        if self.allowed_phases != OPERATIONAL_PHASES:
            raise AthenaValidationError(
                "delivery bundle phase allowlist must be baseline, faulted, recovered"
            )
        configurations = tuple(
            self.configurations.select(phase)
            for phase in OPERATIONAL_PHASES
        )
        for label, values in (
            ("attempt IDs", [item.attempt_id for item in configurations]),
            ("snapshot IDs", [item.snapshot_id for item in configurations]),
            (
                "idempotency keys",
                [item.idempotency_key for item in configurations],
            ),
            (
                "WC-013 configuration files",
                [item.wc013_configuration_file for item in configurations],
            ),
            (
                "fault receipt files",
                [item.fault_receipt_file for item in configurations],
            ),
        ):
            if len(values) != len(set(values)):
                raise AthenaValidationError(
                    f"delivery bundle {label} must be unique across phases"
                )
        if self.bundle_digest != compute_artifact_digest(
            self._digest_payload()
        ):
            raise AthenaValidationError(
                "delivery bundle digest does not match its canonical payload"
            )
        return self


class OperationalPhaseSelector(_StrictOperationalContract):
    phase: str = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def require_allowlisted_phase(self) -> OperationalPhaseSelector:
        if self.phase not in OPERATIONAL_PHASES:
            raise AthenaValidationError("phase selector is not allowlisted")
        return self

    def selected_phase(self) -> ArgusPresentationPhase:
        return cast(ArgusPresentationPhase, self.phase)


class OperationalPhaseArtifactReference(_StrictOperationalContract):
    kind: OperationalArtifactKind
    name: str = Field(min_length=1, max_length=256)
    digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_relative_delivery_file(value)


class OperationalPhaseReceipt(_StrictOperationalContract):
    schema_version: Literal["athena.operationalPhaseReceipt.v1"] = Field(
        alias="schemaVersion"
    )
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    phase: ArgusPresentationPhase
    bundle_digest: str = Field(alias="bundleDigest", pattern=_DIGEST_PATTERN)
    configuration_digest: str = Field(
        alias="configurationDigest",
        pattern=_DIGEST_PATTERN,
    )
    fault_receipt_digest: str = Field(
        alias="faultReceiptDigest",
        pattern=_DIGEST_PATTERN,
    )
    attempt_id: str = Field(alias="attemptId", pattern=_ATTEMPT_ID_PATTERN)
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    idempotency_key_digest: str = Field(
        alias="idempotencyKeyDigest",
        pattern=_DIGEST_PATTERN,
    )
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    snapshot_artifact_digest: str = Field(
        alias="snapshotArtifactDigest",
        pattern=_DIGEST_PATTERN,
    )
    snapshot_semantic_digest: str = Field(
        alias="snapshotSemanticDigest",
        pattern=_DIGEST_PATTERN,
    )
    presentation_digest: str = Field(
        alias="presentationDigest",
        pattern=_DIGEST_PATTERN,
    )
    artifacts: tuple[
        OperationalPhaseArtifactReference,
        ...,
    ] = Field(min_length=4, max_length=4)
    receipt_digest: str = Field(alias="receiptDigest", pattern=_DIGEST_PATTERN)

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        payload.pop("receiptDigest")
        return payload

    @model_validator(mode="after")
    def validate_receipt(self) -> OperationalPhaseReceipt:
        expected_names = operational_phase_artifact_names(self.phase)[:4]
        expected_kinds: tuple[OperationalArtifactKind, ...] = (
            "evaluationResult",
            "evidenceSnapshot",
            "argusPresentation",
            "presentationAttestation",
        )
        if tuple(
            (artifact.kind, artifact.name)
            for artifact in self.artifacts
        ) != tuple(zip(expected_kinds, expected_names, strict=True)):
            raise AthenaValidationError(
                "operational receipt artifacts do not match the frozen phase names"
            )
        if self.receipt_digest != compute_artifact_digest(
            self._digest_payload()
        ):
            raise AthenaValidationError(
                "operational receipt digest does not match its canonical payload"
            )
        return self


def operational_phase_artifact_names(
    phase: ArgusPresentationPhase,
) -> tuple[str, str, str, str, str]:
    prefix = f"operational-demo/{phase}"
    return (
        f"{prefix}/demo-evaluation-result.json",
        f"{prefix}/evidence-snapshot.json",
        f"{prefix}/argus-presentation.json",
        f"{prefix}/presentation-attestation.json",
        f"{prefix}/phase-receipt.json",
    )


def build_operational_phase_delivery_bundle(
    *,
    synthetic_presentation_key_id: str,
    configurations: OperationalPhaseConfigurations,
) -> OperationalPhaseDeliveryBundle:
    draft = OperationalPhaseDeliveryBundle.model_construct(
        schema_version=OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION,
        scenario_id=ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
        allowed_phases=OPERATIONAL_PHASES,
        synthetic_presentation_key_id=synthetic_presentation_key_id,
        configurations=configurations,
        bundle_digest=_ZERO_DIGEST,
    )
    return OperationalPhaseDeliveryBundle.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "bundleDigest": compute_artifact_digest(draft._digest_payload()),
        }
    )


def build_operational_phase_receipt(
    *,
    phase: ArgusPresentationPhase,
    bundle_digest: str,
    configuration_digest: str,
    fault_receipt_digest: str,
    attempt_id: str,
    snapshot_id: str,
    idempotency_key_digest: str,
    result_digest: str,
    snapshot_artifact_digest: str,
    snapshot_semantic_digest: str,
    presentation_digest: str,
    artifacts: tuple[OperationalPhaseArtifactReference, ...],
) -> OperationalPhaseReceipt:
    draft = OperationalPhaseReceipt.model_construct(
        schema_version=OPERATIONAL_PHASE_RECEIPT_SCHEMA_VERSION,
        scenario_id=ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
        phase=phase,
        bundle_digest=bundle_digest,
        configuration_digest=configuration_digest,
        fault_receipt_digest=fault_receipt_digest,
        attempt_id=attempt_id,
        snapshot_id=snapshot_id,
        idempotency_key_digest=idempotency_key_digest,
        result_digest=result_digest,
        snapshot_artifact_digest=snapshot_artifact_digest,
        snapshot_semantic_digest=snapshot_semantic_digest,
        presentation_digest=presentation_digest,
        artifacts=artifacts,
        receipt_digest=_ZERO_DIGEST,
    )
    return OperationalPhaseReceipt.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "receiptDigest": compute_artifact_digest(draft._digest_payload()),
        }
    )


__all__ = [
    "OPERATIONAL_PHASES",
    "OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_RECEIPT_SCHEMA_VERSION",
    "OperationalArtifactKind",
    "OperationalPhaseArtifactReference",
    "OperationalPhaseConfiguration",
    "OperationalPhaseConfigurations",
    "OperationalPhaseDeliveryBundle",
    "OperationalPhaseReceipt",
    "OperationalPhaseSelector",
    "build_operational_phase_delivery_bundle",
    "build_operational_phase_receipt",
    "operational_phase_artifact_names",
]
