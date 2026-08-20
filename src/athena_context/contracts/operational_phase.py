from __future__ import annotations

import re
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.contracts.models import UtcDateTime
from athena_context.contracts.presentation import (
    ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
    ArgusPresentationPhase,
    DemoFaultRunReceipt,
)

OPERATIONAL_PHASES: tuple[
    Literal["baseline"],
    Literal["faulted"],
    Literal["recovered"],
] = ("baseline", "faulted", "recovered")
OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION = (
    "athena.operationalPhaseDeliveryBundle.v2"
)
OPERATIONAL_PHASE_INPUTS_SCHEMA_VERSION = "athena.operationalPhaseInputs.v1"
OPERATIONAL_PHASE_COMPLETION_INDEX_SCHEMA_VERSION = (
    "athena.operationalPhaseCompletionIndex.v1"
)

type OperationalArtifactKind = Literal[
    "evaluationResult",
    "evidenceSnapshot",
    "argusPresentation",
    "presentationAttestation",
]
type ReceiptAction = Literal["inject", "status", "reset"]
type ReceiptPowerState = Literal[
    "PowerState/running",
    "PowerState/stopped",
    "PowerState/deallocated",
]

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_ATTEMPT_ID_PATTERN = r"^attempt-[a-f0-9]{12}$"
_SNAPSHOT_ID_PATTERN = r"^snap-[a-f0-9]{12}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_RUN_ID_PATTERN = (
    r"^synthetic-run-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_RELATIVE_FILE_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,510}[A-Za-z0-9])?$"
)
_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$"
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


def _validate_relative_name(value: str) -> str:
    if (
        value != value.strip()
        or "\\" in value
        or not _RELATIVE_FILE_PATTERN.fullmatch(value)
    ):
        raise AthenaValidationError(
            "artifact name must be one bounded portable relative path"
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AthenaValidationError(
            "artifact name must not contain empty or traversing path segments"
        )
    return value


class VersionPinnedBlobReference(_StrictOperationalContract):
    name: str = Field(min_length=1, max_length=512)
    version: str = Field(pattern=_VERSION_PATTERN)
    content_digest: str = Field(alias="contentDigest", pattern=_DIGEST_PATTERN)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_relative_name(value)


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
    attempt_id: str = Field(alias="attemptId", pattern=_ATTEMPT_ID_PATTERN)
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    idempotency_key: str = Field(
        alias="idempotencyKey",
        pattern=_IDEMPOTENCY_PATTERN,
    )

    @field_validator("wc013_configuration_file")
    @classmethod
    def validate_delivery_file(cls, value: str) -> str:
        return _validate_relative_name(value)


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
        "athena.operationalPhaseDeliveryBundle.v2"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
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


class OperationalPhaseInputs(_StrictOperationalContract):
    schema_version: Literal["athena.operationalPhaseInputs.v1"] = Field(
        alias="schemaVersion"
    )
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    bundle_digest: str = Field(alias="bundleDigest", pattern=_DIGEST_PATTERN)
    phase: ArgusPresentationPhase
    receipt: VersionPinnedBlobReference
    previous_phase_index: VersionPinnedBlobReference | None = Field(
        default=None,
        alias="previousPhaseIndex",
    )
    lineage_reference_digest: str | None = Field(
        default=None,
        alias="lineageReferenceDigest",
        pattern=_DIGEST_PATTERN,
    )

    @model_validator(mode="after")
    def validate_available_inputs(self) -> OperationalPhaseInputs:
        expected_receipt_name = (
            f"runs/{self.run_id}/inputs/{self.phase}/fault-receipt.json"
        )
        if self.receipt.name != expected_receipt_name:
            raise AthenaValidationError(
                "receipt reference must use the frozen run-scoped input name"
            )
        if self.phase == "baseline":
            if (
                self.previous_phase_index is not None
                or self.lineage_reference_digest is not None
            ):
                raise AthenaValidationError(
                    "baseline accepts only its version-pinned status receipt"
                )
        elif self.phase == "faulted":
            if (
                self.previous_phase_index is None
                and self.lineage_reference_digest is None
            ) or (
                self.previous_phase_index is not None
                and self.lineage_reference_digest is not None
            ):
                raise AthenaValidationError(
                    "faulted requires either the baseline index or one lineage reference"
                )
            if (
                self.previous_phase_index is not None
                and self.previous_phase_index.name
                != operational_phase_artifact_names(
                    self.run_id,
                    "baseline",
                )[4]
            ):
                raise AthenaValidationError(
                    "faulted previous index must name the baseline completion index"
                )
        elif (
            self.previous_phase_index is None
            or self.lineage_reference_digest is not None
        ):
            raise AthenaValidationError(
                "recovered requires the faulted completion index"
            )
        elif self.previous_phase_index.name != operational_phase_artifact_names(
            self.run_id,
            "faulted",
        )[4]:
            raise AthenaValidationError(
                "recovered previous index must name the faulted completion index"
            )
        return self


class OperationalPhaseArtifactReference(VersionPinnedBlobReference):
    kind: OperationalArtifactKind


class OperationalPhaseCompletionIndex(_StrictOperationalContract):
    schema_version: Literal[
        "athena.operationalPhaseCompletionIndex.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    phase: ArgusPresentationPhase
    bundle_digest: str = Field(alias="bundleDigest", pattern=_DIGEST_PATTERN)
    configuration_digest: str = Field(
        alias="configurationDigest",
        pattern=_DIGEST_PATTERN,
    )
    receipt: VersionPinnedBlobReference
    previous_phase_index: VersionPinnedBlobReference | None = Field(
        default=None,
        alias="previousPhaseIndex",
    )
    previous_phase_index_digest: str | None = Field(
        default=None,
        alias="previousPhaseIndexDigest",
        pattern=_DIGEST_PATTERN,
    )
    lineage_digest: str = Field(alias="lineageDigest", pattern=_DIGEST_PATTERN)
    attempt_id: str = Field(alias="attemptId", pattern=_ATTEMPT_ID_PATTERN)
    snapshot_id: str = Field(alias="snapshotId", pattern=_SNAPSHOT_ID_PATTERN)
    idempotency_key_digest: str = Field(
        alias="idempotencyKeyDigest",
        pattern=_DIGEST_PATTERN,
    )
    receipt_action: ReceiptAction = Field(alias="receiptAction")
    receipt_started_at: UtcDateTime = Field(alias="receiptStartedAt")
    receipt_completed_at: UtcDateTime = Field(alias="receiptCompletedAt")
    receipt_before_power_state: ReceiptPowerState = Field(
        alias="receiptBeforePowerState"
    )
    receipt_after_power_state: ReceiptPowerState = Field(
        alias="receiptAfterPowerState"
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
    index_digest: str = Field(alias="indexDigest", pattern=_DIGEST_PATTERN)

    def _digest_payload(self) -> dict[str, object]:
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        payload.pop("indexDigest")
        return payload

    @model_validator(mode="after")
    def validate_index(self) -> OperationalPhaseCompletionIndex:
        expected_names = operational_phase_artifact_names(
            self.run_id,
            self.phase,
        )[:4]
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
                "completion index artifacts do not match the run-scoped names"
            )
        if self.receipt_completed_at < self.receipt_started_at:
            raise AthenaValidationError(
                "completion index receipt chronology is invalid"
            )
        expected_actions: dict[ArgusPresentationPhase, ReceiptAction] = {
            "baseline": "status",
            "faulted": "inject",
            "recovered": "reset",
        }
        expected_action = expected_actions[self.phase]
        if self.receipt_action != expected_action:
            raise AthenaValidationError(
                "completion index receipt action does not match its phase"
            )
        if self.phase == "baseline":
            if (
                self.previous_phase_index is not None
                or self.previous_phase_index_digest is not None
            ):
                raise AthenaValidationError(
                    "baseline completion index must start the phase chain"
                )
        elif (
            self.previous_phase_index is None
        ) != (self.previous_phase_index_digest is None):
            raise AthenaValidationError(
                "previous phase reference and digest must be supplied together"
            )
        if self.phase == "recovered" and self.previous_phase_index is None:
            raise AthenaValidationError(
                "recovered completion index requires the faulted index"
            )
        if self.index_digest != compute_artifact_digest(
            self._digest_payload()
        ):
            raise AthenaValidationError(
                "completion index digest does not match its canonical payload"
            )
        return self


def operational_phase_artifact_names(
    run_id: str,
    phase: ArgusPresentationPhase,
) -> tuple[str, str, str, str, str]:
    if re.fullmatch(_RUN_ID_PATTERN, run_id) is None:
        raise AthenaValidationError("runId is not a synthetic run identifier")
    prefix = f"runs/{run_id}/{phase}"
    return (
        f"{prefix}/demo-evaluation-result.json",
        f"{prefix}/evidence-snapshot.json",
        f"{prefix}/argus-presentation.json",
        f"{prefix}/presentation-attestation.json",
        f"{prefix}/phase-completion-index.json",
    )


def compute_fault_lineage_digest(receipt: DemoFaultRunReceipt) -> str:
    return compute_artifact_digest(
        {
            "scenarioId": ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
            "faultRunId": receipt.fault_run_id,
            "faultKind": receipt.fault_kind,
            "resourceGroup": receipt.resource_group.casefold(),
            "prefix": receipt.prefix.casefold(),
            "targetVmName": receipt.target_vm_name.casefold(),
            "targetVmResourceId": receipt.target_vm_resource_id.casefold(),
            "eligibleWebVmNames": sorted(
                name.casefold()
                for name in receipt.eligible_web_vm_names
            ),
        }
    )


def build_operational_phase_delivery_bundle(
    *,
    run_id: str,
    synthetic_presentation_key_id: str,
    configurations: OperationalPhaseConfigurations,
) -> OperationalPhaseDeliveryBundle:
    draft = OperationalPhaseDeliveryBundle.model_construct(
        schema_version=OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION,
        scenario_id=ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
        run_id=run_id,
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


def build_operational_phase_completion_index(
    *,
    run_id: str,
    phase: ArgusPresentationPhase,
    bundle_digest: str,
    configuration_digest: str,
    receipt: VersionPinnedBlobReference,
    previous_phase_index: VersionPinnedBlobReference | None,
    previous_phase_index_digest: str | None,
    lineage_digest: str,
    attempt_id: str,
    snapshot_id: str,
    idempotency_key_digest: str,
    receipt_action: ReceiptAction,
    receipt_started_at: UtcDateTime,
    receipt_completed_at: UtcDateTime,
    receipt_before_power_state: ReceiptPowerState,
    receipt_after_power_state: ReceiptPowerState,
    result_digest: str,
    snapshot_artifact_digest: str,
    snapshot_semantic_digest: str,
    presentation_digest: str,
    artifacts: tuple[OperationalPhaseArtifactReference, ...],
) -> OperationalPhaseCompletionIndex:
    draft = OperationalPhaseCompletionIndex.model_construct(
        schema_version=OPERATIONAL_PHASE_COMPLETION_INDEX_SCHEMA_VERSION,
        scenario_id=ATHENA_WEB_NODE_FAULT_SCENARIO_ID,
        run_id=run_id,
        phase=phase,
        bundle_digest=bundle_digest,
        configuration_digest=configuration_digest,
        receipt=receipt,
        previous_phase_index=previous_phase_index,
        previous_phase_index_digest=previous_phase_index_digest,
        lineage_digest=lineage_digest,
        attempt_id=attempt_id,
        snapshot_id=snapshot_id,
        idempotency_key_digest=idempotency_key_digest,
        receipt_action=receipt_action,
        receipt_started_at=receipt_started_at,
        receipt_completed_at=receipt_completed_at,
        receipt_before_power_state=receipt_before_power_state,
        receipt_after_power_state=receipt_after_power_state,
        result_digest=result_digest,
        snapshot_artifact_digest=snapshot_artifact_digest,
        snapshot_semantic_digest=snapshot_semantic_digest,
        presentation_digest=presentation_digest,
        artifacts=artifacts,
        index_digest=_ZERO_DIGEST,
    )
    return OperationalPhaseCompletionIndex.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "indexDigest": compute_artifact_digest(draft._digest_payload()),
        }
    )


__all__ = [
    "OPERATIONAL_PHASES",
    "OPERATIONAL_PHASE_COMPLETION_INDEX_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_DELIVERY_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_INPUTS_SCHEMA_VERSION",
    "OperationalArtifactKind",
    "OperationalPhaseArtifactReference",
    "OperationalPhaseCompletionIndex",
    "OperationalPhaseConfiguration",
    "OperationalPhaseConfigurations",
    "OperationalPhaseDeliveryBundle",
    "OperationalPhaseInputs",
    "OperationalPhaseSelector",
    "ReceiptAction",
    "ReceiptPowerState",
    "VersionPinnedBlobReference",
    "build_operational_phase_completion_index",
    "build_operational_phase_delivery_bundle",
    "compute_fault_lineage_digest",
    "operational_phase_artifact_names",
]
