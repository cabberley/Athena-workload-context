from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    sha256_hex,
)
from athena_context.contracts.operational_phase import (
    OperationalPhaseInputs,
    ReceiptAction,
    VersionPinnedBlobReference,
    operational_phase_artifact_names,
)
from athena_context.contracts.presentation import (
    ArgusPresentationPhase,
    DemoFaultRunReceipt,
)

OPERATIONAL_DEMO_OPERATOR_SCHEMA_VERSION = "athena.operationalDemoOperator.v1"
OPERATIONAL_DEMO_WORKLOAD_ACTION_SCHEMA_VERSION = (
    "athena.operationalDemoWorkloadAction.v1"
)
OPERATIONAL_PHASE_EXECUTION_REQUEST_SCHEMA_VERSION = (
    "athena.operationalPhaseExecutionRequest.v1"
)
OPERATIONAL_PHASE_EXECUTION_SCHEMA_VERSION = (
    "athena.operationalPhaseExecution.v1"
)
OPERATIONAL_PHASE_EXECUTION_STATUS_SCHEMA_VERSION = (
    "athena.operationalPhaseExecutionStatus.v1"
)
OPERATIONAL_PHASE_REFERENCE_HANDOFF_SCHEMA_VERSION = (
    "athena.operationalPhaseReferenceHandoff.v1"
)

type OperationalPhaseExecutionState = Literal[
    "running",
    "succeeded",
    "failed",
    "unknown",
]

_RUN_ID_PATTERN = r"^synthetic-run-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
_GUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_BLOB_CONTAINER_PATTERN = re.compile(
    r"^(?!.*--)[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$"
)
_PORTABLE_RELATIVE_FILE_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,510}[A-Za-z0-9])?$"
)
_EXECUTION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class _StrictOperationalDemoContract(BaseModel):
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


def _validate_fixed_text(
    value: str,
    *,
    label: str,
    maximum_length: int,
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum_length
        or value != value.strip()
        or any(character in value for character in ("\0", "\r", "\n"))
    ):
        raise AthenaValidationError(f"{label} must be one bounded exact string")
    return value


def _validate_portable_relative_file(value: str) -> str:
    if (
        value != value.strip()
        or "\\" in value
        or _PORTABLE_RELATIVE_FILE_PATTERN.fullmatch(value) is None
    ):
        raise AthenaValidationError(
            "file must be one bounded portable relative path"
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AthenaValidationError(
            "file must not contain empty or traversing path segments"
        )
    return value


def _canonical_receipt_bytes(receipt: DemoFaultRunReceipt) -> bytes:
    return (receipt.canonical_json() + "\n").encode("utf-8")


class SubprocessControllerConfiguration(_StrictOperationalDemoContract):
    executable: str = Field(min_length=1, max_length=512)
    arguments: tuple[str, ...] = Field(default=(), max_length=16)
    timeout_seconds: int = Field(alias="timeoutSeconds", ge=1, le=900)
    max_output_bytes: int = Field(alias="maxOutputBytes", ge=1, le=131072)

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        return _validate_fixed_text(
            value,
            label="executable",
            maximum_length=512,
        )

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for argument in value:
            _validate_fixed_text(
                argument,
                label="argument",
                maximum_length=256,
            )
        return value


class PhaseJobControllerConfiguration(SubprocessControllerConfiguration):
    poll_timeout_seconds: int = Field(alias="pollTimeoutSeconds", ge=1, le=3600)
    poll_interval_seconds: int = Field(alias="pollIntervalSeconds", ge=1, le=300)

    @model_validator(mode="after")
    def validate_polling_window(self) -> PhaseJobControllerConfiguration:
        if self.poll_interval_seconds > self.poll_timeout_seconds:
            raise AthenaValidationError(
                "pollIntervalSeconds must not exceed pollTimeoutSeconds"
            )
        return self


class ArtifactReaderConfiguration(_StrictOperationalDemoContract):
    blob_endpoint: str = Field(alias="blobEndpoint", min_length=12, max_length=2048)
    container_name: str = Field(alias="containerName", min_length=3, max_length=63)
    managed_identity_client_id: str = Field(
        alias="managedIdentityClientId",
        pattern=_GUID_PATTERN,
    )

    @field_validator("blob_endpoint")
    @classmethod
    def validate_blob_endpoint(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise AthenaValidationError(
                "blobEndpoint must be an HTTPS origin without credentials"
            )
        return value.rstrip("/")

    @field_validator("container_name")
    @classmethod
    def validate_container_name(cls, value: str) -> str:
        if _BLOB_CONTAINER_PATTERN.fullmatch(value) is None:
            raise AthenaValidationError(
                "containerName must be one bounded lowercase Blob container name"
            )
        return value


class OperationalDemoOperatorConfiguration(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalDemoOperator.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    bundle_file: str = Field(alias="bundleFile", min_length=1, max_length=512)
    presentation_public_key_file: str = Field(
        alias="presentationPublicKeyFile",
        min_length=1,
        max_length=512,
    )
    workload_controller: SubprocessControllerConfiguration = Field(
        alias="workloadController"
    )
    phase_job_controller: PhaseJobControllerConfiguration = Field(
        alias="phaseJobController"
    )
    artifact_reader: ArtifactReaderConfiguration = Field(alias="artifactReader")

    @field_validator("bundle_file", "presentation_public_key_file")
    @classmethod
    def validate_reviewed_files(cls, value: str) -> str:
        return _validate_portable_relative_file(value)


class OperationalDemoWorkloadActionReport(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalDemoWorkloadAction.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    action: ReceiptAction
    receipt: DemoFaultRunReceipt
    receipt_reference: VersionPinnedBlobReference = Field(alias="receiptReference")

    @model_validator(mode="after")
    def validate_action_report(self) -> OperationalDemoWorkloadActionReport:
        if self.receipt.action != self.action:
            raise AthenaValidationError(
                "workload receipt action does not match its controller report"
            )
        phase_by_action: dict[ReceiptAction, ArgusPresentationPhase] = {
            "status": "baseline",
            "inject": "faulted",
            "reset": "recovered",
        }
        phase = phase_by_action[self.action]
        expected_name = f"runs/{self.run_id}/inputs/{phase}/fault-receipt.json"
        if self.receipt_reference.name != expected_name:
            raise AthenaValidationError(
                "workload receipt reference does not use the frozen run-scoped input name"
            )
        if self.receipt_reference.content_digest != sha256_hex(
            _canonical_receipt_bytes(self.receipt)
        ):
            raise AthenaValidationError(
                "workload receipt reference digest does not match the supplied receipt"
            )
        return self


class OperationalPhaseExecutionRequest(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalPhaseExecutionRequest.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    phase: ArgusPresentationPhase
    bundle_file: str = Field(alias="bundleFile", min_length=1, max_length=2048)
    phase_inputs: OperationalPhaseInputs = Field(alias="phaseInputs")

    @field_validator("bundle_file")
    @classmethod
    def validate_bundle_file(cls, value: str) -> str:
        return _validate_fixed_text(
            value,
            label="bundleFile",
            maximum_length=2048,
        )

    @model_validator(mode="after")
    def validate_request_binding(self) -> OperationalPhaseExecutionRequest:
        if (
            self.phase_inputs.run_id != self.run_id
            or self.phase_inputs.phase != self.phase
        ):
            raise AthenaValidationError(
                "phase execution request inputs do not match the selected run and phase"
            )
        return self


class OperationalPhaseExecutionRecord(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalPhaseExecution.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    phase: ArgusPresentationPhase
    execution_id: str = Field(alias="executionId", pattern=_EXECUTION_ID_PATTERN)


class OperationalPhaseExecutionStatus(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalPhaseExecutionStatus.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    phase: ArgusPresentationPhase
    execution_id: str = Field(alias="executionId", pattern=_EXECUTION_ID_PATTERN)
    state: OperationalPhaseExecutionState

    def is_terminal(self) -> bool:
        return self.state != "running"


class OperationalPhaseReferenceHandoff(_StrictOperationalDemoContract):
    schema_version: Literal[
        "athena.operationalPhaseReferenceHandoff.v1"
    ] = Field(alias="schemaVersion")
    scenario_id: Literal["athena-web-node-fault.v1"] = Field(alias="scenarioId")
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    phase: ArgusPresentationPhase
    bundle_digest: str = Field(alias="bundleDigest", pattern=r"^sha256:[a-f0-9]{64}$")
    completion_index: VersionPinnedBlobReference = Field(alias="completionIndex")

    @model_validator(mode="after")
    def validate_handoff(self) -> OperationalPhaseReferenceHandoff:
        if self.completion_index.name != operational_phase_artifact_names(
            self.run_id,
            self.phase,
        )[4]:
            raise AthenaValidationError(
                "completionIndex does not use the frozen run-scoped index name"
            )
        return self


def build_operational_phase_reference_handoff(
    *,
    run_id: str,
    phase: ArgusPresentationPhase,
    bundle_digest: str,
    completion_index: VersionPinnedBlobReference,
) -> OperationalPhaseReferenceHandoff:
    return OperationalPhaseReferenceHandoff(
        schemaVersion="athena.operationalPhaseReferenceHandoff.v1",
        scenarioId="athena-web-node-fault.v1",
        runId=run_id,
        phase=phase,
        bundleDigest=bundle_digest,
        completionIndex=completion_index,
    )


__all__ = [
    "ArtifactReaderConfiguration",
    "OPERATIONAL_DEMO_OPERATOR_SCHEMA_VERSION",
    "OPERATIONAL_DEMO_WORKLOAD_ACTION_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_EXECUTION_REQUEST_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_EXECUTION_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_EXECUTION_STATUS_SCHEMA_VERSION",
    "OPERATIONAL_PHASE_REFERENCE_HANDOFF_SCHEMA_VERSION",
    "OperationalDemoOperatorConfiguration",
    "OperationalDemoWorkloadActionReport",
    "OperationalPhaseExecutionRecord",
    "OperationalPhaseExecutionRequest",
    "OperationalPhaseExecutionState",
    "OperationalPhaseExecutionStatus",
    "OperationalPhaseReferenceHandoff",
    "PhaseJobControllerConfiguration",
    "SubprocessControllerConfiguration",
    "build_operational_phase_reference_handoff",
]
