from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ValidationError

from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.artifacts import (
    ArtifactReadRequest,
    ArtifactReadResult,
    VersionPinnedArtifactReaderPort,
)
from athena_context.azure_adapters import AzureBlobVersionPinnedArtifactReader
from athena_context.contracts import (
    ArgusPresentationPayload,
    ArgusPresentationPhase,
    EvidenceSnapshot,
    OperationalDemoOperatorConfiguration,
    OperationalDemoWorkloadActionReport,
    OperationalPhaseCompletionIndex,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseExecutionRecord,
    OperationalPhaseExecutionRequest,
    OperationalPhaseExecutionStatus,
    OperationalPhaseInputs,
    OperationalPhaseReferenceHandoff,
    PresentationAttestation,
    ReceiptAction,
    VersionPinnedBlobReference,
    compute_fault_lineage_digest,
    sha256_hex,
)
from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.live_acceptance import (
    PreparedWc013LiveAcceptance,
    Wc013LiveAcceptanceError,
    Wc013LiveAcceptancePlan,
    prepare_wc013_live_acceptance_plan,
    verify_wc013_live_result,
)
from athena_context.presentation import (
    PresentationSignatureVerifier,
    project_argus_presentation,
    verify_demo_evaluation_result,
    verify_presentation_attestation,
)

_MAX_CONFIG_BYTES = 128 * 1024
_MAX_BUNDLE_BYTES = 256 * 1024
_MAX_PHASE_ARTIFACT_BYTES = 1024 * 1024


class OperationalDemoOperatorError(RuntimeError):
    """Raised when the external operational demonstration fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalDemoPhaseSummary:
    phase: str
    synthetic_snapshot_id: str
    result_digest: str
    presentation_digest: str
    verdict: str
    service_state: str
    completion_index_digest: str


@dataclass(frozen=True, slots=True)
class OperationalDemoOperatorResult:
    run_id: str
    baseline: OperationalDemoPhaseSummary
    faulted: OperationalDemoPhaseSummary
    recovered: OperationalDemoPhaseSummary
    reset_status: str


@dataclass(frozen=True, slots=True)
class OperationalDemoValidation:
    run_id: str
    scenario_id: str
    bundle_digest: str
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class _PreparedPhaseReview:
    configuration_path: Path
    prepared: PreparedWc013LiveAcceptance


@dataclass(frozen=True, slots=True)
class PreparedOperationalDemoOperator:
    configuration: OperationalDemoOperatorConfiguration
    configuration_path: Path
    bundle_path: Path
    bundle: OperationalPhaseDeliveryBundle
    phases: dict[ArgusPresentationPhase, _PreparedPhaseReview]
    presentation_verifier: PresentationSignatureVerifier
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class _VerifiedPhaseArtifacts:
    receipt_report: OperationalDemoWorkloadActionReport
    completion_index: OperationalPhaseCompletionIndex
    completion_index_reference: VersionPinnedBlobReference
    summary: OperationalDemoPhaseSummary


class WorkloadActionPort(Protocol):
    def status(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport: ...

    def inject(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport: ...

    def reset(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport: ...


class PhaseJobPort(Protocol):
    def start_phase(
        self,
        request: OperationalPhaseExecutionRequest,
    ) -> OperationalPhaseExecutionRecord: ...

    def read_status(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseExecutionStatus: ...


class ReferenceHandoffPort(Protocol):
    def read_handoff(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseReferenceHandoff: ...


class _Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: int) -> None: ...


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: int) -> None:
        time.sleep(seconds)


class _RsaPresentationVerifier(PresentationSignatureVerifier):
    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        self._public_key = public_key

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool:
        try:
            self._public_key.verify(
                signature,
                canonical_preimage,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        return True


class _BoundedStreamReader(threading.Thread):
    def __init__(self, stream: IO[bytes] | None, limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self.buffer = bytearray()
        self.overflow = False

    def run(self) -> None:
        if self._stream is None:
            return
        try:
            while True:
                chunk = self._stream.read(4096)
                if not chunk:
                    return
                if not self.overflow:
                    remaining = self._limit - len(self.buffer)
                    if remaining <= 0:
                        self.overflow = True
                    elif len(chunk) > remaining:
                        self.buffer.extend(chunk[:remaining])
                        self.overflow = True
                    else:
                        self.buffer.extend(chunk)
        finally:
            self._stream.close()


class _SubprocessJsonRunner:
    def __init__(
        self,
        *,
        executable: str,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> None:
        self._executable = executable
        self._arguments = arguments
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def run_json_command[Model: BaseModel](
        self,
        *,
        verb: str,
        arguments: tuple[str, ...],
        response_model: type[Model],
        failure_message: str,
    ) -> Model:
        content = self._run(
            verb=verb,
            arguments=arguments,
            failure_message=failure_message,
        )
        try:
            return response_model.model_validate_json(content)
        except (ValidationError, ValueError, TypeError) as exc:
            raise OperationalDemoOperatorError(failure_message) from exc

    def _run(
        self,
        *,
        verb: str,
        arguments: tuple[str, ...],
        failure_message: str,
    ) -> bytes:
        argv = [self._executable, *self._arguments, verb, *arguments]
        try:
            process = subprocess.Popen(  # noqa: S603 - reviewed controller boundary.
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        except OSError as exc:
            raise OperationalDemoOperatorError(failure_message) from exc
        stdout_reader = _BoundedStreamReader(
            process.stdout,
            self._max_output_bytes,
        )
        stderr_reader = _BoundedStreamReader(
            process.stderr,
            self._max_output_bytes,
        )
        stdout_reader.start()
        stderr_reader.start()
        try:
            process.wait(timeout=self._timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            stdout_reader.join()
            stderr_reader.join()
            raise OperationalDemoOperatorError(failure_message) from exc
        stdout_reader.join()
        stderr_reader.join()
        if (
            stdout_reader.overflow
            or stderr_reader.overflow
            or process.returncode != 0
            or not stdout_reader.buffer
        ):
            raise OperationalDemoOperatorError(failure_message)
        return bytes(stdout_reader.buffer)


class SubprocessWorkloadController(WorkloadActionPort):
    def __init__(
        self,
        *,
        executable: str,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> None:
        self._runner = _SubprocessJsonRunner(
            executable=executable,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def _run_action(
        self,
        *,
        action: ReceiptAction,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        return self._runner.run_json_command(
            verb=action,
            arguments=(
                "--run-id",
                run_id,
                "--scenario-id",
                scenario_id,
            ),
            response_model=OperationalDemoWorkloadActionReport,
            failure_message=f"{action} action failed closed",
        )

    def status(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        return self._run_action(
            action="status",
            run_id=run_id,
            scenario_id=scenario_id,
        )

    def inject(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        return self._run_action(
            action="inject",
            run_id=run_id,
            scenario_id=scenario_id,
        )

    def reset(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        return self._run_action(
            action="reset",
            run_id=run_id,
            scenario_id=scenario_id,
        )


class SubprocessPhaseJobController(PhaseJobPort, ReferenceHandoffPort):
    def __init__(
        self,
        *,
        executable: str,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> None:
        self._runner = _SubprocessJsonRunner(
            executable=executable,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def start_phase(
        self,
        request: OperationalPhaseExecutionRequest,
    ) -> OperationalPhaseExecutionRecord:
        return self._runner.run_json_command(
            verb="start",
            arguments=("--request-json", request.canonical_json()),
            response_model=OperationalPhaseExecutionRecord,
            failure_message=f"{request.phase} phase start failed closed",
        )

    def read_status(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseExecutionStatus:
        return self._runner.run_json_command(
            verb="status",
            arguments=(
                "--execution-id",
                execution.execution_id,
                "--run-id",
                execution.run_id,
                "--phase",
                execution.phase,
            ),
            response_model=OperationalPhaseExecutionStatus,
            failure_message=f"{execution.phase} phase status failed closed",
        )

    def read_handoff(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseReferenceHandoff:
        return self._runner.run_json_command(
            verb="handoff",
            arguments=(
                "--execution-id",
                execution.execution_id,
                "--run-id",
                execution.run_id,
                "--phase",
                execution.phase,
            ),
            response_model=OperationalPhaseReferenceHandoff,
            failure_message=f"{execution.phase} phase handoff failed closed",
        )


def _read_bounded(path: Path, *, maximum_bytes: int, message: str) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise OperationalDemoOperatorError(message) from exc
    if not content or len(content) > maximum_bytes:
        raise OperationalDemoOperatorError(message)
    return content


def _parse_model[Model: BaseModel](
    content: bytes,
    model: type[Model],
    *,
    message: str,
) -> Model:
    try:
        return model.model_validate_json(content)
    except (ValidationError, ValueError, TypeError) as exc:
        raise OperationalDemoOperatorError(message) from exc


def _parse_file[Model: BaseModel](
    path: Path,
    model: type[Model],
    *,
    maximum_bytes: int,
    message: str,
) -> Model:
    return _parse_model(
        _read_bounded(path, maximum_bytes=maximum_bytes, message=message),
        model,
        message=message,
    )


def _resolve_reviewed_file(root: Path, relative_file: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = (resolved_root / relative_file).resolve(strict=True)
    except OSError as exc:
        raise OperationalDemoOperatorError(
            "reviewed operator file is unavailable"
        ) from exc
    if not resolved.is_file() or not resolved.is_relative_to(resolved_root):
        raise OperationalDemoOperatorError(
            "reviewed operator file escaped its configuration boundary"
        )
    return resolved


def _load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    content = _read_bounded(
        path,
        maximum_bytes=64 * 1024,
        message="presentation verification key is unavailable",
    )
    try:
        public_key = serialization.load_pem_public_key(content)
    except (TypeError, ValueError) as exc:
        raise OperationalDemoOperatorError(
            "presentation verification key is invalid"
        ) from exc
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise OperationalDemoOperatorError(
            "presentation verification key is invalid"
        )
    return public_key


def _identity_snapshot_verifier(
    snapshot: EvidenceSnapshot,
    as_of: datetime,
) -> EvidenceSnapshot:
    del as_of
    return snapshot


def _identity_result_verifier(result: DemoEvaluationResult) -> DemoEvaluationResult:
    return result


def _confirmation_phrase(run_id: str, bundle_digest: str) -> str:
    confirmation_digest = sha256_hex(
        canonicalize_json(
            {
                "scope": "operational-demo-operator",
                "runId": run_id,
                "bundleDigest": bundle_digest,
            }
        ).encode("utf-8")
    )
    return f"ATHENA-OPERATIONAL-DEMO {run_id} {confirmation_digest}"


def prepare_operational_demo_operator(
    config_path: Path,
) -> PreparedOperationalDemoOperator:
    configuration = _parse_file(
        config_path,
        OperationalDemoOperatorConfiguration,
        maximum_bytes=_MAX_CONFIG_BYTES,
        message="operator configuration failed closed validation",
    )
    config_root = config_path.parent
    bundle_path = _resolve_reviewed_file(
        config_root,
        configuration.bundle_file,
    )
    bundle = _parse_file(
        bundle_path,
        OperationalPhaseDeliveryBundle,
        maximum_bytes=_MAX_BUNDLE_BYTES,
        message="reviewed operational phase bundle failed closed validation",
    )
    if (
        bundle.run_id != configuration.run_id
        or bundle.scenario_id != configuration.scenario_id
    ):
        raise OperationalDemoOperatorError(
            "operator configuration does not match the reviewed run and scenario"
        )

    phases: dict[ArgusPresentationPhase, _PreparedPhaseReview] = {}
    for phase in ("baseline", "faulted", "recovered"):
        selected_phase = cast(ArgusPresentationPhase, phase)
        configuration_entry = bundle.configurations.select(selected_phase)
        configuration_path = _resolve_reviewed_file(
            bundle_path.parent,
            configuration_entry.wc013_configuration_file,
        )
        plan = _parse_file(
            configuration_path,
            Wc013LiveAcceptancePlan,
            maximum_bytes=_MAX_BUNDLE_BYTES,
            message="reviewed phase configuration failed closed validation",
        )
        if (
            compute_artifact_digest(
                plan.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            )
            != configuration_entry.wc013_configuration_digest
            or
            plan.evaluation_command.attempt_id != configuration_entry.attempt_id
            or plan.evaluation_command.snapshot_id
            != configuration_entry.snapshot_id
            or plan.idempotency_key != configuration_entry.idempotency_key
        ):
            raise OperationalDemoOperatorError(
                "reviewed phase configuration does not match the delivery bundle"
            )
        try:
            prepared = prepare_wc013_live_acceptance_plan(
                plan,
                plan_path=configuration_path,
            )
        except Wc013LiveAcceptanceError as exc:
            raise OperationalDemoOperatorError(
                "reviewed phase configuration failed closed validation"
            ) from exc
        phases[selected_phase] = _PreparedPhaseReview(
            configuration_path=configuration_path,
            prepared=prepared,
        )

    public_key_path = _resolve_reviewed_file(
        config_root,
        configuration.presentation_public_key_file,
    )
    verifier = _RsaPresentationVerifier(_load_rsa_public_key(public_key_path))
    return PreparedOperationalDemoOperator(
        configuration=configuration,
        configuration_path=config_path,
        bundle_path=bundle_path,
        bundle=bundle,
        phases=phases,
        presentation_verifier=verifier,
        confirmation_phrase=_confirmation_phrase(
            configuration.run_id,
            bundle.bundle_digest,
        ),
    )


def build_operational_demo_validation(
    config_path: Path,
) -> OperationalDemoValidation:
    prepared = prepare_operational_demo_operator(config_path)
    return OperationalDemoValidation(
        run_id=prepared.configuration.run_id,
        scenario_id=prepared.configuration.scenario_id,
        bundle_digest=prepared.bundle.bundle_digest,
        confirmation_phrase=prepared.confirmation_phrase,
    )


def render_operational_demo_validation(
    validation: OperationalDemoValidation,
) -> str:
    return (
        "operational demo operator plan valid\n"
        f"run: {validation.run_id}\n"
        f"scenario: {validation.scenario_id}\n"
        f"bundle digest: {validation.bundle_digest}\n"
        "phases: baseline -> faulted -> recovered\n"
        f"confirmation phrase: {validation.confirmation_phrase}\n"
    )


def render_operational_demo_result(
    result: OperationalDemoOperatorResult,
) -> str:
    def _phase_lines(summary: OperationalDemoPhaseSummary) -> str:
        return (
            f"{summary.phase}: snapshot {summary.synthetic_snapshot_id} | "
            f"verdict {summary.verdict} | "
            f"state {summary.service_state} | "
            f"result {summary.result_digest} | "
            f"presentation {summary.presentation_digest} | "
            f"index {summary.completion_index_digest}"
        )

    return (
        "operational demo operator passed\n"
        f"run: {result.run_id}\n"
        f"{_phase_lines(result.baseline)}\n"
        f"{_phase_lines(result.faulted)}\n"
        f"reset: {result.reset_status}\n"
        f"{_phase_lines(result.recovered)}\n"
    )


def _invoke_workload_action(
    port: WorkloadActionPort,
    *,
    action: ReceiptAction,
    run_id: str,
    scenario_id: str,
) -> OperationalDemoWorkloadActionReport:
    try:
        if action == "status":
            report = port.status(run_id=run_id, scenario_id=scenario_id)
        elif action == "inject":
            report = port.inject(run_id=run_id, scenario_id=scenario_id)
        else:
            report = port.reset(run_id=run_id, scenario_id=scenario_id)
    except OperationalDemoOperatorError:
        raise
    except Exception as exc:  # noqa: BLE001 - injected port boundary.
        raise OperationalDemoOperatorError(f"{action} action failed closed") from exc
    if (
        report.run_id != run_id
        or report.scenario_id != scenario_id
        or report.action != action
    ):
        raise OperationalDemoOperatorError(f"{action} action failed closed")
    return report


def _validate_receipt_transition(
    *,
    previous: OperationalDemoWorkloadActionReport | None,
    current: OperationalDemoWorkloadActionReport,
    expected_action: ReceiptAction,
    allow_missing_state_continuity: bool = False,
) -> None:
    receipt = current.receipt
    if receipt.action != expected_action:
        raise OperationalDemoOperatorError(f"{expected_action} action failed closed")
    if expected_action == "status":
        valid = (
            receipt.before_power_state == "PowerState/running"
            and receipt.after_power_state == "PowerState/running"
        )
    elif expected_action == "inject":
        valid = (
            receipt.before_power_state == "PowerState/running"
            and receipt.after_power_state
            in {"PowerState/stopped", "PowerState/deallocated"}
        )
    else:
        valid = (
            receipt.before_power_state
            in {"PowerState/stopped", "PowerState/deallocated"}
            and receipt.after_power_state == "PowerState/running"
        )
    if not valid:
        raise OperationalDemoOperatorError(f"{expected_action} action failed closed")
    if previous is None:
        return
    previous_receipt = previous.receipt
    if compute_fault_lineage_digest(previous_receipt) != compute_fault_lineage_digest(
        receipt
    ) or receipt.started_at < previous_receipt.completed_at:
        raise OperationalDemoOperatorError(f"{expected_action} action failed closed")
    if (
        not allow_missing_state_continuity
        and receipt.before_power_state != previous_receipt.after_power_state
    ):
        raise OperationalDemoOperatorError(f"{expected_action} action failed closed")


def _build_phase_inputs(
    *,
    prepared: PreparedOperationalDemoOperator,
    phase: ArgusPresentationPhase,
    receipt_reference: VersionPinnedBlobReference,
    previous_phase_index: VersionPinnedBlobReference | None,
) -> OperationalPhaseInputs:
    return OperationalPhaseInputs(
        schemaVersion="athena.operationalPhaseInputs.v1",
        runId=prepared.configuration.run_id,
        bundleDigest=prepared.bundle.bundle_digest,
        phase=phase,
        receipt=receipt_reference,
        previousPhaseIndex=previous_phase_index,
    )


def _start_phase_job(
    *,
    prepared: PreparedOperationalDemoOperator,
    phase: ArgusPresentationPhase,
    phase_inputs: OperationalPhaseInputs,
    phase_job_port: PhaseJobPort,
) -> OperationalPhaseExecutionRecord:
    request = OperationalPhaseExecutionRequest(
        schemaVersion="athena.operationalPhaseExecutionRequest.v1",
        scenarioId=prepared.configuration.scenario_id,
        runId=prepared.configuration.run_id,
        phase=phase,
        bundleFile=str(prepared.bundle_path),
        phaseInputs=phase_inputs,
    )
    try:
        execution = phase_job_port.start_phase(request)
    except OperationalDemoOperatorError:
        raise
    except Exception as exc:  # noqa: BLE001 - injected port boundary.
        raise OperationalDemoOperatorError(f"{phase} phase start failed closed") from exc
    if (
        execution.run_id != request.run_id
        or execution.phase != phase
        or execution.scenario_id != prepared.configuration.scenario_id
    ):
        raise OperationalDemoOperatorError(f"{phase} phase start failed closed")
    return execution


def _wait_for_phase_success(
    *,
    prepared: PreparedOperationalDemoOperator,
    execution: OperationalPhaseExecutionRecord,
    phase_job_port: PhaseJobPort,
    clock: _Clock,
) -> None:
    poll_timeout = prepared.configuration.phase_job_controller.poll_timeout_seconds
    deadline = clock.monotonic() + poll_timeout
    while True:
        try:
            status = phase_job_port.read_status(execution)
        except OperationalDemoOperatorError:
            raise
        except Exception as exc:  # noqa: BLE001 - injected port boundary.
            raise OperationalDemoOperatorError(
                f"{execution.phase} phase status failed closed"
            ) from exc
        if (
            status.run_id != execution.run_id
            or status.phase != execution.phase
            or status.execution_id != execution.execution_id
            or status.scenario_id != execution.scenario_id
        ):
            raise OperationalDemoOperatorError(
                f"{execution.phase} phase status failed closed"
            )
        if status.state == "succeeded":
            return
        if status.state == "failed":
            raise OperationalDemoOperatorError(
                f"{execution.phase} phase failed closed"
            )
        if status.state == "unknown":
            raise OperationalDemoOperatorError(
                f"{execution.phase} phase reached an unknown terminal state"
            )
        if clock.monotonic() >= deadline:
            raise OperationalDemoOperatorError(
                f"{execution.phase} phase timed out"
            )
        clock.sleep(
            prepared.configuration.phase_job_controller.poll_interval_seconds
        )


def _read_phase_handoff(
    *,
    prepared: PreparedOperationalDemoOperator,
    execution: OperationalPhaseExecutionRecord,
    handoff_port: ReferenceHandoffPort,
) -> OperationalPhaseReferenceHandoff:
    try:
        handoff = handoff_port.read_handoff(execution)
    except OperationalDemoOperatorError:
        raise
    except Exception as exc:  # noqa: BLE001 - injected port boundary.
        raise OperationalDemoOperatorError(
            f"{execution.phase} phase handoff failed closed"
        ) from exc
    if (
        handoff.run_id != execution.run_id
        or handoff.phase != execution.phase
        or handoff.scenario_id != prepared.configuration.scenario_id
        or handoff.bundle_digest != prepared.bundle.bundle_digest
    ):
        raise OperationalDemoOperatorError(
            f"{execution.phase} phase handoff failed closed"
        )
    return handoff


def _read_exact_artifact(
    reader: VersionPinnedArtifactReaderPort,
    reference: VersionPinnedBlobReference,
    *,
    failure_message: str,
) -> ArtifactReadResult:
    try:
        result = reader.read(
            ArtifactReadRequest(
                blob_name=reference.name,
                version_id=reference.version,
                expected_payload_sha256=reference.content_digest,
            )
        )
    except Exception as exc:  # noqa: BLE001 - injected port boundary.
        raise OperationalDemoOperatorError(failure_message) from exc
    if (
        result.blob_name != reference.name
        or result.version_id != reference.version
        or result.payload_sha256 != reference.content_digest
        or not result.payload
        or len(result.payload) > _MAX_PHASE_ARTIFACT_BYTES
    ):
        raise OperationalDemoOperatorError(failure_message)
    return result


def _snapshot_json(snapshot: EvidenceSnapshot) -> str:
    return canonicalize_json(
        snapshot.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )


def _verify_phase_artifacts(
    *,
    prepared: PreparedOperationalDemoOperator,
    phase: ArgusPresentationPhase,
    receipt_report: OperationalDemoWorkloadActionReport,
    previous: _VerifiedPhaseArtifacts | None,
    handoff: OperationalPhaseReferenceHandoff,
    artifact_reader: VersionPinnedArtifactReaderPort,
) -> _VerifiedPhaseArtifacts:
    phase_review = prepared.phases[phase]
    selected_configuration = prepared.bundle.configurations.select(phase)
    index_result = _read_exact_artifact(
        artifact_reader,
        handoff.completion_index,
        failure_message=f"{phase} completion index failed closed verification",
    )
    completion_index = _parse_model(
        index_result.payload,
        OperationalPhaseCompletionIndex,
        message=f"{phase} completion index failed closed verification",
    )
    expected_lineage = compute_fault_lineage_digest(receipt_report.receipt)
    if (
        completion_index.run_id != prepared.configuration.run_id
        or completion_index.phase != phase
        or completion_index.bundle_digest != prepared.bundle.bundle_digest
        or completion_index.configuration_digest
        != selected_configuration.wc013_configuration_digest
        or completion_index.receipt != receipt_report.receipt_reference
        or completion_index.lineage_digest != expected_lineage
        or completion_index.attempt_id != selected_configuration.attempt_id
        or completion_index.snapshot_id != selected_configuration.snapshot_id
        or completion_index.idempotency_key_digest
        != sha256_hex(selected_configuration.idempotency_key)
        or completion_index.receipt_action != receipt_report.receipt.action
        or completion_index.receipt_started_at != receipt_report.receipt.started_at
        or completion_index.receipt_completed_at != receipt_report.receipt.completed_at
        or completion_index.receipt_before_power_state
        != receipt_report.receipt.before_power_state
        or completion_index.receipt_after_power_state
        != receipt_report.receipt.after_power_state
    ):
        raise OperationalDemoOperatorError(
            f"{phase} completion index failed closed verification"
        )
    if previous is None:
        if completion_index.previous_phase_index is not None:
            raise OperationalDemoOperatorError(
                f"{phase} completion index failed closed verification"
            )
    elif (
        completion_index.previous_phase_index
        != previous.completion_index_reference
        or completion_index.previous_phase_index_digest
        != previous.completion_index.index_digest
        or previous.completion_index.lineage_digest != expected_lineage
        or previous.completion_index.receipt_completed_at
        > receipt_report.receipt.started_at
        or previous.completion_index.receipt_after_power_state
        != receipt_report.receipt.before_power_state
    ):
        raise OperationalDemoOperatorError(
            f"{phase} completion index failed closed verification"
        )

    artifact_results = tuple(
        _read_exact_artifact(
            artifact_reader,
            reference,
            failure_message=f"{phase} phase artifact verification failed closed",
        )
        for reference in completion_index.artifacts
    )
    result = _parse_model(
        artifact_results[0].payload,
        DemoEvaluationResult,
        message=f"{phase} phase artifact verification failed closed",
    )
    snapshot = _parse_model(
        artifact_results[1].payload,
        EvidenceSnapshot,
        message=f"{phase} phase artifact verification failed closed",
    )
    presentation = _parse_model(
        artifact_results[2].payload,
        ArgusPresentationPayload,
        message=f"{phase} phase artifact verification failed closed",
    )
    attestation = _parse_model(
        artifact_results[3].payload,
        PresentationAttestation,
        message=f"{phase} phase artifact verification failed closed",
    )
    if (
        result.result_digest != completion_index.result_digest
        or result.snapshot.compatibility.artifact_digest
        != completion_index.snapshot_artifact_digest
        or result.snapshot.compatibility.semantic_digest
        != completion_index.snapshot_semantic_digest
        or presentation.athena.result_digest != completion_index.presentation_digest
        or _snapshot_json(snapshot) != _snapshot_json(result.snapshot)
    ):
        raise OperationalDemoOperatorError(
            f"{phase} phase artifact verification failed closed"
        )
    try:
        verify_wc013_live_result(
            phase_review.prepared,
            result,
        )
        verified = verify_demo_evaluation_result(
            result,
            result_verifier=_identity_result_verifier,
            snapshot_verifier=_identity_snapshot_verifier,
        )
        expected_presentation = project_argus_presentation(
            verified,
            receipt=receipt_report.receipt,
            phase=phase,
            synthetic_key_id=prepared.bundle.synthetic_presentation_key_id,
        )
    except (
        AthenaValidationError,
        ValidationError,
        ValueError,
        TypeError,
        Wc013LiveAcceptanceError,
    ) as exc:
        raise OperationalDemoOperatorError(
            f"{phase} phase integrity verification failed closed"
        ) from exc
    if (
        expected_presentation.canonical_json() != presentation.canonical_json()
        or not verify_presentation_attestation(
            presentation,
            attestation,
            verifier=prepared.presentation_verifier,
        )
    ):
        raise OperationalDemoOperatorError(
            f"{phase} phase integrity verification failed closed"
        )
    return _VerifiedPhaseArtifacts(
        receipt_report=receipt_report,
        completion_index=completion_index,
        completion_index_reference=handoff.completion_index,
        summary=OperationalDemoPhaseSummary(
            phase=phase,
            synthetic_snapshot_id=presentation.athena.snapshot_id,
            result_digest=result.result_digest,
            presentation_digest=presentation.athena.result_digest,
            verdict=presentation.findings[0].verdict,
            service_state=presentation.runtime_state.web_tier.service_state,
            completion_index_digest=completion_index.index_digest,
        ),
    )


def _run_verified_phase(
    *,
    prepared: PreparedOperationalDemoOperator,
    phase: ArgusPresentationPhase,
    receipt_report: OperationalDemoWorkloadActionReport,
    previous: _VerifiedPhaseArtifacts | None,
    phase_job_port: PhaseJobPort,
    handoff_port: ReferenceHandoffPort,
    artifact_reader: VersionPinnedArtifactReaderPort,
    clock: _Clock,
) -> _VerifiedPhaseArtifacts:
    phase_inputs = _build_phase_inputs(
        prepared=prepared,
        phase=phase,
        receipt_reference=receipt_report.receipt_reference,
        previous_phase_index=(
            previous.completion_index_reference
            if previous is not None
            else None
        ),
    )
    execution = _start_phase_job(
        prepared=prepared,
        phase=phase,
        phase_inputs=phase_inputs,
        phase_job_port=phase_job_port,
    )
    _wait_for_phase_success(
        prepared=prepared,
        execution=execution,
        phase_job_port=phase_job_port,
        clock=clock,
    )
    handoff = _read_phase_handoff(
        prepared=prepared,
        execution=execution,
        handoff_port=handoff_port,
    )
    return _verify_phase_artifacts(
        prepared=prepared,
        phase=phase,
        receipt_report=receipt_report,
        previous=previous,
        handoff=handoff,
        artifact_reader=artifact_reader,
    )


def run_operational_demo_operator(
    config_path: Path,
    *,
    confirmation_phrase: str | None,
    workload_port: WorkloadActionPort | None = None,
    phase_job_port: PhaseJobPort | None = None,
    handoff_port: ReferenceHandoffPort | None = None,
    artifact_reader: VersionPinnedArtifactReaderPort | None = None,
    clock: _Clock | None = None,
) -> OperationalDemoOperatorResult:
    prepared = prepare_operational_demo_operator(config_path)
    if confirmation_phrase != prepared.confirmation_phrase:
        raise OperationalDemoOperatorError(
            "confirmation phrase did not match the reviewed run"
        )
    runtime_clock = clock if clock is not None else _SystemClock()
    active_workload = workload_port or SubprocessWorkloadController(
        executable=prepared.configuration.workload_controller.executable,
        arguments=prepared.configuration.workload_controller.arguments,
        timeout_seconds=prepared.configuration.workload_controller.timeout_seconds,
        max_output_bytes=prepared.configuration.workload_controller.max_output_bytes,
    )
    active_phase_controller: PhaseJobPort
    active_handoff: ReferenceHandoffPort
    if phase_job_port is None or handoff_port is None:
        controller = SubprocessPhaseJobController(
            executable=prepared.configuration.phase_job_controller.executable,
            arguments=prepared.configuration.phase_job_controller.arguments,
            timeout_seconds=prepared.configuration.phase_job_controller.timeout_seconds,
            max_output_bytes=prepared.configuration.phase_job_controller.max_output_bytes,
        )
        active_phase_controller = phase_job_port or controller
        active_handoff = handoff_port or controller
    else:
        active_phase_controller = phase_job_port
        active_handoff = handoff_port
    active_reader = artifact_reader or AzureBlobVersionPinnedArtifactReader(
        blob_endpoint=prepared.configuration.artifact_reader.blob_endpoint,
        container_name=prepared.configuration.artifact_reader.container_name,
        managed_identity_client_id=(
            prepared.configuration.artifact_reader.managed_identity_client_id
        ),
    )

    try:
        baseline_report = _invoke_workload_action(
            active_workload,
            action="status",
            run_id=prepared.configuration.run_id,
            scenario_id=prepared.configuration.scenario_id,
        )
        _validate_receipt_transition(
            previous=None,
            current=baseline_report,
            expected_action="status",
        )
        baseline = _run_verified_phase(
            prepared=prepared,
            phase="baseline",
            receipt_report=baseline_report,
            previous=None,
            phase_job_port=active_phase_controller,
            handoff_port=active_handoff,
            artifact_reader=active_reader,
            clock=runtime_clock,
        )
    except OperationalDemoOperatorError as exc:
        raise OperationalDemoOperatorError(
            f"{exc}; reset not attempted; recovery not run"
        ) from exc

    injection_attempted = False
    inject_report: OperationalDemoWorkloadActionReport | None = None
    primary_message: str | None = None
    faulted: _VerifiedPhaseArtifacts | None = None
    reset_report: OperationalDemoWorkloadActionReport | None = None
    try:
        injection_attempted = True
        inject_report = _invoke_workload_action(
            active_workload,
            action="inject",
            run_id=prepared.configuration.run_id,
            scenario_id=prepared.configuration.scenario_id,
        )
        _validate_receipt_transition(
            previous=baseline.receipt_report,
            current=inject_report,
            expected_action="inject",
        )
        faulted = _run_verified_phase(
            prepared=prepared,
            phase="faulted",
            receipt_report=inject_report,
            previous=baseline,
            phase_job_port=active_phase_controller,
            handoff_port=active_handoff,
            artifact_reader=active_reader,
            clock=runtime_clock,
        )
    except OperationalDemoOperatorError as exc:
        primary_message = str(exc)
    if injection_attempted:
        previous_for_reset = inject_report or baseline.receipt_report
        try:
            reset_report = _invoke_workload_action(
                active_workload,
                action="reset",
                run_id=prepared.configuration.run_id,
                scenario_id=prepared.configuration.scenario_id,
            )
            _validate_receipt_transition(
                previous=previous_for_reset,
                current=reset_report,
                expected_action="reset",
                allow_missing_state_continuity=inject_report is None,
            )
        except OperationalDemoOperatorError as exc:
            if primary_message is not None:
                raise OperationalDemoOperatorError(
                    f"{primary_message}; reset action failed closed; recovery not run"
                ) from exc
            raise OperationalDemoOperatorError(
                "reset action failed closed; recovery not run"
            ) from exc
    if primary_message is not None:
        reset_status = "reset succeeded" if injection_attempted else "reset not attempted"
        raise OperationalDemoOperatorError(
            f"{primary_message}; {reset_status}; recovery not run"
        )
    if reset_report is None or faulted is None:
        raise OperationalDemoOperatorError(
            "reset action failed closed; recovery not run"
        )
    try:
        recovered = _run_verified_phase(
            prepared=prepared,
            phase="recovered",
            receipt_report=reset_report,
            previous=faulted,
            phase_job_port=active_phase_controller,
            handoff_port=active_handoff,
            artifact_reader=active_reader,
            clock=runtime_clock,
        )
    except OperationalDemoOperatorError as exc:
        raise OperationalDemoOperatorError(
            f"{exc}; reset succeeded"
        ) from exc
    return OperationalDemoOperatorResult(
        run_id=prepared.configuration.run_id,
        baseline=baseline.summary,
        faulted=faulted.summary,
        recovered=recovered.summary,
        reset_status="reset succeeded",
    )


__all__ = [
    "OperationalDemoOperatorError",
    "OperationalDemoOperatorResult",
    "OperationalDemoPhaseSummary",
    "OperationalDemoValidation",
    "PhaseJobPort",
    "PreparedOperationalDemoOperator",
    "ReferenceHandoffPort",
    "SubprocessPhaseJobController",
    "SubprocessWorkloadController",
    "WorkloadActionPort",
    "build_operational_demo_validation",
    "prepare_operational_demo_operator",
    "render_operational_demo_result",
    "render_operational_demo_validation",
    "run_operational_demo_operator",
]
