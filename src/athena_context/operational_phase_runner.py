from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from pydantic import BaseModel, ValidationError

from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.binding.verification import TrustedSnapshotVerifier
from athena_context.contracts.common import (
    AthenaValidationError,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.operational_phase import (
    OperationalArtifactKind,
    OperationalPhaseArtifactReference,
    OperationalPhaseCompletionIndex,
    OperationalPhaseConfiguration,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseInputs,
    OperationalPhaseSelector,
    VersionPinnedBlobReference,
    build_operational_phase_completion_index,
    compute_fault_lineage_digest,
    operational_phase_artifact_names,
)
from athena_context.contracts.presentation import (
    ArgusPresentationPhase,
    DemoFaultRunReceipt,
)
from athena_context.live_acceptance import (
    Wc013LiveAcceptancePlan,
    Wc013LiveAcceptanceResult,
    run_wc013_live_acceptance_plan,
)
from athena_context.presentation import (
    PresentationSigner,
    TrustedDemoEvaluationVerifier,
    attest_argus_presentation,
    project_argus_presentation,
    verify_demo_evaluation_result,
)

_MAX_BUNDLE_BYTES = 256 * 1024
_MAX_INPUTS_BYTES = 64 * 1024
_MAX_CONFIGURATION_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_INDEX_BYTES = 128 * 1024

type Wc013PhaseRunner = Callable[
    [Wc013LiveAcceptancePlan, Path],
    Wc013LiveAcceptanceResult,
]


class OperationalPhaseRunnerError(RuntimeError):
    """Raised when the non-mutating operational phase job fails closed."""


@dataclass(frozen=True, slots=True)
class CreateOnlyArtifact:
    name: str
    content: bytes
    digest: str


class CreateOnlyArtifactWriterPort(Protocol):
    """Create artifacts without overwrite and return their exact blob versions."""

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> tuple[VersionPinnedBlobReference, ...]: ...


class VersionPinnedPhaseInputReaderPort(Protocol):
    """Read only the exact receipt/index versions named by the phase inputs."""

    def read_receipt(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes: ...

    def read_completion_index(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes: ...


class CompletionIndexWriterPort(Protocol):
    """Create the phase completion marker after every payload artifact exists."""

    def create_completion_index(
        self,
        artifact: CreateOnlyArtifact,
    ) -> VersionPinnedBlobReference: ...


@dataclass(frozen=True, slots=True)
class OperationalPhaseRunResult:
    run_id: str
    phase: ArgusPresentationPhase
    snapshot_id: str
    result_digest: str
    presentation_digest: str
    completion_index_digest: str
    artifacts: tuple[OperationalPhaseArtifactReference, ...]
    completion_index: OperationalPhaseCompletionIndex
    completion_index_reference: VersionPinnedBlobReference


@dataclass(frozen=True, slots=True)
class _SelectedDelivery:
    bundle: OperationalPhaseDeliveryBundle
    inputs: OperationalPhaseInputs
    configuration: OperationalPhaseConfiguration
    configuration_path: Path
    plan: Wc013LiveAcceptancePlan
    receipt: DemoFaultRunReceipt
    previous_index: OperationalPhaseCompletionIndex | None


def _read_bounded(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise OperationalPhaseRunnerError(
            "operational phase input is unavailable"
        ) from exc
    if not content or len(content) > maximum_bytes:
        raise OperationalPhaseRunnerError(
            "operational phase input is outside its size bound"
        )
    return content


def _parse_model[Model: BaseModel](
    content: bytes,
    model: type[Model],
) -> Model:
    try:
        return model.model_validate_json(content)
    except (ValidationError, ValueError, TypeError) as exc:
        raise OperationalPhaseRunnerError(
            "operational phase input failed closed validation"
        ) from exc


def _parse_file[Model: BaseModel](
    path: Path,
    model: type[Model],
    *,
    maximum_bytes: int,
) -> Model:
    return _parse_model(
        _read_bounded(path, maximum_bytes=maximum_bytes),
        model,
    )


def _resolve_delivery_file(root: Path, relative_file: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = (resolved_root / relative_file).resolve(strict=True)
    except OSError as exc:
        raise OperationalPhaseRunnerError(
            "reviewed delivery file is unavailable"
        ) from exc
    if not resolved.is_file() or not resolved.is_relative_to(resolved_root):
        raise OperationalPhaseRunnerError(
            "reviewed delivery file escaped its bundle boundary"
        )
    return resolved


def _model_digest(model: BaseModel) -> str:
    return compute_artifact_digest(
        model.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def _read_version_pinned(
    *,
    reference: VersionPinnedBlobReference,
    read: Callable[[VersionPinnedBlobReference], bytes],
    maximum_bytes: int,
) -> bytes:
    try:
        content = bytes(read(reference))
    except Exception as exc:  # noqa: BLE001 - injected readers are trust boundaries.
        raise OperationalPhaseRunnerError(
            "version-pinned phase input could not be read"
        ) from exc
    if (
        not content
        or len(content) > maximum_bytes
        or sha256_hex(content) != reference.content_digest
    ):
        raise OperationalPhaseRunnerError(
            "version-pinned phase input did not match its exact hash"
        )
    return content


def _fault_lineage_digest(receipt: DemoFaultRunReceipt) -> str:
    return compute_fault_lineage_digest(receipt)


def _validate_receipt_phase(
    phase: ArgusPresentationPhase,
    receipt: DemoFaultRunReceipt,
) -> None:
    if phase == "baseline":
        valid = (
            receipt.action == "status"
            and receipt.before_power_state == "PowerState/running"
            and receipt.after_power_state == "PowerState/running"
        )
    elif phase == "faulted":
        valid = (
            receipt.action == "inject"
            and receipt.before_power_state == "PowerState/running"
            and receipt.after_power_state
            in {"PowerState/stopped", "PowerState/deallocated"}
        )
    else:
        valid = (
            receipt.action == "reset"
            and receipt.before_power_state
            in {"PowerState/stopped", "PowerState/deallocated"}
            and receipt.after_power_state == "PowerState/running"
        )
    if not valid:
        raise OperationalPhaseRunnerError(
            "selected receipt does not match the requested phase"
        )


def _validate_previous_index(
    *,
    bundle: OperationalPhaseDeliveryBundle,
    inputs: OperationalPhaseInputs,
    receipt: DemoFaultRunReceipt,
    previous: OperationalPhaseCompletionIndex | None,
) -> tuple[str, str | None]:
    lineage_digest = _fault_lineage_digest(receipt)
    if inputs.phase == "baseline":
        if previous is not None:
            raise OperationalPhaseRunnerError(
                "baseline must not consume a previous phase index"
            )
        return lineage_digest, None

    if previous is None:
        if (
            inputs.phase != "faulted"
            or inputs.lineage_reference_digest != lineage_digest
        ):
            raise OperationalPhaseRunnerError(
                "faulted phase lineage reference did not match its inject receipt"
            )
        return lineage_digest, None

    expected_previous_phase: ArgusPresentationPhase = (
        "baseline" if inputs.phase == "faulted" else "faulted"
    )
    if (
        previous.run_id != bundle.run_id
        or previous.bundle_digest != bundle.bundle_digest
        or previous.phase != expected_previous_phase
        or previous.lineage_digest != lineage_digest
        or previous.receipt_completed_at > receipt.started_at
        or previous.receipt_after_power_state
        != receipt.before_power_state
    ):
        raise OperationalPhaseRunnerError(
            "previous phase index did not preserve chronology and target lineage"
        )
    return lineage_digest, previous.index_digest


def _load_selected_delivery(
    *,
    bundle_path: Path,
    inputs_path: Path,
    phase_selector: str,
    input_reader: VersionPinnedPhaseInputReaderPort,
) -> _SelectedDelivery:
    selector = OperationalPhaseSelector(phase=phase_selector)
    phase = selector.selected_phase()
    bundle = _parse_file(
        bundle_path,
        OperationalPhaseDeliveryBundle,
        maximum_bytes=_MAX_BUNDLE_BYTES,
    )
    inputs = _parse_file(
        inputs_path,
        OperationalPhaseInputs,
        maximum_bytes=_MAX_INPUTS_BYTES,
    )
    if (
        inputs.phase != phase
        or inputs.run_id != bundle.run_id
        or inputs.bundle_digest != bundle.bundle_digest
    ):
        raise OperationalPhaseRunnerError(
            "phase inputs do not match the selected delivery bundle"
        )

    configuration = bundle.configurations.select(phase)
    configuration_path = _resolve_delivery_file(
        bundle_path.parent,
        configuration.wc013_configuration_file,
    )
    plan = _parse_file(
        configuration_path,
        Wc013LiveAcceptancePlan,
        maximum_bytes=_MAX_CONFIGURATION_BYTES,
    )
    if _model_digest(plan) != configuration.wc013_configuration_digest:
        raise OperationalPhaseRunnerError(
            "selected configuration digest does not match the reviewed bundle"
        )
    command = plan.evaluation_command
    if (
        command.attempt_id != configuration.attempt_id
        or command.snapshot_id != configuration.snapshot_id
        or plan.idempotency_key != configuration.idempotency_key
    ):
        raise OperationalPhaseRunnerError(
            "selected phase does not match its reviewed WC-013 configuration"
        )

    receipt = _parse_model(
        _read_version_pinned(
            reference=inputs.receipt,
            read=input_reader.read_receipt,
            maximum_bytes=_MAX_RECEIPT_BYTES,
        ),
        DemoFaultRunReceipt,
    )
    _validate_receipt_phase(phase, receipt)

    previous_index = None
    if inputs.previous_phase_index is not None:
        previous_index = _parse_model(
            _read_version_pinned(
                reference=inputs.previous_phase_index,
                read=input_reader.read_completion_index,
                maximum_bytes=_MAX_INDEX_BYTES,
            ),
            OperationalPhaseCompletionIndex,
        )
    _validate_previous_index(
        bundle=bundle,
        inputs=inputs,
        receipt=receipt,
        previous=previous_index,
    )
    return _SelectedDelivery(
        bundle=bundle,
        inputs=inputs,
        configuration=configuration,
        configuration_path=configuration_path,
        plan=plan,
        receipt=receipt,
        previous_index=previous_index,
    )


def _require_result_binding(
    selected: _SelectedDelivery,
    result: DemoEvaluationResult,
) -> None:
    snapshot = result.snapshot
    attempts = snapshot.collector_attempts
    if (
        snapshot.snapshot_id != selected.configuration.snapshot_id
        or result.publication.snapshot_id
        != selected.configuration.snapshot_id
        or len(attempts) != 1
        or attempts[0].attempt_id != selected.configuration.attempt_id
    ):
        raise OperationalPhaseRunnerError(
            "WC-013 result does not match the selected reviewed phase"
        )


def _canonical_artifact(content: str) -> bytes:
    return (content + "\n").encode("utf-8")


def _artifact_request(name: str, content: bytes) -> CreateOnlyArtifact:
    return CreateOnlyArtifact(
        name=name,
        content=content,
        digest=sha256_hex(content),
    )


def _validate_written_artifacts(
    *,
    requests: tuple[CreateOnlyArtifact, ...],
    references: tuple[VersionPinnedBlobReference, ...],
) -> tuple[OperationalPhaseArtifactReference, ...]:
    if len(references) != len(requests):
        raise OperationalPhaseRunnerError(
            "create-only writer returned an incomplete artifact set"
        )
    kinds: tuple[OperationalArtifactKind, ...] = (
        "evaluationResult",
        "evidenceSnapshot",
        "argusPresentation",
        "presentationAttestation",
    )
    output: list[OperationalPhaseArtifactReference] = []
    for kind, request, reference in zip(
        kinds,
        requests,
        references,
        strict=True,
    ):
        if (
            reference.name != request.name
            or reference.content_digest != request.digest
        ):
            raise OperationalPhaseRunnerError(
                "create-only writer returned a mismatched artifact version"
            )
        output.append(
            OperationalPhaseArtifactReference(
                kind=kind,
                name=reference.name,
                version=reference.version,
                contentDigest=reference.content_digest,
            )
        )
    return tuple(output)


def run_operational_phase(
    *,
    bundle_path: Path,
    inputs_path: Path,
    phase_selector: str,
    artifact_writer: CreateOnlyArtifactWriterPort | None,
    input_reader: VersionPinnedPhaseInputReaderPort | None,
    completion_index_writer: CompletionIndexWriterPort | None,
    result_verifier: TrustedDemoEvaluationVerifier | None,
    snapshot_verifier: TrustedSnapshotVerifier | None,
    signer: PresentationSigner | None,
    wc013_runner: Wc013PhaseRunner | None = None,
) -> OperationalPhaseRunResult:
    """Run one reviewed phase without requiring future receipt artifacts."""

    if artifact_writer is None:
        raise OperationalPhaseRunnerError(
            "create-only artifact writer is not configured"
        )
    if input_reader is None:
        raise OperationalPhaseRunnerError(
            "version-pinned phase input reader is not configured"
        )
    if completion_index_writer is None:
        raise OperationalPhaseRunnerError(
            "completion index writer is not configured"
        )
    if result_verifier is None or snapshot_verifier is None:
        raise OperationalPhaseRunnerError(
            "trusted result and snapshot verifiers are not configured"
        )
    if signer is None:
        raise OperationalPhaseRunnerError(
            "presentation signer is not configured"
        )

    try:
        selected = _load_selected_delivery(
            bundle_path=bundle_path,
            inputs_path=inputs_path,
            phase_selector=phase_selector,
            input_reader=input_reader,
        )
    except OperationalPhaseRunnerError:
        raise
    except (AthenaValidationError, ValidationError, ValueError, TypeError) as exc:
        raise OperationalPhaseRunnerError(
            "operational phase delivery failed closed validation"
        ) from exc

    try:
        executor = (
            wc013_runner
            if wc013_runner is not None
            else run_wc013_live_acceptance_plan
        )
        accepted = executor(selected.plan, selected.configuration_path)
    except Exception as exc:  # noqa: BLE001 - production composition is a trust boundary.
        raise OperationalPhaseRunnerError(
            "WC-013 phase execution failed closed"
        ) from exc
    if accepted.snapshot_path is not None:
        raise OperationalPhaseRunnerError(
            "WC-013 phase runner must not write artifacts directly"
        )
    result = accepted.result
    _require_result_binding(selected, result)

    try:
        verified = verify_demo_evaluation_result(
            result,
            result_verifier=result_verifier,
            snapshot_verifier=snapshot_verifier,
        )
        presentation = project_argus_presentation(
            verified,
            receipt=selected.receipt,
            phase=cast(
                ArgusPresentationPhase,
                selected.configuration.phase,
            ),
            synthetic_key_id=(
                selected.bundle.synthetic_presentation_key_id
            ),
        )
        attestation = attest_argus_presentation(
            presentation,
            signer=signer,
        )
    except Exception as exc:  # noqa: BLE001 - verification and signing fail closed.
        raise OperationalPhaseRunnerError(
            "trusted phase verification or presentation signing failed closed"
        ) from exc

    phase = selected.configuration.phase
    names = operational_phase_artifact_names(
        selected.bundle.run_id,
        phase,
    )
    result_content = _canonical_artifact(result.canonical_json())
    snapshot_content = _canonical_artifact(
        canonicalize_json(
            result.snapshot.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        )
    )
    presentation_content = _canonical_artifact(
        presentation.canonical_json()
    )
    attestation_content = _canonical_artifact(
        attestation.canonical_json()
    )
    artifact_requests = (
        _artifact_request(names[0], result_content),
        _artifact_request(names[1], snapshot_content),
        _artifact_request(names[2], presentation_content),
        _artifact_request(names[3], attestation_content),
    )
    try:
        written = artifact_writer.create_only(artifact_requests)
    except Exception as exc:  # noqa: BLE001 - writer implementations are untrusted ports.
        raise OperationalPhaseRunnerError(
            "create-only artifact persistence failed closed"
        ) from exc
    try:
        artifacts = _validate_written_artifacts(
            requests=artifact_requests,
            references=written,
        )
    except OperationalPhaseRunnerError:
        raise
    except Exception as exc:  # noqa: BLE001 - writer return values are untrusted.
        raise OperationalPhaseRunnerError(
            "create-only writer returned invalid artifact versions"
        ) from exc

    lineage_digest, previous_index_digest = _validate_previous_index(
        bundle=selected.bundle,
        inputs=selected.inputs,
        receipt=selected.receipt,
        previous=selected.previous_index,
    )
    completion_index = build_operational_phase_completion_index(
        run_id=selected.bundle.run_id,
        phase=phase,
        bundle_digest=selected.bundle.bundle_digest,
        configuration_digest=(
            selected.configuration.wc013_configuration_digest
        ),
        receipt=selected.inputs.receipt,
        previous_phase_index=selected.inputs.previous_phase_index,
        previous_phase_index_digest=previous_index_digest,
        lineage_digest=lineage_digest,
        attempt_id=selected.configuration.attempt_id,
        snapshot_id=selected.configuration.snapshot_id,
        idempotency_key_digest=sha256_hex(
            selected.configuration.idempotency_key
        ),
        receipt_action=selected.receipt.action,
        receipt_started_at=selected.receipt.started_at,
        receipt_completed_at=selected.receipt.completed_at,
        receipt_before_power_state=selected.receipt.before_power_state,
        receipt_after_power_state=selected.receipt.after_power_state,
        result_digest=result.result_digest,
        snapshot_artifact_digest=(
            result.snapshot.compatibility.artifact_digest
        ),
        snapshot_semantic_digest=(
            result.snapshot.compatibility.semantic_digest
        ),
        presentation_digest=presentation.athena.result_digest,
        artifacts=artifacts,
    )
    index_content = _canonical_artifact(completion_index.canonical_json())
    index_request = _artifact_request(names[4], index_content)
    try:
        index_reference = completion_index_writer.create_completion_index(
            index_request
        )
    except Exception as exc:  # noqa: BLE001 - writer implementations are untrusted ports.
        raise OperationalPhaseRunnerError(
            "completion index persistence failed closed"
        ) from exc
    try:
        validated_index_reference = VersionPinnedBlobReference(
            name=index_reference.name,
            version=index_reference.version,
            contentDigest=index_reference.content_digest,
        )
        if (
            validated_index_reference.name != index_request.name
            or validated_index_reference.content_digest
            != index_request.digest
        ):
            raise OperationalPhaseRunnerError(
                "completion index writer returned a mismatched version"
            )
    except OperationalPhaseRunnerError:
        raise
    except Exception as exc:  # noqa: BLE001 - writer return values are untrusted.
        raise OperationalPhaseRunnerError(
            "completion index writer returned an invalid version"
        ) from exc
    return OperationalPhaseRunResult(
        run_id=selected.bundle.run_id,
        phase=phase,
        snapshot_id=result.snapshot.snapshot_id,
        result_digest=result.result_digest,
        presentation_digest=presentation.athena.result_digest,
        completion_index_digest=(
            validated_index_reference.content_digest
        ),
        artifacts=artifacts,
        completion_index=completion_index,
        completion_index_reference=validated_index_reference,
    )


__all__ = [
    "CompletionIndexWriterPort",
    "CreateOnlyArtifact",
    "CreateOnlyArtifactWriterPort",
    "OperationalPhaseRunResult",
    "OperationalPhaseRunnerError",
    "VersionPinnedPhaseInputReaderPort",
    "Wc013PhaseRunner",
    "run_operational_phase",
]
