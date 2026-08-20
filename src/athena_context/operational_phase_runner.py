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
    OPERATIONAL_PHASES,
    OperationalArtifactKind,
    OperationalPhaseArtifactReference,
    OperationalPhaseConfiguration,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseReceipt,
    OperationalPhaseSelector,
    build_operational_phase_receipt,
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
_MAX_CONFIGURATION_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024

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
    """Create one complete artifact set without overwriting an existing name."""

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class OperationalPhaseRunResult:
    phase: ArgusPresentationPhase
    snapshot_id: str
    result_digest: str
    presentation_digest: str
    receipt_digest: str
    artifacts: tuple[OperationalPhaseArtifactReference, ...]
    receipt: OperationalPhaseReceipt


@dataclass(frozen=True, slots=True)
class _SelectedDelivery:
    bundle: OperationalPhaseDeliveryBundle
    configuration: OperationalPhaseConfiguration
    configuration_path: Path
    plan: Wc013LiveAcceptancePlan
    fault_receipt: DemoFaultRunReceipt


@dataclass(frozen=True, slots=True)
class _LoadedPhase:
    configuration: OperationalPhaseConfiguration
    configuration_path: Path
    plan: Wc013LiveAcceptancePlan
    fault_receipt: DemoFaultRunReceipt


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
    path: Path,
    model: type[Model],
    *,
    maximum_bytes: int,
) -> Model:
    try:
        return model.model_validate_json(
            _read_bounded(path, maximum_bytes=maximum_bytes)
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise OperationalPhaseRunnerError(
            "operational phase input failed closed validation"
        ) from exc


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


def _load_selected_delivery(
    bundle_path: Path,
    phase_selector: str,
) -> _SelectedDelivery:
    selector = OperationalPhaseSelector(phase=phase_selector)
    phase = selector.selected_phase()
    bundle = _parse_model(
        bundle_path,
        OperationalPhaseDeliveryBundle,
        maximum_bytes=_MAX_BUNDLE_BYTES,
    )
    if phase not in bundle.allowed_phases:
        raise OperationalPhaseRunnerError("phase selector is not allowlisted")
    loaded: dict[ArgusPresentationPhase, _LoadedPhase] = {}
    for configured_phase in OPERATIONAL_PHASES:
        configuration = bundle.configurations.select(configured_phase)
        configuration_path = _resolve_delivery_file(
            bundle_path.parent,
            configuration.wc013_configuration_file,
        )
        receipt_path = _resolve_delivery_file(
            bundle_path.parent,
            configuration.fault_receipt_file,
        )
        plan = _parse_model(
            configuration_path,
            Wc013LiveAcceptancePlan,
            maximum_bytes=_MAX_CONFIGURATION_BYTES,
        )
        fault_receipt = _parse_model(
            receipt_path,
            DemoFaultRunReceipt,
            maximum_bytes=_MAX_RECEIPT_BYTES,
        )
        if (
            _model_digest(plan)
            != configuration.wc013_configuration_digest
            or _model_digest(fault_receipt)
            != configuration.fault_receipt_digest
        ):
            raise OperationalPhaseRunnerError(
                "phase input digest does not match the reviewed bundle"
            )
        command = plan.evaluation_command
        if (
            command.attempt_id != configuration.attempt_id
            or command.snapshot_id != configuration.snapshot_id
            or plan.idempotency_key != configuration.idempotency_key
        ):
            raise OperationalPhaseRunnerError(
                "phase does not match its reviewed WC-013 configuration"
            )
        expected_action = {
            "baseline": "status",
            "faulted": "inject",
            "recovered": "reset",
        }[configured_phase]
        if fault_receipt.action != expected_action:
            raise OperationalPhaseRunnerError(
                "phase does not match its reviewed fault receipt"
            )
        loaded[configured_phase] = _LoadedPhase(
            configuration=configuration,
            configuration_path=configuration_path,
            plan=plan,
            fault_receipt=fault_receipt,
        )
    _validate_receipt_sequence(loaded)
    selected = loaded[phase]
    return _SelectedDelivery(
        bundle=bundle,
        configuration=selected.configuration,
        configuration_path=selected.configuration_path,
        plan=selected.plan,
        fault_receipt=selected.fault_receipt,
    )


def _validate_receipt_sequence(
    loaded: dict[ArgusPresentationPhase, _LoadedPhase],
) -> None:
    baseline = loaded["baseline"].fault_receipt
    faulted = loaded["faulted"].fault_receipt
    recovered = loaded["recovered"].fault_receipt

    def lineage(receipt: DemoFaultRunReceipt) -> tuple[object, ...]:
        return (
            receipt.fault_run_id,
            receipt.fault_kind,
            receipt.resource_group.casefold(),
            receipt.prefix.casefold(),
            receipt.target_vm_name.casefold(),
            receipt.target_vm_resource_id.casefold(),
            tuple(name.casefold() for name in receipt.eligible_web_vm_names),
        )

    if len({lineage(baseline), lineage(faulted), lineage(recovered)}) != 1:
        raise OperationalPhaseRunnerError(
            "phase receipts do not share one reviewed fault lineage"
        )
    if (
        baseline.before_power_state != "PowerState/running"
        or baseline.after_power_state != "PowerState/running"
        or faulted.before_power_state != "PowerState/running"
        or recovered.before_power_state != faulted.after_power_state
        or recovered.after_power_state != "PowerState/running"
    ):
        raise OperationalPhaseRunnerError(
            "phase receipts do not form the reviewed power-state sequence"
        )
    if (
        baseline.completed_at > faulted.started_at
        or faulted.completed_at > recovered.started_at
    ):
        raise OperationalPhaseRunnerError(
            "phase receipt chronology is not baseline, faulted, recovered"
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


def _artifact_reference(
    *,
    kind: OperationalArtifactKind,
    name: str,
    content: bytes,
) -> OperationalPhaseArtifactReference:
    return OperationalPhaseArtifactReference(
        kind=kind,
        name=name,
        digest=sha256_hex(content),
    )


def _artifact_request(
    reference: OperationalPhaseArtifactReference,
    content: bytes,
) -> CreateOnlyArtifact:
    if reference.digest != sha256_hex(content):
        raise OperationalPhaseRunnerError(
            "operational phase artifact digest changed before persistence"
        )
    return CreateOnlyArtifact(
        name=reference.name,
        content=content,
        digest=reference.digest,
    )


def run_operational_phase(
    *,
    bundle_path: Path,
    phase_selector: str,
    artifact_writer: CreateOnlyArtifactWriterPort | None,
    result_verifier: TrustedDemoEvaluationVerifier | None,
    snapshot_verifier: TrustedSnapshotVerifier | None,
    signer: PresentationSigner | None,
    wc013_runner: Wc013PhaseRunner | None = None,
) -> OperationalPhaseRunResult:
    """Run one reviewed phase without injecting or resetting an Azure fault."""

    if artifact_writer is None:
        raise OperationalPhaseRunnerError(
            "create-only artifact writer is not configured"
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
        selected = _load_selected_delivery(bundle_path, phase_selector)
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
    except Exception as exc:  # noqa: BLE001 - the production composition is a trust boundary.
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
            receipt=selected.fault_receipt,
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
    names = operational_phase_artifact_names(phase)
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
    artifact_references = (
        _artifact_reference(
            kind="evaluationResult",
            name=names[0],
            content=result_content,
        ),
        _artifact_reference(
            kind="evidenceSnapshot",
            name=names[1],
            content=snapshot_content,
        ),
        _artifact_reference(
            kind="argusPresentation",
            name=names[2],
            content=presentation_content,
        ),
        _artifact_reference(
            kind="presentationAttestation",
            name=names[3],
            content=attestation_content,
        ),
    )
    receipt = build_operational_phase_receipt(
        phase=phase,
        bundle_digest=selected.bundle.bundle_digest,
        configuration_digest=(
            selected.configuration.wc013_configuration_digest
        ),
        fault_receipt_digest=selected.configuration.fault_receipt_digest,
        attempt_id=selected.configuration.attempt_id,
        snapshot_id=selected.configuration.snapshot_id,
        idempotency_key_digest=sha256_hex(
            selected.configuration.idempotency_key
        ),
        result_digest=result.result_digest,
        snapshot_artifact_digest=(
            result.snapshot.compatibility.artifact_digest
        ),
        snapshot_semantic_digest=(
            result.snapshot.compatibility.semantic_digest
        ),
        presentation_digest=presentation.athena.result_digest,
        artifacts=artifact_references,
    )
    receipt_content = _canonical_artifact(receipt.canonical_json())
    receipt_reference = OperationalPhaseArtifactReference(
        kind="phaseReceipt",
        name=names[4],
        digest=sha256_hex(receipt_content),
    )
    written_references = (*artifact_references, receipt_reference)
    requests = (
        _artifact_request(artifact_references[0], result_content),
        _artifact_request(artifact_references[1], snapshot_content),
        _artifact_request(artifact_references[2], presentation_content),
        _artifact_request(artifact_references[3], attestation_content),
        _artifact_request(receipt_reference, receipt_content),
    )
    if len({request.name for request in requests}) != len(requests):
        raise OperationalPhaseRunnerError(
            "operational phase artifact names are not unique"
        )
    try:
        artifact_writer.create_only(requests)
    except Exception as exc:  # noqa: BLE001 - writer implementations are untrusted ports.
        raise OperationalPhaseRunnerError(
            "create-only artifact persistence failed closed"
        ) from exc
    return OperationalPhaseRunResult(
        phase=phase,
        snapshot_id=result.snapshot.snapshot_id,
        result_digest=result.result_digest,
        presentation_digest=presentation.athena.result_digest,
        receipt_digest=receipt_reference.digest,
        artifacts=written_references,
        receipt=receipt,
    )


__all__ = [
    "CreateOnlyArtifact",
    "CreateOnlyArtifactWriterPort",
    "OperationalPhaseRunResult",
    "OperationalPhaseRunnerError",
    "Wc013PhaseRunner",
    "run_operational_phase",
]
