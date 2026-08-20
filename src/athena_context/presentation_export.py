from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.binding.verification import TrustedSnapshotVerifier
from athena_context.contracts.common import AthenaValidationError
from athena_context.contracts.presentation import (
    ArgusPresentationPayload,
    ArgusPresentationPhase,
    DemoFaultRunReceipt,
    PresentationAttestation,
)
from athena_context.presentation import (
    PresentationSigner,
    TrustedDemoEvaluationVerifier,
    attest_argus_presentation,
    project_argus_presentation,
    verify_demo_evaluation_result,
)

_MAX_RESULT_BYTES = 50 * 1024 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024


class PresentationExportError(RuntimeError):
    """Raised when the fail-closed presentation export cannot complete."""


@dataclass(frozen=True, slots=True)
class PresentationExportResult:
    payload: ArgusPresentationPayload
    attestation: PresentationAttestation
    payload_path: Path
    attestation_path: Path


def _read_bounded_text(path: Path, *, maximum_bytes: int, label: str) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PresentationExportError(f"unable to read {label} file") from exc
    if size <= 0 or size > maximum_bytes:
        raise PresentationExportError(f"{label} file size is outside the allowed bound")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PresentationExportError(f"unable to read {label} file") from exc


def _write_new_text(path: Path, text: str, *, label: str) -> None:
    if not path.parent.is_dir():
        raise PresentationExportError(f"{label} parent directory does not exist")
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(text)
            output.write("\n")
    except FileExistsError as exc:
        raise PresentationExportError(f"{label} file already exists") from exc
    except OSError as exc:
        raise PresentationExportError(f"unable to create {label} file") from exc


def run_argus_presentation_export(
    *,
    result_path: Path,
    receipt_path: Path,
    phase: ArgusPresentationPhase,
    synthetic_key_id: str,
    payload_path: Path,
    attestation_path: Path,
    result_verifier: TrustedDemoEvaluationVerifier,
    snapshot_verifier: TrustedSnapshotVerifier,
    signer: PresentationSigner,
) -> PresentationExportResult:
    """Validate, redact, attest, and write one immutable ARGUS export pair."""

    resolved_outputs = {
        payload_path.resolve(strict=False),
        attestation_path.resolve(strict=False),
    }
    if len(resolved_outputs) != 2:
        raise PresentationExportError(
            "payload and attestation output paths must be different"
        )
    if any(path.exists() for path in resolved_outputs):
        raise PresentationExportError("presentation output files must not already exist")

    try:
        result = DemoEvaluationResult.model_validate_json(
            _read_bounded_text(
                result_path,
                maximum_bytes=_MAX_RESULT_BYTES,
                label="evaluation result",
            )
        )
        receipt = DemoFaultRunReceipt.model_validate_json(
            _read_bounded_text(
                receipt_path,
                maximum_bytes=_MAX_RECEIPT_BYTES,
                label="fault receipt",
            )
        )
        verified = verify_demo_evaluation_result(
            result,
            result_verifier=result_verifier,
            snapshot_verifier=snapshot_verifier,
        )
        payload = project_argus_presentation(
            verified,
            receipt=receipt,
            phase=phase,
            synthetic_key_id=synthetic_key_id,
        )
        attestation = attest_argus_presentation(payload, signer=signer)
    except PresentationExportError:
        raise
    except (AthenaValidationError, ValidationError, ValueError, TypeError) as exc:
        raise PresentationExportError(
            "presentation inputs failed closed validation"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - trust/signing ports fail closed here.
        raise PresentationExportError(
            "trusted presentation verification or signing failed"
        ) from exc

    payload_written = False
    try:
        _write_new_text(
            payload_path,
            payload.canonical_json(),
            label="presentation payload",
        )
        payload_written = True
        _write_new_text(
            attestation_path,
            attestation.canonical_json(),
            label="presentation attestation",
        )
    except PresentationExportError:
        if payload_written:
            with suppress(OSError):
                payload_path.unlink()
        raise
    return PresentationExportResult(
        payload=payload,
        attestation=attestation,
        payload_path=payload_path,
        attestation_path=attestation_path,
    )


__all__ = [
    "PresentationExportError",
    "PresentationExportResult",
    "run_argus_presentation_export",
]
