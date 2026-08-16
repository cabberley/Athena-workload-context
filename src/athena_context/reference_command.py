"""Presentation-only adapter for the local WC-005 golden proof."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from importlib import import_module
from json import JSONDecodeError
from typing import Literal, Protocol, TextIO, cast

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from athena_context.contracts import AthenaValidationError
from athena_context.contracts.manifest import FindingVerdict

EXIT_ORACLE_MISMATCH = 1
EXIT_EXECUTION_FAILURE = 2


class GoldenProfileResultView(Protocol):
    """Read-only WC-005 per-profile result surface used by text presentation."""

    @property
    def profile_id(self) -> str: ...

    @property
    def verdicts(self) -> Sequence[tuple[str, FindingVerdict]]: ...

    @property
    def findings(self) -> Sequence[str]: ...


class GoldenProofResultView(Protocol):
    """WC-005 result seam consumed by the command without evaluating policy."""

    @property
    def snapshot_artifact_digest(self) -> str: ...

    @property
    def snapshot_semantic_digest(self) -> str: ...

    @property
    def profiles(self) -> Sequence[GoldenProfileResultView]: ...

    def canonical_json(self) -> str: ...


class GoldenOracleMismatchError(Exception):
    """Normalized mismatch raised by the WC-005 API adapter."""


type GoldenProofRunner = Callable[[], GoldenProofResultView]
type OutputFormat = Literal["json", "text"]


def run_agreed_golden_api() -> GoldenProofResultView:
    """Call ``athena_context.golden.run_golden_proof`` through a lazy seam."""

    golden_module = import_module("athena_context.golden")
    candidate: object = golden_module.run_golden_proof
    mismatch_type = cast(type[Exception], golden_module.GoldenProofMismatchError)
    if not callable(candidate):
        raise TypeError("athena_context.golden.run_golden_proof is not callable")
    runner = cast(GoldenProofRunner, candidate)
    try:
        return runner()
    except mismatch_type as exc:
        raise GoldenOracleMismatchError(str(exc)) from exc


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"golden result requires non-empty {key}")
    return value


def _finding_payloads(profile: GoldenProfileResultView) -> dict[str, Mapping[str, object]]:
    findings: dict[str, Mapping[str, object]] = {}
    for serialized in profile.findings:
        payload = json.loads(serialized)
        if not isinstance(payload, dict):
            raise ValueError("golden finding must be a JSON object")
        clause_id = _required_string(payload, "clauseId")
        if clause_id in findings:
            raise ValueError(f"golden result contains duplicate finding: {clause_id}")
        findings[clause_id] = payload
    return findings


def _format_evidence_reference(value: object) -> str:
    if not isinstance(value, dict):
        raise ValueError("golden evidence reference must be a JSON object")
    ref_type = _required_string(value, "refType")
    if ref_type == "evidenceItem":
        return (
            f"evidenceItem:{_required_string(value, 'itemDigest')}"
            f"@{_required_string(value, 'sourceResponsePointer')}"
        )
    if ref_type == "evidenceGap":
        return (
            f"evidenceGap:{_required_string(value, 'gapId')}"
            f"@{_required_string(value, 'gapRecordDigest')}"
        )
    raise ValueError(f"unsupported golden evidence reference type: {ref_type}")


def _finding_references(payload: Mapping[str, object]) -> str:
    references = payload.get("evidenceRefs")
    if not isinstance(references, list) or not references:
        raise ValueError("golden finding requires evidenceRefs")
    return ", ".join(
        _format_evidence_reference(reference)
        for reference in sorted(
            references,
            key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True),
        )
    )


def format_golden_proof_text(result: GoldenProofResultView) -> str:
    """Render a concise report; the runner remains the sole oracle evaluator."""

    lines = [
        "Golden proof: MATCH",
        f"Snapshot artifact digest: {result.snapshot_artifact_digest}",
        f"Snapshot semantic digest: {result.snapshot_semantic_digest}",
    ]
    for profile in sorted(result.profiles, key=lambda item: item.profile_id.casefold()):
        lines.append(f"Profile: {profile.profile_id}")
        findings = _finding_payloads(profile)
        for clause_id, verdict in sorted(
            profile.verdicts,
            key=lambda item: item[0].casefold(),
        ):
            finding = findings.get(clause_id)
            if finding is None:
                raise ValueError(f"golden verdict has no finding: {clause_id}")
            acceptance_value = finding.get("riskAcceptanceRef")
            if acceptance_value is not None and not isinstance(acceptance_value, str):
                raise ValueError("golden riskAcceptanceRef must be a string or null")
            acceptance = acceptance_value or "none"
            lines.append(
                f"  {clause_id}: {verdict}"
                f" | residual-risk acceptance: {acceptance}"
                f" | evidence: {_finding_references(finding)}"
            )
    return "\n".join(lines) + "\n"


def format_golden_proof_json(result: GoldenProofResultView) -> str:
    """Serialize the typed WC-005 result as stable canonical JSON."""

    return result.canonical_json() + "\n"


def run_reference_command(
    *,
    output_format: OutputFormat,
    runner: GoldenProofRunner,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    """Run once, present once, and preserve the golden runner's exact decision."""

    try:
        result = runner()
    except GoldenOracleMismatchError as exc:
        detail = str(exc).strip() or exc.__class__.__name__
        stderr.write(f"golden-proof mismatch: {detail}\n")
        return EXIT_ORACLE_MISMATCH
    except (
        AthenaValidationError,
        ImportError,
        InvalidSignature,
        JSONDecodeError,
        ValidationError,
    ) as exc:
        detail = str(exc).strip() or exc.__class__.__name__
        stderr.write(f"golden-proof failed ({exc.__class__.__name__}): {detail}\n")
        return EXIT_EXECUTION_FAILURE

    if output_format == "json":
        stdout.write(format_golden_proof_json(result))
    elif output_format == "text":
        stdout.write(format_golden_proof_text(result))
    else:
        raise ValueError(f"unsupported output format: {output_format}")
    return 0


__all__ = [
    "EXIT_EXECUTION_FAILURE",
    "EXIT_ORACLE_MISMATCH",
    "GoldenOracleMismatchError",
    "GoldenProofResultView",
    "GoldenProofRunner",
    "format_golden_proof_json",
    "format_golden_proof_text",
    "run_agreed_golden_api",
    "run_reference_command",
]
