from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO, cast

from athena_context import __version__
from athena_context.artifacts import VersionPinnedArtifactReaderPort
from athena_context.binding.verification import TrustedSnapshotVerifier
from athena_context.contracts import build_operational_phase_reference_handoff
from athena_context.contracts.presentation import ArgusPresentationPhase
from athena_context.live_acceptance import (
    Wc013LiveAcceptanceError,
    prepare_wc013_live_acceptance,
    render_wc013_configuration,
    run_wc013_live_acceptance,
    wc013_configuration_template,
)
from athena_context.operational_demo_operator import (
    OperationalDemoOperatorError,
    PhaseJobPort,
    ReferenceHandoffPort,
    WorkloadActionPort,
    build_operational_demo_validation,
    render_operational_demo_result,
    render_operational_demo_validation,
    run_operational_demo_operator,
)
from athena_context.operational_phase_job import (
    HANDOFF_BASE64_PREFIX,
    run_operational_phase_job,
)
from athena_context.operational_phase_runner import (
    CompletionIndexWriterPort,
    CreateOnlyArtifactWriterPort,
    OperationalPhaseRunnerError,
    VersionPinnedPhaseInputReaderPort,
    Wc013PhaseRunner,
    run_operational_phase,
)
from athena_context.presentation import (
    PresentationSigner,
    TrustedDemoEvaluationVerifier,
)
from athena_context.presentation_export import (
    PresentationExportError,
    run_argus_presentation_export,
)
from athena_context.reference_command import (
    GoldenProofRunner,
    OutputFormat,
    run_agreed_golden_api,
    run_reference_command,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="athena-context",
        description="Athena Workload Context development CLI.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    golden_parser = subparsers.add_parser(
        "golden-proof",
        help="run the deterministic local three-profile proof",
        description="Run the packaged golden proof without an Azure connection.",
    )
    golden_parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="output format (default: text)",
    )
    subparsers.add_parser(
        "wc013-config-template",
        help="print a non-secret WC-013 live configuration template",
    )
    render_parser = subparsers.add_parser(
        "wc013-render-config",
        help="render bounded WC-013 runtime files from reviewed non-secret inputs",
    )
    render_parser.add_argument("--input", required=True, type=Path)
    render_parser.add_argument("--output-directory", required=True, type=Path)
    live_parser = subparsers.add_parser(
        "wc013-live-acceptance",
        help="validate or run the WC-013 live acceptance gate",
    )
    live_parser.add_argument("--config", required=True, type=Path)
    live_parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate non-secret prerequisites without acquiring credentials or using the network",
    )
    live_parser.add_argument(
        "--snapshot-output",
        type=Path,
        help="create one new read-only canonical EvidenceSnapshot file",
    )
    presentation_parser = subparsers.add_parser(
        "argus-presentation-export",
        help="export a verified synthetic-safe ARGUS presentation",
    )
    presentation_parser.add_argument("--result", required=True, type=Path)
    presentation_parser.add_argument("--receipt", required=True, type=Path)
    presentation_parser.add_argument(
        "--phase",
        required=True,
        choices=("baseline", "faulted", "recovered"),
    )
    presentation_parser.add_argument("--synthetic-key-id", required=True)
    presentation_parser.add_argument("--output", required=True, type=Path)
    presentation_parser.add_argument(
        "--attestation-output",
        required=True,
        type=Path,
    )
    phase_parser = subparsers.add_parser(
        "operational-phase-runner",
        help="run one reviewed non-mutating operational demo phase",
    )
    phase_parser.add_argument("--bundle", required=True, type=Path)
    phase_parser.add_argument("--inputs", required=True, type=Path)
    phase_parser.add_argument("--phase", required=True)
    phase_parser.add_argument("--handoff-output", type=Path)
    phase_job_parser = subparsers.add_parser(
        "operational-phase-job",
        help="run one fixed operational demo phase inside the production job",
    )
    phase_job_parser.add_argument("--bundle", required=True, type=Path)
    phase_job_parser.add_argument("--phase", required=True)
    phase_job_parser.add_argument("--inputs-output", required=True, type=Path)
    phase_job_parser.add_argument("--handoff-output", required=True, type=Path)
    phase_job_parser.add_argument("--artifact-blob-endpoint", required=True)
    phase_job_parser.add_argument("--artifact-container", required=True)
    phase_job_parser.add_argument(
        "--emit-handoff-base64",
        action="store_true",
        help="print the governed handoff as one base64 line for the phase-job controller",
    )
    operator_parser = subparsers.add_parser(
        "operational-demo-operator",
        help="validate or run the external operational demonstration operator",
    )
    operator_parser.add_argument("--config", required=True, type=Path)
    operator_parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the reviewed operator configuration without calling any ports",
    )
    operator_parser.add_argument(
        "--confirm",
        help="exact confirmation phrase printed by --validate-only",
    )
    return parser


def _write_exclusive_json_file(path: Path, content: str, *, message: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.write("\n")
    except OSError as exc:
        raise OperationalPhaseRunnerError(message) from exc


def main(
    argv: Sequence[str] | None = None,
    *,
    golden_runner: GoldenProofRunner | None = None,
    presentation_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    presentation_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    presentation_signer: PresentationSigner | None = None,
    phase_artifact_writer: CreateOnlyArtifactWriterPort | None = None,
    phase_input_reader: VersionPinnedPhaseInputReaderPort | None = None,
    phase_completion_index_writer: CompletionIndexWriterPort | None = None,
    phase_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    phase_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    phase_signer: PresentationSigner | None = None,
    phase_wc013_runner: Wc013PhaseRunner | None = None,
    operational_demo_workload_port: WorkloadActionPort | None = None,
    operational_demo_phase_job_port: PhaseJobPort | None = None,
    operational_demo_handoff_port: ReferenceHandoffPort | None = None,
    operational_demo_artifact_reader: VersionPinnedArtifactReaderPort | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "golden-proof":
        return run_reference_command(
            output_format=cast(OutputFormat, args.format),
            runner=golden_runner or run_agreed_golden_api,
            stdout=stdout if stdout is not None else sys.stdout,
            stderr=stderr if stderr is not None else sys.stderr,
        )
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    if args.command == "wc013-config-template":
        output.write(wc013_configuration_template())
        return 0
    try:
        if args.command == "wc013-render-config":
            rendered = render_wc013_configuration(
                args.input,
                args.output_directory,
            )
            output.write(
                f"rendered WC-013 configuration: {rendered.plan_path}\n"
                f"pinned assertion digest: {rendered.assertion_digest}\n"
                f"pinned authority digest: {rendered.authority_digest}\n"
            )
            return 0
        if args.command == "wc013-live-acceptance":
            if args.validate_only:
                prepared = prepare_wc013_live_acceptance(args.config)
                output.write(
                    "WC-013 live configuration is valid\n"
                    f"endpoint: {prepared.assertion.azure_mcp_internal_endpoint}\n"
                    f"assertion digest: {prepared.assertion.assertion_digest}\n"
                    f"authority digest: {prepared.authority.authority_digest}\n"
                )
                return 0
            accepted = run_wc013_live_acceptance(
                args.config,
                snapshot_output=args.snapshot_output,
            )
            output.write(
                "WC-013 live acceptance passed\n"
                f"snapshot: {accepted.result.snapshot.snapshot_id}\n"
                f"artifact digest: "
                f"{accepted.result.snapshot.compatibility.artifact_digest}\n"
            )
            if accepted.snapshot_path is not None:
                output.write(f"immutable snapshot file: {accepted.snapshot_path}\n")
            return 0
        if args.command == "argus-presentation-export":
            if (
                presentation_result_verifier is None
                or presentation_snapshot_verifier is None
                or presentation_signer is None
            ):
                raise PresentationExportError(
                    "trusted result verifier, snapshot verifier, and signer are required"
                )
            exported = run_argus_presentation_export(
                result_path=args.result,
                receipt_path=args.receipt,
                phase=cast(ArgusPresentationPhase, args.phase),
                synthetic_key_id=args.synthetic_key_id,
                payload_path=args.output,
                attestation_path=args.attestation_output,
                result_verifier=presentation_result_verifier,
                snapshot_verifier=presentation_snapshot_verifier,
                signer=presentation_signer,
            )
            output.write(
                "ARGUS presentation export passed\n"
                f"payload: {exported.payload_path}\n"
                f"attestation: {exported.attestation_path}\n"
                f"result digest: {exported.payload.athena.result_digest}\n"
            )
            return 0
        if args.command == "operational-phase-runner":
            completed = run_operational_phase(
                bundle_path=args.bundle,
                inputs_path=args.inputs,
                phase_selector=args.phase,
                artifact_writer=phase_artifact_writer,
                input_reader=phase_input_reader,
                completion_index_writer=phase_completion_index_writer,
                result_verifier=phase_result_verifier,
                snapshot_verifier=phase_snapshot_verifier,
                signer=phase_signer,
                wc013_runner=phase_wc013_runner,
            )
            if args.handoff_output is not None:
                handoff = build_operational_phase_reference_handoff(
                    run_id=completed.run_id,
                    phase=completed.phase,
                    bundle_digest=completed.completion_index.bundle_digest,
                    completion_index=completed.completion_index_reference,
                )
                _write_exclusive_json_file(
                    args.handoff_output,
                    handoff.canonical_json(),
                    message="phase reference handoff output could not be created",
                )
            output.write(
                "operational phase runner passed\n"
                f"run: {completed.run_id}\n"
                f"phase: {completed.phase}\n"
                f"snapshot: {completed.snapshot_id}\n"
                f"result digest: {completed.result_digest}\n"
                f"presentation digest: {completed.presentation_digest}\n"
                f"completion index digest: "
                f"{completed.completion_index_digest}\n"
            )
            return 0
        if args.command == "operational-phase-job":
            job = run_operational_phase_job(
                bundle_path=args.bundle,
                phase_selector=args.phase,
                inputs_output_path=args.inputs_output,
                handoff_output_path=args.handoff_output,
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                artifact_container_name=args.artifact_container,
            )
            output.write(
                "operational phase job passed\n"
                f"run: {job.completed.run_id}\n"
                f"phase: {job.completed.phase}\n"
                f"snapshot: {job.completed.snapshot_id}\n"
                f"result digest: {job.completed.result_digest}\n"
                f"presentation digest: {job.completed.presentation_digest}\n"
                f"completion index digest: "
                f"{job.completed.completion_index_digest}\n"
            )
            if args.emit_handoff_base64:
                output.write(
                    f"{HANDOFF_BASE64_PREFIX}{job.handoff_base64()}\n"
                )
            return 0
        if args.command == "operational-demo-operator":
            if args.validate_only:
                validation = build_operational_demo_validation(args.config)
                output.write(render_operational_demo_validation(validation))
                return 0
            result = run_operational_demo_operator(
                args.config,
                confirmation_phrase=args.confirm,
                workload_port=operational_demo_workload_port,
                phase_job_port=operational_demo_phase_job_port,
                handoff_port=operational_demo_handoff_port,
                artifact_reader=operational_demo_artifact_reader,
            )
            output.write(render_operational_demo_result(result))
            return 0
    except Wc013LiveAcceptanceError as exc:
        errors.write(f"WC-013 live acceptance failed: {exc}\n")
        return 1
    except PresentationExportError as exc:
        errors.write(f"ARGUS presentation export failed: {exc}\n")
        return 1
    except OperationalPhaseRunnerError as exc:
        label = (
            'operational phase job'
            if args.command == 'operational-phase-job'
            else 'operational phase runner'
        )
        errors.write(f"{label} failed: {exc}\n")
        return 1
    except OperationalDemoOperatorError as exc:
        errors.write(f"operational demo operator failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
