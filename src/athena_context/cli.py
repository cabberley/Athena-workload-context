from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO, cast

from athena_context import __version__
from athena_context.binding.verification import TrustedSnapshotVerifier
from athena_context.contracts.presentation import ArgusPresentationPhase
from athena_context.live_acceptance import (
    Wc013LiveAcceptanceError,
    prepare_wc013_live_acceptance,
    render_wc013_configuration,
    run_wc013_live_acceptance,
    wc013_configuration_template,
)
from athena_context.operational_phase_runner import (
    CreateOnlyArtifactWriterPort,
    OperationalPhaseRunnerError,
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
    phase_parser.add_argument("--phase", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    golden_runner: GoldenProofRunner | None = None,
    presentation_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    presentation_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    presentation_signer: PresentationSigner | None = None,
    phase_artifact_writer: CreateOnlyArtifactWriterPort | None = None,
    phase_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    phase_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    phase_signer: PresentationSigner | None = None,
    phase_wc013_runner: Wc013PhaseRunner | None = None,
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
                phase_selector=args.phase,
                artifact_writer=phase_artifact_writer,
                result_verifier=phase_result_verifier,
                snapshot_verifier=phase_snapshot_verifier,
                signer=phase_signer,
                wc013_runner=phase_wc013_runner,
            )
            output.write(
                "operational phase runner passed\n"
                f"phase: {completed.phase}\n"
                f"snapshot: {completed.snapshot_id}\n"
                f"result digest: {completed.result_digest}\n"
                f"presentation digest: {completed.presentation_digest}\n"
                f"receipt digest: {completed.receipt_digest}\n"
            )
            return 0
    except Wc013LiveAcceptanceError as exc:
        errors.write(f"WC-013 live acceptance failed: {exc}\n")
        return 1
    except PresentationExportError as exc:
        errors.write(f"ARGUS presentation export failed: {exc}\n")
        return 1
    except OperationalPhaseRunnerError as exc:
        errors.write(f"operational phase runner failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
