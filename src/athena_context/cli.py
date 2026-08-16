from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO, cast

from athena_context import __version__
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
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    golden_runner: GoldenProofRunner | None = None,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
