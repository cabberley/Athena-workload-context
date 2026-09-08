"""Emit a local, deterministic, deliberately unpublished WC-022 proposal."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from athena_context.wc022_epic_proposal import (  # noqa: E402
    ResearchDraftConversionError,
    convert_canonical_public_safe_research_draft,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert the guarded public-safe research draft into an unpublished "
            "WC-022 governed workload-context proposal."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="new local JSON output path; omitted writes canonical JSON to stdout",
    )
    args = parser.parse_args(argv)
    try:
        proposal = convert_canonical_public_safe_research_draft()
        rendered = proposal.canonical_json() + "\n"
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print(f"Wrote unpublished WC-022 proposal: {args.output}")
            print(f"Proposal digest: {proposal.proposal_digest}")
    except (OSError, ResearchDraftConversionError, ValueError) as exc:
        print(f"WC-022 research conversion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
