from __future__ import annotations

import io
import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature

import athena_context.reference_command as reference_command
from athena_context.cli import main
from athena_context.contracts import AthenaValidationError
from athena_context.contracts.manifest import FindingVerdict
from athena_context.reference_command import (
    GoldenOracleMismatchError,
    run_agreed_golden_api,
)

_ARTIFACT_DIGEST = "sha256:" + "a" * 64
_SEMANTIC_DIGEST = "sha256:" + "b" * 64
_ITEM_DIGEST = "sha256:" + "c" * 64


def _finding(
    clause_id: str,
    verdict: FindingVerdict,
    risk_acceptance_ref: str | None,
) -> str:
    return json.dumps(
        {
            "clauseId": clause_id,
            "evidenceRefs": [
                {
                    "itemDigest": _ITEM_DIGEST,
                    "refType": "evidenceItem",
                    "sourceResponsePointer": "/response/items/0",
                }
            ],
            "riskAcceptanceRef": risk_acceptance_ref,
            "verdict": verdict,
        },
        sort_keys=True,
    )


@dataclass(frozen=True)
class _Profile:
    profile_id: str
    verdicts: tuple[tuple[str, FindingVerdict], ...]
    findings: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "findings": [json.loads(finding) for finding in self.findings],
            "profileId": self.profile_id,
            "verdicts": dict(self.verdicts),
        }


@dataclass(frozen=True)
class _Result:
    profiles: tuple[_Profile, ...]
    snapshot_artifact_digest: str = _ARTIFACT_DIGEST
    snapshot_semantic_digest: str = _SEMANTIC_DIGEST

    def canonical_json(self) -> str:
        return json.dumps(
            {
                "profiles": [profile.to_payload() for profile in self.profiles],
                "snapshotArtifactDigest": self.snapshot_artifact_digest,
                "snapshotSemanticDigest": self.snapshot_semantic_digest,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _result() -> _Result:
    return _Result(
        profiles=(
            _Profile(
                profile_id="training",
                verdicts=(("web-zone-distribution", "violation"),),
                findings=(
                    _finding("web-zone-distribution", "violation", None),
                ),
            ),
            _Profile(
                profile_id="production",
                verdicts=(
                    ("worker-db-zone-colocation", "pass"),
                    ("db-zone-loss-spof", "acceptedResidualRisk"),
                ),
                findings=(
                    _finding("worker-db-zone-colocation", "pass", None),
                    _finding(
                        "db-zone-loss-spof",
                        "acceptedResidualRisk",
                        "ra-db-zone-loss-production",
                    ),
                ),
            ),
        ),
    )


def test_json_output_is_stable_machine_readable_and_runner_is_called_once() -> None:
    calls = 0

    def runner() -> _Result:
        nonlocal calls
        calls += 1
        return _result()

    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        ["golden-proof", "--format", "json"],
        golden_runner=runner,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert calls == 1
    assert stderr.getvalue() == ""
    payload = json.loads(stdout.getvalue())
    assert payload["snapshotArtifactDigest"] == _ARTIFACT_DIGEST
    assert payload["snapshotSemanticDigest"] == _SEMANTIC_DIGEST
    assert payload["profiles"][1]["profileId"] == "production"
    finding = payload["profiles"][1]["findings"][1]
    assert finding["verdict"] == "acceptedResidualRisk"
    assert finding["riskAcceptanceRef"] == "ra-db-zone-loss-production"
    assert finding["evidenceRefs"][0]["itemDigest"] == _ITEM_DIGEST
    assert stdout.getvalue() == _result().canonical_json() + "\n"


def test_text_output_is_concise_complete_and_deterministically_ordered() -> None:
    stdout = io.StringIO()
    exit_code = main(
        ["golden-proof", "--format", "text"],
        golden_runner=_result,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    output = stdout.getvalue()
    assert exit_code == 0
    assert output.startswith(
        "Golden proof: MATCH\n"
        f"Snapshot artifact digest: {_ARTIFACT_DIGEST}\n"
        f"Snapshot semantic digest: {_SEMANTIC_DIGEST}\n"
    )
    assert output.index("Profile: production") < output.index("Profile: training")
    assert output.index("  db-zone-loss-spof:") < output.index(
        "  worker-db-zone-colocation:"
    )
    assert "acceptedResidualRisk" in output
    assert "residual-risk acceptance: ra-db-zone-loss-production" in output
    assert f"evidenceItem:{_ITEM_DIGEST}@/response/items/0" in output


def test_default_adapter_calls_the_agreed_wc005_public_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_modules: list[str] = []
    expected = _result()

    class Mismatch(AthenaValidationError):
        pass

    def fake_import(name: str) -> SimpleNamespace:
        requested_modules.append(name)
        return SimpleNamespace(
            GoldenProofMismatchError=Mismatch,
            run_golden_proof=lambda: expected,
        )

    monkeypatch.setattr(reference_command, "import_module", fake_import)

    assert run_agreed_golden_api() is expected
    assert requested_modules == ["athena_context.golden"]


def test_default_adapter_normalizes_the_wc005_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Mismatch(AthenaValidationError):
        pass

    def mismatch() -> _Result:
        raise Mismatch("oracle differs")

    monkeypatch.setattr(
        reference_command,
        "import_module",
        lambda _name: SimpleNamespace(
            GoldenProofMismatchError=Mismatch,
            run_golden_proof=mismatch,
        ),
    )

    with pytest.raises(GoldenOracleMismatchError, match="oracle differs"):
        run_agreed_golden_api()


@pytest.mark.parametrize("blocking_state", ["mismatch", "unknown", "conflicting"])
def test_runner_blocking_decision_exits_nonzero(blocking_state: str) -> None:
    def runner() -> _Result:
        raise GoldenOracleMismatchError(f"{blocking_state} blocks the oracle")

    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        ["golden-proof", "--format", "json"],
        golden_runner=runner,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert blocking_state in stderr.getvalue()


@pytest.mark.parametrize(
    "failure",
    [
        AthenaValidationError("invalid packaged fixture"),
        InvalidSignature(),
    ],
)
def test_expected_fixture_and_verification_failures_are_useful(
    failure: Exception,
) -> None:
    def runner() -> _Result:
        raise failure

    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        ["golden-proof"],
        golden_runner=runner,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert "golden-proof failed" in stderr.getvalue()
    assert failure.__class__.__name__ in stderr.getvalue()


def test_unexpected_runner_failure_is_not_swallowed() -> None:
    def runner() -> _Result:
        raise RuntimeError("runner bug")

    with pytest.raises(RuntimeError, match="runner bug"):
        main(
            ["golden-proof"],
            golden_runner=runner,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )


def test_no_subcommand_preserves_bootstrap_without_loading_golden_api() -> None:
    def runner() -> _Result:
        raise AssertionError("runner must not be called")

    assert main([], golden_runner=runner) == 0
