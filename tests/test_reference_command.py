from __future__ import annotations

import io
import json
from dataclasses import dataclass

import pytest
from cryptography.exceptions import InvalidSignature

import athena_context.reference_command as reference_command
from athena_context.cli import main
from athena_context.contracts import AthenaValidationError
from athena_context.contracts.manifest import FindingVerdict
from athena_context.golden import GoldenProofMismatchError
from athena_context.reference_command import run_agreed_golden_api

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
    oracle_status: str = "complete"

    def canonical_json(self) -> str:
        return json.dumps(
            {
                "oracleStatus": self.oracle_status,
                "profiles": [profile.to_payload() for profile in self.profiles],
                "snapshotArtifactDigest": self.snapshot_artifact_digest,
                "snapshotSemanticDigest": self.snapshot_semantic_digest,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _result(*, oracle_status: str = "complete") -> _Result:
    return _Result(
        oracle_status=oracle_status,
        profiles=(
            _Profile(
                profile_id="production",
                verdicts=(
                    ("web-zone-distribution", "pass"),
                    ("db-zone-loss-spof", "acceptedResidualRisk"),
                ),
                findings=(
                    _finding("web-zone-distribution", "pass", None),
                    _finding(
                        "db-zone-loss-spof",
                        "acceptedResidualRisk",
                        "ra-db-zone-loss-production",
                    ),
                ),
            ),
            _Profile(
                profile_id="development",
                verdicts=(
                    ("web-zone-distribution", "pass"),
                    ("db-zone-loss-spof", "observation"),
                ),
                findings=(
                    _finding("web-zone-distribution", "pass", None),
                    _finding("db-zone-loss-spof", "observation", None),
                ),
            ),
            _Profile(
                profile_id="training",
                verdicts=(("web-zone-distribution", "pass"),),
                findings=(
                    _finding("web-zone-distribution", "pass", None),
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
    assert payload["oracleStatus"] == "complete"
    assert payload["snapshotArtifactDigest"] == _ARTIFACT_DIGEST
    assert payload["snapshotSemanticDigest"] == _SEMANTIC_DIGEST
    assert payload["profiles"][0]["profileId"] == "production"
    finding = payload["profiles"][0]["findings"][1]
    assert finding["verdict"] == "acceptedResidualRisk"
    assert finding["riskAcceptanceRef"] == "ra-db-zone-loss-production"
    assert finding["evidenceRefs"][0]["itemDigest"] == _ITEM_DIGEST
    assert {
        profile["profileId"]: profile["verdicts"]["web-zone-distribution"]
        for profile in payload["profiles"]
    } == {
        "production": "pass",
        "development": "pass",
        "training": "pass",
    }
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
    assert output.index("Profile: development") < output.index("Profile: production")
    assert output.index("Profile: production") < output.index("Profile: training")
    assert output.index("  db-zone-loss-spof:") < output.index(
        "  web-zone-distribution:"
    )
    assert "acceptedResidualRisk" in output
    assert "residual-risk acceptance: ra-db-zone-loss-production" in output
    assert f"evidenceItem:{_ITEM_DIGEST}@/response/items/0" in output
    assert output.count("web-zone-distribution: pass") == 3


def test_default_adapter_calls_the_agreed_wc005_public_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _result()
    calls = 0

    def runner() -> _Result:
        nonlocal calls
        calls += 1
        return expected

    monkeypatch.setattr(reference_command, "run_golden_proof", runner)
    assert run_agreed_golden_api() is expected
    assert calls == 1


def test_default_adapter_preserves_the_wc005_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mismatch() -> _Result:
        raise GoldenProofMismatchError("oracle differs")

    monkeypatch.setattr(reference_command, "run_golden_proof", mismatch)

    with pytest.raises(GoldenProofMismatchError, match="oracle differs"):
        run_agreed_golden_api()


@pytest.mark.parametrize(
    ("blocking_state", "error_type"),
    [
        ("mismatch", GoldenProofMismatchError),
        ("unknown", GoldenProofMismatchError),
        ("conflicting", GoldenProofMismatchError),
    ],
)
def test_runner_blocking_decision_exits_nonzero(
    blocking_state: str,
    error_type: type[Exception],
) -> None:
    def runner() -> _Result:
        raise error_type(f"{blocking_state} blocks the oracle")

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


def test_pending_oracle_result_exits_nonzero_without_rendering_match() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main(
        ["golden-proof", "--format", "json"],
        golden_runner=lambda: _result(oracle_status="pending"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert "oracle status is pending" in stderr.getvalue()


def test_real_wc005_result_integrates_with_cli_and_final_zone_policy() -> None:
    stdout = io.StringIO()

    exit_code = main(
        ["golden-proof", "--format", "json"],
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert exit_code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["oracleStatus"] == "complete"
    assert payload["pendingDecisions"] == []
    assert {
        profile["profileId"]: profile["verdicts"]["web-zone-distribution"]
        for profile in payload["profiles"]
    } == {
        "production": "pass",
        "development": "pass",
        "training": "pass",
    }


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
