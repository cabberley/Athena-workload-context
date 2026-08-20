from __future__ import annotations

import base64
import json
import os
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

import athena_context.cli as cli_module
import athena_context.operational_phase_job as phase_job_module
from athena_context.api import PublishedContextSelection
from athena_context.cli import main
from athena_context.contracts import (
    OperationalPhaseConfiguration,
    OperationalPhaseConfigurations,
    OperationalPhaseInputs,
    OperationalPhaseReferenceHandoff,
    VersionPinnedBlobReference,
    build_operational_phase_delivery_bundle,
    build_operational_phase_reference_handoff,
    canonicalize_json,
    compute_artifact_digest,
)
from athena_context.live_acceptance import Wc013LiveAcceptancePlan, wc013_configuration_template
from athena_context.operational_phase_runner import OperationalPhaseRunnerError
from wc013_support import build_harness

SYNTHETIC_KEY_ID = "synthetic-key://athena-argus-demo/rs256-v1"
RUN_ID = "synthetic-run-001"


def _model_digest(model: BaseModel) -> str:
    return compute_artifact_digest(
        model.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def _plan(
    *,
    attempt_id: str,
    snapshot_id: str,
    idempotency_key: str,
) -> Wc013LiveAcceptancePlan:
    template = json.loads(wc013_configuration_template())
    command = build_harness().command.model_copy(
        update={
            "attempt_id": attempt_id,
            "snapshot_id": snapshot_id,
        }
    )
    selection = PublishedContextSelection(
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
    )
    return Wc013LiveAcceptancePlan.model_validate_json(
        json.dumps(
            {
                "wc008_deployment_assertion_file": "wc008-deployment-assertion.json",
                "wc008_operator_approval_file": "wc008-operator-approval.json",
                "wc008_pinned_assertion_digest": "sha256:" + "1" * 64,
                "wc007_authority_file": "wc007-evaluation-authority.json",
                "wc007_authority_approval_file": "wc007-authority-approval.json",
                "wc007_pinned_authority_digest": "sha256:" + "2" * 64,
                "selection": selection.model_dump(mode="json"),
                "context_identity_client_id": (
                    template["deployment"]["context_identity_client_id"]
                ),
                "evidence_identity_client_id": (
                    template["deployment"]["evidence_identity_client_id"]
                ),
                "azure_mcp_audience": template["azure_mcp_audience"],
                "collector_trust": template["collector_trust"],
                "trusted_key": template["trusted_key"],
                "replay": template["replay"],
                "idempotency_key": idempotency_key,
                "evaluation_command": command.model_dump(
                    mode="json",
                    by_alias=True,
                ),
            }
        )
    )


def _configuration(
    *,
    phase: str,
    plan: Wc013LiveAcceptancePlan,
    attempt_id: str,
    snapshot_id: str,
    idempotency_key: str,
) -> OperationalPhaseConfiguration:
    return OperationalPhaseConfiguration(
        phase=phase,
        wc013ConfigurationFile=f"configs/{phase}.json",
        wc013ConfigurationDigest=_model_digest(plan),
        attemptId=attempt_id,
        snapshotId=snapshot_id,
        idempotencyKey=idempotency_key,
    )


def _placeholder_configuration(
    phase: str,
    ordinal: int,
) -> OperationalPhaseConfiguration:
    return OperationalPhaseConfiguration(
        phase=phase,
        wc013ConfigurationFile=f"configs/{phase}.json",
        wc013ConfigurationDigest="sha256:" + f"{ordinal:x}" * 64,
        attemptId=f"attempt-{ordinal:012x}",
        snapshotId=f"snap-{ordinal:012x}",
        idempotencyKey=f"phase-{phase}-{ordinal:03d}",
    )


def _bundle(plan: Wc013LiveAcceptancePlan) -> object:
    return build_operational_phase_delivery_bundle(
        run_id=RUN_ID,
        synthetic_presentation_key_id=SYNTHETIC_KEY_ID,
        configurations=OperationalPhaseConfigurations(
            baseline=_configuration(
                phase="baseline",
                plan=plan,
                attempt_id="attempt-000000000001",
                snapshot_id="snap-000000000001",
                idempotency_key="phase-baseline-001",
            ),
            faulted=_placeholder_configuration("faulted", 2),
            recovered=_placeholder_configuration("recovered", 3),
        ),
    )


def test_phase_job_builds_exact_inputs_and_writes_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(
        attempt_id="attempt-000000000001",
        snapshot_id="snap-000000000001",
        idempotency_key="phase-baseline-001",
    )
    bundle = _bundle(plan)
    bundle_path = tmp_path / "delivery" / "operational-phase-bundle.json"
    config_path = tmp_path / "delivery" / "configs" / "baseline.json"
    bundle_path.parent.mkdir(parents=True)
    config_path.parent.mkdir(parents=True)
    bundle_path.write_text(bundle.canonical_json(), encoding="utf-8")
    config_path.write_text(
        canonicalize_json(
            plan.model_dump(mode="json", by_alias=True, exclude_none=True)
        ),
        encoding="utf-8",
    )

    receipt_reference = VersionPinnedBlobReference(
        name=f"runs/{RUN_ID}/inputs/baseline/fault-receipt.json",
        version="version-0001",
        contentDigest="sha256:" + "3" * 64,
    )
    completion_index_reference = VersionPinnedBlobReference(
        name=f"runs/{RUN_ID}/baseline/phase-completion-index.json",
        version="version-0002",
        contentDigest="sha256:" + "4" * 64,
    )
    prepared = SimpleNamespace(
        plan=plan,
        trusted_key_anchor="trusted-anchor",
        trusted_key_record="trusted-record",
    )
    expected_environment = phase_job_module._wc013_runtime_environment(prepared)  # noqa: SLF001
    observed: dict[str, object] = {}

    class _FakeBlobWriter:
        def __init__(
            self,
            *,
            blob_endpoint: str,
            container_name: str,
            managed_identity_client_id: str,
        ) -> None:
            observed["writer"] = (
                blob_endpoint,
                container_name,
                managed_identity_client_id,
            )

        def create(self, _request: object) -> object:
            raise AssertionError("run_operational_phase owns artifact writes")

    class _FakeBlobReader:
        def __init__(
            self,
            *,
            blob_endpoint: str,
            container_name: str,
            managed_identity_client_id: str,
        ) -> None:
            observed["reader"] = (
                blob_endpoint,
                container_name,
                managed_identity_client_id,
            )

        def read(self, _request: object) -> object:
            raise AssertionError("run_operational_phase owns exact input reads")

    class _FakeSigner:
        def __init__(
            self,
            *,
            trusted_key_anchor: object,
            managed_identity_client_id: str,
        ) -> None:
            observed["signer"] = (
                trusted_key_anchor,
                managed_identity_client_id,
            )

        def sign_preimage(self, canonical_preimage: bytes) -> str:
            return base64.b64encode(canonical_preimage).decode("ascii")

    def fake_prepare(
        supplied_plan: Wc013LiveAcceptancePlan,
        *,
        plan_path: Path,
    ) -> object:
        assert supplied_plan == plan
        assert plan_path == config_path.resolve(strict=True)
        return prepared

    def fake_run_prepared(supplied_prepared: object) -> object:
        assert supplied_prepared is prepared
        observed["runtime_environment"] = {
            name: os.getenv(name) for name in expected_environment
        }
        return SimpleNamespace(result=None, snapshot_path=None)

    def fake_run_operational_phase(
        *,
        bundle_path: Path,
        inputs_path: Path,
        phase_selector: str,
        artifact_writer: object,
        input_reader: object,
        completion_index_writer: object,
        result_verifier: object,
        snapshot_verifier: object,
        signer: object,
        wc013_runner: object,
    ) -> object:
        assert bundle_path == bundle_path_expected
        assert phase_selector == "baseline"
        assert artifact_writer is completion_index_writer
        assert callable(result_verifier)
        assert callable(snapshot_verifier)
        assert signer is not None
        assert input_reader is not None
        generated_inputs = OperationalPhaseInputs.model_validate_json(
            inputs_path.read_text(encoding="utf-8")
        )
        observed["inputs"] = generated_inputs
        assert generated_inputs.receipt == receipt_reference
        assert generated_inputs.phase == "baseline"
        assert generated_inputs.run_id == RUN_ID
        assert generated_inputs.bundle_digest == bundle.bundle_digest
        cast_runner = wc013_runner
        cast_runner(plan, config_path.resolve(strict=True))
        return SimpleNamespace(
            run_id=RUN_ID,
            phase="baseline",
            snapshot_id="snap-000000000001",
            result_digest="sha256:" + "5" * 64,
            presentation_digest="sha256:" + "6" * 64,
            completion_index_digest="sha256:" + "7" * 64,
            completion_index=SimpleNamespace(bundle_digest=bundle.bundle_digest),
            completion_index_reference=completion_index_reference,
        )

    bundle_path_expected = bundle_path
    monkeypatch.setenv("AZURE_CLIENT_ID", "outer-client-id")
    monkeypatch.setenv("ATHENA_WC013_AZURE_MCP_AUDIENCE", "outer-audience")
    monkeypatch.setattr(
        phase_job_module,
        "AzureBlobCreateOnlyArtifactWriter",
        _FakeBlobWriter,
    )
    monkeypatch.setattr(
        phase_job_module,
        "AzureBlobVersionPinnedArtifactReader",
        _FakeBlobReader,
    )
    monkeypatch.setattr(phase_job_module, "KeyVaultRsaSigner", _FakeSigner)
    monkeypatch.setattr(
        phase_job_module,
        "prepare_wc013_live_acceptance_plan",
        fake_prepare,
    )
    monkeypatch.setattr(
        phase_job_module,
        "run_prepared_wc013_live_acceptance",
        fake_run_prepared,
    )
    monkeypatch.setattr(
        phase_job_module,
        "run_operational_phase",
        fake_run_operational_phase,
    )

    result = phase_job_module.run_operational_phase_job(
        bundle_path=bundle_path,
        phase_selector="baseline",
        inputs_output_path=tmp_path / "runtime" / "baseline-inputs.json",
        handoff_output_path=tmp_path / "runtime" / "baseline-handoff.json",
        artifact_blob_endpoint="https://athenareplay.blob.core.windows.net",
        artifact_container_name="operational-artifacts",
        environment={
            "ATHENA_OPERATIONAL_RECEIPT_NAME": receipt_reference.name,
            "ATHENA_OPERATIONAL_RECEIPT_VERSION": receipt_reference.version,
            "ATHENA_OPERATIONAL_RECEIPT_DIGEST": (
                receipt_reference.content_digest
            ),
        },
    )

    assert observed["writer"] == (
        "https://athenareplay.blob.core.windows.net",
        "operational-artifacts",
        plan.context_identity_client_id,
    )
    assert observed["reader"] == observed["writer"]
    assert observed["signer"] == (
        prepared.trusted_key_anchor,
        plan.context_identity_client_id,
    )
    assert observed["runtime_environment"] == expected_environment
    assert os.getenv("AZURE_CLIENT_ID") == "outer-client-id"
    assert os.getenv("ATHENA_WC013_AZURE_MCP_AUDIENCE") == "outer-audience"

    handoff_path = tmp_path / "runtime" / "baseline-handoff.json"
    handoff = OperationalPhaseReferenceHandoff.model_validate_json(
        handoff_path.read_text(encoding="utf-8")
    )
    assert handoff == build_operational_phase_reference_handoff(
        run_id=RUN_ID,
        phase="baseline",
        bundle_digest=bundle.bundle_digest,
        completion_index=completion_index_reference,
    )
    assert result.handoff == handoff


def test_phase_job_environment_requires_exact_reference_sets() -> None:
    plan = _plan(
        attempt_id="attempt-000000000001",
        snapshot_id="snap-000000000001",
        idempotency_key="phase-baseline-001",
    )
    bundle = _bundle(plan)

    with pytest.raises(
        OperationalPhaseRunnerError,
        match="ATHENA_OPERATIONAL_RECEIPT_NAME",
    ):
        phase_job_module._phase_inputs_from_environment(  # noqa: SLF001
            bundle=bundle,
            phase="baseline",
            environment={},
        )

    with pytest.raises(
        OperationalPhaseRunnerError,
        match="valid exact phase input set",
    ):
        phase_job_module._phase_inputs_from_environment(  # noqa: SLF001
            bundle=bundle,
            phase="faulted",
            environment={
                "ATHENA_OPERATIONAL_RECEIPT_NAME": (
                    f"runs/{RUN_ID}/inputs/faulted/fault-receipt.json"
                ),
                "ATHENA_OPERATIONAL_RECEIPT_VERSION": "version-0001",
                "ATHENA_OPERATIONAL_RECEIPT_DIGEST": "sha256:" + "8" * 64,
            },
        )


def test_cli_operational_phase_job_emits_base64_handoff_without_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handoff = build_operational_phase_reference_handoff(
        run_id=RUN_ID,
        phase="baseline",
        bundle_digest="sha256:" + "9" * 64,
        completion_index=VersionPinnedBlobReference(
            name=f"runs/{RUN_ID}/baseline/phase-completion-index.json",
            version="version-0003",
            contentDigest="sha256:" + "a" * 64,
        ),
    )
    job = SimpleNamespace(
        completed=SimpleNamespace(
            run_id=RUN_ID,
            phase="baseline",
            snapshot_id="snap-000000000001",
            result_digest="sha256:" + "b" * 64,
            presentation_digest="sha256:" + "c" * 64,
            completion_index_digest="sha256:" + "d" * 64,
        ),
        handoff=handoff,
        handoff_base64=lambda: base64.b64encode(
            (handoff.canonical_json() + "\n").encode("utf-8")
        ).decode("ascii"),
    )
    monkeypatch.setattr(cli_module, "run_operational_phase_job", lambda **_kwargs: job)

    stdout = StringIO()
    stderr = StringIO()
    exit_code = main(
        [
            "operational-phase-job",
            "--bundle",
            str(tmp_path / "sensitive-bundle.json"),
            "--phase",
            "baseline",
            "--inputs-output",
            str(tmp_path / "sensitive-inputs.json"),
            "--handoff-output",
            str(tmp_path / "sensitive-handoff.json"),
            "--artifact-blob-endpoint",
            "https://athenareplay.blob.core.windows.net",
            "--artifact-container",
            "operational-artifacts",
            "--emit-handoff-base64",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert "sensitive-" not in stdout.getvalue()
    handoff_line = next(
        line
        for line in stdout.getvalue().splitlines()
        if line.startswith(phase_job_module.HANDOFF_BASE64_PREFIX)
    )
    encoded = handoff_line.removeprefix(phase_job_module.HANDOFF_BASE64_PREFIX)
    assert (
        OperationalPhaseReferenceHandoff.model_validate_json(
            base64.b64decode(encoded).decode("utf-8")
        )
        == handoff
    )


def test_cli_operational_phase_job_redacts_paths_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_kwargs: object) -> object:
        raise OperationalPhaseRunnerError("synthetic failure")

    monkeypatch.setattr(cli_module, "run_operational_phase_job", fail)
    stderr = StringIO()

    exit_code = main(
        [
            "operational-phase-job",
            "--bundle",
            str(tmp_path / "sensitive-bundle.json"),
            "--phase",
            "baseline",
            "--inputs-output",
            str(tmp_path / "sensitive-inputs.json"),
            "--handoff-output",
            str(tmp_path / "sensitive-handoff.json"),
            "--artifact-blob-endpoint",
            "https://athenareplay.blob.core.windows.net",
            "--artifact-container",
            "operational-artifacts",
        ],
        stderr=stderr,
    )

    assert exit_code == 1
    assert stderr.getvalue() == "operational phase job failed: synthetic failure\n"
    assert "sensitive-" not in stderr.getvalue()
