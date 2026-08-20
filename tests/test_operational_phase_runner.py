from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Literal, cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ValidationError

import athena_context.operational_phase_runner as phase_runner_module
import wc013_support
from athena_context.api import PublishedContextSelection
from athena_context.api.evaluation_domain import (
    DemoEvaluationCommand,
    DemoEvaluationResult,
)
from athena_context.cli import main
from athena_context.contracts import (
    ArgusPresentationPayload,
    ArgusPresentationPhase,
    ClauseScope,
    DemoFaultRunReceipt,
    EvidenceSnapshot,
    ManifestFinding,
    OperationalPhaseConfiguration,
    OperationalPhaseConfigurations,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseReceipt,
    OperationalPhaseSelector,
    PresentationAttestation,
    ResourceEvidenceRecord,
    build_operational_phase_delivery_bundle,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.manifest import FindingVerdict
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.live_acceptance import (
    Wc013LiveAcceptancePlan,
    Wc013LiveAcceptanceResult,
    wc013_configuration_template,
)
from athena_context.operational_phase_runner import (
    CreateOnlyArtifact,
    OperationalPhaseRunnerError,
    run_operational_phase,
)
from wc013_support import (
    PUBLISHER,
    DemoHarness,
    build_harness,
    key_anchor,
    key_resolver,
)

SYNTHETIC_KEY_ID = "synthetic-key://athena-argus-demo/rs256-v1"
_ORIGINAL_RESOURCE_ITEMS = wc013_support._golden_resource_items


class DeterministicPresentationSigner:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        signature = self._private_key.sign(
            canonical_preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")


class CapturingCreateOnlyWriter:
    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.artifacts: dict[str, CreateOnlyArtifact] = {}

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> None:
        if self._fail:
            raise RuntimeError("sensitive-writer-payload")
        if any(artifact.name in self.artifacts for artifact in artifacts):
            raise FileExistsError("artifact already exists")
        for artifact in artifacts:
            assert artifact.digest == sha256_hex(artifact.content)
            self.artifacts[artifact.name] = artifact


@dataclass(frozen=True, slots=True)
class PhaseFixture:
    bundle_path: Path
    configuration_path: Path
    harness: DemoHarness
    result: DemoEvaluationResult
    receipt: DemoFaultRunReceipt


def _result_with_operational_finding(
    source: DemoEvaluationResult,
    *,
    verdict: FindingVerdict,
) -> DemoEvaluationResult:
    web_records = [
        record
        for record in source.snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
        and record.tags.workload_role == "web-service"
    ]
    web_digests = {record.item_digest for record in web_records}
    references = tuple(
        sorted(
            (
                reference
                for reference in source.snapshot.evidence_refs
                if getattr(reference, "item_digest", None) in web_digests
            ),
            key=lambda reference: reference.canonical_json(),
        )
    )
    finding = ManifestFinding(
        clauseId="web-service-operational-state",
        findingKind="operationalState",
        verdict=verdict,
        manifestId=source.publication.manifest_id,
        manifestVersion=source.publication.manifest_version,
        profileId=source.publication.profile_id,
        resolvedProfileDigest=source.publication.resolved_profile_digest,
        governanceScope=ClauseScope(
            governanceScopeType="clause",
            manifestId=source.publication.manifest_id,
            profileId=source.publication.profile_id,
            clausePath="/constraints/web-service-operational-state",
            ownerRef="synthetic-operations-owner",
        ),
        evidenceRefs=list(references),
    )
    draft = DemoEvaluationResult.model_construct(
        publication=source.publication,
        snapshot=source.snapshot,
        findings=(finding,),
        evaluated_at=source.evaluated_at,
        citation_count=len(references),
        result_digest="sha256:" + "0" * 64,
    )
    return DemoEvaluationResult(
        publication=source.publication,
        snapshot=source.snapshot,
        findings=(finding,),
        evaluated_at=source.evaluated_at,
        citation_count=len(references),
        result_digest=compute_artifact_digest(draft._digest_payload()),
    )


def _build_source(
    monkeypatch: pytest.MonkeyPatch,
    *,
    web_states: tuple[str, ...],
    verdict: FindingVerdict,
) -> tuple[DemoHarness, DemoEvaluationResult]:
    def resource_items(observed_at: datetime) -> list[dict[str, object]]:
        items = _ORIGINAL_RESOURCE_ITEMS(observed_at)
        web_index = 0
        for item in items:
            tags = item.get("tags")
            if (
                isinstance(tags, dict)
                and tags.get("workloadRole") == "web-service"
            ):
                item["state"] = web_states[web_index]
                web_index += 1
        assert web_index == len(web_states)
        return items

    monkeypatch.setattr(
        wc013_support,
        "_golden_resource_items",
        resource_items,
    )
    harness = build_harness()
    source = harness.service.evaluate(
        PUBLISHER,
        f"phase-{'-'.join(web_states)}",
        harness.command,
    )
    return harness, _result_with_operational_finding(
        source,
        verdict=verdict,
    )


def _snapshot_verifier(
    harness: DemoHarness,
) -> Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]:
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    resolver = key_resolver(public_key)
    anchor = key_anchor(public_key)

    def verify(
        snapshot: EvidenceSnapshot,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        return snapshot.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=(
                snapshot.compatibility.artifact_digest
            ),
            publication_resolver=harness.store.resolve_publication,
            identity_evidence=snapshot.identity_evidence,
            key_resolver=resolver,
            trusted_key_anchor=anchor,
            envelope_resolver=harness.store.resolve_envelope,
        )

    return verify


def _web_records(result: DemoEvaluationResult) -> list[ResourceEvidenceRecord]:
    return [
        record
        for record in result.snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
        and record.tags.workload_role == "web-service"
    ]


def _resource_name(resource_id: str) -> str:
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def _resource_group(resource_id: str) -> str:
    parts = resource_id.strip("/").split("/")
    index = [part.casefold() for part in parts].index("resourcegroups")
    return parts[index + 1]


def _receipt(
    result: DemoEvaluationResult,
    *,
    phase: ArgusPresentationPhase,
) -> DemoFaultRunReceipt:
    web_records = _web_records(result)
    target = next(
        (
            record
            for record in web_records
            if record.state in {"stopped", "deallocated"}
        ),
        web_records[0],
    )
    target_name = _resource_name(target.resource_id)
    eligible_names = tuple(
        sorted(_resource_name(record.resource_id) for record in web_records)
    )
    action: Literal["inject", "status", "reset"]
    before_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ]
    after_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ]
    if phase == "baseline":
        action = "status"
        before_state = "PowerState/running"
        after_state = "PowerState/running"
    elif phase == "faulted":
        action = "inject"
        before_state = "PowerState/running"
        after_state = cast(
            Literal[
                "PowerState/running",
                "PowerState/stopped",
                "PowerState/deallocated",
            ],
            f"PowerState/{target.state}",
        )
    else:
        action = "reset"
        before_state = "PowerState/stopped"
        after_state = "PowerState/running"
    completed_at = result.snapshot.collected_at - timedelta(seconds=1)
    return DemoFaultRunReceipt(
        schemaVersion="athena.demoFaultRun.v1",
        faultRunId="operator-run:001",
        faultKind="web-node-power-state",
        action=action,
        resourceGroup=_resource_group(target.resource_id),
        prefix=target_name.rsplit("-", 1)[0],
        targetVmName=target_name,
        targetVmResourceId=target.resource_id,
        eligibleWebVmNames=eligible_names,
        beforePowerState=before_state,
        afterPowerState=after_state,
        startedAt=completed_at - timedelta(seconds=1),
        completedAt=completed_at,
        outcome="confirmed",
    )


def _plan(
    command: DemoEvaluationCommand,
    *,
    idempotency_key: str,
) -> Wc013LiveAcceptancePlan:
    template = json.loads(wc013_configuration_template())
    selection = PublishedContextSelection(
        manifest_id=command.manifest_id,
        manifest_version=command.manifest_version,
        profile_id=command.profile_id,
    )
    return Wc013LiveAcceptancePlan.model_validate_json(
        json.dumps(
            {
                "wc008_deployment_assertion_file": (
                    "wc008-deployment-assertion.json"
                ),
                "wc008_operator_approval_file": (
                    "wc008-operator-approval.json"
                ),
                "wc008_pinned_assertion_digest": "sha256:" + "1" * 64,
                "wc007_authority_file": "wc007-evaluation-authority.json",
                "wc007_authority_approval_file": (
                    "wc007-authority-approval.json"
                ),
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


def _model_digest(model: BaseModel) -> str:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    )


def _unique_ids(
    selected: str,
    prefix: Literal["attempt", "snap"],
) -> tuple[str, str]:
    candidates = [
        f"{prefix}-{value:012x}"
        for value in range(1, 5)
        if f"{prefix}-{value:012x}" != selected
    ]
    return candidates[0], candidates[1]


def _phase_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: ArgusPresentationPhase,
    web_states: tuple[str, ...],
    verdict: FindingVerdict,
    mismatched_plan_binding: bool = False,
    mismatched_lineage: bool = False,
    mismatched_fault_run: bool = False,
    out_of_order: bool = False,
) -> PhaseFixture:
    harness, result = _build_source(
        monkeypatch,
        web_states=web_states,
        verdict=verdict,
    )
    receipt = _receipt(result, phase=phase)
    selected_command = harness.command
    other_attempts = _unique_ids(selected_command.attempt_id, "attempt")
    other_snapshots = _unique_ids(selected_command.snapshot_id, "snap")
    identifiers: dict[str, tuple[str, str, str]] = {
        phase: (
            selected_command.attempt_id,
            selected_command.snapshot_id,
            f"phase-{phase}-001",
        )
    }
    other_index = 0
    for configured_phase in ("baseline", "faulted", "recovered"):
        if configured_phase == phase:
            continue
        identifiers[configured_phase] = (
            other_attempts[other_index],
            other_snapshots[other_index],
            f"phase-{configured_phase}-001",
        )
        other_index += 1
    selected_attempt, selected_snapshot, selected_idempotency = identifiers[
        phase
    ]
    assert selected_attempt == selected_command.attempt_id
    assert selected_snapshot == selected_command.snapshot_id
    selected_started = receipt.started_at
    selected_completed = receipt.completed_at
    if phase == "baseline":
        phase_times = {
            "baseline": (selected_started, selected_completed),
            "faulted": (
                selected_completed + timedelta(seconds=1),
                selected_completed + timedelta(seconds=2),
            ),
            "recovered": (
                selected_completed + timedelta(seconds=3),
                selected_completed + timedelta(seconds=4),
            ),
        }
    elif phase == "faulted":
        phase_times = {
            "baseline": (
                selected_started - timedelta(seconds=2),
                selected_started - timedelta(seconds=1),
            ),
            "faulted": (selected_started, selected_completed),
            "recovered": (
                selected_completed + timedelta(seconds=1),
                selected_completed + timedelta(seconds=2),
            ),
        }
    else:
        phase_times = {
            "baseline": (
                selected_started - timedelta(seconds=4),
                selected_started - timedelta(seconds=3),
            ),
            "faulted": (
                selected_started - timedelta(seconds=2),
                selected_started - timedelta(seconds=1),
            ),
            "recovered": (selected_started, selected_completed),
        }
    if out_of_order:
        faulted_completed = phase_times["faulted"][1]
        phase_times["recovered"] = (
            faulted_completed - timedelta(seconds=1),
            faulted_completed,
        )
    phase_receipts: dict[str, DemoFaultRunReceipt] = {}
    for configured_phase in ("baseline", "faulted", "recovered"):
        started_at, completed_at = phase_times[configured_phase]
        receipt_payload = receipt.model_dump(mode="python", by_alias=True)
        if configured_phase == "baseline":
            receipt_payload.update(
                {
                    "action": "status",
                    "beforePowerState": "PowerState/running",
                    "afterPowerState": "PowerState/running",
                }
            )
        elif configured_phase == "faulted":
            receipt_payload.update(
                {
                    "action": "inject",
                    "beforePowerState": "PowerState/running",
                    "afterPowerState": "PowerState/stopped",
                }
            )
        else:
            receipt_payload.update(
                {
                    "action": "reset",
                    "beforePowerState": "PowerState/stopped",
                    "afterPowerState": "PowerState/running",
                }
            )
            if mismatched_lineage:
                alternate = next(
                    record
                    for record in _web_records(result)
                    if _resource_name(record.resource_id).casefold()
                    != receipt.target_vm_name.casefold()
                )
                receipt_payload.update(
                    {
                        "targetVmName": _resource_name(
                            alternate.resource_id
                        ),
                        "targetVmResourceId": alternate.resource_id,
                    }
                )
            if mismatched_fault_run:
                receipt_payload["faultRunId"] = "operator-run:other"
        receipt_payload.update(
            {
                "startedAt": started_at,
                "completedAt": completed_at,
            }
        )
        phase_receipts[configured_phase] = (
            DemoFaultRunReceipt.model_validate(receipt_payload)
        )

    configuration_directory = tmp_path / "configs"
    receipt_directory = tmp_path / "receipts"
    configuration_directory.mkdir()
    receipt_directory.mkdir()
    configurations: dict[str, OperationalPhaseConfiguration] = {}
    configuration_paths: dict[str, Path] = {}
    for configured_phase in ("baseline", "faulted", "recovered"):
        attempt_id, snapshot_id, idempotency_key = identifiers[
            configured_phase
        ]
        is_selected = configured_phase == phase
        configured_command = (
            selected_command
            if is_selected
            else selected_command.model_copy(
                update={
                    "attempt_id": attempt_id,
                    "snapshot_id": snapshot_id,
                }
            )
        )
        configured_plan = _plan(
            configured_command,
            idempotency_key=idempotency_key,
        )
        configuration_path = (
            configuration_directory / f"{configured_phase}.json"
        )
        receipt_path = receipt_directory / f"{configured_phase}.json"
        configuration_paths[configured_phase] = configuration_path
        configuration_path.write_text(
            canonicalize_json(
                configured_plan.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ),
            encoding="utf-8",
        )
        receipt_path.write_text(
            phase_receipts[configured_phase].canonical_json(),
            encoding="utf-8",
        )
        configurations[configured_phase] = OperationalPhaseConfiguration(
            phase=cast(ArgusPresentationPhase, configured_phase),
            wc013_configuration_file=(
                f"configs/{configured_phase}.json"
            ),
            wc013_configuration_digest=(
                _model_digest(configured_plan)
            ),
            fault_receipt_file=f"receipts/{configured_phase}.json",
            fault_receipt_digest=(
                _model_digest(phase_receipts[configured_phase])
            ),
            attempt_id=attempt_id,
            snapshot_id=(
                "snap-ffffffffffff"
                if is_selected and mismatched_plan_binding
                else snapshot_id
            ),
            idempotency_key=(
                selected_idempotency
                if is_selected
                else idempotency_key
            ),
        )
    bundle = build_operational_phase_delivery_bundle(
        synthetic_presentation_key_id=SYNTHETIC_KEY_ID,
        configurations=OperationalPhaseConfigurations(
            baseline=configurations["baseline"],
            faulted=configurations["faulted"],
            recovered=configurations["recovered"],
        ),
    )
    bundle_path = tmp_path / "operational-phase-bundle.json"
    bundle_path.write_text(bundle.canonical_json(), encoding="utf-8")
    return PhaseFixture(
        bundle_path=bundle_path,
        configuration_path=configuration_paths[phase],
        harness=harness,
        result=result,
        receipt=phase_receipts[phase],
    )


def test_selector_and_schema_are_closed_allowlists() -> None:
    assert OperationalPhaseSelector(phase="baseline").selected_phase() == "baseline"
    with pytest.raises(ValidationError, match="not allowlisted"):
        OperationalPhaseSelector(phase="fault-reset")

    schema = OperationalPhaseDeliveryBundle.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schemaVersion",
        "scenarioId",
        "allowedPhases",
        "syntheticPresentationKeyId",
        "configurations",
        "bundleDigest",
    }
    configurations_schema = schema["$defs"]["OperationalPhaseConfigurations"]
    assert configurations_schema["additionalProperties"] is False
    assert set(configurations_schema["required"]) == {
        "baseline",
        "faulted",
        "recovered",
    }


@pytest.mark.parametrize(
    "field",
    ["attempt_id", "snapshot_id", "idempotency_key"],
)
def test_bundle_rejects_replay_identity_reuse(field: str) -> None:
    configurations = {
        phase: OperationalPhaseConfiguration(
            phase=cast(ArgusPresentationPhase, phase),
            wc013ConfigurationFile=f"configs/{phase}.json",
            wc013ConfigurationDigest="sha256:" + str(index) * 64,
            faultReceiptFile=f"receipts/{phase}.json",
            faultReceiptDigest="sha256:" + str(index + 3) * 64,
            attemptId=f"attempt-{index:012x}",
            snapshotId=f"snap-{index:012x}",
            idempotencyKey=f"phase-{phase}",
        )
        for index, phase in enumerate(
            ("baseline", "faulted", "recovered"),
            start=1,
        )
    }
    faulted = configurations["faulted"].model_copy(
        update={
            field: getattr(configurations["baseline"], field),
        }
    )
    with pytest.raises(ValidationError, match="must be unique"):
        build_operational_phase_delivery_bundle(
            synthetic_presentation_key_id=SYNTHETIC_KEY_ID,
            configurations=OperationalPhaseConfigurations(
                baseline=configurations["baseline"],
                faulted=faulted,
                recovered=configurations["recovered"],
            ),
        )


def test_bundle_rejects_phase_key_mismatch() -> None:
    configuration = OperationalPhaseConfiguration(
        phase="faulted",
        wc013ConfigurationFile="configs/baseline.json",
        wc013ConfigurationDigest="sha256:" + "1" * 64,
        faultReceiptFile="receipts/baseline.json",
        faultReceiptDigest="sha256:" + "2" * 64,
        attemptId="attempt-000000000001",
        snapshotId="snap-000000000001",
        idempotencyKey="phase-baseline",
    )
    with pytest.raises(ValidationError, match="allowlisted key"):
        OperationalPhaseConfigurations(
            baseline=configuration,
            faulted=configuration,
            recovered=configuration,
        )


@pytest.mark.parametrize(
    ("phase", "states", "verdict"),
    [
        ("baseline", ("running", "running", "running"), "pass"),
        ("faulted", ("stopped", "running", "running"), "observation"),
        ("recovered", ("running", "running", "running"), "pass"),
    ],
)
def test_runner_writes_five_digest_bound_safe_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: ArgusPresentationPhase,
    states: tuple[str, ...],
    verdict: FindingVerdict,
) -> None:
    fixture = _phase_fixture(
        tmp_path,
        monkeypatch,
        phase=phase,
        web_states=states,
        verdict=verdict,
    )
    writer = CapturingCreateOnlyWriter()

    completed = run_operational_phase(
        bundle_path=fixture.bundle_path,
        phase_selector=phase,
        artifact_writer=writer,
        result_verifier=lambda supplied: supplied,
        snapshot_verifier=_snapshot_verifier(fixture.harness),
        signer=DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY),
        wc013_runner=lambda plan, path: (
            Wc013LiveAcceptanceResult(
                result=fixture.result,
                snapshot_path=None,
            )
            if (
                path == fixture.configuration_path.resolve()
                and plan.evaluation_command.snapshot_id
                == fixture.result.snapshot.snapshot_id
            )
            else pytest.fail("runner selected an unreviewed configuration")
        ),
    )

    expected_names = (
        f"operational-demo/{phase}/demo-evaluation-result.json",
        f"operational-demo/{phase}/evidence-snapshot.json",
        f"operational-demo/{phase}/argus-presentation.json",
        f"operational-demo/{phase}/presentation-attestation.json",
        f"operational-demo/{phase}/phase-receipt.json",
    )
    assert tuple(writer.artifacts) == expected_names
    assert tuple(reference.name for reference in completed.artifacts) == expected_names
    assert all(
        reference.digest == writer.artifacts[reference.name].digest
        for reference in completed.artifacts
    )

    presentation = ArgusPresentationPayload.model_validate_json(
        writer.artifacts[expected_names[2]].content
    )
    PresentationAttestation.model_validate_json(
        writer.artifacts[expected_names[3]].content
    )
    receipt = OperationalPhaseReceipt.model_validate_json(
        writer.artifacts[expected_names[4]].content
    )
    assert presentation.phase == phase
    assert receipt.phase == phase
    assert tuple(reference.name for reference in receipt.artifacts) == expected_names[:4]
    assert receipt.presentation_digest == presentation.athena.result_digest
    assert completed.receipt_digest == sha256_hex(
        writer.artifacts[expected_names[4]].content
    )
    serialized_presentation = presentation.canonical_json()
    for unsafe_value in (
        fixture.receipt.resource_group,
        fixture.receipt.fault_run_id,
        fixture.receipt.target_vm_name,
        fixture.receipt.target_vm_resource_id,
        fixture.result.snapshot.snapshot_id,
        fixture.result.publication.manifest_id,
        fixture.result.snapshot.snapshot_attestation.key_vault_key_id,
    ):
        assert unsafe_value not in serialized_presentation


def test_runner_rejects_plan_binding_before_wc013_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _phase_fixture(
        tmp_path,
        monkeypatch,
        phase="baseline",
        web_states=("running", "running", "running"),
        verdict="pass",
        mismatched_plan_binding=True,
    )
    called = False

    def runner(
        _plan: Wc013LiveAcceptancePlan,
        _path: Path,
    ) -> Wc013LiveAcceptanceResult:
        nonlocal called
        called = True
        return Wc013LiveAcceptanceResult(
            result=fixture.result,
            snapshot_path=None,
        )

    with pytest.raises(OperationalPhaseRunnerError, match="does not match"):
        run_operational_phase(
            bundle_path=fixture.bundle_path,
            phase_selector="baseline",
            artifact_writer=CapturingCreateOnlyWriter(),
            result_verifier=lambda supplied: supplied,
            snapshot_verifier=_snapshot_verifier(fixture.harness),
            signer=DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY),
            wc013_runner=runner,
        )
    assert not called


@pytest.mark.parametrize(
    ("failure", "expected_message"),
    [
        ("target", "fault lineage"),
        ("fault-run", "fault lineage"),
        ("chronology", "chronology"),
    ],
)
def test_runner_validates_cross_phase_fault_sequence_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_message: str,
) -> None:
    fixture = _phase_fixture(
        tmp_path,
        monkeypatch,
        phase="recovered",
        web_states=("running", "running", "running"),
        verdict="pass",
        mismatched_lineage=failure == "target",
        mismatched_fault_run=failure == "fault-run",
        out_of_order=failure == "chronology",
    )
    called = False

    def runner(
        _plan: Wc013LiveAcceptancePlan,
        _path: Path,
    ) -> Wc013LiveAcceptanceResult:
        nonlocal called
        called = True
        return Wc013LiveAcceptanceResult(
            result=fixture.result,
            snapshot_path=None,
        )

    with pytest.raises(
        OperationalPhaseRunnerError,
        match=expected_message,
    ):
        run_operational_phase(
            bundle_path=fixture.bundle_path,
            phase_selector="recovered",
            artifact_writer=CapturingCreateOnlyWriter(),
            result_verifier=lambda supplied: supplied,
            snapshot_verifier=_snapshot_verifier(fixture.harness),
            signer=DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY),
            wc013_runner=runner,
        )
    assert not called


def test_default_executor_receives_validated_plan_without_reopening_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _phase_fixture(
        tmp_path,
        monkeypatch,
        phase="baseline",
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    received_snapshot_id: str | None = None

    def execute_validated(
        plan: Wc013LiveAcceptancePlan,
        path: Path,
    ) -> Wc013LiveAcceptanceResult:
        nonlocal received_snapshot_id
        received_snapshot_id = plan.evaluation_command.snapshot_id
        tampered_command = plan.evaluation_command.model_copy(
            update={"snapshot_id": "snap-ffffffffffff"}
        )
        tampered_plan = plan.model_copy(
            update={"evaluation_command": tampered_command}
        )
        path.write_text(
            canonicalize_json(
                tampered_plan.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ),
            encoding="utf-8",
        )
        assert plan.evaluation_command.snapshot_id == (
            fixture.result.snapshot.snapshot_id
        )
        return Wc013LiveAcceptanceResult(
            result=fixture.result,
            snapshot_path=None,
        )

    monkeypatch.setattr(
        phase_runner_module,
        "run_wc013_live_acceptance_plan",
        execute_validated,
    )
    run_operational_phase(
        bundle_path=fixture.bundle_path,
        phase_selector="baseline",
        artifact_writer=CapturingCreateOnlyWriter(),
        result_verifier=lambda supplied: supplied,
        snapshot_verifier=_snapshot_verifier(fixture.harness),
        signer=DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY),
    )
    assert received_snapshot_id == fixture.result.snapshot.snapshot_id


@pytest.mark.parametrize("failure", ["verifier", "signer", "writer"])
def test_runner_failures_write_no_payload_and_hide_port_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    fixture = _phase_fixture(
        tmp_path,
        monkeypatch,
        phase="baseline",
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    writer = CapturingCreateOnlyWriter(fail=failure == "writer")

    class FailingSigner:
        def sign_preimage(self, canonical_preimage: bytes) -> str:
            del canonical_preimage
            raise RuntimeError("sensitive-signer-payload")

    def result_verifier(
        supplied: DemoEvaluationResult,
    ) -> DemoEvaluationResult:
        if failure == "verifier":
            raise RuntimeError("sensitive-verifier-payload")
        return supplied

    with pytest.raises(OperationalPhaseRunnerError) as raised:
        run_operational_phase(
            bundle_path=fixture.bundle_path,
            phase_selector="baseline",
            artifact_writer=writer,
            result_verifier=result_verifier,
            snapshot_verifier=_snapshot_verifier(fixture.harness),
            signer=(
                FailingSigner()
                if failure == "signer"
                else DeterministicPresentationSigner(
                    CANONICAL_PRIVATE_KEY
                )
            ),
            wc013_runner=lambda _plan, _path: Wc013LiveAcceptanceResult(
                result=fixture.result,
                snapshot_path=None,
            ),
        )
    assert not writer.artifacts
    assert "sensitive-" not in str(raised.value)


def test_cli_fails_closed_without_injected_ports_and_logs_no_payload(
    tmp_path: Path,
) -> None:
    stderr = StringIO()
    exit_code = main(
        [
            "operational-phase-runner",
            "--bundle",
            str(tmp_path / "sensitive-bundle-name.json"),
            "--phase",
            "baseline",
        ],
        stderr=stderr,
    )

    assert exit_code == 1
    assert stderr.getvalue() == (
        "operational phase runner failed: "
        "create-only artifact writer is not configured\n"
    )
    assert "sensitive-bundle-name" not in stderr.getvalue()
