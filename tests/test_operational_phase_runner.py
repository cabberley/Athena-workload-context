from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
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
    ArgusPresentationPhase,
    ClauseScope,
    DemoFaultRunReceipt,
    EvidenceSnapshot,
    ManifestFinding,
    OperationalPhaseConfiguration,
    OperationalPhaseConfigurations,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseInputs,
    OperationalPhaseSelector,
    ResourceEvidenceRecord,
    VersionPinnedBlobReference,
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
    OperationalPhaseRunResult,
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
RUN_ID = "synthetic-run-001"
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


class InMemoryVersionPinnedArtifactPlane:
    def __init__(self) -> None:
        self._content: dict[tuple[str, str], bytes] = {}
        self._names: set[str] = set()
        self._version = 0
        self.events: list[tuple[str, tuple[str, ...]]] = []

    def seed(
        self,
        *,
        name: str,
        content: bytes,
        version: str | None = None,
    ) -> VersionPinnedBlobReference:
        selected_version = version or self._next_version()
        self._content[(name, selected_version)] = content
        self._names.add(name)
        return VersionPinnedBlobReference(
            name=name,
            version=selected_version,
            contentDigest=sha256_hex(content),
        )

    def _next_version(self) -> str:
        self._version += 1
        return f"version-{self._version:04d}"

    def _read(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._content[(reference.name, reference.version)]

    def read_receipt(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes:
        return self._read(reference)

    def read_completion_index(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes:
        return self._read(reference)

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> tuple[VersionPinnedBlobReference, ...]:
        self.events.append(
            ("artifacts", tuple(artifact.name for artifact in artifacts))
        )
        if any(artifact.name in self._names for artifact in artifacts):
            raise FileExistsError("artifact name already exists")
        return tuple(
            self.seed(
                name=artifact.name,
                content=artifact.content,
            )
            for artifact in artifacts
        )

    def create_completion_index(
        self,
        artifact: CreateOnlyArtifact,
    ) -> VersionPinnedBlobReference:
        self.events.append(("index", (artifact.name,)))
        if artifact.name in self._names:
            raise FileExistsError("completion index already exists")
        return self.seed(
            name=artifact.name,
            content=artifact.content,
        )

    def content(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._read(reference)


@dataclass(frozen=True, slots=True)
class PhaseSource:
    phase: ArgusPresentationPhase
    harness: DemoHarness
    command: DemoEvaluationCommand
    result: DemoEvaluationResult
    plan: Wc013LiveAcceptancePlan
    receipt: DemoFaultRunReceipt
    idempotency_key: str


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
    attempt_id: str,
    snapshot_id: str,
    idempotency_key: str,
) -> tuple[DemoHarness, DemoEvaluationCommand, DemoEvaluationResult]:
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
    command = harness.command.model_copy(
        update={
            "attempt_id": attempt_id,
            "snapshot_id": snapshot_id,
        }
    )
    source = harness.service.evaluate(
        PUBLISHER,
        idempotency_key,
        command,
    )
    return (
        harness,
        command,
        _result_with_operational_finding(source, verdict=verdict),
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
    started_at: datetime,
    completed_at: datetime,
    fault_run_id: str = "operator-run:001",
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
    return DemoFaultRunReceipt(
        schemaVersion="athena.demoFaultRun.v1",
        faultRunId=fault_run_id,
        faultKind="web-node-power-state",
        action=action,
        resourceGroup=_resource_group(target.resource_id),
        prefix=target_name.rsplit("-", 1)[0],
        targetVmName=target_name,
        targetVmResourceId=target.resource_id,
        eligibleWebVmNames=eligible_names,
        beforePowerState=before_state,
        afterPowerState=after_state,
        startedAt=started_at,
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


def _phase_source(
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: ArgusPresentationPhase,
    states: tuple[str, ...],
    verdict: FindingVerdict,
    ordinal: int,
    started_seconds_before_snapshot: int,
    completed_seconds_before_snapshot: int,
) -> PhaseSource:
    attempt_id = f"attempt-{ordinal:012x}"
    snapshot_id = f"snap-{ordinal:012x}"
    idempotency_key = f"phase-{phase}-{ordinal:03d}"
    harness, command, result = _build_source(
        monkeypatch,
        web_states=states,
        verdict=verdict,
        attempt_id=attempt_id,
        snapshot_id=snapshot_id,
        idempotency_key=idempotency_key,
    )
    return PhaseSource(
        phase=phase,
        harness=harness,
        command=command,
        result=result,
        plan=_plan(command, idempotency_key=idempotency_key),
        receipt=_receipt(
            result,
            phase=phase,
            started_at=(
                result.snapshot.collected_at
                - timedelta(seconds=started_seconds_before_snapshot)
            ),
            completed_at=(
                result.snapshot.collected_at
                - timedelta(seconds=completed_seconds_before_snapshot)
            ),
        ),
        idempotency_key=idempotency_key,
    )


def _configuration(
    source: PhaseSource,
) -> OperationalPhaseConfiguration:
    return OperationalPhaseConfiguration(
        phase=source.phase,
        wc013ConfigurationFile=f"configs/{source.phase}.json",
        wc013ConfigurationDigest=_model_digest(source.plan),
        attemptId=source.command.attempt_id,
        snapshotId=source.command.snapshot_id,
        idempotencyKey=source.idempotency_key,
    )


def _placeholder_configuration(
    phase: ArgusPresentationPhase,
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


def _bundle(
    *,
    run_id: str,
    configurations: dict[str, OperationalPhaseConfiguration],
) -> OperationalPhaseDeliveryBundle:
    return build_operational_phase_delivery_bundle(
        run_id=run_id,
        synthetic_presentation_key_id=SYNTHETIC_KEY_ID,
        configurations=OperationalPhaseConfigurations(
            baseline=configurations["baseline"],
            faulted=configurations["faulted"],
            recovered=configurations["recovered"],
        ),
    )


def _write_bundle(
    tmp_path: Path,
    bundle: OperationalPhaseDeliveryBundle,
) -> Path:
    path = tmp_path / f"{bundle.run_id}-bundle.json"
    path.write_text(bundle.canonical_json(), encoding="utf-8")
    return path


def _write_plan(tmp_path: Path, source: PhaseSource) -> Path:
    path = tmp_path / "configs" / f"{source.phase}.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        canonicalize_json(
            source.plan.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        ),
        encoding="utf-8",
    )
    return path


def _receipt_name(
    run_id: str,
    phase: ArgusPresentationPhase,
) -> str:
    return f"runs/{run_id}/inputs/{phase}/fault-receipt.json"


def _write_inputs(
    tmp_path: Path,
    inputs: OperationalPhaseInputs,
) -> Path:
    path = tmp_path / f"{inputs.run_id}-{inputs.phase}-inputs.json"
    path.write_text(inputs.canonical_json(), encoding="utf-8")
    return path


def _seed_receipt(
    store: InMemoryVersionPinnedArtifactPlane,
    *,
    run_id: str,
    source: PhaseSource,
) -> VersionPinnedBlobReference:
    return store.seed(
        name=_receipt_name(run_id, source.phase),
        content=(source.receipt.canonical_json() + "\n").encode("utf-8"),
    )


def _run(
    *,
    bundle_path: Path,
    inputs_path: Path,
    source: PhaseSource,
    store: InMemoryVersionPinnedArtifactPlane,
) -> OperationalPhaseRunResult:
    return run_operational_phase(
        bundle_path=bundle_path,
        inputs_path=inputs_path,
        phase_selector=source.phase,
        artifact_writer=store,
        input_reader=store,
        completion_index_writer=store,
        result_verifier=lambda supplied: supplied,
        snapshot_verifier=_snapshot_verifier(source.harness),
        signer=DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY),
        wc013_runner=lambda plan, _path: (
            Wc013LiveAcceptanceResult(
                result=source.result,
                snapshot_path=None,
            )
            if plan.evaluation_command.snapshot_id
            == source.result.snapshot.snapshot_id
            else pytest.fail("runner selected an unreviewed plan")
        ),
    )


def test_bundle_schema_has_run_id_and_no_receipt_dependencies() -> None:
    schema = OperationalPhaseDeliveryBundle.model_json_schema()
    assert schema["additionalProperties"] is False
    assert "runId" in schema["required"]
    configuration_schema = schema["$defs"]["OperationalPhaseConfiguration"]
    assert "faultReceiptFile" not in configuration_schema["properties"]
    assert "faultReceiptDigest" not in configuration_schema["properties"]


def test_selector_and_replay_identities_remain_closed() -> None:
    with pytest.raises(ValidationError, match="not allowlisted"):
        OperationalPhaseSelector(phase="reset")
    configurations = {
        "baseline": _placeholder_configuration("baseline", 1),
        "faulted": _placeholder_configuration("faulted", 2),
        "recovered": _placeholder_configuration("recovered", 3),
    }
    configurations["faulted"] = configurations["faulted"].model_copy(
        update={
            "attempt_id": configurations["baseline"].attempt_id,
        }
    )
    with pytest.raises(ValidationError, match="must be unique"):
        _bundle(run_id=RUN_ID, configurations=configurations)


def test_lineage_digest_normalizes_case_equivalent_vm_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _phase_source(
        monkeypatch,
        phase="baseline",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=1,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    lower_names = list(source.receipt.eligible_web_vm_names)
    payload = source.receipt.model_dump(mode="python", by_alias=True)
    payload["eligibleWebVmNames"] = (
        lower_names[1].upper(),
        lower_names[0],
        *lower_names[2:],
    )
    case_variant = DemoFaultRunReceipt.model_validate(payload)
    assert phase_runner_module._fault_lineage_digest(  # noqa: SLF001
        source.receipt
    ) == phase_runner_module._fault_lineage_digest(case_variant)  # noqa: SLF001


def test_baseline_runs_without_future_receipts_or_config_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _phase_source(
        monkeypatch,
        phase="baseline",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=1,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    bundle = _bundle(
        run_id=RUN_ID,
        configurations={
            "baseline": _configuration(baseline),
            "faulted": _placeholder_configuration("faulted", 2),
            "recovered": _placeholder_configuration("recovered", 3),
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    _write_plan(tmp_path, baseline)
    store = InMemoryVersionPinnedArtifactPlane()
    receipt_reference = _seed_receipt(
        store,
        run_id=RUN_ID,
        source=baseline,
    )
    inputs_path = _write_inputs(
        tmp_path,
        OperationalPhaseInputs(
            schemaVersion="athena.operationalPhaseInputs.v1",
            runId=RUN_ID,
            bundleDigest=bundle.bundle_digest,
            phase="baseline",
            receipt=receipt_reference,
        ),
    )

    completed = _run(
        bundle_path=bundle_path,
        inputs_path=inputs_path,
        source=baseline,
        store=store,
    )

    assert completed.phase == "baseline"
    assert completed.run_id == RUN_ID
    assert store.events[0][0] == "artifacts"
    assert store.events[1][0] == "index"
    assert all(
        name.startswith(f"runs/{RUN_ID}/baseline/")
        for name in (*store.events[0][1], *store.events[1][1])
    )


def test_progressive_indexes_bind_lineage_chronology_and_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _phase_source(
        monkeypatch,
        phase="baseline",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=1,
        started_seconds_before_snapshot=6,
        completed_seconds_before_snapshot=5,
    )
    faulted = _phase_source(
        monkeypatch,
        phase="faulted",
        states=("stopped", "running", "running"),
        verdict="observation",
        ordinal=2,
        started_seconds_before_snapshot=4,
        completed_seconds_before_snapshot=3,
    )
    recovered = _phase_source(
        monkeypatch,
        phase="recovered",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=3,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    bundle = _bundle(
        run_id=RUN_ID,
        configurations={
            phase.phase: _configuration(phase)
            for phase in (baseline, faulted, recovered)
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    for source in (baseline, faulted, recovered):
        _write_plan(tmp_path, source)
    store = InMemoryVersionPinnedArtifactPlane()
    receipt_references = {
        source.phase: _seed_receipt(
            store,
            run_id=RUN_ID,
            source=source,
        )
        for source in (baseline, faulted, recovered)
    }

    baseline_result = _run(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="baseline",
                receipt=receipt_references["baseline"],
            ),
        ),
        source=baseline,
        store=store,
    )
    faulted_result = _run(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="faulted",
                receipt=receipt_references["faulted"],
                previousPhaseIndex=(
                    baseline_result.completion_index_reference
                ),
            ),
        ),
        source=faulted,
        store=store,
    )
    recovered_result = _run(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="recovered",
                receipt=receipt_references["recovered"],
                previousPhaseIndex=(
                    faulted_result.completion_index_reference
                ),
            ),
        ),
        source=recovered,
        store=store,
    )

    assert faulted_result.completion_index.previous_phase_index_digest == (
        baseline_result.completion_index.index_digest
    )
    assert recovered_result.completion_index.previous_phase_index_digest == (
        faulted_result.completion_index.index_digest
    )
    assert {
        baseline_result.completion_index.lineage_digest,
        faulted_result.completion_index.lineage_digest,
        recovered_result.completion_index.lineage_digest,
    } == {baseline_result.completion_index.lineage_digest}
    assert all(
        artifact.version.startswith("version-")
        and artifact.content_digest.startswith("sha256:")
        for artifact in recovered_result.completion_index.artifacts
    )
    serialized = recovered_result.completion_index.canonical_json()
    for unsafe in (
        recovered.receipt.resource_group,
        recovered.receipt.target_vm_name,
        recovered.receipt.target_vm_resource_id,
        recovered.receipt.fault_run_id,
    ):
        assert unsafe not in serialized
    assert [event[0] for event in store.events] == [
        "artifacts",
        "index",
        "artifacts",
        "index",
        "artifacts",
        "index",
    ]


def test_faulted_accepts_exact_lineage_reference_without_baseline_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    faulted = _phase_source(
        monkeypatch,
        phase="faulted",
        states=("stopped", "running", "running"),
        verdict="observation",
        ordinal=2,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    bundle = _bundle(
        run_id=RUN_ID,
        configurations={
            "baseline": _placeholder_configuration("baseline", 1),
            "faulted": _configuration(faulted),
            "recovered": _placeholder_configuration("recovered", 3),
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    _write_plan(tmp_path, faulted)
    store = InMemoryVersionPinnedArtifactPlane()
    receipt_reference = _seed_receipt(
        store,
        run_id=RUN_ID,
        source=faulted,
    )
    lineage_digest = compute_artifact_digest(
        {
            "scenarioId": "athena-web-node-fault.v1",
            "faultRunId": faulted.receipt.fault_run_id,
            "faultKind": faulted.receipt.fault_kind,
            "resourceGroup": faulted.receipt.resource_group.casefold(),
            "prefix": faulted.receipt.prefix.casefold(),
            "targetVmName": faulted.receipt.target_vm_name.casefold(),
            "targetVmResourceId": (
                faulted.receipt.target_vm_resource_id.casefold()
            ),
            "eligibleWebVmNames": [
                name.casefold()
                for name in faulted.receipt.eligible_web_vm_names
            ],
        }
    )
    completed = _run(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="faulted",
                receipt=receipt_reference,
                lineageReferenceDigest=lineage_digest,
            ),
        ),
        source=faulted,
        store=store,
    )
    assert completed.completion_index.previous_phase_index is None
    assert completed.completion_index.lineage_digest == lineage_digest


def test_distinct_run_ids_create_repeatable_disjoint_namespaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _phase_source(
        monkeypatch,
        phase="baseline",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=1,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    store = InMemoryVersionPinnedArtifactPlane()
    output_names: list[set[str]] = []
    for run_id in ("synthetic-run-001", "synthetic-run-002"):
        run_root = tmp_path / run_id
        run_root.mkdir()
        bundle = _bundle(
            run_id=run_id,
            configurations={
                "baseline": _configuration(baseline),
                "faulted": _placeholder_configuration("faulted", 2),
                "recovered": _placeholder_configuration("recovered", 3),
            },
        )
        bundle_path = _write_bundle(run_root, bundle)
        _write_plan(run_root, baseline)
        receipt_reference = _seed_receipt(
            store,
            run_id=run_id,
            source=baseline,
        )
        completed = _run(
            bundle_path=bundle_path,
            inputs_path=_write_inputs(
                run_root,
                OperationalPhaseInputs(
                    schemaVersion="athena.operationalPhaseInputs.v1",
                    runId=run_id,
                    bundleDigest=bundle.bundle_digest,
                    phase="baseline",
                    receipt=receipt_reference,
                ),
            ),
            source=baseline,
            store=store,
        )
        output_names.append(
            {
                artifact.name for artifact in completed.artifacts
            }
            | {completed.completion_index_reference.name}
        )
    assert output_names[0].isdisjoint(output_names[1])
    assert all(
        name.startswith("runs/synthetic-run-001/")
        for name in output_names[0]
    )
    assert all(
        name.startswith("runs/synthetic-run-002/")
        for name in output_names[1]
    )


def test_recovered_rejects_missing_prior_index() -> None:
    reference = VersionPinnedBlobReference(
        name=f"runs/{RUN_ID}/inputs/recovered/fault-receipt.json",
        version="version-0001",
        contentDigest="sha256:" + "1" * 64,
    )
    with pytest.raises(ValidationError, match="faulted completion index"):
        OperationalPhaseInputs(
            schemaVersion="athena.operationalPhaseInputs.v1",
            runId=RUN_ID,
            bundleDigest="sha256:" + "2" * 64,
            phase="recovered",
            receipt=reference,
        )


def test_recovered_rejects_different_target_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    faulted = _phase_source(
        monkeypatch,
        phase="faulted",
        states=("stopped", "running", "running"),
        verdict="observation",
        ordinal=2,
        started_seconds_before_snapshot=4,
        completed_seconds_before_snapshot=3,
    )
    recovered = _phase_source(
        monkeypatch,
        phase="recovered",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=3,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    bundle = _bundle(
        run_id=RUN_ID,
        configurations={
            "baseline": _placeholder_configuration("baseline", 1),
            "faulted": _configuration(faulted),
            "recovered": _configuration(recovered),
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    _write_plan(tmp_path, faulted)
    _write_plan(tmp_path, recovered)
    store = InMemoryVersionPinnedArtifactPlane()
    faulted_ref = _seed_receipt(store, run_id=RUN_ID, source=faulted)
    faulted_lineage = compute_artifact_digest(
        {
            "scenarioId": "athena-web-node-fault.v1",
            "faultRunId": faulted.receipt.fault_run_id,
            "faultKind": faulted.receipt.fault_kind,
            "resourceGroup": faulted.receipt.resource_group.casefold(),
            "prefix": faulted.receipt.prefix.casefold(),
            "targetVmName": faulted.receipt.target_vm_name.casefold(),
            "targetVmResourceId": (
                faulted.receipt.target_vm_resource_id.casefold()
            ),
            "eligibleWebVmNames": [
                name.casefold()
                for name in faulted.receipt.eligible_web_vm_names
            ],
        }
    )
    faulted_result = _run(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="faulted",
                receipt=faulted_ref,
                lineageReferenceDigest=faulted_lineage,
            ),
        ),
        source=faulted,
        store=store,
    )
    alternate = _web_records(recovered.result)[1]
    bad_payload = recovered.receipt.model_dump(
        mode="python",
        by_alias=True,
    )
    bad_payload.update(
        {
            "targetVmName": _resource_name(alternate.resource_id),
            "targetVmResourceId": alternate.resource_id,
        }
    )
    bad_receipt = DemoFaultRunReceipt.model_validate(bad_payload)
    bad_reference = store.seed(
        name=_receipt_name(RUN_ID, "recovered"),
        content=(bad_receipt.canonical_json() + "\n").encode("utf-8"),
    )
    inputs_path = _write_inputs(
        tmp_path,
        OperationalPhaseInputs(
            schemaVersion="athena.operationalPhaseInputs.v1",
            runId=RUN_ID,
            bundleDigest=bundle.bundle_digest,
            phase="recovered",
            receipt=bad_reference,
            previousPhaseIndex=(
                faulted_result.completion_index_reference
            ),
        ),
    )
    events_before = tuple(store.events)
    with pytest.raises(
        OperationalPhaseRunnerError,
        match="chronology and target lineage",
    ):
        _run(
            bundle_path=bundle_path,
            inputs_path=inputs_path,
            source=recovered,
            store=store,
        )
    assert tuple(store.events) == events_before


@pytest.mark.parametrize(
    ("missing", "expected"),
    [
        ("reader", "phase input reader is not configured"),
        ("index-writer", "completion index writer is not configured"),
    ],
)
def test_production_composition_hooks_fail_closed(
    tmp_path: Path,
    missing: str,
    expected: str,
) -> None:
    store = InMemoryVersionPinnedArtifactPlane()
    with pytest.raises(OperationalPhaseRunnerError, match=expected):
        run_operational_phase(
            bundle_path=tmp_path / "unread-bundle.json",
            inputs_path=tmp_path / "unread-inputs.json",
            phase_selector="baseline",
            artifact_writer=store,
            input_reader=None if missing == "reader" else store,
            completion_index_writer=(
                None if missing == "index-writer" else store
            ),
            result_verifier=lambda supplied: supplied,
            snapshot_verifier=lambda snapshot, _as_of: snapshot,
            signer=DeterministicPresentationSigner(
                CANONICAL_PRIVATE_KEY
            ),
        )
    assert store.events == []


def test_completion_index_writer_requires_a_valid_immutable_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _phase_source(
        monkeypatch,
        phase="baseline",
        states=("running", "running", "running"),
        verdict="pass",
        ordinal=1,
        started_seconds_before_snapshot=2,
        completed_seconds_before_snapshot=1,
    )
    bundle = _bundle(
        run_id=RUN_ID,
        configurations={
            "baseline": _configuration(baseline),
            "faulted": _placeholder_configuration("faulted", 2),
            "recovered": _placeholder_configuration("recovered", 3),
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    _write_plan(tmp_path, baseline)
    store = InMemoryVersionPinnedArtifactPlane()
    receipt_reference = _seed_receipt(
        store,
        run_id=RUN_ID,
        source=baseline,
    )
    inputs_path = _write_inputs(
        tmp_path,
        OperationalPhaseInputs(
            schemaVersion="athena.operationalPhaseInputs.v1",
            runId=RUN_ID,
            bundleDigest=bundle.bundle_digest,
            phase="baseline",
            receipt=receipt_reference,
        ),
    )

    def invalid_index_version(
        artifact: CreateOnlyArtifact,
    ) -> object:
        store.events.append(("index", (artifact.name,)))
        return SimpleNamespace(
            name=artifact.name,
            version="",
            content_digest=artifact.digest,
        )

    monkeypatch.setattr(
        store,
        "create_completion_index",
        invalid_index_version,
    )
    with pytest.raises(
        OperationalPhaseRunnerError,
        match="invalid version",
    ):
        _run(
            bundle_path=bundle_path,
            inputs_path=inputs_path,
            source=baseline,
            store=store,
        )


def test_cli_fails_closed_without_production_ports_and_logs_no_paths(
    tmp_path: Path,
) -> None:
    stderr = StringIO()
    exit_code = main(
        [
            "operational-phase-runner",
            "--bundle",
            str(tmp_path / "sensitive-bundle-name.json"),
            "--inputs",
            str(tmp_path / "sensitive-input-name.json"),
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
    assert "sensitive-" not in stderr.getvalue()
