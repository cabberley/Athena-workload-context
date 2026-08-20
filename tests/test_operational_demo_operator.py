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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel

import athena_context.operational_demo_operator as operator_module
import wc013_support
from athena_context.api import PublishedContextSelection
from athena_context.api.evaluation_domain import DemoEvaluationCommand, DemoEvaluationResult
from athena_context.artifacts import ArtifactReadRequest, ArtifactReadResult
from athena_context.cli import main
from athena_context.contracts import (
    ArgusPresentationPhase,
    ClauseScope,
    DemoFaultRunReceipt,
    EvidenceSnapshot,
    ManifestFinding,
    OperationalDemoWorkloadActionReport,
    OperationalPhaseCompletionIndex,
    OperationalPhaseConfiguration,
    OperationalPhaseConfigurations,
    OperationalPhaseExecutionRecord,
    OperationalPhaseExecutionRequest,
    OperationalPhaseExecutionState,
    OperationalPhaseExecutionStatus,
    OperationalPhaseInputs,
    OperationalPhaseReferenceHandoff,
    ReceiptAction,
    ResourceEvidenceRecord,
    VersionPinnedBlobReference,
    build_operational_phase_delivery_bundle,
    build_operational_phase_reference_handoff,
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
from athena_context.operational_demo_operator import (
    OperationalDemoOperatorError,
    OperationalDemoOperatorResult,
    WorkloadActionPort,
    build_operational_demo_validation,
    run_operational_demo_operator,
)
from athena_context.operational_phase_runner import (
    CreateOnlyArtifact,
    OperationalPhaseRunResult,
    run_operational_phase,
)
from wc013_support import PUBLISHER, DemoHarness, build_harness

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

    def read_receipt(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._read(reference)

    def read_completion_index(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._read(reference)

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> tuple[VersionPinnedBlobReference, ...]:
        if any(artifact.name in self._names for artifact in artifacts):
            raise FileExistsError("artifact name already exists")
        return tuple(
            self.seed(name=artifact.name, content=artifact.content)
            for artifact in artifacts
        )

    def create_completion_index(
        self,
        artifact: CreateOnlyArtifact,
    ) -> VersionPinnedBlobReference:
        if artifact.name in self._names:
            raise FileExistsError("completion index already exists")
        return self.seed(name=artifact.name, content=artifact.content)

    def content(self, name: str, version: str) -> bytes:
        return self._content[(name, version)]


class InspectableArtifactReader:
    def __init__(self, store: InMemoryVersionPinnedArtifactPlane) -> None:
        self._store = store
        self.requests: list[ArtifactReadRequest] = []

    def read(self, request: ArtifactReadRequest) -> ArtifactReadResult:
        self.requests.append(request)
        payload = self._store.content(request.blob_name, request.version_id)
        return ArtifactReadResult(
            container_name="synthetic-container",
            blob_name=request.blob_name,
            version_id=request.version_id,
            payload=payload,
            size_bytes=len(payload),
            content_type="application/json",
            payload_sha256=request.expected_payload_sha256,
        )


@dataclass(frozen=True, slots=True)
class PhaseSource:
    phase: ArgusPresentationPhase
    harness: DemoHarness
    command: DemoEvaluationCommand
    result: DemoEvaluationResult
    plan: Wc013LiveAcceptancePlan
    receipt: DemoFaultRunReceipt
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class OperatorFixture:
    config_path: Path
    confirmation_phrase: str
    workload_reports: dict[ReceiptAction, OperationalDemoWorkloadActionReport]
    phase_results: dict[ArgusPresentationPhase, OperationalPhaseRunResult]
    handoffs: dict[ArgusPresentationPhase, OperationalPhaseReferenceHandoff]
    reader: InspectableArtifactReader
    store: InMemoryVersionPinnedArtifactPlane


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

    monkeypatch.setattr(wc013_support, "_golden_resource_items", resource_items)
    harness = build_harness()
    command = harness.command.model_copy(
        update={
            "attempt_id": attempt_id,
            "snapshot_id": snapshot_id,
        }
    )
    source = harness.service.evaluate(PUBLISHER, idempotency_key, command)
    return harness, command, _result_with_operational_finding(source, verdict=verdict)


def _snapshot_verifier(
    harness: DemoHarness,
) -> Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]:
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    resolver = wc013_support.key_resolver(public_key)
    anchor = wc013_support.key_anchor(public_key)

    def verify(snapshot: EvidenceSnapshot, as_of: datetime) -> EvidenceSnapshot:
        return snapshot.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=snapshot.compatibility.artifact_digest,
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
                "wc008_deployment_assertion_file": "wc008-deployment-assertion.json",
                "wc008_operator_approval_file": "wc008-operator-approval.json",
                "wc008_pinned_assertion_digest": "sha256:" + "1" * 64,
                "wc007_authority_file": "wc007-evaluation-authority.json",
                "wc007_authority_approval_file": "wc007-authority-approval.json",
                "wc007_pinned_authority_digest": "sha256:" + "2" * 64,
                "selection": selection.model_dump(mode="json"),
                "context_identity_client_id": template["deployment"][
                    "context_identity_client_id"
                ],
                "evidence_identity_client_id": template["deployment"][
                    "evidence_identity_client_id"
                ],
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


def _configuration(source: PhaseSource) -> OperationalPhaseConfiguration:
    return OperationalPhaseConfiguration(
        phase=source.phase,
        wc013ConfigurationFile=f"configs/{source.phase}.json",
        wc013ConfigurationDigest=_model_digest(source.plan),
        attemptId=source.command.attempt_id,
        snapshotId=source.command.snapshot_id,
        idempotencyKey=source.idempotency_key,
    )


def _bundle(
    *,
    run_id: str,
    configurations: dict[str, OperationalPhaseConfiguration],
):
    return build_operational_phase_delivery_bundle(
        run_id=run_id,
        synthetic_presentation_key_id=SYNTHETIC_KEY_ID,
        configurations=OperationalPhaseConfigurations(
            baseline=configurations["baseline"],
            faulted=configurations["faulted"],
            recovered=configurations["recovered"],
        ),
    )


def _write_bundle(tmp_path: Path, bundle: BaseModel) -> Path:
    delivery = tmp_path / "delivery"
    delivery.mkdir(parents=True, exist_ok=True)
    path = delivery / "operational-phase-bundle.json"
    path.write_text(bundle.canonical_json(), encoding="utf-8")
    return path


def _write_plan(bundle_path: Path, source: PhaseSource) -> None:
    path = bundle_path.parent / "configs" / f"{source.phase}.json"
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


def _receipt_name(run_id: str, phase: ArgusPresentationPhase) -> str:
    return f"runs/{run_id}/inputs/{phase}/fault-receipt.json"


def _write_inputs(tmp_path: Path, inputs: OperationalPhaseInputs) -> Path:
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


def _run_phase(
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
            Wc013LiveAcceptanceResult(result=source.result, snapshot_path=None)
            if plan.evaluation_command.snapshot_id == source.result.snapshot.snapshot_id
            else pytest.fail("runner selected an unreviewed plan")
        ),
    )


def _write_public_key(path: Path) -> None:
    encoded = CANONICAL_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(encoded)


def _operator_config(bundle_path: Path) -> dict[str, object]:
    return {
        "schemaVersion": "athena.operationalDemoOperator.v1",
        "scenarioId": "athena-web-node-fault.v1",
        "runId": RUN_ID,
        "bundleFile": "delivery/operational-phase-bundle.json",
        "presentationPublicKeyFile": "presentation-public-key.pem",
        "workloadController": {
            "executable": "synthetic-workload-controller",
            "arguments": ["--reviewed"],
            "timeoutSeconds": 5,
            "maxOutputBytes": 4096,
        },
        "phaseJobController": {
            "executable": "synthetic-phase-controller",
            "arguments": ["--reviewed"],
            "timeoutSeconds": 5,
            "maxOutputBytes": 4096,
            "pollTimeoutSeconds": 3,
            "pollIntervalSeconds": 1,
        },
        "artifactReader": {
            "blobEndpoint": "https://athenareplay.blob.core.windows.net",
            "containerName": "operational-artifacts",
            "managedIdentityClientId": "11111111-1111-1111-1111-111111111111",
        },
    }


def _write_operator_config(tmp_path: Path, bundle_path: Path) -> Path:
    config_path = tmp_path / "operator-config.json"
    config_path.write_text(
        json.dumps(_operator_config(bundle_path), indent=2),
        encoding="utf-8",
    )
    return config_path


def _report(
    *,
    action: ReceiptAction,
    phase: ArgusPresentationPhase,
    receipt: DemoFaultRunReceipt,
    reference: VersionPinnedBlobReference,
) -> OperationalDemoWorkloadActionReport:
    return OperationalDemoWorkloadActionReport(
        schemaVersion="athena.operationalDemoWorkloadAction.v1",
        scenarioId="athena-web-node-fault.v1",
        runId=RUN_ID,
        action=action,
        receipt=receipt,
        receiptReference=reference,
    )


def _build_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> OperatorFixture:
    monkeypatch.setattr(
        operator_module,
        "prepare_wc013_live_acceptance_plan",
        lambda plan, plan_path: object(),
    )
    monkeypatch.setattr(
        operator_module,
        "verify_wc013_live_result",
        lambda prepared, result: None,
    )
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
            "baseline": _configuration(baseline),
            "faulted": _configuration(faulted),
            "recovered": _configuration(recovered),
        },
    )
    bundle_path = _write_bundle(tmp_path, bundle)
    for source in (baseline, faulted, recovered):
        _write_plan(bundle_path, source)
    _write_public_key(tmp_path / "presentation-public-key.pem")
    config_path = _write_operator_config(tmp_path, bundle_path)
    store = InMemoryVersionPinnedArtifactPlane()
    receipt_references = {
        "baseline": _seed_receipt(store, run_id=RUN_ID, source=baseline),
        "faulted": _seed_receipt(store, run_id=RUN_ID, source=faulted),
        "recovered": _seed_receipt(store, run_id=RUN_ID, source=recovered),
    }
    baseline_result = _run_phase(
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
    faulted_result = _run_phase(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="faulted",
                receipt=receipt_references["faulted"],
                previousPhaseIndex=baseline_result.completion_index_reference,
            ),
        ),
        source=faulted,
        store=store,
    )
    recovered_result = _run_phase(
        bundle_path=bundle_path,
        inputs_path=_write_inputs(
            tmp_path,
            OperationalPhaseInputs(
                schemaVersion="athena.operationalPhaseInputs.v1",
                runId=RUN_ID,
                bundleDigest=bundle.bundle_digest,
                phase="recovered",
                receipt=receipt_references["recovered"],
                previousPhaseIndex=faulted_result.completion_index_reference,
            ),
        ),
        source=recovered,
        store=store,
    )
    validation = build_operational_demo_validation(config_path)
    return OperatorFixture(
        config_path=config_path,
        confirmation_phrase=validation.confirmation_phrase,
        workload_reports={
            "status": _report(
                action="status",
                phase="baseline",
                receipt=baseline.receipt,
                reference=receipt_references["baseline"],
            ),
            "inject": _report(
                action="inject",
                phase="faulted",
                receipt=faulted.receipt,
                reference=receipt_references["faulted"],
            ),
            "reset": _report(
                action="reset",
                phase="recovered",
                receipt=recovered.receipt,
                reference=receipt_references["recovered"],
            ),
        },
        phase_results={
            "baseline": baseline_result,
            "faulted": faulted_result,
            "recovered": recovered_result,
        },
        handoffs={
            "baseline": build_operational_phase_reference_handoff(
                run_id=RUN_ID,
                phase="baseline",
                bundle_digest=bundle.bundle_digest,
                completion_index=baseline_result.completion_index_reference,
            ),
            "faulted": build_operational_phase_reference_handoff(
                run_id=RUN_ID,
                phase="faulted",
                bundle_digest=bundle.bundle_digest,
                completion_index=faulted_result.completion_index_reference,
            ),
            "recovered": build_operational_phase_reference_handoff(
                run_id=RUN_ID,
                phase="recovered",
                bundle_digest=bundle.bundle_digest,
                completion_index=recovered_result.completion_index_reference,
            ),
        },
        reader=InspectableArtifactReader(store),
        store=store,
    )


class ScriptedWorkloadPort(WorkloadActionPort):
    def __init__(
        self,
        responses: dict[ReceiptAction, list[object]],
    ) -> None:
        self._responses = responses
        self.events: list[ReceiptAction] = []

    def _take(self, action: ReceiptAction) -> OperationalDemoWorkloadActionReport:
        self.events.append(action)
        selected = self._responses[action].pop(0)
        if isinstance(selected, BaseException):
            raise selected
        return cast(OperationalDemoWorkloadActionReport, selected)

    def status(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        del run_id, scenario_id
        return self._take("status")

    def inject(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        del run_id, scenario_id
        return self._take("inject")

    def reset(
        self,
        *,
        run_id: str,
        scenario_id: str,
    ) -> OperationalDemoWorkloadActionReport:
        del run_id, scenario_id
        return self._take("reset")


@dataclass
class PhasePlan:
    statuses: list[object]
    handoff: object


class ScriptedPhaseController:
    def __init__(self, plans: dict[ArgusPresentationPhase, PhasePlan]) -> None:
        self._plans = plans
        self.events: list[tuple[str, str]] = []
        self.requests: list[OperationalPhaseExecutionRequest] = []

    def start_phase(
        self,
        request: OperationalPhaseExecutionRequest,
    ) -> OperationalPhaseExecutionRecord:
        self.requests.append(request)
        self.events.append(("start", request.phase))
        return OperationalPhaseExecutionRecord(
            schemaVersion="athena.operationalPhaseExecution.v1",
            scenarioId="athena-web-node-fault.v1",
            runId=RUN_ID,
            phase=request.phase,
            executionId=f"execution-{request.phase}",
        )

    def read_status(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseExecutionStatus:
        phase = execution.phase
        self.events.append(("status", phase))
        selected = self._plans[phase].statuses
        item = selected.pop(0) if selected else "running"
        if isinstance(item, BaseException):
            raise item
        return OperationalPhaseExecutionStatus(
            schemaVersion="athena.operationalPhaseExecutionStatus.v1",
            scenarioId="athena-web-node-fault.v1",
            runId=RUN_ID,
            phase=phase,
            executionId=execution.execution_id,
            state=cast(OperationalPhaseExecutionState, item),
        )

    def read_handoff(
        self,
        execution: OperationalPhaseExecutionRecord,
    ) -> OperationalPhaseReferenceHandoff:
        phase = execution.phase
        self.events.append(("handoff", phase))
        selected = self._plans[phase].handoff
        if isinstance(selected, BaseException):
            raise selected
        return cast(OperationalPhaseReferenceHandoff, selected)


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0
        self.sleeps: list[int] = []

    def monotonic(self) -> float:
        return self.current

    def sleep(self, seconds: int) -> None:
        self.sleeps.append(seconds)
        self.current += seconds


def _success_ports(
    fixture: OperatorFixture,
) -> tuple[ScriptedWorkloadPort, ScriptedPhaseController]:
    workload = ScriptedWorkloadPort(
        {
            "status": [fixture.workload_reports["status"]],
            "inject": [fixture.workload_reports["inject"]],
            "reset": [fixture.workload_reports["reset"]],
        }
    )
    controller = ScriptedPhaseController(
        {
            "baseline": PhasePlan(
                statuses=["running", "succeeded"],
                handoff=fixture.handoffs["baseline"],
            ),
            "faulted": PhasePlan(
                statuses=["running", "succeeded"],
                handoff=fixture.handoffs["faulted"],
            ),
            "recovered": PhasePlan(
                statuses=["running", "succeeded"],
                handoff=fixture.handoffs["recovered"],
            ),
        }
    )
    return workload, controller


def _rewrite_completion_index_reference(
    fixture: OperatorFixture,
    phase: ArgusPresentationPhase,
    *,
    updates: dict[str, object],
) -> VersionPinnedBlobReference:
    def _json_safe(value: object) -> object:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json", by_alias=True)
        if isinstance(value, tuple):
            return [_json_safe(item) for item in value]
        return value

    result = fixture.phase_results[phase]
    payload = result.completion_index.model_dump(mode="json", by_alias=True)
    payload.update({key: _json_safe(value) for key, value in updates.items()})
    digest_payload = {key: value for key, value in payload.items() if key != "indexDigest"}
    if isinstance(payload.get("artifacts"), list):
        payload["artifacts"] = tuple(payload["artifacts"])
    payload["indexDigest"] = compute_artifact_digest(
        digest_payload
    )
    model = OperationalPhaseCompletionIndex.model_validate(payload)
    return fixture.store.seed(
        name=result.completion_index_reference.name,
        content=(model.canonical_json() + "\n").encode("utf-8"),
    )


def test_validate_only_is_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        [
            "operational-demo-operator",
            "--config",
            str(fixture.config_path),
            "--validate-only",
        ],
        operational_demo_workload_port=cast(WorkloadActionPort, object()),
        operational_demo_phase_job_port=cast(object, object()),
        operational_demo_handoff_port=cast(object, object()),
        operational_demo_artifact_reader=cast(object, object()),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert "operational demo operator plan valid" in stdout.getvalue()
    assert fixture.confirmation_phrase in stdout.getvalue()


def test_live_mode_requires_exact_confirmation_phrase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload, controller = _success_ports(fixture)
    stderr = StringIO()

    exit_code = main(
        [
            "operational-demo-operator",
            "--config",
            str(fixture.config_path),
        ],
        operational_demo_workload_port=workload,
        operational_demo_phase_job_port=controller,
        operational_demo_handoff_port=controller,
        operational_demo_artifact_reader=fixture.reader,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stderr.getvalue() == (
        "operational demo operator failed: "
        "confirmation phrase did not match the reviewed run\n"
    )
    assert workload.events == []
    assert controller.events == []


def test_operator_runs_lifecycle_in_order_and_reads_exact_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload, controller = _success_ports(fixture)
    clock = FakeClock()

    result = run_operational_demo_operator(
        fixture.config_path,
        confirmation_phrase=fixture.confirmation_phrase,
        workload_port=workload,
        phase_job_port=controller,
        handoff_port=controller,
        artifact_reader=fixture.reader,
        clock=clock,
    )

    assert isinstance(result, OperationalDemoOperatorResult)
    assert result.run_id == RUN_ID
    assert result.baseline.verdict == "pass"
    assert result.faulted.verdict == "fail"
    assert result.recovered.verdict == "resolved"
    assert result.reset_status == "reset succeeded"
    assert workload.events == ["status", "inject", "reset"]
    assert controller.events == [
        ("start", "baseline"),
        ("status", "baseline"),
        ("status", "baseline"),
        ("handoff", "baseline"),
        ("start", "faulted"),
        ("status", "faulted"),
        ("status", "faulted"),
        ("handoff", "faulted"),
        ("start", "recovered"),
        ("status", "recovered"),
        ("status", "recovered"),
        ("handoff", "recovered"),
    ]
    assert [request.phase for request in controller.requests] == [
        "baseline",
        "faulted",
        "recovered",
    ]
    expected_reads = [
        fixture.handoffs["baseline"].completion_index,
        *fixture.phase_results["baseline"].completion_index.artifacts,
        fixture.handoffs["faulted"].completion_index,
        *fixture.phase_results["faulted"].completion_index.artifacts,
        fixture.handoffs["recovered"].completion_index,
        *fixture.phase_results["recovered"].completion_index.artifacts,
    ]
    assert [
        (request.blob_name, request.version_id, request.expected_payload_sha256)
        for request in fixture.reader.requests
    ] == [
        (reference.name, reference.version, reference.content_digest)
        for reference in expected_reads
    ]
    assert clock.sleeps == [1, 1, 1]


def test_baseline_failure_does_not_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload = ScriptedWorkloadPort(
        {
            "status": [fixture.workload_reports["status"]],
            "inject": [fixture.workload_reports["inject"]],
            "reset": [fixture.workload_reports["reset"]],
        }
    )
    controller = ScriptedPhaseController(
        {
            "baseline": PhasePlan(statuses=["failed"], handoff=fixture.handoffs["baseline"]),
            "faulted": PhasePlan(statuses=["succeeded"], handoff=fixture.handoffs["faulted"]),
            "recovered": PhasePlan(statuses=["succeeded"], handoff=fixture.handoffs["recovered"]),
        }
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="baseline phase failed closed; reset not attempted; recovery not run",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )

    assert workload.events == ["status"]


def test_ambiguous_inject_still_attempts_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload = ScriptedWorkloadPort(
        {
            "status": [fixture.workload_reports["status"]],
            "inject": [OperationalDemoOperatorError("inject action failed closed")],
            "reset": [fixture.workload_reports["reset"]],
        }
    )
    controller = ScriptedPhaseController(
        {
            "baseline": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["baseline"],
            ),
            "faulted": PhasePlan(statuses=["succeeded"], handoff=fixture.handoffs["faulted"]),
            "recovered": PhasePlan(statuses=["succeeded"], handoff=fixture.handoffs["recovered"]),
        }
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="inject action failed closed; reset succeeded; recovery not run",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )

    assert workload.events == ["status", "inject", "reset"]


def test_faulted_failure_still_resets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload, controller = _success_ports(fixture)
    controller._plans["faulted"] = PhasePlan(
        statuses=["failed"],
        handoff=fixture.handoffs["faulted"],
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="faulted phase failed closed; reset succeeded; recovery not run",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )

    assert workload.events == ["status", "inject", "reset"]


def test_reset_failure_blocks_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload = ScriptedWorkloadPort(
        {
            "status": [fixture.workload_reports["status"]],
            "inject": [fixture.workload_reports["inject"]],
            "reset": [OperationalDemoOperatorError("reset action failed closed")],
        }
    )
    controller = ScriptedPhaseController(
        {
            "baseline": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["baseline"],
            ),
            "faulted": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["faulted"],
            ),
            "recovered": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["recovered"],
            ),
        }
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="reset action failed closed; recovery not run",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )

    assert all(event[1] != "recovered" for event in controller.events)


def test_primary_and_reset_errors_are_both_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload = ScriptedWorkloadPort(
        {
            "status": [fixture.workload_reports["status"]],
            "inject": [fixture.workload_reports["inject"]],
            "reset": [OperationalDemoOperatorError("reset action failed closed")],
        }
    )
    controller = ScriptedPhaseController(
        {
            "baseline": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["baseline"],
            ),
            "faulted": PhasePlan(
                statuses=["failed"],
                handoff=fixture.handoffs["faulted"],
            ),
            "recovered": PhasePlan(
                statuses=["succeeded"],
                handoff=fixture.handoffs["recovered"],
            ),
        }
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="faulted phase failed closed; reset action failed closed; recovery not run",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )


@pytest.mark.parametrize(
    ("statuses", "match"),
    [
        (["running", "running", "running", "running"], "baseline phase timed out"),
        (["unknown"], "baseline phase reached an unknown terminal state"),
        (["failed"], "baseline phase failed closed"),
    ],
)
def test_phase_status_timeouts_and_terminal_failures_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    statuses: list[str],
    match: str,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    workload, controller = _success_ports(fixture)
    controller._plans["baseline"] = PhasePlan(
        statuses=list(statuses),
        handoff=fixture.handoffs["baseline"],
    )

    with pytest.raises(OperationalDemoOperatorError, match=match):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )


def test_index_chain_and_lineage_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    tampered_reference = _rewrite_completion_index_reference(
        fixture,
        "faulted",
        updates={"lineageDigest": "sha256:" + "f" * 64},
    )
    workload, controller = _success_ports(fixture)
    controller._plans["faulted"] = PhasePlan(
        statuses=["succeeded"],
        handoff=build_operational_phase_reference_handoff(
            run_id=RUN_ID,
            phase="faulted",
            bundle_digest=fixture.phase_results["faulted"].completion_index.bundle_digest,
            completion_index=tampered_reference,
        ),
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match=(
            "faulted completion index failed closed verification; "
            "reset succeeded; recovery not run"
        ),
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )


def test_integrity_verification_rejects_tampered_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path, monkeypatch)
    recovered = fixture.phase_results["recovered"]
    attestation_reference = recovered.completion_index.artifacts[3]
    attestation_payload = json.loads(
        fixture.store.content(attestation_reference.name, attestation_reference.version)
        .decode("utf-8")
    )
    attestation_payload["detachedSignature"] = "AA"
    tampered_attestation = fixture.store.seed(
        name=attestation_reference.name,
        content=(canonicalize_json(attestation_payload) + "\n").encode("utf-8"),
    )
    artifacts = list(recovered.completion_index.artifacts)
    artifacts[3] = artifacts[3].model_copy(
        update={
            "version": tampered_attestation.version,
            "content_digest": tampered_attestation.content_digest,
        }
    )
    tampered_index = _rewrite_completion_index_reference(
        fixture,
        "recovered",
        updates={"artifacts": tuple(artifacts)},
    )
    workload, controller = _success_ports(fixture)
    controller._plans["recovered"] = PhasePlan(
        statuses=["succeeded"],
        handoff=build_operational_phase_reference_handoff(
            run_id=RUN_ID,
            phase="recovered",
            bundle_digest=recovered.completion_index.bundle_digest,
            completion_index=tampered_index,
        ),
    )

    with pytest.raises(
        OperationalDemoOperatorError,
        match="recovered phase integrity verification failed closed; reset succeeded",
    ):
        run_operational_demo_operator(
            fixture.config_path,
            confirmation_phrase=fixture.confirmation_phrase,
            workload_port=workload,
            phase_job_port=controller,
            handoff_port=controller,
            artifact_reader=fixture.reader,
            clock=FakeClock(),
        )


def test_cli_error_output_redacts_paths_and_boundary_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_fixture(tmp_path / "sensitive-path-root", monkeypatch)
    stderr = StringIO()

    class LeakyWorkloadPort(WorkloadActionPort):
        def status(
            self,
            *,
            run_id: str,
            scenario_id: str,
        ) -> OperationalDemoWorkloadActionReport:
            del run_id, scenario_id
            raise RuntimeError(
                "token=secret path=C:\\sensitive\\operator.json "
                "/subscriptions/11111111-1111-1111-1111-111111111111"
            )

        def inject(
            self,
            *,
            run_id: str,
            scenario_id: str,
        ) -> OperationalDemoWorkloadActionReport:
            raise AssertionError

        def reset(
            self,
            *,
            run_id: str,
            scenario_id: str,
        ) -> OperationalDemoWorkloadActionReport:
            raise AssertionError

    exit_code = main(
        [
            "operational-demo-operator",
            "--config",
            str(fixture.config_path),
            "--confirm",
            fixture.confirmation_phrase,
        ],
        operational_demo_workload_port=LeakyWorkloadPort(),
        stderr=stderr,
    )

    assert exit_code == 1
    assert stderr.getvalue() == (
        "operational demo operator failed: "
        "status action failed closed; reset not attempted; recovery not run\n"
    )
    assert "sensitive" not in stderr.getvalue().casefold()
    assert "subscription" not in stderr.getvalue().casefold()
