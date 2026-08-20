from __future__ import annotations

import base64
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.artifacts import (
    ArtifactMetadataHashes,
    ArtifactReadRequest,
    ArtifactWriteRequest,
)
from athena_context.azure_adapters import (
    AzureBlobCreateOnlyArtifactWriter,
    AzureBlobVersionPinnedArtifactReader,
    KeyVaultRsaSigner,
)
from athena_context.contracts import (
    ArgusPresentationPhase,
    OperationalPhaseDeliveryBundle,
    OperationalPhaseInputs,
    OperationalPhaseReferenceHandoff,
    OperationalPhaseSelector,
    VersionPinnedBlobReference,
    build_operational_phase_reference_handoff,
    compute_artifact_digest,
)
from athena_context.contracts.models import (
    EvidenceSnapshot,
    SnapshotPublicationRecord,
    TrustedKeyAnchor,
    TrustedKeyRecord,
)
from athena_context.live_acceptance import (
    PreparedWc013LiveAcceptance,
    Wc013LiveAcceptancePlan,
    Wc013LiveAcceptanceResult,
    prepare_wc013_live_acceptance_plan,
    run_prepared_wc013_live_acceptance,
    verify_wc013_live_result,
)
from athena_context.operational_phase_runner import (
    CreateOnlyArtifact,
    OperationalPhaseRunnerError,
    OperationalPhaseRunResult,
    Wc013PhaseRunner,
    run_operational_phase,
)

_MAX_BUNDLE_BYTES = 256 * 1024
_MAX_CONFIGURATION_BYTES = 256 * 1024
HANDOFF_BASE64_PREFIX = "ATHENA_OPERATIONAL_PHASE_HANDOFF_B64="

@dataclass(frozen=True, slots=True)
class OperationalPhaseJobResult:
    completed: OperationalPhaseRunResult
    handoff: OperationalPhaseReferenceHandoff

    def handoff_base64(self) -> str:
        return base64.b64encode(
            (self.handoff.canonical_json() + "\n").encode("utf-8")
        ).decode("ascii")


@dataclass(frozen=True, slots=True)
class _PreparedOperationalPhase:
    phase: ArgusPresentationPhase
    bundle: OperationalPhaseDeliveryBundle
    configuration_path: Path
    prepared: PreparedWc013LiveAcceptance


class _PreparedPhaseVerificationContext:
    def __init__(self, prepared: PreparedWc013LiveAcceptance) -> None:
        self._prepared = prepared
        self._verified_result: DemoEvaluationResult | None = None

    def verify_result(self, result: DemoEvaluationResult) -> DemoEvaluationResult:
        verify_wc013_live_result(self._prepared, result)
        self._verified_result = result
        return result

    def verify_snapshot(
        self,
        snapshot: EvidenceSnapshot,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        verified_result = self._verified_result
        if verified_result is None or verified_result.snapshot is not snapshot:
            raise OperationalPhaseRunnerError(
                "trusted phase snapshot is not bound to the exact verified result"
            )
        publication = SnapshotPublicationRecord(
            snapshot_id=snapshot.snapshot_id,
            artifact_digest=snapshot.compatibility.artifact_digest,
            semantic_digest=snapshot.compatibility.semantic_digest,
            schema_version=snapshot.compatibility.schema_version,
            semantic_contract_version=(
                snapshot.compatibility.semantic_contract_version
            ),
            published_at=verified_result.publication.published_at,
        )
        expected_snapshot_id = snapshot.snapshot_id
        key_record = self._prepared.trusted_key_record

        def resolve_publication(
            snapshot_id: str,
        ) -> SnapshotPublicationRecord | None:
            return publication if snapshot_id == expected_snapshot_id else None

        def resolve_key(
            anchor: TrustedKeyAnchor,
        ) -> TrustedKeyRecord | None:
            return (
                key_record
                if anchor == self._prepared.trusted_key_anchor
                else None
            )

        return snapshot.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=(
                snapshot.compatibility.artifact_digest
            ),
            publication_resolver=resolve_publication,
            identity_evidence=snapshot.identity_evidence,
            key_resolver=resolve_key,
            trusted_key_anchor=self._prepared.trusted_key_anchor,
        )


class _AzureBlobPhaseArtifactStore:
    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        self._writer = AzureBlobCreateOnlyArtifactWriter(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
        )

    def _write(self, artifact: CreateOnlyArtifact) -> VersionPinnedBlobReference:
        receipt = self._writer.create(
            ArtifactWriteRequest(
                blob_name=artifact.name,
                payload=artifact.content,
                content_type="application/json",
                hashes=ArtifactMetadataHashes(
                    payload_sha256=artifact.digest,
                ),
            )
        )
        return VersionPinnedBlobReference(
            name=receipt.blob_name,
            version=receipt.version_id,
            contentDigest=receipt.payload_sha256,
        )

    def create_only(
        self,
        artifacts: tuple[CreateOnlyArtifact, ...],
    ) -> tuple[VersionPinnedBlobReference, ...]:
        return tuple(self._write(artifact) for artifact in artifacts)

    def create_completion_index(
        self,
        artifact: CreateOnlyArtifact,
    ) -> VersionPinnedBlobReference:
        return self._write(artifact)


class _AzureBlobPhaseInputReader:
    def __init__(
        self,
        *,
        blob_endpoint: str,
        container_name: str,
        managed_identity_client_id: str,
    ) -> None:
        self._reader = AzureBlobVersionPinnedArtifactReader(
            blob_endpoint=blob_endpoint,
            container_name=container_name,
            managed_identity_client_id=managed_identity_client_id,
        )

    def _read(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._reader.read(
            ArtifactReadRequest(
                blob_name=reference.name,
                version_id=reference.version,
                expected_payload_sha256=reference.content_digest,
            )
        ).payload

    def read_receipt(self, reference: VersionPinnedBlobReference) -> bytes:
        return self._read(reference)

    def read_completion_index(
        self,
        reference: VersionPinnedBlobReference,
    ) -> bytes:
        return self._read(reference)


def _read_bounded(
    path: Path,
    *,
    maximum_bytes: int,
    unavailable_message: str,
    invalid_message: str,
) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise OperationalPhaseRunnerError(unavailable_message) from exc
    if not content or len(content) > maximum_bytes:
        raise OperationalPhaseRunnerError(invalid_message)
    return content


def _parse_model[Model: BaseModel](
    path: Path,
    model: type[Model],
    *,
    maximum_bytes: int,
    unavailable_message: str,
    invalid_message: str,
) -> Model:
    try:
        return model.model_validate_json(
            _read_bounded(
                path,
                maximum_bytes=maximum_bytes,
                unavailable_message=unavailable_message,
                invalid_message=invalid_message,
            )
        )
    except ValidationError as exc:
        raise OperationalPhaseRunnerError(invalid_message) from exc


def _resolve_bundle_file(root: Path, relative_file: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = (resolved_root / relative_file).resolve(strict=True)
    except OSError as exc:
        raise OperationalPhaseRunnerError(
            "reviewed delivery file is unavailable"
        ) from exc
    if not resolved.is_file() or not resolved.is_relative_to(resolved_root):
        raise OperationalPhaseRunnerError(
            "reviewed delivery file escaped its bundle boundary"
        )
    return resolved


def _model_digest(model: BaseModel) -> str:
    return compute_artifact_digest(
        model.model_dump(mode="json", by_alias=True, exclude_none=True)
    )


def _load_prepared_phase(
    *,
    bundle_path: Path,
    phase_selector: str,
) -> _PreparedOperationalPhase:
    selector = OperationalPhaseSelector(phase=phase_selector)
    phase = selector.selected_phase()
    bundle = _parse_model(
        bundle_path,
        OperationalPhaseDeliveryBundle,
        maximum_bytes=_MAX_BUNDLE_BYTES,
        unavailable_message="reviewed delivery bundle is unavailable",
        invalid_message="reviewed delivery bundle failed closed validation",
    )
    configuration = bundle.configurations.select(phase)
    configuration_path = _resolve_bundle_file(
        bundle_path.parent,
        configuration.wc013_configuration_file,
    )
    plan = _parse_model(
        configuration_path,
        Wc013LiveAcceptancePlan,
        maximum_bytes=_MAX_CONFIGURATION_BYTES,
        unavailable_message="reviewed phase configuration is unavailable",
        invalid_message="reviewed phase configuration failed closed validation",
    )
    if _model_digest(plan) != configuration.wc013_configuration_digest:
        raise OperationalPhaseRunnerError(
            "selected configuration digest does not match the reviewed bundle"
        )
    return _PreparedOperationalPhase(
        phase=phase,
        bundle=bundle,
        configuration_path=configuration_path,
        prepared=prepare_wc013_live_acceptance_plan(
            plan,
            plan_path=configuration_path,
        ),
    )


def _environment_value(
    environment: Mapping[str, str],
    *,
    name: str,
    maximum_length: int,
) -> str | None:
    value = environment.get(name)
    if value is None or value == "":
        return None
    if (
        value != value.strip()
        or len(value) > maximum_length
        or any(character in value for character in ("\0", "\r", "\n"))
    ):
        raise OperationalPhaseRunnerError(
            f"operational phase job environment variable {name} is invalid"
        )
    return value


def _reference_from_environment(
    environment: Mapping[str, str],
    *,
    variable_prefix: str,
    required: bool,
) -> VersionPinnedBlobReference | None:
    name = _environment_value(
        environment,
        name=f"{variable_prefix}_NAME",
        maximum_length=1024,
    )
    version = _environment_value(
        environment,
        name=f"{variable_prefix}_VERSION",
        maximum_length=256,
    )
    digest = _environment_value(
        environment,
        name=f"{variable_prefix}_DIGEST",
        maximum_length=71,
    )
    present = [name is not None, version is not None, digest is not None]
    if any(present) and not all(present):
        raise OperationalPhaseRunnerError(
            f"operational phase job {variable_prefix.casefold()} environment is incomplete"
        )
    if not any(present):
        if required:
            raise OperationalPhaseRunnerError(
                f"operational phase job is missing required environment variable: "
                f"{variable_prefix}_NAME"
            )
        return None
    assert name is not None
    assert version is not None
    assert digest is not None
    try:
        return VersionPinnedBlobReference(
            name=name,
            version=version,
            contentDigest=digest,
        )
    except ValidationError as exc:
        raise OperationalPhaseRunnerError(
            f"operational phase job {variable_prefix.casefold()} reference is invalid"
        ) from exc


def _phase_inputs_from_environment(
    *,
    bundle: OperationalPhaseDeliveryBundle,
    phase: ArgusPresentationPhase,
    environment: Mapping[str, str],
) -> OperationalPhaseInputs:
    receipt = _reference_from_environment(
        environment,
        variable_prefix="ATHENA_OPERATIONAL_RECEIPT",
        required=True,
    )
    previous_phase_index = _reference_from_environment(
        environment,
        variable_prefix="ATHENA_OPERATIONAL_PREVIOUS_INDEX",
        required=False,
    )
    lineage_reference_digest = _environment_value(
        environment,
        name="ATHENA_OPERATIONAL_LINEAGE_REFERENCE_DIGEST",
        maximum_length=71,
    )
    assert receipt is not None
    try:
        return OperationalPhaseInputs(
            schemaVersion="athena.operationalPhaseInputs.v1",
            runId=bundle.run_id,
            bundleDigest=bundle.bundle_digest,
            phase=phase,
            receipt=receipt,
            previousPhaseIndex=previous_phase_index,
            lineageReferenceDigest=lineage_reference_digest,
        )
    except ValidationError as exc:
        raise OperationalPhaseRunnerError(
            "operational phase job environment did not describe a valid exact phase input set"
        ) from exc


def _write_exclusive_json_file(path: Path, content: str, *, message: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.write("\n")
    except OSError as exc:
        raise OperationalPhaseRunnerError(message) from exc


def _wc013_runtime_environment(
    prepared: PreparedWc013LiveAcceptance,
) -> dict[str, str]:
    plan = prepared.plan
    return {
        "AZURE_CLIENT_ID": plan.context_identity_client_id,
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID": (
            plan.context_identity_client_id
        ),
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_AZURE_MCP_AUDIENCE": plan.azure_mcp_audience,
        "ATHENA_WC013_REPLAY_TABLE_ENDPOINT": plan.replay.table_endpoint,
        "ATHENA_WC013_REPLAY_TABLE_NAME": plan.replay.table_name,
        "ATHENA_WC013_REPLAY_PARTITION_KEY": plan.replay.partition_key,
        "ATHENA_WC013_LIVE": "1",
    }


@contextmanager
def _temporary_environment(values: Mapping[str, str]) -> Iterator[None]:
    previous: dict[str, str | None] = {
        name: os.environ.get(name) for name in values
    }
    try:
        for name, current_value in values.items():
            os.environ[name] = current_value
        yield
    finally:
        for name, previous_value in previous.items():
            if previous_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous_value


def _wc013_runner(
    prepared_phase: _PreparedOperationalPhase,
) -> Wc013PhaseRunner:
    expected_plan = prepared_phase.prepared.plan
    expected_path = prepared_phase.configuration_path
    runtime_environment = _wc013_runtime_environment(prepared_phase.prepared)

    def run_selected_plan(
        plan: Wc013LiveAcceptancePlan,
        plan_path: Path,
    ) -> Wc013LiveAcceptanceResult:
        if plan != expected_plan or plan_path != expected_path:
            raise OperationalPhaseRunnerError(
                "selected phase plan changed during production composition"
            )
        with _temporary_environment(runtime_environment):
            return run_prepared_wc013_live_acceptance(
                prepared_phase.prepared
            )

    return run_selected_plan


def run_operational_phase_job(
    *,
    bundle_path: Path,
    phase_selector: str,
    inputs_output_path: Path,
    handoff_output_path: Path,
    artifact_blob_endpoint: str,
    artifact_container_name: str,
    environment: Mapping[str, str] | None = None,
) -> OperationalPhaseJobResult:
    prepared_phase = _load_prepared_phase(
        bundle_path=bundle_path,
        phase_selector=phase_selector,
    )
    runtime_environment = environment if environment is not None else os.environ
    phase_inputs = _phase_inputs_from_environment(
        bundle=prepared_phase.bundle,
        phase=prepared_phase.phase,
        environment=runtime_environment,
    )
    _write_exclusive_json_file(
        inputs_output_path,
        phase_inputs.canonical_json(),
        message="phase inputs output could not be created",
    )

    verification_context = _PreparedPhaseVerificationContext(
        prepared_phase.prepared
    )
    managed_identity_client_id = (
        prepared_phase.prepared.plan.context_identity_client_id
    )
    artifact_store = _AzureBlobPhaseArtifactStore(
        blob_endpoint=artifact_blob_endpoint,
        container_name=artifact_container_name,
        managed_identity_client_id=managed_identity_client_id,
    )
    completed = run_operational_phase(
        bundle_path=bundle_path,
        inputs_path=inputs_output_path,
        phase_selector=prepared_phase.phase,
        artifact_writer=artifact_store,
        input_reader=_AzureBlobPhaseInputReader(
            blob_endpoint=artifact_blob_endpoint,
            container_name=artifact_container_name,
            managed_identity_client_id=managed_identity_client_id,
        ),
        completion_index_writer=artifact_store,
        result_verifier=verification_context.verify_result,
        snapshot_verifier=verification_context.verify_snapshot,
        signer=KeyVaultRsaSigner(
            trusted_key_anchor=prepared_phase.prepared.trusted_key_anchor,
            managed_identity_client_id=managed_identity_client_id,
        ),
        wc013_runner=_wc013_runner(prepared_phase),
    )
    handoff = build_operational_phase_reference_handoff(
        run_id=completed.run_id,
        phase=completed.phase,
        bundle_digest=completed.completion_index.bundle_digest,
        completion_index=completed.completion_index_reference,
    )
    _write_exclusive_json_file(
        handoff_output_path,
        handoff.canonical_json(),
        message="phase reference handoff output could not be created",
    )
    return OperationalPhaseJobResult(
        completed=completed,
        handoff=handoff,
    )


__all__ = [
    "HANDOFF_BASE64_PREFIX",
    "OperationalPhaseJobResult",
    "run_operational_phase_job",
]
