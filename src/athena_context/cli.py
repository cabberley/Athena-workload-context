from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import TextIO, cast

from athena_context import __version__
from athena_context.artifacts import VersionPinnedArtifactReaderPort
from athena_context.binding.verification import TrustedSnapshotVerifier
from athena_context.contracts import (
    ApprovedChangeScope,
    build_operational_phase_reference_handoff,
)
from athena_context.contracts.eventing import WorkloadRole
from athena_context.contracts.presentation import ArgusPresentationPhase
from athena_context.eventing import (
    ChangeIngestionError,
    SignalDetectionError,
    run_event_grid_change_ingestion_worker,
    run_event_grid_dead_letter_purge_worker,
    run_incident_feed_heartbeat,
    run_incident_orchestrator_worker,
    run_notification_dispatcher_worker,
    run_resource_graph_change_history_worker,
    run_scheduled_signal_detector,
)
from athena_context.live_acceptance import (
    Wc013LiveAcceptanceError,
    prepare_wc013_live_acceptance,
    render_wc013_configuration,
    run_wc013_live_acceptance,
    wc013_configuration_template,
)
from athena_context.operational_demo_operator import (
    OperationalDemoOperatorError,
    PhaseJobPort,
    ReferenceHandoffPort,
    WorkloadActionPort,
    build_operational_demo_validation,
    render_operational_demo_result,
    render_operational_demo_validation,
    run_operational_demo_operator,
)
from athena_context.operational_phase_job import (
    HANDOFF_BASE64_PREFIX,
    run_operational_phase_job,
)
from athena_context.operational_phase_runner import (
    CompletionIndexWriterPort,
    CreateOnlyArtifactWriterPort,
    OperationalPhaseRunnerError,
    VersionPinnedPhaseInputReaderPort,
    Wc013PhaseRunner,
    run_operational_phase,
)
from athena_context.precollected_evidence import (
    COLLECTED_EVIDENCE_HANDOFF_BASE64_PREFIX,
)
from athena_context.presentation import (
    PresentationSigner,
    TrustedDemoEvaluationVerifier,
)
from athena_context.presentation_asset_gateway import (
    PresentationAssetGatewayError,
    run_presentation_asset_gateway,
)
from athena_context.presentation_assets import PresentationAssetPublisherPort
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
from athena_context.wc013_collector_controller import (
    Wc013CollectorControllerError,
    Wc013CollectorJobManagementPort,
    run_governed_wc013_collector_start,
)
from athena_context.wc013_evidence_collector import (
    run_wc013_evidence_collector_job,
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
    live_parser.add_argument("--evidence-blob-endpoint")
    live_parser.add_argument("--evidence-container")
    collector_parser = subparsers.add_parser(
        "wc013-evidence-collector-job",
        help="collect and attest WC-013 evidence outside the Athena identity boundary",
    )
    collector_parser.add_argument("--config", required=True, type=Path)
    collector_parser.add_argument("--artifact-blob-endpoint", required=True)
    collector_parser.add_argument("--artifact-container", required=True)
    collector_parser.add_argument(
        "--emit-handoff-base64",
        action="store_true",
        help="print the version-pinned evidence handoff as one base64 line",
    )
    collector_controller_parser = subparsers.add_parser(
        "wc013-collector-controller",
        help="validate and start one exact deployed WC-013 collector template",
    )
    collector_controller_parser.add_argument("--contract", required=True, type=Path)
    collector_controller_parser.add_argument(
        "--controller-identity-client-id",
        required=True,
    )
    collector_controller_parser.add_argument(
        "--validate-only",
        action="store_true",
        help="retrieve and validate the deployed collector without starting it",
    )
    collector_controller_parser.add_argument(
        "--use-arm-access-token-stdin",
        action="store_true",
        help="consume one short-lived ARM access token from stdin",
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
    phase_parser.add_argument("--inputs", required=True, type=Path)
    phase_parser.add_argument("--phase", required=True)
    phase_parser.add_argument("--handoff-output", type=Path)
    phase_job_parser = subparsers.add_parser(
        "operational-phase-job",
        help="run one fixed operational demo phase inside the production job",
    )
    phase_job_parser.add_argument("--bundle", required=True, type=Path)
    phase_job_parser.add_argument("--phase", required=True)
    phase_job_parser.add_argument("--inputs-output", required=True, type=Path)
    phase_job_parser.add_argument("--handoff-output", required=True, type=Path)
    phase_job_parser.add_argument("--artifact-blob-endpoint", required=True)
    phase_job_parser.add_argument("--artifact-container", required=True)
    phase_job_parser.add_argument("--evidence-blob-endpoint", required=True)
    phase_job_parser.add_argument("--evidence-container", required=True)
    phase_job_parser.add_argument(
        "--emit-handoff-base64",
        action="store_true",
        help="print the governed handoff as one base64 line for the phase-job controller",
    )
    operator_parser = subparsers.add_parser(
        "operational-demo-operator",
        help="validate or run the external operational demonstration operator",
    )
    operator_parser.add_argument("--config", required=True, type=Path)
    operator_parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the reviewed operator configuration without calling any ports",
    )
    operator_parser.add_argument(
        "--confirm",
        help="exact confirmation phrase printed by --validate-only",
    )
    gateway_parser = subparsers.add_parser(
        "presentation-asset-gateway",
        help="serve the current verified private presentation asset set",
    )
    gateway_parser.add_argument("--blob-endpoint", required=True)
    gateway_parser.add_argument(
        "--container",
        default="presentation-assets",
        choices=("presentation-assets",),
    )
    gateway_parser.add_argument(
        "--incident-container",
        default="incident-assets",
        choices=("incident-assets",),
    )
    gateway_parser.add_argument("--incident-key-id", required=True)
    gateway_parser.add_argument("--incident-key-fingerprint", required=True)
    gateway_parser.add_argument("--incident-public-key", required=True, type=Path)
    for trust_name in ("feed-v2", "report", "guidance", "enrichment"):
        gateway_parser.add_argument(f"--incident-{trust_name}-key-id")
        gateway_parser.add_argument(f"--incident-{trust_name}-key-fingerprint")
        gateway_parser.add_argument(
            f"--incident-{trust_name}-public-key",
            type=Path,
        )
    gateway_parser.add_argument("--managed-identity-client-id", required=True)
    gateway_parser.add_argument("--port", type=int, default=8081)
    detector_parser = subparsers.add_parser(
        "wc016-signal-detector",
        help="query only approved Azure signals and emit context-bound reassessments",
    )
    detector_parser.add_argument("--service-bus-namespace", required=True)
    detector_parser.add_argument(
        "--reassessment-queue",
        default="incident-reassessment-requests",
    )
    detector_parser.add_argument("--managed-identity-client-id", required=True)
    detector_parser.add_argument("--approved-resource-roles", type=Path)
    detector_parser.add_argument("--approved-resource-roles-json")
    detector_parser.add_argument("--approved-alert-rules", type=Path)
    detector_parser.add_argument("--approved-alert-rules-json")
    detector_parser.add_argument("--state-table-endpoint", required=True)
    detector_parser.add_argument("--state-table-name", required=True)
    detector_parser.add_argument("--state-partition-key", required=True)
    detector_parser.add_argument(
        "--metric-window-minutes",
        type=int,
        default=5,
        choices=range(2, 11),
    )
    incident_parser = subparsers.add_parser(
        "wc016-incident-orchestrator",
        help="consume one reassessment request and publish one signed incident update",
    )
    incident_parser.add_argument("--service-bus-namespace", required=True)
    incident_parser.add_argument(
        "--reassessment-queue",
        default="incident-reassessment-requests",
    )
    incident_parser.add_argument(
        "--notification-queue",
        default="incident-notification-outbox",
    )
    incident_parser.add_argument("--managed-identity-client-id", required=True)
    incident_parser.add_argument("--approved-resource-roles", type=Path)
    incident_parser.add_argument("--approved-resource-roles-json")
    incident_parser.add_argument(
        "--metric-window-minutes",
        type=int,
        default=5,
        choices=range(2, 11),
    )
    incident_parser.add_argument("--blob-endpoint", required=True)
    incident_parser.add_argument("--presentation-url", required=True)
    incident_parser.add_argument("--key-vault-key-id", required=True)
    incident_parser.add_argument("--signing-key-id", required=True)
    incident_parser.add_argument("--signing-key-fingerprint", required=True)
    heartbeat_parser = subparsers.add_parser(
        "wc016-incident-feed-heartbeat",
        help="publish a signed feed heartbeat after independently verifying live health",
    )
    heartbeat_parser.add_argument("--managed-identity-client-id", required=True)
    heartbeat_parser.add_argument("--approved-resource-roles", type=Path)
    heartbeat_parser.add_argument("--approved-resource-roles-json")
    heartbeat_parser.add_argument("--approved-alert-rules", type=Path)
    heartbeat_parser.add_argument("--approved-alert-rules-json")
    heartbeat_parser.add_argument(
        "--metric-window-minutes",
        type=int,
        default=5,
        choices=range(2, 11),
    )
    heartbeat_parser.add_argument("--blob-endpoint", required=True)
    heartbeat_parser.add_argument("--key-vault-key-id", required=True)
    heartbeat_parser.add_argument("--signing-key-id", required=True)
    heartbeat_parser.add_argument("--signing-key-fingerprint", required=True)
    notification_parser = subparsers.add_parser(
        "wc016-notification-dispatcher",
        help="deliver one bounded incident notification through the approved Teams workflow",
    )
    notification_parser.add_argument("--service-bus-namespace", required=True)
    notification_parser.add_argument(
        "--notification-queue",
        default="incident-notification-outbox",
    )
    notification_parser.add_argument("--managed-identity-client-id", required=True)
    notification_parser.add_argument("--webhook-url")
    notification_parser.add_argument(
        "--notification-state-table-endpoint",
        required=True,
    )
    notification_parser.add_argument("--notification-state-table-name", required=True)
    notification_parser.add_argument(
        "--notification-state-partition-key",
        required=True,
    )
    change_event_parser = subparsers.add_parser(
        "wc025-change-event-ingester",
        help="normalize only approved resource-group Event Grid changes into signed evidence",
    )
    change_event_parser.add_argument("--service-bus-namespace", required=True)
    change_event_parser.add_argument(
        "--change-events-queue",
        default="change-evidence-events",
    )
    change_event_parser.add_argument("--managed-identity-client-id", required=True)
    change_event_parser.add_argument("--approved-change-scope", type=Path)
    change_event_parser.add_argument("--approved-change-scope-json")
    change_event_parser.add_argument("--artifact-blob-endpoint", required=True)
    change_event_parser.add_argument("--artifact-container", required=True)
    change_event_parser.add_argument("--key-vault-key-id", required=True)
    change_dead_letter_parser = subparsers.add_parser(
        "wc025-change-dead-letter-purge",
        help="purge raw poison deliveries from the WC-025 Service Bus dead-letter paths",
    )
    change_dead_letter_parser.add_argument("--service-bus-namespace", required=True)
    change_dead_letter_parser.add_argument(
        "--change-events-queue",
        default="change-evidence-events",
    )
    change_dead_letter_parser.add_argument("--managed-identity-client-id", required=True)
    change_dead_letter_parser.add_argument("--artifact-blob-endpoint", required=True)
    change_dead_letter_parser.add_argument(
        "--failure-container",
        default="change-ingestion-failures",
    )
    change_dead_letter_parser.add_argument(
        "--maximum-messages-per-subqueue",
        type=int,
        choices=range(1, 1001),
        default=100,
    )
    change_history_parser = subparsers.add_parser(
        "wc025-change-history-query",
        help="query only approved Azure Resource Graph change history into signed evidence",
    )
    change_history_parser.add_argument("--managed-identity-client-id", required=True)
    change_history_parser.add_argument("--approved-change-scope", type=Path)
    change_history_parser.add_argument("--approved-change-scope-json")
    change_history_parser.add_argument("--artifact-blob-endpoint", required=True)
    change_history_parser.add_argument("--artifact-container", required=True)
    change_history_parser.add_argument("--key-vault-key-id", required=True)
    change_history_parser.add_argument(
        "--lookback-minutes",
        type=int,
        choices=range(1, 16),
        default=10,
    )
    return parser


def _load_json_configuration(
    *,
    path: Path | None,
    inline_json: str | None,
    label: str,
    environment_name: str,
) -> object:
    environment_json = os.environ.get(environment_name)
    sources = sum(value is not None for value in (path, inline_json, environment_json))
    if sources != 1:
        raise ValueError(
            f"{label} must be supplied by exactly one file, JSON argument, or {environment_name}"
        )
    try:
        content = (
            path.read_text(encoding="utf-8")
            if path is not None
            else inline_json
            if inline_json is not None
            else environment_json
        )
        assert content is not None
        if not 1 <= len(content.encode("utf-8")) <= 256 * 1024:
            raise ValueError(f"{label} is outside its byte bound")
        return json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} could not be loaded") from exc


def _load_approved_resource_roles(
    path: Path | None,
    inline_json: str | None = None,
) -> dict[str, WorkloadRole]:
    value = _load_json_configuration(
        path=path,
        inline_json=inline_json,
        label="approved resource role bindings",
        environment_name="ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON",
    )
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError("approved resource role bindings must be one bounded object")
    roles: dict[str, WorkloadRole] = {}
    allowed = {"database-primary", "web", "load-balancer"}
    for resource_id, role in value.items():
        if (
            not isinstance(resource_id, str)
            or not resource_id.startswith("/subscriptions/")
            or len(resource_id) > 2048
            or role not in allowed
        ):
            raise ValueError("approved resource role binding is invalid")
        normalized = resource_id.lower().rstrip("/")
        if normalized in roles:
            raise ValueError("approved resource role binding collides after normalization")
        roles[normalized] = cast(WorkloadRole, role)
    return roles


def _load_approved_alert_rules(
    path: Path | None,
    inline_json: str | None = None,
) -> tuple[str, ...]:
    value = _load_json_configuration(
        path=path,
        inline_json=inline_json,
        label="approved alert rules",
        environment_name="ATHENA_WC016_APPROVED_ALERT_RULES_JSON",
    )
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 128
        or any(
            not isinstance(rule, str) or not 1 <= len(rule) <= 256 or rule.strip() != rule
            for rule in value
        )
    ):
        raise ValueError("approved alert rules must be one bounded string array")
    normalized = tuple(rule.casefold() for rule in value)
    if len(set(normalized)) != len(normalized):
        raise ValueError("approved alert rules collide after normalization")
    return normalized


def _load_approved_change_scope(
    path: Path | None,
    inline_json: str | None = None,
) -> ApprovedChangeScope:
    value = _load_json_configuration(
        path=path,
        inline_json=inline_json,
        label="approved change scope",
        environment_name="ATHENA_WC025_APPROVED_CHANGE_SCOPE_JSON",
    )
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "subscriptionId",
        "resourceGroupName",
        "approvedResourceIds",
    }:
        raise ValueError("approved change scope is invalid")
    approved_resource_ids = value.get("approvedResourceIds")
    if not isinstance(approved_resource_ids, list):
        raise ValueError("approved change scope is invalid")
    normalized = {
        **value,
        "approvedResourceIds": tuple(sorted(approved_resource_ids)),
    }
    try:
        return ApprovedChangeScope.model_validate(normalized)
    except ValueError as exc:
        raise ValueError("approved change scope is invalid") from exc


def _write_exclusive_json_file(path: Path, content: str, *, message: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.write("\n")
    except OSError as exc:
        raise OperationalPhaseRunnerError(message) from exc


def main(
    argv: Sequence[str] | None = None,
    *,
    golden_runner: GoldenProofRunner | None = None,
    presentation_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    presentation_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    presentation_signer: PresentationSigner | None = None,
    phase_artifact_writer: CreateOnlyArtifactWriterPort | None = None,
    phase_input_reader: VersionPinnedPhaseInputReaderPort | None = None,
    phase_completion_index_writer: CompletionIndexWriterPort | None = None,
    phase_result_verifier: TrustedDemoEvaluationVerifier | None = None,
    phase_snapshot_verifier: TrustedSnapshotVerifier | None = None,
    phase_signer: PresentationSigner | None = None,
    phase_wc013_runner: Wc013PhaseRunner | None = None,
    operational_demo_workload_port: WorkloadActionPort | None = None,
    operational_demo_phase_job_port: PhaseJobPort | None = None,
    operational_demo_handoff_port: ReferenceHandoffPort | None = None,
    operational_demo_artifact_reader: VersionPinnedArtifactReaderPort | None = None,
    operational_demo_presentation_publisher: (PresentationAssetPublisherPort | None) = None,
    wc013_collector_job_management_port: (Wc013CollectorJobManagementPort | None) = None,
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
            if not args.evidence_blob_endpoint or not args.evidence_container:
                raise Wc013LiveAcceptanceError("evidence Blob endpoint and container are required")
            accepted = run_wc013_live_acceptance(
                args.config,
                evidence_blob_endpoint=args.evidence_blob_endpoint,
                evidence_container_name=args.evidence_container,
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
        if args.command == "wc013-evidence-collector-job":
            collected = run_wc013_evidence_collector_job(
                args.config,
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                artifact_container_name=args.artifact_container,
            )
            output.write(
                "WC-013 isolated evidence collection passed\n"
                f"attempt: {collected.artifact.collection_request.attempt_id}\n"
                f"artifact: {collected.handoff.evidence.name}\n"
                f"artifact digest: {collected.handoff.evidence.content_digest}\n"
            )
            if args.emit_handoff_base64:
                output.write(
                    f"{COLLECTED_EVIDENCE_HANDOFF_BASE64_PREFIX}{collected.handoff.base64()}\n"
                )
            return 0
        if args.command == "wc013-collector-controller":
            started = run_governed_wc013_collector_start(
                args.contract,
                controller_identity_client_id=args.controller_identity_client_id,
                management=wc013_collector_job_management_port,
                validate_only=args.validate_only,
                use_arm_access_token_stdin=args.use_arm_access_token_stdin,
            )
            output.write(
                "WC-013 collector template validated\n"
                f"job: {started.job_resource_id}\n"
                f"template digest: {started.execution_template_digest}\n"
            )
            if not args.validate_only:
                output.write(f"execution: {started.execution_name or 'accepted'}\n")
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
                inputs_path=args.inputs,
                phase_selector=args.phase,
                artifact_writer=phase_artifact_writer,
                input_reader=phase_input_reader,
                completion_index_writer=phase_completion_index_writer,
                result_verifier=phase_result_verifier,
                snapshot_verifier=phase_snapshot_verifier,
                signer=phase_signer,
                wc013_runner=phase_wc013_runner,
            )
            if args.handoff_output is not None:
                handoff = build_operational_phase_reference_handoff(
                    run_id=completed.run_id,
                    phase=completed.phase,
                    bundle_digest=completed.completion_index.bundle_digest,
                    completion_index=completed.completion_index_reference,
                )
                _write_exclusive_json_file(
                    args.handoff_output,
                    handoff.canonical_json(),
                    message="phase reference handoff output could not be created",
                )
            output.write(
                "operational phase runner passed\n"
                f"run: {completed.run_id}\n"
                f"phase: {completed.phase}\n"
                f"snapshot: {completed.snapshot_id}\n"
                f"result digest: {completed.result_digest}\n"
                f"presentation digest: {completed.presentation_digest}\n"
                f"completion index digest: "
                f"{completed.completion_index_digest}\n"
            )
            return 0
        if args.command == "operational-phase-job":
            job = run_operational_phase_job(
                bundle_path=args.bundle,
                phase_selector=args.phase,
                inputs_output_path=args.inputs_output,
                handoff_output_path=args.handoff_output,
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                artifact_container_name=args.artifact_container,
                evidence_blob_endpoint=args.evidence_blob_endpoint,
                evidence_container_name=args.evidence_container,
            )
            output.write(
                "operational phase job passed\n"
                f"run: {job.completed.run_id}\n"
                f"phase: {job.completed.phase}\n"
                f"snapshot: {job.completed.snapshot_id}\n"
                f"result digest: {job.completed.result_digest}\n"
                f"presentation digest: {job.completed.presentation_digest}\n"
                f"completion index digest: "
                f"{job.completed.completion_index_digest}\n"
            )
            if args.emit_handoff_base64:
                output.write(f"{HANDOFF_BASE64_PREFIX}{job.handoff_base64()}\n")
            return 0
        if args.command == "operational-demo-operator":
            if args.validate_only:
                validation = build_operational_demo_validation(args.config)
                output.write(render_operational_demo_validation(validation))
                return 0
            result = run_operational_demo_operator(
                args.config,
                confirmation_phrase=args.confirm,
                workload_port=operational_demo_workload_port,
                phase_job_port=operational_demo_phase_job_port,
                handoff_port=operational_demo_handoff_port,
                artifact_reader=operational_demo_artifact_reader,
                presentation_publisher=operational_demo_presentation_publisher,
            )
            output.write(render_operational_demo_result(result))
            return 0
        if args.command == "presentation-asset-gateway":
            run_presentation_asset_gateway(
                blob_endpoint=args.blob_endpoint,
                container_name=args.container,
                incident_container_name=args.incident_container,
                incident_key_id=args.incident_key_id,
                incident_key_fingerprint=args.incident_key_fingerprint,
                incident_public_key_path=args.incident_public_key,
                incident_feed_v2_key_id=args.incident_feed_v2_key_id,
                incident_feed_v2_key_fingerprint=(
                    args.incident_feed_v2_key_fingerprint
                ),
                incident_feed_v2_public_key_path=(
                    args.incident_feed_v2_public_key
                ),
                incident_report_key_id=args.incident_report_key_id,
                incident_report_key_fingerprint=(
                    args.incident_report_key_fingerprint
                ),
                incident_report_public_key_path=(
                    args.incident_report_public_key
                ),
                incident_guidance_key_id=args.incident_guidance_key_id,
                incident_guidance_key_fingerprint=(
                    args.incident_guidance_key_fingerprint
                ),
                incident_guidance_public_key_path=(
                    args.incident_guidance_public_key
                ),
                incident_enrichment_key_id=args.incident_enrichment_key_id,
                incident_enrichment_key_fingerprint=(
                    args.incident_enrichment_key_fingerprint
                ),
                incident_enrichment_public_key_path=(
                    args.incident_enrichment_public_key
                ),
                managed_identity_client_id=args.managed_identity_client_id,
                port=args.port,
            )
            return 0
        if args.command == "wc016-signal-detector":
            emitted = run_scheduled_signal_detector(
                fully_qualified_namespace=args.service_bus_namespace,
                reassessment_queue_name=args.reassessment_queue,
                managed_identity_client_id=args.managed_identity_client_id,
                approved_resource_roles=_load_approved_resource_roles(
                    args.approved_resource_roles,
                    args.approved_resource_roles_json,
                ),
                approved_metric_alert_rules=_load_approved_alert_rules(
                    args.approved_alert_rules,
                    args.approved_alert_rules_json,
                ),
                detector_state_table_endpoint=args.state_table_endpoint,
                detector_state_table_name=args.state_table_name,
                detector_state_partition_key=args.state_partition_key,
                metric_window_minutes=args.metric_window_minutes,
            )
            output.write(f"WC-016 detector emitted {emitted} reassessment request(s)\n")
            return 0
        if args.command == "wc016-incident-orchestrator":
            processed = run_incident_orchestrator_worker(
                fully_qualified_namespace=args.service_bus_namespace,
                reassessment_queue_name=args.reassessment_queue,
                notification_queue_name=args.notification_queue,
                managed_identity_client_id=args.managed_identity_client_id,
                approved_resource_roles=_load_approved_resource_roles(
                    args.approved_resource_roles,
                    args.approved_resource_roles_json,
                ),
                blob_endpoint=args.blob_endpoint,
                presentation_url=args.presentation_url,
                key_vault_key_id=args.key_vault_key_id,
                signing_key_id=args.signing_key_id,
                signing_key_fingerprint=args.signing_key_fingerprint,
                metric_window_minutes=args.metric_window_minutes,
            )
            output.write(
                "WC-016 incident published\n"
                if processed
                else "WC-016 reassessment queue was empty or rejected\n"
            )
            return 0
        if args.command == "wc016-incident-feed-heartbeat":
            run_incident_feed_heartbeat(
                managed_identity_client_id=args.managed_identity_client_id,
                approved_resource_roles=_load_approved_resource_roles(
                    args.approved_resource_roles,
                    args.approved_resource_roles_json,
                ),
                approved_metric_alert_rules=_load_approved_alert_rules(
                    args.approved_alert_rules,
                    args.approved_alert_rules_json,
                ),
                blob_endpoint=args.blob_endpoint,
                key_vault_key_id=args.key_vault_key_id,
                signing_key_id=args.signing_key_id,
                signing_key_fingerprint=args.signing_key_fingerprint,
                metric_window_minutes=args.metric_window_minutes,
            )
            output.write("WC-016 incident feed heartbeat published\n")
            return 0
        if args.command == "wc016-notification-dispatcher":
            webhook_url = args.webhook_url or os.environ.get("ATHENA_WC016_TEAMS_WEBHOOK_URL")
            if webhook_url is None:
                raise ValueError("notification webhook URL is required")
            processed = run_notification_dispatcher_worker(
                fully_qualified_namespace=args.service_bus_namespace,
                notification_queue_name=args.notification_queue,
                managed_identity_client_id=args.managed_identity_client_id,
                webhook_url=webhook_url,
                notification_state_table_endpoint=(args.notification_state_table_endpoint),
                notification_state_table_name=args.notification_state_table_name,
                notification_state_partition_key=(args.notification_state_partition_key),
            )
            output.write(
                "WC-016 notification delivered\n"
                if processed
                else "WC-016 notification queue was empty or rejected\n"
            )
            return 0
        if args.command == "wc025-change-event-ingester":
            event_count = run_event_grid_change_ingestion_worker(
                fully_qualified_namespace=args.service_bus_namespace,
                queue_name=args.change_events_queue,
                managed_identity_client_id=args.managed_identity_client_id,
                scope=_load_approved_change_scope(
                    args.approved_change_scope,
                    args.approved_change_scope_json,
                ),
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                artifact_container_name=args.artifact_container,
                signing_key_id=args.key_vault_key_id,
            )
            output.write(f"WC-025 change event ingester processed {event_count} change record(s)\n")
            return 0
        if args.command == "wc025-change-dead-letter-purge":
            purged_count = run_event_grid_dead_letter_purge_worker(
                fully_qualified_namespace=args.service_bus_namespace,
                queue_name=args.change_events_queue,
                managed_identity_client_id=args.managed_identity_client_id,
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                failure_container_name=args.failure_container,
                maximum_messages_per_subqueue=args.maximum_messages_per_subqueue,
            )
            output.write(
                f"WC-025 dead-letter purge removed {purged_count} raw message(s)\n"
            )
            return 0
        if args.command == "wc025-change-history-query":
            history_count = run_resource_graph_change_history_worker(
                managed_identity_client_id=args.managed_identity_client_id,
                scope=_load_approved_change_scope(
                    args.approved_change_scope,
                    args.approved_change_scope_json,
                ),
                artifact_blob_endpoint=args.artifact_blob_endpoint,
                artifact_container_name=args.artifact_container,
                signing_key_id=args.key_vault_key_id,
                lookback=timedelta(minutes=args.lookback_minutes),
            )
            output.write(
                f"WC-025 change history query processed {history_count} change record(s)\n"
            )
            return 0
    except Wc013LiveAcceptanceError as exc:
        errors.write(f"WC-013 live acceptance failed: {exc}\n")
        return 1
    except Wc013CollectorControllerError as exc:
        errors.write(f"WC-013 collector controller failed: {exc}\n")
        return 1
    except PresentationExportError as exc:
        errors.write(f"ARGUS presentation export failed: {exc}\n")
        return 1
    except OperationalPhaseRunnerError as exc:
        label = (
            "operational phase job"
            if args.command == "operational-phase-job"
            else "operational phase runner"
        )
        errors.write(f"{label} failed: {exc}\n")
        return 1
    except OperationalDemoOperatorError as exc:
        errors.write(f"operational demo operator failed: {exc}\n")
        return 1
    except PresentationAssetGatewayError as exc:
        errors.write(f"presentation asset gateway failed: {exc}\n")
        return 1
    except SignalDetectionError as exc:
        errors.write(f"wc016-signal-detector failed: {exc}\n")
        return 1
    except ChangeIngestionError as exc:
        errors.write(f"{args.command} failed: {exc}\n")
        return 1
    except ValueError as exc:
        if args.command in {
            "wc016-signal-detector",
            "wc016-incident-orchestrator",
            "wc016-incident-feed-heartbeat",
            "wc016-notification-dispatcher",
            "wc025-change-event-ingester",
            "wc025-change-dead-letter-purge",
            "wc025-change-history-query",
        }:
            errors.write(f"{args.command} failed: {exc}\n")
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
