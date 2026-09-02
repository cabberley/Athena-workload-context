from __future__ import annotations

import json
from datetime import UTC, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import athena_context.live_acceptance as live_acceptance
import athena_context.wc013_evidence_collector as collector_module
from athena_context.api import (
    OperatorTrustedWc008ConfigurationPort,
    VerifiedWc008DeploymentConfiguration,
    Wc009PrecollectedEvidenceClientAdapter,
)
from athena_context.artifacts import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    ArtifactMetadataHashes,
    ArtifactReadResult,
    ArtifactWriteRequest,
)
from athena_context.contracts import canonicalize_json, sha256_hex
from athena_context.evidence import (
    CollectedEvidence,
    EvidenceClientCompositionError,
    EvidenceCollectionCommand,
    EvidenceResponseBounds,
    McpSuccessResponse,
)
from athena_context.evidence.models import (
    MAX_RECORD_BYTES,
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_ITEMS,
)
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.live_acceptance import (
    PreparedWc013LiveAcceptance,
    prepare_wc013_live_acceptance,
)
from athena_context.precollected_evidence import (
    MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES,
    Wc013CollectedEvidenceArtifact,
    Wc013CollectedEvidenceHandoff,
    build_collected_evidence_artifact,
    wc013_plan_digest,
    wc013_transport_binding,
)
from test_wc013_live_acceptance import _configuration_source
from wc013_support import (
    CURRENT_NOW,
    DeterministicIngestionSigner,
    DeterministicSnapshotSigner,
    ReplayGuard,
    ScenarioTransport,
    StepClock,
    key_resolver,
)


def test_collector_system_clock_returns_utc_millisecond_precision() -> None:
    current = collector_module._SystemClock().now()

    assert current.tzinfo is UTC
    assert current.microsecond % 1000 == 0


def _prepared_and_collected(
    tmp_path: Path,
) -> tuple[PreparedWc013LiveAcceptance, CollectedEvidence]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    rendered = live_acceptance.render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)
    harness = collector_module.Wc009EvidenceClientAdapter(
        transport=collector_module.PrivateMcpEvidenceTransport(
            deployment_configuration=collector_module.OperatorTrustedWc008ConfigurationPort(
                assertion=prepared.assertion,
                pinned_assertion_digest=prepared.assertion.assertion_digest,
                operator_approval=prepared.operator_approval,
            ).load_verified(),
            invoker=ScenarioTransport("success"),
        ),
        signer=DeterministicIngestionSigner(CANONICAL_PRIVATE_KEY),
        replay_guard=ReplayGuard(),
        clock=StepClock(CURRENT_NOW),
        trust_configuration=prepared.collector_trust,
        key_resolver=key_resolver(CANONICAL_PRIVATE_KEY.public_key()),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    command = prepared.plan.evaluation_command
    collected = harness.collect(
        collector_module.EvidenceCollectionCommand(
            attemptId=command.attempt_id,
            evidenceScope=command.authorized_scope,
            authorizedScopes=(command.authorized_scope,),
            bounds=command.bounds,
        )
    )
    return prepared, collected


def _verified_configuration(
    prepared: PreparedWc013LiveAcceptance,
) -> VerifiedWc008DeploymentConfiguration:
    return OperatorTrustedWc008ConfigurationPort(
        assertion=prepared.assertion,
        pinned_assertion_digest=prepared.assertion.assertion_digest,
        operator_approval=prepared.operator_approval,
    ).load_verified()


def test_collected_evidence_handoff_is_version_pinned_and_plan_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, collected = _prepared_and_collected(tmp_path)
    plan_digest = wc013_plan_digest(prepared.plan)
    artifact = build_collected_evidence_artifact(
        plan_digest=plan_digest,
        transport_binding=wc013_transport_binding(
            _verified_configuration(prepared)
        ),
        collected=collected,
        signer=DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    payload = artifact.canonical_json().encode("utf-8")
    handoff = Wc013CollectedEvidenceHandoff(
        schemaVersion="athena.wc013CollectedEvidenceHandoff.v2",
        planDigest=plan_digest,
        transportBinding=artifact.transport_binding,
        attemptId=prepared.plan.evaluation_command.attempt_id,
        evidence={
            "name": (
                f"wc013-evidence/{prepared.plan.evaluation_command.attempt_id}/"
                "collected-evidence.json"
            ),
            "version": "2026-08-28T01:02:03.0000000Z",
            "contentDigest": sha256_hex(payload),
        },
    )
    observed: dict[str, object] = {}

    class _Reader:
        def __init__(
            self,
            *,
            blob_endpoint: str,
            container_name: str,
            managed_identity_client_id: str,
            max_payload_bytes: int,
        ) -> None:
            observed["reader"] = (
                blob_endpoint,
                container_name,
                managed_identity_client_id,
                max_payload_bytes,
            )

        def read(self, request: object) -> ArtifactReadResult:
            observed["request"] = request
            return ArtifactReadResult(
                container_name="collected-evidence",
                blob_name=handoff.evidence.name,
                version_id=handoff.evidence.version,
                payload=payload,
                size_bytes=len(payload),
                content_type="application/json",
                payload_sha256=handoff.evidence.content_digest,
            )

    monkeypatch.setattr(
        live_acceptance,
        "AzureBlobVersionPinnedArtifactReader",
        _Reader,
    )
    loaded = live_acceptance.load_precollected_evidence(
        prepared,
        evidence_blob_endpoint="https://athenareplay.blob.core.windows.net",
        evidence_container_name="collected-evidence",
        environment={
            "ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64": handoff.base64()
        },
        key_resolver=key_resolver(CANONICAL_PRIVATE_KEY.public_key()),
    )

    assert loaded == collected
    assert observed["reader"] == (
        "https://athenareplay.blob.core.windows.net",
        "collected-evidence",
        prepared.plan.context_identity_client_id,
        MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES,
    )


def test_collected_evidence_rejects_tampered_source_envelope(
    tmp_path: Path,
) -> None:
    prepared, collected = _prepared_and_collected(tmp_path)
    artifact = build_collected_evidence_artifact(
        plan_digest=wc013_plan_digest(prepared.plan),
        transport_binding=wc013_transport_binding(
            _verified_configuration(prepared)
        ),
        collected=collected,
        signer=DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    payload = json.loads(artifact.model_dump_json(by_alias=True))
    payload["sourceEnvelope"]["observedAt"] = "2026-08-28T01:02:03.000Z"

    with pytest.raises(
        ValidationError,
        match="source envelope digest",
    ):
        Wc013CollectedEvidenceArtifact.model_validate_json(json.dumps(payload))


def test_cross_endpoint_collected_artifact_relabeling_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_prepared, collected = _prepared_and_collected(tmp_path / "source")
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    target_source = _configuration_source(
        target_directory,
        (
            "https://other-synthetic-mcp.synthetic-env."
            "australiaeast.azurecontainerapps.io"
        ),
    )
    target_rendered = live_acceptance.render_wc013_configuration(
        target_source,
        tmp_path / "target-rendered",
    )
    target_prepared = prepare_wc013_live_acceptance(target_rendered.plan_path)
    target_plan_digest = wc013_plan_digest(target_prepared.plan)
    source_binding = wc013_transport_binding(
        _verified_configuration(source_prepared)
    )
    target_binding = wc013_transport_binding(
        _verified_configuration(target_prepared)
    )
    assert source_binding != target_binding
    artifact = build_collected_evidence_artifact(
        plan_digest=target_plan_digest,
        transport_binding=source_binding,
        collected=collected,
        signer=DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
        trusted_key_anchor=source_prepared.trusted_key_anchor,
    )
    payload = artifact.canonical_json().encode("utf-8")
    relabeled_payload = json.loads(payload)
    relabeled_payload["transportBinding"] = target_binding.model_dump(
        mode="json",
        by_alias=True,
    )
    with pytest.raises(ValidationError, match="attestation digest"):
        Wc013CollectedEvidenceArtifact.model_validate_json(
            json.dumps(relabeled_payload)
        )

    handoff = Wc013CollectedEvidenceHandoff(
        schemaVersion="athena.wc013CollectedEvidenceHandoff.v2",
        planDigest=target_plan_digest,
        transportBinding=target_binding,
        attemptId=target_prepared.plan.evaluation_command.attempt_id,
        evidence={
            "name": (
                f"wc013-evidence/"
                f"{target_prepared.plan.evaluation_command.attempt_id}/"
                "collected-evidence.json"
            ),
            "version": "2026-08-28T01:02:03.0000000Z",
            "contentDigest": sha256_hex(payload),
        },
    )
    read_calls = 0

    class _Reader:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def read(self, _request: object) -> ArtifactReadResult:
            nonlocal read_calls
            read_calls += 1
            return ArtifactReadResult(
                container_name="collected-evidence",
                blob_name=handoff.evidence.name,
                version_id=handoff.evidence.version,
                payload=payload,
                size_bytes=len(payload),
                content_type="application/json",
                payload_sha256=handoff.evidence.content_digest,
            )

    monkeypatch.setattr(
        live_acceptance,
        "AzureBlobVersionPinnedArtifactReader",
        _Reader,
    )

    with pytest.raises(
        live_acceptance.Wc013LiveAcceptanceError,
        match="failed closed validation",
    ):
        live_acceptance.load_precollected_evidence(
            target_prepared,
            evidence_blob_endpoint="https://athenareplay.blob.core.windows.net",
            evidence_container_name="collected-evidence",
            environment={
                "ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64": handoff.base64()
            },
            key_resolver=key_resolver(CANONICAL_PRIVATE_KEY.public_key()),
        )
    assert read_calls == 1


def test_precollected_adapter_rejects_changed_evaluation_request(
    tmp_path: Path,
) -> None:
    prepared, collected = _prepared_and_collected(tmp_path)
    configuration = OperatorTrustedWc008ConfigurationPort(
        assertion=prepared.assertion,
        pinned_assertion_digest=prepared.assertion.assertion_digest,
        operator_approval=prepared.operator_approval,
    ).load_verified()
    adapter = Wc009PrecollectedEvidenceClientAdapter(
        deployment_configuration=configuration,
        collected=collected,
        trust_configuration=prepared.collector_trust,
        key_resolver=key_resolver(CANONICAL_PRIVATE_KEY.public_key()),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    command = prepared.plan.evaluation_command

    with pytest.raises(
        EvidenceClientCompositionError,
        match="exact evaluation request",
    ):
        adapter.collect(
            EvidenceCollectionCommand(
                attemptId="attempt-ffffffffffff",
                evidenceScope=command.authorized_scope,
                authorizedScopes=(command.authorized_scope,),
                bounds=command.bounds,
            )
        )


def test_isolated_collector_uses_only_evidence_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = live_acceptance.render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)
    resolver = key_resolver(CANONICAL_PRIVATE_KEY.public_key())
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        collector_module,
        "KeyVaultTrustedKeyResolver",
        lambda **kwargs: (
            observed.setdefault("resolver_identity", kwargs["managed_identity_client_id"])
            and resolver
        ),
    )
    monkeypatch.setattr(
        collector_module,
        "ManagedIdentityPrivateMcpInvoker",
        lambda **kwargs: (
            observed.setdefault("invoker_identity", kwargs["managed_identity_client_id"])
            and ScenarioTransport("success")
        ),
    )
    monkeypatch.setattr(
        collector_module,
        "DefaultAzureCredentialTrustedIngestionSigner",
        lambda **kwargs: (
            observed.setdefault(
                "signer_identities",
                (
                    kwargs["signing_identity_client_id"],
                    kwargs["evidence_identity_client_id"],
                ),
            )
            and DeterministicIngestionSigner(CANONICAL_PRIVATE_KEY)
        ),
    )
    monkeypatch.setattr(
        collector_module,
        "KeyVaultRsaSigner",
        lambda **kwargs: (
            observed.setdefault(
                "artifact_signer_identity",
                kwargs["managed_identity_client_id"],
            )
            and DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY)
        ),
    )
    monkeypatch.setattr(
        collector_module,
        "AzureTableAttemptReplayGuard",
        lambda **kwargs: (
            observed.setdefault("replay_identity", kwargs["managed_identity_client_id"])
            and ReplayGuard()
        ),
    )
    monkeypatch.setattr(
        collector_module,
        "_SystemClock",
        lambda: StepClock(CURRENT_NOW + timedelta(seconds=1)),
    )

    artifact = collector_module.collect_prepared_wc013_evidence(prepared)

    evidence_id = prepared.plan.evidence_identity_client_id
    context_id = prepared.plan.context_identity_client_id
    assert artifact.collection_request.attempt_id == (
        prepared.plan.evaluation_command.attempt_id
    )
    assert observed == {
        "resolver_identity": evidence_id,
        "invoker_identity": evidence_id,
        "signer_identities": (evidence_id, evidence_id),
        "artifact_signer_identity": evidence_id,
        "replay_identity": evidence_id,
    }
    assert evidence_id != context_id


def test_collector_job_writes_with_evidence_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = live_acceptance.render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared, collected = _prepared_and_collected(tmp_path / "second")
    artifact = build_collected_evidence_artifact(
        plan_digest=wc013_plan_digest(prepared.plan),
        transport_binding=wc013_transport_binding(
            _verified_configuration(prepared)
        ),
        collected=collected,
        signer=DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    observed: dict[str, object] = {}

    class _Writer:
        def __init__(
            self,
            *,
            blob_endpoint: str,
            container_name: str,
            managed_identity_client_id: str,
            max_payload_bytes: int,
        ) -> None:
            observed["writer"] = (
                blob_endpoint,
                container_name,
                managed_identity_client_id,
                max_payload_bytes,
            )

        def create(self, request: object) -> object:
            observed["request"] = request
            return SimpleNamespace(
                blob_name=request.blob_name,
                version_id="2026-08-28T01:02:03.0000000Z",
                payload_sha256=request.hashes.payload_sha256,
            )

    monkeypatch.setattr(
        collector_module,
        "prepare_wc013_live_acceptance",
        lambda _path: prepared,
    )
    monkeypatch.setattr(
        collector_module,
        "collect_prepared_wc013_evidence",
        lambda _prepared: artifact,
    )
    monkeypatch.setattr(
        collector_module,
        "AzureBlobCreateOnlyArtifactWriter",
        _Writer,
    )
    result = collector_module.run_wc013_evidence_collector_job(
        rendered.plan_path,
        artifact_blob_endpoint="https://athenareplay.blob.core.windows.net",
        artifact_container_name="collected-evidence",
        environment={
            "AZURE_CLIENT_ID": prepared.plan.evidence_identity_client_id,
            "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
                prepared.plan.evidence_identity_client_id
            ),
            "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
                prepared.plan.wc007_pinned_authority_digest
            ),
            "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
                prepared.plan.wc008_pinned_assertion_digest
            ),
        },
    )

    assert observed["writer"] == (
        "https://athenareplay.blob.core.windows.net",
        "collected-evidence",
        prepared.plan.evidence_identity_client_id,
        MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES,
    )
    assert observed["request"].maximum_payload_bytes == (
        MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES
    )
    assert result.handoff.evidence.name.endswith("/collected-evidence.json")


def test_collected_evidence_capacity_covers_maximum_valid_raw_response(
    tmp_path: Path,
) -> None:
    rendered = live_acceptance.render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)

    observed_body_sizes: list[int] = []

    class _BoundaryTransport:
        def invoke(
            self,
            _private_mcp_endpoint: str,
            _deployment_tool_name: str,
            request: object,
        ) -> McpSuccessResponse:
            typed_request = request
            prefix = (
                f"/subscriptions/{typed_request.evidence_scope.subscription_id}/"
                f"resourceGroups/{typed_request.evidence_scope.resource_group_name}/"
                "providers/Microsoft.Compute/virtualMachines/"
            )

            def response_with_padding(length: int) -> bytes:
                items = [
                    {
                        "recordType": "resource",
                        "observedAt": typed_request.attempt_started_at,
                        "resourceId": f"{prefix}{'a' * length}{index:03d}",
                        "resourceType": "Microsoft.Compute/virtualMachines",
                        "location": "australiaeast",
                        "availabilityZone": "1",
                        "tags": {"environment": "production"},
                        "state": "running",
                    }
                    for index in range(MAX_RESPONSE_ITEMS)
                ]
                return canonicalize_json(
                    {
                        "schemaVersion": "1.0.0",
                        "toolName": typed_request.tool_name,
                        "toolVersion": typed_request.tool_version,
                        "attemptId": typed_request.attempt_id,
                        "requestDigest": typed_request.request_digest,
                        "evidenceScope": typed_request.evidence_scope.model_dump(
                            mode="json",
                            by_alias=True,
                        ),
                        "observedAt": typed_request.attempt_started_at,
                        "items": items,
                    }
                ).encode("utf-8")

            low = 1
            high = 4096
            while low < high:
                candidate = (low + high + 1) // 2
                if len(response_with_padding(candidate)) <= MAX_RESPONSE_BYTES:
                    low = candidate
                else:
                    high = candidate - 1
            body = response_with_padding(low)
            observed_body_sizes.append(len(body))
            return McpSuccessResponse(
                body=body,
                response_received_at=typed_request.attempt_started_at,
            )

    transport = _BoundaryTransport()
    configuration = _verified_configuration(prepared)
    client = collector_module.Wc009EvidenceClientAdapter(
        transport=collector_module.PrivateMcpEvidenceTransport(
            deployment_configuration=configuration,
            invoker=transport,
        ),
        signer=DeterministicIngestionSigner(CANONICAL_PRIVATE_KEY),
        replay_guard=ReplayGuard(),
        clock=StepClock(CURRENT_NOW),
        trust_configuration=prepared.collector_trust,
        key_resolver=key_resolver(CANONICAL_PRIVATE_KEY.public_key()),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    command = prepared.plan.evaluation_command
    bounded_command = EvidenceCollectionCommand(
        attemptId=command.attempt_id,
        evidenceScope=command.authorized_scope,
        authorizedScopes=(command.authorized_scope,),
        bounds=EvidenceResponseBounds(
            maxResponseBytes=MAX_RESPONSE_BYTES,
            maxItems=MAX_RESPONSE_ITEMS,
            maxRecordBytes=MAX_RECORD_BYTES,
            freshnessSeconds=command.bounds.freshness_seconds,
            timeoutMilliseconds=command.bounds.timeout_milliseconds,
        ),
    )
    collected = client.collect(bounded_command)
    artifact = build_collected_evidence_artifact(
        plan_digest=wc013_plan_digest(prepared.plan),
        transport_binding=wc013_transport_binding(configuration),
        collected=collected,
        signer=DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
        trusted_key_anchor=prepared.trusted_key_anchor,
    )
    payload = artifact.canonical_json().encode("utf-8")

    assert len(observed_body_sizes) == 1
    assert MAX_RESPONSE_BYTES - observed_body_sizes[0] < 4096
    assert len(payload) > MAX_ARTIFACT_PAYLOAD_BYTES
    assert len(payload) <= MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES
    request = ArtifactWriteRequest(
        blob_name="wc013-evidence/attempt-aaaaaaaaaaaa/collected-evidence.json",
        payload=payload,
        content_type="application/json",
        hashes=ArtifactMetadataHashes(payload_sha256=sha256_hex(payload)),
        maximum_payload_bytes=MAX_COLLECTED_EVIDENCE_ARTIFACT_BYTES,
    )
    assert request.payload == payload
