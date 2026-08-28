from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import athena_context.live_acceptance as live_acceptance
import athena_context.wc013_evidence_collector as collector_module
from athena_context.api import (
    OperatorTrustedWc008ConfigurationPort,
    Wc009PrecollectedEvidenceClientAdapter,
)
from athena_context.artifacts import ArtifactReadResult
from athena_context.contracts import sha256_hex
from athena_context.evidence import (
    CollectedEvidence,
    EvidenceClientCompositionError,
    EvidenceCollectionCommand,
)
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.live_acceptance import (
    PreparedWc013LiveAcceptance,
    prepare_wc013_live_acceptance,
)
from athena_context.precollected_evidence import (
    Wc013CollectedEvidenceArtifact,
    Wc013CollectedEvidenceHandoff,
    build_collected_evidence_artifact,
    wc013_plan_digest,
)
from test_wc013_live_acceptance import _configuration_source
from wc013_support import (
    CURRENT_NOW,
    DeterministicIngestionSigner,
    ReplayGuard,
    ScenarioTransport,
    StepClock,
    key_resolver,
)


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


def test_collected_evidence_handoff_is_version_pinned_and_plan_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, collected = _prepared_and_collected(tmp_path)
    plan_digest = wc013_plan_digest(prepared.plan)
    artifact = build_collected_evidence_artifact(
        plan_digest=plan_digest,
        collected=collected,
    )
    payload = artifact.canonical_json().encode("utf-8")
    handoff = Wc013CollectedEvidenceHandoff(
        schemaVersion="athena.wc013CollectedEvidenceHandoff.v1",
        planDigest=plan_digest,
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
        ) -> None:
            observed["reader"] = (
                blob_endpoint,
                container_name,
                managed_identity_client_id,
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
    )

    assert loaded == collected
    assert observed["reader"] == (
        "https://athenareplay.blob.core.windows.net",
        "collected-evidence",
        prepared.plan.context_identity_client_id,
    )


def test_collected_evidence_rejects_tampered_source_envelope(
    tmp_path: Path,
) -> None:
    prepared, collected = _prepared_and_collected(tmp_path)
    artifact = build_collected_evidence_artifact(
        plan_digest=wc013_plan_digest(prepared.plan),
        collected=collected,
    )
    payload = json.loads(artifact.model_dump_json(by_alias=True))
    payload["sourceEnvelope"]["observedAt"] = "2026-08-28T01:02:03.000Z"

    with pytest.raises(
        ValidationError,
        match="source envelope digest",
    ):
        Wc013CollectedEvidenceArtifact.model_validate_json(json.dumps(payload))


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
        collected=collected,
    )
    observed: dict[str, object] = {}

    class _Writer:
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
    )
    assert result.handoff.evidence.name.endswith("/collected-evidence.json")
