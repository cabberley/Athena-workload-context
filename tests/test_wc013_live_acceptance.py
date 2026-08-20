from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

import athena_context.live_acceptance as live_acceptance
from athena_context.api import PublishedContextSelection, Role, RoleGrant
from athena_context.api.domain import WorkloadGrantScope
from athena_context.cli import main
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.live_acceptance import (
    Wc013AuthorityInput,
    Wc013ConfigurationInput,
    Wc013LiveAcceptanceError,
    prepare_wc013_live_acceptance,
    render_wc013_configuration,
    verify_wc013_live_result,
    wc013_configuration_template,
)
from wc013_support import (
    CURRENT_NOW,
    PRIVATE_ENDPOINT,
    PUBLISHER,
    TRUST_ANCHOR,
    DemoHarness,
    DeterministicIngestionSigner,
    DeterministicSnapshotSigner,
    ReplayGuard,
    ScenarioTransport,
    StepClock,
    build_current_synthetic_manifest,
    build_harness,
    deployment_assertion,
    key_anchor,
    key_resolver,
    operator_approval,
    trust_configuration,
)


def _live_harness() -> DemoHarness:
    return build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )


def _write_public_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _configuration_source(tmp_path: Path) -> Path:
    harness = _live_harness()
    assertion = deployment_assertion()
    approval = operator_approval(assertion)
    trust = trust_configuration()
    grant_scope = WorkloadGrantScope(workload_id=harness.command.manifest_id)
    grants = (
        RoleGrant(
            actor_id=PUBLISHER.actor_id,
            role=Role.PUBLISHER,
            scope=grant_scope,
        ),
        RoleGrant(
            actor_id=PUBLISHER.actor_id,
            role=Role.READER,
            scope=grant_scope,
        ),
    )
    authority_source = Wc013AuthorityInput(
        published_context=harness.context_resolver.view,
        evaluation_approval=harness.approval,
        publisher=PUBLISHER,
        context_reader=PUBLISHER,
        evaluation_grants=grants,
    )
    authority_source_path = tmp_path / "wc013-authority-source.json"
    authority_payload = json.loads(
        authority_source.model_dump_json(
            by_alias=True,
            exclude_none=True,
        )
    )
    authority_payload["published_context"]["supersession"] = None
    authority_source_path.write_text(
        json.dumps(authority_payload),
        encoding="utf-8",
    )
    public_key_path = tmp_path / "wc013-signing-public-key.pem"
    _write_public_key(public_key_path, CANONICAL_PRIVATE_KEY)
    payload = {
        "deployment": {
            "azure_mcp_internal_endpoint": (
                assertion.azure_mcp_internal_endpoint
            ),
            "managed_environment_resource_id": (
                assertion.managed_environment_resource_id
            ),
            "azure_mcp_container_app_resource_id": (
                assertion.azure_mcp_container_app_resource_id
            ),
            "evidence_identity_resource_id": (
                assertion.evidence_identity_resource_id
            ),
            "context_identity_resource_id": (
                assertion.context_identity_resource_id
            ),
            "evidence_identity_object_id": (
                assertion.evidence_identity_object_id
            ),
            "context_identity_object_id": (
                assertion.context_identity_object_id
            ),
            "evidence_identity_client_id": trust.managed_identity_client_id,
            "context_identity_client_id": (
                "66666666-6666-6666-6666-666666666666"
            ),
            "evidence_read_assignments": assertion.evidence_read_assignments,
        },
        "operator_approval": {
            "approval_id": approval.approval_id,
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at,
            "reason": approval.reason,
        },
        "authority_bundle_file": authority_source_path.name,
        "authority_approval": {
            "approval_id": "approval-wc007-live-authority",
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at,
            "reason": "Trust the exact synthetic WC-007 authority export",
        },
        "selection": PublishedContextSelection(
            manifest_id=harness.command.manifest_id,
            manifest_version=harness.command.manifest_version,
            profile_id=harness.command.profile_id,
        ),
        "azure_mcp_audience": "api://athena-azure-mcp",
        "collector_trust": {
            "collector_identity_evidence_ref": (
                trust.collector_identity_evidence_ref
            ),
            "mcp_host_id": trust.mcp_host_id,
            "tenant_id": trust.tenant_id,
            "managed_identity_client_id": trust.managed_identity_client_id,
            "ingestion_service_id": trust.ingestion_service_id,
            "ingestion_audience": trust.ingestion_audience,
        },
        "trusted_key": {
            "key_vault_key_id": TRUST_ANCHOR,
            "public_key_file": public_key_path.name,
            "activated_at": CURRENT_NOW - timedelta(days=30),
            "expires_at": CURRENT_NOW + timedelta(days=365),
        },
        "replay": {
            "table_endpoint": "https://athenareplay.table.core.windows.net",
            "table_name": "Wc013Replay",
            "partition_key": "wc013-live-test",
        },
        "idempotency_key": "wc013-live-acceptance-test",
        "evaluation_command": harness.command,
    }
    source = Wc013ConfigurationInput.model_validate(payload)
    source_path = tmp_path / "wc013-source.json"
    source_path.write_text(source.model_dump_json(indent=2), encoding="utf-8")
    return source_path


def test_configuration_template_is_valid_and_contains_no_credentials() -> None:
    template = wc013_configuration_template()
    parsed = Wc013ConfigurationInput.model_validate_json(template)

    assert parsed.deployment.azure_mcp_internal_endpoint.startswith("https://")
    assert parsed.deployment.azure_mcp_internal_endpoint.endswith(
        ".azurecontainerapps.io"
    )
    assert ".internal." not in parsed.deployment.azure_mcp_internal_endpoint
    lowered = template.casefold()
    assert "bearertoken" not in lowered
    assert '"password"' not in lowered
    assert '"client_secret"' not in lowered


def test_rendered_configuration_round_trips_existing_environment_ports(
    tmp_path: Path,
) -> None:
    source_path = _configuration_source(tmp_path)
    output_directory = tmp_path / "rendered"

    rendered = render_wc013_configuration(source_path, output_directory)
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)

    assert prepared.assertion.azure_mcp_internal_endpoint == PRIVATE_ENDPOINT
    assert prepared.assertion.assertion_digest == rendered.assertion_digest
    assert prepared.operator_approval.assertion_digest == rendered.assertion_digest
    assert prepared.trusted_key_anchor == key_anchor(
        CANONICAL_PRIVATE_KEY.public_key()
    )
    powershell = rendered.powershell_path.read_text(encoding="utf-8")
    assert "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE" in powershell
    assert "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST" in powershell
    assert "ATHENA_WC013_REPLAY_TABLE_ENDPOINT" in powershell
    assert "$env:AZURE_CLIENT_ID" in powershell
    assert '= "$configurationRoot\\wc008-deployment-assertion.json"' in powershell
    assert "Bearer " not in powershell
    plan_payload = json.loads(rendered.plan_path.read_text(encoding="utf-8"))
    public_key_file = plan_payload["trusted_key"]["public_key_file"]
    assert "\\" not in public_key_file
    assert public_key_file == "../wc013-signing-public-key.pem"


def test_live_result_verification_accepts_existing_signed_production_shape(
    tmp_path: Path,
) -> None:
    harness = _live_harness()
    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-live-acceptance-shape",
        harness.command,
    )
    rendered = render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)

    verify_wc013_live_result(prepared, result)


def test_tampered_digest_and_wrong_public_key_fail_closed(
    tmp_path: Path,
) -> None:
    source_path = _configuration_source(tmp_path)
    rendered = render_wc013_configuration(source_path, tmp_path / "rendered")
    plan_payload = json.loads(rendered.plan_path.read_text(encoding="utf-8"))
    plan_payload["wc008_pinned_assertion_digest"] = "sha256:" + ("0" * 64)
    rendered.plan_path.write_text(
        json.dumps(plan_payload),
        encoding="utf-8",
    )

    with pytest.raises(Wc013LiveAcceptanceError, match="failed closed"):
        prepare_wc013_live_acceptance(rendered.plan_path)

    rendered.plan_path.unlink()
    rendered = render_wc013_configuration(
        source_path,
        tmp_path / "different-rendered",
    )
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_public_key = tmp_path / "wrong-public-key.pem"
    _write_public_key(wrong_public_key, wrong_key)
    plan_payload = json.loads(rendered.plan_path.read_text(encoding="utf-8"))
    plan_payload["trusted_key"]["public_key_file"] = str(wrong_public_key)
    rendered.plan_path.write_text(
        json.dumps(plan_payload),
        encoding="utf-8",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)
    harness = _live_harness()
    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-live-wrong-key",
        harness.command,
    )

    with pytest.raises(Wc013LiveAcceptanceError, match="cryptographic"):
        verify_wc013_live_result(prepared, result)


def test_tampered_wc007_authority_fails_closed(tmp_path: Path) -> None:
    rendered = render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    payload = json.loads(rendered.authority_path.read_text(encoding="utf-8"))
    payload["publisher"]["actor_id"] = "tampered-publisher"
    rendered.authority_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(Wc013LiveAcceptanceError, match="configuration file"):
        prepare_wc013_live_acceptance(rendered.plan_path)


def test_render_refuses_overwrite_and_validate_only_uses_no_credentials(
    tmp_path: Path,
) -> None:
    source_path = _configuration_source(tmp_path)
    output_directory = tmp_path / "rendered"
    rendered = render_wc013_configuration(source_path, output_directory)

    with pytest.raises(Wc013LiveAcceptanceError, match="refusing to overwrite"):
        render_wc013_configuration(source_path, output_directory)

    assert (
        main(
            [
                "wc013-live-acceptance",
                "--config",
                str(rendered.plan_path),
                "--validate-only",
            ]
        )
        == 0
    )


def test_one_shot_composition_uses_existing_services_without_context_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)
    clock = StepClock(CURRENT_NOW + timedelta(seconds=10))
    resolver = key_resolver(CANONICAL_PRIVATE_KEY.public_key())

    runtime_environment = {
        "AZURE_CLIENT_ID": prepared.plan.context_identity_client_id,
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            prepared.plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            prepared.plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID": (
            prepared.plan.context_identity_client_id
        ),
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            prepared.plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_AZURE_MCP_AUDIENCE": (
            prepared.plan.azure_mcp_audience
        ),
        "ATHENA_WC013_REPLAY_TABLE_ENDPOINT": (
            prepared.plan.replay.table_endpoint
        ),
        "ATHENA_WC013_REPLAY_TABLE_NAME": prepared.plan.replay.table_name,
        "ATHENA_WC013_REPLAY_PARTITION_KEY": (
            prepared.plan.replay.partition_key
        ),
    }
    for name, value in runtime_environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(live_acceptance, "_SystemClock", lambda: clock)
    monkeypatch.setattr(
        live_acceptance,
        "KeyVaultTrustedKeyResolver",
        lambda **_kwargs: resolver,
    )
    monkeypatch.setattr(
        live_acceptance,
        "KeyVaultRsaSigner",
        lambda **_kwargs: DeterministicSnapshotSigner(CANONICAL_PRIVATE_KEY),
    )
    monkeypatch.setattr(
        live_acceptance,
        "DefaultAzureCredentialTrustedIngestionSigner",
        lambda **_kwargs: DeterministicIngestionSigner(CANONICAL_PRIVATE_KEY),
    )
    monkeypatch.setattr(
        live_acceptance,
        "AzureTableAttemptReplayGuard",
        lambda **_kwargs: ReplayGuard(),
    )
    monkeypatch.setattr(
        live_acceptance,
        "ManagedIdentityPrivateMcpInvoker",
        lambda **_kwargs: ScenarioTransport("success"),
    )

    accepted = live_acceptance.run_wc013_live_acceptance(
        rendered.plan_path,
        snapshot_output=tmp_path / "snapshot.json",
    )

    assert accepted.result.snapshot.evidence_records
    assert accepted.snapshot_path is not None
    assert accepted.snapshot_path.is_file()


def test_one_shot_failure_reports_only_exception_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    prepared = prepare_wc013_live_acceptance(rendered.plan_path)
    runtime_environment = {
        "AZURE_CLIENT_ID": prepared.plan.context_identity_client_id,
        "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST": (
            prepared.plan.wc007_pinned_authority_digest
        ),
        "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
            prepared.plan.wc008_pinned_assertion_digest
        ),
        "ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID": (
            prepared.plan.context_identity_client_id
        ),
        "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID": (
            prepared.plan.evidence_identity_client_id
        ),
        "ATHENA_WC013_AZURE_MCP_AUDIENCE": prepared.plan.azure_mcp_audience,
        "ATHENA_WC013_REPLAY_TABLE_ENDPOINT": prepared.plan.replay.table_endpoint,
        "ATHENA_WC013_REPLAY_TABLE_NAME": prepared.plan.replay.table_name,
        "ATHENA_WC013_REPLAY_PARTITION_KEY": prepared.plan.replay.partition_key,
    }
    for name, value in runtime_environment.items():
        monkeypatch.setenv(name, value)

    class SensitiveFailure(RuntimeError):
        pass

    monkeypatch.setattr(
        live_acceptance,
        "_compose_wc013_one_shot_service",
        lambda _prepared: (_ for _ in ()).throw(
            SensitiveFailure("Bearer sensitive-token")
        ),
    )

    with pytest.raises(
        Wc013LiveAcceptanceError,
        match=r"failed closed \(SensitiveFailure\)$",
    ) as raised:
        live_acceptance.run_wc013_live_acceptance(rendered.plan_path)

    assert "sensitive-token" not in str(raised.value)


def test_validation_failure_pointers_do_not_retain_input_values() -> None:
    with pytest.raises(ValidationError) as raised:
        live_acceptance.Wc013LiveAcceptancePlan.model_validate(
            {"inputPath": "sensitive-token"}
        )

    detail = live_acceptance._safe_validation_failure_pointers(raised.value)

    assert detail.startswith("ValidationError[")
    assert ":missing" in detail
    assert "sensitive-token" not in detail


def test_one_shot_composition_requires_pinned_runtime_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = render_wc013_configuration(
        _configuration_source(tmp_path),
        tmp_path / "rendered",
    )
    monkeypatch.setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

    with pytest.raises(
        Wc013LiveAcceptanceError,
        match="runtime environment does not match",
    ):
        live_acceptance.run_wc013_live_acceptance(rendered.plan_path)
