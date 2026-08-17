from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from athena_context.api import (
    Actor,
    ActorKind,
    PrivateMcpEvidenceTransport,
    StaticTestAuthenticator,
    VerifiedAuthentication,
    VerifiedWc008DeploymentConfiguration,
    Wc009EvidenceClientAdapter,
    create_app,
)
from athena_context.api.domain import (
    AuthenticationMethod,
    Role,
    RoleGrant,
    WorkloadGrantScope,
)
from athena_context.api.errors import DemoEvaluationConfigurationError
from athena_context.api.evaluation_ports import (
    seal_mcp_transport_configuration,
)
from athena_context.evidence import EvidenceTransportRequest
from athena_context.evidence.models import McpTransportOutcome
from wc013_support import (
    APPROVER,
    MCP_SERVICE_ACTOR,
    PUBLISHER,
    ScenarioTransport,
    build_harness,
    verified_deployment_configuration,
)

PUBLISHER_TOKEN = "synthetic-wc013-publisher-token"
MCP_TOKEN = "synthetic-wc013-mcp-token"
APPROVER_TOKEN = "synthetic-wc013-approver-token"
UNAUTHORIZED_TOKEN = "synthetic-wc013-unauthorized-token"
CROSS_WORKLOAD_TOKEN = "synthetic-wc013-cross-workload-token"
UNAUTHORIZED = Actor(
    actor_id="wc013-unauthorized-human",
    kind=ActorKind.HUMAN,
)
CROSS_WORKLOAD_AUDITOR = Actor(
    actor_id="wc013-cross-workload-auditor",
    kind=ActorKind.HUMAN,
)


def _verified(actor: object) -> VerifiedAuthentication:
    from athena_context.api import Actor

    assert isinstance(actor, Actor)
    return VerifiedAuthentication(
        actor=actor,
        subject_id=f"synthetic-subject-{actor.actor_id}",
        issuer="https://issuer.invalid/wc013-synthetic",
        audience="api://athena-context-test",
        method=AuthenticationMethod.TEST,
    )


def _client(scenario: str = "success") -> tuple[object, TestClient]:
    harness = build_harness(scenario)
    authentication = StaticTestAuthenticator(
        {
            PUBLISHER_TOKEN: _verified(PUBLISHER),
            MCP_TOKEN: _verified(MCP_SERVICE_ACTOR),
            APPROVER_TOKEN: _verified(APPROVER),
            UNAUTHORIZED_TOKEN: _verified(UNAUTHORIZED),
            CROSS_WORKLOAD_TOKEN: _verified(CROSS_WORKLOAD_AUDITOR),
        }
    )
    return harness, TestClient(
        create_app(
            service=harness.context_resolver.service,
            authentication=authentication,
            demo_evaluation_dependencies=harness.dependencies,
        )
    )


def _headers(token: str, key: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if key is not None:
        headers["Idempotency-Key"] = key
    return headers


def test_api_returns_snapshot_publication_record_and_exact_citations() -> None:
    harness, client = _client()

    response = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, "wc013-http-success"),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["publication"]["snapshot_id"] == body["snapshot"]["snapshotId"]
    assert body["publication"]["approval_decision_id"] == (
        harness.approval.decision_id
    )
    assert body["publication"]["published_by"]["actor_id"] == "athena-context-api"
    assert len(body["findings"]) == 5
    assert body["citation_count"] == 9
    assert all(
        finding["governanceScope"]["clausePath"]
        == f"/constraints/{finding['clauseId']}"
        for finding in body["findings"]
    )
    assert all(
        reference["snapshotId"] == body["snapshot"]["snapshotId"]
        for finding in body["findings"]
        for reference in finding["evidenceRefs"]
    )

    fetched = client.get(
        f"/v1/demo-evaluations/{body['snapshot']['snapshotId']}",
        headers=_headers(PUBLISHER_TOKEN),
    )
    replay = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, "wc013-http-success"),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )
    assert fetched.status_code == 200
    assert fetched.json() == body
    assert replay.status_code == 201
    assert replay.json() == body
    assert harness.transport.calls == 1
    assert harness.store.publication_count == 1


def test_http_rejects_polymorphic_foreign_transport_before_any_side_effect() -> None:
    """The endpoint actually consumed by WC-009 cannot masquerade via __eq__."""

    class AlwaysEqualConfiguration(VerifiedWc008DeploymentConfiguration):
        def __eq__(self, other: object) -> bool:
            del other
            return True

        def __ne__(self, other: object) -> bool:
            del other
            return False

    harness, client = _client()
    foreign_base = verified_deployment_configuration(
        "https://foreign-mcp.internal"
    )
    _, foreign_binding = seal_mcp_transport_configuration(foreign_base)
    foreign_configuration = AlwaysEqualConfiguration.model_validate_json(
        foreign_base.model_dump_json(by_alias=True)
    )
    rejected_invoker = ScenarioTransport()

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="exact operator-verified WC-008 configuration",
    ):
        PrivateMcpEvidenceTransport(
            deployment_configuration=foreign_configuration,
            invoker=rejected_invoker,
        )

    evidence_client = harness.dependencies.evidence_client
    assert type(evidence_client) is Wc009EvidenceClientAdapter
    transport = evidence_client._transport
    object.__setattr__(
        transport,
        "_deployment_configuration",
        foreign_configuration,
    )
    object.__setattr__(
        transport,
        "_transport_configuration",
        foreign_binding,
    )
    idempotency_key = "wc013-http-polymorphic-foreign-endpoint"

    response = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, idempotency_key),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "demo_evaluation_configuration"
    assert rejected_invoker.calls == 0
    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None


def test_http_rejects_overridden_runtime_transport_without_bearer_forwarding() -> None:
    """Advertised trusted config cannot hide a foreign runtime invocation."""

    attacker_endpoint = "https://attacker.example"
    attacker_invoker = ScenarioTransport()
    forwarded_authorizations: list[str] = []

    class ForeignCallingTransport(PrivateMcpEvidenceTransport):
        def invoke(
            self,
            request: EvidenceTransportRequest,
        ) -> McpTransportOutcome:
            forwarded_authorizations.append("managed-identity-bearer")
            return attacker_invoker.invoke(
                attacker_endpoint,
                "group_resource_list",
                request,
            )

    harness, client = _client()
    malicious_transport = ForeignCallingTransport(
        deployment_configuration=harness.deployment_configuration,
        invoker=attacker_invoker,
    )
    evidence_client = harness.dependencies.evidence_client
    assert type(evidence_client) is Wc009EvidenceClientAdapter
    evidence_client._client._transport = malicious_transport
    idempotency_key = "wc013-http-overridden-runtime-transport"

    response = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, idempotency_key),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "demo_evaluation_configuration"
    assert forwarded_authorizations == []
    assert attacker_invoker.calls == 0
    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None


def test_api_never_replays_cross_workload_receipt_after_access_revocation() -> None:
    harness, client = _client()
    idempotency_key = "wc013-http-cross-workload"
    published = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, idempotency_key),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )
    assert published.status_code == 201
    published_body = published.json()
    original_workload = harness.command.manifest_id
    foreign_workload = "wl-authorized-foreign-http"
    harness.authorization.remove_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )
    harness.authorization.add_grant(
        RoleGrant(
            actor_id=PUBLISHER.actor_id,
            role=Role.PUBLISHER,
            scope=WorkloadGrantScope(workload_id=foreign_workload),
        )
    )

    denied_artifact = client.get(
        f"/v1/demo-evaluations/{published_body['snapshot']['snapshotId']}",
        headers=_headers(PUBLISHER_TOKEN),
    )
    foreign_command = harness.command.model_copy(
        update={"manifest_id": foreign_workload}
    )
    mismatched_receipt = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, idempotency_key),
        json=foreign_command.model_dump(mode="json", by_alias=True),
    )

    assert denied_artifact.status_code == 403
    assert mismatched_receipt.status_code == 409
    assert mismatched_receipt.json()["error"]["code"] == "idempotency_conflict"
    response_text = mismatched_receipt.text
    assert original_workload not in response_text
    assert published_body["snapshot"]["snapshotId"] not in response_text
    assert harness.transport.calls == 1
    harness.authorization.add_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )
    assert harness.store.publication_count == 1


def test_approval_reads_use_stored_workload_authority_after_publication() -> None:
    harness, client = _client()
    approval_path = (
        "/v1/demo-evaluation-approvals/"
        f"{harness.approval.decision_id}"
    )
    foreign_workload = "wl-foreign-approval-audit"
    harness.authorization.add_grant(
        RoleGrant(
            actor_id=CROSS_WORKLOAD_AUDITOR.actor_id,
            role=Role.AUDITOR,
            scope=WorkloadGrantScope(workload_id=foreign_workload),
        )
    )
    before_audit = harness.context_resolver.service.audit_history(
        APPROVER,
        harness.command.manifest_id,
    )
    before_approval = harness.approval_registry.resolve(
        harness.approval.decision_id
    )

    unauthorized = client.get(
        approval_path,
        headers=_headers(UNAUTHORIZED_TOKEN),
    )
    cross_workload = client.get(
        approval_path,
        headers=_headers(CROSS_WORKLOAD_TOKEN),
    )
    published = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, "wc013-http-approval-read-publish"),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )
    authorized = client.get(
        approval_path,
        headers=_headers(PUBLISHER_TOKEN),
    )

    assert unauthorized.status_code == 403
    assert cross_workload.status_code == 403
    assert published.status_code == 201
    assert authorized.status_code == 200
    assert authorized.json()["manifest_id"] == harness.command.manifest_id
    sensitive_values = (
        harness.approval.manifest_digest,
        harness.approval.private_mcp_endpoint,
        harness.approval.evidence_identity_object_id,
        harness.approval.approved_by.actor_id,
    )
    for denied in (unauthorized, cross_workload):
        assert all(value not in denied.text for value in sensitive_values)
    receipt = harness.store.load_receipt(
        PUBLISHER.actor_id,
        "wc013-http-approval-read-publish",
    )
    harness.authorization.remove_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )

    revoked = client.get(
        approval_path,
        headers=_headers(PUBLISHER_TOKEN),
    )

    assert revoked.status_code == 403
    assert all(value not in revoked.text for value in sensitive_values)
    assert (
        harness.approval_registry.resolve(
            harness.approval.decision_id
        )
        == before_approval
    )
    assert (
        harness.context_resolver.service.audit_history(
            APPROVER,
            harness.command.manifest_id,
        )
        == before_audit
    )
    harness.authorization.add_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )
    assert harness.store.publication_count == 1
    assert (
        harness.store.load_receipt(
            PUBLISHER.actor_id,
            "wc013-http-approval-read-publish",
        )
        == receipt
    )


def test_http_rejects_forged_approval_provenance_without_state() -> None:
    harness, client = _client()
    service = harness.context_resolver.service
    decision_id = "approval-wc013-http-authoritative"
    idempotency_key = "wc013-http-authoritative-approval"
    expected_approval_time = harness.clock.value
    command = {
        "decision_id": decision_id,
        "expires_at": (
            expected_approval_time + timedelta(hours=1)
        ).isoformat(),
        "manifest_id": harness.command.manifest_id,
        "manifest_version": harness.approval.manifest_version,
        "manifest_digest": harness.command.expected_manifest_digest,
        "profile_id": harness.command.profile_id,
        "authorized_scope": harness.command.authorized_scope.model_dump(
            mode="json",
            by_alias=True,
        ),
        "reason": "Authorize server-attested HTTP approval provenance",
    }
    forged_values = {
        "approved_by": {
            "actor_id": "wc013-forged-approver",
            "kind": "human",
        },
        "approved_at": "2020-01-01T00:00:00.999Z",
    }
    audit_before = service.audit_history(
        APPROVER,
        harness.command.manifest_id,
    )

    for field, value in forged_values.items():
        rejected = client.post(
            "/v1/demo-evaluation-approvals",
            headers=_headers(APPROVER_TOKEN, idempotency_key),
            json={**command, field: value},
        )
        assert rejected.status_code == 422
    assert (
        service.get_demo_evaluation_approval(APPROVER, decision_id)
        is None
    )
    assert harness.store.publication_count == 0
    assert (
        service.audit_history(APPROVER, harness.command.manifest_id)
        == audit_before
    )

    created = client.post(
        "/v1/demo-evaluation-approvals",
        headers=_headers(APPROVER_TOKEN, idempotency_key),
        json=command,
    )
    replay = client.post(
        "/v1/demo-evaluation-approvals",
        headers=_headers(APPROVER_TOKEN, idempotency_key),
        json=command,
    )

    assert created.status_code == 201
    assert replay.status_code == 201
    assert replay.json() == created.json()
    created_body = created.json()
    assert created_body["approved_by"] == APPROVER.model_dump(mode="json")
    assert created_body["approved_at"] == (
        expected_approval_time.isoformat().replace("+00:00", "Z")
    )
    assert created_body["revision"] == 1
    assert created_body["private_mcp_endpoint"] == (
        harness.deployment_configuration.assertion.azure_mcp_internal_endpoint
    )
    assert created_body["evidence_identity_object_id"] == (
        harness.deployment_configuration.assertion.evidence_identity_object_id
    )

    evaluation_command = harness.command.model_copy(
        update={"approval_decision_id": decision_id}
    )
    evaluated = client.post(
        "/v1/demo-evaluations",
        headers=_headers(
            PUBLISHER_TOKEN,
            "wc013-http-authoritative-approval-publication",
        ),
        json=evaluation_command.model_dump(mode="json", by_alias=True),
    )

    assert evaluated.status_code == 201
    publication = evaluated.json()["publication"]
    assert publication["approved_by"] == APPROVER.model_dump(mode="json")
    assert publication["approved_at"] == created_body["approved_at"]
    assert harness.store.publication_count == 1


def test_api_requires_verified_human_publisher_and_ignores_spoofed_actor() -> None:
    harness, client = _client()

    missing = client.post(
        "/v1/demo-evaluations",
        headers={"Idempotency-Key": "wc013-http-missing-auth"},
        json=harness.command.model_dump(mode="json", by_alias=True),
    )
    mcp = client.post(
        "/v1/demo-evaluations",
        headers={
            **_headers(MCP_TOKEN, "wc013-http-mcp-denied"),
            "X-Athena-Actor": PUBLISHER.actor_id,
        },
        json=harness.command.model_dump(mode="json", by_alias=True),
    )

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "authentication_required"
    assert mcp.status_code == 403
    assert mcp.json()["error"]["code"] == "authorization_denied"
    assert harness.transport.calls == 0
    assert harness.store.publication_count == 0


def test_api_maps_closed_mcp_outcome_without_a_publication() -> None:
    harness, client = _client("unavailable")

    response = client.post(
        "/v1/demo-evaluations",
        headers=_headers(PUBLISHER_TOKEN, "wc013-http-unavailable"),
        json=harness.command.model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "evidence_collection_rejected"
    assert harness.store.publication_count == 0


def test_openapi_only_exposes_demo_mutation_when_service_is_configured() -> None:
    harness, configured = _client()
    del harness
    default = TestClient(create_app())

    configured_schema = configured.get("/openapi.json").json()
    default_schema = default.get("/openapi.json").json()

    assert "/v1/demo-evaluations" in configured_schema["paths"]
    assert "/v1/demo-evaluations/{snapshot_id}" in configured_schema["paths"]
    assert "/v1/demo-evaluation-approvals" in configured_schema["paths"]
    assert (
        "/v1/demo-evaluation-approvals/{decision_id}"
        in configured_schema["paths"]
    )
    assert "DemoEvaluationCommand" in configured_schema["components"]["schemas"]
    assert "DemoEvaluationResult" in configured_schema["components"]["schemas"]
    approval_input = configured_schema["components"]["schemas"][
        "CreateDemoEvaluationApprovalCommand"
    ]["properties"]
    assert "approved_by" not in approval_input
    assert "approved_at" not in approval_input
    assert "/v1/demo-evaluations" not in default_schema["paths"]
    assert "/v1/demo-evaluation-approvals" not in default_schema["paths"]


def test_app_rejects_prebuilt_demo_service_from_foreign_context_store() -> None:
    authoritative = build_harness()
    foreign = build_harness()

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="preconstructed demo evaluation services are rejected",
    ):
        create_app(
            service=authoritative.context_resolver.service,
            demo_evaluation_service=foreign.service,
        )

    assert authoritative.store.publication_count == 0
    assert foreign.store.publication_count == 0
