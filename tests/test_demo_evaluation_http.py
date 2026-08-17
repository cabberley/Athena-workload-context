from __future__ import annotations

from fastapi.testclient import TestClient

from athena_context.api import (
    StaticTestAuthenticator,
    VerifiedAuthentication,
    create_app,
)
from athena_context.api.domain import AuthenticationMethod
from wc013_support import (
    MCP_SERVICE_ACTOR,
    PUBLISHER,
    build_harness,
)

PUBLISHER_TOKEN = "synthetic-wc013-publisher-token"
MCP_TOKEN = "synthetic-wc013-mcp-token"


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
        }
    )
    return harness, TestClient(
        create_app(
            authentication=authentication,
            demo_evaluation_service=harness.service,
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
    assert "DemoEvaluationCommand" in configured_schema["components"]["schemas"]
    assert "DemoEvaluationResult" in configured_schema["components"]["schemas"]
    assert "/v1/demo-evaluations" not in default_schema["paths"]
